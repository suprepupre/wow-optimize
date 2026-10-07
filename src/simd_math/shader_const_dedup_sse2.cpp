// ============================================================================
// Module: shader_const_dedup_sse2.cpp
//
// The shader constant shadow compare, sub_6833E0. In a tester's 2026-09-19
// profile it is 1.17% of executing main-thread time.
//
// The client keeps its own copy of every shader constant register and, before
// sending any of them to the device, compares the new values against that copy
// one float at a time on the x87 stack - `fld`, `fcomp`, `fnstsw`, `test`,
// branch, four times per register. Where a register differs it writes the new
// values into the copy and widens a dirty range so the caller knows which
// registers to send.
//
//   __stdcall(int vertexSet, unsigned firstReg, const float* src, unsigned n)
//
//   vertexSet non-zero: copy at 0x00C5DFE0, dirty range 0x00C5EFE4 (low) and
//                       0x00C5EFE0 (high)
//   vertexSet zero:     copy at 0x00C5EFE8, dirty range 0x00C5FFEC and
//                       0x00C5FFE8
//
// There is no arithmetic in it at all - four comparisons of untouched floats
// and, where they differ, a copy of the same bits. One packed compare answers
// all four lanes, and the answer is the same one for the same reason the
// collision outcode's is: nothing is computed, so nothing can round
// differently. An unordered compare counts as "differs" in the client (its
// branch tests C3 and C2 together, and an unordered pair sets both) and in
// cmpneqps alike, so a NaN in either copy is written through the same way.
//
// Writing all four lanes where the client writes only the differing ones leaves
// the same bytes behind: the lanes that matched are written with what they
// already held.
//
// The return value. The client leaves eax holding its `firstReg` argument with
// the low sixteen bits overwritten by the last `fnstsw ax` it executed - the
// status word of the fourth lane of the last register. That is not a value any
// sane caller reads, but this function is reached through three vtables and its
// callers cannot be found statically, so it is reproduced rather than assumed
// away: the last register's fourth lane is compared once on the x87 stack, for
// its status word, before its new value is stored. One compare a call in place
// of four a register.
//
// Verification, predict-then-compare. The copy and the two dirty bounds are
// snapshotted, the client runs and writes the real ones, and then what this
// would have written is worked out from the snapshot and compared byte for
// byte. The first difference retires it for the session.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <xmmintrin.h>

#include "shader_const_dedup_sse2.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "session_verdict.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace ShaderConstDedup {

namespace {

constexpr uintptr_t kTarget = 0x006833E0;

constexpr uintptr_t kVertexCopy = 0x00C5DFE0;
constexpr uintptr_t kVertexLow  = 0x00C5EFE4;
constexpr uintptr_t kVertexHigh = 0x00C5EFE0;
constexpr uintptr_t kPixelCopy  = 0x00C5EFE8;
constexpr uintptr_t kPixelLow   = 0x00C5FFEC;
constexpr uintptr_t kPixelHigh  = 0x00C5FFE8;

// push ebp / mov ebp,esp / mov eax,[ebp+8] / mov edx,[ebp+10h] / push ebx /
// mov ecx,eax / push esi / shl ecx,4
const unsigned char kPrologue[16] = {
    0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x55,
    0x14, 0x53, 0x8B, 0xC8, 0x56, 0xC1, 0xE1, 0x04
};

// Each copy is 256 registers of four floats; anything past that is not a call
// this recognises.
constexpr uint32_t kMaxRegs = 256;
constexpr unsigned long kLearnCalls   = 4096;
constexpr unsigned long kResampleMask = 1023;

typedef uint32_t (__stdcall* SetFn)(int vertexSet, uint32_t firstReg,
                                    const float* src, uint32_t n);
SetFn g_orig = nullptr;

bool g_installed = false;
bool g_dead = false;
bool g_abSubject = false;

unsigned long long g_calls = 0;
unsigned long long g_answered = 0;
unsigned long long g_regs = 0;
unsigned long long g_changed = 0;
unsigned long long g_control = 0;
unsigned long long g_odd = 0;
unsigned long g_verified = 0;
unsigned g_mismatches = 0;

struct Target {
    float*    copy;
    uint32_t* low;
    uint32_t* high;
};

__forceinline Target TargetFor(int vertexSet, uint32_t firstReg) {
    Target t;
    if (vertexSet) {
        t.copy = (float*)(kVertexCopy + 16 * (uintptr_t)firstReg);
        t.low  = (uint32_t*)kVertexLow;
        t.high = (uint32_t*)kVertexHigh;
    } else {
        t.copy = (float*)(kPixelCopy + 16 * (uintptr_t)firstReg);
        t.low  = (uint32_t*)kPixelLow;
        t.high = (uint32_t*)kPixelHigh;
    }
    return t;
}

// The status word of the client's last comparison, which is what it leaves in
// the low half of eax. Taken before the last register is written, because the
// comparison is against the value that was there.
__forceinline uint32_t LastCompareStatus(const float* newVal, const float* oldVal) {
    uint32_t status = 0;
    __asm {
        mov     eax, newVal
        mov     edx, oldVal
        fld     dword ptr [eax+0Ch]
        fcomp   dword ptr [edx+0Ch]
        fnstsw  ax
        movzx   eax, ax
        mov     status, eax
    }
    return status;
}

// Writes the copy and widens the dirty range exactly as the client does.
// Returns the value the client would leave in eax.
__forceinline uint32_t Apply(const Target& t, const float* src, uint32_t firstReg,
                             uint32_t n) {
    uint32_t low = *t.low;
    uint32_t high = *t.high;
    uint32_t reg = firstReg;
    float* dst = t.copy;
    uint32_t status = 0;
    for (uint32_t i = 0; i < n; ++i, dst += 4, src += 4, ++reg) {
        const __m128 a = _mm_loadu_ps(src);
        const __m128 b = _mm_loadu_ps(dst);
        if (i + 1 == n) status = LastCompareStatus(src, dst);
        if (_mm_movemask_ps(_mm_cmpneq_ps(a, b)) != 0) {
            _mm_storeu_ps(dst, a);
            if (low > reg) low = reg;
            if (high < reg) high = reg;
            ++g_changed;
        }
    }
    *t.low = low;
    *t.high = high;
    return (firstReg & 0xFFFF0000u) | (status & 0xFFFFu);
}

__declspec(noinline) void Retire(const char* what) {
    ++g_mismatches;
    g_dead = true;
    Log("[ShaderConstDedup] RETIRED: %s. Every constant update from here on is "
        "the client's own.", what);
    Verdict::Add(Verdict::Bad, "ShaderConstDedup wrote different shader constant "
                 "state from the client and retired itself for this session");
}

// Enough for the whole of one copy, so a call is never turned away for size.
float g_before[kMaxRegs * 4];

uint32_t __stdcall Detour(int vertexSet, uint32_t firstReg, const float* src,
                          uint32_t n) {
    ++g_calls;
    if (g_dead || !src || n == 0 || firstReg >= kMaxRegs ||
        n > kMaxRegs - firstReg) {
        if (!g_dead && (n != 0)) ++g_odd;
        return g_orig(vertexSet, firstReg, src, n);
    }
    if (g_abSubject && AbTest::StandAside()) {
        ++g_control;
        return g_orig(vertexSet, firstReg, src, n);
    }
    g_regs += n;

    const Target t = TargetFor(vertexSet, firstReg);
    const bool learning = (g_verified < kLearnCalls) ||
                          ((unsigned long)g_calls & kResampleMask) == 0;
    if (!learning) {
        ++g_answered;
        return Apply(t, src, firstReg, n);
    }

    // Predict-then-compare: keep what was there, let the client write, then do
    // the same work on the copy and compare what it produced.
    memcpy(g_before, t.copy, (size_t)n * 16);
    const uint32_t lowBefore = *t.low;
    const uint32_t highBefore = *t.high;

    const uint32_t theirs = g_orig(vertexSet, firstReg, src, n);
    const uint32_t theirLow = *t.low, theirHigh = *t.high;

    // Ours, on the state the client started from, written into the snapshot.
    uint32_t low = lowBefore, high = highBefore, reg = firstReg;
    float* dst = g_before;
    const float* s = src;
    for (uint32_t i = 0; i < n; ++i, dst += 4, s += 4, ++reg) {
        const __m128 a = _mm_loadu_ps(s);
        const __m128 b = _mm_loadu_ps(dst);
        if (_mm_movemask_ps(_mm_cmpneq_ps(a, b)) != 0) {
            _mm_storeu_ps(dst, a);
            if (low > reg) low = reg;
            if (high < reg) high = reg;
        }
    }
    if (memcmp(g_before, t.copy, (size_t)n * 16) != 0) {
        Retire("the copy it would have written differs from the client's");
        return theirs;
    }
    if (low != theirLow || high != theirHigh) {
        Retire("the dirty range it would have left differs from the client's");
        return theirs;
    }
    ++g_verified;
    return theirs;
}

bool BytesMatch(uintptr_t addr, const unsigned char* want, size_t n) {
    __try {
        return memcmp((const void*)addr, want, n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

bool Init() {
    if (!Config::g_settings.OptShaderConstDedup) return true;

    if (!BytesMatch(kTarget, kPrologue, sizeof(kPrologue))) {
        char found[64];
        WowOpt_HexBytes(kTarget, found, sizeof(found));
        Log("[ShaderConstDedup] NOT active: the bytes at 0x%08X are not the constant "
            "compare this was read from, so nothing was hooked. Found: %s", (unsigned)kTarget, found);
        return false;
    }
    if (!WowOpt_ClientPatchAllowed((const void*)kTarget)) {
        Log("[ShaderConstDedup] NOT active: No Client Patches is on, and this hooks "
            "a function inside wow.exe.");
        return false;
    }
    if (WineSafe_CreateHook((void*)kTarget, (void*)&Detour, (void**)&g_orig) != MH_OK) {
        Log("[ShaderConstDedup] NOT active: the hook on 0x%08X could not be created.",
            (unsigned)kTarget);
        return false;
    }
    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        MH_RemoveHook((void*)kTarget);
        Log("[ShaderConstDedup] NOT active: the hook on 0x%08X could not be enabled.",
            (unsigned)kTarget);
        return false;
    }
    g_installed = true;
    g_abSubject = AbTest::IsSubject("ShaderConstDedup", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("ShaderConstDedup", (const void*)&Detour);

    Log("[ShaderConstDedup] ACTIVE on the shader constant shadow compare (sub_6833E0 "
        "@ 0x%08X), 1.17%% of executing time in an uncapped tester session. Four x87 "
        "compares and four status-word round trips per register become one packed "
        "compare. There is no arithmetic in it, so the answer is the same bits by "
        "construction. The first %lu calls are answered by the client and the copy "
        "and dirty range compared byte for byte, then one in %lu.",
        (unsigned)kTarget, kLearnCalls, kResampleMask + 1);
    if (g_abSubject)
        Log("[ShaderConstDedup]   under A/B test: the control half runs the client's "
            "function through the same hook.");
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook((void*)kTarget);
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptShaderConstDedup) return;
    if (!g_installed) {
        Log("[ShaderConstDedup] not installed - the reason is at the top of this log");
        return;
    }
    if (g_calls == 0) {
        Log("[ShaderConstDedup] hooked, and no constant update has been reached yet. "
            "That is a measurement: nothing has drawn since it went in.");
        return;
    }
    Log("[ShaderConstDedup] %llu call(s) covering %llu register(s), %llu answered "
        "here; %llu register(s) actually differed and were written. Plain counters, "
        "lower bounds.", g_calls, g_regs, g_answered, g_changed);
    if (g_mismatches) {
        Log("[ShaderConstDedup]   DISABLED after writing something the client did "
            "not; the line that says which is earlier in this log.");
    } else if (g_verified < kLearnCalls) {
        Log("[ShaderConstDedup]   %lu of %lu calls compared with the client so far, "
            "none differed.", g_verified, kLearnCalls);
    } else {
        Log("[ShaderConstDedup]   %lu calls compared with the client byte for byte, "
            "none differed; one in %lu is still compared.",
            g_verified, kResampleMask + 1);
    }
    if (g_odd)
        Log("[ShaderConstDedup]   %llu call(s) named registers outside the copy this "
            "knows about and went straight to the client.", g_odd);
    if (g_abSubject)
        Log("[ShaderConstDedup]   %llu call(s) ran the client's function as the A/B "
            "control half.", g_control);
}

}  // namespace ShaderConstDedup
