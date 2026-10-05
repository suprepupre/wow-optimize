// ============================================================================
// Module: particle_loop_prefetch.cpp
//
// Software prefetch two particles ahead in the three loops that walk an
// emitter's particles through an index array.
//
// The evidence. In the drain profile of 2026-10-04 (uncapped) the address
// 0x97DDE1 is 1.94% of executing time. It is `fadd st, st(1)` and the
// instruction before it is `fld dword ptr [ecx]`, the load of a particle's age
// in sub_97DD20, the emitter update loop. Everything the loop does to a
// particle (the integration, the track evaluation, the fill) is thousands of
// instructions and the next particle's load is not issued until the body has
// finished, so the out-of-order window never reaches it: each particle's first
// touch waits for the whole of its cache miss. The particles are not walked in
// storage order either. The loop reads a particle number from an index array
// (emitter+0x54), shifts it by 5 or 6 (record size, chosen by the flag at
// +0x98) and adds the base (+0x34 or +0x44), so the hardware prefetcher has no
// stride to follow.
//
// The index array is in order and is known: entry i+2 is one load away. This
// computes that particle's address and issues prefetcht0 on both ends of its
// record, a whole iteration or two before the loop reaches it.
//
// Three sites, the same three instructions at the top of each loop:
//
//     0x97DDC0   sub_97DD20 update loop, emitters with no spin variation at +0xA8
//     0x97DE70   sub_97DD20 update loop, the other one
//     0x97E650   sub_97E580 fill loop (the one ParallelParticles replaces), where
//                the particle's first touch is the age read in sub_97BE80
//
// Each starts with `cmp dword ptr [esi+98h], 0`, seven bytes, and each loop reads
// its flag from the result a few instructions later. The hook is a function-level
// MinHook detour on that instruction: the thunk prefetches, then jumps to the
// trampoline, which runs the displaced cmp (so the flags the loop tests are the
// client's own) and carries on. EAX, ECX and EDX are written by the loop before it
// reads them at all three sites, which is why the thunk may use them, and the x87
// stack and ESI, EDI, EBX, EBP are never touched.
//
// Why no verification phase: a prefetch cannot fault, change a flag, change a
// register or change what any later instruction computes, on any address, mapped
// or not. The one load this adds that can fault is the index entry, and it is
// bounded by the same count the client's loop tests (emitter+0x50 for the update
// loop, EBX for the fill loop) so it is inside an array the client reads next.
//
// What is not measured: the saving. The report counts what the thunks did, and
// the module is an A/B subject, so the effect on frame time is for FrameBench.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "particle_loop_prefetch.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

// File scope and outside any namespace: the naked thunks name these from inline
// assembly, which does not resolve namespace-qualified symbols.
static void*    g_plpOrigUpdateA = nullptr;
static void*    g_plpOrigUpdateB = nullptr;
static void*    g_plpOrigFill    = nullptr;
static bool     g_plpOn          = true;      // the A/B harness owns this once registered
static uint32_t g_plpCalls[3]    = {};
static uint32_t g_plpIssued[3]   = {};

// How many particles ahead. An iteration is at least a few hundred cycles even when
// the particle is skipped, a miss to memory is about the same, so one ahead would
// often be late and three is more than the walk ever needs.
#define PLP_AHEAD 2

__declspec(naked) static void ThunkUpdateA() {
    __asm {
        cmp  byte ptr [g_plpOn], 0
        je   go
        add  dword ptr [g_plpCalls], 1
        lea  ecx, [edi + PLP_AHEAD]
        cmp  ecx, [esi + 50h]
        jae  go
        mov  edx, [esi + 54h]
        mov  eax, [edx + ecx*4]
        cmp  dword ptr [esi + 98h], 0
        jnz  big
        shl  eax, 5
        add  eax, [esi + 34h]
        prefetcht0 [eax]
        prefetcht0 [eax + 31]
        add  dword ptr [g_plpIssued], 1
        jmp  go
    big:
        shl  eax, 6
        add  eax, [esi + 44h]
        prefetcht0 [eax]
        prefetcht0 [eax + 63]
        add  dword ptr [g_plpIssued], 1
    go:
        jmp  dword ptr [g_plpOrigUpdateA]
    }
}

__declspec(naked) static void ThunkUpdateB() {
    __asm {
        cmp  byte ptr [g_plpOn], 0
        je   go
        add  dword ptr [g_plpCalls + 4], 1
        lea  ecx, [edi + PLP_AHEAD]
        cmp  ecx, [esi + 50h]
        jae  go
        mov  edx, [esi + 54h]
        mov  eax, [edx + ecx*4]
        cmp  dword ptr [esi + 98h], 0
        jnz  big
        shl  eax, 5
        add  eax, [esi + 34h]
        prefetcht0 [eax]
        prefetcht0 [eax + 31]
        add  dword ptr [g_plpIssued + 4], 1
        jmp  go
    big:
        shl  eax, 6
        add  eax, [esi + 44h]
        prefetcht0 [eax]
        prefetcht0 [eax + 63]
        add  dword ptr [g_plpIssued + 4], 1
    go:
        jmp  dword ptr [g_plpOrigUpdateB]
    }
}

// The fill loop's count is in EBX, not in the emitter: it fills `arg_4` particles.
__declspec(naked) static void ThunkFill() {
    __asm {
        cmp  byte ptr [g_plpOn], 0
        je   go
        add  dword ptr [g_plpCalls + 8], 1
        lea  ecx, [edi + PLP_AHEAD]
        cmp  ecx, ebx
        jae  go
        mov  edx, [esi + 54h]
        mov  eax, [edx + ecx*4]
        cmp  dword ptr [esi + 98h], 0
        jnz  big
        shl  eax, 5
        add  eax, [esi + 34h]
        prefetcht0 [eax]
        prefetcht0 [eax + 31]
        add  dword ptr [g_plpIssued + 8], 1
        jmp  go
    big:
        shl  eax, 6
        add  eax, [esi + 44h]
        prefetcht0 [eax]
        prefetcht0 [eax + 63]
        add  dword ptr [g_plpIssued + 8], 1
    go:
        jmp  dword ptr [g_plpOrigFill]
    }
}

namespace ParticleLoopPrefetch {

namespace {

struct Site {
    uintptr_t   addr;
    const char* name;
    void*       thunk;
    void**      orig;
    // What the client has at the site and for a few instructions after it: the
    // displaced cmp, then the two or three instructions the loop reads its flag
    // and its particle pointer with. One byte out of place means no hook.
    unsigned char want[13];
    bool        installed;
};

Site g_sites[3] = {
    { 0x0097DDC0, "update loop, no variation", (void*)&ThunkUpdateA, &g_plpOrigUpdateA,
      { 0x83, 0xBE, 0x98, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x56, 0x54, 0x8B, 0x04, 0xBA }, false },
    { 0x0097DE70, "update loop, lifetime variation", (void*)&ThunkUpdateB, &g_plpOrigUpdateB,
      { 0x83, 0xBE, 0x98, 0x00, 0x00, 0x00, 0x00, 0xD9, 0x05, 0x34, 0x11, 0x9E, 0x00 }, false },
    { 0x0097E650, "fill loop", (void*)&ThunkFill, &g_plpOrigFill,
      { 0x83, 0xBE, 0x98, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x46, 0x54, 0x8B, 0x04, 0xB8 }, false },
};

bool g_any = false;
bool g_abSubject = false;
uint64_t g_seenCalls[3] = {}, g_seenIssued[3] = {};
uint32_t g_lastCalls[3] = {}, g_lastIssued[3] = {};

bool BytesMatch(uintptr_t addr, const unsigned char* want, size_t n) {
    __try {
        return memcmp((const void*)addr, want, n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

bool Init() {
    if (!Config::g_settings.OptParticleLoopPrefetch) return true;

    if (!WowOpt_ClientPatchAllowed((const void*)g_sites[0].addr)) {
        Log("[ParticleLoopPrefetch] NOT active: No Client Patches is on, and this hooks "
            "instructions inside wow.exe.");
        return false;
    }
    for (int i = 0; i < 3; ++i) {
        Site& s = g_sites[i];
        if (!BytesMatch(s.addr, s.want, sizeof(s.want))) {
            Log("[ParticleLoopPrefetch] %s at 0x%08X NOT hooked: the bytes there are not the "
                "ones this was written against. Either the client differs from build 12340 or "
                "something patched it first (ParallelParticles replaces the fill loop's head "
                "when it is on).", s.name, (unsigned)s.addr);
            continue;
        }
        if (WineSafe_CreateHook((void*)s.addr, s.thunk, s.orig) != MH_OK) {
            Log("[ParticleLoopPrefetch] %s at 0x%08X NOT hooked: the hook could not be created.",
                s.name, (unsigned)s.addr);
            continue;
        }
        if (WO_EnableHook((void*)s.addr) != MH_OK) {
            MH_RemoveHook((void*)s.addr);
            Log("[ParticleLoopPrefetch] %s at 0x%08X NOT hooked: the hook could not be enabled.",
                s.name, (unsigned)s.addr);
            continue;
        }
        s.installed = true;
        g_any = true;
    }
    if (!g_any) return false;

    g_abSubject = AbTest::IsSubject("ParticleLoopPrefetch", &g_plpOn);
    SamplingProfiler::RegisterSelfSymbol("ParticleLoopPrefetch", (const void*)&ThunkUpdateA);

    Log("[ParticleLoopPrefetch] ACTIVE on %d of 3 loops that walk an emitter's particles through "
        "an index array (0x%08X, 0x%08X, 0x%08X). The profile puts 1.94%% of executing time on "
        "the load of a particle's first field in the update loop: the particles are not in storage "
        "order and one iteration is thousands of instructions, so each load waits out its whole "
        "cache miss. This prefetches the particle %d ahead. A prefetch changes no register, flag "
        "or result, so there is no learning phase.",
        (int)g_sites[0].installed + (int)g_sites[1].installed + (int)g_sites[2].installed,
        (unsigned)g_sites[0].addr, (unsigned)g_sites[1].addr, (unsigned)g_sites[2].addr, PLP_AHEAD);
    if (g_abSubject)
        Log("[ParticleLoopPrefetch]   under A/B test: the control half runs the loops without it.");
    return true;
}

void Shutdown() {
    for (int i = 0; i < 3; ++i) {
        if (!g_sites[i].installed) continue;
        MH_DisableHook((void*)g_sites[i].addr);
        g_sites[i].installed = false;
    }
    g_any = false;
}

void LogStats() {
    if (!Config::g_settings.OptParticleLoopPrefetch) return;
    if (!g_any) {
        Log("[ParticleLoopPrefetch] not installed - the reason is at the top of this log");
        return;
    }
    // The thunks keep 32-bit counters; fold the difference since the last report into
    // 64-bit totals, which is exact as long as one report interval holds under 2^32 calls.
    for (int i = 0; i < 3; ++i) {
        const uint32_t c = g_plpCalls[i], p = g_plpIssued[i];
        g_seenCalls[i]  += (uint32_t)(c - g_lastCalls[i]);
        g_seenIssued[i] += (uint32_t)(p - g_lastIssued[i]);
        g_lastCalls[i] = c; g_lastIssued[i] = p;
    }
    for (int i = 0; i < 3; ++i) {
        if (!g_sites[i].installed) {
            Log("[ParticleLoopPrefetch]   %s: not hooked", g_sites[i].name);
            continue;
        }
        if (g_seenCalls[i] == 0) {
            Log("[ParticleLoopPrefetch]   %s: hooked, and the loop has not run since it went in "
                "(or every pass was in an A/B control half)", g_sites[i].name);
            continue;
        }
        Log("[ParticleLoopPrefetch]   %s: %llu iteration(s), %llu with a particle ahead to "
            "prefetch (%.1f%%). Plain counters, lower bounds; this says what it did and not "
            "what it saved.", g_sites[i].name, g_seenCalls[i], g_seenIssued[i],
            100.0 * (double)g_seenIssued[i] / (double)g_seenCalls[i]);
    }
}

}  // namespace ParticleLoopPrefetch
