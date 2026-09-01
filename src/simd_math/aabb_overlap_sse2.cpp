// ============================================================================
// Module: aabb_overlap_sse2.cpp
// Description: SSE2 replacement for the client's box-overlap predicate.
// Safety & Threading: Main thread, same as the function it replaces.
// ============================================================================
//
// sub_78F370 asks whether two axis-aligned boxes overlap. It is 39 instructions,
// eight basic blocks, and seventeen functions call it - the scene-graph culling
// walks (sub_7A50C0 and its five siblings at 0x7A5xxx), the visibility passes at
// 0x7B5xxx to 0x7BCxxx, and the pick test at 0x7D9F90. Each of them calls it once
// per node, per pass, per frame.
//
// What it costs is not the comparing. It is how each answer leaves the x87 stack:
//
//     fld   dword ptr [ecx+0Ch]
//     fcomp dword ptr [edx]
//     fnstsw ax                    <- FPU status word into AX
//     test  ah, 1
//     jnz   reject
//
// six times over. fnstsw is the slowest way a floating-point comparison can reach
// an integer register, and there are six of them; each of the six branches is
// then decided by scene data, so a walk over a mixed set of nodes mispredicts on
// most of them.
//
// ---------------------------------------------------------------------------
// Why this one is bit-exact rather than close
//
// There is no arithmetic in it at all. Six floats are loaded and compared against
// six floats; nothing is added, multiplied or rounded. Widening a float to double
// is exact and order-preserving, so an ordered packed compare of the same two
// floats answers identically to fcom on the widened pair - for every input,
// including every NaN. That is the one shape in this project needing no
// tolerance, no error table and no harness. The same reasoning carries the
// collision outcode replacement in this directory.
//
// ---------------------------------------------------------------------------
// The predicate, read out of the disassembly rather than the decompiler
//
// Two different flag tests, and the second is the one worth getting right:
//
//   fcomp ; test ah, 1   ; jnz reject  -> C0 is less-than, so this passes on
//                                         >= and rejects unordered, which sets C0.
//   fcomp ; test ah, 41h ; jp  reject  -> mask C3|C0. Less-than sets one bit,
//                                         equal sets one bit, greater-than sets
//                                         none, and unordered sets C3, C2 and C0
//                                         and so leaves two bits under the mask.
//                                         Odd parity is therefore <=, ordered.
//
// So, with self and other each laid out as three minimum floats then three
// maximum floats:
//
//     self[3] >= other[0]      self[0] <= other[3]
//     self[4] >= other[1]      self[1] <= other[4]
//     self[5] >= other[2]      self[2] <= other[5]
//
// which is the separating-axis test on three axes: the boxes overlap unless one
// lies entirely past the other along some axis. A NaN anywhere returns 0.
//
// _mm_cmpge_ps and _mm_cmple_ps are both ordered and both false on a NaN operand,
// so the replacement rejects a NaN box exactly where the client does. Signed zero
// compares equal under fcom and under cmpps alike.
//
// ---------------------------------------------------------------------------
// Reading twenty-four bytes where the client sometimes reads twelve
//
// The client short-circuits: a box rejected on the first axis never has self[4]
// or self[5] loaded. This reads both objects whole, as two overlapping sixteen-
// byte loads covering exactly [0,24) - no byte past either object.
//
// That is a wider read than the client's earliest exit makes, and it is left
// unguarded deliberately. There is no __try here: on a function this small the
// exception registration record would cost a good part of what vectorising saves.
// What makes it safe is that the client's own accepting path reads all twenty-
// four bytes of both objects, so any allocation that could fault here would
// already fault in the client whenever two boxes overlap - and boxes overlap
// constantly. A pointer this hook can crash on is one the client crashes on
// first.
//
// ---------------------------------------------------------------------------
// Verification
//
// The predicate is pure: it writes nothing, reads two objects and returns a
// boolean, so the learning-phase shape applies directly and cheaply. Both run,
// the answers are compared, and the client's own answer is handed back. After
// enough agreements this arms and stops calling the client, then resamples. A
// disagreement retires the hook for the session and says so in the log.
//
// The comparison is also what covers the one assumption this file cannot prove by
// reading: that MXCSR has denormals-are-zero clear. DAZ applies to the inputs of
// a packed compare and not to fcom, so a denormal coordinate under DAZ is the one
// way these two could differ. Denormal world coordinates are not a real thing at
// metre scale, but the verifier does not need them to be - it would catch it.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>

#include "aabb_overlap_sse2.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"
#include "ab_test.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace AabbOverlap {

namespace {

constexpr uintptr_t kOverlap = 0x0078F370;

// __thiscall with one stack argument and `retn 4`. Reached as __fastcall: the
// object lands in ECX, the unused second parameter in EDX and is never pushed,
// and the callee cleans the one that is.
typedef int (__fastcall* overlap_fn)(const float* self, void* edx, const float* other);
overlap_fn orig_Overlap = nullptr;

bool g_installed = false;
bool g_armed     = false;
// Set at init when the A/B harness names this module, so the hot path
// tests a plain bool instead of calling out on every invocation.
bool g_abSubject = false;
bool g_dead      = false;

// Plain 32-bit on a leaf this hot. A lost increment costs a number, and the
// report says the numbers are lower bounds.
unsigned long g_calls    = 0;
unsigned long g_verified = 0;
unsigned long g_overlaps = 0;

constexpr unsigned long kVerifyFirst  = 20000;
constexpr unsigned long kResampleMask = 4095;

// The whole function. Four loads, three shuffles, two compares, one and, one
// movemask - against six fld/fcomp/fnstsw/test/jcc groups.
inline int Sse2Overlap(const float* self, const float* other) {
    // Both pairs of loads stay inside the twenty-four bytes: [0,16) and [8,24).
    __m128 s0 = _mm_loadu_ps(self);          // s0 s1 s2 s3
    __m128 s2 = _mm_loadu_ps(self + 2);      // s2 s3 s4 s5
    __m128 o0 = _mm_loadu_ps(other);         // o0 o1 o2 o3
    __m128 o2 = _mm_loadu_ps(other + 2);     // o2 o3 o4 o5

    // Line self[3..5] up against other[0..2] in lanes 1..3, and self[0..2]
    // against other[3..5] in lanes 0..2.
    __m128 lo = _mm_shuffle_ps(o0, o0, _MM_SHUFFLE(2, 1, 0, 0));   // o0 o0 o1 o2
    __m128 hi = _mm_shuffle_ps(o2, o2, _MM_SHUFFLE(3, 3, 2, 1));   // o3 o4 o5 o5

    __m128 ge = _mm_cmpge_ps(s2, lo);   // lanes 1,2,3: self[3..5] >= other[0..2]
    __m128 le = _mm_cmple_ps(s0, hi);   // lanes 0,1,2: self[0..2] <= other[3..5]

    // Slide the three lanes that matter in `ge` down onto the three in `le`.
    __m128 geLo = _mm_shuffle_ps(ge, ge, _MM_SHUFFLE(3, 3, 2, 1));
    return (_mm_movemask_ps(_mm_and_ps(geLo, le)) & 7) == 7;
}

}  // namespace

int __fastcall Hooked_Overlap(const float* self, void* edx, const float* other) {
    g_calls++;

    if (g_dead) return orig_Overlap(self, edx, other);

    // Under the A/B harness this feature alternates on and off in stints
    // so its frame times can be compared against the client doing the same
    // work in the same zone. One predictable branch on a false global when
    // no test names this module.
    if (g_abSubject && AbTest::StandAside()) return orig_Overlap(self, edx, other);

    int mine = Sse2Overlap(self, other);

    // Unarmed, or one call in kResampleMask+1 afterwards: run the client's own
    // code and compare. Its answer is the one returned either way.
    if (!g_armed || (g_calls & kResampleMask) == 0) {
        int theirs = orig_Overlap(self, edx, other);
        g_verified++;
        if ((theirs != 0) != (mine != 0)) {
            g_dead = true;
            Log("[AabbOverlap] DISAGREED with the client after %lu checks "
                "(client said %d, this said %d) - retired for this session, "
                "every call now goes to the client's own code",
                g_verified, theirs, mine);
            return theirs;
        }
        if (!g_armed && g_verified >= kVerifyFirst) {
            g_armed = true;
            Log("[AabbOverlap] armed: %lu calls agreed with the client exactly, "
                "now answering directly and rechecking one call in %lu",
                g_verified, kResampleMask + 1);
        }
        if (theirs) g_overlaps++;
        return theirs;
    }

    if (mine) g_overlaps++;
    return mine;
}

bool Init() {
    if (!Config::g_settings.OptAabbOverlap) return true;

    if (IsBadReadPtr((void*)kOverlap, 16)) {
        Log("[AabbOverlap] 0x%08X unreadable - not installing", (unsigned)kOverlap);
        return false;
    }
    if (WineSafe_CreateHook((void*)kOverlap, (void*)Hooked_Overlap,
                            (void**)&orig_Overlap) != MH_OK) {
        Log("[AabbOverlap] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kOverlap) != MH_OK) {
        Log("[AabbOverlap] hook created but could not be enabled");
        return false;
    }

    g_abSubject = AbTest::IsSubject("AabbOverlap");
    if (g_abSubject) {
        Log("[AabbOverlap] under A/B test: it alternates on and off in stints "
            "and AbTest reports the frame times either way. The correctness "
            "checks are unaffected and still retire it on a disagreement.");
    }

    g_installed = true;
    SamplingProfiler::RegisterSelfSymbol("AabbOverlap_SSE2", (const void*)&Hooked_Overlap);
    Log("[AabbOverlap] ACTIVE on sub_78F370 (0x%08X), the box-overlap test that "
        "seventeen functions call once per scene node per culling pass. Six x87 "
        "compares, each leaving the FPU through fnstsw and a data-dependent "
        "branch, replaced by two packed compares and one movemask. The boxes are "
        "plain floats with no arithmetic applied, so this is bit-exact rather "
        "than close. Checking against the client for the first %lu calls, then "
        "one in %lu.",
        (unsigned)kOverlap, kVerifyFirst, kResampleMask + 1);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptAabbOverlap) return;
    if (!g_installed) { Log("[AabbOverlap] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[AabbOverlap] installed but never called"); return; }

    Log("[AabbOverlap] %lu calls, %lu boxes overlapped (%.1f%%), %lu verified "
        "against the client%s. Counts are lower bounds.",
        g_calls, g_overlaps,
        g_calls ? (100.0 * (double)g_overlaps / (double)g_calls) : 0.0,
        g_verified,
        g_dead ? " - RETIRED on a disagreement"
               : (g_armed ? " - armed" : " - still verifying, every call still "
                                         "runs the client's code as well"));
}

void Shutdown() {
    if (g_installed) MH_DisableHook((void*)kOverlap);
}

}  // namespace AabbOverlap
