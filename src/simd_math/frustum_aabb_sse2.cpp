// ============================================================================
// Module: frustum_aabb_sse2.cpp
// Description: SSE2 rewrite of CFrustum::IsAABBVisible.
// Safety & Threading: Main thread, inside world visibility traversal.
// ============================================================================
//
// sub_9839E0 tests a box against six frustum planes. It is 0.82% of executing
// time in a tester's uncapped session, reached from the world visibility
// traversal, and it is forty-six instructions of which the arithmetic is the
// smaller half.
//
// The larger half is how it picks which corner of the box to test. For each of
// the three components of each plane it reads the plane's sign bit, uses it to
// index a two-entry table of pointers holding the box minimum and maximum, and
// then loads that corner component through the result:
//
//     mov eax, [ecx+4]                  ; plane.z, as bits
//     shr eax, 1Fh                      ; 0 if positive, 1 if negative
//     mov eax, [ebp+eax*4+var_8]        ; -> max corner, or min corner
//     fld dword ptr [eax+8]             ; corner.z
//
// Eighteen of those per call: a sign test, an indexed load, and a dependent load
// through its result. The selection is a blend, and SSE2 does a blend with the
// sign bits themselves as the mask - no branch, no table, no dependent load.
//
// ---------------------------------------------------------------------------
// The association, and why it is safe to reproduce
//
// Read from the instruction order rather than the pseudocode, every plane
// accumulates the same way:
//
//     (((plane.z * corner.z) + (plane.y * corner.y)) + (plane.x * corner.x)) + plane.w
//
// The same order for all six, which is what makes a packed-double version
// answer identically: the x87 control word is left at 53-bit precision, exactly
// what a double lane carries, so each multiply and add rounds where the client's
// does. Nothing is stored to float in between, and nothing here needs to be -
// the value is compared, not kept.
//
// ---------------------------------------------------------------------------
// The comparison passes NaN, and that is deliberate
//
// The client compares with `fcomp` then `test ah, 5` / `jnp`. Working the
// condition codes: C0 is set when the distance is below the threshold and C2
// when the comparison is unordered. Masking both and branching on parity means
// the loop continues when the distance is greater, when it is equal, and when
// either operand is a NaN - only a strictly-below distance exits with zero.
//
// C's `d < threshold` is false for NaN, so `if (d < threshold) return 0;`
// answers identically in all four cases without a special case. Getting this
// backwards would cull geometry whenever a coordinate went bad, which is a
// disappearing-world bug rather than a slow one.
//
// The threshold is the float at 0x00AA2E74, loaded onto the x87 stack once
// before the loop and left there. It is read from the client at Init rather than
// written here as a literal - the decompiler prints it as -0.019444443, and this
// project has already been bitten once by a printed literal that differed from
// the bytes on 29.6% of possible inputs.
//
// ---------------------------------------------------------------------------
// Verification
//
// The function is pure: it reads a frustum and a box and returns 3 or 0, and
// writes nothing. So both versions are simply run and their answers compared,
// with no saving, restoring or predicting - the same shape that made the render
// batch comparator straightforward.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>

#include "frustum_aabb_sse2.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"
#include "ab_test.h"
#include "session_verdict.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace FrustumAabb {

namespace {

constexpr uintptr_t kIsVisible = 0x009839E0;
constexpr uintptr_t kThreshold = 0x00AA2E74;

constexpr int kPlanes = 6;

// __thiscall with one stack argument, ending in `retn 4`.
typedef int (__fastcall* isVisible_fn)(void* frustum, void* edx, void* aabb);
isVisible_fn orig_IsVisible = nullptr;

bool g_installed = false;
bool g_armed     = false;
// Set at init when the A/B harness names this module, so the hot path
// tests a plain bool instead of calling out on every invocation.
bool g_abSubject = false;
bool g_dead      = false;

// Plain 32-bit; this is called hard from the visibility walk. Lower bounds, and
// the report says so.
unsigned long g_calls    = 0;
unsigned long g_verified = 0;
unsigned long g_visible  = 0;

constexpr unsigned long kVerifyFirst  = 20000;
constexpr unsigned long kResampleMask = 4095;

double g_threshold = 0.0;

// Pick the corner the client would pick, for x and y at once.
//
// Loads are eight bytes, never sixteen. A box is three floats of minimum
// followed by three of maximum, so a sixteen-byte load at the maximum would read
// a fourth float that belongs to nothing - real memory most of the time and a
// fault at the end of a page, in a function called from the visibility walk on
// every object in the world. The client reads three floats and so does this.
inline void Corner(const float* mn, const float* mx, const float* pl,
                   __m128d* outXY, double* outZ) {
    __m128 vmn  = _mm_castpd_ps(_mm_load_sd((const double*)mn));
    __m128 vmx  = _mm_castpd_ps(_mm_load_sd((const double*)mx));
    __m128 vpl  = _mm_castpd_ps(_mm_load_sd((const double*)pl));
    // The plane's own sign bits are the mask: a negative component takes the
    // minimum corner and a positive one the maximum. That is exactly the
    // client's `shr eax, 31` table index, without the table or the dependent
    // load it feeds.
    __m128 mask = _mm_castsi128_ps(_mm_srai_epi32(_mm_castps_si128(vpl), 31));
    __m128 sel  = _mm_or_ps(_mm_and_ps(mask, vmn), _mm_andnot_ps(mask, vmx));
    *outXY = _mm_cvtps_pd(sel);

    uint32_t zbits;
    memcpy(&zbits, pl + 2, sizeof(zbits));
    *outZ = (double)((zbits & 0x80000000u) ? mn[2] : mx[2]);
}

// (((plane.z * corner.z) + (plane.y * corner.y)) + (plane.x * corner.x)) + plane.w
// for each of six planes, in that order, stopping the moment one is below the
// threshold. The order is the client's, read from its instruction sequence.
inline int Evaluate(void* frustum, void* aabb) {
    const float* pl = (const float*)frustum;
    const float* mn = (const float*)aabb;
    const float* mx = mn + 3;

    for (int i = 0; i < kPlanes; i++, pl += 4) {
        __m128d cxy;
        double  cz;
        Corner(mn, mx, pl, &cxy, &cz);

        __m128d pxy  = _mm_cvtps_pd(_mm_castpd_ps(_mm_load_sd((const double*)pl)));
        __m128d prod = _mm_mul_pd(pxy, cxy);

        double xterm, yterm;
        _mm_storel_pd(&xterm, prod);
        _mm_storeh_pd(&yterm, prod);

        double d = (((double)pl[2] * cz + yterm) + xterm) + (double)pl[3];

        // Below the threshold is the only outcome that culls. Equal continues,
        // and so does a NaN, because `<` is false for it - which is what the
        // client's parity test on C0 and C2 works out to.
        if (d < g_threshold) return 0;
    }
    return 3;
}

}  // namespace

int __fastcall Hooked_IsVisibleBody(void* frustum, void* edx, void* aabb) {
    g_calls++;
    if (g_dead || !frustum || !aabb) return orig_IsVisible(frustum, edx, aabb);


    if (!g_armed || (g_calls & kResampleMask) == 0) {
        int mine;
        __try {
            mine = Evaluate(frustum, aabb);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return orig_IsVisible(frustum, edx, aabb);
        }
        int theirs = orig_IsVisible(frustum, edx, aabb);
        g_verified++;

        if (mine != theirs) {
            g_dead = true;
            Verdict::Add(Verdict::Bad,
                         "FrustumAabb disagreed with the client and retired itself for "
                         "this session");
            Log("[FrustumAabb] DISAGREED with the client after %lu tests - retired "
                "for this session, every test now goes to the client's own code. "
                "It answered %d and this answered %d.", g_verified, theirs, mine);
            return theirs;
        }
        if (!g_armed && g_verified >= kVerifyFirst) {
            g_armed = true;
            Log("[FrustumAabb] armed: %lu tests agreed with the client. Now "
                "answering directly and rechecking one in %lu.",
                g_verified, kResampleMask + 1);
        }
        if (theirs) g_visible++;
        return theirs;
    }

    __try {
        int r = Evaluate(frustum, aabb);
        if (r) g_visible++;
        return r;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return orig_IsVisible(frustum, edx, aabb);
    }
}

// The detour proper, kept apart from the body above for one reason: the
// A/B harness times the call, and a scope guard that closed the sample on
// every return path cannot be used in a function containing __try - MSVC
// refuses object unwinding alongside SEH. A wrapper has no __try of its own,
// so one pair of reads covers every path the body can take, including the
// ones it takes out of an exception handler.
//
// When no test names this module the whole thing is a branch on a false
// global followed by a direct call.
int __fastcall Hooked_IsVisible(void* frustum, void* edx, void* aabb) {
    if (!g_abSubject) return Hooked_IsVisibleBody(frustum, edx, aabb);
    unsigned long long t = AbTest::TickIn();
    int r = AbTest::StandAside() ? orig_IsVisible(frustum, edx, aabb)
                                       : Hooked_IsVisibleBody(frustum, edx, aabb);
    AbTest::TickOut(t);
    return r;
}

bool Init() {
    if (!Config::g_settings.OptFrustumAabb) return true;

    if (IsBadReadPtr((void*)kIsVisible, 16) || IsBadReadPtr((void*)kThreshold, 4)) {
        Log("[FrustumAabb] 0x%08X unreadable - not installing", (unsigned)kIsVisible);
        return false;
    }
    // push ebp / mov ebp, esp / sub esp, 8
    const unsigned char* p = (const unsigned char*)kIsVisible;
    if (p[0] != 0x55 || p[1] != 0x8B || p[2] != 0xEC || p[3] != 0x83) {
        Log("[FrustumAabb] 0x%08X does not start with the prologue this was read "
            "from (%02X %02X %02X %02X) - not installing",
            (unsigned)kIsVisible, p[0], p[1], p[2], p[3]);
        return false;
    }

    g_threshold = (double)*(const float*)kThreshold;

    if (WineSafe_CreateHook((void*)kIsVisible, (void*)Hooked_IsVisible,
                            (void**)&orig_IsVisible) != MH_OK) {
        Log("[FrustumAabb] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kIsVisible) != MH_OK) {
        Log("[FrustumAabb] hook created but could not be enabled");
        return false;
    }

    g_abSubject = AbTest::IsSubject("FrustumAabb", &g_abSubject);
    if (g_abSubject) {
        Log("[FrustumAabb] under A/B test: it alternates on and off in stints "
            "and AbTest reports the frame times either way. The correctness "
            "checks are unaffected and still retire it on a disagreement.");
    }

    g_installed = true;
    SamplingProfiler::RegisterSelfSymbol("FrustumAabb_SSE2", (const void*)&Hooked_IsVisible);
    Log("[FrustumAabb] ACTIVE on CFrustum::IsAABBVisible (0x%08X), 0.82%% of "
        "executing time in an uncapped tester session. Most of that function is "
        "not arithmetic: for each of three components of each of six planes it "
        "reads the plane's sign bit, indexes a two-entry pointer table with it, "
        "and loads a box corner through the result - eighteen sign tests and "
        "eighteen dependent loads per call. The sign bits are the blend mask in "
        "SSE2, so the table and the dependent loads go away. The threshold is "
        "read from the client at 0x%08X (%.17g), not written here as a literal. "
        "The function is pure, so both answers are compared for the first %lu "
        "calls and one in %lu after that.",
        (unsigned)kIsVisible, (unsigned)kThreshold, g_threshold,
        kVerifyFirst, kResampleMask + 1);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptFrustumAabb) return;
    if (!g_installed) { Log("[FrustumAabb] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[FrustumAabb] installed but never called"); return; }

    Log("[FrustumAabb] %lu visibility tests%s, %lu came back visible (%.1f%%), "
        "%lu verified against the client. Counts are lower bounds.",
        g_calls,
        g_dead ? " - RETIRED on a disagreement"
               : (g_armed ? "" : " - still verifying, the client still answers every one"),
        g_visible, 100.0 * (double)g_visible / (double)g_calls, g_verified);
}

void Shutdown() {
    if (g_installed) MH_DisableHook((void*)kIsVisible);
}

}  // namespace FrustumAabb
