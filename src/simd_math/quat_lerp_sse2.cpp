// ============================================================================
// Module: quat_lerp_sse2.cpp
// Description: SSE2 replacement for the M2 quaternion lerp + renormalise.
// Safety & Threading: Main thread, same as the function it replaces.
// ============================================================================
//
// sub_982630 is called once per animated bone per frame from the quaternion
// track, and it is four independent lerps followed by a renormalise. The client
// evaluates each component separately on the x87 stack:
//
//     out[i] = (b[i] - a[i]) * t + a[i]        i = 0..3
//     then sub_982570 scales all four by an approximation of 1/sqrt(|q|^2)
//
// The renormalise is not a sqrt. It is a polynomial estimate of the inverse
// root refined by one to three Newton steps, chosen by how close the squared
// length already is to one - cheap for the almost-unit quaternions a lerp
// produces. That structure is kept exactly as the client has it, including both
// thresholds and all three constants, because it decides how many steps run and
// a different schedule would be a different function.
//
// What changes is that the four components move together.
//
// ---------------------------------------------------------------------------
// The precision question, which this project has got wrong before.
//
// The note in the archive is blunt: every SIMD replacement written in single
// precision was wrong, and the "sub-ULP" comments attached to them were false.
// x87 under MSVC carries 53 bits through the intermediate steps and rounds once
// on store; packed single rounds at every operation.
//
// So the error was measured rather than asserted, over 12 million components of
// randomised near-unit quaternions, against a reference reproducing the client's
// own scheme at double precision:
//
//     all-single : bit-exact 39.27%, worst absolute error 2.980e-07
//     mixed      : bit-exact 62.98%, worst absolute error 2.682e-07
//
// A component lives in [-1, 1] where the float epsilon is 1.2e-07, so the worst
// case is under three epsilon. Carried into a bone rotation that is an angular
// error near 6e-07 radians - under a micrometre at the end of a metre-long bone,
// and the result is renormalised immediately afterwards.
//
// It is not bit-exact and this file does not claim it is. The single-precision
// form is the one used: the mixed form buys 0.3e-07 for a round trip through
// double on every component, which is most of the reason to vectorise at all.
// ---------------------------------------------------------------------------

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>

#include "quat_lerp_sse2.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

namespace QuatLerpSse2 {

namespace {

constexpr uintptr_t kQuatLerp = 0x00982630;

// The client's constants, read out of sub_982570.
constexpr float kC0 = 1.021435f;
constexpr float kC1 = 0.95906597f;
constexpr float kC2 = 0.532516f;
constexpr float kT1 = 0.91521198f;   // one Newton step is enough above this
constexpr float kT2 = 0.6521197f;    // two above this, three below

typedef float* (__cdecl* QuatLerp_fn)(float* out, float t, const float* a, const float* b);
QuatLerp_fn orig_QuatLerp = nullptr;

// How far the two results may stand apart. The measured worst case is 2.98e-07;
// this sits an order of magnitude above it, so it catches a real divergence -
// swapped operands, a misread constant - without tripping on rounding.
constexpr float kTolerance = 4.0e-06f;

constexpr long kLearnCalls   = 20000;
constexpr long kResampleMask = 1023;

unsigned long g_calls      = 0;
unsigned long g_agreements = 0;
float         g_worstSeen  = 0.0f;
volatile LONG g_armed      = 0;
volatile LONG g_dead       = 0;
bool          g_installed  = false;

inline void LerpNormalise(float* out, float t, const float* a, const float* b) {
    __m128 va = _mm_loadu_ps(a);
    __m128 vb = _mm_loadu_ps(b);
    __m128 q  = _mm_add_ps(_mm_mul_ps(_mm_sub_ps(vb, va), _mm_set1_ps(t)), va);

    // |q|^2, summed across the register.
    __m128 sq = _mm_mul_ps(q, q);
    sq = _mm_add_ps(sq, _mm_shuffle_ps(sq, sq, _MM_SHUFFLE(1, 0, 3, 2)));
    sq = _mm_add_ps(sq, _mm_shuffle_ps(sq, sq, _MM_SHUFFLE(2, 3, 0, 1)));
    float v1 = _mm_cvtss_f32(sq);

    // The client's step schedule, unchanged.
    float v2 = kC0 - (v1 - kC1) * kC2;
    float v3;
    if (v1 > kT1) {
        v3 = v2;
    } else {
        v2 = v2 * (kC0 - (v2 * v2 * v1 - kC1) * kC2);
        if (v1 > kT2) v3 = v2;
        else          v3 = (kC0 - (v1 * (v2 * v2) - kC1) * kC2) * v2;
    }

    _mm_storeu_ps(out, _mm_mul_ps(q, _mm_set1_ps(v3)));
}

void Retire(const char* why) {
    if (InterlockedExchange(&g_dead, 1) == 0) {
        Log("[QuatLerp] Disabled for this session: %s. The client's own routine "
            "runs from here on.", why);
    }
}

float* __cdecl Hooked_QuatLerp(float* out, float t, const float* a, const float* b) {
    if (g_dead || !out || !a || !b) return orig_QuatLerp(out, t, a, b);

    unsigned long n = ++g_calls;
    bool verifying = (g_armed == 0) || ((n & kResampleMask) == 0);

    if (!verifying) {
        __try {
            LerpNormalise(out, t, a, b);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Retire("the vector path faulted");
            return orig_QuatLerp(out, t, a, b);
        }
        return out;
    }

    // While verifying, let the client write its own answer through `out` and put
    // ours somewhere else, then compare. The caller keeps the client's result,
    // so a session spent verifying behaves exactly like an unhooked one.
    float theirs[4];
    float mine[4];
    __try {
        orig_QuatLerp(out, t, a, b);
        theirs[0] = out[0]; theirs[1] = out[1]; theirs[2] = out[2]; theirs[3] = out[3];
        LerpNormalise(mine, t, a, b);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Retire("the vector path faulted during verification");
        return out;
    }

    float worst = 0.0f;
    for (int i = 0; i < 4; i++) {
        float d = theirs[i] - mine[i];
        if (d < 0.0f) d = -d;
        if (d > worst) worst = d;
    }
    if (worst > g_worstSeen) g_worstSeen = worst;

    if (worst > kTolerance) {
        Log("[QuatLerp] Diverged by %.3e at t=%.6f, past what rounding explains. "
            "client=(%.7f %.7f %.7f %.7f) ours=(%.7f %.7f %.7f %.7f)",
            worst, t, theirs[0], theirs[1], theirs[2], theirs[3],
            mine[0], mine[1], mine[2], mine[3]);
        Retire("a result differed by more than rounding can explain");
        return out;
    }

    unsigned long ok = ++g_agreements;
    if (g_armed == 0 && ok >= kLearnCalls) {
        InterlockedExchange(&g_armed, 1);
        Log("[QuatLerp] %lu interpolations matched the client within %.1e "
            "(worst seen %.3e). Using the vector path from here; one call in %d "
            "stays checked.", ok, kTolerance, g_worstSeen, (int)(kResampleMask + 1));
    }
    return out;
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptQuatLerpSse2) return true;

    unsigned char* p = (unsigned char*)kQuatLerp;
    if (IsBadReadPtr(p, 8)) {
        Log("[QuatLerp] 0x%08X unreadable - not installing", (unsigned)kQuatLerp);
        return false;
    }

    if (WineSafe_CreateHook((void*)kQuatLerp, (void*)Hooked_QuatLerp,
                            (void**)&orig_QuatLerp) != MH_OK) {
        Log("[QuatLerp] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kQuatLerp) != MH_OK) {
        Log("[QuatLerp] hook created but could not be enabled");
        return false;
    }

    g_installed = true;
    Log("[QuatLerp] ACTIVE on sub_982630, the per-bone quaternion interpolation. "
        "Four components at once instead of one at a time on the x87 stack. "
        "Verifying against the client for the first %ld calls; worst divergence "
        "measured outside the game is 2.98e-07, tolerance here is %.1e.",
        kLearnCalls, kTolerance);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptQuatLerpSse2) return;
    if (!g_installed) { Log("[QuatLerp] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[QuatLerp] installed but never called"); return; }
    Log("[QuatLerp] %lu interpolations, %lu verified, worst divergence %.3e%s",
        g_calls, g_agreements, g_worstSeen,
        g_dead ? " - DISABLED" : (g_armed ? "" : " (still verifying)"));
}

} // namespace QuatLerpSse2
