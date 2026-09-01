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
// The conclusion drawn from that used to be that a vector replacement here can
// only ever be approximate, and this file shipped one: packed single throughout,
// worst absolute error 2.980e-07.
//
// That conclusion had a gap in it. SSE2 does not only have packed single. x87
// under MSVC runs at 53-bit precision control, and 53 bits is exactly what a
// packed double lane carries, so a sequence of packed double operations in the
// client's own order reproduces the client's arithmetic step for step. Two
// lanes instead of four, and bit-exact instead of close.
//
// Measured on 3000000 randomised near-unit quaternion pairs, against a
// reference in Python doubles rounding to single only where the client
// executes `fstp dword`:
//
//     packed double  bit-exact 100.0000%   worst 0.000e+00
//     packed single  bit-exact   6.4893%   worst 2.980e-07
//
// The single-precision row reproduces the 2.980e-07 recorded by the earlier
// measurement, which is what says the reference is the same reference.
//
// Width is the whole of it, and the summation order is not. The four squares
// are now summed left to right, x2 then +y2 then +z2 then +w2, because that is
// what the x87 stack does, and the version this replaces summed them as a
// shuffle tree. That change was measured on its own and makes no difference:
// in double, tree association and the client's order agreed on every one of
// 2000000 randomised quaternions, worst 0.000e+00, even carried through the
// nonlinear step schedule. It is written the client's way because that is
// easier to check against the disassembly, not because it was the defect.
//
// The same question in the matrix-vector hook next door has the same answer,
// and there the reason is plainer: the products of two floats are exact in
// double and the sum is rounded to float immediately, so association cannot
// survive to the result. Four million adversarial samples with the translation
// twenty binary orders above the products found no disagreement either.
//
// The harness proves the scheme. It cannot prove the transcription or that this
// machine's x87 precision control really is 53, so the module compares its
// output with the client's as bit patterns in the running game, with no
// tolerance, and disables itself on the first differing bit.
// ---------------------------------------------------------------------------

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>

#include "quat_lerp_sse2.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"

extern "C" void Log(const char* fmt, ...);

namespace QuatLerpSse2 {

namespace {

constexpr uintptr_t kQuatLerp = 0x00982630;

// The client's constants, read out of sub_982570.
// Read back out of the image as exact bit patterns rather than typed in:
// 3F82BE62, 3F0852F8, 3F758559, 3F26F151, 3F6A4B55 at 0x00AA2E5C upwards. They
// are float constants in the client, so each widens to double exactly.
constexpr double kC0 = 1.02143502235412598;   // flt_AA2E5C
constexpr double kC1 = 0.959065973758697510;  // flt_AA2E64
constexpr double kC2 = 0.532516002655029297;  // flt_AA2E60
constexpr double kT1 = 0.915211975574493408;  // flt_AA2E6C, one step above this
constexpr double kT2 = 0.652119696140289307;  // flt_AA2E68, two above, three below

typedef float* (__cdecl* QuatLerp_fn)(float* out, float t, const float* a, const float* b);
QuatLerp_fn orig_QuatLerp = nullptr;

// No tolerance. Every operation here is the client's operation at the client's
// width in the client's order, so the only correct outcome is the same four
// bit patterns. A tolerance would hide exactly the thing worth catching: if
// this client's x87 precision control is not 53 bits, or a constant is
// misread, or an operand is swapped, the first comparison says so and the
// module retires itself.

constexpr long kLearnCalls   = 20000;
constexpr long kResampleMask = 1023;

unsigned long g_calls      = 0;
unsigned long g_agreements = 0;
volatile LONG g_armed      = 0;
// Set at init when the A/B harness names this module, so the hot path
// tests a plain bool instead of calling out on every invocation.
bool g_abSubject = false;
volatile LONG g_dead       = 0;
bool          g_installed  = false;

inline void LerpNormalise(float* out, float t, const float* a, const float* b) {
    // --- the lerp, sub_982630 ---
    // Four components at once, in double, then rounded to float exactly where
    // the client rounds: it computes each component in x87 and ends the
    // sequence with `fstp dword`, so the interpolated quaternion is single
    // precision before anything else touches it.
    __m128  va  = _mm_loadu_ps(a);
    __m128  vb  = _mm_loadu_ps(b);
    __m128d a01 = _mm_cvtps_pd(va);
    __m128d a23 = _mm_cvtps_pd(_mm_movehl_ps(va, va));
    __m128d b01 = _mm_cvtps_pd(vb);
    __m128d b23 = _mm_cvtps_pd(_mm_movehl_ps(vb, vb));
    __m128d td  = _mm_set1_pd((double)t);

    __m128d q01 = _mm_add_pd(_mm_mul_pd(_mm_sub_pd(b01, a01), td), a01);
    __m128d q23 = _mm_add_pd(_mm_mul_pd(_mm_sub_pd(b23, a23), td), a23);

    float q[4];
    _mm_storeu_ps(q, _mm_movelh_ps(_mm_cvtpd_ps(q01), _mm_cvtpd_ps(q23)));

    // --- the normalise, sub_982570 ---
    // Left to right, which is what the x87 stack does: x*x, then y*y and add,
    // then z*z and add, then w*w and add. The version this replaces summed the
    // four squares as a shuffle tree, (x2+z2)+(y2+w2), which is a different
    // association and therefore a different number however wide the lanes are.
    double x = q[0], y = q[1], z = q[2], w = q[3];
    double v1 = x * x;
    v1 = v1 + y * y;
    v1 = v1 + z * z;
    v1 = v1 + w * w;

    // The client's step schedule. In double, because the client keeps every one
    // of these in an x87 register at 53-bit precision and never stores one to
    // float. Doing it in float, as this used to, rounds five times to 24 bits
    // where the client rounds to 53.
    double v2 = kC0 - (v1 - kC1) * kC2;
    double v3;
    if (v1 > kT1) {
        v3 = v2;
    } else {
        v2 = v2 * (kC0 - (v2 * v2 * v1 - kC1) * kC2);
        if (v1 > kT2) v3 = v2;
        else          v3 = (kC0 - (v1 * (v2 * v2) - kC1) * kC2) * v2;
    }

    // `fld dword [q]; fmul st,st(1); fstp dword [out]` - the float component is
    // widened, multiplied at 53 bits, and rounded once on store.
    __m128d v3d = _mm_set1_pd(v3);
    __m128  qf  = _mm_loadu_ps(q);
    __m128d p01 = _mm_mul_pd(_mm_cvtps_pd(qf), v3d);
    __m128d p23 = _mm_mul_pd(_mm_cvtps_pd(_mm_movehl_ps(qf, qf)), v3d);
    _mm_storeu_ps(out, _mm_movelh_ps(_mm_cvtpd_ps(p01), _mm_cvtpd_ps(p23)));
}

void Retire(const char* why) {
    if (InterlockedExchange(&g_dead, 1) == 0) {
        Log("[QuatLerp] Disabled for this session: %s. The client's own routine "
            "runs from here on.", why);
    }
}

float* __cdecl Hooked_QuatLerpBody(float* out, float t, const float* a, const float* b) {
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

    // Compared as bit patterns, not as numbers. Two floats that differ in the
    // last bit are not equal here, and -0.0 does not pass for 0.0.
    bool same = true;
    for (int i = 0; i < 4; i++) {
        uint32_t bt, bm;
        memcpy(&bt, &theirs[i], 4);
        memcpy(&bm, &mine[i], 4);
        if (bt != bm) { same = false; break; }
    }

    if (!same) {
        Log("[QuatLerp] Differed from the client at t=%.9g. "
            "client=(%08X %08X %08X %08X) ours=(%08X %08X %08X %08X)",
            t,
            *(const uint32_t*)&theirs[0], *(const uint32_t*)&theirs[1],
            *(const uint32_t*)&theirs[2], *(const uint32_t*)&theirs[3],
            *(const uint32_t*)&mine[0], *(const uint32_t*)&mine[1],
            *(const uint32_t*)&mine[2], *(const uint32_t*)&mine[3]);
        Retire("a result was not bit-identical to the client's");
        return out;
    }

    unsigned long ok = ++g_agreements;
    if (g_armed == 0 && ok >= kLearnCalls) {
        InterlockedExchange(&g_armed, 1);
        Log("[QuatLerp] %lu interpolations were bit-identical to the client. "
            "Using the vector path from here; one call in %d stays checked.",
            ok, (int)(kResampleMask + 1));
    }
    return out;
}

// The detour proper, split from the body above so the A/B harness can time
// the call. A scope guard would be the natural way to close that sample on
// every return path, and MSVC refuses object unwinding in a function that
// contains __try - which the body does. This wrapper has none, so one pair
// of reads covers every path the body can leave by.
float* __cdecl Hooked_QuatLerp(float* out, float t, const float* a, const float* b) {
    if (!g_abSubject) return Hooked_QuatLerpBody(out, t, a, b);
    unsigned long long abTick = AbTest::TickIn();
    float* r = AbTest::StandAside() ? orig_QuatLerp(out, t, a, b)
                    : Hooked_QuatLerpBody(out, t, a, b);
    AbTest::TickOut(abTick);
    return r;
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

    g_abSubject = AbTest::IsSubject("QuatLerpSse2");
    if (g_abSubject) {
        Log("[QuatLerp] under A/B test: it alternates on and off in stints, "
            "and AbTest reports both the frame times and the cost of this "
            "call each way. The correctness checks are unaffected.");
    }

    g_installed = true;
    Log("[QuatLerp] ACTIVE on sub_982630, the per-bone quaternion interpolation. "
        "Two components at a time in double rather than one at a time on the "
        "x87 stack, which makes it bit-identical to the client rather than "
        "close to it: x87 under MSVC carries 53 bits and so does a packed "
        "double lane. The first %ld results are compared with the client's as "
        "bit patterns, with no tolerance, and one in %d stays checked after "
        "that. A single differing bit disables it for the session.",
        kLearnCalls, (int)(kResampleMask + 1));
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptQuatLerpSse2) return;
    if (!g_installed) { Log("[QuatLerp] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[QuatLerp] installed but never called"); return; }
    Log("[QuatLerp] %lu interpolations, %lu of them compared with the client "
        "and bit-identical%s",
        g_calls, g_agreements,
        g_dead ? " - DISABLED" : (g_armed ? "" : " (still verifying)"));
}

} // namespace QuatLerpSse2
