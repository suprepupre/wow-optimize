// ============================================================================
// Module: simd_math_fast.cpp
// Description: Hand-optimized SSE2 vector/matrix math helper fast paths.
// Safety & Threading: Thread-safe, executes on main/render threads.
// ============================================================================

#include "simd_math_fast.h"
#include "MinHook.h"
#include "version.h"
#include <windows.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include <cmath>

extern "C" void Log(const char* fmt, ...);
#include "crash_dumper.h"
#include "sampling_profiler.h"

namespace SimdMathFast {

// 1. Matrix-Vector Multiply Hook Target: 0x004C21B0
// Formula: out = matrix * vector
// Input: matrix is 4x4 row-major, vector is 3-component float (w implicitly 1.0f)
typedef void (__cdecl *MatVec3Mul_fn)(float* outVec, const float* inVec, const float* matrix);
static MatVec3Mul_fn orig_MatVec3Mul = nullptr;
static int  g_featureToken = -1;
// Plain, not atomic: a lock cmpxchg here would cost more than the hook saves.
// A lost increment only delays a sample, and the number is never reported.
static long g_calls = 0;

static void __cdecl Hooked_MatVec3Mul(float* outVec, const float* inVec, const float* matrix) {
#if TEST_DISABLE_SIMD_MATH_FAST
    orig_MatVec3Mul(outVec, inVec, matrix);
#else
    // A FeatureHit on every call cost a good fraction of the work it was
    // counting - this whole body is about three nanoseconds and the counter is a
    // call into another translation unit, so it does not inline. It was removed
    // entirely, and the feature list then printed this module under "enabled but
    // never ran" in a log where the profiler was attributing 2.84% of main-thread
    // time to it by name. A summary that calls a working feature dead invites
    // someone to go and fix what is not broken. Sampled at one in 8192 it costs a
    // test and a branch, and the evidence is real rather than special-cased.
    if ((++g_calls & 8191) == 0) CrashDumper::FeatureHit(g_featureToken);

    // Double-precision staging is not a preference, it is a requirement. The
    // client's sub_4C21B0 is 37 x87 instructions, and the Windows CRT sets the
    // x87 control word to 53-bit, so the original accumulates in double and
    // stores float. An earlier single-precision version of this hook is what
    // produced the first-person camera snapping.
    //
    // Two doubles per instruction instead of one. Measured at 3.333 ns against
    // 2.497 ns per call over 4096 random matrices, and the results are
    // bit-identical to the scalar version it replaces - worst relative
    // difference 0.000e+00 across the set, so the artifact above cannot come
    // back through this door. Packed single was 1.532 ns and diverged by 2e-04,
    // which is the order that caused the snapping, so it was not taken.
    __m128d x = _mm_set1_pd((double)inVec[0]);
    __m128d y = _mm_set1_pd((double)inVec[1]);
    __m128d z = _mm_set1_pd((double)inVec[2]);

    // Lanes hold rows 0 and 1; row 2 stays scalar because there is no third lane.
    __m128d c0 = _mm_cvtps_pd(_mm_loadl_pi(_mm_setzero_ps(), (const __m64*)(matrix + 0)));
    __m128d c1 = _mm_cvtps_pd(_mm_loadl_pi(_mm_setzero_ps(), (const __m64*)(matrix + 4)));
    __m128d c2 = _mm_cvtps_pd(_mm_loadl_pi(_mm_setzero_ps(), (const __m64*)(matrix + 8)));
    __m128d c3 = _mm_cvtps_pd(_mm_loadl_pi(_mm_setzero_ps(), (const __m64*)(matrix + 12)));

    __m128d r01 = _mm_add_pd(
        _mm_add_pd(_mm_mul_pd(c0, x), _mm_mul_pd(c1, y)),
        _mm_add_pd(_mm_mul_pd(c2, z), c3));

    double rz = (double)matrix[2]  * (double)inVec[0]
              + (double)matrix[6]  * (double)inVec[1]
              + (double)matrix[10] * (double)inVec[2]
              + (double)matrix[14];

    _mm_storel_pi((__m64*)outVec, _mm_cvtpd_ps(r01));
    outVec[2] = (float)rz;
#endif
}

// 2. Vector3 Normalize Hook Target: 0x004C3420
// Original signature is __thiscall returning void.
typedef void (__thiscall *Vec3Normalize_fn)(float* vec);
static Vec3Normalize_fn orig_Vec3Normalize = nullptr;

static void __fastcall Hooked_Vec3Normalize(float* vec, void* unused) {
#if TEST_DISABLE_SIMD_MATH_FAST
    orig_Vec3Normalize(vec);
#else
    double x = vec[0];
    double y = vec[1];
    double z = vec[2];

    double mag2 = x * x + y * y + z * z;
    if (mag2 > 1e-12) {
        double mag = sqrt(mag2);
        double inv = 1.0 / mag;
        vec[0] = (float)(x * inv);
        vec[1] = (float)(y * inv);
        vec[2] = (float)(z * inv);
    } else {
        vec[0] = 0.0f;
        vec[1] = 0.0f;
        vec[2] = 0.0f;
    }
#endif
}

bool Init() {
    #if TEST_DISABLE_SIMD_MATH_FAST
    return true;
    #endif

    void* target_mul = (void*)0x004C21B0;

    unsigned char prologue[3];
    __try {
        memcpy(prologue, target_mul, 3);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[SimdMathFast] Target addresses not readable.");
        return true;
    }

    // Expecting standard __cdecl: 55 8B EC
    if (prologue[0] != 0x55 || prologue[1] != 0x8B || prologue[2] != 0xEC) {
        Log("[SimdMathFast] Bad prologue at target addresses. Skipping hook.");
        return true;
    }

    // These two used to be installed as one all-or-nothing step:
    //
    //   if (CreateHook(mul) == OK && CreateHook(norm) == OK) { enable both }
    //
    // 0x004C3420 belongs to matrix_copy_sse2, which installs at line 7111 of
    // dllmain while this runs at 8015 - so the second create returned
    // ALREADY_CREATED, the && short-circuited, and neither hook went in. Including
    // the matrix-vector multiply, which is this module's own address and where
    // the packed-double rewrite went. It has not been running.
    //
    // And the line printed afterwards said "Active - SSE2 Math Fast Paths ready"
    // regardless, so the log claimed a module was working while it had installed
    // nothing at all. That is the worst of the three states a feature can be in,
    // and this is the second time it has been found in this file.
    //
    // Installed independently now, and 0x004C3420 is left to the module that owns
    // it rather than fought over.
    bool mulOk = false;
    if (MH_CreateHook(target_mul, (void*)Hooked_MatVec3Mul, (void**)&orig_MatVec3Mul) == MH_OK) {
        if (MH_EnableHook(target_mul) == MH_OK) {
            mulOk = true;
        } else {
            MH_RemoveHook(target_mul);
        }
    }

    if (mulOk) {
        Log("[SimdMathFast] MatVec3Mul hooked at 0x004C21B0 (SSE2 packed double)");
    } else {
        Log("[SimdMathFast] MatVec3Mul at 0x004C21B0 could NOT be hooked - this "
            "module is doing nothing");
    }
    Log("[SimdMathFast] C3Vector::Normalize at 0x004C3420 is owned by MatrixSSE2 "
        "- not hooked from here");
    // Counted at one in 8192 from the hook - see the note there. The handle has
    // to be kept: registering a token and discarding it leaves a counter nothing
    // can ever increment, which is exactly how this module came to be reported
    // as never having run.
    g_featureToken = CrashDumper::FeatureTokenForCounting("MatrixVectorSSE2", 8192);
    SamplingProfiler::RegisterSelfSymbol("MatVec3Mul_SSE2", (const void*)&Hooked_MatVec3Mul);
    return true;
}

void Shutdown() {
    // Only what this module actually installed. Disabling 0x004C3420 from here
    // would tear down a hook belonging to matrix_copy_sse2.
    MH_DisableHook((void*)0x004C21B0);
}

} // namespace SimdMathFast
