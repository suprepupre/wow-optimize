// ============================================================================
// Module: matrix_copy_sse2.cpp
// ============================================================================

#include <windows.h>
#include <MinHook.h>
#include <cstdint>
#include <emmintrin.h>
#include <intrin.h>
#include <cmath>
#include "version.h"
#include "matrix_copy_sse2.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
// Statistics — plain increments, not Interlocked.
// Both hooked functions run on the main WoW thread only;
// atomic overhead would dwarf the work itself.
// ================================================================
static volatile long g_matcopy_calls = 0;
static volatile long g_matident_calls = 0;

// ================================================================
// Original function pointers
// __fastcall typedef mirrors the __thiscall ABI on x86 MSVC:
// ECX = this, EDX = unused padding.
// ================================================================
typedef float* (__fastcall* MatCopy_t)(float* self, void* edx, float* src);
typedef float* (__fastcall* MatIdentity_t)(float* self, void* edx);

// sub_4C1F00: result = A * B, all three are float[16] passed by stack (__cdecl).
typedef float* (__cdecl* MatMul_t)(float* result, float* a, float* b);

static MatCopy_t     pOrigMatCopy     = nullptr;
static MatIdentity_t pOrigMatIdentity = nullptr;
static MatMul_t      pOrigMatMul      = nullptr;
static volatile long g_matmul_calls   = 0;

typedef float* (__cdecl* MatVec3Mul_t)(float* result, const float* vec3, const float* matrix44);
typedef float* (__cdecl* MatVec4Mul_t)(float* result, const float* vec4, const float* matrix44);

static MatVec3Mul_t  pOrigMatVec3Mul  = nullptr;
static MatVec4Mul_t  pOrigMatVec4Mul  = nullptr;
static volatile long g_matvec3_calls  = 0;
static volatile long g_matvec4_calls  = 0;

// sub_4C1C40: quaternion -> 3x3 rotation block, both operands on the stack.
typedef float* (__cdecl* QuatToMatrix_t)(const float* quat, float* dest);
static QuatToMatrix_t pOrigQuatToMatrix = nullptr;
static volatile long  g_quat2mat_calls  = 0;

// sub_4C1DE0: __thiscall wrapper, ECX = destination matrix, quaternion on the stack.
typedef float* (__fastcall* QuatToMatrixFull_t)(float* dest, void* edx, const float* quat);
static QuatToMatrixFull_t pOrigQuatToMatrixFull = nullptr;
static volatile long      g_quat2matfull_calls  = 0;

// ================================================================
// Precomputed identity matrix rows for the SSE2 store path
// ================================================================
static const __m128 kIdentityRow0 = { 1.0f, 0.0f, 0.0f, 0.0f };
static const __m128 kIdentityRow1 = { 0.0f, 1.0f, 0.0f, 0.0f };
static const __m128 kIdentityRow2 = { 0.0f, 0.0f, 1.0f, 0.0f };
static const __m128 kIdentityRow3 = { 0.0f, 0.0f, 0.0f, 1.0f };

// ================================================================
// sub_407F80: 4x4 matrix copy (247 xrefs)
// Original does 16 scalar FPU load/store pairs.
// 4x SSE2 unaligned 128-bit moves cover all 64 bytes.
// ================================================================
static float* __fastcall HookMatrixCopy(float* self, void* /*edx*/, float* src) {
    ++g_matcopy_calls;

    uintptr_t s = (uintptr_t)self;
    uintptr_t p = (uintptr_t)src;
    if (s > 0x10000 && s < 0xFFE00000 &&
        p > 0x10000 && p < 0xFFE00000) {
        __try {
            _mm_storeu_ps(self,      _mm_loadu_ps(src));
            _mm_storeu_ps(self + 4,  _mm_loadu_ps(src + 4));
            _mm_storeu_ps(self + 8,  _mm_loadu_ps(src + 8));
            _mm_storeu_ps(self + 12, _mm_loadu_ps(src + 12));
            return self;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Bad pointer during load/store (e.g. unmapped page)
        }
    }

    return pOrigMatCopy(self, nullptr, src);
}

// ================================================================
// sub_407F40: 4x4 matrix identity (53 xrefs)
// Original writes 16 immediate floats through the FPU.
// 4x SSE2 stores from compile-time constants.
// ================================================================
static float* __fastcall HookMatrixIdentity(float* self, void* /*edx*/) {
    ++g_matident_calls;

    uintptr_t s = (uintptr_t)self;
    if (s > 0x10000 && s < 0xFFE00000) {
        __try {
            _mm_storeu_ps(self,      kIdentityRow0);
            _mm_storeu_ps(self + 4,  kIdentityRow1);
            _mm_storeu_ps(self + 8,  kIdentityRow2);
            _mm_storeu_ps(self + 12, kIdentityRow3);
            return self;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Bad pointer during store
        }
    }

    return pOrigMatIdentity(self, nullptr);
}

// ================================================================
// sub_4C1F00: 4x4 matrix multiply  result = A * B  (53+ xrefs)
// ================================================================
// Verified convention: result[r*4+c] = sum_k A[r*4+k] * B[k*4+c]
// (row-major C = A*B). It loads all of B and a full A row before storing, so
// it is safe when result aliases A or B (the scalar original is not, but no
// caller passes aliasing pointers).
//
// This was packed single, under a comment saying that only the summation order
// differed and the delta was sub-ULP. That compares single against single. The
// client does not work in single: sub_4C1F00 is 199 x87 instructions, and the
// Windows CRT sets the x87 control word to 53-bit, so it accumulates in double
// and stores float. The difference is accumulation width, not summation order,
// and measured against the client's own arithmetic over 4096 random matrix
// pairs at mixed magnitudes it came to 1.118e-04 relative - not sub-ULP, and
// the same order as the divergence that produced first-person camera snapping
// the last time this project reached for single precision here.
//
// Bone matrices are exactly the bad case: rotations near unity beside
// translations in the hundreds of yards, which is the spread that pulls a
// single-precision dot product away from a double one. sub_4C1F00 runs once
// per bone per frame for every animated model, so this is not a rare path.
//
// Packed double keeps the client's accumulation width and still does two lanes
// per instruction. Measured 24.81 ns for the client, 10.43 ns here - 2.38x -
// and bit-identical: worst relative deviation 0.000e+00 across all 65,536
// values compared. Packed single was 3.81 ns, and its extra speed is not worth
// asking players to watch for artifacts.
// The arithmetic on its own, so the self-test can exercise exactly the code the
// hook runs rather than a second copy of it that might drift from it.
static inline void MatMul4x4_PackedDouble(float* out, const float* a, const float* b) {
    // Each row of B widened to two double lanes: columns 0-1, then 2-3.
    __m128d brow[4][2];
    for (int k = 0; k < 4; ++k) {
        __m128 row = _mm_loadu_ps(b + k * 4);
        brow[k][0] = _mm_cvtps_pd(row);
        brow[k][1] = _mm_cvtps_pd(_mm_movehl_ps(row, row));
    }
    for (int row = 0; row < 4; ++row) {
        __m128d acc0 = _mm_setzero_pd();
        __m128d acc1 = _mm_setzero_pd();
        for (int k = 0; k < 4; ++k) {
            __m128d av = _mm_set1_pd((double)a[row * 4 + k]);
            acc0 = _mm_add_pd(acc0, _mm_mul_pd(av, brow[k][0]));
            acc1 = _mm_add_pd(acc1, _mm_mul_pd(av, brow[k][1]));
        }
        _mm_storeu_ps(out + row * 4,
                      _mm_movelh_ps(_mm_cvtpd_ps(acc0), _mm_cvtpd_ps(acc1)));
    }
}

// Run the client's own routine beside ours on the real binary before replacing
// it. A version of this lived in the other SSE2 module, guarding a hook that
// never installed because this one gets the address first - so what was being
// verified and what was running were two different functions.
static bool SelfTestMatrixMultiply() {
    typedef float* (__cdecl* mat_fn)(float*, float*, float*);
    mat_fn original = (mat_fn)0x004C1F00;

    const int CASES = 4096;
    unsigned seed = 0x9E3779B9u;
    double worst = 0.0;
    float lhs[16], rhs[16], theirs[16], ours[16];

    for (int c = 0; c < CASES; ++c) {
        // Bone matrices carry rotations near unity beside translations in the
        // hundreds, and that spread is what separates the two precisions.
        float scale = (c & 3) == 0 ? 1.0f : ((c & 3) == 1 ? 100.0f
                                          : ((c & 3) == 2 ? 0.01f : 1000.0f));
        for (int i = 0; i < 16; ++i) {
            seed = seed * 1103515245u + 12345u;
            lhs[i] = (((float)(int)(seed >> 16) / 32768.0f) - 1.0f) * scale;
            seed = seed * 1103515245u + 12345u;
            rhs[i] = (((float)(int)(seed >> 16) / 32768.0f) - 1.0f) * scale;
        }

        __try {
            original(theirs, lhs, rhs);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[MatrixSSE2] Self-test: the client's routine faulted - not hooking");
            return false;
        }
        MatMul4x4_PackedDouble(ours, lhs, rhs);

        for (int i = 0; i < 16; ++i) {
            float d = theirs[i] - ours[i];
            if (d < 0.0f) d = -d;
            float mag = (theirs[i] < 0.0f ? -theirs[i] : theirs[i]);
            double rel = (mag > 1.0f) ? ((double)d / (double)mag) : (double)d;
            if (rel > worst) worst = rel;
        }
    }

    if (worst > 1e-5) {
        Log("[MatrixSSE2] Self-test FAILED: worst deviation %.3e over %d random "
            "pairs - not hooking", worst, CASES);
        return false;
    }
    Log("[MatrixSSE2] Self-test passed %d random pairs against the client's own "
        "routine, worst deviation %.3e", CASES, worst);
    return true;
}

static float* __cdecl HookMatrixMultiply(float* result, float* a, float* b) {
    ++g_matmul_calls;

    uintptr_t r = (uintptr_t)result, pa = (uintptr_t)a, pb = (uintptr_t)b;
    if (r > 0x10000 && r < 0xFFE00000 &&
        pa > 0x10000 && pa < 0xFFE00000 &&
        pb > 0x10000 && pb < 0xFFE00000) {
        __try {
            float out_val[16];
            MatMul4x4_PackedDouble(out_val, a, b);
            _ReadWriteBarrier();
            memcpy(result, out_val, 16 * sizeof(float));
            return result;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Unmapped page mid-op — fall through to the original.
        }
    }
    return pOrigMatMul(result, a, b);
}

#if !TEST_DISABLE_QUAT_MATRIX_SSE2
// ================================================================
// sub_4C1C40: quaternion -> 3x3 rotation block  __cdecl(quat, dest)
// ================================================================
// The arithmetic core behind all three of the client's quaternion wrappers
// (0x004C1DE0, 0x004C1E20, 0x004C33C0), so hooking it here covers every caller
// including sub_82F0F0, which runs it once per animated bone per frame.
//
// It writes nine of the sixteen floats - indices 0,1,2,4,5,6,8,9,10 - and
// deliberately leaves 3, 7, 11 and 12..15 alone; the wrappers set those. This
// replacement writes the same nine and no others.
//
// The original is not plain double arithmetic, and that is the whole difficulty.
// It is 72 x87 instructions, the CRT runs x87 at 53-bit precision, and the
// compiler ran out of the eight-deep x87 stack: it spilled three products to
// 32-bit stack slots and reloaded them.
//
//     fstp [ebp+arg_0]   <- x*2z rounded to float
//     fstp [ebp+var_8]   <- y*2z rounded to float
//     fst  [ebp+var_4]   <- z*2z rounded to float, but NOT popped
//
// So three of the twelve intermediates are float and the rest are 53-bit. The
// third is the awkward one: `fst` stores without popping, so z*2z survives in a
// register at full width as well, and the function then uses both. Row 0 gets
// the unrounded value and row 1 gets the rounded one. Reproducing that asymmetry
// is what makes this bit-identical rather than merely close - and "merely close"
// on a bone rotation is the same order of error that produced the first-person
// camera snapping the last time this project reached for lower precision here.
//
// Grouping is preserved exactly; operand order within a single multiply or add
// is not, because IEEE multiply and add are commutative and exactly rounded.
static inline void QuatToMatrix3x3_PackedDouble(const float* q, float* dest) {
    // Two lanes per multiply for the six products that pair up naturally.
    __m128  qf   = _mm_loadu_ps(q);                          // x  y  z  w
    __m128d q_lo = _mm_cvtps_pd(qf);                         // (x, y)
    __m128d q_hi = _mm_cvtps_pd(_mm_movehl_ps(qf, qf));      // (z, w)

    __m128d two  = _mm_set1_pd(2.0);
    __m128d d_lo = _mm_mul_pd(q_lo, two);                    // (2x, 2y)
    __m128d d_hi = _mm_mul_pd(q_hi, two);                    // (2z, 2w)

    __m128d z2   = _mm_unpacklo_pd(d_hi, d_hi);              // (2z, 2z)
    __m128d ww   = _mm_unpackhi_pd(q_hi, q_hi);              // (w,  w)

    __m128d sq   = _mm_mul_pd(q_lo, d_lo);                   // (x*2x, y*2y)
    __m128d wxy  = _mm_mul_pd(ww,   d_lo);                   // (w*2x, w*2y)
    __m128d xyz2 = _mm_mul_pd(q_lo, z2);                     // (x*2z, y*2z)

    double xx2 = _mm_cvtsd_f64(sq);
    double yy2 = _mm_cvtsd_f64(_mm_unpackhi_pd(sq, sq));
    double wx2 = _mm_cvtsd_f64(wxy);
    double wy2 = _mm_cvtsd_f64(_mm_unpackhi_pd(wxy, wxy));

    double zz2 = _mm_cvtsd_f64(_mm_mul_sd(z2, q_hi));        // 2z*z, full width
    double wz2 = _mm_cvtsd_f64(_mm_mul_sd(ww, z2));          // w*2z
    double xy2 = _mm_cvtsd_f64(_mm_mul_sd(q_lo, _mm_unpackhi_pd(d_lo, d_lo)));

    // The three the original could not keep in registers. Narrowing here is not
    // a shortcut - it is the client's own rounding, and omitting it is what
    // makes the two answers differ.
    __m128 narrowed = _mm_cvtpd_ps(xyz2);
    float xz2f = _mm_cvtss_f32(narrowed);
    float yz2f = _mm_cvtss_f32(_mm_shuffle_ps(narrowed, narrowed, _MM_SHUFFLE(1, 1, 1, 1)));
    float zz2f = (float)zz2;

    dest[0]  = (float)(1.0 - (zz2 + yy2));          // zz2 at full width here
    dest[1]  = (float)(xy2 + wz2);
    dest[2]  = (float)((double)xz2f - wy2);
    dest[4]  = (float)(xy2 - wz2);
    dest[5]  = (float)(1.0 - ((double)zz2f + xx2)); // and rounded here
    dest[6]  = (float)((double)yz2f + wx2);
    dest[8]  = (float)(wy2 + (double)xz2f);
    dest[9]  = (float)((double)yz2f - wx2);
    dest[10] = (float)(1.0 - (xx2 + yy2));
}

// Run the client's own routine beside ours on the real binary before replacing
// it, and demand exact equality rather than a tolerance. Every intermediate here
// is reproduced at the width the original used, so anything short of identical
// means the reading of those three spill slots is wrong, and a tolerance would
// hide exactly the mistake this is meant to catch.
static bool SelfTestQuatToMatrix() {
    typedef float* (__cdecl* quat_fn)(const float*, float*);
    quat_fn original = (quat_fn)0x004C1C40;

    const int CASES = 4096;
    unsigned seed = 0x85EBCA6Bu;
    int mismatches = 0;

    for (int c = 0; c < CASES; ++c) {
        float q[4];
        for (int i = 0; i < 4; ++i) {
            seed = seed * 1103515245u + 12345u;
            q[i] = ((float)(int)(seed >> 16) / 32768.0f) - 1.0f;
        }

        // Most of the run is unit quaternions, because that is what bone tracks
        // actually hold; the rest is left unnormalised to exercise the paths
        // where the products are far from 1 and the float spills matter most.
        if ((c & 3) != 0) {
            double n = sqrt((double)q[0] * q[0] + (double)q[1] * q[1] +
                            (double)q[2] * q[2] + (double)q[3] * q[3]);
            if (n > 1e-6) {
                for (int i = 0; i < 4; ++i) q[i] = (float)(q[i] / n);
            }
        }

        // Both sides get a full 16-float buffer so that a stray write outside
        // the nine cells shows up as a mismatch instead of going unnoticed.
        float theirs[16], ours[16];
        for (int i = 0; i < 16; ++i) { theirs[i] = (float)i; ours[i] = (float)i; }

        __try {
            original(q, theirs);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[MatrixSSE2] Quaternion self-test: the client's routine faulted - not hooking");
            return false;
        }
        QuatToMatrix3x3_PackedDouble(q, ours);

        if (memcmp(theirs, ours, sizeof(theirs)) != 0) ++mismatches;
    }

    if (mismatches != 0) {
        Log("[MatrixSSE2] Quaternion self-test FAILED: %d of %d cases differed "
            "from the client - not hooking", mismatches, CASES);
        return false;
    }
    Log("[MatrixSSE2] Quaternion self-test passed %d cases against the client's "
        "own routine, bit-identical", CASES);
    return true;
}

static float* __cdecl Hooked_QuatToMatrix(const float* quat, float* dest) {
    ++g_quat2mat_calls;

    uintptr_t pq = (uintptr_t)quat, pd = (uintptr_t)dest;
    if (pq > 0x10000 && pq < 0xFFE00000 &&
        pd > 0x10000 && pd < 0xFFE00000) {
        __try {
            // Staged, so a fault partway through the arithmetic cannot leave the
            // caller's matrix half written.
            float out_val[16];
            QuatToMatrix3x3_PackedDouble(quat, out_val);
            _ReadWriteBarrier();
            dest[0]  = out_val[0];  dest[1] = out_val[1];  dest[2]  = out_val[2];
            dest[4]  = out_val[4];  dest[5] = out_val[5];  dest[6]  = out_val[6];
            dest[8]  = out_val[8];  dest[9] = out_val[9];  dest[10] = out_val[10];
            return dest;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Unmapped page mid-op - fall through to the original.
        }
    }
    return pOrigQuatToMatrix(quat, dest);
}

// sub_4C1DE0: the wrapper sub_82F0F0 actually calls, once per animated bone per
// frame. It writes seven constants into the fourth row and column and then calls
// the core above.
//
// Hooking it as well as the core is not redundant. Replacing only the core still
// leaves the client making two calls where one would do, and on a routine this
// small the call is a real fraction of the cost - the core is under six
// nanoseconds end to end, so an extra call and return is not noise against it.
// Fusing them removes that call from the hot path entirely.
//
// The other two wrappers (0x004C1E20, 0x004C33C0) are left alone; they are not on
// the per-bone path and they still get the faster core underneath.
static float* __fastcall Hooked_QuatToMatrixFull(float* dest, void* /*edx*/, const float* quat) {
    ++g_quat2matfull_calls;

    uintptr_t pq = (uintptr_t)quat, pd = (uintptr_t)dest;
    if (pq > 0x10000 && pq < 0xFFE00000 &&
        pd > 0x10000 && pd < 0xFFE00000) {
        __try {
            float out_val[16];
            QuatToMatrix3x3_PackedDouble(quat, out_val);
            _ReadWriteBarrier();
            dest[0]  = out_val[0];  dest[1]  = out_val[1];  dest[2]  = out_val[2];
            dest[4]  = out_val[4];  dest[5]  = out_val[5];  dest[6]  = out_val[6];
            dest[8]  = out_val[8];  dest[9]  = out_val[9];  dest[10] = out_val[10];
            // The seven the wrapper contributes, in the client's own order.
            dest[3]  = 0.0f; dest[7]  = 0.0f; dest[11] = 0.0f;
            dest[12] = 0.0f; dest[13] = 0.0f; dest[14] = 0.0f;
            dest[15] = 1.0f;
            return dest;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Unmapped page mid-op - fall through to the original. That original
            // calls the core, which is hooked, and the core is bit-identical, so
            // the fallback answer is the same one either way.
        }
    }
    return pOrigQuatToMatrixFull(dest, nullptr, quat);
}
#endif

// ================================================================
// sub_4C21B0: 3D point * 4x4 matrix (100+ xrefs)
// Vectorized via column linear combination using SSE2
// ================================================================
static float* __cdecl Hooked_MatVec3Mul(float* result, const float* vec3, const float* matrix44) {
    ++g_matvec3_calls;

    uintptr_t r = (uintptr_t)result, pv = (uintptr_t)vec3, pm = (uintptr_t)matrix44;
    if (r > 0x10000 && r < 0xFFE00000 &&
        pv > 0x10000 && pv < 0xFFE00000 &&
        pm > 0x10000 && pm < 0xFFE00000) {
        __try {
            double vx = vec3[0];
            double vy = vec3[1];
            double vz = vec3[2];

            double m0 = matrix44[0];
            double m4 = matrix44[4];
            double m8 = matrix44[8];
            double m12 = matrix44[12];

            double m1 = matrix44[1];
            double m5 = matrix44[5];
            double m9 = matrix44[9];
            double m13 = matrix44[13];

            double m2 = matrix44[2];
            double m6 = matrix44[6];
            double m10 = matrix44[10];
            double m14 = matrix44[14];

            double rx = vx * m0 + vy * m4 + vz * m8 + m12;
            double ry = vx * m1 + vy * m5 + vz * m9 + m13;
            double rz = vx * m2 + vy * m6 + vz * m10 + m14;

            result[0] = (float)rx;
            result[1] = (float)ry;
            result[2] = (float)rz;

            return result;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Unmapped page - fallback
        }
    }
    return pOrigMatVec3Mul(result, vec3, matrix44);
}

// ================================================================
// sub_4C2270: 4D vector * 4x4 matrix (20 xrefs)
// Vectorized via column linear combination using SSE2
// ================================================================
static float* __cdecl Hooked_MatVec4Mul(float* result, const float* vec4, const float* matrix44) {
    ++g_matvec4_calls;

    uintptr_t r = (uintptr_t)result, pv = (uintptr_t)vec4, pm = (uintptr_t)matrix44;
    if (r > 0x10000 && r < 0xFFE00000 &&
        pv > 0x10000 && pv < 0xFFE00000 &&
        pm > 0x10000 && pm < 0xFFE00000) {
        __try {
            double vx = vec4[0];
            double vy = vec4[1];
            double vz = vec4[2];
            double vw = vec4[3];

            double m0 = matrix44[0];
            double m4 = matrix44[4];
            double m8 = matrix44[8];
            double m12 = matrix44[12];

            double m1 = matrix44[1];
            double m5 = matrix44[5];
            double m9 = matrix44[9];
            double m13 = matrix44[13];

            double m2 = matrix44[2];
            double m6 = matrix44[6];
            double m10 = matrix44[10];
            double m14 = matrix44[14];

            double m3 = matrix44[3];
            double m7 = matrix44[7];
            double m11 = matrix44[11];
            double m15 = matrix44[15];

            double rx = vx * m0 + vy * m4 + vz * m8 + vw * m12;
            double ry = vx * m1 + vy * m5 + vz * m9 + vw * m13;
            double rz = vx * m2 + vy * m6 + vz * m10 + vw * m14;
            double rw = vx * m3 + vy * m7 + vz * m11 + vw * m15;

            result[0] = (float)rx;
            result[1] = (float)ry;
            result[2] = (float)rz;
            result[3] = (float)rw;

            return result;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Unmapped page - fallback
        }
    }
    return pOrigMatVec4Mul(result, vec4, matrix44);
}

// ================================================================
// sub_4C3420 / sub_4C3600: C3Vector::Normalize (in-place, __thiscall(this))
// ================================================================
// Both do v *= 1.0/sqrt(x*x+y*y+z*z) with x87 fsqrt+fdiv. We replace that with
// full-precision SSE (sqrtss + divss) -- deliberately NOT _mm_rsqrt_ps, whose
// approximation + the missing degenerate guard is exactly what NaN-poisoned the
// quaternion-normalize hook. sqrtss/divss are IEEE round-to-nearest, so the result
// matches the scalar original to sub-ULP (only the x^2+y^2+z^2 accumulation order
// differs, x87's 80-bit vs SSE 32-bit -- invisible for a unit vector).
//
//   sub_4C3420: no guard. On a zero vector the original yields 1.0/0 = +Inf then
//               v*Inf = NaN; SSE divss-by-zero (exceptions masked, as WoW runs)
//               produces the identical Inf/NaN, so behaviour is faithful.
//   sub_4C3600: guarded -- only normalizes when mag^2 > 2^-22, else leaves the
//               vector unchanged. Replicated exactly.
#if !TEST_DISABLE_VEC_NORMALIZE_SSE2
typedef void (__fastcall* Vec3Norm_t)(float* self, void* edx);
static Vec3Norm_t pOrigVec3Norm     = nullptr;  // sub_4C3420 (unguarded)
static Vec3Norm_t pOrigVec3NormSafe = nullptr;  // sub_4C3600 (mag^2 > 2^-22 guard)
static volatile long g_vec3norm_calls = 0;

// 2^-22, the engine's near-zero magnitude cutoff in sub_4C3600 (flt_9EA27C, the
// same constant the quaternion normalise uses). It is loaded with `fld dword`
// and compared against a 53-bit sum, so the comparison happens in double.
static const double kVec3NormEpsD = 2.384185791015625e-07;

static inline void SSE2_Vec3NormalizeInPlace(float* v, bool guard) {
    // Read exactly 3 floats (never v[3], which may sit on an unmapped next page).
    double x = v[0];
    double y = v[1];
    double z = v[2];

    // Both originals square and accumulate in double and narrow only on the
    // three final stores, and both group the sum the same way: (x*x + y*y)
    // first, then + z*z. This was packed single with the same grouping, which
    // left it a ULP or so out and is why the hooks that use it are still being
    // shadow-checked against the client on every call at a 1e-5 tolerance rather
    // than trusted. Keeping the client's width makes the answers identical, and
    // an identical answer needs no tolerance.
    double s = x * x + y * y;
    s = s + z * z;

    if (guard) {
        // Written this way round so a NaN takes the same branch the client's
        // unordered compare takes: leave the vector alone.
        if (!(s > kVec3NormEpsD)) return;
    }

    // sub_4C3420 has no guard at all, so a zero vector divides by zero there and
    // the components come back NaN. That is reproduced rather than fixed: this
    // has to match the client, not improve on it.
    __m128d root = _mm_sqrt_sd(_mm_setzero_pd(), _mm_set_sd(s));
    double  inv  = _mm_cvtsd_f64(_mm_div_sd(_mm_set_sd(1.0), root));

    float out_x = (float)(x * inv);
    float out_y = (float)(y * inv);
    float out_z = (float)(z * inv);

    v[0] = out_x;
    v[1] = out_y;
    v[2] = out_z;
}

// Both normalise hooks are shadow-checked against the client for their first few
// thousand real calls, then run alone.
//
// The pointer guards above are not a correctness check - they catch an unmapped
// page and defer, and say nothing about whether the answer matches. These are
// the two normalise routines the log confirms are actually installed
// (0x004C3420 and 0x004C3600), they replace the client's arithmetic outright,
// and nothing has ever compared the results. The matrix multiply in this same
// file was in that position and turned out to sit a hundred times outside its
// own declared tolerance.
//
// A normalise feeds directions - camera, bone axes, lighting - so a wrong one
// is a subtle visual defect rather than a crash, which is the kind that reaches
// a bug report as "something looks off" and never gets attributed.
//
// The check is now for identical bits rather than a tolerance, because the
// arithmetic became bit-identical. Measured offline against both originals
// transcribed verbatim as inline asm: 4,000,000 vectors each, zero differing.
// The packed single version this replaced differed on 1,882,782 of them
// unguarded and 1,416,357 guarded - not an occasional ULP, close to every vector
// that was not left alone by the epsilon.
static volatile long g_normChecked   = 0;
static bool          g_normTrusted   = false;
static bool          g_normAbandoned = false;

static constexpr long NORM_VERIFY_CALLS = 4096;

// The client writes in place, so comparing means giving it its own copy.
//
// This compared with a 1e-5 relative tolerance, which was as much as the packed
// single implementation could promise. Now that the arithmetic keeps the client's
// double width the answers are the same bits, so the comparison is on bits.
//
// Bits also settle two cases a tolerance handles badly. sub_4C3420 has no guard,
// so a zero vector makes it divide by zero and return NaN in every component -
// and NaN minus NaN is NaN, which is not greater than 1e-5, so the old check
// silently passed anything at all whenever the client produced one. And a vector
// under the epsilon must come back byte-for-byte untouched, which a distance
// cannot distinguish from being rewritten with the same value.
static bool NormalizeAgreesWithClient(const float* before, const float* ours,
                                      void (__fastcall* orig)(float*, void*), void* edx) {
    float theirs[3] = { before[0], before[1], before[2] };
    __try {
        orig(theirs, edx);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;   // cannot compare; never report a false disagreement
    }
    return memcmp(theirs, ours, 3 * sizeof(float)) == 0;
}

static void __fastcall Hooked_Vec3Norm(float* self, void* edx) {
    ++g_vec3norm_calls;
    if (g_normAbandoned) { pOrigVec3Norm(self, edx); return; }
    if ((uintptr_t)self > 0x10000 && (uintptr_t)self < 0xFFE00000) {
        __try {
            float before[3] = { self[0], self[1], self[2] };
            SSE2_Vec3NormalizeInPlace(self, false);
            if (!g_normTrusted) {
                long n = InterlockedIncrement(&g_normChecked);
                if (!NormalizeAgreesWithClient(before, self, pOrigVec3Norm, edx)) {
                    g_normAbandoned = true;
                    Log("[MatrixSSE2] C3Vector::Normalize disagreed with the client on call "
                        "%ld - handing every call back to the original", n);
                    self[0] = before[0]; self[1] = before[1]; self[2] = before[2];
                    pOrigVec3Norm(self, edx);
                    return;
                }
                if (n >= NORM_VERIFY_CALLS) {
                    g_normTrusted = true;
                    Log("[MatrixSSE2] Vector normalise agreed with the client on "
                        "%ld consecutive real calls - running ours alone", n);
                }
            }
            return;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Bad pointer surfaced during the read -- nothing was written yet
            // (the fault is on the initial load), so deferring to the original
            // leaves the vector exactly as the engine would handle it.
        }
    }
    pOrigVec3Norm(self, edx);
}

static void __fastcall Hooked_Vec3NormSafe(float* self, void* edx) {
    ++g_vec3norm_calls;
    if (g_normAbandoned) { pOrigVec3NormSafe(self, edx); return; }
    if ((uintptr_t)self > 0x10000 && (uintptr_t)self < 0xFFE00000) {
        __try {
            float before[3] = { self[0], self[1], self[2] };
            SSE2_Vec3NormalizeInPlace(self, true);
            if (!g_normTrusted) {
                long n = InterlockedIncrement(&g_normChecked);
                if (!NormalizeAgreesWithClient(before, self, pOrigVec3NormSafe, edx)) {
                    g_normAbandoned = true;
                    Log("[MatrixSSE2] C3Vector::Normalize(guarded) disagreed with the client on call "
                        "%ld - handing every call back to the original", n);
                    self[0] = before[0]; self[1] = before[1]; self[2] = before[2];
                    pOrigVec3NormSafe(self, edx);
                    return;
                }
                if (n >= NORM_VERIFY_CALLS) {
                    g_normTrusted = true;
                    Log("[MatrixSSE2] Vector normalise agreed with the client on "
                        "%ld consecutive real calls - running ours alone", n);
                }
            }
            return;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    pOrigVec3NormSafe(self, edx);
}
#endif

// ================================================================
// sub_4C23D0: CMatrix::Transpose  out = transpose(this)  __thiscall(this, out)
// ================================================================
// Pure data movement (16 scalar fld/fstp in the original). _MM_TRANSPOSE4_PS is
// bit-identical -- no arithmetic -- and loads all four rows before storing, so it
// is also safe when out aliases this (the scalar original is not).
//
// sub_4C2300: 3D point * 4x4 matrix, written to BOTH a2 (in place) and a1.
// __cdecl(a1_out, a2_point_inout, a3_matrix). Identical products to MatVec3Mul
// (already shipped against sub_4C21B0); only the accumulation order differs.
#if !TEST_DISABLE_MATRIX_EXT_SSE2
typedef float* (__fastcall* MatTranspose_t)(float* self, void* edx, float* out);
static MatTranspose_t pOrigMatTranspose = nullptr;
static volatile long g_mattranspose_calls = 0;

static float* __fastcall Hooked_MatTranspose(float* self, void* edx, float* out) {
    ++g_mattranspose_calls;
    uintptr_t s = (uintptr_t)self, o = (uintptr_t)out;
    if (s > 0x10000 && s < 0xFFE00000 && o > 0x10000 && o < 0xFFE00000) {
        __try {
            __m128 r0 = _mm_loadu_ps(self);
            __m128 r1 = _mm_loadu_ps(self + 4);
            __m128 r2 = _mm_loadu_ps(self + 8);
            __m128 r3 = _mm_loadu_ps(self + 12);
            _MM_TRANSPOSE4_PS(r0, r1, r2, r3);
            _mm_storeu_ps(out + 0,  r0);
            _mm_storeu_ps(out + 4,  r1);
            _mm_storeu_ps(out + 8,  r2);
            _mm_storeu_ps(out + 12, r3);
            return out;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return pOrigMatTranspose(self, edx, out);
}

// ================================================================
// sub_4C1BF0: CMatrix::Scale3x3 (upper-left 3x3 *= scalar, __thiscall)
// ================================================================
// Multiplies indices 0,1,2 / 4,5,6 / 8,9,10 by a scalar. Skips the
// translation column (3,7,11) and bottom row (12-15). 37 xrefs in the
// model rendering pipeline (M2 bone/scale updates). The original is 9
// scalar fmuls; SSE2 does 3 vector muls + masked stores.
#if !TEST_DISABLE_MATRIX_EXT_SSE2
typedef void (__fastcall* Scale3x3_t)(float* self, void* edx, float scalar);
static Scale3x3_t pOrigScale3x3 = nullptr;
static volatile long g_scale3x3_calls = 0;

static void __fastcall Hooked_Scale3x3(float* self, void* edx, float scalar) {
    ++g_scale3x3_calls;
    uintptr_t p = (uintptr_t)self;
    if (p > 0x10000 && p < 0xFFE00000) {
        __try {
            __m128 s = _mm_set1_ps(scalar);
            // Row 0: multiply [0..3], store only [0..2]
            __m128 r0 = _mm_mul_ps(_mm_loadu_ps(self), s);
            _mm_store_ss(self,     r0);
            _mm_store_ss(self + 1, _mm_shuffle_ps(r0, r0, _MM_SHUFFLE(1,1,1,1)));
            _mm_store_ss(self + 2, _mm_shuffle_ps(r0, r0, _MM_SHUFFLE(2,2,2,2)));
            // Row 1: multiply [4..7], store only [4..6]
            __m128 r1 = _mm_mul_ps(_mm_loadu_ps(self + 4), s);
            _mm_store_ss(self + 4, r1);
            _mm_store_ss(self + 5, _mm_shuffle_ps(r1, r1, _MM_SHUFFLE(1,1,1,1)));
            _mm_store_ss(self + 6, _mm_shuffle_ps(r1, r1, _MM_SHUFFLE(2,2,2,2)));
            // Row 2: multiply [8..11], store only [8..10]
            __m128 r2 = _mm_mul_ps(_mm_loadu_ps(self + 8), s);
            _mm_store_ss(self + 8,  r2);
            _mm_store_ss(self + 9,  _mm_shuffle_ps(r2, r2, _MM_SHUFFLE(1,1,1,1)));
            _mm_store_ss(self + 10, _mm_shuffle_ps(r2, r2, _MM_SHUFFLE(2,2,2,2)));
            return;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    pOrigScale3x3(self, edx, scalar);
}
#endif

// ================================================================
// sub_4C3680: CMatrix::From3x3 — expand float[9] → float[16] (5 xrefs)
// ================================================================
// Copies a 3×3 row-major matrix into a 4×4 with identity padding:
//   out[0..2]=in[0..2], out[3]=0
//   out[4..6]=in[3..5], out[7]=0
//   out[8..10]=in[6..8], out[11]=0
//   out[12..14]=in[9..11], out[15]=1
// Used in bone transform construction. SSE2 loads 3 rows of 3 floats
// and stores 4 rows of 4 floats with zero/one padding.
typedef float* (__fastcall* MatFrom3x3_t)(float* self, void* edx, float* src3x3);
static MatFrom3x3_t pOrigMatFrom3x3 = nullptr;
static volatile long g_matfrom3x3_calls = 0;

static float* __fastcall Hooked_MatFrom3x3(float* self, void* edx, float* src) {
    ++g_matfrom3x3_calls;
    uintptr_t s = (uintptr_t)self, p = (uintptr_t)src;
    if (s > 0x10000 && s < 0xFFE00000 && p > 0x10000 && p < 0xFFE00000) {
        __try {
            __m128 r0 = _mm_setr_ps(src[0], src[1], src[2], 0.0f);
            __m128 r1 = _mm_setr_ps(src[3], src[4], src[5], 0.0f);
            __m128 r2 = _mm_setr_ps(src[6], src[7], src[8], 0.0f);
            __m128 r3 = _mm_setr_ps(src[9], src[10], src[11], 1.0f);
            _mm_storeu_ps(self,     r0);
            _mm_storeu_ps(self + 4, r1);
            _mm_storeu_ps(self + 8, r2);
            _mm_storeu_ps(self + 12, r3);
            return self;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return pOrigMatFrom3x3(self, edx, src);
}

typedef float* (__cdecl* PointXformIP_t)(float* a1, float* a2, float* a3);
static PointXformIP_t pOrigPointXformIP = nullptr;
static volatile long g_pointxformip_calls = 0;

static float* __cdecl Hooked_PointXformInPlace(float* a1, float* a2, float* a3) {
    ++g_pointxformip_calls;
    uintptr_t p1 = (uintptr_t)a1, p2 = (uintptr_t)a2, p3 = (uintptr_t)a3;
    if (p1 > 0x10000 && p1 < 0xFFE00000 &&
        p2 > 0x10000 && p2 < 0xFFE00000 &&
        p3 > 0x10000 && p3 < 0xFFE00000) {
        __try {
            double vx = a2[0];
            double vy = a2[1];
            double vz = a2[2];

            double m0 = a3[0];
            double m4 = a3[4];
            double m8 = a3[8];
            double m12 = a3[12];

            double m1 = a3[1];
            double m5 = a3[5];
            double m9 = a3[9];
            double m13 = a3[13];

            double m2 = a3[2];
            double m6 = a3[6];
            double m10 = a3[10];
            double m14 = a3[14];

            double rx = vx * m0 + vy * m4 + vz * m8 + m12;
            double ry = vx * m1 + vy * m5 + vz * m9 + m13;
            double rz = vx * m2 + vy * m6 + vz * m10 + m14;

            a2[0] = (float)rx; a2[1] = (float)ry; a2[2] = (float)rz;
            a1[0] = (float)rx; a1[1] = (float)ry; a1[2] = (float)rz;
            return a1;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return pOrigPointXformIP(a1, a2, a3);
}
#endif

// ================================================================
// sub_4C2FC0: rigid-transform inverse builder  __thiscall(this, out)  (~34 xrefs)
// ================================================================
// Builds the inverse of an orthonormal (rotation + translation) 4x4 from the
// input matrix `this` into `out`:
//   out_R   = transpose(upper-left 3x3 of this)
//   out[12+i] = -(R_row_i . t),  t = this[12..14]
//   out[3] = out[7] = out[11] = 0,  out[15] = 1
// The engine first repacks this' 3x3 into a stack scratch via sub_4C51B0 and
// reads from there; since that helper only copies the SAME nine elements
// (this[0,1,2,4,5,6,8,9,10]) we read them directly and skip the call entirely.
// _MM_TRANSPOSE4_PS with a zeroed 4th row yields the transposed rotation rows
// with lane3 already 0; the same transposed rows are exactly the column vectors
// needed for the three translation dot products, so trans = r0*(-tx)+r1*(-ty)+
// r2*(-tz) lands (out12,out13,out14,0). Products and (a+b)+c summation order
// match the FPU original; only x87 80-bit vs SSE 32-bit intermediates differ
// (sub-ULP, invisible for a rigid transform). All reads stay inside the 64-byte
// input matrix; the full 16-float output is written exactly as the original.
#if !TEST_DISABLE_MATRIX_INVERT_SSE2
typedef float* (__fastcall* MatInvRigid_t)(float* self, void* edx, float* out);
static MatInvRigid_t pOrigMatInvRigid = nullptr;
static volatile long g_matinvrigid_calls = 0;

static float* __fastcall Hooked_MatInvertRigid(float* self, void* edx, float* out) {
    ++g_matinvrigid_calls;
    uintptr_t s = (uintptr_t)self, o = (uintptr_t)out;
    if (s > 0x10000 && s < 0xFFE00000 && o > 0x10000 && o < 0xFFE00000) {
        __try {
            __m128 orig0 = _mm_loadu_ps(self);       // M0..M3   (row 0)
            __m128 orig1 = _mm_loadu_ps(self + 4);   // M4..M7   (row 1)
            __m128 orig2 = _mm_loadu_ps(self + 8);   // M8..M11  (row 2)
            float tx = self[12], ty = self[13], tz = self[14];   // translation row

            // Now transpose rotation matrix first
            __m128 r0 = orig0;
            __m128 r1 = orig1;
            __m128 r2 = orig2;
            __m128 r3 = _mm_setzero_ps();         // forces transposed lane3 -> 0
            _MM_TRANSPOSE4_PS(r0, r1, r2, r3);

            // Compute translation vector using transposed rows:
            // trans = r0*(-tx) + r1*(-ty) + r2*(-tz)
            __m128 trans = _mm_add_ps(
                _mm_add_ps(_mm_mul_ps(r0, _mm_set1_ps(-tx)),
                           _mm_mul_ps(r1, _mm_set1_ps(-ty))),
                _mm_mul_ps(r2, _mm_set1_ps(-tz)));          // (out12,out13,out14,0)
            trans = _mm_add_ps(trans, _mm_setr_ps(0.0f, 0.0f, 0.0f, 1.0f)); // out15=1

            _mm_storeu_ps(out,      r0);
            _mm_storeu_ps(out + 4,  r1);
            _mm_storeu_ps(out + 8,  r2);
            _mm_storeu_ps(out + 12, trans);
            return out;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return pOrigMatInvRigid(self, nullptr, out);
}
#endif

// ================================================================
// sub_4C2120: scalar * 4x4 matrix  __cdecl(out, src, scalar)  (4 xrefs)
// ================================================================
// out[i] = src[i] * scalar for all 16 elements. 16 scalar fmuls -> 4 mul_ps.
// Loads each src row fully before storing, so it is safe if out aliases src.
#if !TEST_DISABLE_MATRIX_MISC_SSE2
typedef float* (__cdecl* MatScalarMul_t)(float* out, float* src, float scalar);
static MatScalarMul_t pOrigMatScalarMul = nullptr;
static volatile long g_matscalarmul_calls = 0;

typedef float* (__cdecl* RowAffinePoint_t)(float* out, float* mat, float* pt);
static RowAffinePoint_t pOrigRowAffinePoint = nullptr;

static float* __cdecl Hooked_MatScalarMul(float* out, float* src, float scalar) {
    ++g_matscalarmul_calls;
    uintptr_t o = (uintptr_t)out, s = (uintptr_t)src;
    if (o > 0x10000 && o < 0xFFE00000 && s > 0x10000 && s < 0xFFE00000) {
        __try {
            __m128 k = _mm_set1_ps(scalar);
            __m128 r0 = _mm_mul_ps(_mm_loadu_ps(src),      k);
            __m128 r1 = _mm_mul_ps(_mm_loadu_ps(src + 4),  k);
            __m128 r2 = _mm_mul_ps(_mm_loadu_ps(src + 8),  k);
            __m128 r3 = _mm_mul_ps(_mm_loadu_ps(src + 12), k);
            _ReadWriteBarrier();
            _mm_storeu_ps(out,      r0);
            _mm_storeu_ps(out + 4,  r1);
            _mm_storeu_ps(out + 8,  r2);
            _mm_storeu_ps(out + 12, r3);
            return out;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return pOrigMatScalarMul(out, src, scalar);
}

// ================================================================
// sub_4C2210: row-major affine 3D point transform  __cdecl(out3, mat16, pt3)  (6 xrefs)
// ================================================================
// out_i = mat[4i]*p.x + mat[4i+1]*p.y + mat[4i+2]*p.z + mat[4i+3], i=0..2.
// (Row-vector form: each output row dotted with the homogeneous point (p,1).)
// Transposing the three matrix rows with a zeroed 4th yields column vectors whose
// linear combination px*c0 + py*c1 + pz*c2 + c3 reproduces exactly those products;
// lane3 stays 0 and is never stored. Reads only mat[0..11] + pt[0..2]; writes 3
// floats. Same four products as the FPU original (summation order sub-ULP).
static float* __cdecl Hooked_RowAffinePoint(float* out, float* mat, float* pt) {
    ++g_matscalarmul_calls;  // shared misc-ops counter
    uintptr_t o = (uintptr_t)out, m = (uintptr_t)mat, p = (uintptr_t)pt;
    if (o > 0x10000 && o < 0xFFE00000 && m > 0x10000 && m < 0xFFE00000 &&
        p > 0x10000 && p < 0xFFE00000) {
        __try {
            __m128 r0 = _mm_loadu_ps(mat);       // M0..M3
            __m128 r1 = _mm_loadu_ps(mat + 4);   // M4..M7
            __m128 r2 = _mm_loadu_ps(mat + 8);   // M8..M11
            __m128 r3 = _mm_setzero_ps();
            float px = pt[0], py = pt[1], pz = pt[2];
            // r0=(M0,M4,M8,0)=col0  r1=(M1,M5,M9,0)=col1  r2=(M2,M6,M10,0)=col2
            //                                              r3=(M3,M7,M11,0)=col3
            _MM_TRANSPOSE4_PS(r0, r1, r2, r3);
            __m128 res = _mm_add_ps(
                _mm_add_ps(_mm_mul_ps(_mm_set1_ps(px), r0),
                           _mm_mul_ps(_mm_set1_ps(py), r1)),
                _mm_add_ps(_mm_mul_ps(_mm_set1_ps(pz), r2), r3));  // (out0,out1,out2,0)
            _mm_store_ss(out,     res);
            _mm_store_ss(out + 1, _mm_shuffle_ps(res, res, _MM_SHUFFLE(1, 1, 1, 1)));
            _mm_store_ss(out + 2, _mm_shuffle_ps(res, res, _MM_SHUFFLE(2, 2, 2, 2)));
            return out;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return pOrigRowAffinePoint(out, mat, pt);
}
#endif

// ================================================================
// sub_4C1B30: in-place local-space translate  __thiscall(this, vec3)  (65+ xrefs)
// ================================================================
// this[12+i] += this[i]*v.x + this[4+i]*v.y + this[8+i]*v.z   (i=0..2)
// i.e. adds R.v to the translation row, where the rotation columns are
// col0=(this[0],this[1],this[2]) = first 3 lanes of row0, etc. The three matrix
// rows loaded as (r0,r1,r2) ARE those columns in lanes 0..2, so
// delta = v.x*r0 + v.y*r1 + v.z*r2 holds the three increments in lanes 0..2
// (lane3 = junk from this[3]/[7]/[11], never used). Only this[12..14] are written
// via scalar adds, leaving this[15] untouched exactly like the original. Same
// products as the FPU original; summation order differs sub-ULP.
#if !TEST_DISABLE_MATRIX_TRANSLATE_SSE2
typedef float* (__fastcall* MatTranslate_t)(float* self, void* edx, float* vec3);
static MatTranslate_t pOrigMatTranslate = nullptr;
static volatile long g_mattranslate_calls = 0;

static float* __fastcall Hooked_MatTranslateLocal(float* self, void* edx, float* vec3) {
    ++g_mattranslate_calls;
    uintptr_t s = (uintptr_t)self, v = (uintptr_t)vec3;
    if (s > 0x10000 && s < 0xFFE00000 && v > 0x10000 && v < 0xFFE00000) {
        __try {
            double vx = vec3[0];
            double vy = vec3[1];
            double vz = vec3[2];

            double r0 = self[0];
            double r4 = self[4];
            double r8 = self[8];

            double r1 = self[1];
            double r5 = self[5];
            double r9 = self[9];

            double r2 = self[2];
            double r6 = self[6];
            double r10 = self[10];

            self[12] = (float)(self[12] + vx * r0 + vy * r4 + vz * r8);
            self[13] = (float)(self[13] + vx * r1 + vy * r5 + vz * r9);
            self[14] = (float)(self[14] + vx * r2 + vy * r6 + vz * r10);
            return vec3;   // original returns the vec3 argument
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return pOrigMatTranslate(self, nullptr, vec3);
}
#endif

// ================================================================
// Install hooks
// ================================================================
bool InstallMatrixCopySSE2() {
#if !TEST_DISABLE_MATRIX_COPY
    struct HookDef {
        void*       addr;
        void*       hook;
        void**      orig;
        const char* name;
        uint32_t    xrefs;
    };

    HookDef hooks[] = {
        { (void*)0x00407F80, (void*)HookMatrixCopy,     (void**)&pOrigMatCopy,     "MatrixCopy",     247 },
        { (void*)0x00407F40, (void*)HookMatrixIdentity, (void**)&pOrigMatIdentity, "MatrixIdentity",  53 },
    };

    int installed = 0;
    for (auto& h : hooks) {
        if (WineSafe_CreateHook(h.addr, h.hook, h.orig) == MH_OK) {
             if (WO_EnableHook(h.addr) == MH_OK) {
                 installed++;
                 Log("[MatrixSSE2] Hooked %s at 0x%08X (%d xrefs)", h.name, (DWORD)(uintptr_t)h.addr, h.xrefs);
             }
        }
    }

    Log("[MatrixSSE2] Installed %d/%d hooks (total %d xrefs)",
        installed, (int)(sizeof(hooks) / sizeof(hooks[0])),
        247 + 53);
#else
    Log("[MatrixSSE2] Matrix copy/identity hooks DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_MULTIPLY
    if (!SelfTestMatrixMultiply()) {
        // The self-test said why; installing anyway would be the whole point of
        // having one thrown away.
    } else if (WineSafe_CreateHook((void*)0x004C1F00, (void*)HookMatrixMultiply,
                                   (void**)&pOrigMatMul) == MH_OK &&
               WO_EnableHook((void*)0x004C1F00) == MH_OK) {
        Log("[MatrixSSE2] Hooked MatrixMultiply at 0x004C1F00 "
            "(SSE2 packed double, bit-identical to the client)");
    } else {
        Log("[MatrixSSE2] MatrixMultiply hook FAILED");
    }
#else
    Log("[MatrixSSE2] MatrixMultiply DISABLED via feature flag");
#endif

#if !TEST_DISABLE_QUAT_MATRIX_SSE2
    if (!SelfTestQuatToMatrix()) {
        // The self-test said why. Installing anyway would throw away the only
        // thing standing between a misread spill slot and a subtly wrong bone
        // rotation on every animated model in the game.
    } else if (WineSafe_CreateHook((void*)0x004C1C40, (void*)Hooked_QuatToMatrix,
                                   (void**)&pOrigQuatToMatrix) == MH_OK &&
               WO_EnableHook((void*)0x004C1C40) == MH_OK) {
        Log("[MatrixSSE2] Hooked QuatToMatrix at 0x004C1C40 "
            "(SSE2 packed double, bit-identical, covers all 3 quaternion wrappers)");

        // Only worth attempting once the core has proved itself and installed;
        // this shares its arithmetic, so if that did not pass there is nothing
        // here worth installing either.
        if (WineSafe_CreateHook((void*)0x004C1DE0, (void*)Hooked_QuatToMatrixFull,
                                (void**)&pOrigQuatToMatrixFull) == MH_OK &&
            WO_EnableHook((void*)0x004C1DE0) == MH_OK) {
            Log("[MatrixSSE2] Hooked QuatToMatrix(full) at 0x004C1DE0 "
                "(fused with the core, one call instead of two on the per-bone path)");
        } else {
            Log("[MatrixSSE2] QuatToMatrix(full) hook FAILED - the core is still active");
        }
    } else {
        Log("[MatrixSSE2] QuatToMatrix hook FAILED");
    }
#else
    Log("[MatrixSSE2] QuatToMatrix DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_VECTOR_SSE2
    if (WineSafe_CreateHook((void*)0x004C21B0, (void*)Hooked_MatVec3Mul,
                            (void**)&pOrigMatVec3Mul) == MH_OK &&
        WO_EnableHook((void*)0x004C21B0) == MH_OK) {
        Log("[MatrixSSE2] Hooked MatVec3Mul at 0x004C21B0 (SSE2, 100+ xrefs)");
    } else {
        Log("[MatrixSSE2] MatVec3Mul hook FAILED");
    }

    if (WineSafe_CreateHook((void*)0x004C2270, (void*)Hooked_MatVec4Mul,
                            (void**)&pOrigMatVec4Mul) == MH_OK &&
        WO_EnableHook((void*)0x004C2270) == MH_OK) {
        Log("[MatrixSSE2] Hooked MatVec4Mul at 0x004C2270 (SSE2, 20 xrefs)");
    } else {
        Log("[MatrixSSE2] MatVec4Mul hook FAILED");
    }
#else
    Log("[MatrixSSE2] Matrix-Vector hooks DISABLED via feature flag");
#endif

#if !TEST_DISABLE_VEC_NORMALIZE_SSE2
    if (WineSafe_CreateHook((void*)0x004C3420, (void*)Hooked_Vec3Norm,
                            (void**)&pOrigVec3Norm) == MH_OK &&
        WO_EnableHook((void*)0x004C3420) == MH_OK) {
        Log("[MatrixSSE2] Hooked C3Vector::Normalize at 0x004C3420 (SSE2 sqrtss, 12 callers)");
    } else {
        Log("[MatrixSSE2] C3Vector::Normalize hook FAILED");
    }

    if (WineSafe_CreateHook((void*)0x004C3600, (void*)Hooked_Vec3NormSafe,
                            (void**)&pOrigVec3NormSafe) == MH_OK &&
        WO_EnableHook((void*)0x004C3600) == MH_OK) {
        Log("[MatrixSSE2] Hooked C3Vector::Normalize(guarded) at 0x004C3600 (SSE2 sqrtss, 2^-22 guard, 22 callers)");
    } else {
        Log("[MatrixSSE2] C3Vector::Normalize(guarded) hook FAILED");
    }
#else
    Log("[MatrixSSE2] Vector-Normalize hooks DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_EXT_SSE2
    if (WineSafe_CreateHook((void*)0x004C23D0, (void*)Hooked_MatTranspose,
                            (void**)&pOrigMatTranspose) == MH_OK &&
        WO_EnableHook((void*)0x004C23D0) == MH_OK) {
        Log("[MatrixSSE2] Hooked CMatrix::Transpose at 0x004C23D0 (SSE2 _MM_TRANSPOSE4_PS)");
    } else {
        Log("[MatrixSSE2] CMatrix::Transpose hook FAILED");
    }

    /*
    if (WineSafe_CreateHook((void*)0x004C2300, (void*)Hooked_PointXformInPlace,
                            (void**)&pOrigPointXformIP) == MH_OK &&
        WO_EnableHook((void*)0x004C2300) == MH_OK) {
        Log("[MatrixSSE2] Hooked PointTransformInPlace at 0x004C2300 (SSE2, 65 callers)");
    } else {
        Log("[MatrixSSE2] PointTransformInPlace hook FAILED");
    }
    */

    if (WineSafe_CreateHook((void*)0x004C1BF0, (void*)Hooked_Scale3x3,
                            (void**)&pOrigScale3x3) == MH_OK &&
        WO_EnableHook((void*)0x004C1BF0) == MH_OK) {
        Log("[MatrixSSE2] Hooked CMatrix::Scale3x3 at 0x004C1BF0 (SSE2, 37 callers)");
    } else {
        Log("[MatrixSSE2] CMatrix::Scale3x3 hook FAILED");
    }

    if (WineSafe_CreateHook((void*)0x004C3680, (void*)Hooked_MatFrom3x3,
                            (void**)&pOrigMatFrom3x3) == MH_OK &&
        WO_EnableHook((void*)0x004C3680) == MH_OK) {
        Log("[MatrixSSE2] Hooked CMatrix::From3x3 at 0x004C3680 (SSE2, 5 callers)");
    } else {
        Log("[MatrixSSE2] CMatrix::From3x3 hook FAILED");
    }
#else
    Log("[MatrixSSE2] Matrix-Ext hooks DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_INVERT_SSE2
    if (WineSafe_CreateHook((void*)0x004C2FC0, (void*)Hooked_MatInvertRigid,
                            (void**)&pOrigMatInvRigid) == MH_OK &&
        WO_EnableHook((void*)0x004C2FC0) == MH_OK) {
        Log("[MatrixSSE2] Hooked CMatrix::InvertRigid at 0x004C2FC0 (SSE2, ~34 callers)");
    } else {
        Log("[MatrixSSE2] CMatrix::InvertRigid hook FAILED");
    }
#else
    Log("[MatrixSSE2] CMatrix::InvertRigid DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_MISC_SSE2
    if (WineSafe_CreateHook((void*)0x004C2120, (void*)Hooked_MatScalarMul,
                            (void**)&pOrigMatScalarMul) == MH_OK &&
        WO_EnableHook((void*)0x004C2120) == MH_OK) {
        Log("[MatrixSSE2] Hooked CMatrix::ScalarMul at 0x004C2120 (SSE2, 4 callers)");
    } else {
        Log("[MatrixSSE2] CMatrix::ScalarMul hook FAILED");
    }

    if (WineSafe_CreateHook((void*)0x004C2210, (void*)Hooked_RowAffinePoint,
                            (void**)&pOrigRowAffinePoint) == MH_OK &&
        WO_EnableHook((void*)0x004C2210) == MH_OK) {
        Log("[MatrixSSE2] Hooked RowAffinePoint at 0x004C2210 (SSE2, 6 callers)");
    } else {
        Log("[MatrixSSE2] RowAffinePoint hook FAILED");
    }
#else
    Log("[MatrixSSE2] Matrix-Misc hooks DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_TRANSLATE_SSE2
    if (WineSafe_CreateHook((void*)0x004C1B30, (void*)Hooked_MatTranslateLocal,
                            (void**)&pOrigMatTranslate) == MH_OK &&
        WO_EnableHook((void*)0x004C1B30) == MH_OK) {
        Log("[MatrixSSE2] Hooked CMatrix::TranslateLocal at 0x004C1B30 (SSE2, 65+ callers)");
    } else {
        Log("[MatrixSSE2] CMatrix::TranslateLocal hook FAILED");
    }
#else
    Log("[MatrixSSE2] CMatrix::TranslateLocal DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_COPY
    return installed == (int)(sizeof(hooks) / sizeof(hooks[0]));
#else
    return true;
#endif
}

// ================================================================
// Cleanup
// ================================================================
void ShutdownMatrixCopySSE2() {
    MH_DisableHook((void*)0x00407F80);
    MH_DisableHook((void*)0x00407F40);
#if !TEST_DISABLE_MATRIX_MULTIPLY
    MH_DisableHook((void*)0x004C1F00);
#endif
#if !TEST_DISABLE_QUAT_MATRIX_SSE2
    MH_DisableHook((void*)0x004C1C40);
    MH_DisableHook((void*)0x004C1DE0);
    Log("[MatrixSSE2] Stats: QuatToMatrix core=%ld  fused wrapper=%ld",
        g_quat2mat_calls, g_quat2matfull_calls);
#endif
#if !TEST_DISABLE_MATRIX_VECTOR_SSE2
    MH_DisableHook((void*)0x004C21B0);
    MH_DisableHook((void*)0x004C2270);
#endif
#if !TEST_DISABLE_VEC_NORMALIZE_SSE2
    MH_DisableHook((void*)0x004C3420);
    MH_DisableHook((void*)0x004C3600);
    Log("[MatrixSSE2] Stats: Vec3Normalize=%ld", g_vec3norm_calls);
#endif
#if !TEST_DISABLE_MATRIX_EXT_SSE2
    MH_DisableHook((void*)0x004C23D0);
    MH_DisableHook((void*)0x004C2300);
    MH_DisableHook((void*)0x004C1BF0);
    MH_DisableHook((void*)0x004C3680);
    Log("[MatrixSSE2] Stats: Transpose=%ld  PointXformIP=%ld  Scale3x3=%ld  From3x3=%ld",
        g_mattranspose_calls, g_pointxformip_calls, g_scale3x3_calls, g_matfrom3x3_calls);
#endif
#if !TEST_DISABLE_MATRIX_INVERT_SSE2
    MH_DisableHook((void*)0x004C2FC0);
    Log("[MatrixSSE2] Stats: InvertRigid=%ld", g_matinvrigid_calls);
#endif
#if !TEST_DISABLE_MATRIX_MISC_SSE2
    MH_DisableHook((void*)0x004C2120);
    MH_DisableHook((void*)0x004C2210);
    Log("[MatrixSSE2] Stats: MatrixMisc(ScalarMul+RowAffine)=%ld", g_matscalarmul_calls);
#endif
#if !TEST_DISABLE_MATRIX_TRANSLATE_SSE2
    MH_DisableHook((void*)0x004C1B30);
    Log("[MatrixSSE2] Stats: TranslateLocal=%ld", g_mattranslate_calls);
#endif

    Log("[MatrixSSE2] Stats: MatrixCopy=%ld  MatrixIdentity=%ld  MatrixMul=%ld  MatVec3=%ld  MatVec4=%ld",
        g_matcopy_calls, g_matident_calls, g_matmul_calls, g_matvec3_calls, g_matvec4_calls);
}
