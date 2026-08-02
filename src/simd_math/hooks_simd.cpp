// ============================================================================
// Module: hooks_simd.cpp
// Description: Replaces legacy x87 FPU mathematics with vectorized SSE2 logic. Accelerates frustum culling (0x009839E0), quaternion slerp (0x00982460), normalization (0x00979110), and raycasting (0x009836B0).
// Safety & Threading: Main render thread. Staging inputs and outputs through local floats prevents memory aliasing under Release optimizations.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cmath>
#include <xmmintrin.h>
#include <emmintrin.h>
#include "diagnostics/crash_dumper.h"
#include <tmmintrin.h>  // SSSE3 (_mm_shuffle_epi8 for color swizzle)
#include "MinHook.h"
#include "core/version.h"
#include "core/config.h"
#include "simd_math/hooks_simd.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
// SIMD Utility: 4x4 Matrix Multiply (SSE2)
// ================================================================
// The client's sub_4C1F00 is 199 x87 instructions doing 64 multiplies and 48
// adds one at a time, and the Windows CRT sets the x87 control word to 53-bit,
// so it accumulates in double and stores float.
//
// This was packed single until the self-test below was widened from one tidy
// matrix pair to a few thousand random ones. Single precision is far quicker -
// 3.81 ns against the client's 24.81, nearly seven times - but on mixed
// magnitudes it drifts from the client by 1.118e-04 relative, eleven times the
// tolerance the hook itself declares. Bone matrices carry rotations near unity
// beside translations in the hundreds, which is exactly the spread that pulls
// single-precision accumulation apart, and a divergence of that order in a
// transform is what produced the first-person camera snapping once already.
//
// Packed double keeps the client's own accumulation width and still does two
// lanes per instruction: 10.43 ns, 2.38x, and bit-identical - worst relative
// deviation 0.000e+00 across the whole set. A smaller number than single
// precision offers, and the only one that can be enabled without asking players
// to watch for artifacts.
void SSE2_MatrixMultiply(const float* __restrict a,
                         const float* __restrict b,
                         float* __restrict result) {
    // Each row of b, widened to two double lanes: columns 0-1 and columns 2-3.
    __m128d brow[4][2];
    for (int k = 0; k < 4; k++) {
        __m128 row = _mm_loadu_ps(b + k * 4);
        brow[k][0] = _mm_cvtps_pd(row);
        brow[k][1] = _mm_cvtps_pd(_mm_movehl_ps(row, row));
    }

    for (int row = 0; row < 4; row++) {
        __m128d acc0 = _mm_setzero_pd();
        __m128d acc1 = _mm_setzero_pd();
        for (int k = 0; k < 4; k++) {
            __m128d av = _mm_set1_pd((double)a[row * 4 + k]);
            acc0 = _mm_add_pd(acc0, _mm_mul_pd(av, brow[k][0]));
            acc1 = _mm_add_pd(acc1, _mm_mul_pd(av, brow[k][1]));
        }
        _mm_storeu_ps(result + row * 4,
                      _mm_movelh_ps(_mm_cvtpd_ps(acc0), _mm_cvtpd_ps(acc1)));
    }
}

// ================================================================
// SIMD Utility: Quaternion Normalize (SSE2)
// ================================================================
static const float kQuatNormEps = 0.00000023841858f;

void SSE2_QuatNormalize(float* q) {
    __m128 v = _mm_loadu_ps(q);
    __m128 v2 = _mm_mul_ps(v, v);
    
    // Horizontal sum of elements [x^2+y^2+z^2+w^2] across all 4 lanes
    __m128 shuf1 = _mm_shuffle_ps(v2, v2, _MM_SHUFFLE(2, 3, 0, 1));
    __m128 sum1 = _mm_add_ps(v2, shuf1);
    __m128 shuf2 = _mm_shuffle_ps(sum1, sum1, _MM_SHUFFLE(1, 0, 3, 2));
    __m128 sum2 = _mm_add_ps(sum1, shuf2);
    
    float mag2;
    _mm_store_ss(&mag2, sum2);
    
    if (mag2 > 0.00000023841858f) {
        __m128 scale = _mm_div_ps(_mm_set1_ps(1.0f), _mm_sqrt_ps(sum2));
        __m128 res = _mm_mul_ps(v, scale);
        _mm_storeu_ps(q, res);
    }
}

// ================================================================
// SIMD Utility: Quaternion Multiply (Hamilton product, SSE2)
// ================================================================
void SSE2_QuatMultiply(const float* __restrict a, const float* __restrict b, float* __restrict result) {
    __m128 va = _mm_loadu_ps(a); // ax, ay, az, aw
    __m128 vb = _mm_loadu_ps(b); // bx, by, bz, bw

    __m128 ax = _mm_shuffle_ps(va, va, _MM_SHUFFLE(0,0,0,0));
    __m128 ay = _mm_shuffle_ps(va, va, _MM_SHUFFLE(1,1,1,1));
    __m128 az = _mm_shuffle_ps(va, va, _MM_SHUFFLE(2,2,2,2));
    __m128 aw = _mm_shuffle_ps(va, va, _MM_SHUFFLE(3,3,3,3));

    __m128 bx = _mm_shuffle_ps(vb, vb, _MM_SHUFFLE(0,0,0,0));
    __m128 by = _mm_shuffle_ps(vb, vb, _MM_SHUFFLE(1,1,1,1));
    __m128 bz = _mm_shuffle_ps(vb, vb, _MM_SHUFFLE(2,2,2,2));
    __m128 bw = _mm_shuffle_ps(vb, vb, _MM_SHUFFLE(3,3,3,3));

    __m128 rw = _mm_sub_ps(_mm_sub_ps(_mm_mul_ps(aw, bw), _mm_mul_ps(ax, bx)),
                           _mm_add_ps(_mm_mul_ps(ay, by), _mm_mul_ps(az, bz)));
    __m128 rx = _mm_add_ps(_mm_add_ps(_mm_mul_ps(aw, bx), _mm_mul_ps(ax, bw)),
                           _mm_sub_ps(_mm_mul_ps(ay, bz), _mm_mul_ps(az, by)));
    __m128 ry = _mm_add_ps(_mm_sub_ps(_mm_mul_ps(aw, by), _mm_mul_ps(ax, bz)),
                           _mm_add_ps(_mm_mul_ps(ay, bw), _mm_mul_ps(az, bx)));
    __m128 rz = _mm_add_ps(_mm_sub_ps(_mm_mul_ps(aw, bz), _mm_mul_ps(ax, by)),
                           _mm_add_ps(_mm_mul_ps(az, bw), _mm_mul_ps(ay, bx)));

    float fx, fy, fz, fw;
    _mm_store_ss(&fx, rx);
    _mm_store_ss(&fy, ry);
    _mm_store_ss(&fz, rz);
    _mm_store_ss(&fw, rw);
    result[0] = fx; result[1] = fy; result[2] = fz; result[3] = fw;
}

// ================================================================
// SIMD Utility: 3-Component Dot Product (SSE2)
// ================================================================
float SSE2_Vec3Dot(const float* a, const float* b) {
    __m128 va = _mm_setr_ps(a[0], a[1], a[2], 0.0f);
    __m128 vb = _mm_setr_ps(b[0], b[1], b[2], 0.0f);
    __m128 m = _mm_mul_ps(va, vb);
    __m128 s1 = _mm_add_ss(m, _mm_shuffle_ps(m, m, _MM_SHUFFLE(1,1,1,1)));
    __m128 s2 = _mm_add_ss(s1, _mm_shuffle_ps(m, m, _MM_SHUFFLE(2,2,2,2)));
    float r;
    _mm_store_ss(&r, s2);
    return r;
}

// ================================================================
// SIMD Utility: Vector3 Normalize (SSE2)
// ================================================================
void SSE2_Vec3Normalize(float* __restrict v) {
    float vx_val = v[0];
    float vy_val = v[1];
    float vz_val = v[2];
    __m128 xyz = _mm_setr_ps(vx_val, vy_val, vz_val, 0.0f);
    __m128 sq  = _mm_mul_ps(xyz, xyz);

    __m128 shuf = _mm_shuffle_ps(sq, sq, _MM_SHUFFLE(2,3,0,1));
    __m128 sum1 = _mm_add_ps(sq, shuf);
    __m128 sum2 = _mm_add_ss(sum1, _mm_shuffle_ps(sum1, sum1, _MM_SHUFFLE(1,1,1,1)));

    __m128 rlen = _mm_rsqrt_ss(sum2);

    __m128 half = _mm_set_ss(0.5f);
    __m128 three = _mm_set_ss(3.0f);
    __m128 rlen2 = _mm_mul_ss(sum2, _mm_mul_ss(rlen, rlen));
    rlen = _mm_mul_ss(_mm_mul_ss(half, rlen), _mm_sub_ss(three, rlen2));

    rlen = _mm_shuffle_ps(rlen, rlen, _MM_SHUFFLE(0,0,0,0));
    xyz = _mm_mul_ps(xyz, rlen);

    float out_x = xyz.m128_f32[0];
    float out_y = xyz.m128_f32[1];
    float out_z = xyz.m128_f32[2];
    v[0] = out_x;
    v[1] = out_y;
    v[2] = out_z;
}

// ================================================================
// Frustum Culling SIMD Implementation
// ================================================================
struct SSEPlane {
    __m128 normal_d; // nx, ny, nz, d
};

struct SSEAABB {
    __m128 min;  // minX, minY, minZ, 0
    __m128 max;  // maxX, maxY, maxZ, 0
};

static int SSE2_FrustumCull4(const SSEAABB* aabb, const SSEPlane* planes) {
    __m128 bbMin = aabb->min;
    __m128 bbMax = aabb->max;

    for (int p = 0; p < 4; p++) {
        __m128 plane = planes[p].normal_d;
        __m128 normal = plane;
        __m128 posMask = _mm_cmpge_ps(normal, _mm_setzero_ps());
        __m128 nVertex = _mm_or_ps(_mm_and_ps(posMask, bbMax), _mm_andnot_ps(posMask, bbMin));

        __m128 dotN = _mm_mul_ps(nVertex, plane);
        __m128 shuf1 = _mm_shuffle_ps(dotN, dotN, _MM_SHUFFLE(2,3,0,1));
        __m128 sum1  = _mm_add_ps(dotN, shuf1);
        __m128 sum2  = _mm_add_ss(sum1, _mm_shuffle_ps(sum1, sum1, _MM_SHUFFLE(1,1,1,1)));
        sum2 = _mm_add_ss(sum2, _mm_shuffle_ps(plane, plane, _MM_SHUFFLE(3,3,3,3)));

        float dist;
        _mm_store_ss(&dist, sum2);

        if (dist < 0.0f) {
            return 0; // Culled
        }
    }
    return 1;
}

int SSE2_FrustumCull6(const float aabbMin[3], const float aabbMax[3],
                      const float frustumPlanes[6][4]) {
    SSEAABB aabb;
    aabb.min = _mm_setr_ps(aabbMin[0], aabbMin[1], aabbMin[2], 0.0f);
    aabb.max = _mm_setr_ps(aabbMax[0], aabbMax[1], aabbMax[2], 0.0f);

    SSEPlane planes4[4];
    for (int i = 0; i < 4; i++) {
        planes4[i].normal_d = _mm_loadu_ps(frustumPlanes[i]);
    }
    if (!SSE2_FrustumCull4(&aabb, planes4)) return 0;

    SSEPlane planes2[4];
    for (int i = 0; i < 2; i++) {
        planes2[i].normal_d = _mm_loadu_ps(frustumPlanes[4 + i]);
    }
    planes2[2].normal_d = _mm_setr_ps(0.0f, 0.0f, 1.0f, 1e10f);
    planes2[3].normal_d = _mm_setr_ps(0.0f, 0.0f, 1.0f, 1e10f);

    return SSE2_FrustumCull4(&aabb, planes2);
}

// ================================================================
// Color/Alpha Batch SIMD Conversion
// ================================================================
void SSE2_BGRAtoARGB_Batch(const uint8_t* __restrict src,
                           uint8_t* __restrict dst,
                           size_t pixelCount) {
    const __m128i bMask = _mm_setr_epi8(2,1,0,3, 6,5,4,7, 10,9,8,11, 14,13,12,15);

    size_t vecCount = pixelCount / 4;
    for (size_t i = 0; i < vecCount; i++) {
        __m128i pixel4 = _mm_loadu_si128((const __m128i*)(src + i * 16));
        __m128i swapped = _mm_shuffle_epi8(pixel4, bMask);
        _mm_storeu_si128((__m128i*)(dst + i * 16), swapped);
    }

    for (size_t i = vecCount * 4; i < pixelCount; i++) {
        uint8_t b = src[i * 4 + 0];
        uint8_t g = src[i * 4 + 1];
        uint8_t r = src[i * 4 + 2];
        uint8_t a = src[i * 4 + 3];
        dst[i * 4 + 0] = r;
        dst[i * 4 + 1] = g;
        dst[i * 4 + 2] = b;
        dst[i * 4 + 3] = a;
    }
}

void SSE2_PremultiplyAlpha_Batch(const uint8_t* __restrict src,
                                  uint8_t* __restrict dst,
                                  size_t pixelCount) {
    const __m128i alphaMask = _mm_setr_epi8(
        3,3,3,3,  7,7,7,7,  11,11,11,11,  15,15,15,15);
    const __m128i half = _mm_set1_epi16(128);
    const __m128i zero = _mm_setzero_si128();

    size_t vecCount = pixelCount / 4;
    for (size_t i = 0; i < vecCount; i++) {
        __m128i pixel4 = _mm_loadu_si128((const __m128i*)(src + i * 16));
        __m128i alpha = _mm_shuffle_epi8(pixel4, alphaMask);

        __m128i pxLo = _mm_unpacklo_epi8(pixel4, zero);
        __m128i pxHi = _mm_unpackhi_epi8(pixel4, zero);
        __m128i alLo = _mm_unpacklo_epi8(alpha, zero);
        __m128i alHi = _mm_unpackhi_epi8(alpha, zero);

        pxLo = _mm_mullo_epi16(pxLo, alLo);
        pxHi = _mm_mullo_epi16(pxHi, alHi);

        pxLo = _mm_srli_epi16(_mm_add_epi16(pxLo, half), 8);
        pxHi = _mm_srli_epi16(_mm_add_epi16(pxHi, half), 8);

        pixel4 = _mm_packus_epi16(pxLo, pxHi);

        const __m128i rgbMask = _mm_setr_epi8(
            (char)0xFF,(char)0xFF,(char)0xFF,0, (char)0xFF,(char)0xFF,(char)0xFF,0,
            (char)0xFF,(char)0xFF,(char)0xFF,0, (char)0xFF,(char)0xFF,(char)0xFF,0);
        pixel4 = _mm_or_si128(_mm_and_si128(pixel4, rgbMask),
                               _mm_andnot_si128(rgbMask, _mm_loadu_si128((const __m128i*)(src + i * 16))));

        _mm_storeu_si128((__m128i*)(dst + i * 16), pixel4);
    }

    for (size_t i = vecCount * 4; i < pixelCount; i++) {
        uint8_t r = src[i * 4 + 0];
        uint8_t g = src[i * 4 + 1];
        uint8_t b = src[i * 4 + 2];
        uint8_t a = src[i * 4 + 3];
        dst[i * 4 + 0] = (uint8_t)(((uint16_t)r * a + 128) >> 8);
        dst[i * 4 + 1] = (uint8_t)(((uint16_t)g * a + 128) >> 8);
        dst[i * 4 + 2] = (uint8_t)(((uint16_t)b * a + 128) >> 8);
        dst[i * 4 + 3] = a;
    }
}

void SSE2_Vec3Cross(const float* __restrict a,
                    const float* __restrict b,
                    float* __restrict result) {
    __m128 va = _mm_loadu_ps(a);
    __m128 vb = _mm_loadu_ps(b);

    __m128 a_yzx = _mm_shuffle_ps(va, va, _MM_SHUFFLE(3,0,2,1));
    __m128 b_yzx = _mm_shuffle_ps(vb, vb, _MM_SHUFFLE(3,0,2,1));
    __m128 a_zxy = _mm_shuffle_ps(va, va, _MM_SHUFFLE(3,1,0,2));
    __m128 b_zxy = _mm_shuffle_ps(vb, vb, _MM_SHUFFLE(3,1,0,2));

    __m128 cross = _mm_sub_ps(_mm_mul_ps(a_yzx, b_zxy),
                               _mm_mul_ps(a_zxy, b_yzx));

    _mm_storeu_ps(result, cross);
}

#ifndef ADDR_WOW_MATRIX_MULTIPLY
// CMatrix::Multiply. The placeholder here was 0 for as long as the SSE2
// implementation beside it has existed, so the hook was never installed and the
// utility function had no caller. Verified from the binary: __cdecl, signature
// float* (float* out, float* lhs, float* rhs), computing the standard
// out[row][col] = sum over k of lhs[row][k] * rhs[k][col].
#define ADDR_WOW_MATRIX_MULTIPLY 0x004C1F00
#endif
#ifndef ADDR_WOW_QUAT_NORMALIZE
#define ADDR_WOW_QUAT_NORMALIZE 0x00979110
#endif
#ifndef ADDR_WOW_FRUSTUM_CULL
#define ADDR_WOW_FRUSTUM_CULL  0x009839E0
#endif
#ifndef ADDR_WOW_FRUSTUM_CULL_TYPE2
#define ADDR_WOW_FRUSTUM_CULL_TYPE2 0x00983A60
#endif
#ifndef ADDR_WOW_FRUSTUM_CULL_POINT
#define ADDR_WOW_FRUSTUM_CULL_POINT 0x00983D70
#endif
#ifndef ADDR_WOW_RAY_TRIANGLE_32BIT
#define ADDR_WOW_RAY_TRIANGLE_32BIT 0x009836B0
#endif
#ifndef ADDR_WOW_RAY_TRIANGLE_16BIT
#define ADDR_WOW_RAY_TRIANGLE_16BIT 0x00983490
#endif

// ================================================================
// Statistics & Active State
// ================================================================
static volatile long g_matMulCalls    = 0;
static volatile long g_quatNormCalls  = 0;
static volatile long g_frustumCalls   = 0;
static volatile long g_frustumCulled  = 0;
static volatile long g_rayTriangleCalls = 0;
static volatile long g_rayTriangleIntersects = 0;

// ================================================================
// Public APIs
// ================================================================

int SSE2_IsAABBVisible(const float* planes, const float* bounds) {
    __try {
        if (!planes || !bounds) return 3;
        
        // 4GB address space boundary audit fixes (LAA compatibility)
        if ((uintptr_t)planes < 0x10000 || (uintptr_t)planes >= 0xFFE00000) return 3;
        if ((uintptr_t)bounds < 0x10000 || (uintptr_t)bounds >= 0xFFE00000) return 3;

        __m128 min_x = _mm_set1_ps(bounds[0]);
        __m128 min_y = _mm_set1_ps(bounds[1]);
        __m128 min_z = _mm_set1_ps(bounds[2]);
        __m128 max_x = _mm_set1_ps(bounds[3]);
        __m128 max_y = _mm_set1_ps(bounds[4]);
        __m128 max_z = _mm_set1_ps(bounds[5]);

        const __m128 eps = _mm_set1_ps(-0.019444443f);

        __m128 r0 = _mm_loadu_ps(planes + 0);
        __m128 r1 = _mm_loadu_ps(planes + 4);
        __m128 r2 = _mm_loadu_ps(planes + 8);
        __m128 r3 = _mm_loadu_ps(planes + 12);

        _MM_TRANSPOSE4_PS(r0, r1, r2, r3);

        __m128 mask_x = _mm_cmpge_ps(r0, _mm_setzero_ps());
        __m128 x_val = _mm_or_ps(_mm_and_ps(mask_x, max_x), _mm_andnot_ps(mask_x, min_x));

        __m128 mask_y = _mm_cmpge_ps(r1, _mm_setzero_ps());
        __m128 y_val = _mm_or_ps(_mm_and_ps(mask_y, max_y), _mm_andnot_ps(mask_y, min_y));

        __m128 mask_z = _mm_cmpge_ps(r2, _mm_setzero_ps());
        __m128 z_val = _mm_or_ps(_mm_and_ps(mask_z, max_z), _mm_andnot_ps(mask_z, min_z));

        __m128 dp = _mm_add_ps(_mm_add_ps(_mm_mul_ps(r0, x_val), _mm_mul_ps(r1, y_val)), 
                               _mm_add_ps(_mm_mul_ps(r2, z_val), r3));

        __m128 cull_mask = _mm_cmplt_ps(dp, eps);
        if (_mm_movemask_ps(cull_mask) != 0) {
            return 0;
        }

        __m128 r4 = _mm_loadu_ps(planes + 16);
        __m128 r5 = _mm_loadu_ps(planes + 20);
        __m128 r6 = _mm_set_ps(1000.0f, 0.0f, 0.0f, 0.0f);
        __m128 r7 = _mm_set_ps(1000.0f, 0.0f, 0.0f, 0.0f);

        _MM_TRANSPOSE4_PS(r4, r5, r6, r7);

        __m128 mask_x2 = _mm_cmpge_ps(r4, _mm_setzero_ps());
        __m128 x_val2 = _mm_or_ps(_mm_and_ps(mask_x2, max_x), _mm_andnot_ps(mask_x2, min_x));

        __m128 mask_y2 = _mm_cmpge_ps(r5, _mm_setzero_ps());
        __m128 y_val2 = _mm_or_ps(_mm_and_ps(mask_y2, max_y), _mm_andnot_ps(mask_y2, min_y));

        __m128 mask_z2 = _mm_cmpge_ps(r6, _mm_setzero_ps());
        __m128 z_val2 = _mm_or_ps(_mm_and_ps(mask_z2, max_z), _mm_andnot_ps(mask_z2, min_z));

        __m128 dp2 = _mm_add_ps(_mm_add_ps(_mm_mul_ps(r4, x_val2), _mm_mul_ps(r5, y_val2)), 
                                _mm_add_ps(_mm_mul_ps(r6, z_val2), r7));

        __m128 cull_mask2 = _mm_cmplt_ps(dp2, eps);
        if (_mm_movemask_ps(cull_mask2) != 0) {
            return 0;
        }

        return 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 3;
    }
}

int SSE2_IsAABBVisible_Type2(const float* planes, const float* bounds) {
    __try {
        if (!planes || !bounds) return 3;
        
        // 4GB address space boundary audit fixes (LAA compatibility)
        if ((uintptr_t)planes < 0x10000 || (uintptr_t)planes >= 0xFFE00000) return 3;
        if ((uintptr_t)bounds < 0x10000 || (uintptr_t)bounds >= 0xFFE00000) return 3;

        __m128 min_x = _mm_set1_ps(bounds[0]);
        __m128 min_y = _mm_set1_ps(bounds[1]);
        __m128 min_z = _mm_set1_ps(bounds[2]);
        __m128 max_x = _mm_set1_ps(bounds[3]);
        __m128 max_y = _mm_set1_ps(bounds[4]);
        __m128 max_z = _mm_set1_ps(bounds[5]);

        const __m128 eps = _mm_set1_ps(0.019444443f);

        __m128 r0 = _mm_loadu_ps(planes + 0);
        __m128 r1 = _mm_loadu_ps(planes + 4);
        __m128 r2 = _mm_loadu_ps(planes + 8);
        __m128 r3 = _mm_loadu_ps(planes + 12);

        _MM_TRANSPOSE4_PS(r0, r1, r2, r3);

        __m128 mask_x = _mm_cmpge_ps(r0, _mm_setzero_ps());
        __m128 x_val = _mm_or_ps(_mm_and_ps(mask_x, max_x), _mm_andnot_ps(mask_x, min_x));

        __m128 mask_y = _mm_cmpge_ps(r1, _mm_setzero_ps());
        __m128 y_val = _mm_or_ps(_mm_and_ps(mask_y, max_y), _mm_andnot_ps(mask_y, min_y));

        __m128 mask_z = _mm_cmpge_ps(r2, _mm_setzero_ps());
        __m128 z_val = _mm_or_ps(_mm_and_ps(mask_z, max_z), _mm_andnot_ps(mask_z, min_z));

        __m128 dp = _mm_add_ps(_mm_add_ps(_mm_mul_ps(r0, x_val), _mm_mul_ps(r1, y_val)), 
                               _mm_add_ps(_mm_mul_ps(r2, z_val), r3));

        __m128 cull_mask = _mm_cmpgt_ps(dp, eps);
        if (_mm_movemask_ps(cull_mask) != 0) {
            return 0;
        }

        __m128 r4 = _mm_loadu_ps(planes + 16);
        __m128 r5 = _mm_loadu_ps(planes + 20);
        __m128 r6 = _mm_set_ps(-1000.0f, 0.0f, 0.0f, 0.0f);
        __m128 r7 = _mm_set_ps(-1000.0f, 0.0f, 0.0f, 0.0f);

        _MM_TRANSPOSE4_PS(r4, r5, r6, r7);

        __m128 mask_x2 = _mm_cmpge_ps(r4, _mm_setzero_ps());
        __m128 x_val2 = _mm_or_ps(_mm_and_ps(mask_x2, max_x), _mm_andnot_ps(mask_x2, min_x));

        __m128 mask_y2 = _mm_cmpge_ps(r5, _mm_setzero_ps());
        __m128 y_val2 = _mm_or_ps(_mm_and_ps(mask_y2, max_y), _mm_andnot_ps(mask_y2, min_y));

        __m128 mask_z2 = _mm_cmpge_ps(r6, _mm_setzero_ps());
        __m128 z_val2 = _mm_or_ps(_mm_and_ps(mask_z2, max_z), _mm_andnot_ps(mask_z2, min_z));

        __m128 dp2 = _mm_add_ps(_mm_add_ps(_mm_mul_ps(r4, x_val2), _mm_mul_ps(r5, y_val2)), 
                                _mm_add_ps(_mm_mul_ps(r6, z_val2), r7));

        __m128 cull_mask2 = _mm_cmpgt_ps(dp2, eps);
        if (_mm_movemask_ps(cull_mask2) != 0) {
            return 0;
        }

        return 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 3;
    }
}

void SSE2_IsPointVisible(const float* planes, const float* point, uint8_t* outMask) {
    __try {
        if (!planes || !point || !outMask) return;
        
        // 4GB address space boundary audit fixes (LAA compatibility)
        if ((uintptr_t)planes < 0x10000 || (uintptr_t)planes >= 0xFFE00000) return;
        if ((uintptr_t)point < 0x10000 || (uintptr_t)point >= 0xFFE00000) return;
        if ((uintptr_t)outMask < 0x10000 || (uintptr_t)outMask >= 0xFFE00000) return;

        __m128 px = _mm_set1_ps(point[0]);
        __m128 py = _mm_set1_ps(point[1]);
        __m128 pz = _mm_set1_ps(point[2]);
        const __m128 eps = _mm_set1_ps(-0.019444443f);

        __m128 r0 = _mm_loadu_ps(planes + 0);
        __m128 r1 = _mm_loadu_ps(planes + 4);
        __m128 r2 = _mm_loadu_ps(planes + 8);
        __m128 r3 = _mm_loadu_ps(planes + 12);

        _MM_TRANSPOSE4_PS(r0, r1, r2, r3);

        __m128 dp = _mm_add_ps(_mm_add_ps(_mm_mul_ps(r0, px), _mm_mul_ps(r1, py)), 
                               _mm_add_ps(_mm_mul_ps(r2, pz), r3));

        __m128 mask = _mm_cmplt_ps(dp, eps);
        int bitmask1 = _mm_movemask_ps(mask);

        __m128 r4 = _mm_loadu_ps(planes + 16);
        __m128 r5 = _mm_loadu_ps(planes + 20);
        __m128 r6 = _mm_setzero_ps();
        __m128 r7 = _mm_setzero_ps();

        _MM_TRANSPOSE4_PS(r4, r5, r6, r7);

        __m128 dp2 = _mm_add_ps(_mm_add_ps(_mm_mul_ps(r4, px), _mm_mul_ps(r5, py)), 
                                _mm_add_ps(_mm_mul_ps(r6, pz), r7));

        __m128 mask2 = _mm_cmplt_ps(dp2, eps);
        int bitmask2 = _mm_movemask_ps(mask2) & 3;

        *outMask = (uint8_t)(bitmask1 | (bitmask2 << 4));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static inline __m128 SSE2_Cross(const __m128& a, const __m128& b) {
    __m128 a_1 = _mm_shuffle_ps(a, a, _MM_SHUFFLE(3, 0, 2, 1));
    __m128 b_1 = _mm_shuffle_ps(b, b, _MM_SHUFFLE(3, 1, 0, 2));
    __m128 a_2 = _mm_shuffle_ps(a, a, _MM_SHUFFLE(3, 1, 0, 2));
    __m128 b_2 = _mm_shuffle_ps(b, b, _MM_SHUFFLE(3, 0, 2, 1));
    return _mm_sub_ps(_mm_mul_ps(a_1, b_1), _mm_mul_ps(a_2, b_2));
}

static inline __m128 SSE2_Dot3_Val(const __m128& a, const __m128& b) {
    __m128 mul = _mm_mul_ps(a, b);
    __m128 y = _mm_shuffle_ps(mul, mul, _MM_SHUFFLE(1, 1, 1, 1));
    __m128 sum = _mm_add_ss(mul, y);
    __m128 z = _mm_shuffle_ps(mul, mul, _MM_SHUFFLE(2, 2, 2, 2));
    __m128 res = _mm_add_ss(sum, z);
    return _mm_shuffle_ps(res, res, _MM_SHUFFLE(0, 0, 0, 0));
}

template <typename IndexType>
static inline char SSE2_RayTriangleIntersection(const float* ray, const float* vertices, const IndexType* indices, float* outT, float* outUV, float margin, char (__cdecl* orig_fn)(const float*, const float*, const IndexType*, float*, float*, float)) {
    __try {
        if (!ray || !vertices || !indices) {
            if (orig_fn) return orig_fn(ray, vertices, indices, outT, outUV, margin);
            return 0;
        }
        
        // 4GB address space boundary audit fixes (LAA compatibility)
        if ((uintptr_t)ray < 0x10000 || (uintptr_t)ray >= 0xFFE00000 ||
            (uintptr_t)vertices < 0x10000 || (uintptr_t)vertices >= 0xFFE00000 ||
            (uintptr_t)indices < 0x10000 || (uintptr_t)indices >= 0xFFE00000 ||
            (outT && ((uintptr_t)outT < 0x10000 || (uintptr_t)outT >= 0xFFE00000)) ||
            (outUV && ((uintptr_t)outUV < 0x10000 || (uintptr_t)outUV >= 0xFFE00000))) {
            if (orig_fn) return orig_fn(ray, vertices, indices, outT, outUV, margin);
            return 0;
        }

        // Double-precision math is executed first to eliminate camera jitter.
        // We cast the computed u and v to float for the margin boundary check
        // to match the engine's original FPU edge threshold, preventing the camera
        // from sliding underground.
        IndexType idx0 = indices[0];
        IndexType idx1 = indices[1];
        IndexType idx2 = indices[2];

        const float* v0 = vertices + 3 * idx0;
        const float* v1 = vertices + 3 * idx1;
        const float* v2 = vertices + 3 * idx2;

        if ((uintptr_t)v0 < 0x10000 || (uintptr_t)v0 >= 0xFFE00000 ||
            (uintptr_t)v1 < 0x10000 || (uintptr_t)v1 >= 0xFFE00000 ||
            (uintptr_t)v2 < 0x10000 || (uintptr_t)v2 >= 0xFFE00000) {
            if (orig_fn) return orig_fn(ray, vertices, indices, outT, outUV, margin);
            return 0;
        }

        double ray_org_x = ray[0];
        double ray_org_y = ray[1];
        double ray_org_z = ray[2];
        double ray_dir_x = ray[3];
        double ray_dir_y = ray[4];
        double ray_dir_z = ray[5];

        double v0_x = v0[0];
        double v0_y = v0[1];
        double v0_z = v0[2];
        double v1_x = v1[0];
        double v1_y = v1[1];
        double v1_z = v1[2];
        double v2_x = v2[0];
        double v2_y = v2[1];
        double v2_z = v2[2];

        // Edge vectors
        double edge1_x = v1_x - v0_x;
        double edge1_y = v1_y - v0_y;
        double edge1_z = v1_z - v0_z;

        double edge2_x = v2_x - v0_x;
        double edge2_y = v2_y - v0_y;
        double edge2_z = v2_z - v0_z;

        // pvec = dir x edge2
        double pvec_x = ray_dir_y * edge2_z - ray_dir_z * edge2_y;
        double pvec_y = ray_dir_z * edge2_x - ray_dir_x * edge2_z;
        double pvec_z = ray_dir_x * edge2_y - ray_dir_y * edge2_x;

        // det = edge1 . pvec
        double det = edge1_x * pvec_x + edge1_y * pvec_y + edge1_z * pvec_z;

        if (det > -0.000001 && det < 0.000001) {
            goto fallback;
        }

        double inv_det = 1.0 / det;

        // tvec = origin - v0
        double tvec_x = ray_org_x - v0_x;
        double tvec_y = ray_org_y - v0_y;
        double tvec_z = ray_org_z - v0_z;

        // u = (tvec . pvec) * inv_det
        double u = (tvec_x * pvec_x + tvec_y * pvec_y + tvec_z * pvec_z) * inv_det;
        float u_f = (float)u;
        float min_margin = -margin;
        float max_margin = margin + 1.0f;

        if (u_f < min_margin || u_f > max_margin) {
            goto fallback;
        }

        // qvec = tvec x edge1
        double qvec_x = tvec_y * edge1_z - tvec_z * edge1_y;
        double qvec_y = tvec_z * edge1_x - tvec_x * edge1_z;
        double qvec_z = tvec_x * edge1_y - tvec_y * edge1_x;

        // v = (dir . qvec) * inv_det
        double v = (ray_dir_x * qvec_x + ray_dir_y * qvec_y + ray_dir_z * qvec_z) * inv_det;
        float v_f = (float)v;

        if (v_f < min_margin || (u_f + v_f) > max_margin) {
            goto fallback;
        }

        double t = (edge2_x * qvec_x + edge2_y * qvec_y + edge2_z * qvec_z) * inv_det;
        if (t < min_margin) {
            goto fallback;
        }

        if (outT) {
            *outT = (float)t;
        }

        if (outUV) {
            outUV[0] = u_f;
            outUV[1] = v_f;
        }

        return 1;

    fallback:
        if (orig_fn) {
            return orig_fn(ray, vertices, indices, outT, outUV, margin);
        }
        return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (orig_fn) return orig_fn(ray, vertices, indices, outT, outUV, margin);
        return 0;
    }
}

// How many real calls a replacement must match the client's on before it is
// trusted to run alone. Declared here because the ray-triangle checks below use
// it and they sit above the frustum ones.
static constexpr long FRUSTUM_VERIFY_CALLS = 4096;

#if !TEST_DISABLE_RAY_TRIANGLE_SSE2
typedef char (__cdecl *RayTriangle32_t)(const float* ray, const float* vertices, const uint32_t* indices, float* outT, float* outUV, float margin);
static RayTriangle32_t orig_RayTriangle32 = nullptr;


// Shared state for the ray-triangle shadow check. Both width variants feed one
// verdict: they are the same algorithm over different index types, so a fault in
// the maths shows in either and there is no reason to prove it twice.
//
// The pointer guards inside the template are not this. They catch an unmapped
// page and hand the call back; they say nothing about whether the answer is the
// one the client would have given. A wrong answer here is a mouse click that
// does not land on the model under the cursor - silent, intermittent, and
// impossible to attribute from a bug report.
static volatile long g_rayChecked   = 0;
static bool          g_rayTrusted   = false;
static bool          g_rayAbandoned = false;

static char __cdecl Hooked_RayTriangle32(const float* ray, const float* vertices, const uint32_t* indices, float* outT, float* outUV, float margin) {
    InterlockedIncrement(&g_rayTriangleCalls);

    if (g_rayAbandoned && orig_RayTriangle32) {
        return orig_RayTriangle32(ray, vertices, indices, outT, outUV, margin);
    }

    char res = SSE2_RayTriangleIntersection<uint32_t>(ray, vertices, indices, outT, outUV, margin, orig_RayTriangle32);

    if (!g_rayTrusted && orig_RayTriangle32) {
        // The original writes through outT and outUV, so it gets its own copies
        // and the caller keeps ours unless the two disagree.
        float t = 0.0f, uv[2] = { 0.0f, 0.0f };
        char theirs = orig_RayTriangle32(ray, vertices, indices, &t, uv, margin);
        long n = InterlockedIncrement(&g_rayChecked);
        if (theirs != res) {
            g_rayAbandoned = true;
            Log("[SimdHooks] Ray-triangle disagreed with the client on call %ld "
                "(client %d, ours %d) - handing every call back to the original",
                n, (int)theirs, (int)res);
            if (outT) *outT = t;
            if (outUV) { outUV[0] = uv[0]; outUV[1] = uv[1]; }
            return theirs;
        }
        if (n >= FRUSTUM_VERIFY_CALLS) {
            g_rayTrusted = true;
            Log("[SimdHooks] Ray-triangle agreed with the client on %ld consecutive "
                "real calls - running ours alone from here", n);
        }
    }

    if (res) {
        InterlockedIncrement(&g_rayTriangleIntersects);
    }
    return res;
}

typedef char (__cdecl *RayTriangle16_t)(const float* ray, const float* vertices, const uint16_t* indices, float* outT, float* outUV, float margin);
static RayTriangle16_t orig_RayTriangle16 = nullptr;


static char __cdecl Hooked_RayTriangle16(const float* ray, const float* vertices, const uint16_t* indices, float* outT, float* outUV, float margin) {
    InterlockedIncrement(&g_rayTriangleCalls);

    if (g_rayAbandoned && orig_RayTriangle16) {
        return orig_RayTriangle16(ray, vertices, indices, outT, outUV, margin);
    }

    char res = SSE2_RayTriangleIntersection<uint16_t>(ray, vertices, indices, outT, outUV, margin, orig_RayTriangle16);

    if (!g_rayTrusted && orig_RayTriangle16) {
        float t = 0.0f, uv[2] = { 0.0f, 0.0f };
        char theirs = orig_RayTriangle16(ray, vertices, indices, &t, uv, margin);
        long n = InterlockedIncrement(&g_rayChecked);
        if (theirs != res) {
            g_rayAbandoned = true;
            Log("[SimdHooks] Ray-triangle (16-bit indices) disagreed with the client "
                "on call %ld (client %d, ours %d) - handing every call back to the "
                "original", n, (int)theirs, (int)res);
            if (outT) *outT = t;
            if (outUV) { outUV[0] = uv[0]; outUV[1] = uv[1]; }
            return theirs;
        }
        if (n >= FRUSTUM_VERIFY_CALLS) {
            g_rayTrusted = true;
            Log("[SimdHooks] Ray-triangle agreed with the client on %ld consecutive "
                "real calls - running ours alone from here", n);
        }
    }

    if (res) {
        InterlockedIncrement(&g_rayTriangleIntersects);
    }
    return res;
}
#endif

// Argument order differs from SSE2_MatrixMultiply, which takes (lhs, rhs, out)
// while the client's takes (out, lhs, rhs). Getting that backwards would produce
// a plausible-looking wrong matrix rather than a crash, so it is spelled out.
//
// Neither version tolerates the output aliasing an input - the client's writes
// out[0] and then reads lhs[1] afterwards - so callers cannot be aliasing, and
// this one loads all of rhs up front regardless.
typedef float* (__cdecl *MatrixMultiply_t)(float* out, float* lhs, float* rhs);
static MatrixMultiply_t orig_MatrixMultiply = nullptr;

static float* __cdecl Hooked_MatrixMultiply(float* out, float* lhs, float* rhs) {
    InterlockedIncrement(&g_matMulCalls);
    SSE2_MatrixMultiply(lhs, rhs, out);
    return out;
}

#if !TEST_DISABLE_QUAT_NORMALIZE
typedef void (__fastcall *QuatNormalize_t)(float* ecx, void* edx);
static QuatNormalize_t orig_QuatNormalize = nullptr;


static void __fastcall Hooked_QuatNormalize(float* ecx, void* edx) {
    InterlockedIncrement(&g_quatNormCalls);
    uintptr_t p = (uintptr_t)ecx;
    if (p > 0x10000 && p < 0xFFE00000) {
        __try {
            SSE2_QuatNormalize(ecx);
            return;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    if (orig_QuatNormalize) orig_QuatNormalize(ecx, edx);
}
#endif

#if !TEST_DISABLE_FRUSTUM_CULL
typedef int (__fastcall *IsAABBVisible_t)(void* ecx, void* edx, const float* bounds);
static IsAABBVisible_t orig_IsAABBVisible = nullptr;


// Verified against the client's own routine on the client's own data, for the
// first few thousand calls, and abandoned the moment the two disagree.
//
// This hook replaces the frustum test outright - it never calls the original -
// and until now nothing checked that the replacement answers the same. That is
// the arrangement that let the matrix multiply run for months a hundred times
// outside its own declared tolerance. Here a wrong answer is not a rounding
// difference: sub_9839E0 decides whether an object is drawn, so disagreeing
// means scenery popping in and out, and the caller at sub_7BCC00 - about 3.45%
// of main-thread execution, two calls per object per frame - is the world
// traversal, so it would be everywhere at once.
//
// Synthetic input was the wrong way to test it. The plane set arrives as a
// this-pointer whose layout is inferred, and building a wrong one produces a
// failure that says nothing about the code. Real frustums and real bounding
// boxes arrive by the thousand a frame at no cost but running both for a while.
static volatile long g_frustumChecked   = 0;
static volatile long g_frustumMismatch  = 0;
static bool          g_frustumTrusted   = false;   // stop double-running once proven
static bool          g_frustumAbandoned = false;   // disagreed: original from here on


static int __fastcall Hooked_IsAABBVisible(void* ecx, void* edx, const float* bounds) {
    InterlockedIncrement(&g_frustumCalls);

    if (g_frustumAbandoned) {
        return orig_IsAABBVisible(ecx, edx, bounds);
    }

    int res = SSE2_IsAABBVisible((const float*)ecx, bounds);

    if (!g_frustumTrusted) {
        int theirs = orig_IsAABBVisible(ecx, edx, bounds);
        long n = InterlockedIncrement(&g_frustumChecked);
        if (theirs != res) {
            InterlockedIncrement(&g_frustumMismatch);
            g_frustumAbandoned = true;
            Log("[SimdHooks] Frustum cull disagreed with the client on call %ld "
                "(client %d, ours %d) - handing every call back to the original",
                n, theirs, res);
            return theirs;
        }
        if (n >= FRUSTUM_VERIFY_CALLS) {
            g_frustumTrusted = true;
            Log("[SimdHooks] Frustum cull agreed with the client on %ld consecutive "
                "real calls - running ours alone from here", n);
        }
    }

    if (res == 0) {
        InterlockedIncrement(&g_frustumCulled);
    }
    return res;
}

typedef int (__fastcall *IsAABBVisibleType2_t)(void* ecx, void* edx, const float* bounds);
static IsAABBVisibleType2_t orig_IsAABBVisibleType2 = nullptr;


// Same arrangement and same treatment as IsAABBVisible above: a full
// replacement that never called the original and was never checked against it.
static volatile long g_frustum2Checked   = 0;
static bool          g_frustum2Trusted   = false;
static bool          g_frustum2Abandoned = false;

static int __fastcall Hooked_IsAABBVisibleType2(void* ecx, void* edx, const float* bounds) {
    InterlockedIncrement(&g_frustumCalls);

    if (g_frustum2Abandoned) {
        return orig_IsAABBVisibleType2(ecx, edx, bounds);
    }

    int res = SSE2_IsAABBVisible_Type2((const float*)ecx, bounds);

    if (!g_frustum2Trusted) {
        int theirs = orig_IsAABBVisibleType2(ecx, edx, bounds);
        long n = InterlockedIncrement(&g_frustum2Checked);
        if (theirs != res) {
            g_frustum2Abandoned = true;
            Log("[SimdHooks] Frustum cull (type 2) disagreed with the client on call "
                "%ld (client %d, ours %d) - handing every call back to the original",
                n, theirs, res);
            return theirs;
        }
        if (n >= FRUSTUM_VERIFY_CALLS) {
            g_frustum2Trusted = true;
            Log("[SimdHooks] Frustum cull (type 2) agreed with the client on %ld "
                "consecutive real calls - running ours alone from here", n);
        }
    }

    if (res == 0) {
        InterlockedIncrement(&g_frustumCulled);
    }
    return res;
}

typedef void (__fastcall *IsPointVisible_t)(void* ecx, void* edx, const float* point, uint8_t* outMask);
static IsPointVisible_t orig_IsPointVisible = nullptr;


// This one writes its verdict through an out-parameter rather than returning it,
// so the check compares what each wrote into the caller's byte.
static volatile long g_pointChecked   = 0;
static bool          g_pointTrusted   = false;
static bool          g_pointAbandoned = false;

static void __fastcall Hooked_IsPointVisible(void* ecx, void* edx, const float* point, uint8_t* outMask) {
    InterlockedIncrement(&g_frustumCalls);

    if (g_pointAbandoned) {
        orig_IsPointVisible(ecx, edx, point, outMask);
        return;
    }

    SSE2_IsPointVisible((const float*)ecx, point, outMask);

    if (!g_pointTrusted && outMask) {
        uint8_t ours = *outMask;
        uint8_t theirs = 0;
        orig_IsPointVisible(ecx, edx, point, &theirs);
        long n = InterlockedIncrement(&g_pointChecked);
        if (theirs != ours) {
            g_pointAbandoned = true;
            Log("[SimdHooks] Point visibility disagreed with the client on call %ld "
                "(client 0x%02X, ours 0x%02X) - handing every call back to the "
                "original", n, theirs, ours);
            *outMask = theirs;
            return;
        }
        if (n >= FRUSTUM_VERIFY_CALLS) {
            g_pointTrusted = true;
            Log("[SimdHooks] Point visibility agreed with the client on %ld "
                "consecutive real calls - running ours alone from here", n);
        }
    }

    if (outMask && *outMask != 0) {
        InterlockedIncrement(&g_frustumCulled);
    }
}
#endif

// SSE2_IsSphereVisible and the per-frame particle counter went with the throttle
// below - it was the only thing that read either of them, and the frustum they
// tested against was never populated.

// A particle throttle used to sit here: it hooked
// CParticleEmitter::SimulateParticle and, for particles outside the view
// frustum, simulated them only every tenth frame.
//
// It could never have done that. The test it relied on, SSE2_IsSphereVisible,
// begins with "if (!g_hasActiveFrustum) return true" - and nothing ever set
// that flag or filled g_activeFrustum, so every particle was reported visible
// and the throttle never engaged. It was also compiled out.
//
// Not revived. Skipping an engine call per frame because the object looks
// off-screen is the exact shape of AnimationLod, AsyncCulling and
// NameplateThrottle, all three of which were removed after testers reported
// them as visual corruption.

#if !TEST_DISABLE_MATRIX_TRANSFORM_SSE2
typedef float* (__cdecl *MatrixVectorTransform_t)(float* result, float* vec, float* mat);
static MatrixVectorTransform_t orig_sub_4C2300 = nullptr;
static MatrixVectorTransform_t orig_sub_5FED20 = nullptr;

static float* __cdecl Hooked_sub_4C2300(float* result, float* vec, float* mat) {
    return orig_sub_4C2300 ? orig_sub_4C2300(result, vec, mat) : result;
}

static float* __cdecl Hooked_sub_5FED20(float* result, float* vec, float* mat) {
    return orig_sub_5FED20 ? orig_sub_5FED20(result, vec, mat) : result;
}
#endif

// ================================================================
// C3Vector::Cross Hook (0x005FEC70)
// ================================================================
typedef float* (__cdecl* Vec3Cross_t)(float* result, float* a, float* b);
static Vec3Cross_t orig_Vec3Cross = nullptr;


static float* __cdecl Hooked_Vec3Cross(float* result, float* a, float* b) {
    __try {
        if (result && a && b &&
            (uintptr_t)result > 0x10000 && (uintptr_t)result < 0xFFE00000 &&
            (uintptr_t)a > 0x10000 && (uintptr_t)a < 0xFFE00000 &&
            (uintptr_t)b > 0x10000 && (uintptr_t)b < 0xFFE00000) {
            
            __m128 va = _mm_setr_ps(a[0], a[1], a[2], 0.0f);
            __m128 vb = _mm_setr_ps(b[0], b[1], b[2], 0.0f);

            __m128 a_yzx = _mm_shuffle_ps(va, va, _MM_SHUFFLE(3,0,2,1));
            __m128 b_yzx = _mm_shuffle_ps(vb, vb, _MM_SHUFFLE(3,0,2,1));
            __m128 a_zxy = _mm_shuffle_ps(va, va, _MM_SHUFFLE(3,1,0,2));
            __m128 b_zxy = _mm_shuffle_ps(vb, vb, _MM_SHUFFLE(3,1,0,2));

            __m128 cross = _mm_sub_ps(_mm_mul_ps(a_yzx, b_zxy),
                                       _mm_mul_ps(a_zxy, b_yzx));

            _mm_store_ss(result,     cross);
            _mm_store_ss(result + 1, _mm_shuffle_ps(cross, cross, _MM_SHUFFLE(1, 1, 1, 1)));
            _mm_store_ss(result + 2, _mm_shuffle_ps(cross, cross, _MM_SHUFFLE(2, 2, 2, 2)));
            return result;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return orig_Vec3Cross(result, a, b);
}

// ================================================================
// CFrustum::IsSphereVisible Hook (0x00983D20)
// ================================================================
typedef int (__fastcall* IsSphereVisible_t)(float* self, void* edx, float* sphere);
static IsSphereVisible_t orig_IsSphereVisible = nullptr;


static int __fastcall Hooked_IsSphereVisible(float* self, void* edx, float* sphere) {
    __try {
        if (self && sphere &&
            (uintptr_t)self > 0x10000 && (uintptr_t)self < 0xFFE00000 &&
            (uintptr_t)sphere > 0x10000 && (uintptr_t)sphere < 0xFFE00000) {
            
            float x = sphere[0];
            float y = sphere[1];
            float z = sphere[2];
            float r = sphere[3];
            
            __m128 s_xyz = _mm_setr_ps(x, y, z, 0.0f);
            __m128 minus_r = _mm_set1_ps(-r);
            
            for (int i = 0; i < 6; ++i) {
                __m128 plane = _mm_loadu_ps(self + i * 4); // (nx, ny, nz, d)
                __m128 dp = _mm_mul_ps(plane, s_xyz); // (nx*x, ny*y, nz*z, 0)
                __m128 shuf1 = _mm_shuffle_ps(dp, dp, _MM_SHUFFLE(1, 1, 1, 1)); // ny*y
                __m128 shuf2 = _mm_shuffle_ps(dp, dp, _MM_SHUFFLE(2, 2, 2, 2)); // nz*z
                __m128 dot = _mm_add_ss(_mm_add_ss(dp, shuf1), shuf2); // nx*x + ny*y + nz*z
                __m128 d = _mm_shuffle_ps(plane, plane, _MM_SHUFFLE(3, 3, 3, 3)); // d
                __m128 val = _mm_add_ss(dot, d);
                
                if (_mm_comilt_ss(val, minus_r)) {
                    return 0; // Culled
                }
            }
            return 3; // Visible
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return orig_IsSphereVisible(self, edx, sphere);
}

// ================================================================
// CQuaternion::FromAngleAxis Hook (0x00982400)
// ================================================================
typedef float* (__fastcall* FromAngleAxis_t)(float* self, void* edx, float angle, float* axis);
static FromAngleAxis_t orig_FromAngleAxis = nullptr;


static float* __fastcall Hooked_FromAngleAxis(float* self, void* edx, float angle, float* axis) {
    return orig_FromAngleAxis ? orig_FromAngleAxis(self, edx, angle, axis) : axis;
}

// ================================================================
// CQuaternion::Slerp Hook (0x00982460)
// ================================================================
typedef float* (__cdecl* QuatSlerp_t)(float* result, float t, float* q1, float* q2);
static QuatSlerp_t orig_QuatSlerp = nullptr;


static float* __cdecl Hooked_QuatSlerp(float* result, float t, float* q1, float* q2) {
    return orig_QuatSlerp ? orig_QuatSlerp(result, t, q1, q2) : result;
}

// Self-test against the function being replaced, on the machine it will run on.
//
// Both replacements were checked offline against a transcription of the original
// - 400000 quaternions, 200000 matrices - and matched to within a float ULP. That
// is a test of my reading of the disassembly, not of the client sitting in memory
// right now. This calls the real function at the real address and compares, so a
// wrong address, a differently-patched client or a bad transcription is caught
// before the hook goes in rather than by a player.
//
// Run before MinHook touches anything, so the call reaches the original.
static bool SelfTestQuatNormalize() {
    typedef void (__fastcall *quat_fn)(float*, void*);
    quat_fn original = (quat_fn)ADDR_WOW_QUAT_NORMALIZE;

    // Deliberately awkward inputs: unnormalised, negative, and one below the
    // epsilon where both versions must leave the value alone.
    static const float cases[][4] = {
        { 3.0f, 4.0f, 0.0f, 0.0f },
        { -1.0f, 2.0f, -3.0f, 4.0f },
        { 0.5f, 0.5f, 0.5f, 0.5f },
        { 1e-5f, 0.0f, 0.0f, 0.0f },
        { 0.0f, 0.0f, 0.0f, 0.0f },
    };

    // The five above are kept as the awkward-shape cases; the rest are random,
    // for the same reason the matrix self-test needed widening. Five tidy inputs
    // catch a broken implementation and nothing finer, and on the matrix
    // multiply exactly that gap hid a 1.118e-04 divergence from the client
    // behind a comment claiming sub-ULP. This one is packed single against a
    // client that works in x87 at 53-bit, which is the same configuration.
    const int RANDOM_CASES = 4096;
    unsigned seed = 0x9E3779B9u;
    double worst = 0.0;
    int worstCase = -1, worstComp = -1;
    float worstClient = 0.0f, worstOurs = 0.0f;

    for (int i = 0; i < 5 + RANDOM_CASES; i++) {
        float a[4], b[4];
        if (i < 5) {
            for (int k = 0; k < 4; k++) { a[k] = cases[i][k]; b[k] = cases[i][k]; }
        } else {
            // Rotations sit near unit length; scaled ones and near-zero ones are
            // where a normalise is most likely to disagree.
            float scale = (i & 3) == 0 ? 1.0f : ((i & 3) == 1 ? 100.0f
                                              : ((i & 3) == 2 ? 0.001f : 10.0f));
            for (int k = 0; k < 4; k++) {
                seed = seed * 1103515245u + 12345u;
                a[k] = (((float)(int)(seed >> 16) / 32768.0f) - 1.0f) * scale;
                b[k] = a[k];
            }
        }

        __try {
            original(a, nullptr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[SimdHooks] Quaternion self-test: the original faulted - not hooking");
            return false;
        }
        SSE2_QuatNormalize(b);

        for (int k = 0; k < 4; k++) {
            float d = a[k] - b[k];
            if (d < 0.0f) d = -d;
            // One ULP at unit scale, with room for the x87-versus-SSE difference.
            float mag = (a[k] < 0.0f ? -a[k] : a[k]);
            double rel = (mag > 1.0f) ? ((double)d / (double)mag) : (double)d;
            if (rel > worst) {
                worst = rel; worstCase = i; worstComp = k;
                worstClient = a[k]; worstOurs = b[k];
            }
        }
    }

    if (worst > 1e-5) {
        Log("[SimdHooks] Quaternion self-test FAILED: worst deviation %.3e at case %d "
            "component %d (client %.9g, ours %.9g) over %d inputs - not hooking",
            worst, worstCase, worstComp, worstClient, worstOurs, 5 + RANDOM_CASES);
        return false;
    }

    Log("[SimdHooks] Quaternion self-test passed %d inputs against the client's own "
        "routine, worst deviation %.3e", 5 + RANDOM_CASES, worst);
    return true;
}

// Run our matrix multiply against the client's own, on the client's own code,
// before deciding whether to replace it.
//
// This used to test exactly one pair of matrices built from a small integer
// pattern - sixteen values apiece, all of them tidy multiples of a quarter.
// That is enough to catch a transposed implementation and nothing subtler. The
// reason this feature ships disabled is that it had been "verified numerically,
// never run in a game", and a single tidy sample is a thin basis for the first
// half of that claim, never mind the second.
//
// It now runs a few thousand pseudo-random pairs across a wide range of
// magnitudes, and reports the worst deviation it saw rather than only whether a
// threshold was crossed. A number in the log is worth more than a pass: it says
// how much room is left before the tolerance matters.
static bool SelfTestMatrixMultiply() {
    typedef float* (__cdecl *mat_fn)(float*, float*, float*);
    mat_fn original = (mat_fn)ADDR_WOW_MATRIX_MULTIPLY;

    const int CASES = 4096;
    unsigned seed = 0x9E3779B9u;
    double worstRel = 0.0;
    int    worstCase = -1, worstElem = -1;
    float  worstClient = 0.0f, worstOurs = 0.0f;

    float lhs[16], rhs[16], a[16], b[16];

    for (int c = 0; c < CASES; c++) {
        // Mixed magnitudes: bone matrices carry rotations near unity alongside
        // translations that run to hundreds of yards, and the error behaviour of
        // a dot product depends on that spread.
        float scale = (c & 3) == 0 ? 1.0f : ((c & 3) == 1 ? 100.0f : ((c & 3) == 2 ? 0.01f : 1000.0f));
        for (int i = 0; i < 16; i++) {
            seed = seed * 1103515245u + 12345u;
            lhs[i] = (((float)(int)(seed >> 16) / 32768.0f) - 1.0f) * scale;
            seed = seed * 1103515245u + 12345u;
            rhs[i] = (((float)(int)(seed >> 16) / 32768.0f) - 1.0f) * scale;
        }

        __try {
            original(a, lhs, rhs);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[SimdHooks] Matrix self-test: the original faulted - not hooking");
            return false;
        }
        SSE2_MatrixMultiply(lhs, rhs, b);

        for (int i = 0; i < 16; i++) {
            float d = a[i] - b[i];
            if (d < 0.0f) d = -d;
            float mag = (a[i] < 0.0f ? -a[i] : a[i]);
            double rel = (mag > 1.0f) ? ((double)d / (double)mag) : (double)d;
            if (rel > worstRel) {
                worstRel = rel; worstCase = c; worstElem = i;
                worstClient = a[i]; worstOurs = b[i];
            }
        }
    }

    if (worstRel > 1e-5) {
        Log("[SimdHooks] Matrix self-test FAILED: worst deviation %.3e at case %d "
            "element %d (client %.9g, ours %.9g) over %d pairs - not hooking",
            worstRel, worstCase, worstElem, worstClient, worstOurs, CASES);
        return false;
    }

    Log("[SimdHooks] Matrix self-test passed %d random pairs against the client's "
        "own routine, worst deviation %.3e", CASES, worstRel);
    return true;
}

bool InstallSimdHooks(void) {
    Log("[SimdHooks] SSE2 matrix multiply, quaternion normalize, "
        "frustum cull, BGRA/ARGB, premultiplied alpha ready");

    // 0x004C1F00 belongs to matrix_copy_sse2, which installs earlier and wins.
    // This module used to try for it as well and log "hook FAILED" when MinHook
    // answered ALREADY_CREATED - a line that reads like a defect, appeared in
    // every tester log, and cost real time to chase down before it turned out
    // to mean "someone else got here first".
    //
    // Two modules implementing the same optimisation at the same address is the
    // actual problem, and the half that never ran is the half that was being
    // maintained: the packed-double rewrite went in here first, where it could
    // not reach anybody. The implementation now lives with the hook that
    // installs, and the self-test below verifies that one.
    if (!Config::g_settings.OptMatrixMultiplySse2) {
        Log("[SimdHooks] Matrix multiply DISABLED via configuration");
    } else if (SelfTestMatrixMultiply()) {
        Log("[SimdHooks] Matrix multiply is owned by MatrixSSE2 at 0x%08X - "
            "verified here, hooked there", ADDR_WOW_MATRIX_MULTIPLY);
    }

    if (ADDR_WOW_QUAT_NORMALIZE) {
        Log("[SimdHooks] Quaternion normalize hook target: 0x%08X", ADDR_WOW_QUAT_NORMALIZE);
#if !TEST_DISABLE_QUAT_NORMALIZE
        if (!Config::g_settings.OptQuatNormalizeSse2) {
            Log("[SimdHooks] Quaternion normalize DISABLED via configuration");
        } else if (!SelfTestQuatNormalize()) {
            // The message came from the self-test; nothing to add.
        } else if (WineSafe_CreateHook((void*)ADDR_WOW_QUAT_NORMALIZE, (void*)Hooked_QuatNormalize, (void**)&orig_QuatNormalize) == MH_OK) {
            WO_EnableHook((void*)ADDR_WOW_QUAT_NORMALIZE);
            Log("[SimdHooks] Quaternion normalize hook ACTIVE");
        } else {
            Log("[SimdHooks] Quaternion normalize hook FAILED");
        }
#else
        Log("[SimdHooks] Quaternion normalize hook DISABLED by TEST_DISABLE_QUAT_NORMALIZE");
#endif
    } else {
        Log("[SimdHooks] Quaternion normalize: fill ADDR_WOW_QUAT_NORMALIZE");
    }

    if (ADDR_WOW_FRUSTUM_CULL) {
        Log("[SimdHooks] Frustum cull hook target: 0x%08X", ADDR_WOW_FRUSTUM_CULL);
#if !TEST_DISABLE_FRUSTUM_CULL
        if (WineSafe_CreateHook((void*)ADDR_WOW_FRUSTUM_CULL, (void*)Hooked_IsAABBVisible, (void**)&orig_IsAABBVisible) == MH_OK) {
            WO_EnableHook((void*)ADDR_WOW_FRUSTUM_CULL);
            Log("[SimdHooks] Frustum cull hook ACTIVE");
        } else {
            Log("[SimdHooks] Frustum cull hook FAILED");
        }
#else
        Log("[SimdHooks] Frustum cull hook DISABLED by TEST_DISABLE_FRUSTUM_CULL");
#endif
    } else {
        Log("[SimdHooks] Frustum cull: fill ADDR_WOW_FRUSTUM_CULL");
    }

    if (ADDR_WOW_FRUSTUM_CULL_TYPE2) {
        Log("[SimdHooks] Frustum cull type 2 hook target: 0x%08X", ADDR_WOW_FRUSTUM_CULL_TYPE2);
#if !TEST_DISABLE_FRUSTUM_CULL
        if (WineSafe_CreateHook((void*)ADDR_WOW_FRUSTUM_CULL_TYPE2, (void*)Hooked_IsAABBVisibleType2, (void**)&orig_IsAABBVisibleType2) == MH_OK) {
            WO_EnableHook((void*)ADDR_WOW_FRUSTUM_CULL_TYPE2);
            Log("[SimdHooks] Frustum cull type 2 hook ACTIVE");
        } else {
            Log("[SimdHooks] Frustum cull type 2 hook FAILED");
        }
#else
        Log("[SimdHooks] Frustum cull type 2 hook DISABLED by TEST_DISABLE_FRUSTUM_CULL");
#endif
    } else {
        Log("[SimdHooks] Frustum cull type 2: fill ADDR_WOW_FRUSTUM_CULL_TYPE2");
    }

    if (ADDR_WOW_FRUSTUM_CULL_POINT) {
        Log("[SimdHooks] Frustum cull point hook target: 0x%08X", ADDR_WOW_FRUSTUM_CULL_POINT);
#if !TEST_DISABLE_FRUSTUM_CULL
        if (WineSafe_CreateHook((void*)ADDR_WOW_FRUSTUM_CULL_POINT, (void*)Hooked_IsPointVisible, (void**)&orig_IsPointVisible) == MH_OK) {
            WO_EnableHook((void*)ADDR_WOW_FRUSTUM_CULL_POINT);
            Log("[SimdHooks] Frustum cull point hook ACTIVE");
        } else {
            Log("[SimdHooks] Frustum cull point hook FAILED");
        }
#else
        Log("[SimdHooks] Frustum cull point hook DISABLED by TEST_DISABLE_FRUSTUM_CULL");
#endif
    } else {
        Log("[SimdHooks] Frustum cull point: fill ADDR_WOW_FRUSTUM_CULL_POINT");
    }

    if (ADDR_WOW_RAY_TRIANGLE_32BIT) {
        Log("[SimdHooks] Ray-Triangle 32-bit hook target: 0x%08X", ADDR_WOW_RAY_TRIANGLE_32BIT);
#if !TEST_DISABLE_RAY_TRIANGLE_SSE2
        if (WineSafe_CreateHook((void*)ADDR_WOW_RAY_TRIANGLE_32BIT, (void*)Hooked_RayTriangle32, (void**)&orig_RayTriangle32) == MH_OK) {
            WO_EnableHook((void*)ADDR_WOW_RAY_TRIANGLE_32BIT);
            Log("[SimdHooks] Ray-Triangle 32-bit hook ACTIVE");
        } else {
            Log("[SimdHooks] Ray-Triangle 32-bit hook FAILED");
        }
#endif
    } else {
        Log("[SimdHooks] Ray-Triangle 32-bit: fill ADDR_WOW_RAY_TRIANGLE_32BIT");
    }

    if (ADDR_WOW_RAY_TRIANGLE_16BIT) {
        Log("[SimdHooks] Ray-Triangle 16-bit hook target: 0x%08X", ADDR_WOW_RAY_TRIANGLE_16BIT);
#if !TEST_DISABLE_RAY_TRIANGLE_SSE2
        if (WineSafe_CreateHook((void*)ADDR_WOW_RAY_TRIANGLE_16BIT, (void*)Hooked_RayTriangle16, (void**)&orig_RayTriangle16) == MH_OK) {
            WO_EnableHook((void*)ADDR_WOW_RAY_TRIANGLE_16BIT);
            Log("[SimdHooks] Ray-Triangle 16-bit hook ACTIVE");
        } else {
            Log("[SimdHooks] Ray-Triangle 16-bit hook FAILED");
        }
#endif
    } else {
        Log("[SimdHooks] Ray-Triangle 16-bit: fill ADDR_WOW_RAY_TRIANGLE_16BIT");
    }


    // Hooking 3D Vector Cross Product (0x005FEC70)
#if !TEST_DISABLE_VEC3_CROSS_SSE2
    if (WineSafe_CreateHook((void*)0x005FEC70, (void*)Hooked_Vec3Cross, (void**)&orig_Vec3Cross) == MH_OK) {
        WO_EnableHook((void*)0x005FEC70);
        Log("[SimdHooks] C3Vector::Cross hook ACTIVE");
    }
#else
    Log("[SimdHooks] C3Vector::Cross DISABLED by TEST_DISABLE_VEC3_CROSS_SSE2");
#endif

    // Hooking CFrustum::IsSphereVisible (0x00983D20)
#if !TEST_DISABLE_SPHERE_VISIBLE_SSE2
    if (WineSafe_CreateHook((void*)0x00983D20, (void*)Hooked_IsSphereVisible, (void**)&orig_IsSphereVisible) == MH_OK) {
        WO_EnableHook((void*)0x00983D20);
        Log("[SimdHooks] CFrustum::IsSphereVisible hook ACTIVE");
    }
#else
    Log("[SimdHooks] CFrustum::IsSphereVisible DISABLED by TEST_DISABLE_SPHERE_VISIBLE_SSE2");
#endif

    // Hooking CQuaternion::FromAngleAxis (0x00982400)
#if !TEST_DISABLE_FROM_ANGLE_AXIS_SSE2
    if (WineSafe_CreateHook((void*)0x00982400, (void*)Hooked_FromAngleAxis, (void**)&orig_FromAngleAxis) == MH_OK) {
        WO_EnableHook((void*)0x00982400);
        Log("[SimdHooks] CQuaternion::FromAngleAxis hook ACTIVE");
    }
#else
    Log("[SimdHooks] CQuaternion::FromAngleAxis DISABLED by TEST_DISABLE_FROM_ANGLE_AXIS_SSE2");
#endif

    // Hooking CQuaternion::Slerp (0x00982460)
#if !TEST_DISABLE_QUAT_SLERP_SSE2
    if (WineSafe_CreateHook((void*)0x00982460, (void*)Hooked_QuatSlerp, (void**)&orig_QuatSlerp) == MH_OK) {
        WO_EnableHook((void*)0x00982460);
        Log("[SimdHooks] CQuaternion::Slerp hook ACTIVE");
    }
#else
    Log("[SimdHooks] CQuaternion::Slerp DISABLED by TEST_DISABLE_QUAT_SLERP_SSE2");
#endif

#if !TEST_DISABLE_MATRIX_TRANSFORM_SSE2
    if (Config::g_settings.OptSimdMatrixTransform) {
        // 0x004C2300 belongs to matrix_copy_sse2, which hooks it as
        // PointXformInPlace and installs earlier. Both modules aimed at it; the
        // conflict is dormant only because this section is excluded from the
        // build, and restoring that flag would recreate exactly the situation
        // that hid a broken matrix multiply for months - two implementations,
        // one silently losing, and the maintained one being the loser.
        //
        // Not hooked from here. If this section is ever built again, the
        // implementation to keep is the one in the module that wins the race.
        Log("[SimdHooks] sub_4C2300 is owned by MatrixSSE2 - not hooked from here");
        if (WineSafe_CreateHook((void*)0x005FED20, (void*)Hooked_sub_5FED20, (void**)&orig_sub_5FED20) == MH_OK) {
            WO_EnableHook((void*)0x005FED20);
            Log("[SimdHooks] sub_5FED20 (Vector-Matrix Rotate) hook ACTIVE");
        }
    }
#else
    // Every other compiled-out section in this file says so. This one did not,
    // and it is the only one of them with a launcher switch: a player could turn
    // SimdMatrixTransform on, see it echoed in the settings block at the top of
    // their log, and get no further mention of it anywhere - because the code it
    // controls is removed by the preprocessor and there was nothing left to run
    // or to report. Silent is the worst of the three states a feature can be in.
    if (Config::g_settings.OptSimdMatrixTransform) {
        Log("[SimdHooks] SimdMatrixTransform is ON in your settings but the code is "
            "excluded from this build (TEST_DISABLE_MATRIX_TRANSFORM_SSE2) - the "
            "switch does nothing here");
    }
#endif

    return true;
}

void ShutdownSimdHooks(void) {
    MH_DisableHook((void*)0x005FEC70);
    MH_DisableHook((void*)0x00983D20);
    MH_DisableHook((void*)0x00982400);
    MH_DisableHook((void*)0x00982460);
#if !TEST_DISABLE_MATRIX_TRANSFORM_SSE2
    MH_DisableHook((void*)0x005FED20);
#endif
    Log("[SimdHooks] Stats: matMul=%ld, ... frustum=%ld (culled=%ld, %.1f%%), rayTri=%ld (hit=%ld, %.1f%%)",
        g_matMulCalls,
        g_frustumCalls, g_frustumCulled,
        g_frustumCalls ? 100.0 * g_frustumCulled / g_frustumCalls : 0.0,
        g_rayTriangleCalls, g_rayTriangleIntersects,
        g_rayTriangleCalls ? 100.0 * g_rayTriangleIntersects / g_rayTriangleCalls : 0.0);
}
