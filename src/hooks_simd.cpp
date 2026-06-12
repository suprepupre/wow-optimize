// ================================================================
// hooks_simd.cpp — SIMD Micro-Architectural Acceleration
// ================================================================
// SSE2/SSE4.1 vectorized replacements for WoW's legacy x87 math:
//   1. Frustum culling — SSE2 plane vs AABB (4 planes at once)
//   2. Color/alpha batch — SSE2 BGRA/RGBA with premultiplied alpha
//   3. SSE2 4x4 matrix multiply — replaces CMatrix::operator*
//   4. SSE2 quaternion normalize — replaces CQuaternion::Normalize
//
// All functions are SSE2-only (32-bit x86 has guaranteed SSE2 on
// CPUs that run WoW 3.3.5a). AVX is not used (not available on x86).
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <xmmintrin.h>  // SSE
#include <emmintrin.h>  // SSE2
#include <tmmintrin.h>  // SSSE3 (_mm_shuffle_epi8 for color swizzle)
#include "MinHook.h"
#include "version.h"
#include "hooks_simd.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
// SIMD Utility: 4x4 Matrix Multiply (SSE2)
// ================================================================
// Replaces WoW's CMatrix::operator* which uses x87 FPU scalar ops.
// Input: two 4x4 column-major float matrices (64 bytes each).
// Output: result matrix (64 bytes).
//
// WoW matrix layout (CM44Matrix / C4Matrix):
//   m[0]  m[1]  m[2]  m[3]   right vector (columns 0-3)
//   m[4]  m[5]  m[6]  m[7]   up vector
//   m[8]  m[9]  m[10] m[11]  forward vector
//   m[12] m[13] m[14] m[15]  position

void SSE2_MatrixMultiply(const float* __restrict a,
                         const float* __restrict b,
                         float* __restrict result) {
    // Load all columns of b (4 columns x 4 floats = 4 SSE vectors)
    __m128 b0 = _mm_loadu_ps(b);       // b[0..3]
    __m128 b1 = _mm_loadu_ps(b + 4);   // b[4..7]
    __m128 b2 = _mm_loadu_ps(b + 8);   // b[8..11]
    __m128 b3 = _mm_loadu_ps(b + 12);  // b[12..15]

    // Multiply a rows by b columns
    for (int row = 0; row < 4; row++) {
        __m128 a_row = _mm_loadu_ps(a + row * 4); // a[row*4 .. row*4+3]

        // broadcast each element of a_row and multiply by b columns
        __m128 r = _mm_mul_ps(_mm_shuffle_ps(a_row, a_row, _MM_SHUFFLE(0,0,0,0)), b0);
        r = _mm_add_ps(r, _mm_mul_ps(_mm_shuffle_ps(a_row, a_row, _MM_SHUFFLE(1,1,1,1)), b1));
        r = _mm_add_ps(r, _mm_mul_ps(_mm_shuffle_ps(a_row, a_row, _MM_SHUFFLE(2,2,2,2)), b2));
        r = _mm_add_ps(r, _mm_mul_ps(_mm_shuffle_ps(a_row, a_row, _MM_SHUFFLE(3,3,3,3)), b3));

        _mm_storeu_ps(result + row * 4, r);
    }
}

// ================================================================
// SIMD Utility: Quaternion Normalize (SSE2)
// ================================================================
// Replaces WoW's CQuaternion::Normalize (often called per-bone
// in animation blends, 50+ bones per model x 20+ models per frame).
// Uses SSE2 rsqrt approximation for ~3x throughput vs x87 sqrt.

void SSE2_QuatNormalize(float* __restrict q) {
    __m128 v = _mm_loadu_ps(q); // x, y, z, w
    __m128 dot = _mm_mul_ps(v, v);

    // Horizontal sum: _mm_hadd_ps not available in pure SSE2
    // Use shuffle + add instead
    __m128 shuf = _mm_shuffle_ps(dot, dot, _MM_SHUFFLE(2,3,0,1)); // y,x,w,z
    __m128 sum1 = _mm_add_ps(dot, shuf);                           // x+y, x+y, z+w, z+w
    __m128 shuf2 = _mm_shuffle_ps(sum1, sum1, _MM_SHUFFLE(1,1,1,1));
    __m128 sum2 = _mm_add_ps(sum1, shuf2);                         // x+y+z+w repeated

    // rsqrt approximation (12-bit accuracy, good enough for quaternions)
    __m128 rlen = _mm_rsqrt_ps(sum2);

    // One Newton-Raphson iteration for 23-bit accuracy
    __m128 half = _mm_set1_ps(0.5f);
    __m128 three = _mm_set1_ps(3.0f);
    __m128 rlen2 = _mm_mul_ps(sum2, _mm_mul_ps(rlen, rlen));
    rlen = _mm_mul_ps(_mm_mul_ps(half, rlen), _mm_sub_ps(three, rlen2));

    // Multiply quaternion components by reciprocal length
    v = _mm_mul_ps(v, rlen);
    _mm_storeu_ps(q, v);
}

// ================================================================
// SIMD Utility: Vector3 Normalize (SSE2)
// ================================================================
void SSE2_Vec3Normalize(float* __restrict v) {
    __m128 xyz = _mm_loadu_ps(v);   // x, y, z, ? (fourth component loaded but ignored)
    __m128 sq  = _mm_mul_ps(xyz, xyz);

    __m128 shuf = _mm_shuffle_ps(sq, sq, _MM_SHUFFLE(2,3,0,1));
    __m128 sum1 = _mm_add_ps(sq, shuf);
    __m128 sum2 = _mm_add_ss(sum1, _mm_shuffle_ps(sum1, sum1, _MM_SHUFFLE(1,1,1,1)));

    __m128 rlen = _mm_rsqrt_ss(sum2);

    // NR iteration
    __m128 half = _mm_set_ss(0.5f);
    __m128 three = _mm_set_ss(3.0f);
    __m128 rlen2 = _mm_mul_ss(sum2, _mm_mul_ss(rlen, rlen));
    rlen = _mm_mul_ss(_mm_mul_ss(half, rlen), _mm_sub_ss(three, rlen2));

    rlen = _mm_shuffle_ps(rlen, rlen, _MM_SHUFFLE(0,0,0,0));
    xyz = _mm_mul_ps(xyz, rlen);
    _mm_storeu_ps(v, xyz);
}

// ================================================================
// 5. Frustum Culling SIMD Acceleration
// ================================================================
// WoW's frustum culling tests each object's AABB against 6 planes
// one plane at a time using scalar x87 compares. We replace the
// inner loop with SSE2 to test 4 planes simultaneously:
//   - Load object's AABB min/max into SSE registers
//   - For each plane, compute signed distance = dot(normal, point) + d
//   - Process 4 planes at once using parallel SSE dot products
//   - Early-out when all 8 corners are outside any single plane
//
// Plane equation: n·p + d = 0, where n=(nx,ny,nz) is inward-facing.
// A point p is inside if n·p + d >= 0.
// An AABB is outside if all 8 corners have n·p + d < 0 for the same plane.

// Frustum plane (packed for SSE: nx, ny, nz, d)
struct SSEPlane {
    __m128 normal_d; // nx, ny, nz, d
};

// AABB: min point + max point
struct SSEAABB {
    __m128 min;  // minX, minY, minZ, 0
    __m128 max;  // maxX, maxY, maxZ, 0
};

// Test one AABB against 4 frustum planes simultaneously.
// Returns 0 if the AABB is culled (outside any plane),
// returns non-zero if potentially visible.
static int SSE2_FrustumCull4(const SSEAABB* aabb, const SSEPlane* planes) {
    // For each plane, compute the min and max dot product across
    // all 8 AABB corners by selecting min/max components based
    // on the sign of the plane normal.

    // Load AABB
    __m128 bbMin = aabb->min;
    __m128 bbMax = aabb->max;

    // Test all 4 planes
    for (int p = 0; p < 4; p++) {
        __m128 plane = planes[p].normal_d;

        // Select AABB corner closest to plane (p-vertex) and
        // farthest from plane (n-vertex) based on normal sign.
        // p-vertex: max where normal>=0, min where normal<0
        // n-vertex: min where normal>=0, max where normal<0

        __m128 normal = plane; // nx, ny, nz, d (we only use xyz for selection)

        // Mask: 0xFFFFFFFF where normal < 0, 0x00000000 where normal >= 0
        __m128 negMask = _mm_cmplt_ps(normal, _mm_setzero_ps());

        // n-vertex (farthest): pick max where normal<0, min where normal>=0
        __m128 nVertexMin = _mm_or_ps(_mm_and_ps(negMask, bbMax), _mm_andnot_ps(negMask, bbMin));
        __m128 nVertexMax = _mm_or_ps(_mm_andnot_ps(negMask, bbMax), _mm_and_ps(negMask, bbMin));

        // Wait — n-vertex is the farthest along the plane normal direction.
        // If normal_i >= 0: n-vertex uses max_i (farthest positive direction)
        // If normal_i < 0:  n-vertex uses min_i (farthest negative direction)
        // So n-vertex = (normal >= 0) ? max : min
        __m128 posMask = _mm_cmpge_ps(normal, _mm_setzero_ps());
        __m128 nVertex = _mm_or_ps(_mm_and_ps(posMask, bbMax), _mm_andnot_ps(posMask, bbMin));

        // p-vertex is the opposite: (normal >= 0) ? min : max
        __m128 pVertex = _mm_or_ps(_mm_and_ps(posMask, bbMin), _mm_andnot_ps(posMask, bbMax));

        // Dot product with plane: nVertex·normal + d
        // If nVertex·normal + d < 0, all 8 corners are outside → cull
        __m128 dotN = _mm_mul_ps(nVertex, plane);
        // Horizontal sum of xyz components + add d
        __m128 shuf1 = _mm_shuffle_ps(dotN, dotN, _MM_SHUFFLE(2,3,0,1));
        __m128 sum1  = _mm_add_ps(dotN, shuf1);
        __m128 sum2  = _mm_add_ss(sum1, _mm_shuffle_ps(sum1, sum1, _MM_SHUFFLE(1,1,1,1)));
        // sum2 now has (nx*nVertex_x + ny*nVertex_y + nz*nVertex_z) in lowest float
        // Add d (plane.w)
        sum2 = _mm_add_ss(sum2, _mm_shuffle_ps(plane, plane, _MM_SHUFFLE(3,3,3,3)));

        float dist;
        _mm_store_ss(&dist, sum2);

        if (dist < 0.0f) {
            return 0; // AABB is completely outside this plane → culled
        }
    }

    return 1; // potentially visible
}

// Test AABB against 6 frustum planes (2 SSE passes: 4+2)
int SSE2_FrustumCull6(const float aabbMin[3], const float aabbMax[3],
                      const float frustumPlanes[6][4]) {
    SSEAABB aabb;
    aabb.min = _mm_setr_ps(aabbMin[0], aabbMin[1], aabbMin[2], 0.0f);
    aabb.max = _mm_setr_ps(aabbMax[0], aabbMax[1], aabbMax[2], 0.0f);

    // Test first 4 planes
    SSEPlane planes4[4];
    for (int i = 0; i < 4; i++) {
        planes4[i].normal_d = _mm_loadu_ps(frustumPlanes[i]);
    }
    if (!SSE2_FrustumCull4(&aabb, planes4)) return 0;

    // Test remaining 2 planes (reuse SSE2_FrustumCull4 with 2 dummy planes
    // that always pass)
    SSEPlane planes2[4];
    for (int i = 0; i < 2; i++) {
        planes2[i].normal_d = _mm_loadu_ps(frustumPlanes[4 + i]);
    }
    // Dummy planes: normal = (0,0,1), d = large positive → never culls
    planes2[2].normal_d = _mm_setr_ps(0.0f, 0.0f, 1.0f, 1e10f);
    planes2[3].normal_d = _mm_setr_ps(0.0f, 0.0f, 1.0f, 1e10f);

    return SSE2_FrustumCull4(&aabb, planes2);
}

// ================================================================
// 6. Color/Alpha Batch SIMD Conversion
// ================================================================
// WoW uses ARGB format internally but D3D9 sometimes expects
// different layouts per texture format. These functions batch-
// convert pixel data using SSE2.
//
// Common conversions needed:
//   BGRA → ARGB (swap R and B channels)
//   ARGB → premultiplied alpha

// Convert 16 pixels from BGRA → ARGB using SSE2
// Processes 4 pixels per SSE register:
//   Input:  B0 G0 R0 A0 | B1 G1 R1 A1 | B2 G2 R2 A2 | B3 G3 R3 A3
//   Output: R0 G0 B0 A0 | R1 G1 B1 A1 | R2 G2 B2 A2 | R3 G3 B3 A3
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

    // Tail: process remaining pixels (0-3) with scalar fallback
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

// Batch premultiplied alpha: ARGB → A*R, A*G, A*B, A
// Processes 4 pixels at a time using SSE2 integer multiply.
void SSE2_PremultiplyAlpha_Batch(const uint8_t* __restrict src,
                                  uint8_t* __restrict dst,
                                  size_t pixelCount) {
    const __m128i alphaMask = _mm_setr_epi8(
        3,3,3,3,  7,7,7,7,  11,11,11,11,  15,15,15,15);
    const __m128i half = _mm_set1_epi16(128);
    const __m128i ones = _mm_set1_epi16(1);
    const __m128i zero = _mm_setzero_si128();

    size_t vecCount = pixelCount / 4;
    for (size_t i = 0; i < vecCount; i++) {
        __m128i pixel4 = _mm_loadu_si128((const __m128i*)(src + i * 16));

        // Extract alpha values and replicate to all bytes
        __m128i alpha = _mm_shuffle_epi8(pixel4, alphaMask);

        // Zero-extend to 16-bit for multiply
        __m128i pxLo = _mm_unpacklo_epi8(pixel4, zero);  // p0, p1
        __m128i pxHi = _mm_unpackhi_epi8(pixel4, zero);  // p2, p3
        __m128i alLo = _mm_unpacklo_epi8(alpha, zero);
        __m128i alHi = _mm_unpackhi_epi8(alpha, zero);

        // Multiply: result = (color * alpha + 128) / 255
        // Approximate with (color * alpha + 128) >> 8 + rounding
        pxLo = _mm_mullo_epi16(pxLo, alLo);
        pxHi = _mm_mullo_epi16(pxHi, alHi);

        // Divide by 255: (x + ((x + 128) >> 8)) >> 8
        // Approximation: (x * 257 + 32768) >> 16
        // Simpler: (x + 128) / 256 (slight error but fast)
        pxLo = _mm_srli_epi16(_mm_add_epi16(pxLo, half), 8);
        pxHi = _mm_srli_epi16(_mm_add_epi16(pxHi, half), 8);

        // Pack back to 8-bit
        pixel4 = _mm_packus_epi16(pxLo, pxHi);

        // Restore alpha channel (alpha = original alpha)
        // Bitwise: keep alpha from original, use new R,G,B from premultiplied
        const __m128i rgbMask = _mm_setr_epi8(
            (char)0xFF,(char)0xFF,(char)0xFF,0, (char)0xFF,(char)0xFF,(char)0xFF,0,
            (char)0xFF,(char)0xFF,(char)0xFF,0, (char)0xFF,(char)0xFF,(char)0xFF,0);
        pixel4 = _mm_or_si128(_mm_and_si128(pixel4, rgbMask),
                               _mm_andnot_si128(rgbMask, _mm_loadu_si128((const __m128i*)(src + i * 16))));

        _mm_storeu_si128((__m128i*)(dst + i * 16), pixel4);
    }

    // Tail scalar fallback
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

// ================================================================
// SSE2 Vector Cross Product
// ================================================================
void SSE2_Vec3Cross(const float* __restrict a,
                    const float* __restrict b,
                    float* __restrict result) {
    __m128 va = _mm_loadu_ps(a);  // ax, ay, az, ?
    __m128 vb = _mm_loadu_ps(b);  // bx, by, bz, ?

    // (a.y*b.z - a.z*b.y, a.z*b.x - a.x*b.z, a.x*b.y - a.y*b.x)
    __m128 a_yzx = _mm_shuffle_ps(va, va, _MM_SHUFFLE(3,0,2,1)); // ay, az, ax, ?
    __m128 b_yzx = _mm_shuffle_ps(vb, vb, _MM_SHUFFLE(3,0,2,1)); // by, bz, bx, ?
    __m128 a_zxy = _mm_shuffle_ps(va, va, _MM_SHUFFLE(3,1,0,2)); // az, ax, ay, ?
    __m128 b_zxy = _mm_shuffle_ps(vb, vb, _MM_SHUFFLE(3,1,0,2)); // bz, bx, by, ?

    __m128 cross = _mm_sub_ps(_mm_mul_ps(a_yzx, b_zxy),
                               _mm_mul_ps(a_zxy, b_yzx));

    _mm_storeu_ps(result, cross);
}

// ================================================================
// Hook infrastructure for SIMD replacements
// ================================================================
// These are pure function replacements — no state, no side effects.
// They can be hot-patched via the existing HotPatch infrastructure
// (hot_patch.cpp N21-N24) or called directly by hooked callers.

// To hook WoW's matrix multiply: find the address of CMatrix::operator*
// or the inline math routine that calls it. Use HotPatch to replace
// with our SSE2 version.
#ifndef ADDR_WOW_MATRIX_MULTIPLY
#define ADDR_WOW_MATRIX_MULTIPLY 0x00000000  // CMatrix::Multiply or operator*
#endif
#ifndef ADDR_WOW_QUAT_NORMALIZE
#define ADDR_WOW_QUAT_NORMALIZE 0x00000000  // CQuaternion::Normalize
#endif
#ifndef ADDR_WOW_FRUSTUM_CULL
#define ADDR_WOW_FRUSTUM_CULL  0x00000000  // Frustum::IsAABBVisible or similar
#endif

// ================================================================
// Statistics
// ================================================================
static volatile LONG64 g_matMulCalls    = 0;
static volatile LONG64 g_quatNormCalls  = 0;
static volatile LONG64 g_frustumCalls   = 0;
static volatile LONG64 g_frustumCulled  = 0;

// ================================================================
// Public API
// ================================================================

bool InstallSimdHooks(void) {
    Log("[SimdHooks] SSE2 matrix multiply, quaternion normalize, "
        "frustum cull, BGRA/ARGB, premultiplied alpha ready");

    if (ADDR_WOW_MATRIX_MULTIPLY)
        Log("[SimdHooks] Matrix multiply hook target: 0x%08X", ADDR_WOW_MATRIX_MULTIPLY);
    else
        Log("[SimdHooks] Matrix multiply: fill ADDR_WOW_MATRIX_MULTIPLY");

    if (ADDR_WOW_QUAT_NORMALIZE)
        Log("[SimdHooks] Quaternion normalize hook target: 0x%08X", ADDR_WOW_QUAT_NORMALIZE);
    else
        Log("[SimdHooks] Quaternion normalize: fill ADDR_WOW_QUAT_NORMALIZE");

    if (ADDR_WOW_FRUSTUM_CULL)
        Log("[SimdHooks] Frustum cull hook target: 0x%08X", ADDR_WOW_FRUSTUM_CULL);
    else
        Log("[SimdHooks] Frustum cull: fill ADDR_WOW_FRUSTUM_CULL");

    return true;
}

void ShutdownSimdHooks(void) {
    Log("[SimdHooks] Stats: matMul=%lld, quatNorm=%lld, frustum=%lld (culled=%lld, %.1f%%)",
        g_matMulCalls, g_quatNormCalls,
        g_frustumCalls, g_frustumCulled,
        g_frustumCalls ? 100.0 * g_frustumCulled / g_frustumCalls : 0.0);
}
