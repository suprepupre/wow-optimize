// ============================================================================
// Module: mat44_affine_ops_fast.cpp
//
// Hardware-accelerated 4x4 matrix affine transformations, rotations, scaling,
// translation, and terrain texture projections for WoW 3.3.5a:
//   - sub_4C2FC0: C44Matrix::AffineInverse       (34 call sites)
//   - sub_4C3380: C44Matrix::RotateAroundZ       (39 call sites)
//   - sub_4C3300: C44Matrix::RotateAroundX       (8 call sites)
//   - sub_4C3340: C44Matrix::RotateAroundY       (9 call sites)
//   - sub_4C3290: C44Matrix::FromRotationZ       (13 call sites)
//   - sub_4C2120: C44Matrix::ScaleMatrixByScalar (4 call sites)
//   - sub_4C1C40: C44Matrix::FromQuaternion33    (3 call sites)
//   - sub_4C1B30: C44Matrix::TranslateByVector   (66 call sites)
//   - sub_4C1BF0: C44Matrix::Scale3x3            (36 call sites)
//   - sub_7D06B0: CMapRenderChunk::ComputeTexMatrices (terrain chunk render passes)
//
// In stock 3.3.5a:
//   - sub_4C2FC0 inverts a 4x4 affine matrix by copying it to a 3x3 matrix via
//     sub_4C51B0, computing 15 serial x87 float operations and stack spills,
//     and performing unaligned writes. Called 34 times per frame across camera
//     inversion, model-to-world inversion, attachment frames, and sound orientation.
//   - sub_4C3380/4C3300/4C3340 perform in-place single-axis rotations by
//     allocating a temporary 64-byte matrix on the stack via sub_4C3290,
//     calling sub_4C1F00 (full 64-byte matrix multiplication), and calling
//     sub_407F80 to copy it back. Called 56+ times per frame across unit facings,
//     projectiles, camera updates, and scene orientations.
//   - sub_4C3290 constructs a 4x4 Z-rotation matrix using serial scalar writes.
//   - sub_4C2120 scales a 4x4 matrix using 16 serial x87 multiplications.
//   - sub_4C1C40 converts a quaternion to rotation matrix elements using serial
//     x87 instructions with memory roundtrips.
//   - sub_4C1B30 translates a 4x4 matrix by a 3D vector using 9 x87 multiplies,
//     6 x87 adds, and 3 memory roundtrips.
//   - sub_4C1BF0 scales upper 3x3 matrix elements using 9 scalar x87 multiplies.
//   - sub_7D06B0 computes diffuse and alpha texture projection matrices for every
//     terrain chunk on every frame via 4 function calls, stack frames, and 16
//     register swaps.
//
// This replacement:
//   - Inverts affine matrices directly in registers without intermediate copying.
//   - Evaluates axis rotations in place directly on affected rows without stack
//     temporaries or full 64-byte matrix multiplications.
//   - Vectorizes matrix scalar scaling with 128-bit SSE2 instructions.
//   - Inlines translation dot products and 3x3 scaling in exact IEEE double
//     precision matching client x87 evaluation order.
//   - Evaluates terrain chunk texture matrices in a single direct register pass.
//   - Employs dual-run verification with fail-safe retirement guards.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <algorithm>

#include "mat44_affine_ops_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);

namespace Mat44AffineOpsFast {

namespace {

constexpr uintptr_t kTarget_AffineInverse        = 0x004C2FC0;
constexpr uintptr_t kTarget_RotateAroundZ        = 0x004C3380;
constexpr uintptr_t kTarget_RotateAroundX        = 0x004C3300;
constexpr uintptr_t kTarget_RotateAroundY        = 0x004C3340;
constexpr uintptr_t kTarget_FromRotationZ        = 0x004C3290;
constexpr uintptr_t kTarget_ScaleMatrix          = 0x004C2120;
constexpr uintptr_t kTarget_FromQuaternion33     = 0x004C1C40;
constexpr uintptr_t kTarget_TranslateByVector    = 0x004C1B30;
constexpr uintptr_t kTarget_Scale3x3            = 0x004C1BF0;
constexpr uintptr_t kTarget_ComputeTexMatrices  = 0x007D06B0;

// Verification settings
constexpr unsigned long kVerifyFirst = 20000;
constexpr unsigned long kResampleMask = 4095;
constexpr float kVerifyTolerance = 0.0002f;

// Expected prologues
const unsigned char kExp_AffineInverse[8]       = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x48, 0x56, 0x8B };
const unsigned char kExp_RotateAroundZ[8]       = { 0x55, 0x8B, 0xEC, 0xD9, 0x45, 0x08, 0x81, 0xEC };
const unsigned char kExp_RotateAroundX[8]       = { 0x55, 0x8B, 0xEC, 0xD9, 0x45, 0x08, 0x81, 0xEC };
const unsigned char kExp_RotateAroundY[8]       = { 0x55, 0x8B, 0xEC, 0xD9, 0x45, 0x08, 0x81, 0xEC };
const unsigned char kExp_FromRotationZ[8]       = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x8D, 0x45 };
const unsigned char kExp_ScaleMatrix[8]         = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x0C, 0x8B, 0x45 };
const unsigned char kExp_FromQuaternion33[8]    = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x8B, 0x45 };
const unsigned char kExp_TranslateByVector[8]   = { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0xD9, 0x41 };
const unsigned char kExp_Scale3x3[8]            = { 0x55, 0x8B, 0xEC, 0xD9, 0x01, 0xD9, 0x45, 0x08 };
const unsigned char kExp_ComputeTexMatrices[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0xD9, 0x45 };

// Function signatures
typedef float* (__thiscall* AffineInverse_fn)(const float* this_ptr, float* out);
typedef float* (__thiscall* RotateAroundAxis_fn)(float* this_ptr, float angle);
typedef float* (__cdecl*    FromRotationZ_fn)(float* out, float angle);
typedef float* (__cdecl*    ScaleMatrix_fn)(float* out, const float* in, float scale);
typedef float* (__cdecl*    FromQuaternion33_fn)(const float* q, float* out);
typedef float* (__thiscall* TranslateByVector_fn)(float* this_ptr, const float* vec3);
typedef void   (__thiscall* Scale3x3_fn)(float* this_ptr, float scale);
typedef float* (__cdecl*    ComputeTexMatrices_fn)(float* m1, float* m2, const float* trans, float scale);

AffineInverse_fn      orig_AffineInverse      = nullptr;
RotateAroundAxis_fn   orig_RotateAroundZ      = nullptr;
RotateAroundAxis_fn   orig_RotateAroundX      = nullptr;
RotateAroundAxis_fn   orig_RotateAroundY      = nullptr;
FromRotationZ_fn      orig_FromRotationZ      = nullptr;
ScaleMatrix_fn        orig_ScaleMatrix        = nullptr;
FromQuaternion33_fn   orig_FromQuaternion33   = nullptr;
TranslateByVector_fn  orig_TranslateByVector  = nullptr;
Scale3x3_fn           orig_Scale3x3           = nullptr;
ComputeTexMatrices_fn orig_ComputeTexMatrices = nullptr;

bool g_installed = false;

bool g_dead_affine_inverse    = false;
bool g_dead_rotate_z          = false;
bool g_dead_rotate_x          = false;
bool g_dead_rotate_y          = false;
bool g_dead_from_rot_z        = false;
bool g_dead_scale_matrix      = false;
bool g_dead_from_quat33       = false;
bool g_dead_translate_vec     = false;
bool g_dead_scale_3x3         = false;
bool g_dead_compute_tex       = false;

unsigned long long g_calls_affine_inverse    = 0;
unsigned long long g_calls_rotate_z          = 0;
unsigned long long g_calls_rotate_x          = 0;
unsigned long long g_calls_rotate_y          = 0;
unsigned long long g_calls_from_rot_z        = 0;
unsigned long long g_calls_scale_matrix      = 0;
unsigned long long g_calls_from_quat33       = 0;
unsigned long long g_calls_translate_vec     = 0;
unsigned long long g_calls_scale_3x3         = 0;
unsigned long long g_calls_compute_tex       = 0;

unsigned long long g_verified_affine_inverse    = 0;
unsigned long long g_verified_rotate_z          = 0;
unsigned long long g_verified_rotate_x          = 0;
unsigned long long g_verified_rotate_y          = 0;
unsigned long long g_verified_from_rot_z        = 0;
unsigned long long g_verified_scale_matrix      = 0;
unsigned long long g_verified_from_quat33       = 0;
unsigned long long g_verified_translate_vec     = 0;
unsigned long long g_verified_scale_3x3         = 0;
unsigned long long g_verified_compute_tex       = 0;

unsigned long long g_mismatches_affine_inverse    = 0;
unsigned long long g_mismatches_rotate_z          = 0;
unsigned long long g_mismatches_rotate_x          = 0;
unsigned long long g_mismatches_rotate_y          = 0;
unsigned long long g_mismatches_from_rot_z        = 0;
unsigned long long g_mismatches_scale_matrix      = 0;
unsigned long long g_mismatches_from_quat33       = 0;
unsigned long long g_mismatches_translate_vec     = 0;
unsigned long long g_mismatches_scale_3x3         = 0;
unsigned long long g_mismatches_compute_tex       = 0;

// ============================================================================
// Fast Mathematical Implementations
// ============================================================================

__forceinline float* Fast_AffineInverse(const float* this_ptr, float* out) {
    float a0 = this_ptr[0],  a1 = this_ptr[1],  a2 = this_ptr[2];
    float b0 = this_ptr[4],  b1 = this_ptr[5],  b2 = this_ptr[6];
    float c0 = this_ptr[8],  c1 = this_ptr[9],  c2 = this_ptr[10];

    out[0]  = a0;   out[1]  = b0;   out[2]  = c0;   out[3]  = 0.0f;
    out[4]  = a1;   out[5]  = b1;   out[6]  = c1;   out[7]  = 0.0f;
    out[8]  = a2;   out[9]  = b2;   out[10] = c2;   out[11] = 0.0f;

    float neg_d0 = -this_ptr[12];
    float neg_d1 = -this_ptr[13];
    float neg_d2 = -this_ptr[14];

    out[12] = a0 * neg_d0 + a1 * neg_d1 + a2 * neg_d2;
    out[13] = b0 * neg_d0 + b1 * neg_d1 + b2 * neg_d2;
    out[14] = c0 * neg_d0 + c1 * neg_d1 + c2 * neg_d2;
    out[15] = 1.0f;

    return out;
}

__forceinline float* Fast_RotateAroundZ(float* this_ptr, float angle) {
    float c = cosf(angle);
    float s = sinf(angle);

    for (int i = 0; i < 4; i++) {
        float r0 = this_ptr[i];
        float r1 = this_ptr[4 + i];
        this_ptr[i]     = c * r0 + s * r1;
        this_ptr[4 + i] = -s * r0 + c * r1;
    }
    return this_ptr;
}

__forceinline float* Fast_RotateAroundX(float* this_ptr, float angle) {
    float c = cosf(angle);
    float s = sinf(angle);

    for (int i = 0; i < 4; i++) {
        float r1 = this_ptr[4 + i];
        float r2 = this_ptr[8 + i];
        this_ptr[4 + i] = c * r1 + s * r2;
        this_ptr[8 + i] = -s * r1 + c * r2;
    }
    return this_ptr;
}

__forceinline float* Fast_RotateAroundY(float* this_ptr, float angle) {
    float c = cosf(angle);
    float s = sinf(angle);

    for (int i = 0; i < 4; i++) {
        float r0 = this_ptr[i];
        float r2 = this_ptr[8 + i];
        this_ptr[i]     = c * r0 - s * r2;
        this_ptr[8 + i] = s * r0 + c * r2;
    }
    return this_ptr;
}

__forceinline float* Fast_FromRotationZ(float* out, float angle) {
    float c = cosf(angle);
    float s = sinf(angle);

    out[0]  = c;     out[1]  = s;    out[2]  = 0.0f; out[3]  = 0.0f;
    out[4]  = -s;    out[5]  = c;    out[6]  = 0.0f; out[7]  = 0.0f;
    out[8]  = 0.0f;  out[9]  = 0.0f; out[10] = 1.0f; out[11] = 0.0f;
    out[12] = 0.0f;  out[13] = 0.0f; out[14] = 0.0f; out[15] = 1.0f;

    return out;
}

__forceinline float* Fast_ScaleMatrix(float* out, const float* in, float scale) {
    __m128 s = _mm_set1_ps(scale);
    _mm_storeu_ps(out + 0,  _mm_mul_ps(_mm_loadu_ps(in + 0),  s));
    _mm_storeu_ps(out + 4,  _mm_mul_ps(_mm_loadu_ps(in + 4),  s));
    _mm_storeu_ps(out + 8,  _mm_mul_ps(_mm_loadu_ps(in + 8),  s));
    _mm_storeu_ps(out + 12, _mm_mul_ps(_mm_loadu_ps(in + 12), s));
    return out;
}

__forceinline float* Fast_FromQuaternion33(const float* q, float* out) {
    float x2 = q[0] + q[0];
    float y2 = q[1] + q[1];
    float z2 = q[2] + q[2];

    float xx = q[0] * x2;
    float xy = q[0] * y2;
    float xz = q[0] * z2;

    float yy = q[1] * y2;
    float yz = q[1] * z2;
    float zz = q[2] * z2;

    float wx = q[3] * x2;
    float wy = q[3] * y2;
    float wz = q[3] * z2;

    out[0]  = 1.0f - (yy + zz);
    out[1]  = xy + wz;
    out[2]  = xz - wy;

    out[4]  = xy - wz;
    out[5]  = 1.0f - (xx + zz);
    out[6]  = yz + wx;

    out[8]  = xz + wy;
    out[9]  = yz - wx;
    out[10] = 1.0f - (xx + yy);

    return out;
}

__forceinline float* Fast_TranslateByVector(float* this_ptr, const float* v) {
    const double px = static_cast<double>(v[0]);
    const double py = static_cast<double>(v[1]);
    const double pz = static_cast<double>(v[2]);

    this_ptr[12] = static_cast<float>(((static_cast<double>(this_ptr[4]) * py + static_cast<double>(this_ptr[8]) * pz) + px * static_cast<double>(this_ptr[0])) + static_cast<double>(this_ptr[12]));
    this_ptr[13] = static_cast<float>(((static_cast<double>(this_ptr[5]) * py + static_cast<double>(this_ptr[9]) * pz) + px * static_cast<double>(this_ptr[1])) + static_cast<double>(this_ptr[13]));
    this_ptr[14] = static_cast<float>(((static_cast<double>(this_ptr[6]) * py + static_cast<double>(this_ptr[10]) * pz) + px * static_cast<double>(this_ptr[2])) + static_cast<double>(this_ptr[14]));
    return const_cast<float*>(v);
}

__forceinline void Fast_Scale3x3(float* this_ptr, float scale) {
    const double s = static_cast<double>(scale);
    this_ptr[0]  = static_cast<float>(static_cast<double>(this_ptr[0])  * s);
    this_ptr[1]  = static_cast<float>(static_cast<double>(this_ptr[1])  * s);
    this_ptr[2]  = static_cast<float>(static_cast<double>(this_ptr[2])  * s);
    this_ptr[4]  = static_cast<float>(static_cast<double>(this_ptr[4])  * s);
    this_ptr[5]  = static_cast<float>(static_cast<double>(this_ptr[5])  * s);
    this_ptr[6]  = static_cast<float>(static_cast<double>(this_ptr[6])  * s);
    this_ptr[8]  = static_cast<float>(static_cast<double>(this_ptr[8])  * s);
    this_ptr[9]  = static_cast<float>(static_cast<double>(this_ptr[9])  * s);
    this_ptr[10] = static_cast<float>(static_cast<double>(this_ptr[10]) * s);
}

__forceinline void Fast_ProcessTexMatrix(float* m, const float* trans, float scale) {
    const double s = static_cast<double>(scale);

    const float r0_0 = static_cast<float>(static_cast<double>(m[4]) * s);
    const float r0_1 = static_cast<float>(static_cast<double>(m[5]) * s);
    const float r0_2 = static_cast<float>(static_cast<double>(m[6]) * s);
    const float r0_3 = m[7];

    const float r1_0 = static_cast<float>(static_cast<double>(m[0]) * s);
    const float r1_1 = static_cast<float>(static_cast<double>(m[1]) * s);
    const float r1_2 = static_cast<float>(static_cast<double>(m[2]) * s);
    const float r1_3 = m[3];

    const float r2_0 = static_cast<float>(static_cast<double>(m[8]) * s);
    const float r2_1 = static_cast<float>(static_cast<double>(m[9]) * s);
    const float r2_2 = static_cast<float>(static_cast<double>(m[10]) * s);

    const double t0 = static_cast<double>(trans[0]);
    const double t1 = static_cast<double>(trans[1]);
    const double t2 = static_cast<double>(trans[2]);

    const float m12 = static_cast<float>(((static_cast<double>(r1_0) * t1 + static_cast<double>(r2_0) * t2) + t0 * static_cast<double>(r0_0)) + static_cast<double>(m[12]));
    const float m13 = static_cast<float>(((static_cast<double>(r1_1) * t1 + static_cast<double>(r2_1) * t2) + t0 * static_cast<double>(r0_1)) + static_cast<double>(m[13]));
    const float m14 = static_cast<float>(((static_cast<double>(r1_2) * t1 + static_cast<double>(r2_2) * t2) + t0 * static_cast<double>(r0_2)) + static_cast<double>(m[14]));

    m[0] = r0_0;  m[1] = r0_1;  m[2] = r0_2;  m[3] = r0_3;
    m[4] = r1_0;  m[5] = r1_1;  m[6] = r1_2;  m[7] = r1_3;
    m[8] = r2_0;  m[9] = r2_1;  m[10] = r2_2;
    m[12] = m12;  m[13] = m13;  m[14] = m14;
}

__forceinline float* Fast_ComputeTexMatrices(float* m1, float* m2, const float* trans, float scale) {
    Fast_ProcessTexMatrix(m1, trans, scale);
    Fast_ProcessTexMatrix(m2, trans, scale * 0.125f);
    return const_cast<float*>(trans);
}

// ============================================================================
// Hook Functions with Dual-Run Verification
// ============================================================================

float* __fastcall Hook_AffineInverse(const float* this_ptr, void* /*edx*/, float* out) {
    g_calls_affine_inverse++;

    if (g_dead_affine_inverse) {
        return orig_AffineInverse(this_ptr, out);
    }

    const unsigned long callId = static_cast<unsigned long>(g_calls_affine_inverse);
    const bool doVerify = (callId <= kVerifyFirst) || ((callId & kResampleMask) == 0);

    if (doVerify) {
        float expected[16];
        orig_AffineInverse(this_ptr, expected);

        Fast_AffineInverse(this_ptr, out);

        bool match = true;
        for (int i = 0; i < 16; i++) {
            if (std::fabs(out[i] - expected[i]) > kVerifyTolerance) {
                match = false;
                break;
            }
        }

        if (match) {
            g_verified_affine_inverse++;
        } else {
            g_mismatches_affine_inverse++;
            g_dead_affine_inverse = true;
            Log("[Mat44AffineOpsFast] RETIRED AffineInverse on mismatch");
            std::memcpy(out, expected, sizeof(expected));
            return out;
        }
        return out;
    }

    return Fast_AffineInverse(this_ptr, out);
}

float* __fastcall Hook_RotateAroundZ(float* this_ptr, void* /*edx*/, float angle) {
    g_calls_rotate_z++;

    if (g_dead_rotate_z) {
        return orig_RotateAroundZ(this_ptr, angle);
    }

    const unsigned long callId = static_cast<unsigned long>(g_calls_rotate_z);
    const bool doVerify = (callId <= kVerifyFirst) || ((callId & kResampleMask) == 0);

    if (doVerify) {
        float expected[16];
        std::memcpy(expected, this_ptr, sizeof(expected));
        orig_RotateAroundZ(expected, angle);

        Fast_RotateAroundZ(this_ptr, angle);

        bool match = true;
        for (int i = 0; i < 16; i++) {
            if (std::fabs(this_ptr[i] - expected[i]) > kVerifyTolerance) {
                match = false;
                break;
            }
        }

        if (match) {
            g_verified_rotate_z++;
        } else {
            g_mismatches_rotate_z++;
            g_dead_rotate_z = true;
            Log("[Mat44AffineOpsFast] RETIRED RotateAroundZ on mismatch");
            std::memcpy(this_ptr, expected, sizeof(expected));
            return this_ptr;
        }
        return this_ptr;
    }

    return Fast_RotateAroundZ(this_ptr, angle);
}

float* __fastcall Hook_RotateAroundX(float* this_ptr, void* /*edx*/, float angle) {
    g_calls_rotate_x++;

    if (g_dead_rotate_x) {
        return orig_RotateAroundX(this_ptr, angle);
    }

    const unsigned long callId = static_cast<unsigned long>(g_calls_rotate_x);
    const bool doVerify = (callId <= kVerifyFirst) || ((callId & kResampleMask) == 0);

    if (doVerify) {
        float expected[16];
        std::memcpy(expected, this_ptr, sizeof(expected));
        orig_RotateAroundX(expected, angle);

        Fast_RotateAroundX(this_ptr, angle);

        bool match = true;
        for (int i = 0; i < 16; i++) {
            if (std::fabs(this_ptr[i] - expected[i]) > kVerifyTolerance) {
                match = false;
                break;
            }
        }

        if (match) {
            g_verified_rotate_x++;
        } else {
            g_mismatches_rotate_x++;
            g_dead_rotate_x = true;
            Log("[Mat44AffineOpsFast] RETIRED RotateAroundX on mismatch");
            std::memcpy(this_ptr, expected, sizeof(expected));
            return this_ptr;
        }
        return this_ptr;
    }

    return Fast_RotateAroundX(this_ptr, angle);
}

float* __fastcall Hook_RotateAroundY(float* this_ptr, void* /*edx*/, float angle) {
    g_calls_rotate_y++;

    if (g_dead_rotate_y) {
        return orig_RotateAroundY(this_ptr, angle);
    }

    const unsigned long callId = static_cast<unsigned long>(g_calls_rotate_y);
    const bool doVerify = (callId <= kVerifyFirst) || ((callId & kResampleMask) == 0);

    if (doVerify) {
        float expected[16];
        std::memcpy(expected, this_ptr, sizeof(expected));
        orig_RotateAroundY(expected, angle);

        Fast_RotateAroundY(this_ptr, angle);

        bool match = true;
        for (int i = 0; i < 16; i++) {
            if (std::fabs(this_ptr[i] - expected[i]) > kVerifyTolerance) {
                match = false;
                break;
            }
        }

        if (match) {
            g_verified_rotate_y++;
        } else {
            g_mismatches_rotate_y++;
            g_dead_rotate_y = true;
            Log("[Mat44AffineOpsFast] RETIRED RotateAroundY on mismatch");
            std::memcpy(this_ptr, expected, sizeof(expected));
            return this_ptr;
        }
        return this_ptr;
    }

    return Fast_RotateAroundY(this_ptr, angle);
}

float* __cdecl Hook_FromRotationZ(float* out, float angle) {
    g_calls_from_rot_z++;

    if (g_dead_from_rot_z) {
        return orig_FromRotationZ(out, angle);
    }

    const unsigned long callId = static_cast<unsigned long>(g_calls_from_rot_z);
    const bool doVerify = (callId <= kVerifyFirst) || ((callId & kResampleMask) == 0);

    if (doVerify) {
        float expected[16];
        orig_FromRotationZ(expected, angle);

        Fast_FromRotationZ(out, angle);

        bool match = true;
        for (int i = 0; i < 16; i++) {
            if (std::fabs(out[i] - expected[i]) > kVerifyTolerance) {
                match = false;
                break;
            }
        }

        if (match) {
            g_verified_from_rot_z++;
        } else {
            g_mismatches_from_rot_z++;
            g_dead_from_rot_z = true;
            Log("[Mat44AffineOpsFast] RETIRED FromRotationZ on mismatch");
            std::memcpy(out, expected, sizeof(expected));
            return out;
        }
        return out;
    }

    return Fast_FromRotationZ(out, angle);
}

float* __cdecl Hook_ScaleMatrix(float* out, const float* in, float scale) {
    g_calls_scale_matrix++;

    if (g_dead_scale_matrix) {
        return orig_ScaleMatrix(out, in, scale);
    }

    const unsigned long callId = static_cast<unsigned long>(g_calls_scale_matrix);
    const bool doVerify = (callId <= kVerifyFirst) || ((callId & kResampleMask) == 0);

    if (doVerify) {
        float expected[16];
        orig_ScaleMatrix(expected, in, scale);

        Fast_ScaleMatrix(out, in, scale);

        bool match = true;
        for (int i = 0; i < 16; i++) {
            if (std::fabs(out[i] - expected[i]) > kVerifyTolerance) {
                match = false;
                break;
            }
        }

        if (match) {
            g_verified_scale_matrix++;
        } else {
            g_mismatches_scale_matrix++;
            g_dead_scale_matrix = true;
            Log("[Mat44AffineOpsFast] RETIRED ScaleMatrix on mismatch");
            std::memcpy(out, expected, sizeof(expected));
            return out;
        }
        return out;
    }

    return Fast_ScaleMatrix(out, in, scale);
}

float* __cdecl Hook_FromQuaternion33(const float* q, float* out) {
    g_calls_from_quat33++;

    if (g_dead_from_quat33) {
        return orig_FromQuaternion33(q, out);
    }

    const unsigned long callId = static_cast<unsigned long>(g_calls_from_quat33);
    const bool doVerify = (callId <= kVerifyFirst) || ((callId & kResampleMask) == 0);

    if (doVerify) {
        float expected[16];
        std::memcpy(expected, out, sizeof(expected));
        orig_FromQuaternion33(q, expected);

        Fast_FromQuaternion33(q, out);

        bool match = true;
        const int rotIndices[9] = { 0, 1, 2, 4, 5, 6, 8, 9, 10 };
        for (int idx : rotIndices) {
            if (std::fabs(out[idx] - expected[idx]) > kVerifyTolerance) {
                match = false;
                break;
            }
        }

        if (match) {
            g_verified_from_quat33++;
        } else {
            g_mismatches_from_quat33++;
            g_dead_from_quat33 = true;
            Log("[Mat44AffineOpsFast] RETIRED FromQuaternion33 on mismatch");
            std::memcpy(out, expected, sizeof(expected));
            return out;
        }
        return out;
    }

    return Fast_FromQuaternion33(q, out);
}

float* __fastcall Hook_TranslateByVector(float* this_ptr, void* /*edx*/, const float* vec3) {
    g_calls_translate_vec++;

    if (g_dead_translate_vec) {
        return orig_TranslateByVector(this_ptr, vec3);
    }

    const unsigned long callId = static_cast<unsigned long>(g_calls_translate_vec);
    const bool doVerify = (callId <= kVerifyFirst) || ((callId & kResampleMask) == 0);

    if (doVerify) {
        float expected[16];
        std::memcpy(expected, this_ptr, sizeof(expected));
        orig_TranslateByVector(expected, vec3);

        Fast_TranslateByVector(this_ptr, vec3);

        bool match = (std::memcmp(&this_ptr[12], &expected[12], 3 * sizeof(float)) == 0);
        if (match) {
            g_verified_translate_vec++;
        } else {
            g_mismatches_translate_vec++;
            g_dead_translate_vec = true;
            Log("[Mat44AffineOpsFast] RETIRED TranslateByVector on mismatch");
            std::memcpy(&this_ptr[12], &expected[12], 3 * sizeof(float));
            return const_cast<float*>(vec3);
        }
        return const_cast<float*>(vec3);
    }

    return Fast_TranslateByVector(this_ptr, vec3);
}

void __fastcall Hook_Scale3x3(float* this_ptr, void* /*edx*/, float scale) {
    g_calls_scale_3x3++;

    if (g_dead_scale_3x3) {
        orig_Scale3x3(this_ptr, scale);
        return;
    }

    const unsigned long callId = static_cast<unsigned long>(g_calls_scale_3x3);
    const bool doVerify = (callId <= kVerifyFirst) || ((callId & kResampleMask) == 0);

    if (doVerify) {
        float expected[16];
        std::memcpy(expected, this_ptr, sizeof(expected));
        orig_Scale3x3(expected, scale);

        Fast_Scale3x3(this_ptr, scale);

        bool match = true;
        const int rotIndices[9] = { 0, 1, 2, 4, 5, 6, 8, 9, 10 };
        for (int idx : rotIndices) {
            if (this_ptr[idx] != expected[idx]) {
                match = false;
                break;
            }
        }

        if (match) {
            g_verified_scale_3x3++;
        } else {
            g_mismatches_scale_3x3++;
            g_dead_scale_3x3 = true;
            Log("[Mat44AffineOpsFast] RETIRED Scale3x3 on mismatch");
            std::memcpy(this_ptr, expected, sizeof(expected));
            return;
        }
        return;
    }

    Fast_Scale3x3(this_ptr, scale);
}

float* __cdecl Hook_ComputeTexMatrices(float* m1, float* m2, const float* trans, float scale) {
    g_calls_compute_tex++;

    if (g_dead_compute_tex) {
        return orig_ComputeTexMatrices(m1, m2, trans, scale);
    }

    const unsigned long callId = static_cast<unsigned long>(g_calls_compute_tex);
    const bool doVerify = (callId <= kVerifyFirst) || ((callId & kResampleMask) == 0);

    if (doVerify) {
        float exp1[16];
        float exp2[16];
        std::memcpy(exp1, m1, sizeof(exp1));
        std::memcpy(exp2, m2, sizeof(exp2));
        orig_ComputeTexMatrices(exp1, exp2, trans, scale);

        Fast_ComputeTexMatrices(m1, m2, trans, scale);

        bool match = (std::memcmp(m1, exp1, sizeof(exp1)) == 0) &&
                     (std::memcmp(m2, exp2, sizeof(exp2)) == 0);

        if (match) {
            g_verified_compute_tex++;
        } else {
            g_mismatches_compute_tex++;
            g_dead_compute_tex = true;
            Log("[Mat44AffineOpsFast] RETIRED ComputeTexMatrices on mismatch");
            std::memcpy(m1, exp1, sizeof(exp1));
            std::memcpy(m2, exp2, sizeof(exp2));
            return const_cast<float*>(trans);
        }
        return const_cast<float*>(trans);
    }

    return Fast_ComputeTexMatrices(m1, m2, trans, scale);
}

} // anonymous namespace

// ============================================================================
// Public Interface
// ============================================================================

void Init() {
    if (g_installed) return;

    if (!Config::g_settings.OptMat44AffineOpsFast) {
        return;
    }

    // Verify prologues
    if (std::memcmp(reinterpret_cast<const void*>(kTarget_AffineInverse), kExp_AffineInverse, sizeof(kExp_AffineInverse)) != 0) {
        Log("[Mat44AffineOpsFast] Prologue mismatch at AffineInverse (0x%08X)", kTarget_AffineInverse);
        return;
    }
    if (std::memcmp(reinterpret_cast<const void*>(kTarget_RotateAroundZ), kExp_RotateAroundZ, sizeof(kExp_RotateAroundZ)) != 0) {
        Log("[Mat44AffineOpsFast] Prologue mismatch at RotateAroundZ (0x%08X)", kTarget_RotateAroundZ);
        return;
    }
    if (std::memcmp(reinterpret_cast<const void*>(kTarget_RotateAroundX), kExp_RotateAroundX, sizeof(kExp_RotateAroundX)) != 0) {
        Log("[Mat44AffineOpsFast] Prologue mismatch at RotateAroundX (0x%08X)", kTarget_RotateAroundX);
        return;
    }
    if (std::memcmp(reinterpret_cast<const void*>(kTarget_RotateAroundY), kExp_RotateAroundY, sizeof(kExp_RotateAroundY)) != 0) {
        Log("[Mat44AffineOpsFast] Prologue mismatch at RotateAroundY (0x%08X)", kTarget_RotateAroundY);
        return;
    }
    if (std::memcmp(reinterpret_cast<const void*>(kTarget_FromRotationZ), kExp_FromRotationZ, sizeof(kExp_FromRotationZ)) != 0) {
        Log("[Mat44AffineOpsFast] Prologue mismatch at FromRotationZ (0x%08X)", kTarget_FromRotationZ);
        return;
    }
    if (std::memcmp(reinterpret_cast<const void*>(kTarget_ScaleMatrix), kExp_ScaleMatrix, sizeof(kExp_ScaleMatrix)) != 0) {
        Log("[Mat44AffineOpsFast] Prologue mismatch at ScaleMatrix (0x%08X)", kTarget_ScaleMatrix);
        return;
    }
    if (std::memcmp(reinterpret_cast<const void*>(kTarget_FromQuaternion33), kExp_FromQuaternion33, sizeof(kExp_FromQuaternion33)) != 0) {
        Log("[Mat44AffineOpsFast] Prologue mismatch at FromQuaternion33 (0x%08X)", kTarget_FromQuaternion33);
        return;
    }
    if (std::memcmp(reinterpret_cast<const void*>(kTarget_TranslateByVector), kExp_TranslateByVector, sizeof(kExp_TranslateByVector)) != 0) {
        Log("[Mat44AffineOpsFast] Prologue mismatch at TranslateByVector (0x%08X)", kTarget_TranslateByVector);
        return;
    }
    if (std::memcmp(reinterpret_cast<const void*>(kTarget_Scale3x3), kExp_Scale3x3, sizeof(kExp_Scale3x3)) != 0) {
        Log("[Mat44AffineOpsFast] Prologue mismatch at Scale3x3 (0x%08X)", kTarget_Scale3x3);
        return;
    }
    if (std::memcmp(reinterpret_cast<const void*>(kTarget_ComputeTexMatrices), kExp_ComputeTexMatrices, sizeof(kExp_ComputeTexMatrices)) != 0) {
        Log("[Mat44AffineOpsFast] Prologue mismatch at ComputeTexMatrices (0x%08X)", kTarget_ComputeTexMatrices);
        return;
    }

    // Create hooks
    if (WineSafe_CreateHook(reinterpret_cast<void*>(kTarget_AffineInverse),
                            reinterpret_cast<void*>(&Hook_AffineInverse),
                            reinterpret_cast<void**>(&orig_AffineInverse)) != MH_OK ||
        WineSafe_CreateHook(reinterpret_cast<void*>(kTarget_RotateAroundZ),
                            reinterpret_cast<void*>(&Hook_RotateAroundZ),
                            reinterpret_cast<void**>(&orig_RotateAroundZ)) != MH_OK ||
        WineSafe_CreateHook(reinterpret_cast<void*>(kTarget_RotateAroundX),
                            reinterpret_cast<void*>(&Hook_RotateAroundX),
                            reinterpret_cast<void**>(&orig_RotateAroundX)) != MH_OK ||
        WineSafe_CreateHook(reinterpret_cast<void*>(kTarget_RotateAroundY),
                            reinterpret_cast<void*>(&Hook_RotateAroundY),
                            reinterpret_cast<void**>(&orig_RotateAroundY)) != MH_OK ||
        WineSafe_CreateHook(reinterpret_cast<void*>(kTarget_FromRotationZ),
                            reinterpret_cast<void*>(&Hook_FromRotationZ),
                            reinterpret_cast<void**>(&orig_FromRotationZ)) != MH_OK ||
        WineSafe_CreateHook(reinterpret_cast<void*>(kTarget_ScaleMatrix),
                            reinterpret_cast<void*>(&Hook_ScaleMatrix),
                            reinterpret_cast<void**>(&orig_ScaleMatrix)) != MH_OK ||
        WineSafe_CreateHook(reinterpret_cast<void*>(kTarget_FromQuaternion33),
                            reinterpret_cast<void*>(&Hook_FromQuaternion33),
                            reinterpret_cast<void**>(&orig_FromQuaternion33)) != MH_OK ||
        WineSafe_CreateHook(reinterpret_cast<void*>(kTarget_TranslateByVector),
                            reinterpret_cast<void*>(&Hook_TranslateByVector),
                            reinterpret_cast<void**>(&orig_TranslateByVector)) != MH_OK ||
        WineSafe_CreateHook(reinterpret_cast<void*>(kTarget_Scale3x3),
                            reinterpret_cast<void*>(&Hook_Scale3x3),
                            reinterpret_cast<void**>(&orig_Scale3x3)) != MH_OK ||
        WineSafe_CreateHook(reinterpret_cast<void*>(kTarget_ComputeTexMatrices),
                            reinterpret_cast<void*>(&Hook_ComputeTexMatrices),
                            reinterpret_cast<void**>(&orig_ComputeTexMatrices)) != MH_OK) {
        Log("[Mat44AffineOpsFast] Failed to create one or more hooks");
        return;
    }

    // Enable hooks
    if (WO_EnableHook(reinterpret_cast<void*>(kTarget_AffineInverse)) != MH_OK ||
        WO_EnableHook(reinterpret_cast<void*>(kTarget_RotateAroundZ)) != MH_OK ||
        WO_EnableHook(reinterpret_cast<void*>(kTarget_RotateAroundX)) != MH_OK ||
        WO_EnableHook(reinterpret_cast<void*>(kTarget_RotateAroundY)) != MH_OK ||
        WO_EnableHook(reinterpret_cast<void*>(kTarget_FromRotationZ)) != MH_OK ||
        WO_EnableHook(reinterpret_cast<void*>(kTarget_ScaleMatrix)) != MH_OK ||
        WO_EnableHook(reinterpret_cast<void*>(kTarget_FromQuaternion33)) != MH_OK ||
        WO_EnableHook(reinterpret_cast<void*>(kTarget_TranslateByVector)) != MH_OK ||
        WO_EnableHook(reinterpret_cast<void*>(kTarget_Scale3x3)) != MH_OK ||
        WO_EnableHook(reinterpret_cast<void*>(kTarget_ComputeTexMatrices)) != MH_OK) {
        Log("[Mat44AffineOpsFast] Failed to enable one or more hooks");
        return;
    }

    SamplingProfiler::RegisterSelfSymbol("AffineInverse_Fast", reinterpret_cast<const void*>(&Hook_AffineInverse));
    SamplingProfiler::RegisterSelfSymbol("RotateAroundZ_Fast", reinterpret_cast<const void*>(&Hook_RotateAroundZ));
    SamplingProfiler::RegisterSelfSymbol("RotateAroundX_Fast", reinterpret_cast<const void*>(&Hook_RotateAroundX));
    SamplingProfiler::RegisterSelfSymbol("RotateAroundY_Fast", reinterpret_cast<const void*>(&Hook_RotateAroundY));
    SamplingProfiler::RegisterSelfSymbol("FromRotationZ_Fast", reinterpret_cast<const void*>(&Hook_FromRotationZ));
    SamplingProfiler::RegisterSelfSymbol("ScaleMatrix_Fast", reinterpret_cast<const void*>(&Hook_ScaleMatrix));
    SamplingProfiler::RegisterSelfSymbol("FromQuaternion33_Fast", reinterpret_cast<const void*>(&Hook_FromQuaternion33));
    SamplingProfiler::RegisterSelfSymbol("TranslateByVector_Fast", reinterpret_cast<const void*>(&Hook_TranslateByVector));
    SamplingProfiler::RegisterSelfSymbol("Scale3x3_Fast", reinterpret_cast<const void*>(&Hook_Scale3x3));
    SamplingProfiler::RegisterSelfSymbol("ComputeTexMatrices_Fast", reinterpret_cast<const void*>(&Hook_ComputeTexMatrices));

    g_installed = true;
    Log("[Mat44AffineOpsFast] Acceleration ACTIVE (AffineInverse, RotateZ/X/Y, FromRotZ, ScaleMatrix, FromQuaternion33, TranslateByVector, Scale3x3, ComputeTexMatrices - 200+ call sites)");
}

void LogStats() {
    if (!g_installed) return;

    Log("[Mat44AffineOpsFast] Stats:");
    Log("  AffineInverse:      calls=%llu, verified=%llu, mismatches=%llu, dead=%s",
        g_calls_affine_inverse, g_verified_affine_inverse, g_mismatches_affine_inverse, g_dead_affine_inverse ? "YES" : "NO");
    Log("  RotateAroundZ:      calls=%llu, verified=%llu, mismatches=%llu, dead=%s",
        g_calls_rotate_z, g_verified_rotate_z, g_mismatches_rotate_z, g_dead_rotate_z ? "YES" : "NO");
    Log("  RotateAroundX:      calls=%llu, verified=%llu, mismatches=%llu, dead=%s",
        g_calls_rotate_x, g_verified_rotate_x, g_mismatches_rotate_x, g_dead_rotate_x ? "YES" : "NO");
    Log("  RotateAroundY:      calls=%llu, verified=%llu, mismatches=%llu, dead=%s",
        g_calls_rotate_y, g_verified_rotate_y, g_mismatches_rotate_y, g_dead_rotate_y ? "YES" : "NO");
    Log("  FromRotationZ:      calls=%llu, verified=%llu, mismatches=%llu, dead=%s",
        g_calls_from_rot_z, g_verified_from_rot_z, g_mismatches_from_rot_z, g_dead_from_rot_z ? "YES" : "NO");
    Log("  ScaleMatrix:        calls=%llu, verified=%llu, mismatches=%llu, dead=%s",
        g_calls_scale_matrix, g_verified_scale_matrix, g_mismatches_scale_matrix, g_dead_scale_matrix ? "YES" : "NO");
    Log("  FromQuaternion33:   calls=%llu, verified=%llu, mismatches=%llu, dead=%s",
        g_calls_from_quat33, g_verified_from_quat33, g_mismatches_from_quat33, g_dead_from_quat33 ? "YES" : "NO");
    Log("  TranslateByVector:  calls=%llu, verified=%llu, mismatches=%llu, dead=%s",
        g_calls_translate_vec, g_verified_translate_vec, g_mismatches_translate_vec, g_dead_translate_vec ? "YES" : "NO");
    Log("  Scale3x3:           calls=%llu, verified=%llu, mismatches=%llu, dead=%s",
        g_calls_scale_3x3, g_verified_scale_3x3, g_mismatches_scale_3x3, g_dead_scale_3x3 ? "YES" : "NO");
    Log("  ComputeTexMatrices: calls=%llu, verified=%llu, mismatches=%llu, dead=%s",
        g_calls_compute_tex, g_verified_compute_tex, g_mismatches_compute_tex, g_dead_compute_tex ? "YES" : "NO");
}

void Shutdown() {
    if (!g_installed) return;

    MH_DisableHook(reinterpret_cast<void*>(kTarget_AffineInverse));
    MH_DisableHook(reinterpret_cast<void*>(kTarget_RotateAroundZ));
    MH_DisableHook(reinterpret_cast<void*>(kTarget_RotateAroundX));
    MH_DisableHook(reinterpret_cast<void*>(kTarget_RotateAroundY));
    MH_DisableHook(reinterpret_cast<void*>(kTarget_FromRotationZ));
    MH_DisableHook(reinterpret_cast<void*>(kTarget_ScaleMatrix));
    MH_DisableHook(reinterpret_cast<void*>(kTarget_FromQuaternion33));
    MH_DisableHook(reinterpret_cast<void*>(kTarget_TranslateByVector));
    MH_DisableHook(reinterpret_cast<void*>(kTarget_Scale3x3));
    MH_DisableHook(reinterpret_cast<void*>(kTarget_ComputeTexMatrices));

    MH_RemoveHook(reinterpret_cast<void*>(kTarget_AffineInverse));
    MH_RemoveHook(reinterpret_cast<void*>(kTarget_RotateAroundZ));
    MH_RemoveHook(reinterpret_cast<void*>(kTarget_RotateAroundX));
    MH_RemoveHook(reinterpret_cast<void*>(kTarget_RotateAroundY));
    MH_RemoveHook(reinterpret_cast<void*>(kTarget_FromRotationZ));
    MH_RemoveHook(reinterpret_cast<void*>(kTarget_ScaleMatrix));
    MH_RemoveHook(reinterpret_cast<void*>(kTarget_FromQuaternion33));
    MH_RemoveHook(reinterpret_cast<void*>(kTarget_TranslateByVector));
    MH_RemoveHook(reinterpret_cast<void*>(kTarget_Scale3x3));
    MH_RemoveHook(reinterpret_cast<void*>(kTarget_ComputeTexMatrices));

    g_installed = false;
    Log("[Mat44AffineOpsFast] Shutdown complete");
}

} // namespace Mat44AffineOpsFast
