// ============================================================================
// Module: m2_skinning_40b_fast.cpp
//
// Fast M2 multi-bone 40-byte vertex buffer transformation and skinning:
//   sub_829F40: CM2Model::TransformVerticesMultiBone_40B
//
// Background & Analysis:
//   In WoW 3.3.5a, CPU vertex skinning for 40-byte vertex formats (GxVBF_PNT2:
//   position 12B, normal 12B, uv1 8B, uv2 8B) is handled by sub_829F40, called
//   from CM2Model::FillVertexBuffer (sub_82D910).
//
//   Stock sub_829F40 implementation:
//     1. Evaluates bone blending and matrix transformation entirely on the legacy
//        x87 FPU stack with dozens of fld/fstp instructions per vertex.
//     2. Issues an indirect call to sub_4C21B0 (affine matrix-vector product) for
//        every single vertex, creating severe call overhead and stack spills.
//     3. Performs serial 32-bit scalar loads and stores for texture coordinates
//        uv1 and uv2 across multiple cache lines.
//
// Fast implementation:
//     1. Inlines matrix-vector affine math directly into the vertex loop using
//        register-allocated IEEE double precision strictly matching x87 evaluation
//        order.
//     2. Precomputes a 256-entry scaled weight lookup table eliminating integer-
//        to-float x87 conversion stalls.
//     3. Caches blended bone transform matrices across contiguous vertices with
//        identical bone weights and indices.
//     4. Uses 128-bit vector instructions (_mm_loadu_ps / _mm_storeu_ps) to copy
//        16 bytes of dual texture coordinates in a single operation.
//     5. Employs dual-run verification against the original client routine with
//        automatic fail-safe retirement guards on any discrepancy.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <malloc.h>

#include "m2_skinning_40b_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);

namespace M2Skinning40BFast {

namespace {

constexpr uintptr_t kTarget = 0x00829F40;

const unsigned char kExpectedPrologue[16] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x64, 0xD9, 0xE8,
    0x33, 0xC0, 0xD9, 0x55, 0x9C, 0x89, 0x45, 0xFC
};

constexpr unsigned long kVerifyFirst = 10000;
constexpr unsigned long kResampleMask = 127;

typedef unsigned int (__cdecl* TransformVertices40B_fn)(void* model, void* section, uint8_t* outVertices);

static TransformVertices40B_fn g_orig_TransformVerticesMultiBone_40B = nullptr;

static bool g_installed = false;
static bool g_dead      = false;

static unsigned long long g_calls      = 0;
static unsigned long long g_verified   = 0;
static unsigned long long g_mismatches = 0;

static double s_weightTableD[256];
static bool s_tableInitialized = false;

__forceinline void Fast_Transform40B_Impl(
    const void* bones_ptr,
    const uint8_t* vertex,
    uint16_t vertexCount,
    uint8_t* out_bytes)
{
    float M[16];
    double dM[16];
    uint32_t last_weights = 0xFFFFFFFF;
    uint32_t last_indices = 0xFFFFFFFF;
    const uintptr_t bones = reinterpret_cast<uintptr_t>(bones_ptr);

    for (uint16_t i = 0; i < vertexCount; ++i, vertex += 48, out_bytes += 40) {
        const uint32_t weights = *reinterpret_cast<const uint32_t*>(vertex + 12);
        const uint32_t indices = *reinterpret_cast<const uint32_t*>(vertex + 16);

        if (weights != last_weights || indices != last_indices) {
            last_weights = weights;
            last_indices = indices;

            const uint8_t* w = vertex + 12;
            const uint8_t* b = vertex + 16;

            const float* b0 = reinterpret_cast<const float*>(bones + (static_cast<size_t>(b[0]) << 6));
            const double w0_scale = s_weightTableD[w[0]];

            M[0]  = static_cast<float>(static_cast<double>(b0[0])  * w0_scale);
            M[1]  = static_cast<float>(static_cast<double>(b0[1])  * w0_scale);
            M[2]  = static_cast<float>(static_cast<double>(b0[2])  * w0_scale);
            M[4]  = static_cast<float>(static_cast<double>(b0[4])  * w0_scale);
            M[5]  = static_cast<float>(static_cast<double>(b0[5])  * w0_scale);
            M[6]  = static_cast<float>(static_cast<double>(b0[6])  * w0_scale);
            M[8]  = static_cast<float>(static_cast<double>(b0[8])  * w0_scale);
            M[9]  = static_cast<float>(static_cast<double>(b0[9])  * w0_scale);
            M[10] = static_cast<float>(static_cast<double>(b0[10]) * w0_scale);
            M[12] = static_cast<float>(static_cast<double>(b0[12]) * w0_scale);
            M[13] = static_cast<float>(static_cast<double>(b0[13]) * w0_scale);
            M[14] = static_cast<float>(static_cast<double>(b0[14]) * w0_scale);

            for (int j = 1; j < 4; ++j) {
                if (w[j] == 0) break;
                const float* bj = reinterpret_cast<const float*>(bones + (static_cast<size_t>(b[j]) << 6));
                const double wj_scale = s_weightTableD[w[j]];

                M[0]  = static_cast<float>(static_cast<double>(M[0])  + static_cast<double>(bj[0])  * wj_scale);
                M[1]  = static_cast<float>(static_cast<double>(M[1])  + static_cast<double>(bj[1])  * wj_scale);
                M[2]  = static_cast<float>(static_cast<double>(M[2])  + static_cast<double>(bj[2])  * wj_scale);
                M[4]  = static_cast<float>(static_cast<double>(M[4])  + static_cast<double>(bj[4])  * wj_scale);
                M[5]  = static_cast<float>(static_cast<double>(M[5])  + static_cast<double>(bj[5])  * wj_scale);
                M[6]  = static_cast<float>(static_cast<double>(M[6])  + static_cast<double>(bj[6])  * wj_scale);
                M[8]  = static_cast<float>(static_cast<double>(M[8])  + static_cast<double>(bj[8])  * wj_scale);
                M[9]  = static_cast<float>(static_cast<double>(M[9])  + static_cast<double>(bj[9])  * wj_scale);
                M[10] = static_cast<float>(static_cast<double>(M[10]) + static_cast<double>(bj[10]) * wj_scale);
                M[12] = static_cast<float>(static_cast<double>(M[12]) + static_cast<double>(bj[12]) * wj_scale);
                M[13] = static_cast<float>(static_cast<double>(M[13]) + static_cast<double>(bj[13]) * wj_scale);
                M[14] = static_cast<float>(static_cast<double>(M[14]) + static_cast<double>(bj[14]) * wj_scale);
            }

            dM[0]  = static_cast<double>(M[0]);
            dM[1]  = static_cast<double>(M[1]);
            dM[2]  = static_cast<double>(M[2]);
            dM[4]  = static_cast<double>(M[4]);
            dM[5]  = static_cast<double>(M[5]);
            dM[6]  = static_cast<double>(M[6]);
            dM[8]  = static_cast<double>(M[8]);
            dM[9]  = static_cast<double>(M[9]);
            dM[10] = static_cast<double>(M[10]);
            dM[12] = static_cast<double>(M[12]);
            dM[13] = static_cast<double>(M[13]);
            dM[14] = static_cast<double>(M[14]);
        }

        const float* pos  = reinterpret_cast<const float*>(vertex);
        const float* norm = reinterpret_cast<const float*>(vertex + 20);

        const double px = static_cast<double>(pos[0]);
        const double py = static_cast<double>(pos[1]);
        const double pz = static_cast<double>(pos[2]);

        const double nx = static_cast<double>(norm[0]);
        const double ny = static_cast<double>(norm[1]);
        const double nz = static_cast<double>(norm[2]);

        float* out = reinterpret_cast<float*>(out_bytes);
        out[0] = static_cast<float>(((py * dM[4] + pz * dM[8])  + px * dM[0]) + dM[12]);
        out[1] = static_cast<float>(((py * dM[5] + pz * dM[9])  + px * dM[1]) + dM[13]);
        out[2] = static_cast<float>(((py * dM[6] + pz * dM[10]) + px * dM[2]) + dM[14]);

        out[3] = static_cast<float>((nx * dM[0] + nz * dM[8])  + ny * dM[4]);
        out[4] = static_cast<float>((nx * dM[1] + nz * dM[9])  + ny * dM[5]);
        out[5] = static_cast<float>((nx * dM[2] + nz * dM[10]) + ny * dM[6]);

        _mm_storeu_ps(&out[6], _mm_loadu_ps(reinterpret_cast<const float*>(vertex + 32)));
    }
}

__declspec(noinline) static unsigned int Verify_TransformMultiBone_40B(
    void* model,
    void* section,
    uint8_t* outVertices,
    const void* bones,
    const uint8_t* vertex,
    uint16_t count)
{
    const size_t byte_size = static_cast<size_t>(count) * 40;
    uint8_t* temp_buffer = static_cast<uint8_t*>(_malloca(byte_size));
    if (!temp_buffer) {
        return g_orig_TransformVerticesMultiBone_40B(model, section, outVertices);
    }

    unsigned int orig_ret = g_orig_TransformVerticesMultiBone_40B(model, section, outVertices);
    Fast_Transform40B_Impl(bones, vertex, count, temp_buffer);

    if (memcmp(outVertices, temp_buffer, byte_size) != 0) {
        ++g_mismatches;
        g_dead = true;
        Log("[M2Skinning40BFast] Verification DISAGREEMENT on section vertexCount=%u. Retiring.", (unsigned)count);
    } else {
        ++g_verified;
    }

    _freea(temp_buffer);
    return orig_ret;
}

__declspec(safebuffers) static unsigned int __cdecl Hook_TransformVerticesMultiBone_40B(
    void* model,
    void* section,
    uint8_t* outVertices)
{
    ++g_calls;

    if (g_dead || !model || !section || !outVertices) {
        if (g_orig_TransformVerticesMultiBone_40B) {
            return g_orig_TransformVerticesMultiBone_40B(model, section, outVertices);
        }
        return 0;
    }

    const void* bones = *reinterpret_cast<const void* const*>(
        reinterpret_cast<const char*>(model) + 0x98);
    const void* shared = *reinterpret_cast<const void* const*>(
        reinterpret_cast<const char*>(model) + 0x2C);
    if (!bones || !shared) {
        return g_orig_TransformVerticesMultiBone_40B(model, section, outVertices);
    }

    const void* data = *reinterpret_cast<const void* const*>(
        reinterpret_cast<const char*>(shared) + 0x150);
    if (!data) {
        return g_orig_TransformVerticesMultiBone_40B(model, section, outVertices);
    }

    const uint8_t* vert_base = *reinterpret_cast<const uint8_t* const*>(
        reinterpret_cast<const char*>(data) + 0x40);
    if (!vert_base) {
        return g_orig_TransformVerticesMultiBone_40B(model, section, outVertices);
    }

    const uint16_t vertexStart = *reinterpret_cast<const uint16_t*>(
        reinterpret_cast<const char*>(section) + 4);
    const uint16_t vertexCount = *reinterpret_cast<const uint16_t*>(
        reinterpret_cast<const char*>(section) + 6);
    if (vertexCount == 0) {
        return g_orig_TransformVerticesMultiBone_40B(model, section, outVertices);
    }

    const uint8_t* vertex = vert_base + static_cast<size_t>(vertexStart) * 48;

    if (g_verified < kVerifyFirst || (g_calls & kResampleMask) == 0) {
        return Verify_TransformMultiBone_40B(model, section, outVertices, bones, vertex, vertexCount);
    }

    Fast_Transform40B_Impl(bones, vertex, vertexCount, outVertices);
    return 0;
}

static bool CheckPrologue(uintptr_t addr, const unsigned char* expected, size_t size) {
    __try {
        return memcmp(reinterpret_cast<const void*>(addr), expected, size) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

void Init() {
    if (!Config::g_settings.OptM2Skinning40BFast) {
        return;
    }

    if (!s_tableInitialized) {
        for (int i = 0; i < 256; ++i) {
            s_weightTableD[i] = static_cast<double>(i) * static_cast<double>(0.0039215689f);
        }
        s_tableInitialized = true;
    }

    if (!CheckPrologue(kTarget, kExpectedPrologue, sizeof(kExpectedPrologue))) {
        Log("[M2Skinning40BFast] NOT active: prologue mismatch at 0x%08X", static_cast<unsigned>(kTarget));
        return;
    }

    MH_STATUS status = WineSafe_CreateHook(
        reinterpret_cast<void*>(kTarget),
        reinterpret_cast<void*>(Hook_TransformVerticesMultiBone_40B),
        reinterpret_cast<void**>(&g_orig_TransformVerticesMultiBone_40B));
    if (status != MH_OK) {
        Log("[M2Skinning40BFast] NOT active: hook creation failed with status %d", static_cast<int>(status));
        return;
    }

    status = WO_EnableHook(reinterpret_cast<void*>(kTarget));
    if (status != MH_OK) {
        Log("[M2Skinning40BFast] NOT active: WO_EnableHook failed with status %d", static_cast<int>(status));
        return;
    }

    SamplingProfiler::RegisterSelfSymbol(
        "TransformVerticesMultiBone_40B_Fast",
        reinterpret_cast<const void*>(&Hook_TransformVerticesMultiBone_40B));

    g_installed = true;
    Log("[M2Skinning40BFast] ACTIVE on sub_829F40 (inlined affine math, vector UV copy, bone matrix caching)");
}

void Shutdown() {
    if (g_installed) {
        MH_DisableHook(reinterpret_cast<void*>(kTarget));
        MH_RemoveHook(reinterpret_cast<void*>(kTarget));
        g_installed = false;
        Log("[M2Skinning40BFast] Shutdown complete");
    }
}

void LogStats() {
    if (!Config::g_settings.OptM2Skinning40BFast) return;
    if (!g_installed) {
        Log("[M2Skinning40BFast] not installed");
        return;
    }
    if (g_dead) {
        Log("[M2Skinning40BFast] RETIRED after mismatch (calls=%llu, verified=%llu, mismatches=%llu)",
            g_calls, g_verified, g_mismatches);
    } else {
        Log("[M2Skinning40BFast] active and bit-exact (calls=%llu, verified=%llu)",
            g_calls, g_verified);
    }
}

}  // namespace M2Skinning40BFast

