// ============================================================================
// Module: m2_skinning_sse2_fast.cpp
//
// Accelerates CM2Model vertex skinning in Model2:
//   - CM2Model::TransformVertices_cpp (sub_82A210 @ 0x0082A210)
//   - CM2Model::TransformVerticesOneBone_cpp (sub_82A4E0 @ 0x0082A4E0)
//
// In stock WoW 3.3.5a, whenever the destination vertex buffer is not 16-byte aligned,
// the engine falls back to scalar x87 loops. This module replaces those loops with
// 128-bit SSE2 vector operations and unaligned vector stores (_mm_storeu_ps),
// eliminating x87 FPU bottlenecks completely for all skinning passes.
// Dual-run verified with fail-safe retirement guards.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>
#include <cmath>

#include "m2_skinning_sse2_fast.h"
#include "config.h"
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

namespace M2SkinningSSE2Fast {
namespace {

constexpr uintptr_t kTargetMulti   = 0x0082A210;
constexpr uintptr_t kTargetOneBone = 0x0082A4E0;

const unsigned char kExpectedMulti[6] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x68
};

const unsigned char kExpectedOneBone[6] = {
    0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08
};

typedef void (__cdecl* Skin_fn)(void* model, void* section, uint8_t* vertices, int32_t texCoord);

static Skin_fn orig_Multi   = nullptr;
static Skin_fn orig_OneBone = nullptr;

static bool g_installed = false;
static bool g_retired   = false;

// Statistics
static uint64_t g_callsOneBone     = 0;
static uint64_t g_callsMulti       = 0;
static uint64_t g_verifiedOneBone  = 0;
static uint64_t g_verifiedMulti    = 0;
static uint64_t g_vertsTransformed = 0;

void Fast_TransformOneBone(void* model, void* section, uint8_t* vertices, int32_t texCoord) {
    const float* bones = *reinterpret_cast<const float**>((char*)model + 0x98);
    void* shared = *reinterpret_cast<void**>((char*)model + 0x2C);
    if (!bones || !shared) {
        orig_OneBone(model, section, vertices, texCoord);
        return;
    }
    void* data = *reinterpret_cast<void**>((char*)shared + 0x150);
    if (!data) {
        orig_OneBone(model, section, vertices, texCoord);
        return;
    }
    const uint8_t* vertData = *reinterpret_cast<const uint8_t**>((char*)data + 0x40);
    if (!vertData) {
        orig_OneBone(model, section, vertices, texCoord);
        return;
    }

    uint16_t vertexStart = *reinterpret_cast<const uint16_t*>((char*)section + 4);
    uint16_t vertexCount = *reinterpret_cast<const uint16_t*>((char*)section + 6);

    const uint8_t* vertex = vertData + vertexStart * 48;
    const uint8_t* end = vertex + vertexCount * 48;
    float* out = reinterpret_cast<float*>(vertices);

    size_t texOffset = (texCoord == 0) ? 0x20 : 0x28;

    for (; vertex < end; vertex += 48, out += 8) {
        uint8_t boneIdx = vertex[0x10];
        const float* bone = bones + boneIdx * 16;

        __m128 row0 = _mm_loadu_ps(&bone[0]);
        __m128 row1 = _mm_loadu_ps(&bone[4]);
        __m128 row2 = _mm_loadu_ps(&bone[8]);
        __m128 row3 = _mm_loadu_ps(&bone[12]);

        const float* pos = reinterpret_cast<const float*>(vertex);
        const float* norm = reinterpret_cast<const float*>(vertex + 0x14);

        __m128 position = _mm_add_ps(_mm_add_ps(_mm_mul_ps(row2, _mm_set1_ps(pos[2])),
                                                _mm_add_ps(_mm_mul_ps(row1, _mm_set1_ps(pos[1])),
                                                           _mm_mul_ps(row0, _mm_set1_ps(pos[0])))),
                                     row3);

        __m128 normal = _mm_add_ps(_mm_add_ps(_mm_mul_ps(row0, _mm_set1_ps(norm[0])),
                                              _mm_mul_ps(row1, _mm_set1_ps(norm[1]))),
                                   _mm_mul_ps(row2, _mm_set1_ps(norm[2])));

        _mm_storeu_ps(&out[0], position);
        _mm_storeu_ps(&out[3], normal);

        const float* uv = reinterpret_cast<const float*>(vertex + texOffset);
        out[6] = uv[0];
        out[7] = uv[1];
    }
    g_vertsTransformed += vertexCount;
}

void Fast_TransformMulti(void* model, void* section, uint8_t* vertices, int32_t texCoord) {
    const float* bones = *reinterpret_cast<const float**>((char*)model + 0x98);
    void* shared = *reinterpret_cast<void**>((char*)model + 0x2C);
    if (!bones || !shared) {
        orig_Multi(model, section, vertices, texCoord);
        return;
    }
    void* data = *reinterpret_cast<void**>((char*)shared + 0x150);
    if (!data) {
        orig_Multi(model, section, vertices, texCoord);
        return;
    }
    const uint8_t* vertData = *reinterpret_cast<const uint8_t**>((char*)data + 0x40);
    if (!vertData) {
        orig_Multi(model, section, vertices, texCoord);
        return;
    }

    uint16_t vertexStart = *reinterpret_cast<const uint16_t*>((char*)section + 4);
    uint16_t vertexCount = *reinterpret_cast<const uint16_t*>((char*)section + 6);

    const uint8_t* vertex = vertData + vertexStart * 48;
    const uint8_t* end = vertex + vertexCount * 48;
    float* out = reinterpret_cast<float*>(vertices);

    size_t texOffset = (texCoord == 0) ? 0x20 : 0x28;

    uint32_t cachedWeights = 0xFFFFFFFF;
    uint32_t cachedIndices = 0xFFFFFFFF;
    __m128 row0 = _mm_setzero_ps();
    __m128 row1 = _mm_setzero_ps();
    __m128 row2 = _mm_setzero_ps();
    __m128 row3 = _mm_setzero_ps();

    for (; vertex < end; vertex += 48, out += 8) {
        uint32_t w = *reinterpret_cast<const uint32_t*>(vertex + 0x0C);
        uint32_t idx = *reinterpret_cast<const uint32_t*>(vertex + 0x10);

        if (w != cachedWeights || idx != cachedIndices) {
            cachedWeights = w;
            cachedIndices = idx;

            const uint8_t* weights = vertex + 0x0C;
            const uint8_t* indices = vertex + 0x10;

            float w0 = weights[0] * 0.0039215689f;
            __m128 mw0 = _mm_set1_ps(w0);
            const float* b0 = bones + indices[0] * 16;
            row0 = _mm_mul_ps(_mm_loadu_ps(&b0[0]), mw0);
            row1 = _mm_mul_ps(_mm_loadu_ps(&b0[4]), mw0);
            row2 = _mm_mul_ps(_mm_loadu_ps(&b0[8]), mw0);
            row3 = _mm_mul_ps(_mm_loadu_ps(&b0[12]), mw0);

            for (int k = 1; k < 4 && weights[k] > 0; ++k) {
                float wk = weights[k] * 0.0039215689f;
                __m128 mwk = _mm_set1_ps(wk);
                const float* bk = bones + indices[k] * 16;
                row0 = _mm_add_ps(row0, _mm_mul_ps(_mm_loadu_ps(&bk[0]), mwk));
                row1 = _mm_add_ps(row1, _mm_mul_ps(_mm_loadu_ps(&bk[4]), mwk));
                row2 = _mm_add_ps(row2, _mm_mul_ps(_mm_loadu_ps(&bk[8]), mwk));
                row3 = _mm_add_ps(row3, _mm_mul_ps(_mm_loadu_ps(&bk[12]), mwk));
            }
        }

        const float* pos = reinterpret_cast<const float*>(vertex);
        const float* norm = reinterpret_cast<const float*>(vertex + 0x14);

        __m128 normal = _mm_add_ps(_mm_add_ps(_mm_mul_ps(_mm_set1_ps(norm[0]), row0),
                                              _mm_mul_ps(_mm_set1_ps(norm[1]), row1)),
                                   _mm_mul_ps(_mm_set1_ps(norm[2]), row2));

        __m128 position = _mm_add_ps(_mm_add_ps(_mm_add_ps(_mm_mul_ps(_mm_set1_ps(pos[0]), row0),
                                                           _mm_mul_ps(_mm_set1_ps(pos[1]), row1)),
                                                _mm_mul_ps(_mm_set1_ps(pos[2]), row2)),
                                     row3);

        _mm_storeu_ps(&out[0], position);
        _mm_storeu_ps(&out[3], normal);

        const float* uv = reinterpret_cast<const float*>(vertex + texOffset);
        out[6] = uv[0];
        out[7] = uv[1];
    }
    g_vertsTransformed += vertexCount;
}

void __cdecl Hooked_OneBone(void* model, void* section, uint8_t* vertices, int32_t texCoord) {
    g_callsOneBone++;
    if (!model || !section || !vertices || g_retired || !Config::g_settings.OptM2SkinningSse2Fast) {
        orig_OneBone(model, section, vertices, texCoord);
        return;
    }

    if (g_verifiedOneBone < 500) {
        uint16_t count = *reinterpret_cast<const uint16_t*>((char*)section + 6);
        size_t bytes = count * 32;
        if (bytes > 0 && bytes < 65536) {
            uint8_t* testBuf = (uint8_t*)_malloca(bytes);
            if (testBuf) {
                Fast_TransformOneBone(model, section, testBuf, texCoord);
                orig_OneBone(model, section, vertices, texCoord);

                float* fFast = (float*)testBuf;
                float* fOrig = (float*)vertices;
                size_t numFloats = count * 8;
                bool match = true;
                for (size_t i = 0; i < numFloats; ++i) {
                    if (std::fabs(fFast[i] - fOrig[i]) > 1e-3f) {
                        match = false;
                        break;
                    }
                }
                _freea(testBuf);

                if (!match) {
                    Log("[M2SkinningSSE2Fast] OneBone mismatch on call %llu! Retiring hook.", g_callsOneBone);
                    g_retired = true;
                    return;
                }
                g_verifiedOneBone++;
                return;
            }
        }
    }

    Fast_TransformOneBone(model, section, vertices, texCoord);
}

void __cdecl Hooked_Multi(void* model, void* section, uint8_t* vertices, int32_t texCoord) {
    g_callsMulti++;
    if (!model || !section || !vertices || g_retired || !Config::g_settings.OptM2SkinningSse2Fast) {
        orig_Multi(model, section, vertices, texCoord);
        return;
    }

    if (g_verifiedMulti < 500) {
        uint16_t count = *reinterpret_cast<const uint16_t*>((char*)section + 6);
        size_t bytes = count * 32;
        if (bytes > 0 && bytes < 65536) {
            uint8_t* testBuf = (uint8_t*)_malloca(bytes);
            if (testBuf) {
                Fast_TransformMulti(model, section, testBuf, texCoord);
                orig_Multi(model, section, vertices, texCoord);

                float* fFast = (float*)testBuf;
                float* fOrig = (float*)vertices;
                size_t numFloats = count * 8;
                bool match = true;
                for (size_t i = 0; i < numFloats; ++i) {
                    if (std::fabs(fFast[i] - fOrig[i]) > 1e-3f) {
                        match = false;
                        break;
                    }
                }
                _freea(testBuf);

                if (!match) {
                    Log("[M2SkinningSSE2Fast] MultiBone mismatch on call %llu! Retiring hook.", g_callsMulti);
                    g_retired = true;
                    return;
                }
                g_verifiedMulti++;
                return;
            }
        }
    }

    Fast_TransformMulti(model, section, vertices, texCoord);
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptM2SkinningSse2Fast) return true;

    if (memcmp(reinterpret_cast<const void*>(kTargetMulti), kExpectedMulti, sizeof(kExpectedMulti)) != 0 ||
        memcmp(reinterpret_cast<const void*>(kTargetOneBone), kExpectedOneBone, sizeof(kExpectedOneBone)) != 0) {
        Log("[M2SkinningSSE2Fast] Prologue mismatch; hook aborted.");
        return false;
    }

    MH_STATUS st1 = WineSafe_CreateHook(reinterpret_cast<void*>(kTargetMulti),
                                        reinterpret_cast<void*>(&Hooked_Multi),
                                        reinterpret_cast<void**>(&orig_Multi));
    MH_STATUS st2 = WineSafe_CreateHook(reinterpret_cast<void*>(kTargetOneBone),
                                        reinterpret_cast<void*>(&Hooked_OneBone),
                                        reinterpret_cast<void**>(&orig_OneBone));

    if (st1 != MH_OK || st2 != MH_OK) {
        Log("[M2SkinningSSE2Fast] WineSafe_CreateHook failed.");
        return false;
    }

    if (WO_EnableHook(reinterpret_cast<void*>(kTargetMulti)) != MH_OK ||
        WO_EnableHook(reinterpret_cast<void*>(kTargetOneBone)) != MH_OK) {
        Log("[M2SkinningSSE2Fast] WO_EnableHook failed.");
        return false;
    }

    g_installed = true;
    Log("[M2SkinningSSE2Fast] Hook installed at 0x%08X and 0x%08X (M2 Software Vertex Skinning).",
        kTargetMulti, kTargetOneBone);
    return true;
}

void Shutdown() {
    if (g_installed) {
        MH_DisableHook(reinterpret_cast<void*>(kTargetMulti));
        MH_DisableHook(reinterpret_cast<void*>(kTargetOneBone));
        g_installed = false;
    }
}

void LogStats() {
    if (!g_installed) return;
    Log("[M2SkinningSSE2Fast] CallsOneBone: %llu, CallsMulti: %llu, Verified: %llu/%llu, Verts: %llu, Retired: %s",
        g_callsOneBone, g_callsMulti, g_verifiedOneBone, g_verifiedMulti, g_vertsTransformed, g_retired ? "YES" : "NO");
}

} // namespace M2SkinningSSE2Fast

