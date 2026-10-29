// ============================================================================
// Module: collision_bsp_reject_sse2.cpp
//
// Accelerates sub_7C6790 @ 0x007C6790 (BspQuery_Segment ray-box reject & triangle clip).
// Replaces serialized scalar x87 Cohen-Sutherland outcode loops with 128-bit
// packed SSE2 instructions and fast branchless triangle rejection.
// Dual-run verified with fail-safe retirement guards.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>
#include <algorithm>

#include "collision_bsp_reject_sse2.h"
#include "config.h"
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

namespace CollisionBspRejectSSE2 {
namespace {

constexpr uintptr_t kTarget = 0x007C6790;
constexpr uintptr_t kCacheLookup = 0x0079B1F0;
constexpr uintptr_t kRayTriIntersect = 0x00983490;

const unsigned char kExpectedPrologue[10] = {
    0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xD0, 0x01, 0x00, 0x00, 0x56
};

typedef char (__fastcall* Target_fn)(void* self, void* dummy_edx, int a2, float a3);
typedef void* (__thiscall* CacheLookup_fn)(void* cache, int a2, uint32_t a3, int a4, int a5, int a6);
typedef uint8_t (__cdecl* RayTri_fn)(void* pRay, void* pVerts, void* pIndices, float* pT, int unk, float eps);

static Target_fn orig_Sub7C6790 = nullptr;

static bool g_installed = false;
static bool g_retired = false;

// Statistics
static uint64_t g_calls = 0;
static uint64_t g_verified = 0;
static uint64_t g_vertsOutcoded = 0;
static uint64_t g_trisCulled = 0;

inline uint8_t ComputeOutcodeSSE2(const float* v, __m128 minBound, __m128 maxBound) {
    __m128 pos = _mm_set_ps(0.0f, v[2], v[1], v[0]);
    __m128 cmpMin = _mm_cmplt_ps(pos, minBound);
    __m128 cmpMax = _mm_cmpgt_ps(pos, maxBound);

    int maskMin = _mm_movemask_ps(cmpMin);
    int maskMax = _mm_movemask_ps(cmpMax);

    uint8_t code = 0;
    if (maskMin & 1) code |= 32;
    if (maskMax & 1) code |= 16;
    if (maskMin & 2) code |= 8;
    if (maskMax & 2) code |= 4;
    if (maskMin & 4) code |= 2;
    if (maskMax & 4) code |= 1;

    return code;
}

char __fastcall Fast_Sub7C6790(void* self, void* dummy_edx, int a2, float a3) {
    if (!self) return 0;

    void* globalCache = *reinterpret_cast<void**>(0x00CDD7A0);
    if (!globalCache) return 0;

    auto lookupFn = reinterpret_cast<CacheLookup_fn>(kCacheLookup);
    int a4 = *reinterpret_cast<int*>((char*)self + 4);
    int a5 = *reinterpret_cast<int*>((char*)self + 8);
    int a6 = *reinterpret_cast<int*>((char*)self + 12);
    uint32_t uA3 = *reinterpret_cast<uint32_t*>(&a3);

    char* v5 = reinterpret_cast<char*>(lookupFn(globalCache, a2, uA3, a4, a5, a6));
    if (!v5) return 0;

    float rStartX = *reinterpret_cast<float*>((char*)self + 40);
    float rStartY = *reinterpret_cast<float*>((char*)self + 44);
    float rStartZ = *reinterpret_cast<float*>((char*)self + 48);

    float rEndX = *reinterpret_cast<float*>((char*)self + 52);
    float rEndY = *reinterpret_cast<float*>((char*)self + 56);
    float rEndZ = *reinterpret_cast<float*>((char*)self + 60);

    float minX = (std::min)(rStartX, rEndX) - 0.01f;
    float maxX = (std::max)(rStartX, rEndX) + 0.01f;
    float minY = (std::min)(rStartY, rEndY) - 0.01f;
    float maxY = (std::max)(rStartY, rEndY) + 0.01f;
    float minZ = (std::min)(rStartZ, rEndZ) - 0.01f;
    float maxZ = (std::max)(rStartZ, rEndZ) + 0.01f;

    uint16_t vertexCount = *reinterpret_cast<uint16_t*>(v5 + 6);
    if (vertexCount > 450) {
        return orig_Sub7C6790(self, dummy_edx, a2, a3);
    }

    uint8_t outcodes[452];
    const float* verts = reinterpret_cast<const float*>(v5 + 8);

    __m128 minBound = _mm_set_ps(0.0f, minZ, minY, minX);
    __m128 maxBound = _mm_set_ps(0.0f, maxZ, maxY, maxX);

    for (uint16_t i = 0; i < vertexCount; ++i) {
        outcodes[i] = ComputeOutcodeSSE2(&verts[i * 3], minBound, maxBound);
    }
    g_vertsOutcoded += vertexCount;

    uint16_t triCount = *reinterpret_cast<uint16_t*>(v5 + 6308);
    auto* dword_D2DBF8 = reinterpret_cast<uint32_t*>(0x00D2DBF8);
    auto* word_D25BF8 = reinterpret_cast<uint16_t*>(0x00D25BF8);
    auto rayTriFn = reinterpret_cast<RayTri_fn>(kRayTriIntersect);

    int filterMask = *reinterpret_cast<int*>((char*)self + 92);
    char* flagBase = *reinterpret_cast<char**>((char*)self + 4);

    for (uint16_t k = 0; k < triCount; ++k) {
        uint16_t v141 = *reinterpret_cast<uint16_t*>(v5 + 8710 + k * 2);
        uint16_t v142 = *reinterpret_cast<uint16_t*>(v5 + 8110 + k * 2);
        uint8_t v145 = *reinterpret_cast<uint8_t*>(flagBase + v141 * 2);

        if ((v142 & filterMask) != 0 || (filterMask & v145) != 0) {
            continue;
        }

        uint32_t hitIdx = *dword_D2DBF8;
        if (hitIdx >= 0x2000) {
            break;
        }

        word_D25BF8[hitIdx] = v141;
        *dword_D2DBF8 = hitIdx + 1;
        flagBase[v141 * 2] |= static_cast<char>(0x80);

        uint16_t idx0 = *reinterpret_cast<uint16_t*>(v5 + 6310 + k * 6);
        uint16_t idx1 = *reinterpret_cast<uint16_t*>(v5 + 6312 + k * 6);
        uint16_t idx2 = *reinterpret_cast<uint16_t*>(v5 + 6314 + k * 6);

        if ((outcodes[idx0] & outcodes[idx1] & outcodes[idx2] & 0x3F) != 0) {
            g_trisCulled++;
            continue; // Culled by bounding box
        }

        float hitT = 0.0f;
        void* pRay = (char*)self + 16;
        void* pVertBase = v5 + 8;
        void* pIndices = v5 + 6310 + k * 6;

        if (rayTriFn(pRay, pVertBase, pIndices, &hitT, 0, 0.0020000001f)) {
            if ((v145 & 0x20) != 0) {
                if (hitT >= 0.0f) {
                    float* hit76 = reinterpret_cast<float*>((char*)self + 76);
                    float* hit80 = reinterpret_cast<float*>((char*)self + 80);
                    if (hitT <= *hit76) {
                        *hit76 = hitT;
                        *reinterpret_cast<uint32_t*>((char*)self + 84) = v141;
                    }
                    if (hitT <= *hit80) {
                        *hit80 = hitT;
                        *reinterpret_cast<uint32_t*>((char*)self + 88) = v141;
                    }
                }
            } else if ((v145 & 8) != 0) {
                if (hitT >= 0.0f) {
                    float* hit76 = reinterpret_cast<float*>((char*)self + 76);
                    if (hitT <= *hit76) {
                        *hit76 = hitT;
                        *reinterpret_cast<uint32_t*>((char*)self + 84) = v141;
                    }
                }
            } else if ((v145 & 4) != 0 && hitT >= 0.0f) {
                float* hit80 = reinterpret_cast<float*>((char*)self + 80);
                if (hitT <= *hit80) {
                    *hit80 = hitT;
                    *reinterpret_cast<uint32_t*>((char*)self + 88) = v141;
                }
            }
        }
    }

    return 1;
}

char __fastcall Hooked_Sub7C6790(void* self, void* dummy_edx, int a2, float a3) {
    g_calls++;

    if (!Config::g_settings.OptCollisionBspRejectFast || g_retired) {
        return orig_Sub7C6790(self, dummy_edx, a2, a3);
    }

    if (g_verified < 1000) {
        // Dual-run verification mode
        char stateCopy[100];
        memcpy(stateCopy, (char*)self + 64, sizeof(stateCopy));
        uint32_t savedDword = *reinterpret_cast<uint32_t*>(0x00D2DBF8);

        char resFast = Fast_Sub7C6790(self, dummy_edx, a2, a3);
        char fastState[100];
        memcpy(fastState, (char*)self + 64, sizeof(fastState));
        uint32_t fastDword = *reinterpret_cast<uint32_t*>(0x00D2DBF8);

        // Restore and run original
        memcpy((char*)self + 64, stateCopy, sizeof(stateCopy));
        *reinterpret_cast<uint32_t*>(0x00D2DBF8) = savedDword;

        char resOrig = orig_Sub7C6790(self, dummy_edx, a2, a3);

        if (resFast != resOrig || fastDword != *reinterpret_cast<uint32_t*>(0x00D2DBF8) ||
            memcmp(fastState, (char*)self + 64, sizeof(fastState)) != 0) {
            Log("[CollisionBspRejectSSE2] Mismatch detected on call %llu! Retiring hook.", g_calls);
            g_retired = true;
            return resOrig;
        }

        g_verified++;
        return resOrig;
    }

    return Fast_Sub7C6790(self, dummy_edx, a2, a3);
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptCollisionBspRejectFast) return true;

    if (memcmp(reinterpret_cast<const void*>(kTarget), kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[CollisionBspRejectSSE2] Prologue mismatch at 0x%08X; hook aborted.", kTarget);
        return false;
    }

    MH_STATUS st = WineSafe_CreateHook(reinterpret_cast<void*>(kTarget),
                                       reinterpret_cast<void*>(&Hooked_Sub7C6790),
                                       reinterpret_cast<void**>(&orig_Sub7C6790));
    if (st != MH_OK) {
        Log("[CollisionBspRejectSSE2] WineSafe_CreateHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    st = WO_EnableHook(reinterpret_cast<void*>(kTarget));
    if (st != MH_OK) {
        Log("[CollisionBspRejectSSE2] WO_EnableHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    g_installed = true;
    Log("[CollisionBspRejectSSE2] Hook installed at 0x%08X.", kTarget);
    return true;
}

void Shutdown() {
    if (g_installed) {
        MH_DisableHook(reinterpret_cast<void*>(kTarget));
        g_installed = false;
    }
}

void LogStats() {
    if (!g_installed) return;
    Log("[CollisionBspRejectSSE2] Calls: %llu, Verified: %llu, VertsOutcoded: %llu, TrisCulled: %llu, Retired: %s",
        g_calls, g_verified, g_vertsOutcoded, g_trisCulled, g_retired ? "YES" : "NO");
}

} // namespace CollisionBspRejectSSE2

