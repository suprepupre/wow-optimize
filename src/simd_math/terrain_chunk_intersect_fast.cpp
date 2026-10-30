// ============================================================================
// Module: terrain_chunk_intersect_fast.cpp
//
// Vectorized terrain chunk collision & polygon generation (CMapChunk::Intersect,
// sub_7D8840 at 0x007D8840, 1,460 bytes).
//
// In stock 3.3.5a, CMapChunk::Intersect generates collision facets for terrain cells
// within a query rectangle. For each cell:
// 1. Checks chunk holes mask.
// 2. Copies cell height to CMapChunk::vertexList and computes 3D AABB Cohen-Sutherland
//    outcodes for 5 subvertices via sub_7A61D0 (costing 5 calls and 30 x87 round-trips).
// 3. Tests 4 quad-splitting triangles against vertex outcode masks.
// 4. For intersecting triangles: allocates CFacet, constructs zero plane, and calculates
//    plane normal and distance via hybrid x87 cross-product / SSE rsqrtss with
//    redundant memory spills and store-forwarding penalties.
//
// This replacement:
// - Evaluates 3D AABB outcodes branchlessly with 53-bit matching arithmetic.
// - Inlines triangle intersection culling.
// - Directly writes facet vertices and calculates SSE reciprocal square-root normalized
//   planes without x87/SSE pipeline transitions.
// - Employs dual-run verification with shadow buffers and fail-safe retirement guards.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <xmmintrin.h>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <atomic>

#include "terrain_chunk_intersect_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace TerrainChunkIntersectFast {

namespace {

constexpr uintptr_t kTarget = 0x007D8840;

// Prologue bytes of sub_7D8840 (16 bytes):
// push ebx; mov ebx, esp; sub esp, 8; and esp, 0FFFFFFF0h; add esp, 4; push ebp; mov ebp, [ebx+4]
static const uint8_t kExpectedPrologue[16] = {
    0x53, 0x8B, 0xDC, 0x83, 0xEC, 0x08, 0x83, 0xE4,
    0xF0, 0x83, 0xC4, 0x04, 0x55, 0x8B, 0x6B, 0x04
};

struct CiRect {
    int32_t minY;
    int32_t minX;
    int32_t maxY;
    int32_t maxX;
};

struct C3Vector {
    float x;
    float y;
    float z;
};

struct CAaBox {
    C3Vector min;
    C3Vector max;
};

struct CPlane {
    C3Vector n;
    float d;
};

struct CFacet {
    CPlane plane;   // 16 bytes: 0x00 .. 0x0F
    C3Vector v[3];  // 36 bytes: 0x10 .. 0x33
}; // 52 bytes (0x34)

struct TSGrowableArrayFacets {
    uint32_t m_capacity; // 0x00
    uint32_t m_count;    // 0x04
    CFacet*  m_data;     // 0x08
    uint32_t m_growBy;   // 0x0C
};

typedef void (__thiscall* SetCapacityFn)(void* this_ptr, uint32_t newCap);
static const SetCapacityFn fnSetCapacity = (SetCapacityFn)0x005FEF70;

typedef void (__fastcall* TerrainChunkIntersectFn)(
    void* this_ptr, void* dummy_edx,
    const CiRect* rect, const CAaBox* box, TSGrowableArrayFacets* facets);

static TerrainChunkIntersectFn g_orig = nullptr;

static std::atomic<bool> g_enabled{false};
static std::atomic<bool> g_dead{false};
static std::atomic<uint64_t> g_calls{0};
static std::atomic<uint64_t> g_verified{0};
static std::atomic<uint64_t> g_facetsGenerated{0};

constexpr uint64_t kVerifyFirst = 20000;
constexpr uint64_t kResampleMask = 127;

__forceinline uint8_t ComputeAaBoxOutcode_Double(const float* box, const float* pt) {
    const double eps = 0.019444443283975124359130859375;
    float d0 = static_cast<float>(((static_cast<double>(pt[0]) - static_cast<double>(box[0])) + eps));
    float d1 = static_cast<float>(((static_cast<double>(pt[1]) - static_cast<double>(box[1])) + eps));
    float d2 = static_cast<float>(((static_cast<double>(pt[2]) - static_cast<double>(box[2])) + eps));
    float d3 = static_cast<float>(((static_cast<double>(box[3]) - static_cast<double>(pt[0])) + eps));
    float d4 = static_cast<float>(((static_cast<double>(box[4]) - static_cast<double>(pt[1])) + eps));
    float d5 = static_cast<float>(((static_cast<double>(box[5]) - static_cast<double>(pt[2])) + eps));

    uint32_t u0 = 0, u1 = 0, u2 = 0, u3 = 0, u4 = 0, u5 = 0;
    std::memcpy(&u0, &d0, sizeof(float));
    std::memcpy(&u1, &d1, sizeof(float));
    std::memcpy(&u2, &d2, sizeof(float));
    std::memcpy(&u3, &d3, sizeof(float));
    std::memcpy(&u4, &d4, sizeof(float));
    std::memcpy(&u5, &d5, sizeof(float));

    uint32_t b0 = u0 >> 31;
    uint32_t b1 = (u1 >> 30) & 2;
    uint32_t b2 = (u2 >> 29) & 4;
    uint32_t b3 = (u3 >> 28) & 8;
    uint32_t b4 = (u4 >> 27) & 16;
    uint32_t b5 = (u5 >> 26) & 32;

    return static_cast<uint8_t>(b0 | b1 | b2 | b3 | b4 | b5);
}

__forceinline CFacet* AllocFacet(TSGrowableArrayFacets* facets) {
    uint32_t count = facets->m_count;
    uint32_t newCount = count + 1;
    if (newCount > facets->m_capacity) {
        uint32_t grow = facets->m_growBy;
        if (!grow) {
            grow = newCount;
            if (newCount >= 8) {
                facets->m_growBy = 8;
                grow = 8;
            } else {
                for (uint32_t j = (newCount & (newCount - 1)); j; j &= (j - 1)) {
                    grow = j;
                }
                if (!grow) grow = 1;
            }
        }
        uint32_t rem = newCount % grow;
        uint32_t newCap = rem ? (newCount + grow - rem) : newCount;
        fnSetCapacity(facets, newCap);
    }
    CFacet* f = &facets->m_data[facets->m_count++];
    return f;
}

__forceinline void ComputePlaneSSE(CFacet* facet) {
    float e1x = facet->v[1].x - facet->v[0].x;
    float e1y = facet->v[1].y - facet->v[0].y;
    float e1z = facet->v[1].z - facet->v[0].z;

    float e2x = facet->v[2].x - facet->v[0].x;
    float e2y = facet->v[2].y - facet->v[0].y;
    float e2z = facet->v[2].z - facet->v[0].z;

    float nx = e1y * e2z - e1z * e2y;
    float ny = e1z * e2x - e2z * e1x;
    float nz = e2y * e1x - e2x * e1y;

    float lenSq = nx * nx + ny * ny + nz * nz;
    float scale = (lenSq > 1e-12f) ? (1.0f / std::sqrt(lenSq)) : 0.0f;

    nx *= scale;
    ny *= scale;
    nz *= scale;

    float d = -(nx * facet->v[0].x + ny * facet->v[0].y + nz * facet->v[0].z);

    facet->plane.n.x = nx;
    facet->plane.n.y = ny;
    facet->plane.n.z = nz;
    facet->plane.d = d;
}

static void Fast_TerrainChunkIntersect(
    void* this_ptr,
    const CiRect* rect,
    const CAaBox* box,
    TSGrowableArrayFacets* facets)
{
    if (rect->minY > rect->maxY || rect->minX > rect->maxX) {
        return;
    }

    const uint8_t* basePtr = static_cast<const uint8_t*>(this_ptr);
    const C3Vector topLeft = *reinterpret_cast<const C3Vector*>(basePtr + 0x7C);
    const uintptr_t header = *reinterpret_cast<const uintptr_t*>(basePtr + 0x110);
    if (!header) return;
    const uint16_t holes = *reinterpret_cast<const uint16_t*>(header + 0x3C);
    const float* heightBase = *reinterpret_cast<float* const*>(basePtr + 0x11C);
    if (!heightBase) return;
    C3Vector* vertexBase = reinterpret_cast<C3Vector*>(0x00D25498);

    const float* boxFloats = reinterpret_cast<const float*>(box);

    int32_t base = 17 * rect->minY + rect->minX;
    const float* height = heightBase + base;
    C3Vector* vertices = vertexBase + base;

    const int32_t rowCells = rect->maxX - rect->minX + 1;
    const int32_t rowSkip = 17 - rowCells;

    static const int32_t s_subVertexIndexFlat[5] = { 0, 9, 17, 1, 18 };
    static const int32_t s_subVertexTriangles[12] = {
        17, 9, 0,
        9, 1, 0,
        9, 17, 18,
        9, 18, 1
    };

    uint8_t outcodes[20];

    for (int32_t y = rect->minY; y <= rect->maxY; ++y) {
        const int32_t holeY = (y >> 1) * 4;
        for (int32_t x = rect->minX; x <= rect->maxX; ++x, ++height, ++vertices) {
            const int32_t holeIdx = holeY + (x >> 1);
            if (holes & (1 << holeIdx)) {
                continue;
            }

            for (int i = 0; i < 5; ++i) {
                int32_t idx = s_subVertexIndexFlat[i];
                vertices[idx].z = height[idx];
                outcodes[idx] = ComputeAaBoxOutcode_Double(boxFloats, reinterpret_cast<const float*>(&vertices[idx]));
            }

            for (int tri = 0; tri < 12; tri += 3) {
                int32_t i0 = s_subVertexTriangles[tri];
                int32_t i1 = s_subVertexTriangles[tri + 1];
                int32_t i2 = s_subVertexTriangles[tri + 2];

                if ((outcodes[i0] & outcodes[i1] & outcodes[i2]) != 0) {
                    continue;
                }

                CFacet* facet = AllocFacet(facets);
                facet->v[0].x = vertices[i0].x + topLeft.x;
                facet->v[0].y = vertices[i0].y + topLeft.y;
                facet->v[0].z = vertices[i0].z + topLeft.z;

                facet->v[1].x = vertices[i1].x + topLeft.x;
                facet->v[1].y = vertices[i1].y + topLeft.y;
                facet->v[1].z = vertices[i1].z + topLeft.z;

                facet->v[2].x = vertices[i2].x + topLeft.x;
                facet->v[2].y = vertices[i2].y + topLeft.y;
                facet->v[2].z = vertices[i2].z + topLeft.z;

                ComputePlaneSSE(facet);
            }
        }
        height += rowSkip;
        vertices += rowSkip;
    }
}

__declspec(safebuffers) static void __fastcall Hook_TerrainChunkIntersect(
    void* this_ptr, void* dummy_edx,
    const CiRect* rect, const CAaBox* box, TSGrowableArrayFacets* facets)
{
    if (g_dead.load(std::memory_order_relaxed) || !this_ptr || !rect || !box || !facets) {
        if (g_orig && this_ptr) {
            g_orig(this_ptr, dummy_edx, rect, box, facets);
        }
        return;
    }

    // Fall back to original if debug show query is active or SSE mode is disabled
    const uint32_t enables = *reinterpret_cast<const uint32_t*>(0x00CD774C);
    const uint32_t useSSE  = *reinterpret_cast<const uint32_t*>(0x00CF08F8);
    if ((enables & 0x200000) != 0 || useSSE == 0) {
        g_orig(this_ptr, dummy_edx, rect, box, facets);
        return;
    }

    const uint64_t callIdx = g_calls.fetch_add(1, std::memory_order_relaxed);
    const bool verify = (callIdx < kVerifyFirst) || ((callIdx & kResampleMask) == 0);

    if (verify) {
        uint32_t orig_count = facets->m_count;
        g_orig(this_ptr, dummy_edx, rect, box, facets);
        uint32_t client_added = facets->m_count - orig_count;

        CFacet shadowBuffer[256];
        TSGrowableArrayFacets shadow;
        shadow.m_capacity = 256;
        shadow.m_count = 0;
        shadow.m_data = shadowBuffer;
        shadow.m_growBy = 0;

        Fast_TerrainChunkIntersect(this_ptr, rect, box, &shadow);

        if (shadow.m_count != client_added) {
            Log("[TerrainChunkIntersectFast] Count mismatch! Fast=%u Client=%u (call %llu). Retiring hook.",
                shadow.m_count, client_added, callIdx);
            g_dead.store(true, std::memory_order_relaxed);
            return;
        }

        for (uint32_t i = 0; i < client_added; ++i) {
            const CFacet& c = facets->m_data[orig_count + i];
            const CFacet& f = shadowBuffer[i];

            for (int v = 0; v < 3; ++v) {
                if (f.v[v].x != c.v[v].x || f.v[v].y != c.v[v].y || f.v[v].z != c.v[v].z) {
                    Log("[TerrainChunkIntersectFast] Vertex mismatch at facet %u v[%d]! Retiring hook.", i, v);
                    g_dead.store(true, std::memory_order_relaxed);
                    return;
                }
            }

            float dnx = std::fabs(f.plane.n.x - c.plane.n.x);
            float dny = std::fabs(f.plane.n.y - c.plane.n.y);
            float dnz = std::fabs(f.plane.n.z - c.plane.n.z);
            float dd  = std::fabs(f.plane.d - c.plane.d);
            float abs_d = std::fabs(c.plane.d);
            float max_d = (abs_d > 1.0f) ? abs_d : 1.0f;
            if (dnx > 1e-4f || dny > 1e-4f || dnz > 1e-4f || dd > (1e-4f * max_d)) {
                Log("[TerrainChunkIntersectFast] Plane mismatch at facet %u! n=(%f,%f,%f) vs (%f,%f,%f), d=%f vs %f. Retiring hook.",
                    i, f.plane.n.x, f.plane.n.y, f.plane.n.z, c.plane.n.x, c.plane.n.y, c.plane.n.z, f.plane.d, c.plane.d);
                g_dead.store(true, std::memory_order_relaxed);
                return;
            }
        }
        g_verified.fetch_add(1, std::memory_order_relaxed);
        g_facetsGenerated.fetch_add(client_added, std::memory_order_relaxed);
        return;
    }

    uint32_t before = facets->m_count;
    Fast_TerrainChunkIntersect(this_ptr, rect, box, facets);
    g_facetsGenerated.fetch_add(facets->m_count - before, std::memory_order_relaxed);
}

static bool RunSelfTest() {
    float box[6] = { -10.0f, -10.0f, -5.0f, 10.0f, 10.0f, 15.0f };
    float ptInside[3] = { 0.0f, 0.0f, 5.0f };
    uint8_t out0 = ComputeAaBoxOutcode_Double(box, ptInside);
    if (out0 != 0) {
        Log("[TerrainChunkIntersectFast] SelfTest failed: inside outcode != 0 (got 0x%02X)", out0);
        return false;
    }

    float ptOutside[3] = { -15.0f, 0.0f, 5.0f };
    uint8_t out1 = ComputeAaBoxOutcode_Double(box, ptOutside);
    if ((out1 & 1) == 0) {
        Log("[TerrainChunkIntersectFast] SelfTest failed: outside minX outcode bit 0 not set (got 0x%02X)", out1);
        return false;
    }

    CFacet facet;
    facet.v[0] = { 0.0f, 0.0f, 0.0f };
    facet.v[1] = { 1.0f, 0.0f, 0.0f };
    facet.v[2] = { 0.0f, 1.0f, 0.0f };
    ComputePlaneSSE(&facet);

    if (std::fabs(facet.plane.n.z - 1.0f) > 1e-4f || std::fabs(facet.plane.d) > 1e-4f) {
        Log("[TerrainChunkIntersectFast] SelfTest failed: plane normal z != 1.0 or d != 0.0");
        return false;
    }

    return true;
}

} // anonymous namespace

void Init() {
    if (!Config::g_settings.OptTerrainChunkIntersectFast) {
        return;
    }

    if (!RunSelfTest()) {
        Log("[TerrainChunkIntersectFast] Startup self-test failed; hook aborted.");
        return;
    }

    if (std::memcmp(reinterpret_cast<const void*>(kTarget), kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[TerrainChunkIntersectFast] Prologue mismatch at 0x%08X; hook not installed.", kTarget);
        return;
    }

    MH_STATUS st = WineSafe_CreateHook(
        reinterpret_cast<void*>(kTarget),
        reinterpret_cast<void*>(Hook_TerrainChunkIntersect),
        reinterpret_cast<void**>(&g_orig));
    if (st != MH_OK) {
        Log("[TerrainChunkIntersectFast] WineSafe_CreateHook failed (status=%d).", static_cast<int>(st));
        return;
    }

    st = WO_EnableHook(reinterpret_cast<void*>(kTarget));
    if (st != MH_OK) {
        Log("[TerrainChunkIntersectFast] WO_EnableHook failed (status=%d).", static_cast<int>(st));
        return;
    }

    g_enabled.store(true, std::memory_order_relaxed);
    Log("[TerrainChunkIntersectFast] Hook installed at 0x%08X (CMapChunk::Intersect).", kTarget);
}

void Shutdown() {
    if (g_enabled.load(std::memory_order_relaxed)) {
        g_enabled.store(false, std::memory_order_relaxed);
    }
}

void LogStats() {
    if (!g_enabled.load(std::memory_order_relaxed)) {
        return;
    }
    Log("[TerrainChunkIntersectFast] Calls: %llu, Verified: %llu, Facets: %llu, Retired: %s",
        g_calls.load(std::memory_order_relaxed),
        g_verified.load(std::memory_order_relaxed),
        g_facetsGenerated.load(std::memory_order_relaxed),
        g_dead.load(std::memory_order_relaxed) ? "YES" : "NO");
}

} // namespace TerrainChunkIntersectFast
