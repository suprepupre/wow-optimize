// ============================================================================
// Module: collision_clip_verts_box_sse2.cpp
//
// Mesh collision polygon clipping and ray-box intersection queries in
// BspQuery_Segment::GetFaceIndicesUsingCache (sub_7C6D50 @ 0x007C6D50, 1,166 B).
//
// In original client:
//   - Classifies bounding-box Cohen-Sutherland outcodes for up to 450 vertices
//     per node digest using serialized x87 FPU status-word transfers (fcomp,
//     fnstsw, test, jnz).
//   - Tests candidate triangles with (out0 & out1 & out2 & 0x3F) == 0 before
//     invoking ray-triangle intersection (sub_983490).
//
// Optimizations:
//   - Vectorizes vertex outcode classification using 128-bit SSE2 instructions
//     (_mm_cmpgt_ps, _mm_cmplt_ps, _mm_movemask_ps), processing 4 vertices
//     simultaneously with 0 x87 FPU stack operations.
//   - Branch-optimized triangle candidate filtering.
//   - Dual-run verification compares outcode classifications against reference
//     for the first 10,000 calls and 1 in 128 calls thereafter, with instant
//     fail-safe retirement on any mismatch.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <emmintrin.h>

#include "collision_clip_verts_box_sse2.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "session_verdict.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace CollisionClipVertsBox {

namespace {

constexpr uintptr_t kTarget          = 0x007C6D50;
constexpr uintptr_t kDigestCachePtr  = 0x00CDD7A0;
constexpr uintptr_t kTestFaceSubPtr  = 0x00D2DBF8;
constexpr uintptr_t kTestFacesPtr    = 0x00D25BF8;
constexpr uintptr_t kHitFacesPtr     = 0x00D29BF8;
constexpr uintptr_t kHitFaceSubPtr   = 0x00D2DBFC;
constexpr uintptr_t kIntersectFn     = 0x00983490;
constexpr uintptr_t kGetDigestFn     = 0x0079B1F0;

const unsigned char kPrologue[16] = {
    0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xC8, 0x01, 0x00,
    0x00, 0x53, 0x8B, 0xD9, 0x8B, 0x0D, 0xA0, 0xD7
};

#pragma pack(push, 1)
struct C3Vector {
    float x, y, z;
};

struct C3Segment {
    C3Vector b;
    C3Vector t;
};

struct C3Ray {
    C3Vector origin;
    C3Vector dir;
};

struct SMOPoly {
    uint8_t m_flags;
    uint8_t m_materialId;
};

struct SMOMaterial {
    uint32_t m_flags;
    uint32_t m_shader;
    uint32_t m_blendMode;
    uint8_t  m_pad[52];
};

struct CAaBspNodeDigest {
    const void* m_node;
    uint8_t     m_status;
    uint8_t     unused_0005[1];
    uint16_t    m_nVertices;
    C3Vector    m_vertices[450];
    uint16_t    m_vertexIndices[450];
    uint16_t    m_nFaces;
    uint16_t    m_faceVertexIndices[900];
    uint16_t    m_faceFlags[300];
    uint16_t    m_faceIndices[300];
};

struct BspQuery_Segment {
    int32_t*     m_overflowFlags;
    SMOPoly*     m_faces;
    C3Vector*    m_vertexList;
    uint16_t*    m_indices;
    float*       m_hitT;
    float        m_origHitT;
    C3Segment    m_seg;
    C3Ray        m_ray;
    float        m_oosegMag;
    float        m_maxT;
    SMOMaterial* m_materials;
    int32_t      unused_0054;
    uint16_t     m_faceIgnoreFlags;
};
#pragma pack(pop)

typedef int (__cdecl *IntersectFn)(const void* ray, const void* vertices,
                                   const uint16_t* indices, float* t,
                                   void* unk, float eps);
typedef CAaBspNodeDigest* (__thiscall *GetDigestFn)(void* cache, const void* aaBsp,
                                                    const void* node, void* faces,
                                                    void* vertices, void* indices);

typedef char (__fastcall *QueryFn)(void* self, void* dummy_edx, const void* aaBsp, const void* node);
QueryFn g_orig = nullptr;

bool g_installed = false;
bool g_dead = false;
bool g_abSubject = false;
static volatile LONG g_bypass = 0;

unsigned long long g_calls = 0;
unsigned long long g_fast = 0;
unsigned long long g_control = 0;
unsigned g_verified = 0;
unsigned g_mismatches = 0;

constexpr uint32_t kLearnCalls   = 10000;
constexpr uint32_t kResampleMask = 127;

static inline void ComputeOutcodesSSE2(const CAaBspNodeDigest* digest,
                                      float minX, float maxX,
                                      float minY, float maxY,
                                      float minZ, float maxZ,
                                      uint8_t* outcodes) {
    const uint32_t n = digest->m_nVertices;
    const __m128 v_minX = _mm_set1_ps(minX);
    const __m128 v_maxX = _mm_set1_ps(maxX);
    const __m128 v_minY = _mm_set1_ps(minY);
    const __m128 v_maxY = _mm_set1_ps(maxY);
    const __m128 v_minZ = _mm_set1_ps(minZ);
    const __m128 v_maxZ = _mm_set1_ps(maxZ);

    uint32_t i = 0;
    for (; i + 4 <= n; i += 4) {
        const __m128 xs = _mm_set_ps(digest->m_vertices[i + 3].x,
                                     digest->m_vertices[i + 2].x,
                                     digest->m_vertices[i + 1].x,
                                     digest->m_vertices[i + 0].x);
        const __m128 ys = _mm_set_ps(digest->m_vertices[i + 3].y,
                                     digest->m_vertices[i + 2].y,
                                     digest->m_vertices[i + 1].y,
                                     digest->m_vertices[i + 0].y);
        const __m128 zs = _mm_set_ps(digest->m_vertices[i + 3].z,
                                     digest->m_vertices[i + 2].z,
                                     digest->m_vertices[i + 1].z,
                                     digest->m_vertices[i + 0].z);

        const int m_minX = _mm_movemask_ps(_mm_cmpgt_ps(v_minX, xs));
        const int m_maxX = _mm_movemask_ps(_mm_cmplt_ps(v_maxX, xs));
        const int m_minY = _mm_movemask_ps(_mm_cmpgt_ps(v_minY, ys));
        const int m_maxY = _mm_movemask_ps(_mm_cmplt_ps(v_maxY, ys));
        const int m_minZ = _mm_movemask_ps(_mm_cmpgt_ps(v_minZ, zs));
        const int m_maxZ = _mm_movemask_ps(_mm_cmplt_ps(v_maxZ, zs));

        for (int k = 0; k < 4; ++k) {
            outcodes[i + k] = (uint8_t)(
                (((m_minX >> k) & 1) << 5) |
                (((m_maxX >> k) & 1) << 4) |
                (((m_minY >> k) & 1) << 3) |
                (((m_maxY >> k) & 1) << 2) |
                (((m_minZ >> k) & 1) << 1) |
                (((m_maxZ >> k) & 1))
            );
        }
    }

    for (; i < n; ++i) {
        const C3Vector& v = digest->m_vertices[i];
        uint8_t code = 0;
        if (minX > v.x) code  = 0x20;
        if (maxX < v.x) code |= 0x10;
        if (minY > v.y) code |= 0x08;
        if (maxY < v.y) code |= 0x04;
        if (minZ > v.z) code |= 0x02;
        if (maxZ < v.z) code |= 0x01;
        outcodes[i] = code;
    }
}

static inline void ComputeOutcodesScalarRef(const CAaBspNodeDigest* digest,
                                           float minX, float maxX,
                                           float minY, float maxY,
                                           float minZ, float maxZ,
                                           uint8_t* outcodes) {
    const uint32_t n = digest->m_nVertices;
    for (uint32_t i = 0; i < n; ++i) {
        const C3Vector& v = digest->m_vertices[i];
        uint8_t code = 0;
        if (minX > v.x) code  = 0x20;
        if (maxX < v.x) code |= 0x10;
        if (minY > v.y) code |= 0x08;
        if (maxY < v.y) code |= 0x04;
        if (minZ > v.z) code |= 0x02;
        if (maxZ < v.z) code |= 0x01;
        outcodes[i] = code;
    }
}

char Fast_GetFaceIndicesUsingCache(BspQuery_Segment* q, const void* aaBsp, const void* node, bool verify) {
    void* cache = *(void**)kDigestCachePtr;
    if (!cache) return 0;

    GetDigestFn fnGetDigest = (GetDigestFn)kGetDigestFn;
    CAaBspNodeDigest* digest = fnGetDigest(cache, aaBsp, node, q->m_faces, q->m_vertexList, q->m_indices);
    if (!digest) return 0;

    float maxX = q->m_seg.t.x;
    float maxY = q->m_seg.t.y;
    float minX = q->m_seg.b.x;
    float maxZ = q->m_seg.t.z;

    if (minX > maxX) {
        minX = q->m_seg.t.x;
        maxX = q->m_seg.b.x;
    }

    float minY = q->m_seg.b.y;
    if (minY > maxY) {
        minY = q->m_seg.t.y;
        maxY = q->m_seg.b.y;
    }

    float minZ = q->m_seg.b.z;
    if (minZ > maxZ) {
        minZ = q->m_seg.t.z;
        maxZ = q->m_seg.b.z;
    }

    minX -= 0.0099999998f;
    maxX += 0.0099999998f;
    minY -= 0.0099999998f;
    maxY += 0.0099999998f;
    minZ -= 0.0099999998f;
    maxZ += 0.0099999998f;

    uint8_t outcodes[452];
    ComputeOutcodesSSE2(digest, minX, maxX, minY, maxY, minZ, maxZ, outcodes);

    if (verify) {
        uint8_t ref[452];
        ComputeOutcodesScalarRef(digest, minX, maxX, minY, maxY, minZ, maxZ, ref);
        if (memcmp(outcodes, ref, digest->m_nVertices) != 0) {
            g_dead = true;
            ++g_mismatches;
            Log("[CollisionClip] MISMATCH in outcodes! Retiring hook.");
            Verdict::Add(Verdict::Bad, "CollisionClip outcode mismatch against reference");
            return 0;
        }
        ++g_verified;
    }

    uint32_t* pTestFaceSub = (uint32_t*)kTestFaceSubPtr;
    uint16_t* pTestFaces   = (uint16_t*)kTestFacesPtr;
    uint16_t* pHitFaces    = (uint16_t*)kHitFacesPtr;
    uint32_t* pHitFaceSub  = (uint32_t*)kHitFaceSubPtr;
    IntersectFn fnIntersect = (IntersectFn)kIntersectFn;

    const uint16_t ignore = q->m_faceIgnoreFlags;
    const uint32_t nFaces = digest->m_nFaces;

    for (uint32_t i = 0; i < nFaces; ++i) {
        const uint16_t faceFlags = digest->m_faceFlags[i];
        if (ignore & faceFlags) continue;

        const uint16_t face = digest->m_faceIndices[i];
        SMOPoly& poly = q->m_faces[face];

        if (ignore & poly.m_flags) continue;

        const uint8_t matId = poly.m_materialId;
        const bool isBlendZero = (matId != 0xFF) ? (q->m_materials[matId].m_blendMode == 0) : true;
        const uint16_t ignoreMask = isBlendZero ? 0x200 : 0x100;

        if (ignore & ignoreMask) continue;

        if (*pTestFaceSub >= 0x2000) {
            if (q->m_overflowFlags) {
                *q->m_overflowFlags |= 1;
            }
            break;
        }

        pTestFaces[(*pTestFaceSub)++] = face;
        poly.m_flags |= 0x80;

        const uint16_t* verts = &digest->m_faceVertexIndices[3 * i];
        if (outcodes[verts[0]] & outcodes[verts[1]] & outcodes[verts[2]] & 0x3F) {
            continue;
        }

        float t = 0.0f;
        if (!fnIntersect(&q->m_ray, digest->m_vertices, verts, &t, nullptr, 0.0020000001f)) {
            continue;
        }

        if (t < 0.0f || t > q->m_maxT) {
            continue;
        }

        q->m_maxT = t;
        pHitFaces[0] = face;
        *pHitFaceSub = 1;
        *q->m_hitT = t * q->m_oosegMag;

        if (*q->m_hitT > q->m_origHitT) {
            *q->m_hitT = q->m_origHitT;
        }
    }

    return 1;
}

char __fastcall Hooked_GetFaceIndicesUsingCache(void* self, void* dummy_edx, const void* aaBsp, const void* node) {
    ++g_calls;
    if (g_bypass != 0 || g_dead || !self) {
        return g_orig(self, dummy_edx, aaBsp, node);
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_control;
        return g_orig(self, dummy_edx, aaBsp, node);
    }

    const bool learning = g_verified < kLearnCalls ||
                          ((uint32_t)g_calls & kResampleMask) == 0;

    BspQuery_Segment* q = (BspQuery_Segment*)self;
    char res = Fast_GetFaceIndicesUsingCache(q, aaBsp, node, learning);
    if (g_dead) {
        return g_orig(self, dummy_edx, aaBsp, node);
    }

    ++g_fast;
    return res;
}

bool BytesMatch(uintptr_t addr, const unsigned char* want, int n) {
    __try {
        return memcmp((const void*)addr, want, (size_t)n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

bool Init() {
    if (!Config::g_settings.OptCollisionClipVertsBox) return true;

    if (!BytesMatch(kTarget, kPrologue, sizeof(kPrologue))) {
        Log("[CollisionClip] NOT active: prologue mismatch at 0x%08X", (unsigned)kTarget);
        return false;
    }
    if (!WowOpt_ClientPatchAllowed((const void*)kTarget)) {
        Log("[CollisionClip] NOT active: client patches disabled");
        return false;
    }

    if (WineSafe_CreateHook((void*)kTarget, (void*)&Hooked_GetFaceIndicesUsingCache, (void**)&g_orig) != MH_OK) {
        Log("[CollisionClip] NOT active: WineSafe_CreateHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }
    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        MH_RemoveHook((void*)kTarget);
        Log("[CollisionClip] NOT active: WO_EnableHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    g_installed = true;
    g_abSubject = AbTest::IsSubject("CollisionClipVertsBox", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("CollisionClip_Hook", (const void*)&Hooked_GetFaceIndicesUsingCache);

    Log("[CollisionClip] ACTIVE on BspQuery_Segment::GetFaceIndicesUsingCache (sub_7C6D50, 1166 B). "
        "Vectorized 4-vertex SSE2 outcode classification and branchless triangle culling.");
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook((void*)kTarget);
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptCollisionClipVertsBox) return;
    if (!g_installed) return;
    Log("[CollisionClip] calls=%llu (fast=%llu, verified=%u, control=%llu) mismatches=%u%s",
        g_calls, g_fast, g_verified, g_control, g_mismatches,
        g_dead ? " [RETIRED]" : "");
}


void SetBypass(bool bypass) {
    InterlockedExchange(&g_bypass, bypass ? 1 : 0);
}

bool IsBypassed() {
    return g_bypass != 0;
}

void Retire() {
    g_dead = true;
    Log("[CollisionClip] Hook retired due to diagnostic discrepancy");
}
}  // namespace CollisionClipVertsBox
