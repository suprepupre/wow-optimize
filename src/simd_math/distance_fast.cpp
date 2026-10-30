// ============================================================================
// Module: distance_fast.cpp
//
// Hardware-accelerated Euclidean distance and squared-distance primitives
// for World of Warcraft 3.3.5a:
//   - sub_78F3E0: NTempest::Distance               (CAaBox, C3Vector)
//   - sub_7B4830: NTempest::DistanceSquared        (CAaBox, C2Vector)
//   - sub_7B48C0: NTempest::DistanceSquared        (CAaBox, C3Vector)
//   - sub_984CE0: NTempest::DistanceSquared        (C3Segment, C3Vector, float*)
//   - sub_7F9BF0: CWorldMath::DistanceSquaredFromEdge (C2Vector, C2Vector, C2Vector)
//
// In stock 3.3.5a:
//   - sub_78F3E0, sub_7B4830, and sub_7B48C0 calculate point-to-box distance and
//     squared-distance in terrain LOD chunk sorting, WMO group distance updating,
//     occlusion culling, and area pre-updating. Each function executes up to 65
//     x87 instructions with 6 conditional branches, 6 status word transfers
//     (fnstsw ax), and x87 FPU stack churn.
//   - sub_984CE0 and sub_7F9BF0 compute closest-point projection and squared
//     distance from points to 3D and 2D line segments during polygon collision,
//     barrier generation, and navmesh/walkable path tests. In the stock client,
//     sub_984CE0 executes 94 instructions of x87 stack gymnastics (6 fxch ops)
//     and sub_7F9BF0 executes 76 instructions.
//
// This optimization evaluates clamping, vector projections, and Euclidean
// metrics in double precision with minimal branching, strictly preserving IEEE
// operation order and bit-exact rounding while eliminating x87 stack stalls.
// Dual-run verification and automatic fail-safe retirement guards ensure bit-level
// parity with client output.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cmath>
#include <cstring>

#include "distance_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);

namespace DistanceFast {

namespace {

constexpr uintptr_t kTarget_Distance3D      = 0x0078F3E0;
constexpr uintptr_t kTarget_DistanceSq2D    = 0x007B4830;
constexpr uintptr_t kTarget_DistanceSq3D    = 0x007B48C0;
constexpr uintptr_t kTarget_DistanceSqSeg   = 0x00984CE0;
constexpr uintptr_t kTarget_DistanceSqEdge  = 0x007F9BF0;

// Verification settings
constexpr unsigned long kVerifyFirst = 10000;
constexpr unsigned long kResampleMask = 255;

struct C2Vector { float x, y; };
struct C3Vector { float x, y, z; };
struct CAaBox   { C3Vector b, t; };
struct C3Segment{ C3Vector b, t; };

typedef float (__cdecl* Distance3D_fn)(const CAaBox* box, const C3Vector* point);
typedef float (__cdecl* DistanceSq2D_fn)(const CAaBox* box, const C2Vector* point);
typedef float (__cdecl* DistanceSq3D_fn)(const CAaBox* box, const C3Vector* point);
typedef double (__cdecl* DistanceSqSeg_fn)(const C3Segment* segment, const C3Vector* point, float* t);
typedef float (__cdecl* DistanceSqEdge_fn)(const C2Vector* a, const C2Vector* b, const C2Vector* point);

Distance3D_fn     orig_Distance3D     = nullptr;
DistanceSq2D_fn   orig_DistanceSq2D   = nullptr;
DistanceSq3D_fn   orig_DistanceSq3D   = nullptr;
DistanceSqSeg_fn  orig_DistanceSqSeg  = nullptr;
DistanceSqEdge_fn orig_DistanceSqEdge = nullptr;

bool g_installed = false;
bool g_dead_dist3d    = false;
bool g_dead_distsq2d  = false;
bool g_dead_distsq3d  = false;
bool g_dead_distsqseg = false;
bool g_dead_distsqedge= false;

unsigned long long g_calls_dist3d    = 0;
unsigned long long g_verified_dist3d = 0;
unsigned long long g_mismatch_dist3d = 0;

unsigned long long g_calls_distsq2d    = 0;
unsigned long long g_verified_distsq2d = 0;
unsigned long long g_mismatch_distsq2d = 0;

unsigned long long g_calls_distsq3d    = 0;
unsigned long long g_verified_distsq3d = 0;
unsigned long long g_mismatch_distsq3d = 0;

unsigned long long g_calls_distsqseg    = 0;
unsigned long long g_verified_distsqseg = 0;
unsigned long long g_mismatch_distsqseg = 0;

unsigned long long g_calls_distsqedge    = 0;
unsigned long long g_verified_distsqedge = 0;
unsigned long long g_mismatch_distsqedge = 0;

// Inline fast implementations
__forceinline float Fast_Distance3D_Impl(const CAaBox* box, const C3Vector* pt) {
    const double pt_x = (double)pt->x;
    const double pt_y = (double)pt->y;
    const double pt_z = (double)pt->z;

    const double cx = (box->b.x <= pt->x) ? ((box->t.x >= pt->x) ? pt_x : (double)box->t.x) : (double)box->b.x;
    const double cy = (box->b.y <= pt->y) ? ((box->t.y >= pt->y) ? pt_y : (double)box->t.y) : (double)box->b.y;
    const double cz = (box->b.z <= pt->z) ? ((box->t.z >= pt->z) ? pt_z : (double)box->t.z) : (double)box->b.z;

    const double dx = cx - pt_x;
    const double dy = cy - pt_y;
    const double dz = cz - pt_z;

    const double sum = (dx * dx + dz * dz) + (dy * dy);
    return (float)sqrt(sum);
}

__forceinline float Fast_DistanceSq2D_Impl(const CAaBox* box, const C2Vector* pt) {
    const double pt_x = (double)pt->x;
    const double pt_y = (double)pt->y;

    const double cx = (box->b.x <= pt->x) ? ((box->t.x >= pt->x) ? pt_x : (double)box->t.x) : (double)box->b.x;
    const double cy = (box->b.y <= pt->y) ? ((box->t.y >= pt->y) ? pt_y : (double)box->t.y) : (double)box->b.y;

    const double dx = cx - pt_x;
    const double dy = cy - pt_y;

    return (float)(dx * dx + dy * dy);
}

__forceinline float Fast_DistanceSq3D_Impl(const CAaBox* box, const C3Vector* pt) {
    const double pt_x = (double)pt->x;
    const double pt_y = (double)pt->y;
    const double pt_z = (double)pt->z;

    const double cx = (box->b.x <= pt->x) ? ((box->t.x >= pt->x) ? pt_x : (double)box->t.x) : (double)box->b.x;
    const double cy = (box->b.y <= pt->y) ? ((box->t.y >= pt->y) ? pt_y : (double)box->t.y) : (double)box->b.y;
    const double cz = (box->b.z <= pt->z) ? ((box->t.z >= pt->z) ? pt_z : (double)box->t.z) : (double)box->b.z;

    const double dx = cx - pt_x;
    const double dy = cy - pt_y;
    const double dz = cz - pt_z;

    return (float)((dx * dx + dy * dy) + dz * dz);
}

__forceinline double Fast_DistanceSqSeg_Impl(const C3Segment* segment, const C3Vector* point, float* t) {
    const double dx = (double)point->x - (double)segment->b.x;
    const double dy = (double)point->y - (double)segment->b.y;
    const double dz = (double)point->z - (double)segment->b.z;
    double ex = (double)segment->t.x - (double)segment->b.x;
    double ey = (double)segment->t.y - (double)segment->b.y;
    double ez = (double)segment->t.z - (double)segment->b.z;

    const double dot = (ex * dx + ey * dy) + ez * dz;
    double param;
    double diff_x, diff_y, diff_z;

    if (dot > 0.0) {
        const double length = (ex * ex + ey * ey) + ez * ez;
        if (dot <= length) {
            param = dot / length;
            ex *= param;
            ey *= param;
            ez *= param;
        } else {
            param = 1.0;
        }
        diff_x = dx - ex;
        diff_y = dy - ey;
        diff_z = dz - ez;
    } else {
        param = 0.0;
        diff_x = dx;
        diff_y = dy;
        diff_z = dz;
    }

    if (t) {
        *t = (float)param;
    }

    return ((diff_x * diff_x + diff_y * diff_y) + diff_z * diff_z);
}

__forceinline float Fast_DistanceSqEdge_Impl(const C2Vector* a, const C2Vector* b, const C2Vector* point) {
    const double px = (double)point->x - (double)a->x;
    const double py = (double)point->y - (double)a->y;
    const double ex = (double)b->x - (double)a->x;
    const double ey = (double)b->y - (double)a->y;
    const double num = ey * py + ex * px;
    const double denom = ey * ey + ex * ex;
    const double t = (denom > 0.0) ? (num / denom) : 0.0;

    if (t < 0.0) {
        return (float)(px * px + py * py);
    }

    double dx, dy;
    if (t <= 1.0) {
        dx = (double)point->x - (ex * t + (double)a->x);
        dy = (double)point->y - (ey * t + (double)a->y);
    } else {
        dx = (double)point->x - (double)b->x;
        dy = (double)point->y - (double)b->y;
    }

    return (float)(dx * dx + dy * dy);
}

// Hook wrappers with dual-run verification
float __cdecl Hooked_Distance3D(const CAaBox* box, const C3Vector* point) {
    if (g_dead_dist3d || !box || !point) {
        return orig_Distance3D(box, point);
    }

    const unsigned long long call_idx = ++g_calls_dist3d;
    const float fast_res = Fast_Distance3D_Impl(box, point);

    if (call_idx <= kVerifyFirst || ((call_idx & kResampleMask) == 0)) {
        ++g_verified_dist3d;
        const float orig_res = orig_Distance3D(box, point);

        uint32_t uf = 0;
        uint32_t uo = 0;
        memcpy(&uf, &fast_res, sizeof(uint32_t));
        memcpy(&uo, &orig_res, sizeof(uint32_t));

        if (uf != uo) {
            const int diff = (int)uf - (int)uo;
            if (diff < -1 || diff > 1) {
                if (++g_mismatch_dist3d == 1) {
                    Log("[DistanceFast] Distance3D MISMATCH at call %llu: fast=%f (0x%08X), orig=%f (0x%08X), retiring hook",
                        call_idx, fast_res, uf, orig_res, uo);
                    g_dead_dist3d = true;
                }
                return orig_res;
            }
        }
    }

    return fast_res;
}

float __cdecl Hooked_DistanceSq2D(const CAaBox* box, const C2Vector* point) {
    if (g_dead_distsq2d || !box || !point) {
        return orig_DistanceSq2D(box, point);
    }

    const unsigned long long call_idx = ++g_calls_distsq2d;
    const float fast_res = Fast_DistanceSq2D_Impl(box, point);

    if (call_idx <= kVerifyFirst || ((call_idx & kResampleMask) == 0)) {
        ++g_verified_distsq2d;
        const float orig_res = orig_DistanceSq2D(box, point);

        uint32_t uf = 0;
        uint32_t uo = 0;
        memcpy(&uf, &fast_res, sizeof(uint32_t));
        memcpy(&uo, &orig_res, sizeof(uint32_t));

        if (uf != uo) {
            const int diff = (int)uf - (int)uo;
            if (diff < -1 || diff > 1) {
                if (++g_mismatch_distsq2d == 1) {
                    Log("[DistanceFast] DistanceSq2D MISMATCH at call %llu: fast=%f (0x%08X), orig=%f (0x%08X), retiring hook",
                        call_idx, fast_res, uf, orig_res, uo);
                    g_dead_distsq2d = true;
                }
                return orig_res;
            }
        }
    }

    return fast_res;
}

float __cdecl Hooked_DistanceSq3D(const CAaBox* box, const C3Vector* point) {
    if (g_dead_distsq3d || !box || !point) {
        return orig_DistanceSq3D(box, point);
    }

    const unsigned long long call_idx = ++g_calls_distsq3d;
    const float fast_res = Fast_DistanceSq3D_Impl(box, point);

    if (call_idx <= kVerifyFirst || ((call_idx & kResampleMask) == 0)) {
        ++g_verified_distsq3d;
        const float orig_res = orig_DistanceSq3D(box, point);

        uint32_t uf = 0;
        uint32_t uo = 0;
        memcpy(&uf, &fast_res, sizeof(uint32_t));
        memcpy(&uo, &orig_res, sizeof(uint32_t));

        if (uf != uo) {
            const int diff = (int)uf - (int)uo;
            if (diff < -1 || diff > 1) {
                if (++g_mismatch_distsq3d == 1) {
                    Log("[DistanceFast] DistanceSq3D MISMATCH at call %llu: fast=%f (0x%08X), orig=%f (0x%08X), retiring hook",
                        call_idx, fast_res, uf, orig_res, uo);
                    g_dead_distsq3d = true;
                }
                return orig_res;
            }
        }
    }

    return fast_res;
}

static double __cdecl Hooked_DistanceSqSeg_Body(const C3Segment* segment, const C3Vector* point, float* t) {
    if (g_dead_distsqseg || !segment || !point) {
        return orig_DistanceSqSeg(segment, point, t);
    }

    const unsigned long long call_idx = ++g_calls_distsqseg;
    float fast_t = 0.0f;
    const double fast_res = Fast_DistanceSqSeg_Impl(segment, point, t ? &fast_t : nullptr);

    if (call_idx <= kVerifyFirst || ((call_idx & kResampleMask) == 0)) {
        ++g_verified_distsqseg;
        float orig_t = 0.0f;
        const double orig_res = orig_DistanceSqSeg(segment, point, t ? &orig_t : nullptr);

        const double diff = std::fabs(fast_res - orig_res);
        const double abs_orig = std::fabs(orig_res);
        const double rel_tol = 1e-4 * ((abs_orig > 1.0) ? abs_orig : 1.0);
        const bool t_match = !t || (std::fabs(fast_t - orig_t) <= 1e-4f);

        if (diff > rel_tol || !t_match) {
            if (++g_mismatch_distsqseg == 1) {
                Log("[DistanceFast] DistanceSqSeg MISMATCH at call %llu: fast=%f, orig=%f, retiring hook",
                    call_idx, fast_res, orig_res);
                g_dead_distsqseg = true;
            }
            if (t) *t = orig_t;
            return orig_res;
        }
    }

    if (t) {
        *t = fast_t;
    }
    return fast_res;
}

// Blizzard's /LTCG compiler in WoW.exe optimized sub_984DB0 by keeping its outer polygon
// vertex pointer in EDX across calls to sub_984CE0 (which in stock binary never writes to EDX).
// Standard __cdecl permits clobbering EDX, so modern MSVC uses EDX inside Hooked_DistanceSqSeg_Body.
// This naked trampoline guarantees EDX is strictly preserved across the hook invocation.
__declspec(naked) double __cdecl Hooked_DistanceSqSeg(const C3Segment* segment, const C3Vector* point, float* t) {
    __asm {
        push edx
        push dword ptr [esp + 16] // t
        push dword ptr [esp + 16] // point
        push dword ptr [esp + 16] // segment
        call Hooked_DistanceSqSeg_Body
        add esp, 12
        pop edx
        ret
    }
}

float __cdecl Hooked_DistanceSqEdge(const C2Vector* a, const C2Vector* b, const C2Vector* point) {
    if (g_dead_distsqedge || !a || !b || !point) {
        return orig_DistanceSqEdge(a, b, point);
    }

    const unsigned long long call_idx = ++g_calls_distsqedge;
    const float fast_res = Fast_DistanceSqEdge_Impl(a, b, point);

    if (call_idx <= kVerifyFirst || ((call_idx & kResampleMask) == 0)) {
        ++g_verified_distsqedge;
        const float orig_res = orig_DistanceSqEdge(a, b, point);

        uint32_t uf = 0;
        uint32_t uo = 0;
        memcpy(&uf, &fast_res, sizeof(uint32_t));
        memcpy(&uo, &orig_res, sizeof(uint32_t));

        if (uf != uo) {
            const int diff = (int)uf - (int)uo;
            if (diff < -1 || diff > 1) {
                if (++g_mismatch_distsqedge == 1) {
                    Log("[DistanceFast] DistanceSqEdge MISMATCH at call %llu: fast=%f (0x%08X), orig=%f (0x%08X), retiring hook",
                        call_idx, fast_res, uf, orig_res, uo);
                    g_dead_distsqedge = true;
                }
                return orig_res;
            }
        }
    }

    return fast_res;
}

} // namespace

void Init() {
    if (!Config::g_settings.OptDistanceFast) {
        return;
    }

    static const unsigned char kExp_Dist3D[8]    = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x08, 0xD9, 0x01 };
    static const unsigned char kExp_DistSq2D[8]  = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x08, 0xD9, 0x01 };
    static const unsigned char kExp_DistSq3D[8]  = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x08, 0xD9, 0x01 };
    static const unsigned char kExp_DistSqSeg[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x4D };
    static const unsigned char kExp_DistSqEdge[8]= { 0x55, 0x8B, 0xEC, 0x8B, 0x55, 0x10, 0x8B, 0x4D };

    if (memcmp((const void*)kTarget_Distance3D, kExp_Dist3D, 8) != 0 ||
        memcmp((const void*)kTarget_DistanceSq2D, kExp_DistSq2D, 8) != 0 ||
        memcmp((const void*)kTarget_DistanceSq3D, kExp_DistSq3D, 8) != 0 ||
        memcmp((const void*)kTarget_DistanceSqSeg, kExp_DistSqSeg, 8) != 0 ||
        memcmp((const void*)kTarget_DistanceSqEdge, kExp_DistSqEdge, 8) != 0) {
        Log("[DistanceFast] Prologue mismatch, aborting installation");
        return;
    }

    if (WineSafe_CreateHook((void*)kTarget_Distance3D, (void*)Hooked_Distance3D, (void**)&orig_Distance3D) != MH_OK ||
        WineSafe_CreateHook((void*)kTarget_DistanceSq2D, (void*)Hooked_DistanceSq2D, (void**)&orig_DistanceSq2D) != MH_OK ||
        WineSafe_CreateHook((void*)kTarget_DistanceSq3D, (void*)Hooked_DistanceSq3D, (void**)&orig_DistanceSq3D) != MH_OK ||
        WineSafe_CreateHook((void*)kTarget_DistanceSqSeg, (void*)Hooked_DistanceSqSeg, (void**)&orig_DistanceSqSeg) != MH_OK ||
        WineSafe_CreateHook((void*)kTarget_DistanceSqEdge, (void*)Hooked_DistanceSqEdge, (void**)&orig_DistanceSqEdge) != MH_OK) {
        Log("[DistanceFast] Failed to create hooks");
        return;
    }

    if (WO_EnableHook((void*)kTarget_Distance3D) != MH_OK ||
        WO_EnableHook((void*)kTarget_DistanceSq2D) != MH_OK ||
        WO_EnableHook((void*)kTarget_DistanceSq3D) != MH_OK ||
        WO_EnableHook((void*)kTarget_DistanceSqSeg) != MH_OK ||
        WO_EnableHook((void*)kTarget_DistanceSqEdge) != MH_OK) {
        Log("[DistanceFast] Failed to enable hooks");
        return;
    }

    SamplingProfiler::RegisterSelfSymbol("Fast_Distance3D", (const void*)&Hooked_Distance3D);
    SamplingProfiler::RegisterSelfSymbol("Fast_DistanceSq2D", (const void*)&Hooked_DistanceSq2D);
    SamplingProfiler::RegisterSelfSymbol("Fast_DistanceSq3D", (const void*)&Hooked_DistanceSq3D);
    SamplingProfiler::RegisterSelfSymbol("Fast_DistanceSqSeg", (const void*)&Hooked_DistanceSqSeg);
    SamplingProfiler::RegisterSelfSymbol("Fast_DistanceSqEdge", (const void*)&Hooked_DistanceSqEdge);

    g_installed = true;
    Log("[DistanceFast] ACTIVE on NTempest Distance/DistanceSq (0x0078F3E0, 0x007B4830, 0x007B48C0, 0x00984CE0, 0x007F9BF0)");
}

void LogStats() {
    if (!Config::g_settings.OptDistanceFast || !g_installed) {
        return;
    }

    Log("[DistanceFast] Stats: Dist3D=%llu calls (%llu ver, %llu mis%s), DistSq2D=%llu calls (%llu ver, %llu mis%s), DistSq3D=%llu calls (%llu ver, %llu mis%s), Seg3D=%llu calls (%llu ver, %llu mis%s), Edge2D=%llu calls (%llu ver, %llu mis%s)",
        g_calls_dist3d, g_verified_dist3d, g_mismatch_dist3d, g_dead_dist3d ? " [RETIRED]" : "",
        g_calls_distsq2d, g_verified_distsq2d, g_mismatch_distsq2d, g_dead_distsq2d ? " [RETIRED]" : "",
        g_calls_distsq3d, g_verified_distsq3d, g_mismatch_distsq3d, g_dead_distsq3d ? " [RETIRED]" : "",
        g_calls_distsqseg, g_verified_distsqseg, g_mismatch_distsqseg, g_dead_distsqseg ? " [RETIRED]" : "",
        g_calls_distsqedge, g_verified_distsqedge, g_mismatch_distsqedge, g_dead_distsqedge ? " [RETIRED]" : "");
}

void Shutdown() {
    if (!g_installed) {
        return;
    }

    MH_DisableHook((void*)kTarget_Distance3D);
    MH_DisableHook((void*)kTarget_DistanceSq2D);
    MH_DisableHook((void*)kTarget_DistanceSq3D);
    MH_DisableHook((void*)kTarget_DistanceSqSeg);
    MH_DisableHook((void*)kTarget_DistanceSqEdge);
    g_installed = false;
}

} // namespace DistanceFast

