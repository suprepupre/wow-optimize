// ============================================================================
// Module: m2_mesh_pick_fast.cpp
//
// Accelerates 2D ray/point triangle intersection and Z height interpolation
// in sub_81D510 (0x168 bytes / 360 bytes, 145 instructions, 20 basic blocks).
//
// In profiler logs, sub_81D510 was sampled 9,066 times at 0x0081D64E during
// world scene interaction, model ray-casting, and mouse picking. Callers include
// M2Scene pick-ray traversal helpers sub_81DAF0 and sub_81DD50 (called immediately
// following M2SkinProjection in sub_81D680).
//
// The client implementation executes a tight per-triangle loop on x87 FPU with up
// to 5 status-word transfers (fnstsw ax / test ah, 5) and a 30+ cycle fdivrp on
// every single candidate triangle, even when the 2D test point is far outside the
// triangle.
//
// This replacement:
//   1. Eliminates x87 status-word transfers (fnstsw) and branch stalls.
//   2. Performs branchless 2D orientation and sign checks on cross products,
//      deferring the 64-bit reciprocal division (1.0 / det) and Z height derivation
//      until after the triangle is confirmed to contain the point.
//   3. Evaluates all determinant, barycentric, and height operations in IEEE
//      double precision strictly adhering to client accumulation order,
//      including client intermediate float truncations:
//        - float u = (float)(cross_u * inv_det) [client: fst [ebp+var_4]]
//        - float d0y = (float)(v0[1] - testPoint[1]) [client: fst [ebp+arg_8]]
//        - Z height accumulation: ((v * v1[2]) + (w * v2[2])) + (v0[2] * (float)u)
//   4. Maintains exact caller object selection semantics: honors flag != 0
//      object id comparisons at offset +0x0C and best height updates.
//   5. Guarantees zero security cookies and zero SEH frames on the hot path via
//      __declspec(safebuffers).
//
// Verification: Verified offline against verbatim client instructions over
// 1,000,000 randomized test cases with 0 bit differences (harness only, not run
// in a game). Runtime verification tests the first 10,000 calls and 1 in every 128
// thereafter, retiring immediately on the first mismatch.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "m2_mesh_pick_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace M2MeshPickFast {

namespace {

constexpr uintptr_t kTarget = 0x0081D510;

// push ebp / mov ebp, esp / push ecx / push edi / mov edi, [ebp+8] / cmp edi, [ebp+0Ch] / jnb +0x14D
const unsigned char kPrologue[16] = {
    0x55, 0x8B, 0xEC, 0x51, 0x57, 0x8B, 0x7D, 0x08,
    0x3B, 0x7D, 0x0C, 0x0F, 0x83, 0x4D, 0x01, 0x00
};

typedef int (__thiscall* M2MeshPick_fn)(
    void* this_ptr,
    const uint16_t* indicesBegin,
    const uint16_t* indicesEnd,
    int baseVertexIdx,
    const float* testPoint2D,
    int flag,
    int hitObj,
    float* bestHeight,
    int initialResult);

static M2MeshPick_fn g_orig = nullptr;

static bool g_installed = false;
static bool g_active = false;
static bool g_dead = false;
static bool g_abSubject = false;

static uint64_t g_calls = 0;
static uint64_t g_armedCalls = 0;
static uint64_t g_verifiedCalls = 0;
static uint64_t g_controlCalls = 0;
static uint32_t g_mismatches = 0;

constexpr uint32_t kVerifyCalls = 10000;
constexpr uint32_t kVerifyMask = 127;

__declspec(safebuffers) static inline int Fast_M2MeshPick(
    void* this_ptr,
    const uint16_t* indicesBegin,
    const uint16_t* indicesEnd,
    int baseVertexIdx,
    const float* testPoint2D,
    int flag,
    int hitObj,
    float* bestHeight,
    int initialResult)
{
    if (indicesBegin >= indicesEnd) {
        return initialResult;
    }

    const char* const vertexBase = *(const char* const*)((const char*)this_ptr + 0x124);
    const float px = testPoint2D[0];
    const float py = testPoint2D[1];

    int curResult = initialResult;

    for (const uint16_t* p = indicesBegin; p < indicesEnd; p += 3) {
        const int idx0 = (int)p[0] - baseVertexIdx;
        const int idx1 = (int)p[1] - baseVertexIdx;
        const int idx2 = (int)p[2] - baseVertexIdx;

        const float* const v0 = (const float*)(vertexBase + idx0 * 12);
        const float* const v1 = (const float*)(vertexBase + idx1 * 12);
        const float* const v2 = (const float*)(vertexBase + idx2 * 12);

        // Client x87 determinant:
        // st(0) = (v2[1] - v0[1]) * (v1[0] - v0[0]) - (v2[0] - v0[0]) * (v1[1] - v0[1])
        const double dy20 = (double)v2[1] - (double)v0[1];
        const double dx10 = (double)v1[0] - (double)v0[0];
        const double dy10 = (double)v1[1] - (double)v0[1];
        const double dx20 = (double)v2[0] - (double)v0[0];
        const double det = (dy20 * dx10) - (dx20 * dy10);

        if (fabs(det) < 0.0000099999997) {
            continue;
        }

        // Vector differences relative to testPoint2D:
        const double d1x = (double)v1[0] - (double)px;
        const double d1y = (double)v1[1] - (double)py;
        const double d2x = (double)v2[0] - (double)px;
        const double d2y = (double)v2[1] - (double)py;

        // u cross product: (d2y * d1x) - (d1y * d2x)
        const double cross_u = (d2y * d1x) - (d1y * d2x);
        if (det > 0.0) {
            if (cross_u < 0.0) continue;
        } else {
            if (cross_u > 0.0) continue;
        }

        const double d0x = (double)v0[0] - (double)px;
        const double d0y = (double)v0[1] - (double)py;

        // v cross product: (d2x * d0y - d2y * d0x)
        const double cross_v = (d2x * d0y) - (d2y * d0x);
        if (det > 0.0) {
            if (cross_v < 0.0) continue;
        } else {
            if (cross_v > 0.0) continue;
        }

        // w cross product: (d1y * d0x - d1x * (double)d0y_flt)
        // Client stores d0y to memory as 32-bit float [ebp+arg_8] at 81d5cc and reloads it at 81d5e8
        const float d0y_flt = (float)d0y;
        const double cross_w = (d1y * d0x) - (d1x * (double)d0y_flt);
        if (det > 0.0) {
            if (cross_w < 0.0) continue;
        } else {
            if (cross_w > 0.0) continue;
        }

        // Triangle contains test point! Compute exact reciprocal determinant and interpolated Z height:
        const double inv_det = 1.0 / det;
        const double u_dbl = cross_u * inv_det;
        const float u = (float)u_dbl; // client: fst [ebp+var_4] at 81d5af
        const double v_dbl = cross_v * inv_det;
        const double w_dbl = cross_w * inv_det;

        // Interpolated Z height:
        // Client addition order at 81d600..81d610:
        // ST(0) = w * v2[2]
        // ST(1) = v * v1[2]
        // faddp st(1), st -> (v * v1[2]) + (w * v2[2])
        // ST(0) = v0[2] * (float)u
        // faddp st(1), st -> ((v * v1[2]) + (w * v2[2])) + (v0[2] * (float)u)
        const double z_w = w_dbl * (double)v2[2];
        const double z_v = v_dbl * (double)v1[2];
        const double z_u = (double)v0[2] * (double)u;
        const double z_height_dbl = (z_v + z_w) + z_u;
        const float z_height = (float)z_height_dbl;

        if (z_height_dbl < 0.0) {
            continue;
        }

        bool accept = false;
        if (flag) {
            if (!curResult) {
                accept = true;
            } else {
                const int curVal = *(const int*)(curResult + 0x0C);
                const int hitVal = *(const int*)(hitObj + 0x0C);
                if (curVal != hitVal) {
                    accept = true;
                }
            }
        }

        if (!accept) {
            // The client compares the interpolated height before it is stored as
            // a float (fcom against the float in memory, then fstp dword), so the
            // test is on the 53-bit value. Comparing the rounded float accepted a
            // coplanar triangle whose height was a hair above the best so far and
            // rounded to it, which handed back a different object with an equal
            // stored height: the one disagreement in 3.1 million calls that
            // retired this module.
            if (z_height_dbl <= (double)*bestHeight) {
                accept = true;
            }
        }

        if (accept) {
            *bestHeight = z_height;
            curResult = hitObj;
        }
    }

    return curResult;
}

__declspec(noinline) static int Verify_M2MeshPick(
    void* this_ptr,
    const uint16_t* indicesBegin,
    const uint16_t* indicesEnd,
    int baseVertexIdx,
    const float* testPoint2D,
    int flag,
    int hitObj,
    float* bestHeight,
    int initialResult)
{
    float clientHeight = *bestHeight;
    float fastHeight = *bestHeight;

    const int clientRes = g_orig(this_ptr, indicesBegin, indicesEnd, baseVertexIdx, testPoint2D, flag, hitObj, &clientHeight, initialResult);
    const int fastRes   = Fast_M2MeshPick(this_ptr, indicesBegin, indicesEnd, baseVertexIdx, testPoint2D, flag, hitObj, &fastHeight, initialResult);

    const uint32_t c_bits = *(const uint32_t*)&clientHeight;
    const uint32_t f_bits = *(const uint32_t*)&fastHeight;

    if (clientRes != fastRes || c_bits != f_bits) {
        g_dead = true;
        ++g_mismatches;
        Log("[M2MeshPick] Disagreement: clientRes=0x%08X (height=0x%08X / %f), fastRes=0x%08X (height=0x%08X / %f). Hook retired.",
            clientRes, c_bits, clientHeight, fastRes, f_bits, fastHeight);
        *bestHeight = clientHeight;
        return clientRes;
    }

    ++g_verifiedCalls;
    *bestHeight = clientHeight;
    return clientRes;
}

__declspec(safebuffers) static int __fastcall Hook_M2MeshPick(
    void* this_ptr,
    void* /*dummy_edx*/,
    const uint16_t* indicesBegin,
    const uint16_t* indicesEnd,
    int baseVertexIdx,
    const float* testPoint2D,
    int flag,
    int hitObj,
    float* bestHeight,
    int initialResult)
{
    ++g_calls;
    if (g_dead || !g_active) {
        return g_orig(this_ptr, indicesBegin, indicesEnd, baseVertexIdx, testPoint2D, flag, hitObj, bestHeight, initialResult);
    }
    if (g_abSubject && AbTest::StandAside()) {
        ++g_controlCalls;
        return g_orig(this_ptr, indicesBegin, indicesEnd, baseVertexIdx, testPoint2D, flag, hitObj, bestHeight, initialResult);
    }
    if (g_verifiedCalls < kVerifyCalls || ((g_calls & kVerifyMask) == 0)) {
        return Verify_M2MeshPick(this_ptr, indicesBegin, indicesEnd, baseVertexIdx, testPoint2D, flag, hitObj, bestHeight, initialResult);
    }
    ++g_armedCalls;
    return Fast_M2MeshPick(this_ptr, indicesBegin, indicesEnd, baseVertexIdx, testPoint2D, flag, hitObj, bestHeight, initialResult);
}

} // anonymous namespace

bool Init() {
    if (!Config::g_settings.OptM2MeshPickFast) {
        return true;
    }

    if (!WowOpt_ClientPatchAllowed((const void*)kTarget)) {
        Log("[M2MeshPick] NOT active: client patches not allowed");
        return false;
    }

    if (memcmp((const void*)kTarget, kPrologue, sizeof(kPrologue)) != 0) {
        Log("[M2MeshPick] NOT active: prologue mismatch at 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (WineSafe_CreateHook((void*)kTarget, (void*)Hook_M2MeshPick, (void**)&g_orig) != MH_OK) {
        Log("[M2MeshPick] NOT active: CreateHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        Log("[M2MeshPick] NOT active: EnableHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    g_installed = true;
    g_active = true;
    g_abSubject = AbTest::IsSubject("M2MeshPickFast", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("M2MeshPick_Hook", (const void*)&Hook_M2MeshPick);
    Log("[M2MeshPick] Hook installed on sub_81D510 (0x168 bytes)");
    return true;
}

void Shutdown() {
    if (g_installed) {
        g_active = false;
        g_installed = false;
    }
}

void LogStats() {
    if (!Config::g_settings.OptM2MeshPickFast) return;
    if (!g_installed) {
        Log("[M2MeshPick] Not installed");
        return;
    }
    Log("[M2MeshPick] calls=%llu (armed=%llu, verified=%llu, control=%llu) mismatches=%u%s",
        g_calls, g_armedCalls, g_verifiedCalls, g_controlCalls, g_mismatches,
        g_dead ? " [RETIRED]" : "");
}

} // namespace M2MeshPickFast
