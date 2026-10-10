// ============================================================================
// Module: m2_sphere_ray_gather.cpp
//
// sub_81CFF0 (0x2C1 bytes, __thiscall, retn 10h): the segment-against-bounding-
// sphere pass over the list of model instances that sub_81DF10 and sub_81E110
// run before they test any triangle. In a three-hour CPU-bound session of
// kromvel's (build 9fc59ceb, No Client Patches, so the client's own code) the
// sampled address wow!0x0081D0C5 inside it was 1.10% of executing time,
// 7455 samples, and nothing in this tree touched the function.
//
// What changed against the client. The arithmetic is the client's x87 at 53
// bits written out in double with the same association (see the core header),
// the point transform of sub_4C21B0 is written out instead of called, and the
// next instance's cache lines are requested while the current one is worked on.
// Everything else is the client's order: the pointer slot at +0x2D8 is zeroed
// for every instance before its flag is read, the matrix rebuild goes through
// the client's own sub_4C1F00 and sub_407F80, and the status-word branches
// are reproduced as the instruction sequence takes them, NaN included.
//
// Measured, offline, against wow.exe's own copy of the function (mapped at
// 0x400000 in a suspended child, tools/sphere_harness): 60000 synthetic scenes
// with 130156 hit records, zero differences in the return value, the record
// array, the index array, every pointer slot, every instance matrix; 18
// differences that are NaN payloads only. Speed on 600 instances: 1.17x warm,
// 1.14x with the cache emptied before each call. That is about 0.15% of
// executing time on the profile above, so this is a small change and is off
// by default. Not run in a game.
//
// At run time the first calls and one in 256 after are predicted first: the
// core runs in its dry form (no writes), the client's routine then runs, and
// the records are compared. Running the client twice is not possible, since
// its pointer slots are cleared by the first run. The first disagreement
// retires the hook.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cmath>

#include "m2_sphere_ray_gather.h"
#include "m2_sphere_ray_gather_core.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace M2SphereRayGather {
namespace {

using namespace SphereRayGatherCore;

constexpr uintptr_t kTarget = 0x0081CFF0;
constexpr uintptr_t kEpsAddr = 0x009EA27C;
constexpr uintptr_t kHalfAddr = 0x009E2EC4;
constexpr uintptr_t kPtMat = 0x004C21B0;
constexpr uintptr_t kMatMul = 0x004C1F00;
constexpr uintptr_t kMatCopy = 0x00407F80;

// push ebp / mov ebp,esp / sub esp,64h / push ebx / mov ebx,ecx / push esi / mov esi,[ebx+114h]
const unsigned char kPrologue[16] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x64, 0x53, 0x8B,
    0xD9, 0x56, 0x8B, 0xB3, 0x14, 0x01, 0x00, 0x00
};

typedef int (__fastcall* Gather_fn)(void* self, void* edx, const float* o, const float* c, float len, int flag);
Gather_fn g_orig = nullptr;

Env g_env;
bool g_installed = false;
bool g_dead = false;
bool g_abSubject = false;

// Plain counters, lower bounds: the function runs on the main thread.
uint64_t g_calls = 0;
uint64_t g_fast = 0;
uint64_t g_verified = 0;
uint64_t g_skippedVerify = 0;
uint64_t g_control = 0;
uint32_t g_mismatches = 0;

constexpr uint64_t kLearnCalls = 300;
constexpr uint64_t kResampleMask = 255;

bool SameFloatBits(uint32_t a, uint32_t b) {
    if (a == b) return true;
    float fa, fb;
    memcpy(&fa, &a, 4);
    memcpy(&fb, &b, 4);
    return std::isnan(fa) && std::isnan(fb);
}

__declspec(noinline) int Verify(void* self, void* edx, const float* o, const float* c, float len, int flag) {
    static thread_local DryOut dry;
    Run<true>(g_env, (uint8_t*)self, o, c, len, flag, &dry);
    const int ret = g_orig(self, edx, o, c, len, flag);
    if (dry.overflow) { ++g_skippedVerify; return ret; }

    bool ok = (ret == dry.count);
    int badAt = -1;
    if (ok) {
        const uint8_t* recs = *(const uint8_t**)((uint8_t*)self + 0x118);
        const uint32_t* idx = *(const uint32_t**)((uint8_t*)self + 0x11C);
        for (int i = 0; i < ret; ++i) {
            const uint8_t* r = recs + (size_t)i * 16;
            const Record& d = dry.rec[i];
            if (*(const uint32_t*)r != d.node || !SameFloatBits(*(const uint32_t*)(r + 4), d.v1) ||
                !SameFloatBits(*(const uint32_t*)(r + 8), d.v2) || *(const uint32_t*)(r + 12) != d.payload ||
                idx[i] != (uint32_t)i) {
                ok = false;
                badAt = i;
                break;
            }
        }
    }
    if (!ok) {
        g_dead = true;
        ++g_mismatches;
        Log("[M2SphereRayGather] MISMATCH at call %llu: client returned %d, prediction %d, first differing record %d. "
            "Hook retired; the client's routine already ran, so nothing is wrong in this call.",
            (unsigned long long)g_calls, ret, dry.count, badAt);
        return ret;
    }
    ++g_verified;
    return ret;
}

__declspec(safebuffers) int __fastcall Hook(void* self, void* edx, const float* o, const float* c, float len, int flag) {
    ++g_calls;
    if (g_dead) return g_orig(self, edx, o, c, len, flag);
    if (g_abSubject && AbTest::StandAside()) {
        ++g_control;
        return g_orig(self, edx, o, c, len, flag);
    }
    if (g_calls <= kLearnCalls || (g_calls & kResampleMask) == 0) return Verify(self, edx, o, c, len, flag);
    ++g_fast;
    return Run<false>(g_env, (uint8_t*)self, o, c, len, flag, nullptr);
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptM2SphereRayGather) return true;

    if (!WowOpt_ClientPatchAllowed((const void*)kTarget)) {
        Log("[M2SphereRayGather] NOT active: client patches not allowed");
        return false;
    }
    if (memcmp((const void*)kTarget, kPrologue, sizeof(kPrologue)) != 0) {
        char hex[64];
        WowOpt_HexBytes(kTarget, hex, sizeof(hex));
        Log("[M2SphereRayGather] NOT active: the bytes at 0x%08X are not the ones this was written against: %s",
            (unsigned)kTarget, hex);
        return false;
    }
    // The two constants are read once. A different value means a different client.
    float eps = 0.0f, half = 0.0f;
    __try {
        eps = *(const volatile float*)kEpsAddr;
        half = *(const volatile float*)kHalfAddr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[M2SphereRayGather] NOT active: the constants could not be read");
        return false;
    }
    if (!(eps > 2.0e-7f && eps < 3.0e-7f) || half != 0.5f) {
        Log("[M2SphereRayGather] NOT active: constants at 0x%08X / 0x%08X are %g / %g, not 2.38e-07 / 0.5",
            (unsigned)kEpsAddr, (unsigned)kHalfAddr, eps, half);
        return false;
    }
    g_env.ptMat = (PtMat_fn)kPtMat;
    g_env.matMul = (MatMul_fn)kMatMul;
    g_env.matCopy = (MatCopy_fn)kMatCopy;
    g_env.eps = eps;
    g_env.half = half;

    if (WineSafe_CreateHook((void*)kTarget, (void*)&Hook, (void**)&g_orig) != MH_OK) {
        Log("[M2SphereRayGather] NOT active: CreateHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }
    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        Log("[M2SphereRayGather] NOT active: EnableHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }
    g_installed = true;
    g_abSubject = AbTest::IsSubject("M2SphereRayGather", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("M2SphereRayGather_Hook", (const void*)&Hook);
    Log("[M2SphereRayGather] Installed on sub_81CFF0 (the model bounding-sphere pass). Offline against the client's own "
        "copy: 60000 scenes, no differences; 1.14-1.17x on that function, about 0.15%% of executing time. The first %llu "
        "calls and one in %llu after are predicted and compared. Not run in a game.",
        (unsigned long long)kLearnCalls, (unsigned long long)(kResampleMask + 1));
    if (g_abSubject) Log("[M2SphereRayGather]   under A/B test");
    return true;
}

void Shutdown() {
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptM2SphereRayGather) return;
    if (!g_installed) {
        Log("[M2SphereRayGather] not installed, so nothing was measured");
        return;
    }
    Log("[M2SphereRayGather] calls=%llu (own=%llu, predicted-and-compared=%llu, compare skipped for size=%llu, control=%llu) "
        "mismatches=%u%s. Plain counters, lower bounds.",
        (unsigned long long)g_calls, (unsigned long long)g_fast, (unsigned long long)g_verified,
        (unsigned long long)g_skippedVerify, (unsigned long long)g_control, g_mismatches, g_dead ? " [RETIRED]" : "");
}

} // namespace M2SphereRayGather
