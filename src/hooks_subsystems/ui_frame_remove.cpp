#include "ui_frame_remove.h"
#include <cstdint>
#include <cstring>
#include <emmintrin.h>
#include "config.h"
#include "ab_test.h"
#include "MinHook.h"
#include "version.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace UIFrameRemove {
namespace {

typedef void* (__thiscall *RemoveFrame_fn)(void* thisPtr, void* frameToRemove);
static RemoveFrame_fn g_orig = nullptr;

typedef int (__thiscall *UnlinkNode_fn)(void* container, void* block);
constexpr uintptr_t kUnlinkNodeAddr = 0x00490D00;

constexpr uintptr_t kTarget = 0x00491160;
static const uint8_t kExpectedPrologue[8] = {
    0x55, 0x8B, 0xEC, 0x56, 0x8B, 0xF1, 0x8B, 0x86
};

static bool g_dead = false;
static bool g_abSubject = false;

constexpr uint32_t kLearnCalls = 500;
constexpr uint32_t kResampleMask = 0xFF;

static uint64_t g_calls = 0;
static uint64_t g_fastRemoves = 0;
static uint32_t g_verified = 0;
static uint32_t g_mismatches = 0;
static uint64_t g_controlCalls = 0;

static void Retire(const char* reason) {
    g_dead = true;
    ++g_mismatches;
    Log("[UIFrameRemove] RETIRED: %s. All subsequent calls delegate to client.", reason);
}

static inline void* RemoveFast(void* thisPtr, void* frameToRemove) {
    uintptr_t node = *(uintptr_t*)((uintptr_t)thisPtr + 0x280);
    if ((node & 1) != 0 || !node) {
        return nullptr;
    }

    const uintptr_t target = (uintptr_t)frameToRemove;
    void* const container = (void*)((uintptr_t)thisPtr + 0x278);

    while ((node & 1) == 0 && node) {
        const uintptr_t next = *(uintptr_t*)(node + 4);
        if ((next & 1) == 0 && next) {
            _mm_prefetch((const char*)next, _MM_HINT_T0);
        }

        if (*(uintptr_t*)(node + 8) == target) {
            ((UnlinkNode_fn)kUnlinkNodeAddr)(container, (void*)node);
            ++g_fastRemoves;
            return nullptr;
        }

        node = next;
    }

    return nullptr;
}

static __declspec(noinline) void* VerifyWithClient(void* thisPtr, void* frameToRemove) {
    void* const clientRet = g_orig(thisPtr, frameToRemove);

    if (clientRet != nullptr) {
        Retire("client returned non-null pointer");
        return clientRet;
    }

    ++g_verified;
    return clientRet;
}

__declspec(safebuffers)
static void* __fastcall Hook_UIFrameRemove(void* thisPtr, void* /*dummyEdx*/, void* frameToRemove) {
    ++g_calls;

    if (g_dead) {
        return g_orig(thisPtr, frameToRemove);
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_controlCalls;
        return g_orig(thisPtr, frameToRemove);
    }

    const bool isLearning = (g_verified < kLearnCalls);
    const bool shouldVerify = isLearning || ((g_calls & kResampleMask) == 0);

    if (shouldVerify) {
        return VerifyWithClient(thisPtr, frameToRemove);
    }

    return RemoveFast(thisPtr, frameToRemove);
}

} // anonymous namespace

void Init() {
    if (!Config::g_settings.OptUIFrameRemove) {
        return;
    }

    void* const target = (void*)kTarget;
    if (!WowOpt_ClientPatchAllowed(target)) {
        Log("[UIFrameRemove] NOT active: client patches disallowed at 0x%08X", (uintptr_t)target);
        return;
    }

    if (std::memcmp(target, kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[UIFrameRemove] NOT active: prologue mismatch at 0x%08X", (uintptr_t)target);
        return;
    }

    const MH_STATUS status = WineSafe_CreateHook(target, (void*)&Hook_UIFrameRemove, (void**)&g_orig);
    if (status != MH_OK) {
        Log("[UIFrameRemove] NOT active: MH_CreateHook failed (%d) at 0x%08X", status, (uintptr_t)target);
        return;
    }

    if (WO_EnableHook(target) != MH_OK) {
        Log("[UIFrameRemove] NOT active: MH_EnableHook failed at 0x%08X", (uintptr_t)target);
        return;
    }

    SamplingProfiler::RegisterSelfSymbol("UIFrameRemove", (const void*)kTarget);

    Log("[UIFrameRemove] ACTIVE on frame strata unlinking (sub_491160 @ 0x%08X, %u learn calls, 1/256 sampling)",
        (uintptr_t)kTarget, kLearnCalls);

    if (AbTest::IsSubject("UIFrameRemove", &g_abSubject)) {
        Log("[UIFrameRemove]   under A/B test (subject=%d)", g_abSubject ? 1 : 0);
    }
}

void Shutdown() {
}

void LogStats() {
    if (!Config::g_settings.OptUIFrameRemove) return;
    Log("[UIFrameRemove] calls=%llu fast=%llu verified=%u mismatches=%u ctrl=%llu dead=%d",
        g_calls, g_fastRemoves, g_verified, g_mismatches, g_controlCalls, g_dead ? 1 : 0);
}

} // namespace UIFrameRemove
