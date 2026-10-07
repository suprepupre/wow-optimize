// ============================================================================
// Module: collision_reset_visited.cpp
//
// Fast reset for the collision query visited-flags array in sub_7C7610.
//
// In the 2026-09-21 field session (wow_optimize_2026-09-21_20-10-34.log),
// wow!0x007C7637 in this function showed as 25,249 samples (2.72% of executing
// main-thread time). It is called after every raycast query (sub_7CB0C0,
// sub_7CB180, sub_7CB260, sub_7CB2F0, sub_7CB7B0) to clear the visited bit
// (0x80) from every triangle tested during the query.
//
// The client's loop (0x007C7620 -> 0x007C7641):
//   1. Decrements and writes dword_D2DBF8 to memory on every single iteration.
//   2. Reloads the flags array base pointer from [ecx+4] on every iteration.
//   3. Contains a dead LEA instruction (lea eax, [esi+eax*2]).
//   4. Reloads dword_D2DBF8 from memory on every iteration to test against zero.
//
// This replacement hoists the flags array pointer, unrolls the clearing loop
// four ways, keeps loop counters entirely in registers, and writes the two
// global counts (dword_D2DBFC, dword_D2DBF8) once on exit.
//
// Precision: there is no floating-point arithmetic in this function. It is pure
// integer bit-clearing (flags[idx * 2] &= 0x7F). Clearing bit 7 across the set
// of indices recorded in word_D25BF8 produces the exact same bit-level memory
// result regardless of iteration direction or unrolling.
//
// Verification: predict-then-compare. During learning (the first 500 calls) and
// on periodic resampling (1 in 256 calls), up to 16 indices and their pre-call
// bytes are recorded, the client's function is executed, and its post-call state
// is verified against the prediction: zero in both global counts and bit 7
// cleared in each sampled flag byte. Any disagreement permanently retires the
// hook for the session.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "collision_reset_visited.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace CollisionResetVisited {

namespace {

constexpr uintptr_t kTarget = 0x007C7610;

// mov eax, dword_D2DBF8 / xor edx, edx / cmp eax, edx
const unsigned char kPrologue[8] = {
    0xA1, 0xF8, 0xDB, 0xD2, 0x00, 0x33, 0xD2, 0x3B
};

typedef int (__fastcall* ResetFn)(void* self, void* edx);
ResetFn g_orig = nullptr;

bool g_installed = false;
bool g_dead = false;
bool g_abSubject = false;

constexpr uint32_t kLearnCalls = 500;
constexpr uint32_t kResampleMask = 0xFF;

// Plain 32-bit and 64-bit lower-bound counters for diagnostic reporting.
uint64_t g_calls = 0;
uint64_t g_fastResets = 0;
uint64_t g_emptySkips = 0;
uint64_t g_totalIndicesCleared = 0;
uint32_t g_verified = 0;
uint32_t g_mismatches = 0;
uint64_t g_controlCalls = 0;

struct SampleCheck {
    uint16_t idx;
    uint8_t  preByte;
};

static SampleCheck g_verifySamples[16];

void Retire(const char* reason, uint32_t count) {
    g_dead = true;
    ++g_mismatches;
    Log("[CollisionResetVisited] RETIRED: %s (count=%u). All subsequent calls "
        "delegate to the client.", reason, count);
}

static __declspec(noinline) int VerifyWithClient(void* self, void* edx, uint32_t count, uint8_t* flagsBase) {
    const uint16_t* const indices = (const uint16_t*)0x00D25BF8;
    constexpr uint32_t kMaxSamples = 16;
    const uint32_t sampleCount = (count < kMaxSamples) ? count : kMaxSamples;

    for (uint32_t s = 0; s < sampleCount; ++s) {
        g_verifySamples[s].idx = indices[s];
        g_verifySamples[s].preByte = flagsBase[indices[s] * 2];
    }

    const int clientResult = g_orig(self, edx);

    const uint32_t postCount = *(volatile uint32_t*)0x00D2DBF8;
    const uint32_t postHit = *(volatile uint32_t*)0x00D2DBFC;

    if (postCount != 0 || postHit != 0) {
        Retire("client did not clear global count or hit flag", count);
        return clientResult;
    }

    for (uint32_t s = 0; s < sampleCount; ++s) {
        const uint8_t postByte = flagsBase[g_verifySamples[s].idx * 2];
        const uint8_t expected = (uint8_t)(g_verifySamples[s].preByte & 0x7F);
        if (postByte != expected) {
            Retire("flag byte mismatch after client reset", count);
            return clientResult;
        }
    }

    ++g_verified;
    return clientResult;
}

int __fastcall Hook_CollisionResetVisited(void* self, void* edx) {
    ++g_calls;

    if (g_dead) {
        return g_orig(self, edx);
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_controlCalls;
        return g_orig(self, edx);
    }

    const uint32_t count = *(volatile uint32_t*)0x00D2DBF8;
    if (count == 0) {
        ++g_emptySkips;
        *(uint32_t*)0x00D2DBFC = 0;
        return 0;
    }

    if (!self) {
        return g_orig(self, edx);
    }

    uint8_t* const flagsBase = *(uint8_t**)((uintptr_t)self + 4);
    if (!flagsBase) {
        return g_orig(self, edx);
    }

    const bool isLearning = (g_verified < kLearnCalls);
    const bool shouldVerify = isLearning || ((g_calls & kResampleMask) == 0);

    if (shouldVerify) {
        return VerifyWithClient(self, edx, count, flagsBase);
    }

    // Fast path: hoist pointer, unroll by 4, write globals once on exit.
    const uint16_t* const indices = (const uint16_t*)0x00D25BF8;
    uint32_t i = count;
    while (i >= 4) {
        flagsBase[indices[i - 1] * 2] &= 0x7F;
        flagsBase[indices[i - 2] * 2] &= 0x7F;
        flagsBase[indices[i - 3] * 2] &= 0x7F;
        flagsBase[indices[i - 4] * 2] &= 0x7F;
        i -= 4;
    }
    while (i > 0) {
        flagsBase[indices[i - 1] * 2] &= 0x7F;
        --i;
    }

    *(uint32_t*)0x00D2DBFC = 0;
    *(uint32_t*)0x00D2DBF8 = 0;

    ++g_fastResets;
    g_totalIndicesCleared += count;
    return 0;
}

bool BytesMatch(uintptr_t addr, const unsigned char* want, size_t n) {
    __try {
        return memcmp((const void*)addr, want, n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

bool Init() {
    if (!Config::g_settings.OptCollisionResetVisited) return true;

    if (!BytesMatch(kTarget, kPrologue, sizeof(kPrologue))) {
        Log("[CollisionResetVisited] NOT active: prologue at 0x%08X does not match "
            "sub_7C7610.", (unsigned)kTarget);
        return false;
    }

    if (!WowOpt_ClientPatchAllowed((const void*)kTarget)) {
        Log("[CollisionResetVisited] NOT active: No Client Patches is on, and this hooks "
            "a function inside wow.exe.");
        return false;
    }

    if (WineSafe_CreateHook((void*)kTarget, (void*)&Hook_CollisionResetVisited, (void**)&g_orig) != MH_OK) {
        Log("[CollisionResetVisited] NOT active: hook creation failed on 0x%08X.", (unsigned)kTarget);
        return false;
    }

    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        MH_RemoveHook((void*)kTarget);
        Log("[CollisionResetVisited] NOT active: hook enable failed on 0x%08X.", (unsigned)kTarget);
        return false;
    }

    g_installed = true;
    g_abSubject = AbTest::IsSubject("CollisionResetVisited", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("CollisionResetVisited", (const void*)&Hook_CollisionResetVisited);

    Log("[CollisionResetVisited] ACTIVE on sub_7C7610 (0x%08X), 2.72%% of executing "
        "time in field sessions. Replaces per-iteration global writes and pointer "
        "reloads with a hoisted 4-way unrolled clearing pass. The first %u calls are "
        "checked against client writes, then one in %u.",
        (unsigned)kTarget, kLearnCalls, kResampleMask + 1);
    if (g_abSubject) {
        Log("[CollisionResetVisited]   under A/B test: the control half runs the client's "
            "function through the same hook.");
    }
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook((void*)kTarget);
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptCollisionResetVisited) return;
    if (!g_installed) {
        Log("[CollisionResetVisited] not installed - reason at top of log");
        return;
    }
    if (g_calls == 0) {
        Log("[CollisionResetVisited] hooked, 0 calls reached so far.");
        return;
    }
    Log("[CollisionResetVisited] %llu call(s): %llu fast resets (%llu indices cleared), "
        "%llu empty skips. Plain counters, lower bounds.",
        g_calls, g_fastResets, g_totalIndicesCleared, g_emptySkips);
    if (g_mismatches) {
        Log("[CollisionResetVisited]   RETIRED after a mismatch; reason logged earlier.");
    } else if (g_verified < kLearnCalls) {
        Log("[CollisionResetVisited]   %u of %u learning calls verified against client.",
            g_verified, kLearnCalls);
    } else {
        Log("[CollisionResetVisited]   %u calls verified against client, none disagreed; "
            "1 in %u resampled.", g_verified, kResampleMask + 1);
    }
    if (g_abSubject) {
        Log("[CollisionResetVisited]   %llu call(s) ran client code as A/B control.", g_controlCalls);
    }
}

}  // namespace CollisionResetVisited
