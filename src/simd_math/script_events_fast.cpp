// ============================================================================
// Module: script_events_fast.cpp
//
// Fast O(1) script event and combat signal deduplication:
//   1. Script_SendUniqueSignal (sub_6143F0 @ 0x006143F0, 224 B):
//      - In original client: linear O(N) array scan over all queued unique
//        signals for every event fired (combat text, auras, unit power,
//        health, spell signals, etc.), resulting in O(N^2) quadratic overhead
//        during busy raids and combat.
//      - Optimized: O(1) open-addressing hash table with generational epoch
//        tagging, eliminating 99%+ of linear array scans while maintaining
//        exact client event queue ordering.
//   2. Script_SendUniqueSignals (sub_614760 @ 0x00614760, 78 B):
//      - Advances epoch counter in O(1) upon queue drain, instantly resetting
//        the deduplication table without memory clears.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "script_events_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "session_verdict.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace ScriptEventsFast {

namespace {

constexpr uintptr_t kTargetSendSignal   = 0x006143F0;
constexpr uintptr_t kTargetSendSignals  = 0x00614760;
constexpr uintptr_t kArrayCountPtr      = 0x00C25A00;
constexpr uintptr_t kArrayDataPtr       = 0x00C25A04;

const unsigned char kPrologueSendSignal[11] = {
    0x55, 0x8B, 0xEC, 0x8B, 0x0D, 0x00, 0x5A, 0xC2, 0x00, 0x53, 0x56
};

const unsigned char kPrologueSendSignals[8] = {
    0xA1, 0x00, 0x5A, 0xC2, 0x00, 0x85, 0xC0, 0x76
};

typedef void (__cdecl *SendSignalFn)(const uint64_t* pGuid, int32_t signal);
SendSignalFn g_origSendSignal = nullptr;

typedef void (__cdecl *SendSignalsFn)();
SendSignalsFn g_origSendSignals = nullptr;

bool g_installed = false;
bool g_dead = false;
bool g_abSubject = false;

unsigned long long g_calls = 0;
unsigned long long g_fastDedup = 0;
unsigned long long g_fastAppends = 0;
unsigned long long g_control = 0;
unsigned g_verified = 0;
unsigned g_mismatches = 0;

constexpr uint32_t kLearnCalls   = 10000;
constexpr uint32_t kResampleMask = 127;

struct Slot {
    uint64_t guid;
    int32_t  signal;
    uint32_t epoch;
};

static Slot s_slots[2048];
static uint32_t s_epoch = 1;

static inline void ResetEpochIfEmpty() {
    const uint32_t count = *(const uint32_t*)kArrayCountPtr;
    if (count == 0) {
        ++s_epoch;
        if (s_epoch == 0) {
            memset(s_slots, 0, sizeof(s_slots));
            s_epoch = 1;
        }
    }
}

void __cdecl Hooked_SendUniqueSignal(const uint64_t* pGuid, int32_t signal) {
    ++g_calls;
    if (g_dead || !pGuid) {
        g_origSendSignal(pGuid, signal);
        return;
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_control;
        g_origSendSignal(pGuid, signal);
        return;
    }

    ResetEpochIfEmpty();

    const uint64_t guid = *pGuid;
    const uint32_t h = (uint32_t)(((guid ^ (guid >> 32)) ^ ((uint32_t)signal * 0x9E3779B9u)) & 2047);

    const bool learning = g_verified < kLearnCalls ||
                          ((uint32_t)g_calls & kResampleMask) == 0;

    for (int probe = 0; probe < 8; ++probe) {
        const uint32_t idx = (h + probe) & 2047;
        if (s_slots[idx].epoch == s_epoch) {
            if (s_slots[idx].guid == guid && s_slots[idx].signal == signal) {
                // Duplicate found
                if (learning) {
                    const uint32_t count = *(const uint32_t*)kArrayCountPtr;
                    const uint8_t* data = *(const uint8_t**)kArrayDataPtr;
                    bool inArray = false;
                    for (uint32_t i = 0; i < count; ++i) {
                        const uint64_t entryGuid = *(const uint64_t*)(data + i * 16);
                        const int32_t entrySig = *(const int32_t*)(data + i * 16 + 8);
                        if (entryGuid == guid && entrySig == signal) {
                            inArray = true;
                            break;
                        }
                    }
                    if (!inArray) {
                        g_dead = true;
                        ++g_mismatches;
                        Log("[ScriptEvents] False duplicate detected! Retiring hook.");
                        Verdict::Add(Verdict::Bad, "ScriptEvents false duplicate detected");
                        g_origSendSignal(pGuid, signal);
                        return;
                    }
                    ++g_verified;
                }
                ++g_fastDedup;
                return;
            }
        } else {
            // Empty slot -> not a duplicate
            s_slots[idx].epoch = s_epoch;
            s_slots[idx].guid = guid;
            s_slots[idx].signal = signal;
            if (learning) {
                const uint32_t count = *(const uint32_t*)kArrayCountPtr;
                const uint8_t* data = *(const uint8_t**)kArrayDataPtr;
                bool inArray = false;
                for (uint32_t i = 0; i < count; ++i) {
                    const uint64_t entryGuid = *(const uint64_t*)(data + i * 16);
                    const int32_t entrySig = *(const int32_t*)(data + i * 16 + 8);
                    if (entryGuid == guid && entrySig == signal) {
                        inArray = true;
                        break;
                    }
                }
                if (inArray) {
                    g_dead = true;
                    ++g_mismatches;
                    Log("[ScriptEvents] Missed duplicate detected! Retiring hook.");
                    Verdict::Add(Verdict::Bad, "ScriptEvents missed duplicate detected");
                    g_origSendSignal(pGuid, signal);
                    return;
                }
                ++g_verified;
            }
            g_origSendSignal(pGuid, signal);
            ++g_fastAppends;
            return;
        }
    }

    g_origSendSignal(pGuid, signal);
}

void __cdecl Hooked_SendUniqueSignals() {
    ++s_epoch;
    if (s_epoch == 0) {
        memset(s_slots, 0, sizeof(s_slots));
        s_epoch = 1;
    }
    g_origSendSignals();
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
    if (g_installed) return true;
    if (!Config::g_settings.OptScriptEventsFast) {
        Log("[ScriptEvents] Disabled via config.");
        return false;
    }

    if (!BytesMatch(kTargetSendSignal, kPrologueSendSignal, sizeof(kPrologueSendSignal))) {
        Log("[ScriptEvents] Prologue mismatch at 0x%08X; aborting.", kTargetSendSignal);
        Verdict::Add(Verdict::Warn, "ScriptEvents SendSignal prologue mismatch");
        return false;
    }

    if (!BytesMatch(kTargetSendSignals, kPrologueSendSignals, sizeof(kPrologueSendSignals))) {
        Log("[ScriptEvents] Prologue mismatch at 0x%08X; aborting.", kTargetSendSignals);
        Verdict::Add(Verdict::Warn, "ScriptEvents SendSignals prologue mismatch");
        return false;
    }

    MH_STATUS s1 = WineSafe_CreateHook((void*)kTargetSendSignal,
                                       (void*)&Hooked_SendUniqueSignal,
                                       (void**)&g_origSendSignal);
    if (s1 != MH_OK) {
        Log("[ScriptEvents] Failed to hook Script_SendUniqueSignal (status=%d)", s1);
        Verdict::Add(Verdict::Bad, "Failed to hook Script_SendUniqueSignal");
        return false;
    }

    MH_STATUS s2 = WineSafe_CreateHook((void*)kTargetSendSignals,
                                       (void*)&Hooked_SendUniqueSignals,
                                       (void**)&g_origSendSignals);
    if (s2 != MH_OK) {
        Log("[ScriptEvents] Failed to hook Script_SendUniqueSignals (status=%d)", s2);
        Verdict::Add(Verdict::Bad, "Failed to hook Script_SendUniqueSignals");
        return false;
    }

    if (WO_EnableHook((void*)kTargetSendSignal) != MH_OK ||
        WO_EnableHook((void*)kTargetSendSignals) != MH_OK) {
        Log("[ScriptEvents] Failed to enable hooks.");
        Verdict::Add(Verdict::Bad, "Failed to enable ScriptEvents hooks");
        return false;
    }

    g_installed = true;
    g_abSubject = AbTest::IsSubject("ScriptEventsFast", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("ScriptEvents_SendHook", (const void*)&Hooked_SendUniqueSignal);
    SamplingProfiler::RegisterSelfSymbol("ScriptEvents_DrainHook", (const void*)&Hooked_SendUniqueSignals);

    Log("[ScriptEvents] ACTIVE on Script_SendUniqueSignal (0x006143F0) and Drain (0x00614760). "
        "O(1) hash deduplication with generational epoch reset.");
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook((void*)kTargetSendSignal);
    MH_DisableHook((void*)kTargetSendSignals);
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptScriptEventsFast) return;
    if (!g_installed) return;
    Log("[ScriptEvents] calls=%llu (dedup=%llu, appends=%llu, verified=%u, control=%llu) mismatches=%u%s",
        g_calls, g_fastDedup, g_fastAppends, g_verified, g_control, g_mismatches,
        g_dead ? " [RETIRED]" : "");
}

}  // namespace ScriptEventsFast

