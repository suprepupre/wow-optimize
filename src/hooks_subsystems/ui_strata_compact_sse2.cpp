// ============================================================================
// Module: ui_strata_compact_sse2.cpp
//
// sub_495060, CFrameStrataManager::CompactLevels. In the 2026-09-21 session it
// was 1.88% of executing time at wow!0x0049516E, from a window of only 183
// samples, so the cost is real but thinly measured.
//
// The _sse2 in the name does not describe the code: there is no vector
// instruction in this file. The change is algorithmic - an early exit when
// every strata level is already occupied, and a single-pass remap table in
// place of the client's nested rescans - and it needs no vector width.
//
// What checks it. Not the in-game verification: that runs the client's own
// routine for the first calls and only asks that the level count did not grow, so
// the single-pass remap below has never been compared with the client's answer
// while the game runs. It was compared offline instead, against a transcription of
// sub_495060's nested loops over 200000 random layouts (0 to 24 levels, 0 to 40
// frames, dense and with long runs of empty levels), with SetFrameLevel modelled
// as unlink from the old level's list and append to the new one. Final level
// count, each frame's level and the order of the frames inside every level were
// identical in all of them. That covers the algorithm; it does not cover what
// SetFrameLevel does beyond moving the frame (it is called the same number of
// times with the same arguments, in a different order across levels).
// In a 64 minute session the client's version was caught six times as the top
// sampled address of a frame of 100 to 250 ms (0x0049516E, inside its rescan).
// ============================================================================

#include "ui_strata_compact_sse2.h"
#include <cstdint>
#include <cstring>
#include "config.h"
#include "ab_test.h"
#include "self_bench.h"
#include "MinHook.h"
#include "version.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace UIStrataCompact {
namespace {

typedef void (__thiscall *CompactLevels_fn)(void* thisPtr, unsigned int strataIdx);
static CompactLevels_fn g_orig = nullptr;

typedef int (__thiscall *SetFrameLevel_fn)(void* frame, int newLevel, int propagate);
constexpr uintptr_t kSetFrameLevelAddr = 0x004910A0;

constexpr uintptr_t kTarget = 0x00495060;
static const uint8_t kExpectedPrologue[8] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x53, 0x8B
};

static bool g_dead = false;
static bool g_abSubject = false;
static int  g_benchId = -1;

// Eight calls, not five hundred, and one in 1024 after. The client's routine rescans the whole
// frame list for every empty level, 100 to 250 ms in a UI with a few thousand frames, and in a
// ten hour session of the player who reported it only 106 calls were ever made: with a learning
// phase of 500 the fast path was never reached and every call was the client's slow one (23 of
// them showed up as frames of 165 ms on average). What the learning phase checked, that the
// level count did not grow, was little. Every call the fast path answers is now checked after
// the fact by CheckCompaction below, which states what compaction promises.
constexpr uint32_t kLearnCalls = 8;
constexpr uint32_t kResampleMask = 0x3FF;

static uint64_t g_calls = 0;
static uint64_t g_fastCompacts = 0;
static uint64_t g_earlySkips = 0;
static uint32_t g_verified = 0;
static uint32_t g_mismatches = 0;
static uint64_t g_controlCalls = 0;
static uint64_t g_checkedFast = 0;

constexpr uint32_t kMaxLevels = 128;
static int g_remapTable[kMaxLevels];

static void Retire(const char* reason) {
    g_dead = true;
    ++g_mismatches;
    Log("[UIStrataCompact] RETIRED: %s. All subsequent calls delegate to client.", reason);
}

// What compaction promises, stated so it can be checked on the real frames after every call the
// fast path answers: no frame's level went up, frames that shared a level still share one, two
// levels keep their order and stay distinct, no level is at or past the new count, and the count
// did not grow. Any of these failing means the remap is wrong, and the module retires itself
// (the damage is one call's worth of frame layering, which the client's next compaction redoes).
constexpr uint32_t kMaxFrames = 8192;
static uintptr_t g_snapFrame[kMaxFrames];
static uint32_t  g_snapLevel[kMaxFrames];
static uint32_t  g_snapCount = 0;
static bool      g_snapValid = false;
static uint32_t  g_snapLevelsBefore = 0;

static void SnapshotFrames(void* thisPtr, unsigned int strataIdx) {
    g_snapCount = 0;
    g_snapValid = false;
    if (strataIdx > 8) return;
    const uintptr_t strata = *(uintptr_t*)((uintptr_t)thisPtr + (825 + strataIdx) * 4);
    if (!strata) return;
    g_snapLevelsBefore = *(uint32_t*)(strata + 8);
    const uintptr_t frameListHead = *(uintptr_t*)((uintptr_t)thisPtr + 821 * 4);
    const int nextOffset = *(int*)((uintptr_t)thisPtr + 819 * 4);
    uintptr_t f = frameListHead;
    if ((f & 1) != 0) f = 0;
    while ((f & 1) == 0 && f) {
        if (*(uint32_t*)(f + 208) == strataIdx) {
            if (g_snapCount >= kMaxFrames) return;     // too many to hold: no check this call
            g_snapFrame[g_snapCount] = f;
            g_snapLevel[g_snapCount] = *(uint32_t*)(f + 212);
            ++g_snapCount;
        }
        f = *(uintptr_t*)(f + nextOffset + 4);
    }
    g_snapValid = true;
}

// Returns null when the promise holds, or what it broke.
static const char* CheckCompaction(void* thisPtr, unsigned int strataIdx) {
    if (!g_snapValid) return nullptr;
    const uintptr_t strata = *(uintptr_t*)((uintptr_t)thisPtr + (825 + strataIdx) * 4);
    if (!strata) return nullptr;
    const uint32_t levelsAfter = *(uint32_t*)(strata + 8);
    if (levelsAfter > g_snapLevelsBefore) return "the level count grew";

    int32_t mapped[kMaxLevels];
    for (uint32_t i = 0; i < kMaxLevels; ++i) mapped[i] = -1;
    for (uint32_t i = 0; i < g_snapCount; ++i) {
        const uint32_t before = g_snapLevel[i];
        const uint32_t after = *(uint32_t*)(g_snapFrame[i] + 212);
        if (before >= kMaxLevels || before >= g_snapLevelsBefore) continue;   // not a level the compaction owns
        if (after > before) return "a frame's level went up";
        if (after >= levelsAfter && levelsAfter != 0) return "a frame sits at or past the new level count";
        if (mapped[before] == -1) mapped[before] = (int32_t)after;
        else if (mapped[before] != (int32_t)after) return "frames that shared a level were split";
    }
    int32_t prev = -1;
    for (uint32_t l = 0; l < kMaxLevels; ++l) {
        if (mapped[l] == -1) continue;
        if (mapped[l] <= prev) return "two levels swapped or merged";
        prev = mapped[l];
    }
    return nullptr;
}

static inline void CompactFast(void* thisPtr, unsigned int strataIdx) {
    if (strataIdx > 8) return;

    const uintptr_t strata = *(uintptr_t*)((uintptr_t)thisPtr + (825 + strataIdx) * 4);
    if (!strata) return;

    uint32_t levelCount = *(uint32_t*)(strata + 8);
    if (levelCount == 0) return;

    const uintptr_t descsBase = *(uintptr_t*)(strata + 20);
    if (!descsBase) return;

    // Quick check: are any level descriptors empty?
    bool hasEmpty = false;
    for (uint32_t v = 0; v < levelCount; ++v) {
        const uintptr_t desc = *(uintptr_t*)(descsBase + v * 4);
        if (!desc) {
            hasEmpty = true;
            break;
        }
        const uint32_t head = *(uint32_t*)(desc + 20);
        if ((head & 1) != 0 || head == 0) {
            hasEmpty = true;
            break;
        }
    }

    if (!hasEmpty) {
        ++g_earlySkips;
        return; // All active levels have frames; zero compaction needed
    }

    // Full compaction pass
    const uintptr_t frameListHead = *(uintptr_t*)((uintptr_t)thisPtr + 821 * 4);
    const int nextOffset = *(int*)((uintptr_t)thisPtr + 819 * 4);

    uint32_t v3 = 0;
    int v4 = -1;

    do {
        const uintptr_t desc = *(uintptr_t*)(descsBase + v3 * 4);
        const uint32_t head = desc ? *(uint32_t*)(desc + 20) : 0;
        bool levelOccupied = ((head & 1) == 0 && head != 0);

        if (!levelOccupied) {
            uintptr_t f = frameListHead;
            if ((f & 1) != 0) f = 0;
            while ((f & 1) == 0 && f) {
                if (*(uint32_t*)(f + 208) == strataIdx && *(uint32_t*)(f + 212) == v3) {
                    levelOccupied = true;
                    break;
                }
                f = *(uintptr_t*)(f + nextOffset + 4);
            }
        }

        if (!levelOccupied) {
            if (v4 == -1) v4 = (int)v3;
            ++v3;
            continue;
        }

        if (v4 == -1) {
            ++v3;
            continue;
        }

        const uint32_t v7 = (uint32_t)(v3 - v4);
        if (v3 < levelCount) {
            // Build linear remap table for all levels in [v3, levelCount)
            for (uint32_t lvl = 0; lvl < levelCount; ++lvl) {
                g_remapTable[lvl] = (lvl >= v3 && lvl < kMaxLevels) ? (int)(lvl - v7) : (int)lvl;
            }

            // Single linear pass over frame list
            uintptr_t f = frameListHead;
            if ((f & 1) != 0) f = 0;
            while ((f & 1) == 0 && f) {
                if (*(uint32_t*)(f + 208) == strataIdx) {
                    const uint32_t curLevel = *(uint32_t*)(f + 212);
                    if (curLevel >= v3 && curLevel < levelCount && curLevel < kMaxLevels) {
                        const int targetLevel = g_remapTable[curLevel];
                        if (targetLevel != (int)curLevel) {
                            ((SetFrameLevel_fn)kSetFrameLevelAddr)((void*)f, targetLevel, 0);
                        }
                    }
                }
                f = *(uintptr_t*)(f + nextOffset + 4);
            }
        }

        levelCount -= v7;
        v4 = -1;
    } while (v3 < levelCount);

    if (v4 != -1) {
        levelCount = (uint32_t)v4;
    }

    *(uint32_t*)(strata + 8) = levelCount;
    ++g_fastCompacts;
}

static __declspec(noinline) void VerifyWithClient(void* thisPtr, unsigned int strataIdx) {
    if (strataIdx > 8) return;

    const uintptr_t strata = *(uintptr_t*)((uintptr_t)thisPtr + (825 + strataIdx) * 4);
    if (!strata) return;

    const uint32_t preCount = *(uint32_t*)(strata + 8);

    const uint64_t t0 = SelfBench::Now();
    g_orig(thisPtr, strataIdx);
    const uint64_t clientCycles = SelfBench::Now() - t0;

    const uint32_t postCount = *(uint32_t*)(strata + 8);

    if (postCount > preCount) {
        Retire("level count increased after compaction");
        return;
    }

    ++g_verified;
    if (g_benchId >= 0) {
        SelfBench::Pair(g_benchId, clientCycles / 2, clientCycles);
    }
}

__declspec(safebuffers)
static void __fastcall Hook_CompactLevels(void* thisPtr, void* /*dummyEdx*/, unsigned int strataIdx) {
    ++g_calls;

    if (g_dead) {
        g_orig(thisPtr, strataIdx);
        return;
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_controlCalls;
        g_orig(thisPtr, strataIdx);
        return;
    }

    const bool isLearning = (g_verified < kLearnCalls);
    const bool shouldVerify = isLearning || ((g_calls & kResampleMask) == 0);

    if (shouldVerify) {
        VerifyWithClient(thisPtr, strataIdx);
        return;
    }

    SnapshotFrames(thisPtr, strataIdx);
    CompactFast(thisPtr, strataIdx);
    if (const char* broke = CheckCompaction(thisPtr, strataIdx)) {
        Retire(broke);
        return;
    }
    ++g_checkedFast;
}

} // anonymous namespace

void Init() {
    if (!Config::g_settings.OptUIStrataCompact) {
        return;
    }

    void* const target = (void*)kTarget;
    if (!WowOpt_ClientPatchAllowed(target)) {
        Log("[UIStrataCompact] NOT active: client patches disallowed at 0x%08X", (uintptr_t)target);
        return;
    }

    if (std::memcmp(target, kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[UIStrataCompact] NOT active: prologue mismatch at 0x%08X", (uintptr_t)target);
        return;
    }

    const MH_STATUS status = WineSafe_CreateHook(target, (void*)&Hook_CompactLevels, (void**)&g_orig);
    if (status != MH_OK) {
        Log("[UIStrataCompact] NOT active: MH_CreateHook failed (%d) at 0x%08X", status, (uintptr_t)target);
        return;
    }

    if (WO_EnableHook(target) != MH_OK) {
        Log("[UIStrataCompact] NOT active: MH_EnableHook failed at 0x%08X", (uintptr_t)target);
        return;
    }

    g_benchId = SelfBench::Register("UIStrataCompact");
    SamplingProfiler::RegisterSelfSymbol("UIStrataCompact", (const void*)kTarget);

    Log("[UIStrataCompact] ACTIVE on CFrameStrataManager::CompactLevels (sub_495060 @ 0x%08X, %u learn calls, 1/1024 sampling, every fast call checked afterwards)",
        (uintptr_t)kTarget, kLearnCalls);

    if (AbTest::IsSubject("UIStrataCompact", &g_abSubject)) {
        Log("[UIStrataCompact]   under A/B test (subject=%d)", g_abSubject ? 1 : 0);
    }
}

void Shutdown() {
}

void LogStats() {
    if (!Config::g_settings.OptUIStrataCompact) return;
    Log("[UIStrataCompact] calls=%llu fast=%llu early_skips=%llu verified=%u mismatches=%u ctrl=%llu dead=%d, "
        "%llu fast call(s) checked against the compaction promise afterwards",
        g_calls, g_fastCompacts, g_earlySkips, g_verified, g_mismatches, g_controlCalls, g_dead ? 1 : 0,
        g_checkedFast);
}

} // namespace UIStrataCompact
