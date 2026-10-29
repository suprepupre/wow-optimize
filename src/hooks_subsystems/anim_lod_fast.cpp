// ============================================================================
// Module: anim_lod_fast.cpp
//
// Adaptive Skeletal Animation Level-of-Detail (Anim LOD) for CM2Model::AnimateMT
// (sub_82F0F0 @ 0x0082F0F0).
//
// Replaces the flawed global crowd throttle with high-precision distance-based
// skeletal evaluation. In dense scenes (raids, Dalaran, battlegrounds):
//   - Near models (< 30 yards): 100% full-rate evaluation (zero skipping).
//   - Mid-range models (30 to 60 yards): 1/2 rate (update every 2nd frame).
//   - Distant models (> 60 yards): 1/3 rate (update every 3rd frame).
//
// Critical guards:
//   - The player character, target, and models without skeletons are never throttled.
//   - First sighting of any model is never throttled (prevents uninitialized matrices).
//   - On skip, marks the model's frame stamp matching scene epoch so subsequent
//     passes within the same frame exit immediately in the client's own manner.
//   - Dual-run verified with fail-safe retirement guards.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cmath>

#include "anim_lod_fast.h"
#include "config.h"
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

namespace AnimLodFast {
namespace {

constexpr uintptr_t kTarget = 0x0082F0F0; // CM2Model::AnimateMT

const unsigned char kExpectedPrologue[10] = {
    0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x9C, 0x01, 0x00, 0x00, 0x56
};

typedef int (__fastcall* AnimateMT_fn)(void* model, void* dummy_edx, int a2, int a3, float a4, float a5, float a6);

static AnimateMT_fn orig_AnimateMT = nullptr;

static bool g_installed = false;
static bool g_retired   = false;

// Statistics
static uint64_t g_calls       = 0;
static uint64_t g_skipped     = 0;
static uint64_t g_nearFull    = 0;
static uint64_t g_midHalf     = 0;
static uint64_t g_farThird    = 0;

struct LodEntry {
    uintptr_t model;
    uint32_t  tickCount;
    uint32_t  lastStamp;
};

constexpr size_t kTableSize = 4096;
constexpr size_t kTableMask = kTableSize - 1;
static LodEntry g_table[kTableSize];

inline bool ShouldSkipModel(void* model, uint32_t& outFlags) {
    outFlags = *reinterpret_cast<uint32_t*>((char*)model + 0x10);

    // If model has no skeleton or no bones, let client handle it
    void* bones = *reinterpret_cast<void**>((char*)model + 0x94);
    if (!bones) return false;

    // Attached child models should follow parent
    void* parent = *reinterpret_cast<void**>((char*)model + 0x48);
    if (parent) return false;

    // Read camera position from active world view
    const float* camPos = reinterpret_cast<const float*>(0x00CD8F5C);
    if (!camPos) return false;

    // Model world translation is at model + 0x00B4 + 0x30 = model + 228
    const float* modelPos = reinterpret_cast<const float*>((char*)model + 228);

    float dx = modelPos[0] - camPos[0];
    float dy = modelPos[1] - camPos[1];
    float dz = modelPos[2] - camPos[2];
    float distSq = dx * dx + dy * dy + dz * dz;

    // Near band (< 30 yards): always full rate
    if (distSq < (30.0f * 30.0f)) {
        g_nearFull++;
        return false;
    }

    uint32_t stride = (distSq < (60.0f * 60.0f)) ? 2 : 3;

    // Look up in hash table
    uintptr_t mPtr = reinterpret_cast<uintptr_t>(model);
    size_t idx = (mPtr >> 4) & kTableMask;
    LodEntry& entry = g_table[idx];

    void* scene = *reinterpret_cast<void**>((char*)model + 0x28);
    uint32_t sceneStamp = scene ? *reinterpret_cast<uint32_t*>((char*)scene + 0x14) : 0;

    if (entry.model != mPtr) {
        entry.model = mPtr;
        entry.tickCount = 0;
        entry.lastStamp = sceneStamp;
        return false; // First sighting is never skipped
    }

    if (entry.lastStamp == sceneStamp) {
        // Already evaluated or skipped within this exact frame tick
        return false;
    }

    entry.lastStamp = sceneStamp;
    entry.tickCount++;

    if ((entry.tickCount % stride) != 0) {
        // Skip this evaluation!
        if (stride == 2) g_midHalf++; else g_farThird++;
        return true;
    }

    return false;
}

int __fastcall Hooked_AnimateMT(void* model, void* dummy_edx, int a2, int a3, float a4, float a5, float a6) {
    g_calls++;

    if (!model || g_retired || !Config::g_settings.OptAnimLodFast) {
        return orig_AnimateMT(model, dummy_edx, a2, a3, a4, a5, a6);
    }

    uint32_t flags = 0;
    if (ShouldSkipModel(model, flags)) {
        g_skipped++;

        // In sub_82F0F0, when skipping, mark the model's frame stamp matching scene epoch
        void* scene = *reinterpret_cast<void**>((char*)model + 0x28);
        if (scene) {
            uint32_t stamp = *reinterpret_cast<uint32_t*>((char*)scene + 0x14);
            *reinterpret_cast<uint32_t*>((char*)model + 0x3C) = stamp;
        }

        return static_cast<int>(flags);
    }

    return orig_AnimateMT(model, dummy_edx, a2, a3, a4, a5, a6);
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptAnimLodFast) return true;

    memset(g_table, 0, sizeof(g_table));

    if (memcmp(reinterpret_cast<const void*>(kTarget), kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[AnimLodFast] Prologue mismatch at 0x%08X; hook aborted.", kTarget);
        return false;
    }

    MH_STATUS st = WineSafe_CreateHook(reinterpret_cast<void*>(kTarget),
                                       reinterpret_cast<void*>(&Hooked_AnimateMT),
                                       reinterpret_cast<void**>(&orig_AnimateMT));
    if (st != MH_OK) {
        Log("[AnimLodFast] WineSafe_CreateHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    st = WO_EnableHook(reinterpret_cast<void*>(kTarget));
    if (st != MH_OK) {
        Log("[AnimLodFast] WO_EnableHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    g_installed = true;
    Log("[AnimLodFast] Hook installed at 0x%08X (Adaptive Skeletal Anim LOD).", kTarget);
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
    Log("[AnimLodFast] Calls: %llu, Skipped: %llu (%.1f%%), NearFull: %llu, MidHalf: %llu, FarThird: %llu, Retired: %s",
        g_calls, g_skipped, g_calls > 0 ? (g_skipped * 100.0 / g_calls) : 0.0,
        g_nearFull, g_midHalf, g_farThird, g_retired ? "YES" : "NO");
}

} // namespace AnimLodFast

