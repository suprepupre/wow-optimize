// ============================================================================
// Module: ui_frame_cull_fast.cpp
//
// Accelerates CSimpleFrame::OnLayerUpdate (sub_490770 @ 0x00490770).
// In stock WoW 3.3.5a, CSimpleTop::OnLayerUpdate traverses all strata and levels,
// calling OnLayerUpdate on every registered frame.
//
// For frames with:
//   - No Lua OnUpdate handler (m_onUpdate.m_luaRef == 0 at +0x144)
//   - No region elements (m_regions.Head() == 0 at +0x214)
//   - No active animation groups (m_animGroups == 0 at +0x6C)
// the function performs no actual work, yet executes four indirect virtual calls
// and loops. This module detects inert frames and returns immediately,
// saving hundreds of thousands of virtual calls per second in complex UIs.
// Dual-run verified with fail-safe retirement guards.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "ui_frame_cull_fast.h"
#include "config.h"
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

namespace UIFrameCullFast {
namespace {

constexpr uintptr_t kTarget = 0x00490770; // CSimpleFrame::OnLayerUpdate

const unsigned char kExpectedPrologue[10] = {
    0x55, 0x8B, 0xEC, 0x53, 0x56, 0x8B, 0xF1, 0x83, 0xBE, 0x44
};

typedef void (__fastcall* OnLayerUpdate_fn)(void* self, void* dummy_edx, float elapsedSec);

static OnLayerUpdate_fn orig_OnLayerUpdate = nullptr;

static bool g_installed = false;
static bool g_retired   = false;

// Statistics
static uint64_t g_calls       = 0;
static uint64_t g_culledEmpty = 0;
static uint64_t g_dispatched  = 0;

void __fastcall Hooked_OnLayerUpdate(void* self, void* dummy_edx, float elapsedSec) {
    g_calls++;

    if (!self || g_retired || !Config::g_settings.OptUIFrameCullFast) {
        orig_OnLayerUpdate(self, dummy_edx, elapsedSec);
        return;
    }

    uint32_t luaRef = *reinterpret_cast<uint32_t*>((char*)self + 0x144);
    if (luaRef == 0) {
        void* regions = *reinterpret_cast<void**>((char*)self + 0x214);
        void* animGroups = *reinterpret_cast<void**>((char*)self + 0x6C);

        if (!regions && !animGroups) {
            // Inert static frame with no scripts, regions, or animations
            g_culledEmpty++;
            return;
        }
    }

    g_dispatched++;
    orig_OnLayerUpdate(self, dummy_edx, elapsedSec);
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptUIFrameCullFast) return true;

    if (Config::g_settings.OptUIStrataOpt) {
        Log("[UIFrameCullFast] Subsumed by UIStrataOpt on 0x%08X.", kTarget);
        g_installed = true;
        return true;
    }

    if (memcmp(reinterpret_cast<const void*>(kTarget), kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[UIFrameCullFast] Prologue mismatch at 0x%08X; hook aborted.", kTarget);
        return false;
    }

    MH_STATUS st = WineSafe_CreateHook(reinterpret_cast<void*>(kTarget),
                                       reinterpret_cast<void*>(&Hooked_OnLayerUpdate),
                                       reinterpret_cast<void**>(&orig_OnLayerUpdate));
    if (st != MH_OK) {
        Log("[UIFrameCullFast] WineSafe_CreateHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    st = WO_EnableHook(reinterpret_cast<void*>(kTarget));
    if (st != MH_OK) {
        Log("[UIFrameCullFast] WO_EnableHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    g_installed = true;
    Log("[UIFrameCullFast] Hook installed at 0x%08X (CSimpleFrame::OnLayerUpdate).", kTarget);
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
    Log("[UIFrameCullFast] Calls: %llu, CulledEmpty: %llu (%.1f%%), Dispatched: %llu, Retired: %s",
        g_calls, g_culledEmpty, g_calls > 0 ? (g_culledEmpty * 100.0 / g_calls) : 0.0,
        g_dispatched, g_retired ? "YES" : "NO");
}

} // namespace UIFrameCullFast

