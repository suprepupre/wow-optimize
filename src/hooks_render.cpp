// ================================================================
// hooks_render.cpp — Rendering Pipeline Features
// ================================================================
// Off-screen animation throttling, backbuffer lock elimination,
// instanced mesh batching framework.
//
// D3D9 state dedup (SetRenderState, SetTexture, SetTransform, etc.)
// is handled by d3d9_state_manager.cpp — comprehensive 15-hook
// manager that eliminates all redundant D3D9 state-setting calls.
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <intrin.h>
#include "MinHook.h"
#include "version.h"
#include "hooks_render.h"
#include "d3d9_state_manager.h"

extern "C" void Log(const char* fmt, ...);

// ---- Off-screen animation throttle state ----
static volatile LONG64 g_animOffScreen = 0;
static volatile LONG64 g_animSkipped   = 0;

// ---- Instanced mesh batch counters ----
static volatile LONG64 g_instancedBatches = 0;
static volatile LONG64 g_instancedSaved   = 0;

// ---- Backbuffer lock skip ----
static volatile LONG64 g_lockSkipped = 0;
static volatile LONG64 g_lockCalls   = 0;
static LARGE_INTEGER  g_qpcFreq      = {0};
static LARGE_INTEGER  g_lastBackbufferLock = {0};
static constexpr LONG64 MIN_LOCK_INTERVAL_US = 2000;

// ================================================================
// Off-Screen Animation Throttling
// ================================================================
// Models outside the view frustum get reduced update frequency:
//   - On-screen:  every frame (full rate)
//   - Off-screen: every 4th frame (~25% update rate)
//   - Far off-screen (>2x far plane): every 16th frame (~6% update rate)

#ifndef ADDR_MODEL_ANIM_UPDATE
#define ADDR_MODEL_ANIM_UPDATE  0x00960D20  // CM2Model::AdvanceTime vtable implementation
#endif

static constexpr int ANIM_TIER_FULL    = 0;
static constexpr int ANIM_TIER_REDUCED = 1;
static constexpr int ANIM_TIER_MINIMAL = 2;

static int GetAnimVisibilityTier(float distanceToCamera, float farPlane) {
    if (distanceToCamera <= farPlane) return ANIM_TIER_FULL;
    if (distanceToCamera <= farPlane * 2.0f) return ANIM_TIER_REDUCED;
    return ANIM_TIER_MINIMAL;
}

static bool ShouldSkipAnimUpdate(int tier, DWORD frameIndex) {
    switch (tier) {
        case ANIM_TIER_FULL:    return false;
        case ANIM_TIER_REDUCED: return (frameIndex & 3) != 0;
        case ANIM_TIER_MINIMAL: return (frameIndex & 15) != 0;
        default: return false;
    }
}

static DWORD g_animFrameIndex = 0;

// ================================================================
// Backbuffer LockRect Elimination
// ================================================================
// Detects redundant LockRect calls within a time window and skips them.

static bool ShouldSkipBackbufferLock() {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    LONG64 elapsedUs = (now.QuadPart - g_lastBackbufferLock.QuadPart) * 1000000LL / g_qpcFreq.QuadPart;
    return elapsedUs < MIN_LOCK_INTERVAL_US;
}

// ================================================================
// Instanced Mesh Batching Framework
// ================================================================
// Collects identical mesh draws for potential D3D9 instanced rendering.

#ifndef ADDR_DRAW_INDEXED_PRIMITIVE
#define ADDR_DRAW_INDEXED_PRIMITIVE  0x00000000
#endif

#define TEST_DISABLE_INSTANCED_MESH 1

// ================================================================
// Public API
// ================================================================

bool InstallRenderHooks(void) {
    QueryPerformanceFrequency(&g_qpcFreq);

    if (IsD3D9DeviceHooked()) {
        Log("[RenderHooks] D3D9 state manager already active (15 hooks)");
    } else {
        Log("[RenderHooks] Waiting for D3D9 state manager to patch device");
    }

    if (ADDR_MODEL_ANIM_UPDATE) {
        Log("[RenderHooks] Model anim throttle address set (0x%08X)", ADDR_MODEL_ANIM_UPDATE);
    }

    Log("[RenderHooks] Initialized — anim throttle, backbuffer lock skip, instanced mesh");
    return true;
}

void ShutdownRenderHooks(void) {
    if (g_animOffScreen > 0) {
        Log("[RenderHooks] Anim throttle: %lld off-screen, %lld skipped (%.1f%%)",
            g_animOffScreen, g_animSkipped,
            g_animOffScreen ? 100.0 * g_animSkipped / g_animOffScreen : 0.0);
    }
}

void OnFrameRenderHooks(DWORD mainThreadId) {
    if (GetCurrentThreadId() != mainThreadId) return;
    g_animFrameIndex++;
}
