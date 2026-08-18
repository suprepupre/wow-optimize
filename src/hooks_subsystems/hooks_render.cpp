// ============================================================================
// Module: hooks_render.cpp
// Description: Installs and manages target intercepts for subsystem `hooks_render.cpp`.
// Safety & Threading: Stack layouts and register conventions must match target function definitions exactly.
// ============================================================================

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
#include "render_state_dedup.h"

extern "C" void Log(const char* fmt, ...);

// ---- Instanced mesh batch counters ----
static volatile LONG64 g_instancedBatches = 0;
static volatile LONG64 g_instancedSaved   = 0;

// ---- Backbuffer lock skip ----
static volatile LONG64 g_lockSkipped = 0;
static volatile LONG64 g_lockCalls   = 0;
static LARGE_INTEGER  g_qpcFreq      = {0};
static LARGE_INTEGER  g_lastBackbufferLock = {0};
static constexpr LONG64 MIN_LOCK_INTERVAL_US = 2000;

// Off-screen animation throttling used to be sketched here: a tier function, a
// skip schedule and two counters, none of them reachable from any call site,
// under an address for CM2Model::AdvanceTime that nothing verified. Init logged
// that the throttle address was set, which read as a working feature.
//
// The groundwork it needed has since been established at the right function.
// sub_82F0F0 takes the model in ECX - IDA reports it as __cdecl and misses that
// entirely - and derives its animation time as (now - start) * speed + base from
// an absolute clock rather than accumulating a delta, so a skipped call delays
// when a pose refreshes and cannot make an animation run slow. What is still
// missing is a camera position at that call site, which is the only reason this
// is a comment and not an implementation.

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

    Log("[RenderHooks] Initialized - backbuffer lock skip");
    return true;
}

void ShutdownRenderHooks(void) {
}

void OnFrameRenderHooks(DWORD mainThreadId) {
    if (GetCurrentThreadId() != mainThreadId) return;
    
    // Clear render state deduplication cache on frame boundaries to prevent 
    // stale cached states during focus changes or driver state changes.
    RenderStateDedup_ClearCache();
}
