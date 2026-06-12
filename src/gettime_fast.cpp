// ================================================================
// GetTime() Fast Path
// ================================================================
// WoW's GetTime() Lua function calls GetTickCount() which is a kernel
// syscall. During combat with heavy addon activity, this is called
// millions of times per session. We cache the result per-frame using
// the Sleep hook's frame boundary detection.
//
// Also optimizes the C-level GetTickCount() calls within WoW's engine
// by caching the result for the duration of each frame (~16ms at 60fps).
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

// Statistics
static volatile LONG64 g_gettime_calls = 0;
static volatile LONG64 g_gettime_hits = 0;

// Frame-cached tick count
static volatile DWORD g_cachedTickCount = 0;
static volatile DWORD g_lastFrameTick = 0;

// Original function pointers
typedef DWORD (WINAPI* GetTickCount_fn)(void);
static GetTickCount_fn g_orig_GetTickCount = nullptr;

// Hooked GetTickCount - returns cached value within same frame
static DWORD WINAPI Hooked_GetTickCount(void) {
    InterlockedIncrement64(&g_gettime_calls);
    
    DWORD cached = g_cachedTickCount;
    if (cached != 0 && cached == g_lastFrameTick) {
        InterlockedIncrement64(&g_gettime_hits);
        return cached;
    }
    
    // Cache miss or new frame - call original and update cache
    DWORD result = g_orig_GetTickCount();
    g_cachedTickCount = result;
    g_lastFrameTick = result;
    return result;
}

// Called from Sleep hook at frame boundary to invalidate cache
extern "C" void GetTimeFast_NewFrame(void) {
    // Invalidate cache so next GetTickCount call fetches fresh value
    g_lastFrameTick = 0;
}

bool InstallGetTimeFast(void) {
    // DISABLED: GetTickCount is already hooked by our QPC precision hook.
    // Double-hooking causes MH_CreateHook to fail. The QPC hook already
    // provides microsecond precision which is better than frame caching.
    // Frame-cached GetTickCount would conflict with the existing hook chain.
    Log("[GetTimeFast] SKIPPED: GetTickCount already hooked by QPC precision hook");
    return false;
}

void ShutdownGetTimeFast(void) {
    if (g_orig_GetTickCount) {
        MH_DisableHook((void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount"));
    }
    
    LONG64 calls = g_gettime_calls;
    LONG64 hits = g_gettime_hits;
    if (calls > 0) {
        Log("[GetTimeFast] Stats: %lld calls, %lld cached (%.1f%%)",
            calls, hits, 100.0 * hits / calls);
    }
}