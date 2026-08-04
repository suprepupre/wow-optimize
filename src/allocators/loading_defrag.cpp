// ============================================================================
// Module: loading_defrag.cpp
// Description: Speculative pre-committing and VA defragmentation during loading screens.
// Safety & Threading: Safe background thread execution. Main thread updates zone history.
// ============================================================================

#include "loading_defrag.h"
#include "api_cache.h"
#include "diagnostics/crash_dumper.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <atomic>

#pragma comment(lib, "psapi.lib")

// External functions and variables from other modules
extern "C" void Log(const char* fmt, ...);
extern "C" void mi_collect(bool force);
extern "C" void* mi_malloc(size_t size);
extern "C" void mi_free(void* p);

namespace LuaOpt {
    bool IsLoadingMode();
}

namespace LoadingDefrag {

// Function pointer definitions for Lua/FrameScript
typedef void (__cdecl *fn_lua_getfield)(uintptr_t L, int index, const char* k);
static const fn_lua_getfield lua_getfield_ = (fn_lua_getfield)0x0084E590;

typedef void (__cdecl *fn_FrameScript_Execute)(const char* code, const char* source, int unknown);
static const fn_FrameScript_Execute FrameScript_Execute_ = (fn_FrameScript_Execute)0x00819210;

#define LUA_GLOBALSINDEX (-10002)
#define LUA_TSTRING 4

// Background thread state
static HANDLE g_defragThread = nullptr;
static HANDLE g_defragEvent = nullptr;
static std::atomic<bool> g_shutdown{false};
static std::atomic<bool> g_loadingActive{false};

// Zone history tracking
static char g_currentZone[128] = "Unknown";
static char g_lastZone[128] = "Unknown";
static CRITICAL_SECTION g_zoneLock;

// Keep track of visited zones to speculatively adjust pre-commit amount
struct VisitedZone {
    std::string name;
    int visitCount;
};
static std::vector<VisitedZone> g_zoneHistory;

// Speculatively pre-commit pages in mimalloc thread-local slabs
static void PerformSpeculativePrecommit() {
    // Disabled: allocating on the background thread thrashes the background thread's
    // thread-local mimalloc cache, which is not shared with the main thread.
    // This only causes CPU load and page faults during loading screens.
}

// Background thread function
static DWORD WINAPI DefragWorkerThread(LPVOID) {
    Log("[LoadingDefrag] Defrag background worker thread started");
    
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        // Wait for a loading screen trigger
        WaitForSingleObject(g_defragEvent, INFINITE);

        if (g_shutdown.load(std::memory_order_relaxed)) break;

        // Reset before deciding, not after acting. The event is manual-reset, and
        // the reset used to live inside the branch below - so a wake-up that found
        // loading already finished left the event signalled forever and this loop
        // span at full speed on one core for the rest of the session. Reaching that
        // state became easy once the initial world entry started opening and
        // closing the loading window back to back.
        ResetEvent(g_defragEvent);

        if (g_loadingActive.load(std::memory_order_acquire)) {
            // Step 1: Pre-warm mimalloc caches for the new zone
            PerformSpeculativePrecommit();
            
            // Step 2: wait for the loading screen to end. Nothing else.
            //
            // This used to call mi_collect(true) once a second for the whole
            // duration of the load, and that is the worst possible time for it.
            // A forced collect walks every heap, hands pages back to the OS and
            // takes mimalloc's locks - while the main thread is allocating as
            // hard as it ever does, because it is building a zone.
            //
            // A tester measured what that costs. Same machine, same session
            // shape, the only difference being this switch:
            //
            //   DefragLf=1   184 MB loaded in 10171 ms  =  18 MB/s
            //   DefragLf=0   113 MB loaded in  1222 ms  =  94 MB/s
            //
            // and ReadFile accounted for 107 ms of that 10171, so none of it was
            // disk. A module named after making loading screens better was making
            // them five times slower.
            //
            // The lesson was already written three lines further down, where
            // HeapCompact is disabled for stalling the main thread. It just was
            // not carried back up to the loop.
            //
            // The collect below still happens, once, after the screen ends -
            // which is when the zone's transient allocations are actually free to
            // return and nothing is contending for the allocator.
            Log("[LoadingDefrag] Waiting out the loading screen (no collection "
                "while the client is allocating)");

            while (g_loadingActive.load(std::memory_order_acquire) &&
                   !g_shutdown.load(std::memory_order_relaxed))
            {
                Sleep(200);
            }

            // Step 3: single sweep once the loading screen has finished.
            mi_collect(true);

            // Disabled: HeapCompact on GetProcessHeap() locks the default process heap
            // and stalls the main thread for several seconds after loading completes.

            Log("[LoadingDefrag] Loading finished - one collection run");
        }
    }
    
    Log("[LoadingDefrag] Defrag background worker thread shutting down");
    return 0;
}

bool Init() {
    InitializeCriticalSection(&g_zoneLock);
    g_shutdown.store(false);
    g_loadingActive.store(false);
    
    g_defragEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_defragEvent) {
        Log("[LoadingDefrag] Failed to create worker event");
        return false;
    }
    
    g_defragThread = CreateThread(NULL, 0, DefragWorkerThread, NULL, 0, NULL);
    if (!g_defragThread) {
        Log("[LoadingDefrag] Failed to create background worker thread");
        CloseHandle(g_defragEvent);
        g_defragEvent = nullptr;
        return false;
    }
    
    Log("[LoadingDefrag] Module successfully initialized");
    return true;
}

void Shutdown() {
    g_shutdown.store(true);
    if (g_defragEvent) {
        SetEvent(g_defragEvent);
    }
    if (g_defragThread) {
        WaitForSingleObject(g_defragThread, 2000);
        CloseHandle(g_defragThread);
        g_defragThread = nullptr;
    }
    if (g_defragEvent) {
        CloseHandle(g_defragEvent);
        g_defragEvent = nullptr;
    }
    
    DeleteCriticalSection(&g_zoneLock);
    g_zoneHistory.clear();
    Log("[LoadingDefrag] Module shutdown complete");
}

extern "C" void ClearDbcLookupCache();

static DWORD g_loadingStartTick = 0;

void NotifyLoadingState(bool isLoading) {
    if (isLoading) {
        g_loadingStartTick = GetTickCount();
        g_loadingActive.store(true, std::memory_order_release);
        SetEvent(g_defragEvent);
        ApiCache::ClearCache();
        ClearDbcLookupCache();
    } else {
        g_loadingActive.store(false, std::memory_order_release);
    }
}

// Safety net only. Loading now ends on the client's own PLAYER_ENTERING_WORLD
// signal (LoadingState), so this exists purely so a missed end event cannot pin the
// process in loading mode forever. The previous 8s cap was shorter than a real cold
// zone load on a fragmented client, which silently dropped every loading-time
// bypass part-way through the load it was meant to cover.
static constexpr DWORD LOADING_WATCHDOG_MS = 30000;

bool IsLoadingActive() {
    if (g_loadingActive.load(std::memory_order_acquire)) {
        if (GetTickCount() - g_loadingStartTick > LOADING_WATCHDOG_MS) {
            g_loadingActive.store(false, std::memory_order_release);
            CrashDumper::Trace("LOADING watchdog expired after %u ms", (unsigned)LOADING_WATCHDOG_MS);
            Log("[LoadingDefrag] Loading state watchdog expired after %u ms - forcing exit",
                (unsigned)LOADING_WATCHDOG_MS);
            return false;
        }
        return true;
    }
    return false;
}

// Helper to check if string matches GetStackTopFast / SetStackTopFast definitions
static inline uintptr_t GetStackTopFast(uintptr_t L) {
    return *(uintptr_t*)(L + 0x0C);
}

static inline void SetStackTopFast(uintptr_t L, uintptr_t top) {
    *(uintptr_t*)(L + 0x0C) = top;
}

static bool TryGetZoneName(uintptr_t L, char* outName, size_t outSize) {
    __try {
        if (FrameScript_Execute_) {
            FrameScript_Execute_("if GetRealZoneText then LUABOOST_CURRENT_ZONE = GetRealZoneText() else LUABOOST_CURRENT_ZONE = nil end", "loading_defrag", 0);
            
            // Read it from the stack using lua_getfield
            lua_getfield_(L, LUA_GLOBALSINDEX, "LUABOOST_CURRENT_ZONE");
            uintptr_t top = GetStackTopFast(L);
            if (top >= 0x10) {
                int tt = *(int*)(top - 8);
                if (tt == LUA_TSTRING) {
                    uintptr_t ts = *(uintptr_t*)(top - 16);
                    if (ts >= 0x10000) {
                        const char* zoneName = (const char*)(ts + 20);
                        if (zoneName && strlen(zoneName) < outSize - 1) {
                            strcpy_s(outName, outSize, zoneName);
                            SetStackTopFast(L, top - 16);
                            return true;
                        }
                    }
                }
            }
            // Pop the value from the stack to keep it clean
            SetStackTopFast(L, top - 16);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // Safe fallback
    }
    return false;
}

static void UpdateZoneHistory(const char* zoneName) {
    EnterCriticalSection(&g_zoneLock);
    strcpy_s(g_currentZone, sizeof(g_currentZone), zoneName);
    
    // If a new zone was entered, log and record it
    if (strcmp(g_currentZone, g_lastZone) != 0) {
        Log("[LoadingDefrag] Zone transitioned: '%s' -> '%s'", g_lastZone, g_currentZone);
        strcpy_s(g_lastZone, sizeof(g_lastZone), g_currentZone);
        
        // Update history
        bool found = false;
        for (auto& zone : g_zoneHistory) {
            if (zone.name == g_currentZone) {
                zone.visitCount++;
                found = true;
                break;
            }
        }
        if (!found) {
            g_zoneHistory.push_back({g_currentZone, 1});
        }
    }
    LeaveCriticalSection(&g_zoneLock);
}

void OnFrame() {
    #if !TEST_DISABLE_DEFRAG_LF
    DWORD now = GetTickCount();
    static DWORD lastCollect = 0;
    if (g_loadingActive.load(std::memory_order_acquire)) {
        if (now - lastCollect >= 500) {
            mi_collect(true);
            lastCollect = now;
        }
        return;
    } else {
        if (now - lastCollect >= 30000) {
            mi_collect(false);
            lastCollect = now;
        }
    }
    #endif
}

} // namespace LoadingDefrag
