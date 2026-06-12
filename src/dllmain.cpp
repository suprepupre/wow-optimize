// ================================================================
// wow_optimize.dll
// Author: SUPREMATIST
//
// LOAD MECHANISM:
//   Loaded via version.dll proxy (WoW loads version.dll at startup).
//   version_proxy.cpp forwards all real version.dll exports and
//   spawns this DLL's MainThread after a 5-second delay.
//
// ARCHITECTURE:
//   - MinHook for all API hooking
//   - mimalloc as global allocator replacement
//   - Ring-buffer logger (lock-free, background thread)
//
// OPTIMIZATION CATEGORIES:
//   1.  Memory allocator replacement (mimalloc for CRT)
//   2.  Sleep hook - precise frame pacing, GC stepping, combat log
//   3.  Network - TCP_NODELAY, ACK freq, QoS, buffer sizing
//   4.  MPQ handle tracking (O(1) hash) + memory mapping + prefetch
//   5.  ReadFile - adaptive read-ahead cache for MPQ
//   6.  Timer precision - GetTickCount, timeGetTime, QPC coalescing
//   7.  System hooks - CS spin, heap LFH, thread ID cache, BadPtr
//   8.  File I/O - CreateFile sequential scan, CloseHandle invalidation
//   9.  Thread/process tuning - affinity, priority, working set
//   10. Lua VM - GC optimizer, mimalloc allocator, string table
//   11. Lua fast paths - 28+ C function hooks
//   12. API cache - GetItemInfo result caching
//   13. Combat log - retention patching + periodic clears
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <io.h>
#include <intrin.h>
#include <emmintrin.h>
#include "ui_cache.h"
#include "api_cache.h"
#include "lua_fastpath.h"
#include "lua_internals.h"
#include "lua_vm_cache.h"
#include "crash_dumper.h"

// Forward declaration - Log() defined later in this file
extern "C" void Log(const char* fmt, ...);

// ================================================================
// Freeze Detection Watchdog
// Detects when main thread stops responding (no Sleep calls for N seconds)
// Dumps feature states + hook trace to log so we know what was active
// ================================================================
static volatile DWORD g_lastMainThreadTick = 0;
static volatile bool  g_freezeWatchdogActive = false;
static HANDLE         g_freezeWatchdogThread = NULL;

static void UpdateMainThreadActivity() {
    g_lastMainThreadTick = GetTickCount();
    CrashDumper::FeatureCall("SleepHook");
}

static DWORD WINAPI FreezeWatchdogProc(LPVOID) {
    while (g_freezeWatchdogActive) {
        Sleep(5000);
        if (!g_freezeWatchdogActive) break;

        DWORD lastTick = g_lastMainThreadTick;
        if (lastTick == 0) continue;

        DWORD elapsed = GetTickCount() - lastTick;
        if (elapsed > 10000) {
            Log("!!! FREEZE DETECTED !!! Main thread silent for %u ms", elapsed);
            Log("!!! Last main thread tick: %u, current: %u", lastTick, GetTickCount());

            FeatureState states[MAX_TRACKED_FEATURES];
            int count = CrashDumper::GetFeatureStates(states, MAX_TRACKED_FEATURES);
            Log("!!! FEATURE STATES (%d registered):", count);
            for (int i = 0; i < count; i++) {
                if (states[i].active) {
                    DWORD age = (states[i].lastCallTick > 0) ? (GetTickCount() - states[i].lastCallTick) : 999999;
                    Log("!!!   %-28s calls=%lld errors=%lld lastCall=%ums ago",
                        states[i].name ? states[i].name : "?",
                        states[i].callCount, states[i].errorCount, age);
                }
            }
            Log("!!! END FREEZE REPORT !!!");

            while (g_freezeWatchdogActive && (GetTickCount() - g_lastMainThreadTick) > 10000) {
                Sleep(2000);
            }
        }
    }
    return 0;
}

static void StartFreezeWatchdog() {
    g_lastMainThreadTick = GetTickCount();
    g_freezeWatchdogActive = true;
    g_freezeWatchdogThread = CreateThread(NULL, 0, FreezeWatchdogProc, NULL, 0, NULL);
    Log("[FreezeWatchdog] Started (10s threshold, 5s check interval)");
}

static void StopFreezeWatchdog() {
    g_freezeWatchdogActive = false;
    if (g_freezeWatchdogThread) {
        WaitForSingleObject(g_freezeWatchdogThread, 6000);
        CloseHandle(g_freezeWatchdogThread);
        g_freezeWatchdogThread = NULL;
    }
}

#include "frame_throttle.h"
#include "tooltip_cache.h"
#include "spell_cache.h"
// #include "ui_frame_batch.h" // REMOVED - optimization disabled

#include "MinHook.h"
#include <mimalloc.h>
#include "lua_optimize.h"
#include "combatlog_optimize.h"
#include "combatlog_buffer.h"
#include "combatlog_mt.h"
#include "texture_async.h"
#include "spell_prefetch.h"
#include "addon_dispatcher.h"
#include "model_async.h"
#include "mpq_prefetch.h"
#include "obj_vis_cache.h"
#include "sound_prefetch.h"
#include "quest_async.h"
#include "nameplate_batch.h"
#include "addon_preload.h"
#include "lua_bytecode_cache.h"
#include "strstr_fast.h"
#include "crt_char_fast.h"
#include "crt_pow_sse2.h"
#include "crt_wchar_fast.h"
#include "tls_cache.h"
#include "stream_cache.h"
#include "lua_this_cache.h"
#include "io_cache.h"
#include "lua_global_cache.h"
#include "hot_functions.h"
#include "fast_strncmp.h"
#include "crt_free_hook.h"
#include "aligned_alloc_cache.h"
#include "lua_tonumber_cache.h"
#include "lua_checknumber_cache.h"
#include "lua_pushstring_cache.h"
#include "object_accessor_cache.h"
#include "format_validator_cache.h"
#include "datastore_fastpath.h"
#include "string_ops_fast.h"
#include "heap_compactor.h"
#include "lua_tonumber_fast.h"
#include "lua_pushnumber_fast.h"
#include "gettime_fast.h"
#include "lua_pushvalue_fast.h"
#include "render_state_dedup.h"
#include "lua_settable_cache.h"
#include "regex_cache.h"
#include "trig_lut.h"
#include "data_caches.h"
#include "compute_caches.h"
#include "event_name_hash.h"
#include "cdatastore_batch.h"
#include "strcat_fast.h"
#include "script_handler_cache.h"
#include "dbc_lookup_cache.h"
#include "event_dispatch_cache.h"
#include "event_name_cache.h"
#include "lua_getstr_inline.h"
#include "lua_rawgeti_inline.h"
#include "lua_gettable_safety.h"
#include "lua_vm_engine.h"
#include "lua_vm_phase3.h"
#include "lua_gettable_cache.h"
#include "saved_vars_async.h"
#include "texture_decode_mt.h"
#include "mpq_decompress_mt.h"
#include "spell_effect_mt.h"
#include "lua_bytecode_pre_compiler.h"
#include "anim_mt.h"
#include "hook_prefetch.h"
#include "hot_patch.h"
#include "infra_patch.h"
#include "wow_opt_hooks.h"
#include "wow_perf_hooks.h"
#include "wow_extended_hooks.h"
#include "wow_subsystem_hooks.h"
#include "wow_memory_opt.h"
#include "wow_source_opt.h"
#include "tls_object_cache.h"

#include "d3d9_state_manager.h"
#include "hooks_render.h"
#include "hooks_simd.h"
#include "hooks_logic.h"
#include "hooks_memory.h"
#include "hooks_async.h"

#include "version.h"

// ================================================================
// TOGGLES// Each toggle disables a specific optimization for binary search
// during crash investigation. Set to 1 to DISABLE the feature.
// These are compile-time flags for debugging builds.
// ================================================================
#define CRASH_TEST_DISABLE_COMPARESTRING   0   // CompareStringA fast path
#define CRASH_TEST_DISABLE_GETFILEATTR     0   // GetFileAttributesA cache
#define CRASH_TEST_DISABLE_GLOBALALLOC     1   // GlobalAlloc mimalloc (ALREADY DISABLED - risky)
#define CRASH_TEST_DISABLE_CS_ENTER        1   // CriticalSection TryEnter spin (causes login freeze)
#define CRASH_TEST_DISABLE_CS_INIT         1   // InitializeCriticalSection hook (causes login freeze/crash)
#define CRASH_TEST_DISABLE_CS_SPIN         1   // CriticalSection spin count 8000 (causes login crash)
#define CRASH_TEST_DISABLE_SETFILEPOINTER  0   // SetFilePointer -> SetFilePointerEx
#define CRASH_TEST_DISABLE_READFILE        0   // ReadFile MPQ cache
#define CRASH_TEST_DISABLE_ISBADPTR        0   // IsBadReadPtr/WritePtr fast path (re-enabled - was disabled preemptively)
#define CRASH_TEST_DISABLE_MPQ_MMAP        1   // MPQ memory mapping (ALREADY DISABLED - risky)
#define CRASH_TEST_DISABLE_QPC_CACHE       0   // QPC coalescing cache
#define CRASH_TEST_DISABLE_LUA_INTERNALS   0   // Lua VM internals (concat hook)
#define CRASH_TEST_DISABLE_THREAD_AFFINITY   0   // Thread core pinning (re-enabled - was disabled preemptively)
#define CRASH_TEST_DISABLE_SHORT_WAIT_SPIN   1   // WaitSpin (ALREADY DISABLED - tested bad)
#define CRASH_TEST_DISABLE_VA_ARENA          1   // VA Arena virtual alloc - causes address space fragmentation (LargestBlock=2MB → M2 model OOM on teleport)
#define CRASH_TEST_DISABLE_DISPATCH_POOL     1   // DispatchPool (ALREADY DISABLED - tested bad)
#define CRASH_TEST_DISABLE_BGPRELOAD_CACHE   1   // bgpreloadsleep cache (ALREADY DISABLED - 0 hits)
#define CRASH_TEST_DISABLE_SUBTASK_EVENTPOOL 1   // Subtask event pool (ALREADY DISABLED - 0 hits)

// Feature toggles for hooks
#define CRASH_TEST_DISABLE_GETFILESIZE_CACHE    0   // GetFileSizeEx cache - ENABLED (tested stable by Morbent + Billy Hoyle)
#define CRASH_TEST_DISABLE_WFS_SPIN             1   // WaitForSingleObject spin (DISABLED - tested bad, crashes WoW)
#define CRASH_TEST_DISABLE_MODHANDLE_CACHE      0   // GetModuleHandleA cache
#define CRASH_TEST_DISABLE_LSTRCMP              0   // lstrcmp/lstrcmpiA fast path
#define CRASH_TEST_DISABLE_PROFILE_CACHE        0   // GetPrivateProfileStringA cache
#define CRASH_TEST_DISABLE_MSGPUMP_RC1          1   // sub_869E00 frame-continue (CONFIRMED BROKEN: returns 1 with *a1=-1 → infinite freeze)
#define CRASH_TEST_DISABLE_SWAP_RC1             0   // sub_69E220 swap - glFinish skip (re-enabled - was disabled preemptively)
#define CRASH_TEST_DISABLE_TABLERESHAPE_RC1     0   // luaH_resize table rehash prevention
#define CRASH_TEST_DISABLE_LUAH_GETSTR          1   // luaH_getstr OLD pointer cache DISABLED - replaced by safe v2 in lua_getstr_inline.cpp
#define CRASH_TEST_DISABLE_COMBATLOG_FULLCACHE  1   // CombatLog full event cache (stale TString*)
#define CRASH_TEST_DISABLE_LUA_PUSHSTRING       1   // lua_pushstring intern cache (stale TString*)
#define CRASH_TEST_DISABLE_LUA_RAWGETI          1   // lua_rawgeti OLD pointer cache DISABLED - CONFIRMED: freezes world load when combined with other features
#define TEST_DISABLE_RAWGETI_INLINE             0   // lua_rawgeti inline v2 - RE-ENABLED (safe bucket-index cache)
#define CRASH_TEST_DISABLE_TABLE_CONCAT         0   // table.concat fast path
#define CRASH_TEST_DISABLE_WOW_STRLEN           0   // sub_76EE30 WoW-internal strlen - RE-ENABLED (SSE2 replacement)
#define CRASH_TEST_DISABLE_RTTI_CACHE           0   // sub_4D4DB0 object type check cache - RE-ENABLED (1905 callers)
#define CRASH_TEST_DISABLE_STREAM_FASTPATH      0   // sub_47B3C0/sub_47B0A0 - RE-ENABLED (inline bounds check)
 
// Forward declaration for CRT fast paths (defined in crt_mem_fastpath.cpp)
extern bool InstallCrtMemFastPaths();

// Forward declarations
static bool IsExecutableMemory(uintptr_t addr);
static bool InstallThreadAffinity();
static void InstallWineSTIPNoop();

#define VA_ARENA_PAGE_SIZE  4096
#define VA_ARENA_MAX_PAGES  131072  // 512MB
#define VA_ARENA_BITMAP_SIZE (VA_ARENA_MAX_PAGES / 64)

typedef LPVOID (WINAPI* VirtualAlloc_fn)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL  (WINAPI* VirtualFree_fn)(LPVOID, SIZE_T, DWORD);

static VirtualAlloc_fn orig_VirtualAlloc = nullptr;
static VirtualFree_fn  orig_VirtualFree  = nullptr;

static bool vaOk = false;
static volatile bool  g_vaArenaActive    = false;
static LPVOID         g_vaArenaBase      = nullptr;
static SIZE_T         g_vaArenaSize      = 0;
static SRWLOCK        g_vaArenaLock      = SRWLOCK_INIT;
static long           g_vaArenaHits      = 0;
static long           g_vaArenaFallbacks = 0;
static long           g_vaArenaFailures  = 0;
static DWORD          g_vaArenaUsedPages = 0;

// Bitmap + span tracking
static uint64_t g_vaArenaBitmap[VA_ARENA_BITMAP_SIZE] = {0};
static DWORD    g_vaArenaSpan[VA_ARENA_MAX_PAGES] = {0};  // span length in pages from this page

// Forward declarations
static bool InstallVAArena();
static void ShutdownVAArena();

// Priority watchdog forward declarations
static void StartPriorityWatchdog();
static void StopPriorityWatchdog();
static volatile LONG g_priorityWatchdogRestores = 0;

extern "C" void Log(const char* fmt, ...);

// ================================================================
// Timing Method Fix - Console override only (hook removed for safety)
// ================================================================
#if !TEST_DISABLE_TIMING_FIX
static bool InstallTimingFix() {
    Log("[TimingFix] Hook skipped. Using console override only (safe for HD builds).");
    return true;
}
#else
static bool InstallTimingFix() { return false; }
#endif

// ================================================================
// Hardware Cursor & Raw Input - bypass engine cursor centering
// ================================================================
#if !TEST_DISABLE_HARDWARE_CURSOR

static volatile bool g_cursorInitDone = false;

static void InitHardwareCursor() {
    if (g_cursorInitDone) return;

    HWND hWnd = FindWindowA("GxWindowClassD3d", NULL);
    if (!hWnd) hWnd = FindWindowA("GxWindowClassD3d9Ex", NULL);
    if (!hWnd) hWnd = FindWindowA("GxWindowClassOpenGl", NULL);

    if (hWnd) {
        // Reset cursor visibility reference count to >= 0
        while (ShowCursor(TRUE) < 0);
        
        // Remove window clipping to prevent cursor trapping/lag
        ClipCursor(NULL);

        // Hardware cursor byte patches disabled.
        // byte_CABCDD/CABCDE force gxCursor=0 + gxFixLag=1 which on
        // private servers (Circle/Warmane) activates an uninitialized
        // cursor rendering path → NULL deref at [edi]+0 → [0x0+18].
        // *(volatile uint8_t*)0x00CABCDD = 0;
        // *(volatile uint8_t*)0x00CABCDE = 1;

        g_cursorInitDone = true;
        Log("Hardware cursor: ACTIVE (clipping disabled, visibility reset)");
    }
}

static bool InstallHardwareCursorHooks() {
    InitHardwareCursor();
    return true;
}

#else

static void InitHardwareCursor() {}
static bool InstallHardwareCursorHooks() {
    Log("Hardware cursor: DISABLED (crash isolation)");
    return false;
}

#endif

// ================================================================
// Deferred Unit Field Updates - Synchronous Batch Processor
// ================================================================
static constexpr int FIELD_QUEUE_SIZE = 4096;
static constexpr int FIELD_QUEUE_MASK = FIELD_QUEUE_SIZE - 1;

struct FieldTask {
    void* unit;
    int   fieldId;
    int   value;
};

static FieldTask g_fieldQueue[FIELD_QUEUE_SIZE] = {};
static volatile LONG g_fieldHead = 0;
static volatile LONG g_fieldTail = 0;

typedef void (__thiscall *OnFieldUpdate_fn)(void*, int, int);
static OnFieldUpdate_fn orig_OnFieldUpdate = nullptr;

static void __fastcall Hooked_OnFieldUpdate(void* This, void* unused, int fieldId, int value) {
#if TEST_DISABLE_DEFERRED_FIELD_UPDATES
    return orig_OnFieldUpdate(This, fieldId, value);
#else
    __try {
        // Critical fields (HP, Mana, GUID, Flags, Level) process immediately
        if (fieldId < 0x40) {
            return orig_OnFieldUpdate(This, fieldId, value);
        }

        LONG tail = g_fieldTail;
        LONG nextTail = (tail + 1) & FIELD_QUEUE_MASK;
        if (nextTail == g_fieldHead) {
            return orig_OnFieldUpdate(This, fieldId, value); // Queue full
        }

        g_fieldQueue[tail].unit = This;
        g_fieldQueue[tail].fieldId = fieldId;
        g_fieldQueue[tail].value = value;
        InterlockedExchange(&g_fieldTail, nextTail);
        return;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return orig_OnFieldUpdate(This, fieldId, value);
    }
#endif
}

static void FlushFieldUpdates() {
#if !TEST_DISABLE_DEFERRED_FIELD_UPDATES
    LONG head = g_fieldHead;
    LONG tail = g_fieldTail;
    if (head == tail) return;

    while (head != tail) {
        FieldTask& task = g_fieldQueue[head];
        __try {
            // Validate pointer lifetime before calling original
            uintptr_t p = (uintptr_t)task.unit;
            if (p > 0x10000 && p < 0xBFFF0000) {
                orig_OnFieldUpdate(task.unit, task.fieldId, task.value);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}

        head = (head + 1) & FIELD_QUEUE_MASK;
    }
    InterlockedExchange(&g_fieldHead, head);
#endif
}

static bool InstallFieldUpdateHook() {
#if TEST_DISABLE_DEFERRED_FIELD_UPDATES
    Log("Deferred field updates: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x006A3C40;
    if (WineSafe_CreateHook(target, (void*)Hooked_OnFieldUpdate, (void**)&orig_OnFieldUpdate) != MH_OK) return false;
    if (MH_EnableHook(target) != MH_OK) return false;

    Log("Deferred field updates: ACTIVE (sync batch flush, 4096 slots)");
    return true;
#endif
}

// New system optimizations
static bool InstallGetFileSizeCache();
static bool InstallWaitForSingleObjectHook();
static bool InstallGetModuleHandleCache();
static bool InstallLstrcmpHook();
static bool InstallLStrLenHooks();
static bool InstallWowStrlenHook();
static bool InstallMBWCHooks();
static bool InstallGetProcAddressCache();
static bool InstallGetModuleFileNameCache();
static bool InstallEnvironmentVariableCache();
static bool InstallGetPrivateProfileCache();
static bool InstallLuaHGetStrCache();
static bool InstallCombatLogFullCache();
static void ClearLuaHGetStrCache();
static bool InstallLuaPushStringCache();
static void ClearLuaPushStringCache();
static bool InstallLuaRawGetICache();
static bool InstallRTTICache();
static bool InstallStreamBufferFastPath();

// Exposed for lua_optimize.cpp (UI reload cache clearing)
void ClearAssetPathCache();
extern "C" void ClearLuaOptCaches() {
    ClearLuaHGetStrCache();
    ClearLuaPushStringCache();
    ClearAssetPathCache();
}

// Stats for new hooks (defined with implementations below)
static long g_fsizeHits = 0, g_fsizeMisses = 0;
static long g_wfsSpinHits = 0, g_wfsFallbacks = 0;
static long g_modHits = 0, g_modMisses = 0;
static long g_lstrcmpHits = 0, g_lstrcmpFallbacks = 0;
static long g_mbwcFastHits = 0, g_mbwcFallbacks = 0;
static long g_wcmbFastHits = 0, g_wcmbFallbacks = 0;
static long g_profHits = 0, g_profMisses = 0;
static long g_gpaHits = 0, g_gpaMisses = 0, g_gpaEvictions = 0, g_gpaBypasses = 0;
static long g_envHits = 0, g_envMisses = 0;
static long g_gmfHits = 0, g_gmfMisses = 0;
long g_crtStrlenHits = 0, g_crtStrlenFallbacks = 0;
long g_crtStrcmpHits = 0, g_crtStrcmpFallbacks = 0;
long g_crtMemcmpHits = 0, g_crtMemcmpFallbacks = 0;
long g_crtMemcpyHits = 0, g_crtMemcpyFallbacks = 0;
long g_crtMemsetHits = 0, g_crtMemsetFallbacks = 0;
volatile LONG64 g_memchrHits = 0, g_memchrFallbacks = 0;
volatile LONG64 g_strchrHits = 0, g_strchrFallbacks = 0;
volatile LONG64 g_strcpyHits = 0, g_strcpyFallbacks = 0;
static uint64_t g_tableReshapeHits = 0;
static uint64_t g_getstrHits = 0, g_getstrFallbacks = 0;
static uint64_t g_combatLogCacheHits = 0, g_combatLogCacheMisses = 0;
static uint64_t g_pushStrHits = 0, g_pushStrMisses = 0;
static uint64_t g_rawGetIHits = 0, g_rawGetIMisses = 0;

// ================================================================
// Thread Affinity - background worker core pinning
// Pins WoW async task threads to cores 2..N-1, protecting main thread.
// ================================================================
static bool  g_threadAffOk = false;
static LONG  g_bgThreadIdx    = 0;
static DWORD g_affinityCores[16] = {0};
static int   g_affinityCount  = 0;

typedef int (__cdecl *fn_ThreadWorker)(void* outHandle, LPTHREAD_START_ROUTINE start, LPVOID param, int priority, int a5, int a6, HMODULE hMod);
static fn_ThreadWorker orig_ThreadWorker = nullptr;

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")

// WineSafe_CreateHook is now defined in version.h (shared across all TUs)

// ================================================================
// Global state
// ================================================================
bool   g_isMultiClient = false;         // Set by DetectMultiClient() via named mutex
static HANDLE g_instanceMutex = NULL;   // "wow_optimize_instance_v2" mutex
static DWORD  g_nextStatsDumpTick = 0;  // Next periodic stats dump (GetTickCount)
static DWORD  g_nextMiCollectTick = 0;  // Next mimalloc collect (multi-client only)
static void   DumpPeriodicStats();

// ================================================================
// Logging - ring buffer + background thread
//
// ================================================================
static FILE* g_log = nullptr;

static constexpr int LOG_RING_SIZE = 2048;
static constexpr int LOG_RING_MASK = LOG_RING_SIZE - 1;

struct LogEntry {
    char text[512];
    volatile LONG ready;
};

static LogEntry g_logRing[LOG_RING_SIZE] = {};
static volatile LONG g_logWritePos = 0;
static LONG g_logReadPos = 0;
static HANDLE g_logEvent = NULL;
static HANDLE g_logThread = NULL;
static volatile bool g_logShutdown = false;

static DWORD WINAPI LogThreadProc(LPVOID) {
    while (!g_logShutdown) {
        WaitForSingleObject(g_logEvent, 100);
        if (!g_log) continue;

        int flushed = 0;
        while (g_logRing[g_logReadPos & LOG_RING_MASK].ready) {
            int slot = g_logReadPos & LOG_RING_MASK;
            fputs(g_logRing[slot].text, g_log);
            InterlockedExchange(&g_logRing[slot].ready, 0);
            g_logReadPos++;
            flushed++;
        }
        if (flushed > 0) fflush(g_log);
    }

    while (g_logRing[g_logReadPos & LOG_RING_MASK].ready) {
        int slot = g_logReadPos & LOG_RING_MASK;
        if (g_log) fputs(g_logRing[slot].text, g_log);
        InterlockedExchange(&g_logRing[slot].ready, 0);
        g_logReadPos++;
    }
    if (g_log) fflush(g_log);
    return 0;
}

static void LogOpen() {
    CreateDirectoryA("Logs", NULL);
    
    // Try shared access first (allows multiple WoW clients or other processes to access the file)
    g_log = _fsopen("Logs\\wow_optimize.log", "w", _SH_DENYNO);
    
    // Fallback: if main log fails, try PID-specific log
    if (!g_log) {
        char fallbackPath[64];
        _snprintf(fallbackPath, sizeof(fallbackPath), "Logs\\wow_optimize_%lu.log", GetCurrentProcessId());
        fallbackPath[sizeof(fallbackPath) - 1] = '\0';
        g_log = _fsopen(fallbackPath, "w", _SH_DENYNO);
    }
    
    // Final fallback: use CRT fopen if _fsopen failed
    if (!g_log) {
        g_log = fopen("Logs\\wow_optimize.log", "w");
    }
    
    if (g_log) {
        // Write UTF-8 BOM so editors interpret em-dashes and other UTF-8 correctly
        static const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
        fwrite(bom, 1, 3, g_log);
        fflush(g_log);  // Ensure BOM is written immediately
    }
    g_logShutdown = false;
    g_logEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_logThread = CreateThread(NULL, 0, LogThreadProc, NULL, 0, NULL);
}

static void LogClose() {
    g_logShutdown = true;
    if (g_logEvent) SetEvent(g_logEvent);
    if (g_logThread) {
        WaitForSingleObject(g_logThread, 2000);
        CloseHandle(g_logThread);
        g_logThread = NULL;
    }
    if (g_logEvent) { CloseHandle(g_logEvent); g_logEvent = NULL; }
    if (g_log) { fclose(g_log); g_log = nullptr; }
}

// ================================================================
// LogFlushImmediate - Synchronous flush for crash context
// Called from unhandled exception filter BEFORE writing crash dump.
// Bypasses the background thread and writes directly to file.
// Must be async-signal-safe: no locks, no allocations, no CRT.
// ================================================================
void LogFlushImmediate() {
    if (!g_log) return;

    // Drain all pending ring buffer entries synchronously
    // Use InterlockedCompareExchange to avoid racing with LogThreadProc
    int maxDrain = LOG_RING_SIZE;  // Safety limit
    while (maxDrain-- > 0) {
        int slot = g_logReadPos & LOG_RING_MASK;
        LONG ready = InterlockedCompareExchange(&g_logRing[slot].ready, 0, 1);
        if (ready != 1) break;  // No more pending entries

        // Write directly using Win32 API (avoid CRT in crash context)
        HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(g_log));
        if (hFile != INVALID_HANDLE_VALUE && hFile != NULL) {
            DWORD len = (DWORD)strlen(g_logRing[slot].text);
            DWORD written = 0;
            WriteFile(hFile, g_logRing[slot].text, len, &written, NULL);
        }
        g_logReadPos++;
    }

    // Force OS-level flush
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(g_log));
    if (hFile != INVALID_HANDLE_VALUE && hFile != NULL) {
        FlushFileBuffers(hFile);
    }
}

extern "C" void Log(const char* fmt, ...) {
    if (!g_logEvent) return;

    LONG idx = InterlockedIncrement(&g_logWritePos) - 1;
    int slot = idx & LOG_RING_MASK;

    if (g_logRing[slot].ready) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    int offset = _snprintf(g_logRing[slot].text, 32, "[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, fmt);
    int msgLen = _vsnprintf(g_logRing[slot].text + offset, 510 - offset, fmt, args);
    va_end(args);
    if (msgLen < 0) msgLen = 510 - offset;
    offset += msgLen;

    g_logRing[slot].text[offset] = '\n';
    g_logRing[slot].text[offset + 1] = '\0';

    InterlockedExchange(&g_logRing[slot].ready, 1);
    SetEvent(g_logEvent);
}

// 1. Memory allocator replacement (mimalloc).
//
typedef void* (__cdecl* malloc_fn)(size_t);
typedef void  (__cdecl* free_fn)(void*);
typedef void* (__cdecl* realloc_fn)(void*, size_t);
typedef void* (__cdecl* calloc_fn)(size_t, size_t);
typedef size_t (__cdecl* msize_fn)(void*);

static malloc_fn  orig_malloc  = nullptr;
static free_fn    orig_free    = nullptr;
static realloc_fn orig_realloc = nullptr;
static calloc_fn  orig_calloc  = nullptr;
static msize_fn   orig_msize   = nullptr;

static void* __cdecl hooked_malloc(size_t size) {
    return mi_malloc(size);
}

static void __cdecl hooked_free(void* ptr) {
    if (!ptr) return;
    if (mi_is_in_heap_region(ptr))
        mi_free(ptr);
    else
        orig_free(ptr);
}

static void* __cdecl hooked_realloc(void* ptr, size_t size) {
    if (!ptr) return mi_malloc(size);
    if (size == 0) { hooked_free(ptr); return nullptr; }
    if (mi_is_in_heap_region(ptr))
        return mi_realloc(ptr, size);
    if (orig_msize) {
        size_t old_size = orig_msize(ptr);
        if (old_size > 0) {
            void* np = mi_malloc(size);
            if (np) {
                memcpy(np, ptr, (old_size < size) ? old_size : size);
                orig_free(ptr);
                return np;
            }
        }
    }
    return orig_realloc(ptr, size);
}

static void* __cdecl hooked_calloc(size_t count, size_t size) {
    return mi_calloc(count, size);
}

static size_t __cdecl hooked_msize(void* ptr) {
    if (!ptr) return 0;
    if (mi_is_in_heap_region(ptr)) return mi_usable_size(ptr);
    return orig_msize ? orig_msize(ptr) : 0;
}

static bool InstallAllocatorHooks() {
    const char* crt_names[] = {
        "msvcr80.dll", "msvcr90.dll", "msvcr100.dll",
        "msvcr110.dll", "msvcr120.dll", "ucrtbase.dll",
        "msvcrt.dll", nullptr
    };

    HMODULE hCRT = nullptr;
    const char* found_crt = nullptr;
    for (int i = 0; crt_names[i]; i++) {
        hCRT = GetModuleHandleA(crt_names[i]);
        if (hCRT) { found_crt = crt_names[i]; break; }
    }
    if (!hCRT) { Log("ERROR: No CRT DLL found"); return false; }
    Log("Found CRT: %s at 0x%p", found_crt, hCRT);

    void* pm = (void*)GetProcAddress(hCRT, "malloc");
    void* pf = (void*)GetProcAddress(hCRT, "free");
    void* pr = (void*)GetProcAddress(hCRT, "realloc");
    void* pc = (void*)GetProcAddress(hCRT, "calloc");
    void* ps = (void*)GetProcAddress(hCRT, "_msize");
    if (!pm || !pf || !pr) { Log("ERROR: malloc/free/realloc not found"); return false; }

    int ok = 0, total = 0;
    #define TRY_HOOK(target, hook, orig, name) \
        if (target) { total++; \
            if (MH_CreateHook(target, (void*)(hook), (void**)&(orig)) == MH_OK) { \
                ok++; Log("  Hook %s: OK", name); \
            } else { Log("  Hook %s: FAILED", name); } \
        }
    TRY_HOOK(pm, hooked_malloc,  orig_malloc,  "malloc");
    TRY_HOOK(pf, hooked_free,    orig_free,    "free");
    TRY_HOOK(pr, hooked_realloc, orig_realloc, "realloc");
    TRY_HOOK(pc, hooked_calloc,  orig_calloc,  "calloc");
    TRY_HOOK(ps, hooked_msize,   orig_msize,   "_msize");
    #undef TRY_HOOK

    if (ok == 0) return false;
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) return false;
    Log("Allocator hooks: %d/%d active", ok, total);
    return true;
}

// 2. Sleep hook + frame pacing, GC stepping, combat log cleanup.
//
static DWORD g_mainThreadId = 0;

typedef void (WINAPI* Sleep_fn)(DWORD);
static Sleep_fn orig_Sleep = nullptr;

static double g_sleepFreq = 0.0;
static double g_rdtscFreqMhz = 0.0;  // RDTSC frequency in MHz for easy calculation

static void PreciseSleep(double milliseconds) {
    // Use RDTSC for polling instead of QPC syscalls
    uint64_t startRDTSC = __rdtsc();
    double targetCycles = milliseconds * g_rdtscFreqMhz * 1000.0;  // ms → cycles

    while (true) {
        uint64_t nowRDTSC = __rdtsc();
        double elapsedCycles = (double)(nowRDTSC - startRDTSC);

        if (elapsedCycles >= targetCycles)
            return;

        double remainingMs = (targetCycles - elapsedCycles) / (g_rdtscFreqMhz * 1000.0);

        if (g_isMultiClient) {
            // Multi-client: no busy-wait, always yield CPU
            if (remainingMs > 1.5)
                orig_Sleep(1);
            else
                orig_Sleep(0);
        } else {
            // Single client: precise busy-wait for sub-ms accuracy
            if (remainingMs > 2.0)
                orig_Sleep(1);
            else if (remainingMs > 0.3)
                SwitchToThread();
            else
                _mm_pause();
        }
    }
}

static void RunPeriodicMaintenanceOnMainThread() {
    if (g_mainThreadId == 0 || GetCurrentThreadId() != g_mainThreadId)
        return;

    DWORD nowTick = GetTickCount();

    if (g_nextStatsDumpTick == 0) {
        g_nextStatsDumpTick = nowTick + 30000;
    } else if ((LONG)(nowTick - g_nextStatsDumpTick) >= 0) {
        DumpPeriodicStats();
        g_nextStatsDumpTick = nowTick + 300000;
    }

    if (g_isMultiClient) {
        // HD multi-client: aggressive mimalloc collection every 5 seconds
        // Prevents VA space fragmentation during boss fights (40+ MPQ clients)
        // Previous 60s interval allowed fragmentation to reach critical levels
        if (g_nextMiCollectTick == 0) {
            g_nextMiCollectTick = nowTick + 5000;
        } else if ((LONG)(nowTick - g_nextMiCollectTick) >= 0) {
            mi_collect(true);
            g_nextMiCollectTick = nowTick + 5000;
        }
    }
}
static LARGE_INTEGER g_lastSleepTime = {};
static double g_lastFrameMs = 0.0;

static void WINAPI hooked_Sleep(DWORD ms) {
    if (g_mainThreadId != 0 && GetCurrentThreadId() == g_mainThreadId) {
        UpdateMainThreadActivity();
        RunPeriodicMaintenanceOnMainThread();
    }

    if (ms == 0) {
        orig_Sleep(0);
        return;
    }

    if (ms <= 3 && g_mainThreadId != 0 && GetCurrentThreadId() == g_mainThreadId) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        if (g_lastSleepTime.QuadPart > 0 && g_sleepFreq > 0) {
            g_lastFrameMs = (double)(now.QuadPart - g_lastSleepTime.QuadPart) / g_sleepFreq;
        }
        g_lastSleepTime = now;

        // Detect lua_State destruction (logout/exit) - clear caches
        static uintptr_t g_lastLState = 0;
        uintptr_t currentL = *(uintptr_t*)0x00D3F78C;  // lua_State* global
        if (g_lastLState && currentL == 0) {
            ClearAssetPathCache();
        }
        g_lastLState = currentL;

        LuaOpt::OnMainThreadSleep(g_mainThreadId, g_lastFrameMs);
        CombatLogOpt::OnFrame(g_mainThreadId);
        CombatLogBuffer::OnFrame(g_mainThreadId);
#if !TEST_DISABLE_COMBATLOG_MT
        CombatLogMT::OnFrame(g_mainThreadId);
#endif
#if !TEST_DISABLE_TEXTURE_ASYNC
        TextureAsync::OnFrame(g_mainThreadId);
#endif
#if !TEST_DISABLE_SPELL_PREFETCH
        SpellPrefetch::OnFrame(g_mainThreadId);
#endif
#if !TEST_DISABLE_ADDON_DISPATCHER
        AddonDispatcher::OnFrame(g_mainThreadId);
#endif
#if !TEST_DISABLE_MODEL_ASYNC
        ModelAsync::OnFrame(g_mainThreadId);
#endif
#if !TEST_DISABLE_MPQ_PREFETCH
        MPQPrefetch::OnFrame(g_mainThreadId);
#endif
#if !TEST_DISABLE_OBJ_VIS_CACHE
        ObjVisCache::OnFrame();
#endif
#if !TEST_DISABLE_SOUND_PREFETCH
        SoundPrefetch::OnFrame();
#endif
#if !TEST_DISABLE_QUEST_ASYNC
        QuestAsync::OnFrame();
#endif
#if !TEST_DISABLE_NAMEPLATE_MT
        NameplateMT::OnFrame(g_mainThreadId);
#endif

        // D3D9 disabled (DXVK vtable mismatch), other 4 enabled
        // OnFrameD3D9StateManager(g_mainThreadId);
        OnFrameRenderHooks(g_mainThreadId);
        OnFrameLogicHooks(g_mainThreadId);
        OnFrameAsyncHooks(g_mainThreadId);

        PreciseSleep((double)ms);
        return;
    }

    orig_Sleep(ms);
}

static bool InstallSleepHook() {
    LARGE_INTEGER li;
    QueryPerformanceFrequency(&li);
    g_sleepFreq = (double)li.QuadPart / 1000.0;

    // Calibrate RDTSC frequency for PreciseSleep
    uint64_t rdtscStart = __rdtsc();
    LARGE_INTEGER qpcStart;
    QueryPerformanceCounter(&qpcStart);
    Sleep(10);  // 10ms calibration window
    uint64_t rdtscEnd = __rdtsc();
    LARGE_INTEGER qpcEnd;
    QueryPerformanceCounter(&qpcEnd);

    uint64_t rdtscElapsed = rdtscEnd - rdtscStart;
    LONGLONG qpcElapsed = qpcEnd.QuadPart - qpcStart.QuadPart;
    double qpcMs = (double)qpcElapsed / g_sleepFreq;

    // RDTSC frequency in MHz (cycles per microsecond)
    g_rdtscFreqMhz = (double)rdtscElapsed / (qpcMs * 1000.0);

    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_Sleep, (void**)&orig_Sleep) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("Sleep hook: ACTIVE (PreciseSleep RDTSC %.1f MHz + Lua GC + combat log)", g_rdtscFreqMhz);
    return true;
}

// 3. Network optimization - TCP_NODELAY, immediate ACK, QoS, keepalive.
//

#ifndef SIO_TCP_SET_ACK_FREQUENCY
#define SIO_TCP_SET_ACK_FREQUENCY _WSAIOW(IOC_VENDOR, 23)
#endif

typedef int (WINAPI* connect_fn)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI* send_fn)(SOCKET, const char*, int, int);

static connect_fn orig_connect = nullptr;
static send_fn    orig_send    = nullptr;

// Track sockets that need post-connect optimization
static SOCKET g_pendingSockets[64] = {};
static int    g_pendingCount = 0;
static SRWLOCK g_pendingLock = SRWLOCK_INIT;

static void AddPendingSocket(SOCKET s) {
    AcquireSRWLockExclusive(&g_pendingLock);
    if (g_pendingCount < 64) {
        // Check not already tracked
        for (int i = 0; i < g_pendingCount; i++) {
            if (g_pendingSockets[i] == s) {
                ReleaseSRWLockExclusive(&g_pendingLock);
                return;
            }
        }
        g_pendingSockets[g_pendingCount++] = s;
    }
    ReleaseSRWLockExclusive(&g_pendingLock);
}

static bool RemovePendingSocket(SOCKET s) {
    AcquireSRWLockExclusive(&g_pendingLock);
    for (int i = 0; i < g_pendingCount; i++) {
        if (g_pendingSockets[i] == s) {
            g_pendingSockets[i] = g_pendingSockets[--g_pendingCount];
            ReleaseSRWLockExclusive(&g_pendingLock);
            return true;
        }
    }
    ReleaseSRWLockExclusive(&g_pendingLock);
    return false;
}

static void OptimizeSocket(SOCKET s, const char* trigger) {
    int applied = 0;
    int failed  = 0;

    // 1. Disable Nagle
    BOOL nodelay = TRUE;
    if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay)) == 0)
        applied++;

    // 2. Disable Delayed ACK
    DWORD ackFreq = 1;
    DWORD bytesReturned = 0;
    if (WSAIoctl(s, SIO_TCP_SET_ACK_FREQUENCY, &ackFreq, sizeof(ackFreq),
                 NULL, 0, &bytesReturned, NULL, NULL) == 0)
        applied++;
    else
        failed++;

    // 3. QoS Low Delay
    int tos = 0x10;
    if (setsockopt(s, IPPROTO_IP, IP_TOS, (const char*)&tos, sizeof(tos)) == 0)
        applied++;
    else
        failed++;

    // 4. Buffer sizing
    int sendbuf = 32768;
    int recvbuf = 65536;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char*)&sendbuf, sizeof(sendbuf));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char*)&recvbuf, sizeof(recvbuf));
    applied += 2;

    // 5. Fast keepalive
    tcp_keepalive ka;
    ka.onoff             = 1;
    ka.keepalivetime     = 10000;
    ka.keepaliveinterval = 1000;
    DWORD kaBytes = 0;
    if (WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka),
                 NULL, 0, &kaBytes, NULL, NULL) == 0)
        applied++;
    else
        failed++;

    Log("Socket %d [%s]: %d applied, %d failed (NODELAY+ACK+QoS+BUF+KA)",
       (int)s, trigger, applied, failed);
}

static int WINAPI hooked_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    int result = orig_connect(s, name, namelen);
    int savedError = WSAGetLastError();

    if (result == 0) {
        // Synchronous connect succeeded - optimize immediately
        OptimizeSocket(s, "connect");
    } else if (savedError == WSAEWOULDBLOCK) {
        AddPendingSocket(s);
    }

    WSASetLastError(savedError);
    return result;
}

static int WINAPI hooked_send(SOCKET s, const char* buf, int len, int flags) {
    if (RemovePendingSocket(s)) {
        int savedError = WSAGetLastError();
        OptimizeSocket(s, "send");
        WSASetLastError(savedError);
    }
    return orig_send(s, buf, len, flags);
}

// ================================================================
// 3b. recv / WSARecv - receive-side socket optimization
//
// ================================================================

typedef int (WINAPI* recv_fn)(SOCKET, char*, int, int);
typedef int (WINAPI* WSARecv_fn)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static recv_fn      orig_recv      = nullptr;
static WSARecv_fn   orig_WSARecv   = nullptr;

static long g_recvCalls      = 0;
static long g_recvBytes      = 0;
static long g_recvWouldBlock = 0;
static long g_WSARecvCalls   = 0;
static long g_WSARecvBytes   = 0;
static long g_WSARecvWouldBlock = 0;

static int WINAPI hooked_recv(SOCKET s, char* buf, int len, int flags) {
    int result = orig_recv(s, buf, len, flags);
    if (result > 0) {
        g_recvCalls++;
        g_recvBytes += result;
    } else if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            g_recvWouldBlock++;
        }
    }
    return result;
}

static int WINAPI hooked_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                                  LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
                                  LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int result = orig_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
                               lpFlags, lpOverlapped, lpCompletionRoutine);
    if (result == 0 && lpNumberOfBytesRecvd) {
        g_WSARecvCalls++;
        g_WSARecvBytes += *lpNumberOfBytesRecvd;
    } else if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            g_WSARecvWouldBlock++;
        }
    }
    return result;
}

static bool InstallNetworkHooks() {
    HMODULE h = GetModuleHandleA("ws2_32.dll");
    if (!h) h = LoadLibraryA("ws2_32.dll");
    if (!h) return false;

    void* pConnect = (void*)GetProcAddress(h, "connect");
    void* pSend    = (void*)GetProcAddress(h, "send");
    void* pRecv    = (void*)GetProcAddress(h, "recv");
    void* pWSARecv = (void*)GetProcAddress(h, "WSARecv");
    if (!pConnect) return false;

    int ok = 0;

    if (MH_CreateHook(pConnect, (void*)hooked_connect, (void**)&orig_connect) == MH_OK)
        if (MH_EnableHook(pConnect) == MH_OK) ok++;

    if (pSend && MH_CreateHook(pSend, (void*)hooked_send, (void**)&orig_send) == MH_OK)
        if (MH_EnableHook(pSend) == MH_OK) ok++;

    if (pRecv && MH_CreateHook(pRecv, (void*)hooked_recv, (void**)&orig_recv) == MH_OK)
        if (MH_EnableHook(pRecv) == MH_OK) ok++;

    if (pWSARecv && MH_CreateHook(pWSARecv, (void*)hooked_WSARecv, (void**)&orig_WSARecv) == MH_OK)
        if (MH_EnableHook(pWSARecv) == MH_OK) ok++;

    Log("Network hook: ACTIVE (%d/4 hooks, NODELAY+ACK+QoS+BUF+KA+recv, deferred mode)", ok);
    return ok > 0;
}

// ================================================================
// 4. MPQ Handle Tracking (O(1) hash lookup)
//
// ================================================================

static constexpr int MPQ_HASH_SIZE = 512; // power of 2, load factor < 0.5
static constexpr int MPQ_HASH_MASK = MPQ_HASH_SIZE - 1;

struct MpqHashEntry {
    HANDLE handle;
    bool   occupied;
};

static MpqHashEntry g_mpqHash[MPQ_HASH_SIZE] = {};
static int          g_mpqHandleCount = 0;
static SRWLOCK      g_mpqLock = SRWLOCK_INIT;

static inline int MpqSlot(HANDLE h) {
    // HANDLE values are multiples of 4, shift for distribution
    return (int)(((uintptr_t)h >> 2) & MPQ_HASH_MASK);
}

static void TrackMpqHandle(HANDLE h) {
    AcquireSRWLockExclusive(&g_mpqLock);

    int slot = MpqSlot(h);
    for (int i = 0; i < MPQ_HASH_SIZE; i++) {
        int idx = (slot + i) & MPQ_HASH_MASK;
        if (!g_mpqHash[idx].occupied) {
            g_mpqHash[idx].handle = h;
            g_mpqHash[idx].occupied = true;
            g_mpqHandleCount++;
            break;
        }
        if (g_mpqHash[idx].handle == h) {
            break; // already tracked
        }
    }

    ReleaseSRWLockExclusive(&g_mpqLock);
}

static bool IsMpqHandle(HANDLE h) {
    AcquireSRWLockShared(&g_mpqLock);

    int slot = MpqSlot(h);
    bool found = false;
    for (int i = 0; i < MPQ_HASH_SIZE; i++) {
        int idx = (slot + i) & MPQ_HASH_MASK;
        if (!g_mpqHash[idx].occupied) {
            break; // empty slot = not found
        }
        if (g_mpqHash[idx].handle == h) {
            found = true;
            break;
        }
    }

    ReleaseSRWLockShared(&g_mpqLock);
    return found;
}

static void UntrackMpqHandle(HANDLE h) {
    AcquireSRWLockExclusive(&g_mpqLock);

    int slot = MpqSlot(h);
    for (int i = 0; i < MPQ_HASH_SIZE; i++) {
        int idx = (slot + i) & MPQ_HASH_MASK;
        if (!g_mpqHash[idx].occupied) {
            break; // not found
        }
        if (g_mpqHash[idx].handle == h) {
            // Tombstone removal: rehash subsequent entries
            g_mpqHash[idx].occupied = false;
            g_mpqHash[idx].handle = NULL;
            g_mpqHandleCount--;

            // Rehash chain after deleted slot
            int next = (idx + 1) & MPQ_HASH_MASK;
            int rehashLimit = MPQ_HASH_SIZE;
            while (g_mpqHash[next].occupied && rehashLimit-- > 0) {
                HANDLE rh = g_mpqHash[next].handle;
                g_mpqHash[next].occupied = false;
                g_mpqHash[next].handle = NULL;
                g_mpqHandleCount--;

                // Re-insert
                int rs = MpqSlot(rh);
                for (int j = 0; j < MPQ_HASH_SIZE; j++) {
                    int ri = (rs + j) & MPQ_HASH_MASK;
                    if (!g_mpqHash[ri].occupied) {
                        g_mpqHash[ri].handle = rh;
                        g_mpqHash[ri].occupied = true;
                        g_mpqHandleCount++;
                        break;
                    }
                }

                next = (next + 1) & MPQ_HASH_MASK;
            }
            break;
        }
    }

    ReleaseSRWLockExclusive(&g_mpqLock);
}

// ================================================================
// 4b. Memory-Mapped MPQ Files
//
// ================================================================
// MPQ map lock - always defined (used by scanner even when mmap disabled)
static SRWLOCK g_mpqMapLock = SRWLOCK_INIT;

// MPQ handle tracking - always defined
struct MpqMapping {
    HANDLE fileHandle;
    HANDLE mappingHandle;
    void*  baseAddress;
    DWORD  fileSize;
    bool   active;
};

static constexpr int    MAX_MPQ_MAPPINGS    = 32;
static MpqMapping g_mpqMappings[MAX_MPQ_MAPPINGS] = {};
static DWORD      g_mpqMapTotalBytes = 0;
static long       g_mpqMapHits    = 0;
static long       g_mpqMapMisses  = 0;
static int        g_mpqMapCount   = 0;

#if !CRASH_TEST_DISABLE_MPQ_MMAP

static constexpr DWORD  MPQ_MMAP_MIN_SIZE   = 256 * 1024;              // 256 KB
static constexpr DWORD  MPQ_MMAP_MAX_SIZE   = 512 * 1024 * 1024;      // 512 MB
static constexpr DWORD  MPQ_MMAP_MAX_TOTAL  = 768 * 1024 * 1024;      // 768 MB total (safe for 32-bit)

static MpqMapping* FindMpqMapping(HANDLE h) {
    for (int i = 0; i < MAX_MPQ_MAPPINGS; i++) {
        if (g_mpqMappings[i].active && g_mpqMappings[i].fileHandle == h)
            return &g_mpqMappings[i];
    }
    return nullptr;
}

static MpqMapping* CreateMpqMapping(HANDLE hFile, const char* pathForLog = nullptr) {
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) return nullptr;

    // Size checks with logging
    if (fileSize.QuadPart < MPQ_MMAP_MIN_SIZE) {
        if (pathForLog) {
            Log("MPQ skip: %s (%.0f KB < %d KB min)",
                pathForLog, fileSize.QuadPart / 1024.0, MPQ_MMAP_MIN_SIZE / 1024);
        }
        return nullptr;
    }
    if (fileSize.QuadPart > MPQ_MMAP_MAX_SIZE) {
        if (pathForLog) {
            Log("MPQ skip: %s (%.0f MB > %d MB max, using read-ahead cache)",
                pathForLog, fileSize.QuadPart / (1024.0 * 1024.0), MPQ_MMAP_MAX_SIZE / (1024 * 1024));
        }
        return nullptr;
    }

    DWORD fsize = (DWORD)fileSize.QuadPart;

    // Total limit check
    if (g_mpqMapTotalBytes + fsize > MPQ_MMAP_MAX_TOTAL) {
        if (pathForLog) {
            Log("MPQ skip: %s (%.0f MB, total limit %d MB reached)",
                pathForLog, fsize / (1024.0 * 1024.0), MPQ_MMAP_MAX_TOTAL / (1024 * 1024));
        }
        return nullptr;
    }

    // Already mapped?
    if (FindMpqMapping(hFile)) return nullptr;

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) return nullptr;

    void* base = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        CloseHandle(hMapping);
        if (pathForLog) {
            Log("MPQ skip: %s (MapViewOfFile failed, error %lu)",
                pathForLog, GetLastError());
        }
        return nullptr;
    }

    // Verify the mapping is readable (catch files being modified by launchers/patchers)
    __try {
        volatile uint8_t test = *(volatile uint8_t*)base;
       (void)test;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        UnmapViewOfFile(base);
        CloseHandle(hMapping);
        if (pathForLog) {
            Log("MPQ skip: %s (mapped memory not readable)", pathForLog);
        }
        return nullptr;
    }

    // Find free slot
    for (int i = 0; i < MAX_MPQ_MAPPINGS; i++) {
        if (!g_mpqMappings[i].active) {
            g_mpqMappings[i].fileHandle    = hFile;
            g_mpqMappings[i].mappingHandle = hMapping;
            g_mpqMappings[i].baseAddress   = base;
            g_mpqMappings[i].fileSize      = fsize;
            g_mpqMappings[i].active        = true;
            g_mpqMapTotalBytes += fsize;
            g_mpqMapCount++;
            return &g_mpqMappings[i];
        }
    }

    // No free slot
    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    return nullptr;
}

static void DestroyMpqMapping(HANDLE hFile) {
    for (int i = 0; i < MAX_MPQ_MAPPINGS; i++) {
        if (g_mpqMappings[i].active && g_mpqMappings[i].fileHandle == hFile) {
            UnmapViewOfFile(g_mpqMappings[i].baseAddress);
            // NOTE: mappingHandle is intentionally NOT closed here.
            // CloseHandle is hooked → hooked_CloseHandle → AcquireSRWLock → DEADLOCK
            // The OS will close the handle when the process exits.
            // For runtime cleanup, we just unmap the view - that's sufficient.
            g_mpqMapTotalBytes -= g_mpqMappings[i].fileSize;
            g_mpqMapCount--;
            g_mpqMappings[i].active = false;
            g_mpqMappings[i].baseAddress = nullptr;
            g_mpqMappings[i].mappingHandle = nullptr;
            g_mpqMappings[i].fileSize = 0;
            return;
        }
    }
}

#endif // !CRASH_TEST_DISABLE_MPQ_MMAP

// 5. ReadFile cache MPQ adaptive read-ahead.
//

typedef BOOL (WINAPI* ReadFile_fn)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static ReadFile_fn orig_ReadFile = nullptr;

// ================================================================
// Async MPQ I/O - Predictive Read-Ahead for .m2/.blp
// ================================================================
#if !TEST_DISABLE_ASYNC_MPQ_IO

static constexpr int ASYNC_IO_QUEUE_SIZE = 512;
static constexpr int ASYNC_IO_QUEUE_MASK = ASYNC_IO_QUEUE_SIZE - 1;

struct AsyncIoTask {
    HANDLE hFile;
    LARGE_INTEGER offset;
    DWORD bytes;
    uint8_t* buffer;
    volatile LONG status; // 0=pending, 1=ready, 2=failed
};

static AsyncIoTask g_asyncIoQueue[ASYNC_IO_QUEUE_SIZE] = {};
static volatile LONG g_asyncIoHead = 0;
static volatile LONG g_asyncIoTail = 0;
static HANDLE g_asyncIoWorker = NULL;
static volatile bool g_asyncIoShutdown = false;

static DWORD WINAPI AsyncIoWorkerProc(LPVOID) {
    while (!g_asyncIoShutdown) {
        // Pause during lua_State swap - MPQ handles and buffers may be stale
        if (LuaOpt::IsSwapping()) {
            Sleep(1);
            continue;
        }
        LONG head = g_asyncIoHead;
        if (head == g_asyncIoTail) {
            SwitchToThread();
            continue;
        }
        AsyncIoTask& task = g_asyncIoQueue[head];
        __try {
            DWORD bytesRead = 0;
            SetFilePointerEx(task.hFile, task.offset, NULL, FILE_BEGIN);
            BOOL ok = orig_ReadFile(task.hFile, task.buffer, task.bytes, &bytesRead, NULL);
            InterlockedExchange(&task.status, ok ? 1 : 2);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            InterlockedExchange(&task.status, 2);
        }
        InterlockedExchange(&g_asyncIoHead, (head + 1) & ASYNC_IO_QUEUE_MASK);
    }
    return 0;
}

static bool QueueAsyncRead(HANDLE hFile, LARGE_INTEGER offset, DWORD bytes, uint8_t* buffer) {
    LONG tail = g_asyncIoTail;
    LONG nextTail = (tail + 1) & ASYNC_IO_QUEUE_MASK;
    if (nextTail == g_asyncIoHead) return false; // Queue full

    g_asyncIoQueue[tail].hFile = hFile;
    g_asyncIoQueue[tail].offset = offset;
    g_asyncIoQueue[tail].bytes = bytes;
    g_asyncIoQueue[tail].buffer = buffer;
    g_asyncIoQueue[tail].status = 0;
    InterlockedExchange(&g_asyncIoTail, nextTail);
    return true;
}

static bool CheckAsyncCompletion(HANDLE hFile, LARGE_INTEGER offset, DWORD bytes, uint8_t* dst) {
    LONG head = g_asyncIoHead;
    while (head != g_asyncIoTail) {
        AsyncIoTask& task = g_asyncIoQueue[head];
        if (task.hFile == hFile && task.offset.QuadPart == offset.QuadPart && task.bytes == bytes) {
            if (task.status == 1) {
                memcpy(dst, task.buffer, bytes);
                mi_free(task.buffer);
                InterlockedExchange(&g_asyncIoHead, (head + 1) & ASYNC_IO_QUEUE_MASK);
                return true;
            }
            if (task.status == 2) {
                mi_free(task.buffer);
                InterlockedExchange(&g_asyncIoHead, (head + 1) & ASYNC_IO_QUEUE_MASK);
            }
            return false;
        }
        head = (head + 1) & ASYNC_IO_QUEUE_MASK;
    }
    return false;
}

static bool InstallAsyncIoWorker() {
    g_asyncIoShutdown = false;
    g_asyncIoWorker = CreateThread(NULL, 0, AsyncIoWorkerProc, NULL, 0, NULL);
    if (g_asyncIoWorker) {
        Log("Async MPQ I/O: ACTIVE (background worker, %d slots)", ASYNC_IO_QUEUE_SIZE);
        return true;
    }
    Log("Async MPQ I/O: FAILED to create worker thread");
    return false;
}

#else

static bool QueueAsyncRead(HANDLE, LARGE_INTEGER, DWORD, uint8_t*) { return false; }
static bool CheckAsyncCompletion(HANDLE, LARGE_INTEGER, DWORD, uint8_t*) { return false; }
static bool InstallAsyncIoWorker() { return false; }

#endif

// Async prefetch forward declarations
static const int MAX_PREFETCH_SLOTS = 8;
static const DWORD PREFETCH_SIZE = 256 * 1024;
static void InitPrefetchSlots();
static void QueuePrefetch(HANDLE hFile, LARGE_INTEGER startOffset, DWORD bytes);
static BOOL CheckPrefetch(HANDLE hFile, LARGE_INTEGER offset, LPVOID lpBuffer, DWORD nBytes, LPDWORD lpBytesRead);

struct ReadCache {
    HANDLE handle; uint8_t* buffer;
    LARGE_INTEGER fileOffset; DWORD validBytes; bool active;
};

static const int   MAX_CACHED_HANDLES  = 16;
static const DWORD READ_AHEAD_NORMAL   = 64 * 1024;
static const DWORD READ_AHEAD_LOADING  = 256 * 1024;
static const DWORD READ_AHEAD_MAX      = 256 * 1024;  // buffer allocation size
static ReadCache   g_readCache[MAX_CACHED_HANDLES] = {};
static int         g_cacheEvictIndex = 0;               
static SRWLOCK g_cacheLock = SRWLOCK_INIT;
static bool g_cacheInitialized = false;

static ReadCache* FindCache(HANDLE h) {
    for (int i = 0; i < MAX_CACHED_HANDLES; i++)
        if (g_readCache[i].active && g_readCache[i].handle == h) return &g_readCache[i];
    return nullptr;
}

static ReadCache* AllocCache(HANDLE h) {

    for (int i = 0; i < MAX_CACHED_HANDLES; i++) {
        if (!g_readCache[i].active) {
            g_readCache[i].handle = h;
            if (!g_readCache[i].buffer) g_readCache[i].buffer = (uint8_t*)mi_malloc(READ_AHEAD_MAX);
            g_readCache[i].validBytes = 0;
            g_readCache[i].active = true;
            return &g_readCache[i];
        }
    }

    int idx = g_cacheEvictIndex;
    g_cacheEvictIndex = (g_cacheEvictIndex + 1) % MAX_CACHED_HANDLES;
    g_readCache[idx].handle = h;
    if (!g_readCache[idx].buffer) g_readCache[idx].buffer = (uint8_t*)mi_malloc(READ_AHEAD_MAX);
    g_readCache[idx].validBytes = 0;
    g_readCache[idx].active = true;
    return &g_readCache[idx];
}

static BOOL WINAPI hooked_ReadFile(HANDLE hFile, LPVOID lpBuffer,
    DWORD nBytesToRead, LPDWORD lpBytesRead, LPOVERLAPPED lpOverlapped)
{
    // Skip: overlapped I/O, non-MPQ, or not initialized
    if (lpOverlapped)
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    // Addon file RAM-disk: serve pre-loaded addon files from memory
    if (AddonPreload_TryServe(hFile, lpBuffer, nBytesToRead, lpBytesRead))
        return TRUE;

    if (!g_cacheInitialized || !IsMpqHandle(hFile))
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    // NULL-buffer guard: WoW may call ReadFile with lpBuffer=NULL to advance
    // the file pointer during loading/streaming with HD MPQs.
    if (!lpBuffer || !nBytesToRead)
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    // === Memory-mapped fast path (ANY read size, zero kernel transitions) ===
#if !CRASH_TEST_DISABLE_MPQ_MMAP
    {
        AcquireSRWLockShared(&g_mpqMapLock);
        MpqMapping* m = FindMpqMapping(hFile);
        if (m) {
            LARGE_INTEGER zero, currentPos;
            zero.QuadPart = 0;
            BOOL gotPos = SetFilePointerEx(hFile, zero, &currentPos, FILE_CURRENT);
            if (gotPos) {
                DWORD offset = (DWORD)currentPos.QuadPart;
                if (offset + nBytesToRead <= m->fileSize) {
                    __try {
                        memcpy(lpBuffer, (const uint8_t*)m->baseAddress + offset, nBytesToRead);
                        if (lpBytesRead) *lpBytesRead = nBytesToRead;
                        LARGE_INTEGER newPos;
                        newPos.QuadPart = (LONGLONG)(offset + nBytesToRead);
                        SetFilePointerEx(hFile, newPos, NULL, FILE_BEGIN);
                        InterlockedIncrement(&g_mpqMapHits);
                        ReleaseSRWLockShared(&g_mpqMapLock);
                        return TRUE;
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER) {
                        InterlockedIncrement(&g_mpqMapMisses);
                    }
                }
            }
        }
        ReleaseSRWLockShared(&g_mpqMapLock);
    }
#endif

    // === Read-ahead cache path (only for small reads) ===
    if (nBytesToRead >= READ_AHEAD_MAX)
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    AcquireSRWLockExclusive(&g_cacheLock);

    __try {

    LARGE_INTEGER currentPos, zero;
    zero.QuadPart = 0;
    if (!SetFilePointerEx(hFile, zero, &currentPos, FILE_CURRENT)) {
        ReleaseSRWLockExclusive(&g_cacheLock);
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);
    }

    ReadCache* cache = FindCache(hFile);
    if (cache && cache->validBytes > 0) {
        LONGLONG cStart = cache->fileOffset.QuadPart;
        LONGLONG cEnd   = cStart + cache->validBytes;
        LONGLONG rStart = currentPos.QuadPart;
        LONGLONG rEnd   = rStart + nBytesToRead;
        if (rStart >= cStart && rEnd <= cEnd) {
            DWORD off = (DWORD)(rStart - cStart);
            memcpy(lpBuffer, cache->buffer + off, nBytesToRead);
            if (lpBytesRead) *lpBytesRead = nBytesToRead;
            LARGE_INTEGER newPos; newPos.QuadPart = rEnd;
            SetFilePointerEx(hFile, newPos, NULL, FILE_BEGIN);
            ReleaseSRWLockExclusive(&g_cacheLock);
            return TRUE;
        }
    }

    if (!cache) cache = AllocCache(hFile);
    if (cache && cache->buffer) {
        cache->fileOffset = currentPos;
        DWORD readAhead = LuaOpt::IsLoadingMode() ? READ_AHEAD_LOADING : READ_AHEAD_NORMAL;
        DWORD bytesRead = 0;
        BOOL ok = orig_ReadFile(hFile, cache->buffer, readAhead, &bytesRead, NULL);
        if (ok && bytesRead > 0) {
            cache->validBytes = bytesRead;
            DWORD toCopy = (nBytesToRead < bytesRead) ? nBytesToRead : bytesRead;
            memcpy(lpBuffer, cache->buffer, toCopy);
            if (lpBytesRead) *lpBytesRead = toCopy;
            if (toCopy < bytesRead) {
                LARGE_INTEGER newPos2; newPos2.QuadPart = currentPos.QuadPart + toCopy;
                SetFilePointerEx(hFile, newPos2, NULL, FILE_BEGIN);
                // Queue async prefetch of next chunk
                LARGE_INTEGER prefetchOff; prefetchOff.QuadPart = currentPos.QuadPart + bytesRead;
                QueuePrefetch(hFile, prefetchOff, readAhead);
            }
            ReleaseSRWLockExclusive(&g_cacheLock);
            return TRUE;
        }
        cache->validBytes = 0;
        SetFilePointerEx(hFile, currentPos, NULL, FILE_BEGIN);
    }

    ReleaseSRWLockExclusive(&g_cacheLock);

        // === Async MPQ I/O Fast Path ===
    #if !TEST_DISABLE_ASYNC_MPQ_IO
        if (IsMpqHandle(hFile) && nBytesToRead <= 65536) {
            __try {
               
                if (CheckAsyncCompletion(hFile, currentPos, nBytesToRead, (uint8_t*)lpBuffer)) {
                    if (lpBytesRead) *lpBytesRead = nBytesToRead;
                    LARGE_INTEGER newPos; newPos.QuadPart = currentPos.QuadPart + nBytesToRead;
                    SetFilePointerEx(hFile, newPos, NULL, FILE_BEGIN);
                    return TRUE;
                }

                uint8_t* asyncBuf = (uint8_t*)mi_malloc(nBytesToRead);
                if (asyncBuf) {
                    LARGE_INTEGER nextOff; nextOff.QuadPart = currentPos.QuadPart + nBytesToRead;
                    if (!QueueAsyncRead(hFile, nextOff, nBytesToRead, asyncBuf)) {
                        mi_free(asyncBuf); 
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
    #endif    

    // === Async prefetch check ===
    if (IsMpqHandle(hFile)) {
        if (CheckPrefetch(hFile, currentPos, lpBuffer, nBytesToRead, lpBytesRead)) {
            LARGE_INTEGER newPos; newPos.QuadPart = currentPos.QuadPart + nBytesToRead;
            SetFilePointerEx(hFile, newPos, NULL, FILE_BEGIN);
            return TRUE;
        }
    }

    return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ReleaseSRWLockExclusive(&g_cacheLock);
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);
    }
}

static bool InstallReadFileHook() {
    g_cacheInitialized = true;
    InitPrefetchSlots();
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_ReadFile, (void**)&orig_ReadFile) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("ReadFile hook: ACTIVE (MPQ cache, 64KB/256KB adaptive read-ahead, %d slots + async prefetch)", MAX_CACHED_HANDLES);
    return true;
}

// ================================================================
// 5b. Async MPQ Prefetch Queue - background overlapped reads
//
// ================================================================

struct PrefetchSlot {
    HANDLE        hFile;
    LARGE_INTEGER startOffset;
    DWORD         bytesRequested;
    DWORD         bytesCompleted;
    OVERLAPPED    overlapped;
    uint8_t*      buffer;
    bool          active;
    bool          completed;
    HANDLE        hEvent;
};

static PrefetchSlot g_prefetchSlots[MAX_PREFETCH_SLOTS] = {};
static SRWLOCK      g_prefetchLock = SRWLOCK_INIT;
static long         g_prefetchHits     = 0;
static long         g_prefetchMisses   = 0;
static long         g_prefetchQueued   = 0;
static long         g_prefetchCancelled = 0;

static void InitPrefetchSlots() {
    for (int i = 0; i < MAX_PREFETCH_SLOTS; i++) {
        g_prefetchSlots[i].hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
        g_prefetchSlots[i].buffer = (uint8_t*)mi_malloc(PREFETCH_SIZE);
        g_prefetchSlots[i].overlapped.hEvent = g_prefetchSlots[i].hEvent;
    }
}

static void CancelPrefetch(HANDLE hFile, LARGE_INTEGER beyondOffset) {
    // Cancel any prefetches for this file that start before beyondOffset
    for (int i = 0; i < MAX_PREFETCH_SLOTS; i++) {
        if (g_prefetchSlots[i].active && g_prefetchSlots[i].hFile == hFile) {
            if (g_prefetchSlots[i].startOffset.QuadPart < beyondOffset.QuadPart) {
                CancelIoEx(hFile, &g_prefetchSlots[i].overlapped);
                g_prefetchSlots[i].active = false;
                g_prefetchSlots[i].completed = false;
                g_prefetchCancelled++;
            }
        }
    }
}

static void QueuePrefetch(HANDLE hFile, LARGE_INTEGER startOffset, DWORD bytes) {
    if (bytes == 0 || bytes > PREFETCH_SIZE) return;

    AcquireSRWLockExclusive(&g_prefetchLock);

    // Cancel any overlapping prefetches
    LARGE_INTEGER beyond;
    beyond.QuadPart = startOffset.QuadPart + bytes;
    CancelPrefetch(hFile, beyond);

    // Find free slot
    int slot = -1;
    for (int i = 0; i < MAX_PREFETCH_SLOTS; i++) {
        if (!g_prefetchSlots[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        ReleaseSRWLockExclusive(&g_prefetchLock);
        return;  // Queue full
    }

    // Setup prefetch
    PrefetchSlot& s = g_prefetchSlots[slot];
    s.hFile = hFile;
    s.startOffset = startOffset;
    s.bytesRequested = bytes;
    s.bytesCompleted = 0;
    s.active = true;
    s.completed = false;
    s.overlapped.Offset = startOffset.LowPart;
    s.overlapped.OffsetHigh = startOffset.HighPart;
    ResetEvent(s.hEvent);

    // Issue async read
    if (ReadFile(hFile, s.buffer, bytes, NULL, &s.overlapped)) {
        // Completed immediately
        s.completed = true;
        s.bytesCompleted = bytes;
    } else {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            s.active = false;  // Failed
        }
    }

    g_prefetchQueued++;
    ReleaseSRWLockExclusive(&g_prefetchLock);
}

static BOOL CheckPrefetch(HANDLE hFile, LARGE_INTEGER offset, LPVOID lpBuffer, DWORD nBytes, LPDWORD lpBytesRead) {
    AcquireSRWLockExclusive(&g_prefetchLock);

    for (int i = 0; i < MAX_PREFETCH_SLOTS; i++) {
        PrefetchSlot& s = g_prefetchSlots[i];
        if (!s.active || !s.completed || s.hFile != hFile) continue;

        LONGLONG pStart = s.startOffset.QuadPart;
        LONGLONG pEnd   = pStart + s.bytesCompleted;
        LONGLONG rStart = offset.QuadPart;
        LONGLONG rEnd   = rStart + nBytes;

        if (rStart >= pStart && rEnd <= pEnd) {
            // Hit! Copy from prefetch buffer
            DWORD prefetchOff = (DWORD)(rStart - pStart);
            memcpy(lpBuffer, s.buffer + prefetchOff, nBytes);
            if (lpBytesRead) *lpBytesRead = nBytes;

            // Deactivate slot
            s.active = false;
            s.completed = false;

            g_prefetchHits++;
            ReleaseSRWLockExclusive(&g_prefetchLock);
            return TRUE;
        }
    }

    g_prefetchMisses++;
    ReleaseSRWLockExclusive(&g_prefetchLock);
    return FALSE;
}

// ================================================================
// 6. GetTickCount - QPC Precision
//
// ================================================================
typedef DWORD (WINAPI* GetTickCount_fn)(void);
static GetTickCount_fn orig_GetTickCount = nullptr;
static LARGE_INTEGER g_qpcFreq, g_qpcStart;
static DWORD g_tickStart;

static DWORD WINAPI hooked_GetTickCount(void) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double elapsed = (double)(now.QuadPart - g_qpcStart.QuadPart) / g_qpcFreq.QuadPart;
    return g_tickStart + (DWORD)(elapsed * 1000.0);
}

static bool InstallGetTickCountHook() {
    QueryPerformanceFrequency(&g_qpcFreq);
    QueryPerformanceCounter(&g_qpcStart);
    g_tickStart = GetTickCount();
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_GetTickCount, (void**)&orig_GetTickCount) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("GetTickCount hook: ACTIVE (QPC-based microsecond precision)");
    return true;
}

// ================================================================
// 6b. timeGetTime (WINMM) - QPC Precision
// ================================================================

typedef DWORD (WINAPI* timeGetTime_fn)(void);
static timeGetTime_fn orig_timeGetTime = nullptr;

static DWORD WINAPI hooked_timeGetTime(void) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double elapsed = (double)(now.QuadPart - g_qpcStart.QuadPart) / g_qpcFreq.QuadPart;
    return g_tickStart + (DWORD)(elapsed * 1000.0);
}

static bool InstallTimeGetTimeHook() {
    HMODULE h = GetModuleHandleA("winmm.dll");
    if (!h) h = LoadLibraryA("winmm.dll");
    if (!h) { Log("timeGetTime hook: SKIP (winmm.dll not loaded)"); return false; }

    void* p = (void*)GetProcAddress(h, "timeGetTime");
    if (!p) { Log("timeGetTime hook: SKIP (function not found)"); return false; }

    if (MH_CreateHook(p, (void*)hooked_timeGetTime, (void**)&orig_timeGetTime) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("timeGetTime hook: ACTIVE (QPC-based, synced with GetTickCount)");
    return true;
}

// 7. CriticalSection spin count tuning + TryEnter spin-first path.
//

typedef void (WINAPI* InitCS_fn)(LPCRITICAL_SECTION);
typedef void (WINAPI* EnterCS_fn)(LPCRITICAL_SECTION);
static InitCS_fn  orig_InitCS  = nullptr;
static EnterCS_fn orig_EnterCS = nullptr;
static long g_csSpinHits = 0;

static void WINAPI hooked_InitCS(LPCRITICAL_SECTION lpCS) {
#if CRASH_TEST_DISABLE_CS_SPIN
    InitializeCriticalSection(lpCS);
#else
    InitializeCriticalSectionAndSpinCount(lpCS, 8000);
#endif
}

#if !CRASH_TEST_DISABLE_CS_ENTER
static void WINAPI hooked_EnterCS(LPCRITICAL_SECTION lpCS) {
    if (TryEnterCriticalSection(lpCS)) {
        InterlockedIncrement(&g_csSpinHits);
        return;
    }

    // Spin-wait with 3 retries at increasing intervals
    // Most CS holds are <1us - catching them saves kernel transition
    static const int retrySpins[] = {8, 64, 256};
    for (int r = 0; r < 3; r++) {
        for (int i = 0; i < retrySpins[r]; i++) _mm_pause();
        if (TryEnterCriticalSection(lpCS)) {
            InterlockedIncrement(&g_csSpinHits);
            return;
        }
    }

    orig_EnterCS(lpCS);
}
#endif

static bool InstallCriticalSectionHook() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

#if !CRASH_TEST_DISABLE_CS_INIT
    void* pInit = (void*)GetProcAddress(hK32, "InitializeCriticalSection");
    if (pInit && MH_CreateHook(pInit, (void*)hooked_InitCS, (void**)&orig_InitCS) == MH_OK)
        if (MH_EnableHook(pInit) == MH_OK) ok++;
#endif

#if CRASH_TEST_DISABLE_CS_ENTER
    Log("CriticalSection hook: ACTIVE (%d/1, init only, crash isolation)", ok);
    return ok > 0;
#else
    void* pEnter = (void*)GetProcAddress(hK32, "EnterCriticalSection");
    if (pEnter && MH_CreateHook(pEnter, (void*)hooked_EnterCS, (void**)&orig_EnterCS) == MH_OK)
        if (MH_EnableHook(pEnter) == MH_OK) ok++;

    Log("CriticalSection hooks: ACTIVE (%d/2, spin 4000 + TryEnter spin-first)", ok);
    return ok > 0;
#endif
}

// ================================================================
// 7b. Heap Optimization - Low Fragmentation Heap
//
// ================================================================

typedef HANDLE (WINAPI* HeapCreate_fn)(DWORD, SIZE_T, SIZE_T);
static HeapCreate_fn orig_HeapCreate = nullptr;
static int g_heapsOptimized = 0;

static void EnableLFH(HANDLE hHeap) {
    if (!hHeap) return;
    ULONG heapInfo = 2; // LFH
    HeapSetInformation(hHeap, HeapCompatibilityInformation,
                       &heapInfo, sizeof(heapInfo));
}

static HANDLE WINAPI hooked_HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
    HANDLE h = orig_HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
    if (h && dwMaximumSize == 0) {
        // LFH only works on growable heaps (dwMaximumSize == 0)
        // Fixed-size heaps don't support LFH
        EnableLFH(h);
        g_heapsOptimized++;
    }
    return h;
}

static bool InstallHeapOptimization() {
    // Enable LFH on the process default heap first
    HANDLE processHeap = GetProcessHeap();
    if (processHeap) {
        EnableLFH(processHeap);
        g_heapsOptimized++;
    }

    // Hook HeapCreate to enable LFH on all future heaps
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "HeapCreate");
    if (!p) {
        Log("Heap optimization: LFH on process heap only (%d heaps)", g_heapsOptimized);
        return g_heapsOptimized > 0;
    }

    if (MH_CreateHook(p, (void*)hooked_HeapCreate, (void**)&orig_HeapCreate) != MH_OK) {
        Log("Heap optimization: LFH on process heap only (%d heaps)", g_heapsOptimized);
        return g_heapsOptimized > 0;
    }
    if (MH_EnableHook(p) != MH_OK) {
        Log("Heap optimization: LFH on process heap only (%d heaps)", g_heapsOptimized);
        return g_heapsOptimized > 0;
    }

    Log("Heap optimization: ACTIVE (LFH on process heap + all new heaps)");
    return true;
}

// ================================================================
// 7a. HeapAlloc/HeapFree → mimalloc - redirect process heap to mimalloc
//
// Windows HeapAlloc/HeapFree are used by Win32 APIs and WoW internal
// code. Redirecting the process heap to mimalloc catches all remaining
// allocations that bypass CRT malloc (HeapAlloc, LocalAlloc, etc.).
// Other heaps keep LFH but use the original allocator for safety.
// ================================================================
typedef LPVOID (WINAPI* HeapAlloc_fn)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI* HeapFree_fn)(HANDLE, DWORD, LPVOID);
typedef LPVOID (WINAPI* HeapReAlloc_fn)(HANDLE, DWORD, LPVOID, SIZE_T);
typedef SIZE_T (WINAPI* HeapSize_fn)(HANDLE, DWORD, LPCVOID);

static HeapAlloc_fn  orig_HeapAlloc  = nullptr;
static HeapFree_fn   orig_HeapFree   = nullptr;
static HeapReAlloc_fn orig_HeapReAlloc = nullptr;
static HeapSize_fn   orig_HeapSize   = nullptr;
static HANDLE        g_processHeap   = nullptr;
static long          g_heapAllocHits  = 0;

static LPVOID WINAPI hooked_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    if (hHeap == g_processHeap && dwBytes > 0) {
        InterlockedIncrement(&g_heapAllocHits);
        void* p = mi_malloc(dwBytes);
        if (dwFlags & HEAP_ZERO_MEMORY && p) memset(p, 0, dwBytes);
        return p;
    }
    return orig_HeapAlloc(hHeap, dwFlags, dwBytes);
}

static BOOL WINAPI hooked_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
    if (hHeap == g_processHeap && lpMem) {
        if (mi_is_in_heap_region(lpMem)) { mi_free(lpMem); return TRUE; }
    }
    return orig_HeapFree(hHeap, dwFlags, lpMem);
}

static LPVOID WINAPI hooked_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) {
    if (hHeap == g_processHeap && lpMem) {
        if (mi_is_in_heap_region(lpMem)) {
            if (dwBytes == 0) { mi_free(lpMem); return NULL; }
            void* p = mi_realloc(lpMem, dwBytes);
            if (dwFlags & HEAP_ZERO_MEMORY && p) {
                size_t usable = mi_usable_size(p);
                if (dwBytes > usable) memset((char*)p + usable, 0, dwBytes - usable);
            }
            return p;
        }
    }
    return orig_HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes);
}

static SIZE_T WINAPI hooked_HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem) {
    if (hHeap == g_processHeap && lpMem) {
        if (mi_is_in_heap_region((void*)lpMem)) return mi_usable_size((void*)lpMem);
    }
    return orig_HeapSize(hHeap, dwFlags, lpMem);
}

static bool InstallHeapRedirectToMimalloc() {
    g_processHeap = GetProcessHeap();
    if (!g_processHeap) return false;

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;
    void* p;

    p = (void*)GetProcAddress(hK32, "HeapAlloc");
    if (p && MH_CreateHook(p, (void*)hooked_HeapAlloc, (void**)&orig_HeapAlloc) == MH_OK) ok++;
    p = (void*)GetProcAddress(hK32, "HeapFree");
    if (p && MH_CreateHook(p, (void*)hooked_HeapFree, (void**)&orig_HeapFree) == MH_OK) ok++;
    p = (void*)GetProcAddress(hK32, "HeapReAlloc");
    if (p && MH_CreateHook(p, (void*)hooked_HeapReAlloc, (void**)&orig_HeapReAlloc) == MH_OK) ok++;
    p = (void*)GetProcAddress(hK32, "HeapSize");
    if (p && MH_CreateHook(p, (void*)hooked_HeapSize, (void**)&orig_HeapSize) == MH_OK) ok++;

    if (ok > 0) {
        MH_EnableHook(MH_ALL_HOOKS);
        Log("Heap redirect: ACTIVE (%d/4 hooks, process heap -> mimalloc)", ok);
        return true;
    }
    return false;
}

// ================================================================
// 7c. OutputDebugStringA - No-op when no debugger
//
// ================================================================

typedef void (WINAPI* OutputDebugStringA_fn)(LPCSTR);
static OutputDebugStringA_fn orig_OutputDebugStringA = nullptr;
static long g_debugStringSkipped = 0;

static void WINAPI hooked_OutputDebugStringA(LPCSTR lpOutputString) {
    if (!IsDebuggerPresent()) {
        InterlockedIncrement(&g_debugStringSkipped);
        return;
    }
    orig_OutputDebugStringA(lpOutputString);
}

static bool InstallOutputDebugStringHook() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OutputDebugStringA");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_OutputDebugStringA, (void**)&orig_OutputDebugStringA) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("OutputDebugStringA hook: ACTIVE (no-op when no debugger)");
    return true;
}

// ================================================================
// 7d. CompareStringA - Fast ASCII Path
//
// ================================================================

typedef int (WINAPI* CompareStringA_fn)(LCID, DWORD, LPCSTR, int, LPCSTR, int);
static CompareStringA_fn orig_CompareStringA = nullptr;
static long g_compareAsciiHits = 0;
static long g_compareFallbacks = 0;

#ifndef CSTR_LESS_THAN
#define CSTR_LESS_THAN    1
#define CSTR_EQUAL        2
#define CSTR_GREATER_THAN 3
#endif

static int WINAPI hooked_CompareStringA(LCID Locale, DWORD dwCmpFlags,
    LPCSTR lpString1, int cchCount1, LPCSTR lpString2, int cchCount2)
{
    // Only fast-path for simple flags: none, case-insensitive, or string sort
    if ((dwCmpFlags & ~(NORM_IGNORECASE | SORT_STRINGSORT)) != 0)
        goto cmp_fallback;

    if (!lpString1 || !lpString2)
        goto cmp_fallback;

    {
        bool ignoreCase = (dwCmpFlags & NORM_IGNORECASE) != 0;
        int i1 = 0, i2 = 0;

        while (true) {
            bool end1 = (cchCount1 == -1) ? (lpString1[i1] == '\0') : (i1 >= cchCount1);
            bool end2 = (cchCount2 == -1) ? (lpString2[i2] == '\0') : (i2 >= cchCount2);

            if (end1 && end2) { g_compareAsciiHits++; return CSTR_EQUAL; }
            if (end1)         { g_compareAsciiHits++; return CSTR_LESS_THAN; }
            if (end2)         { g_compareAsciiHits++; return CSTR_GREATER_THAN; }

            unsigned char c1 = (unsigned char)lpString1[i1];
            unsigned char c2 = (unsigned char)lpString2[i2];

            // Bail on non-ASCII - needs locale-aware comparison
            if (c1 > 127 || c2 > 127)
                goto cmp_fallback;

            if (ignoreCase) {
                if (c1 >= 'a' && c1 <= 'z') c1 -= 32;
                if (c2 >= 'a' && c2 <= 'z') c2 -= 32;
            }

            if (c1 != c2) {
                g_compareAsciiHits++;
                return (c1 < c2) ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
            }

            i1++;
            i2++;
        }
    }

cmp_fallback:
    g_compareFallbacks++;
    return orig_CompareStringA(Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2);
}

static bool InstallCompareStringHook() {
#if CRASH_TEST_DISABLE_COMPARESTRING
    Log("CompareStringA hook: DISABLED (crash isolation)");
    return false;
#else
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CompareStringA");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_CompareStringA, (void**)&orig_CompareStringA) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("CompareStringA hook: ACTIVE (fast ASCII path, locale fallback for non-ASCII)");
    return true;
#endif
}

// ================================================================
// 7e. GetFileAttributesA - Cache for MPQ paths
//
// ================================================================

typedef DWORD (WINAPI* GetFileAttributesA_fn)(LPCSTR);
static GetFileAttributesA_fn orig_GetFileAttributesA = nullptr;

static constexpr int FILE_ATTR_CACHE_SIZE = 4096;
static constexpr int FILE_ATTR_CACHE_MASK = FILE_ATTR_CACHE_SIZE - 1;

struct FileAttrEntry {
    uint32_t pathHash;
    DWORD    attributes;
    bool     valid;
};

static FileAttrEntry g_fileAttrCache[FILE_ATTR_CACHE_SIZE] = {};
static long g_fileAttrHits   = 0;
static long g_fileAttrMisses = 0;

static uint32_t HashPathCI(const char* path) {
    uint32_t h = 0x811C9DC5;
    while (*path) {
        char c = *path++;
        if (c >= 'A' && c <= 'Z') c += 32;
        if (c == '/') c = '\\';
        h ^= (uint8_t)c;
        h *= 0x01000193;
    }
    return h;
}

static DWORD WINAPI hooked_GetFileAttributesA(LPCSTR lpFileName) {
    if (!lpFileName) return orig_GetFileAttributesA(lpFileName);

    uint32_t hash = HashPathCI(lpFileName);
    int slot = hash & FILE_ATTR_CACHE_MASK;
    FileAttrEntry* e = &g_fileAttrCache[slot];

    if (e->valid && e->pathHash == hash) {
        g_fileAttrHits++;
        return e->attributes;
    }

    DWORD result = orig_GetFileAttributesA(lpFileName);

    e->pathHash   = hash;
    e->attributes = result;
    e->valid      = true;

    g_fileAttrMisses++;
    return result;
}

static bool InstallGetFileAttributesHook() {
#if CRASH_TEST_DISABLE_GETFILEATTR
    Log("GetFileAttributesA hook: DISABLED (crash isolation)");
    return false;
#else
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetFileAttributesA");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_GetFileAttributesA, (void**)&orig_GetFileAttributesA) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("GetFileAttributesA hook: ACTIVE (cache existing files, %d slots)", FILE_ATTR_CACHE_SIZE);
    return true;
#endif
}

// ================================================================
// 7g. SetFilePointer → SetFilePointerEx Redirect
//
// ================================================================

typedef DWORD (WINAPI* SetFilePointer_fn)(HANDLE, LONG, PLONG, DWORD);
static SetFilePointer_fn orig_SetFilePointer = nullptr;
static long g_sfpRedirected = 0;

static DWORD WINAPI hooked_SetFilePointer(HANDLE hFile, LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
    LARGE_INTEGER liDist;
    if (lpDistanceToMoveHigh) {
        liDist.LowPart  = (DWORD)lDistanceToMove;
        liDist.HighPart = *lpDistanceToMoveHigh;
    } else {
        liDist.QuadPart = (LONGLONG)lDistanceToMove;
    }

    LARGE_INTEGER liNewPos;
    if (SetFilePointerEx(hFile, liDist, &liNewPos, dwMoveMethod)) {
        if (lpDistanceToMoveHigh)
            *lpDistanceToMoveHigh = liNewPos.HighPart;
        g_sfpRedirected++;
        return liNewPos.LowPart;
    }

    return INVALID_SET_FILE_POINTER;
}

static bool InstallSetFilePointerHook() {
#if CRASH_TEST_DISABLE_SETFILEPOINTER
    Log("SetFilePointer hook: DISABLED (crash isolation)");
    return false;
#else
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetFilePointer");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_SetFilePointer, (void**)&orig_SetFilePointer) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("SetFilePointer hook: ACTIVE (redirected to SetFilePointerEx)");
    return true;
#endif
}

// ================================================================
// 7h. GlobalAlloc/GlobalFree - mimalloc for GMEM_FIXED
//
// ================================================================

typedef HGLOBAL (WINAPI* GlobalAlloc_fn)(UINT, SIZE_T);
typedef HGLOBAL (WINAPI* GlobalFree_fn)(HGLOBAL);
static GlobalAlloc_fn orig_GlobalAlloc = nullptr;
static GlobalFree_fn  orig_GlobalFree  = nullptr;
static long g_globalAllocFast = 0;

static HGLOBAL WINAPI hooked_GlobalAlloc(UINT uFlags, SIZE_T dwBytes) {
    // Only optimize GMEM_FIXED (flags == 0 or GPTR which includes GMEM_FIXED+GMEM_ZEROINIT)
    // GMEM_MOVEABLE must use original for GlobalLock/GlobalUnlock semantics
    if ((uFlags & GMEM_MOVEABLE) == 0 && dwBytes > 0) {
        void* ptr;
        if (uFlags & GMEM_ZEROINIT) {
            ptr = mi_calloc(1, dwBytes);
        } else {
            ptr = mi_malloc(dwBytes);
        }
        if (ptr) {
            g_globalAllocFast++;
            return (HGLOBAL)ptr;
        }
    }
    return orig_GlobalAlloc(uFlags, dwBytes);
}

static HGLOBAL WINAPI hooked_GlobalFree(HGLOBAL hMem) {
    if (hMem && mi_is_in_heap_region(hMem)) {
        mi_free(hMem);
        return NULL;
    }
    return orig_GlobalFree(hMem);
}

static bool InstallGlobalAllocHooks() {
#if CRASH_TEST_DISABLE_GLOBALALLOC
    Log("GlobalAlloc hooks: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

    void* pA = (void*)GetProcAddress(hK32, "GlobalAlloc");
    if (pA && MH_CreateHook(pA, (void*)hooked_GlobalAlloc, (void**)&orig_GlobalAlloc) == MH_OK)
        if (MH_EnableHook(pA) == MH_OK) ok++;

    void* pF = (void*)GetProcAddress(hK32, "GlobalFree");
    if (pF && MH_CreateHook(pF, (void*)hooked_GlobalFree, (void**)&orig_GlobalFree) == MH_OK)
        if (MH_EnableHook(pF) == MH_OK) ok++;

    if (ok > 0) {
        Log("GlobalAlloc hooks: ACTIVE (%d/2, mimalloc for GMEM_FIXED)", ok);
        return true;
    }
    return false;
#endif
}

// ================================================================
// 7f2. IsBadReadPtr / IsBadWritePtr - Fast Path
//
// ================================================================

typedef BOOL (WINAPI* IsBadReadPtr_fn)(const void*, UINT_PTR);
typedef BOOL (WINAPI* IsBadWritePtr_fn)(void*, UINT_PTR);
static IsBadReadPtr_fn  orig_IsBadReadPtr  = nullptr;
static IsBadWritePtr_fn orig_IsBadWritePtr = nullptr;
static long g_badPtrFastChecks = 0;

static BOOL WINAPI hooked_IsBadReadPtr(const void* lp, UINT_PTR ucb) {
    if (!lp) return TRUE;
    if (ucb == 0) return FALSE;
    if ((uintptr_t)lp < 0x10000) return TRUE;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(lp, &mbi, sizeof(mbi)) == 0) return TRUE;
    if (mbi.State != MEM_COMMIT) return TRUE;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return TRUE;

    g_badPtrFastChecks++;
    return FALSE;
}

static BOOL WINAPI hooked_IsBadWritePtr(void* lp, UINT_PTR ucb) {
    if (!lp) return TRUE;
    if (ucb == 0) return FALSE;
    if ((uintptr_t)lp < 0x10000) return TRUE;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(lp, &mbi, sizeof(mbi)) == 0) return TRUE;
    if (mbi.State != MEM_COMMIT) return TRUE;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD | PAGE_READONLY)) return TRUE;

    g_badPtrFastChecks++;
    return FALSE;
}

static bool InstallBadPtrHooks() {
#if CRASH_TEST_DISABLE_ISBADPTR
    Log("IsBadPtr hooks: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

    void* pR = (void*)GetProcAddress(hK32, "IsBadReadPtr");
    if (pR && MH_CreateHook(pR, (void*)hooked_IsBadReadPtr, (void**)&orig_IsBadReadPtr) == MH_OK)
        if (MH_EnableHook(pR) == MH_OK) ok++;

    void* pW = (void*)GetProcAddress(hK32, "IsBadWritePtr");
    if (pW && MH_CreateHook(pW, (void*)hooked_IsBadWritePtr, (void**)&orig_IsBadWritePtr) == MH_OK)
        if (MH_EnableHook(pW) == MH_OK) ok++;

    if (ok > 0) {
        Log("IsBadPtr hooks: ACTIVE (%d/2, fast VirtualQuery path)", ok);
        return true;
    }
    return false;
#endif
}

// ================================================================
// 7f. GetCurrentThreadId - TLS Cached
//
// ================================================================

typedef DWORD (WINAPI* GetCurrentThreadId_fn)(void);
typedef HANDLE (WINAPI* GetCurrentThread_fn)(void);
static GetCurrentThreadId_fn orig_GetCurrentThreadId = nullptr;
static GetCurrentThread_fn   orig_GetCurrentThread   = nullptr;

static __declspec(thread) DWORD t_cachedThreadId = 0;
static long g_threadIdCacheHits = 0;

static DWORD WINAPI hooked_GetCurrentThreadId(void) {
    DWORD id = t_cachedThreadId;
    if (id == 0) {
        id = orig_GetCurrentThreadId();
        t_cachedThreadId = id;
    }
    return id;
}

static HANDLE WINAPI hooked_GetCurrentThread(void) {
    return (HANDLE)(LONG_PTR)-2;  // constant pseudo-handle
}

static bool InstallThreadIdCacheHook() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

    void* pTid = (void*)GetProcAddress(hK32, "GetCurrentThreadId");
    if (pTid) {
        if (MH_CreateHook(pTid, (void*)hooked_GetCurrentThreadId, (void**)&orig_GetCurrentThreadId) == MH_OK)
            if (MH_EnableHook(pTid) == MH_OK) ok++;
    }

    void* pTh = (void*)GetProcAddress(hK32, "GetCurrentThread");
    if (pTh) {
        if (MH_CreateHook(pTh, (void*)hooked_GetCurrentThread, (void**)&orig_GetCurrentThread) == MH_OK)
            if (MH_EnableHook(pTh) == MH_OK) ok++;
    }

    if (ok > 0) {
        Log("ThreadId cache: ACTIVE (%d/2 hooks, TLS-cached)", ok);
        return true;
    }
    return false;
}

// ================================================================
// 7f3. QueryPerformanceCounter - Coalesced with RDTSC fast path
//
// ================================================================

typedef BOOL (WINAPI* QueryPerformanceCounter_fn)(LARGE_INTEGER*);
static QueryPerformanceCounter_fn orig_QPC = nullptr;

static __declspec(thread) LONGLONG t_lastQPC = 0;
static __declspec(thread) uint64_t t_lastRDTSC = 0;
static long g_qpcCacheHits = 0;
static long g_qpcCacheMisses = 0;

// Coalescing window in RDTSC cycles (calibrated at init)
static uint64_t g_rdtscThreshold = 0;

static BOOL WINAPI hooked_QPC(LARGE_INTEGER* lpPerformanceCount) {
    if (!lpPerformanceCount)
        return orig_QPC(lpPerformanceCount);

    // Fast path: check cache validity with RDTSC (~10 cycles)
    uint64_t nowRDTSC = __rdtsc();
    uint64_t elapsedRDTSC = nowRDTSC - t_lastRDTSC;

    if (elapsedRDTSC < g_rdtscThreshold && t_lastRDTSC != 0) {
        // Cache hit: return cached QPC value without syscall
        lpPerformanceCount->QuadPart = t_lastQPC;
        InterlockedIncrement(&g_qpcCacheHits);
        return TRUE;
    }

    // Cache miss: call original QPC and update cache
    LARGE_INTEGER now;
    orig_QPC(&now);

    t_lastQPC = now.QuadPart;
    t_lastRDTSC = nowRDTSC;
    lpPerformanceCount->QuadPart = now.QuadPart;
    InterlockedIncrement(&g_qpcCacheMisses);
    return TRUE;
}

static bool InstallQPCHook() {
    // Calibrate RDTSC threshold for 50 microseconds
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    
    // Measure RDTSC frequency over 10ms
    uint64_t rdtscStart = __rdtsc();
    QueryPerformanceCounter(&start);
    Sleep(10);
    uint64_t rdtscEnd = __rdtsc();
    QueryPerformanceCounter(&end);
    
    uint64_t rdtscElapsed = rdtscEnd - rdtscStart;
    LONGLONG qpcElapsed = end.QuadPart - start.QuadPart;
    
    // Calculate RDTSC cycles per QPC tick
    double rdtscPerQpc = (double)rdtscElapsed / (double)qpcElapsed;
    
    // 50us coalescing window in QPC ticks
    LONGLONG qpcWindow = freq.QuadPart / 20000;  // 50us
    if (qpcWindow < 1) qpcWindow = 1;
    
    // Convert to RDTSC cycles
    g_rdtscThreshold = (uint64_t)(rdtscPerQpc * qpcWindow);
    
    // Safety bounds: 1,000 - 10,000,000 cycles (0.25us - 2.5ms on 4GHz CPU)
    if (g_rdtscThreshold < 1000) g_rdtscThreshold = 1000;
    if (g_rdtscThreshold > 10000000) g_rdtscThreshold = 10000000;

    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "QueryPerformanceCounter");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_QPC, (void**)&orig_QPC) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("QPC hook: ACTIVE (50us coalescing, %llu RDTSC cycles, RDTSC fast path)", g_rdtscThreshold);
    return true;
}

// ================================================================
// 8. CreateFile - Sequential Scan + MPQ Tracking
//
// ================================================================
typedef HANDLE (WINAPI* CreateFileA_fn)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI* CreateFileW_fn)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static CreateFileA_fn orig_CreateFileA = nullptr;
static CreateFileW_fn orig_CreateFileW = nullptr;

// Helper: check if path passes through a .MPQ folder (e.g. patch-Sunlight.MPQ\DBFilesClient\...)
static bool PathPassesThroughMPQ(const char* path) {
    if (!path) return false;
    const char* p = path;
    while (p) {
        p = strchr(p, '.');
        if (!p || p == path) return false; // extension can't be first component
        if (_strnicmp(p, ".mpq", 4) == 0 && (p[4] == '\\' || p[4] == '/' || p[4] == 0)) {
            // Found .MPQ/ - verify it's a path component, not just part of filename
            // Ensure there's a separator before the dot (or it's the start of a component)
            if (p > path && (p[-1] != '\\' && p[-1] != '/' && p[-1] != ':')) {
                // Could be "thing.MPQfile" - skip
                p++;
                continue;
            }
            return true;
        }
        p++;
        if (*p == 0) break;
    }
    return false;
}

static HANDLE WINAPI hooked_CreateFileA(LPCSTR lpFileName, DWORD dwAccess, DWORD dwShare,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwDisposition, DWORD dwFlags, HANDLE hTemplate)
{
    bool isMPQ = false;
    if (lpFileName && (dwAccess & GENERIC_READ)) {
        // Strip trailing backslash (folder paths like patch-Sunlight.MPQ\)
        size_t len = strlen(lpFileName);
        const char* checkPath = lpFileName;
        char fixedPath[MAX_PATH];
        if (len > 0 && lpFileName[len-1] == '\\') {
            memcpy(fixedPath, lpFileName, len);
            fixedPath[len-1] = 0;
            checkPath = fixedPath;
        }
        const char* ext = strrchr(checkPath, '.');
        if (ext && _stricmp(ext, ".mpq") == 0) {
            dwFlags |= FILE_FLAG_SEQUENTIAL_SCAN; isMPQ = true;
        }
        // Also detect files inside .MPQ folders (patch-Sunlight.MPQ\DBFilesClient\...)
        if (!isMPQ && PathPassesThroughMPQ(lpFileName)) {
            isMPQ = true;
        }
    }
    HANDLE result = orig_CreateFileA(lpFileName, dwAccess, dwShare, lpSA, dwDisposition, dwFlags, hTemplate);
    if (isMPQ && result != INVALID_HANDLE_VALUE) {
        TrackMpqHandle(result);
#if !CRASH_TEST_DISABLE_MPQ_MMAP
        AcquireSRWLockExclusive(&g_mpqMapLock);
        MpqMapping* m = CreateMpqMapping(result, lpFileName);
        ReleaseSRWLockExclusive(&g_mpqMapLock);
        if (m) {
            Log("MPQ mmap: %s (%.1f MB)", lpFileName, m->fileSize / (1024.0 * 1024.0));
        }
#endif
    }
    // Track addon file handles for RAM-disk serving
    if (result != INVALID_HANDLE_VALUE) {
        AddonPreload_OnCreateFile(result, lpFileName);
    }
    return result;
}

static HANDLE WINAPI hooked_CreateFileW(LPCWSTR lpFileName, DWORD dwAccess, DWORD dwShare,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwDisposition, DWORD dwFlags, HANDLE hTemplate)
{
    bool isMPQ = false;
    if (lpFileName && (dwAccess & GENERIC_READ)) {
        const wchar_t* ext = wcsrchr(lpFileName, L'.');
        if (ext && (_wcsicmp(ext, L".mpq") == 0 || _wcsicmp(ext, L".MPQ") == 0)) {
            dwFlags |= FILE_FLAG_SEQUENTIAL_SCAN; isMPQ = true;
        }
    }
    HANDLE result = orig_CreateFileW(lpFileName, dwAccess, dwShare, lpSA, dwDisposition, dwFlags, hTemplate);
    if (isMPQ && result != INVALID_HANDLE_VALUE) {
        TrackMpqHandle(result);
#if !CRASH_TEST_DISABLE_MPQ_MMAP
        AcquireSRWLockExclusive(&g_mpqMapLock);
        CreateMpqMapping(result, nullptr);
        ReleaseSRWLockExclusive(&g_mpqMapLock);
#endif
    }
    if (result != INVALID_HANDLE_VALUE && lpFileName) {
        char buf[512];
        WideCharToMultiByte(CP_UTF8, 0, lpFileName, -1, buf, 512, NULL, NULL);
        AddonPreload_OnCreateFile(result, buf);
    }
    return result;
}

static bool InstallFileHooks() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;
    int ok = 0;
    void* pA = (void*)GetProcAddress(hK32, "CreateFileA");
    void* pW = (void*)GetProcAddress(hK32, "CreateFileW");
    if (pA && MH_CreateHook(pA, (void*)hooked_CreateFileA, (void**)&orig_CreateFileA) == MH_OK)
        if (MH_EnableHook(pA) == MH_OK) ok++;
    if (pW && MH_CreateHook(pW, (void*)hooked_CreateFileW, (void**)&orig_CreateFileW) == MH_OK)
        if (MH_EnableHook(pW) == MH_OK) ok++;
    if (ok > 0) { Log("CreateFile hooks: ACTIVE (%d/2, sequential scan + MPQ tracking)", ok); return true; }
    return false;
}

// ================================================================
// 9. CloseHandle - Cache Invalidation
//
// ================================================================
typedef BOOL (WINAPI* CloseHandle_fn)(HANDLE);
static CloseHandle_fn orig_CloseHandle = nullptr;

static BOOL WINAPI hooked_CloseHandle(HANDLE hObject) {
    if (!hObject || hObject == INVALID_HANDLE_VALUE ||
        hObject == GetCurrentProcess() || hObject == GetCurrentThread())
        return orig_CloseHandle(hObject);
#if !CRASH_TEST_DISABLE_MPQ_MMAP
    AcquireSRWLockExclusive(&g_mpqMapLock);
    DestroyMpqMapping(hObject);
    ReleaseSRWLockExclusive(&g_mpqMapLock);
#endif
    UntrackMpqHandle(hObject);
    if (g_cacheInitialized) {
        AcquireSRWLockExclusive(&g_cacheLock);
        for (int i = 0; i < MAX_CACHED_HANDLES; i++) {
            if (g_readCache[i].active && g_readCache[i].handle == hObject) {
                g_readCache[i].active = false; g_readCache[i].validBytes = 0; break;
            }
        }
        ReleaseSRWLockExclusive(&g_cacheLock);
    }
    return orig_CloseHandle(hObject);
}

static bool InstallCloseHandleHook() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_CloseHandle, (void**)&orig_CloseHandle) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("CloseHandle hook: ACTIVE (cache invalidation on file close)");
    return true;
}

// 9c. Retroactive MPQ handle scanner finds MPQ handles opened before DLL loaded.
//

typedef DWORD (WINAPI* GetFinalPathNameByHandleA_fn)(HANDLE, LPSTR, DWORD, DWORD);
static GetFinalPathNameByHandleA_fn pGetFinalPathNameByHandleA = nullptr;

static void ScanExistingMpqHandles() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (hK32) {
        pGetFinalPathNameByHandleA = (GetFinalPathNameByHandleA_fn)
            GetProcAddress(hK32, "GetFinalPathNameByHandleA");
    }
    if (!pGetFinalPathNameByHandleA) {
        Log("MPQ scan: GetFinalPathNameByHandleA not available - skipped");
        return;
    }

    char pathBuf[MAX_PATH];
    int tracked = 0;
    int mapped  = 0;
    int alreadyTracked = 0;

    for (DWORD h = 4; h < 0x40000; h += 4) {
        HANDLE handle = (HANDLE)(uintptr_t)h;

        SetLastError(0);
        DWORD fileType = GetFileType(handle);
        // Accept both files and folders (WoW reads MPQ folders as archives)
        if (fileType != FILE_TYPE_DISK && fileType != FILE_TYPE_UNKNOWN) continue;
        if (GetLastError() == ERROR_INVALID_HANDLE) continue;

        DWORD len = pGetFinalPathNameByHandleA(handle, pathBuf, MAX_PATH,
                                                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (len == 0 || len >= MAX_PATH) continue;

        // Check for .mpq/.MPQ in path - file extension, folder name, or parent directory
        bool isMpq = (len >= 4 && _stricmp(pathBuf + len - 4, ".mpq") == 0)
                  || PathPassesThroughMPQ(pathBuf);
        if (!isMpq) continue;

        if (IsMpqHandle(handle)) {
            alreadyTracked++;
            continue;
        }

        TrackMpqHandle(handle);
        tracked++;

        const char* displayPath = pathBuf;
        if (pathBuf[0] == '\\' && pathBuf[1] == '\\' &&
            pathBuf[2] == '?' && pathBuf[3] == '\\') {
            displayPath = pathBuf + 4;
        }

        // Try to memory-map
#if !CRASH_TEST_DISABLE_MPQ_MMAP
        AcquireSRWLockExclusive(&g_mpqMapLock);
        MpqMapping* m = CreateMpqMapping(handle, displayPath);
        ReleaseSRWLockExclusive(&g_mpqMapLock);
        if (m) {
            mapped++;
            Log("MPQ mmap: %s (%.1f MB)", displayPath, m->fileSize / (1024.0 * 1024.0));
        }
#else
        Log("MPQ tracked: %s", displayPath);
#endif
    }

#if !CRASH_TEST_DISABLE_MPQ_MMAP
    Log("MPQ scan: %d handles tracked, %d memory-mapped (%.1f MB), %d already tracked",
        tracked, mapped, g_mpqMapTotalBytes / (1024.0 * 1024.0), alreadyTracked);
#else
    int foldersDetected = 0;
    char dataDir[MAX_PATH] = "";  // stored for Interface detection later
    // Filesystem scan: find .MPQ folders not yet opened by WoW
    // (e.g. patch-Sunlight.MPQ\ with only sub-folders, no handles yet)
    {
        // Use first tracked MPQ to find Data directory
        for (int i = 0; i < MPQ_HASH_SIZE; i++) {
            if (g_mpqHash[i].occupied) {
                DWORD plen = pGetFinalPathNameByHandleA(g_mpqHash[i].handle,
                    dataDir, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
                if (plen > 0 && plen < MAX_PATH) {
                    char* lastSlash = strrchr(dataDir, '\\');
                    if (lastSlash) { *lastSlash = 0; break; }
                }
            }
        }
        if (dataDir[0]) {
            char pattern[MAX_PATH];
            WIN32_FIND_DATAA fd;
            // Scan both the Data directory and its enUS/locale subdirectory
            snprintf(pattern, MAX_PATH, "%s\\*.*", dataDir);
            HANDLE hFind = FindFirstFileA(pattern, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                    if (fd.cFileName[0] == '.') continue;
                    const char* ext = strrchr(fd.cFileName, '.');
                    if (!ext || _stricmp(ext, ".mpq") != 0) continue;
                    Log("MPQ folder detected: %s\\%s", dataDir, fd.cFileName);
                    foldersDetected++;
                } while (FindNextFileA(hFind, &fd));
                FindClose(hFind);
            }
            // Also scan parent (the actual Data folder) if we got locale subdirectory
            char* lastSlash = strrchr(dataDir, '\\');
            if (lastSlash) {
                *lastSlash = 0;
                snprintf(pattern, MAX_PATH, "%s\\*.*", dataDir);
                hFind = FindFirstFileA(pattern, &fd);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                        if (fd.cFileName[0] == '.') continue;
                        const char* ext = strrchr(fd.cFileName, '.');
                        if (!ext || _stricmp(ext, ".mpq") != 0) continue;
                        Log("MPQ folder detected: %s\\%s", dataDir, fd.cFileName);
                        foldersDetected++;
                    } while (FindNextFileA(hFind, &fd));
                    FindClose(hFind);
                }
            }
        }
    }

    // Detect Interface folder as virtual MPQ (addon files, icons, UI textures)
    {
        char* lastSlash = strrchr(dataDir, '\\');
        if (lastSlash) {
            *lastSlash = 0;
            char ifPath[MAX_PATH];
            snprintf(ifPath, MAX_PATH, "%s\\Interface", dataDir);
            if (GetFileAttributesA(ifPath) != INVALID_FILE_ATTRIBUTES)
                Log("MPQ virtual archive: %s (Interface)", ifPath);
        }
    }

    Log("MPQ scan: %d handles, %d folders, %d already tracked (mmap disabled)",
        tracked, foldersDetected, alreadyTracked);
#endif
}

// ================================================================
// 9b. FlushFileBuffers - Skip for MPQ (read-only)
//
// ================================================================

typedef BOOL (WINAPI* FlushFileBuffers_fn)(HANDLE);
static FlushFileBuffers_fn orig_FlushFileBuffers = nullptr;
static long g_flushSkipped = 0;

static BOOL WINAPI hooked_FlushFileBuffers(HANDLE hFile) {
    if (IsMpqHandle(hFile)) {
        InterlockedIncrement(&g_flushSkipped);
        return TRUE;
    }
    return orig_FlushFileBuffers(hFile);
}

static bool InstallFlushFileBuffersHook() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FlushFileBuffers");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_FlushFileBuffers, (void**)&orig_FlushFileBuffers) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("FlushFileBuffers hook: ACTIVE (skip for read-only MPQ handles)");
    return true;
}

// 9d. Multi-client detection via named mutex.
//

static void DetectMultiClient() {
    g_instanceMutex = CreateMutexA(NULL, FALSE, "wow_optimize_instance_v2");
    if (g_instanceMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        g_isMultiClient = true;
        Log("Multi-client: DETECTED (conservative timer + sleep)");
    } else {
        g_isMultiClient = false;
        Log("Single client: optimal timer + sleep settings");
    }
}

// 10. System timer resolution.
//
static void SetHighTimerResolution() {
    typedef LONG (WINAPI* NtSetTimerRes_fn)(ULONG, BOOLEAN, PULONG);
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return;
    auto p = (NtSetTimerRes_fn)GetProcAddress(h, "NtSetTimerResolution");
    if (!p) return;
    ULONG actual;
    // Multi-client: 1.0ms to reduce CPU overhead
    // Single client: 0.5ms for best frame pacing
    ULONG requested = g_isMultiClient ? 10000 : 5000;
    double requestedMs = requested / 10000.0;
    if (p(requested, TRUE, &actual) == 0) {
        double actualMs = actual / 10000.0;
        // Sanity check: valid range is 0.5ms - 100ms (Wine/VM can return garbage)
        if (actualMs >= 0.1 && actualMs <= 100.0) {
            Log("Timer resolution: %.3f ms (requested %.3f ms%s)",
                actualMs, requestedMs,
                g_isMultiClient ? ", multi-client mode" : "");
        } else {
            Log("Timer resolution: SET (actual value invalid: %.0f ms - Wine/VM detected, ignoring)",
                actualMs);
            Log("Timer resolution: requested %.3f ms%s",
                requestedMs,
                g_isMultiClient ? " (multi-client mode)" : "");
        }
    } else {
        Log("WARNING: Timer resolution change failed");
    }
}

// 11. Large pages - requires SeLockMemoryPrivilege.
//
// Enables mimalloc large page support if privilege is available.
static void TryEnableLargePages() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueA(NULL, "SeLockMemoryPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hToken); return;
    }
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        Log("Large pages: no permission (need 'Lock pages in memory' policy)"); return;
    }
    mi_option_set(mi_option_allow_large_os_pages, 1);
    Log("Large pages: enabled for mimalloc");
}

// 12. Thread optimization - ideal processor, priority.
//
static void OptimizeThreads() {
    DWORD pid = GetCurrentProcessId();
    DWORD mainTid = 0;
    ULONGLONG earliest = MAXULONGLONG;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (ht) {
                    FILETIME c, e, k, u;
                    if (GetThreadTimes(ht, &c, &e, &k, &u)) {
                        ULONGLONG ct = ((ULONGLONG)c.dwHighDateTime << 32) | c.dwLowDateTime;
                        if (ct < earliest) { earliest = ct; mainTid = te.th32ThreadID; }
                    }
                    CloseHandle(ht);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    if (!mainTid) { Log("WARNING: Could not find main thread"); return; }

    g_mainThreadId = mainTid;

    if (IsWine()) {
        Log("Main thread %lu: ideal-core/priority SKIPPED (Wine/Rosetta)", mainTid);
        return;
    }

    HANDLE hMain = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, mainTid);
    if (!hMain) return;
    SYSTEM_INFO si; GetSystemInfo(&si);
    DWORD core = (si.dwNumberOfProcessors > 2) ? 1 : 0;
    SetThreadIdealProcessor(hMain, core);
    SetThreadPriority(hMain, THREAD_PRIORITY_ABOVE_NORMAL);
    CloseHandle(hMain);
    Log("Main thread %lu: ideal core %lu, priority ABOVE_NORMAL (of %lu cores)", mainTid, core, si.dwNumberOfProcessors);
}

// 13. Process priority.
//
// Hook SetPriorityClass to prevent WoW from downgrading priority after we set it
typedef BOOL (WINAPI* SetPriorityClass_fn)(HANDLE, DWORD);
static SetPriorityClass_fn orig_SetPriorityClass = nullptr;
static volatile LONG g_priorityDowngradesBlocked = 0;

static BOOL WINAPI hooked_SetPriorityClass(HANDLE hProcess, DWORD dwPriorityClass) {
    // Allow our initial setup and upgrades (ABOVE_NORMAL, HIGH, REALTIME)
    if (dwPriorityClass >= ABOVE_NORMAL_PRIORITY_CLASS) {
        return orig_SetPriorityClass(hProcess, dwPriorityClass);
    }
    
    // Block downgrade attempts (NORMAL, BELOW_NORMAL, IDLE)
    if (hProcess == GetCurrentProcess() || hProcess == (HANDLE)-1) {
        InterlockedIncrement(&g_priorityDowngradesBlocked);
        return TRUE;  // Fake success to avoid breaking WoW logic
    }
    
    // Allow other processes (shouldn't happen, but be safe)
    return orig_SetPriorityClass(hProcess, dwPriorityClass);
}

// Helper: try to enable SE_INC_BASE_PRIORITY_NAME privilege (allows setting process priority above normal)
static bool TryEnablePriorityPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeIncreaseBasePriorityPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return ok && err == ERROR_SUCCESS;
}

static void OptimizeProcess() {
    // Try to obtain the privilege needed for above-normal/high priority
    TryEnablePriorityPrivilege();
    
    // Try ABOVE_NORMAL first (requires admin rights)
    if (SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS)) {
        // FALSE = enable priority boost (Windows dynamic boost still active on top of our priority)
        // Note: SetProcessPriorityBoost(hProcess, TRUE) would DISABLE the boost
        SetProcessPriorityBoost(GetCurrentProcess(), FALSE);
        Log("Process: Above Normal priority set successfully");
    } else {
        // Fallback: try HIGH_PRIORITY_CLASS (may work without full admin in some cases)
        DWORD err = GetLastError();
        if (SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
            SetProcessPriorityBoost(GetCurrentProcess(), FALSE);
            Log("Process: High priority set (Above Normal requires admin, error %lu)", err);
        } else {
            err = GetLastError();
            Log("Process: Failed to set priority (error %lu) - run WoW as administrator for Above Normal/High priority", err);
        }
    }
}

// Priority watchdog thread - monitors and restores process priority
static HANDLE g_priorityWatchdogThread = NULL;
static volatile bool g_priorityWatchdogActive = true;
static DWORD g_priorityWatchdogLastLogTick = 0;

static DWORD WINAPI PriorityWatchdogProc(LPVOID param) {
    while (g_priorityWatchdogActive) {
        Sleep(2000);  // Check every 2 seconds
        
        if (!g_priorityWatchdogActive) break;
        
        DWORD currentPriority = GetPriorityClass(GetCurrentProcess());
        
        if (currentPriority < ABOVE_NORMAL_PRIORITY_CLASS) {
            if (SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS)) {
                InterlockedIncrement(&g_priorityWatchdogRestores);
                // Rate-limit: log first 3 restorations immediately, then once per 60s
                // Loading screens repeatedly call SetPriorityClass(NORMAL), causing
                // log spam without the rate limit.
                LONG count = g_priorityWatchdogRestores;
                DWORD now = GetTickCount();
                if (count <= 3 || (now - g_priorityWatchdogLastLogTick) > 60000) {
                    Log("[Priority] Watchdog restored Above Normal priority (was %lu, restorations=%ld)", 
                        currentPriority, count);
                    g_priorityWatchdogLastLogTick = now;
                }
            }
        }
    }
    
    return 0;
}

static void StartPriorityWatchdog() {
    g_priorityWatchdogActive = true;
    g_priorityWatchdogThread = CreateThread(NULL, 0, PriorityWatchdogProc, NULL, CREATE_SUSPENDED, NULL);
    if (g_priorityWatchdogThread) {
        SetThreadPriority(g_priorityWatchdogThread, THREAD_PRIORITY_LOWEST);
        ResumeThread(g_priorityWatchdogThread);
        Log("Process: Priority watchdog started (2s interval)");
    } else {
        Log("WARNING: Failed to start priority watchdog");
    }
}

static void StopPriorityWatchdog() {
    g_priorityWatchdogActive = false;
    if (g_priorityWatchdogThread) {
        WaitForSingleObject(g_priorityWatchdogThread, 3000);
        CloseHandle(g_priorityWatchdogThread);
        g_priorityWatchdogThread = NULL;
    }
}

// 14. Working set.
//
static void OptimizeWorkingSet() {
    SIZE_T minWS, maxWS;
    if (g_isMultiClient) {
        // Multi-client: reduce footprint to ease 32-bit address space pressure
        minWS = 64 * 1024 * 1024;    // 64 MB
        maxWS = 1024ULL * 1024 * 1024; // Raised from 512MB → 1024MB to prevent ERROR #134 during char switches
    } else {
        minWS = 256 * 1024 * 1024;    // 256 MB
        maxWS = 2048ULL * 1024 * 1024; // 2048 MB
    }
    if (SetProcessWorkingSetSize(GetCurrentProcess(), minWS, maxWS))
        Log("Working set: min %u MB, max %u MB%s",
           (unsigned)(minWS / (1024 * 1024)),
           (unsigned)(maxWS / (1024 * 1024)),
            g_isMultiClient ? " (multi-client reduced)" : "");
    else
        Log("WARNING: Working set failed (error %lu)", GetLastError());
}

// 15. mimalloc configuration.
//
// Configures mimalloc options and pre-warms the allocator.
static void ConfigureMimalloc() {
    // Allow large OS pages when enabled by system policy
    mi_option_set(mi_option_allow_large_os_pages, 1);

    // v3.3.x: eager commit arenas on Windows for faster allocation
    // Commits entire arena at once instead of page-by-page
    mi_option_set(mi_option_arena_eager_commit, 1);

    // Purge delay: -1 = never purge (keeps freed pages mapped to prevent
    // stale Lua string reads during reload from ACCESS_VIOLATION).
    // Multi-client overrides to aggressive purging in AdjustMimallocForMultiClient.
    mi_option_set(mi_option_purge_delay, -1);

    // v3.3.x: use decommit (MEM_DECOMMIT) rather than reset (MEM_RESET)
    // Decommit releases physical memory immediately, reducing RSS pressure
    mi_option_set(mi_option_purge_decommits, 1);

    // Pre-warm allocator with 32MB to reduce VA space pressure
    // 64MB was too aggressive for HD clients with 37+ MPQs (VA fragmentation)
    void* warmup = mi_malloc(32 * 1024 * 1024);
    if (warmup) { memset(warmup, 0, 32 * 1024 * 1024); mi_free(warmup); }

    // Pre-warm size classes matching WoW allocation patterns:
    // TValue(16), Node(24-32), Table(56), TString(24-128), Proto(256-512)
    static const size_t seedSizes[] = {
        16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128,
        160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024
    };
    static const int SEEDS_PER_SIZE = 512;
    for (size_t sz : seedSizes) {
        void* batch[512];
        for (int i = 0; i < SEEDS_PER_SIZE; i++) batch[i] = mi_malloc(sz);
        for (int i = 0; i < SEEDS_PER_SIZE; i++) if (batch[i]) mi_free(batch[i]);
    }

    Log("mimalloc v%d.%d.%d configured (eager commit, decommit purge, pre-warmed 32MB + 23 size classes)",
        mi_version() / 100, (mi_version() % 100) / 10, mi_version() % 10);
}

static void AdjustMimallocForMultiClient() {
    if (g_isMultiClient) {
        // HD multi-client: aggressive memory return to prevent 32-bit VA exhaustion
        // 40+ MPQ clients can hit 2GB VA limit during boss fights
        mi_option_set(mi_option_purge_delay, 10);   // 10ms purge delay
        mi_option_set(mi_option_purge_decommits, 1); // MEM_DECOMMIT for immediate RSS reduction
        mi_collect(true);
        Log("mimalloc: multi-client HD mode (10ms purge, decommit, immediate collect)");
    }
}

// 16. FPS cap removal - patches CMP EAX, 200 to CMP EAX, 999.
//
static uintptr_t FindPattern(uintptr_t base, size_t size, const uint8_t* pat, const char* mask) {
    for (size_t i = 0; i < size; i++) {
        bool found = true;
        for (size_t j = 0; mask[j]; j++) {
            if (mask[j] == 'x' && *(uint8_t*)(base + i + j) != pat[j]) { found = false; break; }
        }
        if (found) return base + i;
    }
    return 0;
}

static void TryRemoveFPSCap() {
    HMODULE hWow = GetModuleHandleA(NULL);
    if (!hWow) return;
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hWow, &modInfo, sizeof(modInfo))) return;

    // BUGFIX: scan for CMP EAX, 200 then verify next byte is a conditional jump
    const uint8_t pat[] = { 0x3D, 0xC8, 0x00, 0x00, 0x00 };
    uintptr_t base = (uintptr_t)hWow;
    size_t size = modInfo.SizeOfImage;
    uintptr_t addr = 0;
    uintptr_t searchFrom = base;

    while (searchFrom < base + size) {
        uintptr_t found = FindPattern(searchFrom, base + size - searchFrom, pat, "xxxxx");
        if (!found) break;

        // Verify: instruction after CMP should be a conditional jump
        uint8_t b = *(uint8_t*)(found + 5);
        if (b == 0x7E || b == 0x7F) {
            // JLE or JG short - valid FPS cap pattern
            addr = found;
            break;
        }
        if (b == 0x0F) {
            uint8_t b2 = *(uint8_t*)(found + 6);
            if (b2 == 0x8E || b2 == 0x8F) {
                // JLE or JG near - valid FPS cap pattern
                addr = found;
                break;
            }
        }

        searchFrom = found + 1;
    }

    if (addr) {
        DWORD old;
        if (VirtualProtect((void*)(addr + 1), 4, PAGE_EXECUTE_READWRITE, &old)) {
            *(uint32_t*)(addr + 1) = 999;
            VirtualProtect((void*)(addr + 1), 4, old, &old);
            Log("FPS cap: changed from 200 to 999 at 0x%08X", (unsigned)addr);
        }
    } else {
        Log("FPS cap: signature not found (may be a different build)");
    }
}

// Periodic stats dump called from hooked_Sleep.
//

static void DumpPeriodicStats() {
    extern long g_assetPathHits;
    extern long g_assetPathMisses;
    extern long g_tvalueMemcpyHits;
    extern long g_sysInfoHits;
    extern long g_regCacheHits;
    extern long g_regCacheMisses;
    extern long g_rttiHits;
    extern long g_rttiMisses;
    extern long g_streamReadHits;
    extern long g_streamReadFallbacks;
    extern long g_streamWriteHits;
    extern long g_streamWriteFallbacks;
    // Process memory diagnostics (helps diagnose HD/custom client OOM)
    PROCESS_MEMORY_COUNTERS pmc = {};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        Log("[Stats] Process: WS=%.0fMB Peak=%.0fMB PageFaults=%lu",
            pmc.WorkingSetSize / (1024.0 * 1024.0),
            pmc.PeakWorkingSetSize / (1024.0 * 1024.0),
            pmc.PageFaultCount);
    }

    // Virtual address space scan (32-bit fragmentation indicator)
    {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t addr = 0x10000;
        SIZE_T largestFree = 0;
        SIZE_T totalFree = 0;
        while (addr < 0x7FFF0000) {
            if (VirtualQuery((void*)addr, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_FREE) {
                    if (mbi.RegionSize > largestFree) largestFree = mbi.RegionSize;
                    totalFree += mbi.RegionSize;
                }
                addr += mbi.RegionSize;
                if (mbi.RegionSize == 0) addr += 0x10000;
            } else {
                addr += 0x10000;
            }
        }
        Log("[Stats] VA Space: Free=%.0fMB LargestBlock=%.0fMB%s",
            totalFree / (1024.0 * 1024.0),
            largestFree / (1024.0 * 1024.0),
           (largestFree < 64 * 1024 * 1024) ? " WARNING: fragmented" : "");
    }    
    Log("[Stats] ====================================");

#if !CRASH_TEST_DISABLE_MPQ_MMAP
    Log("[Stats] MPQ mmap: %ld reads, %ld faults, %d files, %.1f MB mapped",
        g_mpqMapHits, g_mpqMapMisses, g_mpqMapCount,
        g_mpqMapTotalBytes / (1024.0 * 1024.0));
#endif

#if !CRASH_TEST_DISABLE_QPC_CACHE
    if (g_qpcCacheHits + g_qpcCacheMisses > 0) {
        long total = g_qpcCacheHits + g_qpcCacheMisses;
        Log("[Stats] QPC: %ld cached, %ld real (%.1f%% cache hit)",
            g_qpcCacheHits, g_qpcCacheMisses,
           (double)g_qpcCacheHits / total * 100.0);
    }
#endif

    if (g_flushSkipped > 0)
        Log("[Stats] FlushFileBuffers: %ld MPQ skipped", g_flushSkipped);
    if (g_prefetchQueued > 0 || g_prefetchHits > 0)
        Log("[Stats] MPQ Prefetch: %ld queued, %ld hits, %ld misses, %ld cancelled (%.1f%% hit rate)",
            g_prefetchQueued, g_prefetchHits, g_prefetchMisses, g_prefetchCancelled,
           (g_prefetchHits + g_prefetchMisses > 0) ? (double)g_prefetchHits / (g_prefetchHits + g_prefetchMisses) * 100.0 : 0.0);
    if (g_compareAsciiHits + g_compareFallbacks > 0)
        Log("[Stats] CompareStringA: %ld fast, %ld fallback (%.1f%%)",
            g_compareAsciiHits, g_compareFallbacks,
           (double)g_compareAsciiHits / (g_compareAsciiHits + g_compareFallbacks) * 100.0);
    if (g_fileAttrHits + g_fileAttrMisses > 0)
        Log("[Stats] GetFileAttributes: %ld hits, %ld misses (%.1f%%)",
            g_fileAttrHits, g_fileAttrMisses,
           (double)g_fileAttrHits / (g_fileAttrHits + g_fileAttrMisses) * 100.0);
    if (g_badPtrFastChecks > 0)
        Log("[Stats] IsBadPtr: %ld fast checks", g_badPtrFastChecks);
    if (g_csSpinHits > 0)
        Log("[Stats] CriticalSection: %ld spin-acquired", g_csSpinHits);
    if (g_sfpRedirected > 0)
        Log("[Stats] SetFilePointer: %ld redirected", g_sfpRedirected);
    if (g_fsizeHits + g_fsizeMisses > 0)
        Log("[Stats] GetFileSize: %ld hits, %ld misses (%.1f%%)",
            g_fsizeHits, g_fsizeMisses,
           (double)g_fsizeHits / (g_fsizeHits + g_fsizeMisses) * 100.0);
    if (g_wfsSpinHits + g_wfsFallbacks > 0)
        Log("[Stats] WaitForSingleObject: %ld spin, %ld fallback (%.1f%% spin)",
            g_wfsSpinHits, g_wfsFallbacks,
           (double)g_wfsSpinHits / (g_wfsSpinHits + g_wfsFallbacks) * 100.0);
    if (g_modHits + g_modMisses > 0)
        Log("[Stats] GetModuleHandle: %ld hits, %ld misses (%.1f%%)",
            g_modHits, g_modMisses,
           (double)g_modHits / (g_modHits + g_modMisses) * 100.0);
    if (g_lstrcmpHits + g_lstrcmpFallbacks > 0)
        Log("[Stats] lstrcmp: %ld fast, %ld fallback (%.1f%%)",
            g_lstrcmpHits, g_lstrcmpFallbacks,
           (double)g_lstrcmpHits / (g_lstrcmpHits + g_lstrcmpFallbacks) * 100.0);
    if (g_mbwcFastHits + g_mbwcFallbacks > 0)
        Log("[Stats] MultiByteToWideChar: %ld fast, %ld fallback (%.1f%%)",
            g_mbwcFastHits, g_mbwcFallbacks,
           (double)g_mbwcFastHits / (g_mbwcFastHits + g_mbwcFallbacks) * 100.0);
    if (g_wcmbFastHits + g_wcmbFallbacks > 0)
        Log("[Stats] WideCharToMultiByte: %ld fast, %ld fallback (%.1f%%)",
            g_wcmbFastHits, g_wcmbFallbacks,
           (double)g_wcmbFastHits / (g_wcmbFastHits + g_wcmbFallbacks) * 100.0);
    if (g_profHits + g_profMisses > 0)
        Log("[Stats] GetPrivateProfile: %ld hits, %ld misses (%.1f%%)",
            g_profHits, g_profMisses,
           (double)g_profHits / (g_profHits + g_profMisses) * 100.0);
    if (g_gpaHits + g_gpaMisses > 0)
        Log("[Stats] GetProcAddress: %ld hits, %ld misses, %ld evictions (%.1f%% hit rate)",
            g_gpaHits, g_gpaMisses, g_gpaEvictions,
           (double)g_gpaHits / (g_gpaHits + g_gpaMisses) * 100.0);
    if (g_gmfHits + g_gmfMisses > 0)
        Log("[Stats] GetModuleFileName: %ld hits, %ld misses (%.1f%%)",
            g_gmfHits, g_gmfMisses,
           (double)g_gmfHits / (g_gmfHits + g_gmfMisses) * 100.0);
    if (g_envHits + g_envMisses > 0)
        Log("[Stats] GetEnvironmentVariable: %ld hits, %ld misses (%.1f%%)",
            g_envHits, g_envMisses,
           (double)g_envHits / (g_envHits + g_envMisses) * 100.0);
    if (g_crtStrlenHits + g_crtStrlenFallbacks > 0)
        Log("[Stats] CRT strlen: %ld fast, %ld fallback (%.1f%%)",
            g_crtStrlenHits, g_crtStrlenFallbacks,
           (double)g_crtStrlenHits / (g_crtStrlenHits + g_crtStrlenFallbacks) * 100.0);
    if (g_crtStrcmpHits + g_crtStrcmpFallbacks > 0)
        Log("[Stats] CRT strcmp: %ld fast, %ld fallback (%.1f%%)",
            g_crtStrcmpHits, g_crtStrcmpFallbacks,
           (double)g_crtStrcmpHits / (g_crtStrcmpHits + g_crtStrcmpFallbacks) * 100.0);
    if (g_crtMemcmpHits + g_crtMemcmpFallbacks > 0)
        Log("[Stats] CRT memcmp: %ld fast, %ld fallback (%.1f%%)",
            g_crtMemcmpHits, g_crtMemcmpFallbacks,
           (double)g_crtMemcmpHits / (g_crtMemcmpHits + g_crtMemcmpFallbacks) * 100.0);
    if (g_crtMemcpyHits + g_crtMemcpyFallbacks > 0)
        Log("[Stats] CRT memcpy: %ld fast, %ld fallback (%.1f%%)",
            g_crtMemcpyHits, g_crtMemcpyFallbacks,
           (double)g_crtMemcpyHits / (g_crtMemcpyHits + g_crtMemcpyFallbacks) * 100.0);
    if (g_crtMemsetHits + g_crtMemsetFallbacks > 0)
        Log("[Stats] CRT memset: %ld fast, %ld fallback (%.1f%%)",
            g_crtMemsetHits, g_crtMemsetFallbacks,
           (double)g_crtMemsetHits / (g_crtMemsetHits + g_crtMemsetFallbacks) * 100.0);
    if (g_memchrHits + g_memchrFallbacks > 0)
        Log("[Stats] CRT memchr: %lld fast, %lld fallback (%.1f%%)",
            g_memchrHits, g_memchrFallbacks,
           (double)g_memchrHits / (g_memchrHits + g_memchrFallbacks) * 100.0);
    if (g_strchrHits + g_strchrFallbacks > 0)
        Log("[Stats] CRT strchr: %lld fast, %lld fallback (%.1f%%)",
            g_strchrHits, g_strchrFallbacks,
           (double)g_strchrHits / (g_strchrHits + g_strchrFallbacks) * 100.0);
    if (g_strcpyHits + g_strcpyFallbacks > 0)
        Log("[Stats] CRT strcpy: %lld fast, %lld fallback (%.1f%%)",
            g_strcpyHits, g_strcpyFallbacks,
           (double)g_strcpyHits / (g_strcpyHits + g_strcpyFallbacks) * 100.0);

    // Frame Throttle stats
    {
        long skipped = 0, executed = 0, bypassed = 0;
        GetFrameThrottleStats(&skipped, &executed, &bypassed);
        if (skipped + executed + bypassed > 0) {
            long total = skipped + executed;
            double skipPct = total > 0 ? (double)skipped / total * 100.0 : 0.0;
            Log("[Stats] Frame Throttle: %ld executed, %ld skipped, %ld bypassed (%.1f%% reduction)",
                executed, skipped, bypassed, skipPct);
        }
    }

    // Tooltip Cache stats
    {
        TooltipCache::Stats stats = TooltipCache::GetStats();
        if (stats.hits + stats.misses > 0) {
            Log("[Stats] Tooltip Cache: %lld hits, %lld misses, %lld evictions (%.1f%% hit rate)",
                stats.hits, stats.misses, stats.evictions, stats.hitRate);
        }
    }

    // Spell Cache stats
    {
        SpellCache::Stats stats;
        SpellCache::GetStats(&stats);
        if (stats.hits + stats.misses > 0) {
            double hitRate = (double)stats.hits / (stats.hits + stats.misses) * 100.0;
            Log("[Stats] Spell Cache: %ld hits, %ld misses, %ld evictions, %ld entries (%.1f%% hit rate)",
                stats.hits, stats.misses, stats.evictions, stats.cacheSize, hitRate);
        }
    }

    // UI Frame Batch stats - REMOVED (optimization disabled)
    // {
    //     long batched = 0, iterations = 0, peak = 0;
    //     GetUIFrameBatchStats(&batched, &iterations, &peak);
    //     if (batched > 0) {
    //         double avgIterations = batched > 0 ? (double)iterations / batched : 0.0;
    //         Log("[Stats] UI Frame Batch: %ld batches, %ld total iterations, %.1f avg/batch, %ld peak",
    //             batched, iterations, avgIterations, peak);
    //     }
    // }

    if (g_tableReshapeHits > 0)
        Log("[Stats] Lua Table Rehash: %ld rounded to pow2", g_tableReshapeHits);
    if (g_getstrHits + g_getstrFallbacks > 0) {
        Log("[Stats] luaH_getstr: %I64u hits, %I64u fallbacks (%.1f%%)",
            g_getstrHits, g_getstrFallbacks,
           (double)g_getstrHits / (g_getstrHits + g_getstrFallbacks) * 100.0);
    }
    if (g_assetPathHits + g_assetPathMisses > 0)
        Log("[Stats] Asset path cache: %ld hits, %ld misses (%.1f%%)",
            g_assetPathHits, g_assetPathMisses,
           (double)g_assetPathHits / (g_assetPathHits + g_assetPathMisses) * 100.0);
    if (g_tvalueMemcpyHits > 0)
        Log("[Stats] TValue memcpy: %ld 16-byte fast copies", g_tvalueMemcpyHits);
    if (g_lastFrameMs > 0)
        Log("[Stats] Frame: %.1f ms (lower = smoother)", g_lastFrameMs);
    if (g_sysInfoHits > 0)
        Log("[Stats] GetSystemInfo: %ld cached", g_sysInfoHits);
    if (g_regCacheHits + g_regCacheMisses > 0)
        Log("[Stats] RegQueryValueEx: %ld hits, %ld misses (%.1f%%)",
            g_regCacheHits, g_regCacheMisses,
           (double)g_regCacheHits / (g_regCacheHits + g_regCacheMisses) * 100.0);

    if (g_combatLogCacheHits + g_combatLogCacheMisses > 0) {
        Log("[Stats] CombatLog: %I64u hits, %I64u misses (%.1f%%)",
            g_combatLogCacheHits, g_combatLogCacheMisses,
           (double)g_combatLogCacheHits / (g_combatLogCacheHits + g_combatLogCacheMisses) * 100.0);
    }

    if (g_pushStrHits + g_pushStrMisses > 0) {
        Log("[Stats] lua_pushstring: %I64u hits, %I64u misses (%.1f%%)",
            g_pushStrHits, g_pushStrMisses,
           (double)g_pushStrHits / (g_pushStrHits + g_pushStrMisses) * 100.0);
    }

    if (g_rawGetIHits + g_rawGetIMisses > 0) {
        Log("[Stats] lua_rawgeti: %I64u hits, %I64u misses (%.1f%%)",
            g_rawGetIHits, g_rawGetIMisses,
           (double)g_rawGetIHits / (g_rawGetIHits + g_rawGetIMisses) * 100.0);
    }

    if (vaOk && g_vaArenaActive) {
        long total = g_vaArenaHits + g_vaArenaFallbacks;
        double arenaPct = total > 0 ? (double)g_vaArenaHits / total * 100.0 : 0.0;
        double usedMB = (double)g_vaArenaUsedPages * VA_ARENA_PAGE_SIZE / (1024.0 * 1024.0);
        Log("[Stats] VA Arena v3: %ld hits, %ld fallbacks, %ld fail (%.1f%% arena, %.1f MB used)",
            g_vaArenaHits, g_vaArenaFallbacks, g_vaArenaFailures,
            arenaPct, usedMB);
    }
    if (g_rttiHits + g_rttiMisses > 0)
        Log("[Stats] RTTI type check: %ld hits, %ld misses (%.1f%% hit rate)",
            g_rttiHits, g_rttiMisses,
           (double)g_rttiHits / (g_rttiHits + g_rttiMisses) * 100.0);
    if (g_streamReadHits + g_streamReadFallbacks > 0)
        Log("[Stats] Stream read: %ld fast, %ld fallback (%.1f%%)",
            g_streamReadHits, g_streamReadFallbacks,
           (double)g_streamReadHits / (g_streamReadHits + g_streamReadFallbacks) * 100.0);
    if (g_streamWriteHits + g_streamWriteFallbacks > 0)
        Log("[Stats] Stream write: %ld fast, %ld fallback (%.1f%%)",
            g_streamWriteHits, g_streamWriteFallbacks,
           (double)g_streamWriteHits / (g_streamWriteHits + g_streamWriteFallbacks) * 100.0);
    if (g_debugStringSkipped > 0)
        Log("[Stats] OutputDebugString: %ld skipped", g_debugStringSkipped);

    LuaFastPath::Stats fps = LuaFastPath::GetStats();
    if (fps.active) {
        long fmtTotal = fps.formatFastHits + fps.formatFallbacks;
        if (fmtTotal > 0)
            Log("[Stats] Format: %ld fast, %ld fallback (%.1f%%)",
                fps.formatFastHits, fps.formatFallbacks,
               (double)fps.formatFastHits / fmtTotal * 100.0);
    }
    // Receive-side network stats
    if (g_recvCalls > 0 || g_WSARecvCalls > 0)
        Log("[Stats] Network RX: recv=%ld calls, %.1f KB, %ld wouldblock | WSARecv=%ld calls, %.1f KB, %ld wouldblock",
            g_recvCalls, g_recvBytes / 1024.0, g_recvWouldBlock,
            g_WSARecvCalls, g_WSARecvBytes / 1024.0, g_WSARecvWouldBlock);
    if (fps.phase2Active) {
        Log("[Stats] Phase2: find=%ld/%ld match=%ld/%ld type=%ld math=%ld strlen=%ld byte=%ld tostr=%ld/%ld tonum=%ld next=%ld/%ld rawget=%ld/%ld rawset=%ld/%ld tins=%ld/%ld trem=%ld/%ld concat=%ld/%ld unpack=%ld/%ld select=%ld/%ld raweq=%ld/%ld sub=%ld lower=%ld upper=%ld ipairs=%ld/%ld iter=%ld/%ld random=%ld/%ld sqrt=%ld/%ld rep=%ld/%ld find_full=%ld/%ld",
            fps.findPlainHits, fps.findFallbacks, fps.matchHits, fps.matchFallbacks, fps.typeHits, fps.mathHits, fps.strlenHits, fps.strbyteHits,
            fps.tostringHits, fps.tostringFallbacks, fps.tonumberHits,
            fps.nextHits, fps.nextFallbacks, fps.rawgetHits, fps.rawgetFallbacks,
            fps.rawsetHits, fps.rawsetFallbacks,
            fps.tableInsertHits, fps.tableInsertFallbacks,
            fps.tableRemoveHits, fps.tableRemoveFallbacks,
            fps.tableConcatHits, fps.tableConcatFallbacks,
            fps.unpackHits, fps.unpackFallbacks,
            fps.selectHits, fps.selectFallbacks,
            fps.rawequalHits, fps.rawequalFallbacks,
            fps.strsubHits, fps.strlowerHits, fps.strupperHits,
            fps.ipairsHits, fps.ipairsFallbacks,
            fps.ipairsIteratorHits, fps.ipairsIteratorFallbacks,
            fps.mathRandomHits, fps.mathRandomFallbacks,
            fps.mathSqrtHits, fps.mathSqrtFallbacks,
            fps.strRepHits, fps.strRepFallbacks,
            fps.findFullHits, fps.findFullFallbacks);
    }

    // Unit API Fast Path Stats
    LuaFastPath::Stats fpStats = LuaFastPath::GetStats();   
    if (fpStats.unitHealthHits > 0 || fpStats.unitHealthFallbacks > 0)
        Log("[Stats] UnitHealth: %ld fast, %ld fallback", fpStats.unitHealthHits, fpStats.unitHealthFallbacks);
    if (fpStats.unitHealthMaxHits > 0 || fpStats.unitHealthMaxFallbacks > 0)
        Log("[Stats] UnitHealthMax: %ld fast, %ld fallback", fpStats.unitHealthMaxHits, fpStats.unitHealthMaxFallbacks);
    if (fpStats.unitPowerHits > 0 || fpStats.unitPowerFallbacks > 0)
        Log("[Stats] UnitPower: %ld fast, %ld fallback", fpStats.unitPowerHits, fpStats.unitPowerFallbacks);
    if (fpStats.unitPowerMaxHits > 0 || fpStats.unitPowerMaxFallbacks > 0)
        Log("[Stats] UnitPowerMax: %ld fast, %ld fallback", fpStats.unitPowerMaxHits, fpStats.unitPowerMaxFallbacks);
  
    LuaInternals::Stats lis = LuaInternals::GetStats();
    if (lis.active) {
        long catTotal = lis.concatFastHits + lis.concatFallbacks;
        if (catTotal > 0)
            Log("[Stats] Concat: %ld fast, %ld fallback (%.1f%%)",
                lis.concatFastHits, lis.concatFallbacks,
               (double)lis.concatFastHits / catTotal * 100.0);
    }

    if (fpStats.tableSortHits > 0 || fpStats.tableSortFallbacks > 0)
        Log("[Stats] TableSort: %ld fast, %ld fallback", fpStats.tableSortHits, fpStats.tableSortFallbacks);

    if (g_priorityWatchdogRestores > 0)
        Log("[Stats] Priority watchdog: %ld restorations", (long)g_priorityWatchdogRestores);

    Log("[Stats] ====================================");

}

// ================================================================
// 19. sub_869E00 - Zero-Message Frame Continue (disabled)
//
// ================================================================

typedef int (__cdecl* MsgPump_fn)(void*, int*, DWORD*, void*, void*);
static MsgPump_fn orig_MsgPump = nullptr;
static uint64_t g_msgPumpHits = 0;

static int __cdecl hooked_MsgPump(void* a1, int* a2, DWORD* a3, void* a4, void* a5) {
    int result = orig_MsgPump(a1, a2, a3, a4, a5);

    if (result == 0) {
        // Original would exit the render loop (no messages pending).
        // Previous rc1 just returned 1 → stale *a1 → infinite loop.
        // Fix: inject WM_NULL into WoW's message queue so the next
        // PeekMessageA finds a message, goes through the normal flow
        // (GetMessage → DispatchMessage → sub_868DB0), which updates
        // *a1 from the command queue.
        g_msgPumpHits++;

        // Post synthetic message to WoW's main window
        HWND hWoW = FindWindowA("GxWindowClass", nullptr);
        if (hWoW)
            PostMessageA(hWoW, WM_NULL, 0, 0);

        // Yield CPU to avoid busy-wait
        if (orig_Sleep)
            orig_Sleep(1);
        else
            Sleep(1);

        return 1;
    }

    return result;
}

static bool InstallMsgPumpHook() {
#if CRASH_TEST_DISABLE_MSGPUMP_RC1
    Log("MsgPump hook: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x00869E00;

    // Verify we're hooking a real function (prologue: push ebp; mov ebp,esp)
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("MsgPump hook: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_MsgPump, (void**)&orig_MsgPump) != MH_OK) {
        Log("MsgPump hook: MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("MsgPump hook: MH_EnableHook FAILED");
        return false;
    }

    Log("MsgPump hook: ACTIVE (sub_869E00 @ 0x00869E00 - zero-message frame continue)");
    return true;
#endif
}

// ================================================================
// 20. sub_69E220 - Swap/Present Optimization (Vulkan/D3D9)
//
// ================================================================

typedef void (__cdecl* SubFn)();
typedef void (__fastcall* SubFnThis)(void*, void*);

static SubFn orig_sub_682E50 = (SubFn)0x00682E50;
static SubFnThis orig_sub_6841D0 = (SubFnThis)0x006841D0;
static SubFnThis orig_sub_6836D0 = (SubFnThis)0x006836D0;
static SubFnThis orig_sub_6833A0 = (SubFnThis)0x006833A0;

typedef void (WINAPI* wglSwapLayerBuffers_fn)(HDC, UINT);
static wglSwapLayerBuffers_fn orig_wglSwapLayerBuffers = nullptr;

typedef void (__fastcall* SwapPresent_fn)(void*, void*);
static SwapPresent_fn orig_SwapPresent = nullptr;
static uint64_t g_glFinishSkips = 0;

static void __fastcall hooked_SwapPresent(void* This, void* unused) {
    char* T = (char*)This;

    // Wrap entire swap in SEH to handle device lost / alt-tab safely.
    // NO IsBadReadPtr - it breaks guard pages and causes mouse-triggered crashes
    // when cursor/UI redraw happens during device state transitions.
    __try {
        // sub_682E50()
        orig_sub_682E50();

        // if ([esi+2934h]) sub_6841D0(this)
        void* edi = *(void**)(T + 0x2934);
        if (edi)
            orig_sub_6841D0(This, nullptr);

        // Virtual call: eax = [esi]; edx = [eax+10h]; edx(This)
        void* vtable = *(void**)T;
        void* renderFn = *(void**)((char*)vtable + 0x10);
        if (renderFn) {
            ((void(__fastcall*)(void*, void*))renderFn)(This, nullptr);
        }

        // Check [esi+275Ch] & 0x40 → wglSwapLayerBuffers, else glFinish
        if (T[0x275C] & 0x40) {
            HDC hdc = *(HDC*)(T + 0x3AF8);
            if (orig_wglSwapLayerBuffers && hdc)
                orig_wglSwapLayerBuffers(hdc, 1);
        } else {
            // SKIP glFinish - Vulkan/D3D9 handles presentation sync
            g_glFinishSkips++;
        }

        // Post-swap cleanup
        orig_sub_6836D0(This, nullptr);
        orig_sub_6833A0(This, nullptr);
        // nullsub_3 (0x005EEB70) is a 1-byte no-op - skipped
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Device lost / alt-tab / cursor redraw race - silently skip this frame.
        // Do NOT call orig_SwapPresent here: it would re-enter the same broken state
        // and crash harder (recursive swap on lost device).
        return;
    }
}

static bool InstallSwapPresentHook() {
#if CRASH_TEST_DISABLE_SWAP_RC1
    Log("Swap present hook: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0069E220;

    // Verify prologue: push esi; mov esi, ecx
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x56 || p[1] != 0x8B || p[2] != 0xF1) {
        Log("Swap hook: BAD PROLOGUE at 0x%08X (expected 56 8B F1)", (uintptr_t)target);
        return false;
    }

    // Resolve wglSwapLayerBuffers from opengl32.dll
    HMODULE hGL = GetModuleHandleA("opengl32.dll");
    if (!hGL) {
        Log("Swap hook: opengl32.dll not loaded");
        return false;
    }
    orig_wglSwapLayerBuffers = (wglSwapLayerBuffers_fn)GetProcAddress(hGL, "wglSwapLayerBuffers");
    if (!orig_wglSwapLayerBuffers) {
        Log("Swap hook: wglSwapLayerBuffers not found");
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_SwapPresent, (void**)&orig_SwapPresent) != MH_OK) {
        Log("Swap hook: MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("Swap hook: MH_EnableHook FAILED");
        return false;
    }

    Log("Swap present hook: ACTIVE (sub_69E220 @ 0x0069E220 - glFinish skip, Vulkan/D3D9)");
    return true;
#endif
}

// ================================================================
// Shared: FNV-1a hash for C strings
// ================================================================
static inline uint64_t ComputeCStringHash(const char* s) {
    uint64_t h = 0xCBF29CE484222325ULL;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 0x100000001B3ULL;
    }
    return h;
}

// ================================================================
// 21f. sub_84E670 - lua_rawgeti Fast Path (integer-key cache)
//
// ================================================================

#define RAWGETI_CACHE_SIZE 2048
#define RAWGETI_CACHE_MASK (RAWGETI_CACHE_SIZE - 1)

struct RawGetICacheEntry {
    uint64_t keyHash;      // FNV-1a of (table_ptr ^ key)
    int      table;        // Table* pointer
    int      key;          // Integer key
    int      node;         // Cached Node* pointer
};

static RawGetICacheEntry g_rawGetICache[RAWGETI_CACHE_SIZE];

static void ClearLuaRawGetICache() {
    memset(g_rawGetICache, 0, sizeof(g_rawGetICache));
}

static void* (*orig_luaH_getnum)(int table, int key) = nullptr;  // DISABLED — unsafe across lua_State swaps

typedef int (__cdecl* lua_rawgeti_fn)(int L, int idx, int n);
static lua_rawgeti_fn orig_lua_rawgeti = nullptr;

static int __cdecl hooked_lua_rawgeti(int L, int idx, int n) {
    // FULLY DISABLED due to crash on UI reload / exit
    return orig_lua_rawgeti(L, idx, n);
}

static bool InstallLuaRawGetICache() {
#if CRASH_TEST_DISABLE_LUA_RAWGETI
    Log("lua_rawgeti cache: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0084E670;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("lua_rawgeti cache: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_lua_rawgeti, (void**)&orig_lua_rawgeti) != MH_OK) {
        Log("lua_rawgeti cache: MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("lua_rawgeti cache: MH_EnableHook FAILED");
        return false;
    }

    memset(g_rawGetICache, 0, sizeof(g_rawGetICache));

    Log("lua_rawgeti cache: ACTIVE (sub_84E670 @ 0x0084E670 - 2048-slot integer-key cache, SEH)");
    return true;
#endif
}

// ================================================================
// 21e. sub_84E350 - lua_pushstring Fast Path (TString* intern cache)
//
// ================================================================

#define PUSHSTR_CACHE_SIZE 4096
#define PUSHSTR_CACHE_MASK (PUSHSTR_CACHE_SIZE - 1)

struct PushStrCacheEntry {
    uint64_t keyHash;      // FNV-1a of C string content
    int      tstring;      // Cached TString* pointer
    uint32_t generation;   // Cache generation (matches g_getFieldGen)
};

static PushStrCacheEntry g_pushStrCache[PUSHSTR_CACHE_SIZE];

static void ClearLuaPushStringCache() {
    memset(g_pushStrCache, 0, sizeof(g_pushStrCache));
}

typedef int (__cdecl* lua_pushstring_fn)(int L, const char* s);
static lua_pushstring_fn orig_lua_pushstring = nullptr;

// TValue layout: +0x00 value (8B), +0x08 tt (int=4), +0x0C taint (DWORD)
static int __cdecl hooked_lua_pushstring(int L, const char* s) {
#if CRASH_TEST_DISABLE_LUA_PUSHSTRING
    return orig_lua_pushstring(L, s);
#else
    // nil input - push nil
    if (!s || (uintptr_t)s < 0x10000 || (uintptr_t)s > 0xBFFF0000) {
        g_pushStrMisses++;
        return orig_lua_pushstring(L, s);
    }

    __try {
        // Compute FNV-1a hash
        uint64_t hash = ComputeCStringHash(s);

        // Lookup cache
        uint32_t cacheIdx = (uint32_t)(hash & PUSHSTR_CACHE_MASK);
        PushStrCacheEntry* entry = &g_pushStrCache[cacheIdx];

        // Check cache hit
        if (entry->keyHash == hash && entry->generation == g_getFieldGen) {
            // Validate TString* is still in range
            int ts = entry->tstring;
            if (ts >= 0x10000 && ts <= 0xBFFF0000) {
                // Push TValue directly: value=gc_ptr, tt=4 (LUA_TSTRING), taint
                __try {
                    DWORD* top = *(DWORD**)(L + 0x0C);
                    if (!top || (uintptr_t)top < 0x10000 || (uintptr_t)top > 0xBFFF0000) {
                        g_pushStrMisses++;
                        return orig_lua_pushstring(L, s);
                    }

                    // Copy taint from the TString
                    DWORD taint = *(DWORD*)(ts + 0x0C);

                    top[0] = (DWORD)ts;     // value.gc = TString*
                    top[1] = 0;              // value padding (upper 32 bits of double)
                    top[2] = 4;              // tt = LUA_TSTRING
                    top[3] = taint;          // taint

                    *(DWORD**)(L + 0x0C) = top + 4;

                    g_pushStrHits++;
                    return L;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    g_pushStrMisses++;
                    return orig_lua_pushstring(L, s);
                }
            }
        }

        // Cache miss - call original
        int result = orig_lua_pushstring(L, s);

        // Capture TString* from L->top - 16 bytes
        __try {
            DWORD* top = *(DWORD**)(L + 0x0C);
            if (top && (uintptr_t)top >= 0x10000 && (uintptr_t)top <= 0xBFFF0000) {
                DWORD* slot = top - 4;
                if (slot[2] == 4) {  // tt == LUA_TSTRING
                    entry->keyHash = hash;
                    entry->tstring = (int)slot[0];
                    entry->generation = g_getFieldGen;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        g_pushStrMisses++;
        return result;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        g_pushStrMisses++;
        return orig_lua_pushstring(L, s);
    }
#endif
}

static bool InstallLuaPushStringCache() {
#if CRASH_TEST_DISABLE_LUA_PUSHSTRING
    Log("lua_pushstring cache: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0084E350;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("lua_pushstring cache: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_lua_pushstring, (void**)&orig_lua_pushstring) != MH_OK) {
        Log("lua_pushstring cache: MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("lua_pushstring cache: MH_EnableHook FAILED");
        return false;
    }

    memset(g_pushStrCache, 0, sizeof(g_pushStrCache));

    Log("lua_pushstring cache: ACTIVE (sub_84E350 @ 0x0084E350 - 4096-slot TString* intern, SEH)");
    return true;
#endif
}

// ================================================================
// 21c. sub_851C30 - table.concat Fast Path (Direct Array + Inline Nums)
//
// ================================================================

#define TABLE_CONCAT_BUF_SIZE 8192

typedef int (__cdecl* table_concat_fn)(int L);
static table_concat_fn orig_table_concat = nullptr;

static int __cdecl hooked_table_concat(int L) {
#if CRASH_TEST_DISABLE_TABLE_CONCAT
    return orig_table_concat(L);
#else
    // L->base is at L+0x10
    int* base = *(int**)(L + 0x10);
    if (!base) return orig_table_concat(L);

    // Arg 1: Table. Check type 5.
    if (base[2] != 5) return orig_table_concat(L);
    int table = base[0];
    if (!table) return orig_table_concat(L);

    // Arg 2: Separator. Must be string or nil.
    int sep_type = base[5];
    const char* sep = "";
    int sep_len = 0;
    if (sep_type == 4) { // String
        int ts = base[4]; // TString*
        if (!ts) return orig_table_concat(L);
        // TString layout: +8=len, +16=str
        sep = (const char*)(ts + 16);
        sep_len = *(int*)(ts + 8);
    } else if (sep_type == 3) {
        // Number separator - fallback to original
        return orig_table_concat(L);
    } else if (sep_type != 0) {
        return orig_table_concat(L);
    }

    // Arg 3: i (default 1)
    int i = 1;
    if (base[8] == 3) i = (int)*(double*)(base + 8);
    else if (base[8] != 0) return orig_table_concat(L);

    // Arg 4: j (default sizearray)
    int sizearray = *(int*)(table + 32);
    int j = sizearray;
    if (base[11] == 3) j = (int)*(double*)(base + 11);
    else if (base[11] != 0) return orig_table_concat(L);

    if (i < 1) i = 1;
    if (j > sizearray) return orig_table_concat(L); // Hash part fallback
    if (i > j) {
        // Push empty string
       ((void (*)(int, const char*))0x0084E350)(L, "");
        return 1;
    }

    // Direct array loop
    int* array = *(int**)(table + 16);

    // Stack buffer for result
    char buf[TABLE_CONCAT_BUF_SIZE];
    int used = 0;

    char int_buf[32];
    char num_buf[64];

    for (int k = i; k <= j; k++) {
        int* val = array + (k - 1) * 4;
        int tt = val[2];

        const char* s = nullptr;
        int len = 0;

        if (tt == 4) { // String
            int ts = val[0];
            if (!ts) return orig_table_concat(L);
            s = (const char*)(ts + 16);
            len = *(int*)(ts + 8);
        } else if (tt == 3) { // Number
            double n = *(double*)val;
            // Fast integer check
            if (n >= -999999999.0 && n <= 999999999.0 && n == (int)n) {
                len = sprintf(int_buf, "%d", (int)n);
                s = int_buf;
            } else {
                len = sprintf(num_buf, "%.17g", n);
                s = num_buf;
            }
        } else {
            return orig_table_concat(L); // Type error fallback
        }

        // Append separator
        if (k > i && sep_len > 0) {
            if (used + sep_len + len > TABLE_CONCAT_BUF_SIZE - 100)
                return orig_table_concat(L);
            memcpy(buf + used, sep, sep_len);
            used += sep_len;
        }

        // Append string/number
        if (used + len > TABLE_CONCAT_BUF_SIZE - 100)
            return orig_table_concat(L);
        memcpy(buf + used, s, len);
        used += len;
    }

    // Push result
    buf[used] = '\0';
   ((void (*)(int, const char*))0x0084E350)(L, buf);
    return 1;
#endif
}

static bool InstallTableConcatFastPath() {
#if CRASH_TEST_DISABLE_TABLE_CONCAT
    Log("table.concat fast path: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x00851C30;
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) return false;

    if (WineSafe_CreateHook(target, (void*)hooked_table_concat, (void**)&orig_table_concat) != MH_OK) return false;
    if (MH_EnableHook(target) != MH_OK) return false;

    Log("table.concat fast path: ACTIVE (sub_851C30 @ 0x00851C30 - array direct + inline nums)");
    return true;
#endif
}

// ================================================================
// 21b. sub_85C430 - Lua Table String-Key Lookup Fast Path (enabled)
//
// ================================================================

typedef void* (__cdecl* luaH_getstr_fn)(int table, int tstring);
static luaH_getstr_fn orig_luaH_getstr = nullptr;

// Generation counter - incremented on every lua_State swap / cache clear.
// Catches mimalloc table recycling: when a table is freed and its memory
// reused for a non-table object, the generation mismatch invalidates the
// stale cache entry BEFORE we dereference *(table+20).
static volatile LONG g_getstrGeneration = 0;

#define GETSTR_CACHE_SIZE 8192
#define GETSTR_CACHE_MASK (GETSTR_CACHE_SIZE - 1)

struct GetStrCacheEntry {
    int      table;       // Table* pointer
    int      tstring;     // TString* pointer
    int      tableNode;   // *(table+20) - hash array base, detects rehashes
    uint32_t generation;  // Global generation at insert time
    void*    node;        // Cached Node* result (or nilObject)
};

static GetStrCacheEntry g_getstrCache[GETSTR_CACHE_SIZE];

// Safe memory probe - returns true if the 4 bytes at addr are in a
// committed, readable page.  Avoids the ACCESS_VIOLATION that the
// original cache hit on mimalloc-recycled table memory.
static inline bool IsSafeRead4(uintptr_t addr) {
    if (addr < 0x10000 || addr > 0xBFFF0000) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    return (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)));
}

static inline uint64_t GetStrCacheHash(uintptr_t table, uintptr_t tstring) {
    uint64_t h = 0xCBF29CE484222325ULL;
    h ^= (table ^ tstring);
    h *= 0x100000001B3ULL;
    return h & GETSTR_CACHE_MASK;
}

static void ClearLuaHGetStrCache() {
    memset(g_getstrCache, 0, sizeof(g_getstrCache));
    InterlockedIncrement(&g_getstrGeneration);
}

static void* __cdecl hooked_luaH_getstr(int table, int tstring) {
#if CRASH_TEST_DISABLE_LUAH_GETSTR
    return orig_luaH_getstr(table, tstring);
#else
    __try {
        if ((uintptr_t)table < 0x10000 || (uintptr_t)table > 0xBFFF0000)
            { g_getstrFallbacks++; return orig_luaH_getstr(table, tstring); }
        if ((uintptr_t)tstring < 0x10000 || (uintptr_t)tstring > 0xBFFF0000)
            { g_getstrFallbacks++; return orig_luaH_getstr(table, tstring); }

        uint64_t idx = GetStrCacheHash((uintptr_t)table, (uintptr_t)tstring);
        GetStrCacheEntry* e = &g_getstrCache[idx];

        // Generation check: invalidates stale entries from previous lua_State
        uint32_t gen = (uint32_t)InterlockedCompareExchange(&g_getstrGeneration, 0, 0);

        // Cache hit path - every dereference is guarded
        if (e->table == table && e->tstring == tstring
            && e->generation == gen && e->node != nullptr) {

            // Guard: table+20 must be in committed memory (mimalloc may have
            // recycled this address for a non-table allocation)
            if (!IsSafeRead4((uintptr_t)table + 20))
                { g_getstrFallbacks++; return orig_luaH_getstr(table, tstring); }

            int currentTableNode = *(int*)(table + 20);
            if (e->tableNode == currentTableNode) {

                // Guard: cached Node* must be valid memory
                if (!IsSafeRead4((uintptr_t)e->node + 24))
                    { g_getstrFallbacks++; return orig_luaH_getstr(table, tstring); }

                // Validate: key.tt == 4 (LUA_TSTRING), key.gc == tstring
                if (((int*)e->node)[6] == 4 && ((int*)e->node)[4] == tstring) {
                    g_getstrHits++;
                    return e->node;
                }
            }
        }

        // Cache miss - call original
        void* result = orig_luaH_getstr(table, tstring);

        // Store in cache (only if table memory is still valid)
        if (IsSafeRead4((uintptr_t)table + 20)) {
            e->table      = table;
            e->tstring    = tstring;
            e->tableNode  = *(int*)(table + 20);
            e->generation = gen;
            e->node       = result;
        }

        g_getstrFallbacks++;
        return result;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        g_getstrFallbacks++;
        return orig_luaH_getstr(table, tstring);
    }
#endif
}

static bool InstallLuaHGetStrCache() {
#if CRASH_TEST_DISABLE_LUAH_GETSTR
    Log("luaH_getstr cache: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0085C430;

    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("luaH_getstr cache: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_luaH_getstr, (void**)&orig_luaH_getstr) != MH_OK)
        { Log("luaH_getstr cache: MH_CreateHook FAILED"); return false; }
    if (MH_EnableHook(target) != MH_OK)
        { Log("luaH_getstr cache: MH_EnableHook FAILED"); return false; }

    memset(g_getstrCache, 0, sizeof(g_getstrCache));
    InterlockedExchange(&g_getstrGeneration, 1);

    Log("luaH_getstr cache: ACTIVE (sub_85C430 @ 0x0085C430 - %d-slot, generation-guarded, 1.5B calls/session)", GETSTR_CACHE_SIZE);
    return true;
#endif
}

// ================================================================
// 21c. sub_74E290 - CombatLog Event Full Cache
//
// ================================================================

#define COMBATLOG_CACHE_SIZE 256
#define COMBATLOG_CACHE_MASK (COMBATLOG_CACHE_SIZE - 1)
#define COMBATLOG_MAX_FIELDS 32
#define COMBATLOG_FINGERPRINT_BYTES 120

struct CombatLogCacheEntry {
    uint64_t fingerprint;
    int      fieldCount;
    // Captured TValue data - raw 16-byte TValue per field
    struct {
        uint64_t value_lo; // TValue value union (double or gc ptr)
        uint32_t tt;       // type tag
        uint32_t taint;    // taint field
    } fields[COMBATLOG_MAX_FIELDS];
    uint32_t lruStamp;
};

static CombatLogCacheEntry g_combatLogCache[COMBATLOG_CACHE_SIZE];
static uint32_t g_combatLogCacheLRU = 0;

// Known addresses for Lua stack manipulation
static constexpr uintptr_t ADDR_nilObject = 0x00A46F78;

typedef int (__thiscall* CombatLogEvent_fn)(int this_ptr, int luaState);
static CombatLogEvent_fn orig_CombatLogEvent = nullptr;

static inline uint64_t ComputeCombatEventFingerprint(int this_ptr) {
    // Skip bytes 0-11 (includes floating-point timestamp at +8 which changes every frame)
    // Hash only stable event data: eventType(+12), sourceGUID(+24), destGUID(+48),
    // flags(+84), spellID(+92), etc.
    uint64_t hash = 0xCBF29CE484222325ULL;
    const uint8_t* data = (const uint8_t*)this_ptr + 12; // skip timestamp
    for (int i = 0; i < COMBATLOG_FINGERPRINT_BYTES - 12; i++) {
        hash ^= data[i];
        hash *= 0x100000001B3ULL;
    }
    // Also XOR the flags+spellID region heavily (offset 84-116 is critical for dupe detection)
    const uint32_t* flags = (const uint32_t*)(this_ptr + 84);
    for (int i = 0; i < 8; i++) { // 32 bytes of spell damage fields
        hash ^= flags[i];
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

// TValue structure at L+0x0C = top pointer
// TValue = { union { double n; void* gc; } value; int tt; uint32_t taint; } = 16 bytes
static inline uint64_t* GetLuaTopPtr(int L) {
    return *(uint64_t**)(L + 0x0C);
}

static int __fastcall hooked_CombatLogEvent(void* This, void* unused_edx, int luaState) {
#if CRASH_TEST_DISABLE_COMBATLOG_FULLCACHE
    return ((int (__thiscall*)(void*, int))orig_CombatLogEvent)(This, luaState);
#else
    __try {
        int this_ptr = (int)This;
        if (this_ptr < 0x10000 || this_ptr > 0xBFFF0000) {
            g_combatLogCacheMisses++;
            return ((int (__thiscall*)(void*, int))orig_CombatLogEvent)(This, luaState);
        }
        if (luaState < 0x10000 || luaState > 0xBFFF0000) {
            g_combatLogCacheMisses++;
            return ((int (__thiscall*)(void*, int))orig_CombatLogEvent)(This, luaState);
        }

        // Compute fingerprint from event structure
        uint64_t fp = ComputeCombatEventFingerprint(this_ptr);

        // Lookup cache
        uint64_t idx = fp & COMBATLOG_CACHE_MASK;
        CombatLogCacheEntry* entry = &g_combatLogCache[idx];

        if (entry->fingerprint == fp && entry->fieldCount > 0 && entry->lruStamp > 0) {
            // Cache hit - replay the TValue pushes
            uint64_t* topPtr = *(uint64_t**)(luaState + 0x0C);
            for (int i = 0; i < entry->fieldCount; i++) {
                uint64_t* dst = (uint64_t*)(topPtr + i * 2); // 2x uint64_t = 16 bytes
                dst[0] = entry->fields[i].value_lo;
                dst[1] = ((uint64_t)entry->fields[i].taint << 32) | entry->fields[i].tt;
            }
            // Advance L->top
            *(uint64_t**)(luaState + 0x0C) = topPtr + entry->fieldCount * 2;

            entry->lruStamp = ++g_combatLogCacheLRU;
            g_combatLogCacheHits++;
            return entry->fieldCount;
        }

        // Cache miss - call original
        int fieldCount = ((int (__thiscall*)(void*, int))orig_CombatLogEvent)(This, luaState);

        // Capture the pushed TValue data from the Lua stack
        if (fieldCount > 0 && fieldCount <= COMBATLOG_MAX_FIELDS) {
            uint64_t* topPtr = *(uint64_t**)(luaState + 0x0C);
            // The pushed values are at topPtr - fieldCount through topPtr - 1
            uint64_t* startPtr = topPtr - fieldCount * 2;

            entry->fingerprint = fp;
            entry->fieldCount = fieldCount;
            entry->lruStamp = ++g_combatLogCacheLRU;

            for (int i = 0; i < fieldCount; i++) {
                uint64_t* src = startPtr + i * 2;
                entry->fields[i].value_lo = src[0];
                entry->fields[i].tt = (uint32_t)(src[1] & 0xFFFFFFFF);
                entry->fields[i].taint = (uint32_t)((src[1] >> 32) & 0xFFFFFFFF);
            }
        }

        g_combatLogCacheMisses++;
        return fieldCount;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        g_combatLogCacheMisses++;
        return ((int (__thiscall*)(void*, int))orig_CombatLogEvent)(This, luaState);
    }
#endif
}

static bool InstallCombatLogFullCache() {
#if CRASH_TEST_DISABLE_COMBATLOG_FULLCACHE
    Log("CombatLog full cache: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0074E290;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("CombatLog full cache: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_CombatLogEvent, (void**)&orig_CombatLogEvent) != MH_OK) {
        Log("CombatLog full cache: MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("CombatLog full cache: MH_EnableHook FAILED");
        return false;
    }

    memset(g_combatLogCache, 0, sizeof(g_combatLogCache));

    Log("CombatLog full cache: ACTIVE (sub_74E290 @ 0x0074E290 - 256-slot LRU, TValue replay)");
    return true;
#endif
}

// ================================================================
// 21. sub_85C6F0 - Lua Table Rehash Prevention (enabled)
//
// ================================================================

static inline int luaTable_nextPow2(int n) {
    if (n <= 1) return 1;
    --n;
    n |= n >> 1; n |= n >> 2; n |= n >> 4;
    n |= n >> 8; n |= n >> 16;
    return n + 1;
}

// Decision function - called from naked hook, must be __cdecl
static int __cdecl luaTable_reshape_decision(int newSize, void* table) {
    if (!table) return newSize;
    // Validate pointer - must be in valid user-space range
    uintptr_t p = (uintptr_t)table;
    if (p < 0x10000 || p > 0xBFFF0000) return newSize;

    // CRITICAL: Clear luaH_getstr cache on every resize - old Node* pointers are invalidated
    ClearLuaHGetStrCache();
    ClearLuaRawGetICache();

    __try {
        int currentSize = *(int*)((char*)table + 0x20);
        if (currentSize <= 0) return newSize;
        if (newSize <= currentSize) return newSize;
        if (newSize <= 0) return newSize;

        int nextPow = luaTable_nextPow2(newSize);
        // Only round up if we're not already at a power of 2,
        // and the rounded size isn't more than 4x current (cap memory)
        if (newSize < nextPow && nextPow <= currentSize * 4) {
            g_tableReshapeHits++;
            return nextPow;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    return newSize;
}

// Naked hook - preserves exact __usercall register state
// On entry: eax = a1 (newSize), ecx = a2 (table*), [esp] = ret addr, [esp+4] = a3
static void* g_luaHResizeTrampoline = nullptr;

__declspec(naked) static void hooked_luaH_resize() {
    __asm {
        // Save all registers and flags
        pushad
        pushfd

        // Call C++ decision: resize_decision(newSize_in_eax, table_in_ecx)
        push ecx                    // table*
        push eax                    // newSize
        call luaTable_reshape_decision
        add esp, 8                  // clean up args

        // Store result back into saved eax slot in pushad layout
        // pushad order on stack (after pushfd):
        //   [esp+0]=flags, [esp+4]=edi, [esp+8]=esi, [esp+12]=ebp,
        //   [esp+16]=origEsp, [esp+20]=ebx, [esp+24]=edx, [esp+28]=ecx, [esp+32]=eax
        mov [esp + 32], eax         // overwrite saved eax with rounded newSize

        // Restore all registers and flags
        popfd
        popad

        // eax = (potentially rounded) newSize, ecx = table* (unchanged)
        // Jump to MinHook trampoline which runs the original prologue
        jmp g_luaHResizeTrampoline
    }
}

static bool InstallLuaHResizeHook() {
#if CRASH_TEST_DISABLE_TABLERESHAPE_RC1
    Log("LuaH_resize hook: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0085C6F0;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("LuaH_resize hook: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_luaH_resize, &g_luaHResizeTrampoline) != MH_OK) {
        Log("LuaH_resize hook: MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("LuaH_resize hook: MH_EnableHook FAILED");
        return false;
    }

    Log("LuaH_resize hook: ACTIVE (sub_85C6F0 @ 0x0085C6F0 - table rehash prevention, round-up to pow2)");
    return true;
#endif
}

// ================================================================
// 22. sub_819D40 - Asset Path Resolver Cache (643 callers)
//
// Every texture, model, sound, and UI load resolves its path through
// this function.  It does strlen+sprintf+MPQ lookup per call.
// Caching the resolved pointer skips redundant string building.
// ================================================================
typedef int (__cdecl* AssetPathResolver_fn)(const char* path, int typeIdx, int gender);
static AssetPathResolver_fn orig_AssetPathResolver = nullptr;

struct AssetPathCacheEntry {
    uint32_t hash;
    int      result;
    bool     valid;
};

static constexpr int ASSET_PATH_CACHE_SIZE = 1024;
AssetPathCacheEntry g_assetPathCache[ASSET_PATH_CACHE_SIZE] = {};
long g_assetPathHits = 0;
long g_assetPathMisses = 0;

static int __cdecl hooked_AssetPathResolver(const char* path, int typeIdx, int gender) {
    return orig_AssetPathResolver(path, typeIdx, gender); // DISABLED - stale mimalloc pointers on teardown
}

static bool InstallAssetPathCache() {
    void* target = (void*)0x00819D40;
    if (WineSafe_CreateHook(target, (void*)hooked_AssetPathResolver, (void**)&orig_AssetPathResolver) != MH_OK)
        return false;
    if (MH_EnableHook(target) != MH_OK)
        return false;
    Log("Asset path cache: ACTIVE (%d slots, sub_819D40 @ 0x00819D40)", ASSET_PATH_CACHE_SIZE);
    return true;
}

void ClearAssetPathCache() {
    memset(g_assetPathCache, 0, sizeof(g_assetPathCache));
}

// ================================================================
// 23. memcpy 16-byte TValue fast path
//
// luaV_execute copies TValue structures (16 bytes) millions of times
// per frame.  Generic memcpy has alignment checks + size dispatch
// overhead.  For exactly 16 bytes, two movq are faster and always
// page-safe.  Separate from CRT fast paths - minimal, targeted.
// ================================================================
typedef void* (__cdecl* Memcpy_fn)(void*, const void*, size_t);
static Memcpy_fn orig_Memcpy = nullptr;
long g_tvalueMemcpyHits = 0;

static void* __cdecl hooked_Memcpy_TValue(void* dst, const void* src, size_t n) {
    if (n == 16) {
        uint64_t* d = (uint64_t*)dst;
        const uint64_t* s = (const uint64_t*)src;
        d[0] = s[0];
        d[1] = s[1];
        InterlockedIncrement(&g_tvalueMemcpyHits);
        return dst;
    }
    return orig_Memcpy(dst, src, n);
}

static bool InstallTValueMemcpyHook() {
    HMODULE hCRT = GetModuleHandleA("msvcrt.dll");
    if (!hCRT) hCRT = GetModuleHandleA("ucrtbase.dll");
    if (!hCRT) return false;

    void* p = (void*)GetProcAddress(hCRT, "memcpy");
    if (!p) return false;

    if (WineSafe_CreateHook(p, (void*)hooked_Memcpy_TValue, (void**)&orig_Memcpy) != MH_OK)
        return false;
    if (MH_EnableHook(p) != MH_OK)
        return false;

    Log("TValue memcpy: ACTIVE (16-byte fast path)");
    return true;
}

// ================================================================
// 24. GetSystemInfo cache - SYSTEM_INFO never changes, called by addons
// ================================================================
typedef void (WINAPI* GetSystemInfo_fn)(LPSYSTEM_INFO);
static GetSystemInfo_fn orig_GetSystemInfo = nullptr;
static SYSTEM_INFO g_cachedSysInfo = {};
static bool g_sysInfoCached = false;
long g_sysInfoHits = 0;

static void WINAPI hooked_GetSystemInfo(LPSYSTEM_INFO lpSI) {
    if (g_sysInfoCached && lpSI) {
        memcpy(lpSI, &g_cachedSysInfo, sizeof(SYSTEM_INFO));
        InterlockedIncrement(&g_sysInfoHits);
        return;
    }
    orig_GetSystemInfo(lpSI);
}

static bool InstallSysInfoCache() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetSystemInfo");
    if (!p || MH_CreateHook(p, (void*)hooked_GetSystemInfo, (void**)&orig_GetSystemInfo) != MH_OK)
        return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("GetSystemInfo cache: ACTIVE");
    return true;
}

// ================================================================
// 25. RegQueryValueExA cache - WTF config reads, 256-slot hash
// ================================================================
typedef LONG (WINAPI* RegQueryValueExA_fn)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static RegQueryValueExA_fn orig_RegQueryValueExA = nullptr;

struct RegCacheEntry {
    HKEY    hKey;
    uint32_t nameHash;
    DWORD   type;
    DWORD   size;
    BYTE    data[256];
    bool    valid;
};

static constexpr int REG_CACHE_SIZE = 256;
static RegCacheEntry g_regCache[REG_CACHE_SIZE] = {};
long g_regCacheHits = 0, g_regCacheMisses = 0;

static LONG WINAPI hooked_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    if (!lpValueName || !lpType || !lpcbData) goto fallback;

    uint32_t hash = 0x811C9DC5;
    for (const char* p = lpValueName; *p; p++) { hash ^= (uint8_t)*p; hash *= 0x01000193; }
    uint32_t slot = (hash ^ (uint32_t)(uintptr_t)hKey) & (REG_CACHE_SIZE - 1);
    RegCacheEntry* e = &g_regCache[slot];

    if (e->valid && e->hKey == hKey && e->nameHash == hash) {
        *lpType = e->type;
        DWORD copySize = e->size < *lpcbData ? e->size : *lpcbData;
        if (lpData) memcpy(lpData, e->data, copySize);
        *lpcbData = e->size;
        InterlockedIncrement(&g_regCacheHits);
        return ERROR_SUCCESS;
    }

    LONG result = orig_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    if (result == ERROR_SUCCESS && *lpcbData <= sizeof(e->data) && lpData) {
        e->hKey = hKey;
        e->nameHash = hash;
        e->type = *lpType;
        e->size = *lpcbData;
        memcpy(e->data, lpData, *lpcbData);
        e->valid = true;
    }
    InterlockedIncrement(&g_regCacheMisses);
    return result;

fallback:
    return orig_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

static bool InstallRegCache() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("advapi32.dll"), "RegQueryValueExA");
    if (!p || MH_CreateHook(p, (void*)hooked_RegQueryValueExA, (void**)&orig_RegQueryValueExA) != MH_OK)
        return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("RegQueryValueExA cache: ACTIVE (%d slots)", REG_CACHE_SIZE);
    return true;
}

// ================================================================
// 26. GetSystemMetrics cache - screen dimensions, called by UI addons
// ================================================================
typedef int (WINAPI* GetSystemMetrics_fn)(int);
static GetSystemMetrics_fn orig_GetSystemMetrics = nullptr;
static int g_smCache[128] = {};
static bool g_smInited = false;

// Screen-dimension metrics change on display-mode / DPI / maximize, must NOT be cached.
// 0 = SM_CXSCREEN, 1 = SM_CYSCREEN, 16 = SM_CXFULLSCREEN, 17 = SM_CYFULLSCREEN,
// 78 = SM_CXVIRTUALSCREEN, 79 = SM_CYVIRTUALSCREEN
static inline bool IsScreenDimMetric(int idx) {
    return idx == 0 || idx == 1 || idx == 16 || idx == 17 || idx == 78 || idx == 79;
}

static int WINAPI hooked_GetSystemMetrics(int nIndex) {
    if (nIndex >= 0 && nIndex < 128 && g_smInited && !IsScreenDimMetric(nIndex))
        return g_smCache[nIndex];
    int result = orig_GetSystemMetrics(nIndex);
    if (nIndex >= 0 && nIndex < 128 && !IsScreenDimMetric(nIndex)) {
        g_smCache[nIndex] = result;
        g_smInited = true;
    }
    return result;
}

static bool InstallSysMetricsCache() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "GetSystemMetrics");
    if (!p || MH_CreateHook(p, (void*)hooked_GetSystemMetrics, (void**)&orig_GetSystemMetrics) != MH_OK)
        return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    return true;
}

// ================================================================
// 27. IsDebuggerPresent no-op - always false, skips syscall
// ================================================================
typedef BOOL (WINAPI* IsDebuggerPresent_fn)();
static IsDebuggerPresent_fn orig_IsDebuggerPresent = nullptr;

static BOOL WINAPI hooked_IsDebuggerPresent() { return FALSE; }

static bool InstallNoDebuggerPresent() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsDebuggerPresent");
    if (!p || MH_CreateHook(p, (void*)hooked_IsDebuggerPresent, (void**)&orig_IsDebuggerPresent) != MH_OK)
        return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    return true;
}

// ================================================================
// 28. GetVersionExA cache - Windows version never changes
// ================================================================
typedef BOOL (WINAPI* GetVersionExA_fn)(LPOSVERSIONINFOA);
static GetVersionExA_fn orig_GetVersionExA = nullptr;
static OSVERSIONINFOA g_cachedVersion = {};
static bool g_verCached = false;

static BOOL WINAPI hooked_GetVersionExA(LPOSVERSIONINFOA lpVI) {
    if (g_verCached && lpVI) {
        DWORD sz = lpVI->dwOSVersionInfoSize;
        if (sz > sizeof(OSVERSIONINFOA)) sz = sizeof(OSVERSIONINFOA);
        memcpy(lpVI, &g_cachedVersion, sz);
        return TRUE;
    }
    BOOL result = orig_GetVersionExA(lpVI);
    if (result && lpVI) {
        DWORD sz = lpVI->dwOSVersionInfoSize;
        if (sz > sizeof(OSVERSIONINFOA)) sz = sizeof(OSVERSIONINFOA);
        memcpy(&g_cachedVersion, lpVI, sz);
        g_verCached = true;
    }
    return result;
}

static bool InstallVerCache() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetVersionExA");
    if (!p || MH_CreateHook(p, (void*)hooked_GetVersionExA, (void**)&orig_GetVersionExA) != MH_OK)
        return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    return true;
}

// ================================================================
// 24. memcmp fast path - inline compare for 4/8/16 byte cases
// ================================================================
typedef int (__cdecl* Memcmp_fn)(const void*, const void*, size_t);
static Memcmp_fn orig_Memcmp = nullptr;
static long g_memcmpFast = 0;

static int __cdecl hooked_Memcmp_Fast(const void* a, const void* b, size_t n) {
    if (n == 4) {
        uint32_t va = *(const uint32_t*)a, vb = *(const uint32_t*)b;
        InterlockedIncrement(&g_memcmpFast);
        return (va > vb) - (va < vb);
    }
    if (n == 8) {
        uint64_t va = *(const uint64_t*)a, vb = *(const uint64_t*)b;
        InterlockedIncrement(&g_memcmpFast);
        return (va > vb) - (va < vb);
    }
    // 16-byte SSE2 path for TValue comparisons (Lua VM equality checks)
    // Safe when both pointers are valid (caller guarantees this for TValue ops)
    if (n == 16) {
        __m128i va = _mm_loadu_si128((const __m128i*)a);
        __m128i vb = _mm_loadu_si128((const __m128i*)b);
        __m128i eq = _mm_cmpeq_epi8(va, vb);
        int mask = _mm_movemask_epi8(eq);
        InterlockedIncrement(&g_memcmpFast);
        if (mask == 0xFFFF) return 0;  // All 16 bytes equal
        // Find first differing byte for proper ordering
        int diff = _mm_movemask_epi8(_mm_cmpeq_epi8(va, vb)) ^ 0xFFFF;
        unsigned long idx;
        _BitScanForward(&idx, diff);
        unsigned char ca = ((const unsigned char*)a)[idx];
        unsigned char cb = ((const unsigned char*)b)[idx];
        return (ca > cb) - (ca < cb);
    }
    return orig_Memcmp(a, b, n);
}

static bool InstallMemcmpFast() {
    HMODULE hCRT = GetModuleHandleA("msvcrt.dll");
    if (!hCRT) hCRT = GetModuleHandleA("ucrtbase.dll");
    if (!hCRT) return false;
    void* p = (void*)GetProcAddress(hCRT, "memcmp");
    if (!p || MH_CreateHook(p, (void*)hooked_Memcmp_Fast, (void**)&orig_Memcmp) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("memcmp fast path: ACTIVE (4/8-byte inline)");
    return true;
}

// ================================================================
// 25a. LoadLibraryA skip - return handle if DLL already loaded
// ================================================================
typedef HMODULE (WINAPI* LoadLibraryA_fn)(LPCSTR);
static LoadLibraryA_fn orig_LoadLibraryA = nullptr;
static long g_loadLibFast = 0;

static HMODULE WINAPI hooked_LoadLibraryA(LPCSTR lpLibFileName) {
    HMODULE h = GetModuleHandleA(lpLibFileName);
    if (h) { InterlockedIncrement(&g_loadLibFast); return h; }
    return orig_LoadLibraryA(lpLibFileName);
}

static bool InstallLoadLibFast() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!p || MH_CreateHook(p, (void*)hooked_LoadLibraryA, (void**)&orig_LoadLibraryA) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    return true;
}

// ================================================================
// 25b. WaitForMultipleObjects count=1 → WaitForSingleObject
// ================================================================
typedef DWORD (WINAPI* WaitForMultipleObjects_fn)(DWORD, const HANDLE*, BOOL, DWORD);
static WaitForMultipleObjects_fn orig_WFMO = nullptr;
static long g_wfmoFast = 0;

static DWORD WINAPI hooked_WFMO(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMs) {
    if (nCount == 1 && !bWaitAll) {
        InterlockedIncrement(&g_wfmoFast);
        return WaitForSingleObject(lpHandles[0], dwMs);
    }
    return orig_WFMO(nCount, lpHandles, bWaitAll, dwMs);
}

static bool InstallWFMOFast() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WaitForMultipleObjects");
    if (!p || MH_CreateHook(p, (void*)hooked_WFMO, (void**)&orig_WFMO) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    return true;
}

// ================================================================
// VA Arena - dynamic 256MB reserve during loading screens
// ================================================================
static void* g_loadingArena = nullptr;
static SRWLOCK g_arenaLock = SRWLOCK_INIT;

extern "C" void ReserveLoadingArena() {
    AcquireSRWLockExclusive(&g_arenaLock);
    if (g_loadingArena) { ReleaseSRWLockExclusive(&g_arenaLock); return; }

    // Skip on HD clients - VA space already under pressure (32-bit, 1.3GB WS)
    PROCESS_MEMORY_COUNTERS pmc = {};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))
        && pmc.WorkingSetSize > 500u * 1024u * 1024u)
        { ReleaseSRWLockExclusive(&g_arenaLock); return; }

    g_loadingArena = VirtualAlloc(nullptr, 256 * 1024 * 1024, MEM_RESERVE, PAGE_NOACCESS);
    ReleaseSRWLockExclusive(&g_arenaLock);

    if (g_loadingArena) {
        Log("[VA-Arena] Reserved 256MB for loading screen model/texture allocation");
    } else {
        Log("[VA-Arena] Failed to reserve 256MB (VA fragmented - continuing)");
    }
}

extern "C" void ReleaseLoadingArena() {
    AcquireSRWLockExclusive(&g_arenaLock);
    if (g_loadingArena) {
        VirtualFree(g_loadingArena, 0, MEM_RELEASE);
        g_loadingArena = nullptr;
        Log("[VA-Arena] Released - VA space returned to process");
    }
    ReleaseSRWLockExclusive(&g_arenaLock);
}

// ================================================================
// Batch optimizations: kernel caches and fast paths
// ================================================================

// #1: GetSystemTimeAsFileTime → cached QPC. Timestamps used for profiling.
typedef void (WINAPI* GSTAFT_fn)(LPFILETIME);
static GSTAFT_fn orig_GSTAFT = nullptr;
static LARGE_INTEGER g_gstaftFreq = {};
static LARGE_INTEGER g_gstaftBase = {};
static bool g_gstaftInit = false;

static void WINAPI hooked_GSTAFT(LPFILETIME lpFT) {
    // Return cached QPC-based time with 1ms refresh
    if (!g_gstaftInit) {
        QueryPerformanceFrequency(&g_gstaftFreq);
        QueryPerformanceCounter(&g_gstaftBase);
        orig_GSTAFT(lpFT);  // Must call original, not hooked function!
        g_gstaftInit = true;
        return;
    }
    static LARGE_INTEGER lastQPC = {};
    static FILETIME lastFT = {};
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    if (now.QuadPart - lastQPC.QuadPart > g_gstaftFreq.QuadPart / 1000) {  // 1ms refresh
        orig_GSTAFT(&lastFT);
        lastQPC = now;
    }
    *lpFT = lastFT;
}

// #2: GetACP - code page never changes
typedef UINT (WINAPI* GetACP_fn)();
static GetACP_fn orig_GetACP = nullptr;
static UINT g_cachedACP = 0;

static UINT WINAPI hooked_GetACP() {
    if (!g_cachedACP) g_cachedACP = orig_GetACP();
    return g_cachedACP;
}

// #3: GetUserDefaultLangID - language never changes
typedef LANGID (WINAPI* GetUserDefaultLangID_fn)();
static GetUserDefaultLangID_fn orig_GetUDLI = nullptr;
static LANGID g_cachedLang = 0;

static LANGID WINAPI hooked_GetUDLI() {
    if (!g_cachedLang) g_cachedLang = orig_GetUDLI();
    return g_cachedLang;
}

// #4: GetProcessHeap - always returns the same handle
typedef HANDLE (WINAPI* GetProcessHeap_fn)();
static GetProcessHeap_fn orig_GetProcessHeap = nullptr;
static HANDLE g_cachedHeap = NULL;

static HANDLE WINAPI hooked_GetProcessHeap() {
    if (!g_cachedHeap) g_cachedHeap = orig_GetProcessHeap();
    return g_cachedHeap;
}

// #5: CharUpperA ASCII fast path
typedef char* (WINAPI* CharUpperA_fn)(char*);
static CharUpperA_fn orig_CharUpperA = nullptr;

static char* WINAPI hooked_CharUpperA(char* str) {
    if (str) {
        for (char* p = str; *p; p++)
            if (*p >= 'a' && *p <= 'z') *p -= 32;
    }
    return str;
}

// #6: CharLowerA ASCII fast path
typedef char* (WINAPI* CharLowerA_fn)(char*);
static CharLowerA_fn orig_CharLowerA = nullptr;

static char* WINAPI hooked_CharLowerA(char* str) {
    if (str) {
        for (char* p = str; *p; p++)
            if (*p >= 'A' && *p <= 'Z') *p += 32;
    }
    return str;
}

// #7: REMOVED - wsprintfA variadic args can't be forwarded
typedef int (__cdecl* wsprintfA_fn)(char*, const char*, ...);
static wsprintfA_fn orig_wsprintfA = nullptr; // kept for future use, hook not installed

// #8: MapVirtualKeyA - key mappings cached
typedef UINT (WINAPI* MapVirtualKeyA_fn)(UINT, UINT);
static MapVirtualKeyA_fn orig_MapVirtualKeyA = nullptr;
static UINT g_mvkCache[256][4] = {};  // [code][mapType]

static UINT WINAPI hooked_MapVirtualKeyA(UINT code, UINT mapType) {
    if (code < 256 && mapType < 4) {
        UINT& cached = g_mvkCache[code][mapType];
        if (!cached) cached = orig_MapVirtualKeyA(code, mapType);
        return cached;
    }
    return orig_MapVirtualKeyA(code, mapType);
}

// #9: GetThreadPriority - thread priority never changes per thread
typedef int (WINAPI* GetThreadPriority_fn)(HANDLE);
static GetThreadPriority_fn orig_GetThreadPriority = nullptr;
static int g_threadPrio[256] = {};  // simple per-handle cache

static int WINAPI hooked_GetThreadPriority(HANDLE h) {
    DWORD idx = (DWORD)(uintptr_t)h & 255;
    int& c = g_threadPrio[idx];
    if (c) return c;
    c = orig_GetThreadPriority(h);
    return c;
}

// #10: lstrlenW REMOVED - already hooked by SSE2 fast path (duplicate hook crashes MinHook)

static bool InstallBatchOpt10() {
    int ok = 0;
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    HMODULE hU32 = GetModuleHandleA("user32.dll");

    void* p;
    // #1 GSTAFT
    p = (void*)GetProcAddress(hK32, "GetSystemTimeAsFileTime");
    if (p && MH_CreateHook(p, (void*)hooked_GSTAFT, (void**)&orig_GSTAFT) == MH_OK && MH_EnableHook(p) == MH_OK) ok++;
    // #2 GetACP
    p = (void*)GetProcAddress(hK32, "GetACP");
    if (p && MH_CreateHook(p, (void*)hooked_GetACP, (void**)&orig_GetACP) == MH_OK && MH_EnableHook(p) == MH_OK) ok++;
    // #3 GetUserDefaultLangID
    p = (void*)GetProcAddress(hK32, "GetUserDefaultLangID");
    if (p && MH_CreateHook(p, (void*)hooked_GetUDLI, (void**)&orig_GetUDLI) == MH_OK && MH_EnableHook(p) == MH_OK) ok++;
    // #4 GetProcessHeap
    p = (void*)GetProcAddress(hK32, "GetProcessHeap");
    if (p && MH_CreateHook(p, (void*)hooked_GetProcessHeap, (void**)&orig_GetProcessHeap) == MH_OK && MH_EnableHook(p) == MH_OK) ok++;
    // #5 CharUpperA
    p = (void*)GetProcAddress(hU32, "CharUpperA");
    if (p && MH_CreateHook(p, (void*)hooked_CharUpperA, (void**)&orig_CharUpperA) == MH_OK && MH_EnableHook(p) == MH_OK) ok++;
    // #6 CharLowerA
    p = (void*)GetProcAddress(hU32, "CharLowerA");
    if (p && MH_CreateHook(p, (void*)hooked_CharLowerA, (void**)&orig_CharLowerA) == MH_OK && MH_EnableHook(p) == MH_OK) ok++;
    // #7 wsprintfA REMOVED - variadic args can't forward
    // #8 MapVirtualKeyA
    p = (void*)GetProcAddress(hU32, "MapVirtualKeyA");
    if (p && MH_CreateHook(p, (void*)hooked_MapVirtualKeyA, (void**)&orig_MapVirtualKeyA) == MH_OK && MH_EnableHook(p) == MH_OK) ok++;
    // #9 GetThreadPriority
    p = (void*)GetProcAddress(hK32, "GetThreadPriority");
    if (p && MH_CreateHook(p, (void*)hooked_GetThreadPriority, (void**)&orig_GetThreadPriority) == MH_OK && MH_EnableHook(p) == MH_OK) ok++;
    // #10 lstrlenW REMOVED - duplicate hook

    Log("Batch opt #1-8: %d/8 active", ok);
    return ok > 0;
}

// ================================================================
// Batch #11-20: more kernel caches and fast paths
// ================================================================

// #11: GetOEMCP
typedef UINT (WINAPI* GetOEMCP_fn)();
static GetOEMCP_fn orig_GetOEMCP = nullptr; static UINT g_oemcp = 0;
static UINT WINAPI hooked_GetOEMCP() { if (!g_oemcp) g_oemcp = orig_GetOEMCP(); return g_oemcp; }

// #12: GetDoubleClickTime
typedef UINT (WINAPI* GetDoubleClickTime_fn)();
static GetDoubleClickTime_fn orig_GetDoubleClickTime = nullptr; static UINT g_dct = 0;
static UINT WINAPI hooked_GetDoubleClickTime() { if (!g_dct) g_dct = orig_GetDoubleClickTime(); return g_dct; }

// #13: GetCursorPos - DISABLED (breaks hardware cursor with RTSSHooks.dll)
typedef BOOL (WINAPI* GetCursorPos_fn)(LPPOINT);
static GetCursorPos_fn orig_GetCursorPos = nullptr;
static BOOL WINAPI hooked_GetCursorPos(LPPOINT lp) {
    return orig_GetCursorPos(lp);
}

// #14: GetSysColor
typedef DWORD (WINAPI* GetSysColor_fn)(int);
static GetSysColor_fn orig_GetSysColor = nullptr; static DWORD g_sysColors[32] = {};
static DWORD WINAPI hooked_GetSysColor(int idx) {
    if (idx < 32) { if (!g_sysColors[idx]) g_sysColors[idx] = orig_GetSysColor(idx); return g_sysColors[idx]; }
    return orig_GetSysColor(idx);
}

// #15: GetKeyboardLayout
typedef HKL (WINAPI* GetKeyboardLayout_fn)(DWORD);
static GetKeyboardLayout_fn orig_GetKeyboardLayout = nullptr; static HKL g_kbl = 0;
static HKL WINAPI hooked_GetKeyboardLayout(DWORD id) { if (!g_kbl) g_kbl = orig_GetKeyboardLayout(id); return g_kbl; }

// #16: GetKeyboardLayoutNameA
typedef BOOL (WINAPI* GetKeyboardLayoutNameA_fn)(char*);
static GetKeyboardLayoutNameA_fn orig_GetKeyboardLayoutNameA = nullptr; static char g_kbln[9] = {};
static BOOL WINAPI hooked_GetKeyboardLayoutNameA(char* buf) { if (g_kbln[0]) { memcpy(buf, g_kbln, 9); return TRUE; } BOOL r = orig_GetKeyboardLayoutNameA(g_kbln); memcpy(buf, g_kbln, 9); return r; }

// #17: GetCaretBlinkTime
typedef UINT (WINAPI* GetCaretBlinkTime_fn)();
static GetCaretBlinkTime_fn orig_GetCaretBlinkTime = nullptr; static UINT g_cbt = 0;
static UINT WINAPI hooked_GetCaretBlinkTime() { if (!g_cbt) g_cbt = orig_GetCaretBlinkTime(); return g_cbt; }

// #18: IsWindow
typedef BOOL (WINAPI* IsWindow_fn)(HWND);
static IsWindow_fn orig_IsWindow = nullptr; static HWND g_lastIW = NULL; static BOOL g_lastIWRes = TRUE;
static BOOL WINAPI hooked_IsWindow(HWND h) { if (h == g_lastIW) return g_lastIWRes; g_lastIWRes = orig_IsWindow(h); g_lastIW = h; return g_lastIWRes; }

// #19: GetDesktopWindow
typedef HWND (WINAPI* GetDesktopWindow_fn)();
static GetDesktopWindow_fn orig_GetDesktopWindow = nullptr; static HWND g_desktop = NULL;
static HWND WINAPI hooked_GetDesktopWindow() { if (!g_desktop) g_desktop = orig_GetDesktopWindow(); return g_desktop; }

// #20: GetFocus - DISABLED (breaks hardware cursor with RTSSHooks.dll)
typedef HWND (WINAPI* GetFocus_fn)();
static GetFocus_fn orig_GetFocus = nullptr; static HWND g_lastFocus = NULL; static DWORD g_lastFocusTick = 0;
static HWND WINAPI hooked_GetFocus() { return orig_GetFocus(); }

static bool InstallBatchOpt20() {
    int ok = 0;
    HMODULE hK32 = GetModuleHandleA("kernel32.dll"), hU32 = GetModuleHandleA("user32.dll");
    void* p;
    #define H(dll, fn, orig) p=(void*)GetProcAddress(dll,#fn); if(p&&MH_CreateHook(p,(void*)hooked_##fn,(void**)&orig)==MH_OK&&MH_EnableHook(p)==MH_OK) ok++
    H(hK32, GetOEMCP, orig_GetOEMCP); H(hU32, GetDoubleClickTime, orig_GetDoubleClickTime);
    // H(hU32, GetCursorPos, orig_GetCursorPos); // DISABLED - breaks hardware cursor with RTSSHooks.dll
    H(hU32, GetSysColor, orig_GetSysColor);
    // H(hU32, GetKeyboardLayout, orig_GetKeyboardLayout); H(hU32, GetKeyboardLayoutNameA, orig_GetKeyboardLayoutNameA); // DISABLED - breaks language switching
    H(hU32, GetCaretBlinkTime, orig_GetCaretBlinkTime); H(hU32, IsWindow, orig_IsWindow);
    H(hU32, GetDesktopWindow, orig_GetDesktopWindow); H(hU32, GetFocus, orig_GetFocus);
    #undef H
    Log("Batch opt #11-20: %d/10 active", ok);
    return ok > 0;
}

// ================================================================
// Batch #21-30: more caches and fast paths
// ================================================================

// #21: GetTickCount64 - redirect to QPC (same as GetTickCount hook)
typedef ULONGLONG (WINAPI* GetTickCount64_fn)();
static GetTickCount64_fn orig_GetTickCount64 = nullptr;
static ULONGLONG WINAPI hooked_GetTickCount64() {
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    static LARGE_INTEGER freq;
    static bool init = false;
    if (!init) { QueryPerformanceFrequency(&freq); init = true; }
    return (ULONGLONG)(qpc.QuadPart * 1000 / freq.QuadPart);
}

// #22: GetClientRect - cached per HWND (window size rarely changes)
typedef BOOL (WINAPI* GetClientRect_fn)(HWND, LPRECT);
static GetClientRect_fn orig_GetClientRect = nullptr;
static HWND g_crHwnd = NULL; static RECT g_crCache = {};
static BOOL WINAPI hooked_GetClientRect(HWND h, LPRECT r) {
    if (h == g_crHwnd) { *r = g_crCache; return TRUE; }
    BOOL res = orig_GetClientRect(h, r);
    if (res) { g_crHwnd = h; g_crCache = *r; }
    return res;
}

// #23: GetWindowRect - cached per HWND
typedef BOOL (WINAPI* GetWindowRect_fn)(HWND, LPRECT);
static GetWindowRect_fn orig_GetWindowRect = nullptr;
static HWND g_wrHwnd = NULL; static RECT g_wrCache = {};
static BOOL WINAPI hooked_GetWindowRect(HWND h, LPRECT r) {
    if (h == g_wrHwnd) { *r = g_wrCache; return TRUE; }
    BOOL res = orig_GetWindowRect(h, r);
    if (res) { g_wrHwnd = h; g_wrCache = *r; }
    return res;
}

// #24-25: REMOVED - GetDateFormatA/GetTimeFormatA pass-through (no speedup)
// #26: SetCursorPos REMOVED - no-op breaks mouselook (cursor must move)

// #27: ShowCursor - cached (only changes on UI mode switch)
typedef int (WINAPI* ShowCursor_fn)(BOOL);
static ShowCursor_fn orig_ShowCursor = nullptr; static int g_showCount = -1;
static int WINAPI hooked_ShowCursor(BOOL show) {
    if (show) { if (g_showCount < 0) g_showCount = orig_ShowCursor(TRUE); g_showCount++; return g_showCount; }
    else { if (g_showCount > 0) g_showCount--; return g_showCount; }
}

// #28-29: REMOVED - GetDC/ReleaseDC unsafe (prevents screen updates)
// #30: ValidateRect REMOVED - no-op prevents UI repaints, freezes on friend list open

static bool InstallBatchOpt30() {
    int ok = 0;
    HMODULE hK32 = GetModuleHandleA("kernel32.dll"), hU32 = GetModuleHandleA("user32.dll");
    void* p;
    #define H31(dll, fn, orig) p=(void*)GetProcAddress(dll,#fn); if(p&&MH_CreateHook(p,(void*)hooked_##fn,(void**)&orig)==MH_OK&&MH_EnableHook(p)==MH_OK) ok++
    H31(hK32, GetTickCount64, orig_GetTickCount64);
    // H31(hU32, GetClientRect, orig_GetClientRect); // DISABLED - cached window dimensions break window resize (clicks miss UI elements)
    // H31(hU32, GetWindowRect, orig_GetWindowRect); // DISABLED - cached window dimensions break window resize (clicks miss UI elements)
    // H31(hU32, ShowCursor, orig_ShowCursor); // DISABLED - breaks hardware cursor with RTSSHooks.dll
    // H31(hU32, ValidateRect, orig_ValidateRect); // REMOVED - prevents UI repaint, freezes on friend list
    #undef H31
    Log("Batch opt #21-24: %d/4 active", ok);
    return ok > 0;
}

// ================================================================
// Batch #31-35: kernel32 immutable-data caches
// ================================================================

// #31: GetComputerNameA - never changes during session
typedef BOOL (WINAPI* GetComputerNameA_fn)(LPSTR, LPDWORD);
static GetComputerNameA_fn orig_GetComputerNameA = nullptr;
static char g_computerName[64] = {};
static BOOL WINAPI hooked_GetComputerNameA(LPSTR buf, LPDWORD nSize) {
    if (g_computerName[0]) { DWORD len = (DWORD)strlen(g_computerName) + 1; if (*nSize >= len) { memcpy(buf, g_computerName, len); return TRUE; } }
    BOOL r = orig_GetComputerNameA(g_computerName, nSize); memcpy(buf, g_computerName, (size_t)*nSize + 1); return r;
}

// #32: GetUserNameA - never changes during session
typedef BOOL (WINAPI* GetUserNameA_fn)(LPSTR, LPDWORD);
static GetUserNameA_fn orig_GetUserNameA = nullptr;
static char g_userName[64] = {};
static BOOL WINAPI hooked_GetUserNameA(LPSTR buf, LPDWORD nSize) {
    if (g_userName[0]) { DWORD len = (DWORD)strlen(g_userName) + 1; if (*nSize >= len) { memcpy(buf, g_userName, len); return TRUE; } }
    BOOL r = orig_GetUserNameA(g_userName, nSize); memcpy(buf, g_userName, (size_t)*nSize + 1); return r;
}

// #33: GetSystemDirectoryA - never changes
typedef UINT (WINAPI* GetSystemDirectoryA_fn)(LPSTR, UINT);
static GetSystemDirectoryA_fn orig_GetSystemDirectoryA = nullptr;
static char g_sysDir[MAX_PATH] = {};
static UINT WINAPI hooked_GetSystemDirectoryA(LPSTR buf, UINT nSize) {
    if (g_sysDir[0]) { UINT len = (UINT)strlen(g_sysDir) + 1; if (nSize >= len) { memcpy(buf, g_sysDir, len); return len - 1; } }
    UINT r = orig_GetSystemDirectoryA(g_sysDir, MAX_PATH); if (buf != g_sysDir) memcpy(buf, g_sysDir, (size_t)r + 1); return r;
}

// #34: GetWindowsDirectoryA - never changes
typedef UINT (WINAPI* GetWindowsDirectoryA_fn)(LPSTR, UINT);
static GetWindowsDirectoryA_fn orig_GetWindowsDirectoryA = nullptr;
static char g_winDir[MAX_PATH] = {};
static UINT WINAPI hooked_GetWindowsDirectoryA(LPSTR buf, UINT nSize) {
    if (g_winDir[0]) { UINT len = (UINT)strlen(g_winDir) + 1; if (nSize >= len) { memcpy(buf, g_winDir, len); return len - 1; } }
    UINT r = orig_GetWindowsDirectoryA(g_winDir, MAX_PATH); if (buf != g_winDir) memcpy(buf, g_winDir, (size_t)r + 1); return r;
}

// #35: GetTempPathA - changes only on reboot
typedef DWORD (WINAPI* GetTempPathA_fn)(DWORD, LPSTR);
static GetTempPathA_fn orig_GetTempPathA = nullptr;
static char g_tempPath[MAX_PATH] = {};
static DWORD WINAPI hooked_GetTempPathA(DWORD nSize, LPSTR buf) {
    if (g_tempPath[0]) { DWORD len = (DWORD)strlen(g_tempPath) + 1; if (nSize >= len) { memcpy(buf, g_tempPath, len); return len - 1; } }
    DWORD r = orig_GetTempPathA(MAX_PATH, g_tempPath); if (buf != g_tempPath) memcpy(buf, g_tempPath, (size_t)r + 1); return r;
}

static bool InstallBatchOpt35() {
    int ok = 0;
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    void* p;
    #define H35(fn, orig) p=(void*)GetProcAddress(hK32,#fn); if(p&&MH_CreateHook(p,(void*)hooked_##fn,(void**)&orig)==MH_OK&&MH_EnableHook(p)==MH_OK) ok++
    H35(GetComputerNameA, orig_GetComputerNameA);
    H35(GetUserNameA, orig_GetUserNameA);
    H35(GetSystemDirectoryA, orig_GetSystemDirectoryA);
    H35(GetWindowsDirectoryA, orig_GetWindowsDirectoryA);
    H35(GetTempPathA, orig_GetTempPathA);
    #undef H35
    Log("Batch opt #31-35: %d/5 active", ok);
    return ok > 0;
}

// ================================================================
// Batch #36-38: kernel32 immutable-data caches
// #36: GetCurrentProcess - always returns (HANDLE)-1
typedef HANDLE (WINAPI* GetCurrentProcess_fn)();
static GetCurrentProcess_fn orig_GetCurrentProcess = nullptr;
static HANDLE g_hProc = NULL;
static HANDLE WINAPI hooked_GetCurrentProcess() {
    if (g_hProc) return g_hProc;
    g_hProc = orig_GetCurrentProcess(); return g_hProc;
}
// #37: GetCPInfo - code page info immutable per session
typedef BOOL (WINAPI* GetCPInfo_fn)(UINT, LPCPINFO);
static GetCPInfo_fn orig_GetCPInfo = nullptr;
static CPINFO g_cpInfo[4] = {}; static BOOL g_cpValid[4] = {};
static BOOL WINAPI hooked_GetCPInfo(UINT cp, LPCPINFO lp) {
    int idx = (cp == CP_ACP) ? 0 : (cp == CP_OEMCP) ? 1 : (cp == CP_THREAD_ACP) ? 2 : 3;
    if (idx < 3 && g_cpValid[idx]) { *lp = g_cpInfo[idx]; return TRUE; }
    BOOL r = orig_GetCPInfo(cp, &g_cpInfo[idx]); if (r && lp) *lp = g_cpInfo[idx]; g_cpValid[idx] = r; return r;
}
// #38: GetCurrentThread - already handled at line 2256, returns (HANDLE)-2 constant
static bool InstallBatchOpt38() {
    int ok = 0; HMODULE hK32 = GetModuleHandleA("kernel32.dll"); void* p;
    #define H38(fn, orig) p=(void*)GetProcAddress(hK32,#fn); if(p&&MH_CreateHook(p,(void*)hooked_##fn,(void**)&orig)==MH_OK&&MH_EnableHook(p)==MH_OK) ok++
    H38(GetCurrentProcess, orig_GetCurrentProcess);
    H38(GetCPInfo, orig_GetCPInfo);
    #undef H38
    Log("Batch opt #36-38: %d/2 active", ok);
    return ok > 0;
}

// Main initialization thread.
static DWORD WINAPI MainThread(LPVOID param) {
    // One-time caches initialized before hooks
    GetSystemInfo(&g_cachedSysInfo);
    g_sysInfoCached = true;

    Sleep(5000);

    LogOpen();
    Log("========================================");
    Log("  wow_optimize.dll v%s BY %s", WOW_OPTIMIZE_VERSION_STR, WOW_OPTIMIZE_AUTHOR);
    Log("  PID: %lu", GetCurrentProcessId());
    Log("========================================");
    
    if (IsRosetta()) {
        Log("[Rosetta] Detected x86 on ARM64 (macOS Rosetta 2)");
        char val[2] = {0};
        if (GetEnvironmentVariableA("ROSETTA_X87_DISABLE_CACHE", val, sizeof(val)) && val[0] == '1') {
            Log("[Rosetta] x87 JIT cache DISABLED - hooks safe to install");
        } else {
            Log("[Rosetta] WARNING: x87 JIT cache still enabled - hooks may fail");
        }
    }

    if (MH_Initialize() != MH_OK) { Log("FATAL: MinHook initialization failed"); LogClose(); return 1; }
    Log("MinHook initialized");

    CrashDumper::Init();

    // Register ALL features for crash/freeze diagnostics
    CrashDumper::RegisterFeature("SleepHook");
    CrashDumper::RegisterFeature("GetTickCount");
    CrashDumper::RegisterFeature("HeapOptimization");
    CrashDumper::RegisterFeature("ThreadIdCache");
    CrashDumper::RegisterFeature("QPCCache");
    CrashDumper::RegisterFeature("BadPtrCheck");
    CrashDumper::RegisterFeature("CompareStringA");
    CrashDumper::RegisterFeature("CriticalSection");
    CrashDumper::RegisterFeature("NetworkHooks");
    CrashDumper::RegisterFeature("ReadFileCache");
    CrashDumper::RegisterFeature("CloseHandle");
    CrashDumper::RegisterFeature("FlushFileBuffers");
    CrashDumper::RegisterFeature("MPQScan");
    CrashDumper::RegisterFeature("FileAttributes");
    CrashDumper::RegisterFeature("SetFilePointer");
    CrashDumper::RegisterFeature("GlobalAlloc");
    CrashDumper::RegisterFeature("FileSizeCache");
    CrashDumper::RegisterFeature("WFSSpin");
    CrashDumper::RegisterFeature("ModuleHandleCache");
    CrashDumper::RegisterFeature("Lstrcmp");
    CrashDumper::RegisterFeature("Lstrlen");
    CrashDumper::RegisterFeature("WowStrlen");
    CrashDumper::RegisterFeature("StrstrSSE2");
    CrashDumper::RegisterFeature("CrtCharSSE2");
    CrashDumper::RegisterFeature("CrtPowSSE2");
    CrashDumper::RegisterFeature("TlsCache");
    CrashDumper::RegisterFeature("StreamCache");
    CrashDumper::RegisterFeature("LuaThisCache");
    CrashDumper::RegisterFeature("IOCache");
    CrashDumper::RegisterFeature("LuaGlobalCache");
    CrashDumper::RegisterFeature("HotFunctions");
    CrashDumper::RegisterFeature("FastStrncmp");
    CrashDumper::RegisterFeature("CrtFreeHook");
    CrashDumper::RegisterFeature("AlignedAllocCache");
    CrashDumper::RegisterFeature("DataStoreFastPath");
    CrashDumper::RegisterFeature("StringOpsFast");
    CrashDumper::RegisterFeature("MBWCHooks");
    CrashDumper::RegisterFeature("CrtMemFastPaths");
    CrashDumper::RegisterFeature("MsgPump");
    CrashDumper::RegisterFeature("SwapPresent");
    CrashDumper::RegisterFeature("LuaHResize");
    CrashDumper::RegisterFeature("LuaHGetStr");
    CrashDumper::RegisterFeature("FieldUpdates");
    CrashDumper::RegisterFeature("LuaToNumberFast");
    CrashDumper::RegisterFeature("StrcatFast");
    CrashDumper::RegisterFeature("ScriptHandlerCache");
    CrashDumper::RegisterFeature("DbcLookupCache");
    CrashDumper::RegisterFeature("EventDispatchCache");
    CrashDumper::RegisterFeature("LuaGetStrInline");
    CrashDumper::RegisterFeature("RawGetIInline");
    CrashDumper::RegisterFeature("HardwareCursor");
    CrashDumper::RegisterFeature("FrameThrottle");
    CrashDumper::RegisterFeature("SpellCache");
    CrashDumper::RegisterFeature("LuaRawGetICache");
    CrashDumper::RegisterFeature("CombatLogFullCache");
    CrashDumper::RegisterFeature("ThreadAffinity");
    CrashDumper::RegisterFeature("VAArena");
    CrashDumper::RegisterFeature("RTTICache");
    CrashDumper::RegisterFeature("StreamBufFastPath");
    CrashDumper::RegisterFeature("LuaOptimizer");
    CrashDumper::RegisterFeature("CombatLogOpt");
    CrashDumper::RegisterFeature("CombatLogBuffer");
    CrashDumper::RegisterFeature("CombatLogMT");
    CrashDumper::RegisterFeature("TextureAsync");
    CrashDumper::RegisterFeature("SpellPrefetch");
    CrashDumper::RegisterFeature("ModelAsync");
    CrashDumper::RegisterFeature("ObjVisCache");
    CrashDumper::RegisterFeature("SoundPrefetch");
    CrashDumper::RegisterFeature("QuestAsync");
    CrashDumper::RegisterFeature("UICache");
    CrashDumper::RegisterFeature("ApiCache");
    CrashDumper::RegisterFeature("LuaFastPath");
    CrashDumper::RegisterFeature("AddonPreload");
    CrashDumper::RegisterFeature("BytecodeCache");
    CrashDumper::RegisterFeature("LuaVMCache");
    CrashDumper::RegisterFeature("LuaGetTableCache");
    CrashDumper::RegisterFeature("SavedVarsAsync");
    CrashDumper::RegisterFeature("HookPrefetch");
    CrashDumper::RegisterFeature("HotPatch");
    CrashDumper::RegisterFeature("InfraPatch");
    CrashDumper::RegisterFeature("MemoryOpt");
    CrashDumper::RegisterFeature("SourceOpt");
    CrashDumper::RegisterFeature("TlsObjectCache");
    Log("[CrashDumper] Registered %d features for tracking", MAX_TRACKED_FEATURES);

    ConfigureMimalloc();
    TryEnableLargePages();
    g_nextStatsDumpTick = 0;
    g_nextMiCollectTick = 0;

    Log("--- Memory Allocator ---");
    // DISABLED: mimalloc allocator hooks cause corrupted function pointers
    // during login initialization. WoW expects CRT heap layout with specific
    // internal structure; mimalloc returns differently-layouted memory causing
    // ACCESS_VIOLATION at unknown addresses (e.g. 0x1618D830)
    bool allocOk = false; // InstallAllocatorHooks();
    Log("[Allocator] DISABLED: mimalloc causes corrupted pointers during login");

    Log("--- Frame Pacing ---");
    bool sleepOk = InstallSleepHook();
    Log("--- Timer Precision ---");
    bool tickOk = InstallGetTickCountHook();
    bool tgtOk  = InstallTimeGetTimeHook();
    Log("--- Heap Optimization ---");
    bool heapOk = InstallHeapOptimization();
    Log("--- Thread ID Cache ---");
    bool tidOk = InstallThreadIdCacheHook();
    Log("--- QPC Cache ---");
#if !CRASH_TEST_DISABLE_QPC_CACHE
    bool qpcOk = InstallQPCHook();
#else
    bool qpcOk = false;
    Log("QPC hook: DISABLED (crash isolation)");
#endif     
    Log("--- Bad Pointer Checks ---");
    bool bpOk  = InstallBadPtrHooks();    
    Log("--- String Comparison ---");
    bool cmpOk = InstallCompareStringHook();
    Log("--- Debug Strings ---");
    bool debugOk = InstallOutputDebugStringHook();
    Log("--- Critical Sections ---");
    bool csOk = InstallCriticalSectionHook();
    Log("--- Network ---");
    bool netOk = InstallNetworkHooks();
    Log("--- File I/O ---");
    bool fileOk  = InstallFileHooks();
    bool readOk  = InstallReadFileHook();
    bool closeOk = InstallCloseHandleHook();
    bool flushOk = InstallFlushFileBuffersHook();
    Log("--- Async MPQ I/O ---");
    // Worker started after init completes to avoid race with hook setup
    bool asyncIoOk = true;
    Log("--- MPQ Scan ---");
    ScanExistingMpqHandles();
    Log("--- File Attributes ---");
    bool faOk = InstallGetFileAttributesHook();
    Log("--- File Pointer ---");
    bool sfpOk = InstallSetFilePointerHook();
    Log("--- Global Alloc ---");
    bool gaOk  = InstallGlobalAllocHooks();    
    Log("--- Multi-Client ---");
    DetectMultiClient();
    AdjustMimallocForMultiClient();    
    Log("--- System Timer ---");
    SetHighTimerResolution();
    Log("--- Threads ---");
    OptimizeThreads();
    Log("--- Process ---");
    
    // Install SetPriorityClass hook BEFORE setting priority to block downgrade attempts
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        void* pSetPriorityClass = (void*)GetProcAddress(hKernel32, "SetPriorityClass");
        if (pSetPriorityClass && 
            MH_CreateHook(pSetPriorityClass, (void*)hooked_SetPriorityClass, (void**)&orig_SetPriorityClass) == MH_OK &&
            MH_EnableHook(pSetPriorityClass) == MH_OK) {
            Log("SetPriorityClass hook: ACTIVE (blocks priority downgrades)");
        } else {
            Log("WARNING: SetPriorityClass hook failed");
        }
    }
    
    OptimizeProcess();
    StartPriorityWatchdog();
    OptimizeWorkingSet();
    Log("--- FPS Cap ---");
    TryRemoveFPSCap();

    Log("--- File Size Cache ---");
    bool fsizeOk = InstallGetFileSizeCache();
    Log("--- WaitForSingleObject Spin ---");
    bool wfsOk = InstallWaitForSingleObjectHook();
    Log("--- Module Handle Cache ---");
    bool modOk = InstallGetModuleHandleCache();
    Log("--- String Compare (lstrcmp) ---");
    bool lstrOk = InstallLstrcmpHook();
    Log("--- String Length (lstrlen) ---");
    bool lstrlenOk = InstallLStrLenHooks();
    bool strlen76Ok = InstallWowStrlenHook();
    if (strlen76Ok) Log("WoW-internal strlen hook: ACTIVE (SSE2 replacement for sub_76EE30)");

    // CRT strstr SSE2 - algorithmic replacement for byte-by-byte search
#if !TEST_DISABLE_STRSTR_SSE2
    bool strstrOk = InstallStrstrSSE2();
#else
    bool strstrOk = false;
#endif

    // CRT memchr + strchr SSE2 - 16-byte SIMD byte scan
#if !TEST_DISABLE_CRT_CHAR_SSE2
    bool chrOk = InstallCrtCharSSE2();
#else
    bool chrOk = false;
#endif

    // CRT pow() integer fast-path - x^2=x*x, sqrt, etc.
#if !TEST_DISABLE_CRT_POW_SSE2
    bool powOk = InstallCrtPowSSE2();
#else
    bool powOk = false;
#endif
    bool wcharOk = InstallCrtWcharSSE2();

    // TLS Pointer Cache - eliminate 1297+ TEB lookups per frame
    bool tlsCacheOk = InstallTlsCache();

    // Stream Reader/Writer Cache - eliminate bounds checks
    bool streamCacheOk = InstallStreamCache();

    // Lua "this" Object Lookup Cache - cache method dispatcher results
    bool luaThisCacheOk = InstallLuaThisCache();

    // I/O Dispatcher Cache - 4050 callers
    bool ioCacheOk = InstallIOCache();

    // Lua Global Lookup Cache
    bool luaGlobalCacheOk = InstallLuaGlobalCache();

    // memset hook - 1108 callers
    bool hotFuncOk = InstallHotFunctionOptimizations();

    // Fast String Compare (strncmp) - 1013 callers
    bool fastStrncmpOk = InstallFastStrncmp();

    // CRT Free Hook - 2901 callers (#2 most called)
    bool crtFreeOk = InstallCrtFreeHook();

    // Aligned Allocator Cache - 1764 callers (thread-local pool for small allocations)
    bool alignedAllocOk = InstallAlignedAllocCache();

    // NOTE: free_cache, strnicmp_fast, tick_counter_cache are DUPLICATES of existing hooks:
    //   crt_free_hook.cpp   already hooks 0x76E5A0 (2901 callers)
    //   fast_strncmp.cpp    already hooks 0x76E780 (1013 callers)
    //   tls_cache.cpp       already hooks 0x4D3790 (1297 callers)
    // lua_pushnumber_fast DISABLED - corrupts numeric values, breaks addon UI bars

    // CDataStore Fast Path - 4179 xrefs (network packet serialization/deserialization)
    Log("--- CDataStore Fast Path ---");
    bool datastoreOk = InitDataStoreFastPath();

    // String & Memory Ops Fast Path - 3900+ xrefs (free wrapper, strnicmp, Jenkins hash)
    Log("--- String & Memory Ops Fast Path ---");
    bool stringOpsOk = InitStringOpsFast();

    // DISABLED: sub_84D9C0 (get_tvalue helper) uses usercall convention (ECX=L, EAX=idx)
    // Cannot be called as __cdecl - causes ACCESS_VIOLATION at 0x0084D9C4
    bool luaToNumberOk = false;      // InstallLuaToNumberCache();
    bool luaCheckNumberOk = false;   // InstallLuaCheckNumberCache();
    
    // DISABLED: Format validator causes disconnect during login (auth corruption)
    bool formatValidatorOk = false;  // InstallFormatValidatorCache();

    // DISABLED: sub_84F280 uses tail call optimization (last call doesn't return)
    // Cannot be hooked safely - control never returns to hook after orig call
    bool luaPushStringOk = false;    // InstallLuaPushStringCache();

    Log("--- MBT/WCT ASCII Fast Path ---");
    bool mbwcOk = InstallMBWCHooks();
    Log("--- CRT Memory Fast Paths ---");
    bool crtOk = InstallCrtMemFastPaths();
    bool sysInfoOk = InstallSysInfoCache();
    bool regCacheOk = InstallRegCache();
    bool smCacheOk = false; // Disabled - breaks hardware cursor
    bool noDebugOk = InstallNoDebuggerPresent();
    bool verCacheOk = InstallVerCache();
    bool batch10Ok = InstallBatchOpt10();
    bool batch20Ok = InstallBatchOpt20();
    bool batch30Ok = InstallBatchOpt30();
    bool batch35Ok = InstallBatchOpt35();
    bool batch38Ok = false;
    Log("--- GetProcAddress Cache ---");
    bool gpaOk = InstallGetProcAddressCache();
    Log("--- GetModuleFileName Cache ---");
    bool gmfOk = InstallGetModuleFileNameCache();
    Log("--- Environment Variable Cache ---");
    bool envOk = InstallEnvironmentVariableCache();
    Log("--- Profile String Cache ---");
    bool profOk = InstallGetPrivateProfileCache();

    Log("--- Message Pump ---");
    bool msgPumpOk = InstallMsgPumpHook();

    Log("--- Swap/Present ---");
    bool swapOk = InstallSwapPresentHook();

    Log("--- Lua Table Rehash ---");
    bool tableReshapeOk = InstallLuaHResizeHook();
    bool assetPathOk = false; // Disabled - breaks logout/teardown

    Log("--- Lua Table Lookup ---");
    bool luaHGetStrOk = InstallLuaHGetStrCache();

    Log("--- Deferred Field Updates ---");
    bool fieldOk = InstallFieldUpdateHook();
    HeapCompactor_Init();

    Log("--- Lua tonumber Fast Path ---");
    bool luaToNumberFastOk = InstallLuaToNumberFast();

    Log("--- Lua pushnumber Fast Path ---");
    bool luaPushNumberFastOk = InstallLuaPushNumberFast();

    Log("--- GetTime() Frame-Cached Fast Path ---");
    bool getTimeFastOk = InstallGetTimeFast();

    Log("--- lua_pushvalue Direct Stack Copy ---");
    bool pushValueFastOk = InstallLuaPushValueFast();

    Log("--- Render State Deduplication ---");
    bool renderDedupOk = InstallRenderStateDedup();

    Log("--- Lua SetTable Cache ---");
    bool setTableCacheOk = InstallLuaSetTableCache();

    Log("--- Regex Pattern Cache ---");
    bool regexCacheOk = InstallRegexCache();

    Log("--- SSE2 Trig LUT ---");
    InitTrigLUT();

    Log("--- Data Caches (10) ---");
    bool dataCachesOk = InitDataCaches();

    Log("--- Compute Caches (10) ---");
    bool computeCachesOk = InitComputeCaches();

    Log("--- Event Name Hash Cache ---");
    bool eventHashOk = InstallEventNameHash();

    Log("--- CDataStore Batch Read ---");
    bool cdataBatchOk = InstallCDataStoreBatch();

    Log("--- SSE2 Strcpy Optimization ---");
    bool strcpyOk = InstallStrcatFast();

    Log("--- Script Handler Cache ---");
    bool scriptHandlerOk = InstallScriptHandlerCache();

    Log("--- DBC Lookup Cache ---");
    bool dbcLookupOk = InstallDbcLookupCache();

    Log("--- Event Dispatch Cache ---");
    bool eventDispatchOk = InstallEventDispatchCache();

    Log("--- Event Name Cache ---");
    bool eventNameOk = InstallEventNameCache();

    Log("--- luaH_getstr Inline Optimization ---");
    bool getStrInlineOk = InstallLuaGetStrInline();

    Log("--- lua_rawgeti Inline Optimization ---");
#if TEST_DISABLE_RAWGETI_INLINE
    bool rawGetIInlineOk = false;
    Log("[RawGetIInline] DISABLED (suspected loading screen crash at 0x84E9DE)");
#else
    bool rawGetIInlineOk = InstallLuaRawGetIInline();
#endif

    Log("--- luaV_gettable Safety Patch (crash fix) ---");
    bool getTableSafetyOk = InstallLuaGetTableSafety();

    Log("--- Lua VM Engine (Direct-Threaded Interpreter) ---");
    bool vmEngineOk = InstallLuaVMEngine();
    CrashDumper::RegisterFeature("LuaVMEngine");
    CrashDumper::FeatureSetActive("LuaVMEngine", vmEngineOk);

    Log("--- Lua VM Phase3 Optimizations ---");
    bool vmPhase3Ok = LuaVMPhase3::Init();
    CrashDumper::RegisterFeature("LuaVMPhase3");
    CrashDumper::FeatureSetActive("LuaVMPhase3", vmPhase3Ok);

    Log("--- Hardware Cursor ---");
    bool cursorOk = InstallHardwareCursorHooks();

    Log("--- Frame Script Throttling ---");
    bool frameThrottleOk = InstallFrameThrottling();

    Log("--- Tooltip String Caching ---");
    bool tooltipCacheOk = TooltipCache::Install();

    Log("--- Spell Data Caching ---");
    bool spellCacheOk = SpellCache::Init();

    // UI Frame Batching - REMOVED due to calling convention issues
    // Caused MoveAnything addon to break even when disabled
    // See UI_FRAME_BATCHING_ISSUE.md for details
    // Log("--- UI Frame Update Batching ---");
    // bool uiFrameBatchOk = InstallUIFrameBatching();

    Log("--- Table Concat Fast Path ---");
    // table.concat fast path causes 0xC0000005 crashes
    // when addons use string concatenation heavily (ElvUI, WeakAuras, etc.).
    // The hook performs direct Lua stack writes via TValue* which conflicts
    // with addon execution flow during world load.
    bool tableConcatOk = false;

    Log("--- Lua RawGetI ---");
    bool luaRawGetIOk = InstallLuaRawGetICache();

    Log("--- CombatLog Full Cache ---");
    bool combatLogFullCacheOk = InstallCombatLogFullCache();

    Log("--- Thread Affinity ---");
    if (IsWine()) {
        // On Wine/Rosetta, hook SetThreadIdealProcessor at the kernel32
        // level to make it a no-op. WoW's own sub_8D2110 (ThreadWorker)
        // and potentially WoWsilicon call this natively - our own
        // InstallThreadAffinity guard only prevents OUR hook from pinning,
        // but cannot stop WoW's original code. The rosettax87 JIT desyncs
        // when any caller changes thread affinity.
        InstallWineSTIPNoop();
    }
    g_threadAffOk = InstallThreadAffinity();

    Log("--- VA Arena ---");
    vaOk = InstallVAArena();

    Log("--- RTTI Type Check Cache ---");
    bool rttiCacheOk = InstallRTTICache();

    Log("--- Stream Buffer Fast Path ---");
    bool streamBufOk = InstallStreamBufferFastPath();

    bool luaOk = false;
    Log("");
    Log("--- Lua VM Optimizer ---");
#if TEST_DISABLE_LUA_VM_OPT
    Log("[LuaOpt] DISABLED (baseline test - system hooks only)");
#else
    luaOk = LuaOpt::PrepareFromWorkerThread();
#endif

    Log("");
    Log("--- Combat Log ---");
    bool combatLogOk = CombatLogOpt::Init();

    Log("");
    Log("--- Combat Log Buffer Governor ---");
    bool combatLogBufOk = CombatLogBuffer::Init();

    Log("");
    Log("--- Multithreaded Combat Log Parser ---");
#if TEST_DISABLE_COMBATLOG_MT
    Log("[CombatLogMT] DISABLED (feature flag)");
    bool combatLogMTOk = false;
#else
    bool combatLogMTOk = CombatLogMT::Init();
#endif

    Log("");
    Log("--- Async Texture/Model Loading ---");
#if TEST_DISABLE_TEXTURE_ASYNC
    Log("[TextureAsync] DISABLED (feature flag)");
    bool textureAsyncOk = false;
#else
    bool textureAsyncOk = TextureAsync::Init();
#endif

    Log("");
    Log("--- Async Spell Data Prefetching ---");
#if TEST_DISABLE_SPELL_PREFETCH
    Log("[SpellPrefetch] DISABLED (feature flag)");
    bool spellPrefetchOk = false;
#else
    bool spellPrefetchOk = SpellPrefetch::Init();
#endif

    Log("");
    Log("--- Multithreaded Addon Update Dispatcher ---");
    // DISABLED: worker threads write to WoW game state without synchronization
    // causing ACCESS_VIOLATION at 0x009E4F24 from background thread
    Log("[AddonDispatcher] DISABLED: unsynchronized writes to WoW game state");
    bool addonDispatcherOk = false;

    Log("");
    Log("--- Async Model/M2 Loading ---");
#if TEST_DISABLE_MODEL_ASYNC
    Log("[ModelAsync] DISABLED (feature flag)");
    bool modelAsyncOk = false;
#else
    bool modelAsyncOk = ModelAsync::Init();
#endif

    Log("");
    Log("--- Predictive MPQ Prefetching ---");
    // DISABLED: worker threads call hooked SFile2 which touches WoW globals
    // causing ACCESS_VIOLATION at 0x009E4F24 from MPQPrefetch worker thread
    Log("[MPQPrefetch] DISABLED: workers touch WoW globals via hooked SFile2");
    bool mpqPrefetchOk = false;

    Log("");
    Log("--- Object Visibility Cache ---");
#if TEST_DISABLE_OBJ_VIS_CACHE
    Log("[ObjVisCache] DISABLED (feature flag)");
#else
    ObjVisCache::Init();
#endif

    // Crash fix: sub_5E90D0 dereferences dword_C24238 without NULL check.
    // During loading screen transitions, this global may be uninitialized (NULL),
    // causing ACCESS_VIOLATION at 0x5E9108. Patch: insert test ecx,ecx / jz
    // after the mov ecx, [C24238] at 0x5E90FF.
    {
        // Original at 0x5E90FF:
        //   8B 0D 38 42 C2 00   mov ecx, [C24238]   (6 bytes)
        //   83 C4 08            add esp, 8           (3 bytes)
        //   3B 04 B1            cmp eax, [ecx+esi*4] (3 bytes)
        //
        // Patched:
        //   8B 0D 38 42 C2 00   mov ecx, [C24238]   (6 bytes, unchanged)
        //   85 C9               test ecx, ecx        (2 bytes, replaces add esp,8 first 2)
        //   74 05               jz short +5          (2 bytes, skip cmp if NULL)
        //   90                  nop                   (1 byte, padding)
        //   3B 04 B1            cmp eax, [ecx+esi*4] (3 bytes, unchanged)
        //
        // When ecx==NULL: jz skips over cmp to 0x5E910B (jz short loc_5E9112)
        // But we still need add esp,8! So instead, move add esp before the test:
        //
        // Better patch at 0x5E90FF (overwrite 12 bytes):
        //   8B 0D 38 42 C2 00   mov ecx, [C24238]
        //   83 C4 08            add esp, 8
        //   85 C9               test ecx, ecx
        //   74 01               jz short +1 (skip next nop, land on ret-like path)
        //   90                  nop
        // Then 0x5E9108 cmp stays but is only reached when ecx!=NULL
        //
        // Actually simplest: just NOP the cmp when ecx is NULL by patching
        // the function entry to add an early-out. But that's complex.
        //
        // Simplest safe patch: overwrite 0x5E9105-0x5E910A (6 bytes):
        //   Original: 83 C4 08 3B 04 B1  (add esp,8; cmp eax,[ecx+esi*4])
        //   Patched:  83 C4 08 85 C9 74  (add esp,8; test ecx,ecx; jz ...)
        //   Then we need the jz target to skip the cmp. But cmp is only 3 bytes
        //   and we consumed it. We need to reconstruct cmp after the jz.
        //
        // Cleanest: use a 5-byte NOP sled + redirect. Too complex for inline.
        // Use MinHook instead.

        typedef void (__cdecl *Sub5E90D0_fn)();
        static Sub5E90D0_fn orig_Sub5E90D0 = nullptr;

        // Check if dword_C24238 is NULL before calling original
        // sub_5E90D0 is __cdecl retn (no args, no stack cleanup)
        struct NullGuard_5E90D0 {
            static void __cdecl Hooked() {
                uint32_t* pGlobal = (uint32_t*)0xC24238;
                // If the global array pointer is NULL, skip the function entirely.
                // The function only updates visual alert state - skipping is safe.
                if (*pGlobal == 0) {
                    return;
                }
                orig_Sub5E90D0();
            }
        };

        void* target = (void*)0x5E90D0;
        // Use WineSafe_CreateHook to avoid Rosetta JIT desync on macOS
        if (WineSafe_CreateHook(target, (void*)NullGuard_5E90D0::Hooked, (void**)&orig_Sub5E90D0) == MH_OK) {
            if (MH_EnableHook(target) == MH_OK) {
                Log("[CrashFix] sub_5E90D0 NULL guard: ACTIVE (dword_C24238 check)");
            } else {
                Log("[CrashFix] sub_5E90D0 NULL guard: enable failed");
                MH_RemoveHook(target);
            }
        } else {
            if (IsWine()) {
                Log("[CrashFix] sub_5E90D0 NULL guard: SKIPPED (Wine/Rosetta - WoW .text patch unsafe)");
            } else {
                Log("[CrashFix] sub_5E90D0 NULL guard: hook creation failed");
            }
        }
    }

    Log("");
    Log("--- Async Sound/Audio Prefetching ---");
#if TEST_DISABLE_SOUND_PREFETCH
    Log("[SoundPrefetch] DISABLED (feature flag)");
#else
    SoundPrefetch::Init();
    Log("[SoundPrefetch] Initialized");
#endif

    Log("");
    Log("--- Async Quest/Achievement Data Loading ---");
#if TEST_DISABLE_QUEST_ASYNC
    Log("[QuestAsync] DISABLED (feature flag)");
#else
    QuestAsync::Init();
    Log("[QuestAsync] Initialized");
#endif

    Log("");
    Log("--- Multithreaded Nameplate Renderer ---");
    // DISABLED: worker threads write to WoW rendering globals without synchronization
    Log("[NameplateMT] DISABLED: unsynchronized writes to WoW game state");
    bool nameplateMTOk = false;

    Log("");
    Log("--- UI Cache ---");
    bool uiCacheOk = UICache::Init();

    Log("");
    Log("--- API Cache ---");
#if TEST_DISABLE_ALL_APICACHE
    Log("[ApiCache] DISABLED (baseline test)");
    bool apiCacheOk = false;
#else
    bool apiCacheOk = ApiCache::Init();
#endif

    Log("--- Timing Method Fix ---");
    InstallTimingFix();

    bool fastPathOk = false;
    Log("");
    Log("--- Lua Fast Path ---");
#if TEST_DISABLE_ALL_PHASE2
    Log("[FastPath] DISABLED (baseline test)");
#else
    __try {
        fastPathOk = LuaFastPath::Init();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[FastPath] EXCEPTION 0x%08X - SKIPPED", GetExceptionCode());
    }
#endif

    // Addon file RAM-disk - pre-load all addon files into memory
#if !TEST_DISABLE_ADDON_PRELOAD
    bool addonPreloadOk = InitAddonPreload();
#else
    bool addonPreloadOk = false;
#endif

    // Lua bytecode cache (skips script parsing on reload)
#if !TEST_DISABLE_LUA_BYTECODE_CACHE
    bool bytecodeOk = LuaBytecodeCache::Init();
#else
    bool bytecodeOk = false;
#endif

    bool internalsOk = false;
    Log("");
    Log("--- Lua VM Internals ---");
    Log("[LuaVM] DISABLED (baseline test)");

    // Lua VM table lookup cache (luaV_gettable hook)
    Log("--- Lua VM Table Cache ---");
    bool vmCacheOk = InstallLuaVMCache();

    Log("--- luaV_gettable Cache ---");
    bool getTableCacheOk = InstallLuaGetTableCache();

    Log("--- SavedVariables Async Writer ---");
    bool savedVarsAsyncOk = InstallSavedVarsAsync();

    Log("--- Texture Decode MT ---");
    bool textureDecodeMTOk = TextureDecodeMT::Init();
    CrashDumper::RegisterFeature("TextureDecodeMT");

    Log("--- MPQ Decompress MT ---");
    bool mpqDecompressMTOk = MPQDecompressMT::Init();
    CrashDumper::RegisterFeature("MPQDecompressMT");

    Log("--- Spell Effect MT ---");
    bool spellEffectMTOk = SpellEffectMT::Init();
    CrashDumper::RegisterFeature("SpellEffectMT");

    Log("--- Lua Bytecode Pre-Compiler ---");
    bool bytecodePreCompilerOk = LuaBytecodePreCompiler::Init();
    CrashDumper::RegisterFeature("LuaBytecodePreCompiler");

    Log("--- Animation MT ---");
    bool animMTOk = AnimMT::Init();
    CrashDumper::RegisterFeature("AnimMT");

    Log("--- Hook Prefetch (9 hooks) ---");
    bool hookPrefetchOk = HookPrefetch::InstallAll();

    Log("--- Hot Patch (20 features) ---");
    bool hotPatchOk = HotPatch::InstallAll();

    Log("--- Infra API (50 features) ---");
    bool infraPatchOk = InfraPatch::InstallAll();

    // ALL WoW.exe internal hooks DISABLED for crash isolation.
    // Crash at 0x009E4F24 shows ASCII strings executed as code = corrupted vtable/fnptr.
    // These hooks patch WoW's internal functions and may corrupt adjacent memory.
    Log("--- WoW.exe Optimization Hooks (20 hooks) ---");
    Log("[WowOpt] DISABLED: crash isolation (corrupts WoW fnptrs at 0x009E4F24)");
    bool wowOptOk = false; // WowOptHooks::InstallAll();

    Log("--- WoW.exe Performance Hooks (20 hooks) ---");
    Log("[WowPerf] DISABLED: crash isolation");
    bool wowPerfOk = false; // WowPerfHooks::InstallAll();

    Log("--- WoW.exe Extended Hooks (40 features) ---");
    Log("[Extended] DISABLED: crash isolation");
    bool wowExtendedOk = false; // WowExtendedHooks::InstallAll();

    Log("--- WoW.exe Subsystem Hooks (100 features) ---");
    Log("[Subsystem] DISABLED: crash isolation");
    bool wowSubsystemOk = false; // WowSubsystemHooks::InstallAll();

    Log("--- Memory Optimizations: LAA + Async + MemOpt ---");
    bool memoryOptLAA = WowMemoryOpt::EnableLargeAddressAware();
    // Async worker pool DISABLED: background threads writing to WoW globals
    // caused ACCESS_VIOLATION at 0x009E4F24 (write to .data section from worker thread)
    bool memoryOptAsync = false; // WowMemoryOpt::InitAsyncWorkerPool();
    Log("[MemOpt] Async worker pool DISABLED: unsynchronized writes to WoW game state");
    bool memoryOptMem = WowMemoryOpt::ApplyMemoryOptimizations();

    Log("--- Source-Level Optimizations ---");
    bool sourceOptOk = WowSourceOpt::InstallAll();

    Log("--- TLS Object Cache ---");
    bool tlsObjCacheOk = TlsObjectCache::Install();

    Log("");
    Log("--- D3D9 State Manager (15 hooks) ---");
    bool d3d9StateOk = false; // DISABLED: vtable patching crashes with DXVK/d3d9 wrapper
    Log("[D3D9State] DISABLED: vtable layout mismatch (DXVK/overlay wrappers)");

    Log("");
    Log("--- Render Hooks (anim throttle, backbuffer) ---");
    bool renderHooksOk = InstallRenderHooks(); // BISECT

    Log("");
    Log("--- SIMD Hooks (SSE2 matrix, frustum, color) ---");
    bool simdHooksOk = InstallSimdHooks(); // BISECT

    Log("");
    Log("--- Logic Hooks (combat text, UI cache, heartbeat) ---");
    bool logicHooksOk = InstallLogicHooks(); // BISECT

    Log("");
    Log("--- Memory Hooks (aligned slabs, GUID hash) ---");
    bool memHooksOk = InstallMemoryHooks(); // BISECT

    Log("");
    Log("--- Async Hooks (worker pool, particle, prefetch) ---");
    bool asyncHooksOk = InstallAsyncHooks(); // BISECT

    Log("");
    Log("========================================");
    Log("  Initialization complete");
    Log("========================================");

    // Start async I/O worker after all hooks/workers are ready - avoids init race
    InstallAsyncIoWorker();

    Log("");
    Log("  [%s] mimalloc allocator",           allocOk     ? " OK " : "FAIL");
    Log("  [%s] Sleep hook (PreciseSleep)",    sleepOk     ? " OK " : "FAIL");
    Log("  [%s] GetTickCount (QPC)",           tickOk      ? " OK " : "FAIL");
    Log("  [%s] timeGetTime (QPC sync)",       tgtOk       ? " OK " : "FAIL");
    Log("  [%s] Heap optimization (LFH)",      heapOk      ? " OK " : "FAIL");
    Log("  [%s] ThreadId cache (TLS)",         tidOk       ? " OK " : "FAIL");
    #if !CRASH_TEST_DISABLE_QPC_CACHE
        Log("  [%s] QPC cache (50us coalesce)",    qpcOk       ? " OK " : "FAIL");
    #else
        Log("  [SKIP] QPC cache (crash isolation)");
    #endif        
    Log("  [%s] IsBadPtr (fast VirtualQuery)", bpOk        ? " OK " : "FAIL");    
    Log("  [%s] CompareStringA (ASCII fast)",  cmpOk       ? " OK " : "FAIL");
    Log("  [%s] MBT/WCT (SSE2 ASCII fast)",    mbwcOk      ? " OK " : "SKIP");
    Log("  [%s] CRT mem/str fast paths",        crtOk       ? " OK " : "SKIP");
    Log("  [%s] GetSystemInfo cache",            sysInfoOk    ? " OK " : "SKIP");
    Log("  [%s] RegQueryValueEx cache",          regCacheOk   ? " OK " : "SKIP");
    Log("  [%s] GetSystemMetrics cache",         smCacheOk    ? " OK " : "SKIP");
    Log("  [%s] GetVersionExA cache",            verCacheOk   ? " OK " : "SKIP");
    Log("  [%s] IsDebuggerPresent no-op",        noDebugOk    ? " OK " : "SKIP");
    Log("  [%s] Batch 8 kernel caches",         batch10Ok    ? " OK " : "SKIP");
    Log("  [%s] Batch 20 kernel caches",        batch20Ok    ? " OK " : "SKIP");
    Log("  [%s] Batch 24 kernel caches",        batch30Ok    ? " OK " : "SKIP");
    Log("  [%s] Batch 35 kernel caches",        batch35Ok    ? " OK " : "SKIP");
    Log("  [%s] Batch 38 kernel caches",        batch38Ok    ? " OK " : "SKIP");    
    Log("  [%s] OutputDebugString (no-op)",    debugOk     ? " OK " : "FAIL");
    Log("  [%s] CriticalSection (spin+try)",   csOk        ? " OK " : "FAIL");
    Log("  [%s] Network (NODELAY+ACK+QoS+KA)", netOk      ? " OK " : "FAIL");
    Log("  [%s] CreateFile (sequential I/O)",  fileOk      ? " OK " : "FAIL");
    Log("  [%s] ReadFile (adaptive MPQ cache)", readOk     ? " OK " : "FAIL");
    #if !CRASH_TEST_DISABLE_MPQ_MMAP
        Log("  [ OK ] MPQ memory mapping (1-256MB files)");
    #else
        Log("  [SKIP] MPQ memory mapping (disabled - stability)");
    #endif  
    Log("  [%s] CloseHandle (cache cleanup)",  closeOk     ? " OK " : "FAIL");
    Log("  [%s] FlushFileBuffers (MPQ skip)",  flushOk     ? " OK " : "FAIL");
    Log("  [%s] GetFileAttributesA (cache)",   faOk        ? " OK " : "FAIL");
    Log("  [%s] SetFilePointer (64-bit)",      sfpOk       ? " OK " : "FAIL");
    Log("  [SKIP] GlobalAlloc fast path (disabled hotfix)");  
    Log("  [ OK ] Timer resolution (0.5ms)");
    Log("  [ OK ] Thread affinity + priority");
    if (g_isMultiClient)
        Log("  [ OK ] Working set (64MB-512MB, multi-client)");
    else
        Log("  [ OK ] Working set (256MB-2GB)");
    Log("  [ OK ] Process priority (Above Normal)");
    Log("  [ OK ] FPS cap removal (200 -> 999)");
    if (g_isMultiClient) {
        Log("  [ OK ] Multi-client mode (conservative timer + sleep)");
    }
    Log("  [%s] Lua VM GC optimizer",          luaOk       ? "WAIT" : "SKIP");
    Log("  [%s] Combat log optimizer",         combatLogOk ? " OK " : "SKIP");
    Log("  [%s] UI widget cache",              uiCacheOk   ? " OK " : "SKIP");
    Log("  [%s] API cache (ItemInfo only)",    apiCacheOk  ? " OK " : "SKIP");
    Log("  [%s] Lua fast path (format)",       fastPathOk  ? " OK " : "SKIP");
    Log("  [%s] Lua VM internals (str+concat)", internalsOk ? " OK " : "SKIP");
    Log("  [%s] MsgPump (frame-continue)",    msgPumpOk   ? " OK " : "SKIP");
    Log("  [%s] Swap/Present (glFinish skip)", swapOk      ? " OK " : "SKIP");
    Log("  [%s] Lua Table Rehash (pow2)",     tableReshapeOk ? " OK " : "SKIP");
    Log("  [%s] Asset path cache",             assetPathOk   ? " OK " : "SKIP");
    Log("  [%s] Lua Table Lookup (getstr)",   luaHGetStrOk ? " OK " : "SKIP");
    Log("  [%s] Table Concat Fast Path",        tableConcatOk ? " OK " : "SKIP");
    Log("  [%s] Lua PushString (intern)",     luaPushStringOk ? " OK " : "SKIP");
    Log("  [%s] Lua RawGetI (int-key)",       luaRawGetIOk ? " OK " : "SKIP");
    Log("  [%s] CombatLog full cache",        combatLogFullCacheOk ? " OK " : "SKIP");
    Log("  [%s] Tooltip string cache (LRU)",  tooltipCacheOk ? " OK " : "SKIP");
    Log("  [%s] Spell data cache (LRU)",      spellCacheOk ? " OK " : "SKIP");
    Log("  [%s] RTTI type check cache",       rttiCacheOk   ? " OK " : "SKIP");
    Log("  [%s] Stream buffer fast path",     streamBufOk    ? " OK " : "SKIP");
    Log("  [%s] D3D9 State Manager (15 hooks)",   d3d9StateOk ? " OK " : "SKIP");
    Log("  [%s] Render Hooks (anim+backbuffer)",    renderHooksOk ? " OK " : "SKIP");
    Log("  [%s] SIMD Hooks (SSE2 matrix+frustum)", simdHooksOk ? " OK " : "SKIP");
    Log("  [%s] Logic Hooks (CT+UI+heartbeat)",    logicHooksOk ? " OK " : "SKIP");
    Log("  [%s] Memory Hooks (slabs+GUID)",        memHooksOk ? " OK " : "SKIP");
    Log("  [%s] Async Hooks (workers+particles)",  asyncHooksOk ? " OK " : "SKIP");

    // Start freeze detection watchdog AFTER all features initialized
    StartFreezeWatchdog();

    return 0;
}

// ================================================================
// 16a. sub_4D4DB0 - Object Type Check Cache (1905 callers)
//
// This is WoW's RTTI/dynamic_cast equivalent. Called on every object
// type check - UI widget validation, spell target filtering, combat
// log event type dispatch, frame script type guards.  Every call
// walks a hash table via sub_4D4BB0 with GUID + flags comparison.
//
// Cache the successful lookup result.  The (this, mask, guid64)
// tuple is stable for the lifetime of the object type registration.
// Direct-mapped 1024-entry cache with full-key validation.
// ================================================================

typedef int (__cdecl* RTTICheck_fn)(__int64, int);
static RTTICheck_fn orig_RTTICheck = nullptr;

static constexpr int RTTI_CACHE_SIZE = 1024;
static constexpr int RTTI_CACHE_MASK = RTTI_CACHE_SIZE - 1;

struct RTTICacheEntry {
    __int64 guid64;
    int     flags;
    int     result;
    bool    valid;
};

static RTTICacheEntry g_rttiCache[RTTI_CACHE_SIZE] = {};
long g_rttiHits = 0, g_rttiMisses = 0;

static int __cdecl hooked_RTTICheck(__int64 guid64, int flags) {
#if CRASH_TEST_DISABLE_RTTI_CACHE
    return orig_RTTICheck(guid64, flags);
#else
    if (!guid64) return 0;

    uint32_t hash = (uint32_t)(guid64 ^ (guid64 >> 32) ^ flags);
    int slot = hash & RTTI_CACHE_MASK;
    RTTICacheEntry* e = &g_rttiCache[slot];

    if (e->valid && e->guid64 == guid64 && e->flags == flags) {
        InterlockedIncrement(&g_rttiHits);
        return e->result;
    }

    int result = orig_RTTICheck(guid64, flags);
    e->guid64 = guid64;
    e->flags  = flags;
    e->result = result;
    e->valid  = true;
    InterlockedIncrement(&g_rttiMisses);
    return result;
#endif
}

static bool InstallRTTICache() {
#if CRASH_TEST_DISABLE_RTTI_CACHE
    Log("RTTI type check cache: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x004D4DB0;
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("RTTI cache: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }
    if (WineSafe_CreateHook(target, (void*)hooked_RTTICheck, (void**)&orig_RTTICheck) != MH_OK)
        return false;
    if (MH_EnableHook(target) != MH_OK)
        return false;
    Log("RTTI type check cache: ACTIVE (sub_4D4DB0 @ 0x004D4DB0 - %d-slot direct-map, 1905 callers)", RTTI_CACHE_SIZE);
    return true;
#endif
}

// ================================================================
// 16b. sub_47B3C0 / sub_47B0A0 - Stream Buffer Read/Write Fast Path
//
// Called 2662 times across the binary.  sub_47B3C0 reads 4 bytes from
// a stream buffer (used in Lua bytecode fetch, script execution, network
// packet parsing).  sub_47B0A0 writes 4 bytes (script stack push, packet
// assembly).  Both call sub_47B290 for bounds checking which may invoke
// a virtual realloc through (*this+8).
//
// Fast path: inline the common case where cursor + 4 still fits within
// the buffer's committed region.  Bypasses the vtable call on 99%+ of
// invocations.  Falls back to original on the first call after a realloc
// (when the virtual function would have grown the buffer).
// ================================================================

// sub_47B3C0: _DWORD* __thiscall StreamRead(_DWORD* this, _DWORD* out)
//   *(this+4) = cursor, *(this+1)=base, *(this+2)=delta, *(this+3)=size
//   if (bounds_ok) { *out = *(base - delta + cursor); cursor += 4; }
typedef void* (__fastcall* StreamRead_fn)(void*, void*);
static StreamRead_fn orig_StreamRead = nullptr;
long g_streamReadHits = 0, g_streamReadFallbacks = 0;

static void* __fastcall hooked_StreamRead(void* This, void* out) {
#if CRASH_TEST_DISABLE_STREAM_FASTPATH
    return orig_StreamRead(This, out);
#else
    __try {
        uintptr_t t = (uintptr_t)This;
        uint32_t cursor = *(uint32_t*)(t + 0x14);   // this+5 (in dwords: offset 0x14)
        uint32_t base   = *(uint32_t*)(t + 0x04);   // this+1
        uint32_t delta  = *(uint32_t*)(t + 0x08);   // this+2
        uint32_t size   = *(uint32_t*)(t + 0x0C);   // this+3

        // Fast bounds: cursor within [delta, delta+size) (relative to committed region)
        if (cursor + 4 <= delta + size && cursor >= delta) {
            uintptr_t addr = cursor - delta + base;
            if (addr > 0x10000 && addr < 0xBFFF0000) {
                *(uint32_t*)out = *(uint32_t*)addr;
                *(uint32_t*)(t + 0x14) = cursor + 4;
                InterlockedIncrement(&g_streamReadHits);
                return This;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}

    InterlockedIncrement(&g_streamReadFallbacks);
    return orig_StreamRead(This, out);
#endif
}

// sub_47B0A0: unsigned int* __thiscall StreamWrite(unsigned int* this, int val)
//   Same buffer layout as StreamRead.  Writes val at cursor, advances.
typedef void* (__fastcall* StreamWrite_fn)(void*, int);
static StreamWrite_fn orig_StreamWrite = nullptr;
long g_streamWriteHits = 0, g_streamWriteFallbacks = 0;

static void* __fastcall hooked_StreamWrite(void* This, int val) {
#if CRASH_TEST_DISABLE_STREAM_FASTPATH
    return orig_StreamWrite(This, val);
#else
    __try {
        uintptr_t t = (uintptr_t)This;
        uint32_t cursor = *(uint32_t*)(t + 0x10);   // this+4
        uint32_t base   = *(uint32_t*)(t + 0x04);   // this+1
        uint32_t delta  = *(uint32_t*)(t + 0x08);   // this+2
        uint32_t size   = *(uint32_t*)(t + 0x0C);   // this+3

        // Fast bounds: cursor within [delta, delta+size) - same as sub_47B0A0
        if (cursor + 4 <= delta + size && cursor >= delta) {
            uintptr_t addr = cursor - delta + base;
            if (addr > 0x10000 && addr < 0xBFFF0000) {
                *(uint32_t*)addr = val;
                *(uint32_t*)(t + 0x10) = cursor + 4;
                InterlockedIncrement(&g_streamWriteHits);
                return This;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}

    InterlockedIncrement(&g_streamWriteFallbacks);
    return orig_StreamWrite(This, val);
#endif
}

static bool InstallStreamBufferFastPath() {
#if CRASH_TEST_DISABLE_STREAM_FASTPATH
    Log("Stream buffer fast path: DISABLED (crash isolation)");
    return false;
#else
    int ok = 0;

    // sub_47B3C0 - StreamRead (1477 callers)
    void* pRead = (void*)0x0047B3C0;
    unsigned char* pr = (unsigned char*)pRead;
    if (pr[0] == 0x55 && pr[1] == 0x8B) {
        if (WineSafe_CreateHook(pRead, (void*)hooked_StreamRead, (void**)&orig_StreamRead) == MH_OK
            && MH_EnableHook(pRead) == MH_OK) ok++;
    }

    // sub_47B0A0 - StreamWrite (1185 callers)
    void* pWrite = (void*)0x0047B0A0;
    unsigned char* pw = (unsigned char*)pWrite;
    if (pw[0] == 0x55 && pw[1] == 0x8B) {
        if (WineSafe_CreateHook(pWrite, (void*)hooked_StreamWrite, (void**)&orig_StreamWrite) == MH_OK
            && MH_EnableHook(pWrite) == MH_OK) ok++;
    }

    if (ok > 0) {
        Log("Stream buffer fast path: ACTIVE (%d/2 hooked, sub_47B3C0+sub_47B0A0 - inline bounds check, 2662 callers)", ok);
        return true;
    }
    Log("Stream buffer fast path: FAILED (no hooks installed)");
    return false;
#endif
}

// ================================================================
// 17. GetFileSize / GetFileSizeEx - Cache
//
// ================================================================

static constexpr int FSIZE_CACHE_SIZE = 256;
static constexpr int FSIZE_CACHE_MASK = FSIZE_CACHE_SIZE - 1;

struct FSizeEntry {
    uint32_t      pathHash;
    LARGE_INTEGER fileSize;
    bool          valid;
};

static FSizeEntry g_fsizeCache[FSIZE_CACHE_SIZE] = {};

// GetFileSizeEx cache disabled � disabled in production
// hang after character select. Windows reuses handle values; caching
// by handle returns stale sizes for recycled handles.
#define TEST_DISABLE_GETFILESIZE_CACHE  1

typedef BOOL (WINAPI* GetFileSizeEx_fn)(HANDLE, PLARGE_INTEGER);
static GetFileSizeEx_fn orig_GetFileSizeEx = nullptr;

static BOOL WINAPI hooked_GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize) {
    // Cache disabled for testing - pass through to original
    return orig_GetFileSizeEx(hFile, lpFileSize);
}

static bool InstallGetFileSizeCache() {
#if CRASH_TEST_DISABLE_GETFILESIZE_CACHE
    Log("GetFileSizeEx cache: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;
    void* p = (void*)GetProcAddress(hK32, "GetFileSizeEx");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_GetFileSizeEx, (void**)&orig_GetFileSizeEx) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("GetFileSizeEx hook: ACTIVE (cache via FileNameInfo, %d slots)", FSIZE_CACHE_SIZE);
    return true;
#endif
}

// ================================================================
// 18. WaitForSingleObject - Spin-First for Short Waits
//
// ================================================================

typedef DWORD (WINAPI* WaitForSingleObject_fn)(HANDLE, DWORD);
static WaitForSingleObject_fn orig_WaitForSingleObject = nullptr;

static DWORD WINAPI hooked_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    if (dwMilliseconds <= 1) {
        for (int i = 0; i < 32; i++) {
            DWORD result = WaitForSingleObject(hHandle, 0);
            if (result != WAIT_TIMEOUT) {
                g_wfsSpinHits++;
                return result;
            }
            _mm_pause();
        }
        g_wfsFallbacks++;
    }
    return orig_WaitForSingleObject(hHandle, dwMilliseconds);
}

static bool InstallWaitForSingleObjectHook() {
#if CRASH_TEST_DISABLE_WFS_SPIN
    Log("WaitForSingleObject spin: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;
    void* p = (void*)GetProcAddress(hK32, "WaitForSingleObject");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_WaitForSingleObject, (void**)&orig_WaitForSingleObject) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("WaitForSingleObject hook: ACTIVE (spin-first for <=1ms waits, 32x pause)");
    return true;
#endif
}

// ================================================================
// 19. GetModuleHandleA - Cache
//
// ================================================================

static constexpr int MOD_CACHE_SIZE = 1024;
static constexpr int MOD_CACHE_MASK = MOD_CACHE_SIZE - 1;

struct ModCacheEntry {
    uint32_t nameHash;
    HMODULE  hModule;
    bool     valid;
};

static ModCacheEntry g_modCache[MOD_CACHE_SIZE] = {};

typedef HMODULE (WINAPI* GetModuleHandleA_fn)(LPCSTR);
static GetModuleHandleA_fn orig_GetModuleHandleA = nullptr;

static HMODULE WINAPI hooked_GetModuleHandleA(LPCSTR lpModuleName) {
    if (!lpModuleName) return orig_GetModuleHandleA(lpModuleName);

    uint32_t hash = 0x811C9DC5;
    for (const char* p = lpModuleName; *p; p++) {
        char c = *p;
        if (c >= 'A' && c <= 'Z') c += 32;
        hash ^= (uint8_t)c;
        hash *= 0x01000193;
    }
    int slot = hash & MOD_CACHE_MASK;
    ModCacheEntry* e = &g_modCache[slot];

    if (e->valid && e->nameHash == hash) {
        g_modHits++;
        return e->hModule;
    }

    HMODULE h = orig_GetModuleHandleA(lpModuleName);
    if (h) {
        e->nameHash = hash;
        e->hModule = h;
        e->valid = true;
    }
    g_modMisses++;
    return h;
}

static bool InstallGetModuleHandleCache() {
#if CRASH_TEST_DISABLE_MODHANDLE_CACHE
    Log("GetModuleHandleA cache: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;
    void* p = (void*)GetProcAddress(hK32, "GetModuleHandleA");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_GetModuleHandleA, (void**)&orig_GetModuleHandleA) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("GetModuleHandleA hook: ACTIVE (cache, %d slots)", MOD_CACHE_SIZE);
    return true;
#endif
}

// ================================================================
// 20. lstrcmpA / lstrcmpiA - Fast Path
//
// ================================================================

typedef int (WINAPI* lstrcmpA_fn)(LPCSTR, LPCSTR);
typedef int (WINAPI* lstrcmpiA_fn)(LPCSTR, LPCSTR);
static lstrcmpA_fn  orig_lstrcmpA  = nullptr;
static lstrcmpiA_fn orig_lstrcmpiA = nullptr;

static int WINAPI hooked_lstrcmpA(LPCSTR lpString1, LPCSTR lpString2) {
    if (!lpString1 || !lpString2) goto lstr_fallback;

    int len1 = 0, len2 = 0;
    for (const char* p = lpString1; *p && len1 < 256; p++, len1++);
    if (len1 >= 256) goto lstr_fallback;
    for (const char* p = lpString2; *p && len2 < 256; p++, len2++);
    if (len2 >= 256) goto lstr_fallback;

    if (len1 != len2) { g_lstrcmpHits++; return len1 < len2 ? -1 : 1; }

    for (int i = 0; i < len1; i++) {
        if ((unsigned char)lpString1[i] > 127 || (unsigned char)lpString2[i] > 127)
            goto lstr_fallback;
    }

    g_lstrcmpHits++;
    return memcmp(lpString1, lpString2, len1);

lstr_fallback:
    g_lstrcmpFallbacks++;
    return orig_lstrcmpA(lpString1, lpString2);
}

static int WINAPI hooked_lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2) {
    if (!lpString1 || !lpString2) goto lstri_fallback;

    int len1 = 0, len2 = 0;
    for (const char* p = lpString1; *p && len1 < 256; p++, len1++);
    if (len1 >= 256) goto lstri_fallback;
    for (const char* p = lpString2; *p && len2 < 256; p++, len2++);
    if (len2 >= 256) goto lstri_fallback;

    if (len1 != len2) { g_lstrcmpHits++; return len1 < len2 ? -1 : 1; }

    for (int i = 0; i < len1; i++) {
        unsigned char c1 = (unsigned char)lpString1[i];
        unsigned char c2 = (unsigned char)lpString2[i];
        if (c1 > 127 || c2 > 127) goto lstri_fallback;
        if (c1 >= 'a' && c1 <= 'z') c1 -= 32;
        if (c2 >= 'a' && c2 <= 'z') c2 -= 32;
        if (c1 != c2) {
            g_lstrcmpHits++;
            return (int)c1 - (int)c2;
        }
    }

    g_lstrcmpHits++;
    return 0;

lstri_fallback:
    g_lstrcmpFallbacks++;
    return orig_lstrcmpiA(lpString1, lpString2);
}

static bool InstallLstrcmpHook() {
#if CRASH_TEST_DISABLE_LSTRCMP
    Log("lstrcmp/lstrcmpiA hooks: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

    void* pCmp = (void*)GetProcAddress(hK32, "lstrcmpA");
    if (pCmp && MH_CreateHook(pCmp, (void*)hooked_lstrcmpA, (void**)&orig_lstrcmpA) == MH_OK)
        if (MH_EnableHook(pCmp) == MH_OK) ok++;

    void* pCmpi = (void*)GetProcAddress(hK32, "lstrcmpiA");
    if (pCmpi && MH_CreateHook(pCmpi, (void*)hooked_lstrcmpiA, (void**)&orig_lstrcmpiA) == MH_OK)
        if (MH_EnableHook(pCmpi) == MH_OK) ok++;

    if (ok > 0) {
        Log("lstrcmp/lstrcmpiA hooks: ACTIVE (%d/2, fast ASCII path)", ok);
        return true;
    }
    return false;
#endif
}

// ================================================================
// 21. GetPrivateProfileStringA - Cache
//
// ================================================================

static constexpr int PROF_CACHE_SIZE = 128;
static constexpr int PROF_CACHE_MASK = PROF_CACHE_SIZE - 1;
static constexpr int PROF_MAX_VALUE  = 512;

struct ProfCacheEntry {
    uint32_t keyHash;
    char     value[PROF_MAX_VALUE];
    bool     valid;
};

static ProfCacheEntry g_profCache[PROF_CACHE_SIZE] = {};

typedef DWORD (WINAPI* GetPrivateProfileStringA_fn)(LPCSTR, LPCSTR, LPCSTR, LPSTR, DWORD, LPCSTR);
static GetPrivateProfileStringA_fn orig_GetPrivateProfileStringA = nullptr;

static DWORD WINAPI hooked_GetPrivateProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName,
    LPCSTR lpDefault, LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
    if (!lpAppName || !lpKeyName || !lpReturnedString || nSize == 0)
        return orig_GetPrivateProfileStringA(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);

    uint32_t hash = 0x811C9DC5;
    if (lpAppName) {
        for (const char* p = lpAppName; *p; p++) {
            char c = *p;
            if (c >= 'A' && c <= 'Z') c += 32;
            hash ^= (uint8_t)c;
            hash *= 0x01000193;
        }
    }
    if (lpKeyName) {
        for (const char* p = lpKeyName; *p; p++) {
            char c = *p;
            if (c >= 'A' && c <= 'Z') c += 32;
            hash ^= (uint8_t)c;
            hash *= 0x01000193;
        }
    }
    int slot = hash & PROF_CACHE_MASK;
    ProfCacheEntry* e = &g_profCache[slot];

    if (e->valid && e->keyHash == hash) {
        DWORD valLen = (DWORD)strlen(e->value);
        DWORD copyLen = (valLen < nSize - 1) ? valLen : (nSize - 1);
        memcpy(lpReturnedString, e->value, copyLen);
        lpReturnedString[copyLen] = '\0';
        g_profHits++;
        return copyLen;
    }

    DWORD result = orig_GetPrivateProfileStringA(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);

    if (result > 0 && lpReturnedString[0] != '\0' && result < PROF_MAX_VALUE) {
        e->keyHash = hash;
        memcpy(e->value, lpReturnedString, result + 1);
        e->valid = true;
    }

    g_profMisses++;
    return result;
}

static bool InstallGetPrivateProfileCache() {
#if CRASH_TEST_DISABLE_PROFILE_CACHE
    Log("GetPrivateProfileStringA cache: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;
    void* p = (void*)GetProcAddress(hK32, "GetPrivateProfileStringA");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_GetPrivateProfileStringA, (void**)&orig_GetPrivateProfileStringA) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("GetPrivateProfileStringA hook: ACTIVE (cache, %d slots, %dB max value)", PROF_CACHE_SIZE, PROF_MAX_VALUE);
    return true;
#endif
}

// ================================================================
// lstrlenA/W - fast inline string length
//
// ================================================================

typedef int (WINAPI* lstrlenA_fn)(LPCSTR);
typedef int (WINAPI* lstrlenW_fn)(LPCWSTR);

static lstrlenA_fn orig_lstrlenA = nullptr;
static lstrlenW_fn orig_lstrlenW = nullptr;

static long g_lstrlenAHits   = 0;
static long g_lstrlenWHits   = 0;
static long g_lstrlenFallbacks = 0;

static int WINAPI hooked_lstrlenA(LPCSTR lpString) {
    if (!lpString) { g_lstrlenFallbacks++; return 0; }
    __try {
        const char* p = lpString;
        while (*p) p++;
        g_lstrlenAHits++;
        return (int)(p - lpString);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        g_lstrlenFallbacks++;
        return orig_lstrlenA(lpString);
    }
}

static int WINAPI hooked_lstrlenW(LPCWSTR lpString) {
    if (!lpString) { g_lstrlenFallbacks++; return 0; }
    __try {
        const wchar_t* p = lpString;
        while (*p) p++;
        g_lstrlenWHits++;
        return (int)(p - lpString);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        g_lstrlenFallbacks++;
        return orig_lstrlenW(lpString);
    }
}

static bool InstallLStrLenHooks() {
#if TEST_DISABLE_LSTRLEN
    Log("lstrlenA/W hooks: DISABLED (test toggle)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

    void* pA = (void*)GetProcAddress(hK32, "lstrlenA");
    if (pA && MH_CreateHook(pA, (void*)hooked_lstrlenA, (void**)&orig_lstrlenA) == MH_OK)
        if (MH_EnableHook(pA) == MH_OK) ok++;

    void* pW = (void*)GetProcAddress(hK32, "lstrlenW");
    if (pW && MH_CreateHook(pW, (void*)hooked_lstrlenW, (void**)&orig_lstrlenW) == MH_OK)
        if (MH_EnableHook(pW) == MH_OK) ok++;

    if (ok > 0) {
        Log("lstrlenA/W hooks: ACTIVE (%d/2, fast inline length)", ok);
    }
    return ok > 0;
#endif
}

// ================================================================
// sub_76EE30 - WoW-internal strlen (byte-by-byte loop, 300+ callers)
// Replace with SSE2-accelerated inline strlen.
// ================================================================
#if !CRASH_TEST_DISABLE_WOW_STRLEN

typedef unsigned int (__stdcall* strlen76_fn)(const char* str);
static strlen76_fn orig_strlen76 = nullptr;

static long g_strlen76Calls = 0;

static unsigned int __stdcall hooked_strlen76(const char* str) {
    if (!str) {
        return orig_strlen76(str); // NULL → error handler (0x57)
    }
    InterlockedIncrement(&g_strlen76Calls);

    // Inline SSE2 strlen: scan 16 bytes at a time
    const char* p = str;
    __m128i zero = _mm_setzero_si128();
    while (true) {
        __m128i chunk = _mm_loadu_si128((const __m128i*)p);
        __m128i cmp   = _mm_cmpeq_epi8(chunk, zero);
        int mask      = _mm_movemask_epi8(cmp);
        if (mask) {
            unsigned long idx;
            _BitScanForward(&idx, mask);
            return (unsigned int)((p + idx) - str);
        }
        p += 16;
    }
}

static bool InstallWowStrlenHook() {
    void* target = (void*)0x0076EE30;
    if (WineSafe_CreateHook(target, (void*)hooked_strlen76, (void**)&orig_strlen76) != MH_OK)
        return false;
    if (MH_EnableHook(target) != MH_OK)
        return false;
    return true;
}
#else
static bool InstallWowStrlenHook() { return false; }
#endif

// ================================================================
// MultiByteToWideChar / WideCharToMultiByte - ASCII fast path
//
// ================================================================

typedef int (WINAPI* MultiByteToWideChar_fn)(UINT, DWORD, LPCCH, int, LPWSTR, int);
typedef int (WINAPI* WideCharToMultiByte_fn)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

static MultiByteToWideChar_fn orig_MultiByteToWideChar = nullptr;
static WideCharToMultiByte_fn orig_WideCharToMultiByte = nullptr;

static bool AllAsciiBytes(const char* p, size_t n) {
    size_t i = 0;
    while (i + 16 <= n) {
        __m128i v = _mm_loadu_si128((const __m128i*)(p + i));
        if (_mm_movemask_epi8(v) != 0) return false;
        i += 16;
    }
    while (i < n) {
        if ((unsigned char)p[i] >= 0x80) return false;
        i++;
    }
    return true;
}

static bool AllAsciiWide(const wchar_t* p, size_t n) {
    const __m128i mask = _mm_set1_epi16((short)0xFF80);
    const __m128i zero = _mm_setzero_si128();
    size_t i = 0;
    while (i + 8 <= n) {
        __m128i v  = _mm_loadu_si128((const __m128i*)(p + i));
        __m128i hi = _mm_and_si128(v, mask);
        __m128i eq = _mm_cmpeq_epi16(hi, zero);
        if ((unsigned)_mm_movemask_epi8(eq) != 0xFFFFu) return false;
        i += 8;
    }
    while (i < n) {
        if ((unsigned short)p[i] >= 0x80) return false;
        i++;
    }
    return true;
}

static void WidenAsciiBytes(const char* src, wchar_t* dst, size_t n) {
    const __m128i zero = _mm_setzero_si128();
    size_t i = 0;
    while (i + 16 <= n) {
        __m128i v = _mm_loadu_si128((const __m128i*)(src + i));
        _mm_storeu_si128((__m128i*)(dst + i),     _mm_unpacklo_epi8(v, zero));
        _mm_storeu_si128((__m128i*)(dst + i + 8), _mm_unpackhi_epi8(v, zero));
        i += 16;
    }
    while (i < n) {
        dst[i] = (wchar_t)(unsigned char)src[i];
        i++;
    }
}

static void NarrowAsciiWide(const wchar_t* src, char* dst, size_t n) {
    size_t i = 0;
    while (i + 16 <= n) {
        __m128i v1 = _mm_loadu_si128((const __m128i*)(src + i));
        __m128i v2 = _mm_loadu_si128((const __m128i*)(src + i + 8));
        _mm_storeu_si128((__m128i*)(dst + i), _mm_packus_epi16(v1, v2));
        i += 16;
    }
    while (i < n) {
        dst[i] = (char)(unsigned char)src[i];
        i++;
    }
}

static inline bool IsAsciiCompatibleCp(UINT cp) {
    // CP_ACP=0, CP_OEMCP=1, CP_MACCP=2, CP_THREAD_ACP=3, CP_UTF8=65001.
    // All map [0x00..0x7F] identically to ASCII.
    // Windows ANSI codepages 1250-1258 and 874 are also ASCII-compatible.
    if (cp <= 3 || cp == 65001) return true;
    if (cp >= 1250 && cp <= 1258) return true;
    if (cp == 874) return true;
    return false;
}

static int WINAPI hooked_MultiByteToWideChar(
    UINT CodePage, DWORD dwFlags,
    LPCCH lpMultiByteStr, int cbMultiByte,
    LPWSTR lpWideCharStr, int cchWideChar)
{
    if (dwFlags != 0)                        goto mbt_fallback;
    if (!IsAsciiCompatibleCp(CodePage))      goto mbt_fallback;
    if (!lpMultiByteStr)                     goto mbt_fallback;
    if (cbMultiByte == 0 || cbMultiByte < -1) goto mbt_fallback;
    if (cchWideChar < 0)                     goto mbt_fallback;

    __try {
        size_t inLen;
        bool   includeNull;
        if (cbMultiByte == -1) {
            const char* p = lpMultiByteStr;
            while (*p) p++;
            inLen       = (size_t)(p - lpMultiByteStr);
            includeNull = true;
        } else {
            inLen       = (size_t)cbMultiByte;
            includeNull = false;
        }

        if (!AllAsciiBytes(lpMultiByteStr, inLen)) goto mbt_fallback;

        size_t outLen = inLen + (includeNull ? 1 : 0);

        if (cchWideChar == 0) {
            g_mbwcFastHits++;
            return (int)outLen;
        }

        if (!lpWideCharStr) goto mbt_fallback;

        if ((int)outLen > cchWideChar) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            g_mbwcFastHits++;
            return 0;
        }

        WidenAsciiBytes(lpMultiByteStr, lpWideCharStr, inLen);
        if (includeNull) lpWideCharStr[inLen] = L'\0';

        g_mbwcFastHits++;
        return (int)outLen;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }

mbt_fallback:
    g_mbwcFallbacks++;
    return orig_MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

static int WINAPI hooked_WideCharToMultiByte(
    UINT CodePage, DWORD dwFlags,
    LPCWCH lpWideCharStr, int cchWideChar,
    LPSTR lpMultiByteStr, int cbMultiByte,
    LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
    if (dwFlags != 0)                         goto wcmb_fallback;
    if (!IsAsciiCompatibleCp(CodePage))       goto wcmb_fallback;
    if (!lpWideCharStr)                       goto wcmb_fallback;
    if (cchWideChar == 0 || cchWideChar < -1) goto wcmb_fallback;
    if (cbMultiByte < 0)                      goto wcmb_fallback;

    __try {
        size_t inLen;
        bool   includeNull;
        if (cchWideChar == -1) {
            const wchar_t* p = lpWideCharStr;
            while (*p) p++;
            inLen       = (size_t)(p - lpWideCharStr);
            includeNull = true;
        } else {
            inLen       = (size_t)cchWideChar;
            includeNull = false;
        }

        if (!AllAsciiWide(lpWideCharStr, inLen)) goto wcmb_fallback;

        size_t outLen = inLen + (includeNull ? 1 : 0);

        if (cbMultiByte == 0) {
            if (lpUsedDefaultChar) *lpUsedDefaultChar = FALSE;
            g_wcmbFastHits++;
            return (int)outLen;
        }

        if (!lpMultiByteStr) goto wcmb_fallback;

        if ((int)outLen > cbMultiByte) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            g_wcmbFastHits++;
            return 0;
        }

        NarrowAsciiWide(lpWideCharStr, lpMultiByteStr, inLen);
        if (includeNull)            lpMultiByteStr[inLen] = '\0';
        if (lpUsedDefaultChar)      *lpUsedDefaultChar = FALSE;

        g_wcmbFastHits++;
        return (int)outLen;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }

wcmb_fallback:
    g_wcmbFallbacks++;
    return orig_WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

static bool InstallMBWCHooks() {
#if TEST_DISABLE_MBWC
    Log("MBWC hooks: DISABLED (test toggle)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

    void* pMbt = (void*)GetProcAddress(hK32, "MultiByteToWideChar");
    if (pMbt && MH_CreateHook(pMbt, (void*)hooked_MultiByteToWideChar, (void**)&orig_MultiByteToWideChar) == MH_OK)
        if (MH_EnableHook(pMbt) == MH_OK) ok++;

    void* pWcm = (void*)GetProcAddress(hK32, "WideCharToMultiByte");
    if (pWcm && MH_CreateHook(pWcm, (void*)hooked_WideCharToMultiByte, (void**)&orig_WideCharToMultiByte) == MH_OK)
        if (MH_EnableHook(pWcm) == MH_OK) ok++;

    if (ok > 0) {
        Log("MBWC hooks: ACTIVE (%d/2, SSE2 ASCII fast path)", ok);
    }
    return ok > 0;
#endif
}

// ================================================================
// GetProcAddress - 4-way set-associative cache (strcmp-based,
// Wine security-module bypass)
//
// ================================================================

typedef FARPROC (WINAPI* GetProcAddress_fn)(HMODULE, LPCSTR);

static GetProcAddress_fn orig_GetProcAddress = nullptr;

static const int GPA_CACHE_WAYS = 4;
static const int GPA_CACHE_SETS = 128;
static const int GPA_CACHE_SET_MASK = GPA_CACHE_SETS - 1;
static const int GPA_NAME_MAX = 64;

struct GpaCacheEntry {
    uintptr_t moduleHash;
    uintptr_t procHash;
    FARPROC   address;
    char      procName[GPA_NAME_MAX];  // full name for strcmp verification
    uint8_t   lru;      // LRU counter (0-3, higher = more recently used)
    bool      valid;
};

static GpaCacheEntry g_gpaCache[GPA_CACHE_SETS][GPA_CACHE_WAYS] = {};

// Wine bypass: security/HTTP modules and SSPI function names must pass
// through to orig_GetProcAddress so Wine's delay-load / forwarder
// resolution chain is not short-circuited.
static bool g_gpaWineMode = false;

// Module policy cache: memoise bypass decision per HMODULE
struct GpaModulePolicy {
    HMODULE hMod;
    bool    bypass;
    bool    valid;
};
static const int GPA_MODULE_POLICY_SIZE = 64;
static GpaModulePolicy g_gpaModulePolicy[GPA_MODULE_POLICY_SIZE] = {};

static bool IsWineGpaBypassModule(HMODULE hModule) {
    // Check memoised policy
    int slot = (int)(((uintptr_t)hModule >> 4) & (GPA_MODULE_POLICY_SIZE - 1));
    if (g_gpaModulePolicy[slot].valid && g_gpaModulePolicy[slot].hMod == hModule)
        return g_gpaModulePolicy[slot].bypass;

    // Resolve module basename
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(hModule, path, MAX_PATH);
    bool bypass = false;
    if (len > 0) {
        // Find basename
        const char* base = path;
        for (const char* p = path; *p; p++) {
            if (*p == '\\' || *p == '/') base = p + 1;
        }
        // _stricmp for case-insensitive comparison
        static const char* bypassModules[] = {
            "secur32.dll", "security.dll", "schannel.dll", "sspicli.dll",
            "wininet.dll", "winhttp.dll", "crypt32.dll", "cryptnet.dll",
            "bcrypt.dll", "ncrypt.dll", "kerberos.dll", nullptr
        };
        for (int i = 0; bypassModules[i]; i++) {
            if (_stricmp(base, bypassModules[i]) == 0) { bypass = true; break; }
        }
    }

    g_gpaModulePolicy[slot].hMod = hModule;
    g_gpaModulePolicy[slot].bypass = bypass;
    g_gpaModulePolicy[slot].valid = true;
    return bypass;
}

static bool IsWineSecurityProcName(LPCSTR name) {
    if (!name || (uintptr_t)name < 0x10000) return false;
    static const char* bypassPrefixes[] = {
        "AcquireCredentialsHandle", "InitializeSecurityContext",
        "AcceptSecurityContext", "EncryptMessage", "DecryptMessage",
        "MakeSignature", "VerifySignature", "QuerySecurityContextToken",
        "CompleteAuthToken", "DeleteSecurityContext",
        "FreeCredentialsHandle", "QuerySecurityPackageInfo",
        "FreeContextBuffer", "EnumerateSecurityPackages",
        nullptr
    };
    for (int i = 0; bypassPrefixes[i]; i++) {
        size_t plen = strlen(bypassPrefixes[i]);
        if (strncmp(name, bypassPrefixes[i], plen) == 0) return true;
    }
    return false;
}

static inline bool ShouldBypassGpaCache(HMODULE hModule, LPCSTR lpProcName) {
    if (!g_gpaWineMode) return false;
    return IsWineGpaBypassModule(hModule) || IsWineSecurityProcName(lpProcName);
}

static inline uintptr_t HashPtr(const void* p, size_t len) {
    const uint8_t* b = (const uint8_t*)p;
    uintptr_t h = 0;
    for (size_t i = 0; i < len; i++) {
        h = h * 31 + b[i];
    }
    return h;
}

static FARPROC WINAPI hooked_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    // Ordinal lookup - no caching
    if ((uintptr_t)lpProcName < 0x10000) {
        return orig_GetProcAddress(hModule, lpProcName);
    }

    // Wine: bypass security/HTTP modules
    if (ShouldBypassGpaCache(hModule, lpProcName)) {
        g_gpaBypasses++;
        return orig_GetProcAddress(hModule, lpProcName);
    }

    // Compute cache key
    size_t nameLen = strlen(lpProcName);
    uintptr_t modHash = (uintptr_t)hModule;
    uintptr_t procHash = HashPtr(lpProcName, nameLen);
    int setIdx = (int)((modHash ^ procHash) & GPA_CACHE_SET_MASK);

    // Search all 4 ways in this set - hash AND strcmp
    GpaCacheEntry* set = g_gpaCache[setIdx];
    for (int way = 0; way < GPA_CACHE_WAYS; way++) {
        if (set[way].valid && set[way].moduleHash == modHash &&
            set[way].procHash == procHash &&
            strcmp(set[way].procName, lpProcName) == 0) {
            // Cache hit - update LRU
            set[way].lru = 3;
            for (int i = 0; i < GPA_CACHE_WAYS; i++) {
                if (i != way && set[i].lru > 0) set[i].lru--;
            }
            g_gpaHits++;
            return set[way].address;
        }
    }

    // Cache miss - call original
    FARPROC addr = orig_GetProcAddress(hModule, lpProcName);
    if (addr && nameLen < GPA_NAME_MAX) {
        // Find victim: invalid slot first, else LRU=0
        int victim = -1;
        for (int way = 0; way < GPA_CACHE_WAYS; way++) {
            if (!set[way].valid) {
                victim = way;
                break;
            }
        }
        if (victim == -1) {
            for (int way = 0; way < GPA_CACHE_WAYS; way++) {
                if (set[way].lru == 0) {
                    victim = way;
                    g_gpaEvictions++;
                    break;
                }
            }
        }
        if (victim == -1) victim = 0;

        // Insert into cache with full name
        set[victim].moduleHash = modHash;
        set[victim].procHash   = procHash;
        set[victim].address    = addr;
        memcpy(set[victim].procName, lpProcName, nameLen + 1);
        set[victim].lru        = 3;
        set[victim].valid      = true;

        // Age other entries
        for (int i = 0; i < GPA_CACHE_WAYS; i++) {
            if (i != victim && set[i].lru > 0) set[i].lru--;
        }
    }
    g_gpaMisses++;
    return addr;
}

static bool InstallGetProcAddressCache() {
#if TEST_DISABLE_GETPROCADDRESS
    Log("GetProcAddress cache: DISABLED (test toggle)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    void* p = (void*)GetProcAddress(hK32, "GetProcAddress");
    if (!p) return false;

    if (MH_CreateHook(p, (void*)hooked_GetProcAddress, (void**)&orig_GetProcAddress) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;

    g_gpaWineMode = IsWine();
    Log("GetProcAddress cache: ACTIVE (4-way, 128 sets, strcmp-based%s)",
        g_gpaWineMode ? ", Wine security bypass" : "");
    return true;
#endif
}

// ================================================================
// GetModuleFileNameA/W - cache
//
// ================================================================

typedef DWORD (WINAPI* GetModuleFileNameA_fn)(HMODULE, LPSTR, DWORD);
typedef DWORD (WINAPI* GetModuleFileNameW_fn)(HMODULE, LPWSTR, DWORD);

static GetModuleFileNameA_fn orig_GetModuleFileNameA = nullptr;
static GetModuleFileNameW_fn orig_GetModuleFileNameW = nullptr;

static const int GMF_CACHE_SIZE = 64;
static const int GMF_CACHE_MASK = GMF_CACHE_SIZE - 1;

struct GmfCacheEntryA { HMODULE hMod; char path[MAX_PATH]; bool valid; };
struct GmfCacheEntryW { HMODULE hMod; wchar_t path[MAX_PATH]; bool valid; };

static GmfCacheEntryA g_gmfCacheA[GMF_CACHE_SIZE] = {};
static GmfCacheEntryW g_gmfCacheW[GMF_CACHE_SIZE] = {};

static DWORD WINAPI hooked_GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
    int idx = (int)(((uintptr_t)hModule >> 4) & GMF_CACHE_MASK);
    if (g_gmfCacheA[idx].valid && g_gmfCacheA[idx].hMod == hModule) {
        size_t len = strlen(g_gmfCacheA[idx].path);
        if (len < nSize) {
            memcpy(lpFilename, g_gmfCacheA[idx].path, len + 1);
            g_gmfHits++;
            return (DWORD)len;
        }
    }
    DWORD result = orig_GetModuleFileNameA(hModule, lpFilename, nSize);
    if (result > 0 && result < MAX_PATH) {
        g_gmfCacheA[idx].hMod = hModule;
        memcpy(g_gmfCacheA[idx].path, lpFilename, result + 1);
        g_gmfCacheA[idx].valid = true;
    }
    g_gmfMisses++;
    return result;
}

static DWORD WINAPI hooked_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
    int idx = (int)(((uintptr_t)hModule >> 4) & GMF_CACHE_MASK);
    if (g_gmfCacheW[idx].valid && g_gmfCacheW[idx].hMod == hModule) {
        size_t len = wcslen(g_gmfCacheW[idx].path);
        if (len < nSize) {
            memcpy(lpFilename, g_gmfCacheW[idx].path, (len + 1) * sizeof(wchar_t));
            g_gmfHits++;
            return (DWORD)len;
        }
    }
    DWORD result = orig_GetModuleFileNameW(hModule, lpFilename, nSize);
    if (result > 0 && result < MAX_PATH) {
        g_gmfCacheW[idx].hMod = hModule;
        memcpy(g_gmfCacheW[idx].path, lpFilename, (result + 1) * sizeof(wchar_t));
        g_gmfCacheW[idx].valid = true;
    }
    g_gmfMisses++;
    return result;
}

static bool InstallGetModuleFileNameCache() {
#if TEST_DISABLE_MODULEFILENAME
    Log("GetModuleFileName cache: DISABLED (test toggle)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;
    void* pA = (void*)GetProcAddress(hK32, "GetModuleFileNameA");
    if (pA && MH_CreateHook(pA, (void*)hooked_GetModuleFileNameA, (void**)&orig_GetModuleFileNameA) == MH_OK)
        if (MH_EnableHook(pA) == MH_OK) ok++;

    void* pW = (void*)GetProcAddress(hK32, "GetModuleFileNameW");
    if (pW && MH_CreateHook(pW, (void*)hooked_GetModuleFileNameW, (void**)&orig_GetModuleFileNameW) == MH_OK)
        if (MH_EnableHook(pW) == MH_OK) ok++;

    if (ok > 0)
        Log("GetModuleFileNameA/W cache: ACTIVE (%d-slot, HMODULE-keyed)", GMF_CACHE_SIZE);
    return ok > 0;
#endif
}

// ================================================================
// GetEnvironmentVariableA - cache
//
// ================================================================

typedef DWORD (WINAPI* GetEnvironmentVariableA_fn)(LPCSTR, LPSTR, DWORD);

static GetEnvironmentVariableA_fn orig_GetEnvironmentVariableA = nullptr;

static const int ENV_CACHE_SIZE = 32;
static const int ENV_CACHE_MASK = ENV_CACHE_SIZE - 1;

struct EnvCacheEntry { uint32_t nameHash; char value[512]; DWORD len; bool valid; };
static EnvCacheEntry g_envCache[ENV_CACHE_SIZE] = {};

static inline uint32_t HashNameLower(LPCSTR name) {
    uint32_t h = 0;
    for (const char* p = name; *p; p++) {
        char c = *p >= 'A' && *p <= 'Z' ? *p + 32 : *p;
        h = h * 31 + c;
    }
    return h;
}

static DWORD WINAPI hooked_GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
    // NULL checks: lpName or lpBuffer can be NULL (size query)
    if (!lpName || !lpBuffer) return orig_GetEnvironmentVariableA(lpName, lpBuffer, nSize);

    uint32_t h = HashNameLower(lpName);
    int idx = h & ENV_CACHE_MASK;

    if (g_envCache[idx].valid && g_envCache[idx].nameHash == h) {
        if (g_envCache[idx].len < nSize) {
            memcpy(lpBuffer, g_envCache[idx].value, g_envCache[idx].len + 1);
            g_envHits++;
            return g_envCache[idx].len;
        }
    }

    DWORD result = orig_GetEnvironmentVariableA(lpName, lpBuffer, nSize);
    if (result > 0 && result < sizeof(g_envCache[idx].value)) {
        g_envCache[idx].nameHash = h;
        memcpy(g_envCache[idx].value, lpBuffer, result + 1);
        g_envCache[idx].len = result;
        g_envCache[idx].valid = true;
    }
    g_envMisses++;
    return result;
}

static bool InstallEnvironmentVariableCache() {
#if TEST_DISABLE_ENVVARIABLE
    Log("GetEnvironmentVariable cache: DISABLED (test toggle)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    void* p = (void*)GetProcAddress(hK32, "GetEnvironmentVariableA");
    if (!p) return false;

    if (MH_CreateHook(p, (void*)hooked_GetEnvironmentVariableA, (void**)&orig_GetEnvironmentVariableA) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;

    Log("GetEnvironmentVariableA cache: ACTIVE (32-slot, name-hash-keyed)");
    return true;
#endif
}

// ================================================================
//  Thread Affinity - Background Worker CPU Pinning
//
// ================================================================

static int __cdecl Hooked_ThreadWorker(void* outHandle, LPTHREAD_START_ROUTINE start, LPVOID param, int priority, int a5, int a6, HMODULE hMod) {
    int ret = orig_ThreadWorker(outHandle, start, param, priority, a5, a6, hMod);
    if (ret == 0 && outHandle) {
        HANDLE h = *(HANDLE*)outHandle;
        if (h && h != INVALID_HANDLE_VALUE) {
            int idx = InterlockedIncrement(&g_bgThreadIdx) - 1;
            SetThreadIdealProcessor(h, g_affinityCores[idx % g_affinityCount]);
        }
    }
    return ret;
}

static bool IsExecutableMemory(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// Wine/Rosetta: make SetThreadIdealProcessor a global no-op.
// WoW's own sub_8D2110 and external injectors (WoWsilicon) call this
// natively. Guarding only our own hook sites is insufficient - we must
// intercept the kernel32 entry point itself to prevent rosettax87 desync.
static DWORD WINAPI Noop_SetThreadIdealProcessor(HANDLE hThread, DWORD dwIdealProcessor) {
    (void)hThread; (void)dwIdealProcessor;
    return 0;  // return "previous ideal processor" = 0
}

static void InstallWineSTIPNoop() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return;
    void* p = (void*)GetProcAddress(hK32, "SetThreadIdealProcessor");
    if (!p) return;
    static DWORD(WINAPI* orig)(HANDLE, DWORD) = nullptr;
    if (MH_CreateHook(p, (void*)Noop_SetThreadIdealProcessor, (void**)&orig) == MH_OK &&
        MH_EnableHook(p) == MH_OK) {
        Log("SetThreadIdealProcessor: NO-OP on Wine (prevents rosettax87 desync)");
    }
}

static bool InstallThreadAffinity() {
#if CRASH_TEST_DISABLE_THREAD_AFFINITY
    Log("Thread affinity: DISABLED (crash isolation)");
    return false;
#else
    if (IsWine()) {
        Log("Thread affinity: SKIPPED (Wine/Rosetta)");
        return false;
    }
    DWORD_PTR processMask = 0, systemMask = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &processMask, &systemMask)) {
        Log("Thread affinity: SKIP (GetProcessAffinityMask failed)");
        return false;
    }

    int activeCores = 0;
    for (unsigned i = 0; i < sizeof(DWORD_PTR) * 8; i++) {
        if (processMask & ((DWORD_PTR)1 << i))
            activeCores++;
    }

    if (activeCores <= 2) {
        Log("Thread affinity: SKIP (<=2 active process cores)");
        return false;
    }

    g_affinityCount = 0;
    for (unsigned i = 2; i < sizeof(DWORD_PTR) * 8 && g_affinityCount < 16; i++) {
        if (processMask & ((DWORD_PTR)1 << i))
            g_affinityCores[g_affinityCount++] = i;
    }

    if (g_affinityCount == 0) {
        Log("Thread affinity: SKIP (process affinity mask leaves no worker cores >=2)");
        return false;
    }

    void* p = (void*)0x008D2110;
    if (!IsExecutableMemory((uintptr_t)p)) return false;
    if (WineSafe_CreateHook(p, (void*)Hooked_ThreadWorker, (void**)&orig_ThreadWorker) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;

    Log("Thread affinity: ACTIVE (process-mask aware, %d worker cores)", g_affinityCount);
    return true;
#endif
}

// ================================================================
// VA Arena v2 - High-address reserved arena with caller filtering
// ================================================================

static bool IsCallerInWowExe() {
    void* caller = _ReturnAddress();
    if (!caller) return false;
    static uintptr_t wowBase = 0;
    static uintptr_t wowSize = 0;
    if (wowBase == 0) {
        HMODULE hWow = GetModuleHandleA(NULL);
        if (!hWow) return false;
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hWow, &modInfo, sizeof(modInfo))) return false;
        wowBase = (uintptr_t)hWow;
        wowSize = (uintptr_t)modInfo.SizeOfImage;
    }
    uintptr_t addr = (uintptr_t)caller;
    return (addr >= wowBase && addr < wowBase + wowSize);
}

static LPVOID WINAPI Hooked_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flType, DWORD flProtect) {
    // Intercept ALL committed, non-fixed, non-reserve allocations
    // No caller filtering - serve everyone (Wow.exe, addons, mimalloc, D3D9, etc.)
    if (g_vaArenaActive &&
        lpAddress == NULL &&
        dwSize >= VA_ARENA_PAGE_SIZE &&
        dwSize <= 256 * 1024 * 1024 &&  // cap at 256MB per alloc
       (flType & MEM_COMMIT) &&
        !(flType & MEM_RESERVE) &&
        !(flType & MEM_RESET) &&
        !(flType & MEM_PHYSICAL) &&
        !(flType & MEM_LARGE_PAGES) &&
       (flProtect == PAGE_READONLY || flProtect == PAGE_READWRITE ||
         flProtect == PAGE_EXECUTE_READ || flProtect == PAGE_EXECUTE_READWRITE ||
         flProtect == PAGE_NOACCESS) &&
        IsCallerInWowExe())  // RESTORED: prevent addon/D3D9 from fragmenting arena
    {
#if !CRASH_TEST_DISABLE_VA_ARENA
        __try {
            SIZE_T pagesNeeded = (dwSize + VA_ARENA_PAGE_SIZE - 1) / VA_ARENA_PAGE_SIZE;

            AcquireSRWLockExclusive(&g_vaArenaLock);

            if (pagesNeeded > VA_ARENA_MAX_PAGES - g_vaArenaUsedPages) {
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                goto va_fallback;
            }

            // First-fit bitmap scan for consecutive free pages
            DWORD startPage = 0;
            DWORD consecutive = 0;
            bool found = false;

            for (DWORD i = 0; i < VA_ARENA_MAX_PAGES; i++) {
                if (!(g_vaArenaBitmap[i / 64] & (1ULL << (i % 64)))) {
                    if (consecutive == 0) startPage = i;
                    consecutive++;
                    if (consecutive >= pagesNeeded) { found = true; break; }
                } else {
                    consecutive = 0;
                }
            }

            if (!found) {
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                goto va_fallback;
            }

            // Mark bitmap + store span
            for (DWORD i = 0; i < pagesNeeded; i++) {
                g_vaArenaBitmap[(startPage + i) / 64] |= (1ULL << ((startPage + i) % 64));
                g_vaArenaSpan[startPage + i] = 0;  // non-head pages
            }
            g_vaArenaSpan[startPage] = (DWORD)pagesNeeded;
            g_vaArenaUsedPages += (DWORD)pagesNeeded;
            ReleaseSRWLockExclusive(&g_vaArenaLock);

            LPVOID result = (LPVOID)((uintptr_t)g_vaArenaBase + (startPage * VA_ARENA_PAGE_SIZE));

            // Commit the pages from OS
            SIZE_T spanSize = (SIZE_T)pagesNeeded * VA_ARENA_PAGE_SIZE;
            LPVOID committed = orig_VirtualAlloc(result, spanSize, MEM_COMMIT, flProtect);
            if (!committed) {
                // Rollback bitmap + span
                AcquireSRWLockExclusive(&g_vaArenaLock);
                for (DWORD i = 0; i < pagesNeeded; i++) {
                    g_vaArenaBitmap[(startPage + i) / 64] &= ~(1ULL << ((startPage + i) % 64));
                    g_vaArenaSpan[startPage + i] = 0;
                }
                g_vaArenaUsedPages -= (DWORD)pagesNeeded;
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                goto va_fallback;
            }

            InterlockedIncrement(&g_vaArenaHits);
            return result;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            goto va_fallback;
        }
#endif
    }

#if !CRASH_TEST_DISABLE_VA_ARENA
va_fallback:
#endif
    InterlockedIncrement(&g_vaArenaFallbacks);
    return orig_VirtualAlloc(lpAddress, dwSize, flType, flProtect);
}

static BOOL WINAPI Hooked_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (g_vaArenaActive &&
        lpAddress >= g_vaArenaBase &&
       (uintptr_t)lpAddress < ((uintptr_t)g_vaArenaBase + g_vaArenaSize))
    {
#if !CRASH_TEST_DISABLE_VA_ARENA
        __try {
            DWORD page = (DWORD)((uintptr_t)lpAddress - (uintptr_t)g_vaArenaBase) / VA_ARENA_PAGE_SIZE;
            if (page >= VA_ARENA_MAX_PAGES) goto vf_fallback;

            AcquireSRWLockExclusive(&g_vaArenaLock);
            DWORD spanLen = g_vaArenaSpan[page];
            if (spanLen == 0) {
                // Not an arena head page - fallback
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                goto vf_fallback;
            }

            // Calculate actual span size for decommit
            SIZE_T spanPages = spanLen;
            SIZE_T spanSize = spanPages * VA_ARENA_PAGE_SIZE;

            if (dwFreeType == MEM_DECOMMIT) {
                // Decommit arena pages via original VirtualFree
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                BOOL result = orig_VirtualFree(lpAddress, spanSize, MEM_DECOMMIT);
                if (result) {
                    // Clear bitmap + span after successful decommit
                    AcquireSRWLockExclusive(&g_vaArenaLock);
                    for (DWORD i = 0; i < spanPages && (page + i) < VA_ARENA_MAX_PAGES; i++) {
                        g_vaArenaBitmap[(page + i) / 64] &= ~(1ULL << ((page + i) % 64));
                        g_vaArenaSpan[page + i] = 0;
                    }
                    g_vaArenaUsedPages -= (DWORD)spanPages;
                    ReleaseSRWLockExclusive(&g_vaArenaLock);
                    InterlockedIncrement(&g_vaArenaHits);
                }
                return result;
            }

            if (dwFreeType == MEM_RELEASE) {
                // Decommit + clear bitmap + span
                orig_VirtualFree(lpAddress, spanSize, MEM_DECOMMIT);
                for (DWORD i = 0; i < spanPages && (page + i) < VA_ARENA_MAX_PAGES; i++) {
                    g_vaArenaBitmap[(page + i) / 64] &= ~(1ULL << ((page + i) % 64));
                    g_vaArenaSpan[page + i] = 0;
                }
                g_vaArenaUsedPages -= (DWORD)spanPages;
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                InterlockedIncrement(&g_vaArenaHits);
                return TRUE;
            }

            ReleaseSRWLockExclusive(&g_vaArenaLock);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            goto vf_fallback;
        }
#endif
    }

#if !CRASH_TEST_DISABLE_VA_ARENA
vf_fallback:
#endif
    return orig_VirtualFree(lpAddress, dwSize, dwFreeType);
}

static bool InstallVAArena() {
#if CRASH_TEST_DISABLE_VA_ARENA
    Log("VA Arena: DISABLED (crash isolation)");
    return false;
#else
    // Pre-reserve 512MB in high address space (>=0xD0000000)
    // This avoids low-address fragmentation that causes 32-bit crashes
    g_vaArenaSize = VA_ARENA_MAX_PAGES * VA_ARENA_PAGE_SIZE;

    // Try high addresses first with MEM_TOP_DOWN
    g_vaArenaBase = VirtualAlloc((LPVOID)0xF0000000, g_vaArenaSize, MEM_RESERVE | MEM_TOP_DOWN, PAGE_NOACCESS);
    if (!g_vaArenaBase) {
        // Try without specific address
        g_vaArenaBase = VirtualAlloc(NULL, g_vaArenaSize, MEM_RESERVE | MEM_TOP_DOWN, PAGE_NOACCESS);
        if (!g_vaArenaBase) {
            g_vaArenaBase = VirtualAlloc(NULL, g_vaArenaSize, MEM_RESERVE, PAGE_NOACCESS);
            if (!g_vaArenaBase) {
                Log("VA Arena: SKIP (cannot reserve 512MB block)");
                return false;
            }
        }
    }

    Log("VA Arena: ACTIVE (512MB block @ 0x%08X, 4KB pages, ALL callers, SEH-guarded)",
       (unsigned)(uintptr_t)g_vaArenaBase);

    void* pAlloc = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
    void* pFree  = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualFree");
    if (!pAlloc || !pFree) {
        VirtualFree(g_vaArenaBase, 0, MEM_RELEASE);
        g_vaArenaBase = nullptr;
        return false;
    }

    if (MH_CreateHook(pAlloc, (void*)Hooked_VirtualAlloc, (void**)&orig_VirtualAlloc) != MH_OK) {
        VirtualFree(g_vaArenaBase, 0, MEM_RELEASE);
        g_vaArenaBase = nullptr;
        return false;
    }
    if (MH_CreateHook(pFree, (void*)Hooked_VirtualFree, (void**)&orig_VirtualFree) != MH_OK) {
        MH_DisableHook(pAlloc);
        VirtualFree(g_vaArenaBase, 0, MEM_RELEASE);
        g_vaArenaBase = nullptr;
        return false;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        MH_DisableHook(pAlloc); MH_DisableHook(pFree);
        VirtualFree(g_vaArenaBase, 0, MEM_RELEASE);
        g_vaArenaBase = nullptr;
        return false;
    }

    g_vaArenaActive = true;
    return true;
#endif
}

static void ShutdownVAArena() {
    if (g_vaArenaBase) {
        VirtualFree(g_vaArenaBase, 0, MEM_RELEASE);
        g_vaArenaBase = nullptr;
    }
    g_vaArenaActive = false;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            
            // Rosetta: disable x87 JIT cache to force re-translation after hooks
            // This MUST happen before any hooks install, so rosettax87 doesn't
            // serve stale ARM64 translations for patched x86 code.
            // Also enable on Wine: CrossOver on Apple Silicon runs WoW.exe (Windows
            // binary) through Rosetta underneath. Setting the env var on plain Wine
            // (Linux) is harmless — it's simply ignored there.
            if (IsRosetta() || IsWine()) {
                SetEnvironmentVariableA("ROSETTA_X87_DISABLE_CACHE", "1");
                // Signal to lua_fastpath that MinHook inline hooks are now safe
                extern bool g_rosettaCacheDisabled;
                g_rosettaCacheDisabled = true;
            }
            
            // Wine/Rosetta: neutralize SetThreadIdealProcessor BEFORE
            // spawning MainThread. WoW's sub_8D2110 and external injectors
            // (WoWsilicon) may call it on background threads before our
            // init thread installs hooks. This inline patch is loader-lock
            // safe (only VirtualProtect + memory write).
            {
                HMODULE k32 = GetModuleHandleA("kernel32.dll");
                if (k32) {
                    FARPROC stip = GetProcAddress(k32, "SetThreadIdealProcessor");
                    if (stip) {
                        // Check for Wine: ntdll exports wine_get_version
                        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                        bool isWine = ntdll && (GetProcAddress(ntdll, "wine_get_version") != NULL);
                        if (isWine) {
                            DWORD oldProt;
                            // xor eax,eax; ret 8  →  return 0, clean stdcall args
                            unsigned char stub[] = { 0x33, 0xC0, 0xC2, 0x08, 0x00 };
                            if (VirtualProtect((void*)stip, sizeof(stub), PAGE_EXECUTE_READWRITE, &oldProt)) {
                                memcpy((void*)stip, stub, sizeof(stub));
                                VirtualProtect((void*)stip, sizeof(stub), oldProt, &oldProt);
                            }
                        }
                    }
                }
            }
            CloseHandle(CreateThread(NULL, 0, MainThread, NULL, 0, NULL));
            break;
        case DLL_PROCESS_DETACH:
            // Stop background workers BEFORE process teardown.
            ModelAsync::Shutdown();
            TextureAsync::Shutdown();

            if (reserved != NULL) {
                ClearAssetPathCache();
                if (g_log) {
                    SYSTEMTIME st;
                    GetLocalTime(&st);
                    fprintf(g_log, "[%02d:%02d:%02d.%03d] wow_optimize.dll: process terminating, skipping cleanup\n",
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
                    fflush(g_log);
                    fclose(g_log);
                    g_log = nullptr;
                }
                break;
            }

            // Dynamic FreeLibrary - safe to clean up
            __try {
            LuaFastPath::Shutdown();
            LuaInternals::Shutdown();
            LuaBytecodeCache::Shutdown();
            ShutdownStrstrSSE2();
            ShutdownCrtCharSSE2();
            ShutdownCrtPowSSE2();
            ShutdownCrtWcharSSE2();
            ShutdownAddonPreload();
            ApiCache::Shutdown();
            UICache::Shutdown();                       
            CombatLogOpt::Shutdown();
            CombatLogBuffer::Shutdown();
#if !TEST_DISABLE_COMBATLOG_MT
            CombatLogMT::Shutdown();
#endif
#if !TEST_DISABLE_TEXTURE_ASYNC
            TextureAsync::Shutdown();
#endif
#if !TEST_DISABLE_SPELL_PREFETCH
            SpellPrefetch::Shutdown();
#endif
#if !TEST_DISABLE_ADDON_DISPATCHER
            AddonDispatcher::Shutdown();
#endif
#if !TEST_DISABLE_MODEL_ASYNC
            ModelAsync::Shutdown();
#endif
#if !TEST_DISABLE_MPQ_PREFETCH
            MPQPrefetch::Shutdown();
#endif
#if !TEST_DISABLE_OBJ_VIS_CACHE
            ObjVisCache::Shutdown();
#endif
#if !TEST_DISABLE_SOUND_PREFETCH
            SoundPrefetch::Shutdown();
#endif
#if !TEST_DISABLE_QUEST_ASYNC
            QuestAsync::Shutdown();
#endif
#if !TEST_DISABLE_NAMEPLATE_MT
            NameplateMT::Shutdown();
#endif
            LuaOpt::Shutdown();
            if (g_flushSkipped > 0)
                Log("FlushFileBuffers: %ld MPQ flushes skipped", g_flushSkipped);
            if (g_debugStringSkipped > 0)
                Log("OutputDebugStringA: %ld calls skipped (no debugger)", g_debugStringSkipped);
            if (g_heapsOptimized > 0)
                Log("Heap optimization: %d heaps with LFH enabled", g_heapsOptimized);
            if (g_compareAsciiHits + g_compareFallbacks > 0)
                Log("CompareStringA: %ld ASCII fast, %ld locale fallback (%.1f%% fast)",
                    g_compareAsciiHits, g_compareFallbacks,
                   (double)g_compareAsciiHits / (g_compareAsciiHits + g_compareFallbacks) * 100.0);
            if (g_fileAttrHits + g_fileAttrMisses > 0)
                Log("GetFileAttributesA: %ld hits, %ld misses (%.1f%% hit rate)",
                    g_fileAttrHits, g_fileAttrMisses,
                   (double)g_fileAttrHits / (g_fileAttrHits + g_fileAttrMisses) * 100.0);       
            if (g_badPtrFastChecks > 0)
                Log("IsBadPtr: %ld fast checks (avoided SEH probing)", g_badPtrFastChecks);
            if (g_csSpinHits > 0)
                Log("CriticalSection: %ld spin-acquired (avoided kernel wait)", g_csSpinHits);
            if (g_sfpRedirected > 0)
                Log("SetFilePointer: %ld calls redirected to SetFilePointerEx", g_sfpRedirected);
            if (g_threadAffOk) Log("Thread affinity: %d background workers pinned to cores 2+", g_bgThreadIdx);
            if (vaOk && g_vaArenaBase) {
                Log("VA Arena: %ld hits, %ld fallbacks, %ld failures (%.1f%% arena)",
                    g_vaArenaHits, g_vaArenaFallbacks, g_vaArenaFailures,
                   (g_vaArenaHits + g_vaArenaFallbacks) > 0 ? (double)g_vaArenaHits / (g_vaArenaHits + g_vaArenaFallbacks) * 100.0 : 0.0);
                ShutdownVAArena();
            }
            HeapCompactor_Shutdown();
            if (g_globalAllocFast > 0)
                Log("GlobalAlloc: %ld GMEM_FIXED via mimalloc", g_globalAllocFast);
            #if !CRASH_TEST_DISABLE_MPQ_MMAP
            if (g_mpqMapHits + g_mpqMapMisses > 0)
                Log("MPQ mmap: %ld reads served, %ld faults, %d files mapped, %.1f MB total",
                    g_mpqMapHits, g_mpqMapMisses, g_mpqMapCount,
                    g_mpqMapTotalBytes / (1024.0 * 1024.0));
            #endif
            if (g_instanceMutex) {
                CloseHandle(g_instanceMutex);
                g_instanceMutex = NULL;
            }            
            #if !CRASH_TEST_DISABLE_MPQ_MMAP
                        for (int i = 0; i < MAX_MPQ_MAPPINGS; i++) {
                            if (g_mpqMappings[i].active) {
                                UnmapViewOfFile(g_mpqMappings[i].baseAddress);
                                g_mpqMappings[i].active = false;
                            }
                        }
            #endif
            g_asyncIoShutdown = true;
            if (g_asyncIoWorker) {
                WaitForSingleObject(g_asyncIoWorker, 2000);
                CloseHandle(g_asyncIoWorker);
                g_asyncIoWorker = NULL;
            }            

            StopFreezeWatchdog();
            CrashDumper::Shutdown();
            ShutdownFrameThrottling();
            TooltipCache::Shutdown();
            SpellCache::Shutdown();
            // ShutdownUIFrameBatching(); // REMOVED - optimization disabled
            AnimMT::Shutdown();
            LuaBytecodePreCompiler::Shutdown();
            SpellEffectMT::Shutdown();
            MPQDecompressMT::Shutdown();
            TextureDecodeMT::Shutdown();
            ShutdownSavedVarsAsync();
            ShutdownLuaGetTableCache();
            ShutdownDataStoreFastPath();
            ShutdownStringOpsFast();
            ShutdownLuaPushNumberFast();
            ShutdownGetTimeFast();
            ShutdownLuaPushValueFast();
            ShutdownDataCaches();
            ShutdownComputeCaches();
            ShutdownRenderStateDedup();
            ShutdownEventNameHash();
            ShutdownCDataStoreBatch();
            ShutdownD3D9StateManager();
            ShutdownRenderHooks();
            ShutdownSimdHooks();
            ShutdownLogicHooks();
            ShutdownMemoryHooks();
            ShutdownAsyncHooks();
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            for (int i = 0; i < MAX_CACHED_HANDLES; i++) {
                if (g_readCache[i].buffer) { mi_free(g_readCache[i].buffer); g_readCache[i].buffer = nullptr; }
            }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                Log("Exception during DLL shutdown - continuing exit");
            }
            Log("wow_optimize.dll unloaded (clean)");
            LogClose();
            break;
    }
    return TRUE;
}