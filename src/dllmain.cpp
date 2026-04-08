// ================================================================
// wow_optimize.dll — World of Warcraft 3.3.5a (build 12340) Optimizer
// Author: SUPREMATIST
// Version: 3.3.1
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
//   - All WoW addresses hardcoded for build 12340 (IDA Pro verified)
//
// OPTIMIZATION CATEGORIES:
//   1.  Memory allocator replacement (mimalloc for CRT)
//   2.  Sleep hook — precise frame pacing, GC stepping, combat log
//   3.  Network — TCP_NODELAY, ACK freq, QoS, buffer sizing
//   4.  MPQ handle tracking (O(1) hash) + memory mapping + prefetch
//   5.  ReadFile — adaptive read-ahead cache for MPQ
//   6.  Timer precision — GetTickCount, timeGetTime, QPC coalescing
//   7.  System hooks — CS spin, heap LFH, thread ID cache, BadPtr
//   8.  File I/O — CreateFile sequential scan, CloseHandle invalidation
//   9.  Thread/process tuning — affinity, priority, working set
//   10. Lua VM — GC optimizer, mimalloc allocator, string table
//   11. Lua fast paths — 28+ C function hooks
//   12. API cache — GetItemInfo result caching
//   13. Combat log — retention patching + periodic clears
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
#include <intrin.h>
#include "ui_cache.h"
#include "api_cache.h"
#include "lua_fastpath.h"
#include "lua_internals.h"

#include "MinHook.h"
#include <mimalloc.h>
#include "lua_optimize.h"
#include "combatlog_optimize.h"

#include "version.h"

// ================================================================
// CRASH ISOLATION TOGGLES
// Each toggle disables a specific optimization for binary search
// during crash investigation. Set to 1 to DISABLE the feature.
// These are compile-time flags for test builds only.
// ================================================================
#define CRASH_TEST_DISABLE_COMPARESTRING   0   // CompareStringA fast path
#define CRASH_TEST_DISABLE_GETFILEATTR     0   // GetFileAttributesA cache
#define CRASH_TEST_DISABLE_GLOBALALLOC     1   // GlobalAlloc mimalloc (ALREADY DISABLED — risky)
#define CRASH_TEST_DISABLE_CS_ENTER        0   // CriticalSection TryEnter spin
#define CRASH_TEST_DISABLE_SETFILEPOINTER  0   // SetFilePointer -> SetFilePointerEx
#define CRASH_TEST_DISABLE_READFILE        0   // ReadFile MPQ cache
#define CRASH_TEST_DISABLE_ISBADPTR        0   // IsBadReadPtr/WritePtr fast path
#define CRASH_TEST_DISABLE_MPQ_MMAP        1   // MPQ memory mapping (ALREADY DISABLED — risky)
#define CRASH_TEST_DISABLE_QPC_CACHE       0   // QPC coalescing cache
#define CRASH_TEST_DISABLE_LUA_INTERNALS   0   // Lua VM internals (concat hook)
#define CRASH_TEST_DISABLE_THREAD_AFFINITY   0   // Thread core pinning
#define CRASH_TEST_DISABLE_SHORT_WAIT_SPIN   1   // WaitSpin (ALREADY DISABLED — tested bad)
#define CRASH_TEST_DISABLE_VA_ARENA          0   // VA Arena virtual alloc
#define CRASH_TEST_DISABLE_DISPATCH_POOL     1   // DispatchPool (ALREADY DISABLED — tested bad)
#define CRASH_TEST_DISABLE_BGPRELOAD_CACHE   1   // bgpreloadsleep cache (ALREADY DISABLED — 0 hits)
#define CRASH_TEST_DISABLE_SUBTASK_EVENTPOOL 1   // Subtask event pool (ALREADY DISABLED — 0 hits)

// New hooks crash isolation (v3.3.2)
#define CRASH_TEST_DISABLE_GETFILESIZE_CACHE    0   // GetFileSizeEx cache — ENABLED for testing
#define CRASH_TEST_DISABLE_WFS_SPIN             1   // WaitForSingleObject spin (DISABLED — tested bad, crashes WoW)
#define CRASH_TEST_DISABLE_MODHANDLE_CACHE      0   // GetModuleHandleA cache — ENABLED for testing
#define CRASH_TEST_DISABLE_LSTRCMP              0   // lstrcmp/lstrcmpiA fast path — ENABLED for testing
#define CRASH_TEST_DISABLE_PROFILE_CACHE        0   // GetPrivateProfileStringA cache — ENABLED for testing
#define CRASH_TEST_DISABLE_MSGPUMP_RC1          0   // sub_869E00 frame-continue (testbuild-msgpump-rc1)

// Forward declarations
static bool IsExecutableMemory(uintptr_t addr);
static bool InstallThreadAffinity();

// ================================================================
// VA Arena v2 — High-address reserved arena with caller filtering
//
// WHAT: Intercepts VirtualAlloc calls from Wow.exe and serves them
//       from a pre-reserved 512 MB block in high address space.
// WHY:  Prevents 32-bit address space fragmentation by keeping large
//       allocations contiguous in a dedicated region.
// HOW:  1. Reserves 512 MB with MEM_TOP_DOWN at DLL init
//       2. Hooks VirtualAlloc/VirtualFree
//       3. Filters callers — only services allocations from Wow.exe code
//       4. Bitmap-based page allocator (64 KB pages, up to 8192)
//       5. SEH-protected — falls back to original VirtualAlloc on exception
// LIMITS: Only intercepts >=64 KB MEM_COMMIT allocations
// STATUS: Enabled (disabled via CRASH_TEST_DISABLE_VA_ARENA if needed)
// ================================================================
typedef LPVOID (WINAPI* VirtualAlloc_fn)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI* VirtualFree_fn)(LPVOID, SIZE_T, DWORD);

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

#define VA_ARENA_PAGE_SIZE  65536
#define VA_ARENA_MAX_PAGES  8192  // 512 MB
static uint64_t g_vaArenaBitmap[VA_ARENA_MAX_PAGES / 64] = {0};
static DWORD    g_vaArenaSpan[VA_ARENA_MAX_PAGES] = {0};  // span length in pages
static DWORD    g_vaArenaUsedPages = 0;

static uintptr_t g_vaArenaWowBase = 0;
static uintptr_t g_vaArenaWowEnd  = 0;

// Forward declarations
static bool InstallVAArena();
static void ShutdownVAArena();

// New system optimizations (v3.3.2+)
static bool InstallGetFileSizeCache();
static bool InstallWaitForSingleObjectHook();
static bool InstallGetModuleHandleCache();
static bool InstallLstrcmpHook();
static bool InstallGetPrivateProfileCache();

// Stats for new hooks (defined with implementations below)
static long g_fsizeHits = 0, g_fsizeMisses = 0;
static long g_wfsSpinHits = 0, g_wfsFallbacks = 0;
static long g_modHits = 0, g_modMisses = 0;
static long g_lstrcmpHits = 0, g_lstrcmpFallbacks = 0;
static long g_profHits = 0, g_profMisses = 0;

// ================================================================
// Thread Affinity — background worker core pinning
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

// ================================================================
// Global state
// ================================================================
bool   g_isMultiClient = false;         // Set by DetectMultiClient() via named mutex
static HANDLE g_instanceMutex = NULL;   // "wow_optimize_instance_v2" mutex
static DWORD  g_nextStatsDumpTick = 0;  // Next periodic stats dump (GetTickCount)
static DWORD  g_nextMiCollectTick = 0;  // Next mimalloc collect (multi-client only)
static void   DumpPeriodicStats();
// Forward declarations for MPQ prefetch
static void PrefetchMappedMPQs();
static void ResetPrefetchFlag();

// ================================================================
// Logging — ring buffer + background thread
//
// WHAT: Lock-free ring buffer (2048 slots x 512 bytes) with a
//       dedicated background thread that flushes to file.
// WHY:  Avoids file I/O on the main/game threads. Log() is called
//       from hooked functions — must be ultra-fast.
// HOW:  1. Log() writes to ring slot, sets ready flag via Interlocked
//       2. Background thread waits on event, drains ready slots
//       3. On shutdown, drains remaining entries
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
    g_log = fopen("Logs\\wow_optimize.log", "w");
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
// WHAT: Replaces CRT malloc/free/realloc/calloc/msize with mimalloc.
// WHY:  mimalloc is significantly faster than the default Windows heap,
//       especially for small allocations (fragmentation-resistant).
// HOW:  1. Finds loaded CRT DLL (msvcrt.dll etc.)
//       2. Hooks malloc/free/realloc/calloc/_msize via MinHook
//       3. hooked_free checks mi_is_in_heap_region() to avoid freeing
//          non-mimalloc pointers (safety for mixed-allocator code)
//       4. hooked_realloc migrates from old allocator if needed
// STATUS: Active — primary allocator for all CRT allocations
typedef void*  (__cdecl* malloc_fn)(size_t);
typedef void   (__cdecl* free_fn)(void*);
typedef void*  (__cdecl* realloc_fn)(void*, size_t);
typedef void*  (__cdecl* calloc_fn)(size_t, size_t);
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
// WHAT: Hooks Sleep() to intercept WoW's frame pacing calls (typically
//       Sleep(1-3) between frames).
// WHY:  This is the central hook — called ~60 times/sec on main thread.
//       Used as a trigger for: Lua GC stepping, combat log cleanup,
//       addon state polling, MPQ prefetch, mimalloc collect.
// HOW:  1. PreciseSleep: busy-wait for sub-ms accuracy (single client)
//          or pure yield (multi-client to reduce CPU)
//       2. Runs periodic maintenance on main thread
//       3. Calls LuaOpt::OnMainThreadSleep() for GC stepping
//       4. Calls CombatLogOpt::OnFrame() for periodic log clears
// STATUS: Active — core heartbeat mechanism for all optimizations
static DWORD g_mainThreadId = 0;

typedef void (WINAPI* Sleep_fn)(DWORD);
static Sleep_fn orig_Sleep = nullptr;

static double g_sleepFreq = 0.0;

static void PreciseSleep(double milliseconds) {
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    double start = (double)li.QuadPart / g_sleepFreq;

    while (true) {
        QueryPerformanceCounter(&li);
        double elapsed = (double)li.QuadPart / g_sleepFreq - start;

        if (elapsed >= milliseconds)
            return;

        double remaining = milliseconds - elapsed;

        if (g_isMultiClient) {
            // Multi-client: no busy-wait, always yield CPU
            if (remaining > 1.5)
                orig_Sleep(1);
            else
                orig_Sleep(0);
        } else {
            // Single client: precise busy-wait for sub-ms accuracy
            if (remaining > 2.0)
                orig_Sleep(1);
            else if (remaining > 0.3)
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
        if (g_nextMiCollectTick == 0) {
            g_nextMiCollectTick = nowTick + 60000;
        } else if ((LONG)(nowTick - g_nextMiCollectTick) >= 0) {
            mi_collect(true);
            g_nextMiCollectTick = nowTick + 60000;
        }
    }
}
static LARGE_INTEGER g_lastSleepTime = {};
static double g_lastFrameMs = 0.0;

static void WINAPI hooked_Sleep(DWORD ms) {
    if (g_mainThreadId != 0 && GetCurrentThreadId() == g_mainThreadId) {
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

        LuaOpt::OnMainThreadSleep(g_mainThreadId, g_lastFrameMs);
        CombatLogOpt::OnFrame(g_mainThreadId);

        if (LuaOpt::IsLoadingMode()) {
            PrefetchMappedMPQs();
        } else {
            ResetPrefetchFlag();
        }

        PreciseSleep((double)ms);
        return;
    }

    orig_Sleep(ms);
}

static bool InstallSleepHook() {
    LARGE_INTEGER li;
    QueryPerformanceFrequency(&li);
    g_sleepFreq = (double)li.QuadPart / 1000.0;

    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_Sleep, (void**)&orig_Sleep) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("Sleep hook: ACTIVE (PreciseSleep + Lua GC + combat log)");
    return true;
}

// 3. Network optimization - TCP_NODELAY, immediate ACK, QoS, keepalive.
//
// WHAT: Hooks connect() and send() to optimize WoW's TCP socket settings.
// WHY:  Default Nagle algorithm + delayed ACK add 40-200ms latency.
//       For a game server connection, this is noticeable lag.
// HOW:  1. TCP_NODELAY: disables Nagle (sends immediately)
//       2. SIO_TCP_SET_ACK_FREQUENCY: forces ACK every packet (Win7+)
//       3. IP_TOS 0x10: low-delay QoS flag
//       4. Buffer sizing: 32KB send, 64KB receive
//       5. Keepalive: 10s interval, 1s timeout
//       6. Deferred mode: tracks WSAEWOULDBLOCK sockets, optimizes on
//          first send() instead of at connect() time
// STATUS: Active — reduces network latency for game server connection

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
        // Synchronous connect succeeded — optimize immediately
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

static bool InstallNetworkHooks() {
    HMODULE h = GetModuleHandleA("ws2_32.dll");
    if (!h) h = LoadLibraryA("ws2_32.dll");
    if (!h) return false;

    void* pConnect = (void*)GetProcAddress(h, "connect");
    void* pSend    = (void*)GetProcAddress(h, "send");
    if (!pConnect) return false;

    int ok = 0;

    if (MH_CreateHook(pConnect, (void*)hooked_connect, (void**)&orig_connect) == MH_OK)
        if (MH_EnableHook(pConnect) == MH_OK) ok++;

    if (pSend && MH_CreateHook(pSend, (void*)hooked_send, (void**)&orig_send) == MH_OK)
        if (MH_EnableHook(pSend) == MH_OK) ok++;

    Log("Network hook: ACTIVE (%d/2 hooks, NODELAY+ACK+QoS+BUF+KA, deferred mode)", ok);
    return ok > 0;
}

// ================================================================
// 4. MPQ Handle Tracking (O(1) hash lookup)
//
// WHAT: Tracks which file handles are MPQ archives using a hash table.
// WHY:  ReadFile/CreateFile hooks need to know if a handle is MPQ to
//       apply caching/mmap optimizations. Linear scan of 256 elements
//       on EVERY ReadFile call was too slow.
// HOW:  1. Open-addressing hash table (512 slots, power-of-2 size)
//       2. Key insight: HANDLE values are multiples of 4, so we shift
//          right by 2 for better hash distribution
//       3. TrackMpqHandle called from CreateFile hook
//       4. UntrackMpqHandle called from CloseHandle hook
//       5. IsMpqHandle checked from ReadFile hook (fast path gate)
// STATUS: Active — used by ReadFile cache and MPQ mmap features
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
// WHAT: Memory-maps MPQ files (256 KB — 512 MB) for zero-kernel reads.
// WHY:  mmap eliminates kernel transition overhead on every ReadFile.
//       Reads become simple memcpy from user-space mapped memory.
//       For frequently-accessed MPQ data (DBCs, textures), this is
//       a massive speedup — no syscall, no IRP, no driver stack.
// HOW:  1. CreateFile hook: detects .mpq extension, calls CreateMpqMapping
//       2. CreateMpqMapping: CreateFileMapping + MapViewOfFile
//       3. ReadFile hook: checks mapping, does memcpy if in range
//       4. CloseHandle hook: unmaps view (intentionally does NOT close
//          mapping handle to avoid deadlock with hooked_CloseHandle)
// LIMITS: Min 256 KB, max 512 MB per file, 768 MB total, 32 mappings
// STATUS: DISABLED in public release (CRASH_TEST_DISABLE_MPQ_MMAP=1)
//         Tested and found risky — leave disabled for stable builds
// ================================================================
// MPQ map lock — always defined (used by scanner even when mmap disabled)
static SRWLOCK g_mpqMapLock = SRWLOCK_INIT;
#if !CRASH_TEST_DISABLE_MPQ_MMAP

struct MpqMapping {
    HANDLE fileHandle;
    HANDLE mappingHandle;
    void*  baseAddress;
    DWORD  fileSize;
    bool   active;
};

static constexpr int    MAX_MPQ_MAPPINGS    = 32;
static constexpr DWORD  MPQ_MMAP_MIN_SIZE   = 256 * 1024;              // 256 KB
static constexpr DWORD  MPQ_MMAP_MAX_SIZE   = 512 * 1024 * 1024;      // 512 MB
static constexpr DWORD  MPQ_MMAP_MAX_TOTAL  = 768 * 1024 * 1024;      // 768 MB total (safe for 32-bit)

static MpqMapping g_mpqMappings[MAX_MPQ_MAPPINGS] = {};
static DWORD      g_mpqMapTotalBytes = 0;
static long       g_mpqMapHits    = 0;
static long       g_mpqMapMisses  = 0;
static int        g_mpqMapCount   = 0;

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
            // For runtime cleanup, we just unmap the view — that's sufficient.
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
// WHAT: Caches reads from MPQ handles with adaptive read-ahead.
// WHY:  WoW reads MPQ files in small chunks (often 1-8 KB). Each
//       ReadFile is a syscall + disk I/O. Read-ahead fetches 64-256 KB
//       in one syscall, serving subsequent reads from memory.
// HOW:  1. On first read: fetches 64 KB (normal) or 256 KB (loading)
//       2. Subsequent reads within cached range: memcpy from buffer
//       3. Cache miss: refills with new read-ahead
//       4. 16 handle slots, LRU eviction
//       5. Checks IsMpqHandle() to only cache MPQ reads
//       6. If MPQ mmap is enabled, mmap fast path is tried first
// STATUS: Active — primary MPQ read optimization for public release
typedef BOOL (WINAPI* ReadFile_fn)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static ReadFile_fn orig_ReadFile = nullptr;

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
    if (lpOverlapped || !g_cacheInitialized || !IsMpqHandle(hFile))
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
            }
            ReleaseSRWLockExclusive(&g_cacheLock);
            return TRUE;
        }
        cache->validBytes = 0;
        SetFilePointerEx(hFile, currentPos, NULL, FILE_BEGIN);
    }

    ReleaseSRWLockExclusive(&g_cacheLock);
    return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ReleaseSRWLockExclusive(&g_cacheLock);
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);
    }
}

static bool InstallReadFileHook() {
    g_cacheInitialized = true;
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_ReadFile, (void**)&orig_ReadFile) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("ReadFile hook: ACTIVE (MPQ cache, 64KB/256KB adaptive read-ahead, %d slots)", MAX_CACHED_HANDLES);
    return true;
}

// ================================================================
// 6. GetTickCount — QPC Precision
//
// WHAT: Replaces GetTickCount() with QPC-based microsecond precision.
// WHY:  GetTickCount has ~15.6 ms resolution (default timer tick).
//       WoW uses it for frame timing, animation, and UI updates.
//       QPC provides sub-microsecond precision for smoother pacing.
// HOW:  1. Captures QPC frequency + starting point at init
//       2. Returns g_tickStart + elapsed_ms_from_QPC
//       3. Synced with timeGetTime hook (same QPC base)
// STATUS: Active — improves frame timing precision
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
// 6b. timeGetTime (WINMM) — QPC Precision
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
// WHAT: Increases CS spin count to 4000 and adds TryEnter spin-first path.
// WHY:  Default CS spin count is 0 — immediately enters kernel wait.
//       For short-held locks (common in WoW), spinning in user mode is
//       much faster than a kernel transition.
// HOW:  1. hooked_InitCS: sets spin count to 4000 on all new CS
//       2. hooked_EnterCS: tries TryEnter first, then 32x _mm_pause()
//          spin loop, then falls back to original EnterCriticalSection
// STATUS: Active — reduces kernel transitions on contention paths
// NOTE:   TryEnter path can be disabled via CRASH_TEST_DISABLE_CS_ENTER

typedef void (WINAPI* InitCS_fn)(LPCRITICAL_SECTION);
typedef void (WINAPI* EnterCS_fn)(LPCRITICAL_SECTION);
static InitCS_fn  orig_InitCS  = nullptr;
static EnterCS_fn orig_EnterCS = nullptr;
static long g_csSpinHits = 0;

static void WINAPI hooked_InitCS(LPCRITICAL_SECTION lpCS) {
    InitializeCriticalSectionAndSpinCount(lpCS, 4000);
}

#if !CRASH_TEST_DISABLE_CS_ENTER
static void WINAPI hooked_EnterCS(LPCRITICAL_SECTION lpCS) {
    if (TryEnterCriticalSection(lpCS)) {
        InterlockedIncrement(&g_csSpinHits);
        return;
    }

    for (int i = 0; i < 32; i++) {
        _mm_pause();
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

    void* pInit = (void*)GetProcAddress(hK32, "InitializeCriticalSection");
    if (pInit && MH_CreateHook(pInit, (void*)hooked_InitCS, (void**)&orig_InitCS) == MH_OK)
        if (MH_EnableHook(pInit) == MH_OK) ok++;

#if CRASH_TEST_DISABLE_CS_ENTER
    Log("CriticalSection hook: ACTIVE (%d/1, spin count only, crash isolation)", ok);
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
// 7b. Heap Optimization — Low Fragmentation Heap
//
// WHAT: Enables LFH on all growable heaps via HeapSetInformation.
// WHY:  LFH reduces fragmentation and improves allocation speed for
//       small allocations (< 16 KB). WoW creates many heaps at runtime.
// HOW:  1. Enables LFH on process default heap at init
//       2. Hooks HeapCreate to enable LFH on all future growable heaps
//       3. Only targets heaps with dwMaximumSize==0 (growable heaps)
//          Fixed-size heaps don't support LFH
// STATUS: Active — reduces heap fragmentation globally
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
// 7c. OutputDebugStringA — No-op when no debugger
//
// WHAT: Skips OutputDebugStringA calls when no debugger is attached.
// WHY:  WoW/addons may emit debug strings. Without a debugger, these
//       go to DbgPrint which has non-trivial overhead.
// HOW:  Checks IsDebuggerPresent() — returns immediately if false
// STATUS: Active — minor overhead reduction
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
// 7d. CompareStringA — Fast ASCII Path
//
// WHAT: User-mode fast path for pure ASCII string comparisons.
// WHY:  CompareStringA is a locale-aware Win32 API with significant
//       overhead for simple ASCII comparisons (common in WoW addons).
// HOW:  1. Checks flags — only fast-paths simple cases (no flags,
//       NORM_IGNORECASE, or SORT_STRINGSORT)
//       2. Iterates chars, bails on non-ASCII (>127) → original API
//       3. Case-insensitive: uppercases a-z inline (no API call)
//       4. Returns CSTR_LESS_THAN/EQUAL/GREATER_THAN directly
// STATUS: Active — speeds up string comparisons in addons/Blizzard UI
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

            // Bail on non-ASCII — needs locale-aware comparison
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
// 7e. GetFileAttributesA — Cache for MPQ paths
//
// WHAT: 256-slot direct-mapped cache for GetFileAttributesA results.
// WHY:  WoW calls GetFileAttributesA frequently for file existence
//       checks (config, screenshots, addon files). Each call is a
//       filesystem stat syscall — expensive for network/MPQ paths.
// HOW:  1. Case-insensitive FNV-1a hash of path (normalizes slashes)
//       2. Only caches files that EXIST (not INVALID)
//       3. Non-existent files not cached — might be created later
// STATUS: Active — reduces filesystem stat overhead
// ================================================================

typedef DWORD (WINAPI* GetFileAttributesA_fn)(LPCSTR);
static GetFileAttributesA_fn orig_GetFileAttributesA = nullptr;

static constexpr int FILE_ATTR_CACHE_SIZE = 256;
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

    // Only cache files that exist — non-existent files might be created later
    if (result != INVALID_FILE_ATTRIBUTES) {
        e->pathHash   = hash;
        e->attributes = result;
        e->valid      = true;
    }

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
// WHAT: Redirects legacy 32-bit SetFilePointer to SetFilePointerEx.
// WHY:  SetFilePointer has awkward error handling (INVALID_SET_FILE_POINTER
//       + GetLastError) and slightly more overhead. SetFilePointerEx is
//       the "real" implementation internally — cleaner and faster.
// HOW:  1. Converts 32-bit params to LARGE_INTEGER
//       2. Calls SetFilePointerEx
//       3. Converts result back to legacy 32-bit return convention
// STATUS: Active — cleaner I/O semantics, minor speed improvement
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
// 7h. GlobalAlloc/GlobalFree — mimalloc for GMEM_FIXED
//
// WHAT: Routes GMEM_FIXED GlobalAlloc/GlobalFree through mimalloc.
// WHY:  GlobalAlloc uses the process heap. mimalloc is faster for
//       fixed-size allocations (no heap management overhead).
// HOW:  1. hooked_GlobalAlloc: if GMEM_MOVEABLE is NOT set, uses
//       mi_malloc/mi_calloc instead of GlobalAlloc
//       2. hooked_GlobalFree: checks mi_is_in_heap_region() to
//          determine if pointer was allocated by mimalloc
//       3. GMEM_MOVEABLE allocations use original GlobalAlloc because
//          GlobalLock/GlobalUnlock require OS-managed handles
// STATUS: DISABLED in public release (CRASH_TEST_DISABLE_GLOBALALLOC=1)
//         Tested and found risky — leave disabled for stable builds
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
// 7f2. IsBadReadPtr / IsBadWritePtr — Fast Path
//
// WHAT: Fast-path for NULL/obvious bad pointer checks.
// WHY:  IsBadReadPtr/WriteProbes use SEH (try/except) to probe memory.
//       For obvious cases (NULL, <64KB, uncommitted), we can return
//       immediately without SEH overhead.
// HOW:  1. NULL → TRUE (always bad)
//       2. Zero size → FALSE (always valid)
//       3. <64KB → TRUE (guard page region)
//       4. VirtualQuery check: not committed, NOACCESS, GUARD → TRUE
//       5. Otherwise → fall through to FALSE (likely valid)
// STATUS: Active — avoids SEH probing for common bad pointers
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
// 7f. GetCurrentThreadId — TLS Cached
//
// WHAT: Caches thread ID in TLS (__declspec(thread)) variable.
// WHY:  GetCurrentThreadId is a syscall. WoW calls it frequently.
//       Thread ID never changes per-thread, so cache it forever.
// HOW:  1. First call: calls original GetCurrentThreadId, stores in TLS
//       2. Subsequent calls: returns cached TLS value (zero syscall)
//       3. Also hooks GetCurrentThread to return constant pseudo-handle
// STATUS: Active — eliminates GetCurrentThreadId syscalls
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
// 7f3. QueryPerformanceCounter — Coalesced
//
// WHAT: Caches QPC results within a 50μs coalescing window.
// WHY:  QPC is a relatively expensive syscall. WoW calls it multiple
//       times per frame. Within a 50μs window, the value is effectively
//       the same for game logic purposes.
// HOW:  1. Per-thread TLS: stores last QPC value and timestamp
//       2. If elapsed < 50μs since last call, returns cached value
//       3. Otherwise: calls original QPC, updates cache
// STATUS: Active — reduces QPC syscall frequency by ~30-50%
// ================================================================

typedef BOOL (WINAPI* QueryPerformanceCounter_fn)(LARGE_INTEGER*);
static QueryPerformanceCounter_fn orig_QPC = nullptr;

static __declspec(thread) LONGLONG t_lastQPC = 0;
static __declspec(thread) LONGLONG t_lastQPCTime = 0;
static long g_qpcCacheHits = 0;
static long g_qpcCacheMisses = 0;

// Coalescing window in QPC ticks (calculated at init)
static LONGLONG g_qpcCoalesceWindow = 0;

static BOOL WINAPI hooked_QPC(LARGE_INTEGER* lpPerformanceCount) {
    if (!lpPerformanceCount)
        return orig_QPC(lpPerformanceCount);

    LARGE_INTEGER now;
    orig_QPC(&now);

    LONGLONG elapsed = now.QuadPart - t_lastQPCTime;

    if (elapsed >= 0 && elapsed < g_qpcCoalesceWindow && t_lastQPCTime != 0) {
        lpPerformanceCount->QuadPart = t_lastQPC;
        InterlockedIncrement(&g_qpcCacheHits);
        return TRUE;
    }

    t_lastQPC = now.QuadPart;
    t_lastQPCTime = now.QuadPart;
    lpPerformanceCount->QuadPart = now.QuadPart;
    InterlockedIncrement(&g_qpcCacheMisses);
    return TRUE;
}

static bool InstallQPCHook() {
    // Calculate coalescing window: 50 microseconds in QPC ticks
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    g_qpcCoalesceWindow = freq.QuadPart / 20000;  // 50us
    if (g_qpcCoalesceWindow < 1) g_qpcCoalesceWindow = 1;

    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "QueryPerformanceCounter");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_QPC, (void**)&orig_QPC) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("QPC hook: ACTIVE (50us coalescing, %lld ticks window)", g_qpcCoalesceWindow);
    return true;
}

// ================================================================
// 8. CreateFile — Sequential Scan + MPQ Tracking
//
// WHAT: Hooks CreateFileA/W to add FILE_FLAG_SEQUENTIAL_SCAN for MPQ
//       files and track MPQ handles for the read-ahead cache.
// WHY:  1. WoW reads MPQ files sequentially (archive data streams).
//          Sequential scan flag tells the prefetcher to optimize I/O.
//       2. MPQ handles must be tracked for ReadFile cache/mmap hooks.
// HOW:  1. Checks .mpq extension (case-insensitive)
//       2. Adds FILE_FLAG_SEQUENTIAL_SCAN to dwFlags
//       3. Calls original CreateFile
//       4. If MPQ: TrackMpqHandle + TryCreateMpqMapping
// STATUS: Active — enables all MPQ optimization pipeline
// ================================================================
typedef HANDLE (WINAPI* CreateFileA_fn)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI* CreateFileW_fn)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static CreateFileA_fn orig_CreateFileA = nullptr;
static CreateFileW_fn orig_CreateFileW = nullptr;

static HANDLE WINAPI hooked_CreateFileA(LPCSTR lpFileName, DWORD dwAccess, DWORD dwShare,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwDisposition, DWORD dwFlags, HANDLE hTemplate)
{
    bool isMPQ = false;
    if (lpFileName && (dwAccess & GENERIC_READ)) {
        const char* ext = strrchr(lpFileName, '.');
        if (ext && (_stricmp(ext, ".mpq") == 0 || _stricmp(ext, ".MPQ") == 0)) {
            dwFlags |= FILE_FLAG_SEQUENTIAL_SCAN; isMPQ = true;
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
// 9. CloseHandle — Cache Invalidation
//
// WHAT: Invalidates read-ahead cache and MPQ mappings on file close.
// WHY:  When WoW closes an MPQ file, cached data for that handle
//       becomes stale and must be purged to avoid reading freed data.
// HOW:  1. Skips pseudo-handles (GetCurrentProcess/Thread)
//       2. Destroys MPQ mapping (unmaps view, does NOT close mapping
//          handle to avoid deadlock with hooked_CloseHandle)
//       3. Untracks handle from MPQ hash table
//       4. Invalidates read-ahead cache entry for this handle
// STATUS: Active — prevents stale data reads from closed files
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
// WHAT: Scans all existing process handles for MPQ files after init.
// WHY:  WoW opens MPQ handles before wow_optimize.dll is loaded (during
//       early startup). These handles are invisible to CreateFile hook.
// HOW:  1. Iterates handles 4..0x10000 (step 4 — HANDLE alignment)
//       2. GetFileType: must be FILE_TYPE_DISK
//       3. GetFinalPathNameByHandleA: gets file path
//       4. Checks .mpq extension → TrackMpqHandle + CreateMpqMapping
// STATUS: Active — catches MPQ handles opened before DLL initialization

typedef DWORD (WINAPI* GetFinalPathNameByHandleA_fn)(HANDLE, LPSTR, DWORD, DWORD);
static GetFinalPathNameByHandleA_fn pGetFinalPathNameByHandleA = nullptr;

static void ScanExistingMpqHandles() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (hK32) {
        pGetFinalPathNameByHandleA = (GetFinalPathNameByHandleA_fn)
            GetProcAddress(hK32, "GetFinalPathNameByHandleA");
    }
    if (!pGetFinalPathNameByHandleA) {
        Log("MPQ scan: GetFinalPathNameByHandleA not available — skipped");
        return;
    }

    char pathBuf[MAX_PATH];
    int tracked = 0;
    int mapped  = 0;
    int alreadyTracked = 0;

    for (DWORD h = 4; h < 0x10000; h += 4) {
        HANDLE handle = (HANDLE)(uintptr_t)h;

        SetLastError(0);
        DWORD fileType = GetFileType(handle);
        if (fileType != FILE_TYPE_DISK) continue;
        if (GetLastError() == ERROR_INVALID_HANDLE) continue;

        DWORD len = pGetFinalPathNameByHandleA(handle, pathBuf, MAX_PATH,
                                                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (len == 0 || len >= MAX_PATH) continue;

        const char* ext = strrchr(pathBuf, '.');
        if (!ext) continue;
        if (_stricmp(ext, ".mpq") != 0 && _stricmp(ext, ".MPQ") != 0) continue;

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
    Log("MPQ scan: %d handles tracked, %d already tracked (mmap disabled)",
        tracked, alreadyTracked);
#endif
}

// 9e. MPQ prefetch during loading pages in mapped MPQ data.
//
// WHAT: Prefetches memory-mapped MPQ archives into physical RAM.
// WHY:  Memory mapping creates virtual mappings but pages are not
//       resident until first access. During loading screens, WoW
//       streams data from MPQs — prefaulting avoids page faults later.
// HOW:  1. Called once per loading screen (g_prefetchDone flag)
//       2. Uses PrefetchVirtualMemory (Win8+) if available
//       3. Falls back to sequential memory touch (read each 4 KB page)
//       4. ResetPrefetchFlag clears the flag when loading ends
// STATUS: Active — reduces loading screen stutter from page faults

typedef BOOL (WINAPI* PrefetchVirtualMemory_fn)(
    HANDLE, ULONG_PTR, PVOID, ULONG);
static PrefetchVirtualMemory_fn pPrefetchVirtualMemory = nullptr;
static bool g_prefetchResolved = false;
static bool g_prefetchAvailable = false;
static volatile LONG g_prefetchDone = 0;

static void ResolvePrefetch() {
    if (g_prefetchResolved) return;
    g_prefetchResolved = true;
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (hK32) {
        pPrefetchVirtualMemory = (PrefetchVirtualMemory_fn)
            GetProcAddress(hK32, "PrefetchVirtualMemory");
    }
    g_prefetchAvailable = (pPrefetchVirtualMemory != nullptr);
    Log("MPQ prefetch: %s", g_prefetchAvailable ? "PrefetchVirtualMemory available" : "fallback to sequential touch");
}

static void PrefetchMappedMPQs() {
#if CRASH_TEST_DISABLE_MPQ_MMAP
    return;
#else
    // Only prefetch once per loading screen
    if (InterlockedCompareExchange(&g_prefetchDone, 1, 0) != 0) return;

    AcquireSRWLockShared(&g_mpqMapLock);

    int prefetched = 0;

    for (int i = 0; i < MAX_MPQ_MAPPINGS; i++) {
        if (!g_mpqMappings[i].active) continue;

        if (g_prefetchAvailable && pPrefetchVirtualMemory) {
            WIN32_MEMORY_RANGE_ENTRY entry;
            entry.VirtualAddress = g_mpqMappings[i].baseAddress;
            entry.NumberOfBytes  = g_mpqMappings[i].fileSize;
            pPrefetchVirtualMemory(GetCurrentProcess(), 1, &entry, 0);
            prefetched++;
        } else {
            volatile uint8_t* base = (volatile uint8_t*)g_mpqMappings[i].baseAddress;
            DWORD size = g_mpqMappings[i].fileSize;
            __try {
                volatile uint8_t dummy;
                for (DWORD off = 0; off < size; off += 4096) {
                    dummy = base[off];
                }
                (void)dummy;
                prefetched++;
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    ReleaseSRWLockShared(&g_mpqMapLock);

    if (prefetched > 0) {
        Log("MPQ prefetch: %d archives prefetched (%.1f MB)",
            prefetched, g_mpqMapTotalBytes / (1024.0 * 1024.0));
    }
#endif
}

static void ResetPrefetchFlag() {
    InterlockedExchange(&g_prefetchDone, 0);
}

// ================================================================
// 9b. FlushFileBuffers — Skip for MPQ (read-only)
//
// WHAT: Skips FlushFileBuffers calls for MPQ handles.
// WHY:  MPQ archives are read-only. Flushing write buffers is a
//       no-op but still incurs syscall overhead.
// HOW:  Checks IsMpqHandle() → returns TRUE immediately
// STATUS: Active — eliminates useless flush syscalls on read-only files
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
// WHAT: Detects if multiple WoW clients are running.
// WHY:  Multi-client mode requires conservative settings to avoid
//       resource contention and 32-bit address space pressure.
// HOW:  Creates named mutex "wow_optimize_instance_v2".
//       If ERROR_ALREADY_EXISTS → another instance is running.
// EFFECTS: 1. Timer: 1.0ms (vs 0.5ms single)
//          2. Sleep: pure yield (vs busy-wait single)
//          3. Working set: 64-512 MB (vs 256 MB-2 GB single)
//          4. mimalloc: purge_delay=100ms (vs 0ms single)
//          5. mimalloc collect: every 1024 steps (vs 4096 single)
// STATUS: Active — essential for stable multi-client operation

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
// WHAT: Sets system-wide timer resolution via NtSetTimerResolution.
// WHY:  Default Windows timer is 15.6 ms. WoW's Sleep(1) calls round
//       up to this, causing imprecise frame pacing.
// HOW:  Single client: 0.5 ms (5000 * 100ns units)
//       Multi-client: 1.0 ms (10000 units — less CPU overhead)
// STATUS: Active — enables PreciseSleep sub-millisecond accuracy
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
            Log("Timer resolution: SET (actual value invalid: %.0f ms — Wine/VM detected, ignoring)",
                actualMs);
            Log("Timer resolution: requested %.3f ms%s",
                requestedMs,
                g_isMultiClient ? " (multi-client mode)" : "");
        }
    } else {
        Log("WARNING: Timer resolution change failed");
    }
}

// 11. Large pages — requires SeLockMemoryPrivilege.
//
// WHAT: Enables mimalloc large page support if privilege is available.
// WHY:  Large pages (2 MB) reduce TLB pressure and page table overhead.
// HOW:  1. Opens process token, looks up SeLockMemoryPrivilege
//       2. Adjusts token privileges to enable it
//       3. Sets mi_option_allow_large_os_pages = 1
// STATUS: Active (if privilege granted — requires admin policy)
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

// 12. Thread optimization — ideal processor, priority.
//
// WHAT: Sets main thread ideal processor and priority ABOVE_NORMAL.
// WHY:  WoW's main thread handles all rendering, Lua, and game logic.
//       Giving it priority ensures the scheduler favors it over worker
//       threads (network, audio, MPQ streaming).
// HOW:  1. Scans all threads in process, finds earliest-creation (main)
//       2. Sets ideal processor to core 1 (or core 0 on single-core)
//       3. Sets thread priority to THREAD_PRIORITY_ABOVE_NORMAL
// STATUS: Active — main thread gets scheduler preference
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
// WHAT: Sets process to ABOVE_NORMAL_PRIORITY_CLASS + enables priority boost.
// WHY:  Ensures WoW gets CPU time over background apps.
//       Priority boost allows temporary elevation for I/O completion.
// HOW:  SetPriorityClass + SetProcessPriorityBoost
// STATUS: Active — system-wide process priority elevation
static void OptimizeProcess() {
    SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
    SetProcessPriorityBoost(GetCurrentProcess(), TRUE);
    Log("Process: Above Normal priority, priority boost disabled");
}

// 14. Working set.
//
// WHAT: Sets process minimum/maximum working set size.
// WHY:  Controls how much physical RAM WoW can use.
//       Too small → excessive page faults. Too large → starves other
//       processes (especially in multi-client mode).
// HOW:  Single client: 256 MB - 2 GB (generous for HD textures)
//       Multi-client: 64 MB - 512 MB (prevents 32-bit OOM)
// STATUS: Active — memory pressure management
static void OptimizeWorkingSet() {
    SIZE_T minWS, maxWS;
    if (g_isMultiClient) {
        // Multi-client: reduce footprint to ease 32-bit address space pressure
        minWS = 64 * 1024 * 1024;    // 64 MB
        maxWS = 512ULL * 1024 * 1024; // 512 MB
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
// WHAT: Configures mimalloc options and pre-warms the allocator.
// WHY:  mimalloc needs tuning for WoW's usage pattern.
// HOW:  1. Enables large pages (if privilege available)
//       2. Sets purge_delay=0 (single) or 100 (multi — adjusted later)
//       3. Pre-warms 64 MB to populate mimalloc's thread caches
// STATUS: Active — allocator warm and ready at init
static void ConfigureMimalloc() {
    mi_option_set(mi_option_allow_large_os_pages, 1);

    // purge_delay: how quickly mimalloc returns unused pages to OS
    // Single client: never purge (keep pages warm, less page faults)
    // Multi-client: purge after 100ms (reduce address space pressure)
    // NOTE: g_isMultiClient is not yet set at this point,
    //       so we set a moderate default and update later in AdjustMimallocForMultiClient()
    mi_option_set(mi_option_purge_delay, 0);

    void* warmup = mi_malloc(64 * 1024 * 1024);
    if (warmup) { memset(warmup, 0, 64 * 1024 * 1024); mi_free(warmup); }
    Log("mimalloc configured (large pages, pre-warmed 64MB)");
}

static void AdjustMimallocForMultiClient() {
    if (g_isMultiClient) {
        // In multi-client mode: allow mimalloc to return pages to OS
        // This prevents 32-bit address space exhaustion on HD clients
        mi_option_set(mi_option_purge_delay, 100);  // 100ms delay before returning pages
        mi_collect(true);  // force immediate purge of any unused pages
        Log("mimalloc: multi-client purge mode (100ms delay, aggressive collect)");
    }
}

// 16. FPS cap removal — patches CMP EAX, 200 to CMP EAX, 999.
//
// WHAT: Scans Wow.exe for the hardcoded 200 FPS cap and raises it to 999.
// WHY:  WoW 3.3.5a has a built-in 200 FPS limit. With all optimizations
//       active, WoW can exceed this — the cap becomes a bottleneck.
// HOW:  1. Pattern scans for "3D C8 00 00 00" (CMP EAX, 200)
//       2. Verifies next byte is conditional jump (JLE/JG)
//       3. Patches the immediate value from 200 to 999
//       4. VirtualProtect for PAGE_EXECUTE_READWRITE
// STATUS: Active — removes artificial FPS ceiling
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
            // JLE or JG short — valid FPS cap pattern
            addr = found;
            break;
        }
        if (b == 0x0F) {
            uint8_t b2 = *(uint8_t*)(found + 6);
            if (b2 == 0x8E || b2 == 0x8F) {
                // JLE or JG near — valid FPS cap pattern
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
// WHAT: Dumps comprehensive optimization statistics to the log file.
// WHY:  WoW often hangs on exit so DLL_PROCESS_DETACH stats are
//       unreliable. Periodic dumps ensure we capture runtime data.
// HOW:  Called every 30 seconds from RunPeriodicMaintenanceOnMainThread
//       (triggered by hooked_Sleep on main thread).
// DUMPS: 1. Process memory (working set, page faults, VA fragmentation)
//        2. MPQ mmap stats (reads, faults, mapped files, MB)
//        3. QPC cache hit rate
//        4. All hook hit/fallback counters
//        5. Lua fast path per-function stats
//        6. VA Arena usage stats
//        7. Lua allocator stats (mimalloc mallocs/frees)

static void DumpPeriodicStats() {
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
    if (g_profHits + g_profMisses > 0)
        Log("[Stats] GetPrivateProfile: %ld hits, %ld misses (%.1f%%)",
            g_profHits, g_profMisses,
            (double)g_profHits / (g_profHits + g_profMisses) * 100.0);
    

    if (vaOk && g_vaArenaActive) {
        long total = g_vaArenaHits + g_vaArenaFallbacks;
        double arenaPct = total > 0 ? (double)g_vaArenaHits / total * 100.0 : 0.0;
        double usedMB = (double)g_vaArenaUsedPages * VA_ARENA_PAGE_SIZE / (1024.0 * 1024.0);
        Log("[Stats] VA Arena: %ld hits, %ld fallback, %ld fail (%.1f%% arena, %.1f MB used)",
            g_vaArenaHits, g_vaArenaFallbacks, g_vaArenaFailures,
            arenaPct, usedMB);
    }
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
    if (fps.phase2Active) {
        Log("[Stats] Phase2: find=%ld/%ld match=%ld/%ld type=%ld math=%ld strlen=%ld byte=%ld tostr=%ld/%ld tonum=%ld next=%ld/%ld rawget=%ld/%ld rawset=%ld/%ld tins=%ld/%ld trem=%ld/%ld concat=%ld/%ld unpack=%ld/%ld select=%ld/%ld raweq=%ld/%ld sub=%ld lower=%ld upper=%ld",
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
            fps.strsubHits, fps.strlowerHits, fps.strupperHits);
    }
    if (fps.unitNameHits + fps.unitNameFallbacks > 0)
        Log("[Stats] UnitName: %ld hits, %ld fallback (%.1f%%)",
            fps.unitNameHits, fps.unitNameFallbacks,
            (double)fps.unitNameHits / (fps.unitNameHits + fps.unitNameFallbacks) * 100.0);
    LuaInternals::Stats lis = LuaInternals::GetStats();
    if (lis.active) {
        long catTotal = lis.concatFastHits + lis.concatFallbacks;
        if (catTotal > 0)
            Log("[Stats] Concat: %ld fast, %ld fallback (%.1f%%)",
                lis.concatFastHits, lis.concatFallbacks,
                (double)lis.concatFastHits / catTotal * 100.0);
    }

    Log("[Stats] ====================================");


}

// ================================================================
// 19. sub_869E00 — Zero-Message Frame Continue (testbuild-msgpump-rc1)
//
// WHAT: Hooks WoW's message pump function (0x00869E00). When
//       PeekMessageA returns 0 (no pending Windows messages),
//       the original function returns 0, which kills the outer
//       do...while loop in sub_480410 — the game STOPS rendering.
//
// WHY:  In addon-heavy raids, the message queue can be empty between
//       addon timer firings. When the queue is empty, WoW goes
//       completely idle — no rendering, no Lua, no GC. Then it
//       spikes back when the next timer fires. This causes raid
//       stutter and frametime variance.
//
// HOW:  1. Call original sub_869E00
//       2. If it returns 0 (no messages → loop exit):
//          a. Call hooked_Sleep(1) — yields CPU, prevents 100% usage
//          b. Return 1 — keeps the outer loop alive
//       3. The outer loop calls sub_480130 (frame render) again
//       4. Frame pacing is still controlled by our Sleep hook
//
// SAFETY: Minimal — just one extra Sleep(1) per idle cycle.
//         Frame render function handles the dword_D41400 guards.
//         If hooked_Sleep is null, falls back to Sleep(1) directly.
//
// STATUS: Test build only — testbuild-msgpump-rc1
// ================================================================

typedef int (__cdecl* MsgPump_fn)(void*, int*, DWORD*, void*, void*);
static MsgPump_fn orig_MsgPump = nullptr;
static uint64_t g_msgPumpHits = 0;

static int __cdecl hooked_MsgPump(void* a1, int* a2, DWORD* a3, void* a4, void* a5) {
    int result = orig_MsgPump(a1, a2, a3, a4, a5);

    if (result == 0) {
        // Original would exit the render loop (no messages pending).
        // Instead: yield CPU and keep the loop alive.
        g_msgPumpHits++;
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

    if (MH_CreateHook(target, (void*)hooked_MsgPump, (void**)&orig_MsgPump) != MH_OK) {
        Log("MsgPump hook: MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("MsgPump hook: MH_EnableHook FAILED");
        return false;
    }

    Log("MsgPump hook: ACTIVE (sub_869E00 @ 0x00869E00 — zero-message frame continue)");
    return true;
#endif
}

// Main initialization thread.
static DWORD WINAPI MainThread(LPVOID param) {
    Sleep(5000);

    LogOpen();
    Log("========================================");
    Log("  wow_optimize.dll v%s BY %s", WOW_OPTIMIZE_VERSION_STR, WOW_OPTIMIZE_AUTHOR);
    Log("  PID: %lu", GetCurrentProcessId());
    Log("========================================");

    if (MH_Initialize() != MH_OK) { Log("FATAL: MinHook initialization failed"); LogClose(); return 1; }
    Log("MinHook initialized");


    ConfigureMimalloc();
    TryEnableLargePages();
    g_nextStatsDumpTick = 0;
    g_nextMiCollectTick = 0;

    Log("--- Memory Allocator ---");
    bool allocOk = InstallAllocatorHooks();
    Log(allocOk ? ">>> ALLOCATOR: mimalloc ACTIVE <<<" : ">>> ALLOCATOR: FAILED <<<");

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
    Log("--- MPQ Scan ---");
    ScanExistingMpqHandles();
    ResolvePrefetch();
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
    OptimizeProcess();
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
    Log("--- Profile String Cache ---");
    bool profOk = InstallGetPrivateProfileCache();

    Log("--- Message Pump (testbuild) ---");
    bool msgPumpOk = InstallMsgPumpHook();

    Log("--- Thread Affinity ---");
    g_threadAffOk = InstallThreadAffinity();

    Log("--- VA Arena ---");
    vaOk = InstallVAArena();

    bool luaOk = false;
    Log("");
    Log("--- Lua VM Optimizer ---");
    luaOk = LuaOpt::PrepareFromWorkerThread();

    Log("");
    Log("--- Combat Log ---");
    bool combatLogOk = CombatLogOpt::Init();

    Log("");
    Log("--- UI Cache ---");
    bool uiCacheOk = UICache::Init();

    Log("");
    Log("--- API Cache ---");
    bool apiCacheOk = ApiCache::Init();

    bool fastPathOk = false;
    Log("");
    Log("--- Lua Fast Path ---");
    __try {
        fastPathOk = LuaFastPath::Init();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[FastPath] EXCEPTION 0x%08X — SKIPPED", GetExceptionCode());
    }

    bool internalsOk = false;
    Log("");
    Log("--- Lua VM Internals ---");
#if !CRASH_TEST_DISABLE_LUA_INTERNALS
    __try {
        internalsOk = LuaInternals::Init();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaVM] EXCEPTION 0x%08X — SKIPPED", GetExceptionCode());
    }
#else
    Log("[LuaVM] DISABLED (crash isolation)");
#endif



    Log("");
    Log("========================================");
    Log("  Initialization complete");
    Log("========================================");
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
    Log("  [%s] OutputDebugString (no-op)",    debugOk     ? " OK " : "FAIL");
    Log("  [%s] CriticalSection (spin+try)",   csOk        ? " OK " : "FAIL");
    Log("  [%s] Network (NODELAY+ACK+QoS+KA)", netOk      ? " OK " : "FAIL");
    Log("  [%s] CreateFile (sequential I/O)",  fileOk      ? " OK " : "FAIL");
    Log("  [%s] ReadFile (adaptive MPQ cache)", readOk     ? " OK " : "FAIL");
    #if !CRASH_TEST_DISABLE_MPQ_MMAP
        Log("  [ OK ] MPQ memory mapping (1-256MB files)");
    #else
        Log("  [SKIP] MPQ memory mapping (disabled — stability)");
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
    Log("  [%s] MsgPump (frame-continue rc1)", msgPumpOk   ? " OK " : "SKIP");

    return 0;
}

// ================================================================
// 17. GetFileSize / GetFileSizeEx — Cache
//
// WHAT: Caches file size results for frequently-queried files.
// WHY:  WoW repeatedly checks MPQ file sizes during addon loading,
//       texture streaming, and DB file validation. Each call
//       triggers a filesystem metadata syscall.
// HOW:  1. Direct-mapped 256-slot cache using path hash
//       2. Only caches successful results (valid handles + size > 0)
//       3. InvalidateOnClose: cache slot cleared on CloseHandle
// STATUS: Active — reduces filesystem stat overhead
// ================================================================

static constexpr int FSIZE_CACHE_SIZE = 256;
static constexpr int FSIZE_CACHE_MASK = FSIZE_CACHE_SIZE - 1;

struct FSizeEntry {
    uint32_t      pathHash;
    LARGE_INTEGER fileSize;
    bool          valid;
};

static FSizeEntry g_fsizeCache[FSIZE_CACHE_SIZE] = {};

typedef BOOL (WINAPI* GetFileSizeEx_fn)(HANDLE, PLARGE_INTEGER);
static GetFileSizeEx_fn orig_GetFileSizeEx = nullptr;

static BOOL WINAPI hooked_GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize) {
    BOOL result = orig_GetFileSizeEx(hFile, lpFileSize);
    if (!result) return FALSE;

    // Try to resolve path for caching
    __try {
        FILE_NAME_INFO fni;
        if (GetFileInformationByHandleEx(hFile, FileNameInfo, &fni, sizeof(fni))) {
            // Simple hash from filename
            uint32_t h = 0x811C9DC5;
            for (DWORD i = 0; i < fni.FileNameLength / 2 && i < 64; i++) {
                wchar_t c = fni.FileName[i];
                if (c >= 'A' && c <= 'Z') c += 32;
                h ^= (uint32_t)(c & 0xFF);
                h *= 0x01000193;
            }
            int slot = h & FSIZE_CACHE_MASK;
            g_fsizeCache[slot].pathHash = h;
            g_fsizeCache[slot].fileSize = *lpFileSize;
            g_fsizeCache[slot].valid = true;
            g_fsizeMisses++;
            return TRUE;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    g_fsizeMisses++;
    return TRUE;
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
// 18. WaitForSingleObject — Spin-First for Short Waits
//
// WHAT: Spins in user-mode for short timeout waits before entering kernel.
// WHY:  WaitForSingleObject with timeout <= 1ms is common in WoW
//       (MPQ streaming thread, network thread). Kernel transitions
//       for micro-waits cost ~5-10μs vs ~0.5μs for a spin check.
// HOW:  1. For timeout <= 1ms: spin 32x with _mm_pause + zero-wait
//       2. If not signaled after spin → fall back to original
//       3. For timeout > 1ms: use original (kernel wait is appropriate)
// STATUS: Active — reduces kernel transitions for micro-waits
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
// 19. GetModuleHandleA — Cache
//
// WHAT: Caches GetModuleHandle results for loaded DLLs.
// WHY:  WoW and addons frequently call GetModuleHandle to check
//       if certain DLLs are loaded (e.g., "msvcrt.dll", "ws2_32.dll",
//       "d3d9.dll"). Each call walks the PEB module list.
// HOW:  1. 128-slot direct-mapped cache using case-insensitive FNV-1a hash
//       2. Cache is write-through — no invalidation needed (modules
//          don't unload during WoW's lifetime)
// STATUS: Active — eliminates PEB walk on every call
// ================================================================

static constexpr int MOD_CACHE_SIZE = 128;
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
// 20. lstrcmpA / lstrcmpiA — Fast Path
//
// WHAT: User-mode fast path for simple string comparisons.
// WHY:  lstrcmp/lstrcmpi are Win32 API calls with overhead.
//       For pure ASCII strings (most WoW paths, addon names),
//       a simple byte-by-byte comparison is faster.
// HOW:  1. hooked_lstrcmpA: strlen + memcmp if same length,
//       else byte-by-byte compare (bail on non-ASCII → original)
//       2. hooked_lstrcmpiA: same but with inline uppercase
//       3. Falls back to original for non-ASCII (Cyrillic, etc.)
//       4. Strings > 256 chars go directly to original
// STATUS: Active — faster than API for ASCII strings
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
// 21. GetPrivateProfileStringA — Cache
//
// WHAT: Caches INI file reads (config.wtf, bindings-cache.wtf).
// WHY:  WoW reads .wtf files during addon init, key binding setup,
//       and CVAR initialization. Each read is a file open + parse.
//       Values rarely change during a session.
// HOW:  1. 128-slot cache using combined hash of (appName, keyName)
//       2. Only caches successful reads (value retrieved)
//       3. Returns cached string directly — no file I/O
// STATUS: Active — eliminates redundant .wtf file reads
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
//  Thread Affinity — Background Worker CPU Pinning
//
// WHAT: Pins WoW async task threads to cores 2..N-1.
// WHY:  WoW creates background threads for MPQ streaming, UI loading,
//       and network I/O. If the scheduler moves these to the same core
//       as the main thread, it causes preemption and frame stutter.
// HOW:  1. Gets process affinity mask (respects user/task manager settings)
//       2. Skips if <=2 cores (no spare cores for pinning)
//       3. Hooks internal WoW thread creation function (0x008D2110)
//       4. Sets ideal processor for each new background thread
// STATUS: Active — process-affinity-mask aware, safe on all configs
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

static bool InstallThreadAffinity() {
#if CRASH_TEST_DISABLE_THREAD_AFFINITY
    Log("Thread affinity: DISABLED (crash isolation)");
    return false;
#else
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
    if (MH_CreateHook(p, (void*)Hooked_ThreadWorker, (void**)&orig_ThreadWorker) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;

    Log("Thread affinity: ACTIVE (process-mask aware, %d worker cores)", g_affinityCount);
    return true;
#endif
}

// ================================================================
// VA Arena v2 — High-address reserved arena with caller filtering
// ================================================================

static bool IsWowExeCaller(uintptr_t retAddr) {
    if (g_vaArenaWowBase == 0 || g_vaArenaWowEnd == 0) return false;
    return (retAddr >= g_vaArenaWowBase && retAddr < g_vaArenaWowEnd);
}

static LPVOID WINAPI Hooked_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flType, DWORD flProtect) {
    // Strict filter: only intercept large, committed, non-fixed allocations
    if (g_vaArenaActive &&
        lpAddress == NULL &&
        dwSize >= VA_ARENA_PAGE_SIZE &&
        (flType & MEM_COMMIT) &&
        !(flType & MEM_RESERVE) &&
        !(flType & MEM_RESET) &&
        !(flType & MEM_PHYSICAL) &&
        !(flType & MEM_LARGE_PAGES) &&
        (flProtect == PAGE_READONLY || flProtect == PAGE_READWRITE ||
         flProtect == PAGE_EXECUTE_READ || flProtect == PAGE_EXECUTE_READWRITE))
    {
#if !CRASH_TEST_DISABLE_VA_ARENA
        // Caller filter: only service allocations from Wow.exe code
        uintptr_t retAddr = (uintptr_t)_ReturnAddress();
        if (!IsWowExeCaller(retAddr)) {
            goto va_fallback;
        }

        __try {
            SIZE_T pagesNeeded = (dwSize + VA_ARENA_PAGE_SIZE - 1) / VA_ARENA_PAGE_SIZE;
            if (pagesNeeded > VA_ARENA_MAX_PAGES - g_vaArenaUsedPages)
                goto va_fallback;

            AcquireSRWLockExclusive(&g_vaArenaLock);
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

            // Commit the full span from OS
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

va_fallback:
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
                // Not an arena head page — fallback
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

vf_fallback:
    return orig_VirtualFree(lpAddress, dwSize, dwFreeType);
}

static bool InstallVAArena() {
#if CRASH_TEST_DISABLE_VA_ARENA
    Log("VA Arena: DISABLED (crash isolation)");
    return false;
#else
    // Determine Wow.exe image range for caller filtering
    HMODULE hWow = GetModuleHandleA(NULL);
    if (!hWow) {
        Log("VA Arena: SKIP (cannot get Wow.exe handle)");
        return false;
    }
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hWow, &modInfo, sizeof(modInfo))) {
        Log("VA Arena: SKIP (cannot get Wow.exe module info)");
        return false;
    }
    g_vaArenaWowBase = (uintptr_t)hWow;
    g_vaArenaWowEnd  = g_vaArenaWowBase + modInfo.SizeOfImage;

    // Pre-reserve 512MB in high address space
    g_vaArenaSize = VA_ARENA_MAX_PAGES * VA_ARENA_PAGE_SIZE;
    g_vaArenaBase = VirtualAlloc(NULL, g_vaArenaSize, MEM_RESERVE | MEM_TOP_DOWN, PAGE_NOACCESS);
    if (!g_vaArenaBase) {
        // Fallback: normal reserve without MEM_TOP_DOWN
        g_vaArenaBase = VirtualAlloc(NULL, g_vaArenaSize, MEM_RESERVE, PAGE_NOACCESS);
        if (!g_vaArenaBase) {
            Log("VA Arena: SKIP (cannot reserve 512MB block)");
            return false;
        }
        Log("VA Arena: ACTIVE (512MB block @ 0x%08X, Wow.exe caller-filtered, >=64KB, SEH-guarded)",
            (unsigned)(uintptr_t)g_vaArenaBase);
    } else {
        Log("VA Arena: ACTIVE (512MB high block @ 0x%08X, Wow.exe caller-filtered, >=64KB, SEH-guarded)",
            (unsigned)(uintptr_t)g_vaArenaBase);
    }

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
            CloseHandle(CreateThread(NULL, 0, MainThread, NULL, 0, NULL));
            break;
        case DLL_PROCESS_DETACH:
            if (reserved != NULL) {
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

            // Dynamic FreeLibrary — safe to clean up
            LuaFastPath::Shutdown();
            LuaInternals::Shutdown();
            ApiCache::Shutdown();
            UICache::Shutdown();                       
            CombatLogOpt::Shutdown();
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
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            for (int i = 0; i < MAX_CACHED_HANDLES; i++) {
                if (g_readCache[i].buffer) { mi_free(g_readCache[i].buffer); g_readCache[i].buffer = nullptr; }
            }
            Log("wow_optimize.dll unloaded (clean)");
            LogClose();
            break;
    }
    return TRUE;
}