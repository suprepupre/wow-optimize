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

// Crash isolation toggles. Set to 1 only in test builds.
#define CRASH_TEST_DISABLE_COMPARESTRING   0
#define CRASH_TEST_DISABLE_GETFILEATTR     0
#define CRASH_TEST_DISABLE_GLOBALALLOC     1
#define CRASH_TEST_DISABLE_CS_ENTER        0
#define CRASH_TEST_DISABLE_SETFILEPOINTER  0
#define CRASH_TEST_DISABLE_READFILE        0
#define CRASH_TEST_DISABLE_ISBADPTR        0
#define CRASH_TEST_DISABLE_MPQ_MMAP        1
#define CRASH_TEST_DISABLE_QPC_CACHE       0
#define CRASH_TEST_DISABLE_LUA_INTERNALS   0
#define CRASH_TEST_DISABLE_THREAD_AFFINITY  0
#define CRASH_TEST_DISABLE_SHORT_WAIT_SPIN  0

// Forward declarations & global state
static bool IsExecutableMemory(uintptr_t addr);
static bool InstallThreadAffinity();
static bool InstallWaitSpin();

static bool  g_threadAffOk    = false;
static bool  g_waitSpinOk     = false;
static long  g_spinHits       = 0;
static long  g_spinFallbacks  = 0;
static LONG  g_bgThreadIdx    = 0;
static DWORD g_affinityCores[16] = {0};
static int   g_affinityCount  = 0;

typedef int (__cdecl *fn_ThreadWorker)(void* outHandle, LPTHREAD_START_ROUTINE start, LPVOID param, int priority, int a5, int a6, HMODULE hMod);
static fn_ThreadWorker orig_ThreadWorker = nullptr;

typedef DWORD (WINAPI* WaitSingle_fn)(HANDLE, DWORD);
static WaitSingle_fn orig_WaitSingle = nullptr;

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")

bool   g_isMultiClient = false;
static HANDLE g_instanceMutex = NULL;
static DWORD  g_nextStatsDumpTick = 0;
static DWORD  g_nextMiCollectTick = 0;
static void   DumpPeriodicStats();
// Forward declarations for MPQ prefetch
static void PrefetchMappedMPQs();
static void ResetPrefetchFlag();

// ================================================================
// Logging — ring buffer + background thread
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
// ================================================================

// Old: linear scan of 256-element array on EVERY ReadFile call
// New: open-addressing hash table — O(1) average lookup
// Key insight: HANDLE values are always aligned to 4 bytes,
//   so we shift right by 2 for better hash distribution

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
//  For MPQ files between 1MB and 256MB, memory mapping
//  eliminates kernel transitions on every read.
//  Reads become simple memcpy from user-space mapped memory.
//
//  Limits:
//    - Min file: 1 MB (small files not worth mapping)
//    - Max file: 256 MB (32-bit address space constraint)
//    - Max total: 512 MB across all mappings
//    - Max count: 32 simultaneous mappings
//
//  Falls back to read-ahead cache for files outside these limits.
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
// CRASH_TEST_DISABLE_CS_ENTER disables the TryEnter path for isolation.

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
//  For pure ASCII strings with simple flags (case-insensitive or
//  ordinal), we can do the comparison directly in user mode.
//  Falls back to original for non-ASCII (Cyrillic, Korean, etc.)
//  and complex locale flags.
//
//  Return values: CSTR_LESS_THAN(1), CSTR_EQUAL(2), CSTR_GREATER_THAN(3)
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
//  Only caches results for files that EXIST (not INVALID).
//  Files that don't exist are not cached because they might
//  be created later (addons, config, screenshots, etc.)
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
//  WoW uses the legacy 32-bit SetFilePointer API which has
//  awkward error handling (INVALID_SET_FILE_POINTER + GetLastError)
//  and slightly more overhead than SetFilePointerEx.
//
//  We redirect to SetFilePointerEx which:
//    - Has cleaner semantics (BOOL return)
//    - Is the "real" implementation internally
//    - Avoids double error-code checking overhead
//
//  WoW is 32-bit so all file sizes fit in 32 bits anyway.
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
//  GMEM_MOVEABLE allocations use a different mechanism
//  (GlobalLock/GlobalUnlock) and MUST stay on the original
//  heap to work correctly. We only optimize GMEM_FIXED.
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
//  For NULL or obvious bad pointers, return TRUE immediately.
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
// Uses PrefetchVirtualMemory (Win8+) or sequential touch fallback.

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

// 9d. Multi-client detection via named mutex, adjusts timer and sleep behavior.

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

// 11. Large pages requires SeLockMemoryPrivilege.
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

// 12. Thread optimization : ideal processor, priority.
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
static void OptimizeProcess() {
    SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
    SetProcessPriorityBoost(GetCurrentProcess(), TRUE);
    Log("Process: Above Normal priority, priority boost disabled");
}

// 14. Working set.
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

// 16. FPS cap removal - patches CMP EAX, 200 to CMP EAX, 999.
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
// WoW often hangs on exit so DLL_PROCESS_DETACH stats are unreliable.

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

    Log("--- Thread Affinity ---");
    g_threadAffOk = InstallThreadAffinity();

    Log("--- Wait Spin ---");
    g_waitSpinOk = InstallWaitSpin();

    Log("");
    Log("--- Lua VM Optimizer ---");
    bool luaOk = LuaOpt::PrepareFromWorkerThread();

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

    return 0;
}

// ================================================================
//  Thread Affinity — Background Worker CPU Pinning
//  Forces async tasks (MPQ, UI, network) to cores 2..N-1.
//  Protects main thread from scheduler preemption.
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
    SYSTEM_INFO si; GetSystemInfo(&si);
    int total = (int)si.dwNumberOfProcessors;
    if (total <= 2) { Log("Thread affinity: SKIP (<=2 cores)"); return false; }

    g_affinityCount = 0;
    for (int i = 2; i < total && g_affinityCount < 16; i++)
        g_affinityCores[g_affinityCount++] = i;

    void* p = (void*)0x008D2110;
    if (!IsExecutableMemory((uintptr_t)p)) return false;
    if (MH_CreateHook(p, (void*)Hooked_ThreadWorker, (void**)&orig_ThreadWorker) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;

    Log("Thread affinity: ACTIVE (cores 2-%d, %d workers mapped)", total - 1, g_affinityCount);
    return true;
#endif
}

// ================================================================
//  WaitForSingleObject — Short-Wait Spin Fast Path
//  Replaces kernel transitions for <=2ms waits with QPC spin.
//  Strictly limited to events/timers. Falls back instantly on mismatch.
// ================================================================

static DWORD WINAPI Hooked_WaitSingle(HANDLE h, DWORD ms) {
    if (!h || ms == INFINITE || ms > 2) {
        g_spinFallbacks++;
        return orig_WaitSingle(h, ms);
    }

#if !CRASH_TEST_DISABLE_SHORT_WAIT_SPIN
    __try {
        LARGE_INTEGER start, now, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        LONGLONG limit = (freq.QuadPart * ms) / 1000;

        for (int i = 0; i < 5000; i++) {
            QueryPerformanceCounter(&now);
            if ((now.QuadPart - start.QuadPart) >= limit) break;
            if (WaitForSingleObject(h, 0) == WAIT_OBJECT_0) return WAIT_OBJECT_0;
            if (i < 50) _mm_pause();
            else if (i < 500) SwitchToThread();
            else YieldProcessor();
        }
        return WAIT_TIMEOUT;
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
#endif

    g_spinFallbacks++;
    return orig_WaitSingle(h, ms);
}

static bool InstallWaitSpin() {
#if CRASH_TEST_DISABLE_SHORT_WAIT_SPIN
    Log("Wait spin: DISABLED (crash isolation)");
    return false;
#else
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WaitForSingleObject");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)Hooked_WaitSingle, (void**)&orig_WaitSingle) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("Wait spin: ACTIVE (<=2ms QPC spin, hard fallback on timeout)");
    return true;
#endif
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
            if (g_waitSpinOk && (g_spinHits + g_spinFallbacks) > 0)
                Log("Wait spin: %ld fast, %ld fallback", g_spinHits, g_spinFallbacks);
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
                                // mapping handles closed by OS on process exit
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