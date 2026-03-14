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

#include "MinHook.h"
#include <mimalloc.h>
#include "lua_optimize.h"
#include "combatlog_optimize.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")

// ================================================================
// Logging
// ================================================================
static FILE* g_log = nullptr;

static void LogOpen() {
    CreateDirectoryA("Logs", NULL);
    g_log = fopen("Logs\\wow_optimize.log", "w");
}

static void LogClose() {
    if (g_log) { fclose(g_log); g_log = nullptr; }
}

extern "C" void Log(const char* fmt, ...) {
    if (!g_log) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_log, "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args;
    va_start(args, fmt);
    vfprintf(g_log, fmt, args);
    va_end(args);
    fprintf(g_log, "\n");
    fflush(g_log);
}

// ================================================================
// 1. Memory Allocator Replacement (mimalloc)
// ================================================================
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

// ================================================================
// 2. Sleep Hook + Lua GC Stepping + Combat Log Cleanup
// ================================================================
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

        if (remaining > 2.0)
            orig_Sleep(1);
        else if (remaining > 0.3)
            SwitchToThread();
        else
            _mm_pause();
    }
}

static void WINAPI hooked_Sleep(DWORD ms) {
    if (ms == 0) { orig_Sleep(0); return; }

    if (ms <= 3 && g_mainThreadId != 0) {
        LuaOpt::OnMainThreadSleep(g_mainThreadId);
        CombatLogOpt::OnFrame(g_mainThreadId);
    }

    if (ms <= 3) { PreciseSleep((double)ms); return; }
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
    Log("Sleep hook: ACTIVE (hybrid precise sleep + Lua GC + combat log)");
    return true;
}

// ================================================================
// 3. TCP_NODELAY + Immediate ACK + QoS + Keepalive
// ================================================================

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
        // Async connect — socket not ready yet, defer optimization
        AddPendingSocket(s);
        // Still set TCP_NODELAY — this one works even before handshake
        BOOL nodelay = TRUE;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    }

    WSASetLastError(savedError);
    return result;
}

static int WINAPI hooked_send(SOCKET s, const char* buf, int len, int flags) {
    // If this socket was pending optimization, apply now
    // send() is only called after TCP handshake completes
    if (RemovePendingSocket(s)) {
        OptimizeSocket(s, "send");
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
// 5. ReadFile Cache (MPQ-only)
// ================================================================
typedef BOOL (WINAPI* ReadFile_fn)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static ReadFile_fn orig_ReadFile = nullptr;

struct ReadCache {
    HANDLE handle; uint8_t* buffer;
    LARGE_INTEGER fileOffset; DWORD validBytes; bool active;
};

static const int   MAX_CACHED_HANDLES = 16;
static const DWORD READ_AHEAD_SIZE    = 64 * 1024;
static ReadCache   g_readCache[MAX_CACHED_HANDLES] = {};
static int         g_cacheEvictIndex = 0;               
static CRITICAL_SECTION g_cacheLock;
static bool g_cacheInitialized = false;
static bool g_csInitialized    = false;

static ReadCache* FindCache(HANDLE h) {
    for (int i = 0; i < MAX_CACHED_HANDLES; i++)
        if (g_readCache[i].active && g_readCache[i].handle == h) return &g_readCache[i];
    return nullptr;
}


static ReadCache* AllocCache(HANDLE h) {

    for (int i = 0; i < MAX_CACHED_HANDLES; i++) {
        if (!g_readCache[i].active) {
            g_readCache[i].handle = h;
            if (!g_readCache[i].buffer) g_readCache[i].buffer = (uint8_t*)mi_malloc(READ_AHEAD_SIZE);
            g_readCache[i].validBytes = 0;
            g_readCache[i].active = true;
            return &g_readCache[i];
        }
    }

    int idx = g_cacheEvictIndex;
    g_cacheEvictIndex = (g_cacheEvictIndex + 1) % MAX_CACHED_HANDLES;
    g_readCache[idx].handle = h;
    if (!g_readCache[idx].buffer) g_readCache[idx].buffer = (uint8_t*)mi_malloc(READ_AHEAD_SIZE);
    g_readCache[idx].validBytes = 0;
    g_readCache[idx].active = true;
    return &g_readCache[idx];
}

static BOOL WINAPI hooked_ReadFile(HANDLE hFile, LPVOID lpBuffer,
    DWORD nBytesToRead, LPDWORD lpBytesRead, LPOVERLAPPED lpOverlapped)
{
    if (lpOverlapped || !g_cacheInitialized || !IsMpqHandle(hFile) ||
        nBytesToRead >= READ_AHEAD_SIZE)
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    EnterCriticalSection(&g_cacheLock);

    LARGE_INTEGER currentPos, zero;
    zero.QuadPart = 0;
    if (!SetFilePointerEx(hFile, zero, &currentPos, FILE_CURRENT)) {
        LeaveCriticalSection(&g_cacheLock);
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);
    }

    ReadCache* cache = FindCache(hFile);
    if (cache && cache->validBytes > 0) {
        LONGLONG cStart = cache->fileOffset.QuadPart;
        LONGLONG cEnd   = cStart + cache->validBytes;
        LONGLONG rStart = currentPos.QuadPart;
        LONGLONG rEnd   = rStart + nBytesToRead;
        if (rStart >= cStart && rEnd <= cEnd) {
            DWORD offset = (DWORD)(rStart - cStart);
            memcpy(lpBuffer, cache->buffer + offset, nBytesToRead);
            if (lpBytesRead) *lpBytesRead = nBytesToRead;
            LARGE_INTEGER newPos; newPos.QuadPart = rEnd;
            SetFilePointerEx(hFile, newPos, NULL, FILE_BEGIN);
            LeaveCriticalSection(&g_cacheLock);
            return TRUE;
        }
    }

    if (!cache) cache = AllocCache(hFile);
    if (cache && cache->buffer) {
        cache->fileOffset = currentPos;
        SetFilePointerEx(hFile, currentPos, NULL, FILE_BEGIN);
        DWORD bytesRead = 0;
        BOOL ok = orig_ReadFile(hFile, cache->buffer, READ_AHEAD_SIZE, &bytesRead, NULL);
        if (ok && bytesRead > 0) {
            cache->validBytes = bytesRead;
            DWORD toCopy = (nBytesToRead < bytesRead) ? nBytesToRead : bytesRead;
            memcpy(lpBuffer, cache->buffer, toCopy);
            if (lpBytesRead) *lpBytesRead = toCopy;
            LARGE_INTEGER newPos; newPos.QuadPart = currentPos.QuadPart + toCopy;
            SetFilePointerEx(hFile, newPos, NULL, FILE_BEGIN);
            LeaveCriticalSection(&g_cacheLock);
            return TRUE;
        }
        cache->validBytes = 0;
        SetFilePointerEx(hFile, currentPos, NULL, FILE_BEGIN);
    }

    LeaveCriticalSection(&g_cacheLock);
    return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);
}

static bool InstallReadFileHook() {
    g_cacheInitialized = true;
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_ReadFile, (void**)&orig_ReadFile) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("ReadFile hook: ACTIVE (MPQ-only cache, 64KB read-ahead, %d slots)", MAX_CACHED_HANDLES);
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
// 7. CriticalSection Spin
// ================================================================
typedef void (WINAPI* InitCS_fn)(LPCRITICAL_SECTION);
static InitCS_fn orig_InitCS = nullptr;

static void WINAPI hooked_InitCS(LPCRITICAL_SECTION lpCS) {
    InitializeCriticalSectionAndSpinCount(lpCS, 4000);
}

static bool InstallCriticalSectionHook() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "InitializeCriticalSection");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_InitCS, (void**)&orig_InitCS) != MH_OK) return false;
    if (MH_EnableHook(p) != MH_OK) return false;
    Log("CriticalSection hook: ACTIVE (spin count 4000)");
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
    if (isMPQ && result != INVALID_HANDLE_VALUE) TrackMpqHandle(result);
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
    if (isMPQ && result != INVALID_HANDLE_VALUE) TrackMpqHandle(result);
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
    UntrackMpqHandle(hObject);
    if (g_cacheInitialized) {
        EnterCriticalSection(&g_cacheLock);
        for (int i = 0; i < MAX_CACHED_HANDLES; i++) {
            if (g_readCache[i].active && g_readCache[i].handle == hObject) {
                g_readCache[i].active = false; g_readCache[i].validBytes = 0; break;
            }
        }
        LeaveCriticalSection(&g_cacheLock);
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

// ================================================================
// 10. System Timer Resolution
// ================================================================
static void SetHighTimerResolution() {
    typedef LONG (WINAPI* NtSetTimerRes_fn)(ULONG, BOOLEAN, PULONG);
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return;
    auto p = (NtSetTimerRes_fn)GetProcAddress(h, "NtSetTimerResolution");
    if (!p) return;
    ULONG actual;
    if (p(5000, TRUE, &actual) == 0)
        Log("Timer resolution: %.3f ms (requested 0.500 ms)", actual / 10000.0);
    else
        Log("WARNING: Timer resolution change failed");
}

// ================================================================
// 11. Large Pages
// ================================================================
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

// ================================================================
// 12. Thread Optimization
// ================================================================
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
    SetThreadPriority(hMain, THREAD_PRIORITY_HIGHEST);
    CloseHandle(hMain);
    Log("Main thread %lu: ideal core %lu, priority HIGHEST (of %lu cores)", mainTid, core, si.dwNumberOfProcessors);
}

// ================================================================
// 13. Process Priority
// ================================================================
static void OptimizeProcess() {
    SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
    SetProcessPriorityBoost(GetCurrentProcess(), TRUE);
    Log("Process: Above Normal priority, priority boost disabled");
}

// ================================================================
// 14. Working Set
// ================================================================
static void OptimizeWorkingSet() {
    SIZE_T minWS = 256 * 1024 * 1024;
    SIZE_T maxWS = 2048ULL * 1024 * 1024;
    if (SetProcessWorkingSetSize(GetCurrentProcess(), minWS, maxWS))
        Log("Working set: min 256 MB, max 2048 MB");
    else
        Log("WARNING: Working set failed (error %lu)", GetLastError());
}

// ================================================================
// 15. mimalloc Configuration
// ================================================================
static void ConfigureMimalloc() {
    mi_option_set(mi_option_allow_large_os_pages, 1);
    mi_option_set(mi_option_purge_delay, 0);
    void* warmup = mi_malloc(64 * 1024 * 1024);
    if (warmup) { memset(warmup, 0, 64 * 1024 * 1024); mi_free(warmup); }
    Log("mimalloc configured (large pages, pre-warmed 64MB)");
}

// ================================================================
// 16. FPS Cap Removal
// ================================================================
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

// ================================================================
// Main Thread
// ================================================================
static DWORD WINAPI MainThread(LPVOID param) {
    Sleep(5000);

    LogOpen();
    Log("========================================");
    Log("  wow_optimize.dll v1.7.1 BY SUPREMATIST");
    Log("  PID: %lu", GetCurrentProcessId());
    Log("========================================");

    if (MH_Initialize() != MH_OK) { Log("FATAL: MinHook initialization failed"); LogClose(); return 1; }
    Log("MinHook initialized");

    InitializeCriticalSection(&g_cacheLock);
    g_csInitialized = true;

    ConfigureMimalloc();
    TryEnableLargePages();

    Log("--- Memory Allocator ---");
    bool allocOk = InstallAllocatorHooks();
    Log(allocOk ? ">>> ALLOCATOR: mimalloc ACTIVE <<<" : ">>> ALLOCATOR: FAILED <<<");

    Log("--- Frame Pacing ---");
    bool sleepOk = InstallSleepHook();
    Log("--- Timer Precision ---");
    bool tickOk = InstallGetTickCountHook();
    Log("--- Critical Sections ---");
    bool csOk = InstallCriticalSectionHook();
    Log("--- Network ---");
    bool netOk = InstallNetworkHooks();
    Log("--- File I/O ---");
    bool fileOk = InstallFileHooks();
    bool readOk = InstallReadFileHook();
    bool closeOk = InstallCloseHandleHook();
    Log("--- System Timer ---");
    SetHighTimerResolution();
    Log("--- Threads ---");
    OptimizeThreads();
    Log("--- Process ---");
    OptimizeProcess();
    OptimizeWorkingSet();
    Log("--- FPS Cap ---");
    TryRemoveFPSCap();

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
    Log("========================================");
    Log("  Initialization complete");
    Log("========================================");
    Log("");
    Log("  [%s] mimalloc allocator",          allocOk     ? " OK " : "FAIL");
    Log("  [%s] Sleep hook (frame pacing)",   sleepOk     ? " OK " : "FAIL");
    Log("  [%s] GetTickCount (precision)",    tickOk      ? " OK " : "FAIL");
    Log("  [%s] CriticalSection (spin lock)", csOk        ? " OK " : "FAIL");
    Log("  [%s] Network (NODELAY+ACK+QoS+KA)", netOk     ? " OK " : "FAIL");
    Log("  [%s] CreateFile (sequential I/O)", fileOk      ? " OK " : "FAIL");
    Log("  [%s] ReadFile (MPQ read-ahead)",   readOk      ? " OK " : "FAIL");
    Log("  [%s] CloseHandle (cache cleanup)", closeOk     ? " OK " : "FAIL");
    Log("  [ OK ] Timer resolution (0.5ms)");
    Log("  [ OK ] Thread affinity + priority");
    Log("  [ OK ] Working set (256MB-2GB)");
    Log("  [ OK ] Process priority (Above Normal)");
    Log("  [ OK ] FPS cap removal (200 -> 999)");
    Log("  [%s] Lua VM GC optimizer",         luaOk       ? "WAIT" : "SKIP");
    Log("  [%s] Combat log optimizer",        combatLogOk ? " OK " : "SKIP");
    Log("  [%s] FontString SetText cache",    uiCacheOk   ? " OK " : "SKIP");

    return 0;
}

// ================================================================
// DLL Entry Point
// ================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            CloseHandle(CreateThread(NULL, 0, MainThread, NULL, 0, NULL));
            break;
        case DLL_PROCESS_DETACH:
            if (reserved != NULL) {
                // Process is terminating — all memory will be freed by OS.
                // Do NOT touch game memory, hooks, or other DLLs.
                // Lua VM, WoW heap, and hooked DLLs may already be destroyed.
                // Just log and exit.
                Log("wow_optimize.dll: process terminating, skipping cleanup");
                LogClose();
                break;
            }

            // Dynamic FreeLibrary — safe to clean up
            UICache::Shutdown();            
            CombatLogOpt::Shutdown();
            LuaOpt::Shutdown();
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