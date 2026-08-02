// ============================================================================
// Module: hooks_async.cpp
// Description: Installs and manages target intercepts for subsystem `hooks_async.cpp`.
// Safety & Threading: Stack layouts and register conventions must match target function definitions exactly.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <intrin.h>
#include <cstdio>
#include "MinHook.h"
#include "version.h"
#include "hooks_async.h"

typedef unsigned char _BYTE;
typedef unsigned short _WORD;
typedef unsigned long _DWORD;

extern "C" void Log(const char* fmt, ...);

// ================================================================
// Memory validation
// ================================================================
static bool IsReadable(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD);
}

// ================================================================
// Shared Worker Pool Infrastructure
// ================================================================
// Lightweight SPMC ring buffer for fire-and-forget tasks.
// Each hook enqueues a task; N worker threads dequeue and process.
// Pattern established in combatlog_mt.cpp and reused here.

static constexpr int ASYNC_POOL_WORKERS = 2;  // careful: more workers = more contention
static constexpr int TASK_QUEUE_SIZE    = 2048;
static constexpr int TASK_QUEUE_MASK    = TASK_QUEUE_SIZE - 1;

enum AsyncTaskType : uint8_t {
    TASK_NONE = 0,
    TASK_PARTICLE_MATRIX,      // particle emitter matrix calc
    TASK_ADT_PREFETCH,         // terrain chunk prefetch
    TASK_DBC_PARSE,            // DBC record parse
    TASK_CDATA_INFLATE,        // CDataStore decompress
    TASK_STRING_SANITIZE,      // batch string sanitization
};

struct AsyncTask {
    AsyncTaskType type;
    uint32_t      param1;   // generic: pointer or size
    uint32_t      param2;   // generic: pointer or count
    uint32_t      param3;   // generic: flags or pointer
    volatile LONG ready;     // 1 = task populated, 0 = consumed
};

static AsyncTask    g_taskQueue[TASK_QUEUE_SIZE] = {};
static volatile LONG g_taskHead    = 0;  // consumer index
static volatile LONG g_taskTail    = 0;  // producer index
static HANDLE       g_workerThreads[ASYNC_POOL_WORKERS] = {};
static HANDLE       g_workerEvent = NULL;
static volatile bool g_asyncShutdown = false;
static bool         g_asyncInit = false;

static volatile LONG64 g_tasksQueued    = 0;
static volatile LONG64 g_tasksProcessed  = 0;
static volatile LONG64 g_tasksDropped    = 0;
static volatile LONG64 g_tasksByType[6]  = {0};

static void ProcessAdtPrefetch(const char* path) {
    void* handle = nullptr;
    typedef int (__stdcall *SFileOpenFileEx_t)(void*, const char*, int, void**);
    SFileOpenFileEx_t openFile = (SFileOpenFileEx_t)0x00424B50;

    typedef int (__stdcall *SFileCloseFile_t)(void*);
    SFileCloseFile_t closeFile = (SFileCloseFile_t)0x00422910;

    typedef int (__stdcall *SFileReadFile_t)(int, void*, unsigned int, int*, int, int);
    SFileReadFile_t readFile = (SFileReadFile_t)0x00422530;

    typedef int (__stdcall *SFileGetFileSize_t)(void*, int*);
    SFileGetFileSize_t getFileSize = (SFileGetFileSize_t)0x004218C0;

    if (openFile(nullptr, path, 0, &handle)) {
        int size = getFileSize(handle, nullptr);
        if (size > 0 && size < 15 * 1024 * 1024) { // sanity check < 15MB
            void* buf = malloc(size);
            if (buf) {
                int readBytes = 0;
                readFile((int)handle, buf, size, &readBytes, 0, 0);
                free(buf);
            }
        }
        closeFile(handle);
    }
}

// ---- Worker thread ----
static DWORD WINAPI AsyncWorkerProc(LPVOID) {
    while (!g_asyncShutdown) {
        WaitForSingleObject(g_workerEvent, 1);

        LONG head = g_taskHead;
        LONG tail = InterlockedCompareExchange(&g_taskTail, 0, 0);

        while (head != tail && !g_asyncShutdown) {
            int slot = head & TASK_QUEUE_MASK;
            AsyncTask* task = &g_taskQueue[slot];

            if (task->ready) {
                // Process task based on type
                switch (task->type) {
                    case TASK_PARTICLE_MATRIX:
                        // Offloaded matrix math — see ProcessParticleMatrix()
                        break;

                    case TASK_ADT_PREFETCH:
                        if (task->param1) {
                            char* path = (char*)task->param1;
                            ProcessAdtPrefetch(path);
                            free(path);
                        }
                        break;

                    case TASK_DBC_PARSE:
                        // Parse a DBC record row
                        break;

                    case TASK_CDATA_INFLATE:
                        // Inflate packet payload
                        break;

                    case TASK_STRING_SANITIZE:
                        // Batch string sanitization (offsets to worker)
                        break;

                    default:
                        break;
                }

                InterlockedIncrement64(&g_tasksProcessed);
                InterlockedExchange(&task->ready, 0);
            }

            head = (head + 1) & 0x7FFFFFFF;
            InterlockedExchange(&g_taskHead, head);
        }
    }
    return 0;
}

// ---- Enqueue a task (called from hooked functions on main thread) ----
static bool EnqueueTask(AsyncTaskType type, uint32_t p1, uint32_t p2, uint32_t p3) {
    if (!g_asyncInit) return false;

    LONG tail = g_taskTail;
    LONG head = InterlockedCompareExchange(&g_taskHead, 0, 0);

    // Check for full queue (leave 1 slot gap)
    if (((tail + 1) & 0x7FFFFFFF) == head) {
        InterlockedIncrement64(&g_tasksDropped);
        return false;
    }

    int slot = tail & TASK_QUEUE_MASK;
    AsyncTask* task = &g_taskQueue[slot];

    task->type   = type;
    task->param1 = p1;
    task->param2 = p2;
    task->param3 = p3;
    task->ready  = 1;

    // Memory barrier: ensure task is fully written before tail advances
    _ReadWriteBarrier();
    InterlockedExchange(&g_taskTail, (tail + 1) & 0x7FFFFFFF);

    InterlockedIncrement64(&g_tasksQueued);
    InterlockedIncrement64(&g_tasksByType[type]);

    SetEvent(g_workerEvent);
    return true;
}

// ================================================================
// 1. Particle Matrix Math Offloading
// ================================================================
// WoW's CParticleEmitter::Update iterates all particle vertices,
// computing position, velocity, color, and size per-particle using
// scalar FPU math. For emitters with 500+ particles (common in
// spell effects), this is a significant frame-time hog.
//
// Strategy:
//   Phase 1 (safe): SSE2-accelerate the inner math (matrix multiply,
//     vector transform, color interpolation) inline on the main thread.
//   Phase 2 (risky): Offload the entire emitter update to a worker
//     thread for off-screen emitters. Renders on next frame's data.
//     DISABLED by default — D3D vertex buffer writes from worker
//     threads are NOT safe (see Lesson #1 in CONTEXT.md).
//
// Hook target: CParticleEmitter::Update or the particle system manager's
// per-emitter dispatch loop.

#ifndef ADDR_PARTICLE_EMITTER_UPDATE
#define ADDR_PARTICLE_EMITTER_UPDATE 0x007C2700
#endif

#define TEST_DISABLE_PARTICLE_ASYNC 1  // Enabled!

static void* orig_ParticleEmitterUpdate = nullptr;

typedef void (__cdecl *sub_7C25D0_t)(int emitter, int a1, int a2, int a3, int a4, int a5);
static const sub_7C25D0_t call_sub_7C25D0 = (sub_7C25D0_t)0x007C25D0;

typedef bool (__fastcall *sub_7B3990_t)(void* ecx, int edx, int a1, int a2);
static const sub_7B3990_t call_sub_7B3990 = (sub_7B3990_t)0x007B3990;

struct ParticleTaskData {
    int emitter;
    int a1, a2, a3, a4, a5;
};

static ParticleTaskData g_particleTasks[1024];
static volatile LONG g_particleTaskIndex = 0;
static volatile LONG g_particleTaskCount = 0;

static DWORD WINAPI ParticleWorkerThread(LPVOID) {
    while (true) {
        LONG idx = InterlockedIncrement(&g_particleTaskIndex) - 1;
        if (idx >= g_particleTaskCount) break;

        const ParticleTaskData& task = g_particleTasks[idx];
        __try {
            call_sub_7C25D0(task.emitter, task.a1, task.a2, task.a3, task.a4, task.a5);
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return 0;
}

extern "C" char __cdecl Hooked_ParticleEmitterUpdate(int a1, int a2, int a3, int a4, int a5, int a6) {
    *(float *)(a5 + 8) = 1.05f;
    *(_DWORD *)a5 = 0;
    *(float *)(a5 + 24) = 1.05f;
    *(_DWORD *)(a5 + 16) = 0;
    *(float *)(a4 + 8) = 1.05f;
    *(_DWORD *)a4 = 0;
    *(float *)(a4 + 24) = 1.05f;
    *(_DWORD *)(a4 + 16) = 0;

    g_particleTaskCount = 0;
    g_particleTaskIndex = 0;

    if (a6) {
        int v7 = *(_DWORD *)(a6 + 216);
        if ((v7 & 1) == 0 && v7) {
            int v8 = v7;
            while ((v8 & 1) == 0 && v8) {
                int v9 = *(_DWORD *)(v8 + 4);
                if ((*(_BYTE *)(v9 + 12) & 0x20) == 0) {
                    if (call_sub_7B3990((void*)v9, 0, a1, a2)) {
                        if (g_particleTaskCount < 1024) {
                            ParticleTaskData& task = g_particleTasks[g_particleTaskCount++];
                            task.emitter = v9;
                            task.a1 = a1; task.a2 = a2; task.a3 = a3; task.a4 = a4; task.a5 = a5;
                        }
                    }
                }
                v8 = *(_DWORD *)(v8 + *(_DWORD *)(a6 + 208) + 4);
            }
        }
    } else {
        int v10 = *(int*)0x00D25440;
        while ((v10 & 1) == 0 && v10) {
            if ((*(_BYTE *)(v10 + 12) & 0x20) == 0 && call_sub_7B3990((void*)v10, 0, a1, a2)) {
                if (g_particleTaskCount < 1024) {
                    ParticleTaskData& task = g_particleTasks[g_particleTaskCount++];
                    task.emitter = v10;
                    task.a1 = a1; task.a2 = a2; task.a3 = a3; task.a4 = a4; task.a5 = a5;
                }
            }
            v10 = *(_DWORD *)(*(int*)0x00D25438 + v10 + 4);
        }
    }

    if (g_particleTaskCount > 0) {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        int numCores = sysInfo.dwNumberOfProcessors;
        if (numCores < 2) numCores = 2;
        if (numCores > 8) numCores = 8;

        HANDLE threads[8] = {};
        for (int i = 0; i < numCores; i++) {
            threads[i] = CreateThread(NULL, 0, ParticleWorkerThread, NULL, 0, NULL);
        }
        WaitForMultipleObjects(numCores, threads, TRUE, INFINITE);
        for (int i = 0; i < numCores; i++) {
            if (threads[i]) CloseHandle(threads[i]);
        }
    }

    if (!*(_DWORD *)a4 && *(_DWORD *)a5) {
        *(double*)a4 = *(double*)a5;
        *(double*)(a4 + 8) = *(double*)(a5 + 8);
    }
    if (!*(_DWORD *)(a4 + 16) && *(_DWORD *)(a5 + 16)) {
        *(double*)(a4 + 16) = *(double*)(a5 + 16);
        *(double*)(a4 + 24) = *(double*)(a5 + 24);
    }
    if (!*(_DWORD *)a4) {
        if (!*(_DWORD *)(a4 + 16)) return 0;
        *(double*)a4 = *(double*)(a4 + 16);
        *(double*)(a4 + 8) = *(double*)(a4 + 24);
        *(double*)a5 = *(double*)(a5 + 16);
        *(double*)(a5 + 8) = *(double*)(a5 + 24);
        *(_DWORD *)(a4 + 16) = 0;
        *(_DWORD *)(a5 + 16) = 0;
    }
    if (!*(_DWORD *)a5) {
        *(double*)a5 = *(double*)a4;
        *(WORD *)(a5 + 12) = -1;
    }
    if (!*(_DWORD *)(a5 + 16)) {
        *(double*)(a5 + 16) = *(double*)(a4 + 16);
        *(WORD *)(a5 + 28) = -1;
    }
    return 1;
}

// Two SSE2 helpers lived here, SSE2_TransformParticles and SSE2_LerpColors4.
// Both were static with no caller anywhere in the tree - they never ran, and
// they made this file read as though particle transforms and colour blending
// were accelerated when nothing of the sort was wired up.
//
// SSE2_LerpColors4 was also wrong, which is the reason for saying so here
// rather than deleting them quietly: it computed aHi32 from aLo16 instead of
// aHi16 and did the same for b, so it read the low eight bytes twice, ignored
// the high eight entirely, and still stored a full sixteen. If anyone had
// wired it up expecting four particles it would have blended two and
// overwritten the rest. They are in the history if the work is ever picked up.

// ================================================================
// 2. Map (.ADT) Terrain Pre-parsing
// ================================================================
// When a player moves, WoW loads terrain chunks (.adt files) from
// MPQ archives. Each chunk requires:
//   1. MPQ seek + decompress (inflate)
//   2. Vertex height unpacking (16-bit to float conversion)
//   3. Texture layer mapping
//   4. Normal calculation
//
// We hook the terrain chunk request function and speculatively
// prefetch adjacent chunks into memory via async I/O.
//
// Approach:
//   - When chunk (x, y) is requested, also prefetch (x±1, y±1)
//   - Use ReadFileEx (overlapped) for async MPQ reads
//   - Decompress on the async worker thread
//   - Store in a 64-entry LRU cache keyed by ADT coordinates
//
// This avoids stalling the main thread on MPQ I/O latency.
// RISK: MPQ file handles are NOT thread-safe for concurrent reads
// on the SAME handle. Use per-worker duplicated handles or
// restrict to read-only operations with SEH guards.

#ifndef ADDR_ADT_CHUNK_LOAD
#define ADDR_ADT_CHUNK_LOAD 0x007D9A20
#endif

#define TEST_DISABLE_ADT_PREFETCH 1  // Enabled!

// LRU cache for prefetched terrain data
static constexpr int ADT_CACHE_SLOTS = 64;

struct AdtCacheEntry {
    int32_t  x, y;          // terrain tile coordinates
    void*    data;           // decompressed terrain data
    size_t   dataSize;
    uint32_t lastAccess;     // frame counter
    bool     valid;
};

static AdtCacheEntry g_adtCache[ADT_CACHE_SLOTS] = {};
static SRWLOCK      g_adtCacheLock = SRWLOCK_INIT;

static void* orig_AdtChunkLoad = nullptr;

static char g_prefetchHistory[64][260] = {};
static int g_prefetchHistoryIndex = 0;
static SRWLOCK g_prefetchLock = SRWLOCK_INIT;

static bool AddToPrefetchHistory(const char* path) {
    AcquireSRWLockExclusive(&g_prefetchLock);
    for (int i = 0; i < 64; i++) {
        if (strcmp(g_prefetchHistory[i], path) == 0) {
            ReleaseSRWLockExclusive(&g_prefetchLock);
            return false;
        }
    }
    strcpy_s(g_prefetchHistory[g_prefetchHistoryIndex], path);
    g_prefetchHistoryIndex = (g_prefetchHistoryIndex + 1) % 64;
    ReleaseSRWLockExclusive(&g_prefetchLock);
    return true;
}

extern "C" int __cdecl Hooked_sub_7D9A20(void* map_structure) {
    if (map_structure) {
        int x = *(int*)((uintptr_t)map_structure + 0x48);
        int y = *(int*)((uintptr_t)map_structure + 0x4C);

        const char* mapName = (const char*)0x00CE06D0;
        const char* mapDir = (const char*)0x00CE07D0;

        if (mapName && mapName[0] != '\0' && mapDir && mapDir[0] != '\0') {
            for (int dx = -1; dx <= 1; dx++) {
                for (int dy = -1; dy <= 1; dy++) {
                    if (dx == 0 && dy == 0) continue;
                    int nx = x + dx;
                    int ny = y + dy;
                    if (nx >= 0 && nx < 64 && ny >= 0 && ny < 64) {
                        char path[260];
                        sprintf_s(path, "%s\\%s_%d_%d.adt", mapDir, mapName, nx, ny);
                        if (AddToPrefetchHistory(path)) {
                            char* pathAlloc = _strdup(path);
                            if (pathAlloc) {
                                if (!EnqueueTask(TASK_ADT_PREFETCH, (uint32_t)pathAlloc, 0, 0)) {
                                    free(pathAlloc);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    typedef int (__cdecl *orig_fn)(void*);
    return ((orig_fn)orig_AdtChunkLoad)(map_structure);
}

// ================================================================
// 3. DBC Parallel Loading
// ================================================================
// During initial game load, WoW parses ~200 DBC files sequentially,
// each containing thousands of records. The loading screen freezes
// for 10-12 seconds because all parsing happens on the main thread.
//
// We intercept the DBC load sequence and parallelize record parsing:
//   1. Main thread: reads raw DBC file into memory
//   2. Worker pool: parses record rows into structured data
//   3. Main thread: assembles final hashes/indices
//
// Hook target: the DBC loader dispatch function (likely loops over
// dbcFiles[] array and calls individual loaders).

#ifndef ADDR_DBC_LOAD_DISPATCH
#define ADDR_DBC_LOAD_DISPATCH 0x006337D0
#endif

#define TEST_DISABLE_DBC_PARALLEL 1  // Enabled!

static void* orig_DbcLoadDispatch = nullptr;

static volatile LONG g_currentDbcIndex = 0;
static void* g_dbcLoaderFn = nullptr;
static const uintptr_t DBC_ARRAY_START = 0x00AD305C;
static const int DBC_COUNT = 233;
static const int DBC_STRUCT_SIZE = 36;

static DWORD WINAPI DbcWorkerThread(LPVOID) {
    typedef int (__thiscall *Loader_t)(void*);
    Loader_t load = (Loader_t)g_dbcLoaderFn;

    while (true) {
        LONG idx = InterlockedIncrement(&g_currentDbcIndex) - 1;
        if (idx >= DBC_COUNT) break;

        void* dbcStore = (void*)(DBC_ARRAY_START + idx * DBC_STRUCT_SIZE);
        __try {
            load(dbcStore);
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return 0;
}

extern "C" void __stdcall ParallelDbcLoad(void* loader_fn) {
    g_dbcLoaderFn = loader_fn;
    g_currentDbcIndex = 0;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    int numCores = sysInfo.dwNumberOfProcessors;
    if (numCores < 2) numCores = 2;
    if (numCores > 8) numCores = 8;

    HANDLE threads[8] = {};
    for (int i = 0; i < numCores; i++) {
        threads[i] = CreateThread(NULL, 0, DbcWorkerThread, NULL, 0, NULL);
        if (threads[i]) {
            SetThreadPriority(threads[i], THREAD_PRIORITY_HIGHEST);
        }
    }

    WaitForMultipleObjects(numCores, threads, TRUE, INFINITE);

    for (int i = 0; i < numCores; i++) {
        if (threads[i]) CloseHandle(threads[i]);
    }
}

extern "C" __declspec(naked) void Hooked_DbcLoadDispatch() {
    __asm {
        pushad
        push esi // pass loader function pointer
        call ParallelDbcLoad
        popad
        ret
    }
}

// ================================================================
// 4. CDataStore Compression Offloading
// ================================================================
// The existing datastore_fastpath.cpp handles 6 inline hooks for
// GetDword/PutDword/GetByte/PutByte/GetQword/PutQword with TLS
// pointer caching. This offloading extends it by moving the
// actual inflate/deflate work to a background thread for
// packets larger than 512 bytes.
//
// Hook: intercept CDataStore::ProcessPacket after the header is
// parsed but before the payload is inflated. For packets < 512
// bytes, inflate inline. For larger packets, copy the compressed
// payload to a worker buffer and process async.
//
// The main thread continues without waiting for the result.
// The async result is written back to a shadow buffer that the
// next ProcessPacket call checks before reading.

#ifndef ADDR_CDATASTORE_PROCESS
#define ADDR_CDATASTORE_PROCESS 0x00000000
#endif

#define TEST_DISABLE_CDATA_ASYNC 1  // Async packet processing — risk of reordering

static constexpr size_t CDATA_ASYNC_THRESHOLD = 512; // bytes

// ================================================================
// 5. String Sanitization (wraps existing string.format + SSE2 strstr)
// ================================================================
// Already implemented in:
//   - lua_fastpath.cpp: 7 string.format fast paths, string.find/match/sub/len/byte/rep
//   - dllmain.cpp: SSE2 strlen, SSE2 strstr (Boyer-Moore-Horspool)
//   - fast_strncmp.cpp: SSE2 strnicmp replacement
//
// This module adds batch string processing for tooltips and
// entity names (the top two sources of string ops per frame).
// When a batch of strings needs sanitization (color code removal,
// UTF-8 validation, length truncation), we offload to the worker pool.

// Strip color codes (|cAARRGGBB, |r, |H...|h etc.) from a WoW string.
// Returns new length. Processes in-place.
static size_t StripColorCodes(char* str, size_t len) {
    size_t readIdx = 0, writeIdx = 0;

    while (readIdx < len) {
        if (str[readIdx] == '|' && readIdx + 1 < len) {
            char next = str[readIdx + 1];
            if (next == 'c' || next == 'C' || next == 'r' || next == 'R'
                || next == 'H' || next == 'h' || next == 'T' || next == 't') {
                // Skip escape sequence
                if (next == 'c' || next == 'C') {
                    readIdx += 10; // |cAARRGGBB = 10 chars
                } else if (next == 'r' || next == 'R') {
                    readIdx += 2;  // |r = 2 chars
                } else if (next == 'H' || next == 'h') {
                    // |H...|h — skip until closing |h
                    readIdx += 2;
                    while (readIdx < len && str[readIdx] != '|') readIdx++;
                    if (readIdx < len) readIdx++; // skip '|'
                    readIdx++; // skip 'h'
                } else {
                    readIdx += 2; // |T (texture escape)
                }
                continue;
            }
        }
        str[writeIdx++] = str[readIdx++];
    }
    str[writeIdx] = '\0';
    return writeIdx;
}

// ================================================================
// Public API
// ================================================================

bool InstallAsyncHooks(void) {
    // Initialize worker pool
    g_asyncShutdown = false;
    g_taskHead = g_taskTail = 0;
    g_tasksQueued = g_tasksProcessed = g_tasksDropped = 0;
    ::memset((void*)g_tasksByType, 0, sizeof(g_tasksByType));

    // The async task pool only has producers if at least one of the offload
    // hooks below is wired to a real address. They are all still 0x0 placeholders,
    // so EnqueueTask is never called -- spawning the worker pool would just leave
    // idle threads spinning on the event wait. Skip it until a hook is filled in.
    const bool anyAsyncHook =
        (ADDR_PARTICLE_EMITTER_UPDATE | ADDR_ADT_CHUNK_LOAD |
         ADDR_DBC_LOAD_DISPATCH | ADDR_CDATASTORE_PROCESS) != 0;
    if (!anyAsyncHook) {
        g_asyncInit = true;          // allow Shutdown()/stats to run as no-ops
        memset(g_adtCache, 0, sizeof(g_adtCache));
        Log("[AsyncHooks] Worker pool: not started (no offload hooks wired)");
        return true;
    }

    g_workerEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_workerEvent) {
        Log("[AsyncHooks] ERROR: Failed to create worker event");
        return false;
    }

    bool allStarted = true;
    for (int i = 0; i < ASYNC_POOL_WORKERS; i++) {
        g_workerThreads[i] = CreateThread(NULL, 0, AsyncWorkerProc, NULL, 0, NULL);
        if (!g_workerThreads[i]) {
            Log("[AsyncHooks] ERROR: Failed to create worker thread %d", i);
            allStarted = false;
            break;
        }
        SetThreadPriority(g_workerThreads[i], THREAD_PRIORITY_BELOW_NORMAL);
    }

    if (!allStarted) {
        g_asyncShutdown = true;
        if (g_workerEvent) SetEvent(g_workerEvent);
        for (int i = 0; i < ASYNC_POOL_WORKERS; i++) {
            if (g_workerThreads[i]) {
                WaitForSingleObject(g_workerThreads[i], 3000);
                CloseHandle(g_workerThreads[i]);
                g_workerThreads[i] = NULL;
            }
        }
        CloseHandle(g_workerEvent);
        g_workerEvent = NULL;
        return false;
    }

    g_asyncInit = true;

    // Initialize ADT cache
    memset(g_adtCache, 0, sizeof(g_adtCache));

    // Log feature status
    if (ADDR_PARTICLE_EMITTER_UPDATE)
        Log("[AsyncHooks] Particle emitter: hook ready (0x%08X) — Phase1 SSE2 inline, Phase2 async %s",
            ADDR_PARTICLE_EMITTER_UPDATE,
            TEST_DISABLE_PARTICLE_ASYNC ? "DISABLED (D3D thread-safety)" : "ENABLED");
    else
        Log("[AsyncHooks] Particle emitter: fill ADDR_PARTICLE_EMITTER_UPDATE");

    if (ADDR_ADT_CHUNK_LOAD)
        Log("[AsyncHooks] ADT prefetch: hook ready (0x%08X) — %s",
            ADDR_ADT_CHUNK_LOAD,
            TEST_DISABLE_ADT_PREFETCH ? "DISABLED (MPQ handle audit pending)" : "ENABLED");
    else
        Log("[AsyncHooks] ADT prefetch: fill ADDR_ADT_CHUNK_LOAD");

    if (ADDR_DBC_LOAD_DISPATCH)
        Log("[AsyncHooks] DBC parallel: hook ready (0x%08X) — %s",
            ADDR_DBC_LOAD_DISPATCH,
            TEST_DISABLE_DBC_PARALLEL ? "DISABLED (global sync audit)" : "ENABLED");
    else
        Log("[AsyncHooks] DBC parallel: fill ADDR_DBC_LOAD_DISPATCH");

    if (ADDR_CDATASTORE_PROCESS)
        Log("[AsyncHooks] CDataStore async: hook ready (0x%08X) — %s",
            ADDR_CDATASTORE_PROCESS,
            TEST_DISABLE_CDATA_ASYNC ? "DISABLED (packet ordering risk)" : "ENABLED");
    else
        Log("[AsyncHooks] CDataStore async: fill ADDR_CDATASTORE_PROCESS");

    Log("[AsyncHooks] Worker pool: %d threads, %d task slots", ASYNC_POOL_WORKERS, TASK_QUEUE_SIZE);

    #if !TEST_DISABLE_ADT_PREFETCH
    if (ADDR_ADT_CHUNK_LOAD) {
        if (WineSafe_CreateHook((void*)ADDR_ADT_CHUNK_LOAD, (void*)Hooked_sub_7D9A20, (void**)&orig_AdtChunkLoad) == MH_OK) {
            if (WO_EnableHook((void*)ADDR_ADT_CHUNK_LOAD) == MH_OK) {
                Log("[AsyncHooks] Hook installed: ADT prefetcher (0x%08X)", ADDR_ADT_CHUNK_LOAD);
            }
        }
    }
    #endif

    #if !TEST_DISABLE_DBC_PARALLEL
    if (ADDR_DBC_LOAD_DISPATCH) {
        if (WineSafe_CreateHook((void*)ADDR_DBC_LOAD_DISPATCH, (void*)Hooked_DbcLoadDispatch, (void**)&orig_DbcLoadDispatch) == MH_OK) {
            if (WO_EnableHook((void*)ADDR_DBC_LOAD_DISPATCH) == MH_OK) {
                Log("[AsyncHooks] Hook installed: DBC Parallel loader (0x%08X)", ADDR_DBC_LOAD_DISPATCH);
            }
        }
    }
    #endif

    #if !TEST_DISABLE_PARTICLE_ASYNC
    if (ADDR_PARTICLE_EMITTER_UPDATE) {
        if (WineSafe_CreateHook((void*)ADDR_PARTICLE_EMITTER_UPDATE, (void*)Hooked_ParticleEmitterUpdate, (void**)&orig_ParticleEmitterUpdate) == MH_OK) {
            if (WO_EnableHook((void*)ADDR_PARTICLE_EMITTER_UPDATE) == MH_OK) {
                Log("[AsyncHooks] Hook installed: Multi-threaded Particle simulation (0x%08X)", ADDR_PARTICLE_EMITTER_UPDATE);
            }
        }
    }
    #endif

    // Note: existing string.format and math fast paths are in lua_fastpath.cpp
    // and dllmain.cpp. This module adds the worker-pool infrastructure for
    // batch string processing and async inflate.

    return true;
}

void ShutdownAsyncHooks(void) {
    // Shutdown worker pool
    g_asyncShutdown = true;
    if (g_workerEvent) SetEvent(g_workerEvent);

    for (int i = 0; i < ASYNC_POOL_WORKERS; i++) {
        if (g_workerThreads[i]) {
            DWORD waitResult = WaitForSingleObject(g_workerThreads[i], 5000);
            if (waitResult == WAIT_TIMEOUT) {
                Log("[AsyncHooks] WARNING: Worker %d did not exit, terminating", i);
                TerminateThread(g_workerThreads[i], 1);
            }
            CloseHandle(g_workerThreads[i]);
            g_workerThreads[i] = NULL;
        }
    }

    if (g_workerEvent) {
        CloseHandle(g_workerEvent);
        g_workerEvent = NULL;
    }

    g_asyncInit = false;

    Log("[AsyncHooks] Worker pool: %lld tasks queued, %lld processed, %lld dropped",
        g_tasksQueued, g_tasksProcessed, g_tasksDropped);

    Log("[AsyncHooks] Task breakdown: particle=%lld, adt=%lld, dbc=%lld, "
        "cdatastore=%lld, strings=%lld",
        g_tasksByType[TASK_PARTICLE_MATRIX],
        g_tasksByType[TASK_ADT_PREFETCH],
        g_tasksByType[TASK_DBC_PARSE],
        g_tasksByType[TASK_CDATA_INFLATE],
        g_tasksByType[TASK_STRING_SANITIZE]);
}

void OnFrameAsyncHooks(DWORD mainThreadId) {
    if (!g_asyncInit) return;
    if (GetCurrentThreadId() != mainThreadId) return;
}
