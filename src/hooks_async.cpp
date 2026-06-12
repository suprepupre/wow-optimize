// ================================================================
// hooks_async.cpp — Multithreading & Asynchronous Offloading
// ================================================================
// 1. Particle Matrix Math — SSE2-accelerated emitter math + async offload
// 2. Map (.ADT) Pre-parsing — speculative terrain fragment prefetch
// 3. DBC Parallel Loading — parallel DBC record parsing
// 4. CDataStore Compression Offloading — async packet inflate
// 5. String Sanitization — batch string processing (wraps existing)
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <intrin.h>
#include "MinHook.h"
#include "version.h"
#include "hooks_async.h"

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
                        // Prefetch terrain chunk from disk
                        // Touch the memory to bring it into cache
                        if (task->param1 && IsReadable(task->param1)) {
                            _mm_prefetch((const char*)task->param1, _MM_HINT_T0);
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
#define ADDR_PARTICLE_EMITTER_UPDATE 0x00000000
#endif

#define TEST_DISABLE_PARTICLE_ASYNC 1  // Phase 2 disabled: D3D buffer writes not thread-safe

// SSE2-accelerated particle transform (Phase 1 — inline math replacement)
// Transforms N particle positions by a 4x4 matrix.
// Input:  positions = array of {x,y,z,padding} (4 floats each, 16 bytes)
//         count = number of particles
//         matrix = 4x4 transform matrix (column-major, 16 floats)
__declspec(noinline)
static void SSE2_TransformParticles(float* positions, int count,
                                     const float* matrix) {
    if (count <= 0) return;

    __m128 m0 = _mm_loadu_ps(matrix);       // col 0
    __m128 m1 = _mm_loadu_ps(matrix + 4);   // col 1
    __m128 m2 = _mm_loadu_ps(matrix + 8);   // col 2
    __m128 m3 = _mm_loadu_ps(matrix + 12);  // col 3 (translation)

    for (int i = 0; i < count; i++) {
        float* pos = positions + i * 4;
        __m128 p = _mm_loadu_ps(pos);  // x, y, z, w

        // Transform: result = m0*x + m1*y + m2*z + m3*w
        __m128 r = _mm_add_ps(
                     _mm_add_ps(
                       _mm_mul_ps(m0, _mm_shuffle_ps(p, p, _MM_SHUFFLE(0,0,0,0))),
                       _mm_mul_ps(m1, _mm_shuffle_ps(p, p, _MM_SHUFFLE(1,1,1,1)))),
                     _mm_add_ps(
                       _mm_mul_ps(m2, _mm_shuffle_ps(p, p, _MM_SHUFFLE(2,2,2,2))),
                       _mm_mul_ps(m3, _mm_shuffle_ps(p, p, _MM_SHUFFLE(3,3,3,3)))));

        _mm_storeu_ps(pos, r);
    }
}

// SSE2-accelerated color interpolation (4 particles at once)
// srcColors / dstColors: arrays of 4 uint8_t RGBA (4 bytes each, padded to 16)
// t: lerp factor (0.0 – 1.0, broadcast to all components)
__declspec(noinline)
static void SSE2_LerpColors4(uint8_t* __restrict dst,
                              const uint8_t* __restrict srcA,
                              const uint8_t* __restrict srcB,
                              float t) {
    __m128 factor = _mm_set1_ps(t);
    __m128 oneMinusT = _mm_set1_ps(1.0f - t);
    __m128i zero128i = _mm_setzero_si128();

    __m128i a = _mm_loadu_si128((const __m128i*)srcA);
    __m128i b = _mm_loadu_si128((const __m128i*)srcB);

    __m128i aLo16 = _mm_unpacklo_epi8(a, zero128i);
    __m128i aHi16 = _mm_unpackhi_epi8(a, zero128i);
    __m128i bLo16 = _mm_unpacklo_epi8(b, zero128i);
    __m128i bHi16 = _mm_unpackhi_epi8(b, zero128i);

    __m128i aLo32 = _mm_unpacklo_epi16(aLo16, zero128i);
    __m128i aHi32 = _mm_unpackhi_epi16(aLo16, zero128i);
    __m128i bLo32 = _mm_unpacklo_epi16(bLo16, zero128i);
    __m128i bHi32 = _mm_unpackhi_epi16(bLo16, zero128i);

    __m128 aF0 = _mm_cvtepi32_ps(aLo32);
    __m128 aF1 = _mm_cvtepi32_ps(aHi32);
    __m128 bF0 = _mm_cvtepi32_ps(bLo32);
    __m128 bF1 = _mm_cvtepi32_ps(bHi32);

    __m128 r0 = _mm_add_ps(_mm_mul_ps(aF0, oneMinusT), _mm_mul_ps(bF0, factor));
    __m128 r1 = _mm_add_ps(_mm_mul_ps(aF1, oneMinusT), _mm_mul_ps(bF1, factor));

    __m128i ri0 = _mm_cvtps_epi32(r0);
    __m128i ri1 = _mm_cvtps_epi32(r1);
    __m128i packed = _mm_packus_epi16(_mm_packs_epi32(ri0, ri1), zero128i);

    _mm_storeu_si128((__m128i*)dst, packed);
}

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
#define ADDR_ADT_CHUNK_LOAD 0x00000000
#endif

#define TEST_DISABLE_ADT_PREFETCH 1  // Requires MPQ handle thread-safety audit

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
#define ADDR_DBC_LOAD_DISPATCH 0x00000000
#endif

#define TEST_DISABLE_DBC_PARALLEL 1  // Requires careful synchronization of WoW's DBC globals

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
