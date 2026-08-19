// ============================================================================
// Module: dbc_lookup_cache.cpp
// Description: Fast O(1) transformed row cache for DBC database queries.
// Safety & Threading: Thread-safe, executes on main/render threads.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <atomic>
#include "MinHook.h"
#include "version.h"
#include "dbc_lookup_cache.h"

extern "C" void Log(const char* fmt, ...);
#include "crash_dumper.h"
#include "sampling_profiler.h"

static constexpr int CACHE_SIZE = 4096;
static constexpr int CACHE_MASK = CACHE_SIZE - 1;

struct DbcRowEntry {
    std::atomic<uint32_t> seq;
    uintptr_t storePtr;   // DBCStore* — identifies which DBC file
    uint32_t  recordId;
    uint8_t   rowData[0x2A8]; // Cache the actual 680-byte record data directly!
    bool      valid;
};

// Committed by InstallDbcLookupCache rather than living in BSS. The feature is
// off by default, so 2.7 MB of a 32-bit address space was being reserved at DLL
// load for every player who never enabled it - and ClearDbcLookupCache walked
// all 4096 slots with an atomic compare-exchange each, on the main thread, at
// every lua_State change, clearing a cache that was never filled.
static DbcRowEntry* g_cache = nullptr;
static uint64_t   g_hits = 0;
static int g_featureToken = -1;
static uint64_t   g_misses = 0;
// Calls handed straight back because the client's own path was a plain memcpy
// that this cache cannot improve on. See the note in the hook.
static uint64_t   g_bypassedPlainCopy = 0;

typedef bool (__thiscall *orig_dbc_getrow_t)(void* store, int recordId, void* outBuf);
static orig_dbc_getrow_t g_orig = nullptr;

static bool __fastcall Hooked_DbcGetRow(void* store, void* /* edx */, int recordId, void* outBuf)
{
#if TEST_DISABLE_DBC_LOOKUP_CACHE
    return g_orig(store, recordId, outBuf);
#else
    if (!store) {
        return g_orig(store, recordId, outBuf);
    }

    // Whether this cache can win at all is decided by one byte in the client.
    //
    // sub_4CFD20 is three comparisons, an indexed load, and then one of two
    // things: if byte_C5DEA0 is set it runs sub_4CFBB0, a byte-at-a-time RLE
    // decode over 680 bytes, and caching that is a real saving. If it is clear
    // it is a single 680-byte memcpy - and this cache cannot beat a memcpy,
    // because a hit costs a hash, two atomic loads and *two* 680-byte copies,
    // one into a temporary for the seqlock and one out to the caller.
    //
    // A tester's profile put this function at 3.76% of executing main-thread
    // time with 17.6 million hits in 28 minutes, which is what being slower than
    // the thing you are caching looks like. One byte load per call is a cheap
    // price for not paying that.
    if (!*(volatile uint8_t*)0x00C5DEA0) {
        ++g_bypassedPlainCopy;
        return g_orig(store, recordId, outBuf);
    }

    uintptr_t storeKey = (uintptr_t)store;
    uint32_t idx = ((uint32_t)(storeKey >> 2) ^ recordId) & CACHE_MASK;
    DbcRowEntry* e = &g_cache[idx];

    // Optimistic lock-free read using Sequence Lock.
    //
    // The payload goes straight to the caller rather than through a temporary.
    // The seqlock was reading into tempBuf, verifying, then copying tempBuf out,
    // which is 1360 bytes moved per hit for 680 bytes of result - and a tester
    // session took 9869554 hits, so that spare copy was about 6.7 GB of memcpy
    // on the main thread.
    //
    // Writing the caller's buffer before the sequence is verified is safe here
    // because of what happens next: if the sequence moved, control falls through
    // to g_orig, which fills that same buffer completely. The caller cannot
    // observe the discarded bytes. It only works in that order, so the fall-
    // through below must stay unconditional.
    //
    // The key comparison also moves ahead of the copy. It is not the
    // authoritative check - the one after the sequence still is - but a slot
    // holding a different record is the common collision case and there is no
    // reason to copy 680 bytes before noticing.
    uint32_t s1 = e->seq.load(std::memory_order_acquire);
    if ((s1 & 1) == 0 && e->valid &&
        e->storePtr == storeKey && e->recordId == (uint32_t)recordId) {
        if (outBuf) memcpy(outBuf, e->rowData, 0x2A8);
        uint32_t s2 = e->seq.load(std::memory_order_acquire);

        // If sequence didn't change, the data we read is consistent and valid
        if (s1 == s2 && e->storePtr == storeKey && e->recordId == (uint32_t)recordId) {
            g_hits++;
            // Sampled, not per hit. This runs seventeen million times a session,
            // and a cross-module counter call on a path this hot costs a real
            // fraction of the work it is counting - the same mistake this project
            // found once already in the SSE2 matrix-vector hook. One in 1024 is
            // still far more than enough to answer "is it reached".
            if ((g_hits & 1023u) == 0u) CrashDumper::FeatureHit(g_featureToken);
            return true;   // already in the caller's buffer
        }
    }

    g_misses++;
    // Call original function to load
    bool result = g_orig(store, recordId, outBuf);

    if (result) {
        // Safe extraction of direct record pointer from DBCStore fields
        __try {
            uint32_t minId = *reinterpret_cast<const uint32_t*>(storeKey + 0x10);
            uint32_t maxId = *reinterpret_cast<const uint32_t*>(storeKey + 0x0C);
            if (recordId >= (int)minId && recordId <= (int)maxId) {
                uintptr_t rowsArray = *reinterpret_cast<const uintptr_t*>(storeKey + 0x20);
                if (rowsArray) {
                    const void* rptr = *reinterpret_cast<const void**>(rowsArray + (recordId - minId) * 4);
                    if (rptr != nullptr) {
                        uint32_t s = e->seq.load(std::memory_order_relaxed);
                        if ((s & 1) == 0) {
                            if (e->seq.compare_exchange_strong(s, s + 1, std::memory_order_acquire)) {
                                // Once the CAS claims the slot (seq is odd = "write in
                                // progress"), the seq MUST be advanced back to even no
                                // matter what — otherwise a fault while copying the row
                                // (rptr can go stale if the DBC store reloads mid-copy)
                                // leaves this slot's seq stuck odd forever, and
                                // ClearDbcLookupCache()'s spin-wait below then loops on
                                // it for the rest of the process (observed as a hang/
                                // "crash" during loading screens, GitHub issue #35).
                                bool wrote = false;
                                __try {
                                    e->storePtr = storeKey;
                                    e->recordId = (uint32_t)recordId;
                                    if (*(unsigned char*)0x00C5DEA0) {
                                        typedef void* (__cdecl *rle_decompress_fn)(const void*, int, void*);
                                        ((rle_decompress_fn)0x004CFBB0)(rptr, 0x2A8, e->rowData);
                                    } else {
                                        memcpy(e->rowData, rptr, 0x2A8); // Store actual row data
                                    }
                                    wrote = true;
                                } __except(EXCEPTION_EXECUTE_HANDLER) {
                                    wrote = false;
                                }
                                e->valid = wrote;
                                e->seq.store(s + 2, std::memory_order_release); // Even: write complete (or aborted)
                            }
                        }
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }

    return result;
#endif
}

bool InstallDbcLookupCache()
{
    if (!g_cache) {
        g_cache = (DbcRowEntry*)VirtualAlloc(nullptr, sizeof(DbcRowEntry) * CACHE_SIZE,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_cache) {
            Log("[DbcLookupCache] Could not commit %zu KB for the row cache - disabled",
                (sizeof(DbcRowEntry) * CACHE_SIZE) / 1024);
            return false;
        }
    }
    for (int i = 0; i < CACHE_SIZE; i++) {
        g_cache[i].storePtr = 0;
        g_cache[i].recordId = 0;
        g_cache[i].valid = false;
        memset(g_cache[i].rowData, 0, 0x2A8);
        g_cache[i].seq.store(0, std::memory_order_relaxed);
    }
    g_hits = 0;
    g_misses = 0;

    void* target = reinterpret_cast<void*>(0x004CFD20);

    unsigned char prologue[3];
    __try {
        memcpy(prologue, target, 3);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[DbcLookupCache] Target 0x004CFD20 not readable.");
        return true;
    }

    if (prologue[0] != 0x55 || prologue[1] != 0x8B || prologue[2] != 0xEC) {
        Log("[DbcLookupCache] BAD PROLOGUE at 0x%08X (expected 55 8B EC)", (uintptr_t)target);
        return true;
    }

    if (WineSafe_CreateHook(target, (void*)Hooked_DbcGetRow, (void**)&g_orig) != MH_OK) {
        Log("[DbcLookupCache] MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[DbcLookupCache] MH_EnableHook FAILED");
        MH_RemoveHook(target);
        return false;
    }

    g_featureToken = CrashDumper::FeatureTokenForCounting("DbcLookupCache");
    SamplingProfiler::RegisterSelfSymbol("dbc_lookup_cache", (const void*)&Hooked_DbcGetRow);
    Log("[DbcLookupCache] Installed: %d-slot transformed data cache at 0x4CFD20", CACHE_SIZE);
    return true;
}

// Printed from the periodic report.
//
// The hit rate used to be reported only from UninstallDbcLookupCache, which is
// on the teardown path this DLL never reaches - the process exits through
// TerminateProcess. So a cache that ran seventeen million times in one session
// had never once reported whether it was hitting.
void DbcLookupCache_LogStats()
{
    uint64_t total = g_hits + g_misses;
    if (total == 0 && g_bypassedPlainCopy == 0) return;

    if (total > 0) {
        Log("[DbcLookupCache] %llu calls, %llu hits, %llu misses (%.1f%% hit rate)",
            total, g_hits, g_misses, 100.0 * g_hits / total);
    }
    if (g_bypassedPlainCopy > 0) {
        Log("[DbcLookupCache] %llu calls handed straight back - the client's own path "
            "was a plain copy this cache cannot beat", g_bypassedPlainCopy);
    }
}

void UninstallDbcLookupCache()
{
    void* target = reinterpret_cast<void*>(0x004CFD20);
    MH_DisableHook(target);
    MH_RemoveHook(target);
    DbcLookupCache_LogStats();
}

extern "C" void ClearDbcLookupCache()
{
    if (!g_cache) return;   // never installed - nothing to walk
    for (int i = 0; i < CACHE_SIZE; i++) {
        DbcRowEntry* e = &g_cache[i];
        // Bounded retry: a slot's seq should always return to even quickly (the
        // writer critical section above is now guaranteed to advance it). Cap the
        // spin so a still-unforeseen stuck slot can no longer hang this thread
        // forever — skip it and move on instead.
        for (int attempt = 0; attempt < 10000; attempt++) {
            uint32_t s = e->seq.load(std::memory_order_relaxed);
            if ((s & 1) == 0) {
                if (e->seq.compare_exchange_strong(s, s + 1, std::memory_order_acquire)) {
                    e->storePtr = 0;
                    e->recordId = 0;
                    e->valid = false;
                    e->seq.store(s + 2, std::memory_order_release);
                    break;
                }
            } else {
                // If another thread is currently writing, yield CPU and try again
                Sleep(0);
            }
        }
    }
}
