// ============================================================================
// Module: heap_compactor.cpp
// ============================================================================

#include "version.h"

#if TEST_DISABLE_HEAP_COMPACTOR == 0

#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <atomic>

#pragma comment(lib, "psapi.lib")

// Configuration
static constexpr DWORD MONITOR_INTERVAL_MS = 10000;     // Check every 10s (was 3 - reduce CPU overhead)
static constexpr DWORD LOADING_INTERVAL_MS = 3000;      // Faster checks during loading screens
static constexpr SIZE_T CRITICAL_THRESHOLD = 16 * 1024 * 1024;  // 16MB
static constexpr SIZE_T WARNING_THRESHOLD = 32 * 1024 * 1024;  // 32MB

// Statistics
static std::atomic<uint64_t> g_checksPerformed{0};
static std::atomic<uint64_t> g_compactionsTriggered{0};
static std::atomic<SIZE_T>   g_lastLargestBlock{0};
static std::atomic<SIZE_T>   g_minLargestBlock{SIZE_MAX};
static std::atomic<SIZE_T>   g_maxLargestBlock{0};

// Monitor thread handle
static HANDLE g_monitorThread = nullptr;
static volatile bool g_shutdown = false;

// The monitor thread only ever *requests* compaction; the actual HeapCompact()/
// mi_collect() work runs on the main thread via HeapCompactor_RunPendingWork(),
// called from the existing per-frame maintenance tick. HeapCompact() walks and
// mutates every process heap, and mi_collect(true) can decommit/unmap memory —
// doing that from an unsynchronized background thread raced against whatever
// heap WoW's networking code (or Winsock internally) was using mid-connect,
// which could yank a buffer out from under an in-flight WSA operation and
// surface as "unable to connect" (GitHub issue #39).
static std::atomic<int> g_pendingWork{0}; // 0=none, 1=proactive mi_collect, 2=full ForceHeapCompaction

// Brake and self-assessment for the low-half trigger. A compaction that does
// not give address space back is pure stall, and doing it every ten seconds for
// eight hours would be worse than the problem.
static DWORD g_lastCompactTick     = 0;
static DWORD g_compactIntervalMs   = 60000;   // grows when a pass achieves little
static bool  g_compactionGaveUp    = false;
static int   g_uselessInARow       = 0;
static unsigned long long g_reclaimedTotalKb = 0;

// Forward declarations
extern "C" void Log(const char* fmt, ...);
extern "C" void mi_collect(bool force);
#include <mimalloc.h>
#include "crash_dumper.h"

// Largest free virtual address range, measured twice.
//
// This scanned to wherever VirtualQuery stops, which on a large-address-aware
// client means the whole 3 or 4 GB. The region above 2 GB is barely touched, so
// the answer is dominated by it and stays in the gigabytes while the low half -
// where the client's own allocations live, and where anything that cannot hold
// a pointer with the top bit set must go - is down to a megabyte.
//
// A tester session shows both numbers side by side for three and a half hours:
// this function reporting 2046 MB falling to 1361 MB and never approaching its
// 16 MB trigger, while the periodic statistics line, which scans only the low
// half, reported a 1 MB largest block and "fragmented" from the first report
// onwards. Neither line said which range it had measured, so they read as a
// contradiction rather than as two different questions.
//
// `lowHalfOut` receives the figure for the low 2 GB when it is wanted.
static SIZE_T GetLargestFreeBlock(SIZE_T* lowHalfOut = nullptr) {
    static const uintptr_t LOW_HALF_END = 0x80000000u;

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T largestFree = 0;
    SIZE_T currentFree = 0;
    SIZE_T largestLow  = 0;
    SIZE_T currentLow  = 0;
    uintptr_t addr = 0;

    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        uintptr_t base = (uintptr_t)mbi.BaseAddress;

        if (mbi.State == MEM_FREE) {
            currentFree += mbi.RegionSize;

            // Only the part of this region that lies below the boundary counts
            // towards the low-half figure, and a run that crosses it stops
            // there rather than carrying the high side back down.
            if (base < LOW_HALF_END) {
                SIZE_T lowPart = (base + mbi.RegionSize > LOW_HALF_END)
                               ? (SIZE_T)(LOW_HALF_END - base)
                               : mbi.RegionSize;
                currentLow += lowPart;
                if (lowPart != mbi.RegionSize) {
                    if (currentLow > largestLow) largestLow = currentLow;
                    currentLow = 0;
                }
            }
        } else {
            if (currentFree > largestFree) largestFree = currentFree;
            currentFree = 0;
            if (base < LOW_HALF_END) {
                if (currentLow > largestLow) largestLow = currentLow;
                currentLow = 0;
            }
        }

        addr = base + mbi.RegionSize;
        if (addr < base) break; // Overflow
    }

    if (currentFree > largestFree) largestFree = currentFree;
    if (currentLow  > largestLow)  largestLow  = currentLow;

    if (lowHalfOut) *lowHalfOut = largestLow;
    return largestFree;
}

// Force heap compaction via Windows heap APIs
static void ForceHeapCompaction() {
    // Get all process heaps
    HANDLE heaps[64];
    DWORD heapCount = GetProcessHeaps(64, heaps);
    
    for (DWORD i = 0; i < heapCount; i++) {
        // HeapCompact is available on Vista+
        // This consolidates free blocks within the heap
        HeapCompact(heaps[i], 0);
    }
    
    // Also trigger mimalloc collection
    // (mimalloc is our global allocator replacement)
    {
        StallProbe probe("ForceHeapCompaction mi_collect", 4.0);
        mi_collect(true);
    }
}

// Forward declaration for loading mode check
namespace LuaOpt { bool IsLoadingMode(); }

// Monitor thread - checks VA state periodically
static DWORD WINAPI MonitorThread(LPVOID) {
    Log("[HeapCompactor] Monitor thread started (interval=%dms, loading=%dms, critical=%dMB)",
        MONITOR_INTERVAL_MS, LOADING_INTERVAL_MS, CRITICAL_THRESHOLD / (1024*1024));
    
    while (!g_shutdown) {
        // Use faster interval during loading screens, slower during gameplay
        DWORD interval = LuaOpt::IsLoadingMode() ? LOADING_INTERVAL_MS : MONITOR_INTERVAL_MS;
        Sleep(interval);
        
        SIZE_T largestLow = 0;
        SIZE_T largestFree = GetLargestFreeBlock(&largestLow);
        g_checksPerformed++;

        // The low half is what actually runs out, and it is what the trigger
        // reads now.
        //
        // This used to trigger on the full-range figure and log the discrepancy
        // instead of acting on it, because the cost of acting was unknown. An
        // eight-hour session settled it: that line fired 66 times with the low
        // half at 10-14 MB - under the 16 MB threshold the whole time - while
        // the full range sat at 1857 MB and no compaction ever ran. The client
        // spent the session with the resource it actually allocates from
        // exhausted, and this module watched.
        //
        // Acting on it needs a brake, which is the reason it was left alone
        // before: a client parked below the threshold would otherwise compact on
        // every tick, and a full mi_collect plus a HeapCompact of every process
        // heap is exactly the kind of stall this project keeps chasing. So the
        // request is rate limited, and the module measures whether its own work
        // achieves anything - see the recovery check in RunPendingWork.
        if (largestLow < CRITICAL_THRESHOLD) {
            DWORD nowTick2 = GetTickCount();
            bool due = (g_lastCompactTick == 0) ||
                       (nowTick2 - g_lastCompactTick) >= g_compactIntervalMs;
            if (due && !g_compactionGaveUp) {
                g_pendingWork.store(2, std::memory_order_release);
                g_lastCompactTick = nowTick2;
            }
            static DWORD lastSplitTick = 0;
            if (lastSplitTick == 0 || nowTick2 - lastSplitTick > 60000) {
                Log("[HeapCompactor] %uMB free below 2GB (largest block), %uMB "
                    "across all user address space. The low half is what the "
                    "client allocates from, so that is what this acts on.%s",
                    (unsigned)(largestLow / (1024*1024)),
                    (unsigned)(largestFree / (1024*1024)),
                    g_compactionGaveUp ? " Compaction has stopped: it was not "
                                         "recovering anything." : "");
                lastSplitTick = nowTick2;
            }
        }
        
        // Update statistics
        g_lastLargestBlock = largestFree;
        
        SIZE_T minVal = g_minLargestBlock.load();
        while (largestFree < minVal && 
               !g_minLargestBlock.compare_exchange_weak(minVal, largestFree));
        
        SIZE_T maxVal = g_maxLargestBlock.load();
        while (largestFree > maxVal && 
               !g_maxLargestBlock.compare_exchange_weak(maxVal, largestFree));
        
        // Check thresholds — only *request* compaction here; the main thread
        // performs the actual heap mutation (see HeapCompactor_RunPendingWork).
        if (largestFree < CRITICAL_THRESHOLD) {
            // Rate-limited: this fires every monitor tick once the process is out
            // of address space, and a tester log shows it repeating unchanged for
            // five minutes. One line per 30s is enough to establish the state.
            static DWORD lastCriticalTick = 0;
            DWORD nowTick = GetTickCount();
            if (nowTick - lastCriticalTick > 30000) {
                Log("[HeapCompactor] CRITICAL: LargestFreeBlock=%uMB (<%dMB) - requesting compaction",
                    (unsigned)(largestFree / (1024*1024)), (int)(CRITICAL_THRESHOLD / (1024*1024)));
                lastCriticalTick = nowTick;
            }
            g_pendingWork.store(2, std::memory_order_release);
        } else if (largestFree < WARNING_THRESHOLD) {
            // Proactively compact before reaching critical threshold
            static DWORD lastWarningTick = 0;
            DWORD now = GetTickCount();
            if (now - lastWarningTick > 30000) { // Max 1 per 30 seconds
                Log("[HeapCompactor] WARNING: LargestFreeBlock=%uMB (<32MB) - requesting proactive compaction",
                    (unsigned)(largestFree / (1024*1024)));
                int expected = 0;
                g_pendingWork.compare_exchange_strong(expected, 1, std::memory_order_release);
                lastWarningTick = now;
            }
        }
    }

    Log("[HeapCompactor] Monitor thread shutting down");
    return 0;
}

// Called once per frame from the main thread's existing periodic maintenance
// tick. Performs whatever compaction the monitor thread requested — keeps all
// heap-mutating work off the background thread.
extern "C" void HeapCompactor_RunPendingWork() {
    int work = g_pendingWork.exchange(0, std::memory_order_acquire);
    if (work == 0) return;

    if (work == 2) {
        SIZE_T beforeLow = 0;
        SIZE_T before = GetLargestFreeBlock(&beforeLow);
        (void)before;

        // mimalloc runs with purge_decommits off, so a purge resets pages but
        // leaves them committed - physical RAM comes back, address space does not.
        // That is the right trade in normal play (the comment at the option's
        // setting explains the driver-fault reasoning), and exactly the wrong one
        // here: this branch only runs because the process has no address space
        // left, which is the one resource resetting cannot return.
        //
        // A tester's session climbed to 3533 MB of mimalloc commit with 223 MB of
        // VA free and a 1 MB largest block, and every compaction pass achieved
        // nothing. Decommit for the duration of this pass only, then restore.
        {
            StallProbe probe("critical mi_collect (decommit)", 4.0);
            mi_option_set(mi_option_purge_decommits, 1);
            mi_collect(true);
            mi_option_set(mi_option_purge_decommits, 0);
        }

        ForceHeapCompaction();
        g_compactionsTriggered++;

        // Judge the pass by the half it was run for. The full-range figure is
        // what made this module blind in the first place, so measuring recovery
        // with it would repeat the mistake one level down.
        SIZE_T afterLow = 0;
        SIZE_T after = GetLargestFreeBlock(&afterLow);
        long long gainedKb = ((long long)afterLow - (long long)beforeLow) / 1024;
        if (gainedKb > 0) g_reclaimedTotalKb += (unsigned long long)gainedKb;

        Log("[HeapCompactor] After compaction: %uMB largest below 2GB (%+lldKB), "
            "%uMB across all address space",
            (unsigned)(afterLow / (1024*1024)), gainedKb,
            (unsigned)(after / (1024*1024)));

        // A pass that returns almost nothing is pure stall. Back off, and stop
        // entirely if it keeps happening: on a client whose low half is
        // genuinely full rather than merely fragmented there is nothing to
        // recover, and grinding every heap in the process to find that out again
        // costs a frame each time.
        if (gainedKb < 256) {
            if (++g_uselessInARow >= 3) {
                if (g_compactIntervalMs < 600000) {
                    g_compactIntervalMs *= 2;
                    Log("[HeapCompactor] Three passes in a row recovered almost "
                        "nothing; backing off to one attempt per %u seconds.",
                        g_compactIntervalMs / 1000);
                } else {
                    g_compactionGaveUp = true;
                    Log("[HeapCompactor] Compaction is not recovering address "
                        "space on this client, so it stops. The low half is full "
                        "rather than fragmented, and grinding every heap to "
                        "rediscover that costs a frame each time.");
                }
                g_uselessInARow = 0;
            }
        } else {
            g_uselessInARow = 0;
        }
    } else {
        {
            StallProbe probe("compaction mi_collect", 4.0);
            mi_collect(true);
        }
        g_compactionsTriggered++;
    }
}

bool HeapCompactor_Init() {
    if (g_monitorThread) {
        Log("[HeapCompactor] Already initialized");
        return true;
    }
    
    g_shutdown = false;
    g_monitorThread = CreateThread(NULL, 0, MonitorThread, NULL, 0, NULL);
    
    if (!g_monitorThread) {
        Log("[HeapCompactor] Failed to create monitor thread");
        return false;
    }
    
    // Log initial state
    SIZE_T initialFree = GetLargestFreeBlock();
    Log("[HeapCompactor] ACTIVE (initial LargestFreeBlock=%uMB)",
        (unsigned)(initialFree / (1024*1024)));
    
    return true;
}

void HeapCompactor_Shutdown() {
    if (!g_monitorThread) return;
    
    g_shutdown = true;
    WaitForSingleObject(g_monitorThread, 3000);
    CloseHandle(g_monitorThread);
    g_monitorThread = nullptr;
    
    Log("[HeapCompactor] Shutdown complete (checks=%llu, compactions=%llu, min=%uMB, max=%uMB)",
        (unsigned long long)g_checksPerformed.load(),
        (unsigned long long)g_compactionsTriggered.load(),
        (unsigned)(g_minLargestBlock.load() / (1024*1024)),
        (unsigned)(g_maxLargestBlock.load() / (1024*1024)));
}

// Query current state (for diagnostics)
// Printed from the periodic report, not from Shutdown: this DLL exits through
// TerminateProcess and a teardown-only counter never reaches a log.
extern "C" void HeapCompactor_LogStats() {
    SIZE_T low = 0;
    SIZE_T all = GetLargestFreeBlock(&low);
    Log("[HeapCompactor] %uMB largest free below 2GB, %uMB across all address "
        "space; %llu compactions, %lluKB recovered, next attempt no sooner than "
        "%us%s",
        (unsigned)(low / (1024*1024)), (unsigned)(all / (1024*1024)),
        (unsigned long long)g_compactionsTriggered.load(), g_reclaimedTotalKb,
        g_compactIntervalMs / 1000,
        g_compactionGaveUp ? " - stopped, it was not recovering anything" : "");
}

extern "C" SIZE_T HeapCompactor_GetLargestFreeBlock() {
    return GetLargestFreeBlock();
}

// Cheap cached read (no VirtualQuery walk) for per-frame consumers like the GC
// step. Returns the last value the monitor sampled; 0 means "not sampled yet".
extern "C" SIZE_T HeapCompactor_GetCachedLargestBlock() {
    return g_lastLargestBlock.load();
}

extern "C" void HeapCompactor_GetStats(uint64_t* checks, uint64_t* compactions, 
                                        SIZE_T* lastBlock, SIZE_T* minBlock, SIZE_T* maxBlock) {
    if (checks) *checks = g_checksPerformed.load();
    if (compactions) *compactions = g_compactionsTriggered.load();
    if (lastBlock) *lastBlock = g_lastLargestBlock.load();
    if (minBlock) *minBlock = g_minLargestBlock.load();
    if (maxBlock) *maxBlock = g_maxLargestBlock.load();
}

#else  // TEST_DISABLE_HEAP_COMPACTOR

// Compactor disabled: report "no data" so VA-pressure consumers stay inert.
#include <windows.h>
extern "C" SIZE_T HeapCompactor_GetCachedLargestBlock() { return 0; }

#endif // TEST_DISABLE_HEAP_COMPACTOR
