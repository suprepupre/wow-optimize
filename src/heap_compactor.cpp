// Heap Compactor - Prevents VA fragmentation OOM crashes
// Monitors LargestFreeBlock and triggers proactive defragmentation
// when free space drops below critical threshold.

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

// Forward declarations
extern "C" void Log(const char* fmt, ...);
extern "C" void mi_collect(bool force);

// Get largest free virtual memory block
static SIZE_T GetLargestFreeBlock() {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T largestFree = 0;
    SIZE_T currentFree = 0;
    uintptr_t addr = 0;
    
    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_FREE) {
            currentFree += mbi.RegionSize;
        } else {
            if (currentFree > largestFree) {
                largestFree = currentFree;
            }
            currentFree = 0;
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uintptr_t)mbi.BaseAddress) break; // Overflow
    }
    
    if (currentFree > largestFree) {
        largestFree = currentFree;
    }
    
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
    mi_collect(true);
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
        
        // Skip VA scanning during active gameplay to avoid CPU contention
        // Only scan during loading screens or when already near threshold
        if (!LuaOpt::IsLoadingMode() && g_lastLargestBlock.load() > WARNING_THRESHOLD) {
            continue;
        }
        
        SIZE_T largestFree = GetLargestFreeBlock();
        g_checksPerformed++;
        
        // Update statistics
        g_lastLargestBlock = largestFree;
        
        SIZE_T minVal = g_minLargestBlock.load();
        while (largestFree < minVal && 
               !g_minLargestBlock.compare_exchange_weak(minVal, largestFree));
        
        SIZE_T maxVal = g_maxLargestBlock.load();
        while (largestFree > maxVal && 
               !g_maxLargestBlock.compare_exchange_weak(maxVal, largestFree));
        
        // Check thresholds
        if (largestFree < CRITICAL_THRESHOLD) {
            Log("[HeapCompactor] CRITICAL: LargestFreeBlock=%uMB (<8MB) - forcing compaction",
                (unsigned)(largestFree / (1024*1024)));
            ForceHeapCompaction();
            g_compactionsTriggered++;
            
            // Verify improvement
            Sleep(100); // Give compaction time to complete
            SIZE_T afterCompaction = GetLargestFreeBlock();
            Log("[HeapCompactor] After compaction: LargestFreeBlock=%uMB (%+dMB)",
                (unsigned)(afterCompaction / (1024*1024)),
                (int)((afterCompaction - largestFree) / (1024*1024)));
                
        } else if (largestFree < WARNING_THRESHOLD) {
            // Proactively compact before reaching critical threshold
            static DWORD lastWarningTick = 0;
            DWORD now = GetTickCount();
            if (now - lastWarningTick > 30000) { // Max 1 per 30 seconds
                Log("[HeapCompactor] WARNING: LargestFreeBlock=%uMB (<32MB) - proactive compaction",
                    (unsigned)(largestFree / (1024*1024)));
                mi_collect(true);  // Aggressive mimalloc purge
                g_compactionsTriggered++;
                lastWarningTick = now;
            }
        }
    }
    
    Log("[HeapCompactor] Monitor thread shutting down");
    return 0;
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
extern "C" SIZE_T HeapCompactor_GetLargestFreeBlock() {
    return GetLargestFreeBlock();
}

extern "C" void HeapCompactor_GetStats(uint64_t* checks, uint64_t* compactions, 
                                        SIZE_T* lastBlock, SIZE_T* minBlock, SIZE_T* maxBlock) {
    if (checks) *checks = g_checksPerformed.load();
    if (compactions) *compactions = g_compactionsTriggered.load();
    if (lastBlock) *lastBlock = g_lastLargestBlock.load();
    if (minBlock) *minBlock = g_minLargestBlock.load();
    if (maxBlock) *maxBlock = g_maxLargestBlock.load();
}

#endif // TEST_DISABLE_HEAP_COMPACTOR
