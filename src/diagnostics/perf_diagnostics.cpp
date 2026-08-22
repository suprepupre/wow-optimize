#include "perf_diagnostics.h"
#include "../core/world_position.h"
#include "version.h"
#include "crash_dumper.h"
#include <psapi.h>
#include <cstdio>
#include <cstring>
#include <atomic>

extern "C" void Log(const char* fmt, ...);
extern void CrashDumper_DumpHookTrace(int count);
extern "C" void mi_process_info(size_t* elapsed_msecs, size_t* user_msecs, size_t* system_msecs,
                                size_t* current_rss, size_t* peak_rss,
                                size_t* current_commit, size_t* peak_commit,
                                size_t* page_faults);

namespace PerfDiagnostics {

static DWORD g_lastDiagTick = 0;
static std::atomic<long> g_stutterCount{0};


// Insert one allocation into a descending top-N list, dropping the smallest.
template <typename T>
static void TrackTopReservation(T* top, int n, uintptr_t base, SIZE_T size, DWORD type) {
    if (size <= top[n - 1].size) return;
    int i = n - 1;
    while (i > 0 && top[i - 1].size < size) { top[i] = top[i - 1]; i--; }
    top[i].base = base; top[i].size = size; top[i].type = type;
}

// Name an allocation so the log says "d3d9.dll" instead of a bare address.
static void DescribeAllocation(uintptr_t base, DWORD type, char* out, size_t outSize) {
    if (type == MEM_IMAGE) {
        char path[MAX_PATH];
        if (GetModuleFileNameA((HMODULE)base, path, MAX_PATH)) {
            const char* leaf = strrchr(path, '\\');
            lstrcpynA(out, leaf ? leaf + 1 : path, (int)outSize);
            return;
        }
        lstrcpynA(out, "image", (int)outSize);
        return;
    }
    lstrcpynA(out, (type == MEM_MAPPED) ? "mapped file/section" : "private (heap/allocator)",
              (int)outSize);
}

void LogPerformanceSnapshot(double elapsedMs) {
    DWORD now = GetTickCount();
    if (now - g_lastDiagTick < 5000) return; // Rate-limit to once every 5 seconds
    g_lastDiagTick = now;
    
    g_stutterCount.fetch_add(1, std::memory_order_relaxed);
    
    Log("[PerfDiag] === STUTTER DETECTED (Frame duration: %.1f ms) ===", elapsedMs);
    
    // 1. Where this happened. Not a player position: the client's terrain
    //    streaming centre, the only world coordinate available here that the
    //    client actually writes. Said plainly when it cannot be read - a
    //    stutter at the origin and a stutter with no world are different facts,
    //    and the line this replaces printed 0.00, 0.00 for both, always.
    float pos[3];
    if (WowWorld::StreamCentre(pos)) {
        Log("[PerfDiag]   World position: X=%.2f, Y=%.2f, Z=%.2f",
            pos[0], pos[1], pos[2]);
    } else {
        Log("[PerfDiag]   World position: no world loaded, nothing to report");
    }
    
    // 2. Memory State
    PROCESS_MEMORY_COUNTERS pmc = {};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        Log("[PerfDiag]   Working Set: %.1f MB  Private Bytes: %.1f MB", 
            pmc.WorkingSetSize / (1024.0 * 1024.0), 
            pmc.PagefileUsage / (1024.0 * 1024.0));
    }
    
    // 3. Virtual Address Space Check
    //    We walk every region once; while we're here, bucket the FREE regions by
    //    size so we can see the *shape* of the fragmentation, not just the single
    //    largest block. The key number is "usable" free space (blocks big enough
    //    to satisfy a real allocation) vs total free — a large gap between them
    //    means the free space is chopped into unusable slivers, which is what a
    //    segregating VA arena would fix. Buckets are the upper bound of each band.
    static const SIZE_T kBucketMax[] = {
        64 * 1024, 256 * 1024, 1 * 1024 * 1024, 4 * 1024 * 1024,
        16 * 1024 * 1024, 64 * 1024 * 1024, (SIZE_T)-1
    };
    static const char* const kBucketName[] = {
        "<64K", "64K-256K", "256K-1M", "1M-4M", "4M-16M", "16M-64M", ">=64M"
    };
    const int kNumBuckets = 7;
    int   freeCount[7]  = {0};
    SIZE_T freeBytes[7] = {0};

    // The scan must cover the whole user-mode range. Hardcoding 0x7FFF0000 was
    // wrong on a large-address-aware client (WoW is /LARGEADDRESSAWARE, so on
    // 64-bit Windows it gets ~4GB): we stopped at 2GB but still added each
    // region's *full* size, so a free block straddling the 2GB line inflated the
    // totals and hid all fragmentation above 2GB. Ask the OS for the real limit.
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    const uintptr_t kScanEnd = (uintptr_t)si.lpMaximumApplicationAddress;

    // Where the address space actually went. Free space alone can't tell us
    // whether we're out of VA because something committed it or because
    // something reserved a huge block and never touched it.
    SIZE_T commitPrivate = 0, commitMapped = 0, commitImage = 0, reservedOnly = 0;

    // Biggest single reservations, tracked without allocating: regions of one
    // VirtualAlloc share an AllocationBase and are walked consecutively, so we
    // accumulate the run and only keep the top few.
    struct TopEntry { uintptr_t base; SIZE_T size; DWORD type; };
    const int kTopN = 8;
    TopEntry top[kTopN] = {};
    uintptr_t runBase = 0; SIZE_T runSize = 0; DWORD runType = 0;

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0x10000;
    SIZE_T largestFree = 0, totalFree = 0, usableFree = 0; // usableFree = blocks >= 1MB
    while (addr < kScanEnd) {
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) { addr += 0x10000; continue; }

        // Never count past the end of the range we're scanning.
        SIZE_T size = mbi.RegionSize;
        if (addr + size > kScanEnd) size = kScanEnd - addr;

        if (mbi.State == MEM_FREE) {
            if (size > largestFree) largestFree = size;
            totalFree += size;
            if (size >= 1 * 1024 * 1024) usableFree += size;
            for (int b = 0; b < kNumBuckets; b++) {
                if (size <= kBucketMax[b]) { freeCount[b]++; freeBytes[b] += size; break; }
            }
        } else {
            if (mbi.State == MEM_COMMIT) {
                if      (mbi.Type == MEM_IMAGE)  commitImage  += size;
                else if (mbi.Type == MEM_MAPPED) commitMapped += size;
                else                             commitPrivate += size;
            } else {
                reservedOnly += size;
            }

            uintptr_t base = (uintptr_t)mbi.AllocationBase;
            if (base != runBase) {
                if (runSize > 0) TrackTopReservation(top, kTopN, runBase, runSize, runType);
                runBase = base; runSize = 0; runType = mbi.Type;
            }
            runSize += size;
        }

        addr += mbi.RegionSize;
        if (mbi.RegionSize == 0) addr += 0x10000;
    }
    if (runSize > 0) TrackTopReservation(top, kTopN, runBase, runSize, runType);

    Log("[PerfDiag]   VA Total Free: %.1f MB  Largest Block: %.1f MB%s",
        totalFree / (1024.0 * 1024.0),
        largestFree / (1024.0 * 1024.0),
        (largestFree < 64 * 1024 * 1024) ? " [WARNING: FRAGMENTED]" : "");
    Log("[PerfDiag]   VA in use: private %.1f MB, mapped %.1f MB, image %.1f MB, reserved-only %.1f MB",
        commitPrivate / (1024.0 * 1024.0), commitMapped / (1024.0 * 1024.0),
        commitImage / (1024.0 * 1024.0), reservedOnly / (1024.0 * 1024.0));
    Log("[PerfDiag]   Largest VA reservations (who ate the address space):");
    for (int i = 0; i < kTopN && top[i].size > 0; i++) {
        char owner[MAX_PATH];
        DescribeAllocation(top[i].base, top[i].type, owner, sizeof(owner));
        Log("[PerfDiag]     0x%08X  %8.1f MB  %s",
            (unsigned)top[i].base, top[i].size / (1024.0 * 1024.0), owner);
    }

    // mimalloc's own view. If "reserved-only" above is large and mimalloc's
    // reserved number accounts for it, the address space went to our allocator,
    // not to the engine or the D3D9/Vulkan translation layer.
    {
        size_t elapsed = 0, userMs = 0, sysMs = 0, rss = 0, peakRss = 0,
               commit = 0, peakCommit = 0, faults = 0;
        mi_process_info(&elapsed, &userMs, &sysMs, &rss, &peakRss,
                        &commit, &peakCommit, &faults);
        Log("[PerfDiag]   mimalloc: commit %.1f MB (peak %.1f MB), rss %.1f MB (peak %.1f MB)",
            commit / (1024.0 * 1024.0), peakCommit / (1024.0 * 1024.0),
            rss / (1024.0 * 1024.0), peakRss / (1024.0 * 1024.0));
    }
    Log("[PerfDiag]   VA Usable Free (>=1MB blocks): %.1f MB of %.1f MB  (%.0f%% lost to slivers)",
        usableFree / (1024.0 * 1024.0),
        totalFree / (1024.0 * 1024.0),
        totalFree ? (100.0 * (double)(totalFree - usableFree) / (double)totalFree) : 0.0);
    for (int b = 0; b < kNumBuckets; b++) {
        if (freeCount[b] > 0) {
            Log("[PerfDiag]     free[%-8s] count=%-5d total=%.1f MB",
                kBucketName[b], freeCount[b], freeBytes[b] / (1024.0 * 1024.0));
        }
    }
        
    // 4. What happened inside the spike. A state transition landing in a stutter
    // (loading boundary, device reset, cache invalidation) is almost always the
    // explanation, and it is the one thing a raw frame time cannot tell us.
    //
    // Bounded to the stutter itself. Unbounded, this printed whatever was newest
    // in the ring, which in a quiet session is a loading screen from minutes ago -
    // an unrelated event presented as the cause.
    Log("[PerfDiag]   Events within the stutter:");
    CrashDumper::DumpTrace(16, (DWORD)(elapsedMs + 0.5) + 50);

    // 5. Feature usage. Only features that recorded activity are listed - printing
    // every active feature meant ~70 lines of "calls=0" per stutter, because
    // FeatureCall() is wired into almost nothing.
    Log("[PerfDiag]   Features with recorded activity:");
    FeatureState features[MAX_TRACKED_FEATURES];
    int fcount = CrashDumper::GetFeatureStates(features, MAX_TRACKED_FEATURES);
    int reported = 0;
    for (int i = 0; i < fcount; i++) {
        if (features[i].callCount == 0 && features[i].errorCount == 0) continue;
        Log("[PerfDiag]     %-28s active=%d calls=%lld errors=%lld",
            features[i].name ? features[i].name : "(null)",
            features[i].active ? 1 : 0,
            features[i].callCount,
            features[i].errorCount);
        reported++;
    }
    if (reported == 0) Log("[PerfDiag]     (none)");

    // 6. Dump last hook trace to pinpoint exactly what ran during this lag spike
    Log("[PerfDiag]   Last 16 hook calls before stutter:");
    CrashDumper_DumpHookTrace(16);
    
    Log("[PerfDiag] ==================================================");
}

// A full snapshot is about twenty lines - sixteen hook calls, the VA reservation
// table, player position. Printing one per stutter was fine in a smooth session
// and ruinous in a rough one: a 7MB tester log contains 829 of them, and writing
// them is itself work on the main thread, so the diagnostic was making the
// stutters it reports worse.
//
// The first few say everything the later ones do. After that a stutter is worth
// counting, not describing again.
static constexpr DWORD STUTTER_QUIET_MS   = 30000;
static constexpr LONG  STUTTER_MAX_REPORTS = 12;

static DWORD s_lastStutterReport = 0;
static LONG  s_stutterReports    = 0;
static LONG  s_stuttersSeen      = 0;
static LONG  s_gapsIgnored       = 0;

// Above this, the number stops describing a frame.
//
// One log reported "STUTTER DETECTED (Frame duration: 179395.5 ms)" - three
// minutes. Nothing stalled for three minutes; the window was not on screen, so
// Present was not called, and the gap between two Presents was measured as
// though it were one frame. Alt-tabbing, minimising and sitting on a loading
// screen all produce it, and each one burned a snapshot out of the twelve this
// module is allowed to write - snapshots that describe an idle process.
//
// FrameBench already draws this line at two seconds for its percentiles. Here
// the line is higher, because a genuine multi-second freeze is exactly what this
// module exists to catch and must still be described. Thirty seconds is past
// anything a player sits through and calls a stutter.
static constexpr double STUTTER_CEILING_MS = 30000.0;

void OnFrame(double elapsedMs) {
    #if !TEST_DISABLE_SAMPLING_PROFILER
    if (elapsedMs > STUTTER_CEILING_MS) {
        ++s_gapsIgnored;
        return;
    }

    // If a frame takes longer than 100ms (10 FPS or below), it's a severe stutter
    if (elapsedMs > 100.0) {
        ++s_stuttersSeen;

        if (s_stutterReports >= STUTTER_MAX_REPORTS) return;

        DWORD now = GetTickCount();
        if (s_lastStutterReport != 0 && now - s_lastStutterReport < STUTTER_QUIET_MS)
            return;

        s_lastStutterReport = now;
        ++s_stutterReports;
        LogPerformanceSnapshot(elapsedMs);

        if (s_stutterReports == STUTTER_MAX_REPORTS) {
            Log("[PerfDiag] That is %d snapshots; further stutters are counted "
                "only. See the summary at the end.", (int)STUTTER_MAX_REPORTS);
        }
    }
    #endif
}

void LogStats() {
    if (s_stuttersSeen > 0) {
        Log("[PerfDiag] %ld frames over 100ms this session, %ld described in full",
            (long)s_stuttersSeen, (long)s_stutterReports);
    }
    if (s_gapsIgnored > 0) {
        Log("[PerfDiag] %ld gaps over %.0f s ignored - the window was not being "
            "drawn (alt-tab, minimise, loading), so they are not frames",
            (long)s_gapsIgnored, STUTTER_CEILING_MS / 1000.0);
    }
}

bool Init() {
    g_lastDiagTick = 0;
    g_stutterCount.store(0);
    Log("[PerfDiag] Performance Diagnostic Monitor Active (100ms stutter trigger)");
    return true;
}

void Shutdown() {
}

} // namespace PerfDiagnostics
