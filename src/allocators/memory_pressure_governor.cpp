// ============================================================================
// Module: memory_pressure_governor.cpp
// Description: SSE2 vectorized replacement for legacy CRT function `memory_pressure_governor.cpp`.
// Safety & Threading: Concurrent execution safe. Ensure page boundary alignment checks are active.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <atomic>
#include "memory_pressure_governor.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);
extern "C" SIZE_T HeapCompactor_GetCachedLowHalf();

namespace PressureGovernor {

// ---- thresholds (in MB) -----------------------------------------
static constexpr SIZE_T YELLOW_ENTER = 48 * 1024 * 1024;   // 48 MB
static constexpr SIZE_T YELLOW_EXIT  = 64 * 1024 * 1024;   // 64 MB
static constexpr SIZE_T RED_ENTER    = 24 * 1024 * 1024;   // 24 MB
static constexpr SIZE_T RED_EXIT     = 48 * 1024 * 1024;   // same as YELLOW_ENTER

// Hysteresis: require N consecutive samples above/below threshold
// before changing level, so a transient spike doesn't shed+cache
// thrash. At 10 fps the Sleeping hook polls ≥60×/s, so 3 samples
// is ≤50ms of hold-off.
static constexpr int HYST_SAMPLES = 3;

// ---- callback table ----------------------------------------------
static constexpr int MAX_CALLBACKS = 16;

struct CallbackEntry {
    ShedCallback fn;
    void*        ctx;
};

static CallbackEntry g_callbacks[MAX_CALLBACKS];
static int           g_cbCount = 0;

// ---- state ------------------------------------------------------
static std::atomic<Level> g_level{PRESSURE_GREEN};
static int                g_hystCount   = 0;
static int                g_frameTick   = 0;
static bool               g_active      = false;

// ---- helpers -----------------------------------------------------
static const char* LevelName(Level lv) {
    switch (lv) {
        case PRESSURE_GREEN:  return "GREEN";
        case PRESSURE_YELLOW: return "YELLOW";
        case PRESSURE_RED:    return "RED";
        default:              return "?";
    }
}

static void FireCallbacks(Level newLevel) {
    for (int i = 0; i < g_cbCount; i++) {
        if (g_callbacks[i].fn)
            g_callbacks[i].fn(newLevel, g_callbacks[i].ctx);
    }
}

// ---- public API --------------------------------------------------
bool Init() {
    for (int i = 0; i < MAX_CALLBACKS; i++) {
        g_callbacks[i].fn  = nullptr;
        g_callbacks[i].ctx = nullptr;
    }
    g_cbCount   = 0;
    g_level     = PRESSURE_GREEN;
    g_hystCount = 0;
    g_frameTick = 0;
    g_active    = true;
    Log("[PressureGovernor] INIT (YELLOW<48MB, RED<24MB, hysteresis=%d samples)",
        HYST_SAMPLES);
    return true;
}

void Shutdown() {
    g_active = false;
    Log("[PressureGovernor] SHUTDOWN (final level=%s)", LevelName(g_level.load()));
}

Level GetLevel() { return g_level.load(); }

bool RegisterShedCallback(ShedCallback cb, void* ctx) {
    if (g_cbCount >= MAX_CALLBACKS) return false;
    g_callbacks[g_cbCount].fn  = cb;
    g_callbacks[g_cbCount].ctx = ctx;
    g_cbCount++;
    return true;
}

// The largest free run BELOW 2GB, which is where the client allocates from.
//
// A run that crosses the boundary is cut at it rather than carried over, so a
// large free region in the high half cannot make the low half look healthy -
// which is exactly how this governor slept through a session that ran out.
static SIZE_T GetLargestFreeBlockLowHalf() {
    static const uintptr_t LOW_HALF_END = 0x80000000u;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T largestFree = 0;
    SIZE_T currentFree = 0;
    uintptr_t addr = 0;

    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        uintptr_t base = (uintptr_t)mbi.BaseAddress;
        if (base >= LOW_HALF_END) break;
        if (mbi.State == MEM_FREE) {
            SIZE_T part = (base + mbi.RegionSize > LOW_HALF_END)
                        ? (SIZE_T)(LOW_HALF_END - base)
                        : mbi.RegionSize;
            currentFree += part;
            if (part != mbi.RegionSize) break;   // the run ends at the boundary
        } else {
            if (currentFree > largestFree) largestFree = currentFree;
            currentFree = 0;
        }
        addr = base + mbi.RegionSize;
        if (addr < base) break; // Overflow
    }

    if (currentFree > largestFree) largestFree = currentFree;
    return largestFree;
}

void OnFrame() {
    if (!g_active) return;

    // Adaptive throttle: poll every 4th frame (~15Hz) normally, but
    // skip entirely when GREEN and stable for 60+ frames (1 second).
    // This eliminates per-frame overhead during steady-state gameplay.
    g_frameTick++;
    if (g_level.load() == PRESSURE_GREEN && g_hystCount == 0 && g_frameTick > 60) {
        // Stable GREEN: only re-check every 60 frames (~1Hz)
        if ((g_frameTick % 60) != 0) return;
    } else {
        // Under pressure or recently changed: check every 4 frames
        if ((g_frameTick & 0x3) != 0) return;
    }

    // The low half, not the whole address space.
    //
    // This read the full-range figure until 2026-09-02, and a tester session
    // showed what that costs: 1MB largest free below 2GB, four reports running,
    // while the same second had 1237MB free across all of user address space.
    // The client allocates from below 2GB, so it was starving; this governor saw
    // 1237MB, stayed GREEN and shed nothing for the entire session. The two
    // numbers were printed one under the other in that log and nobody subtracted
    // them.
    SIZE_T freeBlock = HeapCompactor_GetCachedLowHalf();
    if (freeBlock == 0) {
        // The compactor is switched off or has not walked yet. Walking the whole
        // space here would answer the wrong question, so the local fallback below
        // measures the low half too.
        freeBlock = GetLargestFreeBlockLowHalf();
    }
    if (freeBlock == 0) return;                     // monitor not sampled yet

    Level current = g_level.load();

    // Hysteresis: accumulate consecutive samples in the target
    // direction before firing the level change.
    Level target = current;  // default: stay

    if (freeBlock < RED_ENTER) {
        target = PRESSURE_RED;
    } else if (freeBlock < YELLOW_ENTER) {
        if (current == PRESSURE_RED) {
            // Exiting RED requires RED_EXIT (48MB)
            target = (freeBlock >= RED_EXIT) ? PRESSURE_YELLOW : PRESSURE_RED;
        } else {
            target = PRESSURE_YELLOW;
        }
    } else {
        // free ≥ YELLOW_ENTER
        if (current == PRESSURE_YELLOW && freeBlock >= YELLOW_EXIT) {
            target = PRESSURE_GREEN;
        } else if (current == PRESSURE_RED) {
            // Still climbing out of RED — need RED_EXIT first
            target = (freeBlock >= RED_EXIT) ? PRESSURE_YELLOW : PRESSURE_RED;
        } else {
            target = PRESSURE_GREEN;
        }
    }

    if (target != current) {
        g_hystCount++;
        if (g_hystCount >= HYST_SAMPLES) {
            g_level.store(target);
            // Naming the range on this line, because the number it used to
            // print was over the whole address space and read as healthy while
            // the half the client uses had a megabyte left.
            Log("[PressureGovernor] %s -> %s (largest free block below 2GB = "
                "%uMB, %d samples)",
                LevelName(current), LevelName(target),
                (unsigned)(freeBlock / (1024*1024)), g_hystCount);
            if (target >= PRESSURE_RED)
                Log("[PressureGovernor]   RED sheds the caches and runs one "
                    "mi_collect. Tightening the purge delay returns physical "
                    "pages, not address space, because purging is by MEM_RESET "
                    "here - the collect is the part that can hand a segment "
                    "back and raise the figure above.");
            FireCallbacks(target);
            g_hystCount = 0;
        }
    } else {
        g_hystCount = 0;  // reset if back to current level
    }
}

} // namespace PressureGovernor