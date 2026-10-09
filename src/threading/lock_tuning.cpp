#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"   // the No Client Patches gate and the foreign-detour check live here
#include "lock_tuning.h"

extern "C" void Log(const char* fmt, ...);

// 4000 is the value Windows itself uses for the process-heap critical section; it
// is long enough to win the common brief-hold race without wasting many cycles.
static const DWORD SPIN_COUNT = 4000;

// CRT _locktable base (see header) and a conservative span to retrofit. Indices
// cover the heap lock (4), errno/signal, and the low stdio locks. We validate
// every pointer before touching it, so an out-of-range or not-yet-created slot is
// simply skipped.
static const uintptr_t CRT_LOCKTABLE = 0x00AB6AB0;
static const int       CRT_LOCK_SPAN = 32;

// WoW's own engine critical sections, initialized at startup via direct
// InitializeCriticalSection(offset stru_Bxxxxx) calls (sub_44CCE0 and siblings).
// These are created long before our InitializeCriticalSection hook installs at
// +5s, so the hook never sees them -- they are the cross-thread engine locks
// (file system / asset / sound / network) that the main thread can stall behind.
// Unlike the CRT table, these globals ARE the CRITICAL_SECTION objects (the
// address is the struct), so they are tuned directly with no dereference.
static const uintptr_t ENGINE_LOCKS[] = {
    0x00B332B0, 0x00B33718, 0x00B33930, 0x00B33C5C,
};

static unsigned g_retrofitted  = 0;
static unsigned g_runtimeTuned = 0;
static bool     g_retrofitRan         = false;
static bool     g_initHookRequested   = false;
static bool     g_initHookInstalled   = false;

typedef void (WINAPI *InitCS_fn)(LPCRITICAL_SECTION);
static InitCS_fn g_origInitCS = nullptr;

// A CRITICAL_SECTION is 24 bytes on x86. Require the whole structure to sit in one
// committed, writable region before we let SetCriticalSectionSpinCount write to it.
static bool IsTunableCS(void* p) {
    uintptr_t a = (uintptr_t)p;
    if (a < 0x10000 || a > 0xBFFFFFE0) return false;
    if (a & 3) return false;  // CRITICAL_SECTION is pointer-aligned
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    const DWORD writable = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!(mbi.Protect & writable) || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
    // Whole 24-byte structure must be inside this committed region.
    uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    return (a + sizeof(CRITICAL_SECTION)) <= regionEnd;
}

static bool TuneCS(LPCRITICAL_SECTION cs) {
    if (!IsTunableCS(cs)) return false;
    __try {
        SetCriticalSectionSpinCount(cs, SPIN_COUNT);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Hook: every critical section created after we install gets a spin count too.
// This catches engine locks created during play (per-connection, per-load, etc.).
static void WINAPI Hooked_InitializeCriticalSection(LPCRITICAL_SECTION cs) {
    g_origInitCS(cs);
    if (cs && SetCriticalSectionSpinCount(cs, SPIN_COUNT))
        ++g_runtimeTuned;
}

// The two halves reach different code. The retrofit writes a spin count into
// critical sections that belong to wow.exe and nothing else. The hook patches
// the kernel32 export, which the loader resolves to ntdll's
// RtlInitializeCriticalSection, so every module in the process passes through
// it whenever it creates a lock: overlays, ReShade, DXVK, and anything else a
// player has injected. It is also outside wow.exe, so No Client Patches does not
// stop it. A tester running ReShade could not enter the world until this whole
// switch was off, while No Client Patches changed nothing. With the hook on its
// own switch he ran the retrofit alone and entered the world, so the hook is the
// half that broke it. How it breaks ReShade is not known. Nothing has measured a
// gain from the hook either, so it is off by default and the retrofit is not.
bool InstallLockTuning(bool retrofit, bool hookInitCS) {
    unsigned engineTuned = 0;
    if (retrofit) {
        g_retrofitRan = true;

        // 1. Retrofit the already-created CRT locks (the heap lock #4 is the prize).
        __try {
            for (int n = 0; n < CRT_LOCK_SPAN; ++n) {
                LPCRITICAL_SECTION* slot = (LPCRITICAL_SECTION*)(CRT_LOCKTABLE + (uintptr_t)n * 4);
                LPCRITICAL_SECTION cs = *slot;   // runtime-populated; NULL if lock n unused
                if (cs && TuneCS(cs))
                    ++g_retrofitted;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[LockTuning] CRT lock-table sweep faulted (skipped)");
        }

        // 2. Retrofit WoW's startup engine locks (missed by the hook below).
        for (uintptr_t addr : ENGINE_LOCKS) {
            if (TuneCS((LPCRITICAL_SECTION)addr)) ++engineTuned;
        }
        g_retrofitted += engineTuned;
    }

    // 3. Blanket future critical sections via the kernel32 export.
    g_initHookRequested = hookInitCS;
    if (hookInitCS &&
        MH_CreateHook((void*)&InitializeCriticalSection,
                      (void*)Hooked_InitializeCriticalSection,
                      (void**)&g_origInitCS) == MH_OK &&
        MH_EnableHook((void*)&InitializeCriticalSection) == MH_OK) {
        g_initHookInstalled = true;
    }

    Log("[LockTuning] ACTIVE: spin=%u, client locks retrofitted=%s%u (CRT + %u engine), "
        "InitializeCriticalSection hook for every module=%s",
        SPIN_COUNT, retrofit ? "" : "off, ", g_retrofitted, engineTuned,
        !hookInitCS ? "OFF by its switch" : g_initHookInstalled ? "ON" : "FAILED");
    return g_retrofitted > 0 || g_initHookInstalled;
}

// Nothing called the old accessor, so no log ever said what either half did.
void LogLockTuningStats() {
    if (!g_retrofitRan && !g_initHookRequested) {
        Log("[LockTuning] not measured: both halves are switched off.");
        return;
    }
    if (g_retrofitRan)
        Log("[LockTuning] %u of the client's own locks were given a spin count at startup.",
            g_retrofitted);
    else
        Log("[LockTuning] the client's own locks were left alone: switched off.");
    if (g_initHookInstalled)
        Log("[LockTuning] InitializeCriticalSection hook: %u lock(s) created since it went in, "
            "by any module in the process, were given a spin count. A plain counter "
            "incremented from many threads, so a lower bound.", g_runtimeTuned);
    else
        Log("[LockTuning] InitializeCriticalSection hook: not installed (%s).",
            g_initHookRequested ? "the hook failed to go in" : "switched off");
}
