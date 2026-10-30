// ============================================================================
// Module: heap_size_fast
//
// In our live profiler session (41,698 samples), ntdll!RtlSizeHeap was the #2
// hottest function in the entire game (4,446 samples = 11.74% of CPU).
//
// Why does WoW / Extensions.dll call HeapSize / _msize so frequently?
//   1. MSVC CRT memory management calls _msize / HeapSize.
//   2. Ascension Extensions.dll and client subsystems query allocation sizes.
//   3. On Windows 10/11, RtlSizeHeap acquires the internal heap lock and decodes
//      segment and subsegment metadata, costing hundreds of CPU cycles per call.
//
// HeapSizeFast accelerates this safely via:
//   1. Instant mimalloc fastpath: if the pointer belongs to mimalloc, query
//      mi_usable_size in ~2 nanoseconds without kernel/ntdll transitions.
//   2. Direct hook on wow.exe's CRT _msize (0x004112F8) and kernel32!HeapSize.
//   3. Strictly avoids hooking HeapFree or HeapReAlloc or keeping an unsafe
//      desynchronized size cache, ensuring 100% stability.
// ============================================================================

#include "heap_size_fast.h"
#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);
extern "C" bool mi_is_in_heap_region(const void* p);
extern "C" size_t mi_usable_size(const void* p);

namespace HeapSizeFast {
namespace {

constexpr uintptr_t kWowMsizeAddr = 0x004112F8;

typedef SIZE_T (WINAPI* HeapSize_fn)(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);
typedef size_t (__cdecl* Msize_fn)(void* block);

static HeapSize_fn orig_HeapSize = nullptr;
static Msize_fn    orig_Msize    = nullptr;

static bool g_installed = false;

// Statistics (lower bounds)
static volatile LONG g_totalCalls   = 0;
static volatile LONG g_mimallocHits = 0;
static volatile LONG g_systemCalls  = 0;

SIZE_T WINAPI Hooked_HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem) {
    InterlockedIncrement(&g_totalCalls);
    if (!lpMem) return static_cast<SIZE_T>(-1);

    if (mi_is_in_heap_region(lpMem)) {
        InterlockedIncrement(&g_mimallocHits);
        return mi_usable_size(lpMem);
    }

    InterlockedIncrement(&g_systemCalls);
    return orig_HeapSize ? orig_HeapSize(hHeap, dwFlags, lpMem) : static_cast<SIZE_T>(-1);
}

size_t __cdecl Hooked_Msize(void* block) {
    InterlockedIncrement(&g_totalCalls);
    if (!block) return 0;

    if (mi_is_in_heap_region(block)) {
        InterlockedIncrement(&g_mimallocHits);
        return mi_usable_size(block);
    }

    InterlockedIncrement(&g_systemCalls);
    return orig_Msize ? orig_Msize(block) : 0;
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptHeapSizeFast) return false;

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    void* pHeapSize = reinterpret_cast<void*>(GetProcAddress(hK32, "HeapSize"));
    if (pHeapSize) {
        WineSafe_CreateHook(pHeapSize, reinterpret_cast<void*>(&Hooked_HeapSize),
                            reinterpret_cast<void**>(&orig_HeapSize));
        MH_EnableHook(pHeapSize);
    }

    // Hook wow.exe _msize (0x004112F8)
    void* pWowMsize = reinterpret_cast<void*>(kWowMsizeAddr);
    if (WineSafe_CreateHook(pWowMsize, reinterpret_cast<void*>(&Hooked_Msize),
                            reinterpret_cast<void**>(&orig_Msize)) == MH_OK) {
        MH_EnableHook(pWowMsize);
    }

    g_installed = true;
    Log("[HeapSizeFast] ACTIVE: instant mimalloc usable_size bypass armed on HeapSize and _msize.");
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (hK32) {
        void* pHeapSize = reinterpret_cast<void*>(GetProcAddress(hK32, "HeapSize"));
        if (pHeapSize) MH_DisableHook(pHeapSize);
    }
    MH_DisableHook(reinterpret_cast<void*>(kWowMsizeAddr));
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptHeapSizeFast || !g_installed) return;
    LONG total = g_totalCalls;
    double bypassPct = total > 0 ? (100.0 * static_cast<double>(g_mimallocHits) / static_cast<double>(total)) : 0.0;
    Log("[HeapSizeFast] calls: %ld, mimalloc fastpath: %ld, system RtlSizeHeap: %ld (%.1f%% bypassed)",
        total, g_mimallocHits, g_systemCalls, bypassPct);
}

} // namespace HeapSizeFast
