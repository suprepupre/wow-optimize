// ============================================================================
// Module: crt_free_hook.cpp
// Description: Removes a dead _msize call from WoW's CRT free wrapper.
// Safety & Threading: Concurrent safe. Calls WoW's own free, never this DLL's.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"
#include "crt_free_hook.h"
#include "config.h"
#include "crash_dumper.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);

// WoW's CRT free wrapper, read out of the binary rather than assumed:
//
//   int __stdcall sub_76E5A0(void *Block, int a2, int a3, int a4) {
//       if (Block) { _msize(Block); free(Block); }
//       return 1;
//   }
//
// The _msize result is computed and thrown away on every call, and it is not
// free: _msize (0x4112F8) ends in HeapSize(hHeap, 0, Block). So every
// deallocation in the client pays a walk into the heap for a number nobody
// reads.
//
// It has a second path that takes _lock(4) first, through the MSVC 6 small-block
// heap, and an earlier version of this comment claimed that cost too. It should
// not have: _heap_init picks the mode from __heap_select, which returns the
// system heap whenever the platform is NT and the major version is 5 or above.
// That is every Windows since 2000, so the locking path is dead on any machine
// this runs on. The measured win is a HeapSize call per allocation and per free,
// nothing more - which was enough to move RtlSizeHeap from 8-10% of main-thread
// execution to 1.28%.
//
// Two independent tester profiles put RtlSizeHeap at 8.09% and 10.59% of the
// time the main thread spent executing, and this wrapper has over a hundred call
// sites across the binary. That is the cost being removed.
//
// The replacement is the same function minus the dead call: same condition, same
// free, same return value. It has to call WoW's free at 0x412FC7 rather than
// this DLL's, because the DLL links its own static CRT and returning a WoW-heap
// block through that would corrupt the heap.
//
// Calling 0x412FC7 by address is safe with the mimalloc redirect on, which is the
// obvious worry: that address is itself detoured by Hooked_free in hooks_memory,
// which dispatches on mi_is_in_heap_region, so a mimalloc block still reaches
// mi_free. Jumping to the address lands in the detour rather than past it, and
// the number of calls arriving there is unchanged - only the _msize beside them
// is gone.
//
// With that redirect on, the removed call was costing more than a HeapSize:
// _msize is detoured too (hooked_msize in dllmain), so it was a region check plus
// mi_usable_size, still discarded.
static const uintptr_t WOW_FREE_WRAPPER = 0x0076E5A0;

typedef int  (__stdcall *crt_free_wrapper_t)(void* block, int, int, int);
typedef void (__cdecl   *wow_free_t)(void*);

static const wow_free_t   g_wow_free  = (wow_free_t)0x00412FC7;
static crt_free_wrapper_t g_orig      = nullptr;
static bool               g_installed = false;
static int                g_token     = -1;

// The allocation wrapper has the same defect, and allocation is at least as hot
// as deallocation. From the binary at 0x0076E540:
//
//   void* __stdcall sub_76E540(int size, int a2, DWORD exitCode, char flags) {
//       size_t n = (size + 7) & 0xFFFFFFF8;
//       void* p = (flags & 8) ? calloc(1, n) : malloc(n);
//       if (p) { _msize(p); return p; }        // discarded again
//       sub_76E4E0(a2, exitCode);              // out-of-memory reporter
//       return nullptr;
//   }
//
// The replacement does the same rounding and the same choice between calloc and
// malloc, and skips the dead _msize.
//
// It does not reimplement the out-of-memory path. sub_76E4E0 is __usercall with
// its first argument in EAX, which would need inline assembly to call correctly,
// and getting that subtly wrong on the path where memory has already run out is
// not a trade worth making. On failure this delegates to the original wrapper,
// which retries the allocation - failing again, at which point it reports the way
// it always did. One extra failed allocation when the process is already out of
// memory costs nothing.
//
// The rounding is done in unsigned arithmetic. The original is machine code and
// simply wraps; (size + 7) on a signed int near INT_MAX is undefined in C++.
static const uintptr_t WOW_ALLOC_WRAPPER = 0x0076E540;

typedef void* (__stdcall *wow_alloc_wrapper_t)(int size, int a2, DWORD exitCode, char flags);
typedef void* (__cdecl   *crt_malloc_t)(size_t);
typedef void* (__cdecl   *crt_calloc_t)(size_t, size_t);

static const crt_malloc_t   g_crt_malloc = (crt_malloc_t)0x00415074;
static const crt_calloc_t   g_crt_calloc = (crt_calloc_t)0x00416A56;
static wow_alloc_wrapper_t  g_origAlloc  = nullptr;
static bool                 g_allocInstalled = false;
static volatile LONG        g_allocCalls = 0;

// Deliberately a non-atomic 32-bit counter, and deliberately not 64-bit.
//
// An interlocked increment on every free would be a real cost on one of the
// hottest paths in the process - the same mistake the memset hook's counters
// made before they were removed. But a plain 64-bit increment is worse than
// unsynchronised: on 32-bit x86 it compiles to add/adc across two words, so a
// race does not merely lose a count, it can tear one and produce a number that
// was never true. An aligned 32-bit increment can only ever lose increments.
//
// So the count is a lower bound, and is reported as one. It wraps after about
// 4.3 billion deallocations; a session that busy is worth knowing about anyway.
static volatile LONG g_calls = 0;

// The feature list reads its evidence from FeatureHit, and this hook used to
// register a token and never touch it - deliberately, because a call into
// another translation unit on the hottest path in the process is a real cost.
// The consequence was worse than the cost: the list printed CrtFreeHook under
// "enabled but never ran - a zero here means the code path was not reached",
// in the same log where this module reported 2858166 deallocations served. A
// summary that calls a working default-on feature dead invites someone to go
// and fix what is not broken.
//
// Sampled instead, which is what DbcLookupCache already does on its own hot
// path: a test and a branch per call, a real call once every 8192.
static inline void NoteHit(LONG n) {
    if ((n & 8191) == 0) CrashDumper::FeatureHit(g_token);
}

int __stdcall Hooked_CrtFree(void* block, int a2, int a3, int a4) {
    LONG n = ++g_calls;
    NoteHit(n);
    if (block) g_wow_free(block);
    return 1;
}

// Size census.
//
// A slab allocator for small fixed-size blocks is a standard suggestion for this
// client, and it may well be right - but it rests on a premise nobody here has
// checked: that the client's allocations are overwhelmingly small. This hook
// already sees every size that passes through the wrapper, so the premise costs
// one array increment to test.
//
// Buckets are powers of two up to 64KB, then one overflow bin.
static constexpr int ALLOC_BUCKETS = 18;
static volatile LONG g_allocSizes[ALLOC_BUCKETS] = {};

static inline void NoteAllocSize(unsigned bytes) {
    int b = 0;
    unsigned v = bytes >> 4;          // 0-15 bytes lands in bucket 0
    while (v && b < ALLOC_BUCKETS - 1) { v >>= 1; ++b; }
    ++g_allocSizes[b];
}

void* __stdcall Hooked_WowAlloc(int size, int a2, DWORD exitCode, char flags) {
    NoteHit(++g_allocCalls);
    NoteAllocSize((unsigned)size);

    unsigned rounded = ((unsigned)size + 7u) & 0xFFFFFFF8u;
    void* p = (flags & 8) ? g_crt_calloc(1, rounded) : g_crt_malloc(rounded);
    if (p) return p;

    // Out of memory: hand it back to the original, which reports it properly.
    return g_origAlloc(size, a2, exitCode, flags);
}

bool InstallCrtFreeHook() {
    if (!Config::g_settings.OptCrtFreeMsize) {
        Log("[CrtFree] DISABLED via configuration");
        return false;
    }

    void* target = (void*)WOW_FREE_WRAPPER;
    if (WineSafe_CreateHook(target, (void*)Hooked_CrtFree, (void**)&g_orig) != MH_OK) {
        Log("[CrtFree] ERROR: could not create hook at 0x%08X", (unsigned)WOW_FREE_WRAPPER);
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[CrtFree] ERROR: could not enable hook at 0x%08X", (unsigned)WOW_FREE_WRAPPER);
        return false;
    }

    g_token = CrashDumper::FeatureTokenForCounting("CrtFreeHook");
    SamplingProfiler::RegisterSelfSymbol("crt_free", (const void*)&Hooked_CrtFree);
    g_installed = true;
    Log("[CrtFree] ACTIVE at 0x%08X - dropping the discarded _msize from every free",
        (unsigned)WOW_FREE_WRAPPER);
    return true;
}

// Separate switch from the free side on purpose. This one replaces more of the
// original than that one did, and it sits on the allocation path, so it has to be
// possible to turn off by itself rather than only together with a change that
// might be behaving perfectly well.
bool InstallCrtAllocHook() {
    if (!Config::g_settings.OptCrtAllocMsize) {
        Log("[CrtAlloc] DISABLED via configuration");
        return false;
    }

    void* target = (void*)WOW_ALLOC_WRAPPER;
    if (WineSafe_CreateHook(target, (void*)Hooked_WowAlloc, (void**)&g_origAlloc) != MH_OK) {
        Log("[CrtAlloc] ERROR: could not create hook at 0x%08X", (unsigned)WOW_ALLOC_WRAPPER);
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[CrtAlloc] ERROR: could not enable hook at 0x%08X", (unsigned)WOW_ALLOC_WRAPPER);
        return false;
    }

    SamplingProfiler::RegisterSelfSymbol("crt_alloc", (const void*)&Hooked_WowAlloc);
    g_allocInstalled = true;
    Log("[CrtAlloc] ACTIVE at 0x%08X - dropping the discarded _msize from every allocation",
        (unsigned)WOW_ALLOC_WRAPPER);
    return true;
}

void UninstallCrtFreeHook() {
    if (g_installed) {
        void* target = (void*)WOW_FREE_WRAPPER;
        MH_DisableHook(target);
        MH_RemoveHook(target);
        g_installed = false;
    }
    if (g_allocInstalled) {
        void* target = (void*)WOW_ALLOC_WRAPPER;
        MH_DisableHook(target);
        MH_RemoveHook(target);
        g_allocInstalled = false;
    }
}

void ReportCrtAllocStats() {
    if (!g_allocInstalled) {
        Log("[CrtAlloc] not installed - no allocations were measured");
        return;
    }
    Log("[CrtAlloc] at least %lu allocations served, each one a HeapSize call "
        "not made", (unsigned long)g_allocCalls);

    LONG total = 0;
    for (int i = 0; i < ALLOC_BUCKETS; i++) total += g_allocSizes[i];
    if (total <= 0) return;

    Log("[CrtAlloc] size distribution - the number that decides whether a small "
        "block pool is worth building:");
    for (int i = 0; i < ALLOC_BUCKETS; i++) {
        if (!g_allocSizes[i]) continue;
        unsigned lo = (i == 0) ? 0u : (16u << i);
        unsigned hi = (32u << i) - 1u;
        if (i == ALLOC_BUCKETS - 1)
            Log("[CrtAlloc]     %8u+       %8ld (%5.1f%%)", lo,
                (long)g_allocSizes[i], 100.0 * g_allocSizes[i] / total);
        else
            Log("[CrtAlloc]     %8u-%-8u %8ld (%5.1f%%)", lo, hi,
                (long)g_allocSizes[i], 100.0 * g_allocSizes[i] / total);
    }
}

void ReportCrtFreeStats() {
    ReportCrtAllocStats();

    // Never measured and measured zero are different answers; say which.
    if (!g_installed) {
        Log("[CrtFree] not installed - no deallocations were measured");
        return;
    }
    Log("[CrtFree] at least %lu deallocations served, each one a HeapSize call "
        "not made (count is a lower bound - see the note on g_calls)",
        (unsigned long)g_calls);
}

void GetCrtFreeStats(uint64_t* hits, uint64_t* total) {
    if (hits)  *hits  = (uint64_t)(unsigned long)g_calls;
    if (total) *total = (uint64_t)(unsigned long)g_calls;
}
