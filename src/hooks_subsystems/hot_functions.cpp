// ============================================================================
// Module: hot_functions.cpp
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <atomic>
#include <cstring>
#include <emmintrin.h>   // SSE2
#include "MinHook.h"
#include "hot_functions.h"
#include "ab_test.h"
#include "crash_dumper.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);

// Plain, deliberately not atomic. These are diagnostics for a single stats line,
// and they sit on the hottest function this DLL installs.
//
// std::atomic<uint64_t> is the trap here: on 32-bit x86 a 64-bit atomic RMW has no
// single instruction, so each fetch_add compiles to a lock cmpxchg8b retry loop.
// Two of those per call cost more than the memset they were measuring. Benchmarked
// against WoW's own memset (rep stosd, 0x0040BB80) over the small sizes engine code
// actually clears:
//
//     WoW's memset            11.76 ns/call
//     ours, atomic counters   11.39 ns/call   -> 3% faster, i.e. nothing
//     ours, plain counters     5.05 ns/call   -> 57% faster
//
// The SSE2 work was always a real 2.3x win; the instrumentation was eating it.
// memset is called from several threads, so an increment can be lost under
// contention - which costs a slightly low number in a diagnostic line, and is the
// same trade RecordHookCallHot already makes for the same reason.
static uint64_t g_memset_calls = 0;
static uint64_t g_simd_path = 0;

static int g_featureToken = -1;

// Above this size, clears are almost always one-shot (large allocations,
// textures, audio/network buffers) and won't be re-read soon, so streaming
// (non-temporal) stores that bypass the cache are a net win.
static const size_t NT_THRESHOLD = 2u * 1024u * 1024u;

typedef void* (__cdecl *memset_t)(void*, int, size_t);
static memset_t g_orig_memset = nullptr;

// All store paths are bounded by Size: the 16-byte stores either fit fully
// (i + 16 <= Size) or are the single trailing block ending exactly at
// dest+Size, so the function never writes past the caller's buffer.
// Set at init when the A/B harness names this module. The replacement was called
// 155,257,774 times in one measured session and has never been compared against
// the client's own memset on a live client - only in a standalone harness, where
// the cache state and the size distribution are not the client's.
static bool g_abSubject = false;

static void* __cdecl Hooked_memsetBody(void* dest, int Val, size_t Size) {
    if (!dest || Size == 0) return dest;

    g_memset_calls++;
    CrashDumper::FeatureHit(g_featureToken);

    unsigned char* p = (unsigned char*)dest;
    unsigned char  v = (unsigned char)Val;

    if (Size < 16) {
        for (size_t i = 0; i < Size; i++) p[i] = v;
        return dest;
    }

    const __m128i v128 = _mm_set1_epi8((char)v);
    g_simd_path++;

    // 16..127 bytes: unaligned 16-byte stores. The overlapping trailing store
    // covers the <16 remainder without a scalar loop (all bytes equal v).
    if (Size < 128) {
        size_t i = 0;
        for (; i + 16 <= Size; i += 16)
            _mm_storeu_si128((__m128i*)(p + i), v128);
        _mm_storeu_si128((__m128i*)(p + Size - 16), v128);
        return dest;
    }

    // Large: align the destination to 16 bytes so the bulk loop uses aligned
    // (and optionally non-temporal) stores.
    size_t head = (size_t)((0u - (uintptr_t)p) & 15);
    if (head) {
        _mm_storeu_si128((__m128i*)p, v128);
        p += head;
        Size -= head;
    }
    size_t blocks = Size & ~(size_t)15;

    if (Size >= NT_THRESHOLD) {
        for (size_t i = 0; i < blocks; i += 16)
            _mm_stream_si128((__m128i*)(p + i), v128);
        if (Size != blocks)
            _mm_storeu_si128((__m128i*)(p + Size - 16), v128);
        _mm_sfence();
    } else {
        for (size_t i = 0; i < blocks; i += 16)
            _mm_store_si128((__m128i*)(p + i), v128);
        if (Size != blocks)
            _mm_storeu_si128((__m128i*)(p + Size - 16), v128);
    }
    return dest;
}

// The detour proper. Kept apart from the body so the harness can time the call on
// both sides with one pair of clock reads covering every path out of it.
//
// Not `static void* r` - a function-local static is initialised once, and every
// call after the first would return the first destination pointer. That is the
// mistake the strncmp wrapper was generated with, on a function called a hundred
// and fifty million times a session.
void* __cdecl Hooked_memset(void* dest, int Val, size_t Size) {
    if (!g_abSubject) return Hooked_memsetBody(dest, Val, Size);
    unsigned long long abTick = AbTest::TickIn();
    void* r = AbTest::StandAside() ? g_orig_memset(dest, Val, Size)
                                   : Hooked_memsetBody(dest, Val, Size);
    AbTest::TickOut(abTick);
    return r;
}

bool InstallHotFunctionOptimizations() {
    void* target = (void*)0x0040BB80;
    
    if (MH_CreateHook(target, (void*)Hooked_memset, (void**)&g_orig_memset) != MH_OK) {
        Log("[FastMemset] Failed to create hook at 0x0040BB80");
        return false;
    }
    
    if (MH_EnableHook(target) != MH_OK) {
        Log("[FastMemset] Failed to enable hook");
        MH_RemoveHook(target);
        return false;
    }
    
    g_featureToken = CrashDumper::FeatureTokenForCounting("HotFunctions");
    SamplingProfiler::RegisterSelfSymbol("memset_SSE2", (const void*)&Hooked_memset);
    g_abSubject = AbTest::IsSubject("FastMemsetOpt", &g_abSubject);
    if (g_abSubject) {
        Log("[FastMemset] under A/B test: it alternates on and off in stints and "
            "AbTest reports the cost of the call each way. 155 million calls in a "
            "measured session, and the standalone harness that timed it did not "
            "have the client's cache state or its size distribution.");
    }
    Log("[FastMemset] Installed: SSE2 memset replacement (1108 callers, NT >= 2MB)");
    return true;
}

// Reports only; it deliberately does not remove the detour. This is the hottest
// function the DLL hooks, and pulling its trampoline out while another thread is
// inside it buys nothing at process exit.
void ReportHotFunctionStats() {
    uint64_t calls = g_memset_calls;
    uint64_t simd = g_simd_path;

    if (calls == 0) {
        Log("[FastMemset] No calls recorded");
        return;
    }
    Log("[FastMemset] Stats: %llu calls, %llu took the SIMD path (%.1f%%)",
        calls, simd, (double)simd * 100.0 / (double)calls);
}
