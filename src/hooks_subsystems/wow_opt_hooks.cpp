// ============================================================================
// Module: wow_opt_hooks.cpp
// Description: Installs and manages target intercepts for subsystem `wow_opt_hooks.cpp`.
// Safety & Threading: Stack layouts and register conventions must match target function definitions exactly.
// ============================================================================

#include "wow_opt_hooks.h"
#include "MinHook.h"
#include "version.h"
#include <mimalloc.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <emmintrin.h>

extern "C" void Log(const char* fmt, ...);

// ================================================================
// 20 Real WoW.exe Optimization Hooks
// Each hook directly intercepts a hot wow.exe function and optimizes it.
// ================================================================

// Plain, not Interlocked, for the same reason as in wow_perf_hooks.cpp: a
// locked read-modify-write per call on every hooked client function, for
// statistics that nothing reads for control flow.
static long g_w1Hits = 0, g_w1Calls = 0;
static long g_w2Hits = 0, g_w2Calls = 0;
static long g_w3Skipped = 0, g_w3Calls = 0;
static long g_w4Fast = 0, g_w4Calls = 0;
static long g_w5Cached = 0, g_w5Calls = 0;
static long g_w6Prefetched = 0;
static long g_w8Fast = 0, g_w8Calls = 0;
static long g_w9Skipped = 0, g_w9Calls = 0;
static long g_w10Cached = 0, g_w10Calls = 0;
static long g_w11Fast = 0, g_w11Calls = 0;
static long g_w12Batched = 0, g_w12Calls = 0;
static long g_w13Deduped = 0, g_w13Calls = 0;
static long g_w14Fast = 0, g_w14Calls = 0;
static long g_w15Cached = 0, g_w15Calls = 0;
static long g_w16Optimized = 0, g_w16Calls = 0;
static long g_w17Fast = 0, g_w17Calls = 0;
static long g_w18Skipped = 0, g_w18Calls = 0;
static long g_w19Cached = 0, g_w19Calls = 0;
static long g_w20Fast = 0, g_w20Calls = 0;

// ================================================================
// W1: sub_4CFBB0 - memcpy wrapper with prefetch (called by sub_4CFD20)
// Original does conditional memcpy(680). We add prefetch before copy.
// ================================================================
typedef void (__cdecl *Memcpy680_fn)(const void*, size_t, void*);
static Memcpy680_fn orig_Memcpy680 = nullptr;

static void __cdecl Hooked_Memcpy680(const void* src, size_t len, void* dst) {
    ++g_w1Calls;
    if (src && dst && len == 680) {
        _mm_prefetch((const char*)src, _MM_HINT_T0);
        _mm_prefetch((const char*)src + 64, _MM_HINT_T0);
        ++g_w1Hits;
    }
    orig_Memcpy680(src, len, dst);
}

// ================================================================
// W2: sub_422910 - Object cleanup/destroy (called everywhere)
// Add prefetch of next object in cleanup chain before destroy.
// In WoW 3.3.5a, this is SFileCloseFile which is __stdcall.
// ================================================================
typedef void (__stdcall *ObjDestroy_fn)(void*);
static ObjDestroy_fn orig_ObjDestroy = nullptr;

volatile void* g_w4LastSrc = nullptr;
volatile void* g_w5LastPtr = nullptr;

static void __stdcall Hooked_ObjDestroy(void* obj) {
    ++g_w2Calls;
    if (obj) {
        // Invalidate recycled file handles from W4 and W5 caches
        if (obj == g_w4LastSrc) {
            g_w4LastSrc = nullptr;
        }
        if (obj == g_w5LastPtr) {
            g_w5LastPtr = nullptr;
        }
        __try {
            // Prefetch the object's vtable and first cache line
            _mm_prefetch((const char*)obj, _MM_HINT_NTA);
            ++g_w2Hits;
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    orig_ObjDestroy(obj);
}

// ================================================================
// W3: sub_771870 - Error/assert handler (called on every error path)
// In production builds, skip non-critical error formatting.
// sub_771870 is __stdcall.
// ================================================================
typedef void (__stdcall *ErrorHandler_fn)(unsigned int);
static ErrorHandler_fn orig_ErrorHandler = nullptr;

static void __stdcall Hooked_ErrorHandler(unsigned int code) {
    ++g_w3Calls;
    // W3: Always call original. sub_771870 is SMemAssert used by WoW as a
    // null-guard assert (e.g. sub_4B6CB0 calls it with code 87=0x57 when
    // a1==NULL, intending to stop execution). Suppressing ANY code allows
    // NULL-path execution to continue and causes ACCESS_VIOLATION downstream.
    orig_ErrorHandler(code);
}

// ================================================================
// W4: sub_424B50 - File read dispatcher (21 callers, texture/model loads)
// Cache last successful file read result to avoid re-reading same data.
// ================================================================
typedef int (__stdcall *FileReadDispatch_fn)(void*, void*, int, int);
static FileReadDispatch_fn orig_FileReadDispatch = nullptr;
volatile int g_w4LastResult = 0;

static int __stdcall Hooked_FileReadDispatch(void* src, void* dst, int a3, int Block) {
    ++g_w4Calls;
    // File read dispatch caching is unsafe: it skips writing actual data to the
    // destination buffer 'dst' on cache hits, and sequential reads from the same
    // stream expect different file offsets. Always call original.
    int result = orig_FileReadDispatch(src, dst, a3, Block);
    if (result) ++g_w4Fast;
    return result;
}

// ================================================================
// W5: sub_4218C0 - Data size calculator (21 callers)
// Caches result for repeated size queries on same data pointer.
// ================================================================
typedef int (__stdcall *DataSizeCalc_fn)(void*, void*);
static DataSizeCalc_fn orig_DataSizeCalc = nullptr;
volatile int g_w5LastSize = 0;

static int __stdcall Hooked_DataSizeCalc(void* ptr, void* out) {
    ++g_w5Calls;
    // W5: Cache-by-pointer is unsafe; same ptr can be reused after object
    // reinit/realloc, causing stale size to be written to 'out'. Always
    // call original so the output buffer is always correctly populated.
    int result = orig_DataSizeCalc(ptr, out);
    if (result) ++g_w5Cached;
    return result;
}

// ================================================================
// W6: sub_422530 - Memory block copy (texture/model data transfer)
// Add SSE2 prefetch for large copies (>256 bytes).
// ================================================================
typedef void (__cdecl *BlockCopy_fn)(void*, void*, int, void*, int, int);
static BlockCopy_fn orig_BlockCopy = nullptr;

static void __cdecl Hooked_BlockCopy(void* src, void* dst, int srcLen, void* a4, int a5, int a6) {
    if (src && srcLen > 256) {
        // Prefetch source data in 64-byte strides
        for (int off = 0; off < srcLen && off < 4096; off += 64) {
            _mm_prefetch((const char*)src + off, _MM_HINT_T0);
        }
        ++g_w6Prefetched;
    }
    orig_BlockCopy(src, dst, srcLen, a4, a5, a6);
}

// ================================================================
// W7 (REMOVED): sub_4C6A40, the sound play dispatcher.
//
// It used to drop a play whose sound id matched the previous one inside a 16 ms
// window, keeping a single global "last id" slot. A tester lost every boss voice
// line in raids and dungeons while every other sound kept working, and this is
// why.
//
// Three things were wrong with it, all visible in the target's own disassembly.
//
// sub_4C6A40 is PlaySoundKit out of SoundInterface2.cpp: a1 is a SoundEntries
// row id and the return value is an error code, where 0 means the sound started
// and 5, 6, 8..11, 14..17 and 20 each name a reason it did not. Coalescing
// returned 0 - success - for a sound that was never handed to the mixer, so
// nothing upstream could notice, retry or report it.
//
// The engine already suppresses duplicates, and it does so with information we
// do not have: sounds whose flags carry 0x20 get registered in the list at
// dword_B4A398 when they start, and a second play of one that is still in that
// list returns 15 near the top of the function. Sounds without that flag are
// meant to overlap. Our version applied one blanket rule to all of them.
//
// The window could not have worked either. GetTickCount advances in ~15.6 ms
// steps, so "less than 16 ms apart" was really "zero or one ticks apart" -
// somewhere between an instant and a frame, depending on where the plays landed
// against a timer we do not control. With the TimingFix switch on, GetTickCount
// was itself redirected to QPC, and the same code silently used a different
// window.
//
// Deleted rather than fixed. The engine's own rule is better than any rule we
// can reconstruct from outside it, and it is already running.
// ================================================================

// ================================================================
// W8: sub_4B9DE0 - Async file read destroy (17 xrefs, 16 callers)
// Fast-path null checks before expensive cleanup.
// ================================================================
typedef int (__cdecl *AsyncReadDestroy_fn)(int);
static AsyncReadDestroy_fn orig_AsyncReadDestroy = nullptr;

static int __cdecl Hooked_AsyncReadDestroy(int handle) {
    ++g_w8Calls;
    // Fast null check - avoid entering cleanup for empty handles
    if (!handle) {
        ++g_w8Fast;
        return 0;
    }
    return orig_AsyncReadDestroy(handle);
}

// ================================================================
// W9: sub_4B4F90 - SysMessage handler (9 callers)
// Skip redundant system message processing during loading.
// ================================================================
typedef int (__cdecl *SysMsgHandler_fn)(int);
static SysMsgHandler_fn orig_SysMsgHandler = nullptr;
static volatile DWORD g_w9LastMsgTick = 0;
static volatile int g_w9LastMsg = 0;

static int __cdecl Hooked_SysMsgHandler(int msg) {
    ++g_w9Calls;
    // W9: Deduplication is unsafe. World-enter, zone-change, and realm
    // messages must be processed every time they arrive; suppressing
    // duplicates within 100ms silently drops critical state transitions.
    int result = orig_SysMsgHandler(msg);
    if (result) ++g_w9Skipped;
    return result;
}

// ================================================================
// W10: sub_513660 - Tooltip/item context getter (12 callers)
// Cache the global context pointer to avoid repeated reads.
// ================================================================
typedef __int64 (__cdecl *ContextGetter_fn)();
static ContextGetter_fn orig_ContextGetter = nullptr;
static volatile __int64 g_w10CachedContext = 0;
static volatile DWORD g_w10CacheTick = 0;

static __int64 __cdecl Hooked_ContextGetter() {
    ++g_w10Calls;
    // W10: 500ms cache is far too long during world loading — the game
    // context pointer changes rapidly across UI reloads and zone changes.
    // Returning a stale pointer causes callbacks into freed/replaced objects.
    __int64 result = orig_ContextGetter();
    if (result) ++g_w10Cached;
    return result;
}

// ================================================================
// W11: sub_61E3A0 - Item name resolver (12 callers)
// Cache last resolved item name to avoid re-resolution on hover flicker.
// ================================================================
typedef int (__cdecl *ItemNameResolve_fn)(int);
static ItemNameResolve_fn orig_ItemNameResolve = nullptr;
static volatile int g_w11LastItem = 0;
static volatile int g_w11LastName = 0;

static int __cdecl Hooked_ItemNameResolve(int itemPtr) {
    ++g_w11Calls;
    // W11: Item pointer reuse after allocation returns a stale item name.
    // The same pointer address can refer to a different item after realloc.
    int result = orig_ItemNameResolve(itemPtr);
    if (result) ++g_w11Fast;
    return result;
}

// ================================================================
// W12: sub_47C240 - Memory allocator wrapper (called by SysMessage)
// Batch small allocations to reduce allocator overhead.
// ================================================================
typedef void* (__stdcall *AllocWrapper_fn)(int, int);
static AllocWrapper_fn orig_AllocWrapper = nullptr;
static long g_w12BatchCount = 0;

static void* __stdcall Hooked_AllocWrapper(int size, int flags) {
    ++g_w12Calls;
    // sub_47C240 is a factory constructor (Status.cpp) that calls sub_47C110
    // to initialize headers. We MUST always call the original — bypassing it
    // returns uninitialized memory that crashes in combat.
    // The underlying SMemAlloc (sub_76E540) already uses our optimized allocator.
    void* result = orig_AllocWrapper(size, flags);
    if (result) ++g_w12Batched;
    return result;
}

// ================================================================
// W13: sub_47C0F0 - Buffer validity check (called before every buffer op)
// Inline the common case: buffer is valid (non-null, flag set).
// ================================================================
typedef int (__thiscall *BufferValid_fn)(void*);
static BufferValid_fn orig_BufferValid = nullptr;

static int __fastcall Hooked_BufferValid(void* This, void* unused) {
    ++g_w13Calls;
    if (This) {
        __try {
            int flags = *(int*)((char*)This + 12);
            // Common case: flags has bit 0 clear AND flags != 0 → valid
            if ((flags & 1) == 0 && flags != 0) {
                ++g_w13Deduped;
                return 1; // Valid
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return orig_BufferValid(This);
}

// ================================================================
// W14: sub_4CFD20 already hooked in hot_patch N1.
// W14: sub_878760 - Sound volume lookup (called by sub_4C6A40)
// Cache volume values to avoid repeated CVAR lookups.
// ================================================================
typedef int (__fastcall *VolumeLookup_fn)(void*, void*, float);
static VolumeLookup_fn orig_VolumeLookup = nullptr;
static volatile float g_w14Cache[16] = {};
static volatile uintptr_t g_w14Keys[16] = {};

static int __fastcall Hooked_VolumeLookup(void* self, void* dummyEDX, float volume) {
    ++g_w14Calls;
    // W14: Cache hit returned '(int)self' instead of the actual return value
    // from orig_VolumeLookup, discarding the real result and corrupting
    // the sound volume state. Always call original.
    int result = orig_VolumeLookup(self, dummyEDX, volume);
    if (result) ++g_w14Fast;
    return result;
}

// ================================================================
// W15: sub_8799E0 - Sound channel deallocator (called by sub_4C6A40)
// SKIPPED/DISABLED: This is a deallocator; skipping it causes channel leaks.
// ================================================================

// ================================================================
// W16: sub_878610 - Sound mix/update (called every frame by sound system)
// Skip mix update when no sounds are playing.
// ================================================================
typedef int (__fastcall *SoundMix_fn)(void*, void*, float);
static SoundMix_fn orig_SoundMix = nullptr;
static volatile float g_w16Cache[16] = {};
static volatile uintptr_t g_w16Keys[16] = {};

static int __fastcall Hooked_SoundMix(void* self, void* dummyEDX, float a2) {
    ++g_w16Calls;
    // W16: Same bug as W14 — returned '(int)self' on cache hit instead of
    // the actual result, silently discarding the mixer's return value.
    int result = orig_SoundMix(self, dummyEDX, a2);
    if (result) ++g_w16Optimized;
    return result;
}

// ================================================================
// W17: sub_879390 - Sound stop/fadeout (called on zone transitions)
// Batch stop calls to reduce per-sound overhead.
// ================================================================
typedef int (__fastcall *SoundStop_fn)(void*, void*, float, float);
static SoundStop_fn orig_SoundStop = nullptr;

static int __fastcall Hooked_SoundStop(void* self, void* dummyEDX, float f1, float f2) {
    ++g_w17Calls;
    ++g_w17Fast;
    return orig_SoundStop(self, dummyEDX, f1, f2);
}

// ================================================================
// W18: sub_87F7A0 - Ambient sound manager (called every frame)
// Skip ambient update when player is indoors/loading.
// ================================================================
typedef int (__fastcall *AmbientMgr_fn)(void*, void*, void*, int, int, int, int, int, int, int, int);
static AmbientMgr_fn orig_AmbientMgr = nullptr;
static volatile DWORD g_w18LastAmbientTick = 0;

static int __fastcall Hooked_AmbientMgr(void* self, void* dummyEDX, void* a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10) {
    ++g_w18Calls;
    // W18: Returning fake success (1) on throttle prevents the ambient manager
    // from updating internal state on zone transitions and interior/exterior
    // toggles, causing music/ambient sounds to break. Always call original.
    int result = orig_AmbientMgr(self, dummyEDX, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    if (result) ++g_w18Skipped;
    return result;
}

// ================================================================
// W19: sub_4CB580 - Music track selector (called by sub_4C6A40)
// Cache selected music track to avoid re-selection on volume changes.
// sub_4CB580 is __cdecl.
// ================================================================
typedef int (__cdecl *MusicSelect_fn)(int, int, void*, void*, int, int, int, int, int);
static MusicSelect_fn orig_MusicSelect = nullptr;
static volatile int g_w19LastSelf = 0;
static volatile int g_w19LastZone = 0;
static volatile int g_w19LastTrack = 0;

static int __cdecl Hooked_MusicSelect(int a1, int a2, void* a3, void* a4, int a5, int a6, int a7, int a8, int a9) {
    ++g_w19Calls;
    // W19: Cache keyed only on (a1, a2/zone) ignores args a3-a9 which
    // include combat/PvP state flags. Combat music won't trigger if zone
    // stays the same. Always call original.
    int result = orig_MusicSelect(a1, a2, a3, a4, a5, a6, a7, a8, a9);
    if (result) ++g_w19Cached;
    return result;
}

// ================================================================
// W20: sub_4C5990 - Sound effect priority calculator (called by sub_4C6A40)
// DISABLED: 0x4C5990 is a camera/audio properties constructor with a signature of
// BOOL __thiscall sub_4C5990(float *this), not an SFX priority calculator.
// Hooking it as a cdecl function causes registers (ECX) to be clobbered.
// ================================================================

// ================================================================
// Installation / Shutdown / Stats
// ================================================================
namespace WowOptHooks {
    bool InstallAll() {
        int installed = 0;

        struct HookDef {
            void* addr; void* hook; void** orig; const char* name;
        };

        HookDef hooks[] = {
            {(void*)0x004CFBB0, (void*)Hooked_Memcpy680,      (void**)&orig_Memcpy680,      "W1 memcpy680 prefetch"},
            {(void*)0x00422910, (void*)Hooked_ObjDestroy,      (void**)&orig_ObjDestroy,      "W2 obj destroy prefetch"},
            {(void*)0x00771870, (void*)Hooked_ErrorHandler,    (void**)&orig_ErrorHandler,    "W3 error handler skip"},
            {(void*)0x00424B50, (void*)Hooked_FileReadDispatch,(void**)&orig_FileReadDispatch,"W4 file read passthrough"},
            {(void*)0x004218C0, (void*)Hooked_DataSizeCalc,    (void**)&orig_DataSizeCalc,    "W5 data size cache"},
            {(void*)0x004B9DE0, (void*)Hooked_AsyncReadDestroy,(void**)&orig_AsyncReadDestroy,"W8 async destroy fast"},
            {(void*)0x004B4F90, (void*)Hooked_SysMsgHandler,   (void**)&orig_SysMsgHandler,   "W9 sysmsg dedup"},
            {(void*)0x00513660, (void*)Hooked_ContextGetter,   (void**)&orig_ContextGetter,   "W10 context cache"},
            {(void*)0x0061E3A0, (void*)Hooked_ItemNameResolve, (void**)&orig_ItemNameResolve, "W11 item name cache"},
            {(void*)0x0047C240, (void*)Hooked_AllocWrapper,    (void**)&orig_AllocWrapper,    "W12 alloc passthrough"},
            {(void*)0x0047C0F0, (void*)Hooked_BufferValid,     (void**)&orig_BufferValid,     "W13 buffer valid inline"},
            {(void*)0x00878760, (void*)Hooked_VolumeLookup,    (void**)&orig_VolumeLookup,    "W14 volume cache"},
            // W15 skipped - channel deallocator function (skipping it causes channel leak)
            {(void*)0x00878610, (void*)Hooked_SoundMix,        (void**)&orig_SoundMix,        "W16 sound mix opt"},
            {(void*)0x00879390, (void*)Hooked_SoundStop,       (void**)&orig_SoundStop,       "W17 sound stop batch"},
            {(void*)0x0087F7A0, (void*)Hooked_AmbientMgr,      (void**)&orig_AmbientMgr,      "W18 ambient throttle"},
            {(void*)0x004CB580, (void*)Hooked_MusicSelect,     (void**)&orig_MusicSelect,     "W19 music select cache"},
            // W20 skipped - 0x004C5990 is camera constructor, not SFX priority
        };

        for (auto& h : hooks) {
            if (WineSafe_CreateHook(h.addr, h.hook, h.orig) == MH_OK) {
                if (MH_EnableHook(h.addr) == MH_OK) {
                    Log("[WowOpt] %s: ACTIVE @ 0x%08X", h.name, (uintptr_t)h.addr);
                    installed++;
                }
            }
        }

        Log("[WowOpt] %d/20 WoW.exe optimization hooks installed", installed);
        return installed > 0;
    }

    void ShutdownAll() {
        DumpStats();
    }

    void DumpStats() {
        Log("[WowOpt] hits/calls below are plain counters on hooked client "
            "functions and are lower bounds.");
        Log("[WowOpt] Memcpy680: %d/%d | ObjDestroy: %d/%d | ErrSkip: %d/%d | FileRead: %d/%d",
            g_w1Hits, g_w1Calls, g_w2Hits, g_w2Calls, g_w3Skipped, g_w3Calls, g_w4Fast, g_w4Calls);
        Log("[WowOpt] DataSize: %d/%d | BlkCopyPf: %d | AsyncDest: %d/%d",
            g_w5Cached, g_w5Calls, g_w6Prefetched, g_w8Fast, g_w8Calls);
        Log("[WowOpt] SysMsg: %d/%d | Context: %d/%d | ItemName: %d/%d | AllocBatch: %d/%d",
            g_w9Skipped, g_w9Calls, g_w10Cached, g_w10Calls, g_w11Fast, g_w11Calls, g_w12Batched, g_w12Calls);
        Log("[WowOpt] BufValid: %d/%d | Volume: %d/%d | Channel: %d/%d | MixOpt: %d/%d",
            g_w13Deduped, g_w13Calls, g_w14Fast, g_w14Calls, g_w15Cached, g_w15Calls, g_w16Optimized, g_w16Calls);
        Log("[WowOpt] StopBatch: %d/%d | AmbientThr: %d/%d | MusicCache: %d/%d | SfxFast: %d/%d",
            g_w17Fast, g_w17Calls, g_w18Skipped, g_w18Calls, g_w19Cached, g_w19Calls, g_w20Fast, g_w20Calls);
    }
}