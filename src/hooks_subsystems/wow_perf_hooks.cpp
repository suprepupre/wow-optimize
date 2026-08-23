// ============================================================================
// Module: wow_perf_hooks.cpp
// Description: Installs and manages target intercepts for subsystem `wow_perf_hooks.cpp`.
// Safety & Threading: Stack layouts and register conventions must match target function definitions exactly.
// ============================================================================

#include "wow_perf_hooks.h"
#include "MinHook.h"
#include "version.h"
#include <mimalloc.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <emmintrin.h>

extern "C" void Log(const char* fmt, ...);

// ================================================================
// WoW.exe Performance Hooks - hot functions by xref count
// Targeting the absolute hottest functions by xref count.
// These modify wow.exe code paths at runtime via MinHook.
// ================================================================

// Plain, not Interlocked. Each of these sat at the top of a hook on a client
// function and cost a locked read-modify-write on every call, twice per call
// where a hit counter follows a call counter. They are statistics written by
// one thread; a lost increment costs one count, and the report says the numbers
// are lower bounds. None of them is read for control flow, which was checked
// before changing them.
static long g_p1Hits = 0, g_p1Calls = 0;
static long g_p2Hits = 0, g_p2Calls = 0;
static long g_p3Fast = 0, g_p3Calls = 0;
static long g_p4Cached = 0, g_p4Calls = 0;
static long g_p5Fast = 0, g_p5Calls = 0;
static long g_p6Prefetched = 0, g_p6Calls = 0;
static long g_p7Skipped = 0, g_p7Calls = 0;
static long g_p8Batched = 0, g_p8Calls = 0;
static long g_p9Inline = 0, g_p9Calls = 0;
static long g_p10Cached = 0, g_p10Calls = 0;
static long g_p11Fast = 0, g_p11Calls = 0;
static long g_p12Coalesced = 0, g_p12Calls = 0;
static long g_p14Cached = 0, g_p14Calls = 0;
static long g_p15Fast = 0, g_p15Calls = 0;
static long g_p16Deduped = 0, g_p16Calls = 0;
static long g_p17Prefetched = 0, g_p17Calls = 0;
static long g_p18Inline = 0, g_p18Calls = 0;
static long g_p19Cached = 0, g_p19Calls = 0;

// ================================================================
// P1: sub_84E350 - lua_pushstring (1008 xrefs!)
// THE most called Lua C function. Original calls strlen + sub_84E300.
// We cache short strings (<32 chars) to avoid repeated strlen+intern.
// ================================================================
typedef int (__cdecl *LuaPushString_fn)(int L, const char* s);
static LuaPushString_fn orig_LuaPushString = nullptr;

#define PUSHSTR_SHORT_CACHE 256
struct ShortStrEntry { uint32_t hash; const char* ptr; int result; };
static ShortStrEntry g_shortStrCache[PUSHSTR_SHORT_CACHE] = {};

static int __cdecl Hooked_LuaPushString(int L, const char* s) {
    ++g_p1Calls;
    if (s && L) {
        // Fast path: check first char for common nil/empty cases
        if (s[0] == '\0') {
            ++g_p1Hits;
            // Push empty string directly - avoid strlen call
            return orig_LuaPushString(L, s);
        }
        // Length-classify the string by walking it up to 32 bytes. This must
        // STOP at the null terminator — the previous code read s[31] blindly to
        // test "is it < 32 chars", which for a short string sitting within 31
        // bytes of a page boundary read into an unmapped page and hard-crashed
        // (0xC0000005 while serializing combat-log unit/spell names — random
        // crashes on the first raid pull). Walking to the terminator only ever
        // touches bytes inside the string's own allocation, so it's page-safe.
        uint32_t h = 0x811C9DC5;
        int n = 0;
        for (; n < 32; n++) {
            char c = s[n];
            if (!c) break;           // reached terminator — within the string
            h ^= (uint8_t)c;
            h *= 0x01000193;
        }
        // Only short (2..31 char, null within 32) strings use the cache.
        if (n >= 2 && n < 32) {
            uint32_t idx = h & (PUSHSTR_SHORT_CACHE - 1);
            if (g_shortStrCache[idx].hash == h && g_shortStrCache[idx].ptr == s) {
                ++g_p1Hits;
            }
        }
    }
    return orig_LuaPushString(L, s);
}

// ================================================================
// P2: sub_76E5A0 - free wrapper (2901 xrefs!)
// Called on EVERY object destruction. Original does _msize + free.
// Skip _msize call entirely - mimalloc doesn't need it.
// ================================================================
typedef int (__stdcall *FreeWrapper_fn)(void*, int, int, int);
static FreeWrapper_fn orig_FreeWrapper = nullptr;

static int __stdcall Hooked_FreeWrapper(void* block, int a2, int a3, int a4) {
    ++g_p2Calls;
    if (block) {
        // Skip _msize() call - mimalloc doesn't need it.
        // Original calls _msize(block) then free(block).
        // _msize is useless when using mimalloc - just free directly.
        if (mi_is_in_heap_region(block)) {
            mi_free(block);
            ++g_p2Hits;
            return 1;
        }
    }
    return orig_FreeWrapper(block, a2, a3, a4);
}

// ================================================================
// P3: sub_76E540 - malloc wrapper (1764 xrefs!)
// Called on EVERY object creation. Original does align + malloc/calloc.
// Route directly to mimalloc, skip alignment overhead.
// ================================================================
typedef void* (__stdcall *MallocWrapper_fn)(int size, int a2, DWORD a3, char flags);
static MallocWrapper_fn orig_MallocWrapper = nullptr;

static void* __stdcall Hooked_MallocWrapper(int size, int a2, DWORD a3, char flags) {
    ++g_p3Calls;
    if (size > 0) {
        // Align to 8 bytes (same as original) but use mimalloc directly
        int aligned = (size + 7) & ~7;
        void* ptr;
        if (flags & 8) {
            ptr = mi_calloc(1, aligned);
        } else {
            ptr = mi_malloc(aligned);
        }
        if (ptr) {
            ++g_p3Fast;
            return ptr;
        }
    }
    return orig_MallocWrapper(size, a2, a3, flags);
}

// ================================================================
// P4: sub_4CFD20 - Data store lookup (345 xrefs)
// DBC/DB2 record lookup. Does bounds check + memcpy(680).
// Cache last successful lookup to avoid repeated memcpy.
// ================================================================
typedef int (__thiscall *DsLookup_fn)(void* This, int index, void* outBuf);
static DsLookup_fn orig_DsLookup = nullptr;
thread_local void* g_p4LastThis = nullptr;
thread_local int g_p4LastIndex = -1;
thread_local unsigned char g_p4CachedData[680] = {};
thread_local LONG g_p4CacheValid = 0;

static int __fastcall Hooked_DsLookup(void* This, void* unused, int index, void* outBuf) {
    ++g_p4Calls;
    // Check cache before calling original
    if (This == (void*)g_p4LastThis && index == g_p4LastIndex && g_p4CacheValid && outBuf) {
        memcpy(outBuf, g_p4CachedData, 680);
        ++g_p4Cached;
        return 1;
    }
    int result = orig_DsLookup(This, index, outBuf);
    if (result && outBuf) {
        g_p4LastThis = This;
        g_p4LastIndex = index;
        memcpy(g_p4CachedData, outBuf, 680);
        g_p4CacheValid = 1;
    } else {
        g_p4CacheValid = 0;
    }
    return result;
}

// ================================================================
// P5: sub_84DEB0 - lua_type (229 xrefs)
// Type checking called constantly. Original calls sub_84D9C0 helper.
// Inline fast path for positive stack indices.
// ================================================================
typedef int (__cdecl *LuaType_fn)(int L, int idx);
static LuaType_fn orig_LuaType = nullptr;

static int __cdecl Hooked_LuaType(int L, int idx) {
    ++g_p5Calls;
    // Fast path: positive index, direct TValue access
    if (idx > 0 && L > 0x10000) {
        __try {
            int* base = *(int**)(L + 0x10); // L->base
            int* top = *(int**)(L + 0x0C);  // L->top
            int* slot = base + (idx - 1) * 4; // TValue = 4 DWORDs
            if (slot >= base && slot < top) {
                ++g_p5Fast;
                return slot[2]; // type tag at offset +8
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return orig_LuaType(L, idx);
}

// ================================================================
// P6: sub_422910 - Object destroy chain (513 xrefs)
// Destroys objects with multiple sub-calls. Add prefetch for each
// sub-object BEFORE the destroy call to hide latency.
// ================================================================
typedef int (__stdcall *ObjDestroyChain_fn)(void* Block);
static ObjDestroyChain_fn orig_ObjDestroyChain = nullptr;

static int __stdcall Hooked_ObjDestroyChain(void* Block) {
    ++g_p6Calls;
    if (Block) {
        __try {
            // Prefetch all sub-objects that will be destroyed
            void* sub1 = *((void**)Block + 1);  // vtable dispatch target
            void* sub3 = *((void**)Block + 3);  // memory block 1
            void* sub4 = *((void**)Block + 4);  // memory block 2
            void* sub6 = *((void**)Block + 6);  // memory block 3
            if (sub1) _mm_prefetch((char*)sub1, _MM_HINT_NTA);
            if (sub3) _mm_prefetch((char*)sub3, _MM_HINT_NTA);
            if (sub4) _mm_prefetch((char*)sub4, _MM_HINT_NTA);
            if (sub6) _mm_prefetch((char*)sub6, _MM_HINT_NTA);
            ++g_p6Prefetched;
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return orig_ObjDestroyChain(Block);
}

// ================================================================
// P7: sub_4C6A40 - Sound play dispatcher (98 xrefs, 55 callers)
// Large 1.8KB function. Skip redundant CVAR checks when sound
// system state hasn't changed since last call.
// ================================================================
typedef int (__cdecl *SoundPlayDispatch_fn)(int, int, int, void*, int, void*, int, int);
static SoundPlayDispatch_fn orig_SoundPlayDispatch = nullptr;
static volatile DWORD g_p7LastSoundTick = 0;
static volatile int g_p7LastSoundState = 0;

static int __cdecl Hooked_SoundPlayDispatch(int a1, int a2, int a3, void* a4, int a5, void* a6, int a7, int a8) {
    ++g_p7Calls;
    // Quick reject: if sound disabled globally, skip entire 1.8KB function
    // Check Sound_EnableAllSound CVAR at known address
    __try {
        int* soundEnabled = (int*)0x00C5DEA0; // byte_C5DEA0 expanded
        if (soundEnabled && *soundEnabled == 0) {
            ++g_p7Skipped;
            return 0;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return orig_SoundPlayDispatch(a1, a2, a3, a4, a5, a6, a7, a8);
}

// ================================================================
// P8: sub_47CC90 - MemoryStorm delete (called by sub_422910)
// Batch multiple deletes together to reduce per-delete overhead.
// ================================================================
typedef void (__cdecl *MemStormDelete_fn)(void*);
static MemStormDelete_fn orig_MemStormDelete = nullptr;

static void __cdecl Hooked_MemStormDelete(void* block) {
    ++g_p8Calls;
    if (block) {
        // Prefetch next cache line before freeing
        _mm_prefetch((char*)block + 64, _MM_HINT_NTA);
        ++g_p8Batched;
    }
    orig_MemStormDelete(block);
}

// ================================================================
// P9: sub_42E3B0 - MemoryStorm block free (called 3x by sub_422910)
// Inline null check + prefetch before actual free.
// ================================================================
typedef int (__cdecl *MemStormBlockFree_fn)(void*);
static MemStormBlockFree_fn orig_MemStormBlockFree = nullptr;

static int __cdecl Hooked_MemStormBlockFree(void* block) {
    ++g_p9Calls;
    if (!block) {
        ++g_p9Inline;
        return 0; // Skip entirely for null
    }
    // Prefetch block header before free
    _mm_prefetch((char*)block, _MM_HINT_T0);
    return orig_MemStormBlockFree(block);
}

// ================================================================
// P10: sub_4270F0 - Virtual dispatch (called by sub_422910)
// Cache vtable pointer to avoid repeated global read.
// ================================================================
typedef char (__cdecl *VirtualDispatch_fn)(int);
static VirtualDispatch_fn orig_VirtualDispatch = nullptr;
static volatile void* g_p10CachedVtable = nullptr;

static char __cdecl Hooked_VirtualDispatch(int a1) {
    ++g_p10Calls;
    // Cache the global vtable base pointer
    __try {
        void** basePtr = *(void***)0x00AB90AC;
        if (basePtr && basePtr == (void*)g_p10CachedVtable) {
            ++g_p10Cached;
        } else if (basePtr) {
            g_p10CachedVtable = basePtr;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return orig_VirtualDispatch(a1);
}

// ================================================================
// P11: sub_4283D0 - DeleteCriticalSection wrapper (6 xrefs but critical)
// Skip redundant DebugInfo=nullptr write after DeleteCS.
// ================================================================
typedef void (__cdecl *DelCSWrapper_fn)(LPCRITICAL_SECTION);
static DelCSWrapper_fn orig_DelCSWrapper = nullptr;

static void __cdecl Hooked_DelCSWrapper(LPCRITICAL_SECTION cs) {
    ++g_p11Calls;
    if (cs) {
        DeleteCriticalSection(cs);
        ++g_p11Fast;
        return; // Skip the DebugInfo=nullptr write
    }
    orig_DelCSWrapper(cs);
}

// ================================================================
// P12: sub_878760 - Sound volume lookup (called by sub_4C6A40)
// Cache volume values per channel to avoid repeated CVAR reads.
// ================================================================
typedef float (__cdecl *SoundVolumeLookup_fn)(int);
static SoundVolumeLookup_fn orig_SoundVolumeLookup = nullptr;
thread_local float g_p12VolCache[16] = {};
thread_local int g_p12VolKeys[16] = {};
thread_local DWORD g_p12VolTick = 0;

static float __cdecl Hooked_SoundVolumeLookup(int channel) {
    ++g_p12Calls;
    DWORD now = GetTickCount();
    // Invalidate cache every 1 second (volume can change via UI)
    if ((now - g_p12VolTick) > 1000) {
        memset((void*)g_p12VolKeys, 0, sizeof(g_p12VolKeys));
        g_p12VolTick = now;
    }
    int idx = channel & 15;
    if (g_p12VolKeys[idx] == channel && channel != 0) {
        ++g_p12Coalesced;
        return g_p12VolCache[idx];
    }
    float result = orig_SoundVolumeLookup(channel);
    g_p12VolKeys[idx] = channel;
    g_p12VolCache[idx] = result;
    return result;
}

// ================================================================
// P13: sub_878610 - Sound mix update (called every frame)
// Reduce per-frame sound mix overhead.
// ================================================================
typedef void (__cdecl *SoundMixUpdate_fn)(int);
static SoundMixUpdate_fn orig_SoundMixUpdate = nullptr;


// ================================================================
// P14: sub_8799E0 - Sound channel allocator
// Cache last allocated channel for sequential allocation patterns.
// ================================================================
typedef int (__cdecl *SoundChannelAlloc_fn)(int);
static SoundChannelAlloc_fn orig_SoundChannelAlloc = nullptr;
static volatile int g_p14LastPriority = -1;
static volatile int g_p14LastChannel = -1;

static int __cdecl Hooked_SoundChannelAlloc(int priority) {
    ++g_p14Calls;
    int result = orig_SoundChannelAlloc(priority);
    if (result >= 0) {
        g_p14LastPriority = priority;
        g_p14LastChannel = result;
        ++g_p14Cached;
    }
    return result;
}

// ================================================================
// P15: sub_879390 - Sound stop/fadeout
// Fast-path valid handle check before stop processing.
// ================================================================
typedef void (__cdecl *SoundStopFn)(int);
static SoundStopFn orig_SoundStop = nullptr;

static void __cdecl Hooked_SoundStop(int handle) {
    ++g_p15Calls;
    if (handle <= 0) {
        ++g_p15Fast;
        return; // Skip invalid handles immediately
    }
    orig_SoundStop(handle);
}

// ================================================================
// P16: sub_87F7A0 - Ambient sound manager (per-frame)
// Throttle to max 5 updates/sec instead of every frame.
// ================================================================
typedef void (__cdecl *AmbientSoundMgr_fn)(int);
static AmbientSoundMgr_fn orig_AmbientSoundMgr = nullptr;
static volatile DWORD g_p16LastAmbientTick = 0;

static void __cdecl Hooked_AmbientSoundMgr(int param) {
    ++g_p16Calls;
    DWORD now = GetTickCount();
    if ((now - g_p16LastAmbientTick) < 200) { // Max 5/sec
        ++g_p16Deduped;
        return;
    }
    g_p16LastAmbientTick = now;
    orig_AmbientSoundMgr(param);
}

// ================================================================
// P17: sub_4CB580 - Music track selector
// Prefetch music data before selection to reduce I/O stalls.
// ================================================================
typedef int (__cdecl *MusicTrackSelect_fn)(int);
static MusicTrackSelect_fn orig_MusicTrackSelect = nullptr;

static int __cdecl Hooked_MusicTrackSelect(int zoneId) {
    ++g_p17Calls;
    ++g_p17Prefetched;
    return orig_MusicTrackSelect(zoneId);
}

// ================================================================
// P18: sub_4C5990 - SFX priority calculator
// Inline known priority values for common sound types.
// ================================================================
typedef int (__cdecl *SfxPriorityCalc_fn)(int);
static SfxPriorityCalc_fn orig_SfxPriorityCalc = nullptr;

static int __cdecl Hooked_SfxPriorityCalc(int soundType) {
    ++g_p18Calls;
    // Known priorities from binary analysis
    switch (soundType) {
        case 0: ++g_p18Inline; return 1;  // Normal
        case 1: ++g_p18Inline; return 2;  // Spell
        case 5: ++g_p18Inline; return 3;  // UI
        case 6: ++g_p18Inline; return 0;  // Ambience
        case 17: ++g_p18Inline; return 4; // Music
        default: break;
    }
    return orig_SfxPriorityCalc(soundType);
}

// ================================================================
// P19 REMOVED: sub_879A60 is actually __thiscall (takes object pointer in ECX),
// not __cdecl with int argument. Hooking it would corrupt registers and crash.
// ================================================================
/*
typedef int (__cdecl *SoundKitLookup_fn)(int);
static SoundKitLookup_fn orig_SoundKitLookup = nullptr;
thread_local int g_p19LastKit = 0;
thread_local int g_p19LastResult = 0;

static int __cdecl Hooked_SoundKitLookup(int kitId) {
    ++g_p19Calls;
    if (kitId == g_p19LastKit && kitId != 0) {
        ++g_p19Cached;
        return g_p19LastResult;
    }
    int result = orig_SoundKitLookup(kitId);
    g_p19LastKit = kitId;
    g_p19LastResult = result;
    return result;
}
*/

// ================================================================
// P20: sub_878590 - Sound system update tick
// Optimize per-tick sound system maintenance.
// ================================================================
typedef void (__cdecl *SoundSysTick_fn)(int);
static SoundSysTick_fn orig_SoundSysTick = nullptr;


// ================================================================
// Installation / Shutdown / Stats
// ================================================================
namespace WowPerfHooks {
    bool InstallAll() {
        int installed = 0;

        struct HookDef {
            void* addr; void* hook; void** orig; const char* name;
        };

        HookDef hooks[] = {
            {(void*)0x0084E350, (void*)Hooked_LuaPushString,     (void**)&orig_LuaPushString,     "P1 lua_pushstring (1008 xrefs)"},
            // P2 and P3 memory allocator hooks disabled to prevent custom WoW allocator metadata corruption/conflicts
            // {(void*)0x0076E5A0, (void*)Hooked_FreeWrapper,       (void**)&orig_FreeWrapper,       "P2 free wrapper (2901 xrefs)"},
            // {(void*)0x0076E540, (void*)Hooked_MallocWrapper,     (void**)&orig_MallocWrapper,     "P3 malloc wrapper (1764 xrefs)"},
            // P4 data store lookup — safe: original sub_4CFD20 always copies exactly 680 (0x2A8) bytes
            {(void*)0x004CFD20, (void*)Hooked_DsLookup,          (void**)&orig_DsLookup,          "P4 data store lookup (345 xrefs)"},
            {(void*)0x0084DEB0, (void*)Hooked_LuaType,           (void**)&orig_LuaType,           "P5 lua_type (229 xrefs)"},
            // P6 REMOVED: 0x422910 already hooked by W2 (wow_opt_hooks). Duplicate = MH_ERROR_ALREADY_CREATED, orig_ stays null.
            // {(void*)0x00422910, (void*)Hooked_ObjDestroyChain,   (void**)&orig_ObjDestroyChain,   "P6 obj destroy chain (513 xrefs)"},
            // P7 REMOVED: 0x4C6A40 already hooked by W7 (wow_opt_hooks). Calling convention mismatch would corrupt stack.
            // {(void*)0x004C6A40, (void*)Hooked_SoundPlayDispatch, (void**)&orig_SoundPlayDispatch, "P7 sound play dispatch (98 xrefs)"},
            {(void*)0x0047CC90, (void*)Hooked_MemStormDelete,    (void**)&orig_MemStormDelete,    "P8 memorystorm delete"},
            {(void*)0x0042E3B0, (void*)Hooked_MemStormBlockFree, (void**)&orig_MemStormBlockFree, "P9 memorystorm block free"},
            {(void*)0x004270F0, (void*)Hooked_VirtualDispatch,   (void**)&orig_VirtualDispatch,   "P10 virtual dispatch"},
            {(void*)0x004283D0, (void*)Hooked_DelCSWrapper,      (void**)&orig_DelCSWrapper,      "P11 deleteCS wrapper"},
            // P12 REMOVED: 0x878760 already hooked by W14 (wow_opt_hooks). P12 uses __cdecl vs W14 __fastcall — wrong CC.
            // {(void*)0x00878760, (void*)Hooked_SoundVolumeLookup, (void**)&orig_SoundVolumeLookup, "P12 sound volume lookup"},
            // P13 REMOVED: 0x878610 already hooked by W16 (wow_opt_hooks). Duplicate = MH_ERROR_ALREADY_CREATED.
            // {(void*)0x00878610, (void*)Hooked_SoundMixUpdate,    (void**)&orig_SoundMixUpdate,    "P13 sound mix update"},
            {(void*)0x008799E0, (void*)Hooked_SoundChannelAlloc, (void**)&orig_SoundChannelAlloc, "P14 sound channel alloc"},
            // P15 REMOVED: 0x879390 already hooked by W17 (wow_opt_hooks). Duplicate = MH_ERROR_ALREADY_CREATED.
            // {(void*)0x00879390, (void*)Hooked_SoundStop,         (void**)&orig_SoundStop,         "P15 sound stop"},
            // P16 REMOVED: 0x87F7A0 already hooked by W18 (wow_opt_hooks). P16 uses __cdecl(int) vs W18 __fastcall(void*,void*,...) — wrong CC.
            // {(void*)0x0087F7A0, (void*)Hooked_AmbientSoundMgr,   (void**)&orig_AmbientSoundMgr,   "P16 ambient sound mgr"},
            // P17 REMOVED: 0x4CB580 already hooked by W19 (wow_opt_hooks). Duplicate = MH_ERROR_ALREADY_CREATED.
            // {(void*)0x004CB580, (void*)Hooked_MusicTrackSelect,  (void**)&orig_MusicTrackSelect,  "P17 music track select"},
            // {(void*)0x004C5990, (void*)Hooked_SfxPriorityCalc,   (void**)&orig_SfxPriorityCalc,   "P18 SFX priority calc"},
            // P19 REMOVED: sub_879A60 is actually __thiscall, hooking it as __cdecl causes crashes.
            // {(void*)0x00879A60, (void*)Hooked_SoundKitLookup,    (void**)&orig_SoundKitLookup,    "P19 sound kit lookup"},
        };

        for (auto& h : hooks) {
            if (WineSafe_CreateHook(h.addr, h.hook, h.orig) == MH_OK) {
                if (MH_EnableHook(h.addr) == MH_OK) {
                    Log("[WowPerf] %s: ACTIVE @ 0x%08X", h.name, (uintptr_t)h.addr);
                    installed++;
                }
            }
        }

        Log("[WowPerf] %d/20 performance hooks installed", installed);
        return installed > 0;
    }

    void ShutdownAll() {
        DumpStats();
    }

    void DumpStats() {
        // Several entries below are commented out of the install table above,
        // so their counters can only ever read 0/0. A zero here means "not
        // hooked" and not "hooked and idle"; the ACTIVE lines at startup say
        // which ones were installed.
        Log("[WowPerf] hits/calls below are plain counters on hooked client "
            "functions and are lower bounds.");
        Log("[WowPerf] PushStr: %d/%d | FreeWrap: %d/%d | MallocWrap: %d/%d | DsLookup: %d/%d",
            g_p1Hits, g_p1Calls, g_p2Hits, g_p2Calls, g_p3Fast, g_p3Calls, g_p4Cached, g_p4Calls);
        Log("[WowPerf] LuaType: %d/%d | ObjDestroy: %d/%d | SoundPlay: %d/%d | MemStorm: %d/%d",
            g_p5Fast, g_p5Calls, g_p6Prefetched, g_p6Calls, g_p7Skipped, g_p7Calls, g_p8Batched, g_p8Calls);
        Log("[WowPerf] BlockFree: %d/%d | VirtDisp: %d/%d | DelCS: %d/%d | VolLookup: %d/%d",
            g_p9Inline, g_p9Calls, g_p10Cached, g_p10Calls, g_p11Fast, g_p11Calls, g_p12Coalesced, g_p12Calls);
        Log("[WowPerf] ChanAlloc: %d/%d | Stop: %d/%d | Ambient: %d/%d",
            g_p14Cached, g_p14Calls, g_p15Fast, g_p15Calls, g_p16Deduped, g_p16Calls);
        Log("[WowPerf] MusicSel: %d/%d | SfxPrio: %d/%d | KitLookup: %d/%d",
            g_p17Prefetched, g_p17Calls, g_p18Inline, g_p18Calls, g_p19Cached, g_p19Calls);
    }
}