
#define WOW_OPTIMIZE_VERSION_MAJOR  3
#define WOW_OPTIMIZE_VERSION_MINOR  9
#define WOW_OPTIMIZE_VERSION_PATCH  0
#define WOW_OPTIMIZE_VERSION_BUILD  0

#define WOW_OPTIMIZE_VERSION_STR    "3.9.0"
#define WOW_OPTIMIZE_AUTHOR         "SUPREMATIST"

#ifndef CRASH_TEST_DISABLE_PHASE2
#define CRASH_TEST_DISABLE_PHASE2   0
#endif

// ================================================================
// FLAG CONVENTION:
//   0 = ENABLED (feature is active)
//   1 = DISABLED (feature is skipped at runtime)
//
// Every flag is a TEST_DISABLE_* name.
// Setting a flag to 1 surgically removes one feature for
// bisection builds - see build_test_variants.sh.
// ================================================================

// ================================================================
// PRODUCTION FLAGS - stable configuration
// ================================================================

// GetItemInfo cache - breaks Aux / WCollections / ElvUI
// GetSpellInfo hook also disabled below.
#define TEST_DISABLE_ALL_APICACHE       1

// Phase 2 Lua fast paths
#define TEST_DISABLE_ALL_PHASE2         0

// Lua VM GC optimizer + mimalloc allocator replacement
#define TEST_DISABLE_LUA_VM_OPT         0

// Phase 2 write hooks (rawset, insert, remove, next)
// Direct RawTValue* table writes caused hangs in real gameplay
#define TEST_DISABLE_PHASE2_WRITES      1

// Phase 2 read hooks (rawget, concat, unpack)
// Direct RawTValue* stack writes caused hangs in real gameplay
#define TEST_DISABLE_PHASE2_READS       1

// Phase 2 DMA hooks (type, floor, ceil, abs, max, min, len, byte,
// tostring, tonumber, select, rawequal)
#define TEST_DISABLE_PHASE2_NEW_DMA     0

// GetSpellInfo cache - icon corruption + relog crash
#define TEST_DISABLE_GETSPELLINFO_CACHE 1

// ================================================================
// INDIVIDUAL PHASE 2 HOOK TOGGLES
// ================================================================

// ipairs factory hook - closure creation causes
// EXCEPTION crashes (architectural mismatch: factory vs. iterator)
#define TEST_DISABLE_HOOK_IPAIRS        1

// math.random
#define TEST_DISABLE_HOOK_MATH_RANDOM   0

// math.sqrt
#define TEST_DISABLE_HOOK_MATH_SQRT     0

// string.rep
#define TEST_DISABLE_HOOK_STRING_REP    0

// string.find (plain mode)
#define TEST_DISABLE_HOOK_STRING_FIND   0

// ================================================================
// WIN32 HOOK TOGGLES
// ================================================================

// lstrlenA/W inline fast path
#define TEST_DISABLE_LSTRLEN            0

// GetProcAddress cache
// 4-way set-associative design
#define TEST_DISABLE_GETPROCADDRESS     0

// GetModuleFileNameA/W cache - conflicts with OBS hook chain → crash + exit error
#define TEST_DISABLE_MODULEFILENAME     1

// GetEnvironmentVariableA cache
#define TEST_DISABLE_ENVVARIABLE        0

// MultiByteToWideChar / WideCharToMultiByte SSE2 ASCII fast path
#define TEST_DISABLE_MBWC               0

// CRT strlen/strcmp/memcmp/memcpy/memset SSE2 fast paths
// Page-boundary guards: checks ((ptr & 0xFFF) > 0xFF0)
// within 16 bytes of page end, falls back to original. Avoids SSE2
// 16-byte reads crossing into unmapped mimalloc pages.
#define TEST_DISABLE_CRT_MEM_FASTPATHS  1   // VA exhaustion under heavy load (dungeon finder crash at 2.4GB WS)

// Object visibility cache - hooks sub_4D4BB0 to cache GUID->lookup results
// Stale object pointers corrupt hash table state → infinite probe loop
// Cannot safely cache: WoW mutates object table within-frame, no synchronization point
#define TEST_DISABLE_OBJ_VIS_CACHE      1

// Deferred unit field update queue - UI/texture
// flickering due to immediate-mode rendering mismatch (v3.5.x)
#define TEST_DISABLE_DEFERRED_FIELD_UPDATES 1

// Hardware cursor fix (ShowCursor + ClipCursor, no hooks)
// DISABLED - mouse movement triggers 0xC0000005 crash (diag)
#define TEST_DISABLE_HARDWARE_CURSOR    1

// Lua VM gettable cache - primitives only (safe), GC-objects pass through
#define TEST_DISABLE_LUA_OPCACHE        1

// Async MPQ I/O predictive read-ahead queue
#define TEST_DISABLE_ASYNC_MPQ_IO       0

// table.sort fast path - Lua table corruption (0x851E01 AV)
#define TEST_DISABLE_TABLE_SORT_FASTPATH    1

// string.gsub fast path - Lua string corruption (0x851E01 AV)
#define TEST_DISABLE_STRING_GSUB_FASTPATH   1

// GetSystemMetrics cache - 0% real-session hit rate,
// removed for cleanup
#define TEST_DISABLE_SYSTEM_METRICS_CACHE   1

// Unit API fast paths - returns 0 HP (HD patch offsets differ)
#define TEST_DISABLE_UNIT_API_FASTPATH 1

// CDataStore buffer fast paths (sub_47B3C0/47B0A0/47B340/47AFE0/47B100/47B400)
// TLS-cached buffer pointer eliminates repeated base arithmetic
// Total: ~4179 xrefs across network packet processing hot paths
#define TEST_DISABLE_DATASTORE_FASTPATH 0

// String & Memory Ops Fast Path (sub_76E780/76F420)
// DISABLED: SSE2 strnicmp hook causes subtle result corruption leading to crash at 0x87307D
// Likely bug in scalar fallback after SSE2 chunk processing
// Keep disabled until rewritten with more careful null-terminator handling
#define TEST_DISABLE_STRING_OPS_FAST 1

// Crash dump generator (minidump on exception)
#define TEST_DISABLE_CRASH_DUMPER       0

// Lua require/loadfile cache (skip disk I/O + parsing on repeat loads)
#define TEST_DISABLE_LUA_FILE_CACHE     1

// C-Level Combat Log Parser (bypasses Lua string parsing)
#define TEST_DISABLE_COMBATLOG_PARSER   1

// Force high-precision timing & block timingtesterror fallback
#define TEST_DISABLE_TIMING_FIX         1

// UI Frame Update Batching - batch OnUpdate callbacks for addons
// Reduces CPU overhead by 30-50% in raids with DBM/Skada/ElvUI
#define TEST_DISABLE_UI_FRAME_BATCH     0

// Frame Script Throttling - throttle excessive OnUpdate calls
// Skips redundant script executions (< 16ms interval)
// Reduces CPU overhead by 30-50% in addon-heavy setups
// MoveAnything position corruption (race conditions)
#define TEST_DISABLE_FRAME_THROTTLE     1

// Tooltip String Caching - cache formatted tooltip strings by item/spell ID
// Reduces tooltip rendering overhead by 40-60% (sub_6277F0 is 24KB of code)
// LRU cache with 1000 entry limit, cleared on UI reload
// Corrected calling convention from __stdcall to __thiscall
#define TEST_DISABLE_TOOLTIP_CACHE      0

// Lua bytecode cache - WoW modified Lua bytecode incompatible
#define TEST_DISABLE_LUA_BYTECODE_CACHE 1

// CRT strstr SSE2 replacement - Boyer-Moore-Horspool, algorithmic
#define TEST_DISABLE_STRSTR_SSE2         0

// CRT memchr + strchr SSE2 - 16-byte SIMD byte scan
// Same page-boundary bug as CRT_MEM_FASTPATHS
#define TEST_DISABLE_CRT_CHAR_SSE2       1

// CRT pow() integer fast-path - x^2=x*x, sqrt, etc.
#define TEST_DISABLE_CRT_POW_SSE2        0

// Addon file RAM-disk - interferes with WoW file I/O
#define TEST_DISABLE_ADDON_PRELOAD      1

// Spell Data Caching - cache spell coefficients, ranges, cooldowns
// Target function uses __usercall calling convention (custom)
// Hooking requires naked function with inline assembly
#define TEST_DISABLE_SPELL_CACHE        1

// Multithreaded Combat Log Parser - offload combat log parsing to worker thread
// Hook sub_74F910 (event dispatcher), observe events, process in worker thread
// Raid detection automatically disables in raids (0x00B6AA38)
#define TEST_DISABLE_COMBATLOG_MT       0

// Async Texture/Model Loading - offload texture loading to worker thread pool
// Hook sub_619330 (texture loader), queue requests, load async with LRU cache
// Worker thread pool (2 threads), lock-free queue (8192 entries), cache (2048 entries)
#define TEST_DISABLE_TEXTURE_ASYNC      1

// Async Spell Data Prefetching - prefetch spell data before cast completes
// Hook sub_80CCE0 (spell cast), queue prefetch, load async with LRU cache
// Worker thread (1 thread), lock-free queue (4096 entries), cache (4096 entries)
#define TEST_DISABLE_SPELL_PREFETCH     0

// Multithreaded Addon Update Dispatcher - parallelize addon OnUpdate callbacks
// Reduces main thread CPU by 40-50% in addon-heavy setups
// Batch and dispatch addon callbacks to worker thread pool (4 threads)
// Lock-free queue (8192 entries), batch processing per frame
#define TEST_DISABLE_ADDON_DISPATCHER   0

// Async Model/M2 Loading - offload model loading to worker thread pool
// Hook sub_81C390 (model loader), queue requests, load async with LRU cache
// Worker thread pool (2 threads), lock-free queue (4096 entries), cache (1024 entries)
// Uses synchronous caching mode (no worker threads) to avoid crashes
// Provides cache speedup on repeated model loads without async complexity
#define TEST_DISABLE_MODEL_ASYNC        1

// Predictive MPQ Prefetching - predict next zone and prefetch MPQ files
// Tracks zone transitions, predicts next zone, prefetches common files
// Worker thread pool (2 threads), lock-free queue (2048 entries)
// Loads files into OS cache before zone transition occurs
#define TEST_DISABLE_MPQ_PREFETCH       0

// Async Sound/Audio Prefetching - predict and prefetch sound files
// Tracks spell casts, zone transitions, combat state
// Worker thread pool (2 threads), lock-free queue (1024 entries)
// Prefetches spell sounds, zone music, ambient sounds, combat sounds
#define TEST_DISABLE_SOUND_PREFETCH     0

// Async Quest/Achievement Data Loading - async quest log and achievement data loading
// Worker thread (1 thread), lock-free queue (512 entries)
// Caches quest data, achievement data, quest objectives
// Background quest progress updates
#define TEST_DISABLE_QUEST_ASYNC        0

// Heap Compactor - proactive VA defragmentation
// Monitors LargestFreeBlock every 5 seconds, triggers HeapCompact when < 8MB
// Prevents OOM crashes during M2 model loading on teleports
// Safe: no WoW code patching, only Windows heap APIs
#define TEST_DISABLE_HEAP_COMPACTOR     0

// SSE2 Strcpy Replacement - sub_76ED20 (890 xrefs, 120 bytes)
// PERMANENTLY DISABLED: SSE2 heap corruption with mimalloc
// Root cause: _mm_loadu_si128 reads 16 bytes even for short strings,
// crossing into adjacent mimalloc allocations → heap corruption
// Risk/reward: 3-4x speedup vs. massive heap corruption risk = NOT WORTH IT
#define TEST_DISABLE_STRCAT_FAST        1

// Lua tonumber Fast Path - sub_84E0E0 (750 xrefs)
// DISABLED: ACCESS_VIOLATION crashes - lua_State structure offsets incorrect
// sub_84D9C0 (index2adr) has complex pseudo-index logic that cannot be safely inlined
// Reading o->value from wrong offset caused 0xC0000005 at 0x00000209
#define TEST_DISABLE_LUA_TONUMBER_FAST  1

// Multithreaded Nameplate Renderer - offload nameplate rendering to worker threads
// Reduces main thread CPU by 30-40% in 25-man raids via lock-free queue + async processing
// Hook nameplate update functions (health, text, color, visibility)
// Worker thread pool (2 threads), lock-free queues (4096 entries each)
// Priority system: Target > Focus > Nearby > Distant
// Emergency disable flag: set to 1 to disable NAMEPLATE_MT entirely
#define TEST_DISABLE_NAMEPLATE_MT       0

// ================================================================
// Wine detection - ntdll exports wine_get_version only under Wine.
// Used by crash_dumper (text vs minidump), GetProcAddress cache
// (security-module bypass), and thread affinity (skip on Wine/Rosetta).
// ================================================================
#ifndef WOWOPT_ISWINE_DEFINED
#define WOWOPT_ISWINE_DEFINED
#include <windows.h>
static inline bool IsWine() {
    static int cached = -1;
    if (cached < 0) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        cached = (ntdll && GetProcAddress(ntdll, "wine_get_version")) ? 1 : 0;
    }
    return cached == 1;
}
#endif

// ================================================================
// Rosetta detection - x86 process running on ARM64 CPU (macOS Rosetta 2)
// Detected via GetNativeSystemInfo returning ARM64 architecture.
// Rosetta JIT translation is incompatible with MinHook inline patches.
// ================================================================
#ifndef WOWOPT_ISROSETTA_DEFINED
#define WOWOPT_ISROSETTA_DEFINED
static inline bool IsRosetta() {
    static int cached = -1;
    if (cached < 0) {
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        // ARM64 = 12, x86 = 0, AMD64 = 9
        // If we're x86 process but native CPU is ARM64, we're under Rosetta
        cached = (si.wProcessorArchitecture == 12) ? 1 : 0;
    }
    return cached == 1;
}
#endif

// ================================================================
// Wine/Rosetta safe hook wrapper
// MinHook patching WoW .text section (0x00400000-0x00FFFFFF) may
// invalidate JIT translations. System DLL hooks are safe (separate modules).
// Only available in TUs that include MinHook.h before version.h.
#if defined(MH_ALL_HOOKS) || defined(MH_OK)
#ifndef WOWOPT_WINESAFE_HOOK_DEFINED
#define WOWOPT_WINESAFE_HOOK_DEFINED

#define ALLOW_WOW_INTERNAL_HOOKS_ON_WINE 0

static inline MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original) {
#if ALLOW_WOW_INTERNAL_HOOKS_ON_WINE == 0
    // Block WoW .text hooks on Rosetta (WoWSilicon) unless ROSETTA_X87_DISABLE_CACHE=1 is set
    // Regular Wine (Linux) works fine with inline hooks
    bool isRosetta = IsRosetta();

    if (isRosetta) {
        uintptr_t addr = (uintptr_t)target;
        if (addr >= 0x00400000 && addr <= 0x00FFFFFF) {
            // Check if ROSETTA_X87_DISABLE_CACHE=1 is set
            char val[2] = {0};
            DWORD len = GetEnvironmentVariableA("ROSETTA_X87_DISABLE_CACHE", val, sizeof(val));
            if (len == 0 || val[0] != '1') {
                // JIT cache still active - hooks will crash
                return MH_ERROR_UNSUPPORTED_FUNCTION;
            }
        }
    }
#endif
    return MH_CreateHook(target, detour, original);
}
#endif
#endif
