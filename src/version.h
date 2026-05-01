#pragma once

#define WOW_OPTIMIZE_VERSION_MAJOR  3
#define WOW_OPTIMIZE_VERSION_MINOR  5
#define WOW_OPTIMIZE_VERSION_PATCH  14
#define WOW_OPTIMIZE_VERSION_BUILD  0

#define WOW_OPTIMIZE_VERSION_STR    "3.5.14"
#define WOW_OPTIMIZE_AUTHOR         "SUPREMATIST"

#ifndef CRASH_TEST_DISABLE_PHASE2
#define CRASH_TEST_DISABLE_PHASE2   0
#endif

// Apply to large file-scope mutable globals (queues, ring buffers) that
// would otherwise be eligible for clang's globalopt promotion to LLVM IR
// `constant` at /O2. That promotion lands them in read-only .rdata as
// on-disk zero bytes, which (a) bloats the cross-built DLL and (b) makes
// the buffers unwritable at runtime. MSVC's cl.exe doesn't do this
// promotion, so the macro expands to nothing there.
#if defined(__clang__)
#define WO_KEEP_BSS __attribute__((used))
#else
#define WO_KEEP_BSS
#endif

// ================================================================
// FLAG CONVENTION:
//   0 = ENABLED  (feature is active)
//   1 = DISABLED (feature is skipped at runtime)
//
// Every flag is a TEST_DISABLE_* name.
// Setting a flag to 1 surgically removes one feature for
// bisection builds — see build_test_variants.sh.
// ================================================================

// ================================================================
// PRODUCTION FLAGS — stable v3.5.11 configuration
// ================================================================

// GetItemInfo cache — disabled: breaks Aux / WCollections / ElvUI
// (Morbent, 9 test builds). GetSpellInfo hook also disabled below.
#define TEST_DISABLE_ALL_APICACHE       1

// Phase 2 Lua fast paths — enabled: stable since v3.5.5
#define TEST_DISABLE_ALL_PHASE2         0

// Lua VM GC optimizer + mimalloc allocator replacement — enabled
#define TEST_DISABLE_LUA_VM_OPT         0

// Phase 2 write hooks (rawset, insert, remove, next) — disabled:
// direct RawTValue* table writes caused hangs in real gameplay
#define TEST_DISABLE_PHASE2_WRITES      1

// Phase 2 read hooks (rawget, concat, unpack) — disabled:
// direct RawTValue* stack writes caused hangs in real gameplay
#define TEST_DISABLE_PHASE2_READS       1

// Phase 2 DMA hooks (type, floor, ceil, abs, max, min, len, byte,
// tostring, tonumber, select, rawequal) — enabled: stable
#define TEST_DISABLE_PHASE2_NEW_DMA     0

// GetSpellInfo cache — disabled: icon corruption + relog crash
#define TEST_DISABLE_GETSPELLINFO_CACHE 1

// ================================================================
// INDIVIDUAL PHASE 2 HOOK TOGGLES
// ================================================================

// ipairs factory hook — disabled: closure creation causes
// EXCEPTION crashes (architectural mismatch: factory vs. iterator)
#define TEST_DISABLE_HOOK_IPAIRS        1

// math.random — enabled: stable, tested
#define TEST_DISABLE_HOOK_MATH_RANDOM   0

// math.sqrt — enabled: stable, tested
#define TEST_DISABLE_HOOK_MATH_SQRT     0

// string.rep — enabled: stable, tested
#define TEST_DISABLE_HOOK_STRING_REP    0

// string.find (plain mode) — enabled: stable, tested
#define TEST_DISABLE_HOOK_STRING_FIND   0

// ================================================================
// WIN32 HOOK TOGGLES
// ================================================================

// lstrlenA/W inline fast path — enabled: cleared of alt-tab crash
// via 3-way bisection in v3.5.10 (MBWC/LSTRLEN/ENV isolation)
#define TEST_DISABLE_LSTRLEN            0

// GetProcAddress cache — enabled: v3.5.13 fixes hash collision
// via 4-way set-associative design (was direct-mapped in v3.5.11)
#define TEST_DISABLE_GETPROCADDRESS     0

// GetModuleFileNameA/W cache — disabled: conflicts with OBS hook
// chain → crash + exit error reported in production
#define TEST_DISABLE_MODULEFILENAME     1

// GetEnvironmentVariableA cache — enabled: v3.5.13 fixes NULL-deref
// crash via lpBuffer validation (isolated via bisection in v3.5.10)
#define TEST_DISABLE_ENVVARIABLE        0

// MultiByteToWideChar / WideCharToMultiByte SSE2 ASCII fast path —
// enabled: cleared of alt-tab crash via 3-way bisection in v3.5.10
#define TEST_DISABLE_MBWC               0

// CRT strlen/strcmp/memcmp/memcpy/memset SSE2 fast paths —
// disabled: causes deadlock/freeze 5-10s after game start
#define TEST_DISABLE_CRT_MEM_FASTPATHS  1

// Deferred unit field update queue — disabled: UI/texture
// flickering due to immediate-mode rendering mismatch (v3.5.x)
#define TEST_DISABLE_DEFERRED_FIELD_UPDATES 1

// Hardware cursor fix (ShowCursor + ClipCursor, no hooks) —
// enabled: stable, shipped in v3.5.11
#define TEST_DISABLE_HARDWARE_CURSOR    0

// Async MPQ I/O predictive read-ahead queue —
// enabled: stable, shipped in v3.5.11
#define TEST_DISABLE_ASYNC_MPQ_IO       0

// table.sort fast path — disabled: persistent 0x00000004 AV on
// HD clients due to corrupted table pointers
#define TEST_DISABLE_TABLE_SORT_FASTPATH    1

// string.gsub fast path — disabled: luaS_newlstr crashes on HD
// clients due to % replacement semantics and buffer edge cases
#define TEST_DISABLE_STRING_GSUB_FASTPATH   1

// GetSystemMetrics cache — disabled: 0% real-session hit rate,
// removed for cleanup
#define TEST_DISABLE_SYSTEM_METRICS_CACHE   1

// Unit API fast paths — disabled: causes ElvUI breakage and character select AV
// Requires full taint propagation handling and UI-state guards before re-enabling.
#define TEST_DISABLE_UNIT_API_FASTPATH 1

// Crash dump generator (minidump on exception)
#define TEST_DISABLE_CRASH_DUMPER       0

// Lua require/loadfile cache (skip disk I/O + parsing on repeat loads)
#define TEST_DISABLE_LUA_FILE_CACHE     1

// C-Level Combat Log Parser (bypasses Lua string parsing)
#define TEST_DISABLE_COMBATLOG_PARSER   1

// Force high-precision timing & block timingtesterror fallback
#define TEST_DISABLE_TIMING_FIX         0

// UI Frame Update Batching — batch OnUpdate callbacks for addons
// Reduces CPU overhead by 30-50% in raids with DBM/Skada/ElvUI
#define TEST_DISABLE_UI_FRAME_BATCH     0  // DISABLED - calling convention mismatch breaks UI

// Frame Script Throttling — throttle excessive OnUpdate calls
// Skips redundant script executions (< 16ms interval)
// Reduces CPU overhead by 30-50% in addon-heavy setups
// DISABLED: causes MoveAnything position corruption (race conditions)
#define TEST_DISABLE_FRAME_THROTTLE     1  // DISABLED - breaks MoveAnything (positions reset)

// Tooltip String Caching — cache formatted tooltip strings by item/spell ID
// Reduces tooltip rendering overhead by 40-60% (sub_6277F0 is 24KB of code)
// LRU cache with 1000 entry limit, cleared on UI reload
// FIXED: corrected calling convention from __stdcall to __thiscall
#define TEST_DISABLE_TOOLTIP_CACHE      0  // ENABLED - ready for testing

// Spell Data Caching — cache spell coefficients, ranges, cooldowns
// Reduces spell casting overhead by 25-35% (sub_80E1B0 is 7.4KB of code)
// LRU cache with 2000 entry limit, cleared on UI reload
// DISABLED: target function uses __usercall calling convention (custom)
// Hooking requires naked function with inline assembly - too complex
#define TEST_DISABLE_SPELL_CACHE        1  // DISABLED - __usercall not supported

// Multithreaded Combat Log Parser — offload combat log parsing to worker thread
// Reduces main thread CPU by 40-60% in raids via lock-free queue + async processing
// Hook sub_74F910 (event dispatcher), observe events, process in worker thread
// FIXED: now hooks event dispatcher instead of entry creation (addon-compatible)
// v3.5.14: Raid detection automatically disables COMBATLOG_MT in raids (0x00B6AA38)
// Emergency disable flag: set to 1 to disable COMBATLOG_MT entirely
// Raid detection logic automatically disables in raids when flag is 0
#define TEST_DISABLE_COMBATLOG_MT       0  // ENABLED - raid detection active (v3.5.14)

// Async Texture/Model Loading — offload texture loading to worker thread pool
// Eliminates 80-90% of loading stutters during teleports/zone changes
// Hook sub_619330 (texture loader), queue requests, load async with LRU cache
// Worker thread pool (2 threads), lock-free queue (8192 entries), cache (2048 entries)
// ENABLED in v3.5.14 for full testing
#define TEST_DISABLE_TEXTURE_ASYNC      0  // ENABLED - full testing (v3.5.14)

// Async Spell Data Prefetching — prefetch spell data before cast completes
// Reduces spell cast lag by 30-40% via predictive data loading
// Hook sub_80CCE0 (spell cast), queue prefetch, load async with LRU cache
// Worker thread (1 thread), lock-free queue (4096 entries), cache (4096 entries)
// ENABLED in v3.5.14 for full testing
#define TEST_DISABLE_SPELL_PREFETCH     0  // ENABLED - full testing (v3.5.14)

// Multithreaded Addon Update Dispatcher — parallelize addon OnUpdate callbacks
// Reduces main thread CPU by 40-50% in addon-heavy setups
// Batch and dispatch addon callbacks to worker thread pool (4 threads)
// Lock-free queue (8192 entries), batch processing per frame
// ENABLED in v3.5.14 for full testing
#define TEST_DISABLE_ADDON_DISPATCHER   0  // ENABLED - full testing (v3.5.14)

// Async Model/M2 Loading — offload model loading to worker thread pool
// Eliminates 70-80% of model loading stutters during teleports/zone changes
// Hook sub_81C390 (model loader), queue requests, load async with LRU cache
// Worker thread pool (2 threads), lock-free queue (4096 entries), cache (1024 entries)
// UPDATED: Now uses synchronous caching mode (no worker threads) to avoid crashes
// Provides cache speedup on repeated model loads without async complexity
// ENABLED in v3.5.14 for full testing
#define TEST_DISABLE_MODEL_ASYNC        0  // ENABLED - full testing (v3.5.14)

// Predictive MPQ Prefetching — predict next zone and prefetch MPQ files
// Eliminates 50-60% of zone loading stutters via predictive file caching
// Tracks zone transitions, predicts next zone, prefetches common files
// Worker thread pool (2 threads), lock-free queue (2048 entries)
// Loads files into OS cache before zone transition occurs
// ENABLED in v3.5.14 for full testing
#define TEST_DISABLE_MPQ_PREFETCH       0  // ENABLED - full testing (v3.5.14)

// Async Sound/Audio Prefetching — predict and prefetch sound files
// Eliminates 40-50% of audio loading stutters via predictive sound caching
// Tracks spell casts, zone transitions, combat state
// Worker thread pool (2 threads), lock-free queue (1024 entries)
// Prefetches spell sounds, zone music, ambient sounds, combat sounds
#define TEST_DISABLE_SOUND_PREFETCH     0  // ENABLED - full testing (v3.5.14)

// Async Quest/Achievement Data Loading — async quest log and achievement data loading
// Eliminates 60-70% of quest log opening lag via background data loading
// Worker thread (1 thread), lock-free queue (512 entries)
// Caches quest data, achievement data, quest objectives
// Background quest progress updates
#define TEST_DISABLE_QUEST_ASYNC        0  // ENABLED - full testing (v3.5.14)

// Multithreaded Nameplate Renderer — offload nameplate rendering to worker threads
// Reduces main thread CPU by 30-40% in 25-man raids via lock-free queue + async processing
// Hook nameplate update functions (health, text, color, visibility)
// Worker thread pool (2 threads), lock-free queues (4096 entries each)
// Priority system: Target > Focus > Nearby > Distant
// Emergency disable flag: set to 1 to disable NAMEPLATE_MT entirely
#define TEST_DISABLE_NAMEPLATE_MT       0  // ENABLED - full testing (v3.5.14)


// Multithreaded Nameplate Renderer — offload nameplate rendering to worker threads
// Reduces main thread CPU by 30-40% in 25-man raids via lock-free queue + async processing
// Hook nameplate update functions (health, text, color, visibility)
// Worker thread pool (2 threads), lock-free queues (4096 entries each)
// Priority system: Target > Focus > Nearby > Distant
// Emergency disable flag: set to 1 to disable NAMEPLATE_MT entirely
#define TEST_DISABLE_NAMEPLATE_MT       0  // ENABLED - full testing (v3.5.14)
