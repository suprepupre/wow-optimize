#pragma once

// ============================================================================
// Module: version.h
// ============================================================================





#define WOW_OPTIMIZE_VERSION_MAJOR  3
#define WOW_OPTIMIZE_VERSION_MINOR  18
#define WOW_OPTIMIZE_VERSION_PATCH  1
#define WOW_OPTIMIZE_VERSION_BUILD  0

#define WOW_OPTIMIZE_VERSION_STR    "3.18.1"
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

// GetItemInfo cache. This flag has been 0 - the cache enabled - for as long as
// the comment above it said the cache "breaks Aux / WCollections / ElvUI",
// which is not a note anyone should have left next to an enabled feature.
//
// The likely reason is now fixed. The cache is direct-mapped and compared its
// string key after truncating to 255 characters, so two arguments sharing a
// 255-character prefix compared equal and one item's data was served for
// another. Aux walks tens of thousands of item links in a scan, which is the
// workload that finds a collision of that kind. Keys that do not fit now bypass
// the cache instead of being truncated. Also gone: an "is it loaded" test that
// read return value four as the item level and refused to store anything with
// an item level of zero, and a result count taken from how many values the
// client pushed rather than how many it returned.
#define TEST_DISABLE_GETITEMINFO_CACHE  0
#define TEST_DISABLE_ALL_APICACHE       0

// Phase 2 Lua fast paths
#define TEST_DISABLE_ALL_PHASE2         0

// Lua VM GC optimizer + mimalloc allocator replacement
#define TEST_DISABLE_LUA_VM_OPT         0

// HARD-DISABLED after a heap-corruption crash. The large-only opt-in redirect
// still hits the same fundamental flaw as the original full CRT redirect: a
// >=1MB block allocated through our malloc hook but freed through a path we do
// NOT hook (operator delete / _free_base / _aligned_free / a driver's own free)
// reaches ntdll's HeapFree as a mimalloc pointer and corrupts the heap free-list
// — observed as a 0xC0000005 in ntdll's free-list splice during raid-exit
// teardown (mass frees). Covering every free path safely is a large, risky
// surface, and the sampling profiler showed the allocator/CPU path is not the
// frame-time bottleneck (WoW-side code is <1% each), so the redirect is not
// worth its crash risk. Removed from the launcher; keep the code for reference.
#define TEST_DISABLE_MIMALLOC_LARGE 1

// Gate for the Lua error diagnostic hook. The hook targets 0x84F610 which
// disassembly-verified is sub_84F610(size_t Size) — luaL_addvalue, NOT lua_error.
// Hooking it as lua_error causes all 50 logged entries to show <unable to read>
// (the L parameter is actually a size_t) and fills the log with noise.
// Set to 1 to disable until the correct lua_error address is found.
#define TEST_DISABLE_LUA_ERROR_DIAG         0

// Redirect process-heap HeapAlloc/HeapFree/HeapReAlloc/HeapSize to mimalloc.
// Catches allocations from Win32 APIs (D3D, WinMM, crypto, shell, OLE) that
// bypass CRT malloc entirely and would otherwise fragment the stock process
// heap on the 32-bit VA. Active only for GetProcessHeap(); other heaps are
// untouched. Uses the same mi_is_in_heap_region guard as the CRT redirect.
// ENABLED by default; set to 1 to revert to stock process heap.
// TEMPORARILY DISABLED: silent exit within seconds of launch. The mi_malloc
// pointers returned by hooked_HeapAlloc are not valid process-heap blocks,
// and Win32 APIs that internally HeapValidate/HeapWalk/HeapSize on them
// detect corruption → CRT abort() → silent exit. Needs a redesign: either
// use a private mimalloc heap that masquerades as the process heap, or
// only redirect allocations above a size threshold where win32 internals
// don't track pointers.
#define TEST_DISABLE_HEAP_REDIRECT        1

// Phase 2 write hooks (rawset, insert, remove, next)
// Direct RawTValue* table writes caused hangs in real gameplay
#define TEST_DISABLE_PHASE2_WRITES      0

// Phase 2 read hooks (rawget, concat, unpack)
// Direct RawTValue* stack writes caused hangs in real gameplay
#define TEST_DISABLE_PHASE2_READS       0

// Phase 2 DMA hooks (type, floor, ceil, abs, max, min, len, byte,
// tostring, tonumber, select, rawequal)
#define TEST_DISABLE_PHASE2_NEW_DMA     0

// ================================================================
// INDIVIDUAL PHASE 2 HOOK TOGGLES
// ================================================================

// ipairs factory hook - closure creation causes
// EXCEPTION crashes (architectural mismatch: factory vs. iterator)
#define TEST_DISABLE_HOOK_IPAIRS        0

// math.random
#define TEST_DISABLE_HOOK_MATH_RANDOM   0

// math.sqrt
#define TEST_DISABLE_HOOK_MATH_SQRT     0

// string.rep
#define TEST_DISABLE_HOOK_STRING_REP    0

// string.gsub plain-literal fast path (plain pattern + literal replacement only;
// falls back to the engine for magic patterns, capture refs, function/table repl)
#define TEST_DISABLE_HOOK_STR_GSUB      0

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
#define TEST_DISABLE_MODULEFILENAME     0

// GetEnvironmentVariableA cache
#define TEST_DISABLE_ENVVARIABLE        0

// MultiByteToWideChar / WideCharToMultiByte SSE2 ASCII fast path
#define TEST_DISABLE_MBWC               0

// CRT strlen/strcmp/memcmp/memcpy/memset SSE2 fast paths.
// DISABLED: the per-chunk page guard + recursion guard + init gate fixes
// addressed the obvious bugs but the feature still crashes in-game
// (STACK_OVERFLOW at 0x40BB77 on world load, ACCESS_VIOLATION in ntdll
// on logout). Root cause is deeper — likely TLS-access recursion during
// thread init or interaction with mimalloc's internal memcpy usage.
// The 87% memcpy fallback rate (from page-boundary guard) also suggests
// the guard is too aggressive, causing double-work on fallback. Keep
// disabled until the TLS recursion root cause is fully diagnosed.
#define TEST_DISABLE_CRT_MEM_FASTPATHS  1

// Object visibility cache - hooks sub_4D4BB0 to cache GUID->lookup results.
// RE-ENABLED: the disable reason above is stale. It described an older design
// that wrote back into WoW's hash table (hence "corrupt hash table state ->
// infinite probe loop"). The current obj_vis_cache.cpp is a READ-ONLY result
// cache — it never mutates WoW's object table, only stores the lookup result
// in its own per-thread pool and returns early on a hit. Staleness is guarded
// four ways: (1) per-frame frameStamp (entries expire every frame via
// OnFrame()); (2) GUID re-verification — a hit re-reads the object's own GUID
// at +0x30 and only returns it if it still matches, so a freed/recycled
// pointer is rejected; (3) InvalidateObjVisCacheFor on UnlinkNode; (4) SEH +
// teardown/reload/swap bypass. Exposed as a launcher checkbox (General/
// ObjVisCache), default OFF/opt-in since it's an unverified hot path — enable
// it in the launcher and watch for unit/object misbehavior or hangs.
#define TEST_DISABLE_OBJ_VIS_CACHE      1

// Deferred unit field update queue v2 - Lock-free SPSC batch processor.
// STALE COMMENT WARNING: the paragraph below describes a v2 fix for an
// older race-condition crash and was written back when this flag was 0.
// It is currently 1 (disabled) for a DIFFERENT, more recent reason: commit
// 87e68e6 ("Disable culling, coalescing, and deferred updates to resolve
// camera and buff update latency") disabled this again because deferring
// UNIT_FIELD_AURA (offset 0x48, >= the 0x40 critical-field cutoff and not
// in the immediate-processing whitelist below) reproduces the same aura/
// buff desync bug documented in CONTEXT.md lesson #2. This flag has been
// enabled and disabled roughly 15 times across this project's history for
// a different symptom nearly every time (race conditions, texture/minimap
// flickering, chat history bugs, camera snapping, empty frames, weapon-
// swap lag, buff latency) — treat any single fix here as addressing ONE
// symptom, not the feature as a whole. Do not re-enable without a full
// manual test pass covering all of the above, not just the aura case.
// v2 fixes applied on top of the original race-condition crash:
// - volatile void* for atomic unit pointer access
// - Data fields written BEFORE tail advance (memory ordering)
// - InterlockedExchangePointer for ownership claim in flush
// - InvalidateDeferredFieldUpdatesFor uses CAS correctly
// - SEH + pointer range validation guards against freed units
// Critical fields (fieldId < 0x40) bypass queue for gameplay correctness.
#define TEST_DISABLE_DEFERRED_FIELD_UPDATES 1

// Hardware cursor fix (ShowCursor + ClipCursor(NULL), no hooks, no WoW memory
// writes). The diagnosed crash cause was two direct byte patches (0xCABCDD/
// CABCDE forcing gxCursor=0 + gxFixLag=1) that activated an uninitialized
// cursor rendering path on private servers (Circle/Warmane) -> NULL deref.
// Those two patch lines are already commented out in dllmain.cpp; the only
// code left in this path is ShowCursor(TRUE) and ClipCursor(NULL) (releases
// any clip region, does not add one — distinct from CONTEXT lesson 13's
// mouselook-clipping bug, which is about actively clipping the cursor).
// RE-ENABLED: the actual crash cause is gone from the code.
#define TEST_DISABLE_HARDWARE_CURSOR    0

// Lua VM gettable cache - primitives only (safe), GC-objects pass through
#define TEST_DISABLE_LUA_OPCACHE         0

// Async MPQ I/O predictive read-ahead queue
#define TEST_DISABLE_ASYNC_MPQ_IO       0

// table.sort fast path - Lua table corruption (0x851E01 AV)
#define TEST_DISABLE_TABLE_SORT_FASTPATH    0

// string.gsub fast path - Lua string corruption (0x851E01 AV)
#define TEST_DISABLE_STRING_GSUB_FASTPATH   0

// GetSystemMetrics cache - 0% real-session hit rate,
// removed for cleanup
#define TEST_DISABLE_SYSTEM_METRICS_CACHE   1

// Unit API fast paths - returns 0 HP (HD patch offsets differ)
#define TEST_DISABLE_UNIT_API_FASTPATH 0  // enabled: safe cache with GUID invalidation on OnFieldUpdate
// CDataStore buffer fast paths (sub_47B3C0/47B0A0/47B340/47AFE0/47B100/47B400)
// TLS-cached buffer pointer eliminates repeated base arithmetic
// Total: ~4179 xrefs across network packet processing hot paths
#define TEST_DISABLE_DATASTORE_FASTPATH 0

// String & Memory Ops Fast Path (sub_76E780/76F420)
// DISABLED: SSE2 strnicmp hook causes subtle result corruption leading to crash at 0x87307D
// Likely bug in scalar fallback after SSE2 chunk processing
// Keep disabled until rewritten with more careful null-terminator handling
#define TEST_DISABLE_STRING_OPS_FAST         0

// Crash dump generator (minidump on exception)
#define TEST_DISABLE_CRASH_DUMPER       0

// Lua require/loadfile cache (skip disk I/O + parsing on repeat loads)
#define TEST_DISABLE_LUA_FILE_CACHE         0

// C-Level Combat Log Parser (bypasses Lua string parsing)
#define TEST_DISABLE_COMBATLOG_PARSER   0

// Force high-precision timing & block timingtesterror fallback
#define TEST_DISABLE_TIMING_FIX         0

// Custom Lua VM Engine (direct-threaded interpreter) - crashes on transitions/raids
#define TEST_DISABLE_LUA_VM_ENGINE         1

// FrameScript hash dispatch - 18 handlers, O(1) FNV-1a hash, disassembly-verified
#define TEST_DISABLE_FRAME_SCRIPT_DISPATCH 0

// UI Frame Update Batching - batch OnUpdate callbacks for addons
// Reduces CPU overhead by 30-50% in raids with DBM/Skada/ElvUI
#define TEST_DISABLE_UI_FRAME_BATCH     0

// Frame Script Throttling
// PERMANENTLY DISABLED: Fundamental design flaws prevent safe re-enable:
// 1. Hooks FrameScript_Execute at 0x819210 - SAME address as lua_optimize.cpp's
//    marker injection hook -> MinHook conflict (only one hook wins).
// 2. std::unordered_map + SRWLOCK on main thread adds overhead per script execution.
// 3. Throttling OnUpdate breaks MoveAnything position tracking and addon timing
//    contracts (addons expect OnUpdate every frame for smooth animation).
// Would need complete rewrite with different hook target and proper addon compat.
#define TEST_DISABLE_FRAME_THROTTLE     1

// Tooltip String Caching - cache formatted tooltip strings by item/spell ID
// Reduces tooltip rendering overhead by 40-60% (sub_6277F0 is 24KB of code)
// LRU cache with 1000 entry limit, cleared on UI reload
// Corrected calling convention from __stdcall to __thiscall
#define TEST_DISABLE_TOOLTIP_CACHE      0

// Lua bytecode cache - WoW modified Lua bytecode incompatible
#define TEST_DISABLE_LUA_BYTECODE_CACHE         1  // DISABLED: WoW modified Lua bytecode incompatible

// CRT strstr SSE2 replacement - Boyer-Moore-Horspool, algorithmic
#define TEST_DISABLE_STRSTR_SSE2         0

#define TEST_DISABLE_CRT_CHAR_SSE2       1

// ================================================================
// WARNING — read before touching ANY flag in this SSE2 math/geometry
// cluster (matrix/vector/quaternion/frustum/ray-triangle, through
// TEST_DISABLE_RAY_TRIANGLE_SSE2 below): these ~15 flags have been
// individually enabled and disabled across more than 30 commits in this
// project's history, almost always for camera zoom/clipping/jiggle bugs
// that a per-function "fix" seemed to resolve until a later commit found
// a new case. The most recent commit in the entire repo at time of
// writing (3e3c0bf) disabled this whole cluster as a deliberate, blanket
// stability decision ("permanently resolve camera zoom-in and clipping
// bugs"), superseding all the individual per-function fixes below. Do
// not re-enable any of these based on reading the per-function comment
// alone — each one previously looked individually correct too. Needs a
// dedicated, isolated test pass per function against real gameplay
// (camera zoom, clipping, mouselook, terrain collision) before touching.
// ================================================================

// SSE2 4x4 matrix multiply (sub_4C1F00, result = A*B). Disassembly-verified row-major
// convention identical to the scalar original; pointer-validated + SEH-guarded.
// Set to 1 if any rendering/transform artifact is observed.
#define TEST_DISABLE_MATRIX_MULTIPLY         0

// SSE2 Matrix-Vector Transformations (sub_4C21B0 / sub_4C2270).
// Vectorized 3D point and 4D vector matrix transformations using SSE2.
// Set to 1 to revert to original FPU scalar implementation.
#define TEST_DISABLE_MATRIX_VECTOR_SSE2  1

// SSE2 C3Vector::Normalize (sub_4C3420 unguarded / sub_4C3600 with the engine's
// mag^2 > 2^-22 guard). Replaces x87 fsqrt+fdiv with full-precision sqrtss+divss
// (NOT rsqrt approximation -- that NaN-poisoned the quaternion path), and
// replicates each function's guard exactly. Pointer-validated + SEH-guarded with
// fallback to the original. Set to 1 to revert to the FPU scalar implementation.
#define TEST_DISABLE_VEC_NORMALIZE_SSE2  0

// SSE2 CMatrix transpose (sub_4C23D0, _MM_TRANSPOSE4_PS, bit-identical) and the
// in-place 3D point * 4x4 transform (sub_4C2300, ~65 callers; same math as the

// Network socket hooks (connect, send, recv, WSARecv)
#define TEST_DISABLE_NETWORK_HOOKS         1

// CVar null pointer guard (sub_7668C0)
#define TEST_DISABLE_CVAR_NULL_GUARD         0

// UnitAura fast-path (sub_00614A76 and sub_00614B4D)
#define TEST_DISABLE_UNIT_AURA_FAST         0

// Network GUID unpacking fast-path (sub_0076DC20)
#define TEST_DISABLE_NETWORK_GUID_SSE2         0

// StreamBuffer read/write fast-path (sub_47B3C0/sub_47B0A0)
#define TEST_DISABLE_STREAM_FASTPATH         0
// shipped MatVec3Mul). Pointer-validated + SEH-guarded with fallback. Completes
// SSE2 coverage of the transform library. Set to 1 to revert to FPU scalar.
#define TEST_DISABLE_MATRIX_EXT_SSE2         0
#define TEST_DISABLE_MATRIX_COPY             0

// SSE2 rigid-transform inverse builder (sub_4C2FC0, ~34 callers across render +
// world code). out_R = transpose(R); out[12..14] = -(R_row_i . t); homogeneous
// row/col zeroed, out[15]=1. Reads the 3x3 + translation straight from the input
// 4x4 (row-major, translation at [12..14]) -- the engine's scratch-buffer helper
// (sub_4C51B0) is bypassed since it only re-packs those same elements. Same
// products + summation order as the FPU original (sub-ULP delta only). Pointer-
// validated + SEH-guarded with fallback. Dedicated flag for in-game isolation.
#define TEST_DISABLE_MATRIX_INVERT_SSE2         0

// SSE2 misc transform ops: sub_4C2120 (scalar * 4x4, 16 fmul -> 4 mul_ps) and
// sub_4C2210 (row-major affine 3D point transform: out_i = row_i[0..2].p + row_i[3],
// 6 model/render callers). Both pure float, pointer-validated + SEH + fallback.
// Same products as the FPU originals (summation order sub-ULP). Isolation flag.
#define TEST_DISABLE_MATRIX_MISC_SSE2         1

// SSE2 in-place local-space translate (sub_4C1B30, 65+ callers across render/
// network/model/UI -- the hottest fn in the transform cluster). Adds R.v to the
// matrix translation row: this[12+i] += col_i.v, col vectors = (this[i],this[4+i],
// this[8+i]). 3 dot products vectorized; only this[12..14] are written (this[15]
// preserved, never stored). Same products as the FPU original (summation order
// sub-ULP). In-place accumulate -> own isolation flag. Pointer-validated + SEH.
#define TEST_DISABLE_MATRIX_TRANSLATE_SSE2         1

// SSE2 6-plane frustum culling (sub_9839E0, CFrustum::IsAABBVisible).
// Vectorized check using transposed SSE2 dot products.
// Set to 1 to revert to original FPU scalar implementation.
#define TEST_DISABLE_FRUSTUM_CULL        1

// SSE2 Ray-Triangle Intersection (sub_9836B0 / sub_983490).
// Vectorized Möller-Trumbore intersection using SSE2 cross/dot products.
// Set to 1 to revert to original FPU scalar implementation.
#define TEST_DISABLE_RAY_TRIANGLE_SSE2   1

// Batch the main-init MinHook enables (MH_QueueEnableHook + one MH_ApplyQueued)
// instead of one per-hook MH_EnableHook (each freezes all threads ~20ms via a
// system-wide thread snapshot). Set to 1 to revert to per-hook immediate enables.
#define TEST_DISABLE_HOOK_BATCHING       0

// Addon Lua-file prefetch (reads ~6000 addon files during loading to warm the OS
// cache). Enabled for testing — warms OS page cache for faster addon loading.
// On multi-client setups with shared disk, set to 1 to avoid I/O contention.
#define TEST_DISABLE_LUA_PRECOMPILE      1

// SSE2 quaternion normalize. Compiled in and gated at run time by the
// QuatNormalizeSse2 setting (default off) rather than compiled out, so it can be
// tested. The client's version at 0x00979110 is measured at 3.13% of main-thread
// execution in a CPU-bound profile. The replacement was checked against it over
// 400000 quaternions: worst per-component difference is one float ULP, the result
// is unit to within 1.6 ULP, and the two never disagree about the epsilon cutoff.
#define TEST_DISABLE_QUAT_NORMALIZE         0

// Addon file RAM-disk - interferes with WoW file I/O
#define TEST_DISABLE_ADDON_PRELOAD      1

// SavedVariables Asynchronous Writer - ENABLED.
// Background writes are stabilized via handle duplication.
#define TEST_DISABLE_SAVED_VARS_ASYNC   0


// Multithreaded Combat Log Parser - DISABLED.
// The worker actually parses nothing: the queue (g_queueTail / entry->ready) is
// never filled, so the worker thread just spins on a 1ms wait forever while the
// hook on sub_74F910 only calls the original and does a per-dispatch VirtualQuery
// (IsInRaid). It was gutted to stop a use-after-free (walking freed entries) and
// left as pure overhead + an idle background thread. Disable it so the combat log
// runs WoW's native path with no added cost (this is also what ran in raids).
#define TEST_DISABLE_COMBATLOG_MT       1

// Async Texture/Model Loading - offload texture loading to worker thread pool
// Hook sub_619330 (texture loader), queue requests, load async with LRU cache
// Worker thread pool (2 threads), lock-free queue (8192 entries), cache (2048 entries)
#define TEST_DISABLE_TEXTURE_ASYNC      1

// Async Spell Data Prefetching - DISABLED.
// The worker never loads anything (PrefetchSpellData just memsets a zeroed
// SpellData into the cache -- the real WoW loader call is an unfinished TODO),
// so the "cache" holds only zeros nobody reads. Meanwhile every spell cast pays
// an SRW-locked map lookup + a worker wakeup on the main thread, plus a 1ms-
// spinning worker and up to ~2.7MB of useless cached zeros. Pure overhead.
#define TEST_DISABLE_SPELL_PREFETCH     1

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

// Async Sound/Audio Prefetching - DISABLED.
// Placeholder: the worker loads nothing (TODOs only), so it just spins 2 idle
// threads. No prefetch ever happens. Pure thread/VA overhead.
#define TEST_DISABLE_SOUND_PREFETCH     1

// Async Quest/Achievement Data Loading - DISABLED.
// Placeholder: the worker's request handlers only bump stats (the WoW quest/
// achievement calls are unfinished TODOs), so it never populates any cache.
// One idle spinning thread for nothing.
#define TEST_DISABLE_QUEST_ASYNC        1

// Dormant pure-compute worker pools. Each spins idle worker threads (Sleep(1)/
// event-wait) but NOTHING ever submits work to them (no external caller feeds the
// decode/inflate/bone queues). On a 32-bit VA-constrained client each thread also
// reserves ~1MB of stack address space. Disabled until a real producer wires them.
#define TEST_DISABLE_TEXTURE_DECODE_MT  0   // 2 workers, BLP decode path wired and hot-swapped
#define TEST_DISABLE_MPQ_DECOMPRESS_MT  1   // 3 workers, inflate path never wired
#define TEST_DISABLE_ANIM_MT            1   // 2 workers, M2 bone path never wired

// Heap Compactor - proactive VA defragmentation
// Monitors LargestFreeBlock every 5 seconds, triggers HeapCompact when < 8MB
// Prevents OOM crashes during M2 model loading on teleports
// Safe: no WoW code patching, only Windows heap APIs
#define TEST_DISABLE_HEAP_COMPACTOR     0

// Memory-Pressure Governor - reads HeapCompactor's cached LargestFreeBlock
// every frame and sheds the DLL's own caches + drops texture budget toward
// stock under critical VA pressure, restoring on ease. Shed callbacks are
// registered at init and fire at YELLOW (free<48MB) / RED (free<24MB) with
// hysteresis to avoid thrashing. Set to 1 to disable.
#define TEST_DISABLE_MEMORY_PRESSURE_GOVERNOR  0

// Next-Gen Memory & Address Space (VA) Management Defragmenter & Pre-committer
#define TEST_DISABLE_LOADING_DEFRAG     0

// Async Visual Frustum Culling Cache
#define TEST_DISABLE_ASYNC_CULLING      0

// D3D9 Render State Redundancy Cache
#define TEST_DISABLE_D3D9_STATE_CACHE   0

// Conflicting duplicate Render State Dedup hook — DISABLED: conflicts with d3d9_state_cache
// and d3d9_state_manager which also hook the same D3D9 vtable functions (SetRenderState,
// SetTextureStageState, SetSamplerState). Triple-hooking causes stale cache state and
// corrupts render state pointers, crashing at sub_685F50.
#define TEST_DISABLE_RENDER_STATE_DEDUP 1

// Lock-Free Addon SavedVariables Incremental Serializer
#define TEST_DISABLE_SAVED_VARS_SERIALIZER 0

// SIMD AVX2 Animated Model Vertex Skinning Accelerator
#define TEST_DISABLE_SIMD_SKINNING      1

// Parallel Network Packet Deserialization Offloader
#define TEST_DISABLE_NET_PACKET_OFFLOAD 0

// Velocity-Based Predictive Asset Prefetcher
#define TEST_DISABLE_PREDICTIVE_PREFETCH 1

// Low-Latency GPU Sync (Max Frame Latency = 1)
#define TEST_DISABLE_LOW_LATENCY_SYNC    0

// High-Precision Hybrid Frame Rate Limiter
#define TEST_DISABLE_FRAME_LIMITER       0

// Disassembly-verified rewrite (2026-06-23): byte-exact to the original __stdcall
// sub_76ED20. No pre-scan strlen (the old heap-corruption root cause — reading
// past short strings into adjacent allocations). Copied body is pure byte-by-
// byte, matching the original's offset-based load (mov cl,[edx+eax]) exactly.
// Page-safe: no unaligned 16-byte loads crossing 4KB boundaries. SEH-guarded
// with fallback to the original on any exception. Safe to enable.
#define TEST_DISABLE_STRCAT_FAST         0

// Lua tonumber Fast Path - sub_84E030. DISABLED because it is REDUNDANT: the
// LuaNumConvFast module already hooks lua_tonumber at 0x84E030 and installs
// first, so this hook always loses the race and logs "BAD PROLOGUE at 0x84E030"
// (the prologue is already a trampoline by the time it runs). Two modules on one
// address -> the 2nd silently fails (CONTEXT lesson 8). Keeping LuaNumConvFast as
// the single lua_tonumber owner; this one is dead weight. (Its re-targeting from
// the old 0x84E0E0=lua_tolstring was still a correct fix, just superseded here.)
#define TEST_DISABLE_LUA_TONUMBER_FAST  1

// Lua Number Conversion Fast Path (gettop, isnumber, tonumber, settop)
// lua_settop modifies the Lua stack — can corrupt state leading to luaD_precall crashes
#define TEST_DISABLE_LUA_NUMCONV_FAST         0

// Multithreaded Nameplate Renderer - offload nameplate rendering to worker threads
// Reduces main thread CPU by 30-40% in 25-man raids via lock-free queue + async processing
// Hook nameplate update functions (health, text, color, visibility)
// Worker thread pool (2 threads), lock-free queues (4096 entries each)
// Priority system: Target > Focus > Nearby > Distant
// Emergency disable flag: set to 1 to disable NAMEPLATE_MT entirely
// HARD-DISABLED: the design is thread-safe but ADDITIVE, not a speedup — the
// hook runs the full native nameplate update AND then re-gathers + re-applies
// name/color via a worker + main-thread OnFrame, so it only adds main-thread
// work with no FPS benefit (profiling confirmed WoW-side code is <1% each;
// the cost is system/GPU/memory, not nameplates). Removed from the launcher.
#define TEST_DISABLE_NAMEPLATE_MT       1

// Frame-Scoped Event Coalescing (Synchronous Deduplication)
// DISABLED again: suppresses whitelisted events and re-emits them a frame later from
// the Sleep hook, which changes event timing/ordering and runs Lua handlers at an
// unintended point in the frame. Unvalidated across the in-world -> glue teardown
// where the char-switch crashes occur. Stability outranks the dedup win until a
// tester can confirm it in-game (see CONTEXT spellbook-desync lesson).
#define TEST_DISABLE_EVENT_COALESCER    1

// Fast SSE2 network GUID unpacking (CDataStore::GetWowGUID at 0x0076DC20) - controlled above

// Particle simulation culling/throttling
// PERMANENTLY DISABLED: 0x981D40 is CParticleEmitter2::Spawn/Init (writes lifespan,
// position, velocity), NOT the per-frame simulate function. Throttling spawn causes
// garbage particles with random positions/velocities/colors. Real per-frame simulate
// function not found in CParticleEmitter2 vtable analysis. Would need to find parent
// class or CParticleSystem2 manager's Update/Simulate function.
#define TEST_DISABLE_PARTICLE_THROTTLE  1

// Inline Lua stack push/type-query fast paths — 8 hooks (lua_pushnil,
// lua_pushinteger, lua_pushboolean, lua_pushlightuserdata, lua_type,
// lua_isfunction, lua_isstring, lua_tothread). Each ≤45 bytes in the
// engine; inlined to eliminate call overhead and index2adr for plain
// stack indices. Disassembly-verified. Set to 1 to disable all 8.
#define TEST_DISABLE_LUA_STACK_FAST         0

// Inline luaS_newlstr intern lookup (string-creation fast path)
// RE-ENABLED after root-causing the crash in disassembly (sub_856C80): the dead-string
// offsets were wrong for WoW's Lua layout. Fixed to the verified offsets --
// TString.marked at +9 (was +5), global_State.currentwhite at +0x15 (was +0x14) --
// and the content-match path now replicates the engine EXACTLY: resurrect the
// interned string in place if it is other-white (changewhite: marked ^= 3), then
// return it, instead of the old "bail to original on dead" which combined with the
// garbage offsets to hand back GC-dead TStrings (use-after-free during the GC-heavy
// lua_State swap; nil method-name lookups on char-select). SEH-guarded; on any miss
// or anomaly it defers to the original. Behaviour is now provably identical to the
// engine on a hit. See CONTEXT lessons 3, 4.
#define TEST_DISABLE_LUAS_NEWLSTR_SSE2         0  // enabled: string interning lookup optimization
#define TEST_DISABLE_LUA_GC_COALESCE           0  // enabled: incremental Lua GC coalescing
#define TEST_DISABLE_FRAMEXML_COALESCE         1  // disabled: coalesced UI layout recalculation

// ================================================================
// 10 Extended Performance Optimization Features
// ================================================================
#define TEST_DISABLE_M2_SIMD_MT                 1
#define TEST_DISABLE_GUID_MAP_LF                0
#define TEST_DISABLE_SIMD_MATH_FAST             0
#define TEST_DISABLE_COMBATLOG_INCREMENTAL      0
#define TEST_DISABLE_LUA_POOL_LF                0
#define TEST_DISABLE_D3D_STATE_CACHE            0
#define TEST_DISABLE_DBC_LOOKUP_CACHE           0
#define TEST_DISABLE_SAVEDVARS_ASYNC            0
#define TEST_DISABLE_WORLD_STATE_COALESCE       1
#define TEST_DISABLE_HW_SKINNING                1
#define TEST_DISABLE_SOUND_MIXER_OPT           0  // enabled: sound mixer thread scheduling tuning
#define TEST_DISABLE_FONT_METRICS_LOCK_FREE    0  // enabled: lock-free font metrics cache
#define TEST_DISABLE_NET_PACKET_COALESCE       0  // enabled: coalesced network packet dispatch
#define TEST_DISABLE_AUDIO_DECODE_MT           0  // enabled: parallel sound wave pre-decoding and cache
#define TEST_DISABLE_DEFRAG_LF                 0  // enabled: lock-free main thread heap defragmentation
#define TEST_DISABLE_LUA_GC_GOVERNOR            0  // enabled: adaptive Lua GC governor
#define TEST_DISABLE_LUA_GETTIME_FAST           0  // disabled by default: Lua GetTime Frame Cache
#define TEST_DISABLE_MATRIX_TRANSFORM_SSE2      1  // disabled: SIMD Matrix Vector Transforms
// HARD-DISABLED: this is the same all-allocations CRT->mimalloc redirect that was
// removed in v3.16.3 for breaking server connections ("unable to connect"). The
// opt-in large-allocation redirect (OptMimallocLarge) is the safe replacement.
#define TEST_DISABLE_CRT_MIMALLOC               1  // disabled: CRT Allocator Redirect (connection breaker)
// HARD-DISABLED: the multithreaded UpdateBones hook is broken by design — it
// dispatches to a worker then immediately blocks waiting on it (no parallelism,
// pure overhead), and on the 10ms wait timeout it frees the ring slot while the
// worker is still running orig_UpdateBones on it (use-after-free), and runs
// non-thread-safe M2 transform code on a worker thread (game-state race). Address
// 0x0082F0F0 is correct, but the design provides no benefit and crashes. Needs a
// full rewrite (in-place SSE bone math, no threads) before it can be re-enabled.
#define TEST_DISABLE_M2_BONE_MT                 1  // disabled: broken multithreaded UpdateBones
#define TEST_DISABLE_MPQ_ASYNC_DECOMPRESS       0  // enabled: Asynchronous MPQ File Decompressor
#define TEST_DISABLE_RCU_OBJ_MGR                0  // enabled: Lock-Free Read-Copy-Update (RCU) Object Manager
#define TEST_DISABLE_M2_LOD_BIAS                1  // disabled: M2 LOD Bias Control
#define TEST_DISABLE_UNIT_AURA_COALESCE         1  // enabled: Unit Aura Coalescer
#define TEST_DISABLE_D3D9_VB_CACHE              1  // disabled: D3D9 VB Shadow Cache
#define TEST_DISABLE_ADDON_TICK_GOVERNOR        0  // enabled: Addon Tick Governor
#define TEST_DISABLE_D3D9_VS_CONSTANT_CACHE     1  // disabled: D3D9 VS Constant Cache
#define TEST_DISABLE_SAVED_VARS_PRETOKEN        0  // enabled: SavedVariables Preloader
#define TEST_DISABLE_ADAPTIVE_FARCLIP           0  // enabled: dynamic adaptive farclip controller
#define TEST_DISABLE_NET_ADDON_COALESCER        0  // enabled: Net Addon Message Coalescer
#define TEST_DISABLE_MIP_BIAS_GOVERNOR          0  // enabled: Dynamic Mipmap Bias Governor
#define TEST_DISABLE_SPATIAL_CULLING            0  // enabled: Spatial Culling Grid
#define TEST_DISABLE_PERF_DIAGNOSTICS           0  // enabled: Performance Diagnostics Monitor
#define TEST_DISABLE_ASYNC_TERRAIN              0  // enabled: Asynchronous Terrain Loader

// DEAD FLAG — not referenced by any #if anywhere in src/. The G1/G2/G2AL/
// G2AI/G2B/G2C/G3 sub-flags below are the actual, independent gates for
// these hooks (all already 0/enabled — verified by grep, they are live).
// Kept only so the historical bisection notes below aren't lost; setting
// this to 0 or 1 has no effect on anything. Do not "fix" by flipping it.
#define TEST_DISABLE_LUA_INLINE_BATCH_SAFE       1
// History: checknumber/str, optnum/str, tolstr, argcheck, typename (G1),
// getlocal, getinfo, ErrorFast, lessthan, gc, xpcall (G2),
// metafield, where, checktype, getupval, bufinit, prepbuf, iscfunc, rawequal (G3)
// were mass-disabled in 8355c31 for crash bisection, then individually
// re-verified safe against disassembly and re-enabled via their own G-flags.
// The crash root causes were the LuaStackFast / pushnumber / pushvalue /
// inline-batch-dangerous groups (confirmed at luaD_precall 0x5565E9).
#define TEST_DISABLE_LUA_SAFE_G1         0  
#define TEST_DISABLE_LUA_SAFE_G2         0  // enabled: Safe Group 2 hooks
#define TEST_DISABLE_LUA_SAFE_G2AL 0
#define TEST_DISABLE_LUA_SAFE_G2AI 0
#define TEST_DISABLE_LUA_SAFE_G2B 0
#define TEST_DISABLE_LUA_SAFE_G2C 0
#define TEST_DISABLE_LUA_SAFE_G3         0  // enabled: buffer ops and helper hooks

// lua_setlocal fast path
// PERMANENTLY DISABLED: 0x84F210 is luaL_where (debug location formatter), NOT
// lua_setlocal. Confirmed via IDA: 2-arg function calling lua_getstack+lua_getinfo("Sl")
// formatting "%s:%d: %s". Hooking corrupts stack on every engine error -> ntdll heap
// corruption at login. Real lua_setlocal address UNKNOWN. Cannot safely re-enable.
#define TEST_DISABLE_LUA_SETLOCAL_FAST  1

// DEAD FLAG — not referenced by any #if anywhere in src/. TEST_DISABLE_
// LUA_INLINE_BATCH (bare, below) is the real gate for the DG1-DG4B group
// and is correctly 1 (disabled): these hooks caused confirmed TValue
// corruption at luaD_precall 0x5565E9. Setting this flag has no effect.
#define TEST_DISABLE_LUA_INLINE_BATCH_DANGEROUS  1

// Bisection groups for dangerous batch hooks — find which causes TValue corruption.
// Only reachable if TEST_DISABLE_LUA_INLINE_BATCH below is flipped to 0 first.
#define TEST_DISABLE_LUA_BATCH_DG1 0
#define TEST_DISABLE_LUA_BATCH_DG2 0
#define TEST_DISABLE_LUA_BATCH_DG3 0
#define TEST_DISABLE_LUA_BATCH_DG4 0  // master
#define TEST_DISABLE_LUA_BATCH_DG4A 0
#define TEST_DISABLE_LUA_BATCH_DG4B 0
// Real gate for the DG1-DG4B group above — confirmed TValue corruption,
// keep disabled (see TEST_DISABLE_LUA_INLINE_BATCH_DANGEROUS note above).
#define TEST_DISABLE_LUA_INLINE_BATCH  1

// lua_rawgeti inline cache (8192 entries) — verified against sub_84E670 disassembly.
// Taint propagation matches engine byte-exact; defers pseudo-indices to index2adr.
#define TEST_DISABLE_RAWGETI_INLINE  0

// lua_rawget inline at 0x84E600 — verified byte-exact to sub_84E600 disassembly.
// Copies TValue from luaH_get result, taint logic matches the engine exactly.
#define TEST_DISABLE_RAWGET_INLINE    0

// lua_toboolean inline (0x84E0B0) — fast path for truthiness check
#define TEST_DISABLE_TOBOOLEAN_INLINE         0  // enabled: lua_toboolean inline

// lua_objlen inline (0x84E150) — fast path for length check
#define TEST_DISABLE_OBJLEN_INLINE         0  // enabled: lua_objlen inline

// luaH_getstr inline bucket-index cache (16384 entries) — verified against disassembly.
// Content-validates keys on every hit; offsets match stock luaH_getstr exactly.
#define TEST_DISABLE_GETSTR_INLINE    0

// lua_pushnumber direct stack write (sub_84E2A0).
#define TEST_DISABLE_PUSHNUMBER_FAST         0

// lua_pushvalue direct stack copy (sub_84DE50, inline fast path).
#define TEST_DISABLE_PUSHVALUE_FAST         0

// FrameScript_Execute hook (inject DLL markers)
#define TEST_DISABLE_FRAMESCRIPT_EXECUTE         0

// luaV_gettable (sub_85BC10) safety check
#define TEST_DISABLE_LUA_GETTABLE_SAFETY         0

// luaH_newkey (sub_85CAB0) SEH guard
#define TEST_DISABLE_LUA_NEWKEY_SAFETY         0

// Sampling Profiler — background thread samples main-thread EIP every ~1ms
// via SuspendThread/GetThreadContext/ResumeThread, buckets by nearest known
// function, dumps top-50 hot functions on shutdown. Read-only, no WoW hooks.
// Fixes the xrefs≠runtime-frequency blind spot. Set to 1 to disable.
// RE-ENABLED: was silently non-functional, not risky — the OpenThread call
// only requested THREAD_QUERY_INFORMATION (insufficient for SuspendThread/
// GetThreadContext, so every sample would have failed) AND the caller closed
// its handle immediately after Init() while the sampler thread kept using it
// afterward. Fixed by requesting THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT and
// having Init() duplicate its own long-lived handle instead of borrowing the
// caller's.
#define TEST_DISABLE_SAMPLING_PROFILER  0

// Fast UIFrame accessor hooks (IsShown at 0x48C610, IsVisible at 0x48C5B0, GetAlpha at 0x48C4C0, GetScale at 0x49F7D0).
// Direct access to C++ object fields from Lua table index 0 with type-checking validation.
// Reduces FrameScript_GetObject overhead on UI updates. Set to 1 to disable.
#define TEST_DISABLE_UI_ACCESSOR_FAST         0  // enabled: UIFrame accessor hooks

// Fast FontString metrics hooks (GetStringWidth at 0x0048DE90, GetStringHeight at 0x0048DF00).
// Directly queries internal C++ metrics structures bypassing full stack setup and type checking.
// Set to 1 to disable.
#define TEST_DISABLE_FONT_METRICS_FAST         0  // disabled: FontString metrics hooks

// Sound system protection guards — SEH-wrapped crash protection for
// sound driver init (sub_508260), emitter registration (sub_5093F0),
// buffer/update ops (sub_508320). Default ENABLED (0 = active).
#define TEST_DISABLE_SOUND_DRIVER_GUARD    0
#define TEST_DISABLE_SOUND_EMITTER_GUARD   0
#define TEST_DISABLE_SOUND_BUFFER_GUARD    0
#define TEST_DISABLE_SOUND_UPDATE_GUARD    0

// ================================================================
// New Extended Hooks (commit 670012c) — disassembly-verified + gated
// ================================================================
//
// SIMD geometry hooks (hooks_simd.cpp):
//  Vec3Cross 0x5FEC70, IsSphereVisible 0x983D20, FromAngleAxis 0x982400,
//  QuatSlerp 0x982460. IsSphereVisible + FromAngleAxis had __fastcall→__thiscall
//  calling-convention bugs fixed (disassembly-verified). Default ENABLED.
#define TEST_DISABLE_VEC3_CROSS_SSE2         1
// IsSphereVisible DISABLED: second-pass _MM_TRANSPOSE4_PS mixes zeros into plane
// normals (only 2 of 4 inputs are actual planes), corrupting frustum culling for
// planes 4-5 and causing camera to clip through player character (zoom-in bug).
#define TEST_DISABLE_SPHERE_VISIBLE_SSE2         1
#define TEST_DISABLE_FROM_ANGLE_AXIS_SSE2         1
#define TEST_DISABLE_QUAT_SLERP_SSE2         1
//
// UI Frame XML accessor hooks (ui_accessor_fast.cpp):
//  Frame_IsShown 0x49FE90, Frame_IsVisible 0x49FE30, Frame_GetAlpha 0x49F980,
//  Frame_GetFrameLevel 0x49E980. Disassembly-verified __cdecl(L) with correct field offsets.
//  Default ENABLED.
#define TEST_DISABLE_FRAME_ACCESSOR_FAST         0  // disabled: Frame XML accessor hooks
//
// UI Layout accessors (ui_accessor_fast.cpp):
//  GetWidth 0x49D3B0, GetHeight 0x49D550.
//  Disassembly decompile marked these __usercall, but full disassembly review shows
//  standard __cdecl prologue (push ebp; mov ebp, esp) with one stack parameter
//  (L = Lua state). The decompiler defaulted to __usercall because it saw callee-saved
//  register use (ebx/esi/edi), not because of a non-standard convention.
//  MinHook is safe. Default ENABLED.
#define TEST_DISABLE_LAYOUT_ACCESSOR_FAST         0  // disabled: layout accessor hooks


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
// Translation layer (Wine on Linux, Rosetta 2 on macOS ARM).
// Our worker-thread / parallel features dispatch work to background threads and
// then BLOCK the main thread waiting for them (some with INFINITE timeouts).
// Under x86->ARM/native translation those workers are themselves translated and
// slow/starved, so the main-thread wait turns into a multi-second freeze
// (observed: 11.7s stall, stack = our DLL -> WaitForSingleObject). These
// features also give little to no benefit under translation (SSE/AVX2 emulated,
// extra threads compete for translation resources). So on a translation layer we
// simply don't run them - a freeze becomes "feature just doesn't run", which is
// strictly better. Native Windows (the primary target) is unaffected.
#ifndef WOWOPT_ISTRANSLATED_DEFINED
#define WOWOPT_ISTRANSLATED_DEFINED
static inline bool RunningUnderTranslation() { return IsWine() || IsRosetta(); }
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

// Counts and reports targets skipped because another party got there first.
// Defined in dllmain.cpp; declared here because this header is included from
// every translation unit that installs a hook.
extern "C" void WowOpt_LogForeignDetour(void* target, unsigned char firstByte);
extern "C" void WowOpt_LogDuplicateHook(void* target);

static inline MH_STATUS WowOpt_CreateHookGuarded(void* target, void* detour, void** original) {
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
    // Refuse a target that somebody else has already detoured.
    //
    // A player on Ascension was kicked seconds after using an ability and then
    // crashed on exit with a call through a null pointer. The addresses were not
    // the problem - Ascension.exe is address-compatible with 3.3.5a, and the
    // bytes on disk at every target checked are the expected 55 8B EC. At run
    // time two of them were E9, a jmp rel32, because that client detours them
    // itself before we initialise.
    //
    // Two modules happened to verify the prologue and stepped aside, saying so
    // in the log. The other hundred and twenty-eight had no such check and
    // installed over whatever was there. Hooking on top of a foreign detour
    // breaks that chain, and a client that inspects its own bytes sees exactly
    // what tampering looks like.
    //
    // The check belongs here rather than in each module: this is the wrapper
    // 102 call sites already go through, and the two that got it right were
    // right by accident of who wrote them.
    unsigned char first = 0;
    bool readable = false;
    __try {
        first = *(volatile unsigned char*)target;
        readable = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        readable = false;
    }

    if (readable && (first == 0xE9 || first == 0xEB)) {
        // Could be our own trampoline from another module rather than a
        // stranger's, and those two cases deserve different answers. MinHook
        // knows which: it reports ALREADY_CREATED for a target it owns.
        MH_STATUS probe = MH_CreateHook(target, detour, original);
        if (probe == MH_ERROR_ALREADY_CREATED) {
            // One of our own modules already owns this address. That is worth
            // saying plainly: two modules aiming at one function is how a broken
            // matrix multiply survived for months, because the half being
            // maintained was the half that silently lost the race. The caller
            // usually logs this as "hook FAILED", which reads like a defect in
            // the target rather than a collision between two of ours.
            WowOpt_LogDuplicateHook(target);
            return probe;
        }
        if (probe == MH_OK) {
            MH_RemoveHook(target);              // created over a stranger - back out
        }
        WowOpt_LogForeignDetour(target, first);
        return MH_ERROR_UNSUPPORTED_FUNCTION;
    }

    return MH_CreateHook(target, detour, original);
}

// Every direct MH_CreateHook in this project now goes through the same check.
//
// The guard was put in WineSafe_CreateHook because 102 call sites use it. The
// other 221 call MinHook directly and sailed straight past it - which is why a
// build carrying the guard still installed 127 hooks on a client that had
// already detoured some of them, and still got the player kicked.
//
// Defined after the function above so the body's own call is the real MinHook
// entry point and not this macro.
// Kept as the name 102 call sites already use; the guard is the same one.
static inline MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original) {
    return WowOpt_CreateHookGuarded(target, detour, original);
}

#define MH_CreateHook WowOpt_CreateHookGuarded

// Hook-enable batching shared across modules. Each MH_EnableHook freezes every
// process thread (~20ms via a system-wide thread snapshot). During MainThread's
// synchronous install sequence g_hookBatchMode is 1, so enables routed through
// WO_EnableHook are queued and applied in a single MH_ApplyQueued freeze at the
// end of init. Outside that window (and for crash guards that call MH_EnableHook
// directly) enables apply immediately. Defined in dllmain.cpp.
extern volatile long g_hookBatchMode;
static inline MH_STATUS WO_EnableHook(void* target) {
#if defined(TEST_DISABLE_HOOK_BATCHING) && TEST_DISABLE_HOOK_BATCHING
    return MH_EnableHook(target);
#else
    if (g_hookBatchMode) return MH_QueueEnableHook(target);
    return MH_EnableHook(target);
#endif
}
#endif
#endif






#define CRASH_TEST_DISABLE_COMPARESTRING         0

#define CRASH_TEST_DISABLE_GETFILEATTR         0

#define CRASH_TEST_DISABLE_SETFILEPOINTER         0

#define CRASH_TEST_DISABLE_READFILE         1

#define CRASH_TEST_DISABLE_GETFILESIZE_CACHE         0

#define CRASH_TEST_DISABLE_MODHANDLE_CACHE         0

#define CRASH_TEST_DISABLE_GLOBALALLOC         1

#define CRASH_TEST_DISABLE_VA_ARENA         0   // compiled in; activation is runtime opt-in via Config OptVaArena (default off). This is the authoritative definition (included before dllmain's #ifndef fallback).

#define CRASH_TEST_DISABLE_ISBADPTR         1

enum LogLevel {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
};

extern "C" void LogEx(LogLevel level, const char* context, const char* fmt, ...);

