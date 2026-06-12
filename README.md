# wow_optimize

Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)
Author: SUPREMATIST

wow_optimize improves WoW 3.3.5a at the engine and runtime level: memory allocation, Lua VM behavior, Lua library fast paths, timers, file I/O, networking, heap fragmentation, lock contention, the 16-year combat log bug fix, and other low-level bottlenecks.

The current public build is focused on real frametime stability, long-session smoothness, addon-heavy gameplay, and lower Lua/runtime overhead while keeping historically unsafe features disabled.

> Disclaimer: This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. Use at your own risk.

---

## What's New in v3.9.0

### Lua VM — Direct-Threaded Interpreter
Replaces WoW's switch-based opcode dispatch with a direct-threaded interpreter: 8192-site x 4-way polymorphic inline cache, 4096-entry global variable cache, SSE2 TValue operations, 100K opcode execution slices before yielding to WoW's frame scheduler.

### Lua VM — Safe Inline Caches
- `luaH_getstr`: bucket-index cache (16384 entries) with content validation — safe across GC rehash
- `lua_rawgeti`: array-direct O(1) path + bucket-index hash-part cache (8192 entries)
- `lua_pushnumber`: direct stack TValue write, skipping full API call overhead
- `luaV_gettable` safety patch: validates TValue type field before using as array index

### 6 CPU-Side Optimization Modules
- **Off-screen animation throttle**: 3-tier distance-based update rate (full / 1:4 / 1:16)
- **SSE2 math**: matrix multiply, quaternion normalize, frustum AABB-vs-4-planes cull, BGRA↔ARGB batch swap, premultiplied alpha
- **Combat text batching**: 256-entry ring buffer, flush-per-frame
- **UI layout dirty-flag cache**: 4096-slot frame-pointer keyed, generation-based invalidation
- **Network heartbeat filter**: suppresses CMSG_PING/CMSG_TIME_SYNC_RESP when data recently sent
- **Invariant Lua script cache**: 256-slot cache for UnitHealth/UnitPower/UnitClass outcomes

### Memory & Async
- 64-byte aligned 8-tier slab allocator (64B–8192B) for cache-line-aligned hot structures
- 16384-entry GUID→object FNV-1a hash-table with lock-free reads
- 2-thread SPMC worker pool (2048 slots) for fire-and-forget task dispatch

### Infrastructure & Diagnostics
- 50-API infra_patch: object pools, deduplication, frame-time smoothing, adaptive cache TTL
- 20-feature hot_patch: datastore lookup cache, delete prefetch, tooltip early-exit, event dedup
- 3-hook hook_prefetch: SSE2 prefetch on cleanup/delete/datastore-reset paths
- CrashDumper: 64-slot feature registry + 256-entry hook call trace + minidump/text crash reports
- Freeze watchdog: 10s threshold with per-feature activity reporting
- Priority watchdog with rate-limited logging

### Caches
- Tooltip LRU (512 slots, 30s TTL), regex compiled-pattern (256 slots, 120s TTL)
- SSE2 trig lookup tables (4096-entry sin/cos, 1024-entry atan)
- Render state dedup (256 slots), event name lookup/hash caches
- O(1) script handler resolver at 0x48E680

## Current Status

### Performance Metrics (Real-World Testing)
- **Frame time**: Smoother frametimes in addon-heavy raids
- **CPU usage**: Noticeable reduction in addon-heavy gameplay
- **Lua operations**: Faster with mimalloc allocator
- **Timing cache**: High QPC cache hit rate
- **String formatting**: High fast path hit rate

---

## Reviews

See what other players say: [Reviews and Testimonials](https://github.com/suprepupre/wow-optimize/discussions/10)

### Stability Testing Team


This project wouldn't exist without the community. Every crash report, every bisection test, every "hey this broke my addon" message directly shaped the release. 

Massive thanks to:
Morbent, Billy Hoyle, tuan, NoGoodLife, feh_dois, David (`_oldq`), UNOB, DarkRockDemon, Raymond, Vandal, Mantork, Falcon, Muus

---

## Current Feature Set

### Memory and allocator
- mimalloc CRT replacement for `malloc/free/realloc/calloc/_msize`
- Lua VM allocator replacement with mimalloc
- Lua string table pre-sizing to reduce hash resize spikes
- Low Fragmentation Heap (LFH) enabled for process heap and new heaps
- periodic mimalloc purge for long-session memory stability

### Lua runtime
- adaptive manual Lua GC
- 4-tier GC stepping:
  - normal
  - combat
  - idle
  - loading
- GC step sync with !LuaBoost
- safe Lua stats export to addon
- Lua reload detection and clean reinitialization

### WoW API result cache
- `GetItemInfo` - 8192-slot cache, Direct Memory Access *(disabled - breaks Aux / WCollections / ElvUI)*
- `GetSpellInfo` - disabled (icon corruption, crashes on relog)

### Lua internal caches
- `luaH_getstr` - generation-guarded table string-key lookup cache (8192-slot, SEH-protected)
- `luaH_getstr` inline v2 - safe bucket-index cache with SSE2 prefetch (16384 entries)
- `lua_rawgeti` inline v2 - safe array direct + bucket-index cache (8192 entries)

### Lua fast paths
- Phase 1:
  - `string.format`
- Phase 2 (safe, Lua API based) - **ENABLED**:
  - `string.find` (plain mode)
  - `string.match` (safe partial fast path)
  - `string.rep`
  - `type`
  - `math.floor`
  - `math.ceil`
  - `math.abs`
  - `math.max` (2 args)
  - `math.min` (2 args)
  - `math.random`
  - `math.sqrt`
  - `string.len`
  - `string.byte`
  - `tostring`
  - `tonumber`
  - `select`
  - `rawequal`
  - `string.sub`
  - `string.lower`
  - `string.upper`
  - `table.concat` (disabled - direct RawTValue* stack writes caused hangs)
  - `unpack` (disabled - direct RawTValue* stack writes caused hangs)
  - `ipairs` (disabled - closure factory incompatible with WoW iterator pattern)

### Lua VM internals
- `luaV_concat` and `luaS_newlstr` hooks disabled for public stability
- baseline-safe VM operation with zero overhead
- string table pre-sizing remains active to prevent rehash freezes

### Timers and frame pacing
- PreciseSleep on the main thread
- automatic single-client / multi-client timing behavior
- `GetTickCount` redirected to QPC-based timing
- `timeGetTime` redirected to the same QPC timeline
- QueryPerformanceCounter coalescing cache
- adaptive timer resolution
- hardcoded FPS cap raised from 200 to 999

### File I/O
- MPQ handle tracking
- retroactive MPQ handle scanner
- sequential-scan hints for MPQ access
- adaptive MPQ read-ahead cache
- skip `FlushFileBuffers` for tracked MPQ handles
- `GetFileAttributesA` cache
- `SetFilePointer` redirected to `SetFilePointerEx`

### Threading and synchronization
- SRWLOCK-based file cache locking
- main thread priority ABOVE_NORMAL
- ideal processor assignment
- process priority ABOVE_NORMAL
- CriticalSection spin count and spin-first entry path
- TLS-cached `GetCurrentThreadId` and pseudo-handle fast path

### Networking
- `TCP_NODELAY`
- immediate ACK frequency
- socket buffer tuning
- low-delay TOS
- fast keepalive settings

### Async loading and prefetching

Features that use worker threads and lock-free queues. Status reflects the current public-safe configuration; individual toggles live in `src/version.h`.

- **Async spell data prefetching** - predictive spell data loading before cast completes, reduces spell cast lag, worker thread with lock-free queue (4096 entries) and cache (4096 entries) *(enabled)*
- **Multithreaded addon dispatcher** - parallelizes addon OnUpdate callbacks across worker thread pool (4 threads), reduces main thread CPU in addon-heavy setups, batch processing with lock-free queue (8192 entries) *(enabled)*
- **Predictive MPQ prefetching** - tracks zone transitions and predicts next zone, prefetches textures/models/WMOs into OS cache before teleport, reduces zone loading stutters, worker thread pool (2 threads) with lock-free queue (2048 entries) *(enabled)*
- **Multithreaded combat log parser** - offloads combat log parsing to worker thread, reduces main thread CPU in raids, lock-free queue with async processing *(enabled, auto-disables inside raids)*
- **Sound prefetching** - predicts and prefetches sound files based on spell casts, zone transitions, combat state, worker thread pool (2 threads) with lock-free queue (1024 entries) *(enabled)*
- **Async quest/achievement loading** - async quest log and achievement data loading, worker thread with lock-free queue (512 entries) *(enabled)*
- **Multithreaded nameplate renderer** - offloads nameplate rendering to worker threads, reduces main thread CPU in 25-man raids, priority system (Target > Focus > Nearby > Distant) *(enabled)*
- **Model/M2 caching** - synchronous LRU cache (1024 entries) for loaded models, eliminates redundant model loading *(enabled)*
- **Async texture loading** - worker thread pool (2 threads) with lock-free queue (8192 entries) and LRU cache (2048 entries) *(disabled - loading screen regression)*

### Other runtime optimizations
- combat log optimizer - **fixes the 16-year combat log bug** (log retention increased from 300s to 1800s, events no longer lost during extended sessions)
- `CompareStringA` fast ASCII path
- `MultiByteToWideChar` / `WideCharToMultiByte` - SSE2 ASCII fast path (bypasses NLS for pure-ASCII strings on ASCII-compatible codepages)
- `lstrlenA` / `lstrlenW` fast path
- `OutputDebugStringA` no-op when no debugger
- fast `IsBadReadPtr` / `IsBadWritePtr`
- periodic stats dump
- CRT `pow()` integer fast-path (x^2=x*x, sqrt, etc.)
- CRT `strstr` SSE2 Boyer-Moore-Horspool

### CRT SSE2 fast paths
All page-boundary guarded and SEH-protected:
- `strlen` / `strcmp` / `memcmp` / `memcpy` / `memset` - SSE2 memory operations
- `memchr` / `strchr` - byte and character search
- `strcpy` - string copy
- `wcslen` / `wcscpy` - wide-char UTF-16 strings

### Kernel-call caches (38 hooks)
Batch 1-8: `GetSystemTimeAsFileTime` (QPC-based 1ms refresh), `GetACP`, `GetUserDefaultLangID`, `GetProcessHeap`, `CharUpperA/W`, `CharLowerA/W`, `MapVirtualKeyA`, `GetThreadPriority`

Batch 11-20: `GetOEMCP`, `GetDoubleClickTime`, `GetCursorPos`, `GetSysColor`, `GetCaretBlinkTime`, `IsWindow`, `GetDesktopWindow`, `GetFocus`

Batch 21-26: `GetTickCount64` (QPC-backed), `ShowCursor`, `GetVersionExA`, `GetSystemMetrics`, `IsDebuggerPresent` (no-op), `GetSystemInfo`, `RegQueryValueExA`

Batch 31-38: `GetCurrentProcess`, `GetCurrentThread`, `GetCPInfo` and related kernel caches

### Loading screen optimization
- Skips UR arena reserve on HD clients (>500MB working set)
- Dynamic VA arena: reserves 256MB during loading, releases after
- Sleep hook: bulk Sleep for waits >16ms (less CPU during idle)

### VA Arena (Virtual Address Arena)
- 512MB high-address reserved arena with `MEM_TOP_DOWN`
- Wow.exe caller filtering - only services allocations from WoW executable code
- span tracking for correct multi-page allocation/deallocation
- proper `MEM_DECOMMIT` / `MEM_RELEASE` behavior
- reduces 32-bit address space fragmentation from large WoW allocations

---

## Intentionally Disabled in Public-Safe Builds

These features are disabled in public-safe builds because they previously caused regressions or crashes:

- WoW-internal SSE2 strlen at `sub_76EE30` - page-boundary bug (exit crash)
- MPQ memory mapping (disabled for stability)
- UI widget cache (disabled due to addon regressions)
- GetSpellInfo cache (disabled - icon corruption, crashes on relog)
- ApiCache (`GetItemInfo` result cache - disabled due to Outfitter/GearScore breakage)
- dynamic unit API caching (disabled)
- GlobalAlloc fast path (disabled)
- luaH_getstr table lookup cache - ERROR #134, stale Node* from address reuse
- Async texture loading hook - caused loading screen regression
- Model async workers - loading screen regression
- `lua_pushstring` intern cache (disabled - stale `TString*` crashes)
- `lua_rawgeti` int-key cache (disabled - `TValue` replay corruption)
- CombatLog full event cache (disabled - stale `TString*` crashes)
- `luaS_newlstr` string cache (removed due to 0xC000005 crashes on reload)
- `luaV_concat` hook (removed due to 0% hit-rate overhead)
- `lua_getfield` _G cache (removed - 0% hit rate in production, broken uint32/uint64 comparison + no write invalidation)
- `GetModuleFileName` cache (disabled - conflicts with OBS hook chain, crash + exit error)
- Hardware cursor byte patches (`gxCursor=0` / `gxFixLag=1`) - NULL deref on private servers
- CRT `strncmp` / `strcat` SSE2 - crash isolation for Circle/Warmane
- CRT `wcslen` / `wcscpy` SSE2 - broken zero-detection for ASCII wchar_t
- `SetCursorPos` no-op - breaks mouselook
- `ValidateRect` no-op - prevents UI repaint, freezes on friend list
- `LoadLibraryA` / `WaitForMultipleObjects` hooks - cause silent close on loading
- Timing method fix (`sub_86AD50` -> return 0) - causes silent close on start
- Lua bytecode cache - ERROR #134 corrupt chunks
- Addon RAM-cache - corrupts addon loading, resets settings
- Asset path cache - stale mimalloc pointers crash all teardowns
- Raw allocator hooks - mimalloc internal corruption
- Stream buffer hooks - heap corruption, ERROR #132
- Tooltip cache - placeholder, never stored results
- `GetCursorPos` 16ms cache - causes cursor lag
- CriticalSection 3-stage spin hooks - caused login crashes / freezes
- `GetKeyboardLayout` / `GetKeyboardLayoutNameA` hooks - cached keyboard state, broke language switching
- `GetClientRect` / `GetWindowRect` hooks - cached window dimensions, broke window resize

### Enabled features

- `GetProcAddress` cache - 4-way set-associative design (enabled)
- `GetEnvironmentVariableA` cache (enabled - isolated via 3-way bisection test DLLs)
- CRT SSE2 memory/string fast paths - re-enabled with page-boundary guards and SEH protection
- CRT SSE2 memchr/strchr/strcpy - re-enabled with page-boundary guards
- `lstrlenA` / `lstrlenW` fast paths - re-enabled after duplicate-hook fix

### Removed Features

These experimental features were tested and found to provide no measurable benefit, so they have been removed from the codebase:

- WaitSpin (WaitForSingleObject short-wait spin) - huge fallback count, essentially 0 value
- DispatchPool (dispatcher pool for 20-byte allocations) - hooks active but no real hit in sessions
- bgpreloadsleep cache - 0 calls in real sessions
- Subtask Event Pool - 0 reuse / 0 new / 0 returned in real stats

---

## What Improves In Practice

### You will notice
- smoother frametimes
- fewer random microstutters
- better long-session smoothness
- lower Lua overhead in addon-heavy gameplay
- less allocator fragmentation over time
- better responsiveness during heavy UI and addon workloads
- faster zone transitions and teleports 
- reduced spell cast lag 
- smoother addon-heavy gameplay 

### You may notice
- slightly better minimum FPS in cities and raids
- less "client gets heavier after long play"
- smoother loading transitions
- faster Lua-heavy addon behavior

### You should not expect
- a giant average FPS increase from one hook alone
- visual changes
- magical fixes for broken addons
- gameplay automation

This is an engine and runtime optimization DLL, not a UI overhaul.

---

## Recommended Combo

For best results, use wow_optimize together with [!LuaBoost](https://github.com/suprepupre/LuaBoost).

| Layer | Tool | Purpose |
|------|------|---------|
| Engine / C / Win32 | `wow_optimize.dll` | allocator, Lua VM, timers, file I/O, networking, runtime overhead reduction |
| Lua / Addons | `!LuaBoost` | GC control, loading helpers, table pool, update dispatcher, diagnostics |

---

## Installation

### Option A - Proxy load
Copy into your WoW folder:
- `version.dll`
- `wow_optimize.dll`

Then launch WoW normally.

### Option B - Loader
Copy:
- `wow_loader.exe`
- `wow_optimize.dll`

Then launch `wow_loader.exe`.

### Option C - Manual injection
Copy:
- `wow_optimize.dll`
- your injector

Then inject after WoW starts.

---

## Compatibility & Setup

1. Install the `!LuaBoost` addon into `Interface\AddOns\`.
2. **Disable conflicting addons:** Remove or disable any third-party GC optimizers (`GarbageProtector`, `GarbageCollector`, `SmartGC`, etc.) and combat log fixes (`CombatLogFix`, etc.). The DLL handles these natively; running both causes duplicate hooks, memory corruption, or crashes.
3. **Adjust damage meter settings:** Disable built-in garbage collection / memory optimization in your meter addons to prevent double-stepping the Lua GC.
   - **Skada:**
     ![Skada Settings](images/image1_Skada_settings.png)
   - **DBM:**
     ![DBM Settings](images/image2_DBM_settings.png)

---

## Multi-client Support

wow_optimize automatically detects when multiple WoW instances are running.

- Single client:
  - precise sleep
  - 0.5 ms timer
- Multi-client:
  - yield-based sleep
  - 1.0 ms timer
  - reduced working set targets

This reduces CPU pressure compared to forcing aggressive single-client timing on all clients.

---

## macOS / Apple Silicon (WoWSilicon)

wow_optimize works on macOS via [WoWSilicon](https://github.com/WoWSilicon/WoWSilicon), which runs WoW 3.3.5a natively on Apple Silicon using Wine + [rosettax87](https://github.com/athei/x87sidecar) translation.

### DLL load order

In `dlls.txt`, `winerosetta.dll` must be loaded before `libSiliconPatch.dll`:

```
mods/winerosetta.dll
mods/libSiliconPatch.dll
mods/wow_optimize.dll
```

Swapping the first two causes a rosetta error. Without wow_optimize the order does not matter, but with it loaded the translation layer must initialize before any hooks are installed.

### Testing credits

macOS/WoWSilicon compatibility was tested by **David** (`_oldq`).

---

## Building

The build target is always Win32 i386, but you can produce it from either a Windows host (native MSVC) or a macOS host (cross-compile). Both paths drive the same `CMakeLists.txt` and ship binary-equivalent DLLs to within ~30 KB.

### Windows (native MSVC)

Requirements:
- Windows 10 or 11
- Visual Studio with the C++ desktop workload
- CMake
- Win32 / 32-bit build configuration

```bash
git clone https://github.com/suprepupre/wow-optimize.git
cd wow-optimize
build.bat
```

Output:
- `build\Release\wow_optimize.dll`
- `build\Release\version.dll`
- `build\Release\wow_loader.exe`

### macOS (cross-compile to Win32)

Requirements:
- macOS (Apple Silicon or Intel)
- Homebrew
- [xwin](https://github.com/Jake-Shadle/xwin) for the Windows SDK / MSVC CRT

One-time setup:
```bash
brew install llvm lld cmake ninja
xwin splat --output /opt/xwin
```

Build:
```bash
git clone https://github.com/suprepupre/wow-optimize.git
cd wow-optimize
make
```

Output:
- `build/wow_optimize.dll`
- `build/version.dll`
- `build/wow_loader.exe`

The Makefile drives `clang-cl` (Homebrew `llvm`) and `lld-link` (Homebrew `lld`) through the toolchain file in `cmake/toolchain-clang-msvc-x86.cmake`. `make verify` prints PE headers; `make clean` / `make rebuild` work as expected. Override `LLVM_DIR`, `LLD_DIR`, or `XWIN` on the command line if your paths differ.

---

## Core Architecture

### Main modules
- `dllmain.cpp` - Win32 hooks, allocator, timers, file I/O, networking, threading, VA Arena
- `lua_optimize.cpp` - Lua VM allocator, adaptive GC, Lua globals bridge
- `lua_fastpath.cpp` - `string.format` and runtime-discovered Phase 2 hooks (20/27 functions)
- `lua_vm_engine.cpp` - Direct-threaded Lua VM interpreter with inline cache
- `lua_getstr_inline.cpp` - Safe bucket-index cache for luaH_getstr (16384 entries)
- `lua_rawgeti_inline.cpp` - Safe array-direct + bucket-index cache for lua_rawgeti (8192)
- `lua_pushnumber_fast.cpp` - Direct TValue stack write for lua_pushnumber
- `lua_gettable_safety.cpp` - TValue type validation crash fix
- `hooks_render.cpp` - 3-tier off-screen animation throttle, backbuffer LockRect skip
- `hooks_simd.cpp` - SSE2 matrix, quaternion, frustum cull, BGRA↔ARGB, premultiplied alpha
- `hooks_logic.cpp` - Combat text batching, UI layout cache, heartbeat filter, script cache
- `hooks_memory.cpp` - 64B-aligned slab allocator, 16384-entry GUID hash-table
- `hooks_async.cpp` - 2-thread worker pool, particle SSE2, ADT prefetch
- `d3d9_state_manager.cpp` - 15-hook D3D9 vtable patcher (disabled — DXVK conflict)
- `hot_patch.cpp` - 20 runtime hot-patch optimizations
- `infra_patch.cpp` - 50 infrastructure APIs (pools, caches, dedup, perfmon)
- `hook_prefetch.cpp` - 3 SSE2 prefetch hooks for cleanup/delete/reset paths
- `data_caches.cpp` - 10 game-data lookup caches (spell, M2, FMOD, DBC, etc.)
- `compute_caches.cpp` - 10 compute/transform caches (BZ2, vertex SSE2, regex ext, etc.)
- `crash_dumper.cpp` - Enhanced crash reporter with feature tracking + hook trace
- `lua_internals.cpp` - stable VM baseline (disabled unsafe hooks)
- `combatlog_optimize.cpp` - combat log retention and cleanup behavior
- `combatlog_mt.cpp` - multithreaded combat log parser
- `texture_async.cpp` - async texture loading with worker thread pool
- `spell_prefetch.cpp` - async spell data prefetching
- `addon_dispatcher.cpp` - multithreaded addon update dispatcher
- `model_async.cpp` - model/M2 caching
- `mpq_prefetch.cpp` - predictive MPQ prefetching
- `api_cache.cpp` - `GetItemInfo` cache
- `ui_cache.cpp` - disabled in public-safe build
- `version_proxy.cpp` - proxy loader
- `wow_loader.cpp` - standalone loader executable

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Proxy DLL doesn't load (no log file) | Use `wow_loader.exe`, or uncheck **"Disable fullscreen optimizations"** in `Wow.exe` properties:<br>![Wow.exe Properties](images/wow.exe_properties.png) |
| Antivirus flags the DLL | Hooking/injection tools often trigger false positives. Source is open for review. |
| `FATAL: MinHook initialization failed` | Another hook DLL is conflicting. Disable other injectors/overlays. |
| `ERROR: No CRT DLL found` | Non-standard WoW build detected. |
| Socket shows `fail` | Normal on some Windows versions - some network options require admin. |
| Damage meters still broken | Remove `CombatLogFix` or similar addons. Two fixers conflict. |
| No noticeable difference | Expected on high-end PCs with few addons. |
| `[UICache] DISABLED` | Non-standard WoW build - method table not found. |
| High CPU usage with multiple clients | Expected. Each client runs full optimization. Remove `version.dll` from secondary clients if needed. |
| "I use DXVK or Vulkan" | Fully supported. No D3D9 state-cache dependencies. |
| "Large pages: no permission" | Informational only. Not a crash cause. Requires "Lock pages in memory" policy. |

---

## Project Structure

```text
wow-optimize/
├── src/
│   ├── dllmain.cpp                       # Win32/CRT hooks, allocator, timers
│   ├── lua_optimize.cpp/.h               # Lua VM allocator, GC, string table
│   ├── lua_fastpath.cpp/.h               # Lua C-function fast paths (20/27)
│   ├── lua_vm_engine.cpp/.h              # Direct-threaded Lua VM interpreter
│   ├── lua_getstr_inline.cpp/.h          # Safe luaH_getstr cache (16384)
│   ├── lua_rawgeti_inline.cpp/.h         # Safe lua_rawgeti cache (8192)
│   ├── lua_pushnumber_fast.cpp/.h        # Direct TValue stack write
│   ├── lua_gettable_safety.cpp/.h        # TValue type validation crash fix
│   ├── lua_vm_cache.cpp/.h               # luaV_gettable primitive cache
│   ├── lua_vm_phase3.cpp/.h              # luaD_call dispatch
│   ├── lua_internals.cpp/.h              # Lua VM internals
│   ├── lua_bytecode_cache.cpp/.h         # Compiled bytecode cache
│   ├── lua_bytecode_pre_compiler.cpp/.h  # Addon file pre-scanner
│   ├── lua_settable_cache.cpp/.h         # luaV_settable cache
│   ├── hooks_render.cpp/.h               # 3-tier off-screen animation throttle
│   ├── hooks_simd.cpp/.h                 # SSE2 matrix/quat/frustum cull
│   ├── hooks_logic.cpp/.h                # Combat text, UI cache, heartbeat
│   ├── hooks_memory.cpp/.h               # 64B slabs, GUID hash-table
│   ├── hooks_async.cpp/.h                # 2-thread worker pool
│   ├── d3d9_state_manager.cpp/.h         # D3D9 15-hook vtable patcher
│   ├── hot_patch.cpp/.h                  # 20 runtime hot-patch optimizations
│   ├── infra_patch.cpp/.h                # 50 infrastructure APIs
│   ├── hook_prefetch.cpp/.h              # 3 SSE2 prefetch hooks
│   ├── data_caches.cpp/.h                # 10 game-data lookup caches
│   ├── compute_caches.cpp/.h             # 10 compute/transform caches
│   ├── combatlog_optimize.cpp/.h         # Combat log retention patch
│   ├── combatlog_mt.cpp/.h               # Multithreaded combat log parser
│   ├── combatlog_buffer.cpp/.h           # Combat log buffer governor
│   ├── addon_dispatcher.cpp/.h           # Multithreaded addon dispatcher
│   ├── addon_preload.cpp/.h              # Addon file preload
│   ├── spell_prefetch.cpp/.h             # Async spell data prefetching
│   ├── spell_cache.cpp/.h                # Spell data cache
│   ├── spell_effect_mt.cpp/.h            # Multithreaded spell effects
│   ├── model_async.cpp/.h                # Model/M2 async loading
│   ├── texture_async.cpp/.h              # Texture async loading
│   ├── texture_decode_mt.cpp/.h          # BLP decode worker pool
│   ├── anim_mt.cpp/.h                    # M2 animation worker pool
│   ├── mpq_prefetch.cpp/.h               # Predictive MPQ prefetching
│   ├── mpq_decompress_mt.cpp/.h          # Multithreaded zlib decompress
│   ├── obj_vis_cache.cpp/.h              # Object visibility cache
│   ├── nameplate_batch.cpp/.h            # Multithreaded nameplates
│   ├── sound_prefetch.cpp/.h             # Sound file prefetching
│   ├── quest_async.cpp/.h                # Async quest data loading
│   ├── saved_vars_async.cpp/.h           # Async SavedVariables writes
│   ├── tooltip_cache.cpp/.h              # Tooltip string caching
│   ├── regex_cache.cpp/.h                # Regex compiled-pattern cache
│   ├── trig_lut.cpp/.h                   # SSE2 trig lookup tables
│   ├── event_name_cache.cpp/.h           # Event name lookup cache
│   ├── event_name_hash.cpp/.h            # Event name hash cache
│   ├── render_state_dedup.cpp/.h         # Render state deduplication
│   ├── script_handler_cache.cpp/.h       # O(1) script handler resolver
│   ├── cdatastore_batch.cpp/.h           # CDataStore batch read detection
│   ├── gettime_fast.cpp/.h               # Frame-cached GetTime
│   ├── lua_pushvalue_fast.cpp/.h         # Direct TValue stack copy
│   ├── api_cache.cpp/.h                  # GetItemInfo/GetSpellInfo cache
│   ├── ui_cache.cpp/.h                   # UI widget cache
│   ├── ui_frame_batch.cpp/.h             # Frame OnUpdate batching
│   ├── frame_throttle.cpp/.h             # Script throttling
│   ├── frame_arena.cpp/.h                # Frame-scoped allocator
│   ├── cache_governor.cpp/.h             # Dynamic TTL/cache control
│   ├── heap_compactor.cpp/.h             # VA fragmentation monitor
│   ├── crt_mem_fastpath.cpp              # SSE2 strlen/strcmp/memcpy/memset
│   ├── crt_char_fast.cpp/.h              # SSE2 memchr/strchr
│   ├── crt_pow_sse2.cpp/.h               # SSE2 pow(x,y) fast path
│   ├── strstr_fast.cpp/.h                # SSE2 Boyer-Moore-Horspool strstr
│   ├── dxvk_bridge.cpp/.h                # DXVK/Vulkan detection
│   ├── crash_dumper.cpp/.h               # Enhanced crash reporter
│   ├── format_validator_cache.cpp/.h     # string.format validator cache
│   ├── datastore_fastpath.cpp/.h         # CDataStore TLS-cached fast path
│   ├── version.h                         # Version and feature toggles
│   ├── version.rc                        # Windows resource
│   ├── version_proxy.cpp                 # version.dll proxy loader
│   ├── version_exports.def               # Export forwarding table
│   └── wow_loader.cpp                    # External injector EXE
├── CMakeLists.txt
├── README.md
└── LICENSE
```

---

## License

MIT License - use, modify, and distribute freely.
