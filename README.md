> [!CAUTION]
> **Do not use this on Warmane.** Their anti-cheat flags performance injectors and
> memory optimization tools as illegal software regardless of intent, and the
> result is a permanent ban on your account.

# wow_optimize

Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)
Author: SUPREMATIST

**[Download Latest Pre-compiled Release](https://github.com/suprepupre/wow-optimize/releases/latest)**

wow_optimize improves WoW 3.3.5a at the engine and runtime level: memory allocation, Lua VM behavior, Lua library fast paths, timers, file I/O, networking, heap fragmentation, lock contention, the 16-year combat log bug fix, and other low-level bottlenecks.

The current public build is focused on real frametime stability, long-session smoothness, addon-heavy gameplay, and lower Lua/runtime overhead while keeping historically unsafe features disabled.

> Disclaimer: This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. Use at your own risk.

---

## Table of Contents
* [What's New in v3.18.1](#whats-new-in-v3181)
* [What's New in v3.18.0](#whats-new-in-v3180)
* [Send me your log](#send-me-your-log)
* [Reviews & Acknowledgments](#reviews)
* [Current Feature Set](#current-feature-set)
* [Installation](#installation)
* [Compatibility & Setup](#compatibility--setup)
* [Multi-client Support](#multi-client-support)
* [macOS / Apple Silicon (WoWSilicon)](#macos--apple-silicon-wowsilicon)
* [Building](#building)
* [Core Architecture](#core-architecture)
* [Troubleshooting & Diagnostics](#troubleshooting)

---

## What's New in v3.18.1

A fix release. Thanks to **prince**, [txtsd](https://github.com/txtsd),
**Signalborn Soulweaver**, **Morbent** and **Doc.James** for the logs.

**Fixed**

- False freeze reports, and per-frame work that stopped running with them — caches were not dropped on a reload or character swap. Introduced in 3.18.0.
- Random UI reloads. Also introduced in 3.18.0.
- WeakAuras icons staying wrong after a talent switch. `GetSpellInfo` is no longer cached; it cannot be cached correctly.
- Loading screens finishing and then sitting for several seconds with Texture Smart Unload Delay on.
- Five launcher switches that controlled nothing, one of which was meant to stop worker threads from starting. Three more removed — their features were gone in 3.18.0.
- Hooks are no longer installed over a function something else has already detoured.

**Faster**

- 4x4 matrix multiply, once per bone per frame on every animated model: 2.38x, and now bit-identical to the client's own result.
- SSE2 terrain horizon rasterisation, 2.46% of main-thread time. New, off by default, on the Experimental tab.

Both verify themselves against the client at startup and refuse to install if the results differ.

**Memory**

148 MB of address space returned on a 32-bit client — 136 MB from the API cache, sized to the function it caches instead of a round number, and 16.6 MB from disabled features that were reserving buffers anyway. The DLL's data section drops from 30.6 MB to 14.0 MB.

**Changed**

- `wow_opt.ini` now lives in the `WTF` folder. An existing file is moved there on first run; nothing is reset.
- Texture Smart Unload Delay reports how often a held texture is actually reused. One long session measured 0.4%. Check your own log before leaving it on.

---

## What's New in v3.18.0

Forty-six modules were removed because they never ran, three optimizations went
in because the logs said where the time actually goes, and the settings that were
quietly overwriting your graphics options are gone. The rest of this release is
the diagnostics catching themselves out — four cases of a log reporting something
it had not actually measured.

Thanks to [txtsd](https://github.com/txtsd), **Signalborn Soulweaver**, **Morbent**,
and **prince**, who between them put this build through raids and a good deal of
open world, and reported what broke. Every measured item below came out of a log
somebody sent in.

**Forty-six modules that did nothing at all**

They appeared in the log at startup and had settings behind them. None installed
a hook, patched anything, or was called from anywhere. `Init()` was
`return true;` and the rest of the module was never entered.

Most had no launcher switch at all and read a default of off, so nobody was
running them — dead weight rather than active mistakes. Two separate minimap
throttles existed, neither wired to anything. A JIT compiler sat behind a LuaJIT
setting on a client that has no JIT. Two files shared a name and a namespace
differing by one letter's case, and only one of them was ever wired up.

Three of them had callers and still did nothing: a throttle whose enable flag was
initialised to false and never set, a particle skip that asked a frustum nobody
filled, and a "font alpha fast path" that turned alpha blending off whenever it
should have left it alone — which would have painted text as solid rectangles had
anything reached it.

Two looked alive on inspection and were not. `ItemDataPrefetch::PrefetchItem` was
an empty body under a comment saying the work was unsafe, called twice per item
lookup into nothing. `CDataStoreBuffering` read a buffer pointer from an offset
that actually holds a length, so the first call would have dereferenced a number
as a pointer — which is presumably why nothing ever called it.

`MpqMmapVfs` and `MpqPrefetch` went too. Both look up StormLib through
`Storm.dll`, and 3.3.5a links Storm into the executable — there is no such file.
Every tester log says so outright.

What is left is a much shorter list of things that actually run: eleven settings
are on unless you turn them off, and every one of them now has a switch.

**Three optimizations that came from measurements, not guesses**

- **The client asks the heap how big every block is, then throws the answer
  away.** Both the `free` wrapper and the allocation wrapper call `_msize` and
  discard the result — a walk into the heap on every single allocation and every
  deallocation, from over a hundred call sites. Two
  independent profiles measured that call at 8.09% and 10.59% of the time the
  main thread spent executing. Both are gone; nothing else about either call
  changes. A three-minute session with the fix in place reports 67,776
  allocations and 28,393 deallocations served without it.

- **`tostring` on numbers is about 50x cheaper.** It was the single largest
  target in this project's own domain — 10.74% of execution in a CPU-bound
  session. There was already a "fast path" hooked onto it, and for numbers it
  called `sprintf("%.14g")`, which is exactly what Lua does, so it took the call
  and paid full price. Integral values now convert directly: 841 ns to 16 ns for
  the formatting step, verified byte-identical against `%.14g` across 200,139
  values before it was allowed anywhere near a build.

  The formatting is one part of a `tostring` call, so the end-to-end gain is
  smaller than 50x. Your log now says how many conversions took the fast route.

**Your graphics settings are yours again**

Three "adaptive" features scaled quality down when frame rate dropped. Each one
started from a number written into the code rather than the number you had set, so
turning them on could raise your settings instead of lowering them. **Dynamic Shadow
Scaler** went in 3.17.0; the other two go now:

- **Adaptive Farclip** assumed a draw distance of 1250. If yours was 500 — a common
  choice on older hardware — it dragged you *up* toward 1250, making the game
  heavier while claiming to make it lighter. It also moved on thresholds three
  frames apart (below 55 fps, above 58), so anyone playing near 60 had it adjusting
  constantly.
- **Particle Density Scaler** assumed 1.0 and restored to 1.0, so a deliberate 0.5
  was pushed back to full density.

Neither survives. Nothing in the DLL now overwrites a setting it never read.

**Adaptive Quality Governor** *(experimental, off by default)*

What replaces them is one dial instead of three that argued with each other. It
learns your ceiling by watching what the game writes when you change a setting, and
treats that as a limit it will never exceed — the worst it can do is give back what
it took.

It reads the p95 of recent frames rather than an instant frame rate, so a single
slow frame moves nothing. It degrades after 5 seconds past 33 ms and restores only
after 30 seconds back under 20 ms; that asymmetry is deliberate, because quality
flickering up and down is worse than quality being slightly too low. Order is
particles, then shadows, then draw distance, on the assumption that you would rather
see the world at full distance with fewer sparks.

It has not been proven on anyone's machine yet. That is why it is opt-in and on the
Experimental tab — if you run it, the `[FrameBench]` block in your log says whether
it helped.

**An Experimental tab in the launcher**

Features that are new or unproven now live on their own tab, and **Enable All no
longer switches them on**. Previously it did, which meant anyone testing "everything
on" was also testing code that had never run in a game — and made their results
impossible to interpret.

**Diagnostics that stop reporting things they did not measure**

Four of these, all found by reading logs testers sent in:

- The CVar watchdog ran at injection, before the client had initialized anything it
  inspects. Every one of its nine "CORRUPT" findings was a game that had not started
  yet. It now waits until the client is up.
- A 41.9-second loading screen was being recorded as a *frame*, which made `p99.9`
  and `max` meaningless. Gaps over 2 seconds are now counted and reported separately
  from frame times.
- The profiler ranked `NtDelayExecution` — a thread doing nothing — as the second
  hottest function, with a share of "executing" time it was by definition not using.
- The loading report printed `0 ms inside ReadFile` in sessions where the ReadFile
  hook was switched off and nothing had been measured at all.

**Loading screens are now measurable**

Logs show loading screens running past 30 seconds on some setups — on one tester's
machine, 7 of 12 loads. The cause is not known yet. This release adds timing that
separates disk time from everything else, without turning the MPQ cache back on to
get it. If your loads are slow, your log now contains the evidence.

### Upgrading

Settings carry over. If you had **Adaptive Farclip** or **Particle Density Scaler**
on, they are gone, and your `farclip` and `particleDensity` will stay wherever you
set them from now on. Worth checking them once in the game's own video options —
these features may have left them somewhere you did not choose, and that value
persisted in your config after the feature stopped running.

To try the replacement, turn on **Adaptive Quality Governor** on the Experimental
tab.

Older releases: see the [Releases page](https://github.com/suprepupre/wow-optimize/releases) for the full version history.

![wow_optimize Launcher Dashboard](images/launcher_screenshot.jpg)

## Current Status

### Performance

**`memset` replacement** — 2.3x faster than the client's own `rep stosd` at the
sizes engine code clears: 5.05 ns/call against 11.76, measured over 4.8M calls per
variant. The client reaches that one function from 1108 call sites.

Everything else is opt-in, and the frame-time benchmark lets you settle it on your own hardware,
with your own addons, instead of taking anyone's word for it. Play a session, quit
the game normally, and read the `[FrameBench]` block at the end of
`Logs\wow_optimize_<date>_<time>.log`. Compare `p95` and `p99` between runs rather
than the average, which hides the stutters you actually feel — and the `config`
fingerprint on that line proves two runs differed only where you meant them to.
A/B testing a single toggle is two logs on the same route.

---

## Send me your log

This is the single most useful thing anyone does for this project, and it costs
you about thirty seconds.

After playing, attach `Logs\wow_optimize_<date>_<time>.log` to an
[issue](https://github.com/suprepupre/wow-optimize/issues) or drop it in
[Discussions](https://github.com/suprepupre/wow-optimize/discussions). Nothing
needs to be wrong for a log to be worth sending — a session where everything
worked is just as informative as one where it did not.

**What is in it and why it matters.** The log ends with a frame-time distribution,
a note on whether your client was actually CPU-bound or waiting on the GPU, a
profile of where time went, and which features did work rather than merely being
switched on. Together those answer questions that cannot be answered from here:

- Which optimizations pay off on hardware and addon sets I do not have. Several
  features have been removed after logs showed they did nothing, and a few were
  fixed after a log showed them doing the wrong thing.
- Where the remaining time actually goes. One log turned out to be 94% idle,
  which meant no CPU-side work could have helped that player at all; another was
  genuinely CPU-bound and pointed straight at the hot code.
- Whether a bug is mine. A log carries the exact build hash, so a report can be
  matched to source instead of guessed at.

Please send the whole file rather than an excerpt, and do not trim the first
lines — that is where the build hash and your settings are. If you are reporting
a bug, say what you saw and roughly when; the log has timestamps and the two
together usually locate it.

If you would rather not share it publicly, that is fine — say so in an issue.

---

## Reviews

<details>
<summary><b>Click to expand community reviews and stability testers list</b></summary>

See what other players say: [Reviews and Testimonials](https://github.com/suprepupre/wow-optimize/discussions/10)

### Stability Testing Team


This project wouldn't exist without the community. Every crash report, every bisection test, every "hey this broke my addon" message directly shaped the release. 

Special thanks to:
Morbent, Darkmoore, Ethodeus, Billy Hoyle, tuan, NoGoodLife, feh_dois, David (`_oldq`), Keoo, UNOB, DarkRockDemon, Raymond, Vandal, Mantork, Falcon, Muus, szopachink17, Shandrax, pathetic-lynx, txtsd, Signalborn Soulweaver, Sicsoo, kojekude, Houmbro

### Code contributions

- **[athei](https://github.com/athei)** (Alexander Theissen) — the macOS cross-compile
  toolchain (`clang-cl` + `lld-link` + `xwin`, [#20](https://github.com/suprepupre/wow-optimize/pull/20)),
  reliable `!LuaBoost` detection across `lua_State` swaps and fast logins
  ([#19](https://github.com/suprepupre/wow-optimize/pull/19)), and the filter that stops
  `ClientExtensions.dll`'s anti-tamper probe from being reported as a crash
  ([#21](https://github.com/suprepupre/wow-optimize/pull/21)).
- **[anzz1](https://github.com/anzz1)** — VS2019 build fix
  ([#2](https://github.com/suprepupre/wow-optimize/pull/2)) and closing dangling thread
  handles ([#7](https://github.com/suprepupre/wow-optimize/pull/7)).
- **[POKOch](https://github.com/POKOch)** — selective rendering, spell visual blocking
  and API caching ([#12](https://github.com/suprepupre/wow-optimize/pull/12)).

### Testing

Every measured item in these notes came out of a log somebody sent in.

- **prince** — Chinese client under DXVK; the WeakAuras talent-switch bug, the
  loading-screen stall, and the crash report that finally pinned an access
  violation to one instruction.
- **[txtsd](https://github.com/txtsd)** — raids on ChromieCraft; the memory growth
  and freeze reports, and the request for per-addon profiling that turned into the
  addon CPU profiler and the Lua compile census.
- **Signalborn Soulweaver**, **Morbent** — early 3.18 logs.
- **Doc.James** — the zone-change stall, with three sessions that made it
  reproducible.

</details>

---

## Current Feature Set

<details>
<summary><b>Click to expand full optimized feature list (Memory, Lua VM, Math, Network, Async, I/O)</b></summary>

### Memory and allocator
- **Large-allocation mimalloc redirect** *(opt-in, default off)* — only main-thread allocations `>= 1 MB` are routed to mimalloc, and only if the returned pointer sits below 2 GB; everything smaller (including all network buffers) and every background-thread allocation stays on WoW's CRT. This is the conservative replacement for the old redirect-everything version, which was removed in v3.16.3 for destabilizing Winsock and breaking connections. Enable in the launcher and confirm you can still connect. `free`/`realloc`/`_msize`/`_recalloc` route mimalloc-owned blocks by region check so nothing is freed on the wrong heap.
- **Adaptive purge delay + memory-pressure governor** — purge aggression scales with VA pressure; forced `mi_collect` under critical pressure (now driven from the main-thread maintenance tick, not a background thread)
- **Direct mimalloc use** — subsystems (aligned-alloc cache, async I/O buffers, prefetch, etc.) call mimalloc directly regardless of the redirect toggle
- Lua allocator replacement *(disabled — corrupted pointers during login)*
- WoW `free`-wrapper fast path (calls WoW's own `free`, skips a redundant `_msize` heap-walk)
- Lua string table pre-sizing to reduce hash resize spikes
- Low Fragmentation Heap (LFH) enabled for process heap and new heaps
- **Deferred Heap Compactor** — defers process heap compaction during loading screens to run once upon screen closure, preventing character login freezes.

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
- **Lua VM Bytecode JIT Redirection & Cache** — detours standard Lua VM preparation function `sub_856370` to run JIT stubs under normal play conditions, utilizing a lock-free direct-mapped cache (`g_protoCache`) to avoid profiling lock contention.

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
  - `string.gsub` (plain-literal fast path)
  - `type`
  - `math.floor`
  - `math.ceil`
  - `math.abs`
  - `math.max` (2 args)
  - `math.min` (2 args)
  - `math.random`
  - `math.sqrt`
  - `math.fmod`
  - `math.modf`
  - `string.len`
  - `string.byte`
  - `string.char`
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
- C-global fast paths - **ENABLED**:
  - `strjoin`
  - `strtrim`
  - `strsplit`

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
- keepalive (30s idle / 5s interval — tuned to keep NAT warm without dropping the connection on transient network jitter)

### Async loading and prefetching

Features that use worker threads and lock-free queues. Status reflects the current public-safe configuration; individual toggles live in `src/version.h`.

- **Async spell data prefetching** - predictive spell data loading before cast completes, reduces spell cast lag, worker thread with lock-free queue (4096 entries) and cache (4096 entries) *(disabled — placeholder worker with no producers)*
- **Multithreaded addon dispatcher** - parallelizes addon OnUpdate callbacks across worker thread pool (4 threads), reduces main thread CPU in addon-heavy setups, batch processing with lock-free queue (8192 entries) *(disabled - unsynchronized writes to WoW game state)*
- **Predictive MPQ prefetching** - tracks zone transitions and predicts next zone, prefetches textures/models/WMOs into OS cache before teleport, reduces zone loading stutters, worker thread pool (2 threads) with lock-free queue (2048 entries) *(enabled)*
- **Multithreaded combat log parser** - offloads combat log parsing to worker thread, reduces main thread CPU in raids, lock-free queue with async processing *(disabled — placeholder worker with no producers)*
- **Sound prefetching** - predicts and prefetches sound files based on spell casts, zone transitions, combat state, worker thread pool (2 threads) with lock-free queue (1024 entries) *(disabled — placeholder worker with no producers)*
- **Async quest/achievement loading** - async quest log and achievement data loading, worker thread with lock-free queue (512 entries) *(disabled — placeholder worker with no producers)*
- **Multithreaded nameplate renderer** - offloads nameplate rendering to worker threads, reduces main thread CPU in 25-man raids, priority system (Target > Focus > Nearby > Distant) *(disabled - unsynchronized writes to WoW game state)*
- **Model/M2 caching** - synchronous LRU cache (1024 entries) for loaded models, eliminates redundant model loading *(enabled)*
- **Asynchronous Texture Hot-Swapping & Storm VFS** *(enabled)* — detours TexCreateBLP to immediately return a placeholder white texture, background loads the real BLP data, and hot-swaps the underlying Direct3D 9 texture pointer and properties during frame boundaries (OnFrame) without visual stutters.
- **Asynchronous Terrain Mesh Loader & Collision Decoupler** *(enabled)* — offloads ADT terrain file loading and geometry compiling to background threads, decoupling collision checks via player Z height fallback, and detouring CMapGrid::Update to prevent character-select crashes.
- **RCU Client Object Manager Traverser** *(enabled)* — replaces linear linked-list entity traversals with lock-free atomic pointer flat mirror arrays updated on link/unlink events.
- **Addon dispatcher** - lightweight event-driven addon update dispatch *(enabled)*

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

### SSE2 string/memory fast paths (WoW-internal, active)
Replacements for WoW's own statically-linked CRT routines at verified addresses:
- WoW `strlen` (sub_76EE30) - 16-byte-aligned SSE2 scan, page-safe
- WoW `memset` (0x40BB80, 1108 callers) - full SSE2 + non-temporal ≥2 MB
- WoW `memcpy` (0x40CB10, 719 callers) - SSE2 16–255 B + non-temporal ≥256 KB, overlap-safe
- WoW `_strnicmp` (0x76E780, 1013 callers) - SSE2 ASCII case-insensitive compare
- `strstr` - SSE2 Boyer–Moore–Horspool
- `MultiByteToWideChar` / `WideCharToMultiByte` - SSE2 ASCII fast path

### SSE2 math and geometry (WoW-internal, active)
- SSE2 4×4 matrix multiply — `CMatrix::operator*` (0x4C1F00)
- SSE2 matrix-vector transforms — 3D point × 4x4 matrix (0x4C21B0), 4D vector × 4x4 matrix (0x4C2270), in-place point × 4x4 (0x4C2300)
- SSE2 `C3Vector::Normalize` — 0x4C3420 + 0x4C3600 (full-precision `sqrtss`/`divss`, engine guards replicated)
- SSE2 `CMatrix::Transpose` — 0x4C23D0 (`_MM_TRANSPOSE4_PS`, bit-identical)
- SSE2 frustum point culling — `CFrustum::IsPointVisible` (0x983D70)
- SSE2 Möller-Trumbore ray-triangle intersection — 32-bit indices (0x9836B0), 16-bit indices (0x983490)
- SSE2 frustum AABB-vs-4-planes cull
- SSE2 BGRA↔ARGB batch swap, premultiplied alpha
- Network GUID SSE2 unpacking — `CDataStore::GetWowGUID` (0x76DC20)
- SSE2 quaternion normalize *(enabled — normalizes in double precision)*
- Particle simulation throttling — `CParticleEmitter::SimulateParticle` (0x981D40) *(disabled — 0x981D40 is the particle spawn/init routine, not a skippable advance; throttling it left particles uninitialized, rendering as colored flashes)*

> The generic msvcrt CRT mem/char SSE2 paths (`crt_mem_fastpath`, `crt_char_fast`) are **disabled** — WoW links its CRT statically, so hooking msvcrt exports had little effect and risked VA exhaustion.

### Lua Event Coalescing *(disabled)*
- Buffers and deduplicates high-frequency UI events per frame
- **Disabled**: suppressing and re-emitting events a frame later changes event timing/ordering and was unvalidated across the in-world → glue teardown where char-switch crashes occur. Stability outranks the dedup win until it can be confirmed in-game.
- The `FrameScript_SignalEvent` (0x81AC90) detour it used to own now belongs to the loading/combat state detector, which is always installed. The dedup queue is a consumer of that detour, so it stays switched off without taking the state tracking down with it.

### Kernel-call caches (38 hooks)
Batch 1-8: `GetSystemTimeAsFileTime` (QPC-based 1ms refresh), `GetACP`, `GetUserDefaultLangID`, `GetProcessHeap`, `CharUpperA/W`, `CharLowerA/W`, `MapVirtualKeyA`, `GetThreadPriority`

Batch 11-20: `GetOEMCP`, `GetDoubleClickTime`, `GetCursorPos`, `GetSysColor`, `GetCaretBlinkTime`, `IsWindow`, `GetDesktopWindow`, `GetFocus`

Batch 21-26: `GetTickCount64` (QPC-backed), `ShowCursor`, `GetVersionExA`, `GetSystemMetrics`, `IsDebuggerPresent` (no-op), `GetSystemInfo`, `RegQueryValueExA`

Batch 31-38: `GetCurrentProcess`, `GetCurrentThread`, `GetCPInfo` and related kernel caches

### Loading screen optimization
- Loading state is detected natively from the client's own event stream (`PLAYER_LEAVING_WORLD` → `PLAYER_ENTERING_WORLD`), so it works with or without the `!LuaBoost` addon. Many subsystems use it as a "bypass this while the world is loading" gate: deferred field updates, the DBC lookup cache, the Lua opcache and the texture unload queue
- Dynamic VA arena: reserves 256MB during loading, releases after. The reservation is skipped on HD clients (>500MB working set), but the loading state itself is always published
- A watchdog force-exits the loading state after 30s, so a missed end event can never pin the process in loading mode
- Sleep hook: bulk Sleep for waits >16ms (less CPU during idle)

### VA Arena (Virtual Address Arena)
- 512MB high-address reserved arena with `MEM_TOP_DOWN`
- Wow.exe caller filtering - only services allocations from WoW executable code
- span tracking for correct multi-page allocation/deallocation
- proper `MEM_DECOMMIT` / `MEM_RELEASE` behavior
- reduces 32-bit address space fragmentation from large WoW allocations

</details>

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

### Option A - Launcher Dashboard (Recommended)
Copy into your WoW folder:
- `wow_optimize_launcher.exe`
- `version.dll`
- `wow_optimize.dll`

Then run `wow_optimize_launcher.exe` to configure settings, load/save profiles, and click **LAUNCH WOW**.

### Option B - Proxy load (Automatic)
Copy into your WoW folder:
- `version.dll`
- `wow_optimize.dll`

Then launch WoW normally. The proxy DLL will automatically load the optimizer with default settings.

### Option C - Standalone Loader
Copy:
- `wow_optimize.dll`
- your injector

Then inject after WoW starts.

---

## Compatibility & Setup

### Supported Clients & Private Servers
The optimization suite is compatible with any standard or customized WotLK 3.3.5a client (build 12340), including private servers using custom executables:
* **Warmane** (Icecrown, Lordaeron, Onyxia) — **STRICTLY PROHIBITED (WILL RESULT IN A PERMANENT BAN)**
* **Project Ascension** (supporting custom `Ascension.exe` launches)
* **WoW Circle** (supporting `WoWCircle.exe` launches)
* **EZ WoW**
* **WoW Sirus** (supporting `Sirus.exe` or custom `run.exe` launches)
* **UWow** / **Firestorm** (supporting `run.exe` launches)
* **ChromieCraft 3.3.5a**

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
- `build\Release\wow_optimize_launcher.exe`

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

<details>
<summary><b>Click to expand full modules listing</b></summary>

### Main modules
- `dllmain.cpp` - Win32 hooks, allocator, timers, file I/O, networking, threading, VA Arena
- `lua_optimize.cpp` - Lua VM allocator, adaptive GC (with frame-time scaling and VA-pressure override), Lua globals bridge
- `async_terrain_loader.cpp` / `async_terrain_loader.h` - Asynchronous ADT terrain loader, CMapGrid update safety, Z-coordinate collision fallback query.
- `rcu_obj_mgr.cpp` / `rcu_obj_mgr.h` - RCU client object manager traverser for lock-free entity enumeration.
- `lua_fastpath.cpp` - `string.format` and runtime-discovered Phase 2 hooks (24/27 functions)
- `lua_vm_engine.cpp` - Direct-threaded Lua VM interpreter with inline cache
- `lua_getstr_inline.cpp` - Safe bucket-index cache for luaH_getstr (16384 entries)
- `lua_rawgeti_inline.cpp` - Safe array-direct + bucket-index cache for lua_rawgeti (8192)
- `lua_pushnumber_fast.cpp` - Direct TValue stack write for lua_pushnumber
- `lua_gettable_safety.cpp` - TValue type validation crash fix
- `hooks_render.cpp` - 3-tier off-screen animation throttle, backbuffer LockRect skip
- `hooks_simd.cpp` - SSE2 matrix multiply, 4×4 matrix multiply, quaternion normalize, frustum AABB/point cull, ray-triangle intersection, matrix-vector transforms, particle simulation throttle, BGRA↔ARGB, premultiplied alpha
- `hooks_logic.cpp` - Combat text batching, UI layout cache, heartbeat filter, script cache
- `hooks_memory.cpp` - 64B-aligned slab allocator, 16384-entry GUID hash-table
- `hooks_async.cpp` - 2-thread worker pool, particle SSE2, ADT prefetch
- `event_coalescer.cpp` - Lua event coalescing via FrameScript_SignalEvent hook, per-frame deduplication
- `network_guid_sse2.cpp` - SSE2 branchless GUID unpacking for CDataStore::GetWowGUID
- `d3d9_state_manager.cpp` - 15-hook D3D9 vtable patcher + device-reset lifecycle tracker and DXVK implicit-resize handler (active)
- `dxvk_bridge.cpp` - DXVK / Vulkan-translation-layer detection (module, d3d9.dll metadata, env)
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

</details>

---

## Troubleshooting

### Reporting a problem

Two things make a report actionable, and both are easy to get wrong:

1. **Send `Logs\wow_optimize_<date>_<time>.log`**, not `Logs\wow_optimize.log`. The second one is overwritten on every launch.
2. **Quit the game normally** — not `alt+F4` — after reproducing the problem, so the end of the log reaches disk.

If the game crashed, attach `Crashes\wow_crash_*.dmp` (or the text report written next to it under Wine) as well.

Every crash report, Lua error dump and stutter dump starts with an event trace — the state transitions leading up to the problem, newest first — which is usually the part that explains it:

```
Recent events:
    -    23ms  TID=900   LUA state swap (UI reload) - new VM settling
    - 27810ms  TID=900   LOADING begin (PLAYER_LEAVING_WORLD)
    -110351ms  TID=900   D3D9 device Reset (dev=0x0EB1AA90)
```

The startup banner reports the exact build the log came from (`v3.18.1 (build abc1234)`), so please don't trim the first lines.

If the complaint is stuttering rather than a crash, look for `slow frame` lines — each one names how far past your session's own median that frame ran, and what was happening during it:

```
[FrameBench] slow frame: 102.9 ms (16.3x the 6.30 ms median) - recent events:
```

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
| `Large pages: no permission` | Informational only — **not** a crash cause. Large pages are an optional TLB optimization (mimalloc 2&nbsp;MB OS pages); the DLL runs fine on normal 4&nbsp;KB pages without them. To enable them, see [Fixing `Large pages: no permission`](#fixing-large-pages-no-permission) below. |

### Fixing `Large pages: no permission`

<details>
<summary><b>Click to expand step-by-step setup guide</b></summary>

This log line means your Windows account does not hold the **Lock pages in memory**
privilege. The DLL can only *use* the privilege if the account already has it — it
cannot grant it for you. Granting it is optional and only enables the large-page TLB
optimization; everything else works without it.

**1. Grant the privilege**

1. Press `Win+R`, type `secpol.msc`, and run it as Administrator (Local Security Policy).
2. Go to **Local Policies → User Rights Assignment → Lock pages in memory**.
3. Click **Add User or Group**, type your Windows username, click **Check Names**, then **OK**.
4. Log off and back on (or restart) for the change to take effect.

**2. Still says `no permission`? Use a group catch-all**

If running as Administrator still produces the `no permission` log line, your Windows
username may not be mapping correctly inside the policy tool. Add the universal groups
instead of a specific account:

1. Open `secpol.msc` again.
2. Go back to **Local Policies → User Rights Assignment → Lock pages in memory**.
3. Clear out your specific account name.
4. Click **Add User or Group**, type `Administrators` (plural), click **Check Names**, then **OK**.
5. Click **Add User or Group** once more, type `Users` (plural), click **Check Names**, then **OK**.
6. Restart your computer.

After a restart the log should read `Large pages: ENABLED for mimalloc`. If you would
rather not change the policy at all, the line is harmless and can be ignored — or set
`TEST_ENABLE_LARGE_PAGES 0` in `src/version.h` to silence the attempt entirely.

</details>

---

## Project Structure

```text
wow-optimize/
├── src/
│   ├── allocators/           # mimalloc redirect, cache governor, heap compactor
│   ├── core/                 # DLL entry, proxy loader, features config (version.h)
│   ├── diagnostics/          # EIP sampling profiler, crash reporter, CVar watchdog
│   ├── hooks_subsystems/     # D3D9 state manager, CRT string fast-paths, event/data caches
│   ├── launcher/             # C# WinForms configurator & launcher dashboard
│   ├── runtime_vm/           # Lua C-API detour hooks, stack query inline paths, VM engine
│   ├── simd_math/            # SSE2 4x4 matrix, frustum point culling, raycast overrides
│   └── threading/            # Multi-threaded work pool dispatcher
├── CMakeLists.txt            # Build system definition
├── README.md                 # Project overview & documentation
└── LICENSE                   # Project license
```

## License

MIT License - use, modify, and distribute freely.

---

## Also for WoW 3.3.5a

| Project | What it does |
|---|---|
| [LuaBoost](https://github.com/suprepupre/LuaBoost) | Addon-side GC control, loading-screen helpers, shared APIs for addon authors |
| [WA_SafeGuard](https://github.com/suprepupre/WA_SafeGuard) | Backs up WeakAuras so a forced disconnect cannot wipe your auras |
| [DefileAlert](https://github.com/suprepupre/DefileAlert) | Instant Defile target callout for the Lich King encounter |

