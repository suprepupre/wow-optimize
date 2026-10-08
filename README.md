> [!CAUTION]
> **Do not use this on Warmane.** Their anti-cheat flags performance injectors and
> memory optimization tools as illegal software regardless of intent, and the
> result is a permanent ban on your account.

> [!WARNING]
> **On WoW Circle the DLL gets you disconnected** - Turning on **No Client Patches** in the launcher stops it, and
> also turns every optimization off.   
Or use the `!LuaBoost` addon without the DLL.

# wow_optimize

Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)
Author: SUPREMATIST

**[Download Latest Pre-compiled Release](https://github.com/suprepupre/wow-optimize/releases/latest)**

wow_optimize improves WoW 3.3.5a at the engine and runtime level: memory allocation, Lua VM behavior, Lua library fast paths, timers, file I/O, networking, heap fragmentation, lock contention, the 16-year combat log bug fix, and other low-level bottlenecks.

The current public build is focused on real frametime stability, long-session smoothness, addon-heavy gameplay, and lower Lua/runtime overhead while keeping historically unsafe features disabled.

> Disclaimer: This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. Use at your own risk.

---

## Table of Contents
* [What's New in v3.22.0](#whats-new-in-v3220)
* [Send me your log](#send-me-your-log)
  * [Measuring rather than reporting](#if-you-want-to-measure-something-rather-than-report-a-bug)
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

## What's New in v3.22.0

### Fixed

* **A crash when an addon set builds a lot of UI layers.** The *UI Strata List
  Compaction (SSE2)* replacement (on by default) wrote past the end of a 128-entry table
  once one layer had more than 128 levels, which large addon sets reach. The
  crash showed when an addon was enabled in AddonControlPanel and when an ICC
  satchel was opened. A layer with more levels than the table holds is now
  compacted by the game's own routine. Reported by Drain.
* **The Lich King movie crash.** In several sessions the game ended inside the
  Windows heap manager at the Fall of the Lich King movie. The cause is not
  settled. The first run with *Large Reservations Above 2GB: Heap Growth* off
  played the movie without it, and the switch exists so that run can be
  repeated. It is on by default, as before. The report now sorts the reservations
  Windows makes for itself by what they ask for, so the next log can tell heap
  segments from large blocks. Reported by Drain and prince.
* **Reports that overstated.** Three replacements printed a speed-up of exactly
  2.00x that was the game's own time halved, and one verdict warned about faults
  that this tool's own addon sampler raises on purpose. Both are corrected.
* **Thread sampling stays off under Wine and Rosetta.** The watchdog samples the
  game's worker threads during a loading screen by suspending them one at a
  time. Under a translation layer it samples the main thread only.

### New (experimental, off by default)

* **Faster Loading Screens (File Reader Polling).** The game's file reader
  polls with a one millisecond sleep on both sides of every request, and in
  logged loading screens most of the main thread's time is that sleep. This
  waits a few tens of microseconds by spinning instead, for those loops only.
* **Skip Addon Garbage Collection During Loading.** An addon's
  `collectgarbage("collect")` during a loading screen returns at once while the
  scripting heap is under 600 MB. The game's normal incremental collection keeps
  running. The log counts every explicit collection and names the addon.
* **Addon Memory Figures Walk.** The per-addon memory totals the game rebuilds
  by walking a list are found from a cache.
* **Particle Quad Fill** now covers emitters with a second quad and the quad that
  faces along the particle's velocity, and checks the track evaluator against the
  game's own on every particle it answers. The two new quad paths were compared
  with the game's instructions over 1.4 billion generated cases and have not been
  run in a game.
* **Low-Fragmentation Heap** has a switch (on, as before) so that an allocator
  crash can be ruled in or out.

### Reports

* **Who puts the main thread to sleep.** The log counts the game's Sleep calls
  per caller and per loading screen.
* **A crash inside the Windows heap names the heap and lists its segments.**
* **The A/B report gives a standard error** from neighbouring stints paired, and
  says when the censuses that were switched on bias the bundle.
* **First-chance faults are split** into those raised inside this DLL and those
  raised elsewhere.

### After updating

Nothing to do. Press DEFAULT in the launcher once if you want the new defaults
written into your profile.

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

### If you want to measure something rather than report a bug

Comparing two sessions compares two different evenings. One session that
alternates a feature on and off compares the same zone, the same addons and the
same machine against itself.

Tick **A/B Test a Feature** on the DIAGNOSTICS tab, and tick the features you want
compared. The harness measures a feature that is switched on, because a feature
registers with it at the moment it installs. These are the ones it can measure:

> UI Layout Relink Shortcut, Model Draw Order Key Cache, Lua Pool Shortcuts,
> Table Lookup Dispatch (SSE2), Bone Rotation Maths (SSE2), Bone Rotation
> Unpack (SSE2), Bone Movement Track (SSE2), Bone Matrix Upload (SSE2),
> Visibility Box Test (SSE2), Box Overlap Test (SSE2), Line-of-Sight Box Test
> (SSE2), M2 Matrix SSE2, M2 Matrix Slot Copy (SSE2), Model Animation Stride,
> Fast SSE2 Memory Clear, SSE2 String Compare, Lua VM: stop the automatic GC,
> and Matrix-Vector SSE2.

Then play somewhere the processor is busy: a raid, a battleground, a crowded
city. Standing in a field the game waits on the graphics card, a saving inside
the frame changes no frame time, and the report says so instead of giving you
numbers.

Each subject is alternated on its own, four on/off pairs of twenty seconds, so
it spends about two minutes and forty seconds on one before moving to the next.
Play for longer than one pass over everything you ticked, and send the log. The
report says, per feature, when there were too few turns for the number to mean
anything.

To spend the whole session on one feature, open `WTF\wow_opt.ini` and put its
ini key under `[General]`:

```ini
AbTestSubject=LayoutRelinkFast
```

and make sure that feature is switched on too. The switch decides whether it
installs; this decides when it does its work. If the name is wrong the report
lists the ones it would have accepted.

`MatrixVectorSse2` is in the list to check the instrument: it is known to be
slower than the code it replaces, so if a report calls it faster, the
measurement is what is wrong.

For counters instead of a comparison - draw calls and how many of them could be
merged, how much Lua the game compiles twice, how long the horizon scans are,
how many tiny file writes there are, and where the main thread is during a
loading screen - press **LOGGING: FULL** and leave A/B Test off. Those cost
frames to collect, which is why they do not share a session with a test that
compares frame times. Twenty minutes of whatever you normally do is enough.
---

## Reviews

<details>
<summary><b>Click to expand community reviews and stability testers list</b></summary>

See what other players say: [Reviews and Testimonials](https://github.com/suprepupre/wow-optimize/discussions/10)

### Stability Testing Team


This project wouldn't exist without the community. Every crash report, every bisection test, every "hey this broke my addon" message directly shaped the release. 

Special thanks to:
Morbent, Darkmoore, Ethodeus, Billy Hoyle, tuan, NoGoodLife, feh_dois, David (`_oldq`), Keoo, UNOB, DarkRockDemon, Raymond, Vandal, Mantork, Falcon, Muus, szopachink17, Shandrax, pathetic-lynx, txtsd, Signalborn Soulweaver, Sicsoo, kojekude, Houmbro, Feles Noctis, kromvel85

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
- **kromvel85** (Roman) — WoW Circle with No Client Patches on: hour-long sessions
  in Dalaran with no crash, the first log from a server that removes players for
  patching the client, and the report that one core sat near full load there.
- **Signalborn Soulweaver**, **Morbent**, **Sicsoo** — early 3.18 logs.
- **Doc.James** — the zone-change stall, with three sessions that made it
  reproducible.
- **kojekude** — boss voice lines going missing in raids and dungeons while every
  other sound kept working, which turned out to be the sound coalescer returning
  "played fine" for sounds it had dropped.
- **nobus** — three sessions with warrior stance-swap crashes, carrying a second
  independent reproduction of a null-callback crash in the client's device
  callback list.
- **[biship](https://github.com/suprepupre/wow-optimize/issues/50)** — read the
  timing switch's code and reported that it gated twelve unrelated things and
  described none of them.
- **Feles Noctis** — QuestHelper printing `no nod :(` several times a minute,
  with the lines of its router that produced it. That was enough to trace it
  to this tool's `math.random` returning exactly 1.0, and from there to the
  unseeded generator behind it.

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
- **Reuse Compiled Scripts** *(off by default, experimental)* — keeps the compiled form of a Lua chunk and hands it back when the client compiles the same source under the same name again, so the parse does not run. The client still builds the function object, its environment and its addon ownership. Nothing is kept until a chunk has been compiled twice. `UI_Lua/LuaProtoCache`

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
- **UI Method Object Lookup** *(off by default, experimental)* — the object fetch that starts every one of 674 Lua calls into a frame (`sub_4A81B0`). Four script-engine calls and a push/pop replaced by direct reads; the addon-ownership propagation `lua_rawgeti` performs is reproduced rather than skipped, and anything unusual is handed back to the client. `UI_Lua/LuaThisFast`
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

Features that use worker threads and lock-free queues. Every one of them is off unless its switch is ticked in the launcher; the key is named at the end of each line.

- **Async spell data prefetching** - predictive spell data loading before cast completes, reduces spell cast lag, worker thread with lock-free queue (4096 entries) and cache (4096 entries) *(disabled — placeholder worker with no producers)*
- **Multithreaded addon dispatcher** - parallelizes addon OnUpdate callbacks across worker thread pool (4 threads), reduces main thread CPU in addon-heavy setups, batch processing with lock-free queue (8192 entries) *(disabled - unsynchronized writes to WoW game state)*
- **Predictive MPQ prefetching** - tracks zone transitions and predicts the next zone, prefetching textures, models and WMOs into the OS cache before a teleport. Worker thread pool with a lock-free queue. `General/TerrainPrefetch`, off by default
- **Multithreaded combat log parser** - offloads combat log parsing to worker thread, reduces main thread CPU in raids, lock-free queue with async processing *(disabled — placeholder worker with no producers)*
- **Sound prefetching** - predicts and prefetches sound files based on spell casts, zone transitions, combat state, worker thread pool (2 threads) with lock-free queue (1024 entries) *(disabled — placeholder worker with no producers)*
- **Async quest/achievement loading** - async quest log and achievement data loading, worker thread with lock-free queue (512 entries) *(disabled — placeholder worker with no producers)*
- **Multithreaded nameplate renderer** - offloads nameplate rendering to worker threads, reduces main thread CPU in 25-man raids, priority system (Target > Focus > Nearby > Distant) *(disabled - unsynchronized writes to WoW game state)*
- **Asynchronous Texture Hot-Swapping** — returns a placeholder texture from TexCreateBLP, loads the real BLP on a background thread, and swaps the Direct3D 9 texture pointer at a frame boundary. `Graphics_Sound/AsyncTexLoader`, off by default
- **RCU Client Object Manager Traverser** — replaces the linear linked-list entity walk with a flat mirror array rebuilt on link and unlink. `UI_Lua/RcuObjMgr`, off by default
- **Addon dispatcher** - event-driven addon update dispatch. `UI_Lua/AddonDispatcher`, off by default

### Other runtime optimizations
- **Spread Model Animation** *(off by default, experimental)* — posing model skeletons measured at 3.68 ms of a 24.5 ms frame in raid content. Below 96 models on screen nothing changes; above it each model's pose refreshes every 2nd to 4th frame, never slower than a quarter of the frame rate, and never before its first pose. Cannot make animations run slow: the client derives animation time from a clock rather than by counting frames. `Graphics_Sound/AnimLod`
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
- **SSE2 collision box test** *(off by default, experimental)* — the AABB outcode classification in `sub_7C7230`, 3.8% of main-thread time in a corrected profile. Six x87 comparisons per vertex become six packed comparisons per four vertices. Bit-exact: the bounds are plain floats with no arithmetic applied. `Graphics_Sound/CollisionOutcode`
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
- `wow_optimize.sym`

Then run `wow_optimize_launcher.exe` to configure settings, load/save profiles, and click **LAUNCH WOW**.

### Option B - Proxy load (Automatic)
Copy into your WoW folder:
- `version.dll`
- `wow_optimize.dll`
- `wow_optimize.sym`

Then launch WoW normally. The proxy DLL will automatically load the optimizer with default settings.

### Option C - Standalone Loader
Copy:
- `wow_optimize.dll`
- `wow_optimize.sym`
- your injector

Then inject after WoW starts.

---

## Compatibility & Setup

### Supported Clients & Private Servers
The optimization suite is compatible with any standard or customized WotLK 3.3.5a client (build 12340), including private servers using custom executables:
* **Warmane** (Icecrown, Lordaeron, Onyxia) — **STRICTLY PROHIBITED (WILL RESULT IN A PERMANENT BAN)**
* **Project Ascension** (supporting custom `Ascension.exe` launches)
* **Arden WoW** (supporting `Arden.exe` and `ArdenWoW.exe` launches). The client carries its own `Extensions.dll`, which already patches a few of the same client functions, so the matching optimizations here stand aside and the log lists them.
* **WoW Circle** - **On WoW Circle the DLL gets you disconnected** - Turning on **No Client Patches** in the launcher stops it, and
also turns every optimization off.   
Or use the `!LuaBoost` addon without the DLL.
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
  - 0.5 ms timer (switch: Ask Windows For A Half-Millisecond Timer)
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

The startup banner reports the exact build the log came from (`v3.19.3 (build abc1234)`), so please don't trim the first lines.

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

