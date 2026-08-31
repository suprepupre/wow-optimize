> [!CAUTION]
> **Do not use this on Warmane.** Their anti-cheat flags performance injectors and
> memory optimization tools as illegal software regardless of intent, and the
> result is a permanent ban on your account.

> [!WARNING]
> **On WoWCircle you will be disconnected.** Not banned - dropped, several times a
> session, in raids and battlegrounds. It is this DLL: two players independently
> turned on **No Client Patches** in the launcher and the disconnects stopped
> entirely, and both were dropped again with it off. That option stops anything
> being written into WoW.exe, which also turns every optimization off, so it is a
> trade rather than a fix. See
> [WoWCircle disconnects](#wowcircle-disconnects) below.

# wow_optimize

Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)
Author: SUPREMATIST

**[Download Latest Pre-compiled Release](https://github.com/suprepupre/wow-optimize/releases/latest)**

wow_optimize improves WoW 3.3.5a at the engine and runtime level: memory allocation, Lua VM behavior, Lua library fast paths, timers, file I/O, networking, heap fragmentation, lock contention, the 16-year combat log bug fix, and other low-level bottlenecks.

The current public build is focused on real frametime stability, long-session smoothness, addon-heavy gameplay, and lower Lua/runtime overhead while keeping historically unsafe features disabled.

> Disclaimer: This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. Use at your own risk.

---

## Table of Contents
* [What's New in v3.19.1](#whats-new-in-v3191)
  * [WoWCircle disconnects](#wowcircle-disconnects)
* [What's New in v3.19.0](#whats-new-in-v3190)
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

## What's New in v3.19.1

A bugfix release. Some of these were reported by testers and reproduced in their
logs; the rest came from reading our own numbers and finding they were wrong.

### WoWCircle disconnects

Reported by [Flokj](https://github.com/Flokj): dropped from the server twice in a
Halion 25 heroic raid, then again in a battleground, then again three seconds
after leaving a cross-realm battleground.

The receive path is watched, so the end of a connection can be described rather
than guessed at. Five of his drops were measured and all five are the same event:
`recv` returns 0, meaning the server sent FIN. Not `WSAECONNRESET`, which is what
a route failure looks like from here, and not a timeout. The client was healthy
at each of those instants - the last byte had arrived 0 to 2156 ms earlier, the
main thread had ticked 0 to 31 ms earlier, and the freeze watchdog stayed silent
at its 10 second threshold through every session. Time from connecting to being
dropped was 76.4, 47.6, 12.5 and 17.7 minutes, so there was no period in it
either. The battleground one came 4.8 seconds after the loading screen finished,
on a connection that had been open the whole session, so it was not a server
handoff.

That is a server closing a working connection, and from inside the process there
is no way to tell a routine kick from a server noticing the client's code has
been modified. So this release added a way to ask: **No Client Patches**, in the
launcher, which writes nothing at all into the WoW.exe image. Every optimization
in this project is a patch, so they all stop; the disconnect watch, the crash
reporter and the frame timing keep running because they live in ws2_32, kernel32
and d3d9 rather than in the client.

Flokj ran two hours and sixteen minutes with it on: one connection, 1,941,806
packets received, 49.4 MB, and no server-side close in the whole log. asslol
reported the same result independently. Both are dropped again with it off.

For contrast, four sessions from a tester on a different server contain zero
server-side closes at all.

About 110 entry points in WoW.exe are rewritten to begin with a jump that is not
in the file on disk. That is what the optimizations are, and it is also what a
memory scan looks for.

So on WoWCircle the options are the switch - keep your connection, lose the
performance work - or the `!LuaBoost` addon on its own without the DLL. There is
deliberately no attempt here to find which of the patches the server's checks do
not cover; that would be working around a server's protection rather than fixing
anything.

### The glowing models

Reported by [txtsd](https://github.com/txtsd): characters glowing, sometimes only
the shoulder pads and the weapon, then snapping back. Turning Spread Model
Animation off stopped it.

The function that feature skips does not only pose bone skeletons. Its last
instructions also animate materials, writing colour, alpha and emissive, and then
walk the model's attachment list and animate each attached model. Weapons and
shoulder pads are attached models, so skipping a character froze its colour
tracks and skipped its whole attached chain with it.

It now refuses to skip any model where either of those would have run. On the
first session measured with the fix that turned out to be 94% of models, so the
feature currently skips almost nothing. The report says so rather than implying
a saving, and says which of the two halves is responsible.

### A crash, and the same defect caught in another log

One tester's dump ends inside the game's own error formatter, reading a line
number out of a compiled script object that had already been freed. Another
tester's log has the same defect caught earlier and more gently: Reuse Compiled
Scripts noticed a cached chunk no longer matched a fresh compile and switched
itself off.

The cache decided a new Lua state had started by comparing one address. The game
runs its own memory pool for Lua, so a new state is routinely allocated where the
old one was and the comparison saw nothing. In the crashing session the tool's
own log recorded six state changes and the cache reported two.

It now hears about every state change directly from the part of the tool that
detects them, and each kept script carries three fields read when it was stored
and checked again before it is handed back.

### The tool could be loaded into its own launcher

`version.dll` sits in the same folder as the launcher and the loader, and Windows
resolves it out of the application directory for anything that runs there. The
loader thread called LoadLibrary without ever asking which process it was in, so
a DLL that patches addresses inside the game could end up inside the launcher.
It checks now.

### Settings that did not do what they said

* **Lua VM: stop the automatic GC** was read, written to the file and shown in
  the launcher, and gated nothing at all. The collector was driven entirely by
  the Adaptive GC Governor tickbox. Both now mean what they say.
* **UI Frame Batch** had no launcher entry at all and could only be changed by
  editing the ini by hand. It also looked like it controlled four things and
  controlled two: the other two have been compiled out of the build for as long
  as anyone can tell. Split into **Cache Script Handlers** and **Unit API Fast
  Path**, each inheriting the old setting so nothing changes for anyone, which
  makes the flickering reported in issue #36 answerable in two runs instead of
  never.
* **Terrain Read-Ahead** was compiled out of every build while appearing to be a
  setting, and read its position from an address the game never writes. Both
  fixed. It is off by default and what it does when it works has still never
  been tested by anyone.

### Numbers that were not true

Six of these, and every one of them was in logs people have been reading.

* **"98/100 SUBSYSTEM performance features installed"** and **"34/40 EXTENDED
  performance features installed"**. Three and five were installed. A loop added
  the rest to the count so the line would say so, beside 127 empty functions that
  nothing called. All gone.
* **The CVar watchdog reported a corrupted client in every log ever collected**,
  on sessions that then played for five hours without a fault. Two of its entries
  did not describe what they pointed at and two more treated a value of zero as
  damage when the game simply had not filled that global in yet.
* **Three modules read a world position from an address the game never writes.**
  Every model distance the animation census has ever printed is a distance from
  the map origin, and the terrain read-ahead silently did nothing on every frame
  of every session because of it. The real one is the point the game itself
  streams terrain around.
* **The feature summary mixed three different units in one column.** Features on
  hot paths report one hit per few thousand calls, and those counts sat beside
  ones that count every call. One entry read as the smallest of five and is
  really the largest by an order of magnitude.
* **A short session printed one report, taken thirty seconds in.** The periodic
  dump fires at 30 seconds and then every 300, and nothing but the frame times
  was printed at exit, so a five-minute session reporting a visual defect
  produced no evidence covering it. Every session ends with a full report now.
* **The freeze watchdog dismissed the very stall people report.** It captures
  where the main thread is stuck only past 45 seconds, so blocks of eleven to
  fourteen seconds during a load were noted on one line and never diagnosed.
  Eight seconds is enough now, once per stall.

### Faster

* **Roughly 120 locked instructions removed from hot paths.** Every call to
  every hooked game function was paying one or two of them to keep a counter.
  On 32-bit that is a locked read-modify-write, and they sat on the CRT string
  functions, the Direct3D state hooks, the frustum test, the clock read and the
  most expensive function in the whole client. The counts they keep are lower
  bounds now and the reports say so.
* **The bone rotation blend is exact.** It shipped approximate, with a measured
  worst error of 2.98e-07 and only 6.5% of results identical to the game's. The
  vector unit has double precision as well as single, and double is exactly what
  the game's floating point stack carries, so the same operations in the same
  order reproduce it perfectly. Measured over three million interpolations:
  100.0000% identical, worst difference zero. The in-game check compares bit
  patterns with no tolerance and switches the feature off on the first
  difference.
* **The point transform is exact too**, and was two millimetres out. Its comment
  claimed otherwise; the claim had never been measured.

### New, all off by default

* **Spread Model Animation** now decides by distance from the camera rather than
  by how crowded the scene is, after proving at runtime which field carries the
  position. Models within 40 yards are never throttled.
* **Object Tick Prefetch** — the game walks a list of objects every frame and
  pokes each one, and the two fields it touches are in different cache lines.
  1.39% of main-thread time in a measured session, spent waiting. It changes
  nothing the game computes and refuses to install unless the function is
  byte-for-byte the one it was written against.
* **Table Emptiness Census** and **Leave Lua Garbage Collection Alone** are
  diagnostics, not optimizations. Garbage collection is the most expensive Lua
  work in every profile taken here, ahead of running scripts, and neither how
  much of it is wasted nor how much of it this tool causes has ever been
  measured. These two answer that.

### Still not claimed

No feature here has a measured frame-rate gain. The sizes of what they target
are measured and their correctness is verified, two of them now bit for bit
against the game's own answer, but no before-and-after frame time exists yet.

---

## What's New in v3.19.0

Thanks to [txtsd](https://github.com/txtsd) for four long sessions, including the
first one anyone has sent in with the frame rate uncapped. Every number below
comes from those logs.

### Four new features, all off by default

They sit in the **Experimental** tab and **Enable All skips them**. Tick them
yourself.

**Reuse Compiled Scripts** — `UI_Lua/LuaProtoCache`

Interface scripts written inside XML templates are recompiled every time a frame
is built from that template. Measured: 68% of every chunk the client compiled in
a session was source it had already compiled. This keeps the compiled form and
hands it back, so the parse does not run. The client still builds the function
object, its environment and its addon ownership, so nothing about permissions is
shared between two uses.

Field: 806 and 704 reuses across two sessions, each compared against a fresh
compile, none differing.

**UI Method Object Lookup** — `UI_Lua/LuaThisFast`

Every call an addon makes into a frame (`SetText`, `GetWidth`, and 672 others)
starts by fetching the frame object out of a table slot through four script-engine
calls. This reads it directly. The addon-ownership propagation those calls perform
is reproduced, not skipped — it decides what may touch protected actions.

Field: 86.6M, 63.4M and 31.4M lookups across three sessions. None handed back,
none disagreeing.

**Spread Model Animation** — `Graphics_Sound/AnimLod`

Posing model skeletons is the largest single block of frame time: 3.68 ms of a
24.5 ms frame in a VoA raid, 114 models averaging 31 bones. No one function
inside it is worth rewriting, so the only way to reach it is to do less.

Below 96 models on screen nothing changes. Above that each model's pose refreshes
every 2nd–4th frame, never slower than a quarter of your frame rate, and never
before its first pose. It cannot make animations run slow: the client derives
animation time from a clock, not by counting frames. In a packed city you may
notice steppier movement on some characters.

**Collision Box Test (SSE2)** — `Graphics_Sound/CollisionOutcode`

Line-of-sight checks, world clicks and projectile paths sort a collision model's
corners against a box — six comparisons per corner on the x87 stack, 3.8% of
main-thread time. This does four corners per instruction.

Unlike the other maths replacements here it is **exact, not approximate**: the
bounds are plain floats with no arithmetic applied, so the vector comparison
answers identically for every input including NaN. Before taking over it predicts
which corners are outside and which triangles the game will queue, lets the game
run, and compares — 3000 matches required.

### The measurement tools were wrong

**Every percentage the profiler printed was 5.6× too small** on a three-hour
session: counts came from the last million ring entries, the divisor was the whole
session. The top fifty summed to 12% of a profile, which no program can do. It
produced a profile with no hot spot in it, and that reading was steering the work.
Corrected: `AwesomeWotlkLib.dll` 9.7%, model animation 7.0%, `d3d9.dll` 6.3%, this
DLL's own modules ~6%, particle vertex fill 2.5%, UI batch draw 2.3%. The
executing/blocked split had the same defect and pinned every long session near
99% executing whatever it was doing.

**The animation counter claimed 72 ms of animation inside a 53 ms frame.** It
closed its frame on the hooked `Sleep` tick, which a CPU-bound client stops
running, so many frames were charged to one.

**The feature summary listed two working default-on features as never having
run**, forty lines below those features reporting their own work.

**The vsync detector called an uncapped session capped** and told a tester to
redo it. It tested the median frame time alone; a limiter has no tail, so the
spread is what separates the two cases.

### Removed and cheapened

Six things that were never running: two event-name caches that logged themselves
at startup and were never read, a CDataStore batch whose Install was called from
nowhere, a frame-script throttle whose entry point nothing called, a sound guard
that re-registered another module's hook, and a combat-text batch flushed every
frame whose producer index nothing incremented. About 550 lines, and six log
lines that claimed something was running.

Nine counters on hot paths were atomic. On 32-bit x86 that is a locked
instruction — and in the D3D9 state cache they sat on the skip branch, the fast
one the whole feature exists to reach. The 64-bit ones in the script handler cache
compiled to a locked retry loop. All are plain counters now; the numbers they
report are a lower bound.

The DBC row cache moved 1360 bytes per hit to deliver 680 — about 6.7 GB of spare
`memcpy` in one session. The payload now goes straight to the caller.

The quality governor could change settings the client only applies later, which
queues a change the player never asked for and leaves the governor unable to
measure what it did. It now reads each setting's flags and refuses those.

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
- **SSE2 collision box test** *(off by default, experimental)* — the AABB outcode classification in `sub_7C7230`, 3.8% of main-thread time in a corrected profile. Six x87 comparisons per vertex become six packed comparisons per four vertices. Bit-exact, not approximate: the bounds are plain floats with no arithmetic applied. `Graphics_Sound/CollisionOutcode`
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

The startup banner reports the exact build the log came from (`v3.19.0 (build abc1234)`), so please don't trim the first lines.

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

