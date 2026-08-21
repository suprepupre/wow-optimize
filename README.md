> [!CAUTION]
> **Do not use this on Warmane.** Their anti-cheat flags performance injectors and
> memory optimization tools as illegal software regardless of intent, and the
> result is a permanent ban on your account.

> [!CAUTION]
> **WoW Circle appears to disconnect you for having this loaded.** A tester gets
> kicked roughly every thirty minutes, reliably, including with every switch in
> the launcher turned off. Note that until 3.18.2 "every switch off" still left
> about 150 hooks in the client (see the release notes below), so that test did
> not mean what it looked like. It is worth re-running on 3.18.2 with the four
> **WoW.exe Hooks** groups turned off, which is the first build where the vanilla
> button is honest. If the kicks continue there, the DLL itself is being
> detected, and I am not going to add a workaround — evading a server's
> anti-cheat is not what this project is for.

# wow_optimize

Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)
Author: SUPREMATIST

**[Download Latest Pre-compiled Release](https://github.com/suprepupre/wow-optimize/releases/latest)**

wow_optimize improves WoW 3.3.5a at the engine and runtime level: memory allocation, Lua VM behavior, Lua library fast paths, timers, file I/O, networking, heap fragmentation, lock contention, the 16-year combat log bug fix, and other low-level bottlenecks.

The current public build is focused on real frametime stability, long-session smoothness, addon-heavy gameplay, and lower Lua/runtime overhead while keeping historically unsafe features disabled.

> Disclaimer: This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. Use at your own risk.

---

## Table of Contents
* [What's New in v3.19.0](#whats-new-in-v3190)
* [What's New in v3.18.2](#whats-new-in-v3182)
* [What's New in v3.18.1](#whats-new-in-v3181)
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

## What's New in v3.19.0

This one has three new optimizations in it, and three of the instruments this
project measures itself with turned out to be reporting confident wrong numbers.
The instruments are the bigger item. Thanks to [txtsd](https://github.com/txtsd),
who ran four long sessions on request — including the first one anybody has ever
sent in with the frame rate uncapped, which is what made the rest of this
possible.

### Four new features, all off by default

They are in the **Experimental** tab, and **Enable All deliberately skips them**.
Tick them yourself if you want to test them.

**Reuse Compiled Scripts** (`UI_Lua/LuaProtoCache`)

Interface scripts written inside XML templates get recompiled from scratch every
time a frame is built from that template. A counter added for this measured 68%
of every chunk the client compiled in a session as source it had already compiled
that session. This keeps the compiled form and hands it back on a repeat, so the
parse does not run.

The client still builds the function object itself, with its own environment and
its own addon ownership, so nothing about who is allowed to touch what is shared
between two uses. The obvious implementation — dump the bytecode and reload it —
does not work here and that was checked in the disassembler rather than assumed:
this client's parser has no bytecode-loading path at all, it was removed.

Two of txtsd's sessions ran it: 806 and 704 reuses, every one of them compared
against a fresh compile of the same source, none of them differing.

**UI Method Object Lookup** (`UI_Lua/LuaThisFast`)

Every call an addon makes into a frame — `SetText`, `GetWidth`, `Show`, 674 of
them — begins by fetching the frame object out of a table slot, and the game
spends four separate script-engine calls plus a push and a pop doing it. This
reads it directly.

The one thing those calls do besides fetch is carry addon ownership between
values, which is what decides whether a caller may touch a protected action.
That is reproduced exactly, not skipped. Anything out of the ordinary is handed
straight back to the game.

Three sessions: 86.6 million, 63.4 million and 31.4 million lookups. None handed
back, none disagreeing with the game's own answer.

**Spread Model Animation** (`Graphics_Sound/AnimLod`)

This one has the largest measured target behind it and **no field data at all
yet**.

Posing the skeletons of everything on screen is the single largest block of frame
time this client spends. Measured across txtsd's runs: 3.68 ms out of a 24.5 ms
frame during a VoA raid, across 114 models averaging 31 bones each. No single
function inside it is worth rewriting — the cost is spread across dozens — so the
only thing that reaches it is doing less of it.

Below 96 models on screen this changes nothing whatsoever. Above that, each model
has its pose refreshed every second to fourth frame instead of every frame, never
less often than a quarter of your frame rate, and a model is never skipped before
its first pose.

It cannot make animations run slow or drift. The client works out where an
animation should be from a clock each time rather than by counting frames, so a
skipped update only delays when a pose is refreshed. That was read out of the
function, not assumed, because if it had been wrong the feature would have been
useless. What you may notice in a packed city is slightly steppier movement on
some characters.

**Collision Box Test (SSE2)** (`Graphics_Sound/CollisionOutcode`)

Every line-of-sight check, every click on the world and every projectile path
makes the game sort the corners of a collision model against a box — six
comparisons per corner, one corner at a time on the old floating-point stack. A
corrected profile puts that one function at 3.8% of main-thread time, the largest
single one left outside model animation. This does four corners per instruction.

Unlike every other maths replacement in this tool, this one is **exact rather
than close**. The box bounds are read as plain numbers with no arithmetic applied
to them, and widening a float to a double is exact and order-preserving, so the
vector comparison gives the same answer as the game's for every possible input
including every NaN. There is no tolerance to pick and nothing to measure.

Verifying it needed a different approach, because the function appends to two
global lists and sets a flag that it also reads — so running it twice and
comparing does not work, the first run changes what the second one does. Instead
it predicts: it works out which corners are outside and which triangles the game
is about to queue, lets the game run and do the real work, then compares the two
lists. Three thousand of those have to match, on both the corner codes and the
queued triangles, before it takes over.

### The instruments were lying

None of these was found by reading code. Each was found because a number was
impossible.

**Every percentage the profiler printed was too small.** Sample counts came from
the last million entries in the ring buffer; the divisor was the number of
samples taken in the whole session. On a three-hour session that is 5.6× too
small. The top fifty entries summed to 12% of the profile — and since every
sample must land in some bucket, no program can have that shape.

What it produced was a profile with no hot spot anywhere in it, and that reading
was steering the work. Corrected, the same session reads: `AwesomeWotlkLib.dll`
9.7%, the model animation functions 7.0%, `d3d9.dll` 6.3%, this DLL's own modules
about 6%, particle vertex fill 2.5%, UI batch draw 2.3%.

The executing-versus-blocked split had the same defect and worse: the wait samples
came from the ring window while the divisor came from the session, so every long
session reported itself as 99% executing whatever it was actually doing.

**The animation counter claimed 72 ms of animation inside a 53 ms frame.** It was
closing its frame on the hooked `Sleep` tick, which a CPU-bound client stops
running, so everything counted between two sleeps was charged to a single frame.
The number it reported tracked how CPU-bound the session was rather than how many
models were on screen — 860, 906, 1092, 1909 models per frame as the main thread
went 85.9%, 91.3%, 95.5%, 99.0% executing.

**The feature summary called two working features dead.** It listed `CrtFreeHook`
under "enabled but never ran — a zero here means the code path was not reached",
forty lines below that same feature reporting 2,858,166 deallocations served.
Both it and the SSE2 matrix-vector hook had registered a counter and deliberately
never incremented it, for a good reason — the counter cost a real fraction of the
work it was counting — and one of them discarded the counter handle at
registration so nothing could have incremented it even by accident. Both now
sample one call in 8192. A summary that calls a working default-on feature dead
invites the next person to go and fix what is not broken.

### Also in this release

**The vsync detector told a tester to throw away a good session.** txtsd ran
uncapped, got 96.5% executing, and then a warning directly underneath saying the
session was capped and no conclusion should be drawn from it. It was testing the
median frame time alone, and 20.00 ms is the 50 Hz interval. The client was
simply slow at that moment: the distribution was 23.10 ms at the median against
62.20 ms at the 95th. A frame limiter has no tail — it holds every frame at the
interval — so the spread is what separates the two cases, and the median cannot
say it alone.

**The DBC row cache was moving 1360 bytes per hit to deliver 680.** Its sequence
lock read the row into a temporary, verified, then copied the temporary out. At
9,869,554 hits in one session that spare copy was about 6.7 GB of `memcpy` on the
main thread. The payload now goes straight to the caller and the sequence is
verified afterwards, which is safe only because a failed verification falls
through to the client's own routine and that fills the same buffer completely.

**A framework for throttling off-screen animation had been sitting in the source
with nothing calling it** — a tier function, a skip schedule and two counters,
none of them reachable, under an address nothing had verified, while startup
logged that the throttle was configured. Removed, and what had been learned about
the real function was left in its place.

**`Hot_857CA0`, which has appeared in every profile this project ever collected,
is `luaV_execute`** — the Lua bytecode interpreter. The client carries two copies
of it and picks between them on the script-profiling flag. The copy that shows up
is the one behind the "profiling off" branch, so the client is already taking the
cheap path.

### Six things removed that were never running

Two modules turned up by accident this week that announced a feature and
implemented none of it. A scan of all 208 source files for the same shape — a
startup line saying ACTIVE or Initialized, with no hook and no patch anywhere in
the file — found four more, plus one dead subsystem inside a module that is
otherwise alive:

* an event-name hash cache that memset a 512-slot table at startup, logged it,
  and never touched it again — its one function had no caller at all
* a second event-name cache, the same shape, 256 slots
* a CDataStore batch module whose own comment read "For now, initialize counters
  only", and whose Install was called from nowhere
* a frame-script throttle with a real body and a real entry point that nothing
  ever called
* a sound guard that registered a feature name another module had already
  registered, one line after that module installed the hook it claimed
* a combat-text batch flushed every frame, whose producer index nothing ever
  incremented — and whose flush would have done nothing anyway, since the
  dispatch was a TODO comment

Four of those had a switch or a startup line advertising them, and two were gated
on an unrelated feature's switch. About 550 lines, and six fewer log lines
claiming something is running.

### Nine counters that cost more than the thing they were counting

With the profiler's numbers corrected, this tool's own modules add up to about 6%
of main-thread execution — and some of that turned out to be the counting rather
than the work.

The D3D9 state cache filters redundant render-state changes: compare two numbers,
return, do not go to the driver. Six of its counters were incremented with an
atomic add on that exact branch — the fast one, the one the whole feature exists
to reach. On 32-bit x86 that is a locked instruction: tens of cycles and a bus
barrier, on a path whose useful work is one comparison, called thousands of times
a frame.

The script handler cache was worse. Its two counters were 64-bit atomics, and
there is no 64-bit atomic add on 32-bit x86, so each one compiled to a locked
retry loop — one on every call and another on every hit, in a module whose entire
purpose is to be the fast replacement for a chain of string comparisons. The
third was on the particle spawn path, counting spawns in the one situation the
feature exists for.

All nine are plain counters now, which is what two comments already in this
codebase said they should be. The numbers they report are a lower bound and now
say so.

### Where the time actually goes now

The largest single entry in a corrected profile is `AwesomeWotlkLib.dll` at 9.7%
of main-thread execution — larger than model animation, larger than d3d9. It used
to print as one line with nothing inside it. The profiler now breaks down the
hottest module it did not write, the same way it already did for wow.exe and for
this DLL, so the next log will say which part of it is expensive.

### What this release does not claim

None of the four new features is measured as a frame-rate gain. The sizes of what
they target are measured, and correctness is verified — two of them across
millions of operations in the field, the other two by construction and against
the client's own output — but no before-and-after frame time exists for any of
them yet. If you run them, the log lines will tell you what they did.

---

## What's New in v3.18.2

Mostly the same story as 3.18.1, told again: most of what is below is something
this project was already shipping that turned out not to be doing what its own
description said. Thanks to **Doc.James**, [txtsd](https://github.com/txtsd),
**prince**, **kojekude**, **nobus**, [biship](https://github.com/suprepupre/wow-optimize/issues/50),
**Sicsoo**, **Signalborn Soulweaver** and **Morbent** — every fixed item here
came out of a log somebody sent in, or out of checking a claim this repo was
making about itself.

**The loading screen fix**

Doc.James reported his first zone change of a session taking two to three seconds
longer than normal, with the loading bar never appearing. Three sessions made it
reproducible, and one switch made it go away.

The lock-free defragmenter was running a full forced heap collection **once a
second for the entire duration of every loading screen** — which is the worst
possible moment for it, because that is when the main thread is allocating harder
than at any other time. From his own logs, same machine, that switch the only
difference:

```
DefragLf=1    184 MB loaded in 10171 ms  =  18 MB/s
DefragLf=0    113 MB loaded in  1222 ms  =  94 MB/s
```

Disk accounted for 107 ms of those 10171. A module named after making loading
screens better was making them five times slower. It now waits the loading screen
out and collects once afterwards, which is when the transient allocations are
actually free to return.

Not all of what he saw was this. A single ~2.15 second frame at the start of each
zone change survives with the switch off, in the same place both times, with no
hook of ours running inside it. That one is the client's own teardown.

**Faster, and now provably identical to the client**

Four routines on the per-bone animation path were replaced. All four verify
themselves against the client's own function at startup and refuse to install if
a single bit differs:

- Quaternion to rotation matrix — **1.40x**. Runs once per animated bone per frame.
- Quaternion normalize — **2.01x**, and now on by default. It was off because the
  old version sat a float ULP away from the client on 1,535,779 of two million
  test quaternions.
- Both vector normalises — **2.25x**.
- `strncmp` — **3.88x** on long strings, 1.33x on short ones.

The reason those first three were wrong before is worth stating, because it
invalidated every "sub-ULP" comment in this repo: the client is not doing single-
precision arithmetic. The CRT leaves x87 at 53-bit, so the engine accumulates in
double and narrows only when it stores a float. Anything written in packed single
disagrees with it on most inputs. Rewritten in packed double with the original's
summation order preserved, all four are bit-identical.

**Boss voice lines going missing in raids**

Reported by **kojekude**: no boss voice before or during fights, every other sound
working normally. The Sound Coalescer did it, and it should never have shipped in
that shape.

It dropped a sound whose id matched the previous one within 16 ms, keeping a
single global "last id". Three things are wrong with that, all of them visible in
the target's own disassembly:

- `sub_4C6A40` is `PlaySoundKit` out of `SoundInterface2.cpp`. Its return value
  is an **error code** — `0` means the sound started. Coalescing returned `0` for
  a sound that never reached the mixer, so nothing upstream could notice.
- The engine already suppresses duplicate plays, using information we don't have:
  sounds flagged `0x20` are registered in a list when they start, and replaying
  one that is still in it returns `15`. Everything else is *meant* to overlap. We
  applied one blanket rule to all of them.
- `GetTickCount` moves in ~15.6 ms steps, so "less than 16 ms apart" was really
  "zero or one ticks apart" — anywhere between an instant and a frame, depending
  on where the plays fell against a timer we don't control.

Removed rather than repaired. The engine's own rule is better than one
reconstructed from outside it, and it was already running underneath ours.

**The crash where the game executes address zero**

Reported independently by **prince** and by **nobus**, who hit it swapping
warrior stances; a third tester's alt-tab crashes fit the same path. Both logs
land on the same instruction:

```
0xC0000005 (ACCESS_VIOLATION) at 0x00000000
[ESP+0x00] = 0x006A2B69   (WoW.exe+0x2A2B69)
[ESP+0x3C] = 0x00690160   (WoW.exe+0x290160)
```

`sub_690150` is device teardown. It calls `sub_6A2AA0`, which walks a list of
registered callbacks and tells each one the graphics device is going away. The
callback lives in the list node itself, at `+0x34`, and the client null-checks
the neighbouring field at `+0x38` twice while never checking `+0x34` at all. A
node with an empty callback slot takes the whole process down.

The guard walks that list read-only before the client does, applying the
client's own two visit conditions. On a healthy client it finds nothing and
hands straight over — one pointer walk per device teardown, not per frame, and
no behaviour change whatsoever. Only when it finds a node that is certain to
crash does it run the loop itself, transcribed instruction by instruction from
the original, skipping exactly one thing: the call through the null pointer.
Everything else the client writes, it writes, in the same order.

It does not try to repair the node. Writing a substitute callback in, or zeroing
a field so the client skips the entry, would both mean writing into a client
structure on a guess — the mistake that produced the layout-relink crash removed
below. The node is written to your log in full instead, which is the first time
anyone will have seen what is in one.

**Two diagnostics that cried wolf**

- **Every log opened with `!!! DISCONNECT !!!`.** Logging in uses two
  connections — the client talks to the logon server, gets its realm list, and
  closes that socket to go and talk to the world server. That close was reported
  as a disconnect on every launch on every machine. One tester's log shows the
  banner at 19:44:31 followed by 593,038 receives over the next twenty-four
  minutes. Worse, the report fires once per session, so the login socket used it
  up and a real mid-raid drop later had nothing left to say. The counters now
  follow whichever socket is actually carrying traffic, only that socket can
  report, and a clean client-side close has to have been a real session before it
  earns a banner.
- **A 179-second "stutter".** Nothing stalled for three minutes; the window was
  alt-tabbed, so `Present` was not called and the gap between two of them was
  measured as one frame. Each of those burned one of the twelve full snapshots
  this build is allowed to write, on an idle process. Gaps over thirty seconds
  are now counted separately and named for what they are.

**"Disable All (vanilla)" did not mean vanilla**

Found by being asked the obvious question about the WoW Circle kicks: *are you
sure nothing is still running with everything switched off?* No, as it turns out.

A tester's log with **every** boolean setting reading 0 still contained:

```
[EXTENDED]  34/40  EXTENDED performance features installed
[SUBSYSTEM] 98/100 SUBSYSTEM performance features installed
--- WoW.exe Optimization Hooks (20 hooks) ---
--- WoW.exe Performance Hooks (20 hooks) ---
```

Four batches — 20, 20, 40 and 100 hooks into WoW's own code — were installed
unconditionally. Not one of those four source files contains a single reference
to any setting. So "Disable All (vanilla)" left roughly 150 detours in the
client, and every report of the form "I turned everything off and it still
happens" was measuring something other than what the person thought.

All four now have a switch. They **default on**, because they have been running
for everyone since they were written and silently removing them on upgrade is
the mistake 3.18.1 already made once. Turning them off is what makes the vanilla
button honest, and they are the first thing to try when you are working out
whether this DLL is behind a problem at all.

**The Lua suite can now be bisected**

**nobus** reported that the Lua C-API Inline Cache Suite corrupts ElvUI: addon
names come out wrong in the addon list, the options panel reports itself
missing, and a `/reload` drops you to the default Blizzard UI. Neither of us
could narrow it, because that one checkbox gated **fifty-five separate hooks**.
That is the same fault as #50, several times over.

It is now four groups, all on by default so the master switch behaves exactly as
it did:

- **Table & index caches** — the global, table, index and `luaH_getstr` caches
  and the VM table indexing path. First to suspect: these are the hooks that can
  return a value for the wrong key, which is what a wrong addon name is.
- **String & buffer paths** — `pushstring`, `pushfstring`, the buffer helpers,
  `tolstring`, `loadstring`, the pattern cache.
- **Setters & object creation** — everything that writes into Lua state.
- **Accessors, arg checks & debug** — mostly read-only, least likely.

Turn the suite on, then turn one group off at a time. Two sessions should find
it. The suite stays off by default.

While looking for the cause I checked the string interning fast path against the
client's own `luaS_newlstr` instruction by instruction — bucket index, length
test, content compare, and the dead-string resurrect — and it is faithful,
including the `marked ^= 3` on an other-white hit. So that one is not the
culprit, which is worth writing down so nobody re-checks it.

**Things that were not doing their job**

- **"High-Precision Timing Fix" was neither.** Reported by
  [biship](https://github.com/suprepupre/wow-optimize/issues/50), who read the
  code and was right about all of it. One checkbox gated twelve unrelated
  installs, its description promised timer work it did not do, and the three
  hooks it named — `GetTickCount`, `timeGetTime` and the QPC coalescing cache —
  are compiled out of the build entirely, after they were found to cause random
  stutters under DXVK. What actually sat behind the switch was eight Windows API
  lookup caches. So a player chasing a timing bug turned off eight caches
  instead, and a player wanting smoothness turned eight caches on. It is now
  called **Windows API Caches**, the description says what it gates, and the log
  states plainly that the timer hooks are compiled out and this switch does not
  reach them. Also gone: an `InstallTimingFix()` whose entire body logged
  "Hook skipped. Using console override only" — there was no console override
  either, and it was called unconditionally, ignoring the setting.
- **A second switch of the same kind, found by looking for one.** "Saved
  Variables Pretokenize" installed the entire Win32 file-hook suite, a stream
  cache, a packet batcher and a stream-buffer fast path. Every one of those was
  dead: the pretokenizer's six entry points were each `return false`, the stream
  cache logged "Disabled" and returned, the batcher only initialised counters,
  and the stream-buffer path aimed at the same two addresses as the packet
  accessors and always lost the race. Two of those dead calls sat on the
  `ReadFile` and `CreateFile` hot paths, running on every file the client
  touched. What was actually doing work behind the switch was the six CDataStore
  packet accessors, about 4,000 call sites, so it is now called **Network Packet
  Reader Fast Paths** and installs only those. The file hooks it forced on are
  back to being gated by the cache that uses them.
- **Two launcher switches did nothing.** Asynchronous Texture Loader and Mipmap
  Bias Governor were written to one section of `wow_opt.ini` and read from
  another, so no setting of either ever reached the DLL. Both now work, both are
  marked experimental, and both stay off unless you go and turn them on — nobody
  has ever run them, so there is no log anywhere saying what they do.
- **Fifteen build flags said "disabled" and disabled nothing.** Each named a
  module that had already been deleted. One of them carried a HARD-DISABLED
  notice about a use-after-free in code that no longer existed. A flag that reads
  1 and decides nothing answers a bisection question falsely, which is worse than
  having no flag.
- The DBC lookup cache was **slower than the function it caches**, about half the
  time — on the client's memcpy path there is nothing for a cache to win. It now
  steps aside there.
- The render null guard could silently drop a model's draw parameters.
- The D3D9 device vtable was left pointing into this DLL after unload.
- Two of our own modules aimed at the same address, and the loser said nothing.
  MinHook knows the difference between "somebody else got here first" and "one of
  ours already owns this"; the log now does too.
- SimdMathFast installed nothing and reported itself active.
- Texture Smart Unload Delay now measures its own reuse rate and switches itself
  off below one percent. Two testers measured 0.4% and 0.2%. It does not pay.
- The addon profiler raised a dialog box and collected nothing at all.
- MinHook's trampolines are no longer freed while WoW's threads may still be
  inside them on the way out.

**Removed**

The UI layout relink shortcut, which corrupted the client's layout list and
crashed on login — `off_AC101C` and `dword_AC1020` are one link pair, and the
client writes to the second during an insert. The shadow buffer experiment, which
a tester confirmed does not stop the flicker in Dalaran. A trig lookup table, two
dead SSE2 helpers, three features that were never installed, and two empty
headers.

**New diagnostics**

- **Lua compile census** (on by default, silent on a healthy client). It answers
  a question nothing could answer before: 88% of everything the client compiles
  at runtime is source it already compiled this session — 332 MB of it in one
  measured session. If your log starts naming something with a five-figure count,
  that is the addon to update or drop.
- **Per-addon CPU profiler** (opt-in). Switches on the script profiler the client
  has always had and nothing ever enabled, and writes a ranked table to your log.
- **Shadow state probe** (opt-in, read-only). For the shadow flicker some people
  see below the highest quality step. That is not caused by this DLL — a tester
  reproduced it with every feature here off and without DXVK — but nobody had
  ever looked at what the game itself is doing when it happens.
- The sampling profiler was attributing up to 4 KB of code to whichever symbol
  came before it. It now reports `name+0xNNN`.

---

## What's New in v3.18.1

A fix release. Thanks to **prince**, [txtsd](https://github.com/txtsd),
**Signalborn Soulweaver**, **Sicsoo**, **Morbent** and **Doc.James** for the logs.

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

