# 🚀 wow_optimize v1.6.0 BY SUPREMATIST

**Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)**

Replaces WoW's ancient memory allocator, optimizes I/O, network, timers, threading, frame pacing, Lua VM, and combat log buffer — all through a single injectable DLL.

> ⚠️ **Disclaimer:** This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. **No ban has been reported**, but **use at your own risk.** The author is not responsible for any consequences including but not limited to account suspensions.

---

## ✨ Features

| # | Feature | What It Does |
|---|---------|--------------|
| 1 | **mimalloc Allocator** | Replaces msvcr80/ucrtbase `malloc`/`free` with Microsoft's modern allocator |
| 2 | **Lua VM Allocator** | Replaces WoW's internal Lua pool allocator with mimalloc |
| 3 | **Sleep Hook** | Precise frame pacing via QPC busy-wait (eliminates Sleep jitter) |
| 4 | **Full Network Stack** | TCP_NODELAY + Immediate ACK + QoS + Buffer tuning + Fast Keepalive |
| 5 | **GetTickCount Hook** | QPC-based microsecond precision (better internal timers) |
| 6 | **CriticalSection Spin** | Adds spin count to all locks (fewer context switches) |
| 7 | **ReadFile Cache** | 64KB read-ahead cache for MPQ files (faster loading) |
| 8 | **CreateFile Hints** | Sequential scan flags for MPQ (OS prefetch optimization) |
| 9 | **CloseHandle Hook** | Cache invalidation on file close (prevents stale data) |
| 10 | **Timer Resolution** | 0.5ms system timer via NtSetTimerResolution |
| 11 | **Thread Affinity** | Pins main thread to optimal core (stable L1/L2 cache) |
| 12 | **Working Set** | Locks 256MB–2GB in RAM (prevents page-outs) |
| 13 | **Process Priority** | Above Normal + disabled priority boost |
| 14 | **FPS Cap Removal** | Raises hardcoded 200 FPS limit to 999 |
| 15 | **Lua VM GC Optimizer** | 4-tier per-frame GC stepping from C (loading/combat/idle/normal) |
| 16 | **Combat Log Optimizer** | Prevents combat log data loss in raids (retention + periodic cleanup) |

---

## 🆕 What's New in v1.6.0

### Full Network Latency Stack (NEW)
Complete TCP optimization for minimum latency:

| Optimization | What It Does | Impact |
|-------------|--------------|--------|
| **SIO_TCP_SET_ACK_FREQUENCY=1** | Forces Windows to ACK every TCP packet immediately instead of waiting 200ms | **−40 to −200ms perceived latency** |
| **IP_TOS LOWDELAY (0x10)** | Marks packets as low-delay interactive traffic for QoS-aware routers | Prioritized over bulk traffic |
| **SO_RCVBUF 64KB** | Increases receive buffer from Windows default 8KB | Prevents TCP window scaling bottleneck |
| **TCP Keepalive 10s/1s** | Detects dead connections in ~20 sec instead of 2 hours | No more hanging on silent disconnects |
| **Deferred Socket Optimization** | Hooks `send()` to apply settings after async TCP handshake completes | All optimizations actually work now |

### Performance Improvements
| Improvement | Details |
|------------|---------|
| **O(1) MPQ Handle Lookup** | Replaced O(n) linear scan (256 elements) with hash table for ReadFile cache checks |
| **SRWLock for ReadFile Cache** | Replaced CriticalSection with SRWLock — concurrent reads on cache hits |
| **Smarter PreciseSleep** | Uses `SwitchToThread()` for 0.3–2ms range — 15-30% less idle CPU usage |
| **Lua State Read Throttle** | Reduced DLL→Lua API calls from ~900/sec to ~124/sec |

### Crash Fixes
| Fix | Details |
|-----|---------|
| **Entry Pool Removed** | Pre-allocated combat log entries caused Error #132 when engine tried to `SMemFree` mimalloc-owned pointers during logout/AFK kick/arena transitions |
| **Safe DLL Unload** | Fixed Error #132 on game exit — DLL no longer touches freed game memory during process termination |

---

## 🤔 What Changes In Practice

This is **not** a magic FPS doubler. Think of it like replacing an HDD with an SSD — same benchmarks, but everything *feels* smoother.

### You WILL notice

- ✅ Fewer random micro-stutters (especially Lua GC stalls)
- ✅ More stable minimum FPS (less variance between frames)
- ✅ Smoother frame pacing (no more Sleep jitter)
- ✅ Less lag degradation over long sessions (2+ hours)
- ✅ **Lower network latency** — spells feel more responsive (NEW in v1.6.0)
- ✅ **Faster disconnect detection** — 20 sec instead of 2+ hours (NEW in v1.6.0)
- ✅ Faster zone loading
- ✅ Reduced lag spikes on boss kills and dungeon queue pops
- ✅ No more broken damage meters in 25-man raids
- ✅ **No more crash on game exit** (fixed in v1.6.0)

### You WON'T notice

- ✗ Average FPS won't jump dramatically
- ✗ No visual changes
- ✗ No in-game notifications

### Where it matters most

- 🏰 Dalaran / Stormwind with many players
- ⚔️ 25-man raids (ICC, RS) with heavy addon usage
- ⏱️ Long play sessions without restarting the client
- 🌐 High-latency connections (**full network stack helps most here**)
- 📊 Damage meters during intense AoE fights

---

## 🔧 Recommended Combo

For maximum optimization, use this DLL together with the **[!LuaBoost](https://github.com/suprepupre/LuaBoost)** addon:

| Layer | Tool | What It Does |
|-------|------|--------------|
| **C / Engine** | wow\_optimize.dll | Faster memory, I/O, network, timers, Lua allocator + GC from C, combat log fix |
| **Lua / Addons** | !LuaBoost addon | Incremental GC, SpeedyLoad, table pool, throttle API, UI Thrashing Protection, GUI |

When both are installed, the DLL handles Lua allocator replacement, GC stepping from C (zero Lua overhead), network optimization, and combat log buffering. The addon provides the GUI, combat awareness, idle detection, SpeedyLoad, and UI thrashing protection.

> ⚠️ **Do NOT use [SmartGC](https://github.com/suprepupre/SmartGC) together with !LuaBoost** — SmartGC has been merged into LuaBoost. Using both will cause conflicts.

> ⚠️ **You can remove the CombatLogFix addon** if you're using wow_optimize.dll v1.4.0+ — the DLL handles combat log cleanup from C level without Lua overhead.

---

## 📦 Building

### Requirements

- **Windows 10/11**
- **Visual Studio 2022** (or 2019) with **"Desktop development with C++"** workload
- **CMake** (included with Visual Studio)
- **Internet connection** (first build downloads dependencies automatically)

### Build Steps

```
git clone https://github.com/suprepupre/wow-optimize.git
cd wow-optimize
build.bat
```

Output: `build\Release\wow_optimize.dll` + `build\Release\version.dll` + `build\Release\wow_loader.exe`

> ⚠️ **Must be compiled as 32-bit (Win32).** WoW 3.3.5a is a 32-bit application.

### Manual Build

```
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A Win32 ..
cmake --build . --config Release
```

---

## 📥 Quick Install (No Building Required)

Download pre-built binaries from [**Releases**](../../releases/latest).

---

## 🎮 Usage

### Option A — Auto-Load via Proxy (standard Wow.exe)

1. Copy `version.dll` and `wow_optimize.dll` to your WoW folder
2. Launch WoW normally
3. Done — loads automatically every time

### Option B — Universal Loader (patched/custom Wow.exe)

1. Copy `wow_loader.exe` and `wow_optimize.dll` to your WoW folder
2. Launch `wow_loader.exe` instead of `Wow.exe`
3. Done — WoW starts with optimizations applied

### Option C — Manual Injection

1. Copy `wow_optimize.dll`, `Dll_Injector.exe`, `inject.bat` to WoW folder
2. Launch WoW, wait for login screen
3. Double-click `inject.bat`

### Verify

Check `Logs/wow_optimize.log` — all lines should show `[ OK ]`.

```
[02:42:28.155] ========================================
[02:42:28.155]   wow_optimize.dll v1.6.0 BY SUPREMATIST
[02:42:28.155]   PID: 13088
[02:42:28.155] ========================================
[02:42:28.155] MinHook initialized
[02:42:28.165] mimalloc configured (large pages, pre-warmed 64MB)
[02:42:28.183] >>> ALLOCATOR: mimalloc ACTIVE <<<
[02:42:28.197] Sleep hook: ACTIVE (frame pacing + Lua GC + combat log)
[02:42:28.215] GetTickCount hook: ACTIVE
[02:42:28.238] CriticalSection hook: ACTIVE
[02:42:28.254] Network hook: ACTIVE (2/2 hooks, NODELAY+ACK+QoS+BUF+KA, deferred mode)
[02:42:28.288] CreateFile hooks: ACTIVE
[02:42:28.305] ReadFile hook: ACTIVE
[02:42:28.322] CloseHandle hook: ACTIVE
[02:42:28.340] [CombatLog]  [ OK ] Retention time (300 -> 1800 sec)
[02:42:28.340] [CombatLog]  [ OK ] Periodic clear (every 1 sec)
[02:42:38.789] [LuaOpt]  >>> ALLOCATOR REPLACED <<<
[02:42:39.100] Socket 10952 [send]: 7 applied, 0 failed (NODELAY+ACK+QoS+BUF+KA)
```

### Uninstall

Delete `version.dll`, `wow_loader.exe` (if present), and `wow_optimize.dll` from WoW folder. Log files in `Logs/` folder can be safely deleted.

---

## 🧠 Lua VM Optimizer

### Lua Allocator Replacement

WoW's Lua 5.1 uses a custom allocator (0x008558E0) with:

    9 size-class pools for small objects (strings, small tables, closures)
    SMemAlloc/SMemFree fallback for large objects

Neither path goes through CRT malloc — so mimalloc CRT hooks don't cover Lua at all.

The DLL replaces the frealloc function pointer in Lua's global_State:

    New allocations → mimalloc (faster, less fragmentation)
    Old pointers → freed via original allocator (safe coexistence during transition)
    Realloc migration: old data copied to mimalloc, old pointer freed via original
    Automatic re-application after UI reload (/reload)

### GC Parameter Tuning

    pause=110 (collect sooner, default 200)
    stepmul=300 (collect faster, default 200)
    Auto-GC stopped — manual per-frame stepping only

### DLL ↔ Addon Communication

```
DLL writes → Lua globals (every ~64 frames):
  LUABOOST_DLL_LOADED      = true
  LUABOOST_DLL_MEM_KB      = 24576.5
  LUABOOST_DLL_GC_STEPS    = 18432
  LUABOOST_DLL_GC_ACTIVE   = true

Addon writes → Lua globals (on events):
  LUABOOST_ADDON_COMBAT    = true/false
  LUABOOST_DLL_GC_REQUEST  = 256 (step) or -1 (full collect)

DLL reads addon globals every ~16 frames from the Sleep hook (main thread).
```

> **Why not `lua_pushcclosure`?** WoW validates C function pointers passed to Lua. If the pointer is outside Wow.exe's code section, WoW crashes with `Fatal condition: Invalid function pointer`. The DLL creates pure Lua wrapper functions via `FrameScript_Execute` instead — these are safe.

---

## 📊 Combat Log Optimizer

### The Problem

In 25-man raids (ICC, RS) with addons like DBM, WeakAuras, and Skada running simultaneously, the combat log loses events. Damage meters show incomplete data, often called "combat log breaks."

### How WoW's Combat Log Works

```
Active List:  HEAD → [entry1] → [entry2] → ... → [entryN]
                      oldest                       newest
                         ↑                            ↑
                    may be recycled              CA1394 (Lua pending)

Free List:    HEAD → [recycled1] → [recycled2] → ...
```

Events are stored as a linked list. Each entry is 0x78 bytes (120 bytes) with timestamp, GUIDs, spell info, and event flags. When a new event arrives:

1. Check free list → reuse a recycled node
2. Free list empty → check if oldest entry expired (age > retention × 1000ms)
3. Expired → **recycle it** (even if Lua hasn't processed it!)
4. Not expired → allocate new node from heap

Step 3 is the data loss bug.

### The Fix (2 Layers)

| Layer | What | How |
|-------|------|-----|
| **Retention** | Prevent premature recycling | CVar `BD09F0+0x30`: 300 → 1800 seconds |
| **Cleanup** | Prevent list corruption | Periodic `CombatLogClearEntries` from Sleep hook |

> **Note:** The entry pool feature from v1.5.0 was **removed** in v1.6.0. Pre-allocated mimalloc entries caused Error #132 crashes when the engine attempted to `SMemFree` them during logout, AFK kick, or arena zone transitions.

### Replacing CombatLogFix Addon

If you use the CombatLogFix addon (from KPack or standalone), you can **remove it**. The DLL does the same job from C level without any Lua overhead.

---

## 🌐 Network Optimization (NEW in v1.6.0)

### The Problem

Windows TCP stack adds hidden latency:

```
Without optimization:
  Client sends data  → Nagle buffers 200ms → sends
  Server sends data  → Client waits 200ms before ACK → server throttles
  Total hidden delay: up to 400ms round-trip

With optimization:
  Client sends data  → TCP_NODELAY → sends immediately
  Server sends data  → ACK_FREQ=1 → ACK immediately → server sends more
  Total hidden delay: ~0ms
```

### What We Set on Every Game Socket

| Setting | Value | Purpose |
|---------|-------|---------|
| `TCP_NODELAY` | `TRUE` | Disable Nagle's algorithm — send every write immediately |
| `SIO_TCP_SET_ACK_FREQUENCY` | `1` | ACK every incoming packet immediately (kills 200ms delayed ACK) |
| `IP_TOS` | `0x10` | DSCP Low Delay — QoS-aware routers prioritize game traffic |
| `SO_SNDBUF` | `32 KB` | Send buffer sized for WoW's small packets |
| `SO_RCVBUF` | `64 KB` | Receive buffer — prevents TCP window scaling bottleneck in raids |
| `SIO_KEEPALIVE_VALS` | `10s/1s` | Detect dead connections in ~20 sec instead of 2 hours |

### Deferred Optimization

WoW uses non-blocking (async) sockets. `connect()` returns `WSAEWOULDBLOCK` before the TCP handshake finishes. Some socket options only work after the connection is established.

Solution: We hook both `connect()` and `send()`. On async connect, the socket is tracked as "pending." When the first `send()` occurs (which only happens after successful handshake), all optimizations are applied.

---

## 🧠 Technical Details

### Safe Allocator Transition

```
Before injection:  malloc() → old CRT heap
After injection:   malloc() → mimalloc heap
                   free()   → checks which heap owns the pointer
                              ├── mimalloc → mi_free()
                              └── old CRT  → original free()
```

### Lua Allocator Transition

```
Before replacement:  Lua alloc → WoW pool (small) / SMemAlloc (large)
After replacement:   Lua alloc → mimalloc
                     Lua free  → checks which heap owns the pointer
                                 ├── mimalloc     → mi_free()
                                 └── WoW pool/SMem → original frealloc()
```

### Safe DLL Unload

```
DLL_PROCESS_DETACH with reserved != NULL (process terminating):
  → Skip ALL cleanup — OS will free everything
  → Touching freed game memory = crash

DLL_PROCESS_DETACH with reserved == NULL (FreeLibrary):
  → Restore Lua GC, unhook functions, free cache buffers
```

### CRT Auto-Detection

| DLL | Compiler |
|-----|----------|
| `msvcr80.dll` | Visual C++ 2005 (original WoW 3.3.5a) |
| `msvcr90.dll` | Visual C++ 2008 |
| `msvcr100-120.dll` | Visual C++ 2010-2013 |
| `ucrtbase.dll` | Visual C++ 2015+ |
| `msvcrt.dll` | System CRT |

### Dependencies

All downloaded automatically by CMake on first build.

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| [mimalloc](https://github.com/microsoft/mimalloc) | 3.2.8 | Memory allocator | MIT |
| [MinHook](https://github.com/TsudaKageyu/minhook) | latest | Function hooking | BSD 2-Clause |

---

## ⚠️ Important Notes

### Anti-Cheat (Warden)

**No bans have been reported.** However, DLL injection is inherently detectable.

What this DLL does **NOT** do:

- ❌ Does not modify `Wow.exe` on disk
- ❌ Does not provide any gameplay advantage
- ❌ Does not read/write game-specific memory (packets, player data)
- ❌ Does not automate gameplay

What this DLL **does**:

- ✅ Hooks system-level functions (`malloc`, `free`, `Sleep`, `connect`, `send`, `ReadFile`)
- ✅ Calls Lua VM GC API for performance tuning (read-only stats + GC stepping)
- ✅ Patches combat log retention (write to CVar value)

### System Requirements

- 32-bit compilation only (WoW 3.3.5a is 32-bit)
- Compatible with DXVK and LAA patch
- Works with standard and patched Wow.exe builds

---

## 🐛 Troubleshooting

### Proxy `version.dll` not loading

**Symptom:** You placed `version.dll` and `wow_optimize.dll` next to `Wow.exe`, but no `wow_optimize.log` is created on launch — the DLL is not being picked up.

**Fix — Option 1:** UNCHECK "Disable fullscreen optimizations" for `Wow.exe`:

1. Right-click `Wow.exe` → **Properties**
2. Go to the **Compatibility** tab
3. UNCHECK **"Disable fullscreen optimizations"**
4. Click **Apply** → **OK**
5. Relaunch WoW

**Fix — Option 2:** Use `wow_loader.exe` instead. It works with any `Wow.exe` regardless of compatibility settings.

---

| Problem | Solution |
|---------|----------|
| Proxy DLL doesn't load (no log file) | Use `wow_loader.exe` instead, or check compatibility settings above |
| WoW crashes after injection | Wait for login screen + 10 seconds before injecting |
| `FATAL: MinHook initialization failed` | Another hook DLL conflicting |
| `ERROR: No CRT DLL found` | Non-standard WoW build |
| Lua optimizer shows `SKIP` | Lua addresses not found (different build?) |
| `Invalid function pointer` crash | Old DLL version — update to v1.6+ |
| `Large pages: no permission` | Normal — requires admin policy change, optional |
| Combat log shows `SKIP` | CVar pointer not valid yet — try injecting later |
| Damage meters still broken | Remove CombatLogFix addon if present — two fixers may conflict |
| Socket shows `fail` | Normal on some Windows versions — some opts need admin or are unsupported |
| No noticeable difference | Expected on high-end PCs with few addons |
| wow_loader.exe shows warning | Check `Logs/wow_loader.log` for details |

---

## 📁 Project Structure

```
wow-optimize/
├── src/
│   ├── dllmain.cpp              # Main DLL — all system hooks + network stack
│   ├── lua_optimize.cpp         # Lua VM optimizer (allocator + GC + communication)
│   ├── lua_optimize.h           # Lua optimizer interface
│   ├── combatlog_optimize.cpp   # Combat log optimizer (retention + cleanup)
│   ├── combatlog_optimize.h     # Combat log optimizer interface
│   ├── wow_loader.cpp           # Universal auto-loader executable
│   ├── version_proxy.cpp        # Auto-loader (version.dll proxy)
│   ├── version_exports.def      # Export definitions for version.dll
│   └── version.rc               # DLL version info resource
├── CMakeLists.txt               # Build config + dependency management
├── build.bat                    # One-click build script
├── README.md
├── LICENSE
└── .gitignore
```

---


## ⭐ Reviews

See what other players say: [**Reviews & Testimonials**](../../discussions/10)

Used wow_optimize or LuaBoost? [**Leave a review!**](../../discussions/10)

## 📜 License

MIT License — use, modify, and distribute freely. See [LICENSE](LICENSE) for full text.


