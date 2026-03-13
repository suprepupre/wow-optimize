
# 🚀 wow_optimize v1.6.2 BY SUPREMATIST

**Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)**

Replaces WoW's ancient memory allocator, optimizes I/O, network, timers, threading, frame pacing, Lua VM, and combat log buffer — all through a single injectable DLL.

> ⚠️ **Disclaimer:** This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. **No ban has been reported**, but **use at your own risk.** The author is not responsible for any consequences including but not limited to account suspensions.

---

## ⭐ Reviews

See what other players say: [**Reviews & Testimonials**](../../discussions/categories/reviews-testimonials)

Used wow_optimize or LuaBoost? [**Leave a review!**](./../discussion/categories/reviews-testimonials)

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
| 16 | **Combat Log Optimizer** | Prevents combat log data loss in raids (retention + adaptive cleanup) |

---

## 1.6.2 (Hotfix)

| Change | Description |
|--------|-------------|
| **Fix Error #132 on /logout** | Removed combat log entry pool — HeapAlloc entries crash when WoW calls SMemFree on them during logout. SMemFree expects its own metadata header before each pointer. |
| **Reverted to 2-layer combat log fix** | Retention (1800s) + Periodic Clear only. No entry pool. |

### Previous (v1.6.0-1)

| Feature | Description |
|---------|-------------|
| **Full Network Latency Stack** | SIO_TCP_SET_ACK_FREQUENCY=1, IP_TOS LOWDELAY, SO_RCVBUF 64KB, TCP Keepalive 10s/1s, deferred socket optimization via send() hook |
| **O(1) MPQ Handle Lookup** | Hash table replaces O(n) linear scan for ReadFile cache |
| **SRWLock for ReadFile Cache** | Concurrent reads on cache hits |
| **Smarter PreciseSleep** | SwitchToThread() for 0.3-2ms range — less idle CPU |
| **Lua State Read Throttle** | DLL→Lua API calls reduced from ~900/sec to ~124/sec |
| **Entry Pool Removed** | Fixed Error #132 crash from mimalloc entries in engine free list |
| **Safe DLL Unload** | Fixed Error #132 on game exit |

---

## 🤔 What Changes In Practice

This is **not** a magic FPS doubler. Think of it like replacing an HDD with an SSD — same benchmarks, but everything *feels* smoother.

### You WILL notice

- ✅ Fewer random micro-stutters (especially Lua GC stalls)
- ✅ More stable minimum FPS (less variance between frames)
- ✅ Smoother frame pacing (no more Sleep jitter)
- ✅ Less lag degradation over long sessions (2+ hours)
- ✅ Lower network latency — spells feel more responsive
- ✅ Faster disconnect detection — 20 sec instead of 2+ hours
- ✅ Faster zone loading
- ✅ Reduced lag spikes on boss kills and dungeon queue pops
- ✅ No more broken damage meters in 25-man raids
- ✅ No more crash on game exit

### You WON'T notice

- ✗ Average FPS won't jump dramatically
- ✗ No visual changes
- ✗ No in-game notifications

### Where it matters most

- 🏰 Dalaran / Stormwind with many players
- ⚔️ 25-man raids (ICC, RS) with heavy addon usage
- ⏱️ Long play sessions without restarting the client
- 🌐 High-latency connections (full network stack helps most here)
- 📊 Damage meters during intense AoE fights

---

## 🔧 Recommended Combo

For maximum optimization, use this DLL together with the **[!LuaBoost](https://github.com/suprepupre/LuaBoost)** addon:

| Layer | Tool | What It Does |
|-------|------|--------------|
| **C / Engine** | wow\_optimize.dll | Faster memory, I/O, network, timers, Lua allocator + GC from C, combat log fix |
| **Lua / Addons** | !LuaBoost addon | Incremental GC, SpeedyLoad, table pool, throttle API, UI Thrashing Protection, Event Profiler, OnUpdate Dispatcher, GUI |

When both are installed, the DLL handles Lua allocator replacement, GC stepping from C (zero Lua overhead), network optimization, and combat log buffering. The addon provides the GUI, combat awareness, idle detection, SpeedyLoad, and UI thrashing protection.

> ⚠️ **Do NOT use SmartGC together with !LuaBoost** — SmartGC has been merged into LuaBoost. Using both will cause conflicts.

> ⚠️ **You can remove the CombatLogFix addon** if you're using wow_optimize.dll — the DLL handles combat log cleanup from C level without Lua overhead.

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

### Option A — Auto-Load via Proxy (recommended)

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
[02:42:28.155]   wow_optimize.dll v1.6.1 BY SUPREMATIST
[02:42:28.155]   PID: 13088
[02:42:28.155] ========================================
[02:42:28.183] >>> ALLOCATOR: mimalloc ACTIVE <<<
[02:42:28.197] Sleep hook: ACTIVE (frame pacing + Lua GC + combat log)
[02:42:28.254] Network hook: ACTIVE (2/2 hooks, NODELAY+ACK+QoS+BUF+KA, deferred mode)
[02:42:28.340] [CombatLog]  [ OK ] Adaptive Clear (500ms combat / 1s normal / 3s idle)
[02:42:38.789] [LuaOpt]  >>> ALLOCATOR REPLACED <<<
[02:42:39.100] Socket 10952 [send]: 7 applied, 0 failed (NODELAY+ACK+QoS+BUF+KA)
```

### Uninstall

Delete `version.dll`, `wow_loader.exe` (if present), and `wow_optimize.dll` from WoW folder. Log files in `Logs/` folder can be safely deleted.

---

## 🧠 Lua VM Optimizer

### Lua Allocator Replacement

WoW's Lua 5.1 uses a custom allocator (0x008558E0) with 9 size-class pools for small objects and SMemAlloc/SMemFree fallback for large objects. Neither path goes through CRT malloc — so mimalloc CRT hooks don't cover Lua at all.

The DLL replaces the frealloc function pointer in Lua's global_State:
- New allocations → mimalloc (faster, less fragmentation)
- Old pointers → freed via original allocator (safe coexistence during transition)
- Realloc migration: old data copied to mimalloc, old pointer freed via original
- Automatic re-application after UI reload (/reload)

### GC Parameter Tuning

- pause=110 (collect sooner, default 200)
- stepmul=300 (collect faster, default 200)
- Auto-GC stopped — manual per-frame stepping only

### DLL ↔ Addon Communication

```
DLL writes → Lua globals (every ~64 frames):
  LUABOOST_DLL_LOADED, LUABOOST_DLL_MEM_KB, LUABOOST_DLL_GC_STEPS, etc.

Addon writes → Lua globals (on events):
  LUABOOST_ADDON_COMBAT, LUABOOST_ADDON_IDLE, LUABOOST_ADDON_LOADING

DLL reads addon globals every ~16 frames from the Sleep hook (main thread).
```

---

## 📊 Combat Log Optimizer

### The Problem

In 25-man raids with addons like DBM, WeakAuras, and Skada, the combat log loses events. Damage meters show incomplete data ("combat log breaks").

### The Fix (2 Layers)

| Layer | What | How |
|-------|------|-----|
| **Retention** | Prevent premature recycling | CVar: 300 → 1800 seconds |
| **Adaptive Cleanup** | Clear processed entries | 500ms combat / 1s normal / 3s idle |

> **Note:** The entry pool feature from v1.5.0 was removed — pre-allocated mimalloc entries caused Error #132 when the engine attempted to SMemFree them.

---

## 🌐 Network Optimization

### What We Set on Every Game Socket

| Setting | Value | Purpose |
|---------|-------|---------|
| `TCP_NODELAY` | `TRUE` | Disable Nagle's algorithm |
| `SIO_TCP_SET_ACK_FREQUENCY` | `1` | ACK every packet immediately (kills 200ms delayed ACK) |
| `IP_TOS` | `0x10` | DSCP Low Delay for QoS-aware routers |
| `SO_SNDBUF` | `32 KB` | Send buffer |
| `SO_RCVBUF` | `64 KB` | Receive buffer (prevents window scaling bottleneck) |
| `SIO_KEEPALIVE_VALS` | `10s/1s` | Detect dead connections in ~20 sec |

Optimizations are deferred via `send()` hook — applied after async TCP handshake completes.

---

## 🧠 Technical Details

### Safe Allocator Transition

```
Before: malloc() → old CRT heap
After:  malloc() → mimalloc heap
        free()   → mi_is_in_heap_region? mi_free() : original free()
```

### Safe DLL Unload

```
DLL_PROCESS_DETACH with reserved != NULL (process terminating):
  → Skip ALL cleanup — OS will free everything

DLL_PROCESS_DETACH with reserved == NULL (FreeLibrary):
  → Restore Lua GC, unhook functions, free cache buffers
```

### Dependencies

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| [mimalloc](https://github.com/microsoft/mimalloc) | 3.2.8 | Memory allocator | MIT |
| [MinHook](https://github.com/TsudaKageyu/minhook) | latest | Function hooking | BSD 2-Clause |

---

## ⚠️ Important Notes

### Anti-Cheat (Warden)

**No bans have been reported.** The DLL only hooks system-level functions (`malloc`, `free`, `Sleep`, `connect`, `send`, `ReadFile`), calls Lua GC API for performance tuning, and patches combat log retention.

### System Requirements

- 32-bit compilation only (WoW 3.3.5a is 32-bit)
- Compatible with DXVK and LAA patch
- Works with standard and patched Wow.exe builds

---

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| Proxy DLL doesn't load (no log file) | Use `wow_loader.exe`, or uncheck "Disable fullscreen optimizations" in Wow.exe properties |
| `FATAL: MinHook initialization failed` | Another hook DLL conflicting |
| `ERROR: No CRT DLL found` | Non-standard WoW build |
| Socket shows `fail` | Normal on some Windows versions — some opts need admin |
| Damage meters still broken | Remove CombatLogFix addon — two fixers may conflict |
| No noticeable difference | Expected on high-end PCs with few addons |

---

## 📁 Project Structure

```
wow-optimize/
├── src/
│   ├── dllmain.cpp              # Main DLL — all system hooks + network stack
│   ├── lua_optimize.cpp         # Lua VM optimizer (allocator + GC + communication)
│   ├── lua_optimize.h           # Lua optimizer interface
│   ├── combatlog_optimize.cpp   # Combat log optimizer (retention + adaptive cleanup)
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

## 📜 License

MIT License — use, modify, and distribute freely. See [LICENSE](LICENSE) for full text.