# 🚀 wow_optimize v1.8.0 BY SUPREMATIST

**Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)**

Replaces WoW's ancient memory allocator, optimizes I/O, network, timers, threading, Lua VM, combat log buffer, and UI widget updates — all through a single injectable DLL.

> ⚠️ **Disclaimer:** This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. **No ban has been reported**, but **use at your own risk.** The author is not responsible for any consequences including but not limited to account suspensions.

---

## ⭐ Reviews

See what other players say: [**Reviews & Testimonials**](https://github.com/suprepupre/wow-optimize/discussions/10)

Used wow_optimize or LuaBoost? [**Leave a review!**](https://github.com/suprepupre/wow-optimize/discussions/10)

---

## ✨ Features

| # | Feature | What It Does |
|---|---------|--------------|
| 1 | **mimalloc Allocator** | Replaces msvcr80/ucrtbase `malloc`/`free` with Microsoft's modern allocator |
| 2 | **Lua VM Allocator** | Replaces WoW's internal Lua pool allocator with mimalloc |
| 3 | **Sleep Hook** | Drives per-frame Lua GC stepping and combat log cleanup |
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
| 17 | **UI Widget Cache** | Skips redundant UI widget updates at C level (10 hooks, taint-free) |
| 18 | **GC Step Sync** | Reads step sizes from LuaBoost addon — GUI controls DLL behavior |

---

## 🆕 What's New in v1.8.0

| Feature | Description |
|---------|-------------|
| **3 new UI Cache hooks** | `Region:SetWidth`, `Region:SetHeight`, `Texture:SetVertexColor` — called every frame by health bars, cast bars, and nameplates. Total: **10 hooked methods**. |
| **UI Cache stats to Lua** | Skip rate, skipped/passed counts exposed via `LuaBoostC_GetUIStats()`. Visible in addon with `/lb` and `/lb gc`. |
| **GC Step Sync** | DLL reads step sizes from addon globals (`LUABOOST_ADDON_STEP_*`). Addon GUI becomes single source of truth for GC tuning. |
| **Larger UI cache** | 8192 → 32768 slots (128KB). Handles 2000+ widgets × 10 methods without overflow. |
| **Better cache hash** | Murmur-style finalizer replaces simple XOR — better distribution, fewer collisions. |
| **Cache probe eviction** | When all probe slots are occupied, evicts last slot instead of silently failing. |

### v1.7.2 Bugfixes (included)

| Fix | Description |
|-----|-------------|
| **ReadFile cache eviction** | Was always evicting slot 0 — now round-robin across all 16 slots. |
| **Sleep timer race condition** | QPC frequency initialized before hook activation — prevents torn read on 32-bit double. |
| **FPS cap false positive** | Pattern scan now verifies conditional jump after `CMP EAX, 200`. |
| **MPQ hash infinite loop** | Safety bound on backward-shift deletion in hash table. |
| **Frame counter reset** | Addon poll counters reset on `/reload` and shutdown. |
| **PreciseSleep disabled** | QPC busy-wait caused damage meter desync — reverted to OS Sleep for compatibility. |

---

## 🤔 What Changes In Practice

This is **not** a magic FPS doubler. Think of it like replacing an HDD with an SSD — same benchmarks, but everything *feels* smoother.

### You WILL notice

- ✅ Fewer random micro-stutters (especially Lua GC stalls)
- ✅ More stable minimum FPS (less variance between frames)
- ✅ Less lag degradation over long sessions (2+ hours)
- ✅ Lower network latency — spells feel more responsive
- ✅ Faster disconnect detection — 20 sec instead of 2+ hours
- ✅ Faster zone loading
- ✅ Reduced lag spikes on boss kills and dungeon queue pops
- ✅ No more broken damage meters in 25-man raids
- ✅ **Smoother UI in crowded areas** (10 widget cache hooks)

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
| **C / Engine** | wow_optimize.dll | Faster memory, I/O, network, timers, Lua allocator + GC from C, combat log fix, **UI widget cache (10 hooks)** |
| **Lua / Addons** | !LuaBoost addon | GC step sync to DLL, SpeedyLoad, table pool, throttle API, UI cache stats display, Event Profiler, FPS Monitor, GUI |

When both are installed, the DLL handles Lua allocator replacement, GC stepping from C using step sizes from the addon GUI, network optimization, combat log buffering, and UI widget caching. The addon provides the GUI, combat awareness, idle detection, SpeedyLoad, and diagnostics.

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
[02:42:28.155]   wow_optimize.dll v1.8.0 BY SUPREMATIST
[02:42:28.155]   PID: 13088
[02:42:28.155] ========================================
[02:42:28.183] >>> ALLOCATOR: mimalloc ACTIVE <<<
[02:42:28.197] Sleep hook: ACTIVE (Lua GC + combat log)
[02:42:28.254] Network hook: ACTIVE (2/2 hooks, NODELAY+ACK+QoS+BUF+KA)
[02:42:28.340] [CombatLog]  [ OK ] Guaranteed Clear (every 1 sec)
[02:42:28.543] [UICache]  Hooks: 10/10 active
[02:42:28.543] [UICache]  [ OK ] ACTIVE
[02:42:38.789] [LuaOpt]  >>> ALLOCATOR REPLACED <<<
[02:42:39.100] Socket 10952 [send]: 7 applied, 0 failed
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

### GC Step Sync (NEW in v1.8.0)

When LuaBoost addon is installed, the DLL reads step sizes from Lua globals every ~16 frames:

```
Addon writes → Lua globals (on settings change):
  LUABOOST_ADDON_STEP_NORMAL, LUABOOST_ADDON_STEP_COMBAT,
  LUABOOST_ADDON_STEP_IDLE, LUABOOST_ADDON_STEP_LOADING

DLL reads → applies to per-frame GC stepping
```

This means the addon GUI is the single source of truth for GC tuning — slider changes take effect within ~250ms.

### DLL ↔ Addon Communication

```
DLL writes → Lua globals (every ~64 frames):
  LUABOOST_DLL_LOADED, LUABOOST_DLL_MEM_KB, LUABOOST_DLL_GC_STEPS,
  LUABOOST_DLL_UICACHE_SKIPPED, LUABOOST_DLL_UICACHE_PASSED, etc.

Addon writes → Lua globals (on events):
  LUABOOST_ADDON_COMBAT, LUABOOST_ADDON_IDLE, LUABOOST_ADDON_LOADING,
  LUABOOST_ADDON_STEP_NORMAL, LUABOOST_ADDON_STEP_COMBAT, etc.

DLL reads addon globals every ~16 frames from the Sleep hook (main thread).
```

---

## 🎨 UI Widget Cache

### The Problem

In crowded areas, addons call UI update functions thousands of times per second — nameplates, unit frames, health bars, damage meters. Most calls set the **same value** that's already displayed, but WoW's engine processes each call fully.

### What's Hooked (10 methods, all taint-free)

| Method | Cache Key | Skip Condition |
|--------|-----------|----------------|
| `FontString:SetText` | FNV-1a text hash | Same text string |
| `FontString:SetTextColor` | Combined RGBA hash | Same color values |
| `StatusBar:SetValue` | Float bits | Same numeric value |
| `StatusBar:SetMinMaxValues` | Combined min+max hash | Same min and max |
| `StatusBar:SetStatusBarColor` | Combined RGBA hash | Same color values |
| `Texture:SetTexture` | FNV-1a path / float ID | Same texture |
| `Texture:SetVertexColor` | Combined RGBA hash | Same color values |
| `Region:SetAlpha` | Float bits | Same alpha value |
| `Region:SetWidth` | Float bits | Same width value |
| `Region:SetHeight` | Float bits | Same height value |

All addresses auto-discovered at startup by scanning method tables — verified by matching 3+ neighboring method names.

### Why This Is Safe

| Concern | Answer |
|---------|--------|
| **Taint?** | Zero. Hooks C functions directly — invisible to Lua taint tracker. |
| **Wrong widget?** | Auto-discovery requires 3+ matching neighbor methods before accepting. |
| **MinMax change?** | SetMinMaxValues invalidates SetValue cache for that widget. |
| **Thread safety?** | All hooks run on main thread only (same as all UI code). |
| **Stale cache?** | Cache uses 32768 slots with murmur hash — naturally evicts old entries. |

### Performance

| Scenario | Skip Rate | Impact |
|----------|-----------|--------|
| Dalaran (100+ players) | 60-80% | Major — thousands of calls/sec eliminated |
| 25-man raid (ICC) | 50-70% | Significant — unit frames, raid frames, meters |
| Solo questing | 30-50% | Moderate — quest text, minimap, buffs |

---

## 📊 Combat Log Optimizer

### The Problem

In 25-man raids with addons like DBM, WeakAuras, and Skada, the combat log loses events. Damage meters show incomplete data ("combat log breaks").

### The Fix (2 Layers)

| Layer | What | How |
|-------|------|-----|
| **Retention** | Prevent premature recycling | CVar: 300 → 1800 seconds |
| **Periodic Cleanup** | Clear processed entries | Every 1 second via CombatLogClearEntries |

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

**No bans have been reported.** The DLL only hooks system-level functions (`malloc`, `free`, `Sleep`, `connect`, `send`, `ReadFile`), calls Lua GC API for performance tuning, patches combat log retention, and caches UI widget values to skip redundant calls.

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
| `[UICache] DISABLED` | Non-standard WoW build — method table not found |

---

## 📁 Project Structure

```
wow-optimize/
├── src/
│   ├── dllmain.cpp              # Main DLL — all system hooks + network stack
│   ├── lua_optimize.cpp         # Lua VM optimizer (allocator + GC + communication)
│   ├── lua_optimize.h           # Lua optimizer interface
│   ├── combatlog_optimize.cpp   # Combat log optimizer (retention + periodic cleanup)
│   ├── combatlog_optimize.h     # Combat log optimizer interface
│   ├── ui_cache.cpp             # UI widget cache (10 hooks, auto-discovered)
│   ├── ui_cache.h               # UI cache interface
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