# 🚀 wow_optimize v2.0.1 BY SUPREMATIST

**Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)**

Replaces WoW's ancient memory allocator, optimizes I/O, network, timers, threading, Lua VM, combat log buffer, UI widget updates, and caches static API results — all through a single injectable DLL.

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
| 3 | **Lua String Table** | Pre-sizes string hash table to 32K buckets — eliminates resize freezes |
| 4 | **Sleep Hook** | Drives per-frame Lua GC stepping and combat log cleanup |
| 5 | **Full Network Stack** | TCP_NODELAY + Immediate ACK + QoS + Buffer tuning + Fast Keepalive |
| 6 | **GetTickCount Hook** | QPC-based microsecond precision (better internal timers) |
| 7 | **CriticalSection Spin** | Adds spin count to all locks (fewer context switches) |
| 8 | **ReadFile Cache** | 64KB read-ahead cache for MPQ files (faster loading) |
| 9 | **CreateFile Hints** | Sequential scan flags for MPQ (OS prefetch optimization) |
| 10 | **CloseHandle Hook** | Cache invalidation on file close (prevents stale data) |
| 11 | **Timer Resolution** | 0.5ms system timer via NtSetTimerResolution |
| 12 | **Thread Priority** | Main thread priority ABOVE_NORMAL + ideal core pinning |
| 13 | **Working Set** | Locks 256MB–2GB in RAM (prevents page-outs) |
| 14 | **Process Priority** | Above Normal + disabled priority boost |
| 15 | **FPS Cap** | Raises hardcoded FPS limit |
| 16 | **Adaptive GC** | Per-frame GC stepping with automatic step size adjustment based on measured time |
| 17 | **Combat Log Optimizer** | Prevents combat log data loss in raids (retention + periodic cleanup) |
| 18 | **UI Widget Cache** | Skips redundant UI widget updates at C level (10 hooks, taint-free) |
| 19 | **GC Step Sync** | Reads step sizes from LuaBoost addon — GUI controls DLL behavior |
| 20 | **GetSpellInfo Cache** | TTL cache (~500ms) for spell data lookups. 95%+ hit rate. |
| 21 | **GetItemInfo Cache** | Permanent cache for item data. Nil results not cached (server hasn't sent data yet). |
| 22 | **Background Logging** | Ring buffer + background thread eliminates disk I/O stalls |
| 23 | **Frame Budget Manager** | Skips non-essential work on slow frames (>33ms/50ms) |

---

## 🤔 What Changes In Practice

### You WILL notice

- ✅ Fewer random micro-stutters (adaptive GC prevents stalls)
- ✅ More stable minimum FPS (less variance between frames)
- ✅ Less lag degradation over long sessions (2+ hours)
- ✅ Lower network latency — spells feel more responsive
- ✅ Faster disconnect detection — 20 sec instead of 2+ hours
- ✅ Faster zone loading
- ✅ Reduced lag spikes on boss kills and dungeon queue pops
- ✅ No more broken damage meters in 25-man raids
- ✅ Smoother UI in crowded areas (10 widget cache hooks)
- ✅ Faster addon response with spell-heavy rotations (GetSpellInfo cache)

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
| **C / Engine** | wow_optimize.dll | Faster memory, I/O, network, timers, adaptive GC from C, combat log fix, UI widget cache, API cache |
| **Lua / Addons** | !LuaBoost addon | GC step sync to DLL, SpeedyLoad, memory leak scanner, table pool, diagnostics, GUI |

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
[02:42:28.155]   wow_optimize.dll v2.0.1 BY SUPREMATIST
[02:42:28.155]   PID: 13088
[02:42:28.155] ========================================
[02:42:28.183] >>> ALLOCATOR: mimalloc ACTIVE <<<
[02:42:28.197] Sleep hook: ACTIVE (Lua GC + combat log)
[02:42:28.254] Network hook: ACTIVE (2/2 hooks, NODELAY+ACK+QoS+BUF+KA)
[02:42:28.340] [CombatLog]  [ OK ] Guaranteed Clear (5s normal, 10s combat)
[02:42:28.543] [UICache]  Hooks: 10/10 active
[02:42:28.543] [UICache]  [ OK ] ACTIVE
[02:42:28.600] [ApiCache]  Hooks: 2/2 active (GetSpellInfo + GetItemInfo)
[02:42:28.600] [ApiCache]  [ OK ] ACTIVE
[02:42:38.789] [LuaOpt]  >>> ALLOCATOR REPLACED <<<
[02:42:39.100] Socket 10952 [send]: 7 applied, 0 failed
```

### Uninstall

Delete `version.dll`, `wow_loader.exe` (if present), and `wow_optimize.dll` from WoW folder. Log files in `Logs/` folder can be safely deleted.

---

## 🧠 API Cache

### GetSpellInfo (TTL ~500ms)

Caches all 9 return values. TTL-based because `castTime` and `cost` change with haste, talents, and gear. 500ms is imperceptible but picks up buff changes.

### GetItemInfo (Permanent)

Caches all 11 return values permanently. Item data is truly static. **Nil results are NOT cached** — nil means the server hasn't sent item data yet.

### Why NOT cache unit APIs?

| API | Cacheable? | Reason |
|-----|-----------|--------|
| `GetSpellInfo` | ✅ TTL | Semi-static DBC data |
| `GetItemInfo` | ✅ Permanent | Truly static item data |
| `UnitHealth/Power` | ❌ | Changes mid-frame via events |
| `UnitGUID/Exists` | ❌ | Changes mid-frame on target/pet changes |
| `UnitIsDeadOrGhost` | ❌ | Changes mid-frame via combat events |

---

## 🧠 Lua VM Optimizer

### Lua Allocator Replacement

WoW's Lua 5.1 uses a custom allocator (0x008558E0) with 9 size-class pools. The DLL replaces the `frealloc` function pointer in `global_State` with mimalloc.

### String Table Pre-Sizing

WoW starts with a small string hash table. With heavy addons, 30,000-50,000 unique strings accumulate. Each resize rehashes ALL strings, causing 5-15ms freezes. The DLL pre-sizes to 32,768 buckets at startup.

### Adaptive GC

Each GC step is timed with QueryPerformanceCounter. The DLL adjusts step sizes automatically:

| Condition | Action |
|-----------|--------|
| Average > 2ms | Reduce step size (prevent frame drops) |
| Average < 0.6ms | Increase step size (collect more) |
| Memory > 200MB | Emergency full collect |

### DLL ↔ Addon Communication

```
DLL writes → Lua globals (every ~64 frames):
  LUABOOST_DLL_LOADED, LUABOOST_DLL_MEM_KB, LUABOOST_DLL_GC_STEPS,
  LUABOOST_DLL_GC_MS, LUABOOST_DLL_UICACHE_SKIPPED,
  LUABOOST_DLL_APICACHE_HITS, LUABOOST_DLL_APICACHE_MISSES, etc.

Addon writes → Lua globals (on events/settings):
  LUABOOST_ADDON_COMBAT, LUABOOST_ADDON_IDLE, LUABOOST_ADDON_LOADING,
  LUABOOST_ADDON_STEP_NORMAL, LUABOOST_ADDON_STEP_COMBAT, etc.

DLL reads addon globals every ~16 frames from the Sleep hook (main thread).
```

---

## 🎨 UI Widget Cache

### What's Hooked (10 methods, all taint-free)

| Method | Cache Key | Skip Condition |
|--------|-----------|----------------|
| `FontString:SetText` | FNV-1a text hash | Same text string |
| `FontString:SetTextColor` | Combined RGBA hash | Same color values |
| `StatusBar:SetValue` | Float bits | Same numeric value |
| `StatusBar:SetMinMaxValues` | Combined min+max hash | Same min and max |
| `StatusBar:SetStatusBarColor` | Combined RGBA hash | Same color values |
| `Texture:SetTexture` | FNV-1a path / RGBA hash | Same texture or color |
| `Texture:SetVertexColor` | Combined RGBA hash | Same color values |
| `Region:SetAlpha` | Float bits | Same alpha value |
| `Region:SetWidth` | Float bits | Same width value |
| `Region:SetHeight` | Float bits | Same height value |

All addresses auto-discovered at startup by scanning method tables. Cache cleared on zone transitions and `/reload`.

---

## 📊 Combat Log Optimizer

| Layer | What | How |
|-------|------|-----|
| **Retention** | Prevent premature recycling | CVar: 300 → 1800 seconds |
| **Periodic Cleanup** | Clear processed entries | Every 5s (normal) / 10s (combat) |

---

## 🌐 Network Optimization

| Setting | Value | Purpose |
|---------|-------|---------|
| `TCP_NODELAY` | `TRUE` | Disable Nagle's algorithm |
| `SIO_TCP_SET_ACK_FREQUENCY` | `1` | ACK every packet immediately |
| `IP_TOS` | `0x10` | DSCP Low Delay for QoS-aware routers |
| `SO_SNDBUF` | `32 KB` | Send buffer |
| `SO_RCVBUF` | `64 KB` | Receive buffer |
| `SIO_KEEPALIVE_VALS` | `10s/1s` | Detect dead connections in ~20 sec |

---

## ⚠️ Important Notes

### Anti-Cheat (Warden)

**No bans have been reported.** The DLL only hooks system-level functions, calls Lua GC API for performance tuning, patches combat log retention, caches UI widget values, and caches static API results.

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
│   ├── lua_optimize.cpp         # Lua VM optimizer (allocator + adaptive GC + communication)
│   ├── lua_optimize.h           # Lua optimizer interface
│   ├── combatlog_optimize.cpp   # Combat log optimizer (retention + periodic cleanup)
│   ├── combatlog_optimize.h     # Combat log optimizer interface
│   ├── ui_cache.cpp             # UI widget cache (10 hooks, auto-discovered)
│   ├── ui_cache.h               # UI cache interface
│   ├── api_cache.cpp            # GetSpellInfo + GetItemInfo cache
│   ├── api_cache.h              # API cache interface
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