# 🚀 wow_optimize BY SUPREMATIST

**Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)**

Replaces WoW's ancient memory allocator, optimizes I/O, network, timers, threading, Lua VM, combat log buffer, UI widget updates, caches static API results, and accelerates string.format — all through a single injectable DLL.

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
| 21 | **GetItemInfo Cache** | Permanent cache for item data. Nil results not cached. |
| 22 | **Background Logging** | Ring buffer + background thread eliminates disk I/O stalls |
| 23 | **Frame Budget Manager** | Skips non-essential work on slow frames (>33ms/50ms) |
| 24 | **string.format Fast Path** | Optimized C implementation for common format patterns (%d, %s, %.Nf). 40-60% faster per call. |

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
- ✅ Faster addon response with spell-heavy rotations (API cache)
- ✅ Smoother addon updates in combat (format fast path)

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
| **C / Engine** | wow_optimize.dll | Faster memory, I/O, network, timers, adaptive GC, combat log fix, UI cache, API cache, format fast path |
| **Lua / Addons** | !LuaBoost addon | GC step sync to DLL, SpeedyLoad, memory leak scanner, table pool, diagnostics, GUI |

> ⚠️ **Do NOT use SmartGC together with !LuaBoost** — SmartGC has been merged into LuaBoost.

> ⚠️ **You can remove the CombatLogFix addon** if you're using wow_optimize.dll — the DLL handles combat log cleanup from C level.

---

## 📦 Building

### Requirements

- **Windows 10/11**
- **Visual Studio 2062** (or 2019) with **"Desktop development with C++"** workload
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

### Option C — Manual Injection

1. Copy `wow_optimize.dll`, `Dll_Injector.exe`, `inject.bat` to WoW folder
2. Launch WoW, wait for login screen
3. Double-click `inject.bat`

### Verify

Check `Logs/wow_optimize.log` — all lines should show `[ OK ]`.

### Uninstall

Delete `version.dll`, `wow_loader.exe` (if present), and `wow_optimize.dll` from WoW folder.

---

## 🧠 API Cache

### GetSpellInfo (TTL ~500ms)

Caches all 9 return values. TTL-based because `castTime` and `cost` change with haste, talents, and gear.

### GetItemInfo (Permanent)

Caches all 11 return values permanently. Item data is truly static. **Nil results and partial data are NOT cached.**

### Why NOT cache unit APIs?

| API | Cacheable? | Reason |
|-----|-----------|--------|
| `GetSpellInfo` | ✅ TTL | Semi-static DBC data |
| `GetItemInfo` | ✅ Permanent | Truly static item data |
| `UnitHealth/Power` | ❌ | Changes mid-frame via events |
| `UnitGUID/Exists` | ❌ | Changes mid-frame on target/pet changes |

---

## ⚡ string.format Fast Path

Hooks `string.format` at C level and provides optimized paths:

| Pattern | Speedup | Coverage |
|---------|---------|----------|
| `format("%d", n)` | ~60% faster | Damage numbers, health, most counters |
| `format("%s", s)` | ~50% faster | String concatenation via format |
| `format("%.1f", n)` | ~55% faster | Timer displays, percentages |
| Generic (multiple specifiers) | ~40% faster | Color codes, complex strings |
| `%q`, `%*`, table args | 0% (fallback) | Rare patterns — uses original |

Expected 85%+ fast path hit rate with typical addon usage.

---

## 🧠 Lua VM Optimizer

### Lua Allocator Replacement

Replaces WoW's Lua 5.1 custom allocator with mimalloc. The original allocator uses 9 size-class pools with SMemAlloc/SMemFree fallback.

### String Table Pre-Sizing

Pre-sizes to 32,768 buckets at startup. Eliminates resize freezes that occur when 30,000-50,000 unique strings accumulate.

### Adaptive GC

| Condition | Action |
|-----------|--------|
| Average > 2ms | Reduce step size |
| Average < 0.6ms | Increase step size |
| Memory > 200MB (not loading) | Emergency full collect |
| Loading mode | Grace period — skip GC for first 30 frames |

---

## 🎨 UI Widget Cache

### What's Hooked (10 methods, all taint-free)

| Method | Skip Condition |
|--------|----------------|
| `FontString:SetText` | Same text string |
| `FontString:SetTextColor` | Same color values |
| `StatusBar:SetValue` | Same numeric value |
| `StatusBar:SetMinMaxValues` | Same min and max |
| `StatusBar:SetStatusBarColor` | Same color values |
| `Texture:SetTexture` | Same texture or color |
| `Texture:SetVertexColor` | Same color values |
| `Region:SetAlpha` | Same alpha value |
| `Region:SetWidth` | Same width value |
| `Region:SetHeight` | Same height value |

All addresses auto-discovered at startup.

---

## 🌐 Network Optimization

| Setting | Value | Purpose |
|---------|-------|---------|
| `TCP_NODELAY` | `TRUE` | Disable Nagle's algorithm |
| `SIO_TCP_SET_ACK_FREQUENCY` | `1` | ACK every packet immediately |
| `IP_TOS` | `0x10` | DSCP Low Delay |
| `SO_SNDBUF` / `SO_RCVBUF` | `32KB` / `64KB` | Buffer sizing |
| `SIO_KEEPALIVE_VALS` | `10s/1s` | Fast dead connection detection |

---

## ⚠️ Important Notes

### Anti-Cheat (Warden)

**No bans have been reported.** The DLL only hooks system-level functions, calls Lua GC API, patches combat log retention, caches UI/API values, and optimizes string.format.

### System Requirements

- 32-bit compilation only (WoW 3.3.5a is 32-bit)
- Compatible with DXVK and LAA patch
- Works with standard and patched Wow.exe builds

---

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| Proxy DLL doesn't load | Use `wow_loader.exe`, or uncheck "Disable fullscreen optimizations" |
| `FATAL: MinHook initialization failed` | Another hook DLL conflicting |
| `ERROR: No CRT DLL found` | Non-standard WoW build |
| Socket shows `fail` | Normal — some opts need admin |
| Damage meters still broken | Remove CombatLogFix addon — two fixers conflict |
| `[UICache] DISABLED` | Non-standard build — method table not found |

---

## 📁 Project Structure

```
wow-optimize/
├── src/
│   ├── version.h                # Version defines (single source of truth)
│   ├── dllmain.cpp              # Main DLL — all system hooks + network stack
│   ├── lua_optimize.cpp/.h      # Lua VM optimizer (allocator + adaptive GC)
│   ├── combatlog_optimize.cpp/.h # Combat log optimizer
│   ├── ui_cache.cpp/.h          # UI widget cache (10 hooks, auto-discovered)
│   ├── api_cache.cpp/.h         # GetSpellInfo + GetItemInfo cache
│   ├── lua_fastpath.cpp/.h      # string.format fast path
│   ├── wow_loader.cpp           # Universal auto-loader executable
│   ├── version_proxy.cpp        # Auto-loader (version.dll proxy)
│   ├── version_exports.def      # Export definitions for version.dll
│   └── version.rc               # DLL version info resource
├── CMakeLists.txt
├── build.bat
├── README.md
└── LICENSE
```

---

## 📜 License

MIT License — use, modify, and distribute freely.