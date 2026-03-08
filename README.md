# 🚀 wow_optimize v1.5.0 BY SUPREMATIST

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
| 4 | **TCP\_NODELAY** | Disables Nagle's algorithm on all sockets (lower ping) |
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
| 16 | **Combat Log Optimizer** | Prevents combat log data loss in raids (retention + cleanup + entry pool) |

---

## 🆕 What's New in v1.5.0

### Combat Log Entry Pool
- **Pre-allocates 4096 entries** (480 KB) into the engine's internal free list
- During AoE combat in 25-man raids, the combat log allocator (`sub_750400`) previously had to call `SMemAlloc` for every new event — **500-1000 heap allocations per second**
- Now the free list is always full — the engine grabs pre-made entries instantly, **zero heap allocation during combat**
- Uses the engine's own `EntryInit` (0x74D920) and `FreeListInsert` (0x86E200) functions — **zero code patching**
- Deferred injection: waits until the CVar system is ready before filling the pool

### Universal Loader (wow_loader.exe)
- **Works with ANY Wow.exe** — patched, custom, standard
- Launches `Wow.exe` in suspended state, injects `wow_optimize.dll`, then resumes
- **Single click** — no manual injection needed
- If injection fails, WoW still starts normally with a warning
- Logs to `Logs/wow_loader.log`
- Alternative to `version.dll` proxy for servers with modified executables

---

## 🤔 What Changes In Practice

This is **not** a magic FPS doubler. Think of it like replacing an HDD with an SSD — same benchmarks, but everything *feels* smoother.

### You WILL notice

- ✅ Fewer random micro-stutters (especially Lua GC stalls)
- ✅ More stable minimum FPS (less variance between frames)
- ✅ Smoother frame pacing (no more Sleep jitter)
- ✅ Less lag degradation over long sessions (2+ hours)
- ✅ Lower network latency (spells feel more responsive)
- ✅ Faster zone loading
- ✅ Reduced lag spikes on boss kills and dungeon queue pops
- ✅ No more broken damage meters in 25-man raids
- ✅ **NEW:** No micro-freezes during AoE combat (entry pool eliminates heap alloc)

### You WON'T notice

- ✗ Average FPS won't jump dramatically
- ✗ No visual changes
- ✗ No in-game notifications

### Where it matters most

- 🏰 Dalaran / Stormwind with many players
- ⚔️ 25-man raids (ICC, RS) with heavy addon usage
- ⏱️ Long play sessions without restarting the client
- 🌐 High-latency connections (TCP\_NODELAY helps most here)
- 📊 Damage meters during intense AoE fights

---

## 🔧 Recommended Combo

For maximum optimization, use this DLL together with the **[!LuaBoost](https://github.com/suprepupre/LuaBoost)** addon:

| Layer | Tool | What It Does |
|-------|------|--------------|
| **C / Engine** | wow\_optimize.dll | Faster memory, I/O, network, timers, Lua allocator + GC from C, combat log fix + pool |
| **Lua / Addons** | !LuaBoost addon | Incremental GC, SpeedyLoad, table pool, throttle API, GUI |

When both are installed, the DLL handles Lua allocator replacement, GC stepping from C (zero Lua overhead), and combat log buffering. The addon provides the GUI, combat awareness, idle detection, SpeedyLoad, and runtime function optimizations.

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
[02:42:28.155]   wow_optimize.dll v1.5.0 BY SUPREMATIST
[02:42:28.155]   PID: 13088
[02:42:28.155] ========================================
[02:42:28.155] MinHook initialized
[02:42:28.165] mimalloc configured (large pages, pre-warmed 64MB)
[02:42:28.183] >>> ALLOCATOR: mimalloc ACTIVE <<<
[02:42:28.197] Sleep hook: ACTIVE (frame pacing + Lua GC + combat log)
[02:42:28.215] GetTickCount hook: ACTIVE
[02:42:28.238] CriticalSection hook: ACTIVE
[02:42:28.254] Network hook: ACTIVE
[02:42:28.288] CreateFile hooks: ACTIVE
[02:42:28.305] ReadFile hook: ACTIVE
[02:42:28.322] CloseHandle hook: ACTIVE
[02:42:28.322] Timer resolution: 0.500 ms
[02:42:28.338] Main thread: ideal core 1, priority HIGHEST
[02:42:28.338] Process: Above Normal priority
[02:42:28.338] Working set: min 256 MB, max 2048 MB
[02:42:28.338] FPS cap: changed from 200 to 999
[02:42:28.340] [CombatLog]  [ OK ] Retention time (300 -> 1800 sec)
[02:42:28.340] [CombatLog]  [ OK ] Periodic clear (every 600 frames)
[02:42:28.340] [CombatLog]  [WAIT] Entry pool (4096 entries, 480 KB)
[02:42:38.789] [LuaOpt]  >>> ALLOCATOR REPLACED <<<
[02:42:39.100] [CombatLog-Pool]  [ OK ] Injected 4096 entries into free list
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

DLL reads addon globals per-frame from the Sleep hook (main thread).
```

> **Why not `lua_pushcclosure`?** WoW validates C function pointers passed to Lua. If the pointer is outside Wow.exe's code section, WoW crashes with `Fatal condition: Invalid function pointer`. The DLL creates pure Lua wrapper functions via `FrameScript_Execute` instead — these are safe.

---

## 📊 Combat Log Optimizer

### The Problem

In 25-man raids (ICC, RS) with addons like DBM, WeakAuras, and Skada running simultaneously, the combat log loses events. Damage meters show incomplete data, often called "combat log breaks." Additionally, heavy AoE combat causes micro-stutters from hundreds of heap allocations per second.

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
4. Not expired → allocate new node from heap (**SLOW**)

Step 3 is the data loss bug. Step 4 is the micro-stutter source.

### The Fix (3 Layers)

| Layer | What | How |
|-------|------|-----|
| **Retention** | Prevent premature recycling | CVar `BD09F0+0x30`: 300 → 1800 seconds |
| **Cleanup** | Prevent list corruption | Periodic `CombatLogClearEntries` from Sleep hook |
| **Entry Pool** | Eliminate heap allocation | Pre-fill free list with 4096 entries via `EntryInit` + `FreeListInsert` |

### Entry Pool Details

```
Without pool (vanilla behavior):
  AoE event → sub_750400 → free list empty → sub_74F2D0 → SMemAlloc
  500 events/sec = 500 heap allocations/sec = MICRO-STUTTERS

With pool (wow_optimize v1.5.0):
  At startup: 4096 entries pre-allocated via mimalloc (480 KB)
            → Each initialized via engine's EntryInit (0x74D920)
            → Each inserted via engine's FreeListInsert (0x86E200)
            → Free list is pre-filled with 4096 ready-to-use entries
  
  AoE event → sub_750400 → free list HAS entries → instant grab
  500 events/sec = 0 heap allocations = SMOOTH

  After use: entries return to free list via normal recycling
           → Pool entries are reused indefinitely
```

### Memory Impact

Pool: 4096 × 120 bytes = 480 KB (one-time allocation, never freed).
Retention: at 500 events/sec × 120 bytes × 1800 sec = ~103 MB worst case. In practice much less because the periodic cleanup frees processed entries continuously.

### Replacing CombatLogFix Addon

If you use the CombatLogFix addon (from KPack or standalone), you can **remove it**. The DLL does the same job from C level without any Lua overhead.

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

### Combat Log Entry Lifecycle

```
New event → sub_750400 (alloc from free list or pool)
         → populate entry (GUIDs, spell info, flags)
         → sub_74F910 (push to Lua via CA1394)
         → addon processes COMBAT_LOG_EVENT_UNFILTERED
         → CA1394 advances to next entry
         ...
         → DLL cleanup: entry expired + processed → sub_750390 (recycle)
         → sub_86E200 (insert back into free list)
         → entry reused for next event (no heap alloc!)
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

- ✅ Hooks system-level functions (`malloc`, `free`, `Sleep`, `connect`, `ReadFile`)
- ✅ Calls Lua VM GC API for performance tuning (read-only stats + GC stepping)
- ✅ Patches combat log retention (write to CVar value)
- ✅ Pre-fills combat log free list (no code patching, uses engine functions)

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

![Disable fullscreen optimizations](screenshots/wow.exe%20properties.png)

---

| Problem | Solution |
|---------|----------|
| Proxy DLL doesn't load (no log file) | Use `wow_loader.exe` instead, or check compatibility settings above |
| WoW crashes after injection | Wait for login screen + 10 seconds before injecting |
| `FATAL: MinHook initialization failed` | Another hook DLL conflicting |
| `ERROR: No CRT DLL found` | Non-standard WoW build |
| Lua optimizer shows `SKIP` | Lua addresses not found (different build?) |
| `Invalid function pointer` crash | Old DLL version — update to v1.5+ |
| `Large pages: no permission` | Normal — requires admin policy change, optional |
| Combat log shows `SKIP` | CVar pointer not valid yet — try injecting later |
| Combat log pool shows `SKIP` | Missing EntryInit or FreeListInsert functions (different build?) |
| Damage meters still broken | Remove CombatLogFix addon if present — two fixers may conflict |
| No noticeable difference | Expected on high-end PCs with few addons |
| wow_loader.exe shows warning | Check `Logs/wow_loader.log` for details |

---

## 📁 Project Structure

```
wow-optimize/
├── src/
│   ├── dllmain.cpp              # Main DLL — all system hooks
│   ├── lua_optimize.cpp         # Lua VM optimizer (allocator + GC + communication)
│   ├── lua_optimize.h           # Lua optimizer interface
│   ├── combatlog_optimize.cpp   # Combat log optimizer (retention + cleanup + pool)
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