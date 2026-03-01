# 🚀 wow_optimize

**Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)**

Replaces WoW's ancient memory allocator, optimizes I/O, network, timers, threading, and frame pacing — all through a single injectable DLL.

> ⚠️ **Disclaimer:** This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. **No ban has been reported**, but **use at your own risk.** The authors are not responsible for any consequences including but not limited to account suspensions. Always test on a throwaway account first.

---

## ✨ Features

| # | Feature | What It Does |
|---|---------|--------------|
| 1 | **mimalloc Allocator** | Replaces msvcr80 `malloc`/`free` with Microsoft's modern allocator |
| 2 | **Sleep Hook** | Precise frame pacing via QPC busy-wait (eliminates Sleep jitter) |
| 3 | **TCP\_NODELAY** | Disables Nagle's algorithm on all sockets (lower ping) |
| 4 | **GetTickCount Hook** | QPC-based microsecond precision (better internal timers) |
| 5 | **CriticalSection Spin** | Adds spin count to all locks (fewer context switches) |
| 6 | **ReadFile Cache** | 64KB read-ahead cache for MPQ files (faster loading) |
| 7 | **CreateFile Hints** | Sequential scan flags for MPQ (OS prefetch optimization) |
| 8 | **Timer Resolution** | 0.5ms system timer via NtSetTimerResolution |
| 9 | **Thread Affinity** | Pins main thread to optimal core (stable L1/L2 cache) |
| 10 | **Working Set** | Locks 256MB–2GB in RAM (prevents page-outs) |
| 11 | **Process Priority** | Above Normal + disabled priority boost |
| 12 | **FPS Cap Removal** | Raises hardcoded 200 FPS limit to 999 |

---

## 🤔 What Changes In Practice

This is **not** a magic FPS doubler. Think of it like replacing an HDD with an SSD — same benchmarks, but everything *feels* smoother.

### You WILL notice

- ✅ Fewer random micro-stutters
- ✅ More stable minimum FPS (less variance between frames)
- ✅ Smoother frame pacing (no more Sleep jitter)
- ✅ Less lag degradation over long sessions (2+ hours)
- ✅ Lower network latency (spells feel more responsive)
- ✅ Faster zone loading

### You WON'T notice

- ✗ Average FPS won't jump dramatically
- ✗ No visual changes
- ✗ No in-game notifications

### VIDEO DEMONSTATION ON WARMANE LORDAERON

[VIDEO](https://www.youtube.com/watch?v=mDswd1cGJ24)

### Where it matters most

- 🏰 Dalaran / Stormwind with many players
- ⚔️ 25-man raids (ICC, RS) with heavy addon usage
- ⏱️ Long play sessions without restarting the client
- 🌐 High-latency connections (TCP\_NODELAY helps most here)

---

## 📦 Building

### Requirements

- **Windows 10/11**
- **Visual Studio 2022** (or 2019) with **"Desktop development with C++"** workload
- **CMake** (included with Visual Studio)
- **Internet connection** (first build downloads mimalloc and MinHook automatically)

### Build Steps

git clone https://github.com/suprepupre/wow-optimize.git
cd wow_optimize
build.bat

Output: `build\Release\wow_optimize.dll`

> ⚠️ **Must be compiled as 32-bit (Win32).** WoW 3.3.5a is a 32-bit application. A 64-bit DLL will not load.

### Manual Build (without build.bat)

mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A Win32 ..
cmake --build . --config Release


---

---

## 📥 Quick Install (No Building Required)

If you don't want to compile anything, just download the pre-built release:

1. Go to [**Releases**](../../releases/latest)
2. Download `wow_optimize.zip`
3. Extract the archive. You will get:
    
wow_optimize/
 
├──wow_optimize.dll # The optimization DLL

├── Dll_Injector.exe # Simple DLL injector

└── inject.bat # One-click injection script

4. Copy **all three files** to your World of Warcraft folder (same directory as `Wow.exe`):
5. Launch `Wow.exe` and **wait for the login screen**
6. Double-click **`inject.bat`**
7. You should see:

=================================

wow_optimize.dll injector

[+] The process wow.exe was found in memory.
[+] DLL injection successful!

Press any key to close...

8. Done! Check `wow_optimize.log` to verify all optimizations are active

> 💡 **Tip:** You only need to inject once per game session. If you restart WoW, inject again.

## 🎮 Usage

### Option A — One-Click (recommended)

1. Download the [latest release](../../releases/latest) and extract to your WoW folder
2. Launch `Wow.exe` → wait for login screen
3. Double-click `inject.bat`
4. Check `wow_optimize.log` to verify

### Option B — Manual Injection

If you prefer to use your own injector:

1. Copy `wow_optimize.dll` to your WoW folder
2. Launch `Wow.exe` → wait for login screen
3. Inject using any DLL injector:

### Step 4 — Verify

Open `wow_optimize.log` in your WoW folder. You should see:

```
[22:59:07.520] ========================================
[22:59:07.520]   wow_optimize.dll 
[22:59:07.520]   PID: 31380
[22:59:07.520] ========================================
[22:59:07.520] MinHook initialized
[22:59:07.528] mimalloc configured (eager commit, pre-warmed 64MB)
[22:59:07.606] >>> ALLOCATOR: mimalloc ACTIVE <<<
[22:59:07.685] Sleep hook: ACTIVE
[22:59:07.685] GetTickCount hook: ACTIVE
[22:59:07.685] CriticalSection hook: ACTIVE
[22:59:07.763] Network hook: ACTIVE
[22:59:07.763] CreateFile hooks: ACTIVE
[22:59:07.763] ReadFile hook: ACTIVE
[22:59:07.764] Timer resolution: 0.500 ms
[22:59:07.840] Main thread: ideal core 1, priority HIGHEST
[22:59:07.840] Process: Above Normal priority
[22:59:07.840] Working set: min 256 MB, max 2048 MB
[22:59:07.840] FPS cap: changed from 200 to 999
[22:59:07.840] ========================================
[22:59:07.840]   Initialization complete
[22:59:07.840] ========================================
[22:59:07.840]
[22:59:07.840]   [ OK ] mimalloc allocator
[22:59:07.840]   [ OK ] Sleep hook (frame pacing)
[22:59:07.840]   [ OK ] GetTickCount (precision)
[22:59:07.840]   [ OK ] CriticalSection (spin lock)
[22:59:07.840]   [ OK ] TCP_NODELAY (network)
[22:59:07.840]   [ OK ] CreateFile (sequential I/O)
[22:59:07.840]   [ OK ] ReadFile (read-ahead cache)
[22:59:07.840]   [ OK ] Timer resolution (0.5ms)
[22:59:07.840]   [ OK ] Thread affinity + priority
[22:59:07.840]   [ OK ] Working set (256MB-2GB)
[22:59:07.840]   [ OK ] Process priority (Above Normal)
[22:59:07.840]   [ OK ] FPS cap removal (200 -> 999)
```

All `[ OK ]` = everything is working. Any `[FAIL]` entries will have an explanation in the log above them.

---

## 🧠 Technical Details

### Safe Allocator Transition

Memory allocated **before** injection (by the old CRT allocator) is detected using `mi_is_in_heap_region()` and freed through the **original** `free()`. Memory allocated **after** injection goes through mimalloc. No crashes, no heap corruption.

```
Before injection:
  malloc() → old CRT heap
  free()   → old CRT heap

After injection:
  malloc() → mimalloc heap
  free()   → checks which heap owns the pointer
              ├── mimalloc pointer → mi_free()
              └── old pointer      → original free()
```

### CRT Auto-Detection

The DLL automatically detects whichever C runtime WoW loaded:

| DLL | Compiler |
|-----|----------|
| `msvcr80.dll` | Visual C++ 2005 (original WoW 3.3.5a) |
| `msvcr90.dll` | Visual C++ 2008 |
| `msvcr100.dll` | Visual C++ 2010 |
| `msvcr110.dll` | Visual C++ 2012 |
| `msvcr120.dll` | Visual C++ 2013 |
| `ucrtbase.dll` | Visual C++ 2015+ (Universal CRT) |
| `msvcrt.dll` | System CRT |

### Dependencies

All dependencies are downloaded automatically by CMake during the first build.

| Library | Version | Purpose | License |
|---------|---------|---------|---------|
| [mimalloc](https://github.com/microsoft/mimalloc) | 3.2.8 | Memory allocator | MIT |
| [MinHook](https://github.com/TsudaKageyu/minhook) | latest | Function hooking | BSD 2-Clause |

---

## 🔧 Recommended Combo

For maximum optimization, use this DLL together with the **[SmartGC](https://github.com/suprepupre/SmartGC)** addon:

| Layer | Tool | What It Does |
|-------|------|--------------|
| **C / Engine** | wow\_optimize.dll | Faster malloc/free, I/O, network, timers, threads |
| **Lua / Addons** | SmartGC addon | Incremental garbage collection, eliminates Lua GC stutter |

Together they cover **both** levels of memory management in WoW — the C engine and the Lua scripting layer.

---

## ⚠️ Important Notes

### Anti-Cheat (Warden)

**No bans have been reported** from using this DLL. However, DLL injection is inherently detectable by anti-cheat systems.

What this DLL does **NOT** do:

- ❌ Does not modify `Wow.exe` on disk
- ❌ Does not provide any gameplay advantage
- ❌ Does not read or write game-specific memory (packets, player data, etc.)
- ❌ Does not automate any gameplay actions

What this DLL **does**:

- ✅ Hooks system-level functions only (`malloc`, `free`, `Sleep`, `connect`, `ReadFile`)
- ✅ All optimizations are generic performance improvements

> **Use at your own risk.** Always test on a throwaway account first. The authors are not responsible for any account actions taken by server administrators.

### System Requirements

- **32-bit compilation only** — WoW 3.3.5a is a 32-bit application
- **Inject AFTER login screen** — WoW needs to fully initialize first
- **One injection per session** — inject once, plays for the entire session
- **Compatible with DXVK** — no conflicts with Vulkan wrapper
- **Compatible with LAA patch** — works alongside Large Address Aware

---

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| WoW crashes immediately after injection | Inject later — wait for login screen, then wait 10 more seconds before injecting |
| Log says `FATAL: MinHook initialization failed` | Another hook DLL may be conflicting. Remove other injected DLLs |
| Log says `ERROR: No CRT DLL found` | Non-standard WoW build. Open an issue with your log file attached |
| Log says `FAIL` on some hooks | Some hooks are optional. As long as `mimalloc ACTIVE` shows, the main optimization works |
| `wow_optimize.log` doesn't exist | DLL was not loaded. Verify your injector is targeting the correct process |
| No noticeable difference | Expected on high-end PCs. Difference is most visible during long sessions and in crowded areas |
| FPS cap pattern not found | Different WoW build or version. Cap removal is optional — everything else still works |
| `Large pages: no permission` | Normal. Requires admin policy change. All other features work without it |

---

## 📁 Project Structure

```
wow_optimize/
├── src/
│   └── dllmain.cpp         # All source code (single file)
├── CMakeLists.txt           # Build configuration + dependency management
├── build.bat                # One-click build script
├── README.md                # This file
├── LICENSE                  # MIT License
└── .gitignore               # Git ignore rules
```

---

## 📜 License

MIT License — use, modify, and distribute freely. See [LICENSE](LICENSE) for full text.
