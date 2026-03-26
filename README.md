# 🚀 wow_optimize 

**Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)**  
Author: **SUPREMATIST**

wow_optimize improves WoW 3.3.5a at the **engine/runtime level**: memory allocation, Lua VM behavior, timers, file I/O, networking, heap fragmentation, lock contention, and other low-level bottlenecks.

The current public build focuses on **safe system-level optimizations** that improve frametime stability, long-session smoothness, loading behavior, and addon-heavy gameplay **without breaking UI logic**.

> ⚠️ **Disclaimer:** This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. Use at your own risk.

---

## ⭐ Reviews

See what other players say: [**Reviews & Testimonials**](https://github.com/suprepupre/wow-optimize/discussions/10)

---

## ✅ Current Public Feature Set

### Memory / Allocator
- **mimalloc CRT replacement** for `malloc/free/realloc/calloc/_msize`
- **Lua VM allocator replacement** with mimalloc
- **Lua string table pre-sizing** to reduce hash resize freezes
- **Low Fragmentation Heap (LFH)** enabled for process heap and new heaps
- **Periodic mimalloc purge** to reduce long-session memory pressure

### Lua Runtime
- **Adaptive manual Lua GC**
- **4-tier GC stepping** (normal / combat / idle / loading)
- **GC step sync with !LuaBoost**
- **Safe Lua stats export to addon**
- **Lua reload detection and clean reinitialization**

### Timers / Frame Pacing
- **PreciseSleep** on the main thread
- **GetTickCount → QPC**
- **timeGetTime → same QPC timeline**
- **0.5ms timer resolution**
- **Hardcoded FPS cap raised**

### File I/O
- **MPQ handle tracking**
- **CreateFile sequential-scan hints for MPQ**
- **Adaptive MPQ read-ahead cache**
  - 64KB during gameplay
  - 256KB during loading screens
- **FlushFileBuffers skipped for read-only MPQ handles**
- **GetFileAttributesA cache**
- **SetFilePointer redirected to SetFilePointerEx**

### Threading / Synchronization
- **Main thread priority ABOVE_NORMAL**
- **Ideal processor assignment**
- **Process priority ABOVE_NORMAL**
- **CriticalSection spin count**
- **TryEnterCriticalSection spin-first path**
- **TLS-cached GetCurrentThreadId / pseudo-handle fast path**

### Networking
- **TCP_NODELAY**
- **Immediate ACK frequency**
- **Socket buffer tuning**
- **QoS / low-delay TOS**
- **Fast keepalive settings**

### Other Runtime Optimizations
- **Combat log optimizer** (retention + periodic clear)
- **string.format fast path**
- **CompareStringA fast ASCII path**
- **OutputDebugStringA no-op when no debugger**
- **Fast VirtualQuery-based IsBadReadPtr / IsBadWritePtr**

---

## 🧠 What Actually Improves In Practice

### You WILL notice
- ✅ Smoother frametimes
- ✅ Fewer random microstutters
- ✅ Better long-session stability
- ✅ Better loading behavior
- ✅ Lower CPU overhead in addon-heavy environments
- ✅ Less allocator fragmentation over time
- ✅ More responsive networking

### You may notice
- ✅ Slightly better minimum FPS in raids/cities
- ✅ Faster zone transitions
- ✅ Less “client feels worse after 2+ hours” behavior

### You should NOT expect
- ✗ Massive average FPS increase from one feature alone
- ✗ Visual changes
- ✗ Any UI redesign
- ✗ Any addon-specific magic fix

This is an **engine-side optimization DLL**, not a UI overhaul.

---

## 🔧 Recommended Combo

For best results, use wow_optimize together with **[!LuaBoost](https://github.com/suprepupre/LuaBoost)**.

| Layer | Tool | Purpose |
|------|------|---------|
| Engine / C / Win32 | `wow_optimize.dll` | Memory, GC, timers, file I/O, networking, runtime overhead reduction |
| Lua / Addons | `!LuaBoost` | GC control, loading behavior, table pool, update dispatcher, diagnostics |

---

## 📦 Installation

### Option A — Proxy Load (recommended)
Copy these into your WoW folder:
- `version.dll`
- `wow_optimize.dll`

Then launch WoW normally.

### Option B — Loader
Copy:
- `wow_loader.exe`
- `wow_optimize.dll`

Then launch `wow_loader.exe`.

### Option C — Manual Injection
Copy:
- `wow_optimize.dll`
- your injector
- optional helper batch script

Then inject after WoW starts.

---

## 🛠 Building

### Requirements
- Windows 10/11
- Visual Studio with C++
- CMake
- **Win32 / 32-bit build** (WoW 3.3.5a is 32-bit)

### Build
```bash
git clone https://github.com/suprepupre/wow-optimize.git
cd wow-optimize
build.bat
```

Output:
- `build\Release\wow_optimize.dll`
- `build\Release\version.dll`
- `build\Release\wow_loader.exe`

---

## 📋 Current Architecture

### Core modules
- `dllmain.cpp` — Win32 hooks, allocator, timers, file I/O, networking, threading
- `lua_optimize.cpp` — Lua VM allocator, adaptive GC, Lua globals bridge
- `combatlog_optimize.cpp` — combat log retention + clear fix
- `api_cache.cpp` — currently **GetItemInfo only**
- `lua_fastpath.cpp` — optimized `string.format`
- `ui_cache.cpp` — currently stubbed / disabled in public build
- `version_proxy.cpp` — proxy `version.dll` loader
- `wow_loader.cpp` — standalone loader executable

---

## 📁 Project Structure

```text
wow-optimize/
├── src/
│   ├── dllmain.cpp
│   ├── lua_optimize.cpp / .h
│   ├── combatlog_optimize.cpp / .h
│   ├── api_cache.cpp / .h
│   ├── ui_cache.cpp / .h
│   ├── lua_fastpath.cpp / .h
│   ├── version.h
│   ├── version.rc
│   ├── version_proxy.cpp
│   ├── version_exports.def
│   └── wow_loader.cpp
├── CMakeLists.txt
├── build.bat
├── inject.bat
├── README.md
└── LICENSE
```

---

## 🔍 Notes On Safety

### Why the public build is stricter now
Several earlier “smart” optimizations looked correct in synthetic testing, but failed in real addon ecosystems.

The current release philosophy is:

> **If a feature can break addon semantics, it does not belong in the public build.**

That is why:
- UI cache is disabled
- GetSpellInfo cache is disabled
- only truly safe caches remain public

---

## 🐛 Troubleshooting

### “The DLL loads but I see no UI cache”
That is expected. UI cache is intentionally disabled in public builds.

### “Why is only GetItemInfo cached?”
Because `GetItemInfo` is static once item data is loaded. `GetSpellInfo` and most unit APIs are not safe enough in practice.

### “Antivirus flags the DLL”
Hooking/injection tools often trigger false positives. Review the source if needed.

### “I use DXVK/Vulkan”
That’s fine. The project does **not** depend on OpenGL-specific optimizations.

---

## 📜 License

MIT License — use, modify, and distribute freely.