# 🚀 wow_optimize

**Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)**  
Author: **SUPREMATIST**

wow_optimize improves WoW 3.3.5a at the **engine/runtime level**: memory allocation, Lua VM behavior, Lua library fast paths, deeper Lua VM internals, timers, file I/O, networking, heap fragmentation, lock contention, and other low-level bottlenecks.

The current branch is focused on **real frametime stability, long-session smoothness, addon-heavy gameplay, and lower VM/runtime overhead** while keeping historically unsafe public features disabled.

> ⚠️ **Disclaimer:** This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. Use at your own risk.

---

## ⭐ Reviews

See what other players say: [**Reviews & Testimonials**](https://github.com/suprepupre/wow-optimize/discussions/10)

---

## ✅ Current Feature Set

### Memory / Allocator
- **mimalloc CRT replacement** for `malloc/free/realloc/calloc/_msize`
- **Lua VM allocator replacement** with mimalloc
- **Lua string table pre-sizing** to reduce hash resize freezes
- **Low Fragmentation Heap (LFH)** enabled for process heap and new heaps
- **Periodic mimalloc purge** (`mi_collect`) for long-session memory stability

### Lua Runtime
- **Adaptive manual Lua GC**
- **4-tier GC stepping** (normal / combat / idle / loading)
- **GC step sync with !LuaBoost**
- **Safe Lua stats export to addon**
- **Lua reload detection and clean reinitialization**

### Lua Fast Paths
- **Phase 1: string.format fast path**
  - common format patterns accelerated
  - embedded-NUL / long-string safety retained
- **Phase 2: runtime-discovered Lua library hooks**
  - `string.find` (plain mode)
  - `type`
  - `math.floor`
  - `math.ceil`
  - `math.abs`
  - `math.max` (2 args)
  - `math.min` (2 args)
  - `string.len`
  - `string.byte` (single-byte fast path)
  - `tostring`
  - `tonumber`
  - `string.sub`
  - `string.lower`
  - `string.upper`

### Lua VM Internals
- **String interning cache** in `luaS_newlstr`
  - reduces repeated string interning lookup overhead for short hot strings
- **Fast small-string concatenation path** in `luaV_concat`
  - reduces overhead for common 2–3 operand concat cases

### Timers / Frame Pacing
- **PreciseSleep** on the main thread (adaptive for multi-client)
- **GetTickCount → QPC**
- **timeGetTime → same QPC timeline**
- **QueryPerformanceCounter coalescing cache**
- **Adaptive timer resolution**
  - single client: 0.5ms
  - multi-client: 1.0ms
- **Hardcoded FPS cap raised** (200 → 999)
- **Automatic multi-client detection**

### File I/O
- **MPQ handle tracking**
- **Retroactive MPQ handle scanner**
- **CreateFile sequential-scan hints for MPQ**
- **Adaptive MPQ read-ahead cache**
- **FlushFileBuffers skipped for MPQ handles**
- **GetFileAttributesA cache**
- **SetFilePointer redirected to SetFilePointerEx**

### Threading / Synchronization
- **SRWLOCK-based file cache**
- **Main thread priority ABOVE_NORMAL**
- **Ideal processor assignment**
- **Process priority ABOVE_NORMAL**
- **CriticalSection spin count + TryEnter spin-first path**
- **TLS-cached GetCurrentThreadId / pseudo-handle fast path**

### Networking
- **TCP_NODELAY**
- **Immediate ACK frequency**
- **Socket buffer tuning**
- **QoS / low-delay TOS**
- **Fast keepalive settings**

### Other Runtime Optimizations
- **Combat log optimizer**
- **GetItemInfo cache**
- **CompareStringA fast ASCII path**
- **OutputDebugStringA no-op when no debugger**
- **Fast VirtualQuery-based IsBadReadPtr / IsBadWritePtr**
- **Periodic stats dump**

---

## 🔒 Intentionally Disabled in Public-Safe Builds

These features are kept out of public-safe builds because they previously caused real regressions or crashes:

- **MPQ memory mapping**
- **UI widget cache**
- **GetSpellInfo cache**
- **dynamic unit API caching**
- **GlobalAlloc fast path**

---

## 🧠 What Improves In Practice

### You WILL notice
- ✅ smoother frametimes
- ✅ fewer random microstutters
- ✅ better long-session stability
- ✅ lower Lua/runtime overhead in addon-heavy gameplay
- ✅ less allocator fragmentation over time
- ✅ better responsiveness during heavy UI/addon workloads

### You may notice
- ✅ slightly better minimum FPS in cities/raids
- ✅ less “client gets heavier after long play”
- ✅ faster Lua-heavy UI behavior
- ✅ smoother loading transitions

### You should NOT expect
- ✗ a giant average FPS increase from one hook alone
- ✗ visual changes
- ✗ gameplay automation
- ✗ magical fixes for broken addons

This is an **engine/runtime optimization DLL**, not a UI overhaul.

---

## 🔧 Recommended Combo

For best results, use wow_optimize together with **[!LuaBoost](https://github.com/suprepupre/LuaBoost)**.

| Layer | Tool | Purpose |
|------|------|---------|
| Engine / C / Win32 | `wow_optimize.dll` | allocator, Lua VM, timers, file I/O, networking, runtime overhead reduction |
| Lua / Addons | `!LuaBoost` | GC control, loading helpers, table pool, update dispatcher, diagnostics |

---

## 📦 Installation

### Option A — Proxy Load
Copy into your WoW folder:
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

Then inject after WoW starts.

---

## 🎮 Multi-Client Support

wow_optimize automatically detects when multiple WoW instances are running.

- **Single client:** precise sleep + 0.5ms timer
- **Multi-client:** yield-based sleep + 1.0ms timer

This reduces CPU pressure compared to forcing aggressive single-client timing on all clients.

---

## 🛠 Building

### Requirements
- Windows 10/11
- Visual Studio with C++
- CMake
- **Win32 / 32-bit build**

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

## 📋 Core Architecture

### Main modules
- `dllmain.cpp` — Win32 hooks, allocator, timers, file I/O, networking, threading
- `lua_optimize.cpp` — Lua VM allocator, adaptive GC, Lua globals bridge
- `lua_fastpath.cpp` — string.format + runtime-discovered Phase 2 hooks
- `lua_internals.cpp` — deeper Lua VM hooks for string interning and concat
- `combatlog_optimize.cpp` — combat log retention + cleanup behavior
- `api_cache.cpp` — GetItemInfo cache
- `ui_cache.cpp` — disabled in public-safe build
- `version_proxy.cpp` — proxy loader
- `wow_loader.cpp` — standalone loader executable

---

## 🐛 Troubleshooting

### "The DLL loads but some old cache feature is missing"
That is expected. Several historically risky caches are intentionally disabled in public-safe builds.

### "Why is only GetItemInfo cached?"
Because `GetItemInfo` is stable once data is loaded. Many other APIs are not safe enough to cache without semantic regressions.

### "Antivirus flags the DLL"
Hooking/injection tools often trigger false positives. Review the source if needed.

### "I use DXVK/Vulkan"
That is fine. The project does not depend on D3D9 state-cache tricks.

### "Large pages: no permission"
This is informational, not a crash cause. Most systems do not have that policy enabled.

### "I use a custom / HD client"
Use extra caution. Public-safe builds keep the historically unsafe MPQ mapping path disabled, but heavily modified clients can still behave differently from stock clients.

---

## 📁 Project Structure

```text
wow-optimize/
├── src/
│   ├── dllmain.cpp
│   ├── lua_optimize.cpp / .h
│   ├── lua_fastpath.cpp / .h
│   ├── lua_internals.cpp / .h
│   ├── combatlog_optimize.cpp / .h
│   ├── api_cache.cpp / .h
│   ├── ui_cache.cpp / .h
│   ├── version.h
│   ├── version.rc
│   ├── version_proxy.cpp
│   ├── version_exports.def
│   └── wow_loader.cpp
├── CMakeLists.txt
├── README.md
└── LICENSE
```

---

## 📜 License

MIT License — use, modify, and distribute freely.