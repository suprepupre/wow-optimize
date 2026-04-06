# wow_optimize

Performance optimization DLL for World of Warcraft 3.3.5a (WotLK)  
Author: SUPREMATIST

wow_optimize improves WoW 3.3.5a at the engine and runtime level: memory allocation, Lua VM behavior, Lua library fast paths, timers, file I/O, networking, heap fragmentation, lock contention, and other low-level bottlenecks.

The current public build is focused on real frametime stability, long-session smoothness, addon-heavy gameplay, and lower Lua/runtime overhead while keeping historically unsafe public features disabled.

> Disclaimer: This project is provided as-is for educational purposes. DLL injection may violate the Terms of Service of private servers. Use at your own risk.

---

## Reviews

See what other players say: [Reviews and Testimonials](https://github.com/suprepupre/wow-optimize/discussions/10)

---

## Current Feature Set

### Memory and allocator
- mimalloc CRT replacement for `malloc/free/realloc/calloc/_msize`
- Lua VM allocator replacement with mimalloc
- Lua string table pre-sizing to reduce hash resize spikes
- Low Fragmentation Heap (LFH) enabled for process heap and new heaps
- periodic mimalloc purge for long-session memory stability

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

### Lua fast paths
- Phase 1:
  - `string.format`
- Phase 2:
  - `string.find` (plain mode)
  - `string.match` (safe partial fast path)
  - `type`
  - `math.floor`
  - `math.ceil`
  - `math.abs`
  - `math.max` (2 args)
  - `math.min` (2 args)
  - `string.len`
  - `string.byte`
  - `tostring`
  - `tonumber`
  - `next`
  - `rawget`
  - `rawset`
  - `table.insert` (append-only fast path)
  - `table.remove` (pop-last fast path)
  - `table.concat` (single-pass, SEH-guarded)
  - `unpack` (dense array fast path)
  - `select` (fast index & "#" count)
  - `rawequal` (direct TValue comparison)
  - `string.sub`
  - `string.lower`
  - `string.upper`

### Lua VM internals
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
- fast keepalive settings

### Other runtime optimizations
- combat log optimizer
- `GetItemInfo` cache
- `CompareStringA` fast ASCII path
- `OutputDebugStringA` no-op when no debugger
- fast `IsBadReadPtr` / `IsBadWritePtr`
- periodic stats dump

---

## Intentionally Disabled in Public-Safe Builds

These features remain disabled in public-safe builds because they previously caused regressions or crashes:

- MPQ memory mapping
- UI widget cache
- GetSpellInfo cache
- dynamic unit API caching
- GlobalAlloc fast path
- `luaS_newlstr` string cache (removed due to 0xC0000005 crashes on reload)
- `luaV_concat` hook (removed due to 0% hit-rate overhead)

---

## What Improves In Practice

### You will notice
- smoother frametimes
- fewer random microstutters
- better long-session smoothness
- lower Lua overhead in addon-heavy gameplay
- less allocator fragmentation over time
- better responsiveness during heavy UI and addon workloads

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

### Option A - Proxy load
Copy into your WoW folder:
- `version.dll`
- `wow_optimize.dll`

Then launch WoW normally.

### Option B - Loader
Copy:
- `wow_loader.exe`
- `wow_optimize.dll`

Then launch `wow_loader.exe`.

### Option C - Manual injection
Copy:
- `wow_optimize.dll`
- your injector

Then inject after WoW starts.

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

## Building

### Requirements
- Windows 10 or 11
- Visual Studio with C++
- CMake
- Win32 / 32-bit build

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

## Core Architecture

### Main modules
- `dllmain.cpp` - Win32 hooks, allocator, timers, file I/O, networking, threading
- `lua_optimize.cpp` - Lua VM allocator, adaptive GC, Lua globals bridge
- `lua_fastpath.cpp` - `string.format` and runtime-discovered Phase 2 hooks
- `lua_internals.cpp` - stable VM baseline (disabled unsafe hooks)
- `combatlog_optimize.cpp` - combat log retention and cleanup behavior
- `api_cache.cpp` - `GetItemInfo` cache
- `ui_cache.cpp` - disabled in public-safe build
- `version_proxy.cpp` - proxy loader
- `wow_loader.cpp` - standalone loader executable

---

## Troubleshooting

### "Antivirus flags the DLL"
Hooking and injection tools often trigger false positives. Review the source if needed.

### "I use DXVK or Vulkan"
That is fine. The project does not depend on D3D9 state-cache tricks.

### "Large pages: no permission"
This is informational, not a crash cause. Most systems do not have that policy enabled.

---

## Project Structure

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

## License

MIT License - use, modify, and distribute freely.