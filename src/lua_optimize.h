#pragma once
// Lua VM optimizer for WoW 3.3.5a build 12340.

#ifndef LUA_OPTIMIZE_H
#define LUA_OPTIMIZE_H

#include <windows.h>
#include <cstdint>

namespace LuaOpt {

// Call from worker thread. Validates addresses.
bool PrepareFromWorkerThread();

// Call from hooked_Sleep on main thread.
// First call: initializes GC + registers functions.
// Subsequent: incremental GC step.
void OnMainThreadSleep(DWORD mainThreadId, double frameMs = 0.0);

// Call on DLL unload.
void Shutdown();

// Combat mode (reduces GC during combat)
void SetCombatMode(bool inCombat);
// Returns true if client is in loading screen
bool IsLoadingMode();

struct Stats {
    bool   initialized;
    bool   gcOptimized;
    bool   allocatorReplaced;
    bool   functionsRegistered;
    double luaMemoryKB;
    int    gcStepsTotal;
    int    gcPause;
    int    gcStepMul;
};

Stats GetStats();

} // namespace LuaOpt

#endif