#pragma once
// ================================================================
//  Lua VM Optimizer Module for wow_optimize.dll
//  WoW 3.3.5a build 12340 (Warmane)
//  
//  Thanks for addresses to some ppl(my friend Choko especially) and also IDA Pro.
//
//  Usage:
//    Worker thread: LuaOpt::PrepareFromWorkerThread()
//    Main thread:   LuaOpt::OnMainThreadSleep(mainThreadId)
//    DLL unload:    LuaOpt::Shutdown()
// ================================================================

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
void OnMainThreadSleep(DWORD mainThreadId);

// Call on DLL unload.
void Shutdown();

// Combat mode (reduces GC during combat)
void SetCombatMode(bool inCombat);

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