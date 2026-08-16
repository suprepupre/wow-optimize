#pragma once
#ifndef WOW_OPT_LUA_ADDON_SAMPLER_H
#define WOW_OPT_LUA_ADDON_SAMPLER_H

// Attributes main-thread samples to the addon whose Lua code is running.
//
// The client has a script profiler behind the scriptProfile CVar, and it is the
// only thing that has ever answered "which addon is costing me frames" here. It
// answers at a price: a reporter running it measured 1-4 fps in a dungeon and
// could not play, which means it cannot be used in the situation it exists for.
// It counts every entry and exit of every script.
//
// This asks the same question by sampling instead. The sampling profiler
// already stops the main thread a thousand times a second and reads its
// instruction pointer; while it is stopped, reading which Lua function is on
// top of the call stack costs a handful of loads and nothing at all on the
// paths being measured.
namespace LuaAddonSampler {

// Called once per sample by the profiler's thread, with the main thread
// suspended. Must not allocate, log, or take a lock.
void NoteSample();

// Printed from the periodic report, not from teardown - this DLL exits through
// TerminateProcess and a Shutdown-only counter never reaches a log.
void Report();

void Reset();

} // namespace LuaAddonSampler

#endif
