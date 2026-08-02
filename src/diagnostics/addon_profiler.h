#pragma once

// ============================================================================
// Module: addon_profiler.h
//
// Turns on the client's own script profiler and reports per-addon CPU cost to
// the log, ranked. Measures nothing itself - the client already can, behind the
// scriptProfile CVar that nothing in the default UI exposes.
// ============================================================================

#ifndef ADDON_PROFILER_H
#define ADDON_PROFILER_H

namespace AddonProfiler {

bool Init();

// From the main-thread pump. Runs Lua, so it must not be called from anywhere
// else; pass luaBusy when the interface is loading or swapping state.
void OnFrame(bool luaBusy);

void Shutdown();

} // namespace AddonProfiler

#endif // ADDON_PROFILER_H
