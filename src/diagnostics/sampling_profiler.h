#pragma once

// ============================================================================
// Module: sampling_profiler.h
// ============================================================================










// ================================================================
// Sampling Profiler — lightweight in-DLL EIP sampler
// ================================================================
// A background thread samples the main thread's EIP every ~1ms via
// SuspendThread/GetThreadContext/ResumeThread, buckets each sample
// by the nearest known function, and dumps the top-N hot functions
// to the log on shutdown.
//
// This fixes the project's core blind spot: xrefs ≠ runtime frequency.
// Every future optimization becomes data-driven instead of a guess.
//
// Read-only sampling — no hooks into WoW code, no writes to WoW memory.
// Risk class: very low (same API family as crash dumpers use).
// ================================================================

#include <windows.h>
#include <cstdint>

namespace SamplingProfiler {

// Initialize the profiler. Stores the main thread handle for sampling.
// Call after the main thread ID is known (post-injection delay).
bool Init(HANDLE mainThread);

// Stop the sampling thread and dump results to the log.
// Call during DLL shutdown before closing handles.
void Shutdown();

// Returns true if the profiler is actively sampling.
bool IsActive();

// Get total number of samples collected (for diagnostics).
uint64_t GetSampleCount();

// Dump the current top-50 hot functions to the log without stopping sampling.
// Called from the periodic stats dump so the profile is captured even when the
// fast process-exit path skips Shutdown().
void DumpNow();

// Names one of our own functions so the profile can say which of this DLL's hooks
// is costing time.
//
// Samples landing inside wow_optimize.dll are reported as "wowopt+0x3EF00". That
// offset is only meaningful against the .map of the exact build that produced the
// log, and tester logs routinely arrive from builds several commits old, by which
// point every offset has moved. A CPU-bound session had 7.6% of its samples in
// this DLL and there was no way to say which part.
//
// Call it at install time with the detour's own address. Costs one array slot and
// nothing at sample time - resolution happens only when the profile is printed.
void RegisterSelfSymbol(const char* name, const void* addr);

// What share of the profile sits inside [lo, hi). For a module that changes how
// often some client code runs and wants to report the cost of having done so,
// rather than only the cost of its own work.
//
// Measured over the same window the periodic dump uses - the last RING_SIZE
// samples - and never over the lifetime total. Dividing a windowed count by a
// lifetime total is what understated every percentage this profiler printed
// before 133c4456 by 5.6x.
//
// Returns false when there is nothing to answer with: profiler off, or fewer
// than `minSamples` samples in the window. A caller that gets false must say it
// could not see this rather than print a zero.
bool ShareForRange(uintptr_t lo, uintptr_t hi, unsigned long minSamples,
                   double* outPercent, unsigned long* outSamples,
                   unsigned long* outWindow);

} // namespace SamplingProfiler