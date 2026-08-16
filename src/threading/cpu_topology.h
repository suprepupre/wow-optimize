#pragma once
#ifndef WOW_OPT_CPU_TOPOLOGY_H
#define WOW_OPT_CPU_TOPOLOGY_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

// What kind of core the main thread is actually running on.
//
// A hybrid CPU (Intel Alder Lake onward, 2021) has performance cores and
// efficiency cores, and Windows decides between them from thread telemetry. A
// 2010 client that sleeps its way through every frame reads as a light load,
// which is exactly the profile that gets moved onto an efficiency core - and
// this client does nearly all its work on one thread, so that decision costs
// most of a frame.
//
// This is measured before it is acted on: the core the main thread runs on is
// sampled every frame, the residency is reported per class, and the pinning is
// a separate switch. If the frame loop already stays on performance cores there
// is nothing here to fix and the report says so.
namespace CpuTopology {

// Reads the topology and logs it. Safe on any Windows: the CPU set API is
// resolved at runtime and its absence is reported rather than assumed away.
void Init();

// One GetCurrentProcessorNumber on the frame boundary. Cheap enough to run
// unconditionally when the feature is on.
void NoteFrame();

// Pins the main thread to the performance cores and asks Windows not to
// power-throttle it. Separate from the measurement on purpose.
bool PinMainThread(HANDLE mainThread);

void Report();

} // namespace CpuTopology

#endif
