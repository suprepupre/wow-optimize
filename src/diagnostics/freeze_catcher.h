// ============================================================================
// Description: Samples the main thread only while a frame is already long.
// Safety & Threading: A watchdog thread; the main thread is touched only during
//                     a frame that has already overrun.
// ============================================================================

#pragma once

#include <windows.h>

namespace FreezeCatcher {

bool Init(HANDLE mainThread);
void OnFrame();
void Shutdown();
void LogStats();

// "kernel32.dll!Sleep" for an address inside a mapped system module, written to
// out; false when the address is not in a module with a nearby export. Used to
// name the profile's detours on system functions, which carried only an address.
bool NameExport(uintptr_t addr, char* out, size_t cap);

} // namespace FreezeCatcher
