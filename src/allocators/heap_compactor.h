#pragma once

// ============================================================================
// Module: heap_compactor.h
// ============================================================================










#include "version.h"

#if TEST_DISABLE_HEAP_COMPACTOR == 0

bool HeapCompactor_Init();
void HeapCompactor_Shutdown();

// Diagnostic queries
extern "C" SIZE_T HeapCompactor_GetLargestFreeBlock();
// The low half on its own. The client allocates from below 2GB, so a caller
// describing how much room was left at some moment wants this, not the total.
extern "C" SIZE_T HeapCompactor_GetLargestFreeLowHalf();
// The same figure from the monitor thread's last walk, with its age. No
// VirtualQuery, so it is safe to call from inside a frame. Age 0 with a result
// of 0 means the monitor has not run yet, not that nothing is free.
extern "C" SIZE_T HeapCompactor_GetLastLowHalf(unsigned long* ageMsOut);

// The largest free run below 2GB and the sum of all free space there, from the
// same cached walk. False when the monitor has not run yet, which is not the
// same as nothing being free.
extern "C" bool HeapCompactor_GetLowHalfSnapshot(SIZE_T* largestOut,
                                                 SIZE_T* totalOut,
                                                 unsigned long* ageMsOut);

// The largest free run over all of user address space, from the same walk.
extern "C" bool HeapCompactor_GetLastLargestFree(SIZE_T* largestOut,
                                                 unsigned long* ageMsOut);
extern "C" void HeapCompactor_GetStats(uint64_t* checks, uint64_t* compactions,
                                        SIZE_T* lastBlock, SIZE_T* minBlock, SIZE_T* maxBlock);

// Runs any compaction the background monitor thread requested. Must be called
// from the main thread only (see heap_compactor.cpp for why: HeapCompact()/
// mi_collect() must never run off an unsynchronized background thread).
extern "C" void HeapCompactor_RunPendingWork();
extern "C" void HeapCompactor_LogStats();

#else

inline bool HeapCompactor_Init() { return true; }
inline void HeapCompactor_Shutdown() {}
inline void HeapCompactor_RunPendingWork() {}
inline void HeapCompactor_LogStats() {}
// Compiled out, so nothing has walked and there is nothing to hand back. The
// callers already print "not measured" for a false return, which is the truth
// here as much as it is before the monitor thread's first pass.
inline SIZE_T HeapCompactor_GetLastLowHalf(unsigned long* ageMsOut) {
    if (ageMsOut) *ageMsOut = 0;
    return 0;
}
inline bool HeapCompactor_GetLowHalfSnapshot(SIZE_T*, SIZE_T*, unsigned long*) {
    return false;
}
inline bool HeapCompactor_GetLastLargestFree(SIZE_T*, unsigned long*) {
    return false;
}

#endif
