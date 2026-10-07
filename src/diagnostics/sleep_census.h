#pragma once
#include <cstdint>

// Who puts the main thread to sleep, and for how long. One row per caller of the client's Sleep
// wrapper (sub_86B280) or, for a direct Sleep, per return address.
namespace SleepCensus {
    // Called by the Sleep hook on the main thread with the address that asked and how long the
    // real sleep took in microseconds.
    void Note(uintptr_t caller, uint32_t requestedMs, uint32_t sleptUs, bool loading);
    void LogStats();
}
