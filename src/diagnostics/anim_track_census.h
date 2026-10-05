#pragma once

// ============================================================================
// How often the M2 animation track evaluators are asked the same question twice.
// A measurement, not an optimisation. See anim_track_census.cpp.
// ============================================================================

#include <cstdint>

namespace AnimTrackCensus {

enum Kind { kQuat = 0, kVec3 = 1, kKinds = 2 };

// Set by Init when the switch is on, so a hot path pays one load of a bool.
extern bool g_on;

// Called at the top of a track evaluator, before it runs, with its own arguments.
void Observe(Kind kind, const void* obj, const uint8_t* state, const uint8_t* track,
             const float* defaults);

bool Init();
void LogStats();

} // namespace AnimTrackCensus
