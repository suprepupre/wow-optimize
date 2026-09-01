#pragma once

#include <cstdint>

// A per-frame ring the player can dump at the moment something goes wrong.
//
// See flight_recorder.cpp for why this exists. The short version: every report in
// this project arrives as "it happened at 20:35", and every log answers with
// ten-second averages, so four rounds of questions go by before anyone can look
// at the second in question.
namespace FlightRecorder {

// Claim a counter column. Returns a slot id, or -1 when the recorder is off or
// full. Call once at init and keep the id; Bump on a bad id does nothing.
int  RegisterSlot(const char* name);

// Add to a column. Main thread only, plain arithmetic, no lock.
void Bump(int slot, uint32_t n = 1);

// One ring entry. Called from the presented-frame boundary.
void OnFrame();

// Write the ring out. `why` names what triggered it and appears in the banner.
void Mark(const char* why);

// Edge-detects the marker key. Called from the frame boundary.
void PollHotkey();

bool Init();
void LogStats();

}  // namespace FlightRecorder
