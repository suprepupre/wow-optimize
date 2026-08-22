// ============================================================================
// Module: world_position.h
// Description: The client's world streaming centre, and whether it can be read.
// Safety & Threading: Main thread.
// ============================================================================
#pragma once

namespace WowWorld {

// Fills out[3] with the world XYZ the client streams terrain around and
// returns true. Returns false when there is no world - before a map is
// entered, and on the login and character screens.
//
// Three states, not two: a caller that gets false must say it could not see a
// position rather than print a zero, because zero is a real place on the map.
bool StreamCentre(float out[3]);

// How many times StreamCentre has been asked, and how many of those could see
// a position. For the periodic report: a feature that depends on this and does
// nothing needs to be able to say which of the two it was.
void GetReadStats(unsigned long& asked, unsigned long& seen);

}  // namespace WowWorld
