#pragma once

#include <cstdint>

// Alternates a feature on and off inside one session and reports the frame times
// each way. See ab_test.cpp for why comparing two sessions cannot work here.
namespace AbTest {

// Whether the feature under test should do its work on this frame. A module that
// opts in calls this on its hot path; it is one relaxed read of a bool.
bool FeatureOn();

// True when a test is configured and running, so a module can say in its own
// report that its numbers are split across two states rather than describing one.
bool Running();

// The name the ini asked for, or nullptr. A module compares this against its own
// name to decide whether it is the one under test.
const char* Subject();

// One presented frame. Called from the frame boundary; it reads the clock
// itself so it does not depend on another module being switched on.
void OnFrame();

bool Init();
void LogStats();

}  // namespace AbTest
