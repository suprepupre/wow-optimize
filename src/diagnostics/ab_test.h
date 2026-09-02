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

// Register this module as a possible subject and hand over the flag its hot path
// tests. Call once at init.
//
// The flag is owned by the harness from that point on. With one subject named in
// the ini it is set once and never changes. With AbTestSubject=all the harness
// rotates: the flag of the subject currently being measured is true and every
// other one is false, so only one feature alternates at a time and none of them
// confound each other. A module needs no idea which mode it is in.
//
// Returns the flag's initial value, so a caller can log that it is the subject
// without reading the flag back.
bool IsSubject(const char* name, bool* flag);

// For the hot path of the module that answered true above: true means stand
// aside and let the client's own code run, because the test is in an OFF stint.
// Counts the call, so the report can say the subject was actually reached.
bool StandAside();

// Timing the subject's own work, for features too small for frame time to see.
//
// A feature worth 0.8% of main-thread time moves a 16 ms frame by 0.13 ms, which
// is well inside the frame-to-frame spread of real play - no number of stints
// recovers it. Timing the replaced function directly does recover it, because
// the noise there is a few cycles rather than a whole frame's worth of unrelated
// work.
//
// TickIn returns 0 on the calls it is not sampling, and TickOut does nothing
// with a 0. One call in 256 is sampled, so a function running thousands of times
// a frame still yields thousands of samples an hour at no measurable cost.
unsigned long long TickIn();
void TickOut(unsigned long long t);

// One presented frame. Called from the frame boundary; it reads the clock
// itself so it does not depend on another module being switched on.
void OnFrame();

bool Init();
void LogStats();

}  // namespace AbTest
