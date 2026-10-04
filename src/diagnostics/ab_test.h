#pragma once

#include <cstdint>
#include <intrin.h>

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
// tests. Call once at init; the harness owns the flag from then on. Unnamed, or
// AbTestSubject=bundle, every subject alternates together; AbTestSubject=all
// rotates, so only one feature alternates at a time; a name measures that one.
// A module may register before or after Init: Init adopts the earlier ones.
//
// Returns the flag's initial value, so a caller can log that it is the subject
// without reading the flag back.
bool IsSubject(const char* name, bool* flag);

// For the hot path of the module that answered true above: true means stand
// aside and let the client's own code run, because the test is in an OFF stint.
// Counts the call, so the report can say the subject was actually reached.
//
// The two-line answer for the ON half is inline, because a replacement that runs
// billions of times in a session paid a call for it each time: the harness was
// 3.85% of one profiled session's executing time, in StandAside, TickIn and
// TickOut alone, and only in a session that was measuring.
extern bool g_onNow;
bool StandAsideSlow();
inline bool StandAside() { return g_onNow ? false : StandAsideSlow(); }

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
extern bool g_active;
extern unsigned int g_sampleSeq;
// One call in 256 is sampled; the mask is 255 in ab_test.cpp (kSampleMask).
inline unsigned long long TickIn() {
    if (!g_active) return 0;
    if ((++g_sampleSeq & 255u) != 0) return 0;
    return __rdtsc();
}
void TickOutSlow(unsigned long long t);
inline void TickOut(unsigned long long t) { if (t) TickOutSlow(t); }

// Re-running one call with chosen replacements standing aside. For a caller that
// has seen a result it doubts and wants to know which replacement produced it:
// DiagBegin remembers the state of every registered flag, DiagSelect(-1) makes
// all of them stand aside and DiagSelect(i) makes only the i-th, and DiagEnd
// puts everything back. Main thread only, and only while a test is running;
// DiagBegin returns false otherwise and the rest must not be called.
bool DiagBegin();
void DiagSelect(int index);        // -1: every subject stands aside
void DiagEnd();
int  DiagCount();                  // registered subjects that handed over a flag
bool DiagSubject(int index, const char** name);   // false for an empty slot

// One presented frame. Called from the frame boundary; it reads the clock
// itself so it does not depend on another module being switched on.
void OnFrame();

bool Init();
void LogStats();

}  // namespace AbTest
