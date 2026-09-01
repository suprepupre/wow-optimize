// ============================================================================
// Module: ab_test.cpp
//
// This project has around fifty optimizations and not one of them has a measured
// frame-time gain. The README said so under a heading called "Still not claimed"
// for two releases. The reason is not that nobody tried - it is that the only
// comparison available was between sessions, and between sessions nothing is
// held still: a different zone, a different raid, a different time of day, a
// different number of players in view. A five percent difference in median frame
// time between two evenings says nothing whatever about a feature.
//
// So the features stay off by default, because turning one on by default needs
// evidence and the evidence cannot be gathered. Every one of them is written,
// verified for correctness, and unmeasured. LayoutRelinkFast targets the largest
// single consumer of main-thread time in the profile - 9.06% of executing time
// in an ElvUI session, first place by more than double - and in every tester log
// collected so far it reads LayoutRelinkFast=0.
//
// ---------------------------------------------------------------------------
// What removes the noise
//
// Alternate. Run the feature for twenty seconds, then not for twenty seconds,
// then again, for as long as the player keeps playing. The zone, the addons, the
// machine, the driver and the player's own behaviour drift slowly compared with
// that, so they land in both buckets in roughly equal measure and cancel. What
// does not cancel is the feature.
//
// This is the same shape as the learning-phase and predict-then-compare checks
// used for correctness elsewhere in the project, pointed at performance instead.
//
// ---------------------------------------------------------------------------
// The two things that would make it lie, and what is done about them
//
// Switching costs a frame. Whatever the feature does when it starts or stops -
// a cache that empties, a first-touch page fault - lands on the frames right
// after a flip. So the frames after each flip are recorded as belonging to
// neither phase and counted separately, and the report says how many were
// dropped. A settle window that swallowed most of a phase would be visible as a
// dropped count near the phase count.
//
// The mean hides the frames that matter. A feature that removes a rare 40 ms
// stall while costing 0.1 ms every frame looks worse on the mean and better on
// the tail, and the tail is what a player feels. So the report carries the
// median and the 95th and 99th percentiles per phase, from a fixed histogram
// rather than a sort - half-millisecond buckets to 120 ms, everything above in
// one overflow bucket that is named rather than folded into the last one.
//
// ---------------------------------------------------------------------------
// What this cannot tell you
//
// Nothing about correctness. A feature that is faster and wrong measures faster.
// The correctness checks each module carries are unaffected and still decide
// whether a feature may run at all.
//
// And nothing from a short session. Twenty seconds a phase means a ten-minute
// session is fifteen phases, and fifteen samples of a noisy quantity is not much.
// The report prints the phase count so a reader can see how thin the evidence
// is instead of reading a difference that is one busy fight in one bucket.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "ab_test.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

namespace AbTest {
namespace {

constexpr int    kBuckets    = 241;    // 0.5 ms each to 120 ms, plus overflow
constexpr double kBucketMs   = 0.5;
constexpr int    kSettleFrames = 12;   // discarded after every flip

struct Phase {
    uint64_t frames    = 0;
    double   sumMs     = 0.0;
    double   maxMs     = 0.0;
    uint32_t hist[kBuckets] = {};
    uint32_t over      = 0;            // above 120 ms, kept out of the histogram
    uint32_t stints    = 0;            // how many times this phase was entered
};

bool     g_active   = false;
char     g_subject[32] = {};
DWORD    g_periodMs = 20000;

bool     g_onNow    = true;
DWORD    g_phaseStart = 0;
int      g_settle   = 0;
uint64_t g_dropped  = 0;

Phase    g_on;
Phase    g_off;

LARGE_INTEGER g_freq = {};
LARGE_INTEGER g_last = {};
bool     g_haveLast = false;

void Add(Phase& p, double ms) {
    ++p.frames;
    p.sumMs += ms;
    if (ms > p.maxMs) p.maxMs = ms;
    if (ms >= 120.0) { ++p.over; return; }
    int b = (int)(ms / kBucketMs);
    if (b < 0) b = 0;
    if (b >= kBuckets) b = kBuckets - 1;
    ++p.hist[b];
}

// The frame time at a given share of the distribution. Frames above 120 ms are
// in `over` and not in the histogram, so a percentile that falls inside them is
// reported as "above 120" rather than as the last bucket, which would read as a
// precise 119.5 ms and be a lie.
bool Percentile(const Phase& p, double frac, double* out) {
    if (!p.frames) return false;
    uint64_t want = (uint64_t)((double)p.frames * frac);
    if (want >= p.frames) want = p.frames - 1;
    uint64_t seen = 0;
    for (int b = 0; b < kBuckets; ++b) {
        seen += p.hist[b];
        if (seen > want) { *out = ((double)b + 0.5) * kBucketMs; return true; }
    }
    return false;   // it landed in the overflow
}

void Report(const char* label, const Phase& p) {
    if (!p.frames) {
        Log("[AbTest]   %-3s no frames recorded - this phase never ran, so there "
            "is nothing to compare against", label);
        return;
    }
    double p50 = 0, p95 = 0, p99 = 0;
    bool h50 = Percentile(p, 0.50, &p50);
    bool h95 = Percentile(p, 0.95, &p95);
    bool h99 = Percentile(p, 0.99, &p99);
    Log("[AbTest]   %-3s %llu frames over %u stint(s): mean %.2f ms, p50 %s%.2f, "
        "p95 %s%.2f, p99 %s%.2f, max %.1f, %u frame(s) above 120 ms",
        label, (unsigned long long)p.frames, p.stints,
        p.sumMs / (double)p.frames,
        h50 ? "" : ">", h50 ? p50 : 120.0,
        h95 ? "" : ">", h95 ? p95 : 120.0,
        h99 ? "" : ">", h99 ? p99 : 120.0,
        p.maxMs, p.over);
}

}  // namespace

bool FeatureOn() { return !g_active || g_onNow; }
bool Running()   { return g_active; }
const char* Subject() { return g_active ? g_subject : nullptr; }

void OnFrame() {
    if (!g_active) return;

    LARGE_INTEGER qnow;
    QueryPerformanceCounter(&qnow);
    double frameMs = 0.0;
    if (g_haveLast)
        frameMs = (double)(qnow.QuadPart - g_last.QuadPart) * 1000.0 / (double)g_freq.QuadPart;
    g_last = qnow;
    bool first = !g_haveLast;
    g_haveLast = true;

    DWORD now = GetTickCount();
    if (g_phaseStart == 0) g_phaseStart = now;

    if ((DWORD)(now - g_phaseStart) >= g_periodMs) {
        g_onNow = !g_onNow;
        g_phaseStart = now;
        g_settle = kSettleFrames;
        ++(g_onNow ? g_on : g_off).stints;
    }

    if (first)         { ++g_dropped; return; }   // no previous frame to measure from
    if (g_settle > 0)  { --g_settle; ++g_dropped; return; }
    if (frameMs <= 0.0 || frameMs > 2000.0) { ++g_dropped; return; }  // a load, not a frame

    Add(g_onNow ? g_on : g_off, frameMs);
}

bool Init() {
    if (!Config::g_settings.OptAbTest) return true;

    QueryPerformanceFrequency(&g_freq);
    if (!g_freq.QuadPart) {
        Log("[AbTest] NOT active: no performance counter, so every frame time "
            "would read zero and the comparison would be between two zeros");
        return false;
    }

    lstrcpynA(g_subject, Config::g_settings.AbTestSubject, (int)sizeof(g_subject));
    if (!g_subject[0]) {
        Log("[AbTest] NOT active: AbTest is on but AbTestSubject names no feature, "
            "so there is nothing to alternate. Put a feature name in wow_opt.ini, "
            "for example AbTestSubject=LayoutRelinkFast.");
        return false;
    }

    g_periodMs = (DWORD)Config::g_settings.AbTestPeriodMs;
    if (g_periodMs < 5000)   g_periodMs = 5000;
    if (g_periodMs > 120000) g_periodMs = 120000;

    g_active = true;
    g_onNow = true;
    g_on.stints = 1;

    Log("[AbTest] ACTIVE on '%s': it runs for %u s, then does not for %u s, and "
        "so on for the session. Frame times are collected separately for the two "
        "and the %d frames after each switch are thrown away. Play normally - the "
        "point is that the zone, the addons and the machine land in both halves "
        "equally and cancel, which is what comparing two sessions could never do.",
        g_subject, g_periodMs / 1000, g_periodMs / 1000, kSettleFrames);
    Log("[AbTest]   the feature must still be enabled by its own switch. This "
        "decides when it does its work, not whether it installed.");
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptAbTest) return;
    if (!g_active) { Log("[AbTest] not running - nothing measured"); return; }

    Log("[AbTest] '%s' alternating every %u s. %llu frame(s) discarded around "
        "switches and loading screens.",
        g_subject, g_periodMs / 1000, (unsigned long long)g_dropped);
    Report("ON", g_on);
    Report("OFF", g_off);

    if (g_on.frames && g_off.frames) {
        double meanOn  = g_on.sumMs  / (double)g_on.frames;
        double meanOff = g_off.sumMs / (double)g_off.frames;
        double d = meanOff - meanOn;   // positive means ON was faster
        Log("[AbTest]   ON is %.3f ms %s per frame on the mean (%+.1f%%). Both "
            "halves come from the same session and the same play, so this is the "
            "closest thing to a controlled figure this project can produce.",
            d < 0 ? -d : d, d > 0 ? "faster" : "slower",
            meanOff != 0.0 ? (-100.0 * d / meanOff) : 0.0);

        uint32_t stints = g_on.stints + g_off.stints;
        if (stints < 8) {
            Log("[AbTest]   only %u stint(s) so far. That is too few to trust: one "
                "busy fight landing in one half moves the whole figure. Play "
                "longer before reading anything into it.", stints);
        }
    } else {
        Log("[AbTest]   one of the two halves has no frames, so no comparison is "
            "possible yet - not a difference of zero.");
    }
}

}  // namespace AbTest
