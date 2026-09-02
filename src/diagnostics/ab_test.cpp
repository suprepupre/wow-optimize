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
#include <cstdio>
#include <intrin.h>

#include "ab_test.h"
#include "config.h"
#include "session_verdict.h"

extern "C" void Log(const char* fmt, ...);

namespace AbTest {
namespace {

constexpr int    kBuckets    = 241;    // 0.5 ms each to 120 ms, plus overflow
constexpr double kBucketMs   = 0.5;
constexpr int    kSettleFrames = 12;   // discarded after every flip

struct Phase {
    uint64_t frames    = 0;
    uint64_t workCalls = 0;        // sampled calls into the subject's hot path
    uint64_t workTicks = 0;        // and their total, in TSC ticks
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
bool     g_claimed  = false;    // some module answered to the configured name
uint64_t g_standAside = 0;      // hot-path calls the subject handed back

// One call in 256 is timed. A power of two so the test is an AND, and a plain
// counter because this is a hot path and a lock-prefixed increment there has
// eaten whole optimizations in this project before.
constexpr uint32_t kSampleMask = 255;
uint32_t g_sampleSeq = 0;

// A sample that spans a context switch or a hardware interrupt is not a
// measurement of this function, and one of them is worth thousands of honest
// samples to the mean. Anything past this is thrown away and counted.
constexpr uint64_t kTickCeiling = 200000;   // ~50 us on any plausible clock
uint64_t g_ticksDiscarded = 0;

// Every name a module offered this session.
//
// The subject is set by hand in the ini, and nothing anywhere tells the reader
// what the valid names are - so a typo, or a guess, produces a session that
// measures nothing and a report that can only say so. The modules know their own
// names because they pass them to IsSubject; collecting them costs one string
// copy each at startup and turns the harness into its own documentation.
constexpr int kMaxOffered = 32;
char     g_offered[kMaxOffered][32] = {};
int      g_offeredCount = 0;
bool     g_wantList = false;    // AbTest on, no subject named

void NoteOffered(const char* name) {
    if (!name || g_offeredCount >= kMaxOffered) return;
    for (int i = 0; i < g_offeredCount; ++i)
        if (lstrcmpiA(g_offered[i], name) == 0) return;
    lstrcpynA(g_offered[g_offeredCount], name, (int)sizeof(g_offered[0]));
    ++g_offeredCount;
}

void LogOffered(const char* lead) {
    if (g_offeredCount == 0) {
        Log("[AbTest] %s - and no module offered a name, which means none of the "
            "features that can be tested were switched on either", lead);
        return;
    }
    char line[512];
    int w = _snprintf(line, sizeof(line) - 1, "[AbTest] %s. Offered this session:", lead);
    for (int i = 0; i < g_offeredCount && w > 0 && w < (int)sizeof(line) - 40; ++i)
        w += _snprintf(line + w, sizeof(line) - 1 - w, " %s", g_offered[i]);
    line[sizeof(line) - 1] = 0;
    Log("%s", line);
    Log("[AbTest] Only a feature that is itself switched on can offer a name, so "
        "this list is what could be tested with the settings you are running, not "
        "everything that exists.");
}
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

bool IsSubject(const char* name) {
    // Recorded whether or not it matches, and whether or not a test is running,
    // so a session with a mistyped subject can still print the list of names that
    // would have worked.
    if (Config::g_settings.OptAbTest) NoteOffered(name);
    if (!g_active || !name || lstrcmpiA(g_subject, name) != 0) return false;
    g_claimed = true;
    return true;
}

bool StandAside() {
    if (g_onNow) return false;
    ++g_standAside;
    return true;
}

unsigned long long TickIn() {
    if (!g_active) return 0;
    if ((++g_sampleSeq & kSampleMask) != 0) return 0;
    return __rdtsc();
}

void TickOut(unsigned long long t) {
    if (!t) return;
    uint64_t d = __rdtsc() - t;
    if (d == 0 || d > kTickCeiling) { ++g_ticksDiscarded; return; }
    Phase& p = g_onNow ? g_on : g_off;
    ++p.workCalls;
    p.workTicks += d;
}

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
        // Not a failure to report and forget. The modules initialise after this
        // and will offer their names, so the list is printed from LogStats rather
        // than here, where it would be empty.
        g_wantList = true;
        Log("[AbTest] NOT active: AbTest is on but AbTestSubject names no feature, "
            "so there is nothing to alternate. Set AbTestSubject in wow_opt.ini; "
            "the names that would have worked are listed in the periodic report "
            "below.");
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
    if (!g_active) {
        if (g_wantList) LogOffered("no subject was named, so nothing was measured");
        else            Log("[AbTest] not running - nothing measured");
        return;
    }

    Log("[AbTest] '%s' alternating every %u s. %llu frame(s) discarded around "
        "switches and loading screens.",
        g_subject, g_periodMs / 1000, (unsigned long long)g_dropped);

    // The failure that would otherwise read as a result.
    //
    // If the name in the ini matches no module - a typo, a feature that was not
    // also switched on, one that never installed on this client - then nothing
    // behaves differently between the halves and the difference below comes out
    // near zero. Reported without this, that is indistinguishable from "measured
    // it, it does nothing", and it is the more likely of the two.
    if (!g_claimed) {
        Log("[AbTest]   NO MODULE ANSWERED TO '%s'. Nothing was alternated, both "
            "halves are the same client doing the same thing, and the numbers "
            "below measure only noise.", g_subject);
        LogOffered("check the spelling against these");
    } else if (g_standAside == 0) {
        Log("[AbTest]   '%s' claimed the test but its hot path was never reached "
            "during an OFF stint - so the two halves may still be identical. That "
            "is a fact about this session's play, not about the feature.",
            g_subject);
    } else {
        Log("[AbTest]   '%s' stood aside %llu time(s) during OFF stints, so the "
            "two halves really did differ.",
            g_subject, (unsigned long long)g_standAside);
    }
    Report("ON", g_on);
    Report("OFF", g_off);

    if (g_on.frames && g_off.frames && g_claimed && g_standAside) {
        double meanOn  = g_on.sumMs  / (double)g_on.frames;
        double meanOff = g_off.sumMs / (double)g_off.frames;
        double d = meanOff - meanOn;   // positive means ON was faster
        Log("[AbTest]   ON is %.3f ms %s per frame on the mean (%+.1f%%). Both "
            "halves come from the same session and the same play, so this is the "
            "closest thing to a controlled figure this project can produce.",
            d < 0 ? -d : d, d > 0 ? "faster" : "slower",
            meanOff != 0.0 ? (-100.0 * d / meanOff) : 0.0);

        // The tail, differenced rather than left for the reader.
        //
        // The mean is the wrong figure for anything whose job is to remove a rare
        // stall - the GC governor exists for exactly that - and several reports in
        // this project tell the reader to look at p95 and p99 without ever
        // subtracting one from the other. A percentile that landed in the overflow
        // bucket has no number, so that pair is skipped rather than differenced
        // against a made-up 120.
        struct { const char* name; double frac; } tails[] = {
            { "p50", 0.50 }, { "p95", 0.95 }, { "p99", 0.99 }
        };
        for (int t = 0; t < 3; ++t) {
            double a = 0.0, b = 0.0;
            if (!Percentile(g_on, tails[t].frac, &a)) continue;
            if (!Percentile(g_off, tails[t].frac, &b)) continue;
            double diff = b - a;   // positive means ON was faster
            Log("[AbTest]   %s: %.2f ms with it on against %.2f without, so ON is "
                "%.2f ms %s there",
                tails[t].name, a, b, diff < 0 ? -diff : diff,
                diff > 0 ? "faster" : "slower");
        }

        // The function's own cost, which is the number that resolves a feature
        // too small for frame time to see. Ticks rather than nanoseconds: the TSC
        // frequency is not the performance-counter frequency and this project has
        // no honest conversion for it, so the ratio is reported and the absolute
        // figure is left in the unit it was measured in.
        if (g_on.workCalls && g_off.workCalls) {
            double tOn  = (double)g_on.workTicks  / (double)g_on.workCalls;
            double tOff = (double)g_off.workTicks / (double)g_off.workCalls;
            Log("[AbTest]   the replaced call itself: %.0f ticks with the feature "
                "on over %llu samples, %.0f ticks without it over %llu. That is "
                "%.2fx. One call in 256 is timed, and %llu sample(s) were thrown "
                "away for spanning something other than this function.",
                tOn, (unsigned long long)g_on.workCalls,
                tOff, (unsigned long long)g_off.workCalls,
                tOn != 0.0 ? tOff / tOn : 0.0,
                (unsigned long long)g_ticksDiscarded);
            Log("[AbTest]   frame time is the figure that matters to a player, but "
                "a feature worth under a percent of main-thread time cannot show "
                "there. When the two disagree, this line is the one measuring the "
                "feature and the frame line is measuring the session.");
        } else if (g_on.workCalls || g_off.workCalls) {
            Log("[AbTest]   the call was timed in only one of the two halves, so "
                "there is nothing to compare it against.");
        }

        uint32_t stints = g_on.stints + g_off.stints;

        // The headline, at the top of the log rather than four hundred lines
        // down. Only once there are enough stints to mean anything - a result
        // from three of them promoted to the summary would be read as settled.
        if (stints >= 8) {
            Verdict::Add(Verdict::Note,
                         "A/B on %s: %.3f ms/frame %s with it on, over %u stints",
                         g_subject, d < 0 ? -d : d,
                         d > 0 ? "faster" : "slower", stints);
        }

        if (stints < 8) {
            Log("[AbTest]   only %u stint(s) so far. That is too few to trust: one "
                "busy fight landing in one half moves the whole figure. Play "
                "longer before reading anything into it.", stints);
        }
    } else if (!g_on.frames || !g_off.frames) {
        Log("[AbTest]   one of the two halves has no frames, so no comparison is "
            "possible yet - not a difference of zero.");
    } else {
        Log("[AbTest]   no difference is printed, because the lines above say the "
            "two halves were not actually different. A number here would be read "
            "as a result and it would be noise.");
    }
}

}  // namespace AbTest
