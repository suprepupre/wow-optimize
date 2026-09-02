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

// How many subjects can register. Declared here because the per-subject arrays
// below are sized by it.
constexpr int kMaxOffered = 32;

bool     g_onNow    = true;
bool     g_claimed  = false;    // some module answered to the configured name
uint64_t g_standAside[kMaxOffered] = {};   // hot-path calls each subject handed back

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
char     g_offered[kMaxOffered][32] = {};
bool*    g_flag[kMaxOffered] = {};   // the hot-path flag each module handed over
int      g_offeredCount = 0;

// Rotation: measure every subject in one session instead of one per session.
//
// A tester gives this project maybe one session a week. Fifteen subjects at that
// rate is months, and the answer to most of them is wanted before deciding what
// to build next. With AbTestSubject=all the harness measures one subject for a
// few stints, then hands its flag back and takes the next.
//
// Only one subject alternates at a time, so none of them confounds another - the
// rest run exactly as their own switches say. The cost is samples per subject,
// and the stint counts printed per subject are what says whether there were
// enough of them.
bool     g_rotate = false;
int      g_rotIndex = 0;        // which offered subject is currently measured
int      g_rotPairs = 0;        // completed ON/OFF pairs on the current subject

// Pairs, not stints. The counter behind this only advances on a switch INTO the
// ON phase, so it counts complete ON/OFF cycles - at 8 with a 20 s period that
// was 320 s a subject and 80 minutes for a rotation of fifteen, while the
// constant was named for stints, commented as four pairs and printed in the log
// as "8 stints of 20 s", which reads as 160 s. Three descriptions of one number,
// none of them the number. Four pairs is what the comment always intended and
// what fits a session: 160 s a subject, 40 minutes for fifteen.
constexpr int kPairsPerSubject = 4;

// Returns the slot this name occupies, or -1 when it could not be recorded.
//
// The caller used to assume the slot was always g_offeredCount - 1, which is
// wrong twice: a name already present returns without adding, so that index
// belongs to a different module, and past the cap nothing is added at all and the
// index is the last registered subject's. Either way a flag pointer or a stats
// slot would have been written over someone else's. Fifteen subjects is nowhere
// near the cap of thirty-two, so this would have stayed invisible until it was
// not.
int NoteOffered(const char* name) {
    if (!name) return -1;
    for (int i = 0; i < g_offeredCount; ++i)
        if (lstrcmpiA(g_offered[i], name) == 0) return i;
    if (g_offeredCount >= kMaxOffered) return -1;
    lstrcpynA(g_offered[g_offeredCount], name, (int)sizeof(g_offered[0]));
    return g_offeredCount++;
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

// One pair per registered subject, so a rotating session keeps them apart.
Phase    g_on[kMaxOffered];
Phase    g_off[kMaxOffered];

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

// The opening stint. Init cannot count it, because in a named run the slot the
// subject will occupy is not known until that module registers - counting it in
// slot 0 put it against whichever module happened to register first.
static void CountOpeningStint() {
    static bool s_done = false;
    if (s_done) return;
    s_done = true;
    g_on[g_rotIndex].stints = 1;
}

bool IsSubject(const char* name, bool* flag) {
    // Recorded whether or not it matches, and whether or not a test is running,
    // so a session with a mistyped subject can still print the list of names that
    // would have worked.
    if (!Config::g_settings.OptAbTest) return false;
    const int slot = NoteOffered(name);
    if (slot < 0) {
        // Past the cap. Registering it as a subject would mean sharing another
        // module's flag and stats, so it is left out and said out loud rather
        // than quietly measured as somebody else.
        Log("[AbTest] '%s' could not register - only %d subjects fit, so it "
            "cannot be tested this session", name ? name : "(null)", kMaxOffered);
        return false;
    }
    if (flag) g_flag[slot] = flag;
    if (!g_active) return false;

    if (g_rotate) {
        // Everything registered is a subject; which one is live is decided by the
        // rotation below, and the first registered starts.
        g_claimed = true;
        if (slot != g_rotIndex) return false;
        CountOpeningStint();
        return true;
    }
    if (lstrcmpiA(g_subject, name) != 0) return false;
    g_claimed = true;
    g_rotIndex = slot;                 // so the stats land in this subject's slot
    CountOpeningStint();
    return true;
}

bool StandAside() {
    if (g_onNow) return false;
    ++g_standAside[g_rotIndex];
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
    Phase& p = g_onNow ? g_on[g_rotIndex] : g_off[g_rotIndex];
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

        // Hand the feature back and take the next one, when rotating. The
        // move happens on an ON boundary so every subject is left switched
        // on when it is not being measured, which is what its own setting
        // asked for.
        if (g_rotate && g_onNow && ++g_rotPairs >= kPairsPerSubject) {
            g_rotPairs = 0;
            if (g_flag[g_rotIndex]) *g_flag[g_rotIndex] = false;
            int next = g_rotIndex;
            for (int n = 0; n < g_offeredCount; ++n) {
                next = (next + 1) % (g_offeredCount ? g_offeredCount : 1);
                if (g_flag[next]) break;
            }
            g_rotIndex = next;
            if (g_flag[g_rotIndex]) *g_flag[g_rotIndex] = true;
            Log("[AbTest] now measuring '%s'", g_offered[g_rotIndex]);
        }

        ++(g_onNow ? g_on[g_rotIndex] : g_off[g_rotIndex]).stints;
    }

    if (first)         { ++g_dropped; return; }   // no previous frame to measure from
    if (g_settle > 0)  { --g_settle; ++g_dropped; return; }
    if (frameMs <= 0.0 || frameMs > 2000.0) { ++g_dropped; return; }  // a load, not a frame

    Add(g_onNow ? g_on[g_rotIndex] : g_off[g_rotIndex], frameMs);
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

    // An empty subject used to stand the harness down and print the list of
    // names that would have worked. Everything about that was right except what
    // it cost: the tickbox is in the launcher, the subject is not, so a tester
    // who ticks the box and plays for an hour gets a list instead of a
    // measurement, and the session that answers something is the next one.
    // Rotation is what they would have picked and needs no ini edit, so it is
    // what an unnamed subject means now.
    bool subjectWasBlank = (g_subject[0] == 0);
    if (subjectWasBlank || lstrcmpiA(g_subject, "all") == 0 ||
        lstrcmpiA(g_subject, "*") == 0) {
        g_rotate = true;
        g_active = true;
        g_onNow = true;
        g_periodMs = (DWORD)Config::g_settings.AbTestPeriodMs;
        if (g_periodMs < 5000)   g_periodMs = 5000;
        if (g_periodMs > 120000) g_periodMs = 120000;
        // The opening stint is counted by CountOpeningStint when the first
        // module registers, because only then is the slot known.
        // The times are computed from the constants rather than written into
        // the sentence, so this line cannot drift from what the code does.
        Log("[AbTest] ACTIVE, rotating: every feature that registers gets %d "
            "on/off pairs of %u s each - %u s a subject - in turn, so one "
            "session measures all of them instead of one per session. Only "
            "the subject being measured alternates; the rest run exactly as "
            "their own switches say, so none of them confounds another. Each "
            "gets a share of the session, and the per-subject stint counts "
            "are what say whether the share was enough to read anything into.",
            kPairsPerSubject, g_periodMs / 1000,
            (unsigned)(2 * kPairsPerSubject * (g_periodMs / 1000)));
        if (subjectWasBlank)
            Log("[AbTest]   no AbTestSubject was named, and rotating every "
                "subject is the useful reading of that. To spend the whole "
                "session on one feature instead, put its name in wow_opt.ini "
                "as AbTestSubject=<name>; the names it answers to are listed "
                "in the periodic report below.");
        return true;
    }

    g_periodMs = (DWORD)Config::g_settings.AbTestPeriodMs;
    if (g_periodMs < 5000)   g_periodMs = 5000;
    if (g_periodMs > 120000) g_periodMs = 120000;

    g_active = true;
    g_onNow = true;
    // Same here: CountOpeningStint puts it in the slot the named subject
    // turns out to occupy.

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

// One subject's result. Split out because a rotating session has several and
// the checks below - did anything claim it, did its hot path ever stand aside -
// have to be made per subject, not once for the run.
static void ReportSubject(int i, const char* name) {
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
                "below measure only noise.", name);
            LogOffered("check the spelling against these");
        } else if (g_standAside[i] == 0) {
            Log("[AbTest]   '%s' claimed the test but its hot path was never reached "
                "during an OFF stint - so the two halves may still be identical. That "
                "is a fact about this session's play, not about the feature.",
                name);
        } else {
            Log("[AbTest]   '%s' stood aside %llu time(s) during OFF stints, so the "
                "two halves really did differ.",
                name, (unsigned long long)g_standAside[i]);
        }
        Report("ON", g_on[i]);
        Report("OFF", g_off[i]);

        if (g_on[i].frames && g_off[i].frames && g_claimed && g_standAside[i]) {
            double meanOn  = g_on[i].sumMs  / (double)g_on[i].frames;
            double meanOff = g_off[i].sumMs / (double)g_off[i].frames;
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
                if (!Percentile(g_on[i], tails[t].frac, &a)) continue;
                if (!Percentile(g_off[i], tails[t].frac, &b)) continue;
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
            if (g_on[i].workCalls && g_off[i].workCalls) {
                double tOn  = (double)g_on[i].workTicks  / (double)g_on[i].workCalls;
                double tOff = (double)g_off[i].workTicks / (double)g_off[i].workCalls;
                Log("[AbTest]   the replaced call itself: %.0f ticks with the feature "
                    "on over %llu samples, %.0f ticks without it over %llu. That is "
                    "%.2fx. One call in 256 is timed, and %llu sample(s) were thrown "
                    "away for spanning something other than this function.",
                    tOn, (unsigned long long)g_on[i].workCalls,
                    tOff, (unsigned long long)g_off[i].workCalls,
                    tOn != 0.0 ? tOff / tOn : 0.0,
                    (unsigned long long)g_ticksDiscarded);
                Log("[AbTest]   frame time is the figure that matters to a player, but "
                    "a feature worth under a percent of main-thread time cannot show "
                    "there. When the two disagree, this line is the one measuring the "
                    "feature and the frame line is measuring the session.");

                // The calibration case, checked rather than left for a reader to
                // remember. MatrixVectorSse2 was measured at 3.333 ns against
                // 2.497 ns for the code it replaces, output bit-identical - it is
                // slower, and the harness has to say so. A calibration case only
                // helps if somebody notices the answer, so it goes to the summary
                // at the top of the log either way.
                if (lstrcmpiA(name, "MatrixVectorSse2") == 0) {
                    if (tOn < tOff) {
                        Verdict::Add(Verdict::Warn,
                                     "the A/B harness reports MatrixVectorSse2 as "
                                     "FASTER, and it is known to be slower - "
                                     "suspect the measurement, not the feature");
                        Log("[AbTest]   THIS IS THE CALIBRATION CASE AND IT CAME OUT "
                            "BACKWARDS. A standalone harness measured this "
                            "replacement at 3.333 ns against 2.497 ns for the code "
                            "it replaces, with output bit-identical. Something here "
                            "is measuring wrongly and every other figure in this "
                            "report is suspect.");
                    } else {
                        Verdict::Add(Verdict::Note,
                                     "the A/B harness got the calibration case "
                                     "right: MatrixVectorSse2 measured slower, "
                                     "which is what it is");
                        Log("[AbTest]   this is the calibration case and it came out "
                            "the right way round - slower, which is what it is. "
                            "That is one reason to believe the other numbers here.");
                    }
                }
            } else if (g_on[i].workCalls || g_off[i].workCalls) {
                Log("[AbTest]   the call was timed in only one of the two halves, so "
                    "there is nothing to compare it against.");
            }

            uint32_t stints = g_on[i].stints + g_off[i].stints;

            // The headline, at the top of the log rather than four hundred lines
            // down. Only once there are enough stints to mean anything - a result
            // from three of them promoted to the summary would be read as settled.
            if (stints >= 8) {
                Verdict::Add(Verdict::Note,
                             "A/B on %s: %.3f ms/frame %s with it on, over %u stints",
                             name, d < 0 ? -d : d,
                             d > 0 ? "faster" : "slower", stints);
            }

            if (stints < 8) {
                Log("[AbTest]   only %u stint(s) so far. That is too few to trust: one "
                    "busy fight landing in one half moves the whole figure. Play "
                    "longer before reading anything into it.", stints);
            }
        } else if (!g_on[i].frames || !g_off[i].frames) {
            Log("[AbTest]   one of the two halves has no frames, so no comparison is "
                "possible yet - not a difference of zero.");
        } else {
            Log("[AbTest]   no difference is printed, because the lines above say the "
                "two halves were not actually different. A number here would be read "
                "as a result and it would be noise.");
        }
}

void LogStats() {
    if (!Config::g_settings.OptAbTest) return;
    if (!g_active) {
        // The one way to be switched on and not active is a machine with no
        // performance counter, and Init said so at the time.
        Log("[AbTest] switched on but not running - nothing measured");
        return;
    }

    // A rotating run has no single subject, and g_subject is the empty string
    // when nobody named one - printing it would read as a feature called "".
    if (g_rotate)
        Log("[AbTest] alternating every %u s. %llu frame(s) discarded around "
            "switches and loading screens.",
            g_periodMs / 1000, (unsigned long long)g_dropped);
    else
        Log("[AbTest] '%s' alternating every %u s. %llu frame(s) discarded "
            "around switches and loading screens.",
            g_subject, g_periodMs / 1000, (unsigned long long)g_dropped);

    if (g_rotate) {
        Log("[AbTest] rotating: every registered subject gets %d on/off pairs "
            "in turn, %u s each, so one pass over %d subject(s) takes %u s. "
            "Only one alternates at a time, so none confounds another - but "
            "each gets a share of the session, and the stint counts below "
            "are what say whether that share was enough.",
            kPairsPerSubject, g_periodMs / 1000, g_offeredCount,
            (unsigned)(2 * kPairsPerSubject * (g_periodMs / 1000) *
                       (g_offeredCount > 0 ? g_offeredCount : 1)));
    }
    // Which name a slot is reported under.
    //
    // Rotating, every slot is a real subject and carries its own name. Named, only
    // one slot is used - and when the name in the ini matched nothing, the frames
    // landed in slot 0 while slot 0 belongs to whichever module registered first.
    // Printing "NO MODULE ANSWERED TO 'AnimQuatUnpack'" when the ini said
    // "AnimQatUnpack" would name the wrong thing entirely, so a named run reports
    // under the configured name whatever slot the frames are in.
    int reported = 0;
    for (int i = 0; i < g_offeredCount; ++i) {
        if (!g_on[i].frames && !g_off[i].frames) continue;
        ReportSubject(i, g_rotate ? g_offered[i] : g_subject);
        ++reported;
    }

    // A rotating run that reported nothing is the case the defaults produce.
    // A module offers itself only after its own install succeeds, so with the
    // lean default set there is close to nothing to rotate - and the loop above
    // then prints an encouraging header followed by silence, which reads as a
    // clean run rather than as an hour that measured nothing.
    if (g_rotate && reported == 0) {
        if (g_offeredCount == 0) {
            Log("[AbTest] NOTHING WAS MEASURED. No feature offered itself, "
                "because a feature registers only once its own switch has let "
                "it install - and by default almost none are on. Turn on the "
                "features you want compared and run this again; the A/B "
                "tickbox decides when they do their work, never whether they "
                "installed.");
            Verdict::Add(Verdict::Warn,
                "The A/B harness ran for the whole session and measured "
                "nothing: no feature was switched on for it to alternate.");
        } else {
            Log("[AbTest] %d subject(s) registered but none collected a frame "
                "yet. Each waits its turn, so a short session can end before "
                "the first handover.", g_offeredCount);
        }
    }

    // A named run whose subject matched nothing has no frames anywhere - the
    // loop above prints nothing, and silence would read as a clean run.
    if (!g_rotate && !g_claimed) {
        Log("[AbTest] NO MODULE ANSWERED TO '%s'. Nothing was alternated and "
            "nothing was measured.", g_subject);
        LogOffered("check the spelling against these");
    }
}

}  // namespace AbTest
