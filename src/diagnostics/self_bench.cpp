// ============================================================================
// Module: self_bench
// Description: Times a replacement against the client on the same input, using
//              the pairs the verification phase already produces.
// Safety & Threading: Main thread, inside a verification path.
// ============================================================================
// Every module in this project that replaces a client function ends its report
// the same way: no frame-time gain is claimed. That is honest and it has been
// true for every one of them, because the only instrument that could claim one
// is the A/B harness and the A/B harness needs a tester to switch it on. Six
// field sessions to hand, from two testers, all carry AbTest=0.
//
// Meanwhile the number is already going past. A verifying module runs both
// implementations on the same arguments, thousands of times, at the start of
// every session - that is what the verification is - and then throws away the
// only paired comparison anyone will ever get. Frame time cannot see a function
// worth a fraction of a percent; a paired comparison on identical input can see
// it exactly, and it needs no configuration, no stints and no tester.
//
// So this counts cycles around each half of a pair the module was going to run
// anyway, and reports the ratio of the totals.
// ---------------------------------------------------------------------------
// What this is and is not
//
// It is: the cost of our code against the client's code, on the same input, in
// the same process, with the same caches warm, summed over thousands of pairs.
//
// It is not a frame-time saving. A function can be four times faster and worth
// nothing at all if the client does not spend time in it, and this says nothing
// about how often it is called or what share of a frame that is. Those are the
// profiler's questions. This answers only "is the replacement actually faster,
// and by how much", which has been assumed for every module here and measured
// for none.
//
// rdtsc is not serialised. Over a single pair that matters; over the thousands
// a verification phase produces it averages out, and the report says how many
// pairs it is based on so a small count can be discounted. The two halves are
// timed the same way in the same loop, so whatever the counter's overhead is,
// both sides carry it.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>

#include "self_bench.h"

extern "C" void Log(const char* fmt, ...);

namespace SelfBench {

namespace {

constexpr int kMaxSlots = 24;

struct Slot {
    const char* name;
    // Plain 64-bit sums on a path that runs at most a few tens of thousands of
    // times a session, so the usual objection to a 64-bit counter on a hot path
    // does not apply here - this one is not hot.
    uint64_t ours;
    uint64_t theirs;
    uint64_t pairs;
    uint64_t discarded;   // a pair straddling something that made it useless
};

Slot g_slot[kMaxSlots];
int  g_count = 0;

// A pair where either half is absurd - a context switch, a page fault, an
// interrupt - would swamp thousands of honest ones, so it is dropped and
// counted. The threshold is deliberately loose: this is for outliers of a
// different order, not for trimming a distribution.
constexpr uint64_t kAbsurdCycles = 2000000ull;

// The fixed cap cannot see an outlier below it. ParticleFillFast read 5.9 to 12.6 times slower than
// the client in three reports from one tester's session, and the excess was the same 3.0e8 cycles
// in all three: a few hundred pairs of up to two million cycles each, all in the first thirty
// thousand pairs, then diluted as normal ones piled up. Once a slot has enough pairs to know what
// a normal one costs, a half more than 64 times the running mean (and over 20000 cycles) is an
// interruption and not the code.
constexpr uint64_t kWarmPairs = 64;
constexpr uint64_t kAdaptiveFactor = 64;
constexpr uint64_t kAdaptiveFloor = 20000;

}  // namespace

int Register(const char* name) {
    if (g_count >= kMaxSlots) return -1;
    const int id = g_count++;
    g_slot[id].name = name;
    return id;
}

void Pair(int id, uint64_t oursCycles, uint64_t theirsCycles) {
    if (id < 0 || id >= g_count) return;
    Slot& s = g_slot[id];
    if (oursCycles > kAbsurdCycles || theirsCycles > kAbsurdCycles) {
        ++s.discarded;
        return;
    }
    if (s.pairs >= kWarmPairs) {
        uint64_t capOurs = kAdaptiveFactor * (s.ours / s.pairs);
        uint64_t capTheirs = kAdaptiveFactor * (s.theirs / s.pairs);
        if (capOurs < kAdaptiveFloor) capOurs = kAdaptiveFloor;
        if (capTheirs < kAdaptiveFloor) capTheirs = kAdaptiveFloor;
        if (oursCycles > capOurs || theirsCycles > capTheirs) {
            ++s.discarded;
            return;
        }
    }
    s.ours += oursCycles;
    s.theirs += theirsCycles;
    ++s.pairs;
}

uint64_t Now() { return __rdtsc(); }

void LogStats() {
    bool any = false;
    for (int i = 0; i < g_count; ++i) if (g_slot[i].pairs) { any = true; break; }
    if (!any) {
        if (g_count == 0)
            Log("[SelfBench] no module registered, so nothing was paired.");
        else
            Log("[SelfBench] %d module(s) registered and no pair recorded yet - "
                "their verification phases have not run.", g_count);
        return;
    }

    Log("[SelfBench] our code against the client's, on the same input, inside "
        "the verification each module runs anyway. This is not a frame-time "
        "saving: it says whether a replacement is faster and by how much, not "
        "how much of a frame it is worth.");

    for (int i = 0; i < g_count; ++i) {
        const Slot& s = g_slot[i];
        if (!s.pairs) {
            Log("[SelfBench]   %-20s no pairs yet", s.name);
            continue;
        }
        const double ours   = (double)s.ours / (double)s.pairs;
        const double theirs = (double)s.theirs / (double)s.pairs;
        if (ours <= 0.0) {
            Log("[SelfBench]   %-20s %llu pairs, and our half measured zero "
                "cycles - too fast for this clock to resolve one call.",
                s.name, (unsigned long long)s.pairs);
            continue;
        }
        Log("[SelfBench]   %-20s %7.1f cycles against %7.1f, %.2fx, over %llu "
            "pairs%s",
            s.name, ours, theirs, theirs / ours,
            (unsigned long long)s.pairs,
            s.discarded ? " (some pairs dropped as outliers)" : "");
        // The first pairs of a session are the first calls into code that is not in
        // the cache yet, and read as slower than the client for that reason: the
        // same four modules were flagged in every log on disk at a few hundred pairs
        // and came out two to four times faster by the end. A verdict needs enough
        // pairs for the cold ones not to decide it.
        constexpr unsigned long long kMinPairsToJudge = 1000;
        if (theirs < ours) {
            if (s.pairs < kMinPairsToJudge)
                Log("[SelfBench]   %s reads slower than the code it replaces after only "
                    "%llu pairs, too few to say: the first calls run cold.",
                    s.name, (unsigned long long)s.pairs);
            else
                Log("[Wrong] [SelfBench]   %s is SLOWER than the code it replaces, "
                    "by %.2fx on the same input over %llu pairs. That is the whole "
                    "reason to replace it, so this one needs looking at.",
                    s.name, ours / theirs, (unsigned long long)s.pairs);
        }
    }
}

}  // namespace SelfBench
