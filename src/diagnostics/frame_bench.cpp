// ============================================================================
// Module: frame_bench.cpp
// Description: Frame-time distribution benchmark.
// Safety & Threading: Main thread only (called from the present path).
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include <algorithm>
#include "frame_bench.h"
#include "core/config.h"
#include "crash_dumper.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

// Frames presented during a zone load are not gameplay frames: one cold load can
// contribute several seconds of frame time and would own the entire tail.
namespace LuaOpt { bool IsLoadingMode(); }

namespace FrameBench {

// 0.1ms buckets up to 100ms covers everything that matters for smoothness; the
// rest lands in an overflow bucket and is still reflected in the max and in the
// "over 100ms" counter, so nothing is silently dropped.
static constexpr int    BUCKET_COUNT = 1000;
static constexpr double BUCKET_MS    = 0.1;

// A frame longer than this is not a frame; it is a gap during which the frame loop
// was not running. See the note at the rejection site.
static constexpr double GAP_MS = 2000.0;
static uint64_t  g_gaps = 0;
static double    g_longestGapMs = 0.0;

static uint32_t  g_buckets[BUCKET_COUNT];
static uint32_t  g_overflow    = 0;
static uint64_t  g_frames      = 0;
static double    g_sumMs       = 0.0;
static double    g_maxMs       = 0.0;
static double    g_over33      = 0.0;   // counters kept as double to avoid casts
static double    g_over50      = 0.0;
static double    g_over100     = 0.0;

// Everything above accumulates for the whole session and never forgets, which
// makes the periodic report unable to answer the question people actually ask
// of it. A player reporting that the frame rate degrades over a raid gets a p99
// that has not moved in an hour, because the frames that set it are still in the
// sample; the same is true in reverse, so a fix cannot be seen either. Two
// reporters have now read those percentiles as simply wrong.
//
// So each report also describes the interval since the previous one. That is a
// snapshot-and-subtract at report time rather than a second set of counters, to
// keep the per-frame path exactly as it was. The window maximum is the one
// figure a subtraction cannot recover, so it is tracked directly.
static uint32_t  g_prevBuckets[BUCKET_COUNT];
static uint64_t  g_prevFrames   = 0;
static double    g_prevSumMs    = 0.0;
static double    g_prevOver33   = 0.0;
static double    g_prevOver50   = 0.0;
static double    g_prevOver100  = 0.0;
static double    g_windowMaxMs  = 0.0;
static bool      g_haveWindow   = false;

// A smoothed frame time, updated in constant time.
//
// RecentP95Ms is the honest measure but it copies the window and sorts it, which
// is fine on the quality governor's few-second cadence and far too expensive for
// anything on a per-frame or per-Sleep path. This is the cheap companion: one
// multiply-add per frame, one load to read.
//
// A torn read from another thread can only produce a value that is too large or
// too small, and both callers treat either extreme as a safe default, so it is
// deliberately unsynchronised.
static double g_smoothedMs = 0.0;

double SmoothedFrameMs() { return g_smoothedMs; }

static LARGE_INTEGER g_freq  = {};
static LARGE_INTEGER g_last  = {};
static Source        g_source = Source::None;
static bool          g_ready  = false;

// ---- slow-frame attribution -------------------------------------------------
//
// The distribution says how bad the hitches are; it cannot say what caused them.
// A tester log showed p50 at 2.4ms and p99.9 at 17.4ms - a sevenfold spread in an
// empty area - with no way to tell what those frames were doing.
//
// The event trace already records the state transitions that explain most stalls
// (loading boundaries, lua_State swaps, device resets, cache invalidations). It is
// only useful if something asks for it at the right moment, so a frame that runs
// far past the session's own median asks for it.
//
// The threshold is relative, not a fixed millisecond count: at 400fps a 20ms frame
// is a severe hitch, while during a heavy raid it is an ordinary one. A fixed
// threshold would either miss every hitch on a fast machine or fire constantly on
// a slow one.
static constexpr double SLOW_FRAME_FACTOR   = 5.0;    // times the running median
static constexpr double SLOW_FRAME_FLOOR_MS = 8.0;    // never report below this
static constexpr DWORD  SLOW_FRAME_QUIET_MS = 2000;   // spacing between reports

static double g_medianMs      = 0.0;   // refreshed periodically from the histogram
static double g_p95Ms         = 0.0;   // same walk, so the two are always comparable
static uint64_t g_medianAtFrame = 0;
static DWORD  g_lastSlowReport = 0;
static uint64_t g_slowFrames  = 0;

double MedianMs() { return g_medianMs; }
double SessionP95Ms() { return g_p95Ms; }

static void ComputePercentiles(const uint32_t* buckets, uint64_t frames,
                               double maxMs, const double* wanted,
                               double* out, int n);

// Recomputing the median every frame would walk 1000 buckets per frame. Every 512
// frames is often enough for a threshold and costs nothing measurable.
static void RefreshMedian() {
    if (g_frames - g_medianAtFrame < 512 && g_medianMs > 0.0) return;
    g_medianAtFrame = g_frames;
    // The 95th comes from the same walk. A caller asking "is this session capped"
    // needs the spread, not the middle, and reading the two from different windows
    // would let them disagree.
    static const double wanted[] = { 0.50, 0.95 };
    double p[2] = {};
    ComputePercentiles(g_buckets, g_frames, g_maxMs, wanted, p, 2);
    g_medianMs = p[0];
    g_p95Ms    = p[1];
}

static const char* SourceName(Source s) {
    switch (s) {
        case Source::D3D9Present: return "D3D9 Present";
        case Source::SwapHook:    return "OpenGL swap path";
        default:               return "none";
    }
}

// Identifies the configuration a log was produced under, so two runs can be
// confirmed to differ only where intended.
static uint32_t ConfigFingerprint() {
    const unsigned char* p = (const unsigned char*)&Config::g_settings;
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < sizeof(Config::Settings); i++) {
        h ^= p[i];
        h *= 0x01000193u;
    }
    return h;
}

void Init() {
    memset(g_buckets, 0, sizeof(g_buckets));
    g_overflow = 0;
    g_frames   = 0;
    g_gaps     = 0;
    g_longestGapMs = 0.0;
    g_sumMs    = 0.0;
    g_maxMs    = 0.0;
    g_over33 = g_over50 = g_over100 = 0.0;
    memset(g_prevBuckets, 0, sizeof(g_prevBuckets));
    g_prevFrames = 0;
    g_prevSumMs = 0.0;
    g_prevOver33 = g_prevOver50 = g_prevOver100 = 0.0;
    g_windowMaxMs = 0.0;
    g_haveWindow = false;
    g_last.QuadPart = 0;
    g_source = Source::None;
    g_medianMs = 0.0;
    g_smoothedMs = 0.0;
    g_medianAtFrame = 0;
    g_lastSlowReport = 0;
    g_slowFrames = 0;
    g_ready = QueryPerformanceFrequency(&g_freq) && g_freq.QuadPart > 0;
}

// Rolling window of the most recent frame times, for RecentP95Ms.
//
// The session histogram above answers "how did this run go" and is deliberately
// cumulative - it must not forget, or two runs stop being comparable. Anything
// reacting to conditions needs the opposite: what the last few seconds looked
// like. Separate storage rather than a second meaning for the same numbers.
static constexpr int RECENT_SIZE = 512;
static float    g_recent[RECENT_SIZE];
static int      g_recentCount = 0;
static int      g_recentPos   = 0;

static void NoteRecent(double ms) {
    g_recent[g_recentPos] = (float)ms;
    g_recentPos = (g_recentPos + 1) % RECENT_SIZE;
    if (g_recentCount < RECENT_SIZE) g_recentCount++;
}

double RecentP95Ms() {
    int n = g_recentCount;
    if (n < 64) return 0.0;          // too early to have an opinion

    float copy[RECENT_SIZE];
    for (int i = 0; i < n; i++) copy[i] = g_recent[i];
    std::sort(copy, copy + n);

    int idx = (int)(n * 0.95);
    if (idx >= n) idx = n - 1;
    return (double)copy[idx];
}

// Accumulation is kept separate from the clock so the distribution can be
// exercised on known input: given a synthetic series of frame times, the
// percentiles it reports are checkable without running the game.
static void Accumulate(double ms) {
    if (ms <= 0.0) return;

    // ~50-frame time constant: long enough to ignore a single slow frame, short
    // enough to notice a zone that is genuinely heavier within about a second.
    g_smoothedMs = (g_smoothedMs <= 0.0) ? ms : (g_smoothedMs * 0.98 + ms * 0.02);

    g_frames++;
    g_sumMs += ms;
    if (ms > g_maxMs) g_maxMs = ms;
    if (ms > g_windowMaxMs) g_windowMaxMs = ms;
    if (ms > 33.0)  g_over33  += 1.0;
    if (ms > 50.0)  g_over50  += 1.0;
    if (ms > 100.0) g_over100 += 1.0;

    int b = (int)(ms / BUCKET_MS);
    if (b >= BUCKET_COUNT) g_overflow++;
    else                   g_buckets[b]++;

    NoteRecent(ms);

    RefreshMedian();

    double threshold = g_medianMs * SLOW_FRAME_FACTOR;
    if (threshold < SLOW_FRAME_FLOOR_MS) threshold = SLOW_FRAME_FLOOR_MS;
    if (ms < threshold) return;

    g_slowFrames++;

    // Report at most one in a while. A burst of hitches shares one cause, and the
    // logging itself must not become part of the problem it is describing.
    DWORD now = GetTickCount();
    if (g_lastSlowReport != 0 && (now - g_lastSlowReport) < SLOW_FRAME_QUIET_MS) return;
    g_lastSlowReport = now;

    // Only events from inside the stalled frame can explain it. Anything older is
    // coincidence, and printing it reads as a diagnosis. The window is the frame
    // itself plus a small margin for work that started just before the boundary.
    DWORD window = (DWORD)(ms + 0.5) + 50;
    Log("[FrameBench] slow frame: %.1f ms (%.1fx the %.2f ms median) - events within it:",
        ms, ms / (g_medianMs > 0.0 ? g_medianMs : 1.0), g_medianMs);
    CrashDumper::DumpTrace(8, window);
}

void OnPresent(Source src) {
    if (!g_ready) return;

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);

    LONGLONG prev = g_last.QuadPart;
    g_last = now;
    g_source = src;

    // First frame after start has no meaningful predecessor. A frame that spans a
    // loading screen is discarded for the same reason: the gap is load time, not
    // frame time, and one cold zone load would own the whole tail.
    if (prev == 0 || LuaOpt::IsLoadingMode()) return;

    double ms = (double)(now.QuadPart - prev) * 1000.0 / (double)g_freq.QuadPart;

    // IsLoadingMode is not enough on its own. LoadingDefrag force-exits the loading
    // state after 30 s, and the 3.17.0 logs show that happening on 7 of 12 loads -
    // so for the rest of a long load the client is still on the loading screen while
    // this code believes it is not. That is how a 41.9-second "frame" reached the
    // histogram and became p99.9 and max.
    //
    // Nothing the player would call a frame takes multiple seconds. Count these
    // separately rather than dropping them: a gap is real information, it is just
    // not frame time, and silently discarding it would be the same mistake in the
    // other direction.
    if (ms > GAP_MS) {
        g_gaps++;
        if (ms > g_longestGapMs) g_longestGapMs = ms;
        return;
    }

    Accumulate(ms);
}

// Walks a histogram once, filling in every requested percentile in order.
// Takes the histogram rather than reading the session one, so the same walk
// serves both the cumulative figures and the per-window ones.
static void ComputePercentiles(const uint32_t* buckets, uint64_t frames,
                               double maxMs, const double* wanted,
                               double* out, int n) {
    uint64_t seen = 0;
    int next = 0;
    for (int i = 0; i < BUCKET_COUNT && next < n; i++) {
        seen += buckets[i];
        while (next < n && (double)seen >= wanted[next] * (double)frames) {
            out[next] = (i + 1) * BUCKET_MS;
            next++;
        }
    }
    // Anything not reached inside the histogram lives in the overflow tail.
    while (next < n) {
        out[next] = (maxMs > BUCKET_COUNT * BUCKET_MS) ? maxMs
                                                       : BUCKET_COUNT * BUCKET_MS;
        next++;
    }
}

void Report(const char* reason) {
    // Saying nothing when no frames arrived is how the first version of this hid
    // its own failure: it was fed from the client's OpenGL swap path, which a D3D9
    // client never reaches, so a log with the hook reporting ACTIVE simply had no
    // FrameBench lines at all - indistinguishable from the feature not existing.
    // An instrument that measures nothing has to say so.
    if (!g_ready) {
        Log("[FrameBench] no timer available - QueryPerformanceFrequency failed");
        return;
    }
    if (g_frames == 0) {
        Log("[FrameBench] no frames recorded (%s) - the present hook never fired",
            reason ? reason : "report");
        return;
    }

    static const double wanted[] = { 0.50, 0.95, 0.99, 0.999 };
    double pct[4] = {};
    ComputePercentiles(g_buckets, g_frames, g_maxMs, wanted, pct, 4);

    double avg = g_sumMs / (double)g_frames;
    double seconds = g_sumMs / 1000.0;

    Log("[FrameBench] === FRAME TIME (%s) ===", reason ? reason : "report");
    Log("[FrameBench]   %llu frames over %.1fs, source: %s, config %08X, build %s",
        (unsigned long long)g_frames, seconds, SourceName(g_source),
        ConfigFingerprint(), WOW_OPTIMIZE_VERSION_STR);
    Log("[FrameBench]   session:  avg %.2f ms (%.1f fps)   p50 %.2f   p95 %.2f   p99 %.2f   p99.9 %.2f   max %.2f",
        avg, avg > 0.0 ? 1000.0 / avg : 0.0, pct[0], pct[1], pct[2], pct[3], g_maxMs);
    Log("[FrameBench]   janky frames: >33ms %.0f (%.2f%%)  >50ms %.0f (%.2f%%)  >100ms %.0f (%.2f%%)",
        g_over33,  100.0 * g_over33  / (double)g_frames,
        g_over50,  100.0 * g_over50  / (double)g_frames,
        g_over100, 100.0 * g_over100 / (double)g_frames);

    // The interval since the previous report. Everything above is cumulative and
    // cannot move once a session has run for a while; this is the line that shows
    // a frame rate degrading, or recovering.
    {
        uint64_t winFrames = g_frames - g_prevFrames;
        if (!g_haveWindow) {
            Log("[FrameBench]   since last report: this is the first report of the session");
        } else if (winFrames == 0) {
            Log("[FrameBench]   since last report: no frames presented");
        } else {
            uint32_t winBuckets[BUCKET_COUNT];
            for (int i = 0; i < BUCKET_COUNT; i++)
                winBuckets[i] = g_buckets[i] - g_prevBuckets[i];

            double winPct[4] = {};
            ComputePercentiles(winBuckets, winFrames, g_windowMaxMs, wanted, winPct, 4);

            double winSum = g_sumMs - g_prevSumMs;
            double winAvg = winSum / (double)winFrames;
            double w33 = g_over33  - g_prevOver33;
            double w50 = g_over50  - g_prevOver50;
            double w100 = g_over100 - g_prevOver100;

            Log("[FrameBench]   window:   avg %.2f ms (%.1f fps)   p50 %.2f   p95 %.2f   p99 %.2f   p99.9 %.2f   max %.2f",
                winAvg, winAvg > 0.0 ? 1000.0 / winAvg : 0.0,
                winPct[0], winPct[1], winPct[2], winPct[3], g_windowMaxMs);
            Log("[FrameBench]   window:   %llu frames over %.1fs, >33ms %.0f (%.2f%%)  >50ms %.0f (%.2f%%)  >100ms %.0f (%.2f%%)",
                (unsigned long long)winFrames, winSum / 1000.0,
                w33,  100.0 * w33  / (double)winFrames,
                w50,  100.0 * w50  / (double)winFrames,
                w100, 100.0 * w100 / (double)winFrames);
        }

        for (int i = 0; i < BUCKET_COUNT; i++) g_prevBuckets[i] = g_buckets[i];
        g_prevFrames   = g_frames;
        g_prevSumMs    = g_sumMs;
        g_prevOver33   = g_over33;
        g_prevOver50   = g_over50;
        g_prevOver100  = g_over100;
        g_windowMaxMs  = 0.0;
        g_haveWindow   = true;
    }
    if (g_gaps > 0) {
        // Named, not hidden. These are excluded from every number above, and the
        // longest of them is usually a loading screen that outlived the 30 s
        // LoadingDefrag watchdog - which is worth knowing on its own.
        Log("[FrameBench]   %llu gaps over %.0f s excluded from the above "
            "(longest %.1f s); a gap that long is a load or a hitch, not a frame",
            (unsigned long long)g_gaps, GAP_MS / 1000.0, g_longestGapMs / 1000.0);
    }
    if (g_slowFrames > 0) {
        Log("[FrameBench]   %llu frames ran past %.1fx the median; see the "
            "\"slow frame\" lines above for what each was doing",
            (unsigned long long)g_slowFrames, SLOW_FRAME_FACTOR);
    }
}

} // namespace FrameBench
