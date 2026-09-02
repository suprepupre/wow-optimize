// ============================================================================
// Module: session_verdict.cpp
//
// A tester session produces between half a megabyte and four megabytes of log,
// and nothing in it says what went wrong. Answering "why did his shadows
// flicker" or "why did that load take 139 seconds" has meant twenty to sixty
// greps through periodic reports, every time, for every report.
//
// The information was always there. In the 139-second load it was one line
// saying 1% of it was inside ReadFile, three hundred lines away from the line
// saying the main thread had been blocked thirteen seconds inside the client's
// own file write. In the disconnect logs it was a banner that fired once per
// session instead of once per connection. In the shadow logs it was a counter
// reading zero flips while the player reported constant flicker.
//
// So the instruments say what they found as they find it, and this prints the
// list. It computes nothing and hooks nothing; every line here was already
// somewhere in the log, in a place nobody would look without knowing what they
// were looking for.
//
// ---------------------------------------------------------------------------
// What keeps it honest
//
// It only reports what an instrument actually observed. A quiet session prints
// "nothing was flagged" and names how many instruments were watching, so an
// empty list can be told apart from an absent one - the third state this project
// keeps having to relearn.
//
// Repeats are counted rather than repeated. A load that took too long forty
// times is one line with a count, because the value of this block is that it can
// be read at a glance, and forty copies of the same line destroys that faster
// than a missing line would.
//
// The text is the finding itself, formatted at the moment of the finding, so a
// module reports what it saw rather than a severity and a category that the
// reader then has to decode.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "session_verdict.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

namespace Verdict {
namespace {

constexpr int kMax     = 24;
constexpr int kTextLen = 200;

struct Finding {
    Severity sev;
    unsigned count;
    DWORD    firstTick;
    DWORD    lastTick;
    char     text[kTextLen];
};

Finding  g_list[kMax];
int      g_used = 0;
unsigned g_dropped = 0;

const char* SevName(Severity s) {
    switch (s) {
        case Bad:  return "BAD ";
        case Warn: return "WARN";
        default:   return "note";
    }
}

// Findings are added from the main thread and from the watchdog thread, and this
// is not a hot path - a few dozen calls a session at most - so a lock is the
// right answer rather than a lock-free scheme that would have to be reasoned
// about. SRWLOCK through the project's own wrapper: <mutex> is banned here
// because it pulls MSVCP140 during early init and crashes under translation.
SRWLOCK g_lock = SRWLOCK_INIT;

}  // namespace

void Add(Severity s, const char* fmt, ...) {
    char text[kTextLen];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf(text, sizeof(text) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) n = (int)sizeof(text) - 1;
    text[n < (int)sizeof(text) ? n : (int)sizeof(text) - 1] = 0;

    DWORD now = GetTickCount();

    AcquireSRWLockExclusive(&g_lock);
    for (int i = 0; i < g_used; ++i) {
        if (strcmp(g_list[i].text, text) == 0) {
            ++g_list[i].count;
            g_list[i].lastTick = now;
            if (s > g_list[i].sev) g_list[i].sev = s;
            ReleaseSRWLockExclusive(&g_lock);
            return;
        }
    }
    if (g_used < kMax) {
        Finding& f = g_list[g_used++];
        f.sev = s;
        f.count = 1;
        f.firstTick = now;
        f.lastTick = now;
        lstrcpynA(f.text, text, kTextLen);
    } else {
        ++g_dropped;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

void LogStats() {
    AcquireSRWLockShared(&g_lock);
    int used = g_used;
    Finding snap[kMax];
    for (int i = 0; i < used; ++i) snap[i] = g_list[i];
    unsigned dropped = g_dropped;
    ReleaseSRWLockShared(&g_lock);

    Log("[Verdict] === WHAT WENT WRONG THIS SESSION ===");

    // What was armed, in one line, because answering "was the A/B test even on"
    // has meant grepping a hundred-and-thirty-eight-line settings dump on every
    // log read this week. A measurement that was off finds nothing and says
    // nothing, and that has to be distinguishable from finding nothing.
    {
        char armed[256];
        int w = _snprintf(armed, sizeof(armed) - 1, "[Verdict] measuring:");
        const struct { bool on; const char* name; } m[] = {
            { Config::g_settings.OptAbTest,           "A/B test" },
            { Config::g_settings.OptFlightRecorder,   "flight recorder" },
            { Config::g_settings.OptLuaCompileCensus, "Lua compile census" },
            { Config::g_settings.OptSamplingProfiler, "sampling profiler" },
            { Config::g_settings.OptShadowStateProbe, "shadow probe" },
            { Config::g_settings.OptNetDiag,          "disconnect watch" },
            { Config::g_settings.OptNoClientPatches,  "NO CLIENT PATCHES" },
        };
        int any = 0;
        for (int i = 0; i < (int)(sizeof(m) / sizeof(m[0])); ++i) {
            if (!m[i].on) continue;
            if (w > 0 && w < (int)sizeof(armed) - 40)
                w += _snprintf(armed + w, sizeof(armed) - 1 - w, "%s %s",
                               any ? "," : "", m[i].name);
            ++any;
        }
        armed[sizeof(armed) - 1] = 0;
        if (any) Log("%s", armed);
        else     Log("[Verdict] measuring: nothing. Every instrument is off, so "
                     "an empty report below says nothing about the session.");
    }

    if (used == 0) {
        Log("[Verdict] Nothing was flagged. That is a report from the instruments "
            "that are switched on, not a claim that the session was perfect - one "
            "that is off finds nothing and says nothing.");
        Log("[Verdict] ====================================");
        return;
    }

    // Worst first, and within a severity the one seen most. A reader who stops
    // after one line should have read the most important one.
    for (int pass = Bad; pass >= Note; --pass) {
        for (int i = 0; i < used; ++i) {
            if ((int)snap[i].sev != pass) continue;
            DWORD ago = (GetTickCount() - snap[i].lastTick) / 1000;
            if (snap[i].count == 1) {
                Log("[Verdict] %s %s   (%lus ago)",
                    SevName(snap[i].sev), snap[i].text, (unsigned long)ago);
            } else {
                Log("[Verdict] %s %s   (x%u, last %lus ago)",
                    SevName(snap[i].sev), snap[i].text, snap[i].count,
                    (unsigned long)ago);
            }
        }
    }

    if (dropped) {
        Log("[Verdict] %u further distinct finding(s) did not fit and were "
            "dropped - the ones above are the first seen, not the worst.",
            dropped);
    }
    Log("[Verdict] Every line above is also somewhere in full detail earlier in "
        "this log; this is the index, not the evidence.");
    Log("[Verdict] ====================================");
}

}  // namespace Verdict
