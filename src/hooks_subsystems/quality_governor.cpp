// ============================================================================
// Module: quality_governor.cpp
// Description: One quality dial for the settings that cost GPU time. Turns it
//              down while the frame-time tail says the machine cannot keep up,
//              and back up to the player's own values when it can.
// Safety & Threading: Main thread only.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "quality_governor.h"
#include "version.h"
#include "core/config.h"
#include "diagnostics/frame_bench.h"
#include "diagnostics/crash_dumper.h"

extern "C" void Log(const char* fmt, ...);

namespace QualityGovernor {

typedef char (__fastcall* CVar_Set_fn)(void* cvar, void* edx, const char* value,
                                       char a3, char a4, char a5, char a6);
static const CVar_Set_fn g_cvarSet = (CVar_Set_fn)0x007668C0;

// ---------------------------------------------------------------------------
// One dial, not three controllers
//
// This replaces DynamicShadowScaler, AdaptiveFarclip and ParticleDensityScaler.
// All three had the same shape and the same defect: an EMA over 1000/elapsed,
// thresholds a single frame could cross, and no idea what the player had chosen.
// The shadow one changed quality several times a minute while a tester walked
// around; the farclip one restores above 58fps and reduces below 55, a three-frame
// band that anyone playing near 60 crosses constantly.
//
// Three independent controllers also means three separate opinions about how the
// machine is doing, arrived at from the same frames. One dial with defined steps
// is easier to reason about and produces one decision instead of three.
//
// Step 0 is always exactly what the player set. Each step adds a reduction; no
// step ever exceeds the player's value, and level 0 shadows are never reached
// because shadows switched off entirely look like a fault, not an adaptation.
// ---------------------------------------------------------------------------
enum Managed { M_PARTICLES = 0, M_SHADOWS, M_FARCLIP, M_COUNT };

struct Setting {
    const char* cvar;
    bool        isFloat;
    void*       obj;        // learned by watching a write go past
    double      userValue;  // the player's own value: the ceiling
    double      current;    // what is set now
    bool        known;
};

static Setting g_set[M_COUNT] = {
    { "particleDensity",  true,  nullptr, 0.0, 0.0, false },
    { "extShadowQuality", false, nullptr, 0.0, 0.0, false },
    { "farclip",          true,  nullptr, 0.0, 0.0, false },
};

// A setting with an existing owner is left alone.
//
// Nothing else writes these three any more. DynamicShadowScaler was removed,
// AdaptiveFarclip and ParticleDensityScaler have been reduced to the CVar
// bookkeeping they also did, so there is one controller per setting rather than
// two with different opinions. The table stays because that guarantee is worth
// checking rather than assuming, and startup logs what it took charge of.
static bool g_managed[M_COUNT] = { false, true, false };

static void DecideOwnership() {
    g_managed[M_PARTICLES] = true;   // ParticleDensityScaler no longer scales it
    g_managed[M_SHADOWS]   = true;
    g_managed[M_FARCLIP]   = true;   // AdaptiveFarclip no longer scales it
}

// What each step does, as a fraction of the player's own value. Particles go
// first because fewer of them is the least noticeable while moving; draw distance
// goes last because shortening it changes what you can see coming.
static const int MAX_STEP = 3;
static double StepFactor(int which, int step) {
    switch (which) {
        case M_PARTICLES: return (step >= 1) ? 0.60 : 1.0;
        case M_SHADOWS:   return (step >= 2) ? 0.0  : 1.0;   // handled as -1 level
        case M_FARCLIP:   return (step >= 3) ? 0.75 : 1.0;
    }
    return 1.0;
}

// ---------------------------------------------------------------------------
// Thresholds. Both on the 95th percentile of the last few seconds, never on an
// instantaneous frame rate. The bands do not touch and the dwells are asymmetric:
// quick to help, slow to undo. Recovering takes 30 seconds of frames comfortably
// better than the level that triggered a reduction, so it cannot oscillate.
// ---------------------------------------------------------------------------
static const double DEGRADE_P95_MS   = 33.0;
static const double RESTORE_P95_MS   = 20.0;
static const DWORD  DEGRADE_DWELL_MS = 5000;
static const DWORD  RESTORE_DWELL_MS = 30000;
static const DWORD  MIN_ACTION_GAP_MS = 10000;

static int    g_step        = 0;
static bool   g_writingOurs = false;
static DWORD  g_badSince    = 0;
static DWORD  g_goodSince   = 0;
static DWORD  g_lastAction  = 0;
static int    g_featureToken = -1;
static int    g_deepest     = 0;
static bool   g_enabled     = false;

static int Find(const char* name) {
    for (int i = 0; i < M_COUNT; i++) {
        if (_stricmp(g_set[i].cvar, name) == 0) return i;
    }
    return -1;
}

// A setting this governor cannot actually apply is one it has no business
// touching, and that is decidable from the CVar itself.
//
// CVar::Set at 0x007668C0 branches on the byte at cvar+0x28. With bit 1 set it
// does not store the value into the live field at all: it assigns the string to
// a second field through RCString::Set and raises the global byte_CA19F8, then
// returns without reaching the normal store. The value becomes a pending change
// that the client applies at a time of its own choosing.
//
// That alone makes such a CVar wrong for this governor, whatever the client then
// does with it. The whole loop is write a value, watch the frame-time tail, and
// decide from the result - and it cannot measure the effect of a change it did
// not make. It also leaves a change queued inside the client that the player
// never asked for.
//
// The occasion for finding it: a session on 2026-08-21 where the player was
// walking and hitting mobs saw the screen flash like a /reload. The log has
// particleDensity written at 14:33:23, farclip at 14:33:43, and the Lua state
// recreated at 14:34:03 - a real interface reload, with no Lua error before it
// and nothing in this DLL that calls ReloadUI. Applying a pending graphics
// setting is the most likely thing to have done that, but this is a correlation
// across one session and the causal step is not proved here.
//
// So a managed setting is checked when its object is learned, and one carrying
// that bit is dropped and named in the log.
static constexpr unsigned kCVarNeedsRestartBit = 2;   // cvar+0x28 & 2
static constexpr unsigned kCVarFlagsOffset     = 0x28;

void NoteCVarObject(void* cvar, const char* name) {
    if (!g_enabled || !cvar || !name) return;
    int i = Find(name);
    if (i < 0 || !g_managed[i]) return;

    unsigned char flags = 0;
    __try {
        flags = *((const unsigned char*)cvar + kCVarFlagsOffset);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_managed[i] = false;
        Log("[QualityGovernor] %s - could not read its flags, so it is left alone",
            g_set[i].cvar);
        return;
    }

    if (flags & kCVarNeedsRestartBit) {
        g_managed[i] = false;
        Log("[QualityGovernor] %s is flagged as needing the client to restart "
            "something before it takes effect, so this will not touch it. "
            "Changing it would blank the screen and reload the interface.",
            g_set[i].cvar);
        return;
    }

    g_set[i].obj = cvar;
}

void NoteCVarWrite(const char* name, const char* value) {
    if (!g_enabled || !name || !value) return;
    int i = Find(name);
    if (i < 0 || !g_managed[i]) return;

    // Our own write coming back around. Recording it would make a reduction the
    // new ceiling, and the player's setting would ratchet down and never return -
    // which is exactly how the feature this replaces destroyed people's settings.
    if (g_writingOurs) return;

    double v = atof(value);
    if (v < 0.0 || v > 100000.0) return;

    g_set[i].userValue = v;
    g_set[i].current   = v;
    g_set[i].known     = true;
    Log("[QualityGovernor] Player's %s is %.3g - that is the ceiling", g_set[i].cvar, v);
}

static void Write(int i, double value, const char* why) {
    Setting& s = g_set[i];
    if (!s.obj || !s.known) return;

    char buf[32];
    if (s.isFloat) _snprintf(buf, sizeof(buf), "%.3f", value);
    else           _snprintf(buf, sizeof(buf), "%d", (int)(value + 0.5));
    buf[sizeof(buf) - 1] = '\0';

    g_writingOurs = true;
    __try {
        g_cvarSet(s.obj, nullptr, buf, 1, 0, 0, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_writingOurs = false;
        return;
    }
    g_writingOurs = false;

    Log("[QualityGovernor] %s %.3g -> %s (%s, p95 %.1f ms, player's value %.3g)",
        s.cvar, s.current, buf, why, FrameBench::RecentP95Ms(), s.userValue);
    s.current = value;
}

// Applies the whole dial position at once, so the three settings can never drift
// out of agreement about which step they are on.
static void ApplyStep(int step, const char* why) {
    if (step < 0) step = 0;
    if (step > MAX_STEP) step = MAX_STEP;

    for (int i = 0; i < M_COUNT; i++) {
        Setting& s = g_set[i];
        if (!g_managed[i] || !s.known || !s.obj) continue;

        double target;
        if (i == M_SHADOWS) {
            // Integer levels, and never below 1.
            target = (step >= 2) ? (s.userValue - 1.0) : s.userValue;
            if (target < 1.0) target = 1.0;
            if (target > s.userValue) target = s.userValue;
        } else {
            target = s.userValue * StepFactor(i, step);
        }

        if (target != s.current) Write(i, target, why);
    }

    g_step = step;
    g_lastAction = GetTickCount();
    if (step > g_deepest) g_deepest = step;
    CrashDumper::Trace("QualityGovernor: step %d (%s)", step, why);
    CrashDumper::FeatureHit(g_featureToken);
}

void OnFrame() {
    if (!g_enabled) return;

    bool anyKnown = false;
    for (int i = 0; i < M_COUNT; i++) {
        if (g_managed[i] && g_set[i].known && g_set[i].obj) { anyKnown = true; break; }
    }
    if (!anyKnown) return;

    double p95 = FrameBench::RecentP95Ms();
    if (p95 <= 0.0) return;            // not enough frames to have an opinion

    DWORD now = GetTickCount();

    if (p95 >= DEGRADE_P95_MS) {
        g_goodSince = 0;
        if (g_badSince == 0) g_badSince = now;
    } else if (p95 <= RESTORE_P95_MS) {
        g_badSince = 0;
        if (g_goodSince == 0) g_goodSince = now;
    } else {
        // Between the bands neither timer runs. This is what stops a value
        // hovering near a threshold from being read as a sustained trend.
        g_badSince = 0;
        g_goodSince = 0;
        return;
    }

    if (g_lastAction != 0 && (now - g_lastAction) < MIN_ACTION_GAP_MS) return;

    if (g_badSince != 0 && (now - g_badSince) >= DEGRADE_DWELL_MS) {
        if (g_step < MAX_STEP) ApplyStep(g_step + 1, "frames sustained slow");
        g_badSince = 0;
    } else if (g_goodSince != 0 && (now - g_goodSince) >= RESTORE_DWELL_MS) {
        if (g_step > 0) ApplyStep(g_step - 1, "frames recovered");
        g_goodSince = 0;
    }
}

bool Init() {
    g_enabled = Config::g_settings.OptQualityGovernor;
    if (!g_enabled) {
        Log("[QualityGovernor] DISABLED via configuration");
        return false;
    }
    g_featureToken = CrashDumper::FeatureTokenForCounting("QualityGovernor");
    DecideOwnership();

    Log("[QualityGovernor] Active - follows the frame-time tail, never above the "
        "player's own values (down at p95>%.0fms for %us, up at p95<%.0fms for %us)",
        DEGRADE_P95_MS, DEGRADE_DWELL_MS / 1000, RESTORE_P95_MS, RESTORE_DWELL_MS / 1000);
    for (int i = 0; i < M_COUNT; i++) {
        if (g_managed[i]) {
            Log("[QualityGovernor]   manages %s", g_set[i].cvar);
        } else {
            Log("[QualityGovernor]   leaves %s alone - another scaler owns it", g_set[i].cvar);
        }
    }
    return true;
}

void Shutdown() {
    if (!g_enabled) return;

    // Put the player's own values back. The features this replaces could not do
    // this - they never knew what to restore - and left people with settings they
    // had not chosen and could not account for.
    if (g_step != 0) ApplyStep(0, "restoring the player's settings on shutdown");

    if (g_deepest > 0) {
        Log("[QualityGovernor] Reduced quality this session, deepest step %d of %d",
            g_deepest, MAX_STEP);
    } else {
        Log("[QualityGovernor] Never had to reduce quality this session");
    }
}

} // namespace QualityGovernor
