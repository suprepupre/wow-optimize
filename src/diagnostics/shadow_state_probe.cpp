// ============================================================================
// Module: shadow_state_probe.cpp
//
// Two testers independently report that lowering extShadowQuality below 5 makes
// shadows flicker or disappear. One of them settled the important question
// before we could: it happens with every feature of ours switched off, and
// without the DXVK proxy. So this is the client's own bug, and this module does
// not try to fix it - it watches it, so there is something to reason from.
//
// ---------------------------------------------------------------------------
// Why this stopped sampling
//
// The first version read six globals from the main-thread pump every frame and
// inferred whether the shadow pass had run by watching byte_D4316C move. It
// produced a confident, wrong answer: a fifty-minute log reported the pass dead
// for three and a half minutes, and the code says that cannot happen the way it
// was described.
//
// Two defects, both ours. MainThreadPump is called from hooked_Sleep and from
// the frame limiter, and the eight-millisecond gate that deduplicates them sits
// BELOW where the probe was called - so it ran twice per frame. Its sample count
// came out at 2.005x the frames FrameBench counted from D3D9 Present, which is
// what put the defect on the table. And reading a per-pass counter twice per
// frame means the second read always sees no movement, so the "did the pass run"
// figure was structurally capped near half and could sit at zero for minutes
// while shadows rendered perfectly.
//
// A sampler cannot answer this question. The pass either ran or it did not, and
// the only instrument that says so exactly is the pass itself.
//
// ---------------------------------------------------------------------------
// What is measured now
//
// sub_875F80 is the shadow pass. It has one caller, sub_7BB570, which has one
// caller, sub_79A870 - the world render - and it sits on that function's
// unconditional main line at 0x79AC21 with no branch in front of it. So an entry
// count here is also the world-render count, and a window with no entries at all
// is a different fact from a window where the pass was entered and declined.
//
// Read from the top of it:
//
//   dword_B1D51C  the suppress flag. sub_873F80 is six instructions and returns
//                 `flag ? 0 : dword_D43154`, so while it is set every caller
//                 that asks the engine for the shadow quality is told zero.
//                 Changing extShadowQuality sets it. sub_875F80 is the only
//                 thing that clears it, and it clears it on the way past - which
//                 is why sampling almost never caught it set, and why "the flag
//                 was never set" was never evidence of anything.
//
//   D43158/5C/60/64  four function pointers. The pass opens with
//                     if (!D43158 || !D4315C || !D43160 || !D43164) return 0;
//                 and that return is before the flag is cleared, so a null one
//                 leaves shadows suppressed until something sets the pointer.
//
//   dword_D43154  the configured quality. The pass does its work under
//                 `if (quality >= 1)`, so quality 0 means entered and declined.
//
// Those two conditions are the only ways past the entry that skip the work, so
// the classification below is exhaustive by construction rather than by guess.
// Read-only, six reads per pass, off by default, and the client's own code runs
// with every register and the stack exactly as they arrived.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cmath>

#include "shadow_state_probe.h"
#include "MinHook.h"
#include "config.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace {

constexpr uintptr_t ADDR_Pass     = 0x00875F80;
constexpr uintptr_t ADDR_Suppress = 0x00B1D51C;
constexpr uintptr_t ADDR_Quality  = 0x00D43154;
constexpr uintptr_t ADDR_Fn0      = 0x00D43158;
constexpr uintptr_t ADDR_Fn1      = 0x00D4315C;
constexpr uintptr_t ADDR_Fn2      = 0x00D43160;
constexpr uintptr_t ADDR_Fn3      = 0x00D43164;

// The cascade cache, which is where the flicker actually lives.
//
// Every input to the pass has now been measured across two five-hour sessions
// and every one is constant: entered on 100% of frames, ran on 100%, quality 4
// throughout with no change, no null pointer, the reinit flag set once at
// startup, and the second draw asked for on 100% of runs with zero changes
// between consecutive frames. The pass is not the flicker.
//
// sub_874890 is. Below quality 5 it does not redraw the shadow map each frame -
// it keeps three cascades, each with a cached centre, a refresh counter and a
// pair of buffers, and:
//
//   * skips a cascade entirely while the camera stays within a squared distance
//     of the cached centre,
//   * otherwise redraws one slice of it - a third for cascades 0 and 1, a fifth
//     for cascade 2, chosen round-robin by the counter,
//   * and on the counter reaching 9 (or 25 for cascade 2) recentres on the
//     current position and FLIPS the cascade's buffer flag.
//
// At quality 5 that whole branch is skipped and everything is redrawn. Which is
// exactly the shape of the original report - "below extShadowQuality 5 shadows
// flicker" - and of the reproduction: running toward the Alliance bank in
// Dalaran, with the buildings on both sides flickering. Running is what keeps
// pushing the camera past the recentre threshold.
//
// So this counts what the cache does. Read-only, before the client's own code
// runs, and the numbers say whether the recentres and buffer flips line up with
// a flicker or not. Guessing that they do is how this project has twice built a
// feature that skipped nothing.
constexpr uintptr_t ADDR_Cascade  = 0x00874890;
constexpr uintptr_t ADDR_Extent    = 0x00D43298;  // half-size the cascade covers
constexpr uintptr_t ADDR_Threshold = 0x00D4329C;  // squared distance to recentre
constexpr uintptr_t ADDR_CentreX   = 0x00D432A0;  // the cached centre
constexpr uintptr_t ADDR_CentreY   = 0x00D432A4;
constexpr uintptr_t ADDR_CentreZ   = 0x00D432A8;
constexpr uintptr_t ADDR_Counter   = 0x00D432C4;  // refresh counter
constexpr uintptr_t ADDR_BufFlag   = 0x00D432C8;  // flips on every recentre
constexpr unsigned  kCascadeStride = 60;          // 15 dwords per cascade
constexpr int       kCascades      = 3;

constexpr DWORD REPORT_MS = 10000;

bool  g_installed = false;
DWORD g_lastReport = 0;

// Per window. Written from the pass, which is the main thread, and read from the
// same thread, so plain counters - and the report says they are lower bounds.
uint32_t g_entries      = 0;   // times the pass was entered
uint32_t g_ran          = 0;   // times it reached the work
uint32_t g_blockedNull  = 0;   // returned early on a null function pointer
uint32_t g_blockedQual  = 0;   // entered, quality below 1, declined
uint32_t g_reinit       = 0;   // suppress flag was set on entry and got cleared
uint32_t g_nullMask     = 0;
int      g_prevQuality  = -1;
uint32_t g_windows      = 0;

// The second argument, and the reason it is now counted.
//
// Every other input to the pass has been measured and is constant: quality 4 on
// every one of 1205674 entries in a five-hour session, no null pointer, the
// suppress flag set once at startup. The pass runs on every frame. So whatever
// makes shadows flicker is not whether the pass runs, and a2 is the only input
// left that can differ frame to frame.
//
// It matters because it gates a second shadow draw. sub_875F80 does its main
// draw unconditionally and then, under `if (a2)`, sets a mode word - 13 above
// quality 4, 5 above quality 2, otherwise 1 - and draws again through
// dword_D43160 and dword_D43164 with a different source texture. At quality 4
// that second draw uses mode 5. A second layer that appears and disappears from
// frame to frame is what flicker looks like.
//
// Its caller computes it as `flt_ADF59C >= 0.0 || dword_CD8778 != 0`, and
// sub_79A870 resets flt_ADF59C to -1.0 early in each frame, so it is genuinely a
// per-frame decision rather than a setting.
uint32_t g_a2Set        = 0;   // entries where the second draw was asked for
uint32_t g_a2Flips      = 0;   // times it differed from the previous entry
int      g_prevA2       = -1;

// Per cascade, per window.
uint32_t g_cascCalls    = 0;                 // times the cascade updater ran
uint32_t g_cascCached   = 0;                 // it took the caching branch at all
uint32_t g_cascSkip[kCascades]   = {};       // camera inside the threshold, no redraw
uint32_t g_cascDraw[kCascades]   = {};       // a slice was redrawn
uint32_t g_cascFlip[kCascades]   = {};       // the buffer flag toggled
int      g_prevFlag[kCascades]   = { -1, -1, -1 };
float    g_worstMove[kCascades]  = {};       // furthest the camera got from the centre
float    g_threshold[kCascades]  = {};       // the squared distance it is compared with
float    g_extent[kCascades]     = {};       // the half-size the cascade covers

// ---------------------------------------------------------------------------
// Holding the cascade centre still for longer
//
// prince's log settles the mechanism. Over 108,225 cascade updates, buffer
// toggles run at 45.3 per thousand frames while moving against 1.0 standing
// still for cascade 0, 31.2 against 0.5 for cascade 1, and 5.9 against exactly
// zero for cascade 2. Redraws divided by toggles is 9.0, matching the counter
// reset the disassembly shows. And the recentre distances are tiny: 4.0, 16.0
// and 1024.0 squared, which is 2, 4 and 32 yards.
//
// So cascade 0 recentres every two yards. Each recentre re-projects the shadow
// map around a new point and restarts the round-robin at slice zero, leaving two
// thirds of the map stale for the new projection until the next frames catch up.
// At running speed that is about three and a half times a second, which is what
// "the houses on both sides flicker as you run" looks like.
//
// Between recentres the map stays complete - the round-robin keeps it that way.
// So a larger recentre distance buys longer stretches of a complete map that is
// slightly off-centre, and off-centre is invisible while the camera is inside
// the area the cascade covers.
//
// That last clause is the whole safety argument, so this does not take a
// multiplier on trust. It reads the cascade's own half-size and never lets the
// drift exceed a quarter of it, so the camera cannot leave the covered area no
// matter what the raise would have been. It never lowers a threshold either.
//
// Off by default and separate from the probe's switch: with only the probe on,
// nothing here writes anything.
bool     g_holdActive = false;
uint32_t g_holdWrites = 0;
float    g_holdFrom[kCascades] = {};
float    g_holdTo[kCascades]   = {};
// A ratchet, and how it was found.
//
// The first version read the threshold from the client every frame and
// multiplied THAT by the factor - but by the second frame the value it read was
// one this module had already written. So it climbed by 16x per frame until it
// hit the cap, and the cap is where it stayed. prince's log showed it plainly:
// the "before" values printed as 64.0, 256.0 and 16384.0, exactly sixteen times
// the 4.0, 16.0 and 1024.0 of the session before, and the "after" values were
// the caps to the digit.
//
// So cascade 0 ended up recentring at ten yards inside a cascade forty yards
// across, and he reported the shadows lagging. Which they were: the map was
// being built around a point up to ten yards behind him.
//
// The stock value is captured the first time each cascade is seen and every
// target is computed from that, never from the current value. And the raise is
// halved: four times the squared threshold is twice the distance, which is a
// smaller change than the caps were making on their own.
constexpr float kHoldMaxFactor = 4.0f;    // on the SQUARED threshold, so 2x distance
constexpr float kHoldDriftFrac = 0.10f;   // nor past this share of the extent
float    g_holdStock[kCascades] = {};     // the client's own value, captured once
bool     g_holdHaveStock[kCascades] = {};

// Whole session, so a window that never fires still has something behind it.
uint32_t g_totalEntries = 0;
uint32_t g_totalRan     = 0;

}  // namespace

// At file scope: the naked thunk reaches it from inline assembly.
static void* g_origPass = nullptr;

extern "C" void __cdecl ShadowProbe_NoteEntry(uint32_t a2) {
    uint32_t suppress, quality, f0, f1, f2, f3;
    __try {
        suppress = *(volatile uint32_t*)ADDR_Suppress;
        quality  = *(volatile uint32_t*)ADDR_Quality;
        f0 = *(volatile uint32_t*)ADDR_Fn0;
        f1 = *(volatile uint32_t*)ADDR_Fn1;
        f2 = *(volatile uint32_t*)ADDR_Fn2;
        f3 = *(volatile uint32_t*)ADDR_Fn3;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    g_entries++;
    g_totalEntries++;
    if (suppress) g_reinit++;

    if (!f0 || !f1 || !f2 || !f3) {
        g_blockedNull++;
        if (!f0) g_nullMask |= 1;
        if (!f1) g_nullMask |= 2;
        if (!f2) g_nullMask |= 4;
        if (!f3) g_nullMask |= 8;
        return;
    }
    if ((int)quality < 1) { g_blockedQual++; return; }

    g_ran++;
    g_totalRan++;

    int a2Now = a2 ? 1 : 0;
    if (a2Now) g_a2Set++;
    if (g_prevA2 >= 0 && a2Now != g_prevA2) g_a2Flips++;
    g_prevA2 = a2Now;

    if (g_prevQuality >= 0 && (int)quality != g_prevQuality) {
        Log("[ShadowProbe] extShadowQuality changed %d -> %d", g_prevQuality, (int)quality);
    }
    g_prevQuality = (int)quality;
}

// Read the cascade cache before the client's own updater changes it. Nothing is
// written; every value here is one the client is about to read for itself.
extern "C" void __cdecl ShadowProbe_NoteCascade(const float* pos) {
    if (!pos) return;
    __try {
        g_cascCalls++;
        uint32_t suppress = *(volatile uint32_t*)ADDR_Suppress;
        uint32_t quality  = *(volatile uint32_t*)ADDR_Quality;
        if ((suppress ? 0u : quality) >= 5u) return;   // the uncached branch
        g_cascCached++;

        for (int c = 0; c < kCascades; c++) {
            unsigned off = kCascadeStride * (unsigned)c;
            uint32_t counter = *(volatile uint32_t*)(ADDR_Counter + off);
            int      flag    = *(volatile uint32_t*)(ADDR_BufFlag + off) ? 1 : 0;
            float    thr     = *(volatile float*)(ADDR_Threshold + off);
            float    cx      = *(volatile float*)(ADDR_CentreX + off);
            float    cy      = *(volatile float*)(ADDR_CentreY + off);
            float    cz      = *(volatile float*)(ADDR_CentreZ + off);

            double dx = (double)cx - (double)pos[0];
            double dy = (double)cy - (double)pos[1];
            double dz = (double)cz - (double)pos[2];
            double d2 = dx * dx + dy * dy + dz * dz;

            g_threshold[c] = thr;
            g_extent[c]    = *(volatile float*)(ADDR_Extent + off);
            if (d2 > (double)g_worstMove[c]) g_worstMove[c] = (float)d2;

            if (g_holdActive && g_extent[c] > 0.0f && thr > 0.0f) {
                // Capture the client's own value once, and notice if it ever
                // changes it back - a settings change would, and computing from
                // a value of ours is what made this ratchet.
                if (!g_holdHaveStock[c] ||
                    (thr != g_holdStock[c] && thr != g_holdTo[c])) {
                    g_holdStock[c]     = thr;
                    g_holdHaveStock[c] = true;
                }
                float stock = g_holdStock[c];
                float drift = g_extent[c] * kHoldDriftFrac;
                float cap   = drift * drift;              // compared squared
                float want  = stock * kHoldMaxFactor;
                if (want > cap) want = cap;
                g_holdFrom[c] = stock;
                g_holdTo[c]   = want;
                if (want > thr) {
                    *(volatile float*)(ADDR_Threshold + off) = want;
                    g_holdWrites++;
                }
            }

            // The client's own test: with the counter at zero, staying inside the
            // threshold skips the cascade entirely for this frame.
            if (counter == 0 && d2 <= (double)thr) g_cascSkip[c]++;
            else                                   g_cascDraw[c]++;

            if (g_prevFlag[c] >= 0 && flag != g_prevFlag[c]) g_cascFlip[c]++;
            g_prevFlag[c] = flag;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// sub_874890 is __cdecl(a1, a2 = the camera position, a3, a4).
void* g_origCascade = nullptr;
__declspec(naked) static void HookedCascade() {
    __asm {
        pushad
        pushfd
        mov  eax, [esp+2Ch]        ; a2, the position: entry [esp+8] under 0x24
        push eax
        call ShadowProbe_NoteCascade
        add  esp, 4
        popfd
        popad
        jmp  dword ptr [g_origCascade]
    }
}

// sub_875F80 is __cdecl with two stack arguments and a plain retn. Everything is
// preserved and the client's own code runs unchanged.
__declspec(naked) static void HookedShadowPass() {
    __asm {
        pushad                        ; 32 bytes
        pushfd                        ; 4 more, so 0x24 below the entry stack
        mov  eax, [esp+2Ch]           ; a2: entry [esp+8], now [esp+0x24+8]
        push eax
        call ShadowProbe_NoteEntry
        add  esp, 4
        popfd
        popad
        jmp  dword ptr [g_origPass]
    }
}

namespace ShadowStateProbe {

bool Init() {
    // Two switches share this file and they gate different things. The probe is a
    // diagnostic; the hold is the flicker fix a player would tick and expect to
    // work. The hold lives in the cascade hook, which was installed below this
    // early return, so ticking "Steadier Shadows" on its own did nothing at all -
    // silently, with the launcher showing it enabled.
    //
    // The cascade hook now installs when either switch is on. The pass hook and
    // the periodic report stay with the probe, because those are the diagnostic.
    g_holdActive = Config::g_settings.OptShadowCascadeHold;
    const bool wantProbe = Config::g_settings.OptShadowStateProbe;
    if (!wantProbe && !g_holdActive) return true;

    if (wantProbe && IsBadReadPtr((void*)ADDR_Pass, 16)) {
        Log("[ShadowProbe] 0x%08X unreadable - not installing", (unsigned)ADDR_Pass);
        return false;
    }
    if (wantProbe &&
        WineSafe_CreateHook((void*)ADDR_Pass, (void*)HookedShadowPass, &g_origPass) != MH_OK) {
        Log("[ShadowProbe] hook NOT created");
        return false;
    }
    if (wantProbe && WO_EnableHook((void*)ADDR_Pass) != MH_OK) {
        Log("[ShadowProbe] hook created but could not be enabled");
        return false;
    }

    // The cascade updater, installed separately so a failure there leaves the
    // pass hook above working rather than taking it down.
    if (!IsBadReadPtr((void*)ADDR_Cascade, 16) &&
        WineSafe_CreateHook((void*)ADDR_Cascade, (void*)HookedCascade, &g_origCascade) == MH_OK &&
        WO_EnableHook((void*)ADDR_Cascade) == MH_OK) {
        Log("[ShadowProbe] also watching the cascade cache (sub_874890 @ 0x%08X). "
            "Below quality 5 the shadow map is not redrawn each frame: three "
            "cascades each keep a centre, a counter and two buffers, skip "
            "entirely while the camera stays within a squared distance of the "
            "centre, redraw one slice at a time otherwise, and flip a buffer on "
            "recentring. That is the shape of the report - flicker below quality "
            "5, worst while running - so it is counted rather than assumed.",
            (unsigned)ADDR_Cascade);
    } else {
        Log("[ShadowProbe] the cascade cache at 0x%08X was NOT hooked - the pass "
            "counters above still work", (unsigned)ADDR_Cascade);
    }

    if (g_holdActive && !g_origCascade) {
        Log("[ShadowProbe] Steadier Shadows is ON but the cascade cache could not "
            "be hooked, so it is doing nothing this session.");
    }
    if (g_holdActive && g_origCascade) {
        Log("[ShadowProbe] cascade hold is ON: the recentre distance is doubled "
            "(%.0fx on the squared value), never past %.0f%% of the cascade's own "
            "half-size, and always computed from the client's stock value rather "
            "than the current one. The first version computed from the current "
            "one and ratcheted to the cap in a few frames - cascade 0 reached ten "
            "yards inside a forty-yard cascade, and the tester reported the "
            "shadows lagging, which they were.",
            (double)kHoldMaxFactor, 100.0 * (double)kHoldDriftFrac);
    }

    if (!wantProbe) {
        Log("[ShadowProbe] the pass counters are off (Shadow State Probe), so this "
            "session reports nothing about shadows - only the hold above runs.");
        return true;
    }

    g_installed = true;
    g_lastReport = GetTickCount();
    Log("[ShadowProbe] ACTIVE on the shadow pass (sub_875F80 @ 0x%08X). It counts "
        "entries and classifies each one, instead of sampling globals from the "
        "main-thread pump the way it used to - that ran twice per frame and "
        "reported the pass dead for minutes at a time while shadows were fine. "
        "The pass sits on the unconditional main line of the world render, so an "
        "entry count is a frame count, and no entries at all is a different "
        "finding from entered-and-declined. Read-only; reports every %lu seconds.",
        (unsigned)ADDR_Pass, (unsigned long)(REPORT_MS / 1000));
    return true;
}

void OnFrame() {
    if (!g_installed) return;

    DWORD now = GetTickCount();
    if (now - g_lastReport < REPORT_MS) return;
    g_lastReport = now;
    ++g_windows;

    if (g_entries == 0) {
        Log("[ShadowProbe] #%u  the shadow pass was not entered at all in this "
            "window. It is called unconditionally from the world render, so this "
            "means the world was not being rendered - a loading screen, character "
            "select, or a minimised window. %u entries and %u runs so far this "
            "session.", g_windows, g_totalEntries, g_totalRan);
        g_nullMask = 0;
        return;
    }

    Log("[ShadowProbe] #%u  quality=%d  %u entries: ran %u (%.1f%%), declined on a "
        "null pointer %u, declined on quality %u, reinit flag was set on entry %u "
        "time(s). Counts are lower bounds.",
        g_windows, g_prevQuality, g_entries, g_ran,
        100.0 * (double)g_ran / (double)g_entries,
        g_blockedNull, g_blockedQual, g_reinit);

    if (g_ran) {
        Log("[ShadowProbe]   the second shadow draw was asked for on %u of those "
            "%u runs (%.1f%%) and changed between consecutive frames %u time(s). "
            "It is the only input to the pass that varies, so if it is flipping, "
            "that is a shadow layer appearing and disappearing.",
            g_a2Set, g_ran, 100.0 * (double)g_a2Set / (double)g_ran, g_a2Flips);
    }

    if (g_blockedNull) {
        Log("[ShadowProbe]   a null function pointer (mask %u) returns before the "
            "suppress flag is cleared, so shadows stay off until something sets "
            "that pointer. This is the state that looks like shadows being gone "
            "for good.", g_nullMask);
    } else if (g_ran == 0) {
        Log("[ShadowProbe]   entered every time and never did the work, with no "
            "null pointer - so quality read below 1 while the launcher and the "
            "client disagree about what it is set to");
    }

    if (g_cascCalls) {
        Log("[ShadowProbe]   cascade cache: %u updates, %u of them on the cached "
            "branch. Per cascade - skipped/redrawn/buffer-flips, and the furthest "
            "the camera got from the cached centre against the distance that "
            "triggers a recentre:", g_cascCalls, g_cascCached);
        for (int c = 0; c < kCascades; c++) {
            Log("[ShadowProbe]     cascade %d: %u skipped, %u redrawn, %u flips, "
                "worst %.1f vs threshold %.1f (squared, = %.1f yards), cascade "
                "covers %.1f yards either side",
                c, g_cascSkip[c], g_cascDraw[c], g_cascFlip[c],
                (double)g_worstMove[c], (double)g_threshold[c],
                sqrt((double)g_threshold[c]), (double)g_extent[c]);
        }
        Log("[ShadowProbe]     a flip is the cascade swapping which buffer it "
            "shows. Measured over 108225 updates: 45.3 flips per thousand frames "
            "while moving against 1.0 standing still for cascade 0. That is the "
            "flicker, and it is the client's own cache.");
        if (g_holdActive) {
            Log("[ShadowProbe]     hold wrote %u time(s) this window. Stock -> "
                "held, as distances: cascade 0 %.1f -> %.1f yards, 1 %.1f -> "
                "%.1f, 2 %.1f -> %.1f. Stock is the client's own value, captured "
                "once - computing from the current one is what made this ratchet "
                "to the cap in prince's first run.",
                g_holdWrites,
                sqrt((double)g_holdFrom[0]), sqrt((double)g_holdTo[0]),
                sqrt((double)g_holdFrom[1]), sqrt((double)g_holdTo[1]),
                sqrt((double)g_holdFrom[2]), sqrt((double)g_holdTo[2]));
        }
        g_holdWrites = 0;
    } else {
        Log("[ShadowProbe]   the cascade updater was never called this window");
    }

    g_entries = g_ran = g_blockedNull = g_blockedQual = g_reinit = 0;
    g_a2Set = g_a2Flips = 0;
    g_cascCalls = g_cascCached = 0;
    for (int c = 0; c < kCascades; c++) {
        g_cascSkip[c] = g_cascDraw[c] = g_cascFlip[c] = 0;
        g_worstMove[c] = 0.0f;
    }
    g_nullMask = 0;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook((void*)ADDR_Pass);
    if (g_origCascade) MH_DisableHook((void*)ADDR_Cascade);
}

} // namespace ShadowStateProbe
