// ============================================================================
// Module: shadow_state_probe.cpp
//
// Two testers independently report that lowering extShadowQuality below 5 makes
// shadows flicker or disappear. One of them settled the important question
// before we could: it happens with every feature of ours switched off, and
// without the DXVK proxy. So this is the client's own bug, and this module does
// not try to fix it - it watches it, so there is something to reason from.
//
// What it watches, from reading the shadow subsystem at 0x873F80..0x876000:
//
//   dword_B1D51C  the shadow suppress flag. While it is set, sub_873F80 reports
//                 an effective quality of 0 to the whole engine and sub_8744E0
//                 binds no shadow constants and no shadow textures at all.
//                 Changing extShadowQuality sets it (sub_874210). Exactly one
//                 function clears it - sub_875F80, the shadow pass, reached from
//                 one call site.
//
//   dword_D43154  the configured quality, 0-5.
//
//   D43158/5C/60/64  four function pointers the shadow pass needs. sub_875F80
//                 opens with
//                     if (!D43158 || !D4315C || !D43160 || !D43164) return 0;
//                 and that return happens *before* the flag is cleared. If any
//                 of them is null at a given quality, the pass gives up and the
//                 suppress flag stays set - which is what permanently missing
//                 shadows would look like.
//
//   byte_D4316C   a counter the pass increments, used as a ring index only at
//                 quality >= 5:  if (v5 >= 5) v3 = byte_D4316C; else v3 = 0;
//                 So it also tells us whether the pass is running at all.
//
// Between them these separate the three explanations that fit the symptom:
// a flag oscillating frame to frame, a null pointer wedging the pass, or the
// pass simply not running. Read-only, six dwords a frame, off by default.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

#include "shadow_state_probe.h"
#include "config.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);
extern DWORD g_mainThreadId;

namespace ShadowStateProbe {

static constexpr uintptr_t ADDR_Suppress = 0x00B1D51C;  // dword_B1D51C
static constexpr uintptr_t ADDR_Quality  = 0x00D43154;  // dword_D43154
static constexpr uintptr_t ADDR_Fn0      = 0x00D43158;
static constexpr uintptr_t ADDR_Fn1      = 0x00D4315C;
static constexpr uintptr_t ADDR_Fn2      = 0x00D43160;
static constexpr uintptr_t ADDR_Fn3      = 0x00D43164;
static constexpr uintptr_t ADDR_PassTick = 0x00D4316C;  // byte_D4316C

static bool  g_active = false;
static DWORD g_lastReport = 0;
static constexpr DWORD REPORT_MS = 10000;

// Per window.
//
// These count SAMPLES, not frames, and the first version of this file called
// them frames. It is called from MainThreadPump, which is not the render loop:
// in the log that prompted the fix it took 135163 samples while the client
// presented 305208 frames, so it saw 44.3% of them and a reader dividing by ten
// seconds got a frame rate that was wrong by more than half.
//
// What that does and does not cost is worth stating, because the answer differs
// per counter. g_passAdvanced watches a byte the client bumps once per shadow
// pass; under-sampling can only make it miss a change, never invent one, so a
// window reporting zero really is a window where the pass did not run.
// g_suppressed and g_flips are shares of samples: a flag toggling faster than
// the sample rate could alias, though a per-frame toggle would still show up as
// roughly half the samples suppressed rather than none of them.
static uint32_t g_samples       = 0;
static uint32_t g_suppressed    = 0;   // samples with the flag set
static uint32_t g_flips         = 0;   // transitions either way
static uint32_t g_passAdvanced  = 0;   // samples where the pass counter moved
static uint32_t g_nullPtrFrames = 0;   // samples with any of the four null
static DWORD    g_windowStart   = 0;
static int      g_prevSuppress  = -1;
static uint32_t g_prevTick      = 0xFFFFFFFF;
static int      g_prevQuality   = -1;
static uint32_t g_nullMask      = 0;   // which pointers were seen null

// A ten-second window can say the pass did not run; it cannot say when it
// stopped, and the moment is what identifies the cause. In the log that prompted
// this, the pass died 17 seconds after a PLAYER_LEAVING_WORLD loading screen and
// stayed dead for three and a half minutes - which is only visible by lining two
// timestamps up by hand. So the transition is logged as it happens, and the next
// log answers "stopped right after what" by itself.
static bool     g_passStalled   = false;
static uint32_t g_stillSamples  = 0;
static DWORD    g_lastMoveAt    = 0;
static constexpr uint32_t kStallSamples = 60;   // about a second at the observed rate

// Whole session.
static uint32_t g_windows = 0;

bool Init() {
    if (!Config::g_settings.OptShadowStateProbe) return true;
    g_active = true;
    g_lastReport = g_windowStart = GetTickCount();
    Log("[ShadowProbe] Watching the client's shadow state (suppress flag 0x%08X, "
        "quality 0x%08X). Read-only; reports every %lu seconds. It samples from "
        "the main-thread pump, NOT from the render loop, so the counts below are "
        "samples and the report says how many per second - do not read a frame "
        "rate out of them.",
        (unsigned)ADDR_Suppress, (unsigned)ADDR_Quality,
        (unsigned long)(REPORT_MS / 1000));
    return true;
}

void OnFrame() {
    if (!g_active) return;
    if (GetCurrentThreadId() != g_mainThreadId) return;

    uint32_t suppress, quality, tick;
    uint32_t nulls = 0;
    __try {
        suppress = *(volatile uint32_t*)ADDR_Suppress;
        quality  = *(volatile uint32_t*)ADDR_Quality;
        tick     = *(volatile uint8_t*)ADDR_PassTick;
        if (!*(volatile uint32_t*)ADDR_Fn0) nulls |= 1;
        if (!*(volatile uint32_t*)ADDR_Fn1) nulls |= 2;
        if (!*(volatile uint32_t*)ADDR_Fn2) nulls |= 4;
        if (!*(volatile uint32_t*)ADDR_Fn3) nulls |= 8;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    ++g_samples;
    if (suppress) ++g_suppressed;
    if (nulls) { ++g_nullPtrFrames; g_nullMask |= nulls; }

    int s = suppress ? 1 : 0;
    if (g_prevSuppress >= 0 && s != g_prevSuppress) ++g_flips;
    g_prevSuppress = s;

    DWORD now = GetTickCount();
    if (g_lastMoveAt == 0) g_lastMoveAt = now;

    if (g_prevTick != 0xFFFFFFFF && tick != g_prevTick) {
        ++g_passAdvanced;
        if (g_passStalled) {
            Log("[ShadowProbe] the shadow pass STARTED advancing again after %lu ms "
                "stopped", (unsigned long)(now - g_lastMoveAt));
            g_passStalled = false;
        }
        g_stillSamples = 0;
        g_lastMoveAt = now;
    } else if (g_prevTick != 0xFFFFFFFF && !g_passStalled) {
        if (++g_stillSamples >= kStallSamples) {
            g_passStalled = true;
            Log("[ShadowProbe] the shadow pass STOPPED advancing - the byte at "
                "0x%08X has not moved for %lu ms, while the suppress flag reads %u "
                "and quality reads %d. Whatever is in the log just above this line "
                "is what it stopped after.",
                (unsigned)ADDR_PassTick, (unsigned long)(now - g_lastMoveAt),
                suppress, g_prevQuality);
        }
    }
    g_prevTick = tick;

    // A quality change is the moment worth naming, since it is the trigger.
    if (g_prevQuality >= 0 && (int)quality != g_prevQuality) {
        Log("[ShadowProbe] extShadowQuality changed %d -> %u (suppress flag is %u "
            "right now)", g_prevQuality, quality, suppress);
    }
    g_prevQuality = (int)quality;

    if (now - g_lastReport < REPORT_MS) return;
    g_lastReport = now;
    ++g_windows;

    if (g_samples == 0) return;

    DWORD windowMs = now - g_windowStart;
    g_windowStart = now;

    Log("[ShadowProbe] #%u  quality=%d  %u samples over %lu ms (%.0f/s): flag said "
        "suppressed on %u (%.1f%%), flipped %u time(s), the shadow pass advanced "
        "on %u",
        g_windows, g_prevQuality, g_samples, (unsigned long)windowMs,
        windowMs ? 1000.0 * (double)g_samples / (double)windowMs : 0.0,
        g_suppressed, 100.0 * (double)g_suppressed / (double)g_samples,
        g_flips, g_passAdvanced);

    if (g_nullPtrFrames) {
        Log("[ShadowProbe]   one of the four shadow function pointers was null on "
            "%u samples (mask %u) - the pass returns before clearing the flag when "
            "that happens, which would wedge shadows off",
            g_nullPtrFrames, g_nullMask);
    }

    // Say what the numbers mean, so a tester's log answers the question without
    // anyone having to hold this file open beside it.
    if (g_flips > 2) {
        Log("[ShadowProbe]   the flag is oscillating - that is the flicker, and it "
            "is the client turning its own shadows off and on");
    } else if (g_suppressed == g_samples) {
        Log("[ShadowProbe]   the flag said suppressed on every sample in this window");
    } else if (g_passAdvanced == 0 && g_prevQuality > 0) {
        Log("[ShadowProbe]   the shadow pass did not run at all in this window, "
            "while the flag said shadows were on and quality stayed at %d. Those "
            "two disagree, and the pass is the one that decides what you see - "
            "this is the state to catch, not a suppressed one",
            g_prevQuality);
    }

    g_samples = g_suppressed = g_flips = g_passAdvanced = g_nullPtrFrames = 0;
    g_nullMask = 0;
}

void Shutdown() {
    g_active = false;
}

} // namespace ShadowStateProbe
