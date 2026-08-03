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
static uint32_t g_frames        = 0;
static uint32_t g_suppressed    = 0;   // frames with the flag set
static uint32_t g_flips         = 0;   // transitions either way
static uint32_t g_passAdvanced  = 0;   // frames where the pass counter moved
static uint32_t g_nullPtrFrames = 0;   // frames with any of the four null
static int      g_prevSuppress  = -1;
static uint32_t g_prevTick      = 0xFFFFFFFF;
static int      g_prevQuality   = -1;
static uint32_t g_nullMask      = 0;   // which pointers were seen null

// Whole session.
static uint32_t g_windows = 0;

bool Init() {
    if (!Config::g_settings.OptShadowStateProbe) return true;
    g_active = true;
    g_lastReport = GetTickCount();
    Log("[ShadowProbe] Watching the client's shadow state (suppress flag 0x%08X, "
        "quality 0x%08X). Read-only; reports every %lu seconds.",
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

    ++g_frames;
    if (suppress) ++g_suppressed;
    if (nulls) { ++g_nullPtrFrames; g_nullMask |= nulls; }

    int s = suppress ? 1 : 0;
    if (g_prevSuppress >= 0 && s != g_prevSuppress) ++g_flips;
    g_prevSuppress = s;

    if (g_prevTick != 0xFFFFFFFF && tick != g_prevTick) ++g_passAdvanced;
    g_prevTick = tick;

    // A quality change is the moment worth naming, since it is the trigger.
    if (g_prevQuality >= 0 && (int)quality != g_prevQuality) {
        Log("[ShadowProbe] extShadowQuality changed %d -> %u (suppress flag is %u "
            "right now)", g_prevQuality, quality, suppress);
    }
    g_prevQuality = (int)quality;

    DWORD now = GetTickCount();
    if (now - g_lastReport < REPORT_MS) return;
    g_lastReport = now;
    ++g_windows;

    if (g_frames == 0) return;

    Log("[ShadowProbe] #%u  quality=%d  %u frames: suppressed %u (%.1f%%), "
        "flag flipped %u time(s), shadow pass ran on %u",
        g_windows, g_prevQuality, g_frames, g_suppressed,
        100.0 * (double)g_suppressed / (double)g_frames,
        g_flips, g_passAdvanced);

    if (g_nullPtrFrames) {
        Log("[ShadowProbe]   one of the four shadow function pointers was null on "
            "%u frames (mask %u) - the pass returns before clearing the flag when "
            "that happens, which would wedge shadows off",
            g_nullPtrFrames, g_nullMask);
    }

    // Say what the numbers mean, so a tester's log answers the question without
    // anyone having to hold this file open beside it.
    if (g_flips > 2) {
        Log("[ShadowProbe]   the flag is oscillating - that is the flicker, and it "
            "is the client turning its own shadows off and on");
    } else if (g_suppressed == g_frames) {
        Log("[ShadowProbe]   shadows are suppressed for every frame in this window");
    } else if (g_passAdvanced == 0 && g_prevQuality > 0) {
        Log("[ShadowProbe]   the shadow pass did not run at all in this window");
    }

    g_frames = g_suppressed = g_flips = g_passAdvanced = g_nullPtrFrames = 0;
    g_nullMask = 0;
}

void Shutdown() {
    g_active = false;
}

} // namespace ShadowStateProbe
