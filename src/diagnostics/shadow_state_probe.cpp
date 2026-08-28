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

// Whole session, so a window that never fires still has something behind it.
uint32_t g_totalEntries = 0;
uint32_t g_totalRan     = 0;

}  // namespace

// At file scope: the naked thunk reaches it from inline assembly.
static void* g_origPass = nullptr;

extern "C" void __cdecl ShadowProbe_NoteEntry() {
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

    if (g_prevQuality >= 0 && (int)quality != g_prevQuality) {
        Log("[ShadowProbe] extShadowQuality changed %d -> %d", g_prevQuality, (int)quality);
    }
    g_prevQuality = (int)quality;
}

// sub_875F80 is __cdecl with two stack arguments and a plain retn. Everything is
// preserved and the client's own code runs unchanged.
__declspec(naked) static void HookedShadowPass() {
    __asm {
        pushad
        pushfd
        call ShadowProbe_NoteEntry
        popfd
        popad
        jmp  dword ptr [g_origPass]
    }
}

namespace ShadowStateProbe {

bool Init() {
    if (!Config::g_settings.OptShadowStateProbe) return true;

    if (IsBadReadPtr((void*)ADDR_Pass, 16)) {
        Log("[ShadowProbe] 0x%08X unreadable - not installing", (unsigned)ADDR_Pass);
        return false;
    }
    if (WineSafe_CreateHook((void*)ADDR_Pass, (void*)HookedShadowPass, &g_origPass) != MH_OK) {
        Log("[ShadowProbe] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)ADDR_Pass) != MH_OK) {
        Log("[ShadowProbe] hook created but could not be enabled");
        return false;
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

    g_entries = g_ran = g_blockedNull = g_blockedQual = g_reinit = 0;
    g_nullMask = 0;
}

void Shutdown() {
    if (g_installed) MH_DisableHook((void*)ADDR_Pass);
}

} // namespace ShadowStateProbe
