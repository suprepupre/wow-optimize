// ============================================================================
// Module: timer_calibration.cpp
//
// The client's startup clock check, sub_86AB30, busy-waits 250 ms before the
// main window can appear. It compares QueryPerformanceCounter against
// GetTickCount across the wait, both read on tick edges, and falls back to the
// tick count for all of the client's timing if they differ by 5 ms or more.
// The wait is `cmp edx, 0FAh` at 0x0086AC9B.
//
// The patch itself is not made here. It runs in the first moments of the
// process and this DLL is loaded three seconds later, so version_proxy.cpp
// writes the immediate from its DllMain when General/FastTimerCalibration is
// on. This module reads back what happened and says which clock the client
// ended up on, which is the one thing a shorter wait could change for the worse.
//
// The check's result is not always used. sub_86AEA0 takes the timingMethod
// setting as an argument and, when it is not 0, replaces the result with it
// (the result only sets the problem code at +12, and only when the setting asks
// for the counter and the check says tick count). A Config.wtf with
// `SET timingMethod "1"`, as the author's has, spends the 250 ms on a
// comparison whose answer is thrown away.
//
// Three states are kept apart in the log: the switch is off, the switch is on
// and the immediate is the shortened one, and the switch is on and it is not
// (no proxy, NoClientPatches, or bytes that were not the expected ones, the
// proxy log says which).
//
// Measured: in a rig that reaches the login screen, the main window appeared
// 0.72-0.77 s after launch with the original wait and 0.48-0.50 s with the
// wait cut to one tick, four alternating runs. Not measured: a session in a
// game with the shortened wait on a machine whose clocks disagree.
// ============================================================================
#include "timer_calibration.h"
#include <windows.h>
#include <cstdint>
#include "config.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);
extern "C" void WowOpt_RecordHookOwner(uintptr_t target, const void* detour);

namespace TimerCalibration {
namespace {

constexpr uintptr_t kWaitImmediate = 0x0086AC9D;   // imm32 of the `cmp edx, 0FAh`
constexpr uintptr_t kTimeManagerPtr = 0x00D4159C;  // pointer to the TimeManager object
constexpr unsigned char kOriginal = 0xFA;

int g_state = 0;        // 0 off and untouched, 1 shortened, 2 switch on but not shortened, 3 unreadable
unsigned g_wait = 0;    // the immediate as read
int g_clock = -1;       // 2 performance counter, 1 tick count, -1 not read
int g_reason = -1;      // 0 none; 3 or 4 the clock check failed; 5 forced to tick count

void ReadState() {
    bool read = false;
    unsigned char b = 0;
    __try {
        b = *(volatile unsigned char*)kWaitImmediate;
        read = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (!read) g_state = 3;
    else if (b != kOriginal) g_state = 1;
    else g_state = Config::g_settings.OptFastTimerCalibration ? 2 : 0;
    g_wait = b;

    // Kept from the first successful read: the client frees the object when it quits, and the last
    // report is made after that.
    __try {
        const uintptr_t tm = *(volatile uintptr_t*)kTimeManagerPtr;
        if (tm) {
            g_clock = *(volatile int*)(tm + 8);
            g_reason = *(volatile int*)(tm + 12);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

}  // namespace

void Init() {
    ReadState();
    // The network start's poll interval, patched by the proxy under General/FastNetworkInit.
    {
        const uintptr_t kNetPollImm = 0x00469401;
        unsigned char b = 0;
        bool read = false;
        __try { b = *(volatile unsigned char*)kNetPollImm; read = true; } __except (EXCEPTION_EXECUTE_HANDLER) {}
        if (read && b == 1) WowOpt_RecordHookOwner(kNetPollImm, (const void*)&Init);
        if (Config::g_settings.OptFastNetworkInit) {
            if (read && b == 1)
                Log("[NetworkInit] The network start waits for its thread by polling every 1 ms instead of 100. "
                    "The version proxy wrote it before the client started.");
            else
                Log("[NetworkInit] Switched on, but the poll interval at 0x%08X is %s: the version proxy did not "
                    "write it (see its log: no proxy, No Client Patches, or different bytes).",
                    (unsigned)kNetPollImm, read ? "still the client's" : "unreadable");
        }
    }
    if (g_state == 1) WowOpt_RecordHookOwner(kWaitImmediate, (const void*)&Init);
    if (Config::g_settings.OptFastTimerCalibration) {
        switch (g_state) {
        case 1:
            Log("[TimerCalibration] The client's startup clock check waits %u ms instead of 250. The version "
                "proxy wrote it before the client started.",
                g_wait);
            break;
        case 2:
            Log("[TimerCalibration] Switched on, but the client's clock check still waits 250 ms: the version "
                "proxy did not write it. The proxy log says why (no proxy in the game folder, No Client "
                "Patches, or different bytes at 0x0086AC9B).");
            break;
        default:
            Log("[TimerCalibration] Switched on; the wait could not be read.");
            break;
        }
    }
}

void LogStats() {
    ReadState();
    const char* clock = g_clock == 2 ? "the performance counter" : g_clock == 1 ? "the tick count" : "unknown (not read)";
    Log("[TimerCalibration] The client times itself with %s%s. Problem code %d (0 = none found; 1 or 2 = no "
        "performance counter; 3 or 4 = its comparison with the tick count failed; 5 = the timingMethod setting "
        "asked for the counter and the check had failed).",
        clock, g_clock == 1 ? ", so every timing it does has tick resolution" : "", g_reason);
}

}  // namespace TimerCalibration
