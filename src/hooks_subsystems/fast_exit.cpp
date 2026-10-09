// ============================================================================
// Module: fast_exit.cpp
//
// Quitting the game from the character screen waits for a web request.
//
// kromvel85's session of 2026-10-08 (WoW Circle, build 9fc59ceb, No Client
// Patches on): the socket closed at 14:35:01.8, the final report and the
// process's end came at 14:35:08.97, and the Sleep census put 5296 calls of one
// millisecond, 5.3 s, on a single call site, 0x004DBC64. prince's 1.5 minute
// session of the same build has 2531 calls and 3.4 s at the same address. That
// address is the Sleep(1) in sub_4DBBC0, a loop in the client's shutdown
// (sub_402910) that runs until two globals clear:
//
//   dword_B6AF88   set when the glue screens start a download of the notice text
//                  (sub_4DA5F0 -> sub_870040 -> sub_86FE40) and cleared by that
//                  download's data callback, sub_4D7890, on its last chunk;
//   dword_B6AFB0   the same for the agreement text (sub_4DA360 -> sub_4DA040).
//
// sub_86FE40 opens a WinINet session called "Blizzard Web Client", connects, and
// sets the connect and receive timeouts to 5000 ms. On a private server the
// address the client was given may not answer, and a shutdown that arrives while
// the request is still waiting for its timeout waits with it; the shutdown does
// nothing else for those seconds. Which way of quitting leaves a request pending
// is a guess (soon after the character screen has loaded): the same player's
// exit in a session of 2026-10-07, build 783ab7af, took 0.3 s from socket close to
// the end of the process, so the wait is not on every exit.
//
// What this does. It remembers the session handle of every InternetOpenA call
// whose agent is "Blizzard Web Client", and hooks sub_4DBBC0. If either global is
// set when the shutdown arrives there, it closes those session handles.
// WinINet then closes each request and connection under them and reports
// INTERNET_STATUS_HANDLE_CLOSING to the client's own status callback
// (sub_86FC80, the 'F' case), which is the path a finished download takes: it
// calls the data callback with the final flag, and the callback clears the global.
// The client's own loop then finds both zero on its next pass. Nothing is
// skipped and nothing is forced: if the globals do not clear within three
// seconds of the close, the client's loop is left to wait as it always did.
//
// What it does not do: change what a download that is not pending does, or touch
// a session the client never opened. A session handle the client has already
// finished with is closed again harmlessly, since the client keeps those open.
//
// Off by default (General/FastExit). Not run in a game. The measurement it is
// built on is two exits in two logs.
// ============================================================================

#include "fast_exit.h"
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include "config.h"
#include "MinHook.h"
#include "version.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);

namespace FastExit {
namespace {

constexpr uintptr_t kTarget      = 0x004DBBC0;      // the shutdown's wait loop
constexpr uintptr_t kNoticeFlag  = 0x00B6AF88;      // notice download in flight
constexpr uintptr_t kAgreeFlag   = 0x00B6AFB0;      // agreement download pending
static const uint8_t kPrologue[9] = { 0x56, 0x33, 0xF6, 0x39, 0x35, 0x88, 0xAF, 0xB6, 0x00 };

constexpr int kMaxSessions = 8;
constexpr DWORD kWaitAfterCloseMs = 3000;

typedef int  (__cdecl *Shutdown_fn)();
typedef void* (WINAPI *InternetOpenA_fn)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef BOOL (WINAPI *InternetCloseHandle_fn)(void*);

Shutdown_fn            g_origShutdown = nullptr;
InternetOpenA_fn       g_origOpen = nullptr;
InternetCloseHandle_fn g_close = nullptr;
bool g_installed = false;

void* volatile g_sessions[kMaxSessions];
volatile LONG g_sessionNext = 0;

unsigned long g_opened = 0;
unsigned long g_exitsSeen = 0;          // the shutdown reached the loop with a download pending
unsigned long g_handlesClosed = 0;
unsigned long g_cleared = 0;            // both globals were zero within the wait after the close
unsigned long g_notCleared = 0;
double        g_lastWaitMs = 0.0;
double        g_worstWaitMs = 0.0;

inline bool Pending() {
    return *(volatile const int*)kNoticeFlag != 0 || *(volatile const int*)kAgreeFlag != 0;
}

void* WINAPI Hooked_InternetOpenA(LPCSTR agent, DWORD type, LPCSTR proxy, LPCSTR bypass, DWORD flags) {
    void* h = g_origOpen(agent, type, proxy, bypass, flags);
    if (h && agent && lstrcmpA(agent, "Blizzard Web Client") == 0) {
        const LONG at = (InterlockedIncrement(&g_sessionNext) - 1) % kMaxSessions;
        g_sessions[at] = h;
        ++g_opened;
    }
    return h;
}

int __cdecl Hooked_Shutdown() {
    if (Pending()) {
        ++g_exitsSeen;
        LARGE_INTEGER f, t0, t1;
        QueryPerformanceFrequency(&f);
        QueryPerformanceCounter(&t0);
        const int noticeBefore = *(volatile const int*)kNoticeFlag;
        const int agreeBefore  = *(volatile const int*)kAgreeFlag;

        unsigned closed = 0;
        for (int i = 0; i < kMaxSessions; ++i) {
            void* h = g_sessions[i];
            if (!h) continue;
            g_sessions[i] = nullptr;
            g_close(h);
            ++closed;
        }
        g_handlesClosed += closed;

        // The client's loop would do this waiting itself. Doing it here only so
        // that the time it took is a number in the log.
        DWORD waited = 0;
        while (Pending() && waited < kWaitAfterCloseMs) {
            Sleep(1);
            ++waited;
        }
        QueryPerformanceCounter(&t1);
        const double ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)f.QuadPart;
        g_lastWaitMs = ms;
        if (ms > g_worstWaitMs) g_worstWaitMs = ms;
        if (Pending()) {
            ++g_notCleared;
            Log("[FastExit] the shutdown reached its wait with a web request pending (notice %d, agreement %d), %u session "
                "handle(s) closed, and the request was still pending %.0f ms later. The client's own wait takes over.",
                noticeBefore, agreeBefore, closed, ms);
        } else {
            ++g_cleared;
            Log("[FastExit] the shutdown reached its wait with a web request pending (notice %d, agreement %d); %u session "
                "handle(s) closed, and the request had cleared %.0f ms later. The client's wait was 5000 ms at its longest "
                "and 5300 ms in the log that showed it.", noticeBefore, agreeBefore, closed, ms);
        }
    }
    return g_origShutdown();
}

} // namespace

void Init() {
    if (!Config::g_settings.OptFastExit) return;
    if (RunningUnderTranslation()) {
        Log("[FastExit] NOT active: not installed under Wine or Rosetta.");
        return;
    }
    void* const target = (void*)kTarget;
    if (!WowOpt_ClientPatchAllowed(target)) {
        Log("[FastExit] NOT active: client patches disallowed at 0x%08X", (unsigned)kTarget);
        return;
    }
    if (std::memcmp(target, kPrologue, sizeof(kPrologue)) != 0) {
        char found[64] = {};
        WowOpt_HexBytes(kTarget, found, sizeof(found));
        Log("[FastExit] NOT active: the bytes at 0x%08X are not the shutdown's wait loop (%s).", (unsigned)kTarget, found);
        return;
    }
    HMODULE wininet = LoadLibraryA("wininet.dll");
    void* open = wininet ? (void*)GetProcAddress(wininet, "InternetOpenA") : nullptr;
    g_close = wininet ? (InternetCloseHandle_fn)GetProcAddress(wininet, "InternetCloseHandle") : nullptr;
    if (!open || !g_close) {
        Log("[FastExit] NOT active: wininet.dll does not export what is needed.");
        return;
    }
    if (MH_CreateHook(open, (void*)&Hooked_InternetOpenA, (void**)&g_origOpen) != MH_OK ||
        WO_EnableHook(open) != MH_OK) {
        Log("[FastExit] NOT active: InternetOpenA could not be hooked.");
        return;
    }
    if (WineSafe_CreateHook(target, (void*)&Hooked_Shutdown, (void**)&g_origShutdown) != MH_OK ||
        WO_EnableHook(target) != MH_OK) {
        Log("[FastExit] NOT active: the hook on 0x%08X could not be created or enabled.", (unsigned)kTarget);
        return;
    }
    g_installed = true;
    SamplingProfiler::RegisterSelfSymbol("FastExit", (const void*)&Hooked_Shutdown);
    Log("[FastExit] ACTIVE: when the shutdown reaches its wait loop (sub_4DBBC0) with a web request pending, the "
        "request's WinINet session is closed so the client's own completion path runs now rather than at the 5000 ms "
        "timeout. Not yet run in a game.");
}

void Shutdown() {
}

void LogStats() {
    if (!Config::g_settings.OptFastExit) return;
    if (!g_installed) { Log("[FastExit] not installed, so nothing here was measured."); return; }
    Log("[FastExit] %lu \"Blizzard Web Client\" session(s) seen opening; the shutdown reached its wait with a request pending "
        "%lu time(s): %lu session handle(s) closed, %lu cleared within %lu ms, %lu did not. Last wait %.0f ms, worst %.0f ms. "
        "Plain counters. This line is printed from the report at the end of the session, which runs after the shutdown.",
        g_opened, g_exitsSeen, g_handlesClosed, g_cleared, (unsigned long)kWaitAfterCloseMs, g_notCleared,
        g_lastWaitMs, g_worstWaitMs);
}

} // namespace FastExit
