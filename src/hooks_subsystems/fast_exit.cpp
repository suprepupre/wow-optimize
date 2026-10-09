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
//
// The same session opens on the main thread, too. prince's sessions of 2026-10-08
// (build 9fc59ceb) each have one frame of 364 to 375 ms, and one of 2849 ms, whose
// samples are 95% inside WININET waiting on an event (WaitForSingleObjectEx under
// WININET.dll, reached through IsHostInProxyBypassList), in all three of his logs and
// in none of the logs from machines without a proxy setting. sub_86FE40 opens the
// session with InternetOpenA(agent, 0, ...), access type 0, which is
// INTERNET_OPEN_TYPE_PRECONFIG: WinINet reads the system's proxy settings and, where
// they say so, looks for an automatic configuration script before it connects. That
// lookup is what the main thread waits for. General/NoWebProxy opens the notice
// and agreement downloads with INTERNET_OPEN_TYPE_DIRECT instead, so there is no
// proxy lookup to wait for. A player who can reach the notice host only through a
// proxy loses the notice text and nothing else: the download then fails the way it
// does when the host does not answer, and the glue screen's flag clears as it does
// then. Which call of the session the wait is in (open, connect or send) is not
// known from the stack; the log reports the time spent in the open call, and the
// answer is whether the long frame is gone.
//
// The sound system's own shutdown wait is the other part, and needs no patch of
// wow.exe. sub_87DED0 stops every sound and then polls: it flags each unfinished
// sound, pumps, looks whether any is still unfinished (state 3 is finished, in the
// list at dword_B1D6AC, under the lock at 0xD4387C), and then sleeps 100 ms
// BEFORE it tests that answer, so a sound system with nothing left to wait for
// still costs one full Sleep(100) and a loop that has to look twice costs two.
// The Sleep census of Drain's twelve sessions of 2026-10-09 has this call site,
// 0x0087DF79, at 2 calls in seven sessions and 3 to 7 in the others, and
// kromvel85's WoW Circle session at 21, which is the loop's own limit of twenty
// passes. That is 0.2 s of every exit, up to 2 s, spent in a sleep that
// changes nothing. sub_87DED0 is reached from the shutdown (sub_402910), from
// the sound restart in sub_4C74F0 and from sub_985D30.
//
// The Sleep hook calls SoundStopSleep for that call site. If the list is
// already all finished, the sleep is skipped, since the loop returns right after
// it. If a sound is still finishing, the sleep is taken in 5 ms slices and ends
// as soon as the list is all finished, or after the full 100 ms as before. The list
// is read under the client's own lock and a fault while reading leaves the sleep
// to the client. The loop's counter and its give-up at twenty passes are
// untouched; a pass just ends sooner when nothing is left to wait for.
//
// Same switch, off by default, not run in a game.
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
bool g_installed = false;               // any part of this module is in place
bool g_webInstalled = false;            // the WinINet hook, and the shutdown hook when it was wanted

void* volatile g_sessions[kMaxSessions];
volatile LONG g_sessionNext = 0;

unsigned long g_opened = 0;
unsigned long g_madeDirect = 0;         // sessions opened direct instead of through the system's proxy settings
unsigned long g_openLogged = 0;
double        g_worstOpenMs = 0.0;
unsigned long g_exitsSeen = 0;          // the shutdown reached the loop with a download pending
unsigned long g_handlesClosed = 0;
unsigned long g_cleared = 0;            // both globals were zero within the wait after the close
unsigned long g_notCleared = 0;
double        g_lastWaitMs = 0.0;
double        g_worstWaitMs = 0.0;

constexpr uintptr_t kSoundStopAsker = 0x0087DF79;   // return address after sub_87DED0's Sleep(100) wrapper call
constexpr uintptr_t kSoundListHead  = 0x00B1D6AC;
constexpr uintptr_t kSoundListLock  = 0x00D4387C;   // CRITICAL_SECTION
constexpr unsigned  kSoundNextOff   = 0x0C;
constexpr unsigned  kSoundStateOff  = 0x3C;
bool g_soundOk = false;
unsigned long g_soundWaits = 0;         // sleeps at that call site the hook was asked about
unsigned long g_soundSkipped = 0;       // skipped because every sound had already finished
unsigned long g_soundShortened = 0;     // ended early once the last sound finished
unsigned long g_soundFull = 0;          // took the whole 100 ms: a sound was still unfinished
unsigned long g_soundUnreadable = 0;    // the list could not be read, so the client slept as asked
double        g_soundSavedMs = 0.0;

// 1: a sound is not finished, 0: all are, -1: the list could not be read.
int SoundsUnfinished() {
    CRITICAL_SECTION* cs = (CRITICAL_SECTION*)kSoundListLock;
    int result = -1;
    EnterCriticalSection(cs);
    __try {
        uintptr_t node = *(volatile const uintptr_t*)kSoundListHead;
        if ((node & 1) || !node) node = 0;
        result = 0;
        for (unsigned guard = 0; node && !(node & 1) && guard < 100000; ++guard) {
            if (*(volatile const int*)(node + kSoundStateOff) != 3) { result = 1; break; }
            node = *(volatile const uintptr_t*)(node + kSoundNextOff);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = -1;
    }
    LeaveCriticalSection(cs);
    return result;
}

inline bool Pending() {
    return *(volatile const int*)kNoticeFlag != 0 || *(volatile const int*)kAgreeFlag != 0;
}

void* WINAPI Hooked_InternetOpenA(LPCSTR agent, DWORD type, LPCSTR proxy, LPCSTR bypass, DWORD flags) {
    const bool ours = agent && lstrcmpA(agent, "Blizzard Web Client") == 0;
    const DWORD askedType = type;
    if (ours && Config::g_settings.OptNoWebProxy && type == 0 /* INTERNET_OPEN_TYPE_PRECONFIG */) {
        type = 1;                                 // INTERNET_OPEN_TYPE_DIRECT
        proxy = nullptr;
        bypass = nullptr;
        ++g_madeDirect;
    }
    LARGE_INTEGER f, t0, t1;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    void* h = g_origOpen(agent, type, proxy, bypass, flags);
    QueryPerformanceCounter(&t1);
    if (ours) {
        const double ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)f.QuadPart;
        if (ms > g_worstOpenMs) g_worstOpenMs = ms;
        if (g_openLogged < 4) {
            ++g_openLogged;
            Log("[FastExit] InternetOpenA for the \"Blizzard Web Client\" session: access type %lu%s, %.1f ms in the call.",
                (unsigned long)askedType, type != askedType ? " changed to 1 (direct, no proxy lookup)" : "", ms);
        }
    }
    if (h && ours) {
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

bool SoundStopSleep(unsigned long ms) {
    if (!g_soundOk || ms != 100) return false;
    ++g_soundWaits;
    const int first = SoundsUnfinished();
    if (first < 0) { ++g_soundUnreadable; return false; }
    if (first == 0) {
        ++g_soundSkipped;
        g_soundSavedMs += 100.0;
        return true;
    }
    for (int slice = 0; slice < 20; ++slice) {
        SleepEx(5, FALSE);
        if (SoundsUnfinished() == 0) {
            ++g_soundShortened;
            g_soundSavedMs += 100.0 - 5.0 * (slice + 1);
            return true;
        }
    }
    ++g_soundFull;
    return true;
}

void Init() {
    if (!Config::g_settings.OptFastExit && !Config::g_settings.OptNoWebProxy) return;
    if (RunningUnderTranslation()) {
        Log("[FastExit] NOT active: not installed under Wine or Rosetta.");
        return;
    }
    // The sound wait reads and sleeps and writes nothing into wow.exe, so No Client Patches does not stop it.
    if (Config::g_settings.OptFastExit) {
        // push 64h / call wrapper at 0x87DF72, with the add esp,4 that follows the call at 0x87DF79.
        static const uint8_t kSoundSite[] = { 0x6A, 0x64, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x04 };
        const uint8_t* site = (const uint8_t*)(kSoundStopAsker - 7);
        if (std::memcmp(site, kSoundSite, 3) == 0 && std::memcmp(site + 7, kSoundSite + 7, 3) == 0) {
            g_soundOk = true;
            g_installed = true;
            Log("[FastExit] sound shutdown wait ACTIVE: the Sleep(100) in sub_87DED0 is skipped when every sound has already "
                "finished and ends early when the last one does. Not yet run in a game.");
        } else {
            char found[64] = {};
            WowOpt_HexBytes(kSoundStopAsker - 7, found, sizeof(found));
            Log("[FastExit] sound shutdown wait NOT active: the bytes at 0x%08X are not the Sleep(100) call of sub_87DED0 (%s).",
                (unsigned)(kSoundStopAsker - 7), found);
        }
    }
    // The shutdown hook patches the client; the proxy change is a hook on a WinINet export and needs
    // no patch of wow.exe, so it runs under No Client Patches and the exit wait does not.
    void* const target = (void*)kTarget;
    const bool wantExit = Config::g_settings.OptFastExit;
    bool exitOk = wantExit;
    if (wantExit && !WowOpt_ClientPatchAllowed(target)) {
        Log("[FastExit] exit wait NOT active: client patches disallowed at 0x%08X", (unsigned)kTarget);
        exitOk = false;
    }
    if (exitOk && std::memcmp(target, kPrologue, sizeof(kPrologue)) != 0) {
        char found[64] = {};
        WowOpt_HexBytes(kTarget, found, sizeof(found));
        Log("[FastExit] exit wait NOT active: the bytes at 0x%08X are not the shutdown's wait loop (%s).", (unsigned)kTarget, found);
        exitOk = false;
    }
    if (!exitOk && !Config::g_settings.OptNoWebProxy) return;
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
    if (exitOk) {
        if (WineSafe_CreateHook(target, (void*)&Hooked_Shutdown, (void**)&g_origShutdown) != MH_OK ||
            WO_EnableHook(target) != MH_OK) {
            Log("[FastExit] exit wait NOT active: the hook on 0x%08X could not be created or enabled.", (unsigned)kTarget);
        } else {
            SamplingProfiler::RegisterSelfSymbol("FastExit", (const void*)&Hooked_Shutdown);
            Log("[FastExit] exit wait ACTIVE: when the shutdown reaches its wait loop (sub_4DBBC0) with a web request "
                "pending, the request's WinINet session is closed so the client's own completion path runs now rather "
                "than at the 5000 ms timeout. Not yet run in a game.");
        }
    }
    g_installed = true;
    g_webInstalled = true;
    if (Config::g_settings.OptNoWebProxy)
        Log("[FastExit] proxy lookup OFF for the notice and agreement downloads: InternetOpenA with access type 0 (system "
            "proxy settings) is opened as type 1 (direct). Not yet run in a game.");
}

void Shutdown() {
}

void LogStats() {
    if (!Config::g_settings.OptFastExit && !Config::g_settings.OptNoWebProxy) return;
    if (!g_installed) { Log("[FastExit] not installed, so nothing here was measured."); return; }
    if (g_soundOk)
        Log("[FastExit] sound shutdown wait: %lu sleep(s) of 100 ms seen at 0x%08X; %lu skipped because every sound had finished, "
            "%lu ended early, %lu ran the full 100 ms with a sound still unfinished, %lu left to the client because the list "
            "could not be read. About %.0f ms not slept. Plain counters. Printed from the report at the end of the session, "
            "which runs after the shutdown.", g_soundWaits, (unsigned)kSoundStopAsker, g_soundSkipped, g_soundShortened,
            g_soundFull, g_soundUnreadable, g_soundSavedMs);
    if (!g_webInstalled) return;
    if (Config::g_settings.OptNoWebProxy)
        Log("[FastExit] proxy lookup: %lu of %lu \"Blizzard Web Client\" session(s) opened direct; the slowest open call took "
            "%.1f ms. Plain counters.", g_madeDirect, g_opened, g_worstOpenMs);
    Log("[FastExit] %lu \"Blizzard Web Client\" session(s) seen opening; the shutdown reached its wait with a request pending "
        "%lu time(s): %lu session handle(s) closed, %lu cleared within %lu ms, %lu did not. Last wait %.0f ms, worst %.0f ms. "
        "Plain counters. This line is printed from the report at the end of the session, which runs after the shutdown.",
        g_opened, g_exitsSeen, g_handlesClosed, g_cleared, (unsigned long)kWaitAfterCloseMs, g_notCleared,
        g_lastWaitMs, g_worstWaitMs);
}

} // namespace FastExit
