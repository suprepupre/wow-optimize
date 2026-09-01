// ============================================================================
// Module: net_diag.cpp
//
// Disconnects are the longest-standing complaint against this project and the
// only one never explained. Reports arrive as "dropped after ten minutes", the
// log around that moment shows nothing unusual, and that is the whole problem:
// nothing records the receive path, so there is no way to tell a server-side
// drop from a client-side one, let alone from something this DLL did.
//
// This is an observer, not an optimisation. It hooks recv, WSARecv and
// closesocket, records four numbers on the hot path, and changes nothing about
// what any of them do or return. Everything it prints happens at the moment a
// connection ends, which is once a session at most.
//
// What it captures at that moment is the part that has been missing:
//
//   - how the connection ended. A graceful zero from the server is a different
//     event from WSAECONNRESET, which is different again from WSAETIMEDOUT, and
//     the player cannot tell them apart while we cannot either.
//   - how long since the last byte actually arrived. A drop after two minutes of
//     silence is the server or the route; a drop while data was still flowing a
//     moment earlier is not.
//   - what this DLL was doing. If the main thread had stalled, or a loading
//     transition was in progress, that is worth knowing before blaming anything.
//
// None of this fixes a disconnect. It is meant to make the next report say which
// of several unrelated things is happening, because at present they all look the
// same from outside.
// ============================================================================

#include <windows.h>
#include <winsock2.h>
#include <cstdint>

#include "net_diag.h"
#include "crash_dumper.h"
#include "config.h"
#include "session_verdict.h"
#include "flight_recorder.h"
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);
extern "C" DWORD WowOpt_LastMainThreadTick();

namespace LuaOpt { bool IsLoadingMode(); bool IsReloading(); bool IsSwapping(); }

namespace NetDiag {

typedef int (WINAPI* recv_fn)(SOCKET, char*, int, int);
typedef int (WINAPI* WSARecv_fn)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD,
                                 LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WINAPI* closesocket_fn)(SOCKET);
typedef int (WINAPI* send_fn)(SOCKET, const char*, int, int);

static recv_fn        orig_recv        = nullptr;
static WSARecv_fn     orig_WSARecv     = nullptr;
static closesocket_fn orig_closesocket = nullptr;
static send_fn        orig_send        = nullptr;

static bool g_active = false;

// A flight-recorder column. The question a drop always raises is whether
// traffic thinned out before it or stopped dead, and a per-window byte
// count cannot answer that.
static int g_frSlotRecv = -1;

// Hot path state. Four writes per receive, no locks - these are counters read
// only when something has already gone wrong.
static volatile DWORD  g_lastRecvTick  = 0;
static volatile LONG   g_recvCalls     = 0;
static volatile LONG   g_sendCalls     = 0;
static          uint64_t g_recvBytes   = 0;
static          uint64_t g_sendBytes   = 0;
static volatile DWORD  g_lastSendTick  = 0;
static volatile DWORD  g_firstRecvTick = 0;

// One report per connection. A disconnect cascades - recv fails, then send
// fails, then the socket closes - and three copies of the same story is noise.
//
// Per connection, not per session, which is what it used to be. A raid log with
// three separate drops in it carried one report, for the first, and both of the
// drops the player actually wrote the report about produced nothing at all. The
// latch is cleared in WatchSocket when traffic moves to a new socket, so it is
// always cleared after the old connection has had its say and before the new one
// can need it.
static volatile LONG g_reported = 0;

// How many connections have carried traffic this session. Printed in the
// periodic line too, because the receive counters restart with each one and a
// count that suddenly falls otherwise reads as a broken counter.
static volatile LONG g_connSeq = 0;

// Which socket the counters above are describing.
//
// Logging in uses two connections: the client talks to the logon server, gets
// its realm list, and closes that socket to go and talk to the world server.
// That close is a normal step in starting the game, and because the counters
// were global and closesocket reported the first close it saw with any receives
// behind it, every session on every machine opened with a "!!! DISCONNECT !!!"
// banner a few seconds after launch. One tester's log showed the report at
// 19:44:31 followed by 593,038 receives over the next twenty-four minutes.
//
// Worse than the noise: the report fires once per session, so the login socket
// consumed it and an actual mid-raid drop later in the same session had nothing
// left to say.
//
// The counters now follow whichever socket is carrying traffic and reset when it
// changes, and only that socket can produce a report.
static volatile LONG g_watchedSocket = -1;

// A close the client performs itself, with no error anywhere, is what an orderly
// logout looks like as well as a realm handoff. Reporting it needs the
// connection to have been substantial enough that its ending is worth a banner:
// the logon exchange in the logs above was 5,584 bytes over 2.7 seconds, while a
// world session is minutes and megabytes. An early drop still gets reported -
// through recv returning 0 or an error, which is what a server-side drop
// actually looks like from here.
static const DWORD    kRealSessionMs    = 30000;
static const uint64_t kRealSessionBytes = 256 * 1024;

// Point the counters at `s`, restarting them if the traffic has moved to a new
// socket. Returns nothing; callers are on the receive hot path.
static void WatchSocket(SOCKET s) {
    LONG sv = (LONG)s;
    if (g_watchedSocket == sv) return;
    if (InterlockedExchange(&g_watchedSocket, sv) == sv) return;
    g_recvCalls     = 0;
    g_sendCalls     = 0;
    g_recvBytes     = 0;
    g_sendBytes     = 0;
    g_firstRecvTick = 0;
    g_lastSendTick  = 0;
    InterlockedIncrement(&g_connSeq);
    InterlockedExchange(&g_reported, 0);
}

static bool IsWatched(SOCKET s) { return g_watchedSocket == (LONG)s; }

static const char* ErrorName(int err) {
    switch (err) {
        case WSAECONNRESET:   return "WSAECONNRESET - the peer reset the connection";
        case WSAECONNABORTED: return "WSAECONNABORTED - aborted locally";
        case WSAETIMEDOUT:    return "WSAETIMEDOUT - no response in time";
        case WSAENETRESET:    return "WSAENETRESET - the route dropped";
        case WSAENOTCONN:     return "WSAENOTCONN - socket was not connected";
        case WSAESHUTDOWN:    return "WSAESHUTDOWN - already shut down this side";
        case WSAEHOSTUNREACH: return "WSAEHOSTUNREACH - no route to host";
        case WSAENETDOWN:     return "WSAENETDOWN - the network went down";
        case WSAEINTR:        return "WSAEINTR - the call was cancelled";
        default:              return "";
    }
}

// `how` describes what ended it; `err` is 0 for a graceful close.
static void ReportDisconnect(const char* how, int err) {
    if (InterlockedCompareExchange(&g_reported, 1, 0) != 0) return;

    DWORD now = GetTickCount();
    DWORD sinceRecv = (g_lastRecvTick != 0) ? (now - g_lastRecvTick) : 0;
    DWORD sinceSend = (g_lastSendTick != 0) ? (now - g_lastSendTick) : 0;
    DWORD sessionMs = (g_firstRecvTick != 0) ? (now - g_firstRecvTick) : 0;

    // A connection that carried neither long enough nor much enough to be a world
    // session is the logon exchange ending, which is a normal step in starting the
    // game. It gets a line rather than a banner. Silence is what let the
    // per-session latch look harmless for as long as it did.
    if (sessionMs < kRealSessionMs && g_recvBytes < kRealSessionBytes) {
        Log("[NetDiag] Connection %ld ended (%s) after %lu ms and %llu bytes - too "
            "short to be a world session, so this is the logon handoff",
            g_connSeq, how, (unsigned long)sessionMs,
            (unsigned long long)g_recvBytes);
        return;
    }

    Verdict::Add(Verdict::Bad, "disconnected: %s", how);
    Log("!!! DISCONNECT !!! (connection %ld) %s%s%s", g_connSeq, how,
        (err && *ErrorName(err)) ? " - " : "",
        (err && *ErrorName(err)) ? ErrorName(err) : "");

    if (err && !*ErrorName(err)) {
        Log("!!!   Winsock error %d (no name known for it here)", err);
    }

    Log("!!!   Last byte arrived %lu ms ago, last send %lu ms ago",
        (unsigned long)sinceRecv, (unsigned long)sinceSend);
    Log("!!!   Session carried %llu bytes in over %ld receives, %llu bytes out "
        "over %ld sends, across %lu ms",
        (unsigned long long)g_recvBytes, g_recvCalls,
        (unsigned long long)g_sendBytes, g_sendCalls,
        (unsigned long)sessionMs);

    // Whether this DLL was in the middle of something. A drop during a loading
    // transition or while the main thread was not ticking is a different
    // situation from one in steady play, and the two have been indistinguishable
    // in every report so far.
    DWORD lastTick = WowOpt_LastMainThreadTick();
    DWORD mainSilent = (lastTick != 0) ? (now - lastTick) : 0;
    Log("!!!   Main thread last ticked %lu ms ago; loading=%d reloading=%d swapping=%d",
        (unsigned long)mainSilent,
        LuaOpt::IsLoadingMode() ? 1 : 0,
        LuaOpt::IsReloading() ? 1 : 0,
        LuaOpt::IsSwapping() ? 1 : 0);

    // A clean close of a healthy connection has one known cause on at least one
    // server, and the reader of this log deserves to be told rather than left to
    // repeat the whole investigation. Only said when the mode is off, because
    // with it on this report is the experiment rather than a complaint.
    if (err == 0 && mainSilent < 1000 && !Config::g_settings.OptNoClientPatches) {
        Log("!!!   The client was healthy when this happened, so nothing here "
            "stalled or crashed. On WoWCircle two players stopped being dropped "
            "entirely once they enabled No Client Patches in the launcher, which "
            "stops this DLL writing anything into WoW.exe. That turns every "
            "optimisation off - it is the trade, not a fix.");
    }

    CrashDumper::DumpTrace(12, 30000);
    // Nobody reacts to a disconnect in time to press a key, so the ring is
    // written out here instead.
    FlightRecorder::Mark("the connection ended");
    Log("!!! END DISCONNECT REPORT !!!");
}

// Winsock's last-error value belongs to the caller, and everything this observer
// does after the original returns - GetTickCount, and above all Log, which
// writes a file - overwrites it. A hook that reports a disconnect and leaves the
// client reading some unrelated error code is not observing, it is interfering.
// Each hook therefore saves the value the original left behind and restores it
// on the way out, so the client sees exactly what it would have seen.
static int WINAPI Hooked_recv(SOCKET s, char* buf, int len, int flags) {
    int r = orig_recv(s, buf, len, flags);
    DWORD le = GetLastError();
    if (r > 0) {
        WatchSocket(s);
        DWORD now = GetTickCount();
        g_lastRecvTick = now;
        if (g_firstRecvTick == 0) g_firstRecvTick = now;
        InterlockedIncrement(&g_recvCalls);
        g_recvBytes += (uint64_t)r;
        FlightRecorder::Bump(g_frSlotRecv);
    } else if (r == 0) {
        if (IsWatched(s)) ReportDisconnect("the server closed the connection cleanly", 0);
    } else {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS && IsWatched(s)) {
            ReportDisconnect("recv failed", err);
        }
    }
    SetLastError(le);
    return r;
}

static int WINAPI Hooked_WSARecv(SOCKET s, LPWSABUF bufs, DWORD count,
                                 LPDWORD got, LPDWORD flags,
                                 LPWSAOVERLAPPED ov,
                                 LPWSAOVERLAPPED_COMPLETION_ROUTINE done) {
    int r = orig_WSARecv(s, bufs, count, got, flags, ov, done);
    DWORD le = GetLastError();
    if (r == 0 && got) {
        if (*got > 0) {
            WatchSocket(s);
            DWORD now = GetTickCount();
            g_lastRecvTick = now;
            if (g_firstRecvTick == 0) g_firstRecvTick = now;
            InterlockedIncrement(&g_recvCalls);
            g_recvBytes += (uint64_t)*got;
            FlightRecorder::Bump(g_frSlotRecv);
        } else if (IsWatched(s)) {
            ReportDisconnect("the server closed the connection cleanly", 0);
        }
    } else if (r == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSA_IO_PENDING && err != WSAEINPROGRESS
            && IsWatched(s)) {
            ReportDisconnect("WSARecv failed", err);
        }
    }
    SetLastError(le);
    return r;
}

static int WINAPI Hooked_send(SOCKET s, const char* buf, int len, int flags) {
    int r = orig_send(s, buf, len, flags);
    DWORD le = GetLastError();
    if (r > 0) {
        g_lastSendTick = GetTickCount();
        InterlockedIncrement(&g_sendCalls);
        g_sendBytes += (uint64_t)r;
    } else if (r == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS && IsWatched(s)) {
            ReportDisconnect("send failed", err);
        }
    }
    SetLastError(le);
    return r;
}

static int WINAPI Hooked_closesocket(SOCKET s) {
    // Only interesting if nothing else has explained the end yet, if this is the
    // socket the counters describe, and if that connection was a real session
    // rather than the logon exchange or a handful of packets. See the notes on
    // g_watchedSocket and kRealSessionMs.
    if (g_reported == 0 && g_recvCalls > 0 && IsWatched(s)) {
        DWORD now      = GetTickCount();
        DWORD lifetime = (g_firstRecvTick != 0) ? (now - g_firstRecvTick) : 0;
        if (lifetime >= kRealSessionMs || g_recvBytes >= kRealSessionBytes) {
            DWORD le = GetLastError();
            ReportDisconnect("the client closed the socket, with no prior error "
                             "(this is also what an orderly logout looks like)", 0);
            SetLastError(le);
        }
    }
    return orig_closesocket(s);
}

bool Init() {
    if (!Config::g_settings.OptNetDiag) return true;

    HMODULE ws = GetModuleHandleA("ws2_32.dll");
    if (!ws) ws = LoadLibraryA("ws2_32.dll");
    if (!ws) {
        Log("[NetDiag] ws2_32.dll is not loaded - nothing to observe");
        return false;
    }

    struct { const char* name; void* detour; void** orig; } hooks[] = {
        { "recv",        (void*)Hooked_recv,        (void**)&orig_recv        },
        { "WSARecv",     (void*)Hooked_WSARecv,     (void**)&orig_WSARecv     },
        { "send",        (void*)Hooked_send,        (void**)&orig_send        },
        { "closesocket", (void*)Hooked_closesocket, (void**)&orig_closesocket },
    };

    int installed = 0;
    for (auto& h : hooks) {
        void* target = (void*)GetProcAddress(ws, h.name);
        if (!target) continue;
        if (WineSafe_CreateHook(target, h.detour, h.orig) == MH_OK &&
            WO_EnableHook(target) == MH_OK) {
            ++installed;
        } else {
            Log("[NetDiag]   %s could not be hooked", h.name);
        }
    }

    if (installed == 0) {
        Log("[NetDiag] No socket entry points could be hooked");
        return false;
    }

    g_frSlotRecv = FlightRecorder::RegisterSlot("recv");

    g_active = true;
    Log("[NetDiag] Watching the receive path, %d/4 entry points - reports once if "
        "a connection ends", installed);
    return true;
}

void LogStats() {
    if (!g_active) return;
    DWORD now = GetTickCount();
    Log("[NetDiag] connection %ld: %ld receives (%llu bytes), %ld sends (%llu "
        "bytes), last byte %lu ms ago",
        g_connSeq, g_recvCalls, (unsigned long long)g_recvBytes,
        g_sendCalls, (unsigned long long)g_sendBytes,
        (unsigned long)(g_lastRecvTick ? (now - g_lastRecvTick) : 0));
}

void Shutdown() {
    if (!g_active) return;
    g_active = false;
    LogStats();
}

} // namespace NetDiag
