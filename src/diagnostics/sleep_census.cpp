// ============================================================================
// Module: sleep_census
//
// prince's profile of 2026-10-07 (build 783ab7af, ICC, 14.3 ms average frame) has the main thread
// blocked 27.9% of its samples and 17.3% of ALL samples in NtDelayExecution called from this
// DLL's Sleep hook. The profiler's caller table stops at the hook, so it cannot say whose Sleep
// it is: the client's frame limiter (sub_6836D0 -> sub_86B280), the polling loops of its
// asynchronous file reader (the same wrapper, Sleep(1) from four places), or something else.
// Whether that sleeping is the game waiting for a file during play, or a limiter doing its job,
// decides what is worth building. This counts it: per caller, the number of sleeps, the requested
// milliseconds, the time actually slept, and whether a loading screen was up.
//
// The caller is the return address of the client's wrapper, read from the stack when the Sleep
// hook was entered from that wrapper (0x0086B28D); otherwise the hook's own return address.
// Plain counters on the main thread only; nothing allocated, no lock.
// ============================================================================

#include "sleep_census.h"
#include <windows.h>
#include <cstdio>

extern "C" void Log(const char* fmt, ...);

namespace SleepCensus {
namespace {

constexpr int kRows = 48;
struct Row {
    uintptr_t caller;
    unsigned long n;
    unsigned long long requestedMs, sleptUs;
    unsigned long loadingN;
    unsigned long long loadingUs;
};
Row g_rows[kRows];
unsigned long g_lost = 0;
unsigned long long g_total = 0, g_totalUs = 0;
// What a report is compared with, so that the rate over the interval is visible.
unsigned long long g_prevUs = 0;
DWORD g_prevTick = 0;

}  // namespace

void Note(uintptr_t caller, uint32_t requestedMs, uint32_t sleptUs, bool loading) {
    ++g_total;
    g_totalUs += sleptUs;
    uint32_t h = (uint32_t)((caller * 2654435761u) >> 8) % kRows;
    for (int step = 0; step < kRows; ++step, h = (h + 1) % kRows) {
        Row& r = g_rows[h];
        if (r.n == 0) r.caller = caller;
        if (r.caller != caller) continue;
        ++r.n;
        r.requestedMs += requestedMs;
        r.sleptUs += sleptUs;
        if (loading) { ++r.loadingN; r.loadingUs += sleptUs; }
        return;
    }
    ++g_lost;
}

void LogStats() {
    if (g_total == 0) {
        Log("[SleepCensus] the main thread has not called Sleep yet.");
        return;
    }
    const DWORD now = GetTickCount();
    const double wallS = g_prevTick ? (double)(DWORD)(now - g_prevTick) / 1000.0 : 0.0;
    const double intervalS = (double)(g_totalUs - g_prevUs) / 1e6;
    Log("[SleepCensus] main thread: %llu Sleep call(s), %.1f s slept in all%s. Plain counters; the time is the real "
        "length of each sleep.", g_total, (double)g_totalUs / 1e6,
        wallS > 0.0 ? "" : "");
    if (wallS > 0.0)
        Log("[SleepCensus]   since the previous report: %.1f s slept in %.0f s of wall time (%.1f%%).", intervalS, wallS,
            100.0 * intervalS / wallS);
    g_prevUs = g_totalUs;
    g_prevTick = now;
    bool taken[kRows] = {};
    for (int shown = 0; shown < 8; ++shown) {
        int best = -1;
        for (int i = 0; i < kRows; ++i)
            if (!taken[i] && g_rows[i].n && (best < 0 || g_rows[i].sleptUs > g_rows[best].sleptUs)) best = i;
        if (best < 0) break;
        taken[best] = true;
        const Row& r = g_rows[best];
        char who[96];
        const uintptr_t cli = (uintptr_t)GetModuleHandleA(nullptr);
        HMODULE owner = nullptr;
        if (r.caller - cli < 0x00A00000u) {
            wsprintfA(who, "wow!0x%08X", (unsigned)r.caller);
        } else if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                      (LPCSTR)r.caller, &owner) && owner) {
            char path[MAX_PATH] = {};
            GetModuleFileNameA(owner, path, MAX_PATH);
            const char* name = path;
            for (const char* c = path; *c; ++c) if (*c == '\\' || *c == '/') name = c + 1;
            wsprintfA(who, "%s+0x%X", name, (unsigned)(r.caller - (uintptr_t)owner));
        } else {
            wsprintfA(who, "0x%08X", (unsigned)r.caller);
        }
        Log("[SleepCensus]   %s  %lu call(s), %.0f ms asked on average, %.2f ms slept on average, %.1f s in all "
            "(%.1f s of it in a loading screen)", who, r.n, (double)r.requestedMs / (double)r.n,
            (double)r.sleptUs / 1000.0 / (double)r.n, (double)r.sleptUs / 1e6, (double)r.loadingUs / 1e6);
    }
    if (g_lost) Log("[SleepCensus]   %lu call(s) from callers that did not fit the table.", g_lost);
}

}  // namespace SleepCensus
