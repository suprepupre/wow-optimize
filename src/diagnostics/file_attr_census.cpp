// ============================================================================
// Module: file_attr_census.cpp
//
// How long the client waits for GetFileAttributesExA, and for which of its two call sites.
//
// The freeze captures of the 2026-10-08 sessions (three machines, build 9fc59ceb) put more
// stalled main-thread samples inside NtQueryFullAttributesFile than inside the CreateFileA
// that opens the same files: 1207 samples at wow.exe 0x004355FA and 1396 at 0x00454D25,
// against 298 for the CreateFileA at 0x004557EE. One frame of 823 ms spent 152 of its 271
// samples at 0x004355FA.
//
//   0x004355FA  sub_435580, run right after the client opens a file (sub_455730): it asks the
//               system for the file's size, then for its dates and attributes by the path it
//               has just opened, though the handle is already in hand.
//   0x00454D25  sub_454CF0, the file stack's "get information by name" operation.
//
// A standalone run on a development machine (6001 files of an addon tree, warm cache) puts a
// path query at 3.0 us and GetFileInformationByHandle at 2.9 us, so a handle-based
// replacement would change nothing there. The captured stalls are therefore either a machine
// where the path lookup is slow (a scanner or filter driver, a slow disk, a network share) or
// a few paths that are slow each time. Which of the two, and how many calls there are, is
// not known, and that decides whether any replacement is worth writing. This counts and times
// the calls from the client by call site and keeps the slowest path's tail.
//
// Nothing is changed. The hook is on a kernel32 export and writes nothing into wow.exe, so
// it runs under No Client Patches. Calls from other modules go straight through.
// Counters are plain and lower bounds: the calls can come from more than one thread.
// ============================================================================

#include "file_attr_census.h"
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include "config.h"
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

namespace FileAttrCensus {
namespace {

constexpr int kRows = 12;

struct Row {
    uintptr_t     caller;
    unsigned long n;
    unsigned long failed;
    double        totalMs;
    double        worstMs;
    unsigned long over1ms;
    unsigned long over10ms;
    char          worstTail[64];
};

typedef BOOL (WINAPI *GetFileAttributesExA_fn)(LPCSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
GetFileAttributesExA_fn g_orig = nullptr;
Row           g_rows[kRows] = {};
unsigned long g_lost = 0;
double        g_freqMs = 0.0;     // counter ticks per millisecond
bool          g_installed = false;

Row* RowFor(uintptr_t caller) {
    for (int i = 0; i < kRows; ++i) {
        if (g_rows[i].caller == caller) return &g_rows[i];
        if (g_rows[i].caller == 0) { g_rows[i].caller = caller; return &g_rows[i]; }
    }
    return nullptr;
}

BOOL WINAPI Hooked(LPCSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID info) {
    if (WOWOPT_FOREIGN_CALLER()) return g_orig(name, level, info);
    const uintptr_t caller = (uintptr_t)_ReturnAddress();
    LARGE_INTEGER a, b;
    QueryPerformanceCounter(&a);
    const BOOL ok = g_orig(name, level, info);
    QueryPerformanceCounter(&b);
    Row* r = RowFor(caller);
    if (!r) { ++g_lost; return ok; }
    const double ms = (double)(b.QuadPart - a.QuadPart) / g_freqMs;
    ++r->n;
    if (!ok) ++r->failed;
    r->totalMs += ms;
    if (ms >= 1.0) ++r->over1ms;
    if (ms >= 10.0) ++r->over10ms;
    if (ms > r->worstMs) {
        r->worstMs = ms;
        // Only the end of the path: enough to tell an addon file from a SavedVariables file
        // from a map, and no more of the player's folders than that.
        const size_t len = name ? strnlen(name, 4096) : 0;
        const size_t keep = len < sizeof(r->worstTail) - 1 ? len : sizeof(r->worstTail) - 1;
        if (keep) memcpy(r->worstTail, name + len - keep, keep);
        r->worstTail[keep] = 0;
    }
    return ok;
}

} // namespace

void Init() {
    if (!Config::g_settings.OptFileAttrCensus) return;
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    g_freqMs = (double)f.QuadPart / 1000.0;
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    void* target = k32 ? (void*)GetProcAddress(k32, "GetFileAttributesExA") : nullptr;
    if (!target || g_freqMs <= 0.0) { Log("[FileAttrCensus] NOT active: GetFileAttributesExA or the counter was not found."); return; }
    if (MH_CreateHook(target, (void*)&Hooked, (void**)&g_orig) != MH_OK || WO_EnableHook(target) != MH_OK) {
        Log("[FileAttrCensus] NOT active: GetFileAttributesExA could not be hooked.");
        return;
    }
    g_installed = true;
    Log("[FileAttrCensus] ACTIVE: the client's GetFileAttributesExA calls are counted and timed per call site. Nothing is changed.");
}

void Shutdown() {
}

void LogStats() {
    if (!Config::g_settings.OptFileAttrCensus) return;
    if (!g_installed) { Log("[FileAttrCensus] not installed, so nothing here was measured."); return; }
    unsigned long total = 0;
    for (int i = 0; i < kRows; ++i) total += g_rows[i].n;
    if (total == 0) { Log("[FileAttrCensus] measured and zero: the client has not called GetFileAttributesExA yet."); return; }
    for (int i = 0; i < kRows; ++i) {
        const Row& r = g_rows[i];
        if (!r.n) continue;
        const char* what = r.caller - 0x004355FAu < 8u ? "  (after opening a file)"
                         : r.caller - 0x00454D25u < 8u ? "  (get information by name)" : "";
        Log("[FileAttrCensus]   wow!0x%08X%s  %lu call(s), %lu failed, %.2f ms on average, %.1f s in all, worst %.1f ms, "
            "%lu over 1 ms, %lu over 10 ms; slowest was ...%s",
            (unsigned)r.caller, what, r.n, r.failed, r.totalMs / (double)r.n, r.totalMs / 1000.0, r.worstMs,
            r.over1ms, r.over10ms, r.worstTail);
    }
    if (g_lost) Log("[FileAttrCensus]   %lu call(s) from call sites that did not fit the table. Plain counters, lower bounds.", g_lost);
}

} // namespace FileAttrCensus
