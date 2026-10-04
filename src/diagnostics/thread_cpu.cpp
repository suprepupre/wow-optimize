// ============================================================================
// Module: thread_cpu
//
// A thread that does nothing useful and never sleeps shows up in no profile of
// the main thread, and the sampling profiler's background table counts where a
// thread's samples fell, not how much CPU it took. One of this DLL's own workers
// called SwitchToThread in a loop with nothing to run and held a core for every
// session for as long as the feature existed; the first thing that said so was a
// standalone loop of the same shape, not any log.
//
// The kernel keeps kernel and user time per thread. Reading them for every thread
// every report interval, and differencing against the previous reading, says
// which threads run flat out and which wait, whoever created them: this DLL, the
// client, the Direct3D runtime or the translation layer.
// ============================================================================

#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "thread_cpu.h"
#include "freeze_catcher.h"

extern "C" void Log(const char* fmt, ...);

namespace ThreadCpu {
namespace {

constexpr int kMaxThreads = 512;
constexpr int kShown      = 12;

struct Prev { DWORD tid; ULONGLONG cpu100ns; };
Prev      g_prev[kMaxThreads];
int       g_prevCount = 0;
ULONGLONG g_lastTick  = 0;
ULONGLONG g_firstTick = 0;

struct Row {
    DWORD     tid;
    ULONGLONG total100ns;
    ULONGLONG interval100ns;
    bool      hadPrev;
    uintptr_t start;
    char      name[64];
};

typedef LONG (NTAPI *NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef HRESULT (WINAPI *GetThreadDescription_t)(HANDLE, PWSTR*);

constexpr ULONG kThreadQuerySetWin32StartAddress = 9;

ULONGLONG ToUll(const FILETIME& f) { return ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }

uintptr_t StartAddressOf(HANDLE h) {
    static NtQueryInformationThread_t fn =
        (NtQueryInformationThread_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    if (!fn) return 0;
    PVOID addr = nullptr;
    if (fn(h, kThreadQuerySetWin32StartAddress, &addr, sizeof(addr), nullptr) != 0) return 0;
    return (uintptr_t)addr;
}

void NameOf(HANDLE h, char* out, size_t cap) {
    out[0] = 0;
    static GetThreadDescription_t fn =
        (GetThreadDescription_t)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "GetThreadDescription");
    if (!fn) return;
    PWSTR w = nullptr;
    if (FAILED(fn(h, &w)) || !w) return;
    WideCharToMultiByte(CP_ACP, 0, w, -1, out, (int)cap, nullptr, nullptr);
    out[cap - 1] = 0;
    LocalFree(w);
}

void DescribeStart(uintptr_t a, char* out, size_t cap) {
    if (!a) { snprintf(out, cap, "start address not available"); return; }
    if (FreezeCatcher::NameExport(a, out, cap)) return;
    HMODULE m = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)a, &m) && m) {
        char path[MAX_PATH] = {};
        GetModuleFileNameA(m, path, MAX_PATH);
        const char* base = strrchr(path, 92);
        snprintf(out, cap, "%s+0x%X", base ? base + 1 : path, (unsigned)(a - (uintptr_t)m));
        return;
    }
    snprintf(out, cap, "0x%08X", (unsigned)a);
}

ULONGLONG PrevCpu(DWORD tid, bool* found) {
    for (int i = 0; i < g_prevCount; ++i)
        if (g_prev[i].tid == tid) { *found = true; return g_prev[i].cpu100ns; }
    *found = false;
    return 0;
}

} // namespace

// The work itself. Takes a snapshot of every thread in the system and opens each of this
// process's, which cost 19.6 to 20.9 ms on the main thread in every periodic report of the
// first logs that carried it ("slowest reporters": ThreadCpu::Report) - a pause the player
// sees, five minutes apart, to read counters that need no particular thread.
static void ReportNow() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        Log("[ThreadCpu] not measured: the thread list could not be read.");
        return;
    }

    static Row rows[kMaxThreads];
    int n = 0, unopened = 0, tooMany = 0;
    ULONGLONG sumTotal = 0, sumInterval = 0;
    const DWORD pid = GetCurrentProcessId();
    const ULONGLONG now = GetTickCount64();
    if (!g_firstTick) g_firstTick = now;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (n >= kMaxThreads) { ++tooMany; continue; }
            // The start address needs full query access; the times and the name need
            // only the limited kind, so a thread that refuses the first is still counted.
            HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!h) h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (!h) { ++unopened; continue; }
            FILETIME c, e, k, u;
            if (!GetThreadTimes(h, &c, &e, &k, &u)) { ++unopened; CloseHandle(h); continue; }
            Row& r = rows[n++];
            r.tid = te.th32ThreadID;
            r.total100ns = ToUll(k) + ToUll(u);
            bool found = false;
            const ULONGLONG before = PrevCpu(r.tid, &found);
            r.hadPrev = found;
            r.interval100ns = (found && r.total100ns >= before) ? r.total100ns - before : 0;
            r.start = StartAddressOf(h);
            NameOf(h, r.name, sizeof(r.name));
            sumTotal += r.total100ns;
            sumInterval += r.interval100ns;
            CloseHandle(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    const ULONGLONG wallMs = g_lastTick ? now - g_lastTick : now - g_firstTick;
    const bool haveInterval = g_lastTick != 0 && wallMs > 0;

    // Remember this reading for the next one.
    g_prevCount = n;
    for (int i = 0; i < n; ++i) { g_prev[i].tid = rows[i].tid; g_prev[i].cpu100ns = rows[i].total100ns; }
    g_lastTick = now;

    if (n == 0) {
        Log("[ThreadCpu] not measured: no thread of this process could be opened.");
        return;
    }

    if (haveInterval) {
        Log("[ThreadCpu] === THREAD CPU: %d thread(s), %.1f s of CPU in the last %.0f s of wall time "
            "(%.2f cores busy on average), %.1f s since the process started ===",
            n, (double)sumInterval / 1e7, (double)wallMs / 1000.0,
            ((double)sumInterval / 1e4) / (double)wallMs, (double)sumTotal / 1e7);
    } else {
        Log("[ThreadCpu] === THREAD CPU: %d thread(s), %.1f s of CPU since the process started; "
            "no earlier reading, so no per-interval figure yet ===", n, (double)sumTotal / 1e7);
    }
    if (unopened || tooMany)
        Log("[ThreadCpu]   %d thread(s) could not be opened and %d did not fit the table; they are not in the "
            "figures above.", unopened, tooMany);

    bool used[kMaxThreads] = {};
    for (int line = 0; line < kShown && line < n; ++line) {
        int best = -1;
        for (int i = 0; i < n; ++i) {
            if (used[i]) continue;
            if (best < 0) { best = i; continue; }
            const ULONGLONG a = haveInterval ? rows[i].interval100ns : rows[i].total100ns;
            const ULONGLONG b = haveInterval ? rows[best].interval100ns : rows[best].total100ns;
            if (a > b) best = i;
        }
        if (best < 0) break;
        used[best] = true;
        const Row& r = rows[best];
        char where[128];
        DescribeStart(r.start, where, sizeof(where));
        if (haveInterval) {
            const double core = ((double)r.interval100ns / 1e4) * 100.0 / (double)wallMs;
            Log("[ThreadCpu]   tid %-6lu %7.1f s total  %6.1f s in the interval (%5.1f%% of a core)%s  %s%s%s",
                (unsigned long)r.tid, (double)r.total100ns / 1e7, (double)r.interval100ns / 1e7, core,
                !r.hadPrev ? " [new]" : "", where, r.name[0] ? "  name: " : "", r.name);
        } else {
            Log("[ThreadCpu]   tid %-6lu %7.1f s total  %s%s%s", (unsigned long)r.tid,
                (double)r.total100ns / 1e7, where, r.name[0] ? "  name: " : "", r.name);
        }
    }
}

namespace {
volatile LONG g_running = 0;
DWORD WINAPI ReportThread(LPVOID) {
    ReportNow();
    InterlockedExchange(&g_running, 0);
    return 0;
}
} // namespace

// Called from the periodic report on the main thread. Returns at once; the reading is done
// by a short-lived thread, and a call that finds the last one still running is skipped
// rather than queued (the next report is five minutes away).
void Report() {
    if (InterlockedCompareExchange(&g_running, 1, 0) != 0) return;
    HANDLE h = CreateThread(nullptr, 64 * 1024, ReportThread, nullptr, 0, nullptr);
    if (!h) {
        InterlockedExchange(&g_running, 0);
        Log("[ThreadCpu] not measured: the reading thread could not be created.");
        return;
    }
    CloseHandle(h);
}

} // namespace ThreadCpu
