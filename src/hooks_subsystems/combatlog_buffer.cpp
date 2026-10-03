#include "combatlog_buffer.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <intrin.h>

extern "C" void Log(const char* fmt, ...);

namespace CombatLogBuffer {

namespace Addr {
    static constexpr uintptr_t PendingListHead = 0x00CA1394;
    static constexpr uintptr_t ProcessEntries  = 0x0074F910;
    static constexpr uintptr_t ClearEntries    = 0x00751120;
}

static constexpr int MAX_PENDING = 512;
static constexpr int FLUSH_THRESH = 256;
static constexpr int MONITOR_MS = 100;

static volatile LONG64 g_total = 0;
static volatile LONG64 g_dropped = 0;
static volatile LONG64 g_flushes = 0;
static volatile LONG g_pending = 0;
static volatile LONG g_peak = 0;
static bool g_init = false;
static double g_freq = 0.0;
static double g_lastTime = 0.0;

typedef int (__cdecl *Process_fn)();
typedef int (__cdecl *Clear_fn)();
static Process_fn g_proc = nullptr;
static Clear_fn g_clear = nullptr;

static bool IsReadable(uintptr_t a) {
    if (!a) return false;
    MEMORY_BASIC_INFORMATION m;
    if (VirtualQuery((void*)a, &m, sizeof(m)) == 0) return false;
    return m.State == MEM_COMMIT && !(m.Protect & PAGE_NOACCESS);
}

static bool IsExec(uintptr_t a) {
    if (!a) return false;
    MEMORY_BASIC_INFORMATION m;
    if (VirtualQuery((void*)a, &m, sizeof(m)) == 0) return false;
    return m.State == MEM_COMMIT && (m.Protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE));
}

static double GetMs() {
    LARGE_INTEGER l;
    QueryPerformanceCounter(&l);
    return (double)l.QuadPart / g_freq;
}

// Walks the client's list, which the retention patch keeps at the 1024 this stops
// at for the whole of a fight. It used to ask VirtualQuery about every node, a
// system call per node and a thousand of them every 100 ms on the main thread in
// combat; the walk is already under an exception handler, so a node that is not
// readable ends it the same way.
static int CountPending() {
    __try {
        if (!IsReadable(Addr::PendingListHead)) return -1;
        int c = 0;
        uintptr_t cur = *(uintptr_t*)Addr::PendingListHead;
        while (cur && !(cur & 1) && c < MAX_PENDING * 2) {
            c++;
            cur = *(uintptr_t*)(cur + 4);
        }
        return c;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

bool Init() {
    Log("[CombatLogBuffer] Init");
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    g_freq = (double)f.QuadPart / 1000.0;
    if (IsExec(Addr::ProcessEntries)) g_proc = (Process_fn)Addr::ProcessEntries;
    if (IsExec(Addr::ClearEntries)) g_clear = (Clear_fn)Addr::ClearEntries;
    Log("[CombatLogBuffer] Process=%s Clear=%s Max=%d Flush=%d",
        g_proc ? "OK" : "FAIL", g_clear ? "OK" : "FAIL", MAX_PENDING, FLUSH_THRESH);
    g_init = true;
    return true;
}

void OnFrame(DWORD tid) {
    if (!g_init || GetCurrentThreadId() != tid) return;
    double now = GetMs();
    if (now - g_lastTime < MONITOR_MS) return;
    g_lastTime = now;
    int p = CountPending();
    if (p < 0) return;
    InterlockedExchange(&g_pending, p);
    InterlockedIncrement64(&g_total);
    LONG pk = g_peak;
    if (p > pk) InterlockedCompareExchange(&g_peak, p, pk);
    // NOTE: We intentionally do NOT call g_proc() here.
    // Calling ProcessEntries (0x74F910) from our frame hook while the game's
    // own combat log dispatch is also running causes double-processing and
    // use-after-free corruption. The game already processes entries each frame.
    // Our role is monitoring only — alerting when the buffer is overwhelmed.
    if (p >= MAX_PENDING) {
        InterlockedIncrement64(&g_flushes);
        // Once, and then once a minute. In a fight the list sits at its ceiling
        // and this line was written ten times a second: 9295 of them in one
        // 64 minute session, in a log the testers are asked to send.
        static double s_lastWarnMs = -1e9;
        if (now - s_lastWarnMs >= 60000.0) {
            s_lastWarnMs = now;
            Log("[CombatLogBuffer] WARNING: %d pending (high combat log volume); "
                "%lld reading(s) at or above %d so far, this line is written once a minute",
                p, (long long)g_flushes, MAX_PENDING);
        }
    }
}

// Printed from the periodic report. Shutdown does not run - the DLL exits via
// TerminateProcess - so anything reported only from there is never seen.
void LogStats() {
    Log("[CombatLogBuffer] total=%lld dropped=%lld flushes=%lld peak=%ld",
        g_total, g_dropped, g_flushes, g_peak);
}

void Shutdown() {
    if (!g_init) return;
    LogStats();
    g_init = false;
}

Stats GetStats() {
    Stats s = {};
    s.totalEvents = g_total;
    s.droppedEvents = g_dropped;
    s.forcedFlushes = g_flushes;
    s.currentPending = g_pending;
    s.peakPending = g_peak;
    s.ringBufferSize = MAX_PENDING;
    s.ringBufferInUse = g_pending;
    return s;
}

} // namespace CombatLogBuffer
