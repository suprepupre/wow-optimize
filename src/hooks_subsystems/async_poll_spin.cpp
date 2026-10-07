// ============================================================================
// Module: async_poll_spin.cpp
//
// The client's asynchronous file reader polls with Sleep(1) on both sides of
// every request, and a loading screen is mostly those requests one after the
// other.
//
// What the client does. A request is queued (sub_4BA170 and its siblings) and
// the thread that needs it either carries on or, for a read it needs now,
// waits in AsyncFileReadWait (sub_4BA060): run the completion callbacks
// (sub_4B9B20), and if the request is not done, Sleep(1) through the client's
// wrapper sub_86B280, and again. The reader is a worker thread (sub_4BA680) and
// it does not block on anything: it drains its two priority lists, and when
// both are empty it calls the same wrapper with 1 and then polls a stop event
// with a zero timeout. A request that arrives while it sleeps waits out the
// rest of the sleep. The loading screen's own pump (sub_4BAE10) and a wait on
// a single item (sub_4B9DE0) are the same loop again.
//
// So a read that is needed now costs the worker's remaining Sleep(1) to be
// picked up and the waiter's Sleep(1) to notice it is done, with a timer at
// 0.5 ms (this DLL sets it) about a millisecond each, for a read that itself
// takes a fraction of that when the archive is in the file cache. In Drain's
// 2026-10-07 sessions, loads of 10.8 to 24.6 seconds read 7569 to 28169 times,
// 0.65 to 2.2 ms a read; FreezeCatcher's samples inside loading frames were
// 9672 of 15320 in NtDelayExecution, every one of them through sub_86B280;
// and the client's two worker threads together used 45 s of CPU in a five
// minute interval that held one load. The main thread was asleep for most of
// a load and the worker threads were not busy either. That is circumstantial:
// no log yet says what the workers are doing inside a load (FreezeCatcher now
// samples them while a loading frame is on), and nothing here has run in a
// game.
//
// What this does. It hooks sub_86B280 and, for those four call sites only
// (the return address says which) and only for a one millisecond request, it
// waits a few tens of microseconds by spinning instead, and returns. Each
// caller is a polling loop that re-reads its state when the sleep returns, so
// returning early changes how often it looks and nothing it looks at. Spinning
// is bounded by an episode budget: after about a millisecond and a half of
// consecutive spinning without the loop having left its wait, the real sleep
// is called again, so a read that takes fifty milliseconds is waited out
// asleep, not on a core. The worker's idle spin is only allowed while a loading
// screen is up or the main thread is inside AsyncFileReadWait, so the worker
// does not hold a core through ordinary play.
//
// What it does not change: which thread does what, the order of requests, any
// lock. Every other caller of sub_86B280 and every other length are passed to
// the client's routine untouched. Under FrameLimiter, which hooks the same
// function, this declines.
// ============================================================================

#include "async_poll_spin.h"
#include <windows.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>
#include "config.h"
#include "ab_test.h"
#include "loading_state.h"
#include "MinHook.h"
#include "version.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
extern "C" void WowOpt_MainThreadPump();
extern DWORD g_mainThreadId;

namespace AsyncPollSpin {
namespace {

constexpr uintptr_t kTarget = 0x0086B280;
static const uint8_t kPrologue[9] = { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x50, 0xFF, 0x15 };

// The return addresses of the four call sites, read from the disassembly.
constexpr uintptr_t kRetFileWait   = 0x004BA153;   // sub_4BA060, AsyncFileReadWait's loop
constexpr uintptr_t kRetPump       = 0x004BAEB6;   // sub_4BAE10, the loading screen's pump
constexpr uintptr_t kRetItemWait   = 0x004B9E1B;   // sub_4B9DE0, the wait on one item
constexpr uintptr_t kRetWorkerIdle = 0x004BA8BD;   // sub_4BA680, the worker with both lists empty
constexpr uintptr_t kFileWaiting   = 0x00B4A26C;   // s_waiting: the main thread is in AsyncFileReadWait

constexpr double kSliceUs   = 80.0;      // one spin, then the caller looks again
constexpr double kBudgetUs  = 1500.0;    // consecutive spinning per episode before the real sleep
constexpr double kGapUs     = 3000.0;    // a call this long after the last one starts a new episode

typedef void (__cdecl *OsSleep_fn)(DWORD ms);
OsSleep_fn g_orig = nullptr;
bool g_installed = false;
bool g_abSubject = false;
double g_freq = 0.0;                     // QPC ticks per microsecond

enum Site { kSiteFileWait = 0, kSitePump, kSiteItemWait, kSiteWorker, kSites };
const char* const kSiteName[kSites] = { "AsyncFileReadWait", "loading pump", "item wait", "reader idle" };

struct Episode {
    uint64_t lastTick;
    double   spunUs;
};
// Per thread: two reader threads would otherwise share one budget.
thread_local Episode g_ep[kSites];

// Plain counters. The worker site runs on another thread and the others on the main thread, and
// each site has its own row, so no row is written from two threads. Lower bounds.
unsigned long g_slices[kSites];
unsigned long g_realSleeps[kSites];
unsigned long g_declinedIdle = 0;
double        g_spunUsTotal[kSites];

inline uint64_t Now() {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (uint64_t)t.QuadPart;
}

inline void SpinFor(double us) {
    const uint64_t end = Now() + (uint64_t)(us * g_freq);
    do {
        for (int i = 0; i < 8; ++i) _mm_pause();
        SwitchToThread();
    } while (Now() < end);
}

void __cdecl Hooked_OsSleep(DWORD ms) {
    if (ms != 1) { g_orig(ms); return; }
    const uintptr_t ret = (uintptr_t)_ReturnAddress();
    int site;
    switch (ret) {
    case kRetFileWait:   site = kSiteFileWait; break;
    case kRetPump:       site = kSitePump; break;
    case kRetItemWait:   site = kSiteItemWait; break;
    case kRetWorkerIdle: site = kSiteWorker; break;
    default: g_orig(ms); return;
    }
    if (g_abSubject && AbTest::StandAside()) { g_orig(ms); return; }

    if (site == kSiteWorker) {
        // The worker only spins while somebody is waiting on it: a loading screen, or the main
        // thread inside AsyncFileReadWait. In ordinary play it sleeps as the client wrote it.
        if (!LoadingState::IsLoading() && *(volatile int*)kFileWaiting == 0) {
            ++g_declinedIdle;
            g_orig(ms);
            return;
        }
    } else if (GetCurrentThreadId() != g_mainThreadId) {
        g_orig(ms);
        return;
    }

    Episode& e = g_ep[site];
    const uint64_t now = Now();
    if (e.lastTick == 0 || (double)(now - e.lastTick) / g_freq > kGapUs) e.spunUs = 0.0;
    if (e.spunUs >= kBudgetUs) {
        // A wait that has outlasted the budget is waited out asleep.
        ++g_realSleeps[site];
        e.lastTick = now;
        g_orig(ms);
        return;
    }
    if (site != kSiteWorker) WowOpt_MainThreadPump();    // what the Sleep hook does for the main thread
    SpinFor(kSliceUs);
    e.spunUs += kSliceUs;
    e.lastTick = Now();
    ++g_slices[site];
    g_spunUsTotal[site] += kSliceUs;
}

} // namespace

void Init() {
    if (!Config::g_settings.OptAsyncPollSpin) return;

    void* const target = (void*)kTarget;
    if (!WowOpt_ClientPatchAllowed(target)) {
        Log("[AsyncPollSpin] NOT active: client patches disallowed at 0x%08X", (unsigned)kTarget);
        return;
    }
    if (std::memcmp(target, kPrologue, sizeof(kPrologue)) != 0) {
        Log("[AsyncPollSpin] NOT active: the bytes at 0x%08X are not the client's sleep wrapper (FrameLimiter, or another "
            "module, has hooked it first, or this is another client).", (unsigned)kTarget);
        return;
    }
    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    g_freq = (double)f.QuadPart / 1000000.0;
    if (g_freq <= 0.0) { Log("[AsyncPollSpin] NOT active: no performance counter."); return; }

    if (WineSafe_CreateHook(target, (void*)&Hooked_OsSleep, (void**)&g_orig) != MH_OK ||
        WO_EnableHook(target) != MH_OK) {
        Log("[AsyncPollSpin] NOT active: the hook on 0x%08X could not be created or enabled.", (unsigned)kTarget);
        return;
    }
    g_installed = true;
    g_abSubject = AbTest::IsSubject("AsyncPollSpin", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("AsyncPollSpin", (const void*)&Hooked_OsSleep);
    Log("[AsyncPollSpin] ACTIVE on the client's sleep wrapper (sub_86B280). A one millisecond sleep from the four loops that "
        "poll the asynchronous file reader waits %.0f microseconds by spinning instead, up to %.0f microseconds in a row, then "
        "sleeps as before. Timing only; the loops look at the same things, more often. Not yet run in a game.",
        kSliceUs, kBudgetUs);
    if (g_abSubject) Log("[AsyncPollSpin]   under A/B test");
}

void Shutdown() {
}

void LogStats() {
    if (!Config::g_settings.OptAsyncPollSpin) return;
    if (!g_installed) {
        Log("[AsyncPollSpin] not installed, so nothing here was measured.");
        return;
    }
    for (int i = 0; i < kSites; ++i)
        Log("[AsyncPollSpin]   %-18s %lu spin slice(s), %.0f ms spun, %lu fell back to the real sleep",
            kSiteName[i], g_slices[i], g_spunUsTotal[i] / 1000.0, g_realSleeps[i]);
    Log("[AsyncPollSpin]   reader idle left asleep because no load or main-thread wait was on: %lu. Plain counters, lower bounds. "
        "Whether loads got shorter is in the \"Load took\" lines.", g_declinedIdle);
}

} // namespace AsyncPollSpin
