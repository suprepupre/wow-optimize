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
// function, this declines. Under Wine and Rosetta it does not install.
//
// Whether it pays is measured inside the loading screen it runs in, and decides
// whether it keeps running. Nothing above was ever seen in a game, so a switch
// that says "faster" would be a claim. While a loading screen is up the hook
// alternates between two modes in windows of about sixty milliseconds: the
// client's own sleep, and the spin. Each window counts the reads the client
// completes in it (the counter LoadingState keeps for the load), and a mode's
// rate is reads per millisecond over all its windows. Both modes see the same
// load, minutes of it interleaved, so a load that is read-heavy at the start and
// Lua-heavy at the end affects both the same way.
//
//   learning   alternate the windows. Once each mode has two seconds of windows
//              and four hundred reads, spin is kept if it completed reads at
//              1.15 times the rate of the sleep or better and dropped for the
//              session if it did not reach the sleep's rate. In between the
//              comparison goes on, and at twenty seconds of windows each it is
//              settled at 1.05.
//   armed      spin is the mode, except that one window in eight is the client's
//              sleep so the comparison keeps being made. If spin falls below
//              0.95 of the sleep's rate over everything measured, it is dropped.
//   retired    the client's sleep, always.
//
// Outside a loading screen nothing is measured: the hook spins when armed and
// otherwise leaves the client's sleep alone. The first world entry of a session
// has no PLAYER_LEAVING_WORLD before it, so it is never inside a loading screen
// as far as LoadingState can tell, and it runs on the client's sleeps until a
// later load has armed the spin.
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
// What moves when the reader makes progress, so that a budget spent on one wait is not held against
// the next one. dword_B4A1F8 is the remaining count the loading pump turns into its progress bar:
// sub_4B9B20 decrements it once per completion callback. dword_B4A204 is the request
// AsyncFileReadWait is waiting for. off_AC3470 is the tail of the completed list, which the reader
// rewrites each time it moves a finished request onto it.
constexpr uintptr_t kRemaining     = 0x00B4A1F8;
constexpr uintptr_t kAwaited       = 0x00B4A204;
constexpr uintptr_t kDoneTail      = 0x00AC3470;

constexpr double kSliceUs   = 80.0;      // one spin, then the caller looks again
constexpr double kBudgetUs  = 1500.0;    // consecutive spinning per episode before the real sleep
constexpr double kGapUs     = 3000.0;    // a call this long after the last one starts a new episode

typedef void (__cdecl *OsSleep_fn)(DWORD ms);
OsSleep_fn g_orig = nullptr;
bool g_installed = false;
bool g_abSubject = false;
double g_freq = 0.0;                     // QPC ticks per microsecond

// ---- does spinning pay ----------------------------------------------------
enum State { kLearning = 0, kArmed = 1, kRetired = 2 };
enum Mode { kModeSleep = 0, kModeSpin = 1 };
constexpr double kWindowMs        = 60.0;     // one window of one mode
constexpr double kMinWindowMs     = 2000.0;   // per mode, before a first verdict
constexpr unsigned long kMinReads = 400;      // per mode, before a first verdict
constexpr double kArmRatio        = 1.15;
constexpr double kKeepRatio       = 0.95;     // below this, an armed spin is dropped
constexpr double kSettleMs        = 20000.0;  // per mode: stop waiting for 1.15
constexpr double kSettleRatio     = 1.05;
constexpr unsigned kArmedSleepEvery = 8;      // one window in this many is the client's sleep

volatile LONG g_state = kLearning;
volatile LONG g_mode  = kModeSleep;           // what the hook does while a load is up
struct Windows { double ms; unsigned long reads; unsigned long count; };
Windows  g_win[2];                            // main thread only
uint64_t g_winStart = 0;
unsigned long g_winReads0 = 0;
int      g_winMode = kModeSleep;
bool     g_winOpen = false;
unsigned g_winSeq = 0;
unsigned long g_winDiscarded = 0;
unsigned long g_flips = 0;

enum Site { kSiteFileWait = 0, kSitePump, kSiteItemWait, kSiteWorker, kSites };
const char* const kSiteName[kSites] = { "AsyncFileReadWait", "loading pump", "item wait", "reader idle" };

struct Episode {
    uint64_t lastTick;
    uint32_t lastToken;
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

inline uint32_t Token(int site) {
    const uint32_t remaining = *(volatile const uint32_t*)kRemaining;
    switch (site) {
    case kSiteFileWait: return *(volatile const uint32_t*)kAwaited ^ (remaining * 2654435761u);
    case kSiteWorker:   return *(volatile const uint32_t*)kDoneTail;
    default:            return remaining;
    }
}

// Calls of the wrapper with 1 from main-thread return addresses that are not one of the four, while
// a loading screen is up. If these dominate, the four are the wrong ones.
struct Stray { uintptr_t ret; unsigned long n; };
constexpr int kStrays = 16;
Stray g_stray[kStrays];
unsigned long g_strayLost = 0;
unsigned long g_strayTotal = 0;

void NoteStray(uintptr_t ret) {
    ++g_strayTotal;
    for (int i = 0; i < kStrays; ++i) {
        if (g_stray[i].ret == ret) { ++g_stray[i].n; return; }
        if (g_stray[i].ret == 0) { g_stray[i].ret = ret; g_stray[i].n = 1; return; }
    }
    ++g_strayLost;
}

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

double RateOf(const Windows& w) { return w.ms > 0.0 ? (double)w.reads / w.ms : 0.0; }

void Retire(const char* why, double ratio) {
    InterlockedExchange(&g_state, kRetired);
    InterlockedExchange(&g_mode, kModeSleep);
    Log("[AsyncPollSpin] RETIRED for this session: %s. Inside loading screens the spin completed %.0f reads in %.0f ms "
        "(%.3f per ms) against %.0f in %.0f ms (%.3f per ms) for the client's sleep, a ratio of %.2f.",
        why, (double)g_win[kModeSpin].reads, g_win[kModeSpin].ms, RateOf(g_win[kModeSpin]),
        (double)g_win[kModeSleep].reads, g_win[kModeSleep].ms, RateOf(g_win[kModeSleep]), ratio);
}

// Called on the main thread from the three main-thread sites. Keeps the window
// bookkeeping while a loading screen is up and sets g_mode, which the worker
// site reads.
void UpdateMode() {
    const LONG state = g_state;
    if (state == kRetired) { g_mode = kModeSleep; return; }
    if (!LoadingState::IsLoading()) {
        g_winOpen = false;
        g_mode = (state == kArmed) ? kModeSpin : kModeSleep;
        return;
    }
    const uint64_t now = Now();
    const unsigned long reads = LoadingState::ReadsThisLoad();
    if (g_winOpen) {
        const double ms = (double)(now - g_winStart) / g_freq / 1000.0;
        if (ms < kWindowMs) return;
        // A window that ran far past its length held something other than the
        // loops (a rendered frame, a long Lua call), and one that saw the read
        // counter go backwards crossed into another load. Neither is a measurement.
        if (ms > 3.0 * kWindowMs || reads < g_winReads0) {
            ++g_winDiscarded;
        } else {
            Windows& w = g_win[g_winMode];
            w.ms += ms;
            w.reads += reads - g_winReads0;
            ++w.count;
        }
        g_winOpen = false;

        const double rSpin = RateOf(g_win[kModeSpin]), rSleep = RateOf(g_win[kModeSleep]);
        const bool enough = g_win[kModeSpin].ms >= kMinWindowMs && g_win[kModeSleep].ms >= kMinWindowMs &&
                            g_win[kModeSpin].reads >= kMinReads && g_win[kModeSleep].reads >= kMinReads;
        if (enough && rSleep > 0.0) {
            const double ratio = rSpin / rSleep;
            if (state == kLearning) {
                const bool settled = g_win[kModeSpin].ms >= kSettleMs && g_win[kModeSleep].ms >= kSettleMs;
                if (ratio >= kArmRatio) {
                    InterlockedExchange(&g_state, kArmed);
                    Log("[AsyncPollSpin] ARMED: inside loading screens the spin completed reads at %.3f per ms against %.3f "
                        "for the client's sleep (ratio %.2f over %.0f and %.0f ms of windows). It spins from here, with one "
                        "window in %u left to the client's sleep so the comparison goes on.",
                        rSpin, rSleep, ratio, g_win[kModeSpin].ms, g_win[kModeSleep].ms, kArmedSleepEvery);
                } else if (ratio < 1.0 || (settled && ratio < kSettleRatio)) {
                    Retire(ratio < 1.0 ? "the spin did not complete reads faster than the client's sleep"
                                       : "the spin gained less than five percent", ratio);
                    return;
                }
            } else if (state == kArmed && ratio < kKeepRatio) {
                Retire("the spin fell behind the client's sleep after it was armed", ratio);
                return;
            }
        }
    }
    // Open the next window: alternate while learning, and while armed let one in
    // kArmedSleepEvery be the client's sleep.
    ++g_winSeq;
    int next;
    if (g_state == kArmed) next = (g_winSeq % kArmedSleepEvery == 0) ? kModeSleep : kModeSpin;
    else next = (g_winSeq & 1) ? kModeSpin : kModeSleep;
    if (next != g_winMode) ++g_flips;
    g_winMode = next;
    g_winStart = now;
    g_winReads0 = reads;
    g_winOpen = true;
    g_mode = next;
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
    default:
        if (GetCurrentThreadId() == g_mainThreadId && LoadingState::IsLoading()) NoteStray(ret);
        g_orig(ms);
        return;
    }
    if (g_abSubject && AbTest::StandAside()) { g_orig(ms); return; }

    if (g_state == kRetired) { g_orig(ms); return; }

    if (site == kSiteWorker) {
        // The worker only spins while somebody is waiting on it: a loading screen, or the main
        // thread inside AsyncFileReadWait. In ordinary play it sleeps as the client wrote it.
        // It follows the mode the main thread has set: the client's sleep in a sleep window,
        // and before the spin has been armed anywhere outside a loading screen.
        if ((!LoadingState::IsLoading() && *(volatile int*)kFileWaiting == 0) || g_mode != kModeSpin) {
            ++g_declinedIdle;
            g_orig(ms);
            return;
        }
    } else {
        if (GetCurrentThreadId() != g_mainThreadId) {
            g_orig(ms);
            return;
        }
        UpdateMode();
        if (g_mode != kModeSpin) { g_orig(ms); return; }
    }

    Episode& e = g_ep[site];
    const uint64_t now = Now();
    const uint32_t token = Token(site);
    if (e.lastTick == 0 || (double)(now - e.lastTick) / g_freq > kGapUs || token != e.lastToken) e.spunUs = 0.0;
    e.lastToken = token;
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
    if (RunningUnderTranslation()) {
        Log("[AsyncPollSpin] NOT active: it spins and yields on the thread that polls the file reader, and a translation "
            "layer has blocked the main thread on code like that before.");
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
        "sleeps as before. Timing only; the loops look at the same things, more often. It spins only once loading screens have "
        "shown it completes reads faster than the client's sleep does, and the log says when. Not yet run in a game.",
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
    Log("[AsyncPollSpin]   reader idle left to the client's sleep because no load or main-thread wait was on, or because the "
        "window was a sleep window: %lu. Plain counters, lower bounds. Whether loads got shorter is in the \"Load took\" lines.",
        g_declinedIdle);
    {
        const Windows& sp = g_win[kModeSpin];
        const Windows& sl = g_win[kModeSleep];
        static const char* const kStateName[3] = { "learning", "ARMED", "RETIRED" };
        Log("[AsyncPollSpin]   state: %s. Inside loading screens, spin windows: %lu (%.0f ms, %lu reads, %.3f per ms); the "
            "client's sleep windows: %lu (%.0f ms, %lu reads, %.3f per ms)%s. %lu window(s) discarded as not a measurement, "
            "%lu mode change(s).",
            kStateName[g_state], sp.count, sp.ms, sp.reads, RateOf(sp), sl.count, sl.ms, sl.reads, RateOf(sl),
            (RateOf(sl) > 0.0 && sp.ms > 0.0)
                ? (RateOf(sp) / RateOf(sl) >= 1.0 ? ", spin ahead" : ", spin behind") : ", no ratio yet",
            g_winDiscarded, g_flips);
        if (RateOf(sl) > 0.0 && sp.ms > 0.0)
            Log("[AsyncPollSpin]   ratio of spin to sleep: %.2f. Plain counters on the main thread; the reads are the ones "
                "LoadingState counts inside a loading screen.", RateOf(sp) / RateOf(sl));
    }
    if (g_strayTotal == 0) {
        Log("[AsyncPollSpin]   no main-thread Sleep(1) from any other return address during a loading screen.");
    } else {
        Log("[AsyncPollSpin]   %lu main-thread Sleep(1) call(s) during loading screens came from return addresses that are not "
            "one of the four (%lu not tabulated); the most frequent:", g_strayTotal, g_strayLost);
        bool taken[kStrays] = {};
        for (int shown = 0; shown < 5; ++shown) {
            int best = -1;
            for (int i = 0; i < kStrays; ++i)
                if (!taken[i] && g_stray[i].ret && (best < 0 || g_stray[i].n > g_stray[best].n)) best = i;
            if (best < 0) break;
            taken[best] = true;
            Log("[AsyncPollSpin]     wow!0x%08X  %lu", (unsigned)g_stray[best].ret, g_stray[best].n);
        }
    }
}

} // namespace AsyncPollSpin
