// ============================================================================
// Module: m2_parallel_roots
//
// The client already animates an M2 scene's root models on two threads. In the
// scene advance, sub_821A20, when the scene's option flags carry bit 4 - the
// M2UseThreads setting, "multithread model animations", default 1 - it does:
//
//     sub_81BFA0(mgr, sub_81CE70, scene)   hand sub_81CE70 to the M2 worker thread
//     for each root at an even position     sub_82F0F0 / sub_82E140 on this thread
//     sub_81BFD0(mgr)                        wait for the worker
//
// and sub_81CE70 animates the roots at the odd positions. A root is a model with
// no parent ([model+48h] == 0); attached models are animated from their root's
// own tail and are never in this loop. So Blizzard already relies on two roots
// animating at once being safe. Read from the disassembly to depth eight, both
// animate entries (sub_82F0F0, sub_82E140) reach 29 functions with no indirect
// call, no allocation, no call into the system and no write to a global except a
// one-time constant initialiser; the material pass writes the instance's own
// array at +2C0h, and nothing in the tree demands another model's animation.
//
// This splits the same pass across more threads. In the active mode the dispatch
// does not wake the client's worker. The main thread runs sub_81CE70 itself and
// both it and the main loop only record the roots; the wait then runs every
// recorded root on a pool of our threads plus the main thread, and returns. Each
// worker takes the main thread's x87 control word and MXCSR first, so every
// result is computed the way the client's own threads would.
//
// The six call sites patched, each a five-byte call whose target is checked:
//   0x00821ADB  sub_81BFA0   dispatch
//   0x00821B21  sub_82E140   main loop, root animate (flag 1000h)
//   0x00821B4E  sub_82F0F0   main loop, root animate
//   0x00821B64  sub_81BFD0   wait
//   0x0081CECF  sub_82E140   worker callback, root animate (flag 1000h)
//   0x0081CEFA  sub_82F0F0   worker callback, root animate
// Each replacement passes straight through to the original whenever this module
// is not active for the pass, so the client's two-thread mode runs unchanged.
//
// What this does not have: a phase that compares results against the client. A
// root cannot be animated twice - the bone loop advances a clock at +4Ch - so
// the correctness case rests on the analysis above and on the client already
// running roots concurrently. A fault on a worker retires the module for the
// session.
//
// What it has instead is a comparison of time, on the machine it runs on. One
// pass in kProbeEvery is left to the client's own two-thread way, and the main
// thread's time per root over those passes is set against its time per root
// over the parallel passes. A field session on a 16-thread machine measured
// 0.65 of the client's time per pass; nothing below that was measured, and a
// machine with few cores or a busy one can lose the difference to worker
// wake-up and the spin on the wait. If ours is the slower of the two once each
// side has kProbeEnough passes, the module retires itself for the session and
// says so.
//
// Not with M2UseThreads 0: that path (the second loop in sub_821A20) is untouched.
// Not with AnimLod, M2AnimStride, M2AnimReuse, AnimCensus or AnimTrackCensus on:
// each keeps tables that are not built for more than the client's two threads.
// ============================================================================
#include "m2_parallel_roots.h"
#include <windows.h>
#include <intrin.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>
#include "config.h"
#include "MinHook.h"
#include "version.h"
#include "ab_test.h"

extern "C" void Log(const char* fmt, ...);

namespace M2ParallelRoots {
namespace {

constexpr uintptr_t kDispatchFn = 0x0081BFA0;
constexpr uintptr_t kWaitFn     = 0x0081BFD0;
constexpr uintptr_t kWorkerCb   = 0x0081CE70;
constexpr uintptr_t kAnimate    = 0x0082F0F0;
constexpr uintptr_t kAnimateAlt = 0x0082E140;

constexpr uintptr_t kSiteDispatch  = 0x00821ADB;
constexpr uintptr_t kSiteMainAlt   = 0x00821B21;
constexpr uintptr_t kSiteMain      = 0x00821B4E;
constexpr uintptr_t kSiteWait      = 0x00821B64;
constexpr uintptr_t kSiteWorkerAlt = 0x0081CECF;
constexpr uintptr_t kSiteWorker    = 0x0081CEFA;

constexpr int  kMaxRoots      = 4096;
constexpr int  kMaxWorkers    = 15;
constexpr int  kMinParallel   = 8;      // fewer roots than this run on the main thread alone
constexpr long kSerialPasses  = 300;    // the client's own way first, so lazy statics are set
constexpr unsigned kProbeEvery = 16;    // once engaged, one pass in this many is the client's way
constexpr unsigned long kProbeEnough = 300;  // passes of each kind, of >= kMinParallel roots, before judging

// ECX = model, then five stack arguments, callee cleans: reached as __fastcall
// with a dummy EDX, as elsewhere in this tree.
typedef int (__fastcall* Animate_fn)(void* model, void* edx, void* root, const float* ones,
                                     const float* zeros, float f1, float f2);
typedef int (__fastcall* Dispatch_fn)(void* mgr, void* edx, void* cb, void* arg);
typedef DWORD (__fastcall* Wait_fn)(void* mgr, void* edx);
typedef int (__cdecl* WorkerCb_fn)(void* scene);

struct Root {
    void* model;
    void* root;
    float ones[3];
    float zeros[3];
    float f1, f2;
    int   alt;
};

struct WorkerRange {
    int begin;
    int end;
};

Root          g_roots[kMaxRoots];
WorkerRange   g_ranges[kMaxWorkers];
volatile LONG g_count = 0;
volatile LONG g_active = 0;
volatile LONG g_deferring = 0;
DWORD         g_deferTid = 0;
bool          g_installed = false;
volatile LONG g_retired = 0;
bool          g_abSubject = false;

int           g_workers = 0;
HANDLE        g_wake[kMaxWorkers] = {};
HANDLE        g_threads[kMaxWorkers] = {};
unsigned short g_fpuCw = 0;
unsigned int  g_mxcsr = 0;

// Counters, main thread only (plain, lower bounds).
unsigned long g_waits = 0;           // waits seen, either way
unsigned long g_parallelPasses = 0;
unsigned long g_soloPasses = 0;      // active but under kMinParallel roots
unsigned long g_clientPasses = 0;
unsigned long g_overflow = 0;
uint64_t      g_rootsRun = 0;
LONGLONG      g_ourTicks = 0, g_clientTicks = 0;
LONGLONG      g_passStart = 0;
// The self-measurement. g_probing is set for a pass left to the client; the
// roots it animates are counted from both of its threads.
volatile LONG g_probing = 0;
volatile LONG g_passRoots = 0;
unsigned long g_probePasses = 0, g_parTimed = 0;
uint64_t      g_probeRoots = 0, g_parRoots = 0;
LONGLONG      g_probeTicks = 0, g_parTicks = 0;
volatile LONG g_retiredSlower = 0;
volatile LONG g_faults = 0;
volatile uintptr_t g_faultModel = 0;
// For the per-interval figures.
unsigned long g_prevParallel = 0, g_prevSolo = 0, g_prevClient = 0;
uint64_t      g_prevRoots = 0;
LONGLONG      g_prevOurTicks = 0, g_prevClientTicks = 0;
LARGE_INTEGER g_freq;

inline bool OnDeferringThread() { return __readfsdword(0x24) == g_deferTid; }

inline LONGLONG Now() { LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart; }

// Runs a contiguous slice of roots without atomic contention or per-model SEH overhead.
void RunSlice(int begin, int end) {
    for (int i = begin; i < end; ++i) {
        const Root& r = g_roots[i];
        const Animate_fn fn = (Animate_fn)(r.alt ? kAnimateAlt : kAnimate);
        fn(r.model, nullptr, r.root, r.ones, r.zeros, r.f1, r.f2);
    }
}

DWORD WINAPI WorkerMain(LPVOID p) {
    const int idx = (int)(intptr_t)p;
    for (;;) {
        WaitForSingleObject(g_wake[idx], INFINITE);
        // The client's arithmetic on this thread must round the way it does on the
        // main thread: same precision control, same SSE state.
        unsigned short cw = g_fpuCw;
        __asm fldcw cw
        _mm_setcsr(g_mxcsr);
        __try {
            RunSlice(g_ranges[idx].begin, g_ranges[idx].end);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            InterlockedIncrement(&g_faults);
            InterlockedExchange(&g_retired, 1);
        }
        InterlockedDecrement(&g_active);
    }
}

bool StartWorkers(int n) {
    for (int i = 0; i < n; ++i) {
        g_wake[i] = CreateEventA(nullptr, FALSE, FALSE, nullptr);
        if (!g_wake[i]) return false;
        g_threads[i] = CreateThread(nullptr, 256 * 1024, WorkerMain, (LPVOID)(intptr_t)i,
                                    STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
        if (!g_threads[i]) return false;
        SetThreadPriority(g_threads[i], THREAD_PRIORITY_ABOVE_NORMAL);
        g_workers = i + 1;
    }
    return true;
}

// ---- the call-site replacements -------------------------------------------------

void Record(void* model, void* root, const float* ones, const float* zeros, float f1, float f2, int alt) {
    const LONG i = g_count;
    if (i >= kMaxRoots) {
        // No room: this one runs now, on this thread, as the client would have.
        ++g_overflow;
        const Animate_fn fn = (Animate_fn)(alt ? kAnimateAlt : kAnimate);
        fn(model, nullptr, root, ones, zeros, f1, f2);
        return;
    }
    Root& r = g_roots[i];
    r.model = model; r.root = root;
    r.ones[0] = ones[0]; r.ones[1] = ones[1]; r.ones[2] = ones[2];
    r.zeros[0] = zeros[0]; r.zeros[1] = zeros[1]; r.zeros[2] = zeros[2];
    r.f1 = f1; r.f2 = f2; r.alt = alt;
    g_count = i + 1;
}

int __fastcall Site_Animate(void* model, void* edx, void* root, const float* ones,
                            const float* zeros, float f1, float f2) {
    if (g_deferring && OnDeferringThread()) { Record(model, root, ones, zeros, f1, f2, 0); return 0; }
    if (g_probing) InterlockedIncrement(&g_passRoots);
    return ((Animate_fn)kAnimate)(model, edx, root, ones, zeros, f1, f2);
}

int __fastcall Site_AnimateAlt(void* model, void* edx, void* root, const float* ones,
                               const float* zeros, float f1, float f2) {
    if (g_deferring && OnDeferringThread()) { Record(model, root, ones, zeros, f1, f2, 1); return 0; }
    if (g_probing) InterlockedIncrement(&g_passRoots);
    return ((Animate_fn)kAnimateAlt)(model, edx, root, ones, zeros, f1, f2);
}

int __fastcall Site_Dispatch(void* mgr, void* edx, void* cb, void* arg) {
    g_passStart = Now();
    bool engage = g_installed && !g_retired && cb == (void*)kWorkerCb && g_waits >= (unsigned long)kSerialPasses;
    if (engage && g_abSubject && AbTest::StandAside()) engage = false;
    if (engage && (g_waits % kProbeEvery) == 0) {
        // Left to the client, to have something to set our time against.
        g_passRoots = 0;
        g_probing = 1;
        engage = false;
    }
    if (!engage) return ((Dispatch_fn)kDispatchFn)(mgr, edx, cb, arg);

    // Active: the client's worker is not woken. Its share is recorded here, the
    // main loop records the rest, and the wait runs them all.
    g_count = 0;
    g_deferTid = __readfsdword(0x24);
    g_deferring = 1;
    ((WorkerCb_fn)kWorkerCb)(arg);
    return 0;
}

// Called on the main thread after a probe pass. Retires the module when its
// time per root, over passes of the same size class, is the larger of the two.
void Judge() {
    if (g_retired || g_probePasses < kProbeEnough || g_parTimed < kProbeEnough) return;
    const double ours = (double)g_parTicks / (double)g_parRoots;
    const double theirs = (double)g_probeTicks / (double)g_probeRoots;
    if (ours <= theirs) return;
    InterlockedExchange(&g_retiredSlower, 1);
    InterlockedExchange(&g_retired, 1);
    const double toUs = 1000000.0 / (double)g_freq.QuadPart;
    Log("[M2ParallelRoots] RETIRED: on this machine the main thread spends %.2f us a root animating them our way "
        "(%lu passes of %.1f roots) against %.2f us the client's own two-thread way (%lu passes of %.1f roots). "
        "The client's own path runs from here.",
        ours * toUs, g_parTimed, (double)g_parRoots / (double)g_parTimed,
        theirs * toUs, g_probePasses, (double)g_probeRoots / (double)g_probePasses);
}

DWORD __fastcall Site_Wait(void* mgr, void* edx) {
    ++g_waits;
    if (!g_deferring) {
        const DWORD r = ((Wait_fn)kWaitFn)(mgr, edx);
        const LONGLONG took = Now() - g_passStart;
        g_clientTicks += took;
        ++g_clientPasses;
        if (g_probing) {
            g_probing = 0;
            const LONG roots = g_passRoots;
            if (roots >= kMinParallel) {
                ++g_probePasses;
                g_probeRoots += (uint64_t)roots;
                g_probeTicks += took;
                Judge();
            }
        }
        return r;
    }
    g_deferring = 0;
    const LONG n = g_count;
    bool parallel = false;
    if (n >= kMinParallel && g_workers > 0) {
        unsigned short cw;
        __asm fnstcw cw
        g_fpuCw = cw;
        g_mxcsr = _mm_getcsr();

        // Contiguous range partition across workers and main thread.
        // Cap total threads at n so no thread gets an empty range.
        int totalThreads = g_workers + 1;
        if (totalThreads > (int)n) totalThreads = (int)n;
        const int workersToUse = totalThreads - 1;

        const int base = (int)n / totalThreads;
        const int rem = (int)n % totalThreads;
        int cur = 0;
        for (int i = 0; i < workersToUse; ++i) {
            const int count = base + (i < rem ? 1 : 0);
            g_ranges[i].begin = cur;
            g_ranges[i].end = cur + count;
            cur += count;
        }
        const int mainBegin = cur;
        const int mainEnd = (int)n;

        g_active = workersToUse;
        for (int i = 0; i < workersToUse; ++i) SetEvent(g_wake[i]);

        RunSlice(mainBegin, mainEnd);

        unsigned spins = 0;
        while (g_active > 0) {
            if (++spins < 4000) YieldProcessor(); else SwitchToThread();
        }
        ++g_parallelPasses;
        parallel = true;
    } else {
        RunSlice(0, (int)n);
        ++g_soloPasses;
    }
    g_rootsRun += (uint64_t)n;
    const LONGLONG took = Now() - g_passStart;
    g_ourTicks += took;
    if (parallel) {
        ++g_parTimed;
        g_parRoots += (uint64_t)n;
        g_parTicks += took;
    }
    return 0;
}

// ---- installing -------------------------------------------------------------------

struct Site { uintptr_t at; uintptr_t want; const void* repl; const char* name; };

bool CallTargets(uintptr_t at, uintptr_t want) {
    const uint8_t* p = (const uint8_t*)at;
    if (p[0] != 0xE8) return false;
    const uintptr_t target = at + 5 + *(const int32_t*)(p + 1);
    return target == want;
}

bool WriteCall(uintptr_t at, const void* to) {
    DWORD old = 0;
    if (!VirtualProtect((void*)at, 5, PAGE_EXECUTE_READWRITE, &old)) return false;
    *(int32_t*)(at + 1) = (int32_t)((uintptr_t)to - (at + 5));
    DWORD ignored = 0;
    VirtualProtect((void*)at, 5, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), (void*)at, 5);
    return true;
}

}  // namespace

void Init() {
    if (!Config::g_settings.OptM2ParallelRoots) return;
    QueryPerformanceFrequency(&g_freq);

    if (RunningUnderTranslation()) {
        Log("[M2ParallelRoots] NOT active: worker threads stay off under a translation layer.");
        return;
    }
    if (Config::g_settings.OptAnimLod || Config::g_settings.OptM2AnimStride || Config::g_settings.OptM2AnimReuse ||
        Config::g_settings.OptAnimCensus || Config::g_settings.OptAnimTrackCensus) {
        Log("[M2ParallelRoots] NOT active: AnimLod, M2AnimStride, M2AnimReuse, AnimCensus or AnimTrackCensus is on, "
            "and each keeps per-model tables that are not built for more threads than the client's two.");
        return;
    }
    const Site sites[] = {
        { kSiteDispatch,  kDispatchFn, (const void*)&Site_Dispatch,   "dispatch" },
        { kSiteMainAlt,   kAnimateAlt, (const void*)&Site_AnimateAlt, "main loop (1000h)" },
        { kSiteMain,      kAnimate,    (const void*)&Site_Animate,    "main loop" },
        { kSiteWait,      kWaitFn,     (const void*)&Site_Wait,       "wait" },
        { kSiteWorkerAlt, kAnimateAlt, (const void*)&Site_AnimateAlt, "worker callback (1000h)" },
        { kSiteWorker,    kAnimate,    (const void*)&Site_Animate,    "worker callback" },
    };
    for (const Site& s : sites) {
        if (!CallTargets(s.at, s.want)) {
            char found[64] = {};
            WowOpt_HexBytes(s.at, found, sizeof(found));
            Log("[M2ParallelRoots] NOT patched: the %s call at 0x%08X is not a call to 0x%08X (%s). Another module or "
                "the client itself changed it.", s.name, (unsigned)s.at, (unsigned)s.want, found);
            return;
        }
        if (!WowOpt_ClientPatchAllowed((const void*)s.at)) {
            Log("[M2ParallelRoots] NOT patched: No Client Patches is on.");
            return;
        }
    }
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int want = (int)si.dwNumberOfProcessors > 2 ? (int)si.dwNumberOfProcessors - 2 : 1;
    if (want > kMaxWorkers) want = kMaxWorkers;
    if (want < 1) {
        Log("[M2ParallelRoots] NOT active: one logical CPU, so there is no second thread to give the work to.");
        return;
    }
    if (!StartWorkers(want)) {
        Log("[M2ParallelRoots] NOT active: the worker threads could not be started (%d of %d).", g_workers, want);
        return;
    }
    for (const Site& s : sites) {
        if (!WriteCall(s.at, s.repl)) {
            Log("[M2ParallelRoots] NOT active: 0x%08X could not be made writable.", (unsigned)s.at);
            return;
        }
        WowOpt_RecordHookOwner(s.at, s.repl);
    }
    g_installed = true;
    g_abSubject = AbTest::IsSubject("M2ParallelRoots", &g_abSubject);
    Log("[M2ParallelRoots] ACTIVE: the root models of a scene are animated on %d thread(s) of ours plus the main thread "
        "instead of the client's two, after the first %ld passes the client's own way. Only with M2UseThreads 1. No "
        "comparison of results is possible here (a root cannot be animated twice); a fault on a worker retires it. "
        "One pass in %u is left to the client and the main thread's time per root is compared with ours; if ours is "
        "the slower after %lu passes of each, it retires itself. Field result so far: one 16-thread machine, 3 h on "
        "two clients, 0.65 of the client's time per pass, no fault.",
        g_workers, kSerialPasses, kProbeEvery, kProbeEnough);
}

void LogStats() {
    if (!Config::g_settings.OptM2ParallelRoots) return;
    if (!g_installed) { Log("[M2ParallelRoots] not measured: not installed (the reason is logged at start)."); return; }
    if (g_waits == 0) {
        Log("[M2ParallelRoots] no scene pass reached the threaded path, so nothing ran and nothing was measured: "
            "M2UseThreads is probably 0, or no M2 scene was drawn yet.");
        return;
    }
    const double toMs = 1000.0 / (double)g_freq.QuadPart;
    const unsigned long ourPasses = g_parallelPasses + g_soloPasses;
    const unsigned long iOur = ourPasses - (g_prevParallel + g_prevSolo);
    const unsigned long iClient = g_clientPasses - g_prevClient;
    const uint64_t iRoots = g_rootsRun - g_prevRoots;
    const LONGLONG iOurT = g_ourTicks - g_prevOurTicks, iClientT = g_clientTicks - g_prevClientTicks;
    Log("[M2ParallelRoots] %s. Since the last report: %lu pass(es) ours (%lu parallel, %lu under %d roots on the main "
        "thread), %.3f ms each on the main thread with %.1f roots on average; %lu the client's own two-thread way, "
        "%.3f ms each. Session: %lu ours, %lu the client's. Plain counters, lower bounds.",
        g_retiredSlower ? "RETIRED: slower than the client's way on this machine"
                        : (g_retired ? "RETIRED: a worker faulted" : "running"),
        iOur, g_parallelPasses - g_prevParallel, g_soloPasses - g_prevSolo, kMinParallel,
        iOur ? (double)iOurT * toMs / (double)iOur : 0.0, iOur ? (double)iRoots / (double)iOur : 0.0,
        iClient, iClient ? (double)iClientT * toMs / (double)iClient : 0.0,
        ourPasses, g_clientPasses);
    if (g_faults)
        Log("[M2ParallelRoots]   %ld worker fault(s), the last animating model %p; the module has used the client's own "
            "path since the first.", (long)g_faults, (void*)g_faultModel);
    if (g_overflow)
        Log("[M2ParallelRoots]   %lu root(s) did not fit the %d-entry table and ran at once on the main thread.",
            g_overflow, kMaxRoots);
    if (g_probePasses && g_parTimed) {
        const double toUs = 1000000.0 / (double)g_freq.QuadPart;
        Log("[M2ParallelRoots]   self-measurement, session: %.2f us a root ours over %lu parallel passes against "
            "%.2f us a root the client's way over %lu probe passes%s. Plain counters, lower bounds.",
            (double)g_parTicks * toUs / (double)g_parRoots, g_parTimed,
            (double)g_probeTicks * toUs / (double)g_probeRoots, g_probePasses,
            (g_probePasses < kProbeEnough || g_parTimed < kProbeEnough) ? " (not yet enough of either to judge)" : "");
    } else {
        Log("[M2ParallelRoots]   self-measurement: not measured yet (%lu probe pass(es), %lu timed parallel pass(es) "
            "of %d or more roots).", g_probePasses, g_parTimed, kMinParallel);
    }
    g_prevParallel = g_parallelPasses; g_prevSolo = g_soloPasses; g_prevClient = g_clientPasses;
    g_prevRoots = g_rootsRun; g_prevOurTicks = g_ourTicks; g_prevClientTicks = g_clientTicks;
}

}  // namespace M2ParallelRoots
