#include "lua_gc_governor.h"
#include "ab_test.h"
#include "flight_recorder.h"
#include "version.h"
#include "lua_optimize.h"
#include "../diagnostics/sampling_profiler.h"
#include "../core/config.h"
#include <atomic>
#include <emmintrin.h>

extern "C" void Log(const char* fmt, ...);

namespace LuaGCGovernor {

typedef int (__cdecl *lua_gc_fn)(void* L, int what, int data);
static lua_gc_fn g_lua_gc = (lua_gc_fn)0x0084ED50;

// Frames on which a collection was declined because a loading screen was up.
// Counted so the guard can be told apart from a guard that never fires.
static unsigned long g_declinedLoading = 0;

// The A/B subject state, when the harness names this feature.
//
// This is the one default-on feature in the project with a crash dump behind it
// and no measured payoff, and the evidence about the payoff does not agree with
// itself. In the one uncapped session profiled here, with this governor asking
// for nothing, steady-state collection was 0.04% of executing time. The note at
// the head of StepTimed cites 10.96% and 7.90% from one tester profile and 2.24%
// from another with the same settings - and those are suspected vsync-capped,
// where the profiler warns its shares are shares of a spin.
//
// Neither figure settles the feature, because a share of the whole cannot rule
// out the thing it is for: a rare full collection that pauses for seconds while
// the steady state stays negligible. That is a tail, and only a tail measurement
// answers it. Flipping a default that everyone runs on a mean instead is exactly
// the move this project has regretted before, so it gets measured.
//
// Unlike the maths replacements, this one carries state across a phase boundary:
// it stops the automatic collector. An OFF stint therefore has to hand the
// collector back - restart it and put it at the stock 200/200 - and an ON stint
// has to take it again. Both transitions cost a frame, which is what the
// harness's settle window is for.
bool          g_abSubject   = false;
int           g_abLastPhase = -1;   // -1 nothing seen yet, 0 off, 1 on
unsigned long g_abHandbacks = 0;

// A flight-recorder column, so a stall in a dump can be lined up against the
// steps that were asked for on the frames leading into it.
int g_frSlotStep = -1;

typedef int (__cdecl *lua_getfield_fn)(void* L, int idx, const char* k);
static lua_getfield_fn g_lua_getfield = (lua_getfield_fn)0x0084E590;

typedef int (__cdecl *lua_toboolean_fn)(void* L, int idx);
static lua_toboolean_fn g_lua_toboolean = (lua_toboolean_fn)0x0084E0B0;

typedef void (__cdecl *lua_settop_fn)(void* L, int idx);
static lua_settop_fn g_lua_settop = (lua_settop_fn)0x0084DBF0;

static inline bool ReadGlobalBool(void* L, const char* name) {
    if (!L) return false;
    g_lua_getfield(L, -10002, name);
    int val = g_lua_toboolean(L, -1);
    g_lua_settop(L, -2);
    return val != 0;
}

static inline double GetLuaMemoryKB(void* L) {
    if (!L) return 0.0;
    int count = g_lua_gc(L, 3, 0); // LUA_GCCOUNT
    int countb = g_lua_gc(L, 4, 0); // LUA_GCCOUNTB
    return (double)count + (double)countb / 1024.0;
}

bool g_inCombat = false;
bool g_isIdle = false;
bool g_isLoading = false;
static bool g_initialized = false;
static double g_lastMemoryKB = 0.0;

bool Init() {
    g_initialized = true;
    g_frSlotStep = FlightRecorder::RegisterSlot("gcstep");
    g_abSubject = AbTest::IsSubject("LuaGcManual");
    if (g_abSubject) {
        Log("[GCGovernor] under A/B test: during OFF stints the automatic "
            "collector is handed back at the stock 200/200 and nothing here "
            "steps it, during ON stints this governor takes it again. Both "
            "transitions cost a frame, which the harness discards.");
    }
    Log("[GCGovernor] Adaptive GC Governor Initialized");
    // Stated once so a log says what this does without anyone reading the source.
    // Lua 5.1 ships with a pause of 200, meaning a new cycle starts once memory
    // has doubled. Everything below is more eager than that, which trades total
    // collector work for a smaller and steadier heap - a reasonable trade on a
    // 32-bit client, and one nobody has ever measured either way.
    Log("[GCGovernor] pause/stepmul: loading 160/150, combat 100/110, "
        "idle 110/400, otherwise 120/200 (stock Lua is 200/200)");
    return true;
}

void Shutdown() {
    g_initialized = false;
}

// Timing the collector.
//
// A tester profile put Lua's mark phase at 10.96%% of main-thread execution and
// its sweep at 7.90%% - the largest single cost inside the client. Another
// session with the same settings put the mark phase at 2.24%%. So the workload
// decides, not the configuration, and any claim about whether this governor
// helps or hurts is unfounded until the steps it asks for are timed.
//
// This times only the steps this module requests. Collection the VM starts on
// its own is not counted here; the sampling profiler covers that.
static double   g_gcStepMsTotal = 0.0;
static uint64_t g_gcStepCount   = 0;
static LARGE_INTEGER g_qpcFreq  = {};

static inline void StepTimed(void* L, int kb) {
    if (g_qpcFreq.QuadPart == 0) QueryPerformanceFrequency(&g_qpcFreq);
    FlightRecorder::Bump(g_frSlotStep);

    LARGE_INTEGER a, b;
    QueryPerformanceCounter(&a);
    g_lua_gc(L, 5, kb);          // LUA_GCSTEP
    QueryPerformanceCounter(&b);

    if (g_qpcFreq.QuadPart > 0) {
        g_gcStepMsTotal += (double)(b.QuadPart - a.QuadPart) * 1000.0
                         / (double)g_qpcFreq.QuadPart;
        g_gcStepCount++;
    }
}

// The client's own collector, which is what the pause setting below actually
// moves. luaC_traversetable is 0x0085A960 and 432 bytes long, luaC_sweeplist is
// 0x0085B200 and 143; both from the profiler's symbol table.
constexpr uintptr_t kTraverseLo = 0x0085A960, kTraverseHi = 0x0085A960 + 432;
constexpr uintptr_t kSweepLo    = 0x0085B200, kSweepHi    = 0x0085B200 + 143;

void LogStats() {
    if (g_gcStepCount == 0) {
        Log("[GCGovernor] no collection steps requested this session%s",
            Config::g_settings.OptLuaGcManual
                ? "" : " - LuaGcManual is off, which is what stops them");
    } else {
        Log("[GCGovernor] %llu steps requested, %.1f ms total, %.3f ms average",
            (unsigned long long)g_gcStepCount, g_gcStepMsTotal,
            g_gcStepMsTotal / (double)g_gcStepCount);
    }

    // Printed whether or not any step ran, because "the guard never fired" and
    // "the guard was never reached" are different facts and the second one is
    // what a session with stepping switched off produces.
    if (g_declinedLoading) {
        Log("[GCGovernor] %lu frame(s) declined because a loading screen was up. "
            "The client builds large tables then, every other cache here bypasses "
            "during it, and this one did not until now.",
            g_declinedLoading);
    } else {
        Log("[GCGovernor] no frame was declined for a loading screen - either none "
            "came up while a step was wanted, or the window is narrower than it "
            "looked");
    }

    if (g_abSubject) {
        Log("[GCGovernor] A/B: the collector was handed back to the client %lu "
            "time(s). What is known going in: in the one uncapped session "
            "profiled here, with this governor asking for nothing, steady-state "
            "collection was 0.04%% of executing time. Other sessions put the mark "
            "phase at 2.24%% and 10.96%%, and those are suspected to be "
            "vsync-capped, where the profiler's shares are shares of a spin. "
            "Either way a rare full collection can pause for seconds while the "
            "steady state stays negligible, and the pause is what this feature "
            "exists for - so read p95 and p99 below, not the mean.",
            g_abHandbacks);
    }

    // Those numbers are this module's own work and nothing else. Lowering the
    // pause below the stock 200 makes the client start a new collection cycle
    // sooner, and all of that work is the client's, in its own functions, where
    // nothing here counts it. A pause of 100 means a new cycle begins as soon
    // as the previous one ends.
    //
    // So the two functions that do the work are measured directly and printed
    // beside the steps. This is the number that says whether the trade is
    // worth making, and until now no log contained it.
    double tp = 0.0, sp = 0.0;
    unsigned long ts = 0, ss = 0, win = 0;
    bool haveT = SamplingProfiler::ShareForRange(kTraverseLo, kTraverseHi, 20000, &tp, &ts, &win);
    bool haveS = SamplingProfiler::ShareForRange(kSweepLo,    kSweepHi,    20000, &sp, &ss, &win);

    if (!haveT || !haveS) {
        Log("[GCGovernor]   what this costs the client is not measured: the "
            "sampling profiler is off or has too few samples yet. Turn on "
            "SamplingProfiler to see it.");
        return;
    }
    Log("[GCGovernor]   the client's own collector, over the last %lu profiler "
        "samples: luaC_traversetable %.2f%% (%lu), luaC_sweeplist %.2f%% (%lu), "
        "%.2f%% together. That is the cost of the pause set here, and it is not "
        "in the step figures above.",
        win, tp, ts, sp, ss, tp + sp);
}

// Where this is allowed to collect from, and what that rules out.
//
// The one tester crash with this DLL genuinely in the call stack (nobus1.dmp,
// 2026-08-05) went Hooked_EngineFrameLimit -> MainThreadPump -> OnFrame ->
// StepTimed -> lua_gc -> the client's traversetable, reading [EAX+9] with EAX
// zero. A null table where the collector expects one is what a half-built or
// mid-resize table looks like, so the standing theory was that the frame-limiter
// hook is not a safe point to collect from.
//
// It is one. sub_6836D0, the function that hook sits on, has three callers -
// sub_69E220, sub_6A3450 and sub_6A7610 - and all three call it immediately
// after presenting the frame: in sub_6A3450 the call is four instructions past
// the device's own present through the vtable at +68. The client is not inside
// Lua at that point, so a GC step there cannot catch the VM mid-operation, and
// that theory is finished.
//
// What it does not rule out is a table left inconsistent earlier in the frame by
// something else - the collector only has to walk it. So the suspicion moves off
// the collection point and onto whatever wrote the table, and the crash stays
// open.
//
// The one window this did not cover is a loading screen. The client builds large
// tables while one is up, every other cache in this project bypasses during it,
// and this did not - it checked only the two transient reload flags. Declines are
// counted rather than silent, so a session can say whether the window was ever
// entered at all.
void OnFrame(double frameMs) {
    if (!g_initialized) return;
    if (LuaOpt::IsReloading() || LuaOpt::IsSwapping()) return;
    if (LuaOpt::IsLoadingMode()) { g_declinedLoading++; return; }

    void* L = *(void**)0x00D3F78C;
    if (!L) return;

    // The A/B phase, when the harness names this feature. Handing the collector
    // back is not optional on the way out: this governor stops it, and a stint
    // that merely skipped stepping would leave the VM with no collector running
    // at all, which measures something nobody wants.
    if (g_abSubject) {
        const int phase = AbTest::FeatureOn() ? 1 : 0;
        if (phase != g_abLastPhase) {
            g_abLastPhase = phase;
            if (phase == 0) {
                g_lua_gc(L, 1, 0);            // LUA_GCRESTART
                g_lua_gc(L, 6, 200);          // LUA_GCSETPAUSE
                g_lua_gc(L, 7, 200);          // LUA_GCSETSTEPMUL
                g_abHandbacks++;
            }
            g_lastMemoryKB = GetLuaMemoryKB(L);
        }
        if (phase == 0) return;
    }

    // The control case. Stock Lua is 200/200 and no manual stepping at all, so
    // one session with this on and one with it off is the whole experiment.
    // Re-applied whenever the state changes rather than once, because a reload
    // brings a new collector with the stock values already in it and this has
    // to survive being right by accident.
    if (Config::g_settings.OptLuaGcStockPace) {
        static void* s_lastL = nullptr;
        if (L != s_lastL) {
            s_lastL = L;
            g_lua_gc(L, 1, 0);          // LUA_GCRESTART
            g_lua_gc(L, 6, 200);        // LUA_GCSETPAUSE
            g_lua_gc(L, 7, 200);        // LUA_GCSETSTEPMUL
            Log("[GCGovernor] LuaGcStockPace is on: the collector is left at "
                "200/200 and nothing here steps it. This is the control run.");
        }
        return;
    }

    double memKB = GetLuaMemoryKB(L);
    double diffKB = memKB - g_lastMemoryKB;
    if (diffKB < 0.0) diffKB = 0.0;
    g_lastMemoryKB = memKB;

#define LUA_GCSETPAUSE   6
#define LUA_GCSETSTEPMUL 7

    if (g_isLoading) {
        // Relax GC during loading screen to accelerate addon instantiation without freezing VM
        g_lua_gc(L, LUA_GCSETPAUSE, 160);
        g_lua_gc(L, LUA_GCSETSTEPMUL, 150);
        return;
    }

    // LuaGcManual is the launcher's "Lua VM: stop the automatic GC", described
    // there as "split out because it is the part worth testing on its own". It
    // was split in the launcher and in the config and never wired here, so
    // until now it gated nothing and the checkbox offered an experiment that
    // could not be run. Everything the entry describes - stopping the VM's
    // collector and stepping it by hand - hangs off it now. The pause and
    // stepmul pacing stays under LuaGcCoalesce, which is what that entry
    // describes.
    const bool manual = Config::g_settings.OptLuaGcManual;

    if (g_inCombat) {
        if (memKB < 256.0 * 1024.0) {
            if (manual) g_lua_gc(L, 0, 0); // LUA_GCSTOP
        } else {
            g_lua_gc(L, 1, 0); // Ensure restarted
            g_lua_gc(L, LUA_GCSETPAUSE, 100);
            g_lua_gc(L, LUA_GCSETSTEPMUL, 110);
            if (manual) StepTimed(L, 16);
        }
        return;
    }

    g_lua_gc(L, 1, 0); // Ensure restarted

    if (g_isIdle && frameMs < 8.0) {
        g_lua_gc(L, LUA_GCSETPAUSE, 110);
        g_lua_gc(L, LUA_GCSETSTEPMUL, 400);
        if (manual) StepTimed(L, 1024);
    } else {
        g_lua_gc(L, LUA_GCSETPAUSE, 120);
        g_lua_gc(L, LUA_GCSETSTEPMUL, 200);
        
        int stepKB = (int)(diffKB * 1.5);
        if (stepKB < 62) stepKB = 62;
        if (stepKB > 512) stepKB = 512;
        
        if (manual) StepTimed(L, stepKB);
    }
}

} // namespace LuaGCGovernor
