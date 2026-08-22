#pragma once

// ============================================================================
// Module: crash_dumper.h
// ============================================================================









#ifndef CRASH_DUMPER_H
#define CRASH_DUMPER_H

// Feature tracking for crash diagnosis
// Each optimization registers itself so crash dumps show exactly what was active
// The 3.17.0 logs registered exactly 128 - the old cap - so the registry was full
// and possibly already dropping names. Overflow is now logged rather than silent;
// raise this again when that line appears.
#define MAX_TRACKED_FEATURES 192

struct FeatureState {
    const char*  name;        // Feature name (e.g., "AdaptiveGC", "GetStrInline")
    bool         active;      // Currently enabled
    bool         counted;     // Something calls FeatureHit for this one
    unsigned int hits;        // Times FeatureHit was called (32-bit: see FeatureHit)
    unsigned int hitStride;   // Calls per FeatureHit. See FeatureTokenForCounting.
    long long    callCount;   // Total invocations via the legacy by-name API
    long long    errorCount;  // SEH exceptions caught
    DWORD        lastCallTick;// GetTickCount of last invocation
    const char*  lastError;   // Last error description (static string)
};

namespace CrashDumper {
    bool Init();
    void Shutdown();

    // Register a tracked feature for crash diagnostics. Returns a token for
    // FeatureHit, or -1 if the table is full.
    int RegisterFeature(const char* name);

    // Claims a token for counting, by the same name dllmain already registered.
    // Resolving the name costs one scan, done once at install time; registration
    // itself lives in dllmain for every feature, so looking up beats registering
    // again and ending up with two rows for one feature. Registers the name if it
    // is not present yet.
    //
    // Claiming also marks the feature as reporting its activity, so a zero count
    // means "it never ran" rather than "nobody instrumented it". Without that
    // distinction the report accuses every uninstrumented feature of doing
    // nothing, which is the same lie as a feature logging success while installing
    // no hook.
    // hitStride is how many calls each FeatureHit stands for. Features on a hot
    // path only report one in a few thousand, and the report used to print those
    // raw sample counts in the same column as the ones that count every call:
    // txtsd's five-hour session listed MatrixVectorSSE2 at 807878 next to
    // HotFunctions at 485862648, when the first samples one call in 8192 and is
    // really the larger of the two by an order of magnitude. Pass the divisor
    // the call site uses, or 1 when it counts every call.
    int FeatureTokenForCounting(const char* name, unsigned hitStride = 1);

    // O(1) increment at a known index. The old by-name API below scans the table
    // and strcmps every entry, which is why in practice it was wired into three
    // call sites out of a hundred features and everything else reported zero.
    //
    // Deliberately not atomic and deliberately 32-bit. This sits on paths that
    // run millions of times a session: a lock cmpxchg8b per call would cost more
    // than the work being counted, and a torn 64-bit read would print a number
    // far more misleading than a lost increment under contention.
    void FeatureHit(int token);

// How many features are actually registered. The startup banner used to print
// MAX_TRACKED_FEATURES here, so it read "Registered 128 features" against a cap of
// 128 and "Registered 192" against a cap of 192 - a constant wearing a count's
// clothing, which looked exactly like a registry overflowing every time.
int RegisteredFeatureCount();

    // Writes the "what actually ran" section to the log.
    void ReportFeatureActivity();

// States how many handled fatal-class exceptions were seen, without printing one
// line each - a single third-party module produced 8889 in one session.
void ReportFirstChanceSummary();

// Caches the address range of modules whose deterministic exceptions are known
// to be benign, so the first-chance probe can recognise them without taking the
// loader lock. Call from the main thread - Init and periodic maintenance - since
// such a module can load after we do.
void RefreshBenignModuleRanges();

    // Update feature state (call from hooks/fast-paths)
    void FeatureCall(const char* name);
    void FeatureError(const char* name, const char* desc);
    void FeatureSetActive(const char* name, bool active);

    // Get current feature states for crash dump
    int GetFeatureStates(FeatureState* out, int maxCount);

    // Record last hook call for crash context (ring buffer, lock-free)
    void RecordHookCall(const char* hookName, uintptr_t addr);

    // Hot-path variant for very high-frequency hooks (UI accessors etc.).
    // Samples ~1/64 calls so the per-call InterlockedIncrement stays off the
    // frame critical path, and so one hot hook can't flood the 256-slot ring
    // and evict the rarer, riskier hooks we actually want in a crash trace.
    void RecordHookCallHot(const char* hookName, uintptr_t addr);

    // ------------------------------------------------------------------
    // Event trace ("flight recorder")
    //
    // RecordHookCall answers "which hook ran last", but only the handful of
    // opt-in features that call it - so in practice a crash report showed an
    // empty trace. This ring records STATE TRANSITIONS instead: loading screen
    // boundaries, lua_State swaps, D3D9 device resets, cache invalidations,
    // watchdogs firing. Those are what actually explain a crash here, they are
    // rare enough that formatting one costs nothing, and they are recorded
    // unconditionally so the trail exists no matter which features are enabled.
    //
    // Safe from any thread; never allocates. Keep messages short and factual.
    void Trace(const char* fmt, ...);

    // Writes the most recent `count` events to the log, newest first.
    //
    // maxAgeMs bounds how far back an event may be and still be printed. A caller
    // explaining something that just happened - a slow frame - must pass the
    // window it actually covers, or the newest three entries in the ring get
    // presented as the cause when they are minutes old and unrelated. 0 means no
    // bound, which is what the crash handler wants: there, the whole trail is the
    // point. Returns the number of events printed.
    int DumpTrace(int count, DWORD maxAgeMs = 0);
}

// Times a scope and traces it ONLY if it ran longer than thresholdMs.
//
// The event ring is fed by state transitions, which are rare - a session can go
// seventeen minutes recording three of them. That is fine for a crash trail and
// useless for explaining a 100 ms frame, because the newest entries are minutes
// old. This fills the gap without flooding: a probe that stays under its
// threshold writes nothing, so every line it does produce is a stall long enough
// to matter, on work known to run on the main thread.
class StallProbe {
public:
    StallProbe(const char* what, double thresholdMs);
    ~StallProbe();
private:
    const char*   m_what;
    double        m_thresholdMs;
    LARGE_INTEGER m_start;
};

// Same measurement without RAII. MSVC rejects objects requiring unwinding in any
// function that uses __try, and several of the places worth probing are SEH
// guarded, so those call StallProbeBegin/End directly.
LARGE_INTEGER StallProbeBegin();
void StallProbeEnd(const char* what, const LARGE_INTEGER& start, double thresholdMs);

// C-callable wrapper for modules that only see the C interface.
extern "C" void CrashDumper_Trace(const char* fmt, ...);

#endif
