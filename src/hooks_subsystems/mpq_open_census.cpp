// ============================================================================
// Module: mpq_open_census
// Description: Counts and times the client's archive file-open path, and says
//              how much of it is asking for the same name twice.
// Safety & Threading: Counting hook. Calls through on every path.
// ============================================================================
// Why this exists, in one measurement from the field
//
// Sicsoo's session, 2026-09-10, one loading screen:
//
//     Load took 45509 ms
//       89 ms (0%) inside ReadFile, 18483 reads, 267.8 MB
//       97 ms (0%) compiling Lua over 3496 chunks
//        0 ms (0%) inside the client's own file writes
//
// That accounts for 186 ms of 45509. Ninety-nine point six percent of a
// forty-five second loading screen is unexplained, and it is the largest single
// thing a player waits for anywhere in these logs. It is also not disk: 267.8 MB
// arrived in 89 ms, which is three gigabytes a second, so the bytes were already
// in the operating system's cache.
//
// So the time is going somewhere that is neither reading, nor writing, nor
// compiling. The obvious candidate has never been counted.
// ---------------------------------------------------------------------------
// What is being counted
//
// Storm is linked into wow.exe rather than shipped as storm.dll - two modules in
// this project look for a storm.dll that does not exist and quietly get nothing.
// Its assert strings put SFile2-Core.cpp between 0x00421950 and 0x00425010, and
// sub_424B50 in that range is __stdcall with four arguments, the second a char*,
// and has 257 callers, which is more than anything else there. That is
// SFileOpenFileEx: open a file by name, optionally in a named archive.
//
// A name that is not in the archive it is asked about is searched for in every
// open archive in turn, and a WoW install of this vintage carries a base set
// plus every patch plus whatever a private server adds. So a miss is not one
// hash lookup, it is one per archive, and the client asks for files that are not
// there constantly: optional textures, per-race variants, sounds an effect might
// not have.
// ---------------------------------------------------------------------------
// The number that decides what to build next
//
// Repeat misses. A name that has already been searched for and not found, being
// searched for again, is work that a negative cache would remove entirely and
// the only work here that is provably removable. Every other kind of open has to
// happen at least once.
//
// So this counts three things separately - found, missed for the first time, and
// missed again - and names the worst repeat offenders. If repeat misses are a
// large share of a loading screen then a negative cache is worth building and
// this says roughly what it would save. If they are not, the idea is dead for
// one log line and the forty-five seconds are somewhere else.
// ---------------------------------------------------------------------------
// And then removing it, under its own switch
//
// MpqNegativeCache turns the count into a saving: a name already searched for
// and not found is answered without asking the client again. Three things keep
// that from being a way to break a loading screen.
//
// It is only alive while a loading screen is up, and the table is cleared when
// one begins. Archives are opened at startup and when a patch is mounted, not
// in the middle of a load, so within one loading screen the set of files that
// exist cannot change. Outside a loading screen nothing is served at all, so
// ordinary play runs exactly as it does now.
//
// The key is the name, the archive handle and the search scope together, not
// just the name. A file absent from one archive is not absent from the next
// one, and a cache that forgot which archive was asked would answer for the
// wrong one.
//
// And it proves itself before it saves anything. For the first kProve hits the
// client is called anyway and its answer compared; only after that many
// agreements does a hit skip the call, and one hit in kRecheck keeps asking
// afterwards. A single disagreement retires the serving half for the session
// and leaves the counting half running.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "mpq_open_census.h"
#include "loading_state.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

extern DWORD g_mainThreadId;   // dllmain.cpp; the thread the client draws on

namespace MpqOpenCensus {

namespace {

// SFileOpenFileEx. Identified by its assert strings, its four stdcall arguments
// with a char* second, and 257 callers - the most of anything in Storm's range.
constexpr uintptr_t kOpen = 0x00424B50;

typedef int (__stdcall* Open_t)(void* archive, const char* name, int scope,
                                void** out);
Open_t orig_Open = nullptr;

bool g_installed = false;

// Plain 32-bit, main thread. Lower bounds if that ever stops being true.
unsigned long g_calls      = 0;
unsigned long g_found      = 0;
unsigned long g_missFirst  = 0;
unsigned long g_missRepeat = 0;
unsigned long g_noName     = 0;

// Loading screens only, so gameplay is separated from the thing being explained.
unsigned long g_callsLoad      = 0;
unsigned long g_missRepeatLoad = 0;
double        g_msLoad         = 0.0;
double        g_msTotal        = 0.0;

double g_qpcPerMs = 0.0;

// Names that have already been searched for and not found. Direct-mapped, so a
// collision loses a name rather than inventing one: two names in one slot means
// the second is counted as a first miss, which under-reports repeats. That is
// the safe direction for a number whose whole purpose is to justify building
// something.
constexpr int kSlots = 8192;
constexpr int kMask  = kSlots - 1;

struct Slot {
    uint32_t hash;
    uint32_t misses;
    char     name[52];
};
Slot* g_seen = nullptr;

// This hook is not main-thread-only, whatever the note on the counters says.
//
// hooks_async.cpp reaches 0x00424B50 directly, as a raw function pointer inside
// ProcessAdtPrefetch, and that runs on the async worker pool. So a second thread
// arrives here whenever AsyncWorkerPool is on, and this module does two things
// that are not safe to do from two threads at once.
//
// It writes a slot as three separate stores - the hash, the miss count, then a
// strncpy of the name - so two threads landing on one slot can leave the hash
// from one name beside the name of another, and the report then blames the
// wrong file. And it answers "not found" on the client's behalf, a decision
// verified only on the thread the verification ran on.
//
// So off-thread calls are handed straight to the client: no serve, no slot, no
// timing, and a count of their own. That keeps the negative cache exactly as
// wide as the evidence for it, and turns "does the prefetcher reach this hook"
// from an assumption into a number.
volatile LONG g_offThread = 0;

// The serving half. Off unless its own switch is on, and then still silent
// until it has proved itself.
constexpr long     kProve   = 2000;
constexpr unsigned kRecheck = 255;    // one hit in this many, as a mask

bool g_serveOn    = false;   // the switch
bool g_serveArmed = false;   // proved, and now actually skipping calls
bool g_serveDead  = false;

unsigned long g_proved   = 0;   // hits where the client was asked anyway and agreed
unsigned long g_served   = 0;   // calls answered without asking the client
unsigned long g_rechecks = 0;

// MPQ names are case-insensitive and mix separators, so both are folded before
// hashing - otherwise the same file under two spellings looks like two names.
// The archive handle and the search scope are part of the key. A name absent
// from one archive is not absent from another, and a cache that forgot which
// one was asked would answer for the wrong archive.
uint32_t HashName(const char* s, const void* archive, int scope) {
    uint32_t h = 2166136261u;
    uint32_t tag = (uint32_t)(uintptr_t)archive ^ (uint32_t)scope;
    for (int i = 0; i < 4; ++i) {
        h ^= (tag >> (i * 8)) & 0xFFu;
        h *= 16777619u;
    }
    for (const char* p = s; *p; ++p) {
        char c = *p;
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        else if (c == '/') c = '\\';
        h ^= (unsigned char)c;
        h *= 16777619u;
    }
    return h ? h : 1u;   // zero marks an empty slot
}

double NowMs() {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / g_qpcPerMs;
}

int __stdcall Hooked_Open(void* archive, const char* name, int scope, void** out) {
    // Another thread, so none of what follows applies. See the note on
    // g_offThread.
    if (g_mainThreadId != 0 && GetCurrentThreadId() != g_mainThreadId) {
        InterlockedIncrement(&g_offThread);
        return orig_Open(archive, name, scope, out);
    }

    // An unnamed open cannot be attributed to anything, so it is counted apart
    // rather than folded in.
    if (!name || !g_seen) {
        ++g_calls;
        ++g_noName;
        return orig_Open(archive, name, scope, out);
    }

    const bool loading = LoadingState::IsLoading();
    const uint32_t h = HashName(name, archive, scope);
    Slot& s = g_seen[h & kMask];
    const bool knownMissing = (s.hash == h);

    // Serving. Only inside a loading screen, only for a name this same archive
    // and scope has already failed to find, and only once the client has agreed
    // enough times. One hit in kRecheck asks anyway, for ever.
    if (knownMissing && loading && g_serveOn && !g_serveDead) {
        const bool ask = !g_serveArmed || ((g_proved & kRecheck) == 0);
        if (!ask) {
            ++s.misses;
            ++g_missRepeat;
            ++g_missRepeatLoad;
            ++g_calls;
            ++g_callsLoad;
            ++g_served;
            if (out) *out = nullptr;
            return 0;
        }
        ++g_rechecks;
    }

    const double t0 = NowMs();
    const int r = orig_Open(archive, name, scope, out);
    const double dt = NowMs() - t0;

    ++g_calls;
    g_msTotal += dt;
    if (loading) { ++g_callsLoad; g_msLoad += dt; }

    // The proof. A name this cache would have answered for, that the client has
    // just found, means the cache is wrong about something and the serving half
    // stops for the session. The counting half carries on.
    if (knownMissing && loading && g_serveOn && !g_serveDead) {
        if (r) {
            g_serveDead = true;
            Log("[MpqOpen] negative cache RETIRED: '%s' was remembered as not "
                "found and the client has just found it. Nothing was skipped "
                "on this call - the client answered it - so the load is "
                "unaffected, but the assumption that the set of files cannot "
                "change inside one loading screen does not hold here.", name);
        } else {
            ++g_proved;
            if (!g_serveArmed && g_proved >= (unsigned long)kProve) {
                g_serveArmed = true;
                Log("[MpqOpen] negative cache armed after %lu agreements: a "
                    "repeated miss inside a loading screen is answered without "
                    "asking the client, and one hit in %u still asks.",
                    g_proved, kRecheck + 1);
            }
        }
    }

    if (r) { ++g_found; return r; }

    if (knownMissing) {
        ++s.misses;
        ++g_missRepeat;
        if (loading) ++g_missRepeatLoad;
    } else {
        ++g_missFirst;
        s.hash = h;
        s.misses = 1;
        // Kept only to name the worst offenders in the report.
        size_t n = strlen(name);
        const char* tail = (n >= sizeof(s.name)) ? name + (n - sizeof(s.name) + 1)
                                                 : name;
        strncpy(s.name, tail, sizeof(s.name) - 1);
        s.name[sizeof(s.name) - 1] = '\0';
    }
    return r;
}

}  // namespace

bool Init() {
    // The cache is served through the same hook, so either switch installs it.
    if (!Config::g_settings.OptMpqOpenCensus &&
        !Config::g_settings.OptMpqNegativeCache) return true;

    LARGE_INTEGER f;
    QueryPerformanceFrequency(&f);
    if (f.QuadPart == 0) {
        Log("[MpqOpen] NOT active: no performance counter.");
        return false;
    }
    g_qpcPerMs = (double)f.QuadPart / 1000.0;

    g_seen = (Slot*)VirtualAlloc(nullptr, sizeof(Slot) * kSlots,
                                 MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                 PAGE_READWRITE);
    if (!g_seen) {
        Log("[MpqOpen] NOT active: the %u KB name table could not be reserved.",
            (unsigned)(sizeof(Slot) * kSlots / 1024));
        return false;
    }

    static const unsigned char kOpenOpening[16] = { 0x55, 0x8B, 0xEC, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x6A, 0xFF, 0x68, 0x5C, 0x5E, 0x9C, 0x00 };
    if (!WowOpt_ClientBytesAre(kOpen, kOpenOpening, sizeof(kOpenOpening))) {
        Log("[MpqOpen] NOT active: the bytes at 0x%08X are not the client's file open of build 12340", (unsigned)kOpen);
        return false;
    }
    if (WineSafe_CreateHook((void*)kOpen, (void*)&Hooked_Open,
                            (void**)&orig_Open) != MH_OK ||
        WO_EnableHook((void*)kOpen) != MH_OK) {
        Log("[MpqOpen] NOT active: could not hook 0x%08X.", (unsigned)kOpen);
        return false;
    }
    g_installed = true;
    g_serveOn = Config::g_settings.OptMpqNegativeCache;

    Log("[MpqOpen] ACTIVE on sub_424B50, the archive open-by-name call - Storm "
        "is linked into wow.exe here rather than shipped as storm.dll, and this "
        "is the entry point with 257 callers. A loading screen in the field took "
        "45509 ms with 89 ms of it inside ReadFile and 97 ms compiling Lua, so "
        "99.6%% of it is unexplained and the bytes were already in the operating "
        "system's cache. This counts the opens, times them, and separates a name "
        "that was searched for and not found from one that had already been "
        "searched for and not found - the second is the only work here a cache "
        "could remove. Nothing is cached and no call is skipped.");
    return true;
}

void Shutdown() {
    if (g_installed) MH_DisableHook((void*)kOpen);
    g_installed = false;
}

void OnLoadBegin() {
    g_callsLoad = 0;
    g_missRepeatLoad = 0;
    g_msLoad = 0.0;
    // Cleared at the start of every load. What exists cannot change inside one
    // loading screen, which is the whole basis for serving from this; across
    // two of them a patch can be mounted, so nothing is carried over.
    if (g_seen) memset(g_seen, 0, sizeof(Slot) * kSlots);
}

void ReportLoad(double loadMs) {
    if (!g_installed) return;
    if (g_callsLoad == 0) {
        Log("[LoadingState]   measured and zero: the client opened no archive "
            "file by name inside this loading screen.");
        return;
    }
    Log("[LoadingState]   and %.0f ms (%.0f%%) opening %lu archive files by "
        "name, %lu of which were a name already searched for and not found. "
        "That last group is the only part a cache could remove.",
        g_msLoad, (loadMs > 0.0) ? (100.0 * g_msLoad / loadMs) : 0.0,
        g_callsLoad, g_missRepeatLoad);
}

void LogStats() {
    if (!Config::g_settings.OptMpqOpenCensus &&
        !Config::g_settings.OptMpqNegativeCache) return;
    if (!g_installed) {
        Log("[MpqOpen] switched on but not installed, so nothing here was "
            "measured.");
        return;
    }
    if (g_calls == 0) {
        Log("[MpqOpen] installed, and no archive file has been opened by name. "
            "This is measured and zero, not unmeasured.");
        return;
    }

    if (g_serveOn)
        Log("[MpqOpen] negative cache: %lu answered without asking the client, "
            "%lu agreements proving it, %lu rechecks. %s",
            g_served, g_proved, g_rechecks,
            g_serveDead ? "RETIRED on a disagreement." :
            g_serveArmed ? "Armed." : "Still proving; nothing skipped yet.");
    Log("[MpqOpen] %lu opens, %.0f ms. %lu found, %lu missed for the first "
        "time, %lu missed a name already missed (%.1f%% of all opens). Counts "
        "are lower bounds and the time includes this hook's own cost.",
        g_calls, g_msTotal, g_found, g_missFirst, g_missRepeat,
        100.0 * (double)g_missRepeat / (double)g_calls);
    if (g_noName > 0)
        Log("[MpqOpen]   %lu opens had no name to attribute and are counted "
            "apart.", g_noName);
    // Printed whether or not it fired. Zero says the async prefetcher never
    // reached this hook - which is a measurement, not an absence of one - and a
    // non-zero figure says how much of the archive traffic is invisible to
    // everything above, because those calls are neither counted nor timed nor
    // eligible to be served.
    Log("[MpqOpen]   %ld open(s) arrived on a thread other than the one the "
        "client draws on and were handed straight to it. hooks_async reaches "
        "0x00424B50 as a raw pointer from the worker pool, and this module "
        "writes a slot in three separate stores and answers on the client's "
        "behalf - neither is safe to do from two threads, so those calls take "
        "none of it.", g_offThread);

    // The worst offenders, so a name in the report can be looked at directly.
    for (int round = 0; round < 5; ++round) {
        int best = -1;
        unsigned long bestN = 1;
        for (int i = 0; i < kSlots; ++i)
            if (g_seen[i].hash && g_seen[i].misses > bestN) {
                bestN = g_seen[i].misses; best = i;
            }
        if (best < 0) break;
        Log("[MpqOpen]   %8lu misses  %s", g_seen[best].misses,
            g_seen[best].name);
        g_seen[best].misses = 0;   // report-time only; the totals above stand
    }
}

}  // namespace MpqOpenCensus
