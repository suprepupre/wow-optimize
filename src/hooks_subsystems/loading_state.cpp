// ============================================================================
// Module: loading_state.cpp
// Description: Native loading-screen / combat state detection.
// Safety & Threading: Main thread only (FrameScript event dispatch).
//
// The loading state gates "bypass this hook while the world is loading" guards in
// LoadingDefrag, the DBC lookup cache, deferred field updates, LuaOpcache and the
// texture unload queue. It used to have exactly two producers, both of which are
// inert in a shipping build:
//   - the !LuaBoost addon writing LUABOOST_ADDON_LOADING, read by lua_optimize -
//     so every user without the addon installed never entered loading state at all;
//   - EventCoalescer's detour, which is compiled out by TEST_DISABLE_EVENT_COALESCER.
// This module owns the detour unconditionally and derives the state from the
// client's own event stream, so the guards work with or without the addon. The
// coalescer's dedup queue is now a consumer of this detour rather than its owner.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "version.h"

#include "loading_state.h"
#include "session_verdict.h"
#include "event_coalescer.h"
#include "combat_log_filter.h"
#include "runtime_vm/lua_gc_governor.h"
#include "diagnostics/crash_dumper.h"

extern "C" void Log(const char* fmt, ...);
extern "C" void ReserveLoadingArena();
extern "C" void ReleaseLoadingArena();

static constexpr uintptr_t ADDR_FrameScript_SignalEvent = 0x0081AC90;

// The client's own file-write wrapper - it carries the string "Win32 Write - %s".
static constexpr uintptr_t kClientWrite = 0x00454910;

void* g_origSignalEvent = nullptr;

static volatile LONG g_isLoading = 0;

namespace {

// Event classification cache. The event id -> name lookup walks the client's event
// table and does a string compare, which is far too heavy to repeat for every
// signalled event, so each id is classified exactly once.
enum EventKind : unsigned char {
    EVENT_UNCLASSIFIED = 0,
    EVENT_OTHER,
    EVENT_LOADING_BEGIN,
    EVENT_LOADING_END,
    EVENT_COMBAT_BEGIN,
    EVENT_COMBAT_END
};

constexpr int EVENT_CACHE_SIZE = 4096;
EventKind g_eventKind[EVENT_CACHE_SIZE] = {};

const char* GetEventName(int eventId) {
    __try {
        if (eventId < 0 || eventId > 2000) return nullptr;
        uintptr_t* eventTable = *(uintptr_t**)0x00D3F7D8;
        if (!eventTable) return nullptr;

        uintptr_t eventPtr = eventTable[eventId];
        if (eventPtr < 0x10000 || eventPtr > 0xFFE00000) return nullptr;

        const char* name = *(const char**)(eventPtr + 20);
        if (name < (const char*)0x10000 || name > (const char*)0xFFE00000) return nullptr;

        return name;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

EventKind ClassifyEvent(int eventId) {
    const char* name = GetEventName(eventId);
    if (!name) return EVENT_OTHER;

    // PLAYER_LEAVING_WORLD opens the loading window (zoning, teleport, instance
    // entry, logout to character select); PLAYER_ENTERING_WORLD closes it once the
    // world is actually playable. PLAYER_ENTERING_WORLD also fires alone after a
    // /reload, which correctly ends any state left open by a missed begin event.
    if (strcmp(name, "PLAYER_LEAVING_WORLD") == 0)  return EVENT_LOADING_BEGIN;
    if (strcmp(name, "PLAYER_ENTERING_WORLD") == 0) return EVENT_LOADING_END;
    if (strcmp(name, "PLAYER_REGEN_DISABLED") == 0) return EVENT_COMBAT_BEGIN;
    if (strcmp(name, "PLAYER_REGEN_ENABLED") == 0)  return EVENT_COMBAT_END;
    return EVENT_OTHER;
}

// ---- where a loading screen's time goes -------------------------------------
static LARGE_INTEGER g_qpcFreq      = {};
static LARGE_INTEGER g_loadStartQpc = {};
static double        g_ioMsThisLoad = 0.0;

// Writes, measured because reads alone did not account for a 139-second load.
static double        g_wrMsThisLoad = 0.0;
static unsigned long long g_wrBytesThisLoad = 0;
static unsigned long long g_wrCountThisLoad = 0;
static double        g_wrMsWorst    = 0.0;
static char          g_wrWorstName[128] = {};
static bool          g_writeHookOn  = false;
static uint64_t      g_ioBytesThisLoad = 0;
static uint64_t      g_ioReadsThisLoad = 0;

static bool     g_readHookOn  = false;
static int      g_loadCount   = 0;
static double   g_loadMsTotal = 0.0;
static double   g_loadMsWorst = 0.0;
static double   g_ioMsTotal   = 0.0;
static uint64_t g_ioBytesTotal = 0;

static void LoadTimerBegin() {
    if (g_qpcFreq.QuadPart == 0) QueryPerformanceFrequency(&g_qpcFreq);
    QueryPerformanceCounter(&g_loadStartQpc);
    g_ioMsThisLoad = 0.0;
    g_ioBytesThisLoad = 0;
    g_ioReadsThisLoad = 0;
    g_wrMsThisLoad = 0.0;
    g_wrBytesThisLoad = 0;
    g_wrCountThisLoad = 0;
}

static void LoadTimerEnd() {
    if (g_qpcFreq.QuadPart == 0) return;
    if (g_loadStartQpc.QuadPart == 0) {
        // The initial entry into the world has no PLAYER_LEAVING_WORLD before it,
        // so there was no start to time. Said out loud, because this is the
        // longest load of the session and silence here reads as "it was free".
        Log("[LoadingState] Initial world entry finished - not timed, it has no "
            "start event to measure from");
        return;
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double ms = (double)(now.QuadPart - g_loadStartQpc.QuadPart) * 1000.0
              / (double)g_qpcFreq.QuadPart;
    g_loadStartQpc.QuadPart = 0;
    if (ms <= 0.0 || ms > 600000.0) return;   // clock went backwards, or a stuck screen

    g_loadCount++;
    g_loadMsTotal += ms;
    g_ioMsTotal   += g_ioMsThisLoad;
    g_ioBytesTotal += g_ioBytesThisLoad;
    if (ms > g_loadMsWorst) g_loadMsWorst = ms;

    // A load nobody would call normal. The threshold is deliberately generous:
    // ten seconds is already something a player notices and mentions, and the
    // reports that took weeks to diagnose were all far past it.
    if (ms > 10000.0) {
        Verdict::Add(ms > 60000.0 ? Verdict::Bad : Verdict::Warn,
                     "a loading screen took %.0f s", ms / 1000.0);
    }

    if (!g_readHookOn) {
        Log("[LoadingState] Load took %.0f ms - disk share not measured "
            "(the ReadFile hook is not installed in this build)", ms);
    } else {
        Log("[LoadingState] Load took %.0f ms - %.0f ms (%.0f%%) inside ReadFile, "
            "%llu reads, %.1f MB",
            ms, g_ioMsThisLoad, (ms > 0.0) ? (100.0 * g_ioMsThisLoad / ms) : 0.0,
            (unsigned long long)g_ioReadsThisLoad,
            (double)g_ioBytesThisLoad / (1024.0 * 1024.0));
    }

    if (!g_writeHookOn) {
        Log("[LoadingState]   writes not measured - the client's write wrapper is "
            "not hooked in this build");
    } else if (g_wrCountThisLoad) {
        Log("[LoadingState]   and %.0f ms (%.0f%%) inside the client's own file "
            "writes, %llu of them, %.1f MB. Worst single write %.0f ms on %s.",
            g_wrMsThisLoad, (ms > 0.0) ? (100.0 * g_wrMsThisLoad / ms) : 0.0,
            (unsigned long long)g_wrCountThisLoad,
            (double)g_wrBytesThisLoad / (1024.0 * 1024.0),
            g_wrMsWorst, g_wrWorstName[0] ? g_wrWorstName : "(unnamed)");
    } else {
        Log("[LoadingState]   and no file writes at all - so the time is neither "
            "reading nor writing");
    }
}

// The client's own file-write wrapper, sub_454910. Found from a freeze capture:
// a tester's main thread was blocked 13 seconds inside it, twice, during a
// character switch, and the same load reported only 1% of its 139 seconds inside
// ReadFile. Reads were instrumented and writes were not, so the larger share had
// nowhere to be counted.
//
// It is the right place rather than WriteFile itself: it is reached only for the
// client's own files, so no lookup is needed to tell them apart, and it carries
// the name at +76 - used there only to build an error string, and read here to
// say which file the worst write was.
//
// Times the call and passes it on. Nothing else.
typedef char (__cdecl* clientWrite_fn)(void* fileObj, const void* buf,
                                       void* overlapped, unsigned long* pBytes);
static clientWrite_fn orig_ClientWrite = nullptr;

static char __cdecl Hooked_ClientWrite(void* fileObj, const void* buf,
                                       void* overlapped, unsigned long* pBytes) {
    unsigned long want = 0;
    __try { if (pBytes) want = *pBytes; } __except (EXCEPTION_EXECUTE_HANDLER) { want = 0; }

    LARGE_INTEGER a, b;
    QueryPerformanceCounter(&a);
    char r = orig_ClientWrite(fileObj, buf, overlapped, pBytes);
    QueryPerformanceCounter(&b);

    if (g_qpcFreq.QuadPart) {
        double ms = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)g_qpcFreq.QuadPart;
        const char* name = nullptr;
        __try {
            name = *(const char**)((const unsigned char*)fileObj + 76);
            if (name < (const char*)0x10000 || name > (const char*)0xFFE00000) name = nullptr;
        } __except (EXCEPTION_EXECUTE_HANDLER) { name = nullptr; }
        LoadingState::NoteWrite(ms, want, name);
    }
    return r;
}

void ApplyEventKind(EventKind kind) {
    switch (kind) {
        case EVENT_LOADING_BEGIN:
            if (InterlockedExchange(&g_isLoading, 1) == 0) {
                LuaGCGovernor::g_isLoading = true;
                LoadTimerBegin();
                CrashDumper::Trace("LOADING begin (PLAYER_LEAVING_WORLD)");
                Log("[LoadingState] Loading screen started (PLAYER_LEAVING_WORLD)");
                ReserveLoadingArena();
            }
            break;
        case EVENT_LOADING_END:
            // The first entry into the world is not preceded by PLAYER_LEAVING_WORLD
            // - there is no world to leave - so the window never opened and the
            // longest, heaviest load of the session ran with every loading-time
            // guard switched off. It showed up in the frame benchmark as a single
            // ~2 second frame counted as gameplay.
            //
            // Treating the end event as authoritative closes that: if the window
            // was never opened, this is the initial load finishing, so open and
            // close it here to run the same end-of-load work every other transition
            // gets - releasing the arena, flushing delayed textures, dropping the
            // caches that the load invalidated.
            if (InterlockedExchange(&g_isLoading, 0) == 0) {
                CrashDumper::Trace("LOADING end (initial world entry)");
                Log("[LoadingState] Initial world entry finished (no preceding "
                    "PLAYER_LEAVING_WORLD) - running end-of-load cleanup");
                ReserveLoadingArena();
            } else {
                CrashDumper::Trace("LOADING end (PLAYER_ENTERING_WORLD)");
                Log("[LoadingState] Loading screen finished (PLAYER_ENTERING_WORLD)");
            }
            LoadTimerEnd();
            LuaGCGovernor::g_isLoading = false;
            ReleaseLoadingArena();
            break;
        case EVENT_COMBAT_BEGIN:
            LuaGCGovernor::g_inCombat = true;
            break;
        case EVENT_COMBAT_END:
            LuaGCGovernor::g_inCombat = false;
            break;
        default:
            break;
    }
}

} // namespace

// Returns true if the event must be swallowed (the coalescer queued it for replay
// at end of frame). State tracking always runs first, so it is never affected by
// whether the coalescer is enabled.
extern "C" bool __fastcall LoadingState_OnSignalEvent(int eventId, const char* format, void* vaStart) {
    if ((unsigned)eventId < (unsigned)EVENT_CACHE_SIZE) {
        EventKind kind = g_eventKind[eventId];
        if (kind == EVENT_UNCLASSIFIED) {
            kind = ClassifyEvent(eventId);
            g_eventKind[eventId] = kind;
        }
        if (kind != EVENT_OTHER) ApplyEventKind(kind);
    } else {
        // Out-of-range ids are vanishingly rare; classify without caching.
        ApplyEventKind(ClassifyEvent(eventId));
    }

    // Combat log filtering has its own switch and used to be reachable only from
    // inside the coalescer's queue, below the IsActive() gate - so with the
    // coalescer off, which is its default and which it stays because of the
    // buffs-and-countdowns defect, the filter's own switch did nothing. It is
    // asked here, before that gate.
    if (CombatLogFilter::IsActive() &&
        CombatLogFilter::ShouldDrop(eventId, format, vaStart)) return true;

    if (!EventCoalescer::IsActive()) return false;
    return EventCoalescer::TryQueue(eventId, format, vaStart);
}

__declspec(naked) static void Hooked_FrameScript_SignalEvent() {
    __asm {
        // [esp+0]  = return address
        // [esp+4]  = eventId
        // [esp+8]  = format
        // [esp+12] = first vararg

        mov ecx, dword ptr [esp+4]   // eventId -> fastcall arg1
        mov edx, dword ptr [esp+8]   // format  -> fastcall arg2
        lea eax, [esp+12]            // &first vararg
        push eax                     // stack arg for __fastcall (callee-cleaned)
        call LoadingState_OnSignalEvent

        test al, al
        jnz drop_event

        jmp [g_origSignalEvent]

    drop_event:
        ret
    }
}

namespace LoadingState {

void SetReadHookInstalled(bool installed) {
    g_readHookOn = installed;
}

void NoteWrite(double ms, unsigned int bytes, const char* name) {
    g_wrMsThisLoad += ms;
    g_wrBytesThisLoad += bytes;
    g_wrCountThisLoad++;
    if (ms > g_wrMsWorst) {
        g_wrMsWorst = ms;
        g_wrWorstName[0] = 0;
        if (name) {
            __try {
                const char* leaf = strrchr(name, '\\');
                leaf = leaf ? leaf + 1 : name;
                strncpy(g_wrWorstName, leaf, sizeof(g_wrWorstName) - 1);
                g_wrWorstName[sizeof(g_wrWorstName) - 1] = 0;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                g_wrWorstName[0] = 0;
            }
        }
    }
}

void NoteRead(double ms, unsigned int bytes) {
    g_ioMsThisLoad += ms;
    g_ioBytesThisLoad += bytes;
    g_ioReadsThisLoad++;
}

void ReportLoadTimes() {
    if (g_loadCount == 0) {
        Log("[LoadingState] No loading screens completed this session");
        return;
    }
    Log("[LoadingState] %d load(s): %.1fs total, %.0f ms average, %.0f ms worst",
        g_loadCount, g_loadMsTotal / 1000.0, g_loadMsTotal / g_loadCount, g_loadMsWorst);
    if (!g_readHookOn) {
        Log("[LoadingState]   How much of that was the disk is unknown: the ReadFile"
            " hook feeding this report is compiled out of this build, so nothing"
            " counted the reads. Not the same as none.");
    } else {
        Log("[LoadingState]   of that, %.1fs was ReadFile (%.0f%%) moving %.1f MB - "
            "prefetch and archive work can only ever address that share",
            g_ioMsTotal / 1000.0,
            (g_loadMsTotal > 0.0) ? (100.0 * g_ioMsTotal / g_loadMsTotal) : 0.0,
            (double)g_ioBytesTotal / (1024.0 * 1024.0));
    }
}


bool Init() {
    unsigned char* p = (unsigned char*)ADDR_FrameScript_SignalEvent;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("[LoadingState] BAD PROLOGUE at 0x%08X (expected 55 8B, got %02X %02X) - skipping",
            ADDR_FrameScript_SignalEvent, p[0], p[1]);
        return false;
    }

    if (WineSafe_CreateHook((void*)ADDR_FrameScript_SignalEvent,
                            (void*)Hooked_FrameScript_SignalEvent,
                            &g_origSignalEvent) != MH_OK) {
        Log("[LoadingState] Failed to hook FrameScript_SignalEvent");
        return false;
    }

    if (WO_EnableHook((void*)ADDR_FrameScript_SignalEvent) != MH_OK) {
        Log("[LoadingState] Failed to enable FrameScript_SignalEvent hook");
        g_origSignalEvent = nullptr;
        return false;
    }

    // The write timer. Separate from the event detour above so a failure here
    // cannot take loading detection down with it.
    if (QueryPerformanceFrequency(&g_qpcFreq) &&
        !IsBadReadPtr((void*)kClientWrite, 8) &&
        WineSafe_CreateHook((void*)kClientWrite, (void*)Hooked_ClientWrite,
                            (void**)&orig_ClientWrite) == MH_OK &&
        WO_EnableHook((void*)kClientWrite) == MH_OK) {
        g_writeHookOn = true;
        Log("[LoadingState] timing the client's file writes at 0x%08X. A tester's "
            "139-second load spent 1%% of itself in ReadFile, and the freeze "
            "watchdog caught its main thread blocked 13 seconds inside this "
            "function - twice, during a character switch. Reads were measured and "
            "writes were not, so the larger share had nowhere to be counted.",
            (unsigned)kClientWrite);
    } else {
        Log("[LoadingState] the client's write wrapper at 0x%08X was NOT hooked - "
            "loads will report their read share only", (unsigned)kClientWrite);
    }

    Log("[LoadingState] ACTIVE (FrameScript_SignalEvent @ 0x%08X) - native loading detection",
        ADDR_FrameScript_SignalEvent);
    return true;
}

void Shutdown() {
    if (g_origSignalEvent) {
        MH_DisableHook((void*)ADDR_FrameScript_SignalEvent);
        g_origSignalEvent = nullptr;
    }
}

bool IsLoading() {
    return g_isLoading != 0;
}

} // namespace LoadingState
