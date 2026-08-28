// ============================================================================
// Module: event_coalescer.cpp
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "version.h"

#include "event_coalescer.h"
#include "runtime_vm/lua_gc_governor.h"
#include "core/config.h"

extern "C" void Log(const char* fmt, ...);

typedef void(__cdecl *FrameScript_SignalEvent_t)(int eventId, const char* format, ...);

// The FrameScript_SignalEvent detour and its trampoline are owned by LoadingState,
// which routes events here only while this module is active. Replaying a queued
// event must go through the trampoline so it is not re-queued.
extern void* g_origSignalEvent;

namespace EventCoalescer { bool g_active = false; }

// Fixed-size event entry — no C++ objects, safe for SEH
struct QueuedEvent {
    int eventId;
    char format[8];        // longest observed format is "%s%s" (5 chars)
    char strArg1[32];      // unitId strings like "player", "party1target" etc
    char strArg2[32];
    int intArg1;
    bool hasStr1;
    bool hasStr2;
    bool hasInt1;
    bool used;
};

static constexpr int MAX_QUEUED = 256;
static QueuedEvent g_queue[MAX_QUEUED];
static int g_queueCount = 0;
static thread_local bool g_isReplaying = false;
static SRWLOCK g_eventLock = SRWLOCK_INIT;

static uint32_t g_eventsTotal = 0;
static uint32_t g_eventsDropped = 0;

static const char* GetEventName(int eventId) {
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

static bool ShouldCoalesce(const char* name) {
    if (!name) return false;
    // UNIT_AURA/SPELL_UPDATE_COOLDOWN/USABLE/CHARGES are intentionally excluded:
    // IsDuplicate() dedups by (eventId, unit token) within a frame and silently
    // drops repeats, but these events don't carry which aura/spell changed —
    // addons rescan full state on receipt, so a dropped repeat can mean a proc
    // that landed in the same frame as an earlier aura change never triggers a
    // rescan, leaving buff icons/countdowns stuck (GitHub issue #42). Health/
    // power events are safe to coalesce since only the latest value matters.
    if (strcmp(name, "UNIT_POWER") == 0 ||
        strcmp(name, "UNIT_HEALTH") == 0 ||
        strcmp(name, "UNIT_MAXHEALTH") == 0 ||
        strcmp(name, "UNIT_MAXPOWER") == 0) {
        return true;
    }
    return false;
}

static bool IsDuplicate(const QueuedEvent* ev) {
    for (int i = 0; i < g_queueCount; ++i) {
        const QueuedEvent* e = &g_queue[i];
        if (!e->used) continue;
        if (e->eventId != ev->eventId) continue;
        if (e->hasStr1 != ev->hasStr1) continue;
        if (e->hasStr1 && strcmp(e->strArg1, ev->strArg1) != 0) continue;
        if (e->hasStr2 != ev->hasStr2) continue;
        if (e->hasStr2 && strcmp(e->strArg2, ev->strArg2) != 0) continue;
        if (e->hasInt1 != ev->hasInt1) continue;
        if (e->hasInt1 && e->intArg1 != ev->intArg1) continue;
        return true;
    }
    return false;
}

static void DispatchSingle(const QueuedEvent* ev) {
    __try {
        auto fn = (FrameScript_SignalEvent_t)g_origSignalEvent;
        if (ev->hasStr1 && ev->hasStr2) {
            fn(ev->eventId, ev->format, ev->strArg1, ev->strArg2);
        } else if (ev->hasStr1) {
            fn(ev->eventId, ev->format, ev->strArg1);
        } else if (ev->hasInt1) {
            fn(ev->eventId, ev->format, ev->intArg1);
        } else {
            fn(ev->eventId, ev->format);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // guard replay
    }
}

// Called from the naked hook — parse format string and queue if coalescable
#include "combat_log_filter.h"

// Combat/loading state tracking lives in LoadingState, which owns the detour and
// runs before this is called. This function is only reached while the coalescer is
// active, so it deals purely with filtering and frame-scoped deduplication.
static bool TryQueueEvent(int eventId, const char* format, void* vaStart) {
    if (g_isReplaying) return false;

    // Combat log filtering used to happen here, which made it reachable only when
    // this feature was on. It has its own switch, so it now runs from the detour
    // in LoadingState before this is ever called, and nothing is done twice.
    const char* eventName = GetEventName(eventId);

    static bool s_coalesceCache[4096] = {};
    static bool s_coalesceChecked[4096] = {};

    // Fall back to slow path for out-of-bounds event IDs (extremely rare)
    if (eventId < 0 || eventId >= 4096) {
        return ShouldCoalesce(eventName);
    }

    if (!s_coalesceChecked[eventId]) {
        s_coalesceCache[eventId] = ShouldCoalesce(eventName);
        s_coalesceChecked[eventId] = true;
    }

    if (!s_coalesceCache[eventId]) {
        return false;
    }

    QueuedEvent ev;
    memset(&ev, 0, sizeof(ev));
    ev.eventId = eventId;
    ev.used = true;

    if (format) {
        size_t fmtLen = strlen(format);
        if (fmtLen >= sizeof(ev.format)) fmtLen = sizeof(ev.format) - 1;
        memcpy(ev.format, format, fmtLen);
        ev.format[fmtLen] = '\0';
    }

    // Parse varargs from the stack based on the format string
    __try {
        uintptr_t* pArgs = (uintptr_t*)vaStart;
        if (format) {
            const char* p = format;
            while (*p) {
                if (*p == '%') {
                    p++;
                    if (*p == '\0') break;
                    char type = *p;
                    if (type == 's') {
                        const char* s = (const char*)*pArgs;
                        pArgs++;
                        if (s >= (const char*)0x10000 && s < (const char*)0xFFE00000) {
                            if (!ev.hasStr1) {
                                strncpy(ev.strArg1, s, sizeof(ev.strArg1) - 1);
                                ev.strArg1[sizeof(ev.strArg1) - 1] = '\0';
                                ev.hasStr1 = true;
                            } else if (!ev.hasStr2) {
                                strncpy(ev.strArg2, s, sizeof(ev.strArg2) - 1);
                                ev.strArg2[sizeof(ev.strArg2) - 1] = '\0';
                                ev.hasStr2 = true;
                            }
                        }
                    } else if (type == 'd' || type == 'u' || type == 'b') {
                        int val = (int)*pArgs;
                        pArgs++;
                        ev.intArg1 = val;
                        ev.hasInt1 = true;
                    } else if (type == 'f') {
                        // skip double (8 bytes on stack)
                        pArgs += 2;
                    }
                }
                p++;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false; // failed to parse, let original handle it
    }

    AcquireSRWLockExclusive(&g_eventLock);
    g_eventsTotal++;

    if (g_queueCount >= MAX_QUEUED) {
        ReleaseSRWLockExclusive(&g_eventLock);
        return false; // queue full, let it through
    }

    if (IsDuplicate(&ev)) {
        g_eventsDropped++;
        ReleaseSRWLockExclusive(&g_eventLock);
        return true; // Drop duplicate (it's already queued to be dispatched at the end of the frame)
    }

    g_queue[g_queueCount++] = ev;
    ReleaseSRWLockExclusive(&g_eventLock);
    return true; // Defer: return true to skip immediate execution!
}

extern "C" void EventCoalescer_Flush() {
    AcquireSRWLockExclusive(&g_eventLock);
    g_isReplaying = true;
    int count = g_queueCount;
    QueuedEvent localQueue[MAX_QUEUED];
    memcpy(localQueue, g_queue, count * sizeof(QueuedEvent));
    g_queueCount = 0;
    ReleaseSRWLockExclusive(&g_eventLock);

    for (int i = 0; i < count; ++i) {
        if (localQueue[i].used) {
            DispatchSingle(&localQueue[i]);
        }
    }

    AcquireSRWLockExclusive(&g_eventLock);
    g_isReplaying = false;
    ReleaseSRWLockExclusive(&g_eventLock);
}

namespace EventCoalescer {
    const char* EventName(int eventId) { return GetEventName(eventId); }

    bool Init() {
        if (!Config::g_settings.OptEventCoalescer) return false;

        // The detour is installed by LoadingState regardless of this setting; without
        // a live trampoline there is no way to replay queued events, so staying
        // inactive is the only safe option.
        if (!g_origSignalEvent) {
            Log("[EventCoalescer] FrameScript_SignalEvent detour unavailable - staying inactive");
            return false;
        }

        memset(g_queue, 0, sizeof(g_queue));
        EventCoalescer::g_active = true;
        Log("[EventCoalescer] ACTIVE (frame-scoped event deduplication)");
        return true;
    }

    bool TryQueue(int eventId, const char* format, void* vaStart) {
        return TryQueueEvent(eventId, format, vaStart);
    }

    void Shutdown() {
        EventCoalescer::g_active = false;
        if (g_eventsTotal > 0) {
            Log("[EventCoalescer] Stats: Total %u, Dropped %u (%.1f%% reduction)",
                g_eventsTotal, g_eventsDropped,
                100.0 * g_eventsDropped / g_eventsTotal);
        }
    }
}
