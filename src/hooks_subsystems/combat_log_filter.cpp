// ============================================================================
// Module: combat_log_filter.cpp
// Description: Drops COMBAT_LOG_EVENT_UNFILTERED by affiliation before it reaches
//              Lua. Only reachable through the event coalescer.
//
// What this actually does, as opposed to what the launcher used to claim: it
// reads the source and destination affiliation flags out of the varargs and drops
// the event unless one of them is MINE, PARTY or RAID (mask 0x7). It has no
// knowledge of what any addon subscribed to.
//
// So it is not a free reduction in work. Everything below stops reaching addons:
//   * arena and battleground opponents fighting each other - both are OUTSIDER,
//   * boss abilities aimed at other NPCs, and add-on-add damage,
//   * anything at all between two units outside the player's group.
//
// A damage meter under-reports, and an arena addon watching an opponent's
// cooldowns sees nothing. That is a behaviour change, not an optimisation, which
// is why it is off by default and why the description says so plainly now.
//
// The vararg walk assumes the 3.3.5a COMBAT_LOG_EVENT_UNFILTERED prefix -
// timestamp, event, sourceGUID, sourceName, sourceFlags, destGUID, destName,
// destFlags - and reads the GUID width from the format string because it varies.
// It is wrapped in __try because a format that does not match would otherwise
// walk off the stack; on any exception it declines to filter.
// ============================================================================

#include "combat_log_filter.h"
#include "event_coalescer.h"
#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

extern "C" void Log(const char* fmt, ...);

namespace CombatLogFilter {
    bool g_active = false;
    static bool g_enabled = true;
    static unsigned int g_filteredCount = 0;
    static unsigned int g_seenCount     = 0;

    // Which event ids are COMBAT_LOG_EVENT_UNFILTERED. The client hands out ids
    // per session, so this is resolved by name on first sight and remembered:
    // 0 unknown, 1 yes, -1 no.
    static signed char g_isCombatEvent[2048] = { 0 };

    bool Init() {
        if (!Config::g_settings.OptCombatLogFilter) {
            g_active = false;
            return true;
        }
        g_active = true;
        Log("[CombatLogFilter] ACTIVE. Drops COMBAT_LOG_EVENT_UNFILTERED unless the "
            "source or the target is you, your party or your raid. This runs from "
            "the FrameScript_SignalEvent detour and no longer needs the event "
            "coalescer, which is where it used to live - with that feature off, "
            "which is its default, ticking this box did nothing at all. It is a "
            "behaviour change, not a free saving: arena and battleground opponents "
            "fighting each other, boss abilities aimed at other NPCs and anything "
            "between two units outside your group stop reaching addons.");
        return true;
    }

    void Shutdown() {
        g_active = false;
    }

    void LogStats() {
        if (!Config::g_settings.OptCombatLogFilter) return;
        if (!g_active)       { Log("[CombatLogFilter] not active - nothing filtered"); return; }
        if (g_seenCount == 0) {
            Log("[CombatLogFilter] active, but no combat log event has been seen yet");
            return;
        }
        Log("[CombatLogFilter] %u combat log events seen, %u dropped (%.1f%%) as "
            "involving neither you nor your group. Counts are lower bounds.",
            g_seenCount, g_filteredCount,
            100.0 * (double)g_filteredCount / (double)g_seenCount);
    }

    bool ShouldDrop(int eventId, const char* format, void* vaStart) {
        if (!g_active) return false;
        if (eventId < 0 || eventId >= 2048) return false;

        if (g_isCombatEvent[eventId] == 0) {
            const char* name = EventCoalescer::EventName(eventId);
            if (!name) return false;   // unresolved; try again next time
            g_isCombatEvent[eventId] =
                (strcmp(name, "COMBAT_LOG_EVENT_UNFILTERED") == 0) ? 1 : -1;
        }
        if (g_isCombatEvent[eventId] != 1) return false;

        g_seenCount++;
        return ShouldFilterEvent(eventId, format, (va_list)vaStart);
    }

    bool ShouldFilterEvent(int eventId, const char* format, va_list args) {
        if (!g_enabled) return false;

        // We only filter if the format string looks like a standard combat log event
        // In 3.3.5a: "d s d s i d s i ..." or similar (timestamp, event, sourceGUID, sourceName, sourceFlags, ...)
        if (format && strlen(format) >= 8) {
            // Check if format begins with 'd' (timestamp), 's' (event type)
            if (format[0] == 'd' && format[1] == 's') {
                va_list argsCopy;
                va_copy(argsCopy, args);

                __try {
                    // 1. Timestamp (double)
                    va_arg(argsCopy, double);
                    // 2. Event type (string)
                    va_arg(argsCopy, const char*);
                    
                    // 3. Source GUID (could be double/uint64 or string/hex depending on context)
                    if (format[2] == 'd') {
                        va_arg(argsCopy, double);
                    } else if (format[2] == 's') {
                        va_arg(argsCopy, const char*);
                    } else {
                        va_arg(argsCopy, unsigned __int64);
                    }

                    // 4. Source Name (string)
                    va_arg(argsCopy, const char*);

                    // 5. Source Flags (int)
                    int sourceFlags = va_arg(argsCopy, int);

                    // 6. Dest GUID
                    if (format[5] == 'd') {
                        va_arg(argsCopy, double);
                    } else if (format[5] == 's') {
                        va_arg(argsCopy, const char*);
                    } else {
                        va_arg(argsCopy, unsigned __int64);
                    }

                    // 7. Dest Name (string)
                    va_arg(argsCopy, const char*);

                    // 8. Dest Flags (int)
                    int destFlags = va_arg(argsCopy, int);

                    // Check if either belongs to player, party, or raid
                    // COMBATLOG_OBJECT_AFFILIATION_MINE      = 0x00000001
                    // COMBATLOG_OBJECT_AFFILIATION_PARTY     = 0x00000002
                    // COMBATLOG_OBJECT_AFFILIATION_RAID      = 0x00000004
                    bool sourceIsRelevant = (sourceFlags & 0x00000007) != 0;
                    bool destIsRelevant = (destFlags & 0x00000007) != 0;

                    if (!sourceIsRelevant && !destIsRelevant) {
                        g_filteredCount++;
                        va_end(argsCopy);
                        return true; // Filter this event!
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    // Safe fallback: do not filter on error
                }
                va_end(argsCopy);
            }
        }

        return false;
    }
}
