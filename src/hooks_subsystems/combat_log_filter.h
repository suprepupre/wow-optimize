#pragma once
#include <windows.h>

namespace CombatLogFilter {
    bool Init();
    void Shutdown();
    void LogStats();

    // True once Init() has accepted the switch. Read on the event-signal path, so
    // it is the flag itself rather than a cross-module call.
    extern bool g_active;
    inline bool IsActive() { return g_active; }

    // The whole decision: is this the combat log event, and should it be dropped.
    // Called from the LoadingState detour, which owns FrameScript_SignalEvent.
    // Returns true if the event must NOT reach the client.
    bool ShouldDrop(int eventId, const char* format, void* vaStart);

    bool ShouldFilterEvent(int eventId, const char* format, va_list args);
}
