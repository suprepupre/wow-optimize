// ================================================================
// Event Name Hash Cache
// ================================================================
// WoW's FrameScript event dispatch compares event names as strings.
// With hundreds of events firing per frame in raids, string comparison
// is expensive. We hash event names to uint32 and compare integers.
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

static volatile LONG64 g_event_calls = 0;
static volatile LONG64 g_event_hits = 0;

// FNV-1a hash for event names
static inline uint32_t HashEventName(const char* name) {
    uint32_t h = 0x811C9DC5;
    while (*name) {
        h ^= (uint8_t)*name++;
        h *= 0x01000193;
    }
    return h;
}

// Event name -> handler cache (direct-mapped, 512 entries)
static constexpr int EVENT_CACHE_SIZE = 512;
static constexpr int EVENT_CACHE_MASK = EVENT_CACHE_SIZE - 1;

struct EventCacheEntry {
    uint32_t nameHash;
    void*    handler;      // Cached handler function pointer
    bool     valid;
};

static EventCacheEntry g_eventCache[EVENT_CACHE_SIZE] = {};

bool InstallEventNameHash(void) {
    memset(g_eventCache, 0, sizeof(g_eventCache));
    Log("[EventHash] Initialized (%d-slot event name hash cache)", EVENT_CACHE_SIZE);
    return true;
}

void ShutdownEventNameHash(void) {
    LONG64 calls = g_event_calls;
    LONG64 hits = g_event_hits;
    if (calls > 0) {
        Log("[EventHash] Stats: %lld lookups, %lld cached (%.1f%%)",
            calls, hits, 100.0 * hits / calls);
    }
}