// ================================================================
// Event Name Lookup Cache
// ================================================================
// Provides O(1) event name → event index lookup for FrameScript.
// No hooks - pure utility cache called from existing hooks.
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <atomic>
#include "event_name_cache.h"

extern "C" void Log(const char* fmt, ...);

// ----------------------------------------------------------------
// FNV-1a 32-bit hash (compile-time evaluable)
// ----------------------------------------------------------------
static constexpr uint32_t fnv1a(const char* s) {
    uint32_t h = 0x811c9dc5u;
    while (*s) {
        h ^= static_cast<uint8_t>(*s++);
        h *= 0x01000193u;
    }
    return h;
}

// ----------------------------------------------------------------
// Statistics
// ----------------------------------------------------------------
static std::atomic<uint64_t> g_total_lookups{0};
static std::atomic<uint64_t> g_cache_hits{0};

// ----------------------------------------------------------------
// Cache structure
// ----------------------------------------------------------------
static constexpr int EVENT_CACHE_SIZE = 256;
static constexpr int EVENT_CACHE_MASK = EVENT_CACHE_SIZE - 1;

struct EventCacheEntry {
    uint32_t hash;
    int      event_index;
    bool     valid;
};

static EventCacheEntry g_event_cache[EVENT_CACHE_SIZE];

// ----------------------------------------------------------------
// Lookup event index by name (with caching)
// Returns cached index if available, otherwise -1 (cache miss).
// ----------------------------------------------------------------
int LookupCachedEventIndex(const char* eventName)
{
    if (!eventName || !*eventName) return -1;

    g_total_lookups.fetch_add(1, std::memory_order_relaxed);

    uint32_t h = fnv1a(eventName);
    int slot = (int)(h & EVENT_CACHE_MASK);
    EventCacheEntry* e = &g_event_cache[slot];

    if (e->valid && e->hash == h) {
        g_cache_hits.fetch_add(1, std::memory_order_relaxed);
        return e->event_index;
    }

    return -1;
}

// ----------------------------------------------------------------
// Store event index in cache after successful lookup
// ----------------------------------------------------------------
void CacheEventIndex(const char* eventName, int eventIndex)
{
    if (!eventName || !*eventName || eventIndex < 0) return;

    uint32_t h = fnv1a(eventName);
    int slot = (int)(h & EVENT_CACHE_MASK);
    EventCacheEntry* e = &g_event_cache[slot];

    e->hash = h;
    e->event_index = eventIndex;
    e->valid = true;
}

// ----------------------------------------------------------------
// Install / Uninstall
// ----------------------------------------------------------------
bool InstallEventNameCache()
{
    memset(g_event_cache, 0, sizeof(g_event_cache));
    Log("[EventNameCache] Initialized: %d-slot cache for event name lookups", EVENT_CACHE_SIZE);
    return true;
}

void UninstallEventNameCache()
{
    uint64_t total = g_total_lookups.load();
    uint64_t hits = g_cache_hits.load();
    if (total > 0) {
        Log("[EventNameCache] Stats: %llu lookups, %llu hits (%.1f%% hit rate)",
            total, hits, total ? 100.0 * hits / total : 0.0);
    }
}