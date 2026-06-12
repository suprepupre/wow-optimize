// ================================================================
// Tooltip Cache - Caches formatted tooltip strings for items/spells
// ================================================================
// sub_6277F0 (24,838 bytes) generates item tooltips by formatting
// strings like "ITEM_HEROIC_EPIC", "ITEM_QUALITY%d_DESC" etc.
// Repeatedly called for the same item when hovering in bags/inventory.
//
// We cache the final formatted tooltip text keyed by (itemID, flags)
// to skip the expensive formatting on subsequent hovers.
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "tooltip_cache.h"

extern "C" void Log(const char* fmt, ...);

namespace TooltipCache {

// ================================================================
// Cache Configuration
// ================================================================
static constexpr int CACHE_SIZE     = 512;
static constexpr int MAX_LEN        = 4096;
static constexpr DWORD TTL_MS       = 30000;    // 30 second TTL

// ================================================================
// Cache Entry
// ================================================================
struct Entry {
    uint32_t key;
    DWORD    lastAccess;
    uint16_t len;
    bool     valid;
    char     data[MAX_LEN];
};

static Entry g_cache[CACHE_SIZE];
static volatile LONG64 g_hits = 0;
static volatile LONG64 g_misses = 0;
static volatile LONG64 g_evictions = 0;

// ================================================================
// Hash Function (FNV-1a)
// ================================================================
uint32_t Hash(uint32_t itemID, uint32_t flags, uint32_t extra) {
    uint32_t h = 0x811c9dc5u;
    h ^= itemID;  h *= 0x01000193u;
    h ^= flags;   h *= 0x01000193u;
    h ^= extra;   h *= 0x01000193u;
    return h;
}

// ================================================================
// Cache Operations
// ================================================================
const char* Get(uint32_t key, int* outLen) {
    uint32_t idx = key & (CACHE_SIZE - 1);
    Entry* e = &g_cache[idx];

    if (e->valid && e->key == key) {
        DWORD now = GetTickCount();
        if ((now - e->lastAccess) < TTL_MS) {
            e->lastAccess = now;
            *outLen = e->len;
            InterlockedIncrement64(&g_hits);
            return e->data;
        }
        e->valid = false;
    }
    InterlockedIncrement64(&g_misses);
    return nullptr;
}

void Put(uint32_t key, const char* text, int len) {
    if (!text || len <= 0 || len >= MAX_LEN) return;

    uint32_t idx = key & (CACHE_SIZE - 1);
    Entry* e = &g_cache[idx];

    if (e->valid && e->key != key) {
        InterlockedIncrement64(&g_evictions);
    }

    e->key = key;
    e->len = (uint16_t)len;
    e->lastAccess = GetTickCount();
    memcpy(e->data, text, len);
    e->data[len] = '\0';
    e->valid = true;
}

void Clear() {
    memset(g_cache, 0, sizeof(g_cache));
}

Stats GetStats() {
    Stats s = {};
    s.hits = g_hits;
    s.misses = g_misses;
    s.evictions = g_evictions;
    int64_t total = s.hits + s.misses;
    s.hitRate = total > 0 ? 100.0 * s.hits / total : 0.0;
    return s;
}

// ================================================================
// Install / Shutdown
// ================================================================
bool Install() {
    memset(g_cache, 0, sizeof(g_cache));

    Log("[TooltipCache] Initialized (%d slots, %d max len, %ds TTL)",
        CACHE_SIZE, MAX_LEN, TTL_MS / 1000);

    // NOTE: Full hooking of sub_6277F0 requires __thiscall naked asm
    // wrapper due to 16-parameter signature. Cache API is available
    // for integration via other hooks (e.g., FrameScript injection).
    // The cache provides O(1) lookup for repeated tooltip queries.

    return true;
}

void Shutdown() {
    Stats s = GetStats();
    if (s.hits + s.misses > 0) {
        Log("[TooltipCache] Stats: %lld hits, %lld misses (%.1f%% hit rate), %lld evictions",
            s.hits, s.misses, s.hitRate, s.evictions);
    }
}

} // namespace TooltipCache