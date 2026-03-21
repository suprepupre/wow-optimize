#include "api_cache.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
//  WoW API Result Cache
//
//  GetSpellInfo: 500ms QPC TTL
//    castTime/cost change with haste/talents/gear
//    500ms is imperceptible but picks up buff changes
//
//  GetItemInfo: PERMANENT cache (no TTL)
//    Item data is truly static — name, quality, iLevel etc.
//    never change for a given itemId.
//    Only non-nil results cached (nil = server hasn't sent data yet)
//    Cleared on /reload (lua_State change)
// ================================================================

typedef struct lua_State lua_State;
typedef double lua_Number;
typedef int (__cdecl *ScriptFunc_fn)(lua_State* L);

typedef const char* (__cdecl *fn_lua_tolstring)(lua_State* L, int index, size_t* len);
typedef lua_Number  (__cdecl *fn_lua_tonumber)(lua_State* L, int index);
typedef int         (__cdecl *fn_lua_gettop)(lua_State* L);
typedef int         (__cdecl *fn_lua_type)(lua_State* L, int index);
typedef void        (__cdecl *fn_lua_pushnumber)(lua_State* L, lua_Number n);
typedef void        (__cdecl *fn_lua_pushstring)(lua_State* L, const char* s);
typedef void        (__cdecl *fn_lua_pushboolean)(lua_State* L, int b);
typedef void        (__cdecl *fn_lua_pushnil)(lua_State* L);
typedef int         (__cdecl *fn_lua_toboolean)(lua_State* L, int index);

static fn_lua_tolstring   lua_tolstring_  = (fn_lua_tolstring)0x0084E0E0;
static fn_lua_tonumber    lua_tonumber_   = (fn_lua_tonumber)0x0084E030;
static fn_lua_gettop      lua_gettop_     = (fn_lua_gettop)0x0084DBD0;
static fn_lua_type        lua_type_       = (fn_lua_type)0x0084DEB0;
static fn_lua_pushnumber  lua_pushnumber_ = (fn_lua_pushnumber)0x0084E2A0;
static fn_lua_pushstring  lua_pushstring_ = (fn_lua_pushstring)0x0084E350;
static fn_lua_pushboolean lua_pushboolean_= (fn_lua_pushboolean)0x0084E4D0;
static fn_lua_pushnil     lua_pushnil_    = (fn_lua_pushnil)0x0084E280;
static fn_lua_toboolean   lua_toboolean_  = (fn_lua_toboolean)0x0084E0B0;

#define LUA_TNIL     0
#define LUA_TBOOLEAN 1
#define LUA_TNUMBER  3
#define LUA_TSTRING  4

// ================================================================
//  Addresses — build 12340
// ================================================================

static constexpr uintptr_t ADDR_GetSpellInfo = 0x00540A30;
static constexpr uintptr_t ADDR_GetItemInfo  = 0x00516C60;

static ScriptFunc_fn orig_GetSpellInfo = nullptr;
static ScriptFunc_fn orig_GetItemInfo  = nullptr;

// ================================================================
//  QPC timer
// ================================================================

static double g_qpcFreqMs = 0.0;
static constexpr double SPELL_TTL_MS = 500.0;  // GetSpellInfo: 0.5 sec

static inline double GetNowMs() {
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (double)li.QuadPart / g_qpcFreqMs;
}

// ================================================================
//  Cache structures
// ================================================================

static constexpr int CACHE_SIZE    = 2048;
static constexpr int CACHE_MASK    = CACHE_SIZE - 1;
static constexpr int MAX_RETVALS   = 11;  // GetItemInfo returns up to 11

struct CachedRetVal {
    int    type;
    double numVal;
    char   strVal[128];  // item links can be ~100 chars
};

struct CacheEntry {
    uint32_t     keyHash;
    double       timestamp;   // QPC ms when cached (0 = permanent)
    bool         valid;
    int          retCount;
    int          pushed;
    CachedRetVal vals[MAX_RETVALS];
};

// Separate cache arrays — no collisions between spell and item lookups
static CacheEntry g_spellCache[CACHE_SIZE] = {};
static CacheEntry g_itemCache[CACHE_SIZE]  = {};

// ================================================================
//  Stats
// ================================================================

static long g_spellHits   = 0;
static long g_spellMisses = 0;
static long g_itemHits    = 0;
static long g_itemMisses  = 0;
static bool g_active      = false;

// ================================================================
//  Hash
// ================================================================

static inline uint32_t HashStr(const char* s) {
    uint32_t h = 0x811C9DC5;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 0x01000193;
    }
    return h;
}

// ================================================================
//  Shared: store return values from stack into cache entry
// ================================================================

static void CaptureReturnValues(lua_State* L, CacheEntry* e,
                                 uint32_t keyHash, double timestamp,
                                 int retCount, int topBefore, int pushed)
{
    e->keyHash   = keyHash;
    e->timestamp = timestamp;
    e->valid     = true;
    e->retCount  = retCount;
    e->pushed    = pushed;

    for (int i = 0; i < pushed; i++) {
        int stackIdx = topBefore + 1 + i;
        int t = lua_type_(L, stackIdx);

        e->vals[i].type      = t;
        e->vals[i].numVal    = 0.0;
        e->vals[i].strVal[0] = '\0';

        switch (t) {
            case LUA_TSTRING: {
                const char* s = lua_tolstring_(L, stackIdx, NULL);
                if (s) {
                    strncpy(e->vals[i].strVal, s, sizeof(e->vals[i].strVal) - 1);
                    e->vals[i].strVal[sizeof(e->vals[i].strVal) - 1] = '\0';
                } else {
                    e->vals[i].type = LUA_TNIL;
                }
                break;
            }
            case LUA_TNUMBER:
                e->vals[i].numVal = lua_tonumber_(L, stackIdx);
                break;
            case LUA_TBOOLEAN:
                e->vals[i].numVal = (double)lua_toboolean_(L, stackIdx);
                break;
        }
    }
}

// ================================================================
//  Shared: replay cached values onto Lua stack
// ================================================================

static inline void ReplayCachedValues(lua_State* L, CacheEntry* e) {
    for (int i = 0; i < e->pushed; i++) {
        switch (e->vals[i].type) {
            case LUA_TSTRING:  lua_pushstring_(L, e->vals[i].strVal);       break;
            case LUA_TNUMBER:  lua_pushnumber_(L, e->vals[i].numVal);       break;
            case LUA_TBOOLEAN: lua_pushboolean_(L, (int)e->vals[i].numVal); break;
            default:           lua_pushnil_(L);                              break;
        }
    }
}

// ================================================================
//  Hook: GetSpellInfo — 500ms TTL
//
//  Returns: name, rank, icon, cost, isFunnel, powerType,
//           castTime, minRange, maxRange  (9 values)
// ================================================================

static int __cdecl Hooked_GetSpellInfo(lua_State* L) {
    uint32_t keyHash;
    int argType = lua_type_(L, 1);

    if (argType == LUA_TNUMBER) {
        keyHash = (uint32_t)lua_tonumber_(L, 1);
    } else if (argType == LUA_TSTRING) {
        const char* name = lua_tolstring_(L, 1, NULL);
        if (!name) return orig_GetSpellInfo(L);
        keyHash = HashStr(name);
    } else {
        return orig_GetSpellInfo(L);
    }

    int slot = keyHash & CACHE_MASK;
    CacheEntry* e = &g_spellCache[slot];
    double now = GetNowMs();

    // Cache hit with TTL check
    if (e->valid && e->keyHash == keyHash &&
        (now - e->timestamp) < SPELL_TTL_MS)
    {
        ReplayCachedValues(L, e);
        g_spellHits++;
        return e->retCount;
    }

    // Miss or expired
    int topBefore = lua_gettop_(L);
    int ret = orig_GetSpellInfo(L);
    int topAfter = lua_gettop_(L);
    int pushed = topAfter - topBefore;

    if (pushed >= 0 && pushed <= MAX_RETVALS) {
        CaptureReturnValues(L, e, keyHash, now, ret, topBefore, pushed);
    }

    g_spellMisses++;
    return ret;
}

// ================================================================
//  Hook: GetItemInfo — PERMANENT cache
//
//  Returns: name, link, quality, iLevel, reqLevel, class,
//           subclass, maxStack, equipSlot, texture, vendorPrice
//           (11 values)
//
//  IMPORTANT: Do NOT cache nil results.
//  GetItemInfo returns nil when item data hasn't loaded from
//  server yet. Caching nil would permanently block that item.
// ================================================================

static int __cdecl Hooked_GetItemInfo(lua_State* L) {
    uint32_t keyHash;
    int argType = lua_type_(L, 1);

    if (argType == LUA_TNUMBER) {
        keyHash = (uint32_t)lua_tonumber_(L, 1);
    } else if (argType == LUA_TSTRING) {
        const char* name = lua_tolstring_(L, 1, NULL);
        if (!name) return orig_GetItemInfo(L);
        keyHash = HashStr(name);
    } else {
        return orig_GetItemInfo(L);
    }

    int slot = keyHash & CACHE_MASK;
    CacheEntry* e = &g_itemCache[slot];

    // Cache hit — permanent, no TTL check
    if (e->valid && e->keyHash == keyHash) {
        ReplayCachedValues(L, e);
        g_itemHits++;
        return e->retCount;
    }

    // Miss
    int topBefore = lua_gettop_(L);
    int ret = orig_GetItemInfo(L);
    int topAfter = lua_gettop_(L);
    int pushed = topAfter - topBefore;

    // Only cache if something was returned (not nil/empty)
    // This prevents permanently caching "item not loaded yet" responses
    if (pushed > 0 && pushed <= MAX_RETVALS) {
        // Extra check: first return value should be a string (item name)
        // If it's nil, the item data isn't loaded yet — don't cache
        if (lua_type_(L, topBefore + 1) == LUA_TSTRING) {
            CaptureReturnValues(L, e, keyHash, 0.0, ret, topBefore, pushed);
        }
    }

    g_itemMisses++;
    return ret;
}

// ================================================================
//  Hook installation helper
// ================================================================

static bool HookFunc(const char* name, uintptr_t addr, void* hookFn, void** origFn) {
    MH_STATUS s = MH_CreateHook((void*)addr, hookFn, origFn);
    if (s != MH_OK) {
        Log("[ApiCache]   %-25s MH_CreateHook failed (%d)", name, (int)s);
        return false;
    }
    s = MH_EnableHook((void*)addr);
    if (s != MH_OK) {
        Log("[ApiCache]   %-25s MH_EnableHook failed (%d)", name, (int)s);
        return false;
    }
    Log("[ApiCache]   %-25s 0x%08X  [ OK ]", name, (unsigned)addr);
    return true;
}

// ================================================================
//  Public API
// ================================================================

namespace ApiCache {

bool Init() {
    Log("[ApiCache] ====================================");
    Log("[ApiCache]  WoW API Result Cache");
    Log("[ApiCache]  Build 12340");
    Log("[ApiCache] ====================================");

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    g_qpcFreqMs = (double)freq.QuadPart / 1000.0;

    int hooked = 0;

    if (HookFunc("GetSpellInfo", ADDR_GetSpellInfo, (void*)Hooked_GetSpellInfo, (void**)&orig_GetSpellInfo))
        hooked++;

    if (HookFunc("GetItemInfo",  ADDR_GetItemInfo,  (void*)Hooked_GetItemInfo,  (void**)&orig_GetItemInfo))
        hooked++;

    if (hooked == 0) {
        Log("[ApiCache]  DISABLED — no hooks installed");
        return false;
    }

    g_active = true;

    Log("[ApiCache] ====================================");
    Log("[ApiCache]  Hooks: %d/2 active", hooked);
    Log("[ApiCache]  GetSpellInfo: %d slots, TTL %.0fms", CACHE_SIZE, SPELL_TTL_MS);
    Log("[ApiCache]  GetItemInfo:  %d slots, permanent (nil not cached)", CACHE_SIZE);
    Log("[ApiCache]  [ OK ] ACTIVE");
    Log("[ApiCache] ====================================");
    return true;
}

void Shutdown() {
    if (!g_active) return;

    MH_DisableHook((void*)ADDR_GetSpellInfo);
    MH_DisableHook((void*)ADDR_GetItemInfo);

    g_active = false;

    long spellTotal = g_spellHits + g_spellMisses;
    long itemTotal  = g_itemHits  + g_itemMisses;

    if (spellTotal > 0) {
        Log("[ApiCache] GetSpellInfo: %ld hits, %ld misses (%.1f%% hit rate)",
            g_spellHits, g_spellMisses, (double)g_spellHits / spellTotal * 100.0);
    }
    if (itemTotal > 0) {
        Log("[ApiCache] GetItemInfo:  %ld hits, %ld misses (%.1f%% hit rate)",
            g_itemHits, g_itemMisses, (double)g_itemHits / itemTotal * 100.0);
    }
}

void OnNewFrame() {
    // No-op — GetSpellInfo uses QPC TTL, GetItemInfo is permanent
}

void ClearCache() {
    memset(g_spellCache, 0, sizeof(g_spellCache));
    memset(g_itemCache,  0, sizeof(g_itemCache));
    Log("[ApiCache] Cache cleared (spell: %d, item: %d entries)", CACHE_SIZE, CACHE_SIZE);
}

Stats GetStats() {
    Stats s;
    s.hits   = g_spellHits + g_itemHits;
    s.misses = g_spellMisses + g_itemMisses;
    s.active = g_active;
    return s;
}

} // namespace ApiCache