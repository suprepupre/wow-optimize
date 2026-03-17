#include "api_cache.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
//  WoW API Result Cache — GetSpellInfo Permanent Cache
//
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
//  GetSpellInfo address — build 12340
// ================================================================

static constexpr uintptr_t ADDR_GetSpellInfo = 0x00540A30;

static ScriptFunc_fn orig_GetSpellInfo = nullptr;

// ================================================================
//  Cache
// ================================================================

static constexpr int CACHE_SIZE    = 2048;
static constexpr int CACHE_MASK    = CACHE_SIZE - 1;
static constexpr int MAX_RETVALS   = 9;

// Generic cached return value — handles string, number, boolean, nil
struct CachedRetVal {
    int    type;         // LUA_TSTRING, LUA_TNUMBER, LUA_TBOOLEAN, LUA_TNIL
    double numVal;       // numbers and booleans (bool stored as 0.0/1.0)
    char   strVal[96];   // strings (name max ~50, rank ~15, icon ~80)
};

struct SpellCacheEntry {
    uint32_t     keyHash;   // spellId or FNV-1a of spell name
    bool         valid;     // entry populated
    int          retCount;  // original C function return value
    int          pushed;    // actual values pushed (measured via gettop)
    CachedRetVal vals[MAX_RETVALS];
};

static SpellCacheEntry g_cache[CACHE_SIZE] = {};

// ================================================================
//  Stats
// ================================================================

static long g_hits   = 0;
static long g_misses = 0;
static bool g_active = false;

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
//  Hook: GetSpellInfo(spellId_or_name)
//
//  Returns: name, rank, icon, cost, isFunnel, powerType,
//           castTime, minRange, maxRange  (9 values)
//  Or: nothing (0 pushed) if spell doesn't exist
// ================================================================

static int __cdecl Hooked_GetSpellInfo(lua_State* L) {
    // Compute cache key from argument 1
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
    SpellCacheEntry* e = &g_cache[slot];

    // ---- Cache hit ----
    if (e->valid && e->keyHash == keyHash) {
        // Replay all cached values in original order
        for (int i = 0; i < e->pushed; i++) {
            switch (e->vals[i].type) {
                case LUA_TSTRING:  lua_pushstring_(L, e->vals[i].strVal);          break;
                case LUA_TNUMBER:  lua_pushnumber_(L, e->vals[i].numVal);          break;
                case LUA_TBOOLEAN: lua_pushboolean_(L, (int)e->vals[i].numVal);    break;
                default:           lua_pushnil_(L);                                 break;
            }
        }
        g_hits++;
        return e->retCount;
    }

    // ---- Cache miss — call original, capture results ----
    int topBefore = lua_gettop_(L);
    int ret = orig_GetSpellInfo(L);
    int topAfter = lua_gettop_(L);
    int pushed = topAfter - topBefore;

    // Don't cache unexpected return counts
    if (pushed < 0 || pushed > MAX_RETVALS) {
        g_misses++;
        return ret;
    }

    // Store in cache
    e->keyHash  = keyHash;
    e->valid    = true;
    e->retCount = ret;
    e->pushed   = pushed;

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
            // LUA_TNIL: defaults are fine
        }
    }

    g_misses++;
    return ret;
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

    MH_STATUS s = MH_CreateHook((void*)ADDR_GetSpellInfo,
                                 (void*)Hooked_GetSpellInfo,
                                 (void**)&orig_GetSpellInfo);
    if (s != MH_OK) {
        Log("[ApiCache]   GetSpellInfo              MH_CreateHook failed (%d)", (int)s);
        Log("[ApiCache]  DISABLED");
        return false;
    }

    s = MH_EnableHook((void*)ADDR_GetSpellInfo);
    if (s != MH_OK) {
        Log("[ApiCache]   GetSpellInfo              MH_EnableHook failed (%d)", (int)s);
        Log("[ApiCache]  DISABLED");
        return false;
    }

    Log("[ApiCache]   GetSpellInfo              0x%08X  [ OK ]", (unsigned)ADDR_GetSpellInfo);

    g_active = true;

    Log("[ApiCache] ====================================");
    Log("[ApiCache]  Hooks: 1 active (GetSpellInfo)");
    Log("[ApiCache]  Cache: %d-slot permanent (cleared on /reload)", CACHE_SIZE);
    Log("[ApiCache]  [ OK ] ACTIVE");
    Log("[ApiCache] ====================================");
    return true;
}

void Shutdown() {
    if (!g_active) return;
    MH_DisableHook((void*)ADDR_GetSpellInfo);
    g_active = false;

    long total = g_hits + g_misses;
    if (total > 0) {
        Log("[ApiCache] Shutdown: %ld hits, %ld misses (%.1f%% hit rate)",
            g_hits, g_misses, (double)g_hits / total * 100.0);
    }
}

void OnNewFrame() {
    // No-op — GetSpellInfo cache is permanent (not per-frame)
    // Reserved for future event-based cache invalidation
}

void ClearCache() {
    memset(g_cache, 0, sizeof(g_cache));
    Log("[ApiCache] Cache cleared (%d entries)", CACHE_SIZE);
}

Stats GetStats() {
    Stats s;
    s.hits   = g_hits;
    s.misses = g_misses;
    s.active = g_active;
    return s;
}

} // namespace ApiCache