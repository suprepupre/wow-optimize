#include "api_cache.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

// WoW API result cache for build 12340.

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

static constexpr uintptr_t ADDR_GetItemInfo  = 0x00516C60;

static ScriptFunc_fn orig_GetItemInfo  = nullptr;

// Cache structures.

static constexpr int CACHE_SIZE    = 2048;
static constexpr int CACHE_MASK    = CACHE_SIZE - 1;
static constexpr int MAX_RETVALS   = 11;  // GetItemInfo returns up to 11

struct CachedRetVal {
    int    type;
    double numVal;
    char   strVal[512];
};

struct CacheEntry {
    uint32_t     keyHash;
    bool         valid;
    int          retCount;
    int          pushed;
    CachedRetVal vals[MAX_RETVALS];
};

static CacheEntry g_itemCache[CACHE_SIZE]  = {};

static long g_itemHits    = 0;
static long g_itemMisses  = 0;
static bool g_active      = false;

static inline uint32_t HashStr(const char* s) {
    uint32_t h = 0x811C9DC5;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 0x01000193;
    }
    return h;
}

static void CaptureReturnValues(lua_State* L, CacheEntry* e,
                                 uint32_t keyHash,
                                 int retCount, int topBefore, int pushed)
{
    e->keyHash   = keyHash;
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
                size_t slen = 0;
                const char* s = lua_tolstring_(L, stackIdx, &slen);
                if (s && slen < sizeof(e->vals[i].strVal)) {
                    memcpy(e->vals[i].strVal, s, slen);
                    e->vals[i].strVal[slen] = '\0';
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

// Do not cache nil or partial results.
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

    if (e->valid && e->keyHash == keyHash) {
        ReplayCachedValues(L, e);
        g_itemHits++;
        return e->retCount;
    }

    int topBefore = lua_gettop_(L);
    int ret = orig_GetItemInfo(L);
    int topAfter = lua_gettop_(L);
    int pushed = topAfter - topBefore;

    if (pushed >= 10 && pushed <= MAX_RETVALS) {
        if (lua_type_(L, topBefore + 1) == LUA_TSTRING &&
            lua_type_(L, topBefore + 2) == LUA_TSTRING) {
            CaptureReturnValues(L, e, keyHash, ret, topBefore, pushed);
        }
    }

    g_itemMisses++;
    return ret;
}

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

namespace ApiCache {

bool Init() {
    Log("[ApiCache] Init (build 12340)");

    int hooked = 0;

    if (HookFunc("GetItemInfo", ADDR_GetItemInfo, (void*)Hooked_GetItemInfo, (void**)&orig_GetItemInfo))
        hooked++;

    if (hooked == 0) {
        Log("[ApiCache]  DISABLED — no hooks installed");
        return false;
    }

    g_active = true;

    Log("[ApiCache] Hooks: %d/1 active | GetItemInfo: %d slots | GetSpellInfo: disabled", hooked, CACHE_SIZE);
    return true;
}

void Shutdown() {
    if (!g_active) return;

    MH_DisableHook((void*)ADDR_GetItemInfo);

    g_active = false;

    long itemTotal  = g_itemHits  + g_itemMisses;

    if (itemTotal > 0) {
        Log("[ApiCache] GetItemInfo: %ld hits, %ld misses (%.1f%% hit rate)",
            g_itemHits, g_itemMisses, (double)g_itemHits / itemTotal * 100.0);
    }
}

void OnNewFrame() {
    // no-op
}

void ClearCache() {
    memset(g_itemCache,  0, sizeof(g_itemCache));
    Log("[ApiCache] Cache cleared (item: %d entries)", CACHE_SIZE);
}

Stats GetStats() {
    Stats s;
    s.hits   = g_itemHits;
    s.misses = g_itemMisses;
    s.active = g_active;
    return s;
}

} // namespace ApiCache