#include "api_cache.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
//  WoW API Result Cache — GetSpellInfo Time-Based Cache
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
//  QPC timer for TTL
// ================================================================

static double g_qpcFreqMs = 0.0;
static constexpr double CACHE_TTL_MS = 500.0;  // 0.5 seconds

static inline double GetNowMs() {
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (double)li.QuadPart / g_qpcFreqMs;
}

// ================================================================
//  Cache
// ================================================================

static constexpr int CACHE_SIZE    = 2048;
static constexpr int CACHE_MASK    = CACHE_SIZE - 1;
static constexpr int MAX_RETVALS   = 9;

struct CachedRetVal {
    int    type;
    double numVal;
    char   strVal[96];
};

struct SpellCacheEntry {
    uint32_t     keyHash;
    double       timestamp;    // QPC milliseconds when cached
    bool         valid;
    int          retCount;
    int          pushed;
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
    SpellCacheEntry* e = &g_cache[slot];
    double now = GetNowMs();

    // ---- Cache hit: check key match AND time-based TTL ----
    if (e->valid && e->keyHash == keyHash &&
        (now - e->timestamp) < CACHE_TTL_MS)
    {
        for (int i = 0; i < e->pushed; i++) {
            switch (e->vals[i].type) {
                case LUA_TSTRING:  lua_pushstring_(L, e->vals[i].strVal);       break;
                case LUA_TNUMBER:  lua_pushnumber_(L, e->vals[i].numVal);       break;
                case LUA_TBOOLEAN: lua_pushboolean_(L, (int)e->vals[i].numVal); break;
                default:           lua_pushnil_(L);                              break;
            }
        }
        g_hits++;
        return e->retCount;
    }

    // ---- Cache miss or expired — call original ----
    int topBefore = lua_gettop_(L);
    int ret = orig_GetSpellInfo(L);
    int topAfter = lua_gettop_(L);
    int pushed = topAfter - topBefore;

    if (pushed < 0 || pushed > MAX_RETVALS) {
        g_misses++;
        return ret;
    }

    e->keyHash   = keyHash;
    e->timestamp = now;
    e->valid     = true;
    e->retCount  = ret;
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

    // Init QPC frequency
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    g_qpcFreqMs = (double)freq.QuadPart / 1000.0;

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
    Log("[ApiCache]  Cache: %d slots, TTL %.0fms (QPC-based)", CACHE_SIZE, CACHE_TTL_MS);
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
    // No-op — using QPC-based TTL, no frame counter needed
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