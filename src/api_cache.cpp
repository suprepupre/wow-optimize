#include "api_cache.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
//  Lua API — known addresses build 12340
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

static fn_lua_tolstring   lua_tolstring  = (fn_lua_tolstring)0x0084E0E0;
static fn_lua_tonumber    lua_tonumber_  = (fn_lua_tonumber)0x0084E030;
static fn_lua_gettop      lua_gettop_    = (fn_lua_gettop)0x0084DBD0;
static fn_lua_type        lua_type_      = (fn_lua_type)0x0084DEB0;
static fn_lua_pushnumber  lua_pushnumber_= (fn_lua_pushnumber)0x0084E2A0;
static fn_lua_pushstring  lua_pushstring_= (fn_lua_pushstring)0x0084E350;
static fn_lua_pushboolean lua_pushboolean_=(fn_lua_pushboolean)0x0084E4D0;
static fn_lua_pushnil     lua_pushnil_   = (fn_lua_pushnil)0x0084E280;

#define LUA_TNIL     0
#define LUA_TBOOLEAN 1
#define LUA_TNUMBER  3
#define LUA_TSTRING  4

// ================================================================
//  WoW API addresses — build 12340
// ================================================================

namespace Addr {
    static constexpr uintptr_t UnitHealth          = 0x0060EB60;
    static constexpr uintptr_t UnitHealthMax       = 0x0060EC60;
    static constexpr uintptr_t UnitPower           = 0x0060ED40;
    static constexpr uintptr_t UnitPowerMax        = 0x0060EF40;
    static constexpr uintptr_t UnitExists          = 0x0060C2A0;
    static constexpr uintptr_t UnitIsDeadOrGhost   = 0x0060F680;
    static constexpr uintptr_t UnitAffectingCombat = 0x0060F860;
    static constexpr uintptr_t UnitCanAttack       = 0x0060D730;
    static constexpr uintptr_t UnitGUID            = 0x0060E630;
}

// ================================================================
//  Frame generation counter
// ================================================================

static uint32_t g_frameGen = 0;

// ================================================================
//  Cache structures
// ================================================================

static constexpr int CACHE_SIZE = 256;
static constexpr int CACHE_MASK = CACHE_SIZE - 1;

struct NumCacheEntry {
    uint32_t gen;
    uint32_t hash;
    double   value;
};

struct BoolCacheEntry {
    uint32_t gen;
    uint32_t hash;
    int      value;
    bool     isNil;
};

struct StrCacheEntry {
    uint32_t gen;
    uint32_t hash;
    char     value[72];
    bool     isNil;
};

static NumCacheEntry  g_healthCache[CACHE_SIZE] = {};
static NumCacheEntry  g_healthMaxCache[CACHE_SIZE] = {};
static NumCacheEntry  g_powerCache[CACHE_SIZE] = {};
static NumCacheEntry  g_powerMaxCache[CACHE_SIZE] = {};
static BoolCacheEntry g_existsCache[CACHE_SIZE] = {};
static BoolCacheEntry g_deadCache[CACHE_SIZE] = {};
static BoolCacheEntry g_combatCache[CACHE_SIZE] = {};
static BoolCacheEntry g_canAttackCache[CACHE_SIZE] = {};
static StrCacheEntry  g_guidCache[CACHE_SIZE] = {};

// ================================================================
//  Stats
// ================================================================

static long g_hits = 0;
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

static inline uint32_t HashStrNum(const char* s, int n) {
    uint32_t h = HashStr(s);
    h ^= (uint32_t)n * 0x9E3779B9;
    return h;
}

static inline uint32_t HashTwoStr(const char* s1, const char* s2) {
    uint32_t h = HashStr(s1);
    h ^= HashStr(s2) * 0x9E3779B9;
    return h;
}

// ================================================================
//  Original function pointers
// ================================================================

static ScriptFunc_fn orig_UnitHealth = nullptr;
static ScriptFunc_fn orig_UnitHealthMax = nullptr;
static ScriptFunc_fn orig_UnitPower = nullptr;
static ScriptFunc_fn orig_UnitPowerMax = nullptr;
static ScriptFunc_fn orig_UnitExists = nullptr;
static ScriptFunc_fn orig_UnitIsDeadOrGhost = nullptr;
static ScriptFunc_fn orig_UnitAffectingCombat = nullptr;
static ScriptFunc_fn orig_UnitCanAttack = nullptr;
static ScriptFunc_fn orig_UnitGUID = nullptr;

// ================================================================
//  Hooks: unit → number (UnitHealth, UnitHealthMax, UnitPower, UnitPowerMax)
//  These always return 1 (a number) — no nil issue.
//  NO CHANGES from original.
// ================================================================

static int __cdecl Hooked_UnitHealth(lua_State* L) {
    const char* unit = lua_tolstring(L, 1, NULL);
    if (unit) {
        uint32_t h = HashStr(unit);
        int slot = h & CACHE_MASK;
        NumCacheEntry* e = &g_healthCache[slot];
        if (e->gen == g_frameGen && e->hash == h) {
            lua_pushnumber_(L, e->value);
            g_hits++;
            return 1;
        }
        int ret = orig_UnitHealth(L);
        if (ret >= 1) {
            e->gen = g_frameGen;
            e->hash = h;
            e->value = lua_tonumber_(L, -1);
        }
        g_misses++;
        return ret;
    }
    return orig_UnitHealth(L);
}

static int __cdecl Hooked_UnitHealthMax(lua_State* L) {
    const char* unit = lua_tolstring(L, 1, NULL);
    if (unit) {
        uint32_t h = HashStr(unit);
        int slot = h & CACHE_MASK;
        NumCacheEntry* e = &g_healthMaxCache[slot];
        if (e->gen == g_frameGen && e->hash == h) {
            lua_pushnumber_(L, e->value);
            g_hits++;
            return 1;
        }
        int ret = orig_UnitHealthMax(L);
        if (ret >= 1) {
            e->gen = g_frameGen;
            e->hash = h;
            e->value = lua_tonumber_(L, -1);
        }
        g_misses++;
        return ret;
    }
    return orig_UnitHealthMax(L);
}

static int __cdecl Hooked_UnitPower(lua_State* L) {
    const char* unit = lua_tolstring(L, 1, NULL);
    if (unit) {
        int powerType = (lua_gettop_(L) >= 2 && lua_type_(L, 2) == LUA_TNUMBER)
                        ? (int)lua_tonumber_(L, 2) : 0;
        uint32_t h = HashStrNum(unit, powerType);
        int slot = h & CACHE_MASK;
        NumCacheEntry* e = &g_powerCache[slot];
        if (e->gen == g_frameGen && e->hash == h) {
            lua_pushnumber_(L, e->value);
            g_hits++;
            return 1;
        }
        int ret = orig_UnitPower(L);
        if (ret >= 1) {
            e->gen = g_frameGen;
            e->hash = h;
            e->value = lua_tonumber_(L, -1);
        }
        g_misses++;
        return ret;
    }
    return orig_UnitPower(L);
}

static int __cdecl Hooked_UnitPowerMax(lua_State* L) {
    const char* unit = lua_tolstring(L, 1, NULL);
    if (unit) {
        int powerType = (lua_gettop_(L) >= 2 && lua_type_(L, 2) == LUA_TNUMBER)
                        ? (int)lua_tonumber_(L, 2) : 0;
        uint32_t h = HashStrNum(unit, powerType);
        int slot = h & CACHE_MASK;
        NumCacheEntry* e = &g_powerMaxCache[slot];
        if (e->gen == g_frameGen && e->hash == h) {
            lua_pushnumber_(L, e->value);
            g_hits++;
            return 1;
        }
        int ret = orig_UnitPowerMax(L);
        if (ret >= 1) {
            e->gen = g_frameGen;
            e->hash = h;
            e->value = lua_tonumber_(L, -1);
        }
        g_misses++;
        return ret;
    }
    return orig_UnitPowerMax(L);
}

// ================================================================
//  Hooks: unit → boolean/nil
// ================================================================

static int __cdecl Hooked_UnitExists(lua_State* L) {
    const char* unit = lua_tolstring(L, 1, NULL);
    if (unit) {
        uint32_t h = HashStr(unit);
        int slot = h & CACHE_MASK;
        BoolCacheEntry* e = &g_existsCache[slot];
        if (e->gen == g_frameGen && e->hash == h) {
            if (e->isNil) {
                g_hits++;
                return 0;           
            }
            lua_pushboolean_(L, e->value);
            g_hits++;
            return 1;
        }
        int ret = orig_UnitExists(L);
        e->gen = g_frameGen;
        e->hash = h;
        if (ret >= 1 && lua_type_(L, -1) != LUA_TNIL) {
            e->isNil = false;
            e->value = 1;          
        } else {
            e->isNil = true;
            e->value = 0;
        }
        g_misses++;
        return ret;
    }
    return orig_UnitExists(L);
}

static int __cdecl Hooked_UnitIsDeadOrGhost(lua_State* L) {
    const char* unit = lua_tolstring(L, 1, NULL);
    if (unit) {
        uint32_t h = HashStr(unit);
        int slot = h & CACHE_MASK;
        BoolCacheEntry* e = &g_deadCache[slot];
        if (e->gen == g_frameGen && e->hash == h) {
            if (e->isNil) {
                g_hits++;
                return 0;        
            }
            lua_pushboolean_(L, e->value);
            g_hits++;
            return 1;
        }
        int ret = orig_UnitIsDeadOrGhost(L);
        e->gen = g_frameGen;
        e->hash = h;
        if (ret >= 1 && lua_type_(L, -1) != LUA_TNIL) {
            e->isNil = false;
            e->value = 1;       
        } else {
            e->isNil = true;
            e->value = 0;
        }
        g_misses++;
        return ret;
    }
    return orig_UnitIsDeadOrGhost(L);
}

static int __cdecl Hooked_UnitAffectingCombat(lua_State* L) {
    const char* unit = lua_tolstring(L, 1, NULL);
    if (unit) {
        uint32_t h = HashStr(unit);
        int slot = h & CACHE_MASK;
        BoolCacheEntry* e = &g_combatCache[slot];
        if (e->gen == g_frameGen && e->hash == h) {
            if (e->isNil) {
                g_hits++;
                return 0;           
            }
            lua_pushboolean_(L, e->value);
            g_hits++;
            return 1;
        }
        int ret = orig_UnitAffectingCombat(L);
        e->gen = g_frameGen;
        e->hash = h;
        if (ret >= 1 && lua_type_(L, -1) != LUA_TNIL) {
            e->isNil = false;
            e->value = 1;         
        } else {
            e->isNil = true;
            e->value = 0;
        }
        g_misses++;
        return ret;
    }
    return orig_UnitAffectingCombat(L);
}

static int __cdecl Hooked_UnitCanAttack(lua_State* L) {
    const char* unit1 = lua_tolstring(L, 1, NULL);
    const char* unit2 = lua_tolstring(L, 2, NULL);
    if (unit1 && unit2) {
        uint32_t h = HashTwoStr(unit1, unit2);
        int slot = h & CACHE_MASK;
        BoolCacheEntry* e = &g_canAttackCache[slot];
        if (e->gen == g_frameGen && e->hash == h) {
            if (e->isNil) {
                g_hits++;
                return 0;     
            }
            lua_pushboolean_(L, e->value);
            g_hits++;
            return 1;
        }
        int ret = orig_UnitCanAttack(L);
        e->gen = g_frameGen;
        e->hash = h;
        if (ret >= 1 && lua_type_(L, -1) != LUA_TNIL) {
            e->isNil = false;
            e->value = 1;       
        } else {
            e->isNil = true;
            e->value = 0;
        }
        g_misses++;
        return ret;
    }
    return orig_UnitCanAttack(L);
}

// ================================================================
//  Hook: unit → string (UnitGUID)
// ================================================================

static int __cdecl Hooked_UnitGUID(lua_State* L) {
    const char* unit = lua_tolstring(L, 1, NULL);
    if (unit) {
        uint32_t h = HashStr(unit);
        int slot = h & CACHE_MASK;
        StrCacheEntry* e = &g_guidCache[slot];
        if (e->gen == g_frameGen && e->hash == h) {
            if (e->isNil) {
                g_hits++;
                return 0;       
            }
            lua_pushstring_(L, e->value);
            g_hits++;
            return 1;
        }
        int ret = orig_UnitGUID(L);
        e->gen = g_frameGen;
        e->hash = h;
        if (ret >= 1 && lua_type_(L, -1) == LUA_TSTRING) {
            const char* s = lua_tolstring(L, -1, NULL);
            if (s) {
                strncpy(e->value, s, sizeof(e->value) - 1);
                e->value[sizeof(e->value) - 1] = '\0';
                e->isNil = false;
            } else {
                e->isNil = true;
            }
        } else {
            e->isNil = true;
        }
        g_misses++;
        return ret;
    }
    return orig_UnitGUID(L);
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
//  API
// ================================================================

namespace ApiCache {

bool Init() {
    Log("[ApiCache] ====================================");
    Log("[ApiCache]  WoW API Result Cache");
    Log("[ApiCache]  Build 12340");
    Log("[ApiCache] ====================================");

    int hooked = 0;

    if (HookFunc("UnitHealth",          Addr::UnitHealth,          (void*)Hooked_UnitHealth,          (void**)&orig_UnitHealth))          hooked++;
    if (HookFunc("UnitHealthMax",       Addr::UnitHealthMax,       (void*)Hooked_UnitHealthMax,       (void**)&orig_UnitHealthMax))       hooked++;
    if (HookFunc("UnitPower",           Addr::UnitPower,           (void*)Hooked_UnitPower,           (void**)&orig_UnitPower))           hooked++;
    if (HookFunc("UnitPowerMax",        Addr::UnitPowerMax,        (void*)Hooked_UnitPowerMax,        (void**)&orig_UnitPowerMax))        hooked++;
    if (HookFunc("UnitExists",          Addr::UnitExists,          (void*)Hooked_UnitExists,          (void**)&orig_UnitExists))          hooked++;
    if (HookFunc("UnitIsDeadOrGhost",   Addr::UnitIsDeadOrGhost,   (void*)Hooked_UnitIsDeadOrGhost,   (void**)&orig_UnitIsDeadOrGhost))   hooked++;
    if (HookFunc("UnitAffectingCombat", Addr::UnitAffectingCombat, (void*)Hooked_UnitAffectingCombat, (void**)&orig_UnitAffectingCombat)) hooked++;
    if (HookFunc("UnitCanAttack",       Addr::UnitCanAttack,       (void*)Hooked_UnitCanAttack,       (void**)&orig_UnitCanAttack))       hooked++;
    if (HookFunc("UnitGUID",            Addr::UnitGUID,            (void*)Hooked_UnitGUID,            (void**)&orig_UnitGUID))            hooked++;

    if (hooked == 0) {
        Log("[ApiCache]  DISABLED — no hooks installed");
        return false;
    }

    g_active = true;

    Log("[ApiCache] ====================================");
    Log("[ApiCache]  Hooks: %d/9 active", hooked);
    Log("[ApiCache]  Cache: %d slots per function", CACHE_SIZE);
    Log("[ApiCache]  [ OK ] ACTIVE");
    Log("[ApiCache] ====================================");
    return true;
}

void Shutdown() {
    if (!g_active) return;

    MH_DisableHook((void*)Addr::UnitHealth);
    MH_DisableHook((void*)Addr::UnitHealthMax);
    MH_DisableHook((void*)Addr::UnitPower);
    MH_DisableHook((void*)Addr::UnitPowerMax);
    MH_DisableHook((void*)Addr::UnitExists);
    MH_DisableHook((void*)Addr::UnitIsDeadOrGhost);
    MH_DisableHook((void*)Addr::UnitAffectingCombat);
    MH_DisableHook((void*)Addr::UnitCanAttack);
    MH_DisableHook((void*)Addr::UnitGUID);

    g_active = false;

    long total = g_hits + g_misses;
    if (total > 0) {
        Log("[ApiCache] Shutdown: %ld hits, %ld misses (%.1f%% hit rate)",
            g_hits, g_misses, (double)g_hits / total * 100.0);
    }
}

void OnNewFrame() {
    g_frameGen++;
}

Stats GetStats() {
    Stats s;
    s.hits = g_hits;
    s.misses = g_misses;
    s.active = g_active;
    return s;
}

} // namespace ApiCache