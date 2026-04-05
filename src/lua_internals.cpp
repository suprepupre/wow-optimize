#include "lua_internals.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

// Lua VM internals for build 12340.

typedef struct lua_State lua_State;

// ================================================================
//  Confirmed addresses — build 12340
// ================================================================

static constexpr uintptr_t ADDR_luaS_newlstr = 0x00856C80;
static constexpr uintptr_t ADDR_luaV_concat  = 0x00857900;

// WoW taint tracking global
static constexpr uintptr_t ADDR_taint_global = 0x00D4139C;

// TString layout (from disassembly):
//   +0x04 = tt (type tag, lu_byte)
//   +0x10 = length (uint32)
//   +0x14 = string data (char[])

// TValue layout (16 bytes, WoW-modified Lua 5.1):
//   +0x00 = value (pointer / number)
//   +0x08 = type tag (int)
//   +0x0C = taint field (uint32)

#define LUA_TSTRING 4

// Crash isolation toggle for concat hook
// Set to 1 to disable ONLY the concat fast path for testing
#ifndef CRASH_TEST_DISABLE_CONCAT
#define CRASH_TEST_DISABLE_CONCAT 0
#endif

typedef void* (__cdecl *fn_luaS_newlstr)(lua_State* L, const char* str, size_t l);
typedef void  (__cdecl *fn_luaV_concat)(lua_State* L, int total, int last);

static fn_luaS_newlstr orig_luaS_newlstr = nullptr;
static fn_luaV_concat  orig_luaV_concat  = nullptr;

static long g_strCacheHits    = 0;
static long g_strCacheMisses  = 0;
static long g_strCacheStale   = 0;
static long g_concatFastHits  = 0;
static long g_concatFallbacks = 0;
static bool g_active = false;

// Short-string interning cache, scoped per Lua VM (by global_State pointer).
static constexpr int    STR_CACHE_SIZE    = 4096;
static constexpr int    STR_CACHE_MASK    = STR_CACHE_SIZE - 1;
static constexpr size_t STR_CACHE_MAX_LEN = 64;

struct StrCacheEntry {
    uint32_t  hash;
    uint32_t  len;
    void*     result;
    uintptr_t globalState;
};

static StrCacheEntry g_strCache[STR_CACHE_SIZE] = {};

static inline uint32_t FNV1a(const char* data, size_t len) {
    uint32_t h = 0x811C9DC5u;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)data[i];
        h *= 0x01000193u;
    }
    return h;
}

// ================================================================
//  Hooked luaS_newlstr — string interning with cache
// ================================================================

static void* __cdecl Hooked_luaS_newlstr(lua_State* L, const char* str, size_t l) {
    if (l == 0 || l > STR_CACHE_MAX_LEN)
        return orig_luaS_newlstr(L, str, l);

    uintptr_t gs = 0;
    __try {
        gs = *(uintptr_t*)((uintptr_t)L + 0x14);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return orig_luaS_newlstr(L, str, l);
    }
    if (gs == 0) return orig_luaS_newlstr(L, str, l);

    uint32_t hash = FNV1a(str, l);
    int slot = hash & STR_CACHE_MASK;
    StrCacheEntry* e = &g_strCache[slot];

    if (e->globalState == gs &&
        e->hash == hash &&
        e->len == (uint32_t)l &&
        e->result != nullptr)
    {
        bool valid = false;
        __try {
            uintptr_t ts = (uintptr_t)e->result;
            uint8_t tt = *(uint8_t*)(ts + 0x04);
            if (tt == LUA_TSTRING) {
                uint32_t cachedLen = *(uint32_t*)(ts + 0x10);
                if (cachedLen == (uint32_t)l) {
                    if (memcmp((const char*)(ts + 0x14), str, l) == 0) {
                        valid = true;
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            e->result = nullptr;
            e->globalState = 0;
        }

        if (valid) {
            g_strCacheHits++;
            return e->result;
        }
        g_strCacheStale++;
    }

    void* result = orig_luaS_newlstr(L, str, l);

    e->hash        = hash;
    e->len         = (uint32_t)l;
    e->result      = result;
    e->globalState = gs;

    g_strCacheMisses++;
    return result;
}

// Fast path for 2 and 3 operand string concat.
static constexpr size_t CONCAT_BUF_SIZE = 2048;

static bool TryConcatFast(lua_State* L, int total, int last) {
    uintptr_t base = *(uintptr_t*)((uintptr_t)L + 0x10);
    if (!base) return false;

    if (total == 2) {
        uintptr_t rightTV = base + (uintptr_t)last * 16;
        uintptr_t leftTV  = rightTV - 16;

        // Type checks (offset +8 = type tag)
        if (*(int*)(rightTV + 8) != LUA_TSTRING || *(int*)(leftTV + 8) != LUA_TSTRING)
            return false;

        // TString pointers (offset +0)
        uintptr_t rTS = *(uintptr_t*)(rightTV);
        uintptr_t lTS = *(uintptr_t*)(leftTV);
        if (!rTS || !lTS) return false;

        // Lengths (TString+0x10)
        size_t rLen = *(uint32_t*)(rTS + 0x10);
        size_t lLen = *(uint32_t*)(lTS + 0x10);
        size_t tLen = lLen + rLen;

        // Sanity checks
        if (tLen > CONCAT_BUF_SIZE || tLen < lLen) return false;
        if (rLen > 0x1000000 || lLen > 0x1000000) return false;

        // Empty right → left is already the result
        if (rLen == 0) return true;

        // Empty left → copy right to left position
        if (lLen == 0) {
            *(uintptr_t*)(leftTV)     = rTS;
            *(int*)(leftTV + 8)       = LUA_TSTRING;
            *(uint32_t*)(leftTV + 12) = *(uint32_t*)ADDR_taint_global;
            return true;
        }

        // Validate string data pointers are readable
        uintptr_t lData = lTS + 0x14;
        uintptr_t rData = rTS + 0x14;
        if (lData < 0x10000 || rData < 0x10000) return false;

        char buf[CONCAT_BUF_SIZE + 1];
        memcpy(buf, (const char*)lData, lLen);
        memcpy(buf + lLen, (const char*)rData, rLen);

        void* result = orig_luaS_newlstr(L, buf, tLen);
        if (!result) return false;

        // Re-read base — GC during string creation could move the stack
        uintptr_t newBase = *(uintptr_t*)((uintptr_t)L + 0x10);
        if (newBase != base) return false;

        *(uintptr_t*)(leftTV)     = (uintptr_t)result;
        *(int*)(leftTV + 8)       = LUA_TSTRING;
        *(uint32_t*)(leftTV + 12) = *(uint32_t*)ADDR_taint_global;
        return true;
    }

    if (total == 3) {
        uintptr_t rightTV = base + (uintptr_t)last * 16;
        uintptr_t midTV   = rightTV - 16;
        uintptr_t leftTV  = rightTV - 32;

        if (*(int*)(rightTV + 8) != LUA_TSTRING ||
            *(int*)(midTV + 8) != LUA_TSTRING ||
            *(int*)(leftTV + 8) != LUA_TSTRING)
            return false;

        uintptr_t rTS = *(uintptr_t*)(rightTV);
        uintptr_t mTS = *(uintptr_t*)(midTV);
        uintptr_t lTS = *(uintptr_t*)(leftTV);
        if (!rTS || !mTS || !lTS) return false;

        size_t rLen = *(uint32_t*)(rTS + 0x10);
        size_t mLen = *(uint32_t*)(mTS + 0x10);
        size_t lLen = *(uint32_t*)(lTS + 0x10);
        size_t tLen = lLen + mLen + rLen;

        if (tLen > CONCAT_BUF_SIZE || tLen < lLen) return false;
        if (rLen > 0x1000000 || mLen > 0x1000000 || lLen > 0x1000000) return false;

        if (tLen == 0) return true;

        // Validate all data pointers
        if ((lTS + 0x14) < 0x10000 || (mTS + 0x14) < 0x10000 || (rTS + 0x14) < 0x10000)
            return false;

        char buf[CONCAT_BUF_SIZE + 1];
        size_t pos = 0;
        if (lLen > 0) { memcpy(buf + pos, (const char*)(lTS + 0x14), lLen); pos += lLen; }
        if (mLen > 0) { memcpy(buf + pos, (const char*)(mTS + 0x14), mLen); pos += mLen; }
        if (rLen > 0) { memcpy(buf + pos, (const char*)(rTS + 0x14), rLen); pos += rLen; }

        void* result = orig_luaS_newlstr(L, buf, tLen);
        if (!result) return false;

        // Re-read base — GC during string creation could move the stack
        uintptr_t newBase = *(uintptr_t*)((uintptr_t)L + 0x10);
        if (newBase != base) return false;

        *(uintptr_t*)(leftTV)     = (uintptr_t)result;
        *(int*)(leftTV + 8)       = LUA_TSTRING;
        *(uint32_t*)(leftTV + 12) = *(uint32_t*)ADDR_taint_global;
        return true;
    }

    return false;
}

static void __cdecl Hooked_luaV_concat(lua_State* L, int total, int last) {
    __try {
        if (TryConcatFast(L, total, last)) {
            g_concatFastHits++;
            return;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Fast path crashed — fall through to safe original
    }
    g_concatFallbacks++;
    orig_luaV_concat(L, total, last);
}

namespace LuaInternals {

bool Init() {
    Log("[LuaVM] Init Lua VM internals (build 12340)");

    int hooked = 0;

    // Hook luaS_newlstr (string interning cache)
    __try {
        MH_STATUS s = MH_CreateHook((void*)ADDR_luaS_newlstr,
                                     (void*)Hooked_luaS_newlstr,
                                     (void**)&orig_luaS_newlstr);
        if (s == MH_OK) {
            s = MH_EnableHook((void*)ADDR_luaS_newlstr);
            if (s == MH_OK) {
                hooked++;
                Log("[LuaVM]   luaS_newlstr    0x%08X  [ OK ] (per-VM cache, %d slots, validated)",
                    (unsigned)ADDR_luaS_newlstr, STR_CACHE_SIZE);
            } else {
                Log("[LuaVM]   luaS_newlstr    MH_EnableHook failed (%d)", (int)s);
            }
        } else {
            Log("[LuaVM]   luaS_newlstr    MH_CreateHook failed (%d)", (int)s);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaVM]   luaS_newlstr    EXCEPTION");
    }

    // Hook luaV_concat (fast concatenation)
#if !CRASH_TEST_DISABLE_CONCAT
    __try {
        MH_STATUS s = MH_CreateHook((void*)ADDR_luaV_concat,
                                     (void*)Hooked_luaV_concat,
                                     (void**)&orig_luaV_concat);
        if (s == MH_OK) {
            s = MH_EnableHook((void*)ADDR_luaV_concat);
            if (s == MH_OK) {
                hooked++;
                Log("[LuaVM]   luaV_concat     0x%08X  [ OK ] (fast 2-3 operand, SEH protected)",
                    (unsigned)ADDR_luaV_concat);
            } else {
                Log("[LuaVM]   luaV_concat     MH_EnableHook failed (%d)", (int)s);
            }
        } else {
            Log("[LuaVM]   luaV_concat     MH_CreateHook failed (%d)", (int)s);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaVM]   luaV_concat     EXCEPTION");
    }
#else
    Log("[LuaVM]   luaV_concat     DISABLED (crash isolation)");
#endif

    g_active = (hooked > 0);

    Log("[LuaVM] ====================================");
    Log("[LuaVM]  Hooks: %d/2 active", hooked);
    if (g_active) {
        Log("[LuaVM]  [ OK ] ACTIVE");
    } else {
        Log("[LuaVM]  DISABLED — no hooks installed");
    }
    Log("[LuaVM] ====================================");
    return g_active;
}

void Shutdown() {
    if (!g_active) return;

    if (orig_luaS_newlstr) MH_DisableHook((void*)ADDR_luaS_newlstr);
    if (orig_luaV_concat)  MH_DisableHook((void*)ADDR_luaV_concat);

    long strTotal = g_strCacheHits + g_strCacheMisses;
    if (strTotal > 0) {
        Log("[LuaVM] StrCache: %ld hits, %ld misses, %ld stale (%.1f%% hit)",
            g_strCacheHits, g_strCacheMisses, g_strCacheStale,
            (double)g_strCacheHits / strTotal * 100.0);
    }

    long catTotal = g_concatFastHits + g_concatFallbacks;
    if (catTotal > 0) {
        Log("[LuaVM] Concat: %ld fast, %ld fallback (%.1f%%)",
            g_concatFastHits, g_concatFallbacks,
            (double)g_concatFastHits / catTotal * 100.0);
    }

    g_active = false;
}

void OnGCStep() {
}

void InvalidateCache() {
    // Full clear on explicit invalidation (VM reload, lua_State change)
    memset(g_strCache, 0, sizeof(g_strCache));
}

Stats GetStats() {
    Stats s;
    s.strCacheHits    = g_strCacheHits;
    s.strCacheMisses  = g_strCacheMisses;
    s.concatFastHits  = g_concatFastHits;
    s.concatFallbacks = g_concatFallbacks;
    s.active          = g_active;
    return s;
}

} // namespace LuaInternals