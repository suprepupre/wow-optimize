#include "spell_cache.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <psapi.h>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

typedef struct lua_State lua_State;
typedef double lua_Number;

typedef lua_Number  (__cdecl *fn_lua_tonumber)(lua_State*, int);
typedef int         (__cdecl *fn_lua_gettop)(lua_State*);
typedef int         (__cdecl *fn_lua_type)(lua_State*, int);
typedef const char* (__cdecl *fn_lua_tolstring)(lua_State*, int, size_t*);
typedef int         (__cdecl *fn_lua_toboolean)(lua_State*, int);
typedef void        (__cdecl *fn_lua_pushnumber)(lua_State*, lua_Number);
typedef const char* (__cdecl *fn_lua_pushstring)(lua_State*, const char*);
typedef void        (__cdecl *fn_lua_pushnil)(lua_State*);
typedef void        (__cdecl *fn_lua_pushboolean)(lua_State*, int);
typedef void        (__cdecl *fn_lua_settop)(lua_State*, int);

static fn_lua_tonumber    sc_tonumber    = (fn_lua_tonumber)   0x0084E030;
static fn_lua_gettop      sc_gettop      = (fn_lua_gettop)     0x0084DBD0;
static fn_lua_type        sc_type        = (fn_lua_type)       0x0084DEB0;
static fn_lua_tolstring   sc_tolstring   = (fn_lua_tolstring)  0x0084E0E0;
static fn_lua_toboolean   sc_toboolean   = (fn_lua_toboolean)  0x0084E0B0;
static fn_lua_pushnumber  sc_pushnumber  = (fn_lua_pushnumber) 0x0084E2A0;
static fn_lua_pushstring  sc_pushstring  = (fn_lua_pushstring) 0x0084E350;
static fn_lua_pushnil     sc_pushnil     = (fn_lua_pushnil)    0x0084E280;
static fn_lua_pushboolean sc_pushboolean = (fn_lua_pushboolean)0x0084E4D0;
static fn_lua_settop      sc_settop      = (fn_lua_settop)     0x0084DBF0;

#define LUA_TNIL      0
#define LUA_TBOOLEAN  1
#define LUA_TNUMBER   3
#define LUA_TSTRING   4

typedef int (__cdecl *ScriptFunc_fn)(lua_State*);

static constexpr int MAX_RETURNS = 9;

struct ReturnValue {
    int    type;
    char   str[128];
    double num;
    int    boolean;
};

struct SpellCacheEntry {
    uint32_t    spellID;
    uint32_t    frameCounter;
    int         numResults;
    ReturnValue results[MAX_RETURNS];
};

static constexpr int CACHE_SIZE = 1024;
static constexpr int CACHE_MASK = CACHE_SIZE - 1;

static SpellCacheEntry g_cache[CACHE_SIZE] = {};
static uint32_t g_frameCounter = 0;
static volatile long g_hits = 0;
static volatile long g_misses = 0;
static bool g_active = false;

static ScriptFunc_fn orig_GetSpellInfo = nullptr;
static uintptr_t addr_GetSpellInfo = 0;

static void PushReturn(lua_State* L, const ReturnValue& rv) {
    switch (rv.type) {
        case LUA_TSTRING:  sc_pushstring(L, rv.str); break;
        case LUA_TNUMBER:  sc_pushnumber(L, rv.num); break;
        case LUA_TBOOLEAN: sc_pushboolean(L, rv.boolean); break;
        default:           sc_pushnil(L); break;
    }
}

static void CaptureReturn(lua_State* L, int idx, ReturnValue& rv) {
    rv.type = sc_type(L, idx);
    switch (rv.type) {
        case LUA_TSTRING: {
            size_t len = 0;
            const char* s = sc_tolstring(L, idx, &len);
            if (s && len < sizeof(rv.str) - 1)
                memcpy(rv.str, s, len + 1);
            else
                { rv.str[0] = '\0'; rv.type = LUA_TNIL; }
            break;
        }
        case LUA_TNUMBER:  rv.num = sc_tonumber(L, idx); break;
        case LUA_TBOOLEAN: rv.boolean = sc_toboolean(L, idx); break;
        default:           rv.type = LUA_TNIL; break;
    }
}

static int __cdecl Hooked_GetSpellInfo(lua_State* L) {
    __try {
        if (sc_type(L, 1) != LUA_TNUMBER) goto miss;

        uint32_t spellID = (uint32_t)sc_tonumber(L, 1);
        int slot = spellID & CACHE_MASK;
        SpellCacheEntry& entry = g_cache[slot];

        if (entry.spellID == spellID && entry.frameCounter == g_frameCounter) {
            for (int i = 0; i < entry.numResults; i++)
                PushReturn(L, entry.results[i]);
            InterlockedIncrement(&g_hits);
            return entry.numResults;
        }

        {
            int topBefore = sc_gettop(L);
            int ret = orig_GetSpellInfo(L);
            if (ret > 0 && ret <= MAX_RETURNS) {
                entry.spellID = spellID;
                entry.frameCounter = g_frameCounter;
                entry.numResults = ret;
                for (int i = 0; i < ret; i++)
                    CaptureReturn(L, topBefore + 1 + i, entry.results[i]);
            }
            InterlockedIncrement(&g_misses);
            return ret;
        }
    } __except(1) {}

miss:
    InterlockedIncrement(&g_misses);
    return orig_GetSpellInfo(L);
}

static bool IsExec(uintptr_t addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static uintptr_t FindFunc(const char* name, uintptr_t base, size_t size) {
    size_t len = strlen(name);
    for (size_t i = 0; i < size - len - 1; i++) {
        if (memcmp((void*)(base + i), name, len + 1) != 0) continue;
        uintptr_t strAddr = base + i;
        for (size_t j = 0; j < size - 8; j += 4) {
            uintptr_t ref = base + j;
            __try {
                if (*(uintptr_t*)ref != strAddr) continue;
                uintptr_t fn = *(uintptr_t*)(ref + 4);
                if (!IsExec(fn)) continue;
                int valid = 0;
                for (int k = -5; k <= 5; k++) {
                    if (k == 0) continue;
                    uintptr_t n = ref + k * 8;
                    if (n < base || n + 8 > base + size) continue;
                    __try {
                        uintptr_t ns = *(uintptr_t*)n;
                        uintptr_t nf = *(uintptr_t*)(n + 4);
                        if (ns >= base && ns < base + size && IsExec(nf)) {
                            const char* s = (const char*)ns;
                            if (s[0] >= 'A' && s[0] <= 'Z') valid++;
                        }
                    } __except(1) {}
                }
                if (valid >= 3) return fn;
            } __except(1) { continue; }
        }
    }
    return 0;
}

namespace SpellCache {

bool Init() {
    Log("[SpellCache] ====================================");
    Log("[SpellCache]  GetSpellInfo Per-Frame Cache");
    Log("[SpellCache] ====================================");

    HMODULE h = GetModuleHandleA(NULL);
    if (!h) return false;
    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi))) return false;

    addr_GetSpellInfo = FindFunc("GetSpellInfo", (uintptr_t)h, mi.SizeOfImage);
    if (!addr_GetSpellInfo) {
        Log("[SpellCache] GetSpellInfo not found"); return false;
    }
    Log("[SpellCache] GetSpellInfo at 0x%08X", (unsigned)addr_GetSpellInfo);

    MH_STATUS s = MH_CreateHook((void*)addr_GetSpellInfo,
        (void*)Hooked_GetSpellInfo, (void**)&orig_GetSpellInfo);
    if (s != MH_OK) { Log("[SpellCache] CreateHook failed (%d)", (int)s); return false; }
    s = MH_EnableHook((void*)addr_GetSpellInfo);
    if (s != MH_OK) { Log("[SpellCache] EnableHook failed (%d)", (int)s); return false; }

    g_active = true;
    Log("[SpellCache]  [ OK ] %d slots", CACHE_SIZE);
    Log("[SpellCache] ====================================");
    return true;
}

void NewFrame() { g_frameCounter++; }

void Shutdown() {
    if (!g_active) return;
    if (addr_GetSpellInfo) MH_DisableHook((void*)addr_GetSpellInfo);
    long total = g_hits + g_misses;
    if (total > 0)
        Log("[SpellCache] hits=%ld misses=%ld (%.1f%%)", g_hits, g_misses,
            (double)g_hits / total * 100.0);
    g_active = false;
}

Stats GetStats() { return { g_hits, g_misses, g_active }; }

}
