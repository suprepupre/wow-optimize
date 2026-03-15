#include "api_cache.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <psapi.h>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

typedef struct lua_State lua_State;
typedef double lua_Number;

typedef lua_Number (__cdecl *fn_lua_tonumber)(lua_State*, int);
typedef int        (__cdecl *fn_lua_gettop)(lua_State*);
typedef int        (__cdecl *fn_lua_type)(lua_State*, int);
typedef void       (__cdecl *fn_lua_pushnumber)(lua_State*, lua_Number);

static fn_lua_tonumber   ac_tonumber   = (fn_lua_tonumber)  0x0084E030;
static fn_lua_gettop     ac_gettop     = (fn_lua_gettop)    0x0084DBD0;
static fn_lua_type       ac_type       = (fn_lua_type)      0x0084DEB0;
static fn_lua_pushnumber ac_pushnumber = (fn_lua_pushnumber)0x0084E2A0;

#define LUA_TNUMBER 3

typedef int (__cdecl *ScriptFunc_fn)(lua_State*);

struct CachedReturn {
    double   values[3];
    int      numReturns;
    uint32_t keyHash;
    uint32_t frameCounter;
    bool     valid;
};

static constexpr int CACHE_SIZE = 256;
static constexpr int CACHE_MASK = CACHE_SIZE - 1;

static uint32_t g_frameCounter = 0;
static volatile long g_totalHits = 0;
static volatile long g_totalMisses = 0;
static bool g_active = false;

static CachedReturn g_cdCache[CACHE_SIZE] = {};
static ScriptFunc_fn orig_GetSpellCooldown = nullptr;
static uintptr_t addr_GetSpellCooldown = 0;
static volatile long g_cdHits = 0;
static volatile long g_cdMisses = 0;

static int __cdecl Hooked_GetSpellCooldown(lua_State* L) {
    __try {
        if (ac_type(L, 1) != LUA_TNUMBER) goto miss;

        uint32_t spellID = (uint32_t)ac_tonumber(L, 1);
        int slot = spellID & CACHE_MASK;
        CachedReturn& e = g_cdCache[slot];

        if (e.valid && e.keyHash == spellID && e.frameCounter == g_frameCounter) {
            for (int i = 0; i < e.numReturns; i++)
                ac_pushnumber(L, e.values[i]);
            InterlockedIncrement(&g_cdHits);
            InterlockedIncrement(&g_totalHits);
            return e.numReturns;
        }

        {
            int top = ac_gettop(L);
            int ret = orig_GetSpellCooldown(L);
            if (ret >= 1 && ret <= 3) {
                e.keyHash = spellID;
                e.frameCounter = g_frameCounter;
                e.numReturns = ret;
                e.valid = true;
                for (int i = 0; i < ret; i++)
                    e.values[i] = (ac_type(L, top + 1 + i) == LUA_TNUMBER)
                        ? ac_tonumber(L, top + 1 + i) : 0;
            }
            InterlockedIncrement(&g_cdMisses);
            InterlockedIncrement(&g_totalMisses);
            return ret;
        }
    } __except(1) {}

miss:
    InterlockedIncrement(&g_cdMisses);
    InterlockedIncrement(&g_totalMisses);
    return orig_GetSpellCooldown(L);
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

static bool InstallHook(const char* name, uintptr_t addr, void* hook, void** orig) {
    if (!addr) { Log("[APICache]   %-25s NOT FOUND", name); return false; }
    MH_STATUS s = MH_CreateHook((void*)addr, hook, orig);
    if (s != MH_OK) { Log("[APICache]   %-25s CreateHook failed (%d)", name, (int)s); return false; }
    s = MH_EnableHook((void*)addr);
    if (s != MH_OK) { Log("[APICache]   %-25s EnableHook failed (%d)", name, (int)s); return false; }
    Log("[APICache]   %-25s 0x%08X  [ OK ]", name, (unsigned)addr);
    return true;
}

namespace APICache {

bool Init() {
    Log("[APICache] ====================================");
    Log("[APICache]  API Call Per-Frame Cache");
    Log("[APICache] ====================================");

    HMODULE h = GetModuleHandleA(NULL);
    if (!h) return false;
    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi))) return false;

    int hooked = 0;
    addr_GetSpellCooldown = FindFunc("GetSpellCooldown", (uintptr_t)h, mi.SizeOfImage);
    if (InstallHook("GetSpellCooldown", addr_GetSpellCooldown,
                     (void*)Hooked_GetSpellCooldown, (void**)&orig_GetSpellCooldown))
        hooked++;

    if (!hooked) { Log("[APICache] No hooks — DISABLED"); return false; }
    g_active = true;
    Log("[APICache]  [ OK ] %d hooks, %d slots", hooked, CACHE_SIZE);
    Log("[APICache] ====================================");
    return true;
}

void NewFrame() { g_frameCounter++; }

void Shutdown() {
    if (!g_active) return;
    if (addr_GetSpellCooldown) MH_DisableHook((void*)addr_GetSpellCooldown);
    long total = g_cdHits + g_cdMisses;
    if (total > 0)
        Log("[APICache] GetSpellCooldown: hits=%ld misses=%ld (%.1f%%)",
            g_cdHits, g_cdMisses, (double)g_cdHits / total * 100.0);
    g_active = false;
}

Stats GetStats() {
    return { g_totalHits, g_totalMisses, (addr_GetSpellCooldown ? 1 : 0), g_active };
}

}
