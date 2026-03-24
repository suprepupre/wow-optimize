#include "ui_cache.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <psapi.h>

#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
//  UI Widget Cache — StatusBar Methods Only
// ================================================================

typedef struct lua_State lua_State;
typedef double lua_Number;

typedef lua_Number  (__cdecl *fn_lua_tonumber)(lua_State* L, int index);
typedef int         (__cdecl *fn_lua_gettop)(lua_State* L);

static fn_lua_tonumber    api_tonumber  = (fn_lua_tonumber)0x0084E030;
static fn_lua_gettop      api_gettop    = (fn_lua_gettop)0x0084DBD0;

#define LUA_TTABLE    5
#define LUA_TUSERDATA 7

// ================================================================
//  Widget Identity — Direct Lua Stack Read
// ================================================================

static inline void* GetWidgetIdentity(lua_State* L) {
    __try {
        uintptr_t base = *(uintptr_t*)((uintptr_t)L + 0x10);
        if (!base || base < 0x10000) return nullptr;

        int tt = *(int*)(base + 8);

        if (tt == LUA_TTABLE || tt == LUA_TUSERDATA) {
            void* identity = *(void**)base;
            if (identity && (uintptr_t)identity >= 0x10000)
                return identity;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return nullptr;
}

// ================================================================
//  Float-to-bits hash helper
// ================================================================

static inline uint32_t DoubleBits(double val) {
    if (val >= -2147483648.0 && val <= 2147483647.0) {
        int iv = (int)val;
        if ((double)iv == val) {
            return (uint32_t)iv;
        }
    }
    float f = (float)val;
    uint32_t bits;
    memcpy(&bits, &f, sizeof(bits));
    return bits;
}

// ================================================================
//  Widget Cache
// ================================================================

static constexpr int METHOD_SETVALUE    = 0;
static constexpr int METHOD_SETMINMAX   = 1;
static constexpr int METHOD_SETBARCOLOR = 2;
static constexpr int NUM_METHODS        = 3;

static constexpr int CACHE_SIZE  = 16384;
static constexpr int CACHE_MASK  = CACHE_SIZE - 1;
static constexpr int CACHE_PROBE = 4;

struct CacheEntry {
    uint64_t  key;
    uint32_t  hash;
    bool      occupied;
};

static CacheEntry g_cache[CACHE_SIZE] = {};

static inline uint64_t MakeKey(uintptr_t widget, int method) {
    return ((uint64_t)widget << 4) | (uint64_t)method;
}

static inline int CacheSlot(uint64_t key) {
    uint32_t k = (uint32_t)(key >> 4) ^ (uint32_t)(key);
    k ^= k >> 16;
    k *= 0x45d9f3b;
    k ^= k >> 16;
    return (int)(k & CACHE_MASK);
}

static bool CheckAndUpdate(uint64_t key, uint32_t hash) {
    int slot = CacheSlot(key);
    for (int i = 0; i < CACHE_PROBE; i++) {
        int idx = (slot + i) & CACHE_MASK;
        if (!g_cache[idx].occupied) {
            g_cache[idx].key  = key;
            g_cache[idx].hash = hash;
            g_cache[idx].occupied = true;
            return false;
        }
        if (g_cache[idx].key == key) {
            if (g_cache[idx].hash == hash) return true;
            g_cache[idx].hash = hash;
            return false;
        }
    }
    int evict = (slot + CACHE_PROBE - 1) & CACHE_MASK;
    g_cache[evict].key  = key;
    g_cache[evict].hash = hash;
    g_cache[evict].occupied = true;
    return false;
}

static void InvalidateWidget(uintptr_t widget, int method) {
    uint64_t key = MakeKey(widget, method);
    int slot = CacheSlot(key);
    for (int i = 0; i < CACHE_PROBE; i++) {
        int idx = (slot + i) & CACHE_MASK;
        if (!g_cache[idx].occupied) break;
        if (g_cache[idx].key == key) {
            g_cache[idx].hash = 0;
            break;
        }
    }
}

// ================================================================
//  Stats
// ================================================================

struct MethodStats {
    long skipped;
    long passed;
};

static MethodStats g_stats[NUM_METHODS] = {};
static bool g_active = false;

// ================================================================
//  Auto-Discovery
// ================================================================

static bool IsExec(uintptr_t addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static bool IsValidString(uintptr_t addr, uintptr_t base, size_t modSize) {
    if (addr < base || addr >= base + modSize) return false;
    __try {
        const char* s = (const char*)addr;
        for (int i = 0; i < 64; i++) {
            if (s[i] == '\0') return (i > 0);
            if (s[i] < 0x20 || s[i] > 0x7E) return false;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    return false;
}

struct DiscoverResult {
    uintptr_t funcAddr;
    int       matchCount;
};

static DiscoverResult DiscoverMethod(
    const char* methodName,
    const char** neighborMethods,
    int requiredMatches,
    uintptr_t base, size_t size)
{
    DiscoverResult result = { 0, 0 };
    size_t nameLen = strlen(methodName);

    uintptr_t stringAddrs[32];
    int numStrings = 0;

    for (size_t i = 0; i < size - nameLen - 1 && numStrings < 32; i++) {
        if (memcmp((void*)(base + i), methodName, nameLen + 1) == 0) {
            stringAddrs[numStrings++] = base + i;
        }
    }

    if (numStrings == 0) return result;

    for (int si = 0; si < numStrings; si++) {
        uintptr_t strAddr = stringAddrs[si];

        for (size_t i = 0; i < size - 16; i += 4) {
            uintptr_t refAddr = base + i;

            __try {
                if (*(uintptr_t*)refAddr != strAddr) continue;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

            int strides[] = { 8, 12 };
            for (int s = 0; s < 2; s++) {
                int stride = strides[s];

                uintptr_t funcPtr = 0;
                __try { funcPtr = *(uintptr_t*)(refAddr + 4); }
                __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

                if (!IsExec(funcPtr)) continue;

                int matches = 0;
                for (int j = -20; j <= 20; j++) {
                    if (j == 0) continue;
                    uintptr_t entryAddr = refAddr + j * stride;
                    if (entryAddr < base || entryAddr + stride > base + size) continue;

                    uintptr_t namePtr = 0;
                    __try { namePtr = *(uintptr_t*)entryAddr; }
                    __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

                    if (!IsValidString(namePtr, base, size)) continue;

                    __try {
                        for (int k = 0; neighborMethods[k]; k++) {
                            if (strcmp((const char*)namePtr, neighborMethods[k]) == 0) {
                                matches++;
                                break;
                            }
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }

                if (matches >= requiredMatches && matches > result.matchCount) {
                    result.funcAddr   = funcPtr;
                    result.matchCount = matches;
                }
            }
        }
    }

    return result;
}

// ================================================================
//  Hook typedefs and state
// ================================================================

typedef int (__cdecl *ScriptFunc_fn)(lua_State* L);

static ScriptFunc_fn orig_SetValue    = nullptr;  static uintptr_t addr_SetValue    = 0;
static ScriptFunc_fn orig_SetMinMax   = nullptr;  static uintptr_t addr_SetMinMax   = 0;
static ScriptFunc_fn orig_SetBarColor = nullptr;  static uintptr_t addr_SetBarColor = 0;

// ================================================================
//  Hook: StatusBar:SetValue
// ================================================================

static int __cdecl Hooked_SetValue(lua_State* L) {
    __try {
        void* widget = GetWidgetIdentity(L);
        if (!widget) goto pass_value;

        double val = api_tonumber(L, 2);
        uint32_t hash = DoubleBits(val);
        uint64_t key = MakeKey((uintptr_t)widget, METHOD_SETVALUE);

        if (CheckAndUpdate(key, hash)) {
            g_stats[METHOD_SETVALUE].skipped++;
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_value:
    g_stats[METHOD_SETVALUE].passed++;
    return orig_SetValue(L);
}

// ================================================================
//  Hook: StatusBar:SetMinMaxValues
// ================================================================

static int __cdecl Hooked_SetMinMax(lua_State* L) {
    __try {
        void* widget = GetWidgetIdentity(L);
        if (!widget) goto pass_minmax;

        uint32_t hash = DoubleBits(api_tonumber(L, 2))
                      ^ (DoubleBits(api_tonumber(L, 3)) * 0x9E3779B9);

        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETMINMAX), hash)) {
            g_stats[METHOD_SETMINMAX].skipped++;
            return 0;
        }
        InvalidateWidget((uintptr_t)widget, METHOD_SETVALUE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_minmax:
    g_stats[METHOD_SETMINMAX].passed++;
    return orig_SetMinMax(L);
}

// ================================================================
//  Hook: StatusBar:SetStatusBarColor
// ================================================================

static int __cdecl Hooked_SetBarColor(lua_State* L) {
    __try {
        void* widget = GetWidgetIdentity(L);
        if (!widget) goto pass_barcolor;

        int nargs = api_gettop(L);
        uint32_t hash = DoubleBits(api_tonumber(L, 2))
                      ^ (DoubleBits(api_tonumber(L, 3)) * 0x9E3779B9)
                      ^ (DoubleBits(api_tonumber(L, 4)) * 0x517CC1B7)
                      ^ (DoubleBits(nargs >= 5 ? api_tonumber(L, 5) : 1.0) * 0x85EBCA6B);

        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETBARCOLOR), hash)) {
            g_stats[METHOD_SETBARCOLOR].skipped++;
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_barcolor:
    g_stats[METHOD_SETBARCOLOR].passed++;
    return orig_SetBarColor(L);
}

// ================================================================
//  Hook Installation Helper
// ================================================================

static bool InstallHook(const char* name, uintptr_t addr,
                        void* hookFn, void** origFn)
{
    if (addr == 0) {
        Log("[UICache]   %-30s NOT FOUND", name);
        return false;
    }

    MH_STATUS status = MH_CreateHook((void*)addr, hookFn, origFn);
    if (status != MH_OK) {
        Log("[UICache]   %-30s MH_CreateHook failed (%d)", name, (int)status);
        return false;
    }

    status = MH_EnableHook((void*)addr);
    if (status != MH_OK) {
        Log("[UICache]   %-30s MH_EnableHook failed (%d)", name, (int)status);
        return false;
    }

    Log("[UICache]   %-30s 0x%08X  [ OK ]", name, (unsigned)addr);
    return true;
}

// ================================================================
//  API
// ================================================================

namespace UICache {

bool Init() {
    Log("[UICache] ====================================");
    Log("[UICache]  UI Widget Cache (StatusBar only)");
    Log("[UICache]  v2.0.4: 10 hooks -> 3 (safety fix)");
    Log("[UICache] ====================================");

    HMODULE hWow = GetModuleHandleA(NULL);
    if (!hWow) return false;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hWow, &modInfo, sizeof(modInfo)))
        return false;

    uintptr_t base = (uintptr_t)hWow;
    size_t size = modInfo.SizeOfImage;

    Log("[UICache] Scanning Wow.exe for StatusBar methods...");

    const char* statusBarNeighbors[] = {
        "SetMinMaxValues", "GetMinMaxValues", "SetStatusBarColor",
        "SetStatusBarTexture", "GetStatusBarTexture", "GetValue",
        "SetOrientation", "GetOrientation", "SetRotatesTexture",
        "SetFillStyle", "SetValue",
        NULL
    };

    DiscoverResult dr;

    dr = DiscoverMethod("SetValue", statusBarNeighbors, 3, base, size);
    addr_SetValue = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   StatusBar:SetValue      matched %d neighbors", dr.matchCount);

    dr = DiscoverMethod("SetMinMaxValues", statusBarNeighbors, 3, base, size);
    addr_SetMinMax = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   StatusBar:SetMinMax     matched %d neighbors", dr.matchCount);

    dr = DiscoverMethod("SetStatusBarColor", statusBarNeighbors, 3, base, size);
    addr_SetBarColor = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   StatusBar:SetBarColor   matched %d neighbors", dr.matchCount);

    Log("[UICache] Installing hooks...");

    int hooked = 0;
    if (InstallHook("StatusBar:SetValue",          addr_SetValue,    (void*)Hooked_SetValue,    (void**)&orig_SetValue))    hooked++;
    if (InstallHook("StatusBar:SetMinMaxValues",   addr_SetMinMax,   (void*)Hooked_SetMinMax,   (void**)&orig_SetMinMax))   hooked++;
    if (InstallHook("StatusBar:SetStatusBarColor", addr_SetBarColor, (void*)Hooked_SetBarColor, (void**)&orig_SetBarColor)) hooked++;

    if (hooked == 0) {
        Log("[UICache] No hooks installed — DISABLED");
        return false;
    }

    g_active = true;

    Log("[UICache] ====================================");
    Log("[UICache]  Hooks: %d/3 active (StatusBar only)", hooked);
    Log("[UICache]  Removed: SetText, SetTextColor, SetTexture,");
    Log("[UICache]           SetVertexColor, SetAlpha, SetWidth, SetHeight");
    Log("[UICache]  Reason: engine resets these via C++ bypassing hooks");
    Log("[UICache]  [ OK ] ACTIVE");
    Log("[UICache] ====================================");

    return true;
}

void ClearCache() {
    if (!g_active) return;
    memset(g_cache, 0, sizeof(g_cache));
}

void Shutdown() {
    if (!g_active) return;

    if (addr_SetValue)    MH_DisableHook((void*)addr_SetValue);
    if (addr_SetMinMax)   MH_DisableHook((void*)addr_SetMinMax);
    if (addr_SetBarColor) MH_DisableHook((void*)addr_SetBarColor);

    g_active = false;

    const char* names[] = { "SetValue", "SetMinMax", "SetBarColor" };

    Log("[UICache] Shutdown:");
    long totalSkipped = 0, totalPassed = 0;

    for (int i = 0; i < NUM_METHODS; i++) {
        long sk = g_stats[i].skipped;
        long ps = g_stats[i].passed;
        long total = sk + ps;
        totalSkipped += sk;
        totalPassed  += ps;

        if (total > 0) {
            Log("[UICache]   %-12s  skipped: %ld  passed: %ld  (%.1f%% skip)",
                names[i], sk, ps, (double)sk / total * 100.0);
        }
    }

    long grandTotal = totalSkipped + totalPassed;
    if (grandTotal > 0) {
        Log("[UICache]   TOTAL         skipped: %ld  passed: %ld  (%.1f%% skip)",
            totalSkipped, totalPassed,
            (double)totalSkipped / grandTotal * 100.0);
    }
}

Stats GetStats() {
    Stats s;
    s.skipped = 0;
    s.passed  = 0;
    for (int i = 0; i < NUM_METHODS; i++) {
        s.skipped += g_stats[i].skipped;
        s.passed  += g_stats[i].passed;
    }
    s.active = g_active;
    return s;
}

} // namespace UICache