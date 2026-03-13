#include "ui_cache.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <psapi.h>

#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
//  Lua API — known addresses build 12340
// ================================================================

typedef struct lua_State lua_State;
typedef double lua_Number;

typedef const char* (__cdecl *fn_lua_tolstring)(lua_State* L, int index, size_t* len);
typedef void*       (__cdecl *fn_lua_touserdata)(lua_State* L, int index);
typedef lua_Number  (__cdecl *fn_lua_tonumber)(lua_State* L, int index);
typedef int         (__cdecl *fn_lua_gettop)(lua_State* L);

static fn_lua_tolstring   api_tolstring  = (fn_lua_tolstring)0x0084E0E0;
static fn_lua_touserdata  api_getwidget  = (fn_lua_touserdata)0x0084E150;
static fn_lua_tonumber    api_tonumber   = (fn_lua_tonumber)0x0084E030;
static fn_lua_gettop      api_gettop     = (fn_lua_gettop)0x0084DBD0;

// ================================================================
//  FNV-1a Hash
// ================================================================

static inline uint32_t FNV1a(const char* str, size_t len) {
    uint32_t hash = 0x811C9DC5;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)str[i];
        hash *= 0x01000193;
    }
    return hash;
}

// Float-to-bits for hashing doubles
static inline uint32_t DoubleBits(double val) {
    // Truncate to float precision — avoids false misses from
    // tiny floating point differences (e.g. 0.999999 vs 1.0)
    float f = (float)val;
    uint32_t bits;
    memcpy(&bits, &f, 4);
    return bits;
}

// ================================================================
//  Widget Cache — shared by all hooks
//
//  Key:   (widget_ptr << 3) | method_id
//  Value: hash of arguments
//
//  method_id:
//    0 = SetText
//    1 = SetValue
//    2 = SetMinMaxValues
//    3 = SetStatusBarColor
// ================================================================

static constexpr int METHOD_SETTEXT          = 0;
static constexpr int METHOD_SETVALUE         = 1;
static constexpr int METHOD_SETMINMAX        = 2;
static constexpr int METHOD_SETBARCOLOR      = 3;

static constexpr int CACHE_SIZE  = 8192;
static constexpr int CACHE_MASK  = CACHE_SIZE - 1;
static constexpr int CACHE_PROBE = 8;

struct CacheEntry {
    uint64_t  key;
    uint32_t  hash;
    bool      occupied;
};

static CacheEntry g_cache[CACHE_SIZE] = {};

static inline uint64_t MakeKey(uintptr_t widget, int method) {
    return ((uint64_t)widget << 3) | (uint64_t)method;
}

static inline int CacheSlot(uint64_t key) {
    uint32_t k = (uint32_t)(key >> 3) ^ (uint32_t)(key);
    return (int)((k >> 3) & CACHE_MASK);
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
            if (g_cache[idx].hash == hash) return true; // SKIP
            g_cache[idx].hash = hash;
            return false;
        }
    }
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
    volatile long skipped;
    volatile long passed;
};

static MethodStats g_stats[4] = {};
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

    // Step 1: Find all instances of the method name string
    uintptr_t stringAddrs[32];
    int numStrings = 0;

    for (size_t i = 0; i < size - nameLen - 1 && numStrings < 32; i++) {
        if (memcmp((void*)(base + i), methodName, nameLen + 1) == 0) {
            stringAddrs[numStrings++] = base + i;
        }
    }

    if (numStrings == 0) return result;

    // Step 2: Find references in method tables
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
//  Hook: FontString:SetText
// ================================================================

typedef int (__cdecl *ScriptFunc_fn)(lua_State* L);

static ScriptFunc_fn orig_SetText = nullptr;
static uintptr_t     addr_SetText = 0;

static int __cdecl Hooked_SetText(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto passthrough_text;

        size_t textLen = 0;
        const char* text = api_tolstring(L, 2, &textLen);

        if (!text || textLen == 0) {
            InvalidateWidget((uintptr_t)widget, METHOD_SETTEXT);
            goto passthrough_text;
        }

        uint32_t hash = FNV1a(text, textLen);
        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETTEXT), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETTEXT].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

passthrough_text:
    InterlockedIncrement(&g_stats[METHOD_SETTEXT].passed);
    return orig_SetText(L);
}

// ================================================================
//  Hook: StatusBar:SetValue
//
//  Lua stack:
//    1 = self (StatusBar userdata)
//    2 = value (number)
// ================================================================

static ScriptFunc_fn orig_SetValue = nullptr;
static uintptr_t     addr_SetValue = 0;

static int __cdecl Hooked_SetValue(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto passthrough_value;

        lua_Number value = api_tonumber(L, 2);
        uint32_t hash = DoubleBits(value);

        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETVALUE), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETVALUE].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

passthrough_value:
    InterlockedIncrement(&g_stats[METHOD_SETVALUE].passed);
    return orig_SetValue(L);
}

// ================================================================
//  Hook: StatusBar:SetMinMaxValues
//
//  Lua stack:
//    1 = self
//    2 = min (number)
//    3 = max (number)
//
//  When min/max change, invalidate SetValue cache for this widget
//  (same value might now fill a different percentage)
// ================================================================

static ScriptFunc_fn orig_SetMinMax = nullptr;
static uintptr_t     addr_SetMinMax = 0;

static int __cdecl Hooked_SetMinMax(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto passthrough_minmax;

        lua_Number lo = api_tonumber(L, 2);
        lua_Number hi = api_tonumber(L, 3);

        // Combine both values into one hash
        uint32_t h1 = DoubleBits(lo);
        uint32_t h2 = DoubleBits(hi);
        uint32_t hash = h1 ^ (h2 * 0x9E3779B9);

        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETMINMAX), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETMINMAX].skipped);
            return 0;
        }

        // Min/max changed — invalidate SetValue cache
        InvalidateWidget((uintptr_t)widget, METHOD_SETVALUE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

passthrough_minmax:
    InterlockedIncrement(&g_stats[METHOD_SETMINMAX].passed);
    return orig_SetMinMax(L);
}

// ================================================================
//  Hook: StatusBar:SetStatusBarColor
//
//  Lua stack:
//    1 = self
//    2 = r (number)
//    3 = g (number)
//    4 = b (number)
//    5 = a (number, optional)
// ================================================================

static ScriptFunc_fn orig_SetBarColor = nullptr;
static uintptr_t     addr_SetBarColor = 0;

static int __cdecl Hooked_SetBarColor(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto passthrough_color;

        int nargs = api_gettop(L);

        lua_Number r = api_tonumber(L, 2);
        lua_Number g = api_tonumber(L, 3);
        lua_Number b = api_tonumber(L, 4);
        lua_Number a = (nargs >= 5) ? api_tonumber(L, 5) : 1.0;

        uint32_t hash = DoubleBits(r) ^ (DoubleBits(g) * 0x9E3779B9)
                      ^ (DoubleBits(b) * 0x517CC1B7) ^ (DoubleBits(a) * 0x85EBCA6B);

        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETBARCOLOR), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETBARCOLOR].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

passthrough_color:
    InterlockedIncrement(&g_stats[METHOD_SETBARCOLOR].passed);
    return orig_SetBarColor(L);
}

// ================================================================
//  Hook Installation Helper
// ================================================================

static bool InstallHook(const char* name, uintptr_t addr,
                        void* hookFn, void** origFn)
{
    if (addr == 0) {
        Log("[UICache]   %-25s NOT FOUND", name);
        return false;
    }

    MH_STATUS status = MH_CreateHook((void*)addr, hookFn, origFn);
    if (status != MH_OK) {
        Log("[UICache]   %-25s MH_CreateHook failed (%d)", name, (int)status);
        return false;
    }

    status = MH_EnableHook((void*)addr);
    if (status != MH_OK) {
        Log("[UICache]   %-25s MH_EnableHook failed (%d)", name, (int)status);
        return false;
    }

    Log("[UICache]   %-25s 0x%08X  [ OK ]", name, (unsigned)addr);
    return true;
}

// ================================================================
//  API
// ================================================================

namespace UICache {

bool Init() {
    Log("[UICache] ====================================");
    Log("[UICache]  UI Widget Cache (auto-discover)");
    Log("[UICache] ====================================");

    HMODULE hWow = GetModuleHandleA(NULL);
    if (!hWow) return false;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hWow, &modInfo, sizeof(modInfo)))
        return false;

    uintptr_t base = (uintptr_t)hWow;
    size_t size = modInfo.SizeOfImage;

    Log("[UICache] Scanning Wow.exe (0x%08X, %u bytes)...",
        (unsigned)base, (unsigned)size);

    // --- FontString:SetText ---
    const char* fontStringNeighbors[] = {
        "GetText", "SetFont", "SetTextColor", "SetTextHeight",
        "GetStringWidth", "SetAlpha", "GetAlpha", "SetJustifyH",
        "SetShadowOffset", "SetShadowColor", "SetFormattedText",
        NULL
    };

    DiscoverResult dr = DiscoverMethod("SetText", fontStringNeighbors, 3, base, size);
    addr_SetText = dr.funcAddr;
    if (dr.funcAddr)
        Log("[UICache]   FontString:SetText   found (matched %d neighbors)", dr.matchCount);

    // --- StatusBar:SetValue ---
    const char* statusBarNeighbors[] = {
        "SetMinMaxValues", "GetMinMaxValues", "SetStatusBarColor",
        "SetStatusBarTexture", "GetStatusBarTexture", "GetValue",
        "SetOrientation", "GetOrientation", "SetRotatesTexture",
        "SetFillStyle",
        NULL
    };

    dr = DiscoverMethod("SetValue", statusBarNeighbors, 3, base, size);
    addr_SetValue = dr.funcAddr;
    if (dr.funcAddr)
        Log("[UICache]   StatusBar:SetValue   found (matched %d neighbors)", dr.matchCount);

    // --- StatusBar:SetMinMaxValues ---
    dr = DiscoverMethod("SetMinMaxValues", statusBarNeighbors, 3, base, size);
    addr_SetMinMax = dr.funcAddr;
    if (dr.funcAddr)
        Log("[UICache]   StatusBar:SetMinMax  found (matched %d neighbors)", dr.matchCount);

    // --- StatusBar:SetStatusBarColor ---
    dr = DiscoverMethod("SetStatusBarColor", statusBarNeighbors, 3, base, size);
    addr_SetBarColor = dr.funcAddr;
    if (dr.funcAddr)
        Log("[UICache]   StatusBar:SetBarClr  found (matched %d neighbors)", dr.matchCount);

    // Install hooks
    Log("[UICache] Installing hooks...");

    int hooked = 0;
    if (InstallHook("FontString:SetText",       addr_SetText,    (void*)Hooked_SetText,    (void**)&orig_SetText))    hooked++;
    if (InstallHook("StatusBar:SetValue",        addr_SetValue,   (void*)Hooked_SetValue,   (void**)&orig_SetValue))   hooked++;
    if (InstallHook("StatusBar:SetMinMaxValues", addr_SetMinMax,  (void*)Hooked_SetMinMax,  (void**)&orig_SetMinMax))  hooked++;
    if (InstallHook("StatusBar:SetStatusBarColor", addr_SetBarColor, (void*)Hooked_SetBarColor, (void**)&orig_SetBarColor)) hooked++;

    if (hooked == 0) {
        Log("[UICache] No hooks installed — DISABLED");
        return false;
    }

    g_active = true;

    Log("[UICache] ====================================");
    Log("[UICache]  Hooks: %d/4 active", hooked);
    Log("[UICache]  Cache: %d slots, FNV-1a + float-bits hash", CACHE_SIZE);
    Log("[UICache]  Taint: SAFE (C-level hooks, invisible to Lua)");
    Log("[UICache]  [ OK ] ACTIVE");
    Log("[UICache] ====================================");

    return true;
}

void Shutdown() {
    if (!g_active) return;

    if (addr_SetText)    MH_DisableHook((void*)addr_SetText);
    if (addr_SetValue)   MH_DisableHook((void*)addr_SetValue);
    if (addr_SetMinMax)  MH_DisableHook((void*)addr_SetMinMax);
    if (addr_SetBarColor) MH_DisableHook((void*)addr_SetBarColor);

    g_active = false;

    const char* names[] = { "SetText", "SetValue", "SetMinMax", "SetBarColor" };

    Log("[UICache] Shutdown:");
    long totalSkipped = 0, totalPassed = 0;

    for (int i = 0; i < 4; i++) {
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
    for (int i = 0; i < 4; i++) {
        s.skipped += g_stats[i].skipped;
        s.passed  += g_stats[i].passed;
    }
    s.active = g_active;
    return s;
}

} // namespace UICache