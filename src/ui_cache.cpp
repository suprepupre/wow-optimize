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
typedef int         (__cdecl *fn_lua_type)(lua_State* L, int index);

static fn_lua_tolstring   api_tolstring = (fn_lua_tolstring)0x0084E0E0;
static fn_lua_touserdata  api_getwidget = (fn_lua_touserdata)0x0084E150;
static fn_lua_tonumber    api_tonumber  = (fn_lua_tonumber)0x0084E030;
static fn_lua_gettop      api_gettop    = (fn_lua_gettop)0x0084DBD0;
static fn_lua_type        api_type      = (fn_lua_type)0x0084DEB0;

#define LUA_TSTRING  4
#define LUA_TNUMBER  3

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

static inline uint32_t DoubleBits(double val) {
    float f = (float)val;
    uint32_t bits;
    memcpy(&bits, &f, 4);
    return bits;
}

// ================================================================
//  Widget Cache — shared by all hooks
// ================================================================

static constexpr int METHOD_SETTEXT         = 0;
static constexpr int METHOD_SETVALUE        = 1;
static constexpr int METHOD_SETMINMAX       = 2;
static constexpr int METHOD_SETBARCOLOR     = 3;
static constexpr int METHOD_SETTEXTCOLOR    = 4;
static constexpr int METHOD_SETTEXTURE      = 5;
static constexpr int METHOD_SETALPHA        = 6;
static constexpr int METHOD_SETWIDTH        = 7;
static constexpr int METHOD_SETHEIGHT       = 8;
static constexpr int METHOD_SETVERTEXCOLOR  = 9;
static constexpr int NUM_METHODS            = 10;

// BUGFIX #7: 32768 slots (128KB) — room for 2000+ widgets × 7 methods
static constexpr int CACHE_SIZE  = 32768;
static constexpr int CACHE_MASK  = CACHE_SIZE - 1;
static constexpr int CACHE_PROBE = 4;   // lower probe depth OK at lower load factor

struct CacheEntry {
    uint64_t  key;
    uint32_t  hash;
    bool      occupied;
};

static CacheEntry g_cache[CACHE_SIZE] = {};

static inline uint64_t MakeKey(uintptr_t widget, int method) {
    return ((uint64_t)widget << 4) | (uint64_t)method;
}


// BUGFIX #8: murmur-style finalizer for better avalanche
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
    // BUGFIX #6: all probe slots occupied by other keys — evict last slot
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
    volatile long skipped;
    volatile long passed;
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

static ScriptFunc_fn orig_SetText     = nullptr;  static uintptr_t addr_SetText     = 0;
static ScriptFunc_fn orig_SetValue    = nullptr;  static uintptr_t addr_SetValue    = 0;
static ScriptFunc_fn orig_SetMinMax   = nullptr;  static uintptr_t addr_SetMinMax   = 0;
static ScriptFunc_fn orig_SetBarColor = nullptr;  static uintptr_t addr_SetBarColor = 0;
static ScriptFunc_fn orig_SetTextColor= nullptr;  static uintptr_t addr_SetTextColor= 0;
static ScriptFunc_fn orig_SetTexture  = nullptr;  static uintptr_t addr_SetTexture  = 0;
static ScriptFunc_fn orig_SetAlpha    = nullptr;  static uintptr_t addr_SetAlpha    = 0;
static ScriptFunc_fn orig_SetWidth       = nullptr;  static uintptr_t addr_SetWidth       = 0;
static ScriptFunc_fn orig_SetHeight      = nullptr;  static uintptr_t addr_SetHeight      = 0;
static ScriptFunc_fn orig_SetVertexColor = nullptr;  static uintptr_t addr_SetVertexColor = 0;

// ================================================================
//  Hook: FontString:SetText
// ================================================================

static int __cdecl Hooked_SetText(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto pass_text;

        size_t textLen = 0;
        const char* text = api_tolstring(L, 2, &textLen);

        if (!text || textLen == 0) {
            InvalidateWidget((uintptr_t)widget, METHOD_SETTEXT);
            goto pass_text;
        }

        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETTEXT), FNV1a(text, textLen))) {
            InterlockedIncrement(&g_stats[METHOD_SETTEXT].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_text:
    InterlockedIncrement(&g_stats[METHOD_SETTEXT].passed);
    return orig_SetText(L);
}

// ================================================================
//  Hook: StatusBar:SetValue
// ================================================================

static int __cdecl Hooked_SetValue(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto pass_value;

        uint32_t hash = DoubleBits(api_tonumber(L, 2));
        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETVALUE), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETVALUE].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_value:
    InterlockedIncrement(&g_stats[METHOD_SETVALUE].passed);
    return orig_SetValue(L);
}

// ================================================================
//  Hook: StatusBar:SetMinMaxValues
// ================================================================

static int __cdecl Hooked_SetMinMax(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto pass_minmax;

        uint32_t hash = DoubleBits(api_tonumber(L, 2))
                      ^ (DoubleBits(api_tonumber(L, 3)) * 0x9E3779B9);

        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETMINMAX), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETMINMAX].skipped);
            return 0;
        }
        InvalidateWidget((uintptr_t)widget, METHOD_SETVALUE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_minmax:
    InterlockedIncrement(&g_stats[METHOD_SETMINMAX].passed);
    return orig_SetMinMax(L);
}

// ================================================================
//  Hook: StatusBar:SetStatusBarColor
// ================================================================

static int __cdecl Hooked_SetBarColor(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto pass_barcolor;

        int nargs = api_gettop(L);
        uint32_t hash = DoubleBits(api_tonumber(L, 2))
                      ^ (DoubleBits(api_tonumber(L, 3)) * 0x9E3779B9)
                      ^ (DoubleBits(api_tonumber(L, 4)) * 0x517CC1B7)
                      ^ (DoubleBits(nargs >= 5 ? api_tonumber(L, 5) : 1.0) * 0x85EBCA6B);

        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETBARCOLOR), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETBARCOLOR].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_barcolor:
    InterlockedIncrement(&g_stats[METHOD_SETBARCOLOR].passed);
    return orig_SetBarColor(L);
}

// ================================================================
//  Hook: FontString:SetTextColor(r, g, b [, a])
// ================================================================

static int __cdecl Hooked_SetTextColor(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto pass_textcolor;

        int nargs = api_gettop(L);
        uint32_t hash = DoubleBits(api_tonumber(L, 2))
                      ^ (DoubleBits(api_tonumber(L, 3)) * 0x9E3779B9)
                      ^ (DoubleBits(api_tonumber(L, 4)) * 0x517CC1B7)
                      ^ (DoubleBits(nargs >= 5 ? api_tonumber(L, 5) : 1.0) * 0x85EBCA6B);

        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETTEXTCOLOR), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETTEXTCOLOR].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_textcolor:
    InterlockedIncrement(&g_stats[METHOD_SETTEXTCOLOR].passed);
    return orig_SetTextColor(L);
}

// ================================================================
//  Hook: Texture:SetTexture(path_or_id)
//
//  Arg 2 can be:
//    string  — texture path ("Interface\\Icons\\...")
//    number  — texture file ID
//    nil     — clear texture
// ================================================================

static int __cdecl Hooked_SetTexture(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto pass_texture;

        int argType = api_type(L, 2);
        uint32_t hash;

        if (argType == LUA_TSTRING) {
            size_t len = 0;
            const char* path = api_tolstring(L, 2, &len);
            if (!path || len == 0) {
                InvalidateWidget((uintptr_t)widget, METHOD_SETTEXTURE);
                goto pass_texture;
            }
            hash = FNV1a(path, len);
        } else if (argType == LUA_TNUMBER) {
            hash = DoubleBits(api_tonumber(L, 2));
        } else {
            // nil or other — clear texture, always pass through
            InvalidateWidget((uintptr_t)widget, METHOD_SETTEXTURE);
            goto pass_texture;
        }

        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETTEXTURE), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETTEXTURE].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_texture:
    InterlockedIncrement(&g_stats[METHOD_SETTEXTURE].passed);
    return orig_SetTexture(L);
}

// ================================================================
//  Hook: Region:SetAlpha(alpha)
// ================================================================

static int __cdecl Hooked_SetAlpha(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto pass_alpha;

        uint32_t hash = DoubleBits(api_tonumber(L, 2));
        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETALPHA), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETALPHA].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_alpha:
    InterlockedIncrement(&g_stats[METHOD_SETALPHA].passed);
    return orig_SetAlpha(L);
}

// ================================================================
//  Hook: Region:SetWidth(width)
// ================================================================

static int __cdecl Hooked_SetWidth(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto pass_width;

        uint32_t hash = DoubleBits(api_tonumber(L, 2));
        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETWIDTH), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETWIDTH].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_width:
    InterlockedIncrement(&g_stats[METHOD_SETWIDTH].passed);
    return orig_SetWidth(L);
}

// ================================================================
//  Hook: Region:SetHeight(height)
// ================================================================

static int __cdecl Hooked_SetHeight(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto pass_height;

        uint32_t hash = DoubleBits(api_tonumber(L, 2));
        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETHEIGHT), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETHEIGHT].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_height:
    InterlockedIncrement(&g_stats[METHOD_SETHEIGHT].passed);
    return orig_SetHeight(L);
}

// ================================================================
//  Hook: Texture:SetVertexColor(r, g, b [, a])
// ================================================================

static int __cdecl Hooked_SetVertexColor(lua_State* L) {
    __try {
        void* widget = api_getwidget(L, 1);
        if (!widget) goto pass_vertexcolor;

        int nargs = api_gettop(L);
        uint32_t hash = DoubleBits(api_tonumber(L, 2))
                      ^ (DoubleBits(api_tonumber(L, 3)) * 0x9E3779B9)
                      ^ (DoubleBits(api_tonumber(L, 4)) * 0x517CC1B7)
                      ^ (DoubleBits(nargs >= 5 ? api_tonumber(L, 5) : 1.0) * 0x85EBCA6B);

        if (CheckAndUpdate(MakeKey((uintptr_t)widget, METHOD_SETVERTEXCOLOR), hash)) {
            InterlockedIncrement(&g_stats[METHOD_SETVERTEXCOLOR].skipped);
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

pass_vertexcolor:
    InterlockedIncrement(&g_stats[METHOD_SETVERTEXCOLOR].passed);
    return orig_SetVertexColor(L);
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

    // --- FontString neighbors (shared by SetText and SetTextColor) ---
    const char* fontStringNeighbors[] = {
        "GetText", "SetFont", "SetTextColor", "SetTextHeight",
        "GetStringWidth", "SetAlpha", "GetAlpha", "SetJustifyH",
        "SetShadowOffset", "SetShadowColor", "SetFormattedText",
        "SetText", "GetFont", "SetJustifyV", "SetIndentedWordWrap",
        NULL
    };

    // --- StatusBar neighbors ---
    const char* statusBarNeighbors[] = {
        "SetMinMaxValues", "GetMinMaxValues", "SetStatusBarColor",
        "SetStatusBarTexture", "GetStatusBarTexture", "GetValue",
        "SetOrientation", "GetOrientation", "SetRotatesTexture",
        "SetFillStyle", "SetValue",
        NULL
    };

    // --- Texture neighbors ---
    const char* textureNeighbors[] = {
        "GetTexture", "SetTexCoord", "GetTexCoord",
        "SetVertexColor", "GetVertexColor", "SetBlendMode",
        "SetDesaturated", "IsDesaturated", "SetNonBlocking",
        "SetRotation", "SetTexture",
        NULL
    };

    // --- Region neighbors (SetAlpha is on Region base class) ---
    const char* regionNeighbors[] = {
        "GetAlpha", "SetPoint", "GetPoint", "ClearAllPoints",
        "SetWidth", "SetHeight", "GetWidth", "GetHeight",
        "Show", "Hide", "IsShown", "IsVisible",
        "GetCenter", "SetParent", "GetParent", "GetNumPoints",
        "SetAllPoints", "SetAlpha",
        NULL
    };

    // Discover all methods
    DiscoverResult dr;

    dr = DiscoverMethod("SetText", fontStringNeighbors, 3, base, size);
    addr_SetText = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   FontString:SetText      matched %d neighbors", dr.matchCount);

    dr = DiscoverMethod("SetValue", statusBarNeighbors, 3, base, size);
    addr_SetValue = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   StatusBar:SetValue      matched %d neighbors", dr.matchCount);

    dr = DiscoverMethod("SetMinMaxValues", statusBarNeighbors, 3, base, size);
    addr_SetMinMax = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   StatusBar:SetMinMax     matched %d neighbors", dr.matchCount);

    dr = DiscoverMethod("SetStatusBarColor", statusBarNeighbors, 3, base, size);
    addr_SetBarColor = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   StatusBar:SetBarColor   matched %d neighbors", dr.matchCount);

    dr = DiscoverMethod("SetTextColor", fontStringNeighbors, 3, base, size);
    addr_SetTextColor = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   FontString:SetTextColor matched %d neighbors", dr.matchCount);

    dr = DiscoverMethod("SetTexture", textureNeighbors, 3, base, size);
    addr_SetTexture = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   Texture:SetTexture      matched %d neighbors", dr.matchCount);

    dr = DiscoverMethod("SetAlpha", regionNeighbors, 3, base, size);
    addr_SetAlpha = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   Region:SetAlpha         matched %d neighbors", dr.matchCount);
    dr = DiscoverMethod("SetWidth", regionNeighbors, 3, base, size);
    addr_SetWidth = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   Region:SetWidth         matched %d neighbors", dr.matchCount);

    dr = DiscoverMethod("SetHeight", regionNeighbors, 3, base, size);
    addr_SetHeight = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   Region:SetHeight        matched %d neighbors", dr.matchCount);

    dr = DiscoverMethod("SetVertexColor", textureNeighbors, 3, base, size);
    addr_SetVertexColor = dr.funcAddr;
    if (dr.funcAddr) Log("[UICache]   Texture:SetVertexColor  matched %d neighbors", dr.matchCount);    

    // Install hooks
    Log("[UICache] Installing hooks...");

    int hooked = 0;
    if (InstallHook("FontString:SetText",          addr_SetText,     (void*)Hooked_SetText,     (void**)&orig_SetText))     hooked++;
    if (InstallHook("StatusBar:SetValue",           addr_SetValue,    (void*)Hooked_SetValue,    (void**)&orig_SetValue))    hooked++;
    if (InstallHook("StatusBar:SetMinMaxValues",    addr_SetMinMax,   (void*)Hooked_SetMinMax,   (void**)&orig_SetMinMax))   hooked++;
    if (InstallHook("StatusBar:SetStatusBarColor",  addr_SetBarColor, (void*)Hooked_SetBarColor, (void**)&orig_SetBarColor)) hooked++;
    if (InstallHook("FontString:SetTextColor",      addr_SetTextColor,(void*)Hooked_SetTextColor,(void**)&orig_SetTextColor))hooked++;
    if (InstallHook("Texture:SetTexture",           addr_SetTexture,  (void*)Hooked_SetTexture,  (void**)&orig_SetTexture))  hooked++;
    if (InstallHook("Region:SetAlpha",              addr_SetAlpha,    (void*)Hooked_SetAlpha,    (void**)&orig_SetAlpha))    hooked++;
    if (InstallHook("Region:SetWidth",              addr_SetWidth,       (void*)Hooked_SetWidth,       (void**)&orig_SetWidth))       hooked++;
    if (InstallHook("Region:SetHeight",             addr_SetHeight,      (void*)Hooked_SetHeight,      (void**)&orig_SetHeight))      hooked++;
    if (InstallHook("Texture:SetVertexColor",       addr_SetVertexColor, (void*)Hooked_SetVertexColor, (void**)&orig_SetVertexColor)) hooked++;

    if (hooked == 0) {
        Log("[UICache] No hooks installed — DISABLED");
        return false;
    }

    g_active = true;

    Log("[UICache] ====================================");
    Log("[UICache]  Hooks: %d/10 active", hooked);
    Log("[UICache]  Cache: %d slots, FNV-1a + float-bits hash", CACHE_SIZE);
    Log("[UICache]  Taint: SAFE (C-level hooks, invisible to Lua)");
    Log("[UICache]  [ OK ] ACTIVE");
    Log("[UICache] ====================================");

    return true;
}

void Shutdown() {
    if (!g_active) return;

    if (addr_SetText)     MH_DisableHook((void*)addr_SetText);
    if (addr_SetValue)    MH_DisableHook((void*)addr_SetValue);
    if (addr_SetMinMax)   MH_DisableHook((void*)addr_SetMinMax);
    if (addr_SetBarColor) MH_DisableHook((void*)addr_SetBarColor);
    if (addr_SetTextColor)MH_DisableHook((void*)addr_SetTextColor);
    if (addr_SetTexture)  MH_DisableHook((void*)addr_SetTexture);
    if (addr_SetAlpha)    MH_DisableHook((void*)addr_SetAlpha);
    if (addr_SetWidth)       MH_DisableHook((void*)addr_SetWidth);
    if (addr_SetHeight)      MH_DisableHook((void*)addr_SetHeight);
    if (addr_SetVertexColor) MH_DisableHook((void*)addr_SetVertexColor);    

    g_active = false;

    const char* names[] = {
        "SetText", "SetValue", "SetMinMax", "SetBarColor",
        "SetTextColor", "SetTexture", "SetAlpha",
        "SetWidth", "SetHeight", "SetVertexColor"
    };

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