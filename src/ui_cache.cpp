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

// lua_tolstring(L, idx, &len) — returns string + length
typedef const char* (__cdecl *fn_lua_tolstring)(lua_State* L, int index, size_t* len);
static fn_lua_tolstring api_tolstring = (fn_lua_tolstring)0x0084E0E0;

// WoW's internal function that extracts C++ object pointer from userdata
// For userdata: returns *(void**)(Udata + 0x14) = the C++ object pointer
// Perfect as a unique per-widget cache key
typedef void* (__cdecl *fn_lua_getwidget)(lua_State* L, int index);
static fn_lua_getwidget api_getwidget = (fn_lua_getwidget)0x0084E150;

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

// ================================================================
//  Widget Text Cache — open-addressing hash table
//
//  Key:   C++ widget pointer (unique per FontString)
//  Value: FNV-1a hash of last SetText argument
//
//  Stale entries are harmless — they get overwritten when
//  the slot is needed for a new widget.
// ================================================================

static constexpr int CACHE_SIZE = 4096;
static constexpr int CACHE_MASK = CACHE_SIZE - 1;
static constexpr int CACHE_PROBE = 8;

struct CacheEntry {
    uintptr_t widget;
    uint32_t  textHash;
    bool      occupied;
};

static CacheEntry g_cache[CACHE_SIZE] = {};
static volatile long g_statsSkipped = 0;
static volatile long g_statsPassed  = 0;
static bool          g_active       = false;
static uintptr_t     g_setTextAddr  = 0;

static inline int CacheSlot(uintptr_t widget) {
    return (int)((widget >> 3) & CACHE_MASK);
}

static bool CheckAndUpdate(uintptr_t widget, uint32_t hash) {
    int slot = CacheSlot(widget);
    for (int i = 0; i < CACHE_PROBE; i++) {
        int idx = (slot + i) & CACHE_MASK;
        if (!g_cache[idx].occupied) {
            g_cache[idx].widget   = widget;
            g_cache[idx].textHash = hash;
            g_cache[idx].occupied = true;
            return false; // new entry — pass through
        }
        if (g_cache[idx].widget == widget) {
            if (g_cache[idx].textHash == hash)
                return true; // SKIP — same text
            g_cache[idx].textHash = hash;
            return false; // changed — pass through
        }
    }
    return false; // table full — pass through
}

// ================================================================
//  Auto-Discovery: Find Script_FontStringSetText
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
        // Must be short readable ASCII string
        for (int i = 0; i < 64; i++) {
            if (s[i] == '\0') return (i > 0);
            if (s[i] < 0x20 || s[i] > 0x7E) return false;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return false;
}

static uintptr_t DiscoverSetTextAddress() {
    HMODULE hWow = GetModuleHandleA(NULL);
    if (!hWow) return 0;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hWow, &modInfo, sizeof(modInfo)))
        return 0;

    uintptr_t base = (uintptr_t)hWow;
    size_t size = modInfo.SizeOfImage;

    Log("[UICache] Scanning Wow.exe (base=0x%08X, size=%u) for FontString methods...",
        (unsigned)base, (unsigned)size);

    // Step 1: Find all "SetText\0" strings
    uintptr_t setTextStrings[32];
    int numFound = 0;

    for (size_t i = 0; i < size - 8 && numFound < 32; i++) {
        if (memcmp((void*)(base + i), "SetText\0", 8) == 0) {
            setTextStrings[numFound++] = base + i;
        }
    }

    Log("[UICache] Found %d 'SetText' strings", numFound);
    if (numFound == 0) return 0;

    // Step 2: For each string, find references in method tables
    for (int si = 0; si < numFound; si++) {
        uintptr_t strAddr = setTextStrings[si];

        // Scan for dwords pointing to this string
        for (size_t i = 0; i < size - 16; i += 4) {
            uintptr_t refAddr = base + i;

            __try {
                if (*(uintptr_t*)refAddr != strAddr) continue;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

            // Found reference at refAddr
            // Try strides 8 and 12 (common method table entry sizes)
            int strides[] = { 8, 12 };

            for (int s = 0; s < 2; s++) {
                int stride = strides[s];

                // The function pointer should be at refAddr + 4
                uintptr_t funcPtr = 0;
                __try { funcPtr = *(uintptr_t*)(refAddr + 4); }
                __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

                if (!IsExec(funcPtr)) continue;

                // Verify: check neighboring entries for FontString methods
                int fontStringMatches = 0;
                const char* fontStringMethods[] = {
                    "GetText", "SetFont", "SetTextColor",
                    "SetTextHeight", "GetStringWidth",
                    "SetAlpha", "GetAlpha", "SetJustifyH",
                    "SetShadowOffset", "SetShadowColor",
                    NULL
                };

                for (int j = -15; j <= 15; j++) {
                    if (j == 0) continue;
                    uintptr_t entryAddr = refAddr + j * stride;
                    if (entryAddr < base || entryAddr + stride > base + size) continue;

                    uintptr_t namePtr = 0;
                    __try { namePtr = *(uintptr_t*)entryAddr; }
                    __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

                    if (!IsValidString(namePtr, base, size)) continue;

                    __try {
                        for (int k = 0; fontStringMethods[k]; k++) {
                            if (strcmp((const char*)namePtr, fontStringMethods[k]) == 0) {
                                fontStringMatches++;
                                break;
                            }
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }

                if (fontStringMatches >= 3) {
                    Log("[UICache] FontString method table found!");
                    Log("[UICache]   String ref at:  0x%08X", (unsigned)refAddr);
                    Log("[UICache]   Function at:    0x%08X", (unsigned)funcPtr);
                    Log("[UICache]   Stride:         %d bytes", stride);
                    Log("[UICache]   Nearby matches: %d FontString methods", fontStringMatches);
                    return funcPtr;
                }
            }
        }
    }

    Log("[UICache] FontString::SetText not found in method tables");
    return 0;
}

// ================================================================
//  Hook: Script_FontStringSetText
//
//  Original: int __cdecl Script_FontStringSetText(lua_State* L)
//
//  Lua stack:
//    1 = self (FontString userdata)
//    2 = text (string or nil)
//
// ================================================================

typedef int (__cdecl *SetText_fn)(lua_State* L);
static SetText_fn orig_SetText = nullptr;

static int __cdecl Hooked_SetText(lua_State* L) {
    __try {
        // Get C++ widget pointer from arg 1
        void* widget = api_getwidget(L, 1);
        if (!widget) {
            InterlockedIncrement(&g_statsPassed);
            return orig_SetText(L);
        }

        // Get text string from arg 2
        size_t textLen = 0;
        const char* text = api_tolstring(L, 2, &textLen);

        if (!text || textLen == 0) {
            // SetText(nil) or SetText("") — always pass through
            // Invalidate cache for this widget
            int slot = CacheSlot((uintptr_t)widget);
            for (int i = 0; i < CACHE_PROBE; i++) {
                int idx = (slot + i) & CACHE_MASK;
                if (g_cache[idx].occupied && g_cache[idx].widget == (uintptr_t)widget) {
                    g_cache[idx].textHash = 0;
                    break;
                }
                if (!g_cache[idx].occupied) break;
            }
            InterlockedIncrement(&g_statsPassed);
            return orig_SetText(L);
        }

        // Hash text and check cache
        uint32_t hash = FNV1a(text, textLen);

        if (CheckAndUpdate((uintptr_t)widget, hash)) {
            InterlockedIncrement(&g_statsSkipped);
            return 0; // SKIP — identical text
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // On any exception, just call original
    }

    InterlockedIncrement(&g_statsPassed);
    return orig_SetText(L);
}

// ================================================================
//  API
// ================================================================

namespace UICache {

bool Init() {
    Log("[UICache] ====================================");
    Log("[UICache]  FontString:SetText Cache (auto-discover)");
    Log("[UICache] ====================================");

    // Auto-discover the SetText function address
    g_setTextAddr = DiscoverSetTextAddress();

    if (g_setTextAddr == 0) {
        Log("[UICache] DISABLED — could not find SetText address");
        return false;
    }

    // Hook with MinHook
    MH_STATUS status = MH_CreateHook(
        (void*)g_setTextAddr,
        (void*)Hooked_SetText,
        (void**)&orig_SetText
    );

    if (status != MH_OK) {
        Log("[UICache] MH_CreateHook failed (status %d)", (int)status);
        return false;
    }

    status = MH_EnableHook((void*)g_setTextAddr);
    if (status != MH_OK) {
        Log("[UICache] MH_EnableHook failed (status %d)", (int)status);
        return false;
    }

    g_active = true;

    Log("[UICache]  Hook:  0x%08X -> Hooked_SetText", (unsigned)g_setTextAddr);
    Log("[UICache]  Cache: %d slots, FNV-1a hash, %d-probe", CACHE_SIZE, CACHE_PROBE);
    Log("[UICache]  Taint: SAFE (C-level hook, invisible to Lua)");
    Log("[UICache]  [ OK ] ACTIVE");
    Log("[UICache] ====================================");

    return true;
}

void Shutdown() {
    if (!g_active) return;

    MH_DisableHook((void*)g_setTextAddr);
    g_active = false;

    long total = g_statsSkipped + g_statsPassed;
    Log("[UICache] Shutdown. Skipped: %ld, Passed: %ld (%.1f%% skip rate)",
        g_statsSkipped, g_statsPassed,
        total > 0 ? (double)g_statsSkipped / total * 100.0 : 0.0);
}

Stats GetStats() {
    Stats s;
    s.skipped = g_statsSkipped;
    s.passed  = g_statsPassed;
    s.active  = g_active;
    return s;
}

} // namespace UICache