#include <windows.h>
#include <unordered_map>
#include "win_mutex.h"
#include "MinHook.h"
#include "version.h"
#include "font_glyph_cache.h"

extern "C" void Log(const char* fmt, ...);
extern volatile LONG g_deviceResetCounter;

static inline bool IsTeardownState() {
    uintptr_t gL = *(uintptr_t*)0x00D3F78C;
    return (gL < 0x10000 || gL > 0xFFE00000);
}

namespace FontGlyphCache {

struct GlyphKey {
    void* fontObj;
    unsigned int charCode;
    int fontSize;
    int a4;
    int a6;
    int a7;

    bool operator==(const GlyphKey& o) const {
        return fontObj == o.fontObj && charCode == o.charCode && fontSize == o.fontSize && a4 == o.a4 && a6 == o.a6 && a7 == o.a7;
    }
};

struct GlyphKeyHash {
    size_t operator()(const GlyphKey& k) const {
        size_t h = std::hash<void*>{}(k.fontObj);
        h ^= std::hash<unsigned int>{}(k.charCode) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<int>{}(k.fontSize) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<int>{}(k.a4) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<int>{}(k.a6) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<int>{}(k.a7) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

struct GlyphCacheEntry {
    uint8_t  structBytes[40];
    uint32_t textureSize;
    uint8_t* textureCopy;
};

static std::unordered_map<GlyphKey, GlyphCacheEntry, GlyphKeyHash> g_glyphCache;
static WinMutex g_cacheMutex;
static uint64_t g_hits = 0;
static uint64_t g_misses = 0;

// GxuAlloc type definition (sub_76E540 debug allocator)
typedef void* (__stdcall* fn_GxuAlloc_t)(int size, const char* file, int line, int flags);
static const fn_GxuAlloc_t fn_GxuAlloc = (fn_GxuAlloc_t)0x0076E540;

// sub_6C8CC0 detour hook typedef
typedef char (__cdecl* fn_GxuLoadGlyph_t)(void* fontObj, unsigned int charCode, int fontSize, int a4, void* outStruct, int a6, int a7);
static fn_GxuLoadGlyph_t orig_GxuLoadGlyph = nullptr;

static bool IsReadable(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD);
}

static bool IsDeviceReady() {
    uintptr_t pGxDevice = *(uintptr_t*)0x00C5DF88;
    if (pGxDevice < 0x10000 || pGxDevice > 0xFFE00000) return false;
    
    uintptr_t pD3d9Device = *(uintptr_t*)(pGxDevice + 0x397C);
    if (pD3d9Device < 0x10000 || pD3d9Device > 0xFFE00000) return false;
    
    uintptr_t pVtable = *(uintptr_t*)pD3d9Device;
    if (pVtable < 0x10000 || pVtable > 0xFFE00000) return false;
    
    return true;
}

static char __cdecl Hooked_GxuLoadGlyph(void* fontObj, unsigned int charCode, int fontSize, int a4, void* outStruct, int a6, int a7) {
    if (!IsDeviceReady()) {
        return 0; // Device not ready, fail gracefully to prevent crashes/hangs
    }
    if (fontObj && charCode && outStruct && !IsTeardownState()) {
        // Device change detection: track BOTH the CGxDevice wrapper pointer
        // AND the nested IDirect3DDevice9* pointer. During gxRestart (windowed
        // mode, vsync, resolution changes), WoW destroys the old CGxDevice and
        // creates a new one. Due to heap address reuse, the nested D3D device
        // pointer can be identical after recreation — checking only it misses
        // the reset. By tracking both levels, we catch all device transitions.
        static LONG lastResetCounter = -1;
        static DWORD deviceChangeTime = 0;  // tick when last device change was detected
        LONG currentResetCounter = g_deviceResetCounter;
        if (currentResetCounter != lastResetCounter) {
            Log("[FontGlyphCache] Device reset/change detected (resetCounter: %ld->%ld). Clearing glyph cache.",
                lastResetCounter, currentResetCounter);
            lastResetCounter = currentResetCounter;
            ClearCache();
            deviceChangeTime = GetTickCount();
        }

        // Grace period: after a device change, skip the cache entirely for 2 seconds.
        // During gxRestart, GxuLoadGlyph may be called while the font rendering
        // pipeline is in a transitional state — rasterized glyphs may contain
        // garbage or partial data. Caching these would corrupt all subsequent
        // text rendering. By bypassing the cache during the transition window,
        // we let WoW's original glyph loader handle the unstable period, and
        // only start caching once the device is fully stable.
        DWORD elapsed = GetTickCount() - deviceChangeTime;
        if (deviceChangeTime != 0 && elapsed < 2000) {
            // During grace period: pass through directly to original, no caching
            return orig_GxuLoadGlyph(fontObj, charCode, fontSize, a4, outStruct, a6, a7);
        }

        GlyphKey key = { fontObj, charCode, fontSize, a4, a6, a7 };
        
        // Fast thread-safe cache lookup
        {
            WinLockGuard lock(g_cacheMutex);
            auto it = g_glyphCache.find(key);
            if (it != g_glyphCache.end()) {
                g_hits++;
                // Copy the 40 bytes of the cached glyph descriptor structure
                memcpy(outStruct, it->second.structBytes, 40);
                
                // Allocate a fresh texture buffer copy using the engine's CRT allocation wrapper
                uint32_t size = it->second.textureSize;
                void* newBuf = fn_GxuAlloc(size, ".\\IGxuFontGlyph.cpp", 0x93, 0);
                if (newBuf) {
                    memcpy(newBuf, it->second.textureCopy, size);
                    *reinterpret_cast<void**>(outStruct) = newBuf; // set pointer at offset 0
                    return 1; // success
                }
            }
        }
    }

    // Cache miss: compile/rasterize glyph outline normally
    char result = orig_GxuLoadGlyph(fontObj, charCode, fontSize, a4, outStruct, a6, a7);
    if (result && fontObj && charCode && outStruct && !IsTeardownState()) {
        GlyphKey key = { fontObj, charCode, fontSize, a4, a6, a7 };
        
        void* textureData = *reinterpret_cast<void**>(outStruct);
        uint32_t textureSize = *reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(outStruct) + 4);
        
        if (textureData && textureSize > 0 && textureSize < 1048576) { // sanity bound: size < 1MB
            WinLockGuard lock(g_cacheMutex);
            g_misses++;
            
            // Allocate a local buffer copy of the texture data for our cache
            uint8_t* cacheBuf = reinterpret_cast<uint8_t*>(malloc(textureSize));
            if (cacheBuf) {
                memcpy(cacheBuf, textureData, textureSize);
                
                GlyphCacheEntry entry;
                memcpy(entry.structBytes, outStruct, 40);
                entry.textureSize = textureSize;
                entry.textureCopy = cacheBuf;
                
                // Insert into cache, evicting any previous entry under this key
                auto oldIt = g_glyphCache.find(key);
                if (oldIt != g_glyphCache.end()) {
                    if (oldIt->second.textureCopy) free(oldIt->second.textureCopy);
                }
                g_glyphCache[key] = entry;
            }
        }
    }
    return result;
}

// Whether the glyph loader is actually detoured by us. In one session it was
// not: something else - an overlay or a client extension - had already put a
// jmp rel32 at 0x006C8CC0, so WineSafe_CreateHook stood aside and this cache
// reported "0 hits, 0 misses (0.0%% hit rate)" for the whole session as though
// it had run and found nothing worth caching.
static bool g_hooked = false;

bool Init() {
    g_hits = 0;
    g_misses = 0;

    // push ebp / mov ebp,esp / mov eax,[ebp+8] / sub esp,14h / test eax,eax / push edi / jz
    static const unsigned char kGlyphLoaderOpening[14] = {
        0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x83, 0xEC, 0x14, 0x85, 0xC0, 0x57, 0x74, 0x0D
    };
    if (!WowOpt_ClientBytesAre(0x006C8CC0, kGlyphLoaderOpening, sizeof(kGlyphLoaderOpening))) {
        char hex[64];
        WowOpt_HexBytes(0x006C8CC0, hex, sizeof(hex));
        Log("[FontGlyphCache] NOT installed: the bytes at 0x006C8CC0 are not the glyph loader's opening "
            "(another detour or another client build): %s", hex);
        return false;
    }

    if (WineSafe_CreateHook((void*)0x006C8CC0, (void*)Hooked_GxuLoadGlyph, (void**)&orig_GxuLoadGlyph) == MH_OK) {
        if (MH_EnableHook((void*)0x006C8CC0) == MH_OK) {
            Log("[FontGlyphCache] Hooked GxuLoadGlyph at 0x006C8CC0 successfully");
        } else {
            Log("[FontGlyphCache] Failed to enable hook on GxuLoadGlyph");
            return false;
        }
    } else {
        Log("[FontGlyphCache] Failed to create hook on GxuLoadGlyph");
        return false;
    }

    g_hooked = true;
    Log("[FontGlyphCache] Active - Font Glyph Pre-Caching Atlas Initialized");
    return true;
}

// Printed from the periodic report, not only from Shutdown. The DLL exits
// through TerminateProcess to avoid deadlocking on background threads, so
// Shutdown does not run and these numbers reached no log at all - four tester
// sessions contain none of them.
void LogStats() {
    if (!g_hooked) {
        Log("[FontGlyphCache] not installed - the glyph loader at 0x006C8CC0 "
            "could not be detoured, and the reason is at the top of this log. "
            "Zero hits here would have meant nothing to cache; it means nothing "
            "ran.");
        return;
    }
    if (g_hits == 0 && g_misses == 0) {
        Log("[FontGlyphCache] installed and the glyph loader was never called. "
            "That is a measurement: no text was drawn through this path.");
        return;
    }
    Log("[FontGlyphCache] %lld hits, %lld misses (%.1f%% hit rate)",
        g_hits, g_misses,
        (g_hits + g_misses) ? (100.0 * g_hits / (g_hits + g_misses)) : 0.0);
}

void Shutdown() {
    LogStats();
    MH_DisableHook((void*)0x006C8CC0);
    ClearCache();
}

void ClearCache() {
    WinLockGuard lock(g_cacheMutex);
    for (auto& pair : g_glyphCache) {
        if (pair.second.textureCopy) {
            free(pair.second.textureCopy);
        }
    }
    g_glyphCache.clear();
    Log("[FontGlyphCache] Cache cleared (device reset or shutdown)");
}

} // namespace FontGlyphCache
