#include "lua_pushstring_cache.h"
#include <windows.h>
#include <MinHook.h>
#include "version.h"   // the No Client Patches gate and the foreign-detour check live here
#include <string.h>

extern "C" void Log(const char* fmt, ...);

#define MAX_CACHE_STRINGS 64
#define MAX_STRING_LEN 32

struct StringEntry {
    char str[MAX_STRING_LEN + 1];
    int len;
    bool used;
};

static __declspec(thread) StringEntry g_cache[MAX_CACHE_STRINGS];
static __declspec(thread) int g_cache_count = 0;

typedef void(__cdecl* lua_pushstring_t)(void* L, const char* str, int len);
static lua_pushstring_t orig_lua_pushstring = nullptr;

static inline unsigned int hash_string(const char* str, int len) {
    unsigned int hash = 5381;
    for (int i = 0; i < len && i < MAX_STRING_LEN; i++) {
        hash = ((hash << 5) + hash) + str[i];
    }
    return hash % MAX_CACHE_STRINGS;
}

static void __cdecl hook_lua_pushstring(void* L, const char* str, int len) {
    // Only cache short strings
    if (len > 0 && len <= MAX_STRING_LEN && str) {
        unsigned int idx = hash_string(str, len);
        
        // Check if already cached
        if (g_cache[idx].used && g_cache[idx].len == len && 
            memcmp(g_cache[idx].str, str, len) == 0) {
            // Already in cache, just call original with cached string
            orig_lua_pushstring(L, g_cache[idx].str, len);
            return;
        }
        
        // Store in cache
        memcpy(g_cache[idx].str, str, len);
        g_cache[idx].str[len] = '\0';
        g_cache[idx].len = len;
        g_cache[idx].used = true;
        
        if (g_cache_count < MAX_CACHE_STRINGS) {
            g_cache_count++;
        }
    }
    
    // Call original
    orig_lua_pushstring(L, str, len);
}

bool InstallLuaPushStringCache() {
    void* target = (void*)0x0084F280;
    
    if (MH_CreateHook(target, (void*)hook_lua_pushstring, (void**)&orig_lua_pushstring) != MH_OK) {
        Log("[LuaPushString] MH_CreateHook failed");
        return false;
    }
    
    if (MH_EnableHook(target) != MH_OK) {
        Log("[LuaPushString] MH_EnableHook failed");
        return false;
    }
    
    // Initialize cache
    memset(g_cache, 0, sizeof(g_cache));
    g_cache_count = 0;
    
    Log("[LuaPushString] Installed string literal cache (1542 callers, max %d strings)", MAX_CACHE_STRINGS);
    return true;
}

void UninstallLuaPushStringCache() {
    MH_DisableHook((void*)0x0084F280);
}
