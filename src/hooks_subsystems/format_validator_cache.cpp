#include "format_validator_cache.h"
#include <windows.h>
#include <MinHook.h>
#include "version.h"   // the No Client Patches gate and the foreign-detour check live here

extern "C" void Log(const char* fmt, ...);

#define CACHE_SIZE 128
#define MAX_FORMAT_LEN 64

struct CacheEntry {
    void* obj_ptr;
    char format[MAX_FORMAT_LEN];
    bool valid;
    bool used;
};

static CacheEntry g_cache[CACHE_SIZE];
static CRITICAL_SECTION g_cache_lock;
static bool g_initialized = false;

typedef int (__cdecl* format_validator_t)(void* obj, int param, const char* format, int extra);
static format_validator_t orig_format_validator = nullptr;

static inline unsigned int hash_entry(void* obj, const char* format) {
    unsigned int h = (unsigned int)((uintptr_t)obj >> 2);
    if (format) {
        for (int i = 0; i < MAX_FORMAT_LEN && format[i]; i++) {
            h = ((h << 5) + h) + format[i];
        }
    }
    return h % CACHE_SIZE;
}

static int __cdecl hook_format_validator(void* obj, int param, const char* format, int extra) {
    if (!obj || !format) {
        return 0;
    }

    if (!g_initialized) {
        InitializeCriticalSection(&g_cache_lock);
        memset(g_cache, 0, sizeof(g_cache));
        g_initialized = true;
    }

    // Check cache
    unsigned int idx = hash_entry(obj, format);
    EnterCriticalSection(&g_cache_lock);

    if (g_cache[idx].used && g_cache[idx].obj_ptr == obj &&
        strncmp(g_cache[idx].format, format, MAX_FORMAT_LEN - 1) == 0) {
        int cached = g_cache[idx].valid;
        LeaveCriticalSection(&g_cache_lock);
        return cached;
    }

    LeaveCriticalSection(&g_cache_lock);

    // Cache miss - call original (not variadic, just fixed params)
    int result = orig_format_validator(obj, param, format, extra);

    // Store in cache
    EnterCriticalSection(&g_cache_lock);
    g_cache[idx].obj_ptr = obj;
    strncpy(g_cache[idx].format, format, MAX_FORMAT_LEN - 1);
    g_cache[idx].format[MAX_FORMAT_LEN - 1] = '\0';
    g_cache[idx].valid = (result != 0);
    g_cache[idx].used = true;
    LeaveCriticalSection(&g_cache_lock);
    
    return result;
}

bool InstallFormatValidatorCache() {
    void* target = (void*)0x0076F070;
    
    if (MH_CreateHook(target, (void*)hook_format_validator, (void**)&orig_format_validator) != MH_OK) {
        Log("[FormatValidator] MH_CreateHook failed");
        return false;
    }
    
    if (MH_EnableHook(target) != MH_OK) {
        Log("[FormatValidator] MH_EnableHook failed");
        return false;
    }
    
    Log("[FormatValidator] Installed validation cache (1208 callers, %d entries)", CACHE_SIZE);
    return true;
}

void UninstallFormatValidatorCache() {
    MH_DisableHook((void*)0x0076F070);
    if (g_initialized) {
        DeleteCriticalSection(&g_cache_lock);
        g_initialized = false;
    }
}
