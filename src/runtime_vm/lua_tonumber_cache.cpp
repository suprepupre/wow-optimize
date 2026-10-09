#include "lua_tonumber_cache.h"
#include <windows.h>
#include <MinHook.h>
#include "version.h"   // the No Client Patches gate and the foreign-detour check live here
#include "lua_index2adr.h"

extern "C" void Log(const char* fmt, ...);

typedef double(__cdecl* lua_tonumber_t)(void* L, int idx);
static lua_tonumber_t orig_lua_tonumber = nullptr;

// TValue structure (Lua 5.1) - 12 bytes total
struct TValue {
    union {
        double n;           // 8 bytes - number value
        void* p;            // pointer
        int b;              // boolean
    } value;
    int tt;                 // 4 bytes - type tag at offset 8
};

static double __cdecl hook_lua_tonumber(void* L, int idx) {
    // Get TValue* from stack (index2adr is __usercall — see lua_index2adr.h)
    TValue* tv = (TValue*)WowIndex2Adr(idx, (uintptr_t)L);

    // Fast path: if already a number, return directly
    if (tv && tv->tt == 3) {  // LUA_TNUMBER
        return tv->value.n;
    }

    // Slow path: call original for conversion
    return orig_lua_tonumber(L, idx);
}

bool InstallLuaToNumberCache() {
    void* target = (void*)0x0084E030;
    
    if (MH_CreateHook(target, (void*)hook_lua_tonumber, (void**)&orig_lua_tonumber) != MH_OK) {
        Log("[LuaToNumber] MH_CreateHook failed");
        return false;
    }
    
    if (MH_EnableHook(target) != MH_OK) {
        Log("[LuaToNumber] MH_EnableHook failed");
        return false;
    }
    
    Log("[LuaToNumber] Installed inline type check optimization (1165 callers)");
    return true;
}

void UninstallLuaToNumberCache() {
    MH_DisableHook((void*)0x0084E030);
}
