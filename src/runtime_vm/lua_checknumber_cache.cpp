#include "lua_checknumber_cache.h"
#include <windows.h>
#include <MinHook.h>
#include "version.h"   // the No Client Patches gate and the foreign-detour check live here
#include "lua_index2adr.h"

extern "C" void Log(const char* fmt, ...);

typedef double(__cdecl* lua_checknumber_t)(void* L, int idx);
static lua_checknumber_t orig_lua_checknumber = nullptr;

// TValue structure (Lua 5.1) - 12 bytes total
struct TValue {
    union {
        double n;           // 8 bytes - number value
        void* p;            // pointer
        int b;              // boolean
    } value;
    int tt;                 // 4 bytes - type tag at offset 8
};

static double __cdecl hook_lua_checknumber(void* L, int idx) {
    // Get TValue* from stack (index2adr is __usercall — see lua_index2adr.h)
    TValue* tv = (TValue*)WowIndex2Adr(idx, (uintptr_t)L);

    // Fast path: if already a number, return directly
    if (tv && tv->tt == 3) {  // LUA_TNUMBER
        return tv->value.n;
    }

    // Slow path: call original for conversion
    return orig_lua_checknumber(L, idx);
}

bool InstallLuaCheckNumberCache() {
    void* target = (void*)0x0084DF20;
    
    if (MH_CreateHook(target, (void*)hook_lua_checknumber, (void**)&orig_lua_checknumber) != MH_OK) {
        Log("[LuaCheckNumber] MH_CreateHook failed");
        return false;
    }
    
    if (MH_EnableHook(target) != MH_OK) {
        Log("[LuaCheckNumber] MH_EnableHook failed");
        return false;
    }
    
    Log("[LuaCheckNumber] Installed inline type check optimization (1194 callers)");
    return true;
}

void UninstallLuaCheckNumberCache() {
    MH_DisableHook((void*)0x0084DF20);
}
