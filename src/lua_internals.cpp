#include "lua_internals.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

namespace LuaInternals {

bool Init() {
    Log("[LuaVM] Init Lua VM internals (build 12340)");
    Log("[LuaVM]   luaV_concat     DISABLED (0%% gain, pure overhead - removed)");
    Log("[LuaVM] ====================================");
    Log("[LuaVM]  Hooks: 0 active");
    Log("[LuaVM]  [ OK ] CLEAN BASELINE");
    Log("[LuaVM] ====================================");
    return false;
}

void Shutdown() {}
void OnGCStep() {}
void InvalidateCache() {}

Stats GetStats() {
    Stats s;
    s.concatFastHits  = 0;
    s.concatFallbacks = 0;
    s.active          = false;
    return s;
}

} // namespace LuaInternals