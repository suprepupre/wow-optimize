// ================================================================
// Lua VM Internals — DISABLED (luaV_concat hook removed)
//
// WHAT: Was intended to hook Lua VM internal functions (luaV_concat
//       for string/table concatenation optimization).
// WHY:  luaV_concat hook was tested and found to give 0% useful
//       hit rate — pure overhead with no measurable benefit.
// STATUS: DISABLED — returns false, no hooks installed
// NOTE:   luaS_newlstr/StrCache hook was also here but removed
//         earlier due to stale TString* crashes (0x0085CB43)
// ================================================================

#include "lua_internals.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
// LuaInternals namespace — stub implementation (disabled).
// ================================================================
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