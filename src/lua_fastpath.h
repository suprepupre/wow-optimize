#pragma once
#ifndef LUA_FASTPATH_H
#define LUA_FASTPATH_H

#include <windows.h>

// Forward declaration
typedef struct lua_State lua_State;

namespace LuaFastPath {

// Phase 1: Hook string.format (hardcoded address, called during DLL init)
bool Init();

// Phase 2: Discover and hook more functions at runtime (called after Lua state ready)
bool InitPhase2(lua_State* L);
// Allow Phase 2 discovery to re-run after lua_State / VM change
void ResetPhase2Discovery();

// Disable all hooks
void Shutdown();

struct Stats {
    long formatFastHits;
    long formatFallbacks;
    long findPlainHits;
    long findFallbacks;
    long matchHits;
    long matchFallbacks;
    long typeHits;
    long typeFallbacks;
    long mathHits;
    long mathFallbacks;
    long strlenHits;
    long strbyteHits;
    long tostringHits;
    long tostringFallbacks;
    long tonumberHits;
    long nextHits;
    long nextFallbacks;
    long rawgetHits;
    long rawgetFallbacks;
    long rawsetHits;
    long rawsetFallbacks;
    long tableInsertHits;
    long tableInsertFallbacks;
    long tableRemoveHits;
    long tableRemoveFallbacks;
    long strsubHits;
    long strlowerHits;
    long strupperHits;
    int  phase2Hooks;
    bool active;
    bool phase2Active;
};

Stats GetStats();

} // namespace LuaFastPath

#endif