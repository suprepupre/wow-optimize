#pragma once
#ifndef LUA_FASTPATH_H
#define LUA_FASTPATH_H

#include <windows.h>

namespace LuaFastPath {

// Install format() hook via MinHook
bool Init();

// Disable hooks
void Shutdown();

struct Stats {
    long formatFastHits;
    long formatFallbacks;
    bool active;
};

Stats GetStats();

} // namespace LuaFastPath

#endif