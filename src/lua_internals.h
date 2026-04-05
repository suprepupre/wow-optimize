#pragma once
#ifndef LUA_INTERNALS_H
#define LUA_INTERNALS_H

#include <windows.h>

namespace LuaInternals {

bool Init();
void Shutdown();
void OnGCStep();
void InvalidateCache();

struct Stats {
    long strCacheHits;
    long strCacheMisses;
    long concatFastHits;
    long concatFallbacks;
    bool active;
};

Stats GetStats();

} // namespace LuaInternals

#endif