#pragma once

// ============================================================================
// Module: lua_this_cache.h
// Description: Accelerates Lua runtime calls in `lua_this_cache.h`. Caches structures to bypass parser overhead.
// Safety & Threading: Thread-safe under Lua VM execution constraints.
// ============================================================================










#include <cstdint>

bool InstallLuaThisCache();
void UninstallLuaThisCache();
void GetLuaThisCacheStats(uint64_t* hits, uint64_t* total);
void LuaThisCache_LogStats();
