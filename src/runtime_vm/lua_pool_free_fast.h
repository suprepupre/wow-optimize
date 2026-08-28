// ============================================================================
// Module: lua_pool_free_fast.h
// Description: Removes the linear chunk scan from every Lua pool free.
// Safety & Threading: Runs wherever the client frees Lua memory.
// ============================================================================
#pragma once

namespace LuaPoolFreeFast {

bool Init();
void LogStats();
void Shutdown();

}  // namespace LuaPoolFreeFast
