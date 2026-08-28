// ============================================================================
// Module: lua_pool_fast.h
// Description: Removes the linear chunk scan from every Lua pool free.
// Safety & Threading: Runs wherever the client frees Lua memory.
// ============================================================================
#pragma once

namespace LuaPoolFast {

bool Init();
void LogStats();
void Shutdown();

}  // namespace LuaPoolFast
