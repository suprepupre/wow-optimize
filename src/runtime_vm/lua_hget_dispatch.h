// ============================================================================
// Module: lua_hget_dispatch.h
// Description: Removes luaH_get's x87 round-trip on integer table keys.
// Safety & Threading: Lua thread; the function is a read-only lookup.
// ============================================================================
#pragma once

namespace LuaHGetDispatch {

bool Init();
void LogStats();
void Shutdown();

}  // namespace LuaHGetDispatch
