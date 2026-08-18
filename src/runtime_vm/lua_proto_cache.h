// ============================================================================
// Module: lua_proto_cache.h
// Description: Skips luaY_parser for source the client has already compiled.
// Safety & Threading: Main thread only, alongside the Lua state.
// ============================================================================

#pragma once

namespace LuaProtoCache {

bool Init();
void LogStats();

} // namespace LuaProtoCache
