// ============================================================================
// Module: lua_proto_cache.h
// Description: Skips luaY_parser for source the client has already compiled.
// Safety & Threading: Main thread only, alongside the Lua state.
// ============================================================================

#pragma once

namespace LuaProtoCache {

bool Init();
void LogStats();

// Called when another module observes the client swapping its lua_State.
//
// This cache used to notice a swap by itself, by comparing l_G on the next
// parse. That is a cache validated by an address the engine frees and hands
// back: this client runs its own Lua memory pool, so a new global state is
// routinely allocated where the old one was, the comparison says nothing
// changed, and every kept Proto is then a pointer into freed memory. A tester's
// log on 2026-08-22 has six "lua_State changed (UI reload)" lines from LuaOpt
// against two flushes here, and a crash in the client's error formatter reading
// Proto->lineinfo at address 4.
void OnLuaStateSwapped();

} // namespace LuaProtoCache
