#pragma once

// ============================================================================
// Module: lua_compile_census.h
//
// Counts what the client compiles at runtime, by chunk name, and reports it
// ranked. About 5% of executing main-thread time in a real session is inside
// the Lua code generator, and nothing has ever said what is feeding it.
// ============================================================================

#ifndef LUA_COMPILE_CENSUS_H
#define LUA_COMPILE_CENSUS_H

namespace LuaCompileCensus {

bool Init();

// From the periodic report. Silent while the totals look like a client that
// loaded its interface once and stopped.
void LogStats();

void Shutdown();

} // namespace LuaCompileCensus

#endif // LUA_COMPILE_CENSUS_H
