// ============================================================================
// Module: lua_table_census.h
// Description: Measures how much of the GC's table walk is empty slots.
// Safety & Threading: Main thread, inside the client's collector.
// ============================================================================
#pragma once

namespace LuaTableCensus {

bool Init();
void LogStats();

}  // namespace LuaTableCensus
