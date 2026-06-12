#pragma once
// lua_gettable_safety.h - Crash fix for sub_85BC10 TValue corruption

bool InstallLuaGetTableSafety();
void UninstallLuaGetTableSafety();
LONG64 GetTableSafety_GetBlockedCount();
LONG64 GetTableSafety_GetTotalCount();