// ============================================================================
// Description: High-performance Micro-JIT pattern matcher for Lua strings.
// Vectorizes and compiles common addon regex patterns into direct native paths.
// ============================================================================

#pragma once

#include <windows.h>
#include <cstdint>
#include <cstddef>

struct lua_State;

namespace LuaPatternJit {

typedef int (__cdecl *lua_CFunction_t)(lua_State* L);

bool Init();
void Shutdown();
void LogStats();

void SetOrigFuncs(lua_CFunction_t origMatch, lua_CFunction_t origFind);

// JIT-accelerated string.match
// Returns:
//   >= 1: Number of values pushed to Lua stack on match or nil
//   -1:   Unsupported pattern shape -> fall back to orig_str_match
int Match(lua_State* L, const char* s, size_t sLen, const char* p, size_t pLen, int init);

// JIT-accelerated string.find
// Returns:
//   >= 1: Number of values pushed (start, end, captures, or nil)
//   -1:   Unsupported pattern shape -> fall back to orig_str_find
int Find(lua_State* L, const char* s, size_t sLen, const char* p, size_t pLen, int init, bool plain);

} // namespace LuaPatternJit

