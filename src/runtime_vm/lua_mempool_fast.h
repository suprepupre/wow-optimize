#pragma once
#ifndef WOW_OPT_LUA_MEMPOOL_FAST_H
#define WOW_OPT_LUA_MEMPOOL_FAST_H

// The Lua memory pool's block allocator, sub_855820. Starts its free-chunk
// search where the previous one succeeded instead of at chunk zero, and counts
// how far the search actually goes so that the assumption behind it stays
// checkable.
namespace LuaMemPoolFast {

bool Init();
void LogStats();

} // namespace LuaMemPoolFast

#endif
