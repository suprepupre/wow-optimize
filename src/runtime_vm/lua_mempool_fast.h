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

// Told by the free hook in lua_pool_fast that a block has gone back into chunk
// `index` of pool `pool`, so the hint can drop to it.
//
// The measurement that made this worth wiring up: with the hint alone, 74.3% of
// allocations find a block in the first chunk they look at, but 18.9% still walk
// 33 or more, which is what drags the average to 43.37. A block freed into a
// chunk *below* the hint is invisible until the scan runs off the end and falls
// back, and that is exactly the tail.
//
// Lowering a hint is safe by construction. It can only make a search start
// earlier, and a search that finds nothing still hands the call to the client's
// own allocator, so no free block can be missed and no chunk created that was
// not needed. That property is what the standalone harness proved, and it does
// not depend on where the hint points.
//
// Does nothing when this feature is off, so the free side does not need to know.
void NoteFreeIntoChunk(unsigned pool, unsigned index);

} // namespace LuaMemPoolFast

#endif
