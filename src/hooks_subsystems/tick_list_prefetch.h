// ============================================================================
// Module: tick_list_prefetch.h
// Description: Prefetches the next node of the per-frame object tick walk.
// Safety & Threading: Main thread, inside the frame.
// ============================================================================
#pragma once

namespace TickListPrefetch {

bool Init();
void LogStats();

}  // namespace TickListPrefetch
