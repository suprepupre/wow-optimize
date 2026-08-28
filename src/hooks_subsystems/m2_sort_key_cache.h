// ============================================================================
// Module: m2_sort_key_cache.h
// Description: Caches the sort key a render-batch comparator re-derives.
// Safety & Threading: Main thread, inside the model render sort.
// ============================================================================
#pragma once

namespace M2SortKey {

bool Init();
void NewFrame();
void LogStats();
void Shutdown();

}  // namespace M2SortKey
