// ============================================================================
// Module: segment_aabb_sse2.h
// Description: Replaces the segment/box test's x87 status-word round-trips.
// Safety & Threading: Main thread; the function is pure.
// ============================================================================
#pragma once

namespace SegmentAabb {

bool Init();
void LogStats();
void Shutdown();

}  // namespace SegmentAabb
