// ============================================================================
// Module: aabb_overlap_sse2.h
// Description: SSE2 replacement for the client's box-overlap predicate.
// Safety & Threading: Main thread, same as the function it replaces.
// ============================================================================
#pragma once

namespace AabbOverlap {

bool Init();
void LogStats();
void Shutdown();

}  // namespace AabbOverlap
