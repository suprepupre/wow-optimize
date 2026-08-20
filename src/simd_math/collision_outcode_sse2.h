// ============================================================================
// Module: collision_outcode_sse2.h
// Description: SSE2 AABB outcode classification for the collision reject pass.
// Safety & Threading: Main thread, same as the function it replaces.
// ============================================================================

#pragma once

namespace CollisionOutcode {

bool Init();
void LogStats();

} // namespace CollisionOutcode
