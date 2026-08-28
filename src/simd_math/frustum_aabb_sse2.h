// ============================================================================
// Module: frustum_aabb_sse2.h
// Description: SSE2 rewrite of CFrustum::IsAABBVisible.
// Safety & Threading: Main thread, inside world visibility traversal.
// ============================================================================
#pragma once

namespace FrustumAabb {

bool Init();
void LogStats();
void Shutdown();

}  // namespace FrustumAabb
