// ============================================================================
// Description: SSE2 AABB outcode classification for the collision ray cast.
// ============================================================================

#pragma once

namespace CollisionRayOutcode {

bool Init();
void Shutdown();
void LogStats();
void SetBypass(bool bypass);
bool IsBypassed();

} // namespace CollisionRayOutcode
