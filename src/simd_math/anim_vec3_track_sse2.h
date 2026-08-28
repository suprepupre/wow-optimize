// ============================================================================
// Module: anim_vec3_track_sse2.h
// Description: SSE2 rewrite of the M2 vector track evaluator.
// Safety & Threading: Main thread, inside the per-model animation pass.
// ============================================================================
#pragma once

namespace AnimVec3Track {

bool Init();
void LogStats();
void Shutdown();

}  // namespace AnimVec3Track
