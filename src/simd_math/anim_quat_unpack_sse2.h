// ============================================================================
// Module: anim_quat_unpack_sse2.h
// Description: SSE2 rewrite of the M2 quaternion track evaluator.
// Safety & Threading: Main thread, inside the per-model animation pass.
// ============================================================================
#pragma once

namespace AnimQuatUnpack {

bool Init();
void LogStats();
void Shutdown();

}  // namespace AnimQuatUnpack
