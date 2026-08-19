// ============================================================================
// Module: anim_lod.h
// Description: Spreads M2 model animation across frames when the scene is crowded.
// Safety & Threading: Main thread, alongside the render loop.
// ============================================================================

#pragma once

namespace AnimLod {

bool Init();
void OnFrame();
void LogStats();

} // namespace AnimLod
