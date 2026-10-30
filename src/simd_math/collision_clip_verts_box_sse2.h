#pragma once

// ============================================================================
// Module: collision_clip_verts_box_sse2.h
//
// Fast SSE2 outcode derivation and triangle culling for mesh collision queries
// in BspQuery_Segment::GetFaceIndicesUsingCache (sub_7C6D50 @ 0x007C6D50).
// ============================================================================

namespace CollisionClipVertsBox {
bool Init();
void Shutdown();
void LogStats();
void SetBypass(bool bypass);
bool IsBypassed();
void Retire();
}
