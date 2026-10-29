#pragma once

// ============================================================================
// Module: m2_skinning_40b_fast.h
//
// Fast M2 multi-bone 40-byte vertex buffer transformation and skinning:
//   sub_829F40: CM2Model::TransformVerticesMultiBone_40B
//
// Vectorizes and register-allocates M2 vertex transformation for 40-byte
// vertex formats (GxVBF_PNT2: pos 12B, norm 12B, uv1 8B, uv2 8B) used during
// CPU vertex buffer filling in sub_82D910. Eliminates x87 control stalls,
// inlines matrix-vector affine math, and utilizes 128-bit vector copies for
// dual texture coordinates.
// ============================================================================

namespace M2Skinning40BFast {

void Init();
void Shutdown();
void LogStats();

}  // namespace M2Skinning40BFast

