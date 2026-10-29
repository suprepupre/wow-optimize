#pragma once

// ============================================================================
// Module: terrain_alpha_unpack_fast.h
//
// Fast SSE2 terrain alpha RLE decompression (DecodeAlphaRLE, sub_7B7420) and
// shadow/alpha channel packing (UnpackAlphaShadowBitsFixed8888Mip0, sub_7B7C60).
// ============================================================================

namespace TerrainAlphaUnpackFast {
bool Init();
void Shutdown();
void LogStats();
}
