#pragma once

// ============================================================================
// Module: spline_catmull_rom_fast.h
//
// Fast Catmull-Rom spline orientation frame builder (IFrameArclength, sub_4C43B0)
// and segment length evaluator (SegLength, sub_4C40B0).
// ============================================================================

namespace SplineCatmullRomFast {
bool Init();
void Shutdown();
void LogStats();
}

