#pragma once

// ============================================================================
// Module: ui_font_render_fast.h
//
// Fast UI Font string initialization and capacity-pooled quad batching
// (CGxString::Initialize, sub_6C74D0 @ 0x006C74D0).
// ============================================================================

namespace UIFontRenderFast {
bool Init();
void Shutdown();
void LogStats();
}

