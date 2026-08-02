#pragma once

// ============================================================================
// Module: layout_relink_fast.h
//
// Skips the UI layout dependency walk in sub_489710 for frames that nothing
// anchors to, using the reverse index the client already maintains at
// frame+0x38. The largest single entry in a real gameplay profile.
// ============================================================================

#ifndef LAYOUT_RELINK_FAST_H
#define LAYOUT_RELINK_FAST_H

namespace LayoutRelinkFast {

bool Init();
void LogStats();
void Shutdown();

} // namespace LayoutRelinkFast

#endif // LAYOUT_RELINK_FAST_H
