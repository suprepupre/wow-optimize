#pragma once

// ============================================================================
// Module: shadow_buffer_alternate.h
//
// Experiment for the shadow flicker below extShadowQuality 5. Makes the client's
// shadow pass alternate its buffer at every quality instead of only at 5, by
// nopping the two-byte branch that decides it. Off by default; see the note in
// the .cpp for what is proven and what is not.
// ============================================================================

#ifndef SHADOW_BUFFER_ALTERNATE_H
#define SHADOW_BUFFER_ALTERNATE_H

namespace ShadowBufferAlternate {

bool Init();
void Shutdown();

} // namespace ShadowBufferAlternate

#endif // SHADOW_BUFFER_ALTERNATE_H
