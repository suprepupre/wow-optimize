#pragma once

// ============================================================================
// Module: shadow_state_probe.h
//
// Read-only watch on the client's own shadow state, for the flicker two testers
// see below extShadowQuality 5. Not our bug - one of them reproduced it with
// every feature off and no DXVK - but nothing has ever looked at what the
// engine is doing when it happens.
// ============================================================================

#ifndef SHADOW_STATE_PROBE_H
#define SHADOW_STATE_PROBE_H

namespace ShadowStateProbe {

bool Init();

// From the main-thread pump. Six reads; self-throttles its reporting.
void OnFrame();

void Shutdown();

} // namespace ShadowStateProbe

#endif // SHADOW_STATE_PROBE_H
