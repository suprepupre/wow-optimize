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

// From the main-thread pump. Only emits the periodic report - the measuring is
// done by the hook on the shadow pass itself, because the sampling this used to
// do ran twice per frame and answered the question wrongly.
void OnFrame();

void Shutdown();

} // namespace ShadowStateProbe

#endif // SHADOW_STATE_PROBE_H
