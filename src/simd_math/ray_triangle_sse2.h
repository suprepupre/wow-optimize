// ============================================================================
// Description: SSE2 double transcription of the client's ray-triangle test.
// ============================================================================

#pragma once

namespace RayTriangle {

bool Init();
void Shutdown();
void LogStats();
void SetBypass(bool bypass);
bool IsBypassed();
void RetireAll();

} // namespace RayTriangle
