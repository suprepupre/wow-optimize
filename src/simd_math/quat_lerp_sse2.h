#pragma once
#ifndef WOW_OPT_QUAT_LERP_SSE2_H
#define WOW_OPT_QUAT_LERP_SSE2_H

// sub_982630: interpolate two quaternions and renormalise. Called for every
// animated bone of every model, every frame, from the M2 quaternion track. The
// client does it one component at a time on the x87 stack; this does all four
// at once.
namespace QuatLerpSse2 {

bool Init();
void LogStats();

} // namespace QuatLerpSse2

#endif
