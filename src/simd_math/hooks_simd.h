#pragma once

// ============================================================================
// Module: hooks_simd.h
// Description: Installs and manages target intercepts for subsystem `hooks_simd.h`.
// Safety & Threading: Stack layouts and register conventions must match target function definitions exactly.
// ============================================================================










bool InstallSimdHooks(void);
void ShutdownSimdHooks(void);

// Call and cull counts for the SIMD hooks. Printed from the periodic report
// rather than from shutdown, which this process does not reach.
void SimdHooks_LogStats(void);

// SSE2 quaternion multiply: result = a * b (Hamilton product)
// All pointers are float[4] (x,y,z,w). Safe for aliasing.
void SSE2_QuatMultiply(const float* __restrict a, const float* __restrict b, float* __restrict result);

// SSE2 3-component dot product: returns a[0]*b[0] + a[1]*b[1] + a[2]*b[2]
float SSE2_Vec3Dot(const float* a, const float* b);