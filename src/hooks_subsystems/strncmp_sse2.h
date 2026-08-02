#pragma once

// ============================================================================
// Module: strncmp_sse2.h
//
// SSE2 replacement for the CRT strncmp linked into the client at 0x004180A6,
// measured at 1.55% of executing main-thread time. Sixteen bytes per compare,
// with page-boundary-safe loads.
// ============================================================================

#ifndef STRNCMP_SSE2_H
#define STRNCMP_SSE2_H

#include <cstddef>

namespace StrncmpSse2 {

// Exposed so the offline test can exercise exactly the shipped arithmetic.
int Compare(const char* s1, const char* s2, size_t n);

bool Init();
void LogStats();
void Shutdown();

} // namespace StrncmpSse2

#endif // STRNCMP_SSE2_H
