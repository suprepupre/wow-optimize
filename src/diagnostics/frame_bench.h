#pragma once

// ============================================================================
// Module: frame_bench.h
// Description: Frame-time distribution benchmark - the instrument that lets one
//              build be compared against another.
//
// This project has around fifty optimization toggles and no way to tell whether
// any of them helps. Every feature has been justified by theory; the README's
// "Performance Metrics" section contains no numbers. Two of the largest findings
// this month were cases where our own code made the game slower, and both were
// found by measurement rather than review.
//
// So: record every presented frame, and report the distribution in a form two
// runs can be diffed on. Percentiles, not an average - an average hides exactly
// the stutters players complain about. Loading screens are excluded, because a
// single zone load would dominate the tail and make runs incomparable.
//
// The config fingerprint in the report is what makes an A/B honest: it is a hash
// of the whole settings block, so a log can be checked to have actually run the
// configuration it claims to.
// ============================================================================

namespace FrameBench {

// Where frame boundaries are being taken from. Only ever one source per session -
// mixing a true present hook with a coarser tick would make runs incomparable, so
// the source is named in the report.
enum class Source {
    None,
    D3D9Present,     // IDirect3DDevice9::Present - the boundary for D3D9 clients
    SwapHook,        // sub_69E220 - the client's OpenGL present path
};

void Init();

// Called once per presented frame. Cost is one QueryPerformanceCounter and one
// histogram increment.
void OnPresent(Source src);

// Writes the distribution to the log. Safe to call repeatedly; each call reports
// the whole session so far.
void Report(const char* reason);

// 95th percentile frame time over the last few seconds, or 0 before enough frames
// have been seen.
//
// Anything that reacts to how the game is running needs this rather than an
// instantaneous frame rate. The scalers in this project each smooth 1000/elapsed
// with their own EMA and switch on thresholds crossed by a single frame, which is
// how one of them ended up changing shadow quality several times a minute while a
// player walked around. What players notice is the tail, and the tail is what this
// returns.
double RecentP95Ms();

// Smoothed frame time in milliseconds, or 0.0 before any frame has been measured.
// Constant time, unlike RecentP95Ms, so it is safe to consult on a per-frame or
// per-Sleep path.
double SmoothedFrameMs();

// The running median frame time, refreshed from the histogram every few hundred
// frames. Read by the sampling profiler to notice a frame-rate cap: a median
// sitting on a display interval means its verdict is describing a wait.
double MedianMs();

} // namespace FrameBench
