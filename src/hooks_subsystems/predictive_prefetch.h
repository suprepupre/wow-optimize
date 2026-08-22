#pragma once

#ifndef PREDICTIVE_PREFETCH_H
#define PREDICTIVE_PREFETCH_H

namespace PredictivePrefetch {

// Initialize the predictive prefetcher
bool Init();

// Tick called per frame to track velocity and prefetch files
void OnFrame();

// What it saw and what it did. A session that queued nothing must be able to
// say whether it never had a world position or had one and found nothing.
void LogStats();

// Shut down resources
void Shutdown();

} // namespace PredictivePrefetch

#endif // PREDICTIVE_PREFETCH_H
