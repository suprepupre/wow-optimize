#pragma once

// Prefetch ahead in the particle emitter loops. See particle_loop_prefetch.cpp.
namespace ParticleLoopPrefetch {
bool Init();
void Shutdown();
void LogStats();
}
