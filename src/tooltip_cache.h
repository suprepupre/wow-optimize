#pragma once

#include <cstdint>

namespace TooltipCache {

struct Stats {
    int64_t hits;
    int64_t misses;
    int64_t evictions;
    double hitRate;
};

bool Install();
void Shutdown();
void Clear();
Stats GetStats();

// Cache API for external integration
const char* Get(uint32_t key, int* outLen);
void Put(uint32_t key, const char* text, int len);
uint32_t Hash(uint32_t itemID, uint32_t flags, uint32_t extra);

} // namespace TooltipCache