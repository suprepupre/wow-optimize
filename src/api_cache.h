#pragma once
#ifndef API_CACHE_H
#define API_CACHE_H

#include <windows.h>

namespace ApiCache {

bool Init();
void Shutdown();
void OnNewFrame();

struct Stats {
    long hits;
    long misses;
    bool active;
};

Stats GetStats();

} // namespace ApiCache

#endif