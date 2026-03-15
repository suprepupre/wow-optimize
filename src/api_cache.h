#pragma once
#ifndef API_CACHE_H
#define API_CACHE_H

#include <windows.h>

namespace APICache {

bool Init();
void Shutdown();
void NewFrame();

struct Stats {
    long totalHits;
    long totalMisses;
    int  hookedFunctions;
    bool active;
};

Stats GetStats();

}

#endif
