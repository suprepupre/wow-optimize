#pragma once
#ifndef UI_CACHE_H
#define UI_CACHE_H

#include <windows.h>

namespace UICache {

bool Init();
void Shutdown();

struct Stats {
    long skipped;
    long passed;
    bool active;
};

Stats GetStats();

} // namespace UICache

#endif