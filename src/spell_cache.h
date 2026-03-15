#pragma once
#ifndef SPELL_CACHE_H
#define SPELL_CACHE_H

#include <windows.h>

namespace SpellCache {

bool Init();
void Shutdown();
void NewFrame();

struct Stats {
    long hits;
    long misses;
    bool active;
};

Stats GetStats();

}

#endif
