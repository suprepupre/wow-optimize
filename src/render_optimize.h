#pragma once
#ifndef RENDER_OPTIMIZE_H
#define RENDER_OPTIMIZE_H

#include <windows.h>
#include <cstdint>

namespace RenderOpt {

bool Init();
void Shutdown();
void OnFrame();

struct Stats {
    long hidden;
    long shown;
    long spellsBlocked;
    bool active;
};

Stats GetStats();

}

#endif
