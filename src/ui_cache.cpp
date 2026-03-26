#include "ui_cache.h"
#include <windows.h>

extern "C" void Log(const char* fmt, ...);

namespace UICache {

static bool g_active = false;

bool Init() {
    Log("[UICache] ====================================");
    Log("[UICache]  UI Widget Cache");
    Log("[UICache]  DISABLED in test build");
    Log("[UICache]  Reason: real-world addon regressions");
    Log("[UICache]  - WeakAuras spec-switch missing auras");
    Log("[UICache]  - Raid frames: dead names red, HP bars not empty");
    Log("[UICache]  C-level StatusBar caching is not release-safe");
    Log("[UICache] ====================================");
    g_active = false;
    return false;
}

void Shutdown() {
    g_active = false;
}

void ClearCache() {
    // no-op
}

Stats GetStats() {
    Stats s;
    s.skipped = 0;
    s.passed  = 0;
    s.active  = false;
    return s;
}

} // namespace UICache