#include "ui_cache.h"
#include <windows.h>

extern "C" void Log(const char* fmt, ...);

namespace UICache {

static bool g_active = false;

bool Init() {
    Log("[UICache] ====================================");
    Log("[UICache]  UI Widget Cache");
    Log("[UICache]  DISABLED in test build");
    Log("[UICache]  Disabled due to addon regressions");
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