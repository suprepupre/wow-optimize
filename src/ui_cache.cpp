// ================================================================
// UI Widget Cache — DISABLED
//
// WHAT: Was intended to cache UI widget lookups (frame references,
//       region objects) to avoid repeated UI hierarchy traversals.
// WHY:  Disabled due to addon regressions — caused incorrect UI
//       behavior in some addons that rely on fresh widget references.
// STATUS: DISABLED — returns false, no hooks installed
// NOTE:   Do NOT re-enable without thorough addon compatibility testing
// ================================================================

#include "ui_cache.h"
#include <windows.h>

extern "C" void Log(const char* fmt, ...);

// ================================================================
// UICache namespace — stub implementation (disabled).
// ================================================================
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