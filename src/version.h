#pragma once

#define WOW_OPTIMIZE_VERSION_MAJOR  3
#define WOW_OPTIMIZE_VERSION_MINOR  2
#define WOW_OPTIMIZE_VERSION_PATCH  0
#define WOW_OPTIMIZE_VERSION_BUILD  0

#define WOW_OPTIMIZE_VERSION_STR    "3.2.0"
#define WOW_OPTIMIZE_AUTHOR         "SUPREMATIST"

// Crash isolation toggle for Phase 2 Lua fast paths
// Set to 1 to disable Phase 2 hooks for testing
#ifndef CRASH_TEST_DISABLE_PHASE2
#define CRASH_TEST_DISABLE_PHASE2   0
#endif