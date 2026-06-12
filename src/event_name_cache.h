#pragma once

// Event Name Lookup Cache
// Replaces linear string search in FrameScript event registration/firing
// with O(1) hash table lookup for common event names.

bool InstallEventNameCache();
void UninstallEventNameCache();