#pragma once

// ============================================================================
// Module: dbc_lookup_cache.h
// ============================================================================










bool InstallDbcLookupCache();
void UninstallDbcLookupCache();

// Hit rate and bypass count, from the periodic report. Reporting it only from
// Uninstall meant it was never seen: that path runs at teardown, and this DLL's
// process exits through TerminateProcess instead.
void DbcLookupCache_LogStats();
extern "C" void ClearDbcLookupCache();
