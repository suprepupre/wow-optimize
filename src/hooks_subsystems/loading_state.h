// ============================================================================
// Description: Native loading-screen / combat state detection from the client's
//              own event stream, independent of the !LuaBoost addon.
// ============================================================================

#pragma once

namespace ClientWriteBatch { typedef char (__cdecl* WriteFn)(void*, const void*, void*, unsigned long*); }

namespace LoadingState {
// Claims the flight recorder columns for file reads and writes. Call once,
// after the recorder is up.
void ClaimRecorderColumns();
// The client's file-write wrapper once it is hooked, or null.
ClientWriteBatch::WriteFn GetClientWriter();
    // Installs the FrameScript_SignalEvent detour. Always installed - the loading
    // state it publishes gates safety bypasses across many other subsystems.
    bool Init();
    void Shutdown();

    // Whether the detour is on the client's function. Another module that needs
    // its events - the combat log filter rides the same detour - asks this
    // instead of assuming Init() succeeded: on a client whose own extension has
    // already patched FrameScript_SignalEvent it declines, and everything that
    // depended on it silently does nothing.
    bool IsInstalled();

    // True between PLAYER_LEAVING_WORLD and PLAYER_ENTERING_WORLD.
    bool IsLoading();

    // Accounting for where a loading screen's time goes.
    //
    // The project has spent years adding prefetch, memory-mapped archives and
    // async texture decode to make loading faster, and has never measured what a
    // load is actually made of. Prefetching only helps if loading is waiting on
    // the disk; if it is dominated by decompression or scene building, more
    // prefetch is free of both cost and benefit. This measures the split so the
    // next change to the loading path is aimed at something.
    //
    // Only called while IsLoading() is true, so gameplay pays nothing.
    void NoteRead(double ms, unsigned int bytes);

    // How many reads NoteRead has counted in the loading screen now up, from a
    // counter that restarts at zero with each one. The low 32 bits, read from any
    // thread without a lock: a caller takes differences of two readings, so a
    // torn or stale value costs one sample and nothing else.
    unsigned long ReadsThisLoad();

    // The write side of the same question. A tester's 139-second loading screen
    // spent 1% of itself in ReadFile, and the freeze watchdog caught its main
    // thread blocked 13 seconds inside the client's own write wrapper - the one
    // carrying the string "Win32 Write - %s". Reads were measured and writes were
    // not, so the largest share of that load had nowhere to be counted.
    void NoteWrite(double ms, unsigned int bytes, const char* name);

    // The third thing a loading screen is made of, and the one the split was
    // missing. A measured load was 1576 ms with 49 ms inside ReadFile and no
    // writes at all, so 97% of it had nowhere to be counted - while the same
    // session spent 2128 ms inside the Lua compiler without anyone knowing how
    // much of that fell inside a load.
    //
    // Called from the compile census, and only while IsLoading() is true.
    void NoteCompile(double ms, bool repeat);

    // Whether the ReadFile hook that feeds NoteRead is actually installed. It is
    // compiled out by CRASH_TEST_DISABLE_READFILE in the shipped build, and the
    // first real log carrying this report said "0 ms (0%) inside ReadFile" for
    // every load - which reads as a measurement of the loading path and is
    // nothing of the kind. Unobserved and zero have to look different.
    void SetReadHookInstalled(bool installed);

    // Session summary: how many loads, how long, and how much of it was I/O.
    void ReportLoadTimes();
}
