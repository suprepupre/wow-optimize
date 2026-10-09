#pragma once

namespace FastExit {
    void Init();
    // Called from the Sleep hook for the Sleep(100) in the sound shutdown loop. True when it took the wait
    // over (skipped it or ended it early) and the caller must not sleep again.
    bool SoundStopSleep(unsigned long ms);
    void Shutdown();
    void LogStats();
}
