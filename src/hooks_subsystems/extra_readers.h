#pragma once

namespace ExtraReaders {
    // Called once per presented frame on the main thread. Does its work once, on the first frame
    // where the client's file reader exists, and costs one flag test after that.
    void OnFrame();
    void LogStats();
}
