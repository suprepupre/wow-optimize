#pragma once

// Deliberately includes nothing. version.h defines the MinHook helpers only when
// MinHook.h has already been seen, and pulling it in early from a header that
// dllmain.cpp includes near the top left every later WO_EnableHook undeclared.

namespace BoneMatrixUpload {

bool Init();
void Shutdown();
void LogStats();

}  // namespace BoneMatrixUpload
