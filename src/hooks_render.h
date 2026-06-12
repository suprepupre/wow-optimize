#pragma once

bool InstallRenderHooks(void);
void ShutdownRenderHooks(void);
void OnFrameRenderHooks(DWORD mainThreadId);
