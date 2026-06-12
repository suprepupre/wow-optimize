#pragma once

bool InstallAsyncHooks(void);
void ShutdownAsyncHooks(void);
void OnFrameAsyncHooks(DWORD mainThreadId);
