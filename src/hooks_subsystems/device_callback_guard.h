#pragma once

// Guards the client's device callback list walk (sub_6A2AA0) against a node
// whose callback pointer is null, which otherwise executes address 0 and kills
// the process. See device_callback_guard.cpp for the disassembly this is built
// from and for what it deliberately does not do.

namespace DeviceCallbackGuard {

bool Init();
void LogStats();

} // namespace DeviceCallbackGuard
