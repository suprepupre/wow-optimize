#pragma once

#ifndef NET_ADDON_COALESCER_H
#define NET_ADDON_COALESCER_H

#include <cstdint>

namespace NetAddonCoalescer {

bool Init();
void Shutdown();
void OnFrame();
void LogStats();

bool IsActive();
bool IsReplaying();

// Evaluates incoming event from LoadingState_OnSignalEvent.
// Returns true if event is CHAT_MSG_ADDON and was queued/deduplicated (caller swallows immediate dispatch).
bool TryQueueIncoming(int eventId, const char* format, void* vaStart);

} // namespace NetAddonCoalescer

#endif // NET_ADDON_COALESCER_H

