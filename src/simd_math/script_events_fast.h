#pragma once

// ============================================================================
// Module: script_events_fast.h
//
// Fast O(1) script event and combat text deduplication & signal dispatch
// (Script_SendUniqueSignal, sub_6143F0 @ 0x006143F0 and sub_614760 @ 0x00614760).
// ============================================================================

namespace ScriptEventsFast {
bool Init();
void Shutdown();
void LogStats();
}

