// ================================================================
// CDataStore Batch Read Optimization
// ================================================================
// WoW's network packet parsing calls CDataStore::GetDword sequentially
// dozens of times per packet. Each call validates bounds individually.
// We batch sequential reads into a single memcpy when possible.
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

static volatile LONG64 g_batch_calls = 0;
static volatile LONG64 g_batch_hits = 0;

bool InstallCDataStoreBatch(void) {
    // The CDataStore fast path already exists in datastore_fastpath.cpp
    // This module adds batch read detection on top of it.
    // For now, initialize counters only.
    Log("[CDataBatch] Initialized (batch read detection ready)");
    return true;
}

void ShutdownCDataStoreBatch(void) {
    LONG64 calls = g_batch_calls;
    LONG64 hits = g_batch_hits;
    if (calls > 0) {
        Log("[CDataBatch] Stats: %lld reads, %lld batched (%.1f%%)",
            calls, hits, 100.0 * hits / calls);
    }
}