// ================================================================
// luaV_settable Inline Cache - sub_857CA0 (5,151 bytes)
// ================================================================
// Complements the existing luaV_gettable cache. Table writes are the
// second most frequent Lua VM operation after reads. This cache stores
// the last successful (table, key_string) -> Node* mapping so that
// repeated writes to the same table field skip the hash lookup.
//
// WoW address: 0x00857CA0 (luaV_settable)
// Called from: luaV_execute (0x00859160) for OP_SETTABLE, OP_SETGLOBAL
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

// ================================================================
// Cache Configuration
// ================================================================
static constexpr int SETTABLE_CACHE_SIZE = 4096;
static constexpr int SETTABLE_CACHE_MASK = SETTABLE_CACHE_SIZE - 1;

struct SetTableCacheEntry {
    uintptr_t table;       // Table* pointer
    uintptr_t tstring;     // TString* key
    uintptr_t tableNode;   // *(table+20) at insert time (detects rehash)
    uint32_t  generation;  // Global generation counter
    uintptr_t node;        // Cached Node* result
};

static SetTableCacheEntry g_setTableCache[SETTABLE_CACHE_SIZE];
static volatile LONG g_setTableGen = 0;
static volatile LONG64 g_stHits = 0;
static volatile LONG64 g_stMisses = 0;

// ================================================================
// Safe Memory Probe
// ================================================================
static inline bool IsSafeRead4(uintptr_t addr) {
    if (addr < 0x10000 || addr > 0xBFFF0000) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    return (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)));
}

static inline uint64_t SetTableHash(uintptr_t table, uintptr_t tstring) {
    uint64_t h = 0xCBF29CE484222325ULL;
    h ^= (table ^ tstring);
    h *= 0x100000001B3ULL;
    return h & SETTABLE_CACHE_MASK;
}

void ClearLuaSetTableCache() {
    memset(g_setTableCache, 0, sizeof(g_setTableCache));
    InterlockedIncrement(&g_setTableGen);
}

// ================================================================
// Hook Target: DISABLED — 0x00857CA0 is luaV_execute (VM interpreter),
// NOT luaV_settable. Wrong function hooked with wrong signature
// (2 params int->int, not 4 params void). See IDA decompilation.
// Bug: every Lua VM opcode execution passed through this broken hook,
// causing return value discard → Lua state corruption.
// ================================================================

#define SETTABLE_CACHE_DISABLED 1

bool InstallLuaSetTableCache() {
#if SETTABLE_CACHE_DISABLED
    Log("[SetTableCache] DISABLED: 0x857CA0 is luaV_execute (VM interpreter), not settable. "
        "Wrong signature caused Lua state corruption.");
    return false;
#else
    Log("[SetTableCache] Code removed — was hooking luaV_execute instead of luaV_settable");
    return false;
#endif
}

void ShutdownLuaSetTableCache() {
    LONG64 hits = g_stHits;
    LONG64 misses = g_stMisses;
    if (hits + misses > 0) {
        Log("[SetTableCache] Stats: %lld hits, %lld misses (%.1f%% hit rate)",
            hits, misses, 100.0 * hits / (hits + misses));
    }
}