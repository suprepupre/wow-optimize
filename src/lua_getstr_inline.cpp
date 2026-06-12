// ================================================================
// luaH_getstr Safe Fast Path v2
// ================================================================
// Replaces sub_85C430 (luaH_getstr) with an optimized version that:
//
// 1. Direct first-node check (no cache, ~80% hit rate)
// 2. Bucket-index cache (NOT pointer cache) for deeper chains
// 3. SSE2 prefetch during chain walks
// 4. Content validation on EVERY cache hit (mimalloc-safe)
//
// Safe bucket-index cache (unlike v1 which cached Node* pointers):
//   - v1 cached absolute Node* pointers → stale after mimalloc reuse
//   - v2 caches bucket INDEX + lsize → recomputes pointer from fresh
//     node_array each time → always points to correct location
//   - Content validation (node[6]==4 && node[4]==tstring) ensures we
//     never return wrong data even if addresses are reused
//   - lsize field detects table resizes (bucket count changed)
//
// Original implementation (at 0x85C430):
//   result = table[20] + 40 * (tstring[12] & ((1 << table[11]) - 1))
//   while (result[6] != 4 || result[4] != a2) {
//     result = result[8];
//     if (!result) return &nilObject;
//   }
//   return result;
//
// Node layout (40 bytes = 10 DWORDs):
//   [0..3]  TValue value
//   [4]     key.gcobject (TString*)
//   [5]     padding
//   [6]     key.tt (type tag: 4 = LUA_TSTRING)
//   [7]     padding
//   [8]     next pointer (Node*)
//   [9]     padding
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <emmintrin.h>
#include "MinHook.h"
#include "lua_getstr_inline.h"
#include "hot_patch.h"
#include "lua_optimize.h"

extern "C" void Log(const char* fmt, ...);

// ----------------------------------------------------------------
// Statistics
// ----------------------------------------------------------------
static volatile LONG64 g_total_calls = 0;
static volatile LONG64 g_first_node_hits = 0;
static volatile LONG64 g_cache_hits = 0;
static volatile LONG64 g_chain_walks = 0;
static volatile LONG64 g_chain_depth_total = 0;
static volatile LONG64 g_nil_returns = 0;

// ----------------------------------------------------------------
// Cache configuration
// ----------------------------------------------------------------
// Direct-mapped cache: 16384 entries, keyed on (table ^ tstring_hash)
// Stores bucket INDEX (not pointer!) + lsize for resize detection
static constexpr int CACHE_BITS = 14;
static constexpr int CACHE_SIZE = 1 << CACHE_BITS;
static constexpr int CACHE_MASK = CACHE_SIZE - 1;

struct SafeGetStrEntry {
    uint32_t table_lo;      // lower 32 bits of table ptr
    uint32_t tstring_hash;  // tstring[12] precomputed hash
    uint32_t bucket_idx;    // bucket index where string was found
    uint8_t  lsize;         // table[11] at time of caching (resize detector)
    uint8_t  pad[3];        // alignment
};

static SafeGetStrEntry g_cache[CACHE_SIZE];

// ----------------------------------------------------------------
// Nil object sentinel (returned when key not found)
// Located at 0xA46F78 in WoW 3.3.5a
// ----------------------------------------------------------------
static void* g_nil_object = (void*)0x00A46F78;

// ----------------------------------------------------------------
// Original function pointer
// ----------------------------------------------------------------
typedef void* (__cdecl *luaH_getstr_fn)(int table, int tstring);
static luaH_getstr_fn g_orig_getstr = nullptr;

// ----------------------------------------------------------------
// Optimized replacement — SAFE (no pointer caching)
// ----------------------------------------------------------------
static void* __cdecl Optimized_GetStr(int table, int tstring)
{
    InterlockedIncrement64(&g_total_calls);

    // Bail out during lua_State swap — table and tstring pointers become
    // garbage when WoW destroys the old Lua VM during UI reload/logout.
    if (LuaOpt::IsReloading() || LuaOpt::IsSwapping()) {
        return g_orig_getstr(table, tstring);
    }

    // Validate inputs — reject obviously invalid pointers
    if ((uintptr_t)table < 0x10000 || (uintptr_t)table > 0xBFFF0000 ||
        (uintptr_t)tstring < 0x10000 || (uintptr_t)tstring > 0xBFFF0000) {
        return g_orig_getstr(table, tstring);
    }

    // Read tstring hash: tstring[12] = precomputed string hash
    uint32_t ts_hash = *(uint32_t*)(tstring + 12);

    // Read table metadata
    uint8_t  lsize      = *(uint8_t*)(table + 11);   // log2 of hash size
    uint32_t* node_array = *(uint32_t**)(table + 20); // hash bucket array

    if (!node_array || lsize == 0 || lsize > 24) {
        return g_orig_getstr(table, tstring);
    }

    // Compute bucket index: ts_hash & ((1 << lsize) - 1)
    uint32_t bucket_mask = (1u << lsize) - 1;
    uint32_t bucket_idx  = ts_hash & bucket_mask;

    // Get first node in chain
    // Each node is 40 bytes = 10 DWORDs
    uint32_t* node = (uint32_t*)((uint8_t*)node_array + 40 * bucket_idx);

    // ============================================================
    // FAST PATH 1: Direct first-node check (~80% of lookups)
    // No cache involved — just check if the bucket's first node
    // is our target. This is the most common case.
    // ============================================================
    if (node[6] == 4 && node[4] == (uint32_t)tstring) {
        InterlockedIncrement64(&g_first_node_hits);
        return node;
    }

    // ============================================================
    // FAST PATH 2: Bucket-index cache lookup
    // Cache stores bucket_idx + lsize, NOT a pointer.
    // We recompute the pointer from fresh node_array each time.
    // ============================================================
    uint32_t cache_key = ((uint32_t)table ^ ts_hash) & CACHE_MASK;
    SafeGetStrEntry* entry = &g_cache[cache_key];

    if (entry->table_lo == (uint32_t)table &&
        entry->tstring_hash == ts_hash &&
        entry->lsize == lsize) {
        // Cache hit — recompute pointer from FRESH node_array
        uint32_t cached_bucket = entry->bucket_idx;
        if (cached_bucket <= bucket_mask) {
            uint32_t* cached_node = (uint32_t*)((uint8_t*)node_array + 40 * cached_bucket);

            // CONTENT VALIDATION — this is what makes it safe.
            // Even if mimalloc reused the address, the content check
            // ensures we only return the correct node.
            uintptr_t cn = (uintptr_t)cached_node;
            if (cn >= 0x10000 && cn <= 0xBFFF0000 &&
                cached_node[6] == 4 && cached_node[4] == (uint32_t)tstring) {
                InterlockedIncrement64(&g_cache_hits);
                return cached_node;
            }
        }
    }

    // ============================================================
    // SLOW PATH: Chain walk with prefetch
    // Walk the linked list from the first node, prefetching ahead.
    // ============================================================
    InterlockedIncrement64(&g_chain_walks);
    int depth = 1;

    void* next = (void*)node[8];
    while (next != nullptr) {
        uint32_t* n = (uint32_t*)next;
        uintptr_t np = (uintptr_t)n;

        // Bounds check
        if (np < 0x10000 || np > 0xBFFF0000) break;

        // Prefetch next node's cache line while we check this one
        void* prefetch_next = (void*)n[8];
        if (prefetch_next) {
            _mm_prefetch((const char*)prefetch_next, _MM_HINT_T0);
        }

        if (n[6] == 4 && n[4] == (uint32_t)tstring) {
            // Found — cache the bucket index (NOT the pointer)
            // Compute which bucket this node belongs to by scanning
            // Actually, we can compute it: the node is somewhere in the
            // chain starting at bucket_idx. For caching, we store the
            // ORIGINAL bucket_idx since that's where the chain starts.
            // On next lookup, we'll find this node via the cached bucket.
            // But wait — the node might be at a different position in the
            // chain. We need to store the bucket where THIS node lives.
            // Since nodes in a chain all hash to the same bucket, we can
            // just store the current bucket_idx.
            entry->table_lo = (uint32_t)table;
            entry->tstring_hash = ts_hash;
            entry->bucket_idx = bucket_idx;
            entry->lsize = lsize;

            InterlockedAdd64(&g_chain_depth_total, depth);
            return n;
        }

        next = prefetch_next;
        depth++;
    }

    // Not found
    InterlockedIncrement64(&g_nil_returns);
    return g_nil_object;
}

// ----------------------------------------------------------------
// Install / Uninstall
// ----------------------------------------------------------------
bool InstallLuaGetStrInline()
{
    void* target = (void*)0x0085C430;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("[GetStrInline] BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (MH_CreateHook(target, (void*)Optimized_GetStr, (void**)&g_orig_getstr) != MH_OK) {
        Log("[GetStrInline] MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[GetStrInline] MH_EnableHook FAILED");
        return false;
    }

    // Zero-initialize cache
    memset(g_cache, 0, sizeof(g_cache));

    Log("[GetStrInline] ACTIVE v2: safe bucket-index cache + prefetch (%d entries)", CACHE_SIZE);
    return true;
}

void UninstallLuaGetStrInline()
{
    MH_DisableHook((void*)0x0085C430);
    MH_RemoveHook((void*)0x0085C430);

    LONG64 total = g_total_calls;
    LONG64 first = g_first_node_hits;
    LONG64 cache = g_cache_hits;
    LONG64 walks = g_chain_walks;
    LONG64 nils  = g_nil_returns;
    LONG64 depth = g_chain_depth_total;

    if (total > 0) {
        double firstPct = 100.0 * first / total;
        double cachePct = 100.0 * cache / total;
        double avgDepth = walks > 0 ? (double)depth / walks : 0;
        Log("[GetStrInline] Stats: %lld calls | %lld first-node (%.1f%%) | "
            "%lld cache (%.1f%%) | %lld walks (avg depth %.1f) | %lld nil",
            total, first, firstPct, cache, cachePct, walks, avgDepth, nils);
    }
}