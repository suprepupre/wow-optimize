// ================================================================
// lua_rawgeti Safe Fast Path v2
// ================================================================
// Replaces sub_84E670 (lua_rawgeti) with an optimized version that:
//
// 1. Direct array access for indices within sizearray (O(1), no cache)
// 2. Bucket-index cache for hash-part lookups (NOT pointer cache)
// 3. Content validation on EVERY cache hit (mimalloc-safe)
// 4. SSE2 prefetch during hash chain walks
//
// Safe bucket-index cache (unlike v1 which cached Node* pointers):
//   - Array path: reads directly from table's array buffer, no caching
//   - Hash path: caches bucket INDEX + lsize, recomputes pointer from
//     fresh node_array each time, validates node content before returning
//   - lsize field detects table resizes (bucket count changed → miss)
//   - Bounds checks on all memory accesses
//
// Original implementation (at 0x84E670):
//   Calls luaH_getnum(table, key) which does:
//   - If (key-1) < sizearray: return &array[key-1]  (array fast path)
//   - Else: hash lookup via fmod(key+1, hash_size) and chain walk
//
// Node layout (40 bytes = 10 DWORDs):
//   [0..3]  TValue value (16 bytes)
//   [4]     key.gcobject / key.n_lo
//   [5]     key.n_hi (for number keys)
//   [6]     key.tt (type tag: 3 = LUA_TNUMBER)
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
#include "lua_rawgeti_inline.h"
#include "lua_optimize.h"

extern "C" void Log(const char* fmt, ...);

// ----------------------------------------------------------------
// Statistics
// ----------------------------------------------------------------
static volatile LONG64 g_total_calls = 0;
static volatile LONG64 g_array_hits = 0;
static volatile LONG64 g_cache_hits = 0;
static volatile LONG64 g_chain_walks = 0;
static volatile LONG64 g_chain_depth_total = 0;
static volatile LONG64 g_nil_returns = 0;

// ----------------------------------------------------------------
// Cache configuration
// ----------------------------------------------------------------
// Direct-mapped cache: 8192 entries, keyed on (table ^ key)
// Stores bucket INDEX (not pointer!) + lsize for resize detection
static constexpr int CACHE_BITS = 13;
static constexpr int CACHE_SIZE = 1 << CACHE_BITS;
static constexpr int CACHE_MASK = CACHE_SIZE - 1;

struct SafeRawGetIEntry {
    uint32_t table_lo;      // lower 32 bits of table ptr
    int32_t  key;           // integer key
    uint32_t bucket_idx;    // bucket index where found
    uint8_t  lsize;         // table[11] at time of caching (resize detector)
    uint8_t  pad[3];        // alignment
};

static SafeRawGetIEntry g_cache[CACHE_SIZE];

// ----------------------------------------------------------------
// Nil object sentinel (returned when key not found)
// Located at 0xA46F78 in WoW 3.3.5a
// ----------------------------------------------------------------
static void* g_nil_object = (void*)0x00A46F78;

// ----------------------------------------------------------------
// Original function pointer
// ----------------------------------------------------------------
typedef int (__cdecl *lua_rawgeti_fn)(int L, int idx, int n);
static lua_rawgeti_fn g_orig_rawgeti = nullptr;

// ----------------------------------------------------------------
// Optimized replacement — SAFE (no pointer caching)
// ----------------------------------------------------------------
static int __cdecl Optimized_RawGetI(int L, int idx, int n)
{
    InterlockedIncrement64(&g_total_calls);

    // Bail out during lua_State swap — L->base and L->top become garbage
    // when WoW destroys the old Lua VM during UI reload/logout.
    if (LuaOpt::IsReloading() || LuaOpt::IsSwapping()) {
        return g_orig_rawgeti(L, idx, n);
    }

    // Validate L pointer
    if ((uintptr_t)L < 0x10000 || (uintptr_t)L > 0xBFFF0000) {
        return g_orig_rawgeti(L, idx, n);
    }

    __try {
        // Resolve table from stack index
        int* tableSlot = nullptr;
        int* L_base = *(int**)(L + 0x10);  // L->base
        int* L_top  = *(int**)(L + 0x0C);  // L->top

        if (idx > 0) {
            if (L_base + (idx - 1) * 4 < L_top)
                tableSlot = L_base + (idx - 1) * 4;
        } else if (idx >= -10000) {
            tableSlot = L_top + idx * 4;
            if (tableSlot < L_base) {
                return g_orig_rawgeti(L, idx, n);
            }
        } else if (idx == -10002) {
            tableSlot = L_base + 18 * 4;  // GLOBALSINDEX
        }

        if (!tableSlot) {
            return g_orig_rawgeti(L, idx, n);
        }

        int table = tableSlot[0];
        // Validate: must be a table (tt==5)
        if (tableSlot[2] != 5 || table < 0x10000 || table > 0xBFFF0000) {
            return g_orig_rawgeti(L, idx, n);
        }

        // ============================================================
        // FAST PATH 1: Direct array access
        // If (n-1) < sizearray, the value is in the array part.
        // This is O(1) with no cache needed.
        // ============================================================
        int sizearray = *(int*)(table + 32);
        if ((unsigned int)(n - 1) < (unsigned int)sizearray) {
            int* array = *(int**)(table + 16);
            if (!array || (uintptr_t)array < 0x10000 || (uintptr_t)array > 0xBFFF0000) {
                return g_orig_rawgeti(L, idx, n);
            }

            // Prefetch next cache line for sequential access patterns
            if (n < sizearray) {
                _mm_prefetch((const char*)(array + n * 4), _MM_HINT_T0);
            }

            int* src = array + (n - 1) * 4;  // 4 DWORDs = 16 bytes per TValue

            // Push TValue onto Lua stack
            DWORD* top = *(DWORD**)(L + 0x0C);
            if (!top || (uintptr_t)top < 0x10000 || (uintptr_t)top > 0xBFFF0000) {
                return g_orig_rawgeti(L, idx, n);
            }

            top[0] = src[0];  // value lo
            top[1] = src[1];  // value hi
            top[2] = src[2];  // tt
            top[3] = src[3];  // taint
            *(DWORD**)(L + 0x0C) = top + 4;

            // Handle taint propagation
            DWORD taint = src[3];
            if (taint) {
                if (*(int*)0x00D413A0 && !*(int*)0x00D413A4)
                    *(DWORD*)0x00D4139C = taint;
            }

            InterlockedIncrement64(&g_array_hits);
            return src[3];  // return taint value (matches original behavior)
        }

        // ============================================================
        // HASH PART: Integer key not in array, need hash lookup
        // ============================================================

        // Read table metadata
        uint8_t  lsize      = *(uint8_t*)(table + 11);   // log2 of hash size
        uint32_t* node_array = *(uint32_t**)(table + 20); // hash bucket array

        if (!node_array || lsize == 0 || lsize > 24) {
            return g_orig_rawgeti(L, idx, n);
        }

        // Compute bucket index for integer key
        // WoW's luaH_getnum uses: fmod(key + 1.0, hash_size)
        // For positive integers: (key + 1) % hash_size (when hash_size is power of 2)
        // But WoW uses ((HIDWORD(v) + LODWORD(v)) % ((1<<lsize-1)|1)) which is different
        // Let's compute it the same way as the original:
        double dkey = (double)n + 1.0;
        // Convert to integer representation matching WoW's approach
        uint64_t dkey_bits;
        memcpy(&dkey_bits, &dkey, sizeof(dkey_bits));
        uint32_t hash_val = (uint32_t)(dkey_bits >> 32) + (uint32_t)dkey_bits;

        uint32_t bucket_mask = ((1u << lsize) - 1) | 1u;  // WoW uses OR 1 for odd size
        uint32_t bucket_idx  = hash_val % bucket_mask;

        // Get first node in chain
        uint32_t* node = (uint32_t*)((uint8_t*)node_array + 40 * bucket_idx);

        // Check first node directly
        if (node[6] == 3) {  // key.tt == LUA_TNUMBER
            double node_key;
            memcpy(&node_key, &node[4], sizeof(double));
            if (node_key == (double)n) {
                // Found on first node - push value
                DWORD* top = *(DWORD**)(L + 0x0C);
                if (top && (uintptr_t)top >= 0x10000 && (uintptr_t)top <= 0xBFFF0000) {
                    top[0] = node[0];
                    top[1] = node[1];
                    top[2] = node[2];
                    top[3] = node[3];
                    *(DWORD**)(L + 0x0C) = top + 4;

                    DWORD taint = node[3];
                    if (taint && *(int*)0x00D413A0 && !*(int*)0x00D413A4)
                        *(DWORD*)0x00D4139C = taint;

                    InterlockedIncrement64(&g_cache_hits);
                    return taint;
                }
            }
        }

        // ============================================================
        // FAST PATH 2: Bucket-index cache lookup
        // ============================================================
        uint32_t cache_key = ((uint32_t)table ^ (uint32_t)n) & CACHE_MASK;
        SafeRawGetIEntry* entry = &g_cache[cache_key];

        if (entry->table_lo == (uint32_t)table &&
            entry->key == n &&
            entry->lsize == lsize) {
            // Cache hit — recompute pointer from FRESH node_array
            uint32_t cached_bucket = entry->bucket_idx;
            if (cached_bucket < bucket_mask + 1) {
                uint32_t* cached_node = (uint32_t*)((uint8_t*)node_array + 40 * cached_bucket);

                // CONTENT VALIDATION
                uintptr_t cn = (uintptr_t)cached_node;
                if (cn >= 0x10000 && cn <= 0xBFFF0000 &&
                    cached_node[6] == 3) {  // key.tt == LUA_TNUMBER
                    double ck;
                    memcpy(&ck, &cached_node[4], sizeof(double));
                    if (ck == (double)n) {
                        // Valid cache hit - push value
                        DWORD* top = *(DWORD**)(L + 0x0C);
                        if (top && (uintptr_t)top >= 0x10000 && (uintptr_t)top <= 0xBFFF0000) {
                            top[0] = cached_node[0];
                            top[1] = cached_node[1];
                            top[2] = cached_node[2];
                            top[3] = cached_node[3];
                            *(DWORD**)(L + 0x0C) = top + 4;

                            DWORD taint = cached_node[3];
                            if (taint && *(int*)0x00D413A0 && !*(int*)0x00D413A4)
                                *(DWORD*)0x00D4139C = taint;

                            InterlockedIncrement64(&g_cache_hits);
                            return taint;
                        }
                    }
                }
            }
        }

        // ============================================================
        // SLOW PATH: Chain walk with prefetch
        // ============================================================
        InterlockedIncrement64(&g_chain_walks);
        int depth = 1;

        void* next = (void*)node[8];
        while (next != nullptr) {
            uint32_t* nd = (uint32_t*)next;
            uintptr_t np = (uintptr_t)nd;

            if (np < 0x10000 || np > 0xBFFF0000) break;

            // Prefetch next node
            void* prefetch_next = (void*)nd[8];
            if (prefetch_next) {
                _mm_prefetch((const char*)prefetch_next, _MM_HINT_T0);
            }

            if (nd[6] == 3) {  // key.tt == LUA_TNUMBER
                double nk;
                memcpy(&nk, &nd[4], sizeof(double));
                if (nk == (double)n) {
                    // Found — cache the bucket index
                    entry->table_lo = (uint32_t)table;
                    entry->key = n;
                    entry->bucket_idx = bucket_idx;
                    entry->lsize = lsize;

                    // Push value
                    DWORD* top = *(DWORD**)(L + 0x0C);
                    if (top && (uintptr_t)top >= 0x10000 && (uintptr_t)top <= 0xBFFF0000) {
                        top[0] = nd[0];
                        top[1] = nd[1];
                        top[2] = nd[2];
                        top[3] = nd[3];
                        *(DWORD**)(L + 0x0C) = top + 4;

                        DWORD taint = nd[3];
                        if (taint && *(int*)0x00D413A0 && !*(int*)0x00D413A4)
                            *(DWORD*)0x00D4139C = taint;

                        InterlockedAdd64(&g_chain_depth_total, depth);
                        return taint;
                    }
                }
            }

            next = prefetch_next;
            depth++;
        }

        // Not found — push nil
        InterlockedIncrement64(&g_nil_returns);
        DWORD* top = *(DWORD**)(L + 0x0C);
        if (top && (uintptr_t)top >= 0x10000 && (uintptr_t)top <= 0xBFFF0000) {
            // Push nil TValue: value=0, tt=0, taint=0
            top[0] = 0;
            top[1] = 0;
            top[2] = 0;
            top[3] = 0;
            *(DWORD**)(L + 0x0C) = top + 4;
        }
        return 0;

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return g_orig_rawgeti(L, idx, n);
    }
}

// ----------------------------------------------------------------
// Install / Uninstall
// ----------------------------------------------------------------
bool InstallLuaRawGetIInline()
{
    void* target = (void*)0x0084E670;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("[RawGetIInline] BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (MH_CreateHook(target, (void*)Optimized_RawGetI, (void**)&g_orig_rawgeti) != MH_OK) {
        Log("[RawGetIInline] MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[RawGetIInline] MH_EnableHook FAILED");
        return false;
    }

    // Zero-initialize cache
    memset(g_cache, 0, sizeof(g_cache));

    Log("[RawGetIInline] ACTIVE v2: safe array direct + bucket-index cache (%d entries)", CACHE_SIZE);
    return true;
}

void UninstallLuaRawGetIInline()
{
    MH_DisableHook((void*)0x0084E670);
    MH_RemoveHook((void*)0x0084E670);

    LONG64 total = g_total_calls;
    LONG64 arr   = g_array_hits;
    LONG64 cache = g_cache_hits;
    LONG64 walks = g_chain_walks;
    LONG64 nils  = g_nil_returns;
    LONG64 depth = g_chain_depth_total;

    if (total > 0) {
        double arrPct   = 100.0 * arr / total;
        double cachePct = 100.0 * cache / total;
        double avgDepth = walks > 0 ? (double)depth / walks : 0;
        Log("[RawGetIInline] Stats: %lld calls | %lld array (%.1f%%) | "
            "%lld cache (%.1f%%) | %lld walks (avg depth %.1f) | %lld nil",
            total, arr, arrPct, cache, cachePct, walks, avgDepth, nils);
    }
}