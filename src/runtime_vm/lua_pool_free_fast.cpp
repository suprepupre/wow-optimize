// ============================================================================
// Module: lua_pool_free_fast.cpp
// Description: Removes the linear chunk scan from every Lua pool free.
// Safety & Threading: Runs wherever the client frees Lua memory.
// ============================================================================
//
// WoW does not use stock Lua's allocator. It has its own pool, and the pool
// names itself in an assert: ".\src\lmemPool.cpp". sub_8558E0 picks one of nine
// size classes and hands the block to sub_855670, which has to work out which
// chunk of that pool the pointer came from before it can push it onto that
// chunk's free list. It does that by walking every chunk:
//
//     mov eax, [edi]        ; chunk = array[i]
//     mov ecx, [eax]        ; chunk->base        <- dependent load
//     cmp esi, ecx
//     jb  next
//     mov eax, [eax+8]      ; chunk->size        <- dependent load
//     add eax, ecx
//     cmp esi, eax
//     jb  found
//   next:
//     add edx, 1 ; add edi, 4 ; cmp edx, ebx ; jb loop
//
// Two dependent loads per chunk into descriptors scattered across the heap, so
// the loop runs at memory latency rather than at the speed of two compares. An
// earlier measurement of this pool put it at 972 chunks and 16 million calls in
// thirty minutes, and this is the second freeze sample from a tester to land on
// the `jb found` at 0x85569F.
//
// ---------------------------------------------------------------------------
// Why a cache beats the scan by more than it looks
//
// The obvious win is doing fewer iterations. The bigger one is that a cache can
// hold each chunk's bounds BY VALUE. The client cannot: its array holds
// pointers, so learning where a chunk starts costs a load that has to complete
// before the comparison can even begin. Eight entries compared against values
// already in registers beat a hundred chunks reached through pointers, and the
// garbage collector frees a chunk's objects together, so the same few chunks
// answer call after call.
//
// ---------------------------------------------------------------------------
// A torn entry cannot corrupt the heap
//
// A cache holding bounds by value could, in principle, be read while it is half
// written and match a pointer that belongs to neither the old chunk nor the new
// one. Pushing a block onto the wrong chunk's free list would be heap
// corruption, which is not a risk worth taking for a lookup.
//
// So the cache only ever nominates a candidate. Before anything is written, the
// candidate is checked against the chunk's own base and size - the same two
// fields the client reads, read from the same place. A torn entry therefore
// fails that check and costs a fallback scan, and can never place a block
// anywhere the client would not have placed it.
//
// The pool pointer is part of the match on purpose. Chunks from different size
// classes do not overlap, so bounds alone would identify the chunk - but the
// client answers "not mine" when a block is handed to the wrong class's pool,
// and the caller then routes it to the CRT instead. Matching across pools would
// quietly change that.
//
// ---------------------------------------------------------------------------
// Verification
//
// This function mutates a list the client owns, so it cannot be run twice and
// compared. It is checked the other way, by predicting: work out which chunk
// owns the block without writing anything, let the client's own code run, and
// then read back whether the chunk this module chose is the one the client
// pushed onto. The client's push puts the block at the head of the owning
// chunk's free list, so `chunk->freeList == block` afterwards is exactly that
// question, and the return value says found or not found alongside it.
//
// During that phase the full scan is walked as well, so the log can say what
// the scan length actually was rather than repeating the 972 from an older
// session. Nothing is skipped until the predictions have agreed.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

#include "lua_pool_free_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace {

constexpr uintptr_t kPoolFree = 0x00855670;

// Pool object, from sub_855670's own prologue.
constexpr unsigned kP_count  = 0x04;   // number of chunks
constexpr unsigned kP_array  = 0x08;   // array of chunk-descriptor pointers

// Chunk descriptor, from the loop and the tail.
constexpr unsigned kC_base     = 0x00;
constexpr unsigned kC_freeList = 0x04;
constexpr unsigned kC_size     = 0x08;
constexpr unsigned kC_freeCnt  = 0x10;

// sub_855670 is __thiscall with one stack argument and ends in `retn 4`.
typedef int (__fastcall* poolFree_fn)(void* pool, void* edx, void* block);
poolFree_fn orig_PoolFree = nullptr;

bool g_installed = false;
bool g_armed     = false;
bool g_dead      = false;

// Plain 32-bit. This is the hot path the module exists to shorten, and a lost
// increment costs a number rather than correctness; the report says so.
unsigned long g_calls      = 0;
unsigned long g_verified   = 0;
unsigned long g_hits       = 0;   // answered from the cache
unsigned long g_misses     = 0;   // had to walk the pool
unsigned long g_notFound   = 0;   // block belongs to no chunk of this pool
unsigned long g_torn       = 0;   // candidate failed its check against the chunk
unsigned long g_scanSteps  = 0;   // chunks stepped over, misses and learning only
unsigned long g_scanCalls  = 0;
unsigned long g_worstScan  = 0;
unsigned long g_poolChunks = 0;   // chunk count last seen, for the report

constexpr unsigned long kVerifyFirst = 20000;

// Eight entries, checked from the last one that hit. Bounds are held by value;
// the chunk pointer is what gets verified before use.
constexpr unsigned kSlots = 8;
struct Slot {
    uint32_t pool;
    uint32_t base;
    uint32_t end;
    uint32_t chunk;
    uint32_t idx;     // where in the pool's array it was, so its removal is detectable
};
Slot     g_slot[kSlots] = {};
unsigned g_lastHit = 0;
unsigned g_nextIns = 0;

// Everything the cache claims, re-derived from what the client itself reads.
//
// The bounds check alone is not enough. A pool that drops a chunk leaves this
// module holding a pointer to a descriptor whose memory can be handed out again
// and refilled with something else, and two words of that something else could
// pass a range test by chance - which would push a block onto a list that is no
// longer a free list. That is the "cache keyed by an address the engine may free
// and reuse" hazard, so the chunk is also required to still be sitting at the
// index it was found at. Both loads land on the pool object and the array, which
// are hot, rather than on a scattered descriptor.
inline bool StillOwns(uint32_t pool, uint32_t idx, uint32_t chunk, uint32_t block) {
    if (idx >= *(const uint32_t*)(pool + kP_count)) return false;
    uint32_t array = *(const uint32_t*)(pool + kP_array);
    if (*(const uint32_t*)(array + 4 * idx) != chunk) return false;
    uint32_t base = *(const uint32_t*)(chunk + kC_base);
    uint32_t size = *(const uint32_t*)(chunk + kC_size);
    return block >= base && block - base < size;
}

// Nominate a chunk without touching anything. Returns 0 when the cache has
// nothing to offer.
inline uint32_t CacheLookup(uint32_t pool, uint32_t block, uint32_t* outIdx) {
    unsigned i = g_lastHit;
    for (unsigned n = 0; n < kSlots; n++) {
        const Slot& s = g_slot[i];
        if (s.chunk && s.pool == pool && block >= s.base && block < s.end) {
            g_lastHit = i;
            *outIdx = s.idx;
            return s.chunk;
        }
        i = (i + 1) & (kSlots - 1);
    }
    return 0;
}

inline void CacheInsert(uint32_t pool, uint32_t chunk, uint32_t idx) {
    uint32_t base = *(const uint32_t*)(chunk + kC_base);
    uint32_t size = *(const uint32_t*)(chunk + kC_size);
    Slot& s = g_slot[g_nextIns];
    s.chunk = 0;              // stop this slot matching while it is being written
    s.pool  = pool;
    s.base  = base;
    s.end   = base + size;
    s.idx   = idx;
    s.chunk = chunk;
    g_lastHit = g_nextIns;
    g_nextIns = (g_nextIns + 1) & (kSlots - 1);
}

// The client's loop, with the steps counted. Returns 0 when no chunk owns it.
uint32_t ScanPool(uint32_t pool, uint32_t block, unsigned long* steps, uint32_t* outIdx) {
    uint32_t count = *(const uint32_t*)(pool + kP_count);
    uint32_t array = *(const uint32_t*)(pool + kP_array);
    g_poolChunks = count;
    for (uint32_t i = 0; i < count; i++) {
        (*steps)++;
        uint32_t chunk = *(const uint32_t*)(array + 4 * i);
        uint32_t base  = *(const uint32_t*)(chunk + kC_base);
        if (block < base) continue;
        uint32_t size = *(const uint32_t*)(chunk + kC_size);
        if (block - base < size) { *outIdx = i; return chunk; }
    }
    return 0;
}

// Exactly the tail of sub_855670: push the block onto the chunk's free list.
inline void PushFree(uint32_t chunk, uint32_t block) {
    *(uint32_t*)block = *(const uint32_t*)(chunk + kC_freeList);
    (*(uint32_t*)(chunk + kC_freeCnt))++;
    *(uint32_t*)(chunk + kC_freeList) = block;
}

}  // namespace

int __fastcall Hooked_PoolFree(void* pool, void* edx, void* block) {
    g_calls++;

    uint32_t p = (uint32_t)pool;
    uint32_t b = (uint32_t)block;
    if (g_dead || !p || !b) return orig_PoolFree(pool, edx, block);

    if (!g_armed) {
        // Predict, then let the client run, then read back whether the chunk
        // chosen here is the one it pushed onto. Nothing is written from here.
        unsigned long steps = 0;
        uint32_t predicted = 0, predIdx = 0;
        __try {
            predicted = CacheLookup(p, b, &predIdx);
            if (predicted && !StillOwns(p, predIdx, predicted, b)) { g_torn++; predicted = 0; }
            uint32_t scanIdx = 0;
            uint32_t scanned = ScanPool(p, b, &steps, &scanIdx);
            // Any disagreement between the two is settled by the scan, which is
            // what the client itself does.
            if (predicted && predicted != scanned) predicted = 0;
            if (!predicted) { predicted = scanned; predIdx = scanIdx; }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return orig_PoolFree(pool, edx, block);
        }

        g_scanCalls++;
        g_scanSteps += steps;
        if (steps > g_worstScan) g_worstScan = steps;

        int rc = orig_PoolFree(pool, edx, block);

        bool agreed;
        __try {
            if (predicted)
                agreed = (rc == 1) && (*(const uint32_t*)(predicted + kC_freeList) == b);
            else
                agreed = (rc == 0);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            agreed = false;
        }

        g_verified++;
        if (!agreed) {
            g_dead = true;
            Log("[LuaPoolFreeFast] DISAGREED with the client after %lu predictions "
                "- retired for this session, every free now goes to the client's "
                "own code. Block %08X in pool %08X: this module chose chunk %08X, "
                "the client returned %d.",
                g_verified, b, p, predicted, rc);
            return rc;
        }

        if (predicted) { __try { CacheInsert(p, predicted, predIdx); } __except (EXCEPTION_EXECUTE_HANDLER) {} }
        else g_notFound++;

        if (g_verified >= kVerifyFirst) {
            g_armed = true;
            Log("[LuaPoolFreeFast] armed: %lu predictions matched the chunk the "
                "client pushed onto. The scan it is replacing averaged %.1f chunks "
                "and reached %lu at worst, over a pool holding %lu.",
                g_verified,
                g_scanCalls ? (double)g_scanSteps / (double)g_scanCalls : 0.0,
                g_worstScan, g_poolChunks);
        }
        return rc;
    }

    __try {
        uint32_t idx = 0;
        uint32_t chunk = CacheLookup(p, b, &idx);
        if (chunk) {
            if (StillOwns(p, idx, chunk, b)) { g_hits++; PushFree(chunk, b); return 1; }
            g_torn++;
        }
        unsigned long steps = 0;
        chunk = ScanPool(p, b, &steps, &idx);
        g_misses++;
        g_scanCalls++;
        g_scanSteps += steps;
        if (steps > g_worstScan) g_worstScan = steps;
        if (!chunk) { g_notFound++; return 0; }
        CacheInsert(p, chunk, idx);
        PushFree(chunk, b);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return orig_PoolFree(pool, edx, block);
    }
}

namespace LuaPoolFreeFast {

bool Init() {
    if (!Config::g_settings.OptLuaPoolFreeFast) return true;

    if (IsBadReadPtr((void*)kPoolFree, 16)) {
        Log("[LuaPoolFreeFast] 0x%08X unreadable - not installing", (unsigned)kPoolFree);
        return false;
    }
    // The prologue this was read from: push ebp / mov ebp, esp / push ecx.
    const unsigned char* p = (const unsigned char*)kPoolFree;
    if (p[0] != 0x55 || p[1] != 0x8B || p[2] != 0xEC || p[3] != 0x51) {
        Log("[LuaPoolFreeFast] 0x%08X does not start with the prologue this was "
            "built against (%02X %02X %02X %02X) - not installing",
            (unsigned)kPoolFree, p[0], p[1], p[2], p[3]);
        return false;
    }
    if (WineSafe_CreateHook((void*)kPoolFree, (void*)Hooked_PoolFree,
                            (void**)&orig_PoolFree) != MH_OK) {
        Log("[LuaPoolFreeFast] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kPoolFree) != MH_OK) {
        Log("[LuaPoolFreeFast] hook created but could not be enabled");
        return false;
    }

    g_installed = true;
    SamplingProfiler::RegisterSelfSymbol("LuaPoolFree_Fast", (const void*)&Hooked_PoolFree);
    Log("[LuaPoolFreeFast] ACTIVE on the Lua pool free (sub_855670 @ 0x%08X). "
        "Every block the client returns to its Lua pool makes it walk that "
        "pool's chunks, two dependent loads each, until one contains the "
        "pointer - and two tester freeze samples have landed on the compare "
        "inside that loop. This keeps the last %u chunks with their bounds held "
        "by value, so the usual answer costs comparisons instead of pointer "
        "chases. A candidate is always re-checked against the chunk's own base "
        "and size before anything is written, so a stale entry costs a scan and "
        "can never place a block on the wrong list. Predicting against the "
        "client for the first %lu frees before it skips anything.",
        (unsigned)kPoolFree, kSlots, kVerifyFirst);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptLuaPoolFreeFast) return;
    if (!g_installed) { Log("[LuaPoolFreeFast] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[LuaPoolFreeFast] installed but never called"); return; }

    unsigned long looked = g_hits + g_misses;
    Log("[LuaPoolFreeFast] %lu frees%s. The scan averaged %.1f chunks over %lu "
        "walks, worst %lu, pool holding %lu at last look. Counts are lower bounds.",
        g_calls,
        g_dead ? " - RETIRED on a disagreement"
               : (g_armed ? "" : " - still predicting, the client still does every free"),
        g_scanCalls ? (double)g_scanSteps / (double)g_scanCalls : 0.0,
        g_scanCalls, g_worstScan, g_poolChunks);
    if (looked)
        Log("[LuaPoolFreeFast]   %lu answered from the cache (%.1f%%), %lu needed "
            "the walk, %lu belonged to no chunk of their pool, %lu stale entries "
            "were caught by the check and cost a walk",
            g_hits, 100.0 * (double)g_hits / (double)looked,
            g_misses, g_notFound, g_torn);
    else if (!g_dead)
        Log("[LuaPoolFreeFast]   nothing skipped yet: %lu of %lu predictions done",
            g_verified, kVerifyFirst);
}

void Shutdown() {
    if (g_installed) MH_DisableHook((void*)kPoolFree);
}

}  // namespace LuaPoolFreeFast
