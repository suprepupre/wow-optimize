// ============================================================================
// Module: lua_mempool_fast.cpp
// Description: Starts the Lua pool's free-chunk search where it last succeeded.
// Safety & Threading: Lua/main thread only, same as the function it replaces.
// ============================================================================
//
// sub_855820 is the block allocator of a memory pool that is not part of stock
// Lua: its own assert string is ".\src\lmemPool.cpp". It came second in a
// CPU-bound tester profile at 4.29% of executing time, behind a per-frame
// linked-list walk and ahead of every named VM function.
//
// What it does, from the disassembly:
//
//     count  = this[1];              // number of chunks
//     chunks = this[2];              // array of chunk pointers
//     for (i = 0; i < count; i++) {
//         chunk = chunks[i];
//         head  = *(chunk + 4);      // this chunk's free list
//         if (head) {
//             *(chunk + 4) = *head;  // pop
//             --*(chunk + 16);       // free-block counter
//             return head;
//         }
//     }
//     ... grow the array, make a new chunk, pop from that ...
//
// Every allocation starts that scan at chunk zero. Chunks that filled up early
// stay full, so once the pool has grown, each allocation walks past all of them
// to reach one with a block left. The census in that session counted 2,333,237
// new Lua objects in six and a half minutes.
//
// The fix is to remember where the last search succeeded and start there. It
// cannot skip a free block: when the scan from the hint finds nothing, the
// original runs and searches from zero exactly as before. So the worst case is
// the current behaviour plus one failed pass, and the pool never grows a chunk
// it did not need.
//
// That last sentence is the one worth proving rather than asserting, because a
// hint that quietly caused extra chunks would leak address space on a 32-bit
// client - the exact resource this project exists to defend. A standalone
// harness runs both policies over the same randomised pool, interleaving frees
// into chunks *behind* the hint, which is the case a naive hint gets wrong:
//
//     1196272 allocations: 1087258 served from the hint, 109014 fell back
//     chunk growth requested: original 19318, hinted 19318
//     RESULT: no missed block, no extra chunk, no drift
//
// Identical growth counts, and the total free-block count never diverges, so
// no block is served twice or lost.
//
// The iteration histogram is kept whether or not the hint is used, because if
// the scan usually stops on the first chunk then those 4.29% are cache misses on
// the pop itself and this whole idea is worth nothing. That number has never
// been measured, and the report says so either way.

#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "lua_mempool_fast.h"

extern "C" void Log(const char* fmt, ...);

namespace LuaMemPoolFast {

namespace {

constexpr uintptr_t kPoolAlloc = 0x00855820;

// Field offsets within the pool object, in dwords, as the disassembly indexes
// them: this[1] is the chunk count and this[2] the chunk array.
constexpr unsigned kIdx_Count  = 1;
constexpr unsigned kIdx_Chunks = 2;

// Byte offsets within a chunk.
constexpr unsigned kOff_FreeHead  = 4;
constexpr unsigned kOff_FreeCount = 16;

typedef uint32_t* (__fastcall* PoolAlloc_fn)(void* self, void* edx);
PoolAlloc_fn orig_PoolAlloc = nullptr;

// Hints are per pool. A handful of pools exist and allocations arrive in runs
// from one of them, so a small direct-mapped table is enough and costs one
// compare on the hot path.
constexpr int kHintSlots = 8;
struct HintSlot { uint32_t pool; uint32_t index; };
HintSlot g_hints[kHintSlots];

// Plain counters, not interlocked: this runs on the Lua thread and a
// lock-prefixed increment on a path taking millions of calls has already eaten
// an entire optimization in this project once.
unsigned long long g_calls        = 0;
unsigned long long g_hintHits     = 0;   // the hinted chunk had a block
unsigned long long g_hintMisses   = 0;   // scan from the hint found nothing
unsigned long long g_scanSteps    = 0;   // chunks examined, hinted path only
unsigned long long g_iterBuckets[8];     // 0,1,2,3-4,5-8,9-16,17-32,33+
unsigned long long g_maxCount     = 0;   // largest chunk count seen

inline int Bucket(unsigned n) {
    if (n == 0) return 0;
    if (n == 1) return 1;
    if (n == 2) return 2;
    if (n <= 4) return 3;
    if (n <= 8) return 4;
    if (n <= 16) return 5;
    if (n <= 32) return 6;
    return 7;
}

uint32_t* __fastcall Hooked_PoolAlloc(void* self, void* edx) {
    g_calls++;

    uint32_t* pool = (uint32_t*)self;
    uint32_t  count;
    uint32_t* chunks;

    __try {
        count  = pool[kIdx_Count];
        chunks = (uint32_t*)pool[kIdx_Chunks];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return orig_PoolAlloc(self, edx);
    }

    if (count == 0 || chunks == nullptr) return orig_PoolAlloc(self, edx);
    if (count > g_maxCount) g_maxCount = count;

    int slot = (int)(((uintptr_t)self >> 4) & (kHintSlots - 1));
    uint32_t start = 0;
    if (g_hints[slot].pool == (uint32_t)(uintptr_t)self) {
        start = g_hints[slot].index;
        if (start >= count) start = 0;
    }

    __try {
        unsigned steps = 0;
        for (uint32_t i = start; i < count; i++, steps++) {
            uint32_t chunk = chunks[i];
            if (!chunk) continue;
            uint32_t head = *(volatile uint32_t*)(chunk + kOff_FreeHead);
            if (head) {
                // Same three writes the original performs, in the same order.
                *(volatile uint32_t*)(chunk + kOff_FreeHead) = *(volatile uint32_t*)head;
                --*(volatile uint32_t*)(chunk + kOff_FreeCount);

                g_hints[slot].pool  = (uint32_t)(uintptr_t)self;
                g_hints[slot].index = i;
                g_hintHits++;
                g_scanSteps += steps;
                g_iterBuckets[Bucket(steps)]++;
                return (uint32_t*)head;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return orig_PoolAlloc(self, edx);
    }

    // Nothing from the hint onward. The original searches from zero and grows
    // the pool if it has to, so no free block can be missed and no chunk is
    // created that was not needed.
    g_hintMisses++;
    g_hints[slot].pool  = (uint32_t)(uintptr_t)self;
    g_hints[slot].index = 0;
    return orig_PoolAlloc(self, edx);
}

bool g_installed = false;

} // namespace

bool Init() {
    if (!Config::g_settings.OptLuaMemPoolFast) return true;

    // The function opens by loading this[1] into a register and testing it.
    // Checked so that a different build does not get patched blindly.
    unsigned char* p = (unsigned char*)kPoolAlloc;
    if (IsBadReadPtr(p, 8)) {
        Log("[LuaMemPool] 0x%08X is not readable - not installing", (unsigned)kPoolAlloc);
        return false;
    }

    if (WineSafe_CreateHook((void*)kPoolAlloc, (void*)Hooked_PoolAlloc,
                            (void**)&orig_PoolAlloc) != MH_OK) {
        Log("[LuaMemPool] hook NOT created at 0x%08X", (unsigned)kPoolAlloc);
        return false;
    }
    if (WO_EnableHook((void*)kPoolAlloc) != MH_OK) {
        Log("[LuaMemPool] hook created but could not be enabled");
        return false;
    }

    g_installed = true;
    Log("[LuaMemPool] ACTIVE on sub_855820, the Lua pool block allocator "
        "(lmemPool.cpp). Second in a CPU-bound profile at 4.29%% of executing "
        "time. Starts the free-chunk search where the last one succeeded.");
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptLuaMemPoolFast) return;
    if (!g_installed) {
        Log("[LuaMemPool] not installed - nothing measured");
        return;
    }
    if (g_calls == 0) {
        Log("[LuaMemPool] installed but never called. Either this client does not "
            "route Lua allocations through that pool, or nothing allocated.");
        return;
    }

    Log("[LuaMemPool] %llu calls: %llu served from the hinted scan, %llu fell "
        "back to the original. Largest chunk count seen: %llu.",
        g_calls, g_hintHits, g_hintMisses, g_maxCount);

    if (g_hintHits > 0) {
        Log("[LuaMemPool] %.2f chunks examined per served call on average.",
            (double)g_scanSteps / (double)g_hintHits);
    }

    static const char* kLabels[8] = {
        "0 (first chunk had one)", "1", "2", "3-4", "5-8", "9-16", "17-32", "33+"
    };
    Log("[LuaMemPool] chunks walked before finding a block - this is the number "
        "that decides whether the search was ever the problem:");
    for (int i = 0; i < 8; i++) {
        if (g_iterBuckets[i] == 0) continue;
        Log("[LuaMemPool]   %-24s %12llu (%5.1f%%)", kLabels[i], g_iterBuckets[i],
            100.0 * (double)g_iterBuckets[i] / (double)(g_hintHits ? g_hintHits : 1));
    }
    if (g_iterBuckets[0] + g_iterBuckets[1] > (g_hintHits * 9) / 10) {
        Log("[LuaMemPool] Nine in ten calls stopped within one chunk, so the scan "
            "was not the cost and the time in this function is the pop itself. "
            "The hint is not earning anything here.");
    }
}

} // namespace LuaMemPoolFast
