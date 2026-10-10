// ============================================================================
// Description: Starts the Lua pool's free-chunk search where it last succeeded.
// Safety & Threading: Lua/main thread only, same as the function it replaces.
// ============================================================================
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
#include <cstring>
#include <intrin.h>
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

// One index per pool was not enough, and the field said so. A session's
// histogram of chunks walked before a block was found:
//
//     0 (first chunk had one)   4827684 (86.8%)
//     1 .. 32                    329566 ( 5.9%)
//     33+                        406274 ( 7.3%)
//
// The 33+ bucket has no upper edge, and this is the loop both tester freeze
// samples landed in. A single hint cannot fix it: a free below the hint pulls it
// back - 535397 times in that session - and everything between the new hint and
// the chunk that actually has a block is walked again, two dependent loads at a
// time into descriptors scattered across the heap.
//
// So the hint becomes a bitmap: one bit a chunk, set when a free puts a block
// back into that chunk, cleared when the chunk is found empty or is emptied. The
// search is then over set bits in our own contiguous words rather than over
// every chunk through a pointer, and chunks known to be full are never touched.
//
// The bitmap is never the authority. A set bit only nominates a chunk, and that
// chunk's own free-list head is read before anything is popped - the same field
// the client reads, from the same place - so a stale bit costs one check and
// clears itself. When the bitmap nominates nothing the client's own function
// runs, searching from zero exactly as before, so no free block can be missed
// and no chunk is grown that was not needed. That is the safety net the single
// hint already had; only the search changed.
//
// Proved and timed before shipping, in a harness that compiles this file, builds
// a pool in the layout it reads, and supplies the client's own loop as
// orig_PoolAlloc. Three million interleaved allocations and frees, both policies
// over the same script:
//
//     chunks grown             reference 340, bitmap 340 - identical
//     blocks handed out twice  0 and 0
//     order checksum           identical - same blocks, same order
//     client scan              54.37 ns/op
//     bitmap                   20.12 ns/op
//     speedup                  2.70x
//     903 fallbacks in 1.5 million allocations, 0 stale bits
//
// The identical order is worth more than the timing and is not a coincidence.
// The bitmap is scanned from word zero and _BitScanForward returns the lowest
// set bit, so it visits chunks in the order the client visits them and simply
// never touches the ones known to be full. Serving the same block every time is
// the strongest form of "no free block is missed" that a test can show.
//
// The first run of that harness divided by the operations asked for while every
// pass was ending early on an exhausted pool, and reported 6.07 ns/op against
// 1.52. The ratio survived because both sides shared the error; the absolute
// figures did not. Counting what actually ran is what caught it, which is the
// rule that has now caught four instruments in this project.
//
// What this is worth is not mainly the average. A session's 5.56 million
// allocations at roughly 68 ns saved each is a few hundred milliseconds spread
// across half a million frames, which nobody would feel. The tail is the point:
// the 33+ bucket has no upper edge, it is where both tester freeze samples
// landed, and a bitmap scan has no tail to land in.
// A field session reported "Largest chunk count seen: 2436", so 2048 left about
// a sixth of the pool outside the bitmap and those allocations fell through to
// the client. 4096 covers it with room; the cost is one kilobyte of bitmap for
// eight pool slots.
constexpr int kMaxChunks = 4096;
constexpr int kWords     = kMaxChunks / 32;

struct PoolSlot {
    uint32_t pool;
    uint32_t bits[kWords];
};
PoolSlot g_slots[kHintSlots];

unsigned long long g_bmpServed  = 0;   // served from a nominated chunk
unsigned long long g_bmpStale   = 0;   // a set bit whose chunk had filled up
unsigned long long g_bmpRebuild = 0;   // full scans done to reseed a bitmap

// Plain counters, not interlocked: this runs on the Lua thread and a
// lock-prefixed increment on a path taking millions of calls has already eaten
// an entire optimization in this project once.
unsigned long long g_calls        = 0;
unsigned long long g_hintHits     = 0;   // the hinted chunk had a block
unsigned long long g_hintMisses   = 0;   // scan from the hint found nothing
unsigned long long g_scanSteps    = 0;   // chunks examined, hinted path only
unsigned long long g_iterBuckets[8];     // 0,1,2,3-4,5-8,9-16,17-32,33+
unsigned long long g_maxCount     = 0;   // largest chunk count seen
unsigned long long g_hintLowered  = 0;   // times a free pulled the hint back

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

    const int slot = (int)(((uintptr_t)self >> 4) & (kHintSlots - 1));
    PoolSlot& s = g_slots[slot];

    if (s.pool == (uint32_t)(uintptr_t)self) {
        __try {
            unsigned steps = 0;
            int words = (int)((count + 31u) / 32u);
            if (words > kWords) words = kWords;
            for (int w = 0; w < words; ++w) {
                uint32_t word = s.bits[w];
                while (word) {
                    unsigned long bit;
                    _BitScanForward(&bit, word);
                    const uint32_t mask = 1u << bit;
                    word &= ~mask;
                    ++steps;

                    const uint32_t i = (uint32_t)(w * 32) + (uint32_t)bit;
                    if (i >= count) { s.bits[w] &= ~mask; continue; }
                    const uint32_t chunk = chunks[i];
                    if (!chunk) { s.bits[w] &= ~mask; continue; }

                    const uint32_t head =
                        *(volatile uint32_t*)(chunk + kOff_FreeHead);
                    if (!head) {
                        // A bit that no longer means anything. Clearing it here
                        // is the whole self-healing story: nothing else has to
                        // be told the chunk filled up.
                        s.bits[w] &= ~mask;
                        ++g_bmpStale;
                        continue;
                    }

                    // The same three writes the original performs, in order.
                    const uint32_t next = *(volatile uint32_t*)head;
                    *(volatile uint32_t*)(chunk + kOff_FreeHead) = next;
                    --*(volatile uint32_t*)(chunk + kOff_FreeCount);
                    if (!next) s.bits[w] &= ~mask;   // that was its last block

                    g_hintHits++;
                    ++g_bmpServed;
                    g_scanSteps += steps - 1;
                    g_iterBuckets[Bucket(steps - 1)]++;
                    return (uint32_t*)head;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return orig_PoolAlloc(self, edx);
        }
    }

    // The bitmap nominated nothing. The original searches from zero and grows
    // the pool if it has to, so no free block can be missed and no chunk is
    // created that was not needed.
    g_hintMisses++;
    uint32_t* result = orig_PoolAlloc(self, edx);

    // Reseed once from what the pool looks like now. This costs the same walk
    // the original has just paid for, and it is what stops the next allocation
    // arriving here again: a bitmap filled only by frees never learns about a
    // chunk that was grown.
    __try {
        const uint32_t now = pool[kIdx_Count];
        uint32_t* nowChunks = (uint32_t*)pool[kIdx_Chunks];
        if (nowChunks) {
            s.pool = (uint32_t)(uintptr_t)self;
            memset(s.bits, 0, sizeof(s.bits));
            uint32_t lim = now;
            if (lim > (uint32_t)kMaxChunks) lim = (uint32_t)kMaxChunks;
            for (uint32_t i = 0; i < lim; ++i) {
                const uint32_t chunk = nowChunks[i];
                if (!chunk) continue;
                if (*(volatile uint32_t*)(chunk + kOff_FreeHead))
                    s.bits[i >> 5] |= 1u << (i & 31u);
            }
            ++g_bmpRebuild;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s.pool = 0;
    }
    return result;
}

bool g_installed = false;

} // namespace

// Called from the free path, which has already worked out which chunk the block
// went back into. One bit; the allocator checks the chunk itself before
// believing it.
void NoteFreeIntoChunk(unsigned pool, unsigned index) {
    if (!g_installed) return;
    if (index >= (unsigned)kMaxChunks) return;   // past what a bitmap covers
    const int slot = (int)((pool >> 4) & (kHintSlots - 1));
    PoolSlot& s = g_slots[slot];
    if (s.pool != (uint32_t)pool) {
        // A different pool owns this slot. Claiming it leaves a bitmap that
        // knows one chunk, which is correct if slow - everything else falls
        // through to the client until the next reseed.
        s.pool = (uint32_t)pool;
        memset(s.bits, 0, sizeof(s.bits));
        ++g_hintLowered;
    }
    s.bits[index >> 5] |= 1u << (index & 31u);
}

bool Init() {
    if (!Config::g_settings.OptLuaMemPoolFast) return true;

    // The function opens by loading this[1] into a register and testing it.
    // Checked so that a different build does not get patched blindly.
    static const unsigned char kPoolAllocOpening[14] = {
        0x53, 0x56, 0x8B, 0xF1, 0x57, 0x8B, 0x7E, 0x04, 0x33, 0xD2, 0x85, 0xFF, 0x76, 0x27
    };
    if (!WowOpt_ClientBytesAre(kPoolAlloc, kPoolAllocOpening, sizeof(kPoolAllocOpening))) {
        char hex[64];
        WowOpt_HexBytes(kPoolAlloc, hex, sizeof(hex));
        Log("[LuaMemPool] NOT installed: the bytes at 0x%08X are not sub_855820's opening: %s",
            (unsigned)kPoolAlloc, hex);
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

    // The tail this was measured against: with the hint alone, 74.3% of calls
    // found a block in the first chunk they looked at and 18.9% still walked 33
    // or more, because a block freed into a chunk below the hint stays invisible.
    // LuaPoolFast's free hook now says when that happens. Zero here with that
    // feature on would mean the wiring is not reaching, which is a different
    // fact from the tail not existing.
    if (g_hintLowered)
        Log("[LuaMemPool] the hint was pulled back %llu times by a free landing "
            "below it - compare the histogram's 33+ bucket against a run without "
            "LuaPoolFast to see what that bought", g_hintLowered);
    else
        Log("[LuaMemPool] no free ever pulled the hint back. Either LuaPoolFast "
            "is off, or nothing was freed into a chunk below the hint.");

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
