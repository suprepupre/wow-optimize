// ============================================================================
// Module: addon_memory_walk.cpp
//
// sub_85B4E0, the object walk behind UpdateAddOnMemoryUsage. It visits every
// collectable object the Lua state owns (the root list and every string hash
// bucket), and for each object that carries an owning addon it adds the
// object's size to that addon's running total. The totals live in a singly
// linked list hanging off the global state at +0x58, one node per addon,
// {owner, total, next}, created on first sight and put at the head.
//
// The cost is in finding the node. The client's sub_85B0F0 searches that list
// from the head for every object, so an object costs a comparison per addon in
// front of its own. With a few hundred addons and a few million objects that is
// the ~95 ms frame a tester's FreezeCatcher caught when an addon asked for the
// memory figures.
//
// What this changes: the search. A direct-mapped cache from owner to node,
// emptied at the start of every call, answers a repeat owner without walking;
// a miss does the client's own search and, if that finds nothing, the client's
// own allocation (sub_85D6F0(L, 0, 0, 12)) and head insertion, so the nodes
// exist in the same order with the same contents. The node for an owner is
// unique (a node is only made when the search finds none), so a cache entry
// can only ever name the node the search would have found, and nodes are not
// freed during a call.
//
// What it does not change: the pointer chase through the object lists, which
// is the other half of the time, and the object size, which is sub_85B030
// transcribed (a switch on the type byte at +8) and so is one more thing the
// learning phase checks.
//
// Verification: the first calls run the client's version, snapshot the totals
// list, run this version over the same heap and compare the list node for node
// (owner, total, order). Any difference restores the client's list by running
// its version again and retires this module. After that one call in 64 is
// checked the same way. What the in-game check cannot reach is the allocation of a
// node: the client's run goes first and creates every node, so this version only ever
// finds them. The order in which new owners are inserted is covered by the offline
// harness alone, and by the code being the client's own allocation call and head
// insertion. SelfBench cannot time this (a call is about 3e8 cycles, over its cap);
// the module reports its own cycles.
// ============================================================================

#include "addon_memory_walk.h"
#include <cstdint>
#include <cstring>
#include "config.h"
#include "ab_test.h"
#include "self_bench.h"
#include "MinHook.h"
#include "version.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace AddonMemoryWalk {
namespace {

constexpr uintptr_t kTarget = 0x0085B4E0;
static const uint8_t kExpectedPrologue[8] = { 0x55, 0x8B, 0xEC, 0x53, 0x8B, 0x5D, 0x08, 0x56 };

constexpr uintptr_t kReallocAddr = 0x0085D6F0;   // luaM_realloc-style: (L, block, oldSize, newSize)

// Where the globals sit in the client's global state (l_G is lua_State +0x14).
constexpr uint32_t kGOffStrHash = 0x00;      // string table: bucket array
constexpr uint32_t kGOffStrSize = 0x08;      // string table: bucket count
constexpr uint32_t kGOffRootGc  = 0x1C;
constexpr uint32_t kGOffAccum   = 0x58;      // head of the per-owner totals list

constexpr uint32_t kLearnCalls = 4;
constexpr uint32_t kResampleMask = 0x3F;
constexpr uint32_t kMaxOwners = 8192;

struct Acc {
    uint32_t owner;
    uint32_t total;
    Acc*     next;
};

typedef int (__cdecl *Walk_fn)(void* L);
typedef void* (__cdecl *Realloc_fn)(void* L, void* block, uint32_t oldSize, uint32_t newSize);

static Walk_fn g_orig = nullptr;
static bool g_dead = false;
static bool g_abSubject = false;
static int  g_benchId = -1;

static uint64_t g_calls = 0;
static uint64_t g_fastCalls = 0;
static uint64_t g_controlCalls = 0;
static uint32_t g_verified = 0;
static uint32_t g_mismatches = 0;
static uint64_t g_objects = 0;
static uint64_t g_repeatHits = 0;
static uint64_t g_cacheHits = 0;
static uint64_t g_searches = 0;
static uint32_t g_lastOwners = 0;
static uint64_t g_lastFastCycles = 0;
static uint64_t g_maxFastCycles = 0;
static uint64_t g_clientCycles = 0;
static uint64_t g_oursCycles = 0;

constexpr uint32_t kCacheBits = 11;
struct CacheEntry { uint32_t owner; Acc* node; };
static CacheEntry g_cache[1u << kCacheBits];

static uint32_t g_snapOwner[kMaxOwners];
static uint32_t g_snapTotal[kMaxOwners];

static void Retire(const char* reason) {
    g_dead = true;
    ++g_mismatches;
    Log("[AddonMemoryWalk] RETIRED: %s. All subsequent calls delegate to client.", reason);
}

// sub_85B030, with the object in EDX: the size of one collectable object by its type tag.
static inline uint32_t ObjectSize(const uint8_t* o) {
    const uint32_t type = o[8];
    switch (type) {
    case 4:  return *(const uint32_t*)(o + 0x10) + 0x15;                       // string
    case 5: {                                                                  // table
        const uint32_t nodes = 1u << (o[0x0B] & 31);
        return (*(const uint32_t*)(o + 0x20) << 4) + nodes * 40u + 0x24;
    }
    case 6:                                                                    // closure
        if (o[0x0A] != 0) return ((uint32_t)o[0x0B] + 2u) << 4;
        return (*(const uint32_t*)(o + 0x14) != 0 ? 0x20u : 0u) + (uint32_t)o[0x0B] * 4u + 0x1C;
    case 7:  return *(const uint32_t*)(o + 0x14) + 0x18;                       // userdata
    case 8:                                                                    // thread
        return ((*(const uint32_t*)(o + 0x30) + 8u) << 4) + *(const uint32_t*)(o + 0x34) * 24u;
    case 9: {                                                                  // function prototype
        uint32_t n = *(const uint32_t*)(o + 0x3C) * 3u + *(const uint32_t*)(o + 0x2C) * 4u + 0x14;
        n += *(const uint32_t*)(o + 0x38);
        n += *(const uint32_t*)(o + 0x34);
        n += *(const uint32_t*)(o + 0x30);
        n += *(const uint32_t*)(o + 0x28);
        return n * 4u;
    }
    case 10: return 0x20;                                                      // upvalue
    default: return 0;
    }
}

// sub_85B0F0 for one list, with the owner search answered from the cache first.
static void AccumulateList(void* L, uint8_t* G, const uint8_t* obj) {
    uint32_t lastOwner = 0;
    Acc* lastNode = nullptr;
    uint64_t objects = 0, repeats = 0, hits = 0, searches = 0;

    for (; obj; obj = *(const uint8_t* const*)obj) {
        ++objects;
        const uint32_t owner = *(const uint32_t*)(obj + 4);
        if (!owner) continue;
        const uint32_t size = ObjectSize(obj);

        if (owner == lastOwner) {
            lastNode->total += size;
            ++repeats;
            continue;
        }
        CacheEntry& ce = g_cache[(owner * 2654435761u) >> (32 - kCacheBits)];
        Acc* node;
        if (ce.node && ce.owner == owner) {
            node = ce.node;
            node->total += size;
            ++hits;
        } else {
            ++searches;
            node = *(Acc**)(G + kGOffAccum);
            while (node && node->owner != owner) node = node->next;
            if (node) {
                node->total += size;
            } else {
                node = (Acc*)((Realloc_fn)kReallocAddr)(L, nullptr, 0, 12);
                node->next = *(Acc**)(G + kGOffAccum);
                node->owner = owner;
                node->total = size;
                *(Acc**)(G + kGOffAccum) = node;
            }
            ce.owner = owner;
            ce.node = node;
        }
        lastOwner = owner;
        lastNode = node;
    }
    g_objects += objects;
    g_repeatHits += repeats;
    g_cacheHits += hits;
    g_searches += searches;
}

// sub_85B4E0 itself.
static void RunOurs(void* L) {
    uint8_t* const G = *(uint8_t**)((uint8_t*)L + 0x14);
    for (Acc* a = *(Acc**)(G + kGOffAccum); a; a = a->next) a->total = 0;
    std::memset(g_cache, 0, sizeof(g_cache));

    AccumulateList(L, G, *(const uint8_t**)(G + kGOffRootGc));
    const int32_t buckets = *(const int32_t*)(G + kGOffStrSize);
    const uint8_t* const* hash = *(const uint8_t* const* const*)(G + kGOffStrHash);
    for (int32_t i = 0; i < buckets; ++i) AccumulateList(L, G, hash[i]);
}

static uint32_t Snapshot(const uint8_t* G, uint32_t* owners, uint32_t* totals) {
    uint32_t n = 0;
    for (const Acc* a = *(const Acc* const*)(G + kGOffAccum); a; a = a->next) {
        if (n >= kMaxOwners) return kMaxOwners + 1;
        owners[n] = a->owner;
        totals[n] = a->total;
        ++n;
    }
    return n;
}

static __declspec(noinline) int VerifyWithClient(void* L) {
    const uint8_t* const G = *(const uint8_t* const*)((const uint8_t*)L + 0x14);

    const uint64_t c0 = SelfBench::Now();
    const int r = g_orig(L);
    const uint64_t clientCycles = SelfBench::Now() - c0;

    const uint32_t n = Snapshot(G, g_snapOwner, g_snapTotal);
    if (n > kMaxOwners) {
        Retire("more owners than the comparison table holds");
        return r;
    }

    const uint64_t o0 = SelfBench::Now();
    RunOurs(L);
    const uint64_t oursCycles = SelfBench::Now() - o0;

    uint32_t i = 0;
    bool same = true;
    for (const Acc* a = *(const Acc* const*)(G + kGOffAccum); a; a = a->next, ++i) {
        if (i >= n || a->owner != g_snapOwner[i] || a->total != g_snapTotal[i]) { same = false; break; }
    }
    if (same && i != n) same = false;

    if (!same) {
        g_orig(L);                                  // hand back the client's own totals
        Retire("totals list differs from the client's");
        return r;
    }

    ++g_verified;
    g_lastOwners = n;
    g_clientCycles += clientCycles;
    g_oursCycles += oursCycles;
    if (g_benchId >= 0) SelfBench::Pair(g_benchId, oursCycles, clientCycles);
    return r;
}

static int __cdecl Hook_Walk(void* L) {
    ++g_calls;

    if (g_dead) return g_orig(L);

    if (g_abSubject && AbTest::StandAside()) {
        ++g_controlCalls;
        return g_orig(L);
    }

    if (g_verified < kLearnCalls || (g_calls & kResampleMask) == 0)
        return VerifyWithClient(L);

    const uint64_t t0 = SelfBench::Now();
    RunOurs(L);
    const uint64_t dt = SelfBench::Now() - t0;
    ++g_fastCalls;
    g_lastFastCycles = dt;
    if (dt > g_maxFastCycles) g_maxFastCycles = dt;
    return 0;                                      // the caller discards it
}

} // anonymous namespace

void Init() {
    if (!Config::g_settings.OptAddonMemoryWalk) return;

    void* const target = (void*)kTarget;
    if (!WowOpt_ClientPatchAllowed(target)) {
        Log("[AddonMemoryWalk] NOT active: client patches disallowed at 0x%08X", (uintptr_t)target);
        return;
    }
    if (std::memcmp(target, kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[AddonMemoryWalk] NOT active: prologue mismatch at 0x%08X", (uintptr_t)target);
        return;
    }
    const MH_STATUS status = WineSafe_CreateHook(target, (void*)&Hook_Walk, (void**)&g_orig);
    if (status != MH_OK) {
        Log("[AddonMemoryWalk] NOT active: MH_CreateHook failed (%d) at 0x%08X", status, (uintptr_t)target);
        return;
    }
    if (WO_EnableHook(target) != MH_OK) {
        Log("[AddonMemoryWalk] NOT active: MH_EnableHook failed at 0x%08X", (uintptr_t)target);
        return;
    }

    g_benchId = SelfBench::Register("AddonMemoryWalk");
    SamplingProfiler::RegisterSelfSymbol("AddonMemoryWalk", (const void*)kTarget);

    Log("[AddonMemoryWalk] ACTIVE on the UpdateAddOnMemoryUsage object walk (sub_85B4E0 @ 0x%08X, %u learn calls "
        "comparing the whole totals list, then 1 call in %u)", (uintptr_t)kTarget, kLearnCalls, kResampleMask + 1);

    if (AbTest::IsSubject("AddonMemoryWalk", &g_abSubject))
        Log("[AddonMemoryWalk]   under A/B test (subject=%d)", g_abSubject ? 1 : 0);
}

void Shutdown() {
}

void LogStats() {
    if (!Config::g_settings.OptAddonMemoryWalk) return;
    if (!g_calls) {
        Log("[AddonMemoryWalk] no call yet: no addon has asked for the memory figures.");
        return;
    }
    Log("[AddonMemoryWalk] calls=%llu fast=%llu verified=%u mismatches=%u ctrl=%llu dead=%d; %u owner(s) at the last "
        "comparison; owner lookups over %llu object(s): %llu same as the previous object, %llu cache, %llu searched "
        "the list; last fast call %llu cycles, longest %llu; compared calls: client %llu cycles, ours %llu. Plain counters.",
        g_calls, g_fastCalls, g_verified, g_mismatches, g_controlCalls, g_dead ? 1 : 0, g_lastOwners,
        g_objects, g_repeatHits, g_cacheHits, g_searches, g_lastFastCycles, g_maxFastCycles,
        g_clientCycles, g_oursCycles);
}

} // namespace AddonMemoryWalk
