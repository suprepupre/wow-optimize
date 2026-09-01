// ============================================================================
// Module: m2_sort_key_cache.cpp
// Description: Caches the sort key a render-batch comparator re-derives.
// Safety & Threading: Main thread, inside the model render sort.
// ============================================================================
//
// sub_824B70 is 2.44% of executing time in a tester's uncapped, CPU-bound
// session - ninth in the profile, above every Lua entry. It is eighty-one
// instructions and does no arithmetic worth the name. It is a comparator.
//
// The client sorts render batches with it, from several inlined sort routines:
// sub_82BC20 calls it three times, sub_82E840 five or more, and there are others.
// So the same batch is compared over and over, and each comparison re-derives
// the same key from scratch.
//
// Deriving it costs five dependent loads per operand:
//
//     v3    = *(*a1 + 720)
//     table = *v3                              ; and base = v3[2]
//     idx16 = *(u16*)(table + 24 * a1[1] + 4)
//     desc  = base + 48 * idx16
//     key   = *(u16*)(desc + 16)
//
// Nothing can start until the one before it returns, and the profile's weight
// sits at 0x824B7E, which is the second link - `mov edx, [eax+720]`. That is not
// a busy function, it is a function waiting on memory.
//
// So the derived descriptor is remembered per (object, submesh index) and the
// key read straight out of it. Three of the five links go away.
//
// ---------------------------------------------------------------------------
// What the comparator actually says
//
// Written as the client's branches resolve, it is a plain lexicographic
// less-than over four keys:
//
//     key (u16 at desc+16), then *(obj+720), then *(obj+44), then the index
//
// all unsigned. Worth writing out because the disassembly expresses it as nested
// `>=` tests with fallthrough, which reads as though the equal cases go
// somewhere else, and they do not.
//
// ---------------------------------------------------------------------------
// Staleness, which is the whole risk
//
// A wrong key does not crash; it changes the sort order, and a wrong render
// order shows up as transparency drawn in the wrong sequence. That is the kind
// of defect nobody reports precisely, so the cache is bounded by something that
// cannot drift: a generation number bumped on the frame boundary, from
// WowOpt_OnFrameBoundary, which both present paths reach exactly once per
// presented frame. An entry from an earlier frame is not stale, it is invisible.
//
// Within a single frame the material a submesh points at does not move - the
// animation pass has finished before the render sort begins - so a hit inside
// the generation is answering with data derived this frame.
//
// ---------------------------------------------------------------------------
// Verification
//
// The comparator is pure. It reads memory and returns a bool, and it writes
// nothing at all - so unlike almost everything else replaced in this project,
// both versions can simply be run and their answers compared, with no saving
// and restoring and no predicting. The first calls do exactly that, and one in
// four thousand keeps doing it afterwards.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

#include "m2_sort_key_cache.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"
#include "ab_test.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace M2SortKey {

namespace {

constexpr uintptr_t kCompare = 0x00824B70;

// Offsets, all read off sub_824B70 itself.
constexpr unsigned kO_batchPtr = 720;   // object + 720: the batch block, or null
constexpr unsigned kO_altRoot  = 44;    // object + 44 when it is null
constexpr unsigned kO_desc     = 16;    // the u16 sort key inside the descriptor
constexpr unsigned kSubStride  = 24;    // submesh table stride
constexpr unsigned kSubIdxOff  = 4;     // u16 index within a submesh entry
constexpr unsigned kDescStride = 48;

typedef int (__stdcall* compare_fn)(void* a, void* b);
compare_fn orig_Compare = nullptr;

bool g_installed = false;
bool g_armed     = false;
// Set at init when the A/B harness names this module, so the hot path
// tests a plain bool instead of calling out on every invocation.
bool g_abSubject = false;
bool g_dead      = false;

// Plain 32-bit on a comparator's path. Lower bounds, and the report says so.
unsigned long g_calls    = 0;
unsigned long g_verified = 0;
unsigned long g_hits     = 0;
unsigned long g_misses   = 0;

constexpr unsigned long kVerifyFirst  = 20000;
constexpr unsigned long kResampleMask = 4095;

constexpr unsigned kSlots = 256;   // power of two; direct-mapped
struct Slot {
    uint32_t obj;
    uint32_t idx;
    uint32_t gen;
    uint32_t desc;
};
Slot     g_slot[kSlots] = {};
uint32_t g_gen = 1;                // never 0, so a zeroed slot cannot match

// The client's derivation, verbatim. Returns 0 if it cannot be followed.
inline uint32_t DeriveDesc(uint32_t obj, uint32_t idx) {
    uint32_t batch = *(const uint32_t*)(obj + kO_batchPtr);
    uint32_t base, table;
    if (batch) {
        base  = *(const uint32_t*)(batch + 8);
        table = *(const uint32_t*)batch;
    } else {
        uint32_t root = *(const uint32_t*)(obj + kO_altRoot);
        base  = *(const uint32_t*)(root + 396);
        table = *(const uint32_t*)(*(const uint32_t*)(root + 368) + 40);
    }
    uint32_t sub = *(const uint16_t*)(table + kSubStride * idx + kSubIdxOff);
    return base + kDescStride * sub;
}

inline uint32_t DescFor(uint32_t obj, uint32_t idx) {
    unsigned h = (unsigned)(((obj >> 4) ^ idx) & (kSlots - 1));
    Slot& s = g_slot[h];
    if (s.gen == g_gen && s.obj == obj && s.idx == idx) { g_hits++; return s.desc; }
    uint32_t d = DeriveDesc(obj, idx);
    g_misses++;
    s.obj = obj; s.idx = idx; s.desc = d; s.gen = g_gen;
    return d;
}

// Lexicographic less-than over the four keys, in the client's order.
inline int Compare(void* a, void* b) {
    const uint32_t* pa = (const uint32_t*)a;
    const uint32_t* pb = (const uint32_t*)b;
    uint32_t oa = pa[0], ia = pa[1];
    uint32_t ob = pb[0], ib = pb[1];

    uint16_t ka = *(const uint16_t*)(DescFor(oa, ia) + kO_desc);
    uint16_t kb = *(const uint16_t*)(DescFor(ob, ib) + kO_desc);
    if (ka != kb) return ka < kb;

    uint32_t ba = *(const uint32_t*)(oa + kO_batchPtr);
    uint32_t bb = *(const uint32_t*)(ob + kO_batchPtr);
    if (ba != bb) return ba < bb;

    uint32_t ra = *(const uint32_t*)(oa + kO_altRoot);
    uint32_t rb = *(const uint32_t*)(ob + kO_altRoot);
    if (ra != rb) return ra < rb;

    return ia < ib;
}

}  // namespace

int __stdcall Hooked_CompareBody(void* a, void* b) {
    g_calls++;
    if (g_dead || !a || !b) return orig_Compare(a, b);


    if (!g_armed || (g_calls & kResampleMask) == 0) {
        int mine;
        __try {
            mine = Compare(a, b);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return orig_Compare(a, b);
        }
        int theirs = orig_Compare(a, b);
        g_verified++;

        if ((mine != 0) != (theirs != 0)) {
            g_dead = true;
            Log("[M2SortKey] DISAGREED with the client after %lu comparisons - "
                "retired for this session, every comparison now goes to the "
                "client's own code. It answered %d and this answered %d.",
                g_verified, theirs, mine);
            return theirs;
        }
        if (!g_armed && g_verified >= kVerifyFirst) {
            g_armed = true;
            Log("[M2SortKey] armed: %lu comparisons agreed with the client. Now "
                "answering directly, rechecking one in %lu, with %lu cache hits "
                "and %lu derivations so far.",
                g_verified, kResampleMask + 1, g_hits, g_misses);
        }
        return theirs;
    }

    __try {
        return Compare(a, b);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return orig_Compare(a, b);
    }
}

// The detour proper, kept apart from the body above for one reason: the
// A/B harness times the call, and a scope guard that closed the sample on
// every return path cannot be used in a function containing __try - MSVC
// refuses object unwinding alongside SEH. A wrapper has no __try of its own,
// so one pair of reads covers every path the body can take, including the
// ones it takes out of an exception handler.
//
// When no test names this module the whole thing is a branch on a false
// global followed by a direct call.
int __stdcall Hooked_Compare(void* a, void* b) {
    if (!g_abSubject) return Hooked_CompareBody(a, b);
    unsigned long long t = AbTest::TickIn();
    int r = AbTest::StandAside() ? orig_Compare(a, b)
                                       : Hooked_CompareBody(a, b);
    AbTest::TickOut(t);
    return r;
}

bool Init() {
    if (!Config::g_settings.OptM2SortKey) return true;

    if (IsBadReadPtr((void*)kCompare, 16)) {
        Log("[M2SortKey] 0x%08X unreadable - not installing", (unsigned)kCompare);
        return false;
    }
    // push ebp / mov ebp, esp / mov eax, [ebp+arg_0]
    const unsigned char* p = (const unsigned char*)kCompare;
    if (p[0] != 0x55 || p[1] != 0x8B || p[2] != 0xEC || p[3] != 0x8B) {
        Log("[M2SortKey] 0x%08X does not start with the prologue this was read "
            "from (%02X %02X %02X %02X) - not installing",
            (unsigned)kCompare, p[0], p[1], p[2], p[3]);
        return false;
    }
    if (WineSafe_CreateHook((void*)kCompare, (void*)Hooked_Compare,
                            (void**)&orig_Compare) != MH_OK) {
        Log("[M2SortKey] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kCompare) != MH_OK) {
        Log("[M2SortKey] hook created but could not be enabled");
        return false;
    }

    g_abSubject = AbTest::IsSubject("M2SortKey");
    if (g_abSubject) {
        Log("[M2SortKey] under A/B test: it alternates on and off in stints "
            "and AbTest reports the frame times either way. The correctness "
            "checks are unaffected and still retire it on a disagreement.");
    }

    g_installed = true;
    SamplingProfiler::RegisterSelfSymbol("M2SortKey_Compare", (const void*)&Hooked_Compare);
    Log("[M2SortKey] ACTIVE on the render batch comparator (sub_824B70 @ "
        "0x%08X), 2.44%% of executing time in an uncapped tester session - ninth "
        "in the profile, above every Lua entry. It does no arithmetic; it derives "
        "one 16-bit key through five dependent loads and compares it, and the "
        "profile's weight sits on the second of those loads. The derived "
        "descriptor is remembered per object and submesh for the length of one "
        "frame, which removes three of the five. The comparator is pure, so both "
        "answers are simply compared for the first %lu calls and one in %lu after "
        "that - no saving, restoring or predicting needed.",
        (unsigned)kCompare, kVerifyFirst, kResampleMask + 1);
    return true;
}

void NewFrame() {
    if (!g_installed) return;
    // Bumping is the whole invalidation. An entry from an earlier frame does not
    // match and is overwritten in place, so nothing has to be cleared.
    if (++g_gen == 0) g_gen = 1;
}

void LogStats() {
    if (!Config::g_settings.OptM2SortKey) return;
    if (!g_installed) { Log("[M2SortKey] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[M2SortKey] installed but never called"); return; }

    unsigned long looked = g_hits + g_misses;
    Log("[M2SortKey] %lu comparisons%s, %lu verified against the client. Key "
        "lookups: %lu from cache (%.1f%%), %lu derived through the full chain. "
        "Counts are lower bounds.",
        g_calls,
        g_dead ? " - RETIRED on a disagreement"
               : (g_armed ? "" : " - still verifying, the client still answers every one"),
        g_verified, g_hits,
        looked ? 100.0 * (double)g_hits / (double)looked : 0.0,
        g_misses);
}

void Shutdown() {
    if (g_installed) MH_DisableHook((void*)kCompare);
}

}  // namespace M2SortKey
