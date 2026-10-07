// ============================================================================
// Description: Removes luaH_get's x87 round-trip on integer table keys.
// Safety & Threading: Lua thread; the function is a read-only lookup.
// ============================================================================
// sub_85C470 is luaH_get, the generic table lookup, at 0.67% of executing time
// in a tester's uncapped session. It does almost no work itself - it reads the
// key's type tag and hands off to the string lookup, the integer lookup, or the
// general hash walk. The 0.67% is the handing off.
//
// Nearly all of it is on the number path, which is how Lua indexes an array:
//
//     fld   qword ptr [edi]     ; the key
//     fstp  [ebp+var_8]         ; store it to a local
//     fld   [ebp+var_8]         ; and load it straight back
//     fistp [ebp+arg_4]         ; to integer, through memory
//     fild  [ebp+arg_4]         ; and back to double, through memory
//     fcomp qword ptr [edi]     ; is it the same number?
//     fnstsw ax
//     test  ah, 44h
//
// Three memory round-trips and an FPU status-word serialisation to answer
// "is this key an integer". The first pair is not even a conversion - it stores
// the value to a stack slot and reloads it unchanged. SSE2 does the whole thing
// in registers: cvtsd2si, cvtsi2sd, ucomisd, and the flags are already set.
// ---------------------------------------------------------------------------
// The conversion rounds, it does not truncate
//
// `fistp` uses whatever the x87 control word says, and that is round-to-nearest,
// so this is not C's `(int)` cast however the decompiler prints it. For 3.5 it
// produces 4, not 3.
//
// It makes no difference to the answer, and that is worth writing down rather
// than discovering later. Whatever the conversion produces is converted back and
// compared against the original, so only a key that survives the round trip is
// used - and for a value that is already an integer, rounding and truncation
// agree. A non-integer fails the comparison either way and falls to the general
// path. Out of range, both mechanisms yield 0x80000000 and the comparison then
// fails unless the key really was -2^31. A NaN fails it too: the client's parity
// test on C0 and C2 sends an unordered compare to the general path, and C's `==`
// is false for a NaN, which is the same decision.
//
// `_mm_cvtsd_si32` is used anyway, because it rounds the way the instruction it
// replaces rounds. Matching the mechanism costs nothing and removes the question.
// ---------------------------------------------------------------------------
// What is not reimplemented
//
// Only the three cheap decisions: a nil key, a string key, an integer key. The
// general hash walk is left to the client, which redoes the tag check and takes
// its own path - it reaches sub_85BCB0 through registers rather than the stack,
// and copying a __usercall boundary to save a branch on the rare path would be
// trading a real risk for nothing.
// ---------------------------------------------------------------------------
// Verification
//
// luaH_get reads a table and a key and returns a pointer into that table, or the
// shared nil object. It writes nothing. So both versions run and the returned
// pointers are compared - no saving, no restoring, no predicting.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include "lua_hget_dispatch.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"
#include "ab_test.h"
#include "session_verdict.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace LuaHGetDispatch {

namespace {

constexpr uintptr_t kHGet    = 0x0085C470;   // luaH_get
constexpr uintptr_t kGetStr  = 0x0085C430;   // luaH_getstr
constexpr uintptr_t kGetNum  = 0x0085C3A0;   // luaH_getnum
constexpr uintptr_t kNilObj  = 0x00A46F78;   // the shared nil TValue

// WoW's Lua is +4-shifted: the type tag sits at +8 of a 16-byte TValue and the
// value occupies the first eight bytes.
constexpr unsigned kTV_tag = 8;

constexpr uint32_t kTagNil    = 0;
constexpr uint32_t kTagNumber = 3;
constexpr uint32_t kTagString = 4;

// ---- the chain census (off by default) ----
//
// FreezeCatcher on a player with a great many WeakAuras (2026-10-06): in the frames over 100 ms the
// main thread was most often inside luaH_getstr's chain walk at 0x0085C45C (990 of 5094 stall
// events in one 110 minute session, 968 of the samples reached from this hook). A lookup of a
// string key goes to the node its hash selects and follows the chain of nodes that collided
// there, comparing the key's address; a chain of a few nodes costs nothing and a very long one,
// or a short one in memory that is never cached, costs a miss a node. Lua 5.1 hashes a string
// longer than 32 bytes by looking at only every (length>>5)+1th byte, so names that differ only
// in the bytes it skips share one hash and one chain, for ever. Nothing says whether that is
// what is happening. This walks the chain itself, in the client's order, which returns the
// same node, and counts the steps.
constexpr int kChainBuckets = 8;     // 1, 2, 3-4, 5-8, 9-16, 17-64, 65-256, 257+
struct LongTable {
    uintptr_t t;
    unsigned long walks;
    unsigned long steps;
    unsigned long missing;
    unsigned long maxSteps;
    unsigned nodes;
    char      sample[48];
};
constexpr int kLongTables = 8;
bool          g_chainCensus = false;
unsigned long g_chainHist[2][kChainBuckets];       // [0] found, [1] not found
unsigned long g_longWalks = 0, g_longSteps = 0;
LongTable     g_long[kLongTables];

inline int BucketOf(unsigned n) {
    if (n <= 1) return 0;
    if (n == 2) return 1;
    if (n <= 4) return 2;
    if (n <= 8) return 3;
    if (n <= 16) return 4;
    if (n <= 64) return 5;
    if (n <= 256) return 6;
    return 7;
}

__declspec(noinline) void NoteLongWalk(void* t, void* s, unsigned steps, bool found) {
    ++g_longWalks;
    g_longSteps += steps;
    LongTable* slot = nullptr;
    for (int i = 0; i < kLongTables; ++i) {
        if (g_long[i].t == (uintptr_t)t) { slot = &g_long[i]; break; }
        if (!slot && g_long[i].t == 0) slot = &g_long[i];
    }
    if (!slot) {                       // the table with the fewest steps so far gives way
        slot = &g_long[0];
        for (int i = 1; i < kLongTables; ++i) if (g_long[i].steps < slot->steps) slot = &g_long[i];
        if (slot->steps >= steps) return;
        memset(slot, 0, sizeof(*slot));
    }
    if (slot->t == 0) {
        slot->t = (uintptr_t)t;
        slot->nodes = 1u << *(const uint8_t*)((const uint8_t*)t + 11);
    }
    ++slot->walks;
    slot->steps += steps;
    if (!found) ++slot->missing;
    if (steps > slot->maxSteps) {
        slot->maxSteps = steps;
        // The key's name, as far as it fits: length at +16, bytes from +20.
        const uint8_t* str = (const uint8_t*)s;
        unsigned len = *(const uint32_t*)(str + 16);
        if (len > 47) len = 47;
        for (unsigned i = 0; i < len; ++i) {
            const char c = (char)str[20 + i];
            slot->sample[i] = (c >= 32 && c < 127) ? c : '?';
        }
        slot->sample[len] = 0;
    }
}

// sub_85C430 as the client has it: the node the hash picks, then the chain, comparing type and
// address, and the shared nil object when the chain runs out.
inline void* CountedGetStr(void* t, void* s) {
    const uint8_t* tb = (const uint8_t*)t;
    const uint32_t nodeBase = *(const uint32_t*)(tb + 20);
    const uint32_t mask = (1u << tb[11]) - 1u;
    const uint32_t hash = *(const uint32_t*)((const uint8_t*)s + 12);
    uint32_t* n = (uint32_t*)(uintptr_t)(nodeBase + 40u * (hash & mask));
    unsigned steps = 1;
    bool found = true;
    while (n[6] != 4 || n[4] != (uint32_t)(uintptr_t)s) {
        n = (uint32_t*)(uintptr_t)n[8];
        if (!n) { n = (uint32_t*)(uintptr_t)kNilObj; found = false; break; }
        ++steps;
    }
    ++g_chainHist[found ? 0 : 1][BucketOf(steps)];
    if (steps > 16) NoteLongWalk(t, s, steps, found);
    return n;
}

typedef void* (__cdecl* hget_fn)(void* t, const void* key);
typedef void* (__cdecl* getstr_fn)(void* t, void* str);
typedef void* (__cdecl* getnum_fn)(void* t, int k);

hget_fn orig_HGet = nullptr;

bool g_installed = false;
bool g_armed     = false;
// Set at init when the A/B harness names this module, so the hot path
// tests a plain bool instead of calling out on every invocation.
bool g_abSubject = false;
bool g_dead      = false;

// Plain 32-bit on a path the VM takes for every table read. Lower bounds, and
// the report says so.
unsigned long g_calls    = 0;
unsigned long g_verified = 0;
unsigned long g_number   = 0;
unsigned long g_string   = 0;
unsigned long g_general  = 0;

constexpr unsigned long kVerifyFirst  = 30000;
constexpr unsigned long kResampleMask = 8191;

inline void* Evaluate(void* t, const void* key) {
    const uint8_t* k = (const uint8_t*)key;
    uint32_t tag = *(const uint32_t*)(k + kTV_tag);

    if (tag == kTagNil) return (void*)kNilObj;

    if (tag == kTagString) {
        void* s;
        memcpy(&s, k, sizeof(s));
        g_string++;
        if (g_chainCensus) return CountedGetStr(t, s);
        return ((getstr_fn)kGetStr)(t, s);
    }

    if (tag == kTagNumber) {
        double d;
        memcpy(&d, k, sizeof(d));
        __m128d v = _mm_set_sd(d);
        int      i = _mm_cvtsd_si32(v);          // rounds, like fistp does
        if (_mm_comieq_sd(_mm_cvtsi32_sd(v, i), v)) {
            g_number++;
            return ((getnum_fn)kGetNum)(t, i);
        }
    }

    // Everything else, and a number that is not an integer: the client's own
    // path, which reaches its hash helper through registers.
    g_general++;
    return orig_HGet(t, key);
}

}  // namespace

// Faults the guard caught, while verifying or after. The guard's fallback is
// the client's own lookup, which reads the same table and key, so a fault here
// is one the fallback would take too; the armed path therefore runs without an
// exception frame once kVerifyFirst lookups have run guarded and this is still
// zero. If it ever is not, every lookup stays guarded.
static unsigned long g_caught = 0;

static __declspec(noinline) void* HGetGuarded(void* t, const void* key) {
    __try {
        return Evaluate(t, key);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ++g_caught;
        return orig_HGet(t, key);
    }
}

static __declspec(noinline) void* HGetVerify(void* t, const void* key) {
    {
        void* mine;
        __try {
            mine = Evaluate(t, key);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ++g_caught;
            return orig_HGet(t, key);
        }
        void* theirs = orig_HGet(t, key);
        g_verified++;

        if (mine != theirs) {
            g_dead = true;
            Verdict::Add(Verdict::Bad,
                         "LuaHGetDispatch disagreed with the client and retired itself for "
                         "this session");
            Log("[LuaHGet] DISAGREED with the client after %lu lookups - retired "
                "for this session, every lookup now goes to the client's own "
                "code. It returned %p and this returned %p.",
                g_verified, theirs, mine);
            return theirs;
        }
        if (!g_armed && g_verified >= kVerifyFirst) {
            g_armed = true;
            Log("[LuaHGet] armed: %lu lookups returned the same slot the client "
                "did. Now answering directly and rechecking one in %lu.",
                g_verified, kResampleMask + 1);
        }
        return theirs;
    }
}

void* __cdecl Hooked_HGetBody(void* t, const void* key) {
    g_calls++;
    if (g_dead || !t || !key) return orig_HGet(t, key);
    if (!g_armed || (g_calls & kResampleMask) == 0) return HGetVerify(t, key);
    if (g_caught) return HGetGuarded(t, key);
    return Evaluate(t, key);
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
void* __cdecl Hooked_HGet(void* t, const void* key) {
    if (!g_abSubject) return Hooked_HGetBody(t, key);
    // Named abTick, not t: the parameter of this function is already t.
    unsigned long long abTick = AbTest::TickIn();
    void* r = AbTest::StandAside() ? orig_HGet(t, key)
                                   : Hooked_HGetBody(t, key);
    AbTest::TickOut(abTick);
    return r;
}

bool Init() {
    if (!Config::g_settings.OptLuaHGetDispatch) return true;

    if (IsBadReadPtr((void*)kHGet, 16) || IsBadReadPtr((void*)kGetStr, 8) ||
        IsBadReadPtr((void*)kGetNum, 8) || IsBadReadPtr((void*)kNilObj, 16)) {
        Log("[LuaHGet] 0x%08X unreadable - not installing", (unsigned)kHGet);
        return false;
    }
    // push ebp / mov ebp, esp / sub esp, 8
    const unsigned char* p = (const unsigned char*)kHGet;
    if (p[0] != 0x55 || p[1] != 0x8B || p[2] != 0xEC || p[3] != 0x83) {
        Log("[LuaHGet] 0x%08X does not start with the prologue this was read from "
            "(%02X %02X %02X %02X) - not installing",
            (unsigned)kHGet, p[0], p[1], p[2], p[3]);
        return false;
    }
    if (WineSafe_CreateHook((void*)kHGet, (void*)Hooked_HGet, (void**)&orig_HGet) != MH_OK) {
        Log("[LuaHGet] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kHGet) != MH_OK) {
        Log("[LuaHGet] hook created but could not be enabled");
        return false;
    }

    g_chainCensus = Config::g_settings.OptLuaChainCensus;
    if (g_chainCensus)
        Log("[LuaHGet] chain census ON: string lookups walk their chain here, in the client's order, and "
            "count the nodes visited. Costs a little on every table read; a measurement for a session.");
    g_abSubject = AbTest::IsSubject("LuaHGetDispatch", &g_abSubject);
    if (g_abSubject) {
        Log("[LuaHGet] under A/B test: it alternates on and off in stints "
            "and AbTest reports the frame times either way. The correctness "
            "checks are unaffected and still retire it on a disagreement.");
    }

    g_installed = true;
    SamplingProfiler::RegisterSelfSymbol("LuaHGet_Dispatch", (const void*)&Hooked_HGet);
    Log("[LuaHGet] ACTIVE on luaH_get (sub_85C470 @ 0x%08X), 0.67%% of executing "
        "time in an uncapped tester session. It does almost no work itself; the "
        "cost is deciding where to hand off. Answering \"is this key an integer\" "
        "takes three memory round-trips and an FPU status-word serialisation "
        "there - and the first pair is not a conversion at all, it stores the key "
        "to a stack slot and reloads it unchanged. SSE2 does it in registers. The "
        "conversion rounds rather than truncates, which is what the instruction "
        "it replaces does and makes no difference to the answer either way. The "
        "general hash walk is left to the client. Read-only, so both answers are "
        "compared for the first %lu lookups and one in %lu after.",
        (unsigned)kHGet, kVerifyFirst, kResampleMask + 1);
    return true;
}

static void LogChains();

void LogStats() {
    if (!Config::g_settings.OptLuaHGetDispatch) return;
    if (!g_installed) { Log("[LuaHGet] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[LuaHGet] installed but never called"); return; }
    Log("[LuaHGet]   exception guard: %lu fault(s) caught; the armed path runs %s.",
        g_caught, !g_armed ? "guarded, still verifying"
                  : (g_caught ? "guarded, because the guard has caught something"
                              : "without an exception frame"));

    LogChains();
    Log("[LuaHGet] %lu lookups%s: %lu integer keys, %lu string keys, %lu left to "
        "the client's general path, %lu verified against it. Counts are lower "
        "bounds.",
        g_calls,
        g_dead ? " - RETIRED on a disagreement"
               : (g_armed ? "" : " - still verifying, the client still answers every one"),
        g_number, g_string, g_general, g_verified);
}

static void LogChains() {
    if (!g_chainCensus) return;
    static const char* const name[kChainBuckets] = { "1", "2", "3-4", "5-8", "9-16", "17-64", "65-256", "257+" };
    unsigned long long total = 0;
    for (int f = 0; f < 2; ++f) for (int b = 0; b < kChainBuckets; ++b) total += g_chainHist[f][b];
    if (!total) { Log("[LuaHGet] chain census: no string lookup seen yet."); return; }
    char line[400]; int n = 0;
    for (int b = 0; b < kChainBuckets; ++b)
        n += snprintf(line + n, sizeof(line) - n, " %s:%lu/%lu", name[b], g_chainHist[0][b], g_chainHist[1][b]);
    Log("[LuaHGet] chain census, %llu string lookups, nodes visited as found/missing:%s. Plain counters.",
        total, line);
    Log("[LuaHGet]   %lu lookup(s) walked more than 16 nodes, %lu nodes in all (%.2f%% of lookups).",
        g_longWalks, g_longSteps, 100.0 * (double)g_longWalks / (double)total);
    for (int i = 0; i < kLongTables; ++i) {
        const LongTable& L = g_long[i];
        if (!L.t) continue;
        Log("[LuaHGet]   table 0x%08X, %u nodes: %lu long walk(s), %lu nodes in them, longest %lu, %lu of the "
            "walks found nothing; the longest was for \"%s\"",
            (unsigned)L.t, L.nodes, L.walks, L.steps, L.maxSteps, L.missing, L.sample);
    }
}

void Shutdown() {
    if (g_installed) MH_DisableHook((void*)kHGet);
}

}  // namespace LuaHGetDispatch
