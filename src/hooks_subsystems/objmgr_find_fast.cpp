// ============================================================================
// Module: objmgr_find_fast.cpp
// Description: Hoists the loop invariant out of the object manager's GUID find.
// Safety & Threading: Same thread as the function it replaces (main).
// ============================================================================
//
// sub_4D4BB0 looks an object up by hash and GUID. It was 2.22% of executing
// time in a CPU-bound tester profile, and it is already a hash table, so there
// is no algorithm to improve. The cost is in how the chain is walked.
//
// Transcribed from the disassembly at 0x4D4BB0:
//
//     mask    = [ecx+24h]                  ; -1 means the table is empty
//     buckets = [ecx+1Ch]
//     idx     = mask & hash
//     node    = *(buckets + 12*idx + 8)
//     loop:
//       if (node & 1) or node == 0: fail
//       if ([node+18h] == hash && [node+30h] == guid[0] && [node+34h] == guid[1])
//           return node
//       ebx = [ecx+1Ch]                    ; buckets, again
//       edx = hash & [ecx+24h]             ; mask, again
//       edx = *(ebx + 12*edx)              ; the bucket's link offset
//       node = *(node + edx + 4)
//       goto loop
//
// The last four lines re-derive, on every step of the chain, a value that
// depends only on `this` and `hash` - both fixed for the whole call. That is
// two loads of the table header, the index arithmetic, and a third load of the
// link offset, per node visited, to compute a constant.
//
// This computes it once. Everything else is the same sequence of reads in the
// same order, including reading the GUID only after the hash matches: doing it
// eagerly would fault on a caller that passes a bad pointer with a hash that
// never hits, which the original tolerates.
//
// And it checks itself. For the first calls of a session it runs both and
// compares the answers; a single disagreement retires the module for the
// session and says so. One call in every 1024 stays checked afterwards.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

#include "objmgr_find_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

namespace ObjMgrFindFast {

namespace {

constexpr uintptr_t kFind = 0x004D4BB0;

// Offsets in the table object, verified against the listing above.
constexpr unsigned kOff_Buckets = 0x1C;
constexpr unsigned kOff_Mask    = 0x24;
// Offsets in a node.
constexpr unsigned kOff_Hash    = 0x18;
constexpr unsigned kOff_GuidLo  = 0x30;
constexpr unsigned kOff_GuidHi  = 0x34;

constexpr long kLearnCalls   = 20000;
constexpr long kResampleMask = 1023;

typedef uint32_t* (__fastcall* Find_fn)(void* self, void* edx, uint32_t hash, uint32_t* guid);
Find_fn orig_Find = nullptr;

// Plain counters. This runs on the main thread and takes millions of calls; a
// lock-prefixed increment here has already cost this project one optimization.
unsigned long g_calls      = 0;
unsigned long g_agreements = 0;
unsigned long g_steps      = 0;   // chain nodes visited, for the report
volatile LONG g_armed      = 0;
volatile LONG g_dead       = 0;

inline uint32_t Rd(uintptr_t p) { return *(volatile uint32_t*)p; }

// The walk, with the invariant hoisted. Returns the node or null.
inline uint32_t* Walk(void* self, uint32_t hash, uint32_t* guid, unsigned* stepsOut) {
    uintptr_t T = (uintptr_t)self;
    uint32_t mask = Rd(T + kOff_Mask);
    if (mask == 0xFFFFFFFFu) return nullptr;

    uint32_t buckets = Rd(T + kOff_Buckets);
    uint32_t idx     = mask & hash;
    uintptr_t bucket = (uintptr_t)buckets + 12u * idx;

    // The whole point: read once, not once per node.
    uint32_t linkOff = Rd(bucket);
    uint32_t node    = Rd(bucket + 8);

    if ((node & 1) || node == 0) node = 0;

    unsigned steps = 0;
    while (node != 0 && (node & 1) == 0) {
        steps++;
        if (Rd(node + kOff_Hash) == hash &&
            Rd(node + kOff_GuidLo) == guid[0] &&
            Rd(node + kOff_GuidHi) == guid[1]) {
            if (stepsOut) *stepsOut = steps;
            return (uint32_t*)node;
        }
        node = Rd(node + linkOff + 4);
    }
    if (stepsOut) *stepsOut = steps;
    return nullptr;
}

void Retire(const char* why) {
    if (InterlockedExchange(&g_dead, 1) == 0) {
        Log("[ObjMgrFind] Disabled for this session: %s. The client's own routine "
            "runs from here on.", why);
    }
}

uint32_t* __fastcall Hooked_Find(void* self, void* edx, uint32_t hash, uint32_t* guid) {
    if (g_dead || !self || !guid) return orig_Find(self, edx, hash, guid);

    unsigned long n = ++g_calls;
    bool verifying = (g_armed == 0) || ((n & kResampleMask) == 0);

    uint32_t* mine;
    unsigned steps = 0;
    __try {
        mine = Walk(self, hash, guid, &steps);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // The original tolerates whatever this was; hand it over rather than
        // guess, and stop trying.
        Retire("the walk faulted");
        return orig_Find(self, edx, hash, guid);
    }
    g_steps += steps;

    if (verifying) {
        uint32_t* theirs = orig_Find(self, edx, hash, guid);
        if (theirs != mine) {
            Log("[ObjMgrFind] Disagreed: hash %08X gave %p here and %p in the "
                "client. The chain walk is not equivalent.",
                hash, (void*)mine, (void*)theirs);
            Retire("a lookup returned a different node than the client's");
            return theirs;
        }
        unsigned long ok = ++g_agreements;
        if (g_armed == 0 && ok >= kLearnCalls) {
            InterlockedExchange(&g_armed, 1);
            Log("[ObjMgrFind] %lu lookups agreed with the client. Taking the "
                "shortcut from here; one call in %d stays checked.",
                ok, (int)(kResampleMask + 1));
        }
        return theirs;
    }

    return mine;
}

bool g_installed = false;

} // namespace

bool Init() {
    if (!Config::g_settings.OptObjMgrFindFast) return true;

    // push ebp / mov ebp, esp / mov eax, [ecx+24h]
    const unsigned char expect[] = { 0x55, 0x8B, 0xEC, 0x8B, 0x41, 0x24 };
    unsigned char* p = (unsigned char*)kFind;
    if (IsBadReadPtr(p, sizeof(expect))) {
        Log("[ObjMgrFind] 0x%08X unreadable - not installing", (unsigned)kFind);
        return false;
    }
    for (size_t i = 0; i < sizeof(expect); i++) {
        if (p[i] != expect[i]) {
            Log("[ObjMgrFind] Prologue at 0x%08X is not the expected sequence - "
                "not installing", (unsigned)kFind);
            return false;
        }
    }

    if (WineSafe_CreateHook((void*)kFind, (void*)Hooked_Find, (void**)&orig_Find) != MH_OK) {
        Log("[ObjMgrFind] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kFind) != MH_OK) {
        Log("[ObjMgrFind] hook created but could not be enabled");
        return false;
    }

    g_installed = true;
    Log("[ObjMgrFind] ACTIVE on sub_4D4BB0 (2.22%% of executing time in a "
        "CPU-bound profile). The chain walk re-read the table header and the "
        "bucket's link offset for every node; it reads them once now. Verifying "
        "against the client for the first %ld calls.", kLearnCalls);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptObjMgrFindFast) return;
    if (!g_installed) { Log("[ObjMgrFind] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[ObjMgrFind] installed but never called"); return; }

    Log("[ObjMgrFind] %lu lookups, %lu verified against the client, %.2f nodes "
        "walked per lookup%s",
        g_calls, g_agreements,
        (double)g_steps / (double)g_calls,
        g_dead ? " - DISABLED" : (g_armed ? "" : " (still verifying)"));
}

} // namespace ObjMgrFindFast
