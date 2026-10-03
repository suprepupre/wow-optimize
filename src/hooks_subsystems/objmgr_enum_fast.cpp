// ============================================================================
// Module: objmgr_enum_fast
// Description: Hoists a loop-invariant out of the object manager's enumerator,
//              and measures what the enumerator actually costs.
// ============================================================================
// sub_4D4B30 is the client's enumerate-all-objects call, reached from
// twenty-five places - targeting, nameplates, aggro, spell visuals, anything
// that asks "what is around me". Its loop is:
//
//     loc_4D4B64:
//       test bl, 1                 ; the tagged end-of-list sentinel
//       jnz  done
//       test ebx, ebx
//       jz   done
//       mov  ecx, [ebx+34h]        ; guid high
//       mov  eax, [ebx+30h]        ; guid low
//       push edi / push ecx / push eax
//       call [ebp+arg_0]           ; the caller's callback, once per object
//       test eax, eax
//       jz   stopped
//       mov  eax, [esi+8]          ; the object manager, out of the TLS block
//       add  eax, 0A4h
//       mov  eax, [eax]            ; the link offset
//       add  eax, ebx
//       mov  ebx, [eax+4]          ; node = node->next
//       jmp  loc_4D4B64
//
// The last four instructions rebuild, for every node, a value that is fixed for
// the whole enumeration. Two of them are dependent loads, and they sit in front
// of the load that fetches the next pointer, so the pointer chase is three
// dependent loads deep per node instead of one. That is the same defect
// objmgr_find_fast already removes from the eleven find functions; the walk was
// simply never looked at.
//
// This walks the live list and hoists that. Nothing else changes: the same
// nodes in the same order, the same callback with the same three arguments, the
// same two exits, and the next pointer read after the callback, as the client
// reads it.
// ---------------------------------------------------------------------------
// Why not a flat array, which is the obvious idea
//
// There is already a module in this tree that does it - rcu_obj_mgr.cpp keeps a
// mirrored array of object pointers and serves the enumeration out of that. It
// is off, it has no launcher entry, and it should stay off:
//
//   - It enumerates a snapshot taken earlier. An object freed in between is
//     still dereferenced to read its GUID, and a freed-and-reused heap block
//     passes a range check without faulting, so the callback is handed a
//     plausible GUID belonging to something else. The __except around it never
//     fires, because nothing traps.
//   - Its array holds 2048 entries and the walk simply stops there. A city
//     with more objects than that enumerates short, silently.
//   - An object spawned since the snapshot is invisible until the next one.
//
// And the arithmetic does not favour it anyway. The per-object cost of this
// loop is dominated by an indirect call into the caller's callback, which no
// change of container removes, and which a hardware prefetcher cannot see
// across. Flattening the list would leave that call exactly where it is.
// ---------------------------------------------------------------------------
// What this measures, which is the part nobody has
//
// Whether any of this is worth more work is an open question, and the answer is
// a count: how often the enumeration runs, how many objects it visits, and how
// much of a frame that is. So the report gives calls per frame, objects per
// call, the largest single walk, and how often a callback stopped it early. If
// it turns out to be a handful of calls over a few dozen objects then the flat
// array idea is dead for one log line, and so is this hoist.
// ---------------------------------------------------------------------------
// Verification
//
// The hoist is only valid if the link offset really is constant across the
// walk, so while checking, every node recomputes it the client's way and
// compares. A single disagreement retires the module for the session and hands
// every later call to the client. The nodes themselves need no comparison: this
// reads the same fields of the same live list in the same order, and running
// the enumeration twice to compare would call the caller's callback twice per
// object, which is not something a verification may do.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <intrin.h>

#include "objmgr_enum_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace ObjMgrEnumFast {

namespace {

constexpr uintptr_t kEnum     = 0x004D4B30;
constexpr uintptr_t kTlsIndex = 0x00D439BC;

// On the object manager, read out of the loop above.
constexpr unsigned kOM_head       = 0xAC;   // [+0A8h] then [+4]
constexpr unsigned kOM_linkOffset = 0xA4;

typedef int (__cdecl* EnumCb_t)(uint32_t guidLow, uint32_t guidHigh, int ctx);
typedef int (__cdecl* Enum_t)(EnumCb_t cb, int ctx);
Enum_t orig_Enum = nullptr;

constexpr long kCheckNodes = 200000;   // link offsets compared before trusting it

bool g_installed = false;
bool g_dead      = false;
bool g_abSubject = false;

// Plain 32-bit, main thread only, and lower bounds if that ever stops being
// true. Every one is incremented before any early return that could stop it.
unsigned long g_calls      = 0;
unsigned long g_deferred   = 0;   // handed to the client: no manager, or retired
unsigned long g_stopped    = 0;   // a callback ended the walk early
unsigned long g_stood      = 0;   // the A/B off stint ran the client's walk
unsigned long g_maxNodes   = 0;
unsigned long g_checked    = 0;
unsigned long g_frames     = 0;

// Objects visited. Hundreds a call and many calls a frame puts this past 32
// bits in a long session, so the wrap is counted and recombined as a double.
unsigned long g_nodes      = 0;
unsigned long g_nodeWraps  = 0;

void AddNodes(unsigned long n) {
    const unsigned long before = g_nodes;
    g_nodes = before + n;
    if (g_nodes < before) ++g_nodeWraps;
}

bool Readable(uintptr_t p) { return p >= 0x10000 && p < 0xFFE00000; }

// The client's own way in: TlsGetValue inlined, then the manager at +8.
uintptr_t ObjectManager() {
    __try {
        // fs:[0x2C] is TEB.ThreadLocalStoragePointer and it already IS the
        // array of per-module blocks - the client does `mov ecx, fs:2Ch` and
        // indexes straight off it. Dereferencing once more reads the array's
        // first entry and then indexes THAT, which is what this did: every call
        // fell through to the client and the report said so plainly, 5888283
        // calls and 0 objects visited.
        uintptr_t* const* tls = (uintptr_t* const*)__readfsdword(0x2C);
        if (!tls) return 0;
        const uint32_t idx = *(const uint32_t*)kTlsIndex;
        const uintptr_t* block = tls[idx];
        if (!block) return 0;
        return block[2];              // [esi+8]
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

int __cdecl HoistedEnum(EnumCb_t cb, int ctx);

// Both halves of the A/B run go through the same bracket, so the harness files
// an ON sample against an OFF one and the report is this walk measured against
// the client's own. A subject without this pair measures nothing at all.
int __cdecl Hooked_Enum(EnumCb_t cb, int ctx) {
    ++g_calls;

    if (g_dead || !cb) { ++g_deferred; return orig_Enum(cb, ctx); }

    const unsigned long long t = AbTest::TickIn();
    int r;
    if (g_abSubject && AbTest::StandAside()) {
        ++g_stood;
        r = orig_Enum(cb, ctx);
    } else {
        r = HoistedEnum(cb, ctx);
    }
    AbTest::TickOut(t);
    return r;
}

int __cdecl HoistedEnum(EnumCb_t cb, int ctx) {

    const uintptr_t om = ObjectManager();
    if (!om || !Readable(om)) { ++g_deferred; return orig_Enum(cb, ctx); }

    uintptr_t node;
    uintptr_t linkOffset;
    __try {
        node       = *(const uintptr_t*)(om + kOM_head);
        linkOffset = *(const uintptr_t*)(om + kOM_linkOffset);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ++g_deferred;
        return orig_Enum(cb, ctx);
    }

    unsigned long visited = 0;
    int result = 1;

    // The client's two end tests, in its order: the tagged sentinel first.
    while ((node & 1) == 0 && node != 0) {
        if (!Readable(node)) { g_dead = true; break; }

        uint32_t lo, hi;
        bool linkStillMatches = true;
        __try {
            lo = *(const uint32_t*)(node + 0x30);
            hi = *(const uint32_t*)(node + 0x34);
            // While checking, rebuild the offset the way the client does and
            // make sure hoisting it was allowed.
            if (g_checked < (unsigned long)kCheckNodes) {
                const uintptr_t om2 = ObjectManager();
                const uintptr_t again = om2 ? *(const uintptr_t*)(om2 + kOM_linkOffset)
                                            : linkOffset;
                if (again != linkOffset) linkStillMatches = false;
                ++g_checked;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_dead = true;
            break;
        }

        if (!linkStillMatches) {
            g_dead = true;
            Log("[ObjMgrEnum] Retired: the link offset changed inside one "
                "enumeration, so hoisting it out of the loop is not valid on "
                "this client. Every later call goes to the client's own walk.");
            return orig_Enum(cb, ctx);
        }

        ++visited;
        if (!cb(lo, hi, ctx)) { result = 0; ++g_stopped; break; }

        // The next pointer is read after the callback, as the client reads it: the
        // callback is game code that can remove this object or add one after it,
        // and a pointer fetched before the call would then name a node that is no
        // longer the next one, or one that has been freed.
        uintptr_t next;
        __try {
            next = *(const uintptr_t*)(node + linkOffset + 4);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_dead = true;
            break;
        }
        node = next;
    }

    AddNodes(visited);
    if (visited > g_maxNodes) g_maxNodes = visited;

    if (g_dead) {
        // Something was unreadable part way through. The client's walk would
        // have faulted too, so this does not re-run it - re-running would call
        // the callback again for every object already handed over.
        Log("[ObjMgrEnum] Retired: a node was unreadable %lu objects into a "
            "walk. The callback has already seen those, so this call is not "
            "restarted; every later one goes to the client.", visited);
        return result;
    }
    return result;
}

}  // namespace

void OnFrame() { ++g_frames; }

bool Init() {
    if (!Config::g_settings.OptObjMgrEnumFast) return true;

    if (!WowOpt_ClientPatchAllowed((const void*)kEnum)) {
        Log("[ObjMgrEnum] Client patches disallowed by policy - not hooking");
        return false;
    }

    static const unsigned char kExp_Enum[8] = { 0x55, 0x8B, 0xEC, 0xA1, 0xBC, 0x39, 0xD4, 0x00 };
    if (IsBadReadPtr((const void*)kEnum, 8) || memcmp((const void*)kEnum, kExp_Enum, 8) != 0) {
        Log("[ObjMgrEnum] 0x%08X bad prologue or unreadable - not installing", (unsigned)kEnum);
        return false;
    }

    if (Config::g_settings.OptRcuObjMgr) {
        Log("[ObjMgrEnum] NOT active: RcuObjMgr is on and hooks the same "
            "address. That one serves the enumeration out of a snapshot; this "
            "one walks the live list. They cannot both have 0x%08X.",
            (unsigned)kEnum);
        return false;
    }
    if (WineSafe_CreateHook((void*)kEnum, (void*)&Hooked_Enum,
                            (void**)&orig_Enum) != MH_OK) {
        Log("[ObjMgrEnum] NOT active: could not hook 0x%08X.", (unsigned)kEnum);
        return false;
    }
    if (WO_EnableHook((void*)kEnum) != MH_OK) {
        Log("[ObjMgrEnum] NOT active: could not enable the hook at 0x%08X.",
            (unsigned)kEnum);
        return false;
    }
    g_installed = true;
    g_abSubject = AbTest::IsSubject("ObjMgrEnumFast", &g_abSubject);

    Log("[ObjMgrEnum] ACTIVE on sub_4D4B30, the enumerate-all-objects call that "
        "twenty-five sites reach. Its loop rebuilds the object manager pointer "
        "and the link offset for every node, two dependent loads in front of "
        "the load that fetches the next pointer, for a value that is fixed for "
        "the whole walk. This walks the same live list in the same order and "
        "hoists that out. The first %ld nodes recompute the offset the client's "
        "way and compare, because the hoist is only valid while it really is "
        "constant.", kCheckNodes);
    Log("[ObjMgrEnum]   it also counts what the walk costs - calls a frame, "
        "objects a call, the longest one - which is the number that decides "
        "whether anything larger here is worth building.");
    return true;
}

void Shutdown() {
    if (g_installed) MH_DisableHook((void*)kEnum);
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptObjMgrEnumFast) return;
    if (!g_installed) {
        Log("[ObjMgrEnum] switched on but not installed, so nothing here was "
            "measured.");
        return;
    }
    if (g_calls == 0) {
        Log("[ObjMgrEnum] installed, and the object enumeration has not run "
            "yet. This is measured and zero, not unmeasured.");
        return;
    }

    const double nodes = (double)g_nodes + (double)g_nodeWraps * 4294967296.0;
    Log("[ObjMgrEnum] %lu calls over %lu frames (%.1f a frame), %.0f objects "
        "visited (%.1f a call), longest walk %lu. %s",
        g_calls, g_frames,
        g_frames ? (double)g_calls / (double)g_frames : 0.0,
        nodes, (double)nodes / (double)g_calls, g_maxNodes,
        g_dead ? "RETIRED - the client walks it now." : "Active.");
    Log("[ObjMgrEnum]   %lu link offsets recomputed and compared, %lu walks "
        "ended early by their callback, %lu calls handed to the client.",
        g_checked, g_stopped, g_deferred);
    if (g_stood > 0)
        Log("[ObjMgrEnum]   %lu walks ran the client's own loop for the A/B off "
            "stint, and both halves are timed with rdtsc, so the harness "
            "compares ticks a walk one way against the other.", g_stood);
    Log("[ObjMgrEnum]   No frame-time gain is claimed. These are the counts "
        "that say whether the walk is worth anything, not a saving.");
}

}  // namespace ObjMgrEnumFast
