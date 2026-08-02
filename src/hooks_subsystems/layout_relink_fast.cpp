// ============================================================================
// Module: layout_relink_fast.cpp
//
// sub_489710 is the single largest executing entry in a 28-minute gameplay
// profile: 590 samples, 9.06% of all time the main thread spent running. Nothing
// else in that profile is within half of it. It had been named
// Node_FindOwnerAndRelink in the profiler's symbol table with a note saying it
// was a candidate for an index rather than a search, and left alone.
//
// It is the UI layout dependency sort. The RTTI in the cluster gives it away -
// CLayoutFrame::FRAMENODE - and sub_48A260 is CLayoutFrame::SetPoint, which
// writes an anchor into `frame + 12 + 4*pointIndex` and creates a CFramePoint
// holding its target at +8. Nine slots, because a frame has nine anchor points.
//
// What sub_489710 does with that:
//
//     if (this is already linked) return;
//     for (node in the global layout list at dword_AC1020) {
//         for (i = 0; i < 9; i++) {
//             p = node->anchor[i];
//             if (p && !(p->flags & 0x800) && p->target == this) { found = node; }
//         }
//         if (found) break;
//     }
//     unlink this; insert it after `found`, or at the head of off_AC101C if none;
//     this->retry = 6;
//
// So for every relink it walks every layout frame in the game and dereferences
// up to nine anchor pointers each, looking for one that points back. With a
// large addon suite that is thousands of frames and tens of thousands of
// scattered pointer loads. The profiler's samples land on the load itself
// (0x489763, `test eax, eax` immediately after `mov eax, [edx-4]`), which is what
// a walk dominated by cache misses looks like.
//
// The search is redundant. The client already maintains the exact reverse
// index the search is reconstructing:
//
//   sub_489C30(target, dependent, 1 << pointIndex)  registers "dependent anchors
//                                                    to target", allocating a
//                                                    FRAMENODE if needed
//   sub_489D70(target, dependent, 1 << pointIndex)  removes those bits, freeing
//                                                    the record at zero
//
// The list head is at frame+0x38, and it is empty when the value is null or has
// its low bit set (the sentinel encoding used throughout this cluster). The
// registrar has exactly two callers and the de-registrar three, all inside
// SetPoint and the frame destructor, so there is no path that sets an anchor
// without registering it. That makes the implication exact:
//
//     frame+0x38 is empty  =>  no CFramePoint anywhere targets this frame
//                          =>  the scan cannot find a match
//
// which is the case that costs the most, because finding nothing means having
// walked everything. A leaf frame that nothing anchors to - most of them - pays
// the full walk every single time.
//
// The shortcut deliberately does not reimplement any of the list surgery. The
// original's not-found path is exactly what should happen, so instead of
// rewriting it, dword_AC1020 is set to zero for the duration of the call: the
// loop then has nothing to iterate and the original falls into its own not-found
// path immediately. Same instructions, same writes, same result - just without
// the walk. sub_489710 makes no calls at all, so nothing can observe the global
// in that window.
//
// Correctness is not asserted. For the first several thousand shortcuts this
// runs the client's own scan read-only first and confirms it finds nothing. One
// disagreement disables the module permanently and says so in the log.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

#include "layout_relink_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "crash_dumper.h"

extern "C" void Log(const char* fmt, ...);
extern DWORD g_mainThreadId;

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace LayoutRelinkFast {

static constexpr uintptr_t ADDR_Relink     = 0x00489710;  // CLayoutFrame relink
static constexpr uintptr_t ADDR_NodeList   = 0x00AC1020;  // head of the layout list
static constexpr uintptr_t ADDR_LinkOffset = 0x00AC1018;  // link offset within a frame

// Head of the frame's FRAMENODE list - "who anchors to me". Read at [esi+38h] in
// both sub_489C30 and sub_489D70.
static constexpr uintptr_t OFF_DependentList = 0x38;

// Anchor slots, and the flag the scan rejects.
static constexpr uintptr_t OFF_Anchors    = 0x0C;
static constexpr int       NUM_ANCHORS    = 9;
static constexpr uint32_t  ANCHOR_SKIP    = 0x800;
static constexpr uintptr_t OFF_PointFlags = 0x0C;
static constexpr uintptr_t OFF_PointTarget= 0x08;

typedef void* (__fastcall* Relink_fn)(void* self, void* edx);
static Relink_fn orig_Relink = nullptr;

static bool g_active    = false;
static bool g_abandoned = false;

static volatile LONG g_calls     = 0;
static volatile LONG g_shortcuts = 0;
static volatile LONG g_scanned   = 0;
static volatile LONG g_verified  = 0;

// Enough to cover a full UI load plus a zone change, which is where the shapes
// this could get wrong would appear.
static constexpr LONG VERIFY_CALLS = 8192;

// The list uses a tagged sentinel: an odd value is the end marker, not a pointer.
static inline bool ListEmpty(uint32_t v) {
    return (v & 1u) != 0u || v == 0u;
}

static inline bool Readable(uintptr_t p) {
    return p >= 0x10000 && p < 0xFFE00000;
}

// The client's own scan, read-only and answering only "is there a match". Used
// to check the shortcut against the thing it is skipping.
static bool ClientScanFindsAMatch(uint32_t self) {
    uint32_t linkOff = *(uint32_t*)ADDR_LinkOffset;
    uint32_t node    = *(uint32_t*)ADDR_NodeList;
    if (ListEmpty(node)) node = 0;

    int guard = 0;
    while (!ListEmpty(node)) {
        if (++guard > 100000) return true;   // malformed list: never claim "none"
        if (!Readable(node)) return true;

        for (int i = 0; i < NUM_ANCHORS; ++i) {
            uint32_t p = *(uint32_t*)(node + OFF_Anchors + 4u * (uint32_t)i);
            if (!p || !Readable(p)) continue;
            if ((*(uint32_t*)(p + OFF_PointFlags) & ANCHOR_SKIP) != 0) continue;
            if (*(uint32_t*)(p + OFF_PointTarget) == self) return true;
        }

        uint32_t nextAddr = linkOff + node + 4u;
        if (!Readable(nextAddr)) return true;
        node = *(uint32_t*)nextAddr;
    }
    return false;
}

static void* __fastcall Hooked_Relink(void* self, void* edx) {
    if (g_abandoned || !self || GetCurrentThreadId() != g_mainThreadId)
        return orig_Relink(self, edx);

    InterlockedIncrement(&g_calls);

    __try {
        uint32_t frame = (uint32_t)(uintptr_t)self;
        uint32_t head  = *(uint32_t*)((uintptr_t)frame + OFF_DependentList);

        if (!ListEmpty(head)) {
            InterlockedIncrement(&g_scanned);
            return orig_Relink(self, edx);   // something does anchor here
        }

        // Nothing anchors to this frame, so the walk is guaranteed fruitless.
        // Prove that against the client's own scan for the first few thousand.
        if (InterlockedIncrement(&g_verified) <= VERIFY_CALLS) {
            if (ClientScanFindsAMatch(frame)) {
                g_abandoned = true;
                Log("[LayoutRelink] The client's scan found an anchor to a frame whose "
                    "dependent list is empty - the assumption is wrong, handing every "
                    "call back to the original");
                return orig_Relink(self, edx);
            }
            if (g_verified == VERIFY_CALLS) {
                Log("[LayoutRelink] Agreed with the client's own scan on %ld consecutive "
                    "real calls - skipping the walk from here", (long)VERIFY_CALLS);
            }
        }

        // Empty the node list for the duration of the call. The original's loop
        // then has nothing to iterate and it takes its own not-found path, which
        // is precisely the outcome the walk would have produced.
        uint32_t* pList = (uint32_t*)ADDR_NodeList;
        uint32_t  saved = *pList;
        *pList = 0;
        void* r = orig_Relink(self, edx);
        *pList = saved;

        InterlockedIncrement(&g_shortcuts);
        return r;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // A malformed frame must cost the shortcut, not the session. The global
        // is restored on every path above before anything can fault, because the
        // only call between the two writes is the original itself.
    }

    return orig_Relink(self, edx);
}

bool Init() {
    if (!Config::g_settings.OptLayoutRelinkFast) {
        Log("[LayoutRelink] DISABLED via configuration");
        return true;
    }

    unsigned char* p = (unsigned char*)ADDR_Relink;
    // sub_489710 starts `test ecx, ecx` (85 C9), not a standard frame prologue.
    if (p[0] != 0x85 || p[1] != 0xC9) {
        Log("[LayoutRelink] Unexpected prologue at 0x%08X (%02X %02X) - not hooking",
            (unsigned)ADDR_Relink, p[0], p[1]);
        return false;
    }

    if (WineSafe_CreateHook((void*)ADDR_Relink, (void*)Hooked_Relink,
                            (void**)&orig_Relink) != MH_OK ||
        WO_EnableHook((void*)ADDR_Relink) != MH_OK) {
        Log("[LayoutRelink] Hook FAILED at 0x%08X", (unsigned)ADDR_Relink);
        return false;
    }

    g_active = true;
    CrashDumper::RegisterFeature("LayoutRelinkFast");
    Log("[LayoutRelink] ACTIVE - skipping the layout dependency walk for frames "
        "nothing anchors to (0x%08X, 9.06%% of executing time in a tester profile)",
        (unsigned)ADDR_Relink);
    return true;
}

void LogStats() {
    if (!g_active) return;
    LONG calls = g_calls;
    if (calls == 0) return;

    Log("[LayoutRelink] %ld relinks: %ld skipped the walk (%.1f%%), %ld had to scan%s",
        calls, g_shortcuts, (double)g_shortcuts * 100.0 / (double)calls, g_scanned,
        g_abandoned ? " - ABANDONED, running the original" : "");
}

void Shutdown() {
    if (!g_active) return;
    g_active = false;
    MH_DisableHook((void*)ADDR_Relink);
}

} // namespace LayoutRelinkFast
