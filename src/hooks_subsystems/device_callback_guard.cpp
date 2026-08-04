// ============================================================================
// Module: device_callback_guard
//
// Stops the client calling a null function pointer while it walks its device
// callback list.
//
// The crash, reported independently by prince and by nobus (who reproduced it
// swapping warrior stances) and consistent with a third tester's alt-tab
// crashes:
//
//     0xC0000005 ACCESS_VIOLATION at 0x00000000, EIP=0, EAX=EBX=0
//     [ESP+0x00] = 0x006A2B69   (WoW.exe+0x2A2B69)
//     [ESP+0x3C] = 0x00690160   (WoW.exe+0x290160)
//     CRASH MODULE: unknown (base=0x00000000 offset=0x00000000)
//
// sub_690150 -> sub_6A2AA0. sub_690150 is device teardown: it releases five
// objects through their vtable +8 and memsets a 0x2D8 block to 0xFF. sub_6A2AA0
// is the part that walks a list of registered callbacks and tells each one the
// device is going away.
//
// The disassembly of the loop, with every offset used below:
//
//     6a2aaa   mov eax, [edi+290Ch]      ; list head
//     6a2ab2   test al, 1                ; low bit tags the end
//     6a2abc   jz  done                  ; ...as does zero
//     6a2ad0   cmp [esi+38h], ebx        ; node skipped entirely if +0x38 is 0
//     6a2ad9   cmp [ebp+arg_0], ebx
//     6a2ade   test byte ptr [esi+2Ch], 80h
//     6a2b10   cmp [esi+5Bh], bl         ; "already done" byte
//     6a2b21   mov ecx, [eax] / mov edx, [ecx+8] / push eax / call edx
//     6a2b2c   call nullsub_4            ; retn 4, does nothing
//     6a2b40   mov [esi+38h], eax        ; eax = [edi+3B58h]
//     6a2b43   mov byte ptr [esi+5Bh], 1
//     6a2b47   call sub_6848A0
//     6a2b5e   mov eax, [esi+34h]        ; the callback
//     6a2b67   call eax                  ; <-- EIP=0 happens here
//     6a2b6c   mov eax, [esi+44h]        ; next
//
// [esi+34h] is a function pointer stored directly in the node. The client null
// checks [esi+38h] twice and never checks [esi+34h] at all, so a node whose
// callback slot is null takes the whole process down.
//
// What this module does, and deliberately does not do:
//
// On every call it walks the list read-only first, applying the client's own
// two visit conditions, and looks for a node that will be reached with a null
// callback. In every healthy session it finds none and hands straight over to
// the original, so the normal path is one short pointer walk and nothing else.
// The list is walked on device loss and teardown, not per frame.
//
// Only when it finds one - a case where the original is certain to crash - does
// it run the loop itself, transcribed from the instructions above, skipping
// exactly one thing: the call through the null pointer. Every write the client
// makes, it makes, in the same order. The two helpers are handled honestly;
// nullsub_4 is a bare retn 4 so omitting it is exact, and sub_6848A0 is called
// for real.
//
// It does not repair the node. Writing a substitute callback in, or zeroing
// +0x38 so the client skips the node, would both mean writing into a client
// structure on a guess - the mistake that produced the layout-relink crash
// earlier in this project's history. The node is logged in full instead, which
// is the first time anyone has seen what is in one.
// ============================================================================

#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "device_callback_guard.h"

extern "C" void Log(const char* fmt, ...);

namespace DeviceCallbackGuard {

namespace {

constexpr uintptr_t kListWalk      = 0x006A2AA0;
constexpr uintptr_t kRectGlobals   = 0x00C60698;  // four dwords
constexpr uintptr_t kRectInitFlag  = 0x00C606A8;
constexpr uintptr_t kSub6848A0     = 0x006848A0;

// Node offsets, all read off the disassembly above.
constexpr unsigned kNodeRectA     = 0x14;
constexpr unsigned kNodeRectB     = 0x18;
constexpr unsigned kNodeSelect    = 0x2C;  // bit 0x80
constexpr unsigned kNodeCbArg     = 0x30;
constexpr unsigned kNodeCallback  = 0x34;
constexpr unsigned kNodeObject    = 0x38;
constexpr unsigned kNodeObject2   = 0x3C;
constexpr unsigned kNodeNext      = 0x44;
constexpr unsigned kNodeDoneByte  = 0x5B;

// Owner offsets.
constexpr unsigned kOwnerListHead = 0x290C;
constexpr unsigned kOwnerReplace  = 0x3B58;

// A malformed or circular list must not turn a guard into a hang.
constexpr int kMaxNodes = 8192;

// Both targets are __thiscall, emulated as __fastcall with a dummy EDX.
typedef int  (__fastcall* ListWalk_fn)(void* self, void* edx, int a2);
typedef int  (__fastcall* Sub6848A0_fn)(void* self, void* edx, uint32_t node,
                                        void* rect, int flush);
typedef void (__stdcall*  Release_fn)(uint32_t obj);
typedef void (__cdecl*    Callback_fn)(int what, uint32_t a, uint32_t b,
                                       int zero1, int zero2, uint32_t arg,
                                       void* outA, void* outB);

ListWalk_fn orig_ListWalk = nullptr;

volatile LONG g_guardedCalls   = 0;   // times a null callback was found
volatile LONG g_skippedNodes   = 0;   // null callbacks not called
volatile LONG g_faults         = 0;   // times even the replacement faulted
volatile LONG g_totalCalls     = 0;

inline uint32_t RdU32(uintptr_t p) { return *(volatile uint32_t*)p; }
inline uint8_t  RdU8 (uintptr_t p) { return *(volatile uint8_t*)p; }

// True when the client's loop would visit this node. Both conditions verbatim:
//   cmp [esi+38h], ebx / jz next          -> object must be non-zero
//   cmp arg_0, ebx / jnz body             -> a2 non-zero selects every node
//   test byte ptr [esi+2Ch], 80h / jz next
inline bool NodeIsVisited(uint32_t node, int a2) {
    if (RdU32(node + kNodeObject) == 0) return false;
    if (a2 != 0) return true;
    return (RdU8(node + kNodeSelect) & 0x80) != 0;
}

// Read-only. Returns the first node that will be visited with a null callback,
// or 0. Never writes, never calls anything.
uint32_t FindNullCallback(void* self, int a2) {
    uint32_t found = 0;
    __try {
        uint32_t node = RdU32((uintptr_t)self + kOwnerListHead);
        if (node == 0 || (node & 1) != 0) return 0;
        for (int n = 0; n < kMaxNodes; ++n) {
            if (NodeIsVisited(node, a2) && RdU32(node + kNodeCallback) == 0) {
                found = node;
                break;
            }
            uint32_t next = RdU32(node + kNodeNext);
            if (next == 0 || (next & 1) != 0) break;
            node = next;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        found = 0;   // an unreadable list is not ours to interpret
    }
    return found;
}

void DescribeNode(uint32_t node) {
    __try {
        Log("[DeviceCbGuard]   node 0x%08X: callback=0x%08X object=0x%08X "
            "object2=0x%08X select=0x%02X done=%u next=0x%08X",
            node,
            RdU32(node + kNodeCallback), RdU32(node + kNodeObject),
            RdU32(node + kNodeObject2), (unsigned)RdU8(node + kNodeSelect),
            (unsigned)RdU8(node + kNodeDoneByte), RdU32(node + kNodeNext));
        Log("[DeviceCbGuard]   callback args would have been: 0x%08X 0x%08X 0x%08X",
            RdU32(node + kNodeRectA), RdU32(node + kNodeRectB),
            RdU32(node + kNodeCbArg));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[DeviceCbGuard]   node 0x%08X became unreadable while describing it",
            node);
    }
}

// The client's loop, transcribed, minus the call through a null pointer.
// Runs only after FindNullCallback has proved the original would fault.
void RunListSkippingNulls(void* self, int a2) {
    uint32_t node = RdU32((uintptr_t)self + kOwnerListHead);
    if (node == 0 || (node & 1) != 0) return;

    for (int n = 0; n < kMaxNodes; ++n) {
        if (NodeIsVisited(node, a2)) {
            // 6a2ae8: one-time init of the rect globals.
            if ((RdU32(kRectInitFlag) & 1) == 0) {
                *(volatile uint32_t*)kRectInitFlag |= 1u;
                *(volatile uint32_t*)(kRectGlobals + 0)  = 0;
                *(volatile uint32_t*)(kRectGlobals + 4)  = 0;
                *(volatile uint32_t*)(kRectGlobals + 8)  = 0;
                *(volatile uint32_t*)(kRectGlobals + 12) = 0;
            }

            // 6a2b10..6a2b2c: release the old object, if this node has not
            // already been done and there is something to release. nullsub_4
            // is a bare retn 4 and is intentionally not called.
            uint32_t obj = RdU32(node + kNodeObject);
            if (RdU8(node + kNodeDoneByte) == 0 &&
                (obj != 0 || RdU32(node + kNodeObject2) != 0)) {
                uint32_t vtbl = RdU32(obj);
                Release_fn release = (Release_fn)RdU32(vtbl + 8);
                release(obj);
            }

            // 6a2b31..6a2b47
            *(volatile uint32_t*)(node + kNodeObject) =
                RdU32((uintptr_t)self + kOwnerReplace);
            *(volatile uint8_t*)(node + kNodeDoneByte) = 1;
            ((Sub6848A0_fn)kSub6848A0)(self, nullptr, node,
                                       (void*)kRectGlobals, 0);

            // 6a2b4c..6a2b69: the callback. This is the one thing skipped.
            uint32_t cb = RdU32(node + kNodeCallback);
            if (cb != 0) {
                uint8_t outA[4] = {0};
                uint8_t outB[4] = {0};
                ((Callback_fn)cb)(3,
                                  RdU32(node + kNodeRectA),
                                  RdU32(node + kNodeRectB),
                                  0, 0,
                                  RdU32(node + kNodeCbArg),
                                  outA, outB);
            } else {
                InterlockedIncrement(&g_skippedNodes);
            }
        }

        uint32_t next = RdU32(node + kNodeNext);
        if (next == 0 || (next & 1) != 0) break;
        node = next;
    }
}

int __fastcall Hooked_ListWalk(void* self, void* edx, int a2) {
    InterlockedIncrement(&g_totalCalls);

    if (!self) return orig_ListWalk(self, edx, a2);

    uint32_t bad = FindNullCallback(self, a2);
    if (bad == 0) {
        // Every healthy call lands here and is untouched.
        return orig_ListWalk(self, edx, a2);
    }

    InterlockedIncrement(&g_guardedCalls);
    Log("[DeviceCbGuard] A device callback node has a null callback. The client "
        "would have executed address 0 at 0x006A2B67 and taken the process with "
        "it (a2=%d).", a2);
    DescribeNode(bad);

    DWORD code = 0;
    __try {
        RunListSkippingNulls(self, a2);
    } __except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement(&g_faults);
        Log("[DeviceCbGuard] The replacement walk faulted too (0x%08X). The list "
            "is damaged beyond a null callback; the rest of it is not being "
            "processed.", (unsigned)code);
    }

    // sub_690150, the only caller that matters here, discards this value.
    return 0;
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptDeviceCbGuard) {
        return true;
    }

    void* target = (void*)kListWalk;
    MH_STATUS st = WineSafe_CreateHook(target, (void*)Hooked_ListWalk,
                                       (void**)&orig_ListWalk);
    if (st != MH_OK) {
        Log("[DeviceCbGuard] hook NOT installed at 0x%08X (MinHook status %d) - "
            "the null-callback crash is unguarded this session",
            (unsigned)kListWalk, (int)st);
        return false;
    }
    if (WO_EnableHook(target) != MH_OK) {
        Log("[DeviceCbGuard] hook created but could not be enabled at 0x%08X",
            (unsigned)kListWalk);
        return false;
    }

    Log("[DeviceCbGuard] ACTIVE on sub_6A2AA0 - checks the device callback list "
        "for a null entry before the client calls it");
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptDeviceCbGuard) return;
    if (g_guardedCalls == 0) {
        // Silent on a healthy client, but say the walk ran at all so a log
        // without the line below is not mistaken for the guard being off.
        if (g_totalCalls > 0) {
            Log("[DeviceCbGuard] %ld device-list walks, no null callback seen",
                (long)g_totalCalls);
        }
        return;
    }
    Log("[DeviceCbGuard] Caught %ld walk(s) that would have crashed; %ld null "
        "callback(s) skipped, %ld replacement fault(s), over %ld walks",
        (long)g_guardedCalls, (long)g_skippedNodes, (long)g_faults,
        (long)g_totalCalls);
}

} // namespace DeviceCallbackGuard
