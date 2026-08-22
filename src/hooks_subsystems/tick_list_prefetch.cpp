// ============================================================================
// Module: tick_list_prefetch.cpp
// Description: Prefetches the next node of the per-frame object tick walk.
// Safety & Threading: Main thread, inside the frame.
// ============================================================================
//
// sub_6BE3E0 walks an intrusive list every frame:
//
//     v2 = dword_AD9ACC;
//     if ((v2 & 1) != 0 || !v2) v2 = 0;
//     while ((v2 & 1) == 0 && v2) { sub_6C6C00(v2); v2 = *(_DWORD *)(v2 + 4); }
//
// and sub_6C6C00 is nine instructions:
//
//     cmp  [ecx+0B0h], 0        ; nothing to do for this node
//     jz   ret
//     mov  eax, [ecx+0D4h]      ; a per-node counter
//     cmp  eax, 1Eh
//     lea  edx, [eax+1]
//     mov  [ecx+0D4h], edx
//     jle  ret                  ; only every 31st call does any work
//     jmp  sub_6C6B90
//
// In txtsd's CPU-bound session of 2026-08-22 that function is 1.39% of the
// profile, and the sample sits on 0x006C6C07 - the branch immediately after the
// first load. That is the shape of a pointer chase paying a cache miss per
// node, and it pays two: +0xB0 lands in the third cache line of the node and
// +0xD4 in the fourth, so touching both pulls two lines, and the next node's
// address is not known until the caller reloads [node+4] after this returns.
//
// It IS known here, from [ecx+4]. So this issues prefetcht0 for the two lines
// the next call will want, a whole call of latency early, and then does the
// original nine instructions.
//
// Why this needs no verification phase, unlike the maths replacements here: a
// prefetch is architecturally inert. It cannot fault, cannot change a flag,
// cannot change a register, and cannot change what any later instruction
// computes - on an unmapped or garbage address it is defined to do nothing.
// What remains is a verbatim transcription of nine instructions with no
// arithmetic in it, which is the same ground the collision outcode replacement
// stands on.
//
// The transcription is checked against the client rather than trusted: the 35
// bytes at the entry point are compared with what was disassembled, and one
// byte out of place means no hook. That also declines cleanly when another
// injector reached the function first.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "tick_list_prefetch.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

// File scope and outside any namespace: the naked thunk names these from inline
// assembly, which does not resolve namespace-qualified symbols.
static void*    g_origTick        = nullptr;
static uint32_t g_nextStage       = 0x006C6B90;  // the tail call, jumped indirectly
static uint32_t g_tickCalls       = 0;           // plain 32-bit: a lower bound
static uint32_t g_tickPrefetched  = 0;

// Exactly what sub_6C6C00 is, byte for byte.
static const unsigned char kExpectedTick[] = {
    0x83, 0xB9, 0xB0, 0x00, 0x00, 0x00, 0x00,   // cmp dword ptr [ecx+0B0h], 0
    0x74, 0x19,                                  // jz  short 0x6C6C22
    0x8B, 0x81, 0xD4, 0x00, 0x00, 0x00,          // mov eax, [ecx+0D4h]
    0x83, 0xF8, 0x1E,                            // cmp eax, 1Eh
    0x8D, 0x50, 0x01,                            // lea edx, [eax+1]
    0x89, 0x91, 0xD4, 0x00, 0x00, 0x00,          // mov [ecx+0D4h], edx
    0x7E, 0x05,                                  // jle short 0x6C6C22
    0xE9, 0x6E, 0xFF, 0xFF, 0xFF,                // jmp sub_6C6B90
    0xC3                                         // retn
};

// __thiscall: the node arrives in ECX and nothing is on the stack.
__declspec(naked) static void HookedTick() {
    __asm {
        // The next node, which the caller loads from the same place once this
        // returns. Prefetching it here buys a whole call of latency.
        mov  eax, [ecx+4]
        test al, 1                      // the caller's own sentinel test
        jnz  no_prefetch
        test eax, eax
        jz   no_prefetch
        prefetcht0 [eax+0B0h]
        prefetcht0 [eax+0D4h]
        inc  dword ptr [g_tickPrefetched]
    no_prefetch:
        inc  dword ptr [g_tickCalls]

        // Verbatim from here down. The cmp precedes the lea and mov in the
        // client too, and neither of those touches flags, so the jle tests the
        // counter's value from before the increment, exactly as it does there.
        cmp  dword ptr [ecx+0B0h], 0
        jz   done
        mov  eax, [ecx+0D4h]
        cmp  eax, 1Eh
        lea  edx, [eax+1]
        mov  [ecx+0D4h], edx
        jle  done
        // Indirect, so EAX still holds what the client's own path would have
        // left in it rather than being clobbered to form the jump target.
        jmp  dword ptr [g_nextStage]
    done:
        ret
    }
}

namespace TickListPrefetch {

namespace {

constexpr uintptr_t kTick = 0x006C6C00;
bool g_installed = false;

}  // namespace

bool Init() {
    if (!Config::g_settings.OptTickListPrefetch) return true;

    if (IsBadReadPtr((void*)kTick, sizeof(kExpectedTick))) {
        Log("[TickPrefetch] 0x%08X unreadable - not installing", (unsigned)kTick);
        return false;
    }
    if (memcmp((void*)kTick, kExpectedTick, sizeof(kExpectedTick)) != 0) {
        Log("[TickPrefetch] the %u bytes at 0x%08X are not the function this was "
            "written against - not installing. Either the client differs from "
            "build 12340 or something hooked it first.",
            (unsigned)sizeof(kExpectedTick), (unsigned)kTick);
        return false;
    }

    if (WineSafe_CreateHook((void*)kTick, (void*)HookedTick, &g_origTick) != MH_OK) {
        Log("[TickPrefetch] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kTick) != MH_OK) {
        Log("[TickPrefetch] hook created but could not be enabled");
        return false;
    }

    g_installed = true;
    Log("[TickPrefetch] ACTIVE on sub_6C6C00 (0x%08X), the per-object tick the "
        "frame reaches by walking a linked list. It is 1.39%% of a measured "
        "profile and the samples sit on the cache miss at its first load, so "
        "the next node's two lines are prefetched a call early. The nine "
        "instructions are transcribed verbatim, the entry bytes were compared "
        "with the disassembly before hooking, and a prefetch cannot change what "
        "any of them compute.",
        (unsigned)kTick);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptTickListPrefetch) return;
    if (!g_installed)     { Log("[TickPrefetch] not installed - nothing measured"); return; }
    if (g_tickCalls == 0) { Log("[TickPrefetch] installed but never called"); return; }
    Log("[TickPrefetch] %u calls, %u with a next node to prefetch (%.1f%%). Both "
        "are plain 32-bit counters on a hot path and are lower bounds. No "
        "frame-time gain is claimed: this says what it did, not what it saved.",
        g_tickCalls, g_tickPrefetched,
        100.0 * (double)g_tickPrefetched / (double)g_tickCalls);
}

}  // namespace TickListPrefetch
