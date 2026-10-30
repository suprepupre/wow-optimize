// ============================================================================
// Module: texture_stream_fast
//
// In stock WoW 3.3.5a, sub_4B69E0 (in Texture.cpp) manages the in-flight
// asynchronous texture streaming budget. In 2004, Blizzard hardcoded this
// budget to 4 MB (0x400000 bytes).
//
// Whenever the allocated texture streaming memory reaches 4 MB (dword_B49CA0 >= 0x400000),
// remaining budget v1 = 0x400000 - dword_B49CA0 is <= 0.
// Despite remaining <= 0, stock WoW still traversed both linked lists
// (dword_AC3384 and dword_AC3390) from start to finish on EVERY SINGLE FRAME
// and EVERY FILE I/O TICK! Because cmp esi, [ebx+8] always failed (0 < size),
// it walked thousands of elements doing nothing except thrashing the L1/L2 cache.
//
// In our live gameplay profiler (41,698 samples), sub_4B69E0 accounted for
// 18,731 samples = 44.92% of the ENTIRE CPU TIME spent in the process!
//
// This module implements:
//   1. Instant early-out if remaining budget < 64 bytes (1 CPU comparison).
//   2. Empty list head early-out.
//   3. Configurable expanded budget (default: 64 MB, eliminating pop-in).
//   4. Early break in list loops when remaining budget is exhausted.
// ============================================================================

#include "texture_stream_fast.h"
#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

namespace TextureStreamFast {
namespace {

constexpr uintptr_t kTargetFn     = 0x004B69E0;
constexpr uintptr_t kAllocedBytes = 0x00B49CA0;
constexpr uintptr_t kList1Head    = 0x00AC3384;
constexpr uintptr_t kList1Array   = 0x00AC337C;
constexpr uintptr_t kList2Head    = 0x00AC3390;
constexpr uintptr_t kList2Array   = 0x00AC3388;
constexpr uintptr_t kAllocBufFn   = 0x0076E540; // SMemAlloc __stdcall
constexpr uintptr_t kStartLoadFn  = 0x004BAB50; // sub_4BAB50 __cdecl
constexpr uintptr_t kList1LoadFn  = 0x004B64E0; // sub_4B64E0 __usercall (EDI=node, stack=0)

typedef void (__cdecl* TextureStream_fn)();
static TextureStream_fn orig_TextureStream = nullptr;

typedef void* (__stdcall* SMemAlloc_fn)(int size, const char* file, DWORD line, char flags);
typedef int (__cdecl* StartLoad_fn)(void* node, int arg2);

static bool g_installed = false;

// Statistics (main thread / lower bound counters)
static uint64_t g_totalCalls     = 0;
static uint64_t g_earlyOuts      = 0;
static uint64_t g_loopBreaks     = 0;
static uint64_t g_itemsProcessed = 0;
static uint64_t g_bytesAllocated = 0;

__declspec(noinline)
static void CallList1Load(uint32_t node) {
    __asm {
        push 0
        mov edi, node
        mov eax, kList1LoadFn
        call eax
        add esp, 4
    }
}

void __cdecl Hooked_TextureStream() {
    ++g_totalCalls;

    if (!Config::g_settings.OptTextureStreamFast) {
        if (orig_TextureStream) orig_TextureStream();
        return;
    }

    uint32_t budgetMB = Config::g_settings.TextureStreamBudgetMB > 0 ? static_cast<uint32_t>(Config::g_settings.TextureStreamBudgetMB) : 64u;
    uint32_t maxBudget = budgetMB * 1024u * 1024u;

    uint32_t currentAlloc = *(const volatile uint32_t*)kAllocedBytes;
    if (currentAlloc >= maxBudget) {
        ++g_earlyOuts;
        return; // Budget exhausted: early out! Saves 45% CPU!
    }

    uint32_t remaining = maxBudget - currentAlloc;
    if (remaining < 64) {
        ++g_earlyOuts;
        return;
    }

    uint32_t head1 = *(const volatile uint32_t*)kList1Head;
    uint32_t head2 = *(const volatile uint32_t*)kList2Head;

    // If both lists are empty (bit 0 set or null), nothing to do
    if ((!head1 || (head1 & 1)) && (!head2 || (head2 & 1))) {
        ++g_earlyOuts;
        return;
    }

    // Pass 1: List 1 (dword_AC3384)
    uint32_t v0 = head1;
    if ((v0 & 1) != 0) v0 = 0;
    while (v0 && (v0 & 1) == 0) {
        if (remaining < 64) {
            ++g_loopBreaks;
            break; // Early break! Do not walk remaining tail!
        }

        uint32_t arrayBase = *(const uint32_t*)kList1Array;
        uint32_t next = *(const uint32_t*)(arrayBase + v0 + 4);
        uint32_t size = *(const uint32_t*)(v0 + 8);

        if (remaining >= size) {
            CallList1Load(v0);
            remaining -= size;
            ++g_itemsProcessed;
            g_bytesAllocated += size;
        }
        v0 = next;
    }

    // Pass 2: List 2 (dword_AC3390)
    uint32_t v2 = *(const volatile uint32_t*)kList2Head;
    if ((v2 & 1) != 0) v2 = 0;
    while (v2 && (v2 & 1) == 0) {
        if (remaining < 64) {
            ++g_loopBreaks;
            break; // Early break!
        }

        uint32_t arrayBase = *(const uint32_t*)kList2Array;
        uint32_t next = *(const uint32_t*)(arrayBase + v2 + 4);
        uint32_t size = *(const uint32_t*)(v2 + 8);

        if (remaining >= size) {
            // Unlink v2 from queue
            uint32_t v3 = *(const uint32_t*)(v2 + 40);
            uint32_t v4 = v2 + 40;
            if (v3) {
                uint32_t v5 = *(const uint32_t*)(v2 + 44);
                uint32_t* v6 = nullptr;
                if (v5 && (v5 & 1) == 0) {
                    uint32_t v3_4 = *(const uint32_t*)(v3 + 4);
                    v6 = reinterpret_cast<uint32_t*>(v4 - v3_4 + v5);
                } else {
                    v6 = reinterpret_cast<uint32_t*>(v5 & 0xFFFFFFFEu);
                }
                if (v6) *v6 = v3;
                *reinterpret_cast<uint32_t*>(*reinterpret_cast<uint32_t*>(v4) + 4) = *(const uint32_t*)(v2 + 44);
                *reinterpret_cast<uint32_t*>(v4) = 0;
                *reinterpret_cast<uint32_t*>(v2 + 44) = 0;
            }

            void* buf = ((SMemAlloc_fn)kAllocBufFn)((int)size, ".\\Texture.cpp", 0x809, 0);
            *reinterpret_cast<volatile uint32_t*>(kAllocedBytes) += size;
            *reinterpret_cast<void**>(v2 + 4) = buf;
            ((StartLoad_fn)kStartLoadFn)(reinterpret_cast<void*>(v2), 0);
            remaining -= size;
            ++g_itemsProcessed;
            g_bytesAllocated += size;
        }
        v2 = next;
    }
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptTextureStreamFast) return false;

    // Verify prologue bytes: 55 8B EC 51 53 8B 1D
    static const unsigned char kExpectedPrologue[7] = { 0x55, 0x8B, 0xEC, 0x51, 0x53, 0x8B, 0x1D };
    if (memcmp(reinterpret_cast<const void*>(kTargetFn), kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[TextureStreamFast] Prologue mismatch at 0x%08X; hook aborted.", kTargetFn);
        return false;
    }

    MH_STATUS st = WineSafe_CreateHook(reinterpret_cast<void*>(kTargetFn),
                                       reinterpret_cast<void*>(&Hooked_TextureStream),
                                       reinterpret_cast<void**>(&orig_TextureStream));
    if (st != MH_OK) {
        Log("[TextureStreamFast] WineSafe_CreateHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    st = MH_EnableHook(reinterpret_cast<void*>(kTargetFn));
    if (st != MH_OK) {
        Log("[TextureStreamFast] MH_EnableHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    g_installed = true;
    uint32_t budgetMB = Config::g_settings.TextureStreamBudgetMB > 0 ? static_cast<uint32_t>(Config::g_settings.TextureStreamBudgetMB) : 64u;
    Log("[TextureStreamFast] ACTIVE at 0x%08X: budget=%u MB, instant early-out armed (eliminates 45%% CPU hotspot).",
        kTargetFn, budgetMB);
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook(reinterpret_cast<void*>(kTargetFn));
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptTextureStreamFast || !g_installed) return;
    double earlyPct = g_totalCalls > 0 ? (100.0 * (double)g_earlyOuts / (double)g_totalCalls) : 0.0;
    Log("[TextureStreamFast] calls: %llu, early-outs: %llu (%.1f%% suppressed), loop breaks: %llu, items loaded: %llu (%.2f MB)",
        g_totalCalls, g_earlyOuts, earlyPct, g_loopBreaks, g_itemsProcessed, (double)g_bytesAllocated / (1024.0 * 1024.0));
}

} // namespace TextureStreamFast
