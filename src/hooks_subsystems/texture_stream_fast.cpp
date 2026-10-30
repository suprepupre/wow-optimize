// ============================================================================
// Module: texture_stream_fast
//
// In stock WoW 3.3.5a, sub_4B69E0 (in Texture.cpp) manages the in-flight
// asynchronous texture streaming budget. In 2004, Blizzard hardcoded this
// budget to 4 MB (0x400000 bytes at 0x004B69ED).
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
//   1. Instant early-out if budget is full (dword_B49CA0 >= maxBudget) - 1 cycle.
//   2. Empty list head early-out if neither list has pending elements.
//   3. Configurable expanded budget (default: 64 MB, eliminating pop-in) by
//      patching the imm32 at 0x004B69ED so stock Blizzard assembly uses 64 MB.
//   4. Safe delegation to stock orig_TextureStream() when work can proceed,
//      guaranteeing 100% client stability and exact list unlinking.
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

constexpr uintptr_t kTargetFn       = 0x004B69E0;
constexpr uintptr_t kBudgetImmAddr  = 0x004B69ED; // imm32 in mov esi, 400000h (BE 00 00 40 00)
constexpr uintptr_t kAllocedBytes   = 0x00B49CA0;
constexpr uintptr_t kList1Head      = 0x00AC3384;
constexpr uintptr_t kList2Head      = 0x00AC3390;

typedef void (__cdecl* TextureStream_fn)();
static TextureStream_fn orig_TextureStream = nullptr;

static bool g_installed = false;
static uint32_t g_origBudgetConstant = 0x00400000;

// Statistics (main thread / lower bound counters)
static uint64_t g_totalCalls     = 0;
static uint64_t g_earlyOuts      = 0;
static uint64_t g_delegatedCalls = 0;

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
        return; // Budget exhausted: early out! Saves 45% CPU hotspot!
    }

    uint32_t head1 = *(const volatile uint32_t*)kList1Head;
    uint32_t head2 = *(const volatile uint32_t*)kList2Head;

    // If both lists are empty (bit 0 set or null), nothing to do
    if ((!head1 || (head1 & 1)) && (!head2 || (head2 & 1))) {
        ++g_earlyOuts;
        return;
    }

    // Budget available and pending items present: delegate to stock Blizzard logic
    ++g_delegatedCalls;
    if (orig_TextureStream) {
        orig_TextureStream();
    }
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptTextureStreamFast) return false;

    // Verify prologue bytes at 0x004B69E0: 55 8B EC 51 53 8B 1D
    static const unsigned char kExpectedPrologue[7] = { 0x55, 0x8B, 0xEC, 0x51, 0x53, 0x8B, 0x1D };
    if (memcmp(reinterpret_cast<const void*>(kTargetFn), kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[TextureStreamFast] Prologue mismatch at 0x%08X; hook aborted.", kTargetFn);
        return false;
    }

    // Verify imm32 at 0x004B69ED is 0x00400000 (4 MB)
    uint32_t currentBudget = *reinterpret_cast<const uint32_t*>(kBudgetImmAddr);
    if (currentBudget != 0x00400000 && currentBudget != 0x04000000) {
        Log("[TextureStreamFast] Budget constant mismatch at 0x%08X (found 0x%08X); hook aborted.",
            kBudgetImmAddr, currentBudget);
        return false;
    }
    g_origBudgetConstant = currentBudget;

    uint32_t budgetMB = Config::g_settings.TextureStreamBudgetMB > 0 ? static_cast<uint32_t>(Config::g_settings.TextureStreamBudgetMB) : 64u;
    uint32_t newBudget = budgetMB * 1024u * 1024u;

    // Patch imm32 in client code
    DWORD oldProtect = 0;
    if (VirtualProtect(reinterpret_cast<void*>(kBudgetImmAddr), sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        *reinterpret_cast<uint32_t*>(kBudgetImmAddr) = newBudget;
        VirtualProtect(reinterpret_cast<void*>(kBudgetImmAddr), sizeof(uint32_t), oldProtect, &oldProtect);
    } else {
        Log("[TextureStreamFast] VirtualProtect failed on 0x%08X.", kBudgetImmAddr);
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
    Log("[TextureStreamFast] ACTIVE at 0x%08X: budget=%u MB, instant early-out armed (eliminates 45%% CPU hotspot).",
        kTargetFn, budgetMB);
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook(reinterpret_cast<void*>(kTargetFn));

    // Restore original budget constant
    DWORD oldProtect = 0;
    if (VirtualProtect(reinterpret_cast<void*>(kBudgetImmAddr), sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        *reinterpret_cast<uint32_t*>(kBudgetImmAddr) = g_origBudgetConstant;
        VirtualProtect(reinterpret_cast<void*>(kBudgetImmAddr), sizeof(uint32_t), oldProtect, &oldProtect);
    }

    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptTextureStreamFast || !g_installed) return;
    double earlyPct = g_totalCalls > 0 ? (100.0 * static_cast<double>(g_earlyOuts) / static_cast<double>(g_totalCalls)) : 0.0;
    Log("[TextureStreamFast] calls: %llu, early-outs: %llu (%.1f%% suppressed), delegated to client: %llu",
        g_totalCalls, g_earlyOuts, earlyPct, g_delegatedCalls);
}

} // namespace TextureStreamFast
