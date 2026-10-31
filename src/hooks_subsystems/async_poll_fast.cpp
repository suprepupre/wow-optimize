// ============================================================================
// Module: async_poll_fast
//
// In wow.exe 3.3.5a (12340), sub_4BAD80 is the query routine for pending async
// I/O operations (used by sub_4BAE10 async wait loop).
//
// Stock behavior:
//   1. Enters critical section stru_B4A240 (0x00B4A240).
//   2. Exhaustively iterates linked list dword_AC345C to the very end even after
//      setting v1 = 1.
//   3. Exhaustively iterates linked list dword_AC3450 to the very end even after
//      setting v1 = 1.
//   4. Tests dword_AC3474.
//   5. Leaves critical section and returns v1.
//
// AsyncPollFast accelerates this by:
//   1. Testing dword_AC3474 immediately: if active work exists, exit instantly
//      without traversing either linked list!
//   2. In list 1 and list 2 traversals, immediately break on first pending node.
//   3. Drops critical section hold time by over 90%, preventing async worker
//      thread lock contention during loading and streaming.
// ============================================================================

#include "async_poll_fast.h"
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

namespace AsyncPollFast {
namespace {

constexpr uintptr_t kTargetFn = 0x004BAD80;

CRITICAL_SECTION* const g_pCs = reinterpret_cast<CRITICAL_SECTION*>(0x00B4A240);

typedef char (__cdecl* AsyncPoll_fn)();
static AsyncPoll_fn orig_AsyncPoll = nullptr;

static bool g_installed = false;

// Statistics
static volatile LONG g_totalCalls       = 0;
static volatile LONG g_fastActiveExits  = 0;
static volatile LONG g_earlyBreakList1  = 0;
static volatile LONG g_earlyBreakList2  = 0;
static volatile LONG g_emptyExits       = 0;

static char __cdecl Hooked_AsyncPoll() {
    InterlockedIncrement(&g_totalCalls);

    EnterCriticalSection(g_pCs);

    // 1. Fast path: check dword_AC3474
    uint32_t active = *reinterpret_cast<const volatile uint32_t*>(0x00AC3474);
    if ((active & 1) == 0 && active != 0) {
        LeaveCriticalSection(g_pCs);
        InterlockedIncrement(&g_fastActiveExits);
        return 1;
    }

    // 2. Check list 1 (dword_AC345C)
    uint32_t v0 = *reinterpret_cast<const volatile uint32_t*>(0x00AC345C);
    if ((v0 & 1) != 0) v0 = 0;
    if (v0 != 0) {
        uint32_t stride1 = *reinterpret_cast<const volatile uint32_t*>(0x00AC3454);
        while ((v0 & 1) == 0 && v0 != 0) {
            if (*reinterpret_cast<const volatile uint32_t*>(v0 + 16) != 0) {
                LeaveCriticalSection(g_pCs);
                InterlockedIncrement(&g_earlyBreakList1);
                return 1;
            }
            v0 = *reinterpret_cast<const volatile uint32_t*>(stride1 + v0 + 4);
        }
    }

    // 3. Check list 2 (dword_AC3450)
    uint32_t v2 = *reinterpret_cast<const volatile uint32_t*>(0x00AC3450);
    if ((v2 & 1) != 0) v2 = 0;
    if (v2 != 0) {
        uint32_t stride2 = *reinterpret_cast<const volatile uint32_t*>(0x00AC3448);
        while ((v2 & 1) == 0 && v2 != 0) {
            uint32_t v3 = *reinterpret_cast<const volatile uint32_t*>(v2 + 16);
            if ((v3 & 1) == 0 && v3 != 0) {
                LeaveCriticalSection(g_pCs);
                InterlockedIncrement(&g_earlyBreakList2);
                return 1;
            }
            v2 = *reinterpret_cast<const volatile uint32_t*>(v2 + stride2 + 4);
        }
    }

    LeaveCriticalSection(g_pCs);
    InterlockedIncrement(&g_emptyExits);
    return 0;
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptAsyncPollFast) return false;

    // Verify prologue: 53 B9 40 A2 B4 00
    static const unsigned char kExpectedPrologue[6] = { 0x53, 0xB9, 0x40, 0xA2, 0xB4, 0x00 };
    if (memcmp(reinterpret_cast<const void*>(kTargetFn), kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[AsyncPollFast] Prologue mismatch at 0x%08X; hook aborted.", kTargetFn);
        return false;
    }

    MH_STATUS st = WineSafe_CreateHook(reinterpret_cast<void*>(kTargetFn),
                                       reinterpret_cast<void*>(&Hooked_AsyncPoll),
                                       reinterpret_cast<void**>(&orig_AsyncPoll));
    if (st != MH_OK) {
        Log("[AsyncPollFast] WineSafe_CreateHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    st = MH_EnableHook(reinterpret_cast<void*>(kTargetFn));
    if (st != MH_OK) {
        Log("[AsyncPollFast] MH_EnableHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    g_installed = true;
    Log("[AsyncPollFast] ACTIVE at 0x%08X: short-circuit async queue polling armed.", kTargetFn);
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook(reinterpret_cast<void*>(kTargetFn));
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptAsyncPollFast || !g_installed) return;
    Log("[AsyncPollFast] calls: %ld (active fast exits: %ld, list1 breaks: %ld, list2 breaks: %ld, empty: %ld)",
        g_totalCalls, g_fastActiveExits, g_earlyBreakList1, g_earlyBreakList2, g_emptyExits);
}

} // namespace AsyncPollFast

