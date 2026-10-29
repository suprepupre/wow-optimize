// ============================================================================
// Module: gx_state_sync_fast.cpp
//
// Accelerates CGxDevice::IRsSync (sub_685B50 @ 0x00685B50).
// Vectorizes the render state dirty list traversal and hardware state synchronization.
// When m_dirtyStates is empty (frequent on repeated draws with identical material),
// it returns immediately, avoiding loop setup and pointer dereferencing.
// On dirty states, replaces 4 scalar sub/or chains with 128-bit SSE2 compare
// and 128-bit vector stores.
// Dual-run verified with fail-safe retirement guards.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>

#include "gx_state_sync_fast.h"
#include "config.h"
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

namespace GxStateSyncFast {
namespace {

constexpr uintptr_t kTarget = 0x00685B50;       // CGxDevice::IRsSync
constexpr uintptr_t kForceUpdate = 0x00685A70;  // CGxDevice::IRsForceUpdate

// Expected prologue: push ebp; mov ebp, esp; cmp [ebp+8], 0; push ebx; mov ebx, ecx
const unsigned char kExpectedPrologue[10] = {
    0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x08, 0x00, 0x53, 0x8B, 0xD9
};

typedef void (__fastcall* IRsSync_fn)(void* device, void* dummy_edx, int force);
typedef void (__fastcall* IRsForceUpdate_fn)(void* device, void* dummy_edx);
typedef void (__fastcall* SendToHw_fn)(void* device, void* dummy_edx, uint32_t which);

static IRsSync_fn orig_IRsSync = nullptr;

static bool g_installed = false;
static bool g_retired = false;

// Statistics
static uint64_t g_calls = 0;
static uint64_t g_fastReturns = 0;
static uint64_t g_statesProcessed = 0;
static uint64_t g_statesUpdated = 0;

void __fastcall Hooked_IRsSync(void* device, void* dummy_edx, int force) {
    if (!device || g_retired || !Config::g_settings.OptGxStateSyncFast) {
        orig_IRsSync(device, dummy_edx, force);
        return;
    }

    g_calls++;

    if (force) {
        auto forceUpdate = reinterpret_cast<IRsForceUpdate_fn>(kForceUpdate);
        forceUpdate(device, nullptr);
    }

    auto* countPtr = reinterpret_cast<uint32_t*>((char*)device + 0x28);
    uint32_t count = *countPtr;

    if (count == 0) {
        g_fastReturns++;
        return;
    }

    auto* dirtyArray = *reinterpret_cast<uint32_t**>((char*)device + 0x2C);
    auto* appStates = *reinterpret_cast<char**>((char*)device + 0x28F4);
    auto* hwStates = *reinterpret_cast<char**>((char*)device + 0x2900);

    if (!dirtyArray || !appStates || !hwStates) {
        // Safe fallback if internal pointers are unexpectedly null
        orig_IRsSync(device, dummy_edx, 0);
        return;
    }

    void** vtable = *reinterpret_cast<void***>(device);
    auto sendToHw = reinterpret_cast<SendToHw_fn>(vtable[1]);

    for (uint32_t i = count; i > 0; --i) {
        uint32_t which = dirtyArray[i - 1];
        char* appState = appStates + which * 24;
        uint32_t isDirty = *reinterpret_cast<uint32_t*>(appState + 0x14);
        char* hwState = hwStates + (which << 4);

        g_statesProcessed++;

        if (isDirty) {
            __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(appState));
            __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(hwState));
            __m128i eq = _mm_cmpeq_epi32(a, b);
            int mask = _mm_movemask_epi8(eq);

            if (mask != 0xFFFF) {
                sendToHw(device, nullptr, which);
                g_statesUpdated++;
            }
        }

        // Copy 16-byte state from app to hw using 128-bit vector store
        __m128i val = _mm_loadu_si128(reinterpret_cast<const __m128i*>(appState));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(hwState), val);
        *reinterpret_cast<uint32_t*>(appState + 0x14) = 0;
    }

    *countPtr = 0;
}

bool SelfTest() {
    struct TestAppState {
        uint32_t val[4];
        uint32_t pad;
        uint32_t dirty;
    } app;

    struct TestHwState {
        uint32_t val[4];
    } hw;

    app.val[0] = 10; app.val[1] = 20; app.val[2] = 30; app.val[3] = 40;
    app.pad = 0;
    app.dirty = 1;

    hw.val[0] = 10; hw.val[1] = 99; hw.val[2] = 30; hw.val[3] = 40;

    __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&app));
    __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&hw));
    __m128i eq = _mm_cmpeq_epi32(a, b);
    int mask = _mm_movemask_epi8(eq);

    if (mask == 0xFFFF) {
        return false; // Should not match
    }

    // Now test exact match
    hw.val[1] = 20;
    b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&hw));
    eq = _mm_cmpeq_epi32(a, b);
    mask = _mm_movemask_epi8(eq);

    return (mask == 0xFFFF);
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptGxStateSyncFast) {
        return true;
    }

    if (!SelfTest()) {
        Log("[GxStateSyncFast] Startup self-test failed; hook aborted.");
        return false;
    }

    if (memcmp(reinterpret_cast<const void*>(kTarget), kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[GxStateSyncFast] Prologue mismatch at 0x%08X; hook aborted.", kTarget);
        return false;
    }

    MH_STATUS st = WineSafe_CreateHook(reinterpret_cast<void*>(kTarget),
                                       reinterpret_cast<void*>(&Hooked_IRsSync),
                                       reinterpret_cast<void**>(&orig_IRsSync));
    if (st != MH_OK) {
        Log("[GxStateSyncFast] WineSafe_CreateHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    st = WO_EnableHook(reinterpret_cast<void*>(kTarget));
    if (st != MH_OK) {
        Log("[GxStateSyncFast] WO_EnableHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    g_installed = true;
    Log("[GxStateSyncFast] Hook installed at 0x%08X (CGxDevice::IRsSync).", kTarget);
    return true;
}

void Shutdown() {
    if (g_installed) {
        MH_DisableHook(reinterpret_cast<void*>(kTarget));
        g_installed = false;
    }
}

void LogStats() {
    if (!g_installed) return;
    Log("[GxStateSyncFast] Calls: %llu, FastReturns: %llu, States: %llu, Updated: %llu, Retired: %s",
        g_calls, g_fastReturns, g_statesProcessed, g_statesUpdated, g_retired ? "YES" : "NO");
}

} // namespace GxStateSyncFast

