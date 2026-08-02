// ============================================================================
// Module: render_null_guard.cpp
//
// sub_873060 is called from the M2 draw path (sub_8203B0 and sub_820AE0, plus
// sub_7A84D0 and sub_873160). It does two things:
//
//   if (dword_D43020) {
//       sub_685F50(dword_C5DF88, 77, *(dword_D43024 + 4*a1 +  44));
//       sub_685F50(dword_C5DF88, 78, *(dword_D43024 + 4*a2 + 404));
//       v2 = (a2 & 8) == 0;
//   } else v2 = 1;
//   if (v2 != dword_D43008) { dword_D43008 = v2; ...apply the mode change... }
//
// The first half sets two per-draw parameters indexed by this model's own a1
// and a2. The second half is a cached two-state mode toggle.
//
// This guard exists because the second half dereferences dword_C5DF88
// unconditionally once the mode differs, and the first half indexes
// dword_D43024, so a null in either is a crash.
//
// What it must not do is skip more than it has to. Suppressing a call does not
// lose the mode change - dword_D43008 is left alone, so the next call that gets
// through still sees a difference and applies it. But it does lose the two
// per-draw parameters, and that model then draws with whichever model set them
// last. Once, for one frame, on one model, is a flicker: intermittent, hard to
// attribute, and exactly the kind of report that arrives as "the screen flickers
// occasionally after changing a graphics setting".
//
// So two changes over the previous version. The D43024 test now matches what the
// original actually dereferences - the original only indexes it when D43020 is
// set - instead of demanding it unconditionally. And every suppression is
// counted and attributed, because until now this could fire on every draw call
// in the game and nothing anywhere would have said so.
//
// The IsDeviceReady check is left as it was. sub_873060 never touches the D3D9
// device pointer itself, so on the face of it that check guards something this
// function does not do - but the mode change makes a CGxDevice virtual call at
// vtable+280, which may well reach the device, and loosening a crash guard on a
// hypothesis is not a trade worth making blind. It is counted separately
// instead, so the next log says whether it is the one firing.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "render_null_guard.h"

extern "C" void Log(const char* fmt, ...);

// Global pointers that sub_873060 reads
static uint32_t* const D43020 = (uint32_t*)0x00D43020; // device-ready flag
static uint32_t* const D43024 = (uint32_t*)0x00D43024; // per-draw parameter table
static uint32_t* const C5DF88 = (uint32_t*)0x00C5DF88; // global CGxDevice

// Original function
typedef int (__cdecl *Sub873060_t)(int a1, int a2);
static Sub873060_t g_orig873060 = nullptr;

static bool g_active = false;

// Suppression accounting. This runs on the render thread only, and these are
// counters read after the fact, so plain increments are enough - an interlocked
// pair on a per-draw path would cost more than the call being guarded.
static volatile long g_calls        = 0;
static volatile long g_suppressed   = 0;
static volatile long g_noParamTable = 0;   // D43020 set but D43024 null
static volatile long g_noGxDevice   = 0;   // C5DF88 null
static volatile long g_deviceNotReady = 0; // D3D9 device missing or vtable bad

static bool IsDeviceReady() {
    uintptr_t pGxDevice = *(uintptr_t*)0x00C5DF88;
    if (pGxDevice < 0x10000 || pGxDevice > 0xFFE00000) return false;

    uintptr_t pD3d9Device = *(uintptr_t*)(pGxDevice + 0x397C);
    if (pD3d9Device < 0x10000 || pD3d9Device > 0xFFE00000) return false;

    uintptr_t pVtable = *(uintptr_t*)pD3d9Device;
    if (pVtable < 0x10000 || pVtable > 0xFFE00000) return false;

    return true;
}

static int __cdecl Hooked_873060(int a1, int a2)
{
    ++g_calls;

    // The original indexes dword_D43024 only inside the `if (dword_D43020)`
    // block. Demanding it when D43020 is clear suppressed calls the original
    // would have run safely, and every one of those cost a model its two
    // per-draw parameters.
    if (*D43020 && !*D43024) {
        ++g_noParamTable; ++g_suppressed;
        return 1;
    }
    if (!*C5DF88) {
        ++g_noGxDevice; ++g_suppressed;
        return 1;
    }
    if (!IsDeviceReady()) {
        ++g_deviceNotReady; ++g_suppressed;
        return 1;
    }

    return g_orig873060(a1, a2);
}

bool InstallRenderNullGuard()
{
    if (!Config::g_settings.OptRenderNullGuard) {
        Log("[RenderGuard] DISABLED via configuration - sub_873060 runs unguarded");
        return true;
    }

    void* target = (void*)0x00873060;
    unsigned char* p = (unsigned char*)target;

    // Verify prologue: push ebp; mov ebp, esp
    if (p[0] != 0x55 || p[1] != 0x8B || p[2] != 0xEC) {
        Log("[RenderGuard] BAD PROLOGUE at 0x%08X (got %02X %02X %02X)",
            (uintptr_t)target, p[0], p[1], p[2]);
        return false;
    }

    if (MH_CreateHook(target, (void*)Hooked_873060, (void**)&g_orig873060) != MH_OK) {
        Log("[RenderGuard] MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[RenderGuard] MH_EnableHook FAILED");
        return false;
    }

    g_active = true;
    Log("[RenderGuard] ACTIVE v3 -- guards sub_873060, suppressions are counted");
    return true;
}

void RenderNullGuard_LogStats()
{
    if (!g_active || g_calls == 0) return;

    if (g_suppressed == 0) {
        Log("[RenderGuard] %ld draw-path calls, none suppressed", g_calls);
        return;
    }

    // Worth saying loudly. Each suppressed call is a model drawn with whatever
    // parameters the previous one left behind.
    Log("[RenderGuard] %ld of %ld draw-path calls SUPPRESSED (%.3f%%) - each one "
        "is a model drawn with the previous model's parameters",
        g_suppressed, g_calls, (double)g_suppressed * 100.0 / (double)g_calls);
    Log("[RenderGuard]   parameter table null: %ld   CGxDevice null: %ld   "
        "D3D9 device not ready: %ld",
        g_noParamTable, g_noGxDevice, g_deviceNotReady);
}
