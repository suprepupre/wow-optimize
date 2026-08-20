// ============================================================================
// Module: sound_buffer_guard.cpp
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"
#include "crash_dumper.h"
#include "sound_buffer_guard.h"
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

extern "C" void Log(const char* fmt, ...);

typedef int (__cdecl* sub_508320_fn)(int a1, int a2);
static sub_508320_fn g_orig_sub_508320 = nullptr;

static volatile LONG64 g_total_calls  = 0;
static volatile LONG64 g_recovered    = 0;
static volatile long   g_logged       = 0;

static ULONGLONG g_lastSoundUpdateTime = 0;

static int __cdecl Safe_sub_508320(int a1, int a2)
{
    ++g_total_calls;

    #if !TEST_DISABLE_SOUND_MIXER_OPT
    ULONGLONG now = GetTickCount64();
    if (now - g_lastSoundUpdateTime < 20) {
        return 0;
    }
    g_lastSoundUpdateTime = now;
    #endif

    __try {
        return g_orig_sub_508320(a1, a2);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ++g_recovered;
        if (InterlockedCompareExchange(&g_logged, 1, 0) == 0) {
            Log("[SndBuffer] ONE-SHOT DIAGNOSTIC: Caught crash in sub_508320! a1=%d a2=%d RetAddr=%p",
                a1, a2, _ReturnAddress());
        }
        return 0;
    }
}

static bool g_soundBufferGuardInstalled = false;

bool InstallSoundBufferGuard()
{
    if (g_soundBufferGuardInstalled) return true;

    void* target = (void*)0x00508320;

    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B || p[2] != 0xEC) {
        Log("[SndBuffer] BAD PROLOGUE at 0x%08X (got %02X %02X %02X)",
            (uintptr_t)target, p[0], p[1], p[2]);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)Safe_sub_508320, (void**)&g_orig_sub_508320) != MH_OK) {
        Log("[SndBuffer] MH_CreateHook FAILED");
        return false;
    }
    if (WO_EnableHook(target) != MH_OK) {
        Log("[SndBuffer] MH_EnableHook FAILED");
        MH_RemoveHook(target);
        return false;
    }

    CrashDumper::RegisterFeature("SndBuffer");
    CrashDumper::FeatureSetActive("SndBuffer", true);
    CrashDumper::RegisterFeature("SndUpdate");
    CrashDumper::FeatureSetActive("SndUpdate", true);

    Log("[SndBuffer] ACTIVE: SEH guard on sub_508320 (buffer + update), covers 0x508740+0x508950");
    g_soundBufferGuardInstalled = true;
    return true;
}

void UninstallSoundBufferGuard()
{
    MH_DisableHook((void*)0x00508320);
    MH_RemoveHook((void*)0x00508320);
    g_soundBufferGuardInstalled = false;

    LONG64 total     = g_total_calls;
    LONG64 recovered = g_recovered;
    if (recovered > 0) {
        Log("[SndBuffer] Stats: %lld calls | %lld recovered from crashes",
            total, recovered);
    }

    CrashDumper::FeatureSetActive("SndBuffer", false);
    CrashDumper::FeatureSetActive("SndUpdate", false);
}
