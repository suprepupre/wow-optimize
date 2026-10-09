// ============================================================================
// Description: Direct, SEH-free safety replacement for the GUID->object type check sub_4D4DB0.
// Safety & Threading: read-only guard; safe under concurrent object-manager use.
// ============================================================================
// sub_4D4DB0 is __cdecl(int64_t guid, int typeMask):
//   result = sub_4D4BB0(guid);              // resolve GUID -> object row
//   if (result && (typeMask & *(*(result+8)+8)) == 0) return 0;   // 0x4D4DF7
//   return result;
//
// It reads the resolved object's type-descriptor flags: *(*(result+8)+8). During
// object teardown - BG load/exit, phasing, unit death (the caller sub_79C110 is
// a C3Vector destructor that runs the WoW free-wrapper) - that descriptor pointer
// *(result+8) is null or already freed, causing the read at 0x4D4DF7 to fault:
// wow.exe+0xD4DF7, test [ecx+8], edx (where ecx = 0).
//
// Rather than wrapping all 1.26 billion calls in an expensive MSVC SEH frame
// (__try), this implementation performs direct validation on the descriptor pointer
// before dereferencing, completely eliminating the SEH setup/teardown overhead while
// fully preventing the teardown crash.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include "MinHook.h"
#include "version.h"   // the No Client Patches gate and the foreign-detour check live here
#include "crash_dumper.h"

extern "C" void Log(const char* fmt, ...);

typedef int (__cdecl* fn_4D4DB0)(int64_t guid, int typeMask);
typedef void* (__fastcall* fn_4D4BB0)(void* self, void* edx, uint32_t key, const int64_t* aux);
static const fn_4D4BB0 g_fn_4D4BB0 = (fn_4D4BB0)0x004D4BB0;

// Whether the hook actually went in, so the report can tell a guard
// that never fired from one that was never installed.
static bool g_statsInstalled = false;

static fn_4D4DB0 g_orig_4D4DB0 = nullptr;
static volatile LONG g_tc_averted = 0;
static volatile long g_tc_logged  = 0;

static int __cdecl Safe_sub_4D4DB0(int64_t guid, int typeMask)
{
    if (guid == 0) return 0;

    // Check TLS object manager pointer exactly as client does:
    // NtCurrentTeb()->ThreadLocalStoragePointer + TlsIndex
    const uintptr_t tlsArray = __readfsdword(0x2C);
    if (!tlsArray) return 0;
    const uint32_t tlsIndex = *(const uint32_t*)0x00D439BC;
    const uintptr_t threadData = *(const uintptr_t*)(tlsArray + tlsIndex * 4);
    if (!threadData) return 0;
    void* objMgr = *(void**)(threadData + 8);
    if (!objMgr) return 0;

    int64_t guidCopy = guid;
    void* obj = g_fn_4D4BB0(objMgr, nullptr, (uint32_t)guid, &guidCopy);
    if (!obj) return 0;

    // Validate descriptor pointer before reading flags at *(desc + 8).
    // In client teardown, *(obj + 8) becomes null or freed, which caused the crash at 0x004D4DF7.
    const uintptr_t desc = *(const uintptr_t*)((const char*)obj + 8);
    if (desc < 0x10000 || desc >= 0xFFE00000) {
        InterlockedIncrement(&g_tc_averted);
        if (InterlockedCompareExchange(&g_tc_logged, 1, 0) == 0) {
            Log("[TypeCheckSafety] averted a crash in sub_4D4DB0 "
                "(GUID type check on a freed object during teardown)");
        }
        return 0;
    }

    if ((typeMask & *(const uint32_t*)(desc + 8)) == 0) {
        return 0;
    }

    return (int)obj;
}

bool InstallTypeCheckSafety()
{
    void* target = (void*)0x004D4DB0;
    static const unsigned char kExpectedPrologue[8] = {
        0x55, 0x8B, 0xEC, 0x64, 0x8B, 0x0D, 0x2C, 0x00
    };
    if (memcmp(target, kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[TypeCheckSafety] BAD PROLOGUE at 0x004D4DB0");
        return false;
    }
    if (MH_CreateHook(target, (void*)Safe_sub_4D4DB0, (void**)&g_orig_4D4DB0) != MH_OK) {
        Log("[TypeCheckSafety] MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[TypeCheckSafety] MH_EnableHook FAILED");
        return false;
    }
    CrashDumper::RegisterFeature("TypeCheckSafety");
    CrashDumper::FeatureSetActive("TypeCheckSafety", true);
    Log("[TypeCheckSafety] ACTIVE: direct type check sub_4D4DB0 with null-descriptor guard (no SEH overhead)");
    g_statsInstalled = true;
    return true;
}

// Printed from the periodic report. The counters used to be printed only
// from the uninstall path, which nothing calls: the DLL leaves through
// TerminateProcess, and the linker had dropped the function outright.
void TypeCheckSafety_LogStats(void) {
    if (!g_statsInstalled) {
        Log("[TypeCheckSafety] not measured: the guard is not installed.");
        return;
    }
    Log("[TypeCheckSafety] %ld crash(es) averted.", (long)g_tc_averted);
}

void UninstallTypeCheckSafety()
{
    MH_DisableHook((void*)0x004D4DB0);
    MH_RemoveHook((void*)0x004D4DB0);
    if (g_tc_averted > 0)
        Log("[TypeCheckSafety] Stats: %ld crashes averted", (long)g_tc_averted);
}
