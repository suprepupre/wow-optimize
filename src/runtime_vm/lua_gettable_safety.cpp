#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "version.h"   // the No Client Patches gate and the foreign-detour check live here
#include "crash_dumper.h"
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

extern "C" void Log(const char* fmt, ...);

// ----------------------------------------------------------------
// Function signature
// sub_85BC10: _DWORD *__cdecl(int a1, _DWORD *a2, int a3)
// ----------------------------------------------------------------
typedef void* (__cdecl* sub_85BC10_fn)(int a1, uint32_t* a2, int a3);
// Whether the hook actually went in, so the report can tell a guard
// that never fired from one that was never installed.
static bool g_statsInstalled = false;

static sub_85BC10_fn g_orig_sub_85BC10 = nullptr;

// Nil object sentinel at 0xA46F78 (same as used by original function)
static void* g_nil_object = (void*)0x00A46F78;

// Maximum valid TValue type tag. WoW Lua types: 0=nil, 1=boolean, 
// 2=lightuserdata, 3=number, 4=string, 5=table, 6=function, 
// 7=userdata, 8=thread. Types above 8 are invalid and cause out-of-bounds reads.
static constexpr uint32_t MAX_VALID_TYPE = 8;

// Statistics (diagnostic only; plain increments -- Lua is single-threaded,
// so a locked cmpxchg8b per table index was wasted on this hot path)
static volatile LONG64 g_total_calls = 0;
static volatile LONG64 g_blocked_calls = 0;
static volatile long g_logged = 0;

static void LogCrashAverted(uint32_t* a2, void* retAddr, const char* reason) {
    if (InterlockedCompareExchange(&g_logged, 1, 0) == 0) {
        Log("[GetTableSafety] ONE-SHOT DIAGNOSTIC: %s! TValue=0x%08X, RetAddr=%p", reason, (unsigned)(uintptr_t)a2, retAddr);
    }
}

// ----------------------------------------------------------------
// Safe wrapper - validates TValue type before calling original.
// Direct pointer and type validation without __try on the hot path,
// avoiding 32-bit MSVC SEH frame setup/teardown on every Lua lookup.
// ----------------------------------------------------------------
static void* __cdecl Safe_sub_85BC10(int a1, uint32_t* a2, int a3)
{
    ++g_total_calls;

    // Validate a2 pointer (must be in valid user-mode address space)
    if (!a2 || (uintptr_t)a2 < 0x10000 || (uintptr_t)a2 >= 0xFFE00000) {
        ++g_blocked_calls;
        LogCrashAverted(a2, _ReturnAddress(), "Bad pointer");
        return g_nil_object;
    }

    // Validate a2[2] (TValue type field) is within safe bounds.
    // The original code uses a2[2] as array index into G(L)->mt: node_array[a2[2]] + offset.
    // Valid Lua types are 0-8. Types > 8 cause out-of-bounds read in global_State.
    uint32_t typeTag = a2[2];
    if (typeTag > MAX_VALID_TYPE) {
        ++g_blocked_calls;
        LogCrashAverted(a2, _ReturnAddress(), "Invalid typeTag");
        return g_nil_object;
    }

    // For table (5) and userdata (7), validate that the payload pointer *a2
    // is in valid user address space before the engine dereferences *(*a2 + 12).
    if (typeTag == 5 || typeTag == 7) {
        uintptr_t obj = (uintptr_t)a2[0];
        if (obj < 0x10000 || obj >= 0xFFE00000) {
            ++g_blocked_calls;
            LogCrashAverted(a2, _ReturnAddress(), "Invalid table/userdata pointer");
            return g_nil_object;
        }
    }

    // Fast path: call original function directly without SEH overhead
    return g_orig_sub_85BC10(a1, a2, a3);
}

// Install / Uninstall
bool InstallLuaGetTableSafety()
{
    void* target = (void*)0x0085BC10;

    // Verify prologue: push ebp; mov ebp, esp; mov edx, [ebp+arg_4]; mov eax, [edx+8]
    static const unsigned char kExpectedPrologue[8] = {
        0x55, 0x8B, 0xEC, 0x8B, 0x55, 0x0C, 0x8B, 0x42
    };
    if (memcmp(target, kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[GetTableSafety] BAD PROLOGUE at 0x%08X", (uintptr_t)target);
        return false;
    }

    if (MH_CreateHook(target, (void*)Safe_sub_85BC10, (void**)&g_orig_sub_85BC10) != MH_OK) {
        Log("[GetTableSafety] MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[GetTableSafety] MH_EnableHook FAILED");
        return false;
    }

    CrashDumper::RegisterFeature("LuaGetTableSafety");
    CrashDumper::FeatureSetActive("LuaGetTableSafety", true);

    Log("[GetTableSafety] ACTIVE: validating TValue type at sub_85BC10 (max_type=%u)", MAX_VALID_TYPE);
    g_statsInstalled = true;
    return true;
}

// Printed from the periodic report. The counters used to be printed only
// from the uninstall path, which nothing calls: the DLL leaves through
// TerminateProcess, and the linker had dropped the function outright.
void LuaGetTableSafety_LogStats(void) {
    if (!g_statsInstalled) {
        Log("[GetTableSafety] not measured: the guard is not installed.");
        return;
    }
    const LONG64 total = g_total_calls, blocked = g_blocked_calls;
    if (total == 0) {
        Log("[GetTableSafety] measured and zero: no lookup reached it.");
        return;
    }
    Log("[GetTableSafety] %lld calls, %lld blocked (%.2f%%).",
        (long long)total, (long long)blocked,
        100.0 * (double)blocked / (double)total);
}

void UninstallLuaGetTableSafety()
{
    MH_DisableHook((void*)0x0085BC10);
    MH_RemoveHook((void*)0x0085BC10);

    LONG64 total = g_total_calls;
    LONG64 blocked = g_blocked_calls;

    if (total > 0) {
        double blockPct = 100.0 * blocked / total;
        Log("[GetTableSafety] Stats: %lld calls | %lld blocked (%.2f%%)",
            total, blocked, blockPct);
    }

    CrashDumper::FeatureSetActive("LuaGetTableSafety", false);
}

// Expose stats for periodic dump
LONG64 GetTableSafety_GetBlockedCount() { return g_blocked_calls; }
LONG64 GetTableSafety_GetTotalCount() { return g_total_calls; }