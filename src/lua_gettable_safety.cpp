// ================================================================
// luaV_gettable Safety Patch - Crash Fix for sub_85BC10
// ================================================================
// Fixes ACCESS_VIOLATION at 0x85BC2C where a2[2] (TValue type field)
// contains garbage and is used as an unsanitized array index.
//
// Original crash:
//   mov ecx, [esi+14h]           ; ecx = table->node_array
//   mov eax, [ecx+eax*4+0A0h]    ; eax = node_array[a2[2] + 0xA0/4]
//
// When a2[2] contains 0x1A248600 instead of valid type (0-8), the
// scaled index overflows and accesses invalid memory.
//
// Fix: Hook sub_85BC10, validate a2[2] is within safe bounds before
// calling original. Return nil object for invalid types.
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "crash_dumper.h"

extern "C" void Log(const char* fmt, ...);

// ----------------------------------------------------------------
// Function signature
// sub_85BC10: _DWORD *__cdecl(int a1, _DWORD *a2, int a3)
// ----------------------------------------------------------------
typedef void* (__cdecl* sub_85BC10_fn)(int a1, uint32_t* a2, int a3);
static sub_85BC10_fn g_orig_sub_85BC10 = nullptr;

// Nil object sentinel at 0xA46F78 (same as used by original function)
static void* g_nil_object = (void*)0x00A46F78;

// Maximum valid TValue type tag. WoW Lua types: 0=nil, 1=boolean, 
// 2=lightuserdata, 3=number, 4=string, 5=table, 6=function, 
// 7=userdata, 8=thread. Types above 15 are definitely invalid.
static constexpr uint32_t MAX_VALID_TYPE = 15;

// Statistics
static volatile LONG64 g_total_calls = 0;
static volatile LONG64 g_blocked_calls = 0;

// ----------------------------------------------------------------
// Safe wrapper - validates TValue type before calling original
// ----------------------------------------------------------------
static void* __cdecl Safe_sub_85BC10(int a1, uint32_t* a2, int a3)
{
    InterlockedIncrement64(&g_total_calls);

    // Validate a2 pointer
    if (!a2 || (uintptr_t)a2 < 0x10000 || (uintptr_t)a2 > 0xBFFF0000) {
        InterlockedIncrement64(&g_blocked_calls);
        return g_nil_object;
    }

    // Validate a2[2] (TValue type field) is within safe bounds
    // The original code uses a2[2] as array index: node_array[a2[2]] + offset
    // Valid Lua types are 0-8. Anything above 15 is definitely garbage.
    __try {
        uint32_t typeTag = a2[2];
        
        if (typeTag > MAX_VALID_TYPE) {
            // Invalid type tag - would cause out-of-bounds access
            InterlockedIncrement64(&g_blocked_calls);
            return g_nil_object;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Can't even read a2[2] safely
        InterlockedIncrement64(&g_blocked_calls);
        return g_nil_object;
    }

    // Type is valid, call original function
    __try {
        return g_orig_sub_85BC10(a1, a2, a3);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Original crashed despite valid-looking type - memory corruption elsewhere
        InterlockedIncrement64(&g_blocked_calls);
        return g_nil_object;
    }
}

// ----------------------------------------------------------------
// Install / Uninstall
// ----------------------------------------------------------------
bool InstallLuaGetTableSafety()
{
    void* target = (void*)0x0085BC10;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("[GetTableSafety] BAD PROLOGUE at 0x%08X (expected 55 8B, got %02X %02X)", 
            (uintptr_t)target, p[0], p[1]);
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
    return true;
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