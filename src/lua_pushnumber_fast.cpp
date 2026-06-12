// ================================================================
// lua_pushnumber Fast Path
// ================================================================
// Replaces sub_84E2A0 (lua_pushnumber) with an optimized version that:
// - Directly writes TValue to Lua stack without function call overhead
// - Skips taint check for pure numeric values (numbers have no taint)
// - Validates stack pointer before write
//
// Original implementation (at 0x84E2A0):
//   1. Read L->top
//   2. Write value (double) to top[0..1]
//   3. Write tt=3 (LUA_TNUMBER) to top[2]
//   4. Write taint from global to top[3]
//   5. Increment L->top by 16 bytes
//
// This is called ~5M+ times per session for combat log, health bars,
// cooldown timers, damage numbers, etc.
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "lua_pushnumber_fast.h"
#include "lua_optimize.h"

extern "C" void Log(const char* fmt, ...);

// Statistics
static volatile LONG64 g_pushnum_calls = 0;
static volatile LONG64 g_pushnum_hits = 0;

// Original function pointer
typedef void (__cdecl *lua_pushnumber_fn)(void* L, double n);
static lua_pushnumber_fn g_orig_pushnumber = nullptr;

// Taint globals
static constexpr uintptr_t ADDR_taint_global  = 0x00D4139C;
static constexpr uintptr_t ADDR_taint_enabled = 0x00D413A0;
static constexpr uintptr_t ADDR_taint_skip    = 0x00D413A4;

// Optimized replacement
static void __cdecl Optimized_PushNumber(void* L, double n)
{
    InterlockedIncrement64(&g_pushnum_calls);

    // Bail out during lua_State swap — L->top is being torn down
    if (LuaOpt::IsReloading() || LuaOpt::IsSwapping()) {
        g_orig_pushnumber(L, n);
        return;
    }

    // Validate L pointer
    uintptr_t L_addr = (uintptr_t)L;
    if (L_addr < 0x10000 || L_addr > 0xBFFF0000) {
        g_orig_pushnumber(L, n);
        return;
    }

    __try {
        // Read L->top
        DWORD* top = *(DWORD**)(L_addr + 0x0C);
        if (!top || (uintptr_t)top < 0x10000 || (uintptr_t)top > 0xBFFF0000) {
            g_orig_pushnumber(L, n);
            return;
        }

        // Write TValue directly: value (8 bytes) + tt (4 bytes) + taint (4 bytes)
        uint64_t value_bits;
        memcpy(&value_bits, &n, sizeof(double));

        top[0] = (DWORD)(value_bits & 0xFFFFFFFF);         // value lo
        top[1] = (DWORD)(value_bits >> 32);                // value hi
        top[2] = 3;                                         // tt = LUA_TNUMBER
        top[3] = *(DWORD*)ADDR_taint_global;               // taint from global

        // Advance L->top
        *(DWORD**)(L_addr + 0x0C) = top + 4;

        InterlockedIncrement64(&g_pushnum_hits);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        g_orig_pushnumber(L, n);
    }
}

bool InstallLuaPushNumberFast()
{
    void* target = (void*)0x0084E2A0;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("[PushNumFast] BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (MH_CreateHook(target, (void*)Optimized_PushNumber, (void**)&g_orig_pushnumber) != MH_OK) {
        Log("[PushNumFast] MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[PushNumFast] MH_EnableHook FAILED");
        return false;
    }

    Log("[PushNumFast] ACTIVE: direct stack write for lua_pushnumber (0x%08X)", (uintptr_t)target);
    return true;
}

void ShutdownLuaPushNumberFast()
{
    MH_DisableHook((void*)0x0084E2A0);

    LONG64 total = g_pushnum_calls;
    LONG64 hits  = g_pushnum_hits;
    if (total > 0) {
        Log("[PushNumFast] Stats: %lld calls, %lld fast (%.1f%%)",
            total, hits, 100.0 * hits / total);
    }
}