// ================================================================
// lua_pushvalue Fast Path
// ================================================================
// lua_pushvalue copies a TValue from one stack slot to top.
// Called heavily during function calls, table operations, and
// closure creation. Direct memory copy avoids function call overhead.
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

static volatile LONG64 g_pushvalue_calls = 0;
static volatile LONG64 g_pushvalue_hits = 0;

typedef void (__cdecl *lua_pushvalue_fn)(void* L, int idx);
static lua_pushvalue_fn g_orig_pushvalue = nullptr;

static void __cdecl Hooked_PushValue(void* L, int idx) {
    InterlockedIncrement64(&g_pushvalue_calls);

    __try {
        uintptr_t L_addr = (uintptr_t)L;
        if (L_addr < 0x10000 || L_addr > 0xBFFF0000) goto fallback;

        // Read base and top pointers
        uint8_t** base_ptr = (uint8_t**)(L_addr + 0x10);
        uint8_t** top_ptr = (uint8_t**)(L_addr + 0x0C);
        uint8_t* base = *base_ptr;
        uint8_t* top = *top_ptr;

        if (!base || !top) goto fallback;
        if ((uintptr_t)base < 0x10000 || (uintptr_t)top < 0x10000) goto fallback;

        // Resolve index to stack slot (TValue = 16 bytes in WoW 3.3.5a)
        uint8_t* src;
        if (idx > 0) {
            src = base + (idx - 1) * 16;
        } else if (idx < 0 && idx > -10000) {
            src = top + idx * 16;
        } else {
            goto fallback;
        }

        // Validate source is within stack bounds
        if ((uintptr_t)src < (uintptr_t)base || (uintptr_t)src >= (uintptr_t)top) goto fallback;
        if ((uintptr_t)src < 0x10000 || (uintptr_t)src > 0xBFFF0000) goto fallback;

        // Copy 16-byte TValue directly to top
        uint64_t* dst64 = (uint64_t*)top;
        const uint64_t* src64 = (const uint64_t*)src;
        dst64[0] = src64[0];  // value (8 bytes)
        dst64[1] = src64[1];  // tt + taint (8 bytes)

        // Advance top by 16 bytes
        *top_ptr = top + 16;

        InterlockedIncrement64(&g_pushvalue_hits);
        return;
    } __except(EXCEPTION_EXECUTE_HANDLER) {}

fallback:
    g_orig_pushvalue(L, idx);
}

bool InstallLuaPushValueFast(void) {
    // DISABLED: lua_pushvalue uses __usercall or non-standard prologue.
    // MinHook requires standard prologue (push ebp; mov ebp,esp) for safe hooking.
    // WoW's Lua VM functions often use custom calling conventions that break
    // MinHook's trampoline generation. Hooking these causes crashes or freezes
    // during UI reload when the VM state is being swapped.
    // The performance gain from direct stack copy doesn't justify the crash risk.
    Log("[PushValueFast] SKIPPED: non-standard prologue (unsafe for MinHook)");
    return false;
}

void ShutdownLuaPushValueFast(void) {
    MH_DisableHook((void*)0x0084E630);

    LONG64 calls = g_pushvalue_calls;
    LONG64 hits = g_pushvalue_hits;
    if (calls > 0) {
        Log("[PushValueFast] Stats: %lld calls, %lld fast (%.1f%%)",
            calls, hits, 100.0 * hits / calls);
    }
}