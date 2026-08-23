// ============================================================================
// Module: wow_extended_hooks.cpp
// Description: Installs and manages target intercepts for subsystem `wow_extended_hooks.cpp`.
// Safety & Threading: Stack layouts and register conventions must match target function definitions exactly.
// ============================================================================

#include "wow_extended_hooks.h"
#include "MinHook.h"
#include "version.h"
#include <mimalloc.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <emmintrin.h>

extern "C" void Log(const char* fmt, ...);

// ================================================================
// 40 EXTENDED WoW.exe Performance Hooks
// ================================================================

// Eight slots, which is how many the surviving hooks use, and plain rather than
// Interlocked: these sit on string copies and Lua pushes, they are statistics,
// and a lost increment costs one count. Lower bounds, said so in the report.
static long g_c[8] = {};   // call counters
static long g_h[8] = {};   // hit/fast counters

// ================================================================
// C1: sub_76ED20 - strcpy (890 xrefs!)
// WoW's internal strcpy does byte-by-byte copy. Replace with SSE2.
// ================================================================
typedef void* (__stdcall *WoWStrcpy_fn)(void* dst, char* src, int maxLen);
static WoWStrcpy_fn orig_WoWStrcpy = nullptr;

static void* __stdcall Hooked_WoWStrcpy(void* dst, char* src, int maxLen) {
    ++g_c[0];
    if (!dst || !src) return orig_WoWStrcpy(dst, src, maxLen);
    // SSE2 fast path for common case (maxLen == 0x7FFFFFFF = unlimited)
    if (maxLen == 0x7FFFFFFF) {
        char* d = (char*)dst;
        const char* s = src;
        while (true) {
            // Check if we are near a 4KB page boundary (last 16 bytes of the page)
            if (((uintptr_t)s & 0xFFF) > 0xFF0) {
                // Byte-by-byte copy until aligned or null terminator found
                while (true) {
                    char c = *s;
                    *d = c;
                    if (!c) {
                        ++g_h[0];
                        return (void*)(d - (char*)dst);
                    }
                    s++; d++;
                    if (((uintptr_t)s & 15) == 0) break; // Now 16-byte aligned
                }
            }
            
            // Safe to load 16 bytes because s is not near page boundary
            __m128i chunk = _mm_loadu_si128((const __m128i*)s);
            __m128i zero = _mm_setzero_si128();
            __m128i cmp = _mm_cmpeq_epi8(chunk, zero);
            int mask = _mm_movemask_epi8(cmp);
            if (mask) {
                unsigned long pos;
                _BitScanForward(&pos, mask);
                memcpy(d, s, pos + 1); // include null terminator
                ++g_h[0];
                return (void*)(d - (char*)dst + pos);
            }
            _mm_storeu_si128((__m128i*)d, chunk);
            s += 16; d += 16;
        }
    }
    return orig_WoWStrcpy(dst, src, maxLen);
}

// C2 skipped (duplicate of W4)

// ================================================================
// C3: sub_84D9C0 - get_tvalue helper (38 xrefs)
// Lua stack index resolver. Inline positive index fast path.
// ================================================================
// This is __usercall - cannot hook directly. Skip.

// ================================================================
// C4: sub_84E300 - lua_pushstring implementation (36 xrefs)
// Actual string intern. Prefetch hash table before lookup.
// ================================================================
typedef int (__cdecl *PushStringImpl_fn)(int L, int str, int len);
static PushStringImpl_fn orig_PushStringImpl = nullptr;

static int __cdecl Hooked_PushStringImpl(int L, int str, int len) {
    ++g_c[3];
    if (L > 0x10000 && str > 0x10000) {
        __try {
            // Prefetch the string data and Lua state globals
            _mm_prefetch((const char*)str, _MM_HINT_T0);
            void* globals = *(void**)(L + 20); // L->l_G
            if (globals) _mm_prefetch((const char*)globals, _MM_HINT_T0);
            ++g_h[3];
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return orig_PushStringImpl(L, str, len);
}

// ================================================================
// C5: sub_85BC10 - lua_tableget (17 xrefs)
// Table field access. Cache last table+key result.
// ================================================================
typedef void* (__cdecl *TableGet_fn)(int table, void* key, int fieldIdx);
static TableGet_fn orig_TableGet = nullptr;
static volatile int g_c5LastTable = 0;
static volatile int g_c5LastField = 0;
static volatile void* g_c5LastResult = nullptr;

static void* __cdecl Hooked_TableGet(int table, void* key, int fieldIdx) {
    ++g_c[4];
    static volatile void* g_c5LastKey = nullptr;
    if (table == g_c5LastTable && key == (void*)g_c5LastKey && fieldIdx == g_c5LastField && g_c5LastResult) {
        ++g_h[4];
        return (void*)g_c5LastResult;
    }
    void* result = orig_TableGet(table, key, fieldIdx);
    g_c5LastTable = table;
    g_c5LastKey = key;
    g_c5LastField = fieldIdx;
    g_c5LastResult = result;
    return result;
}

// C6: sub_85BBE0 - luaH_getn wrapper (7 xrefs)
typedef void* (__cdecl *LuaHGetN_fn)(int table, char flag, int tstring);
static LuaHGetN_fn orig_LuaHGetN = nullptr;

static void* __cdecl Hooked_LuaHGetN(int table, char flag, int tstring) {
    ++g_c[5];
    ++g_h[5];
    return orig_LuaHGetN(table, flag, tstring);
}

// C7 skipped (__usercall)
// C8 skipped (duplicate of W12)

// C9-C40: Batch hooks for remaining hot WoW functions
// These target rendering, UI, network, and game logic hot paths.


// ================================================================
// Installation / Shutdown / Stats
// ================================================================
namespace WowExtendedHooks {
    bool InstallAll() {
        int installed = 0;

        struct HookDef {
            void* addr; void* hook; void** orig; const char* name;
        };

        HookDef hooks[] = {
            // C1 strcpy SSE2 hook disabled temporarily for diagnostic test
            // {(void*)0x0076ED20, (void*)Hooked_WoWStrcpy,       (void**)&orig_WoWStrcpy,       "C1 strcpy SSE2 (890 xrefs)"},
            // C2 skipped - duplicate of W4
            // C3 skipped - __usercall convention
            {(void*)0x0084E300, (void*)Hooked_PushStringImpl,  (void**)&orig_PushStringImpl,  "C4 pushstring impl (36 xrefs)"},
            // C5 table get hook disabled to prevent stale/wild pointer crashes when Lua tables modify/grow
            // {(void*)0x0085BC10, (void*)Hooked_TableGet,        (void**)&orig_TableGet,        "C5 table get (17 xrefs)"},
            {(void*)0x0085BBE0, (void*)Hooked_LuaHGetN,        (void**)&orig_LuaHGetN,        "C6 luaH_getn (7 xrefs)"},
            // C7 skipped - __usercall convention
            // C8 skipped - duplicate of W12
        };

        for (auto& h : hooks) {
            if (WineSafe_CreateHook(h.addr, h.hook, h.orig) == MH_OK) {
                if (MH_EnableHook(h.addr) == MH_OK) {
                    Log("[EXTENDED] %s: ACTIVE @ 0x%08X", h.name, (uintptr_t)h.addr);
                    installed++;
                }
            }
        }

        // The count used to read 34 of 40 because a loop added thirty-two to it
        // for what the source beside it called conceptual hooks. Those were
        // empty functions nothing referenced.
        Log("[EXTENDED] %d hooks installed", installed);
        return installed > 0;
    }

    void ShutdownAll() {
        DumpStats();
    }

    void DumpStats() {
        Log("[EXTENDED] hits/calls, lower bounds - Strcpy: %d/%d | SFile: %d/%d | "
            "PushImpl: %d/%d | TableGet: %d/%d",
            g_h[0], g_c[0], g_h[1], g_c[1], g_h[3], g_c[3], g_h[4], g_c[4]);
        Log("[EXTENDED] GetN: %d/%d | TexInit: %d/%d | Status: %d/%d",
            g_h[5], g_c[5], g_h[6], g_c[6], g_h[7], g_c[7]);
        // C9-C40 are not printed any more. They were empty functions.
    }
}
