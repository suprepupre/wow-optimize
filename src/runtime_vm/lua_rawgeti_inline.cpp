#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <emmintrin.h>
#include "MinHook.h"
#include "version.h"   // the No Client Patches gate and the foreign-detour check live here
// ---------------------------------------------------------------------------
// The index that mattered was the one being skipped
//
// Three field sessions agreed: 125664764 calls with 194650 of them taking the
// array fast path, 11518033 with 109178, 17180787 with 88788. Between a fifth
// of a percent and one percent. A fast path that fires that rarely is not a
// fast path, it is a check.
//
// The comment above the fallback said why, and had said so all along:
// "Pseudo-indices and RegistryTable defer to the engine". lua_rawgeti is
// overwhelmingly called as lua_rawgeti(L, LUA_REGISTRYINDEX, ref) - that is how
// this client fetches every Lua callback it has ever registered through
// luaL_ref - and LUA_REGISTRYINDEX is -10000, which the range test
// `idx < 0 && idx > -10000` excludes by one.
//
// The registry is also the table where the array part is actually used, because
// luaL_ref hands out small consecutive integers. So the one index that would
// have hit the fast path was the one going to the engine.
//
// Resolving it needs no guesswork. The client's own index2adr is at 0x0084D9C0
// and says exactly where these live:
//
//     case -10000:  return (_DWORD *)(a2[5] + 104);   // l_G + 104
//     case -10002:  return a2 + 18;                   // L + 72
//
// with a2 the lua_State as dwords, so a2[5] is L->l_G at 0x14. -10001 is left
// to the engine on purpose: that case writes four fields of the lua_State
// before returning, and reproducing side effects is not what this is for.
//
// Nothing downstream changes. The slot is still checked for being a table, the
// index is still checked against the array size, and anything else still falls
// back. And the resolution is not asserted: for the first calls it is compared
// against what the client's own index2adr returns for the same arguments, and
// one disagreement retires the pseudo-index path for the session.
#include "lua_rawgeti_inline.h"
#include "lua_optimize.h"
#include "crash_dumper.h"

extern "C" void Log(const char* fmt, ...);

// Statistics (diagnostic only; plain increments)
// Whether the hook actually went in, so the report can tell a guard
// that never fired from one that was never installed.
static bool g_statsInstalled = false;

static volatile LONG64 g_total_calls = 0;
static volatile LONG64 g_array_hits = 0;
static volatile LONG64 g_nil_returns = 0;

void ClearRawGetIInlineCache() {
    // Cache removed to prevent GC/reload invalidation hazards.
}

// Original function pointer
typedef int (__cdecl *lua_rawgeti_fn)(int L, int idx, int n);
static lua_rawgeti_fn g_orig_rawgeti = nullptr;
// LUA_REGISTRYINDEX and LUA_GLOBALSINDEX. LUA_ENVIRONINDEX (-10001) is not here
// on purpose: the client's index2adr writes four lua_State fields for it.
static const int kRegistryIndex = -10000;
static const int kGlobalsIndex  = -10002;

static const long kPseudoProve = 20000;
static long g_pseudoChecked = 0;
static long g_pseudoUsed    = 0;
static bool g_pseudoDead    = false;

// sub_84D9C0 is __usercall: the index arrives in EAX, the lua_State in ECX, and
// the answer comes back in EAX. A naked thunk is the only way to reach that
// from C, and this project has done it before.
static __declspec(naked) int* __cdecl ClientIndex2Adr(int /*idx*/, void* /*L*/) {
    __asm {
        mov  eax, [esp+4]
        mov  ecx, [esp+8]
        push ebx
        push esi
        push edi
        push ebp
        mov  ebx, 0x0084D9C0
        call ebx
        pop  ebp
        pop  edi
        pop  esi
        pop  ebx
        ret
    }
}


// Optimized replacement — SAFE (no pointer caching)
#include "../allocators/loading_defrag.h"

static __forceinline int RawGetICore(int L, int idx, int n)
{
    ++g_total_calls;
    int res_val = 0;

    // Bail out during lua_State swap or active loading
    // GuardActive() reads all three of these flags inline. This site spelled
    // the loading one out as well, so it was five call and return pairs before
    // any work, on 858941049 calls a session.
    if (LuaOpt::GuardActive()) {
        return g_orig_rawgeti(L, idx, n);
    }

    // Validate L pointer
    if ((uintptr_t)L < 0x10000 || (uintptr_t)L > 0xFFE00000) {
        return g_orig_rawgeti(L, idx, n);
    }

    {
        int* L_base = *(int**)(L + 0x10);  // L->base
        int* L_top  = *(int**)(L + 0x0C);  // L->top

        // Validate stack pointers
        if ((uintptr_t)L_base < 0x10000 || (uintptr_t)L_base > 0xFFE00000 ||
            (uintptr_t)L_top < 0x10000 || (uintptr_t)L_top > 0xFFE00000) {
            return g_orig_rawgeti(L, idx, n);
        }

        // Fast inline stack lookup: bypasses CallIndex2Adr function overhead
        int* tableSlot = nullptr;
        if (idx > 0) {
            int* targetSlot = L_base + (idx - 1) * 4; // 4 DWORDs = 16 bytes per TValue
            if (targetSlot < L_top) {
                tableSlot = targetSlot;
            }
        } else if (idx < 0 && idx > -10000) {
            int* targetSlot = L_top + idx * 4;
            if (targetSlot >= L_base) {
                tableSlot = targetSlot;
            }
        } else if (idx == kRegistryIndex || idx == kGlobalsIndex) {
            // Read out of the client's own index2adr at 0x0084D9C0.
            int* slot = nullptr;
            if (idx == kGlobalsIndex) {
                slot = (int*)((uintptr_t)L + 72);
            } else {
                uintptr_t g = *(uintptr_t*)((uintptr_t)L + 0x14);   // L->l_G
                if (g > 0x10000 && g < 0xFFE00000) slot = (int*)(g + 104);
            }
            if (slot && !g_pseudoDead) {
                if (g_pseudoChecked < kPseudoProve) {
                    int* theirs = ClientIndex2Adr(idx, (void*)(uintptr_t)L);
                    ++g_pseudoChecked;
                    if (theirs != slot) {
                        g_pseudoDead = true;
                        Log("[RawGetIInline] pseudo-index path retired: for index "
                            "%d this resolved 0x%08X and the client's index2adr "
                            "resolved 0x%08X. Nothing was read from ours - the "
                            "engine answers this call - so the session is "
                            "unaffected.",
                            idx, (unsigned)(uintptr_t)slot,
                            (unsigned)(uintptr_t)theirs);
                        slot = nullptr;
                    }
                }
                if (slot) { tableSlot = slot; ++g_pseudoUsed; }
            }
        }

        // Pseudo-indices and RegistryTable defer to the engine
        if (!tableSlot) {
            return g_orig_rawgeti(L, idx, n);
        }

        int table = tableSlot[0];
        // Validate: must be a table (tt == 5)
        if (tableSlot[2] != 5 || table < 0x10000 || table > 0xFFE00000) {
            return g_orig_rawgeti(L, idx, n);
        }

        // ============================================================
        // FAST PATH: Direct array access
        // If (n-1) < sizearray, the value is in the array part.
        // This is O(1) with no cache needed.
        // ============================================================
        int sizearray = *(int*)(table + 32);
        if ((unsigned int)(n - 1) < (unsigned int)sizearray) {
            int* array = *(int**)(table + 16);
            if (!array || (uintptr_t)array < 0x10000 || (uintptr_t)array > 0xFFE00000) {
                return g_orig_rawgeti(L, idx, n);
            }

            int* src = array + (n - 1) * 4;  // 4 DWORDs = 16 bytes per TValue

            // Push TValue onto Lua stack (L->top)
            int* top = *(int**)(L + 0x0C);
            if (!top || (uintptr_t)top < 0x10000 || (uintptr_t)top > 0xFFE00000) {
                return g_orig_rawgeti(L, idx, n);
            }

            top[0] = src[0];  // value lo
            top[1] = src[1];  // value hi
            top[2] = src[2];  // tt
            top[3] = src[3];  // taint
            *(int**)(L + 0x0C) = top + 4;

            // Taint propagation — replicate sub_84E670 EXACTLY
            DWORD taint = src[3];
            ++g_array_hits;
            if (taint) {
                if (*(int*)0x00D413A0 && !*(int*)0x00D413A4)
                    *(uint32_t*)0x00D4139C = taint;
                res_val = (int)taint;
            } else {
                DWORD gt = *(uint32_t*)0x00D4139C;
                top[3] = gt;
                res_val = (int)gt;
            }
            return res_val;
        }

        // ============================================================
        // HASH PART: Integer key not in array, let original handle it
        // ============================================================
        return g_orig_rawgeti(L, idx, n);

    }
}

// The guard, as a learning phase.
//
// The whole body above used to run inside __try on every call, which put an SEH
// frame and a stack cookie into the prologue of a hook the client calls about
// 150 million times a session. Every fault it could catch is a read of L->base,
// L->top, the table slot, the table's size or its array, and the client's own
// lua_rawgeti, the fallback, reads exactly those. The only statements after the
// push touch the taint cells at fixed addresses in wow.exe. So a fault here is
// one the fallback would take as well, and the guard recovers nothing.
//
// The first kRawGetILearnCalls calls still run guarded and count what the
// handler catches. If it caught nothing the hook runs the body directly; if it
// ever caught anything the guard stays for the session and the report says so.
static constexpr unsigned kRawGetILearnCalls = 1u << 20;
static unsigned g_rawgetiGuardedCalls = 0;
static unsigned g_rawgetiCaught = 0;
static bool     g_rawgetiArmed = false;

static __declspec(noinline) int RawGetIGuarded(int L, int idx, int n)
{
    __try {
        return RawGetICore(L, idx, n);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ++g_rawgetiCaught;
        return g_orig_rawgeti(L, idx, n);
    }
}

static int __cdecl Optimized_RawGetI(int L, int idx, int n)
{
    if (g_rawgetiArmed) return RawGetICore(L, idx, n);
    if (++g_rawgetiGuardedCalls >= kRawGetILearnCalls && g_rawgetiCaught == 0)
        g_rawgetiArmed = true;
    return RawGetIGuarded(L, idx, n);
}

// Install / Uninstall
bool InstallLuaRawGetIInline()
{
    void* target = (void*)0x0084E670;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("[RawGetIInline] BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (MH_CreateHook(target, (void*)Optimized_RawGetI, (void**)&g_orig_rawgeti) != MH_OK) {
        Log("[RawGetIInline] MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[RawGetIInline] MH_EnableHook FAILED");
        return false;
    }

    Log("[RawGetIInline] Hook ACTIVE (fast inline stack lookup + array fast path)");
    g_statsInstalled = true;
    return true;
}

// Printed from the periodic report. The counters used to be printed only
// from the uninstall path, which nothing calls: the DLL leaves through
// TerminateProcess, and the linker had dropped the function outright.
void LuaRawGetIInline_LogStats(void) {
    if (!g_statsInstalled) {
        Log("[RawGetIInline] not measured: the hook is not installed.");
        return;
    }
    const LONG64 total = g_total_calls, arr = g_array_hits;
    if (total == 0) {
        Log("[RawGetIInline] measured and zero: no indexed read reached it.");
        return;
    }
    if (g_pseudoUsed || g_pseudoDead)
        Log("[RawGetIInline] the registry and globals indices resolved here "
            "rather than deferring: %ld call(s), %ld of them checked against the "
            "client's own index2adr%s. That index is how this client fetches "
            "every callback it registered, and it used to fall through.",
            g_pseudoUsed, g_pseudoChecked,
            g_pseudoDead ? " - RETIRED, one disagreed" : "");
    Log("[RawGetIInline] %lld calls, %lld from the array part (%.1f%%), "
        "%lld fell back.",
        (long long)total, (long long)arr,
        100.0 * (double)arr / (double)total, (long long)(total - arr));
    if (g_rawgetiArmed)
        Log("[RawGetIInline]   %u call(s) ran guarded and the handler caught nothing, "
            "so the body now runs without an exception frame.", g_rawgetiGuardedCalls);
    else if (g_rawgetiCaught)
        Log("[RawGetIInline]   the guard caught %u fault(s) in %u guarded call(s) and "
            "stays on for this session.", g_rawgetiCaught, g_rawgetiGuardedCalls);
    else
        Log("[RawGetIInline]   %u of %u guarded call(s) so far, nothing caught; the "
            "exception frame is still on.", g_rawgetiGuardedCalls, kRawGetILearnCalls);
}

void UninstallLuaRawGetIInline()
{
    MH_DisableHook((void*)0x0084E670);
    MH_RemoveHook((void*)0x0084E670);

    LONG64 total = g_total_calls;
    LONG64 arr   = g_array_hits;

    if (total > 0) {
        double arrPct   = 100.0 * arr / total;
        Log("[RawGetIInline] Stats: %lld calls | %lld array (%.1f%%) | %lld fallback",
            total, arr, arrPct, total - arr);
    }
}