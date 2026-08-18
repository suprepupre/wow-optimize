// ============================================================================
// Module: lua_this_cache.cpp
// Description: Inlines the object lookup every Lua call to a UI method starts with.
// Safety & Threading: Main thread, alongside the Lua state.
// ============================================================================
//
// sub_4A81B0 is the prologue of every FrameScript method binding in the client -
// 674 call sites, one for each `frame:SetText`, `frame:GetWidth` and the rest.
// Every call from Lua into a UI object runs it first. What it does:
//
//     if (lua_type(L, 1) != LUA_TTABLE) error("used '.' instead of ':'?")
//     lua_rawgeti(L, 1, 0)                  // the object lives at t[0]
//     obj = lua_touserdata(L, -1)
//     lua_settop(L, -2)                     // pop it straight back off
//     if (!obj) error("non-framescript object")
//     if (!obj->vtable[4](obj, wantedType)) error("wrong object type")
//     return obj
//
// Four calls into the Lua API and a push/pop pair, to read one pointer out of
// one table slot. This reads it directly instead.
//
// ---------------------------------------------------------------------------
// The module that used to be here claimed this and did nothing
//
// It logged "Disabled: __usercall incompatible with MinHook" and returned. The
// diagnosis was wrong: sub_4A81B0 takes L in ESI, which no plain C detour can
// receive, but MinHook enters the detour with the caller's registers intact. A
// naked thunk reads ESI and passes it on, which is what this does.
//
// ---------------------------------------------------------------------------
// What lua_rawgeti does besides fetch, which is the whole difficulty
//
// It moves taint. From 0x0084E670:
//
//     v = luaH_getnum(t, key); copy the 16-byte TValue to L->top
//     if (v->taint) { if (taintEnabled && !taintSuppressed) *taintCell = v->taint; }
//     else          { pushed->taint = *taintCell; }
//     L->top += 16
//
// The first branch writes the client's global current-taint cell. Dropping it
// would make a tainted addon's calls stop spreading taint, which is not a
// performance change - it changes how the client decides what may call
// protected functions. So the fast path reproduces that write exactly.
//
// The second branch stamps the slot being pushed, and lua_settop(L, -2) pops it
// one instruction later with nothing in between, so nothing can observe it and
// nothing reproduces it. lua_settop with a negative index only moves L->top; its
// own taint stamping is on the positive branch, which this path never takes.
//
// ---------------------------------------------------------------------------
// Declining rather than reproducing
//
// The three error paths raise a Lua error, which longjmps. None is reproduced.
// Anything the fast path does not recognise - argument missing, not a table, no
// t[0], t[0] not userdata, failed type check - returns zero, and the client's
// own routine runs and produces whatever it was always going to produce. So the
// only path this has to be right about is the ordinary one, and zero is a safe
// sentinel because the original never returns normally with zero: it raises.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

#include "lua_this_cache.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

static constexpr uintptr_t kGetThis = 0x004A81B0;

// The taint cell holds a pointer; the current taint is written through it.
// The client's dword_D4139C, D413A0 and D413A4.
static constexpr uintptr_t kTaintCellPtr    = 0x00D4139C;
static constexpr uintptr_t kTaintEnabled    = 0x00D413A0;
static constexpr uintptr_t kTaintSuppressed = 0x00D413A4;

// lua_State: top 0x0C, base 0x10. TValue: value +0, tag +8, taint +12, stride 16.
static constexpr unsigned kL_top  = 0x0C;
static constexpr unsigned kL_base = 0x10;

// Table, from luaH_getnum at 0x0085C3A0: lsizenode +11, node +20. A node is
// 40 bytes: value TValue at +0, key value at +16, key tag at +24, next at +32.
static constexpr unsigned kT_lsizenode = 11;
static constexpr unsigned kT_node      = 20;
static constexpr unsigned kN_keyValue  = 16;
static constexpr unsigned kN_keyTag    = 24;
static constexpr unsigned kN_next      = 32;

static constexpr uint32_t kTagLightUserdata = 2;
static constexpr uint32_t kTagNumber        = 3;
static constexpr uint32_t kTagTable         = 5;
static constexpr uint32_t kTagUserdata      = 7;

static void* orig_GetThis = nullptr;

static bool g_installed = false;
static bool g_dead      = false;

static unsigned long g_calls = 0, g_fast = 0, g_declined = 0, g_verified = 0;

// Verify against the client for this many lookups, then one in kResampleMask+1.
static constexpr unsigned long kVerifyFirst  = 20000;
static constexpr unsigned long kResampleMask = 1023;

static volatile LONG g_armed = 0;

// The object pointer sub_4A81B0 would return, or 0 to let the original run.
// Reproduces the taint move on the way, because that is observable.
static uint32_t ComputeThis(uint32_t L, int wantedType) {
    uint32_t base = *(uint32_t*)(L + kL_base);
    uint32_t top  = *(uint32_t*)(L + kL_top);
    if (base >= top) return 0;                        // no argument 1

    const uint32_t* tv = (const uint32_t*)base;
    if (tv[2] != kTagTable) return 0;

    uint32_t t = tv[0];
    if (!t) return 0;

    // luaH_getnum(t, 0). The array part is 1-based and the client's test is
    // (unsigned)(key - 1) < sizearray, which for key 0 is 0xFFFFFFFF < sizearray
    // and never true, so key 0 is always a hash walk.
    //
    // The bucket comes from the double (key + 1.0) with its two halves summed.
    // For key 0 that is 1.0, whose halves are 0x3FF00000 and 0.
    const uint32_t kKeyZeroHash = 0x3FF00000u;
    uint32_t mask = ((1u << *(const uint8_t*)(t + kT_lsizenode)) - 1u) | 1u;
    uint32_t node = *(const uint32_t*)(t + kT_node) + 40u * (kKeyZeroHash % mask);
    if (!node) return 0;

    for (;;) {
        if (*(const uint32_t*)(node + kN_keyTag) == kTagNumber &&
            *(const double*)(node + kN_keyValue) == 0.0) break;
        node = *(const uint32_t*)(node + kN_next);
        if (!node) return 0;                          // no t[0]; the original errors
    }

    const uint32_t* v = (const uint32_t*)node;
    uint32_t obj;
    if      (v[2] == kTagLightUserdata) obj = v[0];
    else if (v[2] == kTagUserdata)      obj = v[0] + 24;
    else                                return 0;
    if (!obj) return 0;

    // The taint move lua_rawgeti performs, reproduced exactly.
    uint32_t vt = v[3];
    if (vt && *(const uint32_t*)kTaintEnabled && !*(const uint32_t*)kTaintSuppressed) {
        uint32_t* cell = *(uint32_t**)kTaintCellPtr;
        if (cell) *cell = vt;
    }

    // The virtual type check still runs; only its error path is declined.
    uint32_t vtable = *(const uint32_t*)obj;
    if (!vtable) return 0;
    uint32_t fn = *(const uint32_t*)(vtable + 16);
    if (!fn) return 0;
    typedef unsigned char (__thiscall* check_fn)(uint32_t self, int wanted);
    if (!((check_fn)fn)(obj, wantedType)) return 0;

    return obj;
}

// Modes handed back to the thunk.
//   0 - declined, run the client's routine and return its answer
//   1 - computed, but still checking: run the client's routine too and compare
//   2 - computed and trusted: do not run the client's routine at all
extern "C" int __cdecl LuaThisFast_Compute(uint32_t L, int wantedType, uint32_t* out) {
    *out = 0;
    if (g_dead || !L) return 0;
    ++g_calls;

    uint32_t mine;
    __try {
        mine = ComputeThis(L, wantedType);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_dead = true;
        Log("[LuaThis] Disabled for this session: the inline lookup faulted. The "
            "client's own routine runs from here on.");
        return 0;
    }

    if (!mine) { ++g_declined; return 0; }

    *out = mine;
    if (g_armed != 0 && (g_calls & kResampleMask) != 0) { ++g_fast; return 2; }
    return 1;
}

// Both answers in hand. Running both is safe: the only thing either writes is
// the taint cell, and both write the same value to it.
extern "C" void __cdecl LuaThisFast_Compare(uint32_t mine, uint32_t theirs) {
    if (g_dead) return;
    if (mine != theirs) {
        Log("[LuaThis] Inline lookup returned 0x%08X where the client returned "
            "0x%08X. Disabled for this session.", mine, theirs);
        g_dead = true;
        return;
    }
    unsigned long ok = ++g_verified;
    if (g_armed == 0 && ok >= kVerifyFirst) {
        InterlockedExchange(&g_armed, 1);
        Log("[LuaThis] %lu object lookups matched the client exactly. Using the "
            "inline path from here; one lookup in %d stays checked.",
            ok, (int)(kResampleMask + 1));
    }
}

// sub_4A81B0 is __usercall: L arrives in ESI, the wanted type is the one stack
// argument, and the caller cleans it. MinHook enters here with ESI still live.
static __declspec(naked) void HookedGetThis() {
    __asm {
        push ebp
        mov  ebp, esp
        sub  esp, 12                  // [ebp-4] ours, [ebp-8] theirs, [ebp-12] mode
        push ebx
        push esi
        push edi

        mov  ebx, esi                 // L, kept across the C calls
        lea  eax, [ebp-4]
        push eax
        mov  eax, [ebp+8]             // wanted type
        push eax
        push ebx
        call LuaThisFast_Compute
        add  esp, 12
        mov  [ebp-12], eax

        cmp  eax, 2
        je   trust

        // Modes 0 and 1 both run the client's routine, with L back in ESI.
        mov  esi, ebx
        mov  eax, [ebp+8]
        push eax
        mov  eax, orig_GetThis
        call eax
        add  esp, 4
        mov  [ebp-8], eax

        cmp  dword ptr [ebp-12], 1
        jne  take_theirs

        mov  ecx, [ebp-4]
        push eax                      // theirs
        push ecx                      // ours
        call LuaThisFast_Compare
        add  esp, 8

    take_theirs:
        mov  eax, [ebp-8]
        jmp  finish

    trust:
        mov  eax, [ebp-4]

    finish:
        pop  edi
        pop  esi
        pop  ebx
        mov  esp, ebp
        pop  ebp
        ret
    }
}

bool InstallLuaThisCache() {
    if (!Config::g_settings.OptLuaThisFast) return true;

    if (IsBadReadPtr((void*)kGetThis, 8)) {
        Log("[LuaThis] 0x%08X unreadable - not installing", (unsigned)kGetThis);
        return false;
    }
    if (WineSafe_CreateHook((void*)kGetThis, (void*)HookedGetThis, &orig_GetThis) != MH_OK) {
        Log("[LuaThis] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kGetThis) != MH_OK) {
        Log("[LuaThis] hook created but could not be enabled");
        return false;
    }

    g_installed = true;
    Log("[LuaThis] ACTIVE on sub_4A81B0 (0x%08X), the object lookup that starts "
        "every one of 674 Lua calls into a UI method. Four Lua API calls and a "
        "push/pop replaced by direct reads, with the taint move lua_rawgeti "
        "performs reproduced. Anything unusual is handed back to the client. "
        "Checking against it for the first %lu lookups, then one in %d.",
        (unsigned)kGetThis, kVerifyFirst, (int)(kResampleMask + 1));
    return true;
}

void UninstallLuaThisCache() {
    if (!g_installed) return;
    MH_DisableHook((void*)kGetThis);
    MH_RemoveHook((void*)kGetThis);
    g_installed = false;
}

void GetLuaThisCacheStats(uint64_t* hits, uint64_t* total) {
    if (hits)  *hits  = g_fast;
    if (total) *total = g_calls;
}

void LuaThisCache_LogStats() {
    if (!Config::g_settings.OptLuaThisFast) return;
    if (!g_installed) { Log("[LuaThis] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[LuaThis] installed but never called"); return; }
    Log("[LuaThis] %lu lookups, %lu inline, %lu handed back to the client, "
        "%lu verified against it%s",
        g_calls, g_fast, g_declined, g_verified,
        g_dead ? " - DISABLED" : (g_armed ? "" : " (still verifying)"));
}
