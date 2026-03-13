#include "lua_optimize.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <psapi.h>
#include <mimalloc.h>

extern "C" void Log(const char* fmt, ...);

// ================================================================
//  Lua 5.1 Types
// ================================================================

typedef struct lua_State lua_State;
typedef double lua_Number;

#define LUA_GCSTOP       0
#define LUA_GCRESTART    1
#define LUA_GCCOLLECT    2
#define LUA_GCCOUNT      3
#define LUA_GCCOUNTB     4
#define LUA_GCSTEP       5
#define LUA_GCSETPAUSE   6
#define LUA_GCSETSTEPMUL 7

#define LUA_GLOBALSINDEX (-10002)

// ================================================================
//  Function Pointer Types
// ================================================================

typedef int         (__cdecl *fn_lua_gc)(lua_State* L, int what, int data);
typedef int         (__cdecl *fn_lua_gettop)(lua_State* L);
typedef void        (__cdecl *fn_lua_settop)(lua_State* L, int index);
typedef lua_Number  (__cdecl *fn_lua_tonumber)(lua_State* L, int index);
typedef int         (__cdecl *fn_lua_toboolean)(lua_State* L, int index);
typedef void        (__cdecl *fn_lua_pushnumber)(lua_State* L, lua_Number n);
typedef void        (__cdecl *fn_lua_pushboolean)(lua_State* L, int b);
typedef const char* (__cdecl *fn_lua_pushstring)(lua_State* L, const char* s);
typedef void        (__cdecl *fn_lua_pushnil)(lua_State* L);
typedef void        (__cdecl *fn_lua_setfield)(lua_State* L, int index, const char* k);
typedef void        (__cdecl *fn_lua_getfield)(lua_State* L, int index, const char* k);
typedef int         (__cdecl *fn_lua_type)(lua_State* L, int index);
typedef void        (__cdecl *fn_luaS_resize)(lua_State* L, int newsize);
typedef void        (__cdecl *fn_FrameScript_Execute)(const char* code,
                                                       const char* source,
                                                       int unknown);

// ================================================================
//  Known Addresses — build 12340 (IDA Pro)
// ================================================================

namespace Addr {
    static constexpr uintptr_t lua_State_ptr       = 0x00D3F78C;
    static constexpr uintptr_t FrameScript_Execute = 0x00819210;
    static constexpr uintptr_t luaS_resize         = 0x00856AF0;
    static constexpr uintptr_t lua_gc              = 0x0084ED50;
    static constexpr uintptr_t lua_gettop          = 0x0084DBD0;
    static constexpr uintptr_t lua_settop          = 0x0084DBF0;
    static constexpr uintptr_t lua_pushnumber      = 0x0084E2A0;
    static constexpr uintptr_t lua_pushboolean     = 0x0084E4D0;
    static constexpr uintptr_t lua_pushstring      = 0x0084E350;
    static constexpr uintptr_t lua_pushnil         = 0x0084E280;
    static constexpr uintptr_t lua_setfield        = 0x0084E900;
    static constexpr uintptr_t lua_getfield        = 0x0084E590;
    static constexpr uintptr_t lua_tonumber        = 0x0084E030;
    static constexpr uintptr_t lua_toboolean       = 0x0084E0B0;
    static constexpr uintptr_t lua_type            = 0x0084DEB0;
}

// ================================================================
//  Resolved API
// ================================================================

static struct {
    lua_State*              L = nullptr;

    fn_lua_gc               lua_gc = nullptr;
    fn_lua_gettop           lua_gettop = nullptr;
    fn_lua_settop           lua_settop = nullptr;
    fn_lua_tonumber         lua_tonumber = nullptr;
    fn_lua_toboolean        lua_toboolean = nullptr;
    fn_lua_pushnumber       lua_pushnumber = nullptr;
    fn_lua_pushboolean      lua_pushboolean = nullptr;
    fn_lua_pushstring       lua_pushstring = nullptr;
    fn_lua_pushnil          lua_pushnil = nullptr;
    fn_lua_setfield         lua_setfield = nullptr;
    fn_lua_getfield         lua_getfield = nullptr;
    fn_lua_type             lua_type = nullptr;
    fn_luaS_resize          luaS_resize = nullptr;
    fn_FrameScript_Execute  FrameScript_Execute = nullptr;
} Api;

// ================================================================
//  Configuration — 4-tier GC stepping
// ================================================================

static struct {
    int  gcPause        = 110;
    int  gcStepMul      = 300;
    int  normalStepKB   = 64;
    int  combatStepKB   = 16;
    int  idleStepKB     = 128;
    int  loadingStepKB  = 256;
    bool manualGCMode   = true;

    bool inCombat       = false;
    bool isIdle         = false;
    bool isLoading      = false;
} Config;

// ================================================================
//  Runtime State
// ================================================================

static volatile LONG g_luaInitState = 0;
static volatile bool g_addressesValid = false;

static struct {
    bool   initialized     = false;
    bool   gcOptimized     = false;

    int    origGCPause     = 200;
    int    origGCStepMul   = 200;

    double luaMemoryKB     = 0.0;
    int    gcStepsTotal    = 0;
    int    fullCollects    = 0;

    int    statsUpdateCounter = 0;

    const char* lastModeName = "unknown";
} State;

// ================================================================
//  Memory Validation
// ================================================================

static bool IsExecutableMemory(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static bool IsReadableMemory(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & PAGE_NOACCESS) == 0 &&
           (mbi.Protect & PAGE_GUARD) == 0;
}

// ================================================================
//  Address Resolution
// ================================================================

static bool ResolveAddresses() {
    Log("[LuaOpt] Resolving addresses for build 12340...");

    int found = 0;
    int failed = 0;

    #define RESOLVE(field, addr, type, name)                             \
        if (IsExecutableMemory(addr)) {                                  \
            Api.field = (type)(addr);                                    \
            found++;                                                     \
            Log("[LuaOpt]   %-22s 0x%08X  OK", name, (unsigned)(addr));  \
        } else {                                                         \
            failed++;                                                    \
            Log("[LuaOpt]   %-22s 0x%08X  INVALID", name, (unsigned)(addr)); \
        }

    RESOLVE(lua_gc,          Addr::lua_gc,          fn_lua_gc,          "lua_gc");
    RESOLVE(lua_gettop,      Addr::lua_gettop,      fn_lua_gettop,      "lua_gettop");
    RESOLVE(lua_settop,      Addr::lua_settop,      fn_lua_settop,      "lua_settop");
    RESOLVE(lua_tonumber,    Addr::lua_tonumber,     fn_lua_tonumber,    "lua_tonumber");
    RESOLVE(lua_toboolean,   Addr::lua_toboolean,    fn_lua_toboolean,   "lua_toboolean");
    RESOLVE(lua_pushnumber,  Addr::lua_pushnumber,   fn_lua_pushnumber,  "lua_pushnumber");
    RESOLVE(lua_pushboolean, Addr::lua_pushboolean,  fn_lua_pushboolean, "lua_pushboolean");
    RESOLVE(lua_pushstring,  Addr::lua_pushstring,   fn_lua_pushstring,  "lua_pushstring");
    RESOLVE(lua_pushnil,     Addr::lua_pushnil,      fn_lua_pushnil,     "lua_pushnil");
    RESOLVE(lua_setfield,    Addr::lua_setfield,     fn_lua_setfield,    "lua_setfield");
    RESOLVE(lua_getfield,    Addr::lua_getfield,     fn_lua_getfield,    "lua_getfield");
    RESOLVE(lua_type,        Addr::lua_type,         fn_lua_type,        "lua_type");
    RESOLVE(luaS_resize,     Addr::luaS_resize,     fn_luaS_resize,     "luaS_resize");

    RESOLVE(FrameScript_Execute, Addr::FrameScript_Execute,
            fn_FrameScript_Execute, "FrameScript_Execute");

    #undef RESOLVE

    if (IsReadableMemory(Addr::lua_State_ptr)) {
        Log("[LuaOpt]   %-22s 0x%08X  OK (data)", "lua_State* ptr", (unsigned)Addr::lua_State_ptr);
        found++;
    } else {
        Log("[LuaOpt]   %-22s 0x%08X  INVALID", "lua_State* ptr", (unsigned)Addr::lua_State_ptr);
        failed++;
    }

    Log("[LuaOpt] Resolved: %d OK, %d FAILED", found, failed);

    if (!Api.lua_gc) {
        Log("[LuaOpt] CRITICAL: lua_gc not available");
        return false;
    }

    return true;
}

// ================================================================
//  Get lua_State*
// ================================================================

static lua_State* ReadLuaState() {
    if (!IsReadableMemory(Addr::lua_State_ptr)) return nullptr;

    __try {
        lua_State* L = *(lua_State**)(Addr::lua_State_ptr);
        if ((uintptr_t)L < 0x00010000 || (uintptr_t)L > 0x7FFFFFFF)
            return nullptr;
        if (!IsReadableMemory((uintptr_t)L))
            return nullptr;
        return L;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// ================================================================
//  Lua Allocator Replacement — mimalloc for Lua VM
// ================================================================

typedef void* (__cdecl *lua_Alloc_fn)(void* ud, void* ptr, size_t osize, size_t nsize);

static lua_Alloc_fn g_origLuaAlloc = nullptr;
static void*        g_origLuaAllocUD = nullptr;
static uintptr_t    g_globalStateAddr = 0;
static bool         g_luaAllocReplaced = false;

static volatile LONG g_luaAllocStats_malloc = 0;
static volatile LONG g_luaAllocStats_free = 0;
static volatile LONG g_luaAllocStats_realloc = 0;
static volatile LONG g_luaAllocStats_freeLegacy = 0;
static volatile LONG g_luaAllocStats_reallocMigrate = 0;

static void* __cdecl MimallocLuaAlloc(void* ud, void* ptr, size_t osize, size_t nsize) {
    if (nsize == 0) {
        if (ptr) {
            if (mi_is_in_heap_region(ptr)) {
                mi_free(ptr);
                InterlockedIncrement(&g_luaAllocStats_free);
            } else {
                g_origLuaAlloc(g_origLuaAllocUD, ptr, osize, 0);
                InterlockedIncrement(&g_luaAllocStats_freeLegacy);
            }
        }
        return NULL;
    }

    if (ptr == NULL) {
        InterlockedIncrement(&g_luaAllocStats_malloc);
        return mi_malloc(nsize);
    }

    if (mi_is_in_heap_region(ptr)) {
        InterlockedIncrement(&g_luaAllocStats_realloc);
        return mi_realloc(ptr, nsize);
    }

    InterlockedIncrement(&g_luaAllocStats_reallocMigrate);
    void* newPtr = mi_malloc(nsize);
    if (newPtr) {
        size_t copySize = (osize < nsize) ? osize : nsize;
        memcpy(newPtr, ptr, copySize);
        g_origLuaAlloc(g_origLuaAllocUD, ptr, osize, 0);
    }
    return newPtr;
}

static bool ReplaceLuaAllocator(lua_State* L) {
    if (!L || g_luaAllocReplaced) return false;

    uintptr_t L_addr = (uintptr_t)L;

    Log("[LuaOpt-Alloc] ========================================");
    Log("[LuaOpt-Alloc]  Lua Allocator Replacement");
    Log("[LuaOpt-Alloc] ========================================");

    __try {
        if (!IsReadableMemory(L_addr + 0x14)) {
            Log("[LuaOpt-Alloc] ERROR: Cannot read L+0x14");
            return false;
        }

        g_globalStateAddr = *(uintptr_t*)(L_addr + 0x14);
        Log("[LuaOpt-Alloc]  global_State* = 0x%08X", (unsigned)g_globalStateAddr);

        if (!IsReadableMemory(g_globalStateAddr + 0x10)) {
            Log("[LuaOpt-Alloc] ERROR: Cannot read global_State");
            return false;
        }

        uintptr_t currentAlloc = *(uintptr_t*)(g_globalStateAddr + 0x0C);
        uintptr_t currentUD    = *(uintptr_t*)(g_globalStateAddr + 0x10);

        Log("[LuaOpt-Alloc]  Current frealloc = 0x%08X", (unsigned)currentAlloc);
        Log("[LuaOpt-Alloc]  Current ud       = 0x%08X", (unsigned)currentUD);

        if (currentAlloc != 0x008558E0) {
            Log("[LuaOpt-Alloc] WARNING: frealloc is not 0x008558E0 (got 0x%08X)",
                (unsigned)currentAlloc);
            Log("[LuaOpt-Alloc] Unexpected allocator — skipping replacement for safety");
            return false;
        }

        if (!IsExecutableMemory(currentAlloc)) {
            Log("[LuaOpt-Alloc] ERROR: frealloc is not executable");
            return false;
        }

        g_origLuaAlloc   = (lua_Alloc_fn)currentAlloc;
        g_origLuaAllocUD = (void*)currentUD;

        void* testPtr = g_origLuaAlloc(g_origLuaAllocUD, NULL, 0, 64);
        if (!testPtr) {
            Log("[LuaOpt-Alloc] ERROR: Original allocator test failed");
            return false;
        }
        g_origLuaAlloc(g_origLuaAllocUD, testPtr, 64, 0);
        Log("[LuaOpt-Alloc]  Original allocator test: OK");

        void* miTestPtr = mi_malloc(64);
        if (!miTestPtr) {
            Log("[LuaOpt-Alloc] ERROR: mimalloc test failed");
            return false;
        }
        if (!mi_is_in_heap_region(miTestPtr)) {
            Log("[LuaOpt-Alloc] ERROR: mi_is_in_heap_region check failed");
            mi_free(miTestPtr);
            return false;
        }
        mi_free(miTestPtr);
        Log("[LuaOpt-Alloc]  mimalloc test: OK");

        DWORD oldProtect;
        VirtualProtect((void*)(g_globalStateAddr + 0x0C), 4, PAGE_READWRITE, &oldProtect);

        *(uintptr_t*)(g_globalStateAddr + 0x0C) = (uintptr_t)&MimallocLuaAlloc;

        uintptr_t verify = *(uintptr_t*)(g_globalStateAddr + 0x0C);
        if (verify != (uintptr_t)&MimallocLuaAlloc) {
            Log("[LuaOpt-Alloc] ERROR: Write verification failed!");
            *(uintptr_t*)(g_globalStateAddr + 0x0C) = (uintptr_t)g_origLuaAlloc;
            VirtualProtect((void*)(g_globalStateAddr + 0x0C), 4, oldProtect, &oldProtect);
            return false;
        }

        VirtualProtect((void*)(g_globalStateAddr + 0x0C), 4, oldProtect, &oldProtect);

        g_luaAllocReplaced = true;

        if (Api.lua_gc) {
            int memBefore = Api.lua_gc(L, LUA_GCCOUNT, 0);
            Log("[LuaOpt-Alloc]  Post-replace Lua memory: %d KB", memBefore);
        }

        Log("[LuaOpt-Alloc]  >>> ALLOCATOR REPLACED <<<");
        Log("[LuaOpt-Alloc]  Old: 0x%08X (WoW pool + SMemAlloc)", (unsigned)(uintptr_t)g_origLuaAlloc);
        Log("[LuaOpt-Alloc]  New: 0x%08X (mimalloc)", (unsigned)(uintptr_t)&MimallocLuaAlloc);
        Log("[LuaOpt-Alloc] ========================================");

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt-Alloc] EXCEPTION during allocator replacement");
        return false;
    }
}

static void RestoreLuaAllocator() {
    if (!g_luaAllocReplaced || !g_origLuaAlloc || !g_globalStateAddr) return;

    __try {
        if (IsReadableMemory(g_globalStateAddr + 0x0C)) {
            DWORD oldProtect;
            VirtualProtect((void*)(g_globalStateAddr + 0x0C), 4, PAGE_READWRITE, &oldProtect);
            *(uintptr_t*)(g_globalStateAddr + 0x0C) = (uintptr_t)g_origLuaAlloc;
            VirtualProtect((void*)(g_globalStateAddr + 0x0C), 4, oldProtect, &oldProtect);
            Log("[LuaOpt-Alloc] Allocator restored to original (0x%08X)",
                (unsigned)(uintptr_t)g_origLuaAlloc);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt-Alloc] EXCEPTION restoring allocator");
    }

    Log("[LuaOpt-Alloc] Final stats: malloc=%ld free=%ld realloc=%ld freeLegacy=%ld migrated=%ld",
        g_luaAllocStats_malloc, g_luaAllocStats_free,
        g_luaAllocStats_realloc, g_luaAllocStats_freeLegacy,
        g_luaAllocStats_reallocMigrate);

    g_luaAllocReplaced = false;
}

static void LogLuaAllocStats() {
    if (!g_luaAllocReplaced) return;
    Log("[LuaOpt-Alloc] mimalloc Lua stats: malloc=%ld free=%ld realloc=%ld legacy_free=%ld migrated=%ld",
        g_luaAllocStats_malloc, g_luaAllocStats_free,
        g_luaAllocStats_realloc, g_luaAllocStats_freeLegacy,
        g_luaAllocStats_reallocMigrate);
}

static void ResetAllocStats() {
    g_luaAllocReplaced = false;
    g_globalStateAddr = 0;
    g_origLuaAlloc = nullptr;
    g_origLuaAllocUD = nullptr;
    g_luaAllocStats_malloc = 0;
    g_luaAllocStats_free = 0;
    g_luaAllocStats_realloc = 0;
    g_luaAllocStats_freeLegacy = 0;
    g_luaAllocStats_reallocMigrate = 0;
}

// ================================================================
//  String Table Pre-sizer
//
//  Lua 5.1 starts with a small string hash table (32-64 buckets).
//  With heavy addons (DBM + Skada + WA + ElvUI), 30,000-50,000
//  unique strings accumulate. Each resize rehashes ALL strings,
//  causing 5-15ms freezes during gameplay.
//
//  We pre-size the table to 32768 buckets at startup.
//  This eliminates all resize events during normal gameplay.
//
//  global_State layout:
//    +0x00 strt.hash  (TString** bucket array)
//    +0x04 strt.nuse  (int, number of strings)
//    +0x08 strt.size  (int, number of buckets)
// ================================================================

static constexpr int STRING_TABLE_TARGET_SIZE = 32768;  // 128 KB of pointers

static bool PreSizeStringTable(lua_State* L) {
    if (!Api.luaS_resize) return false;

    __try {
        // Read current string table size from global_State
        uintptr_t L_addr = (uintptr_t)L;
        if (!IsReadableMemory(L_addr + 0x14)) return false;

        uintptr_t globalState = *(uintptr_t*)(L_addr + 0x14);
        if (!IsReadableMemory(globalState + 0x08)) return false;

        int currentSize = *(int*)(globalState + 0x08);
        int currentNuse = *(int*)(globalState + 0x04);

        Log("[LuaOpt-Str] String table: %d buckets, %d strings (%.1f strings/bucket)",
            currentSize, currentNuse,
            currentSize > 0 ? (double)currentNuse / currentSize : 0.0);

        if (currentSize >= STRING_TABLE_TARGET_SIZE) {
            Log("[LuaOpt-Str] Already large enough, skipping");
            return true;
        }

        // Call luaS_resize to expand the table
        Api.luaS_resize(L, STRING_TABLE_TARGET_SIZE);

        // Verify
        int newSize = *(int*)(globalState + 0x08);
        if (newSize == STRING_TABLE_TARGET_SIZE) {
            Log("[LuaOpt-Str]  [ OK ] Resized: %d -> %d buckets (%.1f KB)",
                currentSize, newSize, (newSize * 4) / 1024.0);
            Log("[LuaOpt-Str]  Strings/bucket: %.2f -> %.2f",
                currentSize > 0 ? (double)currentNuse / currentSize : 0.0,
                newSize > 0 ? (double)currentNuse / newSize : 0.0);
            return true;
        } else {
            Log("[LuaOpt-Str]  [FAIL] Expected %d, got %d",
                STRING_TABLE_TARGET_SIZE, newSize);
            return false;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt-Str] EXCEPTION in PreSizeStringTable");
        return false;
    }
}

// ================================================================
//  GC Optimization
// ================================================================

static bool OptimizeGC(lua_State* L) {
    if (!Api.lua_gc) return false;

    __try {
        int testMem = Api.lua_gc(L, LUA_GCCOUNT, 0);
        if (testMem < 0 || testMem > 4 * 1024 * 1024) {
            Log("[LuaOpt] lua_gc returned implausible value %d — aborting", testMem);
            return false;
        }
        Log("[LuaOpt] lua_gc verified OK: Lua memory = %d KB", testMem);

        State.origGCPause   = Api.lua_gc(L, LUA_GCSETPAUSE,   Config.gcPause);
        State.origGCStepMul = Api.lua_gc(L, LUA_GCSETSTEPMUL, Config.gcStepMul);

        Log("[LuaOpt] GC tuned: pause %d -> %d, stepmul %d -> %d",
            State.origGCPause, Config.gcPause,
            State.origGCStepMul, Config.gcStepMul);

        if (Config.manualGCMode) {
            Api.lua_gc(L, LUA_GCSTOP, 0);
            Log("[LuaOpt] Auto GC stopped — manual stepping active");
        }

        int memKB = Api.lua_gc(L, LUA_GCCOUNT, 0);
        int memB  = Api.lua_gc(L, LUA_GCCOUNTB, 0);
        State.luaMemoryKB = memKB + (memB / 1024.0);

        State.gcOptimized = true;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt] EXCEPTION in GC optimization");
        Api.lua_gc = nullptr;
        return false;
    }
}

static void RestoreGC(lua_State* L) {
    if (!State.gcOptimized || !Api.lua_gc) return;

    __try {
        Api.lua_gc(L, LUA_GCSETPAUSE,   State.origGCPause);
        Api.lua_gc(L, LUA_GCSETSTEPMUL, State.origGCStepMul);
        Api.lua_gc(L, LUA_GCRESTART, 0);
        Log("[LuaOpt] GC restored: pause=%d, stepmul=%d, auto=ON",
            State.origGCPause, State.origGCStepMul);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt] EXCEPTION restoring GC");
    }

    State.gcOptimized = false;
}

// ================================================================
//  4-tier GC Step Size Selection
// ================================================================

static const char* GetGCModeName() {
    if (Config.isLoading) return "loading";
    if (Config.inCombat)  return "combat";
    if (Config.isIdle)    return "idle";
    return "normal";
}

static int GetCurrentStepKB() {
    if (Config.isLoading) return Config.loadingStepKB;
    if (Config.inCombat)  return Config.combatStepKB;
    if (Config.isIdle)    return Config.idleStepKB;
    return Config.normalStepKB;
}

static void StepGC(lua_State* L) {
    if (!State.gcOptimized || !Api.lua_gc) return;

    int stepKB = GetCurrentStepKB();

    __try {
        int done = Api.lua_gc(L, LUA_GCSTEP, stepKB);
        State.gcStepsTotal++;

        if (done) {
            State.fullCollects++;
        }

        State.statsUpdateCounter++;
        if ((State.statsUpdateCounter & 63) == 0) {
            int kb = Api.lua_gc(L, LUA_GCCOUNT, 0);
            int b  = Api.lua_gc(L, LUA_GCCOUNTB, 0);
            State.luaMemoryKB = kb + (b / 1024.0);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt] EXCEPTION in GC step — disabling");
        State.gcOptimized = false;
    }
}

// ================================================================
//  Lua Global Helpers
// ================================================================

static void WriteLuaGlobal_Bool(lua_State* L, const char* name, bool value) {
    if (!Api.lua_pushboolean || !Api.lua_setfield) return;
    Api.lua_pushboolean(L, value ? 1 : 0);
    Api.lua_setfield(L, LUA_GLOBALSINDEX, name);
}

static void WriteLuaGlobal_Number(lua_State* L, const char* name, double value) {
    if (!Api.lua_pushnumber || !Api.lua_setfield) return;
    Api.lua_pushnumber(L, value);
    Api.lua_setfield(L, LUA_GLOBALSINDEX, name);
}

static void WriteLuaGlobal_String(lua_State* L, const char* name, const char* value) {
    if (!Api.lua_pushstring || !Api.lua_setfield) return;
    Api.lua_pushstring(L, value);
    Api.lua_setfield(L, LUA_GLOBALSINDEX, name);
}

static int ReadLuaGlobal_Bool(lua_State* L, const char* name) {
    if (!Api.lua_getfield || !Api.lua_toboolean || !Api.lua_settop) return 0;
    Api.lua_getfield(L, LUA_GLOBALSINDEX, name);
    int val = Api.lua_toboolean(L, -1);
    Api.lua_settop(L, -2);
    return val;
}

// ================================================================
//  Read Addon State from Lua Globals
// ================================================================

static void ReadAddonStateFromLua(lua_State* L) {
    if (!Api.lua_getfield || !Api.lua_toboolean || !Api.lua_settop) return;

    __try {
        Config.inCombat  = (ReadLuaGlobal_Bool(L, "LUABOOST_ADDON_COMBAT")  != 0);
        Config.isIdle    = (ReadLuaGlobal_Bool(L, "LUABOOST_ADDON_IDLE")    != 0);
        Config.isLoading = (ReadLuaGlobal_Bool(L, "LUABOOST_ADDON_LOADING") != 0);

        const char* currentMode = GetGCModeName();
        if (currentMode != State.lastModeName) {
            Log("[LuaOpt] GC mode: %s -> %s (step: %d KB/frame)",
                State.lastModeName, currentMode, GetCurrentStepKB());
            State.lastModeName = currentMode;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ================================================================
//  Write DLL Stats to Lua Globals
// ================================================================

static void UpdateLuaStats(lua_State* L) {
    if (!Api.lua_pushnumber || !Api.lua_setfield) return;

    __try {
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_MEM_KB",      State.luaMemoryKB);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_GC_STEPS",    (double)State.gcStepsTotal);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_GC_FULLS",    (double)State.fullCollects);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_GC_PAUSE",    (double)Config.gcPause);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_GC_STEPMUL",  (double)Config.gcStepMul);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_GC_STEP_KB",  (double)GetCurrentStepKB());
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_COMBAT",      Config.inCombat);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_IDLE",        Config.isIdle);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_LOADING",     Config.isLoading);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_GC_ACTIVE",   State.gcOptimized);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_LUA_ALLOC",   g_luaAllocReplaced);
        WriteLuaGlobal_String(L, "LUABOOST_DLL_GC_MODE",     GetGCModeName());
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ================================================================
//  Initial Setup via FrameScript_Execute
// ================================================================

static void SetupLuaInterface(lua_State* L) {
    if (!Api.FrameScript_Execute) {
        if (Api.lua_pushboolean && Api.lua_setfield) {
            WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_LOADED",    true);
            WriteLuaGlobal_String(L, "LUABOOST_DLL_VERSION",   "1.7.1");
            WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_GC_ACTIVE", State.gcOptimized);
            WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_LUA_ALLOC", g_luaAllocReplaced);
            Log("[LuaOpt] Set DLL globals via Lua API (no FrameScript)");
        }
        return;
    }

    __try {
        Api.FrameScript_Execute(
            "LUABOOST_DLL_LOADED = true "
            "LUABOOST_DLL_VERSION = '1.7.1' "

            "if LUABOOST_ADDON_COMBAT  == nil then LUABOOST_ADDON_COMBAT  = false end "
            "if LUABOOST_ADDON_IDLE    == nil then LUABOOST_ADDON_IDLE    = false end "
            "if LUABOOST_ADDON_LOADING == nil then LUABOOST_ADDON_LOADING = false end "

            "function LuaBoostC_IsLoaded() return true end "

            "function LuaBoostC_GetStats() "
            "  return "
            "    LUABOOST_DLL_MEM_KB or 0, "
            "    LUABOOST_DLL_GC_STEPS or 0, "
            "    LUABOOST_DLL_GC_FULLS or 0, "
            "    LUABOOST_DLL_GC_PAUSE or 0, "
            "    LUABOOST_DLL_GC_STEPMUL or 0, "
            "    LUABOOST_DLL_COMBAT or false, "
            "    LUABOOST_DLL_GC_MODE or 'unknown', "
            "    LUABOOST_DLL_IDLE or false, "
            "    LUABOOST_DLL_LOADING or false, "
            "    LUABOOST_DLL_LUA_ALLOC or false "
            "end "

            "function LuaBoostC_GCMemory() "
            "  return LUABOOST_DLL_MEM_KB or 0 "
            "end "

            "function LuaBoostC_SetCombat(v) "
            "  LUABOOST_ADDON_COMBAT = v and true or false "
            "end "

            "LUABOOST_DLL_GC_REQUEST = nil "
            "function LuaBoostC_GCStep(kb) "
            "  LUABOOST_DLL_GC_REQUEST = kb or 100 "
            "end "

            "function LuaBoostC_GCCollect() "
            "  LUABOOST_DLL_GC_REQUEST = -1 "
            "end ",
            "LuaOpt", 0
        );

        Log("[LuaOpt] Lua interface created via FrameScript");
        Log("[LuaOpt]   LuaBoostC_GetStats() now returns 10 values (added LUA_ALLOC)");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt] EXCEPTION in FrameScript_Execute");
        WriteLuaGlobal_Bool(L, "LUABOOST_DLL_LOADED", true);
    }
}

// ================================================================
//  Process GC Requests from Addon
// ================================================================

static void ProcessGCRequests(lua_State* L) {
    if (!Api.lua_getfield || !Api.lua_type || !Api.lua_tonumber ||
        !Api.lua_pushnil || !Api.lua_setfield || !Api.lua_settop || !Api.lua_gc) {
        return;
    }

    __try {
        Api.lua_getfield(L, LUA_GLOBALSINDEX, "LUABOOST_DLL_GC_REQUEST");

        int t = Api.lua_type(L, -1);
        if (t == 3) {
            double val = Api.lua_tonumber(L, -1);
            Api.lua_settop(L, -2);

            Api.lua_pushnil(L);
            Api.lua_setfield(L, LUA_GLOBALSINDEX, "LUABOOST_DLL_GC_REQUEST");

            if (val < 0) {
                Api.lua_gc(L, LUA_GCCOLLECT, 0);
                State.fullCollects++;
                Log("[LuaOpt] Addon requested full GC collect");
            } else if (val > 0) {
                Api.lua_gc(L, LUA_GCSTEP, (int)val);
                State.gcStepsTotal++;
            }
        } else {
            Api.lua_settop(L, -2);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ================================================================
//  Main Thread Initialization
// ================================================================

static void DoMainThreadInit() {
    Log("[LuaOpt] ====================================");
    Log("[LuaOpt]  Lua VM Init (main thread)");
    Log("[LuaOpt] ====================================");

    Api.L = ReadLuaState();

    if (!Api.L) {
        Log("[LuaOpt] lua_State* is NULL — Lua VM not ready");
        Log("[LuaOpt] Will retry on next frame");
        InterlockedExchange(&g_luaInitState, 1);
        State.initialized = false;
        return;
    }

    Log("[LuaOpt] lua_State* = 0x%08X", (unsigned)(uintptr_t)Api.L);

    bool allocOk = ReplaceLuaAllocator(Api.L);
    bool gcOk = OptimizeGC(Api.L);
    bool strOk = PreSizeStringTable(Api.L);

    SetupLuaInterface(Api.L);

    if (Api.lua_pushnumber && Api.lua_setfield) {
        UpdateLuaStats(Api.L);
    }

    State.initialized = true;
    State.lastModeName = GetGCModeName();

    Log("[LuaOpt] ====================================");
    Log("[LuaOpt]  Init Complete");
    Log("[LuaOpt]    Lua allocator:    %s", allocOk ? "mimalloc (REPLACED)" : "original (WoW pool)");
    Log("[LuaOpt]    GC optimized:     %s", gcOk ? "YES" : "NO");
    Log("[LuaOpt]    String table:     %s", strOk ? "PRE-SIZED" : "default");    
    Log("[LuaOpt]    Lua interface:    via FrameScript (safe)");
    Log("[LuaOpt]    GC tiers (KB/f):");
    Log("[LuaOpt]      normal  = %d", Config.normalStepKB);
    Log("[LuaOpt]      combat  = %d", Config.combatStepKB);
    Log("[LuaOpt]      idle    = %d", Config.idleStepKB);
    Log("[LuaOpt]      loading = %d", Config.loadingStepKB);
    Log("[LuaOpt] ====================================");
}

// ================================================================
//  Public API
// ================================================================

namespace LuaOpt {

bool PrepareFromWorkerThread() {
    Log("[LuaOpt] ====================================");
    Log("[LuaOpt]  Lua VM Optimizer — Preparing");
    Log("[LuaOpt]  Build 12340 (IDA Pro addresses)");
    Log("[LuaOpt] ====================================");

    if (!ResolveAddresses()) {
        Log("[LuaOpt] Address resolution failed");
        return false;
    }

    HMODULE hWow = GetModuleHandleA(nullptr);
    uintptr_t wowBase = (uintptr_t)hWow;
    Log("[LuaOpt] Wow.exe base: 0x%08X", (unsigned)wowBase);

    if (wowBase != 0x00400000) {
        Log("[LuaOpt] WARNING: Unexpected base! Addresses may be wrong.");
    }

    lua_State* testL = ReadLuaState();
    if (testL) {
        Log("[LuaOpt] lua_State* pre-read: 0x%08X", (unsigned)(uintptr_t)testL);
    } else {
        Log("[LuaOpt] lua_State* = NULL (will retry on main thread)");
    }

    g_addressesValid = true;
    InterlockedExchange(&g_luaInitState, 1);

    Log("[LuaOpt] Ready — waiting for main thread...");
    return true;
}

void OnMainThreadSleep(DWORD mainThreadId) {
    if (GetCurrentThreadId() != mainThreadId) return;

    LONG state = g_luaInitState;

    if (state == 1) {
        if (InterlockedCompareExchange(&g_luaInitState, 2, 1) == 1) {
            DoMainThreadInit();
        }
        return;
    }

    if (state != 2 || !State.initialized || !State.gcOptimized || !Api.L) return;

    lua_State* currentL = ReadLuaState();
    if (!currentL) return;

    if (currentL != Api.L) {
        Log("[LuaOpt] lua_State changed (UI reload) — reinitializing");

        if (g_luaAllocReplaced) {
            LogLuaAllocStats();
            // Do NOT call RestoreLuaAllocator() here.
            // Old global_State was freed by lua_close().
            // Writing to freed memory corrupts heap → Error #132.
        }
        ResetAllocStats();

        Api.L = currentL;
        State.gcOptimized = false;
        State.gcStepsTotal = 0;
        State.fullCollects = 0;
        State.statsUpdateCounter = 0;
        State.lastModeName = "unknown";

        ReplaceLuaAllocator(Api.L);
        OptimizeGC(Api.L);
        PreSizeStringTable(Api.L);
        SetupLuaInterface(Api.L);
        return;
    }

    // Read addon state every 16 frames (~4-5 reads/sec at 60fps)
    // Combat/idle/loading state changes at most a few times per minute
    // No need to poll 9 Lua API calls every single frame
    static int addonReadCounter = 0;
    if ((++addonReadCounter & 15) == 0) {
        ReadAddonStateFromLua(Api.L);
    }

    // GC requests from addon checked every 4 frames
    // Addon sets LUABOOST_DLL_GC_REQUEST on burst events (boss kill etc)
    // 4-frame delay = ~66ms at 60fps — imperceptible
    static int gcRequestCounter = 0;
    if ((++gcRequestCounter & 3) == 0) {
        ProcessGCRequests(Api.L);
    }

    StepGC(Api.L);

    if ((State.statsUpdateCounter & 63) == 0) {
        UpdateLuaStats(Api.L);
    }

    if (g_luaAllocReplaced && (State.statsUpdateCounter & 4095) == 0) {
        LogLuaAllocStats();
    }
}

void Shutdown() {
    if (!State.initialized) return;

    if (g_luaAllocReplaced) {
        LogLuaAllocStats();
        RestoreLuaAllocator();
    }

    lua_State* L = ReadLuaState();
    if (L) {
        RestoreGC(L);

        if (Api.lua_pushboolean && Api.lua_setfield) {
            __try {
                WriteLuaGlobal_Bool(L, "LUABOOST_DLL_LOADED", false);
                WriteLuaGlobal_Bool(L, "LUABOOST_DLL_GC_ACTIVE", false);
                WriteLuaGlobal_Bool(L, "LUABOOST_DLL_LUA_ALLOC", false);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    Log("[LuaOpt] Shutdown. Total: %d GC steps, %d full collects",
        State.gcStepsTotal, State.fullCollects);

    State.initialized = false;
    InterlockedExchange(&g_luaInitState, 0);
}

void SetCombatMode(bool inCombat) {
    Config.inCombat = inCombat;
}

Stats GetStats() {
    Stats s = {};
    s.initialized         = State.initialized;
    s.gcOptimized         = State.gcOptimized;
    s.allocatorReplaced   = g_luaAllocReplaced;
    s.functionsRegistered = true;
    s.luaMemoryKB         = State.luaMemoryKB;
    s.gcStepsTotal        = State.gcStepsTotal;
    s.gcPause             = Config.gcPause;
    s.gcStepMul           = Config.gcStepMul;
    return s;
}

} // namespace LuaOpt