// ================================================================
// Lua VM Optimizer - GC, allocator, string table, addon interface
//
// COMPONENTS:
//   1. Lua Allocator Replacement - mimalloc for Lua VM memory
//      Replaces WoW's default allocator (0x008558E0, SMemAlloc-based)
//      with mimalloc. All Lua objects (TString, Table, Closure, etc.)
//      are allocated through mimalloc instead of WoW's pool allocator.
//
//   2. String Table Pre-sizing - expands Lua's string hash table from
//      default 32-64 buckets to 32768 buckets at startup. Heavy addon
//      sessions create 30k-50k strings - pre-sizing avoids rehash freezes.
//
//   3. GC Optimization - tunes Lua's incremental GC:
//      - pause: 200 -> 110 (start GC sooner)
//      - stepmul: 200 -> 300 (do more work per step)
//      - stops auto-GC, uses manual stepping every frame
//      - 4-tier step size: normal(64KB), combat(16KB), idle(128KB),
//        loading(256KB)
//      - Frame-time based pre-adjustment: slow frames → less GC
//      - Adaptive post-GC: smoothed GC time → adjusts base step sizes
//      - Emergency GC (incremental): triggers 1MB GC steps if memory > 500 MB (never full collect - avoids main thread stalls)
//
//   4. Addon Interface - bidirectional communication with Lua addons
//      via global variables (LUABOOST_DLL_*, LUABOOST_ADDON_*)
//      - Reads combat/idle/loading state from addon
//      - Writes GC stats, memory usage, version to addon
//      - Processes GC requests from addon (step/full collect)
//
//   5. UI Reload Detection - detects lua_State changes (UI reload)
//      and reinitializes all optimizations for the new VM.
// ================================================================

#include "lua_optimize.h"
#include "combatlog_optimize.h"
#include "ui_cache.h"
#include "api_cache.h"
#include "lua_fastpath.h"
#include "lua_vm_cache.h"
#include "lua_bytecode_cache.h"
#include "addon_preload.h"

// VA Arena helpers (defined in dllmain.cpp)
extern "C" void ReserveLoadingArena();
extern "C" void ReleaseLoadingArena();

#include "lua_internals.h"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <atomic>
#include <psapi.h>
#include <mimalloc.h>
#include "MinHook.h"

#include "version.h"

extern bool g_isMultiClient;
extern "C" void Log(const char* fmt, ...);

// ================================================================
// Lua 5.1 types and GC constants.
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

// Function pointer types.

typedef int        (__cdecl *fn_lua_gc)(lua_State* L, int what, int data);
typedef int        (__cdecl *fn_lua_gettop)(lua_State* L);
typedef void       (__cdecl *fn_lua_settop)(lua_State* L, int index);
typedef lua_Number (__cdecl *fn_lua_tonumber)(lua_State* L, int index);
typedef int        (__cdecl *fn_lua_toboolean)(lua_State* L, int index);
typedef void       (__cdecl *fn_lua_pushnumber)(lua_State* L, lua_Number n);
typedef void       (__cdecl *fn_lua_pushboolean)(lua_State* L, int b);
typedef const char* (__cdecl *fn_lua_pushstring)(lua_State* L, const char* s);
typedef void       (__cdecl *fn_lua_pushnil)(lua_State* L);
typedef void       (__cdecl *fn_lua_setfield)(lua_State* L, int index, const char* k);
typedef void       (__cdecl *fn_lua_getfield)(lua_State* L, int index, const char* k);
typedef int        (__cdecl *fn_lua_type)(lua_State* L, int index);
typedef void       (__cdecl *fn_lua_pushcclosure)(lua_State* L, void* fn, int n);
typedef void       (__cdecl *fn_luaS_resize)(lua_State* L, int newsize);
typedef void       (__cdecl *fn_FrameScript_Execute)(const char* code,
                                                       const char* source,
                                                       int unknown);

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
    static constexpr uintptr_t lua_pushcclosure    = 0x0084E980;
}

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
    fn_lua_pushcclosure     lua_pushcclosure = nullptr;
    fn_luaS_resize          luaS_resize = nullptr;
    fn_FrameScript_Execute  FrameScript_Execute = nullptr;
} Api;

// ================================================================
//  Configuration - 4-tier GC stepping
//  Increased defaults to handle heavy addon sessions (300-400MB Lua memory).
//  At 60fps: normal=128KB → 7.7 MB/sec, idle=256KB → 15 MB/sec, loading=512KB → 30 MB/sec.
// ================================================================

static struct {
    int  gcPause        = 110;
    int  gcStepMul      = 300;
    int  normalStepKB   = 128;   // was 64 - heavy sessions need faster collection
    int  combatStepKB   = 64;    // Raised from 32 → 64 to prevent memory ballooning during combat logs
    int  idleStepKB     = 256;   // was 128 - aggressive cleanup while AFK
    int  loadingStepKB  = 512;   // was 256 - rapid cleanup during zone transitions
    bool manualGCMode   = true;

    bool inCombat       = false;
    bool isIdle         = false;
    bool isLoading      = false;
} Config;

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

static int g_addonReadCounter = 0;
static int g_gcRequestCounter = 0;
static int g_lastSyncNormal = -1;
static int g_lastSyncCombat = -1;
static int g_lastSyncIdle = -1;
static int g_lastSyncLoading = -1;
static DWORD g_lastLuaSwapTick = 0;
static lua_State* g_pendingLuaState = nullptr;
static DWORD g_pendingLuaStateTick = 0;
static int g_pendingLuaStateFrames = 0;
static bool g_vmInitializedOnce = false;
static int g_luaInterfaceCheckCounter = 0;
static bool g_luaInterfaceFailed = false;
static int g_luaInterfaceRetryCount = 0;
static DWORD g_luaInterfaceLastRetry = 0;

// Forward declaration
static void SetupLuaInterface(lua_State* L);

// Check if Lua interface globals are present, re-setup if missing
static bool CheckAndRestoreLuaInterface(lua_State* L) {
    // Lua interface registration disabled - addon uses stubs regardless
    return true;
}


// Thread-safe state flags for worker threads (atomic, no lock needed)
static std::atomic<bool> g_isReloading{false};
static std::atomic<bool> g_isSwapping{false};

static double g_smoothedGcMs = 0.5;
static LARGE_INTEGER g_gcPerfFreq = {};

static constexpr DWORD LUA_RELOAD_SETTLE_MS_SINGLE = 50;
static constexpr DWORD LUA_RELOAD_SETTLE_MS_MULTI  = 150;
static constexpr int   LUA_RELOAD_SETTLE_FRAMES_SINGLE = 2;
static constexpr int   LUA_RELOAD_SETTLE_FRAMES_MULTI  = 6;

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

static bool ResolveAddresses() {
    Log("[LuaOpt] Resolving addresses...");

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
    RESOLVE(lua_pushcclosure, Addr::lua_pushcclosure, fn_lua_pushcclosure, "lua_pushcclosure");
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
//  Lua Allocator Replacement - mimalloc for Lua VM
//
// ================================================================

typedef void* (__cdecl *lua_Alloc_fn)(void* ud, void* ptr, size_t osize, size_t nsize);

static lua_Alloc_fn g_origLuaAlloc = nullptr;
static void*        g_origLuaAllocUD = nullptr;
static uintptr_t    g_globalStateAddr = 0;
static bool         g_luaAllocReplaced = false;

static long g_luaAllocStats_malloc = 0;
static long g_luaAllocStats_free = 0;
static long g_luaAllocStats_realloc = 0;
static long g_luaAllocStats_freeLegacy = 0;
static long g_luaAllocStats_reallocMigrate = 0;

// Adaptive GC: track net allocation bytes between frames.
// This lets StepGC scale collection to match actual allocation pressure,
// so heavy-addon users (300MB) and light users (100MB) both stay stable.
static volatile LONG64 g_netAllocBytes = 0;   // net bytes allocated since last reset
static volatile LONG64 g_frameAllocBytes = 0; // bytes allocated this frame (for smoothing)

static void ResetAllocCounter() {
    InterlockedExchange64(&g_netAllocBytes, 0);
}

static LONG64 GetAndResetNetAlloc() {
    return InterlockedExchange64(&g_netAllocBytes, 0);
}

static void* __cdecl MimallocLuaAlloc(void* ud, void* ptr, size_t osize, size_t nsize) {
    // SEH wrapper: if any mimalloc call crashes (e.g. HD client heap layout
    // differs, mi_is_in_heap_region false positive), fall back to original
    // allocator to prevent ACCESS_VIOLATION.
    __try {
        if (nsize == 0) {
            if (ptr) {
                size_t freedSize = osize;
                if (mi_is_in_heap_region(ptr)) {
                    freedSize = mi_usable_size(ptr);
                    mi_free(ptr);
                    g_luaAllocStats_free++;
                } else {
                    g_origLuaAlloc(g_origLuaAllocUD, ptr, osize, 0);
                    g_luaAllocStats_freeLegacy++;
                }
                InterlockedAdd64(&g_netAllocBytes, -(LONG64)freedSize);
            }
            return NULL;
        }

        if (ptr == NULL) {
            g_luaAllocStats_malloc++;
            void* p = mi_malloc(nsize);
            if (p) {
                InterlockedAdd64(&g_netAllocBytes, (LONG64)nsize);
            }
            return p;
        }

        if (mi_is_in_heap_region(ptr)) {
            g_luaAllocStats_realloc++;
            size_t oldUsable = mi_usable_size(ptr);
            void* p = mi_realloc(ptr, nsize);
            if (p) {
                InterlockedAdd64(&g_netAllocBytes, (LONG64)nsize - (LONG64)oldUsable);
            }
            return p;
        }

        g_luaAllocStats_reallocMigrate++;
        void* newPtr = mi_malloc(nsize);
        if (newPtr) {
            size_t copySize = (osize < nsize) ? osize : nsize;
            memcpy(newPtr, ptr, copySize);
            g_origLuaAlloc(g_origLuaAllocUD, ptr, osize, 0);
            InterlockedAdd64(&g_netAllocBytes, (LONG64)nsize - (LONG64)osize);
        }
        return newPtr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // mimalloc crashed - disable replacement and use original allocator
        // This prevents repeated crashes on HD/non-standard clients
        static volatile LONG s_fallbackCount = 0;
        LONG count = InterlockedIncrement(&s_fallbackCount);
        if (count <= 3) {
            Log("[LuaOpt-Alloc] EXCEPTION in MimallocLuaAlloc (0x%08X) - falling back to original allocator",
                GetExceptionCode());
        }
        if (count == 1) {
            // Restore original allocator on first exception
            if (g_globalStateAddr && g_origLuaAlloc) {
                DWORD oldProt;
                VirtualProtect((void*)(g_globalStateAddr + 0x0C), 4, PAGE_READWRITE, &oldProt);
                *(uintptr_t*)(g_globalStateAddr + 0x0C) = (uintptr_t)g_origLuaAlloc;
                VirtualProtect((void*)(g_globalStateAddr + 0x0C), 4, oldProt, &oldProt);
                g_luaAllocReplaced = false;
                Log("[LuaOpt-Alloc] RESTORED original Lua allocator (HD client compatibility)");
            }
        }
        // Route this call through original allocator
        return g_origLuaAlloc(g_origLuaAllocUD, ptr, osize, nsize);
    }
}

static bool ReplaceLuaAllocator(lua_State* L) {
    // DISABLED: mimalloc Lua allocator replacement causes ACCESS_VIOLATION crashes
    // during login/logout transitions and multi-client scenarios. Root cause:
    // WoW's Lua VM expects specific heap layout/alignment from its pool allocator
    // that mimalloc doesn't guarantee. Crashes observed at 0x0084EB10 (WoW.exe)
    // and 0x5F2FA7A0 (wow_optimize.dll) within 2 minutes of login.
    // GC tuning, string table pre-sizing, and fast paths remain active.
    Log("[LuaOpt-Alloc] DISABLED: mimalloc Lua allocator causes crashes during login/logout");
    return false;

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
            Log("[LuaOpt-Alloc] Unexpected allocator - skipping replacement for safety");
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

// String table pre-sizer.
//

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
//  GC Optimization - 4-tier adaptive stepping
//
// ================================================================
static bool OptimizeGC(lua_State* L) {
    if (!Api.lua_gc) return false;

    __try {
        int testMem = Api.lua_gc(L, LUA_GCCOUNT, 0);
        if (testMem < 0 || testMem > 4 * 1024 * 1024) {
            Log("[LuaOpt] lua_gc returned implausible value %d - aborting", testMem);
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
            Log("[LuaOpt] Auto GC stopped - manual stepping active");
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

// 4-tier GC step size selection.

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

static int g_loadingGraceFrames = 0;

// Smoothed net allocation rate (bytes/frame) for adaptive GC
static double g_smoothedNetAlloc = 0.0;

static void StepGC(lua_State* L, double frameMs) {
    if (!State.gcOptimized || !Api.lua_gc) return;

    // CRITICAL: Skip ALL GC during VM swap/reload to prevent freeze.
    // During UI reload, WoW destroys old lua_State and creates new one.
    // Accessing stale pointers causes 10+ second freezes.
    if (g_isSwapping.load(std::memory_order_acquire) || g_isReloading.load(std::memory_order_acquire)) {
        ResetAllocCounter();
        return;
    }

    // Skip GC during combat if frame is already slow to prevent compounding stutter
    // Raised threshold from 14ms to 18ms — at 60fps (16.6ms) this was triggering
    // too aggressively, causing GC starvation and memory growth during raids
    if (Config.inCombat && frameMs > 18.0) {
        ResetAllocCounter();  // Still reset counter even when skipping
        return;
    }

    // During combat: use micro-steps spread across frames instead of large bursts.
    // This prevents GC spikes that cause visible stutter during boss mechanics.
    // Instead of 64KB every frame, do 16KB every frame = same throughput, smoother.
    if (Config.inCombat && !Config.isLoading) {
        int microStepKB = 16;
        LONG64 netAlloc = GetAndResetNetAlloc();
        if (netAlloc < 0) netAlloc = 0;
        g_smoothedNetAlloc = g_smoothedNetAlloc * 0.9 + (double)netAlloc * 0.1;
        int adaptiveMicro = (int)(g_smoothedNetAlloc / 1024.0 * 0.5);
        if (adaptiveMicro > microStepKB) microStepKB = adaptiveMicro;
        if (microStepKB > 32) microStepKB = 32;

        if (g_gcPerfFreq.QuadPart == 0) QueryPerformanceFrequency(&g_gcPerfFreq);
        LARGE_INTEGER before, after;
        QueryPerformanceCounter(&before);
        __try {
            Api.lua_gc(L, LUA_GCSTEP, microStepKB);
            State.gcStepsTotal++;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            State.gcOptimized = false;
            return;
        }
        QueryPerformanceCounter(&after);
        double gcMs = (double)(after.QuadPart - before.QuadPart) * 1000.0 / (double)g_gcPerfFreq.QuadPart;
        g_smoothedGcMs = g_smoothedGcMs * 0.95 + gcMs * 0.05;
        return;
    }

    // Skip GC for first 30 frames after entering loading mode
    // Zone transitions are fragile - Lua VM is in transitional state
    if (Config.isLoading) {
        if (g_loadingGraceFrames < 30) {
            g_loadingGraceFrames++;
            ResetAllocCounter();
            return;
        }
    } else {
        g_loadingGraceFrames = 0;
    }

    if (g_gcPerfFreq.QuadPart == 0) {
        QueryPerformanceFrequency(&g_gcPerfFreq);
    }

    // Adaptive GC: read net allocation since last frame and smooth it.
    // This makes GC automatically scale to each user's addon workload:
    //   - Light user (50KB/frame alloc) → collects ~50KB/frame
    //   - Heavy user (2MB/frame alloc) → collects ~2MB/frame
    // Fixed tier values serve as MINIMUMS to ensure baseline collection.
    LONG64 netAlloc = GetAndResetNetAlloc();
    if (netAlloc < 0) netAlloc = 0;  // Negative = more freed than allocated

    // Exponential moving average (alpha=0.1 for stability)
    g_smoothedNetAlloc = g_smoothedNetAlloc * 0.9 + (double)netAlloc * 0.1;

    // Convert smoothed allocation to KB, add 20% headroom to stay ahead
    int adaptiveStepKB = (int)(g_smoothedNetAlloc / 1024.0 * 1.2);

    // Use the larger of adaptive or tier-based minimum
    int tierMin = GetCurrentStepKB();
    int stepKB = (adaptiveStepKB > tierMin) ? adaptiveStepKB : tierMin;

    // Cap at 4MB per frame to prevent GC stalls
    if (stepKB > 4096) stepKB = 4096;

    // Frame-time based pre-adjustment: reduce GC pressure when frames are slow
    if (frameMs > 0.0) {
        if (frameMs > 16.0) {
            // Frame took > 16ms (below 60 FPS) - minimize GC to avoid further slowdown
            if (stepKB > 4) stepKB = stepKB / 2;
        } else if (frameMs < 8.0) {
            // Frame took < 8ms (above 120 FPS) - increase GC to catch up on garbage
            stepKB = stepKB * 3 / 2;
        }
    }

    LARGE_INTEGER before, after;
    QueryPerformanceCounter(&before);

    __try {
        int done = Api.lua_gc(L, LUA_GCSTEP, stepKB);
        State.gcStepsTotal++;
        if (done) {
            State.fullCollects++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt] EXCEPTION in GC step - disabling");
        State.gcOptimized = false;
        return;
    }

    QueryPerformanceCounter(&after);
    double gcMs = (double)(after.QuadPart - before.QuadPart) * 1000.0 / (double)g_gcPerfFreq.QuadPart;
    g_smoothedGcMs = g_smoothedGcMs * 0.95 + gcMs * 0.05;

    // Post-GC adaptive: adjust base step sizes based on GC time.
    // SLOW adaptation - prevent step sizes from collapsing during heavy sessions.
    if (g_smoothedGcMs > 2.0) {
        // Only decrease if GC is VERY slow (>5ms) - avoid over-reacting to temporary spikes.
        if (g_smoothedGcMs > 5.0) {
            if (Config.isLoading) {
                if (Config.loadingStepKB > 64) Config.loadingStepKB -= 32;
            } else if (Config.inCombat) {
                if (Config.combatStepKB > 8) Config.combatStepKB -= 4;
            } else if (Config.isIdle) {
                if (Config.idleStepKB > 32) Config.idleStepKB -= 16;
            } else {
                if (Config.normalStepKB > 16) Config.normalStepKB -= 8;
            }
        }
    } else if (g_smoothedGcMs < 0.6) {
        if (Config.isLoading) {
            if (Config.loadingStepKB < 512) Config.loadingStepKB += 16;
        } else if (Config.inCombat) {
            if (Config.combatStepKB < 48) Config.combatStepKB += 2;
        } else if (Config.isIdle) {
            if (Config.idleStepKB < 512) Config.idleStepKB += 8;
        } else {
            if (Config.normalStepKB < 256) Config.normalStepKB += 4;
        }
    }

    State.statsUpdateCounter++;
    if ((State.statsUpdateCounter & 63) == 0) {
        int kb = Api.lua_gc(L, LUA_GCCOUNT, 0);
        int b  = Api.lua_gc(L, LUA_GCCOUNTB, 0);
        State.luaMemoryKB = kb + (b / 1024.0);
    }

    // Emergency GC: INCREMENTAL only - never block main thread with full collect.
    // Full collect (LUA_GCCOLLECT) causes 500ms-2s stalls → network timeout → ping spike.
    // Instead: aggressive incremental steps spread over multiple frames.
    // Threshold: 300 MB (355 MB was causing OOM crashes - 32-bit address space fragmentation).
    // Loading mode: MUCH more aggressive - 64 MB steps, 2s cooldown (teleport safety).
    // Normal mode: 16 MB steps, 10s cooldown (balance for raid performance).
    static double g_lastEmergencyMem = 0.0;
    static DWORD  g_lastEmergencyTick = 0;

    if (State.luaMemoryKB > 300 * 1024) {
        DWORD nowTick = GetTickCount();
        double memMB = State.luaMemoryKB / 1024.0;

        // Loading mode: aggressive emergency GC (teleport/zone transition safety).
        // During loading there is no rendering - we can collect hard without affecting FPS.
        // This prevents M2 model allocation failures when memory is already high.
        if (Config.isLoading) {
            // 64 MB step every 2 seconds during loading - clear memory fast.
            if (!Config.isLoading && memMB > g_lastEmergencyMem + 5.0 && (nowTick - g_lastEmergencyTick) > 10000) {
                Api.lua_gc(L, LUA_GCSTEP, 16384);  // 16 MB step
                State.fullCollects++;

                int kb = Api.lua_gc(L, LUA_GCCOUNT, 0);
                int b  = Api.lua_gc(L, LUA_GCCOUNTB, 0);
                double afterMB = (kb + (b / 1024.0)) / 1024.0;

                g_lastEmergencyMem = afterMB;
                g_lastEmergencyTick = nowTick;

                Log("[LuaOpt] EMERGENCY GC (incremental): %.1f MB -> %.1f MB", memMB, afterMB);
            }
        }
        // Normal/combat/idle mode: moderate emergency GC.
        else if (memMB > g_lastEmergencyMem + 5.0 && (nowTick - g_lastEmergencyTick) > 10000) {
            // Incremental step: 16 MB per trigger.
            Api.lua_gc(L, LUA_GCSTEP, 16384);  // 16 MB step
            State.fullCollects++;

            int kb = Api.lua_gc(L, LUA_GCCOUNT, 0);
            int b  = Api.lua_gc(L, LUA_GCCOUNTB, 0);
            double afterMB = (kb + (b / 1024.0)) / 1024.0;

            g_lastEmergencyMem = afterMB;
            g_lastEmergencyTick = nowTick;

            Log("[LuaOpt] EMERGENCY GC (incremental): %.1f MB -> %.1f MB", memMB, afterMB);
        }
    }
}

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

static double ReadLuaGlobal_Number(lua_State* L, const char* name, double fallback) {
    if (!Api.lua_getfield || !Api.lua_type || !Api.lua_tonumber || !Api.lua_settop)
        return fallback;
    Api.lua_getfield(L, LUA_GLOBALSINDEX, name);
    if (Api.lua_type(L, -1) != 3) {
        Api.lua_settop(L, -2);
        return fallback;
    }
    double val = Api.lua_tonumber(L, -1);
    Api.lua_settop(L, -2);
    return val;
}

static double RefreshLuaMemoryKB(lua_State* L) {
    if (!L || !Api.lua_gc) return State.luaMemoryKB;

    int kb = Api.lua_gc(L, LUA_GCCOUNT, 0);
    int b  = Api.lua_gc(L, LUA_GCCOUNTB, 0);
    State.luaMemoryKB = kb + (b / 1024.0);
    return State.luaMemoryKB;
}

static void TryTrimForLoadingScreen(lua_State* L) {
    if (!L || !Api.lua_gc || !State.gcOptimized) return;

    static constexpr double PRELOAD_TRIM_MB_SINGLE = 256.0;
    static constexpr double PRELOAD_TRIM_MB_MULTI  = 320.0;
    static constexpr int PRELOAD_TRIM_STEP_KB_SINGLE = 16384;  // 16 MB
    static constexpr int PRELOAD_TRIM_STEP_KB_MULTI  = 32768;  // 32 MB

    double beforeKB = RefreshLuaMemoryKB(L);
    double beforeMB = beforeKB / 1024.0;
    double thresholdMB = g_isMultiClient ? PRELOAD_TRIM_MB_MULTI : PRELOAD_TRIM_MB_SINGLE;
    int trimStepKB = g_isMultiClient ? PRELOAD_TRIM_STEP_KB_MULTI
                                     : PRELOAD_TRIM_STEP_KB_SINGLE;
    bool didTrim = false;
    bool didPurge = false;

    if (beforeMB >= thresholdMB) {
        __try {
            Api.lua_gc(L, LUA_GCSTEP, trimStepKB);
            State.fullCollects++;
            didTrim = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[LuaOpt] EXCEPTION in loading entry trim");
        }
    }

    if (g_luaAllocReplaced && (g_isMultiClient || beforeMB >= thresholdMB - 32.0)) {
        mi_collect(true);
        didPurge = true;
    }

    g_loadingGraceFrames = 0;

    if (didTrim || didPurge) {
        double afterMB = RefreshLuaMemoryKB(L) / 1024.0;
        Log("[LuaOpt] Loading entry trim: %.1f MB -> %.1f MB%s%s",
            beforeMB, afterMB,
            didTrim ? " (Lua GC step)" : "",
            didPurge ? " (mimalloc purge)" : "");
    }
}

// ================================================================
//  Addon State Reader - reads globals set by !LuaBoost addon
//
// ================================================================
static void ReadAddonStateFromLua(lua_State* L) {
    if (!Api.lua_getfield || !Api.lua_toboolean || !Api.lua_settop) return;

    __try {
        bool wasCombat = Config.inCombat;
        Config.inCombat  = (ReadLuaGlobal_Bool(L, "LUABOOST_ADDON_COMBAT")  != 0);
        if (Config.inCombat != wasCombat) {
            CombatLogOpt::SetCombat(Config.inCombat);
        }
        Config.isIdle    = (ReadLuaGlobal_Bool(L, "LUABOOST_ADDON_IDLE")    != 0);
        bool wasLoading = Config.isLoading;
        Config.isLoading = (ReadLuaGlobal_Bool(L, "LUABOOST_ADDON_LOADING") != 0);
        if (Config.isLoading && !wasLoading) {
            UICache::ClearCache();
            TryTrimForLoadingScreen(L);
            ReserveLoadingArena();  // VA arena: claim 256MB for M2/WMO loading
        }
        if (!Config.isLoading && wasLoading) {
            ReleaseLoadingArena(); // VA arena: return to gameplay
        }

        const char* currentMode = GetGCModeName();
        if (currentMode != State.lastModeName) {
            Log("[LuaOpt] GC mode: %s -> %s (step: %d KB/frame)",
                State.lastModeName, currentMode, GetCurrentStepKB());
            State.lastModeName = currentMode;
        }

        double n;
        n = ReadLuaGlobal_Number(L, "LUABOOST_ADDON_STEP_NORMAL", -1);
        if (n >= 1 && (int)n != g_lastSyncNormal) {
            g_lastSyncNormal = (int)n;
            Config.normalStepKB = (int)n;
        }
        n = ReadLuaGlobal_Number(L, "LUABOOST_ADDON_STEP_COMBAT", -1);
        if (n >= 0 && (int)n != g_lastSyncCombat) {
            g_lastSyncCombat = (int)n;
            Config.combatStepKB = (int)n;
        }
        n = ReadLuaGlobal_Number(L, "LUABOOST_ADDON_STEP_IDLE", -1);
        if (n >= 1 && (int)n != g_lastSyncIdle) {
            g_lastSyncIdle = (int)n;
            Config.idleStepKB = (int)n;
        }
        n = ReadLuaGlobal_Number(L, "LUABOOST_ADDON_STEP_LOADING", -1);
        if (n >= 1 && (int)n != g_lastSyncLoading) {
            g_lastSyncLoading = (int)n;
            Config.loadingStepKB = (int)n;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void UpdateLuaStats(lua_State* L) {
    if (!Api.lua_pushnumber || !Api.lua_setfield) return;

    __try {
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_MEM_KB",      State.luaMemoryKB);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_GC_STEPS",   (double)State.gcStepsTotal);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_GC_FULLS",   (double)State.fullCollects);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_GC_PAUSE",   (double)Config.gcPause);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_GC_STEPMUL", (double)Config.gcStepMul);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_GC_STEP_KB", (double)GetCurrentStepKB());
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_COMBAT",      Config.inCombat);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_IDLE",        Config.isIdle);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_LOADING",     Config.isLoading);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_GC_ACTIVE",   State.gcOptimized);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_LUA_ALLOC",   g_luaAllocReplaced);
        WriteLuaGlobal_String(L, "LUABOOST_DLL_GC_MODE",     GetGCModeName());
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_GC_MS",       g_smoothedGcMs);

        UICache::Stats uiStats = UICache::GetStats();
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_UICACHE_SKIPPED", (double)uiStats.skipped);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_UICACHE_PASSED", (double)uiStats.passed);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_UICACHE_ACTIVE",  uiStats.active);

        ApiCache::Stats apiStats = ApiCache::GetStats();
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_APICACHE_ITEM_HITS",  (double)apiStats.itemHits);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_APICACHE_ITEM_MISSES", (double)apiStats.itemMisses);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_APICACHE_SPELL_HITS", (double)apiStats.spellHits);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_APICACHE_SPELL_MISSES",(double)apiStats.spellMisses);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_APICACHE_ACTIVE", apiStats.active);

        LuaFastPath::Stats fpStats = LuaFastPath::GetStats();
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_FASTPATH_HITS",     (double)fpStats.formatFastHits);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_FASTPATH_FALLBACKS", (double)fpStats.formatFallbacks);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_FASTPATH_ACTIVE",    fpStats.active);
 
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// C callback stubs for LuaBoost functions (used when FrameScript_Execute fails)
static int __cdecl LuaBoostC_IsLoaded_cb(lua_State* L) {
    Api.lua_pushboolean(L, 1);
    return 1;
}

static int __cdecl LuaBoostC_GetStats_cb(lua_State* L) {
    if (!Api.lua_pushnumber || !Api.lua_pushboolean || !Api.lua_pushstring) return 0;
    Api.lua_pushnumber(L, State.luaMemoryKB);
    Api.lua_pushnumber(L, (lua_Number)State.gcStepsTotal);
    Api.lua_pushnumber(L, (lua_Number)State.fullCollects);
    Api.lua_pushnumber(L, (lua_Number)Config.gcPause);
    Api.lua_pushnumber(L, (lua_Number)Config.gcStepMul);
    Api.lua_pushboolean(L, Config.inCombat ? 1 : 0);
    Api.lua_pushstring(L, GetGCModeName());
    Api.lua_pushboolean(L, Config.isIdle ? 1 : 0);
    Api.lua_pushboolean(L, Config.isLoading ? 1 : 0);
    Api.lua_pushboolean(L, g_luaAllocReplaced ? 1 : 0);
    return 10;
}

static int __cdecl LuaBoostC_GCMemory_cb(lua_State* L) {
    if (!Api.lua_pushnumber) return 0;
    Api.lua_pushnumber(L, State.luaMemoryKB);
    return 1;
}

static int __cdecl LuaBoostC_SetCombat_cb(lua_State* L) {
    if (!Api.lua_toboolean) return 0;
    Config.inCombat = Api.lua_toboolean(L, 1) ? true : false;
    return 0;
}

static int __cdecl LuaBoostC_GCStep_cb(lua_State* L) {
    // Stub - just accept the call
    return 0;
}

static int __cdecl LuaBoostC_GCCollect_cb(lua_State* L) {
    // Stub - just accept the call
    return 0;
}

static int __cdecl LuaBoostC_GetUIStats_cb(lua_State* L) {
    if (!Api.lua_pushnumber || !Api.lua_pushboolean) return 0;
    UICache::Stats s = UICache::GetStats();
    Api.lua_pushnumber(L, (lua_Number)s.skipped);
    Api.lua_pushnumber(L, (lua_Number)s.passed);
    Api.lua_pushboolean(L, s.active ? 1 : 0);
    return 3;
}

static int __cdecl LuaBoostC_GetApiStats_cb(lua_State* L) {
    if (!Api.lua_pushnumber || !Api.lua_pushboolean) return 0;
    ApiCache::Stats s = ApiCache::GetStats();
    Api.lua_pushnumber(L, (lua_Number)s.itemHits);
    Api.lua_pushnumber(L, (lua_Number)s.itemMisses);
    Api.lua_pushnumber(L, (lua_Number)s.spellHits);
    Api.lua_pushnumber(L, (lua_Number)s.spellMisses);
    Api.lua_pushboolean(L, s.active ? 1 : 0);
    return 5;
}

static int __cdecl LuaBoostC_GetFastPathStats_cb(lua_State* L) {
    if (!Api.lua_pushnumber || !Api.lua_pushboolean) return 0;
    LuaFastPath::Stats s = LuaFastPath::GetStats();
    Api.lua_pushnumber(L, (lua_Number)s.formatFastHits);
    Api.lua_pushnumber(L, (lua_Number)s.formatFallbacks);
    Api.lua_pushboolean(L, s.active ? 1 : 0);
    return 3;
}

static void RegisterLuaFunction(lua_State* L, const char* name, void* fn) {
    if (!Api.lua_pushcclosure || !Api.lua_setfield) return;
    __try {
        Api.lua_pushcclosure(L, fn, 0);
        Api.lua_setfield(L, LUA_GLOBALSINDEX, name);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void SetupLuaInterface(lua_State* L) {
    // Use BOTH Lua C API and FrameScript_Execute to set globals.
    // WoW 3.3.5a may use a different internal lua_State for addon execution
    // than the one at 0x00D3F78C. FrameScript_Execute writes to WoW's actual
    // addon state, ensuring addons can see our markers.
    if (!Api.lua_pushboolean || !Api.lua_setfield || !Api.lua_pushcclosure) {
        Log("[LuaOpt] SetupLuaInterface: missing C API functions");
        return;
    }
    
    __try {
        // Write boolean globals via C API (for DLL-side reads)
        WriteLuaGlobal_Bool(L, "LUABOOST_DLL_LOADED", true);
        WriteLuaGlobal_Bool(L, "LUABOOST_DLL_GC_ACTIVE", State.gcOptimized);
        WriteLuaGlobal_Bool(L, "LUABOOST_DLL_LUA_ALLOC", g_luaAllocReplaced);
        
        // Initialize addon communication globals
        WriteLuaGlobal_Bool(L, "LUABOOST_ADDON_COMBAT", false);
        WriteLuaGlobal_Bool(L, "LUABOOST_ADDON_IDLE", false);
        WriteLuaGlobal_Bool(L, "LUABOOST_ADDON_LOADING", false);

        // Also inject via FrameScript_Execute for addon-side visibility
        if (Api.FrameScript_Execute) {
            __try {
                Api.FrameScript_Execute(
                    "LUABOOST_DLL_LOADED=true "
                    "LUABOOST_DLL_GC_ACTIVE=true "
                    "LUABOOST_DLL_LUA_ALLOC=true",
                    "wow_optimize_inject", 0);
                Log("[LuaOpt] SetupLuaInterface: injected markers via FrameScript_Execute");
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                Log("[LuaOpt] SetupLuaInterface: FrameScript injection failed");
            }
        }
        
        // Register C functions
        RegisterLuaFunction(L, "LuaBoostC_IsLoaded", (void*)LuaBoostC_IsLoaded_cb);
        RegisterLuaFunction(L, "LuaBoostC_GetStats", (void*)LuaBoostC_GetStats_cb);
        RegisterLuaFunction(L, "LuaBoostC_GCMemory", (void*)LuaBoostC_GCMemory_cb);
        RegisterLuaFunction(L, "LuaBoostC_SetCombat", (void*)LuaBoostC_SetCombat_cb);
        RegisterLuaFunction(L, "LuaBoostC_GCStep", (void*)LuaBoostC_GCStep_cb);
        RegisterLuaFunction(L, "LuaBoostC_GCCollect", (void*)LuaBoostC_GCCollect_cb);
        RegisterLuaFunction(L, "LuaBoostC_GetUIStats", (void*)LuaBoostC_GetUIStats_cb);
        RegisterLuaFunction(L, "LuaBoostC_GetApiStats", (void*)LuaBoostC_GetApiStats_cb);
        RegisterLuaFunction(L, "LuaBoostC_GetFastPathStats", (void*)LuaBoostC_GetFastPathStats_cb);
        
        Log("[LuaOpt] SetupLuaInterface: registered 6 globals + 9 functions on L=0x%08X", 
            (unsigned)(uintptr_t)L);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt] SetupLuaInterface: exception during registration");
    }
}

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
                // CRITICAL FIX: Never do full collect - causes 500ms-2s stalls
                // Instead, do incremental 1MB GC steps (same as emergency GC)
                // RATE LIMIT: max 1 full GC collect per 5 seconds
                static DWORD lastFullGCTick = 0;
                DWORD nowTick = GetTickCount();
                if ((LONG)(nowTick - lastFullGCTick) < 5000) {
                    // Rate limited - skip silently
                    return;
                }
                lastFullGCTick = nowTick;
                Log("[LuaOpt] Addon requested full GC collect - using incremental steps instead (rate limited: 1/5s)");
                for (int i = 0; i < 10; i++) {
                    Api.lua_gc(L, LUA_GCSTEP, 1024); // 1MB steps
                }
                State.gcStepsTotal += 10;
            } else if (val > 0) {
                // RATE LIMIT: max 10 GC step requests per second
                static DWORD lastStepGCTick = 0;
                static int stepGCCount = 0;
                DWORD nowTick2 = GetTickCount();
                if ((LONG)(nowTick2 - lastStepGCTick) >= 1000) {
                    lastStepGCTick = nowTick2;
                    stepGCCount = 0;
                }
                if (stepGCCount >= 10) {
                    // Rate limited - skip silently
                    return;
                }
                stepGCCount++;
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
// Timing Method Fix - Force QPC & block timingtesterror fallback
// ================================================================
#if !TEST_DISABLE_TIMING_FIX
typedef int (__thiscall* CVar_SetFn)(void* This, const char* value, char a3, char a4, char a5, char a6);
static CVar_SetFn orig_CVar_Set = (CVar_SetFn)0x007668C0;

int __fastcall Hooked_CVar_Set(void* This, void* unused, const char* value, char a3, char a4, char a5, char a6) {
    if (This && value) {
        const char* name = *(const char**)This;
        if (name) {
            if (_stricmp(name, "timingMethod") == 0) {
                value = "2";
            } else if (_stricmp(name, "timingTestError") == 0) {
                value = "0";
            }
        }
    }
    return orig_CVar_Set(This, value, a3, a4, a5, a6);
}

void ForceTimingOverride() {
    if (MH_CreateHook((void*)orig_CVar_Set, (void*)Hooked_CVar_Set, (void**)&orig_CVar_Set) != MH_OK) {
        Log("[TimingFix] MH_CreateHook failed");
        return;
    }
    if (MH_EnableHook((void*)orig_CVar_Set) != MH_OK) {
        Log("[TimingFix] MH_EnableHook failed");
        return;
    }
    Log("[TimingFix] CVar_Set hook installed (0x%08X) - intercepting timingMethod/timingTestError", (unsigned)orig_CVar_Set);
}
#else
void ForceTimingOverride() {}
#endif

// ================================================================
// FrameScript_Execute hook - inject DLL markers before addon code runs
// ================================================================
static fn_FrameScript_Execute g_origFrameScript = nullptr;
static volatile LONG g_frameScriptInjected = 0;
static lua_State* g_pendingInjectState = nullptr;

static void __cdecl Hooked_FrameScript_Execute(const char* code, const char* source, int unknown) {
    // Inject markers before addon code on new lua_State
    lua_State* currentL = ReadLuaState();
    if (currentL && currentL == g_pendingInjectState &&
        InterlockedCompareExchange(&g_frameScriptInjected, 1, 0) == 0) {
        __try {
            if (Api.lua_pushnil && Api.lua_setfield && Api.lua_pushboolean) {
                Api.lua_pushnil(currentL);
                Api.lua_setfield(currentL, LUA_GLOBALSINDEX, "LUABOOST_LOADED");
                Api.lua_pushboolean(currentL, 1);
                Api.lua_setfield(currentL, LUA_GLOBALSINDEX, "LUABOOST_DLL_LOADED");
                Api.lua_pushboolean(currentL, 1);
                Api.lua_setfield(currentL, LUA_GLOBALSINDEX, "LUABOOST_DLL_GC_ACTIVE");
                Log("[LuaOpt] FrameScript hook: injected DLL markers before addon load on L=0x%08X",
                    (unsigned)(uintptr_t)currentL);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            Log("[LuaOpt] FrameScript hook: injection failed");
        }
    }
    g_origFrameScript(code, source, unknown);
}

static void InstallFrameScriptInjectionHook() {
    if (!Api.FrameScript_Execute) return;
    if (MH_CreateHook((void*)Api.FrameScript_Execute, (void*)Hooked_FrameScript_Execute,
                      (void**)&g_origFrameScript) != MH_OK) {
        Log("[LuaOpt] FrameScript injection hook: FAILED");
        return;
    }
    if (MH_EnableHook((void*)Api.FrameScript_Execute) != MH_OK) {
        Log("[LuaOpt] FrameScript injection hook: enable FAILED");
        return;
    }
    Log("[LuaOpt] FrameScript injection hook: ACTIVE (will inject markers on next addon load)");
}

static void DoMainThreadInit() {
    Log("[LuaOpt] Main thread init");

    Api.L = ReadLuaState();

    if (!Api.L) {
        Log("[LuaOpt] lua_State* is NULL - Lua VM not ready");
        Log("[LuaOpt] Will retry on next frame");
        // Reset to 0 so OnMainThreadSleep retries init on next call
        InterlockedExchange(&g_luaInitState, 0);
        State.initialized = false;
        return;
    }

    Log("[LuaOpt] lua_State* = 0x%08X", (unsigned)(uintptr_t)Api.L);

    // Set LUABOOST_DLL_LOADED early before heavy init operations
    __try {
        if (Api.lua_pushboolean && Api.lua_setfield) {
            Api.lua_pushboolean(Api.L, 1);
            Api.lua_setfield(Api.L, LUA_GLOBALSINDEX, "LUABOOST_DLL_LOADED");
            Log("[LuaOpt] Early marker: LUABOOST_DLL_LOADED set on first init");
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt] Early marker: failed on first init");
    }

    bool allocOk = ReplaceLuaAllocator(Api.L);
    bool gcOk = OptimizeGC(Api.L);
    bool strOk = PreSizeStringTable(Api.L);

    SetupLuaInterface(Api.L);
    ForceTimingOverride();

    // Phase 2: discover and hook Lua library functions at runtime
    __try {
        LuaFastPath::InitPhase2(Api.L);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt] EXCEPTION in LuaFastPath::InitPhase2");
    }

    // Phase 3: WoW C-level API hooks (UnitName, etc.)
    __try {
        LuaFastPath::InitWoWHooks(Api.L);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[LuaOpt] EXCEPTION in LuaFastPath::InitWoWHooks");
    }

    if (Api.lua_pushnumber && Api.lua_setfield) {
        UpdateLuaStats(Api.L);
    }

    State.initialized = true;
    State.lastModeName = GetGCModeName();
    g_pendingLuaState = nullptr;
    g_pendingLuaStateTick = 0;
    g_pendingLuaStateFrames = 0;
    
    g_vmInitializedOnce = true;

    // Hook FrameScript_Execute for marker injection on future /reloads
    InstallFrameScriptInjectionHook();

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

namespace LuaOpt {

bool PrepareFromWorkerThread() {
    Log("[LuaOpt] ====================================");
    Log("[LuaOpt]  Lua VM Optimizer - Preparing");
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

    Log("[LuaOpt] Ready - waiting for main thread...");
    return true;
}

void OnMainThreadSleep(DWORD mainThreadId, double frameMs) {
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
        DWORD nowTick = GetTickCount();
        DWORD settleMs = g_isMultiClient ? LUA_RELOAD_SETTLE_MS_MULTI
                                         : LUA_RELOAD_SETTLE_MS_SINGLE;
        int settleFrames = g_isMultiClient ? LUA_RELOAD_SETTLE_FRAMES_MULTI
                                           : LUA_RELOAD_SETTLE_FRAMES_SINGLE;

        if (currentL != g_pendingLuaState) {
            g_pendingLuaState = currentL;
            g_pendingLuaStateTick = nowTick;
            g_pendingLuaStateFrames = 1;
            Log("[LuaOpt] lua_State changed (UI reload) - waiting for new VM to settle");

            // CRITICAL FIX: Invalidate ALL caches IMMEDIATELY when lua_State changes.
            // Previously, caches were only cleared AFTER the settle period, leaving
            // fast-path hooks active with stale pointers to the OLD lua_State's objects.
            // This caused memory corruption, freezes, and ACCESS_VIOLATION crashes
            // when hooks tried to access freed/reallocated Lua internals.
            Log("[LuaOpt] Invalidating all caches immediately (old L=0x%08X, new L=0x%08X)",
                (unsigned)(uintptr_t)Api.L, (unsigned)(uintptr_t)currentL);
            
            UICache::ClearCache();
            ApiCache::ClearCache();
            ClearLuaOptCaches();
            LuaInternals::InvalidateCache();
            LuaFastPath::InvalidateWoWCache();
            ClearTableCache();
            LuaBytecodeCache::OnLuaStateSwap();
            ClearAddonPreload();
            
            // Mark GC as not optimized to prevent StepGC from running with stale state
            State.gcOptimized = false;

            // ARM FrameScript_Execute hook for pre-addon marker injection.
            // The hook fires BEFORE any addon top-level code runs on the new
            // lua_State, injecting LUABOOST_DLL_LOADED=true and clearing
            // LUABOOST_LOADED so LuaBoost re-runs its detection.
            g_pendingInjectState = currentL;
            InterlockedExchange(&g_frameScriptInjected, 0);
            Log("[LuaOpt] FrameScript injection armed for L=0x%08X", (unsigned)(uintptr_t)currentL);
            return;
        }

        g_pendingLuaStateFrames++;
        if (g_pendingLuaStateFrames < settleFrames ||
           (DWORD)(nowTick - g_pendingLuaStateTick) < settleMs) {
            return;
        }

        g_pendingLuaState = nullptr;
        g_pendingLuaStateTick = 0;
        g_pendingLuaStateFrames = 0;
        // Reset retry counter on every lua_State swap so subsequent /reload
        // gets a fresh 10 attempts (was never reset, exhausting retries permanently)
        g_luaInterfaceRetryCount = 0;
        Log("[LuaOpt] lua_State changed (UI reload) - reinitializing stable VM");
    } else if (g_pendingLuaState) {
        g_pendingLuaState = nullptr;
        g_pendingLuaStateTick = 0;
        g_pendingLuaStateFrames = 0;
    }

    // Debounce removed: causes ACCESS_VIOLATION with overlay hooks
    // that expect immediate lua_State availability during UI transitions.
    if (currentL != Api.L) {
        Log("[LuaOpt] lua_State changed (UI reload) - updating pointer");

        // Full init only once. Re-initializing on every UI reload
        // causes heap corruption and #132 crashes from stale pointers in hooks.
        if (!g_vmInitializedOnce) {
            Log("[LuaOpt] First-time VM initialization");
            g_vmInitializedOnce = true;

            if (g_luaAllocReplaced) {
                LogLuaAllocStats();
            }
            ResetAllocStats();

            Api.L = currentL;
            State.gcOptimized = false;
            State.gcStepsTotal = 0;
            State.fullCollects = 0;
            State.statsUpdateCounter = 0;
            State.lastModeName = "unknown";
            Config.inCombat = false;
            Config.isIdle = false;
            Config.isLoading = false;
            g_loadingGraceFrames = 0;

            UICache::ClearCache();
            ApiCache::ClearCache();
            ClearLuaOptCaches();
            if (g_isMultiClient) {
                mi_collect(true);
            }
            ReplaceLuaAllocator(Api.L);
            OptimizeGC(Api.L);
            PreSizeStringTable(Api.L);
            LuaInternals::InvalidateCache();
            LuaFastPath::InvalidateWoWCache();
            ClearTableCache();
            LuaBytecodeCache::OnLuaStateSwap();
            ClearAddonPreload();
            SetupLuaInterface(Api.L);
            
            // CRITICAL: Verify interface immediately - if SetupLuaInterface failed,
            // mark for retry so CheckAndRestoreLuaInterface will fix it within 500ms
            if (!CheckAndRestoreLuaInterface(Api.L)) {
                Log("[LuaOpt] First-time init: interface verification failed, will retry");
            }
        } else {
            // Subsequent swap: clear caches + re-setup interface only.
            // Skip ReplaceLuaAllocator/OptimizeGC/PreSizeStringTable - they
            // caused heap corruption on re-init in earlier versions.
            Api.L = currentL;
            State.gcOptimized = false;
            State.gcStepsTotal = 0;
            State.lastModeName = "unknown";
            Config.inCombat = false;
            Config.isIdle = false;
            Config.isLoading = false;
            g_loadingGraceFrames = 0;

            UICache::ClearCache();
            ApiCache::ClearCache();
            ClearLuaOptCaches();
            LuaInternals::InvalidateCache();
            LuaFastPath::InvalidateWoWCache();
            ClearTableCache();
            LuaBytecodeCache::OnLuaStateSwap();
            ClearAddonPreload();
            SetupLuaInterface(Api.L);
            
            // CRITICAL: Verify interface immediately after /reload
            // If FrameScript_Execute threw exception or LuaBoost loaded before us,
            // we need to retry within 500ms (not 3 seconds)
            if (!CheckAndRestoreLuaInterface(Api.L)) {
                Log("[LuaOpt] Subsequent swap: interface verification failed, will retry");
            } else {
                Log("[LuaOpt] Subsequent swap - caches cleared, interface re-setup");
            }
        }
        g_addonReadCounter = 0;
        g_gcRequestCounter = 0;
        g_lastSyncNormal = -1;
        g_lastSyncCombat = -1;
        g_lastSyncIdle = -1;
        g_lastSyncLoading = -1;
        g_lastLuaSwapTick = GetTickCount();
        g_smoothedGcMs = 0.5;
        return;
    }

    // Read addon state more aggressively on slow/high-memory frames so
    // loading-mode protections engage before zone-transition allocations spike.
    bool slowFrame = (frameMs > 33.0);
    bool verySlowFrame = (frameMs > 50.0);
    int addonPollMask = (slowFrame || Config.isLoading || State.luaMemoryKB > 256 * 1024) ? 3 : 15;

    if ((++g_addonReadCounter & addonPollMask) == 0) {
        ReadAddonStateFromLua(Api.L);
    }

    // Check Lua interface every 2 frames (~33ms at 60fps)
    // Detects /reload even when mimalloc reuses the same lua_State* pointer
    // Cost is 2 lua_getfield + 2 lua_type + 2 lua_settop = negligible
    if ((++g_luaInterfaceCheckCounter & 1) == 0) {
        CheckAndRestoreLuaInterface(Api.L);
    }

    if (!verySlowFrame && (++g_gcRequestCounter & 3) == 0) {
        ProcessGCRequests(Api.L);
    }

    if (!verySlowFrame) {
        StepGC(Api.L, frameMs);
    }

    if (!slowFrame && (State.statsUpdateCounter & 63) == 0) {
        UpdateLuaStats(Api.L);
    }

    if (!slowFrame && g_luaAllocReplaced) {
        // Single client: collect every ~8192 steps (~136 seconds at 60fps)
        // Multi-client: collect every ~2048 steps (~34 seconds at 60fps)
        int collectInterval = g_isMultiClient ? 2047 : 8191;
        if ((State.statsUpdateCounter & collectInterval) == 0) {
            LogLuaAllocStats();
            mi_collect(false);
        }
        // Multi-client: every ~8x the normal collect, do aggressive reclaim
        // to return freed pages to OS. Prevents VA fragmentation that causes
        // ERROR #134 during character switches when 3-4 clients share 4GB.
        if (g_isMultiClient) {
            int aggressiveInterval = 16383; // ~273s at 60fps
            if ((State.statsUpdateCounter & aggressiveInterval) == 0) {
                mi_collect(true);
            }
        }
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
    g_addonReadCounter = 0;
    g_gcRequestCounter = 0;
    g_pendingLuaState = nullptr;
    g_pendingLuaStateTick = 0;
    g_pendingLuaStateFrames = 0;
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

bool LuaOpt::IsLoadingMode() {
    return Config.isLoading;
}

bool IsReloading() { return g_isReloading.load(std::memory_order_acquire); }
bool IsSwapping()  { return g_isSwapping.load(std::memory_order_acquire); }

void RestoreAllocator() {
    if (g_luaAllocReplaced) {
        RestoreLuaAllocator();
    }
}

} // namespace LuaOpt
