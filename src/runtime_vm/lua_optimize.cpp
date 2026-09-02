// ============================================================================
// Module: lua_optimize.cpp
// Description: Lua garbage collection optimizer. Monitors and paces Lua GC cycles within the rendering loop to prevent garbage collection stalls.
// Safety & Threading: Main render thread only. Disabling pacing will cause heap growth until memory is exhausted.
// ============================================================================

#include "lua_optimize.h"
#include "lua_proto_cache.h"
// config.h is deliberately NOT included here: this file declares a file-scope
// object called Config, and a variable cannot share a name with a namespace in
// the same scope. These two accessors are defined in config.cpp instead.
extern "C" bool WowOpt_LuaVmOptEnabled();
extern "C" bool WowOpt_LuaGcManualEnabled();
#include "diagnostics/crash_dumper.h"
#include "../allocators/loading_defrag.h"
#include "combatlog_optimize.h"
#include "ui_cache.h"
#include "api_cache.h"
#include "combatlog_parser.h"
#include "lua_fastpath.h"
#include "lua_vm_cache.h"
#include "lua_bytecode_cache.h"
#include "addon_preload.h"
#include "event_dispatch_cache.h"

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
#include "version_checker.h"
#include "heap_compactor.h"

extern bool g_isMultiClient;
extern "C" void Log(const char* fmt, ...);
extern "C" SIZE_T HeapCompactor_GetCachedLowHalf();

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
typedef const char* (__cdecl *fn_lua_tolstring)(lua_State* L, int index, size_t* len);
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
    static constexpr uintptr_t lua_pushcclosure    = 0x0084E400;
    static constexpr uintptr_t lua_tolstring       = 0x0084E0E0;
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
    fn_lua_tolstring        lua_tolstring = nullptr;
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
    int  idleStepKB     = 64;    // was 256 → 128 → 64: idle atomic-phase stutter fix
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
    RESOLVE(lua_tolstring,   Addr::lua_tolstring,   fn_lua_tolstring,   "lua_tolstring");

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

        if (Config.manualGCMode && WowOpt_LuaGcManualEnabled()) {
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
    if (Config.isIdle)    return (Config.idleStepKB > 128) ? 128 : Config.idleStepKB;
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

    // During combat: spread collection across frames as small steps, sized to
    // ~110% of the measured allocation rate so the heap trends FLAT.
    //
    // The previous logic collected only ~50% of the alloc rate (capped at 32KB)
    // and skipped GC entirely on any frame >18ms. During a sustained heavy raid
    // (frames are routinely >18ms) that starved the collector: garbage grew until
    // Lua forced a full collection of the entire multi-hundred-MB state, which is
    // the multi-second mid-fight freeze testers reported. Matching the alloc rate
    // keeps memory stable with steady tiny steps instead of one giant stall.
    if (Config.inCombat && !Config.isLoading) {
        LONG64 netAlloc = GetAndResetNetAlloc();
        if (netAlloc < 0) netAlloc = 0;
        g_smoothedNetAlloc = g_smoothedNetAlloc * 0.9 + (double)netAlloc * 0.1;

        int stepKB = (int)(g_smoothedNetAlloc / 1024.0 * 1.1);  // stay just ahead
        if (stepKB < 16) stepKB = 16;

        // On an already-slow frame, halve the step to avoid compounding the
        // stutter -- but never skip, or garbage runs away over a long fight.
        // On high-FPS frames, scale up the step to clean up proactively.
        if (frameMs > 0.0) {
            if (frameMs > 16.0) {
                stepKB = (stepKB > 32) ? stepKB / 2 : 16;
            } else if (frameMs < 8.0) {
                stepKB = stepKB * 3 / 2;
            }
        }

        // Bound a single step; bursts above this catch up over the next frames.
        if (stepKB > 1024) stepKB = 1024;

        if (g_gcPerfFreq.QuadPart == 0) QueryPerformanceFrequency(&g_gcPerfFreq);
        LARGE_INTEGER before, after;
        QueryPerformanceCounter(&before);
        __try {
            Api.lua_gc(L, LUA_GCSTEP, stepKB);
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

    // During loading screens, the Sleep hook may not fire for seconds, so the
    // per-frame GC step misses entirely. When it does fire, burst-step several
    // times at the loading interval to catch up — this prevents the post-load
    // freeze spike when the world first renders and triggers a forced collection.
    if (Config.isLoading) {
        int stepKB = Config.loadingStepKB;
        if (stepKB > 1024) stepKB = 1024;
        for (int burst = 0; burst < 4; burst++) {
            __try {
                Api.lua_gc(L, LUA_GCSTEP, stepKB);
                State.gcStepsTotal++;
            } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
        }
        return;
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

    // Idle mode with negligible allocation: skip manual GC stepping.
    // Lua 5.1's internal luaC_checkGC on the rare allocation will still collect.
    // Prevents periodic atomic-phase stutter on large idle heaps (~80ms spikes).
    if (Config.isIdle && !Config.isLoading && g_smoothedNetAlloc < 1024.0) {
        return;
    }

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

    // VA-pressure override: when contiguous 32-bit address space runs low (the
    // usual precursor to an HD-client OOM crash) collect harder to return Lua
    // memory to the OS before a large engine allocation fails -- a small GC step
    // beats ERROR #134. Uses the heap compactor's cached sample (0 = not yet
    // measured -> ignored). Bounded to 8MB/frame so it can't itself stall.
    {
        // Below 2GB, not across the whole space. This read the full-range
        // figure until 2026-09-02, so in a session whose low half was down to a
        // 1MB largest block it saw 1237MB and never stepped harder once.
        SIZE_T vaLargest = HeapCompactor_GetCachedLowHalf();
        if (vaLargest != 0 && vaLargest < 48u * 1024 * 1024) {
            stepKB *= 3;
            if (stepKB > 8192) stepKB = 8192;
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
            if (Config.idleStepKB < 128) Config.idleStepKB += 8;
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

// Is our marker still standing in this state's globals?
//
// Swap detection compares the lua_State pointer, which only works where the
// client allocates a new one. Two players on Warmane reported the DLL going
// "not detected" after switching character and staying that way until a full
// restart - the pointer had been handed back at the same address, so
// currentL == Api.L, the swap branch never ran, and the globals the companion
// addon looks for were never put back into the rebuilt state.
//
// The pointer is a proxy for the question. This asks the question: if the
// marker is gone, the state was rebuilt, whatever the address says.
static bool MarkerStillPresent(lua_State* L) {
    if (!L || !Api.lua_getfield || !Api.lua_toboolean ||
        !Api.lua_gettop || !Api.lua_settop) {
        return true;   // cannot tell - never report a false rebuild
    }

    bool present = false;
    int top = Api.lua_gettop(L);
    __try {
        Api.lua_getfield(L, LUA_GLOBALSINDEX, "LUABOOST_DLL_LOADED");
        present = Api.lua_toboolean(L, -1) != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        present = true;   // a fault here is not evidence of a rebuild
    }
    Api.lua_settop(L, top);
    return present;
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
    if (!Api.lua_getfield || !Api.lua_toboolean || !Api.lua_settop || !Api.lua_gettop) return;

    int topBefore = Api.lua_gettop(L);
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
            PreWarmEventDispatchCache();
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
    Api.lua_settop(L, topBefore);
}

// The walk of last resort.
//
// VirtualQuery once per region over the whole address space. On a fragmented
// 3GB space that is tens of thousands of syscalls and tens of milliseconds, and
// UpdateLuaStats was calling it from a frame up to once a second, all session,
// for one number an addon displays. The heap compactor's monitor thread already
// pays for this walk every ten seconds off the main thread, so the only reason
// left to run it here is that the compactor is switched off - and then once a
// minute, not once a second.
static SIZE_T GetLargestFreeBlock() {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T largestFree = 0;
    SIZE_T currentFree = 0;
    uintptr_t addr = 0;
    
    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_FREE) {
            currentFree += mbi.RegionSize;
        } else {
            if (currentFree > largestFree) {
                largestFree = currentFree;
            }
            currentFree = 0;
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uintptr_t)mbi.BaseAddress) break; // Overflow
    }
    
    if (currentFree > largestFree) {
        largestFree = currentFree;
    }
    
    return largestFree;
}

static DWORD g_lastMemoryQueryTick = 0;
static double g_cachedWorkingSetMB = 0.0;
static double g_cachedCommitMB = 0.0;
static double g_cachedLargestFreeMB = 0.0;
// Which way the figure above was obtained, so the periodic report can say. A
// walk here is main-thread time inside a frame; a hand-over from the monitor
// thread is three loads.
static DWORD g_lastOwnWalkTick   = 0;
static unsigned long g_vaFromMonitor = 0;
static unsigned long g_vaOwnWalks    = 0;
static double g_vaOwnWalkMsWorst = 0.0;

extern "C" void FontMetrics_GetStats(long* widthCalls, long* heightCalls);

// Where the fragmentation figure came from, for the periodic report.
//
// Three states, not two: handed over by the monitor thread, walked here, or
// neither because UpdateLuaStats never ran. The caller can tell them apart
// because the two counts are separate and both can be zero.
extern "C" void LuaOpt_GetVaSourceStats(unsigned long* fromMonitor,
                                        unsigned long* ownWalks,
                                        double* ownWorstMs) {
    if (fromMonitor) *fromMonitor = g_vaFromMonitor;
    if (ownWalks)    *ownWalks    = g_vaOwnWalks;
    if (ownWorstMs)  *ownWorstMs  = g_vaOwnWalkMsWorst;
}

static void UpdateLuaStats(lua_State* L) {
    if (!Api.lua_pushnumber || !Api.lua_setfield || !Api.lua_gettop || !Api.lua_settop) return;

    int topBefore = Api.lua_gettop(L);
    __try {
        DWORD now = GetTickCount();
        if (now - g_lastMemoryQueryTick >= 1000 || g_lastMemoryQueryTick == 0) {
            g_lastMemoryQueryTick = now;
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
                g_cachedWorkingSetMB = (double)pmc.WorkingSetSize / (1024.0 * 1024.0);
                g_cachedCommitMB = (double)pmc.PagefileUsage / (1024.0 * 1024.0);
            }
            // Prefer the monitor thread's result at any age. It walks every ten
            // seconds, and a ten-second-old fragmentation figure is the same
            // answer for a number that moves over minutes.
            SIZE_T largest = 0;
            unsigned long ageMs = 0;
            if (HeapCompactor_GetLastLargestFree(&largest, &ageMs)) {
                g_cachedLargestFreeMB = (double)largest / (1024.0 * 1024.0);
                ++g_vaFromMonitor;
            } else if (g_lastOwnWalkTick == 0 ||
                       now - g_lastOwnWalkTick >= 60000) {
                LARGE_INTEGER wf, wa, wb;
                QueryPerformanceFrequency(&wf);
                QueryPerformanceCounter(&wa);
                g_cachedLargestFreeMB = (double)GetLargestFreeBlock()
                                      / (1024.0 * 1024.0);
                QueryPerformanceCounter(&wb);
                g_lastOwnWalkTick = now;
                ++g_vaOwnWalks;
                if (wf.QuadPart) {
                    double ms = (double)(wb.QuadPart - wa.QuadPart) * 1000.0
                              / (double)wf.QuadPart;
                    if (ms > g_vaOwnWalkMsWorst) g_vaOwnWalkMsWorst = ms;
                }
            }
        }

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

        WriteLuaGlobal_Number(L, "LUABOOST_DLL_MEM_WORKING_SET_MB", g_cachedWorkingSetMB);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_MEM_COMMIT_MB",      g_cachedCommitMB);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_MEM_LARGEST_FREE_MB", g_cachedLargestFreeMB);

        long fmWidth = 0, fmHeight = 0;
        FontMetrics_GetStats(&fmWidth, &fmHeight);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_FONTMETRICS_WIDTH_CALLS", (double)fmWidth);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_FONTMETRICS_HEIGHT_CALLS", (double)fmHeight);

        UICache::Stats uiStats = UICache::GetStats();
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_UICACHE_SKIPPED", (double)uiStats.skipped);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_UICACHE_PASSED", (double)uiStats.passed);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_UICACHE_ACTIVE",  uiStats.active);

        ApiCache::Stats apiStats = ApiCache::GetStats();
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_APICACHE_ITEM_HITS",  (double)apiStats.itemHits);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_APICACHE_ITEM_MISSES", (double)apiStats.itemMisses);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_APICACHE_ITEM_BYPASSED", (double)apiStats.itemBypassed);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_APICACHE_ACTIVE", apiStats.active);

        LuaFastPath::Stats fpStats = LuaFastPath::GetStats();
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_FASTPATH_HITS",     (double)fpStats.formatFastHits);
        WriteLuaGlobal_Number(L, "LUABOOST_DLL_FASTPATH_FALLBACKS", (double)fpStats.formatFallbacks);
        WriteLuaGlobal_Bool(L,   "LUABOOST_DLL_FASTPATH_ACTIVE",    fpStats.active);
 
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    Api.lua_settop(L, topBefore);
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

// Metatable __index stub for GMChatFrame.lastGM.
// Returns "" for all keys, preventing nil-concatenation crash at UIParent.lua:476.
static int __cdecl gm_index_stub(lua_State* L) {
    if (Api.lua_pushstring) {
        Api.lua_pushstring(L, "");
        return 1;
    }
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
    Api.lua_pushnumber(L, (lua_Number)s.itemBypassed);
    Api.lua_pushboolean(L, s.active ? 1 : 0);
    return 4;
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

    // Handing the VM a C function outside the client's accepted pointer range is a
    // fatal ERROR #134, raised by the client itself - the SEH block below cannot
    // catch it, so the check has to happen before the push.
    if (!LuaCFunctionAccepted(fn)) {
        Log("[LuaOpt] Skipping global '%s': 0x%08X is outside WoW's lua_CFunction range",
            name, (unsigned)(uintptr_t)fn);
        return;
    }

    __try {
        Api.lua_pushcclosure(L, fn, 0);
        Api.lua_setfield(L, LUA_GLOBALSINDEX, name);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void SetupLuaInterface(lua_State* L) {
    ApiCache::ClearCache();
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

        // Version info so the addon can warn when DLL is outdated.
        WriteLuaGlobal_String(L, "LUABOOST_DLL_VERSION", WOW_OPTIMIZE_VERSION_STR);
        char latest[32] = {};
        if (VersionChecker_GetLatestVersion(latest, sizeof(latest))) {
            WriteLuaGlobal_String(L, "LUABOOST_DLL_LATEST_VERSION", latest);
        } else {
            WriteLuaGlobal_String(L, "LUABOOST_DLL_LATEST_VERSION", "unknown");
        }

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
        
        // Register C functions (SKIPPED to bypass WoW function pointer whitelist integrity checks)
        /*
        RegisterLuaFunction(L, "LuaBoostC_IsLoaded", (void*)LuaBoostC_IsLoaded_cb);
        RegisterLuaFunction(L, "LuaBoostC_GetStats", (void*)LuaBoostC_GetStats_cb);
        RegisterLuaFunction(L, "LuaBoostC_GCMemory", (void*)LuaBoostC_GCMemory_cb);
        RegisterLuaFunction(L, "LuaBoostC_SetCombat", (void*)LuaBoostC_SetCombat_cb);
        RegisterLuaFunction(L, "LuaBoostC_GCStep", (void*)LuaBoostC_GCStep_cb);
        RegisterLuaFunction(L, "LuaBoostC_GCCollect", (void*)LuaBoostC_GCCollect_cb);
        RegisterLuaFunction(L, "LuaBoostC_GetUIStats", (void*)LuaBoostC_GetUIStats_cb);
        RegisterLuaFunction(L, "LuaBoostC_GetApiStats", (void*)LuaBoostC_GetApiStats_cb);
        RegisterLuaFunction(L, "LuaBoostC_GetFastPathStats", (void*)LuaBoostC_GetFastPathStats_cb);
        */
        
        LogEx(LOG_LEVEL_INFO, "LUA", "SetupLuaInterface: registered 6 globals on L=0x%08X", 
            (unsigned)(uintptr_t)L);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LogEx(LOG_LEVEL_WARN, "LUA", "SetupLuaInterface: exception during registration");
    }
}

static void ProcessGCRequests(lua_State* L) {
    if (!Api.lua_getfield || !Api.lua_type || !Api.lua_tonumber ||
        !Api.lua_pushnil || !Api.lua_setfield || !Api.lua_settop || !Api.lua_gc || !Api.lua_gettop) {
        return;
    }

    int topBefore = Api.lua_gettop(L);
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
                    Api.lua_settop(L, topBefore);
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
                    Api.lua_settop(L, topBefore);
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
    Api.lua_settop(L, topBefore);
}

static void ProcessLuaErrors(lua_State* L) {
    if (!L || !Api.lua_getfield || !Api.lua_type || !Api.lua_pushnil || !Api.lua_setfield || !Api.lua_settop || !Api.lua_tolstring || !Api.lua_gettop) {
        return;
    }

    int topBefore = Api.lua_gettop(L);
    __try {
        Api.lua_getfield(L, LUA_GLOBALSINDEX, "LUABOOST_LUA_ERROR_REPORT");
        int t = Api.lua_type(L, -1);
        if (t == 4) { // LUA_TSTRING
            size_t len = 0;
            const char* report = Api.lua_tolstring(L, -1, &len);
            if (report && len > 0) {
                LogEx(LOG_LEVEL_ERROR, "LUA_ERR", "Lua Runtime Error Intercepted:\n%s", report);

                // Walk C++ stack trace of the calling thread
                void* stack[32];
                USHORT frames = CaptureStackBackTrace(1, 32, stack, nullptr);
                LogEx(LOG_LEVEL_ERROR, "LUA_ERR", "C++ Stack Backtrace (Offsets):");
                for (USHORT i = 0; i < frames; i++) {
                    uintptr_t addr = (uintptr_t)stack[i];
                    HMODULE hMod = nullptr;
                    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)addr, &hMod) && hMod) {
                        char modPath[MAX_PATH] = "";
                        GetModuleFileNameA(hMod, modPath, sizeof(modPath));
                        const char* lastSlash = strrchr(modPath, '\\');
                        const char* filename = lastSlash ? (lastSlash + 1) : modPath;
                        LogEx(LOG_LEVEL_ERROR, "LUA_ERR", "  [%02d] %s+0x%08X", i, filename, addr - (uintptr_t)hMod);
                    } else {
                        LogEx(LOG_LEVEL_ERROR, "LUA_ERR", "  [%02d] 0x%08X", i, addr);
                    }
                }
            }

            // Clear the report
            Api.lua_settop(L, -2);
            Api.lua_pushnil(L);
            Api.lua_setfield(L, LUA_GLOBALSINDEX, "LUABOOST_LUA_ERROR_REPORT");
        } else {
            Api.lua_settop(L, -2);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    Api.lua_settop(L, topBefore);
}

// ================================================================
// Timing Method Fix - Force QPC & block timingtesterror fallback
// ================================================================
#if !TEST_DISABLE_TIMING_FIX
typedef int (__thiscall* CVar_SetFn)(void* This, const char* value, char a3, char a4, char a5, char a6);
static CVar_SetFn orig_CVar_Set = (CVar_SetFn)0x007668C0;

int __fastcall Hooked_CVar_Set(void* This, void* unused, const char* value, char a3, char a4, char a5, char a6) {
    if (This && value) {
        const char* name = *(const char**)((char*)This + 20);
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
    Log("[TimingFix] Consolidated timing override into CvarNullGuard hook.");
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

extern "C" bool FrameThrottle_Check(const char* namePtr);

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
                if (Api.FrameScript_Execute) {
                    Api.FrameScript_Execute(
                        "local f=CreateFrame'Frame' "
                        "f:RegisterEvent'VARIABLES_LOADED' "
                        "f:RegisterEvent'PLAYER_LOGIN' "
                        "f:RegisterEvent'PLAYER_ENTERING_WORLD' "
                        "f:SetScript('OnEvent', function() "
                        "  local gm = GMChatFrame "
                        "  if gm then "
                        "    if type(gm.lastGM) ~= 'table' then gm.lastGM = {} end "
                        "    setmetatable(gm.lastGM, {__index = function() return '' end}) "
                        "  end "
                        "end) "
                        "local mt = getmetatable(CreateFrame('Frame')) "
                        "if mt and mt.__index and mt.__index.SetScript then "
                        "  local orig = mt.__index.SetScript "
                        "  local list = {details=true, recount=true, skada=true, auctionator=true, auctioneer=true, questhelper=true, gatherer=true, carbonite=true, postal=true, bagnon=true, arkinventory=true, atlasloot=true, overachiever=true, wim=true, chatter=true, prat=true} "
                        "  mt.__index.SetScript = function(self, st, h) "
                        "    if st == 'OnUpdate' and h then "
                        "      local n = self:GetName() "
                        "      if n then "
                        "        n = string.lower(n) "
                        "        for k in pairs(list) do "
                        "          if string.find(n, k, 1, true) then "
                        "            local last = 0 "
                        "            orig(self, st, function(self, el) "
                        "              local now = GetTime() "
                        "              local fps = GetFramerate() "
                        "              local interval = 0.0 "
                        "              if fps < 30 then "
                        "                interval = 0.1 "
                        "              elseif fps < 55 then "
                        "                interval = 0.05 "
                        "              end "
                        "              if now - last >= interval then "
                        "                last = now "
                        "                h(self, el) "
                        "              end "
                        "            end) "
                        "            return "
                        "          end "
                        "        end "
                        "      end "
                        "    end "
                        "    orig(self, st, h) "
                        "  end "
                        "end",
                        "wow_optimize_gm_fix", 0);
                }
                
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
    if (WO_EnableHook((void*)Api.FrameScript_Execute) != MH_OK) {
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

#if !TEST_DISABLE_FRAMESCRIPT_EXECUTE
    // Hook FrameScript_Execute for marker injection on future /reloads
    InstallFrameScriptInjectionHook();
#else
    Log("[LuaOpt] FrameScript injection hook: DISABLED via feature flag");
#endif

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

#if !TEST_DISABLE_COMBATLOG_PARSER
extern "C" int LUABOOST_GetCombatStats(void* L);
extern "C" int LUABOOST_ResetCombatStats(void* L);

static void CombatLogParser_Update(lua_State* L) {
    if (!L || !Api.lua_getfield || !Api.lua_toboolean || !Api.lua_pushnil || !Api.lua_setfield || !Api.lua_settop || !Api.lua_gettop) {
        return;
    }

    int topBefore = Api.lua_gettop(L);
    __try {
        // 1. Check for reset request
        Api.lua_getfield(L, LUA_GLOBALSINDEX, "LUABOOST_COMBAT_STATS_RESET");
        if (Api.lua_toboolean(L, -1)) {
            LUABOOST_ResetCombatStats(L);
            
            // Reset flag
            Api.lua_pushnil(L);
            Api.lua_setfield(L, LUA_GLOBALSINDEX, "LUABOOST_COMBAT_STATS_RESET");
        }

        // 2. Check for stats data request
        Api.lua_getfield(L, LUA_GLOBALSINDEX, "LUABOOST_COMBAT_STATS_REQUEST");
        if (Api.lua_toboolean(L, -1)) {
            LUABOOST_GetCombatStats(L);
            Api.lua_setfield(L, LUA_GLOBALSINDEX, "LUABOOST_COMBAT_STATS");

            // Reset request flag
            Api.lua_pushnil(L);
            Api.lua_setfield(L, LUA_GLOBALSINDEX, "LUABOOST_COMBAT_STATS_REQUEST");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    Api.lua_settop(L, topBefore);
}
#endif

void OnMainThreadSleep(DWORD mainThreadId, double frameMs) {
    if (GetCurrentThreadId() != mainThreadId) return;

    LONG state = g_luaInitState;

    if (state == 1) {
        if (InterlockedCompareExchange(&g_luaInitState, 2, 1) == 1) {
            // Took no setting until 3.18.2, so a client with every switch
            // off still had its Lua allocator replaced, its string table
            // resized and its automatic GC stopped.
            if (WowOpt_LuaVmOptEnabled()) {
                DoMainThreadInit();
            } else {
                Log("[LuaOpt] disabled via configuration - the VM keeps its own allocator, GC and string table");
            }
        }
        return;
    }

    if (state != 2 || !State.initialized || !Api.L) return;

    // Detect lua_State swap BEFORE the gcOptimized guard.
    // On Isengard the lua_State pointer changes on /reload, triggering the
    // first-encounter branch which sets gcOptimized=false. Without this
    // reorder, every subsequent frame hits !gcOptimized and returns early,
    // never advancing the settle timer (line 1571). On Warmane/Chromiecraft
    // where the pointer is reused, currentL==Api.L and this path is skipped.
    lua_State* currentL = ReadLuaState();
    if (!currentL) return;

    // A rebuilt state at the same address looks identical to no change at all,
    // so ask the state itself rather than the pointer. Checked on a timer, not
    // every frame: it costs a getfield and this runs on the main thread.
    if (currentL == Api.L) {
        static DWORD s_nextMarkerCheck = 0;
        DWORD nowTick = GetTickCount();
        if ((LONG)(nowTick - s_nextMarkerCheck) >= 0) {
            s_nextMarkerCheck = nowTick + 2000;
            // Require the marker to be missing twice in a row on the same state
            // before believing it.
            //
            // A single look is not enough, and a log from Warmane shows why: the
            // message fired on L=0x381817D8, and a moment later that state was
            // replaced by 0x40BD8E90. A real reload tears the globals down before
            // it swaps the pointer, so for a brief window the marker is gone from
            // a state whose address has not changed yet - which is exactly what
            // "rebuilt in place" was meant to detect, and is not it. The swapping
            // and reloading flags do not help here because they are raised when
            // the pointer changes, which is after this window.
            //
            // Two sightings two seconds apart cannot both land inside that
            // window: a reload swaps the pointer in milliseconds, so the second
            // look sees a different state and the count resets. Only a state that
            // is genuinely staying put without our marker survives to act on.
            static lua_State* s_missingOn   = nullptr;
            static int        s_missingSeen = 0;

            bool markerGone = !g_isSwapping.load(std::memory_order_acquire) &&
                              !g_isReloading.load(std::memory_order_acquire) &&
                              !MarkerStillPresent(currentL);

            if (!markerGone || currentL != s_missingOn) {
                s_missingOn   = markerGone ? currentL : nullptr;
                s_missingSeen = markerGone ? 1 : 0;
            } else {
                ++s_missingSeen;
            }

            if (markerGone && s_missingSeen >= 2) {
                s_missingOn   = nullptr;
                s_missingSeen = 0;
                Log("[LuaOpt] LUABOOST_DLL_LOADED is gone from an unchanged lua_State "
                    "(0x%08X) - the state was rebuilt in place, reinjecting markers",
                    (unsigned)(uintptr_t)currentL);
                CrashDumper::Trace("LUA state rebuilt in place - reinjecting markers");
                g_pendingInjectState = currentL;
                InterlockedExchange(&g_frameScriptInjected, 0);
                g_lastLuaSwapTick = nowTick;
            }
        }
    }

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
            CrashDumper::Trace("LUA state swap (UI reload) - new VM settling");
            Log("[LuaOpt] lua_State changed (UI reload) - waiting for new VM to settle");

            // This detector sees every swap; the proto cache's own l_G
            // comparison does not, because the client's Lua memory pool hands
            // the new global state the old one's address. Tell it here.
            LuaProtoCache::OnLuaStateSwapped();

            // CRITICAL FIX: Set swapping flag BEFORE cache invalidation so inline
            // hooks (GetStrInline, RawGetIInline, LuaRawGet) bail out to original
            // functions instead of dereferencing freed lua_State memory. Without
            // this, hooks operate on stale pointers between detection and
            // invalidation, returning wrong nodes/nil and causing addon errors.
            g_isSwapping.store(true, std::memory_order_release);
            g_isReloading.store(true, std::memory_order_release);

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

            State.gcOptimized = false;
            LARGE_INTEGER collectStart = StallProbeBegin();
            mi_collect(true);
            StallProbeEnd("lua_State swap mi_collect", collectStart, 4.0);

            g_pendingInjectState = currentL;
            InterlockedExchange(&g_frameScriptInjected, 0);
            Log("[LuaOpt] FrameScript injection armed for L=0x%08X", (unsigned)(uintptr_t)currentL);

            __try {
                int topBefore = Api.lua_gettop ? Api.lua_gettop(currentL) : 0;
                WriteLuaGlobal_Bool(currentL, "LUABOOST_DLL_LOADED", true);
                WriteLuaGlobal_Bool(currentL, "LUABOOST_DLL_GC_ACTIVE", false);
                WriteLuaGlobal_Bool(currentL, "LUABOOST_DLL_LUA_ALLOC", g_luaAllocReplaced);
                WriteLuaGlobal_String(currentL, "LUABOOST_DLL_VERSION", WOW_OPTIMIZE_VERSION_STR);
                char latest[32] = {};
                if (VersionChecker_GetLatestVersion(latest, sizeof(latest))) {
                    WriteLuaGlobal_String(currentL, "LUABOOST_DLL_LATEST_VERSION", latest);
                } else {
                    WriteLuaGlobal_String(currentL, "LUABOOST_DLL_LATEST_VERSION", "unknown");
                }
                if (Api.lua_settop) Api.lua_settop(currentL, topBefore);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                // Stack may be dirty after exception — clean up
                __try { if (Api.lua_settop) Api.lua_settop(currentL, 0); }
                __except(EXCEPTION_EXECUTE_HANDLER) {}
            }
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
        g_luaInterfaceRetryCount = 0;
        CrashDumper::Trace("LUA state swap - reinitializing stable VM");
        Log("[LuaOpt] lua_State changed (UI reload) - reinitializing stable VM");

        // Re-initialization about to begin — keep swapping flag set until
        // DoMainThreadInit-style work below completes (line ~1648).
    } else if (g_pendingLuaState) {
        g_pendingLuaState = nullptr;
        g_pendingLuaStateTick = 0;
        g_pendingLuaStateFrames = 0;
    }

    if (currentL != Api.L) {
        Log("[LuaOpt] lua_State changed (UI reload) - updating pointer");

        if (!g_vmInitializedOnce) {
            Log("[LuaOpt] First-time VM initialization");
            g_vmInitializedOnce = true;
            if (g_luaAllocReplaced) { LogLuaAllocStats(); }
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
            if (g_isMultiClient) { mi_collect(true); }
            ReplaceLuaAllocator(Api.L);
            OptimizeGC(Api.L);
            PreSizeStringTable(Api.L);
            LuaInternals::InvalidateCache();
            LuaFastPath::InvalidateWoWCache();
            ClearTableCache();
            LuaBytecodeCache::OnLuaStateSwap();
            ClearAddonPreload();
            SetupLuaInterface(Api.L);
            if (!CheckAndRestoreLuaInterface(Api.L)) {
                Log("[LuaOpt] First-time init: interface verification failed, will retry");
            }
        } else {
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
            __try {
                LuaFastPath::InitPhase2(Api.L);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                Log("[LuaOpt] EXCEPTION in LuaFastPath::InitPhase2 during swap");
            }
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

        // Swap complete — inline hooks can safely resume on the new lua_State.
        g_isSwapping.store(false, std::memory_order_release);
        g_isReloading.store(false, std::memory_order_release);
        return;
    }

    if (!State.gcOptimized) return;

    bool slowFrame = (frameMs > 33.0);
    bool verySlowFrame = (frameMs > 50.0);

    // Read addon state more aggressively on slow/high-memory frames so
    // loading-mode protections engage before zone-transition allocations spike.
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
        ProcessLuaErrors(Api.L);
#if !TEST_DISABLE_COMBATLOG_PARSER
        CombatLogParser_Update(Api.L);
#endif
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
            int topBefore = Api.lua_gettop ? Api.lua_gettop(L) : 0;
            __try {
                WriteLuaGlobal_Bool(L, "LUABOOST_DLL_LOADED", false);
                WriteLuaGlobal_Bool(L, "LUABOOST_DLL_GC_ACTIVE", false);
                WriteLuaGlobal_Bool(L, "LUABOOST_DLL_LUA_ALLOC", false);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
            __try { if (Api.lua_settop) Api.lua_settop(L, topBefore); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    LogEx(LOG_LEVEL_INFO, "LUA", "Shutdown. Total: %d GC steps, %d full collects",
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
    return Config.isLoading || LoadingDefrag::IsLoadingActive();
}

bool IsReloading() {
    return g_isReloading.load(std::memory_order_acquire) || LoadingDefrag::IsLoadingActive();
}

bool IsSwapping()  {
    return g_isSwapping.load(std::memory_order_acquire) || LoadingDefrag::IsLoadingActive();
}
DWORD GetLastSwapTick() { return g_lastLuaSwapTick; }
bool IsInitialized() { return State.initialized; }

void RestoreAllocator() {
    if (g_luaAllocReplaced) {
        RestoreLuaAllocator();
    }
}

} // namespace LuaOpt
