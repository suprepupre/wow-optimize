// ============================================================================
// Module: hooks_logic.cpp
// Description: Installs and manages target intercepts for subsystem `hooks_logic.cpp`.
// Safety & Threading: Stack layouts and register conventions must match target function definitions exactly.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"
#include "hooks_logic.h"
#include "crash_dumper.h"

extern "C" void Log(const char* fmt, ...);
extern "C" void FlushCoalescedPackets();


static bool IsTeardownState();

// ================================================================
// Coalesced layout recalculation

static void* g_dirtyLayoutFrames[2048] = {};
static int g_dirtyLayoutFramesCount = 0;
static bool g_coalescingLayouts = true;

static bool IsValidFramePtr(void* ptr) {
    uintptr_t addr = (uintptr_t)ptr;
    if (addr < 0x10000 || addr > 0xFFE00000) return false;
    __try {
        uintptr_t vtable = *(uintptr_t*)addr;
        if (vtable >= 0x00401000 && vtable < 0x009DF000) {
            return true;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return false;
}

// A LayoutRecalc detour used to sit here, to break UI layout loops by refusing a
// frame more than 200 layout passes in one game frame. It never refused any: the
// throttle behind it kept its own enable flag, that flag was initialised to false
// and nothing ever set it, so ShouldThrottle returned on its first line every
// time. The detour was left as a pass-through that read a global and called the
// original.
//
// Removed rather than switched on. Declining a layout pass the client asked for
// is the same bet as AnimationLod, AsyncCulling and NameplateThrottle, and all
// three of those were removed after testers reported them as visual corruption.

// Memory validation
// ================================================================
static bool IsReadable(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD);
}

// ================================================================
// 1. Combat Text Batching
// ================================================================
// WoW creates a separate CSimpleFontString for every floating
// combat text event (damage, healing, miss, etc.). In AoE-heavy
// raids with 10+ targets, this means 50-100+ font string allocs
// per frame — each with D3D texture creation overhead.
//
// We intercept the combat text dispatch function, accumulate
// multiple text triggers into a ring buffer, and flush them as
// a single batched update at end of frame.
//
// Addresses pending:
//   - Combat text dispatch: search for "Floating Combat Text" string
//     or follow AddMessage("COMBAT_TEXT_UPDATE") event handler.
//   - Frame update loop: the parent UI frame's update that processes
//     OnUpdate scripts. Look for the frame manager's main loop.


// ================================================================
// 2. UI Layout Traversal Caching (Dirty Flag System)
// ================================================================
// WoW's UI frame system does a deep tree traversal every frame
// to compute layout (anchors, sizes, positions) even when nothing
// changed. We add a dirty-flag cache:
//   - Each frame in the tree gets a generation counter
//   - When a frame's layout changes, it marks itself dirty AND
//     bumps the generation of all ancestors
//   - On traversal, skip subtrees whose root frame has a clean
//     generation number matching the current global generation
//
// CFrame layout structure (reverse-engineered):
//   +0x00: vtbl
//   +0x04: flags (bit 0 = dirty, bit 1 = visible, etc.)
//   +0x08: name* (const char* or TString*)
//   +0x0C: parent* (CFrame*)
//   +0x10: firstChild* (CFrame*)
//   +0x14: nextSibling* (CFrame*)
//   +0x18: left, +0x1C: top, +0x20: width, +0x24: height
//   +0x28: layoutGen (uint32) — our injected field

// We can't add fields to WoW's frame struct without breaking ABI.
// Instead, use a separate hash table keyed by frame pointer.
// For hot-path performance, use a 4096-slot direct-mapped cache
// with frame pointer as key and generation counter as value.

static constexpr int UI_CACHE_SLOTS = 4096;
static constexpr int UI_CACHE_MASK  = UI_CACHE_SLOTS - 1;

struct UILayoutCacheEntry {
    uintptr_t framePtr;    // key: CFrame* (NULL = empty slot)
    uint32_t  layoutGen;   // value: generation counter
};

static UILayoutCacheEntry g_uiLayoutCache[UI_CACHE_SLOTS] = {};
static volatile uint32_t   g_uiGlobalGen = 1; // global layout generation
static volatile LONG64     g_uiChecked   = 0;
static volatile LONG64     g_uiSkipped    = 0;

// FNV-1a hash
static inline uint32_t HashFramePtr(uintptr_t ptr) {
    uint32_t hash = 2166136261u;
    hash ^= (uint32_t)(ptr & 0xFFFF);
    hash *= 16777619u;
    hash ^= (uint32_t)((ptr >> 16) & 0xFFFF);
    hash *= 16777619u;
    return hash;
}

static bool IsUILayoutDirty(uintptr_t framePtr) {
    uint32_t idx = HashFramePtr(framePtr) & UI_CACHE_MASK;
    UILayoutCacheEntry& entry = g_uiLayoutCache[idx];

    InterlockedIncrement64(&g_uiChecked);

    if (entry.framePtr == framePtr && entry.layoutGen == g_uiGlobalGen) {
        InterlockedIncrement64(&g_uiSkipped);
        return false; // clean — skip traversal
    }
    return true; // dirty or not cached — must traverse
}

static void MarkUILayoutClean(uintptr_t framePtr) {
    uint32_t idx = HashFramePtr(framePtr) & UI_CACHE_MASK;
    g_uiLayoutCache[idx].framePtr  = framePtr;
    g_uiLayoutCache[idx].layoutGen = g_uiGlobalGen;
}

// Bump global generation when any layout changes.
// This invalidates all clean cache entries for the next frame.
static void InvalidateUILayoutCache() {
    InterlockedIncrement((LONG*)&g_uiGlobalGen);
    if (g_uiGlobalGen == 0) g_uiGlobalGen = 1; // avoid zero
}

// ================================================================
// 3. Network Heartbeat Filtering
// ================================================================
// WoW sends CMSG_PING and CMSG_TIME_SYNC_RESP periodically to
// maintain the connection. When the game is actively sending
// movement/action packets, these heartbeats are redundant —
// the server already knows the client is alive.
//
// We track the timestamp of the last sent data packet. If a
// heartbeat is about to be sent within 1 second of the last
// data packet, suppress it.
//
// WoW opcode IDs (3.3.5a 12340):
//   CMSG_PING            = 0x01DC
//   CMSG_TIME_SYNC_RESP  = 0x0391
//
// API: void SendPacket(void* this, uint32_t opcode, void* data, uint32_t len)
// Hook: intercept the send call, check opcode, suppress if needed.

// ADDR_NETSEND_PACKET: sub_468D00 — queues packet with opcode, calls sub_468BA0 to send
// Hook here to filter heartbeat opcodes (CMSG_PING=0x1DC, CMSG_TIME_SYNC_RESP=0x391)
#ifndef ADDR_NETSEND_PACKET
#define ADDR_NETSEND_PACKET 0x00468D00
#endif

// Known heartbeat opcodes
static constexpr uint32_t CMSG_PING           = 0x01DC;
static constexpr uint32_t CMSG_TIME_SYNC_RESP = 0x0391;
static constexpr uint32_t CMSG_KEEP_ALIVE     = 0x0416;
static constexpr uint32_t MSG_MOVE_HEARTBEAT  = 0x0EEE;

// Track last send timestamps
static LARGE_INTEGER g_qpcFreqNet = {0};
static LARGE_INTEGER g_lastDataPacket       = {0};
static LARGE_INTEGER g_lastHeartbeat        = {0};
static constexpr LONG64 NET_HEARTBEAT_INTERVAL_US = 2000000LL; // 2s minimum between heartbeats
static constexpr LONG64 NET_DATA_GRACE_US         = 1000000LL; // 1s grace after data packet

static volatile LONG64 g_heartbeatsSuppressed = 0;
static volatile LONG64 g_heartbeatsAllowed    = 0;

static bool IsHeartbeatOpcode(uint32_t opcode) {
    return opcode == CMSG_PING
        || opcode == CMSG_TIME_SYNC_RESP
        || opcode == CMSG_KEEP_ALIVE
        || opcode == MSG_MOVE_HEARTBEAT;
}

// Returns true if the heartbeat should be suppressed
static bool ShouldSuppressHeartbeat(uint32_t opcode) {
    if (!IsHeartbeatOpcode(opcode)) return false;

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);

    LONG64 sinceLastData = (now.QuadPart - g_lastDataPacket.QuadPart) * 1000000LL / g_qpcFreqNet.QuadPart;
    LONG64 sinceLastHB   = (now.QuadPart - g_lastHeartbeat.QuadPart) * 1000000LL / g_qpcFreqNet.QuadPart;

    // If data was sent recently, suppress heartbeat
    if (sinceLastData < NET_DATA_GRACE_US) {
        return true;
    }

    // Ensure at least one heartbeat goes through every 2s
    if (sinceLastHB < NET_HEARTBEAT_INTERVAL_US) {
        return true;
    }

    return false;
}

static void OnHeartbeatSent() {
    QueryPerformanceCounter(&g_lastHeartbeat);
    InterlockedIncrement64(&g_heartbeatsAllowed);
}

static void OnDataPacketSent() {
    QueryPerformanceCounter(&g_lastDataPacket);
}

// ================================================================
// 4. Invariant UI Script Caching
// ================================================================
// WoW addons call Lua functions like UnitHealth("player") or
// UnitPower("player") in OnUpdate handlers every frame, even
// when the value hasn't changed. These calls go through the full
// Lua API stack (pushstring + lua_call → C++ → Lua → C++) each time.
//
// We cache frequently-accessed global states that are invariant
// within a frame:
//   - Unit Aura flags (buff/debuff presence)
//   - Unit classification (elite, rare, boss)
//   - Instance difficulty
//   - Player spec / talent tree
//
// The cache is keyed by (function_id, arg1, arg2) and stores the
// Lua stack result (TValue). Invalidated at the start of each frame.

static constexpr int UI_SCRIPT_CACHE_SIZE = 256;
static constexpr int UI_SCRIPT_CACHE_MASK = UI_SCRIPT_CACHE_SIZE - 1;

struct UIScriptCacheEntry {
    uint64_t  guid;     // unit GUID associated with this entry
    uint32_t  key;      // combined hash of function + args
    uintptr_t funcPtr;  // Lua function pointer (for type safety)
    double    nValue;   // cached number result
    uint32_t  frameGen; // frame generation when cached
    uint16_t  valueType; // Lua type tag (LUA_TNUMBER, LUA_TBOOLEAN, etc.)
    uint16_t  padding;
};

static UIScriptCacheEntry g_uiScriptCache[UI_SCRIPT_CACHE_SIZE] = {};
static volatile uint32_t   g_uiScriptGen = 0; // bumped each frame
static volatile LONG64     g_uiScriptHits = 0;
static volatile LONG64     g_uiScriptMisses = 0;

// Invariant Lua function addresses — verified C function entry points
#ifndef ADDR_LUA_UNITHEALTH
#define ADDR_LUA_UNITHEALTH    0x0060EB60  // UnitHealth
#endif
#ifndef ADDR_LUA_UNITPOWER
#define ADDR_LUA_UNITPOWER     0x0060ED40  // UnitPower
#endif
#ifndef ADDR_LUA_UNITCLASS
#define ADDR_LUA_UNITCLASS     0x0060FEC0  // UnitClass
#endif
#ifndef ADDR_LUA_UNITMAXHEALTH
#define ADDR_LUA_UNITMAXHEALTH 0x0060EC60  // UnitHealthMax
#endif
#ifndef ADDR_LUA_UNITPOWERMAX
#define ADDR_LUA_UNITPOWERMAX  0x0060EF40  // UnitPowerMax
#endif
#ifndef ADDR_LUA_UNITLEVEL
#define ADDR_LUA_UNITLEVEL     0x0060F9E0  // UnitLevel
#endif
#ifndef ADDR_LUA_GETINSTANCEINFO
#define ADDR_LUA_GETINSTANCEINFO 0x00000000  // pending
#endif

static bool IsInvariantLuaFunc(uintptr_t funcPtr) {
    return funcPtr == ADDR_LUA_UNITHEALTH
        || funcPtr == ADDR_LUA_UNITPOWER
        || funcPtr == ADDR_LUA_UNITCLASS
        || funcPtr == ADDR_LUA_UNITMAXHEALTH
        || funcPtr == ADDR_LUA_UNITPOWERMAX
        || funcPtr == ADDR_LUA_UNITLEVEL
        || funcPtr == ADDR_LUA_GETINSTANCEINFO;
}

static uint32_t HashScriptCache(uintptr_t funcPtr, uint32_t arg1) {
    uint32_t hash = 2166136261u;
    hash ^= (uint32_t)(funcPtr & 0xFFF);
    hash *= 16777619u;
    hash ^= arg1;
    hash *= 16777619u;
    return hash;
}

// Look up cached result. Returns true if found, fills *pValue.
static bool LookupInvariantScript(uintptr_t funcPtr, uint32_t argHash, double* pValue) {
    if (!IsInvariantLuaFunc(funcPtr)) return false;

    uint32_t key = HashScriptCache(funcPtr, argHash);
    UIScriptCacheEntry& entry = g_uiScriptCache[key & UI_SCRIPT_CACHE_MASK];

    if (entry.key == key && entry.funcPtr == funcPtr && entry.frameGen == g_uiScriptGen) {
        *pValue = entry.nValue;
        InterlockedIncrement64(&g_uiScriptHits);
        return true;
    }

    InterlockedIncrement64(&g_uiScriptMisses);
    return false;
}

// Store a new cache entry
static void StoreInvariantScript(uintptr_t funcPtr, uint32_t argHash, double value, uint16_t type, uint64_t guid) {
    if (!IsInvariantLuaFunc(funcPtr)) return;

    uint32_t key = HashScriptCache(funcPtr, argHash);
    UIScriptCacheEntry& entry = g_uiScriptCache[key & UI_SCRIPT_CACHE_MASK];
    entry.guid      = guid;
    entry.key       = key;
    entry.funcPtr   = funcPtr;
    entry.nValue    = value;
    entry.frameGen  = g_uiScriptGen;
    entry.valueType = type;
}

// Invalidate cached values for a specific unit GUID (called on OnFieldUpdate/UnlinkNode)
extern "C" void InvalidateUnitApiCacheFor(uint64_t guid) {
    for (int i = 0; i < UI_SCRIPT_CACHE_SIZE; i++) {
        if (g_uiScriptCache[i].guid == guid) {
            g_uiScriptCache[i].frameGen = 0; // invalidate slot
        }
    }
}

// Invalidate all script caches at frame start
static void InvalidateScriptCache() {
    InterlockedIncrement((LONG*)&g_uiScriptGen);
    if (g_uiScriptGen == 0) g_uiScriptGen = 1;
}

// ================================================================
// Lua function cache hooks
// ================================================================
static inline bool IsTeardownState() {
    uintptr_t gL = *(uintptr_t*)0x00D3F78C;
    return (gL < 0x10000 || gL > 0xFFE00000);
}

typedef int (__cdecl* LuaFunc_t)(uintptr_t L);
static LuaFunc_t orig_UnitHealth = nullptr;
static LuaFunc_t orig_UnitPower = nullptr;
static LuaFunc_t orig_UnitMaxHealth = nullptr;
static LuaFunc_t orig_UnitPowerMax = nullptr;
static LuaFunc_t orig_UnitLevel = nullptr;

typedef const char* (__cdecl* lua_tolstring_t)(uintptr_t L, int idx, size_t* len);
static const lua_tolstring_t lua_tolstring_ = (lua_tolstring_t)0x0084E0E0;

typedef double (__cdecl* lua_tonumber_t)(uintptr_t L, int idx);
static const lua_tonumber_t lua_tonumber_ = (lua_tonumber_t)0x0084E030;

typedef void (__cdecl* lua_pushnumber_t)(uintptr_t L, double n);
static const lua_pushnumber_t lua_pushnumber_ = (lua_pushnumber_t)0x0084E2A0;

typedef int (__cdecl* lua_gettop_t)(uintptr_t L);
static const lua_gettop_t lua_gettop_ = (lua_gettop_t)0x0084DBD0;

// DMA direct memory access variables and functions
typedef void (__cdecl* fn_ParseUnitToken)(const char* str, int* out_token, int flags);
typedef void* (__cdecl* fn_ResolveUnit)(int token_low, int token_high, int flags);
static const fn_ParseUnitToken  p_ParseUnitToken  = (fn_ParseUnitToken)0x0060ABF0;
static const fn_ResolveUnit     p_ResolveUnit     = (fn_ResolveUnit)0x004D4DB0;

static constexpr uintptr_t CGUNIT_M_VALUES_OFFS = 0xD0;
static constexpr int UNIT_FIELD_HEALTH      = 18;
static constexpr int UNIT_FIELD_MAXHEALTH   = 26;
static constexpr int UNIT_FIELD_POWER1      = 19;
static constexpr int UNIT_FIELD_MAXPOWER1   = 27;

static bool IsReadableMemory(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD);
}

static bool GetUnitDMAField(const char* unitStr, int fieldIndex, int& outValue) {
    if (!unitStr) return false;
    __try {
        int token[2] = {0, 0};
        p_ParseUnitToken(unitStr, token, 0);
        void* unitObj = p_ResolveUnit(token[0], token[1], 8);
        if (!unitObj) return false;
        
        uintptr_t ptr = (uintptr_t)unitObj;
        if (ptr < 0x10000 || ptr > 0xFFE00000) return false;
        if (!IsReadableMemory(ptr + CGUNIT_M_VALUES_OFFS)) return false;
        
        void* m_values = *(void**)(ptr + CGUNIT_M_VALUES_OFFS);
        if (!m_values) return false;
        
        uintptr_t fieldAddress = (uintptr_t)m_values + fieldIndex * 4;
        if (!IsReadableMemory(fieldAddress)) return false;
        
        outValue = *(int*)fieldAddress;
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static int __cdecl Hooked_UnitHealth(uintptr_t L) {
    CrashDumper::RecordHookCall("UnitHealth", (uintptr_t)L);
    bool processed = false;
    int results = 0;
    __try {
        if (L && !IsTeardownState() && L == *(uintptr_t*)0x00D3F78C) {
            size_t len = 0;
            const char* unit = lua_tolstring_(L, 1, &len);
            if (unit && len < 32) {
                // Try DMA read first!
                int dmaVal = 0;
                if (GetUnitDMAField(unit, UNIT_FIELD_HEALTH, dmaVal)) {
                    lua_pushnumber_(L, (double)dmaVal);
                    results = 1;
                    processed = true;
                }

                if (!processed) {
                    uint64_t guid = 0;
                    typedef char (__cdecl *get_guid_fn)(const char*, uint64_t*, char);
                    if (((get_guid_fn)0x0060ABF0)(unit, &guid, 0) && guid != 0) {
                        uint32_t argHash = 2166136261u;
                        argHash ^= (uint32_t)(guid & 0xFFFFFFFF);
                        argHash *= 16777619u;
                        argHash ^= (uint32_t)(guid >> 32);
                        argHash *= 16777619u;

                        double val = 0.0;
                        if (LookupInvariantScript(ADDR_LUA_UNITHEALTH, argHash, &val)) {
                            lua_pushnumber_(L, val);
                            results = 1;
                            processed = true;
                        } else {
                            processed = true;
                            results = orig_UnitHealth(L);
                            if (results == 1) {
                                uintptr_t top = *(uintptr_t*)(L + 0x0C);
                                if (top >= 0x10000 && *(int*)(top - 8) == 3) {
                                    double actualVal = lua_tonumber_(L, -1);
                                    StoreInvariantScript(ADDR_LUA_UNITHEALTH, argHash, actualVal, 3, guid);
                                }
                            }
                        }
                    }
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    if (processed) return results;
    return orig_UnitHealth(L);
}

static int __cdecl Hooked_UnitPower(uintptr_t L) {
    CrashDumper::RecordHookCall("UnitPower", (uintptr_t)L);
    bool processed = false;
    int results = 0;
    __try {
        if (L && !IsTeardownState() && L == *(uintptr_t*)0x00D3F78C) {
            size_t len = 0;
            const char* unit = lua_tolstring_(L, 1, &len);
            if (unit && len < 32) {
                int powerType = 0;
                int nargs = lua_gettop_(L);
                if (nargs >= 2) {
                    double typeVal = lua_tonumber_(L, 2);
                    powerType = (int)typeVal;
                }

                if (powerType >= 0 && powerType <= 7) {
                    int dmaVal = 0;
                    if (GetUnitDMAField(unit, UNIT_FIELD_POWER1 + powerType, dmaVal)) {
                        lua_pushnumber_(L, (double)dmaVal);
                        results = 1;
                        processed = true;
                    }
                }

                if (!processed) {
                    uint64_t guid = 0;
                    typedef char (__cdecl *get_guid_fn)(const char*, uint64_t*, char);
                    if (((get_guid_fn)0x0060ABF0)(unit, &guid, 0) && guid != 0) {
                        int top = lua_gettop_(L);
                        uint32_t argHash = 2166136261u;
                        argHash ^= (uint32_t)(guid & 0xFFFFFFFF);
                        argHash *= 16777619u;
                        argHash ^= (uint32_t)(guid >> 32);
                        argHash *= 16777619u;

                        if (top >= 2) {
                            double typeVal = lua_tonumber_(L, 2);
                            uint64_t typeBits = *reinterpret_cast<uint64_t*>(&typeVal);
                            argHash ^= (uint32_t)(typeBits & 0xFFFFFFFF);
                            argHash *= 16777619u;
                            argHash ^= (uint32_t)(typeBits >> 32);
                            argHash *= 16777619u;
                        } else {
                            argHash ^= 0xFFFFFFFF;
                            argHash *= 16777619u;
                        }

                        double val = 0.0;
                        if (LookupInvariantScript(ADDR_LUA_UNITPOWER, argHash, &val)) {
                            lua_pushnumber_(L, val);
                            results = 1;
                            processed = true;
                        } else {
                            processed = true;
                            results = orig_UnitPower(L);
                            if (results == 1) {
                                uintptr_t stack_top = *(uintptr_t*)(L + 0x0C);
                                if (stack_top >= 0x10000 && *(int*)(stack_top - 8) == 3) {
                                    double actualVal = lua_tonumber_(L, -1);
                                    StoreInvariantScript(ADDR_LUA_UNITPOWER, argHash, actualVal, 3, guid);
                                }
                            }
                        }
                    }
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    if (processed) return results;
    return orig_UnitPower(L);
}

static int __cdecl Hooked_UnitMaxHealth(uintptr_t L) {
    CrashDumper::RecordHookCall("UnitMaxHealth", (uintptr_t)L);
    bool processed = false;
    int results = 0;
    __try {
        if (L && !IsTeardownState() && L == *(uintptr_t*)0x00D3F78C) {
            size_t len = 0;
            const char* unit = lua_tolstring_(L, 1, &len);
            if (unit && len < 32) {
                // Try DMA read first!
                int dmaVal = 0;
                if (GetUnitDMAField(unit, UNIT_FIELD_MAXHEALTH, dmaVal)) {
                    lua_pushnumber_(L, (double)dmaVal);
                    results = 1;
                    processed = true;
                }

                if (!processed) {
                    uint64_t guid = 0;
                    typedef char (__cdecl *get_guid_fn)(const char*, uint64_t*, char);
                    if (((get_guid_fn)0x0060ABF0)(unit, &guid, 0) && guid != 0) {
                        uint32_t argHash = 2166136261u;
                        argHash ^= (uint32_t)(guid & 0xFFFFFFFF);
                        argHash *= 16777619u;
                        argHash ^= (uint32_t)(guid >> 32);
                        argHash *= 16777619u;

                        double val = 0.0;
                        if (LookupInvariantScript(ADDR_LUA_UNITMAXHEALTH, argHash, &val)) {
                            lua_pushnumber_(L, val);
                            results = 1;
                            processed = true;
                        } else {
                            processed = true;
                            results = orig_UnitMaxHealth(L);
                            if (results == 1) {
                                uintptr_t top = *(uintptr_t*)(L + 0x0C);
                                if (top >= 0x10000 && *(int*)(top - 8) == 3) {
                                    double actualVal = lua_tonumber_(L, -1);
                                    StoreInvariantScript(ADDR_LUA_UNITMAXHEALTH, argHash, actualVal, 3, guid);
                                }
                            }
                        }
                    }
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    if (processed) return results;
    return orig_UnitMaxHealth(L);
}

static int __cdecl Hooked_UnitLevel(uintptr_t L) {
    CrashDumper::RecordHookCall("UnitLevel", (uintptr_t)L);
    bool processed = false;
    int results = 0;
    __try {
        if (L && !IsTeardownState() && L == *(uintptr_t*)0x00D3F78C) {
            size_t len = 0;
            const char* unit = lua_tolstring_(L, 1, &len);
            if (unit && len < 32) {
                uint64_t guid = 0;
                typedef char (__cdecl *get_guid_fn)(const char*, uint64_t*, char);
                if (((get_guid_fn)0x0060ABF0)(unit, &guid, 0) && guid != 0) {
                    uint32_t argHash = 2166136261u;
                    argHash ^= (uint32_t)(guid & 0xFFFFFFFF);
                    argHash *= 16777619u;
                    argHash ^= (uint32_t)(guid >> 32);
                    argHash *= 16777619u;

                    double val = 0.0;
                    if (LookupInvariantScript(ADDR_LUA_UNITLEVEL, argHash, &val)) {
                        lua_pushnumber_(L, val);
                        results = 1;
                        processed = true;
                    } else {
                        processed = true;
                        results = orig_UnitLevel(L);
                        if (results == 1) {
                            uintptr_t top = *(uintptr_t*)(L + 0x0C);
                            if (top >= 0x10000 && *(int*)(top - 8) == 3) {
                                double actualVal = lua_tonumber_(L, -1);
                                StoreInvariantScript(ADDR_LUA_UNITLEVEL, argHash, actualVal, 3, guid);
                            }
                        }
                    }
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    if (processed) return results;
    return orig_UnitLevel(L);
}

static int __cdecl Hooked_UnitPowerMax(uintptr_t L) {
    CrashDumper::RecordHookCall("UnitPowerMax", (uintptr_t)L);
    bool processed = false;
    int results = 0;
    __try {
        if (L && !IsTeardownState() && L == *(uintptr_t*)0x00D3F78C) {
            size_t len = 0;
            const char* unit = lua_tolstring_(L, 1, &len);
            if (unit && len < 32) {
                int powerType = 0;
                int nargs = lua_gettop_(L);
                if (nargs >= 2) {
                    double typeVal = lua_tonumber_(L, 2);
                    powerType = (int)typeVal;
                }

                if (powerType >= 0 && powerType <= 7) {
                    int dmaVal = 0;
                    if (GetUnitDMAField(unit, UNIT_FIELD_MAXPOWER1 + powerType, dmaVal)) {
                        lua_pushnumber_(L, (double)dmaVal);
                        results = 1;
                        processed = true;
                    }
                }

                if (!processed) {
                    uint64_t guid = 0;
                    typedef char (__cdecl *get_guid_fn)(const char*, uint64_t*, char);
                    if (((get_guid_fn)0x0060ABF0)(unit, &guid, 0) && guid != 0) {
                        int top = lua_gettop_(L);
                        uint32_t argHash = 2166136261u;
                        argHash ^= (uint32_t)(guid & 0xFFFFFFFF);
                        argHash *= 16777619u;
                        argHash ^= (uint32_t)(guid >> 32);
                        argHash *= 16777619u;

                        if (top >= 2) {
                            double typeVal = lua_tonumber_(L, 2);
                            uint64_t typeBits = *reinterpret_cast<uint64_t*>(&typeVal);
                            argHash ^= (uint32_t)(typeBits & 0xFFFFFFFF);
                            argHash *= 16777619u;
                            argHash ^= (uint32_t)(typeBits >> 32);
                            argHash *= 16777619u;
                        } else {
                            argHash ^= 0xFFFFFFFF;
                            argHash *= 16777619u;
                        }

                        double val = 0.0;
                        if (LookupInvariantScript(ADDR_LUA_UNITPOWERMAX, argHash, &val)) {
                            lua_pushnumber_(L, val);
                            results = 1;
                            processed = true;
                        } else {
                            processed = true;
                            results = orig_UnitPowerMax(L);
                            if (results == 1) {
                                uintptr_t stack_top = *(uintptr_t*)(L + 0x0C);
                                if (stack_top >= 0x10000 && *(int*)(stack_top - 8) == 3) {
                                    double actualVal = lua_tonumber_(L, -1);
                                    StoreInvariantScript(ADDR_LUA_UNITPOWERMAX, argHash, actualVal, 3, guid);
                                }
                            }
                        }
                    }
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    if (processed) return results;
    return orig_UnitPowerMax(L);
}


// ================================================================
// Public API
// ================================================================
// Public API
// ================================================================

// Frame counter for periodic operations
static volatile DWORD g_logicFrameIndex = 0;

bool InstallLogicHooks(void) {
    QueryPerformanceFrequency(&g_qpcFreqNet);

    // Initialize combat text batch buffer

    // Initialize UI layout cache
    memset(g_uiLayoutCache, 0, sizeof(g_uiLayoutCache));
    g_uiGlobalGen = 1;

    // Initialize UI script cache
    memset(g_uiScriptCache, 0, sizeof(g_uiScriptCache));
    g_uiScriptGen = 1;

    // Log placeholder addresses that need to be filled
    if (!ADDR_NETSEND_PACKET)
        Log("[LogicHooks] Network heartbeat: address placeholder — fill ADDR_NETSEND_PACKET");

    // DISABLED: Invariant script cache hooks cause ERROR #134 (stack leak on SEH paths).
    // The lua_pushnumber_ + fallback-to-original pattern leaks stack slots when exceptions
    // occur mid-push. These hooks provide marginal benefit (caching simple int lookups).
    // Nothing is installed here, and the line below used to say so only as a
    // "(0 hooks active)" at the end of a sentence naming four features.
    //
    // This module has no CreateHook call anywhere in its 805 lines. The combat
    // text dispatch hook, the UI layout hook, the network heartbeat hook and the
    // invariant script cache hooks were all either never written or disabled -
    // the script one says so on the line above. What is left maintains two caches
    // that nothing outside this file reads and flushes a packet queue that
    // nothing fills, once a frame, for as long as the session lasts.
    //
    // It is left in place rather than deleted because deleting eight hundred
    // lines is a change that wants a session behind it, and it is reported as
    // doing nothing rather than as four features by name, because a reader who
    // believes a feature runs is worse off than one who knows it does not.
    int installed = 0;
    Log("[LogicHooks] Invariant script cache hooks DISABLED (stack leak safety)");


    Log("[LogicHooks] NOT ACTIVE: %d hooks installed. Combat text batching, the "
        "UI layout cache, the network heartbeat filter and the invariant script "
        "cache are named in this module and none of them runs - there is no hook "
        "in it anywhere. The caches it keeps are read by nothing.", installed);
    return false;
}

void ShutdownLogicHooks(void) {
    // Flush any remaining combat text entries

    // Invariant script cache hooks not installed (disabled for stack leak safety)
    // MH_DisableHook((void*)ADDR_LUA_UNITLEVEL);
    // MH_DisableHook((void*)ADDR_LUA_UNITHEALTH);
    // MH_DisableHook((void*)ADDR_LUA_UNITPOWER);
    // MH_DisableHook((void*)ADDR_LUA_UNITMAXHEALTH);
    // MH_DisableHook((void*)ADDR_LUA_UNITPOWERMAX);


    Log("[LogicHooks] Stats: UI layout — %lld checked, %lld skipped (%.1f%%)",
        g_uiChecked, g_uiSkipped,
        g_uiChecked ? 100.0 * g_uiSkipped / g_uiChecked : 0.0);

    Log("[LogicHooks] Stats: Network — %lld heartbeats suppressed, %lld allowed",
        g_heartbeatsSuppressed, g_heartbeatsAllowed);

    Log("[LogicHooks] Stats: Script cache — %lld hits, %lld misses (%.1f%% hit rate)",
        g_uiScriptHits, g_uiScriptMisses,
        (g_uiScriptHits + g_uiScriptMisses) ?
            100.0 * g_uiScriptHits / (g_uiScriptHits + g_uiScriptMisses) : 0.0);
}

// (empty - moved to top)

void OnFrameLogicHooks(DWORD mainThreadId) {
    if (GetCurrentThreadId() != mainThreadId) return;

    DWORD frameIdx = InterlockedIncrement((LONG*)&g_logicFrameIndex);


    // Flush any coalesced network packets
    FlushCoalescedPackets();


    // Invalidate frame-scoped caches
    InvalidateUILayoutCache();
    InvalidateScriptCache();
}
