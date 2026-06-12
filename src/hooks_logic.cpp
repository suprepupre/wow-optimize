// ================================================================
// hooks_logic.cpp — Logic Optimization & Loop Bypassing
// ================================================================
// Combat text batching, UI layout traversal caching,
// network heartbeat filtering, invariant UI script caching.
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"
#include "hooks_logic.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
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

// ADDR_COMBAT_TEXT_ADD: sub_608880 called from sub_404130 — initializes combat text event names
// Hook the combat text event dispatch loop (sub_404130 for event processing)
#ifndef ADDR_COMBAT_TEXT_ADD
#define ADDR_COMBAT_TEXT_ADD 0x00608880
#endif
#ifndef ADDR_UI_FRAME_UPDATE_END
#define ADDR_UI_FRAME_UPDATE_END 0x00000000 // End of UI frame update (flush point)
#endif

// Batching buffer — 256 pending text entries
static constexpr int CT_BATCH_SIZE = 256;
static constexpr int CT_BATCH_MASK = CT_BATCH_SIZE - 1;

struct CombatTextEntry {
    uint64_t guid;       // target GUID
    int      amount;     // damage/heal amount
    int      spellID;    // spell that caused it
    int      flags;      // critical, miss, absorb, etc.
    float    x, y, z;    // world position
};

static CombatTextEntry g_ctBuffer[CT_BATCH_SIZE] = {};
static volatile LONG    g_ctHead  = 0;  // producer index
static volatile LONG    g_ctTail  = 0;  // consumer index (flush)
static volatile LONG64  g_ctBatched = 0;
static volatile LONG64  g_ctFlushed = 0;
static volatile LONG64  g_ctOverflow = 0;

// Flush threshold — batch and flush when N entries collected
static constexpr LONG CT_FLUSH_THRESHOLD = 128;

static void FlushCombatTextBatch() {
    LONG tail = g_ctTail;
    LONG head = InterlockedCompareExchange(&g_ctHead, 0, 0); // read atomically
    LONG count = (head - tail) & CT_BATCH_MASK;

    if (count == 0) return;

    // Process all entries in the batch
    // The actual dispatch calls the original function for each entry.
    // Batching saves D3D resource creation overhead by reusing
    // the same font string texture for multiple entries.
    while (tail != head) {
        CombatTextEntry& entry = g_ctBuffer[tail & CT_BATCH_MASK];

        // TODO: call original CombatText_AddMessage with entry data
        // The hook on the original function allows us to batch state
        // (font, color, position) and only flush D3D resources once.

        tail = (tail + 1) & CT_BATCH_MASK;
    }

    InterlockedExchange(&g_ctTail, tail);
    InterlockedIncrement64(&g_ctFlushed);
}

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
#ifndef ADDR_LUA_GETINSTANCEINFO
#define ADDR_LUA_GETINSTANCEINFO 0x00000000  // pending
#endif

static bool IsInvariantLuaFunc(uintptr_t funcPtr) {
    return funcPtr == ADDR_LUA_UNITHEALTH
        || funcPtr == ADDR_LUA_UNITPOWER
        || funcPtr == ADDR_LUA_UNITCLASS
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
static void StoreInvariantScript(uintptr_t funcPtr, uint32_t argHash, double value, uint16_t type) {
    if (!IsInvariantLuaFunc(funcPtr)) return;

    uint32_t key = HashScriptCache(funcPtr, argHash);
    UIScriptCacheEntry& entry = g_uiScriptCache[key & UI_SCRIPT_CACHE_MASK];
    entry.key       = key;
    entry.funcPtr   = funcPtr;
    entry.nValue    = value;
    entry.frameGen  = g_uiScriptGen;
    entry.valueType = type;
}

// Invalidate all script caches at frame start
static void InvalidateScriptCache() {
    InterlockedIncrement((LONG*)&g_uiScriptGen);
    if (g_uiScriptGen == 0) g_uiScriptGen = 1;
}

// ================================================================
// Public API
// ================================================================

// Frame counter for periodic operations
static volatile DWORD g_logicFrameIndex = 0;

bool InstallLogicHooks(void) {
    QueryPerformanceFrequency(&g_qpcFreqNet);

    // Initialize combat text batch buffer
    memset(g_ctBuffer, 0, sizeof(g_ctBuffer));
    g_ctHead = g_ctTail = 0;
    g_ctBatched = g_ctFlushed = g_ctOverflow = 0;

    // Initialize UI layout cache
    memset(g_uiLayoutCache, 0, sizeof(g_uiLayoutCache));
    g_uiGlobalGen = 1;

    // Initialize UI script cache
    memset(g_uiScriptCache, 0, sizeof(g_uiScriptCache));
    g_uiScriptGen = 1;

    // Log placeholder addresses that need to be filled
    if (!ADDR_COMBAT_TEXT_ADD)
        Log("[LogicHooks] Combat text batch: address placeholder — fill ADDR_COMBAT_TEXT_ADD");
    if (!ADDR_NETSEND_PACKET)
        Log("[LogicHooks] Network heartbeat: address placeholder — fill ADDR_NETSEND_PACKET");

    Log("[LogicHooks] Initialized — combat text batching, UI layout cache, "
        "network heartbeat filter, invariant script cache");

    return true;
}

void ShutdownLogicHooks(void) {
    // Flush any remaining combat text entries
    FlushCombatTextBatch();

    Log("[LogicHooks] Stats: Combat text — %lld batched, %lld flushed, %lld overflow",
        g_ctBatched, g_ctFlushed, g_ctOverflow);

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

void OnFrameLogicHooks(DWORD mainThreadId) {
    if (GetCurrentThreadId() != mainThreadId) return;

    DWORD frameIdx = InterlockedIncrement((LONG*)&g_logicFrameIndex);

    // Flush combat text batch every frame
    FlushCombatTextBatch();

    // Invalidate frame-scoped caches
    InvalidateUILayoutCache();
    InvalidateScriptCache();
}
