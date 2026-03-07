// ================================================================
//  Combat Log Buffer Optimizer — Implementation
//  WoW 3.3.5a build 12340 (Warmane)
//
//  Three-layer fix for combat log issues:
//
//  Layer 1: Retention increase (300 -> 1800 sec)
//  Layer 2: Pre-allocated entry pool (eliminates heap alloc)
//  Layer 3: Guaranteed Periodic Clear (fixes the break bug)
// ================================================================

#include "combatlog_optimize.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <mimalloc.h>

extern "C" void Log(const char* fmt, ...);

// ================================================================
//  Known Addresses — build 12340
// ================================================================

namespace Addr {
    static constexpr uintptr_t CVar_RetentionPtr     = 0x00BD09F0;
    static constexpr uintptr_t ActiveListHead        = 0x00ADB97C;
    static constexpr uintptr_t FreeListManager       = 0x00ADB980; 
    static constexpr uintptr_t FreeListHead          = 0x00ADB984; 
    static constexpr uintptr_t FreeListIndicator     = 0x00ADB988; 
    static constexpr uintptr_t PendingEntry          = 0x00CA1394;
    static constexpr uintptr_t ProcessingEntry       = 0x00CA1390;
    static constexpr uintptr_t CurrentTime           = 0x00CD76AC;
    static constexpr uintptr_t CombatLogClearEntries = 0x00751120;
    static constexpr uintptr_t EntryInit             = 0x0074D920; 
    static constexpr uintptr_t FreeListInsert        = 0x0086E200; 
    static constexpr uintptr_t StringVtable          = 0x009EAA04; 
}

static constexpr int ENTRY_SIZE = 0x78;

// ================================================================
//  Configuration
// ================================================================

static constexpr int TARGET_RETENTION_SEC    = 1800;
static constexpr int RETENTION_CHECK_FRAMES  = 600;
static constexpr int MAX_RETENTION_RETRIES   = 600;
static constexpr int CVAR_INT_OFFSET         = 0x30;

// Layer 2: Pool config
static constexpr int POOL_ENTRY_COUNT        = 4096;
static constexpr int POOL_TOTAL_BYTES        = POOL_ENTRY_COUNT * ENTRY_SIZE;

// Layer 3: Clear config (real time, not frames)
static constexpr double CLEAR_INTERVAL_MS    = 1000.0; // Clear every 1 second

// ================================================================
//  Function Types
// ================================================================

typedef int  (__cdecl *ClearEntries_fn)();
typedef void (__thiscall *EntryInit_fn)(void* thisPtr);
typedef void (__thiscall *FreeListInsert_fn)(void* manager, void* entry);

// ================================================================
//  State
// ================================================================

static bool    g_initialized       = false;

static int     g_origRetention     = 0;
static bool    g_retentionPatched  = false;
static bool    g_retentionGaveUp   = false;
static int     g_retentionRetries  = 0;
static int     g_retentionCheckCounter = 0;

static uint8_t* g_poolMemory       = nullptr;
static bool     g_poolInjected     = false;
static int      g_poolEntriesAdded = 0;

static double  g_qpcFreqMs         = 0.0;
static double  g_lastClearTime     = 0.0;
static int     g_totalClears       = 0;

static ClearEntries_fn   g_clearEntries   = nullptr;
static EntryInit_fn      g_entryInit      = nullptr;
static FreeListInsert_fn g_freeListInsert = nullptr;

// ================================================================
//  Helpers
// ================================================================

static bool IsReadable(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD);
}

static bool IsExecutable(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static double GetTimeMs() {
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (double)li.QuadPart / g_qpcFreqMs;
}

// ================================================================
//  Layer 1: Retention
// ================================================================

static int ReadRetention() {
    __try {
        uintptr_t cvarPtr = *(uintptr_t*)Addr::CVar_RetentionPtr;
        if (!cvarPtr || !IsReadable(cvarPtr + CVAR_INT_OFFSET)) return -1;
        return *(int*)(cvarPtr + CVAR_INT_OFFSET);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}

static bool WriteRetention(int seconds) {
    __try {
        uintptr_t cvarPtr = *(uintptr_t*)Addr::CVar_RetentionPtr;
        if (!cvarPtr || !IsReadable(cvarPtr + CVAR_INT_OFFSET)) return false;
        DWORD oldProtect;
        VirtualProtect((void*)(cvarPtr + CVAR_INT_OFFSET), 4, PAGE_READWRITE, &oldProtect);
        *(int*)(cvarPtr + CVAR_INT_OFFSET) = seconds;
        VirtualProtect((void*)(cvarPtr + CVAR_INT_OFFSET), 4, oldProtect, &oldProtect);
        return (*(int*)(cvarPtr + CVAR_INT_OFFSET) == seconds);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static int TryPatchRetention() {
    if (!IsReadable(Addr::CVar_RetentionPtr)) return 0;
    int current = ReadRetention();
    if (current < 0) return 0;
    if (current <= 0 || current > 100000) return -1;
    g_origRetention = current;
    if (!WriteRetention(TARGET_RETENTION_SEC)) return -1;
    g_retentionPatched = true;
    return 1;
}

// ================================================================
//  Layer 2: Entry Pool
// ================================================================

static bool InitializeEntry(uint8_t* entry) {
    __try {
        memset(entry, 0, ENTRY_SIZE);
        *(uintptr_t*)(entry + 0x00) = 0; 
        *(uintptr_t*)(entry + 0x04) = 0; 
        *(uintptr_t*)(entry + 0x48) = Addr::StringVtable;
        *(uintptr_t*)(entry + 0x4C) = 0; 
        g_entryInit((void*)entry);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool InjectPool() {
    if (g_poolInjected) return true;
    if (!g_entryInit || !g_freeListInsert) return false;
    if (!IsReadable(Addr::FreeListManager)) return false;

    g_poolMemory = (uint8_t*)mi_calloc(POOL_ENTRY_COUNT, ENTRY_SIZE);
    if (!g_poolMemory) return false;

    int injected = 0;
    for (int i = 0; i < POOL_ENTRY_COUNT; i++) {
        uint8_t* entry = g_poolMemory + (i * ENTRY_SIZE);
        if (!InitializeEntry(entry)) continue;
        __try {
            g_freeListInsert((void*)Addr::FreeListManager, (void*)entry);
            injected++;
        } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
    }

    g_poolEntriesAdded = injected;
    g_poolInjected = (injected > 0);
    return g_poolInjected;
}

// ================================================================
//  Layer 3: Guaranteed Clear
//
//  This fixes the actual bug. We call clear on a strict wall-clock
//  timer, and we DO NOT check `pending != 0`. 
//  Checking `pending` is what prevented vanilla WoW from fixing itself
//  when the pointer got stuck.
// ================================================================

static void TryClearProcessedEntries(double nowMs) {
    if (nowMs - g_lastClearTime < CLEAR_INTERVAL_MS) return;
    g_lastClearTime = nowMs;

    __try {
        // Only verify the list isn't totally broken
        uintptr_t head = *(uintptr_t*)Addr::ActiveListHead;
        if (!head || (head & 1)) return;

        // FORCE CLEAR regardless of pending pointer.
        // This instantly un-sticks WA and other addons.
        g_clearEntries();
        g_totalClears++;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ================================================================
//  API
// ================================================================

namespace CombatLogOpt {

bool Init() {
    Log("[CombatLog] ====================================");
    Log("[CombatLog]  Combat Log Optimizer v2 (Guaranteed Clear)");
    Log("[CombatLog]  Build 12340");
    Log("[CombatLog] ====================================");

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    g_qpcFreqMs = (double)freq.QuadPart / 1000.0;

    if (IsExecutable(Addr::CombatLogClearEntries)) g_clearEntries = (ClearEntries_fn)Addr::CombatLogClearEntries;
    if (IsExecutable(Addr::EntryInit)) g_entryInit = (EntryInit_fn)Addr::EntryInit;
    if (IsExecutable(Addr::FreeListInsert)) g_freeListInsert = (FreeListInsert_fn)Addr::FreeListInsert;

    int ret = TryPatchRetention();
    if (ret == 1) Log("[CombatLog]  [ OK ] Retention patched (1800s)");
    
    Log("[CombatLog]  [ OK ] Guaranteed Clear (every 1 sec)");

    g_initialized = true;
    return true;
}

void OnFrame(DWORD mainThreadId) {
    if (!g_initialized) return;
    if (GetCurrentThreadId() != mainThreadId) return;

    double nowMs = GetTimeMs();

    if (!g_retentionPatched && !g_retentionGaveUp) {
        g_retentionRetries++;
        if ((g_retentionRetries & 15) == 0) {
            if (TryPatchRetention() == 1) {
                Log("[CombatLog] Retention patched on retry: 1800 sec");
            }
        }
    }

    g_retentionCheckCounter++;
    if (g_retentionPatched && g_retentionCheckCounter >= RETENTION_CHECK_FRAMES) {
        g_retentionCheckCounter = 0;
        if (ReadRetention() != TARGET_RETENTION_SEC) WriteRetention(TARGET_RETENTION_SEC);
    }

    if (!g_poolInjected && g_retentionPatched) {
        InjectPool();
    }

    if (g_clearEntries) {
        TryClearProcessedEntries(nowMs);
    }
}

void Shutdown() {
    if (!g_initialized) return;
    if (g_retentionPatched) WriteRetention(g_origRetention);
    Log("[CombatLog] Shutdown. Clears: %d, Pool: %d", g_totalClears, g_poolEntriesAdded);
    g_initialized = false;
}

PoolStats GetPoolStats() {
    PoolStats s = { POOL_ENTRY_COUNT, g_poolEntriesAdded, g_poolInjected };
    return s;
}

} // namespace CombatLogOpt