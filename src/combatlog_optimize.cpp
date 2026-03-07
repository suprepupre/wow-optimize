// ================================================================
//  Combat Log Buffer Optimizer — Implementation
//  WoW 3.3.5a build 12340 (Warmane)
//
//  Three-layer fix for combat log issues:
//
//  Layer 1: Retention increase (300 -> 1800 sec)
//  Layer 2: Periodic CombatLogClearEntries
//  Layer 3: Pre-allocated entry pool
//
//  Layer 3 eliminates heap allocation during combat by
//  pre-filling the combat log's internal free list with
//  pool entries. Zero code patching — we just give the
//  engine more pre-made bullets to use.
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
    // CVar
    static constexpr uintptr_t CVar_RetentionPtr     = 0x00BD09F0;

    // Combat log linked list
    static constexpr uintptr_t ActiveListHead        = 0x00ADB97C;
    static constexpr uintptr_t FreeListManager       = 0x00ADB980; // unk_ADB980 (ecx for sub_86E200)
    static constexpr uintptr_t FreeListHead           = 0x00ADB984; // ADB980+4
    static constexpr uintptr_t FreeListIndicator      = 0x00ADB988; // checked first in sub_750400

    // Processing pointers
    static constexpr uintptr_t PendingEntry          = 0x00CA1394;
    static constexpr uintptr_t ProcessingEntry       = 0x00CA1390;

    // Engine time
    static constexpr uintptr_t CurrentTime           = 0x00CD76AC;

    // Functions
    static constexpr uintptr_t CombatLogClearEntries = 0x00751120;
    static constexpr uintptr_t EntryInit             = 0x0074D920; // sub_74D920: initializes entry fields
    static constexpr uintptr_t FreeListInsert        = 0x0086E200; // sub_86E200: insert into free list
    static constexpr uintptr_t StringVtable          = 0x009EAA04; // off_9EAA04: string object vtable
}

// ================================================================
//  Combat Log Entry Layout
//
//  +0x00  next pointer (linked list)
//  +0x04  prev pointer (linked list)
//  +0x08  timestamp
//  +0x0C  event type
//  +0x10  ...
//  +0x18  source GUID lo
//  +0x1C  source GUID hi
//  +0x20  source flags
//  +0x24  source name buffer
//  +0x28  ...
//  +0x30  dest GUID lo
//  +0x34  dest GUID hi
//  +0x38  dest flags
//  +0x3C  dest name buffer
//  +0x40  ...
//  +0x44  extra data
//  +0x48  string object (vtable at +0x48, length at +0x4C)
//  +0x50  string buffer pointer
//  +0x54  additional field
//  ...
//  +0x78  END (total size = 0x78 = 120 bytes)
// ================================================================

static constexpr int ENTRY_SIZE = 0x78;  // 120 bytes per entry

// ================================================================
//  Configuration
// ================================================================

static constexpr int TARGET_RETENTION_SEC    = 1800;
static constexpr int CLEAR_INTERVAL_FRAMES   = 600;
static constexpr int RETENTION_CHECK_FRAMES  = 600;
static constexpr int MAX_RETENTION_RETRIES   = 600;
static constexpr int CVAR_INT_OFFSET         = 0x30;

// Pool configuration
static constexpr int POOL_ENTRY_COUNT        = 4096;  // Pre-allocate 4096 entries
static constexpr int POOL_TOTAL_BYTES        = POOL_ENTRY_COUNT * ENTRY_SIZE; // ~480 KB

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

// Retention
static int     g_origRetention     = 0;
static bool    g_retentionPatched  = false;
static bool    g_retentionGaveUp   = false;
static int     g_retentionRetries  = 0;

// Periodic clear
static int     g_clearCounter          = 0;
static int     g_retentionCheckCounter = 0;
static int     g_totalClears           = 0;

// Pool
static uint8_t* g_poolMemory       = nullptr;   // Raw pool memory
static bool     g_poolInjected     = false;
static int      g_poolEntriesAdded = 0;

// Functions
static ClearEntries_fn   g_clearEntries   = nullptr;
static EntryInit_fn      g_entryInit      = nullptr;
static FreeListInsert_fn g_freeListInsert = nullptr;

// ================================================================
//  Memory Validation
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

// ================================================================
//  CVar Access
// ================================================================

static int ReadRetention() {
    __try {
        uintptr_t cvarPtr = *(uintptr_t*)Addr::CVar_RetentionPtr;
        if (!cvarPtr || !IsReadable(cvarPtr + CVAR_INT_OFFSET)) return -1;
        return *(int*)(cvarPtr + CVAR_INT_OFFSET);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
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
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ================================================================
//  Retention Patch
// ================================================================

static int TryPatchRetention() {
    if (!IsReadable(Addr::CVar_RetentionPtr)) return 0;

    int current = ReadRetention();
    if (current < 0) return 0;
    if (current <= 0 || current > 100000) {
        Log("[CombatLog] Implausible retention value: %d", current);
        return -1;
    }

    g_origRetention = current;

    if (!WriteRetention(TARGET_RETENTION_SEC)) {
        Log("[CombatLog] Failed to write retention value");
        return -1;
    }

    g_retentionPatched = true;
    return 1;
}

// ================================================================
//  Periodic Clear
// ================================================================

static void TryClearProcessedEntries() {
    __try {
        uintptr_t pending = *(uintptr_t*)Addr::PendingEntry;
        if (pending != 0) return;

        uintptr_t head = *(uintptr_t*)Addr::ActiveListHead;
        if (!head || (head & 1)) return;

        g_clearEntries();
        g_totalClears++;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[CombatLog] Exception in clear");
    }
}

// ================================================================
//  Entry Pool — Pre-fill the Free List
//
//  We allocate POOL_ENTRY_COUNT entries (each 0x78 bytes) as one
//  contiguous block via mimalloc. Then we initialize each entry
//  and insert it into the combat log's free list using the
//  engine's own FreeListInsert function.
//
//  After this, sub_750400 will find entries in the free list
//  and NEVER need to call sub_74F2D0 (heap alloc) during combat.
//
//  This is called from OnFrame when we detect the free list
//  manager is ready (after player login).
// ================================================================

static bool InitializeEntry(uint8_t* entry) {
    __try {
        // Zero the entire entry
        memset(entry, 0, ENTRY_SIZE);

        // Set up linked list pointers (will be overwritten by FreeListInsert)
        *(uintptr_t*)(entry + 0x00) = 0;  // next
        *(uintptr_t*)(entry + 0x04) = 0;  // prev

        // Set up string object vtable at +0x48
        *(uintptr_t*)(entry + 0x48) = Addr::StringVtable;
        *(uintptr_t*)(entry + 0x4C) = 0;  // string length = 0

        // Call the engine's entry initializer
        g_entryInit((void*)entry);

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool InjectPool() {
    if (g_poolInjected) return true;

    // Verify functions
    if (!g_entryInit || !g_freeListInsert) {
        Log("[CombatLog-Pool] Functions not resolved");
        return false;
    }

    // Verify free list manager exists
    if (!IsReadable(Addr::FreeListManager)) {
        Log("[CombatLog-Pool] Free list manager not readable");
        return false;
    }

    // Allocate pool memory (one big contiguous block)
    g_poolMemory = (uint8_t*)mi_calloc(POOL_ENTRY_COUNT, ENTRY_SIZE);
    if (!g_poolMemory) {
        Log("[CombatLog-Pool] Failed to allocate %d bytes", POOL_TOTAL_BYTES);
        return false;
    }

    Log("[CombatLog-Pool] Allocated %d entries (%d KB) at 0x%08X",
        POOL_ENTRY_COUNT, POOL_TOTAL_BYTES / 1024, (unsigned)(uintptr_t)g_poolMemory);

    // Initialize each entry and insert into free list
    int injected = 0;
    int failed = 0;

    for (int i = 0; i < POOL_ENTRY_COUNT; i++) {
        uint8_t* entry = g_poolMemory + (i * ENTRY_SIZE);

        if (!InitializeEntry(entry)) {
            failed++;
            if (failed > 10) {
                Log("[CombatLog-Pool] Too many init failures, stopping at %d", i);
                break;
            }
            continue;
        }

        // Insert into free list using engine's function
        // sub_86E200 signature: void __thiscall FreeListInsert(void* manager, void* entry)
        // ecx = manager (ADB980), arg = entry pointer
        __try {
            g_freeListInsert((void*)Addr::FreeListManager, (void*)entry);
            injected++;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            failed++;
            Log("[CombatLog-Pool] Exception inserting entry %d", i);
            if (failed > 10) break;
        }
    }

    g_poolEntriesAdded = injected;
    g_poolInjected = (injected > 0);

    if (g_poolInjected) {
        Log("[CombatLog-Pool]  [ OK ] Injected %d entries into free list (%d failed)",
            injected, failed);
    } else {
        Log("[CombatLog-Pool]  [FAIL] Could not inject any entries");
        mi_free(g_poolMemory);
        g_poolMemory = nullptr;
    }

    return g_poolInjected;
}

// ================================================================
//  Public API
// ================================================================

namespace CombatLogOpt {

bool Init() {
    Log("[CombatLog] ====================================");
    Log("[CombatLog]  Combat Log Buffer Optimizer");
    Log("[CombatLog]  Build 12340");
    Log("[CombatLog] ====================================");

    // Resolve functions
    if (!IsExecutable(Addr::CombatLogClearEntries)) {
        Log("[CombatLog] CombatLogClearEntries not found");
        return false;
    }
    g_clearEntries = (ClearEntries_fn)Addr::CombatLogClearEntries;

    if (IsExecutable(Addr::EntryInit)) {
        g_entryInit = (EntryInit_fn)Addr::EntryInit;
        Log("[CombatLog]  EntryInit:       0x%08X  OK", (unsigned)Addr::EntryInit);
    } else {
        Log("[CombatLog]  EntryInit:       FAILED");
    }

    if (IsExecutable(Addr::FreeListInsert)) {
        g_freeListInsert = (FreeListInsert_fn)Addr::FreeListInsert;
        Log("[CombatLog]  FreeListInsert:  0x%08X  OK", (unsigned)Addr::FreeListInsert);
    } else {
        Log("[CombatLog]  FreeListInsert:  FAILED");
    }

    // Try retention patch
    int retResult = TryPatchRetention();
    if (retResult == 1) {
        Log("[CombatLog]  [ OK ] Retention time (%d -> %d sec)",
            g_origRetention, TARGET_RETENTION_SEC);
    } else if (retResult == 0) {
        Log("[CombatLog]  [WAIT] Retention time — CVar not ready, will retry");
    } else {
        Log("[CombatLog]  [FAIL] Retention time");
        g_retentionGaveUp = true;
    }

    Log("[CombatLog]  [ OK ] Periodic clear (every %d frames)", CLEAR_INTERVAL_FRAMES);

    if (g_entryInit && g_freeListInsert) {
        Log("[CombatLog]  [WAIT] Entry pool (%d entries, %d KB) — deferred to main thread",
            POOL_ENTRY_COUNT, POOL_TOTAL_BYTES / 1024);
    } else {
        Log("[CombatLog]  [SKIP] Entry pool — missing functions");
    }

    Log("[CombatLog] ====================================");

    g_initialized = true;
    return true;
}

void OnFrame(DWORD mainThreadId) {
    if (!g_initialized) return;
    if (GetCurrentThreadId() != mainThreadId) return;

    // Retry retention patch if CVar wasn't ready during Init
    if (!g_retentionPatched && !g_retentionGaveUp) {
        g_retentionRetries++;
        if ((g_retentionRetries & 15) == 0) {
            int result = TryPatchRetention();
            if (result == 1) {
                Log("[CombatLog] Retention patched on retry #%d: %d -> %d sec",
                    g_retentionRetries, g_origRetention, TARGET_RETENTION_SEC);
            } else if (result == -1 || g_retentionRetries >= MAX_RETENTION_RETRIES) {
                g_retentionGaveUp = true;
                Log("[CombatLog] Retention patch failed after %d retries",
                    g_retentionRetries);
            }
        }
    }

    // Re-apply retention if overwritten
    g_retentionCheckCounter++;
    if (g_retentionPatched && g_retentionCheckCounter >= RETENTION_CHECK_FRAMES) {
        g_retentionCheckCounter = 0;
        int current = ReadRetention();
        if (current > 0 && current != TARGET_RETENTION_SEC) {
            WriteRetention(TARGET_RETENTION_SEC);
        }
    }

    // Inject pool once (after retention is patched = CVar system ready)
    if (!g_poolInjected && g_retentionPatched && g_entryInit && g_freeListInsert) {
        Log("[CombatLog-Pool] Attempting pool injection...");
        InjectPool();
    }

    // Periodic clear of processed entries
    g_clearCounter++;
    if (g_clearCounter >= CLEAR_INTERVAL_FRAMES) {
        g_clearCounter = 0;
        TryClearProcessedEntries();
    }
}

void Shutdown() {
    if (!g_initialized) return;

    if (g_retentionPatched) {
        WriteRetention(g_origRetention);
        Log("[CombatLog] Retention restored to %d sec", g_origRetention);
        g_retentionPatched = false;
    }

    // NOTE: We do NOT free the pool memory here.
    // The entries are in the engine's free list — freeing them
    // would corrupt the linked list and crash.
    // The memory will be freed when the process exits.

    Log("[CombatLog] Shutdown. Clears: %d, Pool: %s (%d entries)",
        g_totalClears,
        g_poolInjected ? "ACTIVE" : "inactive",
        g_poolEntriesAdded);

    g_initialized = false;
}

PoolStats GetPoolStats() {
    PoolStats s = {};
    s.poolSize   = POOL_ENTRY_COUNT;
    s.poolUsed   = g_poolEntriesAdded;
    s.poolActive = g_poolInjected;
    return s;
}

} // namespace CombatLogOpt