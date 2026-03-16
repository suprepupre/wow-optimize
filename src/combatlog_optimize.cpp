// ================================================================
//  Combat Log Buffer Optimizer — Implementation
//  WoW 3.3.5a build 12340 (Warmane)
//
//  Two-layer fix for combat log issues:
//
//  Layer 1: Retention increase (300 -> 1800 sec)
//  Layer 2: Guaranteed Periodic Clear (fixes the break bug)
// ================================================================

#include "combatlog_optimize.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

extern "C" void Log(const char* fmt, ...);

// ================================================================
//  Known Addresses — build 12340
// ================================================================

namespace Addr {
    static constexpr uintptr_t CVar_RetentionPtr     = 0x00BD09F0;
    static constexpr uintptr_t ActiveListHead        = 0x00ADB97C;
    static constexpr uintptr_t CombatLogClearEntries  = 0x00751120;
}

// ================================================================
//  Configuration
// ================================================================

static constexpr int TARGET_RETENTION_SEC    = 1800;
static constexpr int RETENTION_CHECK_FRAMES  = 600;
static constexpr int CVAR_INT_OFFSET         = 0x30;
static bool g_combatActive = false;

// ================================================================
//  Function Types
// ================================================================

typedef int (__cdecl *ClearEntries_fn)();

// ================================================================
//  State
// ================================================================

static bool    g_initialized       = false;

static int     g_origRetention     = 0;
static bool    g_retentionPatched  = false;
static bool    g_retentionGaveUp   = false;
static int     g_retentionRetries  = 0;
static int     g_retentionCheckCounter = 0;

static double  g_qpcFreqMs         = 0.0;
static double  g_lastClearTime     = 0.0;
static int     g_totalClears       = 0;

static ClearEntries_fn g_clearEntries = nullptr;

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
//  Layer 2: Guaranteed Clear
// ================================================================

static double GetClearIntervalMs() {
    if (g_combatActive) return 10000.0;
    return 5000.0;
}

static void TryClearProcessedEntries(double nowMs) {
    if (nowMs - g_lastClearTime < GetClearIntervalMs()) return;
    g_lastClearTime = nowMs;

    g_clearEntries();
    g_totalClears++;
}

// ================================================================
//  API
// ================================================================

namespace CombatLogOpt {

bool Init() {
    Log("[CombatLog] ====================================");
    Log("[CombatLog]  Combat Log Optimizer (Retention + Clear)");
    Log("[CombatLog]  Build 12340");
    Log("[CombatLog] ====================================");

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    g_qpcFreqMs = (double)freq.QuadPart / 1000.0;

    if (IsExecutable(Addr::CombatLogClearEntries))
        g_clearEntries = (ClearEntries_fn)Addr::CombatLogClearEntries;

    int ret = TryPatchRetention();
    if (ret == 1) Log("[CombatLog]  [ OK ] Retention patched (1800s)");

    Log("[CombatLog]  [ OK ] Guaranteed Clear (5s normal, 10s combat)");

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

    if (g_clearEntries) {
        TryClearProcessedEntries(nowMs);
    }
}

void SetCombat(bool active) {
    g_combatActive = active;
}

void Shutdown() {
    if (!g_initialized) return;
    if (g_retentionPatched) WriteRetention(g_origRetention);
    Log("[CombatLog] Shutdown. Clears: %d", g_totalClears);
    g_initialized = false;
}

PoolStats GetPoolStats() {
    PoolStats s = { 0, 0, false };
    return s;
}

} // namespace CombatLogOpt