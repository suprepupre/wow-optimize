// ============================================================================
// Module: lua_table_census.cpp
// Description: Measures how much of the GC's table walk is empty slots.
// Safety & Threading: Main thread, inside the client's collector.
// ============================================================================
//
// luaC_traversetable is the most expensive Lua function in every profile this
// project has collected: 1.41% to 2.46% of executing time, ahead of
// luaV_execute. Reading it (sub_85A960) shows why it could be wasteful. It
// walks the whole array part at a stride of 16 and the whole hash part at a
// stride of 40, every slot, marked or nil:
//
//     v10 = sizearray;  do { ... if (tv->tt >= 4) mark(tv->value); } while (--v10);
//     v14 = 1 << lsizenode;  do { ... if (node->val.tt) { mark key, mark value } } while (--v14);
//
// A table that once held a thousand entries and now holds one still has a
// thousand nodes, because Lua 5.1 only ever resizes on the rehash that an
// insertion triggers, never on deletion. So a proposal to compact sparse tables
// is well aimed in principle.
//
// What nobody has is the number. Nothing says what share of those slots is
// empty, and a compactor built without it would be a large, dangerous piece of
// work aimed at an unmeasured quantity. Writing one first is how this project
// has produced features that turned out to skip nothing.
//
// So this measures it, weighted correctly by construction: it counts the tables
// the collector actually walks, as often as it walks them, which is exactly the
// weighting that decides whether compaction is worth anything.
//
// ---------------------------------------------------------------------------
// Why a hook here is not the dangerous thing it looks like
//
// This is the function in the one tester crash with this DLL genuinely on the
// stack, and that crash came from the GC governor forcing collection steps, not
// from anything attached to this function. What is installed here only reads
// four fields and adds them to counters, and then jumps to the client's own
// code with every register and the stack exactly as they arrived. It cannot
// change a mark, a colour or a pointer. It is sampled, so most calls do not
// even read the fields, and it is off by default.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

#include "lua_table_census.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

// Named at file scope: the naked thunk reaches them from inline assembly.
static void* g_origTraverse = nullptr;

// Plain 32-bit counters on the GC's hot path, so lower bounds, and the report
// says so. Slot totals are kept as doubles because a long session walks far
// more than four billion of them.
static uint32_t g_sampleCounter = 0;
static uint32_t g_tablesSeen    = 0;
static double   g_capArray      = 0.0;
static double   g_liveArray     = 0.0;
static double   g_capNode       = 0.0;
static double   g_liveNode      = 0.0;
static uint32_t g_worstCap      = 0;   // the emptiest table seen, by capacity
static uint32_t g_worstLive     = 0;
static uint32_t g_faults        = 0;

extern "C" void __cdecl LuaTableCensus_Note(uint32_t t) {
    // One table in 512. The walk below is O(capacity), the same order as the
    // work the collector is about to do, so sampling is what keeps this from
    // doubling the cost of the thing it measures.
    if ((++g_sampleCounter & 511u) != 0) return;
    if (!t) return;

    __try {
        // Table layout, from sub_85A960 itself: lsizenode is the byte at +11,
        // array at +16, node at +20, sizearray at +32. TValue stride 16 with
        // the type tag at +8; Node stride 40 with the value's tag at +8.
        uint32_t sizearray = *(const uint32_t*)(t + 32);
        uint32_t arrayPtr  = *(const uint32_t*)(t + 16);
        uint32_t nodePtr   = *(const uint32_t*)(t + 20);
        uint8_t  lsize     = *(const uint8_t*)(t + 11);
        if (lsize > 26) return;              // 64M nodes; not a real table
        if (sizearray > (1u << 26)) return;
        uint32_t sizenode = 1u << lsize;

        uint32_t liveA = 0;
        if (arrayPtr) {
            for (uint32_t i = 0; i < sizearray; i++)
                if (*(const uint32_t*)(arrayPtr + i * 16 + 8) != 0) liveA++;
        }
        uint32_t liveN = 0;
        if (nodePtr) {
            for (uint32_t i = 0; i < sizenode; i++)
                if (*(const uint32_t*)(nodePtr + i * 40 + 8) != 0) liveN++;
        }

        g_tablesSeen++;
        g_capArray  += (double)sizearray;
        g_liveArray += (double)liveA;
        g_capNode   += (double)sizenode;
        g_liveNode  += (double)liveN;

        uint32_t cap  = sizearray + sizenode;
        uint32_t live = liveA + liveN;
        // The emptiest one, judged by how many slots are wasted rather than by
        // ratio, because a half-empty table of four is not worth a compactor.
        if (cap - live > g_worstCap - g_worstLive) { g_worstCap = cap; g_worstLive = live; }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_faults++;
    }
}

// sub_85A960 is __usercall: the table arrives in EBX and the global state is on
// the stack. Everything is preserved and the client's own code runs unchanged.
__declspec(naked) static void HookedTraverse() {
    __asm {
        pushad
        pushfd
        push ebx
        call LuaTableCensus_Note
        add  esp, 4
        popfd
        popad
        jmp  dword ptr [g_origTraverse]
    }
}

namespace LuaTableCensus {

namespace {
constexpr uintptr_t kTraverse = 0x0085A960;
bool g_installed = false;
}  // namespace

bool Init() {
    if (!Config::g_settings.OptLuaTableCensus) return true;

    if (IsBadReadPtr((void*)kTraverse, 16)) {
        Log("[TableCensus] 0x%08X unreadable - not installing", (unsigned)kTraverse);
        return false;
    }
    if (WineSafe_CreateHook((void*)kTraverse, (void*)HookedTraverse, &g_origTraverse) != MH_OK) {
        Log("[TableCensus] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kTraverse) != MH_OK) {
        Log("[TableCensus] hook created but could not be enabled");
        return false;
    }

    g_installed = true;
    Log("[TableCensus] ACTIVE on luaC_traversetable (0x%08X). One table in 512 "
        "has its array and hash capacity compared with the slots that actually "
        "hold something. This only counts and always calls the client's own "
        "code; it answers whether compacting sparse tables would be worth "
        "building, which nothing has measured.",
        (unsigned)kTraverse);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptLuaTableCensus) return;
    if (!g_installed)      { Log("[TableCensus] not installed - nothing measured"); return; }
    if (g_tablesSeen == 0) { Log("[TableCensus] installed but no table sampled yet"); return; }

    double cap  = g_capArray + g_capNode;
    double live = g_liveArray + g_liveNode;
    Log("[TableCensus] %u tables sampled (one in 512 of the collector's walk). "
        "Slots: %.0f capacity, %.0f holding something, %.1f%% empty. Counts are "
        "lower bounds.",
        g_tablesSeen, cap, live,
        cap > 0.0 ? 100.0 * (cap - live) / cap : 0.0);
    Log("[TableCensus]   array part %.0f of %.0f used, hash part %.0f of %.0f "
        "used; emptiest table seen held %u of %u slots",
        g_liveArray, g_capArray, g_liveNode, g_capNode, g_worstLive, g_worstCap);
    if (g_faults)
        Log("[TableCensus]   %u samples faulted while reading a table and were "
            "discarded", g_faults);
}

}  // namespace LuaTableCensus
