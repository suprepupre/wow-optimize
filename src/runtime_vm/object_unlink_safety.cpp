// ============================================================================
// Description: SEH guard for the generic intrusive-list unlink helper sub_5C6800.
// Safety & Threading: main-thread only (object manager reaping); on a fault it
//              finishes the unlink from the object's own side only.
// ============================================================================
// sub_5C6800 is __thiscall(this), no other args, returns this+4. It unlinks
// `this` from up to two intrusive doubly-linked lists it may be a member of:
//   block 1: this[3]/this[4]  (this+0xC / this+0x10)
//   block 2: this[1]/this[2]  (this+0x4  / this+0x8)
// Each block, if the list pointer is set, computes the sibling slot to patch
// (a tagged self-relative offset scheme) and writes `this`'s neighbor into it,
// then zeroes its own pair of fields. On success this[1..4] all end up 0 -
// that's the function's whole postcondition.
//
// It's shared plumbing (30+ call sites across the client, e.g. object-manager
// hash buckets, spatial/visibility lists), reached here from a periodic
// stale-object reaper (sub_4D48C0 -> sub_4D4090, which references the string
// "ObjectMgrClient.cpp"). A tester's game closed itself with an ACCESS_VIOLATION
// writing through a NULL pointer at 0x5C685C (second block): the object's
// "next" pointer (this+4) was set but its "prev" side decoded to a NULL slot -
// a node that's already half-unlinked, most likely from a prior double-unlink
// or a stale reference elsewhere in the client. Stack trace was 100% engine
// code (Ascension.exe/WoW.exe), nothing of ours in the call chain.
//
// We can't fix the real bug (something on the *other* side of one of these
// lists holds a stale pointer to `this`, and guessing at its layout to patch
// it is how a clean crash becomes a worse, delayed one). What we CAN safely
// guarantee is `this`'s own side of the postcondition: on a fault, force
// this[1..4] to 0 ourselves, exactly matching what the function leaves behind
// on success. This can't make the underlying corruption worse - we're only
// writing to fields the function itself was already about to zero - and it
// stops the reaper from re-faulting on the same node next sweep.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"   // the No Client Patches gate and the foreign-detour check live here
#include "crash_dumper.h"

extern "C" void Log(const char* fmt, ...);

typedef void* (__thiscall* fn_5C6800)(void* pThis);
// Whether the hook actually went in, so the report can tell a guard
// that never fired from one that was never installed.
static bool g_statsInstalled = false;

static fn_5C6800 g_orig_5C6800 = nullptr;
static volatile long g_ul_averted = 0;
static volatile long g_ul_logged  = 0;

static void* __fastcall Safe_sub_5C6800(void* pThis, void* /*edx*/)
{
    __try {
        return g_orig_5C6800(pThis);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement(&g_ul_averted);
        __try {
            uintptr_t self = (uintptr_t)pThis;
            *(uintptr_t*)(self + 0x4)  = 0;
            *(uintptr_t*)(self + 0x8)  = 0;
            *(uintptr_t*)(self + 0xC)  = 0;
            *(uintptr_t*)(self + 0x10) = 0;
        } __except(EXCEPTION_EXECUTE_HANDLER) {}

        if (InterlockedCompareExchange(&g_ul_logged, 1, 0) == 0)
            Log("[ObjectUnlinkSafety] averted a crash in sub_5C6800 "
                "(intrusive list unlink hit a half-unlinked node during object reaping)");
        return (void*)((uintptr_t)pThis + 0x4);
    }
}

bool InstallObjectUnlinkSafety()
{
    void* target = (void*)0x005C6800;
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x56 || p[1] != 0x8D) {   // push esi; lea eax, [ecx+0Ch]
        Log("[ObjectUnlinkSafety] BAD PROLOGUE at 0x005C6800 (expected 56 8D, got %02X %02X)",
            p[0], p[1]);
        return false;
    }
    if (MH_CreateHook(target, (void*)Safe_sub_5C6800, (void**)&g_orig_5C6800) != MH_OK) {
        Log("[ObjectUnlinkSafety] MH_CreateHook FAILED");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[ObjectUnlinkSafety] MH_EnableHook FAILED");
        return false;
    }
    CrashDumper::RegisterFeature("ObjectUnlinkSafety");
    CrashDumper::FeatureSetActive("ObjectUnlinkSafety", true);
    Log("[ObjectUnlinkSafety] ACTIVE: SEH-guarding intrusive-list unlink sub_5C6800 "
        "(object-reaper NULL-write crash fix)");
    g_statsInstalled = true;
    return true;
}

// Printed from the periodic report. The counters used to be printed only
// from the uninstall path, which nothing calls: the DLL leaves through
// TerminateProcess, and the linker had dropped the function outright.
void ObjectUnlinkSafety_LogStats(void) {
    if (!g_statsInstalled) {
        Log("[ObjectUnlinkSafety] not measured: the guard is not installed.");
        return;
    }
    Log("[ObjectUnlinkSafety] %ld crash(es) averted.", (long)g_ul_averted);
}

void UninstallObjectUnlinkSafety()
{
    MH_DisableHook((void*)0x005C6800);
    MH_RemoveHook((void*)0x005C6800);
    if (g_ul_averted > 0)
        Log("[ObjectUnlinkSafety] Stats: %ld crashes averted", (long)g_ul_averted);
}
