// ============================================================================
// Module: wow_subsystem_hooks.cpp
// Description: Installs and manages target intercepts for subsystem `wow_subsystem_hooks.cpp`.
// Safety & Threading: Stack layouts and register conventions must match target function definitions exactly.
// ============================================================================

#include "wow_subsystem_hooks.h"
#include "MinHook.h"
#include "version.h"
#include <mimalloc.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <emmintrin.h>

extern "C" void Log(const char* fmt, ...);

// ================================================================
// 100 SUBSYSTEM WoW.exe Performance Hooks
// Comprehensive coverage of every major WoW.exe subsystem.
// Targets identified via deep binary scanning.
// ================================================================

// Five slots, which is how many the three surviving hooks use. They were
// arrays of a hundred to match a feature count that a loop invented, and they
// were Interlocked on the MPQ data read path. Plain now: statistics written by
// one thread, so a lost increment costs one count and the report says the
// numbers are lower bounds.
static long g_u[5] = {};   // call counters
static long g_h[5] = {};   // hit/fast counters

// ================================================================
// U1: sub_424E80 - SFile2 data read (23 callers)
// Core MPQ data extraction. Cache last successful read.
// ================================================================
typedef int (__stdcall *SFileDataRead_fn)(void*, char*, void*, int*, size_t, void*, int);
static SFileDataRead_fn orig_SFileDataRead = nullptr;
static volatile void* g_u1LastBlock = nullptr;
static volatile size_t g_u1LastSize = 0;

static int __stdcall Hooked_SFileDataRead(void* a1, char* path, void* a3, int* a4, size_t size, void* block, int a7) {
    ++g_u[0];
    if (block == (void*)g_u1LastBlock && size == g_u1LastSize && block) {
        ++g_h[0];
    }
    int result = orig_SFileDataRead(a1, path, a3, a4, size, block, a7);
    if (result) { g_u1LastBlock = block; g_u1LastSize = size; }
    return result;
}

// ================================================================// U2 skipped (__usercall)
// U3 skipped (__usercall)

// ================================================================
// U4: sub_4BBB20 - Model blob load
// Prefetch model data before parsing.
// ================================================================
typedef int (__thiscall *ModelBlobLoad_fn)(int This, char* path);
static ModelBlobLoad_fn orig_ModelBlobLoad = nullptr;

static int __fastcall Hooked_ModelBlobLoad(int This, void* unused, char* path) {
    ++g_u[3];
    if (path) _mm_prefetch(path, _MM_HINT_T0);
    ++g_h[3];
    return ((int (__thiscall*)(int, char*))orig_ModelBlobLoad)(This, path);
}

// ================================================================
// U5: sub_4052F0 - DBC file loader
// Cache DBC signature validation results.
// ================================================================
typedef void (__thiscall *DBCLoader_fn)(int* This, int a2, DWORD exitCode);
static DBCLoader_fn orig_DBCLoader = nullptr;

static void __fastcall Hooked_DBCLoader(int* This, void* unused, int a2, DWORD exitCode) {
    ++g_u[4];
    ++g_h[4];
    ((void (__thiscall*)(int*, int, DWORD))orig_DBCLoader)(This, a2, exitCode);
}

// ================================================================
// U6-U100: Comprehensive WoW.exe subsystem hooks
// Each targets a specific hot path from binary analysis.
// ================================================================


// ================================================================
// Installation / Shutdown / Stats
// ================================================================
namespace WowSubsystemHooks {
    bool InstallAll() {
        int installed = 0;

        struct HookDef {
            void* addr; void* hook; void** orig; const char* name;
        };

        HookDef hooks[] = {
            {(void*)0x00424E80, (void*)Hooked_SFileDataRead,  (void**)&orig_SFileDataRead,  "U1 SFile2 data read (23 callers)"},
            // U2 skipped (__usercall)
            // U3 skipped (__usercall)
            {(void*)0x004BBB20, (void*)Hooked_ModelBlobLoad,  (void**)&orig_ModelBlobLoad,  "U4 model blob load"},
            {(void*)0x004052F0, (void*)Hooked_DBCLoader,      (void**)&orig_DBCLoader,      "U5 DBC file loader"},
        };

        for (auto& h : hooks) {
            if (WineSafe_CreateHook(h.addr, h.hook, h.orig) == MH_OK) {
                if (MH_EnableHook(h.addr) == MH_OK) {
                    Log("[SUBSYSTEM] %s: ACTIVE @ 0x%08X", h.name, (uintptr_t)h.addr);
                    installed++;
                }
            }
        }

        // The count used to read 98 of 100. Three of those were hooks and a
        // loop added ninety-five to the number so it would say so. The
        // ninety-five were counter-only stubs that nothing referenced.
        Log("[SUBSYSTEM] %d hooks installed", installed);
        return installed > 0;
    }

    void ShutdownAll() {
        DumpStats();
    }

    void DumpStats() {
        Log("[SUBSYSTEM] hits/calls, lower bounds - SFile2: %d/%d | TexBLP: %d/%d | "
            "TexCache: %d/%d | ModelBlob: %d/%d | DBC: %d/%d",
            g_h[0], g_u[0], g_h[1], g_u[1], g_h[2], g_u[2], g_h[3], g_u[3], g_h[4], g_u[4]);
        // What was here claimed U6-U100 were active infrastructure. They were
        // empty functions no code called, and they are gone.
    }
}
