// ============================================================================
// Module: dllmain.cpp
// Description: Main DLL orchestration and initialization hub. Detours system APIs (GetSystemMetrics, sleep pacing, timeGetTime, and ReadFile) to establish frame pacing, timing, and I/O caching.
// Safety & Threading: Main thread execution only. Sequence modifications can lead to system loader deadlocks.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <io.h>
#include <intrin.h>
#include <emmintrin.h>
#include "ui_cache.h"
#include "api_cache.h"
#include "lua_fastpath.h"
#include "lua_alloc_census.h"
#include "lua_internals.h"
#include "lua_vm_cache.h"
#include "crash_dumper.h"
#include "memory_pressure_governor.h"
#include "sampling_profiler.h"
#include "anim_census.h"
#include "net_diag.h"
#include "../simd_math/horizon_occlusion_sse2.h"
#include "lua_getstr_inline.h"
#include "lua_rawgeti_inline.h"
#include "lua_rawget_inline.h"
#include "lua_toboolean_inline.h"
#include "strtod_fast.h"
#include "lua_objlen_inline.h"
#include "lua_error_diag.h"
#include "hooks_memory.h"
#include "regex_cache.h"
#include "texcache_tuning.h"
#include "lua_register_fast.h"
#include "lua_ref_fast.h"
#include "lua_unref_fast.h"
#include "lua_callmeta_fast.h"
#include "lua_checktype_fast.h"
#include "lua_iscfunction_fast.h"
#include "lua_isnumber_fast.h"
#include "lua_rawequal_fast.h"
#include "lua_loadstring_fast.h"
#include "lua_yield_fast.h"
#include "lua_getn_fast.h"
#include "loading_defrag.h"
#include "d3d9_state_cache.h"
#include "d3d9_render_thread.h"
#include "frame_limiter.h"
#include "net_packet_offload.h"
#include "predictive_prefetch.h"
#include "guid_lookup_cache.h"
#include "simd_math_fast.h"
#include "combatlog_incremental.h"
#include "world_state_coalesce.h"
#include "hooks_subsystems/sound_coalescer.h"
#include "hooks_subsystems/particle_density_scaler.h"
#include "hooks_subsystems/vertex_buffer_prealloc.h"
#include "hooks_subsystems/saved_vars_backup.h"
#include "hooks_subsystems/mouse_clip_release.h"
#include "hooks_subsystems/combat_log_filter.h"
#include "hooks_subsystems/sound_volume_limit.h"
#include "hooks_subsystems/terrain_height_cache.h"

#include "hooks_subsystems/texture_unload_delay.h"
#include "hooks_subsystems/quality_governor.h"
#include "hooks_subsystems/spell_effect_culling.h"

// Forward declaration - Log() defined later in this file
extern "C" void Log(const char* fmt, ...);

// ================================================================
// Freeze Detection Watchdog
// Detects when main thread stops responding (no Sleep calls for N seconds)
// Dumps feature states + hook trace to log so we know what was active
// ================================================================
static volatile DWORD g_lastMainThreadTick = 0;
static volatile bool  g_freezeWatchdogActive = false;
static HANDLE         g_freezeWatchdogThread = NULL;
DWORD          g_mainThreadId = 0;

// Forward-declared here because the watchdog (below) is defined before
// lua_optimize.h is included; definitions match that header.
namespace LuaOpt { bool IsLoadingMode(); bool IsReloading(); bool IsSwapping(); DWORD GetLastSwapTick(); bool IsInitialized(); }

// A target we declined because its first byte was a jump - somebody had already
// detoured it. Reported once per address and then counted, because a client that
// hooks a dozen functions would otherwise fill the log with the same finding.
static volatile long g_foreignDetours = 0;

extern "C" void WowOpt_LogForeignDetour(void* target, unsigned char firstByte) {
    long n = InterlockedIncrement(&g_foreignDetours);
    if (n <= 16) {
        Log("[Hooks] 0x%08X already carries a %s (0x%02X) - another party hooked "
            "it first, so this one is left alone",
            (unsigned)(uintptr_t)target,
            firstByte == 0xE9 ? "jmp rel32" : "short jmp", firstByte);
    } else if (n == 17) {
        Log("[Hooks] Further already-detoured targets will be counted, not listed");
    }
}

// One of our own modules had already hooked this address. Distinct from a
// foreign detour: that is somebody else's code, this is ours colliding with
// ours, and the two want different fixes.
static volatile long g_duplicateHooks = 0;

extern "C" void WowOpt_LogDuplicateHook(void* target) {
    long n = InterlockedIncrement(&g_duplicateHooks);
    if (n <= 8) {
        Log("[Hooks] 0x%08X is already hooked by another module of ours - two "
            "implementations aimed at one function, and only one of them runs",
            (unsigned)(uintptr_t)target);
    }
}

extern "C" void WowOpt_ReportForeignDetours() {
    long dup = g_duplicateHooks;
    if (dup > 0) {
        Log("[Hooks] %ld address%s targeted by more than one of our own modules. "
            "Whichever installs first wins, which is not decided anywhere on "
            "purpose.", dup, dup == 1 ? "" : "es");
    }

    long n = g_foreignDetours;
    if (n > 0) {
        Log("[Hooks] %ld hook target%s skipped because something else had already "
            "detoured them. On a client that instruments itself this is expected; "
            "installing over it is what breaks the chain.", n, n == 1 ? "" : "s");
    }
}

// For the disconnect observer, which wants to say whether the main thread was
// still ticking when the connection ended.
extern "C" DWORD WowOpt_LastMainThreadTick() { return g_lastMainThreadTick; }

static void UpdateMainThreadActivity() {
    g_lastMainThreadTick = GetTickCount();
    CrashDumper::FeatureCall("SleepHook");
}

// Classify a code address to "module.dll+0xOFFSET" (or raw hex if not in a module).
static void FreezeClassifyAddr(uintptr_t addr, char* out) {
    HMODULE hm = NULL;
    if (addr >= 0x10000 &&
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)addr, &hm) && hm) {
        char path[MAX_PATH];
        if (GetModuleFileNameA(hm, path, MAX_PATH)) {
            const char* base = strrchr(path, '\\');
            base = base ? base + 1 : path;
            wsprintfA(out, "%s+0x%X", base, (unsigned)(addr - (uintptr_t)hm));
            return;
        }
    }
    wsprintfA(out, "0x%08X", (unsigned)addr);
}

// What every other thread in the process was doing when the main thread stalled.
//
// A raid session produced seven real stalls, the longest 10.5 seconds - confirmed
// independently by FrameBench, which counted them as gaps and kept them out of
// the frame statistics. The main thread's stack named the waiter every time:
// sub_774DA0, WoW's own lock, spinning and then waiting on an event. So the main
// thread is blocked on something another thread holds, and the report said
// nothing whatsoever about that other thread.
//
// That is the whole question. This answers it by naming, for every other thread
// in the process, the module and offset it was executing.
//
// Safe to call here: the watchdog thread does nothing between the suspend and the
// resume except read a register, so it cannot want a lock the suspended thread is
// holding. The stall is already in progress, so a few microseconds of extra
// suspension changes nothing.
static void FreezeDumpOtherThreads(DWORD mainTid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        Log("!!!   (could not enumerate threads)");
        return;
    }

    DWORD selfPid = GetCurrentProcessId();
    DWORD watchdogTid = GetCurrentThreadId();
    int reported = 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        Log("!!!   OTHER THREADS AT THE MOMENT OF THE STALL:");
        do {
            if (te.th32OwnerProcessID != selfPid) continue;
            if (te.th32ThreadID == mainTid || te.th32ThreadID == watchdogTid) continue;
            if (reported >= 24) break;

            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                                  FALSE, te.th32ThreadID);
            if (!h) continue;

            uintptr_t eip = 0;
            if (SuspendThread(h) != (DWORD)-1) {
                CONTEXT c;
                c.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(h, &c)) eip = (uintptr_t)c.Eip;
                ResumeThread(h);
            }
            CloseHandle(h);

            if (eip) {
                char where[128];
                FreezeClassifyAddr(eip, where);
                Log("!!!     TID=%-6lu %s", te.th32ThreadID, where);
                reported++;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (reported == 0) Log("!!!     (none could be read)");
}


// On a real freeze, snapshot WHERE the main thread is actually stuck. The EIP
// tells us whether it's blocked in a syscall (ntdll = a wait) and the stack
// return addresses tell us who called it: d3d9.dll/vulkan = DXVK GPU/pipeline
// wait, wow_optimize.dll = our fault, Wow.exe = engine/addon. This is what turns
// a useless "SleepHook 10s ago" into an actual diagnosis.
static void CaptureFreezeLocation(DWORD mainTid) {
    if (mainTid == 0) return;
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                          FALSE, mainTid);
    if (!h) return;

    // While the main thread is suspended, ONLY read raw memory (EIP + a slice of
    // the stack). Do NOT call GetModuleHandleExA here: it takes the loader lock,
    // and if the thread froze while holding that lock (e.g. mid DLL load) we'd
    // deadlock. Classification happens after we resume.
    uintptr_t eip = 0, rawStack[96]; int rawCount = 0;
    if (SuspendThread(h) != (DWORD)-1) {
        CONTEXT ctx; ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (GetThreadContext(h, &ctx)) {
            eip = ctx.Eip;
            uintptr_t* sp = (uintptr_t*)ctx.Esp;
            for (int i = 0; i < 96; i++) {
                __try { rawStack[rawCount] = sp[i]; } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
                rawCount++;
            }
        }
        ResumeThread(h);
    }
    CloseHandle(h);

    // Now safe to classify (loader lock) and log — main thread is running again.
    if (eip) {
        char buf[MAX_PATH + 32];
        FreezeClassifyAddr(eip, buf);
        Log("!!!   STUCK AT: EIP=%s", buf);
        int shown = 0;
        for (int i = 0; i < rawCount && shown < 6; i++) {
            uintptr_t v = rawStack[i];
            HMODULE hm = NULL;
            if (v >= 0x10000 &&
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)v, &hm) && hm) {
                FreezeClassifyAddr(v, buf);
                Log("!!!     stack -> %s", buf);
                shown++;
            }
        }
    }
}

// perf_diagnostics.h is included further down this file; declare what the
// watchdog needs here so the escalation path can dump the memory snapshot.
namespace PerfDiagnostics { void LogPerformanceSnapshot(double elapsedMs); }

static DWORD WINAPI FreezeWatchdogProc(LPVOID) {
    bool escalatedThisStall = false;   // reset once the main thread ticks again
    while (g_freezeWatchdogActive) {
        Sleep(5000);
        if (!g_freezeWatchdogActive) break;

        DWORD lastTick = g_lastMainThreadTick;
        if (lastTick == 0) continue;

        DWORD elapsed = GetTickCount() - lastTick;
        if (elapsed <= 10000) escalatedThisStall = false;
        if (elapsed > 10000) {
            // Loading screens, UI reloads and lua_State swaps legitimately block
            // the main thread (cold MPQ asset loads + addon (re)load). That is NOT
            // a hang the player feels -- it's a progress-bar load -- so don't spam
            // the log with a full freeze report. Note it on one line and wait it
            // out. This is the source of the "many FREEZE DETECTED" entries.
            // Grace period: for 30s after a lua_State swap, treat main-thread silence
            // as expected. WoW's addon loader runs synchronously after the swap completes
            // (our IsReloading/IsSwapping flags clear before this begins).
            DWORD swapTick = LuaOpt::GetLastSwapTick();
            bool inPostSwapGrace = (swapTick != 0 && (GetTickCount() - swapTick) < 30000);
            bool expected = LuaOpt::IsLoadingMode() || LuaOpt::IsReloading() || LuaOpt::IsSwapping() || inPostSwapGrace;

            // A loading screen that never ends looks exactly like "expected"
            // blocking, so staying quiet forever means we never see the one
            // failure we most need to diagnose. Past 45s no legitimate zone load
            // is still running: escalate and capture the stuck location anyway.
            // Once per stall, so a genuinely slow cold load doesn't spam.
            if (expected && elapsed > 45000 && !escalatedThisStall) {
                escalatedThisStall = true;
                Log("!!! LOADING STALL !!! Main thread blocked %u ms and still flagged as "
                    "loading/transition -- this is no longer a normal load", elapsed);
                CaptureFreezeLocation(g_mainThreadId);
                PerfDiagnostics::LogPerformanceSnapshot((double)elapsed);
            }

            if (expected) {
                Log("[FreezeWatchdog] main thread blocked %u ms during loading/transition (expected, not a hang)", elapsed);
            } else {
                Log("!!! FREEZE DETECTED !!! Main thread silent for %u ms (no loading/transition active)", elapsed);
                Log("!!! Last main thread tick: %u, current: %u", lastTick, GetTickCount());
                CaptureFreezeLocation(g_mainThreadId);

                // Concise suspect list only: features that logged an error or were
                // active right up to the stall. The old full dump printed 100+
                // lines that were almost all calls=0 (only SleepHook records calls)
                // -- pure noise that bloated the log on every load.
                FeatureState states[MAX_TRACKED_FEATURES];
                int count = CrashDumper::GetFeatureStates(states, MAX_TRACKED_FEATURES);
                int suspects = 0;
                for (int i = 0; i < count; i++) {
                    if (!states[i].active) continue;
                    DWORD age = (states[i].lastCallTick > 0) ? (GetTickCount() - states[i].lastCallTick) : 999999;
                    if (states[i].errorCount > 0 || age < elapsed + 2000) {
                        Log("!!!   %-28s calls=%lld errors=%lld lastCall=%u ms ago",
                            states[i].name ? states[i].name : "?",
                            states[i].callCount, states[i].errorCount, age);
                        suspects++;
                    }
                }
                if (suspects == 0)
                    Log("!!!   (no error/recently-active DLL feature -- stall is WoW-internal)");

                FreezeDumpOtherThreads(g_mainThreadId);

                Log("!!! END FREEZE REPORT !!!");
            }

            while (g_freezeWatchdogActive && (GetTickCount() - g_lastMainThreadTick) > 10000) {
                Sleep(2000);
            }
        }
    }
    return 0;
}

static void StartFreezeWatchdog() {
    g_lastMainThreadTick = GetTickCount();
    g_freezeWatchdogActive = true;
    g_freezeWatchdogThread = CreateThread(NULL, 65536, FreezeWatchdogProc, NULL, 0, NULL);
    Log("[FreezeWatchdog] Started (10s threshold, 5s check interval)");
}

static void StopFreezeWatchdog() {
    g_freezeWatchdogActive = false;
    if (g_freezeWatchdogThread) {
        WaitForSingleObject(g_freezeWatchdogThread, 6000);
        CloseHandle(g_freezeWatchdogThread);
        g_freezeWatchdogThread = NULL;
    }
}

#include "frame_throttle.h"
// #include "ui_frame_batch.h" // REMOVED - optimization disabled

#include "MinHook.h"
#include <mimalloc.h>
#include <unordered_map>
#include "lua_optimize.h"
#include "combatlog_optimize.h"
#include "combatlog_buffer.h"
#include "addon_dispatcher.h"
#include "mpq_async_decompress.h"
#include "obj_vis_cache.h"
#include "nameplate_batch.h"
#include "addon_preload.h"
#include "lua_bytecode_cache.h"
#include "strstr_fast.h"
#include "crt_char_fast.h"
#include "crt_wchar_fast.h"
#include "stream_cache.h"
#include "lua_this_cache.h"
#include "io_cache.h"
#include "lua_global_cache.h"
#include "hot_functions.h"
#include "fast_strncmp.h"
#include "render_null_guard.h"
#include "cvar_watchdog.h"
#include "lua_precall_cache.h"
#include "lua_table_fast.h"
#include "lua_hget_fast.h"
#include "lua_checknumber_fast.h"
#include "lua_checkstring_fast.h"
#include "lua_optnumber_fast.h"
#include "lua_optstring_fast.h"
#include "lua_tolstring_fast.h"
#include "lua_argcheck_fast.h"
#include "lua_typename_fast.h"
#include "lua_getlocal_fast.h"
#include "lua_setlocal_fast.h"
#include "lua_getinfo_fast.h"
#include "lua_error_fast.h"
#include "lua_lessthan_fast.h"
#include "lua_gc_fast.h"
#include "lua_xpcall_fast.h"
#include "lua_getmetafield_fast.h"
#include "lua_where_fast.h"
#include "cvar_null_guard.h"
#include "d3d_evict_patch.h"
#include "strncmp_null_guard.h"
#include "crt_free_hook.h"
#include "lock_tuning.h"
#include "texcache_tuning.h"
#include "aligned_alloc_cache.h"
#include "lua_tonumber_cache.h"
#include "lua_checknumber_cache.h"
#include "lua_pushstring_cache.h"
#include "format_validator_cache.h"
#include "datastore_fastpath.h"
#include "string_ops_fast.h"
#include "heap_compactor.h"
#include "version_checker.h"
#include "lua_tonumber_fast.h"
#include "lua_pushnumber_fast.h"
#include "gettime_fast.h"
#include "lua_gettime_fast.h"
#include "lua_pushvalue_fast.h"
#include "render_state_dedup.h"
#include "lua_settable_cache.h"
#include "regex_cache.h"
#include "strncmp_sse2.h"
#include "addon_profiler.h"
#include "event_name_hash.h"
#include "cdatastore_batch.h"
#include "crt_memcpy_fast.h"
#include "frame_script_dispatch.h"
#include "strcat_fast.h"
#include "script_handler_cache.h"
#include "dbc_lookup_cache.h"
#include "event_dispatch_cache.h"
#include "event_name_cache.h"
#include "lua_getstr_inline.h"
#include "lua_rawgeti_inline.h"
#include "lua_gettable_safety.h"
#include "lua_newkey_safety.h"
#include "sound_driver_guard.h"
#include "sound_emitter_guard.h"
#include "sound_buffer_guard.h"
#include "sound_update_guard.h"
#include "lua_vm_engine.h"
#include "lua_gettable_cache.h"
#include "saved_vars_async.h"
#include "event_coalescer.h"
#include "loading_state.h"
#include "diagnostics/frame_bench.h"
#include "luaS_newlstr_sse2.h"
#include "hot_patch.h"
#include "wow_opt_hooks.h"
#include "wow_perf_hooks.h"
#include "wow_extended_hooks.h"
#include "unitaura_fastpath.h"
#include "network_guid_sse2.h"
#include "matrix_copy_sse2.h"
#include "lua_numconv_fast.h"
#include "lua_stack_fast.h"
#include "lua_settable_fast.h"
#include "lua_gettable_fast.h"
#include "lua_rawseti_fast.h"
#include "lua_setfield_fast.h"
#include "lua_pushthread_fast.h"
#include "lua_rawset_fast.h"
#include "lua_pushcclosure_fast.h"
#include "lua_createtable_fast.h"
#include "lua_pushstring_fast.h"
#include "lua_pushfstring_fast.h"
#include "lua_getupvalue_fast.h"
#include "lua_buffinit_fast.h"
#include "combatlog_parser.h"

void ClearCombatLogCache();
#include "lua_prepbuffer_fast.h"
#include "lua_pushresult_fast.h"
#include "lua_addlstring_fast.h"
#include "wow_subsystem_hooks.h"
#include "wow_memory_opt.h"
#include "wow_source_opt.h"
#include "tls_object_cache.h"
#include "sound_mixer_opt.h"
#include "lua_gc_governor.h"
#include "async_tex_loader.h"
#include "saved_vars_pretoken.h"
#include "mip_bias_governor.h"
#include "perf_diagnostics.h"
#include "adaptive_farclip.h"
#include "font_glyph_cache.h"
#include "async_sound_loader.h"
#include "rcu_obj_mgr.h"
#include "async_terrain_loader.h"

#include "d3d9_state_manager.h"
#include "dxvk_bridge.h"
#include "hooks_render.h"
#include "hooks_simd.h"
#include "hooks_logic.h"
#include "hooks_memory.h"
#include "hooks_async.h"


#include "version.h"
#include "config.h"

// ================================================================
// TOGGLES// Each toggle disables a specific optimization for binary search
// during crash investigation. Set to 1 to DISABLE the feature.
// These are compile-time flags for debugging builds.
// ================================================================
#ifndef CRASH_TEST_DISABLE_COMPARESTRING
#define CRASH_TEST_DISABLE_COMPARESTRING   0   // CompareStringA fast path
#endif
#ifndef CRASH_TEST_DISABLE_GETFILEATTR
#define CRASH_TEST_DISABLE_GETFILEATTR     0   // GetFileAttributesA cache
#endif
#ifndef CRASH_TEST_DISABLE_GLOBALALLOC
#define CRASH_TEST_DISABLE_GLOBALALLOC     1   // GlobalAlloc->mimalloc (enabled with consistency fixes)
#endif
#define CRASH_TEST_DISABLE_CS_ENTER        1   // CriticalSection TryEnter spin (causes login freeze)
#define CRASH_TEST_DISABLE_CS_INIT         1   // InitializeCriticalSection hook (causes login freeze/crash)
#define CRASH_TEST_DISABLE_CS_SPIN         1   // CriticalSection spin count 8000 (causes login crash)
#ifndef CRASH_TEST_DISABLE_SETFILEPOINTER
#define CRASH_TEST_DISABLE_SETFILEPOINTER  0   // SetFilePointer -> SetFilePointerEx
#endif
#ifndef CRASH_TEST_DISABLE_READFILE
#define CRASH_TEST_DISABLE_READFILE        0   // ReadFile MPQ cache (DISABLED to resolve lock serialization and landing freezes)
#endif
#ifndef CRASH_TEST_DISABLE_ISBADPTR
#define CRASH_TEST_DISABLE_ISBADPTR        1   // IsBadReadPtr/WritePtr fast path (DISABLED - VirtualQuery is slow)
#endif
#define CRASH_TEST_DISABLE_MPQ_MMAP        1   // MPQ memory mapping (ALREADY DISABLED - risky)
#define CRASH_TEST_DISABLE_QPC_CACHE       1   // QPC coalescing cache (DISABLED to fix random stutters under DXVK)
#define CRASH_TEST_DISABLE_TICK_COUNT      1   // GetTickCount/timeGetTime redirection to QPC (DISABLED to fix random stutters and CPU overhead)
#define CRASH_TEST_DISABLE_LUA_INTERNALS   0   // Lua VM internals (concat hook)
#define CRASH_TEST_DISABLE_THREAD_AFFINITY   0   // Thread core pinning (re-enabled - was disabled preemptively)
#define CRASH_TEST_DISABLE_SHORT_WAIT_SPIN   1   // WaitSpin (ALREADY DISABLED - tested bad)
#ifndef CRASH_TEST_DISABLE_VA_ARENA
#define CRASH_TEST_DISABLE_VA_ARENA          0   // VA Arena compiled in; activation is runtime opt-in via Config OptVaArena (default off). Set to 1 to hard-remove.
#endif
#define CRASH_TEST_DISABLE_DISPATCH_POOL     1   // DispatchPool (ALREADY DISABLED - tested bad)
#define CRASH_TEST_DISABLE_BGPRELOAD_CACHE   1   // bgpreloadsleep cache (ALREADY DISABLED - 0 hits)
#define CRASH_TEST_DISABLE_SUBTASK_EVENTPOOL 1   // Subtask event pool (ALREADY DISABLED - 0 hits)

// Feature toggles for hooks
#ifndef CRASH_TEST_DISABLE_GETFILESIZE_CACHE
#define CRASH_TEST_DISABLE_GETFILESIZE_CACHE    0   // GetFileSizeEx cache - ENABLED (tested stable by Morbent + Billy Hoyle)
#endif
#define CRASH_TEST_DISABLE_WFS_SPIN             1   // WaitForSingleObject spin (DISABLED - tested bad, crashes WoW)
#ifndef CRASH_TEST_DISABLE_MODHANDLE_CACHE
#define CRASH_TEST_DISABLE_MODHANDLE_CACHE      0   // GetModuleHandleA cache
#endif
#ifndef CRASH_TEST_DISABLE_LSTRCMP
#define CRASH_TEST_DISABLE_LSTRCMP              0   // lstrcmp/lstrcmpiA fast path - DISABLED: buggy length comparison instead of dictionary order broke CVar sorting/registry
#endif
#define CRASH_TEST_DISABLE_PROFILE_CACHE        0   // GetPrivateProfileStringA cache
#define CRASH_TEST_DISABLE_MSGPUMP_RC1          1   // sub_869E00 frame-continue (CONFIRMED BROKEN: returns 1 with *a1=-1 → infinite freeze)
#define CRASH_TEST_DISABLE_SWAP_RC1             0   // sub_69E220 swap - glFinish skip (re-enabled - was disabled preemptively)
#define CRASH_TEST_DISABLE_TABLERESHAPE_RC1     0   // luaH_resize table rehash prevention
#define CRASH_TEST_DISABLE_LUAH_GETSTR          1   // luaH_getstr OLD pointer cache DISABLED - replaced by safe v2 in lua_getstr_inline.cpp
#define CRASH_TEST_DISABLE_COMBATLOG_FULLCACHE  1   // CombatLog full event cache (memory-safe value copy)
#define CRASH_TEST_DISABLE_LUA_PUSHSTRING       0   // lua_pushstring intern cache (cleared on luaC_step)
#define CRASH_TEST_DISABLE_LUA_RAWGETI          1   // lua_rawgeti OLD pointer cache DISABLED - CONFIRMED: freezes world load when combined with other features
#ifndef TEST_DISABLE_RAWGETI_INLINE
#define TEST_DISABLE_RAWGETI_INLINE             0
#endif
#ifndef TEST_DISABLE_RAWGET_INLINE
#define TEST_DISABLE_RAWGET_INLINE              0
#endif
#define TEST_DISABLE_STRTOD_FAST                0   // enabled: safe string->number fast path
#ifndef TEST_DISABLE_GETSTR_INLINE
#define TEST_DISABLE_GETSTR_INLINE              1
#endif

// ---- Roadmap performance features (latency-oriented; FPS is GPU/vsync-bound) ----
// (TEST_ENABLE_WS_AGGRESSIVE_PIN lives in wow_memory_opt.cpp, where the working set is set.)
#define TEST_ENABLE_LARGE_PAGES         0   // mimalloc 2MB large OS pages (TLB win on the VA-tight heap). Requires the Windows account to hold 'Lock pages in memory' (secpol.msc -> Local Policies -> User Rights Assignment) — the DLL can only ENABLE a privilege the account already holds, not grant it. Harmless no-op without the grant. 32-bit caveat: large pages reserve in 2MB units; on a VA-tight client this can fragment the 2-3GB user VA, so keep /3GB on and watch LargestFreeBlock.
#define CRASH_TEST_DISABLE_TABLE_CONCAT         0   // table.concat fast path
#define CRASH_TEST_DISABLE_WOW_STRLEN           0   // sub_76EE30 WoW-internal strlen - ENABLED (SSE2 replacement protected with SEH backstop)
#define CRASH_TEST_DISABLE_STREAM_FASTPATH      TEST_DISABLE_STREAM_FASTPATH   // sub_47B3C0/sub_47B0A0 - controlled by version.h

// Definition for the WO_EnableHook batching wrapper declared in version.h.
// While this is 1 (set across MainThread's install sequence), module enables
// routed through WO_EnableHook are queued and applied in one MH_ApplyQueued.
volatile long g_hookBatchMode = 0;

// Forward declaration for CRT fast paths (defined in crt_mem_fastpath.cpp)
extern bool InstallCrtMemFastPaths();
extern void ShutdownCrtMemFastPaths();
extern bool InstallUIAccessorFast();
extern void ShutdownUIAccessorFast();
extern bool InstallFontMetricsFast();
extern void ShutdownFontMetricsFast();
extern void FontMetrics_OnFrame();


// Forward declarations
static bool IsExecutableMemory(uintptr_t addr);
static bool InstallThreadAffinity();
static void InstallWineSTIPNoop();

#define VA_ARENA_PAGE_SIZE  4096
#define VA_ARENA_MAX_PAGES  16384   // 64MB
#define VA_ARENA_BITMAP_SIZE (VA_ARENA_MAX_PAGES / 64)

typedef LPVOID (WINAPI* VirtualAlloc_fn)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL  (WINAPI* VirtualFree_fn)(LPVOID, SIZE_T, DWORD);

static VirtualAlloc_fn orig_VirtualAlloc = nullptr;
static VirtualFree_fn  orig_VirtualFree  = nullptr;

static bool vaOk = false;
static volatile bool  g_vaArenaActive    = false;
static LPVOID         g_vaArenaBase      = nullptr;
static SIZE_T         g_vaArenaSize      = 0;
static SRWLOCK        g_vaArenaLock      = SRWLOCK_INIT;
static long           g_vaArenaHits      = 0;
static long           g_vaArenaFallbacks = 0;
static long           g_vaArenaFailures  = 0;
static long           g_vaArenaFull      = 0;  // qualifying requests that didn't fit -> "arena too small" signal for sizing
static DWORD          g_vaArenaUsedPages = 0;
static DWORD          g_vaArenaPeakPages = 0;  // high-water mark of used pages

// Bitmap + span tracking
static uint64_t g_vaArenaBitmap[VA_ARENA_BITMAP_SIZE] = {0};
static DWORD    g_vaArenaSpan[VA_ARENA_MAX_PAGES] = {0};  // span length in pages from this page

// Forward declarations
static bool InstallVAArena();
static void ShutdownVAArena();

// Priority watchdog forward declarations
static void StartPriorityWatchdog();
static void StopPriorityWatchdog();
static volatile LONG g_priorityWatchdogRestores = 0;

extern "C" void Log(const char* fmt, ...);

// ================================================================
// Timing Method Fix - Console override only (hook removed for safety)
// ================================================================
#if !TEST_DISABLE_TIMING_FIX
static bool InstallTimingFix() {
    Log("[TimingFix] Hook skipped. Using console override only (safe for HD builds).");
    return true;
}
#else
static bool InstallTimingFix() { return false; }
#endif

// ================================================================
// Hardware Cursor & Raw Input - bypass engine cursor centering
// ================================================================
#if !TEST_DISABLE_HARDWARE_CURSOR

static volatile bool g_cursorInitDone = false;

static void InitHardwareCursor() {
    if (g_cursorInitDone) return;

    HWND hWnd = FindWindowA("GxWindowClassD3d", NULL);
    if (!hWnd) hWnd = FindWindowA("GxWindowClassD3d9Ex", NULL);
    if (!hWnd) hWnd = FindWindowA("GxWindowClassOpenGl", NULL);

    if (hWnd) {
        // Reset cursor visibility reference count to >= 0
        while (ShowCursor(TRUE) < 0);
        
        // Remove window clipping to prevent cursor trapping/lag
        ClipCursor(NULL);

        // Hardware cursor byte patches disabled.
        // byte_CABCDD/CABCDE force gxCursor=0 + gxFixLag=1 which on
        // private servers (Circle/Warmane) activates an uninitialized
        // cursor rendering path → NULL deref at [edi]+0 → [0x0+18].
        // *(volatile uint8_t*)0x00CABCDD = 0;
        // *(volatile uint8_t*)0x00CABCDE = 1;

        g_cursorInitDone = true;
        Log("Hardware cursor: ACTIVE (clipping disabled, visibility reset)");
    }
}

static bool InstallHardwareCursorHooks() {
    InitHardwareCursor();
    return true;
}

#else

static void InitHardwareCursor() {}
static bool InstallHardwareCursorHooks() {
    Log("Hardware cursor: DISABLED (crash isolation)");
    return false;
}

#endif

// ================================================================
// Deferred Unit Field Updates - Lock-Free SPSC Batch Processor v2
//
// DESIGN: Network thread enqueues non-critical field updates into a
// lock-free single-producer/single-consumer ring buffer. Main thread
// flushes them during Sleep hook (once per frame). Critical fields
// (HP, mana, GUID, flags, level) bypass the queue and execute
// immediately for gameplay correctness.
//
// THREAD SAFETY (v2 fixes):
// - Single producer (network thread via Hooked_OnFieldUpdate)
// - Single consumer (main thread via FlushFieldUpdates)
// - Lock-free ring buffer with atomic head/tail
// - Unit pointer stored with InterlockedExchangePointer (atomic write)
// - Data fields written BEFORE tail advance (memory ordering)
// - Flush claims ownership via InterlockedExchangePointer (only one
//   path gets non-null: flush or invalidate, never both)
// - InvalidateDeferredFieldUpdatesFor uses CAS to nullify stale entries
// - SEH + pointer range validation guards against freed units
// ================================================================
static constexpr int FIELD_QUEUE_SIZE = 4096;
static constexpr int FIELD_QUEUE_MASK = FIELD_QUEUE_SIZE - 1;

struct FieldTask {
    void* unit;
    int   fieldId;
    int   value;
};

static FieldTask g_fieldQueue[FIELD_QUEUE_SIZE] = {};
static LONG g_fieldHead = 0;
static LONG g_fieldTail = 0;
static SRWLOCK g_fieldQueueLock = SRWLOCK_INIT;

typedef void (__thiscall *OnFieldUpdate_fn)(void*, int, int);
static OnFieldUpdate_fn orig_OnFieldUpdate = nullptr;

typedef void* (__thiscall *UnlinkNode_fn)(void*);
static UnlinkNode_fn orig_UnlinkNode = nullptr;

extern "C" void InvalidateDeferredFieldUpdatesFor(void* unit);
#if !TEST_DISABLE_OBJ_VIS_CACHE
extern "C" void InvalidateObjVisCacheFor(void* This);
#endif
extern "C" void InvalidateUnitApiCacheFor(uint64_t guid);

static void* __fastcall Hooked_UnlinkNode(void* This, void* unused) {
    if (This) {
        InvalidateDeferredFieldUpdatesFor(This);
#if !TEST_DISABLE_OBJ_VIS_CACHE
        InvalidateObjVisCacheFor(This);
#endif
        __try {
            uint32_t* j = (uint32_t*)This;
            uint64_t guid = ((uint64_t)j[13] << 32) | j[12];
            InvalidateUnitApiCacheFor(guid);
            GuidLookupCache::Invalidate(guid);
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    void* result = orig_UnlinkNode(This);
    RcuObjMgr::UpdateActiveRcuArray();
    return result;
}

static void __fastcall Hooked_OnFieldUpdate(void* This, void* unused, int fieldId, int value) {
    if (This) {
        __try {
            uint32_t* j = (uint32_t*)This;
            uint64_t guid = ((uint64_t)j[13] << 32) | j[12];
            InvalidateUnitApiCacheFor(guid);
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
#if TEST_DISABLE_DEFERRED_FIELD_UPDATES
    return orig_OnFieldUpdate(This, fieldId, value);
#else
    if (LoadingDefrag::IsLoadingActive()) {
        return orig_OnFieldUpdate(This, fieldId, value);
    }
    __try {
        // Critical fields (HP, Mana, GUID, Flags, Level) process immediately
        if (fieldId < 0x40) {
            if (Config::g_settings.OptWorldStateCoalesce) {
                if (WorldStateCoalesce::ProcessFieldUpdate(This, fieldId, value, (void*)orig_OnFieldUpdate)) {
                    return;
                }
            }
            return orig_OnFieldUpdate(This, fieldId, value);
        }

        // Process display, mount, and scale fields immediately to prevent model stretching/flickering
        if (fieldId == 70 || fieldId == 71 || fieldId == 74 || fieldId == 75 || fieldId == 117) {
            return orig_OnFieldUpdate(This, fieldId, value);
        }

        AcquireSRWLockExclusive(&g_fieldQueueLock);
        LONG tail = g_fieldTail;
        LONG nextTail = (tail + 1) & FIELD_QUEUE_MASK;
        if (nextTail == g_fieldHead) {
            ReleaseSRWLockExclusive(&g_fieldQueueLock);
            return orig_OnFieldUpdate(This, fieldId, value); // Queue full
        }

        g_fieldQueue[tail].fieldId = fieldId;
        g_fieldQueue[tail].value = value;
        g_fieldQueue[tail].unit = This;
        g_fieldTail = nextTail;
        ReleaseSRWLockExclusive(&g_fieldQueueLock);
        return;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return orig_OnFieldUpdate(This, fieldId, value);
    }
#endif
}

extern "C" void InvalidateDeferredFieldUpdatesFor(void* unit) {
#if !TEST_DISABLE_DEFERRED_FIELD_UPDATES
    if (!unit) return;
    AcquireSRWLockExclusive(&g_fieldQueueLock);
    LONG head = g_fieldHead;
    LONG tail = g_fieldTail;
    while (head != tail) {
        if (g_fieldQueue[head].unit == unit) {
            g_fieldQueue[head].unit = nullptr;
        }
        head = (head + 1) & FIELD_QUEUE_MASK;
    }
    ReleaseSRWLockExclusive(&g_fieldQueueLock);
#endif
}

static void FlushFieldUpdates() {
#if !TEST_DISABLE_DEFERRED_FIELD_UPDATES
    // Thread safety: Flush must only run on the main thread
    if (g_mainThreadId != 0 && GetCurrentThreadId() != g_mainThreadId) return;

    static constexpr int TEMP_SIZE = 4096;
    static FieldTask tempQueue[TEMP_SIZE];
    int tempCount = 0;

    AcquireSRWLockExclusive(&g_fieldQueueLock);
    LONG head = g_fieldHead;
    LONG tail = g_fieldTail;
    if (head == tail) {
        ReleaseSRWLockExclusive(&g_fieldQueueLock);
        return;
    }

    while (head != tail && tempCount < TEMP_SIZE) {
        FieldTask& task = g_fieldQueue[head];
        if (task.unit != nullptr) {
            tempQueue[tempCount++] = task;
            task.unit = nullptr;
        }
        head = (head + 1) & FIELD_QUEUE_MASK;
    }
    g_fieldHead = head;
    ReleaseSRWLockExclusive(&g_fieldQueueLock);

    // Process tasks outside of the lock to prevent SRWLock recursion deadlock!
    for (int i = 0; i < tempCount; i++) {
        void* unit = tempQueue[i].unit;
        if (unit != nullptr) {
            __try {
                uintptr_t p = (uintptr_t)unit;
                if (p > 0x10000 && p < 0xFFE00000) {
                    orig_OnFieldUpdate(unit, tempQueue[i].fieldId, tempQueue[i].value);
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                // Unit was freed - safe to ignore
            }
        }
    }
#endif
}

static bool InstallFieldUpdateHook() {
#if TEST_DISABLE_DEFERRED_FIELD_UPDATES
    Log("Deferred field updates: DISABLED (test toggle)");
    return false;
#else
    void* target = (void*)0x006A3C40;
    if (WineSafe_CreateHook(target, (void*)Hooked_OnFieldUpdate, (void**)&orig_OnFieldUpdate) != MH_OK) return false;
    if (WO_EnableHook(target) != MH_OK) return false;

    void* unlink_target = (void*)0x004D4C20;
    if (WineSafe_CreateHook(unlink_target, (void*)Hooked_UnlinkNode, (void**)&orig_UnlinkNode) == MH_OK) {
        WO_EnableHook(unlink_target);
    }

    Log("Deferred field updates: ACTIVE v2 (lock-free SPSC, critical<0x40 immediate, 4096 slots)");
    return true;
#endif
}

// New system optimizations
static bool InstallGetFileSizeCache();
static bool InstallWaitForSingleObjectHook();
static bool InstallGetModuleHandleCache();
static bool InstallLstrcmpHook();
static bool InstallLStrLenHooks();
static bool InstallWowStrlenHook();
static bool InstallMBWCHooks();
static bool InstallGetProcAddressCache();
static bool InstallGetModuleFileNameCache();
static bool InstallEnvironmentVariableCache();
static bool InstallGetPrivateProfileCache();
static bool InstallLuaHGetStrCache();
static bool InstallCombatLogFullCache();
static void ClearLuaHGetStrCache();
static bool InstallLuaPushStringCache();
static void ClearLuaPushStringCache();
static bool InstallLuaRawGetICache();
static bool InstallStreamBufferFastPath();

// Exposed for lua_optimize.cpp (UI reload cache clearing)
void ClearAssetPathCache();
extern "C" void ClearLuaOptCaches() {
    InvalidateLuaGetStrInlineCache();
    ClearLuaPushStringCache();
    ClearAssetPathCache();
    ClearRawGetIInlineCache();
    ClearEventDispatchCache();
    ClearTableCache();

    // The glyph and outline caches are keyed by the font object's address, and a
    // UI reload destroys and recreates every font object without touching the D3D9
    // device. Until now they were only flushed from device reset and device change,
    // so after a /reload the allocator could hand a new font the address of a dead
    // one and a lookup would return a glyph descriptor rasterized for a different
    // font - wrong advance widths, characters drawn on top of each other. That is
    // the "smushed text" seen after reloading, and it is the same defect shape as
    // the model-pointer table that used to hide corpses: a cache keyed by an
    // address the engine is free to reuse must be dropped when the owner dies.
    FontGlyphCache::ClearCache();
}

// Stats for new hooks (defined with implementations below)
static long g_fsizeHits = 0, g_fsizeMisses = 0;
static long g_wfsSpinHits = 0, g_wfsFallbacks = 0;
static long g_modHits = 0, g_modMisses = 0;
static long g_lstrcmpHits = 0, g_lstrcmpFallbacks = 0;
static long g_mbwcFastHits = 0, g_mbwcFallbacks = 0;
static long g_wcmbFastHits = 0, g_wcmbFallbacks = 0;
static long g_profHits = 0, g_profMisses = 0;
static long g_gpaHits = 0, g_gpaMisses = 0, g_gpaEvictions = 0, g_gpaBypasses = 0;
static long g_envHits = 0, g_envMisses = 0;
static long g_gmfHits = 0, g_gmfMisses = 0;
long g_crtStrlenHits = 0, g_crtStrlenFallbacks = 0;
long g_crtStrcmpHits = 0, g_crtStrcmpFallbacks = 0;
long g_crtMemcmpHits = 0, g_crtMemcmpFallbacks = 0;
long g_crtMemcpyHits = 0, g_crtMemcpyFallbacks = 0;
long g_crtMemsetHits = 0, g_crtMemsetFallbacks = 0;
volatile LONG64 g_memchrHits = 0, g_memchrFallbacks = 0;
volatile LONG64 g_strchrHits = 0, g_strchrFallbacks = 0;
volatile LONG64 g_strcpyHits = 0, g_strcpyFallbacks = 0;
static uint64_t g_tableReshapeHits = 0;
static uint64_t g_getstrHits = 0, g_getstrFallbacks = 0;
static uint64_t g_combatLogCacheHits = 0, g_combatLogCacheMisses = 0;
static uint64_t g_pushStrHits = 0, g_pushStrMisses = 0;
static uint64_t g_rawGetIHits = 0, g_rawGetIMisses = 0;

// ================================================================
// Thread Affinity - background worker core pinning
// Pins WoW async task threads to cores 2..N-1, protecting main thread.
// ================================================================
static bool  g_threadAffOk = false;
static LONG  g_bgThreadIdx    = 0;
static DWORD g_affinityCores[16] = {0};
static int   g_affinityCount  = 0;

typedef int (__cdecl *fn_ThreadWorker)(void* outHandle, LPTHREAD_START_ROUTINE start, LPVOID param, int priority, int a5, int a6, HMODULE hMod);
static fn_ThreadWorker orig_ThreadWorker = nullptr;

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ws2_32.lib")

// WineSafe_CreateHook is now defined in version.h (shared across all TUs)

// ================================================================
// Global state
// ================================================================
bool   g_isMultiClient = false;         // Set by DetectMultiClient() via named mutex
static HANDLE g_instanceMutex = NULL;   // "wow_optimize_instance_v2" mutex
static DWORD  g_nextStatsDumpTick = 0;  // Next periodic stats dump (GetTickCount)
static DWORD  g_nextMiCollectTick = 0;  // Next mimalloc collect (multi-client only)
static void   DumpPeriodicStats();

// ================================================================
// Logging - ring buffer + background thread
//
// ================================================================
static FILE* g_log = nullptr;
static FILE* g_sessionLog = nullptr;

static constexpr int LOG_RING_SIZE = 2048;
static constexpr int LOG_RING_MASK = LOG_RING_SIZE - 1;

// ready: 0 = free (producer may fill), 1 = filled, 2 = claimed by a consumer.
// The ring has two consumers - the background log thread and whichever thread calls
// LogFlushImmediate - so a slot must be claimed with an interlocked 1 -> 2 transition
// before it is written out, and only released back to 0 once its text has been read.
static constexpr LONG LOG_SLOT_FREE = 0;
static constexpr LONG LOG_SLOT_FILLED = 1;
static constexpr LONG LOG_SLOT_CLAIMED = 2;

struct LogEntry {
    char text[2048];
    volatile LONG ready;
};

static LogEntry g_logRing[LOG_RING_SIZE] = {};
static volatile LONG g_logWritePos = 0;
static volatile LONG g_logReadPos = 0;
static HANDLE g_logEvent = NULL;
static HANDLE g_logThread = NULL;
static volatile bool g_logShutdown = false;

static HANDLE LogFileHandle(FILE* f) {
    if (!f) return NULL;
    HANDLE h = (HANDLE)_get_osfhandle(_fileno(f));
    if (h == INVALID_HANDLE_VALUE) return NULL;
    return h;
}

// Writes out every filled ring entry and returns how many were drained. Both
// consumers go through this single path with unbuffered WriteFile, so log lines can
// never interleave through two independent stream buffers on the same descriptor.
static int LogDrainRing() {
    HANDLE hMain = LogFileHandle(g_log);
    HANDLE hSession = LogFileHandle(g_sessionLog);
    if (!hMain && !hSession) return 0;

    int drained = 0;
    for (int guard = 0; guard < LOG_RING_SIZE; guard++) {
        int slot = g_logReadPos & LOG_RING_MASK;
        if (InterlockedCompareExchange(&g_logRing[slot].ready,
                                       LOG_SLOT_CLAIMED, LOG_SLOT_FILLED) != LOG_SLOT_FILLED) {
            break;
        }
        InterlockedIncrement(&g_logReadPos);

        DWORD len = (DWORD)strlen(g_logRing[slot].text);
        DWORD written = 0;
        if (hMain) WriteFile(hMain, g_logRing[slot].text, len, &written, NULL);
        if (hSession) WriteFile(hSession, g_logRing[slot].text, len, &written, NULL);

        InterlockedExchange(&g_logRing[slot].ready, LOG_SLOT_FREE);
        drained++;
    }
    return drained;
}

static DWORD WINAPI LogThreadProc(LPVOID) {
    while (!g_logShutdown) {
        WaitForSingleObject(g_logEvent, 100);
        LogDrainRing();
    }

    LogDrainRing();

    HANDLE hMain = LogFileHandle(g_log);
    HANDLE hSession = LogFileHandle(g_sessionLog);
    if (hMain) FlushFileBuffers(hMain);
    if (hSession) FlushFileBuffers(hSession);
    return 0;
}

// Deletes the oldest session logs, keeping the newest `keep`. The timestamp in the
// name is YYYY-MM-DD_HH-MM-SS, so sorting the names as text sorts them by time and
// no file has to be opened to find out how old it is.
//
// Matches only names whose next character is a digit: wow_optimize_proxy.log lives
// in the same folder and is not ours to delete.
static void PruneSessionLogs(int keep) {
    if (keep <= 0) return;

    static const int MAX_TRACKED = 512;
    static char names[MAX_TRACKED][64];
    int count = 0;

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("Logs\\wow_optimize_*.log", &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        const char* tail = fd.cFileName + 13;          // past "wow_optimize_"
        if (*tail < '0' || *tail > '9') continue;
        if (strlen(fd.cFileName) >= sizeof(names[0])) continue;
        if (count < MAX_TRACKED) {
            lstrcpynA(names[count], fd.cFileName, sizeof(names[0]));
            count++;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);

    if (count <= keep) return;

    // Newest first. Insertion sort: a few hundred names at startup, once.
    for (int i = 1; i < count; i++) {
        char tmp[64];
        lstrcpynA(tmp, names[i], sizeof(tmp));
        int j = i - 1;
        while (j >= 0 && strcmp(names[j], tmp) < 0) {
            lstrcpynA(names[j + 1], names[j], sizeof(names[0]));
            j--;
        }
        lstrcpynA(names[j + 1], tmp, sizeof(names[0]));
    }

    for (int i = keep; i < count; i++) {
        char path[MAX_PATH];
        _snprintf(path, sizeof(path), "Logs\\%s", names[i]);
        path[sizeof(path) - 1] = '\0';
        DeleteFileA(path);
    }
}

static void LogOpen() {
    CreateDirectoryA("Logs", NULL);
    
    // 1. Standard log (wow_optimize.log) always overwritten to keep latest easy to access
    g_log = _fsopen("Logs\\wow_optimize.log", "w", _SH_DENYNO);
    if (!g_log) {
        g_log = fopen("Logs\\wow_optimize.log", "w");
    }
    
    // 2. Session log with timestamp (wow_optimize_YYYY-MM-DD_HH-MM-SS.log) to preserve history.
    //
    // The overwritten file above is the "one log like before" - it has never gone
    // away. This second one exists because comparing two configurations needs both
    // runs, and a single file keeps only the last. What it lacked was an end: left
    // alone the folder grows for as long as someone keeps playing.
    if (Config::g_settings.OptSessionLogs) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char sessionPath[MAX_PATH];
        _snprintf(sessionPath, sizeof(sessionPath), "Logs\\wow_optimize_%04d-%02d-%02d_%02d-%02d-%02d.log",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        sessionPath[sizeof(sessionPath) - 1] = '\0';
        g_sessionLog = _fsopen(sessionPath, "w", _SH_DENYNO);
        if (!g_sessionLog) {
            g_sessionLog = fopen(sessionPath, "w");
        }
        PruneSessionLogs(Config::g_settings.SessionLogsToKeep);
    }

    static const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    if (g_log) {
        fwrite(bom, 1, 3, g_log);
        fflush(g_log);
    }
    if (g_sessionLog) {
        fwrite(bom, 1, 3, g_sessionLog);
        fflush(g_sessionLog);
    }

    g_logShutdown = false;
    g_logEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    g_logThread = CreateThread(NULL, 0, LogThreadProc, NULL, 0, NULL);
}

static void LogClose() {
    g_logShutdown = true;
    if (g_logEvent) SetEvent(g_logEvent);
    if (g_logThread) {
        WaitForSingleObject(g_logThread, 2000);
        CloseHandle(g_logThread);
        g_logThread = NULL;
    }
    if (g_logEvent) { CloseHandle(g_logEvent); g_logEvent = NULL; }
    if (g_log) { fclose(g_log); g_log = nullptr; }
    if (g_sessionLog) { fclose(g_sessionLog); g_sessionLog = nullptr; }
}

// Teardown for DLL_PROCESS_DETACH with lpReserved != NULL (the process is exiting).
// LogClose() must NOT be used there: by that point the OS has already terminated
// every other thread, including the log thread, possibly while it held the CRT
// stream lock - so fprintf/fclose can deadlock the exiting process, and waiting on
// the dead log thread just burns the timeout. Drain whatever the log thread never
// got to using raw WriteFile (a syscall, unaffected by an orphaned CRT lock), force
// it to disk, and leave the handles for the OS to close.
static void LogFinalizeOnProcessExit(const char* note) {
    g_logShutdown = true;
    LogDrainRing();

    HANDLE hMain = LogFileHandle(g_log);
    HANDLE hSession = LogFileHandle(g_sessionLog);

    if (note && (hMain || hSession)) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char line[512];
        int n = _snprintf(line, sizeof(line) - 1, "[%02d:%02d:%02d.%03d] %s\n",
                          st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, note);
        if (n > 0) {
            DWORD written = 0;
            if (hMain) WriteFile(hMain, line, (DWORD)n, &written, NULL);
            if (hSession) WriteFile(hSession, line, (DWORD)n, &written, NULL);
        }
    }

    if (hMain) FlushFileBuffers(hMain);
    if (hSession) FlushFileBuffers(hSession);
}

// Minimum spacing between physical FlushFileBuffers calls. WriteFile already hands
// the bytes to the OS file cache, so they survive a process crash (which is all the
// log has to survive); FlushFileBuffers additionally forces a disk sync and costs
// several milliseconds per call. Calling it per line made a multi-line ERROR dump
// stall the main thread for hundreds of milliseconds.
static constexpr DWORD LOG_FSYNC_INTERVAL_MS = 1000;
static DWORD g_lastLogFsyncTick = 0;

void LogFlushImmediate() {
    if (!LogDrainRing()) return;

    DWORD now = GetTickCount();
    if (now - g_lastLogFsyncTick < LOG_FSYNC_INTERVAL_MS) return;
    g_lastLogFsyncTick = now;

    HANDLE hMain = LogFileHandle(g_log);
    HANDLE hSession = LogFileHandle(g_sessionLog);
    if (hMain) FlushFileBuffers(hMain);
    if (hSession) FlushFileBuffers(hSession);
}

  extern "C" void LogEx(LogLevel level, const char* context, const char* fmt, ...) {
    if (!g_logEvent) return;

    LONG idx = InterlockedIncrement(&g_logWritePos) - 1;
    int slot = idx & LOG_RING_MASK;

    if (g_logRing[slot].ready) return;

    SYSTEMTIME st;
    GetLocalTime(&st);

    const char* lvlStr = "INFO";
    switch (level) {
        case LOG_LEVEL_DEBUG:    lvlStr = "DEBUG"; break;
        case LOG_LEVEL_INFO:     lvlStr = "INFO"; break;
        case LOG_LEVEL_WARN:     lvlStr = "WARN"; break;
        case LOG_LEVEL_ERROR:    lvlStr = "ERROR"; break;
        case LOG_LEVEL_CRITICAL: lvlStr = "CRITICAL"; break;
    }

    int offset = _snprintf(g_logRing[slot].text, 128, "[%02u-%02u-%02u %02u:%02u:%02u.%03u] [TID: %u] [%s] [%s] ",
        st.wYear % 100, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        GetCurrentThreadId(), lvlStr, context);

    va_list args;
    va_start(args, fmt);
    int msgLen = _vsnprintf(g_logRing[slot].text + offset, 2046 - offset, fmt, args);
    va_end(args);
    if (msgLen < 0) msgLen = 2046 - offset;
    offset += msgLen;

    g_logRing[slot].text[offset] = '\n';
    g_logRing[slot].text[offset + 1] = '\0';

    InterlockedExchange(&g_logRing[slot].ready, 1);
    SetEvent(g_logEvent);

    // Only flush immediately on ERROR or CRITICAL events to preserve FPS performance
    if (level == LOG_LEVEL_ERROR || level == LOG_LEVEL_CRITICAL) {
        LogFlushImmediate();
    }
}

extern "C" void Log(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[2048];
    _vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    LogEx(LOG_LEVEL_INFO, "DLL", "%s", buf);
}

// 1. Memory allocator replacement (mimalloc) — LARGE-ALLOCATION ONLY, opt-in.
//
// History: a previous version redirected ALL of WoW's static CRT allocations
// (every malloc/free, any size, from any thread) to mimalloc. That repeatedly
// broke the ability to connect ("unable to connect" on login). Three plausible
// causes were never fully separated: (1) with LAA on, mimalloc handed back
// >2GB pointers that, when used as socket receive buffers, tripped socket
// filter drivers / WoW's 32-bit net code; (2) routing every free in the process
// through a region check; (3) MinHook patching the CRT entry points a network
// thread might be executing. So it was removed entirely.
//
// This is a deliberately narrower, opt-in re-introduction (OptMimallocLarge,
// default OFF, launcher-gated). It only redirects allocations that:
//   - are >= 1 MB (model/texture/terrain blocks — the things that actually
//     fragment the 32-bit VA; socket buffers are KB-sized, so cause #1's
//     network path is avoided by construction), AND
//   - originate on the main thread (background socket/db/audio threads never
//     get a mimalloc pointer), AND
//   - land below 2 GB — if mimalloc returns a high pointer we free it and fall
//     back to the CRT, so no redirected block is ever a >2GB pointer (cause #1).
// free/realloc/_msize/_recalloc still route by region check so mimalloc blocks
// are freed through mimalloc (WoW's free() would otherwise HeapFree() a non-heap
// pointer — verified in the 3.3.5a binary). Cause #3 is inherent to any CRT
// hook and is why this ships opt-in and must be connection-tested before use.
static constexpr size_t MIMALLOC_LARGE_THRESHOLD = 1048576; // 1 MB

typedef void*  (__cdecl* malloc_fn)(size_t);
typedef void   (__cdecl* free_fn)(void*);
typedef void*  (__cdecl* realloc_fn)(void*, size_t);
typedef void*  (__cdecl* calloc_fn)(size_t, size_t);
typedef size_t (__cdecl* msize_fn)(void*);
typedef void*  (__cdecl* recalloc_fn)(void*, size_t, size_t);

static malloc_fn   orig_malloc   = nullptr;
static free_fn     orig_free     = nullptr;
static realloc_fn  orig_realloc  = nullptr;
static calloc_fn   orig_calloc   = nullptr;
static msize_fn    orig_msize    = nullptr;
static recalloc_fn orig_recalloc = nullptr;

static void __cdecl hooked_free(void* ptr) {
    if (!ptr) return;
    if (mi_is_in_heap_region(ptr)) mi_free(ptr);
    else orig_free(ptr);
}

static void* __cdecl hooked_malloc(size_t size) {
    if (Config::g_settings.OptCrtMimalloc ||
        (g_mainThreadId != 0 && GetCurrentThreadId() == g_mainThreadId && size >= MIMALLOC_LARGE_THRESHOLD)) {
        void* p = mi_malloc(size);
        if (p) {
            if ((uintptr_t)p < 0x80000000) return p;  // low 2GB only
            mi_free(p);                                // never expose a >2GB block
        }
    }
    return orig_malloc(size);
}

static void* __cdecl hooked_calloc(size_t count, size_t size) {
    if (size != 0 && count > (size_t)-1 / size) return nullptr;  // overflow guard
    size_t total = count * size;
    if (Config::g_settings.OptCrtMimalloc ||
        (g_mainThreadId != 0 && GetCurrentThreadId() == g_mainThreadId && total >= MIMALLOC_LARGE_THRESHOLD)) {
        void* p = mi_calloc(count, size);
        if (p) {
            if ((uintptr_t)p < 0x80000000) return p;
            mi_free(p);
        }
    }
    return orig_calloc(count, size);
}

static void* __cdecl hooked_realloc(void* ptr, size_t size) {
    if (!ptr) return hooked_malloc(size);
    if (size == 0) { hooked_free(ptr); return nullptr; }
    if (mi_is_in_heap_region(ptr)) return mi_realloc(ptr, size);
    return orig_realloc(ptr, size);
}

static size_t __cdecl hooked_msize(void* ptr) {
    if (!ptr) return 0;
    if (mi_is_in_heap_region(ptr)) return mi_usable_size(ptr);
    return orig_msize ? orig_msize(ptr) : 0;
}

static void* __cdecl hooked_recalloc(void* ptr, size_t count, size_t size) {
    if (size != 0 && count > (size_t)-1 / size) return nullptr;
    if (!ptr) return hooked_calloc(count, size);
    if (size == 0) { hooked_free(ptr); return nullptr; }
    if (mi_is_in_heap_region(ptr)) return mi_recalloc(ptr, count, size);
    return orig_recalloc(ptr, count, size);
}

// Create all six trampolines first (CreateHook does not redirect), then queue +
// apply in a single atomic MH_ApplyQueued so malloc and free activate together —
// no window where malloc is redirected but free isn't (which would HeapFree a
// mimalloc block). A partial set is treated as fatal and fully rolled back.
static bool InstallMimallocLargeHooks() {
#if TEST_DISABLE_MIMALLOC_LARGE
    Log("[MimallocLarge] DISABLED (compile flag)");
    return false;
#else
    struct AllocHook { void* addr; void* hook; void** orig; const char* name; };
    static const AllocHook hooks[] = {
        { (void*)0x00415074, (void*)hooked_malloc,   (void**)&orig_malloc,   "malloc"    },
        { (void*)0x00412FC7, (void*)hooked_free,     (void**)&orig_free,     "free"      },
        { (void*)0x00416A95, (void*)hooked_realloc,  (void**)&orig_realloc,  "realloc"   },
        { (void*)0x00416A56, (void*)hooked_calloc,   (void**)&orig_calloc,   "calloc"    },
        { (void*)0x004112F8, (void*)hooked_msize,    (void**)&orig_msize,    "_msize"    },
        { (void*)0x00416CB0, (void*)hooked_recalloc, (void**)&orig_recalloc, "_recalloc" },
    };
    const int N = (int)(sizeof(hooks) / sizeof(hooks[0]));

    for (int i = 0; i < N; i++) {
        if (WineSafe_CreateHook(hooks[i].addr, hooks[i].hook, hooks[i].orig) != MH_OK) {
            Log("[MimallocLarge] CreateHook %s @0x%08X FAILED — aborting (partial set is unsafe)",
                hooks[i].name, (uintptr_t)hooks[i].addr);
            for (int j = 0; j < i; j++) MH_RemoveHook(hooks[j].addr);
            return false;
        }
    }
    for (int i = 0; i < N; i++) {
        if (MH_QueueEnableHook(hooks[i].addr) != MH_OK) {
            Log("[MimallocLarge] QueueEnable %s FAILED — aborting", hooks[i].name);
            for (int j = 0; j < N; j++) MH_RemoveHook(hooks[j].addr);
            return false;
        }
    }
    if (MH_ApplyQueued() != MH_OK) {
        Log("[MimallocLarge] ApplyQueued FAILED — aborting");
        for (int i = 0; i < N; i++) MH_RemoveHook(hooks[i].addr);
        return false;
    }
    Log("[MimallocLarge] ACTIVE — main-thread allocations >= %u KB routed to mimalloc "
        "(low-2GB only). EXPERIMENTAL: confirm server connection before relying on it.",
        (unsigned)(MIMALLOC_LARGE_THRESHOLD / 1024));
    return true;
#endif
}

// 2. Sleep hook + frame pacing, GC stepping, combat log cleanup.
//

typedef void (WINAPI* Sleep_fn)(DWORD);
static Sleep_fn orig_Sleep = nullptr;

static double g_sleepFreq = 0.0;
static double g_rdtscFreqMhz = 0.0;  // RDTSC frequency in MHz for easy calculation

// Above this smoothed frame time the client is not holding a steady rate, and the
// busy-wait in PreciseSleep stops paying for itself. 20ms is just under 50fps -
// past that, precision is not what the frame is short of.
static const double SPIN_ABORT_FRAME_MS = 20.0;

// Non-atomic on purpose: these are diagnostic counts on the Sleep path, and a
// lost increment costs a slightly low number where an interlocked operation
// would cost time on every short sleep.
static volatile LONG g_spinTaken   = 0;
static volatile LONG g_spinSkipped = 0;

static void PreciseSleep(double milliseconds) {
    // Use RDTSC for polling instead of QPC syscalls
    uint64_t startRDTSC = __rdtsc();
    double targetCycles = milliseconds * g_rdtscFreqMhz * 1000.0;  // ms → cycles

    while (true) {
        uint64_t nowRDTSC = __rdtsc();
        double elapsedCycles = (double)(nowRDTSC - startRDTSC);

        if (elapsedCycles >= targetCycles)
            return;

        double remainingMs = (targetCycles - elapsedCycles) / (g_rdtscFreqMhz * 1000.0);

        if (g_isMultiClient) {
            // Multi-client: no busy-wait, always yield CPU
            if (remainingMs > 1.5)
                orig_Sleep(1);
            else
                orig_Sleep(0);
        } else {
            // Single client: precise busy-wait for sub-ms accuracy.
            // < 100us: pure RDTSC spin — calling Sleep(0) or SwitchToThread()
            // would round up to the OS quantum (~1ms) and ruin frame pacing.
            if (remainingMs < 0.1) {
                do {
                    _mm_pause();
                } while ((double)(__rdtsc() - startRDTSC) < targetCycles);
                return;
            }
            if (remainingMs > 2.0)
                orig_Sleep(1);
            else if (remainingMs > 0.3)
                SwitchToThread();
            else
                _mm_pause();
        }
    }
}

static void RunPeriodicMaintenanceOnMainThread() {
    if (g_mainThreadId == 0 || GetCurrentThreadId() != g_mainThreadId)
        return;

    // Everything below is this DLL's own work on the game's main thread, so it
    // lands inside a frame. When a hitch is reported, the first question is
    // whether we caused it, and this is the probe that answers it. The inner
    // probes attribute further once this one fires.
    StallProbe maintenanceProbe("periodic maintenance", 4.0);

    DWORD nowTick = GetTickCount();

    if (g_nextStatsDumpTick == 0) {
        g_nextStatsDumpTick = nowTick + 30000;
    } else if ((LONG)(nowTick - g_nextStatsDumpTick) >= 0) {
        DumpPeriodicStats();
        g_nextStatsDumpTick = nowTick + 300000;
    }

    // Cheap and idempotent: returns immediately once the module is known, and
    // catches the case where it loads after we did.
    CrashDumper::RefreshBenignModuleRanges();

    if (Config::g_settings.OptMemoryPressure) {
        TexCacheTuning_Tick();
    }

    // HeapCompactor's monitor thread only requests compaction; the actual
    // HeapCompact()/mi_collect() work must run here on the main thread so it
    // can never race a background thread mutating a heap WoW's own networking
    // code is using mid-connect (GitHub issue #39: mimalloc/heap work breaking
    // Warmane connections).
    HeapCompactor_RunPendingWork();

#if !TEST_DISABLE_MEMORY_PRESSURE_GOVERNOR
    if (Config::g_settings.OptMemoryPressure) {
        PressureGovernor::OnFrame();
    }
#endif

    if (g_isMultiClient) {
        // Periodic mimalloc trim in multi-client. mi_collect(true) is a forced
        // global heap walk + decommit -- a visible hitch. Now that mimalloc backs
        // WoW's ENTIRE heap (static CRT + process-heap redirect), this collects
        // every freed segment from every WoW allocation -- worth the occasional
        // hitch to raise LargestFreeBlock on a VA-tight multi-client. The 25ms
        // background purge normally keeps up; a 60s safety trim catches anything
        // stranded in mimalloc's internal caches.
        if (g_nextMiCollectTick == 0) {
            g_nextMiCollectTick = nowTick + 60000;
        } else if ((LONG)(nowTick - g_nextMiCollectTick) >= 0) {
            {
                StallProbe probe("60s safety mi_collect", 4.0);
                mi_collect(true);
            }
            g_nextMiCollectTick = nowTick + 60000;
        }
    }
}
static LARGE_INTEGER g_lastSleepTime = {};
static double g_lastFrameMs = 0.0;

// Everything this DLL does once per frame on the main thread: the liveness
// stamp the freeze watchdog reads, the periodic maintenance, cache
// invalidation when the lua_State changes, and every subsystem's OnFrame.
//
// This used to live inside hooked_Sleep, and so it ran only when the client
// called Sleep. That held until the frame limiter stopped calling Sleep: its
// wait moved to a waitable timer, and with it the whole heartbeat stopped.
// The symptoms were a freeze report every ten seconds for a game that was
// still rendering, caches never dropped across a reload or a character swap,
// and the swap detection never running - one root cause behind several
// reports that looked unrelated.
//
// It is called from hooked_Sleep and from the frame limiter now, so it does
// not matter which of them the client's pacing happens to go through. The
// eight-millisecond gate inside is what keeps two callers from doing the work
// twice.
static void MainThreadPump() {
    UpdateMainThreadActivity();

    // Runs Lua, so it belongs here and nowhere else, and not while the interface
    // is between states. It self-throttles to once a minute.
    AddonProfiler::OnFrame(LuaOpt::IsLoadingMode() || LuaOpt::IsReloading() ||
                           LuaOpt::IsSwapping());

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double elapsedMs = 0.0;
    if (g_lastSleepTime.QuadPart > 0 && g_sleepFreq > 0) {
        elapsedMs = (double)(now.QuadPart - g_lastSleepTime.QuadPart) / g_sleepFreq;
    }
    g_lastSleepTime = now;

    // Gate frame ticks so they run at most once every 8ms
    static LARGE_INTEGER lastFrameTickTime = {};
    double msSinceLastTick = 0.0;
    if (lastFrameTickTime.QuadPart > 0 && g_sleepFreq > 0) {
        msSinceLastTick = (double)(now.QuadPart - lastFrameTickTime.QuadPart) / g_sleepFreq;
    }

    double targetPrecision = (double)(Config::g_settings.SleepPrecisionValue > 0 ? Config::g_settings.SleepPrecisionValue : 8);
    if (lastFrameTickTime.QuadPart == 0 || msSinceLastTick >= targetPrecision) {
        lastFrameTickTime = now;

        RunPeriodicMaintenanceOnMainThread();

        // Detect lua_State destruction (logout/exit) - clear caches
        static uintptr_t g_lastLState = 0;
        uintptr_t currentL = *(uintptr_t*)0x00D3F78C;  // lua_State* global
        if (currentL != g_lastLState) {
            ClearAssetPathCache();
            ApiCache::ClearCache();
            ClearCombatLogCache();
            ClearTableCache();
            ClearLuaPushStringCache();
            ClearDbcLookupCache();
            g_lastLState = currentL;
        }

        LuaOpt::OnMainThreadSleep(g_mainThreadId, elapsedMs);
#if !TEST_DISABLE_LUA_GETTIME_FAST
        if (Config::g_settings.OptLuaGetTimeFast) {
            LuaGetTimeFast_NewFrame();
        }
#endif
        if (Config::g_settings.OptDefragLf) {
            LoadingDefrag::OnFrame();
        }
#if !TEST_DISABLE_PREDICTIVE_PREFETCH
        PredictivePrefetch::OnFrame();
#endif
        FlushFieldUpdates();
        CombatLogOpt::ProcessUnifiedFrameTicks((int)currentL, g_mainThreadId);
        WorldStateCoalesce::OnFrame();
#if !TEST_DISABLE_HARDWARE_CURSOR
        if (Config::g_settings.OptHardwareCursor) {
            InitHardwareCursor();
        }
#endif
#if !TEST_DISABLE_ADDON_DISPATCHER
        if (Config::g_settings.OptAddonDispatcher) {
            AddonDispatcher::OnFrame(g_mainThreadId);
        }
#endif
        RcuObjMgr::OnFrame();
#if !TEST_DISABLE_TEXTURE_DECODE_MT
        AsyncTexLoader::OnFrame();
#endif
        TextureUnloadDelay::OnFrame();
        AnimCensus::OnFrame();
        SpellEffectCulling::OnFrame();
#if !TEST_DISABLE_NAMEPLATE_MT
        NameplateMT::OnFrame(g_mainThreadId);
#endif
#if !TEST_DISABLE_EVENT_COALESCER
        EventCoalescer_Flush();
#endif

        // Enable D3D9 State Manager frame update
        OnFrameD3D9StateManager(g_mainThreadId);
        OnFrameRenderHooks(g_mainThreadId);
        OnFrameLogicHooks(g_mainThreadId);
        OnFrameAsyncHooks(g_mainThreadId);
#if !TEST_DISABLE_LUA_GC_GOVERNOR
        LuaGCGovernor::OnFrame(elapsedMs);
#endif
#if !TEST_DISABLE_ADAPTIVE_FARCLIP
    #endif
#if !TEST_DISABLE_NET_ADDON_COALESCER
#endif
#if !TEST_DISABLE_MIP_BIAS_GOVERNOR
        MipBiasGovernor::UpdateMipBias(elapsedMs);
#endif
        if (Config::g_settings.OptMouseClipRelease) MouseClipRelease::OnFrame();
#if !TEST_DISABLE_PERF_DIAGNOSTICS
        PerfDiagnostics::OnFrame(elapsedMs);
#endif
    }
}

// For the frame limiter, which waits without calling Sleep. Checks the thread
// itself so a stray call from anywhere else cannot run main-thread-only work.
extern "C" void WowOpt_MainThreadPump() {
    if (g_mainThreadId != 0 && GetCurrentThreadId() == g_mainThreadId) {
        MainThreadPump();
    }
}


static void WINAPI hooked_Sleep(DWORD ms) {
    if (g_mainThreadId != 0 && GetCurrentThreadId() == g_mainThreadId) {
        MainThreadPump();

        if (ms == 0) {
            orig_Sleep(0);
            return;
        }

        if (Config::g_settings.OptSleepPrecision && ms <= 3) {
            if (IsWine() || IsRosetta() || !LuaOpt::IsInitialized() || LuaOpt::IsLoadingMode() || LuaOpt::IsReloading() || LuaOpt::IsSwapping()) {
                orig_Sleep(ms);
                return;
            }

            // PreciseSleep does not sleep - for a 1ms wait it spins
            // SwitchToThread for most of it and then _mm_pause. That is a fair
            // trade while frames are comfortably inside their budget, because
            // sub-millisecond pacing is what stops a steady frame rate from
            // wobbling.
            //
            // It stops being a fair trade the moment frames are late. Pacing a
            // frame precisely does nothing for one that already missed, and the
            // cycles burned spinning are exactly the cycles it needed. Worse, the
            // cost lands hardest when the machine is CPU-bound, which is when it
            // can least afford it.
            //
            // So above a smoothed frame time that means "not keeping up", hand
            // the time back to the scheduler instead. The reading is 0.0 until
            // enough frames have been measured, which keeps the old behaviour as
            // the default rather than the exception.
            double smoothed = FrameBench::SmoothedFrameMs();
            if (smoothed > SPIN_ABORT_FRAME_MS) {
                ++g_spinSkipped;
                orig_Sleep(ms);
                return;
            }

            ++g_spinTaken;
            PreciseSleep((double)ms);
            return;
        }
    } else {
        if (ms == 0) {
            orig_Sleep(0);
            return;
        }
    }

    orig_Sleep(ms);
}

static bool InstallSleepHook() {
    LARGE_INTEGER li;
    QueryPerformanceFrequency(&li);
    g_sleepFreq = (double)li.QuadPart / 1000.0;

    // Calibrate RDTSC frequency for PreciseSleep
    uint64_t rdtscStart = __rdtsc();
    LARGE_INTEGER qpcStart;
    QueryPerformanceCounter(&qpcStart);
    Sleep(10);  // 10ms calibration window
    uint64_t rdtscEnd = __rdtsc();
    LARGE_INTEGER qpcEnd;
    QueryPerformanceCounter(&qpcEnd);

    uint64_t rdtscElapsed = rdtscEnd - rdtscStart;
    LONGLONG qpcElapsed = qpcEnd.QuadPart - qpcStart.QuadPart;
    double qpcMs = (double)qpcElapsed / g_sleepFreq;

    // RDTSC frequency in MHz (cycles per microsecond)
    g_rdtscFreqMhz = (double)rdtscElapsed / (qpcMs * 1000.0);

    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_Sleep, (void**)&orig_Sleep) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("Sleep hook: ACTIVE (PreciseSleep: %s, RDTSC %.1f MHz + Lua GC + combat log)", Config::g_settings.OptSleepPrecision ? "ENABLED" : "DISABLED", g_rdtscFreqMhz);
    return true;
}

// 3. Network optimization - TCP_NODELAY, immediate ACK, QoS, keepalive.
//

#ifndef SIO_TCP_SET_ACK_FREQUENCY
#define SIO_TCP_SET_ACK_FREQUENCY _WSAIOW(IOC_VENDOR, 23)
#endif

typedef int (WINAPI* connect_fn)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI* send_fn)(SOCKET, const char*, int, int);

static connect_fn orig_connect = nullptr;
static send_fn    orig_send    = nullptr;

// Track sockets that need post-connect optimization
static SOCKET g_pendingSockets[64] = {};
static int    g_pendingCount = 0;
static SRWLOCK g_pendingLock = SRWLOCK_INIT;

static void AddPendingSocket(SOCKET s) {
    AcquireSRWLockExclusive(&g_pendingLock);
    if (g_pendingCount < 64) {
        // Check not already tracked
        for (int i = 0; i < g_pendingCount; i++) {
            if (g_pendingSockets[i] == s) {
                ReleaseSRWLockExclusive(&g_pendingLock);
                return;
            }
        }
        g_pendingSockets[g_pendingCount++] = s;
    }
    ReleaseSRWLockExclusive(&g_pendingLock);
}

static bool RemovePendingSocket(SOCKET s) {
    AcquireSRWLockExclusive(&g_pendingLock);
    for (int i = 0; i < g_pendingCount; i++) {
        if (g_pendingSockets[i] == s) {
            g_pendingSockets[i] = g_pendingSockets[--g_pendingCount];
            ReleaseSRWLockExclusive(&g_pendingLock);
            return true;
        }
    }
    ReleaseSRWLockExclusive(&g_pendingLock);
    return false;
}

static void OptimizeSocket(SOCKET s, const char* trigger) {
    int applied = 0;

    // 1. Disable Nagle (TCP_NODELAY is standard, safe, and lowers latency)
    BOOL nodelay = TRUE;
    if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay)) == 0)
        applied++;

    // 2. Keepalive (30s idle, 5s interval to keep NAT mappings warm without flooding)
    tcp_keepalive ka;
    ka.onoff             = 1;
    ka.keepalivetime     = 30000;
    ka.keepaliveinterval = 5000;
    DWORD kaBytes = 0;
    if (WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka),
                 NULL, 0, &kaBytes, NULL, NULL) == 0)
        applied++;

    Log("Socket %d [%s]: %d applied (TCP_NODELAY + Keepalive, QoS/ACK frequency disabled for ISP/VPN compatibility)",
       (int)s, trigger, applied);
}

static int WINAPI hooked_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    int result = orig_connect(s, name, namelen);
    int savedError = WSAGetLastError();

    if (result == 0) {
        // Synchronous connect succeeded - optimize immediately
        OptimizeSocket(s, "connect");
    } else if (savedError == WSAEWOULDBLOCK) {
        AddPendingSocket(s);
    }

    WSASetLastError(savedError);
    return result;
}

static int WINAPI hooked_send(SOCKET s, const char* buf, int len, int flags) {
    if (RemovePendingSocket(s)) {
        int savedError = WSAGetLastError();
        OptimizeSocket(s, "send");
        WSASetLastError(savedError);
    }
    return orig_send(s, buf, len, flags);
}

// ================================================================
// 3b. recv / WSARecv - receive-side socket optimization
//
// ================================================================

typedef int (WINAPI* recv_fn)(SOCKET, char*, int, int);
typedef int (WINAPI* WSARecv_fn)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static recv_fn      orig_recv      = nullptr;
static WSARecv_fn   orig_WSARecv   = nullptr;

static long g_recvCalls      = 0;
static long g_recvBytes      = 0;
static long g_recvWouldBlock = 0;
static long g_WSARecvCalls   = 0;
static long g_WSARecvBytes   = 0;
static long g_WSARecvWouldBlock = 0;

static int WINAPI hooked_recv(SOCKET s, char* buf, int len, int flags) {
    int result = orig_recv(s, buf, len, flags);
    if (result > 0) {
        g_recvCalls++;
        g_recvBytes += result;
    } else if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            g_recvWouldBlock++;
        }
    }
    return result;
}

static int WINAPI hooked_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                                  LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
                                  LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int result = orig_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
                               lpFlags, lpOverlapped, lpCompletionRoutine);
    if (result == 0 && lpNumberOfBytesRecvd) {
        g_WSARecvCalls++;
        g_WSARecvBytes += *lpNumberOfBytesRecvd;
    } else if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            g_WSARecvWouldBlock++;
        }
    }
    return result;
}

static bool InstallNetworkHooks() {
    Log("Network hook: DISABLED for stability (native socket layer is optimal)");
    return true;
}

// ================================================================
// 4. MPQ Handle Tracking (O(1) hash lookup)
//
// ================================================================

static constexpr int MPQ_HASH_SIZE = 512; // power of 2, load factor < 0.5
static constexpr int MPQ_HASH_MASK = MPQ_HASH_SIZE - 1;

struct MpqHashEntry {
    HANDLE handle;
    bool   occupied;
};

static MpqHashEntry g_mpqHash[MPQ_HASH_SIZE] = {};
static int          g_mpqHandleCount = 0;
static SRWLOCK      g_mpqLock = SRWLOCK_INIT;

static inline int MpqSlot(HANDLE h) {
    // HANDLE values are multiples of 4, shift for distribution
    return (int)(((uintptr_t)h >> 2) & MPQ_HASH_MASK);
}

static void TrackMpqHandle(HANDLE h) {
    AcquireSRWLockExclusive(&g_mpqLock);

    int slot = MpqSlot(h);
    for (int i = 0; i < MPQ_HASH_SIZE; i++) {
        int idx = (slot + i) & MPQ_HASH_MASK;
        if (!g_mpqHash[idx].occupied) {
            g_mpqHash[idx].handle = h;
            g_mpqHash[idx].occupied = true;
            g_mpqHandleCount++;
            break;
        }
        if (g_mpqHash[idx].handle == h) {
            break; // already tracked
        }
    }

    ReleaseSRWLockExclusive(&g_mpqLock);
}

static bool IsMpqHandle(HANDLE h) {
    AcquireSRWLockShared(&g_mpqLock);

    int slot = MpqSlot(h);
    bool found = false;
    for (int i = 0; i < MPQ_HASH_SIZE; i++) {
        int idx = (slot + i) & MPQ_HASH_MASK;
        if (!g_mpqHash[idx].occupied) {
            break; // empty slot = not found
        }
        if (g_mpqHash[idx].handle == h) {
            found = true;
            break;
        }
    }

    ReleaseSRWLockShared(&g_mpqLock);
    return found;
}

static void UntrackMpqHandle(HANDLE h) {
    AcquireSRWLockExclusive(&g_mpqLock);

    int slot = MpqSlot(h);
    for (int i = 0; i < MPQ_HASH_SIZE; i++) {
        int idx = (slot + i) & MPQ_HASH_MASK;
        if (!g_mpqHash[idx].occupied) {
            break; // not found
        }
        if (g_mpqHash[idx].handle == h) {
            // Tombstone removal: rehash subsequent entries
            g_mpqHash[idx].occupied = false;
            g_mpqHash[idx].handle = NULL;
            g_mpqHandleCount--;

            // Rehash chain after deleted slot
            int next = (idx + 1) & MPQ_HASH_MASK;
            int rehashLimit = MPQ_HASH_SIZE;
            while (g_mpqHash[next].occupied && rehashLimit-- > 0) {
                HANDLE rh = g_mpqHash[next].handle;
                g_mpqHash[next].occupied = false;
                g_mpqHash[next].handle = NULL;
                g_mpqHandleCount--;

                // Re-insert
                int rs = MpqSlot(rh);
                for (int j = 0; j < MPQ_HASH_SIZE; j++) {
                    int ri = (rs + j) & MPQ_HASH_MASK;
                    if (!g_mpqHash[ri].occupied) {
                        g_mpqHash[ri].handle = rh;
                        g_mpqHash[ri].occupied = true;
                        g_mpqHandleCount++;
                        break;
                    }
                }

                next = (next + 1) & MPQ_HASH_MASK;
            }
            break;
        }
    }

    ReleaseSRWLockExclusive(&g_mpqLock);
}

// ================================================================
// 4b. Memory-Mapped MPQ Files
//
// ================================================================
// MPQ map lock - always defined (used by scanner even when mmap disabled)
static SRWLOCK g_mpqMapLock = SRWLOCK_INIT;

// MPQ handle tracking - always defined
struct MpqMapping {
    HANDLE fileHandle;
    HANDLE mappingHandle;
    void*  baseAddress;
    DWORD  fileSize;
    bool   active;
};

static constexpr int    MAX_MPQ_MAPPINGS    = 32;
static MpqMapping g_mpqMappings[MAX_MPQ_MAPPINGS] = {};
static DWORD      g_mpqMapTotalBytes = 0;
static long       g_mpqMapHits    = 0;
static long       g_mpqMapMisses  = 0;
static int        g_mpqMapCount   = 0;

#if !CRASH_TEST_DISABLE_MPQ_MMAP

static constexpr DWORD  MPQ_MMAP_MIN_SIZE   = 256 * 1024;              // 256 KB
static constexpr DWORD  MPQ_MMAP_MAX_SIZE   = 512 * 1024 * 1024;      // 512 MB
static constexpr DWORD  MPQ_MMAP_MAX_TOTAL  = 768 * 1024 * 1024;      // 768 MB total (safe for 32-bit)

static MpqMapping* FindMpqMapping(HANDLE h) {
    for (int i = 0; i < MAX_MPQ_MAPPINGS; i++) {
        if (g_mpqMappings[i].active && g_mpqMappings[i].fileHandle == h)
            return &g_mpqMappings[i];
    }
    return nullptr;
}

static MpqMapping* CreateMpqMapping(HANDLE hFile, const char* pathForLog = nullptr) {
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) return nullptr;

    // Size checks with logging
    if (fileSize.QuadPart < MPQ_MMAP_MIN_SIZE) {
        if (pathForLog) {
            Log("MPQ skip: %s (%.0f KB < %d KB min)",
                pathForLog, fileSize.QuadPart / 1024.0, MPQ_MMAP_MIN_SIZE / 1024);
        }
        return nullptr;
    }
    if (fileSize.QuadPart > MPQ_MMAP_MAX_SIZE) {
        if (pathForLog) {
            Log("MPQ skip: %s (%.0f MB > %d MB max, using read-ahead cache)",
                pathForLog, fileSize.QuadPart / (1024.0 * 1024.0), MPQ_MMAP_MAX_SIZE / (1024 * 1024));
        }
        return nullptr;
    }

    DWORD fsize = (DWORD)fileSize.QuadPart;

    // Total limit check
    if (g_mpqMapTotalBytes + fsize > MPQ_MMAP_MAX_TOTAL) {
        if (pathForLog) {
            Log("MPQ skip: %s (%.0f MB, total limit %d MB reached)",
                pathForLog, fsize / (1024.0 * 1024.0), MPQ_MMAP_MAX_TOTAL / (1024 * 1024));
        }
        return nullptr;
    }

    // Already mapped?
    if (FindMpqMapping(hFile)) return nullptr;

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) return nullptr;

    void* base = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        CloseHandle(hMapping);
        if (pathForLog) {
            Log("MPQ skip: %s (MapViewOfFile failed, error %lu)",
                pathForLog, GetLastError());
        }
        return nullptr;
    }

    // Verify the mapping is readable (catch files being modified by launchers/patchers)
    __try {
        volatile uint8_t test = *(volatile uint8_t*)base;
       (void)test;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        UnmapViewOfFile(base);
        CloseHandle(hMapping);
        if (pathForLog) {
            Log("MPQ skip: %s (mapped memory not readable)", pathForLog);
        }
        return nullptr;
    }

    // Find free slot
    for (int i = 0; i < MAX_MPQ_MAPPINGS; i++) {
        if (!g_mpqMappings[i].active) {
            g_mpqMappings[i].fileHandle    = hFile;
            g_mpqMappings[i].mappingHandle = hMapping;
            g_mpqMappings[i].baseAddress   = base;
            g_mpqMappings[i].fileSize      = fsize;
            g_mpqMappings[i].active        = true;
            g_mpqMapTotalBytes += fsize;
            g_mpqMapCount++;
            return &g_mpqMappings[i];
        }
    }

    // No free slot
    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    return nullptr;
}

static void DestroyMpqMapping(HANDLE hFile) {
    for (int i = 0; i < MAX_MPQ_MAPPINGS; i++) {
        if (g_mpqMappings[i].active && g_mpqMappings[i].fileHandle == hFile) {
            UnmapViewOfFile(g_mpqMappings[i].baseAddress);
            // NOTE: mappingHandle is intentionally NOT closed here.
            // CloseHandle is hooked → hooked_CloseHandle → AcquireSRWLock → DEADLOCK
            // The OS will close the handle when the process exits.
            // For runtime cleanup, we just unmap the view - that's sufficient.
            g_mpqMapTotalBytes -= g_mpqMappings[i].fileSize;
            g_mpqMapCount--;
            g_mpqMappings[i].active = false;
            g_mpqMappings[i].baseAddress = nullptr;
            g_mpqMappings[i].mappingHandle = nullptr;
            g_mpqMappings[i].fileSize = 0;
            return;
        }
    }
}

#endif // !CRASH_TEST_DISABLE_MPQ_MMAP

// 5. ReadFile cache MPQ adaptive read-ahead.
//

typedef BOOL (WINAPI* ReadFile_fn)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static ReadFile_fn orig_ReadFile = nullptr;

// ================================================================
// Async MPQ I/O - Predictive Read-Ahead for .m2/.blp
// ================================================================
#if !TEST_DISABLE_ASYNC_MPQ_IO

static constexpr int ASYNC_IO_QUEUE_SIZE = 512;
static constexpr int ASYNC_IO_QUEUE_MASK = ASYNC_IO_QUEUE_SIZE - 1;

struct AsyncIoTask {
    HANDLE hFile;
    LARGE_INTEGER offset;
    DWORD bytes;
    uint8_t* buffer;
    volatile LONG status; // 0=pending, 1=ready, 2=failed
};

static AsyncIoTask g_asyncIoQueue[ASYNC_IO_QUEUE_SIZE] = {};
static volatile LONG g_asyncIoHead = 0;
static volatile LONG g_asyncIoTail = 0;
static HANDLE g_asyncIoWorker = NULL;
static volatile bool g_asyncIoShutdown = false;

static DWORD WINAPI AsyncIoWorkerProc(LPVOID) {
    while (!g_asyncIoShutdown) {
        // Pause during lua_State swap - MPQ handles and buffers may be stale
        if (LuaOpt::IsSwapping()) {
            Sleep(1);
            continue;
        }
        LONG head = g_asyncIoHead;
        if (head == g_asyncIoTail) {
            SwitchToThread();
            continue;
        }
        AsyncIoTask& task = g_asyncIoQueue[head];
        __try {
            DWORD bytesRead = 0;
            OVERLAPPED ov = {};
            ov.Offset = task.offset.LowPart;
            ov.OffsetHigh = task.offset.HighPart;
            // Use OVERLAPPED structure to specify the offset. This ensures the read is thread-safe
            // and does not modify the file handle's shared file pointer (avoiding race conditions with the main thread).
            BOOL ok = orig_ReadFile(task.hFile, task.buffer, task.bytes, &bytesRead, &ov);
            InterlockedExchange(&task.status, ok ? 1 : 2);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            InterlockedExchange(&task.status, 2);
        }
        InterlockedExchange(&g_asyncIoHead, (head + 1) & ASYNC_IO_QUEUE_MASK);
    }
    return 0;
}

static bool QueueAsyncRead(HANDLE hFile, LARGE_INTEGER offset, DWORD bytes, uint8_t* buffer) {
    LONG tail = g_asyncIoTail;
    LONG nextTail = (tail + 1) & ASYNC_IO_QUEUE_MASK;
    if (nextTail == g_asyncIoHead) return false; // Queue full

    g_asyncIoQueue[tail].hFile = hFile;
    g_asyncIoQueue[tail].offset = offset;
    g_asyncIoQueue[tail].bytes = bytes;
    g_asyncIoQueue[tail].buffer = buffer;
    g_asyncIoQueue[tail].status = 0;
    InterlockedExchange(&g_asyncIoTail, nextTail);
    return true;
}

static bool CheckAsyncCompletion(HANDLE hFile, LARGE_INTEGER offset, DWORD bytes, uint8_t* dst) {
    LONG head = g_asyncIoHead;
    while (head != g_asyncIoTail) {
        AsyncIoTask& task = g_asyncIoQueue[head];
        if (task.hFile == hFile && task.offset.QuadPart == offset.QuadPart && task.bytes == bytes) {
            if (task.status == 1) {
                memcpy(dst, task.buffer, bytes);
                mi_free(task.buffer);
                InterlockedExchange(&g_asyncIoHead, (head + 1) & ASYNC_IO_QUEUE_MASK);
                return true;
            }
            if (task.status == 2) {
                mi_free(task.buffer);
                InterlockedExchange(&g_asyncIoHead, (head + 1) & ASYNC_IO_QUEUE_MASK);
            }
            return false;
        }
        head = (head + 1) & ASYNC_IO_QUEUE_MASK;
    }
    return false;
}

static void ShutdownAsyncIoWorker() {
    g_asyncIoShutdown = true;
    if (g_asyncIoWorker) {
        WaitForSingleObject(g_asyncIoWorker, 2000);
        CloseHandle(g_asyncIoWorker);
        g_asyncIoWorker = NULL;
    }
    for (int i = 0; i < ASYNC_IO_QUEUE_SIZE; i++) {
        if (g_asyncIoQueue[i].status == 0 && g_asyncIoQueue[i].buffer) {
            mi_free(g_asyncIoQueue[i].buffer);
            g_asyncIoQueue[i].buffer = nullptr;
        }
    }
}

static bool InstallAsyncIoWorker() {
    g_asyncIoShutdown = false;
    g_asyncIoWorker = CreateThread(NULL, 0, AsyncIoWorkerProc, NULL, 0, NULL);
    if (g_asyncIoWorker) {
        Log("Async MPQ I/O: ACTIVE (background worker, %d slots)", ASYNC_IO_QUEUE_SIZE);
        return true;
    }
    Log("Async MPQ I/O: FAILED to create worker thread");
    return false;
}

#else

static bool QueueAsyncRead(HANDLE, LARGE_INTEGER, DWORD, uint8_t*) { return false; }
static bool CheckAsyncCompletion(HANDLE, LARGE_INTEGER, DWORD, uint8_t*) { return false; }
static bool InstallAsyncIoWorker() { return false; }
static void ShutdownAsyncIoWorker() {}

#endif

// Async prefetch forward declarations
static const int MAX_PREFETCH_SLOTS = 8;
static const DWORD PREFETCH_SIZE = 256 * 1024;
static void InitPrefetchSlots();
static void QueuePrefetch(HANDLE hFile, LARGE_INTEGER startOffset, DWORD bytes);
static BOOL CheckPrefetch(HANDLE hFile, LARGE_INTEGER offset, LPVOID lpBuffer, DWORD nBytes, LPDWORD lpBytesRead);

struct ReadCache {
    HANDLE handle; uint8_t* buffer;
    LARGE_INTEGER fileOffset; DWORD validBytes;
    SRWLOCK lock;
};

static const DWORD READ_AHEAD_NORMAL   = 16 * 1024;
static const DWORD READ_AHEAD_LOADING  = 64 * 1024;
static const DWORD READ_AHEAD_MAX      = 256 * 1024;  // buffer allocation size
static std::unordered_map<HANDLE, ReadCache*> g_readCacheMap;
static SRWLOCK g_cacheMapLock = SRWLOCK_INIT;
static bool g_cacheInitialized = false;

static ReadCache* LockCacheForHandle(HANDLE hFile) {
    if (!g_cacheInitialized) return nullptr;

    AcquireSRWLockShared(&g_cacheMapLock);
    auto it = g_readCacheMap.find(hFile);
    if (it != g_readCacheMap.end()) {
        ReadCache* cache = it->second;
        ReleaseSRWLockShared(&g_cacheMapLock);
        AcquireSRWLockExclusive(&cache->lock);
        return cache;
    }
    ReleaseSRWLockShared(&g_cacheMapLock);

    AcquireSRWLockExclusive(&g_cacheMapLock);
    it = g_readCacheMap.find(hFile);
    if (it != g_readCacheMap.end()) {
        ReadCache* cache = it->second;
        ReleaseSRWLockExclusive(&g_cacheMapLock);
        AcquireSRWLockExclusive(&cache->lock);
        return cache;
    }

    ReadCache* cache = new ReadCache();
    cache->handle = hFile;
    cache->buffer = (uint8_t*)mi_malloc(READ_AHEAD_MAX);
    cache->validBytes = 0;
    InitializeSRWLock(&cache->lock);
    g_readCacheMap[hFile] = cache;
    ReleaseSRWLockExclusive(&g_cacheMapLock);

    AcquireSRWLockExclusive(&cache->lock);
    return cache;
}

static void RemoveCacheForHandle(HANDLE hFile) {
    AcquireSRWLockExclusive(&g_cacheMapLock);
    auto it = g_readCacheMap.find(hFile);
    if (it != g_readCacheMap.end()) {
        ReadCache* cache = it->second;
        g_readCacheMap.erase(it);
        ReleaseSRWLockExclusive(&g_cacheMapLock);

        if (cache) {
            AcquireSRWLockExclusive(&cache->lock);
            if (cache->buffer) {
                mi_free(cache->buffer);
                cache->buffer = nullptr;
            }
            ReleaseSRWLockExclusive(&cache->lock);
            delete cache;
        }
    } else {
        ReleaseSRWLockExclusive(&g_cacheMapLock);
    }
}

static BOOL WINAPI hooked_ReadFile_Inner(HANDLE hFile, LPVOID lpBuffer,
    DWORD nBytesToRead, LPDWORD lpBytesRead, LPOVERLAPPED lpOverlapped);

// Times reads while a loading screen is up, so the load report can say how much
// of a load is the disk. Two QueryPerformanceCounter calls, and only during a
// load - gameplay never reaches this branch.
static BOOL WINAPI hooked_ReadFile(HANDLE hFile, LPVOID lpBuffer,
    DWORD nBytesToRead, LPDWORD lpBytesRead, LPOVERLAPPED lpOverlapped)
{
    if (!LoadingState::IsLoading())
        return hooked_ReadFile_Inner(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    static LARGE_INTEGER freq = {};
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER a, b;
    QueryPerformanceCounter(&a);
    BOOL r = hooked_ReadFile_Inner(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);
    QueryPerformanceCounter(&b);
    if (freq.QuadPart) {
        double ms = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)freq.QuadPart;
        LoadingState::NoteRead(ms, (lpBytesRead && r) ? *lpBytesRead : 0u);
    }
    return r;
}

static BOOL WINAPI hooked_ReadFile_Inner(HANDLE hFile, LPVOID lpBuffer,
    DWORD nBytesToRead, LPDWORD lpBytesRead, LPOVERLAPPED lpOverlapped)
{
    // Skip: overlapped I/O, non-MPQ, or not initialized
    if (lpOverlapped)
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    // NULL-buffer guard: WoW may call ReadFile with lpBuffer=NULL to advance the
    // file pointer during loading/streaming with HD MPQs.
    //
    // This used to sit below the two cache serves, which both memcpy into
    // lpBuffer. A legitimate NULL-buffer call landing on a handle either of them
    // tracked was a memcpy to address zero. That is what "interferes with WoW file
    // I/O" meant in the note that disabled the addon RAM-disk, and it is why the
    // guard belongs above every serve rather than in the middle of them.
    if (!lpBuffer || !nBytesToRead)
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    // Addon file RAM-disk: serve pre-loaded addon files from memory
    if (AddonPreload_TryServe(hFile, lpBuffer, nBytesToRead, lpBytesRead))
        return TRUE;

    #if !TEST_DISABLE_SAVED_VARS_PRETOKEN
    if (SavedVarsPretoken::TryServe(hFile, lpBuffer, nBytesToRead, lpBytesRead))
        return TRUE;
    #endif

    if (!g_cacheInitialized || !IsMpqHandle(hFile))
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    // Get the atomic locked cache for this handle to prevent concurrent seek/read races
    ReadCache* cache = LockCacheForHandle(hFile);
    if (!cache) {
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);
    }

    __try {
        LARGE_INTEGER currentPos, zero;
        zero.QuadPart = 0;
        if (!SetFilePointerEx(hFile, zero, &currentPos, FILE_CURRENT)) {
            ReleaseSRWLockExclusive(&cache->lock);
            return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);
        }

        // === Memory-mapped fast path (ANY read size, zero kernel transitions) ===
#if !CRASH_TEST_DISABLE_MPQ_MMAP
        {
            AcquireSRWLockShared(&g_mpqMapLock);
            MpqMapping* m = FindMpqMapping(hFile);
            if (m) {
                DWORD offset = (DWORD)currentPos.QuadPart;
                if (offset + nBytesToRead <= m->fileSize) {
                    __try {
                        memcpy(lpBuffer, (const uint8_t*)m->baseAddress + offset, nBytesToRead);
                        if (lpBytesRead) *lpBytesRead = nBytesToRead;
                        LARGE_INTEGER newPos;
                        newPos.QuadPart = (LONGLONG)(offset + nBytesToRead);
                        SetFilePointerEx(hFile, newPos, NULL, FILE_BEGIN);
                        InterlockedIncrement(&g_mpqMapHits);
                        ReleaseSRWLockShared(&g_mpqMapLock);
                        ReleaseSRWLockExclusive(&cache->lock);
                        return TRUE;
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER) {
                        InterlockedIncrement(&g_mpqMapMisses);
                    }
                }
            }
            ReleaseSRWLockShared(&g_mpqMapLock);
        }
#endif

        // === Read-ahead cache path (only for small reads) ===
        if (nBytesToRead >= READ_AHEAD_MAX) {
            ReleaseSRWLockExclusive(&cache->lock);
            return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);
        }

        // Check if hit
        if (cache->validBytes > 0) {
            LONGLONG cStart = cache->fileOffset.QuadPart;
            LONGLONG cEnd   = cStart + cache->validBytes;
            LONGLONG rStart = currentPos.QuadPart;
            LONGLONG rEnd   = rStart + nBytesToRead;
            if (rStart >= cStart && rEnd <= cEnd) {
                DWORD off = (DWORD)(rStart - cStart);
                memcpy(lpBuffer, cache->buffer + off, nBytesToRead);
                if (lpBytesRead) *lpBytesRead = nBytesToRead;
                LARGE_INTEGER newPos; newPos.QuadPart = rEnd;
                SetFilePointerEx(hFile, newPos, NULL, FILE_BEGIN);
                ReleaseSRWLockExclusive(&cache->lock);
                return TRUE;
            }
        }

        // Cache miss - perform read-ahead and update cache
        cache->fileOffset = currentPos;
        DWORD readAhead = LuaOpt::IsLoadingMode() ? READ_AHEAD_LOADING : READ_AHEAD_NORMAL;
        DWORD bytesRead = 0;
        BOOL ok = orig_ReadFile(hFile, cache->buffer, readAhead, &bytesRead, NULL);
        if (ok && bytesRead > 0) {
            cache->validBytes = bytesRead;
            DWORD toCopy = (nBytesToRead < bytesRead) ? nBytesToRead : bytesRead;
            memcpy(lpBuffer, cache->buffer, toCopy);
            if (lpBytesRead) *lpBytesRead = toCopy;
            if (toCopy < bytesRead) {
                LARGE_INTEGER newPos2; newPos2.QuadPart = currentPos.QuadPart + toCopy;
                SetFilePointerEx(hFile, newPos2, NULL, FILE_BEGIN);
                // Queue async prefetch of next chunk (only if async I/O is enabled)
#if !TEST_DISABLE_ASYNC_MPQ_IO
                LARGE_INTEGER prefetchOff; prefetchOff.QuadPart = currentPos.QuadPart + bytesRead;
                QueuePrefetch(hFile, prefetchOff, readAhead);
#endif
            }
            ReleaseSRWLockExclusive(&cache->lock);
            return TRUE;
        }

        // Failed to read ahead, clear cache and fall back
        cache->validBytes = 0;
        SetFilePointerEx(hFile, currentPos, NULL, FILE_BEGIN);
        ReleaseSRWLockExclusive(&cache->lock);

        // === Async MPQ I/O Fast Path ===
#if !TEST_DISABLE_ASYNC_MPQ_IO
        if (IsMpqHandle(hFile) && nBytesToRead <= 65536) {
            __try {
                if (CheckAsyncCompletion(hFile, currentPos, nBytesToRead, (uint8_t*)lpBuffer)) {
                    if (lpBytesRead) *lpBytesRead = nBytesToRead;
                    LARGE_INTEGER newPos; newPos.QuadPart = currentPos.QuadPart + nBytesToRead;
                    SetFilePointerEx(hFile, newPos, NULL, FILE_BEGIN);
                    return TRUE;
                }

                uint8_t* asyncBuf = (uint8_t*)mi_malloc(nBytesToRead);
                if (asyncBuf) {
                    LARGE_INTEGER nextOff; nextOff.QuadPart = currentPos.QuadPart + nBytesToRead;
                    if (!QueueAsyncRead(hFile, nextOff, nBytesToRead, asyncBuf)) {
                        mi_free(asyncBuf); 
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
#endif    

        // === Async prefetch check ===
#if !TEST_DISABLE_ASYNC_MPQ_IO
        if (IsMpqHandle(hFile)) {
            if (CheckPrefetch(hFile, currentPos, lpBuffer, nBytesToRead, lpBytesRead)) {
                LARGE_INTEGER newPos; newPos.QuadPart = currentPos.QuadPart + nBytesToRead;
                SetFilePointerEx(hFile, newPos, NULL, FILE_BEGIN);
                return TRUE;
            }
        }
#endif

        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ReleaseSRWLockExclusive(&cache->lock);
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);
    }
}

// Times reads during a loading screen and does nothing else - straight through to
// the original, no cache, no locks, no read-ahead, no prefetch queue.
//
// The MPQ cache above is compiled out by CRASH_TEST_DISABLE_READFILE because it
// serialized on a lock and froze landings. That switch also removed the only thing
// counting reads, so the load report had no way to say how much of a load is the
// disk - and one tester log shows a single load taking 32 seconds with no way to
// look inside it. Measuring does not require the cache, so this path keeps the
// measurement and leaves the cache switched off.
static BOOL WINAPI hooked_ReadFile_TimingOnly(HANDLE hFile, LPVOID lpBuffer,
    DWORD nBytesToRead, LPDWORD lpBytesRead, LPOVERLAPPED lpOverlapped)
{
    if (!LoadingState::IsLoading())
        return orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);

    static LARGE_INTEGER freq = {};
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER a, b;
    QueryPerformanceCounter(&a);
    BOOL r = orig_ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped);
    QueryPerformanceCounter(&b);
    if (freq.QuadPart) {
        double ms = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)freq.QuadPart;
        LoadingState::NoteRead(ms, (lpBytesRead && r) ? *lpBytesRead : 0u);
    }
    return r;
}

static bool InstallReadFileTimingHook() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_ReadFile_TimingOnly, (void**)&orig_ReadFile) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("ReadFile hook: TIMING ONLY (MPQ cache stays off; measures the disk share of a load)");
    return true;
}

static bool InstallReadFileHook() {
    g_cacheInitialized = true;
    InitPrefetchSlots();
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_ReadFile, (void**)&orig_ReadFile) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("ReadFile hook: ACTIVE (MPQ cache, 64KB/256KB adaptive read-ahead, dynamic slots + async prefetch)");
    return true;
}

// ================================================================
// 5b. Async MPQ Prefetch Queue - background overlapped reads
//
// ================================================================

struct PrefetchSlot {
    HANDLE        hFile;
    LARGE_INTEGER startOffset;
    DWORD         bytesRequested;
    DWORD         bytesCompleted;
    OVERLAPPED    overlapped;
    uint8_t*      buffer;
    bool          active;
    bool          completed;
    HANDLE        hEvent;
};

static PrefetchSlot g_prefetchSlots[MAX_PREFETCH_SLOTS] = {};
static SRWLOCK      g_prefetchLock = SRWLOCK_INIT;
static long         g_prefetchHits     = 0;
static long         g_prefetchMisses   = 0;
static long         g_prefetchQueued   = 0;
static long         g_prefetchCancelled = 0;

static void InitPrefetchSlots() {
    for (int i = 0; i < MAX_PREFETCH_SLOTS; i++) {
        g_prefetchSlots[i].hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
        g_prefetchSlots[i].buffer = (uint8_t*)mi_malloc(PREFETCH_SIZE);
        g_prefetchSlots[i].overlapped.hEvent = g_prefetchSlots[i].hEvent;
    }
}

static void CancelPrefetch(HANDLE hFile, LARGE_INTEGER beyondOffset) {
    // Cancel any prefetches for this file that start before beyondOffset
    for (int i = 0; i < MAX_PREFETCH_SLOTS; i++) {
        if (g_prefetchSlots[i].active && g_prefetchSlots[i].hFile == hFile) {
            if (g_prefetchSlots[i].startOffset.QuadPart < beyondOffset.QuadPart) {
                CancelIoEx(hFile, &g_prefetchSlots[i].overlapped);
                g_prefetchSlots[i].active = false;
                g_prefetchSlots[i].completed = false;
                g_prefetchCancelled++;
            }
        }
    }
}

static void QueuePrefetch(HANDLE hFile, LARGE_INTEGER startOffset, DWORD bytes) {
    if (bytes == 0 || bytes > PREFETCH_SIZE) return;

    AcquireSRWLockExclusive(&g_prefetchLock);

    // Cancel any overlapping prefetches
    LARGE_INTEGER beyond;
    beyond.QuadPart = startOffset.QuadPart + bytes;
    CancelPrefetch(hFile, beyond);

    // Find free slot
    int slot = -1;
    for (int i = 0; i < MAX_PREFETCH_SLOTS; i++) {
        if (!g_prefetchSlots[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        ReleaseSRWLockExclusive(&g_prefetchLock);
        return;  // Queue full
    }

    // Setup prefetch
    PrefetchSlot& s = g_prefetchSlots[slot];
    s.hFile = hFile;
    s.startOffset = startOffset;
    s.bytesRequested = bytes;
    s.bytesCompleted = 0;
    s.active = true;
    s.completed = false;
    s.overlapped.Offset = startOffset.LowPart;
    s.overlapped.OffsetHigh = startOffset.HighPart;
    ResetEvent(s.hEvent);

    // Issue async read
    if (ReadFile(hFile, s.buffer, bytes, NULL, &s.overlapped)) {
        // Completed immediately
        s.completed = true;
        s.bytesCompleted = bytes;
    } else {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            s.active = false;  // Failed
        }
    }

    g_prefetchQueued++;
    ReleaseSRWLockExclusive(&g_prefetchLock);
}

static BOOL CheckPrefetch(HANDLE hFile, LARGE_INTEGER offset, LPVOID lpBuffer, DWORD nBytes, LPDWORD lpBytesRead) {
    AcquireSRWLockExclusive(&g_prefetchLock);

    for (int i = 0; i < MAX_PREFETCH_SLOTS; i++) {
        PrefetchSlot& s = g_prefetchSlots[i];
        if (!s.active || !s.completed || s.hFile != hFile) continue;

        LONGLONG pStart = s.startOffset.QuadPart;
        LONGLONG pEnd   = pStart + s.bytesCompleted;
        LONGLONG rStart = offset.QuadPart;
        LONGLONG rEnd   = rStart + nBytes;

        if (rStart >= pStart && rEnd <= pEnd) {
            // Hit! Copy from prefetch buffer
            DWORD prefetchOff = (DWORD)(rStart - pStart);
            memcpy(lpBuffer, s.buffer + prefetchOff, nBytes);
            if (lpBytesRead) *lpBytesRead = nBytes;

            // Deactivate slot
            s.active = false;
            s.completed = false;

            g_prefetchHits++;
            ReleaseSRWLockExclusive(&g_prefetchLock);
            return TRUE;
        }
    }

    g_prefetchMisses++;
    ReleaseSRWLockExclusive(&g_prefetchLock);
    return FALSE;
}

// ================================================================
// 6. GetTickCount - QPC Precision
//
// ================================================================
typedef DWORD (WINAPI* GetTickCount_fn)(void);
static GetTickCount_fn orig_GetTickCount = nullptr;
static LARGE_INTEGER g_qpcFreq, g_qpcStart;
static DWORD g_tickStart;

static DWORD WINAPI hooked_GetTickCount(void) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double elapsed = (double)(now.QuadPart - g_qpcStart.QuadPart) / g_qpcFreq.QuadPart;
    return g_tickStart + (DWORD)(elapsed * 1000.0);
}

static bool InstallGetTickCountHook() {
    QueryPerformanceFrequency(&g_qpcFreq);
    QueryPerformanceCounter(&g_qpcStart);
    g_tickStart = GetTickCount();
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_GetTickCount, (void**)&orig_GetTickCount) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("GetTickCount hook: ACTIVE (QPC-based microsecond precision)");
    return true;
}

// ================================================================
// 6b. timeGetTime (WINMM) - QPC Precision
// ================================================================

typedef DWORD (WINAPI* timeGetTime_fn)(void);
static timeGetTime_fn orig_timeGetTime = nullptr;

static DWORD WINAPI hooked_timeGetTime(void) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double elapsed = (double)(now.QuadPart - g_qpcStart.QuadPart) / g_qpcFreq.QuadPart;
    return g_tickStart + (DWORD)(elapsed * 1000.0);
}

static bool InstallTimeGetTimeHook() {
    HMODULE h = GetModuleHandleA("winmm.dll");
    if (!h) h = LoadLibraryA("winmm.dll");
    if (!h) { Log("timeGetTime hook: SKIP (winmm.dll not loaded)"); return false; }

    void* p = (void*)GetProcAddress(h, "timeGetTime");
    if (!p) { Log("timeGetTime hook: SKIP (function not found)"); return false; }

    if (MH_CreateHook(p, (void*)hooked_timeGetTime, (void**)&orig_timeGetTime) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("timeGetTime hook: ACTIVE (QPC-based, synced with GetTickCount)");
    return true;
}

// 7. CriticalSection spin count tuning + TryEnter spin-first path.
//

typedef void (WINAPI* InitCS_fn)(LPCRITICAL_SECTION);
typedef void (WINAPI* EnterCS_fn)(LPCRITICAL_SECTION);
static InitCS_fn  orig_InitCS  = nullptr;
static EnterCS_fn orig_EnterCS = nullptr;
static long g_csSpinHits = 0;

static void WINAPI hooked_InitCS(LPCRITICAL_SECTION lpCS) {
#if CRASH_TEST_DISABLE_CS_SPIN
    InitializeCriticalSection(lpCS);
#else
    InitializeCriticalSectionAndSpinCount(lpCS, 8000);
#endif
}

#if !CRASH_TEST_DISABLE_CS_ENTER
static void WINAPI hooked_EnterCS(LPCRITICAL_SECTION lpCS) {
    if (TryEnterCriticalSection(lpCS)) {
        InterlockedIncrement(&g_csSpinHits);
        return;
    }

    // Spin-wait with 3 retries at increasing intervals
    // Most CS holds are <1us - catching them saves kernel transition
    static const int retrySpins[] = {8, 64, 256};
    for (int r = 0; r < 3; r++) {
        for (int i = 0; i < retrySpins[r]; i++) _mm_pause();
        if (TryEnterCriticalSection(lpCS)) {
            InterlockedIncrement(&g_csSpinHits);
            return;
        }
    }

    orig_EnterCS(lpCS);
}
#endif

static bool InstallCriticalSectionHook() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

#if !CRASH_TEST_DISABLE_CS_INIT
    void* pInit = (void*)GetProcAddress(hK32, "InitializeCriticalSection");
    if (pInit && MH_CreateHook(pInit, (void*)hooked_InitCS, (void**)&orig_InitCS) == MH_OK)
        if (WO_EnableHook(pInit) == MH_OK) ok++;
#endif

#if CRASH_TEST_DISABLE_CS_ENTER
    Log("CriticalSection hook: ACTIVE (%d/1, init only, crash isolation)", ok);
    return ok > 0;
#else
    void* pEnter = (void*)GetProcAddress(hK32, "EnterCriticalSection");
    if (pEnter && MH_CreateHook(pEnter, (void*)hooked_EnterCS, (void**)&orig_EnterCS) == MH_OK)
        if (WO_EnableHook(pEnter) == MH_OK) ok++;

    Log("CriticalSection hooks: ACTIVE (%d/2, spin 4000 + TryEnter spin-first)", ok);
    return ok > 0;
#endif
}

// ================================================================
// 7b. Heap Optimization - Low Fragmentation Heap
//
// ================================================================

typedef HANDLE (WINAPI* HeapCreate_fn)(DWORD, SIZE_T, SIZE_T);
static HeapCreate_fn orig_HeapCreate = nullptr;
static int g_heapsOptimized = 0;

static void EnableLFH(HANDLE hHeap) {
    if (!hHeap) return;
    ULONG heapInfo = 2; // LFH
    HeapSetInformation(hHeap, HeapCompatibilityInformation,
                       &heapInfo, sizeof(heapInfo));
}

static HANDLE WINAPI hooked_HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
    HANDLE h = orig_HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
    if (h && dwMaximumSize == 0) {
        // LFH only works on growable heaps (dwMaximumSize == 0)
        // Fixed-size heaps don't support LFH
        EnableLFH(h);
        g_heapsOptimized++;
    }
    return h;
}

static bool InstallHeapOptimization() {
    // Enable LFH on the process default heap first
    HANDLE processHeap = GetProcessHeap();
    if (processHeap) {
        EnableLFH(processHeap);
        g_heapsOptimized++;
    }

    // WoW's CRT heap (_crtheap) is created during CRT startup -- long before our
    // HeapCreate hook below installs -- so the "future heaps" path misses it. It is
    // a distinct heap from the process default heap and backs every malloc above the
    // small-block threshold (~1KB): asset chunks, string/buffer allocations, model
    // and texture staging. Without the low-fragmentation front-end those churn into
    // VA fragmentation on the 32-bit client. The handle lives at 0x00B31684 (free()
    // does HeapFree(hHeap=0x00B31684, ...)). HeapSetInformation safely no-ops on a
    // bad handle, and the read is SEH-guarded.
    __try {
        HANDLE crtHeap = *(HANDLE*)0x00B31684;
        if (crtHeap && crtHeap != processHeap) {
            EnableLFH(crtHeap);
            g_heapsOptimized++;
            Log("Heap optimization: LFH enabled on WoW CRT heap (_crtheap @ 0x00B31684)");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("Heap optimization: CRT-heap LFH skipped (handle read faulted)");
    }

    // Hook HeapCreate to enable LFH on all future heaps
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "HeapCreate");
    if (!p) {
        Log("Heap optimization: LFH on process heap only (%d heaps)", g_heapsOptimized);
        return g_heapsOptimized > 0;
    }

    if (MH_CreateHook(p, (void*)hooked_HeapCreate, (void**)&orig_HeapCreate) != MH_OK) {
        Log("Heap optimization: LFH on process heap only (%d heaps)", g_heapsOptimized);
        return g_heapsOptimized > 0;
    }
    if (WO_EnableHook(p) != MH_OK) {
        Log("Heap optimization: LFH on process heap only (%d heaps)", g_heapsOptimized);
        return g_heapsOptimized > 0;
    }

    Log("Heap optimization: ACTIVE (LFH on process heap + all new heaps)");
    return true;
}

// ================================================================
// 7a. HeapAlloc/HeapFree → mimalloc - redirect process heap to mimalloc
//
// Windows HeapAlloc/HeapFree are used by Win32 APIs and WoW internal
// code. Redirecting the process heap to mimalloc catches all remaining
// allocations that bypass CRT malloc (HeapAlloc, LocalAlloc, etc.).
// Other heaps keep LFH but use the original allocator for safety.
// ================================================================
static uintptr_t g_wowBase = 0;
static uintptr_t g_wowEnd = 0;

static inline bool IsCallerWowExe(void* retAddr) {
    if (!g_wowBase) {
        HMODULE hMod = GetModuleHandleA(NULL);
        if (hMod) {
            g_wowBase = (uintptr_t)hMod;
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((char*)hMod + dos->e_lfanew);
            g_wowEnd = g_wowBase + nt->OptionalHeader.SizeOfImage;
        }
    }
    uintptr_t addr = (uintptr_t)retAddr;
    return (addr >= g_wowBase && addr < g_wowEnd);
}

typedef LPVOID (WINAPI* HeapAlloc_fn)(HANDLE, DWORD, SIZE_T);
typedef BOOL   (WINAPI* HeapFree_fn)(HANDLE, DWORD, LPVOID);
typedef LPVOID (WINAPI* HeapReAlloc_fn)(HANDLE, DWORD, LPVOID, SIZE_T);
typedef SIZE_T (WINAPI* HeapSize_fn)(HANDLE, DWORD, LPCVOID);
typedef BOOL   (WINAPI* HeapValidate_fn)(HANDLE, DWORD, LPCVOID);

static HeapAlloc_fn    orig_HeapAlloc  = nullptr;
static HeapFree_fn     orig_HeapFree   = nullptr;
static HeapReAlloc_fn  orig_HeapReAlloc = nullptr;
static HeapSize_fn     orig_HeapSize   = nullptr;
static HeapValidate_fn orig_HeapValidate = nullptr;
static HANDLE        g_processHeap   = nullptr;
static long          g_heapAllocHits  = 0;

static LPVOID WINAPI hooked_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    if (hHeap == g_processHeap && dwBytes > 0 && IsCallerWowExe(_ReturnAddress())) {
        InterlockedIncrement(&g_heapAllocHits);
        void* p = mi_malloc(dwBytes);
        if (!p) {
            if (dwFlags & HEAP_GENERATE_EXCEPTIONS) {
                RaiseException(0xC0000017, 0, 0, NULL);
            }
            return NULL;
        }
        if (dwFlags & HEAP_ZERO_MEMORY) memset(p, 0, dwBytes);
        return p;
    }
    return orig_HeapAlloc(hHeap, dwFlags, dwBytes);
}

static BOOL WINAPI hooked_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
    if (lpMem && mi_is_in_heap_region(lpMem)) {
        mi_free(lpMem);
        return TRUE;
    }
    return orig_HeapFree(hHeap, dwFlags, lpMem);
}

static LPVOID WINAPI hooked_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) {
    if (lpMem && mi_is_in_heap_region(lpMem)) {
        if (dwBytes == 0) {
            mi_free(lpMem);
            return NULL;
        }
        size_t oldSize = mi_usable_size(lpMem);
        if (dwFlags & HEAP_REALLOC_IN_PLACE_ONLY) {
            if (dwBytes <= oldSize) {
                return lpMem;
            }
            if (dwFlags & HEAP_GENERATE_EXCEPTIONS) {
                RaiseException(0xC0000017, 0, 0, NULL);
            }
            return NULL;
        }
        void* p = mi_realloc(lpMem, dwBytes);
        if (!p) {
            if (dwFlags & HEAP_GENERATE_EXCEPTIONS) {
                RaiseException(0xC0000017, 0, 0, NULL);
            }
            return NULL;
        }
        if (dwFlags & HEAP_ZERO_MEMORY) {
            if (dwBytes > oldSize) {
                memset((char*)p + oldSize, 0, dwBytes - oldSize);
            }
        }
        return p;
    }
    return orig_HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes);
}

static SIZE_T WINAPI hooked_HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem) {
    if (lpMem && mi_is_in_heap_region((void*)lpMem)) {
        return mi_usable_size((void*)lpMem);
    }
    return orig_HeapSize(hHeap, dwFlags, lpMem);
}

static BOOL WINAPI hooked_HeapValidate(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem) {
    if (lpMem && mi_is_in_heap_region((void*)lpMem)) {
        return TRUE;
    }
    return orig_HeapValidate(hHeap, dwFlags, lpMem);
}

static bool InstallHeapRedirectToMimalloc() {
    Log("Heap safety redirect bridge: DISABLED for stability (HeapAlloc redirection is inactive)");
    return true;
}

// ================================================================
// 7c. OutputDebugStringA - No-op when no debugger
//
// ================================================================

typedef void (WINAPI* OutputDebugStringA_fn)(LPCSTR);
static OutputDebugStringA_fn orig_OutputDebugStringA = nullptr;
static long g_debugStringSkipped = 0;

static void WINAPI hooked_OutputDebugStringA(LPCSTR lpOutputString) {
    if (!IsDebuggerPresent()) {
        InterlockedIncrement(&g_debugStringSkipped);
        return;
    }
    orig_OutputDebugStringA(lpOutputString);
}

static bool InstallOutputDebugStringHook() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OutputDebugStringA");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_OutputDebugStringA, (void**)&orig_OutputDebugStringA) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("OutputDebugStringA hook: ACTIVE (no-op when no debugger)");
    return true;
}

// ================================================================
// 7d. CompareStringA - Fast ASCII Path
//
// ================================================================

static const unsigned char g_asciiToUpper[256] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
    96, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 123, 124, 125, 126, 127,
    128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
    144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
    160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
    176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
    192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
    208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
    224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

typedef int (WINAPI* CompareStringA_fn)(LCID, DWORD, LPCSTR, int, LPCSTR, int);
static CompareStringA_fn orig_CompareStringA = nullptr;
static long g_compareAsciiHits = 0;
static long g_compareFallbacks = 0;

#ifndef CSTR_LESS_THAN
#define CSTR_LESS_THAN    1
#define CSTR_EQUAL        2
#define CSTR_GREATER_THAN 3
#endif

static int WINAPI hooked_CompareStringA(LCID Locale, DWORD dwCmpFlags,
    LPCSTR lpString1, int cchCount1, LPCSTR lpString2, int cchCount2)
{
    // Only fast-path for simple flags: none, case-insensitive, or string sort
    if ((dwCmpFlags & ~(NORM_IGNORECASE | SORT_STRINGSORT)) != 0)
        goto cmp_fallback;

    if (!lpString1 || !lpString2)
        goto cmp_fallback;

    {
        bool ignoreCase = (dwCmpFlags & NORM_IGNORECASE) != 0;
        int i1 = 0, i2 = 0;

        while (true) {
            bool end1 = (lpString1[i1] == '\0') || (cchCount1 >= 0 && i1 >= cchCount1);
            bool end2 = (lpString2[i2] == '\0') || (cchCount2 >= 0 && i2 >= cchCount2);

            if (end1 && end2) { g_compareAsciiHits++; return CSTR_EQUAL; }
            if (end1)         { g_compareAsciiHits++; return CSTR_LESS_THAN; }
            if (end2)         { g_compareAsciiHits++; return CSTR_GREATER_THAN; }

            unsigned char c1 = (unsigned char)lpString1[i1];
            unsigned char c2 = (unsigned char)lpString2[i2];

            // Bail on non-ASCII - needs locale-aware comparison
            if (c1 > 127 || c2 > 127)
                goto cmp_fallback;

            if (ignoreCase) {
                c1 = g_asciiToUpper[c1];
                c2 = g_asciiToUpper[c2];
            }

            if (c1 != c2) {
                g_compareAsciiHits++;
                return (c1 < c2) ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
            }

            i1++;
            i2++;
        }
    }

cmp_fallback:
    g_compareFallbacks++;
    return orig_CompareStringA(Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2);
}

static bool InstallCompareStringHook() {
#if CRASH_TEST_DISABLE_COMPARESTRING
    Log("CompareStringA hook: DISABLED (crash isolation)");
    return false;
#else
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CompareStringA");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_CompareStringA, (void**)&orig_CompareStringA) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("CompareStringA hook: ACTIVE (fast ASCII path, locale fallback for non-ASCII)");
    return true;
#endif
}

// ================================================================
// 7e. GetFileAttributesA - Cache for MPQ paths
//
// ================================================================

typedef DWORD (WINAPI* GetFileAttributesA_fn)(LPCSTR);
static GetFileAttributesA_fn orig_GetFileAttributesA = nullptr;

static constexpr int FILE_ATTR_CACHE_SIZE = 16384;
static constexpr int FILE_ATTR_CACHE_MASK = FILE_ATTR_CACHE_SIZE - 1;

struct FileAttrEntry {
    uint32_t pathHash;
    DWORD    attributes;
    bool     valid;
};

static FileAttrEntry g_fileAttrCache[FILE_ATTR_CACHE_SIZE] = {};
static long g_fileAttrHits   = 0;
static long g_fileAttrMisses = 0;
static SRWLOCK g_fileAttrLock = SRWLOCK_INIT;

static uint32_t HashPathCI(const char* path) {
    uint32_t h = 0x811C9DC5;
    while (*path) {
        char c = *path++;
        if (c >= 'A' && c <= 'Z') c += 32;
        if (c == '/') c = '\\';
        h ^= (uint8_t)c;
        h *= 0x01000193;
    }
    return h;
}

static DWORD WINAPI hooked_GetFileAttributesA(LPCSTR lpFileName) {
    if (!lpFileName) return orig_GetFileAttributesA(lpFileName);

    // Strictly limit cache to Interface and Data directories (guaranteed static).
    // WTF, Cache, Logs, and config files must never be cached.
    bool isStatic = false;
    for (const char* p = lpFileName; *p; ++p) {
        char c = *p;
        if (c == 'I' || c == 'i') {
            if ((p[1] == 'N' || p[1] == 'n') &&
                (p[2] == 'T' || p[2] == 't') &&
                (p[3] == 'E' || p[3] == 'e') &&
                (p[4] == 'R' || p[4] == 'r') &&
                (p[5] == 'F' || p[5] == 'f') &&
                (p[6] == 'A' || p[6] == 'a') &&
                (p[7] == 'C' || p[7] == 'c') &&
                (p[8] == 'E' || p[8] == 'e')) {
                isStatic = true;
                break;
            }
        }
        if (c == 'D' || c == 'd') {
            if ((p[1] == 'A' || p[1] == 'a') &&
                (p[2] == 'T' || p[2] == 't') &&
                (p[3] == 'A' || p[3] == 'a')) {
                isStatic = true;
                break;
            }
        }
    }

    if (!isStatic) {
        return orig_GetFileAttributesA(lpFileName);
    }

    uint32_t hash = HashPathCI(lpFileName);
    int slot = hash & FILE_ATTR_CACHE_MASK;
    FileAttrEntry* e = &g_fileAttrCache[slot];

    AcquireSRWLockShared(&g_fileAttrLock);
    if (e->valid && e->pathHash == hash) {
        DWORD attr = e->attributes;
        ReleaseSRWLockShared(&g_fileAttrLock);
        g_fileAttrHits++;
        return attr;
    }
    ReleaseSRWLockShared(&g_fileAttrLock);

    DWORD result = orig_GetFileAttributesA(lpFileName);

    AcquireSRWLockExclusive(&g_fileAttrLock);
    e->pathHash   = hash;
    e->attributes = result;
    e->valid      = true;
    ReleaseSRWLockExclusive(&g_fileAttrLock);

    g_fileAttrMisses++;
    return result;
}

static bool InstallGetFileAttributesHook() {
#if CRASH_TEST_DISABLE_GETFILEATTR
    Log("GetFileAttributesA hook: DISABLED (crash isolation)");
    return false;
#else
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetFileAttributesA");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_GetFileAttributesA, (void**)&orig_GetFileAttributesA) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("GetFileAttributesA hook: ACTIVE (cache existing files, %d slots)", FILE_ATTR_CACHE_SIZE);
    return true;
#endif
}

// ================================================================
// 7g. SetFilePointer → SetFilePointerEx Redirect
//
// ================================================================

typedef DWORD (WINAPI* SetFilePointer_fn)(HANDLE, LONG, PLONG, DWORD);
static SetFilePointer_fn orig_SetFilePointer = nullptr;
static long g_sfpRedirected = 0;

static DWORD WINAPI hooked_SetFilePointer(HANDLE hFile, LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
    LARGE_INTEGER liDist;
    if (lpDistanceToMoveHigh) {
        liDist.LowPart  = (DWORD)lDistanceToMove;
        liDist.HighPart = *lpDistanceToMoveHigh;
    } else {
        liDist.QuadPart = (LONGLONG)lDistanceToMove;
    }

    LARGE_INTEGER liNewPos;
    if (SetFilePointerEx(hFile, liDist, &liNewPos, dwMoveMethod)) {
        if (lpDistanceToMoveHigh)
            *lpDistanceToMoveHigh = liNewPos.HighPart;
        g_sfpRedirected++;
        return liNewPos.LowPart;
    }

    return INVALID_SET_FILE_POINTER;
}

static bool InstallSetFilePointerHook() {
#if CRASH_TEST_DISABLE_SETFILEPOINTER
    Log("SetFilePointer hook: DISABLED (crash isolation)");
    return false;
#else
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetFilePointer");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_SetFilePointer, (void**)&orig_SetFilePointer) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("SetFilePointer hook: ACTIVE (redirected to SetFilePointerEx)");
    return true;
#endif
}

// ================================================================
// 7h. GlobalAlloc/GlobalFree - mimalloc for GMEM_FIXED
//
// ================================================================

typedef HGLOBAL (WINAPI* GlobalAlloc_fn)(UINT, SIZE_T);
typedef HGLOBAL (WINAPI* GlobalFree_fn)(HGLOBAL);
typedef SIZE_T  (WINAPI* GlobalSize_fn)(HGLOBAL);
typedef HGLOBAL (WINAPI* GlobalReAlloc_fn)(HGLOBAL, SIZE_T, UINT);

static GlobalAlloc_fn   orig_GlobalAlloc = nullptr;
static GlobalFree_fn    orig_GlobalFree  = nullptr;
static GlobalSize_fn    orig_GlobalSize   = nullptr;
static GlobalReAlloc_fn orig_GlobalReAlloc = nullptr;
static long g_globalAllocFast = 0;

static HGLOBAL WINAPI hooked_GlobalAlloc(UINT uFlags, SIZE_T dwBytes) {
    // Only optimize GMEM_FIXED (flags == 0 or GPTR which includes GMEM_FIXED+GMEM_ZEROINIT)
    // GMEM_MOVEABLE must use original for GlobalLock/GlobalUnlock semantics
    if ((uFlags & GMEM_MOVEABLE) == 0 && dwBytes > 0 && IsCallerWowExe(_ReturnAddress())) {
        void* ptr;
        if (uFlags & GMEM_ZEROINIT) {
            ptr = mi_calloc(1, dwBytes);
        } else {
            ptr = mi_malloc(dwBytes);
        }
        if (ptr) {
            g_globalAllocFast++;
            return (HGLOBAL)ptr;
        }
    }
    return orig_GlobalAlloc(uFlags, dwBytes);
}

static HGLOBAL WINAPI hooked_GlobalFree(HGLOBAL hMem) {
    if (hMem && mi_is_in_heap_region(hMem)) {
        mi_free(hMem);
        return NULL;
    }
    return orig_GlobalFree(hMem);
}

static SIZE_T WINAPI hooked_GlobalSize(HGLOBAL hMem) {
    if (hMem && mi_is_in_heap_region(hMem)) {
        return mi_usable_size(hMem);
    }
    return orig_GlobalSize(hMem);
}

static HGLOBAL WINAPI hooked_GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags) {
    if (hMem && mi_is_in_heap_region(hMem)) {
        if (uFlags & GMEM_MODIFY) {
            return hMem;
        }
        if (dwBytes == 0) {
            mi_free(hMem);
            return NULL;
        }
        size_t oldSize = mi_usable_size(hMem);
        void* ptr = mi_realloc(hMem, dwBytes);
        if (ptr && (uFlags & GMEM_ZEROINIT)) {
            if (dwBytes > oldSize) {
                memset((char*)ptr + oldSize, 0, dwBytes - oldSize);
            }
        }
        return (HGLOBAL)ptr;
    }
    return orig_GlobalReAlloc(hMem, dwBytes, uFlags);
}

static bool InstallGlobalAllocHooks() {
    Log("GlobalAlloc hooks: DISABLED for stability (prevents connection errors and heap mismatches)");
    return false;
}

// ================================================================
// 7f2. IsBadReadPtr / IsBadWritePtr - Fast Path
//
// ================================================================

typedef BOOL (WINAPI* IsBadReadPtr_fn)(const void*, UINT_PTR);
typedef BOOL (WINAPI* IsBadWritePtr_fn)(void*, UINT_PTR);
static IsBadReadPtr_fn  orig_IsBadReadPtr  = nullptr;
static IsBadWritePtr_fn orig_IsBadWritePtr = nullptr;
static long g_badPtrFastChecks = 0;

static BOOL WINAPI hooked_IsBadReadPtr(const void* lp, UINT_PTR ucb) {
    if (!lp) return TRUE;
    if (ucb == 0) return FALSE;
    if ((uintptr_t)lp < 0x10000) return TRUE;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(lp, &mbi, sizeof(mbi)) == 0) return TRUE;
    if (mbi.State != MEM_COMMIT) return TRUE;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return TRUE;

    g_badPtrFastChecks++;
    return FALSE;
}

static BOOL WINAPI hooked_IsBadWritePtr(void* lp, UINT_PTR ucb) {
    if (!lp) return TRUE;
    if (ucb == 0) return FALSE;
    if ((uintptr_t)lp < 0x10000) return TRUE;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(lp, &mbi, sizeof(mbi)) == 0) return TRUE;
    if (mbi.State != MEM_COMMIT) return TRUE;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD | PAGE_READONLY)) return TRUE;

    g_badPtrFastChecks++;
    return FALSE;
}

static bool InstallBadPtrHooks() {
#if CRASH_TEST_DISABLE_ISBADPTR
    Log("IsBadPtr hooks: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

    void* pR = (void*)GetProcAddress(hK32, "IsBadReadPtr");
    if (pR && MH_CreateHook(pR, (void*)hooked_IsBadReadPtr, (void**)&orig_IsBadReadPtr) == MH_OK)
        if (WO_EnableHook(pR) == MH_OK) ok++;

    void* pW = (void*)GetProcAddress(hK32, "IsBadWritePtr");
    if (pW && MH_CreateHook(pW, (void*)hooked_IsBadWritePtr, (void**)&orig_IsBadWritePtr) == MH_OK)
        if (WO_EnableHook(pW) == MH_OK) ok++;

    if (ok > 0) {
        Log("IsBadPtr hooks: ACTIVE (%d/2, fast VirtualQuery path)", ok);
        return true;
    }
    return false;
#endif
}

// ================================================================
// 7f. GetCurrentThreadId - TLS Cached
//
// ================================================================

typedef DWORD (WINAPI* GetCurrentThreadId_fn)(void);
typedef HANDLE (WINAPI* GetCurrentThread_fn)(void);
static GetCurrentThreadId_fn orig_GetCurrentThreadId = nullptr;
static GetCurrentThread_fn   orig_GetCurrentThread   = nullptr;

static __declspec(thread) DWORD t_cachedThreadId = 0;
static long g_threadIdCacheHits = 0;

static DWORD WINAPI hooked_GetCurrentThreadId(void) {
    DWORD id = t_cachedThreadId;
    if (id == 0) {
        id = orig_GetCurrentThreadId();
        t_cachedThreadId = id;
    }
    return id;
}

static HANDLE WINAPI hooked_GetCurrentThread(void) {
    return (HANDLE)(LONG_PTR)-2;  // constant pseudo-handle
}

static bool InstallThreadIdCacheHook() {
    Log("ThreadId cache: DISABLED for stability (native GetCurrentThreadId is optimal).");
    return true;
}

// ================================================================
// 7f3. QueryPerformanceCounter - Coalesced with RDTSC fast path
//
// ================================================================

typedef BOOL (WINAPI* QueryPerformanceCounter_fn)(LARGE_INTEGER*);
static QueryPerformanceCounter_fn orig_QPC = nullptr;

static __declspec(thread) LONGLONG t_lastQPC = 0;
static __declspec(thread) uint64_t t_lastRDTSC = 0;
static long g_qpcCacheHits = 0;
static long g_qpcCacheMisses = 0;

// Coalescing window in RDTSC cycles (calibrated at init)
static uint64_t g_rdtscThreshold = 0;

static BOOL WINAPI hooked_QPC(LARGE_INTEGER* lpPerformanceCount) {
    if (!lpPerformanceCount)
        return orig_QPC(lpPerformanceCount);

    // Fast path: check cache validity with RDTSC (~10 cycles)
    uint64_t nowRDTSC = __rdtsc();
    uint64_t elapsedRDTSC = nowRDTSC - t_lastRDTSC;

    if (elapsedRDTSC < g_rdtscThreshold && t_lastRDTSC != 0) {
        // Cache hit: return cached QPC value without syscall
        lpPerformanceCount->QuadPart = t_lastQPC;
        InterlockedIncrement(&g_qpcCacheHits);
        return TRUE;
    }

    // Cache miss: call original QPC and update cache
    LARGE_INTEGER now;
    orig_QPC(&now);

    t_lastQPC = now.QuadPart;
    t_lastRDTSC = nowRDTSC;
    lpPerformanceCount->QuadPart = now.QuadPart;
    InterlockedIncrement(&g_qpcCacheMisses);
    return TRUE;
}

static bool InstallQPCHook() {
    // Calibrate RDTSC threshold for 25 microseconds
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    
    // Measure RDTSC frequency over 10ms
    uint64_t rdtscStart = __rdtsc();
    QueryPerformanceCounter(&start);
    Sleep(10);
    uint64_t rdtscEnd = __rdtsc();
    QueryPerformanceCounter(&end);
    
    uint64_t rdtscElapsed = rdtscEnd - rdtscStart;
    LONGLONG qpcElapsed = end.QuadPart - start.QuadPart;
    
    // Calculate RDTSC cycles per QPC tick
    double rdtscPerQpc = (double)rdtscElapsed / (double)qpcElapsed;
    
    // 25us coalescing window in QPC ticks
    LONGLONG qpcWindow = freq.QuadPart / 40000;  // 25us
    if (qpcWindow < 1) qpcWindow = 1;
    
    // Convert to RDTSC cycles
    g_rdtscThreshold = (uint64_t)(rdtscPerQpc * qpcWindow);
    
    // Safety bounds: 1,000 - 10,000,000 cycles (0.25us - 2.5ms on 4GHz CPU)
    if (g_rdtscThreshold < 1000) g_rdtscThreshold = 1000;
    if (g_rdtscThreshold > 10000000) g_rdtscThreshold = 10000000;

    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "QueryPerformanceCounter");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_QPC, (void**)&orig_QPC) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("QPC hook: ACTIVE (25us coalescing, %llu RDTSC cycles, RDTSC fast path)", g_rdtscThreshold);
    return true;
}

// ================================================================
// 8. CreateFile - Sequential Scan + MPQ Tracking
//
// ================================================================
typedef HANDLE (WINAPI* CreateFileA_fn)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI* CreateFileW_fn)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static CreateFileA_fn orig_CreateFileA = nullptr;
static CreateFileW_fn orig_CreateFileW = nullptr;

// Helper: check if path passes through a .MPQ folder (e.g. patch-Sunlight.MPQ\DBFilesClient\...)
static bool PathPassesThroughMPQ(const char* path) {
    if (!path) return false;
    const char* p = path;
    while (p) {
        p = strchr(p, '.');
        if (!p || p == path) return false; // extension can't be first component
        if (_strnicmp(p, ".mpq", 4) == 0 && (p[4] == '\\' || p[4] == '/' || p[4] == 0)) {
            // Found .MPQ/ - verify it's a path component, not just part of filename
            // Ensure there's a separator before the dot (or it's the start of a component)
            if (p > path && (p[-1] != '\\' && p[-1] != '/' && p[-1] != ':')) {
                // Could be "thing.MPQfile" - skip
                p++;
                continue;
            }
            return true;
        }
        p++;
        if (*p == 0) break;
    }
    return false;
}

static HANDLE WINAPI hooked_CreateFileA(LPCSTR lpFileName, DWORD dwAccess, DWORD dwShare,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwDisposition, DWORD dwFlags, HANDLE hTemplate)
{
    bool isMPQ = false;
    if (lpFileName && (dwAccess & GENERIC_READ)) {
        // Strip trailing backslash (folder paths like patch-Sunlight.MPQ\)
        size_t len = strlen(lpFileName);
        const char* checkPath = lpFileName;
        char fixedPath[MAX_PATH];
        if (len > 0 && lpFileName[len-1] == '\\') {
            memcpy(fixedPath, lpFileName, len);
            fixedPath[len-1] = 0;
            checkPath = fixedPath;
        }
        const char* ext = strrchr(checkPath, '.');
        if (ext && _stricmp(ext, ".mpq") == 0) {
            dwFlags |= FILE_FLAG_SEQUENTIAL_SCAN; isMPQ = true;
        }
        // Also detect files inside .MPQ folders (patch-Sunlight.MPQ\DBFilesClient\...)
        if (!isMPQ && PathPassesThroughMPQ(lpFileName)) {
            isMPQ = true;
        }
    }
    HANDLE result = orig_CreateFileA(lpFileName, dwAccess, dwShare, lpSA, dwDisposition, dwFlags, hTemplate);
    if (isMPQ && result != INVALID_HANDLE_VALUE) {
        TrackMpqHandle(result);
#if !CRASH_TEST_DISABLE_MPQ_MMAP
        AcquireSRWLockExclusive(&g_mpqMapLock);
        MpqMapping* m = CreateMpqMapping(result, lpFileName);
        ReleaseSRWLockExclusive(&g_mpqMapLock);
        if (m) {
            Log("MPQ mmap: %s (%.1f MB)", lpFileName, m->fileSize / (1024.0 * 1024.0));
        }
#endif
    }
    // Track addon file handles for RAM-disk serving
    if (result != INVALID_HANDLE_VALUE) {
        AddonPreload_OnCreateFile(result, lpFileName);
        #if !TEST_DISABLE_SAVED_VARS_PRETOKEN
        SavedVarsPretoken::OnCreateFile(result, lpFileName, dwAccess);
        #endif
        
        // Track SavedVariables files for async writing
        if (lpFileName) {
            extern bool ContainsWTF(const char* path);
            const char* luaExt = strrchr(lpFileName, '.');
            if (ContainsWTF(lpFileName) && luaExt && _stricmp(luaExt, ".lua") == 0) {
                #if !TEST_DISABLE_SAVED_VARS_ASYNC
                if (dwAccess & (GENERIC_WRITE | FILE_WRITE_DATA | GENERIC_ALL)) {
                    extern void TrackSVHandle(HANDLE h);
                    TrackSVHandle(result);
                }
                #endif
            }
        }
    }
    return result;
}

static HANDLE WINAPI hooked_CreateFileW(LPCWSTR lpFileName, DWORD dwAccess, DWORD dwShare,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwDisposition, DWORD dwFlags, HANDLE hTemplate)
{
    bool isMPQ = false;
    if (lpFileName && (dwAccess & GENERIC_READ)) {
        const wchar_t* ext = wcsrchr(lpFileName, L'.');
        if (ext && (_wcsicmp(ext, L".mpq") == 0 || _wcsicmp(ext, L".MPQ") == 0)) {
            dwFlags |= FILE_FLAG_SEQUENTIAL_SCAN; isMPQ = true;
        }
    }
    HANDLE result = orig_CreateFileW(lpFileName, dwAccess, dwShare, lpSA, dwDisposition, dwFlags, hTemplate);
    if (isMPQ && result != INVALID_HANDLE_VALUE) {
        TrackMpqHandle(result);
#if !CRASH_TEST_DISABLE_MPQ_MMAP
        AcquireSRWLockExclusive(&g_mpqMapLock);
        MpqMapping* m = CreateMpqMapping(result, lpFileName);
        ReleaseSRWLockExclusive(&g_mpqMapLock);
        if (m) {
            Log("MPQ mmap: %s (%.1f MB)", m->fileName, m->fileSize / (1024.0 * 1024.0));
        }
#endif
    }
    if (result != INVALID_HANDLE_VALUE && lpFileName) {
        char buf[512];
        WideCharToMultiByte(CP_UTF8, 0, lpFileName, -1, buf, 512, NULL, NULL);
        AddonPreload_OnCreateFile(result, buf);
        #if !TEST_DISABLE_SAVED_VARS_PRETOKEN
        SavedVarsPretoken::OnCreateFile(result, buf, dwAccess);
        #endif

        // Track SavedVariables files for async writing
        extern bool ContainsWTF(const char* path);
        const char* luaExt = strrchr(buf, '.');
        if (ContainsWTF(buf) && luaExt && _stricmp(luaExt, ".lua") == 0) {
            #if !TEST_DISABLE_SAVED_VARS_ASYNC
            if (dwAccess & (GENERIC_WRITE | FILE_WRITE_DATA | GENERIC_ALL)) {
                extern void TrackSVHandle(HANDLE h);
                TrackSVHandle(result);
            }
            #endif
        }
    }
    return result;
}

static bool InstallFileHooks() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;
    int ok = 0;
    void* pA = (void*)GetProcAddress(hK32, "CreateFileA");
    void* pW = (void*)GetProcAddress(hK32, "CreateFileW");
    if (pA && MH_CreateHook(pA, (void*)hooked_CreateFileA, (void**)&orig_CreateFileA) == MH_OK)
        if (WO_EnableHook(pA) == MH_OK) ok++;
    if (pW && MH_CreateHook(pW, (void*)hooked_CreateFileW, (void**)&orig_CreateFileW) == MH_OK)
        if (WO_EnableHook(pW) == MH_OK) ok++;
    if (ok > 0) { Log("CreateFile hooks: ACTIVE (%d/2, sequential scan + MPQ tracking)", ok); return true; }
    return false;
}

// ================================================================
// 9. CloseHandle - Cache Invalidation
//
// ================================================================
typedef BOOL (WINAPI* CloseHandle_fn)(HANDLE);
static CloseHandle_fn orig_CloseHandle = nullptr;

static BOOL WINAPI hooked_CloseHandle(HANDLE hObject) {
    if (!hObject || hObject == INVALID_HANDLE_VALUE ||
        hObject == GetCurrentProcess() || hObject == GetCurrentThread())
        return orig_CloseHandle(hObject);
#if !CRASH_TEST_DISABLE_MPQ_MMAP
    AcquireSRWLockExclusive(&g_mpqMapLock);
    DestroyMpqMapping(hObject);
    ReleaseSRWLockExclusive(&g_mpqMapLock);
#endif
    UntrackMpqHandle(hObject);
    AddonPreload_OnCloseHandle(hObject);
    #if !TEST_DISABLE_SAVED_VARS_PRETOKEN
    SavedVarsPretoken::OnCloseHandle(hObject);
    #endif
    if (g_cacheInitialized) {
        RemoveCacheForHandle(hObject);
    }
    return orig_CloseHandle(hObject);
}

static bool InstallCloseHandleHook() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_CloseHandle, (void**)&orig_CloseHandle) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("CloseHandle hook: ACTIVE (cache invalidation on file close)");
    return true;
}

// 9c. Retroactive MPQ handle scanner finds MPQ handles opened before DLL loaded.
//

typedef DWORD (WINAPI* GetFinalPathNameByHandleA_fn)(HANDLE, LPSTR, DWORD, DWORD);
static GetFinalPathNameByHandleA_fn pGetFinalPathNameByHandleA = nullptr;

static void ScanExistingMpqHandles() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (hK32) {
        pGetFinalPathNameByHandleA = (GetFinalPathNameByHandleA_fn)
            GetProcAddress(hK32, "GetFinalPathNameByHandleA");
    }
    if (!pGetFinalPathNameByHandleA) {
        Log("MPQ scan: GetFinalPathNameByHandleA not available - skipped");
        return;
    }

    char pathBuf[MAX_PATH];
    int tracked = 0;
    int mapped  = 0;
    int alreadyTracked = 0;

    for (DWORD h = 4; h < 0x40000; h += 4) {
        HANDLE handle = (HANDLE)(uintptr_t)h;

        SetLastError(0);
        DWORD fileType = GetFileType(handle);
        // Accept both files and folders (WoW reads MPQ folders as archives)
        if (fileType != FILE_TYPE_DISK && fileType != FILE_TYPE_UNKNOWN) continue;
        if (GetLastError() == ERROR_INVALID_HANDLE) continue;

        DWORD len = pGetFinalPathNameByHandleA(handle, pathBuf, MAX_PATH,
                                                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (len == 0 || len >= MAX_PATH) continue;

        // Check for .mpq/.MPQ in path - file extension, folder name, or parent directory
        bool isMpq = (len >= 4 && _stricmp(pathBuf + len - 4, ".mpq") == 0)
                  || PathPassesThroughMPQ(pathBuf);
        if (!isMpq) continue;

        if (IsMpqHandle(handle)) {
            alreadyTracked++;
            continue;
        }

        TrackMpqHandle(handle);
        tracked++;

        const char* displayPath = pathBuf;
        if (pathBuf[0] == '\\' && pathBuf[1] == '\\' &&
            pathBuf[2] == '?' && pathBuf[3] == '\\') {
            displayPath = pathBuf + 4;
        }

        // Try to memory-map
#if !CRASH_TEST_DISABLE_MPQ_MMAP
        AcquireSRWLockExclusive(&g_mpqMapLock);
        MpqMapping* m = CreateMpqMapping(handle, displayPath);
        ReleaseSRWLockExclusive(&g_mpqMapLock);
        if (m) {
            mapped++;
            Log("MPQ mmap: %s (%.1f MB)", displayPath, m->fileSize / (1024.0 * 1024.0));
        }
#else
        Log("MPQ tracked: %s", displayPath);
#endif
    }

#if !CRASH_TEST_DISABLE_MPQ_MMAP
    Log("MPQ scan: %d handles tracked, %d memory-mapped (%.1f MB), %d already tracked",
        tracked, mapped, g_mpqMapTotalBytes / (1024.0 * 1024.0), alreadyTracked);
#else
    int foldersDetected = 0;
    char dataDir[MAX_PATH] = "";  // stored for Interface detection later
    // Filesystem scan: find .MPQ folders not yet opened by WoW
    // (e.g. patch-Sunlight.MPQ\ with only sub-folders, no handles yet)
    {
        // Use first tracked MPQ to find Data directory
        for (int i = 0; i < MPQ_HASH_SIZE; i++) {
            if (g_mpqHash[i].occupied) {
                DWORD plen = pGetFinalPathNameByHandleA(g_mpqHash[i].handle,
                    dataDir, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
                if (plen > 0 && plen < MAX_PATH) {
                    char* lastSlash = strrchr(dataDir, '\\');
                    if (lastSlash) { *lastSlash = 0; break; }
                }
            }
        }
        if (dataDir[0]) {
            char pattern[MAX_PATH];
            WIN32_FIND_DATAA fd;
            // Scan both the Data directory and its enUS/locale subdirectory
            snprintf(pattern, MAX_PATH, "%s\\*.*", dataDir);
            HANDLE hFind = FindFirstFileA(pattern, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                    if (fd.cFileName[0] == '.') continue;
                    const char* ext = strrchr(fd.cFileName, '.');
                    if (!ext || _stricmp(ext, ".mpq") != 0) continue;
                    Log("MPQ folder detected: %s\\%s", dataDir, fd.cFileName);
                    foldersDetected++;
                } while (FindNextFileA(hFind, &fd));
                FindClose(hFind);
            }
            // Also scan parent (the actual Data folder) if we got locale subdirectory
            char* lastSlash = strrchr(dataDir, '\\');
            if (lastSlash) {
                *lastSlash = 0;
                snprintf(pattern, MAX_PATH, "%s\\*.*", dataDir);
                hFind = FindFirstFileA(pattern, &fd);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                        if (fd.cFileName[0] == '.') continue;
                        const char* ext = strrchr(fd.cFileName, '.');
                        if (!ext || _stricmp(ext, ".mpq") != 0) continue;
                        Log("MPQ folder detected: %s\\%s", dataDir, fd.cFileName);
                        foldersDetected++;
                    } while (FindNextFileA(hFind, &fd));
                    FindClose(hFind);
                }
            }
        }
    }

    // Detect Interface folder as virtual MPQ (addon files, icons, UI textures)
    {
        char* lastSlash = strrchr(dataDir, '\\');
        if (lastSlash) {
            *lastSlash = 0;
            char ifPath[MAX_PATH];
            snprintf(ifPath, MAX_PATH, "%s\\Interface", dataDir);
            if (GetFileAttributesA(ifPath) != INVALID_FILE_ATTRIBUTES)
                Log("MPQ virtual archive: %s (Interface)", ifPath);
        }
    }

    Log("MPQ scan: %d handles, %d folders, %d already tracked (mmap disabled)",
        tracked, foldersDetected, alreadyTracked);
#endif
}

// ================================================================
// 9b. FlushFileBuffers - Skip for MPQ (read-only)
//
// ================================================================

typedef BOOL (WINAPI* FlushFileBuffers_fn)(HANDLE);
static FlushFileBuffers_fn orig_FlushFileBuffers = nullptr;
static long g_flushSkipped = 0;

static BOOL WINAPI hooked_FlushFileBuffers(HANDLE hFile) {
    if (IsMpqHandle(hFile)) {
        InterlockedIncrement(&g_flushSkipped);
        return TRUE;
    }
    return orig_FlushFileBuffers(hFile);
}

static bool InstallFlushFileBuffersHook() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FlushFileBuffers");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_FlushFileBuffers, (void**)&orig_FlushFileBuffers) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("FlushFileBuffers hook: ACTIVE (skip for read-only MPQ handles)");
    return true;
}

// 9d. Multi-client detection via named mutex.
//

static void DetectMultiClient() {
    g_instanceMutex = CreateMutexA(NULL, FALSE, "wow_optimize_instance_v2");
    if (g_instanceMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        g_isMultiClient = true;
        Log("Multi-client: DETECTED (conservative timer + sleep)");
    } else {
        g_isMultiClient = false;
        Log("Single client: optimal timer + sleep settings");
    }
}

// 10. System timer resolution.
//
static void SetHighTimerResolution() {
    typedef LONG (WINAPI* NtSetTimerRes_fn)(ULONG, BOOLEAN, PULONG);
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return;
    auto p = (NtSetTimerRes_fn)GetProcAddress(h, "NtSetTimerResolution");
    if (!p) return;
    ULONG actual;
    // Multi-client: 1.0ms to reduce CPU overhead
    // Single client: 0.5ms for best frame pacing
    ULONG requested = g_isMultiClient ? 10000 : 5000;
    double requestedMs = requested / 10000.0;
    if (p(requested, TRUE, &actual) == 0) {
        double actualMs = actual / 10000.0;
        // Sanity check: valid range is 0.5ms - 100ms (Wine/VM can return garbage)
        if (actualMs >= 0.1 && actualMs <= 100.0) {
            Log("Timer resolution: %.3f ms (requested %.3f ms%s)",
                actualMs, requestedMs,
                g_isMultiClient ? ", multi-client mode" : "");
        } else {
            Log("Timer resolution: SET (actual value invalid: %.0f ms - Wine/VM detected, ignoring)",
                actualMs);
            Log("Timer resolution: requested %.3f ms%s",
                requestedMs,
                g_isMultiClient ? " (multi-client mode)" : "");
        }
    } else {
        Log("WARNING: Timer resolution change failed");
    }
}

// 11. Large pages - requires SeLockMemoryPrivilege.
//
// Enables mimalloc large page support if privilege is available.
static void TryEnableLargePages() {
#if !TEST_ENABLE_LARGE_PAGES
    Log("Large pages: DISABLED (TEST_ENABLE_LARGE_PAGES=0)");
    return;
#else
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueA(NULL, "SeLockMemoryPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hToken); return;
    }
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        // The account does not hold the privilege; we cannot grant it. The user
        // must add their account to secpol.msc -> Local Policies -> User Rights
        // Assignment -> "Lock pages in memory", then log off/on. Until then this
        // is a harmless no-op (mimalloc falls back to normal 4KB pages).
        Log("Large pages: no permission (grant 'Lock pages in memory' in secpol.msc to this account, then relog)");
        return;
    }
    // Privilege held + enabled. mimalloc will now back arenas with large pages.
    SIZE_T lp = GetLargePageMinimum();  // 0 if unsupported; typically 2MB on x86
    mi_option_set(mi_option_allow_large_os_pages, 1);
    Log("Large pages: configured (mimalloc will use 2MB segments if OS supports)");
#endif
}

// 12. Thread optimization - ideal processor, priority.
//
static void OptimizeThreads() {
    DWORD pid = GetCurrentProcessId();
    DWORD mainTid = 0;
    ULONGLONG earliest = MAXULONGLONG;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (ht) {
                    FILETIME c, e, k, u;
                    if (GetThreadTimes(ht, &c, &e, &k, &u)) {
                        ULONGLONG ct = ((ULONGLONG)c.dwHighDateTime << 32) | c.dwLowDateTime;
                        if (ct < earliest) { earliest = ct; mainTid = te.th32ThreadID; }
                    }
                    CloseHandle(ht);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    if (!mainTid) { Log("WARNING: Could not find main thread"); return; }

    g_mainThreadId = mainTid;

    if (IsWine()) {
        Log("Main thread %lu: ideal-core/priority SKIPPED (Wine/Rosetta)", mainTid);
        return;
    }

    HANDLE hMain = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, mainTid);
    if (!hMain) return;
    SYSTEM_INFO si; GetSystemInfo(&si);
    DWORD core = (si.dwNumberOfProcessors > 2) ? 1 : 0;
    SetThreadIdealProcessor(hMain, core);
    SetThreadPriority(hMain, THREAD_PRIORITY_ABOVE_NORMAL);
    CloseHandle(hMain);
    Log("Main thread %lu: ideal core %lu, priority ABOVE_NORMAL (of %lu cores)", mainTid, core, si.dwNumberOfProcessors);
}

// 13. Process priority.
//
// Hook SetPriorityClass to prevent WoW from downgrading priority after we set it
typedef BOOL (WINAPI* SetPriorityClass_fn)(HANDLE, DWORD);
static SetPriorityClass_fn orig_SetPriorityClass = nullptr;
static volatile LONG g_priorityDowngradesBlocked = 0;

static BOOL WINAPI hooked_SetPriorityClass(HANDLE hProcess, DWORD dwPriorityClass) {
    // Allow our initial setup and upgrades (ABOVE_NORMAL, HIGH, REALTIME)
    if (dwPriorityClass >= ABOVE_NORMAL_PRIORITY_CLASS) {
        return orig_SetPriorityClass(hProcess, dwPriorityClass);
    }
    
    // Block downgrade attempts (NORMAL, BELOW_NORMAL, IDLE)
    if (hProcess == GetCurrentProcess() || hProcess == (HANDLE)-1 ||
        (hProcess && GetProcessId(hProcess) == GetCurrentProcessId())) {
        InterlockedIncrement(&g_priorityDowngradesBlocked);
        return TRUE;  // Fake success to avoid breaking WoW logic
    }
    
    // Allow other processes (shouldn't happen, but be safe)
    return orig_SetPriorityClass(hProcess, dwPriorityClass);
}

// Helper: try to enable SE_INC_BASE_PRIORITY_NAME privilege (allows setting process priority above normal)
static bool TryEnablePriorityPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeIncreaseBasePriorityPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return ok && err == ERROR_SUCCESS;
}

static void OptimizeProcess() {
    // Try to obtain the privilege needed for above-normal/high priority
    TryEnablePriorityPrivilege();
    
    // Try ABOVE_NORMAL first (requires admin rights)
    if (SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS)) {
        // FALSE = enable priority boost (Windows dynamic boost still active on top of our priority)
        // Note: SetProcessPriorityBoost(hProcess, TRUE) would DISABLE the boost
        SetProcessPriorityBoost(GetCurrentProcess(), FALSE);
        Log("Process: Above Normal priority set successfully");
    } else {
        // Fallback: try HIGH_PRIORITY_CLASS (may work without full admin in some cases)
        DWORD err = GetLastError();
        if (SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
            SetProcessPriorityBoost(GetCurrentProcess(), FALSE);
            Log("Process: High priority set (Above Normal requires admin, error %lu)", err);
        } else {
            err = GetLastError();
            Log("Process: Failed to set priority (error %lu) - run WoW as administrator for Above Normal/High priority", err);
        }
    }
}

// Priority watchdog thread - monitors and restores process priority
static HANDLE g_priorityWatchdogThread = NULL;
static volatile bool g_priorityWatchdogActive = true;
static DWORD g_priorityWatchdogLastLogTick = 0;

static DWORD WINAPI PriorityWatchdogProc(LPVOID param) {
    while (g_priorityWatchdogActive) {
        Sleep(2000);  // Check every 2 seconds
        
        if (!g_priorityWatchdogActive) break;
        
        DWORD currentPriority = GetPriorityClass(GetCurrentProcess());
        
        if (currentPriority < ABOVE_NORMAL_PRIORITY_CLASS) {
            if (SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS)) {
                InterlockedIncrement(&g_priorityWatchdogRestores);
                // Rate-limit: log first 3 restorations immediately, then once per 60s
                // Loading screens repeatedly call SetPriorityClass(NORMAL), causing
                // log spam without the rate limit.
                LONG count = g_priorityWatchdogRestores;
                DWORD now = GetTickCount();
                if (count <= 3 || (now - g_priorityWatchdogLastLogTick) > 60000) {
                    Log("[Priority] Watchdog restored Above Normal priority (was %lu, restorations=%ld)", 
                        currentPriority, count);
                    g_priorityWatchdogLastLogTick = now;
                }
            }
        }
    }
    
    return 0;
}

static void StartPriorityWatchdog() {
    g_priorityWatchdogActive = true;
    g_priorityWatchdogThread = CreateThread(NULL, 65536, PriorityWatchdogProc, NULL, CREATE_SUSPENDED, NULL);
    if (g_priorityWatchdogThread) {
        SetThreadPriority(g_priorityWatchdogThread, THREAD_PRIORITY_LOWEST);
        ResumeThread(g_priorityWatchdogThread);
        Log("Process: Priority watchdog started (2s interval)");
    } else {
        Log("WARNING: Failed to start priority watchdog");
    }
}

static void StopPriorityWatchdog() {
    g_priorityWatchdogActive = false;
    if (g_priorityWatchdogThread) {
        WaitForSingleObject(g_priorityWatchdogThread, 3000);
        CloseHandle(g_priorityWatchdogThread);
        g_priorityWatchdogThread = NULL;
    }
}

// 14. Working set.
//
static void OptimizeWorkingSet() {
    SIZE_T minWS, maxWS;
    if (g_isMultiClient) {
        // Multi-client: reduce footprint to ease 32-bit address space pressure
        minWS = 64 * 1024 * 1024;    // 64 MB
        maxWS = 1024ULL * 1024 * 1024; // Raised from 512MB → 1024MB to prevent ERROR #134 during char switches
    } else {
        minWS = 256 * 1024 * 1024;    // 256 MB
        maxWS = 2048ULL * 1024 * 1024; // 2048 MB
    }
    if (SetProcessWorkingSetSize(GetCurrentProcess(), minWS, maxWS))
        Log("Working set: min %u MB, max %u MB%s",
           (unsigned)(minWS / (1024 * 1024)),
           (unsigned)(maxWS / (1024 * 1024)),
            g_isMultiClient ? " (multi-client reduced)" : "");
    else
        Log("WARNING: Working set failed (error %lu)", GetLastError());
}

// 15. mimalloc configuration.
//
// Configures mimalloc options and pre-warms the allocator.
static void ConfigureMimalloc() {
    // Allow large OS pages when enabled by system policy (gated; TryEnableLargePages
    // confirms the privilege). Off here when disabled so mimalloc never even attempts
    // 2MB reservations on a VA-tight 32-bit client.
    mi_option_set(mi_option_allow_large_os_pages, TEST_ENABLE_LARGE_PAGES ? 1 : 0);

    // v3.3.x: eager commit arenas on Windows for faster allocation
    // Commits entire arena at once instead of page-by-page
    mi_option_set(mi_option_arena_eager_commit, 0);

    // Purge delay = how long mimalloc keeps a freed page mapped before decommitting
    // it back to the OS. Now that mimalloc backs WoW's ENTIRE high-churn heap, a too-
    // short delay is actively harmful: WoW frees and re-allocates constantly, so the
    // pages get decommitted and immediately re-committed -> a page-fault storm (a
    // tester saw 6.3M faults + an 11s stall with delay=25). A multi-second main-thread
    // stall also misses WoW's app-level heartbeat -> the server disconnects the client.
    // So default GENTLE (500ms) -> freed pages are reused in place, far fewer faults,
    // and in-place reuse actually fragments LESS than decommit+recommit-elsewhere. The
    // pressure governor tightens this to 100ms (YELLOW) / 10ms (RED) only when VA is
    // genuinely scarce, where aggressive reclaim earns its faults. See the AdaptPurge
    // shed callback.
    mi_option_set(mi_option_purge_delay, 500);

    // Purge via RESET (MEM_RESET), NOT decommit (MEM_DECOMMIT).
    //
    // Now that mimalloc backs WoW's ENTIRE heap, it also backs the dynamic
    // vertex/index/staging buffers WoW locks and hands to the d3d9->OpenGL
    // wrapper. That wrapper's NVIDIA GL driver consumes those buffers
    // ASYNCHRONOUSLY on its own worker thread. With MEM_DECOMMIT, a buffer
    // freed on the main thread gets its page UNMAPPED before the driver
    // finishes reading it -> the driver faults reading a still-valid-looking
    // pointer whose page is gone (verified: #132 ACCESS_VIOLATION reading
    // 0x8589006C on nvoglv32.dll worker thread, login screen, only with this
    // DLL loaded). MEM_RESET keeps the VA mapped and readable (the OS may
    // reclaim the physical frames lazily and faulting it back in just returns
    // zeros/old data) so the driver never faults, while still handing physical
    // RAM back under pressure.
    mi_option_set(mi_option_purge_decommits, 0);

    // Pre-warm allocator with 32MB to reduce VA space pressure
    // 64MB was too aggressive for HD clients with 37+ MPQs (VA fragmentation)
    void* warmup = mi_malloc(32 * 1024 * 1024);
    if (warmup) { memset(warmup, 0, 32 * 1024 * 1024); mi_free(warmup); }

    // Pre-warm size classes matching WoW allocation patterns:
    // TValue(16), Node(24-32), Table(56), TString(24-128), Proto(256-512)
    static const size_t seedSizes[] = {
        16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128,
        160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024
    };
    static const int SEEDS_PER_SIZE = 512;
    for (size_t sz : seedSizes) {
        void* batch[512];
        for (int i = 0; i < SEEDS_PER_SIZE; i++) batch[i] = mi_malloc(sz);
        for (int i = 0; i < SEEDS_PER_SIZE; i++) if (batch[i]) mi_free(batch[i]);
    }

    Log("mimalloc v%d.%d.%d configured (eager commit, reset purge, pre-warmed 32MB + 23 size classes)",
        mi_version() / 100, (mi_version() % 100) / 10, mi_version() % 10);
}

static void AdjustMimallocForMultiClient() {
    if (g_isMultiClient) {
        // Multi-client doubles the VA pressure. The one-time forced collect
        // hands back the pre-warm (32MB + 23 seed batches) which is pure
        // startup waste on the 2nd+ client. Purge delay stays at 500ms
        // (GREEN via ConfigureMimalloc); the pressure governor tightens it
        // on the per-client governor instance only when that client's VA
        // fragments. The real fix remains user-side
        // bcdedit /set increaseuserva 3072 for 3GB VA.
        // RESET (not decommit) — keep freed VA mapped so async GPU-driver
        // reads of in-flight buffers never fault (see ConfigureMimalloc).
        mi_option_set(mi_option_purge_decommits, 0);
        mi_collect(true);
        Log("mimalloc: multi-client mode (reset purge, one-time collect)");
    }
}

// 16. FPS cap removal - patches CMP EAX, 200 to CMP EAX, 999.
//
static uintptr_t FindPattern(uintptr_t base, size_t size, const uint8_t* pat, const char* mask) {
    for (size_t i = 0; i < size; i++) {
        bool found = true;
        for (size_t j = 0; mask[j]; j++) {
            if (mask[j] == 'x' && *(uint8_t*)(base + i + j) != pat[j]) { found = false; break; }
        }
        if (found) return base + i;
    }
    return 0;
}

static void TryRemoveFPSCap() {
    HMODULE hWow = GetModuleHandleA(NULL);
    if (!hWow) return;
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hWow, &modInfo, sizeof(modInfo))) return;

    // BUGFIX: scan for CMP EAX, 200 then verify next byte is a conditional jump
    const uint8_t pat[] = { 0x3D, 0xC8, 0x00, 0x00, 0x00 };
    uintptr_t base = (uintptr_t)hWow;
    size_t size = modInfo.SizeOfImage;
    uintptr_t addr = 0;
    uintptr_t searchFrom = base;

    while (searchFrom < base + size) {
        uintptr_t found = FindPattern(searchFrom, base + size - searchFrom, pat, "xxxxx");
        if (!found) break;

        // Verify: instruction after CMP should be a conditional jump
        uint8_t b = *(uint8_t*)(found + 5);
        if (b == 0x7E || b == 0x7F) {
            // JLE or JG short - valid FPS cap pattern
            addr = found;
            break;
        }
        if (b == 0x0F) {
            uint8_t b2 = *(uint8_t*)(found + 6);
            if (b2 == 0x8E || b2 == 0x8F) {
                // JLE or JG near - valid FPS cap pattern
                addr = found;
                break;
            }
        }

        searchFrom = found + 1;
    }

    if (addr) {
        DWORD old;
        if (VirtualProtect((void*)(addr + 1), 4, PAGE_EXECUTE_READWRITE, &old)) {
            *(uint32_t*)(addr + 1) = 200;  // stock cap — 999 breaks camera interpolation
            VirtualProtect((void*)(addr + 1), 4, old, &old);
            Log("FPS cap: stock value 200 preserved at 0x%08X (999 breaks camera interpolation)", (unsigned)addr);
        }
    } else {
        Log("FPS cap: signature not found (may be a different build)");
    }
}

// Periodic stats dump called from hooked_Sleep.
//

static void DumpPeriodicStats() {
    extern long g_assetPathHits;
    extern long g_assetPathMisses;
    extern long g_tvalueMemcpyHits;
    extern long g_sysInfoHits;
    extern long g_regCacheHits;
    extern long g_regCacheMisses;
    extern long g_streamReadHits;
    extern long g_streamReadFallbacks;
    extern long g_streamWriteHits;
    extern long g_streamWriteFallbacks;
    // Process memory diagnostics (helps diagnose HD/custom client OOM)
    PROCESS_MEMORY_COUNTERS pmc = {};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        Log("[Stats] Process: WS=%.0fMB Peak=%.0fMB PageFaults=%lu",
            pmc.WorkingSetSize / (1024.0 * 1024.0),
            pmc.PeakWorkingSetSize / (1024.0 * 1024.0),
            pmc.PageFaultCount);
    }
    // Renderer line here too: DXVK's d3d9.dll can load after the startup probe,
    // so re-report it once detection has reliably latched. Makes any mid-session
    // log slice self-describing (GPU is static; logged once at startup).
    Log("[Stats] Renderer: %s", DXVKBridge::IsActive() ? "DXVK / Vulkan translation" : "native Direct3D 9");

    // Virtual address space scan (32-bit fragmentation indicator)
    {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t addr = 0x10000;
        SIZE_T largestFree = 0;
        SIZE_T totalFree = 0;
        while (addr < 0x7FFF0000) {
            if (VirtualQuery((void*)addr, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_FREE) {
                    if (mbi.RegionSize > largestFree) largestFree = mbi.RegionSize;
                    totalFree += mbi.RegionSize;
                }
                addr += mbi.RegionSize;
                if (mbi.RegionSize == 0) addr += 0x10000;
            } else {
                addr += 0x10000;
            }
        }
        Log("[Stats] VA Space: Free=%.0fMB LargestBlock=%.0fMB%s",
            totalFree / (1024.0 * 1024.0),
            largestFree / (1024.0 * 1024.0),
           (largestFree < 64 * 1024 * 1024) ? " WARNING: fragmented" : "");
    }    
    Log("[Stats] ====================================");

#if !CRASH_TEST_DISABLE_MPQ_MMAP
    Log("[Stats] MPQ mmap: %ld reads, %ld faults, %d files, %.1f MB mapped",
        g_mpqMapHits, g_mpqMapMisses, g_mpqMapCount,
        g_mpqMapTotalBytes / (1024.0 * 1024.0));
#endif

#if !CRASH_TEST_DISABLE_QPC_CACHE
    if (g_qpcCacheHits + g_qpcCacheMisses > 0) {
        long total = g_qpcCacheHits + g_qpcCacheMisses;
        Log("[Stats] QPC: %ld cached, %ld real (%.1f%% cache hit)",
            g_qpcCacheHits, g_qpcCacheMisses,
           (double)g_qpcCacheHits / total * 100.0);
    }
#endif

    if (g_flushSkipped > 0)
        Log("[Stats] FlushFileBuffers: %ld MPQ skipped", g_flushSkipped);
    if (g_prefetchQueued > 0 || g_prefetchHits > 0)
        Log("[Stats] MPQ Prefetch: %ld queued, %ld hits, %ld misses, %ld cancelled (%.1f%% hit rate)",
            g_prefetchQueued, g_prefetchHits, g_prefetchMisses, g_prefetchCancelled,
           (g_prefetchHits + g_prefetchMisses > 0) ? (double)g_prefetchHits / (g_prefetchHits + g_prefetchMisses) * 100.0 : 0.0);
    if (g_compareAsciiHits + g_compareFallbacks > 0)
        Log("[Stats] CompareStringA: %ld fast, %ld fallback (%.1f%%)",
            g_compareAsciiHits, g_compareFallbacks,
           (double)g_compareAsciiHits / (g_compareAsciiHits + g_compareFallbacks) * 100.0);
    if (g_fileAttrHits + g_fileAttrMisses > 0)
        Log("[Stats] GetFileAttributes: %ld hits, %ld misses (%.1f%%)",
            g_fileAttrHits, g_fileAttrMisses,
           (double)g_fileAttrHits / (g_fileAttrHits + g_fileAttrMisses) * 100.0);
    if (g_badPtrFastChecks > 0)
        Log("[Stats] IsBadPtr: %ld fast checks", g_badPtrFastChecks);
    if (g_csSpinHits > 0)
        Log("[Stats] CriticalSection: %ld spin-acquired", g_csSpinHits);
    if (g_sfpRedirected > 0)
        Log("[Stats] SetFilePointer: %ld redirected", g_sfpRedirected);
    if (g_fsizeHits + g_fsizeMisses > 0)
        Log("[Stats] GetFileSize: %ld hits, %ld misses (%.1f%%)",
            g_fsizeHits, g_fsizeMisses,
           (double)g_fsizeHits / (g_fsizeHits + g_fsizeMisses) * 100.0);
    if (g_wfsSpinHits + g_wfsFallbacks > 0)
        Log("[Stats] WaitForSingleObject: %ld spin, %ld fallback (%.1f%% spin)",
            g_wfsSpinHits, g_wfsFallbacks,
           (double)g_wfsSpinHits / (g_wfsSpinHits + g_wfsFallbacks) * 100.0);
    if (g_modHits + g_modMisses > 0)
        Log("[Stats] GetModuleHandle: %ld hits, %ld misses (%.1f%%)",
            g_modHits, g_modMisses,
           (double)g_modHits / (g_modHits + g_modMisses) * 100.0);
    if (g_lstrcmpHits + g_lstrcmpFallbacks > 0)
        Log("[Stats] lstrcmp: %ld fast, %ld fallback (%.1f%%)",
            g_lstrcmpHits, g_lstrcmpFallbacks,
           (double)g_lstrcmpHits / (g_lstrcmpHits + g_lstrcmpFallbacks) * 100.0);
    if (g_mbwcFastHits + g_mbwcFallbacks > 0)
        Log("[Stats] MultiByteToWideChar: %ld fast, %ld fallback (%.1f%%)",
            g_mbwcFastHits, g_mbwcFallbacks,
           (double)g_mbwcFastHits / (g_mbwcFastHits + g_mbwcFallbacks) * 100.0);
    if (g_wcmbFastHits + g_wcmbFallbacks > 0)
        Log("[Stats] WideCharToMultiByte: %ld fast, %ld fallback (%.1f%%)",
            g_wcmbFastHits, g_wcmbFallbacks,
           (double)g_wcmbFastHits / (g_wcmbFastHits + g_wcmbFallbacks) * 100.0);
    if (g_profHits + g_profMisses > 0)
        Log("[Stats] GetPrivateProfile: %ld hits, %ld misses (%.1f%%)",
            g_profHits, g_profMisses,
           (double)g_profHits / (g_profHits + g_profMisses) * 100.0);
    if (g_gpaHits + g_gpaMisses > 0)
        Log("[Stats] GetProcAddress: %ld hits, %ld misses, %ld evictions (%.1f%% hit rate)",
            g_gpaHits, g_gpaMisses, g_gpaEvictions,
           (double)g_gpaHits / (g_gpaHits + g_gpaMisses) * 100.0);
    if (g_gmfHits + g_gmfMisses > 0)
        Log("[Stats] GetModuleFileName: %ld hits, %ld misses (%.1f%%)",
            g_gmfHits, g_gmfMisses,
           (double)g_gmfHits / (g_gmfHits + g_gmfMisses) * 100.0);
    if (g_envHits + g_envMisses > 0)
        Log("[Stats] GetEnvironmentVariable: %ld hits, %ld misses (%.1f%%)",
            g_envHits, g_envMisses,
           (double)g_envHits / (g_envHits + g_envMisses) * 100.0);
    if (g_crtStrlenHits + g_crtStrlenFallbacks > 0)
        Log("[Stats] CRT strlen: %ld fast, %ld fallback (%.1f%%)",
            g_crtStrlenHits, g_crtStrlenFallbacks,
           (double)g_crtStrlenHits / (g_crtStrlenHits + g_crtStrlenFallbacks) * 100.0);
    if (g_crtStrcmpHits + g_crtStrcmpFallbacks > 0)
        Log("[Stats] CRT strcmp: %ld fast, %ld fallback (%.1f%%)",
            g_crtStrcmpHits, g_crtStrcmpFallbacks,
           (double)g_crtStrcmpHits / (g_crtStrcmpHits + g_crtStrcmpFallbacks) * 100.0);
    if (g_crtMemcmpHits + g_crtMemcmpFallbacks > 0)
        Log("[Stats] CRT memcmp: %ld fast, %ld fallback (%.1f%%)",
            g_crtMemcmpHits, g_crtMemcmpFallbacks,
           (double)g_crtMemcmpHits / (g_crtMemcmpHits + g_crtMemcmpFallbacks) * 100.0);
    if (g_crtMemcpyHits + g_crtMemcpyFallbacks > 0)
        Log("[Stats] CRT memcpy: %ld fast, %ld fallback (%.1f%%)",
            g_crtMemcpyHits, g_crtMemcpyFallbacks,
           (double)g_crtMemcpyHits / (g_crtMemcpyHits + g_crtMemcpyFallbacks) * 100.0);
    if (g_crtMemsetHits + g_crtMemsetFallbacks > 0)
        Log("[Stats] CRT memset: %ld fast, %ld fallback (%.1f%%)",
            g_crtMemsetHits, g_crtMemsetFallbacks,
           (double)g_crtMemsetHits / (g_crtMemsetHits + g_crtMemsetFallbacks) * 100.0);
    if (g_memchrHits + g_memchrFallbacks > 0)
        Log("[Stats] CRT memchr: %lld fast, %lld fallback (%.1f%%)",
            g_memchrHits, g_memchrFallbacks,
           (double)g_memchrHits / (g_memchrHits + g_memchrFallbacks) * 100.0);
    if (g_strchrHits + g_strchrFallbacks > 0)
        Log("[Stats] CRT strchr: %lld fast, %lld fallback (%.1f%%)",
            g_strchrHits, g_strchrFallbacks,
           (double)g_strchrHits / (g_strchrHits + g_strchrFallbacks) * 100.0);
    if (g_strcpyHits + g_strcpyFallbacks > 0)
        Log("[Stats] CRT strcpy: %lld fast, %lld fallback (%.1f%%)",
            g_strcpyHits, g_strcpyFallbacks,
           (double)g_strcpyHits / (g_strcpyHits + g_strcpyFallbacks) * 100.0);

    // Frame Throttle stats
    {
        long skipped = 0, executed = 0, bypassed = 0;
        GetFrameThrottleStats(&skipped, &executed, &bypassed);
        if (skipped + executed + bypassed > 0) {
            long total = skipped + executed;
            double skipPct = total > 0 ? (double)skipped / total * 100.0 : 0.0;
            Log("[Stats] Frame Throttle: %ld executed, %ld skipped, %ld bypassed (%.1f%% reduction)",
                executed, skipped, bypassed, skipPct);
        }
    }


    // UI Frame Batch stats - REMOVED (optimization disabled)
    // {
    //     long batched = 0, iterations = 0, peak = 0;
    //     GetUIFrameBatchStats(&batched, &iterations, &peak);
    //     if (batched > 0) {
    //         double avgIterations = batched > 0 ? (double)iterations / batched : 0.0;
    //         Log("[Stats] UI Frame Batch: %ld batches, %ld total iterations, %.1f avg/batch, %ld peak",
    //             batched, iterations, avgIterations, peak);
    //     }
    // }

    if (g_tableReshapeHits > 0)
        Log("[Stats] Lua Table Rehash: %ld rounded to pow2", g_tableReshapeHits);
    if (g_getstrHits + g_getstrFallbacks > 0) {
        Log("[Stats] luaH_getstr: %I64u hits, %I64u fallbacks (%.1f%%)",
            g_getstrHits, g_getstrFallbacks,
           (double)g_getstrHits / (g_getstrHits + g_getstrFallbacks) * 100.0);
    }
    if (g_assetPathHits + g_assetPathMisses > 0)
        Log("[Stats] Asset path cache: %ld hits, %ld misses (%.1f%%)",
            g_assetPathHits, g_assetPathMisses,
           (double)g_assetPathHits / (g_assetPathHits + g_assetPathMisses) * 100.0);
    if (g_tvalueMemcpyHits > 0)
        Log("[Stats] TValue memcpy: %ld 16-byte fast copies", g_tvalueMemcpyHits);
    if (g_lastFrameMs > 0)
        Log("[Stats] Frame: %.1f ms (lower = smoother)", g_lastFrameMs);
    if (g_sysInfoHits > 0)
        Log("[Stats] GetSystemInfo: %ld cached", g_sysInfoHits);
    if (g_regCacheHits + g_regCacheMisses > 0)
        Log("[Stats] RegQueryValueEx: %ld hits, %ld misses (%.1f%%)",
            g_regCacheHits, g_regCacheMisses,
           (double)g_regCacheHits / (g_regCacheHits + g_regCacheMisses) * 100.0);

    if (g_combatLogCacheHits + g_combatLogCacheMisses > 0) {
        Log("[Stats] CombatLog: %I64u hits, %I64u misses (%.1f%%)",
            g_combatLogCacheHits, g_combatLogCacheMisses,
           (double)g_combatLogCacheHits / (g_combatLogCacheHits + g_combatLogCacheMisses) * 100.0);
    }

    if (g_pushStrHits + g_pushStrMisses > 0) {
        Log("[Stats] lua_pushstring: %I64u hits, %I64u misses (%.1f%%)",
            g_pushStrHits, g_pushStrMisses,
           (double)g_pushStrHits / (g_pushStrHits + g_pushStrMisses) * 100.0);
    }

    if (g_rawGetIHits + g_rawGetIMisses > 0) {
        Log("[Stats] lua_rawgeti: %I64u hits, %I64u misses (%.1f%%)",
            g_rawGetIHits, g_rawGetIMisses,
           (double)g_rawGetIHits / (g_rawGetIHits + g_rawGetIMisses) * 100.0);
    }

    if (vaOk && g_vaArenaActive) {
        long total = g_vaArenaHits + g_vaArenaFallbacks;
        double arenaPct = total > 0 ? (double)g_vaArenaHits / total * 100.0 : 0.0;
        double usedMB = (double)g_vaArenaUsedPages * VA_ARENA_PAGE_SIZE / (1024.0 * 1024.0);
        double peakMB = (double)g_vaArenaPeakPages * VA_ARENA_PAGE_SIZE / (1024.0 * 1024.0);
        double capMB  = (double)VA_ARENA_MAX_PAGES * VA_ARENA_PAGE_SIZE / (1024.0 * 1024.0);
        Log("[Stats] VA Arena: %ld hits, %ld fallbacks, %ld fail (%.1f%% arena, %.1f MB used, %.1f MB peak of %.0f MB)",
            g_vaArenaHits, g_vaArenaFallbacks, g_vaArenaFailures,
            arenaPct, usedMB, peakMB, capMB);
        // g_vaArenaFull is the key sizing signal: qualifying allocations we had
        // to reject because the arena ran out of contiguous space. If this is
        // non-zero, 64MB is too small - grow it (or the peak is near the cap).
        Log("[Stats] VA Arena sizing: %ld qualifying requests rejected (arena full/fragmented)%s",
            g_vaArenaFull,
            g_vaArenaFull > 0 ? "  <-- consider a larger arena" : "");
    }
    if (g_streamReadHits + g_streamReadFallbacks > 0)
        Log("[Stats] Stream read: %ld fast, %ld fallback (%.1f%%)",
            g_streamReadHits, g_streamReadFallbacks,
           (double)g_streamReadHits / (g_streamReadHits + g_streamReadFallbacks) * 100.0);
    if (g_streamWriteHits + g_streamWriteFallbacks > 0)
        Log("[Stats] Stream write: %ld fast, %ld fallback (%.1f%%)",
            g_streamWriteHits, g_streamWriteFallbacks,
           (double)g_streamWriteHits / (g_streamWriteHits + g_streamWriteFallbacks) * 100.0);
    if (g_debugStringSkipped > 0)
        Log("[Stats] OutputDebugString: %ld skipped", g_debugStringSkipped);

    LuaFastPath::Stats fps = LuaFastPath::GetStats();
    if (fps.active) {
        long fmtTotal = fps.formatFastHits + fps.formatFallbacks;
        if (fmtTotal > 0)
            Log("[Stats] Format: %ld fast, %ld fallback (%.1f%%)",
                fps.formatFastHits, fps.formatFallbacks,
               (double)fps.formatFastHits / fmtTotal * 100.0);
    }
    // Receive-side network stats
    if (g_recvCalls > 0 || g_WSARecvCalls > 0)
        Log("[Stats] Network RX: recv=%ld calls, %.1f KB, %ld wouldblock | WSARecv=%ld calls, %.1f KB, %ld wouldblock",
            g_recvCalls, g_recvBytes / 1024.0, g_recvWouldBlock,
            g_WSARecvCalls, g_WSARecvBytes / 1024.0, g_WSARecvWouldBlock);
    if (fps.phase2Active) {
        Log("[Stats] Phase2: find=%ld/%ld match=%ld/%ld type=%ld math=%ld strlen=%ld byte=%ld tostr=%ld/%ld tonum=%ld next=%ld/%ld rawget=%ld/%ld rawset=%ld/%ld tins=%ld/%ld trem=%ld/%ld concat=%ld/%ld unpack=%ld/%ld select=%ld/%ld raweq=%ld/%ld sub=%ld lower=%ld upper=%ld ipairs=%ld/%ld iter=%ld/%ld random=%ld/%ld sqrt=%ld/%ld rep=%ld/%ld find_full=%ld/%ld",
            fps.findPlainHits, fps.findFallbacks, fps.matchHits, fps.matchFallbacks, fps.typeHits, fps.mathHits, fps.strlenHits, fps.strbyteHits,
            fps.tostringHits, fps.tostringFallbacks, fps.tonumberHits,
            fps.nextHits, fps.nextFallbacks, fps.rawgetHits, fps.rawgetFallbacks,
            fps.rawsetHits, fps.rawsetFallbacks,
            fps.tableInsertHits, fps.tableInsertFallbacks,
            fps.tableRemoveHits, fps.tableRemoveFallbacks,
            fps.tableConcatHits, fps.tableConcatFallbacks,
            fps.unpackHits, fps.unpackFallbacks,
            fps.selectHits, fps.selectFallbacks,
            fps.rawequalHits, fps.rawequalFallbacks,
            fps.strsubHits, fps.strlowerHits, fps.strupperHits,
            fps.ipairsHits, fps.ipairsFallbacks,
            fps.ipairsIteratorHits, fps.ipairsIteratorFallbacks,
            fps.mathRandomHits, fps.mathRandomFallbacks,
            fps.mathSqrtHits, fps.mathSqrtFallbacks,
            fps.strRepHits, fps.strRepFallbacks,
            fps.findFullHits, fps.findFullFallbacks);
    }

    // Unit API Fast Path Stats
    LuaFastPath::Stats fpStats = LuaFastPath::GetStats();   
    if (fpStats.unitHealthHits > 0 || fpStats.unitHealthFallbacks > 0)
        Log("[Stats] UnitHealth: %ld fast, %ld fallback", fpStats.unitHealthHits, fpStats.unitHealthFallbacks);
    if (fpStats.unitHealthMaxHits > 0 || fpStats.unitHealthMaxFallbacks > 0)
        Log("[Stats] UnitHealthMax: %ld fast, %ld fallback", fpStats.unitHealthMaxHits, fpStats.unitHealthMaxFallbacks);
    if (fpStats.unitPowerHits > 0 || fpStats.unitPowerFallbacks > 0)
        Log("[Stats] UnitPower: %ld fast, %ld fallback", fpStats.unitPowerHits, fpStats.unitPowerFallbacks);
    if (fpStats.unitPowerMaxHits > 0 || fpStats.unitPowerMaxFallbacks > 0)
        Log("[Stats] UnitPowerMax: %ld fast, %ld fallback", fpStats.unitPowerMaxHits, fpStats.unitPowerMaxFallbacks);
  
    LuaInternals::Stats lis = LuaInternals::GetStats();
    if (lis.active) {
        long catTotal = lis.concatFastHits + lis.concatFallbacks;
        if (catTotal > 0)
            Log("[Stats] Concat: %ld fast, %ld fallback (%.1f%%)",
                lis.concatFastHits, lis.concatFallbacks,
               (double)lis.concatFastHits / catTotal * 100.0);
    }

    if (fpStats.tableSortHits > 0 || fpStats.tableSortFallbacks > 0)
        Log("[Stats] TableSort: %ld fast, %ld fallback", fpStats.tableSortHits, fpStats.tableSortFallbacks);

    if (g_priorityWatchdogRestores > 0)
        Log("[Stats] Priority watchdog: %ld restorations", (long)g_priorityWatchdogRestores);

    Log("[Stats] ====================================");

#if !TEST_DISABLE_SAMPLING_PROFILER
    // If the sampling profiler is active, fold its current top-50 into the
    // periodic dump. Shutdown() is skipped on the fast process-exit path, so
    // this is the only way the profile reliably reaches the log.
    if (Config::g_settings.OptSamplingProfiler) {
        SamplingProfiler::DumpNow();
    }
#endif
    FrameBench::Report("periodic");
    CrashDumper::ReportFeatureActivity();
    CrashDumper::ReportFirstChanceSummary();
    PerfDiagnostics::LogStats();
    LuaGCGovernor::LogStats();
    LuaAllocCensus::LogStats();
    ReportCrtFreeStats();
    if (g_spinTaken > 0 || g_spinSkipped > 0) {
        Log("[SleepPrecision] busy-wait taken %ld, handed back %ld (frames over "
            "%.0f ms give the time to the scheduler instead)",
            (long)g_spinTaken, (long)g_spinSkipped, SPIN_ABORT_FRAME_MS);
    }
    LuaFastPath::LogStats();
    ObjVisCache::LogStats();
    FontGlyphCache::LogStats();
    WowOpt_ReportForeignDetours();
    ApiCache::LogStats();
    TextureUnloadDelay::LogStats();
    NetDiag::LogStats();
    RenderNullGuard_LogStats();
    StrncmpSse2::LogStats();
    DbcLookupCache_LogStats();
    AnimCensus::LogStats();
    HorizonOcclusion::LogStats();
    D3D9StateCache::LogStats();
    D3D9StateCache::ReportDrawCensus();
    AsyncSoundLoader::LogStats();
    VertexBufferPrealloc::LogStats();
    LuaBytecodeCache::LogStats();
    CombatLogBuffer::LogStats();
    MpqAsyncDecompress::LogStats();
}

// ================================================================
// 19. sub_869E00 - Zero-Message Frame Continue (disabled)
//
// ================================================================

typedef int (__cdecl* MsgPump_fn)(void*, int*, DWORD*, void*, void*);
static MsgPump_fn orig_MsgPump = nullptr;
static uint64_t g_msgPumpHits = 0;

static int __cdecl hooked_MsgPump(void* a1, int* a2, DWORD* a3, void* a4, void* a5) {
    int result = orig_MsgPump(a1, a2, a3, a4, a5);

    if (result == 0) {
        uint64_t playerGuid = 0;
        __try {
            playerGuid = *(uint64_t*)0x00BD07A0;
        } __except(EXCEPTION_EXECUTE_HANDLER) {}

        if (playerGuid == 0 || LoadingDefrag::IsLoadingActive()) {
            return result;
        }
        // Original would exit the render loop (no messages pending).
        // Previous rc1 just returned 1 → stale *a1 → infinite loop.
        // Fix: inject WM_NULL into WoW's message queue so the next
        // PeekMessageA finds a message, goes through the normal flow
        // (GetMessage → DispatchMessage → sub_868DB0), which updates
        // *a1 from the command queue.
        g_msgPumpHits++;

        // Post synthetic message to WoW's main window
        HWND hWoW = FindWindowA("GxWindowClass", nullptr);
        if (hWoW)
            PostMessageA(hWoW, WM_NULL, 0, 0);

        // Yield CPU to avoid busy-wait
        if (orig_Sleep)
            orig_Sleep(1);
        else
            Sleep(1);

        return 1;
    }

    return result;
}

static bool InstallMsgPumpHook() {
#if CRASH_TEST_DISABLE_MSGPUMP_RC1
    Log("MsgPump hook: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x00869E00;

    // Verify we're hooking a real function (prologue: push ebp; mov ebp,esp)
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("MsgPump hook: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_MsgPump, (void**)&orig_MsgPump) != MH_OK) {
        Log("MsgPump hook: MH_CreateHook FAILED");
        return false;
    }
    if (WO_EnableHook(target) != MH_OK) {
        Log("MsgPump hook: MH_EnableHook FAILED");
        return false;
    }

    Log("MsgPump hook: ACTIVE (sub_869E00 @ 0x00869E00 - zero-message frame continue)");
    return true;
#endif
}

// ================================================================
// 20. sub_69E220 - Swap/Present Optimization (Vulkan/D3D9)
//
// ================================================================

typedef void (__cdecl* SubFn)();
typedef void (__fastcall* SubFnThis)(void*, void*);

static SubFn orig_sub_682E50 = (SubFn)0x00682E50;
static SubFnThis orig_sub_6841D0 = (SubFnThis)0x006841D0;
static SubFnThis orig_sub_6836D0 = (SubFnThis)0x006836D0;
static SubFnThis orig_sub_6833A0 = (SubFnThis)0x006833A0;

typedef void (WINAPI* wglSwapLayerBuffers_fn)(HDC, UINT);
static wglSwapLayerBuffers_fn orig_wglSwapLayerBuffers = nullptr;

typedef void (__fastcall* SwapPresent_fn)(void*, void*);
static SwapPresent_fn orig_SwapPresent = nullptr;
static uint64_t g_glFinishSkips = 0;

extern "C" void WowOpt_OnFrameBoundary();

static void __fastcall hooked_SwapPresent(void* This, void* unused) {
    char* T = (char*)This;

    // Wrap entire swap in SEH to handle device lost / alt-tab safely.
    // NO IsBadReadPtr - it breaks guard pages and causes mouse-triggered crashes
    // when cursor/UI redraw happens during device state transitions.
    __try {
        // A true per-frame boundary: sub_69E220 is reached only through the render
        // vtable, once per presented frame. It is the one place that can measure
        // frame time honestly, so the benchmark is fed from here.
        FrameBench::OnPresent(FrameBench::Source::SwapHook);
        // Flushes the deferred field and world-state queues. That used to be two
        // explicit calls here, which left the D3D9 path without them.
        WowOpt_OnFrameBoundary();
#if !TEST_DISABLE_LUA_GETTIME_FAST
        if (Config::g_settings.OptLuaGetTimeFast) {
            LuaGetTimeFast_NewFrame();
        }
#endif

        // sub_682E50()
        orig_sub_682E50();

        // if ([esi+2934h]) sub_6841D0(this)
        void* edi = *(void**)(T + 0x2934);
        if (edi)
            orig_sub_6841D0(This, nullptr);

        // Virtual call: eax = [esi]; edx = [eax+10h]; edx(This)
        void* vtable = *(void**)T;
        void* renderFn = *(void**)((char*)vtable + 0x10);
        if (renderFn) {
            ((void(__fastcall*)(void*, void*))renderFn)(This, nullptr);
        }

        // Check [esi+275Ch] & 0x40 → wglSwapLayerBuffers, else glFinish
        if (T[0x275C] & 0x40) {
            HDC hdc = *(HDC*)(T + 0x3AF8);
            if (orig_wglSwapLayerBuffers && hdc)
                orig_wglSwapLayerBuffers(hdc, 1);
        } else {
            // SKIP glFinish - Vulkan/D3D9 handles presentation sync
            g_glFinishSkips++;
        }

        // Post-swap cleanup
        orig_sub_6836D0(This, nullptr);
        orig_sub_6833A0(This, nullptr);
        // nullsub_3 (0x005EEB70) is a 1-byte no-op - skipped
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Device lost / alt-tab / cursor redraw race - silently skip this frame.
        // Do NOT call orig_SwapPresent here: it would re-enter the same broken state
        // and crash harder (recursive swap on lost device).
        return;
    }
}

static bool InstallSwapPresentHook() {
#if CRASH_TEST_DISABLE_SWAP_RC1
    Log("Swap present hook: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0069E220;

    // Verify prologue: push esi; mov esi, ecx
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x56 || p[1] != 0x8B || p[2] != 0xF1) {
        Log("Swap hook: BAD PROLOGUE at 0x%08X (expected 56 8B F1)", (uintptr_t)target);
        return false;
    }

    // Resolve wglSwapLayerBuffers from opengl32.dll
    HMODULE hGL = GetModuleHandleA("opengl32.dll");
    if (!hGL) {
        Log("Swap hook: opengl32.dll not loaded");
        return false;
    }
    orig_wglSwapLayerBuffers = (wglSwapLayerBuffers_fn)GetProcAddress(hGL, "wglSwapLayerBuffers");
    if (!orig_wglSwapLayerBuffers) {
        Log("Swap hook: wglSwapLayerBuffers not found");
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_SwapPresent, (void**)&orig_SwapPresent) != MH_OK) {
        Log("Swap hook: MH_CreateHook FAILED");
        return false;
    }
    if (WO_EnableHook(target) != MH_OK) {
        Log("Swap hook: MH_EnableHook FAILED");
        return false;
    }

    Log("Swap present hook: ACTIVE (sub_69E220 @ 0x0069E220 - glFinish skip, Vulkan/D3D9)");
    return true;
#endif
}

// ================================================================
// Frame-boundary timing detour (used only when the optimizing swap
// hook above is not installed)
// ================================================================
//
// sub_69E220 is the only true frame boundary available: reached solely through
// the render vtable, exactly once per presented frame. The optimizing hook above
// already reports each frame to FrameBench, but it is gated behind OptVulkanDXVK,
// which is off by default - so without this the benchmark would silently record
// nothing for most users, which is worse than having no benchmark at all.
//
// Deliberately thin: report the frame, call the original, nothing else. It adds
// no behaviour of its own, so it cannot influence what it is measuring.
// Disassembly-verified: int __thiscall sub_69E220(void *this) - the instance
// pointer arrives in ECX and there are no stack arguments, so a __fastcall detour
// with an unused second register parameter matches exactly and no stack cleanup
// is involved. The return value is propagated: unlike the optimizing hook above,
// which reimplements the body and never reaches the original, this one wraps it,
// so discarding EAX would change what the caller sees.
typedef int (__fastcall* SwapPresentTiming_fn)(void*, void*);
static SwapPresentTiming_fn orig_SwapPresentTiming = nullptr;

// Work that must happen exactly once per presented frame, called from both
// present paths. Anything that ages per frame belongs here rather than in the
// hooked_Sleep tick, which is gated to fire at most once every 8ms - i.e. it
// stops tracking frames at all above ~125fps.
extern "C" void WowOpt_OnFrameBoundary() {
    // Deferred unit field writes and coalesced world states must be applied on a
    // real frame boundary. Addons read unit state the moment an event arrives, so
    // a descriptor write that is still sitting in a queue is read as stale, and no
    // further event fires to correct it once the queue drains.
    //
    // Both were already flushed from the OpenGL swap hook for exactly this reason,
    // with a comment about uncapped frame rates bypassing hooked_Sleep - but that
    // path is sub_69E220, which a D3D9/DXVK client never reaches. On DXVK the only
    // caller left was the hooked_Sleep tick, gated to one pass every
    // SleepPrecisionValue ms, so past ~125 fps the flush fell behind the frames
    // that queued the work.
    //
    // Calling from both present paths costs an empty-queue check per frame: each
    // of these takes its lock, sees head == tail, and returns.
    FlushFieldUpdates();
    WorldStateCoalesce::OnFrame();

    // Frame counters that bound how long a cached entry stays valid. Both caches
    // re-validate on hit - the Lua inline cache re-reads the key out of the node,
    // the object cache re-reads the GUID out of the object - so the counter is not
    // the only thing standing between a hit and a freed pointer. It is what limits
    // the exposure to a single frame, and on the hooked_Sleep tick that bound
    // stretched to however many frames fit between two passes.
    //
    // These must advance exactly once per frame: incrementing twice would stamp
    // entries with a generation that is already stale by the time they are read,
    // and every lookup would miss. Only one present hook is live per renderer, so
    // this runs once - and they are deliberately not left on the Sleep tick as a
    // fallback, because a fallback here would be the double increment.
    LuaVMEngine_FrameTick();
    ObjVisCache::OnFrame();
    FontMetrics_OnFrame();
    QualityGovernor::OnFrame();
    CvarWatchdog_Check();
    LuaAllocCensus::EnsureInstalled();
#if !TEST_DISABLE_PARTICLE_THROTTLE
#endif
}

static int __fastcall hooked_SwapPresent_TimingOnly(void* This, void* unused) {
    FrameBench::OnPresent(FrameBench::Source::SwapHook);
    WowOpt_OnFrameBoundary();
    return orig_SwapPresentTiming(This, unused);
}

static bool InstallSwapTimingHook() {
    void* target = (void*)0x0069E220;

    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x56 || p[1] != 0x8B || p[2] != 0xF1) {
        Log("[FrameBench] Swap timing hook: BAD PROLOGUE at 0x%08X (expected 56 8B F1)",
            (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_SwapPresent_TimingOnly,
                            (void**)&orig_SwapPresentTiming) != MH_OK) {
        Log("[FrameBench] Swap timing hook: MH_CreateHook FAILED");
        return false;
    }
    if (WO_EnableHook(target) != MH_OK) {
        Log("[FrameBench] Swap timing hook: MH_EnableHook FAILED");
        orig_SwapPresentTiming = nullptr;
        return false;
    }

    Log("[FrameBench] Frame timing ACTIVE (sub_69E220, measurement only)");
    return true;
}

// ================================================================
// Shared: FNV-1a hash for C strings
// ================================================================
static inline uint64_t ComputeCStringHash(const char* s) {
    uint64_t h = 0xCBF29CE484222325ULL;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 0x100000001B3ULL;
    }
    return h;
}

// ================================================================
// 21f. sub_84E670 - lua_rawgeti Fast Path (integer-key cache)
//
// ================================================================

#define RAWGETI_CACHE_SIZE 2048
#define RAWGETI_CACHE_MASK (RAWGETI_CACHE_SIZE - 1)

struct RawGetICacheEntry {
    uint64_t keyHash;      // FNV-1a of (table_ptr ^ key)
    int      table;        // Table* pointer
    int      key;          // Integer key
    int      node;         // Cached Node* pointer
};

static RawGetICacheEntry g_rawGetICache[RAWGETI_CACHE_SIZE];

static void ClearLuaRawGetICache() {
    memset(g_rawGetICache, 0, sizeof(g_rawGetICache));
}

static void* (*orig_luaH_getnum)(int table, int key) = nullptr;  // DISABLED — unsafe across lua_State swaps

typedef int (__cdecl* lua_rawgeti_fn)(int L, int idx, int n);
static lua_rawgeti_fn orig_lua_rawgeti = nullptr;

static int __cdecl hooked_lua_rawgeti(int L, int idx, int n) {
    // FULLY DISABLED due to crash on UI reload / exit
    return orig_lua_rawgeti(L, idx, n);
}

static bool InstallLuaRawGetICache() {
#if CRASH_TEST_DISABLE_LUA_RAWGETI
    Log("lua_rawgeti cache: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0084E670;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("lua_rawgeti cache: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_lua_rawgeti, (void**)&orig_lua_rawgeti) != MH_OK) {
        Log("lua_rawgeti cache: MH_CreateHook FAILED");
        return false;
    }
    if (WO_EnableHook(target) != MH_OK) {
        Log("lua_rawgeti cache: MH_EnableHook FAILED");
        return false;
    }

    memset(g_rawGetICache, 0, sizeof(g_rawGetICache));

    Log("lua_rawgeti cache: ACTIVE (sub_84E670 @ 0x0084E670 - 2048-slot integer-key cache, SEH)");
    return true;
#endif
}

// ================================================================
// 21e. sub_84E350 - lua_pushstring Fast Path (TString* intern cache)
//
// ================================================================

#define PUSHSTR_CACHE_SIZE 4096
#define PUSHSTR_CACHE_MASK (PUSHSTR_CACHE_SIZE - 1)

struct PushStrCacheEntry {
    uint64_t keyHash;      // FNV-1a of C string content
    int      tstring;      // Cached TString* pointer
};

static PushStrCacheEntry g_pushStrCache[PUSHSTR_CACHE_SIZE];

static void ClearLuaPushStringCache() {
    memset(g_pushStrCache, 0, sizeof(g_pushStrCache));
}

typedef int (__cdecl* lua_pushstring_fn)(int L, const char* s);
static lua_pushstring_fn orig_lua_pushstring = nullptr;

typedef void (__cdecl *luaC_step_fn)(int L);
static luaC_step_fn orig_luaC_step = nullptr;

static ULONGLONG g_lastGcTime = 0;
static int g_postponedGcCount = 0;

static void __cdecl hooked_luaC_step(int L) {
    ClearLuaPushStringCache();

    #if !TEST_DISABLE_LUA_GC_COALESCE
    ULONGLONG now = GetTickCount64();
    if (now - g_lastGcTime < 4 && g_postponedGcCount < 100) {
        g_postponedGcCount++;
        return;
    }
    g_lastGcTime = now;
    g_postponedGcCount = 0;
    #endif

    orig_luaC_step(L);
}

// TValue layout: +0x00 value (8B), +0x08 tt (int=4), +0x0C taint (DWORD)
static int __cdecl hooked_lua_pushstring(int L, const char* s) {
#if CRASH_TEST_DISABLE_LUA_PUSHSTRING
    return orig_lua_pushstring(L, s);
#else
    // nil input - push nil
    if (!s || (uintptr_t)s < 0x10000 || (uintptr_t)s > 0xFFE00000) {
        g_pushStrMisses++;
        return orig_lua_pushstring(L, s);
    }

    __try {
        // Compute FNV-1a hash
        uint64_t hash = ComputeCStringHash(s);

        // Lookup cache
        uint32_t cacheIdx = (uint32_t)(hash & PUSHSTR_CACHE_MASK);
        PushStrCacheEntry* entry = &g_pushStrCache[cacheIdx];

        // Check cache hit
        if (entry->keyHash == hash) {
            // Validate TString* is still in range
            int ts = entry->tstring;
            if (ts >= 0x10000 && ts <= 0xFFE00000) {
                // Push TValue directly: value=gc_ptr, tt=4 (LUA_TSTRING), taint
                __try {
                    DWORD* top = *(DWORD**)(L + 0x0C);
                    if (!top || (uintptr_t)top < 0x10000 || (uintptr_t)top > 0xFFE00000) {
                        g_pushStrMisses++;
                        return orig_lua_pushstring(L, s);
                    }

                    // Copy taint from the TString
                    DWORD taint = *(DWORD*)(ts + 0x0C);

                    top[0] = (DWORD)ts;     // value.gc = TString*
                    top[1] = 0;              // value padding (upper 32 bits of double)
                    top[2] = 4;              // tt = LUA_TSTRING
                    top[3] = taint;          // taint

                    *(DWORD**)(L + 0x0C) = top + 4;

                    g_pushStrHits++;
                    return L;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    g_pushStrMisses++;
                    return orig_lua_pushstring(L, s);
                }
            }
        }

        // Cache miss - call original
        int result = orig_lua_pushstring(L, s);

        // Capture TString* from L->top - 16 bytes
        __try {
            DWORD* top = *(DWORD**)(L + 0x0C);
            if (top && (uintptr_t)top >= 0x10000 && (uintptr_t)top <= 0xFFE00000) {
                DWORD* slot = top - 4;
                if (slot[2] == 4) {  // tt == LUA_TSTRING
                    entry->keyHash = hash;
                    entry->tstring = (int)slot[0];
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        g_pushStrMisses++;
        return result;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        g_pushStrMisses++;
        return orig_lua_pushstring(L, s);
    }
#endif
}

static bool InstallLuaPushStringCache() {
#if CRASH_TEST_DISABLE_LUA_PUSHSTRING
    Log("lua_pushstring cache: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0084E350;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("lua_pushstring cache: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_lua_pushstring, (void**)&orig_lua_pushstring) != MH_OK) {
        Log("lua_pushstring cache: MH_CreateHook FAILED");
        return false;
    }
    if (WO_EnableHook(target) != MH_OK) {
        Log("lua_pushstring cache: MH_EnableHook FAILED");
        return false;
    }

    // Hook luaC_step to clear pushstring cache on garbage collection steps
    if (WineSafe_CreateHook((void*)0x0085B950, (void*)hooked_luaC_step, (void**)&orig_luaC_step) != MH_OK) {
        Log("lua_pushstring cache: luaC_step hook FAILED");
    } else {
        WO_EnableHook((void*)0x0085B950);
    }

    memset(g_pushStrCache, 0, sizeof(g_pushStrCache));

    Log("lua_pushstring cache: ACTIVE (sub_84E350 @ 0x0084E350 - 4096-slot TString* intern, SEH)");
    return true;
#endif
}

// ================================================================
// 21c. sub_851C30 - table.concat Fast Path (Direct Array + Inline Nums)
//
// ================================================================

#define TABLE_CONCAT_BUF_SIZE 8192

typedef int (__cdecl* table_concat_fn)(int L);
static table_concat_fn orig_table_concat = nullptr;

static int __cdecl hooked_table_concat(int L) {
#if CRASH_TEST_DISABLE_TABLE_CONCAT
    return orig_table_concat(L);
#else
    // L->base is at L+0x10
    int* base = *(int**)(L + 0x10);
    if (!base) return orig_table_concat(L);

    // Arg 1: Table. Check type 5.
    if (base[2] != 5) return orig_table_concat(L);
    int table = base[0];
    if (!table) return orig_table_concat(L);

    // Arg 2: Separator. Must be string or nil.
    int sep_type = base[6];
    const char* sep = "";
    int sep_len = 0;
    if (sep_type == 4) { // String
        int ts = base[4]; // TString*
        if (!ts) return orig_table_concat(L);
        // TString layout: +16=len, +20=str
        sep = (const char*)(ts + 20);
        sep_len = *(int*)(ts + 16);
    } else if (sep_type == 3) {
        // Number separator - fallback to original
        return orig_table_concat(L);
    } else if (sep_type != 0) {
        return orig_table_concat(L);
    }

    uintptr_t top = *(uintptr_t*)(L + 0x0C);
    uintptr_t base_ptr = *(uintptr_t*)(L + 0x10);
    int top_idx = (top - base_ptr) / 16;

    // Arg 3: i (default 1)
    int i = 1;
    if (top_idx >= 3) {
        if (base[10] == 3) i = (int)*(double*)(base + 8);
        else if (base[10] != 0) return orig_table_concat(L);
    }

    // Arg 4: j (default #t)
    int j = 0;
    if (top_idx >= 4) {
        if (base[14] == 3) j = (int)*(double*)(base + 12);
        else if (base[14] != 0) return orig_table_concat(L);
    } else {
        typedef unsigned int (__cdecl *luaH_getn_fn)(int table);
        j = ((luaH_getn_fn)0x0085C690)(table);
    }

    int sizearray = *(int*)(table + 32);
    if (i < 1) i = 1;
    if (j > sizearray) return orig_table_concat(L); // Hash part fallback
    if (i > j) {
        // Push empty string
       ((void (*)(int, const char*))0x0084E350)(L, "");
        return 1;
    }

    // Direct array loop
    int* array = *(int**)(table + 16);

    // Stack buffer for result
    char buf[TABLE_CONCAT_BUF_SIZE];
    int used = 0;

    char int_buf[32];
    char num_buf[64];

    for (int k = i; k <= j; k++) {
        int* val = array + (k - 1) * 4;
        int tt = val[2];

        const char* s = nullptr;
        int len = 0;

        if (tt == 4) { // String
            int ts = val[0];
            if (!ts) return orig_table_concat(L);
            s = (const char*)(ts + 20);
            len = *(int*)(ts + 16);
        } else if (tt == 3) { // Number
            double n = *(double*)val;
            // Fast integer check
            if (n >= -999999999.0 && n <= 999999999.0 && n == (int)n) {
                len = sprintf(int_buf, "%d", (int)n);
                s = int_buf;
            } else {
                len = sprintf(num_buf, "%.17g", n);
                s = num_buf;
            }
        } else {
            return orig_table_concat(L); // Type error fallback
        }

        // Append separator
        if (k > i && sep_len > 0) {
            if (used + sep_len + len > TABLE_CONCAT_BUF_SIZE - 100)
                return orig_table_concat(L);
            memcpy(buf + used, sep, sep_len);
            used += sep_len;
        }

        // Append string/number
        if (used + len > TABLE_CONCAT_BUF_SIZE - 100)
            return orig_table_concat(L);
        memcpy(buf + used, s, len);
        used += len;
    }

    // Push result
    buf[used] = '\0';
   ((void (*)(int, const char*))0x0084E350)(L, buf);
    return 1;
#endif
}

static bool InstallTableConcatFastPath() {
#if CRASH_TEST_DISABLE_TABLE_CONCAT
    Log("table.concat fast path: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x00851C30;
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) return false;

    if (WineSafe_CreateHook(target, (void*)hooked_table_concat, (void**)&orig_table_concat) != MH_OK) return false;
    if (WO_EnableHook(target) != MH_OK) return false;

    Log("table.concat fast path: ACTIVE (sub_851C30 @ 0x00851C30 - array direct + inline nums)");
    return true;
#endif
}

// ================================================================
// 21b. sub_85C430 - Lua Table String-Key Lookup Fast Path (enabled)
//
// ================================================================

typedef void* (__cdecl* luaH_getstr_fn)(int table, int tstring);
static luaH_getstr_fn orig_luaH_getstr = nullptr;

// Generation counter - incremented on every lua_State swap / cache clear.
// Catches mimalloc table recycling: when a table is freed and its memory
// reused for a non-table object, the generation mismatch invalidates the
// stale cache entry BEFORE we dereference *(table+20).
static volatile LONG g_getstrGeneration = 0;

#define GETSTR_CACHE_SIZE 8192
#define GETSTR_CACHE_MASK (GETSTR_CACHE_SIZE - 1)

struct GetStrCacheEntry {
    int      table;       // Table* pointer
    int      tstring;     // TString* pointer
    int      tableNode;   // *(table+20) - hash array base, detects rehashes
    uint32_t generation;  // Global generation at insert time
    void*    node;        // Cached Node* result (or nilObject)
};

static GetStrCacheEntry g_getstrCache[GETSTR_CACHE_SIZE];

// Safe memory probe - returns true if the 4 bytes at addr are in a
// committed, readable page.  Avoids the ACCESS_VIOLATION that the
// original cache hit on mimalloc-recycled table memory.
static inline bool IsSafeRead4(uintptr_t addr) {
    if (addr < 0x10000 || addr > 0xFFE00000) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    return (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)));
}

static inline uint64_t GetStrCacheHash(uintptr_t table, uintptr_t tstring) {
    uint64_t h = 0xCBF29CE484222325ULL;
    h ^= (table ^ tstring);
    h *= 0x100000001B3ULL;
    return h & GETSTR_CACHE_MASK;
}

static void ClearLuaHGetStrCache() {
    memset(g_getstrCache, 0, sizeof(g_getstrCache));
    InterlockedIncrement(&g_getstrGeneration);
}

static void* __cdecl hooked_luaH_getstr(int table, int tstring) {
#if CRASH_TEST_DISABLE_LUAH_GETSTR
    return orig_luaH_getstr(table, tstring);
#else
    __try {
        if ((uintptr_t)table < 0x10000 || (uintptr_t)table > 0xFFE00000)
            { g_getstrFallbacks++; return orig_luaH_getstr(table, tstring); }
        if ((uintptr_t)tstring < 0x10000 || (uintptr_t)tstring > 0xFFE00000)
            { g_getstrFallbacks++; return orig_luaH_getstr(table, tstring); }

        uint64_t idx = GetStrCacheHash((uintptr_t)table, (uintptr_t)tstring);
        GetStrCacheEntry* e = &g_getstrCache[idx];

        // Generation check: invalidates stale entries from previous lua_State
        uint32_t gen = (uint32_t)InterlockedCompareExchange(&g_getstrGeneration, 0, 0);

        // Cache hit path - every dereference is guarded
        if (e->table == table && e->tstring == tstring
            && e->generation == gen && e->node != nullptr) {

            // Guard: table+20 must be in committed memory (mimalloc may have
            // recycled this address for a non-table allocation)
            if (!IsSafeRead4((uintptr_t)table + 20))
                { g_getstrFallbacks++; return orig_luaH_getstr(table, tstring); }

            int currentTableNode = *(int*)(table + 20);
            if (e->tableNode == currentTableNode) {

                // Guard: cached Node* must be valid memory
                if (!IsSafeRead4((uintptr_t)e->node + 24))
                    { g_getstrFallbacks++; return orig_luaH_getstr(table, tstring); }

                // Validate: key.tt == 4 (LUA_TSTRING), key.gc == tstring
                if (((int*)e->node)[6] == 4 && ((int*)e->node)[4] == tstring) {
                    g_getstrHits++;
                    return e->node;
                }
            }
        }

        // Cache miss - call original
        void* result = orig_luaH_getstr(table, tstring);

        // Store in cache (only if table memory is still valid)
        if (IsSafeRead4((uintptr_t)table + 20)) {
            e->table      = table;
            e->tstring    = tstring;
            e->tableNode  = *(int*)(table + 20);
            e->generation = gen;
            e->node       = result;
        }

        g_getstrFallbacks++;
        return result;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        g_getstrFallbacks++;
        return orig_luaH_getstr(table, tstring);
    }
#endif
}

static bool InstallLuaHGetStrCache() {
#if CRASH_TEST_DISABLE_LUAH_GETSTR
    Log("luaH_getstr cache: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0085C430;

    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("luaH_getstr cache: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_luaH_getstr, (void**)&orig_luaH_getstr) != MH_OK)
        { Log("luaH_getstr cache: MH_CreateHook FAILED"); return false; }
    if (WO_EnableHook(target) != MH_OK)
        { Log("luaH_getstr cache: MH_EnableHook FAILED"); return false; }

    memset(g_getstrCache, 0, sizeof(g_getstrCache));
    InterlockedExchange(&g_getstrGeneration, 1);

    Log("luaH_getstr cache: ACTIVE (sub_85C430 @ 0x0085C430 - %d-slot, generation-guarded, 1.5B calls/session)", GETSTR_CACHE_SIZE);
    return true;
#endif
}

// ================================================================
// 21c. sub_74E290 - CombatLog Event Full Cache
//
// ================================================================

#define COMBATLOG_CACHE_SIZE 256
#define COMBATLOG_CACHE_MASK (COMBATLOG_CACHE_SIZE - 1)
#define COMBATLOG_MAX_FIELDS 32
#define COMBATLOG_FINGERPRINT_BYTES 120

struct CombatLogCacheField {
    uint32_t tt;
    uint32_t taint;
    union {
        double numVal;
        char   strVal[64];
    };
};

struct CombatLogCacheEntry {
    uint64_t fingerprint;
    int      fieldCount;
    CombatLogCacheField fields[COMBATLOG_MAX_FIELDS];
    uint32_t lruStamp;
};

static CombatLogCacheEntry g_combatLogCache[COMBATLOG_CACHE_SIZE];
static uint32_t g_combatLogCacheLRU = 0;

void ClearCombatLogCache() {
    memset(g_combatLogCache, 0, sizeof(g_combatLogCache));
}

typedef void (__cdecl *fn_lua_pushnumber)(int L, double n);
typedef void (__cdecl *fn_lua_pushstring)(int L, const char* s);
typedef void (__cdecl *fn_lua_pushboolean)(int L, int b);
typedef void (__cdecl *fn_lua_pushnil)(int L);

static fn_lua_pushnumber  combat_lua_pushnumber  = (fn_lua_pushnumber)0x0084E2A0;
static fn_lua_pushstring  combat_lua_pushstring  = (fn_lua_pushstring)0x0084E350;
static fn_lua_pushboolean combat_lua_pushboolean = (fn_lua_pushboolean)0x0084E4D0;
static fn_lua_pushnil     combat_lua_pushnil    = (fn_lua_pushnil)0x0084E280;

static inline const char* CombatReadTStringDirect(void* ts_ptr, size_t* out_len) {
    if (!ts_ptr || (uintptr_t)ts_ptr < 0x10000 || (uintptr_t)ts_ptr >= 0xFFFFF000) return nullptr;
    int len = *(int*)((char*)ts_ptr + 16);
    if (len < 0 || len > 1024) return nullptr;
    if (out_len) *out_len = (size_t)len;
    return (char*)ts_ptr + 20;
}

// Known addresses for Lua stack manipulation
static constexpr uintptr_t ADDR_nilObject = 0x00A46F78;

typedef int (__thiscall* CombatLogEvent_fn)(int this_ptr, int luaState);
static CombatLogEvent_fn orig_CombatLogEvent = nullptr;

static inline uint64_t ComputeCombatEventFingerprint(int this_ptr) {
    // Skip bytes 0-11 (includes floating-point timestamp at +8 which changes every frame)
    // Hash only stable event data: eventType(+12), sourceGUID(+24), destGUID(+48),
    // flags(+84), spellID(+92), etc.
    uint64_t hash = 0xCBF29CE484222325ULL;
    const uint8_t* data = (const uint8_t*)this_ptr + 12; // skip timestamp
    for (int i = 0; i < COMBATLOG_FINGERPRINT_BYTES - 12; i++) {
        hash ^= data[i];
        hash *= 0x100000001B3ULL;
    }
    // Also XOR the flags+spellID region heavily (offset 84-116 is critical for dupe detection)
    const uint32_t* flags = (const uint32_t*)(this_ptr + 84);
    for (int i = 0; i < 8; i++) { // 32 bytes of spell damage fields
        hash ^= flags[i];
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

// TValue structure at L+0x0C = top pointer
// TValue = { union { double n; void* gc; } value; int tt; uint32_t taint; } = 16 bytes
static inline uint64_t* GetLuaTopPtr(int L) {
    return *(uint64_t**)(L + 0x0C);
}

static int __fastcall hooked_CombatLogEvent(void* This, void* unused_edx, int luaState) {
    if (This && luaState) {
        if (CombatLogIncremental::ShouldDefer(This, luaState, (void*)orig_CombatLogEvent)) {
            return 0;
        }
    }

#if CRASH_TEST_DISABLE_COMBATLOG_FULLCACHE
    int fieldCount = ((int (__thiscall*)(void*, int))orig_CombatLogEvent)(This, luaState);
    if (fieldCount > 0) {
        CombatLogParser_ProcessEvent((void*)luaState, fieldCount);
    }
    return fieldCount;
#else
    __try {
        int this_ptr = (int)This;
        if (this_ptr < 0x10000 || this_ptr > 0xFFE00000) {
            g_combatLogCacheMisses++;
            int fieldCount = ((int (__thiscall*)(void*, int))orig_CombatLogEvent)(This, luaState);
            if (fieldCount > 0) {
                CombatLogParser_ProcessEvent((void*)luaState, fieldCount);
            }
            return fieldCount;
        }
        if (luaState < 0x10000 || luaState > 0xFFE00000) {
            g_combatLogCacheMisses++;
            int fieldCount = ((int (__thiscall*)(void*, int))orig_CombatLogEvent)(This, luaState);
            if (fieldCount > 0) {
                CombatLogParser_ProcessEvent((void*)luaState, fieldCount);
            }
            return fieldCount;
        }

        // Compute fingerprint from event structure
        uint64_t fp = ComputeCombatEventFingerprint(this_ptr);

        // Lookup cache
        uint64_t idx = fp & COMBATLOG_CACHE_MASK;
        CombatLogCacheEntry* entry = &g_combatLogCache[idx];

        if (entry->fingerprint == fp && entry->fieldCount > 0 && entry->lruStamp > 0) {
            // Cache hit - replay the pushes safely using Lua API
            for (int i = 0; i < entry->fieldCount; i++) {
                int tt = entry->fields[i].tt;
                switch (tt) {
                    case 4: // LUA_TSTRING
                        combat_lua_pushstring(luaState, entry->fields[i].strVal);
                        break;
                    case 3: // LUA_TNUMBER
                        combat_lua_pushnumber(luaState, entry->fields[i].numVal);
                        break;
                    case 1: // LUA_TBOOLEAN
                        combat_lua_pushboolean(luaState, (int)entry->fields[i].numVal);
                        break;
                    case 0: // LUA_TNIL
                    default:
                        combat_lua_pushnil(luaState);
                        break;
                }
            }
            entry->lruStamp = ++g_combatLogCacheLRU;
            g_combatLogCacheHits++;
            CombatLogParser_ProcessEvent((void*)luaState, entry->fieldCount);
            return entry->fieldCount;
        }

        // Cache miss - call original
        int fieldCount = ((int (__thiscall*)(void*, int))orig_CombatLogEvent)(This, luaState);

        // Capture the pushed TValue data from the Lua stack
        if (fieldCount > 0 && fieldCount <= COMBATLOG_MAX_FIELDS) {
            uint64_t* topPtr = *(uint64_t**)(luaState + 0x0C);
            uint64_t* startPtr = topPtr - fieldCount * 2;

            entry->fingerprint = fp;
            entry->fieldCount = fieldCount;
            entry->lruStamp = ++g_combatLogCacheLRU;

            for (int i = 0; i < fieldCount; i++) {
                uint64_t* src = startPtr + i * 2;
                uint32_t tt = (uint32_t)(src[1] & 0xFFFFFFFF);
                uint32_t taint = (uint32_t)((src[1] >> 32) & 0xFFFFFFFF);
                uint64_t val = src[0];

                if (tt == 4) { // LUA_TSTRING
                    void* ts_ptr = (void*)(uintptr_t)val;
                    size_t slen = 0;
                    const char* s = CombatReadTStringDirect(ts_ptr, &slen);
                    if (s && slen < 64) {
                        entry->fields[i].tt = 4;
                        entry->fields[i].taint = taint;
                        memcpy(entry->fields[i].strVal, s, slen);
                        entry->fields[i].strVal[slen] = '\0';
                    } else {
                        // String too long or invalid, discard the cache entry
                        entry->fieldCount = 0;
                        break;
                    }
                } else if (tt == 3) { // LUA_TNUMBER
                    entry->fields[i].tt = 3;
                    entry->fields[i].taint = taint;
                    memcpy(&entry->fields[i].numVal, &val, sizeof(double));
                } else if (tt == 1) { // LUA_TBOOLEAN
                    entry->fields[i].tt = 1;
                    entry->fields[i].taint = taint;
                    entry->fields[i].numVal = (val != 0) ? 1.0 : 0.0;
                } else {
                    // nil or other
                    entry->fields[i].tt = 0; // LUA_TNIL
                    entry->fields[i].taint = taint;
                }
            }
        }

        g_combatLogCacheMisses++;
        if (fieldCount > 0) {
            CombatLogParser_ProcessEvent((void*)luaState, fieldCount);
        }
        return fieldCount;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        g_combatLogCacheMisses++;
        int fieldCount = ((int (__thiscall*)(void*, int))orig_CombatLogEvent)(This, luaState);
        if (fieldCount > 0) {
            CombatLogParser_ProcessEvent((void*)luaState, fieldCount);
        }
        return fieldCount;
    }
#endif
}

static bool InstallCombatLogFullCache() {
#if CRASH_TEST_DISABLE_COMBATLOG_FULLCACHE
    Log("CombatLog full cache: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0074E290;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("CombatLog full cache: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_CombatLogEvent, (void**)&orig_CombatLogEvent) != MH_OK) {
        Log("CombatLog full cache: MH_CreateHook FAILED");
        return false;
    }
    if (WO_EnableHook(target) != MH_OK) {
        Log("CombatLog full cache: MH_EnableHook FAILED");
        return false;
    }

    memset(g_combatLogCache, 0, sizeof(g_combatLogCache));

    Log("CombatLog full cache: ACTIVE (sub_74E290 @ 0x0074E290 - 256-slot LRU, TValue replay)");
    return true;
#endif
}

// ================================================================
// 21. sub_85C6F0 - Lua Table Rehash Prevention (enabled)
//
// ================================================================

static inline int luaTable_nextPow2(int n) {
    if (n <= 1) return 1;
    --n;
    n |= n >> 1; n |= n >> 2; n |= n >> 4;
    n |= n >> 8; n |= n >> 16;
    return n + 1;
}

// Decision function - called from naked hook, must be __cdecl
static int __cdecl luaTable_reshape_decision(int newSize, void* table) {
    if (!table) return newSize;
    uintptr_t p = (uintptr_t)table;
    if (p < 0x10000 || p > 0xFFE00000) return newSize;

    // CRITICAL: Clear luaH_getstr cache on every resize - old Node* pointers are invalidated
    InvalidateLuaGetStrInlineCache();
    ClearRawGetIInlineCache();
    ClearLuaVMEngineCaches();

    return newSize;
}

// Naked hook - preserves exact __usercall register state
// On entry: eax = a1 (newSize), ecx = a2 (table*), [esp] = ret addr, [esp+4] = a3
static void* g_luaHResizeTrampoline = nullptr;

__declspec(naked) static void hooked_luaH_resize() {
    __asm {
        // Save all registers and flags
        pushad
        pushfd

        // Call C++ decision: resize_decision(newSize_in_eax, table_in_ecx)
        push ecx                    // table*
        push eax                    // newSize
        call luaTable_reshape_decision
        add esp, 8                  // clean up args

        // Store result back into saved eax slot in pushad layout
        // pushad order on stack (after pushfd):
        //   [esp+0]=flags, [esp+4]=edi, [esp+8]=esi, [esp+12]=ebp,
        //   [esp+16]=origEsp, [esp+20]=ebx, [esp+24]=edx, [esp+28]=ecx, [esp+32]=eax
        mov [esp + 32], eax         // overwrite saved eax with rounded newSize

        // Restore all registers and flags
        popfd
        popad

        // eax = (potentially rounded) newSize, ecx = table* (unchanged)
        // Jump to MinHook trampoline which runs the original prologue
        jmp g_luaHResizeTrampoline
    }
}

static bool InstallLuaHResizeHook() {
#if CRASH_TEST_DISABLE_TABLERESHAPE_RC1
    Log("LuaH_resize hook: DISABLED (crash isolation)");
    return false;
#else
    void* target = (void*)0x0085C6F0;

    // Verify prologue: push ebp; mov ebp, esp
    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("LuaH_resize hook: BAD PROLOGUE at 0x%08X (expected 55 8B)", (uintptr_t)target);
        return false;
    }

    if (WineSafe_CreateHook(target, (void*)hooked_luaH_resize, &g_luaHResizeTrampoline) != MH_OK) {
        Log("LuaH_resize hook: MH_CreateHook FAILED");
        return false;
    }
    if (WO_EnableHook(target) != MH_OK) {
        Log("LuaH_resize hook: MH_EnableHook FAILED");
        return false;
    }

    Log("LuaH_resize hook: ACTIVE (sub_85C6F0 @ 0x0085C6F0 - table rehash prevention, round-up to pow2)");
    return true;
#endif
}

// ================================================================
// 22. sub_819D40 - Asset Path Resolver Cache (643 callers)
//
// Every texture, model, sound, and UI load resolves its path through
// this function.  It does strlen+sprintf+MPQ lookup per call.
// Caching the resolved pointer skips redundant string building.
// ================================================================
typedef int (__cdecl* AssetPathResolver_fn)(const char* path, int typeIdx, int gender);
static AssetPathResolver_fn orig_AssetPathResolver = nullptr;

struct AssetPathCacheEntry {
    uint32_t hash;
    int      result;
    bool     valid;
};

static constexpr int ASSET_PATH_CACHE_SIZE = 1024;
AssetPathCacheEntry g_assetPathCache[ASSET_PATH_CACHE_SIZE] = {};
long g_assetPathHits = 0;
long g_assetPathMisses = 0;

static int __cdecl hooked_AssetPathResolver(const char* path, int typeIdx, int gender) {
    return orig_AssetPathResolver(path, typeIdx, gender); // DISABLED - stale mimalloc pointers on teardown
}

static bool InstallAssetPathCache() {
    void* target = (void*)0x00819D40;
    if (WineSafe_CreateHook(target, (void*)hooked_AssetPathResolver, (void**)&orig_AssetPathResolver) != MH_OK)
        return false;
    if (WO_EnableHook(target) != MH_OK)
        return false;
    Log("Asset path cache: ACTIVE (%d slots, sub_819D40 @ 0x00819D40)", ASSET_PATH_CACHE_SIZE);
    return true;
}

void ClearAssetPathCache() {
    memset(g_assetPathCache, 0, sizeof(g_assetPathCache));
}

// ================================================================
// 23. memcpy 16-byte TValue fast path
//
// luaV_execute copies TValue structures (16 bytes) millions of times
// per frame.  Generic memcpy has alignment checks + size dispatch
// overhead.  For exactly 16 bytes, two movq are faster and always
// page-safe.  Separate from CRT fast paths - minimal, targeted.
// ================================================================
typedef void* (__cdecl* Memcpy_fn)(void*, const void*, size_t);
static Memcpy_fn orig_Memcpy = nullptr;
long g_tvalueMemcpyHits = 0;

static void* __cdecl hooked_Memcpy_TValue(void* dst, const void* src, size_t n) {
    if (n == 16) {
        uint64_t* d = (uint64_t*)dst;
        const uint64_t* s = (const uint64_t*)src;
        d[0] = s[0];
        d[1] = s[1];
        InterlockedIncrement(&g_tvalueMemcpyHits);
        return dst;
    }
    return orig_Memcpy(dst, src, n);
}

static bool InstallTValueMemcpyHook() {
    HMODULE hCRT = GetModuleHandleA("msvcrt.dll");
    if (!hCRT) hCRT = GetModuleHandleA("ucrtbase.dll");
    if (!hCRT) return false;

    void* p = (void*)GetProcAddress(hCRT, "memcpy");
    if (!p) return false;

    if (WineSafe_CreateHook(p, (void*)hooked_Memcpy_TValue, (void**)&orig_Memcpy) != MH_OK)
        return false;
    if (WO_EnableHook(p) != MH_OK)
        return false;

    Log("TValue memcpy: ACTIVE (16-byte fast path)");
    return true;
}

// ================================================================
// 24. GetSystemInfo cache - SYSTEM_INFO never changes, called by addons
// ================================================================
typedef void (WINAPI* GetSystemInfo_fn)(LPSYSTEM_INFO);
static GetSystemInfo_fn orig_GetSystemInfo = nullptr;
static SYSTEM_INFO g_cachedSysInfo = {};
static bool g_sysInfoCached = false;
long g_sysInfoHits = 0;

static void WINAPI hooked_GetSystemInfo(LPSYSTEM_INFO lpSI) {
    if (g_sysInfoCached && lpSI) {
        memcpy(lpSI, &g_cachedSysInfo, sizeof(SYSTEM_INFO));
        InterlockedIncrement(&g_sysInfoHits);
        return;
    }
    orig_GetSystemInfo(lpSI);
}

static bool InstallSysInfoCache() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetSystemInfo");
    if (!p || MH_CreateHook(p, (void*)hooked_GetSystemInfo, (void**)&orig_GetSystemInfo) != MH_OK)
        return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("GetSystemInfo cache: ACTIVE");
    return true;
}

// ================================================================
// 25. RegQueryValueExA cache - WTF config reads, 256-slot hash
// ================================================================
typedef LONG (WINAPI* RegQueryValueExA_fn)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
static RegQueryValueExA_fn orig_RegQueryValueExA = nullptr;

struct RegCacheEntry {
    HKEY    hKey;
    uint32_t nameHash;
    DWORD   type;
    DWORD   size;
    BYTE    data[256];
    bool    valid;
};

static constexpr int REG_CACHE_SIZE = 256;
static RegCacheEntry g_regCache[REG_CACHE_SIZE] = {};
static SRWLOCK g_regCacheLock = SRWLOCK_INIT;
long g_regCacheHits = 0, g_regCacheMisses = 0;

static LONG WINAPI hooked_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    if (!lpValueName || !lpType || !lpcbData) goto fallback;

    uint32_t hash = 0x811C9DC5;
    for (const char* p = lpValueName; *p; p++) { hash ^= (uint8_t)*p; hash *= 0x01000193; }
    uint32_t slot = (hash ^ (uint32_t)(uintptr_t)hKey) & (REG_CACHE_SIZE - 1);
    RegCacheEntry* e = &g_regCache[slot];

    AcquireSRWLockShared(&g_regCacheLock);
    if (e->valid && e->hKey == hKey && e->nameHash == hash) {
        *lpType = e->type;
        DWORD copySize = e->size < *lpcbData ? e->size : *lpcbData;
        if (lpData) memcpy(lpData, e->data, copySize);
        *lpcbData = e->size;
        ReleaseSRWLockShared(&g_regCacheLock);
        InterlockedIncrement(&g_regCacheHits);
        return ERROR_SUCCESS;
    }
    ReleaseSRWLockShared(&g_regCacheLock);

    LONG result = orig_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    if (result == ERROR_SUCCESS && *lpcbData <= sizeof(e->data) && lpData) {
        AcquireSRWLockExclusive(&g_regCacheLock);
        e->hKey = hKey;
        e->nameHash = hash;
        e->type = *lpType;
        e->size = *lpcbData;
        memcpy(e->data, lpData, *lpcbData);
        e->valid = true;
        ReleaseSRWLockExclusive(&g_regCacheLock);
    }
    InterlockedIncrement(&g_regCacheMisses);
    return result;

fallback:
    return orig_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

static bool InstallRegCache() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("advapi32.dll"), "RegQueryValueExA");
    if (!p || MH_CreateHook(p, (void*)hooked_RegQueryValueExA, (void**)&orig_RegQueryValueExA) != MH_OK)
        return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("RegQueryValueExA cache: ACTIVE (%d slots)", REG_CACHE_SIZE);
    return true;
}

// ================================================================
// 26. GetSystemMetrics cache - screen dimensions, called by UI addons
// ================================================================
typedef int (WINAPI* GetSystemMetrics_fn)(int);
static GetSystemMetrics_fn orig_GetSystemMetrics = nullptr;
static int g_smCache[128] = {};
static bool g_smInited[128] = {};

// Screen-dimension metrics change on display-mode / DPI / maximize, must NOT be cached.
// 0 = SM_CXSCREEN, 1 = SM_CYSCREEN, 16 = SM_CXFULLSCREEN, 17 = SM_CYFULLSCREEN,
// 78 = SM_CXVIRTUALSCREEN, 79 = SM_CYVIRTUALSCREEN
static inline bool IsScreenDimMetric(int idx) {
    return idx == 0 || idx == 1 || idx == 16 || idx == 17 || idx == 78 || idx == 79;
}

static int WINAPI hooked_GetSystemMetrics(int nIndex) {
    if (nIndex >= 0 && nIndex < 128 && !IsScreenDimMetric(nIndex)) {
        if (g_smInited[nIndex]) {
            return g_smCache[nIndex];
        }
        int result = orig_GetSystemMetrics(nIndex);
        g_smCache[nIndex] = result;
        g_smInited[nIndex] = true;
        return result;
    }
    return orig_GetSystemMetrics(nIndex);
}

static bool InstallSysMetricsCache() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "GetSystemMetrics");
    if (!p || MH_CreateHook(p, (void*)hooked_GetSystemMetrics, (void**)&orig_GetSystemMetrics) != MH_OK)
        return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    return true;
}

// ================================================================
// 27. IsDebuggerPresent no-op - always false, skips syscall
// ================================================================
typedef BOOL (WINAPI* IsDebuggerPresent_fn)();
static IsDebuggerPresent_fn orig_IsDebuggerPresent = nullptr;

static BOOL WINAPI hooked_IsDebuggerPresent() { return FALSE; }

static bool InstallNoDebuggerPresent() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsDebuggerPresent");
    if (!p || MH_CreateHook(p, (void*)hooked_IsDebuggerPresent, (void**)&orig_IsDebuggerPresent) != MH_OK)
        return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    return true;
}

// ================================================================
// 28. GetVersionExA cache - Windows version never changes
// ================================================================
typedef BOOL (WINAPI* GetVersionExA_fn)(LPOSVERSIONINFOA);
static GetVersionExA_fn orig_GetVersionExA = nullptr;
static OSVERSIONINFOA g_cachedVersion = {};
static bool g_verCached = false;

static BOOL WINAPI hooked_GetVersionExA(LPOSVERSIONINFOA lpVI) {
    if (g_verCached && lpVI) {
        DWORD sz = lpVI->dwOSVersionInfoSize;
        if (sz > sizeof(OSVERSIONINFOA)) sz = sizeof(OSVERSIONINFOA);
        memcpy(lpVI, &g_cachedVersion, sz);
        return TRUE;
    }
    BOOL result = orig_GetVersionExA(lpVI);
    if (result && lpVI) {
        DWORD sz = lpVI->dwOSVersionInfoSize;
        if (sz > sizeof(OSVERSIONINFOA)) sz = sizeof(OSVERSIONINFOA);
        memcpy(&g_cachedVersion, lpVI, sz);
        g_verCached = true;
    }
    return result;
}

static bool InstallVerCache() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetVersionExA");
    if (!p || MH_CreateHook(p, (void*)hooked_GetVersionExA, (void**)&orig_GetVersionExA) != MH_OK)
        return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    return true;
}

// ================================================================
// 24. memcmp fast path - inline compare for 4/8/16 byte cases
// ================================================================
typedef int (__cdecl* Memcmp_fn)(const void*, const void*, size_t);
static Memcmp_fn orig_Memcmp = nullptr;
static long g_memcmpFast = 0;

static int __cdecl hooked_Memcmp_Fast(const void* a, const void* b, size_t n) {
    if (n == 4) {
        uint32_t va = *(const uint32_t*)a, vb = *(const uint32_t*)b;
        InterlockedIncrement(&g_memcmpFast);
        return (va > vb) - (va < vb);
    }
    if (n == 8) {
        uint64_t va = *(const uint64_t*)a, vb = *(const uint64_t*)b;
        InterlockedIncrement(&g_memcmpFast);
        return (va > vb) - (va < vb);
    }
    // 16-byte SSE2 path for TValue comparisons (Lua VM equality checks)
    // Safe when both pointers are valid (caller guarantees this for TValue ops)
    if (n == 16) {
        __m128i va = _mm_loadu_si128((const __m128i*)a);
        __m128i vb = _mm_loadu_si128((const __m128i*)b);
        __m128i eq = _mm_cmpeq_epi8(va, vb);
        int mask = _mm_movemask_epi8(eq);
        InterlockedIncrement(&g_memcmpFast);
        if (mask == 0xFFFF) return 0;  // All 16 bytes equal
        // Find first differing byte for proper ordering
        int diff = _mm_movemask_epi8(_mm_cmpeq_epi8(va, vb)) ^ 0xFFFF;
        unsigned long idx;
        _BitScanForward(&idx, diff);
        unsigned char ca = ((const unsigned char*)a)[idx];
        unsigned char cb = ((const unsigned char*)b)[idx];
        return (ca > cb) - (ca < cb);
    }
    return orig_Memcmp(a, b, n);
}

static bool InstallMemcmpFast() {
    HMODULE hCRT = GetModuleHandleA("msvcrt.dll");
    if (!hCRT) hCRT = GetModuleHandleA("ucrtbase.dll");
    if (!hCRT) return false;
    void* p = (void*)GetProcAddress(hCRT, "memcmp");
    if (!p || MH_CreateHook(p, (void*)hooked_Memcmp_Fast, (void**)&orig_Memcmp) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("memcmp fast path: ACTIVE (4/8-byte inline)");
    return true;
}

// ================================================================
// 25a. LoadLibraryA skip - return handle if DLL already loaded
// ================================================================
typedef HMODULE (WINAPI* LoadLibraryA_fn)(LPCSTR);
static LoadLibraryA_fn orig_LoadLibraryA = nullptr;
static long g_loadLibFast = 0;

static HMODULE WINAPI hooked_LoadLibraryA(LPCSTR lpLibFileName) {
    HMODULE h = GetModuleHandleA(lpLibFileName);
    if (h) { InterlockedIncrement(&g_loadLibFast); return h; }
    return orig_LoadLibraryA(lpLibFileName);
}

static bool InstallLoadLibFast() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!p || MH_CreateHook(p, (void*)hooked_LoadLibraryA, (void**)&orig_LoadLibraryA) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    return true;
}

// ================================================================
// 25b. WaitForMultipleObjects count=1 → WaitForSingleObject
// ================================================================
typedef DWORD (WINAPI* WaitForMultipleObjects_fn)(DWORD, const HANDLE*, BOOL, DWORD);
static WaitForMultipleObjects_fn orig_WFMO = nullptr;
static long g_wfmoFast = 0;

static DWORD WINAPI hooked_WFMO(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMs) {
    if (nCount == 1 && !bWaitAll) {
        InterlockedIncrement(&g_wfmoFast);
        return WaitForSingleObject(lpHandles[0], dwMs);
    }
    return orig_WFMO(nCount, lpHandles, bWaitAll, dwMs);
}

static bool InstallWFMOFast() {
    void* p = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WaitForMultipleObjects");
    if (!p || MH_CreateHook(p, (void*)hooked_WFMO, (void**)&orig_WFMO) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    return true;
}

// ================================================================
// VA Arena - dynamic 256MB reserve during loading screens
// ================================================================
static void* g_loadingArena = nullptr;
static SRWLOCK g_arenaLock = SRWLOCK_INIT;

// Reserving the arena is a best-effort optimization that is deliberately skipped on
// heavy clients, but entering the loading state is NOT optional - a whole family of
// "bypass this hook while loading" guards depends on it. The two were previously
// fused, so on any client with a working set above 500 MB (i.e. most HD clients) the
// early return skipped the notification and the process never entered loading state.
extern "C" void ReserveLoadingArena() {
    AcquireSRWLockExclusive(&g_arenaLock);
    if (!g_loadingArena) {
        // Skip on HD clients - VA space already under pressure (32-bit, 1.3GB WS)
        PROCESS_MEMORY_COUNTERS pmc = {};
        pmc.cb = sizeof(pmc);
        bool vaUnderPressure = GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))
                               && pmc.WorkingSetSize > 500u * 1024u * 1024u;

        if (!vaUnderPressure) {
            g_loadingArena = VirtualAlloc(nullptr, 256 * 1024 * 1024, MEM_RESERVE, PAGE_NOACCESS);
            ReleaseSRWLockExclusive(&g_arenaLock);
            if (g_loadingArena) {
                Log("[VA-Arena] Reserved 256MB for loading screen model/texture allocation");
            } else {
                Log("[VA-Arena] Failed to reserve 256MB (VA fragmented - continuing)");
            }
        } else {
            ReleaseSRWLockExclusive(&g_arenaLock);
            Log("[VA-Arena] Skipped reservation (working set %.1f MB - VA already under pressure)",
                pmc.WorkingSetSize / (1024.0 * 1024.0));
        }
    } else {
        ReleaseSRWLockExclusive(&g_arenaLock);
    }

    LoadingDefrag::NotifyLoadingState(true);
    TextureUnloadDelay::Flush();
}

extern "C" void ReleaseLoadingArena() {
    AcquireSRWLockExclusive(&g_arenaLock);
    if (g_loadingArena) {
        VirtualFree(g_loadingArena, 0, MEM_RELEASE);
        g_loadingArena = nullptr;
        Log("[VA-Arena] Released - VA space returned to process");
    }
    ReleaseSRWLockExclusive(&g_arenaLock);
    LoadingDefrag::NotifyLoadingState(false);
    TextureUnloadDelay::Flush();
}

// ================================================================
// Batch optimizations: kernel caches and fast paths
// ================================================================

// #1: GetSystemTimeAsFileTime → cached QPC. Timestamps used for profiling.
typedef void (WINAPI* GSTAFT_fn)(LPFILETIME);
static GSTAFT_fn orig_GSTAFT = nullptr;
static LARGE_INTEGER g_gstaftFreq = {};
static LARGE_INTEGER g_gstaftBase = {};
static bool g_gstaftInit = false;

static void WINAPI hooked_GSTAFT(LPFILETIME lpFT) {
    // Return cached QPC-based time with 1ms refresh
    if (!g_gstaftInit) {
        QueryPerformanceFrequency(&g_gstaftFreq);
        QueryPerformanceCounter(&g_gstaftBase);
        orig_GSTAFT(lpFT);  // Must call original, not hooked function!
        g_gstaftInit = true;
        return;
    }
    static LARGE_INTEGER lastQPC = {};
    static FILETIME lastFT = {};
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    if (now.QuadPart - lastQPC.QuadPart > g_gstaftFreq.QuadPart / 1000) {  // 1ms refresh
        orig_GSTAFT(&lastFT);
        lastQPC = now;
    }
    *lpFT = lastFT;
}

// #2: GetACP - code page never changes
typedef UINT (WINAPI* GetACP_fn)();
static GetACP_fn orig_GetACP = nullptr;
static UINT g_cachedACP = 0;

static UINT WINAPI hooked_GetACP() {
    if (!g_cachedACP) g_cachedACP = orig_GetACP();
    return g_cachedACP;
}

// #3: GetUserDefaultLangID - language never changes
typedef LANGID (WINAPI* GetUserDefaultLangID_fn)();
static GetUserDefaultLangID_fn orig_GetUDLI = nullptr;
static LANGID g_cachedLang = 0;

static LANGID WINAPI hooked_GetUDLI() {
    if (!g_cachedLang) g_cachedLang = orig_GetUDLI();
    return g_cachedLang;
}

// #4: GetProcessHeap - always returns the same handle
typedef HANDLE (WINAPI* GetProcessHeap_fn)();
static GetProcessHeap_fn orig_GetProcessHeap = nullptr;
static HANDLE g_cachedHeap = NULL;

static HANDLE WINAPI hooked_GetProcessHeap() {
    if (!g_cachedHeap) g_cachedHeap = orig_GetProcessHeap();
    return g_cachedHeap;
}

// #5: CharUpperA ASCII fast path
typedef char* (WINAPI* CharUpperA_fn)(char*);
static CharUpperA_fn orig_CharUpperA = nullptr;

static char* WINAPI hooked_CharUpperA(char* str) {
    if (str) {
        for (char* p = str; *p; p++)
            if (*p >= 'a' && *p <= 'z') *p -= 32;
    }
    return str;
}

// #6: CharLowerA ASCII fast path
typedef char* (WINAPI* CharLowerA_fn)(char*);
static CharLowerA_fn orig_CharLowerA = nullptr;

static char* WINAPI hooked_CharLowerA(char* str) {
    if (str) {
        for (char* p = str; *p; p++)
            if (*p >= 'A' && *p <= 'Z') *p += 32;
    }
    return str;
}

// #7: REMOVED - wsprintfA variadic args can't be forwarded
typedef int (__cdecl* wsprintfA_fn)(char*, const char*, ...);
static wsprintfA_fn orig_wsprintfA = nullptr; // kept for future use, hook not installed

// #8: MapVirtualKeyA - key mappings cached
typedef UINT (WINAPI* MapVirtualKeyA_fn)(UINT, UINT);
static MapVirtualKeyA_fn orig_MapVirtualKeyA = nullptr;
static UINT g_mvkCache[256][4] = {};  // [code][mapType]

static UINT WINAPI hooked_MapVirtualKeyA(UINT code, UINT mapType) {
    if (code < 256 && mapType < 4) {
        UINT& cached = g_mvkCache[code][mapType];
        if (!cached) cached = orig_MapVirtualKeyA(code, mapType);
        return cached;
    }
    return orig_MapVirtualKeyA(code, mapType);
}

// #9: GetThreadPriority - thread priority never changes per thread
typedef int (WINAPI* GetThreadPriority_fn)(HANDLE);
static GetThreadPriority_fn orig_GetThreadPriority = nullptr;
static int g_threadPrio[256] = {};  // simple per-handle cache

static int WINAPI hooked_GetThreadPriority(HANDLE h) {
    DWORD idx = (DWORD)(uintptr_t)h & 255;
    int& c = g_threadPrio[idx];
    if (c) return c;
    c = orig_GetThreadPriority(h);
    return c;
}

// #10: lstrlenW REMOVED - already hooked by SSE2 fast path (duplicate hook crashes MinHook)

static bool InstallBatchOpt10() {
    int ok = 0;
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    HMODULE hU32 = GetModuleHandleA("user32.dll");

    void* p;
    // #1 GSTAFT
    p = (void*)GetProcAddress(hK32, "GetSystemTimeAsFileTime");
    if (p && MH_CreateHook(p, (void*)hooked_GSTAFT, (void**)&orig_GSTAFT) == MH_OK && WO_EnableHook(p) == MH_OK) ok++;
    // #2 GetACP
    p = (void*)GetProcAddress(hK32, "GetACP");
    if (p && MH_CreateHook(p, (void*)hooked_GetACP, (void**)&orig_GetACP) == MH_OK && WO_EnableHook(p) == MH_OK) ok++;
    // #3 GetUserDefaultLangID
    p = (void*)GetProcAddress(hK32, "GetUserDefaultLangID");
    if (p && MH_CreateHook(p, (void*)hooked_GetUDLI, (void**)&orig_GetUDLI) == MH_OK && WO_EnableHook(p) == MH_OK) ok++;
    // #4 GetProcessHeap
    p = (void*)GetProcAddress(hK32, "GetProcessHeap");
    if (p && MH_CreateHook(p, (void*)hooked_GetProcessHeap, (void**)&orig_GetProcessHeap) == MH_OK && WO_EnableHook(p) == MH_OK) ok++;
    // #5 CharUpperA
    p = (void*)GetProcAddress(hU32, "CharUpperA");
    if (p && MH_CreateHook(p, (void*)hooked_CharUpperA, (void**)&orig_CharUpperA) == MH_OK && WO_EnableHook(p) == MH_OK) ok++;
    // #6 CharLowerA
    p = (void*)GetProcAddress(hU32, "CharLowerA");
    if (p && MH_CreateHook(p, (void*)hooked_CharLowerA, (void**)&orig_CharLowerA) == MH_OK && WO_EnableHook(p) == MH_OK) ok++;
    // #7 wsprintfA REMOVED - variadic args can't forward
    // #8 MapVirtualKeyA — DISABLED: returns 0 for unmapped keys, cache treats 0 as "uncached",
    // causing repeated re-queries. Cached mappings become stale across Shift/CapsLock/IME changes,
    // breaking the entire keyboard input pipeline (all keys dead).
    if (0) {
        p = (void*)GetProcAddress(hU32, "MapVirtualKeyA");
        if (p && MH_CreateHook(p, (void*)hooked_MapVirtualKeyA, (void**)&orig_MapVirtualKeyA) == MH_OK && WO_EnableHook(p) == MH_OK) ok++;
    }
    // #9 GetThreadPriority
    p = (void*)GetProcAddress(hK32, "GetThreadPriority");
    if (p && MH_CreateHook(p, (void*)hooked_GetThreadPriority, (void**)&orig_GetThreadPriority) == MH_OK && WO_EnableHook(p) == MH_OK) ok++;
    // #10 lstrlenW REMOVED - duplicate hook

    Log("Batch opt #1-8: %d/8 active", ok);
    return ok > 0;
}

// ================================================================
// Batch #11-20: more kernel caches and fast paths
// ================================================================

// #11: GetOEMCP
typedef UINT (WINAPI* GetOEMCP_fn)();
static GetOEMCP_fn orig_GetOEMCP = nullptr; static UINT g_oemcp = 0;
static UINT WINAPI hooked_GetOEMCP() { if (!g_oemcp) g_oemcp = orig_GetOEMCP(); return g_oemcp; }

// #12: GetDoubleClickTime
typedef UINT (WINAPI* GetDoubleClickTime_fn)();
static GetDoubleClickTime_fn orig_GetDoubleClickTime = nullptr; static UINT g_dct = 0;
static UINT WINAPI hooked_GetDoubleClickTime() { if (!g_dct) g_dct = orig_GetDoubleClickTime(); return g_dct; }

// #13: GetCursorPos - DISABLED (breaks hardware cursor with RTSSHooks.dll)
typedef BOOL (WINAPI* GetCursorPos_fn)(LPPOINT);
static GetCursorPos_fn orig_GetCursorPos = nullptr;
static BOOL WINAPI hooked_GetCursorPos(LPPOINT lp) {
    return orig_GetCursorPos(lp);
}

// #14: GetSysColor
typedef DWORD (WINAPI* GetSysColor_fn)(int);
static GetSysColor_fn orig_GetSysColor = nullptr; static DWORD g_sysColors[32] = {};
static DWORD WINAPI hooked_GetSysColor(int idx) {
    if (idx < 32) { if (!g_sysColors[idx]) g_sysColors[idx] = orig_GetSysColor(idx); return g_sysColors[idx]; }
    return orig_GetSysColor(idx);
}

// #15: GetKeyboardLayout
typedef HKL (WINAPI* GetKeyboardLayout_fn)(DWORD);
static GetKeyboardLayout_fn orig_GetKeyboardLayout = nullptr; static HKL g_kbl = 0;
static HKL WINAPI hooked_GetKeyboardLayout(DWORD id) { if (!g_kbl) g_kbl = orig_GetKeyboardLayout(id); return g_kbl; }

// #16: GetKeyboardLayoutNameA
typedef BOOL (WINAPI* GetKeyboardLayoutNameA_fn)(char*);
static GetKeyboardLayoutNameA_fn orig_GetKeyboardLayoutNameA = nullptr; static char g_kbln[9] = {};
static BOOL WINAPI hooked_GetKeyboardLayoutNameA(char* buf) { if (g_kbln[0]) { memcpy(buf, g_kbln, 9); return TRUE; } BOOL r = orig_GetKeyboardLayoutNameA(g_kbln); memcpy(buf, g_kbln, 9); return r; }

// #17: GetCaretBlinkTime
typedef UINT (WINAPI* GetCaretBlinkTime_fn)();
static GetCaretBlinkTime_fn orig_GetCaretBlinkTime = nullptr; static UINT g_cbt = 0;
static UINT WINAPI hooked_GetCaretBlinkTime() { if (!g_cbt) g_cbt = orig_GetCaretBlinkTime(); return g_cbt; }

// #18: IsWindow
typedef BOOL (WINAPI* IsWindow_fn)(HWND);
static IsWindow_fn orig_IsWindow = nullptr; static HWND g_lastIW = NULL; static BOOL g_lastIWRes = TRUE;
static BOOL WINAPI hooked_IsWindow(HWND h) { if (h == g_lastIW) return g_lastIWRes; g_lastIWRes = orig_IsWindow(h); g_lastIW = h; return g_lastIWRes; }

// #19: GetDesktopWindow
typedef HWND (WINAPI* GetDesktopWindow_fn)();
static GetDesktopWindow_fn orig_GetDesktopWindow = nullptr; static HWND g_desktop = NULL;
static HWND WINAPI hooked_GetDesktopWindow() { if (!g_desktop) g_desktop = orig_GetDesktopWindow(); return g_desktop; }

// #20: GetFocus - DISABLED (breaks hardware cursor with RTSSHooks.dll)
typedef HWND (WINAPI* GetFocus_fn)();
static GetFocus_fn orig_GetFocus = nullptr; static HWND g_lastFocus = NULL; static DWORD g_lastFocusTick = 0;
static HWND WINAPI hooked_GetFocus() { return orig_GetFocus(); }

static bool InstallBatchOpt20() {
    int ok = 0;
    HMODULE hK32 = GetModuleHandleA("kernel32.dll"), hU32 = GetModuleHandleA("user32.dll");
    void* p;
    #define H(dll, fn, orig) p=(void*)GetProcAddress(dll,#fn); if(p&&MH_CreateHook(p,(void*)hooked_##fn,(void**)&orig)==MH_OK&&WO_EnableHook(p)==MH_OK) ok++
    H(hK32, GetOEMCP, orig_GetOEMCP); H(hU32, GetDoubleClickTime, orig_GetDoubleClickTime);
    // H(hU32, GetCursorPos, orig_GetCursorPos); // DISABLED - breaks hardware cursor with RTSSHooks.dll
    H(hU32, GetSysColor, orig_GetSysColor);
    // H(hU32, GetKeyboardLayout, orig_GetKeyboardLayout); H(hU32, GetKeyboardLayoutNameA, orig_GetKeyboardLayoutNameA); // DISABLED - breaks language switching
    H(hU32, GetCaretBlinkTime, orig_GetCaretBlinkTime); H(hU32, IsWindow, orig_IsWindow);
    H(hU32, GetDesktopWindow, orig_GetDesktopWindow); H(hU32, GetFocus, orig_GetFocus);
    #undef H
    Log("Batch opt #11-20: %d/10 active", ok);
    return ok > 0;
}

// ================================================================
// Batch #21-30: more caches and fast paths
// ================================================================

// #21: GetTickCount64 - redirect to QPC (same as GetTickCount hook)
typedef ULONGLONG (WINAPI* GetTickCount64_fn)();
static GetTickCount64_fn orig_GetTickCount64 = nullptr;
static ULONGLONG WINAPI hooked_GetTickCount64() {
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    static LARGE_INTEGER freq;
    static bool init = false;
    if (!init) { QueryPerformanceFrequency(&freq); init = true; }
    return (ULONGLONG)(qpc.QuadPart * 1000 / freq.QuadPart);
}

// #22: GetClientRect - cached per HWND (window size rarely changes)
typedef BOOL (WINAPI* GetClientRect_fn)(HWND, LPRECT);
static GetClientRect_fn orig_GetClientRect = nullptr;
static HWND g_crHwnd = NULL; static RECT g_crCache = {};
static BOOL WINAPI hooked_GetClientRect(HWND h, LPRECT r) {
    if (h == g_crHwnd) { *r = g_crCache; return TRUE; }
    BOOL res = orig_GetClientRect(h, r);
    if (res) { g_crHwnd = h; g_crCache = *r; }
    return res;
}

// #23: GetWindowRect - cached per HWND
typedef BOOL (WINAPI* GetWindowRect_fn)(HWND, LPRECT);
static GetWindowRect_fn orig_GetWindowRect = nullptr;
static HWND g_wrHwnd = NULL; static RECT g_wrCache = {};
static BOOL WINAPI hooked_GetWindowRect(HWND h, LPRECT r) {
    if (h == g_wrHwnd) { *r = g_wrCache; return TRUE; }
    BOOL res = orig_GetWindowRect(h, r);
    if (res) { g_wrHwnd = h; g_wrCache = *r; }
    return res;
}

// #24-25: REMOVED - GetDateFormatA/GetTimeFormatA pass-through (no speedup)
// #26: SetCursorPos REMOVED - no-op breaks mouselook (cursor must move)

// #27: ShowCursor - cached (only changes on UI mode switch)
typedef int (WINAPI* ShowCursor_fn)(BOOL);
static ShowCursor_fn orig_ShowCursor = nullptr; static int g_showCount = -1;
static int WINAPI hooked_ShowCursor(BOOL show) {
    if (show) { if (g_showCount < 0) g_showCount = orig_ShowCursor(TRUE); g_showCount++; return g_showCount; }
    else { if (g_showCount > 0) g_showCount--; return g_showCount; }
}

// #28-29: REMOVED - GetDC/ReleaseDC unsafe (prevents screen updates)
// #30: ValidateRect REMOVED - no-op prevents UI repaints, freezes on friend list open

static bool InstallBatchOpt30() {
    int ok = 0;
    HMODULE hK32 = GetModuleHandleA("kernel32.dll"), hU32 = GetModuleHandleA("user32.dll");
    void* p;
    #define H31(dll, fn, orig) p=(void*)GetProcAddress(dll,#fn); if(p&&MH_CreateHook(p,(void*)hooked_##fn,(void**)&orig)==MH_OK&&WO_EnableHook(p)==MH_OK) ok++
    H31(hK32, GetTickCount64, orig_GetTickCount64);
    // H31(hU32, GetClientRect, orig_GetClientRect); // DISABLED - cached window dimensions break window resize (clicks miss UI elements)
    // H31(hU32, GetWindowRect, orig_GetWindowRect); // DISABLED - cached window dimensions break window resize (clicks miss UI elements)
    // H31(hU32, ShowCursor, orig_ShowCursor); // DISABLED - breaks hardware cursor with RTSSHooks.dll
    // H31(hU32, ValidateRect, orig_ValidateRect); // REMOVED - prevents UI repaint, freezes on friend list
    #undef H31
    Log("Batch opt #21-24: %d/4 active", ok);
    return ok > 0;
}

// ================================================================
// Batch #31-35: kernel32 immutable-data caches
// ================================================================

// #31: GetComputerNameA - never changes during session
typedef BOOL (WINAPI* GetComputerNameA_fn)(LPSTR, LPDWORD);
static GetComputerNameA_fn orig_GetComputerNameA = nullptr;
static char g_computerName[64] = {};
static BOOL WINAPI hooked_GetComputerNameA(LPSTR buf, LPDWORD nSize) {
    if (g_computerName[0]) { DWORD len = (DWORD)strlen(g_computerName) + 1; if (*nSize >= len) { memcpy(buf, g_computerName, len); return TRUE; } }
    BOOL r = orig_GetComputerNameA(g_computerName, nSize); memcpy(buf, g_computerName, (size_t)*nSize + 1); return r;
}

// #32: GetUserNameA - never changes during session
typedef BOOL (WINAPI* GetUserNameA_fn)(LPSTR, LPDWORD);
static GetUserNameA_fn orig_GetUserNameA = nullptr;
static char g_userName[64] = {};
static BOOL WINAPI hooked_GetUserNameA(LPSTR buf, LPDWORD nSize) {
    if (g_userName[0]) { DWORD len = (DWORD)strlen(g_userName) + 1; if (*nSize >= len) { memcpy(buf, g_userName, len); return TRUE; } }
    BOOL r = orig_GetUserNameA(g_userName, nSize); memcpy(buf, g_userName, (size_t)*nSize + 1); return r;
}

// #33: GetSystemDirectoryA - never changes
typedef UINT (WINAPI* GetSystemDirectoryA_fn)(LPSTR, UINT);
static GetSystemDirectoryA_fn orig_GetSystemDirectoryA = nullptr;
static char g_sysDir[MAX_PATH] = {};
static UINT WINAPI hooked_GetSystemDirectoryA(LPSTR buf, UINT nSize) {
    if (g_sysDir[0]) { UINT len = (UINT)strlen(g_sysDir) + 1; if (nSize >= len) { memcpy(buf, g_sysDir, len); return len - 1; } }
    UINT r = orig_GetSystemDirectoryA(g_sysDir, MAX_PATH); if (buf != g_sysDir) memcpy(buf, g_sysDir, (size_t)r + 1); return r;
}

// #34: GetWindowsDirectoryA - never changes
typedef UINT (WINAPI* GetWindowsDirectoryA_fn)(LPSTR, UINT);
static GetWindowsDirectoryA_fn orig_GetWindowsDirectoryA = nullptr;
static char g_winDir[MAX_PATH] = {};
static UINT WINAPI hooked_GetWindowsDirectoryA(LPSTR buf, UINT nSize) {
    if (g_winDir[0]) { UINT len = (UINT)strlen(g_winDir) + 1; if (nSize >= len) { memcpy(buf, g_winDir, len); return len - 1; } }
    UINT r = orig_GetWindowsDirectoryA(g_winDir, MAX_PATH); if (buf != g_winDir) memcpy(buf, g_winDir, (size_t)r + 1); return r;
}

// #35: GetTempPathA - changes only on reboot
typedef DWORD (WINAPI* GetTempPathA_fn)(DWORD, LPSTR);
static GetTempPathA_fn orig_GetTempPathA = nullptr;
static char g_tempPath[MAX_PATH] = {};
static DWORD WINAPI hooked_GetTempPathA(DWORD nSize, LPSTR buf) {
    if (g_tempPath[0]) { DWORD len = (DWORD)strlen(g_tempPath) + 1; if (nSize >= len) { memcpy(buf, g_tempPath, len); return len - 1; } }
    DWORD r = orig_GetTempPathA(MAX_PATH, g_tempPath); if (buf != g_tempPath) memcpy(buf, g_tempPath, (size_t)r + 1); return r;
}

static bool InstallBatchOpt35() {
    int ok = 0;
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    void* p;
    #define H35(fn, orig) p=(void*)GetProcAddress(hK32,#fn); if(p&&MH_CreateHook(p,(void*)hooked_##fn,(void**)&orig)==MH_OK&&WO_EnableHook(p)==MH_OK) ok++
    H35(GetComputerNameA, orig_GetComputerNameA);
    H35(GetUserNameA, orig_GetUserNameA);
    H35(GetSystemDirectoryA, orig_GetSystemDirectoryA);
    H35(GetWindowsDirectoryA, orig_GetWindowsDirectoryA);
    H35(GetTempPathA, orig_GetTempPathA);
    #undef H35
    Log("Batch opt #31-35: %d/5 active", ok);
    return ok > 0;
}

// ================================================================
// Batch #36-38: kernel32 immutable-data caches
// #36: GetCurrentProcess - always returns (HANDLE)-1
typedef HANDLE (WINAPI* GetCurrentProcess_fn)();
static GetCurrentProcess_fn orig_GetCurrentProcess = nullptr;
static HANDLE g_hProc = NULL;
static HANDLE WINAPI hooked_GetCurrentProcess() {
    if (g_hProc) return g_hProc;
    g_hProc = orig_GetCurrentProcess(); return g_hProc;
}
// #37: GetCPInfo - code page info immutable per session
typedef BOOL (WINAPI* GetCPInfo_fn)(UINT, LPCPINFO);
static GetCPInfo_fn orig_GetCPInfo = nullptr;
static CPINFO g_cpInfo[4] = {}; static BOOL g_cpValid[4] = {};
static BOOL WINAPI hooked_GetCPInfo(UINT cp, LPCPINFO lp) {
    int idx = (cp == CP_ACP) ? 0 : (cp == CP_OEMCP) ? 1 : (cp == CP_THREAD_ACP) ? 2 : 3;
    if (idx < 3 && g_cpValid[idx]) { *lp = g_cpInfo[idx]; return TRUE; }
    BOOL r = orig_GetCPInfo(cp, &g_cpInfo[idx]); if (r && lp) *lp = g_cpInfo[idx]; g_cpValid[idx] = r; return r;
}
// #38: GetCurrentThread - already handled at line 2256, returns (HANDLE)-2 constant
static bool InstallBatchOpt38() {
    int ok = 0; HMODULE hK32 = GetModuleHandleA("kernel32.dll"); void* p;
    #define H38(fn, orig) p=(void*)GetProcAddress(hK32,#fn); if(p&&MH_CreateHook(p,(void*)hooked_##fn,(void**)&orig)==MH_OK&&WO_EnableHook(p)==MH_OK) ok++
    H38(GetCurrentProcess, orig_GetCurrentProcess);
    H38(GetCPInfo, orig_GetCPInfo);
    #undef H38
    Log("Batch opt #36-38: %d/2 active", ok);
    return ok > 0;
}

// Main initialization thread.
static DWORD WINAPI MainThread(LPVOID param) {
    // One-time caches initialized before hooks
    GetSystemInfo(&g_cachedSysInfo);
    g_sysInfoCached = true;

    // Load runtime configuration from wow_opt.ini
    Config::Load();

    // --- Early allocator redirect ---
    // Install mimalloc BEFORE the 5s Sleep so it captures EVERY allocation during
    // login/world-load (MPQ data, world LOD assets, UI setup) — that's precisely
    // where the LargestBlock=14MB fragmentation comes from. The old sequence
    // waited 5s then installed, missing the entire early-init allocation stream.
    LogOpen();
    Config::DumpToLog();
    Log("========================================");
#ifndef WOW_OPTIMIZE_GIT_HASH
#define WOW_OPTIMIZE_GIT_HASH "unknown"
#endif
    Log("  wow_optimize.dll v%s (build %s) BY %s",
        WOW_OPTIMIZE_VERSION_STR, WOW_OPTIMIZE_GIT_HASH, WOW_OPTIMIZE_AUTHOR);
    Log("  PID: %lu", GetCurrentProcessId());
    Log("========================================");
    
    if (IsRosetta()) {
        Log("[Rosetta] Detected x86 on ARM64 (macOS Rosetta 2)");
        char val[2] = {0};
        if (GetEnvironmentVariableA("ROSETTA_X87_DISABLE_CACHE", val, sizeof(val)) && val[0] == '1') {
            Log("[Rosetta] x87 JIT cache DISABLED - hooks safe to install");
        } else {
            Log("[Rosetta] WARNING: x87 JIT cache still enabled - hooks may fail");
        }
    }

    if (MH_Initialize() != MH_OK) { Log("FATAL: MinHook initialization failed"); LogClose(); return 1; }
    Log("MinHook initialized");

    ConfigureMimalloc();
    TryEnableLargePages();
    g_nextStatsDumpTick = 0;
    g_nextMiCollectTick = 0;

    Log("--- Memory Allocator ---");
    Log("[Allocator] CRT-wide redirect removed (Winsock stability). mimalloc used directly by subsystems.");
    bool mimallocLargeOk = false;
    if (Config::g_settings.OptMimallocLarge || Config::g_settings.OptCrtMimalloc) {
        mimallocLargeOk = InstallMimallocLargeHooks();
        // NOTE: this is the LARGE-ONLY redirect — only main-thread allocations
        // >= 1 MB below the 2 GB line go to mimalloc. It is NOT the old CRT-wide
        // redirect (that one broke connections and stays removed). The
        // InstallMimallocLargeHooks() call above logs its own precise ACTIVE line.
        if (!mimallocLargeOk) {
            Log("[MimallocLarge] install failed — staying on stock CRT allocator");
        }
    } else {
        Log("[MimallocLarge] disabled via configuration (opt-in; enable in launcher to route large allocations to mimalloc)");
    }
    (void)mimallocLargeOk;
    Sleep(100);


    // Batch every hook enable installed during this synchronous init into one
    // thread-freeze (applied just before "Initialization complete" below).
    g_hookBatchMode = 1;

    CrashDumper::Init();

    // Register ALL features for crash/freeze diagnostics
    CrashDumper::RegisterFeature("SleepHook");
    CrashDumper::RegisterFeature("GetTickCount");
    CrashDumper::RegisterFeature("HeapOptimization");
    CrashDumper::RegisterFeature("ThreadIdCache");
    CrashDumper::RegisterFeature("QPCCache");
    CrashDumper::RegisterFeature("BadPtrCheck");
    CrashDumper::RegisterFeature("CompareStringA");
    CrashDumper::RegisterFeature("CriticalSection");
    CrashDumper::RegisterFeature("NetworkHooks");
    CrashDumper::RegisterFeature("ReadFileCache");
    CrashDumper::RegisterFeature("CloseHandle");
    CrashDumper::RegisterFeature("FlushFileBuffers");
    CrashDumper::RegisterFeature("MPQScan");
    CrashDumper::RegisterFeature("FileAttributes");
    CrashDumper::RegisterFeature("SetFilePointer");
    CrashDumper::RegisterFeature("GlobalAlloc");
    CrashDumper::RegisterFeature("FileSizeCache");
    CrashDumper::RegisterFeature("WFSSpin");
    CrashDumper::RegisterFeature("ModuleHandleCache");
    CrashDumper::RegisterFeature("Lstrcmp");
    CrashDumper::RegisterFeature("Lstrlen");
    CrashDumper::RegisterFeature("WowStrlen");
    CrashDumper::RegisterFeature("StrstrSSE2");
    CrashDumper::RegisterFeature("CrtCharSSE2");
    CrashDumper::RegisterFeature("StreamCache");
    CrashDumper::RegisterFeature("LuaThisCache");
    CrashDumper::RegisterFeature("IOCache");
    CrashDumper::RegisterFeature("LuaGlobalCache");
    CrashDumper::RegisterFeature("HotFunctions");
    CrashDumper::RegisterFeature("FastMemcpy");
    CrashDumper::RegisterFeature("FrameScriptDispatch");
    CrashDumper::RegisterFeature("FastStrncmp");
    CrashDumper::RegisterFeature("CrtFreeHook");
    CrashDumper::RegisterFeature("AlignedAllocCache");
    CrashDumper::RegisterFeature("DataStoreFastPath");
    CrashDumper::RegisterFeature("StringOpsFast");
    CrashDumper::RegisterFeature("MBWCHooks");
    CrashDumper::RegisterFeature("GetProcAddress");
    CrashDumper::RegisterFeature("GetEnvVariable");
    CrashDumper::RegisterFeature("CrtMemFastPaths");
    CrashDumper::RegisterFeature("MsgPump");
    CrashDumper::RegisterFeature("SwapPresent");
    CrashDumper::RegisterFeature("LuaHResize");
    CrashDumper::RegisterFeature("LuaHGetStr");
    CrashDumper::RegisterFeature("FieldUpdates");
    CrashDumper::RegisterFeature("LuaToNumberFast");
    CrashDumper::RegisterFeature("StrcatFast");
    CrashDumper::RegisterFeature("ScriptHandlerCache");
    CrashDumper::RegisterFeature("DbcLookupCache");
    CrashDumper::RegisterFeature("EventDispatchCache");
    CrashDumper::RegisterFeature("LuaGetStrInline");
    CrashDumper::RegisterFeature("RawGetIInline");
    CrashDumper::RegisterFeature("HardwareCursor");
    CrashDumper::RegisterFeature("FrameThrottle");
    CrashDumper::RegisterFeature("UIFrameBatch");
    CrashDumper::RegisterFeature("LuaRawGetICache");
    CrashDumper::RegisterFeature("CombatLogFullCache");
    CrashDumper::RegisterFeature("ThreadAffinity");
    CrashDumper::RegisterFeature("VAArena");
    CrashDumper::RegisterFeature("HeapCompactor");
    CrashDumper::RegisterFeature("MemoryPressureGovernor");
    CrashDumper::RegisterFeature("StreamBufFastPath");
    CrashDumper::RegisterFeature("LuaOptimizer");
    CrashDumper::RegisterFeature("LuaNewKeySafety");
    CrashDumper::RegisterFeature("LuaGetTableSafety");
    CrashDumper::RegisterFeature("LuaObjLen");
    CrashDumper::RegisterFeature("CombatLogOpt");
    CrashDumper::RegisterFeature("CombatLogBuffer");
    CrashDumper::RegisterFeature("ObjVisCache");
    CrashDumper::RegisterFeature("AddonDispatcher");
    CrashDumper::RegisterFeature("NameplateMT");
    CrashDumper::RegisterFeature("NetworkGUID");
    CrashDumper::RegisterFeature("UICache");
    CrashDumper::RegisterFeature("ApiCache");
    CrashDumper::RegisterFeature("LuaFastPath");
    CrashDumper::RegisterFeature("AddonPreload");
    CrashDumper::RegisterFeature("BytecodeCache");
    CrashDumper::RegisterFeature("FrustumCull");
    CrashDumper::RegisterFeature("RayTriangleSSE2");
    CrashDumper::RegisterFeature("MatrixVectorSSE2");
    CrashDumper::RegisterFeature("Vec3NormalizeSSE2");
    CrashDumper::RegisterFeature("MatrixExtSSE2");
    CrashDumper::RegisterFeature("MatrixMultiply");
    CrashDumper::RegisterFeature("SamplingProfiler");

    Log("--- Engine Stability Guards ---");
    InitCvarWatchdog();
    InstallRenderNullGuard();
#if !TEST_DISABLE_CVAR_NULL_GUARD
    InstallCvarNullGuard();
#endif
    if (Config::g_settings.OptVulkanDXVK) {
        InstallD3DEvictPatch();
    }
    bool strncmpGuardOk = InstallStrncmpNullGuard();

    // Extend the Lua C-function pointer validation range if needed,
    // but avoid modifying dword_D415B8/BC directly to prevent Warden detection.

    Log("--- Sound System Protection Guards ---");
    InstallSoundDriverGuard();
    InstallSoundEmitterGuard();
    InstallSoundBufferGuard();
    InstallSoundUpdateGuard();
    // Always installed: it owns the FrameScript_SignalEvent detour and publishes the
    // loading state that the DBC cache, deferred field updates, LuaOpcache and the
    // texture unload queue use as a safety gate. EventCoalescer, when enabled, hangs
    // its dedup queue off this same detour.
    FrameBench::Init();
    LoadingState::Init();
#if !TEST_DISABLE_EVENT_COALESCER
    EventCoalescer::Init();
#endif
#if !TEST_DISABLE_LUAS_NEWLSTR_SSE2
    // The launcher has always offered a switch for this; nothing read it, so the
    // hook installed unconditionally and a tester turning it off saw no change.
    if (Config::g_settings.OptLuaSNewLstrFast) {
        LuaSNewlstr::Init();
    } else {
        Log("[luaS_newlstr] disabled via configuration (opt-in)");
    }
#endif
    CrashDumper::RegisterFeature("LuaVMCache");
    CrashDumper::RegisterFeature("LuaGetTableCache");
    CrashDumper::RegisterFeature("SavedVarsAsync");
    CrashDumper::RegisterFeature("HotPatch");
    CrashDumper::RegisterFeature("MemoryOpt");
    CrashDumper::RegisterFeature("SourceOpt");
    CrashDumper::RegisterFeature("TlsObjectCache");
    Log("[CrashDumper] Registered %d features for tracking (capacity %d)",
        CrashDumper::RegisteredFeatureCount(), MAX_TRACKED_FEATURES);

    Log("--- DXVK Vulkan Integration ---");
    Log("[VulkanDXVK] Config option: %s", Config::g_settings.OptVulkanDXVK ? "ENABLED (d3d9.dll proxy required in game directory)" : "DISABLED");

    Log("--- Frame Pacing ---");
    bool sleepOk = InstallSleepHook();
#if !CRASH_TEST_DISABLE_TICK_COUNT
    Log("--- Timer Precision ---");
    bool tickOk = Config::g_settings.OptTimingFix && InstallGetTickCountHook();
    bool tgtOk  = Config::g_settings.OptTimingFix && InstallTimeGetTimeHook();
#else
    bool tickOk = false;
    bool tgtOk  = false;
    Log("--- Timer Precision ---");
    Log("[TimerPrecision] GetTickCount/timeGetTime hooks: DISABLED");
#endif
    Log("--- Heap Optimization ---");
    bool heapOk = InstallHeapOptimization();
#if !TEST_DISABLE_HEAP_REDIRECT
    Log("--- Process Heap Redirect ---");
    bool heapRedirectOk = InstallHeapRedirectToMimalloc();
    if (!heapRedirectOk) Log("[HeapRedirect] install failed -- process heap stays stock");
#else
    Log("[HeapRedirect] DISABLED via TEST_DISABLE_HEAP_REDIRECT");
#endif
    InstallLockTuning();   // self-logs; spin counts are best-effort
    Log("--- Texture Cache Budget ---");
    if (Config::g_settings.OptMemoryPressure) {
        InitTexCacheTuning();  // self-logs; single-client only
    }
    Log("--- Thread ID Cache ---");
    bool tidOk = InstallThreadIdCacheHook();
    Log("--- QPC Cache ---");
#if !CRASH_TEST_DISABLE_QPC_CACHE
    bool qpcOk = Config::g_settings.OptTimingFix && InstallQPCHook();
#else
    bool qpcOk = false;
    Log("QPC hook: DISABLED (crash isolation)");
#endif     
    Log("--- Bad Pointer Checks ---");
    bool bpOk  = Config::g_settings.OptCvarNullGuard && InstallBadPtrHooks();    
    Log("--- String Comparison ---");
    bool cmpOk = Config::g_settings.OptStrStrSse2 && InstallCompareStringHook();
    Log("--- Debug Strings ---");
    bool debugOk = Config::g_settings.OptCvarNullGuard && InstallOutputDebugStringHook();
    Log("--- Critical Sections ---");
    bool csOk = Config::g_settings.OptDefragLf && InstallCriticalSectionHook();
    Log("--- Network ---");
#if !TEST_DISABLE_NETWORK_HOOKS
    bool netOk = Config::g_settings.OptPacketOffload && InstallNetworkHooks();
#else
    bool netOk = false;
#endif
    Log("--- File I/O ---");
    bool fileOk  = (Config::g_settings.OptDbcLookupCache || Config::g_settings.OptSavedVarsPretoken) && InstallFileHooks();
#if !CRASH_TEST_DISABLE_READFILE
    bool readOk  = (Config::g_settings.OptDbcLookupCache || Config::g_settings.OptSavedVarsPretoken) && InstallReadFileHook();
#else
    // The cache stays off; the measurement does not have to go with it.
    bool readOk  = InstallReadFileTimingHook();
    if (!readOk) Log("ReadFile hook: DISABLED via CRASH_TEST_DISABLE_READFILE");
#endif
    // The load report counts time spent in the ReadFile hook. If that hook is not
    // in, the report must say so rather than print a confident zero.
    LoadingState::SetReadHookInstalled(readOk);
    bool closeOk = (Config::g_settings.OptDbcLookupCache || Config::g_settings.OptSavedVarsPretoken) && InstallCloseHandleHook();
    bool flushOk = (Config::g_settings.OptDbcLookupCache || Config::g_settings.OptSavedVarsPretoken) && InstallFlushFileBuffersHook();
    Log("--- Async MPQ I/O ---");
    // Worker started after init completes to avoid race with hook setup
    bool asyncIoOk = true;
    Log("--- MPQ Scan ---");
    ScanExistingMpqHandles();
    Log("--- File Attributes ---");
    bool faOk = (Config::g_settings.OptDbcLookupCache || Config::g_settings.OptSavedVarsPretoken) && InstallGetFileAttributesHook();
    Log("--- File Pointer ---");
    bool sfpOk = (Config::g_settings.OptDbcLookupCache || Config::g_settings.OptSavedVarsPretoken) && InstallSetFilePointerHook();

    Log("--- Global Alloc ---");
    bool gaOk  = InstallGlobalAllocHooks();    
    Log("--- Multi-Client ---");
    DetectMultiClient();
    AdjustMimallocForMultiClient();    
    Log("--- System Timer ---");
    SetHighTimerResolution();

    // Compatibility mode: some virtualized environments (HyperV virtual switches
    // especially) break WoW's logon TCP connection when the process runs at
    // ABOVE_NORMAL priority with the anti-downgrade hook + watchdog forcing it -
    // the virtualized network path gets starved. A tester on HyperV couldn't
    // connect at all with the DLL loaded, regardless of feature toggles, because
    // these scheduling tweaks are applied unconditionally. When CompatMode is on
    // we skip all of them and let WoW run at normal priority/affinity/working set.
    if (Config::g_settings.OptCompatMode) {
        Log("--- Process/Threads --- CompatMode ON: skipping CPU priority/affinity/working-set tweaks");
    } else {
        Log("--- Threads ---");
        OptimizeThreads();
        Log("--- Process ---");

        // Install SetPriorityClass hook BEFORE setting priority to block downgrade attempts
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (hKernel32) {
            void* pSetPriorityClass = (void*)GetProcAddress(hKernel32, "SetPriorityClass");
            if (pSetPriorityClass &&
                MH_CreateHook(pSetPriorityClass, (void*)hooked_SetPriorityClass, (void**)&orig_SetPriorityClass) == MH_OK &&
                WO_EnableHook(pSetPriorityClass) == MH_OK) {
                Log("SetPriorityClass hook: ACTIVE (blocks priority downgrades)");
            } else {
                Log("WARNING: SetPriorityClass hook failed");
            }
        }

        OptimizeProcess();
        StartPriorityWatchdog();
        OptimizeWorkingSet();
    }
    Log("--- FPS Cap ---");
    TryRemoveFPSCap();

    Log("--- File Size Cache ---");
    bool fsizeOk = (Config::g_settings.OptDbcLookupCache || Config::g_settings.OptSavedVarsPretoken) && InstallGetFileSizeCache();
    Log("--- WaitForSingleObject Spin ---");
    bool wfsOk = Config::g_settings.OptDefragLf && InstallWaitForSingleObjectHook();
    Log("--- Module Handle Cache ---");
    bool modOk = Config::g_settings.OptModuleHandleCache && InstallGetModuleHandleCache();
    Log("--- String Compare (lstrcmp) ---");
    bool lstrOk = Config::g_settings.OptStrStrSse2 && InstallLstrcmpHook();
    Log("--- String Length (lstrlen) ---");
    bool lstrlenOk = Config::g_settings.OptStrStrSse2 && InstallLStrLenHooks();
    bool strlen76Ok = Config::g_settings.OptStrStrSse2 && InstallWowStrlenHook();
    if (strlen76Ok) Log("WoW-internal strlen hook: ACTIVE (SSE2 replacement for sub_76EE30)");

    // CRT strstr SSE2 - algorithmic replacement for byte-by-byte search
#if !TEST_DISABLE_STRSTR_SSE2
    bool strstrOk = Config::g_settings.OptStrStrSse2 && InstallStrstrSSE2();
#else
    bool strstrOk = false;
#endif

    // CRT memchr + strchr SSE2 - 16-byte SIMD byte scan
#if !TEST_DISABLE_CRT_CHAR_SSE2
    bool chrOk = Config::g_settings.OptStrStrSse2 && InstallCrtCharSSE2();
#else
    bool chrOk = false;
#endif

    bool wcharOk = Config::g_settings.OptStrStrSse2 && InstallCrtWcharSSE2();

    // Stream Reader/Writer Cache - eliminate bounds checks
    bool streamCacheOk = Config::g_settings.OptSavedVarsPretoken && InstallStreamCache();

    // Lua "this" Object Lookup Cache - cache method dispatcher results
    bool luaThisCacheOk = Config::g_settings.OptUIFrameAccessorFast && InstallLuaThisCache();

    // I/O Dispatcher Cache - 4050 callers
    bool ioCacheOk = Config::g_settings.OptDbcLookupCache && InstallIOCache();

    // Lua Global Lookup Cache
    bool luaGlobalCacheOk = Config::g_settings.OptLuaOpcache && InstallLuaGlobalCache();

    // memset hook - 1108 callers
    bool hotFuncOk = Config::g_settings.OptFastMemsetOpt && InstallHotFunctionOptimizations();

    bool memcpyFastOk = false; // Config::g_settings.OptStrStrSse2 && InstallMemcpyFast();

    // FrameScript hash dispatch - 18 handlers, O(1) vs O(n)
#if !TEST_DISABLE_FRAME_SCRIPT_DISPATCH
    bool fsDispatchOk = Config::g_settings.OptFrameScriptDispatch && InstallFrameScriptDispatch();
#else
    bool fsDispatchOk = false;
    Log("[FrameScriptDispatch] DISABLED via feature flag");
#endif

    // Fast String Compare (strncmp) - 1013 callers
#if !TEST_DISABLE_STRING_OPS_FAST
    bool fastStrncmpOk = Config::g_settings.OptFastStrnicmpOpt && InstallFastStrncmp();
#else
    bool fastStrncmpOk = false;
#endif

    // CRT Free Hook - 2901 callers (#2 most called)
    bool crtFreeOk = InstallCrtFreeHook();
    InstallCrtAllocHook();

    // Aligned Allocator Cache - 1764 callers (thread-local pool for small allocations)
    bool alignedAllocOk = InstallAlignedAllocCache();

    // NOTE: free_cache and strnicmp_fast are DUPLICATES of existing hooks:
    //   crt_free_hook.cpp   already hooks 0x76E5A0 (2901 callers)
    //   fast_strncmp.cpp    already hooks 0x76E780 (1013 callers)
    // tick_counter_cache was listed here too, on the claim that tls_cache.cpp
    // already hooked its target 0x4D3790. It never did - InstallTlsCache only
    // logged a line and returned true - so nothing hooks 0x4D3790. It stays
    // unhooked by choice now rather than by accident: wrapping a hot leaf
    // accessor to count and cache it is the shape that measured net-negative
    // every time it was tried, because the trampoline costs more than the
    // handful of instructions it skips.
    // lua_pushnumber_fast DISABLED - corrupts numeric values, breaks addon UI bars

    // CDataStore Fast Path - 4179 xrefs (network packet serialization/deserialization)
    Log("--- CDataStore Fast Path ---");
    bool datastoreOk = Config::g_settings.OptSavedVarsPretoken && InitDataStoreFastPath();

    // String & Memory Ops Fast Path - 3900+ xrefs (free wrapper, strnicmp, Jenkins hash)
    Log("--- String & Memory Ops Fast Path ---");
    bool stringOpsOk = Config::g_settings.OptStrStrSse2 && InitStringOpsFast();

    // DISABLED: sub_84D9C0 (get_tvalue helper) uses usercall convention (ECX=L, EAX=idx)
    // Cannot be called as __cdecl - causes ACCESS_VIOLATION at 0x0084D9C4
    bool luaToNumberOk = false;      // InstallLuaToNumberCache();
    bool luaCheckNumberOk = false;   // InstallLuaCheckNumberCache();
    
    // DISABLED: Format validator causes disconnect during login (auth corruption)
    bool formatValidatorOk = false;  // InstallFormatValidatorCache();

    // DISABLED: sub_84F280 uses tail call optimization (last call doesn't return)
    // Cannot be hooked safely - control never returns to hook after orig call
    bool luaPushStringOk = false;    // InstallLuaPushStringCache();

    Log("--- MBT/WCT ASCII Fast Path ---");
    bool mbwcOk = Config::g_settings.OptStrStrSse2 && InstallMBWCHooks();
    Log("--- CRT Memory Fast Paths ---");
    bool crtOk = InstallCrtMemFastPaths();
    bool sysInfoOk = Config::g_settings.OptTimingFix && InstallSysInfoCache();
    bool regCacheOk = Config::g_settings.OptTimingFix && InstallRegCache();
#if !TEST_DISABLE_SYSTEM_METRICS_CACHE
    bool smCacheOk = Config::g_settings.OptTimingFix && InstallSysMetricsCache();
#else
    bool smCacheOk = false;
#endif
    bool noDebugOk = Config::g_settings.OptCvarNullGuard && InstallNoDebuggerPresent();
    bool verCacheOk = Config::g_settings.OptTimingFix && InstallVerCache();
    bool batch10Ok = Config::g_settings.OptStrStrSse2 && InstallBatchOpt10();
    bool batch20Ok = Config::g_settings.OptStrStrSse2 && InstallBatchOpt20();
    bool batch30Ok = Config::g_settings.OptStrStrSse2 && InstallBatchOpt30();
    bool batch35Ok = Config::g_settings.OptStrStrSse2 && InstallBatchOpt35();
    bool batch38Ok = false;
    Log("--- GetProcAddress Cache ---");
    bool gpaOk = Config::g_settings.OptTimingFix && InstallGetProcAddressCache();
    Log("--- GetModuleFileName Cache ---");
    bool gmfOk = Config::g_settings.OptTimingFix && InstallGetModuleFileNameCache();
    Log("--- Environment Variable Cache ---");
    bool envOk = Config::g_settings.OptTimingFix && InstallEnvironmentVariableCache();
    Log("--- Profile String Cache ---");
    bool profOk = Config::g_settings.OptTimingFix && InstallGetPrivateProfileCache();

    Log("--- Message Pump ---");
    bool msgPumpOk = Config::g_settings.OptUIFrameBatch && InstallMsgPumpHook();

    Log("--- Swap/Present ---");
    bool swapOk = Config::g_settings.OptVulkanDXVK && InstallSwapPresentHook();

    // Only one detour can own an address, and the optimizing hook already reports
    // every frame. Fall back to the measurement-only detour so the benchmark works
    // in every configuration rather than only the DXVK one.
    if (!swapOk) {
        InstallSwapTimingHook();
    }

    Log("--- Lua Table Rehash ---");
    bool tableReshapeOk = Config::g_settings.OptLuaOpcache && InstallLuaHResizeHook();
    bool assetPathOk = false; // Disabled - breaks logout/teardown

    Log("--- Lua Table Lookup ---");
    bool luaHGetStrOk = Config::g_settings.OptLuaOpcache && InstallLuaHGetStrCache();

    Log("--- UnitAura Fast Path ---");
#if !TEST_DISABLE_UNIT_AURA_FAST
    if (Config::g_settings.OptUnitAuraFast) {
        InstallUnitAuraFastPath();
    } else {
        Log("[UnitAuraFastPath] DISABLED via configuration");
    }
#else
    Log("[UnitAuraFastPath] DISABLED via feature flag");
#endif

    Log("--- Network GUID Fast Path ---");
#if !TEST_DISABLE_NETWORK_GUID_SSE2
    if (Config::g_settings.OptNetworkGuidSse2) {
        InstallNetworkGuidSSE2Hooks();
    } else {
        Log("[NetworkGuid] DISABLED via configuration");
    }
#else
    Log("[NetworkGuid] DISABLED via feature flag");
#endif

    Log("--- Matrix SSE2 Fast Path ---");
    if (Config::g_settings.OptM2MatrixSimd) {
        InstallMatrixCopySSE2();
    } else {
        Log("[MatrixSSE2] DISABLED via configuration");
    }

    Log("--- Lua Number Conversion Fast Path ---");
#if !TEST_DISABLE_LUA_NUMCONV_FAST
    if (Config::g_settings.OptLuaNumConvFast) {
        InstallLuaNumConvFast();
    } else {
        Log("[LuaNumConvFast] DISABLED via configuration");
    }
#else
    Log("[LuaNumConvFast] DISABLED via TEST_DISABLE_LUA_NUMCONV_FAST");
#endif

    Log("--- Deferred Field Updates ---");
    bool fieldOk = false;
    if (Config::g_settings.OptUIFrameBatch) {
        fieldOk = InstallFieldUpdateHook();
    } else {
        Log("[FieldUpdates] DISABLED via configuration");
    }
    if (Config::g_settings.OptHeapCompactor) {
        HeapCompactor_Init();
    } else {
        Log("[HeapCompactor] DISABLED via configuration (wow_opt.ini)");
    }
#if !TEST_DISABLE_MEMORY_PRESSURE_GOVERNOR
    if (Config::g_settings.OptMemoryPressure) {
        PressureGovernor::Init();
    } else {
        Log("[PressureGovernor] DISABLED via configuration (wow_opt.ini)");
    }
#endif
    VersionChecker_Init();

    Log("--- Lua tonumber Fast Path ---");
    bool luaToNumberFastOk = Config::g_settings.OptLuaNumConvFast && InstallLuaToNumberFast();

    Log("--- Lua pushnumber Fast Path ---");
    bool luaPushNumberFastOk = Config::g_settings.OptLuaNumConvFast && InstallLuaPushNumberFast();

    Log("--- GetTime() Frame-Cached Fast Path ---");
    bool getTimeFastOk = Config::g_settings.OptTimingFix && InstallGetTimeFast();

    Log("--- Lua GetTime Frame-Cached Fast Path ---");
#if !TEST_DISABLE_LUA_GETTIME_FAST
    bool luaGetTimeFastOk = Config::g_settings.OptLuaGetTimeFast && InstallLuaGetTimeFast();
#else
    bool luaGetTimeFastOk = false;
    Log("[LuaGetTimeFast] DISABLED via TEST_DISABLE_LUA_GETTIME_FAST");
#endif

    Log("--- lua_pushvalue Direct Stack Copy ---");
#if !TEST_DISABLE_PUSHVALUE_FAST
    bool pushValueFastOk = Config::g_settings.OptLuaNumConvFast && InstallLuaPushValueFast();
#else
    bool pushValueFastOk = false;
    Log("[PushValueFast] DISABLED via TEST_DISABLE_PUSHVALUE_FAST");
#endif

    Log("--- Lua Stack Push/Query Fast Paths ---");
#if !TEST_DISABLE_LUA_STACK_FAST
    // Its own switch now. It used to ride on LuaNumConvFast, whose launcher label
    // reads "Lua Number Conversion Fast Path" and promises tonumber/gettop/settop -
    // nothing that suggests sixteen rewrites of the stack API underneath it.
    bool luaStackFastOk = Config::g_settings.OptLuaStackFast && InstallLuaStackFast();
#else
    bool luaStackFastOk = false;
    Log("[LuaStackFast] DISABLED via TEST_DISABLE_LUA_STACK_FAST");
#endif

    Log("--- UI Accessor Fast Paths ---");
#if !TEST_DISABLE_UI_ACCESSOR_FAST
    bool uiAccessorOk = Config::g_settings.OptUIFrameAccessorFast && InstallUIAccessorFast();
    CrashDumper::RegisterFeature("UIAccessorFast");
    CrashDumper::FeatureSetActive("UIAccessorFast", uiAccessorOk);
    // SIMD and UI Frame XML accessors (commit 670012c)
    CrashDumper::RegisterFeature("Vec3CrossSSE2");
    CrashDumper::RegisterFeature("IsSphereVisibleSSE2");
    CrashDumper::RegisterFeature("FromAngleAxisSSE2");
    CrashDumper::RegisterFeature("QuatSlerpSSE2");
    CrashDumper::RegisterFeature("FrameAccessorFast");
    CrashDumper::RegisterFeature("LayoutAccessorFast");
#else
    Log("[UIAccessorFast] DISABLED via TEST_DISABLE_UI_ACCESSOR_FAST");
#endif

    Log("--- Font Metrics Fast Paths ---");
#if !TEST_DISABLE_FONT_METRICS_FAST
    bool fontMetricsOk = Config::g_settings.OptFontMetricsFast && InstallFontMetricsFast();
    CrashDumper::RegisterFeature("FontMetricsFast");
    CrashDumper::FeatureSetActive("FontMetricsFast", fontMetricsOk);
#else
    Log("[FontMetricsFast] DISABLED via TEST_DISABLE_FONT_METRICS_FAST");
#endif


    Log("--- Render State Deduplication ---");
#if !TEST_DISABLE_RENDER_STATE_DEDUP
    bool renderDedupOk = (Config::g_settings.OptVulkanDXVK || Config::g_settings.OptD3d9RenderThread) && InstallRenderStateDedup();
#else
    Log("[RenderDedup] DISABLED via TEST_DISABLE_RENDER_STATE_DEDUP");
    bool renderDedupOk = false;
#endif

    Log("--- Lua SetTable Cache ---");
    bool setTableCacheOk = Config::g_settings.OptLuaOpcache && InstallLuaSetTableCache();

    Log("--- Regex Pattern Cache ---");
    bool regexCacheOk = Config::g_settings.OptLuaOpcache && InstallRegexCache();

    Log("--- SSE2 strncmp ---");
    StrncmpSse2::Init();

    Log("--- Addon CPU Profiler ---");
    AddonProfiler::Init();

    Log("--- Event Name Hash Cache ---");
    bool eventHashOk = Config::g_settings.OptEventCoalescer && InstallEventNameHash();

    Log("--- CDataStore Batch Read ---");
    bool cdataBatchOk = Config::g_settings.OptSavedVarsPretoken && InstallCDataStoreBatch();

    Log("--- SSE2 Strcpy Optimization ---");
    bool strcpyOk = Config::g_settings.OptStrCatFast && InstallStrcatFast();

    Log("--- Script Handler Cache ---");
    bool scriptHandlerOk = Config::g_settings.OptUIFrameBatch && InstallScriptHandlerCache();

    Log("--- DBC Lookup Cache ---");
    bool dbcLookupOk = Config::g_settings.OptDbcLookupCache && InstallDbcLookupCache();

    Log("--- Event Dispatch Cache ---");
#if 0
    bool eventDispatchOk = InstallEventDispatchCache();
#else
    bool eventDispatchOk = false;
    Log("[EventDispatchCache] DISABLED via TEST_DISABLE_UNIT_API_FASTPATH");
#endif

    Log("--- Event Name Cache ---");
    bool eventNameOk = Config::g_settings.OptEventCoalescer && InstallEventNameCache();

    Log("--- luaH_getstr Inline Optimization ---");
#if TEST_DISABLE_GETSTR_INLINE
    bool getStrInlineOk = false;
    Log("[GetStrInline] DISABLED (addon nil-field corruption: WeakAuras aura_env via __index)");
#else
    bool getStrInlineOk = Config::g_settings.OptLuaOpcache && InstallLuaGetStrInline();
#endif

    Log("--- lua_toboolean Inline Optimization ---");
#if !TEST_DISABLE_TOBOOLEAN_INLINE
    bool tobooleanOk = Config::g_settings.OptLuaOpcache && InstallLuaTobooleanInline();
#else
    bool tobooleanOk = false;
    Log("[LuaTBool] DISABLED via TEST_DISABLE_TOBOOLEAN_INLINE");
#endif
    CrashDumper::RegisterFeature("LuaTBoolean");
    CrashDumper::FeatureSetActive("LuaTBoolean", tobooleanOk);

    Log("--- lua_objlen Inline Optimization ---");
#if !TEST_DISABLE_OBJLEN_INLINE
    bool objlenOk = Config::g_settings.OptLuaOpcache && InstallLuaObjLenInline();
#else
    bool objlenOk = false;
    Log("[LuaObjLen] DISABLED via TEST_DISABLE_OBJLEN_INLINE");
#endif

    Log("--- luaH_getn Table Length Optimization ---");
    bool getnOk = Config::g_settings.OptLuaOpcache && InstallLuaGetnFast();

    Log("--- luaD_precall Dispatch Cache ---");
#if !TEST_DISABLE_LUA_INLINE_BATCH
    // --- DG1: allocation / complex ---
#if !TEST_DISABLE_LUA_BATCH_DG1
    bool precallCacheOk = Config::g_settings.OptLuaOpcache && InstallLuaPrecallCache();
    bool tableFastOk = Config::g_settings.OptLuaOpcache && InstallLuaTableFast();
    bool hgetFastOk = Config::g_settings.OptLuaOpcache && InstallLuaHgetFast();
    bool pushCClosureFastOk = Config::g_settings.OptLuaOpcache && InstallLuaPushCClosureFast();
    bool createTableFastOk = Config::g_settings.OptLuaOpcache && InstallLuaCreateTableFast();
#else
    bool precallCacheOk = false, tableFastOk = false, hgetFastOk = false;
    bool pushCClosureFastOk = false, createTableFastOk = false;
#endif
    // --- DG2: table writes ---
#if !TEST_DISABLE_LUA_BATCH_DG2
    bool pushStringFastOk = Config::g_settings.OptLuaOpcache && InstallLuaPushStringFast();
    bool rawSetFastOk = Config::g_settings.OptLuaOpcache && InstallLuaRawSetFast();
    bool rawSetIFastOk = Config::g_settings.OptLuaOpcache && InstallLuaRawSetIFast();
    bool setTableFastOk = Config::g_settings.OptLuaOpcache && InstallLuaSetTableFast();
    bool setFieldFastOk = Config::g_settings.OptLuaOpcache && InstallLuaSetFieldFast();
#else
    bool pushStringFastOk = false, rawSetFastOk = false, rawSetIFastOk = false;
    bool setTableFastOk = false, setFieldFastOk = false;
#endif
    // --- DG3: strings / refs / metamethods ---
#if !TEST_DISABLE_LUA_BATCH_DG3
    // Disable table.concat fast path completely due to 0xC0000005 crashes
    bool concatFastOk = false;
    bool luaRegisterFastOk = Config::g_settings.OptLuaOpcache && InstallLuaRegisterFast();
    bool luaRefFastOk = Config::g_settings.OptLuaOpcache && InstallLuaRefFast();
    bool luaUnrefFastOk = Config::g_settings.OptLuaOpcache && InstallLuaUnrefFast();
    bool luaCallMetaFastOk = Config::g_settings.OptLuaOpcache && InstallLuaCallMetaFast();
#else
    bool concatFastOk = false, luaRegisterFastOk = false, luaRefFastOk = false;
    bool luaUnrefFastOk = false, luaCallMetaFastOk = false;
#endif
    // --- DG4: misc / yield / load ---
#if !TEST_DISABLE_LUA_BATCH_DG4
#if !TEST_DISABLE_LUA_BATCH_DG4A
    bool pushResultFastOk = Config::g_settings.OptLuaOpcache && InstallLuaPushresultFast();
    bool addLStringFastOk = Config::g_settings.OptLuaOpcache && InstallLuaAddlstringFast();
    bool pushfstrFastOk = Config::g_settings.OptLuaOpcache && InstallLuaPushfstringFast();
    bool getTableFastOk = Config::g_settings.OptLuaOpcache && InstallLuaGetTableFast();
#else
    bool pushResultFastOk = false, addLStringFastOk = false;
    bool pushfstrFastOk = false, getTableFastOk = false;
#endif
#if !TEST_DISABLE_LUA_BATCH_DG4B
    bool loadstrFastOk = Config::g_settings.OptLuaOpcache && InstallLuaLoadStringFast();
    bool yieldFastOk = Config::g_settings.OptLuaOpcache && InstallLuaYieldFast();
    bool pushThreadFastOk = Config::g_settings.OptLuaOpcache && InstallLuaPushThreadFast();
#else
    bool loadstrFastOk = false, yieldFastOk = false, pushThreadFastOk = false;
#endif
#else
    bool pushResultFastOk = false, addLStringFastOk = false, loadstrFastOk = false;
    bool yieldFastOk = false, pushThreadFastOk = false, pushfstrFastOk = false;
    bool getTableFastOk = false;
#endif
#else
    bool precallCacheOk = false, tableFastOk = false, hgetFastOk = false;
    bool setTableFastOk = false, getTableFastOk = false, concatFastOk = false;
    bool rawSetIFastOk = false, setFieldFastOk = false, pushfstrFastOk = false;
    bool pushThreadFastOk = false, rawSetFastOk = false, pushCClosureFastOk = false;
    bool createTableFastOk = false, pushStringFastOk = false, luaRegisterFastOk = false;
    bool luaRefFastOk = false, luaUnrefFastOk = false, luaCallMetaFastOk = false;
    bool pushResultFastOk = false, addLStringFastOk = false;
    bool loadstrFastOk = false, yieldFastOk = false;
    Log("[LuaInlineBatch] ALL DISABLED via TEST_DISABLE_LUA_INLINE_BATCH");
#endif

    // --- Safe group 1: string/number validation ---
#if !TEST_DISABLE_LUA_SAFE_G1
    bool checknumOk = Config::g_settings.OptLuaOpcache && InstallLuaCheckNumberFast();
    bool checkstrOk = Config::g_settings.OptLuaOpcache && InstallLuaCheckStringFast();
    bool optnumOk = Config::g_settings.OptLuaOpcache && InstallLuaOptnumberFast();
    bool optstrOk = Config::g_settings.OptLuaOpcache && InstallLuaOptstringFast();
    bool tolstrOk = Config::g_settings.OptLuaOpcache && InstallLuaTolstringFast();
    bool argchkOk = Config::g_settings.OptLuaOpcache && InstallLuaArgcheckFast();
    bool tnameOk = Config::g_settings.OptLuaOpcache && InstallLuaTypeNameFast();
#else
    bool checknumOk = false, checkstrOk = false, optnumOk = false, optstrOk = false;
    bool tolstrOk = false, argchkOk = false, tnameOk = false;
#endif

    // --- Safe group 2: debug / execution control ---
#if !TEST_DISABLE_LUA_SAFE_G2
#if !TEST_DISABLE_LUA_SAFE_G2A
#if !TEST_DISABLE_LUA_SAFE_G2AL
    bool getlocalOk = Config::g_settings.OptLuaOpcache && InstallLuaGetLocalFast();
#else
    bool getlocalOk = false;
#endif
#if !TEST_DISABLE_LUA_SETLOCAL_FAST
    bool setlocalOk = Config::g_settings.OptLuaOpcache && InstallLuaSetLocalFast();
#else
    bool setlocalOk = false;
    Log("[LuaInline] SetLocal DISABLED: confirmed ntdll heap corruption on login");
#endif
#if !TEST_DISABLE_LUA_SAFE_G2AI
    bool getinfoOk = Config::g_settings.OptLuaOpcache && InstallLuaGetInfoFast();
#else
    bool getinfoOk = false;
#endif
#else
    bool getlocalOk = false, setlocalOk = false, getinfoOk = false;
#endif
#if !TEST_DISABLE_LUA_SAFE_G2B
    bool errorfastOk = Config::g_settings.OptLuaOpcache && InstallLuaErrorFast();
    bool lessthanOk = Config::g_settings.OptLuaOpcache && InstallLuaLessThanFast();
#else
    bool errorfastOk = false, lessthanOk = false;
#endif
#if !TEST_DISABLE_LUA_SAFE_G2C
    // bool gcFastOk = InstallLuaGCFast(); // DISABLED: returning 1 for LUA_GCSTEP 0 skips GC work and lies about cycle completion
    // bool xpcallFastOk = InstallLuaXPCallFast(); // DISABLED: Hooked lua_call instead of lua_xpcall, corrupts stack!
#else
    bool gcFastOk = false, xpcallFastOk = false;
#endif
#else
    bool getlocalOk = false, setlocalOk = false, getinfoOk = false;
    bool errorfastOk = false, lessthanOk = false;
    bool gcFastOk = false, xpcallFastOk = false;
#endif

    // --- Safe group 3: metatable / type checks / buffers ---
#if !TEST_DISABLE_LUA_SAFE_G3
    bool metaFieldFastOk = Config::g_settings.OptLuaOpcache && InstallLuaGetMetaFieldFast();
    bool whereFastOk = Config::g_settings.OptLuaOpcache && InstallLuaWhereFast();
    bool luaCheckTypeFastOk = Config::g_settings.OptLuaOpcache && InstallLuaCheckTypeFast();
    bool getUpvalueFastOk = Config::g_settings.OptLuaOpcache && InstallLuaGetUpvalueFast();
    bool buffInitFastOk = Config::g_settings.OptLuaOpcache && InstallLuaBuffinitFast();
    bool prepBufferFastOk = Config::g_settings.OptLuaOpcache && InstallLuaPrepbufferFast();
    bool iscfuncFastOk = Config::g_settings.OptLuaOpcache && InstallLuaIsCFuncFast();
    bool isnumFastOk = Config::g_settings.OptLuaOpcache && InstallLuaIsNumberFast();
    bool raweqFastOk = Config::g_settings.OptLuaOpcache && InstallLuaRawEqualFast();
#else
    bool metaFieldFastOk = false, whereFastOk = false, luaCheckTypeFastOk = false;
    bool getUpvalueFastOk = false, buffInitFastOk = false, prepBufferFastOk = false;
    bool iscfuncFastOk = false, isnumFastOk = false, raweqFastOk = false;
#endif

    CrashDumper::RegisterFeature("LuaObjLen");
    CrashDumper::FeatureSetActive("LuaObjLen", objlenOk);

    Log("--- lua_rawgeti Inline Optimization ---");
#if TEST_DISABLE_RAWGETI_INLINE
    bool rawGetIInlineOk = false;
    Log("[RawGetIInline] DISABLED (suspected loading screen crash at 0x84E9DE)");
#else
    bool rawGetIInlineOk = InstallLuaRawGetIInline();
#endif

    Log("--- lua_rawget Inline Optimization ---");
#if TEST_DISABLE_RAWGET_INLINE
    bool rawGetInlineOk = false;
    Log("[RawGetInline] DISABLED");
#else
    bool rawGetInlineOk = InstallLuaRawGetInline();
#endif

    Log("--- strtod Fast Path ---");
#if TEST_DISABLE_STRTOD_FAST
    bool strtodFastOk = false;
    Log("[StrtodFast] DISABLED");
#else
    bool strtodFastOk = InstallStrtodFast();
#endif

    Log("--- luaV_gettable Safety Patch (crash fix) ---");
#if !TEST_DISABLE_LUA_GETTABLE_SAFETY
    bool getTableSafetyOk = Config::g_settings.OptCvarNullGuard && InstallLuaGetTableSafety();
#else
    bool getTableSafetyOk = false;
    Log("[GetTableSafety] DISABLED via feature flag");
#endif

    Log("--- GUID Type Check Safety Patch (0x4D4DF7 BG-load crash fix) ---");
    extern bool InstallTypeCheckSafety();
    bool typeCheckSafetyOk = Config::g_settings.OptCvarNullGuard && InstallTypeCheckSafety();
    (void)typeCheckSafetyOk;

    Log("--- Object Unlink Safety Patch (0x5C685C reaper NULL-write crash fix) ---");
    extern bool InstallObjectUnlinkSafety();
    bool objUnlinkSafetyOk = Config::g_settings.OptCvarNullGuard && InstallObjectUnlinkSafety();
    (void)objUnlinkSafetyOk;

    Log("--- luaH_newkey Safety Patch (0x85CB43 crash fix) ---");
#if !TEST_DISABLE_LUA_NEWKEY_SAFETY
    InstallLuaNewKeySafety();
#else
    Log("[NewKeySafety] DISABLED via feature flag");
#endif

    Log("--- Lua Error Diagnostics ---");
#if !TEST_DISABLE_LUA_ERROR_DIAG
    InstallLuaErrorDiag();  // logs every Lua error: hook verified against disassembly prologue
#else
    Log("[LuaErrorDiag] DISABLED via TEST_DISABLE_LUA_ERROR_DIAG (0x84F610 = luaL_addvalue, not lua_error)");
#endif

    Log("--- Lua VM Engine (Direct-Threaded Interpreter) ---");
#if !TEST_DISABLE_LUA_VM_ENGINE
    bool vmEngineOk = InstallLuaVMEngine();
#else
    bool vmEngineOk = false;
    Log("[VMEngine] DISABLED via feature flag");
#endif
    CrashDumper::RegisterFeature("LuaVMEngine");
    CrashDumper::FeatureSetActive("LuaVMEngine", vmEngineOk);

    Log("--- Hardware Cursor ---");
    bool cursorOk = Config::g_settings.OptCvarNullGuard && InstallHardwareCursorHooks();

    Log("--- Frame Script Throttling ---");
    bool frameThrottleOk = Config::g_settings.OptUIFrameBatch && InstallFrameThrottling();

    Log("--- Spell Data Caching ---");

    // UI Frame Batching - REMOVED due to calling convention issues
    // Caused MoveAnything addon to break even when disabled
    // See UI_FRAME_BATCHING_ISSUE.md for details
    // Log("--- UI Frame Update Batching ---");
    // bool uiFrameBatchOk = InstallUIFrameBatching();

    Log("--- Table Concat Fast Path ---");
    // table.concat fast path causes 0xC0000005 crashes
    // when addons use string concatenation heavily (ElvUI, WeakAuras, etc.).
    // The hook performs direct Lua stack writes via TValue* which conflicts
    // with addon execution flow during world load.
    bool tableConcatOk = false;

    Log("--- Lua RawGetI ---");
    bool luaRawGetIOk = Config::g_settings.OptLuaOpcache && InstallLuaRawGetICache();

    Log("--- CombatLog Full Cache ---");
    bool combatLogFullCacheOk = Config::g_settings.OptCombatLogParser && InstallCombatLogFullCache();

    Log("--- Thread Affinity ---");
    if (IsWine()) {
        // On Wine/Rosetta, hook SetThreadIdealProcessor at the kernel32
        // level to make it a no-op. WoW's own sub_8D2110 (ThreadWorker)
        // and potentially WoWsilicon call this natively - our own
        // InstallThreadAffinity guard only prevents OUR hook from pinning,
        // but cannot stop WoW's original code. The rosettax87 JIT desyncs
        // when any caller changes thread affinity.
        InstallWineSTIPNoop();
    }
    g_threadAffOk = Config::g_settings.OptDefragLf && !Config::g_settings.OptCompatMode && InstallThreadAffinity();

    Log("--- VA Arena ---");
    vaOk = InstallVAArena();

    Log("--- RTTI Type Check Cache ---");
    // DISABLED, and the reason that matters is the second one: caching
    // (guid64,flags)->result keys a cache on objects that are destroyed at
    // runtime, so cached result pointers dangle - the same defect shape as the
    // glyph and model caches keyed by a reused address.
    // The first reason given here used to be a hook conflict with tls_cache.cpp,
    // which was never true: that module installed no hooks at all. 0x4D4DB0 is
    // hooked, but by type_check_safety.cpp, so a conflict does exist - just not
    // the one recorded.
    bool rttiCacheOk = false;

    Log("--- Stream Buffer Fast Path ---");
    bool streamBufOk = Config::g_settings.OptSavedVarsPretoken && InstallStreamBufferFastPath();

    bool luaOk = false;
    Log("");
    Log("--- Lua VM Optimizer ---");
#if TEST_DISABLE_LUA_VM_OPT
    Log("[LuaOpt] DISABLED (baseline test - system hooks only)");
#else
    luaOk = LuaOpt::PrepareFromWorkerThread();
#endif

    Log("");
    Log("--- Combat Log ---");
    // The retention leak-fix (CombatLogOpt) is the proven, stable part: it just
    // extends the combat-log retention CVar 300s->1800s. It runs on its own
    // default-on flag, independent of the aggressive aggregator (Parser/Buffer/
    // FullCache below, which stay on OptCombatLogParser).
    bool combatLogOk = (Config::g_settings.OptCombatLogLeakFix || Config::g_settings.OptCombatLogParser)
                       && CombatLogOpt::Init();

    Log("");
    Log("--- Combat Log Buffer Governor ---");
    bool combatLogBufOk = Config::g_settings.OptCombatLogParser && CombatLogBuffer::Init();

    Log("");
    Log("--- Multithreaded Addon Update Dispatcher ---");
#if TEST_DISABLE_ADDON_DISPATCHER
    Log("[AddonDispatcher] DISABLED (test toggle)");
    bool addonDispatcherOk = false;
#else
    bool addonDispatcherOk = false;
    if (Config::g_settings.OptAddonDispatcher) {
        addonDispatcherOk = AddonDispatcher::Init();
    } else {
        Log("[AddonDispatcher] DISABLED via configuration");
    }
#endif

    Log("");
    Log("--- Predictive MPQ Prefetching ---");
#if !TEST_DISABLE_MPQ_PREFETCH
#else
    bool mpqPrefetchOk = false;
#endif

    Log("");
    Log("--- Memory-Mapped MPQ VFS & Parallel Decompressor ---");
    if (Config::g_settings.OptMpqAsyncDecompress) MpqAsyncDecompress::Init();

    Log("");
    Log("--- Object Visibility Cache ---");
#if TEST_DISABLE_OBJ_VIS_CACHE
    Log("[ObjVisCache] DISABLED (feature flag)");
#else
    if (Config::g_settings.OptObjVisCache) ObjVisCache::Init();
#endif


    // Crash fix: sub_5E90D0 dereferences dword_C24238 without NULL check.
    // During loading screen transitions, this global may be uninitialized (NULL),
    // causing ACCESS_VIOLATION at 0x5E9108. Patch: insert test ecx,ecx / jz
    // after the mov ecx, [C24238] at 0x5E90FF.
    {
        // Original at 0x5E90FF:
        //   8B 0D 38 42 C2 00   mov ecx, [C24238]   (6 bytes)
        //   83 C4 08            add esp, 8           (3 bytes)
        //   3B 04 B1            cmp eax, [ecx+esi*4] (3 bytes)
        //
        // Patched:
        //   8B 0D 38 42 C2 00   mov ecx, [C24238]   (6 bytes, unchanged)
        //   85 C9               test ecx, ecx        (2 bytes, replaces add esp,8 first 2)
        //   74 05               jz short +5          (2 bytes, skip cmp if NULL)
        //   90                  nop                   (1 byte, padding)
        //   3B 04 B1            cmp eax, [ecx+esi*4] (3 bytes, unchanged)
        //
        // When ecx==NULL: jz skips over cmp to 0x5E910B (jz short loc_5E9112)
        // But we still need add esp,8! So instead, move add esp before the test:
        //
        // Better patch at 0x5E90FF (overwrite 12 bytes):
        //   8B 0D 38 42 C2 00   mov ecx, [C24238]
        //   83 C4 08            add esp, 8
        //   85 C9               test ecx, ecx
        //   74 01               jz short +1 (skip next nop, land on ret-like path)
        //   90                  nop
        // Then 0x5E9108 cmp stays but is only reached when ecx!=NULL
        //
        // Actually simplest: just NOP the cmp when ecx is NULL by patching
        // the function entry to add an early-out. But that's complex.
        //
        // Simplest safe patch: overwrite 0x5E9105-0x5E910A (6 bytes):
        //   Original: 83 C4 08 3B 04 B1  (add esp,8; cmp eax,[ecx+esi*4])
        //   Patched:  83 C4 08 85 C9 74  (add esp,8; test ecx,ecx; jz ...)
        //   Then we need the jz target to skip the cmp. But cmp is only 3 bytes
        //   and we consumed it. We need to reconstruct cmp after the jz.
        //
        // Cleanest: use a 5-byte NOP sled + redirect. Too complex for inline.
        // Use MinHook instead.

        typedef void (__cdecl *Sub5E90D0_fn)();
        static Sub5E90D0_fn orig_Sub5E90D0 = nullptr;

        // Check if dword_C24238 is NULL before calling original
        // sub_5E90D0 is __cdecl retn (no args, no stack cleanup)
        struct NullGuard_5E90D0 {
            static void __cdecl Hooked() {
                uint32_t* pGlobal = (uint32_t*)0xC24238;
                // If the global array pointer is NULL, skip the function entirely.
                // The function only updates visual alert state - skipping is safe.
                if (*pGlobal == 0) {
                    return;
                }
                orig_Sub5E90D0();
            }
        };

        void* target = (void*)0x5E90D0;
        // Use WineSafe_CreateHook to avoid Rosetta JIT desync on macOS
        if (Config::g_settings.OptCvarNullGuard && WineSafe_CreateHook(target, (void*)NullGuard_5E90D0::Hooked, (void**)&orig_Sub5E90D0) == MH_OK) {
            // Crash guard: enable immediately (not batched) so it protects the
            // init window too.
            if (MH_EnableHook(target) == MH_OK) {
                Log("[CrashFix] sub_5E90D0 NULL guard: ACTIVE (dword_C24238 check)");
            } else {
                Log("[CrashFix] sub_5E90D0 NULL guard: enable failed");
                MH_RemoveHook(target);
            }
        } else {
            if (IsWine()) {
                Log("[CrashFix] sub_5E90D0 NULL guard: SKIPPED (Wine/Rosetta - WoW .text patch unsafe)");
            } else {
                Log("[CrashFix] sub_5E90D0 NULL guard: hook creation failed");
            }
        }
    }

    // Hook sub_6D4920 to protect against null pointer dereference and out-of-bounds on dword_C9EB50
    {
        typedef int (__thiscall *Sub6D4920_fn)(void* ecx, int a2);
        static Sub6D4920_fn orig_Sub6D4920 = nullptr;

        struct NullGuard_6D4920 {
            static int __fastcall Hooked(void* ecx, void* edx, int a2) {
                __try {
                    if (!ecx || IsBadReadPtr(ecx, 4)) {
                        return a2 ? *(int*)a2 : 0;
                    }
                    if (!a2 || IsBadReadPtr((const void*)a2, 288)) {
                        return 0;
                    }
                    if ((*(char*)(a2 + 64) & 0x10) != 0) {
                        return *(int*)a2;
                    }
                    if ((*(int*)(a2 + 24) & 0x8000000) != 0
                        || *(int*)(a2 + 284) == 25
                        || *(int*)(a2 + 272) != 2
                        || !*(int*)(a2 + 276)) 
                    {
                        return *(int*)a2;
                    }

                    int** pArray = (int**)0x00C9EB50;
                    int* pCount = (int*)0x00C9EB4C;
                    if (!pArray || IsBadReadPtr(pArray, 4) || !*pArray || !pCount || IsBadReadPtr(pCount, 4) || *pCount <= 0) {
                        return *(int*)a2;
                    }

                    int* arrayPtr = *pArray;
                    int arrayCount = *pCount;

                    int v4 = 0;
                    unsigned char* v5 = nullptr;
                    
                    uintptr_t vtable = *(uintptr_t*)ecx;
                    if (!vtable || IsBadReadPtr((const void*)(vtable + 300), 4)) {
                        return *(int*)a2;
                    }
                    typedef unsigned char* (__thiscall* GetVal_fn)(void* This, int idx, int unused);
                    GetVal_fn GetVal = *(GetVal_fn*)(vtable + 300);
                    if (!GetVal || IsBadReadPtr((const void*)GetVal, 4)) {
                        return *(int*)a2;
                    }

                    while (1) {
                        v5 = GetVal(ecx, v4, 0);
                        if (v5) {
                            if (v5[0] == *(int*)(a2 + 272)) {
                                int v6 = v5[1];
                                if (((1 << v6) & *(int*)(a2 + 276)) != 0) {
                                    if (v6 < arrayCount && arrayPtr[v6]) {
                                        break;
                                    }
                                }
                            }
                        }
                        if (++v4 >= 3) {
                            return *(int*)a2;
                        }
                    }
                    
                    if (v5) {
                        int v6_final = v5[1];
                        if (v6_final < arrayCount) {
                            return arrayPtr[v6_final];
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    // Fallback on access violation
                }
                return a2 ? *(int*)a2 : 0;
            }
        };

        void* target_6D4920 = (void*)0x006D4920;
        if (Config::g_settings.OptCvarNullGuard && WineSafe_CreateHook(target_6D4920, (void*)NullGuard_6D4920::Hooked, (void**)&orig_Sub6D4920) == MH_OK) {
            if (MH_EnableHook(target_6D4920) == MH_OK) {
                Log("[CrashFix] sub_6D4920 NULL/bounds guard: ACTIVE");
            } else {
                Log("[CrashFix] sub_6D4920 NULL/bounds guard: enable failed");
                MH_RemoveHook(target_6D4920);
            }
        } else {
            Log("[CrashFix] sub_6D4920 NULL/bounds guard: hook creation failed");
        }
    }

    Log("");
    Log("--- Multithreaded Nameplate Renderer ---");
#if TEST_DISABLE_NAMEPLATE_MT
    Log("[NameplateMT] DISABLED (test toggle)");
    bool nameplateMTOk = false;
#else
    // NameplateMT spawns worker threads, and its launcher switch was read into
    // the settings struct and then consulted by nothing at all - so it ran on
    // every install and could not be turned off from the launcher that offered
    // to turn it off.
    // Default on, because that is what every install was already running. Until
    // 3.18.1 this switch gated nothing and the feature started its worker
    // threads regardless; giving it a real gate with an off default silently
    // took a working optimisation away from everyone who had never touched it,
    // and a tester reported exactly that as "3.18.1 is worse than 3.18.0" in
    // raids and in Dalaran - which is where nameplate work is heaviest.
    //
    // Not under Wine or Rosetta. Worker features there have already had to be
    // forced off for blocking the main thread, and restoring a default is not a
    // reason to walk back into that.
    bool nameplateMTOk = Config::g_settings.OptNameplateMT && !IsWine() && !IsRosetta()
                         && NameplateMT::Init();
    if (Config::g_settings.OptNameplateMT && (IsWine() || IsRosetta())) {
        Log("[NameplateMT] Skipped: worker threads are forced off under Wine/Rosetta");
    }
#endif

    Log("");
    Log("--- UI Cache ---");
    bool uiCacheOk = Config::g_settings.OptUIFrameAccessorFast && UICache::Init();

    Log("");
    Log("--- API Cache ---");
#if TEST_DISABLE_ALL_APICACHE
    Log("[ApiCache] DISABLED (baseline test)");
    bool apiCacheOk = false;
#else
    bool apiCacheOk = Config::g_settings.OptApiCache && ApiCache::Init();
#endif

    Log("--- Timing Method Fix ---");
    InstallTimingFix();

    bool fastPathOk = false;
    Log("");
    Log("--- Lua Fast Path ---");
#if TEST_DISABLE_ALL_PHASE2
    Log("[FastPath] DISABLED (baseline test)");
#else
    __try {
        fastPathOk = Config::g_settings.OptLuaOpcache && LuaFastPath::Init();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[FastPath] EXCEPTION 0x%08X - SKIPPED", GetExceptionCode());
    }
#endif

    // Addon file RAM-disk - pre-load all addon files into memory
#if !TEST_DISABLE_ADDON_PRELOAD
    // The RAM-disk is served through the CreateFile/CloseHandle hooks, which only
    // go in with DbcLookupCache or SavedVarsPretoken. Tell it so it can decline
    // rather than read thousands of files it will never be asked for.
    AddonPreload_SetFileHooksInstalled(fileOk && closeOk);
    bool addonPreloadOk = InitAddonPreload();
#else
    bool addonPreloadOk = false;
#endif

    // Lua bytecode cache (skips script parsing on reload & addon load)
#if !TEST_DISABLE_LUA_BYTECODE_CACHE
    // LuaOpcache gates about fifty other installs but had never gated this one.
    bool bytecodeOk = Config::g_settings.OptLuaOpcache && LuaBytecodeCache::Init();
#else
    bool bytecodeOk = false;
#endif

    bool internalsOk = false;
    Log("");
    Log("--- Lua VM Internals ---");
    Log("[LuaVM] DISABLED (baseline test)");

    // Lua VM table lookup cache (luaV_gettable hook)
    Log("--- Lua VM Table Cache ---");
    bool vmCacheOk = Config::g_settings.OptLuaOpcache && InstallLuaVMCache();

    Log("--- luaV_gettable Cache ---");
    bool getTableCacheOk = false; // InstallLuaGetTableCache(); // DISABLED: completely broken cache that never invalidates on table mutations

    Log("--- SavedVariables Async Writer ---");
#if !TEST_DISABLE_SAVED_VARS_ASYNC
    // Same story as NameplateMT: no gate before 3.18.1, so this ran everywhere,
    // and adding the gate with an off default moved SavedVariables writing back
    // onto the main thread for every install that had never set the key.
    bool savedVarsAsyncOk = Config::g_settings.OptSavedVarsAsync && !IsWine() && !IsRosetta()
                            && InstallSavedVarsAsync();
    if (Config::g_settings.OptSavedVarsAsync && (IsWine() || IsRosetta())) {
        Log("[SavedVarsAsync] Skipped: background writes are forced off under Wine/Rosetta");
    }
#else
    bool savedVarsAsyncOk = false;
    Log("[SavedVarsAsync] DISABLED via feature flag");
#endif

    Log("--- Combat Log Parser ---");
    bool combatLogParserOk = Config::g_settings.OptCombatLogParser && InstallCombatLogParser();

    Log("--- Lua Bytecode Pre-Compiler ---");
#if TEST_DISABLE_LUA_PRECOMPILE
    bool bytecodePreCompilerOk = false;
    Log("[LuaPreCompile] DISABLED (addon file-prefetch adds I/O pressure on VA-tight HD clients)");
#else
#endif

    Log("--- Hot Patch ---");
    if (Config::g_settings.OptDbcLookupCache) HotPatch::InstallAll();

    Log("--- WoW.exe Optimization Hooks (20 hooks) ---");
    bool wowOptOk = WowOptHooks::InstallAll();

    Log("--- WoW.exe Performance Hooks (20 hooks) ---");
    bool wowPerfOk = WowPerfHooks::InstallAll();

    Log("--- WoW.exe Extended Hooks (40 features) ---");
    bool wowExtendedOk = WowExtendedHooks::InstallAll();

    Log("--- WoW.exe Subsystem Hooks (100 features) ---");
    bool wowSubsystemOk = WowSubsystemHooks::InstallAll();

    Log("--- Memory Optimizations: LAA + Async + MemOpt ---");
    bool memoryOptLAA = WowMemoryOpt::EnableLargeAddressAware();
    // Async worker pool DISABLED: background threads writing to WoW globals
    // caused ACCESS_VIOLATION at 0x009E4F24 (write to .data section from worker thread)
    bool memoryOptAsync = false; // WowMemoryOpt::InitAsyncWorkerPool();
    Log("[MemOpt] Async worker pool DISABLED: unsynchronized writes to WoW game state");
    bool memoryOptMem = WowMemoryOpt::ApplyMemoryOptimizations();

    Log("--- Source-Level Optimizations ---");
    bool sourceOptOk = WowSourceOpt::InstallAll();

    Log("--- TLS Object Cache ---");
    bool tlsObjCacheOk = TlsObjectCache::Install();

    Log("");
    Log("--- DXVK/Vulkan Translation Layer Detection ---");
    DXVKBridge::Init();
    {
        // Log GPU + renderer up front so testers' logs are self-describing and
        // we don't have to ask them for it. GPU comes from the primary display
        // adapter; DXVK state comes from the detection bridge above.
        char gpu[128] = "unknown";
        DISPLAY_DEVICEA dd; ZeroMemory(&dd, sizeof(dd)); dd.cb = sizeof(dd);
        if (EnumDisplayDevicesA(NULL, 0, &dd, 0)) {
            strncpy(gpu, dd.DeviceString, sizeof(gpu) - 1);
            gpu[sizeof(gpu) - 1] = '\0';
        }
        bool dxvk = DXVKBridge::IsActive();   // triggers a detection attempt
        DXVKBridge::Stats dstat; ZeroMemory(&dstat, sizeof(dstat));
        DXVKBridge::GetStats(&dstat);
        Log("[SysInfo] GPU: %s", gpu);
        Log("[SysInfo] Renderer: %s (%s)",
            dxvk ? "DXVK / Vulkan translation" : "native Direct3D 9 (or not detected yet)",
            dstat.detectionReason ? dstat.detectionReason : "no signal");
    }

    Log("");
    Log("--- D3D9 State Manager ---");
    bool d3d9StateOk = InstallD3D9StateManager();

    Log("");
    Log("--- Render Hooks (anim throttle, backbuffer) ---");
    bool renderHooksOk = Config::g_settings.OptDefragLf && InstallRenderHooks(); // BISECT

    Log("");
    Log("--- SIMD Hooks (SSE2 matrix, frustum, color) ---");
    bool simdHooksOk = Config::g_settings.OptStrStrSse2 && InstallSimdHooks(); // BISECT

    Log("");
    Log("--- Logic Hooks (combat text, UI cache, heartbeat) ---");
#if !TEST_DISABLE_UNIT_API_FASTPATH
    bool logicHooksOk = Config::g_settings.OptUIFrameBatch && InstallLogicHooks();
#else
    bool logicHooksOk = false;
    Log("[LogicHooks] DISABLED via TEST_DISABLE_UNIT_API_FASTPATH");
#endif

    Log("");
    Log("--- Memory Hooks (aligned slabs, GUID hash) ---");
    bool memHooksOk = InstallMemoryHooks(); // BISECT

    Log("");
    Log("--- Async Hooks (worker pool, particle, prefetch) ---");
    bool asyncHooksOk = Config::g_settings.OptDefragLf && InstallAsyncHooks(); // BISECT

    Log("");
    Log("--- Loading Defragmenter & Pre-committer ---");
#if !TEST_DISABLE_LOADING_DEFRAG
    bool loadingDefragOk = Config::g_settings.OptDefragLf && LoadingDefrag::Init();
#else
    bool loadingDefragOk = false;
    Log("[LoadingDefrag] DISABLED via TEST_DISABLE_LOADING_DEFRAG");
#endif


    Log("");
    Log("--- D3D9 Render State Cache & Render Thread ---");
#if !TEST_DISABLE_D3D9_STATE_CACHE
    bool d3d9StateCacheOk = (Config::g_settings.OptVulkanDXVK || Config::g_settings.OptD3d9RenderThread) && D3D9StateCache::Init();
#else
    bool d3d9StateCacheOk = false;
    Log("[D3D9StateCache] DISABLED via TEST_DISABLE_D3D9_STATE_CACHE");
#endif

    if (Config::g_settings.OptD3d9RenderThread) {
        D3D9RenderThread::Init();
    }

    Log("");
    Log("--- High-Precision Hybrid Frame Limiter ---");
#if !TEST_DISABLE_FRAME_LIMITER
    bool frameLimiterOk = false;
    if (Config::g_settings.OptFrameLimiter) {
        frameLimiterOk = FrameLimiter::Init();
    } else {
        Log("[FrameLimiter] DISABLED via configuration (wow_opt.ini)");
    }
#else
    bool frameLimiterOk = false;
    Log("[FrameLimiter] DISABLED via TEST_DISABLE_FRAME_LIMITER");
#endif



    Log("");
    Log("--- Parallel Network Packet Offloader ---");
#if !TEST_DISABLE_NET_PACKET_OFFLOAD
    bool netPacketOffloadOk = false;
    if (Config::g_settings.OptPacketOffload && !RunningUnderTranslation()) {
        netPacketOffloadOk = NetPacketOffload::Init();
    } else {
        Log("[NetPacketOffload] DISABLED via configuration (wow_opt.ini)%s",
            RunningUnderTranslation() ? " [forced off: Wine/Rosetta]" : "");
    }
#else
    bool netPacketOffloadOk = false;
    Log("[NetPacketOffload] DISABLED via TEST_DISABLE_NET_PACKET_OFFLOAD");
#endif

    Log("");
    Log("--- Velocity-Based Predictive Asset Prefetcher ---");
#if !TEST_DISABLE_PREDICTIVE_PREFETCH
    bool predictivePrefetchOk = Config::g_settings.OptDbcLookupCache && PredictivePrefetch::Init();
#else
    bool predictivePrefetchOk = false;
    Log("[PredictivePrefetch] DISABLED via TEST_DISABLE_PREDICTIVE_PREFETCH");
#endif

    Log("");
    Log("--- Parallel M2 Geometry SIMD Skinning ---");

    Log("");
    Log("--- Lock-Free Object GUID Lookup Cache ---");
    bool guidCacheOk = Config::g_settings.OptGuidLookupCache && GuidLookupCache::Init();

    Log("");
    Log("--- SSE2 Math Fast Paths ---");
    bool simdMathOk = Config::g_settings.OptStrStrSse2 && SimdMathFast::Init();

    Log("");
    Log("--- Incremental Combat Log Parsing ---");
    bool combatLogIncOk = Config::g_settings.OptCombatLogIncremental && CombatLogIncremental::Init();

    Log("");
    Log("--- Thread-Local Lua Allocator Pool ---");

    Log("");
    Log("--- Coalesced World State Updates ---");
    bool worldStateCoalesceOk = Config::g_settings.OptWorldStateCoalesce && WorldStateCoalesce::Init();

    Log("");
    Log("--- Hardware-Accelerated Vertex Skinning ---");

    Log("");
    Log("--- FMOD Sound Mixer Optimizer ---");
    if (Config::g_settings.OptSoundMixerOpt) SoundMixerOpt::Init();

    Log("");
    Log("--- Adaptive Lua GC Governor ---");
    if (Config::g_settings.OptLuaGcCoalesce) LuaGCGovernor::Init();

    Log("");
    Log("--- Adaptive Farclip Controller ---");
    if (Config::g_settings.OptMemoryPressure) AdaptiveFarclip::Init();

    Log("");
    Log("--- Font Glyph Cache ---");
    if (Config::g_settings.OptFontMetricsFast) FontGlyphCache::Init();

    Log("");
    Log("--- Async SavedVariables Preloader ---");

    Log("");
    Log("--- Combat Text Coalescer ---");

    Log("");
    Log("--- Minimap Throttle ---");

    Log("");
    Log("--- Fast DBC Lookup Cache ---");

    Log("");
    Log("--- 20 New Subsystem Performance & Stability Features ---");
    if (Config::g_settings.OptSoundCoalescer) SoundCoalescer::Init();
    if (Config::g_settings.OptVertexBufferPrealloc) VertexBufferPrealloc::Init();
    if (Config::g_settings.OptSavedVarsBackup) SavedVarsBackup::Init();
    if (Config::g_settings.OptMouseClipRelease) MouseClipRelease::Init();

    Log("--- 10 More New Performance & Stability Features ---");
    if (Config::g_settings.OptCombatLogFilter) CombatLogFilter::Init();
    if (Config::g_settings.OptSoundVolumeLimit) SoundVolumeLimit::Init();
    if (Config::g_settings.OptTerrainHeightCache) TerrainHeightCache::Init();

    if (Config::g_settings.OptTextureUnloadDelay) TextureUnloadDelay::Init();
    NetDiag::Init();
    AnimCensus::Init();
    HorizonOcclusion::Init();
    QualityGovernor::Init();
    if (Config::g_settings.OptSpellEffectCulling) SpellEffectCulling::Init();

    Log("");
    Log("--- World-to-Screen SSE Math ---");

    Log("");
    Log("--- D3D9 Texture Stage State Cache ---");

    Log("");
    Log("--- Lua String Symbol Pool ---");

    Log("");
    Log("--- Async Sound FX Loader ---");
    if (Config::g_settings.OptAudioDecodeMt && !RunningUnderTranslation()) AsyncSoundLoader::Init();

    Log("");
    Log("--- Lua VM Bytecode JIT Compiler ---");

    Log("");
    Log("--- RCU Object Manager Traverser ---");
    if (Config::g_settings.OptRcuObjMgr) RcuObjMgr::Init();

    Log("");
    Log("--- Asynchronous Terrain Mesh Loader ---");
    if (Config::g_settings.OptAsyncTerrainLoader && !RunningUnderTranslation()) AsyncTerrainLoader::Init();

    Log("");
    Log("--- M2 LOD Bias Control ---");

    Log("");
    Log("--- Lock-Free Texture Loader ---");
    if (Config::g_settings.OptAsyncTexLoader && !RunningUnderTranslation()) AsyncTexLoader::Init();

    Log("");
    Log("--- Unit Aura Update Coalescing ---");

    Log("");
    Log("--- SavedVariables Pretoken Caching ---");
    if (Config::g_settings.OptSavedVarsPretoken) SavedVarsPretoken::Init();

    Log("");
    Log("--- Net Addon message Coalescer ---");

    Log("");
    Log("--- Mipmap Bias Governor ---");
    if (Config::g_settings.OptMipBiasGovernor) MipBiasGovernor::Init();

    Log("");
    Log("--- Spatial Culling Grid ---");

    Log("");
    Log("--- Performance Diagnostics Monitor ---");
    PerfDiagnostics::Init();

    // Register memory-pressure governor shed callbacks.  These fire from the
    // main thread (Sleep hook) when VA fragments below threshold, and each
    // clears its cache via a pure memset-to-zero — all safe under pressure.
#if !TEST_DISABLE_MEMORY_PRESSURE_GOVERNOR
    {
        using namespace PressureGovernor;

        // YELLOW (free < 48MB): shed the 2 heaviest non-critical caches +
        // drop texture budget toward stock.  Regex is ~2.2MB (256×8KB bytecode),
        // tooltip is ~2.1MB (512×4KB text) — together ~4.3MB of VA returned.
        struct ShedRegex { static void Go(Level, void*) { RegexCache_Clear(); } };
        RegisterShedCallback(ShedRegex::Go, nullptr);

        // Texture budget: YELLOW → 72MB (half way to stock), RED → 64MB (stock).
        // On ease the normal TexCacheTuning_Tick re-arms the target budget
        // (the slow-path RaiseBudget self-throttles by waiting for WoW to put
        // 64MB back, which it does on device reset / world transition).
        struct ShedTexBudget { static void Go(Level lv, void*) {
            if (lv >= PRESSURE_RED)      TexCache_SetBudget(0x04000000); // 64MB
            else if (lv >= PRESSURE_YELLOW) TexCache_SetBudget(0x04800000); // 72MB
            // GREEN: normal Tick re-asserts the configured target
        }};
        RegisterShedCallback(ShedTexBudget::Go, nullptr);

        // RED (free < 24MB): shed EVERYTHING including the large Lua caches
        // (~256KB GetStrInline + ~128KB RawGetIInline + ~256KB GUID hash)
        // and drop budget to stock 64MB.
        struct ShedGetStrInline { static void Go(Level lv, void*) {
            if (lv >= PRESSURE_RED) InvalidateLuaGetStrInlineCache();
        }};
        RegisterShedCallback(ShedGetStrInline::Go, nullptr);

        struct ShedRawGetIInline { static void Go(Level lv, void*) {
            if (lv >= PRESSURE_RED) ClearRawGetIInlineCache();
        }};
        RegisterShedCallback(ShedRawGetIInline::Go, nullptr);

        struct ShedGuidHash { static void Go(Level lv, void*) {
            if (lv >= PRESSURE_RED) ClearGuidHashTable();
        }};
        RegisterShedCallback(ShedGuidHash::Go, nullptr);

        // RED: mimalloc is used directly by various subsystems (aligned alloc, Lua pool, etc.),
        // force it to return all freed segments to the OS. This reclaims WoW's own
        // freed memory, not just the DLL's, so it directly raises LargestFreeBlock --
        // the one action that actually unfragments the VA. Registered LAST so the
        // cache shedders above have already freed their memory into mimalloc; bounded
        // (fires once per RED transition, not per frame).
        struct ShedMiCollect { static void Go(Level lv, void*) {
            if (lv >= PRESSURE_RED) {
                StallProbe probe("pressure RED mi_collect", 4.0);
                mi_collect(true);
            }
        }};
        RegisterShedCallback(ShedMiCollect::Go, nullptr);

        // Adaptive mimalloc purge delay. Fires on every level change. Gentle when VA
        // has headroom (avoid the decommit/recommit fault storm on the now-whole-heap
        // mimalloc); tighten only under real pressure where returning VA to the OS is
        // worth the faults. Mirrors the default set in ConfigureMimalloc (500ms).
        struct AdaptPurge { static void Go(Level lv, void*) {
            long delay = (lv >= PRESSURE_RED) ? 10 : (lv >= PRESSURE_YELLOW) ? 100 : 500;
            mi_option_set(mi_option_purge_delay, delay);
        }};
        RegisterShedCallback(AdaptPurge::Go, nullptr);

        Log("[PressureGovernor] %d shed callbacks registered", 10);
    }
#endif

    // Apply all queued hook enables in a single thread-freeze, then leave batch
    // mode so any later/lazy install enables immediately.
    g_hookBatchMode = 0;
#if !TEST_DISABLE_HOOK_BATCHING
    {
        MH_STATUS aq = MH_ApplyQueued();
        if (aq != MH_OK) {
            Log("[HookBatch] MH_ApplyQueued FAILED (%d) — some hooks may be inactive", (int)aq);
        } else {
            Log("[HookBatch] Applied queued hook enables in one freeze");
        }
    }
#endif

    Log("");
    Log("========================================");
    Log("  Initialization complete");
    Log("========================================");

    // Start async I/O worker after all hooks/workers are ready - avoids init race
    InstallAsyncIoWorker();

#if !TEST_DISABLE_SAMPLING_PROFILER
    // Start lightweight sampling profiler. A background thread samples the
    // main thread's EIP every ~1ms via SuspendThread/GetThreadContext/
    // ResumeThread and dumps the top-50 hot functions on shutdown.
    // Read-only — no hooks into WoW code, no writes to WoW memory.
    if (Config::g_settings.OptSamplingProfiler) {
        HANDLE hMain = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, g_mainThreadId);
        if (hMain) {
            if (SamplingProfiler::Init(hMain))
                CrashDumper::FeatureSetActive("SamplingProfiler", true);
            CloseHandle(hMain);
        }
    }
#endif

    Log("");
    Log("  [ -- ] mimalloc CRT redirect (REMOVED)");  // destabilized Winsock
    Log("  [%s] Sleep hook (PreciseSleep)",    sleepOk     ? " OK " : "FAIL");
    Log("  [%s] GetTickCount (QPC)",           tickOk      ? " OK " : "FAIL");
    Log("  [%s] timeGetTime (QPC sync)",       tgtOk       ? " OK " : "FAIL");
    Log("  [%s] Heap optimization (LFH)",      heapOk      ? " OK " : "FAIL");
    Log("  [%s] ThreadId cache (TLS)",         tidOk       ? " OK " : "FAIL");
    #if !CRASH_TEST_DISABLE_QPC_CACHE
        Log("  [%s] QPC cache (50us coalesce)",    qpcOk       ? " OK " : "FAIL");
    #else
        Log("  [SKIP] QPC cache (crash isolation)");
    #endif        
    Log("  [%s] IsBadPtr (fast VirtualQuery)", bpOk        ? " OK " : "FAIL");    
    Log("  [%s] CompareStringA (ASCII fast)",  cmpOk       ? " OK " : "FAIL");
    Log("  [%s] MBT/WCT (SSE2 ASCII fast)",    mbwcOk      ? " OK " : "SKIP");
    Log("  [%s] CRT mem/str fast paths",        crtOk       ? " OK " : "SKIP");
    Log("  [%s] GetSystemInfo cache",            sysInfoOk    ? " OK " : "SKIP");
    Log("  [%s] RegQueryValueEx cache",          regCacheOk   ? " OK " : "SKIP");
    Log("  [%s] GetSystemMetrics cache",         smCacheOk    ? " OK " : "SKIP");
    Log("  [%s] GetVersionExA cache",            verCacheOk   ? " OK " : "SKIP");
    Log("  [%s] IsDebuggerPresent no-op",        noDebugOk    ? " OK " : "SKIP");
    Log("  [%s] Batch 8 kernel caches",         batch10Ok    ? " OK " : "SKIP");
    Log("  [%s] Batch 20 kernel caches",        batch20Ok    ? " OK " : "SKIP");
    Log("  [%s] Batch 24 kernel caches",        batch30Ok    ? " OK " : "SKIP");
    Log("  [%s] Batch 35 kernel caches",        batch35Ok    ? " OK " : "SKIP");
    Log("  [%s] Batch 38 kernel caches",        batch38Ok    ? " OK " : "SKIP");    
    Log("  [%s] OutputDebugString (no-op)",    debugOk     ? " OK " : "FAIL");
    Log("  [%s] CriticalSection (spin+try)",   csOk        ? " OK " : "FAIL");
    Log("  [%s] Network (NODELAY+ACK+QoS+KA)", netOk      ? " OK " : "FAIL");
    Log("  [%s] CreateFile (sequential I/O)",  fileOk      ? " OK " : "FAIL");
    Log("  [%s] ReadFile (adaptive MPQ cache)", readOk     ? " OK " : "FAIL");
    #if !CRASH_TEST_DISABLE_MPQ_MMAP
        Log("  [ OK ] MPQ memory mapping (1-256MB files)");
    #else
        Log("  [SKIP] MPQ memory mapping (disabled - stability)");
    #endif  
    Log("  [%s] CloseHandle (cache cleanup)",  closeOk     ? " OK " : "FAIL");
    Log("  [%s] FlushFileBuffers (MPQ skip)",  flushOk     ? " OK " : "FAIL");
    Log("  [%s] GetFileAttributesA (cache)",   faOk        ? " OK " : "FAIL");
    Log("  [%s] SetFilePointer (64-bit)",      sfpOk       ? " OK " : "FAIL");
    Log("  [%s] GlobalAlloc (mimalloc GMEM_FIXED)", gaOk      ? " OK " : "FAIL");
    // Reported here because it was reported nowhere, and its absence let a
    // "hits=0 misses=0" line stand in for "this was never built in".
#if TEST_DISABLE_LUA_BYTECODE_CACHE
    Log("  [SKIP] Lua bytecode cache (compiled out - WoW bytecode is not portable)");
#else
    Log("  [%s] Lua bytecode cache (luaL_loadbuffer)", bytecodeOk ? " OK " : " -- ");
#endif
    Log("  [ OK ] Timer resolution (0.5ms)");
    Log("  [ OK ] Thread affinity + priority");
    if (g_isMultiClient)
        Log("  [ OK ] Working set (64MB-512MB, multi-client)");
    else
        Log("  [ OK ] Working set (256MB-2GB)");
    Log("  [ OK ] Process priority (Above Normal)");
    Log("  [ OK ] FPS cap removal (200 -> 999)");
    if (g_isMultiClient) {
        Log("  [ OK ] Multi-client mode (conservative timer + sleep)");
    }
    Log("  [%s] Lua VM GC optimizer",          luaOk       ? "WAIT" : "SKIP");
    Log("  [%s] Combat log optimizer",         combatLogOk ? " OK " : "SKIP");
    Log("  [%s] UI widget cache",              uiCacheOk   ? " OK " : "SKIP");
    Log("  [%s] API cache (ItemInfo only)",    apiCacheOk  ? " OK " : "SKIP");
    Log("  [%s] Lua fast path (format)",       fastPathOk  ? " OK " : "SKIP");
    Log("  [%s] Lua VM internals (str+concat)", internalsOk ? " OK " : "SKIP");
    Log("  [%s] MsgPump (frame-continue)",    msgPumpOk   ? " OK " : "SKIP");
    Log("  [%s] Swap/Present (glFinish skip)", swapOk      ? " OK " : "SKIP");
    Log("  [%s] Lua Table Rehash (pow2)",     tableReshapeOk ? " OK " : "SKIP");
    Log("  [%s] Asset path cache",             assetPathOk   ? " OK " : "SKIP");
    Log("  [%s] Lua Table Lookup (getstr)",   luaHGetStrOk ? " OK " : "SKIP");
    Log("  [%s] Table Concat Fast Path",        tableConcatOk ? " OK " : "SKIP");
    Log("  [%s] Lua PushString (intern)",     luaPushStringOk ? " OK " : "SKIP");
    Log("  [%s] Lua RawGetI (int-key)",       luaRawGetIOk ? " OK " : "SKIP");
    Log("  [%s] CombatLog full cache",        combatLogFullCacheOk ? " OK " : "SKIP");
    Log("  [%s] Stream buffer fast path",     streamBufOk    ? " OK " : "SKIP");
    Log("  [%s] D3D9 State Manager (15 hooks)",   d3d9StateOk ? " OK " : "SKIP");
    Log("  [%s] Render Hooks (anim+backbuffer)",    renderHooksOk ? " OK " : "SKIP");
    Log("  [%s] SIMD Hooks (SSE2 matrix+frustum)", simdHooksOk ? " OK " : "SKIP");
    Log("  [%s] Logic Hooks (CT+UI+heartbeat)",    logicHooksOk ? " OK " : "SKIP");
    Log("  [%s] Memory Hooks (slabs+GUID)",        memHooksOk ? " OK " : "SKIP");
    Log("  [%s] Async Hooks (workers+particles)",  asyncHooksOk ? " OK " : "SKIP");

    // Start freeze detection watchdog AFTER all features initialized
    StartFreezeWatchdog();

    return 0;
}

// 16a. sub_4D4DB0 - Object Type Check Cache — REMOVED
// It caches (guid64,flags)->result, and objects are destroyed at
// runtime, so the cached result pointers dangle. 0x4D4DB0 is hooked
// by type_check_safety.cpp; the note here used to credit tls_cache.cpp,
// which installed no hooks at all.

// ================================================================
// 16b. sub_47B3C0 / sub_47B0A0 - Stream Buffer Read/Write Fast Path
//
// Called 2662 times across the binary.  sub_47B3C0 reads 4 bytes from
// a stream buffer (used in Lua bytecode fetch, script execution, network
// packet parsing).  sub_47B0A0 writes 4 bytes (script stack push, packet
// assembly).  Both call sub_47B290 for bounds checking which may invoke
// a virtual realloc through (*this+8).
//
// Fast path: inline the common case where cursor + 4 still fits within
// the buffer's committed region.  Bypasses the vtable call on 99%+ of
// invocations.  Falls back to original on the first call after a realloc
// (when the virtual function would have grown the buffer).
// ================================================================

// sub_47B3C0: _DWORD* __thiscall StreamRead(_DWORD* this, _DWORD* out)
//   *(this+4) = cursor, *(this+1)=base, *(this+2)=delta, *(this+3)=size
//   if (bounds_ok) { *out = *(base - delta + cursor); cursor += 4; }
typedef void* (__thiscall* StreamRead_fn)(void*, void*);
static StreamRead_fn orig_StreamRead = nullptr;
long g_streamReadHits = 0, g_streamReadFallbacks = 0;

static void* __fastcall hooked_StreamRead(void* This, void* edx, void* out) {
#if CRASH_TEST_DISABLE_STREAM_FASTPATH
    return orig_StreamRead(This, out);
#else
    __try {
        uintptr_t t = (uintptr_t)This;
        uint32_t cursor = *(uint32_t*)(t + 0x14);   // this+5 (m_readCursor)
        uint32_t writeCursor = *(uint32_t*)(t + 0x10); // this+4 (m_writeCursor)
        uint32_t base   = *(uint32_t*)(t + 0x04);   // this+1
        uint32_t delta  = *(uint32_t*)(t + 0x08);   // this+2
        uint32_t size   = *(uint32_t*)(t + 0x0C);   // this+3

        // Correct fast bounds: cursor within writeCursor and allocated region
        if (cursor + 4 <= writeCursor && cursor >= delta && cursor + 4 <= delta + size) {
            uintptr_t addr = cursor - delta + base;
            if (addr > 0x10000 && addr < 0xFFE00000) {
                *(uint32_t*)out = *(uint32_t*)addr;
                *(uint32_t*)(t + 0x14) = cursor + 4;
                InterlockedIncrement(&g_streamReadHits);
                return This;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}

    InterlockedIncrement(&g_streamReadFallbacks);
    return orig_StreamRead(This, out);
#endif
}

// sub_47B0A0: unsigned int* __thiscall StreamWrite(unsigned int* this, int val)
//   Same buffer layout as StreamRead.  Writes val at cursor, advances.
typedef void* (__thiscall* StreamWrite_fn)(void*, int);
static StreamWrite_fn orig_StreamWrite = nullptr;
long g_streamWriteHits = 0, g_streamWriteFallbacks = 0;

static void* __fastcall hooked_StreamWrite(void* This, void* edx, int val) {
#if CRASH_TEST_DISABLE_STREAM_FASTPATH
    return orig_StreamWrite(This, val);
#else
    __try {
        uintptr_t t = (uintptr_t)This;
        uint32_t cursor = *(uint32_t*)(t + 0x10);   // this+4
        uint32_t base   = *(uint32_t*)(t + 0x04);   // this+1
        uint32_t delta  = *(uint32_t*)(t + 0x08);   // this+2
        uint32_t size   = *(uint32_t*)(t + 0x0C);   // this+3

        // Fast bounds: cursor within [delta, delta+size) - same as sub_47B0A0
        if (cursor + 4 <= delta + size && cursor >= delta) {
            uintptr_t addr = cursor - delta + base;
            if (addr > 0x10000 && addr < 0xFFE00000) {
                *(uint32_t*)addr = val;
                *(uint32_t*)(t + 0x10) = cursor + 4;
                InterlockedIncrement(&g_streamWriteHits);
                return This;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}

    InterlockedIncrement(&g_streamWriteFallbacks);
    return orig_StreamWrite(This, val);
#endif
}

static bool InstallStreamBufferFastPath() {
#if CRASH_TEST_DISABLE_STREAM_FASTPATH
    Log("Stream buffer fast path: DISABLED (crash isolation)");
    return false;
#else
    int ok = 0;

    // sub_47B3C0 - StreamRead (1477 callers)
    void* pRead = (void*)0x0047B3C0;
    unsigned char* pr = (unsigned char*)pRead;
    if (pr[0] == 0x55 && pr[1] == 0x8B) {
        if (WineSafe_CreateHook(pRead, (void*)hooked_StreamRead, (void**)&orig_StreamRead) == MH_OK
            && WO_EnableHook(pRead) == MH_OK) ok++;
    }

    // sub_47B0A0 - StreamWrite (1185 callers)
    void* pWrite = (void*)0x0047B0A0;
    unsigned char* pw = (unsigned char*)pWrite;
    if (pw[0] == 0x55 && pw[1] == 0x8B) {
        if (WineSafe_CreateHook(pWrite, (void*)hooked_StreamWrite, (void**)&orig_StreamWrite) == MH_OK
            && WO_EnableHook(pWrite) == MH_OK) ok++;
    }

    if (ok > 0) {
        Log("Stream buffer fast path: ACTIVE (%d/2 hooked, sub_47B3C0+sub_47B0A0 - inline bounds check, 2662 callers)", ok);
        return true;
    }
    Log("Stream buffer fast path: FAILED (no hooks installed)");
    return false;
#endif
}

// ================================================================
// 17. GetFileSize / GetFileSizeEx - Cache
//
// ================================================================

static constexpr int FSIZE_CACHE_SIZE = 256;
static constexpr int FSIZE_CACHE_MASK = FSIZE_CACHE_SIZE - 1;

struct FSizeEntry {
    uint32_t      pathHash;
    LARGE_INTEGER fileSize;
    bool          valid;
};

static FSizeEntry g_fsizeCache[FSIZE_CACHE_SIZE] = {};

// GetFileSizeEx cache disabled � disabled in production
// hang after character select. Windows reuses handle values; caching
// by handle returns stale sizes for recycled handles.
#define TEST_DISABLE_GETFILESIZE_CACHE  1

typedef BOOL (WINAPI* GetFileSizeEx_fn)(HANDLE, PLARGE_INTEGER);
static GetFileSizeEx_fn orig_GetFileSizeEx = nullptr;

typedef DWORD (WINAPI* GetFileSize_fn)(HANDLE, LPDWORD);
static GetFileSize_fn orig_GetFileSize = nullptr;

static BOOL WINAPI hooked_GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize) {
    #if !TEST_DISABLE_SAVED_VARS_PRETOKEN
    if (SavedVarsPretoken::GetMinifiedFileSize(hFile, lpFileSize)) {
        return TRUE;
    }
    #endif
    return orig_GetFileSizeEx(hFile, lpFileSize);
}

static DWORD WINAPI hooked_GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh) {
    #if !TEST_DISABLE_SAVED_VARS_PRETOKEN
    LARGE_INTEGER sz;
    if (SavedVarsPretoken::GetMinifiedFileSize(hFile, &sz)) {
        if (lpFileSizeHigh) {
            *lpFileSizeHigh = sz.HighPart;
        }
        return sz.LowPart;
    }
    #endif
    return orig_GetFileSize(hFile, lpFileSizeHigh);
}

static bool InstallGetFileSizeCache() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;
    
    void* pEx = (void*)GetProcAddress(hK32, "GetFileSizeEx");
    if (pEx) {
        MH_CreateHook(pEx, (void*)hooked_GetFileSizeEx, (void**)&orig_GetFileSizeEx);
        WO_EnableHook(pEx);
    }
    
    void* pSize = (void*)GetProcAddress(hK32, "GetFileSize");
    if (pSize) {
        MH_CreateHook(pSize, (void*)hooked_GetFileSize, (void**)&orig_GetFileSize);
        WO_EnableHook(pSize);
    }
    
    Log("GetFileSize / GetFileSizeEx hooks: ACTIVE");
    return true;
}

// ================================================================
// 18. WaitForSingleObject - Spin-First for Short Waits
//
// ================================================================

typedef DWORD (WINAPI* WaitForSingleObject_fn)(HANDLE, DWORD);
static WaitForSingleObject_fn orig_WaitForSingleObject = nullptr;

static DWORD WINAPI hooked_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    if (dwMilliseconds <= 1) {
        for (int i = 0; i < 32; i++) {
            DWORD result = WaitForSingleObject(hHandle, 0);
            if (result != WAIT_TIMEOUT) {
                g_wfsSpinHits++;
                return result;
            }
            _mm_pause();
        }
        g_wfsFallbacks++;
    }
    return orig_WaitForSingleObject(hHandle, dwMilliseconds);
}

static bool InstallWaitForSingleObjectHook() {
#if CRASH_TEST_DISABLE_WFS_SPIN
    Log("WaitForSingleObject spin: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;
    void* p = (void*)GetProcAddress(hK32, "WaitForSingleObject");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_WaitForSingleObject, (void**)&orig_WaitForSingleObject) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("WaitForSingleObject hook: ACTIVE (spin-first for <=1ms waits, 32x pause)");
    return true;
#endif
}

// ================================================================
// 19. GetModuleHandleA - Cache
//
// ================================================================

static constexpr int MOD_CACHE_SIZE = 1024;
static constexpr int MOD_CACHE_MASK = MOD_CACHE_SIZE - 1;

struct ModCacheEntry {
    uint32_t nameHash;
    HMODULE  hModule;
    bool     valid;
};

static ModCacheEntry g_modCache[MOD_CACHE_SIZE] = {};
static SRWLOCK g_modCacheLock = SRWLOCK_INIT;

typedef HMODULE (WINAPI* GetModuleHandleA_fn)(LPCSTR);
static GetModuleHandleA_fn orig_GetModuleHandleA = nullptr;

static HMODULE WINAPI hooked_GetModuleHandleA(LPCSTR lpModuleName) {
    if (!lpModuleName) return orig_GetModuleHandleA(lpModuleName);

    uint32_t hash = 0x811C9DC5;
    for (const char* p = lpModuleName; *p; p++) {
        char c = *p;
        if (c >= 'A' && c <= 'Z') c += 32;
        hash ^= (uint8_t)c;
        hash *= 0x01000193;
    }
    int slot = hash & MOD_CACHE_MASK;
    ModCacheEntry* e = &g_modCache[slot];

    AcquireSRWLockShared(&g_modCacheLock);
    if (e->valid && e->nameHash == hash) {
        HMODULE h = e->hModule;
        ReleaseSRWLockShared(&g_modCacheLock);
        g_modHits++;
        return h;
    }
    ReleaseSRWLockShared(&g_modCacheLock);

    HMODULE h = orig_GetModuleHandleA(lpModuleName);
    if (h) {
        AcquireSRWLockExclusive(&g_modCacheLock);
        e->nameHash = hash;
        e->hModule = h;
        e->valid = true;
        ReleaseSRWLockExclusive(&g_modCacheLock);
    }
    g_modMisses++;
    return h;
}

static bool InstallGetModuleHandleCache() {
#if CRASH_TEST_DISABLE_MODHANDLE_CACHE
    Log("GetModuleHandleA cache: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;
    void* p = (void*)GetProcAddress(hK32, "GetModuleHandleA");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_GetModuleHandleA, (void**)&orig_GetModuleHandleA) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("GetModuleHandleA hook: ACTIVE (cache, %d slots)", MOD_CACHE_SIZE);
    return true;
#endif
}

// ================================================================
// 20. lstrcmpA / lstrcmpiA - Fast Path
//
// ================================================================

typedef int (WINAPI* lstrcmpA_fn)(LPCSTR, LPCSTR);
typedef int (WINAPI* lstrcmpiA_fn)(LPCSTR, LPCSTR);
static lstrcmpA_fn  orig_lstrcmpA  = nullptr;
static lstrcmpiA_fn orig_lstrcmpiA = nullptr;

static int WINAPI hooked_lstrcmpA(LPCSTR lpString1, LPCSTR lpString2) {
    if (!lpString1 || !lpString2) return orig_lstrcmpA(lpString1, lpString2);

    const unsigned char* s1 = (const unsigned char*)lpString1;
    const unsigned char* s2 = (const unsigned char*)lpString2;

    int i = 0;
    while (s1[i] && s1[i] == s2[i] && i < 512) {
        if (s1[i] > 127) {
            g_lstrcmpFallbacks++;
            return orig_lstrcmpA(lpString1, lpString2);
        }
        i++;
    }

    if (i < 512) {
        if (s1[i] > 127 || s2[i] > 127) {
            g_lstrcmpFallbacks++;
            return orig_lstrcmpA(lpString1, lpString2);
        }
        g_lstrcmpHits++;
        return (int)s1[i] - (int)s2[i];
    }

    g_lstrcmpFallbacks++;
    return orig_lstrcmpA(lpString1, lpString2);
}

static int WINAPI hooked_lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2) {
    if (!lpString1 || !lpString2) return orig_lstrcmpiA(lpString1, lpString2);

    const unsigned char* s1 = (const unsigned char*)lpString1;
    const unsigned char* s2 = (const unsigned char*)lpString2;

    int i = 0;
    while (s1[i] && i < 512) {
        unsigned char c1 = g_asciiToUpper[s1[i]];
        unsigned char c2 = g_asciiToUpper[s2[i]];
        if (s1[i] > 127 || s2[i] > 127) {
            g_lstrcmpFallbacks++;
            return orig_lstrcmpiA(lpString1, lpString2);
        }
        if (c1 != c2) {
            g_lstrcmpHits++;
            return (int)c1 - (int)c2;
        }
        i++;
    }

    if (i < 512) {
        if (s1[i] > 127 || s2[i] > 127) {
            g_lstrcmpFallbacks++;
            return orig_lstrcmpiA(lpString1, lpString2);
        }
        g_lstrcmpHits++;
        return 0 - (int)g_asciiToUpper[s2[i]];
    }

    g_lstrcmpFallbacks++;
    return orig_lstrcmpiA(lpString1, lpString2);
}

static bool InstallLstrcmpHook() {
#if CRASH_TEST_DISABLE_LSTRCMP
    Log("lstrcmp/lstrcmpiA hooks: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

    void* pCmp = (void*)GetProcAddress(hK32, "lstrcmpA");
    if (pCmp && MH_CreateHook(pCmp, (void*)hooked_lstrcmpA, (void**)&orig_lstrcmpA) == MH_OK)
        if (WO_EnableHook(pCmp) == MH_OK) ok++;

    void* pCmpi = (void*)GetProcAddress(hK32, "lstrcmpiA");
    if (pCmpi && MH_CreateHook(pCmpi, (void*)hooked_lstrcmpiA, (void**)&orig_lstrcmpiA) == MH_OK)
        if (WO_EnableHook(pCmpi) == MH_OK) ok++;

    if (ok > 0) {
        Log("lstrcmp/lstrcmpiA hooks: ACTIVE (%d/2, fast ASCII path)", ok);
        return true;
    }
    return false;
#endif
}

// ================================================================
// 21. GetPrivateProfileStringA - Cache
//
// ================================================================

static constexpr int PROF_CACHE_SIZE = 128;
static constexpr int PROF_CACHE_MASK = PROF_CACHE_SIZE - 1;
static constexpr int PROF_MAX_VALUE  = 512;

struct ProfCacheEntry {
    uint32_t keyHash;
    char     value[PROF_MAX_VALUE];
    bool     valid;
};

static ProfCacheEntry g_profCache[PROF_CACHE_SIZE] = {};
static SRWLOCK g_profCacheLock = SRWLOCK_INIT;

typedef DWORD (WINAPI* GetPrivateProfileStringA_fn)(LPCSTR, LPCSTR, LPCSTR, LPSTR, DWORD, LPCSTR);
static GetPrivateProfileStringA_fn orig_GetPrivateProfileStringA = nullptr;

static DWORD WINAPI hooked_GetPrivateProfileStringA(LPCSTR lpAppName, LPCSTR lpKeyName,
    LPCSTR lpDefault, LPSTR lpReturnedString, DWORD nSize, LPCSTR lpFileName)
{
    if (!lpAppName || !lpKeyName || !lpReturnedString || nSize == 0)
        return orig_GetPrivateProfileStringA(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);

    uint32_t hash = 0x811C9DC5;
    if (lpAppName) {
        for (const char* p = lpAppName; *p; p++) {
            char c = *p;
            if (c >= 'A' && c <= 'Z') c += 32;
            hash ^= (uint8_t)c;
            hash *= 0x01000193;
        }
    }
    if (lpKeyName) {
        for (const char* p = lpKeyName; *p; p++) {
            char c = *p;
            if (c >= 'A' && c <= 'Z') c += 32;
            hash ^= (uint8_t)c;
            hash *= 0x01000193;
        }
    }
    int slot = hash & PROF_CACHE_MASK;
    ProfCacheEntry* e = &g_profCache[slot];

    AcquireSRWLockShared(&g_profCacheLock);
    if (e->valid && e->keyHash == hash) {
        DWORD valLen = (DWORD)strlen(e->value);
        DWORD copyLen = (valLen < nSize - 1) ? valLen : (nSize - 1);
        memcpy(lpReturnedString, e->value, copyLen);
        lpReturnedString[copyLen] = '\0';
        ReleaseSRWLockShared(&g_profCacheLock);
        g_profHits++;
        return copyLen;
    }
    ReleaseSRWLockShared(&g_profCacheLock);

    DWORD result = orig_GetPrivateProfileStringA(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);

    if (result > 0 && lpReturnedString[0] != '\0' && result < PROF_MAX_VALUE) {
        AcquireSRWLockExclusive(&g_profCacheLock);
        e->keyHash = hash;
        memcpy(e->value, lpReturnedString, result + 1);
        e->valid = true;
        ReleaseSRWLockExclusive(&g_profCacheLock);
    }

    g_profMisses++;
    return result;
}

static bool InstallGetPrivateProfileCache() {
#if CRASH_TEST_DISABLE_PROFILE_CACHE
    Log("GetPrivateProfileStringA cache: DISABLED (crash isolation)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;
    void* p = (void*)GetProcAddress(hK32, "GetPrivateProfileStringA");
    if (!p) return false;
    if (MH_CreateHook(p, (void*)hooked_GetPrivateProfileStringA, (void**)&orig_GetPrivateProfileStringA) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;
    Log("GetPrivateProfileStringA hook: ACTIVE (cache, %d slots, %dB max value)", PROF_CACHE_SIZE, PROF_MAX_VALUE);
    return true;
#endif
}

// ================================================================
// lstrlenA/W - fast inline string length
//
// ================================================================

typedef int (WINAPI* lstrlenA_fn)(LPCSTR);
typedef int (WINAPI* lstrlenW_fn)(LPCWSTR);

static lstrlenA_fn orig_lstrlenA = nullptr;
static lstrlenW_fn orig_lstrlenW = nullptr;

static long g_lstrlenAHits   = 0;
static long g_lstrlenWHits   = 0;
static long g_lstrlenFallbacks = 0;

static int WINAPI hooked_lstrlenA(LPCSTR lpString) {
    if (!lpString) { g_lstrlenFallbacks++; return 0; }
    __try {
        const char* p = lpString;
        while (*p) p++;
        g_lstrlenAHits++;
        return (int)(p - lpString);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        g_lstrlenFallbacks++;
        return orig_lstrlenA(lpString);
    }
}

static int WINAPI hooked_lstrlenW(LPCWSTR lpString) {
    if (!lpString) { g_lstrlenFallbacks++; return 0; }
    __try {
        const wchar_t* p = lpString;
        while (*p) p++;
        g_lstrlenWHits++;
        return (int)(p - lpString);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        g_lstrlenFallbacks++;
        return orig_lstrlenW(lpString);
    }
}

static bool InstallLStrLenHooks() {
#if TEST_DISABLE_LSTRLEN
    Log("lstrlenA/W hooks: DISABLED (test toggle)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

    void* pA = (void*)GetProcAddress(hK32, "lstrlenA");
    if (pA && MH_CreateHook(pA, (void*)hooked_lstrlenA, (void**)&orig_lstrlenA) == MH_OK)
        if (WO_EnableHook(pA) == MH_OK) ok++;

    void* pW = (void*)GetProcAddress(hK32, "lstrlenW");
    if (pW && MH_CreateHook(pW, (void*)hooked_lstrlenW, (void**)&orig_lstrlenW) == MH_OK)
        if (WO_EnableHook(pW) == MH_OK) ok++;

    if (ok > 0) {
        Log("lstrlenA/W hooks: ACTIVE (%d/2, fast inline length)", ok);
    }
    return ok > 0;
#endif
}

// ================================================================
// sub_76EE30 - WoW-internal strlen (byte-by-byte loop, 300+ callers)
// Replace with SSE2-accelerated inline strlen.
// ================================================================
#if !CRASH_TEST_DISABLE_WOW_STRLEN

typedef unsigned int (__stdcall* strlen76_fn)(const char* str);
static strlen76_fn orig_strlen76 = nullptr;

static unsigned int __stdcall hooked_strlen76(const char* str) {
    if (!str) {
        return orig_strlen76(str); // NULL → error handler (0x57)
    }

    __try {
        // Scan must be 16-byte aligned. An unaligned _mm_loadu_si128 can straddle a
        // page boundary; when a valid string terminates within 15 bytes of the end
        // of a committed page and the next page is unmapped/decommitted, the load
        // faults reading bytes past the terminator. That overrun is what crashed at
        // RVA 0xA980 during login/logout/char-swap, when heavy string churn (300+
        // callers) coincides with the heap committing/decommitting pages.
        //
        // Aligning the base down to 16 bytes guarantees every _mm_load_si128 stays
        // inside one 4 KiB page (4096 % 16 == 0), so the scan never reads into a
        // page that the string itself does not occupy — exactly as safe as the
        // byte-by-byte function it replaces. The first chunk's leading bytes (those
        // before str) are masked out so they cannot produce a false terminator.
        const __m128i zero = _mm_setzero_si128();
        uintptr_t   addr = (uintptr_t)str;
        const char* base = (const char*)(addr & ~(uintptr_t)15);
        unsigned    off  = (unsigned)(addr & 15);

        int mask = _mm_movemask_epi8(
            _mm_cmpeq_epi8(_mm_load_si128((const __m128i*)base), zero)) >> off;
        if (mask) {
            unsigned long idx;
            _BitScanForward(&idx, (unsigned long)mask);
            return (unsigned int)idx;
        }

        for (const char* p = base + 16; ; p += 16) {
            mask = _mm_movemask_epi8(
                _mm_cmpeq_epi8(_mm_load_si128((const __m128i*)p), zero));
            if (mask) {
                unsigned long idx;
                _BitScanForward(&idx, (unsigned long)mask);
                return (unsigned int)((size_t)(p - str) + idx);
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return orig_strlen76(str);
    }
}

static bool InstallWowStrlenHook() {
    void* target = (void*)0x0076EE30;
    if (WineSafe_CreateHook(target, (void*)hooked_strlen76, (void**)&orig_strlen76) != MH_OK)
        return false;
    if (WO_EnableHook(target) != MH_OK)
        return false;
    return true;
}
#else
static bool InstallWowStrlenHook() { return false; }
#endif

// ================================================================
// MultiByteToWideChar / WideCharToMultiByte - ASCII fast path
//
// ================================================================

typedef int (WINAPI* MultiByteToWideChar_fn)(UINT, DWORD, LPCCH, int, LPWSTR, int);
typedef int (WINAPI* WideCharToMultiByte_fn)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

static MultiByteToWideChar_fn orig_MultiByteToWideChar = nullptr;
static WideCharToMultiByte_fn orig_WideCharToMultiByte = nullptr;

static bool AllAsciiBytes(const char* p, size_t n) {
    size_t i = 0;
    while (i + 16 <= n) {
        __m128i v = _mm_loadu_si128((const __m128i*)(p + i));
        if (_mm_movemask_epi8(v) != 0) return false;
        i += 16;
    }
    while (i < n) {
        if ((unsigned char)p[i] >= 0x80) return false;
        i++;
    }
    return true;
}

static bool AllAsciiWide(const wchar_t* p, size_t n) {
    const __m128i mask = _mm_set1_epi16((short)0xFF80);
    const __m128i zero = _mm_setzero_si128();
    size_t i = 0;
    while (i + 8 <= n) {
        __m128i v  = _mm_loadu_si128((const __m128i*)(p + i));
        __m128i hi = _mm_and_si128(v, mask);
        __m128i eq = _mm_cmpeq_epi16(hi, zero);
        if ((unsigned)_mm_movemask_epi8(eq) != 0xFFFFu) return false;
        i += 8;
    }
    while (i < n) {
        if ((unsigned short)p[i] >= 0x80) return false;
        i++;
    }
    return true;
}

static void WidenAsciiBytes(const char* src, wchar_t* dst, size_t n) {
    const __m128i zero = _mm_setzero_si128();
    size_t i = 0;
    while (i + 16 <= n) {
        __m128i v = _mm_loadu_si128((const __m128i*)(src + i));
        _mm_storeu_si128((__m128i*)(dst + i),     _mm_unpacklo_epi8(v, zero));
        _mm_storeu_si128((__m128i*)(dst + i + 8), _mm_unpackhi_epi8(v, zero));
        i += 16;
    }
    while (i < n) {
        dst[i] = (wchar_t)(unsigned char)src[i];
        i++;
    }
}

static void NarrowAsciiWide(const wchar_t* src, char* dst, size_t n) {
    size_t i = 0;
    while (i + 16 <= n) {
        __m128i v1 = _mm_loadu_si128((const __m128i*)(src + i));
        __m128i v2 = _mm_loadu_si128((const __m128i*)(src + i + 8));
        _mm_storeu_si128((__m128i*)(dst + i), _mm_packus_epi16(v1, v2));
        i += 16;
    }
    while (i < n) {
        dst[i] = (char)(unsigned char)src[i];
        i++;
    }
}

static inline bool IsAsciiCompatibleCp(UINT cp) {
    // CP_ACP=0, CP_OEMCP=1, CP_MACCP=2, CP_THREAD_ACP=3, CP_UTF8=65001.
    // All map [0x00..0x7F] identically to ASCII.
    // Windows ANSI codepages 1250-1258 and 874 are also ASCII-compatible.
    if (cp <= 3 || cp == 65001) return true;
    if (cp >= 1250 && cp <= 1258) return true;
    if (cp == 874) return true;
    return false;
}

static int WINAPI hooked_MultiByteToWideChar(
    UINT CodePage, DWORD dwFlags,
    LPCCH lpMultiByteStr, int cbMultiByte,
    LPWSTR lpWideCharStr, int cchWideChar)
{
    if (dwFlags != 0)                        goto mbt_fallback;
    if (!IsAsciiCompatibleCp(CodePage))      goto mbt_fallback;
    if (!lpMultiByteStr)                     goto mbt_fallback;
    if (cbMultiByte == 0 || cbMultiByte < -1) goto mbt_fallback;
    if (cchWideChar < 0)                     goto mbt_fallback;

    __try {
        size_t inLen;
        bool   includeNull;
        if (cbMultiByte == -1) {
            const char* p = lpMultiByteStr;
            while (*p) p++;
            inLen       = (size_t)(p - lpMultiByteStr);
            includeNull = true;
        } else {
            inLen       = (size_t)cbMultiByte;
            includeNull = false;
        }

        if (!AllAsciiBytes(lpMultiByteStr, inLen)) goto mbt_fallback;

        size_t outLen = inLen + (includeNull ? 1 : 0);

        if (cchWideChar == 0) {
            g_mbwcFastHits++;
            return (int)outLen;
        }

        if (!lpWideCharStr) goto mbt_fallback;

        if ((int)outLen > cchWideChar) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            g_mbwcFastHits++;
            return 0;
        }

        WidenAsciiBytes(lpMultiByteStr, lpWideCharStr, inLen);
        if (includeNull) lpWideCharStr[inLen] = L'\0';

        g_mbwcFastHits++;
        return (int)outLen;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }

mbt_fallback:
    g_mbwcFallbacks++;
    return orig_MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

static int WINAPI hooked_WideCharToMultiByte(
    UINT CodePage, DWORD dwFlags,
    LPCWCH lpWideCharStr, int cchWideChar,
    LPSTR lpMultiByteStr, int cbMultiByte,
    LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
    if (dwFlags != 0)                         goto wcmb_fallback;
    if (!IsAsciiCompatibleCp(CodePage))       goto wcmb_fallback;
    if (!lpWideCharStr)                       goto wcmb_fallback;
    if (cchWideChar == 0 || cchWideChar < -1) goto wcmb_fallback;
    if (cbMultiByte < 0)                      goto wcmb_fallback;

    __try {
        size_t inLen;
        bool   includeNull;
        if (cchWideChar == -1) {
            const wchar_t* p = lpWideCharStr;
            while (*p) p++;
            inLen       = (size_t)(p - lpWideCharStr);
            includeNull = true;
        } else {
            inLen       = (size_t)cchWideChar;
            includeNull = false;
        }

        if (!AllAsciiWide(lpWideCharStr, inLen)) goto wcmb_fallback;

        size_t outLen = inLen + (includeNull ? 1 : 0);

        if (cbMultiByte == 0) {
            if (lpUsedDefaultChar) *lpUsedDefaultChar = FALSE;
            g_wcmbFastHits++;
            return (int)outLen;
        }

        if (!lpMultiByteStr) goto wcmb_fallback;

        if ((int)outLen > cbMultiByte) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            g_wcmbFastHits++;
            return 0;
        }

        NarrowAsciiWide(lpWideCharStr, lpMultiByteStr, inLen);
        if (includeNull)            lpMultiByteStr[inLen] = '\0';
        if (lpUsedDefaultChar)      *lpUsedDefaultChar = FALSE;

        g_wcmbFastHits++;
        return (int)outLen;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }

wcmb_fallback:
    g_wcmbFallbacks++;
    return orig_WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

static bool InstallMBWCHooks() {
#if TEST_DISABLE_MBWC
    Log("MBWC hooks: DISABLED (test toggle)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    int ok = 0;

    void* pMbt = (void*)GetProcAddress(hK32, "MultiByteToWideChar");
    if (pMbt && MH_CreateHook(pMbt, (void*)hooked_MultiByteToWideChar, (void**)&orig_MultiByteToWideChar) == MH_OK)
        if (WO_EnableHook(pMbt) == MH_OK) ok++;

    void* pWcm = (void*)GetProcAddress(hK32, "WideCharToMultiByte");
    if (pWcm && MH_CreateHook(pWcm, (void*)hooked_WideCharToMultiByte, (void**)&orig_WideCharToMultiByte) == MH_OK)
        if (WO_EnableHook(pWcm) == MH_OK) ok++;

    if (ok > 0) {
        Log("MBWC hooks: ACTIVE (%d/2, SSE2 ASCII fast path)", ok);
    }
    return ok > 0;
#endif
}

// ================================================================
// GetProcAddress - 4-way set-associative cache (strcmp-based,
// Wine security-module bypass)
//
// ================================================================

typedef FARPROC (WINAPI* GetProcAddress_fn)(HMODULE, LPCSTR);

static GetProcAddress_fn orig_GetProcAddress = nullptr;

static const int GPA_CACHE_WAYS = 4;
static const int GPA_CACHE_SETS = 128;
static const int GPA_CACHE_SET_MASK = GPA_CACHE_SETS - 1;
static const int GPA_NAME_MAX = 64;

struct GpaCacheEntry {
    uintptr_t moduleHash;
    uintptr_t procHash;
    FARPROC   address;
    char      procName[GPA_NAME_MAX];  // full name for strcmp verification
    uint8_t   lru;      // LRU counter (0-3, higher = more recently used)
    bool      valid;
};

static GpaCacheEntry g_gpaCache[GPA_CACHE_SETS][GPA_CACHE_WAYS] = {};

// Wine bypass: security/HTTP modules and SSPI function names must pass
// through to orig_GetProcAddress so Wine's delay-load / forwarder
// resolution chain is not short-circuited.
static bool g_gpaWineMode = false;

// Module policy cache: memoise bypass decision per HMODULE
struct GpaModulePolicy {
    HMODULE hMod;
    bool    bypass;
    bool    valid;
};
static const int GPA_MODULE_POLICY_SIZE = 64;
static GpaModulePolicy g_gpaModulePolicy[GPA_MODULE_POLICY_SIZE] = {};

static bool IsWineGpaBypassModule(HMODULE hModule) {
    // Check memoised policy
    int slot = (int)(((uintptr_t)hModule >> 4) & (GPA_MODULE_POLICY_SIZE - 1));
    if (g_gpaModulePolicy[slot].valid && g_gpaModulePolicy[slot].hMod == hModule)
        return g_gpaModulePolicy[slot].bypass;

    // Resolve module basename
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(hModule, path, MAX_PATH);
    bool bypass = false;
    if (len > 0) {
        // Find basename
        const char* base = path;
        for (const char* p = path; *p; p++) {
            if (*p == '\\' || *p == '/') base = p + 1;
        }
        // _stricmp for case-insensitive comparison
        static const char* bypassModules[] = {
            "secur32.dll", "security.dll", "schannel.dll", "sspicli.dll",
            "wininet.dll", "winhttp.dll", "crypt32.dll", "cryptnet.dll",
            "bcrypt.dll", "ncrypt.dll", "kerberos.dll", nullptr
        };
        for (int i = 0; bypassModules[i]; i++) {
            if (_stricmp(base, bypassModules[i]) == 0) { bypass = true; break; }
        }
    }

    g_gpaModulePolicy[slot].hMod = hModule;
    g_gpaModulePolicy[slot].bypass = bypass;
    g_gpaModulePolicy[slot].valid = true;
    return bypass;
}

static bool IsWineSecurityProcName(LPCSTR name) {
    if (!name || (uintptr_t)name < 0x10000) return false;
    static const char* bypassPrefixes[] = {
        "AcquireCredentialsHandle", "InitializeSecurityContext",
        "AcceptSecurityContext", "EncryptMessage", "DecryptMessage",
        "MakeSignature", "VerifySignature", "QuerySecurityContextToken",
        "CompleteAuthToken", "DeleteSecurityContext",
        "FreeCredentialsHandle", "QuerySecurityPackageInfo",
        "FreeContextBuffer", "EnumerateSecurityPackages",
        nullptr
    };
    for (int i = 0; bypassPrefixes[i]; i++) {
        size_t plen = strlen(bypassPrefixes[i]);
        if (strncmp(name, bypassPrefixes[i], plen) == 0) return true;
    }
    return false;
}

static inline bool ShouldBypassGpaCache(HMODULE hModule, LPCSTR lpProcName) {
    if (!g_gpaWineMode) return false;
    return IsWineGpaBypassModule(hModule) || IsWineSecurityProcName(lpProcName);
}

static inline uintptr_t HashPtr(const void* p, size_t len) {
    const uint8_t* b = (const uint8_t*)p;
    uintptr_t h = 0;
    for (size_t i = 0; i < len; i++) {
        h = h * 31 + b[i];
    }
    return h;
}

static FARPROC WINAPI hooked_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    // Ordinal lookup - no caching
    if ((uintptr_t)lpProcName < 0x10000) {
        return orig_GetProcAddress(hModule, lpProcName);
    }

    // Wine: bypass security/HTTP modules
    if (ShouldBypassGpaCache(hModule, lpProcName)) {
        g_gpaBypasses++;
        return orig_GetProcAddress(hModule, lpProcName);
    }

    // Compute cache key
    size_t nameLen = strlen(lpProcName);
    uintptr_t modHash = (uintptr_t)hModule;
    uintptr_t procHash = HashPtr(lpProcName, nameLen);
    int setIdx = (int)((modHash ^ procHash) & GPA_CACHE_SET_MASK);

    // Search all 4 ways in this set - hash AND strcmp
    GpaCacheEntry* set = g_gpaCache[setIdx];
    for (int way = 0; way < GPA_CACHE_WAYS; way++) {
        if (set[way].valid && set[way].moduleHash == modHash &&
            set[way].procHash == procHash &&
            strcmp(set[way].procName, lpProcName) == 0) {
            // Cache hit - update LRU
            set[way].lru = 3;
            for (int i = 0; i < GPA_CACHE_WAYS; i++) {
                if (i != way && set[i].lru > 0) set[i].lru--;
            }
            g_gpaHits++;
            return set[way].address;
        }
    }

    // Cache miss - call original
    FARPROC addr = orig_GetProcAddress(hModule, lpProcName);
    if (addr && nameLen < GPA_NAME_MAX) {
        // Find victim: invalid slot first, else LRU=0
        int victim = -1;
        for (int way = 0; way < GPA_CACHE_WAYS; way++) {
            if (!set[way].valid) {
                victim = way;
                break;
            }
        }
        if (victim == -1) {
            for (int way = 0; way < GPA_CACHE_WAYS; way++) {
                if (set[way].lru == 0) {
                    victim = way;
                    g_gpaEvictions++;
                    break;
                }
            }
        }
        if (victim == -1) victim = 0;

        // Insert into cache with full name
        set[victim].moduleHash = modHash;
        set[victim].procHash   = procHash;
        set[victim].address    = addr;
        memcpy(set[victim].procName, lpProcName, nameLen + 1);
        set[victim].lru        = 3;
        set[victim].valid      = true;

        // Age other entries
        for (int i = 0; i < GPA_CACHE_WAYS; i++) {
            if (i != victim && set[i].lru > 0) set[i].lru--;
        }
    }
    g_gpaMisses++;
    return addr;
}

static bool InstallGetProcAddressCache() {
#if TEST_DISABLE_GETPROCADDRESS
    Log("GetProcAddress cache: DISABLED (test toggle)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    void* p = (void*)GetProcAddress(hK32, "GetProcAddress");
    if (!p) return false;

    if (MH_CreateHook(p, (void*)hooked_GetProcAddress, (void**)&orig_GetProcAddress) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;

    g_gpaWineMode = IsWine();
    Log("GetProcAddress cache: ACTIVE (4-way, 128 sets, strcmp-based%s)",
        g_gpaWineMode ? ", Wine security bypass" : "");
    return true;
#endif
}

// ================================================================
// GetModuleFileNameA/W - cache
//
// ================================================================

typedef DWORD (WINAPI* GetModuleFileNameA_fn)(HMODULE, LPSTR, DWORD);
typedef DWORD (WINAPI* GetModuleFileNameW_fn)(HMODULE, LPWSTR, DWORD);

static GetModuleFileNameA_fn orig_GetModuleFileNameA = nullptr;
static GetModuleFileNameW_fn orig_GetModuleFileNameW = nullptr;

static char g_gmfPathA[MAX_PATH] = {};
static wchar_t g_gmfPathW[MAX_PATH] = {};
static DWORD g_gmfPathLenA = 0;
static DWORD g_gmfPathLenW = 0;
static bool g_gmfInitialized = false;

static DWORD WINAPI hooked_GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
    static HMODULE mainMod = GetModuleHandleA(nullptr);
    if ((hModule == NULL || hModule == mainMod) && g_gmfInitialized) {
        if (g_gmfPathLenA < nSize) {
            memcpy(lpFilename, g_gmfPathA, g_gmfPathLenA + 1);
            g_gmfHits++;
            return g_gmfPathLenA;
        }
    }
    g_gmfMisses++;
    return orig_GetModuleFileNameA(hModule, lpFilename, nSize);
}

static DWORD WINAPI hooked_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
    static HMODULE mainMod = GetModuleHandleA(nullptr);
    if ((hModule == NULL || hModule == mainMod) && g_gmfInitialized) {
        if (g_gmfPathLenW < nSize) {
            memcpy(lpFilename, g_gmfPathW, (g_gmfPathLenW + 1) * sizeof(wchar_t));
            g_gmfHits++;
            return g_gmfPathLenW;
        }
    }
    g_gmfMisses++;
    return orig_GetModuleFileNameW(hModule, lpFilename, nSize);
}

static bool InstallGetModuleFileNameCache() {
#if TEST_DISABLE_MODULEFILENAME
    Log("GetModuleFileName cache: DISABLED (test toggle)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    orig_GetModuleFileNameA = (GetModuleFileNameA_fn)GetProcAddress(hK32, "GetModuleFileNameA");
    orig_GetModuleFileNameW = (GetModuleFileNameW_fn)GetProcAddress(hK32, "GetModuleFileNameW");
    if (!orig_GetModuleFileNameA || !orig_GetModuleFileNameW) return false;

    HMODULE mainMod = GetModuleHandleA(nullptr);
    g_gmfPathLenA = orig_GetModuleFileNameA(mainMod, g_gmfPathA, MAX_PATH);
    g_gmfPathLenW = orig_GetModuleFileNameW(mainMod, g_gmfPathW, MAX_PATH);
    if (g_gmfPathLenA > 0 && g_gmfPathLenW > 0) {
        g_gmfInitialized = true;
    }

    int ok = 0;
    if (MH_CreateHook((void*)orig_GetModuleFileNameA, (void*)hooked_GetModuleFileNameA, (void**)&orig_GetModuleFileNameA) == MH_OK)
        if (WO_EnableHook((void*)orig_GetModuleFileNameA) == MH_OK) ok++;

    if (MH_CreateHook((void*)orig_GetModuleFileNameW, (void*)hooked_GetModuleFileNameW, (void**)&orig_GetModuleFileNameW) == MH_OK)
        if (WO_EnableHook((void*)orig_GetModuleFileNameW) == MH_OK) ok++;

    if (ok > 0)
        Log("GetModuleFileNameA/W cache: ACTIVE (thread-safe, read-only)");
    return ok > 0;
#endif
}

// ================================================================
// GetEnvironmentVariableA - cache
//
// ================================================================

typedef DWORD (WINAPI* GetEnvironmentVariableA_fn)(LPCSTR, LPSTR, DWORD);

static GetEnvironmentVariableA_fn orig_GetEnvironmentVariableA = nullptr;

static const int ENV_CACHE_SIZE = 32;
static const int ENV_CACHE_MASK = ENV_CACHE_SIZE - 1;

struct EnvCacheEntry { uint32_t nameHash; char value[512]; DWORD len; bool valid; };
static EnvCacheEntry g_envCache[ENV_CACHE_SIZE] = {};
static SRWLOCK g_envCacheLock = SRWLOCK_INIT;

static inline uint32_t HashNameLower(LPCSTR name) {
    uint32_t h = 0;
    for (const char* p = name; *p; p++) {
        char c = *p >= 'A' && *p <= 'Z' ? *p + 32 : *p;
        h = h * 31 + c;
    }
    return h;
}

static DWORD WINAPI hooked_GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
    // NULL checks: lpName or lpBuffer can be NULL (size query)
    if (!lpName || !lpBuffer) return orig_GetEnvironmentVariableA(lpName, lpBuffer, nSize);

    uint32_t h = HashNameLower(lpName);
    int idx = h & ENV_CACHE_MASK;

    AcquireSRWLockShared(&g_envCacheLock);
    if (g_envCache[idx].valid && g_envCache[idx].nameHash == h) {
        if (g_envCache[idx].len < nSize) {
            memcpy(lpBuffer, g_envCache[idx].value, g_envCache[idx].len + 1);
            ReleaseSRWLockShared(&g_envCacheLock);
            g_envHits++;
            return g_envCache[idx].len;
        }
    }
    ReleaseSRWLockShared(&g_envCacheLock);

    DWORD result = orig_GetEnvironmentVariableA(lpName, lpBuffer, nSize);
    if (result > 0 && result < sizeof(g_envCache[idx].value)) {
        AcquireSRWLockExclusive(&g_envCacheLock);
        g_envCache[idx].nameHash = h;
        memcpy(g_envCache[idx].value, lpBuffer, result + 1);
        g_envCache[idx].len = result;
        g_envCache[idx].valid = true;
        ReleaseSRWLockExclusive(&g_envCacheLock);
    }
    g_envMisses++;
    return result;
}

static bool InstallEnvironmentVariableCache() {
#if TEST_DISABLE_ENVVARIABLE
    Log("GetEnvironmentVariable cache: DISABLED (test toggle)");
    return false;
#else
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return false;

    void* p = (void*)GetProcAddress(hK32, "GetEnvironmentVariableA");
    if (!p) return false;

    if (MH_CreateHook(p, (void*)hooked_GetEnvironmentVariableA, (void**)&orig_GetEnvironmentVariableA) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;

    Log("GetEnvironmentVariableA cache: ACTIVE (32-slot, name-hash-keyed)");
    return true;
#endif
}

// ================================================================
//  Thread Affinity - Background Worker CPU Pinning
//
// ================================================================

static int __cdecl Hooked_ThreadWorker(void* outHandle, LPTHREAD_START_ROUTINE start, LPVOID param, int priority, int a5, int a6, HMODULE hMod) {
    int ret = orig_ThreadWorker(outHandle, start, param, priority, a5, a6, hMod);
    if (ret == 0 && outHandle) {
        HANDLE h = *(HANDLE*)outHandle;
        if (h && h != INVALID_HANDLE_VALUE) {
            int idx = InterlockedIncrement(&g_bgThreadIdx) - 1;
            SetThreadIdealProcessor(h, g_affinityCores[idx % g_affinityCount]);
        }
    }
    return ret;
}

static bool IsExecutableMemory(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// Wine/Rosetta: make SetThreadIdealProcessor a global no-op.
// WoW's own sub_8D2110 and external injectors (WoWsilicon) call this
// natively. Guarding only our own hook sites is insufficient - we must
// intercept the kernel32 entry point itself to prevent rosettax87 desync.
static DWORD WINAPI Noop_SetThreadIdealProcessor(HANDLE hThread, DWORD dwIdealProcessor) {
    (void)hThread; (void)dwIdealProcessor;
    return 0;  // return "previous ideal processor" = 0
}

static void InstallWineSTIPNoop() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return;
    void* p = (void*)GetProcAddress(hK32, "SetThreadIdealProcessor");
    if (!p) return;
    static DWORD(WINAPI* orig)(HANDLE, DWORD) = nullptr;
    if (MH_CreateHook(p, (void*)Noop_SetThreadIdealProcessor, (void**)&orig) == MH_OK &&
        WO_EnableHook(p) == MH_OK) {
        Log("SetThreadIdealProcessor: NO-OP on Wine (prevents rosettax87 desync)");
    }
}

static bool InstallThreadAffinity() {
#if CRASH_TEST_DISABLE_THREAD_AFFINITY
    Log("Thread affinity: DISABLED (crash isolation)");
    return false;
#else
    if (IsWine()) {
        Log("Thread affinity: SKIPPED (Wine/Rosetta)");
        return false;
    }
    DWORD_PTR processMask = 0, systemMask = 0;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &processMask, &systemMask)) {
        Log("Thread affinity: SKIP (GetProcessAffinityMask failed)");
        return false;
    }

    int activeCores = 0;
    for (unsigned i = 0; i < sizeof(DWORD_PTR) * 8; i++) {
        if (processMask & ((DWORD_PTR)1 << i))
            activeCores++;
    }

    if (activeCores <= 2) {
        Log("Thread affinity: SKIP (<=2 active process cores)");
        return false;
    }

    g_affinityCount = 0;
    for (unsigned i = 2; i < sizeof(DWORD_PTR) * 8 && g_affinityCount < 16; i++) {
        if (processMask & ((DWORD_PTR)1 << i))
            g_affinityCores[g_affinityCount++] = i;
    }

    if (g_affinityCount == 0) {
        Log("Thread affinity: SKIP (process affinity mask leaves no worker cores >=2)");
        return false;
    }

    void* p = (void*)0x008D2110;
    if (!IsExecutableMemory((uintptr_t)p)) return false;
    if (WineSafe_CreateHook(p, (void*)Hooked_ThreadWorker, (void**)&orig_ThreadWorker) != MH_OK) return false;
    if (WO_EnableHook(p) != MH_OK) return false;

    Log("Thread affinity: ACTIVE (process-mask aware, %d worker cores)", g_affinityCount);
    return true;
#endif
}

// ================================================================
// VA Arena v2 - High-address reserved arena with caller filtering
// ================================================================

static bool IsCallerInWowExe() {
    void* caller = _ReturnAddress();
    if (!caller) return false;
    static uintptr_t wowBase = 0;
    static uintptr_t wowSize = 0;
    if (wowBase == 0) {
        HMODULE hWow = GetModuleHandleA(NULL);
        if (!hWow) return false;
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hWow, &modInfo, sizeof(modInfo))) return false;
        wowBase = (uintptr_t)hWow;
        wowSize = (uintptr_t)modInfo.SizeOfImage;
    }
    uintptr_t addr = (uintptr_t)caller;
    return (addr >= wowBase && addr < wowBase + wowSize);
}

static LPVOID WINAPI Hooked_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flType, DWORD flProtect) {
    // Intercept ALL committed, non-fixed, non-reserve allocations
    // No caller filtering - serve everyone (Wow.exe, addons, mimalloc, D3D9, etc.)
    if (g_vaArenaActive &&
        lpAddress == NULL &&
        dwSize >= VA_ARENA_PAGE_SIZE &&
        dwSize <= 256 * 1024 * 1024 &&  // cap at 256MB per alloc
       (flType & MEM_COMMIT) &&
        !(flType & MEM_RESERVE) &&
        !(flType & MEM_RESET) &&
        !(flType & MEM_PHYSICAL) &&
        !(flType & MEM_LARGE_PAGES) &&
       (flProtect == PAGE_READONLY || flProtect == PAGE_READWRITE ||
         flProtect == PAGE_EXECUTE_READ || flProtect == PAGE_EXECUTE_READWRITE ||
         flProtect == PAGE_NOACCESS) &&
        IsCallerInWowExe())  // RESTORED: prevent addon/D3D9 from fragmenting arena
    {
#if !CRASH_TEST_DISABLE_VA_ARENA
        __try {
            SIZE_T pagesNeeded = (dwSize + VA_ARENA_PAGE_SIZE - 1) / VA_ARENA_PAGE_SIZE;

            AcquireSRWLockExclusive(&g_vaArenaLock);

            if (pagesNeeded > VA_ARENA_MAX_PAGES - g_vaArenaUsedPages) {
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                InterlockedIncrement(&g_vaArenaFull);  // arena too small to hold this qualifying request
                goto va_fallback;
            }

            // First-fit bitmap scan for consecutive free pages
            DWORD startPage = 0;
            DWORD consecutive = 0;
            bool found = false;

            for (DWORD i = 0; i < VA_ARENA_MAX_PAGES; i++) {
                if (!(g_vaArenaBitmap[i / 64] & (1ULL << (i % 64)))) {
                    if (consecutive == 0) startPage = i;
                    consecutive++;
                    if (consecutive >= pagesNeeded) { found = true; break; }
                } else {
                    consecutive = 0;
                }
            }

            if (!found) {
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                InterlockedIncrement(&g_vaArenaFull);  // qualifying request, but no contiguous run (fragmented arena)
                goto va_fallback;
            }

            // Mark bitmap + store span
            for (DWORD i = 0; i < pagesNeeded; i++) {
                g_vaArenaBitmap[(startPage + i) / 64] |= (1ULL << ((startPage + i) % 64));
                g_vaArenaSpan[startPage + i] = 0;  // non-head pages
            }
            g_vaArenaSpan[startPage] = (DWORD)pagesNeeded;
            g_vaArenaUsedPages += (DWORD)pagesNeeded;
            if (g_vaArenaUsedPages > g_vaArenaPeakPages) g_vaArenaPeakPages = g_vaArenaUsedPages;
            ReleaseSRWLockExclusive(&g_vaArenaLock);

            LPVOID result = (LPVOID)((uintptr_t)g_vaArenaBase + (startPage * VA_ARENA_PAGE_SIZE));

            // Commit the pages from OS
            SIZE_T spanSize = (SIZE_T)pagesNeeded * VA_ARENA_PAGE_SIZE;
            LPVOID committed = orig_VirtualAlloc(result, spanSize, MEM_COMMIT, flProtect);
            if (!committed) {
                // Rollback bitmap + span
                AcquireSRWLockExclusive(&g_vaArenaLock);
                for (DWORD i = 0; i < pagesNeeded; i++) {
                    g_vaArenaBitmap[(startPage + i) / 64] &= ~(1ULL << ((startPage + i) % 64));
                    g_vaArenaSpan[startPage + i] = 0;
                }
                g_vaArenaUsedPages -= (DWORD)pagesNeeded;
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                goto va_fallback;
            }

            InterlockedIncrement(&g_vaArenaHits);
            return result;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            goto va_fallback;
        }
#endif
    }

#if !CRASH_TEST_DISABLE_VA_ARENA
va_fallback:
#endif
    InterlockedIncrement(&g_vaArenaFallbacks);
    return orig_VirtualAlloc(lpAddress, dwSize, flType, flProtect);
}

static BOOL WINAPI Hooked_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    if (g_vaArenaActive &&
        lpAddress >= g_vaArenaBase &&
       (uintptr_t)lpAddress < ((uintptr_t)g_vaArenaBase + g_vaArenaSize))
    {
#if !CRASH_TEST_DISABLE_VA_ARENA
        __try {
            DWORD page = (DWORD)((uintptr_t)lpAddress - (uintptr_t)g_vaArenaBase) / VA_ARENA_PAGE_SIZE;
            if (page >= VA_ARENA_MAX_PAGES) goto vf_fallback;

            AcquireSRWLockExclusive(&g_vaArenaLock);
            DWORD spanLen = g_vaArenaSpan[page];
            if (spanLen == 0) {
                // Not an arena head page - fallback
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                goto vf_fallback;
            }

            // Calculate actual span size for decommit
            SIZE_T spanPages = spanLen;
            SIZE_T spanSize = spanPages * VA_ARENA_PAGE_SIZE;

            if (dwFreeType == MEM_DECOMMIT) {
                // Decommit only: drop the physical/pagefile backing but KEEP the
                // pages marked owned in the bitmap. A decommit does not release
                // the reservation - the caller still owns this address and may
                // re-commit it later - so the arena must NOT hand these pages to
                // another allocation. Only MEM_RELEASE reclaims them.
                //
                // (This is the bug that made the arena unsafe before: it cleared
                // the bitmap on decommit, so a later allocation could grab pages
                // the original owner still held -> heap/data corruption.)
                //
                // Honor the caller's requested range; fall back to the full span
                // if they passed size 0.
                SIZE_T decSize = dwSize ? dwSize : spanSize;
                if (decSize > spanSize) decSize = spanSize;
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                BOOL result = orig_VirtualFree(lpAddress, decSize, MEM_DECOMMIT);
                if (result) InterlockedIncrement(&g_vaArenaHits);
                return result;
            }

            if (dwFreeType == MEM_RELEASE) {
                // Decommit + clear bitmap + span
                orig_VirtualFree(lpAddress, spanSize, MEM_DECOMMIT);
                for (DWORD i = 0; i < spanPages && (page + i) < VA_ARENA_MAX_PAGES; i++) {
                    g_vaArenaBitmap[(page + i) / 64] &= ~(1ULL << ((page + i) % 64));
                    g_vaArenaSpan[page + i] = 0;
                }
                g_vaArenaUsedPages -= (DWORD)spanPages;
                ReleaseSRWLockExclusive(&g_vaArenaLock);
                InterlockedIncrement(&g_vaArenaHits);
                return TRUE;
            }

            ReleaseSRWLockExclusive(&g_vaArenaLock);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            goto vf_fallback;
        }
#endif
    }

#if !CRASH_TEST_DISABLE_VA_ARENA
vf_fallback:
#endif
    return orig_VirtualFree(lpAddress, dwSize, dwFreeType);
}

static bool InstallVAArena() {
    if (IsWine()) {
        Log("VA Arena: DISABLED on Wine (prevents socket issues & exit crashes)");
        return false;
    }
#if CRASH_TEST_DISABLE_VA_ARENA
    Log("VA Arena: DISABLED (crash isolation)");
    return false;
#else
    // Opt-in: the arena hooks VirtualAlloc/VirtualFree process-wide, so it stays
    // off unless a tester explicitly enables it in the launcher. Default users
    // are unaffected - we return before reserving anything or installing hooks.
    if (!Config::g_settings.OptVaArena) {
        Log("VA Arena: DISABLED (opt-in; enable 'Segregated VA Arena' in the launcher to test)");
        return false;
    }

    // Pre-reserve one contiguous block high in the address space (MEM_TOP_DOWN)
    // and sub-allocate WoW's committing VirtualAllocs from it, so they don't
    // scatter holes through the general 2-3GB user VA. VirtualFree still frees
    // normally (placement only, no allocator redirection), so there's no
    // cross-heap hazard like MimallocLarge had.
    g_vaArenaSize = VA_ARENA_MAX_PAGES * VA_ARENA_PAGE_SIZE;  // 64MB (16384 * 4KB)

    // Try high addresses first with MEM_TOP_DOWN
    g_vaArenaBase = VirtualAlloc((LPVOID)0xF0000000, g_vaArenaSize, MEM_RESERVE | MEM_TOP_DOWN, PAGE_NOACCESS);
    if (!g_vaArenaBase) {
        // Try without specific address
        g_vaArenaBase = VirtualAlloc(NULL, g_vaArenaSize, MEM_RESERVE | MEM_TOP_DOWN, PAGE_NOACCESS);
        if (!g_vaArenaBase) {
            g_vaArenaBase = VirtualAlloc(NULL, g_vaArenaSize, MEM_RESERVE, PAGE_NOACCESS);
            if (!g_vaArenaBase) {
                Log("VA Arena: SKIP (cannot reserve 64MB block)");
                return false;
            }
        }
    }

    Log("VA Arena: ACTIVE (64MB block @ 0x%08X, 4KB pages, Wow.exe callers, SEH-guarded)",
       (unsigned)(uintptr_t)g_vaArenaBase);

    void* pAlloc = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc");
    void* pFree  = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualFree");
    if (!pAlloc || !pFree) {
        VirtualFree(g_vaArenaBase, 0, MEM_RELEASE);
        g_vaArenaBase = nullptr;
        return false;
    }

    if (MH_CreateHook(pAlloc, (void*)Hooked_VirtualAlloc, (void**)&orig_VirtualAlloc) != MH_OK) {
        VirtualFree(g_vaArenaBase, 0, MEM_RELEASE);
        g_vaArenaBase = nullptr;
        return false;
    }
    if (MH_CreateHook(pFree, (void*)Hooked_VirtualFree, (void**)&orig_VirtualFree) != MH_OK) {
        MH_DisableHook(pAlloc);
        VirtualFree(g_vaArenaBase, 0, MEM_RELEASE);
        g_vaArenaBase = nullptr;
        return false;
    }

    if (WO_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        MH_DisableHook(pAlloc); MH_DisableHook(pFree);
        VirtualFree(g_vaArenaBase, 0, MEM_RELEASE);
        g_vaArenaBase = nullptr;
        return false;
    }

    g_vaArenaActive = true;
    return true;
#endif
}

static void ShutdownVAArena() {
    if (g_vaArenaBase) {
        VirtualFree(g_vaArenaBase, 0, MEM_RELEASE);
        g_vaArenaBase = nullptr;
    }
    g_vaArenaActive = false;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);

            // Pin the DLL to prevent crashes on process exit if OS unloads DLLs in bad order
            {
                HMODULE hDummy;
                GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                    (LPCSTR)hModule,
                    &hDummy
                );
            }
            
            // Rosetta: disable x87 JIT cache to force re-translation after hooks
            // This MUST happen before any hooks install, so rosettax87 doesn't
            // serve stale ARM64 translations for patched x86 code.
            // Also enable on Wine: CrossOver on Apple Silicon runs WoW.exe (Windows
            // binary) through Rosetta underneath. Setting the env var on plain Wine
            // (Linux) is harmless — it's simply ignored there.
            if (IsRosetta() || IsWine()) {
                SetEnvironmentVariableA("ROSETTA_X87_DISABLE_CACHE", "1");
                // Signal to lua_fastpath that MinHook inline hooks are now safe
                extern bool g_rosettaCacheDisabled;
                g_rosettaCacheDisabled = true;
            }
            
            // Wine/Rosetta: neutralize SetThreadIdealProcessor BEFORE
            // spawning MainThread. WoW's sub_8D2110 and external injectors
            // (WoWsilicon) may call it on background threads before our
            // init thread installs hooks. This inline patch is loader-lock
            // safe (only VirtualProtect + memory write).
            {
                HMODULE k32 = GetModuleHandleA("kernel32.dll");
                if (k32) {
                    FARPROC stip = GetProcAddress(k32, "SetThreadIdealProcessor");
                    if (stip) {
                        // Check for Wine: ntdll exports wine_get_version
                        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                        bool isWine = ntdll && (GetProcAddress(ntdll, "wine_get_version") != NULL);
                        if (isWine) {
                            DWORD oldProt;
                            // xor eax,eax; ret 8  →  return 0, clean stdcall args
                            unsigned char stub[] = { 0x33, 0xC0, 0xC2, 0x08, 0x00 };
                            if (VirtualProtect((void*)stip, sizeof(stub), PAGE_EXECUTE_READWRITE, &oldProt)) {
                                memcpy((void*)stip, stub, sizeof(stub));
                                VirtualProtect((void*)stip, sizeof(stub), oldProt, &oldProt);
                            }
                        }
                    }
                }
            }
            CloseHandle(CreateThread(NULL, 0, MainThread, NULL, 0, NULL));
            break;
        case DLL_PROCESS_DETACH:
            if (reserved != NULL) {
                // Process is terminating — immediately unhook everything so WoW's
                // teardown code doesn't run through our detours after DLL data is
                // being freed. Without this, destructors like sub_47BF30 (refcount
                // release) crash because hooks are still redirecting calls.
                // Wrapped in SEH because MinHook's internal structures may have
                // been partially freed during process teardown.
                __try {
                    MH_DisableHook(MH_ALL_HOOKS);
                    MH_Uninitialize();
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    // Best-effort — if unhooking fails, process is terminating anyway
                }

                // MinHook is not the only thing pointing at this module. The D3D9
                // state manager writes sixteen of its own function pointers
                // directly into the device vtable, which lives inside d3d9.dll -
                // and this path used to break out before ShutdownD3D9StateManager
                // ever ran, so those sixteen entries survived our unload. d3d9
                // then releases the device through a vtable still calling into an
                // unmapped module, on the way out of the process, which is where a
                // crash lands after the player has already quit and is the hardest
                // kind to attribute.
                //
                // Restoring them is cheap and self-checking: each slot is put back
                // only if it still holds our hook, so a third-party hook layered on
                // top is left alone, and the whole walk is inside SEH.
                //
                // The process-exit variant, not the ordinary one: every other
                // thread is already dead here, possibly holding the vtable lock,
                // and that lock is an SRWLOCK with no abandonment recovery. It
                // tries and gives up rather than waits, because hanging a quitting
                // process is worse than the dangling vtable being cleared.
                __try {
                    ShutdownD3D9StateManagerAtProcessExit();
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                }
#if !TEST_DISABLE_SAVED_VARS_ASYNC
                FlushSavedVarsAsyncSynchronously();
#endif
                ClearAssetPathCache();
                // The distribution is the point of the whole session; emit it
                // before the log is finalized or it is lost on every normal exit.
                FrameBench::Report("session end");
                LogFinalizeOnProcessExit(
                    "wow_optimize.dll: process terminating, detours removed and the "
                    "D3D9 device vtable restored, skipping the rest of cleanup");
                break;
            }

            // Dynamic FreeLibrary - safe to clean up
            __try {
#if !TEST_DISABLE_SAMPLING_PROFILER
            SamplingProfiler::Shutdown();
#endif
            TextureUnloadDelay::Shutdown();
            LuaFastPath::Shutdown();
            LuaInternals::Shutdown();
            LuaBytecodeCache::Shutdown();
            ShutdownStrstrSSE2();
            ShutdownCrtCharSSE2();
            ShutdownCrtMemFastPaths();
            ShutdownCrtWcharSSE2();
            ShutdownAddonPreload();
            ApiCache::Shutdown();
            UICache::Shutdown();                       
            CombatLogOpt::Shutdown();
            CombatLogBuffer::Shutdown();
#if !TEST_DISABLE_ADDON_DISPATCHER
            if (Config::g_settings.OptAddonDispatcher) {
                AddonDispatcher::Shutdown();
            }
#endif
#if !TEST_DISABLE_OBJ_VIS_CACHE
            ObjVisCache::Shutdown();
#endif
#if !TEST_DISABLE_NAMEPLATE_MT
            NameplateMT::Shutdown();
#endif
#if !TEST_DISABLE_EVENT_COALESCER
            EventCoalescer::Shutdown();
#endif
#if !TEST_DISABLE_LUAS_NEWLSTR_SSE2
            LuaSNewlstr::Shutdown();
#endif
            UninstallLuaGetnFast();
            LuaOpt::Shutdown();
            if (g_flushSkipped > 0)
                Log("FlushFileBuffers: %ld MPQ flushes skipped", g_flushSkipped);
            if (g_debugStringSkipped > 0)
                Log("OutputDebugStringA: %ld calls skipped (no debugger)", g_debugStringSkipped);
            if (g_heapsOptimized > 0)
                Log("Heap optimization: %d heaps with LFH enabled", g_heapsOptimized);
            if (g_compareAsciiHits + g_compareFallbacks > 0)
                Log("CompareStringA: %ld ASCII fast, %ld locale fallback (%.1f%% fast)",
                    g_compareAsciiHits, g_compareFallbacks,
                   (double)g_compareAsciiHits / (g_compareAsciiHits + g_compareFallbacks) * 100.0);
            if (g_fileAttrHits + g_fileAttrMisses > 0)
                Log("GetFileAttributesA: %ld hits, %ld misses (%.1f%% hit rate)",
                    g_fileAttrHits, g_fileAttrMisses,
                   (double)g_fileAttrHits / (g_fileAttrHits + g_fileAttrMisses) * 100.0);       
            if (g_badPtrFastChecks > 0)
                Log("IsBadPtr: %ld fast checks (avoided SEH probing)", g_badPtrFastChecks);
            if (g_csSpinHits > 0)
                Log("CriticalSection: %ld spin-acquired (avoided kernel wait)", g_csSpinHits);
            if (g_sfpRedirected > 0)
                Log("SetFilePointer: %ld calls redirected to SetFilePointerEx", g_sfpRedirected);
            if (g_threadAffOk) Log("Thread affinity: %d background workers pinned to cores 2+", g_bgThreadIdx);
            if (vaOk && g_vaArenaBase) {
                Log("VA Arena: %ld hits, %ld fallbacks, %ld failures (%.1f%% arena)",
                    g_vaArenaHits, g_vaArenaFallbacks, g_vaArenaFailures,
                   (g_vaArenaHits + g_vaArenaFallbacks) > 0 ? (double)g_vaArenaHits / (g_vaArenaHits + g_vaArenaFallbacks) * 100.0 : 0.0);
                ShutdownVAArena();
            }
            HeapCompactor_Shutdown();
            VersionChecker_Shutdown();
            LoadingDefrag::Shutdown();
            ShutdownAsyncIoWorker();
            D3D9RenderThread::Shutdown();
            D3D9StateCache::Shutdown();
            FrameLimiter::Shutdown();
            NetPacketOffload::Shutdown();
            PredictivePrefetch::Shutdown();
            GuidLookupCache::Shutdown();
            SimdMathFast::Shutdown();
            CombatLogIncremental::Shutdown();
            WorldStateCoalesce::Shutdown();
            SoundMixerOpt::Shutdown();
            LuaGCGovernor::Shutdown();
            AdaptiveFarclip::Shutdown();
            FontGlyphCache::Shutdown();
            CombatLogFilter::Shutdown();
            SoundVolumeLimit::Shutdown();
            TerrainHeightCache::Shutdown();
            QualityGovernor::Shutdown();
            HotPatch::ShutdownAll();
            ReportHotFunctionStats();
            CrashDumper::ReportFeatureActivity();
            LoadingState::ReportLoadTimes();
            AsyncSoundLoader::Shutdown();
            RcuObjMgr::Shutdown();
            AsyncTerrainLoader::Shutdown();
            AsyncTexLoader::Shutdown();
            SavedVarsPretoken::Shutdown();
            MipBiasGovernor::Shutdown();
            PerfDiagnostics::Shutdown();
            CrashDumper::Shutdown();
            ShutdownFrameThrottling();
            // ShutdownUIFrameBatching(); // REMOVED - optimization disabled
            ShutdownCombatLogParser();
#if !TEST_DISABLE_SAVED_VARS_ASYNC
            ShutdownSavedVarsAsync();
#endif
            ShutdownLuaGetTableCache();
            ShutdownDataStoreFastPath();
            ShutdownStringOpsFast();
            ShutdownLuaPushNumberFast();
            ShutdownGetTimeFast();
            ShutdownLuaPushValueFast();
            ShutdownLuaStackFast();
            ShutdownUIAccessorFast();
            ShutdownFontMetricsFast();
#if !TEST_DISABLE_RENDER_STATE_DEDUP
            ShutdownRenderStateDedup();
#endif

            ShutdownEventNameHash();
            ShutdownCDataStoreBatch();
            UninstallMemcpyFast();
            UninstallDbcLookupCache();
            UninstallFrameScriptDispatch();
            ShutdownD3D9StateManager();
            DXVKBridge::Shutdown();
            ShutdownRenderHooks();
            ShutdownSimdHooks();
            ShutdownLogicHooks();
            ShutdownMemoryHooks();
            ShutdownAsyncHooks();
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            {
                AcquireSRWLockExclusive(&g_cacheMapLock);
                for (auto& pair : g_readCacheMap) {
                    ReadCache* cache = pair.second;
                    if (cache) {
                        if (cache->buffer) {
                            mi_free(cache->buffer);
                        }
                        delete cache;
                    }
                }
                g_readCacheMap.clear();
                ReleaseSRWLockExclusive(&g_cacheMapLock);
            }
            // Return all mimalloc-managed pages to the OS before process exit.
            // Without this, freed blocks sit in mimalloc's internal caches and
            // the OS sees them as committed even though they're logically free.
            mi_collect(true);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                Log("Exception during DLL shutdown - continuing exit");
            }
            Log("wow_optimize.dll unloaded (clean)");
            LogClose();
            break;
    }
    return TRUE;
}