# 3.15, not 3.14, and the reason is load-bearing.
#
# MSVC_RUNTIME_LIBRARY and CMAKE_MSVC_RUNTIME_LIBRARY are governed by policy
# CMP0091, which arrived in 3.15. Asking for 3.14 leaves that policy at OLD, and
# at OLD both settings are IGNORED - silently, with no warning. So the line below
# said "force static CRT globally" and forced nothing: the generated project
# carried <RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary>, and the shipped DLL
# imported MSVCP140.dll, VCRUNTIME140.dll and the api-ms-win-crt-* set.
#
# That is not a cosmetic difference.
#   * It makes the Visual C++ Redistributable a requirement to load at all. A
#     user without it sees the injector do nothing, with no message.
#   * This project's own rule is that MSVCP140 must not be pulled in, because it
#     is loaded during early init and has crashed under Wine/Proton. The rule was
#     being enforced in the source and broken by the build.
#
# The policy is set explicitly as well as implied by the version, so that raising
# or lowering cmake_minimum_required later cannot quietly turn it back off.
cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)
project(wow_optimize LANGUAGES C CXX)

# Static CRT for every target and dependency (mimalloc, minhook). Now that
# CMP0091 is NEW this is actually applied - check it the way it was found, by
# reading the DLL's import table rather than by trusting the setting.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")


# ============================================================================
# Whole-program / link-time optimization (LTO) for the DLL.
#   -DWO_ENABLE_LTO=ON  ->  /GL (whole-program) + /LTCG (link-time codegen)
# Default OFF: LTO re-generates code across the whole DLL and can shift the
# exact codegen we are currently stabilizing crashes against. Turn it on only
# after the build is confirmed stable in-game.
#
# The gate above stands. What has changed is the size of the prize behind it:
# "marginal win on a small DLL next to wow.exe" is no longer what the evidence
# says. Without /GL the compiler cannot inline across translation units, and a
# sweep of the built objects in 2026-09-12 found that costing real time on paths
# the field counts in billions:
#
#   * lua_getstr and three siblings called LuaOpt::IsReloading and IsSwapping,
#     each of which calls LoadingDefrag::IsLoadingActive - four call and return
#     pairs on 11522349178 calls a session, to read three flags. Fixed by hand
#     with an inline accessor; /GL would have done it for free.
#   * fast_strncmp and hot_functions called CrashDumper::FeatureHit on all
#     2.8 billion of their calls, for a counter. Fixed by sampling.
#   * m2_sort_key_cache's lookup stopped being inlined when it grew, and needed
#     __forceinline plus a noinline split to come back.
#
# Those three were found and fixed one at a time. /GL addresses the whole class,
# including the instances nobody has looked for yet. So when the build is
# confirmed stable in-game, this is worth measuring properly rather than
# dismissing.
#
# PROFILE-GUIDED OPTIMIZATION (PGO) is a manual 2-phase process because it
# needs YOUR gameplay profile (there is no profile to bake in from here):
#   1. Configure with -DWO_ENABLE_LTO=ON, then link instrumented:
#        add  /GENPROFILE  to the linker (set WO_PGO=GEN below), build, and
#        play a representative session (login -> world -> a raid). This writes
#        wow_optimize!1.pgc next to the DLL.
#   2. Re-link optimized with  /USEPROFILE  (set WO_PGO=USE), which folds the
#        .pgc counts back in. Expect single-digit % on hot DLL paths only.
# ============================================================================
option(WO_ENABLE_LTO "Enable /GL + /LTCG whole-program optimization for wow_optimize" OFF)
set(WO_PGO "OFF" CACHE STRING "PGO phase for wow_optimize: OFF | GEN | USE")

include(FetchContent)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

# MinHook — lightweight function hooking library
#
# Pinned to the commit every build so far has used, instead of master, so a
# fresh clone builds the same hooking code and the edit below always finds the
# line it replaces.
FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG        8af6b4acae5a9388fd742b56fa79ece89d96f823
)
FetchContent_MakeAvailable(minhook)

# MinHook freezes every other thread of the process before it writes a hook, and
# finds them with CreateToolhelp32Snapshot, which copies every thread on the
# machine into a section; Thread32Next then maps and unmaps a view of it once per
# thread. In the rig one batched install of the Lua hooks at login spent about
# 90 ms of a 326 ms frame there, and every later freeze (a hook enabled or
# disabled at run time) pays the same, more on a machine with a browser open.
# The replacement below asks NtQuerySystemInformation once and reads only this
# process's threads. It checks itself - the calling thread must be in the list it
# read - and falls back to MinHook's own snapshot when it is not, when the call
# fails, or on anything but x86. Applied once; the marker comment makes it a no-op
# on the next configure.
set(_wo_mh_hook "${minhook_SOURCE_DIR}/src/hook.c")
file(READ "${_wo_mh_hook}" _wo_mh_src)
string(FIND "${_wo_mh_src}" "wow_optimize: thread list" _wo_mh_done)
if(_wo_mh_done EQUAL -1)
    string(FIND "${_wo_mh_src}" "static BOOL EnumerateThreads(PFROZEN_THREADS pThreads)" _wo_mh_at)
    if(_wo_mh_at EQUAL -1)
        message(WARNING "MinHook's EnumerateThreads was not found in hook.c; it keeps its own snapshot-based thread list.")
    else()
        set(_wo_mh_new [==[static BOOL EnumerateThreadsToolhelp(PFROZEN_THREADS pThreads);

/* wow_optimize: thread list from one NtQuerySystemInformation call, see CMakeLists.txt. */
static BOOL WoAddThread(PFROZEN_THREADS pThreads, DWORD tid)
{
    if (pThreads->pItems == NULL)
    {
        pThreads->capacity = INITIAL_THREAD_CAPACITY;
        pThreads->pItems = (LPDWORD)HeapAlloc(g_hHeap, 0, pThreads->capacity * sizeof(DWORD));
        if (pThreads->pItems == NULL)
            return FALSE;
    }
    else if (pThreads->size >= pThreads->capacity)
    {
        LPDWORD p;
        pThreads->capacity *= 2;
        p = (LPDWORD)HeapReAlloc(g_hHeap, 0, pThreads->pItems, pThreads->capacity * sizeof(DWORD));
        if (p == NULL)
            return FALSE;
        pThreads->pItems = p;
    }
    pThreads->pItems[pThreads->size++] = tid;
    return TRUE;
}

typedef LONG (NTAPI *WO_NTQSI)(ULONG, PVOID, ULONG, PULONG);

static BOOL EnumerateThreads(PFROZEN_THREADS pThreads)
{
#if defined(_M_IX86)
    /* x86 SYSTEM_PROCESS_INFORMATION: UniqueProcessId at 0x44, 0xB8 bytes, then
       SYSTEM_THREAD_INFORMATION entries of 0x40 bytes with ClientId.UniqueThread at 0x24. */
    static WO_NTQSI s_query = NULL;
    static BOOL s_looked = FALSE;
    ULONG size = 512 * 1024;
    ULONG needed = 0;
    LPBYTE buf = NULL;
    LONG st = -1;
    int tries;
    if (!s_looked)
    {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        s_query = nt ? (WO_NTQSI)GetProcAddress(nt, "NtQuerySystemInformation") : NULL;
        s_looked = TRUE;
    }
    if (s_query == NULL)
        return EnumerateThreadsToolhelp(pThreads);
    for (tries = 0; tries < 4; ++tries)
    {
        buf = (LPBYTE)HeapAlloc(g_hHeap, 0, size);
        if (buf == NULL)
            return EnumerateThreadsToolhelp(pThreads);
        st = s_query(5 /* SystemProcessInformation */, buf, size, &needed);
        if (st >= 0)
            break;
        HeapFree(g_hHeap, 0, buf);
        buf = NULL;
        if (st != (LONG)0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */)
            return EnumerateThreadsToolhelp(pThreads);
        size = (needed > size ? needed : size * 2) + 64 * 1024;
    }
    if (buf == NULL)
        return EnumerateThreadsToolhelp(pThreads);
    {
        const DWORD pid  = GetCurrentProcessId();
        const DWORD self = GetCurrentThreadId();
        ULONG off = 0;
        BOOL found = FALSE, sawSelf = FALSE, ok = TRUE;
        for (;;)
        {
            LPBYTE p = buf + off;
            if (off + 0xB8 > size)
                break;
            if ((DWORD)(ULONG_PTR)*(HANDLE*)(p + 0x44) == pid)
            {
                const ULONG n = *(ULONG*)(p + 4);
                ULONG i;
                found = TRUE;
                if (off + 0xB8 + n * 0x40 > size)
                {
                    ok = FALSE;
                    break;
                }
                for (i = 0; i < n && ok; ++i)
                {
                    const DWORD tid = (DWORD)(ULONG_PTR)*(HANDLE*)(p + 0xB8 + i * 0x40 + 0x24);
                    if (tid == self)
                    {
                        sawSelf = TRUE;
                        continue;
                    }
                    ok = WoAddThread(pThreads, tid);
                }
                break;
            }
            if (*(ULONG*)p == 0)
                break;
            off += *(ULONG*)p;
        }
        HeapFree(g_hHeap, 0, buf);
        if (found && sawSelf && ok)
            return TRUE;
        if (pThreads->pItems != NULL)
        {
            HeapFree(g_hHeap, 0, pThreads->pItems);
            pThreads->pItems = NULL;
        }
        pThreads->size = 0;
        pThreads->capacity = 0;
    }
#endif
    return EnumerateThreadsToolhelp(pThreads);
}

]==])
        string(REPLACE "static BOOL EnumerateThreads(PFROZEN_THREADS pThreads)"
                       "${_wo_mh_new}static BOOL EnumerateThreadsToolhelp(PFROZEN_THREADS pThreads)"
                       _wo_mh_src "${_wo_mh_src}")
        file(WRITE "${_wo_mh_hook}" "${_wo_mh_src}")
        message(STATUS "MinHook: thread enumeration replaced with NtQuerySystemInformation (falls back to the snapshot)")
    endif()
endif()

# mimalloc — Microsoft's high-performance allocator
FetchContent_Declare(
    mimalloc
    GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
    GIT_TAG        v3.6.0
)
set(MI_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(MI_BUILD_TESTS  OFF CACHE BOOL "" FORCE)
set(MI_OVERRIDE     OFF CACHE BOOL "" FORCE)
# Since v3.5.2 a release build counts detailed statistics and carries sampled
# profiling hooks unless told otherwise. Both add work to every allocation and
# free, and nothing in this DLL reads either: mi_process_info asks the OS. They
# were compiled out in v3.3.2, and they stay out. MI_OPT_ARCH is already off for
# 32-bit x86 by default; it is pinned so a later default cannot turn on
# /arch:AVX2 for players whose CPUs lack it.
set(MI_STATS        OFF CACHE STRING "" FORCE)
set(MI_PROFILE      OFF CACHE STRING "" FORCE)
set(MI_OPT_ARCH     OFF CACHE STRING "" FORCE)
FetchContent_MakeAvailable(mimalloc)

# === Main optimization DLL ===
add_library(wow_optimize SHARED
    src/core/dllmain.cpp
    src/core/config.cpp
    src/core/world_position.cpp
    src/hooks_subsystems/tick_list_prefetch.cpp
    src/diagnostics/lua_table_census.cpp
    src/runtime_vm/lua_table_traverse_fast.cpp
    src/runtime_vm/lua_table_traverse_fast.h
    src/runtime_vm/lua_gc_sweeplist_fast.cpp
    src/runtime_vm/lua_gc_sweeplist_fast.h
    # Windows file-version metadata. This was never attached to a target, so the
    # shipped DLL carried no version resource at all and the file sat at 3.12.0
    # unnoticed through several releases.
    src/core/version.rc
    src/hooks_subsystems/crt_mem_fastpath.cpp
    src/runtime_vm/lua_mempool_fast.cpp
    src/runtime_vm/lua_optimize.cpp
    src/runtime_vm/lua_optimize.h
    src/hooks_subsystems/combatlog_optimize.cpp
    src/hooks_subsystems/combatlog_optimize.h
    src/hooks_subsystems/combatlog_buffer.cpp
    src/hooks_subsystems/combatlog_buffer.h
    src/threading/addon_dispatcher.cpp
    src/threading/addon_dispatcher.h
    src/hooks_subsystems/obj_vis_cache.cpp
    src/hooks_subsystems/obj_vis_cache.h
    src/hooks_subsystems/rcu_obj_mgr.cpp
    src/hooks_subsystems/objmgr_enum_fast.cpp
    src/hooks_subsystems/mpq_open_census.cpp
    src/hooks_subsystems/rcu_obj_mgr.h
    src/hooks_subsystems/nameplate_batch.cpp
    src/hooks_subsystems/nameplate_batch.h
    src/hooks_subsystems/ui_cache.cpp
    src/hooks_subsystems/ui_cache.h
    src/core/version.h
    src/hooks_subsystems/api_cache.cpp
    src/hooks_subsystems/api_cache.h
    src/runtime_vm/lua_fastpath.cpp
    src/runtime_vm/lua_alloc_census.cpp
    src/runtime_vm/lua_fastpath.h
    src/runtime_vm/lua_internals.cpp
    src/runtime_vm/lua_internals.h
    src/diagnostics/alloc_tag_census.cpp
    src/diagnostics/alloc_tag_census.h
    src/diagnostics/net_diag.cpp
    src/diagnostics/net_diag.h
    src/diagnostics/thread_cpu.cpp
    src/diagnostics/thread_cpu.h
    src/diagnostics/addon_profiler.cpp
    src/diagnostics/addon_profiler.h
    src/diagnostics/lua_compile_census.cpp
    src/diagnostics/lua_compile_census.h
    src/diagnostics/shadow_state_probe.cpp
    src/diagnostics/shadow_state_probe.h
    src/diagnostics/flight_recorder.cpp
    src/diagnostics/flight_recorder.h
    src/diagnostics/ab_test.cpp
    src/diagnostics/self_bench.cpp
    src/diagnostics/freeze_catcher.cpp
    src/diagnostics/ab_test.h
    src/diagnostics/session_verdict.cpp
    src/diagnostics/session_verdict.h
    src/hooks_subsystems/strncmp_sse2.cpp
    src/hooks_subsystems/strncmp_sse2.h
    src/diagnostics/anim_census.cpp
    src/diagnostics/anim_census.h
    src/diagnostics/anim_track_census.cpp
    src/diagnostics/anim_track_census.h
    src/diagnostics/crash_dumper.cpp
    src/hooks_subsystems/vertex_fmt_inline.cpp
    src/hooks_subsystems/objmgr_find_fast.cpp
    src/hooks_subsystems/anim_lod.cpp
    src/simd_math/collision_outcode_sse2.cpp
    src/simd_math/collision_model_cache_sse2.cpp
    src/simd_math/collision_ray_outcode_sse2.cpp
    src/simd_math/x87_precision_check.cpp
    src/simd_math/ray_triangle_sse2.cpp
    src/simd_math/occluder_sphere_sse2.cpp
    src/simd_math/m2_anim_find_key_fast.cpp
    src/simd_math/aabb_overlap_sse2.cpp
    src/simd_math/anim_quat_unpack_sse2.cpp
    src/simd_math/anim_vec3_track_sse2.cpp
    src/simd_math/anim_scalar_track_sse2.cpp
    src/simd_math/anim_spline_track_sse2.cpp
    src/simd_math/anim_spline_track_sse2.h
    src/simd_math/aabb_transform_sse2.cpp
    src/simd_math/aabb_transform_sse2.h
    src/simd_math/color_unpack_sse2.cpp
    src/simd_math/color_unpack_sse2.h
    src/hooks_subsystems/m2_sort_key_cache.cpp
    src/hooks_subsystems/m2_batch_sort.cpp
    src/simd_math/smem_sort_fast.cpp
    src/simd_math/smem_sort_fast.h
    src/simd_math/collision_poly_clip_sse2.cpp
    src/hooks_subsystems/sky_texture_reuse.cpp
    src/hooks_subsystems/sky_cloud_texels.cpp
    src/simd_math/particle_track_eval_sse2.cpp
    src/simd_math/shader_const_dedup_sse2.cpp
    src/simd_math/batch_colour_convert.cpp
    src/simd_math/floor_split_sse2.cpp
    src/simd_math/frustum_aabb_sse2.cpp
    src/simd_math/segment_aabb_sse2.cpp
    src/simd_math/wmo_group_bounds_fast.cpp
    src/simd_math/wmo_group_bounds_fast.h
    src/simd_math/map_obj_query_fast.cpp
    src/simd_math/map_obj_query_fast.h
    src/simd_math/angle_normalize_fast.cpp
    src/simd_math/angle_normalize_fast.h
    src/simd_math/ray_bounding_box_fast.cpp
    src/simd_math/ray_bounding_box_fast.h

    src/runtime_vm/lua_hget_dispatch.cpp
    src/runtime_vm/lua_pool_fast.cpp
    src/runtime_vm/lua_proto_cache.cpp
    src/runtime_vm/lua_bytecode_store.cpp
    src/runtime_vm/lua_undump.cpp
    src/simd_math/quat_lerp_sse2.cpp
    src/simd_math/bone_matrix_upload_sse2.cpp
    src/simd_math/ui_batch_fill_sse2.cpp
    src/simd_math/particle_fill_sse2.cpp
    src/runtime_vm/lua_vm_fast.cpp
    src/runtime_vm/lua_vm_fast.h
    src/simd_math/m2_matrix_slot_sse2.cpp
    src/simd_math/m2_batch_matrix_sse2.cpp
    src/simd_math/m2_batch_matrix_sse2.h
    src/hooks_subsystems/m2_anim_stride.cpp
    src/hooks_subsystems/m2_anim_reuse.cpp
    src/hooks_subsystems/world_vis_traverse_sse2.cpp
    src/hooks_subsystems/world_vis_traverse_sse2.h
    src/hooks_subsystems/ui_strata_opt.cpp
    src/hooks_subsystems/ui_strata_opt.h
    src/hooks_subsystems/ui_strata_occlusion_sse2.cpp
    src/hooks_subsystems/ui_strata_occlusion_sse2.h
    src/hooks_subsystems/ui_frame_level_fast.cpp
    src/hooks_subsystems/ui_frame_level_fast.h
    src/hooks_subsystems/async_time_fast.cpp
    src/hooks_subsystems/async_time_fast.h
    src/hooks_subsystems/ui_anim_update_fast.cpp
    src/hooks_subsystems/ui_anim_update_fast.h
    src/hooks_subsystems/gx_device_texture_fast.cpp
    src/hooks_subsystems/gx_device_texture_fast.h
    src/hooks_subsystems/ui_render_coord_fast.cpp
    src/hooks_subsystems/ui_render_coord_fast.h
    src/hooks_subsystems/gx_texture_wrap_fast.cpp
    src/hooks_subsystems/gx_texture_wrap_fast.h
    src/hooks_subsystems/ui_anchor_check_fast.cpp
    src/hooks_subsystems/ui_anchor_check_fast.h
    src/hooks_subsystems/fog_state_dedup.cpp
    src/hooks_subsystems/fog_state_dedup.h
    src/hooks_subsystems/lua_func_bounds_fast.cpp
    src/hooks_subsystems/lua_func_bounds_fast.h
    src/hooks_subsystems/scene_node_active_fast.cpp
    src/hooks_subsystems/scene_node_active_fast.h
    src/allocators/mimalloc_high_arena.cpp
    src/allocators/high_placement.cpp
    src/allocators/process_top_down.cpp
    src/allocators/process_top_down.h
    src/hooks_subsystems/client_write_batch.cpp
    src/hooks_subsystems/render_null_guard.cpp
    src/hooks_subsystems/device_callback_guard.cpp
    src/hooks_subsystems/layout_relink_fast.cpp
    src/diagnostics/cvar_watchdog.cpp
    src/diagnostics/cvar_watchdog.h
    src/runtime_vm/lua_precall_cache.cpp
    src/runtime_vm/lua_precall_cache.h
    src/runtime_vm/lua_table_fast.cpp
    src/runtime_vm/lua_table_fast.h
    src/runtime_vm/lua_hget_fast.cpp
    src/runtime_vm/lua_hget_fast.h
    src/runtime_vm/lua_checknumber_fast.cpp
    src/runtime_vm/lua_checknumber_fast.h
    src/runtime_vm/lua_checkstring_fast.cpp
    src/runtime_vm/lua_checkstring_fast.h
    src/runtime_vm/lua_optnumber_fast.cpp
    src/runtime_vm/lua_optnumber_fast.h
    src/runtime_vm/lua_optstring_fast.cpp
    src/runtime_vm/lua_optstring_fast.h
    src/runtime_vm/lua_tolstring_fast.cpp
    src/runtime_vm/lua_tolstring_fast.h
    src/runtime_vm/lua_argcheck_fast.cpp
    src/runtime_vm/lua_argcheck_fast.h
    src/runtime_vm/lua_typename_fast.cpp
    src/runtime_vm/lua_typename_fast.h
    src/runtime_vm/lua_getlocal_fast.cpp
    src/runtime_vm/lua_getlocal_fast.h
    src/runtime_vm/lua_setlocal_fast.cpp
    src/runtime_vm/lua_setlocal_fast.h
    src/runtime_vm/lua_getinfo_fast.cpp
    src/runtime_vm/lua_getinfo_fast.h
    src/runtime_vm/lua_error_fast.cpp
    src/runtime_vm/lua_error_fast.h
    src/runtime_vm/lua_lessthan_fast.cpp
    src/runtime_vm/lua_lessthan_fast.h
    src/runtime_vm/lua_gc_fast.cpp
    src/runtime_vm/lua_gc_fast.h
    src/runtime_vm/lua_gc_governor.cpp
    src/runtime_vm/lua_gc_pace.cpp
    src/runtime_vm/lua_gc_governor.h
    src/hooks_subsystems/sound_mixer_opt.cpp
    src/hooks_subsystems/sound_mixer_opt.h
    src/hooks_subsystems/sound_group_guard.cpp
    src/hooks_subsystems/sound_group_guard.h
    src/hooks_subsystems/async_tex_loader.cpp
    src/hooks_subsystems/async_tex_loader.h
    src/hooks_subsystems/adaptive_farclip.cpp
    src/hooks_subsystems/adaptive_farclip.h
    src/hooks_subsystems/quality_governor.cpp
    src/hooks_subsystems/quality_governor.h
    src/hooks_subsystems/font_glyph_cache.cpp
    src/hooks_subsystems/font_glyph_cache.h
    src/hooks_subsystems/async_sound_loader.cpp
    src/hooks_subsystems/async_sound_loader.h
    src/hooks_subsystems/mip_bias_governor.cpp
    src/hooks_subsystems/mip_bias_governor.h
    src/diagnostics/perf_diagnostics.cpp
    src/diagnostics/perf_diagnostics.h
    src/diagnostics/frame_bench.cpp
    src/diagnostics/frame_bench.h
    src/diagnostics/camera_replay.cpp
    src/diagnostics/camera_replay.h
    src/diagnostics/camera_watch.cpp
    src/diagnostics/camera_watch.h
    src/runtime_vm/lua_xpcall_fast.cpp
    src/runtime_vm/lua_xpcall_fast.h
    src/runtime_vm/lua_getmetafield_fast.cpp
    src/runtime_vm/lua_getmetafield_fast.h
    src/runtime_vm/lua_where_fast.cpp
    src/runtime_vm/lua_where_fast.h
    src/runtime_vm/lua_settable_fast.cpp
    src/runtime_vm/lua_settable_fast.h
    src/runtime_vm/lua_pushfstring_fast.cpp
    src/runtime_vm/lua_pushfstring_fast.h
    src/runtime_vm/lua_gettable_fast.cpp
    src/runtime_vm/lua_gettable_fast.h
    src/runtime_vm/lua_rawseti_fast.cpp
    src/runtime_vm/lua_rawseti_fast.h
    src/runtime_vm/lua_setfield_fast.cpp
    src/runtime_vm/lua_setfield_fast.h
    src/runtime_vm/lua_gettime_fast.cpp
    src/runtime_vm/lua_gettime_fast.h
    src/runtime_vm/lua_getupvalue_fast.cpp
    src/runtime_vm/lua_getupvalue_fast.h
    src/runtime_vm/lua_buffinit_fast.cpp
    src/runtime_vm/lua_buffinit_fast.h
    src/runtime_vm/lua_prepbuffer_fast.cpp
    src/runtime_vm/lua_prepbuffer_fast.h
    src/runtime_vm/lua_pushresult_fast.cpp
    src/runtime_vm/lua_pushresult_fast.h
    src/runtime_vm/lua_addlstring_fast.cpp
    src/runtime_vm/lua_addlstring_fast.h
    src/hooks_subsystems/render_null_guard.h
    src/hooks_subsystems/cvar_null_guard.cpp
    src/hooks_subsystems/cvar_null_guard.h
    src/hooks_subsystems/d3d_evict_patch.cpp
    src/hooks_subsystems/d3d_evict_patch.h
    src/hooks_subsystems/dxvk_bridge.cpp
    src/hooks_subsystems/dxvk_bridge.h
    src/hooks_subsystems/strncmp_null_guard.cpp
    src/hooks_subsystems/strncmp_null_guard.h
    src/runtime_vm/lua_vm_cache.cpp
    src/runtime_vm/lua_vm_cache.h
    src/runtime_vm/lua_settable_cache.cpp
    src/runtime_vm/lua_settable_cache.h
    src/runtime_vm/regex_cache.cpp
    src/runtime_vm/regex_cache.h
    src/runtime_vm/lua_bytecode_cache.cpp
    src/runtime_vm/lua_bytecode_cache.h
    src/hooks_subsystems/addon_preload.cpp
    src/hooks_subsystems/addon_preload.h
    src/hooks_subsystems/strstr_fast.cpp
    src/hooks_subsystems/strstr_fast.h
    src/hooks_subsystems/strtod_fast.cpp
    src/hooks_subsystems/strtod_fast.h
    src/hooks_subsystems/crt_char_fast.cpp
    src/hooks_subsystems/crt_char_fast.h
    src/hooks_subsystems/crt_wchar_fast.cpp
    src/hooks_subsystems/crt_wchar_fast.h
    src/runtime_vm/lua_this_cache.cpp
    src/runtime_vm/lua_this_cache.h
    src/hooks_subsystems/io_cache.cpp
    src/hooks_subsystems/io_cache.h
    src/runtime_vm/lua_global_cache.cpp
    src/runtime_vm/lua_global_cache.h
    src/hooks_subsystems/hot_functions.cpp
    src/hooks_subsystems/hot_functions.h
    src/hooks_subsystems/crt_memcpy_fast.cpp
    src/hooks_subsystems/crt_memcpy_fast.h
    src/hooks_subsystems/frame_script_dispatch.cpp
    src/hooks_subsystems/frame_script_dispatch.h
    src/hooks_subsystems/fast_strncmp.cpp
    src/hooks_subsystems/fast_strncmp.h
    src/allocators/crt_free_hook.cpp
    src/threading/lock_tuning.cpp
    src/threading/cpu_topology.cpp
    src/allocators/texcache_tuning.cpp
    src/allocators/crt_free_hook.h
    src/allocators/aligned_alloc_cache.cpp
    src/allocators/aligned_alloc_cache.h
    src/hooks_subsystems/datastore_fastpath.cpp
    src/hooks_subsystems/datastore_fastpath.h
    src/hooks_subsystems/string_ops_fast.cpp
    src/hooks_subsystems/string_ops_fast.h
    src/runtime_vm/lua_tonumber_cache.cpp
    src/runtime_vm/lua_tonumber_cache.h
    src/runtime_vm/lua_checknumber_cache.cpp
    src/runtime_vm/lua_checknumber_cache.h
    src/runtime_vm/lua_pushstring_cache.cpp
    src/runtime_vm/lua_pushstring_cache.h
    src/hooks_subsystems/format_validator_cache.cpp
    src/hooks_subsystems/format_validator_cache.h
    src/allocators/heap_compactor.cpp
    src/allocators/heap_compactor.h
    src/allocators/memory_pressure_governor.cpp
    src/allocators/memory_pressure_governor.h
    src/allocators/loading_defrag.cpp
    src/allocators/high_tables.cpp
    src/allocators/loading_defrag.h
    src/hooks_subsystems/d3d9_state_cache.cpp
    src/hooks_subsystems/d3d9_state_cache.h
    src/hooks_subsystems/d3d9_render_thread.cpp
    src/hooks_subsystems/d3d9_render_thread.h
    src/hooks_subsystems/frame_limiter.cpp
    src/hooks_subsystems/frame_limiter.h
    src/hooks_subsystems/guid_lookup_cache.cpp
    src/hooks_subsystems/guid_lookup_cache.h
    src/simd_math/simd_math_fast.cpp
    src/simd_math/simd_math_fast.h
    src/hooks_subsystems/combatlog_incremental.cpp
    src/hooks_subsystems/combatlog_incremental.h
    src/hooks_subsystems/world_state_coalesce.cpp
    src/hooks_subsystems/world_state_coalesce.h
    src/hooks_subsystems/net_packet_offload.cpp
    src/hooks_subsystems/net_packet_offload.h
    src/hooks_subsystems/predictive_prefetch.cpp
    src/hooks_subsystems/predictive_prefetch.h
    src/runtime_vm/lua_tonumber_fast.cpp
    src/runtime_vm/lua_pushnumber_fast.cpp
    src/hooks_subsystems/gettime_fast.cpp
    src/runtime_vm/lua_pushvalue_fast.cpp
    src/hooks_subsystems/render_state_dedup.cpp
    src/runtime_vm/lua_tonumber_fast.h
    src/hooks_subsystems/strcat_fast.cpp
    src/hooks_subsystems/strcat_fast.h
    src/hooks_subsystems/script_handler_cache.cpp
    src/hooks_subsystems/script_handler_cache.h
    src/hooks_subsystems/dbc_lookup_cache.cpp
    src/hooks_subsystems/dbc_lookup_cache.h
    src/hooks_subsystems/event_dispatch_cache.cpp
    src/hooks_subsystems/event_dispatch_cache.h
    src/runtime_vm/lua_getstr_inline.cpp
    src/runtime_vm/lua_rawgeti_inline.cpp
    src/runtime_vm/lua_rawget_inline.cpp
    src/runtime_vm/lua_toboolean_inline.cpp
    src/runtime_vm/lua_objlen_inline.cpp
    src/runtime_vm/lua_error_diag.cpp
    src/runtime_vm/lua_error_diag.h
    src/runtime_vm/lua_getstr_inline.h
    src/runtime_vm/lua_rawget_inline.h
    src/runtime_vm/lua_toboolean_inline.h
    src/runtime_vm/lua_gettable_safety.cpp
    src/runtime_vm/lua_gettable_safety.h
    src/runtime_vm/type_check_safety.cpp
    src/runtime_vm/object_unlink_safety.cpp
    src/runtime_vm/lua_newkey_safety.cpp
    src/runtime_vm/lua_newkey_safety.h
    src/runtime_vm/lua_vm_engine.cpp
    src/runtime_vm/lua_vm_engine.h
    src/runtime_vm/lua_gettable_cache.cpp
    src/runtime_vm/lua_gettable_cache.h
    src/hooks_subsystems/saved_vars_async.cpp
    src/hooks_subsystems/saved_vars_async.h
    src/hooks_subsystems/wow_perf_hooks.cpp
    src/hooks_subsystems/wow_perf_hooks.h
    src/hooks_subsystems/wow_extended_hooks.cpp
    src/hooks_subsystems/wow_extended_hooks.h
    src/hooks_subsystems/wow_memory_opt.cpp
    src/hooks_subsystems/wow_memory_opt.h
    src/hooks_subsystems/hooks_render.cpp
    src/hooks_subsystems/hooks_render.h
    src/simd_math/horizon_occlusion_sse2.cpp
    src/simd_math/horizon_occlusion_sse2.h
    src/simd_math/hooks_simd.cpp
    src/simd_math/hooks_simd.h
    src/hooks_subsystems/hooks_logic.cpp
    src/hooks_subsystems/hooks_logic.h
    src/hooks_subsystems/hooks_memory.cpp
    src/hooks_subsystems/hooks_memory.h
    src/hooks_subsystems/hooks_async.cpp
    src/hooks_subsystems/hooks_async.h
    src/hooks_subsystems/d3d9_state_manager.cpp
    src/hooks_subsystems/d3d9_state_manager.h
    src/hooks_subsystems/gx_ring.h
    src/hooks_subsystems/gx_internal.h
    src/hooks_subsystems/gx_render_thread.cpp
    src/hooks_subsystems/gx_render_thread.h
    src/hooks_subsystems/gx_buffers.cpp
    src/hooks_subsystems/event_coalescer.cpp
    src/hooks_subsystems/event_coalescer.h
    src/hooks_subsystems/net_addon_coalescer.cpp
    src/hooks_subsystems/net_addon_coalescer.h
    src/hooks_subsystems/loading_state.cpp
    src/hooks_subsystems/loading_state.h
    src/runtime_vm/luaS_newlstr_sse2.cpp
    src/runtime_vm/luaS_newlstr_sse2.h
    src/core/version_checker.cpp
    src/core/version_checker.h
    src/hooks_subsystems/unitaura_fastpath.cpp
    src/hooks_subsystems/unitaura_fastpath.h
    src/simd_math/network_guid_sse2.cpp
    src/simd_math/network_guid_sse2.h
    src/simd_math/matrix_copy_sse2.cpp
    src/simd_math/matrix_copy_sse2.h
    src/runtime_vm/lua_numconv_fast.cpp
    src/runtime_vm/lua_numconv_fast.h
    src/runtime_vm/lua_index2adr.cpp
    src/runtime_vm/lua_stack_fast.cpp
    src/runtime_vm/lua_stack_fast.h
    src/runtime_vm/lua_pushthread_fast.cpp
    src/runtime_vm/lua_pushthread_fast.h
    src/runtime_vm/lua_rawset_fast.cpp
    src/runtime_vm/lua_rawset_fast.h
    src/runtime_vm/lua_pushcclosure_fast.cpp
    src/runtime_vm/lua_pushcclosure_fast.h
    src/runtime_vm/lua_createtable_fast.cpp
    src/runtime_vm/lua_createtable_fast.h
    src/runtime_vm/lua_pushstring_fast.cpp
    src/runtime_vm/lua_pushstring_fast.h
    src/runtime_vm/lua_register_fast.cpp
    src/runtime_vm/lua_register_fast.h
    src/runtime_vm/lua_ref_fast.cpp
    src/runtime_vm/lua_ref_fast.h
    src/runtime_vm/lua_unref_fast.cpp
    src/runtime_vm/lua_unref_fast.h
    src/runtime_vm/lua_callmeta_fast.cpp
    src/runtime_vm/lua_callmeta_fast.h
    src/runtime_vm/lua_checktype_fast.cpp
    src/runtime_vm/lua_checktype_fast.h
    src/runtime_vm/lua_iscfunction_fast.cpp
    src/runtime_vm/lua_iscfunction_fast.h
    src/runtime_vm/lua_isnumber_fast.cpp
    src/runtime_vm/lua_isnumber_fast.h
    src/runtime_vm/lua_rawequal_fast.cpp
    src/runtime_vm/lua_rawequal_fast.h
    src/runtime_vm/lua_loadstring_fast.cpp
    src/runtime_vm/lua_loadstring_fast.h
    src/runtime_vm/lua_yield_fast.cpp
    src/runtime_vm/lua_yield_fast.h
    src/runtime_vm/lua_getn_fast.cpp
    src/runtime_vm/lua_getn_fast.h
    src/runtime_vm/combatlog_parser.cpp
    src/runtime_vm/combatlog_parser.h
    src/hooks_subsystems/ui_accessor_fast.cpp
    src/hooks_subsystems/ui_accessor_fast.h
    src/hooks_subsystems/font_metrics_fast.cpp
    src/hooks_subsystems/font_metrics_fast.h
    src/diagnostics/sampling_profiler.cpp
    src/diagnostics/lua_addon_sampler.cpp
    src/hooks_subsystems/sound_driver_guard.cpp
    src/hooks_subsystems/sound_emitter_guard.cpp
    src/hooks_subsystems/sound_buffer_guard.cpp

    src/diagnostics/sampling_profiler.h
    src/hooks_subsystems/sound_driver_guard.h
    src/hooks_subsystems/sound_emitter_guard.h
    src/hooks_subsystems/sound_buffer_guard.h

    src/hooks_subsystems/sound_coalescer.cpp
    src/hooks_subsystems/sound_coalescer.h
    src/hooks_subsystems/particle_density_scaler.cpp
    src/hooks_subsystems/particle_density_scaler.h
    src/hooks_subsystems/vertex_buffer_prealloc.cpp
    src/hooks_subsystems/vertex_buffer_prealloc.h
    src/hooks_subsystems/saved_vars_backup.cpp
    src/hooks_subsystems/saved_vars_backup.h
    src/hooks_subsystems/mouse_clip_release.cpp
    src/hooks_subsystems/mouse_clip_release.h
    src/hooks_subsystems/combat_log_filter.cpp
    src/hooks_subsystems/combat_log_filter.h
    src/hooks_subsystems/sound_volume_limit.cpp
    src/hooks_subsystems/sound_volume_limit.h
    src/hooks_subsystems/terrain_height_cache.cpp
    src/hooks_subsystems/terrain_height_cache.h
    src/hooks_subsystems/texture_unload_delay.cpp
    src/hooks_subsystems/texture_unload_delay.h
    src/hooks_subsystems/texture_get_gxtex_fast.cpp
    src/hooks_subsystems/texture_get_gxtex_fast.h
    src/hooks_subsystems/spell_effect_culling.cpp
    src/hooks_subsystems/spell_effect_culling.h
    src/simd_math/collision_ray_verts_sse2.cpp
    src/simd_math/collision_ray_verts_sse2.h
    src/hooks_subsystems/fmod_parameq_sse2.cpp
    src/hooks_subsystems/fmod_parameq_sse2.h
    src/hooks_subsystems/ui_rect_subdivide_sse2.cpp
    src/hooks_subsystems/ui_rect_subdivide_sse2.h
    src/hooks_subsystems/scene_vis_traverse_sse2.cpp
    src/hooks_subsystems/scene_vis_traverse_sse2.h
    src/hooks_subsystems/scene_attach_fast.cpp
    src/hooks_subsystems/scene_attach_fast.h
    src/hooks_subsystems/ui_texture_vertex_fast.cpp
    src/hooks_subsystems/ui_texture_vertex_fast.h
    src/hooks_subsystems/scene_query_cell_fast.cpp
    src/hooks_subsystems/scene_query_cell_fast.h
    src/hooks_subsystems/m2_batch_dedupe_cmp.cpp
    src/hooks_subsystems/m2_batch_dedupe_cmp.h
    src/simd_math/spline_interp_fast.cpp
    src/simd_math/spline_interp_fast.h
    src/simd_math/spline_deriv_fast.cpp
    src/simd_math/spline_deriv_fast.h
    src/simd_math/m2_skinning_fast.cpp
    src/simd_math/m2_skinning_fast.h
    src/simd_math/m2_skinning_40b_fast.cpp
    src/simd_math/m2_skinning_40b_fast.h
    src/simd_math/distance_fast.cpp
    src/simd_math/distance_fast.h
    src/simd_math/transform_direction_fast.cpp
    src/simd_math/transform_direction_fast.h
    src/simd_math/m2_bone_blend_fast.cpp
    src/simd_math/m2_bone_blend_fast.h
    src/simd_math/trig_approx_fast.cpp
    src/simd_math/trig_approx_fast.h
    src/simd_math/gx_blit_fast.cpp
    src/simd_math/gx_blit_fast.h
    src/simd_math/inside_frustum_fast.cpp
    src/simd_math/inside_frustum_fast.h
    src/simd_math/aabox_ops_fast.cpp
    src/simd_math/aabox_ops_fast.h
    src/simd_math/m2_lighting_match_fast.cpp
    src/simd_math/m2_lighting_match_fast.h
    src/simd_math/camera_nearest_corner_fast.cpp
    src/simd_math/camera_nearest_corner_fast.h
    src/simd_math/matrix_determinant_fast.cpp
    src/simd_math/matrix_determinant_fast.h
    src/simd_math/rect_ops_fast.cpp
    src/simd_math/rect_ops_fast.h
    src/simd_math/aa_sphere_ops_fast.cpp
    src/simd_math/aa_sphere_ops_fast.h
    src/simd_math/vector_ray_ops_fast.cpp
    src/simd_math/vector_ray_ops_fast.h
    src/simd_math/mat33_quat_ops_fast.cpp
    src/simd_math/mat33_quat_ops_fast.h
    src/simd_math/aabox_multi_ops_fast.cpp
    src/simd_math/aabox_multi_ops_fast.h
    src/simd_math/plane_from_points_fast.cpp
    src/simd_math/plane_from_points_fast.h
    src/simd_math/matrix_adjugate_fast.cpp
    src/simd_math/matrix_adjugate_fast.h
    src/simd_math/particle_physics_sse2.cpp
    src/simd_math/particle_physics_sse2.h
    src/simd_math/collision_reset_visited.cpp
    src/simd_math/collision_reset_visited.h
    src/hooks_subsystems/ui_strata_compact_sse2.cpp
    src/hooks_subsystems/ui_strata_compact_sse2.h
    src/simd_math/dbc_fast_rle.cpp
    src/simd_math/dbc_fast_rle.h
    src/hooks_subsystems/ui_frame_remove.cpp
    src/hooks_subsystems/ui_frame_remove.h
    src/hooks_subsystems/m2_batch_cmp_transparent.cpp
    src/hooks_subsystems/m2_batch_cmp_transparent.h
    src/hooks_subsystems/m2_batch_cmp_solid.cpp
    src/hooks_subsystems/m2_batch_cmp_solid.h
    src/simd_math/particle_quad_sse2.cpp
    src/simd_math/particle_quad_sse2.h
    src/simd_math/detail_doodad_vertices_sse2.cpp
    src/simd_math/detail_doodad_vertices_sse2.h
    src/simd_math/m2_shadow_batch_fast.cpp
    src/simd_math/m2_shadow_batch_fast.h
    src/simd_math/particle_fill_fast.cpp
    src/simd_math/particle_fill_fast.h
    src/simd_math/ribbon_edge_loop.cpp
    src/simd_math/ribbon_edge_loop.h
    src/hooks_subsystems/bone_track_prefetch.cpp
    src/hooks_subsystems/bone_track_prefetch.h
    src/hooks_subsystems/batch_chain_prefetch.cpp
    src/hooks_subsystems/batch_chain_prefetch.h
    src/simd_math/ribbon_edge_model.h
    src/simd_math/particle_fill_model.h
    src/simd_math/particle_eval_model.h
    src/hooks_subsystems/particle_loop_prefetch.cpp
    src/hooks_subsystems/particle_loop_prefetch.h
    src/hooks_subsystems/addon_memory_walk.cpp
    src/hooks_subsystems/addon_memory_walk.h
    src/hooks_subsystems/async_poll_spin.cpp
    src/hooks_subsystems/async_poll_spin.h
    src/diagnostics/client_code_audit.cpp
    src/diagnostics/client_code_audit.h
    src/diagnostics/file_attr_census.cpp
    src/diagnostics/file_attr_census.h
    src/hooks_subsystems/fast_exit.cpp
    src/hooks_subsystems/fast_exit.h
    src/hooks_subsystems/extra_readers.cpp
    src/hooks_subsystems/extra_readers.h
    src/hooks_subsystems/loading_frame_cap.cpp
    src/hooks_subsystems/loading_frame_cap.h
    src/hooks_subsystems/timer_calibration.cpp
    src/hooks_subsystems/timer_calibration.h
    src/runtime_vm/lua_collect_skip.cpp
    src/runtime_vm/lua_collect_skip.h
    src/diagnostics/sleep_census.cpp
    src/diagnostics/sleep_census.h
    src/hooks_subsystems/parallel_particles.cpp
    src/hooks_subsystems/parallel_particles.h
    src/hooks_subsystems/m2_parallel_roots.cpp
    src/hooks_subsystems/m2_parallel_roots.h
    src/hooks_subsystems/m2_parallel_children.cpp
    src/hooks_subsystems/m2_parallel_children.h
    src/hooks_subsystems/nameplate_parallel.cpp
    src/hooks_subsystems/nameplate_parallel.h
    src/hooks_subsystems/grass_parallel.cpp
    src/hooks_subsystems/grass_parallel.h
    src/simd_math/horizon_test_sse2.cpp
    src/simd_math/horizon_test_sse2.h
    src/simd_math/m2_skin_proj_fast.cpp
    src/simd_math/m2_skin_proj_fast.h
    src/simd_math/terrain_vertex_fast.cpp
    src/simd_math/terrain_vertex_fast.h
    src/hooks_subsystems/sstr_hash_fast.cpp
    src/hooks_subsystems/sstr_hash_fast.h
    src/hooks_subsystems/reverb_clear_fast.cpp
    src/hooks_subsystems/reverb_clear_fast.h
    src/hooks_subsystems/ui_layout_rect_fast.cpp
    src/hooks_subsystems/ui_layout_rect_fast.h
    src/hooks_subsystems/ui_strata_overlap_fast.cpp
    src/hooks_subsystems/ui_strata_overlap_fast.h
    src/simd_math/particle_integrate_fast.cpp
    src/simd_math/particle_integrate_fast.h
    src/simd_math/sincos_fast_sse2.cpp
    src/simd_math/sincos_fast_sse2.h
    src/hooks_subsystems/m2_batch_cmp_top.cpp
    src/hooks_subsystems/m2_batch_cmp_top.h
    src/hooks_subsystems/particle_emitter_active.cpp
    src/hooks_subsystems/particle_emitter_active.h
    src/simd_math/collision_face_clip_sse2.cpp
    src/simd_math/collision_face_clip_sse2.h
    src/simd_math/collision_poly_copy_sse2.cpp
    src/simd_math/collision_poly_copy_sse2.h
    src/simd_math/m2_sphere_ray_gather.cpp
    src/simd_math/m2_sphere_ray_gather.h
    src/simd_math/m2_sphere_ray_gather_core.h
    src/simd_math/mat3_rot_axis_sse2.cpp
    src/simd_math/mat3_rot_axis_sse2.h
    src/simd_math/m2_mesh_pick_fast.cpp
    src/simd_math/m2_mesh_pick_fast.h
    src/simd_math/m2_collision_outcode_sse2.cpp
    src/simd_math/m2_collision_outcode_sse2.h
    src/simd_math/collision_tri_test.cpp
    src/simd_math/collision_tri_test.h
    src/simd_math/collision_box_tri.cpp
    src/simd_math/collision_box_tri.h
    src/hooks_subsystems/m2_ray_hit_sort.cpp
    src/hooks_subsystems/m2_ray_hit_sort.h
    src/simd_math/terrain_point_outcode_sse2.cpp
    src/simd_math/terrain_point_outcode_sse2.h
    src/simd_math/collision_bsp_traverse_sse2.cpp
    src/simd_math/collision_bsp_traverse_sse2.h
    src/simd_math/scene_light_grid_sse2.cpp
    src/simd_math/scene_light_grid_sse2.h
    src/simd_math/collision_swept_bsp_sse2.cpp
    src/simd_math/collision_swept_bsp_sse2.h
    src/simd_math/terrain_chunk_sort_sse2.cpp
    src/simd_math/terrain_chunk_sort_sse2.h
    src/simd_math/collision_frustum_bsp_sse2.cpp
    src/simd_math/collision_frustum_bsp_sse2.h
    src/simd_math/collision_swept_tri_sse2.cpp
    src/simd_math/collision_swept_tri_sse2.h
    src/hooks_subsystems/scene_entity_collect_fast.cpp
    src/hooks_subsystems/scene_entity_collect_fast.h
    src/hooks_subsystems/m2_batch_cmp_skin.cpp
    src/hooks_subsystems/m2_batch_cmp_skin.h
    src/simd_math/collision_bsp_leaf_sse2.cpp
    src/simd_math/collision_bsp_leaf_sse2.h
    src/simd_math/collision_swept_leaf_sse2.cpp
    src/simd_math/collision_swept_leaf_sse2.h
    src/simd_math/collision_segment_bsp_sse2.cpp
    src/simd_math/collision_segment_bsp_sse2.h
    src/simd_math/collision_segment_leaf_sse2.cpp
    src/simd_math/collision_segment_leaf_sse2.h
    src/simd_math/spline_seg_length_fast.cpp
    src/simd_math/spline_seg_length_fast.h
    src/hooks_subsystems/gx_device_state_fast.cpp
    src/hooks_subsystems/gx_device_state_fast.h
    src/hooks_subsystems/ui_frame_alpha_fast.cpp
    src/hooks_subsystems/ui_frame_alpha_fast.h
    src/simd_math/doodad_cull_exterior_sse2.cpp
    src/simd_math/doodad_cull_exterior_sse2.h
    src/simd_math/terrain_chunk_alpha_fade.cpp
    src/simd_math/terrain_chunk_alpha_fade.h
    src/hooks_subsystems/ui_anchor_dependents_fast.cpp
    src/hooks_subsystems/ui_anchor_dependents_fast.h
    src/simd_math/m2_particle_emitter_matrix_fast.cpp
    src/simd_math/m2_particle_emitter_matrix_fast.h
    src/simd_math/mat44_affine_ops_fast.cpp
    src/simd_math/mat44_affine_ops_fast.h
    src/simd_math/terrain_chunk_intersect_fast.cpp
    src/simd_math/terrain_chunk_intersect_fast.h
    src/simd_math/collision_clip_verts_box_sse2.cpp
    src/simd_math/collision_clip_verts_box_sse2.h
    src/simd_math/terrain_alpha_unpack_fast.cpp
    src/simd_math/terrain_alpha_unpack_fast.h
    src/simd_math/spline_catmull_rom_fast.cpp
    src/simd_math/spline_catmull_rom_fast.h
    src/simd_math/ui_font_render_fast.cpp
    src/simd_math/ui_font_render_fast.h
    src/simd_math/script_events_fast.cpp
    src/simd_math/script_events_fast.h
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/core/server_sync_compat.cpp")
    target_sources(wow_optimize PRIVATE src/core/server_sync_compat.cpp)
    target_compile_definitions(wow_optimize PRIVATE HAVE_SERVER_SYNC_COMPAT=1)
endif()

target_link_libraries(wow_optimize PRIVATE
    minhook
    mimalloc-static
    psapi
    ws2_32
    version
    winhttp
)

target_link_options(wow_optimize PRIVATE /MAP)

# The sampling profiler resolves an address inside this DLL to the nearest
# symbol it was handed at runtime, and those are entry points with no size, so a
# sample landing in an unregistered neighbour used to be printed under the name
# above it. The linker already knows every function's address; this turns the
# map it writes into a small table the profiler reads at startup, so a profile
# names our own code exactly rather than guessing.
#
# The generator is written out at configure time rather than kept as a separate
# script, so the build stays one file. The .sym is optional at runtime: without
# it the profiler falls back to the registered entry points and says so.
set(WO_SYMGEN "${CMAKE_CURRENT_BINARY_DIR}/wo_make_sym.cmake")
file(WRITE "${WO_SYMGEN}" [=[
file(STRINGS "${MAPFILE}" lines)
set(base "")
set(out "")
foreach(line IN LISTS lines)
  if(base STREQUAL "" AND line MATCHES "Preferred load address is ([0-9a-fA-F]+)")
    set(base "${CMAKE_MATCH_1}")
  endif()
  if(NOT base STREQUAL "" AND line MATCHES "^ [0-9a-fA-F]+:[0-9a-fA-F]+ +([^ ]+) +([0-9a-fA-F]+) f")
    set(name "${CMAKE_MATCH_1}")
    set(rvabase "${CMAKE_MATCH_2}")
    math(EXPR rva "0x${rvabase} - 0x${base}" OUTPUT_FORMAT HEXADECIMAL)
    string(SUBSTRING "${name}" 0 63 name)
    string(APPEND out "${rva} ${name}
")
  endif()
endforeach()
file(WRITE "${SYMFILE}" "${out}")
]=])

add_custom_command(TARGET wow_optimize POST_BUILD
    COMMAND ${CMAKE_COMMAND}
            -DMAPFILE=$<TARGET_FILE_DIR:wow_optimize>/wow_optimize.map
            -DSYMFILE=$<TARGET_FILE_DIR:wow_optimize>/wow_optimize.sym
            -P "${WO_SYMGEN}"
    COMMENT "Writing wow_optimize.sym from the linker map"
    VERBATIM)

target_include_directories(wow_optimize PRIVATE
    ${minhook_SOURCE_DIR}/include
    ${mimalloc_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/allocators
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime_vm
    ${CMAKE_CURRENT_SOURCE_DIR}/src/simd_math
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hooks_subsystems
    ${CMAKE_CURRENT_SOURCE_DIR}/src/threading
    ${CMAKE_CURRENT_SOURCE_DIR}/src/diagnostics
)

set_target_properties(wow_optimize PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

# Stamp the commit into the banner. The version string only moves on releases,
# so several different builds all report "3.16.3" -- which makes a tester log
# impossible to match to source. The short hash identifies the build exactly.
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE WOW_OPT_GIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# The hash above is read at CONFIGURE time. Without this, an incremental build
# after a commit keeps baking in whatever hash was current when cmake last ran,
# so tester logs report a build that no longer matches the source - exactly the
# problem the hash exists to solve. Re-run configure whenever HEAD moves.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/.git/HEAD"
    "${CMAKE_CURRENT_SOURCE_DIR}/.git/logs/HEAD"
)
if(NOT WOW_OPT_GIT_HASH)
    set(WOW_OPT_GIT_HASH "unknown")
endif()

target_compile_definitions(wow_optimize PRIVATE
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
    _WINSOCK_DEPRECATED_NO_WARNINGS
    WOW_OPTIMIZE_GIT_HASH="${WOW_OPT_GIT_HASH}"
)

set_source_files_properties(src/hooks_subsystems/crt_mem_fastpath.cpp PROPERTIES
    COMPILE_FLAGS "/GS-"
)

# --- Floating point and instruction set, pinned rather than inherited ---
#
# Both of these were already what we get, and neither was written down.
#
# /fp:precise is the MSVC default, and this project now depends on it. The
# matrix multiply at 0x004C1F00 accumulates in packed double specifically to
# match what the client's x87 does at 53-bit, and a startup self-test compares
# the two over 4096 random pairs and refuses to install on any disagreement.
# /fp:fast lets the compiler reorder those additions. That would either break
# the self-test outright or, worse, pass on the machine that built it and
# differ on someone else's - which is the failure mode that has cost this
# project the most time.
#
# /arch:SSE2 has been the MSVC x86 default since Visual Studio 2012, so this
# changes nothing today. It is here so that a toolchain whose default moves
# cannot silently turn the ordinary float maths in ninety files back into x87
# while the intrinsics keep working and nothing looks wrong.
if(MSVC)
    target_compile_options(wow_optimize PRIVATE /fp:precise /arch:SSE2)
endif()

# --- LTO / PGO (opt-in; see header block) ---
if(WO_ENABLE_LTO AND MSVC)
    target_compile_options(wow_optimize PRIVATE $<$<CONFIG:Release>:/GL>)
    # So the startup banner in a log says which kind of build wrote it.
    target_compile_definitions(wow_optimize PRIVATE $<$<CONFIG:Release>:WOW_OPTIMIZE_LTO=1>)
    if(WO_PGO STREQUAL "USE")
        target_compile_definitions(wow_optimize PRIVATE $<$<CONFIG:Release>:WOW_OPTIMIZE_PGO=1>)
    endif()
    if(WO_PGO STREQUAL "GEN")
        target_link_options(wow_optimize PRIVATE $<$<CONFIG:Release>:/LTCG:PGINSTRUMENT /GENPROFILE>)
        message(STATUS "wow_optimize: LTO + PGO INSTRUMENT (play a session to emit .pgc, then reconfigure WO_PGO=USE)")
    elseif(WO_PGO STREQUAL "USE")
        target_link_options(wow_optimize PRIVATE $<$<CONFIG:Release>:/LTCG:PGOPTIMIZE /USEPROFILE>)
        message(STATUS "wow_optimize: LTO + PGO OPTIMIZE (folding in collected .pgc profile)")
    else()
        target_link_options(wow_optimize PRIVATE $<$<CONFIG:Release>:/LTCG>)
        message(STATUS "wow_optimize: LTO (/GL + /LTCG) enabled")
    endif()
endif()

# === Proxy DLL (version.dll) — auto-loader ===
add_library(version SHARED
    src/core/version_proxy.cpp
    src/core/version_exports.def
)

set_target_properties(version PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    OUTPUT_NAME "version"
)

target_compile_definitions(version PRIVATE
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

# === Loader EXE (wow_loader.exe) — works with any Wow.exe ===
add_executable(wow_loader WIN32
    src/core/wow_loader.cpp
)

set_target_properties(wow_loader PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    OUTPUT_NAME "wow_loader"
)

target_compile_definitions(wow_loader PRIVATE
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)
