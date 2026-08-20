cmake_minimum_required(VERSION 3.14)
project(wow_optimize LANGUAGES C CXX)

# Force static CRT globally for all targets and dependencies (mimalloc, minhook, etc.)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")


# ============================================================================
# Whole-program / link-time optimization (LTO) for the DLL.
#   -DWO_ENABLE_LTO=ON  ->  /GL (whole-program) + /LTCG (link-time codegen)
# Default OFF: LTO re-generates code across the whole DLL and can shift the
# exact codegen we are currently stabilizing crashes against. Turn it on only
# after the build is confirmed stable in-game. Marginal win on a ~340KB DLL
# next to wow.exe (which we cannot recompile), but free once stable.
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
FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(minhook)

# mimalloc — Microsoft's high-performance allocator
FetchContent_Declare(
    mimalloc
    GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
    GIT_TAG        v3.3.2
)
set(MI_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(MI_BUILD_TESTS  OFF CACHE BOOL "" FORCE)
set(MI_OVERRIDE     OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(mimalloc)

# === Main optimization DLL ===
add_library(wow_optimize SHARED
    src/core/dllmain.cpp
    src/core/config.cpp
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
    src/hooks_subsystems/mpq_async_decompress.cpp
    src/hooks_subsystems/mpq_async_decompress.h
    src/hooks_subsystems/obj_vis_cache.cpp
    src/hooks_subsystems/obj_vis_cache.h
    src/hooks_subsystems/rcu_obj_mgr.cpp
    src/hooks_subsystems/rcu_obj_mgr.h
    src/hooks_subsystems/async_terrain_loader.cpp
    src/hooks_subsystems/async_terrain_loader.h
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
    src/diagnostics/net_diag.cpp
    src/diagnostics/net_diag.h
    src/diagnostics/addon_profiler.cpp
    src/diagnostics/addon_profiler.h
    src/diagnostics/lua_compile_census.cpp
    src/diagnostics/lua_compile_census.h
    src/diagnostics/shadow_state_probe.cpp
    src/diagnostics/shadow_state_probe.h
    src/hooks_subsystems/strncmp_sse2.cpp
    src/hooks_subsystems/strncmp_sse2.h
    src/diagnostics/anim_census.cpp
    src/diagnostics/anim_census.h
    src/diagnostics/crash_dumper.cpp
    src/hooks_subsystems/vertex_fmt_inline.cpp
    src/hooks_subsystems/objmgr_find_fast.cpp
    src/hooks_subsystems/anim_lod.cpp
    src/simd_math/collision_outcode_sse2.cpp
    src/runtime_vm/lua_proto_cache.cpp
    src/simd_math/quat_lerp_sse2.cpp
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
    src/runtime_vm/lua_gc_governor.h
    src/hooks_subsystems/sound_mixer_opt.cpp
    src/hooks_subsystems/sound_mixer_opt.h
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
    src/hooks_subsystems/event_name_cache.cpp
    src/hooks_subsystems/event_name_cache.h
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
    src/hooks_subsystems/hot_patch.cpp
    src/hooks_subsystems/hot_patch.h
    src/hooks_subsystems/wow_opt_hooks.cpp
    src/hooks_subsystems/wow_opt_hooks.h
    src/hooks_subsystems/wow_perf_hooks.cpp
    src/hooks_subsystems/wow_perf_hooks.h
    src/hooks_subsystems/wow_extended_hooks.cpp
    src/hooks_subsystems/wow_extended_hooks.h
    src/hooks_subsystems/wow_subsystem_hooks.cpp
    src/hooks_subsystems/wow_subsystem_hooks.h
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
    src/hooks_subsystems/event_coalescer.cpp
    src/hooks_subsystems/event_coalescer.h
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
    src/hooks_subsystems/sound_update_guard.cpp

    src/diagnostics/sampling_profiler.h
    src/hooks_subsystems/sound_driver_guard.h
    src/hooks_subsystems/sound_emitter_guard.h
    src/hooks_subsystems/sound_buffer_guard.h
    src/hooks_subsystems/sound_update_guard.h

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
    src/hooks_subsystems/spell_effect_culling.cpp
    src/hooks_subsystems/spell_effect_culling.h
)

target_link_libraries(wow_optimize PRIVATE
    minhook
    mimalloc-static
    psapi
    ws2_32
    version
    winhttp
)

target_link_options(wow_optimize PRIVATE /MAP)

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