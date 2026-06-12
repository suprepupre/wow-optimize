cmake_minimum_required(VERSION 3.14)
project(wow_optimize LANGUAGES C CXX)

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
    src/dllmain.cpp
    src/crt_mem_fastpath.cpp
    src/lua_optimize.cpp
    src/lua_optimize.h
    src/combatlog_optimize.cpp
    src/combatlog_optimize.h
    src/combatlog_buffer.cpp
    src/combatlog_buffer.h
    src/combatlog_mt.cpp
    src/combatlog_mt.h
    src/texture_async.cpp
    src/texture_async.h
    src/spell_prefetch.cpp
    src/spell_prefetch.h
    src/addon_dispatcher.cpp
    src/addon_dispatcher.h
    src/model_async.cpp
    src/model_async.h
    src/mpq_prefetch.cpp
    src/mpq_prefetch.h
    src/obj_vis_cache.cpp
    src/obj_vis_cache.h
    src/sound_prefetch.cpp
    src/sound_prefetch.h
    src/quest_async.cpp
    src/quest_async.h
    src/nameplate_batch.cpp
    src/nameplate_batch.h
    src/ui_cache.cpp
    src/ui_cache.h
    src/version.h
    src/api_cache.cpp
    src/api_cache.h
    src/lua_fastpath.cpp
    src/lua_fastpath.h
    src/lua_internals.cpp
    src/lua_internals.h
    src/crash_dumper.cpp
    src/frame_throttle.cpp
    src/frame_throttle.h
    src/ui_frame_batch.cpp
    src/ui_frame_batch.h
    src/lua_vm_cache.cpp
    src/lua_vm_cache.h
    src/tooltip_cache.cpp
    src/tooltip_cache.h
    src/lua_settable_cache.cpp
    src/lua_settable_cache.h
    src/regex_cache.cpp
    src/regex_cache.h
    src/trig_lut.cpp
    src/trig_lut.h
    src/data_caches.cpp
    src/data_caches.h
    src/compute_caches.cpp
    src/compute_caches.h
    src/spell_cache.cpp
    src/spell_cache.h
    src/lua_bytecode_cache.cpp
    src/lua_bytecode_cache.h
    src/addon_preload.cpp
    src/addon_preload.h
    src/strstr_fast.cpp
    src/strstr_fast.h
    src/crt_char_fast.cpp
    src/crt_char_fast.h
    src/crt_pow_sse2.cpp
    src/crt_pow_sse2.h
    src/crt_wchar_fast.cpp
    src/crt_wchar_fast.h
    src/tls_cache.cpp
    src/tls_cache.h
    src/stream_cache.cpp
    src/stream_cache.h
    src/lua_this_cache.cpp
    src/lua_this_cache.h
    src/io_cache.cpp
    src/io_cache.h
    src/lua_global_cache.cpp
    src/lua_global_cache.h
    src/hot_functions.cpp
    src/hot_functions.h
    src/fast_strncmp.cpp
    src/fast_strncmp.h
    src/crt_free_hook.cpp
    src/crt_free_hook.h
    src/aligned_alloc_cache.cpp
    src/aligned_alloc_cache.h
    src/datastore_fastpath.cpp
    src/datastore_fastpath.h
    src/string_ops_fast.cpp
    src/string_ops_fast.h
    src/lua_tonumber_cache.cpp
    src/lua_tonumber_cache.h
    src/lua_checknumber_cache.cpp
    src/lua_checknumber_cache.h
    src/lua_pushstring_cache.cpp
    src/lua_pushstring_cache.h
    src/object_accessor_cache.cpp
    src/object_accessor_cache.h
    src/format_validator_cache.cpp
    src/format_validator_cache.h
    src/heap_compactor.cpp
    src/heap_compactor.h
    src/lua_tonumber_fast.cpp
    src/lua_pushnumber_fast.cpp
    src/gettime_fast.cpp
    src/lua_pushvalue_fast.cpp
    src/render_state_dedup.cpp
    src/event_name_hash.cpp
    src/cdatastore_batch.cpp
    src/lua_tonumber_fast.h
    src/strcat_fast.cpp
    src/strcat_fast.h
    src/script_handler_cache.cpp
    src/script_handler_cache.h
    src/dbc_lookup_cache.cpp
    src/dbc_lookup_cache.h
    src/event_dispatch_cache.cpp
    src/event_dispatch_cache.h
    src/event_name_cache.cpp
    src/event_name_cache.h
    src/lua_getstr_inline.cpp
    src/lua_rawgeti_inline.cpp
    src/lua_getstr_inline.h
    src/lua_gettable_safety.cpp
    src/lua_gettable_safety.h
    src/lua_vm_engine.cpp
    src/lua_vm_engine.h
    src/lua_vm_phase3.cpp
    src/lua_vm_phase3.h
    src/lua_gettable_cache.cpp
    src/lua_gettable_cache.h
    src/saved_vars_async.cpp
    src/saved_vars_async.h
    src/texture_decode_mt.cpp
    src/texture_decode_mt.h
    src/mpq_decompress_mt.cpp
    src/mpq_decompress_mt.h
    src/spell_effect_mt.cpp
    src/spell_effect_mt.h
    src/lua_bytecode_pre_compiler.cpp
    src/lua_bytecode_pre_compiler.h
    src/anim_mt.cpp
    src/anim_mt.h
    src/hook_prefetch.cpp
    src/hook_prefetch.h
    src/hot_patch.cpp
    src/hot_patch.h
    src/infra_patch.cpp
    src/infra_patch.h
    src/wow_opt_hooks.cpp
    src/wow_opt_hooks.h
    src/wow_perf_hooks.cpp
    src/wow_perf_hooks.h
    src/wow_extended_hooks.cpp
    src/wow_extended_hooks.h
    src/wow_subsystem_hooks.cpp
    src/wow_subsystem_hooks.h
    src/wow_memory_opt.cpp
    src/wow_memory_opt.h
    src/wow_source_opt.cpp
    src/wow_source_opt.h
    src/tls_object_cache.cpp
    src/tls_object_cache.h
    src/hooks_render.cpp
    src/hooks_render.h
    src/hooks_simd.cpp
    src/hooks_simd.h
    src/hooks_logic.cpp
    src/hooks_logic.h
    src/hooks_memory.cpp
    src/hooks_memory.h
    src/hooks_async.cpp
    src/hooks_async.h
    src/d3d9_state_manager.cpp
    src/d3d9_state_manager.h
)

target_link_libraries(wow_optimize PRIVATE
    minhook
    mimalloc-static
    psapi
    ws2_32
    version
)

target_include_directories(wow_optimize PRIVATE
    ${minhook_SOURCE_DIR}/include
    ${mimalloc_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(wow_optimize PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

target_compile_definitions(wow_optimize PRIVATE
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
    _WINSOCK_DEPRECATED_NO_WARNINGS
)

# === Proxy DLL (version.dll) — auto-loader ===
add_library(version SHARED
    src/version_proxy.cpp
    src/version_exports.def
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
    src/wow_loader.cpp
)

set_target_properties(wow_loader PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    OUTPUT_NAME "wow_loader"
)

target_compile_definitions(wow_loader PRIVATE
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)