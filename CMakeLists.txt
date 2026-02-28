cmake_minimum_required(VERSION 3.14)
project(wow_optimize LANGUAGES C CXX)

include(FetchContent)

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
    GIT_TAG        v3.2.8
)
set(MI_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(MI_BUILD_TESTS  OFF CACHE BOOL "" FORCE)
set(MI_OVERRIDE     OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(mimalloc)

# Build our DLL
add_library(wow_optimize SHARED src/dllmain.cpp)

target_link_libraries(wow_optimize PRIVATE
    minhook
    mimalloc-static
    psapi
    ws2_32
)

target_include_directories(wow_optimize PRIVATE
    ${minhook_SOURCE_DIR}/include
    ${mimalloc_SOURCE_DIR}/include
)

# Static CRT linkage — no external runtime DLL dependencies
set_target_properties(wow_optimize PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

target_compile_definitions(wow_optimize PRIVATE
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
    _WINSOCK_DEPRECATED_NO_WARNINGS
)