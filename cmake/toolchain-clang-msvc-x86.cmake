# Cross-compile toolchain: macOS host -> i686 Windows MSVC ABI.
# Uses Homebrew LLVM (clang-cl) + Homebrew LLD (lld-link) + xwin-splatted
# Windows SDK / MSVC CRT.
#
# Setup:
#   brew install llvm lld cmake ninja
#   xwin splat --output /opt/xwin     # one-time, supplies SDK + CRT
#
# Usage:
#   cmake -S . -B build-xwin -G Ninja \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-clang-msvc-x86.cmake \
#         -DCMAKE_BUILD_TYPE=Release
#   cmake --build build-xwin
#
# Override -DLLVM_DIR=..., -DLLD_DIR=..., or -DXWIN=... to change paths.

set(CMAKE_SYSTEM_NAME      Windows)
set(CMAKE_SYSTEM_PROCESSOR x86)

if(NOT DEFINED LLVM_DIR)
    set(LLVM_DIR "/opt/homebrew/opt/llvm/bin")
endif()
if(NOT DEFINED LLD_DIR)
    set(LLD_DIR  "/opt/homebrew/opt/lld/bin")
endif()
if(NOT DEFINED XWIN)
    set(XWIN     "/opt/xwin")
endif()

set(CMAKE_C_COMPILER          "${LLVM_DIR}/clang-cl")
set(CMAKE_CXX_COMPILER        "${LLVM_DIR}/clang-cl")
set(CMAKE_C_COMPILER_TARGET   i686-pc-windows-msvc)
set(CMAKE_CXX_COMPILER_TARGET i686-pc-windows-msvc)

set(CMAKE_LINKER      "${LLD_DIR}/lld-link")
set(CMAKE_AR          "${LLVM_DIR}/llvm-lib")
set(CMAKE_RC_COMPILER "${LLVM_DIR}/llvm-rc")
set(CMAKE_MT          "${LLVM_DIR}/llvm-mt")

# Skip the link-step probe — it would try to link a test program before our
# library paths are in place.
set(CMAKE_C_COMPILER_WORKS   1)
set(CMAKE_CXX_COMPILER_WORKS 1)

# xwin sysroot includes
set(_xwin_includes
    "/imsvc${XWIN}/crt/include"
    "/imsvc${XWIN}/sdk/include/ucrt"
    "/imsvc${XWIN}/sdk/include/um"
    "/imsvc${XWIN}/sdk/include/shared"
)
string(JOIN " " _xwin_includes_str ${_xwin_includes})

set(_common_flags "${_xwin_includes_str} -m32")
set(CMAKE_C_FLAGS_INIT   "${_common_flags}")
set(CMAKE_CXX_FLAGS_INIT "${_common_flags}")

# Match the Release-config flags that MSVC's VS generator sets but the
# cross-build path doesn't pick up:
#   /Gy  -> per-function COMDAT (so /OPT:REF /OPT:ICF can drop/fold)
#   /GR- -> no RTTI; codebase doesn't use it
#   /EHs-c- (C++ only) -> no C++ EH; codebase uses SEH (__try/__except) only
# Notably NOT /Gw: clang-cl's per-data COMDAT tags zero-init globals as
# IMAGE_SCN_CNT_INITIALIZED_DATA, which lld-link writes to disk as zero
# bytes instead of merging into BSS. That alone bloats the cross-built DLL
# by ~850 KB on this codebase (g_queue, g_inputQueue, g_outputQueue, ...).
# Notably NOT /GL: it's the MSVC whole-program-optimisation request, which
# clang-cl simply ignores ("argument unused during compilation"). The right
# clang-cl spelling would be -flto / -flto=thin, paired with bitcode-aware
# linking. Wiring real LTO across xwin + lld-link is a separate piece of
# work; for now we ship without it rather than emit a warning every build.
set(CMAKE_C_FLAGS_RELEASE_INIT   "/O2 /DNDEBUG /Gy /GR-")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "/O2 /DNDEBUG /Gy /GR- /EHs-c-")

# xwin sysroot lib paths (x86 / Win32)
set(_xwin_libpaths
    "/libpath:${XWIN}/crt/lib/x86"
    "/libpath:${XWIN}/sdk/lib/ucrt/x86"
    "/libpath:${XWIN}/sdk/lib/um/x86"
)
string(JOIN " " _xwin_libpaths_str ${_xwin_libpaths})

set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_xwin_libpaths_str}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_xwin_libpaths_str}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_xwin_libpaths_str}")

# Release-only linker tightening — match MSVC link.exe's Release defaults:
#   /OPT:REF -> drop unreferenced functions/data
#   /OPT:ICF -> fold identical COMDATs (needs /Gy /Gw above to be useful)
# /LTCG is intentionally absent: it pairs with /GL (whole-program opt) which
# clang-cl ignores in this cross-build, so /LTCG would just be a no-op
# decoration on the link line. Add both back together if real LTO ever lands.
set(_release_link_flags "/OPT:REF /OPT:ICF")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE_INIT    "${_release_link_flags}")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE_INIT "${_release_link_flags}")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE_INIT "${_release_link_flags}")

# Don't let CMake pick up host (macOS) libraries / packages.
set(CMAKE_FIND_ROOT_PATH "${XWIN}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
