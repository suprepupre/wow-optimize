# Cross-compile wow_optimize on macOS -> Win32 (i686) MSVC ABI.
#
# One-time setup:
#   brew install llvm lld cmake ninja
#   xwin splat --output /opt/xwin
#
# Usage:
#   make           # configure (if needed) + build
#   make configure # (re)run cmake configure
#   make verify    # show PE headers of built artifacts
#   make clean     # delete build dir
#   make rebuild   # clean + build

BUILD_DIR  ?= build
TOOLCHAIN  := cmake/toolchain-clang-msvc-x86.cmake
BUILD_TYPE ?= Release

LLVM_DIR ?= /opt/homebrew/opt/llvm/bin
LLD_DIR  ?= /opt/homebrew/opt/lld/bin
XWIN     ?= /opt/xwin

ARTIFACTS := $(BUILD_DIR)/wow_optimize.dll \
             $(BUILD_DIR)/version.dll \
             $(BUILD_DIR)/wow_loader.exe

.PHONY: all configure build verify clean rebuild check-deps

all: build

check-deps:
	@command -v cmake >/dev/null || { echo "cmake not found — brew install cmake"; exit 1; }
	@command -v ninja >/dev/null || { echo "ninja not found — brew install ninja"; exit 1; }
	@test -x $(LLVM_DIR)/clang-cl   || { echo "clang-cl not found at $(LLVM_DIR) — brew install llvm"; exit 1; }
	@test -x $(LLD_DIR)/lld-link    || { echo "lld-link not found at $(LLD_DIR) — brew install lld"; exit 1; }
	@test -d $(XWIN)/sdk/lib/um/x86 || { echo "Windows SDK not found at $(XWIN) — run: xwin splat --output $(XWIN)"; exit 1; }

$(BUILD_DIR)/build.ninja: $(TOOLCHAIN) CMakeLists.txt | check-deps
	cmake -S . -B $(BUILD_DIR) -G Ninja \
		-DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN) \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DLLVM_DIR=$(LLVM_DIR) \
		-DLLD_DIR=$(LLD_DIR) \
		-DXWIN=$(XWIN)

configure: $(BUILD_DIR)/build.ninja

build: $(BUILD_DIR)/build.ninja
	cmake --build $(BUILD_DIR)
	@echo
	@echo "Built:"
	@ls -lh $(ARTIFACTS) 2>/dev/null | awk '{printf "  %-40s %s\n", $$NF, $$5}'

verify: build
	@for f in $(ARTIFACTS); do \
		echo "=== $$f ==="; \
		$(LLVM_DIR)/llvm-readobj --file-headers $$f \
			| grep -E "Machine|Subsystem|FILE_DLL|FILE_EXECUTABLE_IMAGE"; \
	done

clean:
	rm -rf $(BUILD_DIR)

rebuild: clean build
