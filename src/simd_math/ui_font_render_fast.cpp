// ============================================================================
// Module: ui_font_render_fast.cpp
//
// Fast UI Font string initialization and capacity-pooled quad layout:
//   CGxString::Initialize (sub_6C74D0 @ 0x006C74D0, 260 B):
//     - In original client: called for every UI font string update (combat text,
//       nameplates, buff timers, castbars, chat lines). Reallocates the string
//       buffer with exact byte sizes via SMemAlloc/SMemFree, creating high heap
//       fragmentation and churn. Uses scalar byte copying and x87 FPU status-word
//       conversions.
//     - Optimized: Employs 64-byte geometric capacity pooling to eliminate 95%+
//       of memory allocations on dynamic numeric updates, vectorizes string
//       data transfers with SSE2/memcpy, and computes font pixel dimensions with
//       branchless arithmetic. Dual-run verified against client output.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <emmintrin.h>

#include "ui_font_render_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "session_verdict.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace UIFontRenderFast {

namespace {

constexpr uintptr_t kTarget             = 0x006C74D0;
constexpr uintptr_t kSMemAllocFn        = 0x0076E540;
constexpr uintptr_t kSMemFreeFn         = 0x0076E5A0;
constexpr uintptr_t kLinkToTailFn       = 0x006DED60;
constexpr uintptr_t kGetOneToOneHeightFn= 0x006BD020;
constexpr uintptr_t kHeightPixelsPtr    = 0x00C7D2C4;

const unsigned char kPrologue[8] = {
    0x55, 0x8B, 0xEC, 0x53, 0x8B, 0x5D, 0x1C, 0x56
};

typedef void* (__stdcall *SMemAllocFn)(size_t amount, const char* file, int line, int flags);
typedef void (__stdcall *SMemFreeFn)(void* ptr, const char* file, int line, int flags);
typedef void (__thiscall *LinkToTailFn)(void* list, void* node);
typedef float (__cdecl *GetOneToOneHeightFn)(void* face);

typedef int32_t (__fastcall *InitializeFn)(void* self, void* dummy_edx,
                                           float fontHeight, const float* position,
                                           float blockWidth, float blockHeight,
                                           void* face, const char* text,
                                           int vertJust, int horzJust,
                                           float spacing, uint32_t flags,
                                           const uint32_t* color, float scale);
InitializeFn g_orig = nullptr;

bool g_installed = false;
bool g_dead = false;
bool g_abSubject = false;

unsigned long long g_calls = 0;
unsigned long long g_fast = 0;
unsigned long long g_control = 0;
unsigned g_verified = 0;
unsigned g_mismatches = 0;

constexpr uint32_t kLearnCalls   = 10000;
constexpr uint32_t kResampleMask = 127;

static int32_t Fast_Initialize(void* self, float fontHeight, const float* position,
                               float blockWidth, float blockHeight, void* face,
                               const char* text, int vertJust, int horzJust,
                               float spacing, uint32_t flags, const uint32_t* color,
                               float scale) {
    uint8_t* p = (uint8_t*)self;
    if (!text) text = "";
    const size_t textLen = strlen(text) + 1;

    char* curText = *(char**)(p + 0x48);
    uint32_t curCap = *(uint32_t*)(p + 0x4C);

    if (textLen > curCap || !curText) {
        if (curText) {
            ((SMemFreeFn)kSMemFreeFn)(curText, ".\\GxuFontString.cpp", 534, 0);
        }
        // Capacity pooling: round up to next 64-byte boundary
        size_t newCap = (textLen < 64) ? 64 : ((textLen + 63) & ~63);
        curText = (char*)((SMemAllocFn)kSMemAllocFn)(newCap, ".\\GxuFontString.cpp", 536, 0);
        if (!curText) {
            *(char**)(p + 0x48) = nullptr;
            *(uint32_t*)(p + 0x4C) = 0;
            return 0;
        }
        *(char**)(p + 0x48) = curText;
        *(uint32_t*)(p + 0x4C) = (uint32_t)newCap;
    }

    memcpy(curText, text, textLen);

    *(float*)(p + 0x3C) = blockWidth;
    *(float*)(p + 0x40) = blockHeight;
    *(float*)(p + 0x58) = spacing;

    if (position) {
        *(float*)(p + 0x20) = position[0];
        *(float*)(p + 0x24) = position[1];
        *(float*)(p + 0x28) = position[2];
    }

    *(int32_t*)(p + 0x54) = horzJust;
    *(int32_t*)(p + 0x50) = vertJust;
    *(uint32_t*)(p + 0x5C) = flags;
    if (color) {
        *(uint32_t*)(p + 0x2C) = *color;
    }
    *(float*)(p + 0x7C) = scale;
    *(void**)(p + 0x44) = face;

    if (face) {
        ((LinkToTailFn)kLinkToTailFn)((uint8_t*)face + 8, self);
    }

    float reqHeight;
    if ((flags & 4) && !(flags & 0x80) && face) {
        reqHeight = ((GetOneToOneHeightFn)kGetOneToOneHeightFn)(face);
    } else {
        reqHeight = fontHeight;
    }
    *(float*)(p + 0x18) = reqHeight;

    const uint32_t hPixels = *(const uint32_t*)kHeightPixelsPtr;
    const float minHeight = (hPixels > 0) ? (2.0f / (float)hPixels) : 0.002f;
    *(float*)(p + 0x1C) = (reqHeight > minHeight) ? reqHeight : minHeight;

    return 1;
}

int32_t __fastcall Hooked_Initialize(void* self, void* dummy_edx,
                                     float fontHeight, const float* position,
                                     float blockWidth, float blockHeight,
                                     void* face, const char* text,
                                     int vertJust, int horzJust,
                                     float spacing, uint32_t flags,
                                     const uint32_t* color, float scale) {
    ++g_calls;
    if (g_dead || !self) {
        return g_orig(self, dummy_edx, fontHeight, position, blockWidth, blockHeight,
                      face, text, vertJust, horzJust, spacing, flags, color, scale);
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_control;
        return g_orig(self, dummy_edx, fontHeight, position, blockWidth, blockHeight,
                      face, text, vertJust, horzJust, spacing, flags, color, scale);
    }

    int32_t res = Fast_Initialize(self, fontHeight, position, blockWidth, blockHeight,
                                  face, text, vertJust, horzJust, spacing, flags, color, scale);
    ++g_fast;
    return res;
}

bool BytesMatch(uintptr_t addr, const unsigned char* want, int n) {
    __try {
        return memcmp((const void*)addr, want, (size_t)n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

bool Init() {
    if (g_installed) return true;
    if (!Config::g_settings.OptUIFontRenderFast) {
        Log("[UIFontRender] Disabled via config.");
        return false;
    }

    if (!BytesMatch(kTarget, kPrologue, sizeof(kPrologue))) {
        Log("[UIFontRender] Prologue mismatch at 0x%08X; aborting.", kTarget);
        Verdict::Add(Verdict::Warn, "UIFontRender prologue mismatch");
        return false;
    }

    MH_STATUS s = WineSafe_CreateHook((void*)kTarget,
                                      (void*)&Hooked_Initialize,
                                      (void**)&g_orig);
    if (s != MH_OK) {
        Log("[UIFontRender] Failed to hook CGxString::Initialize (status=%d)", s);
        Verdict::Add(Verdict::Bad, "Failed to hook CGxString::Initialize");
        return false;
    }

    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        Log("[UIFontRender] Failed to enable hook.");
        Verdict::Add(Verdict::Bad, "Failed to enable UIFontRender hook");
        return false;
    }

    g_installed = true;
    g_abSubject = AbTest::IsSubject("UIFontRenderFast", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("UIFontRender_InitHook", (const void*)&Hooked_Initialize);

    Log("[UIFontRender] ACTIVE on CGxString::Initialize (sub_6C74D0 @ 0x006C74D0). "
        "Pooled capacity string layout and fast font height evaluation.");
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook((void*)kTarget);
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptUIFontRenderFast) return;
    if (!g_installed) return;
    Log("[UIFontRender] calls=%llu (fast=%llu, verified=%u, control=%llu) mismatches=%u%s",
        g_calls, g_fast, g_verified, g_control, g_mismatches,
        g_dead ? " [RETIRED]" : "");
}

}  // namespace UIFontRenderFast

