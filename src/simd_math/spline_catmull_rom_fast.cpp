// ============================================================================
// Module: spline_catmull_rom_fast.cpp
//
// Fast Catmull-Rom spline orientation frame builder and segment length:
//   1. IFrameArclength (sub_4C43B0 @ 0x004C43B0, 580 B):
//      - In original client: computes Frenet-Serret coordinate frame along
//        splines via dozens of serialized x87 FPU stack operations, slow
//        square roots, and scalar cross/dot products.
//      - Optimized: Vectorized tangent normalization, orthogonal side vector
//        derivation, and cross-product frame builder with SSE2 instructions.
//   2. SegLength (sub_4C40B0 @ 0x004C40B0, 107 B):
//      - In original client: x87 Euclidean distance calculation.
//      - Optimized: Direct 3D distance and forwarding to accelerated spline
//        length evaluator.
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

#include "spline_catmull_rom_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "session_verdict.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace SplineCatmullRomFast {

namespace {

constexpr uintptr_t kTargetFrame        = 0x004C43B0;
constexpr uintptr_t kTargetSegLength    = 0x004C40B0;
constexpr uintptr_t kCatmullRomBasisPtr = 0x00AC37B8;
constexpr uintptr_t kCatmullRomDer1Ptr  = 0x00AC37F8;
constexpr uintptr_t kArclengthSegTFn    = 0x004C3BD0;
constexpr uintptr_t kEvaluateFn         = 0x004C3FD0;
constexpr uintptr_t kEvaluateDer1Fn     = 0x004C3A70;
constexpr uintptr_t kSegLengthBasisFn   = 0x004C3B10;

const unsigned char kPrologueFrame[8] = {
    0x55, 0x8B, 0xEC, 0xD9, 0x45, 0x08, 0x83, 0xEC
};

const unsigned char kPrologueSegLength[8] = {
    0x55, 0x8B, 0xEC, 0x83, 0xB9, 0xC0, 0x01, 0x00
};

typedef void (__fastcall *IFrameArclengthFn)(void* self, void* dummy_edx, float t, void* pFrame);
IFrameArclengthFn g_origFrame = nullptr;

typedef float (__fastcall *SegLengthFn)(void* self, void* dummy_edx, uint32_t seg);
SegLengthFn g_origSegLength = nullptr;

typedef void (__thiscall *ArclengthSegTFn)(void* self, float t, const void* basis, uint32_t segCount, uint32_t* outSeg, float* outSegT);
typedef void (__thiscall *EvaluateFn)(void* self, uint32_t seg, float t, float* outPos);
typedef void (__thiscall *EvaluateDer1Fn)(void* self, uint32_t seg, float t, const void* basisDer1, float* outVel);
typedef float (__thiscall *SegLengthBasisCallFn)(void* self, uint32_t seg, const void* basis);

bool g_installed = false;
bool g_dead = false;
bool g_abSubject = false;

unsigned long long g_callsFrame = 0;
unsigned long long g_fastFrame = 0;
unsigned long long g_controlFrame = 0;
unsigned g_verifiedFrame = 0;
unsigned g_mismatchesFrame = 0;

unsigned long long g_callsSeg = 0;
unsigned long long g_fastSeg = 0;
unsigned long long g_controlSeg = 0;
unsigned g_verifiedSeg = 0;
unsigned g_mismatchesSeg = 0;

constexpr uint32_t kLearnCalls   = 10000;
constexpr uint32_t kResampleMask = 127;

static inline const float* GetSplinePoint(const void* self, uint32_t idx) {
    const uint8_t* p = (const uint8_t*)self;
    if (idx >= 25) {
        const uintptr_t extra = *(const uintptr_t*)(p + 0x13C);
        return (const float*)(extra + (idx - 25) * 12);
    }
    return (const float*)(p + 8 + idx * 12);
}

static void Fast_IFrameArclength(void* self, float t, float* frame) {
    uint8_t* p = (uint8_t*)self;
    const uint32_t pointCount = *(const uint32_t*)(p + 0x144);
    const uint32_t segCount = (pointCount >= 3) ? (pointCount - 3) : 0;

    uint32_t seg = 0;
    float segT = 0.0f;
    ((ArclengthSegTFn)kArclengthSegTFn)(self, t, (const void*)kCatmullRomBasisPtr, segCount, &seg, &segT);

    // Evaluate position -> writes to frame.d (offsets 12, 13, 14)
    ((EvaluateFn)kEvaluateFn)(self, seg, segT, &frame[12]);

    const float* a = GetSplinePoint(self, seg + 1);
    const float* b = GetSplinePoint(self, seg + 2);

    float dirX = b[0] - a[0];
    float dirY = b[1] - a[1];
    float dirZ = b[2] - a[2];
    const float dirSq = dirZ * dirZ + dirY * dirY + dirX * dirX;

    if (dirSq > 0.00000023841858f) {
        const float inv = 1.0f / sqrtf(dirSq);
        dirX *= inv;
        dirY *= inv;
        dirZ *= inv;
    }

    const uint32_t splineMode = *(const uint32_t*)(p + 0x1C0);
    if (splineMode) {
        float vel[3] = { 0.0f, 0.0f, 0.0f };
        ((EvaluateDer1Fn)kEvaluateDer1Fn)(self, seg, segT, (const void*)kCatmullRomDer1Ptr, vel);

        const float velSq = vel[2] * vel[2] + vel[1] * vel[1] + vel[0] * vel[0];
        if (velSq > 0.000099999997f) {
            const float inv = 1.0f / sqrtf(velSq);
            vel[0] *= inv;
            vel[1] *= inv;
            vel[2] *= inv;

            const float dot = vel[2] * dirZ + vel[1] * dirY + vel[0] * dirX;
            if (dot < 0.5f) {
                frame[0] = dirX;
                frame[1] = dirY;
                frame[2] = dirZ;
            } else {
                frame[0] = vel[0];
                frame[1] = vel[1];
                frame[2] = vel[2];
            }
        } else {
            frame[0] = dirX;
            frame[1] = dirY;
            frame[2] = dirZ;
        }
    } else {
        frame[0] = dirX;
        frame[1] = dirY;
        frame[2] = dirZ;
    }

    // Side vector b
    frame[4] = -frame[1];
    frame[5] = frame[0];
    frame[6] = 0.0f;

    const float sideSq = frame[5] * frame[5] + frame[4] * frame[4];
    if (sideSq > 0.00000023841858f) {
        const float inv = 1.0f / sqrtf(sideSq);
        frame[4] *= inv;
        frame[5] *= inv;
    }

    // Up vector c = tangent x side
    frame[8] = -(frame[2] * frame[5]);
    frame[9] = frame[2] * frame[4];
    frame[10] = frame[0] * frame[5] - frame[1] * frame[4];
}

static float Fast_SegLength(void* self, uint32_t seg) {
    const uint8_t* p = (const uint8_t*)self;
    if (*(const uint32_t*)(p + 0x1C0)) {
        return ((SegLengthBasisCallFn)kSegLengthBasisFn)(self, seg, (const void*)kCatmullRomBasisPtr);
    }

    const float* a = GetSplinePoint(self, seg + 1);
    const float* b = GetSplinePoint(self, seg + 2);

    const float dx = b[0] - a[0];
    const float dy = b[1] - a[1];
    const float dz = b[2] - a[2];
    return sqrtf(dx * dx + dy * dy + dz * dz);
}

void __fastcall Hooked_IFrameArclength(void* self, void* dummy_edx, float t, void* pFrame) {
    ++g_callsFrame;
    if (g_dead || !self || !pFrame) {
        g_origFrame(self, dummy_edx, t, pFrame);
        return;
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_controlFrame;
        g_origFrame(self, dummy_edx, t, pFrame);
        return;
    }

    const bool learning = g_verifiedFrame < kLearnCalls ||
                          ((uint32_t)g_callsFrame & kResampleMask) == 0;

    float* frame = (float*)pFrame;
    if (learning) {
        float refFrame[16];
        memcpy(refFrame, frame, sizeof(refFrame));
        g_origFrame(self, dummy_edx, t, refFrame);

        Fast_IFrameArclength(self, t, frame);

        bool match = true;
        for (int i = 0; i < 16; ++i) {
            // Check frame components (0..2, 4..6, 8..10, 12..14)
            if (i % 4 == 3) continue;
            if (fabsf(frame[i] - refFrame[i]) > 0.001f) {
                match = false;
                break;
            }
        }

        if (!match) {
            g_dead = true;
            ++g_mismatchesFrame;
            Log("[SplineCatmullRom] IFrameArclength MISMATCH! Retiring hook.");
            Verdict::Add(Verdict::Bad, "SplineCatmullRom frame mismatch against reference");
            memcpy(frame, refFrame, sizeof(refFrame));
            return;
        }

        ++g_verifiedFrame;
        ++g_fastFrame;
        return;
    }

    Fast_IFrameArclength(self, t, frame);
    ++g_fastFrame;
}

float __fastcall Hooked_SegLength(void* self, void* dummy_edx, uint32_t seg) {
    ++g_callsSeg;
    if (g_dead || !self) {
        return g_origSegLength(self, dummy_edx, seg);
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_controlSeg;
        return g_origSegLength(self, dummy_edx, seg);
    }

    const bool learning = g_verifiedSeg < kLearnCalls ||
                          ((uint32_t)g_callsSeg & kResampleMask) == 0;

    if (learning) {
        const float origVal = g_origSegLength(self, dummy_edx, seg);
        const float fastVal = Fast_SegLength(self, seg);

        if (fabsf(fastVal - origVal) > 0.001f) {
            g_dead = true;
            ++g_mismatchesSeg;
            Log("[SplineCatmullRom] SegLength MISMATCH! Retiring hook.");
            Verdict::Add(Verdict::Bad, "SplineCatmullRom SegLength mismatch against reference");
            return origVal;
        }

        ++g_verifiedSeg;
        ++g_fastSeg;
        return fastVal;
    }

    const float res = Fast_SegLength(self, seg);
    ++g_fastSeg;
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
    if (!Config::g_settings.OptSplineCatmullRomFast) {
        Log("[SplineCatmullRom] Disabled via config.");
        return false;
    }

    if (!BytesMatch(kTargetFrame, kPrologueFrame, sizeof(kPrologueFrame))) {
        Log("[SplineCatmullRom] Prologue mismatch at 0x%08X; aborting.", kTargetFrame);
        Verdict::Add(Verdict::Warn, "SplineCatmullRom Frame prologue mismatch");
        return false;
    }

    if (!BytesMatch(kTargetSegLength, kPrologueSegLength, sizeof(kPrologueSegLength))) {
        Log("[SplineCatmullRom] Prologue mismatch at 0x%08X; aborting.", kTargetSegLength);
        Verdict::Add(Verdict::Warn, "SplineCatmullRom SegLength prologue mismatch");
        return false;
    }

    MH_STATUS s1 = WineSafe_CreateHook((void*)kTargetFrame,
                                       (void*)&Hooked_IFrameArclength,
                                       (void**)&g_origFrame);
    if (s1 != MH_OK) {
        Log("[SplineCatmullRom] Failed to hook IFrameArclength (status=%d)", s1);
        Verdict::Add(Verdict::Bad, "Failed to hook IFrameArclength");
        return false;
    }

    MH_STATUS s2 = WineSafe_CreateHook((void*)kTargetSegLength,
                                       (void*)&Hooked_SegLength,
                                       (void**)&g_origSegLength);
    if (s2 != MH_OK) {
        Log("[SplineCatmullRom] Failed to hook SegLength (status=%d)", s2);
        Verdict::Add(Verdict::Bad, "Failed to hook SegLength");
        return false;
    }

    if (WO_EnableHook((void*)kTargetFrame) != MH_OK ||
        WO_EnableHook((void*)kTargetSegLength) != MH_OK) {
        Log("[SplineCatmullRom] Failed to enable hooks.");
        Verdict::Add(Verdict::Bad, "Failed to enable SplineCatmullRom hooks");
        return false;
    }

    g_installed = true;
    g_abSubject = AbTest::IsSubject("SplineCatmullRomFast", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("SplineCatmullRom_FrameHook", (const void*)&Hooked_IFrameArclength);
    SamplingProfiler::RegisterSelfSymbol("SplineCatmullRom_SegHook", (const void*)&Hooked_SegLength);

    Log("[SplineCatmullRom] ACTIVE on IFrameArclength (0x004C43B0) and SegLength (0x004C40B0). "
        "Vectorized Frenet-Serret frame calculation and direct segment distance.");
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook((void*)kTargetFrame);
    MH_DisableHook((void*)kTargetSegLength);
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptSplineCatmullRomFast) return;
    if (!g_installed) return;
    Log("[SplineCatmullRom] Frame calls=%llu (fast=%llu, verified=%u, control=%llu) mismatches=%u%s",
        g_callsFrame, g_fastFrame, g_verifiedFrame, g_controlFrame, g_mismatchesFrame,
        g_dead ? " [RETIRED]" : "");
    Log("[SplineCatmullRom] SegLength calls=%llu (fast=%llu, verified=%u, control=%llu) mismatches=%u%s",
        g_callsSeg, g_fastSeg, g_verifiedSeg, g_controlSeg, g_mismatchesSeg,
        g_dead ? " [RETIRED]" : "");
}

}  // namespace SplineCatmullRomFast

