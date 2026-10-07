// ============================================================================
// Module: color_unpack_sse2
//
// Hardware SSE2 color packing/unpacking and vector math optimizations:
//   sub_984C90: Color_UnpackBGRA  (32-bit BGRA bytes -> 4x float RGBA in [0, 1])
//   sub_982970: Color_UnpackBGR   (24-bit BGR bytes  -> 3x float RGB  in [0, 1])
//   sub_48BD20: Color_PackBGRA    (4x float ARGB     -> 32-bit BGRA uint32)
//   sub_9851A0: Color_PackBGR     (3x float RGB      -> 32-bit BGRA uint32, A=0xFF)
//   sub_9829B0: Vec3_DominantAxis (C3Vector dominant axis index 0, 1, 2)
//   sub_9829F0: Vec3_RecessiveAxis (C3Vector recessive axis index 0, 1, 2)
//
// Background & Analysis:
//   sub_984C90 is invoked across 12 callers in the rendering and material pipeline
//   (vertex lighting setup, particle emitter initialization, water/sky rendering,
//   M2 model lighting, and WMO material passes). In stock x87, it spills each of
//   the 4 bytes to stack memory, then executes integer load fild, fmul ds:flt_A45564
//   (1.0f / 255.0f), and fstp dword ptr four times in a row.
//
//   sub_982970 is invoked across 6 callers in character model rendering and
//   lighting, performing the same stack spill and fild/fmul/fstp pattern for 3 channels.
//
//   sub_48BD20 is invoked across 21 callers (UI color conversion, particle systems,
//   lighting). It multiplies 4 float components by 255.0f, adds 0.5f, and performs
//   8 pipeline-stalling fldcw instructions (toggling truncation mode 0x0C00 twice
//   per component) with fistp integer stores.
//
//   sub_9851A0 is invoked across 7 callers (lighting and character vertex shading).
//   It multiplies 3 float components by 255.0f and converts using fistp with round
//   to nearest even, forcing alpha to 0xFF.
//
//   sub_9829B0 and sub_9829F0 are invoked in collision clipping, polygon projection,
//   bounding calculations, and HSV color conversions. They load 3 floats to the x87
//   stack, compute fabs, and evaluate conditional branches with status word transfers
//   (fnstsw ax / test ah, 41h / test ah, 5), suffering branch mispredictions.
//
//   This module vectorizes color packing and unpacking using parallel integer
//   unpack/pack and SSE2 cvtdq2ps/cvtps2dq/mulps in a single pipeline without stack
//   spills or control word modifications. Vec3 coordinate extrema evaluate branchlessly
//   using bitwise IEEE fabs.
//
//   Read against the disassembly on 2026-09-28, which found four differences
//   the startup self-tests never reached:
//   - sub_48BD20 forms x * 255 + 0.5 in x87 at 53-bit precision and truncates.
//     Packed single rounded x * 255 first: x = 0.5 / 255 gave 1 where the
//     client gives 0 (12 floats in a million uniform in [0, 1]). Now packed
//     double.
//   - Both pack routines keep the low byte of the integer (movzx byte); the
//     SSE version saturated, so any channel outside [0, 1] differed (1.01 is
//     2 in the client, was 255 here).
//   - sub_9829B0 and sub_9829F0 send an unordered first compare to the Y
//     branch; the C++ comparisons sent a NaN the other way.
//   - sub_985030 subtracts 360 and takes the fractional part in 53-bit
//     precision and clamps a NaN saturation to 1; this did both in single and
//     kept the NaN.
//   The self-tests, which run each routine against the client's own, now
//   include values next to (k + 0.5) / 255, channels outside [0, 1], NaN
//   components and saturations, and hues up to 1200.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>

#include "color_unpack_sse2.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"
#include "ab_test.h"
#include "session_verdict.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace ColorUnpack {

#if !TEST_DISABLE_COLOR_UNPACK_SSE2

namespace {

constexpr uintptr_t kColorUnpackBGRA     = 0x00984C90;
constexpr uintptr_t kColorUnpackBGR      = 0x00982970;
constexpr uintptr_t kColorPackBGRA       = 0x0048BD20;
constexpr uintptr_t kColorPackBGR        = 0x009851A0;
constexpr uintptr_t kColorRGBToHSV       = 0x00984F60;
constexpr uintptr_t kColorHSVToRGB       = 0x00985030;
constexpr uintptr_t kVec3DomAxis         = 0x009829B0;
constexpr uintptr_t kVec3RecAxis         = 0x009829F0;

// __fastcall mirrors x86 __thiscall ABI: ECX = this, EDX = dummy padding
typedef float*   (__fastcall* ColorUnpackBGRA_fn)(float* this_out, void* edx, const uint8_t* bgra);
typedef float*   (__fastcall* ColorUnpackBGR_fn)(float* this_out, void* edx, const uint8_t* bgr);
typedef uint32_t (__fastcall* ColorPackBGRA_fn)(uint32_t* this_out, void* edx, float a, float r, float g, float b);
typedef uint8_t* (__fastcall* ColorPackBGR_fn)(uint8_t* this_out, void* edx, const float* rgb);
typedef void     (__cdecl*    ColorRGBToHSV_fn)(const float* rgb, float* hsv);
typedef void     (__cdecl*    ColorHSVToRGB_fn)(const float* hsv, float* rgb);
typedef int      (__fastcall* Vec3DominantAxis_fn)(const float* this_vec, void* edx);
typedef int      (__fastcall* Vec3RecessiveAxis_fn)(const float* this_vec, void* edx);

ColorUnpackBGRA_fn   orig_ColorUnpackBGRA   = nullptr;
ColorUnpackBGR_fn    orig_ColorUnpackBGR    = nullptr;
ColorPackBGRA_fn     orig_ColorPackBGRA     = nullptr;
ColorPackBGR_fn      orig_ColorPackBGR      = nullptr;
ColorRGBToHSV_fn     orig_ColorRGBToHSV     = nullptr;
ColorHSVToRGB_fn     orig_ColorHSVToRGB     = nullptr;
Vec3DominantAxis_fn  orig_Vec3DominantAxis  = nullptr;
Vec3RecessiveAxis_fn orig_Vec3RecessiveAxis = nullptr;

bool g_installed      = false;
bool g_armedBgra      = false;
bool g_armedBgr       = false;
bool g_armedPackBgra  = false;
bool g_armedPackBgr   = false;
bool g_armedRgbToHsv  = false;
bool g_armedHsvToRgb  = false;
bool g_armedDomAxis   = false;
bool g_armedRecAxis   = false;
bool g_abSubject      = false;
bool g_dead           = false;

unsigned long g_callsBgra        = 0;
unsigned long g_callsBgr         = 0;
unsigned long g_callsPackBgra    = 0;
unsigned long g_callsPackBgr     = 0;
unsigned long g_callsRgbToHsv    = 0;
unsigned long g_callsHsvToRgb    = 0;
unsigned long g_callsDomAxis     = 0;
unsigned long g_callsRecAxis     = 0;
unsigned long g_verifiedBgra     = 0;
unsigned long g_verifiedBgr      = 0;
unsigned long g_verifiedPackBgra = 0;
unsigned long g_verifiedPackBgr  = 0;
unsigned long g_verifiedRgbToHsv = 0;
unsigned long g_verifiedHsvToRgb = 0;
unsigned long g_verifiedDomAxis  = 0;
unsigned long g_verifiedRecAxis  = 0;

constexpr unsigned long kVerifyFirst  = 30000;
constexpr unsigned long kResampleMask = 8191;

// Constant 1.0f / 255.0f matching client ds:flt_A45564 (0x3B808081)
constexpr float kInv255 = 0.003921568859368563f;

// ============================================================================
// Core Vectorized Implementations
// ============================================================================

inline float* Color_UnpackBGRA_SSE2(float* this_out, const uint8_t* bgra) {
    if (!this_out || !bgra) return this_out;

    const __m128 scale = _mm_set1_ps(kInv255);
    const __m128i zero = _mm_setzero_si128();

    uint32_t raw;
    memcpy(&raw, bgra, sizeof(raw));

    __m128i v = _mm_cvtsi32_si128((int)raw);
    v = _mm_unpacklo_epi8(v, zero);   // words: B, G, R, A, 0, 0, 0, 0
    v = _mm_unpacklo_epi16(v, zero);  // dwords: B(0), G(1), R(2), A(3)
    // Swizzle from BGRA to RGBA
    v = _mm_shuffle_epi32(v, _MM_SHUFFLE(3, 0, 1, 2));

    __m128 f = _mm_cvtepi32_ps(v);
    f = _mm_mul_ps(f, scale);

    _mm_storeu_ps(this_out, f);
    return this_out;
}

inline float* Color_UnpackBGR_SSE2(float* this_out, const uint8_t* bgr) {
    if (!this_out || !bgr) return this_out;

    const __m128 scale = _mm_set1_ps(kInv255);
    const __m128i zero = _mm_setzero_si128();

    const uint32_t raw = (uint32_t)bgr[0] | ((uint32_t)bgr[1] << 8) | ((uint32_t)bgr[2] << 16);

    __m128i v = _mm_cvtsi32_si128((int)raw);
    v = _mm_unpacklo_epi8(v, zero);
    v = _mm_unpacklo_epi16(v, zero);
    v = _mm_shuffle_epi32(v, _MM_SHUFFLE(3, 0, 1, 2));

    __m128 f = _mm_cvtepi32_ps(v);
    f = _mm_mul_ps(f, scale);

    alignas(16) float buf[4];
    _mm_store_ps(buf, f);

    this_out[0] = buf[0];
    this_out[1] = buf[1];
    this_out[2] = buf[2];
    return this_out;
}

// sub_48BD20: x * 255 + 0.5 at 53-bit precision, truncated (fldcw 0C00h),
// low byte of the integer kept.
inline uint32_t Color_PackBGRA_SSE2(uint32_t* this_out, float a, float r, float g, float b) {
    if (!this_out) return 0;

    const __m128 v = _mm_setr_ps(b, g, r, a);
    const __m128d k255 = _mm_set1_pd(255.0);
    const __m128d half = _mm_set1_pd(0.5);
    const __m128i lo = _mm_cvttpd_epi32(_mm_add_pd(_mm_mul_pd(_mm_cvtps_pd(v), k255), half));
    const __m128i hi = _mm_cvttpd_epi32(_mm_add_pd(_mm_mul_pd(_mm_cvtps_pd(_mm_movehl_ps(v, v)), k255), half));
    const __m128i vi = _mm_and_si128(_mm_unpacklo_epi64(lo, hi), _mm_set1_epi32(0xFF));
    const __m128i v16 = _mm_packs_epi32(vi, vi);
    const __m128i v8 = _mm_packus_epi16(v16, v16);

    const uint32_t bgra = (uint32_t)_mm_cvtsi128_si32(v8);
    *this_out = bgra;
    return bgra & 0xFFu;
}

inline uint8_t* Color_PackBGR_SSE2(uint8_t* this_out, const float* rgb) {
    if (!this_out || !rgb) return this_out;

    const __m128 v = _mm_setr_ps(rgb[2], rgb[1], rgb[0], 1.0f);
    const __m128 scaled = _mm_mul_ps(v, _mm_set1_ps(255.0f));
    // sub_9851A0 stores x * 255 as a float, rounds it to nearest with fistp and
    // keeps the low byte of the integer.
    const __m128i vi = _mm_and_si128(_mm_cvtps_epi32(scaled), _mm_set1_epi32(0xFF));
    const __m128i v16 = _mm_packs_epi32(vi, vi);
    const __m128i v8 = _mm_packus_epi16(v16, v16);

    const uint32_t bgra = (uint32_t)_mm_cvtsi128_si32(v8);
    memcpy(this_out, &bgra, sizeof(uint32_t));
    return this_out;
}

inline int Vec3_DominantAxis_Fast(const float* this_vec) {
    if (!this_vec) return 0;

    uint32_t ix, iy, iz;
    memcpy(&ix, &this_vec[0], sizeof(float));
    memcpy(&iy, &this_vec[1], sizeof(float));
    memcpy(&iz, &this_vec[2], sizeof(float));

    // Clear IEEE sign bit for instant branchless fabs
    ix &= 0x7FFFFFFFu;
    iy &= 0x7FFFFFFFu;
    iz &= 0x7FFFFFFFu;

    float ax, ay, az;
    memcpy(&ax, &ix, sizeof(float));
    memcpy(&ay, &iy, sizeof(float));
    memcpy(&az, &iz, sizeof(float));

    // sub_9829B0: test ah,41h jnz at 0x009829C7 takes |x| <= |y| and an
    // unordered compare to the Y branch.
    if (!(ax > ay)) {
        return (ay > az) ? 1 : 2;
    } else {
        return (ax > az) ? 0 : 2;
    }
}

inline int Vec3_RecessiveAxis_Fast(const float* this_vec) {
    if (!this_vec) return 0;

    uint32_t ix, iy, iz;
    memcpy(&ix, &this_vec[0], sizeof(float));
    memcpy(&iy, &this_vec[1], sizeof(float));
    memcpy(&iz, &this_vec[2], sizeof(float));

    // Clear IEEE sign bit for instant branchless fabs
    ix &= 0x7FFFFFFFu;
    iy &= 0x7FFFFFFFu;
    iz &= 0x7FFFFFFFu;

    float ax, ay, az;
    memcpy(&ax, &ix, sizeof(float));
    memcpy(&ay, &iy, sizeof(float));
    memcpy(&az, &iz, sizeof(float));

    // sub_9829F0: test ah,5 jp at 0x00982A07 takes |x| >= |y| and an
    // unordered compare to the Y branch; in the X branch only an ordered
    // |x| < |z| answers 0.
    if (!(ax < ay)) {
        return (ay > az) ? 2 : 1;
    } else {
        return (ax < az) ? 0 : 2;
    }
}

inline void Color_RGBToHSV_SSE2(const float* rgb, float* hsv) {
    if (!rgb || !hsv) return;

    // Load locally to support in-place buffers (rgb == hsv)
    float r = rgb[0];
    float g = rgb[1];
    float b = rgb[2];

    float local_rgb[3] = { r, g, b };
    int dom = Vec3_DominantAxis_Fast(local_rgb);
    int rec = Vec3_RecessiveAxis_Fast(local_rgb);

    float max_val = local_rgb[dom];
    float min_val = local_rgb[rec];

    hsv[2] = max_val;  // V = max(R, G, B)

    if (max_val == 0.0f) {
        hsv[1] = 0.0f;  // S
        hsv[0] = -1.0f; // H undefined
        return;
    }

    double d_delta = (double)max_val - (double)min_val;
    float s = (float)(d_delta / (double)max_val);
    hsv[1] = s;

    if (s == 0.0f) {
        hsv[0] = -1.0f; // H undefined
        return;
    }

    double d_h;
    if (dom == 0) {
        d_h = ((double)g - (double)b) / d_delta;
    } else if (dom == 1) {
        d_h = ((double)b - (double)r) / d_delta + 2.0;
    } else {
        d_h = ((double)r - (double)g) / d_delta + 4.0;
    }

    float h = (float)d_h;
    h *= 60.0f;
    if (h < 0.0f) {
        h += 360.0f;
    }
    hsv[0] = h;
}

inline void Color_HSVToRGB_SSE2(const float* hsv, float* rgb) {
    if (!hsv || !rgb) return;

    // Load locally to support in-place buffers (hsv == rgb)
    float h = hsv[0];
    float s = hsv[1];
    float v = hsv[2];

    if (s == 0.0f) {
        rgb[0] = v;
        rgb[1] = v;
        rgb[2] = v;
        return;
    }

    // 0x00985071: h - 360 when h >= 360 (ordered), kept at 53 bits, times
    // flt_A393E4 (0.016666668f), stored as a float.
    const float kInv60 = 0.016666668f;
    const double d_h = (h >= 360.0f) ? (double)h - 360.0 : (double)h;
    const float v12 = (float)(d_h * (double)kInv60);

    // fsub flt_B2D724 (0.5f) at 53 bits, fistp to nearest.
    int sector = _mm_cvtsd_si32(_mm_set_sd((double)v12 - 0.5));
    if (sector > 5) {
        sector = 5;
    }

    // fild; fsubr: the fraction stays at 53 bits. The saturation is used only
    // when it is below 1 (0x009850B6 test ah,41h jnz), so a NaN becomes 1.
    const double d_f = (double)v12 - (double)sector;
    const double d_s = (s < 1.0f) ? (double)s : 1.0;
    const double d_v = (double)v;

    float v9  = (float)((1.0 - d_s * d_f) * d_v);
    float v10 = (float)((1.0 - d_s) * d_v);
    float v11 = (float)((1.0 - d_s * (1.0 - d_f)) * d_v);

    switch (sector) {
    case 0:
        rgb[0] = v;
        rgb[1] = v11;
        rgb[2] = v10;
        break;
    case 1:
        rgb[0] = v9;
        rgb[1] = v;
        rgb[2] = v10;
        break;
    case 2:
        rgb[0] = v10;
        rgb[1] = v;
        rgb[2] = v11;
        break;
    case 3:
        rgb[0] = v10;
        rgb[1] = v9;
        rgb[2] = v;
        break;
    case 4:
        rgb[0] = v11;
        rgb[1] = v10;
        rgb[2] = v;
        break;
    case 5:
        rgb[0] = v;
        rgb[1] = v10;
        rgb[2] = v9;
        break;
    default:
        break;
    }
}

// ============================================================================
// Dual-Run Hook Bodies
// ============================================================================

float* Hooked_ColorUnpackBGRABody(float* this_out, void* edx, const uint8_t* bgra) {
    g_callsBgra++;
    if (g_dead) {
        return orig_ColorUnpackBGRA(this_out, edx, bgra);
    }

    if (!g_armedBgra || (g_callsBgra & kResampleMask) == 0) {
        float theirs[4];
        float mine[4];
        orig_ColorUnpackBGRA(theirs, edx, bgra);
        Color_UnpackBGRA_SSE2(mine, bgra);

        if (memcmp(theirs, mine, sizeof(theirs)) != 0) {
            g_dead = true;
            Verdict::Add(Verdict::Bad, "Color_UnpackBGRA disagreed with client; retired for session");
            Log("[ColorUnpack] DISAGREED on Color_UnpackBGRA at call %lu - retired for session", g_callsBgra);
            memcpy(this_out, theirs, sizeof(theirs));
            return this_out;
        }

        g_verifiedBgra++;
        if (!g_armedBgra && g_verifiedBgra >= kVerifyFirst) {
            g_armedBgra = true;
            Log("[ColorUnpack] Color_UnpackBGRA armed: %lu calls agreed with client exactly, now answering directly (resampling 1 in %lu)",
                g_verifiedBgra, kResampleMask + 1);
        }
        memcpy(this_out, theirs, sizeof(theirs));
        return this_out;
    }

    return Color_UnpackBGRA_SSE2(this_out, bgra);
}

float* Hooked_ColorUnpackBGRBody(float* this_out, void* edx, const uint8_t* bgr) {
    g_callsBgr++;
    if (g_dead) {
        return orig_ColorUnpackBGR(this_out, edx, bgr);
    }

    if (!g_armedBgr || (g_callsBgr & kResampleMask) == 0) {
        float theirs[3];
        float mine[3];
        orig_ColorUnpackBGR(theirs, edx, bgr);
        Color_UnpackBGR_SSE2(mine, bgr);

        if (memcmp(theirs, mine, sizeof(theirs)) != 0) {
            g_dead = true;
            Verdict::Add(Verdict::Bad, "Color_UnpackBGR disagreed with client; retired for session");
            Log("[ColorUnpack] DISAGREED on Color_UnpackBGR at call %lu - retired for session", g_callsBgr);
            memcpy(this_out, theirs, sizeof(theirs));
            return this_out;
        }

        g_verifiedBgr++;
        if (!g_armedBgr && g_verifiedBgr >= kVerifyFirst) {
            g_armedBgr = true;
            Log("[ColorUnpack] Color_UnpackBGR armed: %lu calls agreed with client exactly, now answering directly (resampling 1 in %lu)",
                g_verifiedBgr, kResampleMask + 1);
        }
        memcpy(this_out, theirs, sizeof(theirs));
        return this_out;
    }

    return Color_UnpackBGR_SSE2(this_out, bgr);
}

uint32_t Hooked_ColorPackBGRABody(uint32_t* this_out, void* edx, float a, float r, float g, float b) {
    g_callsPackBgra++;
    if (g_dead) {
        return orig_ColorPackBGRA(this_out, edx, a, r, g, b);
    }

    if (!g_armedPackBgra || (g_callsPackBgra & kResampleMask) == 0) {
        uint32_t theirs_val = 0;
        uint32_t mine_val   = 0;
        const uint32_t theirs_ret = orig_ColorPackBGRA(&theirs_val, edx, a, r, g, b);
        const uint32_t mine_ret   = Color_PackBGRA_SSE2(&mine_val, a, r, g, b);

        if (theirs_val != mine_val || theirs_ret != mine_ret) {
            g_dead = true;
            Verdict::Add(Verdict::Bad, "Color_PackBGRA disagreed with client; retired for session");
            Log("[ColorUnpack] DISAGREED on Color_PackBGRA at call %lu - retired for session (val: %08X vs %08X, ret: %u vs %u)",
                g_callsPackBgra, theirs_val, mine_val, theirs_ret, mine_ret);
            if (this_out) *this_out = theirs_val;
            return theirs_ret;
        }

        g_verifiedPackBgra++;
        if (!g_armedPackBgra && g_verifiedPackBgra >= kVerifyFirst) {
            g_armedPackBgra = true;
            Log("[ColorUnpack] Color_PackBGRA armed: %lu calls agreed with client exactly, now answering directly (resampling 1 in %lu)",
                g_verifiedPackBgra, kResampleMask + 1);
        }
        if (this_out) *this_out = theirs_val;
        return theirs_ret;
    }

    return Color_PackBGRA_SSE2(this_out, a, r, g, b);
}

uint8_t* Hooked_ColorPackBGRBody(uint8_t* this_out, void* edx, const float* rgb) {
    g_callsPackBgr++;
    if (g_dead) {
        return orig_ColorPackBGR(this_out, edx, rgb);
    }

    if (!g_armedPackBgr || (g_callsPackBgr & kResampleMask) == 0) {
        uint8_t theirs_buf[4] = { 0 };
        uint8_t mine_buf[4]   = { 0 };
        orig_ColorPackBGR(theirs_buf, edx, rgb);
        Color_PackBGR_SSE2(mine_buf, rgb);

        if (memcmp(theirs_buf, mine_buf, sizeof(theirs_buf)) != 0) {
            g_dead = true;
            Verdict::Add(Verdict::Bad, "Color_PackBGR disagreed with client; retired for session");
            Log("[ColorUnpack] DISAGREED on Color_PackBGR at call %lu - retired for session", g_callsPackBgr);
            if (this_out) memcpy(this_out, theirs_buf, sizeof(theirs_buf));
            return this_out;
        }

        g_verifiedPackBgr++;
        if (!g_armedPackBgr && g_verifiedPackBgr >= kVerifyFirst) {
            g_armedPackBgr = true;
            Log("[ColorUnpack] Color_PackBGR armed: %lu calls agreed with client exactly, now answering directly (resampling 1 in %lu)",
                g_verifiedPackBgr, kResampleMask + 1);
        }
        if (this_out) memcpy(this_out, theirs_buf, sizeof(theirs_buf));
        return this_out;
    }

    return Color_PackBGR_SSE2(this_out, rgb);
}

int Hooked_Vec3DominantAxisBody(const float* this_vec, void* edx) {
    g_callsDomAxis++;
    if (g_dead) {
        return orig_Vec3DominantAxis(this_vec, edx);
    }

    if (!g_armedDomAxis || (g_callsDomAxis & kResampleMask) == 0) {
        const int theirs = orig_Vec3DominantAxis(this_vec, edx);
        const int mine = Vec3_DominantAxis_Fast(this_vec);

        if (theirs != mine) {
            g_dead = true;
            Verdict::Add(Verdict::Bad, "Vec3_DominantAxis disagreed with client; retired for session");
            Log("[ColorUnpack] DISAGREED on Vec3_DominantAxis at call %lu - retired for session", g_callsDomAxis);
            return theirs;
        }

        g_verifiedDomAxis++;
        if (!g_armedDomAxis && g_verifiedDomAxis >= kVerifyFirst) {
            g_armedDomAxis = true;
            Log("[ColorUnpack] Vec3_DominantAxis armed: %lu calls agreed with client exactly, now answering directly (resampling 1 in %lu)",
                g_verifiedDomAxis, kResampleMask + 1);
        }
        return theirs;
    }

    return Vec3_DominantAxis_Fast(this_vec);
}

int Hooked_Vec3RecessiveAxisBody(const float* this_vec, void* edx) {
    g_callsRecAxis++;
    if (g_dead) {
        return orig_Vec3RecessiveAxis(this_vec, edx);
    }

    if (!g_armedRecAxis || (g_callsRecAxis & kResampleMask) == 0) {
        const int theirs = orig_Vec3RecessiveAxis(this_vec, edx);
        const int mine = Vec3_RecessiveAxis_Fast(this_vec);

        if (theirs != mine) {
            g_dead = true;
            Verdict::Add(Verdict::Bad, "Vec3_RecessiveAxis disagreed with client; retired for session");
            Log("[ColorUnpack] DISAGREED on Vec3_RecessiveAxis at call %lu - retired for session", g_callsRecAxis);
            return theirs;
        }

        g_verifiedRecAxis++;
        if (!g_armedRecAxis && g_verifiedRecAxis >= kVerifyFirst) {
            g_armedRecAxis = true;
            Log("[ColorUnpack] Vec3_RecessiveAxis armed: %lu calls agreed with client exactly, now answering directly (resampling 1 in %lu)",
                g_verifiedRecAxis, kResampleMask + 1);
        }
        return theirs;
    }

    return Vec3_RecessiveAxis_Fast(this_vec);
}

void Hooked_ColorRGBToHSVBody(const float* rgb, float* hsv) {
    g_callsRgbToHsv++;
    if (g_dead) {
        orig_ColorRGBToHSV(rgb, hsv);
        return;
    }

    if (!g_armedRgbToHsv || (g_callsRgbToHsv & kResampleMask) == 0) {
        float theirs[3];
        float mine[3];
        orig_ColorRGBToHSV(rgb, theirs);
        Color_RGBToHSV_SSE2(rgb, mine);

        if (memcmp(theirs, mine, sizeof(theirs)) != 0) {
            g_dead = true;
            Verdict::Add(Verdict::Bad, "Color_RGBToHSV disagreed with client; retired for session");
            Log("[ColorUnpack] DISAGREED on Color_RGBToHSV at call %lu - retired for session", g_callsRgbToHsv);
            memcpy(hsv, theirs, sizeof(theirs));
            return;
        }

        g_verifiedRgbToHsv++;
        if (!g_armedRgbToHsv && g_verifiedRgbToHsv >= kVerifyFirst) {
            g_armedRgbToHsv = true;
            Log("[ColorUnpack] Color_RGBToHSV armed: %lu calls agreed with client exactly, now answering directly (resampling 1 in %lu)",
                g_verifiedRgbToHsv, kResampleMask + 1);
        }
        memcpy(hsv, theirs, sizeof(theirs));
        return;
    }

    Color_RGBToHSV_SSE2(rgb, hsv);
}

void Hooked_ColorHSVToRGBBody(const float* hsv, float* rgb) {
    g_callsHsvToRgb++;
    if (g_dead) {
        orig_ColorHSVToRGB(hsv, rgb);
        return;
    }

    if (!g_armedHsvToRgb || (g_callsHsvToRgb & kResampleMask) == 0) {
        float theirs[3];
        float mine[3];
        orig_ColorHSVToRGB(hsv, theirs);
        Color_HSVToRGB_SSE2(hsv, mine);

        if (memcmp(theirs, mine, sizeof(theirs)) != 0) {
            g_dead = true;
            Verdict::Add(Verdict::Bad, "Color_HSVToRGB disagreed with client; retired for session");
            Log("[ColorUnpack] DISAGREED on Color_HSVToRGB at call %lu - retired for session", g_callsHsvToRgb);
            memcpy(rgb, theirs, sizeof(theirs));
            return;
        }

        g_verifiedHsvToRgb++;
        if (!g_armedHsvToRgb && g_verifiedHsvToRgb >= kVerifyFirst) {
            g_armedHsvToRgb = true;
            Log("[ColorUnpack] Color_HSVToRGB armed: %lu calls agreed with client exactly, now answering directly (resampling 1 in %lu)",
                g_verifiedHsvToRgb, kResampleMask + 1);
        }
        memcpy(rgb, theirs, sizeof(theirs));
        return;
    }

    Color_HSVToRGB_SSE2(hsv, rgb);
}

// ============================================================================
// ============================================================================
// Hook Detours with AbTest
// ============================================================================

float* __fastcall Hooked_ColorUnpackBGRA(float* this_out, void* edx, const uint8_t* bgra) {
    if (!g_abSubject) {
        return Hooked_ColorUnpackBGRABody(this_out, edx, bgra);
    }
    const unsigned long long t = AbTest::TickIn();
    float* res = AbTest::StandAside() ? orig_ColorUnpackBGRA(this_out, edx, bgra)
                                      : Hooked_ColorUnpackBGRABody(this_out, edx, bgra);
    AbTest::TickOut(t);
    return res;
}

float* __fastcall Hooked_ColorUnpackBGR(float* this_out, void* edx, const uint8_t* bgr) {
    if (!g_abSubject) {
        return Hooked_ColorUnpackBGRBody(this_out, edx, bgr);
    }
    const unsigned long long t = AbTest::TickIn();
    float* res = AbTest::StandAside() ? orig_ColorUnpackBGR(this_out, edx, bgr)
                                      : Hooked_ColorUnpackBGRBody(this_out, edx, bgr);
    AbTest::TickOut(t);
    return res;
}

uint32_t __fastcall Hooked_ColorPackBGRA(uint32_t* this_out, void* edx, float a, float r, float g, float b) {
    if (!g_abSubject) {
        return Hooked_ColorPackBGRABody(this_out, edx, a, r, g, b);
    }
    const unsigned long long t = AbTest::TickIn();
    uint32_t res = AbTest::StandAside() ? orig_ColorPackBGRA(this_out, edx, a, r, g, b)
                                        : Hooked_ColorPackBGRABody(this_out, edx, a, r, g, b);
    AbTest::TickOut(t);
    return res;
}

uint8_t* __fastcall Hooked_ColorPackBGR(uint8_t* this_out, void* edx, const float* rgb) {
    if (!g_abSubject) {
        return Hooked_ColorPackBGRBody(this_out, edx, rgb);
    }
    const unsigned long long t = AbTest::TickIn();
    uint8_t* res = AbTest::StandAside() ? orig_ColorPackBGR(this_out, edx, rgb)
                                        : Hooked_ColorPackBGRBody(this_out, edx, rgb);
    AbTest::TickOut(t);
    return res;
}

int __fastcall Hooked_Vec3DominantAxis(const float* this_vec, void* edx) {
    if (!g_abSubject) {
        return Hooked_Vec3DominantAxisBody(this_vec, edx);
    }
    const unsigned long long t = AbTest::TickIn();
    int res = AbTest::StandAside() ? orig_Vec3DominantAxis(this_vec, edx)
                                   : Hooked_Vec3DominantAxisBody(this_vec, edx);
    AbTest::TickOut(t);
    return res;
}

int __fastcall Hooked_Vec3RecessiveAxis(const float* this_vec, void* edx) {
    if (!g_abSubject) {
        return Hooked_Vec3RecessiveAxisBody(this_vec, edx);
    }
    const unsigned long long t = AbTest::TickIn();
    int res = AbTest::StandAside() ? orig_Vec3RecessiveAxis(this_vec, edx)
                                   : Hooked_Vec3RecessiveAxisBody(this_vec, edx);
    AbTest::TickOut(t);
    return res;
}

void __cdecl Hooked_ColorRGBToHSV(const float* rgb, float* hsv) {
    if (!g_abSubject) {
        Hooked_ColorRGBToHSVBody(rgb, hsv);
        return;
    }
    const unsigned long long t = AbTest::TickIn();
    if (AbTest::StandAside()) {
        orig_ColorRGBToHSV(rgb, hsv);
    } else {
        Hooked_ColorRGBToHSVBody(rgb, hsv);
    }
    AbTest::TickOut(t);
}

void __cdecl Hooked_ColorHSVToRGB(const float* hsv, float* rgb) {
    if (!g_abSubject) {
        Hooked_ColorHSVToRGBBody(hsv, rgb);
        return;
    }
    const unsigned long long t = AbTest::TickIn();
    if (AbTest::StandAside()) {
        orig_ColorHSVToRGB(hsv, rgb);
    } else {
        Hooked_ColorHSVToRGBBody(hsv, rgb);
    }
    AbTest::TickOut(t);
}

// ============================================================================
// Startup Self-Tests
// ============================================================================

static bool SelfTestColorUnpack() {
    ColorUnpackBGRA_fn orig_bgra = (ColorUnpackBGRA_fn)kColorUnpackBGRA;
    ColorUnpackBGR_fn  orig_bgr  = (ColorUnpackBGR_fn)kColorUnpackBGR;

    // Test every single one of the 256 possible byte values across all 4 channels
    for (int b = 0; b < 256; ++b) {
        const uint8_t in_bgra[4] = {
            (uint8_t)b,
            (uint8_t)((b * 37 + 13) & 0xFF),
            (uint8_t)((b * 73 + 47) & 0xFF),
            (uint8_t)((b * 101 + 83) & 0xFF)
        };

        float theirs_bgra[4] = { 0 };
        float mine_bgra[4]   = { 0 };

        __try {
            orig_bgra(theirs_bgra, nullptr, in_bgra);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[ColorUnpack] SelfTestColorUnpack: client Color_UnpackBGRA faulted on byte %d - not installing", b);
            return false;
        }

        Color_UnpackBGRA_SSE2(mine_bgra, in_bgra);

        if (memcmp(theirs_bgra, mine_bgra, sizeof(theirs_bgra)) != 0) {
            Log("[ColorUnpack] SelfTestColorUnpack: MISMATCH on BGRA byte %d!\n"
                "  Client: (%.6f, %.6f, %.6f, %.6f)\n"
                "  Ours:   (%.6f, %.6f, %.6f, %.6f)",
                b,
                theirs_bgra[0], theirs_bgra[1], theirs_bgra[2], theirs_bgra[3],
                mine_bgra[0], mine_bgra[1], mine_bgra[2], mine_bgra[3]);
            return false;
        }

        float theirs_bgr[3] = { 0 };
        float mine_bgr[3]   = { 0 };

        __try {
            orig_bgr(theirs_bgr, nullptr, in_bgra);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[ColorUnpack] SelfTestColorUnpack: client Color_UnpackBGR faulted on byte %d - not installing", b);
            return false;
        }

        Color_UnpackBGR_SSE2(mine_bgr, in_bgra);

        if (memcmp(theirs_bgr, mine_bgr, sizeof(theirs_bgr)) != 0) {
            Log("[ColorUnpack] SelfTestColorUnpack: MISMATCH on BGR byte %d!\n"
                "  Client: (%.6f, %.6f, %.6f)\n"
                "  Ours:   (%.6f, %.6f, %.6f)",
                b,
                theirs_bgr[0], theirs_bgr[1], theirs_bgr[2],
                mine_bgr[0], mine_bgr[1], mine_bgr[2]);
            return false;
        }
    }

    Log("[ColorUnpack] SelfTestColorUnpack: 256/256 byte permutations passed with 100%% bit-exact match against client.");
    return true;
}

// The float `n` representable steps away from x.
static float StepFloat(float x, int n) {
    uint32_t b;
    memcpy(&b, &x, 4);
    b += (uint32_t)n;
    memcpy(&x, &b, 4);
    return x;
}

static bool SelfTestColorPack() {
    ColorPackBGRA_fn orig_pack_bgra = (ColorPackBGRA_fn)kColorPackBGRA;
    ColorPackBGR_fn  orig_pack_bgr  = (ColorPackBGR_fn)kColorPackBGR;

    const int CASES = 60000;
    unsigned seed = 0x87654321u;

    for (int c = 0; c < CASES; ++c) {
        float rgba[4];
        for (int i = 0; i < 4; ++i) {
            seed = seed * 1664525u + 1013904223u;
            rgba[i] = (float)(seed & 0xFFFF) / 65535.0f; // [0.0f, 1.0f]
        }

        // Values next to (k + 0.5) / 255, where rounding x * 255 early moves
        // the result, and channels outside [0, 1], where the low byte wraps.
        if (c >= 20000 && c < 40000) {
            for (int i = 0; i < 4; ++i) {
                seed = seed * 1664525u + 1013904223u;
                const int k = (int)((seed >> 8) % 255);
                rgba[i] = StepFloat(((float)k + 0.5f) / 255.0f, (int)((seed >> 20) % 41) - 20);
            }
        } else if (c >= 40000) {
            for (int i = 0; i < 4; ++i) {
                seed = seed * 1664525u + 1013904223u;
                rgba[i] = (float)(int)(seed >> 8 & 0xFFFF) / 65535.0f * 7.0f - 3.0f;
            }
        }

        // Include edge values: 0.0f, 1.0f, exact 1/255 increments
        if (c < 256) {
            rgba[0] = (float)c / 255.0f;
            rgba[1] = (float)((c * 37 + 13) % 256) / 255.0f;
            rgba[2] = (float)((c * 73 + 47) % 256) / 255.0f;
            rgba[3] = (float)((c * 101 + 83) % 256) / 255.0f;
        }

        // Test Color_PackBGRA
        uint32_t theirs_bgra_out = 0;
        uint32_t mine_bgra_out   = 0;
        uint32_t theirs_bgra_ret = 0;
        uint32_t mine_bgra_ret   = 0;

        __try {
            theirs_bgra_ret = orig_pack_bgra(&theirs_bgra_out, nullptr, rgba[0], rgba[1], rgba[2], rgba[3]);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[ColorUnpack] SelfTestColorPack: client Color_PackBGRA faulted on case %d - not installing", c);
            return false;
        }

        mine_bgra_ret = Color_PackBGRA_SSE2(&mine_bgra_out, rgba[0], rgba[1], rgba[2], rgba[3]);

        if (theirs_bgra_out != mine_bgra_out || theirs_bgra_ret != mine_bgra_ret) {
            Log("[ColorUnpack] SelfTestColorPack: MISMATCH on Color_PackBGRA case %d!\n"
                "  Inputs: A=%.6f, R=%.6f, G=%.6f, B=%.6f\n"
                "  Client: out=0x%08X, ret=0x%X\n"
                "  Ours:   out=0x%08X, ret=0x%X",
                c, rgba[0], rgba[1], rgba[2], rgba[3],
                theirs_bgra_out, theirs_bgra_ret,
                mine_bgra_out, mine_bgra_ret);
            return false;
        }

        // Test Color_PackBGR
        uint8_t theirs_bgr_out[4] = { 0 };
        uint8_t mine_bgr_out[4]   = { 0 };

        __try {
            orig_pack_bgr(theirs_bgr_out, nullptr, &rgba[1]); // pass R, G, B
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[ColorUnpack] SelfTestColorPack: client Color_PackBGR faulted on case %d - not installing", c);
            return false;
        }

        Color_PackBGR_SSE2(mine_bgr_out, &rgba[1]);

        if (memcmp(theirs_bgr_out, mine_bgr_out, sizeof(theirs_bgr_out)) != 0) {
            Log("[ColorUnpack] SelfTestColorPack: MISMATCH on Color_PackBGR case %d!\n"
                "  Inputs: R=%.6f, G=%.6f, B=%.6f\n"
                "  Client: [%02X %02X %02X %02X]\n"
                "  Ours:   [%02X %02X %02X %02X]",
                c, rgba[1], rgba[2], rgba[3],
                theirs_bgr_out[0], theirs_bgr_out[1], theirs_bgr_out[2], theirs_bgr_out[3],
                mine_bgr_out[0], mine_bgr_out[1], mine_bgr_out[2], mine_bgr_out[3]);
            return false;
        }
    }

    Log("[ColorUnpack] SelfTestColorPack: %d test cases passed with 100%% bit-exact match against client.", CASES);
    return true;
}

static bool SelfTestDominantAxis() {
    Vec3DominantAxis_fn orig_dom = (Vec3DominantAxis_fn)kVec3DomAxis;
    const int CASES = 20000;
    unsigned seed = 0x54321A7Du;

    for (int c = 0; c < CASES; ++c) {
        float v[3];
        for (int i = 0; i < 3; ++i) {
            seed = seed * 1103515245u + 12345u;
            v[i] = (float)((int)(seed >> 16) - 16384) * 0.25f;
        }

        // Include edge cases with exact ties
        if (c % 10 == 0) {
            v[1] = v[0]; // X == Y
        }
        if (c % 15 == 0) {
            v[2] = v[0]; // X == Z
        }
        if (c % 25 == 0) {
            v[2] = v[1]; // Y == Z
        }
        // A NaN component: the client's compares send it down particular branches.
        if (c % 13 == 0) {
            const uint32_t nan_bits = 0x7FC00000u;
            memcpy(&v[(c / 13) % 3], &nan_bits, 4);
        }

        int theirs = -1;
        __try {
            theirs = orig_dom(v, nullptr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[ColorUnpack] SelfTestDominantAxis: client routine faulted on case %d - not installing", c);
            return false;
        }

        const int mine = Vec3_DominantAxis_Fast(v);

        if (theirs != mine) {
            Log("[ColorUnpack] SelfTestDominantAxis: MISMATCH on case %d!\n"
                "  Vec=(%.6f, %.6f, %.6f) Client=%d Ours=%d",
                c, v[0], v[1], v[2], theirs, mine);
            return false;
        }
    }

    Log("[ColorUnpack] SelfTestDominantAxis: passed %d test cases with 100%% identity match against client.", CASES);
    return true;
}

static bool SelfTestRecessiveAxis() {
    Vec3RecessiveAxis_fn orig_rec = (Vec3RecessiveAxis_fn)kVec3RecAxis;
    const int CASES = 20000;
    unsigned seed = 0x98765432u;

    for (int c = 0; c < CASES; ++c) {
        float v[3];
        for (int i = 0; i < 3; ++i) {
            seed = seed * 1103515245u + 12345u;
            v[i] = (float)((int)(seed >> 16) - 16384) * 0.25f;
        }

        // Include edge cases with exact ties
        if (c % 10 == 0) {
            v[1] = v[0]; // X == Y
        }
        if (c % 15 == 0) {
            v[2] = v[0]; // X == Z
        }
        if (c % 25 == 0) {
            v[2] = v[1]; // Y == Z
        }
        // A NaN component: the client's compares send it down particular branches.
        if (c % 13 == 0) {
            const uint32_t nan_bits = 0x7FC00000u;
            memcpy(&v[(c / 13) % 3], &nan_bits, 4);
        }

        int theirs = -1;
        __try {
            theirs = orig_rec(v, nullptr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[ColorUnpack] SelfTestRecessiveAxis: client routine faulted on case %d - not installing", c);
            return false;
        }

        const int mine = Vec3_RecessiveAxis_Fast(v);

        if (theirs != mine) {
            Log("[ColorUnpack] SelfTestRecessiveAxis: MISMATCH on case %d!\n"
                "  Vec=(%.6f, %.6f, %.6f) Client=%d Ours=%d",
                c, v[0], v[1], v[2], theirs, mine);
            return false;
        }
    }

    Log("[ColorUnpack] SelfTestRecessiveAxis: passed %d test cases with 100%% identity match against client.", CASES);
    return true;
}

static bool SelfTestRGBToHSV() {
    ColorRGBToHSV_fn orig_rgb2hsv = (ColorRGBToHSV_fn)kColorRGBToHSV;

    const float kFixedTests[][3] = {
        { 0.0f, 0.0f, 0.0f },
        { 1.0f, 1.0f, 1.0f },
        { 1.0f, 0.0f, 0.0f },
        { 0.0f, 1.0f, 0.0f },
        { 0.0f, 0.0f, 1.0f },
        { 1.0f, 1.0f, 0.0f },
        { 0.0f, 1.0f, 1.0f },
        { 1.0f, 0.0f, 1.0f },
        { 0.5f, 0.5f, 0.5f },
        { 0.25f, 0.5f, 0.75f },
        { 0.8f, 0.2f, 0.4f },
        { 0.1f, 0.9f, 0.3f },
        { 0.001f, 0.001f, 0.001f },
        { 0.999f, 0.999f, 0.999f },
    };

    for (const auto& rgb : kFixedTests) {
        float theirs[3] = { 0 };
        float mine[3]   = { 0 };
        orig_rgb2hsv(rgb, theirs);
        Color_RGBToHSV_SSE2(rgb, mine);
        if (memcmp(theirs, mine, sizeof(theirs)) != 0) {
            Log("[ColorUnpack] SelfTestRGBToHSV: FAILED on fixed vector (%.3f, %.3f, %.3f)",
                rgb[0], rgb[1], rgb[2]);
            return false;
        }
    }

    uint32_t rng = 0x1337BEEFu;
    auto next_float = [&rng]() -> float {
        rng ^= rng << 13;
        rng ^= rng >> 17;
        rng ^= rng << 5;
        return (float)(rng & 0xFFFF) / 65535.0f;
    };

    constexpr int CASES = 20000;
    for (int i = 0; i < CASES; ++i) {
        float rgb[3];
        rgb[0] = next_float();
        rgb[1] = next_float();
        rgb[2] = next_float();

        if ((i % 5) == 0) rgb[1] = rgb[0];
        if ((i % 7) == 0) rgb[2] = rgb[0];
        if ((i % 11) == 0) rgb[2] = rgb[1];
        if ((i % 13) == 0) {
            const uint32_t nan_bits = 0x7FC00000u;
            memcpy(&rgb[(i / 13) % 3], &nan_bits, 4);
        }

        float theirs[3] = { 0 };
        float mine[3]   = { 0 };
        orig_rgb2hsv(rgb, theirs);
        Color_RGBToHSV_SSE2(rgb, mine);

        if (memcmp(theirs, mine, sizeof(theirs)) != 0) {
            Log("[ColorUnpack] SelfTestRGBToHSV: FAILED at case %d: RGB(%.6f, %.6f, %.6f) theirs(%.6f, %.6f, %.6f) mine(%.6f, %.6f, %.6f)",
                i, rgb[0], rgb[1], rgb[2],
                theirs[0], theirs[1], theirs[2],
                mine[0], mine[1], mine[2]);
            return false;
        }
    }

    Log("[ColorUnpack] SelfTestRGBToHSV: passed %d test cases with 100%% identity match against client.", CASES);
    return true;
}

static bool SelfTestHSVToRGB() {
    ColorHSVToRGB_fn orig_hsv2rgb = (ColorHSVToRGB_fn)kColorHSVToRGB;

    const float kFixedTests[][3] = {
        {   0.0f, 0.0f, 0.5f },
        {   0.0f, 1.0f, 1.0f },
        {  60.0f, 1.0f, 1.0f },
        { 120.0f, 1.0f, 1.0f },
        { 180.0f, 1.0f, 1.0f },
        { 240.0f, 1.0f, 1.0f },
        { 300.0f, 1.0f, 1.0f },
        { 360.0f, 1.0f, 1.0f },
        { 380.0f, 0.8f, 0.9f },
        {  30.0f, 0.5f, 0.8f },
        {  90.0f, 0.6f, 0.7f },
        { 150.0f, 0.4f, 0.6f },
        { 210.0f, 0.7f, 0.5f },
        { 270.0f, 0.9f, 0.4f },
        { 330.0f, 0.3f, 0.9f },
        {  59.999f, 0.8f, 0.7f },
        {  60.001f, 0.8f, 0.7f },
        { 119.999f, 0.8f, 0.7f },
        { 120.001f, 0.8f, 0.7f },
        { 179.999f, 0.8f, 0.7f },
        { 180.001f, 0.8f, 0.7f },
        { 239.999f, 0.8f, 0.7f },
        { 240.001f, 0.8f, 0.7f },
        { 299.999f, 0.8f, 0.7f },
        { 300.001f, 0.8f, 0.7f },
        { 359.999f, 0.8f, 0.7f },
        { 100.0f, 1.5f, 0.8f },
    };

    for (const auto& hsv : kFixedTests) {
        float theirs[3] = { 0 };
        float mine[3]   = { 0 };
        orig_hsv2rgb(hsv, theirs);
        Color_HSVToRGB_SSE2(hsv, mine);
        if (memcmp(theirs, mine, sizeof(theirs)) != 0) {
            Log("[ColorUnpack] SelfTestHSVToRGB: FAILED on fixed vector (%.3f, %.3f, %.3f)",
                hsv[0], hsv[1], hsv[2]);
            return false;
        }
    }

    uint32_t rng = 0xCAFEBABEu;
    auto next_float = [&rng]() -> float {
        rng ^= rng << 13;
        rng ^= rng >> 17;
        rng ^= rng << 5;
        return (float)(rng & 0xFFFF) / 65535.0f;
    };

    constexpr int CASES = 20000;
    for (int i = 0; i < CASES; ++i) {
        float hsv[3];
        hsv[0] = next_float() * 370.0f;
        hsv[1] = next_float();
        hsv[2] = next_float();

        if ((i % 10) == 0) hsv[1] = 0.0f;
        if ((i % 15) == 0) hsv[1] = 1.0f + next_float();
        if ((i % 3) == 1) hsv[0] = next_float() * 1300.0f - 100.0f;  // past 720, and negative
        if ((i % 17) == 0) {
            const uint32_t nan_bits = 0x7FC00000u;
            memcpy(&hsv[1], &nan_bits, 4);
        }

        float theirs[3] = { 0 };
        float mine[3]   = { 0 };
        orig_hsv2rgb(hsv, theirs);
        Color_HSVToRGB_SSE2(hsv, mine);

        if (memcmp(theirs, mine, sizeof(theirs)) != 0) {
            Log("[ColorUnpack] SelfTestHSVToRGB: FAILED at case %d: HSV(%.6f, %.6f, %.6f) theirs(%.6f, %.6f, %.6f) mine(%.6f, %.6f, %.6f)",
                i, hsv[0], hsv[1], hsv[2],
                theirs[0], theirs[1], theirs[2],
                mine[0], mine[1], mine[2]);
            return false;
        }
    }

    Log("[ColorUnpack] SelfTestHSVToRGB: passed %d test cases with 100%% identity match against client.", CASES);
    return true;
}

}  // namespace

#endif  // !TEST_DISABLE_COLOR_UNPACK_SSE2

bool Init() {
#if TEST_DISABLE_COLOR_UNPACK_SSE2
    Log("[ColorUnpack] DISABLED via feature flag");
    return false;
#else
    if (!Config::g_settings.OptColorUnpack) {
        Log("[ColorUnpack] not installed: switched off.");
        return false;
    }

    if (!WowOpt_ClientPatchAllowed((const void*)kColorUnpackBGRA) ||
        !WowOpt_ClientPatchAllowed((const void*)kColorUnpackBGR) ||
        !WowOpt_ClientPatchAllowed((const void*)kColorPackBGRA) ||
        !WowOpt_ClientPatchAllowed((const void*)kColorPackBGR) ||
        !WowOpt_ClientPatchAllowed((const void*)kColorRGBToHSV) ||
        !WowOpt_ClientPatchAllowed((const void*)kColorHSVToRGB) ||
        !WowOpt_ClientPatchAllowed((const void*)kVec3DomAxis) ||
        !WowOpt_ClientPatchAllowed((const void*)kVec3RecAxis)) {
        Log("[ColorUnpack] not installed: No Client Patches is active.");
        return false;
    }

    if (IsBadReadPtr((void*)kColorUnpackBGRA, 16) ||
        IsBadReadPtr((void*)kColorUnpackBGR, 16) ||
        IsBadReadPtr((void*)kColorPackBGRA, 16) ||
        IsBadReadPtr((void*)kColorPackBGR, 16) ||
        IsBadReadPtr((void*)kColorRGBToHSV, 16) ||
        IsBadReadPtr((void*)kColorHSVToRGB, 16) ||
        IsBadReadPtr((void*)kVec3DomAxis, 16) ||
        IsBadReadPtr((void*)kVec3RecAxis, 16)) {
        Log("[ColorUnpack] unreadable targets - not installing.");
        return false;
    }

    static const unsigned char kExp_UnpackBgra[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0xC1, 0x8B, 0x4D, 0x08 };
    static const unsigned char kExp_UnpackBgr[8]  = { 0x55, 0x8B, 0xEC, 0x8B, 0xC1, 0x8B, 0x4D, 0x08 };
    static const unsigned char kExp_PackBgra[8]   = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x80, 0x7D };
    static const unsigned char kExp_PackBgr[8]    = { 0x55, 0x8B, 0xEC, 0x51, 0x8B, 0xC1, 0x8B, 0x4D };
    static const unsigned char kExp_RGBToHSV[8]   = { 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0x57 };
    static const unsigned char kExp_HSVToRGB[8]   = { 0x55, 0x8B, 0xEC, 0xD9, 0xEE, 0x8B, 0x4D, 0x08 };
    static const unsigned char kExp_Dom[8]        = { 0xD9, 0x01, 0xD9, 0xE1, 0xD9, 0x41, 0x04, 0xD9 };
    static const unsigned char kExp_Rec[8]        = { 0xD9, 0x01, 0xD9, 0xE1, 0xD9, 0x41, 0x04, 0xD9 };

    auto CheckPrologue8 = [](void* addr, const unsigned char expected[8], const char* name) -> bool {
        if (IsBadReadPtr(addr, 8) || memcmp(addr, expected, 8) != 0) {
            // prince's client (2026-10-07) declined Color_PackBGRA with this bare line. Whether the
            // bytes are another build's or a detour somebody else put there (E9 or FF 25 first)
            // is what decides if this module can ever run on that client, so say what is there.
            unsigned char got[8] = {};
            if (!IsBadReadPtr(addr, 8)) memcpy(got, addr, 8);
            Log("[ColorUnpack] BAD PROLOGUE for %s at 0x%08X: found %02X %02X %02X %02X %02X %02X %02X %02X, "
                "expected %02X %02X %02X %02X %02X %02X %02X %02X", name, (uintptr_t)addr,
                got[0], got[1], got[2], got[3], got[4], got[5], got[6], got[7],
                expected[0], expected[1], expected[2], expected[3], expected[4], expected[5], expected[6], expected[7]);
            return false;
        }
        return true;
    };

    if (!CheckPrologue8((void*)kColorUnpackBGRA, kExp_UnpackBgra, "Color_UnpackBGRA") ||
        !CheckPrologue8((void*)kColorUnpackBGR,  kExp_UnpackBgr,  "Color_UnpackBGR") ||
        !CheckPrologue8((void*)kColorPackBGRA,   kExp_PackBgra,   "Color_PackBGRA") ||
        !CheckPrologue8((void*)kColorPackBGR,    kExp_PackBgr,    "Color_PackBGR") ||
        !CheckPrologue8((void*)kColorRGBToHSV,   kExp_RGBToHSV,   "Color_RGBToHSV") ||
        !CheckPrologue8((void*)kColorHSVToRGB,   kExp_HSVToRGB,   "Color_HSVToRGB") ||
        !CheckPrologue8((void*)kVec3DomAxis,     kExp_Dom,        "Vec3_DominantAxis") ||
        !CheckPrologue8((void*)kVec3RecAxis,     kExp_Rec,        "Vec3_RecessiveAxis")) {
        Log("[ColorUnpack] unexpected prologue bytes - not installing.");
        return false;
    }

    if (!SelfTestColorUnpack() || !SelfTestColorPack() ||
        !SelfTestRGBToHSV() || !SelfTestHSVToRGB() ||
        !SelfTestDominantAxis() || !SelfTestRecessiveAxis()) {
        Log("[ColorUnpack] startup self-tests failed - not installing.");
        return false;
    }

    int ok = 0;
    if (WineSafe_CreateHook((void*)kColorUnpackBGRA, (void*)Hooked_ColorUnpackBGRA,
                            (void**)&orig_ColorUnpackBGRA) == MH_OK &&
        WO_EnableHook((void*)kColorUnpackBGRA) == MH_OK) {
        ok++;
        SamplingProfiler::RegisterSelfSymbol("ColorUnpackBGRA_SSE2", (const void*)&Hooked_ColorUnpackBGRA);
    }

    if (WineSafe_CreateHook((void*)kColorUnpackBGR, (void*)Hooked_ColorUnpackBGR,
                            (void**)&orig_ColorUnpackBGR) == MH_OK &&
        WO_EnableHook((void*)kColorUnpackBGR) == MH_OK) {
        ok++;
        SamplingProfiler::RegisterSelfSymbol("ColorUnpackBGR_SSE2", (const void*)&Hooked_ColorUnpackBGR);
    }

    if (WineSafe_CreateHook((void*)kColorPackBGRA, (void*)Hooked_ColorPackBGRA,
                            (void**)&orig_ColorPackBGRA) == MH_OK &&
        WO_EnableHook((void*)kColorPackBGRA) == MH_OK) {
        ok++;
        SamplingProfiler::RegisterSelfSymbol("ColorPackBGRA_SSE2", (const void*)&Hooked_ColorPackBGRA);
    }

    if (WineSafe_CreateHook((void*)kColorPackBGR, (void*)Hooked_ColorPackBGR,
                            (void**)&orig_ColorPackBGR) == MH_OK &&
        WO_EnableHook((void*)kColorPackBGR) == MH_OK) {
        ok++;
        SamplingProfiler::RegisterSelfSymbol("ColorPackBGR_SSE2", (const void*)&Hooked_ColorPackBGR);
    }

    if (WineSafe_CreateHook((void*)kColorRGBToHSV, (void*)Hooked_ColorRGBToHSV,
                            (void**)&orig_ColorRGBToHSV) == MH_OK &&
        WO_EnableHook((void*)kColorRGBToHSV) == MH_OK) {
        ok++;
        SamplingProfiler::RegisterSelfSymbol("ColorRGBToHSV_SSE2", (const void*)&Hooked_ColorRGBToHSV);
    }

    if (WineSafe_CreateHook((void*)kColorHSVToRGB, (void*)Hooked_ColorHSVToRGB,
                            (void**)&orig_ColorHSVToRGB) == MH_OK &&
        WO_EnableHook((void*)kColorHSVToRGB) == MH_OK) {
        ok++;
        SamplingProfiler::RegisterSelfSymbol("ColorHSVToRGB_SSE2", (const void*)&Hooked_ColorHSVToRGB);
    }

    if (WineSafe_CreateHook((void*)kVec3DomAxis, (void*)Hooked_Vec3DominantAxis,
                            (void**)&orig_Vec3DominantAxis) == MH_OK &&
        WO_EnableHook((void*)kVec3DomAxis) == MH_OK) {
        ok++;
        SamplingProfiler::RegisterSelfSymbol("Vec3DominantAxis_SSE2", (const void*)&Hooked_Vec3DominantAxis);
    }

    if (WineSafe_CreateHook((void*)kVec3RecAxis, (void*)Hooked_Vec3RecessiveAxis,
                            (void**)&orig_Vec3RecessiveAxis) == MH_OK &&
        WO_EnableHook((void*)kVec3RecAxis) == MH_OK) {
        ok++;
        SamplingProfiler::RegisterSelfSymbol("Vec3RecessiveAxis_SSE2", (const void*)&Hooked_Vec3RecessiveAxis);
    }

    if (ok == 0) {
        Log("[ColorUnpack] not installed: MinHook failed on all targets.");
        return false;
    }

    g_installed = true;
    g_abSubject = AbTest::IsSubject("ColorUnpack", &g_abSubject);

    Log("[ColorUnpack] ACTIVE on %d of 8 color conversion and vector math routines "
        "(Color_UnpackBGRA, Color_UnpackBGR, Color_PackBGRA, Color_PackBGR, Color_RGBToHSV, Color_HSVToRGB, Vec3_DominantAxis, Vec3_RecessiveAxis). "
        "Verifying first %lu calls bit for bit with ongoing resampling.%s",
        ok, kVerifyFirst,
        Config::g_settings.OptAbTest
            ? " The A/B harness alternates the switch between stints."
            : "");
    return true;
#endif
}

void Shutdown() {
#if !TEST_DISABLE_COLOR_UNPACK_SSE2
    if (!g_installed) return;
    MH_DisableHook((void*)kColorUnpackBGRA);
    MH_DisableHook((void*)kColorUnpackBGR);
    MH_DisableHook((void*)kColorPackBGRA);
    MH_DisableHook((void*)kColorPackBGR);
    MH_DisableHook((void*)kColorRGBToHSV);
    MH_DisableHook((void*)kColorHSVToRGB);
    MH_DisableHook((void*)kVec3DomAxis);
    MH_DisableHook((void*)kVec3RecAxis);
    g_installed = false;
#endif
}

void LogStats() {
#if TEST_DISABLE_COLOR_UNPACK_SSE2
    Log("[ColorUnpack] not measured: disabled via feature flag.");
#else
    if (!Config::g_settings.OptColorUnpack) {
        Log("[ColorUnpack] not measured: switched off.");
        return;
    }
    if (!g_installed) {
        Log("[ColorUnpack] not measured: hooks are not installed.");
        return;
    }
    if (g_dead) {
        Log("[ColorUnpack] retired early: evaluation disagreed with the client.");
        return;
    }
    const unsigned long total = g_callsBgra + g_callsBgr + g_callsPackBgra + g_callsPackBgr +
                                g_callsRgbToHsv + g_callsHsvToRgb + g_callsDomAxis + g_callsRecAxis;
    if (total == 0) {
        Log("[ColorUnpack] measured and zero: the hooks are in and none was reached.");
        return;
    }
    Log("[ColorUnpack] calls: UnpackBGRA=%lu (verified=%lu, armed=%s) | "
        "UnpackBGR=%lu (verified=%lu, armed=%s) | "
        "PackBGRA=%lu (verified=%lu, armed=%s) | "
        "PackBGR=%lu (verified=%lu, armed=%s) | "
        "RGBToHSV=%lu (verified=%lu, armed=%s) | "
        "HSVToRGB=%lu (verified=%lu, armed=%s) | "
        "dom_axis=%lu (verified=%lu, armed=%s) | "
        "rec_axis=%lu (verified=%lu, armed=%s)",
        g_callsBgra, g_verifiedBgra, g_armedBgra ? "yes" : "no",
        g_callsBgr, g_verifiedBgr, g_armedBgr ? "yes" : "no",
        g_callsPackBgra, g_verifiedPackBgra, g_armedPackBgra ? "yes" : "no",
        g_callsPackBgr, g_verifiedPackBgr, g_armedPackBgr ? "yes" : "no",
        g_callsRgbToHsv, g_verifiedRgbToHsv, g_armedRgbToHsv ? "yes" : "no",
        g_callsHsvToRgb, g_verifiedHsvToRgb, g_armedHsvToRgb ? "yes" : "no",
        g_callsDomAxis, g_verifiedDomAxis, g_armedDomAxis ? "yes" : "no",
        g_callsRecAxis, g_verifiedRecAxis, g_armedRecAxis ? "yes" : "no");
#endif
}

}  // namespace ColorUnpack
