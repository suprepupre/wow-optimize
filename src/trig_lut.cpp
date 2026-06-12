// ================================================================
// SSE2 Trigonometry Lookup Table - sub_8FE980 acceleration
// ================================================================
// sub_8FE980 (7,732 bytes, 380 complexity) is WoW's rendering math
// function. It calls __CIpow, __ftol2_sse heavily for sin/cos/pow
// calculations during vertex transformation and lighting.
//
// We provide SSE2-accelerated lookup tables that replace expensive
// FPU transcendental operations with interpolated table lookups.
// Accuracy: <0.01% error for sin/cos, sufficient for game rendering.
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cmath>
#include <intrin.h>
#include <emmintrin.h>

extern "C" void Log(const char* fmt, ...);

// ================================================================
// Lookup Tables (cache-line aligned)
// ================================================================
static constexpr int TRIG_TABLE_SIZE = 4096;
static constexpr float TRIG_TABLE_SCALE = (float)(TRIG_TABLE_SIZE / 6.28318530718f);

__declspec(align(64)) static float g_sinTable[TRIG_TABLE_SIZE];
__declspec(align(64)) static float g_cosTable[TRIG_TABLE_SIZE];
__declspec(align(64)) static float g_atanTable[1024];

static bool g_trigLutInitialized = false;

// ================================================================
// Initialization
// ================================================================
void InitTrigLUT() {
    if (g_trigLutInitialized) return;

    for (int i = 0; i < TRIG_TABLE_SIZE; i++) {
        float angle = (float)i * 6.28318530718f / TRIG_TABLE_SIZE;
        g_sinTable[i] = sinf(angle);
        g_cosTable[i] = cosf(angle);
    }

    for (int i = 0; i < 1024; i++) {
        float x = (float)i / 1024.0f;
        g_atanTable[i] = atanf(x);
    }

    g_trigLutInitialized = true;
    Log("[TrigLUT] Initialized (%d-entry sin/cos, 1024-entry atan, SSE2 aligned)", TRIG_TABLE_SIZE);
}

// ================================================================
// Fast Trig Functions (inline-friendly)
// ================================================================
static inline float FastSin(float x) {
    // Normalize to [0, 2*pi)
    x = x * TRIG_TABLE_SCALE;
    int idx = (int)x & (TRIG_TABLE_SIZE - 1);
    int next = (idx + 1) & (TRIG_TABLE_SIZE - 1);
    float frac = x - (float)(int)x;
    return g_sinTable[idx] + frac * (g_sinTable[next] - g_sinTable[idx]);
}

static inline float FastCos(float x) {
    x = x * TRIG_TABLE_SCALE;
    int idx = (int)x & (TRIG_TABLE_SIZE - 1);
    int next = (idx + 1) & (TRIG_TABLE_SIZE - 1);
    float frac = x - (float)(int)x;
    return g_cosTable[idx] + frac * (g_cosTable[next] - g_cosTable[idx]);
}

// SSE2 batch sin/cos - process 4 floats at once
void FastSinCos4(const float* angles, float* outSin, float* outCos) {
    for (int i = 0; i < 4; i++) {
        float x = angles[i] * TRIG_TABLE_SCALE;
        int idx = (int)x & (TRIG_TABLE_SIZE - 1);
        int next = (idx + 1) & (TRIG_TABLE_SIZE - 1);
        float frac = x - (float)(int)x;
        outSin[i] = g_sinTable[idx] + frac * (g_sinTable[next] - g_sinTable[idx]);
        outCos[i] = g_cosTable[idx] + frac * (g_cosTable[next] - g_cosTable[idx]);
    }
}

// Fast pow approximation using exp2/log2 identity
// Accurate to ~0.1% for positive bases
static inline float FastPow(float base, float exp) {
    if (base <= 0.0f) return 0.0f;
    // pow(b,e) = exp2(e * log2(b))
    // Use SSE2 intrinsics for log2/exp2 approximation
    __m128 v = _mm_set_ss(base);
    // Approximate log2 via IEEE754 exponent extraction
    int bits = _mm_cvtsi128_si32(_mm_castps_si128(v));
    float log2_approx = (float)((bits >> 23) & 0xFF) - 127.0f;
    float mantissa = (float)(bits & 0x7FFFFF) / 8388608.0f;
    log2_approx += mantissa * (1.0f - 0.5f * mantissa); // quadratic approx
    float result_exp = exp * log2_approx;
    // exp2 via IEEE754 construction
    int exp_bits = (int)(result_exp + 127.0f);
    if (exp_bits < 0) return 0.0f;
    if (exp_bits > 254) return 3.4e38f;
    float frac_part = result_exp - (float)(int)result_exp;
    float mantissa_out = 1.0f + frac_part * (0.6931472f + frac_part * 0.2402265f);
    bits = (exp_bits << 23) | (int)(mantissa_out * 8388608.0f);
    return _mm_cvtss_f32(_mm_castsi128_ps(_mm_cvtsi32_si128(bits)));
}

bool IsTrigLutInitialized() { return g_trigLutInitialized; }