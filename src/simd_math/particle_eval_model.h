// ============================================================================
// particle_eval_model.h
//
// sub_979E90, the per-particle track evaluator that sub_97BE80 calls when the
// emitter's colour-function flag (0x1000000) is clear, and the five routines
// it calls (sub_9795D0 colour, sub_9794F0 alpha, sub_979480 size, sub_979560
// an integer track, sub_9793B0 / sub_979330 the key search), plus the two
// small generators it draws from (sub_4C1510 seeds, sub_464580 steps). All of
// it is a function of the emitter, the particle's first words and one constant
// table, and writes only its five outputs, so the DLL and the offline harness
// run the same source.
//
// Precision: the client's control word is 0x027F, so every x87 intermediate is
// a double rounded once, a `fstp dword` rounds that double to a float and a
// reload is exact. Scalar doubles under /fp:precise /arch:SSE2 are the same
// arithmetic, operation for operation. Each expression names the address it
// was read from, and the order of operands in a sum or product is the client's.
//
// What is not reproduced bit for bit is declined, and the caller then runs
// the client's own routine: a non-finite key fraction or output, a track with
// a null array, a key search that would read outside the key array.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstring>
#include <cmath>
#include <emmintrin.h>

// The offline harness defines this to count which branches its inputs reach; in the DLL it is
// nothing.
#ifndef PEM_COV
#define PEM_COV(n)
#endif

namespace ParticleEvalModel {

// Emitter fields the evaluator reads, from the disassembly.
constexpr unsigned kOffLifeBase   = 0x0A4;   // float
constexpr unsigned kOffLifeScale  = 0x0A8;   // float
constexpr unsigned kOffColourTrk  = 0x0D8;   // track pointers
constexpr unsigned kOffAlphaTrk   = 0x0DC;
constexpr unsigned kOffSizeTrk    = 0x0E0;
constexpr unsigned kOffSizeVary   = 0x0E4;   // float
constexpr unsigned kOffSizeVary2  = 0x0E8;   // float
constexpr unsigned kOffTileTrk    = 0x0EC;
constexpr unsigned kOffExtraTrk   = 0x0F0;
constexpr unsigned kOffColourKeys = 0x0F4;   // inline colour values (12 bytes each) when flag 0x10
constexpr unsigned kOffCellsPerRow = 0x120;  // uint
constexpr unsigned kOffCells      = 0x124;   // uint
constexpr unsigned kOffAlphaScale = 0x130;   // float
constexpr unsigned kOffFlags      = 0x134;

constexpr uint32_t kFlagInlineColours = 0x000010;
constexpr uint32_t kFlagRandomTile    = 0x100000;
constexpr uint32_t kFlagTwoDraw       = 0x800000;

// The client's constants.
constexpr float kC     = 3.0518509e-05f;    // flt_9EA0B4 = 0x38000100, one over 32767
constexpr float kMinLife = 0.001f;          // flt_9E1134 = 0x3A83126F
constexpr float k255   = 255.0f;            // flt_9E30C0 = 0x437F0000
constexpr float kTwo   = 2.0f;              // flt_A4040C
constexpr float kFloor = 1.0000000e-4f;     // flt_9E8CD0 = 0x38D1B717
constexpr float kOne   = 1.0f;              // flt_9E1130

struct Out {
    uint32_t colour;
    float    w, h;       // adjacent: the client writes two floats from &w
    int32_t  tile;
    int32_t  extra;
};

// The floats the client rounds to integers or bytes, before it does. The harness compares them
// bit for bit, which catches an order of operations that the quantised outputs would hide for
// all but a one in a billion input. Null in the DLL.
struct Taps {
    float x, y, z;       // the interpolated colour channels
    float alpha;         // alpha after both scales
    float tile, extra;   // an integer track's value before its rounding
    bool  haveColour, haveTile, haveExtra;
};

template <class T> inline T Rd(const void* base, unsigned off) {
    T v;
    memcpy(&v, (const char*)base + off, sizeof(T));
    return v;
}
inline const void* Ptr(const void* base, unsigned off) { return Rd<const void*>(base, off); }

// A track: [0] key count, [4] pointer to int16 times, [8] value count, [0xC] pointer to values.
struct Track {
    uint32_t       keys;
    const int16_t* times;
    uint32_t       vals;
    const void*    values;
};
inline Track ReadTrack(const void* t) {
    Track k;
    k.keys = Rd<uint32_t>(t, 0);
    k.times = (const int16_t*)Ptr(t, 4);
    k.vals = Rd<uint32_t>(t, 8);
    k.values = Ptr(t, 0xC);
    return k;
}

inline bool Finite(double d) { return d - d == 0.0; }

// ---- sub_9793B0 with sub_979330 (0x979330..0x9793AF): the two keys either side of t and the
// fraction between them, which the client leaves in st(0) as a double. ----
inline bool Keys(const Track& k, float t, uint32_t* i0, uint32_t* i1, double* f) {
    const double td = (double)t;
    const double c = (double)kC;
    if (k.keys == 2) {                                   // 0x979460: t itself
        PEM_COV(0);
        *i0 = 0; *i1 = 1; *f = td;
        return Finite(*f);
    }
    if (!k.times) return false;
    if (k.keys == 3) {                                   // 0x979415
        const double m = (double)k.times[1] * c;
        if (td < m) { PEM_COV(1); *i0 = 0; *i1 = 1; *f = td / m; }                 // fcom, jp not taken: t < m
        else        { PEM_COV(2); *i0 = 1; *i1 = 2; *f = (td - m) / (1.0 - m); }   // greater, equal or unordered
        return Finite(*f);
    }
    // sub_979330: a binary search over the times scaled by kC, in the client's unsigned arithmetic.
    const uint32_t n = k.keys;
    const uint32_t last = n - 1;
    uint32_t lo = 0, hi = last;
    uint32_t idx;
    if (last == 0) {
        idx = 0;
    } else {
        for (;;) {
            const uint32_t mid = (hi + lo) >> 1;
            if (mid >= n) return false;                  // the client would read outside the array
            const double x = (double)k.times[mid] * c;
            if (!(x > td)) {                             // test ah,41h / jnz: less, equal or unordered
                lo = mid + 1;
                if (lo >= last) { idx = mid; break; }    // cmp edx,edi / jnb
                const double x2 = (double)k.times[mid + 1] * c;
                if (x2 > td || x2 != x2 || td != td) { idx = mid; break; }   // test ah,41h / jp: greater or unordered
            } else {
                hi = mid - 1;
            }
            if (!(lo < hi)) { idx = lo; break; }         // cmp edx,esi / jb
        }
    }
    if (idx + 1 >= n) return false;
    PEM_COV(3);
    *i0 = idx;
    *i1 = idx + 1;
    // 0x9793E1..0x97940F: the time difference is a 16-bit subtraction, sign-extended.
    const int32_t ti = k.times[idx];
    const int32_t dts = (int16_t)(uint16_t)((uint32_t)k.times[idx + 1] - (uint32_t)(uint16_t)k.times[idx]);
    const double T0 = (double)ti * c;
    *f = (td - T0) / (c * (double)dts);
    return Finite(*f);
}

inline uint8_t LowByte(float v) { return (uint8_t)_mm_cvtss_si32(_mm_set_ss(v)); }   // fistp, nearest even

// ---- sub_9795D0: the colour ----
inline bool Colour(const char* em, float t, uint32_t* colour, Taps* tap) {
    const void* tp = Ptr(em, kOffColourTrk);
    if (!tp) return false;
    const Track k = ReadTrack(tp);
    uint8_t b0, b1, b2;
    if (k.vals == 1) {                                   // 0x9795E6
        if (!k.values) return false;
        const float* v = (const float*)k.values;
        b0 = LowByte(v[2]); b1 = LowByte(v[1]); b2 = LowByte(v[0]);
    } else {
        uint32_t i0, i1; double f;
        if (!Keys(k, t, &i0, &i1, &f)) return false;
        const float* base = (Rd<uint32_t>(em, kOffFlags) & kFlagInlineColours)
                          ? (const float*)(em + kOffColourKeys) : (const float*)k.values;
        if (!base) return false;
        const float* v0 = base + i0 * 3;
        const float* v1 = base + i1 * 3;
        const double d0 = (double)v1[0] - (double)v0[0];
        const double d1 = (double)v1[1] - (double)v0[1];
        const double d2 = (double)v1[2] - (double)v0[2];
        const float x = (float)(d0 * f + (double)v0[0]);
        const float y = (float)(d1 * f + (double)v0[1]);
        const float z = (float)(d2 * f + (double)v0[2]);
        b0 = LowByte(z); b1 = LowByte(y); b2 = LowByte(x);
        if (tap) { tap->x = x; tap->y = y; tap->z = z; tap->haveColour = true; }
        PEM_COV(4);
    }
    *colour = (uint32_t)b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16) | 0xFF000000u;
    return true;
}

// ---- sub_9794F0: the alpha before the emitter's scale, a double in st(0) ----
inline bool Alpha(const char* em, float t, double* a) {
    const void* tp = Ptr(em, kOffAlphaTrk);
    if (!tp) return false;
    const Track k = ReadTrack(tp);
    const double c = (double)kC;
    if (!k.values) return false;
    const int16_t* v = (const int16_t*)k.values;
    if (k.vals == 1) {                                   // 0x9794FD
        *a = (double)v[0] * c;
        return true;
    }
    uint32_t i0, i1; double f;
    if (!Keys(k, t, &i0, &i1, &f)) return false;
    const double V0 = (double)v[i0] * c;                 // fmul st(1), st
    const double V1 = c * (double)v[i1];                 // fimul
    *a = f * (V1 - V0) + V0;                             // fsub, fmulp, faddp
    return true;
}

// ---- sub_979480: the size pair ----
inline bool Size(const char* em, float t, float* w, float* h) {
    const void* tp = Ptr(em, kOffSizeTrk);
    if (!tp) return false;
    const Track k = ReadTrack(tp);
    if (!k.values) return false;
    const float* v = (const float*)k.values;
    if (k.vals == 1) {                                   // two dwords copied unchanged
        memcpy(w, v, 4);
        memcpy(h, v + 1, 4);
        return true;
    }
    uint32_t i0, i1; double f;
    if (!Keys(k, t, &i0, &i1, &f)) return false;
    const double dx = (double)v[i1 * 2] - (double)v[i0 * 2];
    const double dy = (double)v[i1 * 2 + 1] - (double)v[i0 * 2 + 1];
    *w = (float)(dx * f + (double)v[i0 * 2]);
    *h = (float)(dy * f + (double)v[i0 * 2 + 1]);
    return true;
}

// ---- sub_979560: an integer-valued track ----
inline bool IntTrack(const void* tp, float t, int32_t* out, float* tapped, bool* have) {
    const Track k = ReadTrack(tp);
    if (!k.values) return false;
    const uint16_t* v = (const uint16_t*)k.values;
    if (k.vals == 1) { *out = (int32_t)v[0]; return true; }
    uint32_t i0, i1; double f;
    if (!Keys(k, t, &i0, &i1, &f)) return false;
    const int32_t a = (int32_t)v[i0];
    const int32_t b = (int32_t)v[i1];
    const float r = (float)(f * (double)(b - a) + (double)a);          // fimul, fiadd, fstp dword
    *out = _mm_cvtss_si32(_mm_set_ss(r));                              // fistp
    if (tapped) { *tapped = r; *have = true; }
    PEM_COV(5);
    return true;
}

// ---- sub_4C1510 and sub_464580: the generator the evaluator draws its variation from ----
struct Rng {
    uint32_t s0, s1;
};

inline Rng RngSeed(uint32_t seed) {                       // sub_4C1510
    auto hi = [](uint32_t m, uint32_t x) { return (uint32_t)(((uint64_t)m * x) >> 32); };
    uint32_t edx = hi(0x22B63CBFu, seed) >> 3;
    edx *= 0x3B;
    uint32_t edi = seed - edx;
    edx = hi(0x4325C53Fu, seed) >> 4;
    edx *= 0x3D;
    uint32_t eax = seed - edx;
    eax = eax + eax;
    eax = eax + eax;
    edi <<= 10;
    edi |= eax;
    edx = hi(0x3521CFB3u, seed);
    eax = seed - edx;
    eax >>= 1;
    eax += edx;
    eax >>= 5;
    eax *= 0x35;
    edx = seed - eax;
    edx <<= 0x12;
    edi |= edx;
    edx = hi(0xAE4C415Du, seed) >> 5;
    eax = edx << 4;
    eax += seed;
    eax += edx;
    eax <<= 0x1A;
    edi |= eax;
    Rng r;
    r.s0 = seed;
    r.s1 = edi;
    return r;
}

inline uint32_t Rol(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

// The table at 0x009F1700; indexed by byte offset, read as unaligned dwords.
inline uint32_t RngStep(Rng* r, const uint8_t* tbl) {      // sub_464580
    const uint32_t s1 = r->s1;
    int32_t ebx = (int32_t)((s1 >> 8) & 0xFF);
    int32_t edx = (int32_t)((s1 >> 16) & 0xFF);
    int32_t ecx = (int32_t)(s1 >> 24);
    int32_t esi = (int32_t)(s1 & 0xFF);
    edx -= 0x0C;
    ecx -= 4;
    if (ecx < 0) ecx += 0xBC;
    ebx -= 0x18;
    if (edx < 0) edx += 0xD4;
    esi -= 0x1C;
    if (ebx < 0) ebx += 0xEC;
    if (esi < 0) esi += 0xF4;
    auto rd = [&](int32_t off) { uint32_t v; memcpy(&v, tbl + off, 4); return v; };
    const uint32_t a = Rol(rd(ecx), 1);
    const uint32_t b = Rol(rd(ebx), 3);
    const uint32_t c = Rol(rd(edx), 2);
    const uint32_t x = ((b ^ c) ^ rd(esi)) ^ a;
    r->s1 = ((((((uint32_t)ecx << 8) | (uint32_t)edx) << 8) | (uint32_t)ebx) << 8) | (uint32_t)esi;
    r->s0 = r->s0 + x;
    return r->s0;
}

// The variation factor both tail paths build from one draw: a float in [1, 2) from the low 23
// bits, then 2 - x for a negative draw and x - 2 otherwise (0x979FE7.. and 0x97A0B7..).
inline double Spread(uint32_t draw) {
    const uint32_t bits = (draw & 0x7FFFFFu) | 0x3F800000u;
    float x;
    memcpy(&x, &bits, 4);
    return ((int32_t)draw < 0) ? ((double)kTwo - (double)x) : ((double)x - (double)kTwo);
}

// ---- sub_979E90 ----
// Writes nothing the client would not and nothing at all when it declines.
inline bool Eval(const char* em, const float* particle, const uint8_t* rngTable, Out* out, Taps* tap = nullptr) {
    const uint32_t flags = Rd<uint32_t>(em, kOffFlags);

    // 0x979E9C..0x979ED9: the particle's age as a fraction of its life.
    const int16_t lifeVar = Rd<int16_t>(particle, 0x1C);
    double life = ((double)lifeVar * (double)Rd<float>(em, kOffLifeScale)) * (double)kC
                  + (double)Rd<float>(em, kOffLifeBase);
    const double minLife = (double)kMinLife;
    if (!(minLife < life)) life = minLife;               // fcom, jp: 0.001 not below life, or unordered
    const float t = (float)((double)Rd<float>(particle, 0) / life);

    Rng rng = RngSeed((uint32_t)Rd<uint16_t>(particle, 0x1E));

    uint32_t colour;
    if (!Colour(em, t, &colour, tap)) return false;

    double a;
    if (!Alpha(em, t, &a)) return false;
    const float af = (float)((a * (double)Rd<float>(em, kOffAlphaScale)) * (double)k255);
    colour = (colour & 0x00FFFFFFu) | ((uint32_t)LowByte(af) << 24);
    if (tap) tap->alpha = af;

    float w, h;
    if (!Size(em, t, &w, &h)) return false;

    int32_t tile = 0, extra = 0;
    const void* tileTrk = Ptr(em, kOffTileTrk);
    if (!tileTrk) return false;
    if (Rd<uint32_t>(tileTrk, 0) != 0) {
        if (!IntTrack(tileTrk, t, &tile, tap ? &tap->tile : nullptr, tap ? &tap->haveTile : nullptr)) return false;
    } else if (flags & kFlagRandomTile) {
        const uint32_t r = RngStep(&rng, rngTable);
        const uint32_t mul = Rd<uint32_t>(em, kOffCells) * Rd<uint32_t>(em, kOffCellsPerRow);
        tile = (int32_t)(uint32_t)(((uint64_t)r * (uint64_t)mul) >> 32);
    }
    const void* extraTrk = Ptr(em, kOffExtraTrk);
    if (!extraTrk) return false;
    if (Rd<uint32_t>(extraTrk, 0) != 0) {
        if (!IntTrack(extraTrk, t, &extra, tap ? &tap->extra : nullptr, tap ? &tap->haveExtra : nullptr)) return false;
    }

    const double floorD = (double)kFloor;
    float ow, oh;
    if (flags & kFlagTwoDraw) {                          // 0x979FD8..0x97A0AB
        const double r1 = Spread(RngStep(&rng, rngTable));
        const double r2 = Spread(RngStep(&rng, rngTable));
        const double p2 = r2 * (double)Rd<float>(em, kOffSizeVary);
        const double q = (double)Rd<float>(em, kOffSizeVary2) * r1;
        const double P = p2 + 1.0;
        const double Q = q + 1.0;
        const double Qc = (floorD < Q) ? Q : floorD;     // fcom, jnp: M below Q keeps Q
        const double Pc = (floorD < P) ? P : floorD;
        PEM_COV(floorD < Q ? 6 : 7);
        PEM_COV(floorD < P ? 8 : 9);
        ow = (float)(Pc * (double)w);
        oh = (float)(Qc * (double)h);
    } else {                                             // 0x97A0AE..0x97A127
        const double r = Spread(RngStep(&rng, rngTable));
        const double P = r * (double)Rd<float>(em, kOffSizeVary) + (double)kOne;
        const double Pc = (floorD > P) ? floorD : P;     // fcom, test ah,41h / jnz: M above P replaces it
        PEM_COV(floorD > P ? 10 : 11);
        ow = (float)((double)w * Pc);
        oh = (float)(Pc * (double)h);
    }
    if (!Finite((double)ow) || !Finite((double)oh)) return false;

    out->colour = colour;
    out->w = ow;
    out->h = oh;
    out->tile = tile;
    out->extra = extra;
    return true;
}

}  // namespace ParticleEvalModel
