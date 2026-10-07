// ============================================================================
// particle_fill_model.h
//
// The arithmetic of sub_97BE80, the per-particle vertex fill, with no client
// calls and no globals of its own, so that the DLL and the offline harness run
// the same source. Every function here reproduces a stretch of the client's
// x87 code at the client's precision: the control word is 0x027F, so each
// intermediate is a double rounded once, and every `fst dword` rounds that
// double to a float. Doubles in SSE2 are the same arithmetic. Which operand a
// sum is built from, and in which order, is the whole of the precision
// question, so each expression below names the address it was read from.
//
// Not here: the track evaluation (sub_979D60 / sub_979E90), the spin values
// (sub_97A130) and the sine and cosine (sub_6F7A60). They are calls the client
// makes and this keeps making.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstring>
#include <cmath>
#include <emmintrin.h>

namespace ParticleFillModel {

// Emitter fields, from the disassembly.
constexpr unsigned kOffShift     = 0x00C;   // int: right shift that turns the tile number into a row
constexpr unsigned kOffDu        = 0x010;   // float: width of one tile in texture space
constexpr unsigned kOffDv        = 0x014;   // float: height of one tile
constexpr unsigned kOffSpinRate  = 0x0C8;   // float: spin rate; zero with kOffSpinVary zero means no spin
constexpr unsigned kOffSpinVary  = 0x0CC;   // float
constexpr unsigned kOffCells     = 0x124;   // uint: tile count, a power of two
constexpr unsigned kOffFlags     = 0x134;
constexpr unsigned kOffAgeScale  = 0x13C;   // float
constexpr unsigned kOffCullBelow = 0x140;   // float
constexpr unsigned kOffTableBias = 0x144;   // float
constexpr unsigned kOffTableMul  = 0x148;   // float
constexpr unsigned kOffSizeMul   = 0x1EC;   // float, used when kFlagSizeMul is set
constexpr unsigned kOffTailAge   = 0x0AC;   // float: the cap on the age that scales a tail's direction
constexpr unsigned kOffBox       = 0x218;   // six floats: min x, min y, min z, max x, max y, max z

constexpr uint32_t kFlagQuad     = 0x000004;   // this emitter writes a quad
constexpr uint32_t kFlagOther    = 0x000008;   // a second quad follows the first: the tail, built along the velocity
constexpr uint32_t kFlagTailCap  = 0x020000;   // the tail's direction is scaled by min(kOffTailAge, age)
constexpr uint32_t kFlagSizeMul  = 0x000400;
constexpr uint32_t kFlagAxes     = 0x004000;   // corners are placed along two axes, not one point
constexpr uint32_t kFlagSpinSign = 0x010000;   // the spin direction depends on the particle's address
constexpr uint32_t kFlagFacing   = 0x200000;   // the quad is turned to face along the velocity
constexpr uint32_t kFlagColourFn = 0x1000000;  // the track evaluator to call

template <class T> inline T Rd(const char* base, unsigned off) {
    T v;
    memcpy(&v, base + off, sizeof(T));
    return v;
}

// Client data the arithmetic reads. The DLL points these at the client's own
// tables; the harness points them at its own.
struct Constants {
    const float*    table;       // flt_DCE690: 128 per-particle scales
    const float*    corner;      // flt_B2D5B4: four (x, y) pairs
    const float*    uvCorner;    // flt_B2D5D4: four (u, v) pairs
    const float*    axes;        // flt_B2D590..B2D5A4: six floats
    const uint32_t* normal;      // dword_B2D540: the three words written as every normal
    const float*    matrix;      // flt_B2D550: 4x4, row vectors, translation in [12..14]
    const float*    tailEps;     // flt_AA2CEC: below this squared length the tail is a plain quad
};

// ---- the stretch 0x97BE96..0x97BF08: which table entry, and whether to skip ----

// False: the client returns 0 for this particle and writes nothing.
inline bool Select(const char* em, const float* particle, uintptr_t particleAddr,
                   const float* table, unsigned* index) {
    const float cull    = Rd<float>(em, kOffCullBelow);
    const float tableMul = Rd<float>(em, kOffTableMul);
    // `fld1 / fcomp [edi+140h] / test ah,41h / jz`: 1.0 > cull, strictly and ordered.
    const bool below = 1.0 > (double)cull;
    unsigned idx = 0;
    // When it is not below, `fcom [edi+148h]` against zero sends an exact zero to index 0
    // (0x97BED5); everything else, NaN included, goes through the age product.
    if (below || !((double)tableMul == 0.0)) {
        const double age = (double)Rd<float>(em, kOffAgeScale) * (double)particle[0];
        const float  ageF = (float)age;                                  // fstp [ebp+var_54]
        const int32_t t = _mm_cvtss_si32(_mm_set_ss(ageF));              // fistp: nearest even
        idx = (unsigned)(((uint32_t)(particleAddr >> 5) + (uint32_t)t) & 0x7F);
    }
    *index = idx;
    // `fld [edi+140h] / fcomp flt_DCE690[esi*4] / test ah,5 / jp`: skipped only
    // when cull < table[idx], strictly and ordered, and only when below was true.
    if (below && ((double)cull < (double)table[idx])) return false;
    return true;
}

// ---- 0x97BF7E..0x97BFC5: the size, from the evaluator's size and the table ----

inline void Scale(const char* em, float tableValue, float wIn, float hIn, float* w, float* h) {
    const double sc = (double)tableValue * (double)Rd<float>(em, kOffTableMul)
                      + (double)Rd<float>(em, kOffTableBias);
    const double wD = (double)wIn * sc;
    const double hD = sc * (double)hIn;
    if (Rd<uint32_t>(em, kOffFlags) & kFlagSizeMul) {
        const double m = (double)Rd<float>(em, kOffSizeMul);
        *w = (float)(wD * m);
        *h = (float)(hD * m);
    } else {
        *w = (float)wD;
        *h = (float)hD;
    }
}

// sub_4C21B0: a point through a 4x4, in the client's order of addition.
inline void Transform(const float* in, const float* m, float* out) {
    const double x = in[0], y = in[1], z = in[2];
    out[0] = (float)((((double)m[8]  * z + (double)m[4] * y) + x * (double)m[0]) + (double)m[12]);
    out[1] = (float)((((double)m[9]  * z + (double)m[5] * y) + x * (double)m[1]) + (double)m[13]);
    out[2] = (float)((((double)m[10] * z + (double)m[6] * y) + x * (double)m[2]) + (double)m[14]);
}

// 0x97BF5A..0x97BF78: red and blue trade places when the device says so.
inline uint32_t SwapRedBlue(uint32_t c) {
    return (c & 0xFF00FF00u) | ((c & 0xFFu) << 16) | ((c >> 16) & 0xFFu);
}

// ---- the quad ----

enum class Kind { Unsupported, Flat, Axes, Spin };

// What the client would do with this emitter. Flat and Axes need no spin; Spin
// needs the sine and cosine of an angle; the rest are left to the client.
inline Kind Classify(const char* em) {
    const uint32_t f = Rd<uint32_t>(em, kOffFlags);
    if (!(f & kFlagQuad) || (f & kFlagFacing)) return Kind::Unsupported;
    // `fldz / fcom [edi+0C8h] / test ah,44h / jp` then the same against 0CCh: both
    // must be exactly equal to zero, so NaN means spin.
    const bool still = (Rd<float>(em, kOffSpinRate) == 0.0f) && (Rd<float>(em, kOffSpinVary) == 0.0f);
    if (still) return (f & kFlagAxes) ? Kind::Axes : Kind::Flat;
    return (f & kFlagAxes) ? Kind::Unsupported : Kind::Spin;
}

struct Frame {
    float    px, py, pz;      // the particle, through the matrix
    float    w, h;            // size after scaling
    uint32_t colour;
    int32_t  tile;            // the evaluator's tile number
    float    sinv, cosv;      // Spin only
};

// Four corners. Positions are kept twice: as the doubles the client's register holds, which the
// bounding box is compared against, and as the floats it stores. x and y travel as a pair in one
// register (lane 0, lane 1) because every operation on them is the same operation.
struct Quad {
    __m128d  xy[4];
    double   zd[4];
    __m128   pos[4];      // x, y as floats in lanes 0 and 1
    float    zf[4];
    __m128   uv[4];       // u, v as floats in lanes 0 and 1
    uint32_t colour;
    bool     zSame;       // the four z are one value
};

// 0x97BFF1..0x97C02D: where the tile sits in texture space.
struct Cell { double u0d, v0d; float u0f, v0f; };

inline Cell CellOrigin(const char* em, int32_t tile) {
    const uint32_t cells = Rd<uint32_t>(em, kOffCells);
    const int32_t masked = (int32_t)((cells - 1u) & (uint32_t)tile);
    double x = (double)masked;
    if (masked < 0) x += 4294967296.0;                                   // flt_9E23AC
    Cell c;
    c.u0d = x * (double)Rd<float>(em, kOffDu);
    c.u0f = (float)c.u0d;                                                // fst [ebp+var_44]
    const int32_t row = tile >> (Rd<int32_t>(em, kOffShift) & 31);       // sar eax, cl
    c.v0d = (double)row * (double)Rd<float>(em, kOffDv);
    c.v0f = (float)c.v0d;                                                // fst [ebp+var_40]
    return c;
}

inline bool AllFinite(const Quad& q) {
    // A NaN in x87 and in SSE2 keeps different payloads when two of them meet; the
    // client's answer is the only one to give for those.
    __m128 bad = _mm_setzero_ps();
    for (int i = 0; i < 4; ++i) {
        bad = _mm_or_ps(bad, _mm_cmpunord_ps(q.pos[i], q.pos[i]));
        bad = _mm_or_ps(bad, _mm_cmpunord_ps(q.uv[i], q.uv[i]));
    }
    if ((_mm_movemask_ps(bad) & 3) != 0) return false;
    for (int i = 0; i < (q.zSame ? 1 : 4); ++i)
        if (q.zf[i] != q.zf[i]) return false;
    return true;
}

inline __m128d Pair(double lo, double hi) { return _mm_set_pd(hi, lo); }
inline __m128d WidenPair(const float* p) {
    return _mm_cvtps_pd(_mm_castsi128_ps(_mm_loadl_epi64((const __m128i*)p)));
}

// 0x97C444: no spin, corners along one point. Four trips round the loop at 0x97C44A.
// x = cx*w + px and y = cy*h + py, u = cu*du + u0, v = cv*dv + v0: a product of two floats is
// exact in a double and the sum is rounded once, which is what the packed operations do.
inline void BuildFlat(const char* em, const Constants& k, const Frame& f, const Cell& c, Quad* q) {
    const __m128d wh   = Pair(f.w, f.h);
    const __m128d pxy  = Pair(f.px, f.py);
    const __m128d dudv = Pair(Rd<float>(em, kOffDu), Rd<float>(em, kOffDv));
    const __m128d uv0  = Pair(c.u0d, c.v0d);
    for (int i = 0; i < 4; ++i) {
        const __m128d xy = _mm_add_pd(_mm_mul_pd(WidenPair(k.corner + 2 * i), wh), pxy);
        q->xy[i]  = xy;
        q->pos[i] = _mm_cvtpd_ps(xy);
        q->zd[i]  = (double)f.pz;
        q->zf[i]  = f.pz;
        q->uv[i]  = _mm_cvtpd_ps(_mm_add_pd(_mm_mul_pd(WidenPair(k.uvCorner + 2 * i), dudv), uv0));
    }
    q->colour = f.colour;
    q->zSame = true;
}

// 0x97C2BF: no spin, corners placed along two axes.
//   s0 = a9c*cyh + cxw*a90,  s1 = cyh*aA0 + cxw*a94,  s2 = cyh*aA4 + cxw*a98
inline void BuildAxes(const char* em, const Constants& k, const Frame& f, const Cell& c, Quad* q) {
    const __m128d wh    = Pair(f.w, f.h);
    const __m128d pxy   = Pair(f.px, f.py);
    const __m128d dudv  = Pair(Rd<float>(em, kOffDu), Rd<float>(em, kOffDv));
    const __m128d uv0   = Pair(c.u0d, (double)c.v0f);        // the stored float v, not the double
    const __m128d cyRow = Pair(k.axes[3], k.axes[4]);        // a9c, aA0
    const __m128d cxRow = Pair(k.axes[0], k.axes[1]);        // a90, a94
    const __m128d aA4   = _mm_set_sd(k.axes[5]);
    const __m128d a98   = _mm_set_sd(k.axes[2]);
    const __m128d pz    = _mm_set_sd(f.pz);
    for (int i = 0; i < 4; ++i) {
        const __m128d p   = _mm_mul_pd(WidenPair(k.corner + 2 * i), wh);   // cxw, cyh
        const __m128d cx2 = _mm_unpacklo_pd(p, p);
        const __m128d cy2 = _mm_unpackhi_pd(p, p);
        const __m128d s01 = _mm_add_pd(_mm_mul_pd(cy2, cyRow), _mm_mul_pd(cx2, cxRow));
        const __m128d s2  = _mm_add_sd(_mm_mul_sd(cy2, aA4), _mm_mul_sd(cx2, a98));
        const __m128d xy  = _mm_add_pd(s01, pxy);
        const __m128d z   = _mm_add_sd(s2, pz);
        q->xy[i]  = xy;
        q->pos[i] = _mm_cvtpd_ps(xy);
        q->zd[i]  = _mm_cvtsd_f64(z);
        q->zf[i]  = _mm_cvtss_f32(_mm_cvtsd_ss(_mm_setzero_ps(), z));
        q->uv[i]  = _mm_cvtpd_ps(_mm_add_pd(_mm_mul_pd(WidenPair(k.uvCorner + 2 * i), dudv), uv0));
    }
    q->colour = f.colour;
    q->zSame = false;
}

// The angle handed to sub_6F7A60 (0x97C59E..0x97C5B2), rounded to the float it is passed as.
inline float SpinAngle(const float* particle, uintptr_t particleAddr, uint32_t flags,
                       float rate, float rot0) {
    double a = (double)particle[0] * (double)rate + (double)rot0;
    if ((flags & kFlagSpinSign) && (particleAddr & 0x20)) a = -a;
    return (float)a;
}

// 0x97C7B3..0x97CC0D: the four corners rotated by the angle whose sine and cosine are given.
// The client builds each corner as two sums of three terms in a fixed order; the same order is
// kept here, with a subtraction written as the addition of a negated term (exact, including
// zero, because the sign bit is flipped and not the value taken from zero).
//   V0  (px - cw) - sh,   (py - sw) + ch        V1  (px - cw) + sh,   (py - sw) - ch
//   V2  (cw + px) - sh,   (ch + sw) + py        V3  (cw + sh) + px,   (sw + py) - ch
inline void BuildSpin(const char* em, const Frame& f, const Cell& c, Quad* q) {
    // [cw, ch] = cos * [w, h] and [sw, sh] = sin * [w, h]: products of two floats, exact.
    const __m128d wh   = Pair(f.w, f.h);
    const __m128d cwch = _mm_mul_pd(_mm_set1_pd((double)f.cosv), wh);
    const __m128d swsh = _mm_mul_pd(_mm_set1_pd((double)f.sinv), wh);
    const __m128d P    = Pair(f.px, f.py);
    const __m128d lo   = _mm_castsi128_pd(_mm_set_epi64x(0, (long long)0x8000000000000000ull));  // flips lane 0
    const __m128d hi   = _mm_castsi128_pd(_mm_set_epi64x((long long)0x8000000000000000ull, 0));  // flips lane 1
    const __m128d cwsw = _mm_unpacklo_pd(cwch, swsh);                        // cw, sw
    const __m128d shch = _mm_unpackhi_pd(swsh, cwch);                        // sh, ch
    const __m128d nsh  = _mm_xor_pd(shch, lo);                               // -sh, ch
    const __m128d nch  = _mm_xor_pd(shch, hi);                               // sh, -ch
    const __m128d t    = _mm_sub_pd(P, cwsw);                                // px - cw, py - sw
    q->xy[0] = _mm_add_pd(t, nsh);                                           // (px - cw) - sh, (py - sw) + ch
    q->xy[1] = _mm_add_pd(t, nch);                                           // (px - cw) + sh, (py - sw) - ch
    const __m128d r2 = _mm_add_pd(cwch, _mm_shuffle_pd(P, swsh, 0));         // cw + px, ch + sw
    q->xy[2] = _mm_add_pd(r2, _mm_shuffle_pd(nsh, P, 2));                    // (cw + px) - sh, (ch + sw) + py
    const __m128d r3 = _mm_add_pd(cwsw, _mm_shuffle_pd(shch, P, 2));         // cw + sh, sw + py
    q->xy[3] = _mm_add_pd(r3, _mm_shuffle_pd(P, nch, 2));                    // (cw + sh) + px, (sw + py) - ch
    for (int i = 0; i < 4; ++i) {
        q->pos[i] = _mm_cvtpd_ps(q->xy[i]);
        q->zd[i] = (double)f.pz;
        q->zf[i] = f.pz;
    }
    const __m128d dudv = Pair(Rd<float>(em, kOffDu), Rd<float>(em, kOffDv));
    const __m128  a  = _mm_set_ps(0.0f, 0.0f, c.v0f, c.u0f);                // u0, v0 as stored
    const __m128  b  = _mm_cvtpd_ps(_mm_add_pd(Pair(c.u0f, c.v0f), dudv));   // u0 + du, v0 + dv
    const __m128  ab = _mm_unpacklo_ps(a, b);                               // a0, b0, a1, b1
    q->uv[0] = a;
    q->uv[1] = _mm_shuffle_ps(ab, ab, _MM_SHUFFLE(3, 3, 3, 0));            // u0, v0 + dv
    q->uv[2] = _mm_shuffle_ps(ab, ab, _MM_SHUFFLE(3, 3, 2, 1));            // u0 + du, v0
    q->uv[3] = b;
    q->colour = f.colour;
    q->zSame = true;
}

// Where the four vertex streams are written, and how far each has got.
struct Streams {
    char*   ptr[4];       // position, normal, colour, uv
    int32_t stride[4];
    int32_t count;
};

constexpr int kElemBytes[4] = { 12, 12, 4, 8 };

// The emitter's box, exactly as the client does it: one corner after another, an edge moving
// only on a strict ordered comparison of the double the client still holds in a register against
// the float it stored last, and the float of that double going in.
inline void GrowBoxSequential(const Quad& q, float* box) {
    for (int v = 0; v < 4; ++v) {
        double xy[2];
        _mm_storeu_pd(xy, q.xy[v]);
        if ((double)box[0] > xy[0]) box[0] = (float)xy[0];     // 0x218
        if ((double)box[1] > xy[1]) box[1] = (float)xy[1];     // 0x21C
        if (q.zd[v] < (double)box[2]) box[2] = (float)q.zd[v]; // 0x220
        if ((double)box[3] < xy[0]) box[3] = (float)xy[0];     // 0x224
        if ((double)box[4] < xy[1]) box[4] = (float)xy[1];     // 0x228
        if (q.zd[v] > (double)box[5]) box[5] = (float)q.zd[v]; // 0x22C
    }
}

// The same result with the four corners reduced first. An edge that moves ends at the float of the
// extreme, and one a later corner would have moved again lands on the same float because rounding
// is monotonic; min and max below keep the earlier of two equal values, as the client's strict
// comparisons do. One case differs, and only in the sign of a zero: when the extreme is exactly
// zero and an earlier corner was a tiny coordinate of the other sign, below half the smallest
// float, the client has already stored -0.0 (or +0.0) from that corner and a zero of the other
// sign is not strictly beyond it, where the reduction would store the extreme's own zero. They
// compare equal and nothing downstream can tell them apart, but they are different bytes. An
// extreme that is exactly zero is therefore handed to the sequential form.
inline void GrowBox(const Quad& q, float* box) {
    __m128d mn = q.xy[0], mx = q.xy[0];
    for (int i = 1; i < 4; ++i) {
        mn = _mm_min_pd(q.xy[i], mn);        // new < old ? new : old
        mx = _mm_max_pd(q.xy[i], mx);        // new > old ? new : old
    }
    __m128d zmn = _mm_set_sd(q.zd[0]), zmx = zmn;
    if (!q.zSame) {
        for (int i = 1; i < 4; ++i) {
            zmn = _mm_min_sd(_mm_set_sd(q.zd[i]), zmn);
            zmx = _mm_max_sd(_mm_set_sd(q.zd[i]), zmx);
        }
    }
    const __m128d zero = _mm_setzero_pd();
    const int exactZero = _mm_movemask_pd(_mm_or_pd(_mm_cmpeq_pd(mn, zero), _mm_cmpeq_pd(mx, zero))) |
                          _mm_movemask_pd(_mm_or_pd(_mm_cmpeq_sd(zmn, zero), _mm_cmpeq_sd(zmx, zero))) ;
    if (exactZero) {
        GrowBoxSequential(q, box);
        return;
    }
    const int lo = _mm_movemask_pd(_mm_cmpgt_pd(WidenPair(box + 0), mn));    // 0x218, 0x21C
    if (lo & 1) box[0] = (float)_mm_cvtsd_f64(mn);
    if (lo & 2) box[1] = (float)_mm_cvtsd_f64(_mm_unpackhi_pd(mn, mn));
    const int hi = _mm_movemask_pd(_mm_cmplt_pd(WidenPair(box + 3), mx));    // 0x224, 0x228
    if (hi & 1) box[3] = (float)_mm_cvtsd_f64(mx);
    if (hi & 2) box[4] = (float)_mm_cvtsd_f64(_mm_unpackhi_pd(mx, mx));
    if (_mm_comilt_sd(zmn, _mm_cvtss_sd(_mm_setzero_pd(), _mm_set_ss(box[2])))) box[2] = (float)_mm_cvtsd_f64(zmn);   // 0x220
    if (_mm_comigt_sd(zmx, _mm_cvtss_sd(_mm_setzero_pd(), _mm_set_ss(box[5])))) box[5] = (float)_mm_cvtsd_f64(zmx);   // 0x22C
}

// ---- 0x97CC10..0x97D35A: the second quad, for an emitter with flag 0x8 ----
//
// After the ordinary quad the client builds four more vertices along the particle's velocity.
// The velocity, negated, goes through the upper 3x3 of the view matrix and is scaled by E, which
// is the emitter's float at +0xAC, or the particle's age when flag 0x20000 is set and that is
// smaller. The first two components decide the direction on screen. If their squared length is
// not below the client's epsilon (and a NaN is not), the four vertices are an ordinary flat
// quad with the tile's own texture origin; otherwise the quad is stretched along that
// direction by the size, from the point and from the point moved by the scaled vector.
//
// Every expression names its address in the comments of the harness that generated the
// reference (gen_tail.py); the order of operands in a sum is the client's. A product of two
// floats is exact in a double, so only the sums and the divisions round.
//
//   vx' = F(((b*m4 + c*m8) + a*m0) * E)   a, b, c the negated velocity, m the matrix floats
//   vy' = F(((b*m5 + c*m9) + a*m1) * E)
//   vz' = F(E * ((b*m6 + c*m10) + a*m2))
//   L2  = vy'*vy' + vx'*vx'          r = 1 / sqrt(L2)
//   A   = vx' * (w * r)              B = vy' * (r * h)      (doubles; Af, Bf their floats)
//   P0x = F(vx' + px)                P0y = F(vy' + py)      Q = vz' + pz
//   corner 0 (px - B,   py + A,   pz)    corner 1 (Bf + px, py - Af, pz)
//   corner 2 (P0x - Bf, Af + P0y, Q)     corner 3 (P0x + Bf, P0y - Af, Q)
//   u = F(du * cu + u0f), v = F(dv * cv + v0f), with u0f and v0f the floats of the texture origin
//   of the evaluator's second number (not the first, which the ordinary quad uses).
inline void BuildTail(const char* em, const Constants& k, const Frame& f, int32_t extra,
                      const float* particle, Quad* q) {
    const uint32_t flags = Rd<uint32_t>(em, kOffFlags);
    double E = (double)Rd<float>(em, kOffTailAge);
    const double age = (double)particle[0];
    if ((flags & kFlagTailCap) && E > age) E = age;                          // fcom, ah&41 clear

    const double a = -(double)particle[4], b = -(double)particle[5], c = -(double)particle[6];
    const float* m = k.matrix;
    const float vx = (float)((((b * (double)m[4]) + (c * (double)m[8])) + (a * (double)m[0])) * E);
    const float vy = (float)((((b * (double)m[5]) + (c * (double)m[9])) + (a * (double)m[1])) * E);
    const float vz = (float)(E * (((b * (double)m[6]) + (c * (double)m[10])) + (a * (double)m[2])));

    // The tile's origin from the second number, as floats (fstp [var_50], [var_4C]).
    const Cell tc = CellOrigin(em, extra);
    const double L2 = ((double)vy * (double)vy) + ((double)vx * (double)vx);
    const double eps = (double)*k.tailEps;
    if (!(eps <= L2)) {                                                      // fcomp, jp: below, or NaN
        Cell fc;
        fc.u0d = (double)tc.u0f; fc.v0d = (double)tc.v0f; fc.u0f = tc.u0f; fc.v0f = tc.v0f;
        BuildFlat(em, k, f, fc, q);
        return;
    }
    const double r = 1.0 / sqrt(L2);
    const double A = (double)vx * ((double)f.w * r);
    const double B = (double)vy * (r * (double)f.h);
    const float Af = (float)A, Bf = (float)B;
    const double px = f.px, py = f.py, pz = f.pz;
    const float P0x = (float)((double)vx + px);
    const float P0y = (float)((double)vy + py);
    const double Qz = (double)vz + pz;
    const double x[4] = { px - B, (double)Bf + px, (double)P0x - (double)Bf, (double)P0x + (double)Bf };
    const double y[4] = { py + A, py - (double)Af, (double)Af + (double)P0y, (double)P0y - (double)Af };
    const double z[4] = { pz, pz, Qz, Qz };
    const __m128d dudv = Pair(Rd<float>(em, kOffDu), Rd<float>(em, kOffDv));
    const __m128d uv0  = Pair((double)tc.u0f, (double)tc.v0f);
    for (int i = 0; i < 4; ++i) {
        q->xy[i]  = Pair(x[i], y[i]);
        q->pos[i] = _mm_cvtpd_ps(q->xy[i]);
        q->zd[i]  = z[i];
        q->zf[i]  = (float)z[i];
        q->uv[i]  = _mm_cvtpd_ps(_mm_add_pd(_mm_mul_pd(WidenPair(k.uvCorner + 2 * i), dudv), uv0));
    }
    q->colour = f.colour;
    q->zSame = false;
}

inline void Commit(const Quad& q, const Constants& k, float* box, Streams* s) {
    for (int v = 0; v < 4; ++v) {
        char* p = s->ptr[0] + v * s->stride[0];
        _mm_storel_pi((__m64*)p, q.pos[v]);
        memcpy(p + 8, &q.zf[v], 4);
        memcpy(s->ptr[1] + v * s->stride[1], k.normal, 12);
        memcpy(s->ptr[2] + v * s->stride[2], &q.colour, 4);
        _mm_storel_pi((__m64*)(s->ptr[3] + v * s->stride[3]), q.uv[v]);
    }
    GrowBox(q, box);
    for (int i = 0; i < 4; ++i) s->ptr[i] += 4 * s->stride[i];
    s->count += 4;
}

}  // namespace ParticleFillModel
