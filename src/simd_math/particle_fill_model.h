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
constexpr unsigned kOffBox       = 0x218;   // six floats: min x, min y, min z, max x, max y, max z

constexpr uint32_t kFlagQuad     = 0x000004;   // this emitter writes a quad
constexpr uint32_t kFlagOther    = 0x000008;   // a second kind of geometry follows the quad
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
    if (!(f & kFlagQuad) || (f & kFlagOther) || (f & kFlagFacing)) return Kind::Unsupported;
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

struct Quad {
    double   X[4], Y[4], Z[4];     // as the client holds them before they go out as floats
    float    x[4], y[4], z[4];
    float    u[4], v[4];
    uint32_t colour;
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
    bool bad = false;
    for (int i = 0; i < 4; ++i)
        bad |= (q.x[i] != q.x[i]) | (q.y[i] != q.y[i]) | (q.z[i] != q.z[i]) |
               (q.u[i] != q.u[i]) | (q.v[i] != q.v[i]);
    return !bad;
}

// 0x97C444: no spin, corners along one point. Four trips round the loop at 0x97C44A.
inline void BuildFlat(const char* em, const Constants& k, const Frame& f, const Cell& c, Quad* q) {
    const double w = f.w, h = f.h;
    const double du = Rd<float>(em, kOffDu), dv = Rd<float>(em, kOffDv);
    for (int i = 0; i < 4; ++i) {
        const double X = (double)k.corner[2 * i] * w + (double)f.px;
        const double Y = (double)k.corner[2 * i + 1] * h + (double)f.py;
        q->X[i] = X; q->Y[i] = Y; q->Z[i] = (double)f.pz;
        q->x[i] = (float)X; q->y[i] = (float)Y; q->z[i] = f.pz;
        q->u[i] = (float)((double)k.uvCorner[2 * i] * du + c.u0d);
        q->v[i] = (float)((double)k.uvCorner[2 * i + 1] * dv + c.v0d);
    }
    q->colour = f.colour;
}

// 0x97C2BF: no spin, corners placed along two axes.
inline void BuildAxes(const char* em, const Constants& k, const Frame& f, const Cell& c, Quad* q) {
    const double w = f.w, h = f.h;
    const double du = Rd<float>(em, kOffDu), dv = Rd<float>(em, kOffDv);
    const double a90 = k.axes[0], a94 = k.axes[1], a98 = k.axes[2];
    const double a9c = k.axes[3], aA0 = k.axes[4], aA4 = k.axes[5];
    for (int i = 0; i < 4; ++i) {
        const double cxw = (double)k.corner[2 * i] * w;
        const double cyh = (double)k.corner[2 * i + 1] * h;
        const double s0 = a9c * cyh + cxw * a90;
        const double s1 = cyh * aA0 + cxw * a94;
        const double s2 = cyh * aA4 + cxw * a98;
        const double X = s0 + (double)f.px;
        const double Y = s1 + (double)f.py;
        const double Z = s2 + (double)f.pz;
        q->X[i] = X; q->Y[i] = Y; q->Z[i] = Z;
        q->x[i] = (float)X; q->y[i] = (float)Y; q->z[i] = (float)Z;
        q->u[i] = (float)((double)k.uvCorner[2 * i] * du + c.u0d);
        q->v[i] = (float)((double)k.uvCorner[2 * i + 1] * dv + (double)c.v0f);
    }
    q->colour = f.colour;
}

// The angle handed to sub_6F7A60 (0x97C59E..0x97C5B2), rounded to the float it is passed as.
inline float SpinAngle(const float* particle, uintptr_t particleAddr, uint32_t flags,
                       float rate, float rot0) {
    double a = (double)particle[0] * (double)rate + (double)rot0;
    if ((flags & kFlagSpinSign) && (particleAddr & 0x20)) a = -a;
    return (float)a;
}

// 0x97C7B3..0x97CC0D: the four corners rotated by the angle whose sine and cosine are given.
inline void BuildSpin(const char* em, const Frame& f, const Cell& c, Quad* q) {
    const double w = f.w, h = f.h, s = f.sinv, co = f.cosv;
    const double cw = co * w, ch = co * h, sw = w * s, sh = h * s;
    const double px = f.px, py = f.py;
    q->X[0] = (px - cw) - sh;   q->Y[0] = (py - sw) + ch;
    q->X[1] = (px - cw) + sh;   q->Y[1] = (py - sw) - ch;
    q->X[2] = (cw + px) - sh;   q->Y[2] = (ch + sw) + py;
    q->X[3] = (cw + sh) + px;   q->Y[3] = (sw + py) - ch;
    const double du = Rd<float>(em, kOffDu), dv = Rd<float>(em, kOffDv);
    const double u0 = c.u0f, v0 = c.v0f;
    for (int i = 0; i < 4; ++i) {
        q->Z[i] = (double)f.pz;
        q->x[i] = (float)q->X[i]; q->y[i] = (float)q->Y[i]; q->z[i] = f.pz;
    }
    q->u[0] = c.u0f;               q->v[0] = c.v0f;
    q->u[1] = c.u0f;               q->v[1] = (float)(v0 + dv);
    q->u[2] = (float)(u0 + du);    q->v[2] = c.v0f;
    q->u[3] = (float)(u0 + du);    q->v[3] = (float)(v0 + dv);
    q->colour = f.colour;
}

// The emitter's box, one vertex after another, each edge moved only by a strict
// ordered comparison against the value the client still holds in a register.
inline void GrowBox(float* box, double X, double Y, double Z) {
    if ((double)box[0] > X) box[0] = (float)X;    // 0x218
    if ((double)box[1] > Y) box[1] = (float)Y;    // 0x21C
    if (Z < (double)box[2]) box[2] = (float)Z;    // 0x220
    if ((double)box[3] < X) box[3] = (float)X;    // 0x224
    if ((double)box[4] < Y) box[4] = (float)Y;    // 0x228
    if (Z > (double)box[5]) box[5] = (float)Z;    // 0x22C
}

// Where the four vertex streams are written, and how far each has got.
struct Streams {
    char*   ptr[4];       // position, normal, colour, uv
    int32_t stride[4];
    int32_t count;
};

constexpr int kElemBytes[4] = { 12, 12, 4, 8 };

inline void Commit(const Quad& q, const Constants& k, float* box, Streams* s) {
    for (int v = 0; v < 4; ++v) {
        char* p = s->ptr[0] + v * s->stride[0];
        memcpy(p, &q.x[v], 4); memcpy(p + 4, &q.y[v], 4); memcpy(p + 8, &q.z[v], 4);
        GrowBox(box, q.X[v], q.Y[v], q.Z[v]);
        char* n = s->ptr[1] + v * s->stride[1];
        memcpy(n, k.normal, 12);
        memcpy(s->ptr[2] + v * s->stride[2], &q.colour, 4);
        char* t = s->ptr[3] + v * s->stride[3];
        memcpy(t, &q.u[v], 4); memcpy(t + 4, &q.v[v], 4);
    }
    for (int i = 0; i < 4; ++i) s->ptr[i] += 4 * s->stride[i];
    s->count += 4;
}

}  // namespace ParticleFillModel
