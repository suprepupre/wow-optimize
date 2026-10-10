// ============================================================================
// m2_sphere_ray_gather_core.h
//
// The body of sub_81CFF0 (0x81CFF0, 0x2C1 bytes, __thiscall, retn 10h), written
// out in double precision so it can be run by the module and by the offline
// harness that calls the client's own copy for comparison.
//
// What the function does. `this` holds a singly linked list of model instances
// (head at +0x114, next at +0x2DC). For each instance that is flagged live
// (byte +0x10 bit 0, id at +0x3C not -1) it takes the instance's bounding
// sphere (centre from a 6-float box, radius at +0x18 of that box), moves the
// centre into world space by the instance matrix at +0xF4, and tests the
// segment (origin a2, direction a3, length a4) against the sphere scaled by
// the matrix's first row. Instances the segment touches are appended as
// 16-byte records {instance, t_enter, t_exit, payload@+0x2E4} to the array at
// this+0x118, with a running index at this+0x11C, and the count is returned.
// When a5 is non-zero and the instance's id is not this+0x14 and its type
// (+0x2D4) is 3 with +0x48 clear, the instance matrix is first rebuilt as
// instance(+0xB4) * this(+0x84).
//
// Arithmetic. The client does this in x87 at 53-bit precision with floats
// loaded and stored through memory; doubles with the same association give the
// same bits. The comparisons are the client's: where it tests the x87 status
// word, an unordered result (NaN) takes the branch the status word's C3/C2/C0
// bits take, which is not always what a C++ relational operator does, so each
// one is written out the way the instruction sequence reads (see the comments).
//
// Side effects reproduced: every instance first has **(inst+0x2D8) = 0 and
// *(inst+0x2D8) = 0 (the client does this before looking at the flag). The
// dry variant omits those and the matrix write-back, and is used to predict the
// output before the client's own routine runs.
// ============================================================================
#pragma once

#include <stdint.h>
#include <math.h>
#include <xmmintrin.h>

namespace SphereRayGatherCore {

typedef float* (__cdecl* PtMat_fn)(float* out, const float* pt, const float* mat);       // sub_4C21B0
typedef float* (__cdecl* MatMul_fn)(float* out, const float* a, const float* b);         // sub_4C1F00
typedef void   (__thiscall* MatCopy_fn)(void* dst, const float* src);                    // sub_407F80

struct Env {
    PtMat_fn ptMat;         // kept for the harness; Run writes the transform out
    MatMul_fn matMul;
    MatCopy_fn matCopy;
    float eps;      // flt_9EA27C
    float half;     // flt_9E2EC4
};

struct Record { uint32_t node; uint32_t v1; uint32_t v2; uint32_t payload; };   // float bits

constexpr int kDryMax = 1024;
struct DryOut {
    int count;
    bool overflow;
    Record rec[kDryMax];
};

template <bool Dry>
static inline int Run(const Env& env, uint8_t* self, const float* o, const float* c, float L, int flag, DryOut* dry) {
    uint8_t* node = *(uint8_t**)(self + 0x114);
    int count = 0;
    uint32_t off = 0;
    uint8_t* const recBase = Dry ? nullptr : *(uint8_t**)(self + 0x118);
    uint32_t* const idxBase = Dry ? nullptr : *(uint32_t**)(self + 0x11C);
    const double Ld = (double)L;
    const double half = (double)env.half;

    while (node) {
        uint8_t* const next = *(uint8_t**)(node + 0x2DC);
        if (next) {
            _mm_prefetch((const char*)next + 0x10, _MM_HINT_T0);
            _mm_prefetch((const char*)next + 0x94, _MM_HINT_T0);
            _mm_prefetch((const char*)next + 0xF4, _MM_HINT_T0);
            _mm_prefetch((const char*)next + 0x2D4, _MM_HINT_T0);
        }
        if (!Dry) {
            **(uint32_t**)(node + 0x2D8) = 0;
            *(uint32_t*)(node + 0x2D8) = 0;
        }
        if (!(node[0x10] & 1)) goto advance;
        {
            const int id = *(int*)(node + 0x3C);
            if (id == -1) goto advance;

            const float* M = (const float*)(node + 0xF4);
            float tmp[16];
            if (flag != 0 && id != *(int*)(self + 0x14)) {
                if (*(int*)(node + 0x2D4) != 3) goto advance;
                if (*(int*)(node + 0x48) != 0) goto advance;
                const float* r = env.matMul(tmp, (const float*)(node + 0xB4), (const float*)(self + 0x84));
                if (!Dry) env.matCopy(node + 0xF4, r);
                else M = r;
            }

            const float* e;
            uint8_t* const q = *(uint8_t**)(*(uint8_t**)(node + 0x2C) + 0x150);
            if (*(int*)(node + 0x2D4) == 3) {
                e = (const float*)(q + 0xBC);
            } else {
                const uint32_t idx = *(uint16_t*)(*(uint8_t**)(node + 0x94) + 0x48);
                e = (const float*)((uint8_t*)(uintptr_t)((idx << 6) + *(uint32_t*)(q + 0x20) + 0x20));
            }

            // fld [e+18h]; fabs; fcomp [eps]; test ah,5; jnp skip  -> skip only when |r| < eps (ordered)
            const float radius = e[6];
            if (fabsf(radius) < env.eps) goto advance;

            float pt[3];
            pt[0] = (float)(((double)e[3] + (double)e[0]) * half);
            pt[1] = (float)(((double)e[4] + (double)e[1]) * half);
            pt[2] = (float)(((double)e[5] + (double)e[2]) * half);
            // sub_4C21B0 written out: ((m[8+k]*z + m[4+k]*y) + x*m[k]) + m[12+k], each sum in double, stored as float.
            float p[3];
            {
                const double x = (double)pt[0], y = (double)pt[1], z = (double)pt[2];
                for (int k = 0; k < 3; ++k) {
                    const double a = (double)M[8 + k] * z + (double)M[4 + k] * y;
                    const double b = a + x * (double)M[k];
                    p[k] = (float)(b + (double)M[12 + k]);
                }
            }

            const double d0 = (double)p[0] - (double)o[0];
            const double d1 = (double)p[1] - (double)o[1];
            const double d2 = (double)p[2] - (double)o[2];
            const double rr = (double)radius;
            const double b0 = (double)M[0], b1 = (double)M[1], b2 = (double)M[2];
            const double lsq = (b0 * b0 + b1 * b1) + b2 * b2;
            const double W = rr * (lsq * rr);
            const double c0 = (double)c[0], c1 = (double)c[1], c2 = (double)c[2];
            const double T = (c0 * d0 + c2 * d2) + c1 * d1;
            const double E0 = c0 * T - d0;
            const double E1 = c1 * T - d1;
            const double E2 = c2 * T - d2;
            const double Q = E0 * E0 + (E1 * E1 + E2 * E2);

            // fcom Q,W ; test ah,41h ; jz reject  -> reject when Q > W (ordered)
            if (Q > W) goto advance;
            const double D = W - Q;
            // fcom 0,T ; jnz pass (0 <= T or unordered) ; else fcomp T*T,D ; jz reject  -> T < 0 and T*T > D
            if (T < 0.0 && T * T > D) goto advance;
            // U = T - L ; fcom U,0 ; jnz pass (U <= 0 or unordered) ; else fcomp U*U,D ; jz reject
            const double U = T - Ld;
            if (U > 0.0 && U * U > D) goto advance;

            const double S = sqrt(D);
            const double A1 = T - S;
            // fcom A1,0 ; test ah,5 ; jp keep  -> keep A1 unless A1 < 0 (ordered)
            const double Aa = (A1 < 0.0) ? 0.0 : A1;
            double V1;
            if (Aa > Ld) V1 = Ld;                       // fcomp Aa,L ; jnz continue (<= or unordered)
            else V1 = (A1 < 0.0) ? 0.0 : A1;

            const double A2 = T + S;
            const double Bb = (A2 < 0.0) ? 0.0 : A2;    // fcom 0,A2 ; jnz keep (0 <= A2 or unordered)
            double V2;
            if (Bb > Ld) V2 = Ld;
            else V2 = (A2 < 0.0) ? 0.0 : A2;

            const float f1 = (float)V1, f2 = (float)V2;
            uint32_t b1v, b2v;
            memcpy(&b1v, &f1, 4);
            memcpy(&b2v, &f2, 4);
            if (Dry) {
                if (count >= kDryMax) { dry->overflow = true; dry->count = count; return count; }
                Record& r = dry->rec[count];
                r.node = (uint32_t)(uintptr_t)node;
                r.v1 = b1v;
                r.v2 = b2v;
                r.payload = *(uint32_t*)(node + 0x2E4);
            } else {
                uint8_t* const rec = recBase + off;
                *(uint32_t*)(rec + 4) = b1v;
                *(uint32_t*)rec = (uint32_t)(uintptr_t)node;
                *(uint32_t*)(rec + 8) = b2v;
                *(uint32_t*)(rec + 12) = *(uint32_t*)(node + 0x2E4);
                idxBase[count] = (uint32_t)count;
            }
            ++count;
            off += 16;
        }
    advance:
        node = next;
    }
    if (Dry) { dry->count = count; dry->overflow = false; }
    return count;
}

} // namespace SphereRayGatherCore
