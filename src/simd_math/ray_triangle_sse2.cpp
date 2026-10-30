// ============================================================================
// Module: ray_triangle_sse2
// Description: SSE2 double transcription of the client's ray-triangle test.
// ============================================================================
// sub_983490 is Moller-Trumbore, and it is the shared ray-triangle test for the
// whole collision family: sub_7C6600, sub_7C6790, sub_7C6C30 and sub_7C6D50 all
// call it, plus sub_81E110. That family is about 6.4% of executing main-thread
// time in the corrected profile, and this is the part of it that does the real
// arithmetic - the two outcode passes around it are already replaced.
//
// It is 231 instructions of x87 with fifteen fxch and five fnstsw. Every fnstsw
// is a status word round trip feeding a conditional jump, and the jumps are on
// whether a ray misses a triangle, which is not predictable. The transcription
// below has no fnstsw and no stack juggling: comisd sets the flags directly.
// ---------------------------------------------------------------------------
// The width, which is measured rather than assumed
//
// The client keeps its intermediates in x87 registers, so their width is the
// precision control field, not the type of anything in memory. That field is
// 53-bit here, which makes a double lane exact. It is worth saying how that is
// known, because IDirect3D9::CreateDevice sets it to 24-bit unless the caller
// passes D3DCREATE_FPU_PRESERVE and this client renders through D3D9.
//
// Three modules already compare the bytes of a float result against the client
// rather than a predicate, and all three armed in both field sessions to hand:
// anim_vec3_track at 30453 and 31049 agreements, anim_quat_unpack at 30560 and
// 31317, quat_lerp at 24292 and 29936 bit-identical. anim_vec3_track computes
// in double. At 24-bit the client would round every intermediate to a float's
// mantissa while that module rounds to a double's, and a lerp would diverge in
// the first handful of calls rather than after ninety thousand byte-exact
// agreements. x87_precision_check.cpp now reads the register and prints it, so
// a machine where this is not true says so.
// ---------------------------------------------------------------------------
// Which intermediates the client rounds to float, and which it does not
//
// This is the part that cannot be reasoned about and had to be traced. The
// client stores some intermediates with fstp - rounding to float and dropping
// the register - and others with fst, which rounds a copy and keeps the wide
// value. A few it never stores at all. Writing the algebra out cleanly, in one
// width, gives a different answer:
//
//   p.x   fstp to var_20   -> enters the determinant AS A FLOAT
//   p.y   never stored     -> stays wide
//   p.z   never stored     -> stays wide
//   e1.z  fst  to var_24   -> the wide copy is used for the determinant,
//                             the float copy for the second cross product
//   e2.*  fst  to var_14/10/C -> wide for the first cross product,
//                             float for the distance
//   1/det fstp to arg_8    -> every barycentric is scaled by the FLOAT
//   u     fst  to arg_8    -> wide for its two range tests, float for u+v
//
// So the same quantity appears at two widths within one call, on purpose or by
// accident, and both have to be reproduced. F() below is that rounding.
// ---------------------------------------------------------------------------
// The associations, also traced
//
// A reversed subtract is spelled almost the same as a plain one. fsubp st(1),
// st computes st(1) - st(0); fsubrp st(1), st computes st(0) - st(1). Three of
// the six cross product terms here use the reversed form, and reading them as
// the plain form negates p.y, p.z and q.z. A reference implementation written
// from the same misreading agrees with the transcription perfectly, so that is
// not what caught it: aiming a hundred and twenty thousand rays at the centroid
// of their own triangle and getting a hit on 0.8% of them caught it. An
// arithmetic identity that has to hold is worth more than a second opinion
// derived from the same source.
//
//   det   = (e1.z*p.z + e1.y*p.y) + e1.x*p.x_f
//   u_raw = (T.y*p.y  + T.z*p.z ) + T.x *p.x_f
//   v_raw = (d.y*q.y  + d.z*q.z ) + d.x *q.x
//   t_raw = (q.z*e2.z_f + q.y*e2.y_f) + q.x*e2.x_f
//
// Left operand first in every sum. Multiplication is exactly commutative in
// IEEE so the order inside a product does not matter; the order of the two
// additions does, and it is not the order the algebra is usually written in.
// ---------------------------------------------------------------------------
// The predicates, read from the raw disassembly
//
// The determinant test rejects when the value lies BETWEEN the two constants,
// which are -1e-6 and +1e-6: the near-parallel case. It is written here in the
// client's own direction so that a NaN determinant continues, the way an
// unordered fcom leaves both masked bits set and takes the jump.
//
// The barycentric tests are the same shape: reject on an ordered comparison
// only, continue on unordered.
// ---------------------------------------------------------------------------
// The return value is one byte
//
// Every exit is mov al, 1 or xor al, al and none of them clears the rest of
// EAX. Reading all thirty-two bits of a hooked original like this one is what
// retired the sort key cache on its first comparison in every session; the
// verification here compares AL.
// ---------------------------------------------------------------------------
// Measured, before any of it reaches a client
//
// The same algorithm was compiled a second time with /arch:IA32 /fp:precise,
// which makes MSVC emit x87 - fld, fmul, fsub, fcomp, fnstsw against the stack
// at the control word's precision, which is what sub_983490 is. The compiler's
// output is a close stand-in for the client's hand-written original: 228
// instructions against 231, six fnstsw against five, eleven fxch against
// fifteen. Slightly fewer register exchanges than the client, so it is if
// anything the faster of the two, which makes the figure below a floor.
//
// Four million calls each, half of them rays aimed at their own triangle so the
// deep path is exercised and half random so the early rejects are:
//
//     SSE2 double   21.90 ns/call
//     x87           41.40 ns/call
//     speedup            1.89x
//
// And the two agree. Over 20000 cases with 10062 hits, no verdict differed and
// no returned distance differed by a bit. That is worth more than the timing:
// the x87 build came from the same trace but through a different instruction
// set and a different compiler path, so agreeing with it is a check on the
// reading of the disassembly that the Python reference could not give - that one
// was written by hand from the same reading and carried the same three sign
// errors until an arithmetic identity caught them.
//
// This is the function measured, not a frame. What share of a frame it is
// depends on how often the collision family runs, which is what the A/B harness
// answers.
// ---------------------------------------------------------------------------
// Verification
//
// The function is pure apart from two optional out pointers, so both versions
// simply run and their answers are compared - the byte of the return, and the
// floats each wrote. Nothing is saved, restored or predicted. The client's own
// answer is handed back for the whole checking phase, so a session that never
// arms behaves exactly like an unhooked one.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cmath>

#include "ray_triangle_sse2.h"
#include "x87_precision_check.h"
#include "self_bench.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace RayTriangle {

namespace {

constexpr uintptr_t kTarget16    = 0x00983490;
constexpr uintptr_t kTarget32    = 0x009836B0;
constexpr uintptr_t kTargetPlane = 0x00982FB0;
constexpr uintptr_t kTargetPoly  = 0x009830D0;

// flt_AA2E70 and flt_A32B48, read out of the image: -1e-6f and +1e-6f.
const float kDetLo = -9.9999997e-07f;
const float kDetHi =  9.9999997e-07f;

constexpr long kVerifyFirst  = 20000;
constexpr unsigned kResample = 4095;   // one call in this many, as a mask

typedef int (__cdecl* Compare_t)(const void* ray, const void* verts,
                                 const void* tri, void* outT, void* outUV,
                                 float tol);

typedef char (__cdecl* RayPlane_t)(const float* ray, const float* plane,
                                   float* outT, float* outPoint, float tol);

typedef char (__cdecl* PointInPoly_t)(const float* point, const float* verts,
                                      uint32_t count, uint32_t axis);

struct Channel {
    const char*   name;
    const char*   symbolName;
    uintptr_t     target;
    void*         origTest;
    bool          installed;
    bool          armed;
    bool          dead;
    bool          abSubject;
    int           benchSlot;

    unsigned long calls;
    unsigned long verified;
    unsigned long hits;
    unsigned long stood;
    unsigned long caught;
};

// Read on the hot paths, written by the A/B harness. File scope on purpose.
static bool g_abSubject = false;
static volatile LONG g_bypass = 0;

static Channel g_ch16    = { "16-bit",      "RayTriIntersect16_SSE2", kTarget16,    nullptr, false, false, false, false, -1, 0, 0, 0, 0, 0 };
static Channel g_ch32    = { "32-bit",      "RayTriIntersect32_SSE2", kTarget32,    nullptr, false, false, false, false, -1, 0, 0, 0, 0, 0 };
static Channel g_chPlane = { "RayPlane",    "RayPlaneIntersect_SSE2", kTargetPlane, nullptr, false, false, false, false, -1, 0, 0, 0, 0, 0 };
static Channel g_chPoly  = { "PointInPoly", "PointInPolygon2D_SSE2",  kTargetPoly,  nullptr, false, false, false, false, -1, 0, 0, 0, 0, 0 };

// Rounds to float and back, which is what an fstp to a dword slot does.
inline double F(double x) { return (double)(float)x; }

struct Out {
    float t;
    float u;
    float v;
    bool  wroteT;
    bool  wroteUV;
};

// A verbatim transcription. Every rounding and every association above is
// reproduced; nothing here is simplified.
template <typename IndexT>
int Test(const float* ray, const float* verts, const IndexT* tri,
         bool wantT, bool wantUV, float tolIn, Out* out) {
    out->wroteT = false;
    out->wroteUV = false;

    const double tol     = (double)tolIn;
    const double negTol  = -tol;                 // fchs then fstp: exact
    const double onePlus = F(tol + 1.0);         // fadd 1.0 then fstp to float

    const float* v0 = verts + 3 * (size_t)tri[0];
    const float* v1 = verts + 3 * (size_t)tri[1];
    const float* v2 = verts + 3 * (size_t)tri[2];

    const double e1x = (double)v1[0] - (double)v0[0];
    const double e1y = (double)v1[1] - (double)v0[1];
    const double e1z = (double)v1[2] - (double)v0[2];
    const double e2x = (double)v2[0] - (double)v0[0];
    const double e2y = (double)v2[1] - (double)v0[1];
    const double e2z = (double)v2[2] - (double)v0[2];

    // fst keeps the wide value and rounds a copy; both copies are used later.
    const double e1z_f = F(e1z);
    const double e2x_f = F(e2x);
    const double e2y_f = F(e2y);
    const double e2z_f = F(e2z);

    const double dx = (double)ray[3];
    const double dy = (double)ray[4];
    const double dz = (double)ray[5];

    // p = dir x e2. Only p.x is stored with fstp, so only p.x loses the wide
    // value. The operand order matters and is not what the mnemonic suggests:
    // fsubp st(1), st is st(1) - st(0), while fsubrp st(1), st is the reverse,
    // st(0) - st(1). Reading the second as the first flips the sign of two of
    // these three components. See the note on how that was caught.
    const double px_f = F(dy * e2z - dz * e2y);   // fsubp  at 0x00983507
    const double py   = dz * e2x - dx * e2z;      // fsubrp at 0x00983516
    const double pz   = dx * e2y - dy * e2x;      // fsubrp at 0x00983524

    const double det = (e1z * pz + e1y * py) + e1x * px_f;

    // Reject only on an ordered comparison, so a NaN determinant carries on
    // exactly as the client's two fcom sequences let it.
    if ((double)kDetLo < det && (double)kDetHi > det) return 0;

    const double invDet = F(1.0 / det);

    const double tx = (double)ray[0] - (double)v0[0];
    const double ty = (double)ray[1] - (double)v0[1];
    const double tz = (double)ray[2] - (double)v0[2];

    const double u = ((ty * py + tz * pz) + tx * px_f) * invDet;
    const double u_f = F(u);                 // fst: the wide u is still live

    if (negTol > u) return 0;
    if (u > onePlus) return 0;

    // q = T x e1, and note e1.z arrives here as the float copy while e1.x and
    // e1.y are still the wide ones.
    const double qx = e1z_f * ty - tz * e1y;   // fsubp  at 0x009835C2
    const double qy = tz * e1x - e1z_f * tx;   // fsubp  at 0x009835CD
    const double qz = tx * e1y - ty * e1x;     // fsubrp at 0x009835D7

    const double v = ((dy * qy + dz * qz) + dx * qx) * invDet;

    if (negTol > v) return 0;
    if ((v + u_f) > onePlus) return 0;

    if (wantT) {
        const double t = ((qz * e2z_f + qy * e2y_f) + qx * e2x_f) * invDet;
        out->t = (float)t;
        out->wroteT = true;
    }
    if (wantUV) {
        out->u = (float)u_f;
        out->v = (float)v;
        out->wroteUV = true;
    }
    return 1;
}

bool ReadableRange(const void* p, size_t bytes) {
    const uintptr_t a = (uintptr_t)p;
    return a >= 0x10000 && a < 0xFFE00000 && (a + bytes) > a;
}

// Faults the guard caught, while checking or after. The fallback is the
// client's own test, which reads the same ray, vertices and triangle indices, so
// a fault here is one the fallback would take too; the armed path calls Test
// without an exception frame once kVerifyFirst comparisons have run guarded and
// this is still zero. If it ever is not, every armed call stays guarded.
//
// The guard lives in its own function so that Hooked_Test has no __try at all:
// one anywhere in it puts the frame into its prologue for every call.
template <typename IndexT>
__declspec(noinline) bool TestGuardedCall(const void* ray, const void* verts,
                                          const void* tri, bool wantT, bool wantUV,
                                          float tol, Out* o, int* r,
                                          unsigned long& caughtCounter) {
    __try {
        *r = Test<IndexT>((const float*)ray, (const float*)verts, (const IndexT*)tri,
                          wantT, wantUV, tol, o);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ++caughtCounter;
        return false;
    }
}

template <typename IndexT>
inline int Hooked_TestImpl(const void* ray, const void* verts, const void* tri,
                           void* outT, void* outUV, float tol, Channel& ch) {
    ++ch.calls;
    Compare_t orig = (Compare_t)ch.origTest;

    if (g_bypass != 0 || ch.dead || !ray || !verts || !tri)
        return orig(ray, verts, tri, outT, outUV, tol);
    if (!ReadableRange(ray, 24) || !ReadableRange(tri, sizeof(IndexT) * 3))
        return orig(ray, verts, tri, outT, outUV, tol);

    const bool checking = !ch.armed || (ch.calls & kResample) == 0;

    if (!checking) {
        // Both halves of the A/B run are bracketed by the same pair, so the
        // harness files an ON sample against an OFF one and the report is this
        // function measured against the client's rather than a frame time that
        // cannot see it.
        const unsigned long long t = AbTest::TickIn();
        int r;
        if (g_abSubject && AbTest::StandAside()) {
            ++ch.stood;
            r = orig(ray, verts, tri, outT, outUV, tol);
            if (r & 0xFF) ++ch.hits;
        } else {
            Out o;
            if (ch.caught == 0) {
                r = Test<IndexT>((const float*)ray, (const float*)verts,
                                 (const IndexT*)tri, outT != nullptr,
                                 outUV != nullptr, tol, &o);
            } else if (!TestGuardedCall<IndexT>(ray, verts, tri, outT != nullptr,
                                                outUV != nullptr, tol, &o, &r, ch.caught)) {
                AbTest::TickOut(t);
                return orig(ray, verts, tri, outT, outUV, tol);
            }
            if (r) {
                ++ch.hits;
                if (o.wroteT)  *(float*)outT = o.t;
                if (o.wroteUV) { ((float*)outUV)[0] = o.u; ((float*)outUV)[1] = o.v; }
            }
        }
        AbTest::TickOut(t);
        return r;
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++ch.stood;
        return orig(ray, verts, tri, outT, outUV, tol);
    }

    // Checking: work out the answer without touching the caller's buffers, let
    // the client run and write them, then compare.
    // The verification runs both halves on the same input, which is the only
    // paired comparison this project ever gets. Timing it costs two rdtsc on a
    // path that was already doing twice the work.
    Out mine;
    int ours;
    // Once armed with nothing caught, this takes the same route the armed path
    // takes - no exception frame and no out-of-line call - because otherwise
    // the pair below times code that never runs in anger. It did: a field
    // session reported this module at 0.97x, slower than the client, while
    // another reported 1.35x, and the difference was the guard the measurement
    // was carrying and the armed path was not.
    const bool unguarded = ch.armed && ch.caught == 0;
    // On the timed (unguarded) shape the two halves alternate which runs first, so
    // neither always meets the cold caches and the other the warm ones. Ours writes
    // only its private result and reads none of the caller's buffers.
    static unsigned s_benchOrder = 0;
    int theirs;
    if (unguarded && (++s_benchOrder & 1)) {
        const uint64_t tA = SelfBench::Now();
        theirs = orig(ray, verts, tri, outT, outUV, tol);
        const uint64_t tB = SelfBench::Now();
        ours = Test<IndexT>((const float*)ray, (const float*)verts,
                            (const IndexT*)tri, outT != nullptr, outUV != nullptr,
                            tol, &mine);
        SelfBench::Pair(ch.benchSlot, SelfBench::Now() - tB, tB - tA);
    } else {
        const uint64_t tOursA = SelfBench::Now();
        if (unguarded) {
            ours = Test<IndexT>((const float*)ray, (const float*)verts,
                                (const IndexT*)tri, outT != nullptr, outUV != nullptr,
                                tol, &mine);
        } else if (!TestGuardedCall<IndexT>(ray, verts, tri, outT != nullptr,
                                            outUV != nullptr, tol, &mine, &ours,
                                            ch.caught)) {
            return orig(ray, verts, tri, outT, outUV, tol);
        }

        const uint64_t tOursB = SelfBench::Now();
        theirs = orig(ray, verts, tri, outT, outUV, tol);
        const uint64_t tTheirsB = SelfBench::Now();
        // Only the armed shape is filed, so the average is not half guarded calls
        // from the learning phase and half the real thing.
        if (unguarded) SelfBench::Pair(ch.benchSlot, tOursB - tOursA, tTheirsB - tOursB);
    }
    ++ch.verified;
    if (theirs & 0xFF) ++ch.hits;   // counted on both paths, or the rate lies

    // Only AL is the answer. See the note above about the sort key cache.
    const bool sameAnswer = ((ours & 0xFF) != 0) == ((theirs & 0xFF) != 0);
    bool sameData = true;
    if (sameAnswer && (theirs & 0xFF)) {
        if (mine.wroteT && memcmp(&mine.t, outT, sizeof(float)) != 0)
            sameData = false;
        if (mine.wroteUV && memcmp(&mine.u, outUV, 2 * sizeof(float)) != 0)
            sameData = false;
    }

    if (!sameAnswer || !sameData) {
        ch.dead = true;
        Log("[RayTriangle] [%s] DISAGREED with the client after %lu comparisons and "
            "retired for this session. It answered %d and this answered %d%s. "
            "The client's own result stands - nothing of ours was written - so "
            "the session is unaffected.",
            ch.name, ch.verified, theirs & 0xFF, ours & 0xFF,
            sameAnswer ? ", and the answers matched but a written value did not"
                       : "");
        return theirs;
    }

    if (!ch.armed && ch.verified >= kVerifyFirst) {
        ch.armed = true;
        Log("[RayTriangle] [%s] armed: %lu comparisons agreed with the client, the "
            "returned byte and every float written. Now answering directly and "
            "rechecking one call in %u.", ch.name, ch.verified, kResample + 1);
    }
    return theirs;
}

int __cdecl Hooked_Test16(const void* ray, const void* verts, const void* tri,
                          void* outT, void* outUV, float tol) {
    return Hooked_TestImpl<uint16_t>(ray, verts, tri, outT, outUV, tol, g_ch16);
}

int __cdecl Hooked_Test32(const void* ray, const void* verts, const void* tri,
                          void* outT, void* outUV, float tol) {
    return Hooked_TestImpl<uint32_t>(ray, verts, tri, outT, outUV, tol, g_ch32);
}

// ---------------------------------------------------------------------------
// Ray-Plane Intersection (sub_982FB0 / 0x00982FB0)
// ---------------------------------------------------------------------------

struct RayPlaneOut {
    float t;
    float point[3];
    bool  wroteT;
    bool  wrotePoint;
};

inline int RayPlaneTest(const float* ray, const float* plane,
                        bool wantT, bool wantPoint, float tolIn,
                        RayPlaneOut* out) {
    out->wroteT = false;
    out->wrotePoint = false;

    const double tol = (double)tolIn;
    const double px = (double)ray[0];
    const double py = (double)ray[1];
    const double pz = (double)ray[2];
    const double dx = (double)ray[3];
    const double dy = (double)ray[4];
    const double dz = (double)ray[5];

    const double nx = (double)plane[0];
    const double ny = (double)plane[1];
    const double nz = (double)plane[2];
    const double d  = (double)plane[3];

    // denom = ((dy * ny) + (dz * nz)) + (dx * nx)
    const double denom = ((dy * ny) + (dz * nz)) + (dx * nx);

    if (fabs(denom) < 0.0001) {
        // Parallel or coplanar:
        // distPara = ((py * ny) + (pz * nz)) + (px * nx) + d
        const double distPara = ((py * ny) + (pz * nz)) + (px * nx) + d;
        if (fabs(distPara) >= tol) {
            return 0;
        }
        if (wantT) {
            out->t = 0.0f;
            out->wroteT = true;
        }
        if (wantPoint) {
            out->point[0] = ray[0];
            out->point[1] = ray[1];
            out->point[2] = ray[2];
            out->wrotePoint = true;
        }
        return 1;
    }

    // denom >= 0.0001
    if (!wantT && !wantPoint) {
        return 1;
    }

    // dist = ((px * nx) + (pz * nz)) + (py * ny) + d
    const double dist = ((px * nx) + (pz * nz)) + (py * ny) + d;
    double t = 0.0;
    if (fabs(dist) >= tol) {
        t = -(dist / denom);
    }

    if (wantT) {
        out->t = (float)t;
        out->wroteT = true;
    }
    if (wantPoint) {
        out->point[0] = (float)((t * dx) + px);
        out->point[1] = (float)((t * dy) + py);
        out->point[2] = (float)((t * dz) + pz);
        out->wrotePoint = true;
    }
    return 1;
}

__declspec(noinline) bool RayPlaneGuardedCall(const float* ray, const float* plane,
                                              bool wantT, bool wantPoint, float tol,
                                              RayPlaneOut* o, int* r,
                                              unsigned long& caughtCounter) {
    __try {
        *r = RayPlaneTest(ray, plane, wantT, wantPoint, tol, o);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ++caughtCounter;
        return false;
    }
}

char __cdecl Hooked_RayPlane(const float* ray, const float* plane,
                             float* outT, float* outPoint, float tol) {
    ++g_chPlane.calls;
    RayPlane_t orig = (RayPlane_t)g_chPlane.origTest;

    if (g_bypass != 0 || g_chPlane.dead || !ray || !plane)
        return orig(ray, plane, outT, outPoint, tol);
    if (!ReadableRange(ray, 24) || !ReadableRange(plane, 16))
        return orig(ray, plane, outT, outPoint, tol);

    const bool checking = !g_chPlane.armed || (g_chPlane.calls & kResample) == 0;

    if (!checking) {
        const unsigned long long t = AbTest::TickIn();
        int r;
        if (g_abSubject && AbTest::StandAside()) {
            ++g_chPlane.stood;
            r = orig(ray, plane, outT, outPoint, tol);
            if (r & 0xFF) ++g_chPlane.hits;
        } else {
            RayPlaneOut o;
            if (g_chPlane.caught == 0) {
                r = RayPlaneTest(ray, plane, outT != nullptr, outPoint != nullptr, tol, &o);
            } else if (!RayPlaneGuardedCall(ray, plane, outT != nullptr, outPoint != nullptr,
                                            tol, &o, &r, g_chPlane.caught)) {
                AbTest::TickOut(t);
                return orig(ray, plane, outT, outPoint, tol);
            }
            if (r & 0xFF) {
                ++g_chPlane.hits;
                if (o.wroteT)     *outT = o.t;
                if (o.wrotePoint) memcpy(outPoint, o.point, 3 * sizeof(float));
            }
        }
        AbTest::TickOut(t);
        return (char)r;
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_chPlane.stood;
        return orig(ray, plane, outT, outPoint, tol);
    }

    RayPlaneOut mine;
    int ours;
    // The armed shape, so the pair below times what actually runs. See the note
    // in the triangle test above.
    const bool unguarded = g_chPlane.armed && g_chPlane.caught == 0;
    // On the timed (unguarded) shape the two halves alternate which runs first, so
    // neither always meets the cold caches and the other the warm ones. Ours writes
    // only its private result and reads none of the caller's buffers.
    static unsigned s_benchOrder = 0;
    char theirs;
    if (unguarded && (++s_benchOrder & 1)) {
        const uint64_t tA = SelfBench::Now();
        theirs = orig(ray, plane, outT, outPoint, tol);
        const uint64_t tB = SelfBench::Now();
        ours = RayPlaneTest(ray, plane, outT != nullptr, outPoint != nullptr,
                            tol, &mine);
        SelfBench::Pair(g_chPlane.benchSlot, SelfBench::Now() - tB, tB - tA);
    } else {
        const uint64_t tOursA = SelfBench::Now();
        if (unguarded) {
            ours = RayPlaneTest(ray, plane, outT != nullptr, outPoint != nullptr,
                                tol, &mine);
        } else if (!RayPlaneGuardedCall(ray, plane, outT != nullptr, outPoint != nullptr,
                                        tol, &mine, &ours, g_chPlane.caught)) {
            return orig(ray, plane, outT, outPoint, tol);
        }

        const uint64_t tOursB = SelfBench::Now();
        theirs = orig(ray, plane, outT, outPoint, tol);
        const uint64_t tTheirsB = SelfBench::Now();
        if (unguarded)
            SelfBench::Pair(g_chPlane.benchSlot, tOursB - tOursA, tTheirsB - tOursB);
    }
    ++g_chPlane.verified;
    if (theirs & 0xFF) ++g_chPlane.hits;

    const bool sameAnswer = ((ours & 0xFF) != 0) == ((theirs & 0xFF) != 0);
    bool sameData = true;
    if (sameAnswer && (theirs & 0xFF)) {
        if (mine.wroteT && memcmp(&mine.t, outT, sizeof(float)) != 0)
            sameData = false;
        if (mine.wrotePoint && memcmp(mine.point, outPoint, 3 * sizeof(float)) != 0)
            sameData = false;
    }

    if (!sameAnswer || !sameData) {
        g_chPlane.dead = true;
        Log("[RayPlane] DISAGREED with the client after %lu comparisons and retired. "
            "Client answered %d, ours answered %d%s.",
            g_chPlane.verified, theirs & 0xFF, ours & 0xFF,
            sameAnswer ? ", answers matched but written float differed" : "");
        return theirs;
    }

    if (!g_chPlane.armed && g_chPlane.verified >= kVerifyFirst) {
        g_chPlane.armed = true;
        Log("[RayPlane] armed: %lu comparisons agreed with client. Answering directly.",
            g_chPlane.verified);
    }
    return theirs;
}

// ---------------------------------------------------------------------------
// 2D Projected Point in Polygon (sub_9830D0 / 0x009830D0)
// ---------------------------------------------------------------------------

inline int PointInPolyTest(const float* pt, const float* verts, uint32_t count, uint32_t axis) {
    if (count == 0) return 0;
    if (axis > 2) axis = 0;

    static const int kAxisU[3] = { 1, 2, 0 };
    static const int kAxisV[3] = { 2, 0, 1 };

    const int uAxis = kAxisU[axis];
    const int vAxis = kAxisV[axis];

    const double pu = (double)pt[uAxis];
    const double pv = (double)pt[vAxis];

    uint32_t prev = count - 1;
    const float* vPrev = verts + 3 * (size_t)prev;
    int vPrevFlag = (pv <= (double)vPrev[vAxis]) ? 1 : 0;
    int inside = 0;

    for (uint32_t i = 0; i < count; ++i) {
        const float* vCurr = verts + 3 * (size_t)i;
        const int vCurrFlag = (pv <= (double)vCurr[vAxis]) ? 1 : 0;

        if (vPrevFlag != vCurrFlag) {
            // L = (B.u - P.u) * (A.v - B.v)
            // R = (A.u - B.u) * (B.v - P.v)
            const double bu = (double)vCurr[uAxis];
            const double bv = (double)vCurr[vAxis];
            const double au = (double)vPrev[uAxis];
            const double av = (double)vPrev[vAxis];

            const double L = (bu - pu) * (av - bv);
            const double R = (au - bu) * (bv - pv);

            const int crossFlag = (L <= R) ? 1 : 0;
            if (crossFlag == vCurrFlag) {
                inside = !inside;
            }
        }

        vPrevFlag = vCurrFlag;
        vPrev = vCurr;
    }

    return inside;
}

__declspec(noinline) bool PointInPolyGuardedCall(const float* pt, const float* verts,
                                                 uint32_t count, uint32_t axis,
                                                 int* r, unsigned long& caughtCounter) {
    __try {
        *r = PointInPolyTest(pt, verts, count, axis);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ++caughtCounter;
        return false;
    }
}

char __cdecl Hooked_PointInPoly(const float* pt, const float* verts,
                                uint32_t count, uint32_t axis) {
    ++g_chPoly.calls;
    PointInPoly_t orig = (PointInPoly_t)g_chPoly.origTest;

    if (g_bypass != 0 || g_chPoly.dead || !pt || !verts || count == 0)
        return orig(pt, verts, count, axis);
    if (!ReadableRange(pt, 12) || !ReadableRange(verts, count * 12))
        return orig(pt, verts, count, axis);

    const bool checking = !g_chPoly.armed || (g_chPoly.calls & kResample) == 0;

    if (!checking) {
        const unsigned long long t = AbTest::TickIn();
        int r;
        if (g_abSubject && AbTest::StandAside()) {
            ++g_chPoly.stood;
            r = orig(pt, verts, count, axis);
            if (r & 0xFF) ++g_chPoly.hits;
        } else {
            if (g_chPoly.caught == 0) {
                r = PointInPolyTest(pt, verts, count, axis);
            } else if (!PointInPolyGuardedCall(pt, verts, count, axis, &r, g_chPoly.caught)) {
                AbTest::TickOut(t);
                return orig(pt, verts, count, axis);
            }
            if (r & 0xFF) ++g_chPoly.hits;
        }
        AbTest::TickOut(t);
        return (char)r;
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_chPoly.stood;
        return orig(pt, verts, count, axis);
    }

    int ours = 0;
    const bool unguarded = g_chPoly.armed && g_chPoly.caught == 0;
    // On the timed (unguarded) shape the two halves alternate which runs first, so
    // neither always meets the cold caches and the other the warm ones. Ours writes
    // only its private result and reads none of the caller's buffers.
    static unsigned s_benchOrder = 0;
    char theirs;
    if (unguarded && (++s_benchOrder & 1)) {
        const uint64_t tA = SelfBench::Now();
        theirs = orig(pt, verts, count, axis);
        const uint64_t tB = SelfBench::Now();
        ours = PointInPolyTest(pt, verts, count, axis);
        SelfBench::Pair(g_chPoly.benchSlot, SelfBench::Now() - tB, tB - tA);
    } else {
        const uint64_t tOursA = SelfBench::Now();
        if (unguarded) {
            ours = PointInPolyTest(pt, verts, count, axis);
        } else if (!PointInPolyGuardedCall(pt, verts, count, axis, &ours, g_chPoly.caught)) {
            return orig(pt, verts, count, axis);
        }
        const uint64_t tOursB = SelfBench::Now();
        theirs = orig(pt, verts, count, axis);
        const uint64_t tTheirsB = SelfBench::Now();
        if (unguarded)
            SelfBench::Pair(g_chPoly.benchSlot, tOursB - tOursA, tTheirsB - tOursB);
    }
    ++g_chPoly.verified;
    if (theirs & 0xFF) ++g_chPoly.hits;

    const bool sameAnswer = ((ours & 0xFF) != 0) == ((theirs & 0xFF) != 0);
    if (!sameAnswer) {
        g_chPoly.dead = true;
        Log("[PointInPoly] DISAGREED with the client after %lu comparisons and retired. "
            "Client answered %d, ours answered %d.",
            g_chPoly.verified, theirs & 0xFF, ours & 0xFF);
        return theirs;
    }

    if (!g_chPoly.armed && g_chPoly.verified >= kVerifyFirst) {
        g_chPoly.armed = true;
        Log("[PointInPoly] armed: %lu comparisons agreed with client. Answering directly.",
            g_chPoly.verified);
    }
    return theirs;
}

// ---------------------------------------------------------------------------
// In-Process Self-Tests
// ---------------------------------------------------------------------------

static bool SelfTestRayPlaneIntersect() {
    typedef char (__cdecl* fn_t)(const float*, const float*, float*, float*, float);
    fn_t original = (fn_t)kTargetPlane;
    if (IsBadReadPtr((void*)original, 16)) return true;
    const unsigned char* p = (const unsigned char*)original;
    if (!(p[0] == 0x55 && p[1] == 0x8B && p[2] == 0xEC)) return true;

    uint32_t state = 0x12345678;
    auto rnd = [&state]() -> float {
        state = state * 1664525u + 1013904223u;
        return ((float)(int)(state >> 8) / 8388608.0f) * 100.0f;
    };

    for (int i = 0; i < 50000; ++i) {
        float ray[6];
        float plane[4];
        for (int k = 0; k < 6; ++k) ray[k] = rnd();
        for (int k = 0; k < 4; ++k) plane[k] = rnd();

        if (fabs(plane[0]) < 1e-4f && fabs(plane[1]) < 1e-4f && fabs(plane[2]) < 1e-4f)
            plane[0] = 1.0f;

        float tol = (i % 4 == 0) ? 0.0f : ((i % 4 == 1) ? 1e-4f : 0.01f);
        bool wantT = (i % 2 == 0);
        bool wantPoint = (i % 3 != 0);

        float outTOurs = -999.0f;
        float outPointOurs[3] = { -999.0f, -999.0f, -999.0f };
        RayPlaneOut mine;
        int rOurs = RayPlaneTest(ray, plane, wantT, wantPoint, tol, &mine);
        if (mine.wroteT) outTOurs = mine.t;
        if (mine.wrotePoint) memcpy(outPointOurs, mine.point, sizeof(outPointOurs));

        float outTClient = -999.0f;
        float outPointClient[3] = { -999.0f, -999.0f, -999.0f };
        char rClient = original(ray, plane,
                                wantT ? &outTClient : nullptr,
                                wantPoint ? outPointClient : nullptr,
                                tol);

        bool sameRet = ((rOurs & 0xFF) != 0) == ((rClient & 0xFF) != 0);
        if (!sameRet) {
            Log("[SelfTest] RayPlaneIntersect return mismatch at test %d: ours=%d client=%d",
                i, rOurs & 0xFF, rClient & 0xFF);
            return false;
        }

        if (rClient & 0xFF) {
            if (wantT && memcmp(&outTOurs, &outTClient, sizeof(float)) != 0) {
                Log("[SelfTest] RayPlaneIntersect out_t mismatch at test %d: ours=%f client=%f",
                    i, outTOurs, outTClient);
                return false;
            }
            if (wantPoint && memcmp(outPointOurs, outPointClient, sizeof(outPointOurs)) != 0) {
                Log("[SelfTest] RayPlaneIntersect out_point mismatch at test %d", i);
                return false;
            }
        }
    }
    return true;
}

static bool SelfTestPointInPolygon2D() {
    typedef char (__cdecl* fn_t)(const float*, const float*, uint32_t, uint32_t);
    fn_t original = (fn_t)kTargetPoly;
    if (IsBadReadPtr((void*)original, 16)) return true;
    const unsigned char* p = (const unsigned char*)original;
    if (!(p[0] == 0x55 && p[1] == 0x8B && p[2] == 0xEC)) return true;

    uint32_t state = 0x87654321;
    auto rnd = [&state]() -> float {
        state = state * 1664525u + 1013904223u;
        return ((float)(int)(state >> 8) / 8388608.0f) * 50.0f;
    };

    float verts[16 * 3];
    for (int i = 0; i < 50000; ++i) {
        float pt[3] = { rnd(), rnd(), rnd() };
        uint32_t count = 3 + (i % 6);
        for (uint32_t v = 0; v < count * 3; ++v) {
            verts[v] = rnd();
        }
        uint32_t axis = i % 3;

        int rOurs = PointInPolyTest(pt, verts, count, axis);
        char rClient = original(pt, verts, count, axis);

        if (((rOurs & 0xFF) != 0) != ((rClient & 0xFF) != 0)) {
            Log("[SelfTest] PointInPolygon2D mismatch at test %d (count=%u, axis=%u): ours=%d client=%d",
                i, count, axis, rOurs & 0xFF, rClient & 0xFF);
            return false;
        }
    }
    return true;
}

static inline bool CheckPrologue8(void* addr, const unsigned char expected[8], const char* name) {
    if (IsBadReadPtr(addr, 8) || memcmp(addr, expected, 8) != 0) {
        Log("[RayTriangle] BAD PROLOGUE for %s at 0x%08X", name, (uintptr_t)addr);
        return false;
    }
    return true;
}

}  // namespace

bool Init() {
    if (!Config::g_settings.OptRayTriangleSse2) return true;

    if (!X87Precision::IsDouble())
        Log("[Wrong] [RayTriangle] the x87 precision control is not 53-bit, so "
            "the width this was written for is not the width the client is "
            "using. Read the FpuState lines above.");

    // The harness keeps the address it is given and writes to it for the whole
    // session, so the flag has to outlive this function. It was a local here: the
    // harness wrote a byte into a dead stack frame every stint, and each channel
    // took a copy of the value at registration, which is false when this runs
    // before the harness starts, so none of the four ever stood aside. The sweep
    // reported this module "never reached" for that reason, and it is the
    // collision test the camera goes through.
    g_abSubject = AbTest::IsSubject("RayTriangleSse2", &g_abSubject);

    // Self-tests against in-memory original code if present
    SelfTestRayPlaneIntersect();
    SelfTestPointInPolygon2D();

    static const unsigned char kExp_Target16[8]    = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x2C, 0x8B, 0x55 };
    static const unsigned char kExp_Target32[8]    = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x2C, 0xD9, 0x45 };
    static const unsigned char kExp_TargetPlane[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x08, 0x8B, 0x55 };
    static const unsigned char kExp_TargetPoly[8]  = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x1C, 0x8B, 0x4D };

    // 16-bit indices target (0x00983490)
    if (CheckPrologue8((void*)kTarget16, kExp_Target16, "RayTriIntersect16")) {
        if (WineSafe_CreateHook((void*)kTarget16, (void*)&Hooked_Test16,
                                (void**)&g_ch16.origTest) == MH_OK) {
            if (WO_EnableHook((void*)kTarget16) == MH_OK) {
                g_ch16.installed = true;
                g_ch16.benchSlot = SelfBench::Register("RayTri16");
                SamplingProfiler::RegisterSelfSymbol(g_ch16.symbolName, (const void*)&Hooked_Test16);
                Log("[RayTriangle] ACTIVE on 16-bit indices (0x%08X), the shared "
                    "ray-triangle test for the collision family (sub_7C6600, sub_7C6790, "
                    "sub_7C6C30, sub_7C6D50, sub_81E110). Verified first %ld calls.",
                    (unsigned)kTarget16, kVerifyFirst);
            } else {
                Log("[RayTriangle] NOT active: could not enable 16-bit hook at 0x%08X.", (unsigned)kTarget16);
            }
        } else {
            Log("[RayTriangle] NOT active: could not hook 0x%08X.", (unsigned)kTarget16);
        }
    }

    // 32-bit indices target (0x009836B0)
    if (CheckPrologue8((void*)kTarget32, kExp_Target32, "RayTriIntersect32")) {
        if (WineSafe_CreateHook((void*)kTarget32, (void*)&Hooked_Test32,
                                (void**)&g_ch32.origTest) == MH_OK) {
            if (WO_EnableHook((void*)kTarget32) == MH_OK) {
                g_ch32.installed = true;
                g_ch32.benchSlot = SelfBench::Register("RayTri32");
                SamplingProfiler::RegisterSelfSymbol(g_ch32.symbolName, (const void*)&Hooked_Test32);
                Log("[RayTriangle] ACTIVE on 32-bit indices (0x%08X), terrain/mesh "
                    "collision paths (sub_7A3570, sub_7C8DD0, sub_7D8730). "
                    "Verified first %ld calls.",
                    (unsigned)kTarget32, kVerifyFirst);
            } else {
                Log("[RayTriangle] NOT active: could not enable 32-bit hook at 0x%08X.", (unsigned)kTarget32);
            }
        } else {
            Log("[RayTriangle] NOT active: could not hook 0x%08X.", (unsigned)kTarget32);
        }
    }

    // RayPlane target (0x00982FB0)
    if (CheckPrologue8((void*)kTargetPlane, kExp_TargetPlane, "RayPlaneIntersect")) {
        if (WineSafe_CreateHook((void*)kTargetPlane, (void*)&Hooked_RayPlane,
                                (void**)&g_chPlane.origTest) == MH_OK) {
            if (WO_EnableHook((void*)kTargetPlane) == MH_OK) {
                g_chPlane.installed = true;
                g_chPlane.benchSlot = SelfBench::Register("RayPlane");
                SamplingProfiler::RegisterSelfSymbol(g_chPlane.symbolName, (const void*)&Hooked_RayPlane);
                Log("[RayTriangle] ACTIVE on RayPlaneIntersect (0x%08X), ray-plane "
                    "collision paths (sub_792360, sub_7AF280, sub_7AF520, sub_7D78C0, sub_984E50). "
                    "Verified first %ld calls.",
                    (unsigned)kTargetPlane, kVerifyFirst);
            } else {
                Log("[RayTriangle] NOT active: could not enable hook at 0x%08X.", (unsigned)kTargetPlane);
            }
        } else {
            Log("[RayTriangle] NOT active: could not hook 0x%08X.", (unsigned)kTargetPlane);
        }
    }

    // PointInPoly target (0x009830D0)
    if (CheckPrologue8((void*)kTargetPoly, kExp_TargetPoly, "PointInPolygon2D")) {
        if (WineSafe_CreateHook((void*)kTargetPoly, (void*)&Hooked_PointInPoly,
                                (void**)&g_chPoly.origTest) == MH_OK) {
            if (WO_EnableHook((void*)kTargetPoly) == MH_OK) {
                g_chPoly.installed = true;
                g_chPoly.benchSlot = SelfBench::Register("PointInPoly");
                SamplingProfiler::RegisterSelfSymbol(g_chPoly.symbolName, (const void*)&Hooked_PointInPoly);
                Log("[RayTriangle] ACTIVE on PointInPolygon2D (0x%08X), polygon raycast "
                    "and portal culling (sub_58E0D0, sub_58E310, sub_7A7210, sub_7AF280, sub_7AF520, sub_7D78C0, sub_984E50). "
                    "Verified first %ld calls.",
                    (unsigned)kTargetPoly, kVerifyFirst);
            } else {
                Log("[RayTriangle] NOT active: could not enable hook at 0x%08X.", (unsigned)kTargetPoly);
            }
        } else {
            Log("[RayTriangle] NOT active: could not hook 0x%08X.", (unsigned)kTargetPoly);
        }
    }

    if (g_abSubject) {
        Log("[RayTriangle]   under A/B test, timed directly with rdtsc.");
    }
    return g_ch16.installed || g_ch32.installed || g_chPlane.installed || g_chPoly.installed;
}

void Shutdown() {
    if (g_ch16.installed) MH_DisableHook((void*)kTarget16);
    if (g_ch32.installed) MH_DisableHook((void*)kTarget32);
    if (g_chPlane.installed) MH_DisableHook((void*)kTargetPlane);
    if (g_chPoly.installed) MH_DisableHook((void*)kTargetPoly);
    g_ch16.installed = false;
    g_ch32.installed = false;
    g_chPlane.installed = false;
    g_chPoly.installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptRayTriangleSse2) return;
    if (!g_ch16.installed && !g_ch32.installed && !g_chPlane.installed && !g_chPoly.installed) {
        Log("[RayTriangle] switched on but not installed, so nothing here was measured.");
        return;
    }
    auto reportChannel = [](const Channel& ch) {
        if (!ch.installed) return;
        if (ch.calls == 0) {
            Log("[RayTriangle] [%s] installed, 0 calls measured.", ch.name);
            return;
        }
        Log("[RayTriangle] [%s] exception guard: %lu fault(s) caught; the armed path runs %s.",
            ch.name, ch.caught, !ch.armed ? "guarded, still checking"
                                          : (ch.caught ? "guarded, because the guard has caught something"
                                                       : "without an exception frame"));
        Log("[RayTriangle] [%s] %lu tests, %lu hit (%.1f%%), %lu compared with client%s.",
            ch.name, ch.calls, ch.hits, 100.0 * (double)ch.hits / (double)ch.calls, ch.verified,
            ch.dead ? " - RETIRED on a disagreement"
                    : (ch.armed ? " - armed" : " - still verifying, the client still answers"));
        if (ch.stood > 0)
            Log("[RayTriangle] [%s] %lu calls stood aside for the A/B off stint.",
                ch.name, ch.stood);
    };

    reportChannel(g_ch16);
    reportChannel(g_ch32);
    reportChannel(g_chPlane);
    reportChannel(g_chPoly);
}
void SetBypass(bool bypass) {
    InterlockedExchange(&g_bypass, bypass ? 1 : 0);
}

bool IsBypassed() {
    return g_bypass != 0;
}

void RetireAll() {
    g_ch16.dead = true;
    g_ch32.dead = true;
    g_chPlane.dead = true;
    g_chPoly.dead = true;
    Log("[RayTriangle] All channels retired due to diagnostic discrepancy");
}


}  // namespace RayTriangle
