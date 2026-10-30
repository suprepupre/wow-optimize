// ============================================================================
// Description: SSE2 AABB outcode classification for the collision ray cast.
// ============================================================================
// sub_7C6790 is 2.6% of executing main-thread time in the corrected tester
// profile and the largest client function with nothing shipped against it. It is
// the ray half of the collision pair: sub_7C7230 answers which triangles a box
// touches, this one walks the same geometry with a segment and keeps the nearest
// hit. Both open the same way, by classifying every vertex of the model against
// a query box as a six-bit outcode, and that opening is what this replaces. The
// triangle loop, the ray-triangle test at sub_983490 and the nearest-hit
// bookkeeping are all left to the client.
// ---------------------------------------------------------------------------
// Why the sibling module cannot be reused
//
// The bounds. sub_7C7230 reads six floats out of the caller and compares them,
// so an ordered packed-single compare answers identically and the module that
// covers it needs no tolerance at all. This function sorts each pair into a
// minimum and a maximum and then pushes the box out by 0.01 in every direction,
// and it does that on the x87 stack: one fld of the constant, six fsub/fadd into
// registers st(1) through st(6), and the six results stay in those registers,
// at 64-bit mantissa, for the whole vertex loop. Nothing ever stores them.
//
// So the comparisons are not float against float. They are an 80-bit value
// against a widened float, and rounding a widened bound back down to single
// would change the answer for any vertex that falls between the two.
// ---------------------------------------------------------------------------
// Why double is the exact width, rather than the close one
//
// The constant at flt_9F1968 is the dword 0x3C23D70A, which is 0.01f, and the
// client loads it with fld dword - an exact widening. A bound is one float plus
// or minus that, worked out once per call.
//
// When that sum is exact in double it equals the real result, so it equals what
// the client's 80-bit register is holding. Not close to it. Equal. Widening the
// vertex float to double is exact as well, so a packed double compare answers
// what fcom answered, for every input including every NaN.
//
// Whether it is exact is measured rather than argued. Each of the six bounds
// goes through Knuth's two-sum, which recovers the rounding error of a double
// addition exactly; a non-zero error means the bound being compared against is
// not the one the client holds, and the call is handed back.
//
// This started as a gate on the exponent instead, and the range it allowed was
// wrong. It covered a coordinate too large, where the top of the result runs
// past 53 bits, and missed one far smaller than 0.01, where the bottom does. A
// sweep against exact rational arithmetic caught it: 71982 of 118400 sampled
// floats inside the accepted range were not exact, the first at an exponent
// field of zero. The two-sum was put through the same reference over every
// exponent field, denormals, infinities and NaNs included, and agreed on all
// 61440 cases; it accepts all 400000 of a draw from the map's own coordinate
// range, and zero.
// ---------------------------------------------------------------------------
// The outcode, read out of the disassembly rather than the decompiler
//
// Two compare shapes alternate, and they are not the two the sibling uses:
//
//   fcom [v] ; fnstsw ax ; test ah, 41h ; jnz skip
//       41h masks C0 and C3. Greater sets neither, so only greater falls
//       through. Less sets C0, equal sets C3, unordered sets both. -> bound > v
//   fcom [v] ; fnstsw ax ; test ah, 5   ; jp  skip
//       5 masks C0 and C2. Less sets C0 alone, one bit, odd parity, so only
//       less falls through. Greater and equal set neither and unordered sets
//       both, all even. -> bound < v
//
// Both strict, both false on NaN, which is _mm_cmpgt_pd and _mm_cmplt_pd. The
// sibling's are >= and <=; reusing its table here would have been wrong at every
// exact touch.
//
//   0x20  xlo - 0.01 >  v.x      0x10  xhi + 0.01 <  v.x
//   0x08  ylo - 0.01 >  v.y      0x04  yhi + 0.01 <  v.y
//   0x02  zlo - 0.01 >  v.z      0x01  zhi + 0.01 <  v.z
//
// The register the bounds live in rotates by an fxch before each compare. The
// order was traced through all six and then checked against the shuffle at
// loc_7C69F1, which restores the entry arrangement for the next iteration; it
// lands back exactly where the loop started, which is what says the trace is
// right.
// ---------------------------------------------------------------------------
// Where the time actually goes
//
// Six compares a vertex, each one fcom, fnstsw, test and a conditional jump.
// The jump is on whether a vertex is outside one face of a query box, which is
// as close to a coin toss as a branch gets, so a model of a few hundred vertices
// costs a few hundred mispredictions. The replacement has no branch in it at
// all: the compare masks are ANDed with their bit values and ORed together, four
// vertices at a time, and packed down to four bytes with one store.
// ---------------------------------------------------------------------------
// Measured, and the number is explained rather than just reported
//
// The same comparisons were compiled a second time with /arch:IA32 /fp:precise,
// which makes MSVC emit fcom and fnstsw against the x87 stack - six of each per
// vertex, exactly what the client's loop has. Forty-eight million vertices
// classified each way:
//
//     packed double    1.922 ns/vertex
//     x87             31.575 ns/vertex
//     speedup             16.43x
//
// That is large enough to be worth checking against what it should be. At
// 3.5 GHz the x87 side is about 110 cycles a vertex for twenty-four
// instructions, which only adds up with the six branches being mispredicted:
// six times fifteen is ninety of those cycles. The vector side is about seven
// cycles a vertex, which is thirteen branchless instructions at roughly two a
// cycle. So the sixteen is not the vector width - four lanes cannot give
// sixteen - it is the branches not being there.
//
// And the two agree: 400 models of 300 vertices, 117995 non-zero outcodes, no
// byte different. The x87 build came through a different instruction set and a
// different compiler path, so agreeing with it checks the outcode table itself
// and not just my own vectorisation of my own reading.
//
// This is the classification loop. The triangle loop after it is the client's
// and is untouched, so it is not a speedup of the whole function.
// ---------------------------------------------------------------------------
// The two patch sites and what the second one is for
//
// Entry is 0x007C67D9, the first of the six flds that load the box, six bytes
// covering two whole instructions. Nothing branches to the second of them.
//
// The join is 0x007C6A75. The client cleans the x87 stack there with six fstp,
// and the sixth of them sits after that label because the path that skips the
// remainder loop arrives having already popped five. So the label is reached
// with exactly one register live. Taking over means jumping past it, to
// 0x007C6A7E, with the stack empty and eax already holding the triangle count -
// which is why the thunk does that movzx itself.
//
// The client pushes edi at 0x007C6827, inside the replaced run, and its epilogue
// pops it. The thunk pushes it too.
//
// The second patch is the whole verification. While unarmed the classification
// goes to a private buffer and the client's own loop still fills the real array;
// the thunk at the join compares the two. That is the only thing that can catch
// a misread of the client - a stride, a field, a bit - because a scalar model of
// my own misreading would agree with my own vectorisation of it perfectly. There
// is no call instruction anywhere between the two sites, so nothing can re-enter
// between them and the pairing needs no more than a flag.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>

#include "collision_ray_outcode_sse2.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);

namespace CollisionRayOutcode {

namespace {

// --- the client -------------------------------------------------------------

constexpr uintptr_t kEntry     = 0x007C67D9;  // fld [esi+28h] ; fld [esi+2Ch]
constexpr uintptr_t kEntryBack = 0x007C67DF;  // fld [esi+30h], where a decline rejoins
constexpr uintptr_t kJoin      = 0x007C6A75;  // movzx eax, word ptr [ebx+18A4h]
constexpr uintptr_t kJoinBack  = 0x007C6A7C;  // fstp st, the sixth and last pop
constexpr uintptr_t kTaken     = 0x007C6A7E;  // xor esi, esi - entered with x87 empty

constexpr unsigned char kEntryWant[6] = { 0xD9, 0x46, 0x28, 0xD9, 0x46, 0x2C };
constexpr unsigned char kJoinWant[7]  = { 0x0F, 0xB7, 0x83, 0xA4, 0x18, 0x00, 0x00 };

// The tail the entry site is checked against, so a match on two fld bytes cannot
// stand in for the whole run being the one that was read.
constexpr uintptr_t kTailAddr = 0x007C6A6B;
constexpr unsigned char kTailWant[10] = {
    0xDD, 0xD8,  // fstp st
    0xDD, 0xDA,  // fstp st(2)
    0xDD, 0xDB,  // fstp st(3)
    0xDD, 0xD8,  // fstp st
    0xDD, 0xD8   // fstp st
};

constexpr unsigned kQueryBox    = 0x28;    // six floats on the caller: lo triple, hi triple
constexpr unsigned kM_vertCount = 6;       // u16 on the model
constexpr unsigned kM_verts     = 8;       // float3, stride 12
constexpr unsigned kM_triCount  = 0x18A4;  // u16 on the model

// The client's own code array is [ebp-1D0h], and the three dwords above it are
// its other locals, so it holds 0x1D0 - 0x0C bytes. A model with more vertices
// than that overruns the client's stack, which is the client's business; those
// are handed straight back.
constexpr int kCodeArray = 0x1D0;
constexpr unsigned kMaxVerts = 0x1D0 - 0x0C;

// fld ds:flt_9F1968, and the dword there is 0x3C23D70A.
const float kEps = 0.01f;

// --- state ------------------------------------------------------------------

constexpr long kLearnCalls = 3000;

bool g_entryPatched = false;
bool g_joinPatched  = false;
unsigned char g_savedEntry[6];
unsigned char g_savedJoin[7];

bool g_armed      = false;
bool g_abSubject  = false;
static volatile LONG g_bypass = 0;

// Every one of these is incremented before any early return that could stop it,
// so a frozen number cannot be read back as a rate.
long g_calls          = 0;   // entry thunk invocations, whatever happens next
long g_declinedSize   = 0;   // more vertices than the client's own buffer holds
long g_declinedBounds = 0;   // a bound whose 0.01 step does not fit a double
long g_agreements     = 0;
long g_disagreed      = 0;
long g_stoodAside     = 0;   // A/B off stint
long g_dead           = 0;   // 1 after a disagreement
long g_joinNoShadow   = 0;   // join reached with nothing to compare against
long g_emptyModel     = 0;   // no vertices, so agreeing about them proves nothing

// Vertices classified. A few hundred a call and thousands of calls a minute puts
// this past 32 bits inside a long session, so the wrap is counted and the two
// are recombined as a double at report time.
unsigned long g_verts     = 0;
unsigned long g_vertWraps = 0;

uint8_t  g_shadow[kMaxVerts];
unsigned g_shadowCount = 0;
bool     g_shadowValid = false;

uintptr_t g_entryBack = kEntryBack;
uintptr_t g_joinBack  = kJoinBack;
uintptr_t g_taken     = kTaken;

void AddVerts(unsigned n) {
    unsigned long before = g_verts;
    g_verts = before + n;
    if (g_verts < before) ++g_vertWraps;
}

// --- the classification -----------------------------------------------------

// Knuth's two-sum. Recovers the rounding error of x + y exactly, so a zero
// error is proof the double sum is the real one and therefore the one the
// client's 80-bit register holds. This needs correctly rounded doubles with no
// excess precision and no reassociation, which is what /arch:SSE2 and
// /fp:precise give; both are set for this target in CMakeLists.
//
// An infinite or NaN input falls out of it as an infinite or NaN error, which
// is not zero, so it is refused along with everything else inexact.
bool ExactSum(double x, double y, double* out) {
    const double s  = x + y;
    const double bb = s - x;
    const double err = (x - (s - bb)) + (y - bb);
    *out = s;
    return err == 0.0;
}

// Two packed double compare results, each two lanes of all-ones or all-zeros,
// collapsed into one register of four 32-bit lanes in vertex order.
__m128i Collapse(__m128d lo, __m128d hi) {
    return _mm_castps_si128(_mm_shuffle_ps(_mm_castpd_ps(lo), _mm_castpd_ps(hi),
                                           _MM_SHUFFLE(2, 0, 2, 0)));
}

// Returns false when the box is outside the range the exactness argument covers,
// having written nothing.
bool ClassifyAll(uint32_t self, const float* verts, unsigned count, uint8_t* out) {
    const float* q = (const float*)(self + kQueryBox);

    float lo[3], hi[3];
    for (int k = 0; k < 3; ++k) {
        const float a = q[k];
        const float b = q[k + 3];
        // fcom / test ah, 41h / jnz: the swap happens only when a is strictly
        // greater. Unordered sets both masked bits and so skips it, and a C
        // compare against a NaN is false, which leaves the pair as it was.
        if (a > b) { lo[k] = b; hi[k] = a; }
        else       { lo[k] = a; hi[k] = b; }
    }

    const double e = (double)kEps;
    double b[6];
    for (int k = 0; k < 3; ++k) {
        if (!ExactSum((double)lo[k], -e, &b[k])) return false;
        if (!ExactSum((double)hi[k],  e, &b[k + 3])) return false;
    }
    const double xl = b[0], yl = b[1], zl = b[2];
    const double xh = b[3], yh = b[4], zh = b[5];

    const __m128d vxl = _mm_set1_pd(xl), vxh = _mm_set1_pd(xh);
    const __m128d vyl = _mm_set1_pd(yl), vyh = _mm_set1_pd(yh);
    const __m128d vzl = _mm_set1_pd(zl), vzh = _mm_set1_pd(zh);

    const __m128i k20 = _mm_set1_epi32(0x20), k10 = _mm_set1_epi32(0x10);
    const __m128i k08 = _mm_set1_epi32(0x08), k04 = _mm_set1_epi32(0x04);
    const __m128i k02 = _mm_set1_epi32(0x02), k01 = _mm_set1_epi32(0x01);

    unsigned i = 0;
    for (; i + 4 <= count; i += 4) {
        const float* p = verts + 3 * i;

        // Three loads cover four vertices exactly, so nothing is read past the
        // last one.
        const __m128 m0 = _mm_loadu_ps(p);      // x0 y0 z0 x1
        const __m128 m1 = _mm_loadu_ps(p + 4);  // y1 z1 x2 y2
        const __m128 m2 = _mm_loadu_ps(p + 8);  // z2 x3 y3 z3

        const __m128 t0 = _mm_shuffle_ps(m0, m1, _MM_SHUFFLE(2, 2, 3, 0)); // x0 x1 x2 x2
        const __m128 tx = _mm_shuffle_ps(m1, m2, _MM_SHUFFLE(1, 1, 2, 2)); // x2 x2 x3 x3
        const __m128 X  = _mm_shuffle_ps(t0, tx, _MM_SHUFFLE(2, 0, 1, 0)); // x0 x1 x2 x3

        const __m128 u0 = _mm_shuffle_ps(m0, m1, _MM_SHUFFLE(1, 0, 2, 1)); // y0 z0 y1 z1
        const __m128 u1 = _mm_shuffle_ps(m1, m2, _MM_SHUFFLE(3, 2, 3, 0)); // y1 y2 y3 z3
        const __m128 Y  = _mm_shuffle_ps(u0, u1, _MM_SHUFFLE(2, 1, 2, 0)); // y0 y1 y2 y3
        const __m128 Z  = _mm_shuffle_ps(u0, m2, _MM_SHUFFLE(3, 0, 3, 1)); // z0 z1 z2 z3

        // Float to double is exact, so this is the widening fcom did.
        const __m128d xa = _mm_cvtps_pd(X);
        const __m128d xb = _mm_cvtps_pd(_mm_movehl_ps(X, X));
        const __m128d ya = _mm_cvtps_pd(Y);
        const __m128d yb = _mm_cvtps_pd(_mm_movehl_ps(Y, Y));
        const __m128d za = _mm_cvtps_pd(Z);
        const __m128d zb = _mm_cvtps_pd(_mm_movehl_ps(Z, Z));

        __m128i acc = _mm_and_si128(
            Collapse(_mm_cmpgt_pd(vxl, xa), _mm_cmpgt_pd(vxl, xb)), k20);
        acc = _mm_or_si128(acc, _mm_and_si128(
            Collapse(_mm_cmplt_pd(vxh, xa), _mm_cmplt_pd(vxh, xb)), k10));
        acc = _mm_or_si128(acc, _mm_and_si128(
            Collapse(_mm_cmpgt_pd(vyl, ya), _mm_cmpgt_pd(vyl, yb)), k08));
        acc = _mm_or_si128(acc, _mm_and_si128(
            Collapse(_mm_cmplt_pd(vyh, ya), _mm_cmplt_pd(vyh, yb)), k04));
        acc = _mm_or_si128(acc, _mm_and_si128(
            Collapse(_mm_cmpgt_pd(vzl, za), _mm_cmpgt_pd(vzl, zb)), k02));
        acc = _mm_or_si128(acc, _mm_and_si128(
            Collapse(_mm_cmplt_pd(vzh, za), _mm_cmplt_pd(vzh, zb)), k01));

        // Every lane is between 0 and 0x3F, so the saturating packs cannot
        // change one.
        const __m128i p16 = _mm_packs_epi32(acc, acc);
        const __m128i p8  = _mm_packs_epi16(p16, p16);
        const int four = _mm_cvtsi128_si32(p8);
        memcpy(out + i, &four, 4);
    }

    for (; i < count; ++i) {
        const float* p = verts + 3 * i;
        const double vx = (double)p[0];
        const double vy = (double)p[1];
        const double vz = (double)p[2];
        uint8_t c = 0;
        if (xl > vx) c  = 0x20;
        if (xh < vx) c |= 0x10;
        if (yl > vy) c |= 0x08;
        if (yh < vy) c |= 0x04;
        if (zl > vz) c |= 0x02;
        if (zh < vz) c |= 0x01;
        out[i] = c;
    }

    return true;
}

// --- the thunks -------------------------------------------------------------

// Returns 1 when the codes have been written into the client's own array and it
// should skip its loop, 0 when it should run it.
int __cdecl ClassifyEntryC(uint32_t self, uint32_t model, uint32_t frame) {
    ++g_calls;
    g_shadowValid = false;

    const unsigned count = *(const uint16_t*)(model + kM_vertCount);
    if (count > kMaxVerts) { ++g_declinedSize; return 0; }

    const float* verts = (const float*)(model + kM_verts);

    if (g_armed) {
        if (g_bypass != 0 || (g_abSubject && AbTest::StandAside())) { ++g_stoodAside; return 0; }
        const unsigned long long t = AbTest::TickIn();
        const bool did = ClassifyAll(self, verts, count,
                                     (uint8_t*)(frame - kCodeArray));
        AbTest::TickOut(t);
        if (!did) { ++g_declinedBounds; return 0; }
        AddVerts(count);
        return 1;
    }

    if (g_dead) return 0;

    if (!ClassifyAll(self, verts, count, g_shadow)) { ++g_declinedBounds; return 0; }
    g_shadowCount = count;
    g_shadowValid = true;
    AddVerts(count);
    return 0;
}

void __cdecl JoinCompareC(uint32_t frame) {
    if (!g_shadowValid) { ++g_joinNoShadow; return; }
    g_shadowValid = false;

    const uint8_t* mine   = g_shadow;
    const uint8_t* theirs = (const uint8_t*)(frame - kCodeArray);

    for (unsigned i = 0; i < g_shadowCount; ++i) {
        if (mine[i] == theirs[i]) continue;
        ++g_disagreed;
        g_dead = 1;
        Log("[CollisionRay] Retired: vertex %u of %u classified 0x%02X here and "
            "0x%02X by the client. Nothing of ours was written - this ran beside "
            "the client's own loop, not instead of it - so the session is "
            "unaffected, but the outcode is being read wrong and this module "
            "will not take over.",
            i, g_shadowCount, (unsigned)mine[i], (unsigned)theirs[i]);
        return;
    }

    // A model with no vertices agrees with anything. Counting those towards
    // arming would let a run of them arm this without a single outcode ever
    // having been compared.
    if (g_shadowCount == 0) { ++g_emptyModel; return; }

    ++g_agreements;
    if (g_agreements == kLearnCalls) {
        g_armed = true;
        Log("[CollisionRay] Taking over after %ld calls agreed, covering %.0f "
            "vertices. From here the client's classification loop does not run.",
            (long)g_agreements,
            (double)g_verts + (double)g_vertWraps * 4294967296.0);
    }
}

__declspec(naked) void EntryThunk() {
    __asm {
        push ebp                              // frame, for [ebp-1D0h]
        push ebx                              // model
        push esi                              // the caller object
        call ClassifyEntryC
        add  esp, 12
        test eax, eax
        jz   short decline
        push edi                              // the push at 0x007C6827
        movzx eax, word ptr [ebx+18A4h]       // what 0x007C6A75 would have loaded
        jmp  dword ptr [g_taken]
    decline:
        fld  dword ptr [esi+28h]
        fld  dword ptr [esi+2Ch]
        jmp  dword ptr [g_entryBack]
    }
}

__declspec(naked) void JoinThunk() {
    __asm {
        push ecx
        push edx
        push ebp
        call JoinCompareC
        add  esp, 4
        pop  edx
        pop  ecx
        movzx eax, word ptr [ebx+18A4h]
        jmp  dword ptr [g_joinBack]
    }
}

// --- installation -----------------------------------------------------------

bool BytesMatch(uintptr_t addr, const unsigned char* want, int n) {
    __try {
        return memcmp((const void*)addr, want, (size_t)n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool WriteJump(uintptr_t at, int len, void* to, unsigned char* saved) {
    DWORD old = 0;
    if (!VirtualProtect((void*)at, (SIZE_T)len, PAGE_EXECUTE_READWRITE, &old))
        return false;
    memcpy(saved, (const void*)at, (size_t)len);

    unsigned char patch[16];
    patch[0] = 0xE9;
    *(int32_t*)(patch + 1) = (int32_t)((uintptr_t)to - (at + 5));
    if (len > 5) memset(patch + 5, 0x90, (size_t)(len - 5));
    memcpy((void*)at, patch, (size_t)len);

    DWORD ignored = 0;
    VirtualProtect((void*)at, (SIZE_T)len, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), (void*)at, (SIZE_T)len);
    return true;
}

void Restore(uintptr_t at, int len, const unsigned char* saved) {
    DWORD old = 0;
    if (!VirtualProtect((void*)at, (SIZE_T)len, PAGE_EXECUTE_READWRITE, &old))
        return;
    memcpy((void*)at, saved, (size_t)len);
    DWORD ignored = 0;
    VirtualProtect((void*)at, (SIZE_T)len, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), (void*)at, (SIZE_T)len);
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptCollisionRayOutcode) return true;

    if (!BytesMatch(kEntry, kEntryWant, sizeof(kEntryWant))) {
        Log("[CollisionRay] NOT active: the bytes at 0x%08X are not the box load "
            "this was read from.", (unsigned)kEntry);
        return false;
    }
    if (!BytesMatch(kTailAddr, kTailWant, sizeof(kTailWant))) {
        Log("[CollisionRay] NOT active: the entry at 0x%08X matches but the x87 "
            "cleanup at 0x%08X does not, so the loop between them is not the one "
            "being replaced.", (unsigned)kEntry, (unsigned)kTailAddr);
        return false;
    }
    if (!BytesMatch(kJoin, kJoinWant, sizeof(kJoinWant))) {
        Log("[CollisionRay] NOT active: the join at 0x%08X is not the triangle "
            "count load, so there is nowhere to check the result against the "
            "client.", (unsigned)kJoin);
        return false;
    }
    if (!WowOpt_ClientPatchAllowed((const void*)kEntry)) {
        Log("[CollisionRay] NOT active: No Client Patches is on, and this writes "
            "into wow.exe like every hook here does.");
        return false;
    }

    // The join goes in first. If the entry went in first and the join then
    // failed, the classification would be running with nothing checking it.
    if (!WriteJump(kJoin, (int)sizeof(kJoinWant), (void*)&JoinThunk, g_savedJoin)) {
        Log("[CollisionRay] NOT active: could not make 0x%08X writable.",
            (unsigned)kJoin);
        return false;
    }
    g_joinPatched = true;

    if (!WriteJump(kEntry, (int)sizeof(kEntryWant), (void*)&EntryThunk, g_savedEntry)) {
        Restore(kJoin, (int)sizeof(kJoinWant), g_savedJoin);
        g_joinPatched = false;
        Log("[CollisionRay] NOT active: could not make 0x%08X writable.",
            (unsigned)kEntry);
        return false;
    }
    g_entryPatched = true;
    SamplingProfiler::RegisterSelfSymbol("CollisionRayOutcode_SSE2", (const void*)&EntryThunk);

    g_abSubject = AbTest::IsSubject("CollisionRayOutcode", &g_abSubject);

    Log("[CollisionRay] ACTIVE. The ray half of the collision pair spends its "
        "opening classifying every vertex of a model against a query box, six "
        "x87 compares and six unpredictable branches each, and it is 2.6%% of "
        "executing time in the corrected profile. This does four vertices at a "
        "time with no branch in it. The box bounds are pushed out by 0.01 on the "
        "x87 stack at 64-bit mantissa, so the compares are done in double rather "
        "than single, and each bound is checked for being exact at that width "
        "before it is used. The first %ld calls are still done both ways and "
        "compared before it takes over.", kLearnCalls);
    if (g_abSubject)
        Log("[CollisionRay]   under A/B test: both halves take the same two "
            "patches and the same call, and only the classification differs.");
    return true;
}

void Shutdown() {
    if (g_entryPatched) {
        Restore(kEntry, (int)sizeof(kEntryWant), g_savedEntry);
        g_entryPatched = false;
    }
    if (g_joinPatched) {
        Restore(kJoin, (int)sizeof(kJoinWant), g_savedJoin);
        g_joinPatched = false;
    }
}

void LogStats() {
    if (!Config::g_settings.OptCollisionRayOutcode) return;
    if (!g_entryPatched) {
        Log("[CollisionRay] switched on but not patched, so nothing here was "
            "measured.");
        return;
    }
    if (g_calls == 0) {
        Log("[CollisionRay] patched, and the ray cast has not run yet. This is "
            "measured and zero, not unmeasured.");
        return;
    }

    const double verts = (double)g_verts + (double)g_vertWraps * 4294967296.0;
    Log("[CollisionRay] %ld calls, %.0f vertices classified. %ld agreed with the "
        "client, %ld disagreed. %s",
        g_calls, verts, g_agreements, g_disagreed,
        g_dead ? "Retired." :
        g_armed ? "Armed; the client's loop no longer runs." :
                  "Still checking against the client.");

    if (!g_armed && !g_dead)
        Log("[CollisionRay]   %ld more agreements arm it.",
            kLearnCalls - g_agreements);
    if (g_declinedSize > 0)
        Log("[CollisionRay]   %ld calls declined: more vertices than the "
            "client's own array holds.", g_declinedSize);
    if (g_declinedBounds > 0)
        Log("[CollisionRay]   %ld calls declined: pushing the box out by 0.01 "
            "did not land on a number a double holds exactly, so the comparison "
            "here would not have been the client's.", g_declinedBounds);
    if (g_emptyModel > 0)
        Log("[CollisionRay]   %ld calls were models with no vertices, which "
            "agree with anything and so do not count towards arming.",
            g_emptyModel);
    if (g_joinNoShadow > 0)
        Log("[CollisionRay]   %ld calls reached the join with nothing to compare "
            "against, which is one of the declines above.", g_joinNoShadow);
    if (g_stoodAside > 0)
        Log("[CollisionRay]   %ld calls stood aside for the A/B off stint.",
            g_stoodAside);
}

void SetBypass(bool bypass) {
    InterlockedExchange(&g_bypass, bypass ? 1 : 0);
}

bool IsBypassed() {
    return g_bypass != 0;
}
} // namespace CollisionRayOutcode
