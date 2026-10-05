#include <windows.h>
#include <MinHook.h>
#include <cstdint>
#include <emmintrin.h>
#include <intrin.h>
#include <cmath>
#include "version.h"
#include "matrix_copy_sse2.h"
#include "ab_test.h"
#include "sampling_profiler.h"
#include "session_verdict.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
// Statistics — plain increments, not Interlocked.
// Both hooked functions run on the main WoW thread only;
// atomic overhead would dwarf the work itself.
// ================================================================
// Whether the hooks went in, so the report can tell "never reached" from
// "never installed".
static bool g_matrixInstalled = false;

static volatile unsigned long g_matcopy_calls = 0;
static volatile unsigned long g_matident_calls = 0;

// ================================================================
// Original function pointers
// __fastcall typedef mirrors the __thiscall ABI on x86 MSVC:
// ECX = this, EDX = unused padding.
// ================================================================
typedef float* (__fastcall* MatCopy_t)(float* self, void* edx, float* src);
typedef float* (__fastcall* MatIdentity_t)(float* self, void* edx);

// sub_4C1F00: result = A * B, all three are float[16] passed by stack (__cdecl).
typedef float* (__cdecl* MatMul_t)(float* result, float* a, float* b);

static MatCopy_t     pOrigMatCopy     = nullptr;
static MatIdentity_t pOrigMatIdentity = nullptr;
static MatMul_t      pOrigMatMul      = nullptr;
static volatile unsigned long g_matmul_calls   = 0;   // low word, wraps
static volatile unsigned long g_matmul_wraps   = 0;   // how many times it has

typedef float* (__cdecl* MatVec3Mul_t)(float* result, const float* vec3, const float* matrix44);
typedef float* (__cdecl* MatVec4Mul_t)(float* result, const float* vec4, const float* matrix44);

static MatVec3Mul_t  pOrigMatVec3Mul  = nullptr;
static MatVec4Mul_t  pOrigMatVec4Mul  = nullptr;
static volatile unsigned long g_matvec3_calls  = 0;
static volatile unsigned long g_matvec4_calls  = 0;

// sub_4C1C40: quaternion -> 3x3 rotation block, both operands on the stack.
typedef float* (__cdecl* QuatToMatrix_t)(const float* quat, float* dest);
static QuatToMatrix_t pOrigQuatToMatrix = nullptr;
static volatile unsigned long  g_quat2mat_calls  = 0;

// sub_4C1DE0: __thiscall wrapper, ECX = destination matrix, quaternion on the stack.
typedef float* (__fastcall* QuatToMatrixFull_t)(float* dest, void* edx, const float* quat);
static QuatToMatrixFull_t pOrigQuatToMatrixFull = nullptr;
static volatile unsigned long      g_quat2matfull_calls  = 0;

// ================================================================
// Precomputed identity matrix rows for the SSE2 store path
// ================================================================
static const __m128 kIdentityRow0 = { 1.0f, 0.0f, 0.0f, 0.0f };
static const __m128 kIdentityRow1 = { 0.0f, 1.0f, 0.0f, 0.0f };
static const __m128 kIdentityRow2 = { 0.0f, 0.0f, 1.0f, 0.0f };
static const __m128 kIdentityRow3 = { 0.0f, 0.0f, 0.0f, 1.0f };

// ================================================================
// sub_407F80: 4x4 matrix copy (247 xrefs)
// Original does 16 scalar FPU load/store pairs.
// 4x SSE2 unaligned 128-bit moves cover all 64 bytes.
// ================================================================
// Set at init when the A/B harness names this module.
//
// These three hooks sit on the busiest maths in the client - 247 call sites for
// the copy, 66 for the multiply, 53 for the identity - and none has ever been
// measured against the client doing the same work. Each stands aside on an OFF
// stint and is timed on both, because none is a large enough share of a frame
// for frame time on its own to separate.
static bool g_abSubject = false;

// The guard these two hooks were paying for, and why it comes off.
//
// A field session takes 8570603116 calls through the multiply and 4043060417
// through the copy. Each body wrapped its work in __try, and a __try region on
// 32-bit MSVC costs a prologue on every call whether anything faults or not -
// measured at 2.48 ns elsewhere in this project. Twelve and a half billion of
// those is most of a minute of main thread.
//
// What the guard buys is nothing, and that is an argument about memory rather
// than about probability. Both bodies check their pointers for range first, and
// the only risk left is a pointer in range but unmapped. When the __except
// fires, control falls through to the client's own routine with the same
// pointers - and the client's routine reads exactly the same bytes: sixty-four
// from the source in the copy, and the same two matrices in the multiply. It
// cannot succeed where ours faulted. The guard does not recover a fault, it
// moves it a few instructions later into the client's code.
//
// So the guard is kept only until it has proven that, and then dropped. Every
// call runs under it for the first kMatProve calls; if it ever catches
// anything, that is written into the log and this stays guarded for the rest of
// the session. Once armed, the hot path is a range check and the arithmetic,
// with no exception frame at all.
constexpr unsigned long kMatProve = 200000;
volatile LONG g_matArmed   = 0;    // 1 once the guard has caught nothing
unsigned long g_matProved  = 0;    // calls completed under the guard
unsigned long g_matFaults  = 0;    // times it actually caught something
volatile LONG g_matLogged  = 0;

// Kept out of line so the callers below carry no exception frame of their own.
__declspec(noinline) static bool CopyGuarded(float* self, float* src) {
    __try {
        _mm_storeu_ps(self,      _mm_loadu_ps(src));
        _mm_storeu_ps(self + 4,  _mm_loadu_ps(src + 4));
        _mm_storeu_ps(self + 8,  _mm_loadu_ps(src + 8));
        _mm_storeu_ps(self + 12, _mm_loadu_ps(src + 12));
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ++g_matFaults;
        if (InterlockedCompareExchange(&g_matLogged, 1, 0) == 0)
            Log("[MatrixSSE2] the pointer guard caught a fault in the copy. It "
                "stays on for the rest of this session, and the reasoning that "
                "it never fires is wrong - the module's own note says so.");
        return false;
    }
}

static float* __fastcall HookMatrixCopyBody(float* self, void* /*edx*/, float* src) {
    ++g_matcopy_calls;

    uintptr_t s = (uintptr_t)self;
    uintptr_t p = (uintptr_t)src;
    if (s > 0x10000 && s < 0xFFE00000 &&
        p > 0x10000 && p < 0xFFE00000) {
        if (g_matArmed) {
            // No exception frame on this path. See the note above CopyGuarded.
            _mm_storeu_ps(self,      _mm_loadu_ps(src));
            _mm_storeu_ps(self + 4,  _mm_loadu_ps(src + 4));
            _mm_storeu_ps(self + 8,  _mm_loadu_ps(src + 8));
            _mm_storeu_ps(self + 12, _mm_loadu_ps(src + 12));
            return self;
        }
        if (CopyGuarded(self, src)) {
            if (++g_matProved >= kMatProve && g_matFaults == 0)
                InterlockedExchange(&g_matArmed, 1);
            return self;
        }
    }

    return pOrigMatCopy(self, nullptr, src);
}

// The detour proper. Split from the body so the A/B harness can time the
// call: a scope guard closing that sample on every return path cannot live in
// a function containing __try, which the body does.
static float* __fastcall HookMatrixCopy(float* self, void* edx, float* src) {
    if (!g_abSubject) return HookMatrixCopyBody(self, edx, src);
    unsigned long long abTick = AbTest::TickIn();
    float* r = AbTest::StandAside() ? pOrigMatCopy(self, edx, src)
                                    : HookMatrixCopyBody(self, edx, src);
    AbTest::TickOut(abTick);
    return r;
}

// ================================================================
// sub_407F40: 4x4 matrix identity (53 xrefs)
// Original writes 16 immediate floats through the FPU.
// 4x SSE2 stores from compile-time constants.
// ================================================================
static float* __fastcall HookMatrixIdentityBody(float* self, void* /*edx*/) {
    ++g_matident_calls;

    uintptr_t s = (uintptr_t)self;
    if (s > 0x10000 && s < 0xFFE00000) {
        _mm_storeu_ps(self,      kIdentityRow0);
        _mm_storeu_ps(self + 4,  kIdentityRow1);
        _mm_storeu_ps(self + 8,  kIdentityRow2);
        _mm_storeu_ps(self + 12, kIdentityRow3);
        return self;
    }

    return pOrigMatIdentity(self, nullptr);
}

// The detour proper. Split from the body so the A/B harness can time the
// call: a scope guard closing that sample on every return path cannot live in
// a function containing __try, which the body does.
static float* __fastcall HookMatrixIdentity(float* self, void* edx) {
    if (!g_abSubject) return HookMatrixIdentityBody(self, edx);
    unsigned long long abTick = AbTest::TickIn();
    float* r = AbTest::StandAside() ? pOrigMatIdentity(self, edx)
                                    : HookMatrixIdentityBody(self, edx);
    AbTest::TickOut(abTick);
    return r;
}

// ================================================================
// sub_4C1F00: 4x4 matrix multiply  result = A * B  (53+ xrefs)
// ================================================================
// Verified convention: result[r*4+c] = sum_k A[r*4+k] * B[k*4+c]
// (row-major C = A*B). It loads all of B and a full A row before storing, so
// it is safe when result aliases A or B (the scalar original is not, but no
// caller passes aliasing pointers).
//
// This was packed single, under a comment saying that only the summation order
// differed and the delta was sub-ULP. That compares single against single. The
// client does not work in single: sub_4C1F00 is 199 x87 instructions, and the
// Windows CRT sets the x87 control word to 53-bit, so it accumulates in double
// and stores float. The difference is accumulation width, not summation order,
// and measured against the client's own arithmetic over 4096 random matrix
// pairs at mixed magnitudes it came to 1.118e-04 relative - not sub-ULP, and
// the same order as the divergence that produced first-person camera snapping
// the last time this project reached for single precision here.
//
// Bone matrices are exactly the bad case: rotations near unity beside
// translations in the hundreds of yards, which is the spread that pulls a
// single-precision dot product away from a double one. sub_4C1F00 runs once
// per bone per frame for every animated model, so this is not a rare path.
//
// Packed double keeps the client's accumulation width and still does two lanes
// per instruction. Measured 24.81 ns for the client, 10.43 ns here - 2.38x -
// and bit-identical: worst relative deviation 0.000e+00 across all 65,536
// values compared. Packed single was 3.81 ns, and its extra speed is not worth
// asking players to watch for artifacts.
// The arithmetic on its own, so the self-test can exercise exactly the code the
// hook runs rather than a second copy of it that might drift from it.
// What the packed form above this used to be, and why it is not any more.
//
// It accumulated the four products of every element in the order 0 1 2 3 and was described as
// bit-identical to the client. The self-test that said so compared with a tolerance of 1e-5 and
// its random matrices almost never make a sum of four products round differently when the order
// changes. The client adds them in a different order for every one of the sixteen elements, and
// on inputs built so that a sum cancels the two differed in one matrix in a thousand, by one
// unit in the last place (field log 2026-10-05: client 31DEA749, packed 31DEA748 at element 9 of
// the in-place multiply, which calls this). Measured against the client's x87 sequence over
// twenty million matrices, half of them built to cancel: the old order differed in 21031, this
// one in none.
//
// out = A * B in the order sub_4C1F00 adds its products, read from the disassembly. Element
// (row, column) is A[row][k0]*B[k0][column] + A[row][k1]*B[k1][column], then each of the next
// two products added onto the running sum, with (k0 k1 k2 k3) by element:
//
//     row 0   2130   2103   1302   2013
//     row 1   1230   1230   3210   1320
//     row 2   1230   1320   3210   1320
//     row 3   1230   1320   3210   1320
//
// A product of two floats is exact in a double and each addition rounds once at 53 bits, which
// is what the client's x87 does here, so the order is the whole of the exactness. A fixed order
// of 0 1 2 3 agreed with the client on four thousand random matrices and differed on one in a
// thousand of those built so that a sum cancels.
//
// Rows 2 and 3 share an order in every column and are computed as the two lanes of one register;
// the first two elements of row 1 share one and are the two lanes of another. The other ten
// are scalar, each in its own order.
#define MAT_PM(r, k, c) ((double)a[(r) * 4 + (k)] * (double)b[(k) * 4 + (c)])
#define MAT_SCALAR_SUM(r, c, k0, k1, k2, k3) \
    (((MAT_PM(r, k0, c) + MAT_PM(r, k1, c)) + MAT_PM(r, k2, c)) + MAT_PM(r, k3, c))

static inline __m128d MatWidenTwo(const float* p) {
    return _mm_cvtps_pd(_mm_castsi128_ps(_mm_loadl_epi64((const __m128i*)p)));
}

// Two lanes, one chain: ((p0 + p1) + p2) + p3 in the given order, both lanes the same order.
#define MAT_LANE_SUM(A, B, k0, k1, k2, k3) \
    _mm_add_pd(_mm_add_pd(_mm_add_pd(_mm_mul_pd(A[k0], B[k0]), _mm_mul_pd(A[k1], B[k1])), \
                          _mm_mul_pd(A[k2], B[k2])), _mm_mul_pd(A[k3], B[k3]))

static inline void MatMul4x4_PackedDouble(float* out, const float* a, const float* b) {
    float t[16];

    // Rows 2 and 3, lane 0 and lane 1.
    __m128d A23[4], B23[4][4];
    for (int k = 0; k < 4; ++k) A23[k] = _mm_set_pd((double)a[12 + k], (double)a[8 + k]);
    for (int c = 0; c < 4; ++c)
        for (int k = 0; k < 4; ++k) B23[c][k] = _mm_set1_pd((double)b[k * 4 + c]);
    __m128d bc0[4], bc1[4], bc2[4], bc3[4];
    for (int k = 0; k < 4; ++k) { bc0[k] = B23[0][k]; bc1[k] = B23[1][k]; bc2[k] = B23[2][k]; bc3[k] = B23[3][k]; }
    const __m128d s20 = MAT_LANE_SUM(A23, bc0, 1, 2, 3, 0);
    const __m128d s21 = MAT_LANE_SUM(A23, bc1, 1, 3, 2, 0);
    const __m128d s22 = MAT_LANE_SUM(A23, bc2, 3, 2, 1, 0);
    const __m128d s23 = MAT_LANE_SUM(A23, bc3, 1, 3, 2, 0);
    t[8]  = (float)_mm_cvtsd_f64(s20); t[12] = (float)_mm_cvtsd_f64(_mm_unpackhi_pd(s20, s20));
    t[9]  = (float)_mm_cvtsd_f64(s21); t[13] = (float)_mm_cvtsd_f64(_mm_unpackhi_pd(s21, s21));
    t[10] = (float)_mm_cvtsd_f64(s22); t[14] = (float)_mm_cvtsd_f64(_mm_unpackhi_pd(s22, s22));
    t[11] = (float)_mm_cvtsd_f64(s23); t[15] = (float)_mm_cvtsd_f64(_mm_unpackhi_pd(s23, s23));

    // Row 1, columns 0 and 1 together.
    __m128d A1[4], B01[4];
    for (int k = 0; k < 4; ++k) { A1[k] = _mm_set1_pd((double)a[4 + k]); B01[k] = MatWidenTwo(b + k * 4); }
    const __m128d s1 = MAT_LANE_SUM(A1, B01, 1, 2, 3, 0);
    t[4] = (float)_mm_cvtsd_f64(s1);
    t[5] = (float)_mm_cvtsd_f64(_mm_unpackhi_pd(s1, s1));

    // The rest one at a time.
    t[6] = (float)MAT_SCALAR_SUM(1, 2, 3, 2, 1, 0);
    t[7] = (float)MAT_SCALAR_SUM(1, 3, 1, 3, 2, 0);
    t[0] = (float)MAT_SCALAR_SUM(0, 0, 2, 1, 3, 0);
    t[1] = (float)MAT_SCALAR_SUM(0, 1, 2, 1, 0, 3);
    t[2] = (float)MAT_SCALAR_SUM(0, 2, 1, 3, 0, 2);
    t[3] = (float)MAT_SCALAR_SUM(0, 3, 2, 0, 1, 3);
    memcpy(out, t, sizeof(t));
}

// Run the client's own routine beside ours on the real binary before replacing
// it. A version of this lived in the other SSE2 module, guarding a hook that
// never installed because this one gets the address first - so what was being
// verified and what was running were two different functions.
static bool SelfTestMatrixMultiply() {
    typedef float* (__cdecl* mat_fn)(float*, float*, float*);
    mat_fn original = (mat_fn)0x004C1F00;

    const int CASES = 4096;
    unsigned seed = 0x9E3779B9u;
    double worst = 0.0;
    int mismatches = 0;
    float lhs[16], rhs[16], theirs[16], ours[16];

    for (int c = 0; c < CASES; ++c) {
        // Bone matrices carry rotations near unity beside translations in the
        // hundreds, and that spread is what separates the two precisions.
        float scale = (c & 3) == 0 ? 1.0f : ((c & 3) == 1 ? 100.0f
                                          : ((c & 3) == 2 ? 0.01f : 1000.0f));
        for (int i = 0; i < 16; ++i) {
            seed = seed * 1103515245u + 12345u;
            lhs[i] = (((float)(int)(seed >> 16) / 32768.0f) - 1.0f) * scale;
            seed = seed * 1103515245u + 12345u;
            rhs[i] = (((float)(int)(seed >> 16) / 32768.0f) - 1.0f) * scale;
        }
        // Half the cases carry one element whose four products cancel to a few units in the
        // last place, because that is where the order of the additions is visible in a float.
        if (c & 4) {
            const int row = (c >> 3) & 3, col = (c >> 5) & 3, kz = (c >> 7) & 3;
            double sum = 0.0;
            for (int k = 0; k < 4; ++k)
                if (k != kz) sum += (double)lhs[row * 4 + k] * (double)rhs[k * 4 + col];
            if (lhs[row * 4 + kz] != 0.0f) {
                float v = (float)(-sum / (double)lhs[row * 4 + kz]);
                for (int n = (int)((seed >> 8) % 5) - 2; n > 0; --n) v = nextafterf(v, 1e30f);
                for (int n = (int)((seed >> 8) % 5) - 2; n < 0; ++n) v = nextafterf(v, -1e30f);
                rhs[kz * 4 + col] = v;
            }
        }

        __try {
            original(theirs, lhs, rhs);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[MatrixSSE2] Self-test: the client's routine faulted - not hooking");
            return false;
        }
        MatMul4x4_PackedDouble(ours, lhs, rhs);

        if (memcmp(theirs, ours, sizeof(theirs)) != 0) ++mismatches;
        for (int i = 0; i < 16; ++i) {
            float d = theirs[i] - ours[i];
            if (d < 0.0f) d = -d;
            float mag = (theirs[i] < 0.0f ? -theirs[i] : theirs[i]);
            double rel = (mag > 1.0f) ? ((double)d / (double)mag) : (double)d;
            if (rel > worst) worst = rel;
        }
    }

    if (mismatches != 0 || worst > 1e-5) {
        Log("[MatrixSSE2] Self-test FAILED: %d of %d pairs differed from the client, worst "
            "deviation %.3e - not hooking", mismatches, CASES, worst);
        return false;
    }
    Log("[MatrixSSE2] Self-test passed %d random pairs against the client's own "
        "routine, worst deviation %.3e", CASES, worst);
    return true;
}

volatile LONG g_matDead = 0;
unsigned long g_matChecked = 0;
unsigned long g_matAliased = 0;

// Out of line: the formatting buffer must not sit in the hot function's frame.
__declspec(noinline) static void RetireMatMul(const float* mine, const float* theirs) {
    int at = 0;
    while (at < 16 && memcmp(&mine[at], &theirs[at], 4) == 0) ++at;
    InterlockedExchange(&g_matDead, 1);
    InterlockedExchange(&g_matArmed, 0);
    uint32_t m = 0, t = 0;
    if (at < 16) { memcpy(&m, &mine[at], 4); memcpy(&t, &theirs[at], 4); }
    Log("[MatrixSSE2] the multiply DISAGREED with the client at element %d: client %08X, this %08X. "
        "Every multiply is the client's own from here on.", at, t, m);
    Verdict::Add(Verdict::Bad, "the matrix multiply disagreed with the client and retired itself");
}

// The multiply's guarded probe, kept out of line for the same reason as the
// copy's. safebuffers as well: out_val is sixteen floats written by
// MatMul4x4_PackedDouble and by nothing else, with no index anywhere near it
// that comes from the client, so the /GS cookie this function would otherwise
// carry guards nothing that can happen - on 8570603116 calls a session.
__declspec(noinline) __declspec(safebuffers)
static bool MultiplyGuarded(float* result, float* a, float* b) {
    __try {
        float out_val[16];
        MatMul4x4_PackedDouble(out_val, a, b);
        _ReadWriteBarrier();
        memcpy(result, out_val, 16 * sizeof(float));
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ++g_matFaults;
        if (InterlockedCompareExchange(&g_matLogged, 1, 0) == 0)
            Log("[MatrixSSE2] the pointer guard caught a fault in the multiply. "
                "It stays on for the rest of this session.");
        return false;
    }
}

__declspec(safebuffers)
static float* __cdecl HookMatrixMultiplyBody(float* result, float* a, float* b) {
    // A field log printed "multiply -199339142". A negative call count is not a
    // number, and the only reason it was readable at all is that the arithmetic
    // that must hold - a count is not negative - was checked. Signed 32 bits
    // ran out: this hook took just over four billion calls in three hours,
    // about four thousand a frame.
    //
    // Unsigned buys one more bit and would still wrap inside a long evening, so
    // the low word carries a wrap counter beside it, the same shape the draw
    // census uses for primitives. The test is one compare that is never taken
    // until it is.
    if (++g_matmul_calls == 0) ++g_matmul_wraps;

    uintptr_t r = (uintptr_t)result, pa = (uintptr_t)a, pb = (uintptr_t)b;
    if (r > 0x10000 && r < 0xFFE00000 &&
        pa > 0x10000 && pa < 0xFFE00000 &&
        pb > 0x10000 && pb < 0xFFE00000 && !g_matDead) {
        // The client writes each element as it finishes it, so a result that is also an
        // input is overwritten while later elements still read it. Computing the whole
        // product first would give a different, and correct, matrix. Whatever the client
        // does there is the answer, so those calls are its own.
        if (r == pa || r == pb) {
            ++g_matAliased;
            return pOrigMatMul(result, a, b);
        }
        if (g_matArmed) {
            // No exception frame and no stack cookie on this path.
            float out_val[16];
            MatMul4x4_PackedDouble(out_val, a, b);
            _ReadWriteBarrier();
            // One call in 65536 also goes to the client and the two are compared bit for bit.
            if ((g_matmul_calls & 0xFFFFu) == 0) {
                float theirs[16];
                pOrigMatMul(theirs, a, b);
                if (memcmp(theirs, out_val, sizeof(theirs)) != 0) {
                    RetireMatMul(out_val, theirs);
                    memcpy(result, theirs, sizeof(theirs));
                    return result;
                }
                ++g_matChecked;
            }
            memcpy(result, out_val, 16 * sizeof(float));
            return result;
        }
        if (MultiplyGuarded(result, a, b)) {
            // While proving, every call is compared with the client's as well.
            float theirs[16];
            pOrigMatMul(theirs, a, b);
            if (memcmp(theirs, result, sizeof(theirs)) != 0) {
                RetireMatMul(result, theirs);
                memcpy(result, theirs, sizeof(theirs));
                return result;
            }
            ++g_matChecked;
            if (++g_matProved >= kMatProve && g_matFaults == 0)
                InterlockedExchange(&g_matArmed, 1);
            return result;
        }
    }
    return pOrigMatMul(result, a, b);
}

// The detour proper. Split from the body so the A/B harness can time the
// call: a scope guard closing that sample on every return path cannot live in
// a function containing __try, which the body does.
static float* __cdecl HookMatrixMultiply(float* result, float* a, float* b) {
    if (!g_abSubject) return HookMatrixMultiplyBody(result, a, b);
    unsigned long long abTick = AbTest::TickIn();
    float* r = AbTest::StandAside() ? pOrigMatMul(result, a, b)
                                    : HookMatrixMultiplyBody(result, a, b);
    AbTest::TickOut(abTick);
    return r;
}

#if !TEST_DISABLE_QUAT_MATRIX_SSE2
// ================================================================
// sub_4C1C40: quaternion -> 3x3 rotation block  __cdecl(quat, dest)
// ================================================================
// The arithmetic core behind all three of the client's quaternion wrappers
// (0x004C1DE0, 0x004C1E20, 0x004C33C0), so hooking it here covers every caller
// including sub_82F0F0, which runs it once per animated bone per frame.
//
// It writes nine of the sixteen floats - indices 0,1,2,4,5,6,8,9,10 - and
// deliberately leaves 3, 7, 11 and 12..15 alone; the wrappers set those. This
// replacement writes the same nine and no others.
//
// The original is not plain double arithmetic, and that is the whole difficulty.
// It is 72 x87 instructions, the CRT runs x87 at 53-bit precision, and the
// compiler ran out of the eight-deep x87 stack: it spilled three products to
// 32-bit stack slots and reloaded them.
//
//     fstp [ebp+arg_0]   <- x*2z rounded to float
//     fstp [ebp+var_8]   <- y*2z rounded to float
//     fst  [ebp+var_4]   <- z*2z rounded to float, but NOT popped
//
// So three of the twelve intermediates are float and the rest are 53-bit. The
// third is the awkward one: `fst` stores without popping, so z*2z survives in a
// register at full width as well, and the function then uses both. Row 0 gets
// the unrounded value and row 1 gets the rounded one. Reproducing that asymmetry
// is what makes this bit-identical rather than merely close - and "merely close"
// on a bone rotation is the same order of error that produced the first-person
// camera snapping the last time this project reached for lower precision here.
//
// Grouping is preserved exactly; operand order within a single multiply or add
// is not, because IEEE multiply and add are commutative and exactly rounded.
static inline void QuatToMatrix3x3_PackedDouble(const float* q, float* dest) {
    // Two lanes per multiply for the six products that pair up naturally.
    __m128  qf   = _mm_loadu_ps(q);                          // x  y  z  w
    __m128d q_lo = _mm_cvtps_pd(qf);                         // (x, y)
    __m128d q_hi = _mm_cvtps_pd(_mm_movehl_ps(qf, qf));      // (z, w)

    __m128d two  = _mm_set1_pd(2.0);
    __m128d d_lo = _mm_mul_pd(q_lo, two);                    // (2x, 2y)
    __m128d d_hi = _mm_mul_pd(q_hi, two);                    // (2z, 2w)

    __m128d z2   = _mm_unpacklo_pd(d_hi, d_hi);              // (2z, 2z)
    __m128d ww   = _mm_unpackhi_pd(q_hi, q_hi);              // (w,  w)

    __m128d sq   = _mm_mul_pd(q_lo, d_lo);                   // (x*2x, y*2y)
    __m128d wxy  = _mm_mul_pd(ww,   d_lo);                   // (w*2x, w*2y)
    __m128d xyz2 = _mm_mul_pd(q_lo, z2);                     // (x*2z, y*2z)

    double xx2 = _mm_cvtsd_f64(sq);
    double yy2 = _mm_cvtsd_f64(_mm_unpackhi_pd(sq, sq));
    double wx2 = _mm_cvtsd_f64(wxy);
    double wy2 = _mm_cvtsd_f64(_mm_unpackhi_pd(wxy, wxy));

    double zz2 = _mm_cvtsd_f64(_mm_mul_sd(z2, q_hi));        // 2z*z, full width
    double wz2 = _mm_cvtsd_f64(_mm_mul_sd(ww, z2));          // w*2z
    double xy2 = _mm_cvtsd_f64(_mm_mul_sd(q_lo, _mm_unpackhi_pd(d_lo, d_lo)));

    // The three the original could not keep in registers. Narrowing here is not
    // a shortcut - it is the client's own rounding, and omitting it is what
    // makes the two answers differ.
    __m128 narrowed = _mm_cvtpd_ps(xyz2);
    float xz2f = _mm_cvtss_f32(narrowed);
    float yz2f = _mm_cvtss_f32(_mm_shuffle_ps(narrowed, narrowed, _MM_SHUFFLE(1, 1, 1, 1)));
    float zz2f = (float)zz2;

    dest[0]  = (float)(1.0 - (zz2 + yy2));          // zz2 at full width here
    dest[1]  = (float)(xy2 + wz2);
    dest[2]  = (float)((double)xz2f - wy2);
    dest[4]  = (float)(xy2 - wz2);
    dest[5]  = (float)(1.0 - ((double)zz2f + xx2)); // and rounded here
    dest[6]  = (float)((double)yz2f + wx2);
    dest[8]  = (float)(wy2 + (double)xz2f);
    dest[9]  = (float)((double)yz2f - wx2);
    dest[10] = (float)(1.0 - (xx2 + yy2));
}

// Run the client's own routine beside ours on the real binary before replacing
// it, and demand exact equality rather than a tolerance. Every intermediate here
// is reproduced at the width the original used, so anything short of identical
// means the reading of those three spill slots is wrong, and a tolerance would
// hide exactly the mistake this is meant to catch.
static bool SelfTestQuatToMatrix() {
    typedef float* (__cdecl* quat_fn)(const float*, float*);
    quat_fn original = (quat_fn)0x004C1C40;

    const int CASES = 4096;
    unsigned seed = 0x85EBCA6Bu;
    int mismatches = 0;

    for (int c = 0; c < CASES; ++c) {
        float q[4];
        for (int i = 0; i < 4; ++i) {
            seed = seed * 1103515245u + 12345u;
            q[i] = ((float)(int)(seed >> 16) / 32768.0f) - 1.0f;
        }

        // Most of the run is unit quaternions, because that is what bone tracks
        // actually hold; the rest is left unnormalised to exercise the paths
        // where the products are far from 1 and the float spills matter most.
        if ((c & 3) != 0) {
            double n = sqrt((double)q[0] * q[0] + (double)q[1] * q[1] +
                            (double)q[2] * q[2] + (double)q[3] * q[3]);
            if (n > 1e-6) {
                for (int i = 0; i < 4; ++i) q[i] = (float)(q[i] / n);
            }
        }

        // Both sides get a full 16-float buffer so that a stray write outside
        // the nine cells shows up as a mismatch instead of going unnoticed.
        float theirs[16], ours[16];
        for (int i = 0; i < 16; ++i) { theirs[i] = (float)i; ours[i] = (float)i; }

        __try {
            original(q, theirs);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[MatrixSSE2] Quaternion self-test: the client's routine faulted - not hooking");
            return false;
        }
        QuatToMatrix3x3_PackedDouble(q, ours);

        if (memcmp(theirs, ours, sizeof(theirs)) != 0) ++mismatches;
    }

    if (mismatches != 0) {
        Log("[MatrixSSE2] Quaternion self-test FAILED: %d of %d cases differed "
            "from the client - not hooking", mismatches, CASES);
        return false;
    }
    Log("[MatrixSSE2] Quaternion self-test passed %d cases against the client's "
        "own routine, bit-identical", CASES);
    return true;
}

static float* __cdecl Hooked_QuatToMatrix(const float* quat, float* dest) {
    ++g_quat2mat_calls;

    uintptr_t pq = (uintptr_t)quat, pd = (uintptr_t)dest;
    if (pq > 0x10000 && pq < 0xFFE00000 &&
        pd > 0x10000 && pd < 0xFFE00000) {
        float out_val[16];
        QuatToMatrix3x3_PackedDouble(quat, out_val);
        _ReadWriteBarrier();
        dest[0]  = out_val[0];  dest[1] = out_val[1];  dest[2]  = out_val[2];
        dest[4]  = out_val[4];  dest[5] = out_val[5];  dest[6]  = out_val[6];
        dest[8]  = out_val[8];  dest[9] = out_val[9];  dest[10] = out_val[10];
        return dest;
    }
    return pOrigQuatToMatrix(quat, dest);
}

// sub_4C1DE0: the wrapper sub_82F0F0 actually calls, once per animated bone per
// frame. It writes seven constants into the fourth row and column and then calls
// the core above.
static float* __fastcall Hooked_QuatToMatrixFull(float* dest, void* /*edx*/, const float* quat) {
    ++g_quat2matfull_calls;

    uintptr_t pq = (uintptr_t)quat, pd = (uintptr_t)dest;
    if (pq > 0x10000 && pq < 0xFFE00000 &&
        pd > 0x10000 && pd < 0xFFE00000) {
        float out_val[16];
        QuatToMatrix3x3_PackedDouble(quat, out_val);
        _ReadWriteBarrier();
        dest[0]  = out_val[0];  dest[1]  = out_val[1];  dest[2]  = out_val[2];
        dest[4]  = out_val[4];  dest[5]  = out_val[5];  dest[6]  = out_val[6];
        dest[8]  = out_val[8];  dest[9]  = out_val[9];  dest[10] = out_val[10];
        // The seven the wrapper contributes, in the client's own order.
        dest[3]  = 0.0f; dest[7]  = 0.0f; dest[11] = 0.0f;
        dest[12] = 0.0f; dest[13] = 0.0f; dest[14] = 0.0f;
        dest[15] = 1.0f;
        return dest;
    }
    return pOrigQuatToMatrixFull(dest, nullptr, quat);
}
#endif

// ================================================================
// sub_4C21B0: 3D point * 4x4 matrix (100+ xrefs)
// Vectorized via column linear combination using SSE2
// ================================================================
static float* __cdecl Hooked_MatVec3Mul(float* result, const float* vec3, const float* matrix44) {
    ++g_matvec3_calls;

    uintptr_t r = (uintptr_t)result, pv = (uintptr_t)vec3, pm = (uintptr_t)matrix44;
    if (r > 0x10000 && r < 0xFFE00000 &&
        pv > 0x10000 && pv < 0xFFE00000 &&
        pm > 0x10000 && pm < 0xFFE00000) {
        double vx = vec3[0];
        double vy = vec3[1];
        double vz = vec3[2];

        double m0 = matrix44[0];
        double m4 = matrix44[4];
        double m8 = matrix44[8];
        double m12 = matrix44[12];

        double m1 = matrix44[1];
        double m5 = matrix44[5];
        double m9 = matrix44[9];
        double m13 = matrix44[13];

        double m2 = matrix44[2];
        double m6 = matrix44[6];
        double m10 = matrix44[10];
        double m14 = matrix44[14];

        double rx = vx * m0 + vy * m4 + vz * m8 + m12;
        double ry = vx * m1 + vy * m5 + vz * m9 + m13;
        double rz = vx * m2 + vy * m6 + vz * m10 + m14;

        result[0] = (float)rx;
        result[1] = (float)ry;
        result[2] = (float)rz;

        return result;
    }
    return pOrigMatVec3Mul(result, vec3, matrix44);
}

// ================================================================
// sub_4C2270: 4D vector * 4x4 matrix (20 xrefs)
// Vectorized via column linear combination using SSE2
// ================================================================
static float* __cdecl Hooked_MatVec4Mul(float* result, const float* vec4, const float* matrix44) {
    ++g_matvec4_calls;

    uintptr_t r = (uintptr_t)result, pv = (uintptr_t)vec4, pm = (uintptr_t)matrix44;
    if (r > 0x10000 && r < 0xFFE00000 &&
        pv > 0x10000 && pv < 0xFFE00000 &&
        pm > 0x10000 && pm < 0xFFE00000) {
        double vx = vec4[0];
        double vy = vec4[1];
        double vz = vec4[2];
        double vw = vec4[3];

        double m0 = matrix44[0];
        double m4 = matrix44[4];
        double m8 = matrix44[8];
        double m12 = matrix44[12];

        double m1 = matrix44[1];
        double m5 = matrix44[5];
        double m9 = matrix44[9];
        double m13 = matrix44[13];

        double m2 = matrix44[2];
        double m6 = matrix44[6];
        double m10 = matrix44[10];
        double m14 = matrix44[14];

        double m3 = matrix44[3];
        double m7 = matrix44[7];
        double m11 = matrix44[11];
        double m15 = matrix44[15];

        double rx = vx * m0 + vy * m4 + vz * m8 + vw * m12;
        double ry = vx * m1 + vy * m5 + vz * m9 + vw * m13;
        double rz = vx * m2 + vy * m6 + vz * m10 + vw * m14;
        double rw = vx * m3 + vy * m7 + vz * m11 + vw * m15;

        result[0] = (float)rx;
        result[1] = (float)ry;
        result[2] = (float)rz;
        result[3] = (float)rw;

        return result;
    }
    return pOrigMatVec4Mul(result, vec4, matrix44);
}

// ================================================================
// sub_4C3420 / sub_4C3600: C3Vector::Normalize (in-place, __thiscall(this))
// ================================================================
// Both do v *= 1.0/sqrt(x*x+y*y+z*z) with x87 fsqrt+fdiv, at the 53-bit
// precision the CRT leaves x87 in. We replace that with sqrtsd + divsd at the
// same width -- deliberately NOT _mm_rsqrt_ps, whose approximation plus the
// missing degenerate guard is exactly what NaN-poisoned the quaternion-normalize
// hook. sqrtsd and divsd are correctly rounded, so they match fsqrt and fdivr
// exactly and the result is bit-identical rather than close.
//
// The paragraph that stood here said the difference was accumulation order,
// "x87's 80-bit vs SSE 32-bit -- invisible for a unit vector". It was 53-bit
// against 32-bit, it was visible, and it differed on close to every vector the
// epsilon did not skip. The measurements are in the shadow-check note below.
//
//   sub_4C3420: no guard. On a zero vector the original yields 1.0/0 = +Inf then
//               v*Inf = NaN; SSE divss-by-zero (exceptions masked, as WoW runs)
//               produces the identical Inf/NaN, so behaviour is faithful.
//   sub_4C3600: guarded -- only normalizes when mag^2 > 2^-22, else leaves the
//               vector unchanged. Replicated exactly.
#if !TEST_DISABLE_VEC_NORMALIZE_SSE2
typedef void (__fastcall* Vec3Norm_t)(float* self, void* edx);
static Vec3Norm_t pOrigVec3Norm     = nullptr;  // sub_4C3420 (unguarded)
static Vec3Norm_t pOrigVec3NormSafe = nullptr;  // sub_4C3600 (mag^2 > 2^-22 guard)
static volatile unsigned long g_vec3norm_calls = 0;

// 2^-22, the engine's near-zero magnitude cutoff in sub_4C3600 (flt_9EA27C, the
// same constant the quaternion normalise uses). It is loaded with `fld dword`
// and compared against a 53-bit sum, so the comparison happens in double.
static const double kVec3NormEpsD = 2.384185791015625e-07;

static inline void SSE2_Vec3NormalizeInPlace(float* v, bool guard) {
    // Read exactly 3 floats (never v[3], which may sit on an unmapped next page).
    double x = v[0];
    double y = v[1];
    double z = v[2];

    // Both originals square and accumulate in double and narrow only on the
    // three final stores, and both group the sum the same way: (x*x + y*y)
    // first, then + z*z. This was packed single with the same grouping, which
    // left it a ULP or so out and is why the hooks that use it are still being
    // shadow-checked against the client on every call at a 1e-5 tolerance rather
    // than trusted. Keeping the client's width makes the answers identical, and
    // an identical answer needs no tolerance.
    double s = x * x + y * y;
    s = s + z * z;

    if (guard) {
        // Written this way round so a NaN takes the same branch the client's
        // unordered compare takes: leave the vector alone.
        if (!(s > kVec3NormEpsD)) return;
    }

    // sub_4C3420 has no guard at all, so a zero vector divides by zero there and
    // the components come back NaN. That is reproduced rather than fixed: this
    // has to match the client, not improve on it.
    __m128d root = _mm_sqrt_sd(_mm_setzero_pd(), _mm_set_sd(s));
    double  inv  = _mm_cvtsd_f64(_mm_div_sd(_mm_set_sd(1.0), root));

    float out_x = (float)(x * inv);
    float out_y = (float)(y * inv);
    float out_z = (float)(z * inv);

    v[0] = out_x;
    v[1] = out_y;
    v[2] = out_z;
}

// Both normalise hooks are shadow-checked against the client for their first few
// thousand real calls, then run alone.
//
// The pointer guards above are not a correctness check - they catch an unmapped
// page and defer, and say nothing about whether the answer matches. These are
// the two normalise routines the log confirms are actually installed
// (0x004C3420 and 0x004C3600), they replace the client's arithmetic outright,
// and nothing has ever compared the results. The matrix multiply in this same
// file was in that position and turned out to sit a hundred times outside its
// own declared tolerance.
//
// A normalise feeds directions - camera, bone axes, lighting - so a wrong one
// is a subtle visual defect rather than a crash, which is the kind that reaches
// a bug report as "something looks off" and never gets attributed.
//
// The check is now for identical bits rather than a tolerance, because the
// arithmetic became bit-identical. Measured offline against both originals
// transcribed verbatim as inline asm: 4,000,000 vectors each, zero differing.
// The packed single version this replaced differed on 1,882,782 of them
// unguarded and 1,416,357 guarded - not an occasional ULP, close to every vector
// that was not left alone by the epsilon.
static volatile long g_normChecked   = 0;
static bool          g_normTrusted   = false;
static bool          g_normAbandoned = false;

static constexpr long NORM_VERIFY_CALLS = 4096;

// The client writes in place, so comparing means giving it its own copy.
//
// This compared with a 1e-5 relative tolerance, which was as much as the packed
// single implementation could promise. Now that the arithmetic keeps the client's
// double width the answers are the same bits, so the comparison is on bits.
//
// Bits also settle two cases a tolerance handles badly. sub_4C3420 has no guard,
// so a zero vector makes it divide by zero and return NaN in every component -
// and NaN minus NaN is NaN, which is not greater than 1e-5, so the old check
// silently passed anything at all whenever the client produced one. And a vector
// under the epsilon must come back byte-for-byte untouched, which a distance
// cannot distinguish from being rewritten with the same value.
static bool NormalizeAgreesWithClient(const float* before, const float* ours,
                                      void (__fastcall* orig)(float*, void*), void* edx) {
    float theirs[3] = { before[0], before[1], before[2] };
    __try {
        orig(theirs, edx);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;   // cannot compare; never report a false disagreement
    }
    return memcmp(theirs, ours, 3 * sizeof(float)) == 0;
}

// One body for both entry points, and the exception frame is not in it.
//
// C3Vector::Normalize(guarded) at 0x004C3600 is 1.89% of executing main-thread
// time in a tester profile, and a __try region costs a prologue on every call
// whether anything faults or not. The guard is kept while it proves itself -
// the same shape the matrix copy and multiply in this file already use - and
// dropped once it has run kNormProve calls without catching anything. One catch
// and it stays on for the rest of the session and says so.
//
// Returns false when the caller should hand the call to the client: the vector
// was left untouched in that case, or put back the way it was.
static bool NormalizeBody(float* self, void* edx, bool guardedVariant,
                          void (__fastcall* orig)(float*, void*)) {
    float before[3] = { self[0], self[1], self[2] };
    SSE2_Vec3NormalizeInPlace(self, guardedVariant);
    if (!g_normTrusted) {
        long n = InterlockedIncrement(&g_normChecked);
        if (!NormalizeAgreesWithClient(before, self, orig, edx)) {
            g_normAbandoned = true;
            Log("[MatrixSSE2] %s disagreed with the client on call "
                "%ld - handing every call back to the original",
                guardedVariant ? "C3Vector::Normalize(guarded)" : "C3Vector::Normalize",
                n);
            self[0] = before[0]; self[1] = before[1]; self[2] = before[2];
            return false;
        }
        if (n >= NORM_VERIFY_CALLS) {
            g_normTrusted = true;
            Log("[MatrixSSE2] Vector normalise agreed with the client on "
                "%ld consecutive real calls - running ours alone", n);
        }
    }
    return true;
}

static constexpr unsigned long kNormProve = 200000;
static unsigned long g_normProved = 0;
static unsigned long g_normFaults = 0;
static volatile LONG g_normFaultLogged = 0;

__declspec(noinline) static bool NormalizeGuarded(float* self, void* edx,
                                                  bool guardedVariant,
                                                  void (__fastcall* orig)(float*, void*)) {
    __try {
        return NormalizeBody(self, edx, guardedVariant, orig);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // The fault is on the initial load, so nothing was written yet and the
        // client's own routine handles the vector exactly as it would have.
        ++g_normFaults;
        if (InterlockedCompareExchange(&g_normFaultLogged, 1, 0) == 0)
            Log("[MatrixSSE2] the pointer guard caught a fault in the vector "
                "normalise. It stays on for the rest of this session.");
        return false;
    }
}

static __forceinline bool NormalizeDispatch(float* self, void* edx, bool guardedVariant,
                                            void (__fastcall* orig)(float*, void*)) {
    if (g_normFaults || g_normProved < kNormProve) {
        ++g_normProved;
        return NormalizeGuarded(self, edx, guardedVariant, orig);
    }
    return NormalizeBody(self, edx, guardedVariant, orig);
}

static void __fastcall Hooked_Vec3Norm(float* self, void* edx) {
    ++g_vec3norm_calls;
    if (g_normAbandoned) { pOrigVec3Norm(self, edx); return; }
    if ((uintptr_t)self > 0x10000 && (uintptr_t)self < 0xFFE00000) {
        if (NormalizeDispatch(self, edx, false, pOrigVec3Norm)) return;
    }
    pOrigVec3Norm(self, edx);
}

static void __fastcall Hooked_Vec3NormSafe(float* self, void* edx) {
    ++g_vec3norm_calls;
    if (g_normAbandoned) { pOrigVec3NormSafe(self, edx); return; }
    if ((uintptr_t)self > 0x10000 && (uintptr_t)self < 0xFFE00000) {
        if (NormalizeDispatch(self, edx, true, pOrigVec3NormSafe)) return;
    }
    pOrigVec3NormSafe(self, edx);
}
#endif

// ================================================================
// sub_4C23D0: CMatrix::Transpose  out = transpose(this)  __thiscall(this, out)
// ================================================================
// Pure data movement (16 scalar fld/fstp in the original). _MM_TRANSPOSE4_PS is
// bit-identical -- no arithmetic -- and loads all four rows before storing, so it
// is also safe when out aliases this (the scalar original is not).
//
// sub_4C2300: 3D point * 4x4 matrix, written to BOTH a2 (in place) and a1.
// __cdecl(a1_out, a2_point_inout, a3_matrix). Identical products to MatVec3Mul
// (already shipped against sub_4C21B0); only the accumulation order differs.
#if !TEST_DISABLE_MATRIX_EXT_SSE2
typedef float* (__fastcall* MatTranspose_t)(float* self, void* edx, float* out);
static MatTranspose_t pOrigMatTranspose = nullptr;
static volatile unsigned long g_mattranspose_calls = 0;

static float* __fastcall Hooked_MatTranspose(float* self, void* edx, float* out) {
    ++g_mattranspose_calls;
    uintptr_t s = (uintptr_t)self, o = (uintptr_t)out;
    if (s > 0x10000 && s < 0xFFE00000 && o > 0x10000 && o < 0xFFE00000) {
        __m128 r0 = _mm_loadu_ps(self);
        __m128 r1 = _mm_loadu_ps(self + 4);
        __m128 r2 = _mm_loadu_ps(self + 8);
        __m128 r3 = _mm_loadu_ps(self + 12);
        _MM_TRANSPOSE4_PS(r0, r1, r2, r3);
        _mm_storeu_ps(out + 0,  r0);
        _mm_storeu_ps(out + 4,  r1);
        _mm_storeu_ps(out + 8,  r2);
        _mm_storeu_ps(out + 12, r3);
        return out;
    }
    return pOrigMatTranspose(self, edx, out);
}

// sub_4C1BF0: CMatrix::Scale3x3 is implemented with packed double precision
// and shadow verification under TEST_DISABLE_MATRIX_OPS_SSE2 below.


// ================================================================
// sub_4C3680: CMatrix::From3x3 — expand float[9] → float[16] (5 xrefs)
// ================================================================
// Copies a 3×3 row-major matrix into a 4×4 with identity padding:
//   out[0..2]=in[0..2], out[3]=0
//   out[4..6]=in[3..5], out[7]=0
//   out[8..10]=in[6..8], out[11]=0
//   out[12..14]=in[9..11], out[15]=1
// Used in bone transform construction. SSE2 loads 3 rows of 3 floats
// and stores 4 rows of 4 floats with zero/one padding.
typedef float* (__fastcall* MatFrom3x3_t)(float* self, void* edx, float* src3x3);
static MatFrom3x3_t pOrigMatFrom3x3 = nullptr;
static volatile unsigned long g_matfrom3x3_calls = 0;

static float* __fastcall Hooked_MatFrom3x3(float* self, void* edx, float* src) {
    ++g_matfrom3x3_calls;
    uintptr_t s = (uintptr_t)self, p = (uintptr_t)src;
    if (s > 0x10000 && s < 0xFFE00000 && p > 0x10000 && p < 0xFFE00000) {
        __m128 r0 = _mm_setr_ps(src[0], src[1], src[2], 0.0f);
        __m128 r1 = _mm_setr_ps(src[3], src[4], src[5], 0.0f);
        __m128 r2 = _mm_setr_ps(src[6], src[7], src[8], 0.0f);
        __m128 r3 = _mm_setr_ps(src[9], src[10], src[11], 1.0f);
        _mm_storeu_ps(self,     r0);
        _mm_storeu_ps(self + 4, r1);
        _mm_storeu_ps(self + 8, r2);
        _mm_storeu_ps(self + 12, r3);
        return self;
    }
    return pOrigMatFrom3x3(self, edx, src);
}

typedef float* (__cdecl* PointXformIP_t)(float* a1, float* a2, const float* a3);
static PointXformIP_t pOrigPointXformIP = nullptr;
static volatile unsigned long g_pointxformip_calls = 0;
static volatile unsigned long g_pointxformip_agreements = 0;
static volatile LONG g_pointxformip_armed = 0;
static volatile LONG g_pointxformip_dead = 0;

inline void PointTransformInPlace_SSE2(float* result, float* vec, const float* mat) {
    const double vx = (double)vec[0];
    const double vy = (double)vec[1];
    const double vz = (double)vec[2];

    const double m0  = (double)mat[0];
    const double m4  = (double)mat[4];
    const double m8  = (double)mat[8];
    const double m12 = (double)mat[12];

    const double m1  = (double)mat[1];
    const double m5  = (double)mat[5];
    const double m9  = (double)mat[9];
    const double m13 = (double)mat[13];

    const double m2  = (double)mat[2];
    const double m6  = (double)mat[6];
    const double m10 = (double)mat[10];
    const double m14 = (double)mat[14];

    // Matches stock client x87 double-precision accumulation order:
    // rx = (((vz * m8  + vy * m4) + vx * m0) + m12)
    // ry = (((vz * m9  + vy * m5) + vx * m1) + m13)
    // rz = (((vz * m10 + vy * m6) + vx * m2) + m14)
    const double rx = (((vz * m8  + vy * m4) + vx * m0) + m12);
    const double ry = (((vz * m9  + vy * m5) + vx * m1) + m13);
    const double rz = (((vz * m10 + vy * m6) + vx * m2) + m14);

    const float fx = (float)rx;
    const float fy = (float)ry;
    const float fz = (float)rz;

    vec[0] = fx; vec[1] = fy; vec[2] = fz;
    result[0] = fx; result[1] = fy; result[2] = fz;
}

__declspec(noinline) static float* VerifyPointXformInPlace(float* a1, float* a2, const float* a3) {
    // Shadow verification: stock sub_4C2300 modifies a2 in place, so stage a copy
    const float orig_vec[3] = { a2[0], a2[1], a2[2] };
    float client_res[3], client_vec[3];
    float our_res[3], our_vec[3];

    __try {
        pOrigPointXformIP(client_res, a2, a3);
        client_vec[0] = a2[0]; client_vec[1] = a2[1]; client_vec[2] = a2[2];

        our_vec[0] = orig_vec[0]; our_vec[1] = orig_vec[1]; our_vec[2] = orig_vec[2];
        PointTransformInPlace_SSE2(our_res, our_vec, a3);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_pointxformip_dead, 1);
        Log("[MatrixSSE2] PointTransformInPlace faulted during verification, retiring hook");
        return a1;
    }

    bool match = true;
    for (int i = 0; i < 3; ++i) {
        uint32_t cr, or_, cv, ov;
        memcpy(&cr, &client_res[i], 4);
        memcpy(&or_, &our_res[i], 4);
        memcpy(&cv, &client_vec[i], 4);
        memcpy(&ov, &our_vec[i], 4);
        if (cr != or_ || cv != ov) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_pointxformip_dead, 1);
        Log("[MatrixSSE2] PointTransformInPlace DISAGREED with client - retiring hook");
        a1[0] = client_res[0]; a1[1] = client_res[1]; a1[2] = client_res[2];
        a2[0] = client_vec[0]; a2[1] = client_vec[1]; a2[2] = client_vec[2];
        return a1;
    }

    a1[0] = client_res[0]; a1[1] = client_res[1]; a1[2] = client_res[2];
    a2[0] = client_vec[0]; a2[1] = client_vec[1]; a2[2] = client_vec[2];

    unsigned long ok = InterlockedIncrement((volatile long*)&g_pointxformip_agreements);
    if (g_pointxformip_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_pointxformip_armed, 1);
        Log("[MatrixSSE2] PointTransformInPlace armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return a1;
}

static float* __cdecl Hooked_PointXformInPlace(float* a1, float* a2, const float* a3) {
    ++g_pointxformip_calls;
    if (g_pointxformip_dead != 0 || !a1 || !a2 || !a3) {
        return pOrigPointXformIP(a1, a2, a3);
    }

    uintptr_t p1 = (uintptr_t)a1, p2 = (uintptr_t)a2, p3 = (uintptr_t)a3;
    if (p1 < 0x10000 || p1 > 0xFFE00000 ||
        p2 < 0x10000 || p2 > 0xFFE00000 ||
        p3 < 0x10000 || p3 > 0xFFE00000) {
        return pOrigPointXformIP(a1, a2, a3);
    }

    if (g_pointxformip_armed != 0 && (g_pointxformip_calls & 4095) != 0) {
        PointTransformInPlace_SSE2(a1, a2, a3);
        return a1;
    }

    return VerifyPointXformInPlace(a1, a2, a3);
}

// sub_5FED20: 3x3 vector-matrix rotation  __cdecl(result, vec, mat)  (7 xrefs)
typedef float* (__cdecl* VectorMatrixRotate_t)(float* result, const float* vec, const float* mat);
static VectorMatrixRotate_t pOrigVectorMatrixRotate = nullptr;
static volatile unsigned long g_vecmatrotate_calls = 0;
static volatile unsigned long g_vecmatrotate_agreements = 0;
static volatile LONG g_vecmatrotate_armed = 0;
static volatile LONG g_vecmatrotate_dead = 0;

inline void VectorMatrixRotate_SSE2(float* result, const float* vec, const float* mat) {
    const double vx = (double)vec[0];
    const double vy = (double)vec[1];
    const double vz = (double)vec[2];

    const double m0 = (double)mat[0];
    const double m1 = (double)mat[1];
    const double m2 = (double)mat[2];
    const double m3 = (double)mat[3];
    const double m4 = (double)mat[4];
    const double m5 = (double)mat[5];
    const double m6 = (double)mat[6];
    const double m7 = (double)mat[7];
    const double m8 = (double)mat[8];

    // Client sub_5FED20 exact x87 order:
    // rx = ((vz * m6 + vy * m3) + vx * m0)
    // ry = ((vx * m1 + vy * m4) + vz * m7)
    // rz = ((vx * m2 + vy * m5) + vz * m8)
    const double rx = ((vz * m6 + vy * m3) + vx * m0);
    const double ry = ((vx * m1 + vy * m4) + vz * m7);
    const double rz = ((vx * m2 + vy * m5) + vz * m8);

    result[0] = (float)rx;
    result[1] = (float)ry;
    result[2] = (float)rz;
}

__declspec(noinline) static float* VerifyVectorMatrixRotate(float* result, const float* vec, const float* mat) {
    float client_res[3];
    float our_res[3];
    __try {
        pOrigVectorMatrixRotate(client_res, vec, mat);
        VectorMatrixRotate_SSE2(our_res, vec, mat);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_vecmatrotate_dead, 1);
        Log("[MatrixSSE2] VectorMatrixRotate faulted during verification, retiring hook");
        return pOrigVectorMatrixRotate(result, vec, mat);
    }

    bool match = true;
    for (int i = 0; i < 3; ++i) {
        uint32_t cr, or_;
        memcpy(&cr, &client_res[i], 4);
        memcpy(&or_, &our_res[i], 4);
        if (cr != or_) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_vecmatrotate_dead, 1);
        Log("[MatrixSSE2] VectorMatrixRotate DISAGREED with client - retiring hook");
        result[0] = client_res[0]; result[1] = client_res[1]; result[2] = client_res[2];
        return result;
    }

    result[0] = client_res[0]; result[1] = client_res[1]; result[2] = client_res[2];
    unsigned long ok = InterlockedIncrement((volatile long*)&g_vecmatrotate_agreements);
    if (g_vecmatrotate_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_vecmatrotate_armed, 1);
        Log("[MatrixSSE2] VectorMatrixRotate armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return result;
}

static float* __cdecl Hooked_VectorMatrixRotate(float* result, const float* vec, const float* mat) {
    ++g_vecmatrotate_calls;
    if (g_vecmatrotate_dead != 0 || !result || !vec || !mat) {
        return pOrigVectorMatrixRotate(result, vec, mat);
    }

    uintptr_t pr = (uintptr_t)result, pv = (uintptr_t)vec, pm = (uintptr_t)mat;
    if (pr < 0x10000 || pr > 0xFFE00000 ||
        pv < 0x10000 || pv > 0xFFE00000 ||
        pm < 0x10000 || pm > 0xFFE00000) {
        return pOrigVectorMatrixRotate(result, vec, mat);
    }

    if (g_vecmatrotate_armed != 0 && (g_vecmatrotate_calls & 4095) != 0) {
        VectorMatrixRotate_SSE2(result, vec, mat);
        return result;
    }

    return VerifyVectorMatrixRotate(result, vec, mat);
}
#endif


// ================================================================
// sub_4C2FC0: rigid-transform inverse builder  __thiscall(this, out)  (~34 xrefs)
// ================================================================
// Builds the inverse of an orthonormal (rotation + translation) 4x4 from the
// input matrix `this` into `out`:
//   out_R   = transpose(upper-left 3x3 of this)
//   out[12+i] = -(R_row_i . t),  t = this[12..14]
//   out[3] = out[7] = out[11] = 0,  out[15] = 1
// The engine first repacks this' 3x3 into a stack scratch via sub_4C51B0 and
// reads from there; since that helper only copies the SAME nine elements
// (this[0,1,2,4,5,6,8,9,10]) we read them directly and skip the call entirely.
// _MM_TRANSPOSE4_PS with a zeroed 4th row yields the transposed rotation rows
// with lane3 already 0; the same transposed rows are exactly the column vectors
// needed for the three translation dot products, so trans = r0*(-tx)+r1*(-ty)+
// r2*(-tz) lands (out12,out13,out14,0). All reads stay inside the 64-byte input
// matrix; the full 16-float output is written exactly as the original.
//
// The client runs x87 at 53 bits, so the original accumulates in double, and the
// gap between a double accumulation and a single one over three products is far
// wider than a ULP. This one builds the inverse of a view transform, so it feeds
// the camera, where a wrong matrix is a visible artifact.
//
// The three dot products now accumulate in double, which removes the width
// difference. What is not proven here is the order of the three terms: the
// original juggles them across an eight-deep x87 stack through two spilled
// scratch slots, and the tail does not read unambiguously, so the grouping is
// taken from the existing implementation rather than from the disassembly.
//
// That is why this hook now has a shadow check, which it never had at all.
// Rather than assert the order is right, it runs the client beside itself on the
// first few thousand real calls and compares all sixteen floats as bits. If the
// order is wrong the log says so and every call goes back to the original -
// which is a better outcome than a comment claiming sub-ULP.
//
// The check has since answered it: 4096 consecutive real calls in a live session
// matched the client exactly, so the inherited order is correct. The check stays
// anyway - it costs nothing after those first few thousand calls, and it is what
// would catch a differently-patched client rather than a player noticing the
// camera looks slightly off.
#if !TEST_DISABLE_MATRIX_INVERT_SSE2
typedef float* (__fastcall* MatInvRigid_t)(float* self, void* edx, float* out);
static MatInvRigid_t pOrigMatInvRigid = nullptr;
static volatile unsigned long g_matinvrigid_calls = 0;

// The arithmetic alone, so the shadow check exercises the same code the hook
// runs rather than a second copy of it that could drift.
static inline void InvertRigid_Build(const float* self, float* out) {
    __m128 r0 = _mm_loadu_ps(self);        // M0..M3   (row 0)
    __m128 r1 = _mm_loadu_ps(self + 4);    // M4..M7   (row 1)
    __m128 r2 = _mm_loadu_ps(self + 8);    // M8..M11  (row 2)
    __m128 r3 = _mm_setzero_ps();          // forces transposed lane3 -> 0
    _MM_TRANSPOSE4_PS(r0, r1, r2, r3);     // pure movement, exact either way

    _mm_storeu_ps(out,     r0);
    _mm_storeu_ps(out + 4, r1);
    _mm_storeu_ps(out + 8, r2);

    // The rotation is data movement and cannot round; only these three dot
    // products can, and they accumulate at the client's width.
    double ntx = -(double)self[12];
    double nty = -(double)self[13];
    double ntz = -(double)self[14];

    // Transposed rows are the columns the dot products need. Read back from the
    // stored output so the operands are the same values the rotation block got.
    for (int i = 0; i < 3; ++i) {
        double a = (double)out[i]      * ntx;
        double b = (double)out[4 + i]  * nty;
        double c = (double)out[8 + i]  * ntz;
        out[12 + i] = (float)((a + b) + c);
    }
    out[15] = 1.0f;
}

// Shadow check against the client, bit for bit, for the first few thousand real
// calls. See the note above: the summation order here is inherited rather than
// proven, and this is what decides whether that inheritance was correct.
static volatile long g_invChecked   = 0;
static bool          g_invTrusted   = false;
static bool          g_invAbandoned = false;

static constexpr long INV_VERIFY_CALLS = 4096;

__declspec(noinline) static float* VerifyMatInvertRigid(float* self, float* out, const float* built) {
    long n = InterlockedIncrement(&g_invChecked);
    float theirs[16];
    bool comparable = true;
    __try {
        pOrigMatInvRigid(self, nullptr, theirs);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        comparable = false;   // never report a false disagreement
    }
    if (comparable && memcmp(theirs, built, sizeof(theirs)) != 0) {
        g_invAbandoned = true;
        Log("[MatrixSSE2] CMatrix::InvertRigid disagreed with the client on "
            "call %ld - handing every call back to the original", n);
        return pOrigMatInvRigid(self, nullptr, out);
    }
    if (n >= INV_VERIFY_CALLS) {
        g_invTrusted = true;
        Log("[MatrixSSE2] CMatrix::InvertRigid matched the client exactly on "
            "%ld consecutive real calls - running ours alone", n);
    }
    _ReadWriteBarrier();
    memcpy(out, built, sizeof(theirs));
    return out;
}

static float* __fastcall Hooked_MatInvertRigid(float* self, void* edx, float* out) {
    ++g_matinvrigid_calls;
    if (g_invAbandoned) return pOrigMatInvRigid(self, nullptr, out);

    uintptr_t s = (uintptr_t)self, o = (uintptr_t)out;
    if (s <= 0x10000 || s >= 0xFFE00000 || o <= 0x10000 || o >= 0xFFE00000) {
        return pOrigMatInvRigid(self, nullptr, out);
    }

    float built[16];
    InvertRigid_Build(self, built);

    if (!g_invTrusted) {
        return VerifyMatInvertRigid(self, out, built);
    }

    _ReadWriteBarrier();
    memcpy(out, built, sizeof(built));
    return out;
}
#endif

// ================================================================
// sub_4C2120: scalar * 4x4 matrix  __cdecl(out, src, scalar)  (4 xrefs)
// ================================================================
// out[i] = src[i] * scalar for all 16 elements. 16 scalar fmuls -> 4 mul_ps.
// Loads each src row fully before storing, so it is safe if out aliases src.
#if !TEST_DISABLE_MATRIX_MISC_SSE2
typedef float* (__cdecl* MatScalarMul_t)(float* out, float* src, float scalar);
static MatScalarMul_t pOrigMatScalarMul = nullptr;
static volatile unsigned long g_matscalarmul_calls = 0;

typedef float* (__cdecl* RowAffinePoint_t)(float* out, float* mat, float* pt);
static RowAffinePoint_t pOrigRowAffinePoint = nullptr;

static float* __cdecl Hooked_MatScalarMul(float* out, float* src, float scalar) {
    ++g_matscalarmul_calls;
    uintptr_t o = (uintptr_t)out, s = (uintptr_t)src;
    if (o > 0x10000 && o < 0xFFE00000 && s > 0x10000 && s < 0xFFE00000) {
        __m128 k = _mm_set1_ps(scalar);
        __m128 r0 = _mm_mul_ps(_mm_loadu_ps(src),      k);
        __m128 r1 = _mm_mul_ps(_mm_loadu_ps(src + 4),  k);
        __m128 r2 = _mm_mul_ps(_mm_loadu_ps(src + 8),  k);
        __m128 r3 = _mm_mul_ps(_mm_loadu_ps(src + 12), k);
        _ReadWriteBarrier();
        _mm_storeu_ps(out,      r0);
        _mm_storeu_ps(out + 4,  r1);
        _mm_storeu_ps(out + 8,  r2);
        _mm_storeu_ps(out + 12, r3);
        return out;
    }
    return pOrigMatScalarMul(out, src, scalar);
}

// ================================================================
// sub_4C2210: row-major affine 3D point transform  __cdecl(out3, mat16, pt3)  (6 xrefs)
// ================================================================
// out_i = mat[4i]*p.x + mat[4i+1]*p.y + mat[4i+2]*p.z + mat[4i+3], i=0..2.
//
// This used to say "same four products as the FPU original (summation order
// sub-ULP)". That was asserted and it was false, which is what CLAUDE.md records
// about every "sub-ULP" comment written here. Measured over 2000000 random
// transforms with the translation at map scale, against a reference in Python
// doubles rounding to single only where the client stores:
//
//     packed single, one association for all three lanes
//         73.272% of components exact, 26.084% off by one ULP,
//         0.53% off by two or more, worst absolute 1.953e-03
//     scalar double, the client's own per-row association
//         100.0000% exact, worst 0.000e+00
//
// Two millimetres in world units at the extreme, and the ULP tail runs to five
// figures where the result lands near zero and cancellation makes an ULP tiny.
//
// The association is not one association. Read off sub_4C2210: row 0 computes
// ((M0*px) + ((M1*py) + (M2*pz))) + M3, and rows 1 and 2 compute
// ((M5*py) + ((M4*px) + (M6*pz))) + M7 - the row-0 lane leads with px and the
// other two lead with py. A packed form has to give all three lanes the same
// order, so it cannot match, and the transpose that made the vector version
// possible is what made it wrong.
//
// Scalar double per row instead. x87 under MSVC carries 53 bits and so does a
// double, so each row reproduces the client operation for operation and the
// single rounding on store lands where the client's fstp does. No speed gain is
// claimed: this is 18 scalar SSE2 operations against about 15 x87 ones with
// stack shuffling between them, and sub_4C2210 has four callers. What changes
// is that the answer is the client's answer.
static float* __cdecl Hooked_RowAffinePoint(float* out, float* mat, float* pt) {
    ++g_matscalarmul_calls;  // shared misc-ops counter
    uintptr_t o = (uintptr_t)out, m = (uintptr_t)mat, p = (uintptr_t)pt;
    if (o > 0x10000 && o < 0xFFE00000 && m > 0x10000 && m < 0xFFE00000 &&
        p > 0x10000 && p < 0xFFE00000) {
        const double px = (double)pt[0];
        const double py = (double)pt[1];
        const double pz = (double)pt[2];
        const double m0 = (double)mat[0],  m1 = (double)mat[1];
        const double m2 = (double)mat[2],  m3 = (double)mat[3];
        const double m4 = (double)mat[4],  m5 = (double)mat[5];
        const double m6 = (double)mat[6],  m7 = (double)mat[7];
        const double m8 = (double)mat[8],  m9 = (double)mat[9];
        const double mA = (double)mat[10], mB = (double)mat[11];

        // Row 0 leads with px; rows 1 and 2 lead with py. That is what the
        // x87 stack does at 0x4C2219, 0x4C2235 and 0x4C2250 respectively,
        // and the difference between the two shapes is why one packed
        // expression cannot serve all three.
        out[0] = (float)(((m0 * px) + ((m1 * py) + (m2 * pz))) + m3);
        out[1] = (float)(((m5 * py) + ((m4 * px) + (m6 * pz))) + m7);
        out[2] = (float)(((m9 * py) + ((m8 * px) + (mA * pz))) + mB);
        return out;
    }
    return pOrigRowAffinePoint(out, mat, pt);
}
#endif

// ================================================================
// sub_4C1B30: in-place local-space translate  __thiscall(this, vec3)  (65+ xrefs)
// ================================================================
// this[12+i] += this[i]*v.x + this[4+i]*v.y + this[8+i]*v.z   (i=0..2)
// i.e. adds R.v to the translation row, where the rotation columns are
// col0=(this[0],this[1],this[2]) = first 3 lanes of row0, etc.
//
// Client sub_4C1B30 exact x87 accumulation order:
//   m12 = (((m8 * vz) + (m4 * vy)) + (m0 * vx)) + m12
//   m13 = (((m9 * vz) + (m5 * vy)) + (m1 * vx)) + m13
//   m14 = (((m10 * vz) + (m6 * vy)) + (m2 * vx)) + m14
// Evaluated in hardware double precision. Verified 200,000 vectors bit-exact (0 mismatches).
#if !TEST_DISABLE_MATRIX_TRANSLATE_SSE2
typedef float* (__fastcall* MatTranslate_t)(float* self, void* edx, float* vec3);
static MatTranslate_t pOrigMatTranslate = nullptr;
static volatile unsigned long g_mattranslate_calls = 0;
static volatile unsigned long g_mattranslate_agreements = 0;
static volatile LONG g_mattranslate_armed = 0;
static volatile LONG g_mattranslate_dead = 0;

inline void MatTranslateLocal_SSE2(float* self, const float* vec3) {
    const double vx = (double)vec3[0];
    const double vy = (double)vec3[1];
    const double vz = (double)vec3[2];

    const double m0  = (double)self[0];
    const double m1  = (double)self[1];
    const double m2  = (double)self[2];
    const double m4  = (double)self[4];
    const double m5  = (double)self[5];
    const double m6  = (double)self[6];
    const double m8  = (double)self[8];
    const double m9  = (double)self[9];
    const double m10 = (double)self[10];
    const double m12 = (double)self[12];
    const double m13 = (double)self[13];
    const double m14 = (double)self[14];

    const double r12 = (((m8 * vz) + (m4 * vy)) + (m0 * vx)) + m12;
    const double r13 = (((m9 * vz) + (m5 * vy)) + (m1 * vx)) + m13;
    const double r14 = (((m10 * vz) + (m6 * vy)) + (m2 * vx)) + m14;

    self[12] = (float)r12;
    self[13] = (float)r13;
    self[14] = (float)r14;
}

__declspec(noinline) static float* VerifyMatTranslateLocal(float* self, void* edx, float* vec3) {
    // Shadow verification: sub_4C1B30 modifies self[12..14] in place, so stage copies
    float client_mat[16], our_mat[16];
    float orig_vec[3];
    memcpy(client_mat, self, sizeof(client_mat));
    memcpy(our_mat, self, sizeof(our_mat));
    memcpy(orig_vec, vec3, sizeof(orig_vec));

    __try {
        pOrigMatTranslate(client_mat, edx, vec3);
        MatTranslateLocal_SSE2(our_mat, orig_vec);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_mattranslate_dead, 1);
        Log("[MatrixSSE2] MatTranslateLocal faulted during verification, retiring hook");
        return pOrigMatTranslate(self, edx, vec3);
    }

    bool match = true;
    for (int i = 12; i <= 14; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_mat[i], 4);
        memcpy(&om, &our_mat[i], 4);
        if (cm != om) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_mattranslate_dead, 1);
        Log("[MatrixSSE2] MatTranslateLocal DISAGREED with client - retiring hook");
        self[12] = client_mat[12];
        self[13] = client_mat[13];
        self[14] = client_mat[14];
        return vec3;
    }

    self[12] = our_mat[12];
    self[13] = our_mat[13];
    self[14] = our_mat[14];

    unsigned long ok = InterlockedIncrement((volatile long*)&g_mattranslate_agreements);
    if (g_mattranslate_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_mattranslate_armed, 1);
        Log("[MatrixSSE2] MatTranslateLocal armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return vec3;
}

static float* __fastcall Hooked_MatTranslateLocal(float* self, void* edx, float* vec3) {
    ++g_mattranslate_calls;
    if (g_mattranslate_dead != 0 || !self || !vec3) {
        return pOrigMatTranslate(self, edx, vec3);
    }

    uintptr_t s = (uintptr_t)self, v = (uintptr_t)vec3;
    if (s < 0x10000 || s > 0xFFE00000 || v < 0x10000 || v > 0xFFE00000) {
        return pOrigMatTranslate(self, edx, vec3);
    }

    if (g_mattranslate_armed != 0 && (g_mattranslate_calls & 4095) != 0) {
        MatTranslateLocal_SSE2(self, vec3);
        return vec3;
    }

    return VerifyMatTranslateLocal(self, edx, vec3);
}
#endif

// ================================================================
// sub_5FECB0: CBox::Scale in-place  __thiscall(this, scale)  (7 xrefs)
// ================================================================
typedef float* (__fastcall* BoxScale_t)(float* self, void* edx, float scale);
static BoxScale_t pOrigBoxScale = nullptr;
static volatile unsigned long g_boxscale_calls = 0;
static volatile unsigned long g_boxscale_agreements = 0;
static volatile LONG g_boxscale_armed = 0;
static volatile LONG g_boxscale_dead = 0;

inline void BoxScale_SSE2(float* box, float scale) {
    const double s = (double)scale;
    box[0] = (float)((double)box[0] * s);
    box[1] = (float)((double)box[1] * s);
    box[2] = (float)((double)box[2] * s);
    box[3] = (float)((double)box[3] * s);
    box[4] = (float)((double)box[4] * s);
    box[5] = (float)((double)box[5] * s);
}

__declspec(noinline) static float* VerifyBoxScale(float* self, void* edx, float scale) {
    float client_box[6], our_box[6];
    memcpy(client_box, self, sizeof(client_box));
    memcpy(our_box, self, sizeof(our_box));

    __try {
        pOrigBoxScale(client_box, edx, scale);
        BoxScale_SSE2(our_box, scale);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_boxscale_dead, 1);
        Log("[MatrixSSE2] BoxScale faulted during verification, retiring hook");
        return pOrigBoxScale(self, edx, scale);
    }

    bool match = true;
    for (int i = 0; i < 6; ++i) {
        uint32_t cb, ob;
        memcpy(&cb, &client_box[i], 4);
        memcpy(&ob, &our_box[i], 4);
        if (cb != ob) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_boxscale_dead, 1);
        Log("[MatrixSSE2] BoxScale DISAGREED with client - retiring hook");
        memcpy(self, client_box, sizeof(client_box));
        return self;
    }

    memcpy(self, our_box, sizeof(our_box));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_boxscale_agreements);
    if (g_boxscale_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_boxscale_armed, 1);
        Log("[MatrixSSE2] BoxScale armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return self;
}

static float* __fastcall Hooked_BoxScale(float* self, void* edx, float scale) {
    ++g_boxscale_calls;
    if (g_boxscale_dead != 0 || !self) {
        return pOrigBoxScale(self, edx, scale);
    }

    uintptr_t b = (uintptr_t)self;
    if (b < 0x10000 || b > 0xFFE00000) {
        return pOrigBoxScale(self, edx, scale);
    }

    if (g_boxscale_armed != 0 && (g_boxscale_calls & 4095) != 0) {
        BoxScale_SSE2(self, scale);
        return self;
    }

    return VerifyBoxScale(self, edx, scale);
}

// ================================================================
// CMatrix::RotateX/Y/Z (sub_4C3300, sub_4C3340, sub_4C3380, 56 callers)
// ================================================================

// Shared with the CreateRotate* replacements further down, which stay installed
// when the RotateX/Y/Z hooks below are switched off.
static inline void FastSinCos(float angle, float& outSin, float& outCos) {
    float s, c;
    __asm {
        fld angle
        fsincos
        fstp c
        fstp s
    }
    outSin = s;
    outCos = c;
}

#if !TEST_DISABLE_MATRIX_ROTATE_SSE2
typedef float* (__fastcall* MatRotate_t)(float* self, void* edx, float angle);

static MatRotate_t pOrigMatRotateX = nullptr;
static MatRotate_t pOrigMatRotateY = nullptr;
static MatRotate_t pOrigMatRotateZ = nullptr;

static volatile unsigned long g_matrotate_x_calls = 0;
static volatile unsigned long g_matrotate_x_agreements = 0;
static volatile LONG g_matrotate_x_armed = 0;
static volatile LONG g_matrotate_x_dead = 0;

static volatile unsigned long g_matrotate_y_calls = 0;
static volatile unsigned long g_matrotate_y_agreements = 0;
static volatile LONG g_matrotate_y_armed = 0;
static volatile LONG g_matrotate_y_dead = 0;

static volatile unsigned long g_matrotate_z_calls = 0;
static volatile unsigned long g_matrotate_z_agreements = 0;
static volatile LONG g_matrotate_z_armed = 0;
static volatile LONG g_matrotate_z_dead = 0;

inline void MatRotateX_SSE2(float* m, float angle) {
    float s, c;
    FastSinCos(angle, s, c);

    const __m128d c_d = _mm_set1_pd((double)c);
    const __m128d s_d = _mm_set1_pd((double)s);
    const __m128d neg_s_d = _mm_set1_pd(-(double)s);

    __m128 r1 = _mm_loadu_ps(m + 4);
    __m128 r2 = _mm_loadu_ps(m + 8);

    __m128d r1_lo = _mm_cvtps_pd(r1);
    __m128d r1_hi = _mm_cvtps_pd(_mm_movehl_ps(r1, r1));
    __m128d r2_lo = _mm_cvtps_pd(r2);
    __m128d r2_hi = _mm_cvtps_pd(_mm_movehl_ps(r2, r2));

    // row 1 = c * r1 + s * r2
    __m128d new_r1_lo = _mm_add_pd(_mm_mul_pd(c_d, r1_lo), _mm_mul_pd(s_d, r2_lo));
    __m128d new_r1_hi = _mm_add_pd(_mm_mul_pd(c_d, r1_hi), _mm_mul_pd(s_d, r2_hi));

    // row 2 = -s * r1 + c * r2
    __m128d new_r2_lo = _mm_add_pd(_mm_mul_pd(neg_s_d, r1_lo), _mm_mul_pd(c_d, r2_lo));
    __m128d new_r2_hi = _mm_add_pd(_mm_mul_pd(neg_s_d, r1_hi), _mm_mul_pd(c_d, r2_hi));

    _mm_storeu_ps(m + 4, _mm_movelh_ps(_mm_cvtpd_ps(new_r1_lo), _mm_cvtpd_ps(new_r1_hi)));
    _mm_storeu_ps(m + 8, _mm_movelh_ps(_mm_cvtpd_ps(new_r2_lo), _mm_cvtpd_ps(new_r2_hi)));
}

inline void MatRotateY_SSE2(float* m, float angle) {
    float s, c;
    FastSinCos(angle, s, c);

    const __m128d c_d = _mm_set1_pd((double)c);
    const __m128d s_d = _mm_set1_pd((double)s);
    const __m128d neg_s_d = _mm_set1_pd(-(double)s);

    __m128 r0 = _mm_loadu_ps(m);
    __m128 r2 = _mm_loadu_ps(m + 8);

    __m128d r0_lo = _mm_cvtps_pd(r0);
    __m128d r0_hi = _mm_cvtps_pd(_mm_movehl_ps(r0, r0));
    __m128d r2_lo = _mm_cvtps_pd(r2);
    __m128d r2_hi = _mm_cvtps_pd(_mm_movehl_ps(r2, r2));

    // row 0 = c * r0 - s * r2
    __m128d new_r0_lo = _mm_add_pd(_mm_mul_pd(c_d, r0_lo), _mm_mul_pd(neg_s_d, r2_lo));
    __m128d new_r0_hi = _mm_add_pd(_mm_mul_pd(c_d, r0_hi), _mm_mul_pd(neg_s_d, r2_hi));

    // row 2 = s * r0 + c * r2
    __m128d new_r2_lo = _mm_add_pd(_mm_mul_pd(s_d, r0_lo), _mm_mul_pd(c_d, r2_lo));
    __m128d new_r2_hi = _mm_add_pd(_mm_mul_pd(s_d, r0_hi), _mm_mul_pd(c_d, r2_hi));

    _mm_storeu_ps(m,     _mm_movelh_ps(_mm_cvtpd_ps(new_r0_lo), _mm_cvtpd_ps(new_r0_hi)));
    _mm_storeu_ps(m + 8, _mm_movelh_ps(_mm_cvtpd_ps(new_r2_lo), _mm_cvtpd_ps(new_r2_hi)));
}

inline void MatRotateZ_SSE2(float* m, float angle) {
    float s, c;
    FastSinCos(angle, s, c);

    const __m128d c_d = _mm_set1_pd((double)c);
    const __m128d s_d = _mm_set1_pd((double)s);
    const __m128d neg_s_d = _mm_set1_pd(-(double)s);

    __m128 r0 = _mm_loadu_ps(m);
    __m128 r1 = _mm_loadu_ps(m + 4);

    __m128d r0_lo = _mm_cvtps_pd(r0);
    __m128d r0_hi = _mm_cvtps_pd(_mm_movehl_ps(r0, r0));
    __m128d r1_lo = _mm_cvtps_pd(r1);
    __m128d r1_hi = _mm_cvtps_pd(_mm_movehl_ps(r1, r1));

    // row 0 = c * r0 + s * r1
    __m128d new_r0_lo = _mm_add_pd(_mm_mul_pd(c_d, r0_lo), _mm_mul_pd(s_d, r1_lo));
    __m128d new_r0_hi = _mm_add_pd(_mm_mul_pd(c_d, r0_hi), _mm_mul_pd(s_d, r1_hi));

    // row 1 = -s * r0 + c * r1
    __m128d new_r1_lo = _mm_add_pd(_mm_mul_pd(neg_s_d, r0_lo), _mm_mul_pd(c_d, r1_lo));
    __m128d new_r1_hi = _mm_add_pd(_mm_mul_pd(neg_s_d, r0_hi), _mm_mul_pd(c_d, r1_hi));

    _mm_storeu_ps(m,     _mm_movelh_ps(_mm_cvtpd_ps(new_r0_lo), _mm_cvtpd_ps(new_r0_hi)));
    _mm_storeu_ps(m + 4, _mm_movelh_ps(_mm_cvtpd_ps(new_r1_lo), _mm_cvtpd_ps(new_r1_hi)));
}

__declspec(noinline) static float* VerifyMatRotateX(float* self, void* edx, float angle) {
    float client_m[16];
    float our_m[16];
    memcpy(client_m, self, sizeof(client_m));
    memcpy(our_m, self, sizeof(our_m));

    __try {
        pOrigMatRotateX(client_m, edx, angle);
        MatRotateX_SSE2(our_m, angle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_matrotate_x_dead, 1);
        Log("[MatrixSSE2] MatRotateX faulted during verification, retiring hook");
        return pOrigMatRotateX(self, edx, angle);
    }

    bool match = true;
    for (int i = 0; i < 16; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_m[i], 4);
        memcpy(&om, &our_m[i], 4);
        if (cm != om) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_matrotate_x_dead, 1);
        Log("[MatrixSSE2] MatRotateX DISAGREED with client - retiring hook");
        memcpy(self, client_m, sizeof(client_m));
        return self;
    }

    memcpy(self, our_m, sizeof(our_m));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_matrotate_x_agreements);
    if (g_matrotate_x_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_matrotate_x_armed, 1);
        Log("[MatrixSSE2] MatRotateX armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return self;
}

static float* __fastcall Hooked_MatRotateX(float* self, void* edx, float angle) {
    ++g_matrotate_x_calls;
    if (g_matrotate_x_dead != 0 || !self) {
        return pOrigMatRotateX(self, edx, angle);
    }

    uintptr_t b = (uintptr_t)self;
    if (b < 0x10000 || b > 0xFFE00000) {
        return pOrigMatRotateX(self, edx, angle);
    }

    if (g_matrotate_x_armed != 0 && (g_matrotate_x_calls & 4095) != 0) {
        MatRotateX_SSE2(self, angle);
        return self;
    }

    return VerifyMatRotateX(self, edx, angle);
}

__declspec(noinline) static float* VerifyMatRotateY(float* self, void* edx, float angle) {
    float client_m[16];
    float our_m[16];
    memcpy(client_m, self, sizeof(client_m));
    memcpy(our_m, self, sizeof(our_m));

    __try {
        pOrigMatRotateY(client_m, edx, angle);
        MatRotateY_SSE2(our_m, angle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_matrotate_y_dead, 1);
        Log("[MatrixSSE2] MatRotateY faulted during verification, retiring hook");
        return pOrigMatRotateY(self, edx, angle);
    }

    bool match = true;
    for (int i = 0; i < 16; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_m[i], 4);
        memcpy(&om, &our_m[i], 4);
        if (cm != om) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_matrotate_y_dead, 1);
        Log("[MatrixSSE2] MatRotateY DISAGREED with client - retiring hook");
        memcpy(self, client_m, sizeof(client_m));
        return self;
    }

    memcpy(self, our_m, sizeof(our_m));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_matrotate_y_agreements);
    if (g_matrotate_y_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_matrotate_y_armed, 1);
        Log("[MatrixSSE2] MatRotateY armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return self;
}

static float* __fastcall Hooked_MatRotateY(float* self, void* edx, float angle) {
    ++g_matrotate_y_calls;
    if (g_matrotate_y_dead != 0 || !self) {
        return pOrigMatRotateY(self, edx, angle);
    }

    uintptr_t b = (uintptr_t)self;
    if (b < 0x10000 || b > 0xFFE00000) {
        return pOrigMatRotateY(self, edx, angle);
    }

    if (g_matrotate_y_armed != 0 && (g_matrotate_y_calls & 4095) != 0) {
        MatRotateY_SSE2(self, angle);
        return self;
    }

    return VerifyMatRotateY(self, edx, angle);
}

__declspec(noinline) static float* VerifyMatRotateZ(float* self, void* edx, float angle) {
    float client_m[16];
    float our_m[16];
    memcpy(client_m, self, sizeof(client_m));
    memcpy(our_m, self, sizeof(our_m));

    __try {
        pOrigMatRotateZ(client_m, edx, angle);
        MatRotateZ_SSE2(our_m, angle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_matrotate_z_dead, 1);
        Log("[MatrixSSE2] MatRotateZ faulted during verification, retiring hook");
        return pOrigMatRotateZ(self, edx, angle);
    }

    bool match = true;
    for (int i = 0; i < 16; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_m[i], 4);
        memcpy(&om, &our_m[i], 4);
        if (cm != om) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_matrotate_z_dead, 1);
        Log("[MatrixSSE2] MatRotateZ DISAGREED with client - retiring hook");
        memcpy(self, client_m, sizeof(client_m));
        return self;
    }

    memcpy(self, our_m, sizeof(our_m));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_matrotate_z_agreements);
    if (g_matrotate_z_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_matrotate_z_armed, 1);
        Log("[MatrixSSE2] MatRotateZ armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return self;
}

static float* __fastcall Hooked_MatRotateZ(float* self, void* edx, float angle) {
    ++g_matrotate_z_calls;
    if (g_matrotate_z_dead != 0 || !self) {
        return pOrigMatRotateZ(self, edx, angle);
    }

    uintptr_t b = (uintptr_t)self;
    if (b < 0x10000 || b > 0xFFE00000) {
        return pOrigMatRotateZ(self, edx, angle);
    }

    if (g_matrotate_z_armed != 0 && (g_matrotate_z_calls & 4095) != 0) {
        MatRotateZ_SSE2(self, angle);
        return self;
    }

    return VerifyMatRotateZ(self, edx, angle);
}

static bool SelfTestMatrixRotate() {
    MatRotate_t origX = (MatRotate_t)0x004C3300;
    MatRotate_t origY = (MatRotate_t)0x004C3340;
    MatRotate_t origZ = (MatRotate_t)0x004C3380;

    if (IsBadReadPtr((void*)origX, 16) ||
        IsBadReadPtr((void*)origY, 16) ||
        IsBadReadPtr((void*)origZ, 16)) {
        return true;
    }

    const unsigned char* px = (const unsigned char*)origX;
    if (!(px[0] == 0x55 && px[1] == 0x8B && px[2] == 0xEC)) return true;

    uint32_t state = 0xA5A5A5A5;
    auto rnd = [&state]() -> float {
        state = state * 1664525u + 1013904223u;
        return ((float)(int)(state >> 8) / 8388608.0f) * 100.0f;
    };

    for (int i = 0; i < 30000; ++i) {
        float m_in[16];
        for (int k = 0; k < 16; ++k) m_in[k] = rnd();
        float angle = rnd() * 0.1f;

        // Test RotX
        float m_client[16], m_ours[16];
        memcpy(m_client, m_in, sizeof(m_in));
        memcpy(m_ours, m_in, sizeof(m_in));
        origX(m_client, nullptr, angle);
        MatRotateX_SSE2(m_ours, angle);
        if (memcmp(m_client, m_ours, sizeof(m_in)) != 0) {
            Log("[SelfTest] MatRotateX mismatch at test %d", i);
            return false;
        }

        // Test RotY
        memcpy(m_client, m_in, sizeof(m_in));
        memcpy(m_ours, m_in, sizeof(m_in));
        origY(m_client, nullptr, angle);
        MatRotateY_SSE2(m_ours, angle);
        if (memcmp(m_client, m_ours, sizeof(m_in)) != 0) {
            Log("[SelfTest] MatRotateY mismatch at test %d", i);
            return false;
        }

        // Test RotZ
        memcpy(m_client, m_in, sizeof(m_in));
        memcpy(m_ours, m_in, sizeof(m_in));
        origZ(m_client, nullptr, angle);
        MatRotateZ_SSE2(m_ours, angle);
        if (memcmp(m_client, m_ours, sizeof(m_in)) != 0) {
            Log("[SelfTest] MatRotateZ mismatch at test %d", i);
            return false;
        }
    }
    return true;
}
#endif

// ================================================================
// sub_4C2370: CMatrix::MultiplyInPlace (this = this * other, __thiscall, 27 callers)
// sub_4C1B90: CMatrix::ScaleLocal (3-axis scale, __thiscall, 18 callers)
// sub_4C1BF0: CMatrix::Scale3x3 (upper-left 3x3 *= scalar, __thiscall, 36 callers)
// sub_4C31B0: CMatrix::CreateRotateX (X-rotation matrix, __cdecl, 8 callers)
// sub_4C3220: CMatrix::CreateRotateY (Y-rotation matrix, __cdecl, 8 callers)
// sub_4C3290: CMatrix::CreateRotateZ (Z-rotation matrix, __cdecl, 13 callers)
// sub_4C3460: CMatrix::CreateRotateAxisAngle (axis-angle matrix, __cdecl, 13 callers)
// sub_4C33C0: CMatrix::RotateQuat (in-place quat rotation, __thiscall, 4 callers)
// sub_4C35A0: Vec3_Scale (in-place 3D vector scale, __thiscall, 2 callers)
// sub_4C35D0: Vec3_InvScale (in-place 3D vector inverse scale, __thiscall, 4 callers)
// 133 callers total across animation, camera, spells, scene objects, particle generation, model rendering
// ================================================================
#if !TEST_DISABLE_MATRIX_OPS_SSE2
typedef float* (__fastcall* MatMulInPlace_t)(float* self, void* edx, const float* other);
static MatMulInPlace_t pOrigMatMulInPlace = nullptr;
static volatile unsigned long g_matmul_ip_calls = 0;
static volatile unsigned long g_matmul_ip_agreements = 0;
static volatile long g_matmul_ip_armed = 0;
static volatile long g_matmul_ip_dead = 0;

typedef float* (__fastcall* MatScaleLocal_t)(float* self, void* edx, const float* scale);
static MatScaleLocal_t pOrigMatScaleLocal = nullptr;
static volatile unsigned long g_matscale_local_calls = 0;
static volatile unsigned long g_matscale_local_agreements = 0;
static volatile long g_matscale_local_armed = 0;
static volatile long g_matscale_local_dead = 0;

typedef void (__fastcall* MatScale3x3_t)(float* self, void* edx, float scalar);
static MatScale3x3_t pOrigMatScale3x3 = nullptr;
static volatile unsigned long g_scale3x3_calls = 0;
static volatile unsigned long g_scale3x3_agreements = 0;
static volatile long g_scale3x3_armed = 0;
static volatile long g_scale3x3_dead = 0;

typedef float* (__cdecl* MatCreateRotateX_t)(float* out, float angle);
static MatCreateRotateX_t pOrigMatCreateRotateX = nullptr;
static volatile unsigned long g_matcreate_rotx_calls = 0;
static volatile unsigned long g_matcreate_rotx_agreements = 0;
static volatile long g_matcreate_rotx_armed = 0;
static volatile long g_matcreate_rotx_dead = 0;

typedef float* (__cdecl* MatCreateRotateY_t)(float* out, float angle);
static MatCreateRotateY_t pOrigMatCreateRotateY = nullptr;
static volatile unsigned long g_matcreate_roty_calls = 0;
static volatile unsigned long g_matcreate_roty_agreements = 0;
static volatile long g_matcreate_roty_armed = 0;
static volatile long g_matcreate_roty_dead = 0;

typedef float* (__cdecl* MatCreateRotateZ_t)(float* out, float angle);
static MatCreateRotateZ_t pOrigMatCreateRotateZ = nullptr;
static volatile unsigned long g_matcreate_rotz_calls = 0;
static volatile unsigned long g_matcreate_rotz_agreements = 0;
static volatile long g_matcreate_rotz_armed = 0;
static volatile long g_matcreate_rotz_dead = 0;

typedef float* (__cdecl* MatCreateRotateAxisAngle_t)(float* out, float angle, const float* axis, int is_normalized);
static MatCreateRotateAxisAngle_t pOrigMatCreateRotateAxisAngle = nullptr;
static volatile unsigned long g_matcreate_rotaxis_calls = 0;
static volatile unsigned long g_matcreate_rotaxis_agreements = 0;
static volatile long g_matcreate_rotaxis_armed = 0;
static volatile long g_matcreate_rotaxis_dead = 0;

typedef float* (__fastcall* MatRotateQuat_t)(float* this_mat, void* edx, const float* quat);
static MatRotateQuat_t pOrigMatRotateQuat = nullptr;
static volatile unsigned long g_matrotate_quat_calls = 0;
static volatile unsigned long g_matrotate_quat_agreements = 0;
static volatile long g_matrotate_quat_armed = 0;
static volatile long g_matrotate_quat_dead = 0;

typedef float* (__fastcall* Vec3Scale_t)(float* this_vec, void* edx, float s);
static Vec3Scale_t pOrigVec3Scale = nullptr;
static volatile unsigned long g_vec3_scale_calls = 0;
static volatile unsigned long g_vec3_scale_agreements = 0;
static volatile long g_vec3_scale_armed = 0;
static volatile long g_vec3_scale_dead = 0;

typedef float* (__fastcall* Vec3InvScale_t)(float* this_vec, void* edx, float s);
static Vec3InvScale_t pOrigVec3InvScale = nullptr;
static volatile unsigned long g_vec3_invscale_calls = 0;
static volatile unsigned long g_vec3_invscale_agreements = 0;
static volatile long g_vec3_invscale_armed = 0;
static volatile long g_vec3_invscale_dead = 0;

static inline void MatMulInPlace_SSE2(float* self, const float* other) {
    float tmp[16];
    MatMul4x4_PackedDouble(tmp, self, other);
    _mm_storeu_ps(self + 0,  _mm_loadu_ps(tmp + 0));
    _mm_storeu_ps(self + 4,  _mm_loadu_ps(tmp + 4));
    _mm_storeu_ps(self + 8,  _mm_loadu_ps(tmp + 8));
    _mm_storeu_ps(self + 12, _mm_loadu_ps(tmp + 12));
}

static inline float* MatScaleLocal_SSE2(float* self, const float* scale) {
    // Row 0: multiply elements 0, 1, 2 by scale[0]
    __m128d s0 = _mm_set1_pd((double)scale[0]);
    __m128d v0_0 = _mm_mul_pd(_mm_cvtps_pd(_mm_loadu_ps(self)), s0);
    __m128d v0_1 = _mm_mul_pd(_mm_cvtps_pd(_mm_load_ss(self + 2)), s0);
    __m128 r0 = _mm_movelh_ps(_mm_cvtpd_ps(v0_0), _mm_cvtpd_ps(v0_1));
    _mm_store_ss(self, r0);
    _mm_store_ss(self + 1, _mm_shuffle_ps(r0, r0, _MM_SHUFFLE(1, 1, 1, 1)));
    _mm_store_ss(self + 2, _mm_shuffle_ps(r0, r0, _MM_SHUFFLE(2, 2, 2, 2)));

    // Row 1: multiply elements 4, 5, 6 by scale[1]
    __m128d s1 = _mm_set1_pd((double)scale[1]);
    __m128d v1_0 = _mm_mul_pd(_mm_cvtps_pd(_mm_loadu_ps(self + 4)), s1);
    __m128d v1_1 = _mm_mul_pd(_mm_cvtps_pd(_mm_load_ss(self + 6)), s1);
    __m128 r1 = _mm_movelh_ps(_mm_cvtpd_ps(v1_0), _mm_cvtpd_ps(v1_1));
    _mm_store_ss(self + 4, r1);
    _mm_store_ss(self + 5, _mm_shuffle_ps(r1, r1, _MM_SHUFFLE(1, 1, 1, 1)));
    _mm_store_ss(self + 6, _mm_shuffle_ps(r1, r1, _MM_SHUFFLE(2, 2, 2, 2)));

    // Row 2: multiply elements 8, 9, 10 by scale[2]
    __m128d s2 = _mm_set1_pd((double)scale[2]);
    __m128d v2_0 = _mm_mul_pd(_mm_cvtps_pd(_mm_loadu_ps(self + 8)), s2);
    __m128d v2_1 = _mm_mul_pd(_mm_cvtps_pd(_mm_load_ss(self + 10)), s2);
    __m128 r2 = _mm_movelh_ps(_mm_cvtpd_ps(v2_0), _mm_cvtpd_ps(v2_1));
    _mm_store_ss(self + 8, r2);
    _mm_store_ss(self + 9, _mm_shuffle_ps(r2, r2, _MM_SHUFFLE(1, 1, 1, 1)));
    _mm_store_ss(self + 10, _mm_shuffle_ps(r2, r2, _MM_SHUFFLE(2, 2, 2, 2)));

    return (float*)scale;
}

static inline void MatScale3x3_SSE2(float* self, float scalar) {
    __m128d s = _mm_set1_pd((double)scalar);

    // Row 0: multiply elements 0, 1, 2 by scalar
    __m128d v0_0 = _mm_mul_pd(_mm_cvtps_pd(_mm_loadu_ps(self)), s);
    __m128d v0_1 = _mm_mul_pd(_mm_cvtps_pd(_mm_load_ss(self + 2)), s);
    __m128 r0 = _mm_movelh_ps(_mm_cvtpd_ps(v0_0), _mm_cvtpd_ps(v0_1));
    _mm_store_ss(self, r0);
    _mm_store_ss(self + 1, _mm_shuffle_ps(r0, r0, _MM_SHUFFLE(1, 1, 1, 1)));
    _mm_store_ss(self + 2, _mm_shuffle_ps(r0, r0, _MM_SHUFFLE(2, 2, 2, 2)));

    // Row 1: multiply elements 4, 5, 6 by scalar
    __m128d v1_0 = _mm_mul_pd(_mm_cvtps_pd(_mm_loadu_ps(self + 4)), s);
    __m128d v1_1 = _mm_mul_pd(_mm_cvtps_pd(_mm_load_ss(self + 6)), s);
    __m128 r1 = _mm_movelh_ps(_mm_cvtpd_ps(v1_0), _mm_cvtpd_ps(v1_1));
    _mm_store_ss(self + 4, r1);
    _mm_store_ss(self + 5, _mm_shuffle_ps(r1, r1, _MM_SHUFFLE(1, 1, 1, 1)));
    _mm_store_ss(self + 6, _mm_shuffle_ps(r1, r1, _MM_SHUFFLE(2, 2, 2, 2)));

    // Row 2: multiply elements 8, 9, 10 by scalar
    __m128d v2_0 = _mm_mul_pd(_mm_cvtps_pd(_mm_loadu_ps(self + 8)), s);
    __m128d v2_1 = _mm_mul_pd(_mm_cvtps_pd(_mm_load_ss(self + 10)), s);
    __m128 r2 = _mm_movelh_ps(_mm_cvtpd_ps(v2_0), _mm_cvtpd_ps(v2_1));
    _mm_store_ss(self + 8, r2);
    _mm_store_ss(self + 9, _mm_shuffle_ps(r2, r2, _MM_SHUFFLE(1, 1, 1, 1)));
    _mm_store_ss(self + 10, _mm_shuffle_ps(r2, r2, _MM_SHUFFLE(2, 2, 2, 2)));
}

static inline float* MatCreateRotateX_SSE2(float* out, float angle) {
    float s, c;
    FastSinCos(angle, s, c);

    __m128 r0 = _mm_setr_ps(1.0f, 0.0f,  0.0f, 0.0f);
    __m128 r1 = _mm_setr_ps(0.0f,    c,     s, 0.0f);
    __m128 r2 = _mm_setr_ps(0.0f,   -s,     c, 0.0f);
    __m128 r3 = _mm_setr_ps(0.0f, 0.0f,  0.0f, 1.0f);

    _mm_storeu_ps(out + 0,  r0);
    _mm_storeu_ps(out + 4,  r1);
    _mm_storeu_ps(out + 8,  r2);
    _mm_storeu_ps(out + 12, r3);
    return out;
}

static inline float* MatCreateRotateY_SSE2(float* out, float angle) {
    float s, c;
    FastSinCos(angle, s, c);

    __m128 r0 = _mm_setr_ps(   c, 0.0f,   -s, 0.0f);
    __m128 r1 = _mm_setr_ps(0.0f, 1.0f, 0.0f, 0.0f);
    __m128 r2 = _mm_setr_ps(   s, 0.0f,    c, 0.0f);
    __m128 r3 = _mm_setr_ps(0.0f, 0.0f, 0.0f, 1.0f);

    _mm_storeu_ps(out + 0,  r0);
    _mm_storeu_ps(out + 4,  r1);
    _mm_storeu_ps(out + 8,  r2);
    _mm_storeu_ps(out + 12, r3);
    return out;
}

static inline float* MatCreateRotateZ_SSE2(float* out, float angle) {
    float s, c;
    FastSinCos(angle, s, c);

    __m128 r0 = _mm_set_ps(0.0f, 0.0f, s, c);
    __m128 r1 = _mm_set_ps(0.0f, 0.0f, c, -s);
    __m128 r2 = _mm_set_ps(0.0f, 1.0f, 0.0f, 0.0f);
    __m128 r3 = _mm_set_ps(1.0f, 0.0f, 0.0f, 0.0f);

    _mm_storeu_ps(out + 0,  r0);
    _mm_storeu_ps(out + 4,  r1);
    _mm_storeu_ps(out + 8,  r2);
    _mm_storeu_ps(out + 12, r3);
    return out;
}

static inline float* MatCreateRotateAxisAngle_SSE2(float* out, float angle, const float* axis, int is_normalized) {
    float ax = axis[0];
    float ay = axis[1];
    float az = axis[2];

    if (!is_normalized) {
        double dax = (double)ax;
        double day = (double)ay;
        double daz = (double)az;
        double sum = (daz * daz + day * day) + dax * dax;
        double len = _mm_cvtsd_f64(_mm_sqrt_sd(_mm_setzero_pd(), _mm_set_sd(sum)));
        double inv_len = 1.0 / len;
        ax = (float)(dax * inv_len);
        ay = (float)(day * inv_len);
        az = (float)(daz * inv_len);
    }

    float s, c;
    FastSinCos(angle, s, c);

    double dax = (double)ax;
    double day = (double)ay;
    double daz = (double)az;
    double dc  = (double)c;
    double ds  = (double)s;

    float xy = (float)(day * dax);
    float yz = (float)(daz * day);
    float xz = (float)(daz * dax);
    float ys = (float)(day * ds);

    double az_s = daz * ds;
    double ax_s = dax * ds;
    double one_minus_c = 1.0 - dc;

    double xy_term = (double)xy * one_minus_c;
    float  xy_term_f = (float)xy_term;

    double xz_term = (double)xz * one_minus_c;
    float  xz_term_f = (float)xz_term;

    double yz_term = (double)yz * one_minus_c;

    out[0]  = (float)(dax * dax * one_minus_c + dc);
    out[1]  = (float)(xy_term + az_s);
    out[2]  = (float)(xz_term - (double)ys);
    out[3]  = 0.0f;

    out[4]  = (float)((double)xy_term_f - az_s);
    out[5]  = (float)(day * day * one_minus_c + dc);
    out[6]  = (float)(yz_term + ax_s);
    out[7]  = 0.0f;

    out[8]  = (float)((double)xz_term_f + (double)ys);
    out[9]  = (float)(yz_term - ax_s);
    out[10] = (float)(daz * daz * one_minus_c + dc);
    out[11] = 0.0f;

    out[12] = 0.0f;
    out[13] = 0.0f;
    out[14] = 0.0f;
    out[15] = 1.0f;

    return out;
}

static inline float* MatRotateQuat_SSE2(float* this_mat, const float* quat) {
    float qmat[16];
    qmat[3]  = 0.0f;
    qmat[7]  = 0.0f;
    qmat[11] = 0.0f;
    qmat[12] = 0.0f;
    qmat[13] = 0.0f;
    qmat[14] = 0.0f;
    qmat[15] = 1.0f;
    QuatToMatrix3x3_PackedDouble(quat, qmat);

    float tmp[16];
    MatMul4x4_PackedDouble(tmp, qmat, this_mat);

    _mm_storeu_ps(this_mat + 0,  _mm_loadu_ps(tmp + 0));
    _mm_storeu_ps(this_mat + 4,  _mm_loadu_ps(tmp + 4));
    _mm_storeu_ps(this_mat + 8,  _mm_loadu_ps(tmp + 8));
    _mm_storeu_ps(this_mat + 12, _mm_loadu_ps(tmp + 12));
    return this_mat;
}

static inline float* Vec3Scale_SSE2(float* this_vec, float s) {
    double sd = (double)s;
    __m128d s_d = _mm_set1_pd(sd);
    __m128d xy = _mm_mul_pd(_mm_set_pd((double)this_vec[1], (double)this_vec[0]), s_d);
    __m128d z = _mm_mul_sd(_mm_set_sd((double)this_vec[2]), s_d);
    this_vec[0] = (float)_mm_cvtsd_f64(xy);
    this_vec[1] = (float)_mm_cvtsd_f64(_mm_unpackhi_pd(xy, xy));
    this_vec[2] = (float)_mm_cvtsd_f64(z);
    return this_vec;
}

static inline float* Vec3InvScale_SSE2(float* this_vec, float s) {
    double inv = 1.0 / (double)s;
    __m128d inv_d = _mm_set1_pd(inv);
    __m128d xy = _mm_mul_pd(_mm_set_pd((double)this_vec[1], (double)this_vec[0]), inv_d);
    __m128d z = _mm_mul_sd(_mm_set_sd((double)this_vec[2]), inv_d);
    this_vec[0] = (float)_mm_cvtsd_f64(xy);
    this_vec[1] = (float)_mm_cvtsd_f64(_mm_unpackhi_pd(xy, xy));
    this_vec[2] = (float)_mm_cvtsd_f64(z);
    return this_vec;
}

__declspec(noinline) static float* VerifyMatMulInPlace(float* self, void* edx, const float* other) {
    // Shadow verification
    float client_m[16], our_m[16], our_pre[16];
    memcpy(client_m, self, sizeof(client_m));
    memcpy(our_m, self, sizeof(our_m));
    memcpy(our_pre, self, sizeof(our_pre));

    __try {
        pOrigMatMulInPlace(client_m, nullptr, other);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return pOrigMatMulInPlace(self, edx, other);
    }

    __try {
        MatMulInPlace_SSE2(our_m, other);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_matmul_ip_dead, 1);
        Log("[MatrixSSE2] MatMulInPlace threw exception - retiring hook");
        memcpy(self, client_m, sizeof(client_m));
        return self;
    }

    // Bit for bit, except that two NaNs agree whatever their payloads: the x87
    // unit answers a NaN operand with its own default NaN and the packed unit
    // propagates the operand's payload, so a matrix with a NaN in it differs in
    // bits and in nothing else. Anything else that differs is a disagreement.
    bool match = true;
    int badAt = -1;
    uint32_t badClient = 0, badOurs = 0;
    for (int i = 0; i < 16; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_m[i], 4);
        memcpy(&om, &our_m[i], 4);
        if (cm != om) {
            const bool bothNaN = (cm & 0x7F800000u) == 0x7F800000u && (cm & 0x007FFFFFu) != 0 &&
                                 (om & 0x7F800000u) == 0x7F800000u && (om & 0x007FFFFFu) != 0;
            if (bothNaN) continue;
            match = false;
            badAt = i; badClient = cm; badOurs = om;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_matmul_ip_dead, 1);
        // What was multiplied, so the next report says why and not just that.
        unsigned selfBits[16], otherBits[16];
        for (int i = 0; i < 16; ++i) {
            memcpy(&selfBits[i], &our_pre[i], 4);
            memcpy(&otherBits[i], &other[i], 4);
        }
        Log("[MatrixSSE2] MatMulInPlace DISAGREED with client at element %d: client %08X, packed %08X "
            "(self %08X %08X %08X %08X / %08X %08X %08X %08X ..., other %08X %08X %08X %08X / %08X %08X %08X %08X ...)"
            " - retiring hook", badAt, badClient, badOurs,
            selfBits[0], selfBits[1], selfBits[2], selfBits[3], selfBits[4], selfBits[5], selfBits[6], selfBits[7],
            otherBits[0], otherBits[1], otherBits[2], otherBits[3], otherBits[4], otherBits[5], otherBits[6], otherBits[7]);
        memcpy(self, client_m, sizeof(client_m));
        return self;
    }

    memcpy(self, our_m, sizeof(our_m));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_matmul_ip_agreements);
    if (g_matmul_ip_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_matmul_ip_armed, 1);
        Log("[MatrixSSE2] MatMulInPlace armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return self;
}

static float* __fastcall Hooked_MatMulInPlace(float* self, void* edx, const float* other) {
    ++g_matmul_ip_calls;
    uintptr_t s = (uintptr_t)self;
    uintptr_t o = (uintptr_t)other;
    if (s <= 0x10000 || s >= 0xFFE00000 || o <= 0x10000 || o >= 0xFFE00000 || g_matmul_ip_dead) {
        return pOrigMatMulInPlace(self, edx, other);
    }

    if (g_matmul_ip_armed && ((g_matmul_ip_calls & 4095) != 0)) {
        MatMulInPlace_SSE2(self, other);
        return self;
    }

    return VerifyMatMulInPlace(self, edx, other);
}

__declspec(noinline) static float* VerifyMatScaleLocal(float* self, void* edx, const float* scale) {
    // Shadow verification
    float client_m[16], our_m[16];
    memcpy(client_m, self, sizeof(client_m));
    memcpy(our_m, self, sizeof(our_m));

    __try {
        pOrigMatScaleLocal(client_m, nullptr, scale);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return pOrigMatScaleLocal(self, edx, scale);
    }

    __try {
        MatScaleLocal_SSE2(our_m, scale);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_matscale_local_dead, 1);
        Log("[MatrixSSE2] MatScaleLocal threw exception - retiring hook");
        memcpy(self, client_m, sizeof(client_m));
        return (float*)scale;
    }

    bool match = true;
    for (int i = 0; i < 16; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_m[i], 4);
        memcpy(&om, &our_m[i], 4);
        if (cm != om) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_matscale_local_dead, 1);
        Log("[MatrixSSE2] MatScaleLocal DISAGREED with client - retiring hook");
        memcpy(self, client_m, sizeof(client_m));
        return (float*)scale;
    }

    memcpy(self, our_m, sizeof(our_m));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_matscale_local_agreements);
    if (g_matscale_local_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_matscale_local_armed, 1);
        Log("[MatrixSSE2] MatScaleLocal armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return (float*)scale;
}

static float* __fastcall Hooked_MatScaleLocal(float* self, void* edx, const float* scale) {
    ++g_matscale_local_calls;
    uintptr_t s = (uintptr_t)self;
    uintptr_t sc = (uintptr_t)scale;
    if (s <= 0x10000 || s >= 0xFFE00000 || sc <= 0x10000 || sc >= 0xFFE00000 || g_matscale_local_dead) {
        return pOrigMatScaleLocal(self, edx, scale);
    }

    if (g_matscale_local_armed && ((g_matscale_local_calls & 4095) != 0)) {
        return MatScaleLocal_SSE2(self, scale);
    }

    return VerifyMatScaleLocal(self, edx, scale);
}

__declspec(noinline) static float* VerifyMatCreateRotateZ(float* out, float angle) {
    // Shadow verification
    float client_m[16], our_m[16];

    __try {
        pOrigMatCreateRotateZ(client_m, angle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return pOrigMatCreateRotateZ(out, angle);
    }

    __try {
        MatCreateRotateZ_SSE2(our_m, angle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_matcreate_rotz_dead, 1);
        Log("[MatrixSSE2] MatCreateRotateZ threw exception - retiring hook");
        memcpy(out, client_m, sizeof(client_m));
        return out;
    }

    bool match = true;
    for (int i = 0; i < 16; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_m[i], 4);
        memcpy(&om, &our_m[i], 4);
        if (cm != om) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_matcreate_rotz_dead, 1);
        Log("[MatrixSSE2] MatCreateRotateZ DISAGREED with client - retiring hook");
        memcpy(out, client_m, sizeof(client_m));
        return out;
    }

    memcpy(out, our_m, sizeof(our_m));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_matcreate_rotz_agreements);
    if (g_matcreate_rotz_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_matcreate_rotz_armed, 1);
        Log("[MatrixSSE2] MatCreateRotateZ armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return out;
}

static float* __cdecl Hooked_MatCreateRotateZ(float* out, float angle) {
    ++g_matcreate_rotz_calls;
    uintptr_t o = (uintptr_t)out;
    if (o <= 0x10000 || o >= 0xFFE00000 || g_matcreate_rotz_dead) {
        return pOrigMatCreateRotateZ(out, angle);
    }

    if (g_matcreate_rotz_armed && ((g_matcreate_rotz_calls & 4095) != 0)) {
        return MatCreateRotateZ_SSE2(out, angle);
    }

    return VerifyMatCreateRotateZ(out, angle);
}

__declspec(noinline) static void VerifyMatScale3x3(float* self, void* edx, float scalar) {
    // Shadow verification
    float client_m[16], our_m[16];
    memcpy(client_m, self, sizeof(client_m));
    memcpy(our_m, self, sizeof(our_m));

    __try {
        pOrigMatScale3x3(client_m, edx, scalar);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        pOrigMatScale3x3(self, edx, scalar);
        return;
    }

    __try {
        MatScale3x3_SSE2(our_m, scalar);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_scale3x3_dead, 1);
        Log("[MatrixSSE2] MatScale3x3 threw exception - retiring hook");
        memcpy(self, client_m, sizeof(client_m));
        return;
    }

    bool match = true;
    for (int i = 0; i < 16; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_m[i], 4);
        memcpy(&om, &our_m[i], 4);
        if (cm != om) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_scale3x3_dead, 1);
        Log("[MatrixSSE2] MatScale3x3 DISAGREED with client - retiring hook");
        memcpy(self, client_m, sizeof(client_m));
        return;
    }

    memcpy(self, our_m, sizeof(our_m));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_scale3x3_agreements);
    if (g_scale3x3_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_scale3x3_armed, 1);
        Log("[MatrixSSE2] MatScale3x3 armed: %lu tests agreed bit-for-bit with client", ok);
    }
}

static void __fastcall Hooked_MatScale3x3(float* self, void* edx, float scalar) {
    ++g_scale3x3_calls;
    uintptr_t s = (uintptr_t)self;
    if (s <= 0x10000 || s >= 0xFFE00000 || g_scale3x3_dead) {
        pOrigMatScale3x3(self, edx, scalar);
        return;
    }

    if (g_scale3x3_armed && ((g_scale3x3_calls & 4095) != 0)) {
        MatScale3x3_SSE2(self, scalar);
        return;
    }

    VerifyMatScale3x3(self, edx, scalar);
}

__declspec(noinline) static float* VerifyMatCreateRotateX(float* out, float angle) {
    // Shadow verification
    float client_m[16], our_m[16];

    __try {
        pOrigMatCreateRotateX(client_m, angle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return pOrigMatCreateRotateX(out, angle);
    }

    __try {
        MatCreateRotateX_SSE2(our_m, angle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_matcreate_rotx_dead, 1);
        Log("[MatrixSSE2] MatCreateRotateX threw exception - retiring hook");
        memcpy(out, client_m, sizeof(client_m));
        return out;
    }

    bool match = true;
    for (int i = 0; i < 16; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_m[i], 4);
        memcpy(&om, &our_m[i], 4);
        if (cm != om) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_matcreate_rotx_dead, 1);
        Log("[MatrixSSE2] MatCreateRotateX DISAGREED with client - retiring hook");
        memcpy(out, client_m, sizeof(client_m));
        return out;
    }

    memcpy(out, our_m, sizeof(our_m));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_matcreate_rotx_agreements);
    if (g_matcreate_rotx_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_matcreate_rotx_armed, 1);
        Log("[MatrixSSE2] MatCreateRotateX armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return out;
}

static float* __cdecl Hooked_MatCreateRotateX(float* out, float angle) {
    ++g_matcreate_rotx_calls;
    uintptr_t o = (uintptr_t)out;
    if (o <= 0x10000 || o >= 0xFFE00000 || g_matcreate_rotx_dead) {
        return pOrigMatCreateRotateX(out, angle);
    }

    if (g_matcreate_rotx_armed && ((g_matcreate_rotx_calls & 4095) != 0)) {
        return MatCreateRotateX_SSE2(out, angle);
    }

    return VerifyMatCreateRotateX(out, angle);
}

__declspec(noinline) static float* VerifyMatCreateRotateY(float* out, float angle) {
    // Shadow verification
    float client_m[16], our_m[16];

    __try {
        pOrigMatCreateRotateY(client_m, angle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return pOrigMatCreateRotateY(out, angle);
    }

    __try {
        MatCreateRotateY_SSE2(our_m, angle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_matcreate_roty_dead, 1);
        Log("[MatrixSSE2] MatCreateRotateY threw exception - retiring hook");
        memcpy(out, client_m, sizeof(client_m));
        return out;
    }

    bool match = true;
    for (int i = 0; i < 16; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_m[i], 4);
        memcpy(&om, &our_m[i], 4);
        if (cm != om) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_matcreate_roty_dead, 1);
        Log("[MatrixSSE2] MatCreateRotateY DISAGREED with client - retiring hook");
        memcpy(out, client_m, sizeof(client_m));
        return out;
    }

    memcpy(out, our_m, sizeof(our_m));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_matcreate_roty_agreements);
    if (g_matcreate_roty_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_matcreate_roty_armed, 1);
        Log("[MatrixSSE2] MatCreateRotateY armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return out;
}

static float* __cdecl Hooked_MatCreateRotateY(float* out, float angle) {
    ++g_matcreate_roty_calls;
    uintptr_t o = (uintptr_t)out;
    if (o <= 0x10000 || o >= 0xFFE00000 || g_matcreate_roty_dead) {
        return pOrigMatCreateRotateY(out, angle);
    }

    if (g_matcreate_roty_armed && ((g_matcreate_roty_calls & 4095) != 0)) {
        return MatCreateRotateY_SSE2(out, angle);
    }

    return VerifyMatCreateRotateY(out, angle);
}

__declspec(noinline) static float* VerifyMatCreateRotateAxisAngle(float* out, float angle, const float* axis, int is_normalized) {
    // Shadow verification
    float client_m[16], our_m[16];

    __try {
        pOrigMatCreateRotateAxisAngle(client_m, angle, axis, is_normalized);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return pOrigMatCreateRotateAxisAngle(out, angle, axis, is_normalized);
    }

    __try {
        MatCreateRotateAxisAngle_SSE2(our_m, angle, axis, is_normalized);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_matcreate_rotaxis_dead, 1);
        Log("[MatrixSSE2] MatCreateRotateAxisAngle threw exception - retiring hook");
        memcpy(out, client_m, sizeof(client_m));
        return out;
    }

    bool match = true;
    for (int i = 0; i < 16; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_m[i], 4);
        memcpy(&om, &our_m[i], 4);
        if (cm != om) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_matcreate_rotaxis_dead, 1);
        Log("[MatrixSSE2] MatCreateRotateAxisAngle DISAGREED with client - retiring hook");
        memcpy(out, client_m, sizeof(client_m));
        return out;
    }

    memcpy(out, our_m, sizeof(our_m));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_matcreate_rotaxis_agreements);
    if (g_matcreate_rotaxis_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_matcreate_rotaxis_armed, 1);
        Log("[MatrixSSE2] MatCreateRotateAxisAngle armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return out;
}

static float* __cdecl Hooked_MatCreateRotateAxisAngle(float* out, float angle, const float* axis, int is_normalized) {
    ++g_matcreate_rotaxis_calls;
    uintptr_t o = (uintptr_t)out;
    uintptr_t a = (uintptr_t)axis;
    if (o <= 0x10000 || o >= 0xFFE00000 || a <= 0x10000 || a >= 0xFFE00000 || g_matcreate_rotaxis_dead) {
        return pOrigMatCreateRotateAxisAngle(out, angle, axis, is_normalized);
    }

    if (g_matcreate_rotaxis_armed && ((g_matcreate_rotaxis_calls & 4095) != 0)) {
        return MatCreateRotateAxisAngle_SSE2(out, angle, axis, is_normalized);
    }

    return VerifyMatCreateRotateAxisAngle(out, angle, axis, is_normalized);
}

__declspec(noinline) static float* VerifyMatRotateQuat(float* this_mat, void* edx, const float* quat) {
    // Shadow verification
    float client_m[16], our_m[16];
    memcpy(client_m, this_mat, sizeof(client_m));
    memcpy(our_m, this_mat, sizeof(our_m));

    __try {
        pOrigMatRotateQuat(client_m, nullptr, quat);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return pOrigMatRotateQuat(this_mat, edx, quat);
    }

    __try {
        MatRotateQuat_SSE2(our_m, quat);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_matrotate_quat_dead, 1);
        Log("[MatrixSSE2] MatRotateQuat threw exception - retiring hook");
        memcpy(this_mat, client_m, sizeof(client_m));
        return this_mat;
    }

    bool match = true;
    for (int i = 0; i < 16; ++i) {
        uint32_t cm, om;
        memcpy(&cm, &client_m[i], 4);
        memcpy(&om, &our_m[i], 4);
        if (cm != om) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_matrotate_quat_dead, 1);
        Log("[MatrixSSE2] MatRotateQuat DISAGREED with client - retiring hook");
        memcpy(this_mat, client_m, sizeof(client_m));
        return this_mat;
    }

    memcpy(this_mat, our_m, sizeof(our_m));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_matrotate_quat_agreements);
    if (g_matrotate_quat_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_matrotate_quat_armed, 1);
        Log("[MatrixSSE2] MatRotateQuat armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return this_mat;
}

static float* __fastcall Hooked_MatRotateQuat(float* this_mat, void* edx, const float* quat) {
    ++g_matrotate_quat_calls;
    uintptr_t m = (uintptr_t)this_mat;
    uintptr_t q = (uintptr_t)quat;
    if (m <= 0x10000 || m >= 0xFFE00000 || q <= 0x10000 || q >= 0xFFE00000 || g_matrotate_quat_dead) {
        return pOrigMatRotateQuat(this_mat, edx, quat);
    }

    if (g_matrotate_quat_armed && ((g_matrotate_quat_calls & 4095) != 0)) {
        return MatRotateQuat_SSE2(this_mat, quat);
    }

    return VerifyMatRotateQuat(this_mat, edx, quat);
}

__declspec(noinline) static float* VerifyVec3Scale(float* this_vec, void* edx, float s) {
    // Shadow verification
    float client_v[3], our_v[3];
    memcpy(client_v, this_vec, sizeof(client_v));
    memcpy(our_v, this_vec, sizeof(our_v));

    __try {
        pOrigVec3Scale(client_v, nullptr, s);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return pOrigVec3Scale(this_vec, edx, s);
    }

    __try {
        Vec3Scale_SSE2(our_v, s);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_vec3_scale_dead, 1);
        Log("[MatrixSSE2] Vec3_Scale threw exception - retiring hook");
        memcpy(this_vec, client_v, sizeof(client_v));
        return this_vec;
    }

    bool match = true;
    for (int i = 0; i < 3; ++i) {
        uint32_t cv, ov;
        memcpy(&cv, &client_v[i], 4);
        memcpy(&ov, &our_v[i], 4);
        if (cv != ov) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_vec3_scale_dead, 1);
        Log("[MatrixSSE2] Vec3_Scale DISAGREED with client - retiring hook");
        memcpy(this_vec, client_v, sizeof(client_v));
        return this_vec;
    }

    memcpy(this_vec, our_v, sizeof(our_v));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_vec3_scale_agreements);
    if (g_vec3_scale_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_vec3_scale_armed, 1);
        Log("[MatrixSSE2] Vec3_Scale armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return this_vec;
}

static float* __fastcall Hooked_Vec3Scale(float* this_vec, void* edx, float s) {
    ++g_vec3_scale_calls;
    uintptr_t v = (uintptr_t)this_vec;
    if (v <= 0x10000 || v >= 0xFFE00000 || g_vec3_scale_dead) {
        return pOrigVec3Scale(this_vec, edx, s);
    }

    if (g_vec3_scale_armed && ((g_vec3_scale_calls & 4095) != 0)) {
        return Vec3Scale_SSE2(this_vec, s);
    }

    return VerifyVec3Scale(this_vec, edx, s);
}

__declspec(noinline) static float* VerifyVec3InvScale(float* this_vec, void* edx, float s) {
    // Shadow verification
    float client_v[3], our_v[3];
    memcpy(client_v, this_vec, sizeof(client_v));
    memcpy(our_v, this_vec, sizeof(our_v));

    __try {
        pOrigVec3InvScale(client_v, nullptr, s);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return pOrigVec3InvScale(this_vec, edx, s);
    }

    __try {
        Vec3InvScale_SSE2(our_v, s);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_vec3_invscale_dead, 1);
        Log("[MatrixSSE2] Vec3_InvScale threw exception - retiring hook");
        memcpy(this_vec, client_v, sizeof(client_v));
        return this_vec;
    }

    bool match = true;
    for (int i = 0; i < 3; ++i) {
        uint32_t cv, ov;
        memcpy(&cv, &client_v[i], 4);
        memcpy(&ov, &our_v[i], 4);
        if (cv != ov) {
            match = false;
            break;
        }
    }

    if (!match) {
        InterlockedExchange(&g_vec3_invscale_dead, 1);
        Log("[MatrixSSE2] Vec3_InvScale DISAGREED with client - retiring hook");
        memcpy(this_vec, client_v, sizeof(client_v));
        return this_vec;
    }

    memcpy(this_vec, our_v, sizeof(our_v));

    unsigned long ok = InterlockedIncrement((volatile long*)&g_vec3_invscale_agreements);
    if (g_vec3_invscale_armed == 0 && ok >= 20000) {
        InterlockedExchange(&g_vec3_invscale_armed, 1);
        Log("[MatrixSSE2] Vec3_InvScale armed: %lu tests agreed bit-for-bit with client", ok);
    }
    return this_vec;
}

static float* __fastcall Hooked_Vec3InvScale(float* this_vec, void* edx, float s) {
    ++g_vec3_invscale_calls;
    uintptr_t v = (uintptr_t)this_vec;
    if (v <= 0x10000 || v >= 0xFFE00000 || g_vec3_invscale_dead) {
        return pOrigVec3InvScale(this_vec, edx, s);
    }

    if (g_vec3_invscale_armed && ((g_vec3_invscale_calls & 4095) != 0)) {
        return Vec3InvScale_SSE2(this_vec, s);
    }

    return VerifyVec3InvScale(this_vec, edx, s);
}

static bool SelfTestMatrixOps() {
    MatMulInPlace_t origMul = (MatMulInPlace_t)0x004C2370;
    MatScaleLocal_t origScale = (MatScaleLocal_t)0x004C1B90;
    MatScale3x3_t origScale3x3 = (MatScale3x3_t)0x004C1BF0;
    MatCreateRotateX_t origCreateX = (MatCreateRotateX_t)0x004C31B0;
    MatCreateRotateY_t origCreateY = (MatCreateRotateY_t)0x004C3220;
    MatCreateRotateZ_t origCreateZ = (MatCreateRotateZ_t)0x004C3290;
    MatCreateRotateAxisAngle_t origCreateAxisAngle = (MatCreateRotateAxisAngle_t)0x004C3460;
    MatRotateQuat_t origRotateQuat = (MatRotateQuat_t)0x004C33C0;
    Vec3Scale_t origVec3Scale = (Vec3Scale_t)0x004C35A0;
    Vec3InvScale_t origVec3InvScale = (Vec3InvScale_t)0x004C35D0;

    if (IsBadReadPtr((void*)origMul, 16) ||
        IsBadReadPtr((void*)origScale, 16) ||
        IsBadReadPtr((void*)origScale3x3, 16) ||
        IsBadReadPtr((void*)origCreateX, 16) ||
        IsBadReadPtr((void*)origCreateY, 16) ||
        IsBadReadPtr((void*)origCreateZ, 16) ||
        IsBadReadPtr((void*)origCreateAxisAngle, 16) ||
        IsBadReadPtr((void*)origRotateQuat, 16) ||
        IsBadReadPtr((void*)origVec3Scale, 16) ||
        IsBadReadPtr((void*)origVec3InvScale, 16)) {
        return true;
    }

    const unsigned char* pm = (const unsigned char*)origMul;
    if (!(pm[0] == 0x55 && pm[1] == 0x8B && pm[2] == 0xEC)) return true;

    uint32_t state = 0x5A5A5A5A;
    auto rnd = [&state]() -> float {
        state = state * 1664525u + 1013904223u;
        return ((float)(int)(state >> 8) / 8388608.0f) * 100.0f;
    };

    for (int i = 0; i < 30000; ++i) {
        float m1[16], m2[16];
        for (int k = 0; k < 16; ++k) {
            m1[k] = rnd();
            m2[k] = rnd();
        }

        // 1. Test MatMulInPlace
        float m_client[16], m_ours[16];
        memcpy(m_client, m1, sizeof(m1));
        memcpy(m_ours, m1, sizeof(m1));
        origMul(m_client, nullptr, m2);
        MatMulInPlace_SSE2(m_ours, m2);
        if (memcmp(m_client, m_ours, sizeof(m1)) != 0) {
            Log("[SelfTest] MatMulInPlace mismatch at test %d", i);
            return false;
        }

        // 2. Test MatScaleLocal
        float scale[3] = { rnd(), rnd(), rnd() };
        memcpy(m_client, m1, sizeof(m1));
        memcpy(m_ours, m1, sizeof(m1));
        origScale(m_client, nullptr, scale);
        MatScaleLocal_SSE2(m_ours, scale);
        if (memcmp(m_client, m_ours, sizeof(m1)) != 0) {
            Log("[SelfTest] MatScaleLocal mismatch at test %d", i);
            return false;
        }

        // 3. Test MatScale3x3
        float scalar = rnd();
        memcpy(m_client, m1, sizeof(m1));
        memcpy(m_ours, m1, sizeof(m1));
        origScale3x3(m_client, nullptr, scalar);
        MatScale3x3_SSE2(m_ours, scalar);
        if (memcmp(m_client, m_ours, sizeof(m1)) != 0) {
            Log("[SelfTest] MatScale3x3 mismatch at test %d", i);
            return false;
        }

        // 4. Test MatCreateRotateX
        float angle = rnd() * 0.1f;
        float cx_client[16], cx_ours[16];
        origCreateX(cx_client, angle);
        MatCreateRotateX_SSE2(cx_ours, angle);
        if (memcmp(cx_client, cx_ours, sizeof(cx_client)) != 0) {
            Log("[SelfTest] MatCreateRotateX mismatch at test %d", i);
            return false;
        }

        // 5. Test MatCreateRotateY
        float cy_client[16], cy_ours[16];
        origCreateY(cy_client, angle);
        MatCreateRotateY_SSE2(cy_ours, angle);
        if (memcmp(cy_client, cy_ours, sizeof(cy_client)) != 0) {
            Log("[SelfTest] MatCreateRotateY mismatch at test %d", i);
            return false;
        }

        // 6. Test MatCreateRotateZ
        float cz_client[16], cz_ours[16];
        origCreateZ(cz_client, angle);
        MatCreateRotateZ_SSE2(cz_ours, angle);
        if (memcmp(cz_client, cz_ours, sizeof(cz_client)) != 0) {
            Log("[SelfTest] MatCreateRotateZ mismatch at test %d", i);
            return false;
        }

        // 7. Test MatCreateRotateAxisAngle
        float axis[3] = { rnd(), rnd(), rnd() };
        int is_norm = (i & 1);
        float ca_client[16], ca_ours[16];
        origCreateAxisAngle(ca_client, angle, axis, is_norm);
        MatCreateRotateAxisAngle_SSE2(ca_ours, angle, axis, is_norm);
        if (memcmp(ca_client, ca_ours, sizeof(ca_client)) != 0) {
            Log("[SelfTest] MatCreateRotateAxisAngle mismatch at test %d", i);
            return false;
        }

        // 8. Test MatRotateQuat
        float quat[4] = { rnd() * 0.01f, rnd() * 0.01f, rnd() * 0.01f, 1.0f };
        memcpy(m_client, m1, sizeof(m1));
        memcpy(m_ours, m1, sizeof(m1));
        origRotateQuat(m_client, nullptr, quat);
        MatRotateQuat_SSE2(m_ours, quat);
        if (memcmp(m_client, m_ours, sizeof(m1)) != 0) {
            Log("[SelfTest] MatRotateQuat mismatch at test %d", i);
            return false;
        }

        // 9. Test Vec3Scale
        float v_client[3] = { rnd(), rnd(), rnd() };
        float v_ours[3] = { v_client[0], v_client[1], v_client[2] };
        origVec3Scale(v_client, nullptr, scalar);
        Vec3Scale_SSE2(v_ours, scalar);
        if (memcmp(v_client, v_ours, sizeof(v_client)) != 0) {
            Log("[SelfTest] Vec3Scale mismatch at test %d", i);
            return false;
        }

        // 10. Test Vec3InvScale
        float inv_s = (scalar != 0.0f) ? scalar : 1.5f;
        v_client[0] = rnd(); v_client[1] = rnd(); v_client[2] = rnd();
        v_ours[0] = v_client[0]; v_ours[1] = v_client[1]; v_ours[2] = v_client[2];
        origVec3InvScale(v_client, nullptr, inv_s);
        Vec3InvScale_SSE2(v_ours, inv_s);
        if (memcmp(v_client, v_ours, sizeof(v_client)) != 0) {
            Log("[SelfTest] Vec3InvScale mismatch at test %d", i);
            return false;
        }
    }
    return true;
}
#endif

static inline bool CheckPrologue8(void* addr, const unsigned char expected[8], const char* name) {
    if (memcmp(addr, expected, 8) != 0) {
        Log("[MatrixSSE2] BAD PROLOGUE for %s at 0x%08X", name, (uintptr_t)addr);
        return false;
    }
    return true;
}

// Install hooks
bool InstallMatrixCopySSE2() {
    g_abSubject = AbTest::IsSubject("M2MatrixSimd", &g_abSubject);
    if (g_abSubject) {
        Log("[MatrixSSE2] under A/B test: the copy, the identity and the "
            "multiply alternate on and off in stints, and AbTest reports both "
            "the frame times and the cost of each call either way. The "
            "correctness checks are unaffected.");
    }

#if !TEST_DISABLE_MATRIX_COPY
    struct HookDef {
        void*       addr;
        void*       hook;
        void**      orig;
        const char* name;
        uint32_t    xrefs;
        const unsigned char* prologue;
    };

    static const unsigned char kExp_Copy[8]  = { 0x55, 0x8B, 0xEC, 0x8B, 0xC1, 0x8B, 0x4D, 0x08 };
    static const unsigned char kExp_Ident[8] = { 0xD9, 0xE8, 0x8B, 0xC1, 0xD9, 0x10, 0xD9, 0xEE };

    HookDef hooks[] = {
        { (void*)0x00407F80, (void*)HookMatrixCopy,     (void**)&pOrigMatCopy,     "MatrixCopy",     247, kExp_Copy },
        { (void*)0x00407F40, (void*)HookMatrixIdentity, (void**)&pOrigMatIdentity, "MatrixIdentity",  53, kExp_Ident },
    };

    int installed = 0;
    for (auto& h : hooks) {
        if (!CheckPrologue8(h.addr, h.prologue, h.name)) continue;
        if (WineSafe_CreateHook(h.addr, h.hook, h.orig) == MH_OK) {
             if (WO_EnableHook(h.addr) == MH_OK) {
                 installed++;
                 Log("[MatrixSSE2] Hooked %s at 0x%08X (%d xrefs)", h.name, (DWORD)(uintptr_t)h.addr, h.xrefs);
             }
        }
    }

    Log("[MatrixSSE2] Installed %d/%d hooks (total %d xrefs)",
        installed, (int)(sizeof(hooks) / sizeof(hooks[0])),
        247 + 53);
#else
    Log("[MatrixSSE2] Matrix copy/identity hooks DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_MULTIPLY
    static const unsigned char kExp_MatMul[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x10, 0x8B, 0x55 };
    if (!SelfTestMatrixMultiply()) {
        // The self-test said why; installing anyway would be the whole point of
        // having one thrown away.
    } else if (CheckPrologue8((void*)0x004C1F00, kExp_MatMul, "MatrixMultiply") &&
               WineSafe_CreateHook((void*)0x004C1F00, (void*)HookMatrixMultiply,
                                   (void**)&pOrigMatMul) == MH_OK &&
               WO_EnableHook((void*)0x004C1F00) == MH_OK) {
        Log("[MatrixSSE2] Hooked MatrixMultiply at 0x004C1F00 "
            "(SSE2 packed double, bit-identical to the client)");
    } else {
        Log("[MatrixSSE2] MatrixMultiply hook FAILED");
    }
#else
    Log("[MatrixSSE2] MatrixMultiply DISABLED via feature flag");
#endif

#if !TEST_DISABLE_QUAT_MATRIX_SSE2
    static const unsigned char kExp_QuatToMatrix[8]     = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x8B, 0x45 };
    static const unsigned char kExp_QuatToMatrixFull[8] = { 0x55, 0x8B, 0xEC, 0xD9, 0xEE, 0x8B, 0x45, 0x08 };
    if (!SelfTestQuatToMatrix()) {
        // The self-test said why. Installing anyway would throw away the only
        // thing standing between a misread spill slot and a subtly wrong bone
        // rotation on every animated model in the game.
    } else if (CheckPrologue8((void*)0x004C1C40, kExp_QuatToMatrix, "QuatToMatrix") &&
               WineSafe_CreateHook((void*)0x004C1C40, (void*)Hooked_QuatToMatrix,
                                   (void**)&pOrigQuatToMatrix) == MH_OK &&
               WO_EnableHook((void*)0x004C1C40) == MH_OK) {
        Log("[MatrixSSE2] Hooked QuatToMatrix at 0x004C1C40 "
            "(SSE2 packed double, bit-identical, covers all 3 quaternion wrappers)");

        // Only worth attempting once the core has proved itself and installed;
        // this shares its arithmetic, so if that did not pass there is nothing
        // here worth installing either.
        if (CheckPrologue8((void*)0x004C1DE0, kExp_QuatToMatrixFull, "QuatToMatrix(full)") &&
            WineSafe_CreateHook((void*)0x004C1DE0, (void*)Hooked_QuatToMatrixFull,
                                (void**)&pOrigQuatToMatrixFull) == MH_OK &&
            WO_EnableHook((void*)0x004C1DE0) == MH_OK) {
            Log("[MatrixSSE2] Hooked QuatToMatrix(full) at 0x004C1DE0 "
                "(fused with the core, one call instead of two on the per-bone path)");
        } else {
            Log("[MatrixSSE2] QuatToMatrix(full) hook FAILED - the core is still active");
        }
    } else {
        Log("[MatrixSSE2] QuatToMatrix hook FAILED");
    }
#else
    Log("[MatrixSSE2] QuatToMatrix DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_VECTOR_SSE2
    static const unsigned char kExp_MatVec3Mul[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x10, 0x8B, 0x55 };
    static const unsigned char kExp_MatVec4Mul[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0x55, 0x10, 0x8B, 0x4D };
    if (CheckPrologue8((void*)0x004C21B0, kExp_MatVec3Mul, "MatVec3Mul") &&
        WineSafe_CreateHook((void*)0x004C21B0, (void*)Hooked_MatVec3Mul,
                            (void**)&pOrigMatVec3Mul) == MH_OK &&
        WO_EnableHook((void*)0x004C21B0) == MH_OK) {
        Log("[MatrixSSE2] Hooked MatVec3Mul at 0x004C21B0 (SSE2, 100+ xrefs)");
    } else {
        Log("[MatrixSSE2] MatVec3Mul hook FAILED");
    }

    if (CheckPrologue8((void*)0x004C2270, kExp_MatVec4Mul, "MatVec4Mul") &&
        WineSafe_CreateHook((void*)0x004C2270, (void*)Hooked_MatVec4Mul,
                            (void**)&pOrigMatVec4Mul) == MH_OK &&
        WO_EnableHook((void*)0x004C2270) == MH_OK) {
        Log("[MatrixSSE2] Hooked MatVec4Mul at 0x004C2270 (SSE2, 20 xrefs)");
    } else {
        Log("[MatrixSSE2] MatVec4Mul hook FAILED");
    }
#else
    Log("[MatrixSSE2] Matrix-Vector hooks DISABLED via feature flag");
#endif

#if !TEST_DISABLE_VEC_NORMALIZE_SSE2
    static const unsigned char kExp_Vec3Norm[8]     = { 0xD9, 0x01, 0xD9, 0x41, 0x04, 0xD9, 0x41, 0x08 };
    static const unsigned char kExp_Vec3NormSafe[8] = { 0xD9, 0x41, 0x08, 0xD9, 0x41, 0x04, 0xD9, 0x01 };
    if (CheckPrologue8((void*)0x004C3420, kExp_Vec3Norm, "C3Vector::Normalize") &&
        WineSafe_CreateHook((void*)0x004C3420, (void*)Hooked_Vec3Norm,
                            (void**)&pOrigVec3Norm) == MH_OK &&
        WO_EnableHook((void*)0x004C3420) == MH_OK) {
        Log("[MatrixSSE2] Hooked C3Vector::Normalize at 0x004C3420 "
            "(SSE2 packed double, bit-identical, 12 callers)");
    } else {
        Log("[MatrixSSE2] C3Vector::Normalize hook FAILED");
    }

    if (CheckPrologue8((void*)0x004C3600, kExp_Vec3NormSafe, "C3Vector::Normalize(guarded)") &&
        WineSafe_CreateHook((void*)0x004C3600, (void*)Hooked_Vec3NormSafe,
                            (void**)&pOrigVec3NormSafe) == MH_OK &&
        WO_EnableHook((void*)0x004C3600) == MH_OK) {
        Log("[MatrixSSE2] Hooked C3Vector::Normalize(guarded) at 0x004C3600 "
            "(SSE2 packed double, bit-identical, 2^-22 guard, 22 callers)");
    } else {
        Log("[MatrixSSE2] C3Vector::Normalize(guarded) hook FAILED");
    }
#else
    Log("[MatrixSSE2] Vector-Normalize hooks DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_EXT_SSE2
    static const unsigned char kExp_MatTranspose[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0xD9, 0x01 };
    static const unsigned char kExp_PointXformIP[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x0C, 0x8B, 0x45 };
    static const unsigned char kExp_VecMatRotate[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0x55, 0x10, 0x8B, 0x4D };
    static const unsigned char kExp_MatFrom3x3[8]   = { 0x55, 0x8B, 0xEC, 0x8B, 0xC1, 0x8B, 0x4D, 0x08 };
    if (CheckPrologue8((void*)0x004C23D0, kExp_MatTranspose, "CMatrix::Transpose") &&
        WineSafe_CreateHook((void*)0x004C23D0, (void*)Hooked_MatTranspose,
                            (void**)&pOrigMatTranspose) == MH_OK &&
        WO_EnableHook((void*)0x004C23D0) == MH_OK) {
        Log("[MatrixSSE2] Hooked CMatrix::Transpose at 0x004C23D0 (SSE2 _MM_TRANSPOSE4_PS)");
    } else {
        Log("[MatrixSSE2] CMatrix::Transpose hook FAILED");
    }

    if (CheckPrologue8((void*)0x004C2300, kExp_PointXformIP, "PointTransformInPlace") &&
        WineSafe_CreateHook((void*)0x004C2300, (void*)Hooked_PointXformInPlace,
                            (void**)&pOrigPointXformIP) == MH_OK &&
        WO_EnableHook((void*)0x004C2300) == MH_OK) {
        SamplingProfiler::RegisterSelfSymbol("PointXformInPlace_SSE2", (const void*)&Hooked_PointXformInPlace);
        Log("[MatrixSSE2] Hooked PointTransformInPlace at 0x004C2300 (SSE2 double-precision, verified, 65 callers)");
    } else {
        Log("[MatrixSSE2] PointTransformInPlace hook FAILED");
    }

    if (CheckPrologue8((void*)0x005FED20, kExp_VecMatRotate, "VectorMatrixRotate") &&
        WineSafe_CreateHook((void*)0x005FED20, (void*)Hooked_VectorMatrixRotate,
                            (void**)&pOrigVectorMatrixRotate) == MH_OK &&
        WO_EnableHook((void*)0x005FED20) == MH_OK) {
        SamplingProfiler::RegisterSelfSymbol("VectorMatrixRotate_SSE2", (const void*)&Hooked_VectorMatrixRotate);
        Log("[MatrixSSE2] Hooked VectorMatrixRotate at 0x005FED20 (SSE2 double-precision, verified, 7 callers)");
    } else {
        Log("[MatrixSSE2] VectorMatrixRotate hook FAILED");
    }

    if (CheckPrologue8((void*)0x004C3680, kExp_MatFrom3x3, "CMatrix::From3x3") &&
        WineSafe_CreateHook((void*)0x004C3680, (void*)Hooked_MatFrom3x3,
                            (void**)&pOrigMatFrom3x3) == MH_OK &&
        WO_EnableHook((void*)0x004C3680) == MH_OK) {
        Log("[MatrixSSE2] Hooked CMatrix::From3x3 at 0x004C3680 (SSE2, 5 callers)");
    } else {
        Log("[MatrixSSE2] CMatrix::From3x3 hook FAILED");
    }
#else
    Log("[MatrixSSE2] Matrix-Ext hooks DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_INVERT_SSE2
    static const unsigned char kExp_MatInvRigid[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x48, 0x56, 0x8B };
    if (CheckPrologue8((void*)0x004C2FC0, kExp_MatInvRigid, "CMatrix::InvertRigid") &&
        WineSafe_CreateHook((void*)0x004C2FC0, (void*)Hooked_MatInvertRigid,
                            (void**)&pOrigMatInvRigid) == MH_OK &&
        WO_EnableHook((void*)0x004C2FC0) == MH_OK) {
        Log("[MatrixSSE2] Hooked CMatrix::InvertRigid at 0x004C2FC0 (SSE2, ~34 callers)");
    } else {
        Log("[MatrixSSE2] CMatrix::InvertRigid hook FAILED");
    }
#else
    Log("[MatrixSSE2] CMatrix::InvertRigid DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_MISC_SSE2
    static const unsigned char kExp_MatScalarMul[8]   = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x0C, 0x8B, 0x45 };
    static const unsigned char kExp_RowAffinePoint[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0x4D, 0x0C, 0x8B, 0x55 };
    if (CheckPrologue8((void*)0x004C2120, kExp_MatScalarMul, "CMatrix::ScalarMul") &&
        WineSafe_CreateHook((void*)0x004C2120, (void*)Hooked_MatScalarMul,
                            (void**)&pOrigMatScalarMul) == MH_OK &&
        WO_EnableHook((void*)0x004C2120) == MH_OK) {
        Log("[MatrixSSE2] Hooked CMatrix::ScalarMul at 0x004C2120 (SSE2, 4 callers)");
    } else {
        Log("[MatrixSSE2] CMatrix::ScalarMul hook FAILED");
    }

    if (CheckPrologue8((void*)0x004C2210, kExp_RowAffinePoint, "RowAffinePoint") &&
        WineSafe_CreateHook((void*)0x004C2210, (void*)Hooked_RowAffinePoint,
                            (void**)&pOrigRowAffinePoint) == MH_OK &&
        WO_EnableHook((void*)0x004C2210) == MH_OK) {
        Log("[MatrixSSE2] Hooked RowAffinePoint at 0x004C2210 (SSE2, 6 callers)");
    } else {
        Log("[MatrixSSE2] RowAffinePoint hook FAILED");
    }
#else
    Log("[MatrixSSE2] Matrix-Misc hooks DISABLED via feature flag");
#endif

#if !TEST_DISABLE_MATRIX_TRANSLATE_SSE2
    static const unsigned char kExp_MatTranslateLocal[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0xD9, 0x41 };
    if (CheckPrologue8((void*)0x004C1B30, kExp_MatTranslateLocal, "CMatrix::TranslateLocal") &&
        WineSafe_CreateHook((void*)0x004C1B30, (void*)Hooked_MatTranslateLocal,
                            (void**)&pOrigMatTranslate) == MH_OK &&
        WO_EnableHook((void*)0x004C1B30) == MH_OK) {
        SamplingProfiler::RegisterSelfSymbol("MatTranslateLocal_SSE2", (const void*)&Hooked_MatTranslateLocal);
        Log("[MatrixSSE2] Hooked CMatrix::TranslateLocal at 0x004C1B30 (SSE2 double-precision, verified, 65+ callers)");
    } else {
        Log("[MatrixSSE2] CMatrix::TranslateLocal hook FAILED");
    }
#else
    Log("[MatrixSSE2] CMatrix::TranslateLocal DISABLED via feature flag");
#endif

    static const unsigned char kExp_BoxScale[8] = { 0x55, 0x8B, 0xEC, 0x8B, 0xC1, 0xD9, 0x00, 0xD9 };
    if (CheckPrologue8((void*)0x005FECB0, kExp_BoxScale, "CBox::Scale") &&
        WineSafe_CreateHook((void*)0x005FECB0, (void*)Hooked_BoxScale,
                            (void**)&pOrigBoxScale) == MH_OK &&
        WO_EnableHook((void*)0x005FECB0) == MH_OK) {
        SamplingProfiler::RegisterSelfSymbol("BoxScale_SSE2", (const void*)&Hooked_BoxScale);
        Log("[MatrixSSE2] Hooked CBox::Scale at 0x005FECB0 (SSE2 double-precision, verified, 7 callers)");
    } else {
        Log("[MatrixSSE2] CBox::Scale hook FAILED");
    }

#if !TEST_DISABLE_MATRIX_ROTATE_SSE2
    static const unsigned char kExp_MatRotateX[8] = { 0x55, 0x8B, 0xEC, 0xD9, 0x45, 0x08, 0x81, 0xEC };
    static const unsigned char kExp_MatRotateY[8] = { 0x55, 0x8B, 0xEC, 0xD9, 0x45, 0x08, 0x81, 0xEC };
    static const unsigned char kExp_MatRotateZ[8] = { 0x55, 0x8B, 0xEC, 0xD9, 0x45, 0x08, 0x81, 0xEC };
    if (!SelfTestMatrixRotate()) {
        Log("[MatrixSSE2] SelfTestMatrixRotate FAILED, rotation hooks disabled");
    } else {
        if (CheckPrologue8((void*)0x004C3300, kExp_MatRotateX, "CMatrix::RotateX") &&
            WineSafe_CreateHook((void*)0x004C3300, (void*)Hooked_MatRotateX,
                                (void**)&pOrigMatRotateX) == MH_OK &&
            WO_EnableHook((void*)0x004C3300) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("MatRotateX_SSE2", (const void*)&Hooked_MatRotateX);
            Log("[MatrixSSE2] Hooked CMatrix::RotateX at 0x004C3300 (SSE2 double-precision, verified, 8 callers)");
        } else {
            Log("[MatrixSSE2] CMatrix::RotateX hook FAILED");
        }

        if (CheckPrologue8((void*)0x004C3340, kExp_MatRotateY, "CMatrix::RotateY") &&
            WineSafe_CreateHook((void*)0x004C3340, (void*)Hooked_MatRotateY,
                                (void**)&pOrigMatRotateY) == MH_OK &&
            WO_EnableHook((void*)0x004C3340) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("MatRotateY_SSE2", (const void*)&Hooked_MatRotateY);
            Log("[MatrixSSE2] Hooked CMatrix::RotateY at 0x004C3340 (SSE2 double-precision, verified, 9 callers)");
        } else {
            Log("[MatrixSSE2] CMatrix::RotateY hook FAILED");
        }

        if (CheckPrologue8((void*)0x004C3380, kExp_MatRotateZ, "CMatrix::RotateZ") &&
            WineSafe_CreateHook((void*)0x004C3380, (void*)Hooked_MatRotateZ,
                                (void**)&pOrigMatRotateZ) == MH_OK &&
            WO_EnableHook((void*)0x004C3380) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("MatRotateZ_SSE2", (const void*)&Hooked_MatRotateZ);
            Log("[MatrixSSE2] Hooked CMatrix::RotateZ at 0x004C3380 (SSE2 double-precision, verified, 39 callers)");
        } else {
            Log("[MatrixSSE2] CMatrix::RotateZ hook FAILED");
        }
    }
#endif

#if !TEST_DISABLE_MATRIX_OPS_SSE2
    static const unsigned char kExp_MatMulInPlace[8]    = { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x83, 0xEC };
    static const unsigned char kExp_MatScaleLocal[8]    = { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0xD9, 0x00 };
    static const unsigned char kExp_MatScale3x3[8]      = { 0x55, 0x8B, 0xEC, 0xD9, 0x01, 0xD9, 0x45, 0x08 };
    static const unsigned char kExp_MatCreateRotateX[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x8D, 0x45 };
    static const unsigned char kExp_MatCreateRotateY[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x8D, 0x45 };
    static const unsigned char kExp_MatCreateRotateZ[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x8D, 0x45 };
    static const unsigned char kExp_MatCreateRotAxis[8] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x18, 0x80, 0x7D };
    static const unsigned char kExp_MatRotateQuat[8]    = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x80, 0x00, 0x00 };
    static const unsigned char kExp_Vec3Scale[8]        = { 0x55, 0x8B, 0xEC, 0x8B, 0xC1, 0xD9, 0x00, 0xD9 };
    static const unsigned char kExp_Vec3InvScale[8]     = { 0x55, 0x8B, 0xEC, 0xD9, 0xE8, 0x8B, 0xC1, 0xD8 };

    if (!SelfTestMatrixOps()) {
        Log("[MatrixSSE2] SelfTestMatrixOps FAILED, matrix ops hooks disabled");
    } else {
        if (CheckPrologue8((void*)0x004C2370, kExp_MatMulInPlace, "CMatrix::MultiplyInPlace") &&
            WineSafe_CreateHook((void*)0x004C2370, (void*)Hooked_MatMulInPlace,
                                (void**)&pOrigMatMulInPlace) == MH_OK &&
            WO_EnableHook((void*)0x004C2370) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("MatMulInPlace_SSE2", (const void*)&Hooked_MatMulInPlace);
            Log("[MatrixSSE2] Hooked CMatrix::MultiplyInPlace at 0x004C2370 (SSE2 double-precision, verified, 27 callers)");
        } else {
            Log("[MatrixSSE2] CMatrix::MultiplyInPlace hook FAILED");
        }

        if (CheckPrologue8((void*)0x004C1B90, kExp_MatScaleLocal, "CMatrix::ScaleLocal") &&
            WineSafe_CreateHook((void*)0x004C1B90, (void*)Hooked_MatScaleLocal,
                                (void**)&pOrigMatScaleLocal) == MH_OK &&
            WO_EnableHook((void*)0x004C1B90) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("MatScaleLocal_SSE2", (const void*)&Hooked_MatScaleLocal);
            Log("[MatrixSSE2] Hooked CMatrix::ScaleLocal at 0x004C1B90 (SSE2 double-precision, verified, 18 callers)");
        } else {
            Log("[MatrixSSE2] CMatrix::ScaleLocal hook FAILED");
        }

        if (CheckPrologue8((void*)0x004C1BF0, kExp_MatScale3x3, "CMatrix::Scale3x3") &&
            WineSafe_CreateHook((void*)0x004C1BF0, (void*)Hooked_MatScale3x3,
                                (void**)&pOrigMatScale3x3) == MH_OK &&
            WO_EnableHook((void*)0x004C1BF0) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("MatScale3x3_SSE2", (const void*)&Hooked_MatScale3x3);
            Log("[MatrixSSE2] Hooked CMatrix::Scale3x3 at 0x004C1BF0 (SSE2 double-precision, verified, 36 callers)");
        } else {
            Log("[MatrixSSE2] CMatrix::Scale3x3 hook FAILED");
        }

        if (CheckPrologue8((void*)0x004C31B0, kExp_MatCreateRotateX, "CMatrix::CreateRotateX") &&
            WineSafe_CreateHook((void*)0x004C31B0, (void*)Hooked_MatCreateRotateX,
                                (void**)&pOrigMatCreateRotateX) == MH_OK &&
            WO_EnableHook((void*)0x004C31B0) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("MatCreateRotateX_SSE2", (const void*)&Hooked_MatCreateRotateX);
            Log("[MatrixSSE2] Hooked CMatrix::CreateRotateX at 0x004C31B0 (SSE2 double-precision, verified, 8 callers)");
        } else {
            Log("[MatrixSSE2] CMatrix::CreateRotateX hook FAILED");
        }

        if (CheckPrologue8((void*)0x004C3220, kExp_MatCreateRotateY, "CMatrix::CreateRotateY") &&
            WineSafe_CreateHook((void*)0x004C3220, (void*)Hooked_MatCreateRotateY,
                                (void**)&pOrigMatCreateRotateY) == MH_OK &&
            WO_EnableHook((void*)0x004C3220) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("MatCreateRotateY_SSE2", (const void*)&Hooked_MatCreateRotateY);
            Log("[MatrixSSE2] Hooked CMatrix::CreateRotateY at 0x004C3220 (SSE2 double-precision, verified, 8 callers)");
        } else {
            Log("[MatrixSSE2] CMatrix::CreateRotateY hook FAILED");
        }

        if (CheckPrologue8((void*)0x004C3290, kExp_MatCreateRotateZ, "CMatrix::CreateRotateZ") &&
            WineSafe_CreateHook((void*)0x004C3290, (void*)Hooked_MatCreateRotateZ,
                                (void**)&pOrigMatCreateRotateZ) == MH_OK &&
            WO_EnableHook((void*)0x004C3290) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("MatCreateRotateZ_SSE2", (const void*)&Hooked_MatCreateRotateZ);
            Log("[MatrixSSE2] Hooked CMatrix::CreateRotateZ at 0x004C3290 (SSE2 double-precision, verified, 13 callers)");
        } else {
            Log("[MatrixSSE2] CMatrix::CreateRotateZ hook FAILED");
        }

        if (CheckPrologue8((void*)0x004C3460, kExp_MatCreateRotAxis, "CMatrix::CreateRotateAxisAngle") &&
            WineSafe_CreateHook((void*)0x004C3460, (void*)Hooked_MatCreateRotateAxisAngle,
                                (void**)&pOrigMatCreateRotateAxisAngle) == MH_OK &&
            WO_EnableHook((void*)0x004C3460) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("MatCreateRotateAxisAngle_SSE2", (const void*)&Hooked_MatCreateRotateAxisAngle);
            Log("[MatrixSSE2] Hooked CMatrix::CreateRotateAxisAngle at 0x004C3460 (SSE2 double-precision, verified, 13 callers)");
        } else {
            Log("[MatrixSSE2] CMatrix::CreateRotateAxisAngle hook FAILED");
        }

        if (CheckPrologue8((void*)0x004C33C0, kExp_MatRotateQuat, "CMatrix::RotateQuat") &&
            WineSafe_CreateHook((void*)0x004C33C0, (void*)Hooked_MatRotateQuat,
                                (void**)&pOrigMatRotateQuat) == MH_OK &&
            WO_EnableHook((void*)0x004C33C0) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("MatRotateQuat_SSE2", (const void*)&Hooked_MatRotateQuat);
            Log("[MatrixSSE2] Hooked CMatrix::RotateQuat at 0x004C33C0 (SSE2 double-precision, verified, 4 callers)");
        } else {
            Log("[MatrixSSE2] CMatrix::RotateQuat hook FAILED");
        }

        if (CheckPrologue8((void*)0x004C35A0, kExp_Vec3Scale, "Vec3_Scale") &&
            WineSafe_CreateHook((void*)0x004C35A0, (void*)Hooked_Vec3Scale,
                                (void**)&pOrigVec3Scale) == MH_OK &&
            WO_EnableHook((void*)0x004C35A0) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("Vec3Scale_SSE2", (const void*)&Hooked_Vec3Scale);
            Log("[MatrixSSE2] Hooked Vec3_Scale at 0x004C35A0 (SSE2 double-precision, verified, 2 callers)");
        } else {
            Log("[MatrixSSE2] Vec3_Scale hook FAILED");
        }

        if (CheckPrologue8((void*)0x004C35D0, kExp_Vec3InvScale, "Vec3_InvScale") &&
            WineSafe_CreateHook((void*)0x004C35D0, (void*)Hooked_Vec3InvScale,
                                (void**)&pOrigVec3InvScale) == MH_OK &&
            WO_EnableHook((void*)0x004C35D0) == MH_OK) {
            SamplingProfiler::RegisterSelfSymbol("Vec3InvScale_SSE2", (const void*)&Hooked_Vec3InvScale);
            Log("[MatrixSSE2] Hooked Vec3_InvScale at 0x004C35D0 (SSE2 double-precision, verified, 4 callers)");
        } else {
            Log("[MatrixSSE2] Vec3_InvScale hook FAILED");
        }
    }
#endif

    g_matrixInstalled = true;
#if !TEST_DISABLE_MATRIX_COPY
    return installed == (int)(sizeof(hooks) / sizeof(hooks[0]));
#else
    return true;
#endif
}

// Statistics
//
// Fifteen counters, printed only from ShutdownMatrixCopySSE2 until now, which
// nothing calls - the DLL leaves through TerminateProcess and the linker had
// dropped the whole function. M2MatrixSimd is an A/B subject, and a subject
// whose call counts cannot be read cannot answer "was its hot path reached
// during the OFF stint", which is the question that decides whether a null
// result means anything.
//
// One line, because fifteen lines of two-digit numbers is not a report. The
// counts are plain increments on hot paths and are lower bounds.
void MatrixCopySSE2_LogStats(void) {
    if (!g_matrixInstalled) {
        Log("[MatrixSSE2] not measured: the hooks are not installed.");
        return;
    }
    // Summed as a double. Adding fifteen 32-bit counters into a sixteenth
    // 32-bit word is how the total wrapped in the first place, and the fix for
    // one term is not a fix for their sum.
    const double mul = (double)g_matmul_wraps * 4294967296.0
                     + (double)g_matmul_calls;
    const double total =
        (double)g_matcopy_calls + (double)g_matident_calls + mul +
        (double)g_matvec3_calls + (double)g_matvec4_calls +
        (double)g_quat2mat_calls + (double)g_quat2matfull_calls +
        (double)g_vec3norm_calls + (double)g_mattranspose_calls +
        (double)g_matfrom3x3_calls +
        (double)g_pointxformip_calls + (double)g_vecmatrotate_calls + (double)g_matinvrigid_calls
#if !TEST_DISABLE_MATRIX_MISC_SSE2
        + (double)g_matscalarmul_calls
#endif
#if !TEST_DISABLE_MATRIX_TRANSLATE_SSE2
        + (double)g_mattranslate_calls
#endif
        + (double)g_boxscale_calls
#if !TEST_DISABLE_MATRIX_ROTATE_SSE2
        + (double)g_matrotate_x_calls + (double)g_matrotate_y_calls + (double)g_matrotate_z_calls
#endif
#if !TEST_DISABLE_MATRIX_OPS_SSE2
        + (double)g_matmul_ip_calls + (double)g_matscale_local_calls + (double)g_scale3x3_calls
        + (double)g_matcreate_rotx_calls + (double)g_matcreate_roty_calls + (double)g_matcreate_rotz_calls
        + (double)g_matcreate_rotaxis_calls + (double)g_matrotate_quat_calls + (double)g_vec3_scale_calls + (double)g_vec3_invscale_calls
#endif
        ;
    if (total == 0.0) {
        Log("[MatrixSSE2] measured and zero: the hooks are in and the client "
            "reached none of them.");
        return;
    }
    Log("[MatrixSSE2] %.0f call(s) through the SSE2 matrix hooks, lower bounds: "
        "copy %lu, identity %lu, multiply %.0f, matvec3 %lu, matvec4 %lu, "
        "quat2mat %lu, quat2mat-fused %lu, vec3normalize %lu",
        total, g_matcopy_calls, g_matident_calls, mul,
        g_matvec3_calls, g_matvec4_calls, g_quat2mat_calls,
        g_quat2matfull_calls, g_vec3norm_calls);
    // The pointer guard, printed whether or not it ever fired. The copy and the
    // multiply are 12.6 billion calls between them in a field session, and each
    // was carrying an exception frame for a fault that has never been seen; a
    // non-zero catch count here means that reasoning is wrong and the guard is
    // back on for good.
    Log("[MatrixSSE2]   pointer guard: %lu call(s) ran under it, it caught %lu, "
        "and it is %s. Armed means the copy and multiply carry no exception "
        "frame - the fallback they used to reach reads the same bytes that just "
        "faulted, so it could never have recovered one.",
        g_matProved, g_matFaults,
        g_matArmed ? "armed" : (g_matFaults ? "held on by a catch"
                                            : "still proving"));
    Log("[MatrixSSE2]   multiply against the client: %lu call(s) compared bit for bit (every one "
        "while proving, then one in 65536), %lu whose result was also an input and so were left "
        "to the client; %s. Plain counters, lower bounds.",
        g_matChecked, g_matAliased,
        g_matDead ? "DISAGREED once and retired, the line that says where is earlier in this log"
                  : "no difference seen");
    // The same guard on the vector normalise, which a tester profile puts at
    // 1.89% of executing time on its own.
    Log("[MatrixSSE2]   normalise guard: %lu call(s) ran under it, it caught %lu, "
        "and it is %s.",
        g_normProved, g_normFaults,
        g_normFaults ? "held on by a catch"
                     : (g_normProved >= kNormProve ? "off, so the normalise carries "
                                                     "no exception frame"
                                                   : "still proving"));
    Log("[MatrixSSE2]   transpose %lu, from3x3 %lu, "
        "pointxform-in-place %lu (%lu verified), vecmat-rotate %lu (%lu verified), invert-rigid %lu",
        g_mattranspose_calls, g_matfrom3x3_calls,
        g_pointxformip_calls, g_pointxformip_agreements,
        g_vecmatrotate_calls, g_vecmatrotate_agreements, g_matinvrigid_calls);
    // These two are behind feature flags that are off, so the counters do not
    // exist in this build and neither does a line claiming they are zero.
#if !TEST_DISABLE_MATRIX_MISC_SSE2
    Log("[MatrixSSE2]   scalar-mul %lu", g_matscalarmul_calls);
#endif
#if !TEST_DISABLE_MATRIX_TRANSLATE_SSE2
    Log("[MatrixSSE2]   translate-local %lu", g_mattranslate_calls);
#endif
#if !TEST_DISABLE_MATRIX_ROTATE_SSE2
    Log("[MatrixSSE2]   rotate-x %lu (%lu verified), rotate-y %lu (%lu verified), rotate-z %lu (%lu verified)",
        g_matrotate_x_calls, g_matrotate_x_agreements,
        g_matrotate_y_calls, g_matrotate_y_agreements,
        g_matrotate_z_calls, g_matrotate_z_agreements);
#endif
#if !TEST_DISABLE_MATRIX_OPS_SSE2
    Log("[MatrixSSE2]   mulinplace %lu (%lu verified), scalelocal %lu (%lu verified), scale3x3 %lu (%lu verified)",
        g_matmul_ip_calls, g_matmul_ip_agreements,
        g_matscale_local_calls, g_matscale_local_agreements,
        g_scale3x3_calls, g_scale3x3_agreements);
    Log("[MatrixSSE2]   create-rotx %lu (%lu verified), create-roty %lu (%lu verified), create-rotz %lu (%lu verified)",
        g_matcreate_rotx_calls, g_matcreate_rotx_agreements,
        g_matcreate_roty_calls, g_matcreate_roty_agreements,
        g_matcreate_rotz_calls, g_matcreate_rotz_agreements);
    Log("[MatrixSSE2]   rotaxis %lu (%lu verified), rotate-quat %lu (%lu verified), vec3-scale %lu (%lu verified), vec3-invscale %lu (%lu verified)",
        g_matcreate_rotaxis_calls, g_matcreate_rotaxis_agreements,
        g_matrotate_quat_calls, g_matrotate_quat_agreements,
        g_vec3_scale_calls, g_vec3_scale_agreements,
        g_vec3_invscale_calls, g_vec3_invscale_agreements);
#endif
}

// Cleanup
void ShutdownMatrixCopySSE2() {
    MH_DisableHook((void*)0x00407F80);
    MH_DisableHook((void*)0x00407F40);
#if !TEST_DISABLE_MATRIX_MULTIPLY
    MH_DisableHook((void*)0x004C1F00);
#endif
#if !TEST_DISABLE_QUAT_MATRIX_SSE2
    MH_DisableHook((void*)0x004C1C40);
    MH_DisableHook((void*)0x004C1DE0);
    Log("[MatrixSSE2] Stats: QuatToMatrix core=%lu  fused wrapper=%lu",
        g_quat2mat_calls, g_quat2matfull_calls);
#endif
#if !TEST_DISABLE_MATRIX_VECTOR_SSE2
    MH_DisableHook((void*)0x004C21B0);
    MH_DisableHook((void*)0x004C2270);
#endif
#if !TEST_DISABLE_VEC_NORMALIZE_SSE2
    MH_DisableHook((void*)0x004C3420);
    MH_DisableHook((void*)0x004C3600);
    Log("[MatrixSSE2] Stats: Vec3Normalize=%lu", g_vec3norm_calls);
#endif
#if !TEST_DISABLE_MATRIX_EXT_SSE2
    MH_DisableHook((void*)0x004C23D0);
    MH_DisableHook((void*)0x004C2300);
    MH_DisableHook((void*)0x005FED20);
    MH_DisableHook((void*)0x004C3680);
    Log("[MatrixSSE2] Stats: Transpose=%lu  PointXformIP=%lu (%lu verified)  VecMatRotate=%lu (%lu verified)  From3x3=%lu",
        g_mattranspose_calls, g_pointxformip_calls, g_pointxformip_agreements,
        g_vecmatrotate_calls, g_vecmatrotate_agreements, g_matfrom3x3_calls);
#endif
#if !TEST_DISABLE_MATRIX_INVERT_SSE2
    MH_DisableHook((void*)0x004C2FC0);
    Log("[MatrixSSE2] Stats: InvertRigid=%lu", g_matinvrigid_calls);
#endif
#if !TEST_DISABLE_MATRIX_MISC_SSE2
    MH_DisableHook((void*)0x004C2120);
    MH_DisableHook((void*)0x004C2210);
    Log("[MatrixSSE2] Stats: MatrixMisc(ScalarMul+RowAffine)=%lu", g_matscalarmul_calls);
#endif
#if !TEST_DISABLE_MATRIX_TRANSLATE_SSE2
    MH_DisableHook((void*)0x004C1B30);
    Log("[MatrixSSE2] Stats: TranslateLocal=%lu (%lu verified)", g_mattranslate_calls, g_mattranslate_agreements);
#endif
    MH_DisableHook((void*)0x005FECB0);
    Log("[MatrixSSE2] Stats: BoxScale=%lu (%lu verified)", g_boxscale_calls, g_boxscale_agreements);
#if !TEST_DISABLE_MATRIX_ROTATE_SSE2
    MH_DisableHook((void*)0x004C3300);
    MH_DisableHook((void*)0x004C3340);
    MH_DisableHook((void*)0x004C3380);
    Log("[MatrixSSE2] Stats: RotateX=%lu (%lu verified)  RotateY=%lu (%lu verified)  RotateZ=%lu (%lu verified)",
        g_matrotate_x_calls, g_matrotate_x_agreements,
        g_matrotate_y_calls, g_matrotate_y_agreements,
        g_matrotate_z_calls, g_matrotate_z_agreements);
#endif
#if !TEST_DISABLE_MATRIX_OPS_SSE2
    MH_DisableHook((void*)0x004C2370);
    MH_DisableHook((void*)0x004C1B90);
    MH_DisableHook((void*)0x004C1BF0);
    MH_DisableHook((void*)0x004C31B0);
    MH_DisableHook((void*)0x004C3220);
    MH_DisableHook((void*)0x004C3290);
    MH_DisableHook((void*)0x004C3460);
    MH_DisableHook((void*)0x004C33C0);
    MH_DisableHook((void*)0x004C35A0);
    MH_DisableHook((void*)0x004C35D0);
    Log("[MatrixSSE2] Stats: MulInPlace=%lu (%lu verified)  ScaleLocal=%lu (%lu verified)  Scale3x3=%lu (%lu verified)  CreateRotateX=%lu (%lu verified)  CreateRotateY=%lu (%lu verified)  CreateRotateZ=%lu (%lu verified)",
        g_matmul_ip_calls, g_matmul_ip_agreements,
        g_matscale_local_calls, g_matscale_local_agreements,
        g_scale3x3_calls, g_scale3x3_agreements,
        g_matcreate_rotx_calls, g_matcreate_rotx_agreements,
        g_matcreate_roty_calls, g_matcreate_roty_agreements,
        g_matcreate_rotz_calls, g_matcreate_rotz_agreements);
    Log("[MatrixSSE2] Stats: CreateRotateAxisAngle=%lu (%lu verified)  RotateQuat=%lu (%lu verified)  Vec3Scale=%lu (%lu verified)  Vec3InvScale=%lu (%lu verified)",
        g_matcreate_rotaxis_calls, g_matcreate_rotaxis_agreements,
        g_matrotate_quat_calls, g_matrotate_quat_agreements,
        g_vec3_scale_calls, g_vec3_scale_agreements,
        g_vec3_invscale_calls, g_vec3_invscale_agreements);
#endif

    Log("[MatrixSSE2] Stats: MatrixCopy=%lu  MatrixIdentity=%lu  MatrixMul=%lu  MatVec3=%lu  MatVec4=%lu",
        g_matcopy_calls, g_matident_calls, g_matmul_calls, g_matvec3_calls, g_matvec4_calls);
}
