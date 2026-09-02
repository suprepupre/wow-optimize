// ============================================================================
// Module: strncmp_sse2.cpp
//
// strncmp at 0x004180A6 is 1.55% of executing main-thread time in a 28-minute
// gameplay profile, with 29 call sites. It is the CRT's own implementation
// linked into the client: byte at a time, unrolled four ways, checking each byte
// for NUL and for inequality separately.
//
// Not to be confused with _strnicmp at 0x0076E780, which this project already
// replaces. That one is case-insensitive and a different function; this one had
// never been touched.
//
// Sixteen bytes per compare instead of one. The mask of "first byte that is
// either different or NUL" falls out of two SSE2 compares:
//
//     eq   = cmpeq(a, b)         bits set where the bytes match
//     zero = cmpeq(a, 0)         bits set where a has a NUL
//     stop = ~eq | zero          bits set where the original would have stopped
//
// and the lowest set bit is the index the original would have returned at. The
// return value is then computed exactly as the original computes it, as the
// difference of the two bytes widened from unsigned char, not clamped to -1/0/1.
//
// The part that needs care is not the arithmetic, it is the reading. The
// original never reads past the byte it is examining, so a string ending one
// byte before an unmapped page is safe for it. A sixteen-byte load is not. Every
// block load is therefore gated on both pointers having sixteen bytes left
// inside their current 4 KB page; where they do not, it steps a byte at a time
// until they do. That keeps the fast path for the body of a long string instead
// of abandoning it at the first page boundary, and it never reads a byte the
// original would not have read.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <emmintrin.h>
#include <intrin.h>

#include "strncmp_sse2.h"
#include "ab_test.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "crash_dumper.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace StrncmpSse2 {

static constexpr uintptr_t ADDR_Strncmp = 0x004180A6;

typedef int (__cdecl* strncmp_fn)(const char*, const char*, size_t);
static strncmp_fn orig_strncmp = nullptr;

static bool g_active = false;
static volatile LONG g_calls = 0;

// The arithmetic on its own, so the self-test exercises the same code the hook
// runs rather than a second copy that could drift from it.
int Compare(const char* s1, const char* s2, size_t n) {
    const unsigned char* a = (const unsigned char*)s1;
    const unsigned char* b = (const unsigned char*)s2;
    size_t i = 0;

    // Blocks, while there are at least sixteen bytes left to compare. The page
    // arithmetic lives only in here: an earlier version computed it once per
    // byte in the tail as well, which made short comparisons - the common shape
    // for a name or a token - twice as slow as the byte loop it replaced. The
    // tail below is now a plain byte loop with none of it.
    while (n - i >= 16) {
        const unsigned char* p1 = a + i;
        const unsigned char* p2 = b + i;

        // Sixteen bytes must fit inside the current 4 KB page for both, or the
        // load could touch a page the original would never have read.
        if (((uintptr_t)p1 & 0xFFFu) <= 0xFF0u && ((uintptr_t)p2 & 0xFFFu) <= 0xFF0u) {
            __m128i va = _mm_loadu_si128((const __m128i*)p1);
            __m128i vb = _mm_loadu_si128((const __m128i*)p2);
            __m128i eq = _mm_cmpeq_epi8(va, vb);
            __m128i z  = _mm_cmpeq_epi8(va, _mm_setzero_si128());

            unsigned stop = ((~(unsigned)_mm_movemask_epi8(eq)) |
                              (unsigned)_mm_movemask_epi8(z)) & 0xFFFFu;
            if (stop) {
                unsigned long k;
                _BitScanForward(&k, stop);
                return (int)(unsigned)p1[k] - (int)(unsigned)p2[k];
            }
            i += 16;
            continue;
        }

        // Straddling a page edge: step a byte and try again, rather than giving
        // up on blocks for the rest of a long string.
        unsigned c1 = p1[0], c2 = p2[0];
        if (c1 == 0 || c1 != c2) return (int)c1 - (int)c2;
        ++i;
    }

    // Fewer than sixteen left. Exactly what the original does.
    for (; i < n; ++i) {
        unsigned c1 = a[i], c2 = b[i];
        if (c1 == 0 || c1 != c2) return (int)c1 - (int)c2;
    }
    return 0;
}

// Set at init when the A/B harness names this module. This hook runs tens of
// millions of times a session, so a fraction of a nanosecond either way is
// real time - and whether it is faster than what it replaced has never been
// measured on a live client, only in a standalone harness.
static bool g_abSubject = false;

static int __cdecl Hooked_StrncmpBody(const char* s1, const char* s2, size_t n) {
    ++g_calls;

    if (n == 0) return 0;

    uintptr_t a = (uintptr_t)s1, b = (uintptr_t)s2;
    if (a > 0x10000 && a < 0xFFE00000 && b > 0x10000 && b < 0xFFE00000) {
        __try {
            return Compare(s1, s2, n);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // A caller that would have faulted in the original faults here too;
            // hand it back so the fault happens where the client expects it.
        }
    }
    return orig_strncmp(s1, s2, n);
}

// The detour proper, split from the body so the harness can time the call on
// both sides. One branch on a false global when no test names this module.
static int __cdecl Hooked_Strncmp(const char* s1, const char* s2, size_t n) {
    if (!g_abSubject) return Hooked_StrncmpBody(s1, s2, n);
    unsigned long long abTick = AbTest::TickIn();
    // `int r`, not `static int r`. A function-local static is initialised once,
    // so every call after the first would have returned the first comparison's
    // answer - on a function the client uses tens of millions of times a session.
    int r = AbTest::StandAside() ? orig_strncmp(s1, s2, n)
                                 : Hooked_StrncmpBody(s1, s2, n);
    AbTest::TickOut(abTick);
    return r;
}

// Run ours against the client's own strncmp, on the client's own code, before
// replacing it. Covers every length up to a block and a half, both alignments,
// equal strings, single-byte differences at every position, embedded NULs, and
// high-bit bytes - which is where a signed-versus-unsigned mistake in the return
// value would show.
static bool SelfTest() {
    strncmp_fn original = (strncmp_fn)ADDR_Strncmp;

    char bufA[128], bufB[128];
    unsigned seed = 0xB16B00B5u;
    int mismatches = 0;

    for (int iter = 0; iter < 20000; ++iter) {
        size_t n = (size_t)(iter % 40);
        int offA = iter % 7;
        int offB = (iter / 7) % 7;

        for (int i = 0; i < 128; ++i) {
            seed = seed * 1103515245u + 12345u;
            // A mix of printable, high-bit and NUL so both the stop condition
            // and the sign of the result are exercised.
            unsigned char c = (unsigned char)(seed >> 16);
            bufA[i] = (char)((iter & 1) ? c : (char)('a' + (c % 4)));
            bufB[i] = bufA[i];
        }
        // Perturb one byte often, and leave the strings identical sometimes.
        if ((iter % 3) != 0) {
            seed = seed * 1103515245u + 12345u;
            int at = (int)((seed >> 8) % 60);
            seed = seed * 1103515245u + 12345u;
            bufB[at] = (char)(unsigned char)(seed >> 16);
        }
        bufA[100] = 0;
        bufB[100] = 0;

        const char* pa = bufA + offA;
        const char* pb = bufB + offB;

        int theirs, ours;
        __try {
            theirs = original(pa, pb, n);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[StrncmpSSE2] Self-test: the client's routine faulted - not hooking");
            return false;
        }
        ours = Compare(pa, pb, n);

        // The sign and zero-ness are what every caller uses; the exact magnitude
        // is also compared because the original returns the byte difference and
        // some callers do subtract-and-branch on it.
        if (theirs != ours) ++mismatches;
    }

    if (mismatches != 0) {
        Log("[StrncmpSSE2] Self-test FAILED: %d of 20000 cases differed from the "
            "client - not hooking", mismatches);
        return false;
    }
    Log("[StrncmpSSE2] Self-test passed 20000 cases against the client's own routine");
    return true;
}

bool Init() {
    if (!Config::g_settings.OptStrncmpSse2) {
        Log("[StrncmpSSE2] DISABLED via configuration");
        return true;
    }

    if (!SelfTest()) return false;

    if (WineSafe_CreateHook((void*)ADDR_Strncmp, (void*)Hooked_Strncmp,
                            (void**)&orig_strncmp) != MH_OK ||
        WO_EnableHook((void*)ADDR_Strncmp) != MH_OK) {
        Log("[StrncmpSSE2] Hook FAILED at 0x%08X", (unsigned)ADDR_Strncmp);
        return false;
    }

    g_active = true;
    g_abSubject = AbTest::IsSubject("StrncmpSse2", &g_abSubject);
    if (g_abSubject) {
        Log("[StrncmpSSE2] under A/B test: it alternates on and off in stints and "
            "AbTest reports the cost of the call each way. At 268 million calls in "
            "a measured session, a fraction of a nanosecond either way is real "
            "time, and nothing has ever compared the two on a live client.");
    }
    CrashDumper::RegisterFeature("StrncmpSse2");
    Log("[StrncmpSSE2] ACTIVE - strncmp at 0x%08X (SSE2, 16 bytes per compare, "
        "1.55%% of executing time in a tester profile)", (unsigned)ADDR_Strncmp);
    return true;
}

void LogStats() {
    if (!g_active) return;
    Log("[StrncmpSSE2] %ld calls", g_calls);
}

void Shutdown() {
    if (!g_active) return;
    g_active = false;
    MH_DisableHook((void*)ADDR_Strncmp);
}

} // namespace StrncmpSse2
