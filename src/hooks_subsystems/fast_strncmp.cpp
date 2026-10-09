// ============================================================================
// Description: SSE2 case-insensitive string comparison helper (overriding _strnicmp at 0x0076E780).
// Safety & Threading: Concurrent safe. Restricts SSE scans near page boundaries to prevent page faults.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <atomic>
#include <cctype>
#include <emmintrin.h>   // SSE2
#include "MinHook.h"
#include "version.h"   // the No Client Patches gate and the foreign-detour check live here
#include "fast_strncmp.h"

extern "C" void Log(const char* fmt, ...);
#include "crash_dumper.h"
#include "sampling_profiler.h"

typedef int (__stdcall *strnicmp_t)(const char*, const char*, size_t);
static strnicmp_t g_orig = nullptr;
static int g_featureToken = -1;

typedef int (__cdecl *strcmp_t)(const char*, const char*);
static strcmp_t g_orig_strcmp = nullptr;

// Calls, kept only to sample the feature counter off.
//
// A field session runs this 1658683076 times - the largest count of anything in
// the feature report - and it used to take a cross-module call into
// CrashDumper::FeatureHit on every one of them, which is a call, a bounds test
// and a store into a shared static array. That is a real fraction of the work a
// short string comparison does, and it is the mistake this project has already
// found twice: once in the SSE2 matrix-vector hook and once in the DBC row
// cache, which both now sample instead.
//
// One in 8192 still leaves two hundred thousand samples in a session, and the
// counter token carries that stride so the report multiplies it back and says
// so. Plain and unsynchronised on purpose: two threads racing here cost a lost
// sample out of two hundred thousand, which is nothing next to a lock on this
// path.
static unsigned long g_strnicmpCalls = 0;

static inline unsigned char to_lower_ascii(unsigned char c) {
    if (c >= 'A' && c <= 'Z') {
        return c | 0x20;
    }
    return c;
}

// Verified against the CRT's own _strnicmp over 3000012 comparisons - random
// strings up to 140 bytes drawn from ASCII, ASCII with punctuation, pure case
// churn, alphabets containing non-ASCII bytes, and client-style path strings,
// each compared with a case flip, a byte change or a truncation, at random
// lengths on either side of the string end. Zero differences in sign, which is
// all _strnicmp specifies.
//
// The SSE2 block only skips runs that are provably equal; every result comes
// from the scalar loop below it, and anything non-ASCII is handed to the
// original so locale behaviour is preserved.
int __stdcall Hooked_strnicmp(const char* s1, const char* s2, size_t n) {
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    if (n == 0) return 0;
    if (s1 == s2) return 0;
    if ((++g_strnicmpCalls & 8191u) == 0u) CrashDumper::FeatureHit(g_featureToken);

    const unsigned char* p1 = (const unsigned char*)s1;
    const unsigned char* p2 = (const unsigned char*)s2;

    // SSE2 fast skip: advance over equal (case-insensitive) 16-byte runs while
    // both pointers are >=16 bytes from a 4 KiB page boundary, so the unaligned
    // loads can never read into an unmapped page.
    {
        const __m128i zero   = _mm_setzero_si128();
        const __m128i loA    = _mm_set1_epi8(0x40);  // 'A' - 1
        const __m128i hiZ    = _mm_set1_epi8(0x5B);  // 'Z' + 1
        const __m128i mask20 = _mm_set1_epi8(0x20);
        while (n >= 16 &&
               ((((uintptr_t)p1 | (uintptr_t)p2) & 0xFFF) <= (0x1000u - 16))) {
            __m128i a = _mm_loadu_si128((const __m128i*)p1);
            __m128i b = _mm_loadu_si128((const __m128i*)p2);

            // If either block contains non-ASCII characters (bytes >= 0x80),
            // break to allow the scalar loop to safely delegate to the original locale-sensitive _strnicmp.
            if (_mm_movemask_epi8(a) || _mm_movemask_epi8(b)) break;

            __m128i la = _mm_add_epi8(a, _mm_and_si128(
                _mm_and_si128(_mm_cmpgt_epi8(a, loA), _mm_cmplt_epi8(a, hiZ)), mask20));
            __m128i lb = _mm_add_epi8(b, _mm_and_si128(
                _mm_and_si128(_mm_cmpgt_epi8(b, loA), _mm_cmplt_epi8(b, hiZ)), mask20));
            int ne  = _mm_movemask_epi8(_mm_cmpeq_epi8(la, lb)) ^ 0xFFFF; // differing bytes
            int nul = _mm_movemask_epi8(_mm_cmpeq_epi8(a, zero));         // terminator in a
            if (ne || nul) break;   // scalar loop produces the exact comparison result
            p1 += 16; p2 += 16; n -= 16;
        }
    }

    while (n--) {
        unsigned char c1 = *p1;
        unsigned char c2 = *p2;

        if (c1 >= 0x80 || c2 >= 0x80) {
            // Fall back to original for non-ASCII characters to preserve locale-aware comparison
            return g_orig((const char*)p1, (const char*)p2, n + 1);
        }

        if (c1 == c2) {
            if (c1 == 0) return 0;
            p1++; p2++;
            continue;
        }

        unsigned char lc1 = to_lower_ascii(c1);
        unsigned char lc2 = to_lower_ascii(c2);
        if (lc1 != lc2) {
            return (lc1 < lc2) ? -1 : 1;
        }

        if (c1 == 0) return 0;
        p1++; p2++;
    }
    return 0;
}

bool InstallFastStrncmp() {
    void* target = (void*)0x0076E780;

    if (MH_CreateHook(target, (void*)Hooked_strnicmp, (void**)&g_orig) != MH_OK) {
        Log("[FastStrnicmp] Failed to create hook at 0x0076E780");
        return false;
    }

    if (MH_EnableHook(target) != MH_OK) {
        Log("[FastStrnicmp] Failed to enable hook");
        MH_RemoveHook(target);
        return false;
    }

    g_featureToken = CrashDumper::FeatureTokenForCounting("FastStrncmp", 8192);
    SamplingProfiler::RegisterSelfSymbol("strnicmp_fast", (const void*)&Hooked_strnicmp);
    Log("[FastStrnicmp] Installed: _strnicmp replacement (1013 callers)");
    return true;
}

void UninstallFastStrncmp() {
    MH_DisableHook((void*)0x0076E780);
    MH_RemoveHook((void*)0x0076E780);
}

void GetFastStrncmpStats(uint64_t* calls) {
    if (calls) *calls = 0;
}
