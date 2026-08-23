// ============================================================================
// Module: crt_char_fast.cpp
// Description: SSE2 vectorized replacement for legacy CRT character/string functions.
// Safety & Threading: Concurrent execution safe.
// ============================================================================

#include "crt_char_fast.h"
#include "version.h"
#include "MinHook.h"
#include "crash_dumper.h"
#include <cstdint>
#include <intrin.h>

extern "C" void Log(const char* fmt, ...);

#if !TEST_DISABLE_CRT_CHAR_SSE2

// Stats defined in dllmain.cpp
extern long g_memchrHits, g_memchrFallbacks;
extern long g_strchrHits, g_strchrFallbacks;
extern long g_strcpyHits, g_strcpyFallbacks;

// ====== memchr ======
typedef void* (__cdecl *memchr_fn)(const void*, int, size_t);
static memchr_fn orig_memchr = nullptr;

static void* __cdecl Hooked_memchr(const void* ptr, int value, size_t num) {
    CrashDumper::RecordHookCall("CRT_memchr", (uintptr_t)_ReturnAddress());
    if (!ptr || num == 0) goto fallback;
    __try {
        const unsigned char* p = (const unsigned char*)ptr;
        unsigned char c = (unsigned char)value;
        while (((uintptr_t)p & 15) && num > 0) {
            if (*p == c) { ++g_memchrHits; return (void*)p; }
            p++; num--;
        }
        if (num == 0) { ++g_memchrHits; return nullptr; }
        __m128i cmpv = _mm_set1_epi8((char)c);
        while (num >= 16) {
            __m128i v = _mm_loadu_si128((const __m128i*)p);
            int mask = _mm_movemask_epi8(_mm_cmpeq_epi8(v, cmpv));
            if (mask) {
                unsigned long idx; _BitScanForward(&idx, mask);
                ++g_memchrHits; return (void*)(p + idx);
            }
            p += 16; num -= 16;
        }
        while (num--) { if (*p == c) { ++g_memchrHits; return (void*)p; } p++; }
        ++g_memchrHits; return nullptr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
fallback:
    ++g_memchrFallbacks;
    return orig_memchr(ptr, value, num);
}

// ====== strchr ======
typedef char* (__cdecl *strchr_fn)(const char*, int);
static strchr_fn orig_strchr = nullptr;

static char* __cdecl Hooked_strchr(const char* str, int value) {
    if (!str) goto fallback;
    __try {
        unsigned char c = (unsigned char)value;
        const char* p = str;
        uintptr_t addr = (uintptr_t)p;
        size_t prefix = (16 - (addr & 15)) & 15;
        for (size_t i = 0; i < prefix; i++) {
            if ((unsigned char)*p == c) { ++g_strchrHits; return (char*)p; }
            if (*p == '\0') {
                ++g_strchrHits;
                return (c == 0) ? (char*)p : nullptr;
            }
            p++;
        }
        
        __m128i cmpv = _mm_set1_epi8((char)c);
        __m128i zero = _mm_setzero_si128();
        for (;;) {
            __m128i v = _mm_load_si128((const __m128i*)p);
            __m128i eq = _mm_cmpeq_epi8(v, cmpv);
            __m128i end = _mm_cmpeq_epi8(v, zero);
            int mask = _mm_movemask_epi8(_mm_or_si128(eq, end));
            if (mask) {
                unsigned long idx; _BitScanForward(&idx, mask);
                unsigned char found = (unsigned char)p[idx];
                ++g_strchrHits;
                if (found == c) return (char*)(p + idx);
                return (c == 0 && found == 0) ? (char*)(p + idx) : nullptr;
            }
            p += 16;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
fallback:
    ++g_strchrFallbacks;
    return orig_strchr(str, value);
}

// ====== strcpy ======
typedef char* (__cdecl *strcpy_fn)(char*, const char*);
static strcpy_fn orig_strcpy = nullptr;

static char* __cdecl Hooked_strcpy(char* dst, const char* src) {
    if (!dst || !src) goto fallback;
    __try {
        char* ret = dst;
        const __m128i zero = _mm_setzero_si128();
        for (;;) {
            // Page-boundary guard inside the loop
            if (((uintptr_t)dst & 0xFFF) > 0xFF0 || ((uintptr_t)src & 0xFFF) > 0xFF0) {
                goto fallback;
            }
            
            __m128i v = _mm_loadu_si128((const __m128i*)src);
            int mask = _mm_movemask_epi8(_mm_cmpeq_epi8(v, zero));
            if (mask) {
                unsigned long idx;
                _BitScanForward(&idx, mask);
                // Safe copy up to the null terminator - NEVER overflow destination!
                for (unsigned long j = 0; j <= idx; j++) {
                    dst[j] = src[j];
                }
                ++g_strcpyHits;
                return ret;
            }
            _mm_storeu_si128((__m128i*)dst, v);
            src += 16; dst += 16;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
fallback:
    ++g_strcpyFallbacks;
    return orig_strcpy(dst, src);
}

// ====== strcat ======
typedef char* (__cdecl *strcat_fn)(char*, const char*);
static strcat_fn orig_strcat = nullptr;

static char* __cdecl Hooked_strcat(char* dst, const char* src) {
    if (!dst || !src) goto fallback;
    __try {
        const __m128i zero = _mm_setzero_si128();
        size_t dlen = 0;
        while (true) {
            // Page-boundary guard inside the loop
            if (((uintptr_t)(dst + dlen) & 0xFFF) > 0xFF0) {
                goto fallback;
            }
            __m128i v = _mm_loadu_si128((const __m128i*)(dst + dlen));
            int mask = _mm_movemask_epi8(_mm_cmpeq_epi8(v, zero));
            if (mask) { unsigned long idx; _BitScanForward(&idx, mask); dlen += idx; break; }
            dlen += 16;
        }
        
        char* d = dst + dlen;
        for (;;) {
            // Page-boundary guard inside the loop
            if (((uintptr_t)d & 0xFFF) > 0xFF0 || ((uintptr_t)src & 0xFFF) > 0xFF0) {
                goto fallback;
            }
            __m128i v = _mm_loadu_si128((const __m128i*)src);
            int mask = _mm_movemask_epi8(_mm_cmpeq_epi8(v, zero));
            if (mask) {
                unsigned long idx;
                _BitScanForward(&idx, mask);
                // Safe copy up to the null terminator - NEVER overflow destination!
                for (unsigned long j = 0; j <= idx; j++) {
                    d[j] = src[j];
                }
                ++g_strcpyHits;
                return dst;
            }
            _mm_storeu_si128((__m128i*)d, v);
            src += 16; d += 16;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
fallback:
    ++g_strcpyFallbacks;
    return orig_strcat(dst, src);
}

static void* g_target_memchr = nullptr;
static void* g_target_strchr = nullptr;
static void* g_target_strcpy = nullptr;
static void* g_target_strcat = nullptr;

bool InstallCrtCharSSE2() {
    HMODULE crt = GetModuleHandleA("msvcrt.dll");
    if (!crt) crt = GetModuleHandleA("ucrtbase.dll");
    if (!crt) { Log("[CrtChar] msvcrt/ucrtbase not found"); return false; }

    int ok = 0;
    auto tryHook = [&](const char* name, void* hook, void** orig, void** target) {
        void* p = GetProcAddress(crt, name);
        if (p && MH_CreateHook(p, hook, orig) == MH_OK && MH_EnableHook(p) == MH_OK) {
            *target = p;
            ok++;
        }
    };

    tryHook("memchr",  (void*)Hooked_memchr,  (void**)&orig_memchr, &g_target_memchr);
    tryHook("strchr",  (void*)Hooked_strchr,  (void**)&orig_strchr, &g_target_strchr);
    tryHook("strcpy",  (void*)Hooked_strcpy,  (void**)&orig_strcpy, &g_target_strcpy);
    tryHook("strcat",  (void*)Hooked_strcat,  (void**)&orig_strcat, &g_target_strcat);

    if (ok > 0) {
        Log("[CrtChar] Active: memchr+strchr+strcpy+strcat SSE2 (%d/4 hooked, page-boundary guarded)", ok);
        return true;
    }
    Log("[CrtChar] No hooks installed");
    return false;
}

void ShutdownCrtCharSSE2() {
    if (g_target_memchr) MH_DisableHook(g_target_memchr);
    if (g_target_strchr) MH_DisableHook(g_target_strchr);
    if (g_target_strcpy) MH_DisableHook(g_target_strcpy);
    if (g_target_strcat) MH_DisableHook(g_target_strcat);
}

#else
bool InstallCrtCharSSE2() { return false; }
void ShutdownCrtCharSSE2() {}
#endif