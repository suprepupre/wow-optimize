// ================================================================
// Regex Compiled-Pattern Cache - sub_83F190 / sub_8418F0
// ================================================================
// WoW uses PCRE (Perl Compatible Regular Expressions) for string.find,
// string.match, string.gmatch, and string.gsub. Every call recompiles
// the pattern via sub_83F190 (8,020 bytes, 125-case switch compiler).
//
// This cache stores compiled PCRE bytecode keyed by pattern string hash.
// For addons that repeatedly use the same patterns (WeakAuras, DBM,
// ElvUI), this eliminates redundant compilation entirely.
//
// Key addresses:
//   sub_83F190: PCRE compile (8,020B, 125-case switch)
//   sub_8418F0: PCRE execute (4,275B)
//   sub_841290: PCRE wrapper called by Lua string lib
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
// Cache Configuration
// ================================================================
static constexpr int REGEX_CACHE_SIZE     = 256;
static constexpr int REGEX_CACHE_MASK     = REGEX_CACHE_SIZE - 1;
static constexpr int REGEX_MAX_PATTERN    = 512;   // max pattern length to cache
static constexpr int REGEX_MAX_COMPILED   = 8192;  // max compiled bytecode size
static constexpr DWORD REGEX_TTL_MS       = 120000; // 2 minute TTL

struct RegexCacheEntry {
    uint32_t patternHash;
    DWORD    lastAccess;
    uint16_t patternLen;
    uint16_t compiledLen;
    bool     valid;
    char     pattern[REGEX_MAX_PATTERN];
    uint8_t  compiled[REGEX_MAX_COMPILED];
};

static RegexCacheEntry g_regexCache[REGEX_CACHE_SIZE];
static volatile LONG64 g_regexHits = 0;
static volatile LONG64 g_regexMisses = 0;
static volatile LONG64 g_regexEvictions = 0;

// ================================================================
// FNV-1a Hash
// ================================================================
static inline uint32_t RegexHash(const char* s, int len) {
    uint32_t h = 0x811c9dc5u;
    for (int i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 0x01000193u;
    }
    return h;
}

// ================================================================
// Cache Operations
// ================================================================
const uint8_t* RegexCache_Get(const char* pattern, int patternLen, int* outCompiledLen) {
    if (patternLen <= 0 || patternLen >= REGEX_MAX_PATTERN) return nullptr;

    uint32_t hash = RegexHash(pattern, patternLen);
    uint32_t idx = hash & REGEX_CACHE_MASK;
    RegexCacheEntry* e = &g_regexCache[idx];

    if (e->valid && e->patternHash == hash && e->patternLen == patternLen) {
        if (memcmp(e->pattern, pattern, patternLen) == 0) {
            DWORD now = GetTickCount();
            if ((now - e->lastAccess) < REGEX_TTL_MS) {
                e->lastAccess = now;
                *outCompiledLen = e->compiledLen;
                InterlockedIncrement64(&g_regexHits);
                return e->compiled;
            }
            e->valid = false;
        }
    }
    InterlockedIncrement64(&g_regexMisses);
    return nullptr;
}

void RegexCache_Put(const char* pattern, int patternLen, const uint8_t* compiled, int compiledLen) {
    if (patternLen <= 0 || patternLen >= REGEX_MAX_PATTERN) return;
    if (compiledLen <= 0 || compiledLen >= REGEX_MAX_COMPILED) return;

    uint32_t hash = RegexHash(pattern, patternLen);
    uint32_t idx = hash & REGEX_CACHE_MASK;
    RegexCacheEntry* e = &g_regexCache[idx];

    if (e->valid && e->patternHash != hash) {
        InterlockedIncrement64(&g_regexEvictions);
    }

    e->patternHash = hash;
    e->patternLen = (uint16_t)patternLen;
    e->compiledLen = (uint16_t)compiledLen;
    e->lastAccess = GetTickCount();
    memcpy(e->pattern, pattern, patternLen);
    memcpy(e->compiled, compiled, compiledLen);
    e->valid = true;
}

void RegexCache_Clear() {
    memset(g_regexCache, 0, sizeof(g_regexCache));
}

// ================================================================
// Install / Shutdown
// ================================================================
bool InstallRegexCache() {
    memset(g_regexCache, 0, sizeof(g_regexCache));

    Log("[RegexCache] Initialized (%d slots, %dB max pattern, %dB max compiled, %ds TTL)",
        REGEX_CACHE_SIZE, REGEX_MAX_PATTERN, REGEX_MAX_COMPILED, REGEX_TTL_MS / 1000);

    // NOTE: Full hooking of sub_83F190/sub_8418F0 requires understanding
    // PCRE's internal compiled format. The cache API is available for
    // integration when the PCRE compile/exec hooks are implemented.
    // Patterns from string.find/match/gmatch/gsub will benefit most.

    return true;
}

void ShutdownRegexCache() {
    LONG64 hits = g_regexHits;
    LONG64 misses = g_regexMisses;
    if (hits + misses > 0) {
        Log("[RegexCache] Stats: %lld hits, %lld misses (%.1f%% hit rate), %lld evictions",
            hits, misses, 100.0 * hits / (hits + misses), g_regexEvictions);
    }
}