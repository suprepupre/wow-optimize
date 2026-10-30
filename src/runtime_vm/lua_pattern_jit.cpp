// ============================================================================
// Description: Micro-JIT pattern matcher for Lua strings.
// ============================================================================

#include "lua_pattern_jit.h"
#include "version.h"
#include <cstring>
#include <string>
#include <vector>

extern "C" void Log(const char* fmt, ...);

namespace LuaPatternJit {

typedef const char* (__cdecl *fn_lua_tolstring)(lua_State* L, int index, size_t* len);
typedef double      (__cdecl *fn_lua_tonumber)(lua_State* L, int index);
typedef int         (__cdecl *fn_lua_gettop)(lua_State* L);
typedef int         (__cdecl *fn_lua_type)(lua_State* L, int index);
typedef void        (__cdecl *fn_lua_pushnumber)(lua_State* L, double n);
typedef void        (__cdecl *fn_lua_pushstring)(lua_State* L, const char* s);
typedef void        (__cdecl *fn_lua_pushlstring)(lua_State* L, const char* s, size_t len);
typedef void        (__cdecl *fn_lua_pushnil)(lua_State* L);
typedef void        (__cdecl *fn_lua_settop)(lua_State* L, int index);

static fn_lua_tolstring   lua_tolstring_   = (fn_lua_tolstring)0x0084E0E0;
static fn_lua_tonumber    lua_tonumber_    = (fn_lua_tonumber)0x0084E030;
static fn_lua_gettop      lua_gettop_      = (fn_lua_gettop)0x0084DBD0;
static fn_lua_type        lua_type_        = (fn_lua_type)0x0084DEB0;
static fn_lua_pushnumber  lua_pushnumber_  = (fn_lua_pushnumber)0x0084E2A0;
static fn_lua_pushstring  lua_pushstring_  = (fn_lua_pushstring)0x0084E350;
static fn_lua_pushlstring lua_pushlstring_ = (fn_lua_pushlstring)0x0084E300;
static fn_lua_pushnil     lua_pushnil_     = (fn_lua_pushnil)0x0084E280;
static fn_lua_settop      lua_settop_      = (fn_lua_settop)0x0084DBF0;

static lua_CFunction_t s_origMatch = nullptr;
static lua_CFunction_t s_origFind  = nullptr;

static volatile LONG g_jitHits          = 0;
static volatile LONG g_jitMisses        = 0;
static volatile LONG g_verifiedCount    = 0;
static volatile LONG g_discrepancies    = 0;
static const LONG    kMaxVerifyCount    = 5000;

enum class JitKind : uint8_t {
    kUnsupported = 0,
    kPlainLiteral,
    kDigits,           // (%d+) unanchored, or with prefix
    kDigitsAnchoredStart, // ^(%d+)
    kDigitsAnchoredEnd,   // (%d+)$
    kTwoNumbers,       // (%d+)<sep>(%d+)
    kDelim,            // ([^<c>]+) or ^([^<c>]+)
    kDelimTwo,         // ([^<c1>]+)<sep>([^<c2>]+)
    kWord,             // (%w+) or ^(%w+)
    kAlpha,            // (%a+) or ^(%a+)
    kHex,              // (%x+) or 0x(%x+) or ^0x(%x+)
    kTrimBoth,         // ^%s*(.-)%s*$
    kTrimRight,        // ^(.-)%s*$
    kTrimLeft,         // ^%s*(.*)$
    kPrefixRemainder,  // ^<prefix>(.*)$ or ^<prefix>(.-)$
    kBracketRemainder  // ^%[(.*)%]$
};

struct CompiledPattern {
    uint64_t hash;
    uint16_t pLen;
    JitKind  kind;
    bool     anchoredStart;
    bool     anchoredEnd;
    char     delimiter;
    char     sep;
    uint8_t  prefixLen;
    char     prefix[32];
    char     patternStr[64];
};

static CompiledPattern s_cache[256] = {};

static uint64_t Fnv1a(const char* s, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; ++i) {
        h ^= (unsigned char)s[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static inline bool IsMagicChar(char c) {
    switch (c) {
        case '^': case '$': case '(': case ')':
        case '%': case '.': case '[': case ']':
        case '*': case '+': case '-': case '?':
            return true;
        default:
            return false;
    }
}

static inline bool IsPlainLiteral(const char* p, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (IsMagicChar(p[i])) return false;
    }
    return true;
}

static inline bool IsDigit(char c) {
    return c >= '0' && c <= '9';
}

static inline bool IsAlpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static inline bool IsWord(char c) {
    return IsAlpha(c) || IsDigit(c) || c == '_';
}

static inline bool IsHex(char c) {
    return IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static inline bool IsSpace(char c) {
    return (unsigned char)c <= 32;
}

static CompiledPattern CompilePattern(const char* p, size_t pLen) {
    CompiledPattern cp = {};
    cp.pLen = (uint16_t)pLen;
    cp.hash = Fnv1a(p, pLen);
    if (pLen < sizeof(cp.patternStr)) {
        memcpy(cp.patternStr, p, pLen);
        cp.patternStr[pLen] = '\0';
    }

    if (pLen == 0) {
        cp.kind = JitKind::kPlainLiteral;
        return cp;
    }

    // 1. Plain literal (no magic characters)
    if (IsPlainLiteral(p, pLen)) {
        cp.kind = JitKind::kPlainLiteral;
        return cp;
    }

    // 2. Trim patterns
    if (pLen == 13 && memcmp(p, "^%s*(.-)%s*$", 13) == 0) {
        cp.kind = JitKind::kTrimBoth;
        return cp;
    }
    if (pLen == 9 && memcmp(p, "^(.-)%s*$", 9) == 0) {
        cp.kind = JitKind::kTrimRight;
        return cp;
    }
    if (pLen == 8 && memcmp(p, "^%s*(.*)$", 8) == 0) {
        cp.kind = JitKind::kTrimLeft;
        return cp;
    }
    if (pLen == 7 && memcmp(p, "^%[(.*)%]$", 7) == 0) {
        cp.kind = JitKind::kBracketRemainder;
        return cp;
    }

    // 3. Hex pattern
    if (pLen == 5 && memcmp(p, "(%x+)", 5) == 0) {
        cp.kind = JitKind::kHex;
        return cp;
    }
    if (pLen == 7 && memcmp(p, "0x(%x+)", 7) == 0) {
        cp.kind = JitKind::kHex;
        cp.prefixLen = 2;
        memcpy(cp.prefix, "0x", 2);
        return cp;
    }
    if (pLen == 8 && memcmp(p, "^0x(%x+)", 8) == 0) {
        cp.kind = JitKind::kHex;
        cp.anchoredStart = true;
        cp.prefixLen = 2;
        memcpy(cp.prefix, "0x", 2);
        return cp;
    }

    // 4. Alpha & Word patterns
    if (pLen == 5 && memcmp(p, "(%a+)", 5) == 0) {
        cp.kind = JitKind::kAlpha;
        return cp;
    }
    if (pLen == 6 && memcmp(p, "^(%a+)", 6) == 0) {
        cp.kind = JitKind::kAlpha;
        cp.anchoredStart = true;
        return cp;
    }
    if (pLen == 5 && memcmp(p, "(%w+)", 5) == 0) {
        cp.kind = JitKind::kWord;
        return cp;
    }
    if (pLen == 6 && memcmp(p, "^(%w+)", 6) == 0) {
        cp.kind = JitKind::kWord;
        cp.anchoredStart = true;
        return cp;
    }

    // 5. Delimiter token patterns: ([^<c>]+) or ^([^<c>]+)
    if (pLen == 7 && p[0] == '(' && p[1] == '[' && p[2] == '^' && p[4] == ']' && p[5] == '+' && p[6] == ')') {
        cp.kind = JitKind::kDelim;
        cp.delimiter = p[3];
        return cp;
    }
    if (pLen == 8 && p[0] == '^' && p[1] == '(' && p[2] == '[' && p[3] == '^' && p[5] == ']' && p[6] == '+' && p[7] == ')') {
        cp.kind = JitKind::kDelim;
        cp.anchoredStart = true;
        cp.delimiter = p[4];
        return cp;
    }
    // Delimiter for %s: ([^%s]+) or ^([^%s]+)
    if (pLen == 9 && memcmp(p, "([^%s]+)", 8) == 0) {
        cp.kind = JitKind::kDelim;
        cp.delimiter = ' '; // special space token
        return cp;
    }
    if (pLen == 10 && memcmp(p, "^([^%s]+)", 9) == 0) {
        cp.kind = JitKind::kDelim;
        cp.anchoredStart = true;
        cp.delimiter = ' ';
        return cp;
    }

    // 6. Two numbers: (%d+)<sep>(%d+)
    if (pLen == 11 && memcmp(p, "(%d+)", 5) == 0 && memcmp(p + 6, "(%d+)", 5) == 0) {
        cp.kind = JitKind::kTwoNumbers;
        cp.sep = p[5];
        return cp;
    }
    // Escaped separators: (%d+)%.(%d+) or (%d+)%-(%d+)
    if (pLen == 12 && memcmp(p, "(%d+)%", 6) == 0 && memcmp(p + 7, "(%d+)", 5) == 0) {
        cp.kind = JitKind::kTwoNumbers;
        cp.sep = p[6]; // '.' or '-'
        return cp;
    }

    // 7. Digits: (%d+) with optional anchors and literal prefix
    if (pLen == 5 && memcmp(p, "(%d+)", 5) == 0) {
        cp.kind = JitKind::kDigits;
        return cp;
    }
    if (pLen == 6 && memcmp(p, "^(%d+)", 6) == 0) {
        cp.kind = JitKind::kDigitsAnchoredStart;
        return cp;
    }
    if (pLen == 6 && memcmp(p, "(%d+)$", 6) == 0) {
        cp.kind = JitKind::kDigitsAnchoredEnd;
        return cp;
    }

    // Prefix + (%d+), e.g. "Rank (%d+)" or "^Rank (%d+)"
    if (pLen >= 7 && memcmp(p + pLen - 5, "(%d+)", 5) == 0) {
        size_t prefLen = pLen - 5;
        bool anchored = (p[0] == '^');
        size_t prefStart = anchored ? 1 : 0;
        size_t actualPrefLen = prefLen - prefStart;
        if (actualPrefLen < sizeof(cp.prefix) && IsPlainLiteral(p + prefStart, actualPrefLen)) {
            cp.kind = anchored ? JitKind::kDigitsAnchoredStart : JitKind::kDigits;
            cp.anchoredStart = anchored;
            cp.prefixLen = (uint8_t)actualPrefLen;
            memcpy(cp.prefix, p + prefStart, actualPrefLen);
            return cp;
        }
    }

    // 8. Prefix remainder: ^<prefix>(.*)$ or ^<prefix>(.-)$
    if (pLen >= 6 && p[0] == '^' &&
        ((memcmp(p + pLen - 5, "(.*)$", 5) == 0) || (memcmp(p + pLen - 5, "(.-)$", 5) == 0))) {
        size_t prefLen = pLen - 6; // exclude '^' and '(.*)$'
        if (prefLen < sizeof(cp.prefix) && IsPlainLiteral(p + 1, prefLen)) {
            cp.kind = JitKind::kPrefixRemainder;
            cp.anchoredStart = true;
            cp.prefixLen = (uint8_t)prefLen;
            memcpy(cp.prefix, p + 1, prefLen);
            return cp;
        }
    }

    cp.kind = JitKind::kUnsupported;
    return cp;
}

static inline const CompiledPattern* GetCompiled(const char* p, size_t pLen) {
    uint64_t h = Fnv1a(p, pLen);
    CompiledPattern& e = s_cache[h & 0xFF];
    if (e.hash == h && e.pLen == pLen && memcmp(e.patternStr, p, pLen) == 0) {
        return &e;
    }
    e = CompilePattern(p, pLen);
    return &e;
}

// ───────────────────────────────────────────────────────────────
//  Execution Engines
// ───────────────────────────────────────────────────────────────

static int MatchDigits(lua_State* L, const char* s, size_t sLen, const CompiledPattern& cp, int init) {
    if (init < 1) init = 1;
    if (init > (int)sLen) { lua_pushnil_(L); return 1; }

    const char* cur = s + (init - 1);
    const char* end = s + sLen;

    if (cp.prefixLen > 0) {
        if (cp.anchoredStart) {
            if (init != 1 || (size_t)(end - cur) < cp.prefixLen || memcmp(cur, cp.prefix, cp.prefixLen) != 0) {
                lua_pushnil_(L);
                return 1;
            }
            cur += cp.prefixLen;
        } else {
            // Find prefix in cur
            const char* found = (const char*)strstr(cur, cp.prefix);
            if (!found) { lua_pushnil_(L); return 1; }
            cur = found + cp.prefixLen;
        }
    } else if (cp.anchoredStart) {
        if (init != 1) { lua_pushnil_(L); return 1; }
    }

    if (cp.kind == JitKind::kDigitsAnchoredEnd) {
        // Must end with digits at end of string
        if (cur >= end || !IsDigit(*(end - 1))) {
            lua_pushnil_(L);
            return 1;
        }
        const char* dStart = end - 1;
        while (dStart > cur && IsDigit(*(dStart - 1))) {
            dStart--;
        }
        lua_pushlstring_(L, dStart, (size_t)(end - dStart));
        return 1;
    }

    // Scan forward for first digit
    if (!cp.anchoredStart) {
        while (cur < end && !IsDigit(*cur)) {
            cur++;
        }
    }

    if (cur >= end || !IsDigit(*cur)) {
        lua_pushnil_(L);
        return 1;
    }

    const char* dStart = cur;
    while (cur < end && IsDigit(*cur)) {
        cur++;
    }

    lua_pushlstring_(L, dStart, (size_t)(cur - dStart));
    return 1;
}

static int MatchTwoNumbers(lua_State* L, const char* s, size_t sLen, const CompiledPattern& cp, int init) {
    if (init < 1) init = 1;
    if (init > (int)sLen) { lua_pushnil_(L); return 1; }

    const char* cur = s + (init - 1);
    const char* end = s + sLen;

    // Find first digit
    while (cur < end && !IsDigit(*cur)) cur++;
    if (cur >= end) { lua_pushnil_(L); return 1; }

    const char* n1Start = cur;
    while (cur < end && IsDigit(*cur)) cur++;
    size_t n1Len = (size_t)(cur - n1Start);

    // Skip separator
    if (cur >= end || *cur != cp.sep) { lua_pushnil_(L); return 1; }
    cur++; // skip sep

    // Check for second number immediately
    if (cur >= end || !IsDigit(*cur)) { lua_pushnil_(L); return 1; }
    const char* n2Start = cur;
    while (cur < end && IsDigit(*cur)) cur++;
    size_t n2Len = (size_t)(cur - n2Start);

    lua_pushlstring_(L, n1Start, n1Len);
    lua_pushlstring_(L, n2Start, n2Len);
    return 2;
}

static int MatchDelim(lua_State* L, const char* s, size_t sLen, const CompiledPattern& cp, int init) {
    if (init < 1) init = 1;
    if (init > (int)sLen) { lua_pushnil_(L); return 1; }

    const char* cur = s + (init - 1);
    const char* end = s + sLen;

    if (cp.anchoredStart && init != 1) { lua_pushnil_(L); return 1; }

    bool isSpaceDelim = (cp.delimiter == ' ');

    // If unanchored, skip leading delimiters to find token start
    if (!cp.anchoredStart) {
        if (isSpaceDelim) {
            while (cur < end && IsSpace(*cur)) cur++;
        } else {
            while (cur < end && *cur == cp.delimiter) cur++;
        }
    }

    if (cur >= end) { lua_pushnil_(L); return 1; }

    // Check that first char is NOT delimiter
    if (isSpaceDelim ? IsSpace(*cur) : (*cur == cp.delimiter)) {
        lua_pushnil_(L);
        return 1;
    }

    const char* tokStart = cur;
    if (isSpaceDelim) {
        while (cur < end && !IsSpace(*cur)) cur++;
    } else {
        const char* nextDelim = (const char*)memchr(cur, cp.delimiter, (size_t)(end - cur));
        cur = nextDelim ? nextDelim : end;
    }

    lua_pushlstring_(L, tokStart, (size_t)(cur - tokStart));
    return 1;
}

static int MatchWordOrAlpha(lua_State* L, const char* s, size_t sLen, const CompiledPattern& cp, int init) {
    if (init < 1) init = 1;
    if (init > (int)sLen) { lua_pushnil_(L); return 1; }

    const char* cur = s + (init - 1);
    const char* end = s + sLen;

    if (cp.anchoredStart && init != 1) { lua_pushnil_(L); return 1; }

    bool isAlpha = (cp.kind == JitKind::kAlpha);
    auto checkFn = isAlpha ? IsAlpha : IsWord;

    if (!cp.anchoredStart) {
        while (cur < end && !checkFn(*cur)) cur++;
    }

    if (cur >= end || !checkFn(*cur)) {
        lua_pushnil_(L);
        return 1;
    }

    const char* start = cur;
    while (cur < end && checkFn(*cur)) cur++;

    lua_pushlstring_(L, start, (size_t)(cur - start));
    return 1;
}

static int MatchHex(lua_State* L, const char* s, size_t sLen, const CompiledPattern& cp, int init) {
    if (init < 1) init = 1;
    if (init > (int)sLen) { lua_pushnil_(L); return 1; }

    const char* cur = s + (init - 1);
    const char* end = s + sLen;

    if (cp.prefixLen > 0) {
        if (cp.anchoredStart) {
            if (init != 1 || (size_t)(end - cur) < cp.prefixLen || memcmp(cur, cp.prefix, cp.prefixLen) != 0) {
                lua_pushnil_(L);
                return 1;
            }
            cur += cp.prefixLen;
        } else {
            const char* found = (const char*)strstr(cur, "0x");
            if (!found) { lua_pushnil_(L); return 1; }
            cur = found + 2;
        }
    } else if (cp.anchoredStart && init != 1) {
        lua_pushnil_(L);
        return 1;
    }

    if (!cp.anchoredStart && cp.prefixLen == 0) {
        while (cur < end && !IsHex(*cur)) cur++;
    }

    if (cur >= end || !IsHex(*cur)) {
        lua_pushnil_(L);
        return 1;
    }

    const char* start = cur;
    while (cur < end && IsHex(*cur)) cur++;

    lua_pushlstring_(L, start, (size_t)(cur - start));
    return 1;
}

static int MatchTrim(lua_State* L, const char* s, size_t sLen, const CompiledPattern& cp, int init) {
    if (init != 1) { lua_pushnil_(L); return 1; }

    const char* start = s;
    const char* end = s + sLen;

    if (cp.kind == JitKind::kTrimBoth || cp.kind == JitKind::kTrimLeft) {
        while (start < end && IsSpace(*start)) start++;
    }

    if (cp.kind == JitKind::kTrimBoth || cp.kind == JitKind::kTrimRight) {
        while (end > start && IsSpace(*(end - 1))) end--;
    }

    lua_pushlstring_(L, start, (size_t)(end - start));
    return 1;
}

static int MatchPrefixRemainder(lua_State* L, const char* s, size_t sLen, const CompiledPattern& cp, int init) {
    if (init != 1 || sLen < cp.prefixLen) { lua_pushnil_(L); return 1; }
    if (memcmp(s, cp.prefix, cp.prefixLen) != 0) { lua_pushnil_(L); return 1; }

    lua_pushlstring_(L, s + cp.prefixLen, sLen - cp.prefixLen);
    return 1;
}

static int MatchBracketRemainder(lua_State* L, const char* s, size_t sLen, int init) {
    if (init != 1 || sLen < 2) { lua_pushnil_(L); return 1; }
    if (s[0] != '[' || s[sLen - 1] != ']') { lua_pushnil_(L); return 1; }

    lua_pushlstring_(L, s + 1, sLen - 2);
    return 1;
}

static int MatchPlain(lua_State* L, const char* s, size_t sLen, const CompiledPattern& cp, int init) {
    if (init < 1) init = 1;
    if (cp.pLen == 0) {
        lua_pushlstring_(L, "", 0);
        return 1;
    }
    if (init > (int)sLen) { lua_pushnil_(L); return 1; }

    size_t searchLen = sLen - (size_t)(init - 1);
    if (cp.pLen > searchLen) { lua_pushnil_(L); return 1; }

    const char* searchStart = s + (init - 1);
    const char* found = nullptr;
    if (cp.pLen == 1) {
        found = (const char*)memchr(searchStart, cp.patternStr[0], searchLen);
    } else {
        found = (const char*)strstr(searchStart, cp.patternStr);
    }

    if (!found) {
        lua_pushnil_(L);
        return 1;
    }

    lua_pushlstring_(L, found, cp.pLen);
    return 1;
}

static int FastMatchImpl(lua_State* L, const char* s, size_t sLen, const CompiledPattern& cp, int init) {
    switch (cp.kind) {
        case JitKind::kDigits:
        case JitKind::kDigitsAnchoredStart:
        case JitKind::kDigitsAnchoredEnd:
            return MatchDigits(L, s, sLen, cp, init);

        case JitKind::kTwoNumbers:
            return MatchTwoNumbers(L, s, sLen, cp, init);

        case JitKind::kDelim:
            return MatchDelim(L, s, sLen, cp, init);

        case JitKind::kWord:
        case JitKind::kAlpha:
            return MatchWordOrAlpha(L, s, sLen, cp, init);

        case JitKind::kHex:
            return MatchHex(L, s, sLen, cp, init);

        case JitKind::kTrimBoth:
        case JitKind::kTrimRight:
        case JitKind::kTrimLeft:
            return MatchTrim(L, s, sLen, cp, init);

        case JitKind::kPrefixRemainder:
            return MatchPrefixRemainder(L, s, sLen, cp, init);

        case JitKind::kBracketRemainder:
            return MatchBracketRemainder(L, s, sLen, init);

        case JitKind::kPlainLiteral:
            return MatchPlain(L, s, sLen, cp, init);

        default:
            return -1;
    }
}

// ───────────────────────────────────────────────────────────────
//  Public Entry Points & Verification Harness
// ───────────────────────────────────────────────────────────────

void SetOrigFuncs(lua_CFunction_t origMatch, lua_CFunction_t origFind) {
    s_origMatch = origMatch;
    s_origFind  = origFind;
}

int Match(lua_State* L, const char* s, size_t sLen, const char* p, size_t pLen, int init) {
    if (pLen > 256 || sLen > 65536) return -1;

    const CompiledPattern* cp = GetCompiled(p, pLen);
    if (!cp || cp->kind == JitKind::kUnsupported) {
        InterlockedIncrement(&g_jitMisses);
        return -1;
    }

    // Dual-run verification mode for initial learning phase
    if (s_origMatch && g_verifiedCount < kMaxVerifyCount) {
        int topBefore = lua_gettop_(L);

        int fastN = FastMatchImpl(L, s, sLen, *cp, init);
        if (fastN < 0) return -1;

        // Capture fast path return values
        struct SavedVal {
            int type;
            std::string s;
            double n;
        } saved[4];
        int count = fastN < 4 ? fastN : 4;
        for (int i = 0; i < count; ++i) {
            int idx = topBefore + 1 + i;
            saved[i].type = lua_type_(L, idx);
            if (saved[i].type == 4 /* LUA_TSTRING */) {
                size_t l = 0;
                const char* str = lua_tolstring_(L, idx, &l);
                if (str) saved[i].s.assign(str, l);
            } else if (saved[i].type == 3 /* LUA_TNUMBER */) {
                saved[i].n = lua_tonumber_(L, idx);
            }
        }

        // Restore stack and run client original
        lua_settop_(L, topBefore);
        int origN = s_origMatch(L);

        // Compare
        bool ok = (fastN == origN);
        if (ok) {
            for (int i = 0; i < count; ++i) {
                int idx = topBefore + 1 + i;
                if (lua_type_(L, idx) != saved[i].type) { ok = false; break; }
                if (saved[i].type == 4) {
                    size_t l = 0;
                    const char* str = lua_tolstring_(L, idx, &l);
                    if (l != saved[i].s.size() || memcmp(str, saved[i].s.data(), l) != 0) {
                        ok = false;
                        break;
                    }
                } else if (saved[i].type == 3) {
                    if (lua_tonumber_(L, idx) != saved[i].n) { ok = false; break; }
                }
            }
        }

        if (!ok) {
            InterlockedIncrement(&g_discrepancies);
            Log("[LuaPatternJit] Verification MISMATCH on pattern '%s'. Retiring pattern to client fallback.", cp->patternStr);
            // Retire pattern
            const_cast<CompiledPattern*>(cp)->kind = JitKind::kUnsupported;
            return origN; // origN results are on stack
        }

        InterlockedIncrement(&g_verifiedCount);
        InterlockedIncrement(&g_jitHits);
        return origN;
    }

    int res = FastMatchImpl(L, s, sLen, *cp, init);
    if (res >= 0) {
        InterlockedIncrement(&g_jitHits);
    } else {
        InterlockedIncrement(&g_jitMisses);
    }
    return res;
}

int Find(lua_State* L, const char* s, size_t sLen, const char* p, size_t pLen, int init, bool plain) {
    if (pLen > 256 || sLen > 65536) return -1;

    const CompiledPattern* cp = GetCompiled(p, pLen);
    if (!cp || cp->kind == JitKind::kUnsupported) {
        return -1;
    }

    // string.find plain optimization
    if (plain || cp->kind == JitKind::kPlainLiteral) {
        if (init < 1) init = 1;
        if (init > (int)sLen + 1) { lua_pushnil_(L); return 1; }
        if (pLen == 0) {
            lua_pushnumber_(L, (double)init);
            lua_pushnumber_(L, (double)(init - 1));
            return 2;
        }

        size_t searchLen = sLen - (size_t)(init - 1);
        if (pLen > searchLen) { lua_pushnil_(L); return 1; }

        const char* searchStart = s + (init - 1);
        const char* found = (pLen == 1) ? (const char*)memchr(searchStart, p[0], searchLen)
                                        : (const char*)strstr(searchStart, p);
        if (!found) {
            lua_pushnil_(L);
            return 1;
        }

        int pos = (int)(found - s) + 1;
        lua_pushnumber_(L, (double)pos);
        lua_pushnumber_(L, (double)(pos + (int)pLen - 1));
        return 2;
    }

    return -1;
}

bool Init() {
    memset(s_cache, 0, sizeof(s_cache));
    Log("[LuaPatternJit] Initialized. Micro-JIT pattern engine ready.");
    return true;
}

void Shutdown() {
}

void LogStats() {
    Log("[LuaPatternJit] Match stats: %ld JIT hits (%ld verified bit-exact, %ld discrepancies), %ld fallbacks",
        g_jitHits, g_verifiedCount, g_discrepancies, g_jitMisses);
}

} // namespace LuaPatternJit

