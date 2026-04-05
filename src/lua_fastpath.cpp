#include "lua_fastpath.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cmath>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

// Lua types and API — known addresses build 12340.

typedef double lua_Number;
typedef int (__cdecl *lua_CFunction_t)(lua_State* L);

typedef const char* (__cdecl *fn_lua_tolstring)(lua_State* L, int index, size_t* len);
typedef lua_Number  (__cdecl *fn_lua_tonumber)(lua_State* L, int index);
typedef int         (__cdecl *fn_lua_gettop)(lua_State* L);
typedef int         (__cdecl *fn_lua_type)(lua_State* L, int index);
typedef void        (__cdecl *fn_lua_pushnumber)(lua_State* L, lua_Number n);
typedef void        (__cdecl *fn_lua_pushstring)(lua_State* L, const char* s);
typedef void        (__cdecl *fn_lua_pushnil)(lua_State* L);
typedef int         (__cdecl *fn_lua_toboolean)(lua_State* L, int index);
typedef void        (__cdecl *fn_lua_settop)(lua_State* L, int index);
typedef void        (__cdecl *fn_lua_getfield)(lua_State* L, int index, const char* k);

static fn_lua_tolstring   lua_tolstring_   = (fn_lua_tolstring)0x0084E0E0;
static fn_lua_tonumber    lua_tonumber_    = (fn_lua_tonumber)0x0084E030;
static fn_lua_gettop      lua_gettop_      = (fn_lua_gettop)0x0084DBD0;
static fn_lua_type        lua_type_        = (fn_lua_type)0x0084DEB0;
static fn_lua_pushnumber  lua_pushnumber_  = (fn_lua_pushnumber)0x0084E2A0;
static fn_lua_pushstring  lua_pushstring_  = (fn_lua_pushstring)0x0084E350;
static fn_lua_pushnil     lua_pushnil_     = (fn_lua_pushnil)0x0084E280;
static fn_lua_toboolean   lua_toboolean_   = (fn_lua_toboolean)0x0084E0B0;
static fn_lua_settop      lua_settop_      = (fn_lua_settop)0x0084DBF0;
static fn_lua_getfield    lua_getfield_    = (fn_lua_getfield)0x0084E590;

typedef void* (__cdecl *fn_luaH_get)(void* t, const void* key);
typedef void* (__cdecl *fn_luaH_getnum)(void* t, int key);
typedef void* (__cdecl *fn_luaH_getstr)(void* t, void* key);
typedef void* (__cdecl *fn_luaH_set)(lua_State* L, void* t, const void* key);
typedef void  (__cdecl *fn_table_barrier)(lua_State* L, void* t);

static fn_luaH_get      luaH_get_      = (fn_luaH_get)0x0085C470;
static fn_luaH_getnum   luaH_getnum_   = (fn_luaH_getnum)0x0085C3A0;
static fn_luaH_getstr   luaH_getstr_   = (fn_luaH_getstr)0x0085C430;
static fn_luaH_set      luaH_set_      = (fn_luaH_set)0x0085C520;
static fn_table_barrier table_barrier_ = (fn_table_barrier)0x0085BA90;

static constexpr uintptr_t ADDR_taint_global  = 0x00D4139C;
static constexpr uintptr_t ADDR_taint_enabled = 0x00D413A0;
static constexpr uintptr_t ADDR_taint_skip    = 0x00D413A4;

#define LUA_TNIL     0
#define LUA_TBOOLEAN 1
#define LUA_TNUMBER  3
#define LUA_TSTRING  4
#define LUA_TTABLE   5
#define LUA_TFUNCTION 6
#define LUA_GLOBALSINDEX (-10002)

union RawValue {
    void*     gc;
    uintptr_t ptr;
    double    n;
};

struct RawTValue {
    RawValue  value;
    int       tt;
    uint32_t  taint;
};

static inline RawTValue* GetStackBaseFast(lua_State* L) {
    return *(RawTValue**)((uintptr_t)L + 0x10);
}

static inline double ReadRawNumber(const RawTValue* tv) {
    double d;
    memcpy(&d, &tv->value, sizeof(double));
    return d;
}

// Phase 1: string.format hook (hardcoded address).

static constexpr uintptr_t ADDR_str_format = 0x00853C50;
static lua_CFunction_t orig_str_format = nullptr;

static long g_formatFastHits       = 0;
static long g_formatFallbacks      = 0;
static long g_findPlainHits        = 0;
static long g_findFallbacks        = 0;
static long g_matchHits            = 0;
static long g_matchFallbacks       = 0;
static long g_typeHits             = 0;
static long g_typeFallbacks        = 0;
static long g_mathHits             = 0;
static long g_mathFallbacks        = 0;
static long g_strlenHits           = 0;
static long g_strbyteHits          = 0;
static long g_tostringHits         = 0;
static long g_tostringFallbacks    = 0;
static long g_tonumberHits         = 0;
static long g_strsubHits           = 0;
static long g_strlowerHits         = 0;
static long g_strupperHits         = 0;
static long g_rawgetHits           = 0;
static long g_rawgetFallbacks      = 0;
static long g_rawsetHits           = 0;
static long g_rawsetFallbacks      = 0;

static inline void NoteRawGetHit() {
    ++g_rawgetHits;
}

static inline void NoteRawGetFallback() {
    ++g_rawgetFallbacks;
}

static inline void NoteRawSetHit() {
    ++g_rawsetHits;
}

static inline void NoteRawSetFallback() {
    ++g_rawsetFallbacks;
}

static bool g_active       = false;
static bool g_phase2Active = false;
static int  g_phase2Hooks  = 0;

static int __cdecl Hooked_StrFormat(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs < 1) return orig_str_format(L);
    if (lua_type_(L, 1) != LUA_TSTRING) return orig_str_format(L);

    size_t fmtLen = 0;
    const char* fmt = lua_tolstring_(L, 1, &fmtLen);
    if (!fmt || fmtLen == 0 || fmtLen > 128) return orig_str_format(L);

    int numArgs = nargs - 1;

    // Safety: bail if any string arg has embedded nuls or is very long
    for (int i = 2; i <= nargs; i++) {
        if (lua_type_(L, i) == LUA_TSTRING) {
            size_t slen = 0;
            const char* s = lua_tolstring_(L, i, &slen);
            if (s && slen > 2048) { g_formatFallbacks++; return orig_str_format(L); }
            if (s) {
                for (size_t j = 0; j < slen; j++) {
                    if (s[j] == '\0') { g_formatFallbacks++; return orig_str_format(L); }
                }
            }
        }
    }

    // Ultra-fast: "%d"
    if (numArgs == 1 && fmtLen == 2 && fmt[0] == '%' && fmt[1] == 'd') {
        char buf[32];
        _snprintf(buf, 31, "%d", (int)lua_tonumber_(L, 2));
        buf[31] = '\0';
        lua_pushstring_(L, buf);
        g_formatFastHits++;
        return 1;
    }

    // Ultra-fast: "%s"
    if (numArgs == 1 && fmtLen == 2 && fmt[0] == '%' && fmt[1] == 's') {
        int t = lua_type_(L, 2);
        if (t == LUA_TSTRING) {
            lua_pushstring_(L, lua_tolstring_(L, 2, NULL));
        } else if (t == LUA_TNIL) {
            lua_pushstring_(L, "nil");
        } else if (t == LUA_TBOOLEAN) {
            lua_pushstring_(L, lua_toboolean_(L, 2) ? "true" : "false");
        } else if (t == LUA_TNUMBER) {
            char buf[64];
            _snprintf(buf, 63, "%.14g", lua_tonumber_(L, 2));
            buf[63] = '\0';
            lua_pushstring_(L, buf);
        } else {
            g_formatFallbacks++;
            return orig_str_format(L);
        }
        g_formatFastHits++;
        return 1;
    }

    // Ultra-fast: "%.Nf"
    if (numArgs == 1 && fmtLen == 4 && fmt[0] == '%' && fmt[1] == '.' &&
        fmt[2] >= '0' && fmt[2] <= '9' && fmt[3] == 'f') {
        char buf[64];
        int n = _snprintf(buf, 63, fmt, lua_tonumber_(L, 2));
        buf[63] = '\0';
        if (n > 0) {
            lua_pushstring_(L, buf);
            g_formatFastHits++;
            return 1;
        }
    }

    // No specifiers — return as-is
    {
        bool hasSpec = false;
        for (size_t i = 0; i < fmtLen; i++) {
            if (fmt[i] == '%') {
                if (i + 1 < fmtLen && fmt[i + 1] == '%') { i++; continue; }
                hasSpec = true; break;
            }
        }
        if (!hasSpec && numArgs == 0) {
            lua_pushstring_(L, fmt);
            g_formatFastHits++;
            return 1;
        }
    }

    // Generic parser
    char output[4096];
    int outPos = 0;
    int argIdx = 2;
    const char* p = fmt;
    const char* end = fmt + fmtLen;

    while (p < end) {
        if (*p != '%') {
            if (outPos >= 3800) goto fallback;
            output[outPos++] = *p++; continue;
        }
        p++;
        if (p >= end) goto fallback;
        if (*p == '%') { if (outPos >= 3800) goto fallback; output[outPos++] = '%'; p++; continue; }
        if (*p == 'q') goto fallback;

        char spec[32]; int specLen = 0; spec[specLen++] = '%';
        while (p < end && specLen < 24 && (*p=='-'||*p=='+'||*p==' '||*p=='#'||*p=='0')) spec[specLen++] = *p++;
        if (p < end && *p == '*') goto fallback;
        while (p < end && specLen < 24 && *p >= '0' && *p <= '9') spec[specLen++] = *p++;
        if (p < end && *p == '.') {
            spec[specLen++] = *p++;
            if (p < end && *p == '*') goto fallback;
            while (p < end && specLen < 24 && *p >= '0' && *p <= '9') spec[specLen++] = *p++;
        }
        if (p >= end || argIdx > nargs) goto fallback;

        char type = *p++;
        char tmpBuf[3072]; int tmpLen = 0;
        switch (type) {
            case 'd': case 'i': spec[specLen++]='d'; spec[specLen]='\0'; tmpLen=_snprintf(tmpBuf,sizeof(tmpBuf)-1,spec,(int)lua_tonumber_(L,argIdx)); break;
            case 'u': spec[specLen++]='u'; spec[specLen]='\0'; tmpLen=_snprintf(tmpBuf,sizeof(tmpBuf)-1,spec,(unsigned)lua_tonumber_(L,argIdx)); break;
            case 'x': case 'X': spec[specLen++]=type; spec[specLen]='\0'; tmpLen=_snprintf(tmpBuf,sizeof(tmpBuf)-1,spec,(unsigned)lua_tonumber_(L,argIdx)); break;
            case 'o': spec[specLen++]='o'; spec[specLen]='\0'; tmpLen=_snprintf(tmpBuf,sizeof(tmpBuf)-1,spec,(unsigned)lua_tonumber_(L,argIdx)); break;
            case 'f': case 'e': case 'g': case 'E': case 'G': spec[specLen++]=type; spec[specLen]='\0'; tmpLen=_snprintf(tmpBuf,sizeof(tmpBuf)-1,spec,lua_tonumber_(L,argIdx)); break;
            case 'c': spec[specLen++]='c'; spec[specLen]='\0'; tmpLen=_snprintf(tmpBuf,sizeof(tmpBuf)-1,spec,(int)lua_tonumber_(L,argIdx)); break;
            case 's': {
                int at = lua_type_(L, argIdx);
                const char* s; char numBuf[64];
                if (at==LUA_TSTRING) { size_t sl=0; s=lua_tolstring_(L,argIdx,&sl); if(!s)s=""; if(sl>2048) goto fallback; }
                else if (at==LUA_TNIL) s="nil";
                else if (at==LUA_TBOOLEAN) s=lua_toboolean_(L,argIdx)?"true":"false";
                else if (at==LUA_TNUMBER) { _snprintf(numBuf,63,"%.14g",lua_tonumber_(L,argIdx)); numBuf[63]='\0'; s=numBuf; }
                else goto fallback;
                spec[specLen++]='s'; spec[specLen]='\0'; tmpLen=_snprintf(tmpBuf,sizeof(tmpBuf)-1,spec,s); break;
            }
            default: goto fallback;
        }
        tmpBuf[sizeof(tmpBuf)-1]='\0'; argIdx++;
        if (tmpLen<0) tmpLen=(int)strlen(tmpBuf);
        if (outPos+tmpLen>=3800) goto fallback;
        memcpy(output+outPos,tmpBuf,tmpLen); outPos+=tmpLen;
    }
    if (argIdx!=nargs+1) goto fallback;
    output[outPos]='\0';
    lua_pushstring_(L, output);
    g_formatFastHits++;
    return 1;
fallback:
    g_formatFallbacks++;
    return orig_str_format(L);
}

// Phase 2: runtime-discovered Lua function hooks.

static bool IsReadableMemory(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD);
}

struct StackLayout {
    int baseOffset;
    int tvalueSize;
    int closureFOffset;
    bool valid;
};

static StackLayout g_layout = {0, 0, 0, false};

static bool CalibrateStackLayout(lua_State* L) {
    uintptr_t L_addr = (uintptr_t)L;

    int topBefore = lua_gettop_(L);
    lua_getfield_(L, LUA_GLOBALSINDEX, "string");
    if (lua_type_(L, -1) != LUA_TTABLE) {
        lua_settop_(L, topBefore);
        return false;
    }
    lua_getfield_(L, -1, "format");
    if (lua_type_(L, -1) != LUA_TFUNCTION) {
        lua_settop_(L, topBefore);
        return false;
    }

    int funcIdx = lua_gettop_(L);

    static const int BASE_OFFS[]   = {0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20};
    static const int TV_SIZES[]    = {12, 16};
    static const int CLOS_F_OFFS[] = {0x10, 0x14, 0x18, 0x0C};

    for (int bi = 0; bi < 7; bi++) {
        for (int ti = 0; ti < 2; ti++) {
            for (int ci = 0; ci < 4; ci++) {
                __try {
                    uintptr_t base = *(uintptr_t*)(L_addr + BASE_OFFS[bi]);
                    if (base == 0 || !IsReadableMemory(base)) continue;

                    uintptr_t slotAddr = base + (uintptr_t)(funcIdx - 1) * TV_SIZES[ti];
                    if (!IsReadableMemory(slotAddr + 12)) continue;

                    int tt = *(int*)(slotAddr + 8);
                    if (tt != LUA_TFUNCTION) continue;

                    uintptr_t gcObj = *(uintptr_t*)(slotAddr);
                    if (gcObj == 0 || !IsReadableMemory(gcObj + CLOS_F_OFFS[ci] + 4)) continue;

                    uintptr_t cfunc = *(uintptr_t*)(gcObj + CLOS_F_OFFS[ci]);

                    if (cfunc == ADDR_str_format) {
                        g_layout.baseOffset     = BASE_OFFS[bi];
                        g_layout.tvalueSize     = TV_SIZES[ti];
                        g_layout.closureFOffset  = CLOS_F_OFFS[ci];
                        g_layout.valid           = true;

                        Log("[FastPath] Calibrated: base=L+0x%02X, TValue=%dB, Closure.f=+0x%02X",
                            BASE_OFFS[bi], TV_SIZES[ti], CLOS_F_OFFS[ci]);

                        lua_settop_(L, topBefore);
                        return true;
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
            }
        }
    }

    lua_settop_(L, topBefore);
    Log("[FastPath] Calibration FAILED — cannot determine stack layout");
    return false;
}

static uintptr_t ReadCFunction(lua_State* L, int stackIndex) {
    if (!g_layout.valid) return 0;
    __try {
        uintptr_t base = *(uintptr_t*)((uintptr_t)L + g_layout.baseOffset);
        if (!base) return 0;

        uintptr_t slot = base + (uintptr_t)(stackIndex - 1) * g_layout.tvalueSize;
        if (*(int*)(slot + 8) != LUA_TFUNCTION) return 0;

        uintptr_t gc = *(uintptr_t*)(slot);
        if (!gc) return 0;

        uintptr_t cfunc = *(uintptr_t*)(gc + g_layout.closureFOffset);
        if (cfunc >= 0x00401000 && cfunc < 0x00F00000) return cfunc;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
    return 0;
}

static uintptr_t DiscoverFunc(lua_State* L, const char* table, const char* name) {
    int topBefore = lua_gettop_(L);

    if (table) {
        lua_getfield_(L, LUA_GLOBALSINDEX, table);
        if (lua_type_(L, -1) != LUA_TTABLE) { lua_settop_(L, topBefore); return 0; }
        lua_getfield_(L, -1, name);
    } else {
        lua_getfield_(L, LUA_GLOBALSINDEX, name);
    }

    if (lua_type_(L, -1) != LUA_TFUNCTION) { lua_settop_(L, topBefore); return 0; }

    uintptr_t addr = ReadCFunction(L, lua_gettop_(L));
    lua_settop_(L, topBefore);
    return addr;
}

static inline bool HasEmbeddedNul(const char* s, size_t len) {
    if (!s) return false;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '\0') return true;
    }
    return false;
}

static inline bool IsPatternMagicChar(char c) {
    switch (c) {
        case '^': case '$': case '(': case ')':
        case '%': case '.': case '[': case ']':
        case '*': case '+': case '-': case '?':
            return true;
        default:
            return false;
    }
}

static bool IsPlainLiteralPattern(const char* p, size_t len) {
    if (!p) return false;
    for (size_t i = 0; i < len; i++) {
        if (IsPatternMagicChar(p[i])) return false;
    }
    return true;
}

static bool MatchAsciiClass(unsigned char c, char cls) {
    if (c > 127) return false;

    switch (cls) {
        case 'd': return (c >= '0' && c <= '9');
        case 'a': return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
        case 'w': return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '_');
        case 'l': return (c >= 'a' && c <= 'z');
        case 'u': return (c >= 'A' && c <= 'Z');
        case 's': return (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
                          c == '\f' || c == '\v');
        default:  return false;
    }
}

static bool PushSubstring(lua_State* L, const char* s, size_t len) {
    if (!s) return false;
    if (len > 4096) return false;
    if (HasEmbeddedNul(s, len)) return false;

    char buf[4097];
    memcpy(buf, s, len);
    buf[len] = '\0';
    lua_pushstring_(L, buf);
    return true;
}
static lua_CFunction_t orig_str_find = nullptr;

static int __cdecl Hooked_StrFind(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs < 2) return orig_str_find(L);

    if (nargs < 4 || !lua_toboolean_(L, 4))
        return orig_str_find(L);

    if (lua_type_(L, 1) != LUA_TSTRING || lua_type_(L, 2) != LUA_TSTRING)
        return orig_str_find(L);

    size_t sLen = 0, pLen = 0;
    const char* s = lua_tolstring_(L, 1, &sLen);
    const char* p = lua_tolstring_(L, 2, &pLen);
    if (!s || !p) return orig_str_find(L);

    int init = 1;
    if (nargs >= 3 && lua_type_(L, 3) == LUA_TNUMBER)
        init = (int)lua_tonumber_(L, 3);

    if (init < 0) init = (int)sLen + init + 1;
    if (init < 1) init = 1;
    if (init > (int)sLen + 1) { lua_pushnil_(L); g_findPlainHits++; return 1; }

    int startIdx = init - 1;

    if (pLen == 0) {
        lua_pushnumber_(L, (double)init);
        lua_pushnumber_(L, (double)(init - 1));
        g_findPlainHits++;
        return 2;
    }

    if (pLen > sLen - startIdx) { lua_pushnil_(L); g_findPlainHits++; return 1; }

    const char* searchStart = s + startIdx;
    size_t searchLen = sLen - startIdx;
    const char* found = nullptr;

    if (pLen == 1) {
        found = (const char*)memchr(searchStart, p[0], searchLen);
    } else {
        size_t limit = searchLen - pLen + 1;
        char first = p[0];
        for (size_t i = 0; i < limit; i++) {
            if (searchStart[i] == first && memcmp(searchStart + i, p, pLen) == 0) {
                found = searchStart + i;
                break;
            }
        }
    }

    if (found) {
        int pos = (int)(found - s) + 1;
        lua_pushnumber_(L, (double)pos);
        lua_pushnumber_(L, (double)(pos + (int)pLen - 1));
    } else {
        lua_pushnil_(L);
    }
    g_findPlainHits++;
    return found ? 2 : 1;
}

static lua_CFunction_t orig_str_match = nullptr;

static int __cdecl Hooked_StrMatch(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs < 2) return orig_str_match(L);

    if (lua_type_(L, 1) != LUA_TSTRING || lua_type_(L, 2) != LUA_TSTRING) {
        g_matchFallbacks++;
        return orig_str_match(L);
    }

    size_t sLen = 0, pLen = 0;
    const char* s = lua_tolstring_(L, 1, &sLen);
    const char* p = lua_tolstring_(L, 2, &pLen);
    if (!s || !p) {
        g_matchFallbacks++;
        return orig_str_match(L);
    }

    // Avoid long / binary strings for safety
    if (sLen > 4096 || pLen > 256 || HasEmbeddedNul(s, sLen) || HasEmbeddedNul(p, pLen)) {
        g_matchFallbacks++;
        return orig_str_match(L);
    }

    int init = 1;
    if (nargs >= 3 && lua_type_(L, 3) == LUA_TNUMBER)
        init = (int)lua_tonumber_(L, 3);

    if (init < 0) init = (int)sLen + init + 1;
    if (init < 1) init = 1;
    if (init > (int)sLen + 1) {
        lua_pushnil_(L);
        g_matchHits++;
        return 1;
    }

    const char* searchStart = s + (init - 1);
    size_t searchLen = sLen - (size_t)(init - 1);

    // Empty pattern => empty match
    if (pLen == 0) {
        lua_pushstring_(L, "");
        g_matchHits++;
        return 1;
    }

    // Case 1: anchored literal "^literal"
    if (pLen > 1 && p[0] == '^' && IsPlainLiteralPattern(p + 1, pLen - 1)) {
        if (init != 1) {
            lua_pushnil_(L);
            g_matchHits++;
            return 1;
        }
        if ((pLen - 1) <= sLen && memcmp(s, p + 1, pLen - 1) == 0) {
            if (PushSubstring(L, s, pLen - 1)) {
                g_matchHits++;
                return 1;
            }
        } else {
            lua_pushnil_(L);
            g_matchHits++;
            return 1;
        }

        g_matchFallbacks++;
        return orig_str_match(L);
    }

    // Case 2: anchored ASCII class "^%x+"
    if (pLen == 4 && p[0] == '^' && p[1] == '%' && p[3] == '+') {
        if (init != 1) {
            lua_pushnil_(L);
            g_matchHits++;
            return 1;
        }

        char cls = p[2];
        if (cls == 'd' || cls == 'a' || cls == 'w' || cls == 'l' || cls == 'u' || cls == 's') {
            size_t i = 0;
            while (i < sLen && MatchAsciiClass((unsigned char)s[i], cls)) {
                i++;
            }

            if (i == 0) {
                lua_pushnil_(L);
                g_matchHits++;
                return 1;
            }

            if (PushSubstring(L, s, i)) {
                g_matchHits++;
                return 1;
            }

            g_matchFallbacks++;
            return orig_str_match(L);
        }
    }

    // Case 3: plain literal pattern
    if (IsPlainLiteralPattern(p, pLen)) {
        if (pLen > searchLen) {
            lua_pushnil_(L);
            g_matchHits++;
            return 1;
        }

        const char* found = nullptr;

        if (pLen == 1) {
            found = (const char*)memchr(searchStart, p[0], searchLen);
        } else {
            size_t limit = searchLen - pLen + 1;
            char first = p[0];
            for (size_t i = 0; i < limit; i++) {
                if (searchStart[i] == first &&
                    memcmp(searchStart + i, p, pLen) == 0) {
                    found = searchStart + i;
                    break;
                }
            }
        }

        if (!found) {
            lua_pushnil_(L);
            g_matchHits++;
            return 1;
        }

        if (PushSubstring(L, found, pLen)) {
            g_matchHits++;
            return 1;
        }

        g_matchFallbacks++;
        return orig_str_match(L);
    }

    g_matchFallbacks++;
    return orig_str_match(L);
}

static lua_CFunction_t orig_luaB_type = nullptr;

static const char* const TYPE_NAMES[] = {
    "nil", "boolean", "userdata", "number",
    "string", "table", "function", "userdata", "thread"
};

static int __cdecl Hooked_Type(lua_State* L) {
    if (lua_gettop_(L) < 1) return orig_luaB_type(L);
    int t = lua_type_(L, 1);
    if (t >= 0 && t <= 8) {
        lua_pushstring_(L, TYPE_NAMES[t]);
        g_typeHits++;
        return 1;
    }
    g_typeFallbacks++;
    return orig_luaB_type(L);
}

static lua_CFunction_t orig_math_floor = nullptr;

static int __cdecl Hooked_MathFloor(lua_State* L) {
    if (lua_type_(L, 1) == LUA_TNUMBER) {
        lua_pushnumber_(L, floor(lua_tonumber_(L, 1)));
        g_mathHits++;
        return 1;
    }
    g_mathFallbacks++;
    return orig_math_floor(L);
}

static lua_CFunction_t orig_math_ceil = nullptr;

static int __cdecl Hooked_MathCeil(lua_State* L) {
    if (lua_type_(L, 1) == LUA_TNUMBER) {
        lua_pushnumber_(L, ceil(lua_tonumber_(L, 1)));
        g_mathHits++;
        return 1;
    }
    g_mathFallbacks++;
    return orig_math_ceil(L);
}

static lua_CFunction_t orig_math_abs = nullptr;

static int __cdecl Hooked_MathAbs(lua_State* L) {
    if (lua_type_(L, 1) == LUA_TNUMBER) {
        lua_pushnumber_(L, fabs(lua_tonumber_(L, 1)));
        g_mathHits++;
        return 1;
    }
    g_mathFallbacks++;
    return orig_math_abs(L);
}

static lua_CFunction_t orig_math_max = nullptr;

static int __cdecl Hooked_MathMax(lua_State* L) {
    int n = lua_gettop_(L);
    if (n == 2 && lua_type_(L, 1) == LUA_TNUMBER && lua_type_(L, 2) == LUA_TNUMBER) {
        double a = lua_tonumber_(L, 1);
        double b = lua_tonumber_(L, 2);
        lua_pushnumber_(L, a > b ? a : b);
        g_mathHits++;
        return 1;
    }
    return orig_math_max(L);
}

static lua_CFunction_t orig_math_min = nullptr;

static int __cdecl Hooked_MathMin(lua_State* L) {
    int n = lua_gettop_(L);
    if (n == 2 && lua_type_(L, 1) == LUA_TNUMBER && lua_type_(L, 2) == LUA_TNUMBER) {
        double a = lua_tonumber_(L, 1);
        double b = lua_tonumber_(L, 2);
        lua_pushnumber_(L, a < b ? a : b);
        g_mathHits++;
        return 1;
    }
    return orig_math_min(L);
}

static lua_CFunction_t orig_str_len = nullptr;

static int __cdecl Hooked_StrLen(lua_State* L) {
    if (lua_type_(L, 1) == LUA_TSTRING) {
        size_t len = 0;
        lua_tolstring_(L, 1, &len);
        lua_pushnumber_(L, (double)len);
        g_strlenHits++;
        return 1;
    }
    return orig_str_len(L);
}

static lua_CFunction_t orig_str_byte = nullptr;

static int __cdecl Hooked_StrByte(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (lua_type_(L, 1) != LUA_TSTRING) return orig_str_byte(L);

    if (nargs <= 2) {
        size_t sLen = 0;
        const char* s = lua_tolstring_(L, 1, &sLen);
        if (!s || sLen == 0) return orig_str_byte(L);

        int pos = 1;
        if (nargs >= 2 && lua_type_(L, 2) == LUA_TNUMBER)
            pos = (int)lua_tonumber_(L, 2);

        if (pos < 0) pos = (int)sLen + pos + 1;
        if (pos < 1 || pos > (int)sLen) { return 0; }

        lua_pushnumber_(L, (double)(unsigned char)s[pos - 1]);
        g_strbyteHits++;
        return 1;
    }

    return orig_str_byte(L);
}

static lua_CFunction_t orig_luaB_tostring = nullptr;

static int __cdecl Hooked_ToString(lua_State* L) {
    if (lua_gettop_(L) < 1) return orig_luaB_tostring(L);

    int t = lua_type_(L, 1);
    switch (t) {
        case LUA_TNIL:
            lua_pushstring_(L, "nil");
            g_tostringHits++;
            return 1;

        case LUA_TBOOLEAN:
            lua_pushstring_(L, lua_toboolean_(L, 1) ? "true" : "false");
            g_tostringHits++;
            return 1;

        case LUA_TNUMBER: {
            char buf[64];
            _snprintf(buf, 63, "%.14g", lua_tonumber_(L, 1));
            buf[63] = '\0';
            lua_pushstring_(L, buf);
            g_tostringHits++;
            return 1;
        }

        case LUA_TSTRING: {
            // Already a string — re-push via Lua interning (hash lookup, not copy)
            size_t len = 0;
            const char* s = lua_tolstring_(L, 1, &len);
            if (s && len <= 4096) {
                // Bail on embedded NULs (lua_pushstring uses strlen)
                for (size_t i = 0; i < len; i++) {
                    if (s[i] == '\0') goto tostring_fallback;
                }
                lua_pushstring_(L, s);
                g_tostringHits++;
                return 1;
            }
            break;
        }

        default:
            // table, function, userdata, thread need __tostring metamethod
            break;
    }

tostring_fallback:
    g_tostringFallbacks++;
    return orig_luaB_tostring(L);
}

static lua_CFunction_t orig_luaB_tonumber = nullptr;

static int __cdecl Hooked_ToNumber_Global(lua_State* L) {
    int nargs = lua_gettop_(L);

    // Only fast-path single-arg (no explicit base)
    if (nargs != 1) return orig_luaB_tonumber(L);

    if (lua_type_(L, 1) == LUA_TNUMBER) {
        lua_pushnumber_(L, lua_tonumber_(L, 1));
        g_tonumberHits++;
        return 1;
    }

    // String parsing, nil, boolean, etc. — let original handle
    return orig_luaB_tonumber(L);
}

static lua_CFunction_t orig_str_sub = nullptr;

static int __cdecl Hooked_StrSub(lua_State* L) {
    if (lua_type_(L, 1) != LUA_TSTRING) return orig_str_sub(L);

    size_t sLen = 0;
    const char* s = lua_tolstring_(L, 1, &sLen);
    if (!s) return orig_str_sub(L);

    int nargs = lua_gettop_(L);

    int i = 1;
    int j = (int)sLen;

    if (nargs >= 2 && lua_type_(L, 2) == LUA_TNUMBER)
        i = (int)lua_tonumber_(L, 2);
    if (nargs >= 3 && lua_type_(L, 3) == LUA_TNUMBER)
        j = (int)lua_tonumber_(L, 3);

    // Lua string index adjustment
    if (i < 0) i = (int)sLen + i + 1;
    if (j < 0) j = (int)sLen + j + 1;
    if (i < 1) i = 1;
    if (j > (int)sLen) j = (int)sLen;

    if (i > j) {
        lua_pushstring_(L, "");
        g_strsubHits++;
        return 1;
    }

    size_t len = (size_t)(j - i + 1);
    if (len > 4096) return orig_str_sub(L);

    const char* start = s + (i - 1);

    // Bail on embedded NUL (lua_pushstring uses strlen)
    for (size_t k = 0; k < len; k++) {
        if (start[k] == '\0') return orig_str_sub(L);
    }

    char buf[4097];
    memcpy(buf, start, len);
    buf[len] = '\0';
    lua_pushstring_(L, buf);
    g_strsubHits++;
    return 1;
}

static lua_CFunction_t orig_str_lower = nullptr;

static int __cdecl Hooked_StrLower(lua_State* L) {
    if (lua_type_(L, 1) != LUA_TSTRING) return orig_str_lower(L);

    size_t sLen = 0;
    const char* s = lua_tolstring_(L, 1, &sLen);
    if (!s || sLen == 0 || sLen > 4096) return orig_str_lower(L);

    char buf[4097];
    for (size_t i = 0; i < sLen; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c > 127 || c == 0) return orig_str_lower(L);
        buf[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
    }
    buf[sLen] = '\0';

    lua_pushstring_(L, buf);
    g_strlowerHits++;
    return 1;
}

static lua_CFunction_t orig_str_upper = nullptr;

static int __cdecl Hooked_StrUpper(lua_State* L) {
    if (lua_type_(L, 1) != LUA_TSTRING) return orig_str_upper(L);

    size_t sLen = 0;
    const char* s = lua_tolstring_(L, 1, &sLen);
    if (!s || sLen == 0 || sLen > 4096) return orig_str_upper(L);

    char buf[4097];
    for (size_t i = 0; i < sLen; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c > 127 || c == 0) return orig_str_upper(L);
        buf[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : (char)c;
    }
    buf[sLen] = '\0';

    lua_pushstring_(L, buf);
    g_strupperHits++;
    return 1;
}

static lua_CFunction_t orig_luaB_rawget = nullptr;

static int __cdecl Hooked_RawGet_Global(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs != 2) {
        NoteRawGetFallback();
        return orig_luaB_rawget(L);
    }

    __try {
        RawTValue* base = GetStackBaseFast(L);
        if (!base) {
            NoteRawGetFallback();
            return orig_luaB_rawget(L);
        }

        RawTValue* tableSlot = base;
        RawTValue* keySlot   = base + 1;

        if (tableSlot->tt != LUA_TTABLE) {
            NoteRawGetFallback();
            return orig_luaB_rawget(L);
        }

        void* tablePtr = tableSlot->value.gc;
        if (!tablePtr) {
            NoteRawGetFallback();
            return orig_luaB_rawget(L);
        }

        RawTValue* resultSlot = nullptr;

        if (keySlot->tt == LUA_TSTRING) {
            void* ts = keySlot->value.gc;
            resultSlot = (RawTValue*)luaH_getstr_(tablePtr, ts);
        } else if (keySlot->tt == LUA_TNUMBER) {
            double n = ReadRawNumber(keySlot);
            int iv = (int)n;
            if ((double)iv == n)
                resultSlot = (RawTValue*)luaH_getnum_(tablePtr, iv);
            else
                resultSlot = (RawTValue*)luaH_get_(tablePtr, keySlot);
        } else {
            resultSlot = (RawTValue*)luaH_get_(tablePtr, keySlot);
        }

        if (!resultSlot) {
            NoteRawGetFallback();
            return orig_luaB_rawget(L);
        }

        *keySlot = *resultSlot;

        if (keySlot->taint) {
            if (*(int*)ADDR_taint_enabled && !*(int*)ADDR_taint_skip)
                *(uint32_t*)ADDR_taint_global = keySlot->taint;
        } else {
            keySlot->taint = *(uint32_t*)ADDR_taint_global;
        }

        NoteRawGetHit();
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        NoteRawGetFallback();
        return orig_luaB_rawget(L);
    }
}

static lua_CFunction_t orig_luaB_rawset = nullptr;

static int __cdecl Hooked_RawSet_Global(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs != 3) {
        NoteRawSetFallback();
        return orig_luaB_rawset(L);
    }

    __try {
        RawTValue* base = GetStackBaseFast(L);
        if (!base) {
            NoteRawSetFallback();
            return orig_luaB_rawset(L);
        }

        RawTValue* tableSlot = base;
        RawTValue* keySlot   = base + 1;
        RawTValue* valueSlot = base + 2;

        if (tableSlot->tt != LUA_TTABLE) {
            NoteRawSetFallback();
            return orig_luaB_rawset(L);
        }

        void* tablePtr = tableSlot->value.gc;
        if (!tablePtr) {
            NoteRawSetFallback();
            return orig_luaB_rawset(L);
        }

        RawTValue* dst = (RawTValue*)luaH_set_(L, tablePtr, keySlot);
        if (!dst) {
            NoteRawSetFallback();
            return orig_luaB_rawset(L);
        }

        *dst = *valueSlot;

        if (valueSlot->taint) {
            if (*(int*)ADDR_taint_enabled && !*(int*)ADDR_taint_skip)
                *(uint32_t*)ADDR_taint_global = valueSlot->taint;
        }

        if (valueSlot->tt >= LUA_TSTRING) {
            uintptr_t valueGc = (uintptr_t)valueSlot->value.gc;
            uintptr_t tableGc = (uintptr_t)tablePtr;

            if (valueGc &&
                ((*(uint8_t*)(valueGc + 9) & 3) != 0) &&
                ((*(uint8_t*)(tableGc + 9) & 4) != 0)) {
                table_barrier_(L, tablePtr);
            }
        }

        *valueSlot = *tableSlot;

        NoteRawSetHit();
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        NoteRawSetFallback();
        return orig_luaB_rawset(L);
    }
}

// Phase 2: discovery and hook installation.

struct FuncHookEntry {
    const char*        table;
    const char*        name;
    void*              hookFn;
    lua_CFunction_t*   origFn;
    uintptr_t          address;
    bool               hooked;
};

static FuncHookEntry g_funcHooks[] = {
    {"string", "find",      (void*)Hooked_StrFind,          &orig_str_find,         0, false},
    {"string", "match",     (void*)Hooked_StrMatch,         &orig_str_match,        0, false},
    {nullptr,  "type",      (void*)Hooked_Type,             &orig_luaB_type,        0, false},
    {"math",   "floor",     (void*)Hooked_MathFloor,        &orig_math_floor,       0, false},
    {"math",   "ceil",      (void*)Hooked_MathCeil,         &orig_math_ceil,        0, false},
    {"math",   "abs",       (void*)Hooked_MathAbs,          &orig_math_abs,         0, false},
    {"math",   "max",       (void*)Hooked_MathMax,          &orig_math_max,         0, false},
    {"math",   "min",       (void*)Hooked_MathMin,          &orig_math_min,         0, false},
    {"string", "len",       (void*)Hooked_StrLen,           &orig_str_len,          0, false},
    {"string", "byte",      (void*)Hooked_StrByte,          &orig_str_byte,         0, false},
    {nullptr,  "tostring",  (void*)Hooked_ToString,         &orig_luaB_tostring,    0, false},
    {nullptr,  "tonumber",  (void*)Hooked_ToNumber_Global,  &orig_luaB_tonumber,    0, false},
    {nullptr,  "rawget",    (void*)Hooked_RawGet_Global,    &orig_luaB_rawget,      0, false},
    {nullptr,  "rawset",    (void*)Hooked_RawSet_Global,    &orig_luaB_rawset,      0, false},
    {"string", "sub",       (void*)Hooked_StrSub,           &orig_str_sub,          0, false},
    {"string", "lower",     (void*)Hooked_StrLower,         &orig_str_lower,        0, false},
    {"string", "upper",     (void*)Hooked_StrUpper,         &orig_str_upper,        0, false},
};

static constexpr int NUM_FUNC_HOOKS = sizeof(g_funcHooks) / sizeof(g_funcHooks[0]);

namespace LuaFastPath {

bool Init() {
    Log("[FastPath] ====================================");
    Log("[FastPath]  Lua Fast Path — Phase 1");
    Log("[FastPath]  Build 12340");
    Log("[FastPath] ====================================");

    __try {
        MH_STATUS s = MH_CreateHook((void*)ADDR_str_format, (void*)Hooked_StrFormat,
                                     (void**)&orig_str_format);
        if (s != MH_OK) {
            Log("[FastPath]   string.format MH_CreateHook failed (%d)", (int)s);
            return false;
        }
        s = MH_EnableHook((void*)ADDR_str_format);
        if (s != MH_OK) {
            Log("[FastPath]   string.format MH_EnableHook failed (%d)", (int)s);
            return false;
        }
        Log("[FastPath]   string.format      0x%08X  [ OK ]", (unsigned)ADDR_str_format);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[FastPath]   string.format: EXCEPTION");
        return false;
    }

    g_active = true;
    Log("[FastPath]  Phase 1 [ OK ] — string.format hooked");
    Log("[FastPath]  Phase 2 will run after Lua state ready");
    Log("[FastPath] ====================================");
    return true;
}

bool InitPhase2(lua_State* L) {
    if (!L) return false;

    Log("[FastPath] Phase 2: runtime function discovery");

    // Recalibrate for current VM (glue/game VM may differ in stack base)
    g_layout.valid = false;
    if (!CalibrateStackLayout(L)) {
        if (g_phase2Active) {
            Log("[FastPath]  Phase 2 calibration failed — keeping existing hooks");
            return true;
        }
        Log("[FastPath]  Phase 2 FAILED — calibration unsuccessful");
        return false;
    }

    int discoveredNow = 0;
    int discoveredTotal = 0;

    for (int i = 0; i < NUM_FUNC_HOOKS; i++) {
        FuncHookEntry& e = g_funcHooks[i];

        if (e.address == 0) {
            e.address = DiscoverFunc(L, e.table, e.name);
            if (e.address) {
                discoveredNow++;
                Log("[FastPath]   %-8s.%-8s  0x%08X  discovered",
                    e.table ? e.table : "_G", e.name, (unsigned)e.address);
            } else {
                Log("[FastPath]   %-8s.%-8s  NOT FOUND",
                    e.table ? e.table : "_G", e.name);
            }
        }

        if (e.address)
            discoveredTotal++;
    }

    int hookedNow = 0;
    int hookedTotal = 0;

    for (int i = 0; i < NUM_FUNC_HOOKS; i++) {
        FuncHookEntry& e = g_funcHooks[i];

        if (e.hooked) {
            hookedTotal++;
            continue;
        }

        if (e.address == 0)
            continue;

        if (e.address == ADDR_str_format) {
            Log("[FastPath]   %-8s.%-8s  SKIP (already hooked in Phase 1)",
                e.table ? e.table : "_G", e.name);
            continue;
        }

        __try {
            MH_STATUS s = MH_CreateHook((void*)e.address, e.hookFn, (void**)e.origFn);
            if (s != MH_OK) {
                Log("[FastPath]   %-8s.%-8s  MH_CreateHook failed (%d)",
                    e.table ? e.table : "_G", e.name, (int)s);
                continue;
            }
            s = MH_EnableHook((void*)e.address);
            if (s != MH_OK) {
                Log("[FastPath]   %-8s.%-8s  MH_EnableHook failed (%d)",
                    e.table ? e.table : "_G", e.name, (int)s);
                continue;
            }

            e.hooked = true;
            hookedNow++;
            hookedTotal++;
            Log("[FastPath]   %-8s.%-8s  0x%08X  [ OK ]",
                e.table ? e.table : "_G", e.name, (unsigned)e.address);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            Log("[FastPath]   %-8s.%-8s  EXCEPTION during hook",
                e.table ? e.table : "_G", e.name);
        }
    }

    g_phase2Hooks  = hookedTotal;
    g_phase2Active = (hookedTotal > 0);

    Log("[FastPath] Phase 2: %d/%d discovered, %d new | %d/%d hooked, %d new",
        discoveredTotal, NUM_FUNC_HOOKS, discoveredNow,
        hookedTotal, discoveredTotal, hookedNow);
    return g_phase2Active;
}

void ResetPhase2Discovery() {
    // Do NOT remove already installed hooks.
    // We only want late rediscovery for functions that were not found in glue VM.
    g_layout.valid = false;
}

void Shutdown() {
    if (g_active) {
        MH_DisableHook((void*)ADDR_str_format);
    }

    for (int i = 0; i < NUM_FUNC_HOOKS; i++) {
        if (g_funcHooks[i].hooked && g_funcHooks[i].address) {
            MH_DisableHook((void*)g_funcHooks[i].address);
            g_funcHooks[i].hooked = false;
        }
    }

    long fmtTotal = g_formatFastHits + g_formatFallbacks;
    if (fmtTotal > 0) {
        Log("[FastPath] Format: %ld fast, %ld fallback (%.1f%%)",
            g_formatFastHits, g_formatFallbacks,
            (double)g_formatFastHits / fmtTotal * 100.0);
    }
    if (g_findPlainHits > 0 || g_findFallbacks > 0)
        Log("[FastPath] Find(plain): %ld fast, %ld fallback", g_findPlainHits, g_findFallbacks);
    if (g_matchHits > 0 || g_matchFallbacks > 0)
        Log("[FastPath] Match: %ld fast, %ld fallback", g_matchHits, g_matchFallbacks);
    if (g_typeHits > 0)
        Log("[FastPath] Type: %ld fast, %ld fallback", g_typeHits, g_typeFallbacks);
    if (g_mathHits > 0)
        Log("[FastPath] Math: %ld fast, %ld fallback", g_mathHits, g_mathFallbacks);
    if (g_strlenHits > 0) Log("[FastPath] StrLen: %ld fast", g_strlenHits);
    if (g_strbyteHits > 0) Log("[FastPath] StrByte: %ld fast", g_strbyteHits);
    if (g_tostringHits > 0)
        Log("[FastPath] ToString: %ld fast, %ld fallback", g_tostringHits, g_tostringFallbacks);
    if (g_tonumberHits > 0) Log("[FastPath] ToNumber: %ld fast", g_tonumberHits);
    if (g_rawgetHits > 0 || g_rawgetFallbacks > 0)
        Log("[FastPath] RawGet: %ld fast, %ld fallback", g_rawgetHits, g_rawgetFallbacks);
    if (g_rawsetHits > 0 || g_rawsetFallbacks > 0)
        Log("[FastPath] RawSet: %ld fast, %ld fallback", g_rawsetHits, g_rawsetFallbacks);
    if (g_strsubHits > 0) Log("[FastPath] StrSub: %ld fast", g_strsubHits);
    if (g_strlowerHits > 0) Log("[FastPath] StrLower: %ld fast", g_strlowerHits);
    if (g_strupperHits > 0) Log("[FastPath] StrUpper: %ld fast", g_strupperHits);

    g_active = false;
    g_phase2Active = false;
}

Stats GetStats() {
    Stats s;
    s.formatFastHits    = g_formatFastHits;
    s.formatFallbacks   = g_formatFallbacks;
    s.findPlainHits     = g_findPlainHits;
    s.findFallbacks     = g_findFallbacks;
    s.matchHits         = g_matchHits;
    s.matchFallbacks    = g_matchFallbacks;
    s.typeHits          = g_typeHits;
    s.typeFallbacks     = g_typeFallbacks;
    s.mathHits          = g_mathHits;
    s.mathFallbacks     = g_mathFallbacks;
    s.strlenHits        = g_strlenHits;
    s.strbyteHits       = g_strbyteHits;
    s.tostringHits      = g_tostringHits;
    s.tostringFallbacks = g_tostringFallbacks;
    s.tonumberHits      = g_tonumberHits;
    s.rawgetHits        = g_rawgetHits;
    s.rawgetFallbacks   = g_rawgetFallbacks;
    s.rawsetHits        = g_rawsetHits;
    s.rawsetFallbacks   = g_rawsetFallbacks;
    s.strsubHits        = g_strsubHits;
    s.strlowerHits      = g_strlowerHits;
    s.strupperHits      = g_strupperHits;
    s.phase2Hooks       = g_phase2Hooks;
    s.active            = g_active;
    s.phase2Active      = g_phase2Active;
    return s;
}

} // namespace LuaFastPath