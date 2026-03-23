#include "lua_fastpath.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cmath>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
//  Lua Fast Path — Optimized string.format
//
//  WoW validates C closure function pointers — only accepts
//  addresses within Wow.exe. We CANNOT register our own C
//  functions via lua_pushcclosure. Only MinHook detours work
//  (they redirect at the original Wow.exe address).
//
//  string.format hook:
//    Ultra-fast paths for %d, %s, %.Nf (most common patterns)
//    Generic fast path for any simple format specifiers
//    Falls back to original for %q, %*, tables as %s args
// ================================================================

typedef struct lua_State lua_State;
typedef double lua_Number;
typedef int (__cdecl *lua_CFunction_t)(lua_State* L);

// ================================================================
//  Lua API — known addresses build 12340
// ================================================================

typedef const char* (__cdecl *fn_lua_tolstring)(lua_State* L, int index, size_t* len);
typedef lua_Number  (__cdecl *fn_lua_tonumber)(lua_State* L, int index);
typedef int         (__cdecl *fn_lua_gettop)(lua_State* L);
typedef int         (__cdecl *fn_lua_type)(lua_State* L, int index);
typedef void        (__cdecl *fn_lua_pushnumber)(lua_State* L, lua_Number n);
typedef void        (__cdecl *fn_lua_pushstring)(lua_State* L, const char* s);
typedef int         (__cdecl *fn_lua_toboolean)(lua_State* L, int index);

static fn_lua_tolstring   lua_tolstring_   = (fn_lua_tolstring)0x0084E0E0;
static fn_lua_tonumber    lua_tonumber_    = (fn_lua_tonumber)0x0084E030;
static fn_lua_gettop      lua_gettop_      = (fn_lua_gettop)0x0084DBD0;
static fn_lua_type        lua_type_        = (fn_lua_type)0x0084DEB0;
static fn_lua_pushnumber  lua_pushnumber_  = (fn_lua_pushnumber)0x0084E2A0;
static fn_lua_pushstring  lua_pushstring_  = (fn_lua_pushstring)0x0084E350;
static fn_lua_toboolean   lua_toboolean_   = (fn_lua_toboolean)0x0084E0B0;

#define LUA_TNIL     0
#define LUA_TBOOLEAN 1
#define LUA_TNUMBER  3
#define LUA_TSTRING  4

// ================================================================
//  Hook Address
// ================================================================

static constexpr uintptr_t ADDR_str_format = 0x00853C50;

static lua_CFunction_t orig_str_format = nullptr;

// ================================================================
//  Stats
// ================================================================

static long g_formatFastHits  = 0;
static long g_formatFallbacks = 0;
static bool g_active          = false;

// ================================================================
//  Format Fast Path
// ================================================================

static int __cdecl Hooked_StrFormat(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs < 1) return orig_str_format(L);
    if (lua_type_(L, 1) != LUA_TSTRING) return orig_str_format(L);

    size_t fmtLen = 0;
    const char* fmt = lua_tolstring_(L, 1, &fmtLen);
    if (!fmt || fmtLen == 0 || fmtLen > 128) return orig_str_format(L);

    int numArgs = nargs - 1;

    // ============================================================
    // Ultra-fast paths for top patterns
    // ============================================================

    if (numArgs == 1) {
        // "%d" — integer
        if (fmtLen == 2 && fmt[0] == '%' && fmt[1] == 'd') {
            char buf[32];
            _snprintf(buf, 31, "%d", (int)lua_tonumber_(L, 2));
            buf[31] = '\0';
            lua_pushstring_(L, buf);
            g_formatFastHits++;
            return 1;
        }
        // "%s" — string
        if (fmtLen == 2 && fmt[0] == '%' && fmt[1] == 's') {
            int t = lua_type_(L, 2);
            if (t == LUA_TSTRING) {
                const char* s = lua_tolstring_(L, 2, NULL);
                lua_pushstring_(L, s ? s : "");
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
        // "%.Nf" — float with precision
        if (fmtLen == 4 && fmt[0] == '%' && fmt[1] == '.' &&
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
    }

    // ============================================================
    // No specifiers — return as-is
    // ============================================================

    {
        bool hasSpec = false;
        for (size_t i = 0; i < fmtLen; i++) {
            if (fmt[i] == '%') {
                if (i + 1 < fmtLen && fmt[i + 1] == '%') { i++; continue; }
                hasSpec = true;
                break;
            }
        }
        if (!hasSpec && numArgs == 0) {
            lua_pushstring_(L, fmt);
            g_formatFastHits++;
            return 1;
        }
    }

    // ============================================================
    // Generic parser
    // ============================================================

    char output[1024];
    int outPos = 0;
    int argIdx = 2;
    const char* p = fmt;
    const char* end = fmt + fmtLen;

    while (p < end) {
        if (*p != '%') {
            if (outPos >= 960) goto fallback;
            output[outPos++] = *p++;
            continue;
        }

        p++;
        if (p >= end) goto fallback;

        if (*p == '%') {
            if (outPos >= 960) goto fallback;
            output[outPos++] = '%';
            p++;
            continue;
        }

        if (*p == 'q') goto fallback;

        char spec[32];
        int specLen = 0;
        spec[specLen++] = '%';

        // Flags
        while (p < end && specLen < 24 &&
               (*p == '-' || *p == '+' || *p == ' ' || *p == '#' || *p == '0')) {
            spec[specLen++] = *p++;
        }

        // Width
        if (p < end && *p == '*') goto fallback;
        while (p < end && specLen < 24 && *p >= '0' && *p <= '9') {
            spec[specLen++] = *p++;
        }

        // Precision
        if (p < end && *p == '.') {
            spec[specLen++] = *p++;
            if (p < end && *p == '*') goto fallback;
            while (p < end && specLen < 24 && *p >= '0' && *p <= '9') {
                spec[specLen++] = *p++;
            }
        }

        if (p >= end) goto fallback;
        if (argIdx > nargs) goto fallback;

        char type = *p++;
        char tmpBuf[256];
        int tmpLen = 0;

        switch (type) {
            case 'd': case 'i': {
                spec[specLen++] = 'd';
                spec[specLen] = '\0';
                tmpLen = _snprintf(tmpBuf, 255, spec, (int)lua_tonumber_(L, argIdx));
                break;
            }
            case 'u': {
                spec[specLen++] = 'u';
                spec[specLen] = '\0';
                tmpLen = _snprintf(tmpBuf, 255, spec, (unsigned int)lua_tonumber_(L, argIdx));
                break;
            }
            case 'x': case 'X': {
                spec[specLen++] = type;
                spec[specLen] = '\0';
                tmpLen = _snprintf(tmpBuf, 255, spec, (unsigned int)lua_tonumber_(L, argIdx));
                break;
            }
            case 'o': {
                spec[specLen++] = 'o';
                spec[specLen] = '\0';
                tmpLen = _snprintf(tmpBuf, 255, spec, (unsigned int)lua_tonumber_(L, argIdx));
                break;
            }
            case 'f': case 'e': case 'g':
            case 'E': case 'G': {
                spec[specLen++] = type;
                spec[specLen] = '\0';
                tmpLen = _snprintf(tmpBuf, 255, spec, lua_tonumber_(L, argIdx));
                break;
            }
            case 'c': {
                spec[specLen++] = 'c';
                spec[specLen] = '\0';
                tmpLen = _snprintf(tmpBuf, 255, spec, (int)lua_tonumber_(L, argIdx));
                break;
            }
            case 's': {
                int argType = lua_type_(L, argIdx);
                const char* s;
                char numBuf[64];

                if (argType == LUA_TSTRING) {
                    s = lua_tolstring_(L, argIdx, NULL);
                    if (!s) s = "";
                } else if (argType == LUA_TNIL) {
                    s = "nil";
                } else if (argType == LUA_TBOOLEAN) {
                    s = lua_toboolean_(L, argIdx) ? "true" : "false";
                } else if (argType == LUA_TNUMBER) {
                    _snprintf(numBuf, 63, "%.14g", lua_tonumber_(L, argIdx));
                    numBuf[63] = '\0';
                    s = numBuf;
                } else {
                    goto fallback;
                }

                spec[specLen++] = 's';
                spec[specLen] = '\0';
                tmpLen = _snprintf(tmpBuf, 255, spec, s);
                break;
            }
            default:
                goto fallback;
        }

        tmpBuf[255] = '\0';
        argIdx++;

        if (tmpLen < 0) tmpLen = (int)strlen(tmpBuf);
        if (outPos + tmpLen >= 960) goto fallback;

        memcpy(output + outPos, tmpBuf, tmpLen);
        outPos += tmpLen;
    }

    if (argIdx != nargs + 1) goto fallback;

    output[outPos] = '\0';
    lua_pushstring_(L, output);
    g_formatFastHits++;
    return 1;

fallback:
    g_formatFallbacks++;
    return orig_str_format(L);
}

// ================================================================
//  Public API
// ================================================================

namespace LuaFastPath {

bool Init() {
    Log("[FastPath] ====================================");
    Log("[FastPath]  Lua string.format Fast Path");
    Log("[FastPath]  Build 12340");
    Log("[FastPath] ====================================");

    int hooked = 0;

    __try {
        MH_STATUS s = MH_CreateHook((void*)ADDR_str_format, (void*)Hooked_StrFormat,
                                     (void**)&orig_str_format);
        if (s != MH_OK) {
            Log("[FastPath]   string.format MH_CreateHook failed (%d)", (int)s);
        } else {
            s = MH_EnableHook((void*)ADDR_str_format);
            if (s != MH_OK) {
                Log("[FastPath]   string.format MH_EnableHook failed (%d)", (int)s);
            } else {
                Log("[FastPath]   string.format      0x%08X  [ OK ]", (unsigned)ADDR_str_format);
                hooked++;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[FastPath]   string.format: EXCEPTION — SKIPPED");
    }

    if (hooked == 0) {
        Log("[FastPath]  DISABLED — hook failed");
        return false;
    }

    g_active = true;

    Log("[FastPath]  NOTE: math.* replacements not possible");
    Log("[FastPath]  (WoW validates C closure pointers — DLL addresses rejected)");
    Log("[FastPath] ====================================");
    Log("[FastPath]  Ultra-fast: %%d, %%s, %%.Nf");
    Log("[FastPath]  Generic: all simple specifiers");
    Log("[FastPath]  Fallback: %%q, %%*, tables/userdata");
    Log("[FastPath]  [ OK ] ACTIVE");
    Log("[FastPath] ====================================");
    return true;
}

void Shutdown() {
    if (!g_active) return;

    MH_DisableHook((void*)ADDR_str_format);
    g_active = false;

    long total = g_formatFastHits + g_formatFallbacks;
    if (total > 0) {
        Log("[FastPath] Format: %ld fast, %ld fallback (%.1f%% fast path)",
            g_formatFastHits, g_formatFallbacks,
            (double)g_formatFastHits / total * 100.0);
    }
}

Stats GetStats() {
    Stats s;
    s.formatFastHits  = g_formatFastHits;
    s.formatFallbacks = g_formatFallbacks;
    s.active          = g_active;
    return s;
}

} // namespace LuaFastPath