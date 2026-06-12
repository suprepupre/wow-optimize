// ================================================================
// Lua Fast Path — Direct C function hooks for WoW's Lua 5.1 VM
//
// ================================================================

#include "lua_fastpath.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cmath>
#include "MinHook.h"
#include <mimalloc.h>
#include "version.h"
#include <algorithm>
#include <vector>

extern "C" void Log(const char* fmt, ...);

// ================================================================
// These are direct function pointers into WoW's Lua 5.1 VM.
// ================================================================

typedef double lua_Number;
typedef int (__cdecl *lua_CFunction_t)(lua_State* L);

typedef const char* (__cdecl *fn_lua_tolstring)(lua_State* L, int index, size_t* len);
typedef lua_Number (__cdecl *fn_lua_tonumber)(lua_State* L, int index);
typedef int        (__cdecl *fn_lua_gettop)(lua_State* L);
typedef int        (__cdecl *fn_lua_type)(lua_State* L, int index);
typedef void       (__cdecl *fn_lua_pushnumber)(lua_State* L, lua_Number n);
typedef void       (__cdecl *fn_lua_pushstring)(lua_State* L, const char* s);
typedef void       (__cdecl *fn_lua_pushnil)(lua_State* L);
typedef int        (__cdecl *fn_lua_toboolean)(lua_State* L, int index);
typedef void       (__cdecl *fn_lua_settop)(lua_State* L, int index);
typedef void       (__cdecl *fn_lua_getfield)(lua_State* L, int index, const char* k);
typedef void       (__cdecl *fn_lua_pushboolean)(lua_State* L, int b);
typedef void       (__cdecl *fn_lua_pushcclosure)(lua_State* L, int (*fn)(lua_State*), int n);
typedef void       (__cdecl *fn_lua_replace)(lua_State* L, int index);
typedef void       (__cdecl *fn_lua_insert)(lua_State* L, int index);
typedef void       (__cdecl *fn_lua_remove)(lua_State* L, int index);
typedef const void* (__cdecl *fn_lua_topointer)(lua_State* L, int index);
typedef void       (__cdecl *fn_lua_pushvalue)(lua_State* L, int index);

static fn_lua_tolstring   lua_tolstring_   = (fn_lua_tolstring)0x0084E0E0;
static fn_lua_tonumber    lua_tonumber_    = (fn_lua_tonumber)0x0084E030;
static fn_lua_gettop      lua_gettop_      = (fn_lua_gettop)0x0084DBD0;
static fn_lua_type        lua_type_        = (fn_lua_type)0x0084DEB0;
static fn_lua_pushnumber  lua_pushnumber_  = (fn_lua_pushnumber)0x0084E2A0;
static fn_lua_pushstring  lua_pushstring_  = (fn_lua_pushstring)0x0084E350;
static fn_lua_pushnil     lua_pushnil_     = (fn_lua_pushnil)0x0084E280;
static fn_lua_toboolean   lua_toboolean_   = (fn_lua_toboolean)0x0084E0B0;
static fn_lua_pushboolean lua_pushboolean_ = (fn_lua_pushboolean)0x0084E4D0;
static fn_lua_settop      lua_settop_      = (fn_lua_settop)0x0084DBF0;
static fn_lua_getfield    lua_getfield_    = (fn_lua_getfield)0x0084E590;
static fn_lua_pushcclosure lua_pushcclosure_ = (fn_lua_pushcclosure)0x0084E980;
static fn_lua_replace     lua_replace_     = (fn_lua_replace)0x0084E850;
static fn_lua_insert      lua_insert_      = (fn_lua_insert)0x0084E8C0;
static fn_lua_remove      lua_remove_      = (fn_lua_remove)0x0084E880;
static fn_lua_topointer   lua_topointer_   = (fn_lua_topointer)0x0084E0A0;
static fn_lua_pushvalue   lua_pushvalue_   = (fn_lua_pushvalue)0x0084E630;

typedef void* (__cdecl *fn_luaH_get)(void* t, const void* key);
typedef void* (__cdecl *fn_luaH_getnum)(void* t, int key);
typedef void* (__cdecl *fn_luaH_getstr)(void* t, void* key);
typedef void* (__cdecl *fn_luaH_set)(lua_State* L, void* t, const void* key);
typedef void* (__cdecl *fn_luaH_setnum)(lua_State* L, void* t, int key);
typedef unsigned int (__cdecl *fn_luaH_getn)(void* t);
typedef void (__cdecl *fn_table_barrier)(lua_State* L, void* t);
typedef int  (__cdecl *fn_lua_next_helper)(lua_State* L, void* t, void* keyslot);

static fn_luaH_get        luaH_get_        = (fn_luaH_get)0x0085C470;
static fn_luaH_getnum     luaH_getnum_     = (fn_luaH_getnum)0x0085C3A0;
static fn_luaH_getstr     luaH_getstr_     = (fn_luaH_getstr)0x0085C430;
static fn_luaH_set        luaH_set_        = (fn_luaH_set)0x0085C520;
static fn_luaH_setnum     luaH_setnum_     = (fn_luaH_setnum)0x0085C590;
static fn_luaH_getn       luaH_getn_       = (fn_luaH_getn)0x0085C690;
static fn_table_barrier   table_barrier_   = (fn_table_barrier)0x0085BA90;
static fn_lua_next_helper lua_next_helper_ = (fn_lua_next_helper)0x0085BE30;
typedef void* (__cdecl *fn_luaS_newlstr_fast)(lua_State* L, const char* str, size_t l);
static fn_luaS_newlstr_fast luaS_newlstr_ = (fn_luaS_newlstr_fast)0x00856C80;

static constexpr uintptr_t ADDR_taint_global  = 0x00D4139C;
static constexpr uintptr_t ADDR_taint_enabled = 0x00D413A0;
static constexpr uintptr_t ADDR_taint_skip    = 0x00D413A4;

#define LUA_TNIL     0
#define LUA_TBOOLEAN 1
#define LUA_TNUMBER  3
#define LUA_TSTRING  4
#define LUA_TTABLE   5
#define LUA_TFUNCTION 6
#define LUA_TTHREAD  8
#define LUA_TUSERDATA 7
#define LUA_GLOBALSINDEX (-10002)
#define lua_upvalueindex(i) (LUA_GLOBALSINDEX - (i))

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

static inline RawTValue* GetStackTopFast(lua_State* L) {
    return *(RawTValue**)((uintptr_t)L + 0x0C);
}

static inline void SetStackTopFast(lua_State* L, RawTValue* top) {
    *(RawTValue**)((uintptr_t)L + 0x0C) = top;
}

static inline double ReadRawNumber(const RawTValue* tv) {
    double d;
    memcpy(&d, &tv->value, sizeof(double));
    return d;
}

// Rosetta cache-disabled flag: set by DllMain after setting ROSETTA_X87_DISABLE_CACHE=1.
// When true, MinHook inline hooks are safe on Rosetta (JIT re-translates on every call).
// When false, must use Lua API path (data writes only, no x86 code modification).
bool g_rosettaCacheDisabled = false;

// Memory validation for function pointers
static bool IsExecutable(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// ================================================================
// Phase 1: string.format hook (hardcoded address 0x00853C50).
//
// ================================================================

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
static long g_nextHits             = 0;
static long g_nextFallbacks        = 0;
static long g_tblInsertHits        = 0;
static long g_tblInsertFallbacks   = 0;
static long g_tblRemoveHits        = 0;
static long g_tblRemoveFallbacks   = 0;
static lua_CFunction_t orig_tbl_concat = nullptr;
static lua_CFunction_t orig_table_sort = nullptr;
static long g_tblConcatHits = 0;
static long g_tblConcatFallbacks = 0;
static lua_CFunction_t orig_luaB_rawequal = nullptr;
static long g_rawequalHits       = 0;
static long g_rawequalFallbacks  = 0;
static lua_CFunction_t orig_luaB_unpack = nullptr;
static long g_unpackHits       = 0;
static long g_unpackFallbacks  = 0;
static long g_tableSortHits = 0;
static long g_tableSortFallbacks = 0;

static lua_CFunction_t orig_luaB_select = nullptr;
static long g_selectHits       = 0;
static long g_selectFallbacks  = 0;

static lua_CFunction_t orig_math_random = nullptr;
static long g_mathRandomHits       = 0;
static long g_mathRandomFallbacks  = 0;

static lua_CFunction_t orig_math_sqrt = nullptr;
static long g_mathSqrtHits       = 0;
static long g_mathSqrtFallbacks  = 0;

static lua_CFunction_t orig_str_rep = nullptr;
static long g_strRepHits       = 0;
static long g_strRepFallbacks  = 0;

// ipairs factory hook — Phase 2
// Architecture: ipairs(table) returns (iterator_closure, table, 0)
// We hook the factory to return our custom fast iterator closure.
// Future optimization: replace the returned iterator with our fast version.
static lua_CFunction_t orig_luaB_ipairs = nullptr;
static long g_ipairsFactoryHits   = 0;
static long g_ipairsFactoryFalls  = 0;
static long g_ipairsIteratorHits  = 0;
static long g_ipairsIteratorFalls = 0;

// Forward declaration
static int __cdecl Hooked_IPairs_Iterator(lua_State* L);

static lua_CFunction_t orig_str_find_full = nullptr;
static long g_findFullHits       = 0;
static long g_findFullFallbacks  = 0;

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

static inline void NoteNextHit() {
    ++g_nextHits;
}

static inline void NoteNextFallback() {
    ++g_nextFallbacks;
}

static inline void NoteTableInsertHit() {
    ++g_tblInsertHits;
}

static inline void NoteTableInsertFallback() {
    ++g_tblInsertFallbacks;
}

static inline void NoteTableRemoveHit() {
    ++g_tblRemoveHits;
}

static inline void NoteTableRemoveFallback() {
    ++g_tblRemoveFallbacks;
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

    // Safety: only check string length limit. Embedded NUL byte scan removed —
    // it was scanning every byte of every string arg on EVERY format call,
    // causing format hit rate to drop from 86% to 9%. The generic parser
    // below handles edge cases safely via _snprintf which stops at NUL.
    for (int i = 2; i <= nargs; i++) {
        if (lua_type_(L, i) == LUA_TSTRING) {
            size_t slen = 0;
            lua_tolstring_(L, i, &slen);
            if (slen > 2048) { g_formatFallbacks++; return orig_str_format(L); }
        }
    }

    // Fast multi-specifier: %d/%d, %d-%d, %s:%d
    if (numArgs == 2 && fmtLen == 5 && !memcmp(fmt, "%d/%d", 5)) {
        char b[64]; _snprintf(b,63,"%d/%d",(int)lua_tonumber_(L,2),(int)lua_tonumber_(L,3));
        b[63]=0; lua_pushstring_(L,b); g_formatFastHits++; return 1;
    }
    if (numArgs == 2 && fmtLen == 5 && !memcmp(fmt, "%d-%d", 5)) {
        char b[64]; _snprintf(b,63,"%d-%d",(int)lua_tonumber_(L,2),(int)lua_tonumber_(L,3));
        b[63]=0; lua_pushstring_(L,b); g_formatFastHits++; return 1;
    }
    if (numArgs == 2 && fmtLen == 6 && !memcmp(fmt, "%s: %d", 6)) {
        size_t sl=0; const char* s=lua_tolstring_(L,2,&sl);
        char b[256]; _snprintf(b,255,"%s: %d",s?s:"",(int)lua_tonumber_(L,3));
        b[255]=0; lua_pushstring_(L,b); g_formatFastHits++; return 1;
    }

    // Fast: "%d"
    // Fast: width-specified numeric: %02d, %04d, %x, %X, %u (single arg)
    if (numArgs == 1 && fmtLen >= 3 && fmtLen <= 5 && fmt[0] == '%') {
        char last = fmt[fmtLen-1];
        if (last == 'd' || last == 'i' || last == 'u' || last == 'x' || last == 'X') {
            bool allNum = true;
            for (size_t i = 1; i < fmtLen-1; i++) if (fmt[i] < '0' || fmt[i] > '9') { allNum = false; break; }
            if (allNum) {
                char b[64]; _snprintf(b,63,fmt,(int)lua_tonumber_(L,2)); b[63]=0;
                lua_pushstring_(L,b); g_formatFastHits++; return 1;
            }
        }
    }
    // Fast: %02d:%02d — time display (timers, cooldowns)
    if (numArgs == 2 && fmtLen == 8 && !memcmp(fmt, "%02d:%02d", 8)) {
        char b[64]; _snprintf(b,63,"%02d:%02d",(int)lua_tonumber_(L,2),(int)lua_tonumber_(L,3));
        b[63]=0; lua_pushstring_(L,b); g_formatFastHits++; return 1;
    }

    // Fast: %02x hex color component
    if (numArgs == 1 && fmtLen == 4 && fmt[0] == '%' && fmt[1] == '0' && fmt[2] >= '0' && fmt[2] <= '9' && (fmt[3] == 'x' || fmt[3] == 'X')) {
        char b[64]; _snprintf(b,63,fmt,(unsigned)lua_tonumber_(L,2)); b[63]=0;
        lua_pushstring_(L,b); g_formatFastHits++; return 1;
    }
    // Fast: "%s%s" — string concatenation via format (common in WeakAuras/ElvUI)
    if (numArgs == 2 && fmtLen == 4 && !memcmp(fmt, "%s%s", 4)) {
        size_t s1l=0, s2l=0;
        const char* s1 = lua_tolstring_(L, 2, &s1l);
        const char* s2 = lua_tolstring_(L, 3, &s2l);
        if (s1 && s2 && s1l + s2l < 4000) {
            char b[4096]; memcpy(b, s1, s1l); memcpy(b+s1l, s2, s2l); b[s1l+s2l]=0;
            lua_pushstring_(L, b); g_formatFastHits++; return 1;
        }
    }
    // Fast: "%s %s" — space-separated strings
    if (numArgs == 2 && fmtLen == 5 && !memcmp(fmt, "%s %s", 5)) {
        size_t s1l=0, s2l=0;
        const char* s1 = lua_tolstring_(L, 2, &s1l);
        const char* s2 = lua_tolstring_(L, 3, &s2l);
        if (s1 && s2 && s1l + s2l + 1 < 4000) {
            char b[4096]; memcpy(b, s1, s1l); b[s1l]=' '; memcpy(b+s1l+1, s2, s2l); b[s1l+1+s2l]=0;
            lua_pushstring_(L, b); g_formatFastHits++; return 1;
        }
    }
    // Fast: "%d %s" — number + string (common in chat/combat log)
    if (numArgs == 2 && fmtLen == 5 && !memcmp(fmt, "%d %s", 5)) {
        size_t sl=0; const char* s=lua_tolstring_(L,3,&sl);
        if (s && sl < 3900) {
            char b[4096]; int nl=_snprintf(b,63,"%d ",(int)lua_tonumber_(L,2));
            if (nl > 0 && nl + sl < 4000) { memcpy(b+nl,s,sl); b[nl+sl]=0; lua_pushstring_(L,b); g_formatFastHits++; return 1; }
        }
    }
    // Fast: "%s: %s" — label: value pattern
    if (numArgs == 2 && fmtLen == 6 && !memcmp(fmt, "%s: %s", 6)) {
        size_t s1l=0, s2l=0;
        const char* s1 = lua_tolstring_(L, 2, &s1l);
        const char* s2 = lua_tolstring_(L, 3, &s2l);
        if (s1 && s2 && s1l + s2l + 2 < 4000) {
            char b[4096]; memcpy(b, s1, s1l); b[s1l]=':'; b[s1l+1]=' '; memcpy(b+s1l+2, s2, s2l); b[s1l+2+s2l]=0;
            lua_pushstring_(L, b); g_formatFastHits++; return 1;
        }
    }
    // Fast: "|c%s%s|r" — colored text (WoW color codes)
    if (numArgs == 2 && fmtLen == 8 && !memcmp(fmt, "|c%s%s|r", 8)) {
        size_t s1l=0, s2l=0;
        const char* s1 = lua_tolstring_(L, 2, &s1l);
        const char* s2 = lua_tolstring_(L, 3, &s2l);
        if (s1 && s2 && s1l + s2l + 4 < 4000) {
            char b[4096]; b[0]='|'; b[1]='c'; memcpy(b+2, s1, s1l); memcpy(b+2+s1l, s2, s2l);
            b[2+s1l+s2l]='|'; b[3+s1l+s2l]='r'; b[4+s1l+s2l]=0;
            lua_pushstring_(L, b); g_formatFastHits++; return 1;
        }
    }
    // Fast: "%.1f" / "%.2f" — single decimal float (HP/mana percentages)
    if (numArgs == 1 && fmtLen == 4 && fmt[0] == '%' && fmt[1] == '.' && fmt[3] == 'f' && fmt[2] >= '0' && fmt[2] <= '9') {
        char b[64]; _snprintf(b,63,fmt,lua_tonumber_(L,2)); b[63]=0;
        lua_pushstring_(L,b); g_formatFastHits++; return 1;
    }
    // Fast: %.Ng float
    if (numArgs == 1 && fmtLen == 4 && fmt[0] == '%' && fmt[1] == '.' && fmt[2] >= '0' && fmt[2] <= '9' && (fmt[3] == 'g' || fmt[3] == 'G')) {
        char b[64]; _snprintf(b,63,fmt,lua_tonumber_(L,2)); b[63]=0;
        if (b[0]) { lua_pushstring_(L,b); g_formatFastHits++; return 1; }
    }

    if (numArgs == 1 && fmtLen == 2 && fmt[0] == '%' && fmt[1] == 'd') {
        char buf[32];
        _snprintf(buf, 31, "%d", (int)lua_tonumber_(L, 2));
        buf[31] = '\0';
        lua_pushstring_(L, buf);
        g_formatFastHits++;
        return 1;
    }

    // Fast: "%s"
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

    // Fast: "%.Nf"
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

    // Fast: "%f" single float
    if (numArgs == 1 && fmtLen == 2 && fmt[0] == '%' && fmt[1] == 'f') {
        char buf[64];
        _snprintf(buf, 63, "%f", lua_tonumber_(L, 2));
        buf[63] = '\0';
        lua_pushstring_(L, buf);
        g_formatFastHits++;
        return 1;
    }

    // Fast: "%s: %s" — common in addon chat/log messages
    if (numArgs == 2 && fmtLen == 6 && !memcmp(fmt, "%s: %s", 6)) {
        size_t s1l=0, s2l=0;
        const char* s1=lua_tolstring_(L,2,&s1l);
        const char* s2=lua_tolstring_(L,3,&s2l);
        if (s1 && s2 && s1l < 512 && s2l < 512) {
            char b[1024]; _snprintf(b,1023,"%s: %s",s1,s2);
            b[1023]=0; lua_pushstring_(L,b); g_formatFastHits++; return 1;
        }
    }

    // Fast: "%s - %s" — common in addon UI labels
    if (numArgs == 2 && fmtLen == 7 && !memcmp(fmt, "%s - %s", 7)) {
        size_t s1l=0, s2l=0;
        const char* s1=lua_tolstring_(L,2,&s1l);
        const char* s2=lua_tolstring_(L,3,&s2l);
        if (s1 && s2 && s1l < 512 && s2l < 512) {
            char b[1024]; _snprintf(b,1023,"%s - %s",s1,s2);
            b[1023]=0; lua_pushstring_(L,b); g_formatFastHits++; return 1;
        }
    }

    // Fast: "%d/%d/%d" — common in date/version display
    if (numArgs == 3 && fmtLen == 8 && !memcmp(fmt, "%d/%d/%d", 8)) {
        char b[64]; _snprintf(b,63,"%d/%d/%d",(int)lua_tonumber_(L,2),(int)lua_tonumber_(L,3),(int)lua_tonumber_(L,4));
        b[63]=0; lua_pushstring_(L,b); g_formatFastHits++; return 1;
    }

    // Fast: "%02d:%02d:%02d" — time display with seconds
    if (numArgs == 3 && fmtLen == 11 && !memcmp(fmt, "%02d:%02d:%02d", 11)) {
        char b[64]; _snprintf(b,63,"%02d:%02d:%02d",(int)lua_tonumber_(L,2),(int)lua_tonumber_(L,3),(int)lua_tonumber_(L,4));
        b[63]=0; lua_pushstring_(L,b); g_formatFastHits++; return 1;
    }

    // Fast: "|c%s%s|r" — WoW color code wrapping
    if (numArgs == 2 && fmtLen == 8 && !memcmp(fmt, "|c%s%s|r", 8)) {
        size_t s1l=0, s2l=0;
        const char* s1=lua_tolstring_(L,2,&s1l);
        const char* s2=lua_tolstring_(L,3,&s2l);
        if (s1 && s2 && s1l < 16 && s2l < 512) {
            char b[544]; _snprintf(b,543,"|c%s%s|r",s1,s2);
            b[543]=0; lua_pushstring_(L,b); g_formatFastHits++; return 1;
        }
    }

    // Fast: "%s (%d)" — label with count
    if (numArgs == 2 && fmtLen == 7 && !memcmp(fmt, "%s (%d)", 7)) {
        size_t sl=0; const char* s=lua_tolstring_(L,2,&sl);
        if (s && sl < 256) {
            char b[320]; _snprintf(b,319,"%s (%d)",s,(int)lua_tonumber_(L,3));
            b[319]=0; lua_pushstring_(L,b); g_formatFastHits++; return 1;
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

// ================================================================
// Phase 2: runtime-discovered Lua function hooks.
//
// ================================================================

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

// ================================================================
    // Fast path for ^([^%s]+) — match first word/token
    // Common in chat parsing: "extract first word from string"
    // Pattern: ^ ( [ ^ % s ] + )
    // Length: 10
    // ================================================================
    if (pLen == 10 &&
        p[0] == '^' && p[1] == '(' && p[2] == '[' &&
        p[3] == '^' && p[4] == '%' && p[5] == 's' &&
        p[6] == ']' && p[7] == '+' && p[8] == ')') {
        
        // Find first whitespace character (ASCII <= 32 covers space, tab, newline, etc.)
        size_t end = 0;
        while (end < sLen && (unsigned char)s[end] > 32) {
            end++;
        }

        if (end > 0) {
            // Match found: return the token
            if (PushSubstring(L, s, end)) {
                g_matchHits++;
                return 1;
            }
        }
        
        // String starts with whitespace or is empty -> match fails (returns nil)
        lua_pushnil_(L);
        g_matchHits++;
        return 1;
    }

    // ================================================================
    // Fast path for ^(.-)%s*$ — trim trailing whitespace
    // Common in UI text cleanup.
    // Pattern: ^ ( . - ) % s * $
    // Length: 9
    // ================================================================
    if (pLen == 9 &&
        p[0] == '^' && p[1] == '(' && p[2] == '.' &&
        p[3] == '-' && p[4] == ')' && p[5] == '%' &&
        p[6] == 's' && p[7] == '*' && p[8] == '$') {
        
        // Find last non-whitespace character
        int last = (int)sLen - 1;
        while (last >= 0 && (unsigned char)s[last] <= 32) {
            last--;
        }

        // Return substring from 0 to last+1
        // If last < 0, string is all whitespace, return ""
        size_t len = (last < 0) ? 0 : (size_t)(last + 1);
        if (PushSubstring(L, s, len)) {
            g_matchHits++;
            return 1;
        }
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


    // Case 3: captured class (%d+), (%w+)
    if (pLen >= 5 && pLen <= 6 && p[pLen-2] == '%' && p[pLen-1] == '+') {
        int off = (p[0] == '^') ? 1 : 0;
        if ((pLen - off) == 5 && p[off] == '(' && p[off+4] == ')') {
            char cls = p[off+2];
            if (cls == 'd' || cls == 'a' || cls == 'w' || cls == 'l' || cls == 'u') {
                if (off && init != 1) { lua_pushnil_(L); g_matchHits++; return 1; }
                const char* start = off ? searchStart : s + (init - 1);
                size_t maxLen = off ? searchLen : sLen - (init - 1);
                size_t i = 0;
                while (i < maxLen && MatchAsciiClass((unsigned char)start[i], cls)) i++;
                if (i > 0 && PushSubstring(L, start, i)) { g_matchHits++; return 1; }
                lua_pushnil_(L); g_matchHits++; return 1;
            }
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
            size_t len = 0;
            const char* s = lua_tolstring_(L, 1, &len);
            if (s && len <= 4096) {
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
            break;
    }

tostring_fallback:
    g_tostringFallbacks++;
    return orig_luaB_tostring(L);
}

static lua_CFunction_t orig_luaB_tonumber = nullptr;

static int __cdecl Hooked_ToNumber_Global(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs != 1) return orig_luaB_tonumber(L);

    if (lua_type_(L, 1) == LUA_TNUMBER) {
        lua_pushnumber_(L, lua_tonumber_(L, 1));
        g_tonumberHits++;
        return 1;
    }

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

        // SAFETY: validate destination pointer before write
        if (!IsReadableMemory((uintptr_t)dst) || !IsReadableMemory((uintptr_t)dst + sizeof(RawTValue))) {
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

static lua_CFunction_t orig_luaB_next = nullptr;

static int __cdecl Hooked_Next_Global(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs != 1 && nargs != 2) {
        NoteNextFallback();
        return orig_luaB_next(L);
    }

    __try {
        RawTValue* base = GetStackBaseFast(L);
        RawTValue* top  = GetStackTopFast(L);
        if (!base || !top) {
            NoteNextFallback();
            return orig_luaB_next(L);
        }

        RawTValue* tableSlot = base;
        if (tableSlot->tt != LUA_TTABLE) {
            NoteNextFallback();
            return orig_luaB_next(L);
        }

        void* tablePtr = tableSlot->value.gc;
        if (!tablePtr) {
            NoteNextFallback();
            return orig_luaB_next(L);
        }

        RawTValue* keySlot = nullptr;

        if (nargs == 2) {
            keySlot = base + 1;
        } else {
            keySlot = top;
            keySlot->value.ptr = 0;
            keySlot->tt = LUA_TNIL;
            keySlot->taint = *(uint32_t*)ADDR_taint_global;
        }

        int more = lua_next_helper_(L, tablePtr, keySlot);
        if (more) {
            if (nargs == 2) {
                SetStackTopFast(L, top + 1);
            } else {
                SetStackTopFast(L, keySlot + 2);
            }

            NoteNextHit();
            return 2;
        }

        keySlot->value.ptr = 0;
        keySlot->tt = LUA_TNIL;
        keySlot->taint = *(uint32_t*)ADDR_taint_global;

        if (nargs == 1)
            SetStackTopFast(L, keySlot + 1);

        NoteNextHit();
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        NoteNextFallback();
        return orig_luaB_next(L);
    }
}

static lua_CFunction_t orig_tbl_insert = nullptr;

static int __cdecl Hooked_TableInsert(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs != 2) {
        NoteTableInsertFallback();
        return orig_tbl_insert(L);
    }

    __try {
        RawTValue* base = GetStackBaseFast(L);
        if (!base) {
            NoteTableInsertFallback();
            return orig_tbl_insert(L);
        }

        RawTValue* tableSlot = base;
        RawTValue* valueSlot = base + 1;

        if (tableSlot->tt != LUA_TTABLE) {
            NoteTableInsertFallback();
            return orig_tbl_insert(L);
        }

        if (valueSlot->tt == LUA_TNIL) {
            NoteTableInsertFallback();
            return orig_tbl_insert(L);
        }

        void* tablePtr = tableSlot->value.gc;
        if (!tablePtr) {
            NoteTableInsertFallback();
            return orig_tbl_insert(L);
        }

        unsigned int len = luaH_getn_(tablePtr);
        if (len >= 0x7FFFFFFF) {
            NoteTableInsertFallback();
            return orig_tbl_insert(L);
        }

        RawTValue* dst = (RawTValue*)luaH_setnum_(L, tablePtr, (int)(len + 1));
        if (!dst) {
            NoteTableInsertFallback();
            return orig_tbl_insert(L);
        }

        // SAFETY: validate destination pointer before write
        if (!IsReadableMemory((uintptr_t)dst) || !IsReadableMemory((uintptr_t)dst + sizeof(RawTValue))) {
            NoteTableInsertFallback();
            return orig_tbl_insert(L);
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

        NoteTableInsertHit();
        return 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        NoteTableInsertFallback();
        return orig_tbl_insert(L);
    }
}

static lua_CFunction_t orig_tbl_remove = nullptr;

static int __cdecl Hooked_TableRemove(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs != 1 && nargs != 2) {
        NoteTableRemoveFallback();
        return orig_tbl_remove(L);
    }

    __try {
        RawTValue* base = GetStackBaseFast(L);
        if (!base) {
            NoteTableRemoveFallback();
            return orig_tbl_remove(L);
        }

        RawTValue* tableSlot = base;
        if (tableSlot->tt != LUA_TTABLE) {
            NoteTableRemoveFallback();
            return orig_tbl_remove(L);
        }

        void* tablePtr = tableSlot->value.gc;
        if (!tablePtr) {
            NoteTableRemoveFallback();
            return orig_tbl_remove(L);
        }

        unsigned int len = luaH_getn_(tablePtr);

        if (nargs == 1) {
            if (len == 0) {
                memset(&tableSlot->value, 0, sizeof(tableSlot->value));
                tableSlot->tt = LUA_TNIL;
                tableSlot->taint = *(uint32_t*)ADDR_taint_global;
                NoteTableRemoveHit();
                return 1;
            }
        } else {
            if (len == 0) {
                NoteTableRemoveFallback();
                return orig_tbl_remove(L);
            }

            RawTValue* indexSlot = base + 1;
            if (indexSlot->tt != LUA_TNUMBER) {
                NoteTableRemoveFallback();
                return orig_tbl_remove(L);
            }

            double n = ReadRawNumber(indexSlot);
            int iv = (int)n;
            if ((double)iv != n || iv <= 0 || (unsigned int)iv != len) {
                NoteTableRemoveFallback();
                return orig_tbl_remove(L);
            }
        }

        RawTValue* src = (RawTValue*)luaH_getnum_(tablePtr, (int)len);
        if (!src || src->tt == LUA_TNIL) {
            NoteTableRemoveFallback();
            return orig_tbl_remove(L);
        }

        RawTValue* dst = (RawTValue*)luaH_setnum_(L, tablePtr, (int)len);
        if (!dst) {
            NoteTableRemoveFallback();
            return orig_tbl_remove(L);
        }

        RawTValue* resultSlot = (nargs == 1) ? tableSlot : (base + 1);
        *resultSlot = *src;

        if (resultSlot->taint) {
            if (*(int*)ADDR_taint_enabled && !*(int*)ADDR_taint_skip)
                *(uint32_t*)ADDR_taint_global = resultSlot->taint;
        } else {
            resultSlot->taint = *(uint32_t*)ADDR_taint_global;
        }

        memset(&dst->value, 0, sizeof(dst->value));
        dst->tt = LUA_TNIL;
        dst->taint = *(uint32_t*)ADDR_taint_global;

        NoteTableRemoveHit();
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        NoteTableRemoveFallback();
        return orig_tbl_remove(L);
    }
}

static int __cdecl Hooked_TableConcat(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs < 1 || nargs > 4) {
        g_tblConcatFallbacks++;
        return orig_tbl_concat(L);
    }

    __try {
        RawTValue* base = GetStackBaseFast(L);
        if (!base) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }

        RawTValue* tableSlot = base;
        if (tableSlot->tt != LUA_TTABLE) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }
        void* tablePtr = tableSlot->value.gc;
        if (!tablePtr) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }

        // Separator (default "")
        const char* sep = "";
        size_t sepLen = 0;
        if (nargs >= 2) {
            RawTValue* sepSlot = &base[1];
            if (sepSlot->tt == LUA_TSTRING) {
                void* ts = sepSlot->value.gc;
                if (ts) {
                    sepLen = (size_t)*(uint32_t*)((char*)ts + 8);
                    sep = (const char*)((char*)ts + 16);
                    if (!sep) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }
                }
            } else if (sepSlot->tt != LUA_TNIL) {
                g_tblConcatFallbacks++; return orig_tbl_concat(L);
            }
        }

        // Start/End indices
        int start = 1;
        int end = (int)luaH_getn_(tablePtr);
        if (nargs >= 3) {
            RawTValue* sSlot = &base[2];
            if (sSlot->tt == LUA_TNUMBER) {
                double n = ReadRawNumber(sSlot);
                start = (int)n;
                if (n != start || start < 1) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }
            } else {
                g_tblConcatFallbacks++; return orig_tbl_concat(L);
            }
        }
        if (nargs >= 4) {
            RawTValue* eSlot = &base[3];
            if (eSlot->tt == LUA_TNUMBER) {
                double n = ReadRawNumber(eSlot);
                end = (int)n;
                if (n != end || end < start) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }
            } else {
                g_tblConcatFallbacks++; return orig_tbl_concat(L);
            }
        }

        if (start > end) {
            lua_pushstring_(L, "");
            g_tblConcatHits++;
            return 1;
        }

        int count = end - start + 1;
        int seps = (count > 0 && sepLen > 0) ? (count - 1) : 0;

        // Guard against massive arrays
        if (count > 8192) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }

        // Pass 1: validate all elements are strings & compute total length
        size_t totalLen = 0;
        for (int i = 0; i < count; i++) {
            RawTValue* val = (RawTValue*)luaH_getnum_(tablePtr, start + i);
            if (!val || val->tt != LUA_TSTRING) {
                g_tblConcatFallbacks++;
                return orig_tbl_concat(L);
            }
            totalLen += *(uint32_t*)((uintptr_t)val->value.gc + 0x10);
        }

        if (seps > 0) {
            if (totalLen + (size_t)seps * sepLen < totalLen) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }
            totalLen += (size_t)seps * sepLen;
        }

        // Hard allocation limit for safety
        if (totalLen > 32768) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }

        // Allocate & fill
        char* buf = (char*)mi_malloc(totalLen + 1);
        if (!buf) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }

        char* p = buf;
        for (int i = 0; i < count; i++) {
            RawTValue* val = (RawTValue*)luaH_getnum_(tablePtr, start + i);
            if (!val || val->tt != LUA_TSTRING) { mi_free(buf); g_tblConcatFallbacks++; return orig_tbl_concat(L); }

            // SAFETY: validate GC string object before direct memory read
            uintptr_t gcPtr = (uintptr_t)val->value.gc;
            if (!gcPtr || !IsReadableMemory(gcPtr) || !IsReadableMemory(gcPtr + 0x14)) { mi_free(buf); g_tblConcatFallbacks++; return orig_tbl_concat(L); }

            // Validate string type byte at offset 9 (LUA_TSTRING = 4)
            uint8_t typeByte = *(uint8_t*)(gcPtr + 9);
            if ((typeByte & 0x1F) != 4) { mi_free(buf); g_tblConcatFallbacks++; return orig_tbl_concat(L); }

            size_t slen = *(uint32_t*)(gcPtr + 0x08);      // len is at offset +8
            if (slen == 0 || slen > 32768) { mi_free(buf); g_tblConcatFallbacks++; return orig_tbl_concat(L); }

            const char* sdata = (const char*)(gcPtr + 0x10); // str[0] is at offset +16

            __try {
                memcpy(p, sdata, slen);
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                mi_free(buf); g_tblConcatFallbacks++; return orig_tbl_concat(L);
            }
            p += slen;

            if (i < count - 1 && sepLen > 0) {
                memcpy(p, sep, sepLen);
                p += sepLen;
            }
        }
        *p = '\0';

        // Intern string
        void* ts = luaS_newlstr_(L, buf, totalLen);
        mi_free(buf);
        if (!ts) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }

        // Push result
        RawTValue* top = GetStackTopFast(L);
        if (!top) { g_tblConcatFallbacks++; return orig_tbl_concat(L); }
        top->value.gc = ts;
        top->tt = LUA_TSTRING;
        top->taint = *(uint32_t*)ADDR_taint_global;
        SetStackTopFast(L, top + 1);

        g_tblConcatHits++;
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        g_tblConcatFallbacks++;
        return orig_tbl_concat(L);
    }
}

static int __cdecl Hooked_Unpack(lua_State* L) {
    __try {
        RawTValue* base = GetStackBaseFast(L);
        if (!base) goto fallback;

        RawTValue* tableSlot = base;
        if (tableSlot->tt != LUA_TTABLE) goto fallback;
        void* tablePtr = tableSlot->value.gc;
        if (!tablePtr) goto fallback;

        int nargs = lua_gettop_(L);
        int start = 1;
        int end   = (int)luaH_getn_(tablePtr);

        if (nargs >= 2) {
            if (lua_type_(L, 2) == LUA_TNUMBER) {
                double s = ReadRawNumber(base + 1);
                start = (int)s;
                if (s != start) goto fallback;
            } else if (lua_type_(L, 2) != LUA_TNIL) {
                goto fallback;
            }
        }
        if (nargs >= 3) {
            if (lua_type_(L, 3) == LUA_TNUMBER) {
                double e = ReadRawNumber(base + 2);
                end = (int)e;
                if (e != end) goto fallback;
            } else if (lua_type_(L, 3) != LUA_TNIL) {
                goto fallback;
            }
        }

        int count = end - start + 1;
        if (count <= 0 || count > 256) goto fallback;

        RawTValue* top = GetStackTopFast(L);
        if (!top) goto fallback;

        for (int i = 0; i < count; i++) {
            RawTValue* val = (RawTValue*)luaH_getnum_(tablePtr, start + i);
            if (!val || val->tt == LUA_TNIL) goto fallback;

            // SAFETY: validate GC object pointer before copy
            if (val->tt >= LUA_TSTRING && (!val->value.gc || !IsReadableMemory((uintptr_t)val->value.gc)))
                goto fallback;

            *top = *val;
            top++;
        }
        SetStackTopFast(L, top);

        g_unpackHits++;
        return count;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}
fallback:
    g_unpackFallbacks++;
    return orig_luaB_unpack(L);
}

static int __cdecl Hooked_Select(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs < 1) goto fallback;

    if (lua_type_(L, 1) == LUA_TSTRING) {
        size_t len = 0;
        const char* s = lua_tolstring_(L, 1, &len);
        if (len == 1 && s[0] == '#') {
            lua_pushnumber_(L, (double)(nargs - 1));
            g_selectHits++;
            return 1;
        }
        // Non-'#' string index is an error in Lua — fall through to original
        goto fallback;
    }

    if (lua_type_(L, 1) == LUA_TNUMBER) {
        double nd = lua_tonumber_(L, 1);
        int n = (int)nd;
        if (nd != n) goto fallback;

        // Negative index: select(-1, a, b, c) returns last argument
        // Lua spec: negative n counts from the end of the argument list
        if (n < 0) {
            n = nargs + n; // e.g. nargs=4, n=-1 -> n=3 (select from index 3)
            if (n < 1) goto fallback; // e.g. select(-999, ...) out of range
        }

        if (n < 1 || n >= nargs) goto fallback;

        // Return values at indices n+1 through nargs.
        // The VM copies these from the stack automatically.
        int ret = nargs - n;
        g_selectHits++;
        return ret;
    }

fallback:
    g_selectFallbacks++;
    return orig_luaB_select(L);
}

static int __cdecl Hooked_RawEqual(lua_State* L) {
    if (lua_gettop_(L) != 2) goto fallback;

    int t1 = lua_type_(L, 1);
    int t2 = lua_type_(L, 2);

    // Type mismatch -> not equal
    if (t1 != t2) {
        lua_pushboolean_(L, 0);
        g_rawequalHits++;
        return 1;
    }

    // Type match — nil is always equal
    if (t1 == LUA_TNIL) {
        lua_pushboolean_(L, 1);
        g_rawequalHits++;
        return 1;
    }

    // All other types — fallback to original for safety
    goto fallback;

fallback:
    g_rawequalFallbacks++;
    return orig_luaB_rawequal(L);
}

// ================================================================
// Hooked_Math_Random — math.random fast path
// CRT rand() call without Lua VM overhead.
// ================================================================

static int __cdecl Hooked_Math_Random(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs > 2) { g_mathRandomFallbacks++; return orig_math_random(L); }

    if (nargs == 0) {
        // No args: return [0, 1)
        double r = (double)rand() / (double)RAND_MAX;
        lua_pushnumber_(L, r);
        g_mathRandomHits++;
        return 1;
    }

    // Check all args are numbers
    for (int i = 1; i <= nargs; i++) {
        if (lua_type_(L, i) != LUA_TNUMBER) { g_mathRandomFallbacks++; return orig_math_random(L); }
    }

    if (nargs == 1) {
        // 1 arg: return [1, n]
        int n = (int)lua_tonumber_(L, 1);
        if (n < 1) { g_mathRandomFallbacks++; return orig_math_random(L); }
        double r = 1.0 + (double)(rand() % n);
        lua_pushnumber_(L, r);
        g_mathRandomHits++;
        return 1;
    }

    // 2 args: return [m, n]
    int m = (int)lua_tonumber_(L, 1);
    int n = (int)lua_tonumber_(L, 2);
    if (n < m) { g_mathRandomFallbacks++; return orig_math_random(L); }
    int range = n - m + 1;
    double r = (double)m + (double)(rand() % range);
    lua_pushnumber_(L, r);
    g_mathRandomHits++;
    return 1;
}

// ================================================================
// Hooked_Math_Sqrt — math.sqrt fast path
// CRT sqrt() call without Lua VM overhead.
// ================================================================

static int __cdecl Hooked_Math_Sqrt(lua_State* L) {
    if (lua_type_(L, 1) == LUA_TNUMBER) {
        double v = lua_tonumber_(L, 1);
        lua_pushnumber_(L, sqrt(v));
        g_mathSqrtHits++;
        return 1;
    }
    g_mathSqrtFallbacks++;
    return orig_math_sqrt(L);
}

// ================================================================
// Hooked_StrRep — string.rep fast path
// Repeat string N times without Lua VM overhead.
// ================================================================

static int __cdecl Hooked_StrRep(lua_State* L) {
    if (lua_type_(L, 1) != LUA_TSTRING || lua_type_(L, 2) != LUA_TNUMBER) {
        g_strRepFallbacks++;
        return orig_str_rep(L);
    }

    size_t sLen = 0;
    const char* s = lua_tolstring_(L, 1, &sLen);
    if (!s || sLen == 0 || sLen > 1024) { g_strRepFallbacks++; return orig_str_rep(L); }

    int n = (int)lua_tonumber_(L, 2);
    if (n < 0 || n > 10000) { g_strRepFallbacks++; return orig_str_rep(L); }

    size_t totalLen = sLen * (size_t)n;
    if (totalLen > 65536 || totalLen == 0) { g_strRepFallbacks++; return orig_str_rep(L); }

    // Safety: check for embedded NULs in source
    for (size_t i = 0; i < sLen; i++) {
        if (s[i] == '\0') { g_strRepFallbacks++; return orig_str_rep(L); }
    }

    // Build result
    char* buf = (char*)mi_malloc(totalLen + 1);
    if (!buf) { g_strRepFallbacks++; return orig_str_rep(L); }

    char* p = buf;
    for (int i = 0; i < n; i++) {
        memcpy(p, s, sLen);
        p += sLen;
    }
    *p = '\0';

    lua_pushstring_(L, buf);
    mi_free(buf);
    g_strRepHits++;
    return 1;
}

// ================================================================
// Hooked_IPairs_Factory — ipairs() factory fast path
// Optimized ipairs() factory that returns our fast iterator.
// ================================================================

static int __cdecl Hooked_IPairs_Factory(lua_State* L) {
    __try {
        // Check that we have at least 1 argument
        if (lua_gettop_(L) < 1) {
            g_ipairsFactoryFalls++;
            return orig_luaB_ipairs(L);
        }

        // Check that argument is a table
        if (lua_type_(L, 1) != LUA_TTABLE) {
            g_ipairsFactoryFalls++;
            return orig_luaB_ipairs(L);
        }

        // Return our custom closure with upvalues:
        // Stack: [table]
        lua_pushvalue_(L, 1);        // [table, table]           - upvalue 1: table
        lua_pushnumber_(L, 0.0);     // [table, table, 0]        - upvalue 2: initial index
        lua_pushcclosure_(L, Hooked_IPairs_Iterator, 2);  // [table, closure] - consumes 2 upvalues
        lua_insert_(L, -2);          // [closure, table]
        lua_pushnumber_(L, 0.0);     // [closure, table, 0]

        g_ipairsFactoryHits++;
        return 3;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        g_ipairsFactoryFalls++;
        return orig_luaB_ipairs(L);
    }
}

// ================================================================
// Hooked_IPairs_Iterator — ipairs iterator fast path
// Fast numeric table iteration via luaH_getnum (bypasses lua_gettable).
// ================================================================

static int __cdecl Hooked_IPairs_Iterator(lua_State* L) {
    __try {
        // Get upvalue 1: table pointer
        void* tablePtr = (void*)lua_topointer_(L, lua_upvalueindex(1));
        if (!tablePtr) {
            g_ipairsIteratorFalls++;
            return orig_luaB_ipairs(L);
        }

        // Get upvalue 2: current index
        if (lua_type_(L, lua_upvalueindex(2)) != LUA_TNUMBER) {
            g_ipairsIteratorFalls++;
            return orig_luaB_ipairs(L);
        }

        int idx = (int)lua_tonumber_(L, lua_upvalueindex(2));
        idx++;  // next index

        // Direct table lookup via luaH_getnum
        RawTValue* valSlot = (RawTValue*)luaH_getnum_(tablePtr, idx);
        if (!valSlot || valSlot->tt == LUA_TNIL) {
            // End of array
            return 0;
        }

        // Update upvalue: current_index = idx
        lua_pushnumber_(L, (double)idx);
        lua_replace_(L, lua_upvalueindex(2));

        // Return: idx, value
        lua_pushnumber_(L, (double)idx);

        switch (valSlot->tt) {
            case LUA_TNIL:     lua_pushnil_(L); break;
            case LUA_TBOOLEAN: lua_pushboolean_(L, valSlot->value.ptr != 0); break;
            case LUA_TNUMBER: {
                double d; memcpy(&d, &valSlot->value, sizeof(double));
                lua_pushnumber_(L, d); break;
            }
            case LUA_TSTRING:  lua_pushstring_(L, (const char*)valSlot->value.gc); break;
            case LUA_TTABLE:
            case LUA_TFUNCTION:
            case LUA_TTHREAD:
            case LUA_TUSERDATA: lua_pushvalue_(L, lua_upvalueindex(1)); break;  // return table reference
            default:           lua_pushnil_(L); break;
        }

        g_ipairsIteratorHits++;
        return 2;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        g_ipairsIteratorFalls++;
        return orig_luaB_ipairs(L);
    }
}

// Phase 2: discovery and hook installation.

// ================================================================
// Hooked_StrFind_Full — string.find with pattern matching
// Full string.find with Lua pattern support (not just plain mode).
// ================================================================

static int __cdecl Hooked_StrFind_Full(lua_State* L) {
    int nargs = lua_gettop_(L);
    if (nargs < 2) return orig_str_find_full(L);

    if (lua_type_(L, 1) != LUA_TSTRING || lua_type_(L, 2) != LUA_TSTRING)
        return orig_str_find_full(L);

    size_t sLen = 0, pLen = 0;
    const char* s = lua_tolstring_(L, 1, &sLen);
    const char* p = lua_tolstring_(L, 2, &pLen);
    if (!s || !p || sLen > 8192 || pLen > 256) return orig_str_find_full(L);

    // If plain mode (4th arg true), use existing plain hook
    if (nargs >= 4 && lua_toboolean_(L, 4))
        return orig_str_find_full(L);

    // Safety: bail on embedded NULs
    if (HasEmbeddedNul(s, sLen) || HasEmbeddedNul(p, pLen))
        return orig_str_find_full(L);

    // Fast: anchored literal "^text"
    if (pLen > 1 && p[0] == '^' && IsPlainLiteralPattern(p + 1, pLen - 1)) {
        int init = 1;
        if (nargs >= 3 && lua_type_(L, 3) == LUA_TNUMBER)
            init = (int)lua_tonumber_(L, 3);
        if (init < 0) init = (int)sLen + init + 1;
        if (init < 1) init = 1;

        if (init == 1 && (pLen - 1) <= sLen && memcmp(s, p + 1, pLen - 1) == 0) {
            lua_pushnumber_(L, 1.0);
            lua_pushnumber_(L, (double)(int)(pLen - 1));
            g_findFullHits++;
            return 2;
        }
        lua_pushnil_(L);
        g_findFullHits++;
        return 1;
    }

    // Fast: single char pattern (no magic)
    if (pLen == 1 && !IsPatternMagicChar(p[0])) {
        int init = 1;
        if (nargs >= 3 && lua_type_(L, 3) == LUA_TNUMBER)
            init = (int)lua_tonumber_(L, 3);
        if (init < 0) init = (int)sLen + init + 1;
        if (init < 1) init = 1;
        if (init > (int)sLen + 1) { lua_pushnil_(L); g_findFullHits++; return 1; }

        const char* found = (const char*)memchr(s + init - 1, p[0], sLen - init + 1);
        if (found) {
            int pos = (int)(found - s) + 1;
            lua_pushnumber_(L, (double)pos);
            lua_pushnumber_(L, (double)pos);
        } else {
            lua_pushnil_(L);
        }
        g_findFullHits++;
        return found ? 2 : 1;
    }

    g_findFullFallbacks++;
    return orig_str_find_full(L);
}

// ================================================================
#if !TEST_DISABLE_ALL_PHASE2

struct FuncHookEntry {
    const char*        table;
    const char*        name;
    void*              hookFn;
    lua_CFunction_t*   origFn;
    uintptr_t          address;
    bool               hooked;
};

static int __cdecl Hooked_UnitHealth(lua_State* L);
static int __cdecl Hooked_UnitHealthMax(lua_State* L);
static int __cdecl Hooked_UnitPower(lua_State* L);
static int __cdecl Hooked_UnitPowerMax(lua_State* L);

static lua_CFunction_t orig_UnitHealth      = nullptr;
static lua_CFunction_t orig_UnitHealthMax   = nullptr;
static lua_CFunction_t orig_UnitPower       = nullptr;
static lua_CFunction_t orig_UnitPowerMax    = nullptr;

#if !TEST_DISABLE_TABLE_SORT_FASTPATH
static int __cdecl Hooked_TableSort(lua_State* L) {
    __try {
        RawTValue* base = GetStackBaseFast(L);
        if (!base || base->tt != LUA_TTABLE) goto fallback;

        void* tablePtr = base->value.gc;
        if (!tablePtr) goto fallback;

        int sizearray = *(int*)((char*)tablePtr + 32);
        if (sizearray < 2 || sizearray > 100000) goto fallback;

        int* array = *(int**)((char*)tablePtr + 16);
        if (!array) goto fallback;

        bool isNumber = true;
        bool isString = true;

        for (int i = 0; i < sizearray; i++) {
            int tt = array[i * 4 + 2];
            if (tt != LUA_TNUMBER) isNumber = false;
            if (tt != LUA_TSTRING) isString = false;
            if (!isNumber && !isString) goto fallback;
        }

        if (isNumber) {
            std::sort(array, array + sizearray, [](int a, int b) {
                double da, db;
                memcpy(&da, (void*)(uintptr_t)a, sizeof(double));
                memcpy(&db, (void*)(uintptr_t)b, sizeof(double));
                return da < db;
            });
        } else {
            std::sort(array, array + sizearray, [](int a, int b) {
                const char* sa = (const char*)((char*)a + 16);
                const char* sb = (const char*)((char*)b + 16);
                int la = *(int*)((char*)a + 8);
                int lb = *(int*)((char*)b + 8);
                int cmp = memcmp(sa, sb, (la < lb) ? la : lb);
                if (cmp != 0) return cmp < 0;
                return la < lb;
            });
        }

        g_tableSortHits++;
        return 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

fallback:
    g_tableSortFallbacks++;
    return orig_table_sort(L);
}
#endif // !TEST_DISABLE_TABLE_SORT_FASTPATH

static FuncHookEntry g_funcHooks[] = {
    {"string", "find",     (void*)Hooked_StrFind,          &orig_str_find,         0, false},
    {"string", "match",    (void*)Hooked_StrMatch,         &orig_str_match,        0, false},
    {nullptr,  "type",     (void*)Hooked_Type,             &orig_luaB_type,        0, false},
    {"math",   "floor",    (void*)Hooked_MathFloor,        &orig_math_floor,       0, false},
    {"math",   "ceil",     (void*)Hooked_MathCeil,         &orig_math_ceil,        0, false},
    {"math",   "abs",      (void*)Hooked_MathAbs,          &orig_math_abs,         0, false},
    {"math",   "max",      (void*)Hooked_MathMax,          &orig_math_max,         0, false},
    {"math",   "min",      (void*)Hooked_MathMin,          &orig_math_min,         0, false},
    {"string", "len",      (void*)Hooked_StrLen,           &orig_str_len,          0, false},
    {"string", "byte",     (void*)Hooked_StrByte,          &orig_str_byte,         0, false},
    {nullptr,  "tostring", (void*)Hooked_ToString,         &orig_luaB_tostring,    0, false},
    {nullptr,  "tonumber", (void*)Hooked_ToNumber_Global,  &orig_luaB_tonumber,    0, false},
    // PERMANENTLY DISABLED: All RawTValue write hooks cause luaH_getstr crashes
    // These hooks write to RawTValue* which corrupts Lua table internals during
    // world entry and heavy addon loading (WeakAuras /wa crash at 0x0085C457)
    // {nullptr,  "next",     (void*)Hooked_Next_Global,      &orig_luaB_next,        0, false},
    // {nullptr,  "rawget",   (void*)Hooked_RawGet_Global,    &orig_luaB_rawget,      0, false},
    // {nullptr,  "rawset",   (void*)Hooked_RawSet_Global,    &orig_luaB_rawset,      0, false},
    // {"table",  "insert",   (void*)Hooked_TableInsert,      &orig_tbl_insert,       0, false},
    // {"table",  "remove",   (void*)Hooked_TableRemove,      &orig_tbl_remove,       0, false},
    // {"table",  "concat",   (void*)Hooked_TableConcat,      &orig_tbl_concat,         0, false},
    // {nullptr,  "unpack",   (void*)Hooked_Unpack,           &orig_luaB_unpack,        0, false},
    {nullptr,  "select",   (void*)Hooked_Select,           &orig_luaB_select,        0, false},
    {nullptr,  "rawequal", (void*)Hooked_RawEqual,         &orig_luaB_rawequal,      0, false},
    {"string", "sub",      (void*)Hooked_StrSub,           &orig_str_sub,          0, false},
    {"string", "lower",    (void*)Hooked_StrLower,         &orig_str_lower,        0, false},
    {"string", "upper",    (void*)Hooked_StrUpper,         &orig_str_upper,        0, false},
#if !TEST_DISABLE_TABLE_SORT_FASTPATH
    {nullptr, "sort", (void*)Hooked_TableSort, &orig_table_sort, 0x00851E00, false},
#endif    
#if 0  // UnitAPI DMA disabled — STACK_OVERFLOW (1.9B recursive calls)
    {nullptr, "UnitHealth",   (void*)Hooked_UnitHealth,    &orig_UnitHealth,    0x0060EB60, false},
    {nullptr, "UnitHealthMax", (void*)Hooked_UnitHealthMax, &orig_UnitHealthMax, 0x0060EC60, false},
    {nullptr, "UnitPower",    (void*)Hooked_UnitPower,     &orig_UnitPower,     0x0060ED40, false},
    {nullptr, "UnitPowerMax", (void*)Hooked_UnitPowerMax,  &orig_UnitPowerMax,  0x0060EF40, false},
#endif    
#if !TEST_DISABLE_HOOK_MATH_RANDOM
    {"math",   "random",   (void*)Hooked_Math_Random,      &orig_math_random,      0x00851100, false},
#endif
#if !TEST_DISABLE_HOOK_MATH_SQRT
    {"math",   "sqrt",     (void*)Hooked_Math_Sqrt,        &orig_math_sqrt,        0x00851360, false},
#endif
    {"string", "rep",      (void*)Hooked_StrRep,           &orig_str_rep,          0x00852780, false},
#if !TEST_DISABLE_HOOK_IPAIRS
    {nullptr,  "ipairs",   (void*)Hooked_IPairs_Factory,   &orig_luaB_ipairs,      0, false},
#endif
};

static constexpr int NUM_FUNC_HOOKS = sizeof(g_funcHooks) / sizeof(g_funcHooks[0]);

#else

// Permanently disabled — all Phase 2 hooks disabled for testing
static constexpr int NUM_FUNC_HOOKS = 0;

#endif // TEST_DISABLE_ALL_PHASE2

// ================================================================
// Unit API Fast Paths — Direct CGUnit_C field reads
// ================================================================

// ================================================================
// Unit API Fast Paths Implementation
// ================================================================

#if 0  // UnitAPI DMA disabled — STACK_OVERFLOW (1.9B recursive calls)

typedef void (__cdecl* fn_ParseUnitToken)(const char* str, int* out_token, int flags);
typedef void*(__cdecl* fn_ResolveUnit)(int token_low, int token_high, int flags);
typedef int (__cdecl* fn_GetPowerDivisor)(int powerType);

static fn_ParseUnitToken  orig_ParseUnitToken  = (fn_ParseUnitToken)0x0060ABF0;
static fn_ResolveUnit     orig_ResolveUnit     = (fn_ResolveUnit)0x004D4DB0;
static fn_GetPowerDivisor orig_GetPowerDivisor = (fn_GetPowerDivisor)0x007FDE00;

static constexpr uintptr_t CGUNIT_M_VALUES_OFFS = 0xD0;
static constexpr uintptr_t CGUNIT_POWER_TYPE_OFFS = 0x47;
static constexpr uintptr_t CGUNIT_FLAGS_OFFS = 0x124;

static constexpr int UNIT_FIELD_HEALTH      = 73;
static constexpr int UNIT_FIELD_MAXHEALTH   = 26;
static constexpr int UNIT_FIELD_POWER_BASE  = 19;
static constexpr int UNIT_FIELD_MAXPOWER_BASE = 27;

static long g_unitHealthHits = 0;
static long g_unitHealthFallbacks = 0;
static long g_unitHealthMaxHits = 0;
static long g_unitHealthMaxFallbacks = 0;
static long g_unitPowerHits = 0;
static long g_unitPowerFallbacks = 0;
static long g_unitPowerMaxHits = 0;
static long g_unitPowerMaxFallbacks = 0;

static int __cdecl Hooked_UnitHealth(lua_State* L) {
    __try {
        RawTValue* base = GetStackBaseFast(L);
        if (!base || base->tt != 4) goto fallback;

        size_t unitLen = 0;
        const char* unitStr = lua_tolstring_(L, 1, &unitLen);
        if (!unitStr || unitLen == 0 || unitLen > 64) goto fallback;

        int token[2] = {0, 0};
        orig_ParseUnitToken(unitStr, token, 0);

        void* unitObj = orig_ResolveUnit(token[0], token[1], 8);
        if (!unitObj) goto fallback;

        uintptr_t ptr = (uintptr_t)unitObj;
        if (ptr < 0x10000 || ptr > 0xBFFF0000) goto fallback;
        if (!IsReadableMemory(ptr + CGUNIT_M_VALUES_OFFS)) goto fallback;

        void* m_values = *(void**)(ptr + CGUNIT_M_VALUES_OFFS);
        if (!m_values) goto fallback;
        if (!IsReadableMemory((uintptr_t)m_values + UNIT_FIELD_HEALTH * 4)) goto fallback;

        int health = *(int*)((char*)m_values + UNIT_FIELD_HEALTH * 4);

        RawTValue* top = GetStackTopFast(L);
        if (!top) goto fallback;

        top->value.n = (double)health;
        top->tt      = 3;
        top->taint   = *(uint32_t*)0x00D4139C;
        SetStackTopFast(L, top + 1);

        g_unitHealthHits++;
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

fallback:
    g_unitHealthFallbacks++;
    return orig_UnitHealth(L);
}

static int __cdecl Hooked_UnitHealthMax(lua_State* L) {
    __try {
        RawTValue* base = GetStackBaseFast(L);
        if (!base || base->tt != 4) goto fallback;

        size_t unitLen = 0;
        const char* unitStr = lua_tolstring_(L, 1, &unitLen);
        if (!unitStr || unitLen == 0 || unitLen > 64) goto fallback;

        int token[2] = {0, 0};
        orig_ParseUnitToken(unitStr, token, 0);

        void* unitObj = orig_ResolveUnit(token[0], token[1], 8);
        if (!unitObj) goto fallback;

        uintptr_t ptr = (uintptr_t)unitObj;
        if (ptr < 0x10000 || ptr > 0xBFFF0000) goto fallback;
        if (!IsReadableMemory(ptr + CGUNIT_M_VALUES_OFFS)) goto fallback;

        void* m_values = *(void**)(ptr + CGUNIT_M_VALUES_OFFS);
        if (!m_values) goto fallback;
        if (!IsReadableMemory((uintptr_t)m_values + UNIT_FIELD_MAXHEALTH * 4)) goto fallback;

        int maxHealth = *(int*)((char*)m_values + UNIT_FIELD_MAXHEALTH * 4);

        RawTValue* top = GetStackTopFast(L);
        if (!top) goto fallback;

        top->value.n = (double)maxHealth;
        top->tt      = 3;
        top->taint   = *(uint32_t*)0x00D4139C;
        SetStackTopFast(L, top + 1);

        g_unitHealthMaxHits++;
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

fallback:
    g_unitHealthMaxFallbacks++;
    return orig_UnitHealthMax(L);
}

static int __cdecl Hooked_UnitPower(lua_State* L) {
    __try {
        RawTValue* base = GetStackBaseFast(L);
        if (!base || base->tt != 4) goto fallback;

        size_t unitLen = 0;
        const char* unitStr = lua_tolstring_(L, 1, &unitLen);
        if (!unitStr || unitLen == 0 || unitLen > 64) goto fallback;

        int powerType = 0;
        int nargs = lua_gettop_(L);
        if (nargs >= 2 && lua_type_(L, 2) == 3) {
            powerType = (int)lua_tonumber_(L, 2);
            if (powerType < 0 || powerType > 7) goto fallback;
        }

        int token[2] = {0, 0};
        orig_ParseUnitToken(unitStr, token, 0);

        void* unitObj = orig_ResolveUnit(token[0], token[1], 8);
        if (!unitObj) goto fallback;

        uintptr_t ptr = (uintptr_t)unitObj;
        if (ptr < 0x10000 || ptr > 0xBFFF0000) goto fallback;
        if (!IsReadableMemory(ptr + CGUNIT_M_VALUES_OFFS)) goto fallback;

        void* m_values = *(void**)(ptr + CGUNIT_M_VALUES_OFFS);
        if (!m_values) goto fallback;

        int powerIndex = UNIT_FIELD_POWER1 + powerType;
        if (!IsReadableMemory((uintptr_t)m_values + powerIndex * 4)) goto fallback;

        int power = *(int*)((char*)m_values + powerIndex * 4);

        RawTValue* top = GetStackTopFast(L);
        if (!top) goto fallback;

        top->value.n = (double)power;
        top->tt      = 3;
        top->taint   = *(uint32_t*)0x00D4139C;
        SetStackTopFast(L, top + 1);

        g_unitPowerHits++;
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

fallback:
    g_unitPowerFallbacks++;
    return orig_UnitPower(L);
}

static int __cdecl Hooked_UnitPowerMax(lua_State* L) {
    __try {
        RawTValue* base = GetStackBaseFast(L);
        if (!base || base->tt != 4) goto fallback;

        size_t unitLen = 0;
        const char* unitStr = lua_tolstring_(L, 1, &unitLen);
        if (!unitStr || unitLen == 0 || unitLen > 64) goto fallback;

        int powerType = 0;
        int nargs = lua_gettop_(L);
        if (nargs >= 2 && lua_type_(L, 2) == 3) {
            powerType = (int)lua_tonumber_(L, 2);
            if (powerType < 0 || powerType > 7) goto fallback;
        }

        int token[2] = {0, 0};
        orig_ParseUnitToken(unitStr, token, 0);

        void* unitObj = orig_ResolveUnit(token[0], token[1], 8);
        if (!unitObj) goto fallback;

        uintptr_t ptr = (uintptr_t)unitObj;
        if (ptr < 0x10000 || ptr > 0xBFFF0000) goto fallback;
        if (!IsReadableMemory(ptr + CGUNIT_M_VALUES_OFFS)) goto fallback;

        void* m_values = *(void**)(ptr + CGUNIT_M_VALUES_OFFS);
        if (!m_values) goto fallback;

        int powerIndex = UNIT_FIELD_MAXPOWER1 + powerType;
        if (!IsReadableMemory((uintptr_t)m_values + powerIndex * 4)) goto fallback;

        int maxPower = *(int*)((char*)m_values + powerIndex * 4);

        RawTValue* top = GetStackTopFast(L);
        if (!top) goto fallback;

        top->value.n = (double)maxPower;
        top->tt      = 3;
        top->taint   = *(uint32_t*)0x00D4139C;
        SetStackTopFast(L, top + 1);

        g_unitPowerMaxHits++;
        return 1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

fallback:
    g_unitPowerMaxFallbacks++;
    return orig_UnitPowerMax(L);
}

#endif // UnitAPI DMA disabled

namespace LuaFastPath {

bool Init() {
    Log("[FastPath] ====================================");
    Log("[FastPath]  Lua Fast Path — Phase 1");
    Log("[FastPath] ====================================");

    __try {
        // Use MinHook on native Windows, or on Wine/Rosetta when JIT cache is disabled
        // (CrossOver on Apple Silicon runs WoW.exe through Rosetta underneath)
        bool useMinHook = g_rosettaCacheDisabled || (!IsWine() && !IsRosetta());

        if (!useMinHook) {
            // Legacy Rosetta-safe path: defer string.format hook to Phase 2 (Lua API path)
            // Phase 1 runs before lua_State is available, so we can't use Lua API yet.
            // Phase 2 will install it via lua_setfield (data write, no x86 patch).
            orig_str_format = (lua_CFunction_t)ADDR_str_format;
            Log("[FastPath]   string.format      0x%08X  [DEFERRED] (Lua API path, Phase 2)",
                (unsigned)ADDR_str_format);
        } else {
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
            Log("[FastPath]   string.format      0x%08X  [ OK ]%s",
                (unsigned)ADDR_str_format,
                g_rosettaCacheDisabled ? " (JIT cache disabled)" : "");
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[FastPath]   string.format: EXCEPTION");
        return false;
    }

    g_active = true;
    Log("[FastPath]  Phase 1 [ OK ] - string.format %s",
        (g_rosettaCacheDisabled || (!IsWine() && !IsRosetta())) ? "hooked" : "deferred to Phase 2");
    Log("[FastPath]  Phase 2 will run after Lua state ready");
    Log("[FastPath] ====================================");
    return true;
}

bool InitPhase2(lua_State* L) {
#if TEST_DISABLE_ALL_PHASE2
   (void)L;
    Log("[FastPath] Phase 2: DISABLED (production — permanently)");
    return false;
#else
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

        if (e.address == ADDR_str_format && (!IsWine() || g_rosettaCacheDisabled)) {
            // Phase 1 already installed inline hook (native Windows, or Wine/Rosetta with cache disabled)
            Log("[FastPath]   %-8s.%-8s  SKIP (already hooked in Phase 1)",
                e.table ? e.table : "_G", e.name);
            continue;
        }
        // On legacy Rosetta (without cache disabled), string.format was deferred from Phase 1.
        // Fall through to install via Lua API path below.

#if TEST_DISABLE_PHASE2_WRITES
        // Write hooks that modify Lua tables/stack
        // via RawTValue* copies — causes hangs in real gameplay
        if (strcmp(e.name, "rawset") == 0 ||
            strcmp(e.name, "insert") == 0 ||
            strcmp(e.name, "remove") == 0 ||
            strcmp(e.name, "next") == 0) {
            Log("[FastPath]   %-8s.%-8s  SKIP (unsafe — RawTValue* table writes)",
                e.table ? e.table : "_G", e.name);
            continue;
        }
#endif

#if TEST_DISABLE_PHASE2_READS
        // Table read hooks that write to stack
        // via RawTValue* copies — causes hangs in real gameplay
        if (strcmp(e.name, "rawget") == 0 ||
            strcmp(e.name, "concat") == 0 ||
            strcmp(e.name, "unpack") == 0) {
            Log("[FastPath]   %-8s.%-8s  SKIP (unsafe — RawTValue* stack writes)",
                e.table ? e.table : "_G", e.name);
            continue;
        }
#endif

#if TEST_DISABLE_PHASE2_NEW_DMA
        // Hooks that directly write to Lua tables/stack via RawTValue*
        // Cause hangs in real gameplay
        if (strcmp(e.name, "type") == 0 ||
            strcmp(e.name, "floor") == 0 ||
            strcmp(e.name, "ceil") == 0 ||
            strcmp(e.name, "abs") == 0 ||
            strcmp(e.name, "max") == 0 ||
            strcmp(e.name, "min") == 0 ||
            strcmp(e.name, "len") == 0 ||
            strcmp(e.name, "byte") == 0 ||
            strcmp(e.name, "tostring") == 0 ||
            strcmp(e.name, "tonumber") == 0 ||
            strcmp(e.name, "select") == 0 ||
            strcmp(e.name, "rawequal") == 0) {
            Log("[FastPath]   %-8s.%-8s  SKIP (unsafe — causes hangs)",
                e.table ? e.table : "_G", e.name);
            continue;
        }
#endif

        __try {
            // Use MinHook on native Windows, or on Wine/Rosetta when JIT cache is disabled
            // (CrossOver on Apple Silicon runs WoW.exe through Rosetta underneath)
            bool useMinHook = g_rosettaCacheDisabled || (!IsWine() && !IsRosetta());

            if (!useMinHook) {
                // ============================================================
                // Legacy Rosetta-safe path: replace lua_CFunction pointer via Lua API
                // This is a DATA write to Lua heap - no x86 code modification,
                // completely invisible to rosettax87 JIT translator.
                // ============================================================
                typedef void (__cdecl *fn_lua_setfield)(lua_State*, int, const char*);
                static fn_lua_setfield lua_setfield_ = (fn_lua_setfield)0x0084E900;

                // Validate Lua API function pointers before use
                if (!IsExecutable((uintptr_t)lua_getfield_) ||
                    !IsExecutable((uintptr_t)lua_type_) ||
                    !IsExecutable((uintptr_t)lua_settop_) ||
                    !IsExecutable((uintptr_t)lua_pushcclosure_) ||
                    !IsExecutable((uintptr_t)lua_setfield_) ||
                    !IsExecutable((uintptr_t)lua_pushvalue_)) {
                    Log("[FastPath]   %-8s.%-8s  SKIP (Lua API addresses invalid on Rosetta)",
                        e.table ? e.table : "_G", e.name);
                    continue;
                }

                // Get the table containing the function
                if (e.table) {
                    lua_getfield_(L, LUA_GLOBALSINDEX, e.table);
                    if (lua_type_(L, -1) != LUA_TTABLE) {
                        lua_settop_(L, -2); // pop non-table
                        Log("[FastPath]   %-8s.%-8s  SKIP (table not found)",
                            e.table, e.name);
                        continue;
                    }
                } else {
                    lua_pushvalue_(L, LUA_GLOBALSINDEX);
                }

                // Save original function pointer
                lua_getfield_(L, -1, e.name);
                if (lua_type_(L, -1) == LUA_TFUNCTION) {
                    // Store original as upvalue so our hook can call it
                    // For simplicity, store the address directly
                    *e.origFn = (lua_CFunction_t)e.address;
                } else {
                    lua_settop_(L, -3); // pop nil + table
                    Log("[FastPath]   %-8s.%-8s  SKIP (not a function)",
                        e.table ? e.table : "_G", e.name);
                    continue;
                }
                lua_settop_(L, -2); // pop old function, keep table

                // Push our hook as a C closure with original as upvalue
                lua_pushcclosure_(L, (int(__cdecl*)(lua_State*))e.hookFn, 0);
                lua_setfield_(L, -2, e.name);
                lua_settop_(L, -2); // pop table

                e.hooked = true;
                hookedNow++;
                hookedTotal++;
                Log("[FastPath]   %-8s.%-8s  0x%08X  [ OK ] (Lua API path)",
                    e.table ? e.table : "_G", e.name, (unsigned)e.address);
            } else {
                // MinHook inline hook path (native Windows, or Wine/Rosetta with cache disabled)
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
                Log("[FastPath]   %-8s.%-8s  0x%08X  [ OK ]%s",
                    e.table ? e.table : "_G", e.name, (unsigned)e.address,
                    g_rosettaCacheDisabled ? " (JIT cache disabled)" : "");
            }
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
#endif // TEST_DISABLE_ALL_PHASE2
}

void ResetPhase2Discovery() {
#if !TEST_DISABLE_ALL_PHASE2
    // Do NOT remove already installed hooks.
    // We only want late rediscovery for functions that were not found in glue VM.
    g_layout.valid = false;
#endif
}

void Shutdown() {
    if (g_active) {
        if (!IsWine()) {
            MH_DisableHook((void*)ADDR_str_format);
        }
        // On Wine/Rosetta, string.format was replaced via Lua API.
        // No MH_DisableHook needed - the replacement is just a data pointer
        // in Lua's table. WoW will clean up Lua state on exit anyway.
    }

#if !TEST_DISABLE_ALL_PHASE2
    for (int i = 0; i < NUM_FUNC_HOOKS; i++) {
        if (g_funcHooks[i].hooked && g_funcHooks[i].address) {
            if (!IsWine()) {
                MH_DisableHook((void*)g_funcHooks[i].address);
            }
            // On Wine/Rosetta: Lua API replacements are cleaned up with Lua state
            g_funcHooks[i].hooked = false;
        }
    }
#endif

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
    if (g_nextHits > 0 || g_nextFallbacks > 0)
        Log("[FastPath] Next: %ld fast, %ld fallback", g_nextHits, g_nextFallbacks);
    if (g_rawgetHits > 0 || g_rawgetFallbacks > 0)
        Log("[FastPath] RawGet: %ld fast, %ld fallback", g_rawgetHits, g_rawgetFallbacks);
    if (g_rawsetHits > 0 || g_rawsetFallbacks > 0)
        Log("[FastPath] RawSet: %ld fast, %ld fallback", g_rawsetHits, g_rawsetFallbacks);
    if (g_tblInsertHits > 0 || g_tblInsertFallbacks > 0)
        Log("[FastPath] TableInsert: %ld fast, %ld fallback", g_tblInsertHits, g_tblInsertFallbacks);
    if (g_tblRemoveHits > 0 || g_tblRemoveFallbacks > 0)
        Log("[FastPath] TableRemove: %ld fast, %ld fallback", g_tblRemoveHits, g_tblRemoveFallbacks);
    if (g_tblConcatHits > 0 || g_tblConcatFallbacks > 0)
        Log("[FastPath] TableConcat: %ld fast, %ld fallback", g_tblConcatHits, g_tblConcatFallbacks);
    if (g_unpackHits > 0 || g_unpackFallbacks > 0)
        Log("[FastPath] Unpack: %ld fast, %ld fallback", g_unpackHits, g_unpackFallbacks);
    if (g_selectHits > 0 || g_selectFallbacks > 0)
        Log("[FastPath] Select: %ld fast, %ld fallback", g_selectHits, g_selectFallbacks);        
    if (g_strsubHits > 0) Log("[FastPath] StrSub: %ld fast", g_strsubHits);
    if (g_strlowerHits > 0) Log("[FastPath] StrLower: %ld fast", g_strlowerHits);
    if (g_strupperHits > 0) Log("[FastPath] StrUpper: %ld fast", g_strupperHits);
    if (g_rawequalHits > 0 || g_rawequalFallbacks > 0)
        Log("[FastPath] RawEqual: %ld fast, %ld fallback", g_rawequalHits, g_rawequalFallbacks);
    if (g_ipairsFactoryHits > 0 || g_ipairsFactoryFalls > 0)
        Log("[FastPath] IPairs(factory): %ld hits, %ld fallbacks", g_ipairsFactoryHits, g_ipairsFactoryFalls);
    if (g_ipairsIteratorHits > 0 || g_ipairsIteratorFalls > 0)
        Log("[FastPath] IPairs(iterator): %ld fast, %ld fallbacks", g_ipairsIteratorHits, g_ipairsIteratorFalls);
    if (g_findFullHits > 0 || g_findFullFallbacks > 0)
        Log("[FastPath] Find(pattern): %ld fast, %ld fallback", g_findFullHits, g_findFullFallbacks);
    if (g_mathRandomHits > 0 || g_mathRandomFallbacks > 0)
        Log("[FastPath] Math.Random: %ld fast, %ld fallback", g_mathRandomHits, g_mathRandomFallbacks);
    if (g_mathSqrtHits > 0 || g_mathSqrtFallbacks > 0)
        Log("[FastPath] Math.Sqrt: %ld fast, %ld fallback", g_mathSqrtHits, g_mathSqrtFallbacks);
    if (g_strRepHits > 0 || g_strRepFallbacks > 0)
        Log("[FastPath] StrRep: %ld fast, %ld fallback", g_strRepHits, g_strRepFallbacks);

    g_active = false;
    g_phase2Active = false;
}

// ================================================================
// Phase 3: WoW C-level API hooks
//
// Permanently disabled — UnitName had 0% hit rate in real sessions.
// Dynamic units (raid1, nameplate1) change every frame — cache never
// reuses. Static units (player, target) are called once at UI load.
// Code kept available for future production use only.
// ================================================================

bool InitWoWHooks(lua_State* L) {
   (void)L;
    Log("[FastPath]  Phase 3 [ SKIP ] — WoW C-level API hooks disabled");
    return false;
}

void InvalidateWoWCache() {
    // No-op — reserved for future use
}

Stats GetStats() {
    Stats s;
    memset(&s, 0, sizeof(s));
    s.formatFastHits      = g_formatFastHits;
    s.formatFallbacks     = g_formatFallbacks;
    s.findPlainHits       = g_findPlainHits;
    s.findFallbacks       = g_findFallbacks;
    s.matchHits           = g_matchHits;
    s.matchFallbacks      = g_matchFallbacks;
    s.typeHits            = g_typeHits;
    s.typeFallbacks       = g_typeFallbacks;
    s.mathHits            = g_mathHits;
    s.mathFallbacks       = g_mathFallbacks;
    s.strlenHits          = g_strlenHits;
    s.strbyteHits         = g_strbyteHits;
    s.tostringHits        = g_tostringHits;
    s.tostringFallbacks   = g_tostringFallbacks;
    s.tonumberHits        = g_tonumberHits;
    s.nextHits            = g_nextHits;
    s.nextFallbacks       = g_nextFallbacks;
    s.rawgetHits          = g_rawgetHits;
    s.rawgetFallbacks     = g_rawgetFallbacks;
    s.rawsetHits          = g_rawsetHits;
    s.rawsetFallbacks     = g_rawsetFallbacks;
    s.tableInsertHits     = g_tblInsertHits;
    s.tableInsertFallbacks= g_tblInsertFallbacks;
    s.tableRemoveHits     = g_tblRemoveHits;
    s.tableRemoveFallbacks= g_tblRemoveFallbacks;
    s.strsubHits          = g_strsubHits;
    s.strlowerHits        = g_strlowerHits;
    s.strupperHits        = g_strupperHits;
    s.phase2Hooks         = g_phase2Hooks;
    s.active              = g_active;
    s.phase2Active        = g_phase2Active;
    s.tableConcatHits     = g_tblConcatHits;
    s.tableConcatFallbacks= g_tblConcatFallbacks;
    s.rawequalHits        = g_rawequalHits;
    s.rawequalFallbacks   = g_rawequalFallbacks;
    s.unpackHits          = g_unpackHits;
    s.unpackFallbacks     = g_unpackFallbacks;
    s.selectHits          = g_selectHits;
    s.selectFallbacks     = g_selectFallbacks;
    s.ipairsHits          = g_ipairsFactoryHits;
    s.ipairsFallbacks     = g_ipairsFactoryFalls;
    s.ipairsIteratorHits  = g_ipairsIteratorHits;
    s.ipairsIteratorFallbacks = g_ipairsIteratorFalls;
    s.findFullHits        = g_findFullHits;
    s.findFullFallbacks   = g_findFullFallbacks;
    s.mathRandomHits      = g_mathRandomHits;
    s.mathRandomFallbacks = g_mathRandomFallbacks;
    s.mathSqrtHits        = g_mathSqrtHits;
    s.mathSqrtFallbacks   = g_mathSqrtFallbacks;
    s.strRepHits          = g_strRepHits;
    s.strRepFallbacks     = g_strRepFallbacks;
    s.tableSortHits       = g_tableSortHits;
    s.tableSortFallbacks  = g_tableSortFallbacks;
    // unitHealth/UnitPower fields left at 0 (UnitAPI DMA disabled via #if 0)
    return s;
}

} // namespace LuaFastPath
