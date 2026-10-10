// ============================================================================
// Caches GetItemInfo. It used to cache GetSpellInfo as well; that hook is gone,
// because reading 0x00540A30 in the disassembler shows the function has no
// cacheable result to speak of.
//
// Two independent reasons, either one sufficient:
//
// 1. A string or slot argument is resolved through the player's own spellbook.
//    With exactly one numeric argument the client takes the value as a spell id
//    directly; every other form calls sub_540670, which fills in a slot index,
//    and the id then comes out of dword_BE6D88[slot] (count at dword_BE8D98) or
//    the pet book dword_BE7D98[slot]. A talent switch rewrites those arrays, so
//    the same name resolves to a different spell id - a different rank, with a
//    different icon. That is precisely the bug three testers reported: a
//    WeakAuras display stuck on the pre-switch icon until /reload, and /reload
//    working only because a new lua_State was the one thing that cleared the
//    cache. One of them bisected it to 3.10 correct, 3.18 wrong.
//
// 2. Even the plain numeric form is not stable. Once the Spell.dbc row is in
//    hand the client calls sub_8012F0 and sub_7FF100 with the player object,
//    and sub_8012F0 computes the power cost from live unit state: a virtual call
//    at [[unit]+0x13C] for max power, then sub_71B770(unit, rec[0xA4]) scaled by
//    rec[0x230] for the spell-school modifier, then a further aura-gated term.
//    Cast time goes through the same shape, divided by sub_7FDE00. So cost and
//    cast time move with buffs, gear and talents while the spell id stays put.
//
// A time-to-live was tried first and was the wrong shape of fix: it bounds how
// long wrong data is served instead of not serving it. Nothing measured the
// cache to be worth anything in the first place, so there is no benefit to
// weigh against a WeakAuras display that shows the wrong spell.
//
// GetItemInfo (0x00516C60) is a different function entirely. Decompiled, every
// value it pushes comes from the item record sub_67CA30 returns or from the
// ItemClass/ItemSubClass tables - the player object never appears - and it
// returns exactly 11 values on success or 0 when the item is not in the local
// cache yet. That is genuinely cacheable, and the client's own return count is
// a better success test than the heuristic this file used to apply.
// ============================================================================

#include "api_cache.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "MinHook.h"
#include "version.h"
#include "high_tables.h"

extern "C" void Log(const char* fmt, ...);

// Forward declaration
typedef struct lua_State lua_State;
typedef double lua_Number;

// ================================================================
// TValue layout
// Matches RawTValue from lua_fastpath.cpp exactly.
//
// Offset 0:  Value union (void* gc / double n) - 8 bytes
// Offset 8:  tt (int) - type tag
// Offset 12: taint (uint32_t)
// Total: 16 bytes per TValue
// ================================================================

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

// Stack base pointer is at L + 0x10
static inline RawTValue* GetStackBase(lua_State* L) {
    return *(RawTValue**)((uintptr_t)L + 0x10);
}

// TString layout:
// Offset 0-7:   CommonHeader (gc header)
// Offset 16:    len (int) - string length
// Offset 20:    str[0] - string data
static inline const char* ReadTStringDirect(RawTValue* tv, size_t* out_len) {
    if (tv->tt != 4) return NULL;  // LUA_TSTRING

    void* ts_ptr = tv->value.gc;
    if ((uintptr_t)ts_ptr < 0x10000 || (uintptr_t)ts_ptr >= 0xFFFFF000) return NULL;

    int len = *(int*)((char*)ts_ptr + 16);
    if (len < 0 || len > 1024) return NULL;

    char* str = (char*)ts_ptr + 20;
    if (out_len) *out_len = (size_t)len;
    return str;
}

static inline double ReadTNumberDirect(RawTValue* tv) {
    if (tv->tt != 3) return 0.0;  // LUA_TNUMBER
    double d;
    memcpy(&d, &tv->value.n, sizeof(double));
    return d;
}

// ================================================================

typedef int (__cdecl *ScriptFunc_fn)(lua_State* L);

typedef lua_Number (__cdecl *fn_lua_tonumber)(lua_State* L, int index);
typedef int        (__cdecl *fn_lua_gettop)(lua_State* L);
typedef void       (__cdecl *fn_lua_pushnumber)(lua_State* L, lua_Number n);
typedef void       (__cdecl *fn_lua_pushstring)(lua_State* L, const char* s);
typedef void       (__cdecl *fn_lua_pushboolean)(lua_State* L, int b);
typedef void       (__cdecl *fn_lua_pushnil)(lua_State* L);

// Pushing goes through the API so strings are interned properly.
static fn_lua_gettop      lua_gettop_     = (fn_lua_gettop)0x0084DBD0;
static fn_lua_pushnumber  lua_pushnumber_ = (fn_lua_pushnumber)0x0084E2A0;
static fn_lua_pushstring  lua_pushstring_ = (fn_lua_pushstring)0x0084E350;
static fn_lua_pushboolean lua_pushboolean_= (fn_lua_pushboolean)0x0084E4D0;
static fn_lua_pushnil     lua_pushnil_    = (fn_lua_pushnil)0x0084E280;

#define LUA_TNIL     0
#define LUA_TBOOLEAN 1
#define LUA_TNUMBER  3
#define LUA_TSTRING  4

static constexpr uintptr_t ADDR_GetItemInfo = 0x00516C60;

static ScriptFunc_fn orig_GetItemInfo = (ScriptFunc_fn)0x00516C60;

// ================================================================
// Cache structure - direct-mapped.
//
// The previous layout was two 8192-slot arrays of entries holding sixteen
// fixed 512-byte string buffers each: a little over 8.5 KB per entry, so
// roughly 71 MB per cache and 143 MB of BSS for the pair. In a 32-bit client
// whose address space this project exists to defend, that was by far the
// largest single allocation the DLL made, and it was reserved whether or not
// anything ever asked for an item.
//
// Deleting the spell cache removes half of it outright. The rest comes from
// sizing the entry to the function instead of to a round number: GetItemInfo
// returns eleven values, six of them strings that together run to about 300
// bytes, so the strings share one blob per entry rather than each getting 512
// bytes of their own. 4096 slots comfortably covers the few thousand distinct
// items a session touches.
// ================================================================

static constexpr int CACHE_SIZE    = 4096;
static constexpr int CACHE_MASK    = CACHE_SIZE - 1;

// GetItemInfo ends in `return 11` on every success path and `return 0` when
// sub_67CA30 has no record for the item yet.
static constexpr int ITEM_RETVALS  = 11;

// Item links run to about 130 characters at their longest - full enchant, gem
// and suffix fields plus a long name. A key that does not fit is not cached
// rather than truncated: the old code compared truncated keys, so two long
// strings sharing a prefix could match each other and serve the wrong item.
static constexpr int ITEM_KEY_MAX  = 192;

// Name, link, class, subclass, equip location and texture path, back to back.
static constexpr int ITEM_BLOB_MAX = 512;

struct ItemRetVal {
    double   numVal;
    uint16_t strOff;   // offset into ItemCacheEntry::blob when type == LUA_TSTRING
    uint8_t  type;
};

struct ItemCacheEntry {
    uint32_t   keyHash;
    double     keyNum1;
    int        keyType1;
    uint16_t   blobUsed;
    uint8_t    retCount;
    bool       valid;
    char       keyStr1[ITEM_KEY_MAX];
    char       blob[ITEM_BLOB_MAX];
    ItemRetVal vals[ITEM_RETVALS];
};

// Out of this DLL's image and into the top half of the address space; see
// high_tables.cpp for why that half and not this one. Indexed exactly as
// the array was, and VirtualAlloc returns it zeroed.
static constexpr size_t ITEM_CACHE_BYTES = sizeof(ItemCacheEntry) * CACHE_SIZE;
static ItemCacheEntry* g_itemCache = nullptr;

static long g_itemHits     = 0;
static long g_itemMisses   = 0;
static long g_itemBypassed = 0;   // key or result too large to store
// Why a miss missed. A hit rate on its own says the cache is not working and
// nothing about which of three different problems it has: a slot that was empty
// (nothing to fix), a slot holding a different item (the table is too small or
// the map too crude), or the client returning nothing because the item is not
// in its own cache yet (nothing this can ever store).
static long g_itemMissCold    = 0;
static long g_itemMissEvicted = 0;
static long g_itemMissNotReady = 0;
static bool g_active       = false;

static SRWLOCK g_itemCacheLock = SRWLOCK_INIT;

// ================================================================
// FNV-1a Hash
// ================================================================

static inline uint32_t HashStr(const char* s, size_t len) {
    uint32_t h = 0x811C9DC5;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 0x01000193;
    }
    return h;
}

// Returns false when the argument cannot be represented as a cache key, in
// which case the caller must go straight to the original function.
static inline bool ComputeItemKey(RawTValue* base, int nargs, uint32_t& hash,
                                  int& kType1, double& kNum1, char* kStr1) {
    kType1 = LUA_TNIL; kNum1 = 0.0; kStr1[0] = '\0';
    if (nargs < 1) return false;

    uint32_t h = 0x811C9DC5;
    RawTValue* arg1 = &base[0];
    kType1 = arg1->tt;
    h ^= (uint32_t)kType1;
    h *= 0x01000193;

    if (kType1 == LUA_TNUMBER) {
        kNum1 = ReadTNumberDirect(arg1);
        uint64_t u;
        memcpy(&u, &kNum1, sizeof(u));
        h ^= (uint32_t)u; h *= 0x01000193;
        h ^= (uint32_t)(u >> 32); h *= 0x01000193;
    } else if (kType1 == LUA_TSTRING) {
        size_t len = 0;
        const char* s = ReadTStringDirect(arg1, &len);
        if (!s) return false;
        if (len >= ITEM_KEY_MAX) return false;   // do not truncate - bypass
        memcpy(kStr1, s, len);
        kStr1[len] = '\0';
        h ^= HashStr(kStr1, len);
        h *= 0x01000193;
    } else {
        return false;   // GetItemInfo only accepts a number or a string
    }

    hash = h;
    return true;
}

// ================================================================
// Capture - reads the results straight off the stack, no lua API calls.
//
// A Lua C function returning n means "the top n values", which is not
// necessarily the first n the function pushed. The old code captured from
// topBefore and returned the pushed count; this indexes from the top, so a
// function that leaves scratch values below its results still replays right.
//
// Returns false and leaves the slot untouched if the strings do not fit, so a
// partially written entry is never marked valid.
// ================================================================

static bool CaptureItemResults(lua_State* L, ItemCacheEntry* e,
                               uint32_t keyHash, int topAfter, int ret,
                               int kType1, double kNum1, const char* kStr1) {
    ItemRetVal vals[ITEM_RETVALS];
    char       blob[ITEM_BLOB_MAX];
    uint16_t   used = 0;

    RawTValue* base  = GetStackBase(L);
    RawTValue* first = &base[topAfter - ret];

    for (int i = 0; i < ret; i++) {
        RawTValue* val = &first[i];
        int t = val->tt;

        vals[i].numVal = 0.0;
        vals[i].strOff = 0;
        vals[i].type   = LUA_TNIL;

        switch (t) {
            case LUA_TSTRING: {
                size_t slen = 0;
                const char* s = ReadTStringDirect(val, &slen);
                if (!s) break;                                  // stays nil
                if (used + slen + 1 > ITEM_BLOB_MAX) return false;
                memcpy(blob + used, s, slen);
                blob[used + slen] = '\0';
                vals[i].strOff = used;
                vals[i].type   = LUA_TSTRING;
                used = (uint16_t)(used + slen + 1);
                break;
            }
            case LUA_TNUMBER:
                vals[i].numVal = ReadTNumberDirect(val);
                vals[i].type   = LUA_TNUMBER;
                break;
            case LUA_TBOOLEAN:
                vals[i].numVal = (val->value.gc != NULL) ? 1.0 : 0.0;
                vals[i].type   = LUA_TBOOLEAN;
                break;
            default:
                break;                                          // stays nil
        }
    }

    e->keyHash  = keyHash;
    e->keyType1 = kType1;
    e->keyNum1  = kNum1;
    if (kType1 == LUA_TSTRING) {
        size_t klen = strlen(kStr1);
        memcpy(e->keyStr1, kStr1, klen + 1);
    } else {
        e->keyStr1[0] = '\0';
    }
    memcpy(e->blob, blob, used);
    e->blobUsed = used;
    e->retCount = (uint8_t)ret;
    memcpy(e->vals, vals, sizeof(ItemRetVal) * (size_t)ret);
    e->valid    = true;
    return true;
}

// ================================================================
// Replay - the API pushes, so strings get interned in the current state.
// ================================================================

static inline void ReplayItemResults(lua_State* L, const ItemCacheEntry* e) {
    for (int i = 0; i < (int)e->retCount; i++) {
        switch (e->vals[i].type) {
            case LUA_TSTRING:  lua_pushstring_(L, e->blob + e->vals[i].strOff); break;
            case LUA_TNUMBER:  lua_pushnumber_(L, e->vals[i].numVal);           break;
            case LUA_TBOOLEAN: lua_pushboolean_(L, (int)e->vals[i].numVal);     break;
            default:           lua_pushnil_(L);                                 break;
        }
    }
}

static lua_State* g_cacheLuaState = nullptr;

// Hooked_GetItemInfo

static int __cdecl Hooked_GetItemInfo(lua_State* L) {
    if (L != g_cacheLuaState) {
        g_cacheLuaState = L;
        ApiCache::ClearCache();
    }

    int nargs = lua_gettop_(L);
    if (nargs < 1) return orig_GetItemInfo(L);

    RawTValue* base = GetStackBase(L);
    uint32_t keyHash = 0;
    int      keyType1;
    double   keyNum1;
    char     keyStr1[ITEM_KEY_MAX];

    if (!ComputeItemKey(base, nargs, keyHash, keyType1, keyNum1, keyStr1)) {
        InterlockedIncrement(&g_itemBypassed);
        return orig_GetItemInfo(L);
    }

    int slot = (int)(keyHash & CACHE_MASK);
    ItemCacheEntry* e = &g_itemCache[slot];

    ItemCacheEntry localEntry;
    bool found = false;
    bool slotHeldSomethingElse = false;

    AcquireSRWLockShared(&g_itemCacheLock);
    slotHeldSomethingElse = e->valid;
    if (e->valid && e->keyHash == keyHash && e->keyType1 == keyType1) {
        bool match = (keyType1 == LUA_TNUMBER)
                       ? (e->keyNum1 == keyNum1)
                       : (strcmp(e->keyStr1, keyStr1) == 0);
        if (match) {
            localEntry = *e;
            found = true;
            slotHeldSomethingElse = false;
        }
    }
    ReleaseSRWLockShared(&g_itemCacheLock);

    if (found) {
        ReplayItemResults(L, &localEntry);
        InterlockedIncrement(&g_itemHits);
        return (int)localEntry.retCount;
    }

    int ret      = orig_GetItemInfo(L);
    int topAfter = lua_gettop_(L);

    // ret == 0 is the client saying the item is not in its local cache yet, and
    // a later call will succeed - so a failure must never be stored. Anything
    // above zero came from a complete item record.
    if (ret > 0 && ret <= ITEM_RETVALS && topAfter >= ret) {
        AcquireSRWLockExclusive(&g_itemCacheLock);
        bool stored = CaptureItemResults(L, e, keyHash, topAfter, ret,
                                        keyType1, keyNum1, keyStr1);
        ReleaseSRWLockExclusive(&g_itemCacheLock);
        if (!stored) InterlockedIncrement(&g_itemBypassed);
    }

    InterlockedIncrement(&g_itemMisses);
    if (ret <= 0) {
        InterlockedIncrement(&g_itemMissNotReady);
    } else if (slotHeldSomethingElse) {
        InterlockedIncrement(&g_itemMissEvicted);
    } else {
        InterlockedIncrement(&g_itemMissCold);
    }
    return ret;
}

// Hook installation helper.

static bool HookFunc(const char* name, uintptr_t addr, void* hookFn, void** origFn) {
    MH_STATUS s = MH_CreateHook((void*)addr, hookFn, origFn);
    if (s != MH_OK) {
        Log("[ApiCache]   %-25s MH_CreateHook failed (%d)", name, (int)s);
        return false;
    }
    s = MH_EnableHook((void*)addr);
    if (s != MH_OK) {
        Log("[ApiCache]   %-25s MH_EnableHook failed (%d)", name, (int)s);
        return false;
    }
    Log("[ApiCache]   %-25s 0x%08X  [ OK ]", name, (unsigned)addr);
    return true;
}

// Public API.

namespace ApiCache {

bool Init() {
    g_active = true;

    g_itemCache = (ItemCacheEntry*)HighTables::Reserve("api_cache",
                                                       ITEM_CACHE_BYTES);
    if (!g_itemCache) {
        Log("[ApiCache] NOT installed: the %u KB table could not be "
            "allocated.", (unsigned)(ITEM_CACHE_BYTES / 1024));
        return false;
    }

#if !TEST_DISABLE_GETITEMINFO_CACHE
    // push ebp / mov ebp,esp / sub esp,5E8h / push ebx / push esi / push edi / lea ecx,[ebp-0E4h]
    static const unsigned char kGetItemInfoOpening[18] = {
        0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xE8, 0x05, 0x00, 0x00, 0x53, 0x56, 0x57, 0x8D, 0x8D, 0x1C, 0xFF, 0xFF, 0xFF
    };
    if (!WowOpt_ClientBytesAre(ADDR_GetItemInfo, kGetItemInfoOpening, sizeof(kGetItemInfoOpening))) {
        char hex[64];
        WowOpt_HexBytes(ADDR_GetItemInfo, hex, sizeof(hex));
        Log("[ApiCache] NOT installed: the bytes at 0x%08X are not GetItemInfo's opening: %s",
            (unsigned)ADDR_GetItemInfo, hex);
        g_active = false;
        return false;
    }
    bool hooked = HookFunc("GetItemInfo", ADDR_GetItemInfo,
                           (void*)Hooked_GetItemInfo, (void**)&orig_GetItemInfo);
#else
    bool hooked = false;
    Log("[ApiCache]   GetItemInfo disabled at build time");
#endif

    Log("[ApiCache] Init complete: GetItemInfo %s, %d slots, %u KB",
        hooked ? "hooked" : "NOT hooked", CACHE_SIZE,
        (unsigned)(ITEM_CACHE_BYTES / 1024));
    return hooked;
}

// Printed from the periodic report. Shutdown does not run - the DLL exits via
// TerminateProcess - so anything reported only from there is never seen.
void LogStats() {
    long total = g_itemHits + g_itemMisses;
    if (total > 0) {
        Log("[ApiCache] GetItemInfo: %ld hits, %ld misses (%.1f%% hit rate), %ld bypassed",
            g_itemHits, g_itemMisses, (double)g_itemHits / total * 100.0, g_itemBypassed);
        // A hit rate on its own does not say which of three problems this is,
        // and they have different answers: nothing, a bigger table, or none of
        // our business. A field session sat at 17.5% over 1.4 million calls and
        // there was no way to tell.
        Log("[ApiCache]   of those misses: %ld had nothing stored for that slot, "
            "%ld found a different item in it, and %ld were the client itself "
            "returning nothing because the item is not in its own cache yet. "
            "Only the middle one is a cache that is too small.",
            g_itemMissCold, g_itemMissEvicted, g_itemMissNotReady);
    } else if (g_active) {
        Log("[ApiCache] GetItemInfo: measured and zero, no call reached it");
    } else {
        Log("[ApiCache] not measured: the cache is not installed.");
    }
}

void Shutdown() {
    if (!g_active) return;
    g_active = false;

    MH_DisableHook((void*)ADDR_GetItemInfo);

    LogStats();
}

void ClearCache() {
    // The table is no longer part of this DLL's image, so it can be absent.
    // This is called from the loading-screen path, which does not know whether
    // the cache installed.
    if (!g_itemCache) return;

    AcquireSRWLockExclusive(&g_itemCacheLock);
    memset(g_itemCache, 0, ITEM_CACHE_BYTES);
    ReleaseSRWLockExclusive(&g_itemCacheLock);

    Log("[ApiCache] Cache cleared (%d item entries)", CACHE_SIZE);
}

Stats GetStats() {
    Stats s;
    s.itemHits    = g_itemHits;
    s.itemMisses  = g_itemMisses;
    s.itemBypassed = g_itemBypassed;
    s.active      = g_active;
    return s;
}

} // namespace ApiCache
