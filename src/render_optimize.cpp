#include "render_optimize.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <intrin.h>
#include <stdlib.h>
#include "MinHook.h"

extern "C" void Log(const char* fmt, ...);

typedef struct lua_State lua_State;
typedef double lua_Number;

#define LUA_GLOBALSINDEX (-10002)
#define LUA_TNIL     0
#define LUA_TNUMBER  3
#define LUA_TSTRING  4

typedef void        (__cdecl *fn_lua_getfield)(lua_State*, int, const char*);
typedef lua_Number  (__cdecl *fn_lua_tonumber)(lua_State*, int);
typedef int         (__cdecl *fn_lua_toboolean)(lua_State*, int);
typedef void        (__cdecl *fn_lua_settop)(lua_State*, int);
typedef int         (__cdecl *fn_lua_type)(lua_State*, int);
typedef const char* (__cdecl *fn_lua_tolstring)(lua_State*, int, size_t*);

static fn_lua_getfield   ro_getfield  = (fn_lua_getfield)  0x0084E590;
static fn_lua_tonumber   ro_tonumber  = (fn_lua_tonumber)  0x0084E030;
static fn_lua_toboolean  ro_toboolean = (fn_lua_toboolean) 0x0084E0B0;
static fn_lua_settop     ro_settop    = (fn_lua_settop)    0x0084DBF0;
static fn_lua_type       ro_type      = (fn_lua_type)      0x0084DEB0;
static fn_lua_tolstring  ro_tolstring = (fn_lua_tolstring) 0x0084E0E0;

static constexpr uintptr_t ADDR_lua_State_ptr   = 0x00D3F78C;
static constexpr uintptr_t ADDR_ShouldRender    = 0x00730F30;
static constexpr uintptr_t ADDR_PlaySpellVisual = 0x007265C0;

struct RenderConfig {
    bool enabled;
    bool hideUnits;
    bool hideSpells;
    int  playerDist;
    int  playerDistCity;
    int  playerDistCombat;
    int  petDist;
    int  petDistCombat;
    int  trashDist;
    int  trashDistCombat;
    bool hideAllPlayers;
    bool showAllPlayers;
};

static RenderConfig g_cfg = {
    false, true, false,
    80, 40, 100,
    60, 40,
    100, 60,
    false, false
};

struct Vec3 { float x, y, z; };

static uint64_t g_playerGUID  = 0;
static Vec3     g_playerPos   = {0, 0, 0};
static bool     g_playerFound = false;
static bool     g_inCombat    = false;
static bool     g_inCity      = false;

static volatile LONG g_hidden        = 0;
static volatile LONG g_shown         = 0;
static volatile LONG g_spellsBlocked = 0;

static inline uint64_t GetGUID(uintptr_t obj) {
    __try {
        uint32_t lo = *(uint32_t*)(obj + 0x30);
        uint32_t hi = *(uint32_t*)(obj + 0x34);
        return ((uint64_t)hi << 32) | lo;
    } __except(1) { return 0; }
}

static inline uint32_t GetType(uintptr_t obj) {
    __try {
        uintptr_t ti = *(uintptr_t*)(obj + 0x08);
        if (!ti) return 0;
        return *(uint32_t*)(ti + 0x08);
    } __except(1) { return 0; }
}

static inline uint32_t Desc32(uintptr_t obj, int off) {
    __try {
        uintptr_t desc = *(uintptr_t*)(obj + 0xD0);
        if (!desc) return 0;
        return *(uint32_t*)(desc + off);
    } __except(1) { return 0; }
}

static inline Vec3 GetPos(uintptr_t obj) {
    Vec3 v = {0, 0, 0};
    __try {
        uintptr_t md = *(uintptr_t*)(obj + 0xD8);
        if (md && md > 0x10000 && md < 0x7FFFFFFF) {
            v.x = *(float*)(md + 0x10);
            v.y = *(float*)(md + 0x14);
            v.z = *(float*)(md + 0x18);
        }
    } __except(1) {}
    return v;
}

static inline float DistSq(uintptr_t obj) {
    Vec3 p = GetPos(obj);
    if (p.x == 0.0f && p.y == 0.0f && p.z == 0.0f) return -1.0f;
    float dx = p.x - g_playerPos.x;
    float dy = p.y - g_playerPos.y;
    float dz = p.z - g_playerPos.z;
    return dx * dx + dy * dy + dz * dz;
}

static inline int ResolvePlayerDist() {
    if (g_inCombat) return g_cfg.playerDistCombat;
    if (g_inCity)   return g_cfg.playerDistCity;
    return g_cfg.playerDist;
}

static inline int ResolvePetDist() {
    if (g_inCombat) return g_cfg.petDistCombat;
    return g_cfg.petDist;
}

static inline int ResolveTrashDist() {
    if (g_inCombat) return g_cfg.trashDistCombat;
    return g_cfg.trashDist;
}

static bool ShouldHideUnit(uintptr_t u) {
    uint64_t guid = GetGUID(u);
    if (!guid || guid == g_playerGUID || !g_playerFound) return false;

    uint32_t tm = GetType(u);
    int d = 0;

    if (tm & 0x10) {
        if (g_cfg.showAllPlayers) return false;
        if (g_cfg.hideAllPlayers) return true;
        d = ResolvePlayerDist();
    } else if (tm & 0x08) {
        uint32_t lv = Desc32(u, 0xC0);
        if (lv >= 83) return false;
        uint32_t fl = Desc32(u, 0xD4);
        d = (fl & 0x01000000) ? ResolvePetDist() : ResolveTrashDist();
    } else {
        return false;
    }

    if (d <= 0) return true;

    float dsq = DistSq(u);
    if (dsq < 0.0f) return false;
    return dsq > (float)(d * d);
}

typedef void (__thiscall *ShouldRender_t)(void*, char, uint32_t*, uint32_t*);
static ShouldRender_t orig_ShouldRender = nullptr;

static void __fastcall Hook_ShouldRender(
    void* self, void*, char a2, uint32_t* a3, uint32_t* a4)
{
    orig_ShouldRender(self, a2, a3, a4);
    if (!g_cfg.enabled || !g_playerGUID) return;

    __try {
        uintptr_t u = (uintptr_t)self;
        uint64_t guid = GetGUID(u);
        if (!guid) return;

        if (guid == g_playerGUID) {
            g_playerPos = GetPos(u);
            g_playerFound = true;
            return;
        }

        if (!g_playerFound || *a4 == 1 || !g_cfg.hideUnits) return;

        if (ShouldHideUnit(u)) {
            *a4 = 1;
            InterlockedIncrement(&g_hidden);
        } else {
            *a4 = 0;
            InterlockedIncrement(&g_shown);
        }
    } __except(1) {}
}

typedef void* (__thiscall *PlaySpellVisual_t)(
    void*, int*, void*, void*, int, int, int, int);
static PlaySpellVisual_t orig_PlaySpellVisual = nullptr;

static void* __fastcall Hook_PlaySpellVisual(
    void* self, void*,
    int* a2, void* a3, void* a4, int a5, int a6,
    int a7_lo, int a7_hi)
{
    if (g_cfg.enabled && g_cfg.hideSpells && g_playerFound) {
        __try {
            uintptr_t u = (uintptr_t)self;
            uint64_t guid = GetGUID(u);
            if (guid && guid != g_playerGUID) {
                uint32_t tm = GetType(u);
                if (tm & 0x10) {
                    InterlockedIncrement(&g_spellsBlocked);
                    return nullptr;
                }
                if (tm & 0x08) {
                    uint32_t lv = Desc32(u, 0xC0);
                    if (lv < 83) {
                        InterlockedIncrement(&g_spellsBlocked);
                        return nullptr;
                    }
                }
            }
        } __except(1) {}
    }
    return orig_PlaySpellVisual(self, a2, a3, a4, a5, a6, a7_lo, a7_hi);
}

static int g_readCounter = 0;

static lua_State* GetL() {
    __try {
        lua_State* L = *(lua_State**)ADDR_lua_State_ptr;
        if ((uintptr_t)L < 0x10000 || (uintptr_t)L > 0x7FFFFFFF) return nullptr;
        return L;
    } __except(1) { return nullptr; }
}

static int ReadInt(lua_State* L, const char* name, int def) {
    ro_getfield(L, LUA_GLOBALSINDEX, name);
    int val = def;
    if (ro_type(L, -1) == LUA_TNUMBER) val = (int)ro_tonumber(L, -1);
    ro_settop(L, -2);
    return val;
}

static bool ReadBool(lua_State* L, const char* name, bool def) {
    ro_getfield(L, LUA_GLOBALSINDEX, name);
    bool val = def;
    if (ro_type(L, -1) != LUA_TNIL) val = (ro_toboolean(L, -1) != 0);
    ro_settop(L, -2);
    return val;
}

static uint64_t ParseHexGUID(const char* s, size_t len) {
    uint64_t result = 0;
    size_t start = 0;
    if (len > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) start = 2;
    for (size_t i = start; i < len; i++) {
        char c = s[i];
        uint64_t d;
        if      (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        result = (result << 4) | d;
    }
    return result;
}

static uint64_t ReadGUID(lua_State* L, const char* name) {
    ro_getfield(L, LUA_GLOBALSINDEX, name);
    uint64_t guid = 0;
    if (ro_type(L, -1) == LUA_TSTRING) {
        size_t len = 0;
        const char* s = ro_tolstring(L, -1, &len);
        if (s && len > 2) guid = ParseHexGUID(s, len);
    }
    ro_settop(L, -2);
    return guid;
}

static void ReadCfg() {
    lua_State* L = GetL();
    if (!L) return;

    __try {
        bool en = ReadBool(L, "RENDEROPT_ENABLED", false);

        if (!en) {
            if (g_cfg.enabled) { g_cfg.enabled = false; Log("[RenderOpt] Disabled"); }
            return;
        }

        if (!g_cfg.enabled) Log("[RenderOpt] Enabling...");
        g_cfg.enabled    = true;
        g_cfg.hideUnits  = ReadBool(L, "RENDEROPT_HIDE_UNITS", true);
        g_cfg.hideSpells = ReadBool(L, "RENDEROPT_HIDE_SPELLS", false);

        uint64_t pg = ReadGUID(L, "RENDEROPT_PLAYER_GUID");
        if (pg) {
            if (g_playerGUID != pg)
                Log("[RenderOpt] GUID: 0x%08X%08X", (unsigned)(pg >> 32), (unsigned)(pg & 0xFFFFFFFF));
            g_playerGUID = pg;
        }

        g_cfg.playerDist       = ReadInt(L, "RENDEROPT_PLAYER_DIST", 80);
        g_cfg.playerDistCity   = ReadInt(L, "RENDEROPT_PLAYER_DIST_CITY", 40);
        g_cfg.playerDistCombat = ReadInt(L, "RENDEROPT_PLAYER_DIST_COMBAT", 100);
        g_cfg.petDist          = ReadInt(L, "RENDEROPT_PET_DIST", 60);
        g_cfg.petDistCombat    = ReadInt(L, "RENDEROPT_PET_DIST_COMBAT", 40);
        g_cfg.trashDist        = ReadInt(L, "RENDEROPT_TRASH_DIST", 100);
        g_cfg.trashDistCombat  = ReadInt(L, "RENDEROPT_TRASH_DIST_COMBAT", 60);

        g_cfg.hideAllPlayers = ReadBool(L, "RENDEROPT_HIDE_ALL_PLAYERS", false);
        g_cfg.showAllPlayers = ReadBool(L, "RENDEROPT_SHOW_ALL_PLAYERS", false);

        g_inCombat = ReadBool(L, "RENDEROPT_IN_COMBAT", false);
        g_inCity   = ReadBool(L, "RENDEROPT_IN_CITY", false);

        static bool loggedOnce = false;
        if (!loggedOnce && g_playerGUID) {
            loggedOnce = true;
            Log("[RenderOpt] Active: units=%d spells=%d player=%d city=%d combat=%d pet=%d trash=%d",
                g_cfg.hideUnits, g_cfg.hideSpells,
                g_cfg.playerDist, g_cfg.playerDistCity, g_cfg.playerDistCombat,
                g_cfg.petDist, g_cfg.trashDist);
        }
    } __except(1) {
        Log("[RenderOpt] EXCEPTION in ReadCfg");
    }
}

namespace RenderOpt {

void OnFrame() {
    if (++g_readCounter < 8) return;
    g_readCounter = 0;
    ReadCfg();
}

bool Init() {
    Log("[RenderOpt] ====================================");
    Log("[RenderOpt]  Selective Unit & Spell Rendering");
    Log("[RenderOpt] ====================================");

    int hooked = 0;

    { MH_STATUS s = MH_CreateHook((void*)ADDR_ShouldRender,
          (void*)Hook_ShouldRender, (void**)&orig_ShouldRender);
      if (s == MH_OK) s = MH_EnableHook((void*)ADDR_ShouldRender);
      if (s == MH_OK) { hooked++; Log("[RenderOpt]  [ OK ] ShouldRender  0x%08X", (unsigned)ADDR_ShouldRender); }
      else Log("[RenderOpt]  [FAIL] ShouldRender (%d)", (int)s); }

    { MH_STATUS s = MH_CreateHook((void*)ADDR_PlaySpellVisual,
          (void*)Hook_PlaySpellVisual, (void**)&orig_PlaySpellVisual);
      if (s == MH_OK) s = MH_EnableHook((void*)ADDR_PlaySpellVisual);
      if (s == MH_OK) { hooked++; Log("[RenderOpt]  [ OK ] SpellVisual   0x%08X", (unsigned)ADDR_PlaySpellVisual); }
      else Log("[RenderOpt]  [FAIL] SpellVisual (%d)", (int)s); }

    if (!hooked) { Log("[RenderOpt]  No hooks — DISABLED"); return false; }
    Log("[RenderOpt]  Hooks: %d/2  [ OK ]", hooked);
    Log("[RenderOpt] ====================================");
    return true;
}

void Shutdown() {
    MH_DisableHook((void*)ADDR_ShouldRender);
    MH_DisableHook((void*)ADDR_PlaySpellVisual);
    Log("[RenderOpt] Shutdown: hidden=%ld shown=%ld spells=%ld",
        g_hidden, g_shown, g_spellsBlocked);
}

Stats GetStats() {
    return { g_hidden, g_shown, g_spellsBlocked, g_cfg.enabled };
}

}
