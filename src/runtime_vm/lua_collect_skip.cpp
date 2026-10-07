// ============================================================================
// Module: lua_collect_skip.cpp
//
// An addon's collectgarbage("collect") during a loading screen.
//
// Drain's loading frames (three 783ab7af sessions, 87.8 s of loading frames
// weighted by their length): 50% in NtDelayExecution, 24% in the Lua VM and
// collector (0x855000 to 0x85D000), and the collector's hottest instructions
// there are sweeplist at 0x0085B233 and the mark phase at 0x0085AA93, reached
// through lua_gc (0x0084ED92) called from luaB_collectgarbage (0x008545C0, the
// return address 0x008545F8): Lua code asked for a collection. The default option
// of collectgarbage is "collect", a complete stop-the-world cycle, and on a heap
// of several hundred megabytes that is a second or more inside a loading screen
// that is otherwise waiting for the file reader.
//
// What this does. It hooks luaB_collectgarbage. While a loading screen is up and
// the Lua heap is under a limit, a call whose option is "collect" (no argument,
// nil, or the string) returns 0 without calling lua_gc, which is the number the
// client pushes for that option. Every other option, every call outside a loading
// screen, and every call with a large heap go to the client's routine. The
// incremental collector keeps running as it always does, so nothing is held back
// for good; the garbage the call would have freed is freed by the steps that
// follow, a little later. An addon that calls collectgarbage("count") right
// after to see what it freed sees a larger number.
//
// What it counts, with or without skipping: the explicit collections seen, in
// and out of a loading screen, the time the client spent in the ones it ran, and
// the addon whose Lua made the call, read from the call stack the way the
// addon sampler reads it. That is the first measurement of what addons'
// explicit collections cost in play, which no log has had.
//
// Off by default (UI_Lua/LoadingCollectSkip). Not run in a game.
// ============================================================================

#include "lua_collect_skip.h"
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "config.h"
#include "ab_test.h"
#include "loading_state.h"
#include "MinHook.h"
#include "version.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
extern DWORD g_mainThreadId;

namespace LuaCollectSkip {
namespace {

constexpr uintptr_t kTarget    = 0x008545C0;     // luaB_collectgarbage
constexpr uintptr_t kLuaGc     = 0x0084ED50;     // lua_gc(L, what, data)
constexpr uintptr_t kPushNumber = 0x0084E2A0;    // lua_pushnumber(L, double)
static const uint8_t kPrologue[9] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x56, 0x8B, 0x75 };

constexpr unsigned kOffTop = 0x0C, kOffBase = 0x10, kOffCi = 0x18, kOffBaseCi = 0x2C;
constexpr unsigned kSizeofCi = 24, kOffCiFunc = 4, kOffClIsC = 10, kOffClProto = 0x18, kOffProtoSrc = 0x24;
constexpr unsigned kOffTsLen = 16, kOffTsData = 20;

constexpr int kSkipBelowKB = 600 * 1024;         // above this heap the explicit collection runs

typedef int  (__cdecl *Collect_fn)(void* L);
typedef int  (__cdecl *LuaGc_fn)(void* L, int what, int data);
typedef void (__cdecl *PushNumber_fn)(void* L, double n);

Collect_fn g_orig = nullptr;
bool g_installed = false;
bool g_abSubject = false;
LARGE_INTEGER g_freq;

unsigned long g_calls = 0;            // any option
unsigned long g_collectIn = 0;        // "collect" during a loading screen
unsigned long g_collectOut = 0;       // "collect" outside one
unsigned long g_skipped = 0;
unsigned long g_bigHeapRan = 0;       // would have skipped, heap over the limit
double        g_msRanIn = 0.0, g_msRanOut = 0.0;

struct Who { char name[40]; unsigned long in, out, skipped; double ms; };
constexpr int kWho = 24;
Who g_who[kWho];
unsigned long g_whoLost = 0;

inline uint32_t Rd32(uintptr_t p) { return *(volatile const uint32_t*)p; }
inline uint8_t  Rd8(uintptr_t p)  { return *(volatile const uint8_t*)p; }
inline bool Plausible(uint32_t p) { return p >= 0x00010000u && p < 0xF0000000u && (p & 3) == 0; }

// Is the first argument absent, nil, or the string "collect"?
bool OptionIsCollect(void* L) {
    __try {
        const uint32_t top = Rd32((uintptr_t)L + kOffTop);
        const uint32_t base = Rd32((uintptr_t)L + kOffBase);
        if (!Plausible(top) || !Plausible(base) || top < base) return false;
        if (top - base < 16) return true;                         // no argument
        const uint32_t tt = Rd32(base + 8);
        if (tt == 0) return true;                                 // nil
        if (tt != 4) return false;
        const uint32_t ts = Rd32(base);
        if (!Plausible(ts)) return false;
        if (Rd32(ts + kOffTsLen) != 7) return false;
        return memcmp((const void*)(ts + kOffTsData), "collect", 7) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The addon or file whose Lua called, read from the call stack.
void Attribute(void* L, char* out, size_t cap) {
    out[0] = 0;
    __try {
        uint32_t ci = Rd32((uintptr_t)L + kOffCi);
        const uint32_t baseCi = Rd32((uintptr_t)L + kOffBaseCi);
        if (!Plausible(ci) || !Plausible(baseCi) || ci < baseCi) { snprintf(out, cap, "(unreadable)"); return; }
        for (int depth = 0; depth < 24 && ci > baseCi; ++depth, ci -= kSizeofCi) {
            const uint32_t slot = Rd32(ci + kOffCiFunc);
            if (!Plausible(slot)) continue;
            const uint32_t cl = Rd32(slot);
            if (!Plausible(cl) || Rd8(cl + kOffClIsC)) continue;
            const uint32_t proto = Rd32(cl + kOffClProto);
            if (!Plausible(proto)) continue;
            const uint32_t srcTs = Rd32(proto + kOffProtoSrc);
            if (!Plausible(srcTs)) continue;
            const char* src = (const char*)(srcTs + kOffTsData);
            if (*src == '@' || *src == '=') ++src;
            static const char kAddons[] = "Interface\\AddOns\\";
            if (_strnicmp(src, kAddons, sizeof(kAddons) - 1) == 0) {
                const char* p = src + sizeof(kAddons) - 1;
                size_t i = 0;
                while (p[i] && p[i] != '\\' && p[i] != '/' && i + 1 < cap) { out[i] = p[i]; ++i; }
                out[i] = 0;
                if (i) return;
            }
            if (_strnicmp(src, "Interface\\FrameXML\\", 19) == 0) { snprintf(out, cap, "(Blizzard UI)"); return; }
        }
        snprintf(out, cap, "(no source)");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snprintf(out, cap, "(unreadable)");
    }
}

Who& Slot(const char* name) {
    for (int i = 0; i < kWho; ++i) {
        if (!g_who[i].name[0]) { strncpy_s(g_who[i].name, sizeof(g_who[i].name), name, _TRUNCATE); return g_who[i]; }
        if (strcmp(g_who[i].name, name) == 0) return g_who[i];
    }
    ++g_whoLost;
    return g_who[kWho - 1];
}

int __cdecl Hooked_Collect(void* L) {
    ++g_calls;
    if (GetCurrentThreadId() != g_mainThreadId || !OptionIsCollect(L)) return g_orig(L);

    const bool loading = LoadingState::IsLoading();
    char who[40];
    Attribute(L, who, sizeof(who));
    Who& w = Slot(who);
    if (loading) { ++g_collectIn; ++w.in; } else { ++g_collectOut; ++w.out; }

    if (loading && !(g_abSubject && AbTest::StandAside())) {
        const int kb = ((LuaGc_fn)kLuaGc)(L, 3 /* LUA_GCCOUNT */, 0);
        if (kb < kSkipBelowKB) {
            ++g_skipped;
            ++w.skipped;
            ((PushNumber_fn)kPushNumber)(L, 0.0);
            return 1;
        }
        ++g_bigHeapRan;
    }

    LARGE_INTEGER t0, t1;
    QueryPerformanceCounter(&t0);
    const int r = g_orig(L);
    QueryPerformanceCounter(&t1);
    const double ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)g_freq.QuadPart;
    w.ms += ms;
    if (loading) g_msRanIn += ms; else g_msRanOut += ms;
    return r;
}

} // namespace

void Init() {
    if (!Config::g_settings.OptLoadingCollectSkip) return;
    void* const target = (void*)kTarget;
    if (!WowOpt_ClientPatchAllowed(target)) {
        Log("[LuaCollectSkip] NOT active: client patches disallowed at 0x%08X", (unsigned)kTarget);
        return;
    }
    if (std::memcmp(target, kPrologue, sizeof(kPrologue)) != 0) {
        Log("[LuaCollectSkip] NOT active: the bytes at 0x%08X are not luaB_collectgarbage.", (unsigned)kTarget);
        return;
    }
    QueryPerformanceFrequency(&g_freq);
    if (WineSafe_CreateHook(target, (void*)&Hooked_Collect, (void**)&g_orig) != MH_OK || WO_EnableHook(target) != MH_OK) {
        Log("[LuaCollectSkip] NOT active: the hook on 0x%08X could not be created or enabled.", (unsigned)kTarget);
        return;
    }
    g_installed = true;
    g_abSubject = AbTest::IsSubject("LoadingCollectSkip", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("LuaCollectSkip", (const void*)&Hooked_Collect);
    Log("[LuaCollectSkip] ACTIVE on luaB_collectgarbage (0x%08X): collectgarbage(\"collect\") during a loading screen returns 0 without "
        "collecting while the Lua heap is under %d MB; every other call runs. Not yet run in a game.",
        (unsigned)kTarget, kSkipBelowKB / 1024);
}

void Shutdown() {
}

void LogStats() {
    if (!Config::g_settings.OptLoadingCollectSkip) return;
    if (!g_installed) { Log("[LuaCollectSkip] not installed, so nothing here was measured."); return; }
    Log("[LuaCollectSkip] %lu collectgarbage call(s); explicit \"collect\": %lu during loading screens (%lu skipped, %lu ran because the heap "
        "was over the limit, %.0f ms spent in those), %lu outside them (%.0f ms spent). Plain counters, lower bounds.",
        g_calls, g_collectIn, g_skipped, g_bigHeapRan, g_msRanIn, g_collectOut, g_msRanOut);
    bool taken[kWho] = {};
    for (int shown = 0; shown < 6; ++shown) {
        int best = -1;
        for (int i = 0; i < kWho; ++i)
            if (!taken[i] && g_who[i].name[0] && (best < 0 || g_who[i].in + g_who[i].out > g_who[best].in + g_who[best].out)) best = i;
        if (best < 0) break;
        taken[best] = true;
        const Who& w = g_who[best];
        Log("[LuaCollectSkip]   %-24s %lu in loading (%lu skipped), %lu outside, %.0f ms spent in the ones that ran",
            w.name, w.in, w.skipped, w.out, w.ms);
    }
    if (g_whoLost) Log("[LuaCollectSkip]   (%lu call(s) from callers beyond the table)", g_whoLost);
}

} // namespace LuaCollectSkip
