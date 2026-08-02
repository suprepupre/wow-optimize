// ============================================================================
// Module: addon_profiler.cpp
//
// "Do you think it would be possible to profile how much time each addon is
// using per frame and graph it out?" - a tester, on a session running at 7-16
// fps with a quarter of the CPU going to one third-party library and no way to
// tell which of his thirty addons were paying for it.
//
// It is possible, and it needs almost nothing from us, because the client
// already has a script profiler. The strings are all in the binary:
//
//     UpdateAddOnCPUUsage   GetAddOnCPUUsage   ResetCPUUsage
//     GetEventCPUUsage      GetFrameCPUUsage   GetScriptCPUUsage
//     GetNumAddOns          GetAddOnInfo
//
// gated behind the scriptProfile CVar, which registers at 0x0052A9CB and
// defaults to zero. Nobody turns it on because nothing in the default UI
// exposes it.
//
// So this does not measure anything itself. It switches the client's own
// profiler on, and every interval asks it - in Lua, through the client's own
// FrameScript_Execute - for the per-addon totals, then reads the answer back
// and writes it to the log ranked by cost.
//
// Deliberately no walking of Lua structures beyond the one read that gets the
// answer string back, and that read follows the shape the client's own C API
// leaves behind: lua_getfield pushes, top is at L+0x0C, a TValue is sixteen
// bytes with its type tag at -8, and a string's characters start twenty bytes
// into the TString. Everything else goes through the client's functions. This
// is a diagnostic, and a diagnostic that crashes the game is worth less than
// no diagnostic at all.
//
// Off by default: the client's profiler is not free, and a player who is not
// chasing a stutter should not pay for it.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "addon_profiler.h"
#include "config.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);
extern DWORD g_mainThreadId;

namespace AddonProfiler {

// Runs a Lua chunk. Same entry point loading_defrag uses.
typedef void (__cdecl* FrameScript_Execute_fn)(const char* code, const char* source, int flags);
static const FrameScript_Execute_fn FrameScript_Execute_ =
    (FrameScript_Execute_fn)0x00819210;

// Pushes a global onto the Lua stack.
typedef void (__cdecl* lua_getfield_fn)(uintptr_t L, int index, const char* k);
static const lua_getfield_fn lua_getfield_ = (lua_getfield_fn)0x0084E590;

// The global lua_State, read out of FrameScript_Execute itself - it loads
// dword_D3F78C and hands it to luaL_loadbuffer and lua_pcall.
static constexpr uintptr_t ADDR_LuaStatePtr = 0x00D3F78C;

static constexpr int LUA_GLOBALSINDEX = -10002;
static constexpr int LUA_TSTRING      = 4;
static constexpr uintptr_t OFF_Top    = 0x0C;   // lua_State::top
static constexpr int TVALUE_SIZE      = 16;     // this build carries a taint word
static constexpr int OFF_TString_Data = 20;

static bool  g_active       = false;
static bool  g_profileOn    = false;
static DWORD g_lastReport   = 0;
static int   g_reports      = 0;

// Long enough that the numbers mean something, short enough to catch a session
// that only goes bad in a raid.
static constexpr DWORD REPORT_INTERVAL_MS = 60000;

// Builds the whole report inside Lua and leaves it in one global, so the only
// thing crossing back into C is a single string.
static const char* kGatherChunk =
    "local ok,err=pcall(function() "
    "if not UpdateAddOnCPUUsage or not GetAddOnCPUUsage then "
    "WOWOPT_ADDON_CPU='unavailable: this client has no script profiler' return end "
    "UpdateAddOnCPUUsage() "
    "local n=GetNumAddOns() local t={} local tot=0 "
    "for i=1,n do local c=GetAddOnCPUUsage(i) or 0 "
    "if c>0 then local nm=GetAddOnInfo(i) t[#t+1]={nm or ('addon'..i),c} tot=tot+c end end "
    "table.sort(t,function(a,b) return a[2]>b[2] end) "
    "local p={} "
    "for i=1,math.min(#t,12) do "
    "p[#p+1]=string.format('%s %.0fms %.1f%%',t[i][1],t[i][2],tot>0 and 100*t[i][2]/tot or 0) end "
    "local ev=GetEventCPUUsage and GetEventCPUUsage() or -1 "
    "local fr=GetFrameCPUUsage and GetFrameCPUUsage() or -1 "
    "WOWOPT_ADDON_CPU=string.format('%d addons, %.0f ms total (events %.0f, frames %.0f) | %s',"
    "#t,tot,ev,fr,table.concat(p,' | ')) "
    "end) "
    "if not ok then WOWOPT_ADDON_CPU='error: '..tostring(err) end";

// Reads one Lua global string back. Guarded, and it always restores the stack
// top it moved, including on the paths that do not find a string.
static bool ReadGlobalString(const char* name, char* out, size_t outSize) {
    uintptr_t L = 0;
    __try {
        L = *(uintptr_t*)ADDR_LuaStatePtr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    if (L < 0x10000 || L >= 0xFFE00000) return false;

    bool got = false;
    __try {
        lua_getfield_(L, LUA_GLOBALSINDEX, name);

        uintptr_t top = *(uintptr_t*)(L + OFF_Top);
        if (top >= 0x10000) {
            int tt = *(int*)(top - 8);
            if (tt == LUA_TSTRING) {
                uintptr_t ts = *(uintptr_t*)(top - TVALUE_SIZE);
                if (ts >= 0x10000 && ts < 0xFFE00000) {
                    const char* s = (const char*)(ts + OFF_TString_Data);
                    size_t n = strnlen(s, outSize - 1);
                    memcpy(out, s, n);
                    out[n] = '\0';
                    got = true;
                }
            }
            // Pop what lua_getfield pushed, whatever it turned out to be.
            *(uintptr_t*)(L + OFF_Top) = top - TVALUE_SIZE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return got;
}

// Turning the client's profiler on. It has to happen through Lua rather than by
// poking the CVar, because SetCVar is what tells the script system to start
// accounting; writing the variable behind its back sets a value nothing reads.
static void EnableScriptProfile() {
    __try {
        FrameScript_Execute_(
            "if SetCVar then SetCVar('scriptProfile','1') end",
            "wow_optimize:addon_profiler", 0);
        g_profileOn = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

bool Init() {
    if (!Config::g_settings.OptAddonProfiler) return true;

    g_active = true;
    g_lastReport = GetTickCount();
    Log("[AddonProfiler] ACTIVE - turning on the client's own script profiler; "
        "per-addon CPU every %lu seconds", (unsigned long)(REPORT_INTERVAL_MS / 1000));
    Log("[AddonProfiler] If the first report says every addon is at zero, reload "
        "the interface once (/reload) - the client only accounts for scripts it "
        "compiled after profiling was switched on");
    return true;
}

// Called from the main-thread pump. Everything here runs Lua, so it must not
// run from anywhere else, and not while the interface is being torn down.
void OnFrame(bool luaBusy) {
    if (!g_active) return;
    if (GetCurrentThreadId() != g_mainThreadId) return;
    if (luaBusy) return;

    DWORD now = GetTickCount();
    if (!g_profileOn) {
        // Give the UI a moment to exist before asking it for anything.
        if (now - g_lastReport < 15000) return;
        EnableScriptProfile();
        g_lastReport = now;
        return;
    }

    if (now - g_lastReport < REPORT_INTERVAL_MS) return;
    g_lastReport = now;

    __try {
        FrameScript_Execute_(kGatherChunk, "wow_optimize:addon_profiler", 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[AddonProfiler] The gather chunk faulted - stopping");
        g_active = false;
        return;
    }

    char report[1024];
    if (ReadGlobalString("WOWOPT_ADDON_CPU", report, sizeof(report))) {
        ++g_reports;
        Log("[AddonProfiler] #%d  %s", g_reports, report);
    } else {
        Log("[AddonProfiler] Could not read the result back this time");
    }
}

void Shutdown() {
    g_active = false;
}

} // namespace AddonProfiler
