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
static int   g_enableTries  = 0;
static bool  g_saidWaiting  = false;
static int   g_badReports   = 0;
// Set when the client may be left profiling with nothing driving it: the switch
// is off this run, or this module retired after having turned profiling on.
static bool  g_disarmPending  = false;
static DWORD g_disarmLastTry  = 0;
static int   g_disarmTries    = 0;

// Long enough that the numbers mean something, short enough to catch a session
// that only goes bad in a raid.
//
// Two minutes rather than one: collecting means UpdateAddOnCPUUsage walking
// every addon, and in a tester's session fifteen of his slow frames landed
// within two seconds of one of these. That was fifteen hitches spent on a
// report that then came back empty because of the bug above, but even a working
// report should not be bought every sixty seconds.
static constexpr DWORD REPORT_INTERVAL_MS = 120000;

// Turning the profiler on. Every call the client might not have is inside its
// own pcall, because a bare SetCVar on a client without scriptProfile raises,
// and a raise from here reaches the player as an error box at the character
// screen. It did, at every launch, until this was fixed.
// Ask before telling. A bare SetCVar on a client without scriptProfile raises,
// and although pcall keeps that away from the player, this project also hooks
// the Lua error path - so every attempt still landed in the log as
//
//     [LuaError] Caught exception: Couldn't find CVar named 'scriptProfile'
//
// three times a session, which reads like something is broken. GetCVar returns
// nil for a name that does not exist instead of raising, so the check costs
// nothing and the error never happens.
// It also reports whether the player is actually in the world, because "this
// client has no scriptProfile CVar" and "you are still on the character screen"
// look identical from out here and are not the same thing at all. scriptProfile
// is registered by GameUI.cpp's init (sub_52A980, the call at 0x0052A9CB), which
// runs when the world interface loads - so at the glue screen the name genuinely
// does not resolve, and asking then and believing the answer is what broke this.
// See the note on OnFrame.
static const char* kEnableChunk =
    "WOWOPT_PROF_STATE='missing' "
    "local li = false "
    "local okl,r = pcall(IsLoggedIn) if okl and r then li = true end "
    "if not li then WOWOPT_PROF_STATE='notyet' return end "
    "local ok,v = pcall(GetCVar,'scriptProfile') "
    "if ok and v ~= nil then "
    "if pcall(function() SetCVar('scriptProfile','1') end) then "
    "WOWOPT_PROF_STATE='on' end end";

// Builds the whole report inside Lua and leaves it in one global, so the only
// thing crossing back into C is a single string.
//
// Every optional API is called inside its own pcall rather than merely tested
// for existence. Testing existence is not enough and that is what broke the
// first version: GetFrameCPUUsage exists, so `GetFrameCPUUsage and
// GetFrameCPUUsage()` passed the test and then raised, because it takes a frame
// - "Usage: GetFrameCPUUsage(frame[, includeChildren])". One raise aborted the
// whole chunk, so twenty-one reports in a row contained nothing but that error
// and the expensive UpdateAddOnCPUUsage call before it was thrown away each
// time. It is dropped here; it answers a different question anyway.
static const char* kGatherChunk =
    "local ok,err=pcall(function() "
    "if not UpdateAddOnCPUUsage or not GetAddOnCPUUsage or not GetNumAddOns then "
    "WOWOPT_ADDON_CPU='unavailable: this client has no addon CPU accounting' return end "
    "UpdateAddOnCPUUsage() "
    "local n=GetNumAddOns() local t={} local tot=0 "
    "for i=1,n do local c=GetAddOnCPUUsage(i) or 0 "
    "if c>0 then local nm=GetAddOnInfo(i) t[#t+1]={nm or ('addon'..i),c} tot=tot+c end end "
    "table.sort(t,function(a,b) return a[2]>b[2] end) "
    "local p={} "
    "for i=1,math.min(#t,12) do "
    "p[#p+1]=string.format('%s %.0fms %.1f%%',t[i][1],t[i][2],tot>0 and 100*t[i][2]/tot or 0) end "
    "local ev=-1 pcall(function() ev=GetEventCPUUsage() end) "
    "if #t==0 then "
    "WOWOPT_ADDON_CPU='every addon reads zero - script profiling is not running "
    "(scriptProfile missing, or the UI needs one /reload)' return end "
    "WOWOPT_ADDON_CPU=string.format('%d addons, %.0f ms total (events %.0f) | %s',"
    "#t,tot,ev,table.concat(p,' | ')) "
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
//
// Three outcomes, and the caller needs all three. Collapsing the last two into
// "false" is the bug this used to have.
enum EnableResult {
    kProfileOn,       // the CVar exists and is now set
    kNotInWorldYet,   // still at the character screen; ask again later
    kNoSuchCVar       // logged in and the name still does not resolve
};

static EnableResult EnableScriptProfile() {
    char state[64];
    __try {
        FrameScript_Execute_(kEnableChunk, "wow_optimize:addon_profiler", 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return kNotInWorldYet;   // an unusable VM is not evidence about the CVar
    }
    if (!ReadGlobalString("WOWOPT_PROF_STATE", state, sizeof(state)))
        return kNotInWorldYet;
    if (strcmp(state, "on") == 0)     return kProfileOn;
    if (strcmp(state, "notyet") == 0) return kNotInWorldYet;
    return kNoSuchCVar;
}

// Turning it off again, which nothing did.
//
// SetCVar('scriptProfile','1') outlives the switch that asked for it: on clients
// that keep this variable it is still set on the next launch, and on all of them
// it stays set for the rest of the session. Nothing here ever wrote a zero, so
// turning the launcher switch off left the client accounting for every script
// call forever, at the cost the switch description warns about. A reporter ran
// several sessions at single-digit frame rates and had no way to get out of it
// from the interface, because the only thing that had turned it on was gone.
//
// Same shape as the enable: only an answer given while logged in means anything,
// and a client without the CVar has nothing to undo.
static const char* kDisableChunk =
    "WOWOPT_PROF_STATE='missing' "
    "local li = false "
    "local okl,r = pcall(IsLoggedIn) if okl and r then li = true end "
    "if not li then WOWOPT_PROF_STATE='notyet' return end "
    "local ok,v = pcall(GetCVar,'scriptProfile') "
    "if ok and v ~= nil then "
    "if tostring(v) == '0' then WOWOPT_PROF_STATE='off' return end "
    "if pcall(function() SetCVar('scriptProfile','0') end) then "
    "WOWOPT_PROF_STATE='off' end end";

// kProfileOn here means "still on and could not be cleared"; kNoSuchCVar means
// there was nothing to clear. Both end the attempt.
static EnableResult DisableScriptProfile() {
    char state[64];
    __try {
        FrameScript_Execute_(kDisableChunk, "wow_optimize:addon_profiler", 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return kNotInWorldYet;
    }
    if (!ReadGlobalString("WOWOPT_PROF_STATE", state, sizeof(state)))
        return kNotInWorldYet;
    if (strcmp(state, "off") == 0)    return kNoSuchCVar;
    if (strcmp(state, "notyet") == 0) return kNotInWorldYet;
    return kNoSuchCVar;
}

bool Init() {
    if (!Config::g_settings.OptAddonProfiler) {
        // The switch may have been on last time, and what it set persists. Clear
        // it once the interface exists, or the player keeps paying for a feature
        // they turned off.
        g_disarmPending = true;
        return true;
    }

    g_active = true;
    g_lastReport = GetTickCount();
    Log("[AddonProfiler] ACTIVE - turning on the client's own script profiler; "
        "per-addon CPU every %lu seconds", (unsigned long)(REPORT_INTERVAL_MS / 1000));
    // Worth saying up front rather than after two empty reports. The CVar has to
    // be set before the interface compiles its scripts, and it cannot be set
    // before the interface exists - so the first session with this on only
    // arms it. SetCVar persists to Config.wtf, so the session after that
    // profiles from the start. A /reload does the same thing sooner.
    Log("[AddonProfiler] Numbers will read zero until the interface is loaded with "
        "profiling already on. Log in first - the CVar does not exist at the "
        "character screen - then type /reload once, or just play this session and "
        "the next one will have real numbers, because the setting persists. "
        "Adding scriptProfile to Config.wtf by hand does nothing: the client "
        "registers it with its save flag clear, so it is neither read from nor "
        "written to that file.");
    return true;
}

// Called from the main-thread pump. Everything here runs Lua, so it must not
// run from anywhere else, and not while the interface is being torn down.
// Stopping for any reason other than "this client never had the CVar". If
// profiling was switched on, it has to be switched back off: nothing else does
// it, and it outlives this module.
static void Retire() {
    g_active = false;
    if (g_profileOn) {
        g_disarmPending = true;
        g_disarmLastTry = 0;
        g_disarmTries   = 0;
    }
}

void OnFrame(bool luaBusy) {
    if (!g_active && !g_disarmPending) return;
    if (GetCurrentThreadId() != g_mainThreadId) return;
    if (luaBusy) return;

    // Clearing a leftover scriptProfile from a previous session, or from this
    // module giving up after it had already switched profiling on.
    if (g_disarmPending) {
        DWORD nowOff = GetTickCount();
        if (g_disarmLastTry != 0 && nowOff - g_disarmLastTry < 15000) return;
        g_disarmLastTry = nowOff;
        EnableResult r = DisableScriptProfile();
        if (r == kNotInWorldYet) {
            // Not logged in yet, or no usable VM. Keep trying for a while; a
            // client that never logs in has nothing to clear anyway.
            if (++g_disarmTries >= 20) {
                g_disarmPending = false;
            }
            return;
        }
        g_disarmPending = false;
        Log("[AddonProfiler] off - the client's script profiler was set back to 0 "
            "in case a previous session left it on (it outlives this switch)");
        return;
    }

    DWORD now = GetTickCount();
    if (!g_profileOn) {
        // Give the UI a moment to exist before asking it for anything.
        if (now - g_lastReport < 15000) return;
        g_lastReport = now;
        // "One attempt. The answer cannot change between tries - either this
        // client has the CVar or it does not." That comment was here, and it was
        // wrong, and it cost a tester an evening.
        //
        // scriptProfile is registered by GameUI.cpp's init, which runs when the
        // world interface loads. At the character screen the name does not
        // resolve yet. This asked once, 17 seconds in, got "missing", and shut
        // itself off permanently - four and a half minutes before that player
        // first entered the world. He then set the CVar in Config.wtf and
        // /reloaded, exactly as instructed, against a module that had already
        // stopped. Nothing he did could have worked.
        //
        // The chunk now reports the two cases apart, and only an answer given
        // while logged in counts against the tries.
        EnableResult r = EnableScriptProfile();
        if (r == kProfileOn) {
            g_profileOn = true;
            Log("[AddonProfiler] Script profiling is on. First report in %lu seconds; "
                "if every addon reads zero, /reload once.",
                (unsigned long)(REPORT_INTERVAL_MS / 1000));
            return;
        }
        if (r == kNotInWorldYet) {
            // Say it once, so a log that stops here explains itself.
            if (!g_saidWaiting) {
                g_saidWaiting = true;
                Log("[AddonProfiler] Waiting for the world to load - the CVar this "
                    "needs does not exist until the interface does.");
            }
            return;
        }
        if (++g_enableTries > 3) {
            Log("[AddonProfiler] Logged in, and this client still has no "
                "scriptProfile CVar, so there is nothing to account for - "
                "stopping. Nothing further will be logged and no time is spent.");
            g_active = false;
        }
        return;
    }

    if (now - g_lastReport < REPORT_INTERVAL_MS) return;
    g_lastReport = now;

    __try {
        FrameScript_Execute_(kGatherChunk, "wow_optimize:addon_profiler", 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[AddonProfiler] The gather chunk faulted - stopping");
        Retire();
        return;
    }

    char report[1024];
    if (ReadGlobalString("WOWOPT_ADDON_CPU", report, sizeof(report))) {
        ++g_reports;
        Log("[AddonProfiler] #%d  %s", g_reports, report);

        // A report that is only an error is worth saying once, not twenty-one
        // times - and each attempt costs an UpdateAddOnCPUUsage walk over every
        // addon, which is a hitch the player feels for nothing.
        // "every addon reads zero" is not a failure worth giving up on - it is
        // the expected first-session state, and it resolves itself on the next
        // launch because SetCVar persists. Only real errors stop the module.
        if (strncmp(report, "every addon reads zero", 21) == 0) {
            g_badReports = 0;
        } else if (strncmp(report, "error:", 6) == 0 ||
                   strncmp(report, "unavailable", 11) == 0) {
            if (++g_badReports >= 2) {
                Log("[AddonProfiler] Two reports in a row came back with nothing usable "
                    "- stopping rather than paying for the collection every minute.");
                Retire();
            }
        } else {
            g_badReports = 0;
        }
    } else {
        Log("[AddonProfiler] Could not read the result back this time");
        if (++g_badReports >= 2) Retire();
    }
}

void Shutdown() {
    g_active = false;
}

} // namespace AddonProfiler
