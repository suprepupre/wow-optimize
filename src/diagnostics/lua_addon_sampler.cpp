// ============================================================================
// Module: lua_addon_sampler.cpp
// Description: Charges main-thread samples to the addon whose Lua is running.
// Safety & Threading: NoteSample runs on the profiler thread with the main
//              thread suspended. Everything it touches is read-only and wrapped
//              in SEH, because a suspended thread can be caught mid-write.
// ============================================================================
//
// Every offset below was read out of the client, not assumed from stock Lua,
// because this VM is +4-shifted and reading stock offsets is what produced the
// smushed-text bug.
//
//   lua_getstack (sub_84FE40):
//       v5 = *(a1 + 24)                  L->ci          -> L + 0x18
//       *(a1 + 44)                       L->base_ci     -> L + 0x2C
//       v5 -= 24                         sizeof(CallInfo) = 24
//       **(_DWORD **)(v5 + 4)            *ci->func      -> CallInfo + 4
//       *(_BYTE *)(closure + 10)         isC            -> Closure + 10
//
//   funcinfo (sub_84FF80), the else branch that fills in a Lua function:
//       *(a1+16) = *(*(a2 + 24) + 36) + 20
//                                        cl->p          -> Closure + 0x18
//                                        p->source      -> Proto   + 0x24
//                                        TString data   -> TString + 20
//
// The source string a chunk carries is what the loader was given, so an addon
// file reads "@Interface\AddOns\WeakAuras\core.lua" and Blizzard's own UI reads
// "@Interface\FrameXML\...". That prefix is the whole attribution.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include "lua_addon_sampler.h"
#include "core/config.h"

extern "C" void Log(const char* fmt, ...);

namespace LuaAddonSampler {

namespace {

// The global lua_State, read out of FrameScript_Execute: it loads this and
// hands it to luaL_loadbuffer and lua_pcall.
constexpr uintptr_t kLuaStatePtr = 0x00D3F78C;

constexpr unsigned kOff_L_ci        = 0x18;
constexpr unsigned kOff_L_base_ci   = 0x2C;
constexpr unsigned kSizeof_CallInfo = 24;
constexpr unsigned kOff_ci_func     = 4;
constexpr unsigned kOff_cl_isC      = 10;
constexpr unsigned kOff_cl_proto    = 0x18;
constexpr unsigned kOff_proto_src   = 0x24;
constexpr unsigned kOff_tstring_data = 20;

// How far down the call stack to look for something attributable. A sample
// taken inside a library helper is still the caller's cost, and addon code is
// usually within a few frames. Bounded because this runs with the main thread
// stopped.
constexpr int kMaxDepth = 24;

constexpr int  kMaxNames = 192;
constexpr int  kNameLen  = 48;

struct Bucket {
    char     name[kNameLen];
    uint64_t samples;
};

Bucket   g_buckets[kMaxNames];
int      g_bucketCount = 0;

uint64_t g_total       = 0;   // samples where Lua was executing
uint64_t g_notInLua    = 0;   // main thread was not inside a Lua call
uint64_t g_unreadable  = 0;   // state could not be read (mid-write, or no VM)
uint64_t g_unattributed = 0;  // Lua ran but nothing named a source

inline uint32_t Rd32(uintptr_t p) { return *(volatile uint32_t*)p; }
inline uint8_t  Rd8(uintptr_t p)  { return *(volatile uint8_t*)p; }

// A pointer that could plausibly be a heap object in this process. Cheap
// rejection, not validation: the SEH block is what makes this safe, and this
// only avoids the cost of faulting on obvious garbage.
inline bool Plausible(uint32_t p) {
    return p >= 0x00010000u && p < 0xF0000000u && (p & 3) == 0;
}

// Copies the addon name out of a source string, or classifies it.
// Returns false when the string says nothing worth charging to anyone.
bool NameFromSource(const char* src, char* out, size_t outSize) {
    if (!src) return false;

    // Skip the load-type marker Lua puts in front: '@' file, '=' literal.
    if (*src == '@' || *src == '=') src++;

    static const char kAddons[]   = "Interface\\AddOns\\";
    static const char kFrameXML[] = "Interface\\FrameXML\\";

    if (_strnicmp(src, kAddons, sizeof(kAddons) - 1) == 0) {
        const char* p = src + sizeof(kAddons) - 1;
        size_t i = 0;
        while (p[i] && p[i] != '\\' && p[i] != '/' && i + 1 < outSize) {
            out[i] = p[i];
            i++;
        }
        out[i] = 0;
        return i > 0;
    }

    if (_strnicmp(src, kFrameXML, sizeof(kFrameXML) - 1) == 0) {
        strncpy_s(out, outSize, "(Blizzard UI)", _TRUNCATE);
        return true;
    }

    // Handlers compiled out of XML arrive as "*:OnLoad" and similar, with no
    // file behind them. They are real work and worth seeing, but they cannot be
    // charged to an addon from here.
    if (src[0] == '*' && src[1] == ':') {
        strncpy_s(out, outSize, "(XML handlers)", _TRUNCATE);
        return true;
    }

    return false;
}

void Charge(const char* name) {
    for (int i = 0; i < g_bucketCount; i++) {
        if (strcmp(g_buckets[i].name, name) == 0) {
            g_buckets[i].samples++;
            return;
        }
    }
    if (g_bucketCount < kMaxNames) {
        strncpy_s(g_buckets[g_bucketCount].name, kNameLen, name, _TRUNCATE);
        g_buckets[g_bucketCount].samples = 1;
        g_bucketCount++;
    }
}

} // namespace

void Reset() {
    memset(g_buckets, 0, sizeof(g_buckets));
    g_bucketCount = 0;
    g_total = g_notInLua = g_unreadable = g_unattributed = 0;
}

void NoteSample() {
    if (!Config::g_settings.OptLuaAddonProfile) return;

    char name[kNameLen];
    name[0] = 0;
    int outcome = 0;   // 0 unreadable, 1 not in Lua, 2 attributed, 3 no source

    __try {
        uint32_t L = Rd32(kLuaStatePtr);
        if (!Plausible(L)) {
            outcome = 0;
        } else {
            uint32_t ci     = Rd32(L + kOff_L_ci);
            uint32_t baseCi = Rd32(L + kOff_L_base_ci);

            if (!Plausible(ci) || !Plausible(baseCi) || ci < baseCi) {
                outcome = 0;
            } else if (ci == baseCi) {
                // No active call. The main thread is somewhere else entirely
                // and charging this sample to whatever ran last would be a
                // fabrication.
                outcome = 1;
            } else {
                outcome = 3;
                for (int depth = 0; depth < kMaxDepth && ci > baseCi; depth++,
                                                        ci -= kSizeof_CallInfo) {
                    uint32_t funcSlot = Rd32(ci + kOff_ci_func);
                    if (!Plausible(funcSlot)) continue;
                    uint32_t cl = Rd32(funcSlot);
                    if (!Plausible(cl)) continue;
                    if (Rd8(cl + kOff_cl_isC)) continue;      // C function, keep walking

                    uint32_t proto = Rd32(cl + kOff_cl_proto);
                    if (!Plausible(proto)) continue;
                    uint32_t srcTs = Rd32(proto + kOff_proto_src);
                    if (!Plausible(srcTs)) continue;

                    const char* src = (const char*)(srcTs + kOff_tstring_data);
                    if (NameFromSource(src, name, sizeof(name))) {
                        outcome = 2;
                        break;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        outcome = 0;
    }

    switch (outcome) {
        case 1: g_notInLua++; break;
        case 2: g_total++; Charge(name); break;
        case 3: g_total++; g_unattributed++; break;
        default: g_unreadable++; break;
    }
}

void Report() {
    if (!Config::g_settings.OptLuaAddonProfile) return;

    uint64_t seen = g_total + g_notInLua + g_unreadable;
    if (seen == 0) {
        Log("[LuaAddonSampler] no samples taken - the sampling profiler is the "
            "source of these and it did not run");
        return;
    }
    if (g_total == 0) {
        Log("[LuaAddonSampler] %llu samples, none of them inside a Lua call "
            "(%llu outside, %llu unreadable). Either this session ran almost no "
            "addon code, or the VM was never up while sampling.",
            (unsigned long long)seen, (unsigned long long)g_notInLua,
            (unsigned long long)g_unreadable);
        return;
    }

    Log("[LuaAddonSampler] %llu of %llu samples were inside Lua (%.1f%% of "
        "main-thread samples). This is time spent, not calls counted, and it "
        "costs nothing on the paths it measures.",
        (unsigned long long)g_total, (unsigned long long)seen,
        100.0 * (double)g_total / (double)seen);

    // Simple selection sort over a small table, once per report.
    int order[kMaxNames];
    for (int i = 0; i < g_bucketCount; i++) order[i] = i;
    for (int i = 0; i < g_bucketCount; i++) {
        int best = i;
        for (int j = i + 1; j < g_bucketCount; j++) {
            if (g_buckets[order[j]].samples > g_buckets[order[best]].samples) best = j;
        }
        int t = order[i]; order[i] = order[best]; order[best] = t;
    }

    int shown = 0;
    for (int i = 0; i < g_bucketCount && shown < 15; i++, shown++) {
        const Bucket& b = g_buckets[order[i]];
        Log("[LuaAddonSampler]   %-28s %6llu samples  %5.1f%% of Lua time",
            b.name, (unsigned long long)b.samples,
            100.0 * (double)b.samples / (double)g_total);
    }

    if (g_unattributed > 0) {
        Log("[LuaAddonSampler]   %llu samples (%.1f%%) were in Lua that named no "
            "source this walk could place - loaded from a string, or deeper than "
            "it looks.",
            (unsigned long long)g_unattributed,
            100.0 * (double)g_unattributed / (double)g_total);
    }
    if (g_unreadable > 0) {
        Log("[LuaAddonSampler]   %llu samples could not be read at all. A sample "
            "lands wherever the thread happened to be, including halfway through "
            "the VM updating its own stack, and those are dropped rather than "
            "guessed at.", (unsigned long long)g_unreadable);
    }
}

} // namespace LuaAddonSampler
