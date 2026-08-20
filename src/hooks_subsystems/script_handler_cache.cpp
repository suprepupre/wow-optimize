// ============================================================================
// Module: script_handler_cache.cpp
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <atomic>
#include "MinHook.h"
#include "script_handler_cache.h"

extern "C" void Log(const char* fmt, ...);

// ----------------------------------------------------------------
// FNV-1a 32-bit (compile-time evaluable)
// ----------------------------------------------------------------
static constexpr uint32_t fnv1a(const char* s) {
    uint32_t h = 0x811c9dc5u;
    while (*s) {
        h ^= static_cast<uint8_t>(*s++);
        h *= 0x01000193u;
    }
    return h;
}

// ----------------------------------------------------------------
// Known script handler hashes
// ----------------------------------------------------------------
enum ScriptHash : uint32_t {
    H_ONLOAD              = fnv1a("OnLoad"),
    H_ONSIZECHANGED       = fnv1a("OnSizeChanged"),
    H_ONUPDATE            = fnv1a("OnUpdate"),
    H_ONSHOW              = fnv1a("OnShow"),
    H_ONHIDE              = fnv1a("OnHide"),
    H_ONENTER             = fnv1a("OnEnter"),
    H_ONLEAVE             = fnv1a("OnLeave"),
    H_ONMOUSEDOWN         = fnv1a("OnMouseDown"),
    H_ONMOUSEUP           = fnv1a("OnMouseUp"),
    H_ONMOUSEWHEEL        = fnv1a("OnMouseWheel"),
    H_ONDRAGSTART         = fnv1a("OnDragStart"),
    H_ONDRAGSTOP          = fnv1a("OnDragStop"),
    H_ONRECEIVEDRAG       = fnv1a("OnReceiveDrag"),
    H_ONCHAR              = fnv1a("OnChar"),
    H_ONKEYDOWN           = fnv1a("OnKeyDown"),
    H_ONKEYUP             = fnv1a("OnKeyUp"),
    H_ONATTRIBUTECHANGED  = fnv1a("OnAttributeChanged"),
    H_ONENABLE            = fnv1a("OnEnable"),
    H_ONDISABLE           = fnv1a("OnDisable"),
};

// ----------------------------------------------------------------
// Statistics
// ----------------------------------------------------------------
// Plain 32-bit counters, and the width is the point as much as the atomicity.
//
// These were std::atomic<uint64_t>, incremented with fetch_add on every call
// into the resolver and again on every hit. On 32-bit x86 there is no 64-bit
// atomic add instruction, so each one compiled to a lock cmpxchg8b retry loop -
// in a module whose entire purpose is to replace a linear strcmp chain with a
// hash switch, on the path that runs for every script handler the client
// resolves. hot_functions.cpp carries a comment about this exact instruction
// sequence, and the free wrapper carries another.
//
// A plain 64-bit increment would be worse than no synchronisation at all here:
// it compiles to add/adc across two words, so a race does not merely lose a
// count, it can tear one and produce a number that was never true. An aligned
// 32-bit increment can only ever lose increments, so these are a lower bound
// and are reported as one.
static long g_total_calls = 0;
static long g_fast_path = 0;

// ----------------------------------------------------------------
// Hook state
// ----------------------------------------------------------------
typedef int (__thiscall *orig_handler_resolver_t)(void* self, char* name, void** out);
static orig_handler_resolver_t g_orig_resolver = nullptr;

// ----------------------------------------------------------------
// Fast strcmp (avoids CRT overhead for short known strings)
// ----------------------------------------------------------------
static inline bool streq(const char* a, const char* b) {
    while (*a && *b) {
        if (*a != *b) return false;
        ++a; ++b;
    }
    return *a == *b;
}

// ----------------------------------------------------------------
// Hooked resolver: hash-dispatch instead of linear strcmp chain
// ----------------------------------------------------------------
static int __fastcall Hooked_ScriptHandlerResolver(void* self, void* /*edx*/, char* name, void** out)
{
    ++g_total_calls;

    if (!name || !out) {
        return g_orig_resolver(self, name, out);
    }

    uint32_t h = fnv1a(name);

    switch (h) {
    case H_ONLOAD:
        if (streq(name, "OnLoad")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONSIZECHANGED:
        if (streq(name, "OnSizeChanged")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONUPDATE:
        if (streq(name, "OnUpdate")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONSHOW:
        if (streq(name, "OnShow")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONHIDE:
        if (streq(name, "OnHide")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONENTER:
        if (streq(name, "OnEnter")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONMOUSEDOWN:
        if (streq(name, "OnMouseDown")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONMOUSEUP:
        if (streq(name, "OnMouseUp")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONMOUSEWHEEL:
        if (streq(name, "OnMouseWheel")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONDRAGSTART:
        if (streq(name, "OnDragStart")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONDRAGSTOP:
        if (streq(name, "OnDragStop")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONRECEIVEDRAG:
        if (streq(name, "OnReceiveDrag")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONCHAR:
        if (streq(name, "OnChar")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONKEYDOWN:
        if (streq(name, "OnKeyDown")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONKEYUP:
        if (streq(name, "OnKeyUp")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONATTRIBUTECHANGED:
        if (streq(name, "OnAttributeChanged")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONENABLE:
        if (streq(name, "OnEnable")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    case H_ONDISABLE:
        if (streq(name, "OnDisable")) { ++g_fast_path; break; }
        return g_orig_resolver(self, name, out);

    default:
        return g_orig_resolver(self, name, out);
    }

    // Fall through to original for matched handlers
    // The original function sets up the correct offset + format string
    return g_orig_resolver(self, name, out);
}

// ----------------------------------------------------------------
// Install / Uninstall
// ----------------------------------------------------------------
bool InstallScriptHandlerCache()
{
    // Disabled: the hook never actually replaced the resolver. The original
    // (0x0048E680) first calls sub_816830 (a custom-handler pre-check this code
    // skips) and matches names case-insensitively via _strnicmp, whereas the
    // hash dispatch here is case-sensitive. Unable to reproduce either, every
    // path fell through to g_orig_resolver -- so the hook ran the full original
    // plus an FNV-1a hash, a switch, a streq and two atomics on top. Net loss;
    // let the original resolver run directly.
    (void)&Hooked_ScriptHandlerResolver;
    Log("[ScriptHandlerCache] Disabled (hook was pure overhead over the original)");
    return false;
}

void UninstallScriptHandlerCache()
{
    MH_DisableHook(reinterpret_cast<void*>(0x0048E680));
    MH_RemoveHook(reinterpret_cast<void*>(0x0048E680));

    long total = g_total_calls;
    long fast = g_fast_path;
    if (total > 0) {
        Log("[ScriptHandlerCache] Stats: %ld calls, %ld fast-path (%.1f%%) - counts are a lower bound",
            total, fast, total ? 100.0 * fast / total : 0.0);
    }
}