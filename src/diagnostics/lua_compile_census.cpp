// ============================================================================
// Module: lua_compile_census.cpp
//
// About 5% of executing main-thread time in a real session is inside the Lua
// code generator. The profiler points straight at it: sub_862390, ten
// instructions that write an emitted instruction back into fs->f->code, at
// 4.94% of executing time. That is not a slow function, it is a function called
// an enormous number of times - the client is compiling Lua while you play.
//
// Caching the result is not available here. WoW's Lua is modified and its
// bytecode does not survive a lua_dump and reload, which is why the bytecode
// cache in this project is compiled out and always has been.
//
// But 5% spent compiling almost never means "the game compiles a lot". It means
// something calls loadstring in a hot path - a single addon, usually building a
// closure per update or per event instead of once. Nobody can fix that without
// knowing which one, and nothing has ever counted it.
//
// So this counts. Every chunk handed to the loader, tallied by name, reported
// ranked. It measures nothing about our own code and changes nothing about the
// client's; the answer is a line in the log naming the culprit, and the fix is
// then the addon author's or the player's.
//
// On by default, and silent unless there is something to say. A client that
// compiles a few hundred chunks during load and then stops - which is the
// healthy shape - never prints a word.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include "lua_compile_census.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace LuaCompileCensus {

struct lua_State;

// luaL_loadbuffer is the convenient level. lua_load is one call deeper, where
// luaL_loadbuffer is going anyway - it skips a UTF-8 BOM and calls lua_load with
// the standard getS reader over a {const char* s; size_t size;} pair. Hooking
// the deeper one catches every load rather than only the buffer helper, and is
// the fallback if a client extension has already taken the outer one.
typedef int (__cdecl* luaL_loadbuffer_fn)(lua_State*, const char*, size_t, const char*);
typedef const char* (__cdecl* lua_Reader)(lua_State*, void*, size_t*);
typedef int (__cdecl* lua_load_fn)(lua_State*, lua_Reader, void*, const char*);

static constexpr uintptr_t ADDR_luaL_loadbuffer = 0x0084F860;
static constexpr uintptr_t ADDR_lua_load        = 0x0084ECC0;
static constexpr uintptr_t ADDR_getS            = 0x0084F830;

struct LoadS { const char* s; size_t size; };

static luaL_loadbuffer_fn orig_luaL_loadbuffer = nullptr;
static lua_load_fn        orig_lua_load        = nullptr;

static bool g_active = false;

// Open-addressed, fixed size, never grows. A session that overflows this has
// already answered the question - thousands of distinct chunk names means the
// names are generated, which is itself the finding.
static constexpr int SLOTS = 512;
struct Entry {
    uint64_t key;
    uint32_t count;
    uint64_t bytes;
    char     name[72];
};
static Entry g_tab[SLOTS];
static int      g_used     = 0;
static uint64_t g_total    = 0;
static uint64_t g_totalBytes = 0;
static uint32_t g_overflow = 0;
static int      g_reports  = 0;

// Only the main thread compiles Lua, so no locking. The counters are read from
// the periodic report on that same thread.
static uint64_t Fnv1a(const void* d, size_t n) {
    const unsigned char* p = (const unsigned char*)d;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 0x100000001b3ULL; }
    return h;
}

// What to call this chunk in the report.
//
// A file gets a path; loadstring gets whatever the caller passed, and Lua's
// default is the chunk text itself. Both are useful, so whichever exists is
// taken, trimmed to something that fits on a log line, with newlines flattened
// so one entry cannot spill across the report.
static void DescribeChunk(const char* name, const char* buf, size_t sz,
                          char* out, size_t outSize) {
    const char* src = nullptr;
    size_t      n   = 0;

    if (name && (uintptr_t)name > 0x10000 && (uintptr_t)name < 0xFFE00000) {
        n = strnlen(name, outSize - 1);
        if (n) src = name;
    }
    if (!src && buf) {
        n = sz < (outSize - 1) ? sz : (outSize - 1);
        src = buf;
    }
    if (!src) { lstrcpynA(out, "(unnamed)", (int)outSize); return; }

    size_t w = 0;
    for (size_t i = 0; i < n && w < outSize - 1; ++i) {
        char c = src[i];
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        if ((unsigned char)c < 0x20) c = '.';
        out[w++] = c;
    }
    out[w] = '\0';
}

static void Record(const char* name, const char* buf, size_t sz) {
    char label[72];
    __try {
        DescribeChunk(name, buf, sz, label, sizeof(label));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    ++g_total;
    g_totalBytes += (uint64_t)sz;

    uint64_t k = Fnv1a(label, strlen(label));
    if (!k) k = 1;
    int idx = (int)(k % SLOTS);
    for (int probe = 0; probe < SLOTS; ++probe) {
        Entry& e = g_tab[idx];
        if (e.key == k) { ++e.count; e.bytes += sz; return; }
        if (e.key == 0) {
            e.key = k; e.count = 1; e.bytes = sz;
            lstrcpynA(e.name, label, sizeof(e.name));
            ++g_used;
            return;
        }
        idx = (idx + 1) % SLOTS;
    }
    ++g_overflow;
}

static int __cdecl Hooked_luaL_loadbuffer(lua_State* L, const char* buf, size_t sz,
                                          const char* name) {
    if (g_active) Record(name, buf, sz);
    return orig_luaL_loadbuffer(L, buf, sz, name);
}

static int __cdecl Hooked_lua_load(lua_State* L, lua_Reader reader, void* data,
                                   const char* name) {
    // Only a load streaming from a plain buffer has something to describe; the
    // reader identifies it, and its user data is the {s, size} pair.
    if (g_active) {
        if ((uintptr_t)reader == ADDR_getS && data) {
            __try {
                LoadS* ls = (LoadS*)data;
                Record(name, ls->s, ls->size);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        } else {
            Record(name, nullptr, 0);
        }
    }
    return orig_lua_load(L, reader, data, name);
}

bool Init() {
    if (!Config::g_settings.OptLuaCompileCensus) return true;

    void* outer = (void*)ADDR_luaL_loadbuffer;
    MH_STATUS st = WineSafe_CreateHook(outer, (void*)Hooked_luaL_loadbuffer,
                                       (void**)&orig_luaL_loadbuffer);
    if (st == MH_OK && WO_EnableHook(outer) == MH_OK) {
        g_active = true;
        Log("[LuaCompile] Counting what gets compiled at runtime (luaL_loadbuffer)");
        return true;
    }
    if (st == MH_OK) MH_RemoveHook(outer);
    orig_luaL_loadbuffer = nullptr;

    void* inner = (void*)ADDR_lua_load;
    MH_STATUS st2 = WineSafe_CreateHook(inner, (void*)Hooked_lua_load,
                                        (void**)&orig_lua_load);
    if (st2 == MH_OK && WO_EnableHook(inner) == MH_OK) {
        g_active = true;
        Log("[LuaCompile] Counting what gets compiled at runtime (lua_load - "
            "luaL_loadbuffer was already detoured by something else)");
        return true;
    }
    if (st2 == MH_OK) MH_RemoveHook(inner);
    orig_lua_load = nullptr;

    Log("[LuaCompile] NOT active: neither luaL_loadbuffer (0x%X, status %d) nor "
        "lua_load (0x%X, status %d) could be hooked",
        (unsigned)ADDR_luaL_loadbuffer, (int)st, (unsigned)ADDR_lua_load, (int)st2);
    return false;
}

// Anything at or below this is a client loading its interface once, which is
// what it is supposed to do. Saying so every report would bury the case worth
// reading.
static constexpr uint64_t QUIET_BELOW = 2000;

void LogStats() {
    if (!g_active || g_total == 0) return;
    if (g_total < QUIET_BELOW && g_reports > 0) return;

    ++g_reports;

    if (g_total < QUIET_BELOW) {
        Log("[LuaCompile] %llu chunks compiled so far (%llu KB) - normal; "
            "nothing is recompiling in a loop",
            (unsigned long long)g_total, (unsigned long long)(g_totalBytes / 1024));
        return;
    }

    // Rank by count. A dozen is plenty: the shape of this problem is one or two
    // entries with five figures and a long tail of ones.
    int order[12];
    int n = 0;
    for (int i = 0; i < SLOTS; ++i) {
        if (!g_tab[i].key) continue;
        int pos = n;
        if (n < 12) { order[n++] = i; }
        else if (g_tab[i].count > g_tab[order[11]].count) { order[11] = i; }
        else continue;
        for (pos = (n < 12 ? n - 1 : 11); pos > 0; --pos) {
            if (g_tab[order[pos]].count > g_tab[order[pos - 1]].count) {
                int t = order[pos]; order[pos] = order[pos - 1]; order[pos - 1] = t;
            } else break;
        }
    }

    Log("[LuaCompile] %llu chunks compiled (%llu KB, %d distinct%s) - this is why "
        "the Lua code generator is hot. Top by count:",
        (unsigned long long)g_total, (unsigned long long)(g_totalBytes / 1024),
        g_used, g_overflow ? ", table full" : "");

    for (int i = 0; i < n; ++i) {
        const Entry& e = g_tab[order[i]];
        Log("[LuaCompile]   %6u x  %5llu KB  %s",
            e.count, (unsigned long long)(e.bytes / 1024), e.name);
    }
    Log("[LuaCompile] Anything here with a five-figure count is being compiled "
        "over and over - that addon is calling loadstring in a hot path, and "
        "fixing or removing it is worth several percent of your CPU.");
}

void Shutdown() {
    if (!g_active) return;
    g_active = false;
    if (orig_luaL_loadbuffer) MH_DisableHook((void*)ADDR_luaL_loadbuffer);
    if (orig_lua_load)        MH_DisableHook((void*)ADDR_lua_load);
}

} // namespace LuaCompileCensus
