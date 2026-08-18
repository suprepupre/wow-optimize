// ============================================================================
// Module: lua_proto_cache.cpp
// Description: Skips luaY_parser for source the client has already compiled.
// Safety & Threading: Main thread only, alongside the Lua state.
// ============================================================================
//
// The compile census answered this one with a number. Over txtsd's sessions:
//
//     43129 chunks compiled (447262 KB) - 38037 of them (88%) were source
//           already compiled earlier in the same session - 332563 KB repeated
//
// The names at the top of that tally are `*:OnLoad`, `*:OnClick`, `*:OnEnter`:
// the chunk names WoW gives to script handlers written inline in an XML
// template. Every frame built from that template recompiles them. Independently
// the sampling profiler puts the Lua code generator (sub_862390, the ten
// instructions that write an emitted opcode into fs->f->code) at 4.94% of
// executing main-thread time.
//
// ---------------------------------------------------------------------------
// Why the obvious route does not work here
//
// The textbook fix is lua_dump plus reload. That is dead in this client, and it
// was checked in the disassembler rather than assumed. Stock Lua 5.1 f_parser
// does a luaZ_lookahead and picks luaU_undump or luaY_parser by LUA_SIGNATURE.
// WoW's f_parser (0x00856190) has no lookahead and no undump call at all - it
// goes straight to luaY_parser. Bytecode loading is gone from the client, so a
// dumped chunk has nothing to load it.
//
// ---------------------------------------------------------------------------
// What this does instead: keep the Proto, let the client build the closure
//
// f_parser, verbatim from 0x00856190:
//
//     proto = luaY_parser(L, z, buff, name)
//     cl    = luaF_newLclosure(L, proto->nups, L->gt)
//     cl->p = proto
//     ...upvalues if nups...
//     L->top->value = cl; L->top->tt = 6; L->top->taint = *dword_D4139C
//
// So the hook sits on luaY_parser and nothing else. On a repeat it returns the
// Proto it kept from last time and the parse does not run. Everything after -
// the closure, its environment, its taint - is still built by the client's own
// code, on the hit exactly as on a miss.
//
// That division is what makes reuse safe, and it was checked, not assumed:
//
//   - luaF_newproto (0x0085CF40) allocates 80 bytes and zeroes every field. It
//     never touches dword_D4139C. A Proto carries no taint.
//   - luaF_newLclosure (0x0085CC90) allocates a fresh 32-byte taint block per
//     closure and zeroes it, and writes the environment into cl+16.
//   - f_parser stamps the pushed TValue with the taint current at push time.
//
// Two closures over one Proto is what the client itself produces whenever the
// same function is created twice at runtime. Sharing the compiled code shares
// no ownership, no environment and no taint.
//
// ---------------------------------------------------------------------------
// What the parser does besides parse, since skipping a call has gone wrong here
// before
//
//   - It consumes the ZIO. Nothing reads the ZIO afterwards: luaD_protectedparser
//     frees the Mbuffer, and both the ZIO and the getS pair are stack locals of
//     lua_load and luaL_loadbuffer. Leaving it unread is inert.
//   - It interns TStrings for the chunk name and every constant. Those are
//     already interned from the first compile and stay reachable through the
//     cached Proto.
//   - It can raise a syntax error. A hit is source that compiled cleanly once,
//     so there is no error to raise.
//   - It allocates, which is the point of not running it.
//
// ---------------------------------------------------------------------------
// Keeping the Proto alive
//
// A Proto is a collectable object. Once the closure holding it is dropped, the
// GC frees it and a cached pointer becomes a dangling one. So on a miss the
// closure the client just built is duplicated and anchored in the registry with
// luaL_ref, and the GC reaches the Proto through it. The reference is never
// released: an entry costs one closure, and the cache is capped.
//
// The anchoring happens in a second hook on luaL_loadbuffer, one level out,
// where the closure is on the stack and we are at an API boundary rather than
// halfway through a parse.
//
// ---------------------------------------------------------------------------
// Identity
//
// Two chunks are the same chunk when the source bytes and the chunk name are
// both identical. The name matters: it becomes the Proto source string and
// shows up in every error message and traceback from that function.
//
// The hash only selects a candidate. What decides a hit is a memcmp of the full
// source and the full name, so a hash collision cannot serve the wrong code.
// Paying for that means keeping a copy of the source, which is why chunks above
// kMaxChunkBytes are not cached at all - they are counted instead, so the log
// can say how much was left behind rather than quietly ignoring it.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <unordered_map>

#include "lua_proto_cache.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace LuaProtoCache {

namespace {

// --- The client -------------------------------------------------------------

constexpr uintptr_t kLuaYParser     = 0x00861AD0;  // Proto* (L, ZIO*, Mbuffer*, name)
constexpr uintptr_t kLuaLLoadBuffer = 0x0084F860;  // int (L, buf, size, name)
constexpr uintptr_t kGetSReader     = 0x0084F830;  // the reader luaL_loadbuffer installs
constexpr uintptr_t kLuaPushValue   = 0x0084DE50;
constexpr uintptr_t kLuaLRef        = 0x0084F6C0;

constexpr int kRegistryIndex = -10000;

// lua_State, +4-shifted from stock like everything else in this client.
constexpr unsigned kL_top = 0x0C;
constexpr unsigned kL_lG  = 0x14;

// ZIO, from luaZ_init at 0x0085D140: n, p, reader, data, L.
constexpr unsigned kZ_n      = 0;
constexpr unsigned kZ_reader = 8;
constexpr unsigned kZ_data   = 12;

// Proto, from luaF_newproto at 0x0085CF40 (80 bytes, every field zeroed) and
// open_func at 0x0085F410, which writes source at +36 and maxstacksize at +79.
constexpr unsigned kP_code            = 16;
constexpr unsigned kP_source          = 36;
constexpr unsigned kP_sizek           = 44;
constexpr unsigned kP_sizecode        = 48;
constexpr unsigned kP_sizep           = 56;
constexpr unsigned kP_linedefined     = 64;
constexpr unsigned kP_lastlinedefined = 68;
constexpr unsigned kP_nups            = 76;
constexpr unsigned kP_numparams       = 77;
constexpr unsigned kP_isvararg        = 78;
constexpr unsigned kP_maxstacksize    = 79;

// LClosure, from luaF_newLclosure: isC at +10, nups at +11, env at +16, the
// taint block at +20, p at +24, upvalue slots from +28.
constexpr unsigned kC_isC = 10;
constexpr unsigned kC_p   = 24;

constexpr uint32_t kTagFunction = 6;

typedef void* (__cdecl* luaY_parser_fn)(void* L, void* z, void* buff, const char* name);
typedef int   (__cdecl* luaL_loadbuffer_fn)(void* L, const char* buf, size_t sz, const char* name);
typedef int   (__cdecl* lua_pushvalue_fn)(void* L, int idx);
typedef int   (__cdecl* luaL_ref_fn)(void* L, int t);

luaY_parser_fn     orig_luaY_parser     = nullptr;
luaL_loadbuffer_fn orig_luaL_loadbuffer = nullptr;

lua_pushvalue_fn p_lua_pushvalue = (lua_pushvalue_fn)kLuaPushValue;
luaL_ref_fn      p_luaL_ref      = (luaL_ref_fn)kLuaLRef;

inline uint32_t RD32(const void* p, unsigned off) { return *(const uint32_t*)((const char*)p + off); }
inline uint8_t  RD8 (const void* p, unsigned off) { return *(const uint8_t*) ((const char*)p + off); }
inline void*    RDP (const void* p, unsigned off) { return *(void* const*)   ((const char*)p + off); }

// --- Budget -----------------------------------------------------------------
//
// The census puts the average repeated chunk at 8.7 KB, so 32 KB keeps every
// handler-sized chunk and turns away whole addon files, which load once and
// never repeat anyway. The totals below cap what the cache can cost at roughly
// 12 MB of source copies; both limits are reported, so a session that hits one
// says so rather than silently degrading.

constexpr size_t kMaxChunkBytes = 32u * 1024u;
constexpr size_t kMaxEntries    = 8192;
constexpr size_t kMaxTotalBytes = 12u * 1024u * 1024u;

// --- Verification -----------------------------------------------------------
//
// A hit runs the real parser as well for the first kVerifyFirst hits and one in
// kResampleMask+1 after that, then compares the two Protos. During a check the
// caller is handed the client's freshly parsed Proto, never the cached one, so
// a verifying session behaves exactly like an unhooked one.

constexpr unsigned long kVerifyFirst  = 2000;
constexpr unsigned long kResampleMask = 255;

struct Entry {
    void*         proto;
    char*         blob;      // source bytes, then the name, both NUL-terminated
    uint32_t      srcLen;
    uint32_t      nameLen;
    unsigned long hits;
};

std::unordered_map<uint64_t, Entry> g_cache;
size_t g_blobBytes = 0;

void*  g_globalState = nullptr;   // the l_G these Protos belong to
DWORD  g_ownerThread = 0;

bool g_installed = false;
bool g_dead      = false;

unsigned long g_seen = 0, g_hits = 0, g_stored = 0;
unsigned long g_tooBig = 0, g_notBuffer = 0, g_capped = 0, g_anchorFailed = 0;
unsigned long g_verified = 0;
unsigned long long g_bytesSaved = 0, g_bytesTooBig = 0;

// What luaY_parser handed back on a miss, for the luaL_loadbuffer hook one
// level out to anchor. Only ever written and read on the owner thread.
struct Pending {
    bool        want;
    uint64_t    key;
    const char* src;
    size_t      srcLen;
    const char* name;
    size_t      nameLen;
    void*       proto;
};
Pending g_pending = { false, 0, nullptr, 0, nullptr, 0, nullptr };

uint64_t Fnv1a(const void* d, size_t n, uint64_t h) {
    const unsigned char* p = (const unsigned char*)d;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001b3ULL; }
    return h;
}

uint64_t KeyOf(const char* src, size_t srcLen, const char* name, size_t nameLen) {
    uint64_t h = Fnv1a(src, srcLen, 0xcbf29ce484222325ULL);
    h = Fnv1a(name, nameLen, h);
    h ^= (uint64_t)srcLen * 0x9E3779B97F4A7C15ULL;
    return h;
}

void FlushAll() {
    for (std::unordered_map<uint64_t, Entry>::iterator it = g_cache.begin();
         it != g_cache.end(); ++it) {
        free(it->second.blob);
    }
    g_cache.clear();
    g_blobBytes = 0;
}

void Retire(const char* why) {
    if (g_dead) return;
    g_dead = true;
    FlushAll();
    Log("[ProtoCache] Disabled for this session: %s. Every chunk is compiled by "
        "the client from here on.", why);
}

// Everything a repeat compile of identical source must reproduce. The bytecode
// array is the real check; the rest catches a mismatch earlier and names it.
bool ProtosAgree(void* a, void* b, const char** what) {
    if (RD32(a, kP_sizecode)        != RD32(b, kP_sizecode))        { *what = "sizecode";        return false; }
    if (RD32(a, kP_sizek)           != RD32(b, kP_sizek))           { *what = "sizek";           return false; }
    if (RD32(a, kP_sizep)           != RD32(b, kP_sizep))           { *what = "sizep";           return false; }
    if (RD32(a, kP_linedefined)     != RD32(b, kP_linedefined))     { *what = "linedefined";     return false; }
    if (RD32(a, kP_lastlinedefined) != RD32(b, kP_lastlinedefined)) { *what = "lastlinedefined"; return false; }
    if (RD8 (a, kP_nups)            != RD8 (b, kP_nups))            { *what = "nups";            return false; }
    if (RD8 (a, kP_numparams)       != RD8 (b, kP_numparams))       { *what = "numparams";       return false; }
    if (RD8 (a, kP_isvararg)        != RD8 (b, kP_isvararg))        { *what = "is_vararg";       return false; }
    if (RD8 (a, kP_maxstacksize)    != RD8 (b, kP_maxstacksize))    { *what = "maxstacksize";    return false; }

    // Identical names intern to one TString, and the cached Proto keeps its own
    // alive, so these are the same pointer or something is wrong.
    if (RDP(a, kP_source) != RDP(b, kP_source)) { *what = "source"; return false; }

    uint32_t n = RD32(a, kP_sizecode);
    const void* ca = RDP(a, kP_code);
    const void* cb = RDP(b, kP_code);
    if (n) {
        if (!ca || !cb) { *what = "code (null)"; return false; }
        if (memcmp(ca, cb, (size_t)n * 4) != 0) { *what = "code"; return false; }
    }
    return true;
}

// Pulls the source out of the reader and decides what to do with this chunk.
// Returns the cached Proto on a reuse that needs no check, or null to let the
// client compile - with g_pending armed when the result is worth keeping.
void* Classify(void* L, void* z, void* buff, const char* name, bool* checked) {
    *checked = false;

    if (RD32(z, kZ_reader) != (uint32_t)kGetSReader) { g_notBuffer++; return nullptr; }
    if (RD32(z, kZ_n) != 0)                          { g_notBuffer++; return nullptr; }

    const uint32_t* ud = (const uint32_t*)RDP(z, kZ_data);
    if (!ud) { g_notBuffer++; return nullptr; }

    const char* src    = (const char*)ud[0];
    size_t      srcLen = (size_t)ud[1];
    if (!src || srcLen == 0) { g_notBuffer++; return nullptr; }

    size_t nameLen = strlen(name);
    g_seen++;

    if (srcLen > kMaxChunkBytes) {
        g_tooBig++;
        g_bytesTooBig += srcLen;
        return nullptr;
    }

    // A new global state means every Proto from the old one is gone with it.
    void* lG = RDP(L, kL_lG);
    if (lG != g_globalState) {
        if (g_globalState) FlushAll();
        g_globalState = lG;
    }

    uint64_t key = KeyOf(src, srcLen, name, nameLen);
    std::unordered_map<uint64_t, Entry>::iterator it = g_cache.find(key);
    if (it != g_cache.end()) {
        const Entry& e = it->second;
        if (e.srcLen == srcLen && e.nameLen == nameLen &&
            memcmp(e.blob, src, srcLen) == 0 &&
            memcmp(e.blob + srcLen + 1, name, nameLen) == 0) {

            it->second.hits++;
            g_hits++;
            g_bytesSaved += srcLen;

            if ((g_hits > kVerifyFirst) && ((g_hits & kResampleMask) != 0))
                return e.proto;

            // Let the client compile it too and compare. The caller is handed
            // the client result, so a checked reuse changes nothing at all.
            void* fresh = orig_luaY_parser(L, z, buff, name);
            *checked = true;
            if (!fresh) return nullptr;

            const char* what = "";
            if (!ProtosAgree(e.proto, fresh, &what)) {
                Log("[ProtoCache] Cached and freshly compiled Proto differ in %s "
                    "for \"%s\" (%u bytes of source).",
                    what, name, (unsigned)srcLen);
                Retire("a cached chunk did not match a fresh compile");
                return fresh;
            }
            g_verified++;
            return fresh;
        }
        // Same hash, different chunk. The first one keeps the slot.
        return nullptr;
    }

    if (g_cache.size() >= kMaxEntries ||
        g_blobBytes + srcLen + nameLen + 2 > kMaxTotalBytes) {
        g_capped++;
        return nullptr;
    }

    g_pending.want    = true;
    g_pending.key     = key;
    g_pending.src     = src;
    g_pending.srcLen  = srcLen;
    g_pending.name    = name;
    g_pending.nameLen = nameLen;
    g_pending.proto   = nullptr;
    return nullptr;
}

void* __cdecl Hooked_luaY_parser(void* L, void* z, void* buff, const char* name) {
    g_pending.want = false;

    if (g_dead || !L || !z || !name) return orig_luaY_parser(L, z, buff, name);

    // One Lua state, one thread. Anything else compiles normally.
    DWORD tid = GetCurrentThreadId();
    if (g_ownerThread == 0) g_ownerThread = tid;
    else if (g_ownerThread != tid) return orig_luaY_parser(L, z, buff, name);

    void* decided = nullptr;
    bool  checked = false;
    __try {
        decided = Classify(L, z, buff, name, &checked);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_pending.want = false;
        Retire("reading the source out of the reader faulted");
        return orig_luaY_parser(L, z, buff, name);
    }

    // Either a reuse, or a check that already ran the parser for us.
    if (decided || checked) return decided;

    void* p = orig_luaY_parser(L, z, buff, name);
    if (g_pending.want) g_pending.proto = p;
    return p;
}

// Duplicate the closure the client just built and hand it to the registry, so
// the GC reaches the Proto through it for the rest of the session.
bool AnchorTopClosure(void* L, void* proto) {
    uintptr_t top = *(uintptr_t*)((char*)L + kL_top);
    if (!top) return false;
    const char* tv = (const char*)(top - 16);
    if (RD32(tv, 8) != kTagFunction) return false;
    void* cl = RDP(tv, 0);
    if (!cl) return false;
    if (RD8(cl, kC_isC) != 0) return false;
    if (RDP(cl, kC_p) != proto) return false;

    p_lua_pushvalue(L, -1);
    return p_luaL_ref(L, kRegistryIndex) > 0;
}

int __cdecl Hooked_luaL_loadbuffer(void* L, const char* buf, size_t sz, const char* name) {
    g_pending.want = false;
    int rc = orig_luaL_loadbuffer(L, buf, sz, name);

    if (rc != 0 || g_dead || !g_pending.want || !g_pending.proto) {
        g_pending.want = false;
        return rc;
    }

    __try {
        if (!AnchorTopClosure(L, g_pending.proto)) {
            g_anchorFailed++;
        } else {
            size_t blobLen = g_pending.srcLen + g_pending.nameLen + 2;
            char* blob = (char*)malloc(blobLen);
            if (blob) {
                memcpy(blob, g_pending.src, g_pending.srcLen);
                blob[g_pending.srcLen] = 0;
                memcpy(blob + g_pending.srcLen + 1, g_pending.name, g_pending.nameLen);
                blob[g_pending.srcLen + 1 + g_pending.nameLen] = 0;

                Entry e;
                e.proto   = g_pending.proto;
                e.blob    = blob;
                e.srcLen  = (uint32_t)g_pending.srcLen;
                e.nameLen = (uint32_t)g_pending.nameLen;
                e.hits    = 0;
                g_cache[g_pending.key] = e;
                g_blobBytes += blobLen;
                g_stored++;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Retire("anchoring a compiled chunk faulted");
    }

    g_pending.want = false;
    return rc;
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptLuaProtoCache) return true;

    if (IsBadReadPtr((void*)kLuaYParser, 8) || IsBadReadPtr((void*)kLuaLLoadBuffer, 8)) {
        Log("[ProtoCache] 0x%08X or 0x%08X unreadable - not installing",
            (unsigned)kLuaYParser, (unsigned)kLuaLLoadBuffer);
        return false;
    }

    if (WineSafe_CreateHook((void*)kLuaYParser, (void*)Hooked_luaY_parser,
                            (void**)&orig_luaY_parser) != MH_OK) {
        Log("[ProtoCache] luaY_parser hook NOT created");
        return false;
    }
    if (WineSafe_CreateHook((void*)kLuaLLoadBuffer, (void*)Hooked_luaL_loadbuffer,
                            (void**)&orig_luaL_loadbuffer) != MH_OK) {
        Log("[ProtoCache] luaL_loadbuffer hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kLuaYParser) != MH_OK ||
        WO_EnableHook((void*)kLuaLLoadBuffer) != MH_OK) {
        Log("[ProtoCache] hooks created but could not be enabled");
        return false;
    }

    g_installed = true;
    Log("[ProtoCache] ACTIVE on luaY_parser (0x%08X). A census of tester sessions "
        "found 88%% of compiled chunks were source already compiled that session, "
        "332 MB of repeated parsing. Repeats now reuse the compiled Proto and the "
        "client still builds the closure, its environment and its taint. Chunks "
        "over %u KB are not cached. The first %lu reuses are checked against a "
        "fresh compile, then one in %d.",
        (unsigned)kLuaYParser, (unsigned)(kMaxChunkBytes / 1024), kVerifyFirst,
        (int)(kResampleMask + 1));
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptLuaProtoCache) return;
    if (!g_installed) { Log("[ProtoCache] not installed - nothing measured"); return; }
    if (g_seen == 0)  { Log("[ProtoCache] installed but no chunk reached it yet"); return; }

    Log("[ProtoCache] %lu chunks offered, %lu reused (%.1f%%), %lu cached in %u KB, "
        "%llu KB of parsing skipped%s",
        g_seen, g_hits, g_seen ? (100.0 * (double)g_hits / (double)g_seen) : 0.0,
        g_stored, (unsigned)(g_blobBytes / 1024), g_bytesSaved / 1024,
        g_dead ? " - DISABLED" : "");
    Log("[ProtoCache]   %lu reuses verified against a fresh compile; turned away: "
        "%lu over the size cap (%llu KB), %lu after the cache filled, %lu not a "
        "flat buffer, %lu could not be anchored",
        g_verified, g_tooBig, g_bytesTooBig / 1024, g_capped, g_notBuffer,
        g_anchorFailed);
}

} // namespace LuaProtoCache
