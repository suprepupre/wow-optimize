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
#include <unordered_set>

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
constexpr unsigned kP_lineinfo        = 24;
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
// Nothing is cached until it has been compiled twice.
//
// The first field session said why. Of 6023 chunks, only 863 were repeats, but
// the cache took the first 3648 it saw, filled its 12 MB on chunks averaging
// 3.4 KB that never came back, and then turned away 1656 later ones - including
// the repeats it existed for. The client's own census, in the same log, named
// them: `*:OnLoad`, 831 compiles totalling 150 KB. About 185 bytes each. They
// would have fitted a hundred times over.
//
// So a first sighting only records a key and a length, twelve bytes and no copy
// of the source. The source is kept on the second sighting, and reuse starts on
// the third. That costs one extra compile per chunk and buys a cache holding
// nothing but proven repeats, which is also why the per-chunk limit can be
// larger now: 402 chunks were refused for exceeding 32 KB, and with only proven
// repeats competing for the budget there is room to keep the ones that recur.

constexpr size_t kMaxChunkBytes = 128u * 1024u;
constexpr size_t kMaxEntries    = 8192;
constexpr size_t kMaxTotalBytes = 24u * 1024u * 1024u;
constexpr size_t kMaxSeenKeys   = 32768;

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
    // Read off the Proto when it was stored, checked again before it is handed
    // back. If the block was freed and the client's Lua memory pool handed it
    // to something else, these stop matching. See FingerprintStillHolds.
    uint32_t      fpCode;
    uint32_t      fpLineinfo;
    uint32_t      fpSizecode;
};

// A recycled Proto is what the crash on 2026-08-22 was: the client faulted in
// its own error formatter at sub_84FDF0, reading Proto->lineinfo[pc] with
// lineinfo holding 4. Four is not a pointer, and the client's only guard there
// is a test against zero, so a small non-zero value walks straight into a read
// of address 4.
//
// The root cause is fixed elsewhere - the cache now hears about every lua_State
// swap instead of guessing from l_G. This is the second line: three words read
// when the Proto was stored and compared before it is used. It cannot prove a
// Proto is alive, and a block recycled into another Proto with the same shape
// would still pass. It does catch the case that actually happened, where the
// pool wrote its own bookkeeping over the fields.
bool FingerprintStillHolds(const Entry& e) {
    __try {
        uint32_t code     = RD32(e.proto, kP_code);
        uint32_t lineinfo = RD32(e.proto, kP_lineinfo);
        uint32_t sizecode = RD32(e.proto, kP_sizecode);
        if (code != e.fpCode || lineinfo != e.fpLineinfo || sizecode != e.fpSizecode)
            return false;
        // Whatever they are, code has to be a real pointer and lineinfo has to
        // be one or nothing. This is what the client itself fails to check.
        if (code < 0x10000) return false;
        if (lineinfo != 0 && lineinfo < 0x10000) return false;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::unordered_map<uint64_t, Entry> g_cache;
size_t g_blobBytes = 0;

// Chunks compiled once. Value is the source length, so a key collision between
// two different chunks does not promote either of them on the wrong evidence.
std::unordered_map<uint64_t, uint32_t> g_seenOnce;

// Chunks that have already earned their place once. A reload replaces the Lua
// state and every Proto in it, so the cache has to be emptied - but what is worth
// caching is not state-specific knowledge, and throwing it away meant every
// handler had to be compiled twice again after each reload. The first field
// session did four of them. This set survives, so a chunk already known to repeat
// is kept the first time it is seen in the new state.
std::unordered_set<uint64_t> g_knownRepeaters;

void*  g_globalState = nullptr;   // the l_G these Protos belong to
DWORD  g_ownerThread = 0;

bool g_installed = false;
bool g_dead      = false;

unsigned long g_seen = 0, g_hits = 0, g_stored = 0;
unsigned long g_tooBig = 0, g_notBuffer = 0, g_capped = 0, g_anchorFailed = 0;
unsigned long g_verified = 0, g_firstSighting = 0, g_flushes = 0, g_onSight = 0;
unsigned long g_stale = 0;
unsigned long long g_bytesSaved = 0, g_bytesTooBig = 0;

// What the cache saves, in time rather than in kilobytes.
//
// This module has always reported "N KB of parsing skipped", and kilobytes of
// source are not a saving - the whole argument for building it was that 88% of
// compiled chunks were source already compiled, which is equally not a saving.
// The number that decides whether it is worth its risk is how long the parses it
// skipped would have taken.
//
// No A/B run is needed for it. A miss runs the client's parser and can be timed
// directly; a hit skips it entirely and costs the lookup. Mean miss time times
// the hit count is what the session saved, and both halves are measured here
// rather than assumed.
//
// One call in 64 is timed on each side. The parser is not a per-frame hot path -
// a few thousand calls a session - so the sampling is only there to keep a
// context switch from dominating a small sample set.
LARGE_INTEGER g_parseFreq = {};
unsigned long g_missTimed = 0, g_hitTimed = 0;
double        g_missMsTotal = 0.0, g_hitMsTotal = 0.0;
constexpr unsigned kParseSampleMask = 63;
unsigned long g_parseSeq = 0;

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
    g_seenOnce.clear();
    g_blobBytes = 0;
}

// Set by OnLuaStateSwapped, acted on inside the parser hook where the cache is
// actually touched. A flush from arbitrary code would be a container mutation
// at a moment this module knows nothing about.
bool g_swapPending = false;
unsigned long g_swapFlushes = 0;

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
    // Two independent reasons to drop everything, and the second is the one
    // that matters. l_G changing proves a new state; l_G staying the same
    // proves nothing, because the client's Lua memory pool reuses the address.
    void* lG = RDP(L, kL_lG);
    if (g_swapPending) {
        g_swapPending = false;
        if (g_globalState) { FlushAll(); g_flushes++; g_swapFlushes++; }
    } else if (lG != g_globalState) {
        if (g_globalState) { FlushAll(); g_flushes++; }
    }
    g_globalState = lG;

    uint64_t key = KeyOf(src, srcLen, name, nameLen);
    std::unordered_map<uint64_t, Entry>::iterator it = g_cache.find(key);
    if (it != g_cache.end()) {
        const Entry& e = it->second;
        if (e.srcLen == srcLen && e.nameLen == nameLen &&
            memcmp(e.blob, src, srcLen) == 0 &&
            memcmp(e.blob + srcLen + 1, name, nameLen) == 0) {

            if (!FingerprintStillHolds(e)) {
                // Do not hand it back and do not trust anything else stored
                // under the same state either.
                g_stale++;
                FlushAll();
                Log("[ProtoCache] A kept Proto no longer looks like the one that "
                    "was stored (\"%s\"). Everything held has been dropped; the "
                    "client compiles this one.", name);
                return nullptr;
            }

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

    // A first sighting leaves a key and a length behind and nothing else. Only
    // something the client has now compiled twice is worth a copy of its source.
    std::unordered_map<uint64_t, uint32_t>::iterator seen = g_seenOnce.find(key);
    bool second = (seen != g_seenOnce.end() && seen->second == (uint32_t)srcLen);
    bool known  = (g_knownRepeaters.find(key) != g_knownRepeaters.end());

    if (!second && !known) {
        if (g_seenOnce.size() < kMaxSeenKeys) {
            g_seenOnce[key] = (uint32_t)srcLen;
            g_firstSighting++;
        } else {
            g_capped++;
        }
        return nullptr;
    }

    if (g_cache.size() >= kMaxEntries ||
        g_blobBytes + srcLen + nameLen + 2 > kMaxTotalBytes) {
        g_capped++;
        return nullptr;
    }

    // Promoted. If the anchor fails later this key is gone and the chunk simply
    // starts again as unseen, which costs one more compile and corrects itself.
    if (second) g_seenOnce.erase(seen);
    if (known) {
        g_onSight++;
    } else if (g_knownRepeaters.size() < kMaxSeenKeys) {
        // Remember that this one repeats, so the next Lua state keeps it the
        // first time it appears instead of paying for a second compile again.
        g_knownRepeaters.insert(key);
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

    // Taken before Classify, so a timed hit covers the lookup as well as the
    // skipped parse - which is what the client actually pays on a hit.
    LARGE_INTEGER enter;
    if (g_parseFreq.QuadPart) QueryPerformanceCounter(&enter);
    else                      enter.QuadPart = 0;

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
    //
    // `decided` without `checked` is a straight reuse: the parser did not run.
    // Timed here so the saving can be stated in milliseconds rather than in
    // kilobytes of source, which is not a saving. A verification pass sets
    // `checked` and did run the parser, so it is not timed as a hit.
    if (decided || checked) {
        if (decided && !checked && g_parseFreq.QuadPart &&
            (++g_parseSeq & kParseSampleMask) == 0) {
            LARGE_INTEGER e;
            QueryPerformanceCounter(&e);
            double ms = (double)(e.QuadPart - enter.QuadPart) * 1000.0
                      / (double)g_parseFreq.QuadPart;
            if (ms >= 0.0 && ms < 100.0) { g_hitMsTotal += ms; ++g_hitTimed; }
        }
        return decided;
    }

    const bool timeThis = g_parseFreq.QuadPart &&
                          (++g_parseSeq & kParseSampleMask) == 0;
    LARGE_INTEGER a;
    if (timeThis) QueryPerformanceCounter(&a);
    void* p = orig_luaY_parser(L, z, buff, name);
    if (timeThis) {
        LARGE_INTEGER b2;
        QueryPerformanceCounter(&b2);
        double ms = (double)(b2.QuadPart - a.QuadPart) * 1000.0
                  / (double)g_parseFreq.QuadPart;
        // A parse that spans a context switch is not a measurement of the parser,
        // and one of them outweighs a hundred honest samples in a mean.
        if (ms >= 0.0 && ms < 100.0) { g_missMsTotal += ms; ++g_missTimed; }
    }
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
                e.fpCode     = RD32(g_pending.proto, kP_code);
                e.fpLineinfo = RD32(g_pending.proto, kP_lineinfo);
                e.fpSizecode = RD32(g_pending.proto, kP_sizecode);
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
        // Both hooks or neither. This one anchors the Proto the parser hook
        // keeps, and without it the collector frees a Proto still in the cache -
        // which is the crash this module already has a story about. Leaving the
        // parser hook created also leaves the address claimed against anything
        // else that wants it, for a feature that is not going to run.
        MH_RemoveHook((void*)kLuaYParser);
        orig_luaY_parser = nullptr;
        Log("[ProtoCache] NOT active: luaL_loadbuffer (0x%08X) is already hooked "
            "by something else, and without it a kept Proto cannot be anchored "
            "against the collector. If that something else is the Lua compile "
            "census, run the two in separate sessions.",
            (unsigned)kLuaLLoadBuffer);
        return false;
    }
    if (WO_EnableHook((void*)kLuaYParser) != MH_OK ||
        WO_EnableHook((void*)kLuaLLoadBuffer) != MH_OK) {
        MH_RemoveHook((void*)kLuaYParser);
        MH_RemoveHook((void*)kLuaLLoadBuffer);
        orig_luaY_parser = nullptr;
        orig_luaL_loadbuffer = nullptr;
        Log("[ProtoCache] NOT active: hooks created but could not be enabled");
        return false;
    }

    QueryPerformanceFrequency(&g_parseFreq);
    g_installed = true;
    Log("[ProtoCache] ACTIVE on luaY_parser (0x%08X). A census of tester sessions "
        "found 88%% of compiled chunks were source already compiled that session, "
        "332 MB of repeated parsing. Repeats now reuse the compiled Proto and the "
        "client still builds the closure, its environment and its taint. A chunk "
        "is kept only once the client has compiled it twice, so the cache holds "
        "proven repeats rather than whatever came first; chunks over %u KB are "
        "never kept. The first %lu reuses are checked against a fresh compile, "
        "then one in %d.",
        (unsigned)kLuaYParser, (unsigned)(kMaxChunkBytes / 1024), kVerifyFirst,
        (int)(kResampleMask + 1));
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptLuaProtoCache) return;
    if (!g_installed) { Log("[ProtoCache] not installed - nothing measured"); return; }
    if (g_seen == 0)  { Log("[ProtoCache] installed but no chunk reached it yet"); return; }

    // The saving in time, which is the figure this module exists to produce and
    // has never printed. Kilobytes of source skipped is not a saving; the parses
    // those kilobytes would have cost is.
    if (g_missTimed && g_hitTimed) {
        double meanMiss = g_missMsTotal / (double)g_missTimed;
        double meanHit  = g_hitMsTotal  / (double)g_hitTimed;
        Log("[ProtoCache] a parse costs %.3f ms on average over %lu timed misses; "
            "a reuse costs %.3f ms over %lu timed hits. At %lu reuses that is "
            "about %.0f ms of parsing this session that did not happen.",
            meanMiss, g_missTimed, meanHit, g_hitTimed, g_hits,
            (meanMiss - meanHit) * (double)g_hits);
    } else if (g_missTimed || g_hitTimed) {
        Log("[ProtoCache] only one of hit and miss was ever timed (%lu misses, "
            "%lu hits sampled), so there is no saving to state - not a saving of "
            "zero.", g_missTimed, g_hitTimed);
    } else {
        Log("[ProtoCache] no parse was timed, so the saving is not measured rather "
            "than measured small. One call in %u is sampled.",
            kParseSampleMask + 1);
    }

    Log("[ProtoCache] %lu chunks offered, %lu reused (%.1f%%), %llu KB of parsing "
        "skipped%s",
        g_seen, g_hits, g_seen ? (100.0 * (double)g_hits / (double)g_seen) : 0.0,
        g_bytesSaved / 1024, g_dead ? " - DISABLED" : "");

    // Holding now and stored over the session are different numbers, and printing
    // one under the other's label is how an earlier log came to read "3648 cached
    // in 1 KB" after a reload emptied the cache.
    Log("[ProtoCache]   holding %u chunks in %u KB now; %lu stored over the "
        "session, %lu of them kept on sight as known repeaters; %lu Lua state "
        "reset(s) emptied it; %u compiled once so far and not repeated, %u known "
        "to repeat",
        (unsigned)g_cache.size(), (unsigned)(g_blobBytes / 1024), g_stored,
        g_onSight, g_flushes, (unsigned)g_seenOnce.size(),
        (unsigned)g_knownRepeaters.size());

    Log("[ProtoCache]   %lu reuses verified against a fresh compile; turned away: "
        "%lu over the %u KB size cap (%llu KB), %lu after the cache filled, %lu "
        "not a flat buffer, %lu could not be anchored (%lu of the resets were "
        "reported by the state-swap watcher rather than noticed here)",
        g_verified, g_tooBig, (unsigned)(kMaxChunkBytes / 1024),
        g_bytesTooBig / 1024, g_capped, g_notBuffer, g_anchorFailed,
        g_swapFlushes);
    if (g_stale)
        Log("[ProtoCache]   %lu times a kept Proto had stopped looking like "
            "itself and the cache was emptied. Anything above zero here means a "
            "state swap went unseen.", g_stale);
}

void OnLuaStateSwapped() {
    // Only a flag. The flush happens inside the parser hook, on the thread that
    // owns the containers, before the next lookup can reach a stale entry.
    g_swapPending = true;
}

} // namespace LuaProtoCache
