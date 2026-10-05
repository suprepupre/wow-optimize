// ============================================================================
// Module: anim_track_census
//
// In the drain profile of 2026-10-04 the M2 track evaluators we already replaced
// are the largest block of our own code: the rotation track about 5% of executing
// time, the keyframe search about 4%, the translation and scale track about 2.5%,
// after replacements that measured 3.3x, 3.9x and 3.9x faster than the client's
// own. What is left is the work itself, run for every bone of every visible model
// on every frame.
//
// A track evaluation is a function of the track, the animation time, the
// animation index, and for a blended pair the second time, index and weight, and
// the default value the track falls back on. If the same question comes back, the
// answer could be kept. Whether it comes back is not something the code can say.
// A model's own bone array repeating (the animation census: 82% of calls) is not
// the same thing: the arguments of the call that census compares do not contain
// the time, and the one module built on it retired itself. A track and a time are
// shared by every instance of a model file, so this can repeat across models and
// across frames in a way a per-bone comparison cannot see, or it can fail to,
// because the time is a millisecond counter and a frame is six to sixteen of them.
//
// This counts it. Every evaluation that has a real keyframe search to do is
// reduced to a 64-bit key of everything the answer depends on, and the key is
// looked up in simulated direct-mapped tables of several sizes, one per kind of
// track. A table holds only the key, so a hit says "a cache this size would have
// held this question", which is the number needed to decide whether a real one is
// worth building and how big it should be: a hit has to beat the evaluation, and
// a table too large for the cache misses on every lookup.
//
// Also counted, per bone record: how often the key equals the one the same record
// produced last time, which is the animation being paused, as opposed to
// revisited.
//
// Not measured: anything about the answers. The key is built from the inputs.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include "anim_track_census.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);
extern DWORD g_mainThreadId;

namespace AnimTrackCensus {

bool g_on = false;

namespace {

constexpr int kSizes = 5;
constexpr int kSizeBits[kSizes] = { 12, 14, 16, 18, 22 };
constexpr int kRecBits = 16;

struct PerKind {
    uint64_t* table[kSizes] = {};
    uint64_t* lastByRecord = nullptr;       // key a bone record produced last time
    uint64_t  calls = 0;
    uint64_t  trivial = 0;                  // nothing to search: no keys or one
    uint64_t  searched = 0;                 // a real keyframe search
    uint64_t  blended = 0;                  // of those, a second track blended in
    uint64_t  globalSeq = 0;                // of those, driven by a global sequence
    uint64_t  hit[kSizes] = {};
    uint64_t  sameAsRecordsLast = 0;
    // The same counters at the previous report, for a per-interval figure.
    uint64_t  prevSearched = 0, prevHit[kSizes] = {}, prevSame = 0;
};

PerKind g_k[kKinds];
bool g_ready = false;

uint64_t Mix(uint64_t h, uint64_t w) {
    h ^= w + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2);
    h *= 0xFF51AFD7ED558CCDull;
    h ^= h >> 32;
    return h;
}

}  // namespace

void Observe(Kind kind, const void* obj, const uint8_t* state, const uint8_t* track,
             const float* defaults) {
    if (!g_ready || GetCurrentThreadId() != g_mainThreadId) return;
    PerKind& k = g_k[kind];
    ++k.calls;

    // The same fields the evaluators read (anim_vec3_track_sse2.cpp, anim_quat_unpack_sse2.cpp).
    const uint32_t w0      = *(const uint32_t*)(track + 0x00);        // interp | global sequence << 16
    const uint32_t count   = *(const uint32_t*)(track + 0x0C);
    const uint32_t entries = *(const uint32_t*)(track + 0x10);
    const uint32_t gs      = w0 >> 16;
    const uint16_t id1     = *(const uint16_t*)(state + 0x44);
    const uint32_t sel     = (id1 < count) ? id1 : 0u;
    const uint32_t nKeys   = *(const uint32_t*)(entries + 8u * sel);
    if (nKeys <= 1) { ++k.trivial; return; }
    ++k.searched;

    uint32_t time1 = *(const uint32_t*)(state + 0x40);
    if (gs != 0xFFFFu) {
        ++k.globalSeq;
        const uint32_t* seqs = *(const uint32_t* const*)((const uint8_t*)obj + 0x70);
        if (seqs) time1 = seqs[gs];
    }
    uint64_t h = Mix(0x1234567ull, (uint32_t)(uintptr_t)track);
    h = Mix(h, entries);
    h = Mix(h, count);
    h = Mix(h, w0);
    h = Mix(h, time1);
    h = Mix(h, id1);

    const float blend = *(const float*)(state + 0x0A8);
    if (blend != 0.0f && gs == 0xFFFFu) {
        ++k.blended;
        h = Mix(h, *(const uint32_t*)(state + 0x64));
        h = Mix(h, *(const uint16_t*)(state + 0x68));
        h = Mix(h, *(const uint32_t*)(state + 0xA8));
    }
    const int nDef = (kind == kQuat) ? 4 : 3;
    for (int i = 0; i < nDef; ++i) h = Mix(h, ((const uint32_t*)defaults)[i]);
    if (h == 0) h = 1;

    for (int s = 0; s < kSizes; ++s) {
        uint64_t& slot = k.table[s][h & ((1ull << kSizeBits[s]) - 1)];
        if (slot == h) ++k.hit[s];
        slot = h;
    }
    uint64_t& last = k.lastByRecord[Mix(0, (uint32_t)(uintptr_t)state) >> (64 - kRecBits)];
    // A record is identified by its address; two records sharing a slot only make this a
    // lower bound on the repeat share.
    if (last == h) ++k.sameAsRecordsLast;
    last = h;
}

bool Init() {
    if (!Config::g_settings.OptAnimTrackCensus) return true;
    for (int kind = 0; kind < kKinds; ++kind) {
        PerKind& k = g_k[kind];
        for (int s = 0; s < kSizes; ++s) {
            const size_t bytes = (size_t)8 << kSizeBits[s];
            // High in the address space: the low half is the scarce one.
            k.table[s] = (uint64_t*)VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
            if (!k.table[s]) {
                Log("[AnimTrackCensus] NOT active: %u bytes could not be allocated.", (unsigned)bytes);
                return false;
            }
        }
        k.lastByRecord = (uint64_t*)VirtualAlloc(nullptr, (size_t)8 << kRecBits, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
        if (!k.lastByRecord) return false;
    }
    g_ready = true;
    g_on = true;
    Log("[AnimTrackCensus] ACTIVE: every rotation and translation/scale track evaluation that has a "
        "keyframe search to do is reduced to a key of all its inputs and looked up in simulated "
        "direct-mapped tables of 2^12, 2^14, 2^16, 2^18 and 2^22 entries. Costs frames; a "
        "measurement for one session.");
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptAnimTrackCensus) return;
    if (!g_ready) { Log("[AnimTrackCensus] not active - the reason is at the top of this log"); return; }
    static const char* const name[kKinds] = { "rotation (sub_828680)", "translation/scale (sub_82B0A0)" };
    for (int kind = 0; kind < kKinds; ++kind) {
        PerKind& k = g_k[kind];
        if (k.calls == 0) {
            Log("[AnimTrackCensus] %s: no calls yet. That is a measurement: nothing animated since it went in.",
                name[kind]);
            continue;
        }
        Log("[AnimTrackCensus] %s: %llu evaluations, %llu with at most one keyframe (nothing to search), "
            "%llu searched; of those %llu blended with a second track, %llu on a global sequence.",
            name[kind], (unsigned long long)k.calls, (unsigned long long)k.trivial,
            (unsigned long long)k.searched, (unsigned long long)k.blended, (unsigned long long)k.globalSeq);
        if (k.searched == 0) continue;
        const uint64_t dS = k.searched - k.prevSearched;
        char line[512];
        int n = 0;
        for (int s = 0; s < kSizes; ++s) {
            const uint64_t dH = k.hit[s] - k.prevHit[s];
            n += snprintf(line + n, sizeof(line) - n, " 2^%d: %.1f%% (this interval %.1f%%)", kSizeBits[s],
                          100.0 * (double)k.hit[s] / (double)k.searched,
                          dS ? 100.0 * (double)dH / (double)dS : 0.0);
        }
        Log("[AnimTrackCensus]   a cache would have held the question:%s", line);
        Log("[AnimTrackCensus]   the same bone record asked the same question as last time (animation "
            "not advancing): %.1f%% (this interval %.1f%%). A lower bound: records share slots.",
            100.0 * (double)k.sameAsRecordsLast / (double)k.searched,
            dS ? 100.0 * (double)(k.sameAsRecordsLast - k.prevSame) / (double)dS : 0.0);
        k.prevSearched = k.searched;
        for (int s = 0; s < kSizes; ++s) k.prevHit[s] = k.hit[s];
        k.prevSame = k.sameAsRecordsLast;
    }
}

}  // namespace AnimTrackCensus
