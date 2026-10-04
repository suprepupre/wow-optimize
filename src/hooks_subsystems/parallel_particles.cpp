// ============================================================================
// Particle vertex fill on worker threads.
//
// The client is single-threaded: in a tester's three-hour profile on a
// 16-thread machine the main thread executed 67% of the time and every one of
// the client's own worker threads sat in a kernel wait. Building particle
// geometry was about 6% of the main thread there, more in a raid full of
// spell effects. This spreads that one job over otherwise idle cores.
//
// What the client does, per emitter (IDA, 2026-09-28):
//   sub_97E730  locks a dynamic vertex buffer through the Gx device (vtable
//               +216), sets up a writer (sub_97A2E0), calls sub_97E580, then
//               unlocks (+220) and draws (sub_97A580).
//   sub_97E580  for each particle, sub_97BE80(emitter, particle, writer);
//               the unsorted loop is 0x0097E650-0x0097E67E.
//   sub_97BE80  writes the particle's vertices through the writer and widens
//               the emitter's bounding box at +0x218..+0x22C.
//
// Why it can run in parallel: sub_97BE80 and the twenty functions it reaches
// write no global. Its random numbers come from a stack-local generator seeded
// from the particle itself (sub_4C1510(particle+30) -> sub_464580). The globals
// it reads - the billboard basis at 0x00B2D540.. - are written per emitter by
// sub_97A390 before the fill starts. Its only writes outside the vertex buffer
// are the emitter's bounding box, which sub_97EA60 resets to +-FLT_MAX just
// before this loop, and nothing else calls the loop.
//
// How:
//   * The Gx lock, unlock and draw stay on the main thread in the client's
//     order; only the loop in between is replaced (a jump at 0x0097E650 that
//     rejoins at 0x0097E680, where the client computes the rest itself).
//   * The emitter's particles are cut into chunks. Each chunk runs the
//     client's own sub_97BE80 against a private copy of the emitter (560 bytes,
//     the furthest field the tree reads is +0x22C) and a private writer aimed
//     at a staging area whose end touches a guard page. The client sizes the
//     buffer for vpp (+0x8C) vertices per particle, so a chunk that wrote more
//     would already overflow the client's own buffer; here it faults on the
//     guard instead, is caught, and the emitter is filled the client's way.
//   * The chunks are copied into the real buffer in order, the writer is
//     advanced as the client would have left it, and the bounding boxes are
//     merged with the client's rule (a coordinate replaces the box only when
//     strictly smaller or larger, so on equal values the earlier one stays).
//
// Checked, not argued: for the first 2000 emitters and one in 256 after, the
// client's loop also runs - on the real emitter, into a staging area of its
// own - and the two are compared byte for byte: every vertex byte, the
// bounding box, the rest of the emitter (which must not have changed), and the
// dummy normal a stream without normals writes to. The client's answer is the
// one used. The first difference retires the module for the session.
//
// Not reached by this: the sorted path (emitters with flag 0x20 at +0x134),
// which keeps the client's loop. Off by default, experimental.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <intrin.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include "parallel_particles.h"
#include "config.h"
#include "version.h"
#include "session_verdict.h"
#include "sampling_profiler.h"
#include "ab_test.h"

extern "C" void Log(const char* fmt, ...);

namespace ParallelParticles {

namespace {

// ---- the client ------------------------------------------------------------

constexpr uintptr_t kLoopBytes  = 0x0097E646;   // byte check starts here
constexpr uintptr_t kPatchAt    = 0x0097E650;   // loop head, 7-byte cmp
constexpr unsigned  kPatchLen   = 7;
constexpr uintptr_t kRejoin     = 0x0097E680;   // test ebx, ebx after the loop
constexpr uintptr_t kFillFn     = 0x0097BE80;

// mov ebx,[ebp+0Ch] / test ebx,ebx / jbe / lea ecx,[ecx+0] / the loop itself.
const unsigned char kLoopWant[0x3A] = {
    0x8B, 0x5D, 0x0C, 0x85, 0xDB, 0x76, 0x35, 0x8D, 0x49, 0x00, 0x83, 0xBE, 0x98, 0x00, 0x00, 0x00,
    0x00, 0x8B, 0x46, 0x54, 0x8B, 0x04, 0xB8, 0x75, 0x08, 0xC1, 0xE0, 0x05, 0x03, 0x46, 0x34, 0xEB,
    0x06, 0xC1, 0xE0, 0x06, 0x03, 0x46, 0x44, 0x8B, 0x4D, 0x08, 0x51, 0x50, 0x8B, 0xCE, 0xE8, 0x07,
    0xD8, 0xFF, 0xFF, 0x83, 0xC7, 0x01, 0x3B, 0xFB, 0x72, 0xD0,
};

// Emitter fields the loop and the fill use.
constexpr unsigned kEmParticles32 = 0x34;
constexpr unsigned kEmParticles64 = 0x44;
constexpr unsigned kEmIndices     = 0x54;
constexpr unsigned kEmVertsPer    = 0x8C;
constexpr unsigned kEmWide        = 0x98;
constexpr unsigned kEmBox         = 0x218;      // min xyz, max xyz
constexpr unsigned kEmCopyBytes   = 0x230;

typedef int (__thiscall* FillFn)(void* emitter, const void* particle, void* writer);
const FillFn g_fill = (FillFn)kFillFn;

// sub_97A2E0's writer: four stream pointers, their strides, a vertex count.
// Stream 1 is the normal; an emitter without one points it at a dummy global
// with stride 0.
struct Writer {
    uint8_t* p[4];
    int32_t  s[4];
    uint32_t count;
};
static_assert(sizeof(Writer) == 36, "Writer layout");

const uint8_t* ParticleAt(const uint8_t* em, uint32_t i) {
    const uint32_t idx = (*(const uint32_t* const*)(em + kEmIndices))[i];
    if (*(const uint32_t*)(em + kEmWide))
        return *(const uint8_t* const*)(em + kEmParticles64) + (idx << 6);
    return *(const uint8_t* const*)(em + kEmParticles32) + (idx << 5);
}

// ---- settings and state ----------------------------------------------------

constexpr int      kMaxWorkers    = 3;
constexpr int      kMaxChunks     = kMaxWorkers + 1;
constexpr uint32_t kMinParticles  = 32;         // below this the fork costs more than it saves
constexpr uint32_t kMinPerChunk   = 16;
constexpr unsigned kLearnEmitters = 2000;
constexpr unsigned kResampleMask  = 255;
constexpr int      kMaxStride     = 64;
constexpr size_t   kRegionBytes   = 16384 * kMaxStride;   // the client caps an emitter at 16384 vertices
constexpr int      kSpins         = 4000;

bool g_installed = false;
bool g_dead      = false;
bool g_abSubject = false;
unsigned char g_saved[kPatchLen];
uintptr_t g_rejoin = kRejoin;

// Staging areas: one per chunk plus one for the client's run when checking.
// Each ends at a reserved, uncommitted page.
uint8_t* g_regionEnd[kMaxChunks + 2];
void*    g_regionBase[kMaxChunks + 2];   // the last is for repeating the client's run on a difference

__declspec(align(64)) uint8_t g_emCopy[kMaxChunks][(kEmCopyBytes + 63) & ~63u];
__declspec(align(64)) uint8_t g_sink[kMaxChunks + 2][64];

// Main-thread counters, read by the periodic report; lower bounds.
unsigned long long g_emitters = 0, g_particles = 0;
unsigned long long g_parallel = 0, g_parallelParticles = 0;
unsigned long long g_small = 0, g_layout = 0, g_faults = 0, g_nan = 0, g_control = 0;
unsigned long long g_checked = 0;
unsigned long long g_lastEmitters = 0, g_lastParallel = 0;

// ---- worker pool -------------------------------------------------------------
//
// One job at a time. A chunk is claimed with a compare-exchange on one word
// that holds the job's generation, its chunk count and the next index, so a
// worker still finishing an old job cannot take a chunk of a new one before
// its parameters are written: the generation it holds no longer matches.

struct ChunkOut {
    Writer w;
    bool   fault;
};

struct Job {
    const uint8_t* emitter;
    uint32_t lo[kMaxChunks], hi[kMaxChunks];
    Writer   start[kMaxChunks];
    ChunkOut out[kMaxChunks];
    uint16_t cw;
    uint32_t mxcsr;
};

Job g_job;
volatile LONG g_claim = 0;      // gen << 8 | chunks << 4 | next
volatile LONG g_done  = 0;
volatile LONG g_gen   = 0;
volatile LONG g_quit  = 0;
int    g_workers = 0;
HANDLE g_threads[kMaxWorkers];
DWORD  g_threadIds[kMaxWorkers];
HANDLE g_wake[kMaxWorkers];
volatile LONG g_sleeping[kMaxWorkers];

__declspec(naked) void LoadFpu(uint16_t /*cw*/) {
    __asm {
        fninit
        fldcw word ptr [esp + 4]
        ret
    }
}

void FillChunk(int c) {
    Job& j = g_job;
    ChunkOut& o = j.out[c];
    Writer w = j.start[c];
    __try {
        for (uint32_t i = j.lo[c]; i < j.hi[c]; ++i)
            g_fill(g_emCopy[c], ParticleAt(j.emitter, i), &w);
        o.w = w;
        o.fault = false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // The fault can land in the middle of client x87 code; whatever it had
        // pushed is still on this thread's stack.
        LoadFpu(j.cw);
        _mm_setcsr(j.mxcsr);
        o.fault = true;
    }
}

// Claims and runs chunks of generation `gen` until none are left.
void RunChunks(LONG gen) {
    for (;;) {
        const LONG cur = g_claim;
        if ((cur >> 8) != gen) return;
        const LONG chunks = (cur >> 4) & 0xF, next = cur & 0xF;
        if (next >= chunks) return;
        if (InterlockedCompareExchange(&g_claim, cur + 1, cur) != cur) continue;
        FillChunk((int)next);
        InterlockedIncrement(&g_done);
    }
}

DWORD WINAPI WorkerMain(LPVOID param) {
    const int me = (int)(intptr_t)param;
    LONG seen = 0;
    for (;;) {
        int spins = 0;
        while (g_gen == seen && !g_quit) {
            if (++spins < kSpins) { _mm_pause(); continue; }
            InterlockedExchange(&g_sleeping[me], 1);
            if (g_gen != seen || g_quit) { InterlockedExchange(&g_sleeping[me], 0); break; }
            WaitForSingleObject(g_wake[me], INFINITE);
            InterlockedExchange(&g_sleeping[me], 0);
            spins = 0;
        }
        if (g_quit) return 0;
        seen = g_gen;
        // The FPU state of the thread that published the job.
        LoadFpu(g_job.cw);
        _mm_setcsr(g_job.mxcsr);
        RunChunks(seen);
    }
}

// Publishes the prepared job and runs chunks on this thread too, until all are done.
void RunJob(int chunks) {
    g_done = 0;
    const LONG gen = (g_gen + 1) & 0x7FFFFF;
    _ReadWriteBarrier();
    MemoryBarrier();
    InterlockedExchange(&g_claim, (gen << 8) | (chunks << 4));
    InterlockedExchange(&g_gen, gen);
    for (int i = 0; i < g_workers; ++i)
        if (InterlockedExchange(&g_sleeping[i], 0)) SetEvent(g_wake[i]);
    RunChunks(gen);
    while (g_done < chunks) _mm_pause();
    MemoryBarrier();
}

// ---- the replaced loop -----------------------------------------------------

void ClientLoop(uint8_t* em, void* writer, uint32_t count) {
    for (uint32_t i = 0; i < count; ++i) g_fill(em, ParticleAt(em, i), writer);
}

struct Layout {
    int      stride;
    uint8_t* base;          // first byte of the first vertex
    uint32_t off[4];        // each stream's offset inside a vertex
    bool     sink;          // stream 1 has stride 0 (no normals)
};

bool ReadLayout(const Writer& w, Layout& L) {
    const int S = w.s[0];
    if (S <= 0 || S > kMaxStride || (S & 3) || w.s[2] != S || w.s[3] != S) return false;
    if (w.s[1] != S && w.s[1] != 0) return false;
    L.stride = S;
    L.sink = (w.s[1] == 0);
    uint8_t* base = w.p[0];
    for (int k = 2; k < 4; ++k) if (w.p[k] < base) base = w.p[k];
    if (!L.sink && w.p[1] < base) base = w.p[1];
    for (int k = 0; k < 4; ++k) {
        if (k == 1 && L.sink) { L.off[k] = 0; continue; }
        const uintptr_t d = (uintptr_t)(w.p[k] - base);
        if (d >= (uintptr_t)S) return false;
        L.off[k] = (uint32_t)d;
    }
    L.base = base;
    return true;
}

// A writer aimed at a staging area of `vertices` capacity that ends at `end`.
Writer StagingWriter(const Writer& w0, const Layout& L, uint8_t* end, uint32_t vertices,
                     uint8_t* sink, uint8_t** baseOut) {
    uint8_t* b = end - (size_t)vertices * (size_t)L.stride;
    Writer w = w0;
    for (int k = 0; k < 4; ++k) w.p[k] = b + L.off[k];
    if (L.sink) { w.p[1] = sink; w.s[1] = 0; }
    w.count = 0;
    *baseOut = b;
    return w;
}

// Whether a staging writer ended where `n` vertices from `b` put it.
bool Advanced(const Writer& w, const Layout& L, const uint8_t* b, uint32_t n, const uint8_t* sink) {
    if (w.count != n) return false;
    for (int k = 0; k < 4; ++k) {
        if (k == 1 && L.sink) { if (w.p[1] != sink) return false; continue; }
        if (w.p[k] != b + L.off[k] + (size_t)n * (size_t)L.stride) return false;
    }
    return true;
}

// The client's rule: a coordinate replaces the box only when strictly beyond it.
void MergeBox(float* box, const float* part) {
    for (int k = 0; k < 3; ++k) if (part[k] < box[k]) box[k] = part[k];
    for (int k = 3; k < 6; ++k) if (part[k] > box[k]) box[k] = part[k];
}

void Retire(const char* what) {
    g_dead = true;
    Verdict::Add(Verdict::Bad, "ParallelParticles differed from the client (%s); retired "
                 "for the session", what);
    Log("[ParallelParticles] RETIRED: the parallel fill differed from the client's own "
        "loop (%s). The client's result was used for that emitter and every emitter "
        "after it runs the client's loop.", what);
}

// What differed, written for the first few differences only, because the retirement line
// says "different vertex bytes" and nothing about which. One field session retired the
// module after 9491 compared emitters; the log held no way to say whether the parallel
// fill was wrong, the client's own loop gave different bytes from one run to the next, or
// the emitter copy the chunks run on lacked a field the client read.
//
// The client's loop is run a second time into a staging area of its own. If the two
// client runs disagree, the fill is not deterministic and no replacement can match it.
unsigned g_diffLogged = 0;

void LogVertexDifference(uint8_t* em, const Job& j, int chunks, uint8_t* const* stageBase,
                         const uint8_t* aBase, uint32_t n, const Layout& L, uint32_t vpp,
                         uint32_t count, const Writer& w0) {
    if (g_diffLogged >= 3) return;
    ++g_diffLogged;
    uint32_t at = 0;
    for (int c = 0; c < chunks; ++c) {
        const size_t bytes = (size_t)j.out[c].w.count * L.stride;
        const uint8_t* mine = stageBase[c];
        const uint8_t* theirs = aBase + (size_t)at * L.stride;
        size_t d = 0;
        while (d < bytes && mine[d] == theirs[d]) ++d;
        if (d < bytes) {
            const uint32_t vertex = (uint32_t)(d / L.stride), off = (uint32_t)(d % L.stride);
            const uint32_t particle = j.lo[c] + vertex / vpp;
            size_t differing = 0;
            for (size_t k = 0; k < bytes; ++k) differing += (mine[k] != theirs[k]);
            Log("[ParallelParticles] difference: %u particles, %u vertices per particle, stride %d, "
                "%d chunk(s); first in chunk %d at particle %u, vertex %u of it, byte %u of the "
                "vertex (stream offsets %u %u %u %u, normal stream %s); %u byte(s) of %u differ in "
                "all.", count, vpp, L.stride, chunks, c, particle, vertex % vpp, off,
                L.off[0], L.off[1], L.off[2], L.off[3], L.sink ? "absent" : "present",
                (unsigned)differing, (unsigned)bytes);
            const uint32_t lo = off & ~15u;
            char a[3 * 16 + 1] = {}, b2[3 * 16 + 1] = {};
            for (int k = 0; k < 16 && lo + k < (uint32_t)L.stride; ++k) {
                snprintf(a + 3 * k, 4, "%02X ", mine[(size_t)vertex * L.stride + lo + k]);
                snprintf(b2 + 3 * k, 4, "%02X ", theirs[(size_t)vertex * L.stride + lo + k]);
            }
            Log("[ParallelParticles]   bytes %u..%u of that vertex: parallel %s | client %s",
                lo, lo + 15, a, b2);
            const uint8_t* pt = ParticleAt(em, particle);
            char pb[3 * 32 + 1] = {};
            for (int k = 0; k < 32; ++k) snprintf(pb + 3 * k, 4, "%02X ", pt[k]);
            Log("[ParallelParticles]   that particle's first 32 bytes: %s", pb);
            break;
        }
        at += j.out[c].w.count;
    }
    uint8_t* bBase;
    Writer wb = StagingWriter(w0, L, g_regionEnd[kMaxChunks + 1], count * vpp,
                              g_sink[kMaxChunks + 1], &bBase);
    memset(bBase, 0xCD, (size_t)count * vpp * L.stride);
    ClientLoop(em, &wb, count);
    const bool repeats = wb.count == n && memcmp(bBase, aBase, (size_t)n * L.stride) == 0;
    Log("[ParallelParticles]   the client's own loop run a second time on the same emitter %s.",
        repeats ? "gave the same bytes, so the difference is in the parallel fill"
                : "gave different bytes from its first run, so this fill is not deterministic and "
                  "no replacement can match it");
}

void Parallel(uint8_t* em, void* writerPtr, uint32_t count) {
    Writer& real = *(Writer*)writerPtr;
    const Writer w0 = real;
    Layout L;
    const uint32_t vpp = *(const uint32_t*)(em + kEmVertsPer);
    if (!ReadLayout(w0, L) || vpp == 0 || vpp > 64 ||
        (size_t)count * vpp * (size_t)L.stride > kRegionBytes) {
        ++g_layout;
        ClientLoop(em, writerPtr, count);
        return;
    }

    const bool check = (g_checked < kLearnEmitters) || ((g_emitters & kResampleMask) == 0);

    // Chunks of equal size, as many as there are threads and enough particles.
    int chunks = g_workers + 1;
    while (chunks > 1 && count / (uint32_t)chunks < kMinPerChunk) --chunks;
    Job& j = g_job;
    j.emitter = em;
    uint8_t* stageBase[kMaxChunks];
    for (int c = 0; c < chunks; ++c) {
        j.lo[c] = (uint32_t)((uint64_t)count * c / chunks);
        j.hi[c] = (uint32_t)((uint64_t)count * (c + 1) / chunks);
        const uint32_t cap = (j.hi[c] - j.lo[c]) * vpp;
        j.start[c] = StagingWriter(w0, L, g_regionEnd[c], cap, g_sink[c], &stageBase[c]);
        if (check) memset(stageBase[c], 0xCD, (size_t)cap * L.stride);
        memcpy(g_emCopy[c], em, kEmCopyBytes);
    }
    // Each dummy normal starts as the real one, so bytes the client does not
    // write there keep their value when the last chunk's copy goes back.
    if (L.sink)
        for (int c = 0; c <= kMaxChunks; ++c) memcpy(g_sink[c], w0.p[1], 12);
    unsigned short cw;
    __asm fnstcw cw
    j.cw = cw;
    j.mxcsr = _mm_getcsr();

    RunJob(chunks);

    uint32_t total = 0;
    for (int c = 0; c < chunks; ++c) {
        const uint32_t cap = (j.hi[c] - j.lo[c]) * vpp;
        if (j.out[c].fault || j.out[c].w.count > cap ||
            !Advanced(j.out[c].w, L, stageBase[c], j.out[c].w.count, g_sink[c])) {
            // Nothing real was touched: the copies and staging areas are ours.
            ++g_faults;
            Log("[ParallelParticles] chunk %d of an emitter %s; the emitter was filled "
                "by the client's loop instead.", c,
                j.out[c].fault ? "faulted" : "left its writer where no vertex count explains");
            Retire("a chunk faulted or its writer did not add up");
            ClientLoop(em, writerPtr, count);
            return;
        }
        total += j.out[c].w.count;
    }
    // The client's bounding-box compares come in several forms that agree on
    // every ordered value and part ways on a NaN (one of them lets a NaN in,
    // after which the next point replaces it whatever it is), so with a NaN
    // the order of the chunks matters and the merge below would not be the
    // client's answer. Stream 0 is the position; a NaN anywhere in it sends
    // the emitter to the client's loop.
    for (int c = 0; c < chunks; ++c) {
        const uint8_t* v = stageBase[c] + L.off[0];
        for (uint32_t n = 0; n < j.out[c].w.count; ++n, v += L.stride) {
            const float* f = (const float*)v;
            if (f[0] != f[0] || f[1] != f[1] || f[2] != f[2]) {
                ++g_nan;
                ClientLoop(em, writerPtr, count);
                return;
            }
        }
    }
    int lastWith = -1;
    for (int c = 0; c < chunks; ++c) if (j.out[c].w.count) lastWith = c;

    float box[6];
    memcpy(box, em + kEmBox, sizeof(box));
    for (int c = 0; c < chunks; ++c) MergeBox(box, (const float*)(g_emCopy[c] + kEmBox));

    if (check) {
        ++g_checked;
        uint8_t before[kEmCopyBytes];
        memcpy(before, em, kEmCopyBytes);
        uint8_t* aBase;
        Writer wa = StagingWriter(w0, L, g_regionEnd[kMaxChunks], count * vpp,
                                  g_sink[kMaxChunks], &aBase);
        memset(aBase, 0xCD, (size_t)count * vpp * L.stride);
        ClientLoop(em, &wa, count);        // the real emitter, a staging writer
        const uint32_t n = wa.count;

        const char* bad = nullptr;
        if (n != total || !Advanced(wa, L, aBase, n, g_sink[kMaxChunks]))
            bad = "a different number of vertices";
        uint32_t at = 0;
        for (int c = 0; !bad && c < chunks; ++c) {
            const size_t bytes = (size_t)j.out[c].w.count * L.stride;
            if (memcmp(stageBase[c], aBase + (size_t)at * L.stride, bytes) != 0)
                bad = "different vertex bytes";
            at += j.out[c].w.count;
        }
        if (!bad && memcmp(box, em + kEmBox, sizeof(box)) != 0) bad = "a different bounding box";
        if (!bad && memcmp(before, em, kEmBox) != 0) bad = "the client changed emitter fields other than the box";
        if (!bad && L.sink && n && lastWith >= 0 &&
            memcmp(g_sink[lastWith], g_sink[kMaxChunks], 12) != 0)
            bad = "a different value in the dummy normal";

        if (bad && strcmp(bad, "different vertex bytes") == 0)
            LogVertexDifference(em, j, chunks, stageBase, aBase, n, L, vpp, count, w0);

        // The client's own answer goes out either way.
        memcpy(L.base, aBase, (size_t)n * L.stride);
        for (int k = 0; k < 4; ++k) real.p[k] = w0.p[k] + (size_t)n * w0.s[k];
        real.count = w0.count + n;
        if (L.sink && n) memcpy(w0.p[1], g_sink[kMaxChunks], 12);
        // em + kEmBox already holds the client's box.
        if (bad) Retire(bad);
        ++g_parallel;
        g_parallelParticles += count;
        return;
    }

    uint32_t at = 0;
    for (int c = 0; c < chunks; ++c) {
        const size_t bytes = (size_t)j.out[c].w.count * L.stride;
        memcpy(L.base + (size_t)at * L.stride, stageBase[c], bytes);
        at += j.out[c].w.count;
    }
    for (int k = 0; k < 4; ++k) real.p[k] = w0.p[k] + (size_t)total * w0.s[k];
    real.count = w0.count + total;
    if (L.sink && lastWith >= 0) memcpy(w0.p[1], g_sink[lastWith], 12);
    memcpy(em + kEmBox, box, sizeof(box));
    ++g_parallel;
    g_parallelParticles += count;
}

extern "C" void __cdecl ParallelParticles_RunLoop(uint8_t* em, void* writer, uint32_t count) {
    ++g_emitters;
    g_particles += count;
    if (g_abSubject && AbTest::StandAside()) {
        ++g_control;
        ClientLoop(em, writer, count);
        return;
    }
    if (g_dead || count < kMinParticles || g_workers == 0) {
        if (!g_dead && g_workers) ++g_small;
        ClientLoop(em, writer, count);
        return;
    }
    Parallel(em, writer, count);
}

// Entered at 0x0097E650 with esi = emitter, ebx = particle count (non-zero),
// [ebp+8] = writer. Leaves to 0x0097E680 with ebx intact, which is all the
// client reads there before overwriting the rest.
__declspec(naked) void Thunk() {
    __asm {
        pushad
        mov  eax, [ebp + 8]
        push ebx
        push eax
        push esi
        call ParallelParticles_RunLoop
        add  esp, 12
        popad
        jmp  dword ptr [g_rejoin]
    }
}

bool BytesMatch(uintptr_t addr, const unsigned char* want, size_t n) {
    __try {
        return memcmp((const void*)addr, want, n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool ReserveRegions() {
    for (int i = 0; i <= kMaxChunks + 1; ++i) {
        void* r = VirtualAlloc(nullptr, kRegionBytes + 4096, MEM_RESERVE | MEM_TOP_DOWN, PAGE_NOACCESS);
        if (!r) return false;
        if (!VirtualAlloc(r, kRegionBytes, MEM_COMMIT, PAGE_READWRITE)) {
            VirtualFree(r, 0, MEM_RELEASE);
            return false;
        }
        g_regionBase[i] = r;
        g_regionEnd[i] = (uint8_t*)r + kRegionBytes;    // the next page is the guard
    }
    return true;
}

bool StartWorkers(int n) {
    for (int i = 0; i < n; ++i) {
        g_wake[i] = CreateEventA(nullptr, FALSE, FALSE, nullptr);
        if (!g_wake[i]) return false;
        g_threads[i] = CreateThread(nullptr, 256 * 1024, WorkerMain, (LPVOID)(intptr_t)i,
                                    STACK_SIZE_PARAM_IS_A_RESERVATION, &g_threadIds[i]);
        if (!g_threads[i]) return false;
        SetThreadPriority(g_threads[i], THREAD_PRIORITY_ABOVE_NORMAL);
        g_workers = i + 1;
    }
    return true;
}

}  // namespace

bool OnWorkerThread() {
    const DWORD me = GetCurrentThreadId();
    for (int i = 0; i < g_workers; ++i) if (g_threadIds[i] == me) return true;
    return false;
}

bool Init() {
    if (!Config::g_settings.OptParallelParticles) return true;

    if (RunningUnderTranslation()) {
        Log("[ParallelParticles] NOT active: worker threads stay off under a translation "
            "layer, where they have blocked the main thread before.");
        return false;
    }
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const int workers = (int)si.dwNumberOfProcessors - 2 < kMaxWorkers
                      ? (int)si.dwNumberOfProcessors - 2 : kMaxWorkers;
    if (workers < 1) {
        Log("[ParallelParticles] NOT active: %lu logical CPU(s); it needs at least three so "
            "the workers do not take the main thread's core.", si.dwNumberOfProcessors);
        return false;
    }
    if (!BytesMatch(kLoopBytes, kLoopWant, sizeof(kLoopWant))) {
        Log("[ParallelParticles] NOT patched: the particle loop at 0x%08X is not the one this "
            "was built for.", (unsigned)kLoopBytes);
        return false;
    }
    if (!WowOpt_ClientPatchAllowed((const void*)kPatchAt)) {
        Log("[ParallelParticles] NOT patched: No Client Patches is on, and this writes seven "
            "bytes into wow.exe.");
        return false;
    }
    if (!ReserveRegions()) {
        Log("[ParallelParticles] NOT active: could not reserve its %u staging areas.",
            (unsigned)(kMaxChunks + 1));
        return false;
    }
    if (!StartWorkers(workers)) {
        Log("[ParallelParticles] NOT active: could not start its worker threads.");
        Shutdown();
        return false;
    }

    DWORD old = 0;
    if (!VirtualProtect((void*)kPatchAt, kPatchLen, PAGE_EXECUTE_READWRITE, &old)) {
        Log("[ParallelParticles] NOT patched: could not make 0x%08X writable", (unsigned)kPatchAt);
        Shutdown();
        return false;
    }
    memcpy(g_saved, (const void*)kPatchAt, kPatchLen);
    unsigned char patch[kPatchLen];
    patch[0] = 0xE9;
    *(int32_t*)(patch + 1) = (int32_t)((uintptr_t)&Thunk - (kPatchAt + 5));
    memset(patch + 5, 0x90, kPatchLen - 5);
    memcpy((void*)kPatchAt, patch, kPatchLen);
    DWORD ignored = 0;
    VirtualProtect((void*)kPatchAt, kPatchLen, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), (void*)kPatchAt, kPatchLen);
    g_installed = true;
    g_abSubject = AbTest::IsSubject("ParallelParticles", &g_abSubject);

    SamplingProfiler::RegisterSelfSymbol("ParallelParticles_Thunk", (const void*)&Thunk);
    Log("[ParallelParticles] ACTIVE: emitters with %u or more particles are filled by the "
        "main thread and %d worker(s); the Gx lock, unlock and draw stay on the main "
        "thread. The first %u such emitters, and one in %u after, are also run the "
        "client's way and compared byte for byte. On by default; it checks itself first.",
        kMinParticles, workers, kLearnEmitters, kResampleMask + 1);
    return true;
}

void Shutdown() {
    if (g_installed) {
        DWORD old = 0;
        if (VirtualProtect((void*)kPatchAt, kPatchLen, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy((void*)kPatchAt, g_saved, kPatchLen);
            DWORD ignored = 0;
            VirtualProtect((void*)kPatchAt, kPatchLen, old, &ignored);
            FlushInstructionCache(GetCurrentProcess(), (void*)kPatchAt, kPatchLen);
        }
        g_installed = false;
    }
    InterlockedExchange(&g_quit, 1);
    for (int i = 0; i < g_workers; ++i) if (g_wake[i]) SetEvent(g_wake[i]);
}

void LogStats() {
    if (!Config::g_settings.OptParallelParticles) return;
    if (!g_installed) {
        Log("[ParallelParticles] not installed - the reason is at the top of this log.");
        return;
    }
    const unsigned long long de = g_emitters - g_lastEmitters;
    const unsigned long long dp = g_parallel - g_lastParallel;
    g_lastEmitters = g_emitters;
    g_lastParallel = g_parallel;
    if (g_emitters == 0) {
        Log("[ParallelParticles] installed, and no unsorted emitter has been filled yet.");
        return;
    }
    Log("[ParallelParticles] %llu emitter fill(s), %llu particle(s); %llu emitter(s) "
        "(%llu particles) split across threads, %llu of them also run the client's way and "
        "compared. Left to the client: %llu under %u particles, %llu with a vertex layout "
        "this does not handle, %llu with a NaN position, %llu after a chunk fault. Since the "
        "last report: %llu fills, "
        "%llu split.%s Plain counters, lower bounds.",
        g_emitters, g_particles, g_parallel, g_parallelParticles, g_checked,
        g_small, kMinParticles, g_layout, g_nan, g_faults, de, dp,
        g_dead ? " [RETIRED - see above]" : "");
    if (g_abSubject)
        Log("[ParallelParticles] under A/B test: %llu emitter fill(s) ran the client's loop in "
            "OFF stints. Plain counter, lower bound.", g_control);
}

}  // namespace ParallelParticles
