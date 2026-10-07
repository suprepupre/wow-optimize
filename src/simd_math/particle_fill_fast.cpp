// ============================================================================
// Module: particle_fill_fast.cpp
//
// The per-particle vertex fill, sub_97BE80, for the three kinds of emitter that
// make up nearly all particles: a flat quad, a quad placed along two axes, and
// a quad spun by an angle. Everything else is handed to the client.
//
// In an uncapped tester session (drain, 2026-10-04) the function and the blocks
// of it the profiler names are the largest region of the particle update that
// the DLL did not yet replace: 0x97C28C alone is 4.1% of executing time, and the
// 512-byte regions from 0x97BE00 to 0x97CA00 add roughly another 3.5%. The
// function is about 1100 instructions of x87 per particle. For these three
// kinds it spends them on four corner positions, a bounding box update that is
// twenty-four compare/fnstsw/test/branch groups, and four rounds through the
// normal, colour and texture streams.
//
// What is replaced. The whole of the function for an emitter whose flags say
// quad, no second geometry, and no facing along the velocity (flags 0x4 set, 0x8
// and 0x200000 clear), and which is not a spin with the axes flag (0x4000). What
// stays the client's: the track evaluator (sub_979D60 or sub_979E90, ours when
// ParticleTrackEval is on), the sine and cosine (sub_6F7A60, ours when
// FastSinCos is on), and, for a spun quad, the spin values sub_97A130.
//
// Calls dropped, each read first:
//   sub_532AF0   returns its argument plus 532. Inlined, and the one field read
//                from it is the device's red/blue swap flag.
//   sub_4C21B0   a point through a 4x4. Inlined in the client's order of addition.
//   sub_97A130   for the two kinds without spin. It writes two floats those paths
//                never read, and its only other work is a random number from a
//                generator that lives in its own frame (sub_4C1510 and sub_464580
//                touch nothing but that object and a constant table).
//
// The arithmetic is in particle_fill_model.h, which also holds the address each
// expression was read from. It is shared with an offline harness that runs the
// client's instruction sequence, transcribed into inline assembly with the
// control word at 0x027F, against that header over random emitters, particles
// and tables. The assembly is generated from the disassembly dump by a script,
// line for line, with the three calls it makes replaced (the matrix transform by
// its own instruction sequence, the sine and cosine by supplied values).
//
//     41963158 fills compared   0 differed   (flat, axis-placed and spun in about
//                                              equal parts; half the inputs shaped
//                                              so that a sum cancels to a few ulps,
//                                              which is where the order of
//                                              additions can show in a float; some
//                                              runs with NaN, infinity, denormals and
//                                              both zeros in every field, some with
//                                              box edges within ulps of a corner)
//       619106 more declined     a NaN in the answer, handed to the client
//
// A harness that has never failed has not been shown to be able to, so wrong
// versions of the header were run through it. Against the packed form that is
// shipped: a box edge moved on equal as well as on strictly beyond (twice), the
// texture row taken from the double where the client stores the float, one spun
// corner built from the wrong term, and the two zeros of a tie resolved the other
// way round, which only inputs built to carry negative zeros expose. Against the
// scalar form with the same arithmetic, which this replaced: the other order of
// three additions in four places, in the axis sum and in the matrix transform.
// Every one was caught. Two changes were not and are equivalent: comparing the
// box in float instead of double (it ends at the rounded value either way) and
// adding two texture floats in float instead of double.
//
// Two differences the harness found in this form and that are handled rather than
// excused. A coordinate below half the smallest float rounds to -0.0, and the client
// then keeps it against a later exact +0.0, which is not strictly beyond it; the
// reduction of the four corners would store +0.0. An extreme that is exactly zero is
// therefore sent through the corner-by-corner form (GrowBoxSequential). And a NaN
// spin angle is declined, since x87 and SSE2 give the negated NaN different sign bits.
//
// Speed, from the same harness, warm caches, the client's instruction sequence for
// the body against this, excluding the calls the client keeps (evaluator, spin
// values, sine and cosine): flat 211 cycles against 91, axis-placed 239 against 138,
// spun 194 against 121. The first version, with a scalar compare for every corner,
// was 1.1 to 1.3 times faster and not worth shipping: six comparisons and eight
// float-double conversions per corner cost as much as the x87 did. Whether that
// is a gain in the game depends on how much of the call is the part kept, which is
// not measured here; the learning phase times both halves with SelfBench.
//
// Verification, predict-then-compare. The function writes four vertex streams,
// the emitter's bounding box and the stream pointers. While learning, the
// answer is worked out into private buffers, the client runs against the real
// ones, and the two are compared byte for byte, each stream, the box, the
// pointer advance and the return value. The first difference retires this for
// the session. Each kind is learned separately; after that one call in 4096 is
// compared again.
//
// What is not measured here: how often each kind occurs in play. The report
// says, per kind, how many calls it answered and how many it handed back.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include "particle_fill_fast.h"
#include "particle_fill_model.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "self_bench.h"
#include "session_verdict.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
extern DWORD g_mainThreadId;
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace ParticleFillFast {

namespace {

using namespace ParticleFillModel;

constexpr uintptr_t kTarget      = 0x0097BE80;
constexpr uintptr_t kEvalColour  = 0x00979D60;   // used when the colour-function flag is set
constexpr uintptr_t kEvalPlain   = 0x00979E90;
constexpr uintptr_t kSpinFn      = 0x0097A130;
constexpr uintptr_t kSinCosFn    = 0x006F7A60;
constexpr uintptr_t kDevicePtr   = 0x00C5DF88;   // the graphics device object
constexpr unsigned  kDeviceSwap  = 0x228;        // sub_532AF0 returns this+0x214; the flag is at +0x14 of that

constexpr uintptr_t kTableAddr   = 0x00DCE690;
constexpr uintptr_t kCornerAddr  = 0x00B2D5B4;
constexpr uintptr_t kUvAddr      = 0x00B2D5D4;
constexpr uintptr_t kAxesAddr    = 0x00B2D590;
constexpr uintptr_t kNormalAddr  = 0x00B2D540;
constexpr uintptr_t kMatrixAddr  = 0x00B2D550;

// push ebp / mov ebp,esp / fld1 / sub esp,84h / push ebx / push esi / push edi / mov edi,ecx
const unsigned char kPrologue[16] = {
    0x55, 0x8B, 0xEC, 0xD9, 0xE8, 0x81, 0xEC, 0x84,
    0x00, 0x00, 0x00, 0x53, 0x56, 0x57, 0x8B, 0xF9
};

constexpr unsigned long kLearnCalls   = 10000;
constexpr unsigned long kResampleMask = 4095;
constexpr int           kMaxStride    = 256;

typedef int   (__fastcall* FillFn)(char* em, void* edx, float* particle, Streams* vb);
typedef void* (__fastcall* EvalFn)(char* em, void* edx, const float* particle, uint32_t* colour,
                                   float* size, int32_t* tile, int32_t* extra);
typedef void  (__fastcall* SpinFn)(char* em, void* edx, const float* particle, float* rot0, float* rate);
typedef void  (__cdecl*    SinCosFn)(float angle, float* outSin, float* outCos);

FillFn g_orig = nullptr;

bool g_installed = false;
bool g_dead = false;
bool g_abSubject = false;
int  g_benchSlot = -1;

enum Result { kEarly = 0, kEmitted = 1, kDecline = 2 };

// Plain counters on the main thread; lower bounds by construction.
unsigned long long g_calls = 0;
unsigned long long g_unsupported = 0;
unsigned long long g_other = 0;       // other threads, dead, or an A/B control half
unsigned long long g_declined = 0;    // handed back, of which the three below
unsigned long long g_declNaN = 0, g_declAngle = 0, g_declStride = 0, g_declDevice = 0;
unsigned long long g_early = 0;
unsigned long long g_answered[3] = {};
unsigned long      g_verified[3] = {};
unsigned           g_mismatches = 0;
unsigned           g_unstable = 0;     // differences that the evaluator's own re-run explains

// What the last Process saw from the evaluator, for the check that follows a difference. Plain
// stores, main thread only.
uint32_t g_lastColour = 0;
int32_t  g_lastTile = 0;
uint32_t g_lastAgeBits = 0;

const char* const kKindName[3] = { "flat", "axes", "spin" };

// Private streams for the learning phase. Main thread only, which the detour checks.
alignas(16) char g_scratch[4][4 * kMaxStride + 32];

struct Evaluated {
    uint32_t colour;
    float    w, h;       // must stay adjacent: the evaluator writes two floats from &w
    int32_t  tile;
    int32_t  extra;
};

Constants Client() {
    Constants k;
    k.table    = (const float*)kTableAddr;
    k.corner   = (const float*)kCornerAddr;
    k.uvCorner = (const float*)kUvAddr;
    k.axes     = (const float*)kAxesAddr;
    k.normal   = (const uint32_t*)kNormalAddr;
    k.matrix   = (const float*)kMatrixAddr;
    return k;
}

// One particle. Writes nothing until the answer is complete and has no NaN in it.
//
// No stack cookie: this runs once per particle and the cookie is a load, an xor and a store
// on entry and a check on the way out. The writers of its locals, all of them: Quad and
// Frame by the Build functions in particle_fill_model.h, which loop to four and write named
// members; Frame.sinv and Frame.cosv by sub_6F7A60, two floats; Evaluated by sub_979D60 or
// sub_979E90, which write the colour dword, two floats, and two ints through the five
// pointers (both read, 979E90 in full: *a3, a3[3], a4[0..1], *a5, *a6); rot0 and rate by
// sub_97A130, one float each.
__declspec(safebuffers) int Process(char* em, float* particle, Streams* s, float* box, Kind kind, const Constants& k) {
    unsigned idx;
    if (!Select(em, particle, (uintptr_t)particle, k.table, &idx)) return kEarly;

    const uint32_t flags = Rd<uint32_t>(em, kOffFlags);
    Evaluated e;
    e.colour = 0; e.w = 0.0f; e.h = 0.0f; e.tile = 0; e.extra = 0;
    ((EvalFn)((flags & kFlagColourFn) ? kEvalColour : kEvalPlain))(
        em, nullptr, particle, &e.colour, &e.w, &e.tile, &e.extra);
    g_lastColour = e.colour;
    g_lastTile = e.tile;
    g_lastAgeBits = *(const uint32_t*)particle;

    float rot0 = 0.0f, rate = 0.0f;
    if (kind == Kind::Spin) ((SpinFn)kSpinFn)(em, nullptr, particle, &rot0, &rate);

    const char* device = *(const char* const*)kDevicePtr;
    if (!device) { ++g_declDevice; return kDecline; }
    if (*(const int32_t*)(device + kDeviceSwap) == 1) e.colour = SwapRedBlue(e.colour);

    Frame f;
    Scale(em, k.table[idx], e.w, e.h, &f.w, &f.h);
    Transform(particle + 1, k.matrix, &f.px);
    f.colour = e.colour;
    f.tile = e.tile;
    f.sinv = 0.0f; f.cosv = 0.0f;
    const Cell cell = CellOrigin(em, e.tile);

    Quad q;
    switch (kind) {
    case Kind::Flat: BuildFlat(em, k, f, cell, &q); break;
    case Kind::Axes: BuildAxes(em, k, f, cell, &q); break;
    default: {
        const float angle = SpinAngle(particle, (uintptr_t)particle, flags, rate, rot0);
        // x87 and SSE2 keep different NaN payloads, and the sign of one differs after a
        // negation; the client's answer is the only one to give for a NaN angle.
        if (angle != angle) { ++g_declAngle; return kDecline; }
        ((SinCosFn)kSinCosFn)(angle, &f.sinv, &f.cosv);
        BuildSpin(em, f, cell, &q);
        break;
    }
    }
    if (!AllFinite(q)) { ++g_declNaN; return kDecline; }

    Commit(q, k, box, s);
    return kEmitted;
}

// First difference between the answer worked out here and the client's, or false.
__declspec(noinline) bool Differs(int mine, int theirs, const Streams& priv, const Streams& before,
                                  const Streams& real, const float* privBox, const float* realBox,
                                  char* why, size_t cap) {
    __try {
        if (mine != theirs) {
            snprintf(why, cap, "the client returned %d where this worked out %d", theirs, mine);
            return true;
        }
        if (memcmp(privBox, realBox, 6 * sizeof(float)) != 0) {
            for (int i = 0; i < 6; ++i) {
                if (memcmp(&privBox[i], &realBox[i], 4) == 0) continue;
                uint32_t a, b;
                memcpy(&a, &realBox[i], 4); memcpy(&b, &privBox[i], 4);
                snprintf(why, cap, "bounding box float %d: the client %08X, this %08X", i, a, b);
                return true;
            }
        }
        if (mine == kEarly) {
            if (memcmp(&before, &real, sizeof(Streams)) != 0) {
                snprintf(why, cap, "the client moved the streams for a particle this skipped");
                return true;
            }
            return false;
        }
        for (int i = 0; i < 4; ++i) {
            if (real.ptr[i] != before.ptr[i] + 4 * before.stride[i]) {
                snprintf(why, cap, "stream %d pointer advanced by %d, expected %d", i,
                         (int)(real.ptr[i] - before.ptr[i]), 4 * before.stride[i]);
                return true;
            }
            for (int v = 0; v < 4; ++v) {
                const char* a = before.ptr[i] + v * before.stride[i];
                const char* b = g_scratch[i] + v * before.stride[i];
                if (memcmp(a, b, kElemBytes[i]) == 0) continue;
                uint32_t wa[3] = {}, wb[3] = {};
                memcpy(wa, a, kElemBytes[i]); memcpy(wb, b, kElemBytes[i]);
                snprintf(why, cap, "stream %d vertex %d: the client %08X %08X %08X, this %08X %08X %08X",
                         i, v, wa[0], wa[1], wa[2], wb[0], wb[1], wb[2]);
                return true;
            }
        }
        if (real.count != before.count + 4) {
            snprintf(why, cap, "vertex count moved by %d, expected 4", real.count - before.count);
            return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snprintf(why, cap, "reading the streams faulted");
        return true;
    }
}

__declspec(noinline) void Retire(Kind kind, uint32_t flags, const char* why) {
    ++g_mismatches;
    g_dead = true;
    Log("[ParticleFillFast] RETIRED on a %s emitter (flags %08X): %s. Every fill from here "
        "on is the client's own.", kKindName[(int)kind - 1], flags, why);
    Verdict::Add(Verdict::Bad, "ParticleFillFast filled a particle's vertices differently from the "
                 "client and retired itself for this session");
}

// A difference in the verification can be the evaluator's doing and not this module's: the colour
// and tile come from a client routine that this side and the client's own fill each call once per
// particle, and if that routine does not return the same thing twice for one particle (a particle
// advanced in between, state it reads that something else changes) the two outputs differ
// whatever this module computes. Asked after a difference, by calling the evaluator twice more.
// True when the evaluator now answers differently from what Process was given, or from itself.
__declspec(noinline) bool EvaluatorMoved(char* em, float* particle, char* detail, size_t cap) {
    const uint32_t flags = Rd<uint32_t>(em, kOffFlags);
    Evaluated a, b;
    a.colour = b.colour = 0; a.w = b.w = 0.0f; a.h = b.h = 0.0f; a.tile = b.tile = 0; a.extra = b.extra = 0;
    EvalFn fn = (EvalFn)((flags & kFlagColourFn) ? kEvalColour : kEvalPlain);
    fn(em, nullptr, particle, &a.colour, &a.w, &a.tile, &a.extra);
    fn(em, nullptr, particle, &b.colour, &b.w, &b.tile, &b.extra);
    const uint32_t ageNow = *(const uint32_t*)particle;
    snprintf(detail, cap, "; the evaluator now gives colour %08X then %08X against %08X when this was worked out, "
             "tile %d then %d against %d, particle age bits %08X now and %08X then",
             a.colour, b.colour, g_lastColour, a.tile, b.tile, g_lastTile, ageNow, g_lastAgeBits);
    return a.colour != g_lastColour || b.colour != a.colour || a.tile != g_lastTile || b.tile != a.tile ||
           ageNow != g_lastAgeBits;
}

__declspec(noinline) int Learn(char* em, void* edx, float* particle, Streams* vb, Kind kind) {
    const Constants k = Client();
    const int ki = (int)kind - 1;

    // A stride of zero is legal (a stream without normals writes every vertex to one dummy
    // location, and both sides write the same bytes there in the same order); a negative one
    // or one past the private buffers cannot be held.
    for (int i = 0; i < 4; ++i)
        if (vb->stride[i] < 0 || vb->stride[i] > kMaxStride) {
            ++g_declined; ++g_declStride;
            return g_orig(em, edx, particle, vb);
        }

    Streams priv;
    for (int i = 0; i < 4; ++i) { priv.ptr[i] = g_scratch[i]; priv.stride[i] = vb->stride[i]; }
    priv.count = vb->count;
    float privBox[6];
    memcpy(privBox, em + kOffBox, sizeof(privBox));

    const uint64_t t0 = SelfBench::Now();
    const int mine = Process(em, particle, &priv, privBox, kind, k);
    const uint64_t t1 = SelfBench::Now();
    if (mine == kDecline) {
        ++g_declined;
        return g_orig(em, edx, particle, vb);
    }

    const Streams before = *vb;
    const int theirs = g_orig(em, edx, particle, vb);
    const uint64_t t2 = SelfBench::Now();
    if (g_benchSlot >= 0) SelfBench::Pair(g_benchSlot, t1 - t0, t2 - t1);

    char why[480];
    if (Differs(mine, theirs, priv, before, *vb, privBox, (const float*)(em + kOffBox), why, sizeof(why))) {
        char detail[220];
        if (EvaluatorMoved(em, particle, detail, sizeof(detail))) {
            if (++g_unstable <= 5)
                Log("[ParticleFillFast] a difference that is not this module's (flags %08X): %s%s. "
                    "Not counted, not retired; the client's own output was used.",
                    Rd<uint32_t>(em, kOffFlags), why, detail);
            return theirs;
        }
        size_t n = strlen(why);
        snprintf(why + n, sizeof(why) - n, "%s", detail);
        Retire(kind, Rd<uint32_t>(em, kOffFlags), why);
        return theirs;
    }
    ++g_verified[ki];
    return theirs;
}

int __fastcall Detour(char* em, void* edx, float* particle, Streams* vb) {
    ++g_calls;
    if (g_dead || !em || !particle || !vb || GetCurrentThreadId() != g_mainThreadId) {
        ++g_other;
        return g_orig(em, edx, particle, vb);
    }
    const Kind kind = Classify(em);
    if (kind == Kind::Unsupported) {
        ++g_unsupported;
        return g_orig(em, edx, particle, vb);
    }
    if (g_abSubject && AbTest::StandAside()) {
        ++g_other;
        return g_orig(em, edx, particle, vb);
    }

    const int ki = (int)kind - 1;
    if (g_verified[ki] < kLearnCalls || ((unsigned long)g_calls & kResampleMask) == 0)
        return Learn(em, edx, particle, vb, kind);

    const int r = Process(em, particle, vb, (float*)(em + kOffBox), kind, Client());
    if (r == kDecline) {
        ++g_declined;
        return g_orig(em, edx, particle, vb);
    }
    if (r == kEarly) { ++g_early; return 0; }
    ++g_answered[ki];
    return 1;
}

bool BytesMatch(uintptr_t addr, const unsigned char* want, size_t n) {
    __try {
        return memcmp((const void*)addr, want, n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

bool Init() {
    if (!Config::g_settings.OptParticleFillFast) return true;

    if (!BytesMatch(kTarget, kPrologue, sizeof(kPrologue))) {
        Log("[ParticleFillFast] NOT active: the bytes at 0x%08X are not the particle fill this "
            "was read from, so nothing was hooked.", (unsigned)kTarget);
        return false;
    }
    if (!WowOpt_ClientPatchAllowed((const void*)kTarget)) {
        Log("[ParticleFillFast] NOT active: No Client Patches is on, and this hooks a function "
            "inside wow.exe.");
        return false;
    }
    if (WineSafe_CreateHook((void*)kTarget, (void*)&Detour, (void**)&g_orig) != MH_OK) {
        Log("[ParticleFillFast] NOT active: the hook on 0x%08X could not be created.", (unsigned)kTarget);
        return false;
    }
    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        MH_RemoveHook((void*)kTarget);
        Log("[ParticleFillFast] NOT active: the hook on 0x%08X could not be enabled.", (unsigned)kTarget);
        return false;
    }
    g_installed = true;
    g_abSubject = AbTest::IsSubject("ParticleFillFast", &g_abSubject);
    g_benchSlot = SelfBench::Register("ParticleFillFast");
    SamplingProfiler::RegisterSelfSymbol("ParticleFillFast", (const void*)&Detour);

    Log("[ParticleFillFast] ACTIVE on the per-particle vertex fill (sub_97BE80 @ 0x%08X) for "
        "flat, axis-placed and spun quads. The rest of the client's function is its own "
        "instruction sequence per particle, four corners, six bounding box compares a corner and "
        "four streams; this does the same arithmetic in SSE2 doubles at the client's rounding. "
        "The first %lu fills of each kind are worked out here into private buffers, then run by "
        "the client, and compared byte for byte; then one call in %lu.",
        (unsigned)kTarget, kLearnCalls, kResampleMask + 1);
    if (g_abSubject)
        Log("[ParticleFillFast]   under A/B test: the control half runs the client's function "
            "through the same hook.");
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook((void*)kTarget);
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptParticleFillFast) return;
    if (!g_installed) {
        Log("[ParticleFillFast] not installed - the reason is at the top of this log");
        return;
    }
    if (g_calls == 0) {
        Log("[ParticleFillFast] hooked, and no particle has been filled yet. That is a measurement: "
            "no emitter has run since it went in.");
        return;
    }
    Log("[ParticleFillFast] %llu call(s): %llu answered here (%llu flat, %llu axes, %llu spin), "
        "%llu skipped by the client's own test, %llu of an emitter kind this does not do, %llu "
        "handed back (%llu a NaN in the answer, %llu a NaN spin angle, %llu a stride the check "
        "cannot hold, %llu no device object), %llu from another thread, after a retirement or in "
        "the A/B control half. Plain counters, lower bounds.",
        g_calls, g_answered[0] + g_answered[1] + g_answered[2], g_answered[0], g_answered[1],
        g_answered[2], g_early, g_unsupported, g_declined, g_declNaN, g_declAngle, g_declStride,
        g_declDevice, g_other);
    if (g_unstable)
        Log("[ParticleFillFast]   %u comparison(s) differed because the client's colour and tile "
            "evaluator did not answer the same twice for one particle; those fills were left "
            "to the client and not counted.", g_unstable);
    if (g_mismatches) {
        Log("[ParticleFillFast]   DISABLED after a difference from the client's own output; the "
            "line that says which is earlier in this log.");
        return;
    }
    for (int i = 0; i < 3; ++i) {
        if (g_verified[i] < kLearnCalls)
            Log("[ParticleFillFast]   %s: %lu of %lu fills compared with the client so far, none "
                "differed; until then every fill of this kind is the client's own.",
                kKindName[i], g_verified[i], kLearnCalls);
        else
            Log("[ParticleFillFast]   %s: %lu fills compared with the client byte for byte, none "
                "differed; one call in %lu is still compared.",
                kKindName[i], g_verified[i], kResampleMask + 1);
    }
    if (g_abSubject)
        Log("[ParticleFillFast]   under A/B test; calls in the control half are counted among "
            "'another thread'.");
}

}  // namespace ParticleFillFast
