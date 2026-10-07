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
// quad and no facing along the velocity (flag 0x4 set, 0x200000 clear), and which is
// not a spin with the axes flag (0x4000). With flag 0x8 the client builds a second
// quad after the first, stretched along the particle's velocity; that is replaced too
// (BuildTail in the model header) and learned separately from the same kind without it.
// Its arithmetic was checked offline on its own against the client's instructions for
// 0x97CC10..0x97D367 (about 18 million cases in four input modes, including the length
// test at exactly its epsilon, 0 differences; the client's 204 cycles against 107 here).
// Sixteen wrong versions of it: nine caught, seven not. Three of the seven are the same
// arithmetic (a commutative sum written the other way, in two places, and an equality
// that gives the same value); four differ at the 1e-16 level before a float is stored
// (the order of two products in the stretch, a sum made in float, a rounding of the
// vertical offset), which random input reaches about once in a billion: the
// transcription was read against the assembly for those. What
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
//
// The track evaluator. The evaluator sub_979E90 (colour, alpha, size, tile and
// extra tracks, and the two generators it draws its size variation from) is a
// function of the emitter and the particle's first words and writes only its
// five outputs, so it is replaced too, in particle_eval_model.h, and checked on
// its own: for the first 20000 particles of an emitter whose colour-function flag
// is clear, and one call in 4096 after, the client's routine and the model are
// run on the same particle and their five outputs compared, and the model
// answers only after those agree. A comparison that fails is followed by two more
// calls of the client's routine; if it does not repeat itself the difference is not
// the model's and the sample is dropped, otherwise the model retires and the client's
// evaluator is called again. The model declines (the client's routine runs) on a key
// fraction that is not finite, a null array or a search that would read outside its
// array. Offline against the client's own x87 code for the evaluator and its callees,
// generated from the disassembly, over six million random emitters with the
// integer, colour and alpha values taken before they are rounded as well as after:
// no difference. Of twenty-one wrong versions run through it, eleven were caught and ten
// were not: six are the same arithmetic, one only changed what is declined, one differs
// for a NaN operand, and two (the order of the two alpha scales, the order of the life
// product) differ by about 1e-16 ahead of a float and a byte, which random input reaches
// about once in a billion. For those two the transcription was read against the assembly.
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
#include "particle_eval_model.h"
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
constexpr uintptr_t     kTailEpsAddr  = 0x00AA2CEC;   // flt_AA2CEC: the second quad's length test

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
// Why a particle was handed back as an emitter kind this does not do, by the first test it fails.
// The profile of 2026-10-07 has this function's hottest instruction at 0x97CD41, the reciprocal
// square root of the second-quad path (flags bit 8) that this never takes, and 17.7% of calls in
// that session were of a kind not done: whether that is the tail, the quad facing along the
// velocity (0x200000) or a spin with axes decides what, if anything, to transcribe next.
unsigned long long g_unsNotQuad = 0, g_unsFacing = 0, g_unsSpinAxes = 0;
unsigned long long g_other = 0;       // other threads, dead, or an A/B control half
unsigned long long g_declined = 0;    // handed back, of which the three below
unsigned long long g_declNaN = 0, g_declAngle = 0, g_declStride = 0, g_declDevice = 0;
unsigned long long g_early = 0;
// One slot per kind and per whether a second quad (flag 0x8) follows, so each is learned alone.
unsigned long long g_answered[6] = {};
unsigned long      g_verified[6] = {};
unsigned           g_mismatches = 0;
unsigned           g_unstable = 0;     // differences that the evaluator's own re-run explains

// The model of sub_979E90, used in place of the client's routine once it has agreed with it on
// kEvalLearn particles. Plain flags and counters, main thread only.
constexpr uintptr_t kRngTableAddr = 0x009F1700;
constexpr unsigned long kEvalLearn = 20000;
alignas(16) uint8_t g_evalTable[260];
bool               g_evalReady = false;      // constants and table read and matching
bool               g_evalArmed = false;
bool               g_evalDead = false;
int                g_evalBench = -1;
unsigned long      g_evalChecked = 0;        // comparisons that agreed
unsigned long      g_evalDeclined = 0;       // the model handed a particle back to the client's routine
unsigned           g_evalMismatch = 0;
unsigned           g_evalUnstable = 0;       // differences that the client's own re-run explains

// What the last Process saw from the evaluator, for the check that follows a difference. Plain
// stores, main thread only.
uint32_t g_lastColour = 0;
int32_t  g_lastTile = 0;
uint32_t g_lastAgeBits = 0;

const char* const kKindName[6] = { "flat", "axes", "spin", "flat with a second quad", "axes with a second quad",
                                    "spin with a second quad" };

// Private streams for the learning phase. Main thread only, which the detour checks.
alignas(16) char g_scratch[4][8 * kMaxStride + 32];

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
    k.tailEps  = (const float*)kTailEpsAddr;
    return k;
}

// The model of sub_979E90 into the same five outputs. False: the client's routine must run.
__declspec(noinline) bool EvalModel(const char* em, const float* particle, Evaluated* e) {
    ParticleEvalModel::Out o;
    if (!ParticleEvalModel::Eval(em, particle, g_evalTable, &o)) {
        ++g_evalDeclined;
        return false;
    }
    e->colour = o.colour; e->w = o.w; e->h = o.h; e->tile = o.tile; e->extra = o.extra;
    return true;
}

// One particle. Writes nothing until the answer is complete and has no NaN in it.
//
// No stack cookie: this runs once per particle and the cookie is a load, an xor and a store
// on entry and a check on the way out. The writers of its locals, all of them: Quad (and the second one, tq) and
// Frame by the Build functions in particle_fill_model.h, which loop to four and write named
// members; Frame.sinv and Frame.cosv by sub_6F7A60, two floats; Evaluated by sub_979D60 or
// sub_979E90, which write the colour dword, two floats, and two ints through the five
// pointers (both read, 979E90 in full: *a3, a3[3], a4[0..1], *a5, *a6), or by EvalModel, five
// stores of named members and only on success; rot0 and rate by sub_97A130, one float each.
__declspec(safebuffers) int Process(char* em, float* particle, Streams* s, float* box, Kind kind, const Constants& k,
                                    bool modelMayAnswer) {
    unsigned idx;
    if (!Select(em, particle, (uintptr_t)particle, k.table, &idx)) return kEarly;

    const uint32_t flags = Rd<uint32_t>(em, kOffFlags);
    Evaluated e;
    e.colour = 0; e.w = 0.0f; e.h = 0.0f; e.tile = 0; e.extra = 0;
    if (!(modelMayAnswer && g_evalArmed && !(flags & kFlagColourFn) && EvalModel(em, particle, &e)))
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

    // The second quad is built from the same frame before anything is written, so a NaN in either
    // hands the whole particle to the client.
    if (flags & kFlagOther) {
        Quad tq;
        BuildTail(em, k, f, e.extra, particle, &tq);
        if (!AllFinite(tq)) { ++g_declNaN; return kDecline; }
        Commit(q, k, box, s);
        Commit(tq, k, box, s);
        return kEmitted;
    }

    Commit(q, k, box, s);
    return kEmitted;
}

// First difference between the answer worked out here and the client's, or false.
__declspec(noinline) bool Differs(int mine, int theirs, const Streams& priv, const Streams& before,
                                  const Streams& real, const float* privBox, const float* realBox,
                                  char* why, size_t cap, int nv) {
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
            if (real.ptr[i] != before.ptr[i] + nv * before.stride[i]) {
                snprintf(why, cap, "stream %d pointer advanced by %d, expected %d", i,
                         (int)(real.ptr[i] - before.ptr[i]), nv * before.stride[i]);
                return true;
            }
            for (int v = 0; v < nv; ++v) {
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
        if (real.count != before.count + nv) {
            snprintf(why, cap, "vertex count moved by %d, expected %d", real.count - before.count, nv);
            return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snprintf(why, cap, "reading the streams faulted");
        return true;
    }
}

__declspec(noinline) void Retire(int slot, uint32_t flags, const char* why) {
    ++g_mismatches;
    g_dead = true;
    Log("[ParticleFillFast] RETIRED on a %s emitter (flags %08X): %s. Every fill from here "
        "on is the client's own.", kKindName[slot], flags, why);
    Verdict::Add(Verdict::Bad, "ParticleFillFast filled a particle's vertices differently from the "
                 "client and retired itself for this session");
}

// A difference in the verification can be the evaluator's doing and not this module's: the colour
// and tile come from a client routine that this side and the client's own fill each call once per
// particle, and a routine that does not return the same thing twice in a row for one particle
// makes the two outputs differ whatever this module computes. Asked after a difference, by calling
// the evaluator twice more. True only when those two calls differ from each other. What ran between
// Process's call and these is the client's own fill, so an answer that is steady but is not what
// Process saw means the fill changed state this module does not reproduce: that is this module's
// difference, and it is reported in the detail, not excused.
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
    return a.colour != b.colour || a.tile != b.tile || memcmp(&a.w, &b.w, 4) != 0 || memcmp(&a.h, &b.h, 4) != 0 ||
           a.extra != b.extra;
}

// The client's evaluator and the model on one particle, outputs compared. Pure on both sides, so
// running both changes nothing the fill sees.
__declspec(noinline) void CheckEvaluator(char* em, float* particle) {
    Evaluated c, d;
    c.colour = 0; c.w = c.h = 0.0f; c.tile = c.extra = 0;
    d = c;
    ParticleEvalModel::Out o;
    bool modelOk;
    const bool mineFirst = (g_evalChecked & 1) != 0;       // alternate, so neither side always meets the cold caches
    const uint64_t t0 = SelfBench::Now();
    if (mineFirst) modelOk = ParticleEvalModel::Eval(em, particle, g_evalTable, &o);
    const uint64_t t1 = SelfBench::Now();
    ((EvalFn)kEvalPlain)(em, nullptr, particle, &c.colour, &c.w, &c.tile, &c.extra);
    const uint64_t t2 = SelfBench::Now();
    if (!mineFirst) modelOk = ParticleEvalModel::Eval(em, particle, g_evalTable, &o);
    const uint64_t t3 = SelfBench::Now();
    if (!modelOk) { ++g_evalDeclined; return; }
    if (g_evalBench >= 0) {
        const uint64_t mine = mineFirst ? (t1 - t0) : (t3 - t2);
        SelfBench::Pair(g_evalBench, mine, t2 - t1);
    }
    if (c.colour == o.colour && memcmp(&c.w, &o.w, 4) == 0 && memcmp(&c.h, &o.h, 4) == 0 &&
        c.tile == o.tile && c.extra == o.extra) {
        if (++g_evalChecked >= kEvalLearn && !g_evalDead && !g_evalArmed) {
            g_evalArmed = true;
            Log("[ParticleFillFast] the track evaluator model agreed with the client's sub_979E90 on %lu "
                "particles; it answers from here, and one call in %lu is compared again.", g_evalChecked, kResampleMask + 1);
        }
        return;
    }
    // A difference. Is the client's routine the same twice on this particle?
    Evaluated c2 = d, c3 = d;
    ((EvalFn)kEvalPlain)(em, nullptr, particle, &c2.colour, &c2.w, &c2.tile, &c2.extra);
    ((EvalFn)kEvalPlain)(em, nullptr, particle, &c3.colour, &c3.w, &c3.tile, &c3.extra);
    const bool stable = c2.colour == c.colour && c3.colour == c.colour && c2.tile == c.tile && c3.tile == c.tile &&
                        c2.extra == c.extra && c3.extra == c.extra &&
                        memcmp(&c2.w, &c.w, 4) == 0 && memcmp(&c3.w, &c.w, 4) == 0 &&
                        memcmp(&c2.h, &c.h, 4) == 0 && memcmp(&c3.h, &c.h, 4) == 0;
    if (!stable) {
        if (++g_evalUnstable <= 5)
            Log("[ParticleFillFast] the client's own evaluator gave different answers for one particle (colour %08X, "
                "%08X, %08X); that comparison is dropped.", c.colour, c2.colour, c3.colour);
        return;
    }
    ++g_evalMismatch;
    g_evalDead = true;
    g_evalArmed = false;
    Log("[ParticleFillFast] the track evaluator model RETIRED (flags %08X, age bits %08X): colour client %08X, model %08X; "
        "w %08X/%08X; h %08X/%08X; tile %d/%d; extra %d/%d. The client's sub_979E90 runs again.",
        Rd<uint32_t>(em, kOffFlags), *(const uint32_t*)particle, c.colour, o.colour, *(uint32_t*)&c.w, *(uint32_t*)&o.w,
        *(uint32_t*)&c.h, *(uint32_t*)&o.h, c.tile, o.tile, c.extra, o.extra);
    Verdict::Add(Verdict::Bad, "ParticleFillFast's track evaluator model differed from the client's sub_979E90 and retired itself for this session");
}

__declspec(noinline) int Learn(char* em, void* edx, float* particle, Streams* vb, Kind kind) {
    const Constants k = Client();
    const bool tail = (Rd<uint32_t>(em, kOffFlags) & kFlagOther) != 0;
    const int ki = (int)kind - 1 + (tail ? 3 : 0);
    const int nv = tail ? 8 : 4;

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
    // The client's evaluator here, always: this comparison is about the fill, and CheckEvaluator alone
    // judges the evaluator model. It also makes g_lastColour the client's own answer for the probe below.
    const int mine = Process(em, particle, &priv, privBox, kind, k, false);
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
    if (Differs(mine, theirs, priv, before, *vb, privBox, (const float*)(em + kOffBox), why, sizeof(why), nv)) {
        char detail[220];
        if (EvaluatorMoved(em, particle, detail, sizeof(detail))) {
            if (++g_unstable <= 5)
                Log("[ParticleFillFast] the client's evaluator did not repeat itself after a difference (flags %08X): %s%s. "
                    "Not counted, not retired; the client's own output was used.",
                    Rd<uint32_t>(em, kOffFlags), why, detail);
            return theirs;
        }
        size_t n = strlen(why);
        snprintf(why + n, sizeof(why) - n, "%s", detail);
        Retire(ki, Rd<uint32_t>(em, kOffFlags), why);
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
        {
            const uint32_t f = Rd<uint32_t>(em, kOffFlags);
            if (!(f & kFlagQuad)) ++g_unsNotQuad;
            else if (f & kFlagFacing) ++g_unsFacing;
            else ++g_unsSpinAxes;
        }
        return g_orig(em, edx, particle, vb);
    }
    if (g_abSubject && AbTest::StandAside()) {
        ++g_other;
        return g_orig(em, edx, particle, vb);
    }

    if (g_evalReady && !g_evalDead && !(Rd<uint32_t>(em, kOffFlags) & kFlagColourFn) &&
        (g_evalChecked < kEvalLearn || ((unsigned long)g_calls & kResampleMask) == 0))
        CheckEvaluator(em, particle);

    const int ki = (int)kind - 1 + ((Rd<uint32_t>(em, kOffFlags) & kFlagOther) ? 3 : 0);
    if (g_verified[ki] < kLearnCalls || ((unsigned long)g_calls & kResampleMask) == 0)
        return Learn(em, edx, particle, vb, kind);

    const int r = Process(em, particle, vb, (float*)(em + kOffBox), kind, Client(), true);
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

// The constants the model was written against, and the generator's table, read from the client.
// Any difference and the evaluator stays the client's.
bool PrepareEvaluator() {
    struct K { uintptr_t addr; float want; } const consts[] = {
        { 0x009EA0B4, ParticleEvalModel::kC },      { 0x009E1134, ParticleEvalModel::kMinLife },
        { 0x009E30C0, ParticleEvalModel::k255 },    { 0x00A4040C, ParticleEvalModel::kTwo },
        { 0x009E8CD0, ParticleEvalModel::kFloor },  { 0x009E1130, ParticleEvalModel::kOne } };
    __try {
        for (const K& k : consts) {
            if (memcmp((const void*)k.addr, &k.want, 4) != 0) {
                Log("[ParticleFillFast] track evaluator model NOT used: the constant at 0x%08X is not the one it was written against.", (unsigned)k.addr);
                return false;
            }
        }
        memcpy(g_evalTable, (const void*)kRngTableAddr, sizeof(g_evalTable));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[ParticleFillFast] track evaluator model NOT used: its constants could not be read.");
        return false;
    }
    return true;
}

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
    g_evalBench = SelfBench::Register("ParticleEvalModel");
    g_evalReady = PrepareEvaluator();
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
    Log("[ParticleFillFast] %llu call(s): %llu answered here (%llu flat, %llu axes, %llu spin, %llu of them with a second quad), "
        "%llu skipped by the client's own test, %llu of an emitter kind this does not do, %llu "
        "handed back (%llu a NaN in the answer, %llu a NaN spin angle, %llu a stride the check "
        "cannot hold, %llu no device object), %llu from another thread, after a retirement or in "
        "the A/B control half. Plain counters, lower bounds.",
        g_calls, g_answered[0] + g_answered[1] + g_answered[2] + g_answered[3] + g_answered[4] + g_answered[5],
        g_answered[0] + g_answered[3], g_answered[1] + g_answered[4], g_answered[2] + g_answered[5],
        g_answered[3] + g_answered[4] + g_answered[5], g_early, g_unsupported, g_declined, g_declNaN, g_declAngle, g_declStride,
        g_declDevice, g_other);
    Log("[ParticleFillFast]   of the %llu handed back as a kind this does not do: "
        "%llu facing along the velocity (0x200000), %llu a spin on axes, %llu not a quad at all. Plain counters, "
        "lower bounds.", g_unsupported, g_unsFacing, g_unsSpinAxes, g_unsNotQuad);
    if (!g_evalReady)
        Log("[ParticleFillFast]   track evaluator model: not used (constants or table not read).");
    else if (g_evalDead)
        Log("[ParticleFillFast]   track evaluator model: RETIRED after a difference from the client's routine (line earlier in this log); "
            "%lu comparisons agreed before it.", g_evalChecked);
    else
        Log("[ParticleFillFast]   track evaluator model: %lu of %lu comparisons agreed so far, %s; %lu particle(s) handed back to the client's "
            "routine; %u comparison(s) dropped because the client's routine did not repeat itself. Plain counters, lower bounds.",
            g_evalChecked, kEvalLearn, g_evalArmed ? "answering" : "still the client's routine", g_evalDeclined, g_evalUnstable);
    if (g_unstable)
        Log("[ParticleFillFast]   %u comparison(s) differed because the client's colour and tile "
            "evaluator did not answer the same twice for one particle; those fills were left "
            "to the client and not counted.", g_unstable);
    if (g_dead) {
        Log("[ParticleFillFast]   DISABLED after a difference from the client's own output; the "
            "line that says which is earlier in this log.");
        return;
    }
    for (int i = 0; i < 6; ++i) {
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
