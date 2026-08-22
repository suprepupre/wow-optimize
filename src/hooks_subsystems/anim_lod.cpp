// ============================================================================
// Module: anim_lod.cpp
// Description: Spreads M2 model animation across frames when the scene is crowded.
// Safety & Threading: Main thread, alongside the render loop.
// ============================================================================
//
// Animating models is the largest single block of frame time this client spends,
// and it is the one place where no amount of instruction-level work can reach it.
// Measured on txtsd's sessions with a fixed census:
//
//     city    65.3 models/frame, 37.82 us each -> 2.47 ms of a 23.4 ms frame
//     raid   113.9 models/frame, 32.30 us each -> 3.68 ms of a 24.5 ms frame
//
// Fifteen percent of the frame, in the same profile where the four named M2
// functions add up to 1.26% of self time between them: FindKey 0.36, Quat 0.33,
// AnimateModel 0.30, Interp 0.27. The cost is spread so thin that vectorising any
// one of them buys about two tenths of a percent. The only way to reach it is to
// do less of it.
//
// ---------------------------------------------------------------------------
// Why skipping a call is safe, which was the open question
//
// sub_82F0F0 both advances the animation state and evaluates it, so the obvious
// worry is that skipping a call makes animations run slow. It does not. At
// 0x0082f5a3 the time is
//
//     (now[model+0x74] - start[model+0x70]) * speed[model+0x78] + base[model+0x80]
//
// clamped to the sequence length. It is derived from an absolute clock every
// time, never accumulated, so a call that does not happen delays when a pose
// refreshes and cannot make an animation drift, stall or run at the wrong rate.
// The next call lands on the correct pose for the current time.
//
// ---------------------------------------------------------------------------
// What a skip has to look like
//
// The client already declines to animate, twice, in the first eight instructions:
// once on a flag in model+0x10, once when model+0x3C already equals the current
// stamp because this model was animated earlier in the same frame. Both jump to
// the same exit, which restores the frame and returns with EAX still holding
// model+0x10 - the flags word read on entry.
//
// So a skip here returns exactly that and touches nothing else. It is the client
// declining, in the client's own words, at the client's own exit.
//
// The function is __thiscall-shaped: the model arrives in ECX, five arguments are
// on the stack and it ends in `retn 14h`, so the callee cleans them. IDA reports
// it as __cdecl with five arguments and misses the object entirely, which is why
// its callers appear to pass inconsistent first arguments.
//
// ---------------------------------------------------------------------------
// The policy, and why it is not distance
//
// Distance from the camera would be the better signal and it is not available
// here yet: the model's own world position does reach this call, but nothing at
// this call site knows where the camera is, and the two obvious routes into it
// were followed and did not lead there. Rather than guess at a camera pointer in
// an animation path, this throttles on load instead.
//
// Below kBudget distinct models in a frame nothing is skipped at all, so an
// ordinary scene behaves exactly as it does today. Above it, each model is
// allowed one update every `stride` frames, where stride is how many times over
// budget the previous frame ran, capped. At 114 models and a budget of 96 that is
// a stride of two: half the models update on any given frame and every model
// still updates at 20 Hz in a 40 fps frame. The busier the scene, the more the
// work is spread, and the cap keeps the worst case bounded.
//
// A model is never skipped the first time it is seen. Its bone matrices are
// whatever the allocation happened to contain until the first evaluation writes
// them, and rendering that is not a stutter, it is garbage.
//
// ---------------------------------------------------------------------------
// The table is keyed by a pointer the engine can free and reuse
//
// That has bitten this project before, and here the failure mode is visible: a
// new model landing on a dead model's address would inherit "animated recently"
// and be skipped before it had ever been evaluated. So each entry carries two
// words read from the model beside the key - the animation block at +0x28 and the
// pointer at +0x2C - and an entry whose fingerprint disagrees is treated as a
// model never seen before. A recycled allocation would have to match the address
// and both words to slip through.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cmath>

#include "anim_lod.h"
#include "../core/world_position.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

// File scope, and deliberately not inside a namespace: the naked thunk below
// refers to it from inline assembly, which resolves plain symbols and not
// namespace-qualified ones.
static void* g_origAnimateModel = nullptr;

namespace AnimLod {

namespace {

constexpr uintptr_t kAnimateModel = 0x0082F0F0;

// Model fields, from sub_82F0F0 itself.
constexpr unsigned kM_flags     = 0x10;  // returned by the client's own early exit
constexpr unsigned kM_animBlock = 0x28;
constexpr unsigned kM_owner     = 0x2C;
constexpr unsigned kM_stamp     = 0x3C;

// This function does not only pose bones, and the first version of this module
// missed it. Its last instructions are:
//
//     and  [esi+10h], 0FFFFFBFFh          clear a flag
//     cmp  [edx+128h], 0  / call sub_82D2F0     edx = [[esi+2Ch]+150h]
//     cmp  [esi+4Ch], 0 / cmp [esi+58h], 0 / call sub_82E550
//     mov  [esi+3Ch], [[esi+28h]+14h]     stamp it done for this frame
//
// sub_82D2F0 is the material pass. It walks the model's texture-animation blocks
// and calls M2_AnimTrackColor ten times per block, writing colour and alpha, and
// it maintains bit 0x400 of the flags. Skip the call and every one of those
// tracks freezes at its last value.
//
// A tester saw exactly that on 2026-08-22: characters glowing, shoulder pads and
// weapons glowing, then snapping back to normal. Turning this feature off stopped
// it. Emissive and alpha tracks stuck bright until the model was posed again.
//
// The rule in CLAUDE.md is "before skipping an engine call, establish what else
// that call does", and it records three features that shipped on "skipping this
// only skips work" and were wrong. This was the fourth. What was established was
// that skipping cannot affect animation *timing* - true, and beside the point.
//
// sub_82E550 is the attachment pass, and it accounts for the rest of the report.
// Its first loop runs [data+0F0h] attachment points; its second walks the list
// of attached models at [esi+58h], linked through +60h, and calls sub_82F0F0 on
// each one. A weapon and a shoulder pad are attached models. Skipping a
// character skipped its whole attached chain with it.
//
// The rule in CLAUDE.md is "before skipping an engine call, establish what else
// that call does", and it records three features that shipped on "skipping this
// only skips work" and were wrong. This was the fourth. What was established was
// that skipping cannot affect animation *timing* - true, and beside the point.
//
// So a model is now skipped only when the tail would have done nothing. The test
// is not the client's own two `cmp` guards above: those over-approximate, and
// [esi+4Ch] is the bone array, which is set on everything that reaches this far,
// so guarding on it would decline every model there is. The tests below are the
// conditions the tail functions themselves loop on - texture-animation count,
// attachment count, child list. Anything unreadable declines too. This can only
// ever refuse to skip, so it cannot break rendering, and the counter below says
// how much population is left after it.
constexpr unsigned kO_data      = 0x150;   // model data: [[model+0x2C]+0x150], IDA var_4
constexpr unsigned kD_matAnims  = 0x128;   // texture-animation count, gates sub_82D2F0
constexpr unsigned kD_attachCnt = 0x0F0;   // attachment count, sub_82E550's loop bound
constexpr unsigned kM_childList = 0x58;    // attached models, sub_82E550's second walk

// ---------------------------------------------------------------------------
// Distance
//
// sub_82E140, this function's sibling, does
//
//     sub_4C1F00(tmp, this+180, a2);   // tmp = [this+180] x a2
//     sub_407F80(this+244, tmp);       // and the product feeds the bone palette
//
// so this+180 is a 4x4 whose translation row sits at this+228. Whether that
// translation is world space or model space is not decidable by reading the
// code - it is the left operand of a multiply and could be either - and the
// animation census could not decide it either: it measured the translation
// varying by up to 5641.8 units between models in one frame, which is map
// scale, but its distance column was computed against 0x00BE1F30 and was
// therefore all zeros. See world_position.cpp.
//
// It is decidable at runtime, without waiting for another tester log, because
// the two cases look nothing alike once a real camera position exists:
//
//   world space   distance varies model to model and is small - the client is
//                 not animating anything past its own far clip, and the model
//                 under the camera is a few yards away
//   model space   distance is |translation - camera| ~= |camera|, which is
//                 thousands of yards and nearly identical for every model,
//                 because the camera is at map coordinates and the local
//                 translations are all near zero
//
// So the learning phase below watches, per frame, the smallest distance and the
// spread between smallest and largest. A world-space candidate produces a small
// minimum and a wide spread. Anything else is refused and the feature stays on
// the crowd rule, saying so in the log.
constexpr unsigned kM_localMatrix = 180;   // 4x4; translation row at +228
constexpr unsigned kM_worldMatrix = 244;   // the product, same shape

// Thresholds for the verdict. A world position must put something within this
// distance of the camera in a frame, and must spread the models out by at
// least this much. Both are generous: the intent is to reject a candidate that
// is off by thousands, not to grade a good one.
constexpr float kLearnMaxNearYd = 300.0f;
constexpr float kLearnMinSpread = 40.0f;

// Frames of agreement before the distance rule is used, and the smallest crowd
// worth judging - a frame with three models says nothing about spread.
constexpr uint32_t kLearnFrames   = 240;
constexpr uint32_t kLearnMinCrowd = 8;

// Distance bands. Near models are never throttled at all.
constexpr float kBandNearYd = 40.0f;
constexpr float kBandMidYd  = 90.0f;
constexpr float kBandFarYd  = 180.0f;

// With distance the crowd threshold can be far lower than the crowd-only rule
// needs: a model 150 yards away does not need a new pose every frame whether or
// not the scene is busy. Measured on txtsd's sessions, the open world averages
// 16.7 models a frame and peaks at 161, so a budget of 96 never engaged at all
// outside a raid.
constexpr uint32_t kDistBudget = 24;

// Below this many distinct models in a frame, nothing is throttled.
constexpr uint32_t kBudget = 96;

// A model updates at least this often however crowded the scene gets. Four means
// a model animates at 10 Hz in a 40 fps frame, which is the point where a walk
// cycle starts to read as stepping rather than moving.
constexpr uint32_t kMaxStride = 4;

// Open addressing, power of two, never grows. A scene with more models than this
// simply stops throttling the overflow, which is the safe direction.
constexpr uint32_t kSlots = 8192;
constexpr uint32_t kMask  = kSlots - 1;

struct Slot {
    uint32_t key;         // model pointer, 0 when empty
    uint32_t fpA, fpB;    // animation block and owner, to catch a reused address
    uint32_t lastFrame;   // last frame this model was actually animated
    uint32_t seenFrame;   // last frame it was counted toward the budget
};
Slot g_slots[kSlots];

// Which candidate translation, if either, turned out to be a world position.
enum DistState { kLearning, kArmed, kRefused };
DistState g_distState  = kLearning;
unsigned  g_distOffset = 0;        // kM_localMatrix or kM_worldMatrix once armed

// Per-frame extremes for each candidate, and how many frames each has agreed.
float    g_minD[2], g_maxD[2];
uint32_t g_agree[2]     = { 0, 0 };
uint32_t g_learnFrames  = 0;

// The camera, read once a frame rather than once a model.
float    g_cam[3]   = { 0.0f, 0.0f, 0.0f };
bool     g_camValid = false;
uint32_t g_camFrames = 0;   // frames a world position was actually available

unsigned long long g_distSkipped = 0;   // skips the distance rule made
unsigned long long g_nearKept    = 0;   // models the distance rule protected


bool g_installed = false;
bool g_dead      = false;

uint32_t g_frame       = 1;   // never 0, so a zeroed slot cannot look current
uint32_t g_stride      = 1;
uint32_t g_seenThis    = 0;   // distinct models so far this frame
uint32_t g_seenPrev    = 0;

unsigned long long g_calls = 0, g_skipped = 0, g_firstSight = 0, g_evicted = 0;
unsigned long long g_hasTailWork = 0;   // declined: the tail animates materials
uint32_t g_peakModels = 0, g_peakStride = 1;

// Squared distance from the camera to the translation row of the 4x4 at
// model+off. Squared, so no square root runs per model per frame; the bands are
// squared once at file scope terms below. Returns false if the value is not a
// finite map coordinate, which also rejects a matrix that has never been
// written.
inline bool CameraDistSq(uint32_t model, unsigned off, float& outSq) {
    const float* m = (const float*)(model + off);
    float x = m[12], y = m[13], z = m[14];
    if (!(x > -64000.0f && x < 64000.0f)) return false;
    if (!(y > -64000.0f && y < 64000.0f)) return false;
    if (!(z > -64000.0f && z < 64000.0f)) return false;
    float dx = x - g_cam[0], dy = y - g_cam[1], dz = z - g_cam[2];
    outSq = dx * dx + dy * dy + dz * dz;
    return true;
}

// Stride for a distance, in yards squared.
inline uint32_t StrideForDistSq(float dSq) {
    if (dSq <= kBandNearYd * kBandNearYd) return 1;
    if (dSq <= kBandMidYd  * kBandMidYd)  return 2;
    if (dSq <= kBandFarYd  * kBandFarYd)  return 3;
    return kMaxStride;
}

inline uint32_t Hash(uint32_t p) {
    p ^= p >> 16; p *= 0x7feb352du;
    p ^= p >> 15; p *= 0x846ca68bu;
    p ^= p >> 16;
    return p;
}

} // namespace

// Returns 1 to skip this model's animation for this frame, 0 to let it run.
extern "C" int __cdecl AnimLod_ShouldSkip(uint32_t model) {
    if (g_dead || !model) return 0;
    ++g_calls;

    int decision = 0;
    __try {
        // The client's own two refusals, replayed before anything is counted.
        // Both of these calls are already free, and counting them would inflate
        // the model count that sets the stride - a scene where the client
        // declines most of the calls would look crowded and get throttled for it.
        uint32_t flags = *(const uint32_t*)(model + kM_flags);
        if ((flags & 1) == 0) return 0;

        uint32_t fpA = *(const uint32_t*)(model + kM_animBlock);
        uint32_t fpB = *(const uint32_t*)(model + kM_owner);
        if (!fpA) return 0;
        if (*(const uint32_t*)(model + kM_stamp) == *(const uint32_t*)(fpA + 0x14))
            return 0;   // already animated this frame; the client would bail too

        // Would the tail have done anything? If so this model is not skippable
        // at any stride - see the note on the offsets above. Not the client's
        // own cheap pre-tests: those over-approximate, and one of them is the
        // bone array, which is set on everything that reaches here. These are
        // the conditions the two tail functions themselves loop on.
        if (!fpB) { ++g_hasTailWork; return 0; }
        uint32_t data = *(const uint32_t*)(fpB + kO_data);
        if (!data) { ++g_hasTailWork; return 0; }
        if (*(const uint32_t*)(data + kD_matAnims) != 0 ||
            *(const uint32_t*)(data + kD_attachCnt) != 0 ||
            *(const uint32_t*)(model + kM_childList) != 0) {
            ++g_hasTailWork;
            return 0;
        }

        uint32_t i = Hash(model) & kMask;
        uint32_t probe = 0;
        Slot* s = nullptr;
        for (; probe < 8; ++probe) {
            Slot* c = &g_slots[(i + probe) & kMask];
            if (c->key == 0 || c->key == model) { s = c; break; }
        }
        if (!s) {
            // Eight collisions deep. Take the slot anyway rather than leak the
            // model out of the accounting; the entry it replaces loses its
            // history and is treated as new, which only costs an extra update.
            s = &g_slots[(i + 7) & kMask];
            ++g_evicted;
            s->key = 0;
        }

        bool known = (s->key == model && s->fpA == fpA && s->fpB == fpB);

        if (!known) {
            // Never seen, or the address was recycled under us. Either way its
            // bone matrices cannot be trusted to hold a previous pose.
            s->key = model; s->fpA = fpA; s->fpB = fpB;
            s->lastFrame = g_frame;
            s->seenFrame = g_frame;
            ++g_seenThis;
            ++g_firstSight;
            return 0;
        }

        // Counted once per frame, updated at most once per stride. These have to
        // be separate: a skipped model never gets the client's stamp, so it
        // arrives here again on the next call within the same frame, and one
        // field could not say both "already counted" and "already updated".
        if (s->seenFrame != g_frame) {
            s->seenFrame = g_frame;
            ++g_seenThis;
        }
        // While learning, both candidates are sampled on every model of every
        // frame that has a crowd worth judging. This costs two reads and two
        // subtractions per model for four seconds of play and then stops.
        if (g_camValid && g_distState == kLearning) {
            float dSq;
            if (CameraDistSq(model, kM_localMatrix, dSq)) {
                if (dSq < g_minD[0]) g_minD[0] = dSq;
                if (dSq > g_maxD[0]) g_maxD[0] = dSq;
            }
            if (CameraDistSq(model, kM_worldMatrix, dSq)) {
                if (dSq < g_minD[1]) g_minD[1] = dSq;
                if (dSq > g_maxD[1]) g_maxD[1] = dSq;
            }
        }

        // The stride for this model. Distance wins when it is available: a far
        // model does not need a new pose every frame whether or not the scene
        // is busy, and a near one should never be throttled however busy it is.
        uint32_t stride = g_stride;
        bool     byDistance = false;
        if (g_distState == kArmed && g_camValid && g_seenPrev >= kDistBudget) {
            float dSq;
            if (CameraDistSq(model, g_distOffset, dSq)) {
                stride = StrideForDistSq(dSq);
                byDistance = true;
                if (stride == 1) ++g_nearKept;
            }
        }

        {
            uint32_t age = g_frame - s->lastFrame;
            if (stride > 1 && age < stride) {
                ++g_skipped;
                if (byDistance) ++g_distSkipped;
                decision = 1;
            } else {
                s->lastFrame = g_frame;
            }
        }
        // Same model, same frame: the client's own stamp check handles it.
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_dead = true;
        Log("[AnimLod] Disabled for this session: reading a model faulted. Every "
            "model is animated by the client from here on.");
        return 0;
    }
    return decision;
}

namespace {

// sub_82F0F0 takes the model in ECX, five arguments on the stack, and cleans
// them itself. MinHook enters the detour with ECX still holding the model.
__declspec(naked) void HookedAnimateModel() {
    __asm {
        push ebp
        mov  ebp, esp
        push ebx
        push esi
        push edi

        mov  ebx, ecx                 // the model
        push ebx
        call AnimLod_ShouldSkip
        add  esp, 4
        test eax, eax
        jnz  do_skip

        // Hand it to the client: same object in ECX, same five arguments, and
        // the trampoline ends in retn 14h so it cleans them itself.
        push dword ptr [ebp+18h]
        push dword ptr [ebp+14h]
        push dword ptr [ebp+10h]
        push dword ptr [ebp+0Ch]
        push dword ptr [ebp+08h]
        mov  ecx, ebx
        mov  eax, g_origAnimateModel
        call eax
        jmp  done

    do_skip:
        // Exactly what the client's own two early exits return: the flags word
        // it read on entry, with nothing else touched.
        mov  eax, [ebx+10h]           ; kM_flags

    done:
        pop  edi
        pop  esi
        pop  ebx
        mov  esp, ebp
        pop  ebp
        retn 14h
    }
}

} // namespace

// One frame of learning evidence, folded in at the frame boundary. Both
// candidates are judged on the same frame, against the same camera.
// Called from the frame boundary before g_seenThis is reset, so g_seenThis is
// still the distinct model count of the frame being judged.
void JudgeLearningFrame() {
    if (g_seenThis < kLearnMinCrowd) return;   // too few models to say anything
    ++g_learnFrames;

    for (int c = 0; c < 2; ++c) {
        if (g_minD[c] > g_maxD[c]) continue;     // nothing readable this frame
        float nearYd = sqrtf(g_minD[c]);
        float farYd  = sqrtf(g_maxD[c]);
        if (nearYd <= kLearnMaxNearYd && (farYd - nearYd) >= kLearnMinSpread)
            ++g_agree[c];
    }

    if (g_learnFrames < kLearnFrames) return;

    // Whichever agreed on more of the judged frames, and only if it agreed on a
    // clear majority of them. A tie or a weak winner is a refusal, because the
    // cost of being wrong here is throttling a model that is standing in front
    // of the player.
    int   win  = (g_agree[1] > g_agree[0]) ? 1 : 0;
    uint32_t hits = g_agree[win];
    if (hits * 4 >= g_learnFrames * 3) {
        g_distState  = kArmed;
        g_distOffset = win ? kM_worldMatrix : kM_localMatrix;
        Log("[AnimLod] Distance rule armed on model+%u: it put something within "
            "%.0f yards of the camera and spread the models by at least %.0f "
            "yards on %u of %u judged frames. The other candidate (model+%u) "
            "managed %u. Models inside %.0f yards are never throttled from here "
            "on; past that the stride is 2, 3 and %u by %.0f and %.0f yards.",
            win ? kM_worldMatrix : kM_localMatrix,
            kLearnMaxNearYd, kLearnMinSpread, hits, g_learnFrames,
            win ? kM_localMatrix : kM_worldMatrix, g_agree[win ^ 1],
            kBandNearYd, kMaxStride, kBandMidYd, kBandFarYd);
    } else {
        g_distState = kRefused;
        Log("[AnimLod] Distance rule refused. Over %u judged frames model+%u "
            "looked like a world position on %u and model+%u on %u, and neither "
            "reached three quarters. Neither translation is being used; the "
            "feature is on the crowd rule alone, which engages above %u models "
            "in a frame.",
            g_learnFrames, kM_localMatrix, g_agree[0], kM_worldMatrix,
            g_agree[1], kBudget);
    }
}

void OnFrame() {
    if (!g_installed || g_dead) return;

    if (g_seenThis > g_peakModels) g_peakModels = g_seenThis;

    if (g_distState == kLearning) {
        JudgeLearningFrame();
        g_minD[0] = g_minD[1] = 3.4e38f;
        g_maxD[0] = g_maxD[1] = -1.0f;
    }

    // Once a frame, not once a model. A frame with no world - a loading screen,
    // character select - leaves the distance rule inert for that frame and the
    // crowd rule carries it.
    g_camValid = WowWorld::StreamCentre(g_cam);
    if (g_camValid) ++g_camFrames;

    // How many frames to spread one pass over every model across. Computed from
    // the frame that just finished, so it reacts within one frame of a scene
    // filling up and never reads a count that is still being built.
    uint32_t stride = 1;
    if (g_seenThis > kBudget) {
        stride = (g_seenThis + kBudget - 1) / kBudget;
        if (stride > kMaxStride) stride = kMaxStride;
    }
    g_stride = stride;
    if (stride > g_peakStride) g_peakStride = stride;

    g_seenPrev = g_seenThis;
    g_seenThis = 0;

    if (++g_frame == 0) {
        // Wrapped. Every stored lastFrame is now in the future, which would read
        // as "updated recently" forever, so start the table again.
        memset(g_slots, 0, sizeof(g_slots));
        g_frame = 1;
    }
}

bool Init() {
    if (!Config::g_settings.OptAnimLod) return true;

    if (IsBadReadPtr((void*)kAnimateModel, 8)) {
        Log("[AnimLod] 0x%08X unreadable - not installing", (unsigned)kAnimateModel);
        return false;
    }
    memset(g_slots, 0, sizeof(g_slots));
    g_minD[0] = g_minD[1] = 3.4e38f;
    g_maxD[0] = g_maxD[1] = -1.0f;

    if (WineSafe_CreateHook((void*)kAnimateModel, (void*)HookedAnimateModel,
                            &g_origAnimateModel) != MH_OK) {
        Log("[AnimLod] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kAnimateModel) != MH_OK) {
        Log("[AnimLod] hook created but could not be enabled");
        return false;
    }

    g_installed = true;
    Log("[AnimLod] ACTIVE on sub_82F0F0 (0x%08X), the per-model animation pass. "
        "A census measured it at 3.68 ms of a 24.5 ms frame in raid content and "
        "0.69 ms in open world. A model is never skipped before its first "
        "evaluation, and never when the call's tail would have animated its "
        "materials or its attachments. Skipping cannot slow an animation down: "
        "the client derives its time from an absolute clock rather than "
        "accumulating it.",
        (unsigned)kAnimateModel);
    Log("[AnimLod]   Two rules. The crowd rule spreads work above %u models in a "
        "frame, capped at one update in %u. The distance rule is better and has "
        "to earn its place first: for the next %u frames with at least %u models "
        "in them it watches both candidate translations against the camera and "
        "arms whichever behaves like a world position, or refuses both and says "
        "so. Armed, it never throttles a model inside %.0f yards.",
        kBudget, kMaxStride, kLearnFrames, kLearnMinCrowd, kBandNearYd);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptAnimLod) return;
    if (!g_installed)  { Log("[AnimLod] not installed - nothing measured"); return; }
    if (g_calls == 0)  { Log("[AnimLod] installed but never called"); return; }

    Log("[AnimLod] %llu calls, %llu skipped (%.1f%%), %llu first sightings never "
        "skipped; peak %u models in a frame, peak stride %u, currently %u%s",
        g_calls, g_skipped,
        g_calls ? (100.0 * (double)g_skipped / (double)g_calls) : 0.0,
        g_firstSight, g_peakModels, g_peakStride, g_stride,
        g_dead ? " - DISABLED" : "");
    Log("[AnimLod]   %llu calls (%.1f%%) declined because the tail would have "
        "animated materials or attachments", g_hasTailWork,
        g_calls ? (100.0 * (double)g_hasTailWork / (double)g_calls) : 0.0);

    // Three states, and the fourth thing that can happen to it.
    if (g_camFrames == 0) {
        Log("[AnimLod]   distance: no world position was available on any frame, "
            "so the distance rule never had anything to learn from. The crowd "
            "rule is what ran.");
    } else if (g_distState == kLearning) {
        Log("[AnimLod]   distance: still learning - %u of %u frames judged so far "
            "(model+%u agreed on %u, model+%u on %u). A frame is only judged when "
            "at least %u models are in it.",
            g_learnFrames, kLearnFrames, kM_localMatrix, g_agree[0],
            kM_worldMatrix, g_agree[1], kLearnMinCrowd);
    } else if (g_distState == kRefused) {
        Log("[AnimLod]   distance: refused after %u judged frames, neither "
            "translation looked like a world position. Crowd rule only.",
            g_learnFrames);
    } else {
        Log("[AnimLod]   distance: armed on model+%u; %llu of the %llu skips were "
            "its decision, and it protected %llu models that were inside %.0f "
            "yards and would otherwise have been throttled by the crowd rule.",
            g_distOffset, g_distSkipped, g_skipped, g_nearKept, kBandNearYd);
    }
    if (g_evicted)
        Log("[AnimLod]   %llu entries displaced by collisions; those models were "
            "animated rather than skipped", g_evicted);
    if (g_peakModels <= kBudget)
        Log("[AnimLod]   the busiest frame stayed under the %u-model budget, so "
            "nothing was throttled at any point", kBudget);
}

} // namespace AnimLod
