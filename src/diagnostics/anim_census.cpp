// ============================================================================
// Module: anim_census.cpp
//
// A tester's sampling profile puts roughly a fifth of main-thread execution in
// the M2 animation family around sub_82F0F0 - the largest single target in the
// whole profile, and about twice anything else. That function interpolates the
// translation, rotation and scale tracks of every bone of a model and assembles
// a 4x4 matrix for each, then walks its attachments, particle emitters, ribbon
// emitters and lights.
//
// The obvious thing to do with a fifth of the frame is level-of-detail: stop
// re-animating models that are far away or small on screen every single frame.
// The obvious thing is not currently possible, and this module exists because
// of why.
//
// sub_82F0F0 takes a matrix as its second argument, and a matrix carries a
// translation - so at first glance the model's world position is right there.
// It is not. Reading the two call sites in the disassembler:
//
//   sub_81CE70   sub_82F0F0(model, a1 + 132, ...)
//   sub_830DC0   sub_82F0F0(this, *(this + 40) + 132, ...)
//
// Both pass +132 of the shared animation context - the same object that holds
// the frame counter at +20 which the once-per-frame guard compares against. It
// is one matrix shared by every model, not that model's placement in the world.
// The other call in sub_830DC0 passes the parent model's +244, which is its
// local 3x3, and no better.
//
// So there is no distance and no screen size at this call site, and level of
// detail driven by anything else is level of detail driven by a guess. The cost
// of guessing wrong is a frozen skeleton on the player's own character or on
// whatever they are fighting, which is not a trade to make blind.
//
// What is missing before that decision can be made is the shape of the work:
// how many models per frame, how many bones between them, and how much of the
// frame it really costs on the machine complaining. A profile says a fifth of
// execution; it does not say whether that is forty models at thirty bones or
// four hundred at three, and those want completely different answers. This
// counts it.
//
// -- Revisiting the "no distance" conclusion -------------------------------
//
// That conclusion was drawn from two call sites. There are seven, and the two
// that were read are not the ones on the render path: sub_821A20 calls this
// twice while building draw batches, and passes a register rather than a fixed
// +132, so the claim that every caller shares one matrix was never actually
// tested against the call that matters most.
//
// It is not being re-litigated in a disassembler. Reading call sites is what
// produced the unverified claim in the first place, and static reasoning about
// this codebase has been wrong twice before where a log was right. Three
// measurements settle it, and all three are read-only:
//
//   - how many DISTINCT matrices arrive as the second argument in one frame.
//     One means the original conclusion holds. Anything near the model count
//     means each model brings its own placement and a distance exists.
//   - whether the translation of the matrix at this+180 varies between models.
//     sub_82F0F0 multiplies that by the second argument, which is what a local
//     transform paired with a shared parent would look like - and if it varies
//     and reads like world coordinates, the distance is there after all.
//   - the actual spread of both, printed for the first few calls, so the
//     numbers can be looked at rather than assumed.
//
// Until those come back this module still only counts. Nothing here changes
// what the client does.
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cmath>

#include "anim_census.h"
#include "../core/world_position.h"
#include "crash_dumper.h"
#include "config.h"
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);
extern DWORD g_mainThreadId;

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace AnimCensus {

static constexpr uintptr_t ADDR_AnimateModel = 0x0082F0F0;

// __thiscall with five stack arguments, emulated as __fastcall with the unused
// EDX slot, which is how every other thiscall detour in this project is written.
typedef int(__fastcall* AnimateModel_fn)(void* This, void* edx,
                                         int a2, int a3, float a4, float a5, float a6);
static AnimateModel_fn orig_AnimateModel = nullptr;

static bool g_active = false;

// Per-frame, reset by OnFrame.
static volatile LONG g_callsThisFrame = 0;
static volatile LONG g_bonesThisFrame = 0;

// Running totals and peaks across the session.
static double   g_sumCalls = 0.0;
static double   g_sumBones = 0.0;
static uint64_t g_frames   = 0;
// Frames that presented with nothing animated. Kept out of the average, which
// answers "when models are animating, how many" - and reported, so the divisor
// is visible rather than assumed.
static uint64_t g_idleFrames = 0;
static LONG     g_peakCalls = 0;
static LONG     g_peakBones = 0;

// Timing is sampled rather than measured on every call. This function runs
// hundreds of times a frame, and a QueryPerformanceCounter pair around each one
// would be a fair fraction of what it is trying to weigh - the same mistake as
// putting a cross-module counter inside a three-nanosecond hook.
static constexpr LONG TIME_EVERY_N = 64;
static volatile LONG g_sinceTimed = 0;
static double   g_sampledNs = 0.0;
static uint64_t g_sampledCount = 0;
static double   g_qpcToNs = 0.0;

// Bone count for a model, read the same way sub_82F0F0 reads it:
//   modelData = *(*(this + 44) + 336);  boneCount = modelData[11];
// Guarded because this runs on every animated model and a malformed one must
// cost a skipped count, not a crash.
// ---- Is there a per-model transform at this call site? ---------------------
//
// All of this is read-only and lives behind the diagnostic's own setting, which
// is off by default.

// Distinct second-argument matrices seen in the current frame. The hook runs on
// the main thread only - it returns to the original otherwise - so these need no
// interlocking. The cap is deliberate: the answer worth having is "one" versus
// "many", and a linear scan of a small table costs less than a hash on a path
// that runs hundreds of times a frame.
static constexpr int MAX_DISTINCT = 96;
static void* g_distinct[MAX_DISTINCT];
static int   g_distinctCount    = 0;
static bool  g_distinctOverflow = false;

static int  g_peakDistinct   = 0;
static bool g_everOverflowed = false;

// ---- Would caching the animation result have helped? -----------------------
//
// The M2 cluster is about 15% of executing time in the one CPU-bound profile
// this project has, and bone matrices are a function of the model's animation
// state. If that state is unchanged from the previous frame the matrices are
// unchanged too, so a cache could skip the work. Whether there is anything to
// skip is a measurement, and this is it - the same discipline that killed
// AnimLod, which declined 94.2% of models and skipped 0.0%.
//
// Two things have to be counted apart, because the client already does some of
// this itself. sub_82F0F0 opens with
//
//     mov eax, [esi+10h]  / test al, 1  / jz  out      ; an instance flag
//     mov ecx, [esi+28h]  / mov edx, [esi+3Ch]
//     cmp edx, [ecx+14h]  / jz  out                    ; a per-tick stamp
//
// so a share of the calls counted here return without doing anything. Those are
// not work a cache could remove - they are work already removed. Counting them
// separately is the difference between "models animated" and "models that
// actually rebuilt their bones".
//
// For the rest, the ceiling on what a cache could skip is how often a model is
// asked for the same animation state two frames running. That is what repeats
// below counts. It is a ceiling and not a promise: a matching tuple is strong
// evidence the output matches, not proof, and proving it needs the bone array
// compared rather than the arguments. If the ceiling turns out to be small the
// idea is dead and one log says so, which is the cheap half of the work.
static constexpr int  ANIM_SLOTS = 512;
struct AnimKey {
    void*    model;
    int      a2, a3;
    uint32_t a4, a5, a6;      // the floats, by bit pattern
    uint64_t frame;
};
static AnimKey g_animKey[ANIM_SLOTS];

static uint64_t g_workCalls   = 0;   // reached past both early exits
static uint64_t g_skipFlag    = 0;   // the instance flag was clear
static uint64_t g_skipStamp   = 0;   // the per-tick stamp already matched
static uint64_t g_repeats     = 0;   // same model, same tuple, previous frame
static uint64_t g_evictions   = 0;   // a slot held a different model

// Read the two conditions the client tests before doing anything, without
// repeating its work. Guarded: this runs on every animated model.
static bool ClassifyEntry(void* This, bool* outFlagClear, bool* outStampMatch) {
    __try {
        const uint8_t* m = (const uint8_t*)This;
        uint32_t flags = *(const uint32_t*)(m + 0x10);
        *outFlagClear = (flags & 1u) == 0u;
        if (*outFlagClear) { *outStampMatch = false; return true; }
        uint32_t owner = *(const uint32_t*)(m + 0x28);
        if (!owner) return false;
        *outStampMatch = *(const uint32_t*)(m + 0x3C) == *(const uint32_t*)(owner + 0x14);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static void NoteAnimRepeat(void* This, int a2, int a3, float a4, float a5, float a6) {
    unsigned slot = (unsigned)(((uintptr_t)This >> 4) & (ANIM_SLOTS - 1));
    AnimKey& k = g_animKey[slot];
    uint32_t b4, b5, b6;
    memcpy(&b4, &a4, 4); memcpy(&b5, &a5, 4); memcpy(&b6, &a6, 4);

    if (k.model == This) {
        // A later frame asking for the same state. Same-frame duplicates are not
        // counted - the client's own stamp already removes those, and counting
        // them would inflate the ceiling with work nobody would have done.
        if (k.frame != g_frames &&
            k.a2 == a2 && k.a3 == a3 &&
            k.a4 == b4 && k.a5 == b5 && k.a6 == b6) {
            g_repeats++;
        }
    } else if (k.model) {
        g_evictions++;
    }
    k.model = This; k.a2 = a2; k.a3 = a3;
    k.a4 = b4; k.a5 = b5; k.a6 = b6; k.frame = g_frames;
}

// Spread of the candidate per-model position across one frame. If every model
// reports the same point this stays at zero and there is nothing to drive a
// distance from.
static float g_locMin[3] = { 0.0f, 0.0f, 0.0f };
static float g_locMax[3] = { 0.0f, 0.0f, 0.0f };
static bool  g_locSeen   = false;
static double g_worstSpread = 0.0;

// A handful of raw samples, so the numbers can be read rather than inferred.
static int g_samplesLogged = 0;
static constexpr int MAX_SAMPLES = 16;

// The client's terrain streaming centre. Without a world position the sampled
// translations are just numbers; with one they can be read as distances, which
// is the form the answer is actually needed in - this census exists to find out
// whether a distance is reachable at the animation call site at all.
//
// It used to read 0x00BE1F30, which no instruction in wow.exe touches, so every
// distance printed here before 2026-08-22 is a distance from the map origin.
static bool ReadPlayerXY(float& px, float& py) {
    float pos[3];
    if (!WowWorld::StreamCentre(pos)) return false;
    px = pos[0];
    py = pos[1];
    return true;
}

static void NoteDistinct(void* m) {
    for (int i = 0; i < g_distinctCount; ++i) {
        if (g_distinct[i] == m) return;
    }
    if (g_distinctCount < MAX_DISTINCT) {
        g_distinct[g_distinctCount++] = m;
    } else {
        g_distinctOverflow = true;
    }
}

// Translation row of the 4x4 at this+180, which sub_82F0F0 multiplies by the
// second argument. Guarded: a malformed model must cost a skipped sample.
static bool ReadLocalTranslation(void* This, float out[3]) {
    __try {
        const float* m = (const float*)((char*)This + 180);
        out[0] = m[12];
        out[1] = m[13];
        out[2] = m[14];
        // A world coordinate in this client stays inside a few tens of
        // thousands; anything else means the guess about the layout is wrong
        // and the number should not be averaged into anything.
        for (int i = 0; i < 3; ++i) {
            if (!(out[i] > -64000.0f && out[i] < 64000.0f)) return false;
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool ReadMatrixTranslation(const void* m, float out[3]) {
    uintptr_t p = (uintptr_t)m;
    if (p < 0x10000 || p >= 0xFFE00000) return false;
    __try {
        const float* f = (const float*)m;
        out[0] = f[12];
        out[1] = f[13];
        out[2] = f[14];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static uint32_t BoneCountOf(void* This) {
    __try {
        uintptr_t base = *(uintptr_t*)((char*)This + 44);
        if (base < 0x10000 || base >= 0xFFE00000) return 0;
        uintptr_t md = *(uintptr_t*)(base + 336);
        if (md < 0x10000 || md >= 0xFFE00000) return 0;
        uint32_t bones = *(uint32_t*)(md + 11 * 4);
        return bones > 4096 ? 0 : bones;   // clearly wrong, do not count it
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static int __fastcall Hooked_AnimateModel(void* This, void* edx,
                                          int a2, int a3, float a4, float a5, float a6) {
    if (!g_active || GetCurrentThreadId() != g_mainThreadId)
        return orig_AnimateModel(This, edx, a2, a3, a4, a5, a6);

    InterlockedIncrement(&g_callsThisFrame);

    // Before anything else: which of the client's two early exits this call
    // would take, and whether its animation state repeats a previous frame's.
    bool flagClear = false, stampMatch = false;
    if (ClassifyEntry(This, &flagClear, &stampMatch)) {
        if (flagClear)       g_skipFlag++;
        else if (stampMatch) g_skipStamp++;
        else {
            g_workCalls++;
            NoteAnimRepeat(This, a2, a3, a4, a5, a6);
        }
    }

    uint32_t bones = BoneCountOf(This);
    if (bones) InterlockedExchangeAdd(&g_bonesThisFrame, (LONG)bones);

    NoteDistinct((void*)(uintptr_t)a2);

    float loc[3];
    if (ReadLocalTranslation(This, loc)) {
        if (!g_locSeen) {
            g_locSeen = true;
            for (int i = 0; i < 3; ++i) { g_locMin[i] = loc[i]; g_locMax[i] = loc[i]; }
        } else {
            for (int i = 0; i < 3; ++i) {
                if (loc[i] < g_locMin[i]) g_locMin[i] = loc[i];
                if (loc[i] > g_locMax[i]) g_locMax[i] = loc[i];
            }
        }

        if (g_samplesLogged < MAX_SAMPLES) {
            ++g_samplesLogged;
            float arg[3];
            bool haveArg = ReadMatrixTranslation((const void*)(uintptr_t)a2, arg);
            Log("[AnimCensus] sample %d: model=%p bones=%u  local(this+180) "
                "= %.1f %.1f %.1f  arg2=%08X%s",
                g_samplesLogged, This, bones, loc[0], loc[1], loc[2],
                (unsigned)a2,
                haveArg ? "" : " (unreadable)");
            if (haveArg) {
                Log("[AnimCensus]            arg2 translation = %.1f %.1f %.1f",
                    arg[0], arg[1], arg[2]);
            }
            // Printed beside them so the samples read as distances rather than
            // as bare coordinates. If either translation is a world position,
            // one of these two distances will look like a plausible yardage and
            // will differ between models.
            float px, py;
            if (!ReadPlayerXY(px, py)) {
                Log("[AnimCensus]            no world position available for "
                    "this sample, so neither translation can be read as a "
                    "distance");
            } else {
                double dl = sqrt((double)(loc[0] - px) * (loc[0] - px) +
                                 (double)(loc[1] - py) * (loc[1] - py));
                Log("[AnimCensus]            camera at %.1f %.1f -> %.1f yd from "
                    "the this+180 translation", px, py, dl);
                if (haveArg) {
                    double da = sqrt((double)(arg[0] - px) * (arg[0] - px) +
                                     (double)(arg[1] - py) * (arg[1] - py));
                    Log("[AnimCensus]            and %.1f yd from the arg2 translation", da);
                }
            }
        }
    }

    // Sampled timing. Note this measures the call including everything it
    // recurses into, which is what a level-of-detail decision would actually
    // save, so it is the number worth having.
    if (InterlockedIncrement(&g_sinceTimed) >= TIME_EVERY_N) {
        InterlockedExchange(&g_sinceTimed, 0);
        LARGE_INTEGER a, b;
        QueryPerformanceCounter(&a);
        int r = orig_AnimateModel(This, edx, a2, a3, a4, a5, a6);
        QueryPerformanceCounter(&b);
        g_sampledNs += (double)(b.QuadPart - a.QuadPart) * g_qpcToNs;
        g_sampledCount++;
        return r;
    }

    return orig_AnimateModel(This, edx, a2, a3, a4, a5, a6);
}

void OnFrame() {
    if (!g_active) return;

    LONG calls = InterlockedExchange(&g_callsThisFrame, 0);
    LONG bones = InterlockedExchange(&g_bonesThisFrame, 0);
    if (calls == 0) { g_idleFrames++; return; }   // no world, or nothing animated

    g_frames++;
    g_sumCalls += (double)calls;
    g_sumBones += (double)bones;
    if (calls > g_peakCalls) g_peakCalls = calls;
    if (bones > g_peakBones) g_peakBones = bones;

    // Both questions are about one frame, so they are settled and reset here.
    if (g_distinctCount > g_peakDistinct) g_peakDistinct = g_distinctCount;
    if (g_distinctOverflow) g_everOverflowed = true;
    g_distinctCount    = 0;
    g_distinctOverflow = false;

    if (g_locSeen) {
        for (int i = 0; i < 3; ++i) {
            double spread = (double)g_locMax[i] - (double)g_locMin[i];
            if (spread > g_worstSpread) g_worstSpread = spread;
        }
        g_locSeen = false;
    }
}

bool Init() {
    if (!Config::g_settings.OptAnimCensus) return true;

    // AnimLod hooks this same function. Two of our modules on one address means
    // whichever installs first wins and the other logs what reads as a failure
    // of the target - the collision this project has a guard for. Both have real
    // switches, so a tester can tick both and get a silent race.
    //
    // The census yields, because it only measures and the other one is a feature
    // a player asked for. Saying so is the point: an absent census with AnimLod
    // on is a decision, and an absent census with AnimLod off would be a defect.
    if (Config::g_settings.OptAnimLod) {
        Log("[AnimCensus] not installing: AnimLod owns sub_%08X and both were "
            "switched on. Turn AnimLod off to measure with this.",
            (unsigned)ADDR_AnimateModel);
        return true;
    }

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    if (freq.QuadPart == 0) return false;
    g_qpcToNs = 1e9 / (double)freq.QuadPart;

    if (WineSafe_CreateHook((void*)ADDR_AnimateModel, (void*)Hooked_AnimateModel,
                            (void**)&orig_AnimateModel) != MH_OK) {
        Log("[AnimCensus] Could not hook the model animation update at 0x%08X",
            (unsigned)ADDR_AnimateModel);
        return false;
    }
    if (WO_EnableHook((void*)ADDR_AnimateModel) != MH_OK) {
        Log("[AnimCensus] Could not enable the hook");
        return false;
    }

    g_active = true;
    CrashDumper::RegisterFeature("AnimCensus");
    Log("[AnimCensus] Counting M2 animation work at 0x%08X (diagnostic - "
        "timing sampled one call in %d)", (unsigned)ADDR_AnimateModel, TIME_EVERY_N);
    return true;
}

// Printed from the periodic report. Shutdown does not run - the DLL exits via
// TerminateProcess - so anything reported only from there is never seen.
void LogStats() {
    if (!g_active || g_frames == 0) return;

    double avgCalls = g_sumCalls / (double)g_frames;
    double avgBones = g_sumBones / (double)g_frames;
    double avgNs    = (g_sampledCount > 0) ? (g_sampledNs / (double)g_sampledCount) : 0.0;

    Log("[AnimCensus] %.1f models/frame (peak %ld), %.0f bones/frame (peak %ld), "
        "%.0f bones per model, over %llu presented frames that animated something "
        "(%llu presented with nothing to animate)",
        avgCalls, g_peakCalls, avgBones, g_peakBones,
        avgCalls > 0.0 ? avgBones / avgCalls : 0.0,
        (unsigned long long)g_frames, (unsigned long long)g_idleFrames);

    if (g_sampledCount > 0) {
        Log("[AnimCensus] %.2f us per model measured over %llu sampled calls, so "
            "about %.2f ms/frame at the average model count",
            avgNs / 1000.0, (unsigned long long)g_sampledCount,
            avgNs * avgCalls / 1e6);
    }

    uint64_t entries = g_workCalls + g_skipFlag + g_skipStamp;
    if (entries) {
        Log("[AnimCensus] of %llu calls: %llu rebuilt bones, %llu returned on the "
            "instance flag, %llu returned because the per-tick stamp already "
            "matched. Only the first group is work a cache could remove.",
            (unsigned long long)entries, (unsigned long long)g_workCalls,
            (unsigned long long)g_skipFlag, (unsigned long long)g_skipStamp);
    }
    if (g_workCalls) {
        Log("[AnimCensus] %llu of those %llu (%.1f%%) were the same model asked "
            "for the same animation state as in an earlier frame. That is the "
            "CEILING on what caching the result could skip, not a promise - a "
            "matching argument tuple is evidence the bones match, and proving it "
            "needs the bone array compared. %llu lookups hit a slot held by a "
            "different model and could not be judged.",
            (unsigned long long)g_repeats, (unsigned long long)g_workCalls,
            100.0 * (double)g_repeats / (double)g_workCalls,
            (unsigned long long)g_evictions);
        if (g_repeats * 20 < g_workCalls)
            Log("[AnimCensus]   under five percent - caching the animation result "
                "is not worth building, and this is the log that says so.");
    }

    // The two numbers that decide whether level of detail is possible here.
    Log("[AnimCensus] Second argument: up to %d distinct matrices in one frame%s",
        g_peakDistinct, g_everOverflowed ? " (hit the table cap, so at least that)" : "");
    Log("[AnimCensus] this+180 translation varied by up to %.1f across one frame",
        g_worstSpread);

    if (g_peakDistinct <= 1 && g_worstSpread < 1.0) {
        Log("[AnimCensus] Both are flat - every model gets the same transform at "
            "this call, so there is still no distance here and no basis for LOD");
    } else {
        Log("[AnimCensus] These vary per model, so a per-model position does reach "
            "this call after all - worth reading the samples above before acting");
    }
}

void Shutdown() {
    if (!g_active) return;
    g_active = false;
    MH_DisableHook((void*)ADDR_AnimateModel);
    LogStats();
}

} // namespace AnimCensus
