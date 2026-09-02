// ============================================================================
// Module: anim_quat_unpack_sse2.cpp
// Description: SSE2 rewrite of the M2 quaternion track evaluator.
// Safety & Threading: Main thread, inside the per-model animation pass.
// ============================================================================
//
// sub_828680 evaluates one bone's rotation track. It has exactly one caller,
// sub_82F0F0, which is the largest single entry in every main-thread profile
// this project has collected, and it runs once per animated bone per frame.
//
// The interpolation inside it is already vectorised - sub_982630 and sub_982460
// are hooked by quat_lerp_sse2 and hooks_simd. What was left untouched is how
// the keyframes get out of the file format. Each quaternion is stored as four
// uint16 and expanded as v * K - 1.0, and the client does that one component at
// a time through memory:
//
//     movzx ecx, word ptr [eax+edx*8]
//     mov   [ebp+arg_4], ecx        <- spill the integer to the stack
//     fild  [ebp+arg_4]             <- and read it straight back
//     fmul  st, st(1)
//     fsub  st, st(2)
//     fstp  dword ptr [ebx+8]
//
// x86 has no register path from an integer to the x87 stack, so every one of
// those conversions is a store followed immediately by a load of the same
// address. There are four per quaternion, and a call unpacks one, two or four
// quaternions depending on which branch it takes - up to sixteen conversions.
//
// cvtdq2pd converts two at a time in a register with no memory in the way.
//
// ---------------------------------------------------------------------------
// The constant is not the one the decompiler prints
//
// Hex-Rays renders the scale as 0.000030518044. The instruction is
//
//     8286e1  d9 05 60 55 a4 00     fld dword ptr [0x00A45560]
//
// - opcode D9 /0, so a four-byte float, not a double - and the four bytes there
// are 80 00 00 38, which is 3.051804378628731e-05. It is not 1/32767.5 either,
// which is the value the format suggests and which was the first guess here.
//
// That difference was measured rather than argued. Building the scale from the
// decompiler's printed literal instead of the client's own bytes changes the
// result for 19433 of the 65536 possible uint16 inputs - 29.6% of them. So this
// module does not carry a literal at all: Init reads the float out of the
// client's own memory, and refuses to install if the four bytes are not the ones
// this analysis was done against.
//
// ---------------------------------------------------------------------------
// Why packed double is bit-exact here
//
// MSVC leaves the x87 control word at 53-bit precision, which is exactly what a
// double lane carries, so a multiply and a subtract in packed double round
// identically to the same two x87 operations. The sequence is
//
//     exact widening of a uint16   ->  one multiply  ->  one subtract  ->  one
//     round to float on the store
//
// and cvtepi32_pd, mulpd, subpd and cvtpd2ps do the same four steps with the
// same roundings, in the same order. The one place a 53-bit x87 and a double
// still differ is the exponent range - x87 keeps fifteen bits - and that cannot
// reach here: the output of v * K - 1.0 over every uint16 spans exactly -1.0 to
// 1.0, nowhere near an overflow or a denormal.
//
// The fourth component is written as K * v rather than v * K, through fimul
// instead of fild plus fmul. IEEE multiplication is exactly commutative and
// fimul widens the integer exactly, so that is the same value too.
//
// ---------------------------------------------------------------------------
// The argument the decompiler dropped
//
// Hex-Rays types sub_828680 as taking five arguments and never using the first.
// It uses it:
//
//     8286b9  mov ecx, [ebp+arg_0]
//     8286c2  call sub_8284D0
//
// arg_0 is the object sub_8284D0 needs in ECX, and the pseudocode shifted the
// remaining four arguments left to hide it. sub_8284D0 ends in `retn 14h`, so it
// is __thiscall with five stack arguments and is reached here as __fastcall.
// This is the third time in this project a register argument has been missing
// from a prototype; the call site's register writes decide it, not the listing.
//
// ---------------------------------------------------------------------------
// Verification
//
// The only thing this function writes is the twenty-four byte block at `out`:
// two keyframe hints and the four resulting floats. Nothing else is touched -
// sub_8284D0 reads the model and the track and writes only through the caller's
// pointers, and the two interpolators write only their result buffer.
//
// So the block is saved, the client's own routine runs, its answer is copied
// aside, the block is put back exactly as it was, and this one runs on the same
// input. Comparing all twenty-four bytes checks the hints as well as the
// quaternion, which is what proves this drives the keyframe search identically
// and not merely that the arithmetic agrees.
//
// The hints make that replay valid rather than accidental: sub_8284D0 reads
// out[0] as its starting guess and writes back the keyframe it settled on, and
// the search converges on the same keyframe for a given time whichever guess it
// starts from. A run is therefore repeatable in its output even though it is not
// repeatable in the path it takes.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>

#include "anim_quat_unpack_sse2.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"
#include "ab_test.h"
#include "session_verdict.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace AnimQuatUnpack {

namespace {

constexpr uintptr_t kTrackQuat = 0x00828680;
constexpr uintptr_t kFindKey   = 0x008284D0;
constexpr uintptr_t kQuatLerp  = 0x00982630;
constexpr uintptr_t kQuatSlerp = 0x00982460;
constexpr uintptr_t kScaleAddr = 0x00A45560;

// The four bytes this analysis was done against: the float 3.051804378628731e-05.
constexpr uint32_t kScaleBits = 0x38000080u;

// Animation state, from sub_828680 itself.
constexpr unsigned kS_timing1  = 0x40;   // timing sub-struct for the first track
constexpr unsigned kS_trackIdx = 0x44;   // u16, which track entry to evaluate
constexpr unsigned kS_timing2  = 0x64;   // timing sub-struct for the blend track
constexpr unsigned kS_blendIdx = 0x68;   // u16
constexpr unsigned kS_blend    = 0xA8;   // float; zero means no blend

// Track descriptor.
constexpr unsigned kT_interp    = 0x00;  // u16; zero means take the keyframe whole
constexpr unsigned kT_globalSeq = 0x02;  // u16; 0xFFFF means no global sequence
constexpr unsigned kT_count     = 0x0C;
constexpr unsigned kT_entries   = 0x10;  // array of { u32 count; u16* keys }

// sub_8284D0 is __thiscall with five stack arguments and cleans them itself.
typedef void* (__fastcall* findKey_fn)(void* obj, void* edx, void* timing, void* track,
                                       uint32_t* hint, uint32_t* second, float* frac);
typedef float* (__cdecl* quatBlend_fn)(float* out, float t, const float* a, const float* b);
typedef void (__cdecl* trackQuat_fn)(void* obj, void* state, void* track,
                                     uint32_t* out, const float* defQuat);

trackQuat_fn orig_TrackQuat = nullptr;

bool g_installed = false;
bool g_armed     = false;
// Set at init when the A/B harness names this module, so the hot path
// tests a plain bool instead of calling out on every invocation.
bool g_abSubject = false;
bool g_dead      = false;

// Plain 32-bit: this runs per bone per frame and a lost increment costs a
// number, not correctness. The report says the counts are lower bounds.
unsigned long g_calls    = 0;
unsigned long g_verified = 0;
unsigned long g_unpacked = 0;

constexpr unsigned long kVerifyFirst  = 30000;
constexpr unsigned long kResampleMask = 8191;

// Built at Init from the client's own constant rather than from a literal here.
__m128d g_scale;
__m128d g_one;

// Four uint16 to four floats: two conversions instead of four spill-and-reload
// pairs, and the multiply and subtract done two lanes at a time.
inline void UnpackQuat(const uint16_t* src, float* dst) {
    __m128i w   = _mm_loadl_epi64((const __m128i*)src);
    __m128i z   = _mm_unpacklo_epi16(w, _mm_setzero_si128());   // zero-extended
    __m128d d01 = _mm_cvtepi32_pd(z);
    __m128d d23 = _mm_cvtepi32_pd(_mm_shuffle_epi32(z, _MM_SHUFFLE(1, 0, 3, 2)));
    d01 = _mm_sub_pd(_mm_mul_pd(d01, g_scale), g_one);
    d23 = _mm_sub_pd(_mm_mul_pd(d23, g_scale), g_one);
    _mm_storeu_ps(dst, _mm_movelh_ps(_mm_cvtpd_ps(d01), _mm_cvtpd_ps(d23)));
    g_unpacked++;
}

inline void Copy4(float* dst, const float* src) {
    dst[0] = src[0]; dst[1] = src[1]; dst[2] = src[2]; dst[3] = src[3];
}

// Everything read here is read by the client on the path that accepts, so a
// pointer this can fault on is one the client faults on first. No __try: this
// runs per bone per frame.
void Evaluate(void* obj, uint8_t* state, uint8_t* track,
              uint32_t* out, const float* defQuat) {
    const uint32_t  count   = *(const uint32_t*)(track + kT_count);
    const uint32_t  entries = *(const uint32_t*)(track + kT_entries);
    const uint16_t  interp  = *(const uint16_t*)(track + kT_interp);

    uint16_t want = *(const uint16_t*)(state + kS_trackIdx);
    uint32_t sel  = (want < count) ? want : 0u;
    const uint32_t* entry = (const uint32_t*)(entries + 8u * sel);

    float* q = (float*)(out + 2);

    if (entry[0]) {
        uint32_t second = 0;
        float    frac   = 0.0f;
        ((findKey_fn)kFindKey)(obj, nullptr, state + kS_timing1, track,
                               out, &second, &frac);
        const uint16_t* keys = (const uint16_t*)entry[1];
        if (interp == 0) {
            UnpackQuat(keys + 4u * out[0], q);
            return;
        }
        float a[4], b[4], r[4];
        UnpackQuat(keys + 4u * out[0], a);
        UnpackQuat(keys + 4u * second, b);
        Copy4(q, ((quatBlend_fn)kQuatLerp)(r, frac, a, b));
    } else {
        Copy4(q, defQuat);
        if (interp == 0) return;
    }

    const float blend = *(const float*)(state + kS_blend);
    if (blend == 0.0f || *(const uint16_t*)(track + kT_globalSeq) != 0xFFFFu) return;

    float q2[4] = { 0.0f, 0.0f, 0.0f, 1.0f };
    uint16_t wantB = *(const uint16_t*)(state + kS_blendIdx);
    uint32_t selB  = (wantB < count) ? wantB : 0u;
    const uint32_t* entryB = (const uint32_t*)(entries + 8u * selB);

    if (entryB[0] == 0) {
        Copy4(q2, defQuat);
    } else {
        uint32_t second = 0;
        float    frac   = 0.0f;
        ((findKey_fn)kFindKey)(obj, nullptr, state + kS_timing2, track,
                               out + 1, &second, &frac);
        const uint16_t* keys = (const uint16_t*)entryB[1];
        float a[4], b[4], r[4];
        UnpackQuat(keys + 4u * out[1], a);
        UnpackQuat(keys + 4u * second, b);
        Copy4(q2, ((quatBlend_fn)kQuatLerp)(r, frac, a, b));
    }

    float r2[4];
    Copy4(q, ((quatBlend_fn)kQuatSlerp)(r2, blend, q, q2));
}

}  // namespace

void __cdecl Hooked_TrackQuatBody(void* obj, void* state, void* track,
                              uint32_t* out, const float* defQuat) {
    g_calls++;

    if (g_dead || !out || !state || !track || !defQuat) {
        orig_TrackQuat(obj, state, track, out, defQuat);
        return;
    }

    if (!g_armed || (g_calls & kResampleMask) == 0) {
        uint32_t saved[6], theirs[6];
        memcpy(saved, out, sizeof(saved));
        orig_TrackQuat(obj, state, track, out, defQuat);
        memcpy(theirs, out, sizeof(theirs));
        memcpy(out, saved, sizeof(saved));

        Evaluate(obj, (uint8_t*)state, (uint8_t*)track, out, defQuat);
        g_verified++;

        if (memcmp(out, theirs, sizeof(theirs)) != 0) {
            memcpy(out, theirs, sizeof(theirs));
            g_dead = true;
            Verdict::Add(Verdict::Bad,
                         "AnimQuatUnpack disagreed with the client and retired itself for "
                         "this session");
            Log("[AnimQuatUnpack] DISAGREED with the client after %lu checks - "
                "retired for this session, every call now goes to the client's "
                "own code. Client gave %08X %08X %08X %08X (hints %u/%u), this "
                "gave %08X %08X %08X %08X (hints %u/%u).",
                g_verified,
                theirs[2], theirs[3], theirs[4], theirs[5], theirs[0], theirs[1],
                out[2], out[3], out[4], out[5], out[0], out[1]);
            return;
        }
        if (!g_armed && g_verified >= kVerifyFirst) {
            g_armed = true;
            Log("[AnimQuatUnpack] armed: %lu calls matched the client bit for "
                "bit, hints included. Now evaluating directly and rechecking one "
                "call in %lu.", g_verified, kResampleMask + 1);
        }
        return;
    }

    Evaluate(obj, (uint8_t*)state, (uint8_t*)track, out, defQuat);
}

// The detour proper, split from the body above so the A/B harness can time
// the call. A scope guard would be the natural way to close that sample on
// every return path, and MSVC refuses object unwinding in a function that
// contains __try - which the body does. This wrapper has none, so one pair
// of reads covers every path the body can leave by.
void __cdecl Hooked_TrackQuat(void* obj, void* state, void* track,
                              uint32_t* out, const float* defQuat) {
    if (!g_abSubject) { Hooked_TrackQuatBody(obj, state, track, out, defQuat); return; }
    unsigned long long abTick = AbTest::TickIn();
    if (AbTest::StandAside()) orig_TrackQuat(obj, state, track, out, defQuat);
    else                      Hooked_TrackQuatBody(obj, state, track, out, defQuat);
    AbTest::TickOut(abTick);
}

bool Init() {
    if (!Config::g_settings.OptAnimQuatUnpack) return true;

    if (IsBadReadPtr((void*)kTrackQuat, 16) || IsBadReadPtr((void*)kScaleAddr, 4) ||
        IsBadReadPtr((void*)kFindKey, 16)) {
        Log("[AnimQuatUnpack] 0x%08X unreadable - not installing", (unsigned)kTrackQuat);
        return false;
    }

    // Read the scale out of the client instead of carrying a literal, and refuse
    // if it is not the constant this was analysed against - a different four
    // bytes means a different binary and the offsets below would be guesses.
    uint32_t bits = *(const uint32_t*)kScaleAddr;
    if (bits != kScaleBits) {
        Log("[AnimQuatUnpack] the scale at 0x%08X is %08X, not the %08X this was "
            "built against - not installing", (unsigned)kScaleAddr, bits, kScaleBits);
        return false;
    }
    float scaleF;
    memcpy(&scaleF, &bits, sizeof(scaleF));
    g_scale = _mm_set1_pd((double)scaleF);
    g_one   = _mm_set1_pd(1.0);

    if (WineSafe_CreateHook((void*)kTrackQuat, (void*)Hooked_TrackQuat,
                            (void**)&orig_TrackQuat) != MH_OK) {
        Log("[AnimQuatUnpack] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kTrackQuat) != MH_OK) {
        Log("[AnimQuatUnpack] hook created but could not be enabled");
        return false;
    }

    g_abSubject = AbTest::IsSubject("AnimQuatUnpack", &g_abSubject);
    if (g_abSubject) {
        Log("[AnimQuatUnpack] under A/B test: it alternates on and off in stints, "
            "and AbTest reports both the frame times and the cost of this "
            "call each way. The correctness checks are unaffected.");
    }

    g_installed = true;
    SamplingProfiler::RegisterSelfSymbol("AnimQuatUnpack_SSE2", (const void*)&Hooked_TrackQuat);
    Log("[AnimQuatUnpack] ACTIVE on sub_828680 (0x%08X), the bone rotation track, "
        "run once per animated bone per frame from the largest entry in the "
        "main-thread profile. Each keyframe is four uint16 expanded as v * K - "
        "1.0, and x86 has no register path from an integer to the x87 stack, so "
        "the client spills and reloads every component - up to sixteen times a "
        "call. cvtdq2pd converts two at a time in a register. The scale was read "
        "from the client at 0x%08X (%.17g), not from the decompiler, which prints "
        "a value that differs on 29.6%% of the possible inputs. Comparing all "
        "twenty-four output bytes against the client for the first %lu calls, "
        "then one in %lu.",
        (unsigned)kTrackQuat, (unsigned)kScaleAddr, (double)scaleF,
        kVerifyFirst, kResampleMask + 1);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptAnimQuatUnpack) return;
    if (!g_installed) { Log("[AnimQuatUnpack] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[AnimQuatUnpack] installed but never called"); return; }

    Log("[AnimQuatUnpack] %lu track evaluations, %lu quaternions unpacked "
        "(%lu integer conversions the client would have put through memory), "
        "%lu verified against the client%s. Counts are lower bounds.",
        g_calls, g_unpacked, g_unpacked * 4, g_verified,
        g_dead ? " - RETIRED on a disagreement"
               : (g_armed ? " - armed" : " - still verifying, every call still "
                                         "runs the client's code as well"));
}

void Shutdown() {
    if (g_installed) MH_DisableHook((void*)kTrackQuat);
}

}  // namespace AnimQuatUnpack
