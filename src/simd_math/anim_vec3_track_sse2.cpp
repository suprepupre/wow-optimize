// ============================================================================
// Module: anim_vec3_track_sse2.cpp
// Description: SSE2 rewrite of the M2 vector track evaluator.
// Safety & Threading: Main thread, inside the per-model animation pass.
// ============================================================================
//
// sub_82B0A0 evaluates one three-float animation track - the translation of a
// bone, and the same routine is reused for every other vector-valued track. It
// has eight call sites, six of them inside sub_82F0F0, which is the largest
// single entry in every main-thread profile this project has collected. The
// quaternion track next door has one. So this runs more often per model than the
// rotation work already replaced, and it was worth checking rather than assuming
// the quaternion was the busier of the two.
//
// The work is three linear interpolations, done one component at a time on the
// x87 stack, and up to two stages of them.
//
// ---------------------------------------------------------------------------
// Where the client rounds, and where it does not
//
// This is the part that decides whether a replacement can be bit-exact, and it
// is not uniform across the function. Stage one ends each component with a store:
//
//     fld  dword ptr [eax+ecx*4]   ; b
//     fsub dword ptr [eax+edx*4]   ; b - a
//     fld  [ebp+var_4]             ; t
//     fmul st(1), st
//     fxch st(1)
//     fadd dword ptr [eax]         ; (b-a)*t + a
//     fstp dword ptr [esi+8]       ; rounded to float here
//
// Stage two, which blends a second track over the first, does not:
//
//     fadd dword ptr [eax]         ; (b-a)*t + a  - stays on the stack
//     fld  dword ptr [ecx+4]       ; no fstp; the value is never rounded
//
// The three results of the second track's interpolation accumulate at the x87
// stack's working precision and feed the final blend directly, while the first
// stage's results are read back out of memory as floats. A replacement that
// rounds where the client does not, or fails to round where it does, is wrong -
// and a single-precision version would be wrong in both ways at once. Every
// intermediate here is therefore carried in double and rounded only at the two
// places the client rounds.
//
// That the double is enough is the same argument that held for the quaternion
// lerp, which was measured bit-identical over three million samples: MSVC leaves
// the x87 control word at 53-bit precision, which is exactly what a double lane
// carries, so subtract, multiply and add round identically in the same order.
// The association is uniform across all three components - (b - a) * t + a - and
// the two places the client writes `t * (b - a)` instead are the same value,
// because IEEE multiplication is exactly commutative.
//
// ---------------------------------------------------------------------------
// The argument the decompiler dropped, again
//
// Hex-Rays types this as five arguments and never uses the first. It is used:
//
//     82b0d5  mov ecx, [ebp+arg_0]
//     82b0de  call sub_8284D0
//     82b1c7  mov ecx, [ebp+arg_0]
//     82b1ca  call sub_8284D0
//
// arg_0 is the object the keyframe search needs in ECX, at both call sites.
// Fourth time in this project that a register argument has been missing from a
// prototype, and the second in this same family of functions.
//
// ---------------------------------------------------------------------------
// The zero test is a comparison, not a threshold
//
// Stage two is entered on `blend != 0.0`, which the client writes as an fcomp
// against a constant followed by `test ah, 44h` / `jnp`. Working through the
// condition codes: equal skips, less and greater both enter, and unordered -
// a NaN weight - enters as well. C's `!= 0.0f` answers identically for all four,
// including NaN and negative zero, so the plain comparison is exact here and
// needs no special case.
//
// ---------------------------------------------------------------------------
// Verification
//
// The only thing this function writes is the twenty-byte block at `out`: two
// keyframe hints and the three resulting floats. The keyframe search reads the
// model and the track and writes only through the caller's pointers.
//
// So the block is saved, the client's own routine runs, its answer is copied
// aside, the block is put back exactly as it was, and this one runs on the same
// input. All twenty bytes are compared, which checks the hints as well as the
// vector - proving the keyframe search is driven identically rather than merely
// that the arithmetic agrees.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>

#include "anim_vec3_track_sse2.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "sampling_profiler.h"
#include "ab_test.h"
#include "session_verdict.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace AnimVec3Track {

namespace {

constexpr uintptr_t kVecTrack = 0x0082B0A0;
constexpr uintptr_t kFindKey  = 0x008284D0;

// Animation state, read straight off the disassembly above.
constexpr unsigned kS_timing1  = 0x40;
constexpr unsigned kS_trackIdx = 0x44;   // u16
constexpr unsigned kS_timing2  = 0x64;
constexpr unsigned kS_blendIdx = 0x68;   // u16
constexpr unsigned kS_blend    = 0xA8;   // float

// Track descriptor.
constexpr unsigned kT_interp    = 0x00;  // u16; zero means take the keyframe whole
constexpr unsigned kT_globalSeq = 0x02;  // u16; 0xFFFF means no global sequence
constexpr unsigned kT_count     = 0x0C;
constexpr unsigned kT_entries   = 0x10;  // { u32 count; float* keys }

constexpr unsigned kKeyStride = 3;       // floats per keyframe

// sub_8284D0 is __thiscall with five stack arguments and cleans them itself.
typedef void* (__fastcall* findKey_fn)(void* obj, void* edx, void* timing, void* track,
                                       uint32_t* hint, uint32_t* second, float* frac);
typedef void (__cdecl* vecTrack_fn)(void* obj, void* state, void* track,
                                    uint32_t* out, const float* defVec);

vecTrack_fn orig_VecTrack = nullptr;

bool g_installed = false;
bool g_armed     = false;
// Set at init when the A/B harness names this module, so the hot path
// tests a plain bool instead of calling out on every invocation.
bool g_abSubject = false;
bool g_dead      = false;

// Plain 32-bit: per bone per frame, and a lost increment costs a number rather
// than correctness. The report says the counts are lower bounds.
unsigned long g_calls    = 0;
unsigned long g_verified = 0;
unsigned long g_lerps    = 0;
unsigned long g_blends   = 0;

constexpr unsigned long kVerifyFirst  = 30000;
constexpr unsigned long kResampleMask = 8191;

// Three floats widened exactly into two double lanes plus a scalar. The third
// component is kept scalar rather than padded, because a fourth lane would read
// a float past the end of a twelve-byte keyframe.
struct Vec3d {
    __m128d xy;
    double  z;
};

inline Vec3d LoadVec3(const float* p) {
    Vec3d v;
    v.xy = _mm_cvtps_pd(_mm_castsi128_ps(_mm_loadl_epi64((const __m128i*)p)));
    v.z  = (double)p[2];
    return v;
}

// (b - a) * t + a, in the order and at the precision the client uses.
inline Vec3d LerpVec3(const Vec3d& a, const Vec3d& b, double t) {
    Vec3d r;
    __m128d td = _mm_set1_pd(t);
    r.xy = _mm_add_pd(_mm_mul_pd(_mm_sub_pd(b.xy, a.xy), td), a.xy);
    r.z  = (b.z - a.z) * t + a.z;
    return r;
}

inline void StoreVec3(float* out, const Vec3d& v) {
    _mm_storel_pi((__m64*)out, _mm_cvtpd_ps(v.xy));
    out[2] = (float)v.z;
}

inline Vec3d FromFloats(const float* p) { return LoadVec3(p); }

// Everything read here is read by the client on the path that accepts, so a
// pointer this can fault on is one the client faults on first. No __try: this
// runs per bone per frame.
void Evaluate(void* obj, uint8_t* state, uint8_t* track,
              uint32_t* out, const float* defVec) {
    const uint32_t count   = *(const uint32_t*)(track + kT_count);
    const uint32_t entries = *(const uint32_t*)(track + kT_entries);
    const uint16_t interp  = *(const uint16_t*)(track + kT_interp);

    uint16_t want = *(const uint16_t*)(state + kS_trackIdx);
    uint32_t sel  = (want < count) ? want : 0u;
    const uint32_t* entry = (const uint32_t*)(entries + 8u * sel);

    float* o = (float*)(out + 2);

    if (entry[0]) {
        uint32_t second = 0;
        float    frac   = 0.0f;
        ((findKey_fn)kFindKey)(obj, nullptr, state + kS_timing1, track,
                               out, &second, &frac);
        const float* keys = (const float*)entry[1];
        if (interp == 0) {
            const float* k = keys + kKeyStride * out[0];
            o[0] = k[0]; o[1] = k[1]; o[2] = k[2];
            return;
        }
        Vec3d a = LoadVec3(keys + kKeyStride * out[0]);
        Vec3d b = LoadVec3(keys + kKeyStride * second);
        StoreVec3(o, LerpVec3(a, b, (double)frac));
        g_lerps++;
    } else {
        o[0] = defVec[0]; o[1] = defVec[1]; o[2] = defVec[2];
        if (interp == 0) return;
    }

    const float blend = *(const float*)(state + kS_blend);
    if (blend == 0.0f || *(const uint16_t*)(track + kT_globalSeq) != 0xFFFFu) return;

    uint16_t wantB = *(const uint16_t*)(state + kS_blendIdx);
    uint32_t selB  = (wantB < count) ? wantB : 0u;
    const uint32_t* entryB = (const uint32_t*)(entries + 8u * selB);

    // Held in double on purpose. The client leaves these on the x87 stack and
    // never rounds them to float before the blend below.
    Vec3d v;
    if (entryB[0]) {
        uint32_t second = 0;
        float    frac   = 0.0f;
        ((findKey_fn)kFindKey)(obj, nullptr, state + kS_timing2, track,
                               out + 1, &second, &frac);
        const float* keys = (const float*)entryB[1];
        Vec3d a = LoadVec3(keys + kKeyStride * out[1]);
        Vec3d b = LoadVec3(keys + kKeyStride * second);
        v = LerpVec3(a, b, (double)frac);
    } else {
        v = FromFloats(defVec);
    }

    Vec3d cur = LoadVec3(o);
    StoreVec3(o, LerpVec3(cur, v, (double)blend));
    g_blends++;
}

}  // namespace

void __cdecl Hooked_VecTrackBody(void* obj, void* state, void* track,
                             uint32_t* out, const float* defVec) {
    g_calls++;

    if (g_dead || !out || !state || !track || !defVec) {
        orig_VecTrack(obj, state, track, out, defVec);
        return;
    }

    if (!g_armed || (g_calls & kResampleMask) == 0) {
        uint32_t saved[5], theirs[5];
        memcpy(saved, out, sizeof(saved));
        orig_VecTrack(obj, state, track, out, defVec);
        memcpy(theirs, out, sizeof(theirs));
        memcpy(out, saved, sizeof(saved));

        Evaluate(obj, (uint8_t*)state, (uint8_t*)track, out, defVec);
        g_verified++;

        if (memcmp(out, theirs, sizeof(theirs)) != 0) {
            memcpy(out, theirs, sizeof(theirs));
            g_dead = true;
            Verdict::Add(Verdict::Bad,
                         "AnimVec3Track disagreed with the client and retired itself for "
                         "this session");
            Log("[AnimVec3Track] DISAGREED with the client after %lu checks - "
                "retired for this session, every call now goes to the client's "
                "own code. Client gave %08X %08X %08X (hints %u/%u), this gave "
                "%08X %08X %08X (hints %u/%u).",
                g_verified,
                theirs[2], theirs[3], theirs[4], theirs[0], theirs[1],
                out[2], out[3], out[4], out[0], out[1]);
            return;
        }
        if (!g_armed && g_verified >= kVerifyFirst) {
            g_armed = true;
            Log("[AnimVec3Track] armed: %lu calls matched the client bit for bit, "
                "hints included. Now evaluating directly and rechecking one call "
                "in %lu.", g_verified, kResampleMask + 1);
        }
        return;
    }

    Evaluate(obj, (uint8_t*)state, (uint8_t*)track, out, defVec);
}

// The detour proper, split from the body above so the A/B harness can time
// the call. A scope guard would be the natural way to close that sample on
// every return path, and MSVC refuses object unwinding in a function that
// contains __try - which the body does. This wrapper has none, so one pair
// of reads covers every path the body can leave by.
void __cdecl Hooked_VecTrack(void* obj, void* state, void* track,
                             uint32_t* out, const float* defVec) {
    if (!g_abSubject) { Hooked_VecTrackBody(obj, state, track, out, defVec); return; }
    unsigned long long abTick = AbTest::TickIn();
    if (AbTest::StandAside()) orig_VecTrack(obj, state, track, out, defVec);
    else                      Hooked_VecTrackBody(obj, state, track, out, defVec);
    AbTest::TickOut(abTick);
}

bool Init() {
    if (!Config::g_settings.OptAnimVec3Track) return true;

    if (IsBadReadPtr((void*)kVecTrack, 16) || IsBadReadPtr((void*)kFindKey, 16)) {
        Log("[AnimVec3Track] 0x%08X unreadable - not installing", (unsigned)kVecTrack);
        return false;
    }
    // push ebp / mov ebp, esp / mov edx, [ebp+arg_4]
    const unsigned char* p = (const unsigned char*)kVecTrack;
    if (p[0] != 0x55 || p[1] != 0x8B || p[2] != 0xEC || p[3] != 0x8B) {
        Log("[AnimVec3Track] 0x%08X does not start with the prologue this was read "
            "from (%02X %02X %02X %02X) - not installing",
            (unsigned)kVecTrack, p[0], p[1], p[2], p[3]);
        return false;
    }
    if (WineSafe_CreateHook((void*)kVecTrack, (void*)Hooked_VecTrack,
                            (void**)&orig_VecTrack) != MH_OK) {
        Log("[AnimVec3Track] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kVecTrack) != MH_OK) {
        Log("[AnimVec3Track] hook created but could not be enabled");
        return false;
    }

    g_abSubject = AbTest::IsSubject("AnimVec3Track");
    if (g_abSubject) {
        Log("[AnimVec3Track] under A/B test: it alternates on and off in stints, "
            "and AbTest reports both the frame times and the cost of this "
            "call each way. The correctness checks are unaffected.");
    }

    g_installed = true;
    SamplingProfiler::RegisterSelfSymbol("AnimVec3Track_SSE2", (const void*)&Hooked_VecTrack);
    Log("[AnimVec3Track] ACTIVE on sub_82B0A0 (0x%08X), the vector animation "
        "track. Eight call sites, six of them inside the largest entry in the "
        "main-thread profile, against one for the quaternion track already "
        "replaced. Three interpolations done one component at a time on the x87 "
        "stack become two lanes and a scalar. Stage one rounds each component to "
        "float on the store and stage two does not round at all before the blend, "
        "so both are reproduced where they happen and the result is bit-exact "
        "rather than close. Comparing all twenty output bytes against the client "
        "for the first %lu calls, then one in %lu.",
        (unsigned)kVecTrack, kVerifyFirst, kResampleMask + 1);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptAnimVec3Track) return;
    if (!g_installed) { Log("[AnimVec3Track] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[AnimVec3Track] installed but never called"); return; }

    Log("[AnimVec3Track] %lu track evaluations, %lu interpolated, %lu of those "
        "blended with a second track, %lu verified against the client%s. Counts "
        "are lower bounds.",
        g_calls, g_lerps, g_blends, g_verified,
        g_dead ? " - RETIRED on a disagreement"
               : (g_armed ? " - armed" : " - still verifying, every call still "
                                         "runs the client's code as well"));
}

void Shutdown() {
    if (g_installed) MH_DisableHook((void*)kVecTrack);
}

}  // namespace AnimVec3Track
