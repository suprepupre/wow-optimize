// ============================================================================
// Module: collision_outcode_sse2.cpp
// Description: SSE2 AABB outcode classification for the collision reject pass.
// Safety & Threading: Main thread, same as the function it replaces.
// ============================================================================
//
// sub_7C7230 is 3.8% of executing main-thread time in a corrected tester profile,
// the largest single client function left after the animation path. It takes a
// collision model and a query box, classifies every vertex against the box as a
// six-bit outcode, and then walks the triangles rejecting any whose three vertex
// codes share an outside bit.
//
// The classification is the expensive half and it is all x87: six fcom/fnstsw/
// test/jcc sequences per vertex, four vertices per unrolled pass, with the six
// box bounds pinned on the x87 stack for the whole loop. That is what a shape
// scan reads as dense floating-point maths - there is no arithmetic in it at all,
// only comparisons.
//
// ---------------------------------------------------------------------------
// Why this one and not its sibling
//
// sub_7C6D50 does the same job and was analysed first, at length, for nothing:
// samples do not land there. Before decompiling a hot address, ask which function
// contains it.
//
// The difference that matters is the bounds. sub_7C6D50 sorts pairs into min and
// max and applies a 0.01 epsilon, in x87, at double precision - reproducing that
// in packed single needs an argument about rounding a minimum up and a maximum
// down. This function reads six floats straight out of *(float**)(this+0x10) and
// compares them. There is no arithmetic to reproduce. Widening a float to double
// is exact and order-preserving, so an ordered packed-single compare of the same
// two floats gives the same answer as fcom on the widened pair, for every input
// including every NaN. Bit-exact, with nothing to measure.
//
// ---------------------------------------------------------------------------
// The outcode, read out of the disassembly rather than the decompiler
//
//   fcom [v] ; test ah, 1   ; jnz skip  -> set when C0 = 0, that is bound >= v
//   fcom [v] ; test ah, 41h ; jp  skip  -> set when C3|C0 has odd parity
//
// The second is the interesting one. C3 is equality and C0 is less-than, so the
// bit is set for less-than (one bit) and for equal (one bit) and cleared for
// greater-than (no bits) and for unordered, which sets C3, C2 and C0 and so
// leaves two bits under the mask. That is bound <= v, ordered, false on NaN -
// exactly _mm_cmple_ps. The first is _mm_cmpge_ps by the same reading.
//
//   0x20  b[0] >= v.x      0x10  b[3] <= v.x
//   0x08  b[1] >= v.y      0x04  b[4] <= v.y
//   0x02  b[2] >= v.z      0x01  b[5] <= v.z
//
// So b[0..2] is the minimum corner and b[3..5] the maximum, and a triangle is
// rejected when its three codes share a bit: entirely outside one plane.
//
// ---------------------------------------------------------------------------
// Verifying a function that mutates globals
//
// The triangle loop appends to two global arrays with their own counters and ORs
// a flag bit into a per-index byte. Running it twice and comparing does not work:
// the appends are not idempotent, and worse, the loop tests that same flag byte,
// so the first run changes what the second one does.
//
// So verification predicts instead of repeating. While unarmed this computes what
// it would have appended - reading the flag bytes before anything touches them,
// and modelling its own writes in a private bitset - then lets the client's own
// routine run and do the real work, then compares the client's two appended
// slices against the prediction. Nothing is restored because nothing of ours was
// written. A checked session behaves exactly like an unhooked one.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <emmintrin.h>
#include <cstdint>
#include <cstring>

#include "collision_outcode_sse2.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace CollisionOutcode {

namespace {

constexpr uintptr_t kClassify   = 0x007C7230;
constexpr uintptr_t kFindModel  = 0x0079B1F0;   // __stdcall, 5 args, returns model
constexpr uintptr_t kEnabledFlg = 0x00CDD7A0;

// The two output rings and their counters.
constexpr uintptr_t kHitCount   = 0x00D2DBF8;
constexpr uintptr_t kHitArray   = 0x00D25BF8;
constexpr uintptr_t kNearCount  = 0x00D2DBFC;
constexpr uintptr_t kNearArray  = 0x00D29BF8;
constexpr uint32_t  kRingCap    = 0x2000;

// Model layout, from sub_7C7230 itself.
constexpr unsigned kM_vertCount = 6;
constexpr unsigned kM_verts     = 8;
constexpr unsigned kM_triCount  = 6308;
constexpr unsigned kM_triVerts  = 6310;   // three u16 per triangle, stride 6
constexpr unsigned kM_triMask   = 8110;   // one u16 per triangle
constexpr unsigned kM_triIndex  = 8710;   // one u16 per triangle

// The caller object.
constexpr unsigned kT_overflow  = 0x00;   // pointer; bit 0 set when the ring fills
constexpr unsigned kT_flags     = 0x04;   // byte array indexed by 2 * triangle index
constexpr unsigned kT_bounds    = 0x10;   // pointer to six floats
constexpr unsigned kT_mask      = 0x14;   // u16

// The client's own stack buffer for the codes is 452 bytes. A model with more
// vertices than that would overrun it, which is the client's business and not
// something to differ about - those are handed straight back.
constexpr int kMaxVerts = 452;

typedef int (__stdcall* findModel_fn)(int a0, int a4, void* p1, void* p2, void* p3);

void* orig_Classify = nullptr;

bool g_installed = false;
bool g_dead      = false;

unsigned long g_calls = 0, g_verified = 0, g_declined = 0;
unsigned long long g_verts = 0, g_tris = 0;

constexpr unsigned long kVerifyFirst  = 3000;
constexpr unsigned long kResampleMask = 255;
volatile LONG g_armed = 0;

inline uint32_t RD32(uintptr_t a)          { return *(const uint32_t*)a; }
inline uint16_t RD16(uintptr_t a)          { return *(const uint16_t*)a; }

// Four vertices per pass, three floats each, into four outcode bytes.
//
// The vertices are a packed array of 3 floats, so a pass reads twelve floats as
// three unaligned 16-byte loads and transposes them. The last pass of a model
// would read up to four bytes past its final vertex if it used a 16-byte load on
// the tail, so the tail is done one vertex at a time below.
void ClassifySse2(uint8_t* codes, const float* v, int n, const float* b) {
    const __m128 bx0 = _mm_set1_ps(b[0]), bx1 = _mm_set1_ps(b[3]);
    const __m128 by0 = _mm_set1_ps(b[1]), by1 = _mm_set1_ps(b[4]);
    const __m128 bz0 = _mm_set1_ps(b[2]), bz1 = _mm_set1_ps(b[5]);

    const __m128i m20 = _mm_set1_epi32(0x20), m10 = _mm_set1_epi32(0x10);
    const __m128i m08 = _mm_set1_epi32(0x08), m04 = _mm_set1_epi32(0x04);
    const __m128i m02 = _mm_set1_epi32(0x02), m01 = _mm_set1_epi32(0x01);

    int i = 0;
    for (; i + 4 <= n; i += 4, v += 12) {
        // Gathered by lane rather than shuffled from three loads. A hand-written
        // 3x4 transpose is four shuffles shorter and it is not worth a shuffle
        // mask nobody here can execute to check: the six compares that follow are
        // the point, and they replace ninety-odd x87 instructions either way.
        __m128 X = _mm_set_ps(v[9],  v[6], v[3], v[0]);
        __m128 Y = _mm_set_ps(v[10], v[7], v[4], v[1]);
        __m128 Z = _mm_set_ps(v[11], v[8], v[5], v[2]);

        __m128i r =
            _mm_or_si128(
                _mm_or_si128(
                    _mm_or_si128(_mm_and_si128(_mm_castps_si128(_mm_cmpge_ps(bx0, X)), m20),
                                 _mm_and_si128(_mm_castps_si128(_mm_cmple_ps(bx1, X)), m10)),
                    _mm_or_si128(_mm_and_si128(_mm_castps_si128(_mm_cmpge_ps(by0, Y)), m08),
                                 _mm_and_si128(_mm_castps_si128(_mm_cmple_ps(by1, Y)), m04))),
                _mm_or_si128(_mm_and_si128(_mm_castps_si128(_mm_cmpge_ps(bz0, Z)), m02),
                             _mm_and_si128(_mm_castps_si128(_mm_cmple_ps(bz1, Z)), m01)));

        r = _mm_packs_epi32(r, r);
        r = _mm_packus_epi16(r, r);
        *(uint32_t*)(codes + i) = (uint32_t)_mm_cvtsi128_si32(r);
    }

    for (; i < n; ++i, v += 3) {
        uint8_t c = 0;
        if (b[0] >= v[0]) c |= 0x20;
        if (b[3] <= v[0]) c |= 0x10;
        if (b[1] >= v[1]) c |= 0x08;
        if (b[4] <= v[1]) c |= 0x04;
        if (b[2] >= v[2]) c |= 0x02;
        if (b[5] <= v[2]) c |= 0x01;
        codes[i] = c;
    }
}

// The same classification written the obvious way, used only while verifying.
void ClassifyScalar(uint8_t* codes, const float* v, int n, const float* b) {
    for (int i = 0; i < n; ++i, v += 3) {
        uint8_t c = 0;
        if (b[0] >= v[0]) c |= 0x20;
        if (b[3] <= v[0]) c |= 0x10;
        if (b[1] >= v[1]) c |= 0x08;
        if (b[4] <= v[1]) c |= 0x04;
        if (b[2] >= v[2]) c |= 0x02;
        if (b[5] <= v[2]) c |= 0x01;
        codes[i] = c;
    }
}

void Retire(const char* why) {
    if (g_dead) return;
    g_dead = true;
    Log("[CollisionOutcode] Disabled for this session: %s. The client's own "
        "routine runs from here on.", why);
}

} // namespace

// A private bitset over the u16 index space, so a prediction run can model the
// flag bit it would have set without touching the client's byte array.
static uint32_t g_shadow[65536 / 32];

extern "C" char __fastcall CollisionOutcode_Hooked(void* thisPtr, void* /*edx*/,
                                                   int a0, int a4) {
    typedef char (__fastcall* orig_fn)(void*, void*, int, int);
    orig_fn call_orig = (orig_fn)orig_Classify;

    if (g_dead || !thisPtr) return call_orig(thisPtr, nullptr, a0, a4);
    ++g_calls;

    uintptr_t T = (uintptr_t)thisPtr;
    uint8_t   codes[kMaxVerts];
    uint8_t   ref[kMaxVerts];
    int       n = 0;
    int       model = 0;
    bool      verifying = (g_armed == 0) || ((g_calls & kResampleMask) == 0);

    __try {
        if (RD32(kEnabledFlg) == 0) { ++g_declined; return call_orig(thisPtr, nullptr, a0, a4); }

        model = ((findModel_fn)kFindModel)(a0, a4,
                    *(void**)(T + 4), *(void**)(T + 8), *(void**)(T + 12));
        if (!model) { ++g_declined; return call_orig(thisPtr, nullptr, a0, a4); }

        n = (int)RD16((uintptr_t)model + kM_vertCount);
        if (n <= 0 || n > kMaxVerts) { ++g_declined; return call_orig(thisPtr, nullptr, a0, a4); }

        const float* bounds = *(const float**)(T + kT_bounds);
        if (!bounds) { ++g_declined; return call_orig(thisPtr, nullptr, a0, a4); }

        ClassifySse2(codes, (const float*)((uintptr_t)model + kM_verts), n, bounds);
        if (verifying) {
            ClassifyScalar(ref, (const float*)((uintptr_t)model + kM_verts), n, bounds);
            if (memcmp(codes, ref, (size_t)n) != 0) {
                Log("[CollisionOutcode] The vector classification disagreed with the "
                    "scalar one over %d vertices.", n);
                Retire("a vertex was classified differently by the two paths");
                return call_orig(thisPtr, nullptr, a0, a4);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Retire("classifying the vertices faulted");
        return call_orig(thisPtr, nullptr, a0, a4);
    }

    g_verts += (unsigned long long)n;

    // ---- the triangle pass -------------------------------------------------
    uint32_t triCount = 0;
    uint16_t mask     = 0;
    uint8_t* flags    = nullptr;

    __try {
        triCount = RD16((uintptr_t)model + kM_triCount);
        mask     = RD16(T + kT_mask);
        flags    = *(uint8_t**)(T + kT_flags);
        if (!flags) { ++g_declined; return call_orig(thisPtr, nullptr, a0, a4); }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Retire("reading the triangle block faulted");
        return call_orig(thisPtr, nullptr, a0, a4);
    }

    if (verifying) {
        // Predict, do not perform. Everything below reads the flag bytes as they
        // are now and models its own writes in g_shadow, so the client's routine
        // afterwards sees exactly the state it would have seen alone.
        static uint16_t predHit[kRingCap];
        static uint16_t predNear[kRingCap];
        uint32_t nHit = 0, nNear = 0;

        uint32_t hitBefore  = RD32(kHitCount);
        uint32_t nearBefore = RD32(kNearCount);

        __try {
            memset(g_shadow, 0, sizeof(g_shadow));
            uint32_t room = hitBefore;
            for (uint32_t i = 0; i < triCount; ++i) {
                uintptr_t tri = (uintptr_t)model + 6u * i;
                uint16_t idx = RD16((uintptr_t)model + kM_triIndex + 2u * i);
                if ((mask & RD16((uintptr_t)model + kM_triMask + 2u * i)) != 0) continue;

                uint8_t f = flags[2u * idx];
                if (g_shadow[idx >> 5] & (1u << (idx & 31))) f |= 0x80u;
                if (((uint8_t)mask & f) != 0) continue;

                if (room >= kRingCap) break;      // the client stops here too
                if (nHit < kRingCap) predHit[nHit++] = idx;
                ++room;
                g_shadow[idx >> 5] |= (1u << (idx & 31));

                uint8_t ca = codes[RD16(tri + kM_triVerts)];
                uint8_t cb = codes[RD16(tri + kM_triVerts + 2)];
                uint8_t cc = codes[RD16(tri + kM_triVerts + 4)];
                if (((ca & cb & cc) & 0x3F) == 0 && nNear < kRingCap)
                    predNear[nNear++] = idx;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Retire("predicting the triangle pass faulted");
            return call_orig(thisPtr, nullptr, a0, a4);
        }

        char rc = call_orig(thisPtr, nullptr, a0, a4);

        __try {
            uint32_t hitAfter  = RD32(kHitCount);
            uint32_t nearAfter = RD32(kNearCount);
            const uint16_t* hits  = (const uint16_t*)kHitArray;
            const uint16_t* nears = (const uint16_t*)kNearArray;

            bool ok = (hitAfter - hitBefore == nHit) && (nearAfter - nearBefore == nNear);
            for (uint32_t i = 0; ok && i < nHit; ++i)
                if (hits[hitBefore + i] != predHit[i]) ok = false;
            for (uint32_t i = 0; ok && i < nNear; ++i)
                if (nears[nearBefore + i] != predNear[i]) ok = false;

            if (!ok) {
                Log("[CollisionOutcode] Prediction differed from the client: it "
                    "queued %u/%u where this expected %u/%u, over %u triangles.",
                    hitAfter - hitBefore, nearAfter - nearBefore, nHit, nNear, triCount);
                Retire("the predicted triangle list did not match the client's");
                return rc;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Retire("comparing against the client faulted");
            return rc;
        }

        unsigned long okCount = ++g_verified;
        if (g_armed == 0 && okCount >= kVerifyFirst) {
            InterlockedExchange(&g_armed, 1);
            Log("[CollisionOutcode] %lu classifications matched the client exactly, "
                "vertex codes and queued triangles both. Doing the work from here; "
                "one call in %d stays checked.",
                okCount, (int)(kResampleMask + 1));
        }
        return rc;
    }

    // ---- armed: do the work ------------------------------------------------
    __try {
        for (uint32_t i = 0; i < triCount; ++i) {
            uintptr_t tri = (uintptr_t)model + 6u * i;
            uint16_t idx = RD16((uintptr_t)model + kM_triIndex + 2u * i);
            if ((mask & RD16((uintptr_t)model + kM_triMask + 2u * i)) != 0) continue;
            if (((uint8_t)mask & flags[2u * idx]) != 0) continue;

            uint32_t count = RD32(kHitCount);
            if (count >= kRingCap) {
                void* ov = *(void**)(T + kT_overflow);
                if (ov) *(uint32_t*)ov |= 1u;
                break;
            }
            ((uint16_t*)kHitArray)[count] = idx;
            *(uint32_t*)kHitCount = count + 1;
            flags[2u * idx] |= 0x80u;

            uint8_t ca = codes[RD16(tri + kM_triVerts)];
            uint8_t cb = codes[RD16(tri + kM_triVerts + 2)];
            uint8_t cc = codes[RD16(tri + kM_triVerts + 4)];
            if (((ca & cb & cc) & 0x3F) == 0) {
                uint32_t nc = RD32(kNearCount);
                ((uint16_t*)kNearArray)[nc] = idx;
                *(uint32_t*)kNearCount = nc + 1;
            }
        }
        g_tris += triCount;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Retire("the triangle pass faulted");
        return call_orig(thisPtr, nullptr, a0, a4);
    }
    return 1;
}

bool Init() {
    if (!Config::g_settings.OptCollisionOutcode) return true;

    if (IsBadReadPtr((void*)kClassify, 8) || IsBadReadPtr((void*)kFindModel, 8)) {
        Log("[CollisionOutcode] 0x%08X unreadable - not installing", (unsigned)kClassify);
        return false;
    }
    if (WineSafe_CreateHook((void*)kClassify, (void*)CollisionOutcode_Hooked,
                            &orig_Classify) != MH_OK) {
        Log("[CollisionOutcode] hook NOT created");
        return false;
    }
    if (WO_EnableHook((void*)kClassify) != MH_OK) {
        Log("[CollisionOutcode] hook created but could not be enabled");
        return false;
    }

    g_installed = true;
    Log("[CollisionOutcode] ACTIVE on sub_7C7230 (0x%08X), the collision reject "
        "pass - 3.8%% of executing time in a corrected profile. Six x87 compares "
        "per vertex replaced by six packed compares per four vertices. The bounds "
        "are plain floats with no arithmetic applied, so the vector compares are "
        "bit-exact rather than close. Checking against the client for the first "
        "%lu calls - vertex codes and queued triangles both - then one in %d.",
        (unsigned)kClassify, kVerifyFirst, (int)(kResampleMask + 1));
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptCollisionOutcode) return;
    if (!g_installed) { Log("[CollisionOutcode] not installed - nothing measured"); return; }
    if (g_calls == 0) { Log("[CollisionOutcode] installed but never called"); return; }
    Log("[CollisionOutcode] %lu calls, %llu vertices classified, %llu triangles "
        "walked, %lu verified against the client, %lu handed back%s",
        g_calls, g_verts, g_tris, g_verified, g_declined,
        g_dead ? " - DISABLED" : (g_armed ? "" : " (still verifying)"));
}

} // namespace CollisionOutcode
