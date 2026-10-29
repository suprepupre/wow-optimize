// ============================================================================
// Module: particle_fill_sse2.cpp
//
// The per-particle vertex fill in the client's particle emitter, sub_6C4440
// (Particle_FillVertices, 2.5% of self time in the corrected combat profile).
//
// The function is __thiscall with nine stack arguments and ends in `retn 24h`:
//
//   ecx      the emitter: +0Ch particle count, +10h particles (20 bytes each),
//            +1Ch colour count, +20h colours (4 bytes each)
//   arg_0    destination, 24 bytes a vertex
//   arg_4    the single colour used when the emitter has no colour array
//   arg_8    UV scroll pair, read only by the wrapping path
//   arg_C    a colour, read only by the wrapping path
//   arg_10   the world offset added to every particle position
//   arg_14   low byte set: the wrapping path with floor() and a colour convert
//   arg_18   low byte, read only by the wrapping path
//   arg_1C   first particle
//   arg_20   particles wanted
//
// It has two loops. The stock client executes serial x87 arithmetic for
// coordinates and calls sub_532AF0 once per particle on the global device to
// read one flag at +14h (red/blue swap).
//
// Optimizations:
//   1. Reads device red/blue swap flag once per fill instead of once per particle.
//   2. If colour is uniform (colourStride == 0), hoists the colour fetch and
//      red/blue byte-swap completely outside the particle loop.
//   3. Processes particles in 2x unrolled dual-register SIMD streams (_mm_loadu_ps,
//      _mm_add_ps, _mm_storeu_ps) with hazard-free 64-bit UV writes.
//   4. Supports the wrapping path for scrolling particles (evaluating scroll
//      floors and slicing wrapped vs trailing segments) instead of bailing out
//      to stock x87 scalar code. Complex modulated alpha cases fall back to client.
//   5. Bit-exact dual-run verification compares predicted vertex buffers byte for
//      byte against client output for the first 4096 fills and 1 in 1024 fills
//      thereafter, with instant fail-safe retirement on any mismatch.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <emmintrin.h>

#include "particle_fill_sse2.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "session_verdict.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace ParticleFill {

namespace {

constexpr uintptr_t kTarget    = 0x006C4440;
constexpr uintptr_t kGateByte  = 0x00C7D2E4;
constexpr uintptr_t kDevicePtr = 0x00C5DF88;

// push ebp / mov ebp,esp / sub esp,0ECh / push edi / mov edi,[ebp+28h] /
// test edi,edi / mov [ebp-10h],ecx - the first bytes this was read from.
const unsigned char kPrologue[16] = {
    0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xEC, 0x00, 0x00,
    0x00, 0x57, 0x8B, 0x7D, 0x28, 0x85, 0xFF, 0x89
};

// Emitter fields.
constexpr unsigned kE_count       = 0x0C;
constexpr unsigned kE_particles   = 0x10;
constexpr unsigned kE_colourCount = 0x1C;
constexpr unsigned kE_colours     = 0x20;

// No emitter in a measured session is known to be this large; a larger call is
// left to the client while learning rather than overrun the buffer.
constexpr uint32_t kMaxParticles = 0x8000;
constexpr uint32_t kLearnFills   = 4096;
constexpr uint32_t kResampleMask = 1023;

typedef void (__fastcall *FillFn)(void* self, void* edx, uint8_t* dst,
                                  const uint8_t* colour, const float* scroll,
                                  const uint8_t* colour2, const float* offset,
                                  uint32_t wrap, uint32_t arg18, int32_t start,
                                  int32_t count);
FillFn g_orig = nullptr;

bool g_installed = false;
bool g_dead = false;
bool g_abSubject = false;
uint8_t* g_scratch = nullptr;

// Main thread only, so plain. Lower bounds if that ever stops being true.
unsigned long long g_calls = 0;
unsigned long long g_filled = 0;
unsigned long long g_particles = 0;
unsigned long long g_wrapPath = 0;
unsigned long long g_gatePath = 0;
unsigned long long g_control = 0;
unsigned long long g_tooLarge = 0;
unsigned g_verified = 0;
unsigned g_mismatches = 0;
uint32_t g_largest = 0;

struct Plan {
    const uint8_t* src;
    const uint8_t* colour;
    size_t         colourStride;
    int32_t        count;
};

static inline uint32_t SwapRB(uint32_t c) {
    return (c & 0xFF00FF00u) | ((c >> 16) & 0xFFu) | ((c & 0xFFu) << 16);
}

void Fill(const Plan& p, const float* offset, uint8_t* dst) {
    const uintptr_t device = *(const uintptr_t*)kDevicePtr;
    const bool swap = (device != 0) && (*(const int32_t*)(device + 0x214 + 0x14) == 1);
    const __m128 off = _mm_setr_ps(offset[0], offset[1], offset[2], 0.0f);
    const uint8_t* src = p.src;
    int32_t count = p.count;

    if (p.colourStride == 0) {
        uint32_t c = 0;
        if (p.colour) {
            memcpy(&c, p.colour, 4);
        }
        if (swap) c = SwapRB(c);

        while (count >= 2) {
            __m128 p0 = _mm_loadu_ps((const float*)src);
            __m128 p1 = _mm_loadu_ps((const float*)(src + 20));
            __m128 s0 = _mm_add_ps(p0, off);
            __m128 s1 = _mm_add_ps(p1, off);

            _mm_storeu_ps((float*)dst, s0);
            memcpy(dst + 12, &c, 4);
            memcpy(dst + 16, src + 12, 8);

            _mm_storeu_ps((float*)(dst + 24), s1);
            memcpy(dst + 36, &c, 4);
            memcpy(dst + 40, src + 32, 8);

            src += 40;
            dst += 48;
            count -= 2;
        }

        if (count > 0) {
            __m128 p0 = _mm_loadu_ps((const float*)src);
            __m128 s0 = _mm_add_ps(p0, off);
            _mm_storeu_ps((float*)dst, s0);
            memcpy(dst + 12, &c, 4);
            memcpy(dst + 16, src + 12, 8);
        }
    } else {
        const uint8_t* col = p.colour;
        if (swap) {
            while (count >= 2) {
                __m128 p0 = _mm_loadu_ps((const float*)src);
                __m128 p1 = _mm_loadu_ps((const float*)(src + 20));
                __m128 s0 = _mm_add_ps(p0, off);
                __m128 s1 = _mm_add_ps(p1, off);

                uint32_t c0 = 0, c1 = 0;
                if (col) {
                    memcpy(&c0, col, 4);
                    memcpy(&c1, col + 4, 4);
                }
                c0 = SwapRB(c0);
                c1 = SwapRB(c1);

                _mm_storeu_ps((float*)dst, s0);
                memcpy(dst + 12, &c0, 4);
                memcpy(dst + 16, src + 12, 8);

                _mm_storeu_ps((float*)(dst + 24), s1);
                memcpy(dst + 36, &c1, 4);
                memcpy(dst + 40, src + 32, 8);

                src += 40;
                col += 8;
                dst += 48;
                count -= 2;
            }

            if (count > 0) {
                __m128 p0 = _mm_loadu_ps((const float*)src);
                __m128 s0 = _mm_add_ps(p0, off);
                uint32_t c0 = 0;
                if (col) memcpy(&c0, col, 4);
                c0 = SwapRB(c0);
                _mm_storeu_ps((float*)dst, s0);
                memcpy(dst + 12, &c0, 4);
                memcpy(dst + 16, src + 12, 8);
            }
        } else {
            while (count >= 2) {
                __m128 p0 = _mm_loadu_ps((const float*)src);
                __m128 p1 = _mm_loadu_ps((const float*)(src + 20));
                __m128 s0 = _mm_add_ps(p0, off);
                __m128 s1 = _mm_add_ps(p1, off);

                _mm_storeu_ps((float*)dst, s0);
                if (col) memcpy(dst + 12, col, 4);
                memcpy(dst + 16, src + 12, 8);

                _mm_storeu_ps((float*)(dst + 24), s1);
                if (col) memcpy(dst + 36, col + 4, 4);
                memcpy(dst + 40, src + 32, 8);

                src += 40;
                col += 8;
                dst += 48;
                count -= 2;
            }

            if (count > 0) {
                __m128 p0 = _mm_loadu_ps((const float*)src);
                __m128 s0 = _mm_add_ps(p0, off);
                _mm_storeu_ps((float*)dst, s0);
                if (col) memcpy(dst + 12, col, 4);
                memcpy(dst + 16, src + 12, 8);
            }
        }
    }
}

// Out of line on purpose: its message buffer would otherwise put a stack
// cookie check into the prologue of the hook, which runs for every fill.
__declspec(noinline) void Compare(int32_t totalWritten, const uint8_t* client) {
    for (int32_t i = 0; i < totalWritten; ++i) {
        const uint8_t* a = client + 24 * (size_t)i;
        const uint8_t* b = g_scratch + 24 * (size_t)i;
        if (memcmp(a, b, 24) == 0) continue;
        char what[160] = "";
        for (int f = 0; f < 24; f += 4) {
            uint32_t ca = 0, cb = 0;
            memcpy(&ca, a + f, 4);
            memcpy(&cb, b + f, 4);
            if (ca != cb) {
                _snprintf(what, sizeof(what) - 1, "particle %d of %d, bytes +%d: "
                          "client %08X, prediction %08X", i, totalWritten, f, ca, cb);
                break;
            }
        }
        what[sizeof(what) - 1] = '\0';
        ++g_mismatches;
        g_dead = true;
        Log("[ParticleFill] DISABLED for this session: a fill came out differently "
            "from the client's own loop - %s. The client's bytes are the ones in the "
            "buffer; every fill from here on is left to the client.", what);
        Verdict::Add(Verdict::Bad, "ParticleFill predicted particle vertices that "
                     "differed from what the client wrote and retired itself for this "
                     "session");
        return;
    }
    ++g_verified;
}

int32_t RunFillPipeline(uintptr_t e, int32_t n, bool hasColourArray,
                        const uint8_t* colour, const float* scroll,
                        const uint8_t* colour2, const float* offset,
                        uint32_t wrap, int32_t start, int32_t count,
                        uint8_t* target_dst) {
    const uint8_t* const particle_base = *(const uint8_t* const*)(e + kE_particles);
    const uint8_t* const colour_base   = *(const uint8_t* const*)(e + kE_colours);

    int32_t cur_start = start;
    int32_t cur_count = count;
    uint8_t* cur_dst = target_dst;
    int32_t written = 0;

    if ((wrap & 0xFF) != 0) {
        if (cur_start < n) {
            int32_t avail = n - cur_start;
            int32_t take1 = (cur_count < avail) ? cur_count : avail;

            typedef double (__cdecl *ScrollFloorFn)(int mode, float val);
            const ScrollFloorFn fn_6C0B20 = (ScrollFloorFn)0x006C0B20;
            const ScrollFloorFn fn_6C0B60 = (ScrollFloorFn)0x006C0B60;

            float wrap_off[3];
            wrap_off[0] = offset[0] + (float)floor(fn_6C0B60(0, scroll ? scroll[0] : 0.0f));
            wrap_off[1] = offset[1] + (float)floor(fn_6C0B20(0, scroll ? scroll[1] : 0.0f));
            wrap_off[2] = offset[2];

            Plan p1;
            p1.src = particle_base + (intptr_t)cur_start * 20;
            p1.count = take1;
            p1.colour = colour2 ? colour2 : colour;
            p1.colourStride = 0;

            Fill(p1, wrap_off, cur_dst);

            cur_count -= take1;
            cur_dst   += 24 * (size_t)take1;
            cur_start += take1;
            written   += take1;
            if (cur_start >= n) cur_start = 0;
        } else {
            cur_start -= n;
        }
    }

    if (cur_count > 0 && cur_start < n) {
        int32_t avail = n - cur_start;
        int32_t take2 = (cur_count < avail) ? cur_count : avail;

        Plan p2;
        p2.src = particle_base + (intptr_t)cur_start * 20;
        p2.count = take2;
        p2.colour = colour;
        p2.colourStride = 0;
        if (hasColourArray) {
            p2.colour = colour_base + (intptr_t)cur_start * 4;
            p2.colourStride = 4;
        }

        Fill(p2, offset, cur_dst);
        written += take2;
    }

    return written;
}

void __fastcall Hooked_Fill(void* self, void* edx, uint8_t* dst, const uint8_t* colour,
                            const float* scroll, const uint8_t* colour2,
                            const float* offset, uint32_t wrap, uint32_t arg18,
                            int32_t start, int32_t count) {
    ++g_calls;
    if (g_dead || *(const uint8_t*)kGateByte != 0) {
        if (!g_dead) ++g_gatePath;
        g_orig(self, edx, dst, colour, scroll, colour2, offset, wrap, arg18, start, count);
        return;
    }

    const uintptr_t e = (uintptr_t)self;
    const int32_t n = *(const int32_t*)(e + kE_count);
    if (n <= 0 || count <= 0 || start < 0) {
        return;
    }

    const int32_t colourCount = *(const int32_t*)(e + kE_colourCount);
    const bool hasColourArray = (colourCount != 0 && colourCount == n);

    // If wrapped with alpha modulation, fall back to stock client verbatim
    if ((wrap & 0xFF) != 0 && ((arg18 & 0xFF) != 0 && hasColourArray)) {
        ++g_wrapPath;
        g_orig(self, edx, dst, colour, scroll, colour2, offset, wrap, arg18, start, count);
        return;
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_control;
        g_orig(self, edx, dst, colour, scroll, colour2, offset, wrap, arg18, start, count);
        return;
    }

    if ((uint32_t)count > g_largest) g_largest = (uint32_t)count;

    const bool learning = g_verified < kLearnFills ||
                          ((uint32_t)g_calls & kResampleMask) == 0;
    if (learning) {
        if ((uint32_t)count > kMaxParticles) {
            ++g_tooLarge;
            g_orig(self, edx, dst, colour, scroll, colour2, offset, wrap, arg18, start, count);
            return;
        }
        int32_t predicted = RunFillPipeline(e, n, hasColourArray, colour, scroll, colour2,
                                            offset, wrap, start, count, g_scratch);
        g_orig(self, edx, dst, colour, scroll, colour2, offset, wrap, arg18, start, count);
        Compare(predicted, dst);
        return;
    }

    int32_t filled = RunFillPipeline(e, n, hasColourArray, colour, scroll, colour2,
                                     offset, wrap, start, count, dst);
    ++g_filled;
    g_particles += (unsigned long long)filled;
}

bool BytesMatch(uintptr_t addr, const unsigned char* want, int n) {
    __try {
        return memcmp((const void*)addr, want, (size_t)n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

bool Init() {
    if (!Config::g_settings.OptParticleFill) return true;

    if (!BytesMatch(kTarget, kPrologue, sizeof(kPrologue))) {
        Log("[ParticleFill] NOT active: the bytes at 0x%08X are not the particle fill "
            "this was read from, so nothing was hooked.", (unsigned)kTarget);
        return false;
    }
    if (!WowOpt_ClientPatchAllowed((const void*)kTarget)) {
        Log("[ParticleFill] NOT active: No Client Patches is on, and this hooks a "
            "function inside wow.exe.");
        return false;
    }

    // Without the scratch the verification cannot run, and without the
    // verification this does not hook.
    g_scratch = (uint8_t*)VirtualAlloc(nullptr, (SIZE_T)kMaxParticles * 24,
                                       MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                       PAGE_READWRITE);
    if (!g_scratch) {
        Log("[ParticleFill] NOT active: the %u KB verification buffer could not be "
            "committed, error %lu", (unsigned)((SIZE_T)kMaxParticles * 24 / 1024),
            GetLastError());
        return false;
    }

    if (WineSafe_CreateHook((void*)kTarget, (void*)&Hooked_Fill, (void**)&g_orig) != MH_OK) {
        Log("[ParticleFill] NOT active: the hook on 0x%08X could not be created.",
            (unsigned)kTarget);
        return false;
    }
    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        MH_RemoveHook((void*)kTarget);
        Log("[ParticleFill] NOT active: the hook on 0x%08X could not be enabled.",
            (unsigned)kTarget);
        return false;
    }
    g_installed = true;
    g_abSubject = AbTest::IsSubject("ParticleFill", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("ParticleFill_Hook", (const void*)&Hooked_Fill);

    Log("[ParticleFill] ACTIVE on the particle vertex fill in sub_6C4440 (2.5%% of "
        "self time in the corrected combat profile). Vectorized dual-stream SSE2 filling, "
        "hoisted single-colour swap, and accelerated wrapping path with bit-exact "
        "dual-run verification.");
    if (g_abSubject)
        Log("[ParticleFill]   under A/B test: the control half calls the client's "
            "function through the same hook, so both halves pay for the hook and only "
            "the fill differs.");
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook((void*)kTarget);
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptParticleFill) return;
    if (!g_installed) {
        Log("[ParticleFill] not installed - the reason is at the top of this log");
        return;
    }
    if (g_calls == 0) {
        Log("[ParticleFill] hooked, and no particle fill has been reached yet. That is "
            "a measurement: no emitter has drawn since it went in.");
        return;
    }
    Log("[ParticleFill] %llu fill(s) reached the hook; %llu filled here (%llu particles); "
        "largest %u particles. %llu bypassed (modulated wrap), %llu matrix transformed.",
        g_calls, g_filled, g_particles, g_largest, g_wrapPath, g_gatePath);
    if (g_mismatches) {
        Log("[ParticleFill]   DISABLED after a difference from the client's own output; "
            "the line that says where is earlier in this log.");
    } else if (g_verified < kLearnFills) {
        Log("[ParticleFill]   %u of %u fills verified against the client so far; still "
            "leaving every fill to the client and comparing.", g_verified, kLearnFills);
    } else {
        Log("[ParticleFill]   %u fills verified byte for byte against the client, none "
            "differed; one in %u is still compared.", g_verified, kResampleMask + 1);
    }
    if (g_tooLarge)
        Log("[ParticleFill]   %llu fill(s) were larger than the verification buffer and "
            "were left to the client.", g_tooLarge);
    if (g_abSubject)
        Log("[ParticleFill]   %llu fill(s) went through the client's function as the A/B "
            "control half.", g_control);
}

}  // namespace ParticleFill
