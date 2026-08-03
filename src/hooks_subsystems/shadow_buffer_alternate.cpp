// ============================================================================
// Module: shadow_buffer_alternate.cpp
//
// An experiment, not a fix. Read the whole note before switching it on.
//
// Two testers report shadows flickering below extShadowQuality 5. It is not
// ours - one of them reproduced it with every feature off and no DXVK - and the
// shadow state probe has now ruled out everything I suspected. Two sessions from
// the same machine, one flickering and one not:
//
//   bugged      quality=3   720 frames, suppressed 0, flag flipped 0, pass ran 720
//   not bugged  quality=5   720 frames, suppressed 0, flag flipped 0, pass ran 720
//
// Identical. The suppress flag is not oscillating, the pass is not wedged, it
// runs every single frame at both settings, and none of the four shadow function
// pointers was ever null. So the difference is not whether the pass runs - it is
// what the pass produces.
//
// In sub_875F80 there is exactly one place where quality changes the result
// rather than the amount of work:
//
//     if (v5 >= 5) v3 = byte_D4316C;   // free-running counter, +1 per pass
//     else         v3 = 0;             // always the same value
//
// and v3 is handed to dword_D43160, which begins the shadow render pass. At
// quality 5 that argument changes every frame; below 5 it is pinned at zero. A
// render target that is written and sampled in the same frame with no
// alternation is the classic way to get exactly this symptom on a driver that
// does not silently serialise for you - which is what "it flickers on my machine
// and not on yours" usually means.
//
// The instruction that makes the choice is two bytes:
//
//     00876185  7C 07        jl short loc_87618E     ; skip when quality < 5
//     00876187  0F B6 3D ..  movzx edi, byte_D4316C
//
// Replacing 7C 07 with two NOPs makes the counter be used at every quality.
//
// What I cannot prove, and why this is off by default and marked experimental:
// I have not established how many shadow buffers exist at lower qualities.
// byte_D4316C is a free-running byte, so whatever dword_D43160 does with it must
// already mask or wrap it - it cannot be a raw index into a small array even at
// quality 5. That makes the patch probably safe. Probably is not proven, and the
// failure mode if I am wrong is a bad index into render targets.
//
// So: off unless someone deliberately turns it on, to answer one question. If it
// stops the flicker, this is a real fix for a client bug and it becomes a proper
// feature. If it crashes or changes nothing, it goes.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>

#include "shadow_buffer_alternate.h"
#include "config.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

namespace ShadowBufferAlternate {

static constexpr uintptr_t ADDR_Branch = 0x00876185;
static const unsigned char EXPECTED[2] = { 0x7C, 0x07 };   // jl short +7
static const unsigned char PATCH[2]    = { 0x90, 0x90 };   // nop nop

static bool g_applied = false;
static unsigned char g_saved[2];

bool Init() {
    if (!Config::g_settings.OptShadowBufferAlternate) return true;

    unsigned char* p = (unsigned char*)ADDR_Branch;

    // Never patch bytes that are not the ones this was written against. A
    // differently-built client, or something else already here, must stop this
    // dead rather than have two bytes overwritten on a guess.
    __try {
        if (p[0] != EXPECTED[0] || p[1] != EXPECTED[1]) {
            Log("[ShadowAlt] NOT applied: expected %02X %02X at 0x%08X, found %02X %02X. "
                "This client is not the one this was worked out on.",
                EXPECTED[0], EXPECTED[1], (unsigned)ADDR_Branch, p[0], p[1]);
            return false;
        }
        g_saved[0] = p[0];
        g_saved[1] = p[1];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("[ShadowAlt] NOT applied: could not read 0x%08X", (unsigned)ADDR_Branch);
        return false;
    }

    DWORD old = 0;
    if (!VirtualProtect(p, 2, PAGE_EXECUTE_READWRITE, &old)) {
        Log("[ShadowAlt] NOT applied: VirtualProtect failed at 0x%08X",
            (unsigned)ADDR_Branch);
        return false;
    }
    p[0] = PATCH[0];
    p[1] = PATCH[1];
    VirtualProtect(p, 2, old, &old);
    FlushInstructionCache(GetCurrentProcess(), p, 2);

    g_applied = true;
    Log("[ShadowAlt] EXPERIMENT ACTIVE - the shadow pass now alternates its buffer "
        "at every quality, not only at 5. Two bytes at 0x%08X. If shadows still "
        "flicker below quality 5, this idea is wrong; if the game misbehaves, turn "
        "it off.", (unsigned)ADDR_Branch);
    return true;
}

void Shutdown() {
    if (!g_applied) return;
    unsigned char* p = (unsigned char*)ADDR_Branch;
    DWORD old = 0;
    __try {
        if (VirtualProtect(p, 2, PAGE_EXECUTE_READWRITE, &old)) {
            p[0] = g_saved[0];
            p[1] = g_saved[1];
            VirtualProtect(p, 2, old, &old);
            FlushInstructionCache(GetCurrentProcess(), p, 2);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    g_applied = false;
}

} // namespace ShadowBufferAlternate
