// ============================================================================
// Module: particle_emitter_active.cpp
//
// Accelerates particle emitter hierarchy activity detection in sub_97B9E0
// (68 bytes / 0x44). Sampled up to 8,803 times per snapshot (~1.0-1.5% of
// frame time during intense particle scenes and M2 model updates).
//
// sub_97B9E0 is a pure read-only boolean predicate:
//   __thiscall int sub_97B9E0(void); (ecx = this)
//
// Client behavior:
//   1. Checks if *(uint32_t*)(this + 0x50) != 0. If non-zero, returns 1.
//   2. Otherwise reads childCount at *(uint32_t*)(this + 0x6C).
//      If childCount == 0, returns 0.
//   3. For childCount > 0, reads child pointer array at (this + 0x70) and
//      recursively calls sub_97B9E0 on each child. Returns 1 on first active child.
//      Returns 0 if all children inactive.
//
// This replacement provides:
//   - Immediate fast-path return for active roots and childless leaf roots.
//   - Flattened iterative depth-first traversal with a safe 32-entry stack.
//   - Inlined child active checks before pushing to stack.
//   - Zero recursive stack frame setup and zero function call overhead.
//   - Zero /GS stack security cookies via __declspec(safebuffers).
//   - Zero SEH frame overhead.
//
// Verification:
//   Dual-runs against client sub_97B9E0 for the first 10,000 calls and
//   1 in every 128 calls thereafter; retires immediately on first mismatch.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "particle_emitter_active.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);

namespace ParticleEmitterActive {

namespace {

typedef int (__thiscall *OrigFn)(const void* thisPtr);
static OrigFn g_orig = nullptr;

static bool g_installed = false;
static bool g_dead = false;
static bool g_abSubject = false;

static uint64_t g_calls = 0;
static uint64_t g_armedCalls = 0;
static uint64_t g_verifiedCalls = 0;
static uint64_t g_controlCalls = 0;
static uint64_t g_overflowCalls = 0;   // left to the client: deeper than the stack here
static uint32_t g_mismatches = 0;

static const uintptr_t kTarget = 0x0097B9E0;
static const uint8_t kPrologue[8] = {
    0x83, 0x79, 0x50, 0x00, 0x74, 0x06, 0xB8, 0x01
};

// -1 when the hierarchy has more pending branches than the 32-entry stack holds. A
// branch left unvisited could be the active one, so the caller hands such a call to
// the client's recursive routine instead of answering "inactive".
__declspec(safebuffers) static inline int Fast_HasActiveParticles(const void* root) {
    if (!root) return 0;
    const char* p = (const char*)root;
    if (*(const uint32_t*)(p + 0x50) != 0) return 1;

    uint32_t count = *(const uint32_t*)(p + 0x6C);
    if (count == 0) return 0;

    const void* stack[32];
    int top = 0;
    const void* const* children = (const void* const*)(p + 0x70);

    for (uint32_t i = 0; i < count; ++i) {
        const char* child = (const char*)children[i];
        if (child) {
            if (*(const uint32_t*)(child + 0x50) != 0) return 1;
            if (*(const uint32_t*)(child + 0x6C) != 0) {
                if (top >= 32) return -1;
                stack[top++] = child;
            }
        }
    }

    while (top > 0) {
        const char* cur = (const char*)stack[--top];
        count = *(const uint32_t*)(cur + 0x6C);
        children = (const void* const*)(cur + 0x70);
        for (uint32_t i = 0; i < count; ++i) {
            const char* child = (const char*)children[i];
            if (child) {
                if (*(const uint32_t*)(child + 0x50) != 0) return 1;
                if (*(const uint32_t*)(child + 0x6C) != 0) {
                    if (top >= 32) return -1;
                    stack[top++] = child;
                }
            }
        }
    }

    return 0;
}

__declspec(safebuffers) static int __fastcall Hook_sub_97B9E0(const void* thisPtr, void* edxUnused) {
    (void)edxUnused;
    if (g_dead) {
        return g_orig(thisPtr);
    }

    g_calls++;

    if (g_abSubject && AbTest::StandAside()) {
        g_controlCalls++;
        return g_orig(thisPtr);
    }

    // Verify first 10,000 calls, then sample 1 in 128
    const bool verifyThisCall = (g_verifiedCalls < 10000) || ((g_calls & 0x7F) == 0);
    if (!verifyThisCall) {
        const int armed = Fast_HasActiveParticles(thisPtr);
        if (armed < 0) {
            g_overflowCalls++;
            return g_orig(thisPtr);
        }
        g_armedCalls++;
        return armed;
    }

    g_verifiedCalls++;
    const int clientRes = g_orig(thisPtr);
    const int fastRes = Fast_HasActiveParticles(thisPtr);

    if (fastRes < 0) {
        g_overflowCalls++;
        return clientRes;
    }
    if (clientRes != fastRes) {
        g_mismatches++;
        g_dead = true;
        Log("[ParticleEmitterActive] Disagreement at this=%p: client=%d fast=%d",
            thisPtr, clientRes, fastRes);
        return clientRes;
    }

    return clientRes;
}

} // anonymous namespace

bool Init() {
    if (!Config::g_settings.OptParticleEmitterActive) {
        return false;
    }

    if (memcmp((const void*)kTarget, kPrologue, sizeof(kPrologue)) != 0) {
        Log("[ParticleEmitterActive] NOT active: prologue mismatch at 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (!WowOpt_ClientPatchAllowed((const void*)kTarget)) {
        Log("[ParticleEmitterActive] NOT active: client patches not allowed");
        return false;
    }

    if (WineSafe_CreateHook((void*)kTarget, (void*)&Hook_sub_97B9E0, (void**)&g_orig) != MH_OK) {
        Log("[ParticleEmitterActive] NOT active: CreateHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    if (WO_EnableHook((void*)kTarget) != MH_OK) {
        MH_RemoveHook((void*)kTarget);
        Log("[ParticleEmitterActive] NOT active: EnableHook failed on 0x%08X", (unsigned)kTarget);
        return false;
    }

    g_installed = true;
    g_abSubject = AbTest::IsSubject("ParticleEmitterActive", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("ParticleEmitterActive_Hook", (const void*)&Hook_sub_97B9E0);

    Log("[ParticleEmitterActive] Hook installed on sub_97B9E0 (68 bytes)");
    return true;
}

void Shutdown() {
    if (g_installed) {
        MH_DisableHook((void*)kTarget);
        MH_RemoveHook((void*)kTarget);
        g_installed = false;
    }
}

void LogStats() {
    if (!g_installed) {
        return;
    }

    Log("[ParticleEmitterActive] calls=%llu (armed=%llu, verified=%llu, control=%llu, "
        "left to the client as deeper than the stack here=%llu) mismatches=%u%s",
        (unsigned long long)g_calls,
        (unsigned long long)g_armedCalls,
        (unsigned long long)g_verifiedCalls,
        (unsigned long long)g_controlCalls,
        (unsigned long long)g_overflowCalls,
        g_mismatches,
        g_dead ? " [RETIRED]" : "");
}

} // namespace ParticleEmitterActive
