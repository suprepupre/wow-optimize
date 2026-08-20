#include "spell_effect_culling.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include <atomic>
#include <cmath>

extern "C" void Log(const char* fmt, ...);

namespace SpellEffectCulling {

    static bool g_enabled = false;

    // ---- Particle Spawn Counter ----
    // We hook the per-particle spawn function to count spawns per frame.
    // sub_97D820 is __thiscall: this + (float a2, int a3)
    typedef int (__thiscall *ParticleSpawn_fn)(void* thisPtr, float dt, int matrix);
    static ParticleSpawn_fn orig_ParticleSpawn = nullptr;

    // Plain, not atomic. Particle spawn is a main-thread path and so is the
    // frame boundary that reads and clears this, so there is no race to protect
    // against - and a lock xadd on every particle spawned is a real cost in the
    // one situation this feature exists for, a screen full of spell effects.
    static int g_frameSpawnCount = 0;
    static int g_lastFrameSpawnCount = 0;

    // ---- Density Getter Hook ----
    // sub_980ED0 returns flt_B2D678 (the particleDensity CVar value).
    // It is a simple __cdecl function: double sub_980ED0()
    typedef double (__cdecl *DensityGetter_fn)();
    static DensityGetter_fn orig_DensityGetter = nullptr;

    // The scale factor we apply to the native density value (0.1 - 1.0)
    static float g_scaleFactor = 1.0f;
    static float g_smoothedScale = 1.0f;

    // ---- Hooked Functions ----

    static int __fastcall Hooked_ParticleSpawn(void* thisPtr, void* /*edx*/, float dt, int matrix) {
        ++g_frameSpawnCount;
        return orig_ParticleSpawn(thisPtr, dt, matrix);
    }

    static double __cdecl Hooked_DensityGetter() {
        double nativeDensity = orig_DensityGetter();
        return nativeDensity * (double)g_smoothedScale;
    }

    // ---- Lifecycle ----

    bool Init() {
        if (!Config::g_settings.OptSpellEffectCulling) {
            g_enabled = false;
            return true;
        }

        Log("[SpellEffectCulling] Initializing Spell Effect Particle Culling...");

        // Hook sub_980ED0 - particle density getter
        void* target_DensityGetter = (void*)0x00980ED0;
        if (WineSafe_CreateHook(target_DensityGetter, (void*)Hooked_DensityGetter, (void**)&orig_DensityGetter) != MH_OK) {
            Log("[SpellEffectCulling] Failed to hook DensityGetter (0x980ED0)");
            return false;
        }
        if (WO_EnableHook(target_DensityGetter) != MH_OK) {
            Log("[SpellEffectCulling] Failed to enable DensityGetter hook");
            return false;
        }

        // Hook sub_97D820 - per-particle spawn function
        void* target_ParticleSpawn = (void*)0x0097D820;
        if (WineSafe_CreateHook(target_ParticleSpawn, (void*)Hooked_ParticleSpawn, (void**)&orig_ParticleSpawn) != MH_OK) {
            Log("[SpellEffectCulling] Failed to hook ParticleSpawn (0x97D820)");
            return false;
        }
        if (WO_EnableHook(target_ParticleSpawn) != MH_OK) {
            Log("[SpellEffectCulling] Failed to enable ParticleSpawn hook");
            return false;
        }

        g_enabled = true;
        Log("[SpellEffectCulling] ACTIVE (Dynamic particle density scaling based on spawn pressure)");
        Log("[SpellEffectCulling]   Thresholds: <2000=100%%, 2000-4000=75%%, 4000-6000=50%%, 6000-8000=25%%, >8000=10%%");
        return true;
    }

    void Shutdown() {
        if (!g_enabled) return;

        MH_DisableHook((void*)0x00980ED0);
        MH_DisableHook((void*)0x0097D820);

        Log("[SpellEffectCulling] Shutdown");
    }

    void OnFrame() {
        if (!g_enabled) return;

        // Snapshot the spawn count from last frame and reset
        int spawns = g_frameSpawnCount;
        g_frameSpawnCount = 0;
        g_lastFrameSpawnCount = spawns;

        // Compute target scale factor based on spawn pressure
        float target;
        if (spawns < 2000) {
            target = 1.0f;       // Normal: no reduction
        } else if (spawns < 4000) {
            target = 0.75f;      // Moderate load
        } else if (spawns < 6000) {
            target = 0.50f;      // Heavy load
        } else if (spawns < 8000) {
            target = 0.25f;      // Very heavy load
        } else {
            target = 0.10f;      // Emergency minimum
        }

        g_scaleFactor = target;

        // Exponential moving average for smooth transitions (avoid particle pop-in/out)
        // Blend factor: 0.15 = reasonably responsive but visually smooth
        g_smoothedScale = g_smoothedScale * 0.85f + g_scaleFactor * 0.15f;

        // Clamp to sane range
        if (g_smoothedScale < 0.10f) g_smoothedScale = 0.10f;
        if (g_smoothedScale > 1.0f)  g_smoothedScale = 1.0f;

        // Log significant density changes (but not every frame to avoid spam)
        static int logThrottle = 0;
        static float lastLoggedScale = 1.0f;
        if (++logThrottle >= 300) { // every ~5 seconds at 60fps
            logThrottle = 0;
            if (std::abs(g_smoothedScale - lastLoggedScale) > 0.05f || g_smoothedScale < 0.9f) {
                Log("[SpellEffectCulling] spawns/frame=%d scale=%.0f%% (smoothed=%.0f%%)",
                    spawns, g_scaleFactor * 100.0f, g_smoothedScale * 100.0f);
                lastLoggedScale = g_smoothedScale;
            }
        }
    }

} // namespace SpellEffectCulling
