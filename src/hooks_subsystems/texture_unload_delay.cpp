#include "texture_unload_delay.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include <vector>
#include <unordered_set>
#include <string>
#include "win_mutex.h"
#include "../allocators/loading_defrag.h"
#include "../runtime_vm/lua_optimize.h"

extern "C" void Log(const char* fmt, ...);
extern DWORD g_mainThreadId;

namespace TextureUnloadDelay {
    static bool g_enabled = false;
    static thread_local bool g_isReleasing = false;
    static WinMutex g_textureLock;
    static volatile DWORD g_lastTransitionEndTick = 0;

    struct DelayedTexture {
        void* ptr;
        DWORD timestamp;
    };

    static std::vector<DelayedTexture> g_delayedQueue;

    // Membership set for g_delayedQueue, kept in step with it under the same lock.
    //
    // The duplicate check used to be a linear walk of the queue, on the main
    // thread, on every single texture release. Nothing bounded the queue, so the
    // walk grew with it and releasing n textures cost on the order of n squared -
    // in a zone that churns textures, the hottest function in the module got
    // slower the more work there was to do.
    static std::unordered_set<void*> g_queued;

    // The queue is a delay, not a cache: anything still in it after five seconds
    // is released anyway. A cap only decides what happens under a burst larger
    // than the sweep can carry, and releasing immediately is the right answer
    // there - it is what the client would have done without us.
    static constexpr size_t MAX_DELAYED = 4096;

    // The point of the delay is that a texture released and then wanted again
    // shortly afterwards never gets destroyed and rebuilt. Nothing counted how
    // often that actually happened, so there has never been an answer to whether
    // the feature earns the hook it installs on the client's hottest release
    // path. g_reused is that answer.
    static volatile long g_overflowReleases = 0;
    static volatile long g_queuedTotal      = 0;
    static volatile long g_reused           = 0;   // wanted again before the TTL
    static volatile long g_expired          = 0;   // released after the TTL
    static volatile long g_bypassed         = 0;

// Set once the measured reuse rate says holding textures is not worth the
// memory. See the note at the queue site.
static bool g_selfDisabled = false;
static constexpr long SELF_CHECK_AFTER = 20000;   // decided releases before judging

    static bool IsBypassActive() {
        DWORD now = GetTickCount();
        // A transition ended recently, so let the engine free things itself while
        // the load path is still tearing down and rebuilding.
        bool postTransitionGrace = (g_lastTransitionEndTick != 0 &&
                                    (now - g_lastTransitionEndTick) < 10000);
        DWORD swapTick = LuaOpt::GetLastSwapTick();
        bool postSwapGrace = (swapTick != 0 && (now - swapTick) < 10000);

        return LoadingDefrag::IsLoadingActive() ||
               LuaOpt::IsLoadingMode() ||
               LuaOpt::IsReloading() ||
               LuaOpt::IsSwapping() ||
               postTransitionGrace ||
               postSwapGrace;
    }

    // Hook Target Types
    // Texture_Release (sub_47BF30) decrements refcount at offset 4
    typedef int (__cdecl *Texture_Release_fn)(void* Block);
    static Texture_Release_fn orig_Texture_Release = nullptr;

    static void ReleaseTexture(void* ptr) {
        g_isReleasing = true;
        __try {
            orig_Texture_Release(ptr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[TextureUnloadDelay] Exception during texture release of 0x%p", ptr);
        }
        g_isReleasing = false;
    }

    // Detour for Texture Release
    int __cdecl Hooked_Texture_Release(void* Block) {
        if (!Block) return 0;

        if (!g_enabled || g_isReleasing || GetCurrentThreadId() != g_mainThreadId)
            return orig_Texture_Release(Block);

        // This branch used to call Flush() - on the main thread, for every
        // release, while a transition was in progress or within ten seconds of
        // one. Flush() stamps g_lastTransitionEndTick, and that stamp is what
        // decides the ten-second window, so calling it from here kept renewing
        // the very window that had brought us here. Any game releases a texture
        // at least once every ten seconds, so after the first loading screen the
        // window never closed again: the feature spent the rest of the session
        // switched off while still paying for the hook, the state queries and a
        // mutex acquisition on every release.
        //
        // Flush now happens only where a transition genuinely begins or ends,
        // which is where it was always called from anyway.
        if (IsBypassActive()) {
            InterlockedIncrement(&g_bypassed);
            return orig_Texture_Release(Block);
        }

        // Refcount is at offset 4 in HTEXTURE. Anything above one is still owned
        // by the engine and none of our business.
        int* refCount = (int*)((char*)Block + 4);
        if (*refCount != 1)
            return orig_Texture_Release(Block);

        // Stop holding textures once the feature has measured itself useless.
        //
        // The whole premise is that a texture released now is often wanted again
        // shortly, so holding it for five seconds saves a reload. Two testers
        // have now measured that:
        //
        //     784051 queued, 1631 reused before TTL (0.2%), 780792 expired
        //     (an earlier session on another machine: 0.4%)
        //
        // Three quarters of a million textures held to save sixteen hundred
        // reloads. That is not a cache, it is a memory leak with a timer - and
        // the session those numbers come from had a 32-bit process at a 2.4 GB
        // working set, freezing for a second at a time.
        //
        // So it now stops after a large enough sample says it is not paying.
        // Anything already queued still expires normally through Flush; this
        // only stops adding more. A feature that measures itself and gives up is
        // better than one that has to be found in a log and switched off by
        // hand, and this one has now been found twice.
        if (!g_selfDisabled) {
            long q = g_queuedTotal, r = g_reused, e = g_expired;
            long decided = r + e;
            if (decided >= SELF_CHECK_AFTER && (double)r < 0.01 * (double)decided) {
                g_selfDisabled = true;
                Log("[TextureUnloadDelay] Reuse is %.2f%% over %ld decided releases - "
                    "holding textures is not paying for itself, so it stops here. "
                    "Queued %ld in total; the ones still held expire normally.",
                    100.0 * (double)r / (double)decided, decided, q);
            }
        }
        if (g_selfDisabled)
            return orig_Texture_Release(Block);

        bool queued = false;
        {
            WinLockGuard lock(g_textureLock);
            if (g_delayedQueue.size() < MAX_DELAYED && g_queued.insert(Block).second) {
                DelayedTexture entry;
                entry.ptr = Block;
                entry.timestamp = GetTickCount();
                g_delayedQueue.push_back(entry);
                InterlockedIncrement(&g_queuedTotal);
                queued = true;
            } else if (g_delayedQueue.size() >= MAX_DELAYED) {
                InterlockedIncrement(&g_overflowReleases);
            }
        }

        // Held the texture back, so the refcount stays at 1 and the engine keeps
        // it. Never call through while holding the lock - a release can re-enter
        // this hook and can block on a worker thread.
        if (queued) return 0;

        return orig_Texture_Release(Block);
    }

    bool Init() {
        if (!Config::g_settings.OptTextureUnloadDelay) {
            g_enabled = false;
            return true;
        }

        Log("[TextureUnloadDelay] Initializing Texture Smart Unload Delay...");

        void* target_Release = (void*)0x0047BF30;

        if (WineSafe_CreateHook(target_Release, (void*)Hooked_Texture_Release, (void**)&orig_Texture_Release) != MH_OK) {
            Log("[TextureUnloadDelay] Failed to hook Texture Release");
            return false;
        }

        if (WO_EnableHook(target_Release) != MH_OK) {
            Log("[TextureUnloadDelay] Failed to enable hooks");
            return false;
        }

        g_enabled = true;
        Log("[TextureUnloadDelay] ACTIVE (Delayed release queue, TTL: 5000ms)");
        return true;
    }

    void Shutdown() {
        if (!g_enabled) return;
        
        void* target_Release = (void*)0x0047BF30;
        MH_DisableHook(target_Release);
        
        Flush();
        
        Log("[TextureUnloadDelay] Shutdown - All delayed textures cleaned up");
    }

    // Called at the two points a transition begins or ends, and at shutdown.
    // Stamping the tick here is what opens the ten-second grace window; nothing
    // on the per-release path may do it, or the window never closes.
    void Flush() {
        if (!g_enabled) return;

        g_lastTransitionEndTick = GetTickCount();

    // Release a bounded number here, not the whole queue.
    //
    // Flush runs at both ends of a loading transition, on the main thread, and
    // it used to hand every held texture to the engine in one go. A tester
    // reported the loading bar completing and then the screen sitting there for
    // several seconds before the new scene appeared, and their log has a
    // thousand textures held at the moment the transition ended. That burst is
    // the stall.
    //
    // It only started happening because this feature began working: until the
    // self-disabling bug was fixed the queue was always empty here and the flush
    // cost nothing. Whatever is left stays queued and goes out through the
    // ordinary five-second sweep in OnFrame, a few per frame, which is where
    // this work belongs.
    static constexpr size_t FLUSH_BUDGET = 128;

        std::vector<void*> toRelease;
        {
            WinLockGuard lock(g_textureLock);
            size_t take = g_delayedQueue.size() < FLUSH_BUDGET
                        ? g_delayedQueue.size() : FLUSH_BUDGET;
            toRelease.reserve(take);
            for (size_t i = 0; i < take; ++i) {
                toRelease.push_back(g_delayedQueue[i].ptr);
                g_queued.erase(g_delayedQueue[i].ptr);
            }
            g_delayedQueue.erase(g_delayedQueue.begin(),
                                 g_delayedQueue.begin() + (ptrdiff_t)take);
        }

        for (void* ptr : toRelease) {
            ReleaseTexture(ptr);
        }
    }

    // Printed from the periodic report. Shutdown does not run - the DLL exits via
    // TerminateProcess - so anything reported only from there is never seen.
    void LogStats() {
        if (!g_enabled) return;
        long q = g_queuedTotal, r = g_reused, e = g_expired;
        long decided = r + e;
        size_t inQueue;
        {
            WinLockGuard lock(g_textureLock);
            inQueue = g_delayedQueue.size();
        }
        Log("[TextureUnloadDelay] %ld queued, %ld reused before TTL (%.1f%% of %ld decided), "
            "%ld expired, %ld bypassed, %ld overflowed, %llu held now",
            q, r, decided > 0 ? (100.0 * r / decided) : 0.0, decided,
            e, g_bypassed, g_overflowReleases, (unsigned long long)inQueue);
    }

    void Discard() {
        if (!g_enabled) return;
        WinLockGuard lock(g_textureLock);
        g_delayedQueue.clear();
        g_queued.clear();
        Log("[TextureUnloadDelay] Queue discarded without release (device change/reset)");
    }

    void OnFrame() {
        if (!g_enabled) return;
        
        DWORD now = GetTickCount();
        std::vector<void*> toRelease;
        
        {
            WinLockGuard lock(g_textureLock);
            // erase() from the middle of a vector shifts every later element, so
            // a sweep that drops many entries copies the tail once per drop.
            // Compacting in one pass keeps the sweep linear however much it
            // takes out.
            size_t keep = 0;
            for (size_t i = 0; i < g_delayedQueue.size(); ++i) {
                const DelayedTexture& e = g_delayedQueue[i];
                // A refcount above one means the engine looked the texture up
                // again and now owns it, so drop it without releasing.
                int* refCount = (int*)((char*)e.ptr + 4);
                if (*refCount > 1) {
                    InterlockedIncrement(&g_reused);
                    g_queued.erase(e.ptr);
                } else if (now - e.timestamp >= 5000) {   // 5-second grace period
                    InterlockedIncrement(&g_expired);
                    toRelease.push_back(e.ptr);
                    g_queued.erase(e.ptr);
                } else {
                    g_delayedQueue[keep++] = e;
                }
            }
            g_delayedQueue.resize(keep);
        }
        
        // Release textures OUTSIDE of the lock to prevent deadlocks with background worker threads
        for (void* ptr : toRelease) {
            ReleaseTexture(ptr);
        }
    }
}
