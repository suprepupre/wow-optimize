#pragma once
#ifndef WOW_OPT_CONFIG_H
#define WOW_OPT_CONFIG_H

namespace Config {
    // The initialisers below are not the defaults anyone actually gets. Load()
    // overwrites every one of them from GetPrivateProfileIntA, whose own default
    // argument is what applies when a key is absent from wow_opt.ini - which it
    // is for anything the launcher never writes.
    //
    // They had drifted apart on ten settings, and reading this file instead of
    // the ini call led me to state in the release notes that thirty-five removed
    // features "ran on every install". They did not: their ini-read default was
    // zero, so they were off for everyone. Keep these two in step, and when the
    // question is what a player is actually running, read Load().
    struct Settings {
        // General & Memory
        bool OptSleepPrecision = true;
        int SleepPrecisionValue = 8;
        // One log per session preserves earlier runs, which is the whole point
        // when a tester is comparing two configurations - a single overwritten
        // file keeps only the last one. Turning this off restores that older
        // behaviour for anyone who would rather not accumulate files.
        bool OptSessionLogs = true;
        // Reimplements 16 core Lua stack API functions, including the three that
        // shift values around (lua_remove, lua_insert, lua_replace). Off by
        // default: an error of one slot there moves every later argument, and the
        // logs of two testers running it are full of exactly that shape of failure.
        bool OptLuaStackFast = false;

        // Lowers shadow quality when the frame-time tail says the machine cannot
        // keep up, and puts the player's own value back when it can. Off by
        // default: it changes a graphics setting the player chose, which is worth
        // being asked for rather than assumed.
        bool OptQualityGovernor = false;
        // How many session logs to keep. The oldest beyond this are deleted at
        // startup, so the folder stops growing without anyone having to tidy it.
        int SessionLogsToKeep = 10;
        bool OptMemoryPressure = true;
        bool OptHeapCompactor = true;
        bool OptDefragLf = false;
        bool OptVulkanDXVK = false;
        bool OptTimingFix = false;
        bool OptCvarNullGuard = true; // Safe default: enabled
        // Null-callback crash in the client's device callback list. On by
        // default: on a healthy client it is one read-only pointer walk per
        // device teardown and changes nothing.
        bool OptDeviceCbGuard = true;

        // LuaOpcache gated fifty-five separate installs on its own, so a report
        // that it corrupts an addon could not be narrowed by anyone. These four
        // subdivide it and all default on, so LuaOpcache=1 behaves exactly as
        // before; turning one off removes only its group.
        bool OptLuaOpcacheTables  = true;   // table, index and global caches
        bool OptLuaOpcacheStrings = true;   // string, buffer and pattern paths
        bool OptLuaOpcacheWrites  = true;   // setters and object creation
        bool OptLuaOpcacheReads   = true;   // accessors, arg checks, debug

        // Four batches of hooks into WoW.exe that were installed unconditionally,
        // ignoring every switch in the launcher. With all switches off a log
        // still showed "[SUBSYSTEM] 98/100" and "[EXTENDED] 34/40", so "Disable
        // All (vanilla)" left about 150 detours in the client. They default ON
        // because they have always been running for everyone; turning them off
        // is now what makes the vanilla button honest.
        bool OptWowOptHooks       = true;   // 20 hooks
        bool OptWowPerfHooks      = true;   // 20 hooks
        bool OptWowExtendedHooks  = true;   // 40 features
        bool OptWowSubsystemHooks = true;   // 100 features
        // Pins timingMethod to 2 and timingTestError to 0 whatever the client
        // asks. On by default because it has shipped that way for a long time;
        // it used to have no switch at all and lived inside CvarNullGuard.
        bool OptTimingCvarPin = true;
        bool OptFrameLimiter = false;
        bool OptObjVisCache = true;
        bool OptOomGovernor = false;
        bool OptHardwareCursor = false;
        bool OptSamplingProfiler = false;
        bool OptMimallocLarge = false;
        bool OptVaArena = false;   // EXPERIMENTAL opt-in: segregated VirtualAlloc arena (anti-fragmentation)
        bool OptCompatMode = false; // Compatibility: skip aggressive CPU-priority/affinity/working-set tweaks (for VMs/HyperV where they break the connection)

        // UI & Lua
        bool OptUIFrameBatch = false;
        bool OptAddonDispatcher = false;
        bool OptUIFrameAccessorFast = false;
        bool OptFontMetricsFast = false;
        bool OptModuleHandleCache = false;
        bool OptFrameScriptDispatch = false;
        bool OptLuaNumConvFast = false;
        bool OptLuaOpcache = false;
        bool OptLuaGcCoalesce = false;
        bool OptLuaGetTimeFast = false;
        bool OptSimdMatrixTransform = false;
        bool OptAsyncTexLoader = false;
        bool OptAsyncTerrainLoader = false;
        bool OptRcuObjMgr = false;
        bool OptMipBiasGovernor = false;
        
        // Combat & Network
        bool OptCombatLogLeakFix = true; // Proven fix: extend combat log retention 300s->1800s (writes the retention CVar). Default on.
        bool OptCombatLogParser = false;
        bool OptCombatLogIncremental = false;
        bool OptEventCoalescer = false;
        // Off, and equally inert: InstallSavedVarsAsync is a three-line stub that
        // logs "Bypassed for stability" and returns true, and its Shutdown is a
        // no-op. Nothing writes SavedVariables off the main thread here.
        //
        // Both of these were turned on in a fix for what looked like the
        // 3.18.0 -> 3.18.1 regression: 3.18.1 gave real gates to switches that
        // had gated nothing, and left them defaulting off, which does silently
        // remove a feature from everyone who never wrote the key. That reasoning
        // is right and the rule still stands - it just does not apply to these
        // two, because neither has run in either version. A tester's log said so
        // plainly and I had not checked.
        bool OptSavedVarsAsync = false;
        bool OptSavedVarsPretoken = false;
        bool OptUnitAuraFast = false;
        bool OptNetworkGuidSse2 = false;
        // Caches GetItemInfo and GetSpellInfo. On by default because that is what
        // every install has already been running: ApiCache::Init was called with no
        // setting check at all. The switch named GetSpellInfoCache, which looked
        // like it controlled this, gated a different module whose Init logged
        // "DISABLED" and returned false - so a tester who turned the cache off
        // still had the hook installed. This is the cache behind the WeakAuras
        // icon that stays wrong after a talent switch.
        bool OptApiCache = true;
        // Lock-free GUID -> object lookup cache. On by default because it has
        // always been installed unconditionally - it had no setting at all - and
        // this only gives that behaviour a switch.
        bool OptGuidLookupCache = true;
        bool OptPacketOffload = false;
        // Off, and it does not matter which way it is set: the module is compiled
        // out by TEST_DISABLE_NAMEPLATE_MT, in this build and in 3.18.0, and its
        // Init logs "DISABLED (test toggle)" and returns. I briefly defaulted
        // this to on believing the gate added in 3.18.1 had taken a working
        // feature away from everyone. It had not - there was nothing there to
        // take. See the note on OptSavedVarsAsync.
        bool OptNameplateMT = false;

        // Graphics & Sound
        // Hooks luaS_newlstr, through which every Lua string in the game is
        // interned. Default off: it duplicates work the engine already does
        // (hash, bucket walk, compare) and falls through to the original on a
        // miss, so a miss costs both - and its value has never been measured.
        // Both of these had a launcher switch whose ini key nothing read, so the
        // hooks installed regardless and a tester bisecting string corruption got
        // no signal from turning them off.
        bool OptFastMemsetOpt = true;    // SSE2 memset replacement (0x0040BB80)
        bool OptFastStrnicmpOpt = true;  // SSE2 _strnicmp replacement (0x0076E780)
        bool OptLuaSNewLstrFast = false;
        bool OptStrStrSse2 = false;
        bool OptStrCatFast = false;
        bool OptSoundMixerOpt = false;
        bool OptAudioDecodeMt = false;
        bool OptDbcLookupCache = false;
        bool OptWorldStateCoalesce = false;
        bool OptD3d9RenderThread = false;

        // 10 new features
        // Off by default. It drops events by affiliation, not by subscription, so
        // anything happening between two units outside your group never reaches
        // addons - see the note in combat_log_filter.cpp.
        bool OptCombatLogFilter = false;
        bool OptSoundVolumeLimit = false;
        bool OptTerrainHeightCache = false;

        bool OptTextureUnloadDelay = false;
        bool OptM2MatrixSimd = false;
        bool OptMpqAsyncDecompress = false;
        bool OptSpellEffectCulling = false;
        // Read-only watch on the client's own shadow state, for the flicker seen
        // below extShadowQuality 5. Not our bug - a tester reproduced it with
        // every feature off and no DXVK - but nothing has ever looked at what the
        // engine does when it happens. Off by default.
        bool OptShadowStateProbe = false;
        // Counts what the client compiles at runtime, by chunk name. On by
        // default and silent unless the totals say something is recompiling in a
        // loop - the case that costs about 5% of a real session's CPU and that
        // nothing has ever been able to name.
        bool OptLuaCompileCensus = true;
        // Turns on the client's own script profiler and reports per-addon CPU to
        // the log every minute, ranked. Off by default: the client's profiler is
        // not free, and only someone chasing a stutter should pay for it.
        bool OptAddonProfiler = false;
        // SSE2 strncmp for the CRT copy at 0x004180A6, 1.55% of executing time.
        // 3.88x on a 63-byte compare and 1.33x on a short one, so it does not
        // regress the short case the way a naive block version does - though a
        // very short compare is close to break-even once the detour is counted.
        bool OptStrncmpSse2 = true;
        // Null guard on sub_873060, the per-draw parameter setter in the M2 path.
        // On by default - it prevents a real null dereference - but it can only
        // do that by skipping the call, and a skipped call draws that model with
        // the previous one's parameters. Exposed so a flicker report can be
        // tested against it in one session instead of guessed at.
        bool OptRenderNullGuard = true;
        // Drops a dead _msize from WoW's free wrapper. Measured at 8-10% of
        // main-thread execution in two tester profiles.
        // SSE2 quaternion normalize, 3.13% of execution in a CPU-bound profile.
        // On by default now that it is bit-identical to the client rather than
        // within one ULP - it reproduces the client's double-precision width and
        // its left-to-right summation order, and a self-test refuses to install
        // it on a single differing bit.
        bool OptQuatNormalizeSse2 = true;
        // SSE2 4x4 matrix multiply. Off by default for the same reason: verified
        // against the client's version numerically, never run in a game.
        // On by default since the accumulation moved to packed double: the
        // results are bit-identical to the client's own routine, and a startup
        // self-test compares the two over 4096 random pairs and refuses to
        // install on any disagreement.
        bool OptMatrixMultiplySse2 = true;
        // Counts draw calls per frame. A diagnostic, not an optimisation: it
        // wraps the hottest call in the renderer, so it is meant to answer the
        // question in one session and be switched off again.
        bool OptDrawCensus = false;
        // Counts Lua VM allocations by size through G->frealloc. A measurement,
        // like the draw census - it decides whether a dedicated Lua arena is
        // worth building.
        bool OptLuaAllocCensus = false;
        // Counts what the M2 animation update does per frame. A measurement in
        // the same spirit as the draw and allocation censuses: it decides
        // whether animation level-of-detail is worth building, and is meant to
        // answer that in one session and be switched off again.
        bool OptAnimCensus = false;
        // SSE2 rasterisation for the terrain horizon builder at 0x0078F6A0,
        // 2.46% of main-thread execution in a tester's profile. Off by default
        // until a log shows the startup verification passing: it replaces a
        // culling routine, and a wrong answer is terrain that fails to draw.
        bool OptHorizonOcclusionSse2 = false;
        // Passive watcher on the receive path. On by default: disconnects are
        // the oldest unexplained complaint here, they happen once a session at
        // most, and a diagnostic that is off when the thing it watches for
        // happens is worth nothing. Costs four counters per receive.
        bool OptNetDiag = true;
        bool OptCrtFreeMsize = true;
        bool OptCrtAllocMsize = true;
        bool OptCrtMimalloc = false;

        // Previously Init'd unconditionally (ignored their launcher toggles).
        // Default true = preserve the old always-on behavior; now disableable.
        bool OptMouseClipRelease = false;
        bool OptSavedVarsBackup = false;
        bool OptSoundCoalescer = false;
        bool OptVertexBufferPrealloc = false;
    };

    extern Settings g_settings;

    // Load settings from wow_opt.ini
    void Load();

    // Writes the resolved ini path and its contents to the log. Call after Load
    // and after logging is up, so every report says what was actually enabled.
    void DumpToLog();
}

#endif // WOW_OPT_CONFIG_H
