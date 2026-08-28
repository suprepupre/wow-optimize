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

        // Four more that took no setting at all. Same rule: they have always
        // run, so they default on, and turning them off is what the vanilla
        // button needs in order to mean anything.
        bool OptLockTuning        = true;   // retrofits spin counts onto 15 client locks
        bool OptAsyncMpqIo        = true;   // spawns a background I/O worker thread
        bool OptThreadIdCache     = true;   // hooks GetCurrentThreadId
        bool OptPriorityGuard     = true;   // hooks SetPriorityClass to block downgrades

        // The Lua VM optimizer: it replaces the VM's allocator with mimalloc,
        // pre-sizes the string table and retunes the collector, and it did all
        // of that with every switch off. Split in two because stopping the
        // automatic collector is the part worth isolating on its own.
        bool OptLuaVmOpt          = true;
        bool OptLuaGcManual       = true;

        // Sixteen hooks into the D3D9 device vtable, deduplicating redundant
        // render-state calls. Also took no setting: it patched the vtable on
        // every install regardless of the launcher.
        bool OptD3d9StateManager  = true;

        // The UI layout dependency relink, sub_489710: 9.06% of main-thread
        // executing time, the largest single entry in the profile. New, and it
        // rewrites pointer surgery in the client's layout list, so it is
        // opt-in until testers have run it.
        bool OptLayoutRelinkFast  = false;
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
        // The Win32 file hooks: CreateFile sequential-scan hinting, the adaptive
        // MPQ ReadFile cache, CloseHandle cleanup, the FlushFileBuffers skip,
        // and the GetFileAttributes / SetFilePointer / GetFileSize caches.
        //
        // These used to hang off OptDbcLookupCache, which is described to the
        // player as speeding up .dbc reads and says nothing about file I/O.
        // Anyone who cleared that switch to test the DBC cache silently removed
        // the whole file layer; anyone who set it got seven hooks they never
        // asked for. Defaults to whatever DbcLookupCache resolved to, so no
        // install changes behaviour until its owner sets it deliberately.
        bool OptFileIoHooks = false;
        // The terrain read-ahead. It hung off FileIoHooks, which names the
        // Win32 file layer and not a prefetcher, and it never ran: its player
        // coordinate came from an address no instruction in wow.exe writes, so
        // it took its own zero-coordinate early return on every frame ever.
        // Now that it has a working coordinate it does real background I/O, and
        // that has never been tested by anyone. Off by default is not the 3.18.1
        // mistake of removing a running feature - there is nothing running to
        // remove.
        bool OptTerrainPrefetch = false;
        // Prefetches the next node of the per-frame object tick walk. New, and
        // it is a cache hint on a hot list, so off until someone has run it.
        bool OptTickListPrefetch = false;
        // Makes the GC governor leave Lua's collector at its stock 200/200 and
        // stop stepping it by hand, so the pace it normally sets can be
        // measured against doing nothing. Off, because on is what ships today.
        bool OptLuaGcStockPace = false;
        // Diagnostic. Samples the tables the collector walks and reports how
        // many of their slots are empty, which is the number a table compactor
        // would have to justify itself against.
        bool OptLuaTableCensus = false;
        // UIFrameBatch reads as gating four things. Two of them, the message
        // pump hook and the deferred field updates, are compiled out by
        // CRASH_TEST_DISABLE_MSGPUMP_RC1 and TEST_DISABLE_DEFERRED_FIELD_UPDATES
        // and have never run. What it really controls is these two. Issue #36,
        // the artifacting that made it default off for everyone, can therefore
        // only have come from one of them, and splitting makes that answerable
        // in two runs instead of never.
        //
        // Both inherit UIFrameBatch, so no install changes behaviour until its
        // owner sets one of them deliberately.
        bool OptUiScriptHandlerCache = false;
        bool OptUnitApiFastPath      = false;
        // The lua_type fast path in hot_patch.cpp, which resolves a positive
        // stack index inline instead of calling the engine's index2adr. It was
        // gated on OptDbcLookupCache as well and has nothing to do with .dbc
        // reads. Same inheritance rule, same reason.
        bool OptLuaTypeFast = false;
        // Caches over Win32 calls that answer the same thing every time:
        // GetSystemInfo, GetSystemMetrics, GetVersionEx, RegQueryValueEx,
        // GetProcAddress, GetModuleFileName, GetEnvironmentVariable and
        // GetPrivateProfile. They hung off OptTimingFix, which is described as
        // a timing fix and should own the clock hooks, not eight lookups that
        // have nothing to do with time.
        bool OptWin32ApiCaches = false;
        // The debug-family Win32 hooks: IsBadReadPtr / IsBadWritePtr answered
        // from VirtualQuery, OutputDebugString turned into a no-op, and
        // IsDebuggerPresent forced to false. They hung off OptCvarNullGuard,
        // which declines CVar writes through uninitialised objects and is
        // unrelated to any of them.
        // Defaults on, matching CvarNullGuard, which is what it used to run under.
        bool OptDebugApiHooks = true;
        // Spin counts retrofitted onto CriticalSection and WaitForSingleObject.
        // They hung off OptDefragLf, the lock-free heap defragmenter, which is
        // a different subsystem; OptLockTuning is the neighbouring switch and
        // does the same kind of work, but it defaults on while DefragLf defaults
        // off, so folding them in would silently start them everywhere.
        bool OptLockSpinHooks = false;
        // Charges the sampling profiler's main-thread samples to the addon whose
        // Lua is on the call stack. Rides on the sampler, which already stops
        // the thread, so it adds nothing to the paths it measures - unlike the
        // client's own script profiler, which a reporter measured at 1-4 fps in
        // a dungeon. Inherits SamplingProfiler: no sampler, nothing to charge.
        bool OptLuaAddonProfile = false;
        // Reads the CPU's core classes and samples which one the frame loop is
        // running on. Measurement only, and cheap: one GetCurrentProcessorNumber
        // per frame. On by default because the answer is worth having in every
        // log and nothing acts on it.
        bool OptCpuTopology = true;
        // Keeps the main thread off the efficiency cores of a hybrid CPU. Off by
        // default: it overrides the scheduler, and the residency figure from
        // OptCpuTopology should say it is needed before anyone turns it on.
        bool OptPinMainThread = false;
        // The Lua pool block allocator (lmemPool.cpp, sub_855820) restarts its
        // free-chunk search at chunk zero on every allocation. Second in a
        // CPU-bound profile at 4.29% of executing time, with 2.3 million
        // allocations in six minutes. Opt-in until a log shows the search is
        // really where that time goes - the counters it adds answer that.
        bool OptLuaMemPoolFast = false;
        // Removes a per-vertex call from the UI batcher and the particle vertex
        // filler. The call resolved to a fixed offset from a global whose value
        // cannot change between two vertices of a batch; together those two
        // functions were 5.06% of executing time. Patches machine code in place
        // after verifying it byte for byte, so it is opt-in.
        bool OptVertexFmtInline = false;
        // The object manager's find-by-GUID re-derived the bucket link offset
        // from the table header on every node of the chain. 2.22% of executing
        // time in a CPU-bound profile. Verifies against the client and retires
        // on one disagreement, so it is opt-in until a log shows it agreeing.
        bool OptObjMgrFindFast = false;
        // The per-bone quaternion interpolation (sub_982630), four components at
        // once instead of one at a time on the x87 stack. Not bit-exact: the
        // worst divergence measured over 12 million components is 2.98e-07,
        // under three float epsilon, and the result is renormalised right after.
        // Opt-in, and it verifies against the client before trusting itself.
        bool OptQuatLerpSse2 = false;
        // 88% of the chunks this client compiles are source it already compiled
        // this session - 332 MB of repeated parsing, measured. A repeat reuses
        // the compiled Proto; the client still builds the closure, environment
        // and taint, so nothing about ownership is shared. Opt-in, and it checks
        // reuses against a fresh compile before trusting itself.
        bool OptLuaProtoCache = false;
        // The object lookup every Lua call into a UI method starts with
        // (sub_4A81B0, 674 call sites). Four Lua API calls replaced by direct
        // reads, including the taint move lua_rawgeti performs. Opt-in, and it
        // checks itself against the client before trusting itself.
        bool OptLuaThisFast = false;
        // Animating models is 3.68 ms of a 24.5 ms frame in raid content, and no
        // single function in it exceeds 0.4% of self time, so only doing less of
        // it can help. Above a model budget each model updates every Nth frame
        // instead of every frame. Opt-in; skipping cannot slow an animation down
        // because the client derives its time from an absolute clock.
        bool OptAnimLod = false;
        // The collision reject pass (sub_7C7230), 3.8% of executing in a
        // corrected profile. Six x87 compares per vertex become six packed
        // compares per four. The bounds are plain floats with no arithmetic
        // applied, so this is bit-exact rather than close. Opt-in, and it
        // predicts the client's whole output and compares before trusting itself.
        bool OptCollisionOutcode = false;
        // The box-overlap predicate (sub_78F370) that seventeen culling and
        // pick functions call once per scene node per pass. Six x87 compares,
        // each leaving the FPU through fnstsw and a data-dependent branch,
        // become two packed compares and one movemask. No arithmetic in it at
        // all, so bit-exact rather than close. Opt-in, and it checks itself
        // against the client before it stops calling it.
        bool OptAabbOverlap = false;
        // The bone rotation track (sub_828680), run once per animated bone per
        // frame from the largest entry in the main-thread profile. Keyframes are
        // four uint16 expanded as v * K - 1.0, and x86 has no register path from
        // an integer to the x87 stack, so the client spills and reloads every
        // component - up to sixteen times a call. Packed double rounds where the
        // client rounds, so this is bit-exact. Opt-in, and it compares all
        // twenty-four output bytes against the client before trusting itself.
        bool OptAnimQuatUnpack = false;
        // The Lua pool free (sub_855670). Every block returned to the client's
        // own Lua pool makes it walk that pool's chunks, two dependent loads
        // each, until one contains the pointer. Two tester freeze samples landed
        // on the compare inside that loop. Opt-in, and it predicts against the
        // client before it skips anything.
        bool OptLuaPoolFast = false;
        // The vector animation track (sub_82B0A0). Eight call sites, six of
        // them inside the largest entry in the main-thread profile, against one
        // for the quaternion track. Opt-in, and it compares all twenty output
        // bytes against the client before trusting itself.
        bool OptAnimVec3Track = false;
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
