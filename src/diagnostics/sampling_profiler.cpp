// ============================================================================
// Module: sampling_profiler.cpp
// Description: Samples thread contexts periodically to trace hot execution execution paths.
// Safety & Threading: Dedicated profiler thread.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include "sampling_profiler.h"
#include "lua_addon_sampler.h"
#include "frame_bench.h"
#include "version.h"
#pragma comment(lib, "psapi.lib")

extern "C" void Log(const char* fmt, ...);

// Forward decl (avoid pulling in the whole lua_optimize header here). Returns
// true while a zone/UI load or transition is in progress.
namespace LuaOpt { bool IsLoadingMode(); }

namespace SamplingProfiler {

// Samples taken during loading screens / the first few seconds after start are
// not representative of steady-state play (they're dominated by MPQ/DBC load,
// hook install and page faults). Excluding them makes the profile reflect what
// actually costs frame time in the world. Counted separately for transparency.
static DWORD    g_samplerStartTick = 0;
static uint64_t g_skippedSamples = 0;
static const DWORD PROFILER_WARMUP_MS = 15000;

// ---- configuration ------------------------------------------------
static constexpr DWORD SAMPLE_INTERVAL_MS = 1;      // target interval
// Cadence while nothing is being recorded (warmup, loading screens). Only needs
// to notice the state changing back, so it costs one wake-up per frame at most.
static constexpr DWORD IDLE_INTERVAL_MS   = 16;
static constexpr int   MAX_KNOWN_FUNCS    = 256;     // address table size
static constexpr int   TOP_N              = 50;      // functions to dump
static constexpr uintptr_t WOW_BASE       = 0x00400000;
static constexpr uintptr_t WOW_END        = 0x00BFFFFF;  // wow.exe image range

// ---- known-function table -----------------------------------------
// Each entry: { address, name }. Sorted by address for binary search.
// Populated at Init() from the verified address list.
struct FuncEntry {
    uintptr_t   addr;
    uint32_t    size;   // exact byte length, read from the binary
    const char* name;
};

struct SampleBucket {
    uintptr_t   addr;       // nearest known function (or 0 for unknown)
    const char* name;       // null if unknown
    uint64_t    count;

    // Where inside the 4 KB window after `addr` the samples actually landed,
    // in 256-byte steps.
    //
    // Without this the report is misleading in a way that is easy to act on and
    // hard to notice. A named symbol claims every sample within 4 KB after it,
    // and the offset was thrown away - so "tostring 4.73%" could be
    // luaB_tostring itself or any unnamed function in the four kilobytes
    // following it, and the line reads identically either way. That is a lot of
    // Lua library code to attribute to one dispatcher.
    //
    // Costs nothing on the sampling path; this is filled in at dump time.
    uint32_t    offHist[16];
};

static FuncEntry    g_knownFuncs[MAX_KNOWN_FUNCS];
static int          g_knownCount = 0;

// ---- sample storage -----------------------------------------------
// We store raw EIP values and aggregate at dump time. This avoids
// lock contention during sampling. The ring buffer is written only
// by the sampler thread and read only at shutdown (after the thread
// is joined), so no synchronization is needed beyond the atomic
// write index.
static constexpr int RING_SIZE = 1 << 20;  // ~1M samples (~17 min at 1ms)
// Committed on Init rather than living in BSS. The profiler is off by default,
// but a static array is committed the moment the DLL is mapped, so every player
// who never turns it on was still paying four megabytes of a 32-bit address
// space this project exists to defend. Null until Init succeeds; every write
// site below is reachable only once the sampler thread is running.
static volatile uintptr_t* g_ring = nullptr;
static constexpr size_t RING_BYTES = (size_t)RING_SIZE * sizeof(uintptr_t);
static volatile uint64_t  g_writeIdx = 0;
static volatile uint64_t  g_totalSamples = 0;

// Per-4KB-page sample counts for WoW-image samples that don't match a named
// function. Turns the opaque "unknown_wow" blob into a per-region hot-map so
// unlisted hot code is still pinpointed by address (label "wow_region_0x...").
static constexpr int NUM_PAGES = (int)((WOW_END - WOW_BASE) >> 12) + 1;  // ~2048
static uint32_t g_pageCounts[NUM_PAGES];

// ---- state --------------------------------------------------------
static HANDLE  g_mainThread  = nullptr;
static HANDLE  g_samplerThread = nullptr;
static volatile bool g_running = false;
static HMODULE g_wowModule = nullptr;

// ---- populate known-function table --------------------------------
// Add entries here as new hooks/targets are verified in disassembly.
// Keep sorted by address for binary-search lookup.
static void BuildKnownFuncTable() {
    // Format: { RVA_or_VA, "symbol_name" }
    // Using absolute VAs (base 0x400000).
    static const FuncEntry table[] = {
        // --- CRT / memory ---
        { 0x0040BB80,   122, "memset" },
        { 0x0040CB10,   869, "memcpy" },
        { 0x004112F8,   163, "_msize" },
        { 0x00412FC7,   142, "free" },
        { 0x00415074,   195, "malloc" },
        { 0x00416A56,    63, "calloc" },
        { 0x00416A95,   539, "realloc" },
        { 0x00416CB0,   121, "_recalloc" },

        // --- Math / transform library ---
        { 0x004C1B30,    90, "CMatrix::TranslateLocal" },
        { 0x004C1C40,   170, "CMatrix::FromQuaternion" },
        { 0x004C1F00,   533, "CMatrix::Multiply" },
        { 0x004C2120,   140, "CMatrix::ScalarMul" },
        { 0x004C21B0,    93, "sub_4C21B0_pt_x_mat4" },
        { 0x004C2210,    93, "RowAffinePoint" },
        { 0x004C2270,   140, "sub_4C2270_vec4_x_mat4" },
        { 0x004C2300,   111, "InPlacePointXform" },
        { 0x004C23D0,   104, "CMatrix::Transpose" },
        { 0x004C2440,  2892, "CMatrix_AdjugateDet" },
        { 0x004C2FC0,   212, "CMatrix::InvertRigid" },
        { 0x004C3420,    53, "C3Vector::Normalize" },
        { 0x004C3600,    67, "C3Vector::NormalizeGuarded" },

        // --- Object manager ---
        { 0x004D3790,    43, "TLS_Accessor" },
        { 0x004D4DB0,    82, "ClntObjMgrObjectPtr" },

        // --- Network / serialization ---
        { 0x00468D00,    28, "NetPacketSend" },
        { 0x0047B340,    49, "CDataStore_GetBytes" },
        { 0x0076DC20,    96, "CDataStore_GetWowGUID" },

        // --- World / cleanup ---
        { 0x00528C30,   712, "WorldExitCleanup" },
        { 0x005D9D90,   363, "ObjMgrTeardownWalk" },

        // --- FrameScript / events ---
        { 0x0048E680,   737, "FrameScript_Dispatch" },
        { 0x0081AC90,   447, "FrameScript_SignalEvent" },

        // --- Lua VM core ---
        { 0x0084D9C0,   136, "index2adr" },
        { 0x0084E030,    52, "lua_tonumber" },
        { 0x0084E0B0,    42, "lua_toboolean" },
        { 0x0084E1C0,    42, "lua_touserdata" },
        { 0x0084E2A0,    36, "lua_pushnumber" },
        { 0x0084E670,   109, "lua_rawgeti" },
        { 0x0084E8D0,    45, "lua_settable" },
        { 0x0084EBF0,    59, "lua_pcall" },
        { 0x0084F9F0,    94, "luaL_checklstring" },

        // --- Lua internals ---
        // Named from a CPU-bound tester profile where each of these showed as a
        // raw address, or worse as a neighbour's name. Identified in the
        // disassembly, not guessed:
        //   sub_855820 loops over the pool's chunk array looking for one with a
        //   free block; its file string is ".\src\lmemPool.cpp", a Blizzard
        //   addition that stock Lua does not have.
        //   sub_85A960 and sub_85B200 are the collector's table traversal and
        //   sweep; separately they look small and together they were larger than
        //   anything else in that profile.
        { 0x00855570,    97, "LuaMemPool_NewChunk" },

        // Identified by disassembly while hunting for optimisable shapes, and
        // named here so the next profile does not report them as raw addresses.
        // The StormHash_* set are eleven instantiations of one template
        // (Storm\h\stpl.h): the same chain walk, differing only in what they
        // compare. Three of them are hooked; the rest are named so a log can say
        // whether any of the others ever gets hot.
        { 0x00505480,   110, "StormHash_Find_505480" },
        { 0x005B2350,    41, "AchievementCriteria_Find" },
        { 0x005B58B0,  1449, "Lua_GetAchievementCriteriaInfo" },
        { 0x005EEB70,     1, "StrippedNoOp" },
        { 0x006792E0,   110, "StormHash_FindKeyPair" },
        { 0x006BBD40,   102, "StormHash_Find_6BBD40" },
        { 0x006C2A50,   108, "StormHash_FindKeyPtr" },
        { 0x006F6020,    91, "StormHash_FindKey" },
        { 0x00734790,   111, "StormHash_Find_734790" },
        { 0x007B0690,    92, "StormHash_Find_7B0690" },
        { 0x007BDD80,   109, "StormHash_Find_7BDD80" },
        { 0x007BDDF0,    92, "StormHash_Find_7BDDF0" },
        { 0x00810970,   118, "StormHash_Find_810970" },
        // The two vertex loops the colour-format call was removed from, the
        // accessor it called, and the wrappers behind the CriticalSection time
        // that shows up as ntdll in every profile.
        { 0x00484B00,  1597, "UI_BatchDraw" },
        { 0x00490770,   193, "UIFrame_OnUpdateTree" },
        { 0x00532AF0,     7, "Renderer_GetColorFmtBlock" },
        { 0x006C4440,   877, "Particle_FillVertices" },
        { 0x00774640,     8, "EnterCriticalSection_wrap" },
        { 0x00774650,     8, "LeaveCriticalSection_wrap" },
        { 0x00817DB0,     6, "GetLuaState" },
        { 0x008B7DA0,     3, "ReturnThis" },
        { 0x00855670,   102, "LuaMemPool_Free" },
        // Hot in a CPU-bound profile but not yet understood. Named by address so
        // a repeat appearance is recognisable rather than looking like noise.
        { 0x00494A10,   214, "Hot_494A10" },
        { 0x007A50C0,   384, "Hot_7A50C0" },
        { 0x007C6D50,  1166, "Collision_ClipVertsToBox" },
        // Seventeen callers, once per scene node per culling pass. Its samples
        // used to be attributed to whichever named function preceded it.
        { 0x0078F370,    97, "AABB_Overlap" },
        // Classifies every vertex of a collision model against the query box
        // as a six-bit outcode, four vertices per unrolled pass, then tests
        // each triangle by ANDing its three. Called once per line-of-sight or
        // pick ray from sub_7C9A00. The six bounds live on the x87 stack for
        // the whole loop, which is why 158 of its 418 instructions are x87.
        { 0x008203B0,   872, "Hot_8203B0" },
        { 0x00857CA0,  5151, "luaV_execute" },
        // The Lua bytecode dispatch loop, and the client has two of them.
        // luaD_call at 0x00856760 picks by the byte at G(L)+20 - the script
        // profiling flag, the same one luaF_newLclosure reads: set, it calls a
        // timing precall and the copy at 0x00859160; clear, it calls this one.
        // This is the copy that shows up, so the client is already taking the
        // cheap path and there is nothing to win by steering it.
        { 0x00855820,   187, "LuaMemPool_Alloc" },
        // The pool's lua_Alloc: takes (pool, ptr, oldSize, newSize), finds the
        // size class for each by walking a nine-entry table, and dispatches.
        // Showed up as "LuaMemPool_NewChunk+0x100" before sizes were exact.
        { 0x008558E0,   305, "LuaMemPool_Realloc" },
        { 0x00856C80,   326, "luaS_newlstr" },
        { 0x00859160,  5583, "luaV_execute_profiled" },
        { 0x0085A960,   432, "luaC_traversetable" },
        { 0x0085B200,   143, "luaC_sweeplist" },
        { 0x00856E50,    78, "luaV_tonumber" },
        { 0x00857900,   455, "luaV_concat" },
        { 0x0085BC10,    87, "luaV_gettable" },
        { 0x0085C430,    63, "luaH_getstr" },
        { 0x0085C6F0,   618, "LuaH_resize" },
        { 0x0085CAB0,   260, "luaH_newkey" },

        // --- Rendering / culling ---
        //
        // Identified from a tester's profile, where each showed as raw hex and had
        // to be looked up in the disassembler one at a time. Naming them here means
        // the next profile reads as a list of functions rather than addresses - the
        // percentages were never the hard part, working out what they belonged to
        // was.
        { 0x0082F0F0,  6267, "M2_AnimateModel" },        // bone tracks + matrix per bone
        { 0x00828680,   885, "M2_AnimTrackQuat" },
        // Quaternion track, not a vector one: it unpacks each component from
        // a uint16 as (double)v * 0.000030518044 - 1.0, eight or sixteen times
        // per call, each through a store and an fild.
        { 0x008284D0,   420, "M2_AnimTrackFindKey" },
        // The keyframe search shared by all nine track evaluators. Hinted by
        // the caller's last index, with a binary search for a jump over 500ms
        // and a double division for the interpolation factor at the end.
        { 0x0082B0A0,   450, "M2_AnimTrackInterp" },
        { 0x0082AF40,   345, "M2_AnimTrackScalar" },
        { 0x0082B340,   273, "M2_AnimTrackColor" },
        { 0x007BCC00,   796, "World_VisibilityTraverse" },  // 64x64 tiles, 16x16 cells
        { 0x0078F6A0,   601, "Terrain_HorizonOcclusionBuild" },
        { 0x00861D90,   235, "luaK_patchlistaux" },      // Lua code generator jump patching
        { 0x00685F50,    96, "Unit_SetDisplaySlot" },    // equipment slots 21..36
        { 0x00516C60,   616, "Script_GetItemInfo" },
        { 0x00540A30,   822, "Script_GetSpellInfo" },
        // Linear walk of an intrusive list, nine pointer tests per node, until
        // the node owning `this` is found - then relinked. 2.44% of main-thread
        // execution. A candidate for an index rather than a search, but it is
        // pointer surgery with side effects and wants a careful sitting.
        { 0x00489710,   408, "Node_FindOwnerAndRelink" },
        { 0x00821A20,  5658, "M2_DrawBatchBuilder" },
        { 0x00960D20,   154, "Lua_Model_SetLight" },
        { 0x00979110,    84, "CQuaternion::Normalize" },
        { 0x00981D40,   936, "ParticleSpawn_Init" },
        { 0x00983490,   537, "RayTriIntersect16" },
        { 0x009836B0,   535, "RayTriIntersect32" },
        { 0x009839E0,   124, "CFrustum::IsAABBVisible" },
        { 0x00983D70,   241, "CFrustum::IsPointVisible" },

        // --- CRT string/memory (static) ---
        { 0x0076E5A0,    36, "free_wrapper" },
        { 0x0076E780,    27, "_strnicmp" },
        { 0x0076ED20,   120, "strncpy" },
        { 0x0076EE30,    46, "strlen" },

        // --- Combat text ---
        { 0x00608880,  6290, "CombatText_EventInit" },

        // --- Misc ---
        { 0x0081B510,    30, "EventNameWrapper" },

        // --- Lua pattern matcher (verified this session, 0x852A10-0x853D9C) ---
        { 0x00852A10,   109, "lua_classend" },
        { 0x00852C30,   112, "lua_matchbalance" },
        { 0x00852F60,   611, "lua_match" },
        { 0x00853240,   251, "lua_lmemfind" },
        { 0x008535B0,    20, "string.find" },
        { 0x008535D0,    20, "string.match" },
        { 0x00853980,   357, "string.gsub" },
        { 0x00853C50,   969, "string.format" },

        // --- Lua string library ---
        { 0x00852400,    43, "string.len" },
        { 0x00852430,   162, "string.sub" },
        { 0x008524E0,   146, "string.reverse" },
        { 0x00852580,   250, "string.lower" },
        { 0x00852680,   250, "string.upper" },
        { 0x00852780,   118, "string.rep" },
        { 0x00852800,   196, "string.byte" },
        { 0x008528D0,   161, "string.char" },

        // --- Lua API (stack / push / query) ---
        { 0x0084DBD0,    17, "lua_gettop" },
        { 0x0084DBF0,    89, "lua_settop" },
        { 0x0084DC50,   112, "lua_remove" },
        { 0x0084DCC0,   176, "lua_insert" },
        { 0x0084DEB0,    31, "lua_type" },
        { 0x0084DF20,    53, "lua_isnumber" },
        { 0x0084E280,    31, "lua_pushnil" },
        { 0x0084E2D0,    36, "lua_pushinteger" },
        { 0x0084E350,    76, "lua_pushstring" },
        { 0x0084E590,    98, "lua_getfield" },
        { 0x0084E900,   101, "lua_setfield" },
        { 0x0084E970,   142, "lua_rawset" },
        { 0x0084EC30,    27, "lua_call" },
        { 0x0084ED50,   216, "lua_gc" },

        // --- Lua VM dispatch / tables ---
        { 0x00856760,   169, "luaD_call" },
        { 0x00857250,   357, "luaV_gettable" },
        { 0x008573C0,   402, "luaV_settable" },

        // --- Lua base / conversion / table lib ---
        { 0x00851C30,   231, "table.concat" },
        { 0x00854100,   271, "tonumber" },
        { 0x00854660,    48, "type" },
        { 0x00854A20,   229, "tostring" },
    };

    g_knownCount = 0;
    for (const auto& e : table) {
        if (g_knownCount >= MAX_KNOWN_FUNCS) break;
        g_knownFuncs[g_knownCount++] = e;
    }

    // Sort by address for binary search
    std::sort(g_knownFuncs, g_knownFuncs + g_knownCount,
              [](const FuncEntry& a, const FuncEntry& b) { return a.addr < b.addr; });
}

// Find the nearest known function at or below the given address.
// Returns nullptr if no known function is within 4KB (likely not in a
// function we care about, or in an unlisted helper).
static const FuncEntry* FindNearestFunc(uintptr_t eip) {
    if (g_knownCount == 0) return nullptr;

    // Binary search for the largest addr <= eip
    int lo = 0, hi = g_knownCount - 1;
    int best = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (g_knownFuncs[mid].addr <= eip) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }

    if (best < 0) return nullptr;

    // A name reaches exactly as far as its function does, and no further.
    //
    // This was a flat 4KB window, which is room for several functions, and the
    // report named the wrong one with complete confidence. A tester profile put
    // "tostring+0xE00" second overall at 4.29% of executing time; tostring is
    // 229 bytes long, so those samples were 3.5KB past its end, inside the Lua
    // pool's block allocator. Acting on that line would have meant optimizing a
    // function that was not running.
    //
    // Narrowing the window to 512 bytes was not enough either, and the same log
    // proved it twice over: "LuaMemPool_NewChunk+0x100" and
    // "LuaMemPool_Alloc+0x100" were both neighbours of the named function, which
    // are 97 and 187 bytes long. Any fixed window is wrong, because function
    // sizes here run from 17 bytes to 6 kilobytes.
    //
    // So the table carries each function's exact length, read out of the binary.
    // Past the end of a function the sample is reported by address, which can be
    // looked up. A wrong name cannot be un-believed.
    uintptr_t delta = eip - g_knownFuncs[best].addr;
    if (delta >= g_knownFuncs[best].size) return nullptr;

    return &g_knownFuncs[best];
}

// ---- background threads --------------------------------------------------
//
// Everything above samples the main thread and nothing else, which makes this
// profile blind to an entire half of the client. WoW decompresses MPQ data,
// decodes sound and services IO completions on worker threads; if any of that
// costs real time, the only trace it leaves in a main-thread profile is the main
// thread waiting - which reads as "blocked" and says nothing about why.
//
// The question that exposed the gap was whether replacing the client's zlib
// would be worth doing. It cannot be answered without looking here.
//
// Sampled far more slowly than the main thread and one at a time. Suspending
// arbitrary threads is only safe because the sampler does nothing between the
// suspend and the resume except read a register - no allocation, no lock, no
// call that could need something the suspended thread is holding.
static constexpr int WORKER_MAX      = 16;
static constexpr int WORKER_EVERY_N  = 50;   // one worker sample per 50 main ones

static HANDLE   g_workerThreads[WORKER_MAX] = {};
static int      g_workerCount = 0;
static int      g_workerCursor = 0;
static uint64_t g_workerSamples = 0;

struct WorkerBucket {
    char     module[40];
    uint64_t count;
};
static WorkerBucket g_workerBuckets[32] = {};
static int          g_workerBucketCount = 0;

static void EnumerateWorkerThreads() {
    DWORD selfPid = GetCurrentProcessId();
    DWORD mainTid = 0;
    if (g_mainThread) mainTid = GetThreadId(g_mainThread);
    DWORD samplerTid = GetCurrentThreadId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != selfPid) continue;
            if (te.th32ThreadID == mainTid || te.th32ThreadID == samplerTid) continue;
            if (g_workerCount >= WORKER_MAX) break;

            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                                  FALSE, te.th32ThreadID);
            if (h) g_workerThreads[g_workerCount++] = h;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

// Buckets by owning module, because a worker's exact address is far less useful
// than knowing whether the time went to the decompressor, the sound mixer or the
// kernel.
static void NoteWorkerSample(uintptr_t eip) {
    char name[40] = "unknown";

    HMODULE mod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)eip, &mod) && mod) {
        char path[MAX_PATH] = "";
        GetModuleFileNameA(mod, path, sizeof(path));
        const char* slash = strrchr(path, '\\');
        const char* file = slash ? slash + 1 : path;

        // wow.exe is the interesting case: name the address so it can be looked
        // up, since that is where decompression would live if it is statically
        // linked - which it is.
        if (eip >= WOW_BASE && eip <= WOW_END)
            wsprintfA(name, "wow!0x%08X", (unsigned)(eip & ~0xFFFu));
        else
            lstrcpynA(name, file, sizeof(name));
    }

    for (int i = 0; i < g_workerBucketCount; i++) {
        if (lstrcmpiA(g_workerBuckets[i].module, name) == 0) {
            g_workerBuckets[i].count++;
            return;
        }
    }
    if (g_workerBucketCount < 32) {
        lstrcpynA(g_workerBuckets[g_workerBucketCount].module, name, 40);
        g_workerBuckets[g_workerBucketCount].count = 1;
        g_workerBucketCount++;
    }
}

static void SampleOneWorker() {
    if (g_workerCount == 0) return;

    HANDLE h = g_workerThreads[g_workerCursor];
    g_workerCursor = (g_workerCursor + 1) % g_workerCount;
    if (!h) return;

    CONTEXT wctx;
    wctx.ContextFlags = CONTEXT_CONTROL;
    if (SuspendThread(h) == (DWORD)-1) return;

    uintptr_t eip = 0;
    if (GetThreadContext(h, &wctx)) eip = (uintptr_t)wctx.Eip;
    ResumeThread(h);

    if (eip) {
        g_workerSamples++;
        NoteWorkerSample(eip);
    }
}

static void DumpWorkerThreads(uint64_t mainSamples) {
    if (g_workerSamples == 0) {
        Log("[SamplingProfiler] === BACKGROUND THREADS: nothing sampled ===");
        return;
    }

    Log("[SamplingProfiler] === BACKGROUND THREADS (%llu samples across %d threads, "
        "one per %d main-thread samples) ===",
        (unsigned long long)g_workerSamples, g_workerCount, WORKER_EVERY_N);
    Log("[SamplingProfiler]   These are not frame time. They say where the client's "
        "own workers spend theirs, which a main-thread profile cannot show.");

    // Simple selection sort; at most 32 entries, once per report.
    for (int i = 0; i < g_workerBucketCount; i++) {
        int best = i;
        for (int j = i + 1; j < g_workerBucketCount; j++)
            if (g_workerBuckets[j].count > g_workerBuckets[best].count) best = j;
        if (best != i) {
            WorkerBucket t = g_workerBuckets[i];
            g_workerBuckets[i] = g_workerBuckets[best];
            g_workerBuckets[best] = t;
        }
    }

    int shown = (g_workerBucketCount < 12) ? g_workerBucketCount : 12;
    for (int i = 0; i < shown; i++) {
        Log("[SamplingProfiler]   %2d. %-32s %8llu samples (%5.2f%%)",
            i + 1, g_workerBuckets[i].module,
            (unsigned long long)g_workerBuckets[i].count,
            100.0 * (double)g_workerBuckets[i].count / (double)g_workerSamples);
    }
    (void)mainSamples;
}

// ---- sampler thread -----------------------------------------------
static DWORD WINAPI SamplerThreadProc(LPVOID) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;  // just EIP + segment regs

    if (g_samplerStartTick == 0) g_samplerStartTick = GetTickCount();

    while (g_running) {
        // Only steady-state, in-world samples are kept: the warmup window and
        // any loading transition are excluded, so that startup one-shots (hook
        // install, MPQ/DBC load) and load-screen page-fault spikes stay out of
        // the "what costs frame time in play" picture.
        //
        // That decision used to be made *after* the sample was taken. The
        // discarded ones cost exactly as much as the kept ones: a suspend, a
        // context read and a resume of the main thread, a thousand times a
        // second, throughout every loading screen - against a thread that is
        // decompressing and page-faulting its way through a zone load, and
        // holding the allocator and archive locks while it does. A reporter
        // traced their excessive loading screen times to this profiler being
        // enabled, and turning it off shortened them.
        //
        // Decide first. The main thread is now touched only when the sample is
        // going to be kept, and the loop idles instead of spinning at the
        // sampling rate while there is nothing to record.
        const bool warmedUp = (GetTickCount() - g_samplerStartTick) >= PROFILER_WARMUP_MS;
        if (!warmedUp || LuaOpt::IsLoadingMode()) {
            g_skippedSamples++;
            Sleep(IDLE_INTERVAL_MS);
            continue;
        }

        // Suspend → read → resume. The window is ~microseconds;
        // WoW won't notice. Same technique crash dumpers use.
        if (SuspendThread(g_mainThread) != (DWORD)-1) {
            uintptr_t eip = 0;
            if (GetThreadContext(g_mainThread, &ctx)) eip = (uintptr_t)ctx.Eip;

            // Which addon's Lua is on the stack, read while the thread is still
            // stopped. The suspend is already paid for; this is a few loads on
            // top of it and nothing at all on the paths being measured, which
            // is the whole reason to do it here instead of instrumenting calls.
            LuaAddonSampler::NoteSample();

            ResumeThread(g_mainThread);  // resume ASAP, then decide off-thread

            if (eip) {
                uint64_t idx = g_writeIdx % RING_SIZE;
                g_ring[idx] = eip;
                g_writeIdx++;
                g_totalSamples++;
            }
        }

        // One background sample per WORKER_EVERY_N main ones. Enumeration is done
        // once, after the warmup window, by which point the client has created
        // the threads it is going to use. Reaching here already means warmed up
        // and not loading.
        static uint64_t tick = 0;
        if (++tick % WORKER_EVERY_N == 0) {
            if (g_workerCount == 0) EnumerateWorkerThreads();
            SampleOneWorker();
        }

        Sleep(SAMPLE_INTERVAL_MS);
    }

    return 0;
}

// ---- system-module classification ---------------------------------
// Samples that land outside the WoW image are otherwise lumped into one
// opaque "system_dll" bucket. On DXVK that bucket can be the majority of
// main-thread time, and it matters a great deal WHICH module it is:
// d3d9.dll/vulkan-1.dll = GPU present/sync wait (not CPU-fixable), while
// ntdll.dll = page-fault / heap work (fixable by reducing memory pressure).
// Enumerate loaded modules once per dump and range-classify each system sample.
struct ModRange { uintptr_t base; uintptr_t end; char name[32]; uint64_t count; };
static ModRange g_mods[128];
static int g_modCount = 0;

// Our own DLL is broken down per-4KB-page too (like the WoW image), because it
// showed up as a top-4 consumer (~8% of main-thread time) and we need to know
// WHICH of our hooks costs that. Reported as "wowopt+0xNNNN" (offset from our
// DLL base) so it maps directly to wow_optimize.map.
static uintptr_t g_selfBase = 0;
static uintptr_t g_selfEnd  = 0;

// Our own functions, by absolute address, so a hot spot inside this DLL prints a
// name instead of an offset nobody can resolve without the matching .map.
// Every Lua fast path registers itself, which alone is 55 names, plus the
// allocator hooks and the caches. 64 was exactly enough to overflow.
static constexpr int MAX_SELF_SYMBOLS = 128;
struct SelfSymbol { uintptr_t addr; const char* name; };
static SelfSymbol g_selfSymbols[MAX_SELF_SYMBOLS] = {};
static int        g_selfSymbolCount = 0;

bool ShareForRange(uintptr_t lo, uintptr_t hi, unsigned long minSamples,
                   double* outPercent, unsigned long* outSamples,
                   unsigned long* outWindow) {
    if (outPercent) *outPercent = 0.0;
    if (outSamples) *outSamples = 0;
    if (outWindow)  *outWindow  = 0;

    if (!g_ring || hi <= lo) return false;

    uint64_t total = g_totalSamples;
    uint64_t n     = (total < RING_SIZE) ? total : RING_SIZE;
    if (n < (uint64_t)minSamples) return false;

    uint64_t startIdx = (total <= RING_SIZE) ? 0 : (total - RING_SIZE);

    unsigned long hits = 0;
    for (uint64_t i = 0; i < n; i++) {
        uintptr_t eip = g_ring[(startIdx + i) % RING_SIZE];
        if (eip >= lo && eip < hi) hits++;
    }

    if (outPercent) *outPercent = 100.0 * (double)hits / (double)n;
    if (outSamples) *outSamples = hits;
    if (outWindow)  *outWindow  = (unsigned long)n;
    return true;
}

void RegisterSelfSymbol(const char* name, const void* addr) {
    if (!name || !addr) return;

    // Phase 2 of the Lua fast path runs again after every UI reload, so the same
    // hook can arrive here repeatedly. Registering it twice wastes a slot and
    // makes the table lie about how full it is.
    for (int i = 0; i < g_selfSymbolCount; i++) {
        if (g_selfSymbols[i].addr == (uintptr_t)addr) return;
    }

    if (g_selfSymbolCount >= MAX_SELF_SYMBOLS) {
        // Dropping this silently would leave the hot code it names showing as a
        // raw offset, indistinguishable from code nobody registered - the same
        // ambiguity the feature registry had before it started saying so.
        static bool s_saidFull = false;
        if (!s_saidFull) {
            s_saidFull = true;
            Log("[SamplingProfiler] Symbol table full at %d; '%s' and any after it "
                "will appear as raw offsets. Raise MAX_SELF_SYMBOLS.",
                MAX_SELF_SYMBOLS, name);
        }
        return;
    }

    g_selfSymbols[g_selfSymbolCount].addr = (uintptr_t)addr;
    g_selfSymbols[g_selfSymbolCount].name = name;
    g_selfSymbolCount++;
}

// Nearest registered symbol at or below addr, within a sane distance. The bound
// matters: without it every unregistered hot spot would be attributed to whichever
// registered function happens to sit lowest in the image, which is worse than
// admitting we do not know.
static const char* ResolveSelfSymbol(uintptr_t addr, uintptr_t* outDelta = nullptr) {
    const char* best = nullptr;
    uintptr_t bestDelta = 0x4000;   // 16 KB
    for (int i = 0; i < g_selfSymbolCount; i++) {
        if (g_selfSymbols[i].addr > addr) continue;
        uintptr_t d = addr - g_selfSymbols[i].addr;
        if (d < bestDelta) {
            bestDelta = d;
            best = g_selfSymbols[i].name;
        }
    }
    if (outDelta) *outDelta = best ? bestDelta : 0;
    return best;
}

// The distance past a registered symbol at which its name stops being evidence.
// Nothing here records a function's size - RegisterSelfSymbol is handed an entry
// point and nothing else - so a sample far past one is at best "somewhere after
// it" and at worst inside an unregistered neighbour. Naming those was how
// txtsd's 2026-08-22 session reported wowopt!dbc_lookup_cache at 1.00% of the
// profile while the cache's own counter recorded 336908 calls over 184004
// frames, which is 1.8 calls a frame and cannot cost one percent of anything.
// Past this the offset is printed, so a reader can see the label is a
// neighbourhood and not a function.
static constexpr uintptr_t kSelfSymbolTrusted = 0x200;   // 512 bytes
static constexpr int SELF_PAGES = 4096;   // covers a 16MB image
static uint32_t g_selfPageCounts[SELF_PAGES];

// The 4KB page above ranks our DLL against everything else, but it cannot answer
// WHICH hook is hot: at this build's code density a single page holds about
// nineteen functions, so a page that reads 1.97% could be one expensive hook or
// nineteen cheap ones. Resolving that from a tester log used to mean rebuilding
// the exact commit just to read its .map, and even then a page listed too many
// candidates to choose between.
//
// So our own image is counted a second time at 256-byte resolution, and reported
// as its own section rather than merged into the main ranking - splitting our
// share across eight buckets would push every one of them below the top-N cutoff
// and hide the very thing this is for.
static constexpr int SELF_FINE_SHIFT = 8;      // 256-byte buckets
static constexpr int SELF_FINE_SLOTS = 8192;   // covers a 2MB image (~600KB today)
static constexpr int SELF_FINE_TOP   = 20;
static uint32_t g_selfFineCounts[SELF_FINE_SLOTS];

// The client's code has exactly the same problem, and it is the bigger half: the
// hottest region in a recent profile, 0x005B2000 at 6.45%, holds four functions,
// so "which client function is worth hooking" could not be answered from a log at
// all. 512 bytes over the 8MB image costs 64KB of counters and usually lands on
// one function, which can then be decompiled directly.
static constexpr int WOW_FINE_SHIFT = 9;       // 512-byte buckets
static constexpr int WOW_FINE_SLOTS = (int)((WOW_END - WOW_BASE) >> WOW_FINE_SHIFT) + 1;
static uint32_t g_wowFineCounts[WOW_FINE_SLOTS];

// Prints the top SELF_FINE_TOP buckets of a histogram, largest first. Selection is
// an insertion pass over a 20-entry list rather than a sort of the whole array,
// which would mean copying 16-32K entries inside a diagnostic dump.
static bool IsWaitSymbol(const char* n) {
    if (!n) return false;
    if (n[0] != 'N' || n[1] != 't') return false;
    return strncmp(n, "NtWaitFor", 9) == 0 ||
           strncmp(n, "NtDelayExecution", 16) == 0 ||
           strncmp(n, "NtRemoveIoCompletion", 20) == 0;
}

// Finds the single most-sampled instruction address inside a 4KB page.
//
// The ranked list groups unnamed client code by page, which is far too coarse to
// act on - one page holds a dozen functions. But the ring still holds every raw
// sample address when the report is built, so the exact peak is recoverable, and
// one address resolves to one function in a disassembler where a page does not.
//
// Runs once per reported region at dump time only. The counter array is static
// rather than stack because 16KB is more than a comfortable frame, and it is
// reused across regions since the passes are sequential.
static uint32_t s_pageExact[4096];

static uintptr_t HottestAddressInPage(uintptr_t pageBase) {
    memset(s_pageExact, 0, sizeof(s_pageExact));

    uint64_t written = g_writeIdx;
    uint64_t count   = (written < RING_SIZE) ? written : RING_SIZE;

    for (uint64_t i = 0; i < count; i++) {
        uintptr_t eip = g_ring[i];
        if (eip - pageBase < 4096) s_pageExact[eip - pageBase]++;
    }

    uint32_t  best = 0;
    uintptr_t at   = 0;
    for (int off = 0; off < 4096; off++) {
        if (s_pageExact[off] > best) { best = s_pageExact[off]; at = pageBase + off; }
    }
    return at;
}

static void DumpFineHistogram(const uint32_t* counts, int slots, int shift,
                              uint64_t total, const char* title,
                              const char* addrFormat, uintptr_t addrBase) {
    int idx[SELF_FINE_TOP];
    int found = 0;

    for (int i = 0; i < slots; i++) {
        uint32_t c = counts[i];
        if (!c) continue;
        int at = found;
        if (found < SELF_FINE_TOP) {
            found++;
        } else if (c > counts[idx[SELF_FINE_TOP - 1]]) {
            at = SELF_FINE_TOP - 1;
        } else {
            continue;
        }
        while (at > 0 && c > counts[idx[at - 1]]) {
            idx[at] = idx[at - 1];
            at--;
        }
        idx[at] = i;
    }

    if (found == 0 || total == 0) return;

    Log("[SamplingProfiler] === %s ===", title);
    for (int i = 0; i < found; i++) {
        uint32_t c = counts[idx[i]];
        char addr[32];
        uintptr_t slotAddr = addrBase + ((uintptr_t)idx[i] << shift);
        uintptr_t delta = 0;
        const char* sym = (addrBase == 0)
                        ? ResolveSelfSymbol(g_selfBase + slotAddr, &delta) : nullptr;
        if (sym && delta < kSelfSymbolTrusted) wsprintfA(addr, "wowopt!%.20s", sym);
        else if (sym) wsprintfA(addr, "wowopt!%.14s+0x%X", sym, (unsigned)delta);
        else          wsprintfA(addr, addrFormat, (unsigned)slotAddr);
        Log("[SamplingProfiler]   %-14s %8u samples (%5.2f%%)",
            addr, c, 100.0 * (double)c / (double)total);
    }
}

// A cheap marker: this variable lives inside our own DLL, so its address tells
// us which module is ours.
static int g_selfAnchor = 0;

static void BuildModuleTable() {
    g_modCount = 0;
    g_selfBase = g_selfEnd = 0;
    HMODULE mods[256];
    DWORD needed = 0;
    HANDLE proc = GetCurrentProcess();
    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed)) return;
    int count = (int)(needed / sizeof(HMODULE));
    if (count > 256) count = 256;
    for (int i = 0; i < count && g_modCount < 128; i++) {
        MODULEINFO mi;
        if (!GetModuleInformation(proc, mods[i], &mi, sizeof(mi))) continue;
        uintptr_t base = (uintptr_t)mi.lpBaseOfDll;
        uintptr_t end  = base + mi.SizeOfImage;
        // Skip the wow.exe main image — those samples are already handled by
        // the named-function / per-page buckets (WOW_BASE..WOW_END).
        if (base <= WOW_BASE && WOW_BASE < end) continue;
        // Identify our own DLL by the anchor address; it gets a per-page
        // breakdown instead of a single module bucket.
        if ((uintptr_t)&g_selfAnchor >= base && (uintptr_t)&g_selfAnchor < end) {
            g_selfBase = base;
            g_selfEnd  = end;
            continue;
        }
        char nm[MAX_PATH];
        if (!GetModuleBaseNameA(proc, mods[i], nm, sizeof(nm))) continue;
        ModRange& m = g_mods[g_modCount];
        m.base = base;
        m.end  = end;
        strncpy(m.name, nm, sizeof(m.name) - 1);
        m.name[sizeof(m.name) - 1] = '\0';
        m.count = 0;
        g_modCount++;
    }
}

// The largest single entry in a corrected profile is a module we did not write.
// AwesomeWotlkLib.dll came out at 9.7% of executing time in a tester's raid
// session, reported as one line with nothing inside it, and there is nothing to
// be done about a number like that until somebody knows which part of it is hot.
//
// So the hottest foreign module gets the treatment our own image and wow.exe
// already get: a second walk of the ring, bucketed by offset from its base. The
// bucket width is chosen so any module fits the same 8192 slots - a 4 MB library
// lands on 512-byte buckets, a 32 MB one on 4 KB - and the width is printed,
// because a reader has to know how much of a function a line covers.
//
// This runs once per report, at dump time, over a ring that has already been
// walked once. It costs nothing while sampling.
static constexpr int MOD_FINE_SLOTS = 8192;
static constexpr int MOD_FINE_TOP   = 12;
static uint32_t g_modFineCounts[MOD_FINE_SLOTS];

static void DumpHottestForeignModule(const volatile uintptr_t* ring,
                                     uint64_t startIdx, uint64_t n, uint64_t total) {
    if (g_modCount <= 0 || n == 0) return;

    int best = -1;
    for (int i = 0; i < g_modCount; i++)
        if (g_mods[i].count && (best < 0 || g_mods[i].count > g_mods[best].count))
            best = i;
    if (best < 0) return;

    const ModRange& m = g_mods[best];
    // Below a percent of the profile there is nothing worth a section.
    if ((double)m.count < 0.01 * (double)n) return;

    uintptr_t size = m.end - m.base;
    int shift = 9;
    while ((size >> shift) >= MOD_FINE_SLOTS && shift < 24) shift++;

    memset(g_modFineCounts, 0, sizeof(g_modFineCounts));
    for (uint64_t i = 0; i < n; i++) {
        uintptr_t eip = ring[(startIdx + i) % RING_SIZE];
        if (eip < m.base || eip >= m.end) continue;
        uint32_t b = (uint32_t)((eip - m.base) >> shift);
        if (b < MOD_FINE_SLOTS) g_modFineCounts[b]++;
    }

    Log("[SamplingProfiler] === %s HOT SPOTS (%d-byte resolution, %.2f%% of the "
        "profile is in this module) ===",
        m.name, 1 << shift, 100.0 * (double)m.count / (double)n);

    for (int rank = 0; rank < MOD_FINE_TOP; rank++) {
        int top = -1;
        for (int i = 0; i < MOD_FINE_SLOTS; i++)
            if (g_modFineCounts[i] && (top < 0 || g_modFineCounts[i] > g_modFineCounts[top]))
                top = i;
        if (top < 0) break;
        Log("[SamplingProfiler]   %s+0x%06X %8u samples (%5.2f%%)",
            m.name, (unsigned)((uintptr_t)top << shift), g_modFineCounts[top],
            100.0 * (double)g_modFineCounts[top] / (double)n);
        g_modFineCounts[top] = 0;
    }
    (void)total;
}

static ModRange* FindModule(uintptr_t eip) {
    for (int i = 0; i < g_modCount; i++) {
        if (eip >= g_mods[i].base && eip < g_mods[i].end) return &g_mods[i];
    }
    return nullptr;
}

// ntdll shows up as one big bucket (~40%+ of main-thread time), but that lumps
// together two very different things: threads BLOCKED in a wait (NtWait* /
// NtDelayExecution = idle GPU/frame-pacing, NOT CPU we can cut) versus HEAP work
// (RtlAllocateHeap/RtlFreeHeap = reducible by cutting allocations). Resolving
// ntdll samples to the nearest key exported function tells us which - i.e.
// whether a memory optimization is even worth attempting.
struct NtFunc { uintptr_t addr; const char* name; uint64_t count; };
static NtFunc g_ntFuncs[24];
static int g_ntFuncCount = 0;
static uintptr_t g_ntdllBase = 0, g_ntdllEnd = 0;

static void BuildNtFuncTable() {
    g_ntFuncCount = 0; g_ntdllBase = g_ntdllEnd = 0;
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return;
    MODULEINFO mi;
    if (GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi))) {
        g_ntdllBase = (uintptr_t)mi.lpBaseOfDll;
        g_ntdllEnd  = g_ntdllBase + mi.SizeOfImage;
    }
    static const char* const names[] = {
        // blocked in a wait -> idle (GPU/frame-pacing/lock), not fixable CPU work
        "NtWaitForSingleObject", "NtWaitForMultipleObjects", "NtDelayExecution",
        "NtWaitForAlertByThreadId", "NtSignalAndWaitForSingleObject", "NtRemoveIoCompletion",
        // heap -> real CPU work, reducible by cutting main-thread allocations
        "RtlAllocateHeap", "RtlFreeHeap", "RtlReAllocateHeap", "RtlSizeHeap",
        // locks / dispatch
        "RtlEnterCriticalSection", "RtlLeaveCriticalSection",
        "KiUserCallbackDispatcher", "KiUserApcDispatcher", "KiUserExceptionDispatcher",
    };
    for (int i = 0; i < (int)(sizeof(names)/sizeof(names[0])) && g_ntFuncCount < 24; i++) {
        void* p = (void*)GetProcAddress(h, names[i]);
        if (p) {
            g_ntFuncs[g_ntFuncCount].addr = (uintptr_t)p;
            g_ntFuncs[g_ntFuncCount].name = names[i];
            g_ntFuncs[g_ntFuncCount].count = 0;
            g_ntFuncCount++;
        }
    }
    for (int i = 1; i < g_ntFuncCount; i++) {  // insertion sort by address
        NtFunc t = g_ntFuncs[i]; int j = i - 1;
        while (j >= 0 && g_ntFuncs[j].addr > t.addr) { g_ntFuncs[j+1] = g_ntFuncs[j]; j--; }
        g_ntFuncs[j+1] = t;
    }
}

// Nearest key ntdll function at or below eip, within 64KB. Wait stubs are leaf
// syscalls so a blocked thread lands right on them (precise); heap internals are
// approximate but a heap-heavy cluster is still unmistakable.
static NtFunc* FindNtFunc(uintptr_t eip) {
    NtFunc* best = nullptr;
    for (int i = 0; i < g_ntFuncCount; i++) {
        if (g_ntFuncs[i].addr <= eip) best = &g_ntFuncs[i];
        else break;
    }
    if (best && (eip - best->addr) <= 0x10000) return best;
    return nullptr;
}

// ---- aggregation + dump -------------------------------------------
static void DumpResults() {
    uint64_t total = g_totalSamples;
    if (total == 0) {
        Log("[SamplingProfiler] No samples collected");
        return;
    }

    // Reset the per-page tally so DumpResults can be called repeatedly (the
    // periodic stats dump calls it every few minutes, not only at shutdown —
    // the shutdown path is often skipped on the fast process-exit, which lost
    // the profile entirely). Each call re-aggregates the current ring contents.
    memset(g_pageCounts, 0, sizeof(g_pageCounts));
    memset(g_selfPageCounts, 0, sizeof(g_selfPageCounts));
    memset(g_selfFineCounts, 0, sizeof(g_selfFineCounts));
    memset(g_wowFineCounts, 0, sizeof(g_wowFineCounts));

    // Snapshot loaded modules so system samples can be attributed to a DLL.
    BuildModuleTable();
    BuildNtFuncTable();

    // Buckets: one per named function, one "system_dll", plus one per non-empty
    // 4KB WoW page (so unlisted hot code is reported by address, not lumped into
    // a single opaque blob). Static (not on the stack) because of the page slots.
    static constexpr int MAX_BUCKETS = MAX_KNOWN_FUNCS + NUM_PAGES + SELF_PAGES + 128 + 24 + 1;
    static SampleBucket buckets[MAX_BUCKETS];
    int bucketCount = 0;

    // Initialize buckets from known funcs. The array is static and this runs on
    // every periodic report, so the offset histogram has to be cleared here as
    // well as the count - otherwise the second report annotates itself with the
    // first one's offsets.
    for (int i = 0; i < g_knownCount; i++) {
        buckets[bucketCount].addr  = g_knownFuncs[i].addr;
        buckets[bucketCount].name  = g_knownFuncs[i].name;
        buckets[bucketCount].count = 0;
        memset(buckets[bucketCount].offHist, 0, sizeof(buckets[bucketCount].offHist));
        bucketCount++;
    }

    // System (outside the WoW image) bucket
    int systemIdx = bucketCount;
    buckets[bucketCount].addr  = 0;
    buckets[bucketCount].name  = "system_dll";
    buckets[bucketCount].count = 0;
    bucketCount++;

    // Walk the ring buffer and bucket each sample.
    //
    // The ring holds RING_SIZE samples and a long session takes far more, so what
    // follows describes the last RING_SIZE of them and nothing before that. Every
    // percentage below is therefore a share of `n`, not of `total`, and getting
    // that wrong is not a rounding error: a three-hour session took 5853152
    // samples into a ring of 1048576, so dividing bucket counts by the lifetime
    // total understated every figure in the report by 5.6x. It made the client
    // look like it had no hot spot anywhere - the top fifty summed to 12% of a
    // profile where they are really 67% - and that false flatness was used to
    // decide what to optimise for a week.
    uint64_t n = (total < RING_SIZE) ? total : RING_SIZE;
    uint64_t startIdx = (total <= RING_SIZE) ? 0 : (total - RING_SIZE);

    for (uint64_t i = 0; i < n; i++) {
        uintptr_t eip = g_ring[(startIdx + i) % RING_SIZE];

        const FuncEntry* f = FindNearestFunc(eip);
        if (f) {
            // Find the bucket for this function (linear scan — only at
            // dump time, not on the hot path).
            for (int b = 0; b < g_knownCount; b++) {
                if (buckets[b].addr == f->addr) {
                    buckets[b].count++;
                    uintptr_t off = eip - f->addr;
                    buckets[b].offHist[(off >> 8) & 15u]++;
                    goto next_sample;
                }
            }
        }

        // Not matched to a named function: aggregate WoW samples per 4KB page,
        // our own DLL per 4KB page, and other non-WoW samples per owning module
        // (falling back to the opaque system bucket only when unresolved).
        if (eip >= WOW_BASE && eip <= WOW_END) {
            uintptr_t woff = eip - WOW_BASE;
            g_pageCounts[woff >> 12]++;
            uint32_t wfine = (uint32_t)(woff >> WOW_FINE_SHIFT);
            if (wfine < WOW_FINE_SLOTS) g_wowFineCounts[wfine]++;
        } else if (g_selfBase && eip >= g_selfBase && eip < g_selfEnd) {
            uintptr_t off = eip - g_selfBase;
            uint32_t pg = (uint32_t)(off >> 12);
            if (pg < SELF_PAGES) g_selfPageCounts[pg]++;
            uint32_t fine = (uint32_t)(off >> SELF_FINE_SHIFT);
            if (fine < SELF_FINE_SLOTS) g_selfFineCounts[fine]++;
        } else {
            ModRange* m = FindModule(eip);
            if (m) {
                if (g_ntdllBase && eip >= g_ntdllBase && eip < g_ntdllEnd) {
                    NtFunc* nf = FindNtFunc(eip);
                    if (nf) nf->count++;   // attributed to a known ntdll function
                    else    m->count++;    // ntdll but unrecognized -> stays in ntdll bucket
                } else {
                    m->count++;
                }
            } else {
                buckets[systemIdx].count++;
            }
        }
        next_sample:;
    }

    // Emit one bucket per non-empty page of our own DLL (labelled "wowopt+0x..").
    for (int p = 0; p < SELF_PAGES && bucketCount < MAX_BUCKETS; p++) {
        if (!g_selfPageCounts[p]) continue;
        buckets[bucketCount].addr  = g_selfBase + ((uintptr_t)p << 12);
        buckets[bucketCount].name  = nullptr;   // labelled by self-offset at print time
        buckets[bucketCount].count = g_selfPageCounts[p];
        bucketCount++;
    }

    // Emit one bucket per system module that got samples (labelled "sys:<dll>").
    for (int mi = 0; mi < g_modCount && bucketCount < MAX_BUCKETS; mi++) {
        if (!g_mods[mi].count) continue;
        buckets[bucketCount].addr  = g_mods[mi].base;
        buckets[bucketCount].name  = g_mods[mi].name;  // e.g. "d3d9.dll", "ntdll.dll"
        buckets[bucketCount].count = g_mods[mi].count;
        bucketCount++;
    }

    // Emit ntdll sub-function buckets (e.g. "ntdll!NtWaitForSingleObject") so the
    // big ntdll bucket is split into idle-wait vs heap vs locks.
    for (int i = 0; i < g_ntFuncCount && bucketCount < MAX_BUCKETS; i++) {
        if (!g_ntFuncs[i].count) continue;
        buckets[bucketCount].addr  = g_ntFuncs[i].addr;
        buckets[bucketCount].name  = g_ntFuncs[i].name;  // e.g. "NtWaitForSingleObject"
        buckets[bucketCount].count = g_ntFuncs[i].count;
        bucketCount++;
    }

    // Merge every non-empty page region as an address-labelled bucket.
    for (int p = 0; p < NUM_PAGES && bucketCount < MAX_BUCKETS; p++) {
        if (!g_pageCounts[p]) continue;
        buckets[bucketCount].addr  = WOW_BASE + ((uintptr_t)p << 12);
        buckets[bucketCount].name  = nullptr;   // labelled by address at print time
        buckets[bucketCount].count = g_pageCounts[p];
        bucketCount++;
    }

    // Sort by count descending
    std::sort(buckets, buckets + bucketCount,
              [](const SampleBucket& a, const SampleBucket& b) {
                  return a.count > b.count;
              });

    // A blocked thread is not a hot function, and must never be ranked as one.
    // The first version of this report excluded waits from the denominator but
    // still listed them, so NtDelayExecution appeared in a table of hot functions
    // holding "17.42% of executing" - a share of exactly the thing it was not
    // doing.
    // Separate "the thread was blocked" from "the thread was running code".
    //
    // Every sample landing in one of these is the main thread parked in the
    // kernel with nothing to do - waiting on the present queue, a vsync interval,
    // an event or an IO completion. Listing them by heat put
    // NtWaitForAlertByThreadId at the top of a table headed HOT FUNCTIONS, where
    // it reads as the most expensive thing in the client rather than as proof
    // that the client had no work at all. A tester session came back with 94.8%
    // of samples there: 0.9ms of CPU per 16.7ms frame, with every optimization in
    // this DLL competing for the remaining 5%.
    //
    // Knowing which side of that line a session falls on decides whether any CPU
    // work here can matter, so it is now the first thing the profile says.
    uint64_t waitSamples = 0;
    for (int i = 0; i < bucketCount; i++) {
        if (IsWaitSymbol(buckets[i].name)) waitSamples += buckets[i].count;
    }
    uint64_t workSamples = (n > waitSamples) ? (n - waitSamples) : 0;
    double   workPct     = n ? (100.0 * (double)workSamples / (double)n) : 0.0;

    Log("[SamplingProfiler] === MAIN THREAD: %.1f%% executing, %.1f%% blocked "
        "(%llu of the %llu most recent samples were a kernel wait; %llu taken in "
        "all, and everything below describes the recent ones) ===",
        workPct, 100.0 - workPct,
        (unsigned long long)waitSamples, (unsigned long long)n,
        (unsigned long long)total);
    if (total >= 1000) {
        if (workPct < 15.0) {
            Log("[SamplingProfiler]   The client is not CPU-bound here - it spends "
                "the frame waiting on the GPU, vsync or a frame limiter. CPU-side "
                "optimizations cannot show up in this session no matter how good "
                "they are; uncap the frame rate or profile a heavier scene to get "
                "a workload where they can.");
        } else if (workPct > 60.0) {
            Log("[SamplingProfiler]   The client IS CPU-bound here. The list below "
                "is where the frame time actually goes.");
        }

        // A frame-rate cap turns this verdict into a lie, and the lie is not
        // obvious: under a translation layer the wait for the next frame is a
        // busy-wait, so the thread reads as executing while doing nothing. An
        // eight-hour session came back reporting 99.2% executing with the whole
        // top fifty adding up to 2.9% of samples - the rest spread thinly across
        // a spin loop. Every percentage below is then a share of waiting.
        //
        // A median pinned within a few percent of a display interval is what a
        // cap looks like - but the median alone does not say it, and testing it
        // alone made this warning fire on a session that was not capped at all.
        //
        // A tester ran uncapped on 2026-08-18 and got 96.5% executing, then this
        // warning directly underneath, because the median was 20.00 ms and 20.00
        // is the 50 Hz interval. It was a client that was simply slow: p50 23.10
        // with p95 62.20, a tail nearly three times the middle. A limiter has no
        // tail - it holds every frame at the interval, which is exactly what makes
        // the median look pinned - so the spread is what separates the two, and
        // the median is only worth checking once the spread says it is flat.
        double med = FrameBench::MedianMs();
        double p95 = FrameBench::SessionP95Ms();
        bool   pinned = (med > 0.0 && p95 > 0.0 && p95 < med * 1.25);
        if (pinned) {
            const double kIntervals[] = { 16.667, 33.333, 8.333, 20.0, 11.111 };
            for (int i = 0; i < 5; i++) {
                double d = med - kIntervals[i];
                if (d < 0) d = -d;
                if (d < kIntervals[i] * 0.03) {
                    Log("[SamplingProfiler]   WARNING: the median frame is %.2f ms, "
                        "a %.0f Hz display interval, and the 95th is %.2f ms - the "
                        "distribution is flat against that interval, which is a cap "
                        "and not a workload. The split above therefore measures "
                        "waiting, not work, and the percentages below are shares of "
                        "a spin. Uncap the frame rate before drawing any conclusion "
                        "from this profile.", med, 1000.0 / kIntervals[i], p95);
                    break;
                }
            }
        }
    }

    // Dump top-N (named functions and hot unlisted regions intermixed by heat).
    // Two percentages: of everything, and of the time the thread was running -
    // the second is the one that says how much of a real optimization target
    // something is, and it is the one that was missing.
    // A count here is the whole named function, however large, and it is self
    // time: a sample lands on the innermost function that was executing, so a
    // caller is not charged for what its callees did. Both halves of that have
    // been misread from these logs. A "+0x600" suffix marks where inside the
    // function the samples concentrated and never splits the count, and a
    // function whose children do the work reads as small here while an inclusive
    // timer around the same call reads as large - which is how M2_AnimateModel
    // came to be 0.17% in this table and 2.47 ms of a 23.4 ms frame in the
    // animation census on the same day. Neither instrument was wrong.
    Log("[SamplingProfiler] === TOP %d HOT FUNCTIONS/REGIONS - self time, whole "
        "function; a +0xNNN suffix is where the weight sits, not a split "
        "(shares of the %llu most recent samples, %llu idle ticks during "
        "loading/warmup where the main thread was left alone) ===",
        TOP_N, (unsigned long long)n, (unsigned long long)g_skippedSamples);

    int printed = 0;
    for (int i = 0; i < bucketCount && printed < TOP_N; i++) {
        if (buckets[i].count == 0) break;
        double pct = 100.0 * (double)buckets[i].count / (double)n;
        char label[40];
        const char* name;
        if (buckets[i].name) {
            name = buckets[i].name;

            // A named symbol claims every sample within 4 KB after it, and the
            // offset used to be discarded - so a line reading "tostring 4.73%"
            // could be luaB_tostring itself or any unnamed function in the four
            // kilobytes following it, with nothing to tell the two apart. That
            // is a lot of Lua library code to hang on one dispatcher, and it was
            // read as exact.
            //
            // So when the samples are not concentrated at the start, say where
            // they actually are. The offset resolves to exactly one function in
            // a disassembler, which is what makes the number worth acting on.
            int domIdx = 0;
            uint32_t domCount = buckets[i].offHist[0];
            uint32_t histTotal = buckets[i].offHist[0];
            for (int h = 1; h < 16; h++) {
                histTotal += buckets[i].offHist[h];
                if (buckets[i].offHist[h] > domCount) {
                    domCount = buckets[i].offHist[h];
                    domIdx = h;
                }
            }
            // Only annotate when the weight really sits past the first 256 bytes;
            // a symbol whose samples are in its own prologue needs no comment.
            if (domIdx > 0 && histTotal > 0 &&
                buckets[i].offHist[0] * 2u < histTotal) {
                wsprintfA(label, "%.20s+0x%03X", buckets[i].name,
                          (unsigned)(domIdx << 8));
                name = label;
            }
        } else if (g_selfBase && buckets[i].addr >= g_selfBase && buckets[i].addr < g_selfEnd) {
            // A hot page inside our own DLL — label by offset from our base so it
            // maps directly to wow_optimize.map (which of our hooks costs time).
            uintptr_t delta = 0;
            const char* sym = ResolveSelfSymbol(buckets[i].addr, &delta);
            if (sym && delta < kSelfSymbolTrusted) wsprintfA(label, "wowopt!%.24s", sym);
            else if (sym) wsprintfA(label, "wowopt!%.16s+0x%X", sym, (unsigned)delta);
            else     wsprintfA(label, "wowopt+0x%05X", (unsigned)(buckets[i].addr - g_selfBase));
            name = label;
        } else {
            // Unlisted WoW code region. Labelling it by page base alone was not
            // enough to act on: a 4KB page holds a dozen functions, and even the
            // 512-byte histogram below spans about five, so "6.76% is in this
            // region" never identified anything. The raw sample addresses are
            // still in the ring at this point, so name the single hottest
            // instruction in the page as well - that one resolves to exactly one
            // function in a disassembler.
            uintptr_t peak = HottestAddressInPage(buckets[i].addr);
            if (peak) wsprintfA(label, "wow!0x%08X", (unsigned)peak);
            else      wsprintfA(label, "wow_region_0x%08X", (unsigned)buckets[i].addr);
            name = label;
        }
        if (IsWaitSymbol(buckets[i].name)) {
            Log("[SamplingProfiler] %3d. %-24s  %8llu samples (%5.2f%% total, blocked - not executing)",
                printed + 1, name, (unsigned long long)buckets[i].count, pct);
        } else {
            double workPctOfEntry = workSamples
                ? (100.0 * (double)buckets[i].count / (double)workSamples) : 0.0;
            Log("[SamplingProfiler] %3d. %-24s  %8llu samples (%5.2f%% total, %5.2f%% of executing)",
                printed + 1, name, (unsigned long long)buckets[i].count, pct, workPctOfEntry);
        }
        printed++;
    }

    // Our own hot spots at 256-byte resolution, then the client's at 512-byte.
    // Both are narrow enough to land on a single function, which the 4KB page
    // buckets in the ranking above cannot do.
    DumpFineHistogram(g_selfFineCounts, SELF_FINE_SLOTS, SELF_FINE_SHIFT, n,
                      "wow_optimize.dll HOT SPOTS (256-byte resolution)", "wowopt+0x%05X", 0);
    DumpFineHistogram(g_wowFineCounts, WOW_FINE_SLOTS, WOW_FINE_SHIFT, n,
                      "wow.exe HOT SPOTS (512-byte resolution)", "0x%08X", WOW_BASE);

    DumpHottestForeignModule(g_ring, startIdx, n, total);

    DumpWorkerThreads(total);

    // Which addon the Lua time belonged to. Same samples, read a second way:
    // the list above says which code ran, this says whose code it was.
    LuaAddonSampler::Report();

    Log("[SamplingProfiler] === END PROFILE ===");
}

// ---- public API ---------------------------------------------------
bool Init(HANDLE mainThread) {
    if (!g_ring) {
        // VirtualAlloc returns zeroed pages, which is what the ring wants anyway.
        g_ring = (volatile uintptr_t*)VirtualAlloc(nullptr, RING_BYTES,
                                                   MEM_COMMIT | MEM_RESERVE,
                                                   PAGE_READWRITE);
        if (!g_ring) {
            Log("[SamplingProfiler] Could not commit %zu KB for the sample ring - disabled",
                RING_BYTES / 1024);
            return false;
        }
    }
    if (!mainThread) return false;

    // Duplicate so this module owns an independent, long-lived handle —
    // the caller only needs the thread open for the duration of this call
    // and closes its own copy right after Init() returns, but the sampler
    // thread below uses g_mainThread for the rest of the process lifetime.
    if (!DuplicateHandle(GetCurrentProcess(), mainThread, GetCurrentProcess(),
                          &g_mainThread, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        Log("[SamplingProfiler] FAILED to duplicate main thread handle (err=%u)", GetLastError());
        return false;
    }
    g_writeIdx = 0;
    g_totalSamples = 0;
    g_skippedSamples = 0;
    g_samplerStartTick = 0;  // re-arm the warmup window on (re)start
    if (g_ring) memset((void*)g_ring, 0, RING_BYTES);
    memset(g_pageCounts, 0, sizeof(g_pageCounts));

    BuildKnownFuncTable();

    g_running = true;
    g_samplerThread = CreateThread(
        nullptr,
        64 * 1024,           // small stack — we barely use any
        SamplerThreadProc,
        nullptr,
        0,                   // run immediately
        nullptr
    );

    if (!g_samplerThread) {
        Log("[SamplingProfiler] FAILED to create sampler thread (err=%u)", GetLastError());
        g_running = false;
        CloseHandle(g_mainThread);   // release the handle duplicated above
        g_mainThread = nullptr;
        return false;
    }

    // Lowest priority — never compete with WoW's threads
    SetThreadPriority(g_samplerThread, THREAD_PRIORITY_IDLE);

    Log("[SamplingProfiler] INIT (interval=%dms, known_funcs=%d, ring=%d entries)",
        SAMPLE_INTERVAL_MS, g_knownCount, RING_SIZE);
    return true;
}

void Shutdown() {
    if (!g_running) return;

    g_running = false;

    // Wait for the sampler thread to exit (it checks g_running each iteration)
    if (g_samplerThread) {
        WaitForSingleObject(g_samplerThread, 2000);
        CloseHandle(g_samplerThread);
        g_samplerThread = nullptr;
    }

    DumpResults();

    if (g_mainThread) {
        CloseHandle(g_mainThread);
        g_mainThread = nullptr;
    }

    Log("[SamplingProfiler] SHUTDOWN (total_samples=%llu)",
        (unsigned long long)g_totalSamples);
}

bool IsActive() { return g_running; }

uint64_t GetSampleCount() { return g_totalSamples; }

// Dump the current top-50 without stopping the sampler. Safe to call from the
// main thread while sampling continues (it only reads the ring). Used by the
// periodic stats dump so the profile survives the fast process-exit path that
// skips Shutdown().
void DumpNow() {
    if (!g_running) return;
    DumpResults();
}

} // namespace SamplingProfiler