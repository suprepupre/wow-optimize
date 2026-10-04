// ============================================================================
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
#include <cstdlib>
#include <algorithm>
#include "sampling_profiler.h"
#include "freeze_catcher.h"
#include "session_verdict.h"
#include "lua_addon_sampler.h"
#include "frame_bench.h"
#include "version.h"
#include "high_tables.h"
#pragma comment(lib, "psapi.lib")

extern "C" void Log(const char* fmt, ...);

// Forward decl (avoid pulling in the whole lua_optimize header here). Returns
// true while a zone/UI load or transition is in progress.
namespace LuaOpt { bool IsLoadingMode(); }

// Declared rather than included: loading_state.h pulls in the write batcher.
//
// At file scope on purpose. Written inside namespace SamplingProfiler it
// becomes SamplingProfiler::LoadingState::IsLoading, which compiles and then
// fails to link against a name nothing defines - the same shape as a
// namespace opened inside an anonymous one, which cost a link error in
// loading_state.cpp the same week.
namespace LoadingState { bool IsLoading(); }

namespace SamplingProfiler {

// Samples taken during loading screens / the first few seconds after start are
// not representative of steady-state play (they're dominated by MPQ/DBC load,
// hook install and page faults). Excluding them makes the profile reflect what
// actually costs frame time in the world. Counted separately for transparency.
static DWORD    g_samplerStartTick = 0;
static uint64_t g_skippedSamples = 0;
// The share of main-thread samples that were executing rather than blocked in
// a kernel wait, from the most recent report. Negative until one has run, so a
// caller can tell "not measured" from "measured and low".
static double   g_lastWorkPct     = -1.0;
static uint64_t g_lastWorkSamples = 0;
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
// Fine-grained buckets over wow.exe, 512 bytes each. Declared here rather than
// beside the dump because the sampler fills a second copy of them live.
static constexpr int WOW_FINE_SHIFT = 9;
static constexpr int WOW_FINE_SLOTS = (int)((WOW_END - WOW_BASE) >> WOW_FINE_SHIFT) + 1;

// That second copy, filled only while a loading screen is up.
//
// A tester loading screen took 25 seconds. The loading timer accounts for two
// percent of it in ReadFile and ten percent in the client's own file writes. The
// other eighty-eight has never been attributed to anything, and loading screens
// are the complaint this project hears most.
//
// The ring the main report reads is a window of recent samples, so a load that
// happened twenty minutes ago has rolled out of it. This accumulates instead,
// live, at one shift and one increment per sample - which is why it is a fine
// histogram and not a function lookup. Naming happens at dump time, against the
// same symbol table the rest of the report uses.
static uint32_t g_loadFineCounts[WOW_FINE_SLOTS];
// A copy of the above taken when a loading screen starts, so the one that just
// finished can be reported on its own. 64 KB, written once per load.
static uint32_t g_loadWindowBase[WOW_FINE_SLOTS];
static uint64_t g_loadWindowInWow = 0;
static uint64_t g_loadWindowTotal = 0;
static bool     g_loadWindowOpen  = false;
static uint64_t g_loadSamples   = 0;   // taken while loading, anywhere
static uint64_t g_loadInWow     = 0;   // and of those, inside wow.exe
static uint64_t g_loadInSelf    = 0;   // inside this DLL
static uint64_t g_loadElsewhere = 0;   // a system DLL, the driver, a wait

// This DLL's own mapped range. Declared here because the sampler classifies a
// loading-screen sample by it before the dump code that used to own it.
static uintptr_t g_selfBase = 0;
static uintptr_t g_selfEnd  = 0;

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

// Who called the code a sample landed in, for samples outside the client and this
// DLL: a wait in ntdll, Direct3D in the translation layer, the driver. The ranking
// above says the main thread was in d3d9.dll 8% of the time, or blocked in a wait
// for IO completion 3% of it, and not which client function asked. Kept for the
// whole session in a small table, keyed by the address and the nearest return
// address into wow.exe or this DLL found on the stack, counted only for samples
// that are in neither of them.
struct CallerRow { uintptr_t eip; uintptr_t caller; uint32_t n; };
static constexpr int CALLER_SLOTS = 4096;
static CallerRow g_callerRows[CALLER_SLOTS];
static uint32_t  g_callerLost = 0;          // rows that did not fit
static uint64_t  g_callerSamples = 0;       // samples counted into the table
static uint64_t  g_callerNoCaller = 0;      // of those, ones with no return address found

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
        { 0x004C1B90,    86, "CMatrix::ScaleLocal" },
        { 0x004C1BF0,    80, "CMatrix::Scale3x3" },
        { 0x004C1C40,   170, "CMatrix::FromQuaternion" },
        { 0x004C1F00,   533, "CMatrix::Multiply" },
        { 0x004C2120,   140, "CMatrix::ScalarMul" },
        { 0x004C21B0,    93, "sub_4C21B0_pt_x_mat4" },
        { 0x004C2210,    93, "RowAffinePoint" },
        { 0x004C2270,   140, "sub_4C2270_vec4_x_mat4" },
        { 0x004C2300,   111, "InPlacePointXform" },
        { 0x004C2370,    43, "CMatrix::MultiplyInPlace" },
        { 0x004C23D0,   104, "CMatrix::Transpose" },
        { 0x004C2440,  2892, "CMatrix_AdjugateDet" },
        { 0x004C2FC0,   212, "CMatrix::InvertRigid" },
        { 0x004C31B0,   103, "CMatrix::CreateRotateX" },
        { 0x004C3220,   103, "CMatrix::CreateRotateY" },
        { 0x004C3290,   103, "CMatrix::CreateRotateZ" },
        { 0x004C3300,    60, "CMatrix::RotateX" },
        { 0x004C3340,    60, "CMatrix::RotateY" },
        { 0x004C3380,    60, "CMatrix::RotateZ" },
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
        { 0x0048BD20,   186, "Color_PackBGRA" },
        { 0x00490770,   193, "UIFrame_OnUpdateTree" },
        { 0x00532AF0,     7, "Renderer_GetColorFmtBlock" },
        { 0x006C4440,   877, "Particle_FillVertices" },
        { 0x00774640,     8, "EnterCriticalSection_wrap" },
        { 0x00774650,     8, "LeaveCriticalSection_wrap" },
        { 0x00817DB0,     6, "GetLuaState" },
        { 0x008B7DA0,     3, "ReturnThis" },
        { 0x00855670,   102, "LuaMemPool_Free" },
        // UI frame hierarchy update and culling traversal
        { 0x00494A10,   214, "CFrameManager::OnUpdate" },
        { 0x00495320,   230, "CFrameStrataManager::OnUpdate" },
        { 0x007A50C0,   384, "Scene_VisibilityTraverse" },
        { 0x007C6D50,  1166, "Collision_ClipVertsToBox" },
        { 0x0078F370,    39, "AABB_Overlap" },
        // Classifies every vertex of a collision model against the query box
        // as a six-bit outcode, four vertices per unrolled pass, then tests
        // each triangle by ANDing its three. Called once per line-of-sight or
        // pick ray from sub_7C9A00. The six bounds live on the x87 stack for
        // the whole loop, which is why 158 of its 418 instructions are x87.
        // Named from a profile before anyone had read it. It contains the same
        // bone matrix transpose as sub_829BA0, in a second draw path, and
        // BoneMatrixUpload patches all three (sub_829BA0, sub_8203B0, sub_820AE0).
        { 0x008203B0,   872, "M2_BoneMatrixUploadB" },
        { 0x00820AE0,  1109, "M2_BoneMatrixUploadC" },
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

        // The four blocks the fld/fstp scan found and nothing has ever claimed.
        // None of them has profile evidence, which is exactly why they are here:
        // the fine histogram reports raw addresses for anything hot, and a raw
        // address needs this build's linker map to resolve. Named, one uncapped
        // session answers whether any of them is worth replacing, and the answer
        // may well be no.
        //
        // Each holds a run of pure fld/fstp with no arithmetic between - the one
        // shape that vectorises with no precision argument at all. See
        // m2_matrix_slot_sse2.cpp for what claiming one looks like.
        { 0x00823130,  2909, "PureFloatMove_sub823130" },   // 32/32 block at 0x008236B3 (vectorized by m2_batch_matrix_sse2.cpp)
        { 0x008EDFC0,  2410, "PureFloatMove_sub8EDFC0" },   // 24/24 at 0x008EE463, 0x008EE746
        { 0x007762A0,  1303, "PureFloatMove_sub7762A0" },   // 20/20 at 0x00776448
        { 0x0094A440,   785, "PureFloatMove_sub94A440" },   // 21/21 at 0x0094A649
        { 0x00828680,   885, "M2_AnimTrackQuat" },
        // 3.35% of executing time in the corrected profile, and it showed as
        // "wow!0x00829D29" - a raw address that cost a func_profile call to place.
        // The loop it names transposes a 4x4 bone matrix into three vec4s with
        // twelve x87 load/store pairs; BoneMatrixUpload replaces it.
        { 0x00829BA0,   660, "M2_BoneMatrixUpload" },
        { 0x00829E40,   247, "M2_BoneMatrixUploadOuter" },  // its only caller
        // Quaternion track, not a vector one: it unpacks each component from
        // a uint16 as (double)v * 0.000030518044 - 1.0, eight or sixteen times
        // per call, each through a store and an fild.
        { 0x008284D0,   420, "M2_AnimTrackFindKey" },
        // The keyframe search shared by all nine track evaluators. Hinted by
        // the caller's last index, with a binary search for a jump over 500ms
        // and a double division for the interpolation factor at the end.
        { 0x0082B0A0,   450, "M2_AnimTrackInterp" },
        { 0x0082AF40,   345, "M2_AnimTrackScalar" },        // packed int16 scalar (vectorized by anim_scalar_track_sse2.cpp)
        { 0x0082B340,   273, "M2_AnimTrackColor" },         // float scalar (vectorized by anim_scalar_track_sse2.cpp)
        { 0x0082B460,  1081, "M2_AnimTrackSpline" },        // 3D vector cubic spline (vectorized by anim_spline_track_sse2.cpp)
        { 0x0082B8A0,   681, "M2_AnimTrackSplineScalar" },  // scalar cubic spline (vectorized by anim_spline_track_sse2.cpp)
        { 0x007F9430,    66, "AABB_Transform" },             // 4x4 matrix * AABB (vectorized by aabb_transform_sse2.cpp)
        { 0x007F93D0,    91, "AABB_Transform3x3" },          // 3x3 matrix * AABB (vectorized by aabb_transform_sse2.cpp)
        { 0x007F9320,   171, "AABB_TransformCore_Arvo" },     // Arvo bounding box transformation core
        { 0x00714D10,    78, "Vec3_Min" },
        { 0x00714D70,    78, "Vec3_Max" },
        { 0x00715130,   100, "CAxisAlignedBox::Union" },
        { 0x007CCE00,   403, "Occluder_TestSphere" },        // sphere occluder culling (vectorized by occluder_sphere_sse2.cpp)
        { 0x007CCFA0,   404, "Occluder_TestPolygon" },       // polygon/mesh occluder culling (vectorized by occluder_sphere_sse2.cpp)
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
        { 0x004C1B30,    90, "CMatrix::TranslateLocal" },
        { 0x004C1B90,    86, "CMatrix::ScaleLocal" },
        { 0x004C1BF0,    80, "CMatrix::Scale3x3" },
        { 0x004C1C40,   170, "QuatToMatrix" },
        { 0x004C1F00,   533, "CMatrix::Multiply" },
        { 0x004C21B0,    93, "CMatrix::MatVec3Mul" },
        { 0x004C2270,   140, "CMatrix::MatVec4Mul" },
        { 0x004C2300,   111, "CMatrix::PointTransformInPlace" },
        { 0x004C2370,    43, "CMatrix::MultiplyInPlace" },
        { 0x004C2FC0,   212, "CMatrix::InvertRigid" },
        { 0x004C31B0,   103, "CMatrix::CreateRotateX" },
        { 0x004C3220,   103, "CMatrix::CreateRotateY" },
        { 0x004C3290,   103, "CMatrix::CreateRotateZ" },
        { 0x004C3300,    60, "CMatrix::RotateX" },
        { 0x004C3340,    60, "CMatrix::RotateY" },
        { 0x004C3380,    60, "CMatrix::RotateZ" },
        { 0x004C33C0,    82, "CMatrix::RotateQuat" },
        { 0x004C3420,    53, "Vec3_Normalize" },
        { 0x004C3460,   307, "CMatrix::CreateRotateAxisAngle" },
        { 0x004C35A0,    34, "Vec3_Scale" },
        { 0x004C35D0,    34, "Vec3_InvScale" },
        { 0x004C3600,    67, "Vec4_Normalize" },
        { 0x005FEC70,    60, "C3Vector::Cross" },
        { 0x005FECB0,    58, "CBox::Scale" },
        { 0x005FED20,    84, "VectorMatrixRotate" },
        { 0x00821A20,  5658, "M2_DrawBatchBuilder" },
        { 0x00960D20,   154, "Lua_Model_SetLight" },
        { 0x00979110,    84, "CQuaternion::Normalize" },
        { 0x00981D40,   936, "ParticleSpawn_Init" },
        { 0x00982400,    85, "CQuaternion::FromAngleAxis" },
        { 0x00982460,   268, "CQuaternion::Slerp" },
        { 0x00982630,   111, "Quat_Lerp" },
        { 0x00982970,    61, "Color_UnpackBGR" },
        { 0x009829B0,    61, "Vec3_DominantAxis" },
        { 0x009829F0,    67, "Vec3_RecessiveAxis" },
        { 0x00982FB0,   283, "RayPlaneIntersect" },
        { 0x009830D0,   957, "PointInPolygon2D" },
        { 0x00983490,   537, "RayTriIntersect16" },
        { 0x009836B0,   535, "RayTriIntersect32" },
        { 0x00983990,    67, "CFrustum::GetAABB" },
        { 0x009839E0,   124, "CFrustum::IsAABBVisible" },
        { 0x00983A60,   124, "CFrustum::IsAABBInside" },
        { 0x00983AE0,   560, "CFrustum::Translate" },
        { 0x00983D20,    79, "CFrustum::IsSphereVisible" },
        { 0x00983D70,   241, "CFrustum::IsPointVisible" },  // vectorized by frustum_aabb_sse2.cpp
        { 0x00984860,   198, "AABB_TransformAffine" },
        { 0x00984930,   829, "AABB_FromVertices" },
        { 0x00984C90,    76, "Color_UnpackBGRA" },
        { 0x00984F60,   193, "Color_RGBToHSV" },
        { 0x00985030,   334, "Color_HSVToRGB" },
        { 0x009851A0,    91, "Color_PackBGR" },

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
    // No fixed window: function sizes here run from 17 bytes to 6 kilobytes, so
    // any window names a neighbour with complete confidence. A 4KB one put
    // "tostring+0xE00" second overall at 4.29% of executing time, 3.5KB past the
    // end of a 229-byte function and inside the Lua pool's block allocator.
    //
    // The table carries each function's exact length, read out of the binary.
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

static bool ReadWordSafe(uintptr_t a, uintptr_t* out) {
    if (a < 0x10000u || (a & 3u)) return false;
    __try { *out = *(const volatile uintptr_t*)a; return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// A word on the stack that is a return address: a code address in the client or
// this DLL whose preceding bytes are a call (E8 rel32, FF /2 with a register or
// a displacement). Not exact; the first match nearest the stack pointer is the
// nearest caller, which is what is wanted.
static bool LooksLikeReturn(uintptr_t v) {
    const bool inWow  = v >= WOW_BASE && v <= WOW_END;
    const bool inSelf = g_selfBase && v >= g_selfBase && v < g_selfEnd;
    if (!inWow && !inSelf) return false;
    if ((v & 0xFFFF) < 8) return false;     // an image base on the stack, not a return address
    __try {
        const uint8_t* p = (const uint8_t*)v;
        return p[-5] == 0xE8 || p[-2] == 0xFF || p[-3] == 0xFF || p[-6] == 0xFF || p[-7] == 0xFF;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Called while the main thread is suspended, so its stack cannot change.
static void NoteForeignCaller(const CONTEXT& ctx, uintptr_t eip) {
    if (eip >= WOW_BASE && eip <= WOW_END) return;
    if (g_selfBase && eip >= g_selfBase && eip < g_selfEnd) return;
    uintptr_t caller = 0;
    uintptr_t sp = (uintptr_t)ctx.Esp, w = 0;
    for (int i = 0; i < 256; ++i, sp += sizeof(uintptr_t)) {
        if (!ReadWordSafe(sp, &w)) break;
        if (LooksLikeReturn(w)) { caller = w; break; }
    }
    ++g_callerSamples;
    if (!caller) ++g_callerNoCaller;
    uint32_t h = (uint32_t)((eip * 2654435761u) ^ (caller * 40503u)) & (CALLER_SLOTS - 1);
    for (int step = 0; step < CALLER_SLOTS; ++step, h = (h + 1) & (CALLER_SLOTS - 1)) {
        CallerRow& r = g_callerRows[h];
        if (r.n == 0) { r.eip = eip; r.caller = caller; r.n = 1; return; }
        if (r.eip == eip && r.caller == caller) { ++r.n; return; }
    }
    ++g_callerLost;
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
        // Decide before sampling, not after. A discarded sample costs the same
        // as a kept one - suspend, context read, resume - a thousand times a
        // second against a thread decompressing its way through a zone load and
        // holding the allocator and archive locks. A reporter traced their long
        // loading screens to this profiler being on.
        //
        // The main thread is touched only when the sample will be kept, and the
        // loop idles instead of spinning at the
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
            if (GetThreadContext(g_mainThread, &ctx)) {
                eip = (uintptr_t)ctx.Eip;
                NoteForeignCaller(ctx, eip);
            }

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

                // A second, accumulating histogram for loading screens only.
                // One atomic load and one increment; the naming is deferred.
                if (::LoadingState::IsLoading()) {
                    ++g_loadSamples;
                    if (eip >= WOW_BASE && eip <= WOW_END) {
                        ++g_loadInWow;
                        uint32_t lf = (uint32_t)((eip - WOW_BASE) >> WOW_FINE_SHIFT);
                        if (lf < WOW_FINE_SLOTS) g_loadFineCounts[lf]++;
                    } else if (g_selfBase && eip >= g_selfBase && eip < g_selfEnd) {
                        ++g_loadInSelf;
                    } else {
                        ++g_loadElsewhere;
                    }
                }
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

// Our own functions, by absolute address, so a hot spot inside this DLL prints a
// name instead of an offset nobody can resolve without the matching .map. The
// DLL installs a few hundred detours and every one registers itself, so leave
// room: a table that fills up silently leaves the hot code it would have named
// indistinguishable from code nobody registered.
static constexpr int MAX_SELF_SYMBOLS = 512;
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

// Called from the one wrapper every hook in this project passes through, so a
// detour installed anywhere gets a name without its module having to remember.
//
// The name is the address being hooked, which is what a reader wants: seeing
// "hook@00489710" beside a hot offset says the time is in our detour on the UI
// layout relink, and no linker map is needed to know it. RegisterSelfSymbol
// keeps the pointer rather than a copy, so the text has to outlive the call -
// hence the fixed pool rather than a local buffer.
extern "C" void WowOpt_NoteDetour(uintptr_t target, const void* detour) {
    if (!detour) return;
    static char  s_names[MAX_SELF_SYMBOLS][48];
    static int   s_used = 0;
    if (s_used >= MAX_SELF_SYMBOLS) return;
    char* n = s_names[s_used];
    // A detour on a system function says which one: "hook@kernel32!Sleep" says
    // what the time is spent in, where "hook@771AE5B0" was an address that is
    // different on every Windows build and meant nothing in a tester's log. The
    // client's own addresses stay as they were, since those are what this
    // project reads in IDA.
    char ex[40];
    if ((target < 0x00400000u || target > 0x00BFFFFFu) && FreezeCatcher::NameExport(target, ex, sizeof(ex)))
        wsprintfA(n, "hook@%s", ex);
    else
        wsprintfA(n, "hook@%08X", (unsigned)target);
    s_used++;
    RegisterSelfSymbol(n, detour);
}

// Every function in this DLL, read from wow_optimize.sym beside the DLL.
//
// The registered symbols below are entry points with no size, which is why a
// sample landing in an unregistered neighbour used to be printed under the name
// above it. The linker map has every function and its address; the build turns
// it into this file. With it loaded, a symbol owns the bytes up to the next
// one, so an address resolves to exactly one function or to nothing.
//
// The file is optional. Without it everything below works as it did, and the
// profile header says which of the two it is.
struct MapSym { uint32_t rva; const char* name; };
static MapSym*  g_mapSyms = nullptr;
static int      g_mapSymCount = 0;
static char*    g_mapText = nullptr;
static bool     g_mapTried = false;
static char     g_mapWhy[160] = "";

static int __cdecl MapSymLess(const void* a, const void* b) {
    const uint32_t ra = ((const MapSym*)a)->rva, rb = ((const MapSym*)b)->rva;
    return ra < rb ? -1 : (ra > rb ? 1 : 0);
}

static void LoadMapSymbols() {
    if (g_mapTried) return;
    g_mapTried = true;
    if (!g_selfBase) { lstrcpynA(g_mapWhy, "our own module was not identified", sizeof(g_mapWhy)); return; }

    char path[MAX_PATH];
    if (!GetModuleFileNameA((HMODULE)g_selfBase, path, sizeof(path))) {
        lstrcpynA(g_mapWhy, "the DLL's own path could not be read", sizeof(g_mapWhy));
        return;
    }
    int n = lstrlenA(path);
    while (n > 0 && path[n - 1] != '.') --n;
    if (n == 0 || n + 4 >= MAX_PATH) { lstrcpynA(g_mapWhy, "the DLL's path has no extension", sizeof(g_mapWhy)); return; }
    lstrcpyA(path + n, "sym");

    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        snprintf(g_mapWhy, sizeof(g_mapWhy), "no symbol file beside the DLL (%s)", path);
        return;
    }
    DWORD size = GetFileSize(h, nullptr);
    if (size == INVALID_FILE_SIZE || size == 0 || size > (16u << 20)) {
        CloseHandle(h);
        lstrcpynA(g_mapWhy, "the symbol file is empty or implausibly large", sizeof(g_mapWhy));
        return;
    }
    g_mapText = (char*)VirtualAlloc(nullptr, size + 1, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                    PAGE_READWRITE);
    DWORD got = 0;
    if (!g_mapText || !ReadFile(h, g_mapText, size, &got, nullptr) || got != size) {
        CloseHandle(h);
        if (g_mapText) { VirtualFree(g_mapText, 0, MEM_RELEASE); g_mapText = nullptr; }
        lstrcpynA(g_mapWhy, "the symbol file could not be read", sizeof(g_mapWhy));
        return;
    }
    CloseHandle(h);
    g_mapText[size] = 0;

    int lines = 0;
    for (DWORD i = 0; i < size; ++i) if (g_mapText[i] == '\n') ++lines;
    g_mapSyms = (MapSym*)VirtualAlloc(nullptr, (SIZE_T)(lines + 1) * sizeof(MapSym),
                                      MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
    if (!g_mapSyms) {
        VirtualFree(g_mapText, 0, MEM_RELEASE); g_mapText = nullptr;
        lstrcpynA(g_mapWhy, "the symbol table could not be committed", sizeof(g_mapWhy));
        return;
    }

    char* p = g_mapText;
    while (*p) {
        char* line = p;
        while (*p && *p != '\n') ++p;
        if (*p) *p++ = 0;
        int len = lstrlenA(line);
        if (len && line[len - 1] == '\r') line[len - 1] = 0;
        if (line[0] != '0' || line[1] != 'x') continue;
        uint32_t rva = 0;
        char* q = line + 2;
        while (*q && *q != ' ') {
            const char c = *q;
            uint32_t d;
            if (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
            else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
            else break;
            rva = rva * 16 + d;
            ++q;
        }
        if (*q != ' ') continue;
        ++q;
        if (!*q) continue;
        g_mapSyms[g_mapSymCount].rva = rva;
        g_mapSyms[g_mapSymCount].name = q;
        ++g_mapSymCount;
    }
    qsort(g_mapSyms, (size_t)g_mapSymCount, sizeof(MapSym), MapSymLess);
    if (g_mapSymCount == 0) lstrcpynA(g_mapWhy, "the symbol file held no usable lines", sizeof(g_mapWhy));
}

// Index of the first symbol sharing the address that owns this RVA, or -1.
static int MapSymbolIndex(uint32_t rva) {
    if (!g_mapSymCount) return -1;
    int lo = 0, hi = g_mapSymCount - 1, best = -1;
    while (lo <= hi) {
        const int mid = (lo + hi) / 2;
        if (g_mapSyms[mid].rva <= rva) { best = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    if (best < 0) return -1;
    while (best > 0 && g_mapSyms[best - 1].rva == g_mapSyms[best].rva) --best;
    return best;
}

// One counter per symbol in the map, so a sample in our own DLL is credited to
// the function it landed in. The 4 KB page buckets this replaces were labelled
// with the function at the page's first byte, which is not where the samples
// were: a tester profile put 3% on BatchColourConvert::Shutdown, a function that
// runs once at exit, because the page it sits at the start of holds a hot one.
static uint32_t* g_selfSymCounts = nullptr;
static int       g_selfSymCap    = 0;

// The function that owns this address, bounded by the next symbol, or null.
static const char* ResolveMapSymbol(uintptr_t addr, uintptr_t* outDelta) {
    if (!g_mapSymCount || !g_selfBase || addr < g_selfBase || addr >= g_selfEnd) return nullptr;
    const uint32_t rva = (uint32_t)(addr - g_selfBase);
    int lo = 0, hi = g_mapSymCount - 1, best = -1;
    while (lo <= hi) {
        const int mid = (lo + hi) / 2;
        if (g_mapSyms[mid].rva <= rva) { best = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    if (best < 0) return nullptr;
    // Several names can share an address after identical code folding; the
    // first of them is as good an answer as any, and the bound is the next
    // address that differs.
    int next = best;
    while (next < g_mapSymCount && g_mapSyms[next].rva == g_mapSyms[best].rva) ++next;
    const uint32_t end = (next < g_mapSymCount) ? g_mapSyms[next].rva : 0xFFFFFFFFu;
    if (rva >= end) return nullptr;
    if (outDelta) *outDelta = rva - g_mapSyms[best].rva;
    return g_mapSyms[best].name;
}

// Nearest registered symbol at or below addr, within a sane distance. The bound
// matters: without it every unregistered hot spot would be attributed to whichever
// registered function happens to sit lowest in the image, which is worse than
// admitting we do not know.
static const char* ResolveSelfSymbol(uintptr_t addr, uintptr_t* outDelta = nullptr) {
    // The map, when it is there, answers exactly; the entry points are the
    // fallback and are a guess past the first few hundred bytes.
    if (const char* exact = ResolveMapSymbol(addr, outDelta)) return exact;
    const char* best = nullptr;
    // Was 16 KB. Nothing here knows a detour's size, so every byte of that
    // distance is a chance to name an unregistered neighbour instead: a tester
    // profile put "wowopt!hook@00875F80+0x1AD0" ninth in its top fifty, and
    // 6.8 KB past an entry point is not that entry point. Four KB is still
    // generous for one function and is as far as a guess is worth making.
    uintptr_t bestDelta = 0x1000;   // 4 KB
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

// The 4KB page above ranks our DLL against everything else but cannot say WHICH
// hook is hot: at this build's code density a page holds about nineteen
// functions, so a page reading 1.97% could be one expensive hook or nineteen
// cheap ones.
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

// ---- executing time by subsystem --------------------------------------------
//
// The function list is flat - the hottest client function is a few percent - and
// a flat list cannot say which part of the client is worth rebuilding. This sums
// the same buckets by subsystem.
//
// The wow.exe ranges come from the client's own source-file names: the engine
// passes __FILE__ to its allocator and its asserts, so 1768 functions carry a
// reference to exactly one .cpp, and the linker keeps each object file's
// functions together. Each range below is bounded by functions tagged with the
// files named (IDA, 2026-09-28). Untagged functions between two different files
// are assigned by these bounds, so a range edge can be off by a function, and a
// page of unnamed code is classified by where the page starts.
enum ProfileFamily {
    PF_LUA, PF_M2, PF_PARTICLES, PF_MAP, PF_WORLD, PF_UI, PF_GAMEUI, PF_OBJECTS,
    PF_GX, PF_MATH, PF_TEXTURES, PF_SOUND, PF_OBJMGR, PF_WORLDFRAME, PF_FONTS,
    PF_DBCACHE, PF_RLE, PF_WOW_OTHER, PF_SELF, PF_D3D9, PF_DRIVER, PF_NTDLL,
    PF_OTHER_MODULE, PF_COUNT
};

static const char* const kFamilyName[PF_COUNT] = {
    "Lua (0x84B000-0x860000, lmemPool.cpp inside)",
    "M2 models and animation (M2Cache/M2Scene/M2Model/M2Shared.cpp)",
    "particles (ParticleSystem2.cpp)",
    "map: terrain, WMO, liquids, collision (Map*.cpp)",
    "world and scene (World.cpp, WorldScene.cpp, MapWeather.cpp)",
    "UI framework (CSimple*.cpp)",
    "game UI scripts and events (AddOns, ScriptEvents, Tooltip, Camera)",
    "game objects (Unit_C, Player_C, Spell/Effect, Missile, Item)",
    "Gx render device, engine side of D3D (CGxDevice*.cpp)",
    "math and geometry library (CMatrix, quaternions, frustum, ray-tri)",
    "textures and model blobs (Texture.cpp, ModelBlob.cpp)",
    "sound (FMOD, SoundInterface2)",
    "object manager (ObjectMgrClient.cpp)",
    "world frame and character components",
    "font rendering (GxuFont*.cpp)",
    "DB cache (DBCache.cpp)",
    "run-length decoder sub_4CFBB0 (DbcFastRle replaces it)",
    "wow.exe outside the ranges above",
    "wow_optimize.dll",
    "d3d9.dll (DXVK or the system runtime)",
    "graphics driver and Vulkan",
    "ntdll: heap, locks, loader (not waiting)",
    "other modules",
};

struct FamilyRange { uintptr_t lo, hi; ProfileFamily fam; };
static const FamilyRange kFamilyRanges[] = {
    { 0x00481000, 0x0049F000, PF_UI },          // EvtTimer .. CSimpleFrameScript
    { 0x004B4000, 0x004BD200, PF_TEXTURES },    // Texture, ModelBlob, Profile
    { 0x004BD200, 0x004C5D60, PF_MATH },        // CMatrix / C3Vector (TextureBlob inside)
    { 0x004C5D60, 0x004CE000, PF_SOUND },       // SoundInterface2*
    { 0x004CFBB0, 0x004CFC10, PF_RLE },
    { 0x004D2000, 0x004D7800, PF_OBJMGR },      // ObjectAlloc, ObjectMgrClient
    { 0x004F1A00, 0x004FAC00, PF_WORLDFRAME },  // CharacterComponent .. WorldFrame
    { 0x005F2A00, 0x00631600, PF_GAMEUI },      // CalendarEvent .. Tooltip
    { 0x0067BA00, 0x00680E00, PF_DBCACHE },
    { 0x00680E00, 0x006AB400, PF_GX },          // shader constants sub_6833E0, CGxDevice*
    { 0x006C4000, 0x006C9000, PF_FONTS },
    { 0x006CE000, 0x0071F400, PF_OBJECTS },     // Player_C .. Unit_C
    { 0x00780000, 0x0079E000, PF_WORLD },       // World, MapWeather, WorldScene
    { 0x0079E000, 0x007DA000, PF_MAP },         // Map, MapObj, MapChunk, MapObjGroup, liquids
    { 0x0081C000, 0x0083E000, PF_M2 },          // M2Cache .. M2Shared
    { 0x0084B000, 0x00860000, PF_LUA },
    { 0x008F0000, 0x0095D000, PF_SOUND },       // fmod_*, aSfxDsp
    { 0x0095DC00, 0x00978A10, PF_UI },          // CSimpleMovieFrame .. CSimpleHyperlinkedFrame
    { 0x00978A10, 0x00981130, PF_PARTICLES },   // ParticleSystem2 up to GfxSingletonManager
    { 0x00981130, 0x00986000, PF_MATH },        // quaternions, colour, frustum, ray-tri
};

static bool IsDriverModule(const char* n) {
    static const char* const kPrefixes[] = {
        "nv", "ati", "amd", "igd", "ig7", "ig8", "ig9", "ig1",
        "vulkan", "dxgi", "d3d10", "d3d11", "d3d12",
    };
    for (const char* p : kPrefixes)
        if (_strnicmp(n, p, strlen(p)) == 0) return true;
    return false;
}

static ProfileFamily FamilyOfBucket(uintptr_t addr, const char* name) {
    if (addr >= WOW_BASE && addr <= WOW_END) {
        for (const FamilyRange& r : kFamilyRanges)
            if (addr >= r.lo && addr < r.hi) return r.fam;
        return PF_WOW_OTHER;
    }
    if (g_selfBase && addr >= g_selfBase && addr < g_selfEnd) return PF_SELF;
    if (!name) return PF_OTHER_MODULE;
    if (lstrcmpiA(name, "d3d9.dll") == 0) return PF_D3D9;
    if (IsDriverModule(name)) return PF_DRIVER;
    if (lstrcmpiA(name, "ntdll.dll") == 0 || (name[0] == 'N' && name[1] == 't') ||
        (name[0] == 'R' && name[1] == 't' && name[2] == 'l'))
        return PF_NTDLL;
    return PF_OTHER_MODULE;
}

// Called once per report with the finished buckets and the executing total the
// percentages are shares of. The shares of a whole must add up to it, so the
// report says when they do not.
static void LogFamilies(const SampleBucket* buckets, int bucketCount, uint64_t workSamples) {
    if (!workSamples) return;
    uint64_t fam[PF_COUNT] = {};
    uint64_t summed = 0;
    for (int i = 0; i < bucketCount; i++) {
        if (!buckets[i].count || IsWaitSymbol(buckets[i].name)) continue;
        fam[FamilyOfBucket(buckets[i].addr, buckets[i].name)] += buckets[i].count;
        summed += buckets[i].count;
    }
    int order[PF_COUNT];
    for (int i = 0; i < PF_COUNT; i++) order[i] = i;
    std::sort(order, order + PF_COUNT, [&](int a, int b) { return fam[a] > fam[b]; });

    Log("[SamplingProfiler] === EXECUTING TIME BY SUBSYSTEM (share of the time the main "
        "thread was running code; wow.exe split by the client's own source files) ===");
    for (int k = 0; k < PF_COUNT; k++) {
        const int f = order[k];
        if (!fam[f]) break;
        Log("[SamplingProfiler]   %5.1f%%  %s", 100.0 * (double)fam[f] / (double)workSamples,
            kFamilyName[f]);
    }
    if (summed != workSamples)
        Log("[SamplingProfiler]   these add up to %llu samples where %llu were executing; "
            "the difference is samples no bucket holds, so every share above is low by "
            "up to %.1f%%.", (unsigned long long)summed, (unsigned long long)workSamples,
            100.0 * (double)(workSamples > summed ? workSamples - summed : summed - workSamples)
                  / (double)workSamples);
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

// Where our own registered symbols sit, as offsets from the module base.
//
// Nine percent of executing time in a tester's uncapped session was inside this
// DLL, spread over entries like "wowopt+0x11300" that name nothing. Resolving
// those needs the linker map for that exact build, which nobody has when they
// are reading a log - and guessing with a map from a different build is how this
// project has already produced three wrong conclusions in a day, because a
// nearest-symbol name reaches past the end of its own function.
//
// So the table goes in the log. An offset between two entries below is inside
// the first of them, and one past the last is code nobody has registered. That
// is the difference between a number a reader can act on and a number they can
// only stare at. It costs a handful of lines, once per report.
static void DumpSelfSymbolTable() {
    // Once per session, not once per report. Every detour in the project
    // registers itself now, so this is a few hundred lines; repeating it in each
    // periodic profile would bury the profile itself. The addresses do not move
    // during a run, so one printing serves every report in the log.
    static bool s_done = false;
    if (s_done) return;
    s_done = true;

    if (g_selfSymbolCount == 0 || !g_selfBase) {
        Log("[SamplingProfiler] === no self-symbols registered - every wowopt+0x "
            "entry below is unresolvable without this build's linker map ===");
        return;
    }

    // Insertion sort by offset; the table is small and this runs once a report.
    int order[MAX_SELF_SYMBOLS];
    for (int i = 0; i < g_selfSymbolCount; i++) order[i] = i;
    for (int i = 1; i < g_selfSymbolCount; i++) {
        int k = order[i], j = i - 1;
        while (j >= 0 && g_selfSymbols[order[j]].addr > g_selfSymbols[k].addr) {
            order[j + 1] = order[j];
            j--;
        }
        order[j + 1] = k;
    }

    Log("[SamplingProfiler] === wow_optimize.dll SYMBOLS (%d registered, offsets "
        "from the module base) - use these to place any wowopt+0x entry below; an "
        "offset between two of them is inside the first ===", g_selfSymbolCount);
    for (int i = 0; i < g_selfSymbolCount; i++) {
        const SelfSymbol& s = g_selfSymbols[order[i]];
        Log("[SamplingProfiler]   +0x%05X  %s",
            (unsigned)(s.addr - g_selfBase), s.name);
    }
}

// `baseline`, when given, is a copy of `counts` taken earlier and every slot is
// read as the difference. That is how one loading screen is reported out of a
// histogram that accumulates across all of them, without a second 64 KB array
// to hold the subtraction.
static inline uint32_t SlotAt(const uint32_t* counts, const uint32_t* baseline, int i) {
    uint32_t c = counts[i];
    if (!baseline) return c;
    uint32_t b = baseline[i];
    return (c > b) ? (c - b) : 0u;
}

static void DumpFineHistogram(const uint32_t* counts, int slots, int shift,
                              uint64_t total, const char* title,
                              const char* addrFormat, uintptr_t addrBase,
                              const uint32_t* baseline = nullptr) {
    int idx[SELF_FINE_TOP];
    int found = 0;

    for (int i = 0; i < slots; i++) {
        uint32_t c = SlotAt(counts, baseline, i);
        if (!c) continue;
        int at = found;
        if (found < SELF_FINE_TOP) {
            found++;
        } else if (c > SlotAt(counts, baseline, idx[SELF_FINE_TOP - 1])) {
            at = SELF_FINE_TOP - 1;
        } else {
            continue;
        }
        while (at > 0 && c > SlotAt(counts, baseline, idx[at - 1])) {
            idx[at] = idx[at - 1];
            at--;
        }
        idx[at] = i;
    }

    if (found == 0 || total == 0) return;

    Log("[SamplingProfiler] === %s ===", title);
    for (int i = 0; i < found; i++) {
        uint32_t c = SlotAt(counts, baseline, idx[i]);
        // 48, and bounded. It was 32 and written with wsprintfA, which takes no
        // size: "wowopt+0x%X after %.12s" reaches 37 bytes with its terminator,
        // so every label that took that branch ran five bytes past the end and
        // over the stack cookie. The check at the return then failed and the CRT
        // ended the process through __fastfail, which runs no exception filter
        // and no exit hook - two tester sessions died thirty seconds in, inside
        // the first report, with nothing in the log to say why.
        char addr[48];
        uintptr_t slotAddr = addrBase + ((uintptr_t)idx[i] << shift);
        uintptr_t delta = 0;
        // A 256-byte slot holds several functions and the name found at its first
        // byte says nothing about where its samples are, so with the map loaded the
        // per-function list above is the place for names and this one is offsets.
        const char* sym = (addrBase == 0 && !g_mapSymCount)
                        ? ResolveSelfSymbol(g_selfBase + slotAddr, &delta) : nullptr;
        if (sym && delta < kSelfSymbolTrusted) snprintf(addr, sizeof(addr), "wowopt!%.20s", sym);
        // Past the trusted distance the address is the fact and the name is a
        // neighbourhood, so the address leads and the name follows it.
        else if (sym) snprintf(addr, sizeof(addr), "wowopt+0x%X after %.20s", (unsigned)slotAddr, sym);
        else          snprintf(addr, sizeof(addr), addrFormat, (unsigned)slotAddr);
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

static void DescribeForeign(uintptr_t a, char* out, size_t cap) {
    if (FreezeCatcher::NameExport(a, out, cap)) return;
    HMODULE m = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)a, &m) && m) {
        char path[MAX_PATH] = {};
        GetModuleFileNameA(m, path, MAX_PATH);
        const char* base = strrchr(path, 92);
        wsprintfA(out, "%s+0x%X", base ? base + 1 : path, (unsigned)(a - (uintptr_t)m));
        return;
    }
    wsprintfA(out, "0x%08X", (unsigned)a);
}

// What the main thread was running in, outside the client and this DLL, and which
// of the client's functions called it. Cumulative over the session, so shares are
// of every sample taken since the start and not of the ring window the rest of the
// report is read from.
static void DumpForeignCallers() {
    if (g_callerSamples == 0) {
        Log("[SamplingProfiler] === WHO CALLED THE CODE OUTSIDE wow.exe AND THIS DLL === not measured: "
            "no sample landed outside them.");
        return;
    }
    const uint64_t all = g_totalSamples ? g_totalSamples : 1;
    Log("[SamplingProfiler] === WHO CALLED THE CODE OUTSIDE wow.exe AND THIS DLL === %llu sample(s) "
        "(%.1f%% of all %llu taken since the start), %llu of them with no caller found on the "
        "stack, %lu row(s) that did not fit ===",
        (unsigned long long)g_callerSamples, 100.0 * (double)g_callerSamples / (double)all,
        (unsigned long long)all, (unsigned long long)g_callerNoCaller, (unsigned long)g_callerLost);

    bool used[CALLER_SLOTS] = {};
    for (int row = 0; row < 14; ++row) {
        int best = -1;
        for (int i = 0; i < CALLER_SLOTS; ++i)
            if (!used[i] && g_callerRows[i].n && (best < 0 || g_callerRows[i].n > g_callerRows[best].n)) best = i;
        if (best < 0) break;
        used[best] = true;
        const CallerRow& r = g_callerRows[best];
        char where[128], who[64];
        DescribeForeign(r.eip, where, sizeof(where));
        if (r.caller >= WOW_BASE && r.caller <= WOW_END) wsprintfA(who, "wow!0x%08X", (unsigned)r.caller);
        else if (r.caller) wsprintfA(who, "wowopt+0x%X", (unsigned)(r.caller - g_selfBase));
        else lstrcpyA(who, "(not found)");
        Log("[SamplingProfiler]   %6u  %5.2f%%  %s  <-  %s", (unsigned)r.n,
            100.0 * (double)r.n / (double)all, where, who);
    }

    // The same rows summed by the calling function's 256-byte region, which is
    // the question for Direct3D: which part of the client makes the calls.
    struct Sum { uintptr_t region; uint64_t n; };
    static Sum sums[1024];
    int ns = 0;
    for (int i = 0; i < CALLER_SLOTS; ++i) {
        if (!g_callerRows[i].n || !g_callerRows[i].caller) continue;
        const uintptr_t reg = g_callerRows[i].caller & ~(uintptr_t)0xFF;
        int k = 0;
        for (; k < ns; ++k) if (sums[k].region == reg) break;
        if (k == ns) { if (ns >= 1024) continue; sums[ns].region = reg; sums[ns].n = 0; ++ns; }
        sums[k].n += g_callerRows[i].n;
    }
    Log("[SamplingProfiler]   by the calling code's 256-byte region:");
    bool usedS[1024] = {};
    for (int row = 0; row < 10; ++row) {
        int best = -1;
        for (int i = 0; i < ns; ++i) if (!usedS[i] && (best < 0 || sums[i].n > sums[best].n)) best = i;
        if (best < 0) break;
        usedS[best] = true;
        const bool inWow = sums[best].region >= WOW_BASE && sums[best].region <= WOW_END;
        Log("[SamplingProfiler]   %6llu  %5.2f%%  %s0x%08X", (unsigned long long)sums[best].n,
            100.0 * (double)sums[best].n / (double)all, inWow ? "wow!" : "wowopt+",
            (unsigned)(inWow ? sums[best].region : sums[best].region - g_selfBase));
    }
}

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
    LoadMapSymbols();
    if (!g_selfSymCounts && g_mapSymCount) {
        g_selfSymCounts = (uint32_t*)HighTables::Reserve(
            "profiler_selfsym", sizeof(uint32_t) * (size_t)g_mapSymCount);
        g_selfSymCap = g_selfSymCounts ? g_mapSymCount : 0;
    }
    if (g_selfSymCounts) memset(g_selfSymCounts, 0, sizeof(uint32_t) * (size_t)g_selfSymCap);
    // Deliberately NOT cleared here. The main histogram is rebuilt from the
    // ring on every dump; the loading one accumulates across the session,
    // because a load that happened twenty minutes ago is exactly the one
    // somebody wants to know about.

    // Snapshot loaded modules so system samples can be attributed to a DLL.
    BuildModuleTable();
    LoadMapSymbols();
    BuildNtFuncTable();

    // Buckets: one per named function, one "system_dll", plus one per non-empty
    // 4KB WoW page (so unlisted hot code is reported by address, not lumped into
    // a single opaque blob). Too large for the stack because of the page slots.
    //
    // Not a function-local static: that puts half a megabyte in this DLL's
    // image, which is mapped into the low 2GB the client allocates from, for a
    // report most sessions never run. Reserved on the first report instead, out
    // of the top of the address space, and kept for the ones after it.
    static constexpr int MAX_BUCKETS = MAX_KNOWN_FUNCS + NUM_PAGES + SELF_PAGES + 128 + 24 + 1;
    static SampleBucket* buckets = nullptr;
    if (!buckets) {
        buckets = (SampleBucket*)HighTables::Reserve(
            "profiler_report", sizeof(SampleBucket) * MAX_BUCKETS);
        if (!buckets) {
            Log("[Profiler] no report this interval: the %u KB bucket table "
                "could not be reserved.",
                (unsigned)(sizeof(SampleBucket) * MAX_BUCKETS / 1024));
            return;
        }
    }
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
    // The ring holds the last RING_SIZE samples and a long session takes far
    // more, so every percentage below is a share of `n`, never of `total`. A
    // three-hour session put 5853152 samples through a ring of 1048576: dividing
    // by the lifetime total understates each figure by 5.6x.
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
            if (g_selfSymCounts) {
                const int si = MapSymbolIndex((uint32_t)off);
                if (si >= 0 && si < g_selfSymCap) g_selfSymCounts[si]++;
            }
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
    if (g_selfSymCounts) {
        // Per function, from the map. Each bucket sits at its function's first
        // byte, so the label resolved from it names that function.
        for (int si = 0; si < g_selfSymCap && bucketCount < MAX_BUCKETS; si++) {
            if (!g_selfSymCounts[si]) continue;
            buckets[bucketCount].addr  = g_selfBase + g_mapSyms[si].rva;
            buckets[bucketCount].name  = nullptr;
            buckets[bucketCount].count = g_selfSymCounts[si];
            bucketCount++;
        }
    }
    for (int p = 0; p < SELF_PAGES && bucketCount < MAX_BUCKETS && !g_selfSymCounts; p++) {
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

    // Published for the A/B harness. A frame-time comparison in a session the
    // client spends waiting on the GPU cannot show a CPU saving, and it used to
    // print one anyway while this line, in the same log, said the client was
    // not CPU-bound.
    g_lastWorkPct = workPct;
    g_lastWorkSamples = n;

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

    LogFamilies(buckets, bucketCount, workSamples);

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
    if (g_mapSymCount)
        Log("[SamplingProfiler] our own addresses are resolved against %d function(s) "
            "read from wow_optimize.sym, so a name below means the address is inside "
            "that function and not merely after it.", g_mapSymCount);
    else
        Log("[SamplingProfiler] wow_optimize.sym was not loaded (%s), so our own "
            "addresses fall back to the hooks registered at runtime - those are entry "
            "points with no size, and a name is only trustworthy within the first few "
            "hundred bytes.", g_mapWhy[0] ? g_mapWhy : "reason not recorded");

    Log("[SamplingProfiler] === TOP %d HOT FUNCTIONS/REGIONS - self time, whole "
        "function; a +0xNNN suffix on a client function is where the weight sits "
        "inside it, not a split, because those have known sizes. A line reading "
        "\"wowopt+0xNNN after <name>\" is the other case: our own symbols are "
        "entry points with no size, so that address is somewhere past that one "
        "and may be in an unregistered neighbour "
        "(shares of the %llu most recent samples, %llu idle ticks during "
        "loading/warmup where the main thread was left alone) ===",
        TOP_N, (unsigned long long)n, (unsigned long long)g_skippedSamples);

    int    printed = 0;
    double pctSum  = 0.0;
    for (int i = 0; i < bucketCount && printed < TOP_N; i++) {
        if (buckets[i].count == 0) break;
        double pct = 100.0 * (double)buckets[i].count / (double)n;
        char label[40];
        const char* name;
        if (buckets[i].name) {
            name = buckets[i].name;

            // Keep the offset. Without it a line reading "tostring 4.73%" could
            // be that function or any unnamed one after it, with nothing to tell
            // them apart.
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
                snprintf(label, sizeof(label), "%.20s+0x%03X", buckets[i].name,
                         (unsigned)(domIdx << 8));
                name = label;
            }
        } else if (g_selfBase && buckets[i].addr >= g_selfBase && buckets[i].addr < g_selfEnd) {
            // A hot page inside our own DLL — label by offset from our base so it
            // maps directly to wow_optimize.map (which of our hooks costs time).
            uintptr_t delta = 0;
            const char* sym = ResolveSelfSymbol(buckets[i].addr, &delta);
            // Bounded. The middle one reached 39 bytes into this 40 - correct
            // by one byte, which is not the same as correct.
            if (sym && delta < kSelfSymbolTrusted) snprintf(label, sizeof(label), "wowopt!%.32s", sym);
            else if (sym) snprintf(label, sizeof(label), "wowopt+0x%05X after %.14s",
                                   (unsigned)(buckets[i].addr - g_selfBase), sym);
            else     snprintf(label, sizeof(label), "wowopt+0x%05X", (unsigned)(buckets[i].addr - g_selfBase));
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
        pctSum += pct;
        printed++;
    }

    // The arithmetic that has to hold before any of the above is worth reading.
    //
    // These are shares of one whole, so the fifty largest of them cannot come to
    // a small number. When this profiler divided ring-window counts by a lifetime
    // total, its top fifty summed to 12% and every entry was understated 5.6x -
    // and that was found by noticing the sum, not by reading the code. A profile
    // whose top entry was really 9.7% had already been read as flat for a week.
    //
    // The threshold is deliberately loose. Fifty buckets out of thousands may
    // genuinely not reach half the profile on a flat workload, so only a sum small
    // enough to be arithmetically suspicious says anything.
    if (printed >= 10 && pctSum < 15.0) {
        Verdict::Add(Verdict::Warn,
                     "the profiler's top %d entries sum to %.0f%% of the profile, "
                     "too little for shares of one whole - suspect the denominator",
                     printed, pctSum);
        Log("[SamplingProfiler] the %d entries above sum to %.1f%% of the profile. "
            "They are shares of one whole and cannot legitimately be this small; "
            "the last time this happened the denominator was a lifetime sample "
            "count while the numerators came from a ring window.", printed, pctSum);
    }

    // Our own hot spots at 256-byte resolution, then the client's at 512-byte.
    // Both are narrow enough to land on a single function, which the 4KB page
    // buckets in the ranking above cannot do.
    DumpSelfSymbolTable();
    DumpFineHistogram(g_selfFineCounts, SELF_FINE_SLOTS, SELF_FINE_SHIFT, n,
                      "wow_optimize.dll HOT SPOTS (256-byte resolution)", "wowopt+0x%05X", 0);
    // Loading screens, separately, because they are the complaint this project
    // hears most and the loading timer can only account for twelve percent of
    // one - two in reads and ten in the client's own writes.
    if (g_loadSamples == 0) {
        Log("[SamplingProfiler] === LOADING SCREENS === no sample was taken "
            "while one was up. Either none came up, or none lasted long enough "
            "to be sampled - not a measurement that they are fast.");
    } else {
        Log("[SamplingProfiler] === LOADING SCREENS: %llu sample(s) taken while "
            "one was up, %.1f%% of the session. Of those, %.0f%% were inside "
            "wow.exe, %.0f%% inside this tool, and %.0f%% in a system library, a "
            "driver or a wait ===",
            (unsigned long long)g_loadSamples,
            total ? (100.0 * (double)g_loadSamples / (double)total) : 0.0,
            100.0 * (double)g_loadInWow     / (double)g_loadSamples,
            100.0 * (double)g_loadInSelf    / (double)g_loadSamples,
            100.0 * (double)g_loadElsewhere / (double)g_loadSamples);
        Log("[SamplingProfiler]   these accumulate over the whole session rather "
            "than living in the ring, so a load twenty minutes ago is still "
            "here. The shares below are of the wow.exe samples only.");
        DumpFineHistogram(g_loadFineCounts, WOW_FINE_SLOTS, WOW_FINE_SHIFT,
                          g_loadInWow,
                          "WHERE A LOADING SCREEN GOES (512-byte resolution)",
                          "0x%08X", WOW_BASE);
    }

    DumpFineHistogram(g_wowFineCounts, WOW_FINE_SLOTS, WOW_FINE_SHIFT, n,
                      "wow.exe HOT SPOTS (512-byte resolution)", "0x%08X", WOW_BASE);

    DumpHottestForeignModule(g_ring, startIdx, n, total);

    DumpForeignCallers();

    DumpWorkerThreads(total);

    // Which addon the Lua time belonged to. Same samples, read a second way:
    // the list above says which code ran, this says whose code it was.
    LuaAddonSampler::Report();

    Log("[SamplingProfiler] === END PROFILE ===");
}

// ---- public API ---------------------------------------------------
// The share of main-thread samples that were executing rather than blocked, as
// of the last report. False when no report has run, so a caller can tell "not
// measured" from "measured and low".
bool GetExecutingShare(double* pct, unsigned long long* samples) {
    if (g_lastWorkPct < 0.0) return false;
    if (pct)     *pct = g_lastWorkPct;
    if (samples) *samples = g_lastWorkSamples;
    return true;
}

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


// --- one loading screen at a time -------------------------------------------

void MarkLoadWindowStart() {
    if (!g_running) { g_loadWindowOpen = false; return; }
    // The sampler writes these from its own thread while this copies them. A
    // slot that changes mid-copy moves one sample between this window and the
    // next, which is not a difference a profile can show.
    memcpy(g_loadWindowBase, g_loadFineCounts, sizeof(g_loadWindowBase));
    g_loadWindowInWow = g_loadInWow;
    g_loadWindowTotal = g_loadSamples;
    g_loadWindowOpen  = true;
}

void ReportLoadWindow() {
    if (!g_running) {
        Log("[LoadingState]   where it went is not measured: the sampling "
            "profiler is off. LOGGING: FULL in the launcher turns it on, and "
            "the next load says which addresses the time was in.");
        return;
    }
    if (!g_loadWindowOpen) {
        Log("[LoadingState]   where it went is not measured: the profiler "
            "started after this load began.");
        return;
    }
    g_loadWindowOpen = false;

    uint64_t inWow = (g_loadInWow > g_loadWindowInWow)
                   ? (g_loadInWow - g_loadWindowInWow) : 0;
    uint64_t took  = (g_loadSamples > g_loadWindowTotal)
                   ? (g_loadSamples - g_loadWindowTotal) : 0;

    if (took == 0) {
        Log("[LoadingState]   not measured: the profiler took no sample at all "
            "during this load, which at a %lu ms interval means it was not "
            "running rather than that the load was short.",
            (unsigned long)SAMPLE_INTERVAL_MS);
        return;
    }
    if (inWow == 0) {
        Log("[LoadingState]   measured and zero: %llu sample(s) were taken "
            "during this load and not one landed inside wow.exe. The time was "
            "in a driver, a system library or a wait, and the address "
            "histogram cannot name those.", (unsigned long long)took);
        return;
    }

    Log("[LoadingState]   the main thread during this load: %llu sample(s), "
        "%llu of them inside wow.exe (%.0f%%). The rest were in a driver, a "
        "system library or a wait. This is where the time went that was neither "
        "read, written nor compiled.",
        (unsigned long long)took, (unsigned long long)inWow,
        100.0 * (double)inWow / (double)took);
    DumpFineHistogram(g_loadFineCounts, WOW_FINE_SLOTS, WOW_FINE_SHIFT,
                      inWow, "THIS LOADING SCREEN (512-byte resolution)",
                      "0x%08X", WOW_BASE, g_loadWindowBase);
}

} // namespace SamplingProfiler