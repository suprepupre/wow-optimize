// ============================================================================
// Description: Deduplicates D3D9 device state changes and caches rendering states
//              to maximize CPU throughput and minimize driver overhead.
// Safety & Threading: Main render thread only. Crash-guarded against NULL pointers.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <intrin.h>
#include <d3d9.h>
#include "d3d9_state_manager.h"
#include "config.h"
#include "draw_merge.h"
#include "m2_anim_stride.h"
#include "session_verdict.h"
#include "sampling_profiler.h"
#include "font_glyph_cache.h"
#include "texture_unload_delay.h"
#include "d3d9_state_cache.h"
#include "gx_render_thread.h"
#include "render_state_dedup.h"
#include "win_mutex.h"
#include "diagnostics/crash_dumper.h"
#include "diagnostics/frame_bench.h"

extern "C" void Log(const char* fmt, ...);

// Per-frame work that must run on a true frame boundary (see dllmain).
extern "C" void WowOpt_OnFrameBoundary();

// Memory validation
static bool IsReadable(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD);
}

// ================================================================
// VTable indices (IDirect3DDevice9)
// ================================================================
enum {
    V_SETSAMPLERSTATE      = 69,
    V_SETTEXTURESTAGESTATE = 67,
    V_SETRENDERSTATE       = 57,
    V_SETTRANSFORM         = 44,
    V_SETMATERIAL          = 49,
    V_SETVIEWPORT          = 47,
    // Not deduped, and hooked for the opposite reason: it changes state this
    // file caches without going through any of the setters. See
    // Hooked_SetRenderTarget.
    V_SETRENDERTARGET      = 37,
    V_SETDEPTHSTENCIL      = 39,
    V_SETSCISSORRECT       = 75,
    V_SETSTREAMSOURCE      = 100,
    V_SETINDICES           = 104,
    V_SETVERTEXDECLARATION = 87,
    V_SETFVF               = 89,
    V_SETPIXELSHADER       = 107,
    V_SETVERTEXSHADER      = 92,
    V_SETTEXTURE           = 65,
    V_RESET                = 16,
    V_PRESENT              = 17,
    // The two nobody has ever counted. d3d9.dll is the largest single entry in
    // the one CPU-bound profile this project has - 7.75% of executing time - and
    // under DXVK that is the cost of RECORDING calls on the main thread, because
    // DXVK executes them on its own command-stream thread. Recording cost scales
    // with the number of calls, so the question is whether there are too many
    // draws, and nothing here could answer it: DrawIndexedPrimitive was not
    // hooked anywhere in the tree.
    //
    // The number that decides it is primitives per draw. Two triangles a call
    // means batching is worth a great deal; five hundred means the draws are
    // already as large as they get and the 7.75% is not reducible from our side.
    V_DRAWPRIMITIVE        = 81,
    V_DRAWINDEXEDPRIMITIVE = 82,
};

static constexpr int NUM_HOOKS = 20;
static int g_vtableIndices[NUM_HOOKS] = {
    V_SETRENDERSTATE, V_SETTEXTURESTAGESTATE, V_SETSAMPLERSTATE,
    V_SETTEXTURE, V_SETTRANSFORM, V_SETMATERIAL,
    V_SETVIEWPORT, V_SETSCISSORRECT, V_SETSTREAMSOURCE,
    V_SETINDICES, V_SETVERTEXDECLARATION, V_SETFVF,
    V_SETVERTEXSHADER, V_SETPIXELSHADER, V_RESET,
    V_PRESENT, V_DRAWPRIMITIVE, V_DRAWINDEXEDPRIMITIVE,
    V_SETRENDERTARGET, V_SETDEPTHSTENCIL
};

static void* g_vtableOriginals[NUM_HOOKS] = {};
static bool  g_vtablePatched[NUM_HOOKS] = {};

static void* g_pDevice = nullptr;
static void* g_pPatchedVTable = nullptr;
static bool  g_deviceHooked = false;
volatile LONG g_deviceResetCounter = 0;

// Guards vtable read-modify-write in PatchDeviceVTable/UnpatchDeviceVTable. Without
// this, the init thread's first-time patch and the game thread's CheckDeviceChange
// re-patch can race on the same VirtualProtect'd page: one thread restores the
// page to non-writable between another thread's protect and its write, faulting
// on the vtable-slot store (observed as ACCESS_VIOLATION inside PatchDeviceVTable
// at startup, offset 0x3E9C0, both threads logging "Device vtable patched" within
// the same millisecond).
static WinMutex g_vtableMutex;

// Per-frame statistics
// Plain 32-bit, not LONG64 with InterlockedIncrement64. There was one of those
// at the top of every one of these sixteen hooks, so SetRenderState, SetTexture
// and DrawPrimitive each carried a lock cmpxchg8b retry loop on 32-bit x86, on
// the hottest calls in the frame. The 3.19.0 pass that removed nine of these
// fixed the state cache next door and never opened this file.
//
// Plain 32-bit and never plain 64-bit: add/adc across two words can tear a
// value where a 32-bit increment can only lose one. These are lower bounds and
// the report says so.
static unsigned long g_statCalls[NUM_HOOKS]   = {};
static unsigned long g_statSkipped[NUM_HOOKS] = {};
static const char* g_statNames[NUM_HOOKS] = {
    "SetRenderState", "SetTextureStageState", "SetSamplerState",
    "SetTexture", "SetTransform", "SetMaterial",
    "SetViewport", "SetScissorRect", "SetStreamSource",
    "SetIndices", "SetVertexDeclaration", "SetFVF",
    "SetVertexShader", "SetPixelShader", "Reset",
    "Present", "DrawPrimitive", "DrawIndexedPrimitive",
    "SetRenderTarget", "SetDepthStencilSurface"
};

static unsigned long g_totalFrames = 0;

// What the two exclusions above are costing, counted and never acted on.
//
// A tester session recorded 127,757,947 SetTexture calls and 39,267,692
// SetRenderState calls with zero skips against both. For SetTexture that is
// correct and deliberate - it does not dedup at all, because a texture freed and
// a new one allocated at the same address inside one frame would compare equal
// to a stale entry. For SetRenderState the eight blend and depth states are
// excluded by name, and those are exactly the ones a renderer toggles per batch,
// so what is left to dedup may genuinely never repeat.
//
// Both of those are arguments. Under DXVK every one of these calls is recording
// cost on the main thread and d3d9.dll is the largest single entry in the
// profile at 7.75%, so the share that WOULD have been redundant is the number
// that decides whether either exclusion is worth what it costs - and nothing has
// ever measured it.
//
// These counters change no behaviour. They compare and count; the call goes
// through either way. Plain 32-bit on a path that runs a hundred million times a
// session, so they are lower bounds and the report says so.
static void*         g_shadowTex[8]   = {};
static bool          g_shadowTexValid[8] = {};
// Which render states the shadow comparison watches, as a table rather than a
// chain of eight compares.
//
// A tester session put 39,267,692 calls through Hooked_SetRenderState, and each
// one evaluated eight equality tests to answer a question a single byte load
// answers. The states are D3DRS_* constants below 256; a state at or above 256
// reads as not critical, which is what the eight compares did for it too, so
// both branches below behave exactly as before for every input.
//
// Filled in InstallD3D9StateManager, before any hook it installs can fire, so
// there is no static initialisation order to reason about.
static unsigned char g_isCriticalRs[256] = {};
// The eight are 7, 14, 15, 19, 20, 24, 25 and 27 in the SDK this builds
// against. Asserted rather than trusted, because the table indexes by them.
static_assert(D3DRS_ALPHABLENDENABLE < 256 && D3DRS_SRCBLEND < 256 &&
              D3DRS_DESTBLEND        < 256 && D3DRS_ALPHATESTENABLE < 256 &&
              D3DRS_ALPHAREF         < 256 && D3DRS_ALPHAFUNC       < 256 &&
              D3DRS_ZWRITEENABLE     < 256 && D3DRS_ZENABLE         < 256,
              "a watched render state fell outside the 256-entry table");

static unsigned long g_texWouldSkip   = 0;
static unsigned long g_texCompared    = 0;
static DWORD         g_shadowRs[256]  = {};
static bool          g_shadowRsValid[256] = {};
// The four setters below skipped nothing at all in a 2318 second session:
// SetRenderState 0 of 83,139,937, SetSamplerState 0 of 119,490,300,
// SetTextureStageState 0 of 3,398,084, SetMaterial 0 of 251,855. Not "almost
// nothing" - zero, at every report point in the session, and the independent
// shadow measurement on the eight excluded render states agrees at 0 of
// 33,937,602.
//
// Two hundred and six million calls cannot all carry a new value by accident.
// The likely reason is structural rather than statistical: these detours sit on
// the D3D9 vtable, which the client reaches only after CGxDevice has decided the
// state actually changed, so everything arriving here has already passed a
// filter. That is not proven from the disassembly and is labelled as a guess.
//
// What is measured is that the skip cannot fire, and a skip that cannot fire is
// a return that bypasses D3D9 for no gain - the same shape as the viewport bug
// above, carried for nothing. They count what they would have skipped and always
// call through now. If the number below ever comes back non-zero on some client,
// the dedup is worth putting back.
static unsigned long g_wouldSkip[NUM_HOOKS] = {};
static unsigned long g_rsCritWouldSkip = 0;
static unsigned long g_rsCritCompared  = 0;

// State caches
static DWORD  g_rsCache[256] = {};
static bool   g_rsValid[256] = {};
static DWORD  g_tssCache[256] = {};
static bool   g_tssValid[256] = {};
static DWORD  g_ssCache[256] = {};
static bool   g_ssValid[256] = {};
static void*  g_texCache[8] = {};
static bool   g_texValid[8] = {};
static uint64_t g_xformHash[32] = {};
static bool   g_xformValid[32] = {};
static uint32_t g_materialHash = 0;
static bool   g_materialValid = false;
static DWORD    g_viewportData[6] = {};
static bool     g_viewportValid = false;
static LONG     g_scissorData[4] = {};
static bool     g_scissorValid = false;
static void*  g_streamBuf[16] = {};
static UINT   g_streamOffset[16] = {};
static UINT   g_streamStride[16] = {};
static bool   g_streamValid[16] = {};
static void*  g_indexBuf = nullptr;
static bool   g_indexValid = false;
static void*  g_vertDecl = nullptr;
static bool   g_vertDeclValid = false;
static DWORD  g_fvf = 0;
static bool   g_fvfValid = false;
static void*  g_vs = nullptr;
static bool   g_vsValid = false;
static void*  g_ps = nullptr;
static bool   g_psValid = false;

static void InvalidateAllCaches();
static void UnpatchDeviceVTable();
static bool PatchDeviceVTable(void* pDevice);

static volatile LONG g_mainThreadClearPending = 0;

static void ClearMainThreadCaches() {
    #ifndef TEST_DISABLE_FONT_METRICS_FAST
    FontGlyphCache::ClearCache();
    #endif
    TextureUnloadDelay::Discard();
    D3D9StateCache::InvalidateAllCaches(false);
}

void D3D9StateManager_RunDeferredMainThreadWork(void) {
    if (g_mainThreadClearPending && InterlockedExchange(&g_mainThreadClearPending, 0)) {
        ClearMainThreadCaches();
    }
}

static inline void CheckDeviceChange(void* dev) {
    // Do NOT bypass this under DXVK: it's the only mechanism that notices a
    // device reset/recreation (windowed<->fullscreen, resize) and invalidates
    // FontGlyphCache/TextureUnloadDelay/D3D9StateCache. Skipping it here left
    // those caches hanging onto descriptors for destroyed textures after any
    // display-mode change, corrupting all on-screen text. The vtable-patch
    // race that DXVKBridge::IsActive() was introduced to dodge is fixed at
    // the source now (g_vtableMutex in PatchDeviceVTable/UnpatchDeviceVTable).
    if (dev && dev != g_pDevice) {
        CrashDumper::Trace("D3D9 device pointer changed %p -> %p", g_pDevice, dev);
        Log("[D3D9State] Real-time Device pointer change detected (old: %p, new: %p).", g_pDevice, dev);
        
        InterlockedIncrement(&g_deviceResetCounter);
        InvalidateAllCaches();
        RenderStateDedup_ClearCache();
        if (GxRT::OnRenderThread()) InterlockedExchange(&g_mainThreadClearPending, 1);
        else ClearMainThreadCaches();

        g_pDevice = dev;

        g_deviceHooked = false; // Force PatchDeviceVTable to run and verify/re-hook the new device vtable
        PatchDeviceVTable(dev);
    }
}

// Fast matrix/material hash functions
static uint64_t QuickMatrixHash(const float* m) {
    uint64_t h = 0;
    const uint32_t* p = (const uint32_t*)m;
    for (int i = 0; i < 16; i++) {
        h ^= (uint64_t)p[i] << (i % 32);
        h = (h * 0x9E3779B97F4A7C15ULL) ^ (h >> 31);
    }
    return h;
}

static uint32_t HashMaterial(const DWORD* mat) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < 16; i++) {
        h ^= mat[i];
        h *= 16777619u;
    }
    return h;
}

// original function pointers for calling back to driver
typedef HRESULT (__stdcall *SetRenderState_t)(void* dev, DWORD state, DWORD value);
static SetRenderState_t g_orig_SetRenderState = nullptr;

typedef HRESULT (__stdcall *SetTextureStageState_t)(void* dev, DWORD stage, DWORD type, DWORD value);
static SetTextureStageState_t g_orig_SetTextureStageState = nullptr;

typedef HRESULT (__stdcall *SetSamplerState_t)(void* dev, DWORD sampler, DWORD type, DWORD value);
static SetSamplerState_t g_orig_SetSamplerState = nullptr;

typedef HRESULT (__stdcall *SetTexture_t)(void* dev, DWORD stage, void* tex);
static SetTexture_t g_orig_SetTexture = nullptr;

typedef HRESULT (__stdcall *SetTransform_t)(void* dev, DWORD state, const void* matrix);
static SetTransform_t g_orig_SetTransform = nullptr;

typedef HRESULT (__stdcall *SetMaterial_t)(void* dev, const void* material);
static SetMaterial_t g_orig_SetMaterial = nullptr;

typedef HRESULT (__stdcall *SetViewport_t)(void* dev, const DWORD* vp);
static SetViewport_t g_orig_SetViewport = nullptr;

typedef HRESULT (__stdcall *SetScissorRect_t)(void* dev, const RECT* rect);
static SetScissorRect_t g_orig_SetScissorRect = nullptr;

typedef HRESULT (__stdcall *SetStreamSource_t)(void* dev, UINT stream, void* vb, UINT offset, UINT stride);
static SetStreamSource_t g_orig_SetStreamSource = nullptr;

typedef HRESULT (__stdcall *SetIndices_t)(void* dev, void* ib);
static SetIndices_t g_orig_SetIndices = nullptr;

typedef HRESULT (__stdcall *SetVertexDeclaration_t)(void* dev, void* decl);
static SetVertexDeclaration_t g_orig_SetVertexDeclaration = nullptr;

typedef HRESULT (__stdcall *SetFVF_t)(void* dev, DWORD fvf);
static SetFVF_t g_orig_SetFVF = nullptr;

typedef HRESULT (__stdcall *SetVertexShader_t)(void* dev, void* vs);
static SetVertexShader_t g_orig_SetVertexShader = nullptr;

typedef HRESULT (__stdcall *SetPixelShader_t)(void* dev, void* ps);
static SetPixelShader_t g_orig_SetPixelShader = nullptr;

typedef HRESULT (__stdcall *Reset_t)(void* dev, D3DPRESENT_PARAMETERS* params);
static Reset_t g_orig_Reset = nullptr;

typedef HRESULT (__stdcall *PresentFn)(void* dev, const RECT* src, const RECT* dst,
                                       HWND hOverride, const RGNDATA* dirty);

// Hooked functions

// Bumped whenever a state setter actually reaches D3D9, and never on a call the
// dedup above skips - a skipped call means the state did not change, which is
// exactly what a draw-merge census needs to know. Free on the fast path, and
// beside a real D3D9 call on the slow one.
//
// It exists for one question: how many of the 27 million draw calls a session
// makes could have been merged with the one before them. 35.3% of them carry
// eight primitives or fewer and 21.2% carry one or two, so the per-call cost
// dominates - but two draws can only merge if nothing changed between them, and
// nothing has ever counted that.
extern "C" unsigned long g_stateEpoch = 0;

static HRESULT __stdcall Hooked_SetRenderState(void* dev, DWORD state, DWORD value) {
    CheckDeviceChange(dev);
    ++g_statCalls[0];
    
    const bool isCriticalState = (state < 256) && (g_isCriticalRs[state] != 0);

    // Measurement only, on the states the dedup is not allowed to touch.
    if (state < 256 && isCriticalState) {
        ++g_rsCritCompared;
        if (g_shadowRsValid[state] && g_shadowRs[state] == value) ++g_rsCritWouldSkip;
        g_shadowRs[state] = value;
        g_shadowRsValid[state] = true;
    }

    if (state < 256 && !isCriticalState && g_rsValid[state] && g_rsCache[state] == value)
        ++g_wouldSkip[0];
    HRESULT hr = (D3D9_StateBarrier(), g_orig_SetRenderState)(dev, state, value);
    if (SUCCEEDED(hr) && state < 256) {
        g_rsCache[state] = value;
        g_rsValid[state] = true;
    }
    return hr;
}

static HRESULT __stdcall Hooked_SetTextureStageState(void* dev, DWORD stage, DWORD type, DWORD value) {
    CheckDeviceChange(dev);
    ++g_statCalls[1];

    DWORD idx = (stage & 7) * 32 + (type & 31);
    if (idx < 256 && g_tssValid[idx] && g_tssCache[idx] == value)
        ++g_wouldSkip[1];
    HRESULT hr = (D3D9_StateBarrier(), g_orig_SetTextureStageState)(dev, stage, type, value);
    if (SUCCEEDED(hr) && idx < 256) {
        g_tssCache[idx] = value;
        g_tssValid[idx] = true;
    }
    return hr;
}

// What a skipped SetSamplerState would save, measured rather than assumed: one call in
// kSsTimeEvery is timed with the time-stamp counter, kept apart by whether the value was
// already set. The detour runs on the thread that calls the device, so these are written
// by one thread and read by the report on the same one.
static const unsigned long kSsTimeEvery = 256;
static unsigned long       g_ssTimeTick = 0;
static unsigned long long  g_ssCyc[2]   = {};   // [0] value changed, [1] value already set
static unsigned long       g_ssCycN[2]  = {};
static unsigned long long  g_ssTsc0 = 0, g_ssQpc0 = 0;

static HRESULT __stdcall Hooked_SetSamplerState(void* dev, DWORD sampler, DWORD type, DWORD value) {
    CheckDeviceChange(dev);
    ++g_statCalls[2];

    DWORD idx = (sampler & 15) * 16 + (type & 15);
    const bool repeated = idx < 256 && g_ssValid[idx] && g_ssCache[idx] == value;
    if (repeated)
        ++g_wouldSkip[2];
    HRESULT hr;
    if (++g_ssTimeTick >= kSsTimeEvery) {
        g_ssTimeTick = 0;
        const unsigned long long t0 = __rdtsc();
        hr = (D3D9_StateBarrier(), g_orig_SetSamplerState)(dev, sampler, type, value);
        const unsigned long long dt = __rdtsc() - t0;
        if (!g_ssTsc0) {
            LARGE_INTEGER q; QueryPerformanceCounter(&q);
            g_ssQpc0 = (unsigned long long)q.QuadPart;
            g_ssTsc0 = t0;
        }
        g_ssCyc[repeated ? 1 : 0] += dt;
        ++g_ssCycN[repeated ? 1 : 0];
    } else {
        hr = (D3D9_StateBarrier(), g_orig_SetSamplerState)(dev, sampler, type, value);
    }
    if (SUCCEEDED(hr) && idx < 256) {
        g_ssCache[idx] = value;
        g_ssValid[idx] = true;
    }
    return hr;
}

// The last thing that can change what a held draw produces without going near
// the device: the client rewriting a bound texture's pixels.
//
// IDirect3DTexture9, CubeTexture9 and VolumeTexture9 all put their lock at
// vtable slot 19 - LockRect, LockRect and LockBox - and all three take
// (Level, out, rect-or-box, Flags), so the flags sit at [esp+20] on entry for
// every one of them and a single thunk shape covers the lot. Each type has its
// own vtable, so there is a small table of them rather than one slot; every
// texture a D3D9 implementation hands out shares the vtable of its type.
//
// D3DLOCK_READONLY promises not to write, so it is not a barrier. Everything
// else is.
//
// If a fourth vtable turns up, or a patch fails, merging stops for the session
// rather than continuing with a hole in it. Refusing to merge is always correct;
// merging across a texture rewrite is not.
static const int kMaxTexVTables = 4;
static uintptr_t* g_texLockVT[kMaxTexVTables] = {};
static int        g_texLockCount = 0;

// One original per vtable, named rather than indexed: a naked thunk has to
// name the pointer it jumps through.
static void* g_texLockOrig0 = nullptr;
static void* g_texLockOrig1 = nullptr;
static void* g_texLockOrig2 = nullptr;
static void* g_texLockOrig3 = nullptr;

static __declspec(naked) void g_bThunk_TexLock0() {
    __asm {
        mov  eax, [esp+20]
        push eax
        call D3D9DrawMerge_TextureLockBarrier
        add  esp, 4
        jmp  dword ptr [g_texLockOrig0]
    }
}
static __declspec(naked) void g_bThunk_TexLock1() {
    __asm {
        mov  eax, [esp+20]
        push eax
        call D3D9DrawMerge_TextureLockBarrier
        add  esp, 4
        jmp  dword ptr [g_texLockOrig1]
    }
}
static __declspec(naked) void g_bThunk_TexLock2() {
    __asm {
        mov  eax, [esp+20]
        push eax
        call D3D9DrawMerge_TextureLockBarrier
        add  esp, 4
        jmp  dword ptr [g_texLockOrig2]
    }
}
static __declspec(naked) void g_bThunk_TexLock3() {
    __asm {
        mov  eax, [esp+20]
        push eax
        call D3D9DrawMerge_TextureLockBarrier
        add  esp, 4
        jmp  dword ptr [g_texLockOrig3]
    }
}

static void** const g_texLockOrigSlot[kMaxTexVTables] = {
    &g_texLockOrig0, &g_texLockOrig1, &g_texLockOrig2, &g_texLockOrig3
};

static void* const g_texLockThunks[kMaxTexVTables] = {
    (void*)g_bThunk_TexLock0, (void*)g_bThunk_TexLock1,
    (void*)g_bThunk_TexLock2, (void*)g_bThunk_TexLock3
};

// Called from Hooked_SetTexture for every texture the client binds. The common
// case is the third instruction: a vtable already in the table.
static void NoteBoundTexture(void* tex) {
    if (!tex || !IsReadable((uintptr_t)tex)) return;
    uintptr_t* vt = *(uintptr_t**)tex;
    if (!vt) return;
    for (int i = 0; i < g_texLockCount; i++)
        if (g_texLockVT[i] == vt) return;

    if (g_texLockCount >= kMaxTexVTables || !IsReadable((uintptr_t)vt)) {
        Log("[DrawMerger] more than %d texture vtables appeared, so one type's "
            "lock cannot be made a barrier. Merging stops here.", kMaxTexVTables);
        D3D9DrawMerge_Disable();
        g_texLockCount = kMaxTexVTables;   // stop looking
        return;
    }

    const int slot = g_texLockCount;
    uintptr_t orig = vt[19];
    DWORD prot;
    if (!IsReadable(orig) ||
        !VirtualProtect(&vt[19], sizeof(void*), PAGE_EXECUTE_READWRITE, &prot)) {
        Log("[DrawMerger] could not make a texture lock a merge barrier. "
            "Merging stops here.");
        D3D9DrawMerge_Disable();
        g_texLockCount = kMaxTexVTables;
        return;
    }
    *g_texLockOrigSlot[slot] = (void*)orig;
    g_texLockVT[slot]        = vt;
    vt[19] = (uintptr_t)g_texLockThunks[slot];
    VirtualProtect(&vt[19], sizeof(void*), prot, &prot);
    ++g_texLockCount;
    Log("[DrawMerger] texture lock is a merge barrier now (%d of %d vtables).",
        g_texLockCount, kMaxTexVTables);
}

static HRESULT __stdcall Hooked_SetTexture(void* dev, DWORD stage, void* tex) {
    CheckDeviceChange(dev);
    ++g_statCalls[3];
    if (Config::g_settings.OptDrawMerge && g_texLockCount < kMaxTexVTables)
        NoteBoundTexture(tex);

    // The recycling argument, written out because the measurement below exists to
    // decide whether to act on it and the reasoning should not be invented on the
    // day the number arrives.
    //
    // The stated risk is that a texture is freed and a new one lands at the same
    // address, so a cached pointer matches an object that is no longer the one
    // the client means. That cannot happen to this particular cache.
    //
    // SetTexture AddRefs the texture it binds and Releases the one it replaces.
    // So while a stage holds pointer P, the device itself holds a reference to P,
    // and P cannot be freed - its address cannot be recycled while it is the
    // thing this cache would compare against. The moment the client binds
    // something else to that stage, the old texture may be freed, and that is
    // also the moment the cache entry is overwritten with the new pointer. The
    // cache mirrors exactly what the device is holding a reference to.
    //
    // What else the call does, since skipping an engine call on "it only skips
    // work" has been wrong three times here: it AddRefs the new and Releases the
    // old, which for new == old is a no-op in net, and it marks the stage dirty
    // for the next draw, which is what we would be avoiding on purpose.
    //
    // ANSWERED, and the answer is no. 2026-09-02: **23,825 of 28,624,247 calls**
    // - 0.083% - set the stage to the texture already bound. The safety argument
    // above is sound and there is nothing behind it worth having. The two
    // questions it was waiting on, whether calls arrive from more than one
    // thread and whether DXVK does bookkeeping beyond the D3D9 contract, stay
    // unasked because a tenth of a percent does not justify asking them.
    //
    // The comparison stays. It costs one compare and two stores on a call the
    // client makes twenty-eight million times, which is worth paying to keep the
    // answer current rather than have someone re-derive it from first principles
    // in a year. If a future client or a future addon set moves it, the number
    // in the report moves with it.
    //
    // Measurement only for now. The pointer is compared and counted, never acted
    // on, so a recycled address costs a wrong count and nothing else.
    if (stage < 8) {
        ++g_texCompared;
        if (g_shadowTexValid[stage] && g_shadowTex[stage] == tex) ++g_texWouldSkip;
        g_shadowTex[stage] = tex;
        g_shadowTexValid[stage] = true;
    }

    // Caching resource pointers is unsafe due to address recycling. Always call original.
    return (D3D9_StateBarrier(), g_orig_SetTexture)(dev, stage, tex);
}

static HRESULT __stdcall Hooked_SetTransform(void* dev, DWORD state, const void* matrix) {
    CheckDeviceChange(dev);
    ++g_statCalls[4];
    // Always call original transform setter to guarantee 100% world matrix accuracy on weapon sub-meshes
    return (D3D9_StateBarrier(), g_orig_SetTransform)(dev, state, matrix);
}

static HRESULT __stdcall Hooked_SetMaterial(void* dev, const void* material) {
    CheckDeviceChange(dev);
    ++g_statCalls[5];

    if (!material) {
        g_materialValid = false;
        return (D3D9_StateBarrier(), g_orig_SetMaterial)(dev, material);
    }

    uint32_t hash = HashMaterial((const DWORD*)material);
    if (g_materialValid && g_materialHash == hash)
        ++g_wouldSkip[5];
    HRESULT hr = (D3D9_StateBarrier(), g_orig_SetMaterial)(dev, material);
    if (SUCCEEDED(hr)) {
        g_materialHash = hash;
        g_materialValid = true;
    }
    return hr;
}

static HRESULT __stdcall Hooked_SetViewport(void* dev, const DWORD* vp) {
    CheckDeviceChange(dev);
    ++g_statCalls[6];

    if (!vp) {
        g_viewportValid = false;
        return (D3D9_StateBarrier(), g_orig_SetViewport)(dev, vp);
    }

    if (g_viewportValid && memcmp(g_viewportData, vp, sizeof(g_viewportData)) == 0) {
        ++g_statSkipped[6];
        return 0;
    }
    HRESULT hr = (D3D9_StateBarrier(), g_orig_SetViewport)(dev, vp);
    if (SUCCEEDED(hr)) {
        memcpy(g_viewportData, vp, sizeof(g_viewportData));
        g_viewportValid = true;
    }
    return hr;
}

static HRESULT __stdcall Hooked_SetScissorRect(void* dev, const RECT* rect) {
    CheckDeviceChange(dev);
    ++g_statCalls[7];

    if (!rect) {
        g_scissorValid = false;
        return (D3D9_StateBarrier(), g_orig_SetScissorRect)(dev, rect);
    }

    if (g_scissorValid
        && g_scissorData[0] == rect->left
        && g_scissorData[1] == rect->top
        && g_scissorData[2] == rect->right
        && g_scissorData[3] == rect->bottom) {
        ++g_statSkipped[7];
        return 0;
    }
    HRESULT hr = (D3D9_StateBarrier(), g_orig_SetScissorRect)(dev, rect);
    if (SUCCEEDED(hr)) {
        g_scissorData[0] = rect->left;
        g_scissorData[1] = rect->top;
        g_scissorData[2] = rect->right;
        g_scissorData[3] = rect->bottom;
        g_scissorValid = true;
    }
    return hr;
}

// A vertex or index buffer being written under a held draw is the one state
// change that does not go through the device at all. Both buffer types put
// Lock at vtable slot 11, and every buffer a D3D9 implementation hands out
// shares one vtable per type, so patching the first one seen covers all of
// them. The client passes the lock flags at [esp+20] on entry: return address,
// this, OffsetToLock, SizeToLock, ppbData, Flags.
static void* g_bOrig_VBLock = nullptr;
static __declspec(naked) void g_bThunk_VBLock() {
    __asm {
        mov  eax, [esp+20]
        push eax
        call D3D9DrawMerge_BufferLockBarrier
        add  esp, 4
        jmp  dword ptr [g_bOrig_VBLock]
    }
}

static void* g_bOrig_IBLock = nullptr;
static __declspec(naked) void g_bThunk_IBLock() {
    __asm {
        mov  eax, [esp+20]
        push eax
        call D3D9DrawMerge_BufferLockBarrier
        add  esp, 4
        jmp  dword ptr [g_bOrig_IBLock]
    }
}

static bool g_vbLockPatched = false;
static bool g_ibLockPatched = false;

// Patch slot 11 of a buffer's vtable, once, the first time one is seen.
static void PatchBufferLock(void* buffer, void** origSlot, void* thunk, bool* done,
                            const char* what) {
    if (*done || !buffer) return;
    *done = true;   // one attempt, win or lose - this runs on the draw path
    if (!IsReadable((uintptr_t)buffer)) return;
    uintptr_t* vt = *(uintptr_t**)buffer;
    if (!vt || !IsReadable((uintptr_t)vt)) return;
    uintptr_t orig = vt[11];
    if (!IsReadable(orig) || orig == (uintptr_t)thunk) return;
    DWORD prot;
    if (!VirtualProtect(&vt[11], sizeof(void*), PAGE_EXECUTE_READWRITE, &prot)) {
        Log("[DrawMerger] could not make the %s vtable writable; a lock on one "
            "will not release a held draw, so merging stays off.", what);
        return;
    }
    *origSlot = (void*)orig;
    vt[11] = (uintptr_t)thunk;
    VirtualProtect(&vt[11], sizeof(void*), prot, &prot);
    Log("[DrawMerger] %s Lock is a merge barrier now.", what);
}

static HRESULT __stdcall Hooked_SetStreamSource(void* dev, UINT stream, void* vb, UINT offset, UINT stride) {
    CheckDeviceChange(dev);
    ++g_statCalls[8];
    if (Config::g_settings.OptDrawMerge && !g_vbLockPatched)
        PatchBufferLock(vb, &g_bOrig_VBLock, (void*)g_bThunk_VBLock, &g_vbLockPatched,
                        "vertex buffer");
    // Caching resource pointers is unsafe due to address recycling. Always call original.
    return (D3D9_StateBarrier(), g_orig_SetStreamSource)(dev, stream, vb, offset, stride);
}

static HRESULT __stdcall Hooked_SetIndices(void* dev, void* ib) {
    CheckDeviceChange(dev);
    ++g_statCalls[9];
    if (Config::g_settings.OptDrawMerge && !g_ibLockPatched)
        PatchBufferLock(ib, &g_bOrig_IBLock, (void*)g_bThunk_IBLock, &g_ibLockPatched,
                        "index buffer");
    // Caching resource pointers is unsafe due to address recycling. Always call original.
    return (D3D9_StateBarrier(), g_orig_SetIndices)(dev, ib);
}

static HRESULT __stdcall Hooked_SetVertexDeclaration(void* dev, void* decl) {
    CheckDeviceChange(dev);
    ++g_statCalls[10];
    // Setting a declaration clears the FVF - the two are the same piece of
    // device state expressed two ways, and D3D9 has GetFVF return zero after
    // this. So the FVF cache below has to be dropped here, or a later SetFVF
    // matching what this file last cached is skipped while the device is still
    // holding the declaration, and the draw reads its vertices under the wrong
    // layout. Same shape as the viewport and the render target.
    g_fvfValid = false;
    // Caching resource pointers is unsafe due to address recycling. Always call original.
    return (D3D9_StateBarrier(), g_orig_SetVertexDeclaration)(dev, decl);
}

static HRESULT __stdcall Hooked_SetFVF(void* dev, DWORD fvf) {
    CheckDeviceChange(dev);
    ++g_statCalls[11];

    if (g_fvfValid && g_fvf == fvf) {
        ++g_statSkipped[11];
        return 0;
    }
    HRESULT hr = (D3D9_StateBarrier(), g_orig_SetFVF)(dev, fvf);
    if (SUCCEEDED(hr)) {
        g_fvf = fvf;
        g_fvfValid = true;
    }
    return hr;
}

static HRESULT __stdcall Hooked_SetVertexShader(void* dev, void* vs) {
    CheckDeviceChange(dev);
    ++g_statCalls[12];
    // Caching resource pointers is unsafe due to address recycling. Always call original.
    return (D3D9_StateBarrier(), g_orig_SetVertexShader)(dev, vs);
}

static HRESULT __stdcall Hooked_SetPixelShader(void* dev, void* ps) {
    CheckDeviceChange(dev);
    ++g_statCalls[13];
    // Caching resource pointers is unsafe due to address recycling. Always call original.
    return (D3D9_StateBarrier(), g_orig_SetPixelShader)(dev, ps);
}

// Setting a render target resets the viewport. That is D3D9's documented
// behaviour and it happens inside the driver, so nothing in this file sees it -
// and this file caches the viewport and skips a SetViewport that matches what it
// cached.
//
// The sequence that breaks is ordinary. The client sets a viewport for the main
// scene, points the device at a shadow surface, renders into it using the
// viewport SetRenderTarget implicitly gave it, points the device back at the
// back buffer, and sets the main viewport again. That last call matches the
// cache, so it was skipped - and the device had been left on whatever the
// render target change reset it to. The pass renders into the wrong rectangle.
//
// A shadow atlas is where that shows first and worst, because it is the render
// target whose size differs from the back buffer, and a slice rendered under the
// wrong rectangle is a shadow that does not refresh or flickers between frames.
// Two testers reported exactly that, and the switch this file lives behind is on
// by default.
//
// The depth stencil surface is here for the same reason and out of caution
// rather than from the specification. Both cost one redundant SetViewport per
// render target change, which is nothing next to being wrong.
typedef HRESULT (__stdcall *SetRenderTarget_t)(void*, DWORD, void*);
static SetRenderTarget_t g_orig_SetRenderTargetHook = nullptr;
static unsigned long g_rtInvalidations = 0;

static HRESULT __stdcall Hooked_SetRenderTarget(void* dev, DWORD idx, void* surf) {
    CheckDeviceChange(dev);
    ++g_statCalls[18];
    g_viewportValid = false;
    g_scissorValid  = false;
    ++g_rtInvalidations;
    return (D3D9_StateBarrier(), g_orig_SetRenderTargetHook)(dev, idx, surf);
}

typedef HRESULT (__stdcall *SetDepthStencil_t)(void*, void*);
static SetDepthStencil_t g_orig_SetDepthStencilHook = nullptr;

static HRESULT __stdcall Hooked_SetDepthStencilSurface(void* dev, void* surf) {
    CheckDeviceChange(dev);
    ++g_statCalls[19];
    g_viewportValid = false;
    g_scissorValid  = false;
    ++g_rtInvalidations;
    return (D3D9_StateBarrier(), g_orig_SetDepthStencilHook)(dev, surf);
}

static HRESULT __stdcall Hooked_Reset(void* dev, D3DPRESENT_PARAMETERS* params) {
    CheckDeviceChange(dev);
    ++g_statCalls[14];
    // A held draw must not survive the device losing its buffers.
    if (g_drawMergePending) D3D9DrawMerge_FlushPending();
    CrashDumper::Trace("D3D9 device Reset (dev=%p)", dev);
    Log("[D3D9State] Device Reset detected! Invalidating all caches and flushing delayed textures...");
    InvalidateAllCaches();
    RenderStateDedup_ClearCache();
    D3D9StateCache::InvalidateAllCaches(true);
    
    // Clear font glyph cache
    #ifndef TEST_DISABLE_FONT_METRICS_FAST
    FontGlyphCache::ClearCache();
    #endif

    // Flush delayed textures
    TextureUnloadDelay::Discard();

    InterlockedIncrement(&g_deviceResetCounter);

    HRESULT hr = g_orig_Reset(dev, params);
    if (SUCCEEDED(hr)) {
        InvalidateAllCaches();
        RenderStateDedup_ClearCache();
        D3D9StateCache::InvalidateAllCaches(true);
        #ifndef TEST_DISABLE_FONT_METRICS_FAST
        FontGlyphCache::ClearCache();
        #endif
        InterlockedIncrement(&g_deviceResetCounter);
    }
    return hr;
}

// The frame boundary for every D3D9 client, which on Windows is all of them.
//
// The frame benchmark was originally fed from the client's swap function
// (sub_69E220). That turned out to be the OpenGL present path - its body calls
// wglSwapLayerBuffers and glFinish - so under D3D9 it is never reached, and the
// benchmark silently recorded nothing even with the hook reporting ACTIVE.
// IDirect3DDevice9::Present is the real boundary, and this vtable is patched
// unconditionally, so the measurement now exists in every configuration.
static PresentFn g_orig_Present = nullptr;

static HRESULT __stdcall Hooked_Present(void* dev, const RECT* src, const RECT* dst,
                                        HWND hOverride, const RGNDATA* dirty) {
    CheckDeviceChange(dev);
    ++g_statCalls[15];
    // EndScene is a barrier and comes first in any correct renderer, so this
    // should never have anything to do. It is here so that nothing can be held
    // across a presented frame even if EndScene is skipped.
    if (g_drawMergePending) D3D9DrawMerge_FlushPending();
    // The census counts draws per frame and needs the frame boundary. Its own
    // Present hook is in the dead half of d3d9_state_cache.cpp, which is why
    // every report so far said "installed but no frame was presented".
    D3D9StateCache::NoteFrameForDrawCensus();
    // A frame at any frame rate, which the stride phase needs and the
    // maintenance tick cannot give it - that runs about once in four.
    //
    // With the render thread active this hook runs on that thread, and the
    // frame boundary does main-thread work (Lua, object manager, the client's
    // own tables). The render thread's Present entry point calls it on the
    // main thread instead, once per frame.
    if (!GxRT::OnRenderThread()) {
        M2AnimStride::OnPresent();
        FrameBench::OnPresent(FrameBench::Source::D3D9Present);
        WowOpt_OnFrameBoundary();
    }

    HRESULT hr = g_orig_Present(dev, src, dst, hOverride, dirty);

    // Drop the shadow state at the real frame boundary.
    //
    // The caches above answer "is this state already set?" by returning S_OK
    // without touching the device. That is only sound while this DLL is the sole
    // writer of device state, and it is not: any overlay injected into the
    // process - RTSS, Afterburner, Steam, Discord, OBS - issues its own D3D9
    // calls around Present. Once one changes a state we believe is current, every
    // later SetRenderState for it is skipped and the device keeps the overlay's
    // value. Wrong lighting, fog or colour-write state darkens the whole frame.
    //
    // OnFrameD3D9StateManager already invalidated per frame for exactly this
    // reason, but it runs from hooked_Sleep, which is gated to one tick every
    // SleepPrecisionValue ms (8 by default). That caps it near 125 ticks/second
    // while frames keep coming, and a client with frames to spare barely calls
    // Sleep at all - so above roughly 125 fps the per-frame invalidation quietly
    // stops being per-frame. That matches the report this fixes: flicker and a
    // darkened screen with an overlay running above 120 fps.
    //
    // Present is the one place that is a frame, at any frame rate. The Sleep-side
    // call stays as the fallback for the OpenGL swap path, where this hook never
    // runs. Done after the original returns, so whatever the overlay drew for
    // this frame is already behind us.
    InvalidateAllCaches();
    RenderStateDedup_ClearCache();

    return hr;
}

// VTable patching
// Draw-call census
// These two skip nothing and never will - they exist to answer one question
// that no instrument in this project could answer before: how many primitives
// does a draw call carry?
//
// It decides whether the largest entry in the profile is reducible. d3d9.dll is
// 7.75% of executing time, and under DXVK - which both testers run - that is the
// cost of recording calls on the main thread, because DXVK executes them on its
// own command-stream thread. Recording scales with the call count, so batching
// helps if and only if the calls are small. The average alone would hide that,
// so the spread is bucketed: a frame of ten thousand two-triangle draws and a
// frame of forty large ones can share an average and want opposite answers.
typedef HRESULT (__stdcall *DrawPrim_t)(void* dev, D3DPRIMITIVETYPE t, UINT start, UINT count);
static DrawPrim_t g_orig_DrawPrimitive = nullptr;
typedef HRESULT (__stdcall *DrawIdxPrim_t)(void* dev, D3DPRIMITIVETYPE t, INT base,
                                           UINT minV, UINT numV, UINT startIdx, UINT count);
static DrawIdxPrim_t g_orig_DrawIndexedPrimitive = nullptr;

// Plain 32-bit on the hottest calls in the frame, for the reason written above
// the state counters. Lower bounds, and the report says so.
// Primitives, in two words rather than one.
//
// This was a single `unsigned long`, and a tester's session summed 293 million
// draws at roughly seventeen primitives each - five billion, which does not fit
// in thirty-two bits. It wrapped, and the report printed the total going down
// between reports: 3.40 billion, then 1.44 billion, then 479 million, then 223
// million, ending at "0.8 primitives per call" for a client whose draws are all
// triangle lists and therefore carry at least one each.
//
// A plain sixty-four-bit counter is not the fix here: this is the busiest call
// in the frame and a lock cmpxchg8b on it is the shape that has eaten three
// optimisations in this project. Two thirty-two-bit words are. Each store is
// atomic on x86, the wrap count can only lose an increment the way any plain
// counter can, and the report puts them back together.
static unsigned long g_drawPrims  = 0;    // low word, wraps
static unsigned long g_drawPrimWraps = 0; // how many times it has
static unsigned long g_drawTiny   = 0;    // draws of eight primitives or fewer
static unsigned long g_drawBucket[6] = {};  // 1-2, 3-8, 9-32, 33-128, 129-512, 513+
static const char*   g_bucketName[6] = { "1-2", "3-8", "9-32", "33-128", "129-512", "513+" };

static inline void NoteDraw(UINT prims) {
    const unsigned long before = g_drawPrims;
    g_drawPrims += prims;
    if (g_drawPrims < before) ++g_drawPrimWraps;
    int b;
    if      (prims <= 2)   b = 0;
    else if (prims <= 8)   b = 1;
    else if (prims <= 32)  b = 2;
    else if (prims <= 128) b = 3;
    else if (prims <= 512) b = 4;
    else                   b = 5;
    g_drawBucket[b]++;
    if (b <= 1) g_drawTiny++;
}

static HRESULT __stdcall Hooked_DrawPrimitive(void* dev, D3DPRIMITIVETYPE t,
                                              UINT start, UINT count) {
    CheckDeviceChange(dev);
    ++g_statCalls[16];
    NoteDraw(count);
    return g_orig_DrawPrimitive(dev, t, start, count);
}

static HRESULT __stdcall Hooked_DrawIndexedPrimitive(void* dev, D3DPRIMITIVETYPE t, INT base,
                                                     UINT minV, UINT numV, UINT startIdx,
                                                     UINT count) {
    CheckDeviceChange(dev);
    ++g_statCalls[17];
    NoteDraw(count);
    return g_orig_DrawIndexedPrimitive(dev, t, base, minV, numV, startIdx, count);
}

// Which of the twenty are worth a place in the device's vtable when nobody is
// measuring anything.
//
// A three-hour session put 4.8 billion calls through them, and the per-hook
// table in that log says what each one did with its share:
//
//     SetViewport             18,994,540   skipped 1,123,888  (5.9%)
//     SetScissorRect           6,635,708   skipped   442,464  (6.7%)
//     SetRenderState         430,665,355   skipped         0
//     SetSamplerState        601,228,496   skipped         0
//     SetTexture           1,206,479,830   skipped         0
//     SetStreamSource        270,949,042   skipped         0
//     SetIndices             359,576,568   skipped         0
//     SetVertexDeclaration    69,030,300   skipped         0
//     SetTransform            51,235,171   skipped         0
//     DrawIndexedPrimitive 1,462,163,962   counting only
//
// Two of them do work. The rest increment a counter and return to the client,
// and the numbers they were counting have been answered twice over on two
// different machines. That is about five thousand detours a frame, every frame,
// for arithmetic nobody is reading.
//
// So they install while something is measuring and stay out of the way
// otherwise. What is kept and why:
//
//   SetViewport, SetScissorRect      they are the cache, and it skips
//   SetRenderTarget, SetDepthStencil they drop that cache, which is the fix for
//                                    shadows drawing into the wrong rectangle
//   Present                          the frame counter, and it is once a frame
//   Reset                            the device lifecycle; it must be there for
//                                    the one call in a session that arrives
static bool HookEarnsItsPlace(int i) {
    switch (i) {
        case 6:   // SetViewport
        case 7:   // SetScissorRect
        case 14:  // Reset
        case 15:  // Present
        case 18:  // SetRenderTarget
        case 19:  // SetDepthStencilSurface
            return true;
        default:
            return Config::g_settings.OptDrawCensus ||
                   Config::g_settings.OptDrawMerge;
    }
}

static void* g_hookFuncs[NUM_HOOKS] = {
    (void*)Hooked_SetRenderState,
    (void*)Hooked_SetTextureStageState,
    (void*)Hooked_SetSamplerState,
    (void*)Hooked_SetTexture,
    (void*)Hooked_SetTransform,
    (void*)Hooked_SetMaterial,
    (void*)Hooked_SetViewport,
    (void*)Hooked_SetScissorRect,
    (void*)Hooked_SetStreamSource,
    (void*)Hooked_SetIndices,
    (void*)Hooked_SetVertexDeclaration,
    (void*)Hooked_SetFVF,
    (void*)Hooked_SetVertexShader,
    (void*)Hooked_SetPixelShader,
    (void*)Hooked_Reset,
    (void*)Hooked_Present,
    (void*)Hooked_DrawPrimitive,
    (void*)Hooked_DrawIndexedPrimitive,
    (void*)Hooked_SetRenderTarget,
    (void*)Hooked_SetDepthStencilSurface
};

static void SetHookOrigin(int idx, void* orig) {
    switch (idx) {
        case 0:  g_orig_SetRenderState       = (SetRenderState_t)orig; break;
        case 1:  g_orig_SetTextureStageState = (SetTextureStageState_t)orig; break;
        case 2:  g_orig_SetSamplerState      = (SetSamplerState_t)orig; break;
        case 3:  g_orig_SetTexture            = (SetTexture_t)orig; break;
        case 4:  g_orig_SetTransform          = (SetTransform_t)orig; break;
        case 5:  g_orig_SetMaterial           = (SetMaterial_t)orig; break;
        case 6:  g_orig_SetViewport           = (SetViewport_t)orig; break;
        case 7:  g_orig_SetScissorRect        = (SetScissorRect_t)orig; break;
        case 8:  g_orig_SetStreamSource       = (SetStreamSource_t)orig; break;
        case 9:  g_orig_SetIndices            = (SetIndices_t)orig; break;
        case 10: g_orig_SetVertexDeclaration  = (SetVertexDeclaration_t)orig; break;
        case 11: g_orig_SetFVF                = (SetFVF_t)orig; break;
        case 12: g_orig_SetVertexShader       = (SetVertexShader_t)orig; break;
        case 13: g_orig_SetPixelShader        = (SetPixelShader_t)orig; break;
        case 14: g_orig_Reset                 = (Reset_t)orig; break;
        case 15: g_orig_Present               = (PresentFn)orig; break;
        case 16: g_orig_DrawPrimitive         = (DrawPrim_t)orig; break;
        case 17: g_orig_DrawIndexedPrimitive  = (DrawIdxPrim_t)orig; break;
        case 18: g_orig_SetRenderTargetHook = (SetRenderTarget_t)orig; break;
        case 19: g_orig_SetDepthStencilHook = (SetDepthStencil_t)orig; break;
        default: break;
    }
}

#ifndef ADDR_CGXDEVICED3D_PTR
#define ADDR_CGXDEVICED3D_PTR  0x00C5DF88  // global CGxDeviceD3d*
#endif


// ---------------------------------------------------------------------------
// Merge barriers
//
// The draw-merge census counts two consecutive DrawIndexedPrimitive calls as
// joinable when the state epoch has not moved between them. The epoch is bumped
// by the fourteen setters this module wraps - and by nothing else, which means
// the census has been counting a pair as joinable when the client changed a
// vertex shader constant between them, or cleared the render target, or ended
// the scene. It over-counts, and a census that over-counts the thing it exists
// to decide is worse than no census.
//
// Every device method below can change what a draw produces. None of them needs
// a wrapper with a signature: a naked thunk that bumps the epoch and jumps to the
// original leaves the stack exactly as it was, so the original returns straight
// to the client and the argument count never comes into it. Two instructions.
// The flags the inc touches are not live across a __stdcall boundary.
//
// Gated on the draw census, which is off by default. These exist to make its
// answer sound and there is nothing else to spend them on, so the default path
// keeps the fourteen it had.
//
// One hole is left and it is named rather than papered over:
// IDirect3DStateBlock9::Apply changes device state without touching the device
// vtable at all. It cannot be seen from here. So state block creation is counted
// separately, and the census says its answer is unsound if the count is not zero.

static unsigned long g_stateBlockCreates = 0;

static void* g_bOrig_UpdateSurface = nullptr;
static __declspec(naked) void g_bThunk_UpdateSurface() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_UpdateSurface]
    }
}

static void* g_bOrig_UpdateTexture = nullptr;
static __declspec(naked) void g_bThunk_UpdateTexture() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_UpdateTexture]
    }
}

static void* g_bOrig_DrawRectPatch = nullptr;
static __declspec(naked) void g_bThunk_DrawRectPatch() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_DrawRectPatch]
    }
}

static void* g_bOrig_DrawTriPatch = nullptr;
static __declspec(naked) void g_bThunk_DrawTriPatch() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_DrawTriPatch]
    }
}

// SetRenderTarget and SetDepthStencilSurface used to be barrier thunks here.
// They are real hooks now, in the main table above, because they do more than
// move the epoch: a render target change resets the viewport inside the driver
// and this file caches the viewport. See Hooked_SetRenderTarget.
//
// Reading back what has been drawn. A held draw has not reached the target
// yet, so a readback that happens first sees the frame without it - a
// screenshot missing a model, a portrait missing its character.
static void* g_bOrig_GetRenderTargetData = nullptr;
static __declspec(naked) void g_bThunk_GetRenderTargetData() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_GetRenderTargetData]
    }
}

static void* g_bOrig_GetFrontBufferData = nullptr;
static __declspec(naked) void g_bThunk_GetFrontBufferData() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_GetFrontBufferData]
    }
}

static void* g_bOrig_StretchRect = nullptr;
static __declspec(naked) void g_bThunk_StretchRect() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_StretchRect]
    }
}

static void* g_bOrig_ColorFill = nullptr;
static __declspec(naked) void g_bThunk_ColorFill() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_ColorFill]
    }
}



static void* g_bOrig_BeginScene = nullptr;
static __declspec(naked) void g_bThunk_BeginScene() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_BeginScene]
    }
}

static void* g_bOrig_EndScene = nullptr;
static __declspec(naked) void g_bThunk_EndScene() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_EndScene]
    }
}

static void* g_bOrig_Clear = nullptr;
static __declspec(naked) void g_bThunk_Clear() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_Clear]
    }
}

static void* g_bOrig_SetLight = nullptr;
static __declspec(naked) void g_bThunk_SetLight() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetLight]
    }
}

static void* g_bOrig_LightEnable = nullptr;
static __declspec(naked) void g_bThunk_LightEnable() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_LightEnable]
    }
}

static void* g_bOrig_SetClipPlane = nullptr;
static __declspec(naked) void g_bThunk_SetClipPlane() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetClipPlane]
    }
}

static void* g_bOrig_SetClipStatus = nullptr;
static __declspec(naked) void g_bThunk_SetClipStatus() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetClipStatus]
    }
}

static void* g_bOrig_SetPaletteEntries = nullptr;
static __declspec(naked) void g_bThunk_SetPaletteEntries() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetPaletteEntries]
    }
}

static void* g_bOrig_SetCurrentTexturePalette = nullptr;
static __declspec(naked) void g_bThunk_SetCurrentTexturePalette() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetCurrentTexturePalette]
    }
}

static void* g_bOrig_SetSoftwareVertexProcessing = nullptr;
static __declspec(naked) void g_bThunk_SetSoftwareVertexProcessing() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetSoftwareVertexProcessing]
    }
}

static void* g_bOrig_SetNPatchMode = nullptr;
static __declspec(naked) void g_bThunk_SetNPatchMode() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetNPatchMode]
    }
}

static void* g_bOrig_DrawPrimitiveUP = nullptr;
static __declspec(naked) void g_bThunk_DrawPrimitiveUP() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_DrawPrimitiveUP]
    }
}

static void* g_bOrig_DrawIndexedPrimitiveUP = nullptr;
static __declspec(naked) void g_bThunk_DrawIndexedPrimitiveUP() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_DrawIndexedPrimitiveUP]
    }
}

static void* g_bOrig_ProcessVertices = nullptr;
static __declspec(naked) void g_bThunk_ProcessVertices() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_ProcessVertices]
    }
}

static void* g_bOrig_SetVertexShaderConstantF = nullptr;
static __declspec(naked) void g_bThunk_SetVertexShaderConstantF() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetVertexShaderConstantF]
    }
}

static void* g_bOrig_SetVertexShaderConstantI = nullptr;
static __declspec(naked) void g_bThunk_SetVertexShaderConstantI() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetVertexShaderConstantI]
    }
}

static void* g_bOrig_SetVertexShaderConstantB = nullptr;
static __declspec(naked) void g_bThunk_SetVertexShaderConstantB() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetVertexShaderConstantB]
    }
}

static void* g_bOrig_SetStreamSourceFreq = nullptr;
static __declspec(naked) void g_bThunk_SetStreamSourceFreq() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetStreamSourceFreq]
    }
}

static void* g_bOrig_SetPixelShaderConstantF = nullptr;
static __declspec(naked) void g_bThunk_SetPixelShaderConstantF() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetPixelShaderConstantF]
    }
}

static void* g_bOrig_SetPixelShaderConstantI = nullptr;
static __declspec(naked) void g_bThunk_SetPixelShaderConstantI() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetPixelShaderConstantI]
    }
}

static void* g_bOrig_SetPixelShaderConstantB = nullptr;
static __declspec(naked) void g_bThunk_SetPixelShaderConstantB() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_SetPixelShaderConstantB]
    }
}

static void* g_bOrig_MultiplyTransform = nullptr;
static __declspec(naked) void g_bThunk_MultiplyTransform() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_MultiplyTransform]
    }
}

static void* g_bOrig_CreateStateBlock = nullptr;
static __declspec(naked) void g_bThunk_CreateStateBlock() {
    __asm {
        inc dword ptr [g_stateEpoch]
        inc dword ptr [g_stateBlockCreates]
        pushad
        call D3D9DrawMerge_Disable
        popad
        jmp dword ptr [g_bOrig_CreateStateBlock]
    }
}

static void* g_bOrig_EndStateBlock = nullptr;
static __declspec(naked) void g_bThunk_EndStateBlock() {
    __asm {
        inc dword ptr [g_stateEpoch]
        inc dword ptr [g_stateBlockCreates]
        pushad
        call D3D9DrawMerge_Disable
        popad
        jmp dword ptr [g_bOrig_EndStateBlock]
    }
}

// A texture's pixels can also be written through a surface, and an occlusion
// query counts the pixels drawn between its two Issue calls. Neither goes
// through the device vtable, and neither can be reached from a hook that waits
// for the client to hand one over: a surface comes from GetSurfaceLevel as
// readily as from GetBackBuffer, and waiting means the merger runs from the
// first frame with those two barriers missing, which is the shape of the defect
// that put smeared triangles on a tester's screen.
//
// So this asks the device for one of each, patches the vtable every object of
// that type shares, and releases them. It happens before anything is held and
// before anything else is patched, so the calls go to the client's own
// implementation.
//
// IDirect3DSurface9 puts LockRect at slot 13 and takes (pLockedRect, pRect,
// Flags) with no Level, so the flags are at [esp+16] rather than the [esp+20]
// the texture and buffer locks use. IDirect3DQuery9 puts Issue at slot 6.
static void* g_bOrig_SurfLock = nullptr;
static __declspec(naked) void g_bThunk_SurfLock() {
    __asm {
        mov  eax, [esp+16]
        push eax
        call D3D9DrawMerge_TextureLockBarrier
        add  esp, 4
        jmp  dword ptr [g_bOrig_SurfLock]
    }
}

static void* g_bOrig_QueryIssue = nullptr;
static __declspec(naked) void g_bThunk_QueryIssue() {
    __asm {
        inc dword ptr [g_stateEpoch]
        cmp byte ptr [g_drawMergePending], 0
        je  nothing_held
        pushad
        call D3D9DrawMerge_FlushPending
        popad
    nothing_held:
        jmp dword ptr [g_bOrig_QueryIssue]
    }
}

// Both barriers in, or neither: the merger refuses to start on anything less.
static bool g_derivedBarriersOk = false;

static bool PatchSharedSlot(void* obj, int slot, void* thunk, void** origSlot,
                            const char* what) {
    if (!obj || !IsReadable((uintptr_t)obj)) return false;
    uintptr_t* vt = *(uintptr_t**)obj;
    if (!vt || !IsReadable((uintptr_t)vt)) return false;
    uintptr_t orig = vt[slot];
    if (!IsReadable(orig)) return false;
    if (orig == (uintptr_t)thunk) return true;      // already ours
    DWORD prot;
    if (!VirtualProtect(&vt[slot], sizeof(void*), PAGE_EXECUTE_READWRITE, &prot))
        return false;
    *origSlot = (void*)orig;
    vt[slot] = (uintptr_t)thunk;
    VirtualProtect(&vt[slot], sizeof(void*), prot, &prot);
    Log("[DrawMerger] %s is a merge barrier now.", what);
    return true;
}

// Called from PatchDeviceVTable before anything else is patched.
static void PatchDerivedVTables(IDirect3DDevice9* dev) {
    if (!Config::g_settings.OptDrawMerge) return;

    bool surfOk = false;
    IDirect3DSurface9* surf = nullptr;
    if (SUCCEEDED(dev->GetRenderTarget(0, &surf)) && surf) {
        surfOk = PatchSharedSlot(surf, 13, (void*)g_bThunk_SurfLock,
                                 &g_bOrig_SurfLock, "surface LockRect");
        surf->Release();
    }
    if (!surfOk)
        Log("[DrawMerger] could not reach a surface to make its LockRect a "
            "barrier, so a texture written through one would go unseen.");

    bool queryOk = false;
    IDirect3DQuery9* q = nullptr;
    HRESULT qhr = dev->CreateQuery(D3DQUERYTYPE_OCCLUSION, &q);
    if (SUCCEEDED(qhr) && q) {
        queryOk = PatchSharedSlot(q, 6, (void*)g_bThunk_QueryIssue,
                                  &g_bOrig_QueryIssue, "query Issue");
        q->Release();
    } else if (qhr == D3DERR_NOTAVAILABLE) {
        // The device cannot make occlusion queries, so the client cannot have
        // one, so nothing can Issue one. Nothing to guard.
        queryOk = true;
        Log("[DrawMerger] this device has no occlusion queries, so none can be "
            "issued across a held draw.");
    }
    if (!queryOk)
        Log("[DrawMerger] could not reach a query to make its Issue a barrier, "
            "so an occlusion count taken across a held draw would be short.");

    g_derivedBarriersOk = surfOk && queryOk;
}

bool D3D9StateManager_DerivedBarriersOk(void) { return g_derivedBarriersOk; }

struct Barrier { int vt; const char* name; void* thunk; void** origSlot; bool patched; };
static Barrier g_barriers[] = {
    {  30, "UpdateSurface", (void*)g_bThunk_UpdateSurface, &g_bOrig_UpdateSurface, false },
    {  31, "UpdateTexture", (void*)g_bThunk_UpdateTexture, &g_bOrig_UpdateTexture, false },
    { 115, "DrawRectPatch", (void*)g_bThunk_DrawRectPatch, &g_bOrig_DrawRectPatch, false },
    { 116, "DrawTriPatch", (void*)g_bThunk_DrawTriPatch, &g_bOrig_DrawTriPatch, false },
    {  32, "GetRenderTargetData", (void*)g_bThunk_GetRenderTargetData, &g_bOrig_GetRenderTargetData, false },
    {  33, "GetFrontBufferData", (void*)g_bThunk_GetFrontBufferData, &g_bOrig_GetFrontBufferData, false },
    {  34, "StretchRect", (void*)g_bThunk_StretchRect, &g_bOrig_StretchRect, false },
    {  35, "ColorFill", (void*)g_bThunk_ColorFill, &g_bOrig_ColorFill, false },
    {  41, "BeginScene", (void*)g_bThunk_BeginScene, &g_bOrig_BeginScene, false },
    {  42, "EndScene", (void*)g_bThunk_EndScene, &g_bOrig_EndScene, false },
    {  43, "Clear", (void*)g_bThunk_Clear, &g_bOrig_Clear, false },
    {  46, "MultiplyTransform", (void*)g_bThunk_MultiplyTransform, &g_bOrig_MultiplyTransform, false },
    {  51, "SetLight", (void*)g_bThunk_SetLight, &g_bOrig_SetLight, false },
    {  53, "LightEnable", (void*)g_bThunk_LightEnable, &g_bOrig_LightEnable, false },
    {  55, "SetClipPlane", (void*)g_bThunk_SetClipPlane, &g_bOrig_SetClipPlane, false },
    {  62, "SetClipStatus", (void*)g_bThunk_SetClipStatus, &g_bOrig_SetClipStatus, false },
    {  71, "SetPaletteEntries", (void*)g_bThunk_SetPaletteEntries, &g_bOrig_SetPaletteEntries, false },
    {  73, "SetCurrentTexturePalette", (void*)g_bThunk_SetCurrentTexturePalette, &g_bOrig_SetCurrentTexturePalette, false },
    {  77, "SetSoftwareVertexProcessing", (void*)g_bThunk_SetSoftwareVertexProcessing, &g_bOrig_SetSoftwareVertexProcessing, false },
    {  79, "SetNPatchMode", (void*)g_bThunk_SetNPatchMode, &g_bOrig_SetNPatchMode, false },
    {  83, "DrawPrimitiveUP", (void*)g_bThunk_DrawPrimitiveUP, &g_bOrig_DrawPrimitiveUP, false },
    {  84, "DrawIndexedPrimitiveUP", (void*)g_bThunk_DrawIndexedPrimitiveUP, &g_bOrig_DrawIndexedPrimitiveUP, false },
    {  85, "ProcessVertices", (void*)g_bThunk_ProcessVertices, &g_bOrig_ProcessVertices, false },
    {  94, "SetVertexShaderConstantF", (void*)g_bThunk_SetVertexShaderConstantF, &g_bOrig_SetVertexShaderConstantF, false },
    {  96, "SetVertexShaderConstantI", (void*)g_bThunk_SetVertexShaderConstantI, &g_bOrig_SetVertexShaderConstantI, false },
    {  98, "SetVertexShaderConstantB", (void*)g_bThunk_SetVertexShaderConstantB, &g_bOrig_SetVertexShaderConstantB, false },
    { 102, "SetStreamSourceFreq", (void*)g_bThunk_SetStreamSourceFreq, &g_bOrig_SetStreamSourceFreq, false },
    { 109, "SetPixelShaderConstantF", (void*)g_bThunk_SetPixelShaderConstantF, &g_bOrig_SetPixelShaderConstantF, false },
    { 111, "SetPixelShaderConstantI", (void*)g_bThunk_SetPixelShaderConstantI, &g_bOrig_SetPixelShaderConstantI, false },
    { 113, "SetPixelShaderConstantB", (void*)g_bThunk_SetPixelShaderConstantB, &g_bOrig_SetPixelShaderConstantB, false },
    {  59, "CreateStateBlock", (void*)g_bThunk_CreateStateBlock, &g_bOrig_CreateStateBlock, false },
    {  61, "EndStateBlock", (void*)g_bThunk_EndStateBlock, &g_bOrig_EndStateBlock, false },
};
static const int NUM_BARRIERS = (int)(sizeof(g_barriers) / sizeof(g_barriers[0]));
static int g_barriersPatched = 0;

// Patch the barrier slots. Same mechanism as the loop below, kept separate
// because these carry no state of their own and must not be able to fail the
// eighteen that do: a barrier that will not patch costs the census its
// soundness, and the report says so, but the state manager still works.
void D3D9StateManager_GetBarrierState(int* installed, int* total,
                                      unsigned long* stateBlocks) {
    if (installed)   *installed   = g_barriersPatched;
    if (total)       *total       = NUM_BARRIERS;
    if (stateBlocks) *stateBlocks = g_stateBlockCreates;
}

static void PatchBarriers(uintptr_t* vtable) {
    // Both, and not just the census. The merger holds a draw call and needs
    // these to let it go again; gating them on the census alone meant a tester
    // who ticked only Draw Call Merging ran the merger with thirty of its
    // forty-four barriers missing, and geometry came out drawn under the
    // transform of whatever was in front of it.
    if (!Config::g_settings.OptDrawCensus && !Config::g_settings.OptDrawMerge) return;
    for (int i = 0; i < NUM_BARRIERS; i++) {
        Barrier& b = g_barriers[i];
        if (b.patched) continue;
        uintptr_t orig = vtable[b.vt];
        if (!IsReadable(orig)) continue;
        if (orig == (uintptr_t)b.thunk) { b.patched = true; g_barriersPatched++; continue; }
        DWORD prot;
        if (!VirtualProtect(&vtable[b.vt], sizeof(void*), PAGE_EXECUTE_READWRITE, &prot))
            continue;
        *b.origSlot = (void*)orig;
        vtable[b.vt] = (uintptr_t)b.thunk;
        VirtualProtect(&vtable[b.vt], sizeof(void*), prot, &prot);
        b.patched = true;
        g_barriersPatched++;
    }
}

static bool PatchDeviceVTable(void* pDevice) {
    WinLockGuard lock(g_vtableMutex);
    if (!pDevice || g_deviceHooked) return false;

    uintptr_t* vtable = *(uintptr_t**)pDevice;
    if (!vtable || !IsReadable((uintptr_t)vtable)) return false;

    // Before anything is patched, so these calls reach the client's own
    // implementation rather than one of our thunks.
    PatchDerivedVTables((IDirect3DDevice9*)pDevice);

    int patched = 0;
    int measuringOnly = 0;
    for (int i = 0; i < NUM_HOOKS; i++) {
        int vtIndex = g_vtableIndices[i];
        if (!g_hookFuncs[i]) continue;
        if (!HookEarnsItsPlace(i)) { measuringOnly++; continue; }

        uintptr_t origFunc = vtable[vtIndex];
        if (!IsReadable(origFunc)) {
            Log("[D3D9State] Skipping vtable[%d] — original not readable", vtIndex);
            continue;
        }

        // Avoid infinite recursion: check if the vtable entry is already pointing to our hook
        if (origFunc == (uintptr_t)g_hookFuncs[i]) {
            g_vtablePatched[i] = true;
            patched++;
            continue;
        }

        // The render thread's thunk over a hook this module wrote earlier. Its
        // original is that hook, so taking the thunk as this hook's original
        // closes a loop: hook, thunk, hook, until the stack ends. The first
        // in-game device restart with the render thread on did exactly that.
        // The hook is still there, under the thunk; leave both as they are.
        if (g_vtablePatched[i] && GxRT::IsThunk((const void*)origFunc)) {
            patched++;
            continue;
        }

        DWORD oldProtect;
        if (!VirtualProtect(&vtable[vtIndex], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            Log("[D3D9State] VirtualProtect failed for vtable[%d]", vtIndex);
            for (int j = i - 1; j >= 0; j--) {
                if (g_vtablePatched[j]) {
                    vtable[g_vtableIndices[j]] = (uintptr_t)g_vtableOriginals[j];
                    g_vtablePatched[j] = false;
                }
            }
            return false;
        }

        g_vtableOriginals[i] = (void*)origFunc;
        SetHookOrigin(i, (void*)origFunc);
        vtable[vtIndex] = (uintptr_t)g_hookFuncs[i];
        VirtualProtect(&vtable[vtIndex], sizeof(void*), oldProtect, &oldProtect);
        // (barriers are patched after this loop, see PatchBarriers)
        g_vtablePatched[i] = true;
        patched++;
    }

    PatchBarriers(vtable);

    // The draw census and the merger hook the two draw entry points through
    // MinHook, on the addresses this loop just replaced in the vtable. Their
    // own installer is unreachable - see InstallDrawHooks - so this is the only
    // thing that calls it.
    D3D9StateCache::InstallDrawHooks(g_vtableOriginals[16], g_vtableOriginals[17]);

    g_pDevice = pDevice;
    g_pPatchedVTable = vtable;
    g_deviceHooked = true;
    InterlockedIncrement(&g_deviceResetCounter);
    if (Config::g_settings.OptDrawCensus || Config::g_settings.OptDrawMerge) {
        Log("[D3D9State] %d of %d merge barriers installed. These bump the state "
            "epoch and jump straight to the original, so the draw-merge census "
            "stops counting a pair as joinable when the client changed a shader "
            "constant, cleared the target or ended the scene between them.%s",
            g_barriersPatched, NUM_BARRIERS,
            g_barriersPatched == NUM_BARRIERS ? ""
              : " Any that did not install leave the census over-counting, and "
                "the census says so.");
    }
    Log("[D3D9State] Device vtable patched: %d/%d state hooks installed "
        "(vtable: %p, resetCounter: %ld)", patched, NUM_HOOKS, vtable,
        g_deviceResetCounter);
    if (measuringOnly) {
        // Worded to stay out of the fault list. This is a decision, not a
        // failure, and it was being collected as one because "not installed"
        // is what a module says when it could not install.
        Log("[D3D9State]   %d of them are left out on purpose: their dedup was "
            "measured against two clients and skipped nothing, so all they can "
            "do now is count. Draw Call Census puts them back.", measuringOnly);
    }

    // Name these to the profiler. Sixteen detours on the device vtable are among
    // the most frequently entered code this DLL owns - a tester's session put
    // 43.7 million calls through SetVertexShader alone - and without a name they
    // land in the profile as bare "wowopt+0x" offsets that need this exact
    // build's linker map to resolve.
    for (int i = 0; i < NUM_HOOKS; i++)
        SamplingProfiler::RegisterSelfSymbol(g_statNames[i], g_hookFuncs[i]);

    return true;
}

// Split from UnpatchDeviceVTable() because MSVC forbids __try in a function
// that also has a C++ object needing unwinding (WinLockGuard) — C2712.
static void UnpatchDeviceVTableInner() {
    __try {
        uintptr_t* vtable = (uintptr_t*)g_pPatchedVTable;
        if (!IsReadable((uintptr_t)vtable)) {
            return;
        }

        // Restore state hooks in reverse order
        for (int i = NUM_HOOKS - 1; i >= 0; i--) {
            if (!g_vtablePatched[i]) continue;
            int vtIndex = g_vtableIndices[i];

            // Safety: verify that the target vtable address is still readable
            if (!IsReadable((uintptr_t)&vtable[vtIndex])) continue;

            // Verify that the vtable currently points to our hook before restoring it,
            // to prevent overwriting third-party hooks or crashing
            if (vtable[vtIndex] == (uintptr_t)g_hookFuncs[i]) {
                DWORD oldProtect;
                if (VirtualProtect(&vtable[vtIndex], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    vtable[vtIndex] = (uintptr_t)g_vtableOriginals[i];
                    VirtualProtect(&vtable[vtIndex], sizeof(void*), oldProtect, &oldProtect);
                }
            }
            g_vtablePatched[i] = false;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[D3D9State] SEH exception caught during UnpatchDeviceVTable!");
    }
}

static void UnpatchDeviceVTable() {
    WinLockGuard lock(g_vtableMutex);
    if (!g_deviceHooked || !g_pPatchedVTable) return;

    UnpatchDeviceVTableInner();

    g_deviceHooked = false;
    g_pDevice = nullptr;
    g_pPatchedVTable = nullptr;
}

static void InvalidateAllCaches() {
    memset(g_rsValid, 0, sizeof(g_rsValid));
    // The shadow copies follow the real caches, so the measurement describes what
    // a dedup under these same invalidation rules would have achieved rather than
    // an idealised one that never forgets.
    memset(g_shadowTexValid, 0, sizeof(g_shadowTexValid));
    memset(g_shadowRsValid, 0, sizeof(g_shadowRsValid));
    memset(g_tssValid, 0, sizeof(g_tssValid));
    memset(g_ssValid, 0, sizeof(g_ssValid));
    memset(g_texValid, 0, sizeof(g_texValid));
    memset(g_xformValid, 0, sizeof(g_xformValid));
    g_materialValid = false;
    g_viewportValid = false;
    g_scissorValid = false;
    memset(g_streamValid, 0, sizeof(g_streamValid));
    g_indexValid = false;
    g_vertDeclValid = false;
    g_fvfValid = false;
    g_vsValid = false;
    g_psValid = false;
}

// Which module an address belongs to, by file name, for the log.
static HMODULE ModuleOfAddress(uintptr_t addr, char* name, int cap) {
    HMODULE h = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)addr, &h) || !h) {
        lstrcpynA(name, "no module (allocated memory)", cap);
        return nullptr;
    }
    char path[MAX_PATH];
    if (!GetModuleFileNameA(h, path, MAX_PATH)) {
        lstrcpynA(name, "an unnamed module", cap);
        return h;
    }
    const char* leaf = path;
    for (const char* p = path; *p; ++p) {
        if (*p == '\\' || *p == '/') leaf = p + 1;
    }
    lstrcpynA(name, leaf, cap);
    return h;
}

// The two exports ReShade's own add-on header (include/reshade.hpp) uses to find
// the ReShade module among the loaded ones.
static bool IsReShadeModule(HMODULE h) {
    return h && GetProcAddress(h, "ReShadeRegisterAddon") &&
           GetProcAddress(h, "ReShadeUnregisterAddon");
}

// Whose device table this module is about to write into.
//
// A player with ReShade installed could not enter the world, could with ReShade
// removed, and No Client Patches did not help - which it cannot, because the
// device table lives in whatever module implements the device, not in wow.exe.
// The log said "vtable: 6A88B604" and nothing about whose that is. The client's
// device pointer is whatever the renderer stack handed it: DXVK's device, or a
// wrapper around it that another program put in between. Named here, before
// anything is patched, so the slots still hold the originals.
static void LogDeviceOwnership(uintptr_t* vtable) {
    char vtName[MAX_PATH], presentName[MAX_PATH], rsName[MAX_PATH];
    const HMODULE vtMod = ModuleOfAddress((uintptr_t)vtable, vtName, MAX_PATH);
    const HMODULE prMod = ModuleOfAddress(vtable[17], presentName, MAX_PATH);
    const HMODULE rsMod = ModuleOfAddress(vtable[57], rsName, MAX_PATH);
    Log("[D3D9State] the device function table at %p is in %s; Present comes from "
        "%s and SetRenderState from %s.", vtable, vtName, presentName, rsName);

    const HMODULE reshade = IsReShadeModule(vtMod) ? vtMod
                          : IsReShadeModule(prMod) ? prMod
                          : IsReShadeModule(rsMod) ? rsMod : nullptr;
    if (reshade) {
        char rsFile[MAX_PATH];
        ModuleOfAddress((uintptr_t)reshade, rsFile, MAX_PATH);
        Log("[D3D9State] %s is ReShade (it exports ReShadeRegisterAddon), so every "
            "hook below sits on ReShade's own layer over the device. If the game "
            "misbehaves with ReShade installed and not without it, turn off D3D9 "
            "Render State Dedup: that removes all of them.", rsFile);
    }
}

static bool TryFindAndPatchDevice() {
    // Always patch, even under DXVK: this is what installs the Reset hook that
    // FontGlyphCache/TextureUnloadDelay/D3D9StateCache rely on for invalidation
    // (see CheckDeviceChange). DXVKBridge::IsActive() used to bypass this
    // entirely, leaving no way to detect device resets under DXVK at all.
    if (g_deviceHooked) return true;

    uintptr_t addr = ADDR_CGXDEVICED3D_PTR;
    if (addr == 0 || !IsReadable(addr)) return false;
    uintptr_t pGxDevice = *(uintptr_t*)addr;
    if (!pGxDevice || !IsReadable(pGxDevice)) return false;

    uintptr_t devicePtrAddr = pGxDevice + 0x397C;
    if (!IsReadable(devicePtrAddr)) return false;
    void* pDevice = *(void**)devicePtrAddr;
    if (!pDevice || !IsReadable((uintptr_t)pDevice)) return false;

    uintptr_t* vtable = *(uintptr_t**)pDevice;
    if (!vtable || !IsReadable((uintptr_t)vtable)) return false;

    LogDeviceOwnership(vtable);
    return PatchDeviceVTable(pDevice);
}

// Public API
bool IsD3D9DeviceHooked(void) { return g_deviceHooked; }
void* D3D9StateManager_GetDevice(void) {
    return (g_pDevice && IsReadable((uintptr_t)g_pDevice) && *(const uintptr_t*)g_pDevice) ? g_pDevice : nullptr;
}

bool InstallD3D9StateManager(void) {
    memset(g_isCriticalRs, 0, sizeof(g_isCriticalRs));
    g_isCriticalRs[D3DRS_ALPHABLENDENABLE] = 1;
    g_isCriticalRs[D3DRS_SRCBLEND]         = 1;
    g_isCriticalRs[D3DRS_DESTBLEND]        = 1;
    g_isCriticalRs[D3DRS_ALPHATESTENABLE]  = 1;
    g_isCriticalRs[D3DRS_ALPHAREF]         = 1;
    g_isCriticalRs[D3DRS_ALPHAFUNC]        = 1;
    g_isCriticalRs[D3DRS_ZWRITEENABLE]     = 1;
    g_isCriticalRs[D3DRS_ZENABLE]          = 1;
    memset(g_rsCache, 0, sizeof(g_rsCache));
    memset(g_rsValid, 0, sizeof(g_rsValid));
    memset(g_tssCache, 0, sizeof(g_tssCache));
    memset(g_tssValid, 0, sizeof(g_tssValid));
    memset(g_ssCache, 0, sizeof(g_ssCache));
    memset(g_ssValid, 0, sizeof(g_ssValid));
    memset(g_texCache, 0, sizeof(g_texCache));
    memset(g_texValid, 0, sizeof(g_texValid));
    memset(g_xformHash, 0, sizeof(g_xformHash));
    memset(g_xformValid, 0, sizeof(g_xformValid));
    memset(g_streamBuf, 0, sizeof(g_streamBuf));
    memset(g_streamOffset, 0, sizeof(g_streamOffset));
    memset(g_streamStride, 0, sizeof(g_streamStride));
    memset(g_streamValid, 0, sizeof(g_streamValid));
    memset((void*)g_statCalls, 0, sizeof(g_statCalls));
    memset((void*)g_statSkipped, 0, sizeof(g_statSkipped));
    g_totalFrames = 0;

    bool ok = TryFindAndPatchDevice();
    if (ok) {
        Log("[D3D9State] [ OK ] Device vtable patched (%d hooks)", NUM_HOOKS);
    } else {
        Log("[D3D9State] Device not found at init — retrying each frame");
    }

    return true;
}

// Process-exit variant of the above.
//
// Sixteen of this module's function pointers live in the device vtable, which is
// inside d3d9.dll rather than inside us. Leaving them there while this module is
// unloaded means d3d9 releases the device through a vtable that calls into an
// address space we no longer occupy - after the player has already quit, with no
// log left running to say so.
//
// It cannot simply call ShutdownD3D9StateManager. By the time DLL_PROCESS_DETACH
// runs with lpReserved != NULL the OS has already terminated every other thread,
// possibly while one held g_vtableMutex, and an SRWLOCK has no abandonment
// recovery - blocking on it here would hang the exiting process, which is a worse
// outcome for the player than the dangling vtable this is meant to clear.
//
// So it tries the lock and gives up rather than waits. Giving up leaves things
// exactly as they were before this existed, so the failure mode is the old
// behaviour rather than a new one. No statistics are printed: the log thread is
// already gone at this point.
void ShutdownD3D9StateManagerAtProcessExit(void) {
    if (!g_vtableMutex.try_lock()) return;

    if (g_deviceHooked && g_pPatchedVTable) {
        UnpatchDeviceVTableInner();
        g_deviceHooked = false;
        g_pDevice = nullptr;
        g_pPatchedVTable = nullptr;
    }

    g_vtableMutex.unlock();
}

void ShutdownD3D9StateManager(void) {
    UnpatchDeviceVTable();

    D3D9StateManager_LogStats();
}

// These used to print only from ShutdownD3D9StateManager, which this process
// never reaches: it leaves through TerminateProcess and the exit path skips
// straight past it. So the call and skip counts of all sixteen device hooks
// have never appeared in a single log, and a report of a black cursor could not
// be checked against them - there was no way to ask whether this cache had
// suppressed anything at all. It is called from the periodic report now.
void D3D9StateManager_LogStats(void) {
    if (!g_deviceHooked && g_totalFrames == 0) {
        Log("[D3D9State] not hooked - nothing measured");
        return;
    }
    // g_totalFrames is not a frame count. It is bumped from
    // OnFrameD3D9StateManager, which runs out of hooked_Sleep at one tick every
    // SleepPrecisionValue ms, so it counts sleeps. In one tester session it read
    // 2,150 while Present had been called 56,321 times - a factor of twenty-six -
    // and the draw report below divided by it, which is how 1,323 draw calls a
    // frame got printed as 34,671.
    //
    // Present is the frame boundary, and it is counted by the same hook table as
    // everything else in this report, so it is the denominator. The sleep count
    // is still worth printing because it is what the state-cache invalidation
    // fallback actually runs at.
    const unsigned long frames = g_statCalls[15];   // Present
    Log("[D3D9State] %lu frames (Present), %lu maintenance ticks; per-hook calls "
        "and skips, all lower bounds:", frames, g_totalFrames);
    bool anySkip = false;
    for (int i = 0; i < NUM_HOOKS; i++) {
        if (g_statCalls[i] == 0) {
            // Not installed is not the same as installed and idle. Without this
            // the table simply loses a row and the reader is left to assume the
            // hook was there and the client never called it.
            if (!HookEarnsItsPlace(i) && g_hookFuncs[i]) {
                Log("[D3D9State]   %-22s: left out on purpose - it only counts, "
                    "and the count is already answered. Draw Call Census puts "
                    "it back.", g_statNames[i]);
            }
            continue;
        }
        // Indices 12 and 13 are SetVertexShader and SetPixelShader, which never
        // attempt a skip: caching a resource pointer is unsafe because the
        // address can be recycled, so those two detours only count. Reporting
        // them as "skipped=0 (0.0%)" beside hooks that genuinely tried and
        // failed invites the reader to think the dedup was tested here and lost.
        // It was never run.
        if (i == 16 || i == 17) {
            Log("[D3D9State]   %-22s: calls=%lu, counting only - this is the "
                "draw-call census, not a dedup",
                g_statNames[i], g_statCalls[i]);
            continue;
        }
        if (i == 12 || i == 13) {
            Log("[D3D9State]   %-22s: calls=%lu, no skip attempted - this detour "
                "only counts, because caching a shader pointer is unsafe when the "
                "address can be recycled",
                g_statNames[i], g_statCalls[i]);
            continue;
        }
        Log("[D3D9State]   %-22s: calls=%lu skipped=%lu (%.1f%%)",
            g_statNames[i], g_statCalls[i], g_statSkipped[i],
            (double)g_statSkipped[i] * 100.0 / (double)g_statCalls[i]);
        if (g_statSkipped[i]) anySkip = true;
    }
    if (!anySkip)
        Log("[D3D9State]   nothing was suppressed on any hook, so nothing this "
            "module did can have changed what the client drew");

    // What the two exclusions cost. Counted, never acted on.
    if (g_texCompared) {
        {
        const unsigned long ws = g_wouldSkip[0] + g_wouldSkip[1] + g_wouldSkip[2] +
                                 g_wouldSkip[5];
        if (ws == 0) {
            Log("[D3D9State]   SetRenderState, SetTextureStageState, "
                "SetSamplerState and SetMaterial no longer skip anything, they "
                "only count: a 2318 second session put 206 million calls through "
                "them and not one carried a value that was already set. A skip "
                "that cannot fire is a return that bypasses D3D9 for no gain, "
                "and this session agrees - zero would have been skipped.");
        } else {
            // Any nonzero count used to print the verdict that the dedup was worth
            // restoring. Sixty-three repeats in nine million calls is not that, and
            // the line sat beside the figures that said so. The verdict now needs a
            // share that could matter.
            const unsigned long total = g_statCalls[0] + g_statCalls[1] +
                                        g_statCalls[2] + g_statCalls[5];
            const double share = total ? 100.0 * (double)ws / (double)total : 0.0;
            if (share >= 1.0) {
                Log("[D3D9State]   %lu of %lu call(s) (%.1f%%) to SetRenderState, "
                    "SetTextureStageState, SetSamplerState or SetMaterial carried a "
                    "value that was already set. They only count now; whether skipping "
                    "them would pay is the timing line below, which is what the real "
                    "call costs when the value is already set.", ws, total, share);
                if (g_ssCycN[0] >= 100 && g_ssCycN[1] >= 100 && g_ssTsc0) {
                    LARGE_INTEGER q, f; QueryPerformanceCounter(&q); QueryPerformanceFrequency(&f);
                    const unsigned long long tsc1 = __rdtsc();
                    const double secs = (double)((unsigned long long)q.QuadPart - g_ssQpc0) / (double)f.QuadPart;
                    const double cycPerNs = secs > 1.0 ? (double)(tsc1 - g_ssTsc0) / (secs * 1e9) : 0.0;
                    if (cycPerNs > 0.0) {
                        const double nsSame = (double)g_ssCyc[1] / (double)g_ssCycN[1] / cycPerNs;
                        const double nsDiff = (double)g_ssCyc[0] / (double)g_ssCycN[0] / cycPerNs;
                        const double perFrame = frames ? (double)g_wouldSkip[2] / (double)frames : 0.0;
                        Log("[D3D9State]   SetSamplerState timing, one call in %lu timed with the time-stamp counter "
                            "(%.2f GHz): %.0f ns when the value was already set (%lu timed), %.0f ns when it changed "
                            "(%lu timed). Skipping the repeats would save about %.0f ns x %.0f repeats per frame = %.1f us "
                            "per frame, before the cost of the check itself.",
                            kSsTimeEvery, cycPerNs, nsSame, g_ssCycN[1], nsDiff, g_ssCycN[0], nsSame, perFrame,
                            nsSame * perFrame / 1000.0);
                    }
                } else {
                    Log("[D3D9State]   SetSamplerState timing: not measured, too few timed calls (%lu repeated, %lu changed).",
                        g_ssCycN[1], g_ssCycN[0]);
                }
            } else {
                Log("[D3D9State]   %lu of %lu call(s) (%.4f%%) to SetRenderState, "
                    "SetTextureStageState, SetSamplerState or SetMaterial carried a "
                    "value that was already set. Too few to be worth skipping; "
                    "they only count.", ws, total, share);
            }
            // The sum above cannot say which of the four carries it, and the
            // earlier zero and this figure disagree, so the split is printed.
            Log("[D3D9State]   of those, by call: SetRenderState %lu of %lu, "
                "SetTextureStageState %lu of %lu, SetSamplerState %lu of %lu, "
                "SetMaterial %lu of %lu. Each is compared against this module's "
                "cache, which is dropped every frame, so this is repetition inside "
                "one frame.",
                g_wouldSkip[0], g_statCalls[0], g_wouldSkip[1], g_statCalls[1],
                g_wouldSkip[2], g_statCalls[2], g_wouldSkip[5], g_statCalls[5]);
        }
    }
    Log("[D3D9State]   SetTexture is never deduped, on purpose - a texture "
            "freed and reallocated at the same address inside one frame would "
            "match a stale entry. Measured anyway: %lu of %lu calls set the stage "
            "to the pointer it already held (%.1f%%). Under DXVK each of those is "
            "recording work on this thread.",
            g_texWouldSkip, g_texCompared,
            100.0 * (double)g_texWouldSkip / (double)g_texCompared);
    } else {
        Log("[D3D9State]   SetTexture redundancy not measured - the hook saw no "
            "call with a stage under 8");
    }

    if (g_rsCritCompared) {
        Log("[D3D9State]   the eight blend and depth render states are excluded "
            "from the dedup by name. Measured: %lu of %lu calls to them set the "
            "value already there (%.1f%%). A high share means the exclusion is "
            "where the saving went; a low one means those states really do change "
            "every time and the exclusion costs nothing.",
            g_rsCritWouldSkip, g_rsCritCompared,
            100.0 * (double)g_rsCritWouldSkip / (double)g_rsCritCompared);
    } else {
        Log("[D3D9State]   no call reached one of the eight excluded render "
            "states, so their redundancy is not measured rather than zero");
    }

    unsigned long draws = g_statCalls[16] + g_statCalls[17];
    if (draws && !frames) {
        Log("[D3D9State] draw calls: %lu counted, but Present was never seen, so "
            "there is no frame count to divide by and no per-frame figure here.",
            draws);
    }
    if (draws && frames) {
        // A number no client produces. This printed 34,671 draw calls a frame for
        // a whole release because the denominator counted sleeps rather than
        // frames, and nothing said the figure was impossible.
        double perFrame = (double)draws / (double)frames;
        if (perFrame > 20000.0) {
            Verdict::Add(Verdict::Warn,
                         "the draw census reports %.0f draw calls per frame, which "
                         "no client produces - suspect the frame count",
                         perFrame);
        }
        const double prims = (double)g_drawPrimWraps * 4294967296.0 +
                             (double)g_drawPrims;
        Log("[D3D9State] draw calls: %lu over %lu frames = %.0f per frame, "
            "carrying %.0f primitives = %.0f per frame and %.1f per call.",
            draws, frames, (double)draws / (double)frames,
            prims, prims / (double)frames, prims / (double)draws);
        // A triangle list draw carries at least one primitive and this client
        // issues nothing else through here, so anything under one means the
        // count is wrong rather than interesting.
        if (prims / (double)draws < 1.0) {
            Log("[D3D9State]   THAT IS IMPOSSIBLE: fewer than one primitive per "
                "draw call. The primitive total is wrong; do not use it.");
            Verdict::Add(Verdict::Warn,
                         "the draw census reports fewer than one primitive per "
                         "draw call, which cannot happen - its primitive total "
                         "is broken");
        }
        Log("[D3D9State]   %lu render target or depth surface change(s) dropped "
            "the cached viewport and scissor. D3D9 resets the viewport inside "
            "the driver when the render target changes, so a SetViewport that "
            "matched the cache used to be skipped against a device that was no "
            "longer where the cache said - which is a pass rendering into the "
            "wrong rectangle, and a shadow atlas is where that shows first.",
            g_rtInvalidations);
        Log("[D3D9State]   primitives per draw - the number that decides whether "
            "batching is worth anything, because an average hides it:");
        for (int b = 0; b < 6; b++) {
            if (!g_drawBucket[b]) continue;
            Log("[D3D9State]     %-8s %8lu draws (%4.1f%%)",
                g_bucketName[b], g_drawBucket[b],
                100.0 * (double)g_drawBucket[b] / (double)draws);
        }
        Log("[D3D9State]   %lu of them (%.1f%%) carried eight primitives or "
            "fewer. Under DXVK the per-call cost is recording on this thread, so "
            "that share is what a batching pass could remove; a small share means "
            "the draws are already as large as they get.",
            g_drawTiny, 100.0 * (double)g_drawTiny / (double)draws);
    }

    // Outside the "did this file count any draws" guard on purpose. Both of
    // these say which of the three states they are in, and a session where the
    // state manager counted nothing is exactly when that answer is wanted.
    D3D9StateCache::LogMergeCensus();
    D3D9StateCache::DrawMerge_LogStats();
}

// DXVK (and some other D3D9-on-Vulkan translation layers) can resize its
// Vulkan swapchain implicitly inside Present() when it notices the window's
// client area changed size -- it does NOT require WoW to call
// IDirect3DDevice9::Reset() first, unlike real D3D9. Maximizing/restoring the
// window is exactly this case: no Reset() is ever seen, so CheckDeviceChange
// and Hooked_Reset both stay silent and FontGlyphCache/TextureUnloadDelay/etc.
// never get invalidated, leaving glyphs pointing at a back buffer that no
// longer matches the new swapchain (renders as blank text under Vulkan's
// robustness clamping instead of the garbage a real driver would show).
// Poll the window's client rect every frame and treat a change the same as
// a Reset.
//
// g_pDevice is the last device a hooked call was seen on, and a device restart
// destroys it before the new one has made a call. Native Direct3D 9 zeroes the
// object when it is destroyed, so the page is still readable and the first
// dword, the vtable pointer, is null: the 3.20.0 test build died here, reading
// address 0x24, two milliseconds after the render thread's restart on a
// GeForce with the native runtime. DXVK leaves the old object intact, which is
// why no earlier log showed it. The pointer is therefore not trusted until its
// vtable is, and the one call made through it is guarded.
static bool DeviceHasVtable(void* dev) {
    if (!dev || !IsReadable((uintptr_t)dev)) return false;
    const uintptr_t vt = *(const uintptr_t*)dev;
    return vt && IsReadable(vt);
}

static bool QueryFocusWindow(void* dev, HWND* out) {
    __try {
        D3DDEVICE_CREATION_PARAMETERS params;
        if (FAILED(((IDirect3DDevice9*)dev)->GetCreationParameters(&params)) ||
            !params.hFocusWindow) return false;
        *out = params.hFocusWindow;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static void CheckWindowSizeChange() {
    if (!DeviceHasVtable(g_pDevice)) return;

    static HWND s_hwnd = nullptr;
    static int  s_lastWidth = -1;
    static int  s_lastHeight = -1;

    if (!s_hwnd && !QueryFocusWindow(g_pDevice, &s_hwnd)) return;

    RECT rect;
    if (!GetClientRect(s_hwnd, &rect)) return;
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;
    if (width <= 0 || height <= 0) return; // minimized

    if (s_lastWidth < 0) {
        s_lastWidth = width;
        s_lastHeight = height;
        return;
    }

    if (width != s_lastWidth || height != s_lastHeight) {
        Log("[D3D9State] Window client size changed (%dx%d -> %dx%d) with no Reset call observed "
            "-- likely an implicit DXVK swapchain resize. Invalidating caches.",
            s_lastWidth, s_lastHeight, width, height);
        s_lastWidth = width;
        s_lastHeight = height;

        InterlockedIncrement(&g_deviceResetCounter);
        InvalidateAllCaches();
        RenderStateDedup_ClearCache();
        #ifndef TEST_DISABLE_FONT_METRICS_FAST
        FontGlyphCache::ClearCache();
        #endif
        TextureUnloadDelay::Discard();
        // safeToRelease=false: this runs from the frame loop with no render-thread
        // PipelineFlush (unlike Hooked_Reset), so we must NOT Release() the D3D9
        // latency-query COM objects here — the render thread may be mid-GetData()/
        // Issue() on them when D3d9RenderThread is active. Just drop the pointers
        // and let them be recreated, matching CheckDeviceChange's async path.
        D3D9StateCache::InvalidateAllCaches(false);
    }
}

void OnFrameD3D9StateManager(DWORD mainThreadId) {
    if (GetCurrentThreadId() != mainThreadId) return;

    g_totalFrames++;

    // Invalidate state cache every frame to ensure synchronization with device resets,
    // window resizing, resolution changes, and DXVK state updates!
    //
    // This is the fallback path. It runs from hooked_Sleep, which is gated to one
    // tick every SleepPrecisionValue ms, so it stops keeping up with frames above
    // roughly 125 fps. Hooked_Present carries the same invalidation and is a true
    // frame boundary at any frame rate; this call still matters for the OpenGL
    // swap path, where Present is never reached.
    //
    // Not while the render thread is active: the hooks that fill these caches then
    // run on that thread, so clearing them from this one races their readers. The
    // Present hook clears them there, once a frame.
    if (!GxRT::IsActive()) InvalidateAllCaches();

    CheckWindowSizeChange();

    if (!g_deviceHooked) {
        TryFindAndPatchDevice();
    }
}
