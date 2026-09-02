// ============================================================================
// Module: d3d9_state_manager.cpp
// Description: Deduplicates D3D9 device state changes and caches rendering states
//              to maximize CPU throughput and minimize driver overhead.
// Safety & Threading: Main render thread only. Crash-guarded against NULL pointers.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <d3d9.h>
#include "d3d9_state_manager.h"
#include "session_verdict.h"
#include "sampling_profiler.h"
#include "font_glyph_cache.h"
#include "texture_unload_delay.h"
#include "d3d9_state_cache.h"
#include "render_state_dedup.h"
#include "win_mutex.h"
#include "diagnostics/crash_dumper.h"
#include "diagnostics/frame_bench.h"

extern "C" void Log(const char* fmt, ...);

// Per-frame work that must run on a true frame boundary (see dllmain).
extern "C" void WowOpt_OnFrameBoundary();

// ================================================================
// Memory validation
// ================================================================
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

static constexpr int NUM_HOOKS = 18;
static int g_vtableIndices[NUM_HOOKS] = {
    V_SETRENDERSTATE, V_SETTEXTURESTAGESTATE, V_SETSAMPLERSTATE,
    V_SETTEXTURE, V_SETTRANSFORM, V_SETMATERIAL,
    V_SETVIEWPORT, V_SETSCISSORRECT, V_SETSTREAMSOURCE,
    V_SETINDICES, V_SETVERTEXDECLARATION, V_SETFVF,
    V_SETVERTEXSHADER, V_SETPIXELSHADER, V_RESET,
    V_PRESENT, V_DRAWPRIMITIVE, V_DRAWINDEXEDPRIMITIVE
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

// ================================================================
// Per-frame statistics
// ================================================================
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
    "Present", "DrawPrimitive", "DrawIndexedPrimitive"
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
static unsigned long g_texWouldSkip   = 0;
static unsigned long g_texCompared    = 0;
static DWORD         g_shadowRs[256]  = {};
static bool          g_shadowRsValid[256] = {};
static unsigned long g_rsCritWouldSkip = 0;
static unsigned long g_rsCritCompared  = 0;

// ================================================================
// State caches
// ================================================================
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
        #ifndef TEST_DISABLE_FONT_METRICS_FAST
        FontGlyphCache::ClearCache();
        #endif
        TextureUnloadDelay::Discard();
        D3D9StateCache::InvalidateAllCaches(false);

        g_pDevice = dev;

        g_deviceHooked = false; // Force PatchDeviceVTable to run and verify/re-hook the new device vtable
        PatchDeviceVTable(dev);
    }
}

// ================================================================
// Fast matrix/material hash functions
// ================================================================
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

// ================================================================
// original function pointers for calling back to driver
// ================================================================
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

// ================================================================
// Hooked functions
// ================================================================

static HRESULT __stdcall Hooked_SetRenderState(void* dev, DWORD state, DWORD value) {
    CheckDeviceChange(dev);
    ++g_statCalls[0];
    
    bool isCriticalState = (state == D3DRS_ALPHABLENDENABLE || state == D3DRS_SRCBLEND || 
                           state == D3DRS_DESTBLEND || state == D3DRS_ALPHATESTENABLE || 
                           state == D3DRS_ALPHAREF || state == D3DRS_ALPHAFUNC ||
                           state == D3DRS_ZWRITEENABLE || state == D3DRS_ZENABLE);

    // Measurement only, on the states the dedup is not allowed to touch.
    if (state < 256 && isCriticalState) {
        ++g_rsCritCompared;
        if (g_shadowRsValid[state] && g_shadowRs[state] == value) ++g_rsCritWouldSkip;
        g_shadowRs[state] = value;
        g_shadowRsValid[state] = true;
    }

    if (state < 256 && !isCriticalState && g_rsValid[state] && g_rsCache[state] == value) {
        ++g_statSkipped[0];
        return 0;
    }
    HRESULT hr = g_orig_SetRenderState(dev, state, value);
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
    if (idx < 256 && g_tssValid[idx] && g_tssCache[idx] == value) {
        ++g_statSkipped[1];
        return 0;
    }
    HRESULT hr = g_orig_SetTextureStageState(dev, stage, type, value);
    if (SUCCEEDED(hr) && idx < 256) {
        g_tssCache[idx] = value;
        g_tssValid[idx] = true;
    }
    return hr;
}

static HRESULT __stdcall Hooked_SetSamplerState(void* dev, DWORD sampler, DWORD type, DWORD value) {
    CheckDeviceChange(dev);
    ++g_statCalls[2];

    DWORD idx = (sampler & 15) * 16 + (type & 15);
    if (idx < 256 && g_ssValid[idx] && g_ssCache[idx] == value) {
        ++g_statSkipped[2];
        return 0;
    }
    HRESULT hr = g_orig_SetSamplerState(dev, sampler, type, value);
    if (SUCCEEDED(hr) && idx < 256) {
        g_ssCache[idx] = value;
        g_ssValid[idx] = true;
    }
    return hr;
}

static HRESULT __stdcall Hooked_SetTexture(void* dev, DWORD stage, void* tex) {
    CheckDeviceChange(dev);
    ++g_statCalls[3];

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
    // Two things that are NOT settled and would have to be before acting:
    // whether calls arrive from more than one thread when D3d9RenderThread is on,
    // because none of these caches take a lock; and whether DXVK's own SetTexture
    // does bookkeeping beyond the D3D9 contract. Until the share below says the
    // saving is worth asking those questions, they stay unasked.
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
    return g_orig_SetTexture(dev, stage, tex);
}

static HRESULT __stdcall Hooked_SetTransform(void* dev, DWORD state, const void* matrix) {
    CheckDeviceChange(dev);
    ++g_statCalls[4];
    // Always call original transform setter to guarantee 100% world matrix accuracy on weapon sub-meshes
    return g_orig_SetTransform(dev, state, matrix);
}

static HRESULT __stdcall Hooked_SetMaterial(void* dev, const void* material) {
    CheckDeviceChange(dev);
    ++g_statCalls[5];

    if (!material) {
        g_materialValid = false;
        return g_orig_SetMaterial(dev, material);
    }

    uint32_t hash = HashMaterial((const DWORD*)material);
    if (g_materialValid && g_materialHash == hash) {
        ++g_statSkipped[5];
        return 0;
    }
    HRESULT hr = g_orig_SetMaterial(dev, material);
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
        return g_orig_SetViewport(dev, vp);
    }

    if (g_viewportValid && memcmp(g_viewportData, vp, sizeof(g_viewportData)) == 0) {
        ++g_statSkipped[6];
        return 0;
    }
    HRESULT hr = g_orig_SetViewport(dev, vp);
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
        return g_orig_SetScissorRect(dev, rect);
    }

    if (g_scissorValid
        && g_scissorData[0] == rect->left
        && g_scissorData[1] == rect->top
        && g_scissorData[2] == rect->right
        && g_scissorData[3] == rect->bottom) {
        ++g_statSkipped[7];
        return 0;
    }
    HRESULT hr = g_orig_SetScissorRect(dev, rect);
    if (SUCCEEDED(hr)) {
        g_scissorData[0] = rect->left;
        g_scissorData[1] = rect->top;
        g_scissorData[2] = rect->right;
        g_scissorData[3] = rect->bottom;
        g_scissorValid = true;
    }
    return hr;
}

static HRESULT __stdcall Hooked_SetStreamSource(void* dev, UINT stream, void* vb, UINT offset, UINT stride) {
    CheckDeviceChange(dev);
    ++g_statCalls[8];
    // Caching resource pointers is unsafe due to address recycling. Always call original.
    return g_orig_SetStreamSource(dev, stream, vb, offset, stride);
}

static HRESULT __stdcall Hooked_SetIndices(void* dev, void* ib) {
    CheckDeviceChange(dev);
    ++g_statCalls[9];
    // Caching resource pointers is unsafe due to address recycling. Always call original.
    return g_orig_SetIndices(dev, ib);
}

static HRESULT __stdcall Hooked_SetVertexDeclaration(void* dev, void* decl) {
    CheckDeviceChange(dev);
    ++g_statCalls[10];
    // Caching resource pointers is unsafe due to address recycling. Always call original.
    return g_orig_SetVertexDeclaration(dev, decl);
}

static HRESULT __stdcall Hooked_SetFVF(void* dev, DWORD fvf) {
    CheckDeviceChange(dev);
    ++g_statCalls[11];

    if (g_fvfValid && g_fvf == fvf) {
        ++g_statSkipped[11];
        return 0;
    }
    HRESULT hr = g_orig_SetFVF(dev, fvf);
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
    return g_orig_SetVertexShader(dev, vs);
}

static HRESULT __stdcall Hooked_SetPixelShader(void* dev, void* ps) {
    CheckDeviceChange(dev);
    ++g_statCalls[13];
    // Caching resource pointers is unsafe due to address recycling. Always call original.
    return g_orig_SetPixelShader(dev, ps);
}

static HRESULT __stdcall Hooked_Reset(void* dev, D3DPRESENT_PARAMETERS* params) {
    CheckDeviceChange(dev);
    ++g_statCalls[14];
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
    FrameBench::OnPresent(FrameBench::Source::D3D9Present);
    WowOpt_OnFrameBoundary();

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

// ================================================================
// VTable patching
// ================================================================
// ================================================================
// Draw-call census
// ================================================================
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
static unsigned long g_drawPrims  = 0;    // primitives summed over all draws
static unsigned long g_drawTiny   = 0;    // draws of eight primitives or fewer
static unsigned long g_drawBucket[6] = {};  // 1-2, 3-8, 9-32, 33-128, 129-512, 513+
static const char*   g_bucketName[6] = { "1-2", "3-8", "9-32", "33-128", "129-512", "513+" };

static inline void NoteDraw(UINT prims) {
    g_drawPrims += prims;
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
    (void*)Hooked_DrawIndexedPrimitive
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
        default: break;
    }
}

#ifndef ADDR_CGXDEVICED3D_PTR
#define ADDR_CGXDEVICED3D_PTR  0x00C5DF88  // global CGxDeviceD3d*
#endif

static bool PatchDeviceVTable(void* pDevice) {
    WinLockGuard lock(g_vtableMutex);
    if (!pDevice || g_deviceHooked) return false;

    uintptr_t* vtable = *(uintptr_t**)pDevice;
    if (!vtable || !IsReadable((uintptr_t)vtable)) return false;

    int patched = 0;
    for (int i = 0; i < NUM_HOOKS; i++) {
        int vtIndex = g_vtableIndices[i];
        if (!g_hookFuncs[i]) continue;

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
        g_vtablePatched[i] = true;
        patched++;
    }

    g_pDevice = pDevice;
    g_pPatchedVTable = vtable;
    g_deviceHooked = true;
    InterlockedIncrement(&g_deviceResetCounter);
    Log("[D3D9State] Device vtable patched: %d/%d state hooks installed (vtable: %p, resetCounter: %ld)", patched, NUM_HOOKS, vtable, g_deviceResetCounter);

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

    return PatchDeviceVTable(pDevice);
}

// ================================================================
// Public API
// ================================================================
bool IsD3D9DeviceHooked(void) { return g_deviceHooked; }

bool InstallD3D9StateManager(void) {
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
        if (g_statCalls[i] == 0) continue;
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
        Log("[D3D9State] draw calls: %lu over %lu frames = %.0f per frame, "
            "carrying %lu primitives = %.0f per frame and %.1f per call.",
            draws, frames, (double)draws / (double)frames,
            g_drawPrims, (double)g_drawPrims / (double)frames,
            (double)g_drawPrims / (double)draws);
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
static void CheckWindowSizeChange() {
    if (!g_pDevice || !IsReadable((uintptr_t)g_pDevice)) return;

    static HWND s_hwnd = nullptr;
    static int  s_lastWidth = -1;
    static int  s_lastHeight = -1;

    if (!s_hwnd) {
        D3DDEVICE_CREATION_PARAMETERS params;
        IDirect3DDevice9* dev = (IDirect3DDevice9*)g_pDevice;
        if (FAILED(dev->GetCreationParameters(&params)) || !params.hFocusWindow) return;
        s_hwnd = params.hFocusWindow;
    }

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
    InvalidateAllCaches();

    CheckWindowSizeChange();

    if (!g_deviceHooked) {
        TryFindAndPatchDevice();
    }
}
