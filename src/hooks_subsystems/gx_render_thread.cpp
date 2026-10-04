// ============================================================================
// Module: gx_render_thread.cpp
//
// The device layer of the D3D9 render thread.
//
// How it is wired. The client loads d3d9.dll and asks it for an IDirect3D9 in
// sub_6A0AA0; we detour that, and on the first object it returns we detour
// CreateDevice with D3DCREATE_MULTITHREADED added, which is the flag the earlier
// render thread never set. When the device comes back its vtable is rewritten:
//
//   * State setters, draws, scene calls and Present are replaced with thunks that
//     write a command into the ring and return. They never look at the device.
//   * Methods that create resources or only ask about the device (caps, display
//     mode, cooperative level, cursor) are left alone. They are legal from the
//     main thread on a MULTITHREADED device and do not depend on queued work.
//   * Everything else gets a stub that drains the ring first and then jumps to
//     the real method. That is the safe default: a call this file has no opinion
//     about waits for the render thread to catch up, then runs on the main thread
//     exactly as it did before. The per-slot counters in the report say which
//     of them are called, so the ones that matter can be promoted.
//
// Results. A queued call returns D3D_OK at once. Present returns the previous
// frame's result, so a lost device is noticed a frame late.
//
// Lifetimes. A queued call that carries an interface pointer takes a reference
// before it returns and the render thread drops it after the device has taken its
// own, so the client releasing the object in between cannot free it under a
// queued command.
//
// Pipelining. The main thread may be one Present ahead of the render thread and
// no more (kMaxFramesInFlight), which bounds the latency it adds.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <d3d9.h>
#include <stdint.h>
#include <string.h>
#include <intrin.h>

#include "gx_render_thread.h"
#include "gx_internal.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "high_tables.h"
#include "sampling_profiler.h"
#include "d3d9_state_manager.h"
#include "m2_anim_stride.h"
#include "diagnostics/frame_bench.h"
#include "loading_state.h"
#include "lua_optimize.h"

extern "C" void Log(const char* fmt, ...);
extern "C" void WowOpt_OnFrameBoundary();

namespace GxRT {

// ---- shared state -----------------------------------------------------------
Ring        g_ring;
FrameArena  g_arena;
volatile LONG g_dead = 0;
volatile LONG g_active = 0;
DWORD       g_mainTid = 0;
void*       g_orig[kSlots] = {};
IDirect3DDevice9* g_dev = nullptr;
unsigned long g_syncCalls[kSlots] = {};
uint64_t    g_ticksDrain = 0;
unsigned long g_drains = 0;
unsigned long g_drainGaveUp = 0;       // drains abandoned after kDrainGiveUpMs
unsigned long g_syncFromRuntime = 0;   // sync calls made by d3d9.dll itself, not drained
constexpr DWORD kDrainGiveUpMs = 3000;
uint64_t    g_ticksRingFull = 0;
unsigned long g_waitsRingFull = 0;

namespace {

// ---- slots ------------------------------------------------------------------
enum Slot {
    S_Release = 2, S_Reset = 16, S_Present = 17, S_CreateTexture = 23, S_CreateVB = 26, S_CreateIB = 27, S_CreateQuery = 118,
    S_SetRT = 37, S_SetDS = 39, S_BeginScene = 41, S_EndScene = 42, S_Clear = 43,
    S_SetTransform = 44, S_SetViewport = 47, S_SetMaterial = 49, S_SetLight = 51,
    S_LightEnable = 53, S_SetClipPlane = 55, S_SetRS = 57, S_SetTexture = 65,
    S_SetTSS = 67, S_SetSampler = 69, S_SetScissor = 75, S_Draw = 81, S_DrawIdx = 82,
    S_SetVDecl = 87, S_SetFVF = 89, S_SetVS = 92, S_SetVSConstF = 94,
    S_SetStream = 100, S_SetStreamFreq = 102, S_SetIndices = 104, S_SetPS = 107,
    S_SetPSConstF = 109
};

const char* const kSlotName[kSlots] = {
    "QueryInterface","AddRef","Release","TestCooperativeLevel","GetAvailableTextureMem",
    "EvictManagedResources","GetDirect3D","GetDeviceCaps","GetDisplayMode",
    "GetCreationParameters","SetCursorProperties","SetCursorPosition","ShowCursor",
    "CreateAdditionalSwapChain","GetSwapChain","GetNumberOfSwapChains","Reset","Present",
    "GetBackBuffer","GetRasterStatus","SetDialogBoxMode","SetGammaRamp","GetGammaRamp",
    "CreateTexture","CreateVolumeTexture","CreateCubeTexture","CreateVertexBuffer",
    "CreateIndexBuffer","CreateRenderTarget","CreateDepthStencilSurface","UpdateSurface",
    "UpdateTexture","GetRenderTargetData","GetFrontBufferData","StretchRect","ColorFill",
    "CreateOffscreenPlainSurface","SetRenderTarget","GetRenderTarget","SetDepthStencilSurface",
    "GetDepthStencilSurface","BeginScene","EndScene","Clear","SetTransform","GetTransform",
    "MultiplyTransform","SetViewport","GetViewport","SetMaterial","GetMaterial","SetLight",
    "GetLight","LightEnable","GetLightEnable","SetClipPlane","GetClipPlane","SetRenderState",
    "GetRenderState","CreateStateBlock","BeginStateBlock","EndStateBlock","SetClipStatus",
    "GetClipStatus","GetTexture","SetTexture","GetTextureStageState","SetTextureStageState",
    "GetSamplerState","SetSamplerState","ValidateDevice","SetPaletteEntries","GetPaletteEntries",
    "SetCurrentTexturePalette","GetCurrentTexturePalette","SetScissorRect","GetScissorRect",
    "SetSoftwareVertexProcessing","GetSoftwareVertexProcessing","SetNPatchMode","GetNPatchMode",
    "DrawPrimitive","DrawIndexedPrimitive","DrawPrimitiveUP","DrawIndexedPrimitiveUP",
    "ProcessVertices","CreateVertexDeclaration","SetVertexDeclaration","GetVertexDeclaration",
    "SetFVF","GetFVF","CreateVertexShader","SetVertexShader","GetVertexShader",
    "SetVertexShaderConstantF","GetVertexShaderConstantF","SetVertexShaderConstantI",
    "GetVertexShaderConstantI","SetVertexShaderConstantB","GetVertexShaderConstantB",
    "SetStreamSource","GetStreamSource","SetStreamSourceFreq","GetStreamSourceFreq",
    "SetIndices","GetIndices","CreatePixelShader","SetPixelShader","GetPixelShader",
    "SetPixelShaderConstantF","GetPixelShaderConstantF","SetPixelShaderConstantI",
    "GetPixelShaderConstantI","SetPixelShaderConstantB","GetPixelShaderConstantB",
    "DrawRectPatch","DrawTriPatch","DeletePatch","CreateQuery"
};

// Left exactly as the device made them. None of these depends on what is still in
// the ring, and each is legal from the main thread on a MULTITHREADED device.
//
// GetBackBuffer (18) is not on this list. The client's pixel readback
// (sub_6A16D0) is GetBackBuffer followed at once by LockRect on that surface, and a
// surface method is not something this module can fence. The readback is how the
// portrait probe (sub_616DC0) decides whether the unit portraits are drawn into a
// texture: it clears the target, reads 64x64 back and looks at the alpha bytes.
// With the Clear still in the ring the probe read the previous frame, answered
// no, and the player and target portraits stayed black for the session. Draining
// here makes the surface complete before it is handed out.
bool IsDirectSlot(int s) {
    switch (s) {
    case 0: case 1: case 3: case 4: case 6: case 7: case 8: case 9:
    case 10: case 11: case 12: case 13: case 14: case 15: case 19:
    case 21: case 22: case 24: case 25: case 28: case 29: case 36:
    case 86: case 91: case 106:
        return true;
    default:
        return false;
    }
}

// ---- original signatures ------------------------------------------------------
typedef HRESULT (__stdcall *F_RS)(IDirect3DDevice9*, D3DRENDERSTATETYPE, DWORD);
typedef HRESULT (__stdcall *F_TSS)(IDirect3DDevice9*, DWORD, D3DTEXTURESTAGESTATETYPE, DWORD);
typedef HRESULT (__stdcall *F_Sampler)(IDirect3DDevice9*, DWORD, D3DSAMPLERSTATETYPE, DWORD);
typedef HRESULT (__stdcall *F_Tex)(IDirect3DDevice9*, DWORD, IDirect3DBaseTexture9*);
typedef HRESULT (__stdcall *F_Xform)(IDirect3DDevice9*, D3DTRANSFORMSTATETYPE, const D3DMATRIX*);
typedef HRESULT (__stdcall *F_VP)(IDirect3DDevice9*, const D3DVIEWPORT9*);
typedef HRESULT (__stdcall *F_Mtl)(IDirect3DDevice9*, const D3DMATERIAL9*);
typedef HRESULT (__stdcall *F_Light)(IDirect3DDevice9*, DWORD, const D3DLIGHT9*);
typedef HRESULT (__stdcall *F_LightEn)(IDirect3DDevice9*, DWORD, BOOL);
typedef HRESULT (__stdcall *F_Clip)(IDirect3DDevice9*, DWORD, const float*);
typedef HRESULT (__stdcall *F_Scissor)(IDirect3DDevice9*, const RECT*);
typedef HRESULT (__stdcall *F_Stream)(IDirect3DDevice9*, UINT, IDirect3DVertexBuffer9*, UINT, UINT);
typedef HRESULT (__stdcall *F_StreamFreq)(IDirect3DDevice9*, UINT, UINT);
typedef HRESULT (__stdcall *F_Indices)(IDirect3DDevice9*, IDirect3DIndexBuffer9*);
typedef HRESULT (__stdcall *F_VDecl)(IDirect3DDevice9*, IDirect3DVertexDeclaration9*);
typedef HRESULT (__stdcall *F_FVF)(IDirect3DDevice9*, DWORD);
typedef HRESULT (__stdcall *F_VS)(IDirect3DDevice9*, IDirect3DVertexShader9*);
typedef HRESULT (__stdcall *F_PS)(IDirect3DDevice9*, IDirect3DPixelShader9*);
typedef HRESULT (__stdcall *F_ConstF)(IDirect3DDevice9*, UINT, const float*, UINT);
typedef HRESULT (__stdcall *F_RT)(IDirect3DDevice9*, DWORD, IDirect3DSurface9*);
typedef HRESULT (__stdcall *F_DS)(IDirect3DDevice9*, IDirect3DSurface9*);
typedef HRESULT (__stdcall *F_Scene)(IDirect3DDevice9*);
typedef HRESULT (__stdcall *F_Clear)(IDirect3DDevice9*, DWORD, const D3DRECT*, DWORD, D3DCOLOR, float, DWORD);
typedef HRESULT (__stdcall *F_Draw)(IDirect3DDevice9*, D3DPRIMITIVETYPE, UINT, UINT);
typedef HRESULT (__stdcall *F_DrawIdx)(IDirect3DDevice9*, D3DPRIMITIVETYPE, INT, UINT, UINT, UINT, UINT);
typedef HRESULT (__stdcall *F_Present)(IDirect3DDevice9*, const RECT*, const RECT*, HWND, const RGNDATA*);

// ---- counters (plain 32-bit on the hot paths; lower bounds) ------------------------
unsigned long g_cmds[OP__COUNT];
unsigned long g_presents = 0;
unsigned long g_throttleWaits = 0;
uint64_t      g_ticksThrottle = 0;
unsigned long g_clearFallbacks = 0;
unsigned long g_presentFallbacks = 0;
unsigned long g_consumerSleeps = 0;
// What the render thread spent running commands, in time stamp counter ticks,
// written by it alone and read by the report. A tick count is 64 bits and the
// report is on another thread, so it is added with an interlocked add once per
// batch and once per present, a few times a frame, not once per command.
volatile LONG64 g_ticksBusy = 0;       // all commands, Present included
volatile LONG64 g_ticksPresent = 0;    // Present alone: it waits for the display, which is not CPU work
volatile LONG64 g_batches = 0;
volatile HRESULT g_lastPresentHr = D3D_OK;
uint64_t      g_tsc0 = 0;
LARGE_INTEGER g_qpc0;

const char* g_why = "not started";
bool          g_configured = false;
bool          g_everActive = false;
volatile LONG g_stop = 0;
HANDLE        g_thread = nullptr;
DWORD         g_renderTid = 0;
uint8_t*      g_stubs = nullptr;
void*         g_thunk[kSlots] = {};      // what this file wrote into each slot
uintptr_t*    g_patchedVt = nullptr;     // the vtable those thunks were written into

// The device restart this module asks the client for, once, when the client made
// its first device before the loader hook could see it.
bool          g_armed = false;           // Init succeeded and no device has come through the hook yet
bool          g_restartAsked = false;
bool          g_restartReported = false;
bool          g_hookReported = false;
volatile bool g_deviceThroughHook = false;   // the client's device has been created by our hook at least once
LARGE_INTEGER g_restartQpc;

// ---- the render thread ----------------------------------------------------------
inline void RelObj(IUnknown* o) { if (o) o->Release(); }

// Runs one command against the real device. No exceptions escape: the caller wraps it.
void Execute(CmdHdr* h) {
    IDirect3DDevice9* d = g_dev;
    switch (h->op) {
    case OP_WRAP: break;
    case OP_SET_RS:      { CmdRS* c = (CmdRS*)h;  O<F_RS>(S_SetRS)(d, (D3DRENDERSTATETYPE)c->state, c->value); break; }
    case OP_SET_TSS:     { CmdTSS* c = (CmdTSS*)h; O<F_TSS>(S_SetTSS)(d, c->stage, (D3DTEXTURESTAGESTATETYPE)c->type, c->value); break; }
    case OP_SET_SAMPLER: { CmdSampler* c = (CmdSampler*)h; O<F_Sampler>(S_SetSampler)(d, c->sampler, (D3DSAMPLERSTATETYPE)c->type, c->value); break; }
    case OP_SET_TEXTURE: { CmdTexture* c = (CmdTexture*)h; O<F_Tex>(S_SetTexture)(d, c->stage, c->tex); RelObj(c->tex); break; }
    case OP_SET_TRANSFORM:{ CmdTransform* c = (CmdTransform*)h; O<F_Xform>(S_SetTransform)(d, (D3DTRANSFORMSTATETYPE)c->state, &c->m); break; }
    case OP_SET_VIEWPORT:{ CmdViewport* c = (CmdViewport*)h; O<F_VP>(S_SetViewport)(d, &c->vp); break; }
    case OP_SET_MATERIAL:{ CmdMaterial* c = (CmdMaterial*)h; O<F_Mtl>(S_SetMaterial)(d, &c->m); break; }
    case OP_SET_LIGHT:   { CmdLight* c = (CmdLight*)h; O<F_Light>(S_SetLight)(d, c->index, &c->l); break; }
    case OP_LIGHT_ENABLE:{ CmdLightEn* c = (CmdLightEn*)h; O<F_LightEn>(S_LightEnable)(d, c->index, c->enable); break; }
    case OP_SET_CLIP:    { CmdClip* c = (CmdClip*)h; O<F_Clip>(S_SetClipPlane)(d, c->index, c->plane); break; }
    case OP_SET_SCISSOR: { CmdScissor* c = (CmdScissor*)h; O<F_Scissor>(S_SetScissor)(d, &c->r); break; }
    case OP_SET_STREAM:  { CmdStream* c = (CmdStream*)h; O<F_Stream>(S_SetStream)(d, c->n, c->vb, c->offset, c->stride); RelObj(c->vb); break; }
    case OP_SET_STREAM_FREQ:{ CmdStreamFreq* c = (CmdStreamFreq*)h; O<F_StreamFreq>(S_SetStreamFreq)(d, c->n, c->divider); break; }
    case OP_SET_INDICES: { CmdIndices* c = (CmdIndices*)h; O<F_Indices>(S_SetIndices)(d, c->ib); RelObj(c->ib); break; }
    case OP_SET_VDECL:   { CmdObject* c = (CmdObject*)h; O<F_VDecl>(S_SetVDecl)(d, (IDirect3DVertexDeclaration9*)c->obj); RelObj(c->obj); break; }
    case OP_SET_FVF:     { CmdFVF* c = (CmdFVF*)h; O<F_FVF>(S_SetFVF)(d, c->fvf); break; }
    case OP_SET_VS:      { CmdObject* c = (CmdObject*)h; O<F_VS>(S_SetVS)(d, (IDirect3DVertexShader9*)c->obj); RelObj(c->obj); break; }
    case OP_SET_PS:      { CmdObject* c = (CmdObject*)h; O<F_PS>(S_SetPS)(d, (IDirect3DPixelShader9*)c->obj); RelObj(c->obj); break; }
    case OP_SET_VS_CONSTF:{ CmdConstF* c = (CmdConstF*)h; O<F_ConstF>(S_SetVSConstF)(d, c->start, (const float*)(c + 1), c->count); break; }
    case OP_SET_PS_CONSTF:{ CmdConstF* c = (CmdConstF*)h; O<F_ConstF>(S_SetPSConstF)(d, c->start, (const float*)(c + 1), c->count); break; }
    case OP_SET_RT:      { CmdRT* c = (CmdRT*)h; O<F_RT>(S_SetRT)(d, c->index, c->surf); RelObj(c->surf); break; }
    case OP_SET_DS:      { CmdObject* c = (CmdObject*)h; O<F_DS>(S_SetDS)(d, (IDirect3DSurface9*)c->obj); RelObj(c->obj); break; }
    case OP_BEGIN_SCENE: O<F_Scene>(S_BeginScene)(d); break;
    case OP_END_SCENE:   O<F_Scene>(S_EndScene)(d); break;
    case OP_CLEAR:       { CmdClear* c = (CmdClear*)h; O<F_Clear>(S_Clear)(d, c->count, c->count ? (const D3DRECT*)(c + 1) : nullptr, c->flags, c->color, c->z, c->stencil); break; }
    case OP_DRAW:        { CmdDraw* c = (CmdDraw*)h; O<F_Draw>(S_Draw)(d, (D3DPRIMITIVETYPE)c->type, c->start, c->prims); break; }
    case OP_DRAW_INDEXED:{ CmdDrawIdx* c = (CmdDrawIdx*)h; O<F_DrawIdx>(S_DrawIdx)(d, (D3DPRIMITIVETYPE)c->type, c->baseVertex, c->minVertex, c->numVertices, c->startIndex, c->prims); break; }
    case OP_BUFFER_UPLOAD: {
        // The real Lock, a copy of what the client wrote, the real Unlock. Both
        // functions are the buffer's own, taken from its vtable when it was created.
        typedef HRESULT (__stdcall *LockFn)(void*, UINT, UINT, void**, DWORD);
        typedef HRESULT (__stdcall *UnlockFn)(void*);
        CmdUpload* c = (CmdUpload*)h;
        void* p = nullptr;
        if (SUCCEEDED(((LockFn)c->lockFn)(c->buf, c->offset, c->size, &p, c->lockFlags)) && p) {
            memcpy(p, c->data, c->size);
            ((UnlockFn)c->unlockFn)(c->buf);
        }
        break; }
    case OP_PRESENT: {
        CmdPresent* c = (CmdPresent*)h;
        const uint64_t tp0 = __rdtsc();
        g_lastPresentHr = O<F_Present>(S_Present)(d, (c->flags & 1) ? &c->src : nullptr,
                                                   (c->flags & 2) ? &c->dst : nullptr, c->wnd, nullptr);
        InterlockedExchangeAdd64(&g_ticksPresent, (LONG64)(__rdtsc() - tp0));
        GX_COMPILER_BARRIER();
        g_ring.framesConsumed = g_ring.framesConsumed + 1;
        SetEvent(g_ring.evFrame);
        break; }
    default: break;
    }
}

LONG WINAPI RenderFilter(EXCEPTION_POINTERS* ep) {
    Log("[GxRT] the render thread faulted: %08X at %p, reading/writing %p. Queued rendering is "
        "switched off for the rest of the session and calls go straight to the device.",
        (unsigned)ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress,
        ep->ExceptionRecord->NumberParameters > 1 ? (void*)ep->ExceptionRecord->ExceptionInformation[1] : nullptr);
    return EXCEPTION_EXECUTE_HANDLER;
}

DWORD WINAPI RenderThreadProc(LPVOID) {
    g_renderTid = GetCurrentThreadId();
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    SamplingProfiler::RegisterSelfSymbol("GxRT_RenderThread", (const void*)&RenderThreadProc);

    Ring& R = g_ring;
    uint32_t rd = R.rd;
    for (;;) {
        if (g_stop) break;
        uint32_t pub = R.pub;
        if (rd == pub) {
            for (int i = 0; i < 2000 && R.pub == rd; ++i) YieldProcessor();
            if (R.pub == rd) {
                R.sleeping = 1;
                _mm_mfence();                       // store 'sleeping', then look at 'pub'
                if (R.pub == rd && !g_stop) {
                    ++g_consumerSleeps;
                    WaitForSingleObject(R.evData, 1);   // capped so shutdown never waits on us
                }
                R.sleeping = 0;
            }
            continue;
        }
        unsigned n = 0;
        const uint64_t tb0 = __rdtsc();
        while (rd != pub) {
            CmdHdr* h = (CmdHdr*)(R.base + (rd & kRingMask));
            __try {
                Execute(h);
            } __except (RenderFilter(GetExceptionInformation())) {
                InterlockedExchange(&g_active, 0);
                InterlockedExchange(&g_dead, 1);
                return 1;
            }
            rd += h->bytes;
            if ((++n & 15u) == 0) { GX_COMPILER_BARRIER(); R.rd = rd; }
        }
        GX_COMPILER_BARRIER();
        R.rd = rd;
        InterlockedExchangeAdd64(&g_ticksBusy, (LONG64)(__rdtsc() - tb0));
        InterlockedIncrement64(&g_batches);
    }
    return 0;
}

// ---- main-thread waits ------------------------------------------------------------
void Throttle() {
    Ring& R = g_ring;
    if ((uint32_t)(R.framesProduced - R.framesConsumed) <= kMaxFramesInFlight) return;
    const uint64_t t0 = __rdtsc();
    unsigned spins = 0;
    while ((uint32_t)(R.framesProduced - R.framesConsumed) > kMaxFramesInFlight) {
        if (g_dead) break;
        ++spins;
        if (spins < 300) YieldProcessor();
        else if (spins < 400) SwitchToThread();
        else WaitForSingleObject(R.evFrame, 1);
    }
    g_ticksThrottle += __rdtsc() - t0;
    ++g_throttleWaits;
}

}  // namespace

void Drain() {
    Ring& R = g_ring;
    if (R.rd == R.wr) return;
    R.Flush();
    if (g_dead) return;
    const uint64_t t0 = __rdtsc();
    unsigned spins = 0;
    DWORD startMs = 0;
    while (R.rd != R.wr) {
        if (g_dead) break;
        if (++spins < 20000) { YieldProcessor(); continue; }
        SwitchToThread();
        // A ring that does not empty is a render thread that cannot run, and
        // what stops it is a lock this thread holds further up its own stack.
        // Waiting longer never helps, and a frozen window is worse than one
        // call made out of order, so give up after a few seconds and say so.
        if ((spins & 1023u) == 0) {
            const DWORD now = GetTickCount();
            if (!startMs) startMs = now;
            else if (now - startMs > kDrainGiveUpMs) { ++g_drainGaveUp; break; }
        }
    }
    g_ticksDrain += __rdtsc() - t0;
    ++g_drains;
}

namespace {

// ---- thunks: queued -----------------------------------------------------------------
#define GX_LIVE_OR(slot, FT, ...) \
    if (!Live()) return O<FT>(slot)(__VA_ARGS__)

HRESULT __stdcall T_SetRenderState(IDirect3DDevice9* d, D3DRENDERSTATETYPE s, DWORD v) {
    GX_LIVE_OR(S_SetRS, F_RS, d, s, v);
    CmdRS* c = Emit<CmdRS>(OP_SET_RS); c->state = s; c->value = v;
    ++g_cmds[OP_SET_RS]; return D3D_OK;
}
HRESULT __stdcall T_SetTextureStageState(IDirect3DDevice9* d, DWORD st, D3DTEXTURESTAGESTATETYPE t, DWORD v) {
    GX_LIVE_OR(S_SetTSS, F_TSS, d, st, t, v);
    CmdTSS* c = Emit<CmdTSS>(OP_SET_TSS); c->stage = st; c->type = t; c->value = v;
    ++g_cmds[OP_SET_TSS]; return D3D_OK;
}
HRESULT __stdcall T_SetSamplerState(IDirect3DDevice9* d, DWORD sm, D3DSAMPLERSTATETYPE t, DWORD v) {
    GX_LIVE_OR(S_SetSampler, F_Sampler, d, sm, t, v);
    CmdSampler* c = Emit<CmdSampler>(OP_SET_SAMPLER); c->sampler = sm; c->type = t; c->value = v;
    ++g_cmds[OP_SET_SAMPLER]; return D3D_OK;
}
HRESULT __stdcall T_SetTexture(IDirect3DDevice9* d, DWORD st, IDirect3DBaseTexture9* t) {
    GX_LIVE_OR(S_SetTexture, F_Tex, d, st, t);
    if (t) t->AddRef();
    CmdTexture* c = Emit<CmdTexture>(OP_SET_TEXTURE); c->stage = st; c->tex = t;
    ++g_cmds[OP_SET_TEXTURE]; return D3D_OK;
}
HRESULT __stdcall T_SetTransform(IDirect3DDevice9* d, D3DTRANSFORMSTATETYPE s, const D3DMATRIX* m) {
    GX_LIVE_OR(S_SetTransform, F_Xform, d, s, m);
    if (!m) return O<F_Xform>(S_SetTransform)(d, s, m);
    CmdTransform* c = Emit<CmdTransform>(OP_SET_TRANSFORM); c->state = s; c->m = *m;
    ++g_cmds[OP_SET_TRANSFORM]; return D3D_OK;
}
HRESULT __stdcall T_SetViewport(IDirect3DDevice9* d, const D3DVIEWPORT9* vp) {
    GX_LIVE_OR(S_SetViewport, F_VP, d, vp);
    if (!vp) return O<F_VP>(S_SetViewport)(d, vp);
    CmdViewport* c = Emit<CmdViewport>(OP_SET_VIEWPORT); c->vp = *vp;
    ++g_cmds[OP_SET_VIEWPORT]; return D3D_OK;
}
HRESULT __stdcall T_SetMaterial(IDirect3DDevice9* d, const D3DMATERIAL9* m) {
    GX_LIVE_OR(S_SetMaterial, F_Mtl, d, m);
    if (!m) return O<F_Mtl>(S_SetMaterial)(d, m);
    CmdMaterial* c = Emit<CmdMaterial>(OP_SET_MATERIAL); c->m = *m;
    ++g_cmds[OP_SET_MATERIAL]; return D3D_OK;
}
HRESULT __stdcall T_SetLight(IDirect3DDevice9* d, DWORD i, const D3DLIGHT9* l) {
    GX_LIVE_OR(S_SetLight, F_Light, d, i, l);
    if (!l) return O<F_Light>(S_SetLight)(d, i, l);
    CmdLight* c = Emit<CmdLight>(OP_SET_LIGHT); c->index = i; c->l = *l;
    ++g_cmds[OP_SET_LIGHT]; return D3D_OK;
}
HRESULT __stdcall T_LightEnable(IDirect3DDevice9* d, DWORD i, BOOL e) {
    GX_LIVE_OR(S_LightEnable, F_LightEn, d, i, e);
    CmdLightEn* c = Emit<CmdLightEn>(OP_LIGHT_ENABLE); c->index = i; c->enable = e;
    ++g_cmds[OP_LIGHT_ENABLE]; return D3D_OK;
}
HRESULT __stdcall T_SetClipPlane(IDirect3DDevice9* d, DWORD i, const float* p) {
    GX_LIVE_OR(S_SetClipPlane, F_Clip, d, i, p);
    if (!p) return O<F_Clip>(S_SetClipPlane)(d, i, p);
    CmdClip* c = Emit<CmdClip>(OP_SET_CLIP); c->index = i; memcpy(c->plane, p, sizeof(c->plane));
    ++g_cmds[OP_SET_CLIP]; return D3D_OK;
}
HRESULT __stdcall T_SetScissorRect(IDirect3DDevice9* d, const RECT* r) {
    GX_LIVE_OR(S_SetScissor, F_Scissor, d, r);
    if (!r) return O<F_Scissor>(S_SetScissor)(d, r);
    CmdScissor* c = Emit<CmdScissor>(OP_SET_SCISSOR); c->r = *r;
    ++g_cmds[OP_SET_SCISSOR]; return D3D_OK;
}
HRESULT __stdcall T_SetStreamSource(IDirect3DDevice9* d, UINT n, IDirect3DVertexBuffer9* vb, UINT off, UINT stride) {
    GX_LIVE_OR(S_SetStream, F_Stream, d, n, vb, off, stride);
    if (vb) vb->AddRef();
    CmdStream* c = Emit<CmdStream>(OP_SET_STREAM); c->n = n; c->vb = vb; c->offset = off; c->stride = stride;
    ++g_cmds[OP_SET_STREAM]; return D3D_OK;
}
HRESULT __stdcall T_SetStreamSourceFreq(IDirect3DDevice9* d, UINT n, UINT div) {
    GX_LIVE_OR(S_SetStreamFreq, F_StreamFreq, d, n, div);
    CmdStreamFreq* c = Emit<CmdStreamFreq>(OP_SET_STREAM_FREQ); c->n = n; c->divider = div;
    ++g_cmds[OP_SET_STREAM_FREQ]; return D3D_OK;
}
HRESULT __stdcall T_SetIndices(IDirect3DDevice9* d, IDirect3DIndexBuffer9* ib) {
    GX_LIVE_OR(S_SetIndices, F_Indices, d, ib);
    if (ib) ib->AddRef();
    CmdIndices* c = Emit<CmdIndices>(OP_SET_INDICES); c->ib = ib;
    ++g_cmds[OP_SET_INDICES]; return D3D_OK;
}
HRESULT __stdcall T_SetVertexDeclaration(IDirect3DDevice9* d, IDirect3DVertexDeclaration9* v) {
    GX_LIVE_OR(S_SetVDecl, F_VDecl, d, v);
    if (v) v->AddRef();
    CmdObject* c = Emit<CmdObject>(OP_SET_VDECL); c->obj = v;
    ++g_cmds[OP_SET_VDECL]; return D3D_OK;
}
HRESULT __stdcall T_SetFVF(IDirect3DDevice9* d, DWORD fvf) {
    GX_LIVE_OR(S_SetFVF, F_FVF, d, fvf);
    CmdFVF* c = Emit<CmdFVF>(OP_SET_FVF); c->fvf = fvf;
    ++g_cmds[OP_SET_FVF]; return D3D_OK;
}
HRESULT __stdcall T_SetVertexShader(IDirect3DDevice9* d, IDirect3DVertexShader9* s) {
    GX_LIVE_OR(S_SetVS, F_VS, d, s);
    if (s) s->AddRef();
    CmdObject* c = Emit<CmdObject>(OP_SET_VS); c->obj = s;
    ++g_cmds[OP_SET_VS]; return D3D_OK;
}
HRESULT __stdcall T_SetPixelShader(IDirect3DDevice9* d, IDirect3DPixelShader9* s) {
    GX_LIVE_OR(S_SetPS, F_PS, d, s);
    if (s) s->AddRef();
    CmdObject* c = Emit<CmdObject>(OP_SET_PS); c->obj = s;
    ++g_cmds[OP_SET_PS]; return D3D_OK;
}
HRESULT __stdcall T_SetVertexShaderConstantF(IDirect3DDevice9* d, UINT start, const float* data, UINT count) {
    GX_LIVE_OR(S_SetVSConstF, F_ConstF, d, start, data, count);
    if (!data || count > 256) return O<F_ConstF>(S_SetVSConstF)(d, start, data, count);
    CmdConstF* c = EmitVar<CmdConstF>(OP_SET_VS_CONSTF, count * 16u); c->start = start; c->count = count;
    memcpy(c + 1, data, count * 16u);
    ++g_cmds[OP_SET_VS_CONSTF]; return D3D_OK;
}
HRESULT __stdcall T_SetPixelShaderConstantF(IDirect3DDevice9* d, UINT start, const float* data, UINT count) {
    GX_LIVE_OR(S_SetPSConstF, F_ConstF, d, start, data, count);
    if (!data || count > 256) return O<F_ConstF>(S_SetPSConstF)(d, start, data, count);
    CmdConstF* c = EmitVar<CmdConstF>(OP_SET_PS_CONSTF, count * 16u); c->start = start; c->count = count;
    memcpy(c + 1, data, count * 16u);
    ++g_cmds[OP_SET_PS_CONSTF]; return D3D_OK;
}
HRESULT __stdcall T_SetRenderTarget(IDirect3DDevice9* d, DWORD i, IDirect3DSurface9* s) {
    GX_LIVE_OR(S_SetRT, F_RT, d, i, s);
    if (s) s->AddRef();
    CmdRT* c = Emit<CmdRT>(OP_SET_RT); c->index = i; c->surf = s;
    ++g_cmds[OP_SET_RT]; return D3D_OK;
}
HRESULT __stdcall T_SetDepthStencilSurface(IDirect3DDevice9* d, IDirect3DSurface9* s) {
    GX_LIVE_OR(S_SetDS, F_DS, d, s);
    if (s) s->AddRef();
    CmdObject* c = Emit<CmdObject>(OP_SET_DS); c->obj = s;
    ++g_cmds[OP_SET_DS]; return D3D_OK;
}
HRESULT __stdcall T_BeginScene(IDirect3DDevice9* d) {
    GX_LIVE_OR(S_BeginScene, F_Scene, d);
    Emit<CmdScene>(OP_BEGIN_SCENE); ++g_cmds[OP_BEGIN_SCENE]; return D3D_OK;
}
HRESULT __stdcall T_EndScene(IDirect3DDevice9* d) {
    GX_LIVE_OR(S_EndScene, F_Scene, d);
    Emit<CmdScene>(OP_END_SCENE); ++g_cmds[OP_END_SCENE]; return D3D_OK;
}
HRESULT __stdcall T_Clear(IDirect3DDevice9* d, DWORD count, const D3DRECT* rects, DWORD flags, D3DCOLOR color, float z, DWORD stencil) {
    GX_LIVE_OR(S_Clear, F_Clear, d, count, rects, flags, color, z, stencil);
    if (count > 16 || (count && !rects)) {          // too many rectangles to copy: wait, then do it here
        ++g_clearFallbacks;
        Drain();
        return O<F_Clear>(S_Clear)(d, count, rects, flags, color, z, stencil);
    }
    CmdClear* c = EmitVar<CmdClear>(OP_CLEAR, count * (uint32_t)sizeof(D3DRECT));
    c->count = count; c->flags = flags; c->color = color; c->z = z; c->stencil = stencil;
    if (count) memcpy(c + 1, rects, count * sizeof(D3DRECT));
    ++g_cmds[OP_CLEAR]; return D3D_OK;
}
HRESULT __stdcall T_DrawPrimitive(IDirect3DDevice9* d, D3DPRIMITIVETYPE t, UINT start, UINT prims) {
    GX_LIVE_OR(S_Draw, F_Draw, d, t, start, prims);
    CmdDraw* c = Emit<CmdDraw>(OP_DRAW); c->type = t; c->start = start; c->prims = prims;
    ++g_cmds[OP_DRAW]; return D3D_OK;
}
HRESULT __stdcall T_DrawIndexedPrimitive(IDirect3DDevice9* d, D3DPRIMITIVETYPE t, INT base, UINT minV, UINT numV, UINT startIdx, UINT prims) {
    GX_LIVE_OR(S_DrawIdx, F_DrawIdx, d, t, base, minV, numV, startIdx, prims);
    CmdDrawIdx* c = Emit<CmdDrawIdx>(OP_DRAW_INDEXED);
    c->type = t; c->baseVertex = base; c->minVertex = minV; c->numVertices = numV; c->startIndex = startIdx; c->prims = prims;
    ++g_cmds[OP_DRAW_INDEXED]; return D3D_OK;
}
HRESULT __stdcall T_Present(IDirect3DDevice9* d, const RECT* src, const RECT* dst, HWND wnd, const RGNDATA* dirty) {
    if (!Live()) return O<F_Present>(S_Present)(d, src, dst, wnd, dirty);
    if (dirty) {                                    // a dirty region is not carried; do this one here
        ++g_presentFallbacks;
        Drain();
        return O<F_Present>(S_Present)(d, src, dst, wnd, dirty);
    }
    // The frame boundary, here on the main thread where its work belongs. The
    // state manager's Present hook, which would have run it, executes on the
    // render thread from here on and leaves it out. The two paths above reach
    // that hook on this thread and it runs the boundary itself, so each frame
    // sees exactly one.
    D3D9StateManager_RunDeferredMainThreadWork();
    M2AnimStride::OnPresent();
    FrameBench::OnPresent(FrameBench::Source::D3D9Present);
    WowOpt_OnFrameBoundary();
    CmdPresent* c = Emit<CmdPresent>(OP_PRESENT);
    c->flags = (src ? 1u : 0u) | (dst ? 2u : 0u);
    if (src) c->src = *src;
    if (dst) c->dst = *dst;
    c->wnd = wnd;
    GX_COMPILER_BARRIER();
    g_ring.framesProduced = g_ring.framesProduced + 1;
    g_ring.Flush();
    ++g_presents;
    Throttle();                                     // at most kMaxFramesInFlight ahead
    g_arena.Flip();                                 // the frame before last is finished: its arena is free
    return g_lastPresentHr;                         // the previous frame's result
}

// ---- thunks: drain first ----------------------------------------------------------------
// True when the address lies inside d3d9.dll. The native runtime calls back
// through the public device vtable while it holds its own device lock: a
// resource being destroyed releases its parent device that way. Draining there
// waits for a render thread that is waiting for that lock, and the main thread
// spun in SwitchToThread for as long as the tester left it running. The
// runtime's own bookkeeping needs nothing from the ring, so those calls pass.
bool InsideD3d9Runtime(uintptr_t addr) {
    static uintptr_t lo = 0, hi = 0;
    if (!lo) {
        HMODULE m = GetModuleHandleW(L"d3d9.dll");
        if (!m) return false;
        const uint8_t* b = (const uint8_t*)m;
        const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(b + ((const IMAGE_DOS_HEADER*)b)->e_lfanew);
        hi = (uintptr_t)b + nt->OptionalHeader.SizeOfImage;
        lo = (uintptr_t)b;
    }
    return addr >= lo && addr < hi;
}

// The stub pushes the slot and calls this, so the caller's own return address
// sits one word above the argument.
void __cdecl SyncEnter(int slot) {
    if (!Live()) return;
    ++g_syncCalls[slot];
    if (InsideD3d9Runtime(((const uintptr_t*)&slot)[1])) { ++g_syncFromRuntime; return; }
    Drain();
    if (slot == S_Reset) g_lastPresentHr = D3D_OK;
}

// ---- textures: a CPU write must not overtake draws still in the ring --------------------
// A texture is locked and written from the main thread while draws that sample it
// may still be queued for the render thread. On a managed texture the draw then
// sees newer contents than the frame it was recorded in, which is harmless. On a
// dynamic texture locked with DISCARD the real lock renames the backing store, and
// a draw queued before it executes afterwards against a store nothing has been
// written into: the glyph atlas is that texture, and the symptom is letters missing
// from text that stay missing until the page is rebuilt. So a lock that writes
// waits for the ring to empty, the way every other call that is not queued does.
// A read-only lock does not: no draw writes a texture the client can lock.
typedef HRESULT (__stdcall *F_CreateTexture)(IDirect3DDevice9*, UINT, UINT, UINT, DWORD, D3DFORMAT,
                                             D3DPOOL, IDirect3DTexture9**, HANDLE*);
typedef HRESULT (__stdcall *F_TexLockRect)(void*, UINT, D3DLOCKED_RECT*, const RECT*, DWORD);
constexpr int kTexSlotLockRect = 19;      // IDirect3DTexture9: 3 IUnknown, 8 resource, 6 base texture, 2 level methods
struct TexVt { uintptr_t* vt; F_TexLockRect lock; };
constexpr int kMaxTexVt = 8;
TexVt         g_texVt[kMaxTexVt];
volatile LONG g_texVtCount = 0;
volatile LONG g_texPatchLock = 0;
unsigned long g_texLocks = 0, g_texLockDrains = 0, g_texLockOffMain = 0;

HRESULT __stdcall T_TexLockRect(void* self, UINT level, D3DLOCKED_RECT* lr, const RECT* rc, DWORD flags) {
    uintptr_t* vt = *(uintptr_t**)self;
    F_TexLockRect orig = nullptr;
    const LONG n = g_texVtCount;
    for (LONG i = 0; i < n; ++i) if (g_texVt[i].vt == vt) { orig = g_texVt[i].lock; break; }
    if (!orig) return D3DERR_INVALIDCALL;
    if (g_active) {
        if (!OnMain()) {
            ++g_texLockOffMain;     // the async loader's own lock: nothing queued can be reading it yet
        } else {
            ++g_texLocks;
            if (!(flags & D3DLOCK_READONLY) &&
                !InsideD3d9Runtime((uintptr_t)_ReturnAddress())) {
                ++g_texLockDrains;
                Drain();
            }
        }
    }
    return orig(self, level, lr, rc, flags);
}

void PatchTextureVtable(IDirect3DTexture9* tex) {
    uintptr_t* vt = *(uintptr_t**)tex;
    if (!vt) return;
    while (InterlockedCompareExchange(&g_texPatchLock, 1, 0) != 0) YieldProcessor();
    bool known = false;
    const LONG n = g_texVtCount;
    for (LONG i = 0; i < n; ++i) if (g_texVt[i].vt == vt) { known = true; break; }
    if (!known && n < kMaxTexVt) {
        DWORD old = 0;
        if (VirtualProtect(&vt[kTexSlotLockRect], sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) {
            g_texVt[n].vt = vt;
            g_texVt[n].lock = (F_TexLockRect)vt[kTexSlotLockRect];
            MemoryBarrier();
            g_texVtCount = n + 1;            // registered before the slot points at the thunk
            vt[kTexSlotLockRect] = (uintptr_t)&T_TexLockRect;
            VirtualProtect(&vt[kTexSlotLockRect], sizeof(void*), old, &old);
        }
    }
    g_texPatchLock = 0;
}

HRESULT __stdcall T_CreateTexture(IDirect3DDevice9* d, UINT w, UINT h, UINT levels, DWORD usage,
                                  D3DFORMAT fmt, D3DPOOL pool, IDirect3DTexture9** pp, HANDLE* shared) {
    const HRESULT hr = O<F_CreateTexture>(S_CreateTexture)(d, w, h, levels, usage, fmt, pool, pp, shared);
    if (SUCCEEDED(hr) && pp && *pp) PatchTextureVtable(*pp);
    return hr;
}

// ---- queries: Begin and End must meet the draws they bracket ------------------------------
// The client creates occlusion queries (sub_6A0140 and its neighbours: type 9, Issue
// with the flag in sub_6A01C0, GetData in sub_6A0280). A query's Issue is a call on
// the query object, not on the device, so it ran on the main thread at once while
// the draws between BEGIN and END were still in the ring: BEGIN and END met with
// nothing drawn between them and the count came back zero. Issue now drains first.
// At BEGIN that finishes everything queued before it, so the query starts after
// them; at END it finishes the bracketed draws, so the query ends after them. The
// result is then what the client would have read without a render thread. Two
// stalls for a query pair, and only for what uses queries.
typedef HRESULT (__stdcall *F_CreateQuery)(IDirect3DDevice9*, D3DQUERYTYPE, IDirect3DQuery9**);
typedef HRESULT (__stdcall *F_QueryIssue)(void*, DWORD);
constexpr int kQuerySlotIssue = 6;         // IDirect3DQuery9: 3 IUnknown, GetDevice, GetType, GetDataSize, Issue
struct QVt { uintptr_t* vt; F_QueryIssue issue; };
constexpr int kMaxQVt = 4;
QVt           g_qVt[kMaxQVt];
volatile LONG g_qVtCount = 0;
volatile LONG g_qPatchLock = 0;
unsigned long g_queryCreates = 0, g_queryIssues = 0, g_queryIssueDrains = 0;
bool          g_queryReported = false;

HRESULT __stdcall T_QueryIssue(void* self, DWORD flags) {
    uintptr_t* vt = *(uintptr_t**)self;
    F_QueryIssue orig = nullptr;
    const LONG n = g_qVtCount;
    for (LONG i = 0; i < n; ++i) if (g_qVt[i].vt == vt) { orig = g_qVt[i].issue; break; }
    if (!orig) return D3DERR_INVALIDCALL;
    if (g_active && OnMain()) {
        ++g_queryIssues;
        if (!InsideD3d9Runtime((uintptr_t)_ReturnAddress())) { ++g_queryIssueDrains; Drain(); }
    }
    return orig(self, flags);
}

void PatchQueryVtable(IDirect3DQuery9* q) {
    uintptr_t* vt = *(uintptr_t**)q;
    if (!vt) return;
    while (InterlockedCompareExchange(&g_qPatchLock, 1, 0) != 0) YieldProcessor();
    bool known = false;
    const LONG n = g_qVtCount;
    for (LONG i = 0; i < n; ++i) if (g_qVt[i].vt == vt) { known = true; break; }
    if (!known && n < kMaxQVt) {
        DWORD old = 0;
        if (VirtualProtect(&vt[kQuerySlotIssue], sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) {
            g_qVt[n].vt = vt;
            g_qVt[n].issue = (F_QueryIssue)vt[kQuerySlotIssue];
            MemoryBarrier();
            g_qVtCount = n + 1;
            vt[kQuerySlotIssue] = (uintptr_t)&T_QueryIssue;
            VirtualProtect(&vt[kQuerySlotIssue], sizeof(void*), old, &old);
        }
    }
    g_qPatchLock = 0;
}

HRESULT __stdcall T_CreateQuery(IDirect3DDevice9* d, D3DQUERYTYPE type, IDirect3DQuery9** pp) {
    const HRESULT hr = O<F_CreateQuery>(S_CreateQuery)(d, type, pp);
    if (SUCCEEDED(hr) && pp && *pp) {
        ++g_queryCreates;
        PatchQueryVtable(*pp);
        if (!g_queryReported) {
            g_queryReported = true;
            Log("[GxRT] the client created a D3D query (type %d). Its Issue calls drain the ring first, "
                "so the bracketed draws have run when it ends.", (int)type);
        }
    }
    return hr;
}

void BuildStubs() {
    if (g_stubs) return;
    g_stubs = (uint8_t*)VirtualAlloc(nullptr, kSlots * 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_stubs) return;
    for (int i = 0; i < kSlots; ++i) {
        uint8_t* s = g_stubs + i * 16;
        s[0] = 0x6A; s[1] = (uint8_t)i;                                          // push slot
        s[2] = 0xE8; *(int32_t*)(s + 3) = (int32_t)((uint8_t*)&SyncEnter - (s + 7));   // call SyncEnter
        s[7] = 0x83; s[8] = 0xC4; s[9] = 0x04;                                   // add esp, 4
        s[10] = 0xFF; s[11] = 0x25; *(uint32_t*)(s + 12) = (uint32_t)(uintptr_t)&g_orig[i];  // jmp [g_orig[i]]
    }
    FlushInstructionCache(GetCurrentProcess(), g_stubs, kSlots * 16);
}

void* QueuedThunk(int slot) {
    switch (slot) {
    case S_Present:       return (void*)&T_Present;
    case S_CreateTexture: return (void*)&T_CreateTexture;
    case S_CreateQuery:   return (void*)&T_CreateQuery;
    case S_CreateVB:      return (void*)&T_CreateVertexBuffer;
    case S_CreateIB:      return (void*)&T_CreateIndexBuffer;
    case S_SetRT:         return (void*)&T_SetRenderTarget;
    case S_SetDS:         return (void*)&T_SetDepthStencilSurface;
    case S_BeginScene:    return (void*)&T_BeginScene;
    case S_EndScene:      return (void*)&T_EndScene;
    case S_Clear:         return (void*)&T_Clear;
    case S_SetTransform:  return (void*)&T_SetTransform;
    case S_SetViewport:   return (void*)&T_SetViewport;
    case S_SetMaterial:   return (void*)&T_SetMaterial;
    case S_SetLight:      return (void*)&T_SetLight;
    case S_LightEnable:   return (void*)&T_LightEnable;
    case S_SetClipPlane:  return (void*)&T_SetClipPlane;
    case S_SetRS:         return (void*)&T_SetRenderState;
    case S_SetTexture:    return (void*)&T_SetTexture;
    case S_SetTSS:        return (void*)&T_SetTextureStageState;
    case S_SetSampler:    return (void*)&T_SetSamplerState;
    case S_SetScissor:    return (void*)&T_SetScissorRect;
    case S_Draw:          return (void*)&T_DrawPrimitive;
    case S_DrawIdx:       return (void*)&T_DrawIndexedPrimitive;
    case S_SetVDecl:      return (void*)&T_SetVertexDeclaration;
    case S_SetFVF:        return (void*)&T_SetFVF;
    case S_SetVS:         return (void*)&T_SetVertexShader;
    case S_SetVSConstF:   return (void*)&T_SetVertexShaderConstantF;
    case S_SetStream:     return (void*)&T_SetStreamSource;
    case S_SetStreamFreq: return (void*)&T_SetStreamSourceFreq;
    case S_SetIndices:    return (void*)&T_SetIndices;
    case S_SetPS:         return (void*)&T_SetPixelShader;
    case S_SetPSConstF:   return (void*)&T_SetPixelShaderConstantF;
    default:              return nullptr;
    }
}

// ---- device creation ----------------------------------------------------------------------
typedef HRESULT (__stdcall *F_CreateDevice)(IDirect3D9*, UINT, D3DDEVTYPE, HWND, DWORD,
                                            D3DPRESENT_PARAMETERS*, IDirect3DDevice9**);
typedef int (__cdecl *F_LoadD3dLib)(HMODULE*, int*);

F_CreateDevice g_origCreateDevice = nullptr;
F_LoadD3dLib   g_origLoadD3dLib = nullptr;
bool           g_createDeviceHooked = false;

void StartThread() {
    if (g_thread) return;
    g_thread = CreateThread(nullptr, 0, RenderThreadProc, nullptr, 0, nullptr);
    if (!g_thread) {
        g_why = "CreateThread failed";
        Log("[GxRT] the render thread could not be created; rendering stays on the main thread.");
    }
}

void PatchDevice(IDirect3DDevice9* dev) {
    uintptr_t* vt = *(uintptr_t**)dev;
    BuildStubs();
    if (!g_stubs) { g_why = "the stub page could not be allocated"; return; }

    // The same vtable again, which is what a recreated device on the same class
    // hands back. It is already ours and whatever sits in a slot now is either
    // our thunk or another module's hook written over it. Capturing that hook as
    // the original would make it call our thunk which calls it, forever: the first
    // in-game device restart did exactly that with the state manager's hooks and
    // both threads ran out of stack.
    if (g_patchedVt == vt) {
        Log("[GxRT] device %p shares the vtable already rewritten; nothing to patch.", (void*)dev);
        return;
    }
    // A different class: nothing captured for the old one applies to this one.
    if (g_patchedVt) {
        for (int i = 0; i < kSlots; ++i) { g_orig[i] = nullptr; g_thunk[i] = nullptr; }
    }

    // Originals first, whatever the slot holds now: another module's hook that
    // was there before this file arrived is the function to call through.
    for (int i = 0; i < kSlots; ++i) {
        if (!g_orig[i]) g_orig[i] = (void*)vt[i];
    }

    DWORD oldProt = 0;
    if (!VirtualProtect(vt, kSlots * sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt)) {
        g_why = "the device vtable could not be made writable";
        return;
    }
    int queued = 0, drained = 0, direct = 0;
    for (int i = 0; i < kSlots; ++i) {
        if (IsDirectSlot(i)) { g_thunk[i] = (void*)g_orig[i]; ++direct; continue; }
        void* t = QueuedThunk(i);
        if (t) ++queued; else { t = g_stubs + i * 16; ++drained; }
        g_thunk[i] = t;
        vt[i] = (uintptr_t)t;
    }
    VirtualProtect(vt, kSlots * sizeof(void*), oldProt, &oldProt);
    g_patchedVt = vt;
    Log("[GxRT] device vtable rewritten: %d slots queued, %d drain-then-direct, %d left alone.",
        queued, drained, direct);
}

HRESULT __stdcall Hook_CreateDevice(IDirect3D9* self, UINT adapter, D3DDEVTYPE type, HWND focus,
                                    DWORD flags, D3DPRESENT_PARAMETERS* pp, IDirect3DDevice9** ppDev) {
    // The flag the first render thread never set: without it a device is only
    // defined for the thread that made it.
    HRESULT hr = g_origCreateDevice(self, adapter, type, focus, flags | D3DCREATE_MULTITHREADED, pp, ppDev);
    if (FAILED(hr) || !ppDev || !*ppDev) return hr;
    g_deviceThroughHook = true;

    // A second device replaces the first: stop queueing, let the thread finish what it has.
    if (g_active) { Drain(); InterlockedExchange(&g_active, 0); }
    g_dev = *ppDev;
    g_mainTid = __readfsdword(0x24);
    PatchDevice(g_dev);
    if (g_stubs) {
        BuffersInit();
        StartThread();
        if (g_thread) {
            g_everActive = true;
            g_why = "running";
            InterlockedExchange(&g_active, 1);
            Log("[GxRT] ACTIVE: device %p created MULTITHREADED, render thread started, main thread id %lu. "
                "Draws and state changes are queued; the main thread may run %u frame(s) ahead.",
                (void*)g_dev, (unsigned long)g_mainTid, (unsigned)kMaxFramesInFlight);
        }
    }
    return hr;
}

// True when the d3d9.dll this process loaded is Windows' own, found in the system
// directory. DXVK and wined3d ship theirs beside the game. Native Direct3D 9 has
// frozen the main thread after the restart on every machine it was run on: one
// frame never ended, 266,000 buffer locks drained the ring one at a time and two
// frames were presented in two minutes. So the render thread starts on a
// translation layer's runtime and not on that one.
bool NativeRuntimeLoaded() {
    HMODULE m = GetModuleHandleW(L"d3d9.dll");
    if (!m) return false;
    wchar_t mod[MAX_PATH] = {}, sys[MAX_PATH] = {};
    if (!GetModuleFileNameW(m, mod, MAX_PATH)) return false;
    const UINT n = GetSystemDirectoryW(sys, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    return _wcsnicmp(mod, sys, n) == 0 && mod[n] == L'\\';
}

bool g_nativeRefused = false;

void HookCreateDeviceOn(IDirect3D9* d3d) {
    if (g_createDeviceHooked || g_nativeRefused || !d3d) return;
    if (NativeRuntimeLoaded()) {
        g_nativeRefused = true;
        g_armed = false;
        g_why = "the game is using Windows' own Direct3D 9, where this froze the main thread";
        Log("[GxRT] not started: %s. The device is created the client's way and nothing is queued.", g_why);
        return;
    }
    uintptr_t* vt = *(uintptr_t**)d3d;
    if (!vt || (uintptr_t)vt < 0x10000) return;
    void* fn = (void*)vt[16];                       // IDirect3D9::CreateDevice
    if (!fn) return;
    MH_STATUS st = MH_CreateHook(fn, (void*)&Hook_CreateDevice, (void**)&g_origCreateDevice);
    if (st == MH_OK) st = MH_EnableHook(fn);
    if (st != MH_OK) {
        g_why = "the CreateDevice hook could not be installed";
        Log("[GxRT] CreateDevice hook failed (%d); the device will be created the client's way.", (int)st);
        return;
    }
    g_createDeviceHooked = true;
    Log("[GxRT] CreateDevice hooked at %p, waiting for the client to create its device.", fn);
}

// sub_6A0AA0: loads d3d9.dll and returns an IDirect3D9 in *a2. It runs for the
// format enumeration and again for the real device, well before the first frame.
int __cdecl Hook_LoadD3dLib(HMODULE* a1, int* a2) {
    int r = g_origLoadD3dLib(a1, a2);
    if (r && a2 && *a2 && !g_createDeviceHooked) HookCreateDeviceOn((IDirect3D9*)(uintptr_t)*a2);
    return r;
}

constexpr uintptr_t kLoadD3dLib = 0x006A0AA0;
const uint8_t kLoadD3dLibPrologue[8] = { 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x0C, 0x57 };

}  // namespace

bool Init() {
    g_configured = Config::g_settings.OptD3d9RenderThread;
    if (!g_configured) { g_why = "switched off"; return false; }
    if (RunningUnderTranslation()) {
        g_why = "forced off under Wine/Rosetta";
        Log("[GxRT] not started: %s.", g_why);
        return false;
    }
    if (Config::g_settings.OptNoClientPatches || !WowOpt_ClientPatchAllowed((const void*)kLoadD3dLib)) {
        g_why = "client patches are not allowed";
        Log("[GxRT] not started: %s.", g_why);
        return false;
    }
    if (memcmp((const void*)kLoadD3dLib, kLoadD3dLibPrologue, sizeof(kLoadD3dLibPrologue)) != 0) {
        g_why = "the client's D3D loader is not the one this was read from";
        Log("[GxRT] not started: %s (0x%08X).", g_why, (unsigned)kLoadD3dLib);
        return false;
    }

    g_tsc0 = __rdtsc();
    QueryPerformanceCounter(&g_qpc0);
    g_ring.base = (uint8_t*)HighTables::Reserve("gx_ring", kRingBytes);
    uint8_t* arena = (uint8_t*)HighTables::Reserve("gx_arena", 2u * kArenaBytes);
    if (!g_ring.base || !arena) { g_why = "the ring or the arena could not be reserved"; return false; }
    g_arena.base[0] = arena;
    g_arena.base[1] = arena + kArenaBytes;
    g_arena.used = 0; g_arena.cur = 0;
    g_ring.wr = g_ring.rd = g_ring.pub = g_ring.rdCache = g_ring.unflushed = 0;
    g_ring.framesProduced = g_ring.framesConsumed = 0;
    g_ring.evData  = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    g_ring.evFrame = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    if (!g_ring.evData || !g_ring.evFrame) { g_why = "the events could not be created"; return false; }

    if (WineSafe_CreateHook((void*)kLoadD3dLib, (void*)&Hook_LoadD3dLib, (void**)&g_origLoadD3dLib) != MH_OK ||
        MH_EnableHook((void*)kLoadD3dLib) != MH_OK) {                       // immediate: the loader may run any moment
        g_why = "the loader hook could not be installed";
        Log("[GxRT] not started: %s.", g_why);
        return false;
    }
    g_why = "waiting for the device";
    g_armed = true;
    Log("[GxRT] armed: the client's D3D loader (0x%08X) is hooked; the device will be created MULTITHREADED "
        "and its calls queued to a render thread. Ring %u KB, arena 2 x %u KB.",
        (unsigned)kLoadD3dLib, kRingBytes >> 10, kArenaBytes >> 10);
    return true;
}

bool IsActive() { return g_active != 0; }

bool OnRenderThread() {
    const DWORD tid = g_renderTid;
    return tid != 0 && GetCurrentThreadId() == tid;
}

namespace {
// sub_4DD400 is `sub_7658A0("gxRestart", 1)` and nothing else: the console
// dispatcher with the restart command, which is what typing it runs. It takes no
// arguments, so nothing about the dispatcher's own signature is assumed here.
constexpr uintptr_t kGxRestartCommand = 0x004DD400;
const uint8_t kGxRestartCommandPrologue[7] = { 0x6A, 0x01, 0x68, 0x08, 0x57, 0x9F, 0x00 };
constexpr uintptr_t kGxDeviceGlobal = 0x00C5DF88;     // the client's CGxDevice pointer
constexpr uintptr_t kLuaStateGlobal = 0x00D3F78C;
constexpr double    kSettleMs = 4000.0;               // after Init, before asking
constexpr double    kReportMs = 6000.0;               // after asking, before saying it did not take
}  // namespace

void OnMainThreadTick() {
    if (!g_armed || g_everActive || g_dead) return;

    LARGE_INTEGER f, now;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&now);

    if (g_restartAsked) {
        if (!g_restartReported &&
            (double)(now.QuadPart - g_restartQpc.QuadPart) * 1000.0 / (double)f.QuadPart >= kReportMs) {
            g_restartReported = true;
            if (g_deviceThroughHook) {
                g_why = "a device came through the hook but the render thread did not start";
                Log("[GxRT] the device restart was requested %.0f ms ago: %s. The client is running on that "
                    "device with its calls made directly.", kReportMs, g_why);
            } else {
                g_why = "the restart did not create a device through the hook";
                Log("[GxRT] the device restart was requested %.0f ms ago and no device has come through the "
                    "hook since: %s. The client is running its own device; '/console gxRestart' can be tried by hand.",
                    kReportMs, g_why);
            }
        }
        return;
    }

    if ((double)(now.QuadPart - g_qpc0.QuadPart) * 1000.0 / (double)f.QuadPart < kSettleMs) return;
    // Wait for the client to have a device and an interface, and never restart
    // in the middle of a loading screen or a state swap.
    if (!*(volatile uintptr_t*)kGxDeviceGlobal || !*(volatile uintptr_t*)kLuaStateGlobal) return;
    if (LoadingState::IsLoading() || LuaOpt::IsLoadingMode() || LuaOpt::IsReloading() || LuaOpt::IsSwapping()) return;

    // A restart does not go back through the client's D3D loader: the first one
    // in a field log made a new device at once, through the IDirect3D9 the client
    // already held, and the loader hook that installs the CreateDevice hook only
    // ran eleven seconds later. So put that hook in from the device we have. On
    // DXVK the IDirect3D9 vtable is one static table, so any instance reaches it.
    if (!g_createDeviceHooked) {
        IDirect3D9* d3d = nullptr;
        void* dev = D3D9StateManager_GetDevice();
        __try {
            if (dev && SUCCEEDED(((IDirect3DDevice9*)dev)->GetDirect3D(&d3d)) && d3d) {
                HookCreateDeviceOn(d3d);
                d3d->Release();
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            d3d = nullptr;
        }
        if (!g_createDeviceHooked) {
            if (!g_hookReported &&
                (double)(now.QuadPart - g_qpc0.QuadPart) * 1000.0 / (double)f.QuadPart >= kSettleMs + kReportMs) {
                g_hookReported = true;
                g_why = "no IDirect3D9 was reachable to hook CreateDevice on";
                Log("[GxRT] no automatic device restart: %s (device %p).", g_why, dev);
            }
            return;
        }
    }

    if (memcmp((const void*)kGxRestartCommand, kGxRestartCommandPrologue, sizeof(kGxRestartCommandPrologue)) != 0) {
        g_armed = false;
        g_why = "the client's gxRestart command is not the one this was read from";
        Log("[GxRT] no automatic device restart: %s (0x%08X).", g_why, (unsigned)kGxRestartCommand);
        return;
    }

    g_restartAsked = true;
    g_restartQpc = now;
    g_why = "waiting for the device restart";
    Log("[GxRT] the client created its device before this module loaded; asking it for a device restart "
        "(the gxRestart command) so the device is made through the hook. The screen goes black for a moment.");
    ((void (__cdecl*)())kGxRestartCommand)();
}

bool IsThunk(const void* fn) {
    if (!fn || !g_patchedVt) return false;
    for (int i = 0; i < kSlots; ++i) {
        if (!IsDirectSlot(i) && g_thunk[i] == fn) return true;
    }
    return false;
}

void Shutdown() {
    if (g_active) { Drain(); InterlockedExchange(&g_active, 0); }
    InterlockedExchange(&g_stop, 1);
    if (g_ring.evData) SetEvent(g_ring.evData);
}

void LogStats() {
    if (!g_configured) { Log("[GxRT] not measured: switched off."); return; }
    if (!g_everActive) { Log("[GxRT] not measured: %s.", g_why); return; }

    unsigned long total = 0;
    for (int i = 1; i < OP__COUNT; ++i) total += g_cmds[i];
    // Cycles to milliseconds, from the time stamp counter and the performance
    // counter since Init. Zero means the interval was too short to tell.
    LARGE_INTEGER f, q1; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&q1);
    const double ms = (double)(q1.QuadPart - g_qpc0.QuadPart) * 1000.0 / (double)f.QuadPart;
    const double cyclesPerMs = ms > 1000.0 ? (double)(__rdtsc() - g_tsc0) / ms : 0.0;
    auto toMs = [&](uint64_t t) { return cyclesPerMs > 0.0 ? (double)t / cyclesPerMs : -1.0; };
    Log("[GxRT] %s. %lu frame(s) presented, %lu command(s) queued (%.0f a frame), %lu draw(s), "
        "%lu the render thread had to be woken from sleep. Plain counters, lower bounds.",
        g_dead ? "DEAD: the render thread faulted, calls go direct" : "running",
        g_presents, total, g_presents ? (double)total / g_presents : 0.0,
        g_cmds[OP_DRAW] + g_cmds[OP_DRAW_INDEXED], g_consumerSleeps);
    Log("[GxRT]   the main thread waited on the render thread: %lu time(s) at the frame limit (%.0f ms in all), "
        "%lu time(s) for the ring to drain (%.0f ms), %lu time(s) for ring space (%.0f ms). A wait at the "
        "frame limit is the render thread being the slower side; a drain is a call it had to wait for. "
        "(-1 ms: the run was too short to time.)",
        g_throttleWaits, toMs(g_ticksThrottle), g_drains, toMs(g_ticksDrain),
        g_waitsRingFull, toMs(g_ticksRingFull));
    {
        // The number GxRT exists for, from this session alone: Direct3D work the
        // main thread no longer does, set against what it now waits for. Present
        // is left out of the render thread's figure because it blocks for the
        // display, and a thread blocked in Present is not doing work the main
        // thread would have done. Queueing the commands is not subtracted: it is
        // not measured, and it is small (a command is a few stores into the ring).
        const double busy = toMs((uint64_t)(g_ticksBusy - g_ticksPresent));
        const double present = toMs((uint64_t)g_ticksPresent);
        const double waited = toMs(g_ticksThrottle) + toMs(g_ticksDrain) + toMs(g_ticksRingFull);
        if (busy < 0.0 || g_presents == 0) {
            Log("[GxRT]   work moved off the main thread: not measured, the run was too short to time.");
        } else {
            const double perFrame = busy / (double)g_presents;
            const double waitFrame = waited / (double)g_presents;
            Log("[GxRT]   the render thread ran commands for %.0f ms apart from Present (%.0f ms in Present, "
                "waiting for the display): %.3f ms a frame of Direct3D work the main thread no longer does. "
                "The main thread waited %.3f ms a frame for it. Difference, positive meaning saved: %.3f ms a "
                "frame, before the cost of queueing, which is not measured. %lld batch(es) of commands.",
                busy, present, perFrame, waitFrame, perFrame - waitFrame, (long long)g_batches);
        }
    }
    Log("[GxRT]   Clear with too many rectangles done in place: %lu. Present with a dirty region done in place: %lu.",
        g_clearFallbacks, g_presentFallbacks);
    Log("[GxRT]   %lu sync call(s) came from inside d3d9.dll and were let through without a drain; "
        "%lu drain(s) waited over %lu ms and were abandoned (a lock held above the drain, which is a "
        "defect to report). Plain counters, lower bounds.",
        g_syncFromRuntime, g_drainGaveUp, (unsigned long)kDrainGiveUpMs);

    // The slots that made the main thread wait, most-called first.
    int order[kSlots]; int n = 0;
    for (int i = 0; i < kSlots; ++i) if (g_syncCalls[i]) order[n++] = i;
    for (int a = 0; a < n; ++a)
        for (int b = a + 1; b < n; ++b)
            if (g_syncCalls[order[b]] > g_syncCalls[order[a]]) { int t = order[a]; order[a] = order[b]; order[b] = t; }
    if (n == 0) {
        Log("[GxRT]   no drain-then-direct call was made: measured and zero.");
    } else {
        Log("[GxRT]   calls that drained the ring before running (each stalls the pipeline until the render "
            "thread has caught up; the top of this list is what to promote to the queue or leave alone):");
        for (int k = 0; k < n && k < 12; ++k)
            Log("[GxRT]     %-28s %lu", kSlotName[order[k]], g_syncCalls[order[k]]);
    }
    Log("[GxRT]   texture LockRect: %lu on the main thread, %lu of them waited for the ring to drain "
        "first (a write; a read-only lock does not), %lu from other threads and not waited on. "
        "Plain counters, lower bounds.", g_texLocks, g_texLockDrains, g_texLockOffMain);
    Log("[GxRT]   D3D queries: %lu created, %lu Issue call(s) on the main thread, %lu of them waited for the ring "
        "to drain. Zero created means the client never used one this session: measured and zero.",
        g_queryCreates, g_queryIssues, g_queryIssueDrains);
    BuffersLogStats();
}

}  // namespace GxRT
