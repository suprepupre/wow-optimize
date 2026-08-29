#include "d3d9_render_thread.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include <atomic>
// <thread> was included here and never used - every worker in this project is
// a CreateThread. Including it is what the no-std::thread rule exists to stop:
// it is the doorway to MSVCP140, which is loaded during early init and has
// crashed under Wine/Proton. Removed so the next person cannot reach through
// it by accident.
#include <windows.h>
#include <d3d9.h>

extern "C" void Log(const char* fmt, ...);
extern DWORD g_mainThreadId;

namespace D3D9StateCache {
    typedef HRESULT (WINAPI *SetRenderState_fn)(IDirect3DDevice9* device, D3DRENDERSTATETYPE state, DWORD value);
    extern SetRenderState_fn orig_SetRenderState;

    typedef HRESULT (WINAPI *SetTransform_fn)(IDirect3DDevice9* device, D3DTRANSFORMSTATETYPE state, const D3DMATRIX* matrix);
    extern SetTransform_fn orig_SetTransform;

    typedef HRESULT (WINAPI *SetViewport_fn)(IDirect3DDevice9* device, const D3DVIEWPORT9* viewport);
    extern SetViewport_fn orig_SetViewport;

    typedef HRESULT (WINAPI *SetVertexShaderConstantF_fn)(IDirect3DDevice9* device, UINT StartRegister, const float* pConstantData, UINT Vector4fCount);
    extern SetVertexShaderConstantF_fn orig_SetVertexShaderConstantF;

    typedef HRESULT (WINAPI *SetSamplerState_fn)(IDirect3DDevice9* device, DWORD Sampler, D3DSAMPLERSTATETYPE Type, DWORD Value);
    extern SetSamplerState_fn orig_SetSamplerState;

    typedef HRESULT (WINAPI *SetTextureStageState_fn)(IDirect3DDevice9* device, DWORD Stage, D3DTEXTURESTAGESTATETYPE Type, DWORD Value);
    extern SetTextureStageState_fn orig_SetTextureStageState;

    typedef HRESULT (WINAPI *Reset_fn)(IDirect3DDevice9* device, D3DPRESENT_PARAMETERS* params);
    extern Reset_fn orig_Reset;

    typedef HRESULT (WINAPI *Present_fn)(IDirect3DDevice9* device, const RECT* src, const RECT* dest, HWND window, const RGNDATA* dirty);
    extern Present_fn orig_Present;
}

namespace D3D9RenderThread {

enum CommandType {
    CMD_SET_RENDER_STATE,
    CMD_SET_TRANSFORM,
    CMD_SET_VIEWPORT,
    CMD_SET_VERTEX_SHADER_CONSTANT_F,
    CMD_SET_SAMPLER_STATE,
    CMD_SET_TEXTURE_STAGE_STATE,
    CMD_SET_TEXTURE,
    CMD_SET_STREAM_SOURCE,
    CMD_SET_INDICES,
    CMD_SET_VERTEX_DECLARATION,
    CMD_SET_VERTEX_SHADER,
    CMD_SET_PIXEL_SHADER,
    CMD_DRAW_PRIMITIVE,
    CMD_DRAW_INDEXED_PRIMITIVE,
    CMD_BEGIN_SCENE,
    CMD_END_SCENE,
    CMD_CLEAR,
    CMD_PRESENT,
    CMD_RESET
};

struct RenderCommand {
    CommandType type;
    IDirect3DDevice9* device;
    union {
        struct {
            D3DRENDERSTATETYPE state;
            DWORD value;
        } setRenderState;
        struct {
            D3DTRANSFORMSTATETYPE state;
            D3DMATRIX matrix;
        } setTransform;
        struct {
            D3DVIEWPORT9 viewport;
        } setViewport;
        struct {
            UINT startRegister;
            uint32_t poolOffset;
            UINT vector4fCount;
        } setVSConstF;
        struct {
            DWORD sampler;
            D3DSAMPLERSTATETYPE type;
            DWORD value;
        } setSamplerState;
        struct {
            DWORD stage;
            D3DTEXTURESTAGESTATETYPE type;
            DWORD value;
        } setTextureStageState;
        struct {
            DWORD stage;
            IDirect3DBaseTexture9* texture;
        } setTexture;
        struct {
            UINT streamNumber;
            IDirect3DVertexBuffer9* streamData;
            UINT offsetInBytes;
            UINT stride;
        } setStreamSource;
        struct {
            IDirect3DIndexBuffer9* indexData;
        } setIndices;
        struct {
            IDirect3DVertexDeclaration9* decl;
        } setVertexDecl;
        struct {
            IDirect3DVertexShader9* shader;
        } setVertexShader;
        struct {
            IDirect3DPixelShader9* shader;
        } setPixelShader;
        struct {
            D3DPRIMITIVETYPE primitiveType;
            UINT startVertex;
            UINT primitiveCount;
        } drawPrimitive;
        struct {
            D3DPRIMITIVETYPE primitiveType;
            INT baseVertexIndex;
            UINT minVertexIndex;
            UINT numVertices;
            UINT startIndex;
            UINT primCount;
        } drawIndexed;
        struct {
            DWORD count;
            D3DRECT rect;
            DWORD flags;
            D3DCOLOR color;
            float z;
            DWORD stencil;
        } clear;
        struct {
            RECT src;
            RECT dest;
            HWND window;
            RGNDATA* dirty;
        } present;
        struct {
            D3DPRESENT_PARAMETERS params;
        } reset;
    };
};

typedef HRESULT (WINAPI *DrawPrimitive_fn)(IDirect3DDevice9* device, D3DPRIMITIVETYPE PrimitiveType, UINT StartVertex, UINT PrimitiveCount);
static DrawPrimitive_fn orig_DrawPrimitive = nullptr;

typedef HRESULT (WINAPI *DrawIndexedPrimitive_fn)(IDirect3DDevice9* device, D3DPRIMITIVETYPE PrimitiveType, INT BaseVertexIndex, UINT MinVertexIndex, UINT NumVertices, UINT StartIndex, UINT primCount);
static DrawIndexedPrimitive_fn orig_DrawIndexedPrimitive = nullptr;

typedef HRESULT (WINAPI *SetTexture_fn)(IDirect3DDevice9* device, DWORD Stage, IDirect3DBaseTexture9* pTexture);
static SetTexture_fn orig_SetTexture = nullptr;

typedef HRESULT (WINAPI *SetStreamSource_fn)(IDirect3DDevice9* device, UINT StreamNumber, IDirect3DVertexBuffer9* pStreamData, UINT OffsetInBytes, UINT Stride);
static SetStreamSource_fn orig_SetStreamSource = nullptr;

typedef HRESULT (WINAPI *SetIndices_fn)(IDirect3DDevice9* device, IDirect3DIndexBuffer9* pIndexData);
static SetIndices_fn orig_SetIndices = nullptr;

typedef HRESULT (WINAPI *SetVertexDeclaration_fn)(IDirect3DDevice9* device, IDirect3DVertexDeclaration9* pDecl);
static SetVertexDeclaration_fn orig_SetVertexDeclaration = nullptr;

typedef HRESULT (WINAPI *SetVertexShader_fn)(IDirect3DDevice9* device, IDirect3DVertexShader9* pShader);
static SetVertexShader_fn orig_SetVertexShader = nullptr;

typedef HRESULT (WINAPI *SetPixelShader_fn)(IDirect3DDevice9* device, IDirect3DPixelShader9* pShader);
static SetPixelShader_fn orig_SetPixelShader = nullptr;

typedef HRESULT (WINAPI *BeginScene_fn)(IDirect3DDevice9* device);
static BeginScene_fn orig_BeginScene = nullptr;

typedef HRESULT (WINAPI *EndScene_fn)(IDirect3DDevice9* device);
static EndScene_fn orig_EndScene = nullptr;

typedef HRESULT (WINAPI *Clear_fn)(IDirect3DDevice9* device, DWORD Count, const D3DRECT* pRects, DWORD Flags, D3DCOLOR Color, float Z, DWORD Stencil);
static Clear_fn orig_Clear = nullptr;

static constexpr int RING_BUFFER_SIZE = 65536;
// Both buffers are committed on Init instead of sitting in BSS. This feature is
// off by default, yet between them they reserved close to nine megabytes at DLL
// load for every player, whether or not the render thread ever started.
static RenderCommand* g_commandQueue = nullptr;
static std::atomic<int> g_writeIndex{0};
static std::atomic<int> g_readIndex{0};

static constexpr int CONSTANT_POOL_SIZE = 65536 * 16;
static float* g_constantPool = nullptr;
static std::atomic<uint32_t> g_constantPoolWriteIdx{0};

static HANDLE g_renderThread = NULL;
static DWORD g_renderThreadId = 0;
static std::atomic<bool> g_renderThreadShutdown{false};
static std::atomic<bool> g_isActive{false};

bool IsActive() {
    return g_isActive.load(std::memory_order_relaxed);
}

DWORD GetRenderThreadId() {
    return g_renderThreadId;
}

void PipelineFlush() {
    if (!g_isActive.load(std::memory_order_relaxed) || GetCurrentThreadId() == g_renderThreadId) return;

    int writeIdx = g_writeIndex.load(std::memory_order_acquire);
    while (g_readIndex.load(std::memory_order_acquire) < writeIdx) {
        YieldProcessor();
        SwitchToThread();
    }
}

static void QueueCommand(const RenderCommand& cmd) {
    int currentWrite = g_writeIndex.load(std::memory_order_relaxed);
    while (currentWrite - g_readIndex.load(std::memory_order_acquire) >= RING_BUFFER_SIZE - 2) {
        YieldProcessor();
        SwitchToThread();
    }

    g_commandQueue[currentWrite % RING_BUFFER_SIZE] = cmd;
    g_writeIndex.store(currentWrite + 1, std::memory_order_release);
}

static void ExecuteCommand(const RenderCommand& cmd) {
    switch (cmd.type) {
        case CMD_SET_RENDER_STATE:
            D3D9StateCache::orig_SetRenderState(cmd.device, cmd.setRenderState.state, cmd.setRenderState.value);
            break;
        case CMD_SET_TRANSFORM:
            D3D9StateCache::orig_SetTransform(cmd.device, cmd.setTransform.state, &cmd.setTransform.matrix);
            break;
        case CMD_SET_VIEWPORT:
            D3D9StateCache::orig_SetViewport(cmd.device, &cmd.setViewport.viewport);
            break;
        case CMD_SET_VERTEX_SHADER_CONSTANT_F: {
            float localBuffer[256 * 4];
            uint32_t count = cmd.setVSConstF.vector4fCount * 4;
            for (uint32_t i = 0; i < count; ++i) {
                localBuffer[i] = g_constantPool[(cmd.setVSConstF.poolOffset + i) % CONSTANT_POOL_SIZE];
            }
            D3D9StateCache::orig_SetVertexShaderConstantF(cmd.device, cmd.setVSConstF.startRegister, localBuffer, cmd.setVSConstF.vector4fCount);
            break;
        }
        case CMD_SET_SAMPLER_STATE:
            D3D9StateCache::orig_SetSamplerState(cmd.device, cmd.setSamplerState.sampler, cmd.setSamplerState.type, cmd.setSamplerState.value);
            break;
        case CMD_SET_TEXTURE_STAGE_STATE:
            D3D9StateCache::orig_SetTextureStageState(cmd.device, cmd.setTextureStageState.stage, cmd.setTextureStageState.type, cmd.setTextureStageState.value);
            break;
        case CMD_SET_TEXTURE:
            orig_SetTexture(cmd.device, cmd.setTexture.stage, cmd.setTexture.texture);
            if (cmd.setTexture.texture) cmd.setTexture.texture->Release();
            break;
        case CMD_SET_STREAM_SOURCE:
            orig_SetStreamSource(cmd.device, cmd.setStreamSource.streamNumber, cmd.setStreamSource.streamData, cmd.setStreamSource.offsetInBytes, cmd.setStreamSource.stride);
            if (cmd.setStreamSource.streamData) cmd.setStreamSource.streamData->Release();
            break;
        case CMD_SET_INDICES:
            orig_SetIndices(cmd.device, cmd.setIndices.indexData);
            if (cmd.setIndices.indexData) cmd.setIndices.indexData->Release();
            break;
        case CMD_SET_VERTEX_DECLARATION:
            orig_SetVertexDeclaration(cmd.device, cmd.setVertexDecl.decl);
            if (cmd.setVertexDecl.decl) cmd.setVertexDecl.decl->Release();
            break;
        case CMD_SET_VERTEX_SHADER:
            orig_SetVertexShader(cmd.device, cmd.setVertexShader.shader);
            if (cmd.setVertexShader.shader) cmd.setVertexShader.shader->Release();
            break;
        case CMD_SET_PIXEL_SHADER:
            orig_SetPixelShader(cmd.device, cmd.setPixelShader.shader);
            if (cmd.setPixelShader.shader) cmd.setPixelShader.shader->Release();
            break;
        case CMD_DRAW_PRIMITIVE:
            orig_DrawPrimitive(cmd.device, cmd.drawPrimitive.primitiveType, cmd.drawPrimitive.startVertex, cmd.drawPrimitive.primitiveCount);
            break;
        case CMD_DRAW_INDEXED_PRIMITIVE:
            orig_DrawIndexedPrimitive(cmd.device, cmd.drawIndexed.primitiveType, cmd.drawIndexed.baseVertexIndex, cmd.drawIndexed.minVertexIndex, cmd.drawIndexed.numVertices, cmd.drawIndexed.startIndex, cmd.drawIndexed.primCount);
            break;
        case CMD_BEGIN_SCENE:
            orig_BeginScene(cmd.device);
            break;
        case CMD_END_SCENE:
            orig_EndScene(cmd.device);
            break;
        case CMD_CLEAR:
            orig_Clear(cmd.device, cmd.clear.count, (cmd.clear.count > 0 ? &cmd.clear.rect : NULL), cmd.clear.flags, cmd.clear.color, cmd.clear.z, cmd.clear.stencil);
            break;
        case CMD_PRESENT:
            D3D9StateCache::orig_Present(cmd.device, &cmd.present.src, &cmd.present.dest, cmd.present.window, cmd.present.dirty);
            break;
        case CMD_RESET:
            D3D9StateCache::orig_Reset(cmd.device, (D3DPRESENT_PARAMETERS*)&cmd.reset.params);
            break;
    }
}

static DWORD WINAPI RenderThreadProc(LPVOID param) {
    g_renderThreadId = GetCurrentThreadId();
    Log("[D3D9RenderThread] Started asynchronously on thread ID: %d", g_renderThreadId);

    while (!g_renderThreadShutdown.load(std::memory_order_relaxed)) {
        int readIdx = g_readIndex.load(std::memory_order_acquire);
        int writeIdx = g_writeIndex.load(std::memory_order_acquire);

        if (readIdx == writeIdx) {
            YieldProcessor();
            SwitchToThread();
            continue;
        }

        while (readIdx != writeIdx) {
            RenderCommand& cmd = g_commandQueue[readIdx % RING_BUFFER_SIZE];
            ExecuteCommand(cmd);
            readIdx++;
            g_readIndex.store(readIdx, std::memory_order_release);
        }
    }

    Log("[D3D9RenderThread] Exiting");
    return 0;
}



// A "font alpha fast path" used to sit here. It tracked the last TEXTUREFACTOR
// and, whenever the client enabled ALPHABLENDENABLE, turned it back off if that
// factor's alpha was 0xFF or 0x00.
//
// Neither case is a valid equivalence. Disabling the blend is only equivalent
// when the per-pixel source alpha is 1 everywhere, and TEXTUREFACTOR is a stage
// constant: under the usual MODULATE the source alpha is texture alpha times
// factor alpha, so a factor of 0xFF leaves the texture's own alpha in charge. For
// text that texture is almost entirely alpha - the glyph shape lives there - so
// dropping the blend paints the whole quad and turns letters into solid
// rectangles. The 0x00 case has no defence at all: source alpha becomes zero, so
// the draw is invisible with blending and fully opaque without it.
//
// Removed along with the module behind it. The tracked factor went too, having no
// other reader.
void QueueSetRenderState(IDirect3DDevice9* device, D3DRENDERSTATETYPE state, DWORD value) {
    RenderCommand cmd;
    cmd.type = CMD_SET_RENDER_STATE;
    cmd.device = device;
    cmd.setRenderState.state = state;
    cmd.setRenderState.value = value;
    QueueCommand(cmd);
}

void QueueSetTransform(IDirect3DDevice9* device, D3DTRANSFORMSTATETYPE state, const D3DMATRIX* matrix) {
    RenderCommand cmd;
    cmd.type = CMD_SET_TRANSFORM;
    cmd.device = device;
    cmd.setTransform.state = state;
    if (matrix) memcpy(&cmd.setTransform.matrix, matrix, sizeof(D3DMATRIX));
    QueueCommand(cmd);
}

void QueueSetViewport(IDirect3DDevice9* device, const D3DVIEWPORT9* viewport) {
    RenderCommand cmd;
    cmd.type = CMD_SET_VIEWPORT;
    cmd.device = device;
    if (viewport) memcpy(&cmd.setViewport.viewport, viewport, sizeof(D3DVIEWPORT9));
    QueueCommand(cmd);
}

void QueueSetVertexShaderConstantF(IDirect3DDevice9* device, UINT startRegister, const float* constantData, UINT vector4fCount) {
    RenderCommand cmd;
    cmd.type = CMD_SET_VERTEX_SHADER_CONSTANT_F;
    cmd.device = device;
    cmd.setVSConstF.startRegister = startRegister;
    cmd.setVSConstF.vector4fCount = vector4fCount;

    uint32_t count = vector4fCount * 4;
    uint32_t offset = g_constantPoolWriteIdx.fetch_add(count, std::memory_order_relaxed);
    for (uint32_t i = 0; i < count; ++i) {
        g_constantPool[(offset + i) % CONSTANT_POOL_SIZE] = constantData[i];
    }
    cmd.setVSConstF.poolOffset = offset;
    QueueCommand(cmd);
}

void QueueSetSamplerState(IDirect3DDevice9* device, DWORD sampler, D3DSAMPLERSTATETYPE type, DWORD value) {
    RenderCommand cmd;
    cmd.type = CMD_SET_SAMPLER_STATE;
    cmd.device = device;
    cmd.setSamplerState.sampler = sampler;
    cmd.setSamplerState.type = type;
    cmd.setSamplerState.value = value;
    QueueCommand(cmd);
}

void QueueSetTextureStageState(IDirect3DDevice9* device, DWORD stage, D3DTEXTURESTAGESTATETYPE type, DWORD value) {
    RenderCommand cmd;
    cmd.type = CMD_SET_TEXTURE_STAGE_STATE;
    cmd.device = device;
    cmd.setTextureStageState.stage = stage;
    cmd.setTextureStageState.type = type;
    cmd.setTextureStageState.value = value;
    QueueCommand(cmd);
}

void QueueReset(IDirect3DDevice9* device, D3DPRESENT_PARAMETERS* params) {
    PipelineFlush();

    RenderCommand cmd;
    cmd.type = CMD_RESET;
    cmd.device = device;
    if (params) memcpy(&cmd.reset.params, params, sizeof(D3DPRESENT_PARAMETERS));
    QueueCommand(cmd);

    PipelineFlush();
}

void QueuePresent(IDirect3DDevice9* device, const RECT* src, const RECT* dest, HWND window, const RGNDATA* dirty) {
    RenderCommand cmd;
    cmd.type = CMD_PRESENT;
    cmd.device = device;
    if (src) cmd.present.src = *src;
    else memset(&cmd.present.src, 0, sizeof(RECT));
    if (dest) cmd.present.dest = *dest;
    else memset(&cmd.present.dest, 0, sizeof(RECT));
    cmd.present.window = window;
    cmd.present.dirty = (RGNDATA*)dirty;
    QueueCommand(cmd);
}

static HRESULT WINAPI Hooked_DrawPrimitive(IDirect3DDevice9* device, D3DPRIMITIVETYPE PrimitiveType, UINT StartVertex, UINT PrimitiveCount) {
    if (g_isActive.load(std::memory_order_relaxed) && GetCurrentThreadId() == g_mainThreadId) {
        RenderCommand cmd;
        cmd.type = CMD_DRAW_PRIMITIVE;
        cmd.device = device;
        cmd.drawPrimitive.primitiveType = PrimitiveType;
        cmd.drawPrimitive.startVertex = StartVertex;
        cmd.drawPrimitive.primitiveCount = PrimitiveCount;
        QueueCommand(cmd);
        return D3D_OK;
    }
    return orig_DrawPrimitive(device, PrimitiveType, StartVertex, PrimitiveCount);
}

static HRESULT WINAPI Hooked_DrawIndexedPrimitive(IDirect3DDevice9* device, D3DPRIMITIVETYPE PrimitiveType, INT BaseVertexIndex, UINT MinVertexIndex, UINT NumVertices, UINT StartIndex, UINT primCount) {
    if (g_isActive.load(std::memory_order_relaxed) && GetCurrentThreadId() == g_mainThreadId) {
        RenderCommand cmd;
        cmd.type = CMD_DRAW_INDEXED_PRIMITIVE;
        cmd.device = device;
        cmd.drawIndexed.primitiveType = PrimitiveType;
        cmd.drawIndexed.baseVertexIndex = BaseVertexIndex;
        cmd.drawIndexed.minVertexIndex = MinVertexIndex;
        cmd.drawIndexed.numVertices = NumVertices;
        cmd.drawIndexed.startIndex = StartIndex;
        cmd.drawIndexed.primCount = primCount;
        QueueCommand(cmd);
        return D3D_OK;
    }
    return orig_DrawIndexedPrimitive(device, PrimitiveType, BaseVertexIndex, MinVertexIndex, NumVertices, StartIndex, primCount);
}

static HRESULT WINAPI Hooked_SetTexture(IDirect3DDevice9* device, DWORD Stage, IDirect3DBaseTexture9* pTexture) {
    if (g_isActive.load(std::memory_order_relaxed) && GetCurrentThreadId() == g_mainThreadId) {
        if (pTexture) pTexture->AddRef();
        RenderCommand cmd;
        cmd.type = CMD_SET_TEXTURE;
        cmd.device = device;
        cmd.setTexture.stage = Stage;
        cmd.setTexture.texture = pTexture;
        QueueCommand(cmd);
        return D3D_OK;
    }
    return orig_SetTexture(device, Stage, pTexture);
}

static HRESULT WINAPI Hooked_SetStreamSource(IDirect3DDevice9* device, UINT StreamNumber, IDirect3DVertexBuffer9* pStreamData, UINT OffsetInBytes, UINT Stride) {
    if (g_isActive.load(std::memory_order_relaxed) && GetCurrentThreadId() == g_mainThreadId) {
        if (pStreamData) pStreamData->AddRef();
        RenderCommand cmd;
        cmd.type = CMD_SET_STREAM_SOURCE;
        cmd.device = device;
        cmd.setStreamSource.streamNumber = StreamNumber;
        cmd.setStreamSource.streamData = pStreamData;
        cmd.setStreamSource.offsetInBytes = OffsetInBytes;
        cmd.setStreamSource.stride = Stride;
        QueueCommand(cmd);
        return D3D_OK;
    }
    return orig_SetStreamSource(device, StreamNumber, pStreamData, OffsetInBytes, Stride);
}

static HRESULT WINAPI Hooked_SetIndices(IDirect3DDevice9* device, IDirect3DIndexBuffer9* pIndexData) {
    if (g_isActive.load(std::memory_order_relaxed) && GetCurrentThreadId() == g_mainThreadId) {
        if (pIndexData) pIndexData->AddRef();
        RenderCommand cmd;
        cmd.type = CMD_SET_INDICES;
        cmd.device = device;
        cmd.setIndices.indexData = pIndexData;
        QueueCommand(cmd);
        return D3D_OK;
    }
    return orig_SetIndices(device, pIndexData);
}

static HRESULT WINAPI Hooked_SetVertexDeclaration(IDirect3DDevice9* device, IDirect3DVertexDeclaration9* pDecl) {
    if (g_isActive.load(std::memory_order_relaxed) && GetCurrentThreadId() == g_mainThreadId) {
        if (pDecl) pDecl->AddRef();
        RenderCommand cmd;
        cmd.type = CMD_SET_VERTEX_DECLARATION;
        cmd.device = device;
        cmd.setVertexDecl.decl = pDecl;
        QueueCommand(cmd);
        return D3D_OK;
    }
    return orig_SetVertexDeclaration(device, pDecl);
}

static HRESULT WINAPI Hooked_SetVertexShader(IDirect3DDevice9* device, IDirect3DVertexShader9* pShader) {
    if (g_isActive.load(std::memory_order_relaxed) && GetCurrentThreadId() == g_mainThreadId) {
        if (pShader) pShader->AddRef();
        RenderCommand cmd;
        cmd.type = CMD_SET_VERTEX_SHADER;
        cmd.device = device;
        cmd.setVertexShader.shader = pShader;
        QueueCommand(cmd);
        return D3D_OK;
    }
    return orig_SetVertexShader(device, pShader);
}

static HRESULT WINAPI Hooked_SetPixelShader(IDirect3DDevice9* device, IDirect3DPixelShader9* pShader) {
    if (g_isActive.load(std::memory_order_relaxed) && GetCurrentThreadId() == g_mainThreadId) {
        if (pShader) pShader->AddRef();
        RenderCommand cmd;
        cmd.type = CMD_SET_PIXEL_SHADER;
        cmd.device = device;
        cmd.setPixelShader.shader = pShader;
        QueueCommand(cmd);
        return D3D_OK;
    }
    return orig_SetPixelShader(device, pShader);
}

static HRESULT WINAPI Hooked_BeginScene(IDirect3DDevice9* device) {
    if (g_isActive.load(std::memory_order_relaxed) && GetCurrentThreadId() == g_mainThreadId) {
        RenderCommand cmd;
        cmd.type = CMD_BEGIN_SCENE;
        cmd.device = device;
        QueueCommand(cmd);
        return D3D_OK;
    }
    return orig_BeginScene(device);
}

static HRESULT WINAPI Hooked_EndScene(IDirect3DDevice9* device) {
    if (g_isActive.load(std::memory_order_relaxed) && GetCurrentThreadId() == g_mainThreadId) {
        RenderCommand cmd;
        cmd.type = CMD_END_SCENE;
        cmd.device = device;
        QueueCommand(cmd);
        return D3D_OK;
    }
    return orig_EndScene(device);
}

static HRESULT WINAPI Hooked_Clear(IDirect3DDevice9* device, DWORD Count, const D3DRECT* pRects, DWORD Flags, D3DCOLOR Color, float Z, DWORD Stencil) {
    if (g_isActive.load(std::memory_order_relaxed) && GetCurrentThreadId() == g_mainThreadId) {
        RenderCommand cmd;
        cmd.type = CMD_CLEAR;
        cmd.device = device;
        cmd.clear.count = Count > 0 ? 1 : 0;
        if (Count > 0 && pRects) {
            cmd.clear.rect = *pRects;
        } else {
            memset(&cmd.clear.rect, 0, sizeof(D3DRECT));
        }
        cmd.clear.flags = Flags;
        cmd.clear.color = Color;
        cmd.clear.z = Z;
        cmd.clear.stencil = Stencil;
        QueueCommand(cmd);
        return D3D_OK;
    }
    return orig_Clear(device, Count, pRects, Flags, Color, Z, Stencil);
}

bool Init() {
    if (!g_commandQueue) {
        g_commandQueue = (RenderCommand*)VirtualAlloc(
            nullptr, sizeof(RenderCommand) * RING_BUFFER_SIZE,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!g_constantPool) {
        g_constantPool = (float*)VirtualAlloc(
            nullptr, sizeof(float) * (size_t)CONSTANT_POOL_SIZE,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!g_commandQueue || !g_constantPool) {
        Log("[D3D9RenderThread] Could not commit the command queue and constant "
            "pool - disabled");
        return false;
    }
    if (!Config::g_settings.OptD3d9RenderThread) {
        Log("[D3D9RenderThread] DISABLED via configuration");
        return true;
    }

    g_renderThreadShutdown = false;
    g_renderThread = CreateThread(NULL, 0, RenderThreadProc, NULL, 0, NULL);
    if (!g_renderThread) {
        Log("[D3D9RenderThread] Failed to create background render thread!");
        return false;
    }
    SetThreadPriority(g_renderThread, THREAD_PRIORITY_HIGHEST);

    g_isActive = true;
    Log("[D3D9RenderThread] Worker thread started (waiting for device hooks)");
    return true;
}


void OnCreateDevice(IDirect3DDevice9* device) {
    g_isActive = false;
    static bool loggedBypass = false;
    if (!loggedBypass) {
        Log("[D3D9RenderThread] Bypass: hooks disabled to maintain rendering integrity and prevent state desynchronization.");
        loggedBypass = true;
    }
}


void Shutdown() {
    if (!g_isActive.load(std::memory_order_relaxed)) return;

    g_renderThreadShutdown = true;
    if (g_renderThread) {
        WaitForSingleObject(g_renderThread, 2000);
        CloseHandle(g_renderThread);
        g_renderThread = NULL;
    }

    g_isActive = false;
    Log("[D3D9RenderThread] Shutdown completed");
}

void OnFrame() {
}

} // namespace D3D9RenderThread
