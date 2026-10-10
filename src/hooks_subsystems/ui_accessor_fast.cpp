#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"
#include "lua_optimize.h"
#include "ui_accessor_fast.h"
#include "crash_dumper.h"

extern "C" void Log(const char* fmt, ...);

#define TAINT_CELL ( *(uint32_t**)0x00D4139C )

static bool g_inLuaShutdown = false;

static inline bool IsTeardownState() {
    if (g_inLuaShutdown) return true;
    uintptr_t gL = *(uintptr_t*)0x00D3F78C;
    return (gL < 0x10000 || gL > 0xFFE00000);
}

static __forceinline bool IsValidPtr(uintptr_t p) {
    return p > 0x10000 && p < 0xFFE00000;
}

static __forceinline bool IsWowCodePtr(uintptr_t p) {
    return p >= 0x00401000 && p < 0x009DF000;
}

static __forceinline bool IsWowDataPtr(uintptr_t p) {
    return p >= 0x009DF000 && p < 0x00DD1000;
}

static __forceinline uintptr_t ResolveTValue(uintptr_t L, int idx, bool* deferToOrig) {
    *deferToOrig = false;
    if (idx > 0) {
        uintptr_t base = *(uintptr_t*)(L + 0x10);
        if (!IsValidPtr(base)) return 0;
        uintptr_t tv = base + (uintptr_t)(idx - 1) * 16;
        uintptr_t top = *(uintptr_t*)(L + 0x0C);
        if (tv >= top) return 0;
        return tv;
    }
    if (idx < 0 && idx > -10000) {
        uintptr_t top = *(uintptr_t*)(L + 0x0C);
        if (!IsValidPtr(top)) return 0;
        uintptr_t tv = top + (uintptr_t)idx * 16;
        uintptr_t base = *(uintptr_t*)(L + 0x10);
        if (tv < base) return 0;
        return tv;
    }
    *deferToOrig = true;
    return 0;
}

static __forceinline void* GetCFrameFromLuaTable(uintptr_t L, int idx) {
    bool defer = false;
    uintptr_t tv = ResolveTValue(L, idx, &defer);
    if (defer || !tv) return nullptr;

    if (*(int*)(tv + 8) != 5) return nullptr; // LUA_TTABLE
    uintptr_t t = *(uintptr_t*)(tv + 0);
    if (!IsValidPtr(t)) return nullptr;

    uintptr_t nodes = *(uintptr_t*)(t + 0x14); // t->node
    if (!IsValidPtr(nodes)) return nullptr;

    int size = 1 << *(unsigned char*)(t + 11); // 1 << t->lsizes
    for (int i = 0; i < size; i++) {
        uintptr_t node = nodes + i * 40; // sizeof(Node) is 40
        int key_tt = *(int*)(node + 24); // TKey.tt
        if (key_tt == 3) { // LUA_TNUMBER
            double key_val = *(double*)(node + 16); // TKey.value
            if (key_val == 0.0) {
                int val_tt = *(int*)(node + 8); // TValue.tt
                if (val_tt == 7) { // LUA_TUSERDATA
                    uintptr_t udata = *(uintptr_t*)(node + 0); // TValue.value
                    if (IsValidPtr(udata)) {
                        return (void*)(udata + 24);
                    }
                }
                break;
            }
        }
    }
    return nullptr;
}

// Stats
static volatile long g_isshown_calls = 0;
static volatile long g_isvisible_calls = 0;
static volatile long g_getalpha_calls = 0;
static volatile long g_getscale_calls = 0;
static volatile long g_getwidth_calls = 0;
static volatile long g_getheight_calls = 0;
static volatile long g_frame_isshown_calls = 0;
static volatile long g_frame_isvisible_calls = 0;
static volatile long g_frame_getalpha_calls = 0;
static volatile long g_frame_getframelevel_calls = 0;

// Type checking helper
static __forceinline bool ValidateObjectType(void* obj, int typeId) {
    uintptr_t pObj = (uintptr_t)obj;
    if (pObj < 0x10000 || pObj > 0xFFE00000) return false;

    uintptr_t vtable = *(uintptr_t*)obj;
    if (!IsWowDataPtr(vtable)) return false;

    uintptr_t is_type_fn = *(uintptr_t*)(vtable + 16);
    if (!IsWowCodePtr(is_type_fn)) return false;

    return ((bool (__thiscall*)(void*, int))is_type_fn)(obj, typeId);
}

// 1. IsShown — 0x0048C610
typedef int (__cdecl* IsShown_t)(uintptr_t L);
static IsShown_t orig_IsShown = nullptr;

static int __cdecl hook_IsShown(uintptr_t L) {
    CrashDumper::RecordHookCallHot("UIAccessor_IsShown", (uintptr_t)L);
    if (IsTeardownState() || LuaOpt::IsReloading() || LuaOpt::IsSwapping() || LuaOpt::IsLoadingMode()) 
        return orig_IsShown(L);

    ++g_isshown_calls;
    __try {
        int typeId = *(int*)0x00B4793C;
        if (typeId != 0) {
            void* obj = GetCFrameFromLuaTable(L, 1);
            if (obj && ValidateObjectType(obj, typeId)) {
                bool isShown = (*(uint8_t*)((uintptr_t)obj + 204) & 0x10) != 0;
                if (isShown) {
                    ((void (__cdecl*)(uintptr_t, double))0x0084E2A0)(L, 1.0);
                } else {
                    ((void (__cdecl*)(uintptr_t))0x0084E280)(L);
                }
                return 1;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return orig_IsShown(L);
}

// 2. IsVisible — 0x0048C5B0
typedef int (__cdecl* IsVisible_t)(uintptr_t L);
static IsVisible_t orig_IsVisible = nullptr;

static int __cdecl hook_IsVisible(uintptr_t L) {
    CrashDumper::RecordHookCallHot("UIAccessor_IsVisible", (uintptr_t)L);
    if (IsTeardownState() || LuaOpt::IsReloading() || LuaOpt::IsSwapping() || LuaOpt::IsLoadingMode()) 
        return orig_IsVisible(L);

    ++g_isvisible_calls;
    __try {
        int typeId = *(int*)0x00B4793C;
        if (typeId != 0) {
            void* obj = GetCFrameFromLuaTable(L, 1);
            if (obj && ValidateObjectType(obj, typeId)) {
                bool isVisible = (*(uint8_t*)((uintptr_t)obj + 204) & 0x20) != 0;
                if (isVisible) {
                    ((void (__cdecl*)(uintptr_t, double))0x0084E2A0)(L, 1.0);
                } else {
                    ((void (__cdecl*)(uintptr_t))0x0084E280)(L);
                }
                return 1;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return orig_IsVisible(L);
}

// 3. GetAlpha — 0x0048C4C0
typedef int (__cdecl* GetAlpha_t)(uintptr_t L);
static GetAlpha_t orig_GetAlpha = nullptr;

static int __cdecl hook_GetAlpha(uintptr_t L) {
    CrashDumper::RecordHookCallHot("UIAccessor_GetAlpha", (uintptr_t)L);
    if (IsTeardownState() || LuaOpt::IsReloading() || LuaOpt::IsSwapping() || LuaOpt::IsLoadingMode()) 
        return orig_GetAlpha(L);

    ++g_getalpha_calls;
    __try {
        int typeId = *(int*)0x00B4793C;
        if (typeId != 0) {
            void* obj = GetCFrameFromLuaTable(L, 1);
            if (obj && ValidateObjectType(obj, typeId)) {
                uint8_t alpha_byte = 255;
                if (*(int*)((uintptr_t)obj + 168) == 1) {
                    alpha_byte = *(uint8_t*)((uintptr_t)obj + 164);
                }
                double alpha_val = (double)alpha_byte * 0.00392156862745098;
                ((void (__cdecl*)(uintptr_t, double))0x0084E2A0)(L, alpha_val);
                return 1;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return orig_GetAlpha(L);
}

// 4. GetScale — 0x0049F7D0
typedef int (__cdecl* GetScale_t)(uintptr_t L);
static GetScale_t orig_GetScale = nullptr;

static int __cdecl hook_GetScale(uintptr_t L) {
    CrashDumper::RecordHookCallHot("UIAccessor_GetScale", (uintptr_t)L);
    if (IsTeardownState() || LuaOpt::IsReloading() || LuaOpt::IsSwapping() || LuaOpt::IsLoadingMode()) 
        return orig_GetScale(L);

    ++g_getscale_calls;
    __try {
        int typeId = *(int*)0x00B49984; // Note different typeId global address
        if (typeId != 0) {
            void* obj = GetCFrameFromLuaTable(L, 1);
            if (obj && ValidateObjectType(obj, typeId)) {
                float scale = *(float*)((uintptr_t)obj + 184);
                ((void (__cdecl*)(uintptr_t, double))0x0084E2A0)(L, (double)scale);
                return 1;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return orig_GetScale(L);
}

// 5. GetWidth — 0x0049D3B0
typedef int (__cdecl* GetWidth_t)(uintptr_t L);
static GetWidth_t orig_GetWidth = nullptr;

static int __cdecl c_hook_GetWidth(uintptr_t L) {
    if (IsTeardownState() || LuaOpt::IsReloading() || LuaOpt::IsSwapping() || LuaOpt::IsLoadingMode()) 
        return -1;

    ++g_getwidth_calls;
    __try {
        uintptr_t base = *(uintptr_t*)(L + 0x10);
        uintptr_t top = *(uintptr_t*)(L + 0x0C);
        if (IsValidPtr(base) && IsValidPtr(top)) {
            int nargs = (top - base) / 16;
            if (nargs < 2) {
                int typeId = *(int*)0x00B49978;
                if (typeId != 0) {
                    void* obj = GetCFrameFromLuaTable(L, 1);
                    if (obj && ValidateObjectType(obj, typeId)) {
                        void* layoutFrame = (void*)((uintptr_t)obj + 32);
                        uintptr_t vtable = *(uintptr_t*)layoutFrame;
                        if (IsValidPtr(vtable)) {
                            typedef double (__thiscall* LayoutFrame_GetWidth_t)(void*);
                            LayoutFrame_GetWidth_t getWidthFn = *(LayoutFrame_GetWidth_t*)(vtable + 40);
                            if (IsValidPtr((uintptr_t)getWidthFn)) {
                                double w = getWidthFn(layoutFrame);
                                if (w != 0.0) {
                                    typedef double (*sub_47BFE0_t)();
                                    typedef double (*sub_47C050_t)(float);
                                    double scale = ((sub_47BFE0_t)0x0047BFE0)();
                                    double v7 = scale * 1024.0 * w;
                                    double final_w = ((sub_47C050_t)0x0047C050)((float)v7);

                                    typedef int (__cdecl* lua_pushnumber_t)(uintptr_t, double);
                                    ((lua_pushnumber_t)0x0084E2A0)(L, final_w);
                                    return 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return -1;
}

static __declspec(naked) void naked_hook_GetWidth() {
    __asm {
        push esi
        push edi
        push ebx
        
        mov eax, [esp + 16] // L (4 bytes return address + 12 bytes pushed registers)
        push eax
        call c_hook_GetWidth
        add esp, 4
        
        cmp eax, 0
        jl fallback
        
        pop ebx
        pop edi
        pop esi
        ret
        
    fallback:
        pop ebx
        pop edi
        pop esi
        jmp orig_GetWidth
    }
}

// 6. GetHeight — 0x0049D550
typedef int (__cdecl* GetHeight_t)(uintptr_t L);
static GetHeight_t orig_GetHeight = nullptr;

static int __cdecl c_hook_GetHeight(uintptr_t L) {
    if (IsTeardownState() || LuaOpt::IsReloading() || LuaOpt::IsSwapping() || LuaOpt::IsLoadingMode()) 
        return -1;

    ++g_getheight_calls;
    __try {
        uintptr_t base = *(uintptr_t*)(L + 0x10);
        uintptr_t top = *(uintptr_t*)(L + 0x0C);
        if (IsValidPtr(base) && IsValidPtr(top)) {
            int nargs = (top - base) / 16;
            if (nargs < 2) {
                int typeId = *(int*)0x00B49978;
                if (typeId != 0) {
                    void* obj = GetCFrameFromLuaTable(L, 1);
                    if (obj && ValidateObjectType(obj, typeId)) {
                        void* layoutFrame = (void*)((uintptr_t)obj + 32);
                        uintptr_t vtable = *(uintptr_t*)layoutFrame;
                        if (IsValidPtr(vtable)) {
                            typedef double (__thiscall* LayoutFrame_GetHeight_t)(void*);
                            LayoutFrame_GetHeight_t getHeightFn = *(LayoutFrame_GetHeight_t*)(vtable + 44);
                            if (IsValidPtr((uintptr_t)getHeightFn)) {
                                double h = getHeightFn(layoutFrame);
                                if (h != 0.0) {
                                    typedef double (*sub_47BFE0_t)();
                                    typedef double (*sub_47C050_t)(float);
                                    double scale = ((sub_47BFE0_t)0x0047BFE0)();
                                    double v7 = scale * 1024.0 * h;
                                    double final_h = ((sub_47C050_t)0x0047C050)((float)v7);

                                    typedef int (__cdecl* lua_pushnumber_t)(uintptr_t, double);
                                    ((lua_pushnumber_t)0x0084E2A0)(L, final_h);
                                    return 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return -1;
}

static __declspec(naked) void naked_hook_GetHeight() {
    __asm {
        push esi
        push edi
        push ebx
        
        mov eax, [esp + 16] // L
        push eax
        call c_hook_GetHeight
        add esp, 4
        
        cmp eax, 0
        jl fallback
        
        pop ebx
        pop edi
        pop esi
        ret
        
    fallback:
        pop ebx
        pop edi
        pop esi
        jmp orig_GetHeight
    }
}

// 7. Frame_IsShown — 0x0049FE90
typedef int (__cdecl* Frame_IsShown_t)(uintptr_t L);
static Frame_IsShown_t orig_Frame_IsShown = nullptr;

static int __cdecl hook_Frame_IsShown(uintptr_t L) {
    CrashDumper::RecordHookCallHot("UIAccessor_FrameIsShown", (uintptr_t)L);
    if (IsTeardownState() || LuaOpt::IsReloading() || LuaOpt::IsSwapping() || LuaOpt::IsLoadingMode()) 
        return orig_Frame_IsShown(L);

    ++g_frame_isshown_calls;
    __try {
        int typeId = *(int*)0x00B49984;
        if (typeId != 0) {
            void* obj = GetCFrameFromLuaTable(L, 1);
            if (obj && ValidateObjectType(obj, typeId)) {
                bool isShown = *(int*)((uintptr_t)obj + 220) != 0;
                if (isShown) {
                    ((void (__cdecl*)(uintptr_t, double))0x0084E2A0)(L, 1.0);
                } else {
                    ((void (__cdecl*)(uintptr_t))0x0084E280)(L);
                }
                return 1;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return orig_Frame_IsShown(L);
}

// 8. Frame_IsVisible — 0x0049FE30
typedef int (__cdecl* Frame_IsVisible_t)(uintptr_t L);
static Frame_IsVisible_t orig_Frame_IsVisible = nullptr;

static int __cdecl hook_Frame_IsVisible(uintptr_t L) {
    CrashDumper::RecordHookCallHot("UIAccessor_FrameIsVisible", (uintptr_t)L);
    if (IsTeardownState() || LuaOpt::IsReloading() || LuaOpt::IsSwapping() || LuaOpt::IsLoadingMode()) 
        return orig_Frame_IsVisible(L);

    ++g_frame_isvisible_calls;
    __try {
        int typeId = *(int*)0x00B49984;
        if (typeId != 0) {
            void* obj = GetCFrameFromLuaTable(L, 1);
            if (obj && ValidateObjectType(obj, typeId)) {
                bool isVisible = *(int*)((uintptr_t)obj + 224) != 0;
                if (isVisible) {
                    ((void (__cdecl*)(uintptr_t, double))0x0084E2A0)(L, 1.0);
                } else {
                    ((void (__cdecl*)(uintptr_t))0x0084E280)(L);
                }
                return 1;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return orig_Frame_IsVisible(L);
}

// 9. Frame_GetAlpha — 0x0049F980
typedef int (__cdecl* Frame_GetAlpha_t)(uintptr_t L);
static Frame_GetAlpha_t orig_Frame_GetAlpha = nullptr;

static int __cdecl hook_Frame_GetAlpha(uintptr_t L) {
    CrashDumper::RecordHookCallHot("UIAccessor_FrameGetAlpha", (uintptr_t)L);
    if (IsTeardownState() || LuaOpt::IsReloading() || LuaOpt::IsSwapping() || LuaOpt::IsLoadingMode()) 
        return orig_Frame_GetAlpha(L);

    ++g_frame_getalpha_calls;
    __try {
        int typeId = *(int*)0x00B49984;
        if (typeId != 0) {
            void* obj = GetCFrameFromLuaTable(L, 1);
            if (obj && ValidateObjectType(obj, typeId)) {
                double alpha_val = (double)*(unsigned __int8 *)((uintptr_t)obj + 188) * 0.00392156862745098;
                ((void (__cdecl*)(uintptr_t, double))0x0084E2A0)(L, alpha_val);
                return 1;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return orig_Frame_GetAlpha(L);
}

// 10. Frame_GetFrameLevel — 0x0049E980
typedef int (__cdecl* Frame_GetFrameLevel_t)(uintptr_t L);
static Frame_GetFrameLevel_t orig_Frame_GetFrameLevel = nullptr;

static int __cdecl hook_Frame_GetFrameLevel(uintptr_t L) {
    CrashDumper::RecordHookCallHot("UIAccessor_FrameGetLevel", (uintptr_t)L);
    if (IsTeardownState() || LuaOpt::IsReloading() || LuaOpt::IsSwapping() || LuaOpt::IsLoadingMode()) 
        return orig_Frame_GetFrameLevel(L);

    ++g_frame_getframelevel_calls;
    __try {
        int typeId = *(int*)0x00B49984;
        if (typeId != 0) {
            void* obj = GetCFrameFromLuaTable(L, 1);
            if (obj && ValidateObjectType(obj, typeId)) {
                double level = (double)*(int*)((uintptr_t)obj + 212);
                ((void (__cdecl*)(uintptr_t, double))0x0084E2A0)(L, level);
                return 1;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    return orig_Frame_GetFrameLevel(L);
}

// FrameScript Initialization/Shutdown Hooks for Safe Teardown State Detection
typedef void* (__cdecl* FrameScript_Shutdown_t)();
static FrameScript_Shutdown_t orig_FrameScript_Shutdown = nullptr;

static void* __cdecl hook_FrameScript_Shutdown() {
    g_inLuaShutdown = true;
    void* res = orig_FrameScript_Shutdown();
    return res;
}

typedef int (__cdecl* FrameScript_Initialize_t)(int a1);
static FrameScript_Initialize_t orig_FrameScript_Initialize = nullptr;

static int __cdecl hook_FrameScript_Initialize(int a1) {
    g_inLuaShutdown = false;
    int res = orig_FrameScript_Initialize(a1);
    return res;
}

// The openings of the functions this module replaces, from build 12340. Each replacement reads the
// frame object at that build's offsets and type ids, so an address that holds anything else is left alone.
struct KnownOpening { uintptr_t addr; unsigned char bytes[12]; };
static const KnownOpening kKnownOpenings[] = {
    { 0x0048C610, { 0x55, 0x8B, 0xEC, 0xA1, 0x3C, 0x79, 0xB4, 0x00, 0x85, 0xC0, 0x75, 0x12 } },
    { 0x0048C5B0, { 0x55, 0x8B, 0xEC, 0xA1, 0x3C, 0x79, 0xB4, 0x00, 0x85, 0xC0, 0x75, 0x12 } },
    { 0x0048C4C0, { 0x55, 0x8B, 0xEC, 0xA1, 0x3C, 0x79, 0xB4, 0x00, 0x83, 0xEC, 0x08, 0x85 } },
    { 0x0049F7D0, { 0x55, 0x8B, 0xEC, 0xA1, 0x84, 0x99, 0xB4, 0x00, 0x85, 0xC0, 0x75, 0x12 } },
    { 0x0049FE90, { 0x55, 0x8B, 0xEC, 0xA1, 0x84, 0x99, 0xB4, 0x00, 0x85, 0xC0, 0x75, 0x12 } },
    { 0x0049FE30, { 0x55, 0x8B, 0xEC, 0xA1, 0x84, 0x99, 0xB4, 0x00, 0x85, 0xC0, 0x75, 0x12 } },
    { 0x0049F980, { 0x55, 0x8B, 0xEC, 0x51, 0xA1, 0x84, 0x99, 0xB4, 0x00, 0x85, 0xC0, 0x75 } },
    { 0x0049E980, { 0x55, 0x8B, 0xEC, 0xA1, 0x84, 0x99, 0xB4, 0x00, 0x85, 0xC0, 0x75, 0x12 } },
    { 0x0049D3B0, { 0x55, 0x8B, 0xEC, 0xA1, 0x78, 0x99, 0xB4, 0x00, 0x83, 0xEC, 0x14, 0x85 } },
    { 0x0049D550, { 0x55, 0x8B, 0xEC, 0xA1, 0x78, 0x99, 0xB4, 0x00, 0x83, 0xEC, 0x14, 0x85 } },
    { 0x0081A9A0, { 0xA1, 0x8C, 0xF7, 0xD3, 0x00, 0x56, 0x50, 0xE8, 0x64, 0xAB, 0x03, 0x00 } },
    { 0x00819BB0, { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x56, 0xE8, 0x84, 0xBB, 0x03, 0x00 } },
};

static bool UiOpeningMatches(uintptr_t addr) {
    for (const KnownOpening& k : kKnownOpenings)
        if (k.addr == addr) return WowOpt_ClientBytesAre(addr, k.bytes, sizeof(k.bytes));
    return false;
}

// Install / Shutdown
bool InstallUIAccessorFast() {
    int installed = 0;
    
#define INSTALL(fn_t, orig_ptr, hook_ptr, addr, name) \
    if (!UiOpeningMatches((uintptr_t)(addr))) { \
        Log("[UIAccessorFast] " name " NOT hooked: the bytes at 0x%08X are not build 12340's", (DWORD)(addr)); \
    } else if (WineSafe_CreateHook((void*)(addr), (void*)(hook_ptr), (void**)&(orig_ptr)) == MH_OK) { \
        if (WO_EnableHook((void*)(addr)) == MH_OK) { \
            installed++; \
            Log("[UIAccessorFast] Hooked " name " at 0x%08X", (DWORD)(addr)); \
        } else { \
            Log("[UIAccessorFast] Enable " name " FAILED"); \
        } \
    } else { \
        Log("[UIAccessorFast] Create " name " FAILED"); \
    }
#define INSTALL_GATED(fn_t, orig_ptr, hook_ptr, addr, name, flag) \
    do { \
        if (!(flag)) { \
            INSTALL(fn_t, orig_ptr, hook_ptr, addr, name) \
        } else { \
            Log("[UIAccessorFast] " name " DISABLED by flag (0x%08X)", (DWORD)(flag)); \
        } \
    } while(0)

    INSTALL_GATED(IsShown_t,    orig_IsShown,    hook_IsShown,    0x0048C610, "IsShown",    TEST_DISABLE_UI_ACCESSOR_FAST);
    INSTALL_GATED(IsVisible_t,  orig_IsVisible,  hook_IsVisible,  0x0048C5B0, "IsVisible",  TEST_DISABLE_UI_ACCESSOR_FAST);
    INSTALL_GATED(GetAlpha_t,   orig_GetAlpha,   hook_GetAlpha,   0x0048C4C0, "GetAlpha",   TEST_DISABLE_UI_ACCESSOR_FAST);
    INSTALL_GATED(GetScale_t,   orig_GetScale,   hook_GetScale,   0x0049F7D0, "GetScale",   TEST_DISABLE_UI_ACCESSOR_FAST);

    // NEW Frame XML accessor hooks (disassembly-verified __cdecl, gated)
    INSTALL_GATED(Frame_IsShown_t,      orig_Frame_IsShown,      hook_Frame_IsShown,      0x0049FE90, "Frame_IsShown",      TEST_DISABLE_FRAME_ACCESSOR_FAST);
    INSTALL_GATED(Frame_IsVisible_t,    orig_Frame_IsVisible,    hook_Frame_IsVisible,    0x0049FE30, "Frame_IsVisible",    TEST_DISABLE_FRAME_ACCESSOR_FAST);
    INSTALL_GATED(Frame_GetAlpha_t,     orig_Frame_GetAlpha,     hook_Frame_GetAlpha,     0x0049F980, "Frame_GetAlpha",     TEST_DISABLE_FRAME_ACCESSOR_FAST);
    INSTALL_GATED(Frame_GetFrameLevel_t,orig_Frame_GetFrameLevel,hook_Frame_GetFrameLevel, 0x0049E980, "Frame_GetFrameLevel",TEST_DISABLE_FRAME_ACCESSOR_FAST);

    // Layout accessor hooks (disassembly-verified __usercall)
    INSTALL_GATED(GetWidth_t,  orig_GetWidth,  naked_hook_GetWidth,  0x0049D3B0, "GetWidth",  TEST_DISABLE_LAYOUT_ACCESSOR_FAST);
    INSTALL_GATED(GetHeight_t, orig_GetHeight, naked_hook_GetHeight, 0x0049D550, "GetHeight", TEST_DISABLE_LAYOUT_ACCESSOR_FAST);
    INSTALL(FrameScript_Shutdown_t, orig_FrameScript_Shutdown, hook_FrameScript_Shutdown, 0x0081A9A0, "FrameScript_Shutdown");
    INSTALL(FrameScript_Initialize_t, orig_FrameScript_Initialize, hook_FrameScript_Initialize, 0x00819BB0, "FrameScript_Initialize");

#undef INSTALL_GATED
#undef INSTALL

    Log("[UIAccessorFast] %d/12 hooks installed", installed);
    return installed > 0;
}

void ShutdownUIAccessorFast() {
    MH_DisableHook((void*)0x0048C610);
    MH_DisableHook((void*)0x0048C5B0);
    MH_DisableHook((void*)0x0048C4C0);
    MH_DisableHook((void*)0x0049F7D0);
    MH_DisableHook((void*)0x0049D3B0);
    MH_DisableHook((void*)0x0049D550);
    MH_DisableHook((void*)0x0049FE90);
    MH_DisableHook((void*)0x0049FE30);
    MH_DisableHook((void*)0x0049F980);
    MH_DisableHook((void*)0x0049E980);
    MH_DisableHook((void*)0x0081A9A0);
    MH_DisableHook((void*)0x00819BB0);
    Log("[UIAccessorFast] Stats: IsShown=%ld IsVisible=%ld GetAlpha=%ld GetScale=%ld GetWidth=%ld GetHeight=%ld FrameIsShown=%ld FrameIsVisible=%ld FrameGetAlpha=%ld FrameGetFrameLevel=%ld",
        g_isshown_calls, g_isvisible_calls, g_getalpha_calls, g_getscale_calls,
        g_getwidth_calls, g_getheight_calls, g_frame_isshown_calls, g_frame_isvisible_calls, g_frame_getalpha_calls, g_frame_getframelevel_calls);
}

