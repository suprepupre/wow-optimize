// ============================================================================
// Module: dxvk_bridge.cpp
// ============================================================================

#include "dxvk_bridge.h"
#include "version.h"
#include <psapi.h>
#include <cstring>
#include <cstdio>

extern "C" void Log(const char* fmt, ...);

namespace DXVKBridge {

static volatile LONG g_active = 0;
static const char*   g_reason = "not detected";

static const char* CheckLoadedModules() {
    HMODULE mods[1024];
    DWORD needed = 0;
    HANDLE proc = GetCurrentProcess();
    if (!EnumProcessModules(proc, mods, sizeof(mods), &needed)) return nullptr;
    DWORD count = needed / sizeof(HMODULE);
    if (count > 1024) count = 1024;

    static const char* signals[] = {
        "dxvk_d3d9.dll", "dxvk-d3d9.dll", "dxvk.dll",
        "vulkan-1.dll", "winevulkan.dll", "vk9.dll",
        "d8vk.dll", "d9vk.dll", "dxvk_native.dll", nullptr
    };

    char name[MAX_PATH];
    for (DWORD i = 0; i < count; i++) {
        if (!GetModuleBaseNameA(proc, mods[i], name, sizeof(name))) continue;
        for (char* p = name; *p; ++p) if (*p >= 'A' && *p <= 'Z') *p += 32;
        for (int s = 0; signals[s]; s++) {
            if (strcmp(name, signals[s]) == 0) {
                static char buf[64];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE, "module: %s", signals[s]);
                return buf;
            }
        }
    }
    return nullptr;
}

// Why this check said no.
//
// It has five ways to return nullptr and they mean different things. Four are
// "I could not look" and one is "I looked and it is not DXVK". The renderer line
// in the periodic report printed "native Direct3D 9" for all five, which is a
// claim about the machine rather than about what we could see; it now prints
// this string instead. One of the four is our own doing: these three calls
// resolve through the version.dll shipped beside the client, which is this
// project's proxy, and if its forward to the system copy failed they return
// zero forever.
static const char* g_metaWhyNot = "not attempted";

static const char* CheckD3D9Metadata() {
    HMODULE h = GetModuleHandleA("d3d9.dll");
    if (!h) { g_metaWhyNot = "d3d9.dll is not loaded yet"; return nullptr; }

    char path[MAX_PATH];
    if (!GetModuleFileNameA(h, path, sizeof(path))) {
        g_metaWhyNot = "d3d9.dll is loaded but its path could not be read";
        return nullptr;
    }

    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeA(path, &dummy);
    if (size == 0) {
        g_metaWhyNot = "d3d9.dll carries no version resource, or the version.dll "
                       "beside the client did not forward to the system one";
        return nullptr;
    }
    if (size > 65536) {
        g_metaWhyNot = "d3d9.dll version resource is implausibly large";
        return nullptr;
    }

    void* buf = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        g_metaWhyNot = "could not allocate for the version resource";
        return nullptr;
    }

    const char* result = nullptr;
    if (GetFileVersionInfoA(path, 0, size, buf)) {
        const char* subBlocks[] = {
            "\\StringFileInfo\\040904E4\\ProductName",
            "\\StringFileInfo\\040904B0\\ProductName",
            "\\StringFileInfo\\040904E4\\FileDescription",
            "\\StringFileInfo\\040904B0\\FileDescription", nullptr
        };
        for (int i = 0; subBlocks[i]; i++) {
            void* val = nullptr;
            UINT vlen = 0;
            if (VerQueryValueA(buf, subBlocks[i], &val, &vlen) && val && vlen > 0) {
                const char* s = (const char*)val;
                for (UINT j = 0; j + 4 <= vlen; j++) {
                    char a = s[j], b = s[j+1], c = s[j+2], d = s[j+3];
                    if ((a=='D'||a=='d') && (b=='X'||b=='x') &&
                       (c=='V'||c=='v') && (d=='K'||d=='k')) {
                        result = "d3d9.dll metadata: DXVK";
                        break;
                    }
                }
                if (result) break;
            }
        }
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    if (!result)
        g_metaWhyNot = "read d3d9.dll's version resource; it does not name DXVK";
    return result;
}

static const char* CheckEnv() {
    static const char* envVars[] = {
        "DXVK_HUD", "DXVK_LOG_PATH", "DXVK_LOG_LEVEL",
        "DXVK_STATE_CACHE_PATH", "DXVK_FILTER_DEVICE_NAME", nullptr
    };
    char buf[8];
    for (int i = 0; envVars[i]; i++) {
        DWORD r = GetEnvironmentVariableA(envVars[i], buf, sizeof(buf));
        if (r > 0) {
            static char out[64];
            _snprintf_s(out, sizeof(out), _TRUNCATE, "env: %s", envVars[i]);
            return out;
        }
    }
    return nullptr;
}

static void DetectOnce() {
    const char* r = CheckLoadedModules();
    if (!r) r = CheckD3D9Metadata();
    if (!r) r = CheckEnv();

    if (r) {
        g_reason = r;
        InterlockedExchange(&g_active, 1);
        Log("[DXVKBridge] Vulkan translation layer DETECTED - %s", r);
    }
}

bool Init() {
    DetectOnce();
    if (!g_active) {
        Log("[DXVKBridge] no Vulkan translation layer detected yet (vulkan-1.dll loads lazily on device creation; will keep checking via IsActive())");
        Log("[DXVKBridge]   the file-metadata check: %s. Which of the five ways "
            "this can end matters: four of them are \"could not look\" and only "
            "one is \"looked, and it is not DXVK\".", g_metaWhyNot);
    }
    return true;
}

void Shutdown() {
    InterlockedExchange(&g_active, 0);
    Log("[DXVKBridge] shutdown");
}

static volatile LONG g_lazyAttempted = 0;

// Detection can run before DXVK's d3d9.dll has loaded vulkan-1.dll (that only
// happens once WoW actually creates the D3D9 device), so a single one-shot
// check at Init() time can miss it. This adds exactly ONE more attempt, run
// lazily on the first IsActive() call: that call comes from a D3D9 hook (our
// hooks live on d3d9.dll's vtable), so d3d9.dll — and, after device creation,
// vulkan-1.dll — is loaded by then and detection can succeed. After that single
// retry we settle to a cheap volatile read, so a genuinely non-DXVK process
// does NOT re-enumerate modules and read file-version info on every hot-path
// call (e.g. Hooked_VB_Lock runs IsActive() per vertex-buffer lock).
bool IsActive() {
    if (g_active) return true;
    if (InterlockedCompareExchange(&g_lazyAttempted, 1, 0) == 0) {
        DetectOnce();
    }
    return g_active != 0;
}
void GetStats(Stats* out) {
    if (!out) return;
    out->active            = g_active != 0;
    // When nothing was detected, the interesting string is not "not detected"
    // but what the one check that could have answered actually saw.
    out->detectionReason   = g_active ? g_reason : g_metaWhyNot;
}

} // namespace DXVKBridge
