// ============================================================================
// Description: Proxy wrapper for standard version.dll exports. Intercepts game boot calls and schedules the initialization thread after process setup.
// Safety & Threading: Loader lock safe. Export ordinals must match native dll to boot.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#include <cstdlib>

// Real version.dll function pointers
static HMODULE g_realVersionDll = nullptr;

typedef BOOL (WINAPI* GetFileVersionInfoA_fn)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI* GetFileVersionInfoW_fn)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI* GetFileVersionInfoSizeA_fn)(LPCSTR, LPDWORD);
typedef DWORD (WINAPI* GetFileVersionInfoSizeW_fn)(LPCWSTR, LPDWORD);
typedef BOOL (WINAPI* GetFileVersionInfoExA_fn)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI* GetFileVersionInfoExW_fn)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI* GetFileVersionInfoSizeExA_fn)(DWORD, LPCSTR, LPDWORD);
typedef DWORD (WINAPI* GetFileVersionInfoSizeExW_fn)(DWORD, LPCWSTR, LPDWORD);
typedef BOOL (WINAPI* VerQueryValueA_fn)(LPCVOID, LPCSTR, LPVOID*, PUINT);
typedef BOOL (WINAPI* VerQueryValueW_fn)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
typedef DWORD (WINAPI* VerFindFileA_fn)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
typedef DWORD (WINAPI* VerFindFileW_fn)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
typedef DWORD (WINAPI* VerInstallFileA_fn)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
typedef DWORD (WINAPI* VerInstallFileW_fn)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
typedef DWORD (WINAPI* VerLanguageNameA_fn)(DWORD, LPSTR, DWORD);
typedef DWORD (WINAPI* VerLanguageNameW_fn)(DWORD, LPWSTR, DWORD);

static GetFileVersionInfoA_fn       real_GetFileVersionInfoA       = nullptr;
static GetFileVersionInfoW_fn       real_GetFileVersionInfoW       = nullptr;
static GetFileVersionInfoSizeA_fn   real_GetFileVersionInfoSizeA   = nullptr;
static GetFileVersionInfoSizeW_fn   real_GetFileVersionInfoSizeW   = nullptr;
static GetFileVersionInfoExA_fn     real_GetFileVersionInfoExA     = nullptr;
static GetFileVersionInfoExW_fn     real_GetFileVersionInfoExW     = nullptr;
static GetFileVersionInfoSizeExA_fn real_GetFileVersionInfoSizeExA = nullptr;
static GetFileVersionInfoSizeExW_fn real_GetFileVersionInfoSizeExW = nullptr;
static VerQueryValueA_fn            real_VerQueryValueA            = nullptr;
static VerQueryValueW_fn            real_VerQueryValueW            = nullptr;
static VerFindFileA_fn              real_VerFindFileA              = nullptr;
static VerFindFileW_fn              real_VerFindFileW              = nullptr;
static VerInstallFileA_fn           real_VerInstallFileA           = nullptr;
static VerInstallFileW_fn           real_VerInstallFileW           = nullptr;
static VerLanguageNameA_fn          real_VerLanguageNameA          = nullptr;
static VerLanguageNameW_fn          real_VerLanguageNameW          = nullptr;

static bool LoadRealVersionDll() {
    char systemPath[MAX_PATH];
    GetSystemDirectoryA(systemPath, MAX_PATH);
    strcat_s(systemPath, MAX_PATH, "\\version.dll");

    g_realVersionDll = LoadLibraryA(systemPath);
    if (!g_realVersionDll) return false;

    #define LOAD_FN(name) real_##name = (name##_fn)GetProcAddress(g_realVersionDll, #name)
    LOAD_FN(GetFileVersionInfoA);
    LOAD_FN(GetFileVersionInfoW);
    LOAD_FN(GetFileVersionInfoSizeA);
    LOAD_FN(GetFileVersionInfoSizeW);
    LOAD_FN(GetFileVersionInfoExA);
    LOAD_FN(GetFileVersionInfoExW);
    LOAD_FN(GetFileVersionInfoSizeExA);
    LOAD_FN(GetFileVersionInfoSizeExW);
    LOAD_FN(VerQueryValueA);
    LOAD_FN(VerQueryValueW);
    LOAD_FN(VerFindFileA);
    LOAD_FN(VerFindFileW);
    LOAD_FN(VerInstallFileA);
    LOAD_FN(VerInstallFileW);
    LOAD_FN(VerLanguageNameA);
    LOAD_FN(VerLanguageNameW);
    #undef LOAD_FN

    return true;
}

// Proxy log
// This was fopen on a relative path, which resolves against the process working
// directory. A shortcut with a different "Start in", or anything that starts the
// game from another folder, put the one record of whether the payload loaded
// where nobody looks, and what comes back is "no logs appeared". The path is now
// built from this DLL's own location, which is the folder the game loaded it
// from.
//
// Raw Win32 rather than the CRT, so the attach line can be written from inside
// DllMain while the loader lock is held.
static void ProxyLogPath(HMODULE hSelf, char* out, size_t cap) {
    out[0] = '\0';

    char dir[MAX_PATH];
    DWORD n = GetModuleFileNameA(hSelf, dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;

    char* lastSlash = strrchr(dir, '\\');
    if (!lastSlash) return;
    *(lastSlash + 1) = '\0';

    const size_t tail = sizeof("Logs\\wow_optimize_proxy.log");
    size_t base = strlen(dir);
    if (base + tail > cap || base + tail > MAX_PATH) return;

    strcat_s(dir, MAX_PATH, "Logs");
    CreateDirectoryA(dir, NULL);

    strcpy_s(out, cap, dir);
    strcat_s(out, cap, "\\wow_optimize_proxy.log");
}

static void ProxyLog(HMODULE hSelf, const char* text, bool startFresh) {
    char logPath[MAX_PATH];
    ProxyLogPath(hSelf, logPath, MAX_PATH);
    if (logPath[0] == '\0') return;

    HANDLE h = CreateFileA(logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, startFresh ? CREATE_ALWAYS : OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    DWORD written = 0;
    WriteFile(h, text, (DWORD)strlen(text), &written, NULL);
    CloseHandle(h);
}

// Written before anything in this DLL can fail, so a folder our proxy never
// reached and a proxy that ran and could not load the payload stop looking the
// same from outside.
static void ProxyLogAttach(HMODULE hSelf) {
    char host[MAX_PATH];
    if (GetModuleFileNameA(NULL, host, MAX_PATH) == 0) strcpy_s(host, MAX_PATH, "<unknown>");

    char self[MAX_PATH];
    if (GetModuleFileNameA(hSelf, self, MAX_PATH) == 0) strcpy_s(self, MAX_PATH, "<unknown>");

    char line[MAX_PATH * 2 + 64];
    strcpy_s(line, sizeof(line), "ATTACH: proxy loaded into ");
    strcat_s(line, sizeof(line), host);
    strcat_s(line, sizeof(line), "\r\nProxy file: ");
    strcat_s(line, sizeof(line), self);
    strcat_s(line, sizeof(line), "\r\n");

    ProxyLog(hSelf, line, true);
}


// Forwarded exports
extern "C" {

__declspec(dllexport) BOOL WINAPI Export_GetFileVersionInfoA(LPCSTR a, DWORD b, DWORD c, LPVOID d) {
    return real_GetFileVersionInfoA ? real_GetFileVersionInfoA(a, b, c, d) : FALSE;
}
__declspec(dllexport) BOOL WINAPI Export_GetFileVersionInfoW(LPCWSTR a, DWORD b, DWORD c, LPVOID d) {
    return real_GetFileVersionInfoW ? real_GetFileVersionInfoW(a, b, c, d) : FALSE;
}
__declspec(dllexport) DWORD WINAPI Export_GetFileVersionInfoSizeA(LPCSTR a, LPDWORD b) {
    return real_GetFileVersionInfoSizeA ? real_GetFileVersionInfoSizeA(a, b) : 0;
}
__declspec(dllexport) DWORD WINAPI Export_GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b) {
    return real_GetFileVersionInfoSizeW ? real_GetFileVersionInfoSizeW(a, b) : 0;
}
__declspec(dllexport) BOOL WINAPI Export_GetFileVersionInfoExA(DWORD f, LPCSTR a, DWORD b, DWORD c, LPVOID d) {
    return real_GetFileVersionInfoExA ? real_GetFileVersionInfoExA(f, a, b, c, d) : FALSE;
}
__declspec(dllexport) BOOL WINAPI Export_GetFileVersionInfoExW(DWORD f, LPCWSTR a, DWORD b, DWORD c, LPVOID d) {
    return real_GetFileVersionInfoExW ? real_GetFileVersionInfoExW(f, a, b, c, d) : FALSE;
}
__declspec(dllexport) DWORD WINAPI Export_GetFileVersionInfoSizeExA(DWORD f, LPCSTR a, LPDWORD b) {
    return real_GetFileVersionInfoSizeExA ? real_GetFileVersionInfoSizeExA(f, a, b) : 0;
}
__declspec(dllexport) DWORD WINAPI Export_GetFileVersionInfoSizeExW(DWORD f, LPCWSTR a, LPDWORD b) {
    return real_GetFileVersionInfoSizeExW ? real_GetFileVersionInfoSizeExW(f, a, b) : 0;
}
__declspec(dllexport) BOOL WINAPI Export_VerQueryValueA(LPCVOID a, LPCSTR b, LPVOID* c, PUINT d) {
    return real_VerQueryValueA ? real_VerQueryValueA(a, b, c, d) : FALSE;
}
__declspec(dllexport) BOOL WINAPI Export_VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID* c, PUINT d) {
    return real_VerQueryValueW ? real_VerQueryValueW(a, b, c, d) : FALSE;
}
__declspec(dllexport) DWORD WINAPI Export_VerFindFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPSTR e, PUINT f, LPSTR g, PUINT h) {
    return real_VerFindFileA ? real_VerFindFileA(a, b, c, d, e, f, g, h) : 0;
}
__declspec(dllexport) DWORD WINAPI Export_VerFindFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPWSTR e, PUINT f, LPWSTR g, PUINT h) {
    return real_VerFindFileW ? real_VerFindFileW(a, b, c, d, e, f, g, h) : 0;
}
__declspec(dllexport) DWORD WINAPI Export_VerInstallFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPCSTR e, LPCSTR f, LPSTR g, PUINT h) {
    return real_VerInstallFileA ? real_VerInstallFileA(a, b, c, d, e, f, g, h) : 0;
}
__declspec(dllexport) DWORD WINAPI Export_VerInstallFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR e, LPCWSTR f, LPWSTR g, PUINT h) {
    return real_VerInstallFileW ? real_VerInstallFileW(a, b, c, d, e, f, g, h) : 0;
}
__declspec(dllexport) DWORD WINAPI Export_VerLanguageNameA(DWORD a, LPSTR b, DWORD c) {
    return real_VerLanguageNameA ? real_VerLanguageNameA(a, b, c) : 0;
}
__declspec(dllexport) DWORD WINAPI Export_VerLanguageNameW(DWORD a, LPWSTR b, DWORD c) {
    return real_VerLanguageNameW ? real_VerLanguageNameW(a, b, c) : 0;
}

} // extern "C"

// Loader thread
// The release payload puts version.dll, wow_optimize_launcher.exe and
// wow_loader.exe in the same folder as Wow.exe, and Windows resolves version.dll
// out of the application directory for whatever runs there, so this proxy can
// end up inside our own launcher or loader. It must ask which process it is in
// before loading wow_optimize.dll: that DLL patches absolute addresses inside
// Wow.exe's image, which in any other process are somebody else's code.
//
// The test names our own two executables rather than requiring the host to be
// called Wow.exe, because private-server clients get renamed and refusing an
// unfamiliar name would break them.
static bool HostIsOneOfOurs() {
    char exePath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, exePath, MAX_PATH)) return false;

    const char* leaf = strrchr(exePath, '\\');
    leaf = leaf ? leaf + 1 : exePath;

    static const char* kOurs[] = { "wow_optimize_launcher.exe", "wow_loader.exe" };
    for (int i = 0; i < 2; i++) {
        if (_stricmp(leaf, kOurs[i]) == 0) return true;
    }
    return false;
}

// The client's startup clock check (sub_86AB30, called from the TimeManager constructor) busy-waits
// 250 ms with the process at realtime priority, comparing QueryPerformanceCounter against
// GetTickCount, before the main window can appear. The wait is `cmp edx, 0FAh` at 0x0086AC9B and
// the comparison is edge-aligned on tick changes, so a shorter span makes the same test. It runs
// in the first moments of the process, long before wow_optimize.dll loads (the loader thread
// sleeps three seconds), so the patch is made here, from DllMain.
//
// Off unless FastTimerCalibration=1 in the ini, and skipped under NoClientPatches. The ini is
// looked up the way Config::ResolveIniPath does, without creating or moving anything.
static const unsigned kTimerCmpSite  = 0x0086AC9B;
static const unsigned char kTimerCmpOld[6] = { 0x81, 0xFA, 0xFA, 0x00, 0x00, 0x00 };
static const unsigned char kTimerWaitMs = 16;    // two tick edges, about 31 ms

static bool FileThere(const char* path) {
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static bool ProxyFindIni(char* out, size_t cap) {
    char env[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("WOW_OPT_CONFIG", env, MAX_PATH);
    if (n > 0 && n < MAX_PATH && FileThere(env)) { strcpy_s(out, cap, env); return true; }

    char root[MAX_PATH];
    if (!GetModuleFileNameA(NULL, root, MAX_PATH)) return false;
    char* slash = strrchr(root, '\\');
    if (!slash) return false;
    *(slash + 1) = '\0';

    char path[MAX_PATH];
    strcpy_s(path, sizeof(path), root);
    strcat_s(path, sizeof(path), "WTF\\wow_opt.ini");
    if (FileThere(path)) { strcpy_s(out, cap, path); return true; }
    strcpy_s(path, sizeof(path), root);
    strcat_s(path, sizeof(path), "wow_opt.ini");
    if (FileThere(path)) { strcpy_s(out, cap, path); return true; }
    return false;
}

static void ApplyFastTimerCalibration(HMODULE hSelf) {
    char ini[MAX_PATH];
    if (!ProxyFindIni(ini, sizeof(ini))) return;
    if (GetPrivateProfileIntA("General", "FastTimerCalibration", 0, ini) == 0) return;

    if (GetPrivateProfileIntA("General", "NoClientPatches", 0, ini) != 0) {
        ProxyLog(hSelf, "FastTimerCalibration: skipped, NoClientPatches is on\r\n", false);
        return;
    }
    if ((uintptr_t)GetModuleHandleA(NULL) != 0x00400000) {
        ProxyLog(hSelf, "FastTimerCalibration: skipped, the client is not at 0x00400000\r\n", false);
        return;
    }

    unsigned char* site = (unsigned char*)(uintptr_t)kTimerCmpSite;
    unsigned char* imm = site + 2;
    DWORD oldProt = 0;
    if (!VirtualProtect(site, sizeof(kTimerCmpOld), PAGE_EXECUTE_READWRITE, &oldProt)) {
        ProxyLog(hSelf, "FastTimerCalibration: skipped, the client's code could not be made writable\r\n", false);
        return;
    }
    bool matches = memcmp(site, kTimerCmpOld, sizeof(kTimerCmpOld)) == 0;
    if (matches) *imm = kTimerWaitMs;
    DWORD ignored;
    VirtualProtect(site, sizeof(kTimerCmpOld), oldProt, &ignored);
    FlushInstructionCache(GetCurrentProcess(), site, sizeof(kTimerCmpOld));

    ProxyLog(hSelf, matches
        ? "FastTimerCalibration: the client's 250 ms clock check now waits 16 ms (0x0086AC9D)\r\n"
        : "FastTimerCalibration: skipped, the bytes at 0x0086AC9B are not the ones this was written against\r\n",
        false);
}

static DWORD WINAPI LoaderThread(LPVOID param) {
    Sleep(3000);

    if (HostIsOneOfOurs()) return 0;

    char dllPath[MAX_PATH];
    char modulePath[MAX_PATH];

    HMODULE hSelf = (HMODULE)param;
    GetModuleFileNameA(hSelf, modulePath, MAX_PATH);

    char* lastSlash = strrchr(modulePath, '\\');
    if (lastSlash) {
        *(lastSlash + 1) = '\0';
        strcpy_s(dllPath, MAX_PATH, modulePath);
        strcat_s(dllPath, MAX_PATH, "wow_optimize.dll");
    } else {
        strcpy_s(dllPath, MAX_PATH, "wow_optimize.dll");
    }

    DWORD attrib = GetFileAttributesA(dllPath);
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        char msg[MAX_PATH + 128];
        strcpy_s(msg, sizeof(msg), "ERROR: wow_optimize.dll not found at: ");
        strcat_s(msg, sizeof(msg), dllPath);
        strcat_s(msg, sizeof(msg), "\r\nPlace wow_optimize.dll in the same folder as Wow.exe\r\n");
        ProxyLog(hSelf, msg, false);
        return 1;
    }

    HMODULE hOptDll = LoadLibraryA(dllPath);

    // Read here and not at the point of printing. The old code called
    // GetLastError after CreateDirectoryA and fopen had both run, so the number
    // in the log was whatever those left behind.
    DWORD loadErr = hOptDll ? 0 : GetLastError();

    char msg[MAX_PATH + 128];
    if (hOptDll) {
        strcpy_s(msg, sizeof(msg), "OK: wow_optimize.dll loaded from: ");
        strcat_s(msg, sizeof(msg), dllPath);
        strcat_s(msg, sizeof(msg), "\r\n");
    } else {
        char code[16];
        _ultoa_s(loadErr, code, sizeof(code), 10);
        strcpy_s(msg, sizeof(msg), "ERROR: Failed to load wow_optimize.dll (error ");
        strcat_s(msg, sizeof(msg), code);
        strcat_s(msg, sizeof(msg), ")\r\nPath: ");
        strcat_s(msg, sizeof(msg), dllPath);
        strcat_s(msg, sizeof(msg), "\r\n");
    }
    ProxyLog(hSelf, msg, false);

    return hOptDll ? 0 : 1;
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            if (!HostIsOneOfOurs()) ProxyLogAttach(hModule);
            if (!LoadRealVersionDll()) {
                if (!HostIsOneOfOurs())
                    ProxyLog(hModule, "ERROR: the system version.dll could not be loaded\r\n", false);
                return FALSE;
            }
            if (!HostIsOneOfOurs()) ApplyFastTimerCalibration(hModule);
            CloseHandle(CreateThread(NULL, 0, LoaderThread, (LPVOID)hModule, 0, NULL));
            break;

        case DLL_PROCESS_DETACH:
            if (g_realVersionDll && reserved == NULL) {
                FreeLibrary(g_realVersionDll);
                g_realVersionDll = nullptr;
            }
            break;
    }
    return TRUE;
}