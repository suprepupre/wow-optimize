#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>

// ================================================================
// Real version.dll function pointers
// ================================================================
static HMODULE g_realVersionDll = nullptr;

typedef BOOL  (WINAPI* GetFileVersionInfoA_fn)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL  (WINAPI* GetFileVersionInfoW_fn)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI* GetFileVersionInfoSizeA_fn)(LPCSTR, LPDWORD);
typedef DWORD (WINAPI* GetFileVersionInfoSizeW_fn)(LPCWSTR, LPDWORD);
typedef BOOL  (WINAPI* GetFileVersionInfoExA_fn)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL  (WINAPI* GetFileVersionInfoExW_fn)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI* GetFileVersionInfoSizeExA_fn)(DWORD, LPCSTR, LPDWORD);
typedef DWORD (WINAPI* GetFileVersionInfoSizeExW_fn)(DWORD, LPCWSTR, LPDWORD);
typedef BOOL  (WINAPI* VerQueryValueA_fn)(LPCVOID, LPCSTR, LPVOID*, PUINT);
typedef BOOL  (WINAPI* VerQueryValueW_fn)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
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

// ================================================================
// Forwarded exports
// ================================================================
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

// ================================================================
// Loader thread
// ================================================================
static DWORD WINAPI LoaderThread(LPVOID param) {
    Sleep(3000);

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
        CreateDirectoryA("Logs", NULL);
        FILE* f = fopen("Logs\\wow_optimize_proxy.log", "w");
        if (f) {
            fprintf(f, "ERROR: wow_optimize.dll not found at: %s\n", dllPath);
            fprintf(f, "Place wow_optimize.dll in the same folder as Wow.exe\n");
            fclose(f);
        }
        return 1;
    }

    HMODULE hOptDll = LoadLibraryA(dllPath);

    CreateDirectoryA("Logs", NULL);
    FILE* f = fopen("Logs\\wow_optimize_proxy.log", "w");
    if (f) {
        if (hOptDll)
            fprintf(f, "OK: wow_optimize.dll loaded from: %s\n", dllPath);
        else
            fprintf(f, "ERROR: Failed to load wow_optimize.dll (error %lu)\nPath: %s\n",
                    GetLastError(), dllPath);
        fclose(f);
    }

    return hOptDll ? 0 : 1;
}

// ================================================================
// DLL Entry Point
// ================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            if (!LoadRealVersionDll()) return FALSE;
            CloseHandle(CreateThread(NULL, 0, LoaderThread, (LPVOID)hModule, 0, NULL));
            break;

        case DLL_PROCESS_DETACH:
            if (g_realVersionDll) {
                FreeLibrary(g_realVersionDll);
                g_realVersionDll = nullptr;
            }
            break;
    }
    return TRUE;
}