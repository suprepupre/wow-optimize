// ================================================================
//  wow_loader.exe — Auto-loader for wow_optimize.dll
//  WoW 3.3.5a
//
//  Launches Wow.exe and injects wow_optimize.dll automatically.
//  Works with ANY Wow.exe (patched, unpatched, custom).
//
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#include <cstring>

static void ShowError(const char* msg) {
    MessageBoxA(NULL, msg, "wow_loader", MB_OK | MB_ICONERROR);
}

static void ShowErrorFmt(const char* fmt, DWORD err) {
    char buf[512];
    sprintf(buf, fmt, err);
    ShowError(buf);
}

static bool FileExists(const char* path) {
    DWORD attrib = GetFileAttributesA(path);
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

static bool InjectDLL(HANDLE hProcess, const char* dllPath) {
    // Get full path
    char fullPath[MAX_PATH];
    DWORD len = GetFullPathNameA(dllPath, MAX_PATH, fullPath, NULL);
    if (len == 0 || len >= MAX_PATH) return false;

    // Allocate memory in target process for the DLL path string
    size_t pathSize = strlen(fullPath) + 1;
    void* remoteMem = VirtualAllocEx(hProcess, NULL, pathSize,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return false;

    // Write the DLL path into target process memory
    if (!WriteProcessMemory(hProcess, remoteMem, fullPath, pathSize, NULL)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Get LoadLibraryA address (same in all processes on same OS)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibrary) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Create remote thread that calls LoadLibraryA(dllPath)
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)pLoadLibrary,
                                         remoteMem, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    // Wait for the DLL to load (max 10 seconds)
    WaitForSingleObject(hThread, 10000);

    // Check if LoadLibrary succeeded (return value = HMODULE or NULL)
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

    return (exitCode != 0);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    // Check that we're in the WoW folder
    if (!FileExists("Wow.exe")) {
        ShowError("Wow.exe not found.\n\n"
                  "Place wow_loader.exe in the same folder as Wow.exe.");
        return 1;
    }

    if (!FileExists("wow_optimize.dll")) {
        ShowError("wow_optimize.dll not found.\n\n"
                  "Place wow_optimize.dll in the same folder as Wow.exe.");
        return 1;
    }

    // Build command line (pass through any arguments)
    char cmdLine[MAX_PATH * 2];
    if (lpCmdLine && lpCmdLine[0]) {
        sprintf(cmdLine, "Wow.exe %s", lpCmdLine);
    } else {
        strcpy(cmdLine, "Wow.exe");
    }

    // Launch Wow.exe in SUSPENDED state
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA("Wow.exe", cmdLine, NULL, NULL, FALSE,
                         CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        DWORD err = GetLastError();
        ShowErrorFmt("Failed to launch Wow.exe (error %lu).\n\n"
                     "Try running wow_loader.exe as Administrator.", err);
        return 1;
    }

    // Create log directory
    CreateDirectoryA("Logs", NULL);

    // Open log file
    FILE* log = fopen("Logs\\wow_loader.log", "w");

    if (log) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(log, "[%02d:%02d:%02d] wow_loader started\n",
                st.wHour, st.wMinute, st.wSecond);
        fprintf(log, "[%02d:%02d:%02d] Wow.exe PID: %lu\n",
                st.wHour, st.wMinute, st.wSecond, pi.dwProcessId);
    }

    // Inject the DLL
    bool injected = InjectDLL(pi.hProcess, "wow_optimize.dll");

    if (log) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        if (injected) {
            fprintf(log, "[%02d:%02d:%02d] wow_optimize.dll injected successfully\n",
                    st.wHour, st.wMinute, st.wSecond);
        } else {
            fprintf(log, "[%02d:%02d:%02d] FAILED to inject wow_optimize.dll (error %lu)\n",
                    st.wHour, st.wMinute, st.wSecond, GetLastError());
        }
    }

    // Resume the main thread (WoW starts running)
    ResumeThread(pi.hThread);

    if (log) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(log, "[%02d:%02d:%02d] Wow.exe resumed\n",
                st.wHour, st.wMinute, st.wSecond);
        fclose(log);
    }

    // Clean up handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // If injection failed, show warning but don't kill WoW
    if (!injected) {
        MessageBoxA(NULL,
                    "wow_optimize.dll could not be loaded.\n"
                    "WoW will start normally without optimizations.\n\n"
                    "Check Logs\\wow_loader.log for details.",
                    "wow_loader — Warning",
                    MB_OK | MB_ICONWARNING);
    }

    return 0;
}