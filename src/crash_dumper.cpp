#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include "version.h"

#pragma comment(lib, "dbghelp.lib")

extern "C" void Log(const char* fmt, ...);

static LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    // Recursion protection: prevent infinite crash dump loop
    // If we're already handling an exception on this thread, return immediately
    // This ensures we only create ONE dump per thread, preventing infinite loops
    // when the same exception keeps firing at the same address
    static thread_local bool s_InHandler = false;
    if (s_InHandler) {
        // Already handling an exception on this thread - prevent infinite recursion
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    DWORD code = ExceptionInfo->ExceptionRecord->ExceptionCode;
    
    // Filter out non-fatal exceptions that are handled by WoW or wow_optimize
    if (code == EXCEPTION_BREAKPOINT ||          // Debugger breakpoint
        code == DBG_PRINTEXCEPTION_C ||          // OutputDebugString
        code == 0x4001000A ||                    // Unknown (possibly WoW-specific)
        code == 0x406D1388 ||                    // SetThreadName (MS Visual C++)
        code == EXCEPTION_GUARD_PAGE ||          // Guard page violation (SEH)
        code == EXCEPTION_SINGLE_STEP ||         // Single step (debugger)
        code == EXCEPTION_DATATYPE_MISALIGNMENT) { // Alignment fault (handled)
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Anti-debug / anti-tamper probe inside ClientExtensions.dll (Project
    // Epoch). It raises a deterministic EXCEPTION_ILLEGAL_INSTRUCTION at
    // ClientExtensions+0x11fc42 every launch and resolves it via its own
    // __except frame at step 3 of the Win32 dispatch chain. Our VEH (step 2)
    // fires first and would otherwise write a misleading minidump every run.
    //
    // Observed only on macOS / Wine so far; native Windows behaviour is
    // unverified, so the filter may be a no-op there. The module-identity
    // check makes the no-op case harmless.
    //
    // Only filter when the faulting address resolves to ClientExtensions.dll —
    // genuine illegal-instruction crashes anywhere else (Wow.exe, our DLL, any
    // other loaded PE, or MEM_PRIVATE shellcode pages) still produce a dump.
    // GetModuleHandleEx with FROM_ADDRESS|UNCHANGED_REFCOUNT is safe from a VEH:
    // no allocations, no callbacks, no refcount mutation.
    if (code == EXCEPTION_ILLEGAL_INSTRUCTION) {
        HMODULE hMod = NULL;
        if (GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                (LPCSTR)ExceptionInfo->ExceptionRecord->ExceptionAddress,
                &hMod) && hMod != NULL) {
            char path[MAX_PATH];
            DWORD n = GetModuleFileNameA(hMod, path, sizeof(path));
            if (n > 0 && n < sizeof(path)) {
                const char* base = strrchr(path, '\\');
                base = base ? base + 1 : path;
                if (_stricmp(base, "ClientExtensions.dll") == 0) {
                    return EXCEPTION_CONTINUE_SEARCH;
                }
            }
        }
    }
    
    // Set flag before processing to prevent re-entry
    // We intentionally do NOT reset s_InHandler to false
    // This ensures we only create ONE dump per thread, preventing infinite loops
    s_InHandler = true;
    
    // Create dump for all remaining exceptions (not in known-safe list)
    // The ExceptionFlags check was removed because it prevented dumps for real crashes
    // that start as first-chance exceptions (ExceptionFlags == 0)
    CreateDirectoryA("Crashes", NULL);

    time_t now = time(nullptr);
    tm tm_buf;
    localtime_s(&tm_buf, &now);
    char filename[MAX_PATH];
    sprintf_s(filename, sizeof(filename), "Crashes\\wow_crash_%04d%02d%02d_%02d%02d%02d.dmp",
              tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
              tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);

    HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mdei;
        mdei.ThreadId           = GetCurrentThreadId();
        mdei.ExceptionPointers  = ExceptionInfo;
        mdei.ClientPointers     = FALSE;

        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                        (MINIDUMP_TYPE)(MiniDumpWithIndirectlyReferencedMemory | MiniDumpScanMemory),
                        &mdei, NULL, NULL);
        CloseHandle(hFile);
    }

    Log("CRASH: 0x%08X at 0x%08X. Dump written to %s",
        ExceptionInfo->ExceptionRecord->ExceptionCode,
        (uintptr_t)ExceptionInfo->ExceptionRecord->ExceptionAddress,
        filename);

    return EXCEPTION_CONTINUE_SEARCH;
}

namespace CrashDumper {

bool Init() {
#if TEST_DISABLE_CRASH_DUMPER
    return false;
#else
    AddVectoredExceptionHandler(1, ExceptionHandler);
    Log("[CrashDumper] Vectored exception handler registered");
    return true;
#endif
}

void Shutdown() {
#if !TEST_DISABLE_CRASH_DUMPER
    // Vectored handlers are automatically removed on process exit.
    // No explicit cleanup needed.
#endif
}

} // namespace CrashDumper