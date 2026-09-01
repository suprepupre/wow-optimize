// ============================================================================
// Module: crash_dumper.cpp
// Description: Monitors game exception handlers and outputs minidump diagnostic logs on crash.
// Safety & Threading: Safe across all threads. Do not allocate heap memory inside exception callbacks.
// ============================================================================

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <cstdio>
#include <ctime>
#include <cstring>
#include "MinHook.h"
#include "version.h"
#include "crash_dumper.h"
#include "session_verdict.h"
#include <intrin.h>

#include <dbghelp.h>
// Deliberately no #pragma comment(lib, "dbghelp.lib"): the one entry point we need
// is resolved at run time from System32 (see ResolveSystemMiniDumpWriteDump).
#pragma comment(lib, "psapi.lib")

extern "C" void Log(const char* fmt, ...);

// Previous unhandled-exception filter (WoW's WowError reporter)
static LPTOP_LEVEL_EXCEPTION_FILTER s_prevFilter = nullptr;

// One-shot: only dump the first crash
static volatile LONG s_dumped = 0;

// ================================================================
// Feature Registry - tracks all active optimizations
// ================================================================
static FeatureState s_features[MAX_TRACKED_FEATURES] = {};
static volatile LONG s_featureCount = 0;
static SRWLOCK s_featureLock = SRWLOCK_INIT;

// ================================================================
// Hook Call Trace - lock-free ring buffer for crash diagnosis
// Records last 256 hook calls so we know WHAT was running at crash
// ================================================================
#define HOOK_TRACE_SIZE 256
#define HOOK_TRACE_MASK (HOOK_TRACE_SIZE - 1)

struct HookTraceEntry {
    const char* hookName;   // Static string - safe in crash context
    uintptr_t   addr;       // Address being hooked or accessed
    DWORD       tick;       // GetTickCount when called
    DWORD       threadId;   // Thread that made the call
    LONG        repeats;    // Consecutive identical calls collapsed into this slot
};

static HookTraceEntry s_hookTrace[HOOK_TRACE_SIZE] = {};
static volatile LONG s_hookTracePos = 0;  // Monotonic write position

// ================================================================
// Event trace ("flight recorder") - state transitions, not hot calls
// ================================================================
#define EVENT_TRACE_SIZE 256
#define EVENT_TRACE_MASK (EVENT_TRACE_SIZE - 1)
#define EVENT_TRACE_TEXT 112

struct EventTraceEntry {
    DWORD        tick;
    DWORD        threadId;
    volatile LONG complete;              // 1 once text is fully written
    char         text[EVENT_TRACE_TEXT];
};

static EventTraceEntry s_eventTrace[EVENT_TRACE_SIZE] = {};
static volatile LONG s_eventTracePos = 0;

// ================================================================
// Crash-time log flush - force ring buffer to disk before dump
// ================================================================
extern void LogFlushImmediate();  // Defined in dllmain.cpp

// Forward declarations for crash report sections
static void WriteFeatureStates(HANDLE hFile);
static void WriteHookTrace(HANDLE hFile);
static void WriteEventTrace(HANDLE hFile);
static void WriteMemoryInfo(HANDLE hFile);

// ================================================================
// Exception code → human-readable name
// ================================================================
static const char* ExceptionName(DWORD code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:        return "ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:   return "ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT:              return "BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT:   return "DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:    return "FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:      return "FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:      return "FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:   return "FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:            return "FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:         return "FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:           return "FLT_UNDERFLOW";
    case EXCEPTION_ILLEGAL_INSTRUCTION:     return "ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:           return "IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:      return "INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:            return "INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:     return "INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:return "NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:        return "PRIVILEGED_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP:             return "SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW:          return "STACK_OVERFLOW";
    default:                                return "UNKNOWN";
    }
}

// ================================================================
// EBP-chain stack walk (user-mode, no dbghelp)
// ================================================================
static void WriteStackWalk(HANDLE hFile, CONTEXT* ctx) {
    char buf[128];
    DWORD written;

    const char* hdr = "\n=== STACK TRACE (EBP chain) ===\n";
    WriteFile(hFile, hdr, (DWORD)strlen(hdr), &written, NULL);

    DWORD ebp = ctx->Ebp;
    DWORD eip = ctx->Eip;

    for (int frame = 0; frame < 64; frame++) {
        int len = 0;
        HMODULE hMod = nullptr;

        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)eip, &hMod) && hMod) {
            char modPath[MAX_PATH] = "";
            GetModuleFileNameA(hMod, modPath, sizeof(modPath));
            const char* lastSlash = strrchr(modPath, '\\');
            const char* filename = lastSlash ? (lastSlash + 1) : modPath;
            len = sprintf_s(buf, sizeof(buf), "  [%02d] EIP=%s+0x%08X  EBP=0x%08X\n", frame, filename, eip - (uintptr_t)hMod, ebp);
        } else {
            len = sprintf_s(buf, sizeof(buf), "  [%02d] EIP=0x%08X  EBP=0x%08X\n", frame, eip, ebp);
        }
        if (len > 0) WriteFile(hFile, buf, (DWORD)len, &written, NULL);

        // Validate EBP before dereferencing
        if (ebp < 0x10000 || (ebp & 3) != 0)
            break;

        __try {
            DWORD nextEbp = *(DWORD*)(ebp);
            DWORD retAddr = *(DWORD*)(ebp + 4);

            // Sanity: EBP must grow up the stack, return addr must be > 0x10000
            if (nextEbp <= ebp || nextEbp == 0 || retAddr < 0x10000)
                break;

            eip = retAddr;
            ebp = nextEbp;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
    }
}

// ================================================================
// Raw ESP stack scan (user-mode, no dbghelp)
// ================================================================
static void WriteRawStackScan(HANDLE hFile, CONTEXT* ctx) {
    char buf[256];
    DWORD written;

    const char* hdr = "\n=== STACK SCAN (Raw ESP values) ===\n";
    WriteFile(hFile, hdr, (DWORD)strlen(hdr), &written, NULL);

    __try {
        DWORD* stack = (DWORD*)ctx->Esp;
        HMODULE hWow = GetModuleHandleA(NULL);
        HMODULE hDll = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)&WriteRawStackScan, &hDll);

        for (int i = 0; i < 64; i++) {
            DWORD val = stack[i]; // Safe inside __try
            if (val < 0x00401000 || val > 0x7FFE0000) continue;

            HMODULE hMod = NULL;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)val, &hMod)) {
                char modPath[MAX_PATH] = "";
                const char* label = "unknown";
                if (hMod == hWow) {
                    label = "WoW.exe";
                } else if (hMod == hDll) {
                    label = "wow_optimize.dll";
                } else {
                    if (GetModuleFileNameA(hMod, modPath, MAX_PATH)) {
                        char* lastSlash = strrchr(modPath, '\\');
                        label = lastSlash ? lastSlash + 1 : modPath;
                    }
                }
                int len = sprintf_s(buf, sizeof(buf), "  [ESP+0x%02X] = 0x%08X  (%s+0x%X)\n",
                                    i * 4, val, label, (unsigned)(val - (uintptr_t)hMod));
                if (len > 0) WriteFile(hFile, buf, (DWORD)len, &written, NULL);
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        const char* err = "  (failed to read stack)\n";
        WriteFile(hFile, err, (DWORD)strlen(err), &written, NULL);
    }
}

// ================================================================
// Instructions at EIP (user-mode, no dbghelp)
// ================================================================
static void WriteInstructions(HANDLE hFile, CONTEXT* ctx) {
    char buf[128];
    DWORD written;

    const char* hdr = "\n=== INSTRUCTIONS (EIP) ===\n";
    WriteFile(hFile, hdr, (DWORD)strlen(hdr), &written, NULL);

    __try {
        unsigned char codeBytes[16];
        if (ReadProcessMemory(GetCurrentProcess(), (void*)ctx->Eip, codeBytes, 16, NULL)) {
            char bytesStr[64] = {0};
            int pos = 0;
            for (int i = 0; i < 16; i++) {
                pos += sprintf_s(bytesStr + pos, sizeof(bytesStr) - pos, "%02X ", codeBytes[i]);
            }
            int len = sprintf_s(buf, sizeof(buf), "  Code: %s\n", bytesStr);
            if (len > 0) WriteFile(hFile, buf, (DWORD)len, &written, NULL);
        } else {
            const char* err = "  Code at EIP is inaccessible\n";
            WriteFile(hFile, err, (DWORD)strlen(err), &written, NULL);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        const char* err = "  Exception while reading EIP memory\n";
        WriteFile(hFile, err, (DWORD)strlen(err), &written, NULL);
    }
}

// ================================================================
// Loaded module enumeration (user-mode, no dbghelp)
// ================================================================
static void WriteModuleMap(HANDLE hFile) {
    char buf[256];
    DWORD written;

    const char* hdr = "\n=== LOADED MODULES ===\n";
    WriteFile(hFile, hdr, (DWORD)strlen(hdr), &written, NULL);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32 me = { sizeof(me) };
    if (Module32First(hSnap, &me)) {
        do {
            int len = sprintf_s(buf, sizeof(buf), "  0x%08X - 0x%08X  %s\n",
                (uintptr_t)me.modBaseAddr,
                (uintptr_t)me.modBaseAddr + me.modBaseSize,
                me.szModule);
            if (len > 0) WriteFile(hFile, buf, (DWORD)len, &written, NULL);
        } while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);
}

// ================================================================
// Register dump
// ================================================================
static void WriteRegisters(HANDLE hFile, CONTEXT* ctx) {
    char buf[512];
    DWORD written;

    const char* hdr = "\n=== REGISTERS ===\n";
    WriteFile(hFile, hdr, (DWORD)strlen(hdr), &written, NULL);

    int len = sprintf_s(buf, sizeof(buf),
        "  EAX=0x%08X  EBX=0x%08X  ECX=0x%08X  EDX=0x%08X\n"
        "  ESI=0x%08X  EDI=0x%08X  EBP=0x%08X  ESP=0x%08X\n"
        "  EIP=0x%08X  EFL=0x%08X\n",
        ctx->Eax, ctx->Ebx, ctx->Ecx, ctx->Edx,
        ctx->Esi, ctx->Edi, ctx->Ebp, ctx->Esp,
        ctx->Eip, ctx->EFlags);
    if (len > 0) WriteFile(hFile, buf, (DWORD)len, &written, NULL);
}

// ================================================================
// Wine text-format crash report - no dbghelp, no loader lock
// ================================================================
static void WriteTextReport(EXCEPTION_POINTERS* ep) {
    CreateDirectoryA("Crashes", NULL);

    time_t now = time(nullptr);
    tm tm_buf;
    localtime_s(&tm_buf, &now);
    char filename[MAX_PATH];
    sprintf_s(filename, sizeof(filename), "Crashes\\wow_crash_%04d%02d%02d_%02d%02d%02d.txt",
              tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
              tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);

    HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD written;
    char buf[512];

    DWORD code = ep->ExceptionRecord->ExceptionCode;
    uintptr_t addr = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;

    int hlen = sprintf_s(buf, sizeof(buf),
        "wow_optimize v" WOW_OPTIMIZE_VERSION_STR " crash report (Wine)\n"
        "==================================================\n"
        "Time:       %04d-%02d-%02d %02d:%02d:%02d\n"
        "Process ID: %lu\n"
        "Thread ID:  %lu\n"
        "Exception:  0x%08X (%s) at 0x%08X\n",
        tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
        tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
        GetCurrentProcessId(), GetCurrentThreadId(),
        code, ExceptionName(code), addr);
    if (hlen > 0) WriteFile(hFile, buf, (DWORD)hlen, &written, NULL);

    WriteRegisters(hFile, ep->ContextRecord);
    WriteInstructions(hFile, ep->ContextRecord);
    WriteStackWalk(hFile, ep->ContextRecord);
    WriteRawStackScan(hFile, ep->ContextRecord);
    WriteEventTrace(hFile);
    WriteFeatureStates(hFile);
    WriteHookTrace(hFile);
    WriteMemoryInfo(hFile);
    WriteModuleMap(hFile);

    CloseHandle(hFile);

    Log("CRASH: 0x%08X (%s) at 0x%08X. Text report: %s",
        code, ExceptionName(code), addr, filename);
}

// ================================================================
// Windows minidump (no ScanMemory to avoid loader-lock slowness)
// ================================================================
// MiniDumpWriteDump is resolved from the copy of dbghelp.dll in System32, never
// from whatever sits next to Wow.exe.
//
// Statically importing it means the loader takes the game directory first, and
// private WoW installs routinely ship their own dbghelp - a tester's crash landed
// inside X:\games\chromiecraft\dbghelp.dll at +0x36E74 while writing the dump. A
// crash handler that crashes is worse than none: it turns a recoverable fault into
// a wedged process with the main thread dead inside the handler, and destroys the
// evidence for the fault that started it.
typedef BOOL (WINAPI *MiniDumpWriteDump_fn)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
                                            PMINIDUMP_EXCEPTION_INFORMATION,
                                            PMINIDUMP_USER_STREAM_INFORMATION,
                                            PMINIDUMP_CALLBACK_INFORMATION);

static MiniDumpWriteDump_fn ResolveSystemMiniDumpWriteDump() {
    static MiniDumpWriteDump_fn s_fn = nullptr;
    static bool s_tried = false;
    if (s_tried) return s_fn;
    s_tried = true;

    char path[MAX_PATH];
    UINT n = GetSystemDirectoryA(path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH - 16) return nullptr;
    lstrcatA(path, "\\dbghelp.dll");

    HMODULE h = LoadLibraryA(path);
    if (!h) return nullptr;
    s_fn = (MiniDumpWriteDump_fn)GetProcAddress(h, "MiniDumpWriteDump");
    return s_fn;
}

static void WriteMinidump(EXCEPTION_POINTERS* ep) {
    CreateDirectoryA("Crashes", NULL);

    time_t now = time(nullptr);
    tm tm_buf;
    localtime_s(&tm_buf, &now);
    char filename[MAX_PATH];
    sprintf_s(filename, sizeof(filename), "Crashes\\wow_crash_%04d%02d%02d_%02d%02d%02d.dmp",
              tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
              tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);

    MiniDumpWriteDump_fn writeDump = ResolveSystemMiniDumpWriteDump();
    if (!writeDump) {
        Log("[CrashDumper] System dbghelp.dll unavailable - text report only");
    } else {
        HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            MINIDUMP_EXCEPTION_INFORMATION mdei;
            mdei.ThreadId           = GetCurrentThreadId();
            mdei.ExceptionPointers  = ep;
            mdei.ClientPointers     = FALSE;

            // MiniDumpWithIndirectlyReferencedMemory walks pointers and allocates
            // while doing it. The fault being reported is often address-space
            // exhaustion, which is exactly when that walk fails, so the dump is
            // guarded and downgraded rather than allowed to take the handler down.
            __try {
                if (!writeDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                               MiniDumpWithIndirectlyReferencedMemory,
                               &mdei, NULL, NULL)) {
                    writeDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                              MiniDumpNormal, &mdei, NULL, NULL);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Log("[CrashDumper] minidump writer faulted - text report stands");
            }
            CloseHandle(hFile);
        }
    }

    DWORD code = ep->ExceptionRecord->ExceptionCode;
    uintptr_t addr = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
    Log("CRASH: 0x%08X (%s) at 0x%08X. Dump: %s",
        code, ExceptionName(code), addr, filename);
}

// ================================================================
// Write Feature States to crash report
// ================================================================
static void WriteFeatureStates(HANDLE hFile) {
    char buf[512];
    DWORD written;

    const char* hdr = "\n=== ACTIVE FEATURES (wow_optimize) ===\n";
    WriteFile(hFile, hdr, (DWORD)strlen(hdr), &written, NULL);

    LONG count = InterlockedCompareExchange(&s_featureCount, 0, 0);
    if (count == 0) {
        const char* none = "  (no features registered)\n";
        WriteFile(hFile, none, (DWORD)strlen(none), &written, NULL);
        return;
    }

    DWORD nowTick = GetTickCount();
    for (int i = 0; i < count && i < MAX_TRACKED_FEATURES; i++) {
        FeatureState& f = s_features[i];
        DWORD ageMs = nowTick - f.lastCallTick;
        int len = sprintf_s(buf, sizeof(buf),
            "  %-28s active=%d calls=%lld errors=%lld lastCall=%ums ago%s%s\n",
            f.name ? f.name : "(null)",
            f.active ? 1 : 0,
            f.callCount,
            f.errorCount,
            f.lastCallTick > 0 ? ageMs : 0,
            f.lastError ? " err=\"" : "",
            f.lastError ? f.lastError : "");
        if (f.lastError) {
            // Append closing quote
            int elen = strlen(buf);
            if (elen < (int)sizeof(buf) - 2) {
                buf[elen] = '"'; buf[elen+1] = '\n'; buf[elen+2] = '\0';
            }
        }
        if (len > 0) WriteFile(hFile, buf, (DWORD)strlen(buf), &written, NULL);
    }
}

// ================================================================
// Write Hook Call Trace to crash report
// ================================================================
static void WriteHookTrace(HANDLE hFile) {
    char buf[256];
    DWORD written;

    const char* hdr = "\n=== HOOK CALL TRACE (last 256 calls) ===\n";
    WriteFile(hFile, hdr, (DWORD)strlen(hdr), &written, NULL);

    LONG pos = InterlockedCompareExchange(&s_hookTracePos, 0, 0);
    if (pos == 0) {
        const char* none = "  (no hook calls recorded)\n";
        WriteFile(hFile, none, (DWORD)strlen(none), &written, NULL);
        return;
    }

    // Show last 64 entries (most recent first)
    int showCount = (pos < 64) ? pos : 64;
    for (int i = 0; i < showCount; i++) {
        int idx = (pos - 1 - i) & HOOK_TRACE_MASK;
        HookTraceEntry& e = s_hookTrace[idx];
        if (!e.hookName) continue;
        int len = sprintf_s(buf, sizeof(buf),
            "  [%02d] TID=%5lu tick=%10lu addr=0x%08X %s x%ld\n",
            i, e.threadId, e.tick, (unsigned)e.addr, e.hookName, e.repeats + 1);
        if (len > 0) WriteFile(hFile, buf, (DWORD)strlen(buf), &written, NULL);
    }
}

// ================================================================
// Write Event Trace to crash report - the state transitions leading
// up to the crash, which is usually the section that explains it
// ================================================================
static void WriteEventTrace(HANDLE hFile) {
    char buf[256];
    DWORD written;

    const char* hdr = "\n=== EVENT TRACE (most recent first) ===\n";
    WriteFile(hFile, hdr, (DWORD)strlen(hdr), &written, NULL);

    LONG pos = InterlockedCompareExchange(&s_eventTracePos, 0, 0);
    DWORD now = GetTickCount();
    int printed = 0;

    for (int i = 0; i < EVENT_TRACE_SIZE && i < pos; i++) {
        EventTraceEntry& e = s_eventTrace[(pos - 1 - i) & EVENT_TRACE_MASK];
        if (!e.complete) continue;
        int len = sprintf_s(buf, sizeof(buf), "  -%7ums TID=%5lu %s\n",
                            (unsigned)(now - e.tick), e.threadId, e.text);
        if (len > 0) WriteFile(hFile, buf, (DWORD)len, &written, NULL);
        printed++;
    }

    if (printed == 0) {
        const char* none = "  (no events recorded)\n";
        WriteFile(hFile, none, (DWORD)strlen(none), &written, NULL);
    }
}

// ================================================================
// Write Process Memory Info to crash report
// ================================================================
static void WriteMemoryInfo(HANDLE hFile) {
    char buf[512];
    DWORD written;

    const char* hdr = "\n=== MEMORY STATE ===\n";
    WriteFile(hFile, hdr, (DWORD)strlen(hdr), &written, NULL);

    PROCESS_MEMORY_COUNTERS pmc = {};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        int len = sprintf_s(buf, sizeof(buf),
            "  WorkingSet:    %.1f MB\n"
            "  PeakWS:        %.1f MB\n"
            "  PrivateBytes:  %.1f MB\n"
            "  PageFaults:    %lu\n",
            pmc.WorkingSetSize / (1024.0 * 1024.0),
            pmc.PeakWorkingSetSize / (1024.0 * 1024.0),
            pmc.PagefileUsage / (1024.0 * 1024.0),
            pmc.PageFaultCount);
        if (len > 0) WriteFile(hFile, buf, (DWORD)strlen(buf), &written, NULL);
    }

    // VA space fragmentation check
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0x10000;
    SIZE_T largestFree = 0, totalFree = 0;
    while (addr < 0x7FFF0000) {
        if (VirtualQuery((void*)addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_FREE) {
                if (mbi.RegionSize > largestFree) largestFree = mbi.RegionSize;
                totalFree += mbi.RegionSize;
            }
            addr += mbi.RegionSize;
            if (mbi.RegionSize == 0) addr += 0x10000;
        } else {
            addr += 0x10000;
        }
    }
    int len = sprintf_s(buf, sizeof(buf),
        "  VA Free:       %.1f MB\n"
        "  VA LargestBlk: %.1f MB%s\n",
        totalFree / (1024.0 * 1024.0),
        largestFree / (1024.0 * 1024.0),
        (largestFree < 64 * 1024 * 1024) ? " WARNING: FRAGMENTED" : "");
    if (len > 0) WriteFile(hFile, buf, (DWORD)strlen(buf), &written, NULL);
}

// ================================================================
// WoW Internal Assertion Handler Hook (sub_8889B0)
// WoW's ERROR #134 "Fatal Condition" fires through sub_8889B0 →
// sub_771800 → sub_772AA0 → sub_7729B0 → ExitProcess.
// This path does NOT raise a Windows exception, so our SEH/UEF
// never triggers. We hook the assertion entry point to log it.
// ================================================================

// sub_8889B0 signature: void __cdecl sub_8889B0(char msg, int arg1, int arg2)
// It pushes msg onto stack, calls sub_771800(arg1, arg2) to set error context,
// then calls sub_772AA0 which formats and fires ExitProcess(1).
typedef void (__cdecl *WowAssert_fn)(const char* msg, int arg1, int arg2);
static WowAssert_fn orig_WowAssert = nullptr;

static void __cdecl Hooked_WowAssert(const char* msg, int arg1, int arg2) {
    __try {
        if (arg1 == 0x009E14FF && *(uintptr_t*)0x00B499A8 == 0) {
            static unsigned char s_dummyConsole[8192] = {0};
            *(uintptr_t*)0x00B499A8 = (uintptr_t)s_dummyConsole;
            Log("[CrashDumper] Bypassed NOT_OWNER assert (arg1=0x9E14FF): redirected NULL console pointer to dummy buffer");
            LogFlushImmediate();
            return;
        }

        // Flush and log the assertion before WoW kills the process
        LogFlushImmediate();

        Log("!!! WOW ASSERTION (ERROR #134 Fatal Condition) !!!");
        __try {
            Log("!!!   Message: %s", msg ? msg : "(null)");
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            Log("!!!   Message: (inaccessible pointer 0x%08X)", (unsigned)msg);
        }
        Log("!!!   arg1=0x%08X  arg2=0x%08X", (unsigned)arg1, (unsigned)arg2);
        Log("!!!   Caller=0x%08X", (unsigned)(uintptr_t)_ReturnAddress());
        Log("!!!   TID=%lu", GetCurrentThreadId());

        // Log active features
        LONG fcount = InterlockedCompareExchange(&s_featureCount, 0, 0);
        int activeFeatures = 0;
        for (int i = 0; i < fcount && i < MAX_TRACKED_FEATURES; i++) {
            if (s_features[i].active) activeFeatures++;
        }
        Log("!!!   ACTIVE FEATURES: %d/%ld registered", activeFeatures, fcount);

        // Log last hook calls
        LONG hpos = InterlockedCompareExchange(&s_hookTracePos, 0, 0);
        for (int i = 0; i < 10 && i < hpos; i++) {
            int idx = (hpos - 1 - i) & HOOK_TRACE_MASK;
            HookTraceEntry& e = s_hookTrace[idx];
            if (e.hookName) {
                Log("!!!   LAST HOOK[%d]: %s @ 0x%08X (TID=%lu, %ums ago, x%ld)",
                    i, e.hookName, (unsigned)e.addr, e.threadId,
                    GetTickCount() - e.tick, e.repeats + 1);
            }
        }

        Log("!!! END WOW ASSERTION !!!");
        LogFlushImmediate();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        Log("[CrashDumper] EXCEPTION inside Hooked_WowAssert logging");
        LogFlushImmediate();
    }

    // Chain to WoW's original assertion handler (will ExitProcess)
    orig_WowAssert(msg, arg1, arg2);
}

// ================================================================
// TerminateProcess Hook (catches silent kills from Warden, anti-cheat, or WoW internals)
// ================================================================
typedef BOOL (WINAPI *TerminateProcess_fn)(HANDLE hProcess, UINT uExitCode);
static TerminateProcess_fn orig_TerminateProcess = nullptr;

static BOOL WINAPI Hooked_TerminateProcess(HANDLE hProcess, UINT uExitCode) {
    __try {
        // Only log if it's our own process being terminated
        if (hProcess == GetCurrentProcess() || (hProcess && GetProcessId(hProcess) == GetCurrentProcessId())) {
            LogFlushImmediate();
            Log("!!! TERMINATE PROCESS (code=%u) — silent kill detected !!!", uExitCode);
            Log("!!!   TID=%lu  Caller=0x%08X", GetCurrentThreadId(), (unsigned)(uintptr_t)_ReturnAddress());

            // Log last hook calls for context
            LONG hpos = InterlockedCompareExchange(&s_hookTracePos, 0, 0);
            for (int i = 0; i < 5 && i < hpos; i++) {
                int idx = (hpos - 1 - i) & HOOK_TRACE_MASK;
                HookTraceEntry& e = s_hookTrace[idx];
                if (e.hookName) {
                    Log("!!!   LAST HOOK[%d]: %s @ 0x%08X (TID=%lu, %ums ago, x%ld)",
                        i, e.hookName, (unsigned)e.addr, e.threadId,
                        GetTickCount() - e.tick, e.repeats + 1);
                }
            }

            Log("!!! END TERMINATE REPORT !!!");
            LogFlushImmediate();
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Safe fallback
    }
    return orig_TerminateProcess(hProcess, uExitCode);
}

// ================================================================
// ExitProcess Hook (fallback for any abnormal exit)
// ================================================================
typedef void (WINAPI *ExitProcess_fn)(UINT uExitCode);
static ExitProcess_fn orig_ExitProcess = nullptr;

static void WINAPI Hooked_ExitProcess(UINT uExitCode) {
    __try {
        LogFlushImmediate();

        if (uExitCode != 0) {
            Log("!!! PROCESS EXIT (code=%u) — abnormal termination !!!", uExitCode);
            Log("!!!   TID=%lu  Caller=0x%08X", GetCurrentThreadId(), (unsigned)(uintptr_t)_ReturnAddress());
            LogFlushImmediate();
        } else {
            Log("[Exit] Normal termination (code=0). TID=%lu  Caller=0x%08X",
                GetCurrentThreadId(), (unsigned)(uintptr_t)_ReturnAddress());
            LogFlushImmediate();
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Best-effort logging during exit — don't crash the exit path
    }

    // Chain to original ExitProcess (allows DLL_PROCESS_DETACH and proper cleanup)
    orig_ExitProcess(uExitCode);
}

// Forward declaration
static LONG WINAPI WowOpt_UnhandledExceptionFilter(EXCEPTION_POINTERS* ep);

// ================================================================
// SetUnhandledExceptionFilter Hook (prevents overriding our handler)
// ================================================================
typedef LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI *SetUnhandledExceptionFilter_fn)(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
static SetUnhandledExceptionFilter_fn orig_SetUnhandledExceptionFilter = nullptr;

static LPTOP_LEVEL_EXCEPTION_FILTER WINAPI Hooked_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
    // If the caller tries to set our own filter, let it go to the original API
    if (lpTopLevelExceptionFilter == (LPTOP_LEVEL_EXCEPTION_FILTER)&WowOpt_UnhandledExceptionFilter) {
        return orig_SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
    }
    
    // Save the caller's filter so we can chain to it, but do NOT register it with the OS.
    // We keep WowOpt_UnhandledExceptionFilter registered to guarantee our reporting runs first.
    LPTOP_LEVEL_EXCEPTION_FILTER old = s_prevFilter;
    s_prevFilter = lpTopLevelExceptionFilter;
    
    // Return the old filter to the caller to maintain transparent API behavior.
    return old;
}

// ================================================================
// Top-level unhandled exception filter
// ================================================================
// For an access violation the exception record carries the two facts that actually
// identify the bug: whether the faulting instruction was reading or writing, and
// which address it touched. Only the instruction pointer was ever logged, so a
// crash inside memcpy could not be told apart from a crash writing into a device
// surface - the difference between a bad source and a bad destination, which is the
// difference between two entirely different features.
static void LogAccessViolationDetail(EXCEPTION_RECORD* er) {
    if (!er || er->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return;
    if (er->NumberParameters < 2) return;

    ULONG_PTR op   = er->ExceptionInformation[0];
    ULONG_PTR addr = er->ExceptionInformation[1];
    const char* what = (op == 0) ? "READING from" :
                       (op == 1) ? "WRITING to"   :
                       (op == 8) ? "EXECUTING"    : "accessing";

    // Naming the region turns the address into a cause rather than a number.
    const char* region;
    if (addr < 0x10000)             region = "null page - a null pointer plus a small offset";
    else if (addr >= 0x80000000)    region = "kernel space - almost always a corrupted pointer";
    else {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) region = "unqueryable";
        else if (mbi.State == MEM_FREE)    region = "freed or never mapped - a stale pointer, or a view that was unmapped";
        else if (mbi.State == MEM_RESERVE) region = "reserved but not committed";
        else if (mbi.Protect & PAGE_NOACCESS) region = "committed but no-access";
        else region = "mapped and committed - a length or stride overran it";
    }

    Log("!!! FAULT: %s 0x%08X (%s)", what, (unsigned)addr, region);
}

// ================================================================
// First-chance probe
//
// SetUnhandledExceptionFilter only fires for exceptions nobody handles. Any
// __except frame above the fault swallows it first, and the client has plenty of
// those - so a crash can end the session with our filter never running at all.
// A druid-shapeshift report looked exactly like that: the log stops mid-line, no
// crash report, no shutdown notice, no TerminateProcess notice.
//
// A vectored handler runs before every frame-based handler and before the
// unhandled filter, so it sees the fault whatever becomes of it afterwards. It
// has to stay cheap - it is entered for every exception on every thread,
// including ordinary handled ones - and it must never change what the process
// does, hence EXCEPTION_CONTINUE_SEARCH on every path.
// ================================================================
static volatile LONG s_firstChanceLogged = 0;

// Totals, so the log can state the scale without printing every occurrence.
static volatile LONG g_firstChanceTotal   = 0;
static volatile LONG g_firstChanceRepeats = 0;
static const LONG FIRST_CHANCE_LOG_LIMIT = 8;

static bool IsFatalClass(DWORD code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_STACK_OVERFLOW:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_IN_PAGE_ERROR:
        return true;
    default:
        return false;   // C++ throws, breakpoints, DXVK's own control flow
    }
}

// Set while this thread is inside the probe. If reporting a fault somehow faults,
// the second entry leaves at once instead of recursing.
static __declspec(thread) bool t_inProbe = false;

// ClientExtensions.dll (Project Epoch) raises a deterministic
// EXCEPTION_ILLEGAL_INSTRUCTION as an anti-debug / anti-tamper probe on every
// launch and resolves it in its own __except frame. It is not a crash, but the
// first-chance probe sees it before that frame does, so it spends one of only
// eight log slots and a trace-ring entry on the same benign fault every session.
//
// The module's base address is resolved on the main thread and cached here. The
// probe itself must not call GetModuleHandleExA - see the note further down
// about the loader lock - so it compares against this instead, reaching the
// allocation base through VirtualQuery, which this handler already relies on.
// Zero means "not loaded / not resolved yet", and then nothing is suppressed.
static volatile uintptr_t g_clientExtBase = 0;
static volatile uintptr_t g_clientExtEnd  = 0;

// Called from Init and from periodic main-thread maintenance, because the module
// can appear after we do. Safe there: an ordinary thread, no fault in progress.
void CrashDumper::RefreshBenignModuleRanges() {
    HMODULE h = GetModuleHandleA("ClientExtensions.dll");
    if (!h) {
        g_clientExtBase = 0;
        g_clientExtEnd  = 0;
        return;
    }
    if ((uintptr_t)h == g_clientExtBase) return;   // already known

    MODULEINFO mi;
    if (GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi))) {
        g_clientExtBase = (uintptr_t)mi.lpBaseOfDll;
        g_clientExtEnd  = (uintptr_t)mi.lpBaseOfDll + mi.SizeOfImage;
        Log("[CrashDumper] ClientExtensions.dll at 0x%08X-0x%08X - its illegal-instruction "
            "probe will not be reported as a fault",
            (unsigned)g_clientExtBase, (unsigned)g_clientExtEnd);
    }
}

// True when the faulting address lies inside ClientExtensions.dll. Uses
// VirtualQuery rather than GetModuleHandleEx so no loader lock is taken; a
// genuine illegal instruction anywhere else - Wow.exe, this DLL, any other
// module, or a private shellcode page - still reports normally.
static bool IsClientExtensionsProbe(DWORD code, uintptr_t at) {
    if (code != EXCEPTION_ILLEGAL_INSTRUCTION) return false;
    uintptr_t base = g_clientExtBase;
    if (!base) return false;
    if (at >= base && at < g_clientExtEnd) return true;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)at, &mbi, sizeof(mbi)) == sizeof(mbi))
        return (uintptr_t)mbi.AllocationBase == base;
    return false;
}

static LONG CALLBACK WowOpt_FirstChanceProbe(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (!IsFatalClass(code)) return EXCEPTION_CONTINUE_SEARCH;
    if (t_inProbe) return EXCEPTION_CONTINUE_SEARCH;

    uintptr_t at = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;

    // A known anti-tamper probe is not a fault worth a log slot or a ring entry.
    if (IsClientExtensionsProbe(code, at)) return EXCEPTION_CONTINUE_SEARCH;

    t_inProbe = true;

    // Always cheap: a mark in the ring costs no I/O and survives into whatever
    // report does eventually get written.
    // Only the first sighting of an address reaches the ring.
    //
    // The unbounded version of this cost a tester 14%% of their main thread. One
    // third-party module raised the same handled access violation 8889 times in a
    // session - it uses exceptions as control flow - and every one wrote an entry
    // to the event ring. That ring is the flight recorder for state transitions,
    // and the slow-frame attribution prints all of it every time it fires, so
    // 1363 slow frames each dumped a ring made entirely of this noise.
    //
    // Which is precisely the mistake the hook trace had to be cured of, where
    // UIAccessor_FrameIsShown crowded out everything rarer. I put a
    // high-frequency event into a ring meant for rare ones, one ring over.
    //
    // A repeated fault at one address is one fact, so it is recorded once and
    // counted thereafter.
    static uintptr_t s_lastFaultAddr = 0;
    ++g_firstChanceTotal;
    if (at != s_lastFaultAddr) {
        s_lastFaultAddr = at;
        CrashDumper::Trace("first-chance %s at 0x%08X TID=%lu",
                           ExceptionName(code), (unsigned)at, GetCurrentThreadId());
    } else {
        ++g_firstChanceRepeats;
        t_inProbe = false;
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Log the first few properly, then fall silent, so a path that faults in a
    // loop behind a __except cannot fill the disk.
    if (InterlockedIncrement(&s_firstChanceLogged) <= FIRST_CHANCE_LOG_LIMIT) {
        // Deliberately no GetModuleHandleExA here, unlike the unhandled filter.
        // That call takes the loader lock, and this handler runs while the process
        // is still alive - including on a fault raised by a thread that already
        // holds that lock, which is exactly the startup and module-load case this
        // was added to catch. The raw address resolves fine in a disassembler; a
        // hang would not.
        //
        // Everything that remains is safe to call from here: the log path is
        // lock-free (InterlockedCompareExchange into a ring, then WriteFile) and
        // LogAccessViolationDetail only calls VirtualQuery.
        Log("!!! FIRST-CHANCE %s at 0x%08X TID=%lu - handled or not, it happened",
            ExceptionName(code), (unsigned)at, GetCurrentThreadId());
        LogAccessViolationDetail(ep->ExceptionRecord);
        LogFlushImmediate();
    }

    t_inProbe = false;
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI WowOpt_UnhandledExceptionFilter(EXCEPTION_POINTERS* ep) {
    // One-shot: only dump the first unhandled crash
    if (InterlockedCompareExchange(&s_dumped, 1, 0) != 0)
        return s_prevFilter ? s_prevFilter(ep) : EXCEPTION_EXECUTE_HANDLER;

    DWORD code = ep->ExceptionRecord->ExceptionCode;
    uintptr_t crashAddr = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;

    // CRITICAL: Flush log ring buffer BEFORE writing crash report
    // Without this, the last N log entries (including the cause) are lost
    LogFlushImmediate();

    Log("!!! CRASH !!! 0x%08X (%s) at 0x%08X TID=%lu",
        code, ExceptionName(code), crashAddr, GetCurrentThreadId());

    LogAccessViolationDetail(ep->ExceptionRecord);

    if (ep->ContextRecord) {
        CONTEXT* ctx = ep->ContextRecord;
        Log("!!! REGISTERS: EAX=0x%08X EBX=0x%08X ECX=0x%08X EDX=0x%08X",
            ctx->Eax, ctx->Ebx, ctx->Ecx, ctx->Edx);
        Log("!!!            ESI=0x%08X EDI=0x%08X EBP=0x%08X ESP=0x%08X",
            ctx->Esi, ctx->Edi, ctx->Ebp, ctx->Esp);
        Log("!!!            EIP=0x%08X EFLAGS=0x%08X",
            ctx->Eip, ctx->EFlags);

        __try {
            unsigned char codeBytes[16];
            if (ReadProcessMemory(GetCurrentProcess(), (void*)ctx->Eip, codeBytes, 16, NULL)) {
                char bytesStr[64] = {0};
                int pos = 0;
                for (int i = 0; i < 16; i++) {
                    pos += sprintf_s(bytesStr + pos, sizeof(bytesStr) - pos, "%02X ", codeBytes[i]);
                }
                Log("!!! INSTRUCTIONS (EIP): %s", bytesStr);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            Log("!!! INSTRUCTIONS (EIP): (inaccessible)");
        }

        // Stack walk: dump return addresses from the stack to identify the call chain
        // This is critical for EIP=0x00000000 crashes (NULL function pointer calls)
        // where the return address at [ESP] reveals who made the bad call
        __try {
            DWORD* stack = (DWORD*)ctx->Esp;
            Log("!!! STACK WALK (ESP=0x%08X):", ctx->Esp);
            HMODULE hWow = GetModuleHandleA(NULL);
            HMODULE hDll = NULL;
            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)&WowOpt_UnhandledExceptionFilter, &hDll);
            for (int i = 0; i < 64; i++) {
                DWORD val = stack[i]; // Safe inside __try
                // Filter: only log values that look like code addresses
                if (val < 0x00401000 || val > 0x7FFE0000) continue;
                HMODULE hMod = NULL;
                if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                       (LPCSTR)val, &hMod)) {
                    const char* label = "unknown";
                    if (hMod == hWow) label = "WoW.exe";
                    else if (hMod == hDll) label = "wow_optimize.dll";
                    else {
                        // For other modules, get the filename
                        static char stackModName[MAX_PATH];
                        if (GetModuleFileNameA(hMod, stackModName, MAX_PATH)) {
                            // Extract just the filename
                            char* lastSlash = strrchr(stackModName, '\\');
                            label = lastSlash ? lastSlash + 1 : stackModName;
                        }
                    }
                    Log("!!!   [ESP+0x%02X] = 0x%08X  (%s+0x%X)",
                        i * 4, val, label, (unsigned)(val - (uintptr_t)hMod));
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            Log("!!! STACK WALK: (failed to read stack)");
        }
    }

    // Identify which module the crash address belongs to
    HMODULE hCrashMod = NULL;
    char modName[MAX_PATH] = "unknown";
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)crashAddr, &hCrashMod)) {
        GetModuleFileNameA(hCrashMod, modName, MAX_PATH);
    }
    Log("!!! CRASH MODULE: %s (base=0x%08X offset=0x%08X)",
        modName, (uintptr_t)hCrashMod,
        hCrashMod ? (unsigned)(crashAddr - (uintptr_t)hCrashMod) : 0);

    // Log active features summary
    LONG fcount = InterlockedCompareExchange(&s_featureCount, 0, 0);
    int activeFeatures = 0;
    for (int i = 0; i < fcount && i < MAX_TRACKED_FEATURES; i++) {
        if (s_features[i].active) activeFeatures++;
    }
    Log("!!! ACTIVE FEATURES: %d/%ld registered", activeFeatures, fcount);

    // Log last few hook calls
    LONG hpos = InterlockedCompareExchange(&s_hookTracePos, 0, 0);
    for (int i = 0; i < 5 && i < hpos; i++) {
        int idx = (hpos - 1 - i) & HOOK_TRACE_MASK;
        HookTraceEntry& e = s_hookTrace[idx];
        if (e.hookName) {
            Log("!!! LAST HOOK[%d]: %s @ 0x%08X (TID=%lu, %ums ago, x%ld)",
                i, e.hookName, (unsigned)e.addr, e.threadId,
                GetTickCount() - e.tick, e.repeats + 1);
        }
    }

    if (IsWine()) {
        WriteTextReport(ep);
    } else {
        WriteMinidump(ep);
    }

    // Chain to WoW's own error handler (WowError) if it exists
    if (s_prevFilter)
        return s_prevFilter(ep);

    return EXCEPTION_EXECUTE_HANDLER;
}

// ================================================================
// Public API
// ================================================================
namespace CrashDumper {

bool Init() {
#if TEST_DISABLE_CRASH_DUMPER
    return false;
#else
    memset(s_features, 0, sizeof(s_features));
    memset(s_hookTrace, 0, sizeof(s_hookTrace));
    InterlockedExchange(&s_featureCount, 0);
    InterlockedExchange(&s_hookTracePos, 0);

    s_prevFilter = SetUnhandledExceptionFilter(WowOpt_UnhandledExceptionFilter);

    // Runs ahead of every frame-based handler, so a fault that something else
    // catches still leaves a record. See the note on WowOpt_FirstChanceProbe.
    AddVectoredExceptionHandler(1, WowOpt_FirstChanceProbe);

    // Resolve now if the module is already up; periodic maintenance retries in
    // case it loads after we do.
    RefreshBenignModuleRanges();

    // Hook WoW's internal assertion handler (sub_8889B0)
    // This fires on ERROR #134 "Fatal Condition" which bypasses Windows exceptions
    void* assertTarget = (void*)0x008889B0;
    if (WineSafe_CreateHook(assertTarget, (void*)Hooked_WowAssert, (void**)&orig_WowAssert) == MH_OK) {
        MH_EnableHook(assertTarget);
        Log("[CrashDumper] WoW assertion handler hook ACTIVE (sub_8889B0)");
    }

    // Hook ExitProcess as a fallback to flush logs on any abnormal exit
    void* exitTarget = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess");
    if (exitTarget && WineSafe_CreateHook(exitTarget, (void*)Hooked_ExitProcess, (void**)&orig_ExitProcess) == MH_OK) {
        MH_EnableHook(exitTarget);
        Log("[CrashDumper] ExitProcess hook ACTIVE (log flush on exit)");
    }

    // Hook TerminateProcess to catch silent kills (Warden, anti-cheat, or WoW internals)
    void* termTarget = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "TerminateProcess");
    if (termTarget && WineSafe_CreateHook(termTarget, (void*)Hooked_TerminateProcess, (void**)&orig_TerminateProcess) == MH_OK) {
        MH_EnableHook(termTarget);
        Log("[CrashDumper] TerminateProcess hook ACTIVE (silent kill detection)");
    }

    // Hook SetUnhandledExceptionFilter to prevent WoW or anti-cheat from overriding our UEF handler
    void* suefTarget = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetUnhandledExceptionFilter");
    if (suefTarget && WineSafe_CreateHook(suefTarget, (void*)Hooked_SetUnhandledExceptionFilter, (void**)&orig_SetUnhandledExceptionFilter) == MH_OK) {
        MH_EnableHook(suefTarget);
        Log("[CrashDumper] SetUnhandledExceptionFilter hook ACTIVE (override protection)");
    }

    Log("[CrashDumper] Enhanced crash reporter active%s",
        IsWine() ? " (Wine: text reports)" : " (Windows: minidump)");
    Log("[CrashDumper] Feature tracking: %d slots, Hook trace: %d entries",
        MAX_TRACKED_FEATURES, HOOK_TRACE_SIZE);
    return true;
#endif
}

void Shutdown() {
#if !TEST_DISABLE_CRASH_DUMPER
    SetUnhandledExceptionFilter(s_prevFilter);
    s_prevFilter = nullptr;
#endif
}

int RegisterFeature(const char* name) {
    AcquireSRWLockExclusive(&s_featureLock);
    LONG idx = InterlockedIncrement(&s_featureCount) - 1;
    if (idx < MAX_TRACKED_FEATURES) {
        s_features[idx].name = name;
        s_features[idx].active = true;
        s_features[idx].counted = false;
        s_features[idx].hits = 0;
        s_features[idx].callCount = 0;
        s_features[idx].errorCount = 0;
        s_features[idx].lastCallTick = 0;
        s_features[idx].lastError = nullptr;
    }
    ReleaseSRWLockExclusive(&s_featureLock);
    if (idx >= MAX_TRACKED_FEATURES) {
        // Silently dropping it would make the activity report quietly incomplete -
        // the feature would simply be absent, indistinguishable from one nobody
        // wired up, which is exactly the ambiguity that report exists to remove.
        if (idx == MAX_TRACKED_FEATURES) {
            Log("[CrashDumper] Feature registry full at %d; '%s' and any after it "
                "are untracked. Raise MAX_TRACKED_FEATURES.",
                MAX_TRACKED_FEATURES, name ? name : "(unnamed)");
        }
        return -1;
    }
    return (int)idx;
}

int FeatureTokenForCounting(const char* name, unsigned hitStride) {
    if (!name) return -1;
    if (hitStride == 0) hitStride = 1;

    LONG count = InterlockedCompareExchange(&s_featureCount, 0, 0);
    if (count > MAX_TRACKED_FEATURES) count = MAX_TRACKED_FEATURES;
    for (int i = 0; i < count; i++) {
        if (s_features[i].name && strcmp(s_features[i].name, name) == 0) {
            s_features[i].counted   = true;
            s_features[i].hitStride = hitStride;
            return i;
        }
    }

    int token = RegisterFeature(name);
    if (token >= 0) {
        s_features[token].counted   = true;
        s_features[token].hitStride = hitStride;
    }
    return token;
}

int RegisteredFeatureCount() {
    LONG count = InterlockedCompareExchange(&s_featureCount, 0, 0);
    if (count > MAX_TRACKED_FEATURES) count = MAX_TRACKED_FEATURES;
    return (int)count;
}

void FeatureHit(int token) {
    if (token < 0 || token >= MAX_TRACKED_FEATURES) return;
    ++s_features[token].hits;
}

void ReportFirstChanceSummary() {
    LONG total = g_firstChanceTotal;
    if (total <= 0) return;
    Log("[FirstChance] %ld fatal-class exceptions were raised and handled by "
        "someone (%ld of them repeats of the previous address). These are not "
        "crashes - something is using exceptions as control flow.",
        total, (LONG)g_firstChanceRepeats);

    // A count that stops moving after startup is a client that throws while
    // setting itself up and then behaves; one that keeps climbing is something
    // faulting on a hot path and being caught. The two read identically from a
    // single report and differently across two, so what is worth surfacing is
    // the growth rather than the total.
    static LONG s_lastTotal = -1;
    if (s_lastTotal >= 0 && total > s_lastTotal) {
        Verdict::Add(Verdict::Warn,
                     "fatal-class exceptions are still being raised and caught - "
                     "%ld more since the last report, %ld in all",
                     total - s_lastTotal, total);
    }
    s_lastTotal = total;
}

void ReportFeatureActivity() {
    LONG count = InterlockedCompareExchange(&s_featureCount, 0, 0);
    if (count > MAX_TRACKED_FEATURES) count = MAX_TRACKED_FEATURES;

    int ran = 0, silent = 0, uncounted = 0, disabled = 0;
    for (int i = 0; i < count; i++) {
        if (!s_features[i].active)      { disabled++;  continue; }
        if (!s_features[i].counted)     { uncounted++; continue; }
        if (s_features[i].hits > 0)     { ran++; }
        else                            { silent++; }
    }

    Log("");
    Log("[Features] === WHAT ACTUALLY RAN THIS SESSION ===");

    if (ran > 0) {
        Log("[Features] Did work (%d):", ran);
        for (int i = 0; i < count; i++) {
            if (s_features[i].active && s_features[i].counted && s_features[i].hits > 0) {
                unsigned stride = s_features[i].hitStride ? s_features[i].hitStride : 1;
                if (stride == 1) {
                    Log("[Features]     %-32s %u", s_features[i].name, s_features[i].hits);
                } else {
                    // Scaled, because otherwise this column silently mixes units.
                    // Stated as an estimate: the sample count is a plain counter
                    // on a hot path, so it is itself a lower bound.
                    Log("[Features]     %-32s ~%.0f  (%u samples x %u)",
                        s_features[i].name,
                        (double)s_features[i].hits * (double)stride,
                        s_features[i].hits, stride);
                }
            }
        }
    }

    if (silent > 0) {
        Log("[Features] Enabled but never ran (%d) - these report their own activity,"
            " so a zero here means the code path was not reached:", silent);
        for (int i = 0; i < count; i++) {
            if (s_features[i].active && s_features[i].counted && s_features[i].hits == 0) {
                Log("[Features]     %s", s_features[i].name);
            }
        }
    }

    // Said plainly, because the alternative is a reader assuming these did nothing.
    Log("[Features] %d enabled features do not report activity and are not judged"
        " here; %d are disabled.", uncounted, disabled);
}

void FeatureCall(const char* name) {
    // Lock-free fast path: linear scan is fine for <64 features
    // Called from hot paths so must be minimal overhead
    LONG count = InterlockedCompareExchange(&s_featureCount, 0, 0);
    for (int i = 0; i < count && i < MAX_TRACKED_FEATURES; i++) {
        if (s_features[i].name == name || 
            (s_features[i].name && name && strcmp(s_features[i].name, name) == 0)) {
            InterlockedIncrement64((volatile LONG64*)&s_features[i].callCount);
            s_features[i].lastCallTick = GetTickCount();
            return;
        }
    }
}

void FeatureError(const char* name, const char* desc) {
    LONG count = InterlockedCompareExchange(&s_featureCount, 0, 0);
    for (int i = 0; i < count && i < MAX_TRACKED_FEATURES; i++) {
        if (s_features[i].name == name ||
            (s_features[i].name && name && strcmp(s_features[i].name, name) == 0)) {
            InterlockedIncrement64((volatile LONG64*)&s_features[i].errorCount);
            s_features[i].lastError = desc;
            s_features[i].lastCallTick = GetTickCount();
            return;
        }
    }
}

void FeatureSetActive(const char* name, bool active) {
    LONG count = InterlockedCompareExchange(&s_featureCount, 0, 0);
    for (int i = 0; i < count && i < MAX_TRACKED_FEATURES; i++) {
        if (s_features[i].name == name ||
            (s_features[i].name && name && strcmp(s_features[i].name, name) == 0)) {
            s_features[i].active = active;
            return;
        }
    }
}

int GetFeatureStates(FeatureState* out, int maxCount) {
    LONG count = InterlockedCompareExchange(&s_featureCount, 0, 0);
    int copied = 0;
    for (int i = 0; i < count && i < MAX_TRACKED_FEATURES && copied < maxCount; i++) {
        out[copied++] = s_features[i];
    }
    return copied;
}

void Trace(const char* fmt, ...) {
    if (!fmt) return;

    LONG pos = InterlockedIncrement(&s_eventTracePos) - 1;
    EventTraceEntry& e = s_eventTrace[pos & EVENT_TRACE_MASK];

    // Mark incomplete first: a reader (crash handler) must never print a slot
    // that is halfway through being overwritten.
    InterlockedExchange(&e.complete, 0);
    e.tick = GetTickCount();
    e.threadId = GetCurrentThreadId();

    va_list args;
    va_start(args, fmt);
    int n = _vsnprintf(e.text, EVENT_TRACE_TEXT - 1, fmt, args);
    va_end(args);
    if (n < 0) n = EVENT_TRACE_TEXT - 1;
    e.text[n] = '\0';

    InterlockedExchange(&e.complete, 1);
}

int DumpTrace(int count, DWORD maxAgeMs) {
    if (count > EVENT_TRACE_SIZE) count = EVENT_TRACE_SIZE;
    LONG pos = InterlockedCompareExchange(&s_eventTracePos, 0, 0);
    DWORD now = GetTickCount();

    int printed = 0;
    for (int i = 0; i < count && i < pos; i++) {
        EventTraceEntry& e = s_eventTrace[(pos - 1 - i) & EVENT_TRACE_MASK];
        if (!e.complete) continue;
        DWORD age = now - e.tick;
        // The ring is ordered, so the first entry past the window ends the walk.
        if (maxAgeMs != 0 && age > maxAgeMs) break;
        Log("    -%6ums  TID=%-5lu %s", (unsigned)age, e.threadId, e.text);
        printed++;
    }
    if (printed == 0) {
        Log(maxAgeMs != 0 ? "    (nothing traced in this window)"
                          : "    (no events recorded)");
    }
    return printed;
}

void RecordHookCall(const char* hookName, uintptr_t addr) {
    // Collapse consecutive identical calls instead of letting them consume slots.
    //
    // The ring is meant to answer "what was happening just before the crash", and
    // it could not: UIAccessor_IsShown is called often enough that even at the 1/64
    // sampling below it filled all 256 slots, so every crash report in four tester
    // logs showed the same hook in all five printed entries and nothing rarer
    // survived. It read like evidence pointing at one module when it was only ever
    // showing whichever hook ran most.
    //
    // The check races: two threads can both decide to extend the same slot, and the
    // repeat count is then approximate. That is fine for a flight recorder, and far
    // cheaper than serialising a path this hot.
    LONG last = InterlockedCompareExchange(&s_hookTracePos, 0, 0);
    if (last > 0) {
        HookTraceEntry& prev = s_hookTrace[(last - 1) & HOOK_TRACE_MASK];
        if (prev.hookName == hookName && prev.threadId == GetCurrentThreadId()) {
            InterlockedIncrement(&prev.repeats);
            prev.tick = GetTickCount();
            prev.addr = addr;
            return;
        }
    }

    // Lock-free: atomic increment gives us a unique slot
    LONG pos = InterlockedIncrement(&s_hookTracePos) - 1;
    int idx = pos & HOOK_TRACE_MASK;
    s_hookTrace[idx].hookName = hookName;
    s_hookTrace[idx].addr = addr;
    s_hookTrace[idx].tick = GetTickCount();
    s_hookTrace[idx].threadId = GetCurrentThreadId();
    s_hookTrace[idx].repeats = 0;
}

void RecordHookCallHot(const char* hookName, uintptr_t addr) {
    // Sample ~1/64 calls. The counter is a deliberately non-atomic increment:
    // a lost increment under thread contention only skews the sample rate, and
    // avoiding the InterlockedIncrement is the entire point on this hot path.
    // On x86 the aligned 32-bit load/store is itself tear-free, so no bad reads.
    static volatile LONG s_hotSkip = 0;
    LONG n = s_hotSkip + 1;
    s_hotSkip = n;
    if ((n & 0x3F) != 0) return;   // record only every 64th call
    RecordHookCall(hookName, addr);
}

} // namespace CrashDumper

LARGE_INTEGER StallProbeBegin() {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return t;
}

void StallProbeEnd(const char* what, const LARGE_INTEGER& start, double thresholdMs) {
    static LARGE_INTEGER freq = {};
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
        if (freq.QuadPart == 0) return;
    }
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    double ms = (double)(end.QuadPart - start.QuadPart) * 1000.0 / (double)freq.QuadPart;
    if (ms >= thresholdMs) {
        CrashDumper::Trace("STALL %s took %.1f ms", what, ms);
    }
}

StallProbe::StallProbe(const char* what, double thresholdMs)
    : m_what(what), m_thresholdMs(thresholdMs) {
    m_start = StallProbeBegin();
}

StallProbe::~StallProbe() {
    StallProbeEnd(m_what, m_start, m_thresholdMs);
}

extern "C" void CrashDumper_Trace(const char* fmt, ...) {
    if (!fmt) return;
    char buf[EVENT_TRACE_TEXT];
    va_list args;
    va_start(args, fmt);
    _vsnprintf(buf, sizeof(buf) - 1, fmt, args);
    va_end(args);
    buf[sizeof(buf) - 1] = '\0';
    CrashDumper::Trace("%s", buf);
}

// Called from lua_error_diag to dump hook trace on Lua errors
void CrashDumper_DumpHookTrace(int count) {
    if (count > HOOK_TRACE_SIZE) count = HOOK_TRACE_SIZE;
    LONG hpos = InterlockedCompareExchange(&s_hookTracePos, 0, 0);
    DWORD now = GetTickCount();
    int printed = 0;
    for (int i = 0; i < count && i < hpos; i++) {
        int idx = (hpos - 1 - i) & HOOK_TRACE_MASK;
        HookTraceEntry& e = s_hookTrace[idx];
        if (e.hookName && e.hookName[0]) {
            Log("    [%d] %s @ 0x%08X  TID=%lu  %ums ago",
                i, e.hookName, (unsigned)e.addr, e.threadId,
                (unsigned)(now - e.tick));
            printed++;
        }
    }
    if (printed == 0) {
        Log("    (no hook trace entries recorded)");
    }
}
