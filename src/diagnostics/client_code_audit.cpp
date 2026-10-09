// ============================================================================
// Module: client_code_audit.cpp
//
// What is actually different in wow.exe's code, as opposed to what the log says.
//
// "No Client Patches" is a promise to a server that removes players for a patched
// client, and until 2026-10-08 it was broken without any log line saying so:
// kromvel85's session on WoW Circle, with the switch on, logged four client hooks
// as ACTIVE (fourteen files called MinHook directly and never asked the gate). The
// log's own claims were the only evidence anyone looked at, and a module that
// installs a hook is also the module that says whether it did.
//
// This reads the code sections of the running image and the same sections from
// the executable file on disk and lists where they differ. It does not care who
// wrote the bytes: a MinHook detour of this DLL's, the same of another module's
// (AwesomeWotlkLib, ClientExtensions and a launcher's own patcher all write into
// wow.exe), or a write from anything else. For each place it says whether this
// DLL recorded a hook within a few bytes of it. With No Client Patches on, a place
// this DLL recorded is a broken promise and goes to the verdict list.
//
// What it cannot see: a patch made to the file on disk before the process started
// (the running code and the file agree), and anything outside the code sections.
// It reads the file once, 45 seconds after the start so that other injectors have
// finished, on a thread of its own, and again every twenty minutes. The report is
// printed from the periodic report, which runs on the main thread; the thread only
// fills the result.
//
// Three states, never two: not run yet, could not run (and why), measured. A
// measured zero is a statement; an empty list is not.
// ============================================================================

#include "client_code_audit.h"
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include "config.h"
#include "version.h"
#include "session_verdict.h"

extern "C" void Log(const char* fmt, ...);
extern "C" bool WowOpt_IsRecordedHookTarget(uintptr_t addr, uintptr_t slack);

namespace ClientCodeAudit {
namespace {

constexpr int kMaxPlaces = 24;
constexpr DWORD kFirstRunDelayMs = 45000;
constexpr DWORD kRepeatMs = 20u * 60u * 1000u;
constexpr uintptr_t kRecordedSlack = 8;

struct Place { uintptr_t addr; unsigned len; bool ours; };

volatile LONG g_state = 0;                 // 0 not run, 1 measured, 2 could not run
char          g_why[96] = {};
unsigned long g_codeBytes = 0, g_sections = 0;
unsigned long g_diffBytes = 0, g_places = 0, g_ours = 0, g_foreign = 0;
Place         g_first[kMaxPlaces] = {};
unsigned long g_runs = 0;
bool          g_verdictAdded = false;
HANDLE        g_thread = nullptr;

void Fail(const char* why) {
    lstrcpynA(g_why, why, sizeof(g_why));
    InterlockedExchange(&g_state, 2);
}

void Run() {
    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, path, MAX_PATH)) { Fail("the executable's path is not available"); return; }

    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) { Fail("the executable could not be opened"); return; }
    LARGE_INTEGER sz = {};
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart < 4096 || sz.QuadPart > 64ll * 1024 * 1024) {
        CloseHandle(f);
        Fail("the executable's size is not one this reads");
        return;
    }
    // From above 2GB when the address space allows it, so that the 7 MB copy does not sit in the half
    // the client allocates from, even briefly.
    uint8_t* buf = (uint8_t*)VirtualAlloc(nullptr, (SIZE_T)sz.QuadPart, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
    if (!buf) buf = (uint8_t*)VirtualAlloc(nullptr, (SIZE_T)sz.QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { CloseHandle(f); Fail("no memory for the file"); return; }
    DWORD got = 0;
    const BOOL read = ReadFile(f, buf, (DWORD)sz.QuadPart, &got, nullptr);
    CloseHandle(f);
    if (!read || got != (DWORD)sz.QuadPart) { VirtualFree(buf, 0, MEM_RELEASE); Fail("the executable could not be read"); return; }

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || (uint32_t)dos->e_lfanew > (uint32_t)sz.QuadPart - sizeof(IMAGE_NT_HEADERS)) {
        VirtualFree(buf, 0, MEM_RELEASE); Fail("the file is not a PE image"); return;
    }
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { VirtualFree(buf, 0, MEM_RELEASE); Fail("the file is not a PE image"); return; }
    const uint8_t* base = (const uint8_t*)GetModuleHandleA(nullptr);
    if (!base) { VirtualFree(buf, 0, MEM_RELEASE); Fail("the running image is not found"); return; }
    // A relocated image has every absolute address in its code rewritten by the loader, and each of
    // those bytes would be counted as a patch. wow.exe 3.3.5a loads at its preferred base.
    if ((uintptr_t)base != (uintptr_t)nt->OptionalHeader.ImageBase) {
        VirtualFree(buf, 0, MEM_RELEASE);
        Fail("the image was relocated, so its code differs from the file by the loader's own fixups");
        return;
    }

    unsigned long codeBytes = 0, sections = 0, diffBytes = 0, places = 0, ours = 0, foreign = 0;
    Place first[kMaxPlaces] = {};
    int nFirst = 0;

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
        const IMAGE_SECTION_HEADER& sh = sec[s];
        if (!(sh.Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE))) continue;
        const DWORD n = sh.SizeOfRawData < sh.Misc.VirtualSize ? sh.SizeOfRawData : sh.Misc.VirtualSize;
        if (!n || sh.PointerToRawData + (uint64_t)n > (uint64_t)sz.QuadPart) continue;
        ++sections;
        codeBytes += n;
        const uint8_t* mem = base + sh.VirtualAddress;
        const uint8_t* disk = buf + sh.PointerToRawData;

        // One open run of differing bytes, closed when eight clean bytes pass: a five byte
        // jump and the bytes a hook left after it are one place, not two.
        uintptr_t runStart = 0, runEnd = 0;
        bool open = false;
        auto close = [&]() {
            if (!open) return;
            ++places;
            const bool mine = WowOpt_IsRecordedHookTarget(runStart, kRecordedSlack);
            if (mine) ++ours; else ++foreign;
            if (nFirst < kMaxPlaces) { first[nFirst].addr = runStart; first[nFirst].len = (unsigned)(runEnd - runStart + 1); first[nFirst].ours = mine; ++nFirst; }
            open = false;
        };
        __try {
            for (DWORD i = 0; i < n; ) {
                // Whole clean blocks are skipped with one compare.
                if (i + 64 <= n && memcmp(mem + i, disk + i, 64) == 0) { i += 64; continue; }
                const DWORD end = (i + 64 < n) ? i + 64 : n;
                for (; i < end; ++i) {
                    if (mem[i] != disk[i]) {
                        const uintptr_t a = (uintptr_t)(mem + i);
                        if (open && a - runEnd > 8) close();
                        if (!open) { runStart = a; open = true; }
                        runEnd = a;
                        ++diffBytes;
                    }
                }
                if (open && (uintptr_t)(mem + i) - runEnd > 8) close();
            }
            close();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            VirtualFree(buf, 0, MEM_RELEASE);
            Fail("reading the running image faulted");
            return;
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    if (sections == 0) { Fail("no code section was found to compare"); return; }

    g_codeBytes = codeBytes; g_sections = sections;
    g_diffBytes = diffBytes; g_places = places; g_ours = ours; g_foreign = foreign;
    memcpy(g_first, first, sizeof(first));
    ++g_runs;
    InterlockedExchange(&g_state, 1);
}

DWORD WINAPI Worker(LPVOID) {
    Sleep(kFirstRunDelayMs);
    for (;;) {
        Run();
        Sleep(kRepeatMs);
    }
}

} // namespace

void Init() {
    if (!Config::g_settings.OptClientCodeAudit) return;
    if (RunningUnderTranslation()) {
        Log("[ClientCodeAudit] NOT run: not under Wine or Rosetta.");
        return;
    }
    g_thread = CreateThread(nullptr, 128 * 1024, Worker, nullptr, 0, nullptr);
    if (!g_thread) { Log("[ClientCodeAudit] NOT run: the thread could not be created."); return; }
    SetThreadPriority(g_thread, THREAD_PRIORITY_BELOW_NORMAL);
    Log("[ClientCodeAudit] ACTIVE: wow.exe's code in memory is compared with the file on disk %lu s after the start and every "
        "%lu minutes, and the places that differ are listed.", (unsigned long)(kFirstRunDelayMs / 1000), (unsigned long)(kRepeatMs / 60000));
}

void Shutdown() {
}

void LogStats() {
    if (!Config::g_settings.OptClientCodeAudit) return;
    if (!g_thread) { Log("[ClientCodeAudit] not run, so nothing here was measured."); return; }
    const LONG state = g_state;
    if (state == 0) { Log("[ClientCodeAudit] not run yet: the first comparison is %lu s after the start.", (unsigned long)(kFirstRunDelayMs / 1000)); return; }
    if (state == 2) { Log("[ClientCodeAudit] could not compare: %s.", g_why); return; }

    const bool noPatches = WowOpt_NoClientPatches() != 0;
    Log("[ClientCodeAudit] wow.exe code in memory against the file on disk (%lu byte(s) of code in %lu section(s), run %lu): "
        "%lu byte(s) differ in %lu place(s), %lu recorded as this DLL's hooks and %lu not.%s",
        g_codeBytes, g_sections, g_runs, g_diffBytes, g_places, g_ours, g_foreign,
        g_places == 0 ? " Measured and zero: the running code is the file's." : "");
    if (g_places > 0) {
        const unsigned long shown = g_places < (unsigned long)kMaxPlaces ? g_places : (unsigned long)kMaxPlaces;
        for (unsigned long i = 0; i < shown; ++i)
            Log("[ClientCodeAudit]   0x%08X  %u byte(s)  %s", (unsigned)g_first[i].addr, g_first[i].len,
                g_first[i].ours ? "this DLL's hook" : "not recorded by this DLL (another module, or a write from elsewhere)");
        if (g_places > shown) Log("[ClientCodeAudit]   and %lu more place(s) not listed.", g_places - shown);
    }
    if (noPatches && g_ours > 0 && !g_verdictAdded) {
        g_verdictAdded = true;
        Verdict::Add(Verdict::Bad, "No Client Patches is on and %lu place(s) in wow.exe's code carry this DLL's hooks", g_ours);
    }
    if (noPatches && g_ours == 0)
        Log("[ClientCodeAudit]   No Client Patches is on and none of the places is one this DLL recorded.");
}

} // namespace ClientCodeAudit
