// ============================================================================
// Module: freeze_catcher
// Description: Samples the main thread only while a frame is already long, so
//              a freeze says what it was doing.
// Safety & Threading: A watchdog thread; the main thread is touched only during
//                     a frame that has already overrun.
// ============================================================================
// The worst thing in the field data is a frame that took 1918 ms - three hundred
// and forty-three times the median - and this is the whole of what the log could
// say about it:
//
//     slow frame: 1918.3 ms (342.6x the 5.60 ms median) - events within it:
//     (nothing traced in this window)
//
// The flight recorder has columns for archive opens, our own hooks, file reads,
// file writes and socket receives, and not one of them moved. The same session
// has a 1068 ms frame, an 880 ms frame and a hundred and forty frames over a
// hundred milliseconds. Whatever they are, they are CPU work nobody instruments,
// and they are the only thing in this project a player can actually feel.
//
// The sampling profiler could answer it and is switched off in every field log,
// because sampling a thousand times a second all session is a real cost and one
// reporter traced longer loading screens to having it on. Their conclusion was
// right for a profiler and wrong for this question: nothing needs sampling while
// frames are fine.
//
// So this watches instead. A thread wakes every few milliseconds, reads how long
// the current frame has been running, and does nothing at all unless that is
// already past the arm threshold. Inside a frame that has overrun it samples
// hard, and when the frame finally ends it prints where the main thread was.
// Normal frames cost one clock read and one comparison per wake-up, on a thread
// that is asleep the rest of the time; the main thread is never suspended during
// a frame that is behaving.
// ---------------------------------------------------------------------------
// The stamp, and why it is milliseconds
//
// The watchdog has to read the frame's start from another thread. A 64-bit QPC
// value read across threads on x86 can tear between its halves, and a torn
// start time would arm the catcher inside a frame that is fine or hide one that
// is not. A 32-bit millisecond count cannot tear on this architecture, and a
// millisecond is four hundred times finer than the events being caught.
// ---------------------------------------------------------------------------
// What it prints
//
// The addresses, grouped, most-sampled first. Not symbols: this project reads
// wow.exe in IDA and an address is what it wants - the profiler's own reports
// name their hottest entries the same way, and the one that found the UI layout
// relink at 9% did it by printing wow!0x00489763 and nothing else.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include "freeze_catcher.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

namespace FreezeCatcher {

namespace {

// A frame past this is not a frame any more, it is a stall worth explaining.
// The field median is 5.6 to 9 ms and the events being caught are 100 ms and up.
constexpr long kArmMs   = 60;
constexpr DWORD kWakeMs = 4;     // how often the watchdog looks
constexpr DWORD kFastMs = 1;     // how often it samples once armed
constexpr DWORD kSlowestMs = 64; // the floor on thinning; see the note below
// First report from inside a frame that has not ended, then four times later
// each time (3 s, 12 s, 48 s), so a long stall costs a few lines and no more.
constexpr long kFirstInterimMs = 3000;

constexpr int kRing = 512;

HANDLE g_main    = nullptr;
HANDLE g_thread  = nullptr;
volatile LONG g_running = 0;

// Milliseconds since init, stamped by the main thread at every frame boundary.
// 32-bit so a cross-thread read cannot tear.
volatile LONG g_frameStartMs = 0;
LARGE_INTEGER g_freq = {};
LARGE_INTEGER g_base = {};

// Where the call came from, taken in the same suspension as the address: the
// word on top of the stack and the return addresses up the frame-pointer chain.
// An address inside ntdll says the main thread was waiting; only the callers say
// what it was waiting for.
constexpr int kChain = 4;
uintptr_t g_eip[kRing];
uintptr_t g_chain[kRing][kChain];
long      g_atMs[kRing];
volatile LONG g_count = 0;       // samples in the current armed window

// Totals for the report.
unsigned long g_frames   = 0;
unsigned long g_caught   = 0;    // frames that armed it
unsigned long g_samples  = 0;
unsigned long g_worstMs  = 0;
unsigned long g_wakes    = 0;
unsigned long g_thinned  = 0;    // times a stall outlasted the ring

long NowMs() {
    LARGE_INTEGER n;
    QueryPerformanceCounter(&n);
    if (!g_freq.QuadPart) return 0;
    return (long)(((n.QuadPart - g_base.QuadPart) * 1000) / g_freq.QuadPart);
}

// A readable dword, or false. The main thread is suspended while this runs, so
// its stack cannot change under the read, but a frame pointer is not always a
// frame pointer.
bool ReadWord(uintptr_t a, uintptr_t* out) {
    if (a < 0x10000u || (a & 3u)) return false;
    __try {
        *out = *(const volatile uintptr_t*)a;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void CaptureChain(const CONTEXT& ctx, uintptr_t* out) {
    for (int k = 0; k < kChain; ++k) out[k] = 0;
    uintptr_t top = 0;
    ReadWord((uintptr_t)ctx.Esp, &top);
    out[0] = top;
    uintptr_t ebp = (uintptr_t)ctx.Ebp;
    const uintptr_t esp = (uintptr_t)ctx.Esp;
    for (int k = 1; k < kChain; ++k) {
        // The stack grows down, so a caller's frame is above this one, and a
        // frame pointer that is not is a register in use for something else.
        if (ebp < esp || ebp - esp > 0x100000u) break;
        uintptr_t ret = 0, next = 0;
        if (!ReadWord(ebp + 4, &ret) || !ReadWord(ebp, &next)) break;
        out[k] = ret;
        if (next <= ebp) break;
        ebp = next;
    }
}

// The exported name at or just before an address inside a module, for the
// system DLLs whose code the main thread waits in. Walks the export table of a
// module that is already mapped; reads only.
const char* NearestExport(HMODULE m, uintptr_t addr, unsigned* delta) {
    __try {
        const uint8_t* base = (const uint8_t*)m;
        const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
        const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        const IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!dir.VirtualAddress) return nullptr;
        const IMAGE_EXPORT_DIRECTORY* exp = (const IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
        const DWORD* funcs = (const DWORD*)(base + exp->AddressOfFunctions);
        const DWORD* names = (const DWORD*)(base + exp->AddressOfNames);
        const WORD*  ords  = (const WORD*)(base + exp->AddressOfNameOrdinals);
        const uintptr_t rva = addr - (uintptr_t)base;
        DWORD best = 0;
        const char* bestName = nullptr;
        for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
            const DWORD f = funcs[ords[i]];
            // A forwarder's "address" is the string that names its target.
            if (f >= dir.VirtualAddress && f < dir.VirtualAddress + dir.Size) continue;
            if (f <= rva && f > best) { best = f; bestName = (const char*)(base + names[i]); }
        }
        if (bestName && rva - best < 0x4000u) { *delta = (unsigned)(rva - best); return bestName; }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return nullptr;
}

// "wow!0x...", or the module and the export the address is in. Anything that
// is not the client or this DLL is named, because a bare address in ntdll is
// not something anyone can look up.
void Describe(uintptr_t a, char* out, size_t cap) {
    if (!a) { snprintf(out, cap, "0"); return; }
    if (a >= 0x00400000u && a <= 0x00BFFFFFu) { snprintf(out, cap, "wow!0x%08X", (unsigned)a); return; }
    HMODULE m = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)a, &m) && m) {
        char path[MAX_PATH] = {};
        GetModuleFileNameA(m, path, MAX_PATH);
        const char* base = strrchr(path, 92);
        base = base ? base + 1 : path;
        unsigned delta = 0;
        const char* ex = NearestExport(m, a, &delta);
        if (ex) snprintf(out, cap, "%s!%s+0x%X (0x%08X)", base, ex, delta, (unsigned)a);
        else    snprintf(out, cap, "%s+0x%X (0x%08X)", base, (unsigned)(a - (uintptr_t)m), (unsigned)a);
        return;
    }
    snprintf(out, cap, "other!0x%08X", (unsigned)a);
}

const char* Where(uintptr_t a) {
    if (a >= 0x00400000u && a <= 0x00BFFFFFu) return "wow";
    if (a >= 0x10000000u && a <= 0x11000000u) return "wowopt";
    return "other";
}

void PrintSamples(const char* what, long len, int take) {
    // How much of the frame these samples actually cover. Printed because
    // the ring thins rather than stopping, so the density is not uniform and
    // the reader should not assume one sample per millisecond.
    long spanTo = 0;
    for (int i = 0; i < take; ++i) if (g_atMs[i] > spanTo) spanTo = g_atMs[i];
    Log("[FreezeCatcher] %s %ld ms, %d sample(s) of where the main "
        "thread was while it ran, reaching %ld ms into it (%.0f%%):",
        what, len, take, spanTo, len > 0 ? 100.0 * (double)spanTo / (double)len : 0.0);

    // Group by address without sorting in place - the ring is small and this
    // runs once per caught frame, not per sample.
    bool done[kRing];
    memset(done, 0, sizeof(done));
    for (int printed = 0; printed < 8; ++printed) {
        int best = -1, bestCount = 0;
        for (int i = 0; i < take; ++i) {
            if (done[i]) continue;
            int c = 0;
            for (int j = 0; j < take; ++j)
                if (!done[j] && g_eip[j] == g_eip[i]) ++c;
            if (c > bestCount) { bestCount = c; best = i; }
        }
        if (best < 0) break;
        Log("[FreezeCatcher]   %s!0x%08X  %d sample(s), first at %ld ms in",
            Where(g_eip[best]), (unsigned)g_eip[best], bestCount,
            g_atMs[best]);

        // Name it, and say who called it. The chain printed is the one most of
        // this address's samples agree on (top of stack and first return
        // address), so one odd sample does not decide what a stall was waiting
        // for. The client's own addresses are already what this project reads in
        // IDA and are named only when the address is not in the client.
        int rep = best, repCount = 0;
        for (int i = 0; i < take; ++i) {
            if (g_eip[i] != g_eip[best]) continue;
            int c = 0;
            for (int j = 0; j < take; ++j)
                if (g_eip[j] == g_eip[best] && g_chain[j][0] == g_chain[i][0] &&
                    g_chain[j][1] == g_chain[i][1]) ++c;
            if (c > repCount) { repCount = c; rep = i; }
        }
        char d[160];
        if (Where(g_eip[best])[0] == 'o') {
            Describe(g_eip[best], d, sizeof(d));
            Log("[FreezeCatcher]     in %s", d);
        }
        char line[640];
        int len = snprintf(line, sizeof(line), "[FreezeCatcher]     stack:");
        for (int k = 0; k < kChain && len > 0 && len < (int)sizeof(line) - 170; ++k) {
            if (!g_chain[rep][k]) continue;
            Describe(g_chain[rep][k], d, sizeof(d));
            len += snprintf(line + len, sizeof(line) - len, "%s %s", k ? "  <-" : "", d);
        }
        Log("%s", line);

        for (int j = 0; j < take; ++j)
            if (g_eip[j] == g_eip[best]) done[j] = true;
    }
}

DWORD WINAPI WatchdogProc(LPVOID) {
    while (InterlockedCompareExchange(&g_running, 1, 1)) {
        const long start = g_frameStartMs;
        const long age   = NowMs() - start;
        ++g_wakes;

        if (age < kArmMs) {
            Sleep(kWakeMs);
            continue;
        }

        // This frame has already overrun. Sample it until it ends; the main
        // thread is only suspended from here.
        //
        // A full ring must not end the sampling: that describes a stall by its
        // first 512 milliseconds and nothing else, which is 9% of a 5860 ms
        // loading screen and misses the part nothing else accounts for.
        //
        // So a full ring thins instead: every other sample is kept,
        // which leaves 256 spread evenly over the whole elapsed window, and the
        // interval doubles so the next 256 cover twice as long. Repeating that
        // describes a stall of any length with a fixed 512 slots, at a
        // resolution that halves each time. A 5860 ms load thins four times and
        // ends up sampled about every 16 ms across all of it, instead of every
        // millisecond across the first twelfth.
        DWORD interval = kFastMs;
        long nextInterimMs = kFirstInterimMs;
        while (InterlockedCompareExchange(&g_running, 1, 1) &&
               g_frameStartMs == start) {
            const long at = NowMs() - start;

            // A frame that never ends is reported by nobody: OnFrame prints
            // only when the next boundary arrives, and a session that stops in
            // the frame (a window closed on a black screen, a hang) leaves its
            // samples in the ring and out of the log. Say where the main thread
            // is while it is still there.
            if (at >= nextInterimMs) {
                const LONG have = g_count;
                if (have > 0)
                    PrintSamples("a frame still running after", at,
                                 (int)(have < kRing ? have : kRing));
                nextInterimMs *= 4;
            }
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (SuspendThread(g_main) != (DWORD)-1) {
                uintptr_t eip = 0;
                uintptr_t chain[kChain] = {};
                if (GetThreadContext(g_main, &ctx)) {
                    eip = (uintptr_t)ctx.Eip;
                    CaptureChain(ctx, chain);
                }
                ResumeThread(g_main);
                const LONG i = InterlockedIncrement(&g_count) - 1;
                if (i < kRing && eip) {
                    g_eip[i] = eip;
                    for (int k = 0; k < kChain; ++k) g_chain[i][k] = chain[k];
                    g_atMs[i] = at;
                } else if (i >= kRing) {
                    // Re-check the frame before compacting. OnFrame stamps the
                    // new frame first and then reads the ring, so this test
                    // leaves only a window of a few instructions in which both
                    // could touch it - and the worst that produces is a repeated
                    // address in one report, never an unsafe read.
                    if (g_frameStartMs != start) break;
                    for (int k = 0; k * 2 < kRing; ++k) {
                        g_eip[k]  = g_eip[k * 2];
                        for (int c = 0; c < kChain; ++c) g_chain[k][c] = g_chain[k * 2][c];
                        g_atMs[k] = g_atMs[k * 2];
                    }
                    InterlockedExchange(&g_count, kRing / 2);
                    if (interval < kSlowestMs) interval *= 2;
                    ++g_thinned;
                }
            }
            Sleep(interval);
        }
    }
    return 0;
}

}  // namespace

void OnFrame() {
    ++g_frames;

    const long now = NowMs();
    const long was = g_frameStartMs;
    const long len = now - was;

    // Stamp the new frame BEFORE reading the ring, not after. The watchdog's
    // inner loop runs while g_frameStartMs still equals the frame it armed on,
    // so leaving the stamp until the end of this function meant it went on
    // writing samples into the ring being read here. One statement, and the
    // only place in this module where two threads touch the same memory.
    g_frameStartMs = now;

    // The frame that just ended. If the watchdog armed on it, say what it saw.
    const LONG n = InterlockedExchange(&g_count, 0);
    if (n > 0 && len >= kArmMs) {
        ++g_caught;
        g_samples += (unsigned long)(n < kRing ? n : kRing);
        if ((unsigned long)len > g_worstMs) g_worstMs = (unsigned long)len;

        PrintSamples("a frame of", len, (int)(n < kRing ? n : kRing));
    }
}

bool Init(HANDLE mainThread) {
    if (!Config::g_settings.OptFreezeCatcher) return true;
    if (!mainThread) {
        Log("[FreezeCatcher] NOT active: no handle to the main thread.");
        return false;
    }
    QueryPerformanceFrequency(&g_freq);
    QueryPerformanceCounter(&g_base);
    if (!g_freq.QuadPart) {
        Log("[FreezeCatcher] NOT active: no performance counter.");
        return false;
    }

    // The caller closes its handle as soon as Init returns, the way it does
    // for the sampling profiler, so this keeps its own.
    if (!DuplicateHandle(GetCurrentProcess(), mainThread, GetCurrentProcess(),
                         &g_main, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        Log("[FreezeCatcher] NOT active: could not duplicate the main thread "
            "handle (error %lu).", GetLastError());
        return false;
    }
    g_frameStartMs = NowMs();
    InterlockedExchange(&g_running, 1);
    g_thread = CreateThread(nullptr, 0, WatchdogProc, nullptr, 0, nullptr);
    if (!g_thread) {
        InterlockedExchange(&g_running, 0);
        Log("[FreezeCatcher] NOT active: the watchdog thread would not start.");
        return false;
    }

    Log("[FreezeCatcher] ACTIVE. The worst frame in the field data is 1918 ms "
        "and the log's whole account of it is \"nothing traced in this window\" "
        "- the flight recorder's columns are archive opens, our hooks, file "
        "reads and writes and socket receives, and none of them moved. This "
        "watches instead of sampling: a thread wakes every %u ms, and does "
        "nothing until the frame in progress is already past %ld ms. Only then "
        "is the main thread touched, and only until that frame ends. A frame "
        "that behaves costs one clock read and one comparison on a sleeping "
        "thread.", kWakeMs, kArmMs);
    return true;
}

void Shutdown() {
    InterlockedExchange(&g_running, 0);
    if (g_thread) {
        WaitForSingleObject(g_thread, 1000);
        CloseHandle(g_thread);
        g_thread = nullptr;
    }
}

void LogStats() {
    if (!Config::g_settings.OptFreezeCatcher) return;
    if (!g_thread) {
        Log("[FreezeCatcher] switched on but not watching, so nothing here was "
            "measured.");
        return;
    }
    if (g_caught == 0) {
        Log("[FreezeCatcher] %lu frames watched over %lu wake-ups and none of "
            "them ran past %ld ms. Measured and zero: there was nothing to "
            "catch, not nothing looking.", g_frames, g_wakes, kArmMs);
        return;
    }
    Log("[FreezeCatcher] %lu frames watched, %lu of them ran past %ld ms and "
        "were sampled, %lu samples in total, worst frame %lu ms. Each one is "
        "printed above with the addresses it was caught at.",
        g_frames, g_caught, kArmMs, g_samples, g_worstMs);
    // Printed whether or not it happened. Zero means every stall fitted in the
    // ring at full rate; a large number means the stalls are long enough that
    // the ring is describing them at reduced resolution, which is the intended
    // behaviour and not a fault.
    Log("[FreezeCatcher]   the ring was thinned %lu time(s) - each halves the "
        "samples kept and doubles the interval, down to one every %u ms, so a "
        "stall longer than the ring is described across all of itself rather "
        "than across its first half second.", g_thinned, kSlowestMs);
}

}  // namespace FreezeCatcher
