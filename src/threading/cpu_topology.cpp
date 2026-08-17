// ============================================================================
// Module: cpu_topology.cpp
// Description: Core-class topology, main-thread residency, performance pinning.
// Safety & Threading: Init and PinMainThread on the init thread; NoteFrame on
//              the main thread only. Nothing here touches client structures.
// ============================================================================
//
// The problem this exists for did not exist when this client shipped.
//
// Intel's hybrid parts (Alder Lake, 2021 onward) mix performance cores and
// efficiency cores, and Windows picks between them using the Thread Director's
// view of what a thread is doing. A frame loop that calls Sleep every frame -
// which this one does, and which this DLL makes more precise rather than less
// frequent - presents as a light, latency-tolerant load. That is the profile
// that gets parked on an efficiency core. An E-core is roughly half a P-core on
// single-threaded work, and this client does nearly everything on one thread.
//
// The existing thread-affinity code spreads the client's own worker threads
// over "every core from index 2 upwards". It knows nothing about core classes,
// and it never touches the main thread at all.
//
// Measurement first. The residency histogram below is the evidence: if the main
// thread already sits on performance cores, pinning it changes nothing and this
// module should say so rather than claim a win. Pinning is a separate switch.
//
// GetSystemCpuSetInformation is Windows 10 1607 and later. It is resolved at
// runtime, and its absence is reported, not silently treated as "no hybrid".
// EfficiencyClass is 0 for the slowest cores and rises; on a non-hybrid machine
// every core reports the same class, which this module then says plainly.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "cpu_topology.h"
#include "core/config.h"
#include "core/version.h"   // IsWine

extern "C" void Log(const char* fmt, ...);

namespace CpuTopology {

namespace {

constexpr int kMaxCpus = 64;

// Declared here rather than taken from the SDK: this project targets an old
// toolchain header set, and SYSTEM_CPU_SET_INFORMATION is not in all of them.
// Layout from the documented structure.
struct WO_SYSTEM_CPU_SET_INFORMATION {
    DWORD Size;
    DWORD Type;              // 0 = CpuSetInformation
    DWORD Id;
    WORD  Group;
    BYTE  LogicalProcessorIndex;
    BYTE  CoreIndex;
    BYTE  LastLevelCacheIndex;
    BYTE  NumaNodeIndex;
    BYTE  EfficiencyClass;
    BYTE  AllFlags;
    DWORD Reserved1;
    ULONGLONG AllocationTag;
};

typedef BOOL (WINAPI* GetSystemCpuSetInformation_fn)(
    WO_SYSTEM_CPU_SET_INFORMATION* Information, ULONG BufferLength,
    PULONG ReturnedLength, HANDLE Process, ULONG Flags);

// THREAD_POWER_THROTTLING_STATE, Windows 10 1709+.
struct WO_THREAD_POWER_THROTTLING_STATE {
    ULONG Version;
    ULONG ControlMask;
    ULONG StateMask;
};
constexpr ULONG WO_THREAD_POWER_THROTTLING_CURRENT_VERSION = 1;
constexpr ULONG WO_THREAD_POWER_THROTTLING_EXECUTION_SPEED = 0x1;
constexpr int   WO_ThreadPowerThrottling = 3;   // THREAD_INFORMATION_CLASS

typedef BOOL (WINAPI* SetThreadInformation_fn)(HANDLE, int, LPVOID, DWORD);

BYTE     g_effClass[kMaxCpus];
bool     g_known[kMaxCpus];
int      g_cpuCount     = 0;
BYTE     g_maxEffClass  = 0;
BYTE     g_minEffClass  = 0xFF;
bool     g_hybrid       = false;
bool     g_haveTopology = false;
const char* g_whyNot    = "not probed";

DWORD_PTR g_perfMask = 0;   // logical processors at the highest efficiency class

// Residency, sampled once per frame from the main thread. Plain counters: this
// runs on the frame boundary and a lock-prefixed increment there is exactly the
// kind of cost this project has already lost an optimization to.
uint64_t g_frames = 0;
uint64_t g_perCpu[kMaxCpus];

bool     g_pinned = false;
DWORD_PTR g_pinnedMask = 0;
bool     g_throttlingOff = false;

} // namespace

void Init() {
    memset(g_effClass, 0, sizeof(g_effClass));
    memset(g_known, 0, sizeof(g_known));
    memset(g_perCpu, 0, sizeof(g_perCpu));

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    GetSystemCpuSetInformation_fn pGet = k32
        ? (GetSystemCpuSetInformation_fn)GetProcAddress(k32, "GetSystemCpuSetInformation")
        : nullptr;

    if (!pGet) {
        g_whyNot = "GetSystemCpuSetInformation is not present (needs Windows 10 1607)";
        Log("[CpuTopology] Core classes unavailable: %s. Nothing here can run, and "
            "on a pre-hybrid machine there would be nothing to do anyway.", g_whyNot);
        return;
    }

    ULONG needed = 0;
    pGet(nullptr, 0, &needed, GetCurrentProcess(), 0);
    if (needed == 0) {
        g_whyNot = "the API returned no data";
        Log("[CpuTopology] Core classes unavailable: %s", g_whyNot);
        return;
    }

    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, needed);
    if (!buf) {
        g_whyNot = "allocation for the CPU set list failed";
        Log("[CpuTopology] Core classes unavailable: %s", g_whyNot);
        return;
    }

    ULONG got = 0;
    if (!pGet((WO_SYSTEM_CPU_SET_INFORMATION*)buf, needed, &got, GetCurrentProcess(), 0)) {
        HeapFree(GetProcessHeap(), 0, buf);
        g_whyNot = "the CPU set query failed";
        Log("[CpuTopology] Core classes unavailable: %s", g_whyNot);
        return;
    }

    ULONG off = 0;
    while (off + sizeof(DWORD) * 2 <= got) {
        WO_SYSTEM_CPU_SET_INFORMATION* e = (WO_SYSTEM_CPU_SET_INFORMATION*)(buf + off);
        if (e->Size == 0 || off + e->Size > got) break;
        if (e->Type == 0 && e->LogicalProcessorIndex < kMaxCpus) {
            int idx = e->LogicalProcessorIndex;
            g_effClass[idx] = e->EfficiencyClass;
            g_known[idx] = true;
            if (idx + 1 > g_cpuCount) g_cpuCount = idx + 1;
            if (e->EfficiencyClass > g_maxEffClass) g_maxEffClass = e->EfficiencyClass;
            if (e->EfficiencyClass < g_minEffClass) g_minEffClass = e->EfficiencyClass;
        }
        off += e->Size;
    }
    HeapFree(GetProcessHeap(), 0, buf);

    if (g_cpuCount == 0) {
        g_whyNot = "no CPU set entries were returned";
        Log("[CpuTopology] Core classes unavailable: %s", g_whyNot);
        return;
    }

    g_haveTopology = true;
    g_hybrid = (g_maxEffClass != g_minEffClass);

    int perf = 0, eff = 0;
    for (int i = 0; i < g_cpuCount; i++) {
        if (!g_known[i]) continue;
        if (g_effClass[i] == g_maxEffClass) {
            g_perfMask |= ((DWORD_PTR)1 << i);
            perf++;
        } else {
            eff++;
        }
    }

    if (g_hybrid) {
        Log("[CpuTopology] Hybrid CPU: %d logical processors, %d at the top "
            "efficiency class and %d below it. Windows decides which a thread "
            "runs on, and a frame loop that sleeps every frame is the kind of "
            "load it moves down.", g_cpuCount, perf, eff);
    } else {
        Log("[CpuTopology] %d logical processors, all one core class. Nothing to "
            "choose between here; the residency below still says whether the "
            "frame loop stays put.", g_cpuCount);
    }
}

void NoteFrame() {
    if (!Config::g_settings.OptCpuTopology) return;
    DWORD cpu = GetCurrentProcessorNumber();
    if (cpu < kMaxCpus) g_perCpu[cpu]++;
    g_frames++;
}

bool PinMainThread(HANDLE mainThread) {
    if (!Config::g_settings.OptPinMainThread) return false;
    if (!g_haveTopology) {
        Log("[CpuTopology] Not pinning: %s", g_whyNot);
        return false;
    }
    if (!g_hybrid) {
        // Pinning on a uniform machine takes choices away from the scheduler
        // and gives nothing back.
        Log("[CpuTopology] Not pinning: every core is the same class, so there is "
            "no faster one to move to.");
        return false;
    }
    if (g_perfMask == 0) {
        Log("[CpuTopology] Not pinning: no performance cores identified.");
        return false;
    }

    // Intersect with what the process is actually allowed to use, or this fails
    // outright on a machine where affinity was already restricted.
    DWORD_PTR procMask = 0, sysMask = 0;
    if (GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask) && procMask) {
        DWORD_PTR wanted = g_perfMask & procMask;
        if (wanted == 0) {
            Log("[CpuTopology] Not pinning: the process affinity mask excludes every "
                "performance core.");
            return false;
        }
        g_perfMask = wanted;
    }

    // The whole performance set, not one core: the point is to keep the thread
    // off the slow cores, not to stop Windows from balancing among the fast ones.
    if (SetThreadAffinityMask(mainThread, g_perfMask) == 0) {
        Log("[CpuTopology] Pinning failed (SetThreadAffinityMask, err=%lu)", GetLastError());
        return false;
    }
    g_pinned = true;
    g_pinnedMask = g_perfMask;

    // Separately, ask Windows to stop treating this thread as a candidate for
    // energy-efficient scheduling. Without this the hint that put it on a slow
    // core in the first place is still in force.
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    SetThreadInformation_fn pSet = k32
        ? (SetThreadInformation_fn)GetProcAddress(k32, "SetThreadInformation") : nullptr;
    if (pSet) {
        WO_THREAD_POWER_THROTTLING_STATE st;
        st.Version = WO_THREAD_POWER_THROTTLING_CURRENT_VERSION;
        st.ControlMask = WO_THREAD_POWER_THROTTLING_EXECUTION_SPEED;
        st.StateMask = 0;   // 0 = do not throttle
        if (pSet(mainThread, WO_ThreadPowerThrottling, &st, sizeof(st))) {
            g_throttlingOff = true;
        }
    }

    int n = 0;
    for (int i = 0; i < kMaxCpus; i++) if (g_pinnedMask & ((DWORD_PTR)1 << i)) n++;
    Log("[CpuTopology] Main thread pinned to %d performance cores (mask 0x%llX)%s",
        n, (unsigned long long)g_pinnedMask,
        g_throttlingOff ? ", power throttling disabled" : "");
    return true;
}

void Report() {
    if (!Config::g_settings.OptCpuTopology) return;

    if (!g_haveTopology) {
        Log("[CpuTopology] no topology read this session (%s)", g_whyNot);
        return;
    }
    if (g_frames == 0) {
        Log("[CpuTopology] topology known but no frame was sampled - the frame "
            "boundary never called in");
        return;
    }

    uint64_t onPerf = 0, onEff = 0;
    for (int i = 0; i < g_cpuCount; i++) {
        if (!g_known[i]) continue;
        if (g_effClass[i] == g_maxEffClass) onPerf += g_perCpu[i];
        else onEff += g_perCpu[i];
    }

    if (!g_hybrid) {
        Log("[CpuTopology] %llu frames sampled across %d cores of one class%s",
            (unsigned long long)g_frames, g_cpuCount,
            g_pinned ? " (pinned)" : "");
        return;
    }

    Log("[CpuTopology] %llu frames: %.1f%% on performance cores, %.1f%% on "
        "efficiency cores%s",
        (unsigned long long)g_frames,
        100.0 * (double)onPerf / (double)g_frames,
        100.0 * (double)onEff / (double)g_frames,
        g_pinned ? " (main thread pinned)" : " (not pinned)");

    if (!g_pinned && onEff > 0) {
        if (IsWine()) {
            // Saying "turn on PinMainThread" here would be advice that cannot
            // work: the thread setup it lives in is skipped entirely under a
            // translation layer, and scheduling is the host's business anyway.
            Log("[CpuTopology] Time is being spent on the slower cores, but the "
                "pinning is not available here: thread scheduling is left alone "
                "under Wine, where the host kernel makes these decisions.");
        } else {
            Log("[CpuTopology] Time on the slower cores is time this client cannot "
                "get back, because almost all of its work is on this one thread. "
                "PinMainThread=1 keeps it off them.");
        }
    }

    // Per-core detail, so a machine where one core is doing all the work is
    // distinguishable from one where the thread is migrating constantly.
    for (int i = 0; i < g_cpuCount; i++) {
        if (!g_known[i] || g_perCpu[i] == 0) continue;
        Log("[CpuTopology]   cpu%-3d class %d  %6.2f%%", i, g_effClass[i],
            100.0 * (double)g_perCpu[i] / (double)g_frames);
    }
}

} // namespace CpuTopology
