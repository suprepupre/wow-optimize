// ============================================================================
// Who holds the address space, and moving the large reservations above 2GB.
//
// Every out-of-memory report from this client ends the same way: the process
// cannot find a contiguous block, and the dumps say how much private memory
// sits below 2GB but never whose it is. The occupancy dump names images and
// mapped sections by file and has to call everything else "private" - 1377 MB
// in 4461 regions in the last tester log - because nothing on the path that
// created those regions wrote down who asked.
//
// That path is NtAllocateVirtualMemory, and on Windows 10 and later also
// NtAllocateVirtualMemoryEx. VirtualAlloc, the C runtime, mimalloc, DXVK and
// the GPU driver reserve through them, and so does ntdll's heap when it grows,
// which is why the VirtualAlloc arena (VaArena) never saw heap growth. The
// second entry point is not optional: a standalone test reserved an 8 MB heap
// block that a hook on the first one alone never saw.
//
// Both are hooked, with NtFreeVirtualMemory, and one entry is kept per live
// private reservation, indexed by its base. Windows places reservations on a
// 64 KB granularity, so a 4 GB space has 65536 possible bases, and a
// direct-mapped table of that many entries needs no hashing and no lock. Each
// entry names the module that asked.
//
// Finding the module. The first return address outside ntdll, kernel32,
// kernelbase and the C runtimes is the caller. RtlCaptureStackBackTrace follows
// frame pointers, and the system DLLs between this hook and the caller keep
// them, so the caller's return address is on the chain even when the caller
// itself was built without. When the walk still yields only system frames, the
// stack is scanned for a word inside a non-system module with a call
// instruction ending at it. Both ways are counted, and so are the reservations
// neither could attribute, so the report says what it did not see.
// Reservations that already existed when the hook went in are recorded once,
// from an address-space walk, under their own name: their callers are gone.
//
// Nothing on the hooked path takes a lock or allocates. It runs inside heap
// growth with the heap lock held and inside DLL loads with the loader lock
// held, and either would deadlock. The module list it attributes against is
// rebuilt elsewhere and published by swapping a pointer.
//
// Moving reservations up. With a switch on, a reservation of at least
// HighPlacementMinKB from an enabled class of caller gets MEM_TOP_DOWN added,
// so on a large-address-aware client it lands above 2GB and leaves the low
// half's contiguous space alone. This is placement only: nothing is
// redirected, the caller frees it the ordinary way, and a reservation that
// names an address, asks for zero high bits or carries extended parameters is
// passed through untouched. A top-down request that fails is retried exactly
// as the caller made it, so this cannot turn a success into a failure.
//
// The two classes are separate switches because they carry different risk.
// Modules other than wow.exe - DXVK, the GPU driver, other injected DLLs - are
// ordinary modern code. wow.exe is 2008 code whose large-address-aware flag was
// set by a patch rather than by its authors, and nothing has checked that every
// path in it treats a pointer above 2GB as unsigned. One observation is in its
// favour and it is not a proof: a tester's client kept running for a minute
// after the low half had run out, which it could only do on memory the OS
// placed above 2GB. And one limit on the module class: a heap segment placed
// high because a module grew a shared heap is afterwards used by every caller
// of that heap, wow.exe included.
//
// Not covered: NtMapViewOfSection. Mapped files and GPU-mapped memory reserve
// through it, and they are the "mapped" figure in the occupancy dump.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>

#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "high_placement.h"
#include "mimalloc_high_arena.h"
#include <cstdio>

extern "C" void Log(const char* fmt, ...);
extern "C" bool mi_is_in_heap_region(const void* p);

namespace HighPlacement {
namespace {

typedef LONG (NTAPI* NtAllocateVirtualMemory_fn)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
// Seven arguments: the WoW64 stub returns with ret 1Ch. Same order as
// VirtualAlloc2 in memoryapi.h, with the base and the size passed by pointer as
// in every other Nt allocation call. The standalone test calls it directly to
// confirm the order before anything here relies on it.
typedef LONG (NTAPI* NtAllocateVirtualMemoryEx_fn)(HANDLE, PVOID*, PSIZE_T, ULONG, ULONG, PVOID, ULONG);
typedef LONG (NTAPI* NtFreeVirtualMemory_fn)(HANDLE, PVOID*, PSIZE_T, ULONG);

NtAllocateVirtualMemory_fn   orig_NtAllocateVirtualMemory   = nullptr;
NtAllocateVirtualMemoryEx_fn orig_NtAllocateVirtualMemoryEx = nullptr;
NtFreeVirtualMemory_fn       orig_NtFreeVirtualMemory       = nullptr;

const HANDLE    kCurrentProcess = (HANDLE)(LONG_PTR)-1;
const uintptr_t kLowHalfEnd     = 0x80000000u;

const unsigned char kClassUnresolved = 0;
const unsigned char kClassBefore     = 1;
const unsigned char kClassClient     = 2;
const unsigned char kClassOurs       = 3;
const unsigned char kClassSystem     = 4;
const unsigned char kClassOther      = 5;

// A slot names one module for the whole session, so counters and live entries
// survive the module list being rebuilt. Slot 0 is "caller not found" and slot 1
// is "existed before install"; modules take the rest in the order first seen.
const LONG kMaxSlots       = 256;
const LONG kSlotUnresolved = 0;
const LONG kSlotBefore     = 1;

struct Slot {
    uintptr_t     base;
    uintptr_t     end;
    unsigned char cls;
    char          name[39];
};
Slot g_slots[kMaxSlots];
volatile LONG g_slotCount = 2;

// Plain counters. Several threads reserve at once and an increment can be lost,
// so every figure printed from these is a lower bound.
ULONG g_slotReserves[kMaxSlots];
ULONG g_slotTopDown[kMaxSlots];

struct ModuleRange { uintptr_t base; uintptr_t end; LONG slot; };
struct ModuleTable { LONG count; ModuleRange mod[kMaxSlots]; };
ModuleTable g_tables[2];
ModuleTable* volatile g_currentTable = nullptr;
SRWLOCK g_refreshLock = SRWLOCK_INIT;
DWORD   g_lastRefreshTick = 0;

// One entry per possible 64 KB allocation base. Zero size means no entry.
struct LiveEntry { ULONG sizeKB; USHORT slot; USHORT reserved; };
const ULONG kLiveEntries = 65536;
LiveEntry* g_live = nullptr;

// Where this DLL's own reservations below 2GB were asked for. The census says
// how much a module holds in the half the client allocates from, and for this
// DLL that was 144 MB in 31 reservations with nothing to say what they were.
// Entries are kept as they are made and checked against the live table when
// reported, so one that has been freed since is not listed.
struct OursEntry { uintptr_t base; ULONG sizeKB; uintptr_t ret; };
const LONG kOursMax = 256;
OursEntry     g_ours[kOursMax];
volatile LONG g_oursCount = 0;

HMODULE g_self = nullptr;
HMODULE g_client = nullptr;
bool    g_installed = false;
const char* g_exState = "not looked for";

ULONG g_reserveCalls = 0, g_reserveCallsEx = 0;
ULONG g_attribWalk = 0, g_attribScan = 0, g_attribNone = 0;
ULONG g_topDownAdded = 0, g_topDownHigh = 0, g_topDownLow = 0, g_topDownRetried = 0;
ULONG g_heapGrowthLeft = 0;                   // reservations made by ntdll itself that were not moved
uintptr_t g_ntdllLo = 0, g_ntdllSize = 0;
ULONG g_liveOverwrites = 0;
ULONG g_lastReportReserves = 0, g_lastReportTopDown = 0;

bool IsSystemModuleName(const char* name) {
    static const char* const kSystem[] = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "ucrtbase.dll",
        "msvcrt.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll",
        "msvcr120.dll", "msvcp_win.dll", "msvcp140.dll", "vcruntime140.dll",
        "apphelp.dll",
    };
    for (size_t i = 0; i < sizeof(kSystem) / sizeof(kSystem[0]); i++) {
        if (_stricmp(name, kSystem[i]) == 0) return true;
    }
    return false;
}

unsigned char ClassifyModule(HMODULE h, const char* name) {
    if (h == g_client) return kClassClient;
    if (h == g_self) return kClassOurs;
    if (IsSystemModuleName(name)) return kClassSystem;
    return kClassOther;
}

// Called with g_refreshLock held, so only one thread ever adds a slot. A slot's
// fields are written before the count that makes it visible.
LONG FindOrAddSlot(HMODULE h, uintptr_t base, uintptr_t end) {
    char full[MAX_PATH];
    if (!GetModuleBaseNameA(GetCurrentProcess(), h, full, MAX_PATH)) {
        lstrcpynA(full, "(unnamed module)", MAX_PATH);
    }
    char name[sizeof(g_slots[0].name)];
    lstrcpynA(name, full, sizeof(name));

    const LONG count = g_slotCount;
    for (LONG s = kSlotBefore + 1; s < count; s++) {
        if (g_slots[s].base == base && g_slots[s].end == end &&
            strcmp(g_slots[s].name, name) == 0) {
            return s;
        }
    }
    if (count >= kMaxSlots) return -1;
    Slot& slot = g_slots[count];
    slot.base = base;
    slot.end  = end;
    lstrcpynA(slot.name, name, sizeof(slot.name));
    slot.cls  = ClassifyModule(h, full);
    g_slotCount = count + 1;
    return count;
}

// Readers may hold a table that a later refresh is rewriting. Every index read
// from it is bounded, so a torn read costs one wrong attribution and never a
// read outside the arrays.
LONG SlotForAddress(const ModuleTable* t, uintptr_t addr) {
    LONG lo = 0;
    LONG hi = t->count;
    if (hi < 0) hi = 0;
    if (hi > kMaxSlots) hi = kMaxSlots;
    while (lo < hi) {
        const LONG mid = (lo + hi) / 2;
        if (addr < t->mod[mid].base) {
            hi = mid;
        } else if (addr >= t->mod[mid].end) {
            lo = mid + 1;
        } else {
            const LONG s = t->mod[mid].slot;
            return (s >= 0 && s < kMaxSlots) ? s : -1;
        }
    }
    return -1;
}

// Whether a call instruction ends exactly at this address: E8 rel32, the far 9A,
// or FF /2 in any of its lengths. The same filter FreezeCallPrecedes applies in
// dllmain.cpp, for the same reason: a return address always has one in front of
// it, and a stale word on the stack almost never does.
bool CallEndsAt(uintptr_t addr) {
    __try {
        const unsigned char* p = (const unsigned char*)addr;
        if (p[-5] == 0xE8) return true;
        if (p[-7] == 0x9A) return true;
        for (int len = 2; len <= 7; len++) {
            if (p[-len] == 0xFF && ((p[-len + 1] >> 3) & 7) == 2) return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return false;
}

bool Attributable(LONG slot) {
    return slot >= 0 && g_slots[slot].cls != kClassSystem;
}

// A new reservation is MEM_RESERVE, or MEM_COMMIT with no address, which
// reserves and commits in one call. The first version accepted only the flag,
// and a standalone test's 8 MB HeapAlloc went past both the census and placement
// entirely: ntdll's heap asks for large blocks with MEM_COMMIT alone.
bool IsOwnReserve(HANDLE process, PVOID* baseAddress, PSIZE_T regionSize,
                  ULONG allocationType) {
    if (process != kCurrentProcess || !baseAddress || !regionSize) return false;
    if ((allocationType & MEM_RESERVE) != 0) return true;
    return (allocationType & MEM_COMMIT) != 0 && *baseAddress == nullptr;
}

struct Decision {
    LONG slot;
    bool addTopDown;
    uintptr_t ret;      // who asked, as the address the call returns to
};

#pragma optimize("y", off)

// retAddr is the return address of the hook itself, which is the instruction
// after the call into ntdll, and retSlot is where it sits on the stack. Frames
// are considered only from there outward, so this module's own frames are never
// mistaken for the caller.
__declspec(noinline)
LONG AttributeCaller(const ModuleTable* t, uintptr_t retAddr, uintptr_t retSlot, uintptr_t* where) {
    LONG s = SlotForAddress(t, retAddr);
    if (Attributable(s)) { ++g_attribWalk; *where = retAddr; return s; }

    PVOID frames[24];
    const USHORT n = RtlCaptureStackBackTrace(0, 24, frames, NULL);
    bool past = false;
    for (USHORT i = 0; i < n; i++) {
        const uintptr_t a = (uintptr_t)frames[i];
        if (!past) {
            past = (a == retAddr);
            continue;
        }
        s = SlotForAddress(t, a);
        if (Attributable(s)) { ++g_attribWalk; *where = a; return s; }
    }

    __try {
        const uintptr_t stackBase = (uintptr_t)__readfsdword(4);
        uintptr_t sp = retSlot + sizeof(uintptr_t);
        uintptr_t stop = sp + 1024 * sizeof(uintptr_t);
        if (stackBase > sp && stackBase < stop) stop = stackBase;
        for (; sp + sizeof(uintptr_t) <= stop; sp += sizeof(uintptr_t)) {
            const uintptr_t v = *(uintptr_t*)sp;
            s = SlotForAddress(t, v);
            if (Attributable(s) && CallEndsAt(v)) { ++g_attribScan; *where = v; return s; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    ++g_attribNone;
    return kSlotUnresolved;
}

// Everything decided before the call: who asked, and whether to add
// MEM_TOP_DOWN. mayPlace carries what only the hook knows - zero high bits for
// one entry point, no extended parameters for the other.
__declspec(noinline)
Decision Decide(PVOID* baseAddress, SIZE_T asked, ULONG allocationType, bool mayPlace,
                uintptr_t retAddr, uintptr_t retSlot) {
    Decision d = { kSlotUnresolved, false, retAddr };
    const bool placeClient  = Config::g_settings.OptHighPlacementClient;
    const bool placeModules = Config::g_settings.OptHighPlacementModules;
    const SIZE_T minBytes   = (SIZE_T)Config::g_settings.HighPlacementMinKB * 1024;
    // A reservation that ntdll itself makes - the heap manager growing a heap by a segment, which
    // is what the return address inside ntdll means - is left where Windows puts it when
    // HighPlacementHeapGrowth is 0. The switch is on by default: the return address cannot tell a
    // heap growing by a segment from a heap handing out a large block, and the client's large
    // allocations come through the second, so leaving all of them would have taken most of the
    // client's placement away from every player who had it on. Eight dumps from two players on two realms (2026-10-06/07, build
    // 783ab7af, HighPlacementClient and Modules on) end the same way: DivxDecoder.dll, playing the
    // Lich King kill movie, calls HeapAlloc(heap, 0, 0x2820) on a heap of one 60 KB segment, and
    // ntdll faults reading [esi+14h] with ESI zero, in the same state every time (ECX 3B, EDX 3C,
    // EAX inside a zero-filled table in the first 12 KB of the heap). The request is the first
    // one the segment cannot satisfy, so the heap manager reserves a second segment, 2 MB from
    // SegmentReserve, which is over HighPlacementMinKB, is attributed through the stack to the
    // module that asked, and is moved above 2GB. That a segment of a heap lies above 2GB is the
    // one thing these dumps could share and nothing in them shows: the second segment is not in
    // them. A heap segment is also not placement-neutral the way a model buffer is, since every
    // later caller of the heap is handed memory from it.
    const bool fromHeapManager = (retAddr - g_ntdllLo) < g_ntdllSize;
    const bool heapGrowthLeft  = fromHeapManager && !Config::g_settings.OptHighPlacementHeapGrowth;
    const bool candidate    = mayPlace && (placeClient || placeModules) &&
                              *baseAddress == nullptr &&
                              (allocationType & (MEM_TOP_DOWN | MEM_PHYSICAL |
                                                 MEM_LARGE_PAGES)) == 0 &&
                              asked >= minBytes && !heapGrowthLeft;
    if (heapGrowthLeft && mayPlace && (placeClient || placeModules) && *baseAddress == nullptr &&
        asked >= minBytes)
        ++g_heapGrowthLeft;

    const ModuleTable* table = g_currentTable;
    if (table && (g_live != nullptr || candidate)) {
        uintptr_t where = retAddr;
        d.slot = AttributeCaller(table, retAddr, retSlot, &where);
        d.ret = where;
    }
    if (candidate) {
        const unsigned char cls = g_slots[d.slot].cls;
        d.addTopDown = (cls == kClassClient && placeClient) ||
                       (cls == kClassOther && placeModules);
    }
    return d;
}

void Record(const Decision& d, LONG status, bool retried, PVOID base, SIZE_T size) {
    if (d.addTopDown) {
        ++g_topDownAdded;
        ++g_slotTopDown[d.slot];
        if (retried) {
            if (status >= 0) ++g_topDownRetried;
        } else if (status >= 0) {
            if ((uintptr_t)base >= kLowHalfEnd) ++g_topDownHigh; else ++g_topDownLow;
        }
    }
    if (status < 0) return;
    ++g_slotReserves[d.slot];
    if (g_slots[d.slot].cls == kClassOurs && (uintptr_t)base < kLowHalfEnd) {
        const LONG at = InterlockedIncrement(&g_oursCount) - 1;
        if (at < kOursMax) {
            g_ours[at].base   = (uintptr_t)base;
            g_ours[at].sizeKB = (ULONG)((size + 1023) / 1024);
            g_ours[at].ret    = d.ret;
        }
    }
    if (g_live) {
        const ULONG index = (ULONG)((uintptr_t)base >> 16);
        if (g_live[index].sizeKB != 0) ++g_liveOverwrites;
        g_live[index].slot   = (USHORT)d.slot;
        g_live[index].sizeKB = (ULONG)((size + 1023) / 1024);
    }
}

LONG NTAPI Hooked_NtAllocateVirtualMemory(HANDLE process, PVOID* baseAddress,
                                          ULONG_PTR zeroBits, PSIZE_T regionSize,
                                          ULONG allocationType, ULONG protect) {
    if (!IsOwnReserve(process, baseAddress, regionSize, allocationType)) {
        return orig_NtAllocateVirtualMemory(process, baseAddress, zeroBits,
                                            regionSize, allocationType, protect);
    }
    ++g_reserveCalls;
    const SIZE_T asked = *regionSize;
    const Decision d = Decide(baseAddress, asked, allocationType, zeroBits == 0,
                              (uintptr_t)_ReturnAddress(),
                              (uintptr_t)_AddressOfReturnAddress());
    LONG status = orig_NtAllocateVirtualMemory(
        process, baseAddress, zeroBits, regionSize,
        d.addTopDown ? (allocationType | MEM_TOP_DOWN) : allocationType, protect);
    bool retried = false;
    if (d.addTopDown && status < 0) {
        *baseAddress = nullptr;
        *regionSize  = asked;
        status = orig_NtAllocateVirtualMemory(process, baseAddress, zeroBits,
                                              regionSize, allocationType, protect);
        retried = true;
    }
    Record(d, status, retried, *baseAddress, *regionSize);
    return status;
}

LONG NTAPI Hooked_NtAllocateVirtualMemoryEx(HANDLE process, PVOID* baseAddress,
                                            PSIZE_T regionSize, ULONG allocationType,
                                            ULONG protect, PVOID extended,
                                            ULONG extendedCount) {
    if (!IsOwnReserve(process, baseAddress, regionSize, allocationType)) {
        return orig_NtAllocateVirtualMemoryEx(process, baseAddress, regionSize,
                                              allocationType, protect, extended,
                                              extendedCount);
    }
    ++g_reserveCalls;
    ++g_reserveCallsEx;
    const SIZE_T asked = *regionSize;
    const Decision d = Decide(baseAddress, asked, allocationType, extendedCount == 0,
                              (uintptr_t)_ReturnAddress(),
                              (uintptr_t)_AddressOfReturnAddress());
    LONG status = orig_NtAllocateVirtualMemoryEx(
        process, baseAddress, regionSize,
        d.addTopDown ? (allocationType | MEM_TOP_DOWN) : allocationType, protect,
        extended, extendedCount);
    bool retried = false;
    if (d.addTopDown && status < 0) {
        *baseAddress = nullptr;
        *regionSize  = asked;
        status = orig_NtAllocateVirtualMemoryEx(process, baseAddress, regionSize,
                                                allocationType, protect, extended,
                                                extendedCount);
        retried = true;
    }
    Record(d, status, retried, *baseAddress, *regionSize);
    return status;
}

LONG NTAPI Hooked_NtFreeVirtualMemory(HANDLE process, PVOID* baseAddress,
                                      PSIZE_T regionSize, ULONG freeType) {
    if (g_live && process == kCurrentProcess && baseAddress &&
        (freeType & MEM_RELEASE) != 0) {
        const ULONG index = (ULONG)((uintptr_t)*baseAddress >> 16);
        const LiveEntry saved = g_live[index];
        // Cleared before the release rather than after it. The moment the
        // release completes another thread can be handed this same base, and
        // clearing afterwards would wipe that thread's new entry.
        g_live[index].sizeKB = 0;
        const LONG status = orig_NtFreeVirtualMemory(process, baseAddress,
                                                     regionSize, freeType);
        if (status < 0 && saved.sizeKB != 0 && g_live[index].sizeKB == 0) {
            g_live[index] = saved;
        }
        return status;
    }
    return orig_NtFreeVirtualMemory(process, baseAddress, regionSize, freeType);
}

#pragma optimize("", on)

void RecordExisting(uintptr_t base, SIZE_T size) {
    if (base == 0 || size == 0) return;
    const ULONG index = (ULONG)(base >> 16);
    g_live[index].slot   = (USHORT)kSlotBefore;
    g_live[index].sizeKB = (ULONG)((size + 1023) / 1024);
}

// Every private reservation that exists before the hook, so the census accounts
// for the whole address space rather than only what came after it.
void RecordExistingReservations() {
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0x10000;
    uintptr_t runBase = 0;
    SIZE_T    runSize = 0;
    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State != MEM_FREE && mbi.Type == MEM_PRIVATE) {
            const uintptr_t allocBase = (uintptr_t)mbi.AllocationBase;
            if (allocBase != runBase) {
                RecordExisting(runBase, runSize);
                runBase = allocBase;
                runSize = 0;
            }
            runSize += mbi.RegionSize;
        } else {
            RecordExisting(runBase, runSize);
            runBase = 0;
            runSize = 0;
        }
        const uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    RecordExisting(runBase, runSize);
}

const char* ClassName(unsigned char cls) {
    switch (cls) {
        case kClassClient: return "client";
        case kClassOurs:   return "this tool";
        case kClassSystem: return "system";
        case kClassOther:  return "module";
        default:           return "-";
    }
}

bool HookOne(const char* name, void* detour, void** original, bool required) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    void* target = ntdll ? (void*)GetProcAddress(ntdll, name) : nullptr;
    if (!target) {
        if (required) Log("[HighPlacement] ntdll does not export %s", name);
        return false;
    }
    if (MH_CreateHook(target, detour, original) != MH_OK) {
        Log("[HighPlacement] %s could not be hooked", name);
        return false;
    }
    if (WO_EnableHook(target) != MH_OK) {
        MH_RemoveHook(target);
        Log("[HighPlacement] %s could not be enabled", name);
        return false;
    }
    return true;
}

}  // namespace

void RefreshModules() {
    if (!g_installed) return;
    AcquireSRWLockExclusive(&g_refreshLock);

    HMODULE mods[kMaxSlots];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        ReleaseSRWLockExclusive(&g_refreshLock);
        return;
    }
    DWORD n = needed / sizeof(HMODULE);
    if (n > (DWORD)kMaxSlots) n = (DWORD)kMaxSlots;

    ModuleTable* next = (g_currentTable == &g_tables[0]) ? &g_tables[1] : &g_tables[0];
    next->count = 0;
    LONG count = 0;
    for (DWORD i = 0; i < n; i++) {
        MODULEINFO info;
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &info, sizeof(info))) continue;
        const uintptr_t base = (uintptr_t)info.lpBaseOfDll;
        const uintptr_t end  = base + info.SizeOfImage;
        const LONG slot = FindOrAddSlot(mods[i], base, end);
        if (slot < 0) continue;
        LONG j = count;
        while (j > 0 && next->mod[j - 1].base > base) {
            next->mod[j] = next->mod[j - 1];
            j--;
        }
        next->mod[j].base = base;
        next->mod[j].end  = end;
        next->mod[j].slot = slot;
        count++;
    }
    next->count = count;
    g_currentTable = next;
    g_lastRefreshTick = GetTickCount();

    ReleaseSRWLockExclusive(&g_refreshLock);
}

bool Init() {
    const bool census       = Config::g_settings.OptVaCensus;
    const bool placeClient  = Config::g_settings.OptHighPlacementClient;
    const bool placeModules = Config::g_settings.OptHighPlacementModules;
    if (!census && !placeClient && !placeModules) {
        Log("[HighPlacement] off: VaCensus, HighPlacementModules and "
            "HighPlacementClient are all 0");
        return true;
    }
    if (RunningUnderTranslation()) {
        Log("[HighPlacement] NOT active: running under Wine or Rosetta, where "
            "ntdll's allocation entry points are not the Windows ones this "
            "hooks");
        return false;
    }

    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    const uintptr_t top = (uintptr_t)si.lpMaximumApplicationAddress;
    if ((placeClient || placeModules) && top <= kLowHalfEnd) {
        Log("[HighPlacement] placement has nowhere to put anything: the address "
            "space ends at 0x%08X, so this client is not large-address-aware. "
            "The census still runs if it is on.", (unsigned)top);
    }

    {
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        if (nt) {
            const uint8_t* b = (const uint8_t*)nt;
            const IMAGE_NT_HEADERS* h = (const IMAGE_NT_HEADERS*)(b + ((const IMAGE_DOS_HEADER*)b)->e_lfanew);
            g_ntdllLo = (uintptr_t)b;
            g_ntdllSize = h->OptionalHeader.SizeOfImage;
        }
    }
    g_client = GetModuleHandleA(NULL);
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&RefreshModules, &g_self);

    lstrcpynA(g_slots[kSlotUnresolved].name, "(caller not found)",
              sizeof(g_slots[0].name));
    g_slots[kSlotUnresolved].cls = kClassUnresolved;
    lstrcpynA(g_slots[kSlotBefore].name, "(existed before install)",
              sizeof(g_slots[0].name));
    g_slots[kSlotBefore].cls = kClassBefore;

    if (census) {
        g_live = (LiveEntry*)VirtualAlloc(nullptr, sizeof(LiveEntry) * kLiveEntries,
                                          MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                          PAGE_READWRITE);
        if (!g_live) {
            Log("[HighPlacement] the census table (%u KB) could not be committed, "
                "error %lu, so the census does not run",
                (unsigned)(sizeof(LiveEntry) * kLiveEntries / 1024), GetLastError());
        } else {
            RecordExistingReservations();
        }
    }

    g_installed = true;
    RefreshModules();

    if (!HookOne("NtFreeVirtualMemory", (void*)Hooked_NtFreeVirtualMemory,
                 (void**)&orig_NtFreeVirtualMemory, true) ||
        !HookOne("NtAllocateVirtualMemory", (void*)Hooked_NtAllocateVirtualMemory,
                 (void**)&orig_NtAllocateVirtualMemory, true)) {
        g_installed = false;
        Log("[HighPlacement] NOT active - the reason is the line above");
        return false;
    }
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!GetProcAddress(ntdll, "NtAllocateVirtualMemoryEx")) {
        g_exState = "not exported by this Windows, so there is nothing to miss";
    } else if (HookOne("NtAllocateVirtualMemoryEx", (void*)Hooked_NtAllocateVirtualMemoryEx,
                       (void**)&orig_NtAllocateVirtualMemoryEx, false)) {
        g_exState = "hooked";
    } else {
        g_exState = "NOT hooked, so heap growth is missing from the census and "
                    "from placement";
    }

    Log("[HighPlacement] ACTIVE: census %s, MEM_TOP_DOWN for reservations of at "
        "least %d KB from %s. NtAllocateVirtualMemoryEx: %s. Placement only - "
        "nothing is redirected and nothing is freed differently.",
        g_live ? "on" : "off", Config::g_settings.HighPlacementMinKB,
        (placeClient && placeModules) ? "wow.exe and other modules"
        : placeClient                 ? "wow.exe only"
        : placeModules                ? "modules other than wow.exe"
                                      : "nobody (placement is off)",
        g_exState);
    return true;
}

void LogLiveByCaller(bool lowHalfOnly, const char* compareWith) {
    if (!g_live) {
        Log("[HighPlacement]   live reservations by caller: not measured, the "
            "census is off");
        return;
    }

    unsigned long long lowKB[kMaxSlots] = {};
    unsigned long long highKB[kMaxSlots] = {};
    ULONG lowCount[kMaxSlots] = {};
    unsigned long long totalLow = 0, totalHigh = 0;
    for (ULONG i = 0; i < kLiveEntries; i++) {
        const LiveEntry e = g_live[i];
        if (e.sizeKB == 0 || e.slot >= kMaxSlots) continue;
        if (i < 0x8000) {
            lowKB[e.slot] += e.sizeKB;
            lowCount[e.slot]++;
            totalLow += e.sizeKB;
        } else {
            highKB[e.slot] += e.sizeKB;
            totalHigh += e.sizeKB;
        }
    }

    Log("[HighPlacement]   live private reservations: %.0f MB below 2GB, %.0f MB "
        "above, by the module that asked%s%s%s:",
        totalLow / 1024.0, totalHigh / 1024.0,
        compareWith ? " (the below-2GB total should roughly match " : "",
        compareWith ? compareWith : "",
        compareWith ? ")" : "");

    bool shown[kMaxSlots] = {};
    const LONG slotCount = g_slotCount;
    for (int row = 0; row < 12; row++) {
        LONG best = -1;
        unsigned long long bestKey = 0;
        for (LONG s = 0; s < slotCount && s < kMaxSlots; s++) {
            if (shown[s]) continue;
            const unsigned long long key = lowHalfOnly ? lowKB[s] : lowKB[s] + highKB[s];
            if (key == 0) continue;
            if (best < 0 || key > bestKey) { best = s; bestKey = key; }
        }
        if (best < 0) break;
        shown[best] = true;
        Log("[HighPlacement]     %-26s %-9s %7.1f MB below 2GB in %lu reservation(s), "
            "%7.1f MB above",
            g_slots[best].name, ClassName(g_slots[best].cls),
            lowKB[best] / 1024.0, lowCount[best], highKB[best] / 1024.0);
    }

    // This DLL's own largest reservations in the low half that are still live,
    // with the offset in this DLL of the call that asked for each: map it with
    // the .map beside the build named at the top of the log.
    {
        LONG n = g_oursCount;
        if (n > kOursMax) n = kOursMax;
        bool used[kOursMax] = {};
        int listed = 0;
        for (int row = 0; row < 8; row++) {
            LONG best = -1;
            for (LONG i = 0; i < n; i++) {
                if (used[i]) continue;
                const ULONG idx = (ULONG)(g_ours[i].base >> 16);
                if (idx >= kLiveEntries || g_live[idx].sizeKB != g_ours[i].sizeKB) continue;   // gone since
                if (best < 0 || g_ours[i].sizeKB > g_ours[best].sizeKB) best = i;
            }
            if (best < 0) break;
            used[best] = true;
            const uintptr_t selfBase = (uintptr_t)g_self;
            const uintptr_t r = g_ours[best].ret;
            if (!listed++) Log("[HighPlacement]   this tool's largest live reservations below 2GB, by size:");
            Log("[HighPlacement]     %7.1f MB at 0x%08X, asked by wow_optimize.dll+0x%X%s",
                g_ours[best].sizeKB / 1024.0, (unsigned)g_ours[best].base,
                (unsigned)(r - selfBase),
                (r >= selfBase && r - selfBase < 0x400000) ? "" : " (outside this DLL: a system call made on its behalf)");
        }
        if (!listed && n > 0)
            Log("[HighPlacement]   this tool's below-2GB reservations are all freed again.");
        if (g_oursCount > kOursMax)
            Log("[HighPlacement]   %ld such reservations were made; only the first %ld are remembered.",
                (long)g_oursCount, (long)kOursMax);
    }
}

namespace {

// One-off low-half address space census when the largest free block below 2GB
// crosses under the critical threshold.
static constexpr SIZE_T kCensusThreshold = 16 * 1024 * 1024; // 16 MB

struct CensusRecord {
    char          name[48];
    char          category[12];
    uint64_t      reservedBytes;
    uint64_t      committedBytes;
    uint32_t      regionCount;
};

// Free space by the size of the hole it sits in. Five classes, the same
// boundaries the private reservations are split on below.
static constexpr int kSizeClasses = 5;
static const char* const kSizeClassName[kSizeClasses] = {
    "64 KB or less", "64 KB - 1 MB", "1 - 4 MB", "4 - 16 MB", "over 16 MB"
};

static int SizeClass(uint64_t bytes) {
    if (bytes <= 64ull * 1024) return 0;
    if (bytes <= 1024ull * 1024) return 1;
    if (bytes <= 4ull * 1024 * 1024) return 2;
    if (bytes <= 16ull * 1024 * 1024) return 3;
    return 4;
}

// One of the largest free holes, and the reservations either side of it.
// Those two are what keep it from being part of something bigger.
struct CensusHole {
    uintptr_t     base;
    uint64_t      bytes;
    char          below[48];
    char          above[48];
};
static constexpr int kHolesKept = 8;

struct CensusSnapshot {
    bool          valid;
    DWORD         timestampTick;
    SIZE_T        triggerLargestLowMB;
    uint64_t      totalReservedBytes;
    uint64_t      totalCommittedBytes;
    uint64_t      totalFreeBytes;
    SIZE_T        largestFreeBlockBytes;
    uint32_t      freeRegionCount;
    uint32_t      occupiedRegionCount;
    uint32_t      entryCount;
    CensusRecord  entries[256];

    uint32_t      freeClassCount[kSizeClasses];
    uint64_t      freeClassBytes[kSizeClasses];
    CensusHole    holes[kHolesKept];
    uint32_t      holeCount;

    // How the thread stacks were found, or why they were not. Zero stacks
    // with no reason would read as "none in the low half", which is not
    // what a failed enumeration means.
    uint32_t      stacksFound;
    char          stacksWhyNot[64];
};

static CensusSnapshot g_censusSnapshot = {};
static bool   g_censusBelowThreshold = false;
static SIZE_T g_censusLastObservedLow = 0;
static SIZE_T g_censusLowestObservedLow = 0;
static SRWLOCK g_censusLock = SRWLOCK_INIT;

// The reservation base of every thread stack in the process.
//
// Each thread reserves its stack in the low half, one reservation per thread,
// and until now every one of them went into the unattributed private bucket.
// A thread's stack limit is in its TEB, whose first member on x86 is the
// documented NT_TIB; the reservation that contains that limit is the stack.
// Everything here only reads - no thread is suspended and no lock is taken.
struct StackSet {
    uintptr_t base[1024];
    uint32_t  count;
};

typedef LONG (NTAPI* NtQueryInformationThread_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct ThreadBasicInfo {           // THREAD_BASIC_INFORMATION, class 0
    LONG      ExitStatus;
    PVOID     TebBaseAddress;
    HANDLE    UniqueProcess;
    HANDLE    UniqueThread;
    ULONG_PTR AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
};

static void CollectThreadStacks(StackSet& out, char* whyNot, size_t whyNotCap) {
    out.count = 0;
    whyNot[0] = 0;
    NtQueryInformationThread_fn qit = (NtQueryInformationThread_fn)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    if (!qit) {
        snprintf(whyNot, whyNotCap, "NtQueryInformationThread not found");
        return;
    }
    HANDLE snapH = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapH == INVALID_HANDLE_VALUE) {
        snprintf(whyNot, whyNotCap, "thread snapshot failed (%lu)", GetLastError());
        return;
    }
    const DWORD pid = GetCurrentProcessId();
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    uint32_t seen = 0, unreadable = 0;
    for (BOOL ok = Thread32First(snapH, &te); ok; ok = Thread32Next(snapH, &te)) {
        if (te.th32OwnerProcessID != pid) continue;
        ++seen;
        HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
        if (!th) { ++unreadable; continue; }
        ThreadBasicInfo tbi = {};
        const LONG st = qit(th, 0, &tbi, sizeof(tbi), nullptr);
        CloseHandle(th);
        if (st < 0 || !tbi.TebBaseAddress) { ++unreadable; continue; }
        uintptr_t limit = 0;
        __try {
            limit = (uintptr_t)((NT_TIB*)tbi.TebBaseAddress)->StackLimit;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            limit = 0;
        }
        MEMORY_BASIC_INFORMATION mbi;
        if (!limit || !VirtualQuery((LPCVOID)limit, &mbi, sizeof(mbi))) { ++unreadable; continue; }
        if (out.count < 1024) out.base[out.count++] = (uintptr_t)mbi.AllocationBase;
    }
    CloseHandle(snapH);
    if (out.count == 0) {
        snprintf(whyNot, whyNotCap, "%u thread(s) seen, none readable", seen);
    } else if (unreadable) {
        snprintf(whyNot, whyNotCap, "%u of %u thread(s) unreadable", unreadable, seen);
    }
}

static const StackSet* g_censusStacks = nullptr;   // valid during one walk only

static bool IsThreadStack(uintptr_t allocBase) {
    if (!g_censusStacks) return false;
    for (uint32_t i = 0; i < g_censusStacks->count; i++) {
        if (g_censusStacks->base[i] == allocBase) return true;
    }
    return false;
}

// What a reservation is called in the table. Filled into the caller's buffers
// so the walk can use the same name for the neighbours of a free hole.
static void NameReservation(uintptr_t allocBase, uint64_t reserved, DWORD type,
                            char* name, size_t nameCap, char* category, size_t catCap) {
    name[0] = 0;
    category[0] = 0;

    if (type == MEM_IMAGE) {
        lstrcpynA(category, "image", (int)catCap);
        char path[MAX_PATH];
        if (GetModuleFileNameA((HMODULE)allocBase, path, MAX_PATH)) {
            const char* leaf = strrchr(path, '\\');
            lstrcpynA(name, leaf ? leaf + 1 : path, (int)nameCap);
        } else if (GetMappedFileNameA(GetCurrentProcess(), (LPVOID)allocBase, path, MAX_PATH)) {
            const char* leaf = strrchr(path, '\\');
            lstrcpynA(name, leaf ? leaf + 1 : path, (int)nameCap);
        } else {
            snprintf(name, nameCap, "image@0x%08X", (unsigned)allocBase);
        }
    } else if (type == MEM_MAPPED) {
        lstrcpynA(category, "mapped", (int)catCap);
        char path[MAX_PATH];
        if (GetMappedFileNameA(GetCurrentProcess(), (LPVOID)allocBase, path, MAX_PATH)) {
            const char* leaf = strrchr(path, '\\');
            lstrcpynA(name, (leaf && *(leaf + 1)) ? leaf + 1 : path, (int)nameCap);
        } else {
            lstrcpynA(name, "mapped section", (int)nameCap);
        }
    } else { // MEM_PRIVATE
        lstrcpynA(category, "private", (int)catCap);
        if (MimallocHighArena::Contains((const void*)allocBase)) {
            lstrcpynA(name, "this tool's high arena", (int)nameCap);
        } else if (IsThreadStack(allocBase)) {
            lstrcpynA(name, "thread stacks", (int)nameCap);
        } else {
            bool ours = false;
            __try { ours = mi_is_in_heap_region((const void*)allocBase); }
            __except (EXCEPTION_EXECUTE_HANDLER) { ours = false; }
            if (ours) {
                lstrcpynA(name, "this tool's allocator (mimalloc)", (int)nameCap);
            } else if (g_live && (allocBase >> 16) < kLiveEntries && g_live[allocBase >> 16].sizeKB > 0) {
                const LONG s = g_live[allocBase >> 16].slot;
                if (s >= 0 && s < g_slotCount) {
                    lstrcpynA(name, g_slots[s].name, (int)nameCap);
                } else {
                    lstrcpynA(name, "private (unattributed)", (int)nameCap);
                }
            } else if (allocBase == (uintptr_t)GetProcessHeap()) {
                lstrcpynA(name, "client default heap", (int)nameCap);
            } else {
                HANDLE heaps[32];
                DWORD numHeaps = GetProcessHeaps(32, heaps);
                bool isHeap = false;
                for (DWORD i = 0; i < numHeaps; i++) {
                    if (allocBase == (uintptr_t)heaps[i]) {
                        isHeap = true;
                        break;
                    }
                }
                if (isHeap) {
                    lstrcpynA(name, "process heap", (int)nameCap);
                } else {
                    // Split by reservation size. The single bucket this used
                    // to be held 1519 MB of a 1916 MB low half in the first
                    // session it ran in, and named nothing. The shape of it
                    // does: hundreds of regions near 1 MB are heap segments,
                    // a handful over 16 MB are arenas someone reserved whole.
                    snprintf(name, nameCap, "unattributed, %s each",
                             kSizeClassName[SizeClass(reserved)]);
                }
            }
        }
    }
}

// A hole learns what sits above it only when the reservation after it has been
// walked to its end, because only then is its size - and so its name - known.
static void ResolveHole(CensusSnapshot& snap, int& pendingHole, const char* aboveName) {
    if (pendingHole < 0) return;
    lstrcpynA(snap.holes[pendingHole].above, aboveName, sizeof(snap.holes[pendingHole].above));
    pendingHole = -1;
}

static void AddCensusReservation(CensusSnapshot& snap, uintptr_t allocBase,
                                 uint64_t reserved, uint64_t committed, DWORD type,
                                 char* nameOut, size_t nameOutCap) {
    if (reserved == 0) return;
    char name[48] = {};
    char category[12] = {};
    NameReservation(allocBase, reserved, type, name, sizeof(name), category, sizeof(category));
    if (nameOut) lstrcpynA(nameOut, name, (int)nameOutCap);

    snap.totalReservedBytes += reserved;
    snap.totalCommittedBytes += committed;
    snap.occupiedRegionCount++;

    for (uint32_t i = 0; i < snap.entryCount; i++) {
        if (strcmp(snap.entries[i].name, name) == 0 &&
            strcmp(snap.entries[i].category, category) == 0) {
            snap.entries[i].reservedBytes += reserved;
            snap.entries[i].committedBytes += committed;
            snap.entries[i].regionCount++;
            return;
        }
    }

    if (snap.entryCount < 256) {
        CensusRecord& rec = snap.entries[snap.entryCount++];
        lstrcpynA(rec.name, name, sizeof(rec.name));
        lstrcpynA(rec.category, category, sizeof(rec.category));
        rec.reservedBytes = reserved;
        rec.committedBytes = committed;
        rec.regionCount = 1;
    }
}

static void RunLowHalfCensus(SIZE_T triggerLargestLow) {
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    // Static rather than on the stack: the snapshot is around 20 KB, and this
    // runs once per crossing on the monitor thread, never concurrently.
    static CensusSnapshot snap;
    memset(&snap, 0, sizeof(snap));
    snap.triggerLargestLowMB = (triggerLargestLow + 1024 * 1024 - 1) / (1024 * 1024);

    static StackSet stacks;
    CollectThreadStacks(stacks, snap.stacksWhyNot, sizeof(snap.stacksWhyNot));
    snap.stacksFound = stacks.count;
    g_censusStacks = &stacks;

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0x10000;
    uintptr_t curAllocBase = 0;
    uint64_t curReserved = 0;
    uint64_t curCommitted = 0;
    DWORD curType = 0;

    // The name of the last reservation flushed, and the hole waiting to learn
    // what sits above it.
    char lastName[48] = "(start of address space)";
    int  pendingHole = -1;

    while (addr < kLowHalfEnd && VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        uintptr_t base = (uintptr_t)mbi.BaseAddress;
        if (base >= kLowHalfEnd) break;

        SIZE_T size = mbi.RegionSize;
        if (base + size > kLowHalfEnd) size = (SIZE_T)(kLowHalfEnd - base);

        if (mbi.State == MEM_FREE) {
            if (curAllocBase != 0) {
                AddCensusReservation(snap, curAllocBase, curReserved, curCommitted, curType,
                                     lastName, sizeof(lastName));
                curAllocBase = 0; curReserved = 0; curCommitted = 0; curType = 0;
                ResolveHole(snap, pendingHole, lastName);
            }
            snap.totalFreeBytes += size;
            snap.freeRegionCount++;
            if (size > snap.largestFreeBlockBytes) snap.largestFreeBlockBytes = size;
            const int c = SizeClass(size);
            snap.freeClassCount[c]++;
            snap.freeClassBytes[c] += size;

            // Keep the largest holes, sorted descending.
            int slot = -1;
            if (snap.holeCount < (uint32_t)kHolesKept) {
                slot = (int)snap.holeCount++;
            } else if (size > snap.holes[kHolesKept - 1].bytes) {
                slot = kHolesKept - 1;
            }
            if (slot >= 0) {
                while (slot > 0 && snap.holes[slot - 1].bytes < size) {
                    snap.holes[slot] = snap.holes[slot - 1];
                    --slot;
                }
                CensusHole& h = snap.holes[slot];
                h.base = base;
                h.bytes = size;
                lstrcpynA(h.below, lastName, sizeof(h.below));
                lstrcpynA(h.above, "(end of the low half)", sizeof(h.above));
                pendingHole = slot;
            }
        } else {
            uintptr_t allocBase = (uintptr_t)mbi.AllocationBase;
            if (allocBase != curAllocBase) {
                if (curAllocBase != 0) {
                    AddCensusReservation(snap, curAllocBase, curReserved, curCommitted, curType,
                                         lastName, sizeof(lastName));
                    ResolveHole(snap, pendingHole, lastName);
                }
                curAllocBase = allocBase;
                curReserved = 0;
                curCommitted = 0;
                curType = mbi.Type;
            }
            curReserved += size;
            if (mbi.State == MEM_COMMIT) {
                curCommitted += size;
            }
        }

        uintptr_t next = base + mbi.RegionSize;
        if (mbi.RegionSize == 0) next += 0x10000;
        if (next <= addr) break;
        addr = next;
    }
    if (curAllocBase != 0) {
        AddCensusReservation(snap, curAllocBase, curReserved, curCommitted, curType,
                             lastName, sizeof(lastName));
        ResolveHole(snap, pendingHole, lastName);
    }
    g_censusStacks = nullptr;

    // Sort descending by reservedBytes
    for (uint32_t i = 1; i < snap.entryCount; i++) {
        CensusRecord key = snap.entries[i];
        int j = (int)i - 1;
        while (j >= 0 && snap.entries[j].reservedBytes < key.reservedBytes) {
            snap.entries[j + 1] = snap.entries[j];
            j--;
        }
        snap.entries[j + 1] = key;
    }

    QueryPerformanceCounter(&t1);
    double walkMs = freq.QuadPart
                  ? (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart
                  : 0.0;

    snap.timestampTick = GetTickCount();
    snap.valid = true;

    AcquireSRWLockExclusive(&g_censusLock);
    g_censusSnapshot = snap;
    ReleaseSRWLockExclusive(&g_censusLock);

    Log("[HighPlacement] low-half census walk complete (took %.1f ms on monitor thread): "
        "%.1f MB reserved (%.1f MB committed) in %u region(s), %.1f MB free (largest block %.1f MB)",
        walkMs, snap.totalReservedBytes / (1024.0 * 1024.0),
        snap.totalCommittedBytes / (1024.0 * 1024.0),
        snap.occupiedRegionCount,
        snap.totalFreeBytes / (1024.0 * 1024.0),
        snap.largestFreeBlockBytes / (1024.0 * 1024.0));
}

}  // namespace

void NotifyLowHalfFree(SIZE_T largestLow, SIZE_T totalLow) {
    (void)totalLow;
    g_censusLastObservedLow = largestLow;
    if (g_censusLowestObservedLow == 0 || largestLow < g_censusLowestObservedLow) {
        g_censusLowestObservedLow = largestLow;
    }

    if (largestLow < kCensusThreshold) {
        if (!g_censusBelowThreshold) {
            g_censusBelowThreshold = true;
            Log("[HighPlacement] largest free block below 2GB dropped to %.1f MB "
                "(crossed under 16 MB threshold) - walking low-half census once",
                largestLow / (1024.0 * 1024.0));
            RunLowHalfCensus(largestLow);
        }
    } else {
        if (g_censusBelowThreshold) {
            g_censusBelowThreshold = false;
            Log("[HighPlacement] largest free block below 2GB recovered to %.1f MB "
                "(above 16 MB threshold)",
                largestLow / (1024.0 * 1024.0));
        }
    }
}

void LogStats() {
    CensusSnapshot snap;
    AcquireSRWLockShared(&g_censusLock);
    snap = g_censusSnapshot;
    ReleaseSRWLockShared(&g_censusLock);

    if (snap.valid) {
        const DWORD ageSec = (GetTickCount() - snap.timestampTick) / 1000;
        Log("[HighPlacement] === LOW-HALF ADDRESS SPACE CENSUS (below 2GB) ===");
        Log("[HighPlacement] Walked once %lu s ago when largest free block dropped to %u MB (threshold 16 MB):",
            (unsigned long)ageSec, (unsigned)snap.triggerLargestLowMB);
        Log("[HighPlacement]   Total below 2GB: %.1f MB reserved (%.1f MB committed), %.1f MB free in %u region(s) (largest free block %.1f MB)",
            snap.totalReservedBytes / (1024.0 * 1024.0),
            snap.totalCommittedBytes / (1024.0 * 1024.0),
            snap.totalFreeBytes / (1024.0 * 1024.0),
            snap.freeRegionCount,
            snap.largestFreeBlockBytes / (1024.0 * 1024.0));
        Log("[HighPlacement]   Occupancy by module/mapping (largest first):");
        const uint32_t maxPrint = 15;
        uint64_t otherReserved = 0, otherCommitted = 0;
        uint32_t otherRegions = 0;
        for (uint32_t i = 0; i < snap.entryCount; i++) {
            if (i < maxPrint) {
                Log("[HighPlacement]     %-32s %-8s %7.1f MB reserved (%7.1f MB committed) in %u region(s)",
                    snap.entries[i].name, snap.entries[i].category,
                    snap.entries[i].reservedBytes / (1024.0 * 1024.0),
                    snap.entries[i].committedBytes / (1024.0 * 1024.0),
                    snap.entries[i].regionCount);
            } else {
                otherReserved += snap.entries[i].reservedBytes;
                otherCommitted += snap.entries[i].committedBytes;
                otherRegions += snap.entries[i].regionCount;
            }
        }
        if (otherRegions > 0) {
            Log("[HighPlacement]     %-32s %-8s %7.1f MB reserved (%7.1f MB committed) in %u region(s)",
                "(other smaller regions)", "-",
                otherReserved / (1024.0 * 1024.0),
                otherCommitted / (1024.0 * 1024.0),
                otherRegions);
        }
        if (snap.stacksFound > 0) {
            Log("[HighPlacement]   thread stacks: %u identified%s%s",
                snap.stacksFound, snap.stacksWhyNot[0] ? "; " : "", snap.stacksWhyNot);
        } else {
            Log("[HighPlacement]   thread stacks were not identified (%s), so they are "
                "counted in the unattributed rows above rather than on their own.",
                snap.stacksWhyNot[0] ? snap.stacksWhyNot : "no reason recorded");
        }

        Log("[HighPlacement]   Free space by the size of the hole it is in:");
        for (int c = 0; c < kSizeClasses; c++) {
            if (snap.freeClassCount[c] == 0) continue;
            Log("[HighPlacement]     %-14s %4u hole(s), %7.1f MB",
                kSizeClassName[c], snap.freeClassCount[c],
                snap.freeClassBytes[c] / (1024.0 * 1024.0));
        }
        if (snap.holeCount > 0) {
            Log("[HighPlacement]   Largest holes, and the reservations either side that keep "
                "each from being bigger:");
            for (uint32_t i = 0; i < snap.holeCount; i++) {
                const CensusHole& h = snap.holes[i];
                Log("[HighPlacement]     %6.1f MB at 0x%08X, between %s and %s",
                    h.bytes / (1024.0 * 1024.0), (unsigned)h.base, h.below, h.above);
            }
        }

        // Reserved and free together have to cover the low half from 64 KB,
        // where the walk starts, to 2 GB. If they do not, something above is
        // wrong and the table should not be trusted.
        const double spanMB = (double)(kLowHalfEnd - 0x10000) / (1024.0 * 1024.0);
        const double sumMB = (snap.totalReservedBytes + snap.totalFreeBytes) / (1024.0 * 1024.0);
        if (sumMB > spanMB - 0.05 && sumMB < spanMB + 0.05) {
            Log("[HighPlacement]   reserved and free add up to %.1f MB, the whole low half.", sumMB);
        } else {
            Log("[HighPlacement]   reserved and free add up to %.1f MB of %.1f MB. The walk "
                "missed part of the low half, so the figures above are incomplete.",
                sumMB, spanMB);
        }
        Log("[HighPlacement] ==================================================");
    } else {
        if (g_censusLastObservedLow > 0) {
            Log("[HighPlacement] low-half census did not run: largest free block below 2GB has remained above 16 MB (current: %.1f MB, lowest observed: %.1f MB)",
                g_censusLastObservedLow / (1024.0 * 1024.0),
                g_censusLowestObservedLow / (1024.0 * 1024.0));
        } else {
            Log("[HighPlacement] low-half census did not run: monitor thread has not evaluated free memory yet");
        }
    }

    const bool census       = Config::g_settings.OptVaCensus;
    const bool placeClient  = Config::g_settings.OptHighPlacementClient;
    const bool placeModules = Config::g_settings.OptHighPlacementModules;
    if (!census && !placeClient && !placeModules) {
        return;
    }
    if (!g_installed) {
        Log("[HighPlacement] allocation hooks not active - the reason is at the top of this log");
        return;
    }
    if (GetTickCount() - g_lastRefreshTick > 60000) RefreshModules();

    const ULONG reserves = g_reserveCalls;
    const ULONG added    = g_topDownAdded;
    Log("[HighPlacement] %lu private reservations seen (%lu through "
        "NtAllocateVirtualMemoryEx), %lu since the last report; lower bounds. "
        "Callers found by frame walk %lu, by stack scan %lu, not found %lu.",
        reserves, g_reserveCallsEx, reserves - g_lastReportReserves,
        g_attribWalk, g_attribScan, g_attribNone);
    if (placeClient || placeModules) {
        Log("[HighPlacement] MEM_TOP_DOWN added to %lu of them, %lu since the last "
            "report: %lu landed above 2GB, %lu still below because the high half "
            "had no room, %lu failed that way and succeeded when retried as asked.",
            added, added - g_lastReportTopDown,
            g_topDownHigh, g_topDownLow, g_topDownRetried);
        if (Config::g_settings.OptHighPlacementHeapGrowth)
            Log("[HighPlacement] reservations the heap manager makes are placed too (HighPlacementHeapGrowth=1, the default).");
        else
            Log("[HighPlacement] %lu reservation(s) of the minimum size or more were made by the heap manager "
                "itself (a heap growing by a segment, or a large block) and were left where Windows put "
                "them because HighPlacementHeapGrowth is 0; 1 places them as well.", g_heapGrowthLeft);
    } else {
        Log("[HighPlacement] placement is off; this session only records who "
            "reserves what.");
    }
    if (g_liveOverwrites) {
        Log("[HighPlacement] %lu reservation(s) arrived at a base the census still "
            "held, so a release was missed - the live totals below overstate by "
            "that much at most.", g_liveOverwrites);
    }
    g_lastReportReserves = reserves;
    g_lastReportTopDown  = added;

    LogLiveByCaller(false, nullptr);
}

}  // namespace HighPlacement

