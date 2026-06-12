#include "frame_arena.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

namespace FrameArena {

static constexpr size_t   ARENA_SIZE   = 16u * 1024u * 1024u;
static constexpr size_t   MAX_BLOCK    = 1024;
static constexpr uint32_t HEADER_MAGIC = 0xFA12CAFE;
static constexpr size_t   ALIGN        = 16;

#pragma pack(push, 1)
struct Header { uint32_t magic; uint32_t size; };
#pragma pack(pop)

static volatile LONG g_active = 0;
static uint8_t*      g_base   = nullptr;
static size_t        g_size   = 0;
static volatile LONG g_cursor = 0;

static volatile LONG64 g_totalAllocs     = 0;
static volatile LONG64 g_totalAllocBytes = 0;
static volatile LONG64 g_fallbacks       = 0;
static volatile LONG64 g_freesNoOp       = 0;
static volatile LONG   g_resets          = 0;

bool Init() {
    g_base = (uint8_t*)VirtualAlloc(NULL, ARENA_SIZE,
                                    MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
                                    PAGE_READWRITE);
    if (!g_base) {
        Log("[FrameArena] VirtualAlloc(%u) FAILED", (unsigned)ARENA_SIZE);
        return false;
    }
    g_size = ARENA_SIZE;
    g_cursor = 0;
    InterlockedExchange(&g_active, 1);
    Log("[FrameArena] active base=0x%p size=%u MB max-block=%u",
        g_base, (unsigned)(g_size / (1024*1024)), (unsigned)MAX_BLOCK);
    return true;
}

void Shutdown() {
    InterlockedExchange(&g_active, 0);
    // Wait for any in-flight TryAlloc/Owns/SizeOf calls to complete.
    // Those functions check g_active first, so after setting it to 0
    // no NEW callers will proceed, but one thread may have passed the
    // check before we cleared the flag.  A short sleep is sufficient
    // because the arena operations are lock-free and very fast (<1 µs).
    Sleep(10);
    if (g_base) {
        VirtualFree(g_base, 0, MEM_RELEASE);
        g_base = nullptr;
        g_size = 0;
    }
    Log("[FrameArena] shutdown allocs=%lld bytes=%lld fallbacks=%lld noop-frees=%lld resets=%ld",
       (long long)g_totalAllocs, (long long)g_totalAllocBytes,
       (long long)g_fallbacks, (long long)g_freesNoOp, g_resets);
}

bool Owns(const void* p) {
    if (!g_active || !p || !g_base) return false;
    uintptr_t a = (uintptr_t)p;
    uintptr_t b = (uintptr_t)g_base;
    return (a >= b + sizeof(Header)) && (a < b + g_size);
}

size_t SizeOf(const void* p) {
    if (!Owns(p)) return 0;
    const Header* h = (const Header*)((const uint8_t*)p - sizeof(Header));
    if (h->magic != HEADER_MAGIC) return 0;
    return (size_t)h->size;
}

void* TryAlloc(size_t size) {
    if (!g_active || !g_base) return nullptr;
    if (size == 0 || size > MAX_BLOCK) {
        InterlockedIncrement64(&g_fallbacks);
        return nullptr;
    }

    size_t need = sizeof(Header) + ((size + (ALIGN - 1)) & ~(ALIGN - 1));
    LONG newCursor = InterlockedExchangeAdd(&g_cursor, (LONG)need) + (LONG)need;
    if ((size_t)newCursor > g_size) {
        InterlockedExchangeAdd(&g_cursor, -(LONG)need);
        InterlockedIncrement64(&g_fallbacks);
        return nullptr;
    }

    uint8_t* slot = g_base + (size_t)newCursor - need;
    Header*  h    = (Header*)slot;
    h->magic = HEADER_MAGIC;
    h->size  = (uint32_t)size;

    InterlockedIncrement64(&g_totalAllocs);
    InterlockedExchangeAdd64(&g_totalAllocBytes, (LONG64)size);
    return slot + sizeof(Header);
}

void Reset() {
    if (!g_active || !g_base) return;
    InterlockedExchange(&g_cursor, 0);
    InterlockedIncrement(&g_resets);
}

void NoteNoOpFree() {
    if (!g_active) return;
    InterlockedIncrement64(&g_freesNoOp);
}

void GetStats(Stats* out) {
    if (!out) return;
    out->active          = g_active != 0;
    out->capacity        = (uint32_t)g_size;
    out->inUse           = (uint32_t)g_cursor;
    out->resets          = (uint32_t)g_resets;
    out->totalAllocs     = (uint64_t)g_totalAllocs;
    out->totalAllocBytes = (uint64_t)g_totalAllocBytes;
    out->fallbacks       = (uint64_t)g_fallbacks;
    out->freesNoOp       = (uint64_t)g_freesNoOp;
}

} // namespace FrameArena
