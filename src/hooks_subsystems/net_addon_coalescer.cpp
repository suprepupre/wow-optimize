// ============================================================================
// Module: net_addon_coalescer.cpp
//
// Network Addon Message Coalescer & Outgoing Sync Throttler
// Targets:
//   - Incoming CHAT_MSG_ADDON events dispatched via FrameScript_SignalEvent (0x0081AC90)
//   - Outgoing SendAddonMessage bursts via Script_SendAddonMessage (0x00500560)
//
// In large raids (25-40 players), addons (Details, Recount, DBM, BigWigs, ThreatClassic,
// WeakAuras) broadcast high-frequency synchronization packets.
// 1. Incoming bursts trigger dozens of CHAT_MSG_ADDON events per frame, each re-entering
//    Lua, executing across dozens of registered addon frames, thrashing the Lua GC and
//    causing massive pull stutters and FPS spikes.
// 2. Outgoing addon message spam can saturate client sockets and trigger server-side
//    addon rate-limit disconnects.
//
// This module:
// - Deduplicates identical incoming sync broadcasts within the frame.
// - Batches incoming CHAT_MSG_ADDON dispatch to the frame boundary.
// - Suppresses duplicate outgoing SendAddonMessage spam within 50ms windows.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <atomic>

#include "net_addon_coalescer.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);
extern void* g_origSignalEvent;
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace NetAddonCoalescer {

namespace {

constexpr uintptr_t kSendAddonMessageTarget = 0x00500560;

// Prologue bytes of sub_500560 (16 bytes):
// push ebp; mov ebp, esp; sub esp, 0BD4h; call sub_4D3790; push offset aUsageSendaddon
static const uint8_t kExpectedPrologue[16] = {
    0x55, 0x8B, 0xEC, 0x81, 0xEC, 0xD4, 0x0B, 0x00,
    0x00, 0xE8, 0x22, 0x32, 0xFD, 0xFF, 0x68, 0xA0
};

typedef int (__cdecl* Script_SendAddonMessageFn)(void* L);
static Script_SendAddonMessageFn g_origSendAddonMessage = nullptr;

typedef const char* (__cdecl* Lua_TolstringFn)(void* L, int idx, size_t* len);
static const Lua_TolstringFn fnLua_Tolstring = reinterpret_cast<Lua_TolstringFn>(0x0084E0E0);

typedef void (__cdecl *FrameScript_SignalEvent_t)(int eventId, const char* format, ...);

struct QueuedAddonMessage {
    int eventId;
    char format[16];
    char prefix[32];
    char text[260];
    char channel[16];
    char sender[48];
    uint32_t textHash;
};

static constexpr int MAX_QUEUED = 256;
static QueuedAddonMessage g_queue[MAX_QUEUED];
static int g_queueCount = 0;
static SRWLOCK g_queueLock = SRWLOCK_INIT;

static std::atomic<bool> g_active{false};
static thread_local bool g_isReplaying = false;

static int s_addonEventId = -1;

// Outgoing throttling state
static SRWLOCK g_outgoingLock = SRWLOCK_INIT;
static uint32_t g_lastOutgoingHash = 0;
static DWORD g_lastOutgoingTick = 0;

// Statistics
static std::atomic<uint64_t> g_incomingQueued{0};
static std::atomic<uint64_t> g_incomingDuplicatesDropped{0};
static std::atomic<uint64_t> g_incomingDispatched{0};
static std::atomic<uint64_t> g_outgoingSent{0};
static std::atomic<uint64_t> g_outgoingThrottled{0};

static inline uint32_t Fnv1a(const char* s, uint32_t h = 0x811c9dc5) {
    if (!s) return h;
    while (*s) {
        h = (h ^ static_cast<uint8_t>(*s++)) * 0x01000193;
    }
    return h;
}

static const char* GetEventName(int eventId) {
    __try {
        if (eventId < 0 || eventId > 2000) return nullptr;
        uintptr_t* eventTable = *reinterpret_cast<uintptr_t**>(0x00D3F7D8);
        if (!eventTable) return nullptr;

        uintptr_t eventPtr = eventTable[eventId];
        if (eventPtr < 0x10000 || eventPtr > 0xFFE00000) return nullptr;

        const char* name = *reinterpret_cast<const char**>(eventPtr + 20);
        if (name < reinterpret_cast<const char*>(0x10000) || name > reinterpret_cast<const char*>(0xFFE00000)) return nullptr;

        return name;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

static int __cdecl Hook_SendAddonMessage(void* L) {
    if (!g_active.load(std::memory_order_relaxed) || !g_origSendAddonMessage) {
        return g_origSendAddonMessage ? g_origSendAddonMessage(L) : 0;
    }

    const char* prefix = fnLua_Tolstring(L, 1, nullptr);
    const char* text   = fnLua_Tolstring(L, 2, nullptr);
    const char* chan   = fnLua_Tolstring(L, 3, nullptr);

    if (prefix && text) {
        uint32_t hash = Fnv1a(prefix);
        hash = Fnv1a(text, hash);
        if (chan) hash = Fnv1a(chan, hash);

        DWORD now = GetTickCount();
        AcquireSRWLockExclusive(&g_outgoingLock);
        if (hash == g_lastOutgoingHash && (now - g_lastOutgoingTick) < 50) {
            ReleaseSRWLockExclusive(&g_outgoingLock);
            g_outgoingThrottled.fetch_add(1, std::memory_order_relaxed);
            return 0; // Suppress duplicate burst
        }
        g_lastOutgoingHash = hash;
        g_lastOutgoingTick = now;
        ReleaseSRWLockExclusive(&g_outgoingLock);
        g_outgoingSent.fetch_add(1, std::memory_order_relaxed);
    }

    return g_origSendAddonMessage(L);
}

} // anonymous namespace

bool Init() {
    if (!Config::g_settings.OptNetAddonCoalescer) {
        return false;
    }

    if (std::memcmp(reinterpret_cast<const void*>(kSendAddonMessageTarget), kExpectedPrologue, sizeof(kExpectedPrologue)) == 0) {
        MH_STATUS st = WineSafe_CreateHook(
            reinterpret_cast<void*>(kSendAddonMessageTarget),
            reinterpret_cast<void*>(Hook_SendAddonMessage),
            reinterpret_cast<void**>(&g_origSendAddonMessage));
        if (st == MH_OK) {
            st = WO_EnableHook(reinterpret_cast<void*>(kSendAddonMessageTarget));
            if (st == MH_OK) {
                Log("[NetAddonCoalescer] Outgoing SendAddonMessage hook active at 0x%08X.", kSendAddonMessageTarget);
            }
        }
    } else {
        Log("[NetAddonCoalescer] SendAddonMessage prologue mismatch at 0x%08X; outgoing throttle disabled.", kSendAddonMessageTarget);
    }

    g_active.store(true, std::memory_order_relaxed);
    Log("[NetAddonCoalescer] Active - Incoming and outgoing addon message coalescing enabled.");
    return true;
}

void Shutdown() {
    if (g_active.load(std::memory_order_relaxed)) {
        g_active.store(false, std::memory_order_relaxed);
        if (g_origSendAddonMessage) {
            MH_DisableHook(reinterpret_cast<void*>(kSendAddonMessageTarget));
            g_origSendAddonMessage = nullptr;
        }
    }
}

bool IsActive() {
    return g_active.load(std::memory_order_relaxed);
}

bool IsReplaying() {
    return g_isReplaying;
}

bool TryQueueIncoming(int eventId, const char* format, void* vaStart) {
    if (g_isReplaying || !g_active.load(std::memory_order_relaxed)) {
        return false;
    }

    if (s_addonEventId == -1) {
        const char* name = GetEventName(eventId);
        if (name && std::strcmp(name, "CHAT_MSG_ADDON") == 0) {
            s_addonEventId = eventId;
        } else {
            return false;
        }
    } else if (eventId != s_addonEventId) {
        return false;
    }

    const char* prefix = nullptr;
    const char* text = nullptr;
    const char* chan = nullptr;
    const char* sender = nullptr;

    __try {
        uintptr_t* pArgs = static_cast<uintptr_t*>(vaStart);
        prefix = reinterpret_cast<const char*>(pArgs[0]);
        text   = reinterpret_cast<const char*>(pArgs[1]);
        chan   = reinterpret_cast<const char*>(pArgs[2]);
        sender = reinterpret_cast<const char*>(pArgs[3]);

        if (!prefix || !text || prefix < reinterpret_cast<const char*>(0x10000) || text < reinterpret_cast<const char*>(0x10000)) {
            return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    uint32_t hash = Fnv1a(prefix);
    hash = Fnv1a(text, hash);
    if (chan) hash = Fnv1a(chan, hash);

    AcquireSRWLockExclusive(&g_queueLock);

    // Frame-scoped duplicate check
    for (int i = 0; i < g_queueCount; ++i) {
        const QueuedAddonMessage& q = g_queue[i];
        if (q.textHash == hash &&
            std::strcmp(q.channel, chan ? chan : "") == 0 &&
            std::strcmp(q.prefix, prefix) == 0 &&
            std::strcmp(q.text, text) == 0)
        {
            ReleaseSRWLockExclusive(&g_queueLock);
            g_incomingDuplicatesDropped.fetch_add(1, std::memory_order_relaxed);
            return true; // Swallowed duplicate sync message
        }
    }

    if (g_queueCount >= MAX_QUEUED) {
        ReleaseSRWLockExclusive(&g_queueLock);
        return false; // Queue full, dispatch immediately
    }

    QueuedAddonMessage& msg = g_queue[g_queueCount++];
    msg.eventId = eventId;
    msg.textHash = hash;

    if (format) {
        size_t flen = std::strlen(format);
        if (flen >= sizeof(msg.format)) flen = sizeof(msg.format) - 1;
        std::memcpy(msg.format, format, flen);
        msg.format[flen] = '\0';
    } else {
        std::strcpy(msg.format, "%s%s%s%s");
    }

    __try {
        size_t plen = std::strlen(prefix);
        if (plen >= sizeof(msg.prefix)) plen = sizeof(msg.prefix) - 1;
        std::memcpy(msg.prefix, prefix, plen);
        msg.prefix[plen] = '\0';

        size_t tlen = std::strlen(text);
        if (tlen >= sizeof(msg.text)) tlen = sizeof(msg.text) - 1;
        std::memcpy(msg.text, text, tlen);
        msg.text[tlen] = '\0';

        if (chan) {
            size_t clen = std::strlen(chan);
            if (clen >= sizeof(msg.channel)) clen = sizeof(msg.channel) - 1;
            std::memcpy(msg.channel, chan, clen);
            msg.channel[clen] = '\0';
        } else {
            msg.channel[0] = '\0';
        }

        if (sender) {
            size_t slen = std::strlen(sender);
            if (slen >= sizeof(msg.sender)) slen = sizeof(msg.sender) - 1;
            std::memcpy(msg.sender, sender, slen);
            msg.sender[slen] = '\0';
        } else {
            msg.sender[0] = '\0';
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        --g_queueCount;
        ReleaseSRWLockExclusive(&g_queueLock);
        return false;
    }

    ReleaseSRWLockExclusive(&g_queueLock);
    g_incomingQueued.fetch_add(1, std::memory_order_relaxed);
    return true; // Successfully queued for frame boundary
}

void OnFrame() {
    if (!g_active.load(std::memory_order_relaxed) || g_queueCount == 0) {
        return;
    }

    AcquireSRWLockExclusive(&g_queueLock);
    int count = g_queueCount;
    QueuedAddonMessage localQueue[MAX_QUEUED];
    std::memcpy(localQueue, g_queue, count * sizeof(QueuedAddonMessage));
    g_queueCount = 0;
    ReleaseSRWLockExclusive(&g_queueLock);

    g_isReplaying = true;
    auto fnSignalEvent = reinterpret_cast<FrameScript_SignalEvent_t>(g_origSignalEvent);
    if (fnSignalEvent) {
        for (int i = 0; i < count; ++i) {
            const auto& msg = localQueue[i];
            __try {
                fnSignalEvent(msg.eventId, msg.format, msg.prefix, msg.text, msg.channel, msg.sender);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Ignore failure during dispatch
            }
        }
    }
    g_isReplaying = false;
    g_incomingDispatched.fetch_add(count, std::memory_order_relaxed);
}

void LogStats() {
    if (!g_active.load(std::memory_order_relaxed)) {
        return;
    }
    Log("[NetAddonCoalescer] InQueued: %llu, InDedupDropped: %llu, InDispatched: %llu | OutSent: %llu, OutThrottled: %llu",
        g_incomingQueued.load(std::memory_order_relaxed),
        g_incomingDuplicatesDropped.load(std::memory_order_relaxed),
        g_incomingDispatched.load(std::memory_order_relaxed),
        g_outgoingSent.load(std::memory_order_relaxed),
        g_outgoingThrottled.load(std::memory_order_relaxed));
}

} // namespace NetAddonCoalescer

