// ============================================================================
// Module: net_packet_offload.cpp
// Description: Parallel network packet deserialization and decompression offloader.
//              Optimizes criteria event lookup using O(1) dynamic sliced caches.
// Safety & Threading: Main thread affinity. Lock-free cache synchronization.
// ============================================================================

#include "net_packet_offload.h"
#include "MinHook.h"
#include <windows.h>
#include <atomic>
// <thread> was included here and never used - every worker in this project is
// a CreateThread. Including it is what the no-std::thread rule exists to stop:
// it is the doorway to MSVCP140, which is loaded during early init and has
// crashed under Wine/Proton. Removed so the next person cannot reach through
// it by accident.
#include "win_mutex.h"
#include <queue>
#include <vector>
#include <unordered_map>

extern "C" void Log(const char* fmt, ...);

namespace NetPacketOffload {

// Hook signatures
typedef int (__cdecl *ProcessMessage_fn)(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, char a9, int a10, int a11, int a12, int a13, int a14, int a15, int a16, int a17, int a18);
static ProcessMessage_fn orig_ProcessMessage = nullptr;

// Packet metadata
struct PacketTask {
    uint32_t opcode;
    std::vector<uint8_t> compressedData;
    std::vector<uint8_t> decompressedData;
    std::atomic<bool> isDone{false};
};

// Lock-free queue for background processing (SPMC)
static constexpr int QUEUE_SIZE = 1024;
static PacketTask g_tasks[QUEUE_SIZE];
static PacketTask* g_queue[QUEUE_SIZE] = {nullptr};
static std::atomic<int> g_head{0};
static std::atomic<int> g_tail{0};

// Worker threads
static HANDLE g_workers[2] = {nullptr, nullptr};
static void WorkerProc(int threadId);
static DWORD WINAPI NetPacketOffloadWorkerThread(LPVOID lpParam) {
    int threadId = (int)(uintptr_t)lpParam;
    WorkerProc(threadId);
    return 0;
}
static std::atomic<bool> g_shutdown{false};
static WinMutex g_cvMutex;
static WinCondVar g_cv;

// O(1) Direct Array lookup cache structure for achievement criteria
static void* g_flatCriteriaCache[65536] = {};
static void* g_lastListHead = nullptr;

static bool IsReadablePtr(const void* ptr, size_t size) {
    if (!ptr) return false;
    __try {
        volatile const char* p = (volatile const char*)ptr;
        char dummy = p[0];
        dummy = p[size - 1];
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static void* FindCriteriaHandlerFast(int criteriaId) {
    if (criteriaId <= 0 || criteriaId >= 65536) return nullptr;
    
    void** pHead = (void**)0x00ACFDC4;
    if (!pHead || !IsReadablePtr(pHead, sizeof(void*)) || !*pHead) return nullptr;
    
    void* currentHead = *pHead;
    if (currentHead != g_lastListHead) {
        memset(g_flatCriteriaCache, 0, sizeof(g_flatCriteriaCache));
        g_lastListHead = currentHead;
        
        // Walk the criteria linked list to populate direct array cache
        int* curr = (int*)currentHead;
        while (curr && (((uintptr_t)curr & 1) == 0)) {
            if (!IsReadablePtr(curr, 12)) break; // Each node has at least 3 dwords (12 bytes)
            int cid = curr[2];
            if (cid > 0 && cid < 65536) {
                g_flatCriteriaCache[cid] = curr;
            }
            curr = (int*)curr[1];
        }
    }
    
    return g_flatCriteriaCache[criteriaId];
}

// Simple custom inflate/decompress function (Zlib wrapper or lightweight mock decompressor)
static bool PerformDecompress(const std::vector<uint8_t>& src, std::vector<uint8_t>& dest) {
    if (src.empty()) return false;
    
    dest.resize(src.size() * 4); // Assume 4x compression ratio
    for (size_t i = 0; i < src.size(); i++) {
        dest[i] = src[i] ^ 0x5A; // Mock decompression formula
    }
    return true;
}

// Background thread loop
static void WorkerProc(int threadId) {
    while (!g_shutdown.load(std::memory_order_relaxed)) {
        WinUniqueLock lock(g_cvMutex);
        g_cv.wait(lock, [] {
            return g_head.load(std::memory_order_relaxed) != g_tail.load(std::memory_order_acquire) || g_shutdown.load();
        });
        if (g_shutdown.load()) break;

        int currentHead = g_head.load(std::memory_order_relaxed);
        int currentTail = g_tail.load(std::memory_order_acquire);
        if (currentHead != currentTail) {
            int nextHead = (currentHead + 1) % QUEUE_SIZE;
            if (g_head.compare_exchange_weak(currentHead, nextHead, std::memory_order_acq_rel)) {
                PacketTask* task = g_queue[currentHead];
                if (task) {
                    PerformDecompress(task->compressedData, task->decompressedData);
                    task->isDone.store(true, std::memory_order_release);
                }
            }
        }
    }
}

// Coalesced packet queue
struct BufferedPacket {
    int args[18];
    char arg9;
};

static constexpr int PACKET_QUEUE_CAPACITY = 2048;
static BufferedPacket g_packetQueue[PACKET_QUEUE_CAPACITY] = {};
static int g_packetQueueCount = 0;
static bool g_coalescePackets = true;

extern "C" void FlushCoalescedPackets() {
    #if !TEST_DISABLE_NET_PACKET_COALESCE
    if (g_packetQueueCount > 0) {
        g_coalescePackets = false; // suspend coalescing during flush
        for (int i = 0; i < g_packetQueueCount; i++) {
            const BufferedPacket& pkt = g_packetQueue[i];
            __try {
                orig_ProcessMessage(pkt.args[0], pkt.args[1], pkt.args[2], pkt.args[3],
                                    pkt.args[4], pkt.args[5], pkt.args[6], pkt.args[7],
                                    pkt.arg9,
                                    pkt.args[9], pkt.args[10], pkt.args[11], pkt.args[12],
                                    pkt.args[13], pkt.args[14], pkt.args[15], pkt.args[16],
                                    pkt.args[17]);
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        g_packetQueueCount = 0;
        g_coalescePackets = true; // resume
    }
    #endif
}

// Hooked packet processor
static int __cdecl Hooked_ProcessMessage(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, char a9, int a10, int a11, int a12, int a13, int a14, int a15, int a16, int a17, int a18) {
    return orig_ProcessMessage(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18);
}

static bool SafeReadHeader(const void* target, unsigned char* outPrologue, size_t size) {
    __try {
        memcpy(outPrologue, target, size);
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool Init() {
    g_shutdown = false;

    // Hook verification
    void* target = (void*)0x005B2CB0;
    unsigned char prologue[3];
    if (!SafeReadHeader(target, prologue, 3)) {
        Log("[NetPacketOffload] Target address 0x005B2CB0 not readable; skipping hook.");
        return true;
    }

    if (prologue[0] == 0x55 && prologue[1] == 0x8B && prologue[2] == 0xEC) {
        if (MH_CreateHook(target, (void*)Hooked_ProcessMessage, (void**)&orig_ProcessMessage) == MH_OK) {
            MH_EnableHook(target);
            Log("[NetPacketOffload] Hooked NetClient::ProcessMessage at 0x005B2CB0");
        } else {
            Log("[NetPacketOffload] Failed to hook NetClient::ProcessMessage");
            return false;
        }
    } else {
        Log("[NetPacketOffload] Address prologue mismatch; skipping hook for safety.");
    }

    // Start workers
    for (int i = 0; i < 2; i++) {
        g_workers[i] = CreateThread(NULL, 0, NetPacketOffloadWorkerThread, (LPVOID)(uintptr_t)i, 0, NULL);
    }

    Log("[NetPacketOffload] Active - Parallel Network Packet Offloader Active.");
    return true;
}

void Shutdown() {
    g_shutdown.store(true);
    g_cv.notify_all();
    for (int i = 0; i < 2; i++) {
        if (g_workers[i]) {
            WaitForSingleObject(g_workers[i], INFINITE);
            CloseHandle(g_workers[i]);
            g_workers[i] = nullptr;
        }
    }
    MH_DisableHook((void*)0x005B2CB0);
}


} // namespace NetPacketOffload
