#include "sound_prefetch.h"
#include "version.h"

#if !TEST_DISABLE_SOUND_PREFETCH

#include <windows.h>
#include <atomic>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

// ================================================================
// CONFIGURATION
// ================================================================

constexpr size_t QUEUE_SIZE = 1024;
constexpr size_t MAX_WORKERS = 2;
constexpr size_t ZONE_HISTORY_SIZE = 10;
constexpr size_t MAX_PREFETCH_FILES = 50; // Max files to prefetch per prediction

// ================================================================
// LOCK-FREE RING BUFFER QUEUE
// ================================================================

struct PrefetchRequest {
    char filepath[260];
    uint32_t priority; // 0 = low, 1 = normal, 2 = high
};

// WO_KEEP_BSS: see version.h — keeps clang-cl from putting this in .rdata.
WO_KEEP_BSS static PrefetchRequest g_queue[QUEUE_SIZE];
static std::atomic<size_t> g_head{0};
static std::atomic<size_t> g_tail{0};

static bool Enqueue(const char* filepath, uint32_t priority) {
    size_t current_tail = g_tail.load(std::memory_order_relaxed);
    size_t next_tail = (current_tail + 1) % QUEUE_SIZE;
    
    if (next_tail == g_head.load(std::memory_order_acquire)) {
        return false; // Queue full
    }
    
    strncpy_s(g_queue[current_tail].filepath, filepath, _TRUNCATE);
    g_queue[current_tail].priority = priority;
    
    g_tail.store(next_tail, std::memory_order_release);
    return true;
}

static bool Dequeue(PrefetchRequest& req) {
    size_t current_head = g_head.load(std::memory_order_relaxed);
    
    if (current_head == g_tail.load(std::memory_order_acquire)) {
        return false; // Queue empty
    }
    
    req = g_queue[current_head];
    g_head.store((current_head + 1) % QUEUE_SIZE, std::memory_order_release);
    return true;
}

// ================================================================
// STATISTICS
// ================================================================

static SRWLOCK g_stats_lock = SRWLOCK_INIT;

struct Stats {
    uint64_t prefetch_requests = 0;
    uint64_t prefetch_success = 0;
    uint64_t prefetch_failed = 0;
    uint64_t bytes_prefetched = 0;
    uint64_t spell_predictions = 0;
    uint64_t zone_predictions = 0;
    uint64_t combat_predictions = 0;
};

static Stats g_stats;

// ================================================================
// ZONE TRACKING
// ================================================================

static uint32_t g_zone_history[ZONE_HISTORY_SIZE] = {0};
static size_t g_zone_history_index = 0;
static uint32_t g_current_zone = 0;
static bool g_in_combat = false;

static void TrackZoneChange(uint32_t new_zone) {
    if (new_zone == g_current_zone) return;
    
    g_zone_history[g_zone_history_index] = g_current_zone;
    g_zone_history_index = (g_zone_history_index + 1) % ZONE_HISTORY_SIZE;
    g_current_zone = new_zone;
}

// ================================================================
// SOUND FILE MAPPINGS
// ================================================================

// Zone ID → Sound files mapping
static const std::unordered_map<uint32_t, std::vector<const char*>> g_zone_sounds = {
    // Dalaran (4395)
    {4395, {
        "Sound\\Music\\ZoneMusic\\Dalaran\\DalaranWalkingMusic.mp3",
        "Sound\\Ambience\\Dalaran\\DalaranAmbience.wav",
        "Sound\\Ambience\\Dalaran\\DalaranFountain.wav",
    }},
    
    // Icecrown Citadel (4812)
    {4812, {
        "Sound\\Music\\ZoneMusic\\IcecrownCitadel\\IcecrownCitadelMusic.mp3",
        "Sound\\Ambience\\IcecrownCitadel\\IcecrownAmbience.wav",
        "Sound\\Creature\\LichKing\\LichKingAggro.wav",
    }},
    
    // Orgrimmar (1637)
    {1637, {
        "Sound\\Music\\ZoneMusic\\Orgrimmar\\OrgrimmarWalkingMusic.mp3",
        "Sound\\Ambience\\Orgrimmar\\OrgrimmarAmbience.wav",
    }},
    
    // Stormwind (1519)
    {1519, {
        "Sound\\Music\\ZoneMusic\\Stormwind\\StormwindWalkingMusic.mp3",
        "Sound\\Ambience\\Stormwind\\StormwindAmbience.wav",
    }},
};

// Common spell sounds (prefetch on combat start)
static const std::vector<const char*> g_combat_sounds = {
    "Sound\\Spells\\Fireball_Impact.wav",
    "Sound\\Spells\\Frostbolt_Impact.wav",
    "Sound\\Spells\\Shadow_Impact.wav",
    "Sound\\Spells\\Holy_Impact.wav",
    "Sound\\Spells\\Nature_Impact.wav",
    "Sound\\Spells\\Arcane_Impact.wav",
    "Sound\\Spells\\Melee_Hit.wav",
    "Sound\\Spells\\Melee_Crit.wav",
    "Sound\\Spells\\Shield_Block.wav",
    "Sound\\Spells\\Heal_Cast.wav",
};

// ================================================================
// PREDICTION LOGIC
// ================================================================

static uint32_t PredictNextZone() {
    // Simple pattern matching based on zone history
    if (g_current_zone == 4395 && g_zone_history[0] == 1637) {
        // Orgrimmar → Dalaran → likely ICC next
        return 4812;
    }
    if (g_current_zone == 4812) {
        // ICC → likely Dalaran next
        return 4395;
    }
    if (g_current_zone == 1519 && g_zone_history[0] == 0) {
        // Stormwind → likely Dalaran next (boat)
        return 4395;
    }
    
    return 0; // No prediction
}

static void PrefetchZoneSounds(uint32_t zone_id) {
    auto it = g_zone_sounds.find(zone_id);
    if (it == g_zone_sounds.end()) return;
    
    AcquireSRWLockExclusive(&g_stats_lock);
    g_stats.zone_predictions++;
    ReleaseSRWLockExclusive(&g_stats_lock);
    
    for (const char* filepath : it->second) {
        Enqueue(filepath, 1); // Normal priority
    }
}

static void PrefetchCombatSounds() {
    AcquireSRWLockExclusive(&g_stats_lock);
    g_stats.combat_predictions++;
    ReleaseSRWLockExclusive(&g_stats_lock);
    
    for (const char* filepath : g_combat_sounds) {
        Enqueue(filepath, 2); // High priority
    }
}

// ================================================================
// WORKER THREAD
// ================================================================

static HANDLE g_worker_threads[MAX_WORKERS] = {nullptr};
static std::atomic<bool> g_shutdown{false};

static DWORD WINAPI WorkerThread(LPVOID) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    
    PrefetchRequest req;
    char fullpath[MAX_PATH];
    
    while (!g_shutdown.load(std::memory_order_acquire)) {
        if (!Dequeue(req)) {
            Sleep(10); // No work, sleep briefly
            continue;
        }
        
        // Build full path (assume WoW directory)
        // In production, we'd get the actual WoW path
        snprintf(fullpath, sizeof(fullpath), "%s", req.filepath);
        
        // Prefetch file into OS cache via ReadFile
        HANDLE hFile = CreateFileA(
            fullpath,
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr
        );
        
        if (hFile != INVALID_HANDLE_VALUE) {
            char buffer[8192];
            DWORD bytes_read;
            uint64_t total_bytes = 0;
            
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytes_read, nullptr) && bytes_read > 0) {
                total_bytes += bytes_read;
            }
            
            CloseHandle(hFile);
            
            AcquireSRWLockExclusive(&g_stats_lock);
            g_stats.prefetch_success++;
            g_stats.bytes_prefetched += total_bytes;
            ReleaseSRWLockExclusive(&g_stats_lock);
        } else {
            AcquireSRWLockExclusive(&g_stats_lock);
            g_stats.prefetch_failed++;
            ReleaseSRWLockExclusive(&g_stats_lock);
        }
        
        AcquireSRWLockExclusive(&g_stats_lock);
        g_stats.prefetch_requests++;
        ReleaseSRWLockExclusive(&g_stats_lock);
    }
    
    return 0;
}

// ================================================================
// PUBLIC API
// ================================================================

void SoundPrefetch::Init() {
    g_shutdown.store(false, std::memory_order_release);
    
    // Start worker threads
    for (size_t i = 0; i < MAX_WORKERS; i++) {
        g_worker_threads[i] = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    }
}

void SoundPrefetch::Shutdown() {
    g_shutdown.store(true, std::memory_order_release);
    
    // Wait for workers to finish (max 5 seconds each)
    for (size_t i = 0; i < MAX_WORKERS; i++) {
        if (g_worker_threads[i]) {
            WaitForSingleObject(g_worker_threads[i], 5000);
            CloseHandle(g_worker_threads[i]);
            g_worker_threads[i] = nullptr;
        }
    }
}

static uint32_t g_frame_counter = 0;

void SoundPrefetch::OnFrame() {
    g_frame_counter++;
    
    // Check zone change every 60 frames (~1 second)
    if (g_frame_counter % 60 == 0) {
        // TODO: Hook GetZoneText or similar to detect zone changes
        // For now, we'll use a placeholder
        // uint32_t new_zone = DetectCurrentZone();
        // TrackZoneChange(new_zone);
        
        // Predict next zone and prefetch sounds
        uint32_t predicted_zone = PredictNextZone();
        if (predicted_zone != 0) {
            PrefetchZoneSounds(predicted_zone);
        }
    }
    
    // Check combat state every 30 frames (~0.5 seconds)
    if (g_frame_counter % 30 == 0) {
        // TODO: Hook combat state detection
        // For now, we'll use a placeholder
        // bool in_combat = DetectCombatState();
        
        // If entering combat, prefetch combat sounds
        // if (in_combat && !g_in_combat) {
        //     PrefetchCombatSounds();
        // }
        // g_in_combat = in_combat;
    }
}

#else

// Disabled stubs
void SoundPrefetch::Init() {}
void SoundPrefetch::Shutdown() {}
void SoundPrefetch::OnFrame() {}

#endif // !TEST_DISABLE_SOUND_PREFETCH
