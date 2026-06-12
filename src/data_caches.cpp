// ================================================================
// data_caches.cpp — 10 game-data lookup and processing caches
// ================================================================
// 1. Spell History Cache (sub_80E1B0) - 7,457B, 67 callees
// 2. M2 Model Init Cache (sub_832EA0) - 5,692B, 41 callers
// 3. FMOD Audio Config Cache (sub_8D67D0) - 8,216B
// 4. FrameScript Opcode Cache (sub_842DA0) - 18,022B
// 5. DBC Record Lookup Index
// 6. Event Name SSE2 Hash
// 7. String Interning L2 Cache
// 8. Combat Log Bloom Dedup
// 9. Render State Batch Coalescing
// 10. Texture Decode Prefetch
// ================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <emmintrin.h>
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
// 1. SPELL HISTORY CACHE (sub_80E1B0)
// ================================================================
// sub_80E1B0 is Spell_C.cpp's spell history processor with 67 callees.
// It processes SPELLHISTORY structures during combat log events.
// Cache recent spell lookups to avoid repeated hash table walks.
// ================================================================
static constexpr int SPELL_CACHE_SIZE = 1024;
static constexpr int SPELL_CACHE_MASK = SPELL_CACHE_SIZE - 1;

struct SpellCacheEntry {
    uint32_t spellId;
    uint32_t resultHash;   // cached lookup result fingerprint
    DWORD    timestamp;
    bool     valid;
};

static SpellCacheEntry g_spellCache[SPELL_CACHE_SIZE];
static volatile LONG64 g_spellCacheHits = 0;
static volatile LONG64 g_spellCacheMisses = 0;

static inline uint32_t SpellHash(uint32_t spellId) {
    uint32_t h = spellId * 0x9E3779B1u;
    return h & SPELL_CACHE_MASK;
}

bool SpellCache_Lookup(uint32_t spellId, uint32_t* outResultHash) {
    uint32_t idx = SpellHash(spellId);
    SpellCacheEntry* e = &g_spellCache[idx];
    if (e->valid && e->spellId == spellId) {
        DWORD age = GetTickCount() - e->timestamp;
        if (age < 60000) { // 60s TTL
            *outResultHash = e->resultHash;
            InterlockedIncrement64(&g_spellCacheHits);
            return true;
        }
        e->valid = false;
    }
    InterlockedIncrement64(&g_spellCacheMisses);
    return false;
}

void SpellCache_Store(uint32_t spellId, uint32_t resultHash) {
    uint32_t idx = SpellHash(spellId);
    SpellCacheEntry* e = &g_spellCache[idx];
    e->spellId = spellId;
    e->resultHash = resultHash;
    e->timestamp = GetTickCount();
    e->valid = true;
}

// ================================================================
// 2. M2 MODEL INIT CACHE (sub_832EA0)
// ================================================================
// sub_832EA0 is M2Model.cpp constructor with 41 callers and 62 callees.
// Called for every model load. Cache model init parameters to skip
// redundant farClip/nearClip/fieldOfView validation.
// ================================================================
static constexpr int MODEL_CACHE_SIZE = 512;
static constexpr int MODEL_CACHE_MASK = MODEL_CACHE_SIZE - 1;

struct ModelCacheEntry {
    uint32_t pathHash;
    float    farClip;
    float    nearClip;
    float    fieldOfView;
    DWORD    lastAccess;
    bool     valid;
};

static ModelCacheEntry g_modelCache[MODEL_CACHE_SIZE];
static volatile LONG64 g_modelCacheHits = 0;
static volatile LONG64 g_modelCacheMisses = 0;

bool ModelCache_Get(uint32_t pathHash, float* farClip, float* nearClip, float* fov) {
    uint32_t idx = pathHash & MODEL_CACHE_MASK;
    ModelCacheEntry* e = &g_modelCache[idx];
    if (e->valid && e->pathHash == pathHash) {
        DWORD age = GetTickCount() - e->lastAccess;
        if (age < 300000) { // 5 min TTL
            *farClip = e->farClip;
            *nearClip = e->nearClip;
            *fov = e->fieldOfView;
            e->lastAccess = GetTickCount();
            InterlockedIncrement64(&g_modelCacheHits);
            return true;
        }
        e->valid = false;
    }
    InterlockedIncrement64(&g_modelCacheMisses);
    return false;
}

void ModelCache_Put(uint32_t pathHash, float farClip, float nearClip, float fov) {
    uint32_t idx = pathHash & MODEL_CACHE_MASK;
    ModelCacheEntry* e = &g_modelCache[idx];
    e->pathHash = pathHash;
    e->farClip = farClip;
    e->nearClip = nearClip;
    e->fieldOfView = fov;
    e->lastAccess = GetTickCount();
    e->valid = true;
}

// ================================================================
// 3. FMOD AUDIO CONFIG CACHE (sub_8D67D0)
// ================================================================
// sub_8D67D0 is FMOD system init with multiple 11-case switches.
// Cache audio format negotiation results to skip repeated probing.
// ================================================================
static constexpr int AUDIO_CACHE_SIZE = 256;
static constexpr int AUDIO_CACHE_MASK = AUDIO_CACHE_SIZE - 1;

struct AudioCacheEntry {
    uint32_t configHash;
    uint32_t result;
    DWORD    lastAccess;
    bool     valid;
};

static AudioCacheEntry g_audioCache[AUDIO_CACHE_SIZE];
static volatile LONG64 g_audioCacheHits = 0;
static volatile LONG64 g_audioCacheMisses = 0;

bool AudioCache_Get(uint32_t configHash, uint32_t* result) {
    uint32_t idx = configHash & AUDIO_CACHE_MASK;
    AudioCacheEntry* e = &g_audioCache[idx];
    if (e->valid && e->configHash == configHash) {
        DWORD age = GetTickCount() - e->lastAccess;
        if (age < 120000) {
            *result = e->result;
            e->lastAccess = GetTickCount();
            InterlockedIncrement64(&g_audioCacheHits);
            return true;
        }
        e->valid = false;
    }
    InterlockedIncrement64(&g_audioCacheMisses);
    return false;
}

void AudioCache_Put(uint32_t configHash, uint32_t result) {
    uint32_t idx = configHash & AUDIO_CACHE_MASK;
    AudioCacheEntry* e = &g_audioCache[idx];
    e->configHash = configHash;
    e->result = result;
    e->lastAccess = GetTickCount();
    e->valid = true;
}

// ================================================================
// 4. FRAMESCRIPT OPCODE HOT-PATH (sub_842DA0)
// ================================================================
// sub_842DA0 is the FrameScript/XML event dispatcher (18,022B, 81-case).
// NOT the Lua VM. Cache frequent event dispatch results.
// ================================================================
static constexpr int FS_CACHE_SIZE = 2048;
static constexpr int FS_CACHE_MASK = FS_CACHE_SIZE - 1;

struct FrameScriptCacheEntry {
    uint64_t eventKey;    // (eventType << 32) | handlerPtr
    uint32_t result;
    DWORD    lastAccess;
    bool     valid;
};

static FrameScriptCacheEntry g_fsCache[FS_CACHE_SIZE];
static volatile LONG64 g_fsCacheHits = 0;
static volatile LONG64 g_fsCacheMisses = 0;

bool FrameScriptCache_Get(uint64_t eventKey, uint32_t* result) {
    uint32_t idx = (uint32_t)(eventKey ^ (eventKey >> 32)) & FS_CACHE_MASK;
    FrameScriptCacheEntry* e = &g_fsCache[idx];
    if (e->valid && e->eventKey == eventKey) {
        DWORD age = GetTickCount() - e->lastAccess;
        if (age < 30000) {
            *result = e->result;
            e->lastAccess = GetTickCount();
            InterlockedIncrement64(&g_fsCacheHits);
            return true;
        }
        e->valid = false;
    }
    InterlockedIncrement64(&g_fsCacheMisses);
    return false;
}

void FrameScriptCache_Put(uint64_t eventKey, uint32_t result) {
    uint32_t idx = (uint32_t)(eventKey ^ (eventKey >> 32)) & FS_CACHE_MASK;
    FrameScriptCacheEntry* e = &g_fsCache[idx];
    e->eventKey = eventKey;
    e->result = result;
    e->lastAccess = GetTickCount();
    e->valid = true;
}

// ================================================================
// 5. DBC RECORD LOOKUP ACCELERATION
// ================================================================
// WoW's DBC (Database Client) files contain game data tables.
// Lookups by ID are linear scans. We provide a hash-based index.
// ================================================================
static constexpr int DBC_INDEX_SIZE = 4096;
static constexpr int DBC_INDEX_MASK = DBC_INDEX_SIZE - 1;

struct DbcIndexEntry {
    uint32_t recordId;
    uintptr_t recordPtr;
    bool     valid;
};

static DbcIndexEntry g_dbcIndex[DBC_INDEX_SIZE];
static volatile LONG64 g_dbcHits = 0;
static volatile LONG64 g_dbcMisses = 0;

uintptr_t DbcIndex_Lookup(uint32_t recordId) {
    uint32_t idx = recordId & DBC_INDEX_MASK;
    DbcIndexEntry* e = &g_dbcIndex[idx];
    if (e->valid && e->recordId == recordId) {
        InterlockedIncrement64(&g_dbcHits);
        return e->recordPtr;
    }
    InterlockedIncrement64(&g_dbcMisses);
    return 0;
}

void DbcIndex_Store(uint32_t recordId, uintptr_t recordPtr) {
    uint32_t idx = recordId & DBC_INDEX_MASK;
    DbcIndexEntry* e = &g_dbcIndex[idx];
    e->recordId = recordId;
    e->recordPtr = recordPtr;
    e->valid = true;
}

// ================================================================
// 6. EVENT NAME HASH FAST-PATH
// ================================================================
// WoW fires thousands of events per frame. Event name hashing is
// called on every FireEvent. SSE2-accelerated FNV-1a for short names.
// ================================================================
static volatile LONG64 g_eventHashFast = 0;
static volatile LONG64 g_eventHashSlow = 0;

uint32_t FastEventNameHash(const char* name, int len) {
    // SSE2 fast path for names <= 16 bytes (most WoW events)
    if (len > 0 && len <= 16) {
        __m128i data = _mm_loadu_si128((const __m128i*)name);
        // Mask out bytes beyond length
        static const uint8_t masks[17][16] = {
            {0},{0xFF},{0xFF,0xFF},{0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF},{0xFF,0xFF,0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
            {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}
        };
        __m128i mask = _mm_loadu_si128((const __m128i*)masks[len]);
        data = _mm_and_si128(data, mask);

        // Horizontal FNV-1a approximation via XOR folding
        __m128i h = _mm_set1_epi32(0x811C9DC5);
        data = _mm_xor_si128(data, h);
        // Multiply by FNV prime (approximated with shifts)
        __m128i lo = _mm_mullo_epi16(data, _mm_set1_epi16(0x0193));
        __m128i hi = _mm_mulhi_epu16(data, _mm_set1_epi16(0x0193));
        __m128i result = _mm_or_si128(
            _mm_slli_epi32(hi, 16),
            _mm_and_si128(lo, _mm_set1_epi32(0x0000FFFF))
        );
        // XOR fold 4 dwords into one
        uint32_t* r = (uint32_t*)&result;
        uint32_t final_hash = r[0] ^ r[1] ^ r[2] ^ r[3];
        InterlockedIncrement64(&g_eventHashFast);
        return final_hash;
    }

    // Scalar fallback for long names
    uint32_t h = 0x811C9DC5;
    for (int i = 0; i < len; i++) {
        h ^= (uint8_t)name[i];
        h *= 0x01000193u;
    }
    InterlockedIncrement64(&g_eventHashSlow);
    return h;
}

// ================================================================
// 7. STRING INTERNING L2 CACHE
// ================================================================
// Second-level cache above luaH_getstr for frequently accessed
// global strings. Direct-mapped, no collision handling.
// ================================================================
static constexpr int STR_L2_SIZE = 2048;
static constexpr int STR_L2_MASK = STR_L2_SIZE - 1;

struct StrL2Entry {
    uint64_t nameHash;
    uintptr_t tstringPtr;
    uint32_t generation;
    bool     valid;
};

static StrL2Entry g_strL2[STR_L2_SIZE];
static volatile LONG g_strL2Gen = 0;
static volatile LONG64 g_strL2Hits = 0;
static volatile LONG64 g_strL2Misses = 0;

uintptr_t StrL2_Lookup(uint64_t nameHash) {
    uint32_t idx = (uint32_t)(nameHash & STR_L2_MASK);
    StrL2Entry* e = &g_strL2[idx];
    uint32_t gen = (uint32_t)InterlockedCompareExchange(&g_strL2Gen, 0, 0);
    if (e->valid && e->nameHash == nameHash && e->generation == gen) {
        InterlockedIncrement64(&g_strL2Hits);
        return e->tstringPtr;
    }
    InterlockedIncrement64(&g_strL2Misses);
    return 0;
}

void StrL2_Store(uint64_t nameHash, uintptr_t tstringPtr) {
    uint32_t idx = (uint32_t)(nameHash & STR_L2_MASK);
    StrL2Entry* e = &g_strL2[idx];
    uint32_t gen = (uint32_t)InterlockedCompareExchange(&g_strL2Gen, 0, 0);
    e->nameHash = nameHash;
    e->tstringPtr = tstringPtr;
    e->generation = gen;
    e->valid = true;
}

void StrL2_Invalidate() {
    InterlockedIncrement(&g_strL2Gen);
}

// ================================================================
// 8. COMBAT LOG EVENT DEDUPLICATION
// ================================================================
// Many combat log events are duplicates (same spell hitting same target
// in same frame). Bloom filter dedup reduces redundant processing.
// ================================================================
static constexpr int CLE_BLOOM_SIZE = 8192;
static constexpr int CLE_BLOOM_MASK = CLE_BLOOM_SIZE - 1;
static uint64_t g_cleBloom[CLE_BLOOM_SIZE / 64];
static volatile LONG64 g_cleDedupHits = 0;
static volatile LONG64 g_cleDedupPasses = 0;
static DWORD g_cleLastFrameTick = 0;

// Clear bloom filter each frame
void CombatLogDedup_NewFrame() {
    DWORD now = GetTickCount();
    if (now != g_cleLastFrameTick) {
        memset(g_cleBloom, 0, sizeof(g_cleBloom));
        g_cleLastFrameTick = now;
    }
}

bool CombatLogDedup_IsDuplicate(uint64_t eventFingerprint) {
    CombatLogDedup_NewFrame();
    uint32_t h1 = (uint32_t)(eventFingerprint & CLE_BLOOM_MASK);
    uint32_t h2 = (uint32_t)((eventFingerprint >> 16) & CLE_BLOOM_MASK);
    uint32_t h3 = (uint32_t)((eventFingerprint >> 32) & CLE_BLOOM_MASK);

    uint64_t bit1 = 1ULL << (h1 & 63);
    uint64_t bit2 = 1ULL << (h2 & 63);
    uint64_t bit3 = 1ULL << (h3 & 63);

    bool allSet = (g_cleBloom[h1 / 64] & bit1) &&
                  (g_cleBloom[h2 / 64] & bit2) &&
                  (g_cleBloom[h3 / 64] & bit3);

    if (allSet) {
        InterlockedIncrement64(&g_cleDedupHits);
        return true; // probable duplicate
    }

    g_cleBloom[h1 / 64] |= bit1;
    g_cleBloom[h2 / 64] |= bit2;
    g_cleBloom[h3 / 64] |= bit3;
    InterlockedIncrement64(&g_cleDedupPasses);
    return false;
}

// ================================================================
// 9. RENDER STATE BATCH COALESCING
// ================================================================
// WoW sets render states individually. We batch consecutive state
// changes and flush once per frame, reducing D3D9/GL driver calls.
// ================================================================
static constexpr int RS_BATCH_SIZE = 128;

struct RenderStateBatch {
    uint32_t state;
    uint32_t value;
};

static RenderStateBatch g_rsBatch[RS_BATCH_SIZE];
static int g_rsBatchCount = 0;
static volatile LONG64 g_rsBatchFlushes = 0;
static volatile LONG64 g_rsBatchCoalesced = 0;

bool RenderStateBatch_Add(uint32_t state, uint32_t value) {
    // Check if same state already in batch - update in place
    for (int i = 0; i < g_rsBatchCount; i++) {
        if (g_rsBatch[i].state == state) {
            g_rsBatch[i].value = value;
            InterlockedIncrement64(&g_rsBatchCoalesced);
            return true; // coalesced
        }
    }
    if (g_rsBatchCount < RS_BATCH_SIZE) {
        g_rsBatch[g_rsBatchCount].state = state;
        g_rsBatch[g_rsBatchCount].value = value;
        g_rsBatchCount++;
        return true;
    }
    return false; // batch full, caller must flush
}

int RenderStateBatch_Flush(RenderStateBatch* outBatch) {
    int count = g_rsBatchCount;
    if (count > 0) {
        memcpy(outBatch, g_rsBatch, count * sizeof(RenderStateBatch));
        g_rsBatchCount = 0;
        InterlockedIncrement64(&g_rsBatchFlushes);
    }
    return count;
}

// ================================================================
// 10. TEXTURE DECODE PIPELINE PREFETCH
// ================================================================
// Predict next texture decode based on spatial locality.
// Prefetch BLP header + first mip level into L2 cache.
// ================================================================
static volatile LONG64 g_texPrefetchHits = 0;
static volatile LONG64 g_texPrefetchMisses = 0;

void TextureDecodePrefetch(const void* blpData, size_t dataSize) {
    if (!blpData || dataSize < 64) return;

    // Prefetch BLP header (first 64 bytes) into L1
    _mm_prefetch((const char*)blpData, _MM_HINT_T0);

    // Prefetch first mip offset (typically at header+16)
    if (dataSize >= 256) {
        _mm_prefetch((const char*)blpData + 64, _MM_HINT_T1);
        _mm_prefetch((const char*)blpData + 128, _MM_HINT_T1);
        _mm_prefetch((const char*)blpData + 192, _MM_HINT_T2);
    }

    InterlockedIncrement64(&g_texPrefetchHits);
}

// ================================================================
// INSTALL / SHUTDOWN
// ================================================================
bool InitDataCaches() {
    // Clear all caches
    memset(g_spellCache, 0, sizeof(g_spellCache));
    memset(g_modelCache, 0, sizeof(g_modelCache));
    memset(g_audioCache, 0, sizeof(g_audioCache));
    memset(g_fsCache, 0, sizeof(g_fsCache));
    memset(g_dbcIndex, 0, sizeof(g_dbcIndex));
    memset(g_strL2, 0, sizeof(g_strL2));
    memset(g_cleBloom, 0, sizeof(g_cleBloom));
    g_rsBatchCount = 0;

    Log("[DataCache] 10 caches initialized:");
    Log("  [1] Spell History Cache (%d slots)", SPELL_CACHE_SIZE);
    Log("  [2] M2 Model Init Cache (%d slots)", MODEL_CACHE_SIZE);
    Log("  [3] FMOD Audio Config Cache (%d slots)", AUDIO_CACHE_SIZE);
    Log("  [4] FrameScript Opcode Cache (%d slots)", FS_CACHE_SIZE);
    Log("  [5] DBC Record Index (%d slots)", DBC_INDEX_SIZE);
    Log("  [6] Event Name SSE2 Hash (fast-path)");
    Log("  [7] String Interning L2 Cache (%d slots)", STR_L2_SIZE);
    Log("  [8] Combat Log Bloom Dedup (%d bits)", CLE_BLOOM_SIZE);
    Log("  [9] Render State Batch (%d entries)", RS_BATCH_SIZE);
    Log("  [10] Texture Decode Prefetch (L1/L2 hints)");

    return true;
}

void ShutdownDataCaches() {
    LONG64 spellTotal = g_spellCacheHits + g_spellCacheMisses;
    LONG64 modelTotal = g_modelCacheHits + g_modelCacheMisses;
    LONG64 audioTotal = g_audioCacheHits + g_audioCacheMisses;
    LONG64 fsTotal = g_fsCacheHits + g_fsCacheMisses;
    LONG64 dbcTotal = g_dbcHits + g_dbcMisses;
    LONG64 strTotal = g_strL2Hits + g_strL2Misses;
    LONG64 cleTotal = g_cleDedupHits + g_cleDedupPasses;
    LONG64 evtTotal = g_eventHashFast + g_eventHashSlow;

    Log("[DataCache] Shutdown stats:");
    if (spellTotal > 0)
        Log("  Spell Cache: %lld hits, %lld misses (%.1f%%)",
            g_spellCacheHits, g_spellCacheMisses, 100.0 * g_spellCacheHits / spellTotal);
    if (modelTotal > 0)
        Log("  Model Cache: %lld hits, %lld misses (%.1f%%)",
            g_modelCacheHits, g_modelCacheMisses, 100.0 * g_modelCacheHits / modelTotal);
    if (audioTotal > 0)
        Log("  Audio Cache: %lld hits, %lld misses (%.1f%%)",
            g_audioCacheHits, g_audioCacheMisses, 100.0 * g_audioCacheHits / audioTotal);
    if (fsTotal > 0)
        Log("  FrameScript Cache: %lld hits, %lld misses (%.1f%%)",
            g_fsCacheHits, g_fsCacheMisses, 100.0 * g_fsCacheHits / fsTotal);
    if (dbcTotal > 0)
        Log("  DBC Index: %lld hits, %lld misses (%.1f%%)",
            g_dbcHits, g_dbcMisses, 100.0 * g_dbcHits / dbcTotal);
    if (strTotal > 0)
        Log("  String L2: %lld hits, %lld misses (%.1f%%)",
            g_strL2Hits, g_strL2Misses, 100.0 * g_strL2Hits / strTotal);
    if (cleTotal > 0)
        Log("  CLE Dedup: %lld deduped, %lld passed (%.1f%% dedup rate)",
            g_cleDedupHits, g_cleDedupPasses, 100.0 * g_cleDedupHits / cleTotal);
    if (evtTotal > 0)
        Log("  Event Hash: %lld SSE2 fast, %lld scalar (%.1f%% fast)",
            g_eventHashFast, g_eventHashSlow, 100.0 * g_eventHashFast / evtTotal);
    if (g_rsBatchFlushes > 0)
        Log("  RS Batch: %lld flushes, %lld coalesced",
            g_rsBatchFlushes, g_rsBatchCoalesced);
    Log("  Tex Prefetch: %lld prefetched", g_texPrefetchHits);
}