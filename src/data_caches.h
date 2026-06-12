#pragma once
#include <cstdint>
#include <cstddef>

bool InitDataCaches();
void ShutdownDataCaches();

// 1. Spell History Cache
bool SpellCache_Lookup(uint32_t spellId, uint32_t* outResultHash);
void SpellCache_Store(uint32_t spellId, uint32_t resultHash);

// 2. M2 Model Init Cache
bool ModelCache_Get(uint32_t pathHash, float* farClip, float* nearClip, float* fov);
void ModelCache_Put(uint32_t pathHash, float farClip, float nearClip, float fov);

// 3. FMOD Audio Config Cache
bool AudioCache_Get(uint32_t configHash, uint32_t* result);
void AudioCache_Put(uint32_t configHash, uint32_t result);

// 4. FrameScript Opcode Cache
bool FrameScriptCache_Get(uint64_t eventKey, uint32_t* result);
void FrameScriptCache_Put(uint64_t eventKey, uint32_t result);

// 5. DBC Record Index
uintptr_t DbcIndex_Lookup(uint32_t recordId);
void DbcIndex_Store(uint32_t recordId, uintptr_t recordPtr);

// 6. Event Name SSE2 Hash
uint32_t FastEventNameHash(const char* name, int len);

// 7. String Interning L2 Cache
uintptr_t StrL2_Lookup(uint64_t nameHash);
void StrL2_Store(uint64_t nameHash, uintptr_t tstringPtr);
void StrL2_Invalidate();

// 8. Combat Log Bloom Dedup
void CombatLogDedup_NewFrame();
bool CombatLogDedup_IsDuplicate(uint64_t eventFingerprint);

// 9. Render State Batch
struct RenderStateBatch { uint32_t state; uint32_t value; };
bool RenderStateBatch_Add(uint32_t state, uint32_t value);
int RenderStateBatch_Flush(RenderStateBatch* outBatch);

// 10. Texture Decode Prefetch
void TextureDecodePrefetch(const void* blpData, size_t dataSize);