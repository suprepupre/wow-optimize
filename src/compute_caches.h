#pragma once
#include <cstdint>
#include <cstddef>

bool InitComputeCaches();
void ShutdownComputeCaches();

// 1. BZ2 Decompression SSE2
void SSE2_MoveToFront(uint8_t* data, size_t len, uint8_t* mtfState);

// 2. Vertex Transform SSE2
void SSE2_BatchVertexTransform(
    const float* positions, const float* normals, const float* matrix,
    float* outPositions, float* outNormals);

// 3. FMOD IT Codec Cache
bool ITCodecCache_Get(uint32_t fileHash, uint32_t* channels, uint32_t* sampleRate, uint32_t* samples);
void ITCodecCache_Put(uint32_t fileHash, uint32_t channels, uint32_t sampleRate, uint32_t samples);

// 4. Render State Tracker
bool RenderStateTracker_ShouldSet(uint32_t state, uint32_t value);
void RenderStateTracker_Reset();

// 5. Tooltip Prefetch
void TooltipPrefetch_Begin(uintptr_t itemPtr, uintptr_t spellPtr);

// 6. FrameScript Dispatch Cache
uintptr_t FSDispatchCache_Get(uint32_t opcode);
void FSDispatchCache_Put(uint32_t opcode, uintptr_t handler);

// 7. M2 Model Prepare Cache
bool M2PrepareCache_Get(uint32_t modelHash, uint32_t* bones, uint32_t* textures, uint32_t* anims);
void M2PrepareCache_Put(uint32_t modelHash, uint32_t bones, uint32_t textures, uint32_t anims);

// 8. Spell Batch Processor
struct SpellBatchEntry { uint32_t spellId; uint32_t timestamp; uint32_t sourceGuid; uint32_t destGuid; bool valid; };
void SpellBatch_Add(uint32_t spellId, uint32_t timestamp, uint32_t srcGuid, uint32_t dstGuid);
int SpellBatch_Flush(SpellBatchEntry* outBatch);

// 9. Regex Extended Cache
uintptr_t RegexExtCache_Get(uint64_t patternHash, uint32_t* size);
void RegexExtCache_Put(uint64_t patternHash, uintptr_t compiledPtr, uint32_t compiledSize);

// 10. Audio Mixer Cache
bool MixerCache_Get(uint32_t configHash, uint32_t* sampleRate, uint32_t* channels, uint32_t* bufLen);
void MixerCache_Put(uint32_t configHash, uint32_t sampleRate, uint32_t channels, uint32_t bufLen);