// ============================================================================
// Module: terrain_alpha_unpack_fast.cpp
//
// Vectorized terrain texture streaming and shadow channel packing:
//   1. DecodeAlphaRLE (sub_7B7420 @ 0x007B7420, 107 B):
//      - In original client: scalar byte-by-byte loop and repeated _memset calls.
//      - Optimized: 128-bit SSE2 vector loads/stores for both run-length fills
//        and literal copy runs.
//   2. UnpackAlphaShadowBitsFixed8888Mip0 (sub_7B7C60 @ 0x007B7C60, 338 B):
//      - In original client: per-pixel bit extraction, shift, table lookups,
//        and scalar channel packing.
//      - Optimized: 8-pixel unrolled batch packing directly from alpha rows and
//        shadow bit masks.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <emmintrin.h>

#include "terrain_alpha_unpack_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "session_verdict.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace TerrainAlphaUnpackFast {

namespace {

constexpr uintptr_t kTargetDecode    = 0x007B7420;
constexpr uintptr_t kTargetUnpack    = 0x007B7C60;
constexpr uintptr_t kSetupAlphaRowsFn = 0x007B74A0;

const unsigned char kPrologueDecode[8] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0x56, 0x57
};

const unsigned char kPrologueUnpack[8] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x3C, 0x8B, 0x45
};

#pragma pack(push, 1)
struct SLayerAlpha {
    uint32_t m_flags;
    uint8_t* m_alphaData;
};
#pragma pack(pop)

typedef void* (*OrigDecodeFn)();
OrigDecodeFn g_origDecode = nullptr;

typedef void (__stdcall *OrigUnpackFn)(uint32_t* dstBase, int32_t dstOffset, int32_t dstPitch,
                                       uint32_t size, SLayerAlpha* cursors, int32_t alphaSlot,
                                       uint8_t* shadowMap);
OrigUnpackFn g_origUnpack = nullptr;

bool g_installed = false;
bool g_dead = false;
bool g_abSubject = false;

unsigned long long g_callsDecode = 0;
unsigned long long g_fastDecode = 0;
unsigned long long g_controlDecode = 0;
unsigned g_verifiedDecode = 0;
unsigned g_mismatchesDecode = 0;

unsigned long long g_callsUnpack = 0;
unsigned long long g_fastUnpack = 0;
unsigned long long g_controlUnpack = 0;
unsigned g_verifiedUnpack = 0;
unsigned g_mismatchesUnpack = 0;

constexpr uint32_t kLearnCalls   = 10000;
constexpr uint32_t kResampleMask = 127;

// Call original __usercall sub_7B7420 (ebx = src, [esp+4] = dst, [esp+8] = count)
static uint8_t* CallOrig_DecodeAlphaRLE(const uint8_t* src, uint8_t* dst, int32_t count) {
    uint8_t* res;
    __asm {
        push ebx
        mov ebx, src
        push count
        push dst
        call g_origDecode
        add esp, 8
        mov res, eax
        pop ebx
    }
    return res;
}

// Optimized SSE2 DecodeAlphaRLE implementation
static uint8_t* Fast_DecodeAlphaRLE(const uint8_t* src, uint8_t* dst, int32_t count) {
    int32_t dstIndex = 0;
    while (dstIndex < count) {
        int8_t header = (int8_t)*src++;
        if (header < 0) {
            uint32_t runLength = (uint32_t)(header & 0x7F);
            uint8_t val = *src++;
            if (runLength > 0) {
                if (dstIndex + (int32_t)runLength > count) {
                    runLength = (uint32_t)(count - dstIndex);
                }
                uint8_t* out = dst + dstIndex;
                uint32_t rem = runLength;
                if (rem >= 16) {
                    __m128i v = _mm_set1_epi8((char)val);
                    while (rem >= 16) {
                        _mm_storeu_si128((__m128i*)out, v);
                        out += 16;
                        rem -= 16;
                    }
                }
                if (rem > 0) {
                    memset(out, val, rem);
                }
                dstIndex += runLength;
            }
        } else {
            uint32_t runLength = (uint32_t)(uint8_t)header;
            if (runLength > 0) {
                if (dstIndex + (int32_t)runLength > count) {
                    runLength = (uint32_t)(count - dstIndex);
                }
                uint8_t* out = dst + dstIndex;
                uint32_t rem = runLength;
                if (rem >= 16) {
                    while (rem >= 16) {
                        __m128i v = _mm_loadu_si128((const __m128i*)src);
                        _mm_storeu_si128((__m128i*)out, v);
                        src += 16;
                        out += 16;
                        rem -= 16;
                    }
                }
                if (rem > 0) {
                    memcpy(out, src, rem);
                    src += rem;
                }
                dstIndex += runLength;
            }
        }
    }
    return const_cast<uint8_t*>(src);
}

extern "C" uint8_t* __cdecl Dispatch_DecodeAlphaRLE(const uint8_t* src, uint8_t* dst, int32_t count) {
    ++g_callsDecode;
    if (g_dead || !src || !dst || count <= 0) {
        return CallOrig_DecodeAlphaRLE(src, dst, count);
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_controlDecode;
        return CallOrig_DecodeAlphaRLE(src, dst, count);
    }

    const bool learning = g_verifiedDecode < kLearnCalls ||
                          ((uint32_t)g_callsDecode & kResampleMask) == 0;

    if (learning) {
        uint8_t refBuf[512];
        uint8_t* pRef = (count <= (int32_t)sizeof(refBuf)) ? refBuf : (uint8_t*)malloc(count);
        if (pRef) {
            uint8_t* origRes = CallOrig_DecodeAlphaRLE(src, pRef, count);
            uint8_t* fastRes = Fast_DecodeAlphaRLE(src, dst, count);
            if (memcmp(dst, pRef, (size_t)count) != 0 || fastRes != origRes) {
                g_dead = true;
                ++g_mismatchesDecode;
                Log("[TerrainAlpha] DecodeAlphaRLE MISMATCH! Retiring hook.");
                Verdict::Add(Verdict::Bad, "DecodeAlphaRLE mismatch against reference");
                memcpy(dst, pRef, (size_t)count);
                if (pRef != refBuf) free(pRef);
                return origRes;
            }
            if (pRef != refBuf) free(pRef);
            ++g_verifiedDecode;
            ++g_fastDecode;
            return fastRes;
        }
    }

    ++g_fastDecode;
    return Fast_DecodeAlphaRLE(src, dst, count);
}

__declspec(naked) void Hook_DecodeAlphaRLE() {
    __asm {
        push dword ptr [esp+8]  // count
        push dword ptr [esp+8]  // dst (offset shifted by 4)
        push ebx                // src
        call Dispatch_DecodeAlphaRLE
        add esp, 12
        ret
    }
}

// Invokes SetupAlphaRows (0x007B74A0)
static void CallSetupAlphaRows(uint8_t** pShadowMap, uint8_t** pShadowRow, SLayerAlpha* cursors,
                               uint32_t rowSize, uint8_t** alphaRows) {
    __asm {
        push alphaRows
        push rowSize
        push cursors
        mov edx, pShadowRow
        mov ecx, pShadowMap
        mov eax, kSetupAlphaRowsFn
        call eax
        add esp, 12
    }
}

static void Fast_UnpackAlphaShadow(uint32_t* dstBase, int32_t dstOffset, int32_t dstPitch,
                                   uint32_t size, SLayerAlpha* cursors, int32_t alphaSlot,
                                   uint8_t* shadowMap) {
    uint32_t* dst = dstBase + dstOffset;

    for (uint32_t y = 0; y < size; ++y) {
        uint8_t* shadowRow = nullptr;
        uint8_t* alphaRows[4] = { nullptr, nullptr, nullptr, nullptr };
        CallSetupAlphaRows(&shadowMap, &shadowRow, cursors, size, alphaRows);

        uint32_t x = 0;
        if (!alphaSlot) {
            // Fast 8-pixel batching when alphaSlot is 0
            for (; x + 8 <= size; x += 8) {
                const uint8_t sbyte = shadowRow[x >> 3];
                for (int i = 0; i < 8; ++i) {
                    const uint32_t b = alphaRows[3][x + i];
                    const uint32_t g = alphaRows[2][x + i];
                    const uint32_t r = alphaRows[1][x + i];
                    const uint32_t a = (sbyte & (1 << i)) ? 0 : 255;
                    dst[x + i] = (a << 24) | (r << 16) | (g << 8) | b;
                }
            }
            for (; x < size; ++x) {
                const uint8_t sbyte = shadowRow[x >> 3];
                const uint32_t b = alphaRows[3][x];
                const uint32_t g = alphaRows[2][x];
                const uint32_t r = alphaRows[1][x];
                const uint32_t a = (sbyte & (1 << (x & 7))) ? 0 : 255;
                dst[x] = (a << 24) | (r << 16) | (g << 8) | b;
            }
        } else {
            // Fast 8-pixel batching with dynamic alphaSlot computation
            for (; x + 8 <= size; x += 8) {
                const uint8_t sbyte = shadowRow[x >> 3];
                for (int i = 0; i < 8; ++i) {
                    uint32_t alpha[4];
                    alpha[1] = alphaRows[1][x + i];
                    alpha[2] = alphaRows[2][x + i];
                    alpha[3] = alphaRows[3][x + i];
                    alpha[alphaSlot] = (uint32_t)(255 - alpha[3] - alpha[2] - alpha[1] - alphaRows[0][x + i]);
                    const uint32_t a = (sbyte & (1 << i)) ? 0 : 255;
                    dst[x + i] = (a << 24) | (alpha[1] << 16) | (alpha[2] << 8) | alpha[3];
                }
            }
            for (; x < size; ++x) {
                const uint8_t sbyte = shadowRow[x >> 3];
                uint32_t alpha[4];
                alpha[1] = alphaRows[1][x];
                alpha[2] = alphaRows[2][x];
                alpha[3] = alphaRows[3][x];
                alpha[alphaSlot] = (uint32_t)(255 - alpha[3] - alpha[2] - alpha[1] - alphaRows[0][x]);
                const uint32_t a = (sbyte & (1 << (x & 7))) ? 0 : 255;
                dst[x] = (a << 24) | (alpha[1] << 16) | (alpha[2] << 8) | alpha[3];
            }
        }

        dst += dstPitch;
    }
}

void __stdcall Hooked_UnpackAlphaShadow(uint32_t* dstBase, int32_t dstOffset, int32_t dstPitch,
                                       uint32_t size, SLayerAlpha* cursors, int32_t alphaSlot,
                                       uint8_t* shadowMap) {
    ++g_callsUnpack;
    if (g_dead || !dstBase || !cursors || size == 0) {
        g_origUnpack(dstBase, dstOffset, dstPitch, size, cursors, alphaSlot, shadowMap);
        return;
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_controlUnpack;
        g_origUnpack(dstBase, dstOffset, dstPitch, size, cursors, alphaSlot, shadowMap);
        return;
    }

    const bool learning = g_verifiedUnpack < kLearnCalls ||
                          ((uint32_t)g_callsUnpack & kResampleMask) == 0;

    if (learning) {
        // Dual-run verification: clone cursors and shadowMap state
        SLayerAlpha savedCursors[4];
        memcpy(savedCursors, cursors, sizeof(savedCursors));
        uint8_t* savedShadowMap = shadowMap;

        const size_t totalPixels = (size_t)size * (size_t)dstPitch;
        uint32_t* refBuf = (uint32_t*)malloc(totalPixels * sizeof(uint32_t));
        if (refBuf) {
            memcpy(refBuf, dstBase, totalPixels * sizeof(uint32_t));

            // Run original with saved state
            g_origUnpack(refBuf, dstOffset, dstPitch, size, savedCursors, alphaSlot, savedShadowMap);

            // Run fast with actual pointers
            Fast_UnpackAlphaShadow(dstBase, dstOffset, dstPitch, size, cursors, alphaSlot, shadowMap);

            // Compare result rows
            bool match = true;
            for (uint32_t y = 0; y < size; ++y) {
                const uint32_t* refRow = refBuf + dstOffset + y * dstPitch;
                const uint32_t* fastRow = dstBase + dstOffset + y * dstPitch;
                if (memcmp(fastRow, refRow, size * sizeof(uint32_t)) != 0) {
                    match = false;
                    break;
                }
            }

            if (!match) {
                g_dead = true;
                ++g_mismatchesUnpack;
                Log("[TerrainAlpha] UnpackAlphaShadow MISMATCH! Retiring hook.");
                Verdict::Add(Verdict::Bad, "UnpackAlphaShadow mismatch against reference");
                memcpy(dstBase, refBuf, totalPixels * sizeof(uint32_t));
                free(refBuf);
                return;
            }

            free(refBuf);
            ++g_verifiedUnpack;
            ++g_fastUnpack;
            return;
        }
    }

    Fast_UnpackAlphaShadow(dstBase, dstOffset, dstPitch, size, cursors, alphaSlot, shadowMap);
    ++g_fastUnpack;
}

bool BytesMatch(uintptr_t addr, const unsigned char* want, int n) {
    __try {
        return memcmp((const void*)addr, want, (size_t)n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

bool Init() {
    if (g_installed) return true;
    if (!Config::g_settings.OptTerrainAlphaUnpackFast) {
        Log("[TerrainAlpha] Disabled via config.");
        return false;
    }

    if (!BytesMatch(kTargetDecode, kPrologueDecode, sizeof(kPrologueDecode))) {
        Log("[TerrainAlpha] Prologue mismatch at 0x%08X; aborting.", kTargetDecode);
        Verdict::Add(Verdict::Warn, "TerrainAlpha Decode prologue mismatch");
        return false;
    }

    if (!BytesMatch(kTargetUnpack, kPrologueUnpack, sizeof(kPrologueUnpack))) {
        Log("[TerrainAlpha] Prologue mismatch at 0x%08X; aborting.", kTargetUnpack);
        Verdict::Add(Verdict::Warn, "TerrainAlpha Unpack prologue mismatch");
        return false;
    }

    MH_STATUS s1 = WineSafe_CreateHook((void*)kTargetDecode,
                                       (void*)Hook_DecodeAlphaRLE,
                                       (void**)&g_origDecode);
    if (s1 != MH_OK) {
        Log("[TerrainAlpha] Failed to hook DecodeAlphaRLE (status=%d)", s1);
        Verdict::Add(Verdict::Bad, "Failed to hook DecodeAlphaRLE");
        return false;
    }

    MH_STATUS s2 = WineSafe_CreateHook((void*)kTargetUnpack,
                                       (void*)Hooked_UnpackAlphaShadow,
                                       (void**)&g_origUnpack);
    if (s2 != MH_OK) {
        Log("[TerrainAlpha] Failed to hook UnpackAlphaShadow (status=%d)", s2);
        Verdict::Add(Verdict::Bad, "Failed to hook UnpackAlphaShadow");
        return false;
    }

    if (WO_EnableHook((void*)kTargetDecode) != MH_OK ||
        WO_EnableHook((void*)kTargetUnpack) != MH_OK) {
        Log("[TerrainAlpha] Failed to enable hooks.");
        Verdict::Add(Verdict::Bad, "Failed to enable TerrainAlpha hooks");
        return false;
    }

    g_installed = true;
    g_abSubject = AbTest::IsSubject("TerrainAlphaUnpackFast", &g_abSubject);
    SamplingProfiler::RegisterSelfSymbol("TerrainAlpha_DecodeHook", (const void*)&Hook_DecodeAlphaRLE);
    SamplingProfiler::RegisterSelfSymbol("TerrainAlpha_UnpackHook", (const void*)&Hooked_UnpackAlphaShadow);

    Log("[TerrainAlpha] ACTIVE on DecodeAlphaRLE (0x007B7420) and UnpackAlphaShadow (0x007B7C60). "
        "Vectorized SSE2 RLE decode and 8-pixel batch unpack.");
    // active
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook((void*)kTargetDecode);
    MH_DisableHook((void*)kTargetUnpack);
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptTerrainAlphaUnpackFast) return;
    if (!g_installed) return;
    Log("[TerrainAlpha] Decode calls=%llu (fast=%llu, verified=%u, control=%llu) mismatches=%u%s",
        g_callsDecode, g_fastDecode, g_verifiedDecode, g_controlDecode, g_mismatchesDecode,
        g_dead ? " [RETIRED]" : "");
    Log("[TerrainAlpha] Unpack calls=%llu (fast=%llu, verified=%u, control=%llu) mismatches=%u%s",
        g_callsUnpack, g_fastUnpack, g_verifiedUnpack, g_controlUnpack, g_mismatchesUnpack,
        g_dead ? " [RETIRED]" : "");
}

}  // namespace TerrainAlphaUnpackFast
