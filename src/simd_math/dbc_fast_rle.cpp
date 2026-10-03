#include "dbc_fast_rle.h"
#include <cstdint>
#include <cstring>
#include <emmintrin.h>
#include "config.h"
#include "ab_test.h"
#include "self_bench.h"
#include "MinHook.h"
#include "version.h"
#include "sampling_profiler.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace DbcFastRle {
namespace {

typedef uint8_t* (__cdecl *RleDecompress_fn)(const uint8_t* src, size_t dst_len, uint8_t* dst);
static RleDecompress_fn g_orig = nullptr;

constexpr uintptr_t kTarget = 0x004CFBB0;
static const uint8_t kExpectedPrologue[8] = {
    0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x10, 0x8B, 0x4D
};

static bool g_dead = false;
static bool g_abSubject = false;
static int  g_benchId = -1;

constexpr uint32_t kLearnCalls = 500;
constexpr uint32_t kResampleMask = 0xFF;

static uint64_t g_calls = 0;
static uint64_t g_fastDecomp = 0;
static uint64_t g_totalBytesOut = 0;
static uint32_t g_verified = 0;
static uint32_t g_mismatches = 0;
static uint64_t g_controlCalls = 0;

// The client's run loop does not stop at the end of the destination: a run byte of
// 255 near the end writes up to 255 bytes past dst_len. The scratch buffers carry
// that much room beyond the largest length they are used for, so the client's
// overrun in verification lands in them and not in the next static.
constexpr size_t kVerifyMax = 2048;
constexpr size_t kOverrunRoom = 512;
static uint8_t g_verifyClientBuf[kVerifyMax + kOverrunRoom];
static uint8_t g_verifyFastBuf[kVerifyMax + kOverrunRoom];
static uint64_t g_clientEdge = 0;   // calls handed to the client for the two cases below

static void Retire(const char* reason) {
    g_dead = true;
    ++g_mismatches;
    Log("[DbcFastRle] RETIRED: %s. All subsequent calls delegate to client.", reason);
}

// Returns null for the two inputs where the client does something this does not
// copy: a zero length (the client still stores the first byte and returns dst+1)
// and a run that is longer than what is left (the client keeps writing past the
// end). Both go to the client's own routine, so the answer and the bytes written
// are the client's.
static inline uint8_t* DecompressFast(const uint8_t* src, size_t dst_len, uint8_t* dst) {
    if (!src || dst_len == 0) return nullptr;
    uint8_t* result = dst;
    const uint8_t* const end = dst + dst_len;

    *result++ = *src;
    const uint8_t* i = src + 1;

    while (result < end) {
        const uint8_t b = *i;
        *result++ = b;

        if (b == *(i - 1)) {
            uint32_t run = i[1];
            if (run != 0) {
                const size_t remaining = (size_t)(end - result);
                if (run > remaining) return nullptr;

                if (run >= 16) {
                    const __m128i v = _mm_set1_epi8((char)b);
                    while (run >= 16) {
                        _mm_storeu_si128((__m128i*)result, v);
                        result += 16;
                        run -= 16;
                    }
                }
                if (run >= 4) {
                    const uint32_t b4 = (uint32_t)b * 0x01010101u;
                    while (run >= 4) {
                        *(uint32_t*)result = b4;
                        result += 4;
                        run -= 4;
                    }
                }
                while (run > 0) {
                    *result++ = b;
                    --run;
                }
            }
            i += 2;
            if (result < end) {
                *result++ = *i;
            }
        }
        ++i;
    }
    return result;
}

static __declspec(noinline) uint8_t* VerifyWithClient(const uint8_t* src, size_t dst_len, uint8_t* dst) {
    if (dst_len > kVerifyMax) {
        // Too long for the scratch buffers: no comparison, same shortcut as the
        // unverified path.
        uint8_t* const r = DecompressFast(src, dst_len, dst);
        if (!r) { ++g_clientEdge; return g_orig(src, dst_len, dst); }
        return r;
    }

    const uint64_t t0 = SelfBench::Now();
    uint8_t* const clientRet = g_orig(src, dst_len, g_verifyClientBuf);
    const uint64_t clientCycles = SelfBench::Now() - t0;

    const uint64_t t1 = SelfBench::Now();
    uint8_t* const fastRet = DecompressFast(src, dst_len, g_verifyFastBuf);
    const uint64_t fastCycles = SelfBench::Now() - t1;

    if (!fastRet) {
        // One of the inputs the client treats differently. Nothing to compare:
        // the client's output is the answer, and it is what was just produced.
        ++g_clientEdge;
        const size_t written = (size_t)(clientRet - g_verifyClientBuf);
        std::memcpy(dst, g_verifyClientBuf, written);
        return dst + written;
    }

    const size_t clientWritten = (size_t)(clientRet - g_verifyClientBuf);
    const size_t fastWritten = (size_t)(fastRet - g_verifyFastBuf);

    if (clientWritten != fastWritten || std::memcmp(g_verifyClientBuf, g_verifyFastBuf, clientWritten) != 0) {
        Retire("decompressed buffer mismatch against client");
        std::memcpy(dst, g_verifyClientBuf, clientWritten);
        return dst + clientWritten;
    }

    ++g_verified;
    if (g_benchId >= 0) {
        SelfBench::Pair(g_benchId, fastCycles, clientCycles);
    }

    std::memcpy(dst, g_verifyFastBuf, fastWritten);
    return dst + fastWritten;
}

__declspec(safebuffers)
static uint8_t* __cdecl Hook_DbcRle(const uint8_t* src, size_t dst_len, uint8_t* dst) {
    ++g_calls;

    if (g_dead) {
        return g_orig(src, dst_len, dst);
    }

    if (g_abSubject && AbTest::StandAside()) {
        ++g_controlCalls;
        return g_orig(src, dst_len, dst);
    }

    const bool isLearning = (g_verified < kLearnCalls);
    const bool shouldVerify = isLearning || ((g_calls & kResampleMask) == 0);

    if (shouldVerify) {
        return VerifyWithClient(src, dst_len, dst);
    }

    uint8_t* const ret = DecompressFast(src, dst_len, dst);
    if (!ret) {
        ++g_clientEdge;
        return g_orig(src, dst_len, dst);
    }
    ++g_fastDecomp;
    g_totalBytesOut += dst_len;
    return ret;
}

} // anonymous namespace

void Init() {
    if (!Config::g_settings.OptDbcFastRle) {
        return;
    }

    void* const target = (void*)kTarget;
    if (!WowOpt_ClientPatchAllowed(target)) {
        Log("[DbcFastRle] NOT active: client patches disallowed at 0x%08X", (uintptr_t)target);
        return;
    }

    if (std::memcmp(target, kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[DbcFastRle] NOT active: prologue mismatch at 0x%08X", (uintptr_t)target);
        return;
    }

    const MH_STATUS status = WineSafe_CreateHook(target, (void*)&Hook_DbcRle, (void**)&g_orig);
    if (status != MH_OK) {
        Log("[DbcFastRle] NOT active: MH_CreateHook failed (%d) at 0x%08X", status, (uintptr_t)target);
        return;
    }

    if (WO_EnableHook(target) != MH_OK) {
        Log("[DbcFastRle] NOT active: MH_EnableHook failed at 0x%08X", (uintptr_t)target);
        return;
    }

    g_benchId = SelfBench::Register("DbcFastRle");
    SamplingProfiler::RegisterSelfSymbol("DbcFastRle", (const void*)kTarget);

    Log("[DbcFastRle] ACTIVE on DBC/record RLE decompressor (sub_4CFBB0 @ 0x%08X, %u learn calls, 1/256 sampling)",
        (uintptr_t)kTarget, kLearnCalls);

    if (AbTest::IsSubject("DbcFastRle", &g_abSubject)) {
        Log("[DbcFastRle]   under A/B test (subject=%d)", g_abSubject ? 1 : 0);
    }
}

void Shutdown() {
    // Hooks cleared on exit by MinHook
}

void LogStats() {
    if (!Config::g_settings.OptDbcFastRle) return;
    Log("[DbcFastRle] calls=%llu fast=%llu out_bytes=%llu verified=%u mismatches=%u ctrl=%llu dead=%d",
        g_calls, g_fastDecomp, g_totalBytesOut, g_verified, g_mismatches, g_controlCalls, g_dead ? 1 : 0);
    Log("[DbcFastRle]   %llu call(s) went to the client's routine because the length was zero or a run "
        "reached past the end of the destination, which the client writes through. Plain counter, lower bound.",
        g_clientEdge);
}

} // namespace DbcFastRle
