// ============================================================================
// Module: mpq_inflate_fast
//
// In our live gameplay profiler (41,698 samples), wow!0x00868407 was #6
// (1,740 samples = 4.59% of CPU).
// Address 0x00868340 is stock zlib 1.2.3's inflate_fast(), called during all
// MPQ chunk decompression (textures, terrain, models, sounds, spells, DBCs).
//
// Stock 2004 zlib copies matches 3 bytes at a time in scalar byte-by-byte loops:
//     do { *out++ = *from++; *out++ = *from++; *out++ = *from++; len -= 3; } while (len > 2);
//
// Because inflate_fast() guarantees avail_in >= 6 and avail_out >= 258 on entry,
// writing in 64-bit (8-byte) chunks is completely safe and conforms to the zlib-ng
// design. For dist >= 8 (>95% of all matches in WoW assets), unaligned 64-bit
// transfers copy up to 8x more bytes per instruction. For dist == 1, memset
// accelerates RLE padding blocks.
// ============================================================================

#include "mpq_inflate_fast.h"
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <emmintrin.h>
#include "MinHook.h"
#include "version.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

namespace MpqInflateFast {
namespace {

constexpr uintptr_t kTargetFn = 0x00868340;

struct Code {
    uint8_t  op;
    uint8_t  bits;
    uint16_t val;
};

// Layout matching stock zlib 1.2.3 in wow.exe
struct ZStreamInternal {
    uint8_t*     next_in;   // 0
    uint32_t     avail_in;  // 4
    uint32_t     total_in;  // 8
    uint8_t*     next_out;  // 12
    uint32_t     avail_out; // 16
    uint32_t     total_out; // 20
    const char*  msg;       // 24
    uint32_t*    state;     // 28
};

// Offsets in state:
// state[0]  = mode (11 = TYPE, 27 = BAD)
// state[8]  = wsize
// state[9]  = whave
// state[10] = wnext
// state[11] = window (uint8_t*)
// state[12] = hold
// state[13] = bits
// state[17] = lencode (Code*)
// state[18] = distcode (Code*)
// state[19] = lenbits
// state[20] = distbits

typedef void* (__cdecl* InflateFast_fn)(void* strm, int start);
static InflateFast_fn orig_InflateFast = nullptr;

static bool g_installed = false;

// Statistics
static uint64_t g_totalCalls        = 0;
static uint64_t g_fastMatchesCopied = 0;
static uint64_t g_rleMatchesCopied  = 0;
static uint64_t g_bytesDecompressed = 0;

static inline void CopyMatchFast(uint8_t*& out, const uint8_t* from, unsigned len, unsigned dist) {
    if (dist >= 8) {
        while (len > 8) {
            *reinterpret_cast<uint64_t*>(out) = *reinterpret_cast<const uint64_t*>(from);
            out += 8;
            from += 8;
            len -= 8;
        }
        *reinterpret_cast<uint64_t*>(out) = *reinterpret_cast<const uint64_t*>(from);
        out += len;
        ++g_fastMatchesCopied;
    } else if (dist == 1) {
        uint8_t b = *from;
        memset(out, b, len);
        out += len;
        ++g_rleMatchesCopied;
    } else {
        do {
            *out++ = *from++;
        } while (--len);
    }
}

void* __cdecl Hooked_InflateFast(void* strmPtr, int start) {
    ++g_totalCalls;
    if (!Config::g_settings.OptMpqInflateFast) {
        return orig_InflateFast ? orig_InflateFast(strmPtr, start) : nullptr;
    }

    ZStreamInternal* strm = reinterpret_cast<ZStreamInternal*>(strmPtr);
    uint32_t* state = strm->state;

    uint8_t* in   = strm->next_in;
    uint8_t* last = in + (strm->avail_in - 5);
    uint8_t* out  = strm->next_out;
    uint8_t* beg  = out - (start - strm->avail_out);
    uint8_t* end  = out + (strm->avail_out - 257);

    uint32_t wsize    = state[8];
    uint32_t whave    = state[9];
    uint32_t wnext    = state[10];
    uint8_t* window   = reinterpret_cast<uint8_t*>(state[11]);
    uint32_t hold     = state[12];
    uint32_t bits     = state[13];
    const Code* lcode = reinterpret_cast<const Code*>(state[17]);
    const Code* dcode = reinterpret_cast<const Code*>(state[18]);
    uint32_t lmask    = (1u << state[19]) - 1u;
    uint32_t dmask    = (1u << state[20]) - 1u;

    uint8_t* startOut = out;

    do {
        if (bits < 15) {
            hold += static_cast<uint32_t>(*in++) << bits;
            bits += 8;
            hold += static_cast<uint32_t>(*in++) << bits;
            bits += 8;
        }

        Code here = lcode[hold & lmask];
    dolen:
        hold >>= here.bits;
        bits -= here.bits;
        uint8_t op = here.op;

        if (op == 0) {
            *out++ = static_cast<uint8_t>(here.val);
        } else if (op & 16) {
            unsigned len = here.val;
            op &= 15;
            if (op) {
                if (bits < op) {
                    hold += static_cast<uint32_t>(*in++) << bits;
                    bits += 8;
                }
                len += hold & ((1u << op) - 1u);
                hold >>= op;
                bits -= op;
            }

            if (bits < 15) {
                hold += static_cast<uint32_t>(*in++) << bits;
                bits += 8;
                hold += static_cast<uint32_t>(*in++) << bits;
                bits += 8;
            }

            here = dcode[hold & dmask];
        dodist:
            hold >>= here.bits;
            bits -= here.bits;
            op = here.op;

            if (op & 16) {
                unsigned dist = here.val;
                op &= 15;
                if (bits < op) {
                    hold += static_cast<uint32_t>(*in++) << bits;
                    bits += 8;
                    if (bits < op) {
                        hold += static_cast<uint32_t>(*in++) << bits;
                        bits += 8;
                    }
                }
                dist += hold & ((1u << op) - 1u);
                hold >>= op;
                bits -= op;

                unsigned dlen = static_cast<unsigned>(out - beg);
                if (dist > dlen) {
                    unsigned fromDist = dist - dlen;
                    if (fromDist > whave) {
                        strm->msg = "invalid distance too far back";
                        state[0] = 27; // BAD
                        break;
                    }
                    const uint8_t* from = window;
                    if (wnext == 0) {
                        from += wsize - fromDist;
                        if (fromDist < len) {
                            len -= fromDist;
                            do { *out++ = *from++; } while (--fromDist);
                            from = out - dist;
                            CopyMatchFast(out, from, len, dist);
                        } else {
                            do { *out++ = *from++; } while (--len);
                        }
                    } else if (wnext >= fromDist) {
                        from += wnext - fromDist;
                        if (fromDist < len) {
                            len -= fromDist;
                            do { *out++ = *from++; } while (--fromDist);
                            from = out - dist;
                            CopyMatchFast(out, from, len, dist);
                        } else {
                            do { *out++ = *from++; } while (--len);
                        }
                    } else {
                        from += wsize + wnext - fromDist;
                        fromDist -= wnext;
                        if (fromDist < len) {
                            len -= fromDist;
                            do { *out++ = *from++; } while (--fromDist);
                            from = window;
                            if (wnext < len) {
                                len -= wnext;
                                unsigned wn = wnext;
                                do { *out++ = *from++; } while (--wn);
                                from = out - dist;
                                CopyMatchFast(out, from, len, dist);
                            } else {
                                do { *out++ = *from++; } while (--len);
                            }
                        } else {
                            do { *out++ = *from++; } while (--len);
                        }
                    }
                } else {
                    const uint8_t* from = out - dist;
                    CopyMatchFast(out, from, len, dist);
                }
            } else if ((op & 64) == 0) {
                here = dcode[here.val + (hold & ((1u << op) - 1u))];
                goto dodist;
            } else {
                strm->msg = "invalid distance code";
                state[0] = 27; // BAD
                break;
            }
        } else if ((op & 64) == 0) {
            here = lcode[here.val + (hold & ((1u << op) - 1u))];
            goto dolen;
        } else if (op & 32) {
            state[0] = 11; // TYPE
            break;
        } else {
            strm->msg = "invalid literal/length code";
            state[0] = 27; // BAD
            break;
        }
    } while (in < last && out < end);

    // Return unused bytes to input stream
    unsigned len = bits >> 3;
    in -= len;
    bits -= len << 3;
    hold &= (1u << bits) - 1u;

    strm->next_in   = in;
    strm->next_out  = out;
    strm->avail_in  = static_cast<uint32_t>(in < last ? 5 + (last - in) : 5 - (in - last));
    strm->avail_out = static_cast<uint32_t>(out < end ? 257 + (end - out) : 257 - (out - end));
    state[12]       = hold;
    state[13]       = bits;

    g_bytesDecompressed += static_cast<uint64_t>(out - startOut);
    return state;
}

// Self-test for chunk copy correctness
bool RunSelfTest() {
    uint8_t src[512];
    uint8_t dstFast[512];
    uint8_t dstScalar[512];

    for (int i = 0; i < 512; ++i) {
        src[i] = static_cast<uint8_t>((i * 7 + 13) & 0xFF);
    }

    const unsigned testDistances[] = { 1, 2, 3, 4, 7, 8, 16, 32, 64, 128 };
    const unsigned testLengths[]   = { 3, 4, 8, 15, 16, 31, 32, 64, 128, 258 };

    for (unsigned dist : testDistances) {
        for (unsigned len : testLengths) {
            memset(dstFast, 0xAA, sizeof(dstFast));
            memset(dstScalar, 0xAA, sizeof(dstScalar));

            uint8_t* pFast = dstFast + 200;
            const uint8_t* fromFast = pFast - dist;
            // Pre-fill seed
            for (unsigned i = 0; i < dist; ++i) dstFast[200 - dist + i] = src[i];
            for (unsigned i = 0; i < dist; ++i) dstScalar[200 - dist + i] = src[i];

            CopyMatchFast(pFast, fromFast, len, dist);

            uint8_t* pScalar = dstScalar + 200;
            const uint8_t* fromScalar = pScalar - dist;
            for (unsigned i = 0; i < len; ++i) {
                *pScalar++ = *fromScalar++;
            }

            if (memcmp(dstFast + 200, dstScalar + 200, len) != 0) {
                Log("[MpqInflateFast] Self-test FAILED for dist=%u len=%u!", dist, len);
                return false;
            }
        }
    }
    return true;
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptMpqInflateFast) return false;

    if (!RunSelfTest()) {
        Log("[MpqInflateFast] Self-test failed; hook aborted.");
        return false;
    }

    // Verify prologue: 55 8B EC 83 EC 3C 53 56 57
    static const unsigned char kExpectedPrologue[9] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x3C, 0x53, 0x56, 0x57 };
    if (memcmp(reinterpret_cast<const void*>(kTargetFn), kExpectedPrologue, sizeof(kExpectedPrologue)) != 0) {
        Log("[MpqInflateFast] Prologue mismatch at 0x%08X; hook aborted.", kTargetFn);
        return false;
    }

    MH_STATUS st = WineSafe_CreateHook(reinterpret_cast<void*>(kTargetFn),
                                       reinterpret_cast<void*>(&Hooked_InflateFast),
                                       reinterpret_cast<void**>(&orig_InflateFast));
    if (st != MH_OK) {
        Log("[MpqInflateFast] WineSafe_CreateHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    st = MH_EnableHook(reinterpret_cast<void*>(kTargetFn));
    if (st != MH_OK) {
        Log("[MpqInflateFast] MH_EnableHook failed (status=%d).", static_cast<int>(st));
        return false;
    }

    g_installed = true;
    Log("[MpqInflateFast] ACTIVE at 0x%08X: 64-bit SIMD chunk transfers armed (accelerates MPQ decompression).", kTargetFn);
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook(reinterpret_cast<void*>(kTargetFn));
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptMpqInflateFast || !g_installed) return;
    Log("[MpqInflateFast] calls: %llu, 64-bit fast copies: %llu, RLE fast copies: %llu, decompressed: %.2f MB",
        g_totalCalls, g_fastMatchesCopied, g_rleMatchesCopied, (double)g_bytesDecompressed / (1024.0 * 1024.0));
}

} // namespace MpqInflateFast

