// ============================================================================
// Module: vertex_fmt_inline.cpp
// Description: Removes a per-vertex call from the client's two vertex fillers.
// Safety & Threading: Patched once at init, before the render path runs.
// ============================================================================
//
// The UI batcher (sub_484B00) and the particle vertex filler (sub_6C4440) both
// decide, once per vertex, whether the colour needs its bytes swapped for the
// device's format. They ask like this:
//
//     mov  ecx, dword_C5DF88          ; the renderer
//     mov  [ebp+..], reg              ; unrelated spill
//     call sub_532AF0                 ; -> eax = ecx + 532
//     cmp  dword ptr [eax+14h], 1
//
// and sub_532AF0 is, in its entirety, `return this + 532`. So the whole
// sequence computes a fixed address from a global and reads one dword from it.
// The value is a property of the render device and cannot change between two
// vertices of the same batch, but the call is made for every vertex of every
// batch. Together those two functions were 5.06% of executing time in a
// CPU-bound tester profile.
//
// Rewriting either function is not worth it: 1597 and 877 bytes of x87
// arithmetic, and this project has already been burned transcribing x87. The
// call can be removed without touching anything else, because the replacement
// fits in the same bytes exactly:
//
//     mov  [ebp+..], reg              ; 3, unchanged and moved first
//     mov  eax, dword_C5DF88          ; 5
//     add  eax, 214h                  ; 5
//     nop                             ; 1
//                                     = 14, the same 14 it replaces
//
// What makes it safe rather than merely small:
//
//   * ecx is not set any more. It was only there to pass `this`. In sub_6C4440
//     the very next instruction is `mov ecx, 1`; in sub_484B00 the next use is
//     `movzx ecx, byte ptr [eax+2]`. Both overwrite it before reading it.
//   * `add` writes flags where `call` did not. The next instruction is a `cmp`
//     in both, which overwrites them before anything reads them.
//   * The original bytes are checked before writing. A client that does not
//     match byte for byte is left alone and says so.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "vertex_fmt_inline.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

namespace VertexFmtInline {

namespace {

// Where the sequence starts in each function, and the three bytes of the spill
// instruction that has to be preserved (it differs between the two sites).
struct Site {
    uintptr_t   addr;         // first byte of `mov ecx, dword_C5DF88`
    uint8_t     spill[3];     // the instruction between it and the call
    const char* what;
};

constexpr int kLen = 14;

const Site kSites[] = {
    { 0x00484F3F, { 0x89, 0x55, 0xDC }, "UI batcher (sub_484B00)" },
    { 0x006C475F, { 0x89, 0x5D, 0x28 }, "particle vertices (sub_6C4440)" },
};

// mov ecx, dword_C5DF88
const uint8_t kMovEcx[6] = { 0x8B, 0x0D, 0x88, 0xDF, 0xC5, 0x00 };

int g_patched = 0;
int g_rejected = 0;

bool PatchOne(const Site& s) {
    uint8_t* p = (uint8_t*)s.addr;

    if (IsBadReadPtr(p, kLen)) {
        Log("[VertexFmt] %s: address not readable, skipped", s.what);
        return false;
    }

    // Verify byte for byte: the six-byte global load, the three-byte spill this
    // site is expected to carry, and an E8 call opcode.
    if (memcmp(p, kMovEcx, sizeof(kMovEcx)) != 0 ||
        memcmp(p + 6, s.spill, 3) != 0 ||
        p[9] != 0xE8) {
        Log("[VertexFmt] %s: bytes do not match the expected sequence, left alone "
            "(%02X %02X %02X %02X %02X %02X | %02X %02X %02X | %02X)",
            s.what, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9]);
        g_rejected++;
        return false;
    }

    // And that the call really goes to sub_532AF0, rather than to whatever a
    // different build put at that offset.
    int32_t rel = *(int32_t*)(p + 10);
    uintptr_t target = s.addr + 9 + 5 + (uintptr_t)rel;
    if (target != 0x00532AF0) {
        Log("[VertexFmt] %s: the call goes to 0x%08X, not the accessor, left alone",
            s.what, (unsigned)target);
        g_rejected++;
        return false;
    }

    uint8_t repl[kLen];
    int i = 0;
    repl[i++] = s.spill[0];               // the spill, first now
    repl[i++] = s.spill[1];
    repl[i++] = s.spill[2];
    repl[i++] = 0xA1;                      // mov eax, [dword_C5DF88]
    repl[i++] = 0x88; repl[i++] = 0xDF; repl[i++] = 0xC5; repl[i++] = 0x00;
    repl[i++] = 0x05;                      // add eax, 214h
    repl[i++] = 0x14; repl[i++] = 0x02; repl[i++] = 0x00; repl[i++] = 0x00;
    repl[i++] = 0x90;                      // nop, to fill the 14th byte

    DWORD old = 0;
    if (!VirtualProtect(p, kLen, PAGE_EXECUTE_READWRITE, &old)) {
        Log("[VertexFmt] %s: VirtualProtect failed (%lu)", s.what, GetLastError());
        return false;
    }
    memcpy(p, repl, kLen);
    VirtualProtect(p, kLen, old, &old);
    FlushInstructionCache(GetCurrentProcess(), p, kLen);

    g_patched++;
    return true;
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptVertexFmtInline) return true;

    for (const Site& s : kSites) PatchOne(s);

    if (g_patched == 0) {
        Log("[VertexFmt] nothing patched (%d sites rejected). The client is a "
            "different build from the one these offsets were read out of.",
            g_rejected);
        return false;
    }

    Log("[VertexFmt] %d of %d vertex loops no longer call an accessor per vertex. "
        "The call computed a fixed offset from a global that cannot change "
        "between vertices; it is now inline. Same 14 bytes, no branch.",
        g_patched, (int)(sizeof(kSites) / sizeof(kSites[0])));
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptVertexFmtInline) return;
    Log("[VertexFmt] %d sites inlined, %d left alone", g_patched, g_rejected);
}

} // namespace VertexFmtInline
