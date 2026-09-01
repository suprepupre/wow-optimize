// ============================================================================
// Module: flight_recorder.cpp
//
// Every visual defect reported against this project has cost three to five
// rounds of questions, and every one of them stalled at the same place. The
// player says "the shadows flashed while I was flying over Redridge, around
// 20:35". The log answers with ten-second windows of averages, in which the
// second they are describing is one entry in three hundred and has been averaged
// away. So the next message asks for another log, and the one after that.
//
// The shadow flicker took four rounds and ended with two features moved in
// opposite directions before the counters were read against the complaint at
// all - and when they finally were, they said the mechanism had fired zero times
// while the symptom was continuously present. The garbled SavedVariables names
// took months to catch because nothing recorded the moment a name was written.
//
// The missing piece is the same every time: a way for the person who can see the
// bug to say NOW, and have the log keep the frames around that instant instead
// of their average.
//
// ---------------------------------------------------------------------------
// Why a key and not a slash command
//
// The obvious route is a Lua function the addon calls. It is not available: the
// client validates lua_CFunction pointers against its own range and raises a
// fatal ERROR #134 for one outside it, which is why RegisterLuaFunction in
// lua_optimize.cpp is there and why every call to it is commented out.
//
// A key works everywhere the DLL runs, which includes the two places that matter
// most and where no addon is executing at all: a loading screen, and the
// character-switch transition where the garbled names appear. Scroll Lock by
// default because the client binds no action to it.
//
// ---------------------------------------------------------------------------
// What it records
//
// A fixed ring of frames. Each entry is the frame's duration and one absolute
// value per registered column; the dump prints the deltas, so a column that did
// nothing costs a zero and reads as one. Columns are claimed by name at startup
// by whichever module wants to be visible in a dump - the shadow cascades, the
// Lua compiler, the file layer.
//
// Absolute values rather than per-frame deltas, deliberately. A module bumping a
// counter does not have to know when a frame ended, cannot lose a bump to a race
// with the ring, and a dump that spans a gap still subtracts correctly across it.
//
// 512 frames at 24 columns is 48 KB, and the per-frame cost is one memcpy of 96
// bytes. It is off by default anyway.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "flight_recorder.h"
#include "config.h"

extern "C" void Log(const char* fmt, ...);

namespace FlightRecorder {
namespace {

constexpr int kSlots  = 24;
constexpr int kFrames = 512;
constexpr int kDumpFrames = 240;   // what a dump prints, newest last

struct Frame {
    double   ms;
    uint32_t v[kSlots];
};

bool     g_active = false;
char     g_name[kSlots][24] = {};
uint32_t g_cur[kSlots] = {};
int      g_slotsUsed = 0;

Frame    g_ring[kFrames] = {};
uint32_t g_written = 0;            // total frames ever written; index = % kFrames

LARGE_INTEGER g_freq = {};
LARGE_INTEGER g_last = {};
bool     g_haveLast = false;

int      g_markKey = 0;
bool     g_keyWasDown = false;
uint32_t g_marks = 0;

}  // namespace

int RegisterSlot(const char* name) {
    if (!g_active || g_slotsUsed >= kSlots || !name) return -1;
    int id = g_slotsUsed++;
    lstrcpynA(g_name[id], name, (int)sizeof(g_name[0]));
    return id;
}

void Bump(int slot, uint32_t n) {
    if (slot < 0 || slot >= g_slotsUsed) return;
    g_cur[slot] += n;
}

void OnFrame() {
    if (!g_active) return;

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double ms = 0.0;
    if (g_haveLast && g_freq.QuadPart)
        ms = (double)(now.QuadPart - g_last.QuadPart) * 1000.0 / (double)g_freq.QuadPart;
    g_last = now;
    g_haveLast = true;

    Frame& f = g_ring[g_written % kFrames];
    f.ms = ms;
    memcpy(f.v, g_cur, sizeof(f.v));
    ++g_written;
}

void Mark(const char* why) {
    if (!g_active) {
        Log("[FlightRec] mark requested but the recorder is off - nothing to show");
        return;
    }
    ++g_marks;

    SYSTEMTIME st;
    GetLocalTime(&st);
    Log("=== FLIGHT RECORDER MARK %u === %02u:%02u:%02u.%03u - %s",
        g_marks, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        why ? why : "(no reason given)");

    if (g_written == 0) {
        Log("[FlightRec] no frame has been recorded yet - the frame boundary has "
            "not run, so this is not an empty ring, it is an unfed one");
        return;
    }

    uint32_t have = g_written < (uint32_t)kFrames ? g_written : (uint32_t)kFrames;
    uint32_t want = have < (uint32_t)kDumpFrames ? have : (uint32_t)kDumpFrames;
    uint32_t first = g_written - want;   // oldest frame to print

    // A header naming the columns, so a dump can be read without the source.
    char hdr[512];
    int w = _snprintf(hdr, sizeof(hdr) - 1, "[FlightRec] frame   ms");
    for (int s = 0; s < g_slotsUsed && w > 0 && w < (int)sizeof(hdr) - 12; ++s)
        w += _snprintf(hdr + w, sizeof(hdr) - 1 - w, " %8.8s", g_name[s]);
    hdr[sizeof(hdr) - 1] = 0;
    Log("%s", hdr);

    Log("[FlightRec] the last %u frames before the mark; counters are per frame, "
        "differenced from the running totals the ring stores", want);

    uint32_t printed = 0;
    for (uint32_t i = first; i < g_written; ++i) {
        const Frame& f = g_ring[i % kFrames];
        // The frame before it, for the delta. The oldest entry in the window has
        // one only when the ring holds something older still.
        bool havePrev = (i > 0) && (g_written - i) < (uint32_t)kFrames;
        const Frame* p = havePrev ? &g_ring[(i - 1) % kFrames] : nullptr;

        // Frames where nothing happened and the timing is unremarkable are the
        // bulk of any window and say nothing. Print a frame when a counter moved
        // or the frame was slow; count the rest.
        bool interesting = (f.ms > 20.0);
        if (p) {
            for (int s = 0; s < g_slotsUsed; ++s)
                if (f.v[s] != p->v[s]) { interesting = true; break; }
        }
        if (!interesting) continue;

        char line[512];
        int n = _snprintf(line, sizeof(line) - 1, "[FlightRec] %5u %6.2f",
                          (unsigned)i, f.ms);
        for (int s = 0; s < g_slotsUsed && n > 0 && n < (int)sizeof(line) - 12; ++s) {
            uint32_t d = p ? (f.v[s] - p->v[s]) : 0;
            n += _snprintf(line + n, sizeof(line) - 1 - n, " %8u", d);
        }
        line[sizeof(line) - 1] = 0;
        Log("%s", line);
        if (++printed >= 120) {
            Log("[FlightRec] ... stopping at 120 printed frames; the rest of the "
                "window had activity too and is not shown");
            break;
        }
    }

    if (printed == 0) {
        Log("[FlightRec] every frame in the window was under 20 ms with no counter "
            "moving. That is a measurement, not an empty log: whatever you saw did "
            "not touch anything this recorder watches.");
    }
    Log("=== END MARK %u ===", g_marks);
}

void PollHotkey() {
    if (!g_active || !g_markKey) return;
    bool down = (GetAsyncKeyState(g_markKey) & 0x8000) != 0;
    if (down && !g_keyWasDown) Mark("marker key pressed");
    g_keyWasDown = down;
}

bool Init() {
    if (!Config::g_settings.OptFlightRecorder) return true;

    QueryPerformanceFrequency(&g_freq);
    if (!g_freq.QuadPart) {
        Log("[FlightRec] NOT active: no performance counter, so frame times "
            "would all read zero");
        return false;
    }

    g_markKey = Config::g_settings.FlightRecorderKey;
    g_active = true;

    Log("[FlightRec] ACTIVE: keeping the last %d frames, dumping %d of them on a "
        "mark. Press virtual key 0x%02X the moment something looks wrong and the "
        "log will carry that second frame by frame instead of a ten-second "
        "average. Nothing is written until you press it.",
        kFrames, kDumpFrames, (unsigned)g_markKey);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptFlightRecorder) return;
    if (!g_active) { Log("[FlightRec] not installed - nothing recorded"); return; }
    Log("[FlightRec] %u frames recorded, %d columns claimed, %u mark(s) taken%s",
        g_written, g_slotsUsed, g_marks,
        g_marks == 0 ? " - press the marker key when you see the problem" : "");
}

}  // namespace FlightRecorder
