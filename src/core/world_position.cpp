// ============================================================================
// Module: world_position.cpp
// Description: The client's world streaming centre, and whether it can be read.
// Safety & Threading: Main thread.
// ============================================================================
//
// Three modules used to read a player position from 0x00BE1F30. No instruction
// in wow.exe references that address - it has no cross-references and no type
// information, and it sits in zero-filled storage nothing writes. So all three
// read 0.0, 0.0 forever:
//
//   perf_diagnostics printed "Player position: X=0.00, Y=0.00" on every stutter
//   anim_census measured every distance from the map origin
//   predictive_prefetch returned at its own "cx == 0 && cy == 0" guard on every
//     frame of every session, having logged itself ACTIVE and spawned a worker
//
// The real one is the terrain streamer's own centre. sub_780860 stores its
// argument's three floats to 0x00CD7778, 0x00CD777C and 0x00CD7780, and the
// per-frame world update at sub_7831A0 - identifiable by the thirty-entry frame
// time ring it maintains at flt_CD76B0 first - calls it every frame. Every
// consumer of that value in the client reads the same pair: sub_7B5950 measures
// each terrain tile's distance from it to decide what to load, and derives the
// chunk bounds at 0x00CD77C8 through 0x00CD77E4 from it, which are the same
// values >> 4 that give an ADT tile index.
//
// That makes it better than a player position for every use here. It is what
// the client itself decides to stream around, it is a camera position rather
// than a character position, and it is written on the same frame boundary the
// rest of this DLL hooks.
//
// It is not always valid. Before a map is entered it holds whatever it last
// held, and on a fresh process that is zero - which is a real place on the map,
// so it cannot be distinguished by value. The check below is the world flag the
// streamer itself tests, plus a range test, and the counters let a caller say
// "not measured" instead of printing a zero.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "world_position.h"

namespace WowWorld {

namespace {

// sub_780860 writes these three, in this order, from its one argument.
const float* const kCentre = (const float*)0x00CD7778;

// The chunk bounds sub_7B5950 derives from the centre. They are set together
// with it and stay at their initial value until a world exists, which is what
// makes them usable as a "is there a world" test that a coordinate of zero
// cannot fake.
const int* const kChunkMinX = (const int*)0x00CD77D8;
const int* const kChunkMinY = (const int*)0x00CD77DC;
const int* const kChunkMaxX = (const int*)0x00CD77E0;
const int* const kChunkMaxY = (const int*)0x00CD77E4;

// A map is 64 tiles of 533.33333 yards, centred on the origin, so nothing on it
// is further than about 17067 yards from the middle in either axis.
constexpr float kMapHalfSpan = 17100.0f;

unsigned long g_asked = 0;
unsigned long g_seen  = 0;

}  // namespace

bool StreamCentre(float out[3]) {
    ++g_asked;
    __try {
        int minX = *kChunkMinX, minY = *kChunkMinY;
        int maxX = *kChunkMaxX, maxY = *kChunkMaxY;
        // 64 tiles of 16 chunks. An empty or inverted window means the streamer
        // has not run for a world yet.
        if (maxX < minX || maxY < minY) return false;
        if (minX < 0 || minY < 0 || maxX >= 1024 || maxY >= 1024) return false;

        float x = kCentre[0], y = kCentre[1], z = kCentre[2];
        if (!(x > -kMapHalfSpan && x < kMapHalfSpan)) return false;
        if (!(y > -kMapHalfSpan && y < kMapHalfSpan)) return false;
        if (!(z > -kMapHalfSpan && z < kMapHalfSpan)) return false;

        out[0] = x; out[1] = y; out[2] = z;
        ++g_seen;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void GetReadStats(unsigned long& asked, unsigned long& seen) {
    asked = g_asked;
    seen  = g_seen;
}

}  // namespace WowWorld
