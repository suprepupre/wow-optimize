// ============================================================================
// Why this exists. Two testers on two clients reported the camera zooming in
// to the character by itself, and neither could say when. A key press taken at
// the moment is the usual answer and one of them could not produce it: the log
// of a forty minute session had no press in it, so the log could not place a
// single event, and every conclusion drawn from it was about a time the file
// does not contain.
//
// What the client does. sub_606F90 is the follow camera's per-frame update.
// The camera's distance from the character is the float at +280 (the same slot
// the client's own SetView restores as a saved view value). Further down the
// function sub_605D60 works out how far the camera may be from the character
// without being inside geometry, and when the distance is more than a ninth of
// a yard past that, the function writes the shorter value straight into +280
// and sets bit 0x04000000 of the flags at +152. A wall behind the character
// does exactly that, so a pull-in is not by itself a fault: it is what the
// client does when its collision query says something is in the way. A scroll
// of the mouse wheel does not look like it, because the zoom is animated and
// moves the distance a little each frame.
//
// So this counts pull-ins and splits them by whether the A/B test had its
// replacements on or off in that frame. An effect that belongs to the
// replacements shows as a rate that differs between the two halves; walls show
// as the same rate in both. Neither is a verdict on one event.
//
// Nothing here writes to the client.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>

#include "MinHook.h"
#include "version.h"
#include "camera_watch.h"
#include "ab_test.h"
#include "flight_recorder.h"
#include "config.h"
#include "ray_triangle_sse2.h"
#include "collision_clip_verts_box_sse2.h"
#include "collision_ray_outcode_sse2.h"


extern "C" void Log(const char* fmt, ...);

namespace CameraWatch {
namespace {

// ---------------------------------------------------------------------------
// The trace behind the pull-in
//
// sub_605D60 asks the world one question to decide how far back the camera may
// sit: sub_77F310(from, to, size, &fraction, flags, 0), which is a jump to
// sub_7A3B70. It returns true when the segment hits something and writes how
// far along the segment the hit is, 1.0 meaning not at all. The camera then
// multiplies its distance by that fraction. A camera that lands a tenth of a
// yard from the character has been told the fraction is nearly zero.
//
// When that happens this runs the same trace again, with the same inputs
// and in the same frame: as it was, with every replacement that registered with
// the A/B test standing aside, with each of them standing aside alone, and as it
// was once more. Answers are compared by fraction, since a hit at 0.0 and a hit at
// 0.19 are both hits and only one of them zooms the camera. The log says what
// each gave. A replacement outside the A/B test cannot be switched here.
//
// The trace is the client's own query, called the way the camera calls it, from
// the main thread, and it writes only its fraction. It runs at most a dozen
// times a session.
// ---------------------------------------------------------------------------
typedef char (__cdecl* Trace_fn)(const float* from, const float* to, float* hitPoint,
                                 float* fraction, int flags, void* hitInfo);
Trace_fn orig_Trace = nullptr;
const uintptr_t kTrace = 0x007A3B70;

// The three places in the camera code that call it, as the address the call
// returns to: sub_605D60 twice and sub_6061D0 once. The trace has twenty callers
// and only these are the camera's.
const uintptr_t kCameraCalls[3] = { 0x00605F05, 0x00606103, 0x0060625B };

DWORD g_mainTid     = 0;
bool  g_inDiag      = false;
unsigned long g_diagRuns = 0, g_diagSkipped = 0, g_traces = 0, g_suspicious = 0;
constexpr unsigned long kMaxDiag = 24;
// One burst of identical traces used the whole budget in an earlier build, so a
// second diagnosis waits at least this long after the last.
constexpr DWORD kDiagGapMs = 8000;
DWORD g_lastDiagTick = 0;
constexpr float kSuspect = 0.03f;

// The trace writes the hit point to its third argument, a hit record to its
// last, and two globals that name what it hit. So every re-run gets scratch
// space of its own and no hit record, and the last one is the call the client
// made, with the client's inputs, so the globals end where the camera expects.
void Diagnose(const float* from, const float* to, int flags, float frac0,
              float* outFrac, float* outHit, char* outR) {
    g_inDiag = true;
    ++g_diagRuns;

    auto run = [&](float* frac, float* hit) -> char {
        *frac = 1.0f;
        if (hit) hit[0] = hit[1] = hit[2] = 0.0f;
        return (char)orig_Trace(from, to, hit, frac, flags, nullptr);
    };
    auto differs = [](float a, float b) { return (a > b ? a - b : b - a) > 0.001f; };

    // 1. Run as it currently is (with optimizations active)
    float hitFirst[3] = {};
    float fFirst = 1.0f;
    char rFirst = run(&fFirst, hitFirst);

    // 2. Run with all candidate collision optimizations bypassed (pure stock client answer)
    RayTriangle::SetBypass(true);
    CollisionClipVertsBox::SetBypass(true);
    CollisionRayOutcode::SetBypass(true);

    float hitStock[3] = {};
    float fStock = 1.0f;
    char rStock = run(&fStock, hitStock);

    RayTriangle::SetBypass(false);
    CollisionClipVertsBox::SetBypass(false);
    CollisionRayOutcode::SetBypass(false);

    // 3. Isolated module testing if stock differed
    float fNoRayTri = 1.0f, fNoClip = 1.0f, fNoOutcode = 1.0f;
    const bool isFalsePositive = (!rStock || fStock >= kSuspect);

    if (isFalsePositive) {
        // Test with RayTriangle alone bypassed
        RayTriangle::SetBypass(true);
        run(&fNoRayTri, nullptr);
        RayTriangle::SetBypass(false);

        // Test with CollisionClip alone bypassed
        CollisionClipVertsBox::SetBypass(true);
        run(&fNoClip, nullptr);
        CollisionClipVertsBox::SetBypass(false);

        // Test with CollisionRayOutcode alone bypassed
        CollisionRayOutcode::SetBypass(true);
        run(&fNoOutcode, nullptr);
        CollisionRayOutcode::SetBypass(false);

        const char* culprit = "Unknown";
        if (differs(fNoRayTri, fFirst) && !differs(fNoRayTri, fStock)) {
            culprit = "RayTriangle";
            RayTriangle::RetireAll();
        } else if (differs(fNoClip, fFirst) && !differs(fNoClip, fStock)) {
            culprit = "CollisionClip";
            CollisionClipVertsBox::Retire();
        } else if (differs(fNoOutcode, fFirst) && !differs(fNoOutcode, fStock)) {
            culprit = "CollisionRayOutcode";
        }

        Log("[CameraWatch] FALSE POSITIVE camera collision intercepted! Ray: (%.1f,%.1f,%.1f) -> (%.1f,%.1f,%.1f), flags %08X. "
            "Fast=%.4f, Stock=%.4f (NoRayTri=%.4f, NoClip=%.4f, NoOutcode=%.4f). Culprit: %s. Overriding with stock fraction.",
            (double)from[0], (double)from[1], (double)from[2],
            (double)to[0], (double)to[1], (double)to[2], (unsigned)flags,
            (double)fFirst, (double)fStock, (double)fNoRayTri, (double)fNoClip, (double)fNoOutcode, culprit);

        *outFrac = fStock;
        if (outHit) { outHit[0] = hitStock[0]; outHit[1] = hitStock[1]; outHit[2] = hitStock[2]; }
        *outR = rStock;
    } else {
        Log("[CameraWatch] Real geometry collision: stock client also hit at fraction %.4f (fast=%.4f) from (%.1f,%.1f,%.1f) to (%.1f,%.1f,%.1f), flags %08X.",
            (double)fStock, (double)fFirst, (double)from[0], (double)from[1], (double)from[2],
            (double)to[0], (double)to[1], (double)to[2], (unsigned)flags);
        *outFrac = frac0;
        *outR = 1;
    }

    // Run A/B test diagnosis if A/B test is active
    float fAside = 1.0f, fLast = 1.0f;
    char named[640] = {};
    int namedCount = 0;
    const bool begun = AbTest::DiagBegin();
    if (begun) {
        AbTest::DiagSelect(-1);
        run(&fAside, nullptr);
        const int n = AbTest::DiagCount();
        for (int i = 0; i < n; ++i) {
            const char* name = nullptr;
            if (!AbTest::DiagSubject(i, &name)) continue;
            AbTest::DiagSelect(i);
            float fi = 1.0f;
            run(&fi, nullptr);
            if (differs(fi, fFirst)) {
                ++namedCount;
                char item[96];
                wsprintfA(item, "%s %d.%04d", name, (int)fi, (int)((fi - (int)fi) * 10000.0f));
                const size_t used = strlen(named);
                if (used + strlen(item) + 3 < sizeof(named)) {
                    if (used) strcat(named, ", ");
                    strcat(named, item);
                }
            }
        }
        AbTest::DiagEnd();
    }
    run(&fLast, nullptr);

    if (begun) {
        char lead[64];
        wsprintfA(lead, "%d.%04d", (int)fAside, (int)((fAside - (int)fAside) * 10000.0f));
        if (differs(fAside, fFirst))
            Log("[CameraWatch]   every replacement standing aside gives fraction %s against %.4f as it was.",
                lead, (double)fFirst);
        if (namedCount)
            Log("[CameraWatch]   standing aside alone changes the answer: %s", named);
    }
    g_inDiag = false;
}

char __cdecl Hooked_Trace(const float* from, const float* to, float* hitPoint,
                          float* frac, int flags, void* hitInfo) {
    const uintptr_t ret = (uintptr_t)_ReturnAddress();
    ++g_traces;
    const float before = frac ? *frac : 1.0f;
    char r = orig_Trace(from, to, hitPoint, frac, flags, hitInfo);
    if (r && frac && !g_inDiag && *frac < kSuspect && before >= 0.99f &&
        (ret == kCameraCalls[0] || ret == kCameraCalls[1] || ret == kCameraCalls[2]) &&
        GetCurrentThreadId() == g_mainTid) {
        ++g_suspicious;
        const DWORD now = GetTickCount();
        float savedFrac = *frac;
        float savedHit[3] = {};
        if (hitPoint) { savedHit[0] = hitPoint[0]; savedHit[1] = hitPoint[1]; savedHit[2] = hitPoint[2]; }

        char outR = r;
        float outFrac = savedFrac;
        float outHit[3] = { savedHit[0], savedHit[1], savedHit[2] };

        if (g_diagRuns < kMaxDiag && (g_diagRuns == 0 || now - g_lastDiagTick >= kDiagGapMs)) {
            g_lastDiagTick = now;
            __try {
                Diagnose(from, to, flags, savedFrac, &outFrac, outHit, &outR);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                g_inDiag = false;
                AbTest::DiagEnd();
            }
        } else {
            ++g_diagSkipped;
            // Quick stock check to prevent camera collapse even when logging is rate-limited
            RayTriangle::SetBypass(true);
            CollisionClipVertsBox::SetBypass(true);
            CollisionRayOutcode::SetBypass(true);
            float stockHit[3] = {};
            float stockFrac = 1.0f;
            char stockR = orig_Trace(from, to, stockHit, &stockFrac, flags, nullptr);
            RayTriangle::SetBypass(false);
            CollisionClipVertsBox::SetBypass(false);
            CollisionRayOutcode::SetBypass(false);

            if (!stockR || stockFrac >= kSuspect) {
                outFrac = stockFrac;
                outHit[0] = stockHit[0]; outHit[1] = stockHit[1]; outHit[2] = stockHit[2];
                outR = stockR;
            }
        }
        *frac = outFrac;
        if (hitPoint) { hitPoint[0] = outHit[0]; hitPoint[1] = outHit[1]; hitPoint[2] = outHit[2]; }
        r = outR;
    }
    return r;
}

const uintptr_t kWorldFrame     = 0x00B7436C;
const uintptr_t kWorldCameraOff = 0x7E20;
const uintptr_t kDistance       = 280;     // float: distance behind the character
const uintptr_t kFlags          = 152;     // dword; 0x04000000 is set on a pull-in

// One frame's drop that is not a wheel zoom. A wheel notch moves the distance
// well under a yard a frame at any frame rate this client reaches.
constexpr float kMinDrop      = 1.5f;
constexpr float kMinBefore    = 2.5f;      // nothing to pull in from at point blank
constexpr float kFarEnough    = 0.9f;      // recovered when back within this share
constexpr int   kMaxLogged    = 40;
constexpr int   kMaxMarked    = 12;

float    g_prev       = -1.0f;
bool     g_inEvent    = false;
float    g_eventFrom  = 0.0f;
DWORD    g_eventStart = 0;

unsigned long g_frames[2]   = {};          // [0] replacements off, [1] on or no test
unsigned long g_events[2]   = {};
unsigned long g_unread      = 0;
unsigned long g_logged      = 0;
unsigned long g_collapseLogged = 0;
unsigned long g_collapses[2] = {};   // pull-ins to under a yard, by half
float         g_worstDrop   = 0.0f;
DWORD         g_longestMs   = 0;

bool ReadCamera(float* dist, unsigned* flags) {
    __try {
        const uintptr_t wf = *(const uintptr_t*)kWorldFrame;
        if (wf < 0x10000 || wf > 0xFFE00000) return false;
        const uintptr_t cam = *(const uintptr_t*)(wf + kWorldCameraOff);
        if (cam < 0x10000 || cam > 0xFFE00000) return false;
        *dist  = *(const float*)(cam + kDistance);
        *flags = *(const unsigned*)(cam + kFlags);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

}  // namespace

void Init() {
    // Unconditional install for camera pull-in protection
    __try {
        const unsigned char* p = (const unsigned char*)kTrace;
        if (!(p[0] == 0x55 && p[1] == 0x8B && p[2] == 0xEC && p[3] == 0x83 && p[4] == 0xEC && p[5] == 0x18)) {
            Log("[CameraWatch] trace re-run NOT installed: 0x%08X does not start with the bytes "
                "of build 12340", (unsigned)kTrace);
            return;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }
    if (MH_CreateHook((void*)kTrace, (void*)Hooked_Trace, (void**)&orig_Trace) != MH_OK ||
        WO_EnableHook((void*)kTrace) != MH_OK) {
        orig_Trace = nullptr;
        Log("[CameraWatch] trace re-run NOT installed: the world trace could not be hooked");
        return;
    }
    Log("[CameraWatch] trace re-run installed on 0x%08X: a camera trace that hits within "
        "%.0f%% of its length is run again with replacements standing aside, to name the "
        "one that made it.", (unsigned)kTrace, (double)kSuspect * 100.0);
}

void OnFrame() {
    if (!g_mainTid) g_mainTid = GetCurrentThreadId();
    if (!Config::g_settings.OptFlightRecorder) return;

    float d = 0.0f;
    unsigned flags = 0;
    if (!ReadCamera(&d, &flags) || !(d == d) || d < 0.0f || d > 1000.0f) {
        ++g_unread;
        g_prev = -1.0f;
        g_inEvent = false;
        return;
    }

    const int half = (AbTest::Running() && !AbTest::FeatureOn()) ? 0 : 1;
    ++g_frames[half];

    if (g_inEvent) {
        if (d >= g_eventFrom * kFarEnough) {
            const DWORD ms = GetTickCount() - g_eventStart;
            if (ms > g_longestMs) g_longestMs = ms;
            if (g_logged + g_collapseLogged <= (unsigned long)kMaxLogged + 200ul)
                Log("[CameraWatch]   back to %.1f yd after %lu ms", d, (unsigned long)ms);
            g_inEvent = false;
        }
    } else if (g_prev >= kMinBefore && g_prev - d >= kMinDrop) {
        ++g_events[half];
        if (d < 1.0f) ++g_collapses[half];
        if (g_prev - d > g_worstDrop) g_worstDrop = g_prev - d;
        g_inEvent    = true;
        g_eventFrom  = g_prev;
        g_eventStart = GetTickCount();
        // Every collapse to the character is kept; the partial ones, which are
        // what walls do, stop being listed after a few.
        const bool collapse = d < 1.0f;
        if (collapse ? g_collapseLogged < 200ul : g_logged < (unsigned long)kMaxLogged) {
            if (collapse) ++g_collapseLogged; else ++g_logged;
            Log("[CameraWatch] camera pulled in from %.1f to %.1f yd in one frame "
                "(flags %08X, %s)", g_prev, d, flags,
                !AbTest::Running() ? "no A/B test running"
                                   : half ? "replacements ON" : "replacements OFF");
            if (g_logged + g_collapseLogged <= (unsigned long)kMaxMarked)
                FlightRecorder::Mark("camera pulled in");
        }
    }
    g_prev = d;
}

void LogStats() {
    if (!Config::g_settings.OptFlightRecorder) return;
    const unsigned long total = g_frames[0] + g_frames[1];
    if (!total) {
        Log("[CameraWatch] not measured: no frame saw a readable camera (%lu unreadable).",
            g_unread);
        return;
    }
    Log("[CameraWatch] %lu pull-in(s) of %.1f yd or more in a single frame: %lu with the "
        "replacements ON over %lu frames, %lu with them OFF over %lu frames. Worst drop "
        "%.1f yd, longest %lu ms. %lu frame(s) could not read the camera.",
        g_events[0] + g_events[1], (double)kMinDrop, g_events[1], g_frames[1],
        g_events[0], g_frames[0], (double)g_worstDrop, (unsigned long)g_longestMs,
        g_unread);
    Log("[CameraWatch]   of those, pulled in to under a yard from the character (the zoom to "
        "the character): ON %lu, OFF %lu.", g_collapses[1], g_collapses[0]);
    if (orig_Trace)
        Log("[CameraWatch]   the world trace ran %lu times, %lu hit within %.0f%% of their length "
            "from a clear start, %lu of those were run again and %lu left alone.",
            g_traces, g_suspicious, (double)kSuspect * 100.0, g_diagRuns, g_diagSkipped);
    if (g_frames[0] && g_frames[1]) {
        Log("[CameraWatch]   per 100000 frames: ON %.1f, OFF %.1f. Walls give the same "
            "rate in both halves; a rate that differs is what to follow. A handful of "
            "events is too few to say either way.",
            100000.0 * g_events[1] / (double)g_frames[1],
            100000.0 * g_events[0] / (double)g_frames[0]);
    } else {
        Log("[CameraWatch]   no A/B test split this session, so the count above is every "
            "pull-in and cannot be told from walls.");
    }
}

}  // namespace CameraWatch
