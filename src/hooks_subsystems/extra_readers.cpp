// ============================================================================
// Module: extra_readers.cpp
//
// A client whose file layer is not in its multi-threaded mode reads every asynchronous request on one
// thread. sub_4BAA40 builds one queue and sub_4BA980 starts one CAsyncThread on it when the two mode
// bytes at 0xB38180/0xB38181 are clear (with them set it builds three queues and three threads). A
// world load is a stream of requests through that thread - file read, MPQ sector decompression (98.7%
// of the compressed bytes in a stock Data folder are zlib), then the completion callback on the main
// thread - so the reader is the throughput limit of any load whose requests are queued ahead.
//
// What this does: asks the client's own routine for one more CAsyncThread on the same queue. The
// worker loop (sub_4BA680) takes a request from the queue's lists under the queue's lock and marks it
// in progress before it reads, so two threads do not take the same request; the read itself runs
// outside the lock on that request's own file handle.
//
// Measured in the offline rig through the client's own world-load pump (tools/rig_async_reads_workers
// .patch), 2340 requests per pass, completions checked against checksums from synchronous reads:
//
//   reader threads   everything queued at once   8 dependent chains   (best of four passes)
//   1                256.8 ms                     557.0 ms
//   2                131.7 ms (1.95x)             477.4 ms
//   3                 99.9 ms (2.6x)              460.3 ms
//   4                 99.3 ms (2.6x)              428.6 ms
//
// no wrong checksum in any pass. With AsyncPollSpin on the chain column is 355, 239, 140, 134 ms, so
// the two compose. The main thread runs the completion callbacks (the rig's checksum is one), which is
// where the curve flattens.
//
// What is not shown: that the client never relies on completion order within a queue. The requests
// are served in list order by one thread today; with two, a small request queued after a large one
// can complete before it. Callers that queue dependent work do it from the completion callback (the
// chain scenario), which is unaffected, but a caller that queues A then B and assumes A is done when
// B is would be. The client's own three-queue mode already breaks any global order across queues,
// which is the only reason to expect that none does. That is a hypothesis; a tester log decides.
//
// Off by default (General/ExtraReaderThread), experimental. Declines under Wine/Rosetta, under No
// Client Patches, and when the file layer is already in its three-thread mode.
// ============================================================================
#include "extra_readers.h"
#include <windows.h>
#include <cstdint>
#include "config.h"
#include "MinHook.h"
#include "version.h"

extern "C" void Log(const char* fmt, ...);

namespace ExtraReaders {
namespace {

constexpr uintptr_t kStartThread = 0x004BA980;    // sub_4BA980(queue, name) -> CAsyncThread*
constexpr uintptr_t kQueueSlot   = 0x00B4A20C;    // dword_B4A20C[0]: the queue
constexpr uintptr_t kModeFlag    = 0x00B38180;    // the file layer's multi-threaded mode
constexpr uintptr_t kWorker      = 0x004BA680;

// push ebp / mov ebp,esp / push esi / push edi / push 8 / push 0FFFFFFFEh / push offset ".?AVCAsyncThread@@"
const unsigned char kStartOpening[10] = { 0x55, 0x8B, 0xEC, 0x56, 0x57, 0x6A, 0x08, 0x6A, 0xFE, 0x68 };
// push ebp / mov ebp,esp / sub esp,408h / mov eax,[ebp+8]
const unsigned char kWorkerOpening[12] = { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x08, 0x04, 0x00, 0x00, 0x8B, 0x45, 0x08 };

int g_state = 0;            // 0 waiting, 1 started, 2 declined
int g_waitedFrames = 0;
void* g_thread = nullptr;

typedef void* (__cdecl* StartThread_fn)(int queue, const char* name);

void Decline(const char* why) {
    g_state = 2;
    Log("[ExtraReaders] NOT started: %s", why);
}

}  // namespace

void OnFrame() {
    if (g_state != 0) return;
    if (!Config::g_settings.OptExtraReaderThread) { g_state = 2; return; }

    if (RunningUnderTranslation()) { Decline("it runs a client thread of its own and a translation layer has blocked on that before."); return; }
    if (WowOpt_NoClientPatches()) { Decline("No Client Patches is on."); return; }

    int queue = 0;
    unsigned char mode = 0;
    __try {
        queue = *(volatile int*)kQueueSlot;
        mode = *(volatile unsigned char*)kModeFlag;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Decline("the client's reader state could not be read.");
        return;
    }
    if (queue == 0) {
        // The reader is built early in the client's start; give it a few seconds of frames.
        if (++g_waitedFrames > 1200) Decline("the client's reader queue never appeared.");
        return;
    }
    if (mode != 0) { Decline("the file layer is already in its multi-threaded mode (three reader threads)."); return; }
    if (!WowOpt_ClientBytesAre(kStartThread, kStartOpening, sizeof(kStartOpening)) ||
        !WowOpt_ClientBytesAre(kWorker, kWorkerOpening, sizeof(kWorkerOpening))) {
        Decline("the reader's routines are not the ones of build 12340.");
        return;
    }

    g_thread = ((StartThread_fn)kStartThread)(queue, "AsyncRead2");
    if (!g_thread) { Decline("the client's thread routine returned nothing."); return; }
    g_state = 1;
    Log("[ExtraReaders] ACTIVE: a second reader thread (CAsyncThread %p) serves the client's asynchronous file queue. "
        "Requests are still taken one at a time under the queue's lock. Not run in a game; the Load took lines with the "
        "switch on and off are the measurement.", g_thread);
}

void LogStats() {
    if (!Config::g_settings.OptExtraReaderThread) return;
    if (g_state == 1) Log("[ExtraReaders] a second reader thread has been running since the reader appeared.");
    else if (g_state == 2) Log("[ExtraReaders] not running; the reason is logged where it was decided.");
    else Log("[ExtraReaders] waiting for the client's reader queue.");
}

}  // namespace ExtraReaders
