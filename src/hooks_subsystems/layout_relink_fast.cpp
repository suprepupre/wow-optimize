// ============================================================================
// Module: layout_relink_fast
//
// sub_489710, the UI layout dependency relink, is the largest single consumer of
// main-thread time in real gameplay: 590 samples, 9.06% of executing time, in a
// 28-minute ElvUI session. First place, more than double the next entry. It
// scales with the number of UI frames, so addon-heavy setups pay most.
//
// What it does, from its own disassembly:
//
//     v3 = dword_AC1020;                     // head of the GLOBAL layout list
//     while (v3 && !(v3 & 1)) {
//         // 3 iterations x 3 anchors = nine dereferences per node
//         if (a && !(*(a+12) & 0x800) && *(a+8) == this) v2 = v3;
//         ...
//         v3 = *(dword_AC1018 + v3 + 4);     // next
//     }
//
// It walks the entire list looking for a frame anchored to `this`. The expensive
// case is not finding one, because not finding one means having walked
// everything and dereferenced nine pointers per node on the way.
//
// The client already maintains the index that search reconstructs.
// sub_489C30 - RTTI in the cluster gives it as CLayoutFrame::FRAMENODE -
// registers "X anchors to me" in a list whose head is at `me + 0x38`, encoded
// empty as null or with the low bit set. Its two callers are SetPoint
// (sub_48A260) and sub_48A3E0; the de-registrar sub_489D70 has three, in
// SetPoint, sub_48A200 and the frame destructor sub_48B130. Nothing sets an
// anchor without registering it.
//
// Therefore `this+0x38` empty implies the scan cannot find a match, and that is
// exactly the case that costs the most.
//
// ---------------------------------------------------------------------------
// This is the second attempt. The first one crashed the game on login and is
// worth writing down.
//
// It made the original take its own not-found path by setting dword_AC1020 to 0
// for the duration of the call and restoring it afterwards, reasoning that
// sub_489710 contains no call instructions so nothing could observe the global
// inside that window. Nothing reads it, true. But off_AC101C at 0xAC101C and
// dword_AC1020 at 0xAC1020 are adjacent dwords forming ONE link pair - the root
// node of the list - and the not-found path *writes* to the second of them:
//
//     489827  mov esi, offset off_AC101C
//     48982c  mov edx, [esi]          ; edx = off_AC101C
//     489836  mov [edx+4], ecx        ; <-- when edx is the root, this IS AC1020
//
// So the restore clobbered the client's own write and the layout list lost a
// link. EIP 0x00489873, `mov [ebx], esi` with EBX = 0, on the next relink.
//
// I had checked that nothing reads the global. I had not checked that something
// writes it.
//
// This version writes to no client global. It reads one word to decide, and
// when it decides yes it performs the same pointer surgery the client would
// have performed, transcribed instruction by instruction from the tail below.
// ---------------------------------------------------------------------------
//
// And it does not believe itself. For the first calls of every session it takes
// no shortcut at all: it makes its prediction, calls the original, and then
// checks what the original actually did. The not-found tail ends with
// `off_AC101C = result`, so afterwards off_AC101C == result iff the not-found
// path ran, which is a one-word test. Only after a run of agreements does the
// fast path switch on, and one in every 1024 calls stays in shadow mode
// afterwards so a late divergence still gets caught.
//
// ---------------------------------------------------------------------------
// The check is deliberately one-sided, and the first version of it was not.
//
// Only one of the two ways the prediction can miss is dangerous:
//
//   predicted not-found, client found one   -> we would have run the not-found
//                                              tail on a frame that needed the
//                                              other one. Wrong. Retire.
//   predicted found, client found nothing   -> we defer to the original on a
//                                              non-empty +0x38 (see the
//                                              `if (!predictNotFound)` guard
//                                              below), so the client's own
//                                              routine ran and the result is
//                                              correct. We merely paid for a
//                                              scan we could have skipped.
//
// The original check was `actualNotFound != predictNotFound`, which retired on
// both. A tester's log (nobus, v3.18.2) shows the cost: the module disabled
// itself three seconds into the session on the *second* kind, having taken zero
// shortcuts, and the client's 9%-of-profile scan ran unaided for the rest of the
// session. A divergence that cannot produce a wrong answer must not be able to
// switch the module off. It is counted instead, because a high count means the
// dependants list holds entries the scan rejects and there is more win available
// than we are taking.
// ---------------------------------------------------------------------------
// ============================================================================

#include <windows.h>
#include <cstdint>
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "layout_relink_fast.h"

extern "C" void Log(const char* fmt, ...);

namespace LayoutRelinkFast {

namespace {

constexpr uintptr_t kRelink        = 0x00489710;
constexpr uintptr_t kNodeOffsetVar = 0x00AC1018;  // member offset of the link pair
constexpr uintptr_t kListRoot      = 0x00AC101C;  // off_AC101C; AC1020 is its [1]
constexpr unsigned  kDependentsOff = 0x38;        // "who anchors to me" list head
constexpr unsigned  kStateByteOff  = 0x40;        // set to 6 by both tails

// How many calls to verify before trusting the prediction, and how often to
// keep checking afterwards.
constexpr long kLearnCalls   = 20000;
constexpr long kResampleMask = 1023;   // one in 1024

typedef uint32_t* (__fastcall* Relink_fn)(void* self, void* edx);
Relink_fn orig_Relink = nullptr;

volatile LONG g_calls        = 0;
volatile LONG g_agreements   = 0;
volatile LONG g_fastTaken    = 0;
volatile LONG g_deferred     = 0;
volatile LONG g_disagreed    = 0;
volatile LONG g_pessimistic  = 0;   // predicted found, client found nothing
// Every entry into the hook. g_calls below counts only those that get past the
// client's own early-out and reach the scan - the ones that cost anything - and
// it stops entirely once the module retires. This one never stops, so a log can
// say how often the function actually runs.
unsigned long g_invocations  = 0;
// Reached the hook while it was still live and stopped at the client's own
// early-out. Kept apart from the invocation count so that "retired early, so
// most invocations were never examined" cannot be misread as "most invocations
// take the early-out".
unsigned long g_earlyOut     = 0;
volatile LONG g_armed        = 0;   // 1 once the fast path is trusted
volatile LONG g_dead         = 0;   // 1 after a disagreement

inline uint32_t Rd(uintptr_t p)          { return *(volatile uint32_t*)p; }
inline void     Wr(uintptr_t p, uint32_t v) { *(volatile uint32_t*)p = v; }

// Empty is encoded two ways throughout this cluster: null, or a tagged sentinel
// with the low bit set.
inline bool IsEmptyLink(uint32_t v) { return v == 0 || (v & 1) != 0; }

// The not-found tail of sub_489710, transcribed from 0x004897CE to 0x0048983D.
// `result` is eax, `self` is ecx. There are no calls in it.
void RunNotFoundTail(uint32_t* result, uintptr_t self) {
    // 4897ce  mov esi,[eax] / test esi,esi / jz link
    uint32_t v14 = result[0];
    if (v14 != 0) {
        // 4897d4  mov ebx,[eax+4]
        uint32_t v15 = result[1];
        uint32_t* v16;
        if ((v15 & 1) == 0 && v15 != 0) {
            // 4897e5  mov edx,eax / sub edx,[esi+4] / add ebx,edx
            v16 = (uint32_t*)((uintptr_t)result + v15 - Rd((uintptr_t)v14 + 4));
        } else {
            // 4897e0  and ebx,0FFFFFFFEh
            v16 = (uint32_t*)(uintptr_t)(v15 & 0xFFFFFFFEu);
        }
        // 4897ec  mov [ebx],esi
        *v16 = v14;
        // 4897ee  mov edx,[eax] / mov esi,[eax+4] / mov [edx+4],esi
        //         (both re-read, exactly as the original does)
        uint32_t edx = result[0];
        uint32_t esi = result[1];
        Wr((uintptr_t)edx + 4, esi);
        // 4897f6 / 4897fc
        result[0] = 0;
        result[1] = 0;
    }

    // 489827  mov esi, offset off_AC101C
    // 48982c  mov edx,[esi]      ; edx = off_AC101C
    uint32_t v17 = Rd(kListRoot);
    // 48982e  mov [eax],edx
    result[0] = v17;
    // 489830  mov edi,[edx+4] / mov [eax+4],edi
    result[1] = Rd((uintptr_t)v17 + 4);
    // 489836  mov [edx+4],ecx    ; when edx is the root this writes AC1020
    Wr((uintptr_t)v17 + 4, (uint32_t)self);
    // 48983a  mov [esi],eax
    Wr(kListRoot, (uint32_t)(uintptr_t)result);
    // 48983d  mov byte ptr [ecx+40h], 6
    *(volatile uint8_t*)(self + kStateByteOff) = 6;
}

void Retire(const char* why) {
    if (InterlockedExchange(&g_dead, 1) != 0) return;
    Log("[LayoutRelink] Disabled for this session: %s. The client's own routine "
        "runs from here on; nothing is left half-applied.", why);
}

uint32_t* __fastcall Hooked_Relink(void* self, void* edx) {
    (void)edx;
    // Counted before anything can return, including after this module has
    // retired, because every other counter here stops the moment it does.
    //
    // A session log read "5 calls" and it was taken - by me - as the call rate
    // of the hottest function in the client's profile, which made no sense and
    // led to the conclusion that the shortcut could never arm. The module had
    // retired three seconds in; from then on the first line returned without
    // counting, and the function went on being called for the rest of the
    // session with nothing recording it. The number was not a rate, it was
    // where the counting stopped.
    //
    // Plain increment, not interlocked: this is the client's layout relink and
    // it runs on the main thread, and a lock-prefixed read-modify-write on a
    // function that owns nine percent of executing time costs more than the
    // diagnostic is worth.
    g_invocations++;
    if (g_dead || !self) return orig_Relink(self, edx);

    uintptr_t This = (uintptr_t)self;
    uint32_t* result;
    bool predictNotFound;

    __try {
        result = (uint32_t*)(This + Rd(kNodeOffsetVar));
        // The whole body of the original is inside `if (!result[1])`. When that
        // is false it does nothing at all, so there is nothing to be clever
        // about and the original is the cheapest correct answer.
        if (result[1] != 0) { g_earlyOut++; return orig_Relink(self, edx); }
        predictNotFound = IsEmptyLink(Rd(This + kDependentsOff));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return orig_Relink(self, edx);
    }

    LONG n = InterlockedIncrement(&g_calls);
    bool verifying = (g_armed == 0) || ((n & kResampleMask) == 0);

    if (verifying) {
        uint32_t rootBefore = 0;
        __try { rootBefore = Rd(kListRoot); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return orig_Relink(self, edx); }

        uint32_t* r = orig_Relink(self, edx);

        // The not-found tail ends with off_AC101C = result. Nothing else in this
        // function writes that word, so this distinguishes the two paths.
        bool actualNotFound = false;
        __try {
            uint32_t rootAfter = Rd(kListRoot);
            actualNotFound = (rootAfter == (uint32_t)(uintptr_t)result)
                          && (rootAfter != rootBefore);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Retire("the list root became unreadable during verification");
            return r;
        }

        // The unsafe direction: we would have run the not-found tail on a frame
        // the client found a match for. This is the only one that invalidates
        // the optimisation.
        if (predictNotFound && !actualNotFound) {
            InterlockedIncrement(&g_disagreed);
            Log("[LayoutRelink] Prediction was wrong: frame 0x%08X had nothing at "
                "+0x38 but the client took the found path. An empty dependants "
                "list does not imply the scan finds nothing, so this optimisation "
                "is not valid.", (unsigned)This);
            Retire("a prediction would have produced the wrong result");
            return r;
        }

        // The safe direction: a non-empty +0x38 where the client still found
        // nothing. We defer on non-empty, so the original ran and the answer is
        // correct - this is a skipped shortcut, not an error. Log the first one
        // so the asymmetry is visible in a session log, then just count them.
        if (!predictNotFound && actualNotFound) {
            if (InterlockedIncrement(&g_pessimistic) == 1) {
                Log("[LayoutRelink] Frame 0x%08X had something at +0x38 but the "
                    "client found nothing. Correct either way - we defer on "
                    "non-empty - so this is a missed shortcut, not a divergence. "
                    "Counting the rest.", (unsigned)This);
            }
            return r;
        }

        LONG ok = InterlockedIncrement(&g_agreements);
        if (g_armed == 0 && ok >= kLearnCalls) {
            InterlockedExchange(&g_armed, 1);
            Log("[LayoutRelink] %ld calls verified, no disagreement. Taking the "
                "shortcut from here; one call in %d stays checked.",
                (long)ok, (int)(kResampleMask + 1));
        }
        return r;
    }

    if (!predictNotFound) {
        InterlockedIncrement(&g_deferred);
        return orig_Relink(self, edx);
    }

    __try {
        RunNotFoundTail(result, This);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Retire("the transcribed tail faulted");
        return orig_Relink(self, edx);
    }
    InterlockedIncrement(&g_fastTaken);
    return result;
}

} // namespace

bool Init() {
    if (!Config::g_settings.OptLayoutRelinkFast) return true;

    // The prologue is `test ecx, ecx` / `jz short`, not a frame setup - this
    // function takes `this` in ecx and has no stack frame at all. Checking for
    // the usual 55 8B EC would have rejected the right address.
    unsigned char* p = (unsigned char*)kRelink;
    if (p[0] != 0x85 || p[1] != 0xC9) {
        Log("[LayoutRelink] Expected `test ecx,ecx` at 0x%08X and found %02X %02X "
            "- not installing", (unsigned)kRelink, p[0], p[1]);
        return false;
    }

    if (WineSafe_CreateHook((void*)kRelink, (void*)Hooked_Relink,
                            (void**)&orig_Relink) != MH_OK) {
        Log("[LayoutRelink] hook NOT installed at 0x%08X", (unsigned)kRelink);
        return false;
    }
    if (WO_EnableHook((void*)kRelink) != MH_OK) {
        Log("[LayoutRelink] hook created but could not be enabled");
        return false;
    }

    Log("[LayoutRelink] ACTIVE on sub_489710, the largest single entry in the "
        "main-thread profile (9.06%%). Verifying against the client for the first "
        "%ld calls before it changes anything.", (long)kLearnCalls);
    return true;
}

void LogStats() {
    if (!Config::g_settings.OptLayoutRelinkFast) return;
    if (g_calls == 0) return;
    Log("[LayoutRelink] %lu invocations, %ld of them reached the scan: %ld took "
        "the shortcut, %ld deferred (a dependant existed), %ld verified against "
        "the client, %ld disagreed%s",
        g_invocations, (long)g_calls, (long)g_fastTaken, (long)g_deferred,
        (long)g_agreements, (long)g_disagreed,
        g_dead ? " - DISABLED" : "");
    // The gap between the two is the client's own early-out, which this module
    // deliberately leaves alone. If almost every invocation stops there, the
    // nine percent measured in the profile is not where this module is looking
    // and the whole approach needs rechecking.
    unsigned long examined = g_earlyOut + (unsigned long)g_calls;
    if (examined > 0) {
        Log("[LayoutRelink] of %lu invocations seen while live, %.1f%% stopped at the "
            "client's own early-out before any scan - those cost nothing and are not "
            "this module's target%s",
            examined, 100.0 * (double)g_earlyOut / (double)examined,
            g_dead ? "; the remaining invocations came after this module retired"
                   : "");
    }
    if (g_pessimistic > 0) {
        Log("[LayoutRelink] %ld of the deferred calls had a non-empty +0x38 but "
            "the client found nothing anyway - shortcuts we could have taken and "
            "did not. A large share here means the dependants list holds entries "
            "the scan rejects, and there is more win available than we take.",
            (long)g_pessimistic);
    }
}

} // namespace LayoutRelinkFast
