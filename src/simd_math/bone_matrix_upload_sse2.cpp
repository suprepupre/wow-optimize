// ============================================================================
// Module: bone_matrix_upload_sse2.cpp
//
// The largest unclaimed entry in the corrected main-thread profile. The sample
// address is 0x00829D29, which func_profile puts inside sub_829BA0 at 3.35% of
// executing time - ahead of every M2 animation function already replaced here
// and behind only d3d9.dll itself and a third-party library in the tester's
// process.
//
// It is not a slow algorithm. It is twelve x87 load/store pairs and eleven
// address increments, per bone, per draw call, moving floats:
//
//     fld  [ecx]      fstp [eax-14h]      ; dst[0]  = src[0]
//     fld  [ecx+10h]  fstp [eax-14h]      ; dst[1]  = src[4]
//     fld  [ecx+20h]  fstp [eax-18h]      ; dst[2]  = src[8]
//     ...                                   dst[11] = src[14]
//
// Read out, that is the transpose of a 4x4 matrix with the fourth column
// dropped: its first three columns written as three consecutive vec4s, the 3x4
// bone matrix a skinning shader wants. Twenty-four memory operations to move
// forty-eight bytes.
//
// ---------------------------------------------------------------------------
// There are two of them
//
// A scan for functions holding ten or more fld/fstp pairs and no floating point
// arithmetic at all found twenty-one in the client, and two are this same loop:
// one in sub_829BA0 and one in sub_8203B0, which the sampling profiler already
// carried in its symbol table as "Hot_8203B0" because an earlier profile had put
// it near the top. Same transpose, same destination (sub_683560's buffer plus
// 496), same sub_683580(0, 31, 3*count) after it. They differ only in where the
// batch record, the bone remap table and the matrix array are reached from.
//
// Both are patched. The transpose, the learning phase and the counters are
// shared; each site has its own thunk because each derives its pointers from a
// different register.
//
// The scan is worth keeping: ten fld and ten fstp with no fadd, fmul, fcom or
// fild anywhere is a function that moves floats without computing anything, and
// that is exactly the shape that vectorises with no precision question to
// answer. Of the twenty-one, matrix_copy_sse2.cpp already covers the three with
// the most callers.
//
// ---------------------------------------------------------------------------
// Why this one needs no precision harness
//
// Every SIMD replacement in this project has had to prove it matches the
// client's x87 arithmetic to the last bit, and one was rejected on that
// evidence. This one has no arithmetic. It loads floats and stores the same
// floats somewhere else; a shuffle moves a 32-bit lane without looking inside
// it. Bit-exactness here is not a measurement, it is the absence of an
// operation.
//
// What can still be wrong is the reading of the layout - which offset holds
// what, how the bone index is remapped, where the destination advances to. That
// is what the learning phase checks: for the first bones the transpose is done
// both ways into two buffers and compared byte for byte, and one disagreement
// hands back the client's answer for every bone after it.
//
// ---------------------------------------------------------------------------
// Why this is a patch and not a hook
//
// Neither loop is a function, so there is nothing to detour. Five bytes at the
// loop head become a jump to a naked thunk that hands the registers to C and
// returns past the loop's back edge. The bytes in between are left as they are,
// unreachable, so Shutdown puts them back and both functions are byte-identical
// to how they shipped.
//
// The register contracts, read off the disassembly rather than assumed.
//
// Site A, sub_829BA0, 0x00829D02 -> 0x00829D99:
//
//   in    eax  destination, advances 48 bytes a bone
//         edx  0, the bone counter the loop increments
//         esi  the batch record: [esi+0Ch] count, [esi+0Eh] first bone
//         edi  the model record whose +0x150 leads to the bone remap table
//         ebp  the caller's frame; [ebp-14h] is the matrix array base
//   out   eax  advanced by 48 * count
//         ecx  [esi+0Ch], because 0x829CEB tests it on the next outer iteration
//              before reloading it - the original leaves it there, so must we
//         edx  dead, reloaded at 0x829CE4
//         ebx  dead, reloaded at 0x829CE7
//         edi  dead, reloaded at 0x829D99
//         [ebp+18h]  += count, the running total the caller passes on
//
// Site B, sub_8203B0, 0x00820480 -> 0x00820522, and simpler: everything past the
// exit reloads eax, ecx and edx before reading them, and the first mention of
// edi there is a write. Nothing the loop computes is live except what it wrote.
//
//   in    eax  destination, base + 1F0h
//         edx  0
//         esi  the object: [esi+90h] batch record, [esi+48h] model,
//              [esi+60h] the record whose +98h is the matrix array base
//   out   nothing. esi, ebx and ebp preserved; everything else dead.
//
// The x87 stack is balanced in both originals and untouched here, so it is
// unchanged either way. No MMX, so no emms.
//
// Loads hoisted that the client repeats every bone: the two or three that reach
// the bone remap table and the matrix array, and the count it re-reads for the
// loop condition. Nothing in either loop writes any of them and neither loop
// calls anything, so reading them once is the same program. That is the only
// behavioural difference between the two versions.
//
// These are raw writes, not MinHook detours, so the duplicate-hook detector does
// not see them. A detour on either function's entry would not collide - those
// land on the first bytes and these are 354 and 208 bytes in - but a second tool
// patching the same loop would, silently. The byte check catches that only if
// the other tool got there first.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <emmintrin.h>

#include "bone_matrix_upload_sse2.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "session_verdict.h"
#include "flight_recorder.h"

extern "C" void Log(const char* fmt, ...);

#if TEST_DISABLE_BONE_MATRIX_UPLOAD == 0

namespace BoneMatrixUpload {

enum { kSiteA = 0, kSiteB = 1, kSites = 2 };

// The bytes each jump overwrites or splits, and the bytes at each loop's tail.
// Both are checked before anything is written: a client that does not match is
// not the one this was read from, and the answer is to patch nothing rather than
// to patch something else.
//
// A head: 0F B7 4E 0E        movzx ecx, word ptr [esi+0Eh]
//         8B 9F 50 01 00 00  mov   ebx, [edi+150h]
// A tail: 0F B7 4E 0C        movzx ecx, word ptr [esi+0Ch]
//         3B D1              cmp   edx, ecx
//         0F 82 69 FF FF FF  jb    loc_829D02
static const unsigned char kHeadA[10] = {
    0x0F, 0xB7, 0x4E, 0x0E, 0x8B, 0x9F, 0x50, 0x01, 0x00, 0x00
};
static const unsigned char kTailA[12] = {
    0x0F, 0xB7, 0x4E, 0x0C, 0x3B, 0xD1, 0x0F, 0x82, 0x69, 0xFF, 0xFF, 0xFF
};
// B head: 8B 8E 90 00 00 00  mov   ecx, [esi+90h]
// B tail: 8B 8E 90 00 00 00  mov   ecx, [esi+90h]
//         0F B7 49 0C        movzx ecx, word ptr [ecx+0Ch]
//         3B D1              cmp   edx, ecx
//         0F 82 5E FF FF FF  jb    loc_820480
static const unsigned char kHeadB[6] = { 0x8B, 0x8E, 0x90, 0x00, 0x00, 0x00 };
static const unsigned char kTailB[18] = {
    0x8B, 0x8E, 0x90, 0x00, 0x00, 0x00, 0x0F, 0xB7, 0x49, 0x0C,
    0x3B, 0xD1, 0x0F, 0x82, 0x5E, 0xFF, 0xFF, 0xFF
};

struct Site {
    const char*          name;
    uintptr_t            head;      // where the jump goes
    uintptr_t            tailAddr;  // the loop's compare and branch
    const unsigned char* headWant;
    int                  headLen;   // bytes saved and restored, at least 5
    const unsigned char* tailWant;
    int                  tailLen;
    void*                thunk;
    void*                returnTo;
    bool                 patched;
};

static void ThunkA();
static void ThunkB();

static Site g_site[kSites] = {
    { "sub_829BA0", 0x00829D02, 0x00829D8D, kHeadA, 10, kTailA, 12,
      nullptr, (void*)0x00829D99, false },
    { "sub_8203B0", 0x00820480, 0x00820510, kHeadB,  6, kTailB, 18,
      nullptr, (void*)0x00820522, false },
};
static unsigned char g_saved[kSites][10] = {};

static bool g_dead = false;

// Learning phase. Both transposes into two buffers, compared byte for byte.
// Counted in bones rather than calls - one call with sixty bones checks sixty
// matrices, and the bone is the unit the layout could be wrong about. Shared by
// the two sites, because the transpose they perform is the same one.
static const unsigned kLearnBones = 20000;
static unsigned g_verified   = 0;
static unsigned g_mismatched = 0;

// Main thread only, so plain. Lower bounds if that ever stops being true.
static unsigned long long g_bones[kSites] = {};
static unsigned long long g_calls[kSites] = {};
static unsigned g_maxBones[kSites] = {};
static unsigned g_scalarBones = 0;   // bones the A/B control half did

// When this is the A/B subject the OFF stint runs the scalar transpose, so the
// two halves of the comparison differ in the transpose and in nothing else - the
// patches, the calls and the hoisted loads are in both.
static bool g_abSubject = false;

// A flight recorder column. Skinning load is the one thing a player describing
// a stutter in a raid is usually standing in the middle of, and a per-frame bone
// count is what says whether the frame they marked had five hundred of them or
// five thousand. A ten-second average cannot show that.
static int g_frSlot = -1;

static inline void TransposeScalar(const float* s, float* d) {
    d[0]  = s[0];  d[1]  = s[4];  d[2]  = s[8];   d[3]  = s[12];
    d[4]  = s[1];  d[5]  = s[5];  d[6]  = s[9];   d[7]  = s[13];
    d[8]  = s[2];  d[9]  = s[6];  d[10] = s[10];  d[11] = s[14];
}

// Four loads, four unpacks, three shuffles, three stores. Every output lane is
// an input lane, moved: no lane is combined with another and none is rounded.
static inline void TransposeSse(const float* s, float* d) {
    __m128 r0 = _mm_loadu_ps(s);
    __m128 r1 = _mm_loadu_ps(s + 4);
    __m128 r2 = _mm_loadu_ps(s + 8);
    __m128 r3 = _mm_loadu_ps(s + 12);

    __m128 t0 = _mm_unpacklo_ps(r0, r1);   // s0  s4  s1  s5
    __m128 t1 = _mm_unpacklo_ps(r2, r3);   // s8  s12 s9  s13
    __m128 t2 = _mm_unpackhi_ps(r0, r1);   // s2  s6  s3  s7
    __m128 t3 = _mm_unpackhi_ps(r2, r3);   // s10 s14 s11 s15

    _mm_storeu_ps(d,     _mm_movelh_ps(t0, t1));   // s0 s4 s8  s12
    _mm_storeu_ps(d + 4, _mm_movehl_ps(t1, t0));   // s1 s5 s9  s13
    _mm_storeu_ps(d + 8, _mm_movelh_ps(t2, t3));   // s2 s6 s10 s14
}

// The loop both sites share, once their pointers are resolved.
static unsigned RunCore(float* dst, const unsigned short* batch,
                        const unsigned short* remap,
                        const unsigned char* matrixBase, int site)
{
    const unsigned count = batch[6];
    const unsigned first = batch[7];

    ++g_calls[site];
    g_bones[site] += count;
    FlightRecorder::Bump(g_frSlot, count);
    if (count > g_maxBones[site]) g_maxBones[site] = count;

    const bool control = g_abSubject && AbTest::StandAside();
    if (control) g_scalarBones += count;

    for (unsigned i = 0; i < count; ++i) {
        const float* s =
            (const float*)(matrixBase + ((size_t)remap[first + i] << 6));
        float* d = dst + 12 * i;

        if (control || g_dead) { TransposeScalar(s, d); continue; }

        if (g_verified < kLearnBones) {
            float a[12], b[12];
            TransposeScalar(s, a);
            TransposeSse(s, b);
            if (memcmp(a, b, sizeof(a)) != 0) {
                ++g_mismatched;
                if (g_mismatched == 1)
                    Verdict::Add(Verdict::Bad,
                                 "BoneMatrixUpload read the bone matrix layout "
                                 "wrongly and retired itself for this session");
                // Hand back the client's answer. Unpatching from inside the
                // patched code is not safe, so the flag is set and every bone
                // after this one takes the scalar path; the report says so.
                memcpy(d, a, sizeof(a));
                g_dead = true;
                continue;
            }
            ++g_verified;
            memcpy(d, b, sizeof(b));
            continue;
        }

        TransposeSse(s, d);
    }
    return count;
}

}  // namespace BoneMatrixUpload

// Site A: the model record needs one dereference more than site B's.
extern "C" unsigned __cdecl BoneMatrixUpload_RunA(float* dst,
                                                  const unsigned short* batch,
                                                  const unsigned char* model,
                                                  const unsigned char* matrixBase)
{
    const unsigned char* const p336 =
        *(const unsigned char* const*)(model + 0x150);
    const unsigned short* const remap =
        *(const unsigned short* const*)(p336 + 0x7C);
    return BoneMatrixUpload::RunCore(dst, batch, remap, matrixBase,
                                     BoneMatrixUpload::kSiteA);
}

// Site B: the thunk already followed [esi+48h], so this is the record the remap
// table hangs off directly.
extern "C" unsigned __cdecl BoneMatrixUpload_RunB(float* dst,
                                                  const unsigned short* batch,
                                                  const unsigned char* model,
                                                  const unsigned char* matrixBase)
{
    const unsigned short* const remap =
        *(const unsigned short* const*)(model + 0x7C);
    return BoneMatrixUpload::RunCore(dst, batch, remap, matrixBase,
                                     BoneMatrixUpload::kSiteB);
}

namespace BoneMatrixUpload {

static void* g_returnA = (void*)0x00829D99;
static void* g_returnB = (void*)0x00820522;

// Register marshalling only; the contracts are in the header comment. ebp
// belongs to the client for as long as this runs, which is why [ebp-14h] is read
// before the call and [ebp+18h] written after it.
static __declspec(naked) void ThunkA() {
    __asm {
        push eax                        // the destination we came in with
        mov  ecx, [ebp-14h]
        push ecx                        // matrixBase
        push edi                        // model
        push esi                        // batch
        push eax                        // dst
        call BoneMatrixUpload_RunA
        add  esp, 16
        mov  edx, eax                   // count
        pop  ecx                        // the destination we came in with

        add  [ebp+18h], edx             // the caller's running total

        lea  eax, [edx+edx*2]           // count * 3
        shl  eax, 4                     // * 16, so count * 48
        add  eax, ecx                   // where the client's loop would have left it

        movzx ecx, word ptr [esi+0Ch]   // what 0x829CEB tests before reloading
        jmp  dword ptr [g_returnA]
    }
}

// Nothing this loop computes is live after its exit, so there is nothing to hand
// back: the writes are the whole effect.
static __declspec(naked) void ThunkB() {
    __asm {
        mov  ecx, [esi+60h]
        mov  ecx, [ecx+98h]
        push ecx                        // matrixBase
        mov  ecx, [esi+48h]
        push ecx                        // model, remap table at +7Ch
        mov  ecx, [esi+90h]
        push ecx                        // batch
        push eax                        // dst
        call BoneMatrixUpload_RunB
        add  esp, 16
        jmp  dword ptr [g_returnB]
    }
}

static bool BytesMatch(uintptr_t addr, const unsigned char* want, int n) {
    __try {
        return memcmp((const void*)addr, want, (size_t)n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool PatchSite(int i) {
    Site& s = g_site[i];

    if (!BytesMatch(s.head, s.headWant, s.headLen)) {
        Log("[BoneUpload] %s NOT patched: the bytes at 0x%08X are not the loop "
            "this was read from.", s.name, (unsigned)s.head);
        return false;
    }
    if (!BytesMatch(s.tailAddr, s.tailWant, s.tailLen)) {
        Log("[BoneUpload] %s NOT patched: the head at 0x%08X matches but the "
            "tail at 0x%08X does not, so the body between them is not the one "
            "being replaced.", s.name, (unsigned)s.head, (unsigned)s.tailAddr);
        return false;
    }
    // The same refusal every hook in this project passes through. A patch site
    // that does not ask is a hole in the No Client Patches experiment.
    if (!WowOpt_ClientPatchAllowed((const void*)s.head)) {
        Log("[BoneUpload] %s NOT patched: No Client Patches is on, and this "
            "writes five bytes into wow.exe like every hook here does.", s.name);
        return false;
    }

    DWORD old = 0;
    if (!VirtualProtect((void*)s.head, s.headLen, PAGE_EXECUTE_READWRITE, &old)) {
        Log("[BoneUpload] %s NOT patched: could not make 0x%08X writable",
            s.name, (unsigned)s.head);
        return false;
    }
    memcpy(g_saved[i], (const void*)s.head, (size_t)s.headLen);

    unsigned char patch[10];
    patch[0] = 0xE9;
    *(int32_t*)(patch + 1) = (int32_t)((uintptr_t)s.thunk - (s.head + 5));
    // Whatever follows the jump inside the saved run is the tail of an
    // instruction it split. Unreachable either way; filled so anything reading
    // the code sees nops rather than half of a mov.
    if (s.headLen > 5) memset(patch + 5, 0x90, (size_t)(s.headLen - 5));
    memcpy((void*)s.head, patch, (size_t)s.headLen);

    DWORD ignored = 0;
    VirtualProtect((void*)s.head, s.headLen, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), (void*)s.head, (SIZE_T)s.headLen);

    s.patched = true;
    return true;
}

bool Init() {
    if (!Config::g_settings.OptBoneMatrixUpload) return true;

    g_site[kSiteA].thunk = (void*)&ThunkA;
    g_site[kSiteB].thunk = (void*)&ThunkB;

    int done = 0;
    for (int i = 0; i < kSites; ++i)
        if (PatchSite(i)) ++done;

    if (done == 0) {
        Log("[BoneUpload] NOT active: neither loop matched the bytes it was read "
            "from, so nothing was written.");
        return false;
    }

    g_abSubject = AbTest::IsSubject("BoneMatrixUpload", &g_abSubject);
    g_frSlot    = FlightRecorder::RegisterSlot("bones");

    Log("[BoneUpload] ACTIVE on %d of %d bone matrix upload loops. The one in "
        "sub_829BA0 is 3.35%% of executing time in the corrected profile and the "
        "largest entry with nothing shipped against it; the one in sub_8203B0 is "
        "the same transpose in a second draw path, which the profiler already "
        "carried as a hot symbol. Twelve x87 load/store pairs a bone become four "
        "loads, seven shuffles and three stores. There is no arithmetic in it, "
        "so it is bit-exact by construction rather than by measurement - the "
        "first %u bones are still done both ways and compared, because the "
        "layout can be misread even where the maths cannot be wrong.",
        done, (int)kSites, kLearnBones);
    if (done != kSites)
        Log("[BoneUpload]   the site that did not match is named above and the "
            "one that did is running. Half of this is not the same as none.");
    if (g_abSubject)
        Log("[BoneUpload]   under A/B test: the control half runs the same "
            "patches, the same calls and the same hoisted loads, and only the "
            "transpose differs.");
    return true;
}

void Shutdown() {
    for (int i = 0; i < kSites; ++i) {
        Site& s = g_site[i];
        if (!s.patched) continue;
        DWORD old = 0;
        if (VirtualProtect((void*)s.head, s.headLen, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy((void*)s.head, g_saved[i], (size_t)s.headLen);
            DWORD ignored = 0;
            VirtualProtect((void*)s.head, s.headLen, old, &ignored);
            FlushInstructionCache(GetCurrentProcess(), (void*)s.head,
                                  (SIZE_T)s.headLen);
        }
        s.patched = false;
    }
}

void LogStats() {
    if (!Config::g_settings.OptBoneMatrixUpload) return;

    int patched = 0;
    for (int i = 0; i < kSites; ++i) if (g_site[i].patched) ++patched;
    if (patched == 0) { Log("[BoneUpload] not installed - nothing measured"); return; }

    unsigned long long calls = 0, bones = 0;
    for (int i = 0; i < kSites; ++i) { calls += g_calls[i]; bones += g_bones[i]; }

    if (calls == 0) {
        Log("[BoneUpload] %d loop(s) patched, and neither has run. That is a "
            "measurement: either nothing skinned was drawn, or the patches are "
            "not on the path they were read from.", patched);
        Verdict::Add(Verdict::Warn,
                     "BoneMatrixUpload patched the client and neither loop ran - "
                     "five bytes of wow.exe were changed for nothing");
        return;
    }

    Log("[BoneUpload] %llu call(s), %llu bone(s), %llu bytes moved.",
        calls, bones, bones * 48);
    for (int i = 0; i < kSites; ++i) {
        if (!g_site[i].patched) {
            Log("[BoneUpload]   %s: not patched", g_site[i].name);
            continue;
        }
        Log("[BoneUpload]   %s: %llu call(s), %llu bone(s), largest batch %u%s",
            g_site[i].name, g_calls[i], g_bones[i], g_maxBones[i],
            g_calls[i] == 0 ? " - patched and never reached" : "");
    }

    if (g_mismatched) {
        Log("[BoneUpload]   DISABLED: %u bone(s) came out differently from the "
            "client's own order of stores. Since the replacement performs no "
            "arithmetic, a difference means the layout was misread, not that a "
            "result was rounded. Every bone since has taken the scalar path.",
            g_mismatched);
    } else if (g_verified < kLearnBones) {
        Log("[BoneUpload]   %u of %u bones verified against the scalar order so "
            "far; still checking every one.", g_verified, kLearnBones);
    } else {
        Log("[BoneUpload]   %u bones verified byte for byte against the scalar "
            "order, none differed, and the check is off.", kLearnBones);
    }

    if (g_abSubject)
        Log("[BoneUpload]   %u bone(s) went through the scalar control half of "
            "the A/B test.", g_scalarBones);
}

}  // namespace BoneMatrixUpload

#endif  // TEST_DISABLE_BONE_MATRIX_UPLOAD == 0
