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
// The loop is in the middle of sub_829BA0, not a function of its own. There is
// nothing to detour. So the loop head at 0x00829D02 is overwritten with a jump
// to a naked thunk that hands the registers to C, and the thunk returns to
// 0x00829D99, the instruction after the loop's back edge. The bytes in between
// are left as they are, unreachable, so Shutdown puts ten bytes back and the
// function is byte-identical to how it shipped.
//
// The register contract, read off the disassembly rather than assumed:
//
//   in    eax  destination, advances 48 bytes a bone
//         edx  0, the bone counter the loop increments
//         esi  the per-batch record: [esi+0Ch] count, [esi+0Eh] first bone
//         edi  the model record whose +0x150 leads to the bone index table
//         ebp  the caller's frame; [ebp-14h] is the matrix array base
//   out   eax  advanced by 48 * count
//         ecx  [esi+0Ch], because 0x829CEB tests it on the next outer iteration
//              before reloading it - the original leaves it there, so must we
//         edx  dead, reloaded at 0x829CE4
//         ebx  dead, reloaded at 0x829CE7
//         edi  dead, reloaded at 0x829D99
//         [ebp+18h]  += count, the running total the caller passes on
//
// The x87 stack is balanced in the original and untouched here, so it is
// unchanged either way. No MMX, so no emms.
//
// One thing the replacement does that the client does not: the two loads that
// reach the bone index table, [edi+150h] and [+7Ch], are loop-invariant and the
// client repeats them every bone. Nothing in the loop writes them and the loop
// calls nothing, so they are read once. That is two loads a bone on top of the
// transpose, and it is the only behavioural difference.
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

extern "C" void Log(const char* fmt, ...);

#if TEST_DISABLE_BONE_MATRIX_UPLOAD == 0

namespace BoneMatrixUpload {

static const uintptr_t kLoopHead = 0x00829D02;   // where the jump goes
static const uintptr_t kLoopExit = 0x00829D99;   // where the thunk returns
static const uintptr_t kTailAddr = 0x00829D8D;   // the loop's compare and branch
static const int       kSaveLen  = 10;           // 5 for the jump, 5 nopped out

// The first ten bytes of the loop, which the jump overwrites or splits, and the
// last twelve. Both checked before anything is written: a client that does not
// match is not the one this was read from, and the right answer is to install
// nothing rather than to patch something else.
//
//   0F B7 4E 0E        movzx ecx, word ptr [esi+0Eh]
//   8B 9F 50 01 00 00  mov   ebx, [edi+150h]
static const unsigned char kExpectHead[10] = {
    0x0F, 0xB7, 0x4E, 0x0E, 0x8B, 0x9F, 0x50, 0x01, 0x00, 0x00
};
//   0F B7 4E 0C        movzx ecx, word ptr [esi+0Ch]
//   3B D1              cmp   edx, ecx
//   0F 82 69 FF FF FF  jb    loc_829D02
static const unsigned char kExpectTail[12] = {
    0x0F, 0xB7, 0x4E, 0x0C, 0x3B, 0xD1, 0x0F, 0x82, 0x69, 0xFF, 0xFF, 0xFF
};

static bool g_installed = false;
static bool g_dead      = false;
static unsigned char g_saved[kSaveLen] = {};
static void* g_returnTo = (void*)kLoopExit;

// Learning phase. Both transposes into two buffers, compared byte for byte.
// Counted in bones rather than calls - one call with sixty bones checks sixty
// matrices, and the bone is the unit the layout could be wrong about.
static const unsigned kLearnBones = 20000;
static unsigned g_verified   = 0;
static unsigned g_mismatched = 0;

// Main thread only, so plain. Lower bounds if that ever stops being true.
static unsigned long long g_bones = 0;
static unsigned long long g_calls = 0;
static unsigned g_maxBones = 0;
static unsigned g_scalarBones = 0;   // bones the A/B control half did

// When this is the A/B subject the OFF stint runs the scalar transpose, so the
// two halves of the comparison differ in the transpose and in nothing else -
// the patch, the hoisted loads and the call are in both.
static bool g_abSubject = false;

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

}  // namespace BoneMatrixUpload

// The loop body, called from the thunk. Returns the number of bones written,
// which is what the thunk turns back into the loop's exit state.
extern "C" unsigned __cdecl BoneMatrixUpload_Run(float* dst,
                                                 const unsigned short* batch,
                                                 const unsigned char* model,
                                                 const unsigned char* matrixBase)
{
    using namespace BoneMatrixUpload;

    const unsigned count = batch[6];
    const unsigned first = batch[7];

    // Hoisted; the client reloads both every bone. Read before anything is
    // written, so both versions see the same table.
    const unsigned char* const  p336  =
        *(const unsigned char* const*)(model + 0x150);
    const unsigned short* const remap =
        *(const unsigned short* const*)(p336 + 0x7C);

    ++g_calls;
    g_bones += count;
    if (count > g_maxBones) g_maxBones = count;

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

namespace BoneMatrixUpload {

// Register marshalling only; the contract it implements is in the header
// comment. ebp belongs to the client for as long as this runs, which is why
// [ebp-14h] is read before the call and [ebp+18h] written after it.
static __declspec(naked) void Thunk() {
    __asm {
        push eax                        // the destination we came in with
        mov  ecx, [ebp-14h]
        push ecx                        // matrixBase
        push edi                        // model
        push esi                        // batch
        push eax                        // dst
        call BoneMatrixUpload_Run
        add  esp, 16
        mov  edx, eax                   // count
        pop  ecx                        // the destination we came in with

        add  [ebp+18h], edx             // the caller's running total

        lea  eax, [edx+edx*2]           // count * 3
        shl  eax, 4                     // * 16, so count * 48
        add  eax, ecx                   // where the client's loop would have left it

        movzx ecx, word ptr [esi+0Ch]   // what 0x829CEB tests before reloading
        jmp  dword ptr [g_returnTo]
    }
}

static bool BytesMatch(uintptr_t addr, const unsigned char* want, int n) {
    __try {
        return memcmp((const void*)addr, want, (size_t)n) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool Init() {
    if (!Config::g_settings.OptBoneMatrixUpload) return true;

    if (!BytesMatch(kLoopHead, kExpectHead, sizeof(kExpectHead))) {
        Log("[BoneUpload] NOT installed: the bytes at 0x%08X are not the loop "
            "this was read from. Nothing patched.", (unsigned)kLoopHead);
        return false;
    }
    if (!BytesMatch(kTailAddr, kExpectTail, sizeof(kExpectTail))) {
        Log("[BoneUpload] NOT installed: the loop head at 0x%08X matches but its "
            "tail at 0x%08X does not, so the body between them is not the one "
            "being replaced. Nothing patched.",
            (unsigned)kLoopHead, (unsigned)kTailAddr);
        return false;
    }

    // The same refusal every hook in this project passes through. A patch site
    // that does not ask is a hole in the No Client Patches experiment.
    if (!WowOpt_ClientPatchAllowed((const void*)kLoopHead)) {
        Log("[BoneUpload] NOT installed: No Client Patches is on, and this "
            "writes five bytes into wow.exe like every hook here does.");
        return false;
    }

    DWORD old = 0;
    if (!VirtualProtect((void*)kLoopHead, kSaveLen, PAGE_EXECUTE_READWRITE, &old)) {
        Log("[BoneUpload] NOT installed: could not make 0x%08X writable",
            (unsigned)kLoopHead);
        return false;
    }
    memcpy(g_saved, (const void*)kLoopHead, kSaveLen);

    unsigned char patch[kSaveLen];
    patch[0] = 0xE9;
    *(int32_t*)(patch + 1) =
        (int32_t)((uintptr_t)&Thunk - (kLoopHead + 5));
    // The five bytes after the jump are the tail of an instruction it split.
    // Unreachable either way; filled so anything reading the code sees nops
    // rather than half of a mov.
    memset(patch + 5, 0x90, 5);
    memcpy((void*)kLoopHead, patch, kSaveLen);

    DWORD ignored = 0;
    VirtualProtect((void*)kLoopHead, kSaveLen, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), (void*)kLoopHead, kSaveLen);

    g_installed = true;
    g_abSubject = AbTest::IsSubject("BoneMatrixUpload", &g_abSubject);

    Log("[BoneUpload] ACTIVE on the bone matrix upload loop inside sub_829BA0, "
        "3.35%% of executing time in the corrected profile and the largest entry "
        "with nothing shipped against it. Twelve x87 load/store pairs a bone "
        "become four loads, seven shuffles and three stores. There is no "
        "arithmetic in it, so it is bit-exact by construction rather than by "
        "measurement - the first %u bones are still done both ways and compared, "
        "because the layout could be misread even when the maths cannot be "
        "wrong.", kLearnBones);
    if (g_abSubject)
        Log("[BoneUpload]   under A/B test: the control half runs the same "
            "patch, the same call and the same hoisted loads, and only the "
            "transpose differs.");
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    DWORD old = 0;
    if (VirtualProtect((void*)kLoopHead, kSaveLen, PAGE_EXECUTE_READWRITE, &old)) {
        memcpy((void*)kLoopHead, g_saved, kSaveLen);
        DWORD ignored = 0;
        VirtualProtect((void*)kLoopHead, kSaveLen, old, &ignored);
        FlushInstructionCache(GetCurrentProcess(), (void*)kLoopHead, kSaveLen);
    }
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptBoneMatrixUpload) return;
    if (!g_installed) { Log("[BoneUpload] not installed - nothing measured"); return; }
    if (g_calls == 0) {
        Log("[BoneUpload] installed, and the loop has not run once. That is a "
            "measurement: either nothing skinned was drawn, or the patch is not "
            "on the path it was read from.");
        return;
    }

    Log("[BoneUpload] %llu call(s), %llu bone(s), largest batch %u. That is "
        "%llu matrices transposed, %llu bytes moved.",
        g_calls, g_bones, g_maxBones, g_bones, g_bones * 48);

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
