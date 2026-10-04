// ============================================================================
// The client's Lua interpreter, sub_857CA0, transcribed instruction by
// instruction from its disassembly, with the string-key table lookup inlined.
//
// What this is for, stated as what it removes. A global read (OP_GETGLOBAL), a
// table read (OP_GETTABLE) and a method fetch (OP_SELF) each reach their value
// through three nested calls, read off the client:
//
//     luaV_gettable  0x00857250   frame, four arguments, a loop for the
//                                 non-table case, then
//     luaH_get       0x0085C470   frame, two arguments, a dispatch on the key
//                                 type, then
//     luaH_getstr    0x0085C430   frame, two arguments, and the ten
//                                 instructions that are the actual work:
//                                 nodes at table+0x14, index
//                                 (2^table[0x0B] - 1) & string[0x0C], a walk of
//                                 the chain at node+0x20 comparing the key at
//                                 node+0x10.
//
// Three prologues and eight argument pushes to reach ten instructions. This runs
// those ten in place and calls the client only when the answer is not a plain
// hit - a miss, a nil value, a non-table, a key that is not a string.
//
// What it costs, so the trade is on the page: one trampoline and one prologue
// per entry to the interpreter, which is per Lua call frame rather than per
// opcode, and whatever difference there is between this switch and the client's
// own jump table on the other thirty-five opcodes, which run unchanged. The
// saving lands on three opcodes and the cost lands on all of them, so whether
// it is a gain at all is an open question. Nothing here answers it: that is
// what the A/B subject is for.
//
// What is NOT attempted: compiling anything. There is no JIT here, and the
// client's Lua is not stock Lua - the layout is shifted by four and every
// TValue carries a taint word - so a third-party VM cannot be dropped in.
// ---------------------------------------------------------------------------
// Taint, and why it decides the shape of this module
//
// Every value carries a taint word at +12, and three globals steer it:
// 0x00D4139C is the current taint of the context, 0x00D413A0 says the system is
// armed, 0x00D413A4 says the context is frozen. The disassembly settles a
// question two other modules in this tree disagree about: 0x00D4139C is the
// cell itself, not a pointer to it - `mov dword_D4139C, ecx` at 0x00857DBA and
// `mov eax, dword_D4139C` at 0x00857DC5.
//
// The rule the client applies on every value copy is: copy all sixteen bytes;
// if the source's taint is non-zero, and the system is armed, and the context
// is not frozen, the context takes that taint; if the source's taint is zero,
// the destination takes the context's taint instead. Getting this backwards
// would let a value read through a fast path arrive untainted where the client
// would have tainted it, which is how addon code reaches protected calls. That
// is a security bug, not a speed bug, and it is the reason the previous engine
// in this tree was switched off.
// ---------------------------------------------------------------------------
// The exit, and why it makes the rest safe
//
// Anything this does not implement exactly - an arithmetic metamethod, a
// comparison that is not two numbers, a debug hook, an unknown opcode - is
// handed back: the instruction pointer is written to L->savedpc pointing AT the
// current instruction and the client's own luaV_execute is called with the same
// nexeccalls. Its entry re-reads L->savedpc, re-derives the frozen flag from
// the closure's taint word exactly as it does on a normal call, and continues.
// Nothing is half-executed at an exit: each case bails before its first write.
//
// The one thing that must not be double-counted is the instruction hook. The
// client decrements L->hookcount per instruction when the mask at L+0x3A has
// bit 2 or 3 set, so this refuses to run at all while that mask is non-zero and
// hands the instruction back before touching the count.
// ---------------------------------------------------------------------------
// Verification
//
// The inlined lookup is checked against the client's own luaH_getstr, which is
// a pure function of the table and the string: the first kVerifyFirst hits and
// one in 1024 after that ask it for the node this found. A single disagreement
// retires the lookup for the session and every read goes back to the client.
// The rest of the transcription has no such shape - running an opcode twice
// changes the state - so it is a transcription and is documented as one: every
// case below cites the address it came from.
//
// Off by default and marked experimental. A/B subject "LuaVmFast".
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <intrin.h>

#include "lua_vm_fast.h"
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "ab_test.h"
#include "session_verdict.h"
#include "lua_optimize.h"

extern "C" void Log(const char* fmt, ...);
MH_STATUS WineSafe_CreateHook(void* target, void* detour, void** original);
MH_STATUS WO_EnableHook(void* target);

namespace LuaVmFast {

namespace {

typedef uint32_t Instruction;

// The client's TValue: eight bytes of value, the type tag, the taint word.
struct TV {
    uint32_t lo;
    uint32_t hi;
    int32_t  tt;
    uint32_t taint;
};

// lua_State, CallInfo, Closure, Proto, Table, TString field offsets, all read
// off sub_857CA0 and its callees rather than from stock Lua headers.
constexpr unsigned kL_status    = 0x0A;
constexpr unsigned kL_top       = 0x0C;
constexpr unsigned kL_base      = 0x10;
constexpr unsigned kL_G         = 0x14;
constexpr unsigned kL_ci        = 0x18;
constexpr unsigned kL_savedpc   = 0x1C;
constexpr unsigned kL_stackLast = 0x20;
constexpr unsigned kL_hookmask  = 0x3A;
constexpr unsigned kL_gt        = 0x48;
constexpr unsigned kL_openupval = 0x68;
constexpr unsigned kL_abort     = 0x78;

constexpr unsigned kCI_base      = 0x00;
constexpr unsigned kCI_func      = 0x04;
constexpr unsigned kCI_top       = 0x08;
constexpr unsigned kCI_savedpc   = 0x0C;
constexpr unsigned kCI_tailcalls = 0x14;
constexpr unsigned kCI_size      = 24;

constexpr unsigned kCl_isC    = 0x0A;   // the byte luaD_precall tests, 0x00856380
constexpr unsigned kCl_taint  = 0x04;
constexpr unsigned kCl_env    = 0x10;
constexpr unsigned kCl_p      = 0x18;
constexpr unsigned kCl_upvals = 0x1C;

constexpr unsigned kP_k         = 0x0C;
constexpr unsigned kP_protos    = 0x14;
constexpr unsigned kP_nups      = 0x4C;
constexpr unsigned kP_numparams = 0x4D;

constexpr unsigned kUV_v = 0x0C;

constexpr unsigned kT_flags     = 0x0A;
constexpr unsigned kT_lsizenode = 0x0B;
constexpr unsigned kT_node      = 0x14;
constexpr unsigned kT_sizearray = 0x20;

constexpr unsigned kTS_hash = 0x0C;
constexpr unsigned kTS_len  = 0x10;
constexpr unsigned kTS_data = 0x14;

constexpr unsigned kNode_size    = 40;
constexpr unsigned kNode_keyVal  = 0x10;
constexpr unsigned kNode_keyTt   = 0x18;
constexpr unsigned kNode_next    = 0x20;

constexpr unsigned kG_totalbytes = 0x44;
constexpr unsigned kG_threshold  = 0x40;

constexpr uintptr_t kTaintCell   = 0x00D4139C;
constexpr uintptr_t kTaintArmed  = 0x00D413A0;
constexpr uintptr_t kTaintFrozen = 0x00D413A4;
constexpr uintptr_t kTaintReport = 0x00D413B0;

constexpr uintptr_t kExecute = 0x00857CA0;

// Client entry points this calls, all __cdecl unless noted.
typedef int   (__cdecl* execute_fn)(void* L, int nexeccalls);
typedef void  (__cdecl* gettable_fn)(void* L, const TV* t, const TV* key, TV* val);
typedef void  (__cdecl* settable_fn)(void* L, const TV* t, const TV* key, const TV* val);
typedef void  (__cdecl* barrierf_fn)(void* L, void* o, void* v);
typedef void  (__cdecl* barrierback_fn)(void* L, void* t);
typedef int   (__cdecl* fb2int_fn)(int x);
typedef void* (__cdecl* newtable_fn)(void* L, int narray, int nhash);
typedef void  (__cdecl* step_fn)(void* L);
typedef int   (__cdecl* getn_fn)(void* t);
typedef void  (__cdecl* concat_fn)(void* L, int total, int last);
typedef int   (__cdecl* equalval_fn)(void* L, const TV* a, const TV* b);
typedef int   (__cdecl* lessthan_fn)(void* L, const TV* l, const TV* r);
typedef int   (__cdecl* precall_fn)(void* L, TV* func, int nresults);
typedef int   (__cdecl* poscall_fn)(void* L, TV* firstResult);
typedef void  (__cdecl* close_fn)(void* L, void* level);
typedef void  (__cdecl* call_fn)(void* L, TV* func, int nresults);
typedef void  (__cdecl* resizearray_fn)(void* L, void* t, int n);
typedef TV*   (__cdecl* setnum_fn)(void* L, void* t, int key);
typedef void* (__cdecl* newlclosure_fn)(void* L, int nelems, void* env);
typedef void* (__cdecl* findupval_fn)(void* L, TV* level);
typedef void  (__cdecl* growstack_fn)(void* L, int n);
typedef void* (__cdecl* getstr_fn)(void* t, void* key);
typedef void  (__cdecl* report_fn)(void* L, int kind, const char* name, uint32_t taint);

execute_fn     g_orig        = nullptr;
gettable_fn    g_gettable    = (gettable_fn)0x00857250;
settable_fn    g_settable    = (settable_fn)0x008573C0;
barrierf_fn    g_barrierf    = (barrierf_fn)0x0085BA50;
barrierback_fn g_barrierback = (barrierback_fn)0x0085BA90;
fb2int_fn      g_fb2int      = (fb2int_fn)0x0084D3D0;
newtable_fn    g_newtable    = (newtable_fn)0x0085C2E0;
step_fn        g_step        = (step_fn)0x0085B950;
getn_fn        g_getn        = (getn_fn)0x0085C690;
concat_fn      g_concat      = (concat_fn)0x00857900;
equalval_fn    g_equalval    = (equalval_fn)0x00857820;
lessthan_fn    g_lessthan    = (lessthan_fn)0x008576F0;
precall_fn     g_precall     = (precall_fn)0x00856370;
poscall_fn     g_poscall     = (poscall_fn)0x00856010;
close_fn       g_close       = (close_fn)0x0085CE70;
call_fn        g_call        = (call_fn)0x00856760;
resizearray_fn g_resizearray = (resizearray_fn)0x0085C960;
setnum_fn      g_setnum      = (setnum_fn)0x0085C590;
newlclosure_fn g_newlclosure = (newlclosure_fn)0x0085CC90;
findupval_fn   g_findupval   = (findupval_fn)0x0085CD80;
growstack_fn   g_growstack   = (growstack_fn)0x00855CD0;
getstr_fn      g_getstr      = (getstr_fn)0x0085C430;

constexpr uintptr_t kCIpow = 0x0088D0C0;
// The CRT floor the client's own OP_MOD calls, at 0x008583AB.
constexpr uintptr_t kFloor = 0x0088CE30;

bool g_installed = false;
bool g_dead = false;
bool g_abSubject = false;
bool g_lookupDead = false;

// Main thread only, so plain. Lower bounds if that ever stops being true.
unsigned long long g_calls = 0;
unsigned long long g_ops = 0;
unsigned long long g_bails = 0;
unsigned long long g_stood = 0;
unsigned long long g_fastGets = 0;
unsigned long long g_slowGets = 0;
unsigned long g_verified = 0;
unsigned long g_hitSeq = 0;
unsigned long g_bailOp[64] = {};

// Which opcode the loop was executing at a sample. The loop already counts every
// instruction in g_ops, so a sample costs one compare of that count's low word
// against a target, and the histogram is touched about once in 128 instructions.
// The gap to the next sample is jittered from the time stamp counter, 96 to 159
// instructions: a fixed gap would land on the same position of every tight loop
// whose body length divides it (a numeric for is three or four instructions), and
// the histogram would then report that position as the whole loop.
//
// Plain counters, main thread only. The sample path is rare enough that an atomic
// would be affordable, but nothing else reads these, so it would only add a lock
// prefix to no purpose.
constexpr unsigned kOpcodes = 38;                 // Lua 5.1, numbered as the client numbers them
constexpr unsigned kSampleGapMin = 96;
constexpr unsigned kSampleGapMask = 63;
unsigned long g_opSamples[64] = {};
unsigned long g_opSamplesTotal = 0;
unsigned g_opNextSample = kSampleGapMin;

// Which C functions the scripts call, sampled at CALL. Answers "what are the most
// called API functions" for anything that wants to fast-path them: without it
// the list is a guess. One CALL in about 64 is looked at, at a jittered gap for
// the same reason as above; a callee that is a C closure (isC at +10, the
// function at +24, both read off the client's own luaD_precall) is counted by
// its address in a small open-addressing table. Callees that are not functions
// (a __call metamethod) are counted as neither.
constexpr unsigned kCallGapMin = 48;
constexpr unsigned kCallGapMask = 31;
constexpr unsigned kCfnSlots = 256;
struct CfnSlot { const void* f; unsigned long n; };
CfnSlot g_cfn[kCfnSlots] = {};
unsigned long g_callSeen = 0;                 // every CALL, plain
unsigned g_callNext = kCallGapMin;
unsigned long g_callSamples = 0, g_callSampledC = 0, g_callSampledLua = 0, g_callSampledOther = 0;
unsigned long g_cfnLost = 0;                  // sampled C calls the table had no room for

const char* const kOpName[kOpcodes] = {
    "MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETGLOBAL", "GETTABLE", "SETGLOBAL",
    "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF", "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "UNM",
    "NOT", "LEN", "CONCAT", "JMP", "EQ", "LT", "LE", "TEST", "TESTSET", "CALL", "TAILCALL",
    "RETURN", "FORLOOP", "FORPREP", "TFORLOOP", "SETLIST", "CLOSE", "CLOSURE", "VARARG"
};

constexpr unsigned long kVerifyFirst = 65536;
constexpr unsigned long kResampleMask = 1023;

template <typename T> __forceinline T& F(void* p, unsigned off) {
    return *(T*)((uint8_t*)p + off);
}
template <typename T> __forceinline T Fc(const void* p, unsigned off) {
    return *(const T*)((const uint8_t*)p + off);
}

void NoteCallee(const TV* fn) {
    if (fn->tt != 6) { ++g_callSampledOther; return; }
    const void* cl = (const void*)(uintptr_t)fn->lo;
    if (!Fc<uint8_t>(cl, 10)) { ++g_callSampledLua; return; }
    ++g_callSampledC;
    const void* f = Fc<const void*>(cl, kCl_p);      // CClosure::f shares the offset with LClosure::p
    unsigned h = (unsigned)(((uintptr_t)f >> 4) ^ ((uintptr_t)f >> 12)) & (kCfnSlots - 1);
    for (unsigned probe = 0; probe < 8; ++probe, h = (h + 1) & (kCfnSlots - 1)) {
        if (g_cfn[h].f == f) { ++g_cfn[h].n; return; }
        if (!g_cfn[h].f) { g_cfn[h].f = f; g_cfn[h].n = 1; return; }
    }
    ++g_cfnLost;
}

__forceinline uint32_t Cell()   { return *(uint32_t*)kTaintCell; }
__forceinline uint32_t Armed()  { return *(uint32_t*)kTaintArmed; }
__forceinline uint32_t Frozen() { return *(uint32_t*)kTaintFrozen; }
__forceinline void SetCell(uint32_t v)   { *(uint32_t*)kTaintCell = v; }
__forceinline void SetFrozen(uint32_t v) { *(uint32_t*)kTaintFrozen = v; }

// The copy every value-moving opcode performs, from 0x00857D83..0x00857DCD.
__forceinline void CopyTaint(TV* dst, const TV* src) {
    dst->lo = src->lo;
    dst->hi = src->hi;
    dst->tt = src->tt;
    dst->taint = src->taint;
    const uint32_t t = src->taint;
    if (t) {
        if (Armed() && !Frozen()) SetCell(t);
    } else {
        dst->taint = Cell();
    }
}

// The same rule where the client applies only its first half: OP_SETUPVAL at
// 0x00857FC6 and OP_SETLIST at 0x00858D6E take the taint from the value but do
// not write the context's taint back when the value carries none.
__forceinline void TaintFromValue(uint32_t t) {
    if (t && Armed() && !Frozen()) SetCell(t);
}

__forceinline double NumOf(const TV* v) {
    double d;
    memcpy(&d, v, sizeof(d));
    return d;
}

// Arithmetic exactly as the client does it, on the x87 stack, so the result
// carries the same rounding at whatever precision control the client is in -
// including the subnormal range, where an SSE double and an x87 double at
// 53-bit precision do not have to agree.
__declspec(noinline) void XAdd(TV* ra, const TV* b, const TV* c) {
    __asm {
        mov eax, b
        mov ecx, c
        mov edx, ra
        fld qword ptr [eax]
        fld qword ptr [ecx]
        faddp st(1), st
        fstp qword ptr [edx]
    }
}
__declspec(noinline) void XSub(TV* ra, const TV* b, const TV* c) {
    __asm {
        mov eax, b
        mov ecx, c
        mov edx, ra
        fld qword ptr [eax]
        fld qword ptr [ecx]
        fsubp st(1), st
        fstp qword ptr [edx]
    }
}
__declspec(noinline) void XMul(TV* ra, const TV* b, const TV* c) {
    __asm {
        mov eax, b
        mov ecx, c
        mov edx, ra
        fld qword ptr [eax]
        fld qword ptr [ecx]
        fmulp st(1), st
        fstp qword ptr [edx]
    }
}
__declspec(noinline) void XDiv(TV* ra, const TV* b, const TV* c) {
    __asm {
        mov eax, b
        mov ecx, c
        mov edx, ra
        fld qword ptr [eax]
        fld qword ptr [ecx]
        fdivp st(1), st
        fstp qword ptr [edx]
    }
}
// b - floor(b / c) * c, with the client's own floor, as at 0x00858391.
__declspec(noinline) void XMod(TV* ra, const TV* b, const TV* c) {
    double keepB, keepC;
    const uintptr_t fn = kFloor;
    __asm {
        mov eax, b
        mov ecx, c
        fld qword ptr [eax]
        fst keepB
        fld qword ptr [ecx]
        fst keepC
        fdivp st(1), st
        sub esp, 8
        fstp qword ptr [esp]
        call dword ptr [fn]
        fmul keepC
        add esp, 8
        fsubr keepB
        mov edx, ra
        fstp qword ptr [edx]
    }
}
// The client reaches pow through the CRT helper that takes both operands on the
// x87 stack; calling the same one keeps the result identical.
__declspec(noinline) void XPow(TV* ra, const TV* b, const TV* c) {
    const uintptr_t fn = kCIpow;
    __asm {
        mov eax, b
        mov ecx, c
        fld qword ptr [eax]
        fld qword ptr [ecx]
        call dword ptr [fn]
        mov edx, ra
        fstp qword ptr [edx]
    }
}
__declspec(noinline) void XNeg(TV* ra, const TV* b) {
    __asm {
        mov eax, b
        mov edx, ra
        fld qword ptr [eax]
        fchs
        fstp qword ptr [edx]
    }
}
// idx + step, the addition OP_FORLOOP performs at 0x00858A66.
__declspec(noinline) double XLoopStep(const TV* idx, const TV* step) {
    double sum;   // not `out`: that is an instruction mnemonic in inline asm
    __asm {
        mov eax, step
        mov ecx, idx
        fld qword ptr [eax]
        fadd qword ptr [ecx]
        fstp sum
    }
    return sum;
}
// The unsigned widening OP_LEN uses for a string length, at 0x00858643.
__forceinline void SetLenString(TV* ra, uint32_t len) {
    double d = (double)(int32_t)len;
    if ((int32_t)len < 0) d += 4294967296.0;
    memcpy(ra, &d, sizeof(d));
}
__forceinline void SetLenTable(TV* ra, int n) {
    double d = (double)n;
    memcpy(ra, &d, sizeof(d));
}

__forceinline void CheckGC(void* L) {
    void* g = F<void*>(L, kL_G);
    if (Fc<uint32_t>(g, kG_totalbytes) >= Fc<uint32_t>(g, kG_threshold)) g_step(L);
}

// The inlined string-key read. Returns false for anything the client's own
// luaV_gettable has to decide: a non-table, a non-string key, a key that is not
// present, or a present key whose value is nil - all of which can reach a
// metatable.
__forceinline bool FastGet(void* L, const TV* t, const TV* key, TV* dst) {
    if (g_lookupDead) return false;
    if (t->tt != 5 || key->tt != 4) return false;

    void* h = (void*)(uintptr_t)t->lo;
    void* ts = (void*)(uintptr_t)key->lo;
    const uint8_t lsize = Fc<uint8_t>(h, kT_lsizenode);
    uint8_t* const nodes = Fc<uint8_t*>(h, kT_node);
    const uint32_t mask = (1u << lsize) - 1u;
    uint8_t* n = nodes + (size_t)(mask & Fc<uint32_t>(ts, kTS_hash)) * kNode_size;
    for (;;) {
        if (Fc<int32_t>(n, kNode_keyTt) == 4 &&
            Fc<uint32_t>(n, kNode_keyVal) == (uint32_t)(uintptr_t)ts) break;
        uint8_t* next = Fc<uint8_t*>(n, kNode_next);
        if (!next) return false;
        n = next;
    }
    TV* val = (TV*)n;
    if (val->tt == 0) return false;

    // The client's own lookup is pure, so it can simply be asked whether this
    // is the node it would have found.
    if (g_verified < kVerifyFirst || ((++g_hitSeq) & kResampleMask) == 0) {
        void* theirs = g_getstr(h, ts);
        ++g_verified;
        if (theirs != (void*)n) {
            g_lookupDead = true;
            Log("[LuaVmFast] the inlined table lookup RETIRED after %lu checks: for one "
                "table and key it found node 0x%08X and the client's own luaH_getstr "
                "answers 0x%08X. Nothing was read from ours on this call, so the "
                "session is unaffected; every read now goes to the client.",
                g_verified, (unsigned)(uintptr_t)n, (unsigned)(uintptr_t)theirs);
            Verdict::Add(Verdict::Bad, "LuaVmFast's inlined table lookup disagreed with "
                         "the client's luaH_getstr and retired itself for this session");
            return false;
        }
    }

    // luaV_gettable reports a tainted read of a global before it copies, at
    // 0x0085730F: the callback, the table being the state's globals, a string
    // key, a tainted value and an unfrozen context.
    const uint32_t cb = *(uint32_t*)kTaintReport;
    if (cb && (uint32_t)(uintptr_t)h == Fc<uint32_t>(L, kL_gt) && val->taint && !Frozen()) {
        ((report_fn)(uintptr_t)cb)(L, 2, (const char*)((uint8_t*)ts + kTS_data), val->taint);
    }
    CopyTaint(dst, val);
    return true;
}

__forceinline bool IsFalse(const TV* v) {
    return v->tt == 0 || (v->tt == 1 && v->lo == 0);
}

// A call frame whose closure is a C closure or has no Proto reached the interpreter's
// prologue. Written for the first occurrence only, because the next thing that
// happens is the fault.
__declspec(noinline) void NoteBadFrame(void* L, void* ci, void* cl, int nexeccalls, unsigned how) {
    static bool said = false;
    if (said) return;
    said = true;
    static const char* const kHow[] = { "a fresh entry", "after OP_CALL", "after OP_TAILCALL", "after OP_RETURN" };
    const uint8_t* base_ci = Fc<const uint8_t*>(L, 0x2C);
    const unsigned slot = base_ci ? (unsigned)(((const uint8_t*)ci - base_ci) / kCI_size) : 0u;
    const uint32_t* w = (const uint32_t*)cl;
    Log("[LuaVmFast] a call frame the interpreter cannot run: reached %s, nexeccalls %d, frame %u of the "
        "state's CallInfo array, status %u, closure %p isC %u p %p. First words of the closure: "
        "%08X %08X %08X %08X %08X %08X %08X %08X. The client's interpreter is handed the frame next.",
        kHow[how & 3], nexeccalls, slot, (unsigned)Fc<uint8_t>(L, kL_status), cl,
        (unsigned)Fc<uint8_t>(cl, kCl_isC), Fc<void*>(cl, kCl_p),
        w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
}

}  // namespace

// The interpreter. Every case names the address in sub_857CA0 it was read from.
int __cdecl Hooked_Execute(void* L, int nexeccalls) {
    ++g_calls;
    if (g_dead || !L) return g_orig(L, nexeccalls);
    if (LuaOpt::GuardActive()) return g_orig(L, nexeccalls);
    if (g_abSubject && AbTest::StandAside()) { ++g_stood; return g_orig(L, nexeccalls); }

    void* ci;
    void* cl;
    const TV* k;
    TV* base;
    Instruction* pc;
    unsigned how = 0;   // what led to this pass through 'reentry': 0 entry, 1 CALL, 2 TAILCALL, 3 RETURN

reentry:   // 0x00857CB0
    ci = F<void*>(L, kL_ci);
    pc = F<Instruction*>(L, kL_savedpc);
    {
        TV* func = Fc<TV*>(ci, kCI_func);
        cl = (void*)(uintptr_t)func->lo;
        SetFrozen(0);
        const uint32_t clTaint = Fc<uint32_t>(cl, kCl_taint);
        if (clTaint) {
            if (Armed()) SetCell(clTaint);
            SetFrozen(1);
        }
        void* p = Fc<void*>(cl, kCl_p);
        if (!p || Fc<uint8_t>(cl, kCl_isC)) {
            // The client's own prologue reads cl->p->k here too, so handing the
            // frame back faults the same way. The point is to say what the frame
            // was before it does: one tester's crash was this load with p == NULL,
            // and the log held nothing about how the interpreter got there.
            NoteBadFrame(L, ci, cl, nexeccalls, how);
            return g_orig(L, nexeccalls);
        }
        k = Fc<const TV*>(p, kP_k);
        base = F<TV*>(L, kL_base);
    }

    for (;;) {
        const Instruction i = *pc++;
        const unsigned op = i & 0x3F;

        // The instruction hook and the abort flag, 0x00857D0D and 0x00857D3C.
        // Both are handed back rather than performed here: the hook decrements
        // a counter that must not be decremented twice, and the abort raises.
        if ((Fc<uint8_t>(L, kL_hookmask) & 0x0C) != 0 || Fc<uint32_t>(L, kL_abort) != 0) {
            F<Instruction*>(L, kL_savedpc) = pc - 1;
            ++g_bails;
            ++g_bailOp[op];
            return g_orig(L, nexeccalls);
        }

        ++g_ops;
        if ((unsigned)g_ops == g_opNextSample) {
            ++g_opSamples[op];
            ++g_opSamplesTotal;
            g_opNextSample = (unsigned)g_ops + kSampleGapMin + ((unsigned)__rdtsc() & kSampleGapMask);
        }
        const unsigned a = (i >> 6) & 0xFF;
        const unsigned b = i >> 23;
        const unsigned c = (i >> 14) & 0x1FF;
        const unsigned bx = i >> 14;
        TV* ra = base + a;

        switch (op) {
        case 0: {   // MOVE, 0x00857D7A
            CopyTaint(ra, base + b);
            break;
        }
        case 1: {   // LOADK, 0x00857DD2
            CopyTaint(ra, k + bx);
            break;
        }
        case 2: {   // LOADBOOL, 0x00857E21
            ra->taint = Cell();
            ra->lo = b;
            ra->tt = 1;
            if (i & 0x7FC000) ++pc;
            break;
        }
        case 3: {   // LOADNIL, 0x00857E4C
            TV* q = base + b;
            for (;;) {
                TV* slot = q;
                TV* next = q - 1;
                slot->taint = Cell();
                slot->tt = 0;
                if (next < ra) break;
                q = next;
            }
            break;
        }
        case 4: {   // GETUPVAL, 0x00857E7A
            void* uv = Fc<void*>(cl, kCl_upvals + 4 * b);
            CopyTaint(ra, Fc<const TV*>(uv, kUV_v));
            break;
        }
        case 5: {   // GETGLOBAL, 0x00857ED6
            TV env;
            env.lo = (uint32_t)(uintptr_t)Fc<void*>(cl, kCl_env);
            env.hi = 0;
            env.tt = 5;
            env.taint = Cell();
            const TV* key = k + bx;
            F<Instruction*>(L, kL_savedpc) = pc;
            if (FastGet(L, &env, key, ra)) { ++g_fastGets; }
            else { ++g_slowGets; g_gettable(L, &env, key, ra); }
            base = F<TV*>(L, kL_base);
            break;
        }
        case 6: {   // GETTABLE, 0x00857F17
            const TV* rkc = (c & 0x100) ? (k + (c & 0xFF)) : (base + c);
            TV* rb = base + b;
            F<Instruction*>(L, kL_savedpc) = pc;
            if (FastGet(L, rb, rkc, ra)) { ++g_fastGets; }
            else { ++g_slowGets; g_gettable(L, rb, rkc, ra); }
            base = F<TV*>(L, kL_base);
            break;
        }
        case 7: {   // SETGLOBAL, 0x00857F61
            TV env;
            env.lo = (uint32_t)(uintptr_t)Fc<void*>(cl, kCl_env);
            env.hi = 0;
            env.tt = 5;
            env.taint = Cell();
            F<Instruction*>(L, kL_savedpc) = pc;
            g_settable(L, &env, k + bx, ra);
            base = F<TV*>(L, kL_base);
            break;
        }
        case 8: {   // SETUPVAL, 0x00857FA3
            void* uv = Fc<void*>(cl, kCl_upvals + 4 * b);
            TV* v = Fc<TV*>(uv, kUV_v);
            v->lo = ra->lo;
            v->hi = ra->hi;
            v->tt = ra->tt;
            v->taint = ra->taint;
            TaintFromValue(ra->taint);
            if (ra->tt >= 4) {
                void* gc = (void*)(uintptr_t)ra->lo;
                if ((Fc<uint8_t>(gc, 9) & 3) && (Fc<uint8_t>(uv, 9) & 4)) g_barrierf(L, uv, gc);
            }
            break;
        }
        case 9: {   // SETTABLE, 0x00858014
            const TV* rkc = (c & 0x100) ? (k + (c & 0xFF)) : (base + c);
            const TV* rkb = (b & 0x100) ? (k + (b & 0xFF)) : (base + b);
            F<Instruction*>(L, kL_savedpc) = pc;
            g_settable(L, ra, rkb, rkc);
            base = F<TV*>(L, kL_base);
            break;
        }
        case 10: {  // NEWTABLE, 0x00858074
            ra->taint = Cell();
            const int nhash = g_fb2int((int)c);
            const int narray = g_fb2int((int)b);
            ra->lo = (uint32_t)(uintptr_t)g_newtable(L, narray, nhash);
            ra->tt = 5;
            F<Instruction*>(L, kL_savedpc) = pc;
            CheckGC(L);
            base = F<TV*>(L, kL_base);
            break;
        }
        case 11: {  // SELF, 0x008580BB
            TV* rb = base + b;
            CopyTaint(ra + 1, rb);
            const TV* rkc = (c & 0x100) ? (k + (c & 0xFF)) : (base + c);
            F<Instruction*>(L, kL_savedpc) = pc;
            if (FastGet(L, rb, rkc, ra)) { ++g_fastGets; }
            else { ++g_slowGets; g_gettable(L, rb, rkc, ra); }
            base = F<TV*>(L, kL_base);
            break;
        }
        case 12:    // ADD, 0x00858160
        case 13:    // SUB, 0x008581D2
        case 14:    // MUL, 0x00858244
        case 15:    // DIV, 0x008582B3
        case 16:    // MOD, 0x0085833C
        case 17: {  // POW, 0x008583C7
            const TV* rkb = (b & 0x100) ? (k + (b & 0xFF)) : (base + b);
            const TV* rkc = (c & 0x100) ? (k + (c & 0xFF)) : (base + c);
            if (rkb->tt != 3 || rkc->tt != 3) goto bail;   // the metamethod path
            ra->taint = Cell();
            switch (op) {
            case 12: XAdd(ra, rkb, rkc); break;
            case 13: XSub(ra, rkb, rkc); break;
            case 14: XMul(ra, rkb, rkc); break;
            case 15: XDiv(ra, rkb, rkc); break;
            case 16: XMod(ra, rkb, rkc); break;
            default: XPow(ra, rkb, rkc); break;
            }
            ra->tt = 3;
            break;
        }
        case 18: {  // UNM, 0x00858456
            const TV* rb = base + b;
            if (rb->tt != 3) goto bail;   // string coercion and the metamethod
            ra->taint = Cell();
            XNeg(ra, rb);
            ra->tt = 3;
            break;
        }
        case 19: {  // NOT, 0x00858551
            const TV* rb = base + b;
            const int isFalse = IsFalse(rb) ? 1 : 0;
            ra->taint = Cell();
            ra->lo = (uint32_t)isFalse;
            ra->tt = 1;
            break;
        }
        case 20: {  // LEN, 0x0085858D
            const TV* rb = base + b;
            if (rb->tt == 4) {
                ra->taint = Cell();
                SetLenString(ra, Fc<uint32_t>((void*)(uintptr_t)rb->lo, kTS_len));
                ra->tt = 3;
            } else if (rb->tt == 5) {
                ra->taint = Cell();
                SetLenTable(ra, g_getn((void*)(uintptr_t)rb->lo));
                ra->tt = 3;
            } else {
                goto bail;   // the metamethod path
            }
            break;
        }
        case 21: {  // CONCAT, 0x0085865E
            F<Instruction*>(L, kL_savedpc) = pc;
            g_concat(L, (int)c - (int)b + 1, (int)c);
            CheckGC(L);
            base = F<TV*>(L, kL_base);
            CopyTaint(base + a, base + b);
            break;
        }
        case 22: {  // JMP, 0x008586FA
            pc += (int)bx - 131071;
            break;
        }
        case 23: {  // EQ, 0x0085870F
            const TV* rkb = (b & 0x100) ? (k + (b & 0xFF)) : (base + b);
            const TV* rkc = (c & 0x100) ? (k + (c & 0xFF)) : (base + c);
            F<Instruction*>(L, kL_savedpc) = pc;
            int eq = 0;
            if (rkb->tt == rkc->tt) {
                switch (rkb->tt) {
                case 0: eq = 1; break;
                case 1:
                case 2: eq = (rkb->lo == rkc->lo) ? 1 : 0; break;
                case 3: eq = (NumOf(rkb) == NumOf(rkc)) ? 1 : 0; break;
                case 4:
                case 6:
                case 8: eq = (rkb->lo == rkc->lo) ? 1 : 0; break;
                default: eq = g_equalval(L, rkb, rkc) ? 1 : 0; break;
                }
            }
            if (eq == (int)a) pc += (int)(*pc >> 14) - 131071;
            ++pc;
            base = F<TV*>(L, kL_base);
            break;
        }
        case 24: {  // LT, 0x00858781
            const TV* rkb = (b & 0x100) ? (k + (b & 0xFF)) : (base + b);
            const TV* rkc = (c & 0x100) ? (k + (c & 0xFF)) : (base + c);
            F<Instruction*>(L, kL_savedpc) = pc;
            const int r = (rkb->tt == 3 && rkc->tt == 3)
                              ? ((NumOf(rkb) < NumOf(rkc)) ? 1 : 0)
                              : g_lessthan(L, rkb, rkc);
            if (r == (int)a) pc += (int)(*pc >> 14) - 131071;
            ++pc;
            base = F<TV*>(L, kL_base);
            break;
        }
        case 25: {  // LE, 0x008587FB - the client's helper takes its operands in
                    // registers, so only the two-number case is done here.
            const TV* rkb = (b & 0x100) ? (k + (b & 0xFF)) : (base + b);
            const TV* rkc = (c & 0x100) ? (k + (c & 0xFF)) : (base + c);
            if (rkb->tt != 3 || rkc->tt != 3) goto bail;
            F<Instruction*>(L, kL_savedpc) = pc;
            const int r = (NumOf(rkb) <= NumOf(rkc)) ? 1 : 0;
            if (r == (int)a) pc += (int)(*pc >> 14) - 131071;
            ++pc;
            break;
        }
        case 26: {  // TEST, 0x00858875
            const int isFalse = IsFalse(ra) ? 1 : 0;
            if (isFalse != (int)c) pc += (int)(*pc >> 14) - 131071;
            ++pc;
            break;
        }
        case 27: {  // TESTSET, 0x008588B7
            const TV* rb = base + b;
            const int isFalse = IsFalse(rb) ? 1 : 0;
            if (isFalse != (int)c) {
                CopyTaint(ra, rb);
                pc += (int)(*pc >> 14) - 131071;
            }
            ++pc;
            break;
        }
        case 28: {  // CALL, 0x00858942
            if (++g_callSeen == g_callNext) {
                ++g_callSamples;
                NoteCallee(ra);
                g_callNext = (unsigned)g_callSeen + kCallGapMin + ((unsigned)__rdtsc() & kCallGapMask);
            }
            const uint32_t saved = Frozen() ? Cell() : 0;
            SetFrozen(0);
            if (b) F<TV*>(L, kL_top) = ra + b;
            F<Instruction*>(L, kL_savedpc) = pc;
            const int r = g_precall(L, ra, (int)c - 1);
            if (r == 0) {
                ++nexeccalls;
                how = 1;
                goto reentry;
            }
            if (r == 1) {
                if ((int)c - 1 >= 0)
                    F<TV*>(L, kL_top) = Fc<TV*>(F<void*>(L, kL_ci), kCI_top);
                base = F<TV*>(L, kL_base);
                if (saved) {
                    if (Armed()) SetCell(saved);
                    SetFrozen(1);
                } else {
                    SetFrozen(0);
                }
                break;
            }
            return r - 1;
        }
        case 29: {  // TAILCALL, 0x008589DA
            const uint32_t saved = Frozen() ? Cell() : 0;
            SetFrozen(0);
            if (b) F<TV*>(L, kL_top) = ra + b;
            F<Instruction*>(L, kL_savedpc) = pc;
            const int r = g_precall(L, ra, -1);
            if (r == 0) {
                // The frame fixup at 0x00858F8A: the callee's frame slides down
                // over the caller's, one CallInfo is dropped, and the tail-call
                // count on the surviving frame goes up.
                void* ciNow = F<void*>(L, kL_ci);
                TV* func = Fc<TV*>(ciNow, kCI_func);
                uint8_t* prev = (uint8_t*)ciNow - kCI_size;
                TV* pfunc = Fc<TV*>(prev, kCI_func);
                if (F<void*>(L, kL_openupval)) g_close(L, Fc<void*>(prev, kCI_base));
                const ptrdiff_t delta = (uint8_t*)Fc<TV*>(ciNow, kCI_base) - (uint8_t*)func;
                TV* newBase = (TV*)((uint8_t*)pfunc + delta);
                F<TV*>(prev, kCI_base) = newBase;
                F<TV*>(L, kL_base) = newBase;
                unsigned moved = 0;
                while (func + moved < F<TV*>(L, kL_top)) {
                    CopyTaint(pfunc + moved, func + moved);
                    ++moved;
                }
                TV* newTop = pfunc + moved;
                F<TV*>(L, kL_top) = newTop;
                F<TV*>(prev, kCI_top) = newTop;
                F<Instruction*>(prev, kCI_savedpc) = F<Instruction*>(L, kL_savedpc);
                F<uint32_t>(prev, kCI_tailcalls) += 1;
                F<uint8_t*>(L, kL_ci) = (uint8_t*)ciNow - kCI_size;
                how = 2;
                goto reentry;
            }
            if (r == 1) {
                base = F<TV*>(L, kL_base);
                if (saved) {
                    if (Armed()) SetCell(saved);
                    SetFrozen(1);
                } else {
                    SetFrozen(0);
                }
                break;
            }
            return r - 1;
        }
        case 30: {  // RETURN, 0x0085904D
            SetFrozen(0);
            if (b) F<TV*>(L, kL_top) = ra + (b - 1);
            if (F<void*>(L, kL_openupval)) g_close(L, base);
            F<Instruction*>(L, kL_savedpc) = pc;
            const int r = g_poscall(L, ra);
            if (--nexeccalls == 0) return r;
            if (r) F<TV*>(L, kL_top) = Fc<TV*>(F<void*>(L, kL_ci), kCI_top);
            how = 3;
            goto reentry;
        }
        case 31: {  // FORLOOP, 0x00858A61
            const double step = NumOf(ra + 2);
            const double limit = NumOf(ra + 1);
            const double idx = XLoopStep(ra, ra + 2);
            const bool go = (step <= 0.0) ? (idx >= limit) : (idx <= limit);
            if (go) {
                memcpy(ra, &idx, sizeof(idx));
                ra->taint = Cell();
                ra->tt = 3;
                pc += (int)bx - 131071;
                memcpy(ra + 3, &idx, sizeof(idx));
                ra[3].taint = Cell();
                ra[3].tt = 3;
            }
            break;
        }
        case 32: {  // FORPREP, 0x00858ACA
            if (ra->tt != 3 || ra[1].tt != 3 || ra[2].tt != 3) goto bail;   // the
                    // string coercions and the three error paths
            ra->taint = Cell();
            XSub(ra, ra, ra + 2);
            ra->tt = 3;
            pc += (int)bx - 131071;
            break;
        }
        case 33: {  // TFORLOOP, 0x00858B67
            TV* cb = ra + 3;
            CopyTaint(cb + 2, ra + 2);
            CopyTaint(cb + 1, ra + 1);
            CopyTaint(cb + 0, ra + 0);
            F<TV*>(L, kL_top) = cb + 3;
            F<Instruction*>(L, kL_savedpc) = pc;
            g_call(L, cb, (int)c);
            F<TV*>(L, kL_top) = Fc<TV*>(F<void*>(L, kL_ci), kCI_top);
            base = F<TV*>(L, kL_base);
            cb = base + (a + 3);
            if (cb->tt != 0) {
                CopyTaint(cb - 1, cb);
                pc += (int)(*pc >> 14) - 131071;
            }
            ++pc;
            break;
        }
        case 34: {  // SETLIST, 0x00858CCB
            int n = (int)b;
            unsigned batch = c;
            if (n == 0) {
                n = (int)(F<TV*>(L, kL_top) - ra) - 1;
                F<TV*>(L, kL_top) = Fc<TV*>(F<void*>(L, kL_ci), kCI_top);
            }
            if (batch == 0) batch = *pc++;
            if (ra->tt != 5) break;
            void* h = (void*)(uintptr_t)ra->lo;
            int last = (int)batch * 50 + n - 50;
            if (last > Fc<int32_t>(h, kT_sizearray)) g_resizearray(L, h, last);
            for (; n > 0; --n, --last) {
                const TV* val = ra + n;
                TV* slot = g_setnum(L, h, last);
                slot->lo = val->lo;
                slot->hi = val->hi;
                slot->tt = val->tt;
                slot->taint = val->taint;
                TaintFromValue(val->taint);
                if (val->tt >= 4) {
                    void* gc = (void*)(uintptr_t)val->lo;
                    if ((Fc<uint8_t>(gc, 9) & 3) && (Fc<uint8_t>(h, 9) & 4)) g_barrierback(L, h);
                }
            }
            break;
        }
        case 35: {  // CLOSE, 0x00858DC2
            g_close(L, ra);
            break;
        }
        case 36: {  // CLOSURE, 0x00858DD1
            void* p = Fc<void*>(cl, kCl_p);
            void* np = Fc<void**>(p, kP_protos)[bx];
            const unsigned nups = Fc<uint8_t>(np, kP_nups);
            void* ncl = g_newlclosure(L, (int)nups, Fc<void*>(cl, kCl_env));
            F<void*>(ncl, kCl_p) = np;
            for (unsigned j = 0; j < nups; ++j) {
                const Instruction ins = *pc++;
                const unsigned ub = ins >> 23;
                if ((ins & 0x3F) == 4) {
                    F<void*>(ncl, kCl_upvals + 4 * j) = Fc<void*>(cl, kCl_upvals + 4 * ub);
                } else {
                    F<void*>(ncl, kCl_upvals + 4 * j) = g_findupval(L, base + ub);
                }
            }
            ra->taint = Cell();
            ra->lo = (uint32_t)(uintptr_t)ncl;
            ra->tt = 6;
            F<Instruction*>(L, kL_savedpc) = pc;
            CheckGC(L);
            base = F<TV*>(L, kL_base);
            break;
        }
        case 37: {  // VARARG, 0x00858E8D
            int want = (int)b - 1;
            void* ciNow = F<void*>(L, kL_ci);
            void* p = Fc<void*>(cl, kCl_p);
            const int have = (int)((uint8_t*)Fc<TV*>(ciNow, kCI_base) -
                                   (uint8_t*)Fc<TV*>(ciNow, kCI_func)) / 16 -
                             (int)Fc<uint8_t>(p, kP_numparams) - 1;
            if (want == -1) {
                F<Instruction*>(L, kL_savedpc) = pc;
                if ((int)((uint8_t*)F<TV*>(L, kL_stackLast) - (uint8_t*)F<TV*>(L, kL_top))
                        <= 16 * have)
                    g_growstack(L, have);
                base = F<TV*>(L, kL_base);
                ra = base + a;
                want = have;
                F<TV*>(L, kL_top) = ra + have;
            }
            for (int j = 0; j < want; ++j) {
                if (j < have) {
                    CopyTaint(ra + j, Fc<TV*>(ciNow, kCI_base) - have + j);
                } else {
                    ra[j].tt = 0;
                    ra[j].taint = Cell();
                }
            }
            break;
        }
        default:
            goto bail;
        }
        continue;

    bail:
        F<Instruction*>(L, kL_savedpc) = pc - 1;
        ++g_bails;
        ++g_bailOp[op];
        return g_orig(L, nexeccalls);
    }
}

bool Init() {
    if (!Config::g_settings.OptLuaVmFast) return true;

    // push ebp / mov ebp, esp / sub esp, 6Ch. Read out of the client rather
    // than guessed: sub with a byte immediate is 83, not 81, and the guess put
    // 81 here, so this refused to install on the very function it was written
    // for and said the bytes were somebody else's.
    static const unsigned char kPrologue[] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x6C };
    const unsigned char* p = (const unsigned char*)kExecute;
    if (memcmp(p, kPrologue, sizeof(kPrologue)) != 0) {
        Log("[LuaVmFast] NOT active: the bytes at 0x%08X are not the interpreter this "
            "was transcribed from.", (unsigned)kExecute);
        return false;
    }
    if (!WowOpt_ClientPatchAllowed((const void*)kExecute)) {
        Log("[LuaVmFast] NOT active: No Client Patches is on, and this hooks a function "
            "inside wow.exe.");
        return false;
    }
    if (WineSafe_CreateHook((void*)kExecute, (void*)&Hooked_Execute, (void**)&g_orig) != MH_OK) {
        Log("[LuaVmFast] NOT active: the hook on 0x%08X could not be created.",
            (unsigned)kExecute);
        return false;
    }
    if (WO_EnableHook((void*)kExecute) != MH_OK) {
        MH_RemoveHook((void*)kExecute);
        Log("[LuaVmFast] NOT active: the hook on 0x%08X could not be enabled.",
            (unsigned)kExecute);
        return false;
    }
    g_installed = true;
    g_abSubject = AbTest::IsSubject("LuaVmFast", &g_abSubject);

    Log("[LuaVmFast] ACTIVE on luaV_execute (sub_857CA0), transcribed opcode by opcode "
        "from its disassembly with the string-key table lookup inlined: a global read "
        "or a method fetch resolves here instead of calling luaV_gettable, luaH_get and "
        "luaH_getstr. Anything this does not do exactly - an arithmetic metamethod, a "
        "comparison that is not two numbers, a debug hook - is handed back to the "
        "client's own interpreter at the same instruction. The first %lu lookups, and "
        "one in %lu after, are checked against the client's luaH_getstr.",
        kVerifyFirst, kResampleMask + 1);
    if (g_abSubject)
        Log("[LuaVmFast]   under A/B test: the OFF half runs the client's interpreter "
            "through the same hook, so both halves pay for the call and only the "
            "dispatch differs.");
    return true;
}

void Shutdown() {
    if (!g_installed) return;
    MH_DisableHook((void*)kExecute);
    g_installed = false;
}

void LogStats() {
    if (!Config::g_settings.OptLuaVmFast) {
        Log("[LuaVmFast] not measured: switched off (UI_Lua/LuaVmFast).");
        return;
    }
    if (!g_installed) {
        Log("[LuaVmFast] not installed - the reason is at the top of this log");
        return;
    }
    if (g_calls == 0) {
        Log("[LuaVmFast] hooked, and the interpreter has not been entered since. That is "
            "measured and zero, not unmeasured.");
        return;
    }
    Log("[LuaVmFast] %llu entries, %llu opcodes executed here, %llu handed back to the "
        "client. Plain counters, lower bounds.", g_calls, g_ops, g_bails);
    Log("[LuaVmFast]   table reads: %llu answered by the inlined lookup, %llu left to "
        "luaV_gettable%s.", g_fastGets, g_slowGets,
        g_lookupDead ? " - the lookup is RETIRED after a disagreement" : "");
    if (!g_lookupDead) {
        Log("[LuaVmFast]   %lu lookup(s) checked against the client's luaH_getstr, none "
            "differed%s.", g_verified,
            g_verified < kVerifyFirst ? " yet - still checking every one" : "");
    }
    // What the interpreter spends its instructions on, from the sampled histogram.
    // A share is instructions, not time: a CALL and a MOVE count once each.
    if (g_opSamplesTotal < 1000) {
        Log("[LuaVmFast]   opcode mix: %lu sample(s) so far, too few to say (a share is read to "
            "within about +-%.1f points at 1000).", g_opSamplesTotal, 100.0 * 0.5 / 31.6);
    } else {
        const double n = (double)g_opSamplesTotal;
        unsigned order[kOpcodes];
        for (unsigned k = 0; k < kOpcodes; ++k) order[k] = k;
        for (unsigned x = 1; x < kOpcodes; ++x) {               // insertion sort, descending
            unsigned v = order[x], y = x;
            while (y > 0 && g_opSamples[order[y - 1]] < g_opSamples[v]) { order[y] = order[y - 1]; --y; }
            order[y] = v;
        }
        Log("[LuaVmFast]   opcode mix over %lu sample(s), one in about 128 instructions, taken at "
            "a jittered gap. A share is instructions executed here, not time. One standard error is "
            "at most %.2f points.", g_opSamplesTotal, 100.0 * 0.5 / sqrt(n));
        for (unsigned r = 0; r < 12; ++r) {
            const unsigned o = order[r];
            if (!g_opSamples[o]) break;
            Log("[LuaVmFast]     %-9s %5.1f%%  (%lu)", kOpName[o], 100.0 * (double)g_opSamples[o] / n, g_opSamples[o]);
        }
        unsigned long beyond = 0;
        for (unsigned o = kOpcodes; o < 64; ++o) beyond += g_opSamples[o];
        if (beyond) Log("[LuaVmFast]     %lu sample(s) named an opcode above %u.", beyond, kOpcodes - 1);
        Log("[LuaVmFast]     GETGLOBAL %.1f%% SETGLOBAL %.1f%% GETTABLE %.1f%% SELF %.1f%% CALL %.1f%%.",
            100.0 * (double)g_opSamples[5] / n, 100.0 * (double)g_opSamples[7] / n,
            100.0 * (double)g_opSamples[6] / n, 100.0 * (double)g_opSamples[11] / n,
            100.0 * (double)g_opSamples[28] / n);
    }
    // What the scripts call, from the sampled CALLs.
    if (g_callSamples < 500) {
        Log("[LuaVmFast]   callees: %lu sampled CALL(s) so far, too few to say.", g_callSamples);
    } else {
        const double cn = (double)g_callSamples;
        Log("[LuaVmFast]   callees over %lu sampled CALL(s) of %lu (one in about 64): %.1f%% C functions, "
            "%.1f%% Lua functions, %.1f%% neither (a __call metamethod). Calls made by the client's own "
            "interpreter are not seen.",
            g_callSamples, g_callSeen, 100.0 * g_callSampledC / cn, 100.0 * g_callSampledLua / cn,
            100.0 * g_callSampledOther / cn);
        unsigned idx[kCfnSlots];
        unsigned used = 0;
        for (unsigned s = 0; s < kCfnSlots; ++s) if (g_cfn[s].f) idx[used++] = s;
        for (unsigned x = 1; x < used; ++x) {                   // insertion sort, descending
            unsigned v = idx[x], y = x;
            while (y > 0 && g_cfn[idx[y - 1]].n < g_cfn[v].n) { idx[y] = idx[y - 1]; --y; }
            idx[y] = v;
        }
        const double cc = g_callSampledC ? (double)g_callSampledC : 1.0;
        double cum = 0.0;
        for (unsigned r = 0; r < used && r < 15; ++r) {
            const CfnSlot& e = g_cfn[idx[r]];
            const double share = 100.0 * (double)e.n / cc;
            cum += share;
            Log("[LuaVmFast]     C function %p  %5.1f%% of C calls  (%lu)  cumulative %.1f%%%s",
                e.f, share, e.n, cum,
                ((uintptr_t)e.f >= 0x00401000 && (uintptr_t)e.f < 0x009DF000) ? "" : "  - outside wow.exe");
        }
        Log("[LuaVmFast]     %u distinct C function(s) seen%s. Addresses are the function itself; "
            "name one by finding what the client registers it under.",
            used, g_cfnLost ? " (the table was full, so some are missing)" : "");
    }
    // Which opcodes leave. A number here is the reason to transcribe that case
    // next; a zero is the reason not to.
    unsigned top = 0;
    for (unsigned n = 1; n < 64; ++n) if (g_bailOp[n] > g_bailOp[top]) top = n;
    if (g_bailOp[top])
        Log("[LuaVmFast]   the opcode handed back most often is %u, %lu time(s).",
            top, g_bailOp[top]);
    if (g_abSubject)
        Log("[LuaVmFast]   %llu entry(ies) ran the client's interpreter as the A/B "
            "control half.", g_stood);
}

}  // namespace LuaVmFast
