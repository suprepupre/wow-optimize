#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <emmintrin.h>
#include <cmath>
#include "MinHook.h"
#include "version.h"   // the No Client Patches gate and the foreign-detour check live here
#include "crash_dumper.h"
#include "lua_vm_engine.h"
#include "lua_optimize.h"
#include "high_tables.h"

extern "C" void Log(const char* fmt, ...);

// ================================================================
// WoW Lua 5.1 Constants
// ================================================================
static constexpr int LUA_TNIL          = 0;
static constexpr int LUA_TBOOLEAN      = 1;
static constexpr int LUA_TLIGHTUSERDATA = 2;
static constexpr int LUA_TNUMBER       = 3;
static constexpr int LUA_TSTRING       = 4;
static constexpr int LUA_TTABLE        = 5;
static constexpr int LUA_TFUNCTION     = 6;
static constexpr int LUA_TUSERDATA     = 7;
static constexpr int LUA_TTHREAD       = 8;

static constexpr uintptr_t TAINT_GLOBAL  = 0x00D4139C;
static constexpr uintptr_t TAINT_FLAG_A  = 0x00D413A0;
static constexpr uintptr_t TAINT_FLAG_B  = 0x00D413A4;

static inline uint32_t GetGlobalTaint() {
    return *(uint32_t*)TAINT_GLOBAL;
}

// TValue layout (16 bytes)
struct TValue {
    union {
        double n;
        void* gc;
        int b;
        uintptr_t p;
    } value;
    int tt;
    uint32_t taint;
};

static_assert(sizeof(TValue) == 16, "TValue must be 16 bytes");

typedef uint32_t Instruction;

static inline int GET_OPCODE(Instruction i) { return (int)(i & 0x3F); }
static inline int GETARG_A(Instruction i)   { return (int)((i >> 6) & 0xFF); }
static inline int GETARG_B(Instruction i)   { return (int)((i >> 23) & 0x1FF); }
static inline int GETARG_C(Instruction i)   { return (int)((i >> 14) & 0x1FF); }
static inline int GETARG_Bx(Instruction i)  { return (int)((i >> 14) & 0x3FFFF); }
static inline int GETARG_sBx(Instruction i) { return GETARG_Bx(i) - 131071; }

enum OpCode {
    OP_MOVE = 0,     OP_LOADK,      OP_LOADBOOL,   OP_LOADNIL,
    OP_GETUPVAL,     OP_GETGLOBAL,  OP_GETTABLE,   OP_SETGLOBAL,
    OP_SETUPVAL,     OP_SETTABLE,   OP_NEWTABLE,   OP_SELF,
    OP_ADD,          OP_SUB,        OP_MUL,        OP_DIV,
    OP_MOD,          OP_POW,        OP_UNM,        OP_NOT,
    OP_LEN,          OP_CONCAT,     OP_JMP,        OP_EQ,
    OP_LT,           OP_LE,         OP_TEST,       OP_TESTSET,
    OP_CALL,         OP_TAILCALL,   OP_RETURN,     OP_FORLOOP,
    OP_FORPREP,      OP_TFORLOOP,   OP_SETLIST,    OP_CLOSE,
    OP_CLOSURE,      OP_VARARG
};

// Statistics
static LuaVMEngineStats g_stats = {};

LuaVMEngineStats GetLuaVMEngineStats() { return g_stats; }

// Inline Cache System
static constexpr int IC_ENTRIES_PER_SITE = 4;
static constexpr int IC_TOTAL_SITES = 8192;

struct ICEntry {
    uintptr_t tablePtr;      // Table* or 0
    uint64_t  keyIdentity;   // TString*
    int       keyType;       // LUA_TSTRING
    void*     resultNode;    // Node*
    uint32_t  generation;
    uint32_t  nodeArray;     // the table's node array when this was recorded
};

// This client's Table is the stock Lua 5.1 layout plus four, the same shift the
// rest of the VM has: stock `node` is at +16, so it is at +20 here.
static const unsigned kTable_Node = 20;

// A cache that says it found the same node the engine would is a claim, and it
// is cheap to check: luaH_getstr is a pure lookup with no side effect, so it can
// simply be asked. The first hits are all checked and one in kIcRecheck after,
// and a single disagreement retires the cache for the session.
static const long kIcProve   = 20000;
static const unsigned kIcRecheck = 1023;
static long g_icChecked = 0;
static long g_icHitSeq  = 0;
static bool g_icDead    = false;

// A megabyte exactly, and it used to sit in this DLL's image, which is
// mapped into the low 2GB - the half the client allocates from and the half
// a tester log has reported down to a 5MB largest free block. It is indexed
// the same way through a pointer, and the hot path below cannot see a null
// one because the hook it lives in is only installed after this is reserved.
static constexpr size_t IC_BYTES =
    sizeof(ICEntry) * IC_TOTAL_SITES * IC_ENTRIES_PER_SITE;
static ICEntry* g_inlineCache = nullptr;
static volatile LONG g_icGeneration = 0;

static inline void ICInvalidate() {
    InterlockedIncrement(&g_icGeneration);
}

// Invalidating the whole inline cache is an O(1) operation: a lookup only accepts
// a way whose stored generation equals the current one, so bumping the generation
// orphans every entry at once.
//
// This used to memset the entire table first - 8192 sites x 4 ways x 32 bytes =
// exactly 1 MB - and it is called from the luaH_resize hook, i.e. once per Lua
// table growth. Addon load resizes tables tens of thousands of times, so the main
// thread spent whole seconds inside a memcpy loop clearing a cache the very next
// instruction was about to invalidate anyway. That is the "world loads but the
// loading screen never goes away" freeze in issue #46: the game keeps running
// (addons execute, events fire) while the frame loop cannot advance. A tester
// profile had 52% of all steady-state samples inside VCRUNTIME140, reached
// through this function, with a 39.7 s and a 95.7 s frame either side of it.
void ClearLuaVMEngineCaches() {
    LONG gen = InterlockedIncrement(&g_icGeneration);

    // The one case the counter cannot cover on its own: on wrap-around a stale
    // entry could carry a generation equal to the new current one. Physically
    // clearing there keeps the invariant exact, and costs 1 MB once per 2^32
    // invalidations.
    if (gen == 0 && g_inlineCache) {
        memset(g_inlineCache, 0, IC_BYTES);
    }
}

void LuaVMEngine_FrameTick() {
    InterlockedIncrement(&g_icGeneration);
}

// Original function pointers & internal Lua APIs
typedef int (__cdecl* luaV_execute_fn)(void* L, int nexeccalls);
static luaV_execute_fn g_orig_luaV_execute = nullptr;

typedef void* (__cdecl* luaV_gettable_fn)(int L, int* table, int* key, void* result);
static luaV_gettable_fn g_orig_luaV_gettable = nullptr;

typedef void* (__cdecl* luaV_settable_fn)(int L, int* table, int* key, int* val);
static luaV_settable_fn g_orig_luaV_settable = nullptr;

typedef void* (__cdecl* luaH_getstr_fn)(int table, int tstring);
static luaH_getstr_fn g_orig_luaH_getstr = nullptr;



typedef void (__cdecl* luaC_barrier__fn)(void* L, void* p, void* v);
static luaC_barrier__fn g_orig_luaC_barrier_ = (luaC_barrier__fn)0x0085BA50;

typedef int (__cdecl* luaD_precall_fn)(void* L, TValue* func, int nresults, __int64 start_time, __int64* end_time);
static luaD_precall_fn g_orig_luaD_precall = (luaD_precall_fn)0x00856550;

typedef int (__cdecl* luaD_poscall_fn)(void* L, TValue* ra);
static luaD_poscall_fn g_orig_luaD_poscall = (luaD_poscall_fn)0x00856010;

typedef void (__cdecl* luaF_close_fn)(void* L, TValue* level);
static luaF_close_fn g_orig_luaF_close = (luaF_close_fn)0x0085CE70;

typedef __int64 (__cdecl* get_cycles_fn)();
static get_cycles_fn g_get_cycles = (get_cycles_fn)0x0086AE30;

// ================================================================
// Fast TValue helpers (SSE2-accelerated)
// ================================================================
// The tail of the client's luaV_gettable at 0x00857250, transcribed from the
// disassembly rather than the decompiler, because the decompiler renders the
// taint cell as a pointer and it is not one - 0x0085737F is
// `mov dword_D4139C, ebx`, a direct store.
//
//     mov ecx,[ebx]    / mov [eax],ecx        ; value lo
//     mov edx,[ebx+4]  / mov [eax+4],edx      ; value hi
//     mov ecx,[ebx+8]  / mov [eax+8],ecx      ; tt
//     mov edx,[ebx+0Ch]/ mov [eax+0Ch],edx    ; taint
//     mov ebx,[ebx+0Ch] / test ebx,ebx / jz  ...
//     cmp dword_D413A0,0 / jz  out
//     cmp dword_D413A4,0 / jnz out
//     mov dword_D4139C, ebx                   ; and taint the context
//
// with the zero branch writing the *current* global taint into the result.
//
// A plain sixteen-byte copy is wrong in the direction that matters: it returns a
// taint word of zero where the engine would have written the ambient taint, so a
// read through the cache launders the context clean. In this client's terms that
// is a security bug, not a performance one.
static const uintptr_t kTaintCell   = 0x00D4139C;
static const uintptr_t kTaintArmed  = 0x00D413A0;
static const uintptr_t kTaintFrozen = 0x00D413A4;
static const uintptr_t kTaintReport = 0x00D413B0;   // a callback, may be null

// value, tt and taint copied the way the engine copies them, then the engine's
// own two-branch taint rule.
static inline void CopyWithTaint(TValue* dst, const TValue* src) {
    dst->value = src->value;
    dst->tt    = src->tt;
    const uint32_t t = src->taint;
    dst->taint = t;
    if (t) {
        if (*(volatile uint32_t*)kTaintArmed && !*(volatile uint32_t*)kTaintFrozen)
            *(volatile uint32_t*)kTaintCell = t;
    } else {
        dst->taint = *(volatile uint32_t*)kTaintCell;
    }
}

// The engine also reports a tainted read of a global, before the copy:
//
//     if (D413B0 && table == *(L+72) && key->tt == LUA_TSTRING) {
//         v11 = node->taint;
//         if (v11 && !D413A4) D413B0(L, 2, key->value.gc + 20, v11);
//     }
//
// L+72 is gt(L), the same slot LUA_GLOBALSINDEX resolves to, and key + 20 is the
// TString's characters - this client's TString is the stock layout plus four.
typedef void (__cdecl* TaintReport_fn)(int L, int kind, const char* name, uint32_t taint);

static inline void ReportTaintedGlobalRead(int L, uintptr_t tablePtr,
                                           const TValue* key, uint32_t nodeTaint) {
    TaintReport_fn cb = *(TaintReport_fn*)kTaintReport;
    if (!cb) return;
    if (tablePtr != *(uint32_t*)((uintptr_t)L + 72)) return;
    if (key->tt != LUA_TSTRING) return;
    if (!nodeTaint) return;
    if (*(volatile uint32_t*)kTaintFrozen) return;
    cb(L, 2, (const char*)((uintptr_t)key->value.gc + 20), nodeTaint);
}

// Asks the engine's own luaH_getstr whether the cached node is the node it would
// have found. Pure, so it can be called without disturbing anything.
static inline bool VerifyAgainstEngine(uintptr_t tablePtr, uintptr_t keyPtr,
                                       void* cached) {
    if (g_icDead) return false;
    const bool check = (g_icChecked < kIcProve) ||
                       ((++g_icHitSeq & kIcRecheck) == 0);
    if (!check) return true;
    if (!g_orig_luaH_getstr) return true;
    void* theirs = g_orig_luaH_getstr((int)tablePtr, (int)keyPtr);
    ++g_icChecked;
    if (theirs == cached) return true;
    g_icDead = true;
    Log("[VMEngine] inline cache RETIRED after %ld checks: for one table and key "
        "it held node 0x%08X and the engine's own luaH_getstr answers 0x%08X. "
        "Nothing was read from ours on this call - the engine answers it - so "
        "the session is unaffected.",
        g_icChecked, (unsigned)(uintptr_t)cached, (unsigned)(uintptr_t)theirs);
    return false;
}

static inline void TValueCopy(TValue* dst, const TValue* src) {
    __m128i v = _mm_loadu_si128((const __m128i*)src);
    _mm_storeu_si128((__m128i*)dst, v);
}

static inline void SetNilValue(TValue* v) {
    _mm_storeu_si128((__m128i*)v, _mm_setzero_si128());
}

// Bulk-nil: zeroes value+tt+taint in one SSE2 store per slot.
// Pre-built __m128i with taint in the high dword avoids a separate taint write.
static inline void SetNilValueTaint(TValue* v, int taintVal) {
    __m128i packed = _mm_set_epi32(taintVal, 0, 0, 0);
    _mm_storeu_si128((__m128i*)v, packed);
}

// Write {value.n, tt=LUA_TNUMBER, taint} as one coalesced 16-byte store.
static inline void TValueSetNum(TValue* dst, double val, uint32_t taint) {
    dst->value.n = val;
    dst->tt = LUA_TNUMBER;
    dst->taint = taint;
}

// Write {value.b, tt=LUA_TBOOLEAN, taint} as one coalesced 16-byte store.
static inline void TValueSetBool(TValue* dst, int bval, uint32_t taint) {
    dst->value.b = bval;
    dst->tt = LUA_TBOOLEAN;
    dst->taint = taint;
}

static inline bool IsCollectable(const TValue* o) {
    return o->tt >= LUA_TSTRING;
}

static inline unsigned char GetGCMarked(void* gc) {
    return *(unsigned char*)((char*)gc + 9);
}

static inline void LuaC_Barrier(void* L, void* p, const TValue* v) {
    if (IsCollectable(v)) {
        void* gc_v = v->value.gc;
        if (gc_v && p) {
            unsigned char marked_p = GetGCMarked(p);
            unsigned char marked_v = GetGCMarked(gc_v);
            if ((marked_v & 3) && (marked_p & 4)) {
                g_orig_luaC_barrier_(L, p, gc_v);
            }
        }
    }
}

// Optimized gettable with inline cache
static void* __fastcall FastGetTable(void* L, TValue* table, TValue* key, TValue* result) {
    ++g_stats.gettableFastPath;
    
    if (table->tt != LUA_TTABLE || key->tt != LUA_TSTRING) {
        return g_orig_luaV_gettable((int)L, (int*)table, (int*)key, result);
    }

    uintptr_t tablePtr = (uintptr_t)table->value.gc;
    uintptr_t tstringPtr = (uintptr_t)key->value.gc;
    
    if (tablePtr < 0x10000 || tablePtr > 0xFFE00000 ||
        tstringPtr < 0x10000 || tstringPtr > 0xFFE00000) {
        return g_orig_luaV_gettable((int)L, (int*)table, (int*)key, result);
    }

    uintptr_t retAddr = (uintptr_t)_ReturnAddress();
    uint32_t icIdx = ((uint32_t)(retAddr ^ tablePtr ^ tstringPtr)) % IC_TOTAL_SITES;
    LONG currentGen = g_icGeneration;
    
    ICEntry* site = &g_inlineCache[icIdx * IC_ENTRIES_PER_SITE];
    for (int way = 0; way < IC_ENTRIES_PER_SITE; way++) {
        if (site[way].tablePtr == tablePtr && 
            site[way].keyIdentity == tstringPtr &&
            site[way].keyType == LUA_TSTRING &&
            site[way].generation == currentGen) {
            
            void* node = site[way].resultNode;
            if (node && (uintptr_t)node >= 0x10000 && (uintptr_t)node <= 0xFFE00000) {
                uint32_t* np = (uint32_t*)node;
                // Check key matches (np[6] is key.tt at +24, np[4] is key.value.gc at +16)
                if (np[6] == LUA_TSTRING && np[4] == (uint32_t)tstringPtr) {
                    // The cached node has to still belong to this table's live
                    // node array. A rehash frees the old array, and without this
                    // the reads above land in memory the allocator has taken
                    // back. Comparing the array pointer the entry was made
                    // against with the table's current one closes that window:
                    // a freed array cannot still be the table's own.
                    if (*(uint32_t*)(tablePtr + kTable_Node) != site[way].nodeArray) {
                        site[way].tablePtr = 0;   // stale, drop it
                        break;
                    }
                    if (!VerifyAgainstEngine(tablePtr, tstringPtr, node))
                        break;
                    ++g_stats.icHits;
                    ReportTaintedGlobalRead((int)L, tablePtr, key,
                                            ((TValue*)node)->taint);
                    CopyWithTaint(result, (TValue*)node);
                    return result;
                }
            }
        }
    }
    
    ++g_stats.icMisses;
    
    void* ret = g_orig_luaV_gettable((int)L, (int*)table, (int*)key, result);
    
    int victim = 0;
    for (int way = 0; way < IC_ENTRIES_PER_SITE; way++) {
        if (site[way].tablePtr == 0 || site[way].generation != currentGen) { 
            victim = way; 
            break; 
        }
    }
    
    uintptr_t expectedNull = site[victim].tablePtr;
    if (InterlockedCompareExchange(
            (volatile LONG*)&site[victim].tablePtr,
            (LONG)tablePtr, (LONG)expectedNull) == (LONG)expectedNull ||
        site[victim].tablePtr == tablePtr) {
        
        void* node = g_orig_luaH_getstr((int)tablePtr, (int)tstringPtr);
        site[victim].keyIdentity = tstringPtr;
        site[victim].keyType = LUA_TSTRING;
        site[victim].resultNode = node;
        site[victim].nodeArray  = *(uint32_t*)(tablePtr + kTable_Node);
        site[victim].generation = currentGen;
        MemoryBarrier();
        site[victim].tablePtr = tablePtr;
    }
    
    return ret;
}

static void* __fastcall FastSetTable(void* L, TValue* table, TValue* key, TValue* val) {
    ++g_stats.settableFastPath;
    return g_orig_luaV_settable((int)L, (int*)table, (int*)key, (int*)val);
}



// Thread-local VM execution state
static constexpr int MAX_OPCODES_PER_SLICE = 100000;

static __declspec(thread) void* t_currentL = nullptr;
static __declspec(thread) int t_opcodesRemaining = 0;
static __declspec(thread) bool t_inOptimizedExecution = false;

// The Hooked Interpreter Core
static inline bool IsTeardownState() {
    uintptr_t gL = *(uintptr_t*)0x00D3F78C;
    return (gL < 0x10000 || gL > 0xFFE00000);
}

#pragma warning(push)
#pragma warning(disable: 4715)
static int __cdecl Hooked_luaV_execute(void* L, int nexeccalls) {
    if (IsTeardownState()) {
        return g_orig_luaV_execute(L, nexeccalls);
    }
    // The same three flags, read inline; see LuaOpt::GuardActive.
    if (LuaOpt::GuardActive()) {
        return g_orig_luaV_execute(L, nexeccalls);
    }
    if (t_inOptimizedExecution) {
        return g_orig_luaV_execute(L, nexeccalls);
    }
    if (!L || (uintptr_t)L < 0x10000 || (uintptr_t)L > 0xFFE00000) {
        return g_orig_luaV_execute(L, nexeccalls);
    }
    
    __try {
        t_currentL = L;
        t_inOptimizedExecution = true;
        t_opcodesRemaining = MAX_OPCODES_PER_SLICE;
        
        TValue* base = *(TValue**)((char*)L + 0x10);
        TValue* top = *(TValue**)((char*)L + 0x0C);
        Instruction* pc = *(Instruction**)((char*)L + 0x1C);
        
        if (!base || !pc) {
            t_inOptimizedExecution = false;
            return g_orig_luaV_execute(L, nexeccalls);
        }
        
        void* ci = *(void**)((char*)L + 0x18);
        if (!ci) {
            t_inOptimizedExecution = false;
            return g_orig_luaV_execute(L, nexeccalls);
        }
        
        TValue* funcSlot = *(TValue**)((char*)ci + 0x04);
        if (!funcSlot || funcSlot->tt != LUA_TFUNCTION) {
            t_inOptimizedExecution = false;
            return g_orig_luaV_execute(L, nexeccalls);
        }
        
        void* closure = funcSlot->value.gc;
        if (!closure || (uintptr_t)closure < 0x10000) {
            t_inOptimizedExecution = false;
            return g_orig_luaV_execute(L, nexeccalls);
        }
        
        void* proto = *(void**)((char*)closure + 24);
        if (!proto || (uintptr_t)proto < 0x10000) {
            t_inOptimizedExecution = false;
            return g_orig_luaV_execute(L, nexeccalls);
        }
        
        TValue* k = *(TValue**)((char*)proto + 12);
        if (!k) {
            t_inOptimizedExecution = false;
            return g_orig_luaV_execute(L, nexeccalls);
        }
        
        #define RA(i) GETARG_A(i)
        #define RB(i) GETARG_B(i)
        #define RC(i) GETARG_C(i)
        #define RKB(i) (GETARG_B(i) > 255 ? &k[GETARG_B(i)-256] : &base[GETARG_B(i)])
        #define RKC(i) (GETARG_C(i) > 255 ? &k[GETARG_C(i)-256] : &base[GETARG_C(i)])
        #define KBx(i) &k[GETARG_Bx(i)]
        
        #define DISPATCH() \
            do { \
                if (--t_opcodesRemaining <= 0) goto yield_back; \
                ++g_stats.totalOpcodes; \
                i = *pc++; \
                op = GET_OPCODE(i); \
                goto dispatch_table; \
            } while(0)
            
        #define DELEGATE_AND_RETURN(pc_adj) \
            do { \
                *(Instruction**)((char*)L + 0x1C) = pc - 1 + (pc_adj); \
                *(TValue**)((char*)L + 0x0C) = top; \
                t_inOptimizedExecution = false; \
                int res = g_orig_luaV_execute(L, nexeccalls); \
                t_currentL = nullptr; \
                return res; \
            } while(0)
            
        Instruction i;
        int op;
        
        // Initial fetch
        i = *pc++;
        op = GET_OPCODE(i);
        
    dispatch_table:
        switch (op) {
            case OP_MOVE: {
                TValueCopy(&base[RA(i)], &base[RB(i)]);
                DISPATCH();
            }
            case OP_LOADK: {
                TValueCopy(&base[RA(i)], KBx(i));
                DISPATCH();
            }
            case OP_LOADBOOL: {
                int a = RA(i);
                int b = RB(i);
                int c = RC(i);
                TValueSetBool(&base[a], b, GetGlobalTaint());
                if (c) pc++;
                DISPATCH();
            }
            case OP_LOADNIL: {
                int a = RA(i);
                int b = RB(i);
                int gTaint = (int)GetGlobalTaint();
                __m128i nilVal = _mm_set_epi32(gTaint, 0, 0, 0);
                for (int j = a; j <= b; j++) {
                    _mm_storeu_si128((__m128i*)&base[j], nilVal);
                }
                DISPATCH();
            }
            case OP_GETUPVAL: {
                int a = RA(i);
                int b = RB(i);
                void* upval = *(void**)((char*)closure + 28 + b * 4);
                if (upval && (uintptr_t)upval >= 0x10000) {
                    TValue* uv = *(TValue**)((char*)upval + 12);
                    if (uv) {
                        TValueCopy(&base[a], uv);
                    } else {
                        SetNilValueTaint(&base[a], (int)GetGlobalTaint());
                    }
                } else {
                    SetNilValueTaint(&base[a], (int)GetGlobalTaint());
                }
                if (base[a].taint && *(uint32_t*)TAINT_FLAG_A && !*(uint32_t*)TAINT_FLAG_B) {
                    *(uint32_t*)TAINT_GLOBAL = base[a].taint;
                }
                DISPATCH();
            }
            case OP_GETGLOBAL: {
                TValue* ra = &base[RA(i)];
                TValue* kstr = KBx(i);
                
                void* envTable = *(void**)((char*)closure + 16);
                if (envTable && (uintptr_t)envTable >= 0x10000) {
                    TValue envVal;
                    envVal.value.gc = envTable;
                    envVal.tt = LUA_TTABLE;
                    envVal.taint = GetGlobalTaint();
                    
                    TValue globalKey;
                    TValueCopy(&globalKey, kstr);
                    
                    FastGetTable(L, &envVal, &globalKey, ra);
                } else {
                    SetNilValueTaint(ra, (int)GetGlobalTaint());
                }
                DISPATCH();
            }
            case OP_GETTABLE: {
                TValue* rb = &base[RB(i)];
                TValue* rkc = RKC(i);
                TValue* ra = &base[RA(i)];
                
                if (rb->tt == LUA_TTABLE && rkc->tt == LUA_TSTRING) {
                    FastGetTable(L, rb, rkc, ra);
                } else {
                    g_orig_luaV_gettable((int)L, (int*)rb, (int*)rkc, ra);
                }
                DISPATCH();
            }
            case OP_SETGLOBAL: {
                TValue* ra = &base[RA(i)];
                TValue* kstr = KBx(i);
                void* envTable = *(void**)((char*)closure + 16);
                if (envTable && (uintptr_t)envTable >= 0x10000) {
                    TValue envVal;
                    envVal.value.gc = envTable;
                    envVal.tt = LUA_TTABLE;
                    envVal.taint = GetGlobalTaint();
                    FastSetTable(L, &envVal, kstr, ra);
                }
                DISPATCH();
            }
            case OP_SETUPVAL: {
                int a = RA(i);
                int b = RB(i);
                void* upval = *(void**)((char*)closure + 28 + b * 4);
                if (upval && (uintptr_t)upval >= 0x10000) {
                    TValue* uv = *(TValue**)((char*)upval + 12);
                    if (uv) {
                        TValueCopy(uv, &base[a]);
                        LuaC_Barrier(L, upval, &base[a]);
                    }
                }
                DISPATCH();
            }
            case OP_SETTABLE: {
                TValue* ra = &base[RA(i)];
                TValue* rkb = RKB(i);
                TValue* rkc = RKC(i);
                FastSetTable(L, ra, rkb, rkc);
                DISPATCH();
            }
            case OP_NEWTABLE: {
                DELEGATE_AND_RETURN(0);
            }
            case OP_SELF: {
                int a = RA(i);
                TValueCopy(&base[a+1], &base[RB(i)]);
                TValue* rkc = RKC(i);
                FastGetTable(L, &base[a+1], rkc, &base[a]);
                DISPATCH();
            }
            case OP_ADD: {
                TValue* rkb = RKB(i);
                TValue* rkc = RKC(i);
                TValue* ra = &base[RA(i)];
                if (rkb->tt == LUA_TNUMBER && rkc->tt == LUA_TNUMBER) {
                    TValueSetNum(ra, rkb->value.n + rkc->value.n, GetGlobalTaint());
                    DISPATCH();
                } else {
                    DELEGATE_AND_RETURN(0);
                }
            }
            case OP_SUB: {
                TValue* rkb = RKB(i);
                TValue* rkc = RKC(i);
                TValue* ra = &base[RA(i)];
                if (rkb->tt == LUA_TNUMBER && rkc->tt == LUA_TNUMBER) {
                    TValueSetNum(ra, rkb->value.n - rkc->value.n, GetGlobalTaint());
                    DISPATCH();
                } else {
                    DELEGATE_AND_RETURN(0);
                }
            }
            case OP_MUL: {
                TValue* rkb = RKB(i);
                TValue* rkc = RKC(i);
                TValue* ra = &base[RA(i)];
                if (rkb->tt == LUA_TNUMBER && rkc->tt == LUA_TNUMBER) {
                    TValueSetNum(ra, rkb->value.n * rkc->value.n, GetGlobalTaint());
                    DISPATCH();
                } else {
                    DELEGATE_AND_RETURN(0);
                }
            }
            case OP_DIV: {
                TValue* rkb = RKB(i);
                TValue* rkc = RKC(i);
                TValue* ra = &base[RA(i)];
                if (rkb->tt == LUA_TNUMBER && rkc->tt == LUA_TNUMBER) {
                    TValueSetNum(ra, rkb->value.n / rkc->value.n, GetGlobalTaint());
                    DISPATCH();
                } else {
                    DELEGATE_AND_RETURN(0);
                }
            }
            case OP_MOD: {
                TValue* rkb = RKB(i);
                TValue* rkc = RKC(i);
                TValue* ra = &base[RA(i)];
                if (rkb->tt == LUA_TNUMBER && rkc->tt == LUA_TNUMBER) {
                    double d1 = rkb->value.n, d2 = rkc->value.n;
                    TValueSetNum(ra, d1 - floor(d1/d2)*d2, GetGlobalTaint());
                    DISPATCH();
                } else {
                    DELEGATE_AND_RETURN(0);
                }
            }
            case OP_POW: {
                TValue* rkb = RKB(i);
                TValue* rkc = RKC(i);
                TValue* ra = &base[RA(i)];
                if (rkb->tt == LUA_TNUMBER && rkc->tt == LUA_TNUMBER) {
                    TValueSetNum(ra, pow(rkb->value.n, rkc->value.n), GetGlobalTaint());
                    DISPATCH();
                } else {
                    DELEGATE_AND_RETURN(0);
                }
            }
            case OP_UNM: {
                TValue* rb = &base[RB(i)];
                TValue* ra = &base[RA(i)];
                if (rb->tt == LUA_TNUMBER) {
                    TValueSetNum(ra, -rb->value.n, GetGlobalTaint());
                    DISPATCH();
                } else {
                    DELEGATE_AND_RETURN(0);
                }
            }
            case OP_NOT: {
                TValue* rb = &base[RB(i)];
                TValue* ra = &base[RA(i)];
                int isFalse = (rb->tt == LUA_TNIL) || 
                              (rb->tt == LUA_TBOOLEAN && rb->value.b == 0);
                TValueSetBool(ra, isFalse ? 1 : 0, GetGlobalTaint());
                DISPATCH();
            }
            case OP_LEN: {
                DELEGATE_AND_RETURN(0);
            }
            case OP_CONCAT: {
                DELEGATE_AND_RETURN(0);
            }
            case OP_JMP: {
                int sbx = GETARG_sBx(i);
                pc += sbx;
                DISPATCH();
            }
            case OP_EQ: {
                int a = RA(i);
                TValue* rkb = RKB(i);
                TValue* rkc = RKC(i);
                
                bool equal;
                if (rkb->tt != rkc->tt) {
                    equal = false;
                } else if (rkb->tt == LUA_TNUMBER) {
                    equal = (rkb->value.n == rkc->value.n);
                } else if (rkb->tt == LUA_TSTRING) {
                    equal = (rkb->value.gc == rkc->value.gc);
                } else if (rkb->tt == LUA_TBOOLEAN) {
                    equal = (rkb->value.b == rkc->value.b);
                } else if (rkb->tt >= LUA_TTABLE) {
                    DELEGATE_AND_RETURN(0);
                } else {
                    equal = (rkb->value.gc == rkc->value.gc);
                }
                
                if (equal != (a != 0)) {
                    pc++;
                }
                DISPATCH();
            }
            case OP_LT: {
                int a = RA(i);
                TValue* rkb = RKB(i);
                TValue* rkc = RKC(i);
                bool result = false;
                if (rkb->tt == LUA_TNUMBER && rkc->tt == LUA_TNUMBER) {
                    result = (rkb->value.n < rkc->value.n);
                    if (result != (a != 0)) pc++;
                    DISPATCH();
                } else {
                    DELEGATE_AND_RETURN(0);
                }
            }
            case OP_LE: {
                int a = RA(i);
                TValue* rkb = RKB(i);
                TValue* rkc = RKC(i);
                bool result = false;
                if (rkb->tt == LUA_TNUMBER && rkc->tt == LUA_TNUMBER) {
                    result = (rkb->value.n <= rkc->value.n);
                    if (result != (a != 0)) pc++;
                    DISPATCH();
                } else {
                    DELEGATE_AND_RETURN(0);
                }
            }
            case OP_TEST: {
                int a = RA(i);
                int c = RC(i);
                TValue* ra = &base[a];
                
                bool cond;
                switch (ra->tt) {
                    case LUA_TNIL: cond = false; break;
                    case LUA_TBOOLEAN: cond = ra->value.b != 0; break;
                    default: cond = true; break;
                }
                
                if (cond == (c != 0)) {
                    pc++;
                }
                DISPATCH();
            }
            case OP_TESTSET: {
                int a = RA(i);
                int b = RB(i);
                int c = RC(i);
                TValue* rb = &base[b];
                bool cond;
                switch (rb->tt) {
                    case LUA_TNIL: cond = false; break;
                    case LUA_TBOOLEAN: cond = rb->value.b != 0; break;
                    default: cond = true; break;
                }
                if (cond == (c != 0)) {
                    TValueCopy(&base[a], rb);
                } else {
                    pc++;
                }
                DISPATCH();
            }
            case OP_CALL: {
                int a = RA(i);
                int b = RB(i);
                int c = RC(i);
                TValue* ra = &base[a];
                int nresults_val = c - 1;
                
                if (b != 0) {
                    top = ra + b;
                }
                
                *(Instruction**)((char*)L + 0x1C) = pc;
                *(TValue**)((char*)L + 0x0C) = top;
                
                __int64 startTime = g_get_cycles();
                __int64 endTime = startTime;
                
                t_inOptimizedExecution = false;
                int precall_res = g_orig_luaD_precall(L, ra, nresults_val, startTime, &endTime);
                t_inOptimizedExecution = true;
                
                if (precall_res == 0) {
                    // Enter new Lua frame
                    nexeccalls++;
                    ci = *(void**)((char*)L + 0x18);
                    funcSlot = *(TValue**)((char*)ci + 0x04);
                    closure = funcSlot->value.gc;
                    proto = *(void**)((char*)closure + 24);
                    k = *(TValue**)((char*)proto + 12);
                    
                    pc = *(Instruction**)((char*)L + 0x1C);
                    base = *(TValue**)((char*)L + 0x10);
                    top = *(TValue**)((char*)L + 0x0C);
                    
                    t_opcodesRemaining = MAX_OPCODES_PER_SLICE;
                } else if (precall_res == 1) {
                    // C function returned
                    base = *(TValue**)((char*)L + 0x10);
                    top = *(TValue**)((char*)L + 0x0C);
                } else {
                    // Yield or error
                    t_inOptimizedExecution = false;
                    t_currentL = nullptr;
                    return precall_res;
                }
                
                DISPATCH();
            }
            case OP_TAILCALL: {
                DELEGATE_AND_RETURN(0);
            }
            case OP_RETURN: {
                int a = RA(i);
                int b = RB(i);
                TValue* ra = &base[a];
                
                if (b != 0) {
                    top = ra + b - 1;
                    *(TValue**)((char*)L + 0x0C) = top;
                }
                
                void* openupval = *(void**)((char*)L + 104);
                if (openupval) {
                    g_orig_luaF_close(L, base);
                }
                
                *(Instruction**)((char*)L + 0x1C) = pc - 1;
                
                t_inOptimizedExecution = false;
                int poscall_res = g_orig_luaD_poscall(L, ra);
                t_inOptimizedExecution = true;
                
                nexeccalls--;
                if (nexeccalls == 0) {
                    t_inOptimizedExecution = false;
                    t_currentL = nullptr;
                    return poscall_res;
                }
                
                if (poscall_res != 0) {
                    t_inOptimizedExecution = false;
                    t_currentL = nullptr;
                    return poscall_res;
                }
                
                // Continue in caller
                ci = *(void**)((char*)L + 0x18);
                funcSlot = *(TValue**)((char*)ci + 0x04);
                closure = funcSlot->value.gc;
                proto = *(void**)((char*)closure + 24);
                k = *(TValue**)((char*)proto + 12);
                
                base = *(TValue**)((char*)L + 0x10);
                top = *(TValue**)((char*)L + 0x0C);
                pc = *(Instruction**)((char*)L + 0x1C);
                
                t_opcodesRemaining = MAX_OPCODES_PER_SLICE;
                DISPATCH();
            }
            case OP_FORLOOP: {
                int a = RA(i);
                int sbx = GETARG_sBx(i);
                
                if (base[a].tt == LUA_TNUMBER && base[a+1].tt == LUA_TNUMBER && base[a+2].tt == LUA_TNUMBER) {
                    double step = base[a+2].value.n;
                    double limit = base[a+1].value.n;
                    double idx = base[a].value.n + step;
                    
                    base[a].value.n = idx;
                    
                    bool continueLoop;
                    if (step > 0) {
                        continueLoop = (idx <= limit);
                    } else {
                        continueLoop = (idx >= limit);
                    }
                    
                    if (continueLoop) {
                        pc += sbx;
                        TValueCopy(&base[a+3], &base[a]);
                    }
                    DISPATCH();
                } else {
                    DELEGATE_AND_RETURN(0);
                }
            }
            case OP_FORPREP: {
                int a = RA(i);
                int sbx = GETARG_sBx(i);
                
                if (base[a].tt == LUA_TNUMBER && base[a+1].tt == LUA_TNUMBER && base[a+2].tt == LUA_TNUMBER) {
                    base[a].value.n -= base[a+2].value.n;
                    pc += sbx;
                    DISPATCH();
                } else {
                    DELEGATE_AND_RETURN(0);
                }
            }
            case OP_TFORLOOP: {
                DELEGATE_AND_RETURN(0);
            }
            case OP_SETLIST: {
                DELEGATE_AND_RETURN(0);
            }
            case OP_CLOSE: {
                DELEGATE_AND_RETURN(0);
            }
            case OP_CLOSURE: {
                DELEGATE_AND_RETURN(0);
            }
            case OP_VARARG: {
                DELEGATE_AND_RETURN(0);
            }
            default: {
                DELEGATE_AND_RETURN(0);
            }
        }
        
    yield_back:
        *(Instruction**)((char*)L + 0x1C) = pc;
        *(TValue**)((char*)L + 0x0C) = top;
        t_inOptimizedExecution = false;
        t_currentL = nullptr;
        return 0;
        
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ++g_stats.fallbackExecutions;
        t_inOptimizedExecution = false;
        t_currentL = nullptr;
        return g_orig_luaV_execute(L, nexeccalls);
    }
}
#pragma warning(pop)

// Install / Uninstall
bool InstallLuaVMEngine()
{
    g_inlineCache = (ICEntry*)HighTables::Reserve("lua_vm_engine", IC_BYTES);
    if (!g_inlineCache) {
        Log("[VMEngine] NOT installed: the %u KB inline cache could not be "
            "allocated.", (unsigned)(IC_BYTES / 1024));
        return false;
    }

    void* target = (void*)0x00859160;

    unsigned char* p = (unsigned char*)target;
    if (p[0] != 0x55 || p[1] != 0x8B) {
        Log("[VMEngine] BAD PROLOGUE at 0x%08X (expected 55 8B, got %02X %02X)",
            (uintptr_t)target, p[0], p[1]);
        return false;
    }
    
    g_orig_luaV_gettable = (luaV_gettable_fn)0x00857250;
    g_orig_luaV_settable = (luaV_settable_fn)0x008573C0;
    g_orig_luaH_getstr = (luaH_getstr_fn)0x0085C430;
    
    if (MH_CreateHook(target, (void*)Hooked_luaV_execute, (void**)&g_orig_luaV_execute) != MH_OK) {
        Log("[VMEngine] MH_CreateHook FAILED for luaV_execute");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        Log("[VMEngine] MH_EnableHook FAILED for luaV_execute");
        return false;
    }
    

    
    // Initialize caches
    if (g_inlineCache) memset(g_inlineCache, 0, IC_BYTES);
    
    CrashDumper::RegisterFeature("LuaVMEngine");
    CrashDumper::FeatureSetActive("LuaVMEngine", true);
    
    Log("[VMEngine] ACTIVE: Direct-threaded Lua VM interpreter");
    Log("[VMEngine]   - Inline cache: %d sites x %d ways = %d entries",
        IC_TOTAL_SITES, IC_ENTRIES_PER_SITE, IC_TOTAL_SITES * IC_ENTRIES_PER_SITE);
    Log("[VMEngine]   - SSE2 TValue operations enabled");
    Log("[VMEngine]   - Max %d opcodes per execution slice", MAX_OPCODES_PER_SLICE);

    return true;
}

void UninstallLuaVMEngine()
{
    MH_DisableHook((void*)0x00859160);
    MH_RemoveHook((void*)0x00859160);
    
    MH_DisableHook((void*)0x0085C6F0);
    MH_RemoveHook((void*)0x0085C6F0);
    
    LuaVMEngineStats s = g_stats;
    if (s.totalOpcodes > 0) {
        double icRate = (s.icHits + s.icMisses > 0) ? 
            (double)s.icHits / (s.icHits + s.icMisses) * 100.0 : 0.0;
        Log("[VMEngine] Stats: %lld opcodes | %lld IC hits (%.1f%%) | %lld fused | %lld fallbacks",
            s.totalOpcodes, s.icHits, icRate, s.fusedOpcodes, s.fallbackExecutions);
    Log("[VMEngine]   %ld cached nodes checked against the engine's own "
        "luaH_getstr%s. Every hit carries the taint the engine would have "
        "written - the ambient one when the value is clean, the value's own "
        "otherwise - and reports a tainted read of a global the way the engine "
        "does. A hit whose table has rehashed since is dropped rather than "
        "followed.",
        g_icChecked, g_icDead ? " - RETIRED, one disagreed" : "");
    }
    
    CrashDumper::FeatureSetActive("LuaVMEngine", false);
}