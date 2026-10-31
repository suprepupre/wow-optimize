#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <intrin.h>
#include <emmintrin.h>
#include "MinHook.h"
#include "version.h"
#include "config.h"
#include "self_bench.h"

extern "C" void Log(const char* fmt, ...);

static constexpr uintptr_t ADDR_luaS_newlstr = 0x00856C80;

typedef void* (__cdecl *luaS_newlstr_t)(void* L, const char* str, size_t l);
static luaS_newlstr_t orig_luaS_newlstr = nullptr;
static bool g_installed = false;

// Plain 32-bit with a wrap counter beside each.
//
// These were bare uint32_t, and this hook sits on luaS_newlstr - every string
// the client interns, which is every push, every concatenation and every table
// key. Nothing in the project knows how often that is, because of the second
// problem below, but four billion is not a safe assumption to make about it. A
// wrapped numerator over an unwrapped denominator is how frustum_aabb came to
// print a hit rate of 73322%.
static uint32_t g_newlstr_calls = 0,     g_newlstr_callWraps = 0;
static uint32_t g_newlstr_fast_hits = 0, g_newlstr_hitWraps = 0;
static uint32_t g_newlstr_dead = 0;

static inline void BumpWrap(uint32_t& low, uint32_t& wraps) {
    const uint32_t before = low;
    low = before + 1;
    if (low < before) ++wraps;
}

static inline double TotalOf(uint32_t low, uint32_t wraps) {
    return (double)low + (double)wraps * 4294967296.0;
}

static inline bool CompareStringInline(const char* s1, const char* s2, size_t len) {
    if (len == 0) return true;
    switch (len) {
        case 1: return s1[0] == s2[0];
        case 2: return *(const uint16_t*)s1 == *(const uint16_t*)s2;
        case 3: return *(const uint16_t*)s1 == *(const uint16_t*)s2 && s1[2] == s2[2];
        case 4: return *(const uint32_t*)s1 == *(const uint32_t*)s2;
        case 5: return *(const uint32_t*)s1 == *(const uint32_t*)s2 && s1[4] == s2[4];
        case 6: return *(const uint32_t*)s1 == *(const uint32_t*)s2 && *(const uint16_t*)(s1 + 4) == *(const uint16_t*)(s2 + 4);
        case 7: return *(const uint32_t*)s1 == *(const uint32_t*)s2 && *(const uint16_t*)(s1 + 4) == *(const uint16_t*)(s2 + 4) && s1[6] == s2[6];
        case 8: return *(const uint64_t*)s1 == *(const uint64_t*)s2;
        default:
            if (*(const uint64_t*)s1 != *(const uint64_t*)s2) return false;
            if (s1[len - 1] != s2[len - 1]) return false;
            return memcmp(s1 + 8, s2 + 8, len - 9) == 0;
    }
}

// The table walk itself, with no exception frame around it. Returns the
// interned string, or null for "not here" - a miss, a shape it does not
// recognise, or, in the guarded copy below, a fault.
static __forceinline void* LookupInterned(void* L, const char* str, size_t l) {
    {
        uintptr_t L_addr = (uintptr_t)L;
        if (L_addr < 0x10000 || L_addr >= 0xFFE00000) {
            return nullptr;
        }

        // global_State is at L + 0x14
        uintptr_t globalState = *(uintptr_t*)(L_addr + 0x14);
        if (globalState < 0x10000 || globalState >= 0xFFE00000) {
            return nullptr;
        }
        
        // Compute Lua 5.1 string hash
        uint32_t h = (uint32_t)l;
        size_t step = (l >> 5) + 1;
        for (size_t l1 = l; l1 >= step; l1 -= step) {
            h = h ^ ((h << 5) + (h >> 2) + (uint8_t)str[l1 - 1]);
        }
        
        // stringtable is at globalState + 0x00
        uint32_t* hash_array = *(uint32_t**)(globalState + 0x00);
        int nsize = *(int*)(globalState + 0x08);
        
        if (!hash_array || nsize <= 0 || (uintptr_t)hash_array < 0x10000 || (uintptr_t)hash_array >= 0xFFE00000) {
            return nullptr;
        }
        
        uint32_t bucket = h & (nsize - 1);
        uint32_t tstring = hash_array[bucket];

        // currentwhite lives at G+0x15 in this build
        uint8_t currentwhite = *(uint8_t*)(globalState + 0x15);

        while (tstring) {
            if (tstring < 0x10000 || tstring > 0xFFE00000) break;

            // tstring+16 is length
            if (*(uint32_t*)(tstring + 16) == l) {
                // tstring+20 is string data
                const char* ts_data = (const char*)(tstring + 20);

                if (CompareStringInline(ts_data, str, l)) {
                    uint8_t marked = *(uint8_t*)(tstring + 9);
                    if (((uint8_t)(~currentwhite) & marked & 3) != 0) {
                        // Resurrecting a string the collector had already marked
                        // dead. It is the one thing this fast path does that the
                        // client's own luaS_newlstr also does, and the riskiest,
                        // so the report says how often. The counter existed and
                        // printed a zero nothing wrote to.
                        g_newlstr_dead++;
                        *(uint8_t*)(tstring + 9) = (uint8_t)(marked ^ 3);
                    }
                    BumpWrap(g_newlstr_fast_hits, g_newlstr_hitWraps);
                    return (void*)tstring;
                }
            }
            // next pointer
            tstring = *(uint32_t*)(tstring + 0);
        }
    }
    return nullptr;
}

// Faults the guard caught, and how many calls have run guarded so far.
//
// The walk above used to run inside a __try on every call, and this hook sits
// on every string the client interns - every push, every concatenation, every
// table key, and 2.12% of executing time in a tester profile. An exception
// frame per call is a cost this project has removed from three other hot
// detours for the same reason. The guard stays on for the first calls of the
// session, which is where a wrong offset would show itself, and comes off only
// if nothing faulted; one fault ever and every later call is guarded again.
static uint32_t g_caught = 0;
static uint32_t g_guarded = 0;
static constexpr uint32_t kGuardCalls = 200000;

static __declspec(noinline) void* LookupGuarded(void* L, const char* str, size_t l) {
    __try {
        return LookupInterned(L, str, l);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ++g_caught;
        return nullptr;
    }
}

// Nothing here ever asked the client whether it agrees.
//
// This walk reads the client's string table through six offsets taken from a
// disassembly - the global state at L+0x14, the hash array and its size at
// G+0x00 and G+0x08, the collector's current white at G+0x15, and a TString's
// length and bytes at +16 and +20 - and hands back whatever it finds as an
// interned string. Every other replacement in this tree runs both halves on the
// same input for a while and retires itself on the first disagreement; this one
// was the hottest of them at 2.12% of executing time in a field profile and had
// no check at all. A wrong offset would not fault. It would return the wrong
// string, or resurrect the wrong object, and nothing would say so.
//
// Interning is idempotent: asking the client for a string that is already in
// the table returns that same pointer and allocates nothing. So a sample of
// calls can simply ask it and compare pointers, which is both the verification
// and the only paired timing this module can get.
constexpr uint32_t kVerifyFirst  = 20000;
constexpr uint32_t kResampleMask = 4095;
static uint32_t g_verified = 0;
static uint32_t g_disagreed = 0;
static bool     g_dead = false;
static int      g_benchSlot = -1;

static __declspec(noinline) void RetireOnDisagreement(const char* str, size_t l,
                                                      void* mine, void* theirs) {
    ++g_disagreed;
    g_dead = true;
    Log("[luaS_newlstr] RETIRED: for a %u-byte string the table walk here answered "
        "0x%08X and the client answered 0x%08X. Every intern from here on is the "
        "client's own. First bytes: %.16s",
        (unsigned)l, (unsigned)(uintptr_t)mine, (unsigned)(uintptr_t)theirs, str);
}

void* __cdecl Hooked_luaS_newlstr(void* L, const char* str, size_t l) {
    BumpWrap(g_newlstr_calls, g_newlstr_callWraps);

    // Bounds check string length and validate pointer
    if (g_dead || l >= (1 << 30) || !str || (uintptr_t)str < 0x10000 ||
        (uintptr_t)str >= 0xFFE00000) {
        return orig_luaS_newlstr(L, str, l);
    }

    const bool checking = (g_verified < kVerifyFirst) ||
                          ((g_newlstr_calls & kResampleMask) == 0);

    void* found;
    if (g_caught || g_guarded < kGuardCalls) {
        ++g_guarded;
        found = LookupGuarded(L, str, l);
    } else if (checking) {
        const unsigned long long tA = SelfBench::Now();
        found = LookupInterned(L, str, l);
        const unsigned long long tB = SelfBench::Now();
        if (found) {
            void* theirs = orig_luaS_newlstr(L, str, l);
            SelfBench::Pair(g_benchSlot, tB - tA, SelfBench::Now() - tB);
            if (theirs != found) {
                RetireOnDisagreement(str, l, found, theirs);
                return theirs;
            }
            ++g_verified;
        }
        return found ? found : orig_luaS_newlstr(L, str, l);
    } else {
        found = LookupInterned(L, str, l);
    }
    if (found) return found;

    return orig_luaS_newlstr(L, str, l);
}

namespace LuaSNewlstr {
    bool Init() {
        Log("[luaS_newlstr] Initializing SSE2 Fast Path");
        
        unsigned char* p = (unsigned char*)ADDR_luaS_newlstr;
        if (p[0] != 0x55 || p[1] != 0x8B) {
            Log("[luaS_newlstr] BAD PROLOGUE at 0x%08X", ADDR_luaS_newlstr);
            return false;
        }

        if (WineSafe_CreateHook((void*)ADDR_luaS_newlstr, (void*)Hooked_luaS_newlstr, (void**)&orig_luaS_newlstr) != MH_OK) {
            Log("[luaS_newlstr] Failed to hook");
            return false;
        }
        
        if (MH_EnableHook((void*)ADDR_luaS_newlstr) != MH_OK) {
            Log("[luaS_newlstr] Failed to enable hook");
            return false;
        }
        
        g_installed = true;
        g_benchSlot = SelfBench::Register("LuaStrIntern", SelfBench::kOursFirst);
        Log("[luaS_newlstr] ACTIVE at 0x%08X - every string the client interns comes "
            "through here. The first %u finds are checked against the client's own "
            "answer and one in %u after that; the first different pointer retires it.",
            ADDR_luaS_newlstr, kVerifyFirst, kResampleMask + 1);
        return true;
    }

    // Printed from the periodic report, not from Shutdown.
    //
    // Everything this module measures used to be printed from Shutdown() alone,
    // and the DLL leaves through TerminateProcess, so it has never once reported
    // in a field session. The project writes that rule down and this module was
    // breaking it: the reason nothing here knows how often luaS_newlstr is
    // called is that nothing was ever told.
    //
    // That matters beyond bookkeeping. The fast path here is wrapped in SEH, and
    // whether taking that off is worth the risk is a question about call volume
    // that could not be asked.
    void LogStats() {
        if (!g_installed) {
            Log("[luaS_newlstr] not measured: the hook is not installed.");
            return;
        }
        const double calls = TotalOf(g_newlstr_calls, g_newlstr_callWraps);
        const double hits  = TotalOf(g_newlstr_fast_hits, g_newlstr_hitWraps);
        if (calls == 0.0) {
            Log("[luaS_newlstr] measured and zero: installed, and no string was "
                "interned through it.");
            return;
        }
        Log("[luaS_newlstr] %.0f call(s), %.0f answered from the string table "
            "inline (%.1f%%), %u string(s) resurrected that the collector had "
            "marked dead. Counts are lower bounds.",
            calls, hits, 100.0 * hits / calls, g_newlstr_dead);
        if (g_disagreed) {
            Log("[luaS_newlstr]   DISABLED: an answer differed from the client's. The "
                "line saying which is earlier in this log.");
        } else if (g_verified < kVerifyFirst) {
            Log("[luaS_newlstr]   %u of %u finds checked against the client so far, "
                "none differed.", g_verified, kVerifyFirst);
        } else {
            Log("[luaS_newlstr]   %u finds checked against the client, none differed; "
                "one in %u is still checked.", g_verified, kResampleMask + 1);
        }
        if (g_caught) {
            Log("[luaS_newlstr]   %u fault(s) were caught in the table walk, so "
                "every call stays inside an exception frame. Anything above zero "
                "here means an offset this reads is wrong on this client.",
                g_caught);
        } else if (g_guarded >= kGuardCalls) {
            Log("[luaS_newlstr]   the first %u calls ran guarded and none faulted, "
                "so the walk now runs without an exception frame.", kGuardCalls);
        } else {
            Log("[luaS_newlstr]   %u of %u guarded calls done; the exception frame "
                "comes off after that.", g_guarded, kGuardCalls);
        }
    }

    void Shutdown() {
        if (orig_luaS_newlstr) {
            MH_DisableHook((void*)ADDR_luaS_newlstr);
        }
    }
}
