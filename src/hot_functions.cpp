/*
 * memset replacement
 * Target: 0x0040BB80 (1108 callers)
 * void* __cdecl(void* dest, int Val, size_t Size)
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <atomic>
#include <cstring>
#include "MinHook.h"
#include "hot_functions.h"

extern "C" void Log(const char* fmt, ...);

static std::atomic<uint64_t> g_memset_calls{0};
static std::atomic<uint64_t> g_fast_path{0};

typedef void* (__cdecl *memset_t)(void*, int, size_t);
static memset_t g_orig_memset = nullptr;

void* __cdecl Hooked_memset(void* dest, int Val, size_t Size) {
    if (!dest || Size == 0) return dest;
    
    g_memset_calls.fetch_add(1, std::memory_order_relaxed);
    
    if (Size < 16) {
        unsigned char* p = (unsigned char*)dest;
        unsigned char v = (unsigned char)Val;
        for (size_t i = 0; i < Size; i++) {
            p[i] = v;
        }
        return dest;
    }
    
    if (Size < 64) {
        unsigned char* p = (unsigned char*)dest;
        unsigned char v = (unsigned char)Val;
        uint32_t v32 = v | (v << 8) | (v << 16) | (v << 24);
        
        size_t align = ((uintptr_t)p) & 3;
        if (align) {
            size_t fix = 4 - align;
            for (size_t i = 0; i < fix && i < Size; i++) {
                *p++ = v;
            }
            Size -= fix;
        }
        
        uint32_t* p32 = (uint32_t*)p;
        size_t dwords = Size / 4;
        for (size_t i = 0; i < dwords; i++) {
            p32[i] = v32;
        }
        
        size_t remainder = Size % 4;
        p = (unsigned char*)(p32 + dwords);
        for (size_t i = 0; i < remainder; i++) {
            p[i] = v;
        }
        
        return dest;
    }
    
    g_fast_path.fetch_add(1, std::memory_order_relaxed);
    return g_orig_memset(dest, Val, Size);
}

bool InstallHotFunctionOptimizations() {
    void* target = (void*)0x0040BB80;
    
    if (MH_CreateHook(target, (void*)Hooked_memset, (void**)&g_orig_memset) != MH_OK) {
        Log("[FastMemset] Failed to create hook at 0x0040BB80");
        return false;
    }
    
    if (MH_EnableHook(target) != MH_OK) {
        Log("[FastMemset] Failed to enable hook");
        MH_RemoveHook(target);
        return false;
    }
    
    Log("[FastMemset] Installed: memset replacement (1108 callers)");
    return true;
}

void UninstallHotFunctionOptimizations() {
    MH_DisableHook((void*)0x0040BB80);
    MH_RemoveHook((void*)0x0040BB80);
    
    uint64_t calls = g_memset_calls.load(std::memory_order_relaxed);
    uint64_t fast = g_fast_path.load(std::memory_order_relaxed);
    
    if (calls > 0) {
        Log("[FastMemset] Stats: %llu total calls, %llu large-size",
            calls, fast);
    }
}
