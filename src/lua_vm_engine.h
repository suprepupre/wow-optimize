#pragma once
// ================================================================
// lua_vm_engine.h - Direct-Threaded Lua VM Execution Engine
// ================================================================
// Replaces WoW's switch-based luaV_execute with a direct-threaded
// interpreter that eliminates dispatch overhead, fuses common
// opcode sequences, and implements inline caching.
//
// Performance targets:
//   - 3-5x faster opcode dispatch (no switch/case overhead)
//   - 2-3x faster table lookups (inline cache)
//   - 1.5-2x faster function calls (fused GETGLOBAL+CALL)
//   - 10-20% overall addon FPS improvement
// ================================================================

bool InstallLuaVMEngine();
void UninstallLuaVMEngine();

// Statistics
struct LuaVMEngineStats {
    volatile LONG64 totalOpcodes;
    volatile LONG64 fusedOpcodes;
    volatile LONG64 icHits;
    volatile LONG64 icMisses;
    volatile LONG64 callFastPath;
    volatile LONG64 gettableFastPath;
    volatile LONG64 settableFastPath;
    volatile LONG64 globalCacheHits;
    volatile LONG64 translationsPerformed;
    volatile LONG64 fallbackExecutions;
};

LuaVMEngineStats GetLuaVMEngineStats();