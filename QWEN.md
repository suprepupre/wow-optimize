## Qwen Added Memories
- wow_optimize project — WoW 3.3.5a build 12340 optimization DLL (C++/MinHook/mimalloc). User: Aleksander (SUPREMATIST). Communication: Russian preferred. Safety-first: clearly state risks, use crash-isolation test builds. No PQR mentions in public text. Practical results > theory. All changes as proper git workflow (commit/tag/push).

CRITICAL STATE (v3.5.0):
- GetItemInfo cache: ACTIVE (8192-slot DMA)
- GetSpellInfo cache: DISABLED (tested, needs investigation)
- Phase 2 safe hooks: ACTIVE (type, math, tostring, tonumber, string.*, select, rawequal — Lua API based)
- Phase 2 write hooks: PERMANENTLY DISABLED (rawset, insert, remove, next — proven to cause hangs via RawTValue* writes)
- Phase 2 table reads: PERMANENTLY DISABLED (rawget, concat, unpack — proven to cause hangs via RawTValue* writes)
- Lua VM Optimizer: ACTIVE (mimalloc allocator + GC tuning + string table)
- MPQ mmap: DISABLED for public (unsafe on HD/custom clients)
- Large pages "no permission" = NORMAL, not a crash cause
- ElvUI + Armory + DLL = HANGS (GC rate limiting 1/5s + 67M select calls → garbage stall)
- API cache for dynamic units (UnitHealth, UnitPower, etc.) = UNSAFE (breaks semantics)
- UI widget cache = DISABLED (addon regressions)
- GlobalAlloc fast path = DISABLED (crash-on-login)
- Direct Memory Access (TValue* stack reads) = SAFE when used correctly, but RawTValue* stack WRITES cause hangs
