#include "config.h"
#include <windows.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>

extern "C" void Log(const char* fmt, ...);

namespace Config {
    Settings g_settings;

    // Which file the settings above actually came from. A bug report is only as
    // good as knowing what was switched on, and twice now a log and the ini sent
    // with it disagreed - once because a launcher button had overridden a switch,
    // once with no explanation available at all, because nothing recorded where
    // the DLL had read from or what it concluded.
    static std::string g_loadedFrom;

    // Set when the config was relocated during this run. Reported by DumpToLog,
    // because Load() happens before the log file is open.
    static const char* g_migrationNote = nullptr;

// Generated from the reads in Load(): every boolean setting, the ini section and
// key it comes from, and the field it lands in.
struct BoolSetting {
    const char*   section;
    const char*   key;
    bool Settings::* field;
};

static const BoolSetting kBoolSettings[] = {
    { "General", "SleepPrecision", &Settings::OptSleepPrecision },
    { "General", "SessionLogs", &Settings::OptSessionLogs },
    { "UI_Lua", "LuaStackFast", &Settings::OptLuaStackFast },
    { "Graphics_Sound", "QualityGovernor", &Settings::OptQualityGovernor },
    { "General", "MemoryPressure", &Settings::OptMemoryPressure },
    { "General", "HeapCompactor", &Settings::OptHeapCompactor },
    { "General", "DefragLf", &Settings::OptDefragLf },
    { "General", "VulkanDXVK", &Settings::OptVulkanDXVK },
    { "General", "TimingFix", &Settings::OptTimingFix },
    { "General", "CvarNullGuard", &Settings::OptCvarNullGuard },
    { "General", "DeviceCbGuard", &Settings::OptDeviceCbGuard },
    { "General", "WowOptHooks", &Settings::OptWowOptHooks },
    { "General", "WowPerfHooks", &Settings::OptWowPerfHooks },
    { "General", "WowExtendedHooks", &Settings::OptWowExtendedHooks },
    { "General", "WowSubsystemHooks", &Settings::OptWowSubsystemHooks },
    { "General", "LockTuning", &Settings::OptLockTuning },
    { "General", "AsyncMpqIo", &Settings::OptAsyncMpqIo },
    { "General", "ThreadIdCache", &Settings::OptThreadIdCache },
    { "General", "PriorityGuard", &Settings::OptPriorityGuard },
    { "UI_Lua", "LuaVmOpt", &Settings::OptLuaVmOpt },
    { "UI_Lua", "LuaGcManual", &Settings::OptLuaGcManual },
    { "Graphics_Sound", "D3d9StateManager", &Settings::OptD3d9StateManager },
    { "UI_Lua", "LayoutRelinkFast", &Settings::OptLayoutRelinkFast },
    { "General", "TimingCvarPin", &Settings::OptTimingCvarPin },
    { "General", "FrameLimiter", &Settings::OptFrameLimiter },
    { "General", "ObjVisCache", &Settings::OptObjVisCache },
    { "General", "OomGovernor", &Settings::OptOomGovernor },
    { "General", "HardwareCursor", &Settings::OptHardwareCursor },
    { "General", "SamplingProfiler", &Settings::OptSamplingProfiler },
    { "General", "MimallocLarge", &Settings::OptMimallocLarge },
    { "General", "VaArena", &Settings::OptVaArena },
    { "General", "CompatMode", &Settings::OptCompatMode },
    { "UI_Lua", "UIFrameBatch", &Settings::OptUIFrameBatch },
    { "UI_Lua", "AddonDispatcher", &Settings::OptAddonDispatcher },
    { "UI_Lua", "UIFrameAccessorFast", &Settings::OptUIFrameAccessorFast },
    { "UI_Lua", "FontMetricsFast", &Settings::OptFontMetricsFast },
    { "UI_Lua", "ModuleHandleCache", &Settings::OptModuleHandleCache },
    { "UI_Lua", "FrameScriptDispatch", &Settings::OptFrameScriptDispatch },
    { "UI_Lua", "LuaNumConvFast", &Settings::OptLuaNumConvFast },
    { "UI_Lua", "LuaOpcache", &Settings::OptLuaOpcache },
    { "UI_Lua", "LuaOpcacheTables", &Settings::OptLuaOpcacheTables },
    { "UI_Lua", "LuaOpcacheStrings", &Settings::OptLuaOpcacheStrings },
    { "UI_Lua", "LuaOpcacheWrites", &Settings::OptLuaOpcacheWrites },
    { "UI_Lua", "LuaOpcacheReads", &Settings::OptLuaOpcacheReads },
    { "UI_Lua", "LuaGcCoalesce", &Settings::OptLuaGcCoalesce },
    { "UI_Lua", "LuaGetTimeFast", &Settings::OptLuaGetTimeFast },
    // AsyncTexLoader and MipBiasGovernor are read from Graphics_Sound because
    // that is the section the launcher writes them to. They used to be read from
    // UI_Lua, which the launcher never writes for these two keys, so the switch
    // was inert: whatever you set, the DLL read the absent-key default of off and
    // neither feature could be turned on by anyone.
    { "Graphics_Sound", "AsyncTexLoader", &Settings::OptAsyncTexLoader },
    { "UI_Lua", "AsyncTerrainLoader", &Settings::OptAsyncTerrainLoader },
    { "UI_Lua", "RcuObjMgr", &Settings::OptRcuObjMgr },
    { "Graphics_Sound", "MipBiasGovernor", &Settings::OptMipBiasGovernor },
    { "Combat_Net", "CombatLogLeakFix", &Settings::OptCombatLogLeakFix },
    { "Combat_Net", "CombatLogParser", &Settings::OptCombatLogParser },
    { "Combat_Net", "CombatLogIncremental", &Settings::OptCombatLogIncremental },
    { "Combat_Net", "EventCoalescer", &Settings::OptEventCoalescer },
    { "Combat_Net", "SavedVarsAsync", &Settings::OptSavedVarsAsync },
    { "Combat_Net", "SavedVarsPretoken", &Settings::OptSavedVarsPretoken },
    { "Combat_Net", "UnitAuraFast", &Settings::OptUnitAuraFast },
    { "Combat_Net", "NetworkGuidSse2", &Settings::OptNetworkGuidSse2 },
    { "Combat_Net", "ApiCache", &Settings::OptApiCache },
    { "Combat_Net", "GuidLookupCache", &Settings::OptGuidLookupCache },
    { "Combat_Net", "PacketOffload", &Settings::OptPacketOffload },
    { "Combat_Net", "NameplateMT", &Settings::OptNameplateMT },
    { "Graphics_Sound", "FastMemsetOpt", &Settings::OptFastMemsetOpt },
    { "UI_Lua", "FastStrnicmpOpt", &Settings::OptFastStrnicmpOpt },
    { "UI_Lua", "LuaSNewLstrFast", &Settings::OptLuaSNewLstrFast },
    { "Graphics_Sound", "StrStrSse2", &Settings::OptStrStrSse2 },
    { "Graphics_Sound", "StrCatFast", &Settings::OptStrCatFast },
    { "Graphics_Sound", "SoundMixerOpt", &Settings::OptSoundMixerOpt },
    { "Graphics_Sound", "AudioDecodeMt", &Settings::OptAudioDecodeMt },
    { "Graphics_Sound", "DbcLookupCache", &Settings::OptDbcLookupCache },
    { "General", "FileIoHooks", &Settings::OptFileIoHooks },
    { "General", "TerrainPrefetch", &Settings::OptTerrainPrefetch },
    { "Graphics_Sound", "TickListPrefetch", &Settings::OptTickListPrefetch },
    { "UI_Lua", "LuaGcStockPace", &Settings::OptLuaGcStockPace },
    { "UI_Lua", "LuaTableCensus", &Settings::OptLuaTableCensus },
    { "UI_Lua", "UiScriptHandlerCache", &Settings::OptUiScriptHandlerCache },
    { "UI_Lua", "UnitApiFastPath", &Settings::OptUnitApiFastPath },
    { "UI_Lua", "LuaTypeFast", &Settings::OptLuaTypeFast },
    { "General", "Win32ApiCaches", &Settings::OptWin32ApiCaches },
    { "General", "DebugApiHooks", &Settings::OptDebugApiHooks },
    { "General", "LockSpinHooks", &Settings::OptLockSpinHooks },
    { "UI_Lua", "LuaAddonProfile", &Settings::OptLuaAddonProfile },
    { "General", "CpuTopology", &Settings::OptCpuTopology },
    { "General", "PinMainThread", &Settings::OptPinMainThread },
    { "UI_Lua", "LuaMemPoolFast", &Settings::OptLuaMemPoolFast },
    { "Graphics_Sound", "VertexFmtInline", &Settings::OptVertexFmtInline },
    { "General", "ObjMgrFindFast", &Settings::OptObjMgrFindFast },
    { "Graphics_Sound", "QuatLerpSse2", &Settings::OptQuatLerpSse2 },
    { "UI_Lua", "LuaProtoCache", &Settings::OptLuaProtoCache },
    { "UI_Lua", "LuaThisFast", &Settings::OptLuaThisFast },
    { "Graphics_Sound", "AnimLod", &Settings::OptAnimLod },
    { "Graphics_Sound", "CollisionOutcode", &Settings::OptCollisionOutcode },
    { "Graphics_Sound", "AabbOverlap", &Settings::OptAabbOverlap },
    { "Graphics_Sound", "AnimQuatUnpack", &Settings::OptAnimQuatUnpack },
    { "UI_Lua", "LuaPoolFast", &Settings::OptLuaPoolFast },
    { "Graphics_Sound", "AnimVec3Track", &Settings::OptAnimVec3Track },
    { "Graphics_Sound", "M2SortKey", &Settings::OptM2SortKey },
    { "Graphics_Sound", "FrustumAabb", &Settings::OptFrustumAabb },
    { "Graphics_Sound", "SegmentAabb", &Settings::OptSegmentAabb },
    { "UI_Lua", "LuaHGetDispatch", &Settings::OptLuaHGetDispatch },
    { "Graphics_Sound", "WorldStateCoalesce", &Settings::OptWorldStateCoalesce },
    { "Graphics_Sound", "D3d9RenderThread", &Settings::OptD3d9RenderThread },
    { "Combat_Net", "CombatLogFilter", &Settings::OptCombatLogFilter },
    { "Graphics_Sound", "SoundVolumeLimit", &Settings::OptSoundVolumeLimit },
    { "Graphics_Sound", "TerrainHeightCache", &Settings::OptTerrainHeightCache },
    { "Graphics_Sound", "TextureUnloadDelay", &Settings::OptTextureUnloadDelay },
    { "Graphics_Sound", "M2MatrixSimd", &Settings::OptM2MatrixSimd },
    { "General", "MpqAsyncDecompress", &Settings::OptMpqAsyncDecompress },
    { "Graphics_Sound", "SimdMatrixTransform", &Settings::OptSimdMatrixTransform },
    { "Graphics_Sound", "SpellEffectCulling", &Settings::OptSpellEffectCulling },
    { "Graphics_Sound", "RenderNullGuard", &Settings::OptRenderNullGuard },
    { "Graphics_Sound", "StrncmpSse2", &Settings::OptStrncmpSse2 },
    { "UI_Lua", "AddonProfiler", &Settings::OptAddonProfiler },
    { "UI_Lua", "LuaCompileCensus", &Settings::OptLuaCompileCensus },
    { "Graphics_Sound", "ShadowStateProbe", &Settings::OptShadowStateProbe },
    { "Graphics_Sound", "QuatNormalizeSse2", &Settings::OptQuatNormalizeSse2 },
    { "Graphics_Sound", "MatrixMultiplySse2", &Settings::OptMatrixMultiplySse2 },
    { "Graphics_Sound", "DrawCensus", &Settings::OptDrawCensus },
    { "UI_Lua", "LuaAllocCensus", &Settings::OptLuaAllocCensus },
    { "Graphics_Sound", "AnimCensus", &Settings::OptAnimCensus },
    { "Graphics_Sound", "HorizonOcclusionSse2", &Settings::OptHorizonOcclusionSse2 },
    { "Combat_Net", "NetDiag", &Settings::OptNetDiag },
    { "General", "CrtFreeMsize", &Settings::OptCrtFreeMsize },
    { "General", "CrtAllocMsize", &Settings::OptCrtAllocMsize },
    { "General", "CrtMimalloc", &Settings::OptCrtMimalloc },
    { "General", "MouseClipRelease", &Settings::OptMouseClipRelease },
    { "General", "SavedVarsBackup", &Settings::OptSavedVarsBackup },
    { "Graphics_Sound", "SoundCoalescer", &Settings::OptSoundCoalescer },
    { "General", "VertexBufferPrealloc", &Settings::OptVertexBufferPrealloc },
};

static const int kBoolSettingCount = (int)(sizeof(kBoolSettings) / sizeof(kBoolSettings[0]));

    static void ReportDuplicateKeys(const char* path);

    void DumpToLog() {
        Log("[Config] Read from: %s", g_loadedFrom.empty() ? "(none)" : g_loadedFrom.c_str());
        if (g_migrationNote) Log("[Config]   (%s)", g_migrationNote);

        // This used to print the ini file and call it "Effective contents". It was
        // neither effective nor complete: a setting the launcher never wrote is
        // absent from the file, so it silently took its compiled default and left
        // no trace in the log at all. Four tester logs were read on the assumption
        // that a key's absence meant the feature was not in play, when it actually
        // meant the feature was running on a default nobody had chosen.
        // SavedVarsPretoken - which by itself gates the whole Win32 file-hook suite
        // and the CDataStore batcher - was invisible in every one of them.
        //
        // So report the resolved value of every setting and say where it came from.
        // Present-and-on, present-and-off, and absent-so-defaulted are three
        // different states, and the log has to keep them apart.
        const char* path = g_loadedFrom.c_str();
        bool haveFile = !g_loadedFrom.empty() &&
                        GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
        if (!haveFile) {
            Log("[Config] No ini file was read - every value below is a default.");
        }

        Log("[Config] Resolved settings (%d); \"default\" means absent from the file:",
            kBoolSettingCount);

        int fromFile = 0, defaulted = 0;
        for (int i = 0; i < kBoolSettingCount; i++) {
            const BoolSetting& e = kBoolSettings[i];
            bool value = g_settings.*(e.field);

            // Asking twice with opposite defaults is how absence is detected: a key
            // that is present returns its own value both times.
            bool present = false;
            if (haveFile) {
                present = GetPrivateProfileIntA(e.section, e.key, 0, path) ==
                          GetPrivateProfileIntA(e.section, e.key, 1, path);
            }
            if (present) fromFile++; else defaulted++;

            Log("[Config]   [%s] %s=%d%s", e.section, e.key, value ? 1 : 0,
                present ? "" : "   (default - not in file)");
        }

        Log("[Config]   [General] SleepPrecisionValue=%d", g_settings.SleepPrecisionValue);
        Log("[Config]   [General] SessionLogsToKeep=%d", g_settings.SessionLogsToKeep);
        Log("[Config] %d set in the file, %d left at defaults.", fromFile, defaulted);

        if (haveFile) ReportDuplicateKeys(path);
    }

    // A key written twice in one section is not a hypothetical. A tester's ini
    // carried LuaGcManual=1 near the top of [UI_Lua] and LuaGcManual=0 at the
    // bottom, and spent a session believing the collector was on manual when
    // GetPrivateProfileInt had answered from the first one. Everything above
    // reports the resolved value correctly and still cannot show that, because
    // the losing line never reaches this code.
    //
    // Reads the file directly rather than through the profile API, which is what
    // hides the duplicate in the first place.
    static void ReportDuplicateKeys(const char* path) {
        FILE* f = nullptr;
        if (fopen_s(&f, path, "rb") != 0 || !f) return;

        struct Seen { std::string section; std::string key; int line; };
        std::vector<Seen> seen;
        std::string section;
        char buf[512];
        int lineNo = 0, reported = 0;

        while (fgets(buf, sizeof(buf), f)) {
            lineNo++;
            char* s = buf;
            while (*s == ' ' || *s == '\t') s++;
            if (*s == ';' || *s == '#' || *s == '\r' || *s == '\n' || *s == 0) continue;

            if (*s == '[') {
                char* end = strchr(s, ']');
                if (end) section.assign(s + 1, end - s - 1);
                continue;
            }

            char* eq = strchr(s, '=');
            if (!eq) continue;
            std::string key(s, eq - s);
            while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
            if (key.empty()) continue;

            bool dup = false;
            for (size_t i = 0; i < seen.size(); i++) {
                if (seen[i].section == section && _stricmp(seen[i].key.c_str(), key.c_str()) == 0) {
                    if (reported == 0) {
                        Log("[Config] This file sets the same key more than once. Windows "
                            "answers with the first one it finds, so the later line does "
                            "nothing and a setting you believe you changed has not "
                            "changed:");
                    }
                    Log("[Config]   [%s] %s - line %d wins, line %d is ignored",
                        section.c_str(), key.c_str(), seen[i].line, lineNo);
                    reported++;
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                Seen e; e.section = section; e.key = key; e.line = lineNo;
                seen.push_back(e);
            }
        }
        fclose(f);
    }

    static bool FileExists(const std::string& p) {
        return GetFileAttributesA(p.c_str()) != INVALID_FILE_ATTRIBUTES;
    }

    static bool DirExists(const std::string& p) {
        DWORD a = GetFileAttributesA(p.c_str());
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
    }

    // The folder Wow.exe lives in, with a trailing separator.
    static std::string GameRoot() {
        char path[MAX_PATH];
        DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return std::string();
        std::string s(path);
        size_t lastSlash = s.find_last_of("\\/");
        return (lastSlash == std::string::npos) ? std::string()
                                                : s.substr(0, lastSlash + 1);
    }

    // Where wow_opt.ini lives, in the order the file is looked for:
    //
    //   1. WOW_OPT_CONFIG, so wow_loader can point each client of a multi-client
    //      setup at its own profile. Only honoured if the file is really there.
    //   2. WTF\wow_opt.ini, next to Config.wtf and the account folders.
    //   3. wow_opt.ini beside Wow.exe, which is where it has always lived.
    //
    // WTF is the folder people carry across when they replace a client, so a
    // config that lives there survives a reinstall and one in the root does not.
    // That is the reason for the move; tidiness on its own would not be worth it.
    //
    // Nothing is ever silently abandoned. An existing root config is copied into
    // WTF the first time this runs and the old file renamed to wow_opt.ini.moved,
    // because the alternative - looking in the new place, finding nothing and
    // writing a fresh default - would reset everyone's settings at once and read,
    // from the outside, exactly like features switching themselves off.
    static std::string ResolveIniPath() {
        char envPath[MAX_PATH];
        DWORD envLen = GetEnvironmentVariableA("WOW_OPT_CONFIG", envPath, MAX_PATH);
        if (envLen > 0 && envLen < MAX_PATH && FileExists(envPath)) {
            return std::string(envPath);
        }

        std::string root = GameRoot();
        if (root.empty()) return "wow_opt.ini";

        std::string wtfDir  = root + "WTF";
        std::string wtfPath = wtfDir + "\\wow_opt.ini";
        std::string rootPath = root + "wow_opt.ini";

        if (FileExists(wtfPath)) return wtfPath;

        if (FileExists(rootPath)) {
            // Migrate, but only when there is a WTF folder to migrate into and
            // the copy actually succeeds. If either fails, keep using the file
            // where it already is rather than losing the player's settings.
            if (DirExists(wtfDir) && CopyFileA(rootPath.c_str(), wtfPath.c_str(), TRUE)) {
                std::string moved = rootPath + ".moved";
                DeleteFileA(moved.c_str());
                if (!MoveFileA(rootPath.c_str(), moved.c_str())) {
                    // Could not rename the original. Two files that both look
                    // live is worse than not moving at all, so undo the copy.
                    DeleteFileA(wtfPath.c_str());
                    return rootPath;
                }
                // Not Log() - Load() runs before LogOpen(), so anything printed
                // from here goes nowhere. DumpToLog reports it once logging is up,
                // which is the same reason g_loadedFrom exists.
                g_migrationNote = "moved here from the game folder on this run; "
                                  "the old copy is now wow_opt.ini.moved";
                return wtfPath;
            }
            return rootPath;
        }

        // Nothing anywhere: create it in WTF when that folder exists, otherwise
        // fall back to the root so a client without a WTF folder still works.
        return DirExists(wtfDir) ? wtfPath : rootPath;
    }

    void Load() {
        std::string iniPath = ResolveIniPath();

        // Check if the file exists, if not, write the default template
        DWORD attribs = GetFileAttributesA(iniPath.c_str());
        if (attribs == INVALID_FILE_ATTRIBUTES) {
            // Write default ini template with safe defaults (mostly 0 except core/stable guards)
            // General
            WritePrivateProfileStringA("General", "SleepPrecision", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "SleepPrecisionValue", "8", iniPath.c_str());
            WritePrivateProfileStringA("General", "SessionLogs", "1", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LuaStackFast", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "QualityGovernor", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "SessionLogsToKeep", "10", iniPath.c_str());
            WritePrivateProfileStringA("General", "MemoryPressure", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "HeapCompactor", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "DefragLf", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "VulkanDXVK", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "TimingFix", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "CvarNullGuard", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "DeviceCbGuard", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "WowOptHooks", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "WowPerfHooks", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "WowExtendedHooks", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "WowSubsystemHooks", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "LockTuning", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "AsyncMpqIo", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "ThreadIdCache", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "PriorityGuard", "1", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LuaVmOpt", "1", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LuaGcManual", "1", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "D3d9StateManager", "1", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LayoutRelinkFast", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "FrameLimiter", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "ObjVisCache", "1", iniPath.c_str());
            WritePrivateProfileStringA("General", "DbcPreload", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "OomGovernor", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "HardwareCursor", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "SamplingProfiler", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "MimallocLarge", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "VaArena", "0", iniPath.c_str());  // EXPERIMENTAL, opt-in
            WritePrivateProfileStringA("General", "CompatMode", "0", iniPath.c_str());  // set 1 on VMs/HyperV if the game can't connect


            // UI & Lua
            WritePrivateProfileStringA("UI_Lua", "UIFrameBatch", "0", iniPath.c_str());  // #36: artifacting/flicker — off by default
            WritePrivateProfileStringA("UI_Lua", "AddonDispatcher", "0", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "UIFrameAccessorFast", "0", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "FontMetricsFast", "0", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "ModuleHandleCache", "0", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "FrameScriptDispatch", "0", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LuaNumConvFast", "0", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LuaOpcache", "0", iniPath.c_str());  // #37: slow loads + Lua errors — off by default
            WritePrivateProfileStringA("UI_Lua", "LuaOpcacheTables", "1", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LuaOpcacheStrings", "1", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LuaOpcacheWrites", "1", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LuaOpcacheReads", "1", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LuaGcCoalesce", "0", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LuaJIT", "0", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "LuaGetTimeFast", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "AsyncTexLoader", "0", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "AsyncTerrainLoader", "0", iniPath.c_str());
            WritePrivateProfileStringA("UI_Lua", "RcuObjMgr", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "MipBiasGovernor", "0", iniPath.c_str());

            // Combat & Network
            WritePrivateProfileStringA("Combat_Net", "CombatLogLeakFix", "1", iniPath.c_str());
            WritePrivateProfileStringA("Combat_Net", "CombatLogParser", "0", iniPath.c_str());
            WritePrivateProfileStringA("Combat_Net", "CombatLogIncremental", "0", iniPath.c_str());
            WritePrivateProfileStringA("Combat_Net", "EventCoalescer", "0", iniPath.c_str());  // #42: hides buffs/countdowns — off by default
            WritePrivateProfileStringA("Combat_Net", "SavedVarsSerializer", "0", iniPath.c_str());
            WritePrivateProfileStringA("Combat_Net", "SavedVarsAsync", "0", iniPath.c_str());
            WritePrivateProfileStringA("Combat_Net", "SavedVarsPretoken", "0", iniPath.c_str());
            WritePrivateProfileStringA("Combat_Net", "UnitAuraFast", "0", iniPath.c_str());
            WritePrivateProfileStringA("Combat_Net", "NetworkGuidSse2", "0", iniPath.c_str());
            WritePrivateProfileStringA("Combat_Net", "PacketOffload", "0", iniPath.c_str());
            WritePrivateProfileStringA("Combat_Net", "NameplateMT", "0", iniPath.c_str());

            // Graphics & Sound
            WritePrivateProfileStringA("Graphics_Sound", "StrStrSse2", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "StrCatFast", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "SoundMixerOpt", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "AudioDecodeMt", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "DbcLookupCache", "0", iniPath.c_str());  // #35: crash while loading — off by default
            WritePrivateProfileStringA("Graphics_Sound", "WorldStateCoalesce", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "D3d9RenderThread", "0", iniPath.c_str());

            // 10 new features defaults
            WritePrivateProfileStringA("Combat_Net", "CombatLogFilter", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "SoundVolumeLimit", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "TerrainHeightCache", "0", iniPath.c_str());

            WritePrivateProfileStringA("Graphics_Sound", "TextureUnloadDelay", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "M2MatrixSimd", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "MpqAsyncDecompress", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "SimdMatrixTransform", "0", iniPath.c_str());
            WritePrivateProfileStringA("Graphics_Sound", "SpellEffectCulling", "0", iniPath.c_str());
            WritePrivateProfileStringA("General", "CrtMimalloc", "0", iniPath.c_str());
        }

        // Read all settings
        // General
        g_settings.OptSleepPrecision      = GetPrivateProfileIntA("General", "SleepPrecision", 1, iniPath.c_str()) != 0;
        g_settings.SleepPrecisionValue    = GetPrivateProfileIntA("General", "SleepPrecisionValue", 8, iniPath.c_str());
        g_settings.OptSessionLogs         = GetPrivateProfileIntA("General", "SessionLogs", 1, iniPath.c_str()) != 0;
        g_settings.OptLuaStackFast        = GetPrivateProfileIntA("UI_Lua", "LuaStackFast", 0, iniPath.c_str()) != 0;
        g_settings.OptQualityGovernor     = GetPrivateProfileIntA("Graphics_Sound", "QualityGovernor", 0, iniPath.c_str()) != 0;
        g_settings.SessionLogsToKeep      = GetPrivateProfileIntA("General", "SessionLogsToKeep", 10, iniPath.c_str());
        g_settings.OptMemoryPressure      = GetPrivateProfileIntA("General", "MemoryPressure", 1, iniPath.c_str()) != 0;
        g_settings.OptHeapCompactor       = GetPrivateProfileIntA("General", "HeapCompactor", 1, iniPath.c_str()) != 0;
        g_settings.OptDefragLf            = GetPrivateProfileIntA("General", "DefragLf", 0, iniPath.c_str()) != 0;
        g_settings.OptVulkanDXVK          = GetPrivateProfileIntA("General", "VulkanDXVK", 0, iniPath.c_str()) != 0;
        g_settings.OptTimingFix           = GetPrivateProfileIntA("General", "TimingFix", 0, iniPath.c_str()) != 0;
        g_settings.OptCvarNullGuard       = GetPrivateProfileIntA("General", "CvarNullGuard", 1, iniPath.c_str()) != 0;
        g_settings.OptDeviceCbGuard       = GetPrivateProfileIntA("General", "DeviceCbGuard", 1, iniPath.c_str()) != 0;
        g_settings.OptWowOptHooks        = GetPrivateProfileIntA("General", "WowOptHooks", 1, iniPath.c_str()) != 0;
        g_settings.OptWowPerfHooks       = GetPrivateProfileIntA("General", "WowPerfHooks", 1, iniPath.c_str()) != 0;
        g_settings.OptWowExtendedHooks   = GetPrivateProfileIntA("General", "WowExtendedHooks", 1, iniPath.c_str()) != 0;
        g_settings.OptWowSubsystemHooks  = GetPrivateProfileIntA("General", "WowSubsystemHooks", 1, iniPath.c_str()) != 0;
        g_settings.OptLockTuning         = GetPrivateProfileIntA("General", "LockTuning", 1, iniPath.c_str()) != 0;
        g_settings.OptAsyncMpqIo         = GetPrivateProfileIntA("General", "AsyncMpqIo", 1, iniPath.c_str()) != 0;
        g_settings.OptThreadIdCache      = GetPrivateProfileIntA("General", "ThreadIdCache", 1, iniPath.c_str()) != 0;
        g_settings.OptPriorityGuard      = GetPrivateProfileIntA("General", "PriorityGuard", 1, iniPath.c_str()) != 0;
        g_settings.OptLuaVmOpt           = GetPrivateProfileIntA("UI_Lua", "LuaVmOpt", 1, iniPath.c_str()) != 0;
        g_settings.OptLuaGcManual        = GetPrivateProfileIntA("UI_Lua", "LuaGcManual", 1, iniPath.c_str()) != 0;
        g_settings.OptD3d9StateManager    = GetPrivateProfileIntA("Graphics_Sound", "D3d9StateManager", 1, iniPath.c_str()) != 0;
        g_settings.OptLayoutRelinkFast    = GetPrivateProfileIntA("UI_Lua", "LayoutRelinkFast", 0, iniPath.c_str()) != 0;
        g_settings.OptTimingCvarPin       = GetPrivateProfileIntA("General", "TimingCvarPin", 1, iniPath.c_str()) != 0;
        g_settings.OptFrameLimiter        = GetPrivateProfileIntA("General", "FrameLimiter", 0, iniPath.c_str()) != 0;
        g_settings.OptObjVisCache         = GetPrivateProfileIntA("General", "ObjVisCache", 1, iniPath.c_str()) != 0;
        g_settings.OptOomGovernor         = GetPrivateProfileIntA("General", "OomGovernor", 0, iniPath.c_str()) != 0;
        g_settings.OptHardwareCursor      = GetPrivateProfileIntA("General", "HardwareCursor", 0, iniPath.c_str()) != 0;
        g_settings.OptSamplingProfiler    = GetPrivateProfileIntA("General", "SamplingProfiler", 0, iniPath.c_str()) != 0;
        g_settings.OptMimallocLarge       = GetPrivateProfileIntA("General", "MimallocLarge", 0, iniPath.c_str()) != 0;
        g_settings.OptVaArena             = GetPrivateProfileIntA("General", "VaArena", 0, iniPath.c_str()) != 0;
        g_settings.OptCompatMode          = GetPrivateProfileIntA("General", "CompatMode", 0, iniPath.c_str()) != 0;
        // HARD-DISABLED regardless of ini: in tester logs the arena was active
        // on machines with zero fragmentation (2GB+ largest free block), so it
        // used ~0.2MB of its 64MB and delivered no benefit - while still routing
        // EVERY process VirtualAlloc/VirtualFree through our global hook + lock.
        // It correlated with repeated 10-14s main-thread freezes and an
        // exit-time crash, and it is unproven. Keep the (corrected) code for a
        // future, fragmentation-gated retry, but do not activate it now.
        g_settings.OptVaArena = false;


        // UI & Lua
        g_settings.OptUIFrameBatch        = GetPrivateProfileIntA("UI_Lua", "UIFrameBatch", 0, iniPath.c_str()) != 0;
        g_settings.OptAddonDispatcher     = GetPrivateProfileIntA("UI_Lua", "AddonDispatcher", 0, iniPath.c_str()) != 0;
        g_settings.OptUIFrameAccessorFast = GetPrivateProfileIntA("UI_Lua", "UIFrameAccessorFast", 0, iniPath.c_str()) != 0;
        g_settings.OptFontMetricsFast     = GetPrivateProfileIntA("UI_Lua", "FontMetricsFast", 0, iniPath.c_str()) != 0;
        g_settings.OptModuleHandleCache   = GetPrivateProfileIntA("UI_Lua", "ModuleHandleCache", 0, iniPath.c_str()) != 0;
        g_settings.OptFrameScriptDispatch = GetPrivateProfileIntA("UI_Lua", "FrameScriptDispatch", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaNumConvFast      = GetPrivateProfileIntA("UI_Lua", "LuaNumConvFast", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaOpcache          = GetPrivateProfileIntA("UI_Lua", "LuaOpcache", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaOpcacheTables   = GetPrivateProfileIntA("UI_Lua", "LuaOpcacheTables", 1, iniPath.c_str()) != 0;
        g_settings.OptLuaOpcacheStrings  = GetPrivateProfileIntA("UI_Lua", "LuaOpcacheStrings", 1, iniPath.c_str()) != 0;
        g_settings.OptLuaOpcacheWrites   = GetPrivateProfileIntA("UI_Lua", "LuaOpcacheWrites", 1, iniPath.c_str()) != 0;
        g_settings.OptLuaOpcacheReads    = GetPrivateProfileIntA("UI_Lua", "LuaOpcacheReads", 1, iniPath.c_str()) != 0;
        g_settings.OptLuaGcCoalesce       = GetPrivateProfileIntA("UI_Lua", "LuaGcCoalesce", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaGetTimeFast      = GetPrivateProfileIntA("UI_Lua", "LuaGetTimeFast", 0, iniPath.c_str()) != 0;
        g_settings.OptAsyncTexLoader      = GetPrivateProfileIntA("Graphics_Sound", "AsyncTexLoader", 0, iniPath.c_str()) != 0;
        g_settings.OptAsyncTerrainLoader  = GetPrivateProfileIntA("UI_Lua", "AsyncTerrainLoader", 0, iniPath.c_str()) != 0;
        g_settings.OptRcuObjMgr           = GetPrivateProfileIntA("UI_Lua", "RcuObjMgr", 0, iniPath.c_str()) != 0;
        g_settings.OptMipBiasGovernor     = GetPrivateProfileIntA("Graphics_Sound", "MipBiasGovernor", 0, iniPath.c_str()) != 0;

        // Combat & Network
        g_settings.OptCombatLogLeakFix    = GetPrivateProfileIntA("Combat_Net", "CombatLogLeakFix", 1, iniPath.c_str()) != 0;
        g_settings.OptCombatLogParser     = GetPrivateProfileIntA("Combat_Net", "CombatLogParser", 0, iniPath.c_str()) != 0;
        g_settings.OptCombatLogIncremental = GetPrivateProfileIntA("Combat_Net", "CombatLogIncremental", 0, iniPath.c_str()) != 0;
        g_settings.OptEventCoalescer      = GetPrivateProfileIntA("Combat_Net", "EventCoalescer", 0, iniPath.c_str()) != 0;
        // Back to 0. Both modules are inert - see the notes in config.h - so a 1
        // here only makes the config dump read as though something is running.
        g_settings.OptSavedVarsAsync      = GetPrivateProfileIntA("Combat_Net", "SavedVarsAsync", 0, iniPath.c_str()) != 0;
        g_settings.OptSavedVarsPretoken   = GetPrivateProfileIntA("Combat_Net", "SavedVarsPretoken", 0, iniPath.c_str()) != 0;
        g_settings.OptUnitAuraFast        = GetPrivateProfileIntA("Combat_Net", "UnitAuraFast", 0, iniPath.c_str()) != 0;
        g_settings.OptNetworkGuidSse2     = GetPrivateProfileIntA("Combat_Net", "NetworkGuidSse2", 0, iniPath.c_str()) != 0;
        g_settings.OptApiCache   = GetPrivateProfileIntA("Combat_Net", "ApiCache", 1, iniPath.c_str()) != 0;
        g_settings.OptGuidLookupCache   = GetPrivateProfileIntA("Combat_Net", "GuidLookupCache", 1, iniPath.c_str()) != 0;
        g_settings.OptPacketOffload       = GetPrivateProfileIntA("Combat_Net", "PacketOffload", 0, iniPath.c_str()) != 0;
        g_settings.OptNameplateMT         = GetPrivateProfileIntA("Combat_Net", "NameplateMT", 0, iniPath.c_str()) != 0;

        // Graphics & Sound
        g_settings.OptFastMemsetOpt       = GetPrivateProfileIntA("Graphics_Sound", "FastMemsetOpt", 1, iniPath.c_str()) != 0;
        g_settings.OptFastStrnicmpOpt     = GetPrivateProfileIntA("UI_Lua", "FastStrnicmpOpt", 1, iniPath.c_str()) != 0;
        g_settings.OptLuaSNewLstrFast     = GetPrivateProfileIntA("UI_Lua", "LuaSNewLstrFast", 0, iniPath.c_str()) != 0;
        g_settings.OptStrStrSse2          = GetPrivateProfileIntA("Graphics_Sound", "StrStrSse2", 0, iniPath.c_str()) != 0;
        g_settings.OptStrCatFast          = GetPrivateProfileIntA("Graphics_Sound", "StrCatFast", 0, iniPath.c_str()) != 0;
        g_settings.OptSoundMixerOpt       = GetPrivateProfileIntA("Graphics_Sound", "SoundMixerOpt", 0, iniPath.c_str()) != 0;
        g_settings.OptAudioDecodeMt       = GetPrivateProfileIntA("Graphics_Sound", "AudioDecodeMt", 0, iniPath.c_str()) != 0;
        g_settings.OptDbcLookupCache      = GetPrivateProfileIntA("Graphics_Sound", "DbcLookupCache", 0, iniPath.c_str()) != 0;
        // Inherits DbcLookupCache when absent, which is exactly what these
        // hooks were gated on before they had a switch of their own. An
        // existing wow_opt.ini therefore keeps the behaviour it had.
        g_settings.OptFileIoHooks         = GetPrivateProfileIntA("General", "FileIoHooks", g_settings.OptDbcLookupCache ? 1 : 0, iniPath.c_str()) != 0;
        g_settings.OptLuaTypeFast         = GetPrivateProfileIntA("UI_Lua", "LuaTypeFast", g_settings.OptDbcLookupCache ? 1 : 0, iniPath.c_str()) != 0;
        // Deliberately not inheriting FileIoHooks. See config.h: this one has
        // never executed, so defaulting it off takes nothing away from anyone.
        g_settings.OptTerrainPrefetch     = GetPrivateProfileIntA("General", "TerrainPrefetch", 0, iniPath.c_str()) != 0;
        g_settings.OptTickListPrefetch    = GetPrivateProfileIntA("Graphics_Sound", "TickListPrefetch", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaGcStockPace      = GetPrivateProfileIntA("UI_Lua", "LuaGcStockPace", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaTableCensus      = GetPrivateProfileIntA("UI_Lua", "LuaTableCensus", 0, iniPath.c_str()) != 0;
        // Inherit UIFrameBatch when absent, which is what these two were
        // gated on before they had switches of their own.
        g_settings.OptUiScriptHandlerCache = GetPrivateProfileIntA("UI_Lua", "UiScriptHandlerCache", g_settings.OptUIFrameBatch ? 1 : 0, iniPath.c_str()) != 0;
        g_settings.OptUnitApiFastPath      = GetPrivateProfileIntA("UI_Lua", "UnitApiFastPath", g_settings.OptUIFrameBatch ? 1 : 0, iniPath.c_str()) != 0;
        // Same inheritance rule as FileIoHooks: each takes the switch it used to
        // hang off as its default, so an existing wow_opt.ini keeps behaving the
        // way it did until its owner writes the new key.
        g_settings.OptWin32ApiCaches      = GetPrivateProfileIntA("General", "Win32ApiCaches", g_settings.OptTimingFix ? 1 : 0, iniPath.c_str()) != 0;
        g_settings.OptDebugApiHooks       = GetPrivateProfileIntA("General", "DebugApiHooks", g_settings.OptCvarNullGuard ? 1 : 0, iniPath.c_str()) != 0;
        g_settings.OptLockSpinHooks       = GetPrivateProfileIntA("General", "LockSpinHooks", g_settings.OptDefragLf ? 1 : 0, iniPath.c_str()) != 0;
        // There is nothing to charge samples to without the sampler running.
        g_settings.OptLuaAddonProfile     = GetPrivateProfileIntA("UI_Lua", "LuaAddonProfile", g_settings.OptSamplingProfiler ? 1 : 0, iniPath.c_str()) != 0;
        g_settings.OptCpuTopology         = GetPrivateProfileIntA("General", "CpuTopology", 1, iniPath.c_str()) != 0;
        g_settings.OptPinMainThread       = GetPrivateProfileIntA("General", "PinMainThread", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaMemPoolFast      = GetPrivateProfileIntA("UI_Lua", "LuaMemPoolFast", 0, iniPath.c_str()) != 0;
        g_settings.OptVertexFmtInline     = GetPrivateProfileIntA("Graphics_Sound", "VertexFmtInline", 0, iniPath.c_str()) != 0;
        g_settings.OptObjMgrFindFast      = GetPrivateProfileIntA("General", "ObjMgrFindFast", 0, iniPath.c_str()) != 0;
        g_settings.OptQuatLerpSse2        = GetPrivateProfileIntA("Graphics_Sound", "QuatLerpSse2", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaProtoCache       = GetPrivateProfileIntA("UI_Lua", "LuaProtoCache", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaThisFast         = GetPrivateProfileIntA("UI_Lua", "LuaThisFast", 0, iniPath.c_str()) != 0;
        g_settings.OptAnimLod             = GetPrivateProfileIntA("Graphics_Sound", "AnimLod", 0, iniPath.c_str()) != 0;
        g_settings.OptCollisionOutcode    = GetPrivateProfileIntA("Graphics_Sound", "CollisionOutcode", 0, iniPath.c_str()) != 0;
        g_settings.OptAabbOverlap         = GetPrivateProfileIntA("Graphics_Sound", "AabbOverlap", 0, iniPath.c_str()) != 0;
        g_settings.OptAnimQuatUnpack      = GetPrivateProfileIntA("Graphics_Sound", "AnimQuatUnpack", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaPoolFast     = GetPrivateProfileIntA("UI_Lua", "LuaPoolFast", 0, iniPath.c_str()) != 0;
        g_settings.OptAnimVec3Track   = GetPrivateProfileIntA("Graphics_Sound", "AnimVec3Track", 0, iniPath.c_str()) != 0;
        g_settings.OptM2SortKey       = GetPrivateProfileIntA("Graphics_Sound", "M2SortKey", 0, iniPath.c_str()) != 0;
        g_settings.OptFrustumAabb     = GetPrivateProfileIntA("Graphics_Sound", "FrustumAabb", 0, iniPath.c_str()) != 0;
        g_settings.OptSegmentAabb     = GetPrivateProfileIntA("Graphics_Sound", "SegmentAabb", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaHGetDispatch = GetPrivateProfileIntA("UI_Lua", "LuaHGetDispatch", 0, iniPath.c_str()) != 0;
        g_settings.OptWorldStateCoalesce  = GetPrivateProfileIntA("Graphics_Sound", "WorldStateCoalesce", 0, iniPath.c_str()) != 0;
        g_settings.OptD3d9RenderThread    = GetPrivateProfileIntA("Graphics_Sound", "D3d9RenderThread", 0, iniPath.c_str()) != 0;
        // HARD-DISABLED regardless of ini: this offloads D3D9 draw/Present/Reset
        // calls to a worker thread, but WoW's device isn't created
        // D3DCREATE_MULTITHREADED, so cross-thread rendering is undefined
        // behavior -> mid-fight screen flashing, and the main thread spin-waits
        // in PipelineFlush on a render thread that stalls on the device Reset
        // during zone loads -> the "loaded then froze forever" hang. Same class
        // of unsafe-by-design as MimallocLarge. Kept readable above only so old
        // profiles with D3d9RenderThread=1 don't silently re-enable it.
        g_settings.OptD3d9RenderThread = false;

        // Parse Features 21-30
        g_settings.OptCombatLogFilter    = GetPrivateProfileIntA("Combat_Net", "CombatLogFilter", 0, iniPath.c_str()) != 0;
        g_settings.OptSoundVolumeLimit   = GetPrivateProfileIntA("Graphics_Sound", "SoundVolumeLimit", 0, iniPath.c_str()) != 0;
        g_settings.OptTerrainHeightCache = GetPrivateProfileIntA("Graphics_Sound", "TerrainHeightCache", 0, iniPath.c_str()) != 0;

        // Parse Features 31-50
        g_settings.OptTextureUnloadDelay = GetPrivateProfileIntA("Graphics_Sound", "TextureUnloadDelay", 0, iniPath.c_str()) != 0;
        g_settings.OptM2MatrixSimd = GetPrivateProfileIntA("Graphics_Sound", "M2MatrixSimd", 0, iniPath.c_str()) != 0;
        g_settings.OptMpqAsyncDecompress = GetPrivateProfileIntA("General", "MpqAsyncDecompress", 0, iniPath.c_str()) != 0;
        g_settings.OptSimdMatrixTransform = GetPrivateProfileIntA("Graphics_Sound", "SimdMatrixTransform", 0, iniPath.c_str()) != 0;
        g_settings.OptSpellEffectCulling = GetPrivateProfileIntA("Graphics_Sound", "SpellEffectCulling", 0, iniPath.c_str()) != 0;
        g_settings.OptRenderNullGuard = GetPrivateProfileIntA("Graphics_Sound", "RenderNullGuard", 1, iniPath.c_str()) != 0;
        g_settings.OptStrncmpSse2 = GetPrivateProfileIntA("Graphics_Sound", "StrncmpSse2", 1, iniPath.c_str()) != 0;
        g_settings.OptAddonProfiler = GetPrivateProfileIntA("UI_Lua", "AddonProfiler", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaCompileCensus = GetPrivateProfileIntA("UI_Lua", "LuaCompileCensus", 1, iniPath.c_str()) != 0;
        g_settings.OptShadowStateProbe = GetPrivateProfileIntA("Graphics_Sound", "ShadowStateProbe", 0, iniPath.c_str()) != 0;
        g_settings.OptQuatNormalizeSse2 = GetPrivateProfileIntA("Graphics_Sound", "QuatNormalizeSse2", 1, iniPath.c_str()) != 0;
        g_settings.OptMatrixMultiplySse2 = GetPrivateProfileIntA("Graphics_Sound", "MatrixMultiplySse2", 1, iniPath.c_str()) != 0;
        g_settings.OptDrawCensus = GetPrivateProfileIntA("Graphics_Sound", "DrawCensus", 0, iniPath.c_str()) != 0;
        g_settings.OptLuaAllocCensus = GetPrivateProfileIntA("UI_Lua", "LuaAllocCensus", 0, iniPath.c_str()) != 0;
        g_settings.OptAnimCensus = GetPrivateProfileIntA("Graphics_Sound", "AnimCensus", 0, iniPath.c_str()) != 0;
        g_settings.OptHorizonOcclusionSse2 = GetPrivateProfileIntA("Graphics_Sound", "HorizonOcclusionSse2", 0, iniPath.c_str()) != 0;
        g_settings.OptNetDiag = GetPrivateProfileIntA("Combat_Net", "NetDiag", 1, iniPath.c_str()) != 0;
        g_settings.OptCrtFreeMsize = GetPrivateProfileIntA("General", "CrtFreeMsize", 1, iniPath.c_str()) != 0;
        g_settings.OptCrtAllocMsize = GetPrivateProfileIntA("General", "CrtAllocMsize", 1, iniPath.c_str()) != 0;
        g_settings.OptCrtMimalloc = GetPrivateProfileIntA("General", "CrtMimalloc", 0, iniPath.c_str()) != 0;

        // Previously Init'd unconditionally - now read from their launcher keys.
        // Default 1 preserves the old always-on behavior; they are now disableable.
        g_settings.OptMouseClipRelease     = GetPrivateProfileIntA("General", "MouseClipRelease", 0, iniPath.c_str()) != 0;
        g_settings.OptSavedVarsBackup      = GetPrivateProfileIntA("General", "SavedVarsBackup", 0, iniPath.c_str()) != 0;
        g_settings.OptSoundCoalescer       = GetPrivateProfileIntA("Graphics_Sound", "SoundCoalescer", 0, iniPath.c_str()) != 0;

        g_loadedFrom = iniPath;
        g_settings.OptVertexBufferPrealloc = GetPrivateProfileIntA("General", "VertexBufferPrealloc", 0, iniPath.c_str()) != 0;
    }
}

// lua_optimize.cpp has a file-scope object named Config, so it cannot include
// config.h. It reads these two settings through here instead.
extern "C" bool WowOpt_LuaVmOptEnabled()    { return Config::g_settings.OptLuaVmOpt; }
extern "C" bool WowOpt_LuaGcManualEnabled() { return Config::g_settings.OptLuaGcManual; }
