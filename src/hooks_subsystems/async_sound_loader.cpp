// ============================================================================
// Module: async_sound_loader.cpp
// Description: Preloads and caches FMOD sound files in memory to bypass disk I/O.
//              Uses a safe background task queue and worker thread to prevent thread leaks.
// Safety & Threading: Thread-safe cache and queue using mutex protection.
// ============================================================================

#include "async_sound_loader.h"
#include "core/config.h"
#include "MinHook.h"
#include "version.h"
#include <windows.h>
#include <string>
#include <vector>
// <thread> was included here and never used - every worker in this project is
// a CreateThread. Including it is what the no-std::thread rule exists to stop:
// it is the doorway to MSVCP140, which is loaded during early init and has
// crashed under Wine/Proton. Removed so the next person cannot reach through
// it by accident.
#include "win_mutex.h"
#include <queue>
#include <atomic>
#include <unordered_map>

extern "C" void Log(const char* fmt, ...);

namespace AsyncSoundLoader {

struct SoundBuffer {
    std::vector<uint8_t> data;
    bool ready;
};

static std::unordered_map<std::string, SoundBuffer> g_soundCache;
static WinMutex g_soundMutex;
static bool g_active = false;
static uint64_t g_preloads = 0;

static std::queue<std::string> g_preloadQueue;
static WinMutex g_queueMutex;
static WinCondVar g_queueCv;
static HANDLE g_workerThread = nullptr;
static void SoundWorkerProc();
static DWORD WINAPI SoundWorkerThreadProc(LPVOID) {
    SoundWorkerProc();
    return 0;
}
static std::atomic<bool> g_workerShutdown{false};

// Storm DLL types
typedef BOOL (APIENTRY *SFileOpenFileEx_fn)(HANDLE hArchive, const char* szFileName, DWORD dwSearchScope, HANDLE* phFile);
typedef BOOL (APIENTRY *SFileReadFile_fn)(HANDLE hFile, void* lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
typedef BOOL (APIENTRY *SFileCloseFile_fn)(HANDLE hFile);

static SFileOpenFileEx_fn pSFileOpenFileEx = nullptr;
static SFileReadFile_fn pSFileReadFile = nullptr;
static SFileCloseFile_fn pSFileCloseFile = nullptr;

// FMOD Hook Types
typedef void* (APIENTRY *FSOUND_Sample_Load_fn)(int index, const void* name_or_data, unsigned int mode, int offset, int length);
static FSOUND_Sample_Load_fn orig_FSOUND_Sample_Load = nullptr;

typedef void* (APIENTRY *FSOUND_Stream_OpenFile_fn)(const char *filename, unsigned int mode, int offset, int length);
static FSOUND_Stream_OpenFile_fn orig_FSOUND_Stream_OpenFile = nullptr;

static void* APIENTRY Hooked_FSOUND_Sample_Load(int index, const void* name_or_data, unsigned int mode, int offset, int length) {
    if (name_or_data && !(mode & 0x0800)) { // 0x0800 = FSOUND_LOADMEMORY
        std::string filePath = (const char*)name_or_data;
        std::string normPath = filePath;
        for (char& c : normPath) {
            if (c == '/') c = '\\';
            else c = tolower(c);
        }

        const void* memData = nullptr;
        size_t memSize = 0;
        {
            WinLockGuard lock(g_soundMutex);
            auto it = g_soundCache.find(normPath);
            if (it != g_soundCache.end() && it->second.ready) {
                memData = it->second.data.data();
                memSize = it->second.data.size();
            }
        }

        if (memData) {
            unsigned int newMode = mode | 0x0800; // Force load from memory
            return orig_FSOUND_Sample_Load(index, memData, newMode, offset, (int)memSize);
        }
    }
    return orig_FSOUND_Sample_Load(index, name_or_data, mode, offset, length);
}

static void* APIENTRY Hooked_FSOUND_Stream_OpenFile(const char *filename, unsigned int mode, int offset, int length) {
    if (filename && !(mode & 0x0800)) {
        std::string filePath = filename;
        std::string normPath = filePath;
        for (char& c : normPath) {
            if (c == '/') c = '\\';
            else c = tolower(c);
        }

        const char* memData = nullptr;
        size_t memSize = 0;
        {
            WinLockGuard lock(g_soundMutex);
            auto it = g_soundCache.find(normPath);
            if (it != g_soundCache.end() && it->second.ready) {
                memData = (const char*)it->second.data.data();
                memSize = it->second.data.size();
            }
        }

        if (memData) {
            unsigned int newMode = mode | 0x0800;
            return orig_FSOUND_Stream_OpenFile(memData, newMode, 0, (int)memSize);
        }
    }
    return orig_FSOUND_Stream_OpenFile(filename, mode, offset, length);
}

void SoundLoadWorker(std::string filePath) {
    if (!pSFileOpenFileEx || !pSFileReadFile || !pSFileCloseFile) return;

    std::string normPath = filePath;
    for (char& c : normPath) {
        if (c == '/') c = '\\';
        else c = tolower(c);
    }

    HANDLE hFile = nullptr;
    if (pSFileOpenFileEx(nullptr, filePath.c_str(), 0, &hFile)) {
        DWORD size = GetFileSize(hFile, NULL);
        if (size > 0 && size < 2 * 1024 * 1024) { // Preload files under 2MB
            std::vector<uint8_t> buffer(size);
            DWORD readBytes = 0;
            if (pSFileReadFile(hFile, buffer.data(), size, &readBytes, NULL) && readBytes == size) {
                WinLockGuard lock(g_soundMutex);
                g_soundCache[normPath] = { std::move(buffer), true };
            }
        }
        pSFileCloseFile(hFile);
    }
}

static void SoundWorkerProc() {
    while (!g_workerShutdown.load(std::memory_order_relaxed)) {
        std::string filePath;
        {
            WinUniqueLock lock(g_queueMutex);
            g_queueCv.wait(lock, [] {
                return !g_preloadQueue.empty() || g_workerShutdown.load();
            });
            if (g_workerShutdown.load()) break;
            filePath = std::move(g_preloadQueue.front());
            g_preloadQueue.pop();
        }
        SoundLoadWorker(filePath);
    }
}

void PreloadSound(const std::string& filePath) {
    if (!Config::g_settings.OptAudioDecodeMt) return;
    if (!g_active) return;

    std::string normPath = filePath;
    for (char& c : normPath) {
        if (c == '/') c = '\\';
        else c = tolower(c);
    }

    {
        WinLockGuard lock(g_soundMutex);
        if (g_soundCache.find(normPath) != g_soundCache.end()) return;
        g_soundCache[normPath] = { {}, false };
    }
    
    {
        WinLockGuard lock(g_queueMutex);
        g_preloadQueue.push(filePath);
    }
    g_queueCv.notify_one();
    g_preloads++;
}

bool Init() {
    if (!Config::g_settings.OptAudioDecodeMt) {
        Log("[AsyncSoundLoader] DISABLED via configuration");
        return true;
    }

    HMODULE hStorm = GetModuleHandleA("storm.dll");
    if (hStorm) {
        pSFileOpenFileEx = (SFileOpenFileEx_fn)GetProcAddress(hStorm, "SFileOpenFileEx");
        pSFileReadFile = (SFileReadFile_fn)GetProcAddress(hStorm, "SFileReadFile");
        pSFileCloseFile = (SFileCloseFile_fn)GetProcAddress(hStorm, "SFileCloseFile");
    }

    HMODULE hFmod = GetModuleHandleA("fmod32.dll");
    if (hFmod) {
        void* pLoad = (void*)GetProcAddress(hFmod, "_FSOUND_Sample_Load@20");
        if (!pLoad) pLoad = (void*)GetProcAddress(hFmod, "FSOUND_Sample_Load");

        void* pStream = (void*)GetProcAddress(hFmod, "_FSOUND_Stream_OpenFile@16");
        if (!pStream) pStream = (void*)GetProcAddress(hFmod, "FSOUND_Stream_OpenFile");

        if (pLoad && pStream) {
            if (MH_CreateHook(pLoad, (void*)Hooked_FSOUND_Sample_Load, (void**)&orig_FSOUND_Sample_Load) == MH_OK &&
                MH_CreateHook(pStream, (void*)Hooked_FSOUND_Stream_OpenFile, (void**)&orig_FSOUND_Stream_OpenFile) == MH_OK) {
                
                MH_EnableHook(pLoad);
                MH_EnableHook(pStream);
                Log("[AsyncSoundLoader] Hooked FMOD Sample Load and Stream Open APIs successfully.");
            }
        }
    }

    g_active = true;
    g_workerShutdown = false;
    g_workerThread = CreateThread(NULL, 0, SoundWorkerThreadProc, NULL, 0, NULL);

    // Preload critical combat sounds
    const char* sounds[] = {
        "Sound\\Spells\\Fireball.wav",
        "Sound\\Spells\\Frostbolt.wav",
        "Sound\\Spells\\ShadowBolt.wav",
        "Sound\\Spells\\ChainLightning.wav",
        "Sound\\Spells\\Heal.wav",
        "Sound\\Spells\\FlashHeal.wav",
        "Sound\\Spells\\Rejuvenation.wav",
        "Sound\\Spells\\SpellCastFailure.wav",
        "Sound\\Spells\\SpellCastStart.wav",
        "Sound\\Spells\\Fizzle.wav"
    };
    for (const char* sound : sounds) {
        PreloadSound(sound);
    }

    Log("[AsyncSoundLoader] Active - Asynchronous Sound FX Loader Initialized.");
    return true;
}

// Printed from the periodic report. Shutdown does not run - the DLL exits via
// TerminateProcess - so anything reported only from there is never seen.
void LogStats() {
    Log("[AsyncSoundLoader] Stats: Preloaded %lld sound effects.", g_preloads);
}

void Shutdown() {
    if (!Config::g_settings.OptAudioDecodeMt) return;
    g_active = false;
    g_workerShutdown = true;
    g_queueCv.notify_all();
    if (g_workerThread) {
        WaitForSingleObject(g_workerThread, INFINITE);
        CloseHandle(g_workerThread);
        g_workerThread = nullptr;
    }
    WinLockGuard lock(g_soundMutex);
    g_soundCache.clear();
    LogStats();
}


} // namespace AsyncSoundLoader
