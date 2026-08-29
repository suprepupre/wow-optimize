#include "async_tex_loader.h"
#include "core/config.h"
#include "../allocators/loading_defrag.h"
#include "../../build/_deps/minhook-src/include/MinHook.h"
#include <windows.h>
#include <string>
#include <vector>
#include <queue>
#include "win_mutex.h"
// <thread> was included here and never used - every worker in this project is
// a CreateThread. Including it is what the no-std::thread rule exists to stop:
// it is the doorway to MSVCP140, which is loaded during early init and has
// crashed under Wine/Proton. Removed so the next person cannot reach through
// it by accident.
#include <atomic>
#include <unordered_map>
#include <unordered_set>

#include <psapi.h>

extern "C" void Log(const char* fmt, ...);

namespace AsyncTexLoader {

// Storm API Types
typedef BOOL (APIENTRY *SFileOpenArchive_fn)(const char* szArchiveName, DWORD dwPriority, DWORD dwFlags, HANDLE* phArchive);
typedef BOOL (APIENTRY *SFileOpenFileEx_fn)(HANDLE hArchive, const char* szFileName, DWORD dwSearchScope, HANDLE* phFile);
typedef BOOL (APIENTRY *SFileReadFile_fn)(HANDLE hFile, void* lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
typedef BOOL (APIENTRY *SFileCloseFile_fn)(HANDLE hFile);
typedef BOOL (APIENTRY *SFileCloseArchive_fn)(HANDLE hArchive);

static SFileOpenArchive_fn pSFileOpenArchive = nullptr;
static SFileOpenFileEx_fn pSFileOpenFileEx = nullptr;
static SFileReadFile_fn pSFileReadFile = nullptr;
static SFileCloseFile_fn pSFileCloseFile = nullptr;
static SFileCloseArchive_fn pSFileCloseArchive = nullptr;

static SFileOpenFileEx_fn orig_SFileOpenFileEx = nullptr;
static SFileReadFile_fn orig_SFileReadFile = nullptr;
static SFileCloseFile_fn orig_SFileCloseFile = nullptr;

static std::vector<HANDLE> g_privateArchives;

// Thread variables
static HANDLE g_workerThread = nullptr;
static void WorkerProc();
static DWORD WINAPI WorkerThreadProc(LPVOID) {
    WorkerProc();
    return 0;
}
static std::queue<std::string> g_prefetchQueue;
static WinMutex g_queueMutex;
static WinCondVar g_queueCv;
static std::atomic<bool> g_shutdown{false};
static DWORD g_workerThreadId = 0;

// Virtual File System (VFS) structures
struct VirtualFile {
    std::string path;
    std::vector<char> data;
    size_t offset = 0;
};

static std::unordered_map<HANDLE, VirtualFile*> g_virtualHandles;
static WinMutex g_virtualHandlesMutex;
static HANDLE g_nextVirtualHandle = (HANDLE)0xFEED0000;

static std::unordered_map<std::string, std::vector<char>> g_fileMemoryCache;
static WinMutex g_fileCacheMutex;

#pragma pack(push, 1)
struct BLPHeader {
    uint32_t magic;          // 'BLP2'
    uint32_t type;           // 0 or 1
    uint8_t  encoding;       // 1 = uncompressed/raw, 2 = DXT, 3 = RGBA
    uint8_t  alphaDepth;     // 0, 1, 8
    uint8_t  alphaEncoding;  // 0, 1, 7, 8
    uint8_t  hasMipmaps;     // 0 or 1
    uint32_t width;
    uint32_t height;
    uint32_t mipmapOffsets[16];
    uint32_t mipmapSizes[16];
};
#pragma pack(pop)

static bool CheckMemoryOomPressure() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        // Threshold: 2.3 GB (2468241408 bytes)
        return pmc.PagefileUsage > 2468241408ULL;
    }
    return false;
}

static void DownscaleBLPInPlace(std::vector<char>& fileData, const std::string& path) {
    if (fileData.size() < sizeof(BLPHeader)) return;
    
    BLPHeader* header = (BLPHeader*)fileData.data();
    if (header->magic != 0x32504C42) return; // 'BLP2'
    
    if (header->width <= 16 || header->height <= 16) return;
    if (header->mipmapOffsets[1] == 0) return;
    
    header->width /= 2;
    header->height /= 2;
    if (header->width < 1) header->width = 1;
    if (header->height < 1) header->height = 1;
    
    for (int i = 0; i < 15; i++) {
        header->mipmapOffsets[i] = header->mipmapOffsets[i + 1];
        header->mipmapSizes[i] = header->mipmapSizes[i + 1];
    }
    header->mipmapOffsets[15] = 0;
    header->mipmapSizes[15] = 0;
}

// Hot-swapping structures
struct PlaceholderEntry {
    int placeholderHandle;
    std::string realPath;
    unsigned int flags;
    void* a3;
    int a4;
};

static std::unordered_map<std::string, PlaceholderEntry> g_placeholderMap;
static std::unordered_set<std::string> g_hotSwapTextures;
static WinMutex g_swapMutex;

static std::vector<char> g_whiteTextureBytes;

// Hook definitions
typedef int (__cdecl *TexCreateBLP_fn)(char* path, int flags, int a3);
static TexCreateBLP_fn orig_TexCreateBLP = nullptr;

static bool LoadStormAPIs() {
    HMODULE hStorm = GetModuleHandleA("storm.dll");
    if (!hStorm) hStorm = LoadLibraryA("storm.dll");
    if (!hStorm) return false;

    pSFileOpenArchive = (SFileOpenArchive_fn)GetProcAddress(hStorm, "SFileOpenArchive");
    pSFileOpenFileEx = (SFileOpenFileEx_fn)GetProcAddress(hStorm, "SFileOpenFileEx");
    pSFileReadFile = (SFileReadFile_fn)GetProcAddress(hStorm, "SFileReadFile");
    pSFileCloseFile = (SFileCloseFile_fn)GetProcAddress(hStorm, "SFileCloseFile");
    pSFileCloseArchive = (SFileCloseArchive_fn)GetProcAddress(hStorm, "SFileCloseArchive");

    return pSFileOpenArchive && pSFileOpenFileEx && pSFileReadFile && pSFileCloseFile && pSFileCloseArchive;
}

static void OpenPrivateArchives() {
    const char* archiveNames[] = {
        "Data\\common.MPQ",
        "Data\\world.MPQ",
        "Data\\lichking.MPQ",
        "Data\\patch.MPQ",
        "Data\\patch-2.MPQ",
        "Data\\patch-3.MPQ"
    };

    for (const char* name : archiveNames) {
        HANDLE hArchive = nullptr;
        if (pSFileOpenArchive(name, 0, 0, &hArchive)) {
            g_privateArchives.push_back(hArchive);
        }
    }
}

static bool LoadPlaceholderTextureBytes() {
    for (HANDLE hArchive : g_privateArchives) {
        HANDLE hFile = nullptr;
        if (pSFileOpenFileEx(hArchive, "Interface\\Buttons\\WHITE8X8.blp", 0, &hFile)) {
            DWORD size = GetFileSize(hFile, NULL);
            if (size != INVALID_FILE_SIZE && size > 0) {
                g_whiteTextureBytes.resize(size);
                DWORD read = 0;
                if (pSFileReadFile(hFile, g_whiteTextureBytes.data(), size, &read, NULL) && read == size) {
                    pSFileCloseFile(hFile);
                    return true;
                }
            }
            pSFileCloseFile(hFile);
        }
    }
    return false;
}

bool GetCachedTextureData(const std::string& path, std::vector<uint8_t>& outData) {
    std::string normPath = path;
    for (char& c : normPath) {
        if (c == '/') c = '\\';
        else c = tolower(c);
    }
    WinLockGuard lock(g_fileCacheMutex);
    auto it = g_fileMemoryCache.find(normPath);
    if (it != g_fileMemoryCache.end()) {
        outData.assign(it->second.begin(), it->second.end());
        return true;
    }
    return false;
}

static void WorkerProc() {
    g_workerThreadId = GetCurrentThreadId();
    std::vector<char> readBuffer(262144);

    while (!g_shutdown.load(std::memory_order_relaxed)) {
        std::string filename;
        {
            WinUniqueLock lock(g_queueMutex);
            g_queueCv.wait_for(lock, std::chrono::milliseconds(50), [] {
                return !g_prefetchQueue.empty() || g_shutdown.load();
            });
            if (g_shutdown.load() && g_prefetchQueue.empty()) break;
            if (g_prefetchQueue.empty()) continue;
            filename = std::move(g_prefetchQueue.front());
            g_prefetchQueue.pop();
        }

        bool alreadyLoaded = false;
        {
            WinLockGuard cacheLock(g_fileCacheMutex);
            if (g_fileMemoryCache.count(filename) && g_fileMemoryCache[filename].size() != g_whiteTextureBytes.size()) {
                alreadyLoaded = true;
            }
        }
        if (alreadyLoaded) continue;

        // Load the file data from MPQ into memory
        std::vector<char> fileData;
        bool loaded = false;

        for (HANDLE hArchive : g_privateArchives) {
            HANDLE hFile = nullptr;
            if (pSFileOpenFileEx(hArchive, filename.c_str(), 0, &hFile)) {
                DWORD size = GetFileSize(hFile, NULL);
                if (size != INVALID_FILE_SIZE && size > 0) {
                    fileData.resize(size);
                    DWORD read = 0;
                    if (pSFileReadFile(hFile, fileData.data(), size, &read, NULL) && read == size) {
                        loaded = true;
                    }
                }
                pSFileCloseFile(hFile);
            }
            if (loaded) break;
        }

        if (loaded) {
            if (Config::g_settings.OptOomGovernor && CheckMemoryOomPressure()) {
                DownscaleBLPInPlace(fileData, filename);
            }
            WinLockGuard cacheLock(g_fileCacheMutex);
            g_fileMemoryCache[filename] = std::move(fileData);
        }
    }
}

static bool IsCacheableAsset(const char* path) {
    if (!path) return false;
    std::string p(path);
    if (p.find("Interface\\") == 0 || p.find("interface\\") == 0) {
        return false;
    }
    if (p.find(".blp") != std::string::npos || p.find(".BLP") != std::string::npos) {
        return true;
    }
    return false;
}

int Call_Orig_TexCreateBLP(unsigned int flags, char* path, void* a3, int a4) {
    int result;
    __asm {
        push a4
        push a3
        push path
        mov eax, flags
        call orig_TexCreateBLP
        mov result, eax
    }
    return result;
}

// C++ Handler for BLP creation
int __stdcall Handle_TexCreateBLP(unsigned int flags, char* path, void* a3, int a4) {
    if (!path) return 0;

    std::string realPath(path);

    // Queue real file read in background for prefetching
    {
        WinLockGuard qLock(g_queueMutex);
        g_prefetchQueue.push(realPath);
        g_queueCv.notify_one();
    }

    // Always create texture with real MPQ data directly to eliminate white texture flashing
    return Call_Orig_TexCreateBLP(flags, path, a3, a4);
}

// Naked detour wrapper to preserve registers and calling conventions
__declspec(naked) void Hooked_TexCreateBLP_Naked() {
    __asm {
        push [esp + 12] // push a4
        push [esp + 12] // push a3
        push [esp + 12] // push path
        push eax        // push flags (EAX)
        call Handle_TexCreateBLP
        ret 12
    }
}

typedef int (__stdcall *TextureRelease_fn)(void* Block);
static TextureRelease_fn orig_TextureRelease = nullptr;

int __stdcall Hooked_TextureRelease(void* Block) {
    if (Block) {
        WinLockGuard lock(g_swapMutex);
        for (auto it = g_placeholderMap.begin(); it != g_placeholderMap.end(); ) {
            if (it->second.placeholderHandle == (int)Block) {
                Log("[AsyncTexLoader] Active placeholder %p released, removing from swap queue", Block);
                it = g_placeholderMap.erase(it);
            } else {
                ++it;
            }
        }
    }
    return orig_TextureRelease(Block);
}

static bool SafeSwapPointers(int placeholderHandle, int realHandle) {
    __try {
        if (placeholderHandle && ((placeholderHandle & 3) == 0) && (placeholderHandle >= 0x00010000) && (placeholderHandle < 0x7FFE0000)) {
            int placeholderD3D = *(int*)(placeholderHandle + 68);
            int realD3D = *(int*)(realHandle + 68);

            *(int*)(placeholderHandle + 68) = realD3D;

            *(short*)(placeholderHandle + 76) = *(short*)(realHandle + 76);
            *(short*)(placeholderHandle + 78) = *(short*)(realHandle + 78);
            *(int*)(placeholderHandle + 80) = *(int*)(realHandle + 80);
            *(int*)(placeholderHandle + 84) = *(int*)(realHandle + 84);

            // Reclaim placeholder D3D resource via temp object release
            *(int*)(realHandle + 68) = placeholderD3D;
            return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Safe handling of exception if pointer is invalid
    }
    return false;
}

void OnFrame() {
    if (!Config::g_settings.OptAsyncTexLoader) return;
#if TEST_DISABLE_TEXTURE_DECODE_MT
    return;
#endif
    std::vector<PlaceholderEntry> completed;

    {
        WinLockGuard lock(g_swapMutex);
        WinLockGuard cacheLock(g_fileCacheMutex);

        auto it = g_placeholderMap.begin();
        while (it != g_placeholderMap.end()) {
            if (g_fileMemoryCache.count(it->first) && 
                g_fileMemoryCache[it->first].size() != g_whiteTextureBytes.size()) {
                completed.push_back(it->second);
                it = g_placeholderMap.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (const auto& entry : completed) {
        std::string tempPath = entry.realPath + "_tmp";

        {
            WinLockGuard cacheLock(g_fileCacheMutex);
            g_fileMemoryCache[tempPath] = g_fileMemoryCache[entry.realPath];
        }

        int real = Call_Orig_TexCreateBLP(entry.flags, const_cast<char*>(tempPath.c_str()), entry.a3, entry.a4);
        if (real) {
            bool swapped = SafeSwapPointers(entry.placeholderHandle, real);

            if (swapped) {
                WinLockGuard lock(g_swapMutex);
                g_hotSwapTextures.insert(entry.realPath);
            }

            // Release the temporary real texture handle (now holding the placeholder resource)
            if (orig_TextureRelease) {
                orig_TextureRelease((void*)real);
            }
        }

        {
            WinLockGuard cacheLock(g_fileCacheMutex);
            g_fileMemoryCache.erase(tempPath);
            g_fileMemoryCache.erase(entry.realPath);
        }
    }
}

bool Init() {
    if (!Config::g_settings.OptAsyncTexLoader) {
        Log("[AsyncTexLoader] DISABLED via configuration");
        return true;
    }
#if TEST_DISABLE_TEXTURE_DECODE_MT
    Log("[AsyncTexLoader] Disabled via TEST_DISABLE_TEXTURE_DECODE_MT");
    return true;
#endif
    if (!LoadStormAPIs()) return false;
    OpenPrivateArchives();

    if (!LoadPlaceholderTextureBytes()) {
        Log("[AsyncTexLoader] Failed to pre-load WHITE8X8 placeholder bytes.");
        return false;
    }

    g_shutdown = false;
    g_workerThread = CreateThread(NULL, 0, WorkerThreadProc, NULL, 0, NULL);

    void* target = (void*)0x004B8910;
    if (MH_CreateHook(target, (void*)Hooked_TexCreateBLP_Naked, (void**)&orig_TexCreateBLP) != MH_OK) {
        Log("[AsyncTexLoader] Failed to create TexCreateBLP hook.");
        return false;
    }

    if (MH_EnableHook(target) != MH_OK) {
        Log("[AsyncTexLoader] Failed to enable TexCreateBLP hook.");
        return false;
    }

    void* releaseTarget = (void*)0x004B83F0;
    if (MH_CreateHook(releaseTarget, (void*)Hooked_TextureRelease, (void**)&orig_TextureRelease) != MH_OK) {
        Log("[AsyncTexLoader] Failed to create TextureRelease hook.");
        return false;
    }

    if (MH_EnableHook(releaseTarget) != MH_OK) {
        Log("[AsyncTexLoader] Failed to enable TextureRelease hook.");
        return false;
    }

    Log("[AsyncTexLoader] Active - VFS redirector and hot-swapper active.");
    return true;
}

void Shutdown() {
    if (!Config::g_settings.OptAsyncTexLoader) return;
#if TEST_DISABLE_TEXTURE_DECODE_MT
    return;
#endif
    g_shutdown.store(true);
    g_queueCv.notify_all();
    if (g_workerThread) {
        WaitForSingleObject(g_workerThread, INFINITE);
        CloseHandle(g_workerThread);
        g_workerThread = nullptr;
    }

    void* target = (void*)0x004B8910;
    MH_DisableHook(target);
    MH_RemoveHook(target);

    void* releaseTarget = (void*)0x004B83F0;
    MH_DisableHook(releaseTarget);
    MH_RemoveHook(releaseTarget);

    for (HANDLE hArchive : g_privateArchives) {
        pSFileCloseArchive(hArchive);
    }
    g_privateArchives.clear();

    WinLockGuard cacheLock(g_fileCacheMutex);
    g_fileMemoryCache.clear();

    WinLockGuard lock(g_virtualHandlesMutex);
    for (auto pair : g_virtualHandles) {
        delete pair.second;
    }
    g_virtualHandles.clear();

    WinLockGuard swapLock(g_swapMutex);
    g_placeholderMap.clear();
    g_hotSwapTextures.clear();
}

} // namespace AsyncTexLoader
