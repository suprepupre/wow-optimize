// ============================================================================
// Module: addon_preload.cpp
// ============================================================================

#include "addon_preload.h"
#include "version.h"
#include "MinHook.h"
#include <cstdio>
#include <cstring>
#include <windows.h>
#include <string>
#include <unordered_map>
#include <vector>

extern "C" void Log(const char* fmt, ...);

// Set by DetectMultiClient() in dllmain.
extern bool g_isMultiClient;

#if !TEST_DISABLE_ADDON_PRELOAD

static std::unordered_map<std::string, std::vector<uint8_t>> g_cache;
static SRWLOCK g_cacheLock = SRWLOCK_INIT;
static volatile LONG g_ready = 0;

// Total bytes held in the in-memory cache, and a hard ceiling. Without a budget
// this RAM-disk grows to the full size of every addon file, which on the
// VA-constrained 32-bit client (especially with several clients each holding their
// own copy) feeds 32-bit address-space exhaustion. Stop caching past the ceiling;
// files beyond it simply fall through to normal disk/MPQ reads.
static volatile LONG64 g_cacheBytes = 0;
static constexpr LONG64 CACHE_BUDGET_BYTES = 192LL * 1024 * 1024;

// Track handles opened for addon files
static constexpr int MAX_HANDLES = 1024;
static HANDLE g_handles[MAX_HANDLES] = {};
static std::string g_handlePaths[MAX_HANDLES];
static volatile LONG g_handleCount = 0;
static SRWLOCK g_handleLock = SRWLOCK_INIT;

static volatile LONG g_hits = 0, g_misses = 0, g_filesLoaded = 0;

// Set by dllmain once it knows whether the CreateFile/CloseHandle hooks went in.
// Without them this cache has no way to learn which handle belongs to which file.
static volatile LONG g_fileHooksInstalled = 0;
static bool AddonPreload_FileHooksInstalled() {
    return InterlockedCompareExchange(&g_fileHooksInstalled, 0, 0) != 0;
}

// Worker threads
static HANDLE g_workers[2] = {};
static volatile LONG g_shutdown = 0;
static volatile LONG g_filesToLoad = 0;
static volatile LONG g_filesDone = 0;
static std::vector<std::string> g_fileList;
static SRWLOCK g_fileLock = SRWLOCK_INIT;

static DWORD WINAPI WorkerProc(LPVOID) {
    while (!InterlockedCompareExchange(&g_shutdown, 0, 0)) {
        std::string path;
        {
            AcquireSRWLockExclusive(&g_fileLock);
            if (g_filesDone < (LONG)g_fileList.size()) {
                path = g_fileList[g_filesDone++];
                ReleaseSRWLockExclusive(&g_fileLock);
            } else {
                ReleaseSRWLockExclusive(&g_fileLock);
                if (InterlockedDecrement(&g_filesToLoad) <= 0) break;
                SwitchToThread();
                continue;
            }
        }

        HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;

        DWORD size = GetFileSize(h, NULL);
        if (size > 0 && size < 16 * 1024 * 1024 &&
            g_cacheBytes + (LONG64)size <= CACHE_BUDGET_BYTES) {
            std::vector<uint8_t> data(size);
            DWORD read = 0;
            if (ReadFile(h, data.data(), size, &read, NULL) && read == size) {
                AcquireSRWLockExclusive(&g_cacheLock);
                g_cache[path] = std::move(data);
                ReleaseSRWLockExclusive(&g_cacheLock);
                InterlockedAdd64(&g_cacheBytes, (LONG64)size);
                InterlockedIncrement(&g_filesLoaded);
            }
        }
        CloseHandle(h);
    }
    return 0;
}

// Map handle → cache entry when WoW opens addon files
static std::string g_addonDir;

void AddonPreload_OnCreateFile(HANDLE hFile, const char* filename) {
    if (!InterlockedCompareExchange(&g_ready, 0, 0) || !hFile || hFile == INVALID_HANDLE_VALUE || !filename) return;

    // Only track files that are already in our pre-scan cache.
    // Files created/modified after init (SavedVariables, config)
    // must not be served from stale cache.
    AcquireSRWLockShared(&g_cacheLock);
    bool cached = (g_cache.find(filename) != g_cache.end());
    ReleaseSRWLockShared(&g_cacheLock);

    if (!cached) return;

    AcquireSRWLockExclusive(&g_handleLock);
    if (g_handleCount < MAX_HANDLES) {
        g_handles[g_handleCount] = hFile;
        g_handlePaths[g_handleCount] = filename;
        g_handleCount++;
    }
    ReleaseSRWLockExclusive(&g_handleLock);
}

// Invalidate cache entry when a tracked file is written to
void AddonPreload_OnWriteFile(const char* filename) {
    if (!InterlockedCompareExchange(&g_ready, 0, 0) || !filename) return;

    AcquireSRWLockExclusive(&g_cacheLock);
    g_cache.erase(filename);
    ReleaseSRWLockExclusive(&g_cacheLock);

    // Remove handle tracking
    AcquireSRWLockExclusive(&g_handleLock);
    for (LONG i = 0; i < g_handleCount; i++) {
        if (g_handlePaths[i] == filename) {
            // Swap with last
            g_handles[i] = g_handles[g_handleCount - 1];
            g_handlePaths[i].swap(g_handlePaths[g_handleCount - 1]);
            g_handles[g_handleCount - 1] = NULL;
            g_handlePaths[g_handleCount - 1].clear();
            g_handleCount--;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_handleLock);
}

bool AddonPreload_TryServe(HANDLE hFile, LPVOID lpBuffer, DWORD nBytes, LPDWORD lpBytesRead) {
    if (!InterlockedCompareExchange(&g_ready, 0, 0)) return false;

    // The caller is expected to have screened these already, but this function
    // memcpys into lpBuffer and the cost of being wrong is a write to address
    // zero. WoW calls ReadFile with a null buffer on purpose, to advance the file
    // pointer without reading, so this is a case that genuinely occurs rather
    // than a defensive formality.
    if (!lpBuffer || !nBytes) return false;

    // Nothing is tracked, so there is nothing to scan for. Worth its own check:
    // the loop below runs under a lock on every single ReadFile the client makes.
    if (InterlockedCompareExchange(&g_handleCount, 0, 0) == 0) return false;

    AcquireSRWLockShared(&g_handleLock);
    for (LONG i = 0; i < g_handleCount; i++) {
        if (g_handles[i] == hFile) {
            std::string path = g_handlePaths[i];
            ReleaseSRWLockShared(&g_handleLock);

            AcquireSRWLockShared(&g_cacheLock);
            auto it = g_cache.find(path);
            if (it != g_cache.end() && !it->second.empty()) {
                const auto& data = it->second;
                DWORD filePos = SetFilePointer(hFile, 0, NULL, FILE_CURRENT);
                if (filePos != INVALID_SET_FILE_POINTER && filePos < (DWORD)data.size()) {
                    DWORD toCopy = nBytes;
                    if (filePos + nBytes > (DWORD)data.size())
                        toCopy = (DWORD)data.size() - filePos;
                    memcpy(lpBuffer, data.data() + filePos, toCopy);
                    if (lpBytesRead) *lpBytesRead = toCopy;
                    SetFilePointer(hFile, filePos + toCopy, NULL, FILE_BEGIN);
                    InterlockedIncrement(&g_hits);
                    ReleaseSRWLockShared(&g_cacheLock);
                    return true;
                }
            }
            InterlockedIncrement(&g_misses);
            ReleaseSRWLockShared(&g_cacheLock);
            return false;
        }
    }
    ReleaseSRWLockShared(&g_handleLock);
    return false;
}

static void ScanAddonDir(const std::string& base, int depth) {
    if (depth > 5) return;
    WIN32_FIND_DATAA fd;
    std::string search = base + "\\*";
    HANDLE h = FindFirstFileA(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.') continue;
        std::string full = base + "\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ScanAddonDir(full, depth + 1);
        } else {
            const char* ext = strrchr(fd.cFileName, '.');
            if (ext && (_stricmp(ext, ".lua") == 0 || _stricmp(ext, ".toc") == 0
                     || _stricmp(ext, ".xml") == 0)) {
                AcquireSRWLockExclusive(&g_fileLock);
                g_fileList.push_back(full);
                ReleaseSRWLockExclusive(&g_fileLock);
                InterlockedIncrement(&g_filesToLoad);
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void AddonPreload_SetFileHooksInstalled(bool installed) {
    InterlockedExchange(&g_fileHooksInstalled, installed ? 1 : 0);
}

bool InitAddonPreload() {
    // Skip the RAM-disk entirely when several clients share the machine: each
    // client would hold its own full copy of every addon file, multiplying memory
    // and 32-bit VA pressure on exactly the configuration that hits OutOfMemory.
    // The ReadFile/CreateFile hooks tolerate an empty cache and fall through to
    // normal I/O, so single-client keeps the load-time win and multi-client trades
    // it for headroom.
    if (g_isMultiClient) {
        Log("[AddonPreload] Disabled in multi-client mode (memory/VA headroom)");
        return true;
    }

    // This cache is only reachable through the CreateFile and CloseHandle hooks:
    // CreateFile is what maps an opened handle onto a cached file, CloseHandle is
    // what releases that mapping. Both are installed together, and only when
    // DbcLookupCache is on - a switch that has nothing to do with addons and
    // defaults to off. (SavedVarsPretoken used to enable them too, until it
    // turned out to be a stub whose whole implementation was `return false`.)
    //
    // Without them nothing is ever tracked, so every read misses and the only
    // effect of this feature is reading several thousand files at startup and
    // holding up to 192 MB of them in a 32-bit address space for no reason.
    // Refusing here is the difference between a feature that does nothing and a
    // feature that costs a lot to do nothing.
    if (!AddonPreload_FileHooksInstalled()) {
        Log("[AddonPreload] Not started: the CreateFile/CloseHandle hooks it serves "
            "through are not installed (they need DbcLookupCache enabled). "
            "Nothing would be served from the cache.");
        return true;
    }

    // Find WoW AddOns directory
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    char* lastSep = strrchr(exePath, '\\');
    if (lastSep) *lastSep = 0;
    g_addonDir = std::string(exePath) + "\\Interface\\AddOns";
    std::string wtfDir = std::string(exePath) + "\\WTF\\Account";

    Log("[AddonPreload] Scanning: %s and %s", g_addonDir.c_str(), wtfDir.c_str());

    // Scan addon directory and SavedVariables directory
    ScanAddonDir(g_addonDir, 0);
    ScanAddonDir(wtfDir, 0);
    LONG total = g_filesToLoad;
    Log("[AddonPreload] Found %d files to preload", total);
    if (total == 0) return true;

    // Start workers
    InterlockedExchange(&g_shutdown, 0);
    for (int i = 0; i < 2; i++) {
        g_workers[i] = CreateThread(NULL, 0, WorkerProc, NULL, 0, NULL);
        if (g_workers[i])
            SetThreadPriority(g_workers[i], THREAD_PRIORITY_BELOW_NORMAL);
    }

    // Wait for workers to finish
    for (int i = 0; i < 2; i++) {
        if (g_workers[i]) {
            WaitForSingleObject(g_workers[i], 10000);
            CloseHandle(g_workers[i]);
            g_workers[i] = NULL;
        }
    }

    InterlockedExchange(&g_ready, 1);
    size_t totalBytes = 0;
    for (auto& p : g_cache) totalBytes += p.second.size();
    Log("[AddonPreload] Loaded %d files (%.1f MB)", g_filesLoaded,
        totalBytes / (1024.0 * 1024.0));
    return true;
}

void ShutdownAddonPreload() {
    InterlockedExchange(&g_shutdown, 1);
    InterlockedExchange(&g_ready, 0);
    for (int i = 0; i < 2; i++) {
        if (g_workers[i]) {
            WaitForSingleObject(g_workers[i], 2000);
            CloseHandle(g_workers[i]);
            g_workers[i] = NULL;
        }
    }
    g_cache.clear();
    g_handleCount = 0;
    Log("[AddonPreload] Shutdown: hits=%d misses=%d files=%d", g_hits, g_misses, g_filesLoaded);
}

void ClearAddonPreload() {
    AcquireSRWLockExclusive(&g_cacheLock);
    g_cache.clear();
    ReleaseSRWLockExclusive(&g_cacheLock);
    g_handleCount = 0;
}

void AddonPreload_OnCloseHandle(HANDLE hFile) {
    if (!InterlockedCompareExchange(&g_ready, 0, 0) || !hFile || hFile == INVALID_HANDLE_VALUE) return;

    AcquireSRWLockExclusive(&g_handleLock);
    for (LONG i = 0; i < g_handleCount; i++) {
        if (g_handles[i] == hFile) {
            // Swap with last
            g_handles[i] = g_handles[g_handleCount - 1];
            g_handlePaths[i].swap(g_handlePaths[g_handleCount - 1]);
            g_handles[g_handleCount - 1] = NULL;
            g_handlePaths[g_handleCount - 1].clear();
            g_handleCount--;
            break;
        }
    }
    ReleaseSRWLockExclusive(&g_handleLock);
}

#else
bool InitAddonPreload() { return false; }
void AddonPreload_SetFileHooksInstalled(bool) {}
void ShutdownAddonPreload() {}
void ClearAddonPreload() {}
void AddonPreload_OnCreateFile(HANDLE, const char*) {}
void AddonPreload_OnWriteFile(const char*) {}
void AddonPreload_OnCloseHandle(HANDLE) {}
bool AddonPreload_TryServe(HANDLE, LPVOID, DWORD, LPDWORD) { return false; }
#endif
