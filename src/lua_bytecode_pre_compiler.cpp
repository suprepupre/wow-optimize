#include "lua_bytecode_pre_compiler.h"
#include "lua_optimize.h"
#include "version.h"
#include <vector>
#include <string>

extern "C" void Log(const char* fmt, ...);

namespace LuaBytecodePreCompiler {

static const int  WORKER_COUNT      = 2;
static const size_t QUEUE_SIZE      = 1024;
static const size_t QUEUE_MASK      = QUEUE_SIZE - 1;
static const size_t MAX_PRELOAD_BYTES = 128u * 1024u * 1024u;

struct Job { wchar_t path[MAX_PATH]; volatile LONG ready; };
static Job           g_queue[QUEUE_SIZE] = {};
static volatile LONG g_queueHead = 0;
static volatile LONG g_queueTail = 0;

static volatile LONG  g_active        = 0;
static volatile LONG  g_stop          = 0;
static HANDLE         g_workers[WORKER_COUNT] = {};
static HANDLE         g_wakeup        = nullptr;
static volatile LONG  g_filesScanned  = 0;
static volatile LONG  g_filesPreloaded = 0;
static volatile LONG64 g_bytesPreloaded = 0;

static void EnumerateDirRecursive(const wchar_t* dir, std::vector<std::wstring>& out, int depth) {
    if (depth > 6) return;
    wchar_t pattern[MAX_PATH];
    if (swprintf_s(pattern, MAX_PATH, L"%ls\\*", dir) < 0) return;

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.cFileName[0] == L'.') continue;
        wchar_t full[MAX_PATH];
        if (swprintf_s(full, MAX_PATH, L"%ls\\%ls", dir, fd.cFileName) < 0) continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            EnumerateDirRecursive(full, out, depth + 1);
        } else {
            size_t n = wcslen(fd.cFileName);
            bool isAddonFile = (n >= 4 && _wcsicmp(fd.cFileName + n - 4, L".lua") == 0)
                            || (n >= 4 && _wcsicmp(fd.cFileName + n - 4, L".toc") == 0)
                            || (n >= 4 && _wcsicmp(fd.cFileName + n - 4, L".xml") == 0);
            if (isAddonFile) {
                out.emplace_back(full);
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

static bool TryEnqueue(const wchar_t* path) {
    LONG head = g_queueHead;
    LONG next = (head + 1) & (LONG)QUEUE_MASK;
    if (next == g_queueTail) return false;
    wcsncpy_s(g_queue[head].path, MAX_PATH, path, _TRUNCATE);
    InterlockedExchange(&g_queue[head].ready, 1);
    InterlockedExchange(&g_queueHead, next);
    SetEvent(g_wakeup);
    return true;
}

static DWORD WINAPI Worker(LPVOID) {
    while (!g_stop) {
        WaitForSingleObject(g_wakeup, 500);

        // Only preload during loading screens to avoid I/O contention during gameplay
        if (!LuaOpt::IsLoadingMode()) continue;

        for (;;) {
            LONG tail = g_queueTail;
            if (tail == g_queueHead || !g_queue[tail].ready) break;

            // Re-check loading mode before each file read
            if (!LuaOpt::IsLoadingMode()) break;

            wchar_t path[MAX_PATH];
            wcsncpy_s(path, MAX_PATH, g_queue[tail].path, _TRUNCATE);
            InterlockedExchange(&g_queue[tail].ready, 0);
            InterlockedExchange(&g_queueTail, (tail + 1) & (LONG)QUEUE_MASK);

            if ((uint64_t)g_bytesPreloaded >= MAX_PRELOAD_BYTES) continue;

            HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
            if (h == INVALID_HANDLE_VALUE) continue;

            LARGE_INTEGER sz; sz.QuadPart = 0;
            GetFileSizeEx(h, &sz);
            if (sz.QuadPart > 0 && sz.QuadPart < 4 * 1024 * 1024) {
                char buf[8192];
                DWORD got = 0;
                LONG64 read = 0;
                while (ReadFile(h, buf, sizeof(buf), &got, NULL) && got > 0) {
                    read += got;
                }
                InterlockedIncrement(&g_filesPreloaded);
                InterlockedExchangeAdd64(&g_bytesPreloaded, read);
            }
            CloseHandle(h);
        }
    }
    return 0;
}

static void EnqueueWowAddonRoots() {
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) return;

    wchar_t* slash = wcsrchr(exePath, L'\\');
    if (!slash) return;
    *slash = 0;

    wchar_t addonsDir[MAX_PATH];
    swprintf_s(addonsDir, MAX_PATH, L"%ls\\Interface\\AddOns", exePath);

    std::vector<std::wstring> files;
    EnumerateDirRecursive(addonsDir, files, 0);
    InterlockedExchange(&g_filesScanned, (LONG)files.size());

    for (auto& f : files) TryEnqueue(f.c_str());
}

static DWORD WINAPI EnumeratorThread(LPVOID) {
    // Sleep 15s to avoid competing with login screen rendering
    Sleep(15000);
    if (g_stop) return 0;
    EnqueueWowAddonRoots();
    Log("[LuaPreCompile] enumeration complete, scanned=%ld files", g_filesScanned);
    return 0;
}

bool Init() {
    g_wakeup = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!g_wakeup) return false;

    for (int i = 0; i < WORKER_COUNT; i++) {
        g_workers[i] = CreateThread(NULL, 0, Worker, NULL, 0, NULL);
        if (g_workers[i]) SetThreadPriority(g_workers[i], THREAD_PRIORITY_LOWEST);
    }
    InterlockedExchange(&g_active, 1);

    // Defer addon enumeration to background thread with delay
    // to avoid blocking the login screen
    HANDLE hEnum = CreateThread(NULL, 0, EnumeratorThread, NULL, 0, NULL);
    if (hEnum) {
        SetThreadPriority(hEnum, THREAD_PRIORITY_LOWEST);
        CloseHandle(hEnum);
    }
    Log("[LuaPreCompile] active workers=%d (enumeration deferred 15s)", WORKER_COUNT);
    return true;
}

void Shutdown() {
    InterlockedExchange(&g_active, 0);
    InterlockedExchange(&g_stop, 1);
    if (g_wakeup) for (int i = 0; i < WORKER_COUNT; i++) SetEvent(g_wakeup);
    for (int i = 0; i < WORKER_COUNT; i++) {
        if (!g_workers[i]) continue;
        if (WaitForSingleObject(g_workers[i], 2000) == WAIT_TIMEOUT)
            TerminateThread(g_workers[i], 0);
        CloseHandle(g_workers[i]);
        g_workers[i] = nullptr;
    }
    if (g_wakeup) { CloseHandle(g_wakeup); g_wakeup = nullptr; }
    Log("[LuaPreCompile] shutdown preloaded=%ld bytes=%lld",
        g_filesPreloaded, (long long)g_bytesPreloaded);
}

void OnFrame() { /* worker-driven, nothing per-frame */ }

void GetStats(Stats* out) {
    if (!out) return;
    out->active         = g_active != 0;
    out->filesScanned   = (uint32_t)g_filesScanned;
    out->filesPreloaded = (uint32_t)g_filesPreloaded;
    out->bytesPreloaded = (uint64_t)g_bytesPreloaded;
    out->workers        = WORKER_COUNT;
    LONG h = g_queueHead, t = g_queueTail;
    out->queueDepth = (uint32_t)((h - t) & (LONG)QUEUE_MASK);
}

} // namespace LuaBytecodePreCompiler
