// ================================================================
// Multithreaded Nameplate Renderer — Implementation
// WoW 3.3.5a build 12340
// ================================================================

#include "nameplate_batch.h"
#include "version.h"
#include "MinHook.h"
#include <cstdio>
#include <cstring>
#include <intrin.h>

extern "C" void Log(const char* fmt, ...);

// ================================================================
// Constants
// ================================================================
static constexpr int QUEUE_SIZE = 4096;
static constexpr int QUEUE_MASK = QUEUE_SIZE - 1;
static constexpr int WORKER_THREAD_COUNT = 2;

// ================================================================
// Statistics (atomic counters)
// ================================================================
static volatile LONG g_tasksQueued = 0;
static volatile LONG g_tasksProcessed = 0;
static volatile LONG g_tasksDropped = 0;
static volatile LONG g_resultsProcessed = 0;
static volatile LONG g_exceptionsHandled = 0;

static volatile LONG g_nameplatesPerSecond = 0;
static volatile LONG g_avgProcessingTimeUs = 0;
static volatile LONG g_queueUtilizationPct = 0;
static volatile LONG g_workerCpuUsagePct = 0;
static volatile LONG g_mainThreadTimeSavedMs = 0;

static volatile LONG g_fpsBeforeOptimization = 0;
static volatile LONG g_fpsAfterOptimization = 0;
static volatile LONG g_fpsImprovementPct = 0;

static volatile LONG g_inputQueueDepth = 0;
static volatile LONG g_outputQueueDepth = 0;
static volatile LONG g_maxInputQueueDepth = 0;
static volatile LONG g_maxOutputQueueDepth = 0;

// ================================================================
// Lock-Free Queues (4096 entries each, ring buffer)
// ================================================================
// WO_KEEP_BSS: see version.h — keeps clang-cl from putting these in .rdata.
WO_KEEP_BSS static NameplateMT::NameplateTask   g_inputQueue [QUEUE_SIZE] = {};
WO_KEEP_BSS static NameplateMT::NameplateResult g_outputQueue[QUEUE_SIZE] = {};
static volatile LONG g_inputHead = 0;  // Consumer index (worker threads)
static volatile LONG g_inputTail = 0;  // Producer index (main thread)
static volatile LONG g_outputHead = 0; // Consumer index (main thread)
static volatile LONG g_outputTail = 0; // Producer index (worker threads)

// ================================================================
// Worker Thread State
// ================================================================
static HANDLE g_workerThreads[WORKER_THREAD_COUNT] = {NULL};
static volatile bool g_workerShutdown = false;
static HANDLE g_workerEvent = NULL;
static LARGE_INTEGER g_qpcFreq = {0};
static bool g_initialized = false;

// ================================================================
// Memory Validation Helpers
// ================================================================
static bool IsReadable(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD);
}

static bool IsExecutable(uintptr_t addr) {
    if (addr == 0) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((void*)addr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// ================================================================
// Lock-Free Queue Operations
// ================================================================

// Queue a nameplate task for worker thread processing
static bool QueueNameplateTask(const NameplateMT::NameplateTask* task) {
    LONG tail = InterlockedIncrement(&g_inputTail) - 1;
    int slot = tail & QUEUE_MASK;
    
    // Check for queue overflow
    LONG head = g_inputHead;
    if (((tail - head) & 0x7FFFFFFF) >= QUEUE_SIZE) {
        InterlockedIncrement(&g_tasksDropped);
        Log("[NameplateMT] WARNING: Input queue overflow, dropping task");
        return false;
    }
    
    // Copy task data (avoid pointer sharing)
    memcpy(&g_inputQueue[slot], task, sizeof(NameplateMT::NameplateTask));
    
    // Signal worker threads
    SetEvent(g_workerEvent);
    InterlockedIncrement(&g_tasksQueued);
    
    // Update queue depth statistics
    LONG depth = (tail - head + 1) & 0x7FFFFFFF;
    InterlockedExchange(&g_inputQueueDepth, depth);
    
    // Update max depth if needed
    LONG maxDepth = g_maxInputQueueDepth;
    while (depth > maxDepth) {
        LONG prev = InterlockedCompareExchange(&g_maxInputQueueDepth, depth, maxDepth);
        if (prev == maxDepth) break;
        maxDepth = prev;
    }
    
    return true;
}

// Dequeue a nameplate task for processing (worker thread)
static bool DequeueNameplateTask(NameplateMT::NameplateTask* task) {
    LONG head = InterlockedCompareExchange(&g_inputHead, 0, 0); // Read atomically
    LONG tail = g_inputTail;
    
    if (head == tail) return false; // Queue empty
    
    int slot = head & QUEUE_MASK;
    memcpy(task, &g_inputQueue[slot], sizeof(NameplateMT::NameplateTask));
    
    InterlockedIncrement(&g_inputHead);
    return true;
}

// Queue a nameplate result for main thread consumption (worker thread)
static bool QueueNameplateResult(const NameplateMT::NameplateResult* result) {
    LONG tail = InterlockedIncrement(&g_outputTail) - 1;
    int slot = tail & QUEUE_MASK;
    
    // Check for queue overflow
    LONG head = g_outputHead;
    if (((tail - head) & 0x7FFFFFFF) >= QUEUE_SIZE) {
        InterlockedIncrement(&g_tasksDropped);
        Log("[NameplateMT] WARNING: Output queue overflow, dropping result");
        return false;
    }
    
    // Copy result data (avoid pointer sharing)
    memcpy(&g_outputQueue[slot], result, sizeof(NameplateMT::NameplateResult));
    
    // Update queue depth statistics
    LONG depth = (tail - head + 1) & 0x7FFFFFFF;
    InterlockedExchange(&g_outputQueueDepth, depth);
    
    // Update max depth if needed
    LONG maxDepth = g_maxOutputQueueDepth;
    while (depth > maxDepth) {
        LONG prev = InterlockedCompareExchange(&g_maxOutputQueueDepth, depth, maxDepth);
        if (prev == maxDepth) break;
        maxDepth = prev;
    }
    
    return true;
}

// Dequeue a nameplate result for UI application (main thread)
static bool DequeueNameplateResult(NameplateMT::NameplateResult* result) {
    LONG head = InterlockedCompareExchange(&g_outputHead, 0, 0); // Read atomically
    LONG tail = g_outputTail;
    
    if (head == tail) return false; // Queue empty
    
    int slot = head & QUEUE_MASK;
    memcpy(result, &g_outputQueue[slot], sizeof(NameplateMT::NameplateResult));
    
    InterlockedIncrement(&g_outputHead);
    InterlockedIncrement(&g_resultsProcessed);
    return true;
}

// ================================================================
// Nameplate Processing Functions (Worker Thread)
// ================================================================

// Process health update task
static void ProcessHealthUpdate(const NameplateMT::NameplateTask* task, NameplateMT::NameplateResult* result) {
    __try {
        // Calculate health percentage
        float healthPercent = 0.0f;
        if (task->healthMax > 0) {
            healthPercent = (float)task->healthCurrent / (float)task->healthMax;
        }
        
        // Determine health bar color based on percentage
        DWORD healthBarColor = 0xFF00FF00; // Green
        if (healthPercent < 0.25f) {
            healthBarColor = 0xFFFF0000; // Red
        } else if (healthPercent < 0.50f) {
            healthBarColor = 0xFFFF8000; // Orange
        } else if (healthPercent < 0.75f) {
            healthBarColor = 0xFFFFFF00; // Yellow
        }
        
        result->healthBarColor = healthBarColor;
        result->healthPercent = healthPercent;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement(&g_exceptionsHandled);
        result->healthBarColor = 0xFFFFFFFF; // White (error)
        result->healthPercent = 0.0f;
    }
}

// Process text update task
static void ProcessTextUpdate(const NameplateMT::NameplateTask* task, NameplateMT::NameplateResult* result) {
    __try {
        // Format nameplate text: "[Level] Name <Guild>"
        char formatted[128] = {0};
        
        if (task->unitLevel > 0) {
            if (task->guildName[0] != '\0') {
                _snprintf_s(formatted, sizeof(formatted), _TRUNCATE, 
                           "[%d] %s <%s>", task->unitLevel, task->unitName, task->guildName);
            } else {
                _snprintf_s(formatted, sizeof(formatted), _TRUNCATE, 
                           "[%d] %s", task->unitLevel, task->unitName);
            }
        } else {
            if (task->guildName[0] != '\0') {
                _snprintf_s(formatted, sizeof(formatted), _TRUNCATE, 
                           "%s <%s>", task->unitName, task->guildName);
            } else {
                _snprintf_s(formatted, sizeof(formatted), _TRUNCATE, 
                           "%s", task->unitName);
            }
        }
        
        memcpy(result->formattedText, formatted, sizeof(result->formattedText));
        result->textColor = 0xFFFFFFFF; // White
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement(&g_exceptionsHandled);
        memset(result->formattedText, 0, sizeof(result->formattedText));
        result->textColor = 0xFFFF0000; // Red (error)
    }
}

// Process color update task
static void ProcessColorUpdate(const NameplateMT::NameplateTask* task, NameplateMT::NameplateResult* result) {
    __try {
        // Blend class color with threat color based on threat level
        DWORD finalColor = task->classColor;
        
        if (task->threatLevel > 0.0f) {
            // Blend with threat color (red) based on threat level
            float threatBlend = task->threatLevel;
            if (threatBlend > 1.0f) threatBlend = 1.0f;
            
            BYTE classR = (task->classColor >> 16) & 0xFF;
            BYTE classG = (task->classColor >> 8) & 0xFF;
            BYTE classB = task->classColor & 0xFF;
            
            BYTE threatR = (task->threatColor >> 16) & 0xFF;
            BYTE threatG = (task->threatColor >> 8) & 0xFF;
            BYTE threatB = task->threatColor & 0xFF;
            
            BYTE finalR = (BYTE)(classR * (1.0f - threatBlend) + threatR * threatBlend);
            BYTE finalG = (BYTE)(classG * (1.0f - threatBlend) + threatG * threatBlend);
            BYTE finalB = (BYTE)(classB * (1.0f - threatBlend) + threatB * threatBlend);
            
            finalColor = 0xFF000000 | (finalR << 16) | (finalG << 8) | finalB;
        }
        
        result->finalColor = finalColor;
        result->borderColor = finalColor; // Same as final color for now
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement(&g_exceptionsHandled);
        result->finalColor = 0xFFFFFFFF; // White (error)
        result->borderColor = 0xFFFFFFFF;
    }
}

// Process visibility update task
static void ProcessVisibilityUpdate(const NameplateMT::NameplateTask* task, NameplateMT::NameplateResult* result) {
    __try {
        // Determine visibility based on flags and distance
        BOOL shouldShow = TRUE;
        float alpha = 1.0f;
        
        // Check visibility flags
        if ((task->flags & 0x01) == 0) {
            shouldShow = FALSE;
        }
        
        // Fade based on distance (beyond 40 yards)
        if (task->distance > 40.0f) {
            alpha = 1.0f - ((task->distance - 40.0f) / 20.0f);
            if (alpha < 0.0f) alpha = 0.0f;
            if (alpha < 0.1f) shouldShow = FALSE;
        }
        
        result->shouldShow = shouldShow;
        result->alpha = alpha;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedIncrement(&g_exceptionsHandled);
        result->shouldShow = TRUE; // Safe default
        result->alpha = 1.0f;
    }
}

// ================================================================
// Worker Thread Procedure
// ================================================================
static DWORD WINAPI WorkerThreadProc(LPVOID threadIndex) {
    DWORD workerIndex = (DWORD)(uintptr_t)threadIndex;
    Log("[NameplateMT] Worker thread %d started (TID: %d)", workerIndex, GetCurrentThreadId());

    while (!g_workerShutdown) {
        // Wait for work or timeout (100ms to check shutdown flag)
        WaitForSingleObject(g_workerEvent, 100);
        
        NameplateMT::NameplateTask task;
        while (DequeueNameplateTask(&task)) {
            LARGE_INTEGER startTime;
            QueryPerformanceCounter(&startTime);
            
            NameplateMT::NameplateResult result = {};
            result.nameplate = task.nameplate;
            result.type = task.type;
            
            // Process based on task type
            switch (task.type) {
                case NameplateMT::TASK_HEALTH_UPDATE:
                    ProcessHealthUpdate(&task, &result);
                    break;
                case NameplateMT::TASK_TEXT_UPDATE:
                    ProcessTextUpdate(&task, &result);
                    break;
                case NameplateMT::TASK_COLOR_UPDATE:
                    ProcessColorUpdate(&task, &result);
                    break;
                case NameplateMT::TASK_VISIBILITY_UPDATE:
                    ProcessVisibilityUpdate(&task, &result);
                    break;
            }
            
            LARGE_INTEGER endTime;
            QueryPerformanceCounter(&endTime);
            result.processingTimeUs = (DWORD)((endTime.QuadPart - startTime.QuadPart) * 1000000 / g_qpcFreq.QuadPart);
            
            // Queue result for main thread
            QueueNameplateResult(&result);
            
            InterlockedIncrement(&g_tasksProcessed);
        }
    }

    Log("[NameplateMT] Worker thread %d exiting", workerIndex);
    return 0;
}

// ================================================================
// Public API Implementation
// ================================================================
namespace NameplateMT {

bool Init() {
    // Emergency disable check
    #if TEST_DISABLE_NAMEPLATE_MT
    Log("[NameplateMT] Disabled via TEST_DISABLE_NAMEPLATE_MT flag");
    return false;
    #endif

    Log("[NameplateMT] Init (build 12340)");

    // Initialize QPC frequency for time measurements
    QueryPerformanceFrequency(&g_qpcFreq);

    // Initialize queue pointers
    g_inputHead = 0;
    g_inputTail = 0;
    g_outputHead = 0;
    g_outputTail = 0;

    // Create worker event
    g_workerEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!g_workerEvent) {
        Log("[NameplateMT] ERROR: Failed to create worker event");
        return false;
    }

    // Create worker threads
    g_workerShutdown = false;
    for (int i = 0; i < WORKER_THREAD_COUNT; i++) {
        g_workerThreads[i] = CreateThread(NULL, 0, WorkerThreadProc, (LPVOID)(uintptr_t)i, 0, NULL);
        if (!g_workerThreads[i]) {
            Log("[NameplateMT] ERROR: Failed to create worker thread %d", i);
            Shutdown();
            return false;
        }
        
        // Set worker thread priority
        SetThreadPriority(g_workerThreads[i], THREAD_PRIORITY_BELOW_NORMAL);
    }

    // TODO: Install hooks (Task 6)

    g_initialized = true;
    Log("[NameplateMT] [ OK ] Worker threads created (count: %d, queue size: %d)", 
        WORKER_THREAD_COUNT, QUEUE_SIZE);
    return true;
}

void Shutdown() {
    if (!g_initialized) return;

    Log("[NameplateMT] Shutdown");

    // Signal worker threads to exit
    g_workerShutdown = true;
    if (g_workerEvent) SetEvent(g_workerEvent);

    // Wait for worker threads (5 second timeout)
    for (int i = 0; i < WORKER_THREAD_COUNT; i++) {
        if (g_workerThreads[i]) {
            DWORD waitResult = WaitForSingleObject(g_workerThreads[i], 5000);
            if (waitResult == WAIT_TIMEOUT) {
                Log("[NameplateMT] WARNING: Worker thread %d did not exit, terminating", i);
                TerminateThread(g_workerThreads[i], 1);
            }
            CloseHandle(g_workerThreads[i]);
            g_workerThreads[i] = NULL;
        }
    }

    // Cleanup event
    if (g_workerEvent) {
        CloseHandle(g_workerEvent);
        g_workerEvent = NULL;
    }

    // TODO: Remove hooks (Task 6)

    // Log final stats
    Log("[NameplateMT] Final stats: Queued=%d, Processed=%d, Dropped=%d, Results=%d",
        g_tasksQueued, g_tasksProcessed, g_tasksDropped, g_resultsProcessed);

    g_initialized = false;
}

void OnFrame(DWORD mainThreadId) {
    if (!g_initialized) return;
    if (GetCurrentThreadId() != mainThreadId) return;

    // TODO: Process results from output queue (Task 7)
    // TODO: Update statistics (Task 9)
}

Stats GetStats() {
    Stats s;
    s.tasksQueued = g_tasksQueued;
    s.tasksProcessed = g_tasksProcessed;
    s.tasksDropped = g_tasksDropped;
    s.resultsProcessed = g_resultsProcessed;
    s.exceptionsHandled = g_exceptionsHandled;
    
    s.nameplatesPerSecond = g_nameplatesPerSecond;
    s.avgProcessingTimeUs = g_avgProcessingTimeUs;
    s.queueUtilizationPct = g_queueUtilizationPct;
    s.workerCpuUsagePct = g_workerCpuUsagePct;
    s.mainThreadTimeSavedMs = g_mainThreadTimeSavedMs;
    
    s.fpsBeforeOptimization = g_fpsBeforeOptimization;
    s.fpsAfterOptimization = g_fpsAfterOptimization;
    s.fpsImprovementPct = g_fpsImprovementPct;
    
    s.inputQueueDepth = g_inputQueueDepth;
    s.outputQueueDepth = g_outputQueueDepth;
    s.maxInputQueueDepth = g_maxInputQueueDepth;
    s.maxOutputQueueDepth = g_maxOutputQueueDepth;

    return s;
}

} // namespace NameplateMT
