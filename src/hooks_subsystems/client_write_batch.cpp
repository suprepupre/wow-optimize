// ============================================================================
// A tester's loading screen: 16828 ms, of which 2470 ms - fifteen percent - was
// inside the client's own file writes. 593,557 of them, for 5.6 MB. Nine bytes
// a call.
//
// sub_454910 is why. It is the client's whole write path and it is a thin
// wrapper: check the handle, call WriteFile, store the count, report an error if
// it failed. No buffering anywhere. So every nine-byte piece of every
// SavedVariables file is one kernel transition, and a player with forty addons
// pays two and a half seconds of it on every loading screen and every /reload.
//
// This gathers those writes and issues them in 64 KB pieces. The saving is the
// syscall count: 593,557 becomes about ninety.
// ---------------------------------------------------------------------------
// The part that has to be right
//
// This is the SavedVariables path, and a file that loses its tail is a player
// losing their interface. A buffer that misses one flush does exactly that, so
// the design is built around not being able to.
//
// **One file at a time.** There is a single buffer and a single owner. A write
// for any other file flushes the current one first. That is not a limitation in
// practice - the client opens a SavedVariables file, writes it, closes it, and
// moves to the next - and it means the state to reason about is one pointer, one
// handle and one length, instead of a table with a lifetime.
//
// **Flushed from every exit.** CloseHandle, FlushFileBuffers, SetFilePointer and
// ReadFile on the same handle, any write to a different file, any overlapped or
// large write, the end of a loading screen, the periodic tick, and process exit.
// The one that must not be missed is CloseHandle, so this refuses to install at
// all unless that hook is up.
//
// **It checks itself.** Every byte the client hands over is counted. At close,
// the file's size on disk is read back and compared against that count. They
// must be equal; anything else means bytes were lost, and the module retires for
// the session and says so in the verdict. This is the same shape as the SIMD
// replacements here: run, compare against what the client would have done, and
// stand down on the first disagreement.
//
// The check is not free of assumptions. It holds for a file the client opens,
// writes from the start and closes, which is what SavedVariables are. A file
// opened for append, or seeked before writing, will not match - so a seek on the
// handle flushes and stops the file being verified rather than reporting a
// failure that is not one.
// ---------------------------------------------------------------------------
// What changes for the client, said plainly
//
// The error path moves. If a write fails - a full disk, a file locked by
// something else - the client used to find out on the call that failed. Now it
// finds out on the flush, which is later and may be on a different call. Both
// end with a broken file; only the moment it is noticed differs. Nothing else
// about the client's behaviour changes: the flush goes through sub_454910
// itself, so the handle check, the byte count it writes back, the error code it
// sets and the message it formats are the client's own.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

#include "client_write_batch.h"
#include "version.h"
#include "config.h"
#include "win_mutex.h"
#include "session_verdict.h"

extern "C" void Log(const char* fmt, ...);

#if TEST_DISABLE_CLIENT_WRITE_BATCH == 0

namespace ClientWriteBatch {
namespace {

// 64 KB. Large enough that a 5.6 MB session is ninety syscalls instead of six
// hundred thousand, small enough that holding it costs nothing worth naming.
const unsigned long kBufBytes  = 64 * 1024;
// A write at or above this goes straight through. Batching a large write saves
// nothing and only delays it.
const unsigned long kMaxAbsorb = 16 * 1024;

WinMutex   g_lock;
bool       g_installed = false;
bool       g_dead      = false;

WriteFn    g_write     = nullptr;

void*      g_owner     = nullptr;   // the client's file object we are buffering
HANDLE     g_handle    = nullptr;   // its Win32 handle, read at the time we took it
bool       g_verify    = true;      // false once a seek makes the size check meaningless
unsigned long long g_ownerBytes = 0; // everything the client handed us for this file
unsigned char g_buf[kBufBytes];
unsigned long g_len = 0;

// Counters. Main thread in practice, but the lock covers them either way.
unsigned long long g_absorbed   = 0;   // writes taken into the buffer
unsigned long long g_absorbedB  = 0;
unsigned long long g_passed     = 0;   // writes handed straight through
unsigned long long g_flushes    = 0;   // real WriteFile calls we made
unsigned long      g_filesOk    = 0;   // closed and verified byte for byte
unsigned long      g_filesUnver = 0;   // closed, but a seek made the check invalid
unsigned long      g_mismatch   = 0;

const char* NameOf(void* fileObj) {
    __try {
        const char* n = *(const char* const*)((const unsigned char*)fileObj + 76);
        if (n > (const char*)0x10000 && n < (const char*)0xFFE00000) return n;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return "(unnamed)";
}

HANDLE HandleOf(void* fileObj) {
    __try {
        return *(HANDLE*)fileObj;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return INVALID_HANDLE_VALUE;
}

// Push what we hold through the client's own writer. Caller holds the lock.
// Returns false when the client reported a failure, which retires the module:
// once a flush has failed the file is already wrong and continuing to buffer it
// would only add to the damage.
bool FlushLocked() {
    if (g_len == 0 || !g_owner || !g_write) { g_len = 0; return true; }
    const unsigned long want = g_len;
    unsigned long bytes = want;      // in: what to write, out: what was written
    g_len = 0;                       // cleared before the call, so a re-entrant
                                     // one cannot see the same bytes twice
    ++g_flushes;
    const char ok = g_write(g_owner, g_buf, nullptr, &bytes);
    // A short write is a failure here even when the client calls it success: the
    // file is already missing bytes and nothing later can put them back.
    return ok != 0 && bytes == want;
}

// Copy into the buffer, guarded. No destructors here, so __try is allowed.
bool CopyIn(const void* src, unsigned long bytes) {
    __try {
        memcpy(g_buf + g_len, src, bytes);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The client clears the byte at fileObj+8 on the way into every write, before it
// calls WriteFile. A write this module absorbs has to leave the object in the
// same state as one the client performed, or something that reads that byte sees
// a value the original would have cleared.
void ClearWriteFlag(void* fileObj) {
    __try {
        *((unsigned char*)fileObj + 8) = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

void DropOwner() {
    g_owner = nullptr;
    g_handle = nullptr;
    g_ownerBytes = 0;
    g_verify = true;
}

}  // namespace

bool Init(WriteFn writer, bool closeHookInstalled) {
    if (!Config::g_settings.OptClientWriteBatch) return true;
    if (!writer) {
        Log("[WriteBatch] NOT active: the client's write wrapper is not hooked, "
            "so there is nothing to batch.");
        return false;
    }
    if (!closeHookInstalled) {
        // The one flush that cannot be missed. Without it a buffered file would
        // be closed with its tail still in memory, which is the exact failure
        // this module must not cause.
        Log("[WriteBatch] NOT active: the CloseHandle hook did not install, and "
            "that is where a buffered file gets flushed.");
        return false;
    }
    g_write = writer;
    g_installed = true;
    Log("[WriteBatch] ACTIVE: the client writes SavedVariables about nine bytes "
        "at a time - a tester's loading screen spent 2470 ms of 16828 in 593557 "
        "of those calls, for 5.6 MB. They are gathered into %u KB pieces here. "
        "One file is buffered at a time, every exit flushes it, and each file's "
        "size on disk is checked against what the client handed over.",
        kBufBytes / 1024);
    return true;
}

bool TryAbsorb(void* fileObj, const void* buf, unsigned long bytes,
               void* overlapped) {
    if (!g_installed || g_dead || !fileObj || !buf) return false;
    // An overlapped write is the caller asking for its own completion; never
    // absorb one. A large write saves nothing by waiting.
    if (overlapped || bytes == 0 || bytes >= kMaxAbsorb) {
        WinLockGuard g(g_lock);
        ++g_passed;
        if (g_owner == fileObj) {
            if (!FlushLocked()) { g_dead = true; }
            g_ownerBytes += bytes;   // still this file's, still counted
        }
        return false;
    }

    WinLockGuard g(g_lock);
    if (g_owner != fileObj) {
        if (!FlushLocked()) { g_dead = true; return false; }
        DropOwner();
        HANDLE h = HandleOf(fileObj);
        if (h == INVALID_HANDLE_VALUE || h == nullptr) return false;
        g_owner  = fileObj;
        g_handle = h;
    }

    if (g_len + bytes > kBufBytes) {
        if (!FlushLocked()) { g_dead = true; return false; }
    }
    // Split out because MSVC will not put __try and an object with a destructor
    // in one function, and this one holds a lock guard.
    if (!CopyIn(buf, bytes)) return false;  // unreadable source: let the client try
    ClearWriteFlag(fileObj);
    g_len += bytes;
    g_ownerBytes += bytes;
    ++g_absorbed;
    g_absorbedB += bytes;
    return true;
}

void FlushHandle(HANDLE h, bool stopVerifying) {
    if (!g_installed || !h) return;
    // Read before locking. This is called from the ReadFile and SetFilePointer
    // hooks, which every part of the process goes through - one loading screen
    // makes fifteen thousand reads - and taking a lock on each of them to
    // discover there is nothing buffered is a cost paid by everything to serve
    // one file. An empty buffer has nothing to lose, and a buffer that fills
    // between this read and the lock belongs to a thread writing the same handle
    // that this one is reading, which is the client's own race and not one this
    // introduces.
    if (g_len == 0) return;
    WinLockGuard g(g_lock);
    if (g_handle != h) return;
    if (!FlushLocked()) g_dead = true;
    if (stopVerifying) g_verify = false;
}

void OnClosing(HANDLE h) {
    if (!g_installed || !h) return;

    void* owner = nullptr;
    unsigned long long expect = 0;
    bool verify = false;
    char name[MAX_PATH] = "";
    {
        WinLockGuard g(g_lock);
        if (g_handle != h) return;
        if (!FlushLocked()) g_dead = true;
        owner  = g_owner;
        expect = g_ownerBytes;
        verify = g_verify && !g_dead;
        DropOwner();
    }
    if (owner) lstrcpynA(name, NameOf(owner), (int)sizeof(name));

    // The check. The file is still open here - CloseHandle has not run yet - so
    // its size is readable, and for a file written from the start it must equal
    // everything the client handed over.
    if (!verify || expect == 0) {
        if (expect) ++g_filesUnver;
        return;
    }
    LARGE_INTEGER sz = {};
    if (!GetFileSizeEx(h, &sz)) { ++g_filesUnver; return; }
    if ((unsigned long long)sz.QuadPart == expect) {
        ++g_filesOk;
        return;
    }
    ++g_mismatch;
    g_dead = true;
    Log("[WriteBatch] DISABLED: %s is %llu bytes on disk and the client handed "
        "over %llu. Bytes went missing, which is the one thing this must never "
        "do, so every write from here on goes straight to the client.",
        name, (unsigned long long)sz.QuadPart, expect);
    Verdict::Add(Verdict::Bad,
                 "the write batcher lost bytes on %s and retired itself", name);
}

void FlushAll(const char* /*why*/) {
    if (!g_installed) return;
    WinLockGuard g(g_lock);
    if (!FlushLocked()) g_dead = true;
}

void LogStats() {
    if (!Config::g_settings.OptClientWriteBatch) return;
    if (!g_installed) { Log("[WriteBatch] not installed - nothing measured"); return; }
    if (g_absorbed == 0 && g_passed == 0) {
        Log("[WriteBatch] installed, and the client has not written a file yet.");
        return;
    }
    Log("[WriteBatch] %llu write(s) gathered into %llu real one(s), %llu KB. "
        "That is %llu system calls the client did not make.",
        g_absorbed, g_flushes, g_absorbedB / 1024,
        g_absorbed > g_flushes ? g_absorbed - g_flushes : 0);
    Log("[WriteBatch]   %lu file(s) closed and verified byte for byte, %lu not "
        "checkable because the client seeked in them%s",
        g_filesOk, g_filesUnver,
        g_dead ? " - RETIRED, see the line above" : "");
}

}  // namespace ClientWriteBatch

#endif  // TEST_DISABLE_CLIENT_WRITE_BATCH == 0
