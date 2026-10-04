// ============================================================================
// Module: gx_buffers.cpp
//
// Vertex and index buffer Lock/Unlock for the D3D9 render thread.
//
// The client locks dynamic buffers all the time (text, UI, particles) and writes
// into them. Waiting for the render thread on each Lock would cancel the point of
// having one, so a Lock never waits: it hands the client memory that is ours, and
// the Unlock turns what was written into an upload command in the ring. The
// render thread performs the real Lock, the copy and the real Unlock, in order
// with the draws that use the data.
//
// Three classes, decided when the buffer is created:
//   DIRECT  D3DUSAGE_DYNAMIC and WRITEONLY. Lock returns a block of this frame's
//           arena and the client writes straight into it; Unlock queues it. There
//           is no copy on our side and nothing to read back, because a WRITEONLY
//           buffer has no contents the client may read.
//   SHADOW  Dynamic but readable, or a lock too large for the arena. Lock returns
//           a persistent system-memory copy of the whole buffer (mimalloc, made
//           when first needed); Unlock copies the locked range into the arena in
//           pieces and queues them.
//   SYNC    Everything else: static buffers and system-memory buffers. Lock drains
//           the ring so no queued draw can still be reading the old contents, then
//           locks the real buffer as before. These locks happen while loading.
//
// A buffer this file has no record of is treated as SYNC, which is always right.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <d3d9.h>
#include <stdint.h>
#include <string.h>
#include <mimalloc.h>

#include "gx_internal.h"
#include "version.h"
#include "high_tables.h"

extern "C" void Log(const char* fmt, ...);

namespace GxRT {

// Defined below, after the helpers they use; PatchVtable needs their addresses.
ULONG   __stdcall T_BufRelease(void* self);
HRESULT __stdcall T_BufLock(void* self, UINT off, UINT size, void** pp, DWORD flags);
HRESULT __stdcall T_BufUnlock(void* self);

namespace {

typedef HRESULT (__stdcall *LockFn)(void*, UINT, UINT, void**, DWORD);
typedef HRESULT (__stdcall *UnlockFn)(void*);
typedef ULONG   (__stdcall *ReleaseFn)(void*);

constexpr int kSlotRelease = 2, kSlotLock = 11, kSlotUnlock = 12;   // IDirect3DVertexBuffer9 / IndexBuffer9

// Every distinct vtable a buffer has been seen with. Appended by the creating
// thread; the count is published after the entry is complete.
struct VtInfo { uintptr_t* vt; LockFn lock; UnlockFn unlock; ReleaseFn release; };
constexpr int kMaxVt = 16;
VtInfo        g_vt[kMaxVt];
volatile LONG g_vtCount = 0;

VtInfo* FindVt(void* self) {
    uintptr_t* vt = *(uintptr_t**)self;
    const LONG n = g_vtCount;
    for (LONG i = 0; i < n; ++i) if (g_vt[i].vt == vt) return &g_vt[i];
    return nullptr;
}

enum : uint8_t { CLS_SYNC = 0, CLS_DIRECT = 1, CLS_SHADOW = 2 };
enum : uint8_t { MODE_NONE = 0, MODE_ARENA = 1, MODE_SHADOW = 2 };

struct Entry {
    void*    key;                 // 0 empty
    uint32_t size;
    uint8_t  cls, mode;
    uint16_t pad;
    uint32_t lockOff, lockSize, lockFlags;
    uint8_t* lockData;            // MODE_ARENA: the block the client is writing
    uint8_t* shadow;              // MODE_SHADOW and later: the persistent copy
};

constexpr uint32_t kTableBits = 15;
constexpr uint32_t kTableSize = 1u << kTableBits;
constexpr uint32_t kTableMask = kTableSize - 1;
Entry*        g_table = nullptr;
volatile LONG g_tblLock = 0;

// The render thread drops the last reference to a buffer, so the table is touched
// from two threads; the lock is held for a probe and never across a call out.
inline void TblLock()   { while (InterlockedCompareExchange(&g_tblLock, 1, 0) != 0) YieldProcessor(); }
inline void TblUnlock() { GX_COMPILER_BARRIER(); g_tblLock = 0; }

inline uint32_t HashKey(void* p) { return (((uint32_t)(uintptr_t)p >> 4) * 2654435761u) >> (32 - kTableBits); }

Entry* Find(void* key) {                                            // table lock held
    uint32_t i = HashKey(key);
    for (uint32_t n = 0; n < kTableSize; ++n, i = (i + 1) & kTableMask) {
        if (g_table[i].key == key) return &g_table[i];
        if (!g_table[i].key) return nullptr;
    }
    return nullptr;
}

bool Insert(void* key, uint32_t size, uint8_t cls) {                // table lock held
    uint32_t i = HashKey(key);
    for (uint32_t n = 0; n < kTableSize; ++n, i = (i + 1) & kTableMask) {
        if (!g_table[i].key || g_table[i].key == key) {
            if (g_table[i].key == key && g_table[i].shadow) mi_free(g_table[i].shadow);
            memset(&g_table[i], 0, sizeof(Entry));
            g_table[i].key = key; g_table[i].size = size; g_table[i].cls = cls;
            return true;
        }
    }
    return false;                                                   // full: this buffer stays untracked
}

// Linear probing with backward-shift deletion, so there are no tombstones to
// pile up under buffers being created and destroyed all session.
void Erase(void* key) {                                             // table lock held
    Entry* e = Find(key);
    if (!e) return;
    if (e->shadow) mi_free(e->shadow);
    uint32_t i = (uint32_t)(e - g_table), j = i;
    for (;;) {
        j = (j + 1) & kTableMask;
        if (!g_table[j].key) break;
        const uint32_t k = HashKey(g_table[j].key);
        const bool movable = (j > i) ? (k <= i || k > j) : (k <= i && k > j);
        if (movable) { g_table[i] = g_table[j]; i = j; }
    }
    memset(&g_table[i], 0, sizeof(Entry));
}

unsigned long g_lockDirect = 0, g_lockShadow = 0, g_lockSync = 0, g_lockOverflow = 0;
unsigned long g_uploads = 0, g_uploadInPlace = 0, g_tracked = 0, g_untracked = 0;
uint64_t      g_uploadBytes = 0;
LONG          g_live = 0;

void PatchVtable(void* obj) {
    if (FindVt(obj)) return;
    const LONG n = g_vtCount;
    if (n >= kMaxVt) return;
    uintptr_t* vt = *(uintptr_t**)obj;
    VtInfo v;
    v.vt = vt;
    v.lock = (LockFn)vt[kSlotLock]; v.unlock = (UnlockFn)vt[kSlotUnlock]; v.release = (ReleaseFn)vt[kSlotRelease];
    DWORD old = 0;
    if (!VirtualProtect(vt, 16 * sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) return;
    g_vt[n] = v;
    GX_COMPILER_BARRIER();
    g_vtCount = n + 1;                       // registered before any slot points at a thunk
    vt[kSlotLock] = (uintptr_t)&T_BufLock;
    vt[kSlotUnlock] = (uintptr_t)&T_BufUnlock;
    vt[kSlotRelease] = (uintptr_t)&T_BufRelease;
    VirtualProtect(vt, 16 * sizeof(void*), old, &old);
}

void Track(void* obj, UINT size, DWORD usage, D3DPOOL pool) {
    if (!g_table || !obj) return;
    PatchVtable(obj);
    if (!FindVt(obj)) return;
    uint8_t cls = CLS_SYNC;
    if ((usage & D3DUSAGE_DYNAMIC) && pool != D3DPOOL_SYSTEMMEM)
        cls = (usage & D3DUSAGE_WRITEONLY) ? CLS_DIRECT : CLS_SHADOW;
    TblLock();
    const bool ok = Insert(obj, size, cls);
    TblUnlock();
    if (ok) { ++g_tracked; InterlockedIncrement(&g_live); } else ++g_untracked;
}

// Hand a finished range to the render thread.
inline void Post(VtInfo* vi, void* self, const uint8_t* data, uint32_t off, uint32_t size, DWORD flags) {
    // The upload runs up to a few frames after the client's Unlock. Without a
    // reference of its own, a buffer the client releases in between is destroyed
    // before the render thread locks it, as the draws that name a buffer already
    // avoid by taking one. The render thread drops it after the upload.
    ((IUnknown*)self)->AddRef();
    CmdUpload* c = Emit<CmdUpload>(OP_BUFFER_UPLOAD);
    c->buf = self; c->lockFn = (void*)vi->lock; c->unlockFn = (void*)vi->unlock;
    c->data = data; c->offset = off; c->size = size; c->lockFlags = flags;
    ++g_uploads; g_uploadBytes += size;
}

// The same upload, done here after draining. Used when this frame's arena is full.
void UploadInPlace(VtInfo* vi, void* self, const uint8_t* data, uint32_t off, uint32_t size, DWORD flags) {
    Drain();
    void* p = nullptr;
    if (SUCCEEDED(vi->lock(self, off, size, &p, flags)) && p) {
        memcpy(p, data, size);
        vi->unlock(self);
    }
    ++g_uploadInPlace;
}

constexpr DWORD kRealLockMask = D3DLOCK_DISCARD | D3DLOCK_NOOVERWRITE | D3DLOCK_NOSYSLOCK;

}  // namespace

// ---- thunks -----------------------------------------------------------------------------
ULONG __stdcall T_BufRelease(void* self) {
    VtInfo* vi = FindVt(self);
    if (!vi) return 0;
    const ULONG r = vi->release(self);
    if (r == 0 && g_table) {
        TblLock();
        Erase(self);
        TblUnlock();
        InterlockedDecrement(&g_live);
    }
    return r;
}

HRESULT __stdcall T_BufLock(void* self, UINT off, UINT size, void** pp, DWORD flags) {
    VtInfo* vi = FindVt(self);
    if (!vi) return D3DERR_INVALIDCALL;
    if (!Live() || !g_table) return vi->lock(self, off, size, pp, flags);

    bool found = false;
    uint8_t cls = CLS_SYNC, mode = MODE_NONE;
    uint32_t bufSize = 0;
    TblLock();
    if (Entry* e = Find(self)) { found = true; cls = e->cls; mode = e->mode; bufSize = e->size; }
    TblUnlock();

    if (found && mode != MODE_NONE) return D3DERR_INVALIDCALL;              // already locked, as D3D9 says
    if (!found || cls == CLS_SYNC || off > bufSize) {
        ++g_lockSync;
        Drain();                                                            // no queued draw may still read the old contents
        return vi->lock(self, off, size, pp, flags);
    }
    if (size == 0 || off + size > bufSize) size = bufSize - off;
    if (size == 0) { ++g_lockSync; Drain(); return vi->lock(self, off, size, pp, flags); }

    uint8_t* direct = nullptr;
    uint8_t* shadow = nullptr;
    uint8_t  newMode = MODE_NONE;
    if (cls == CLS_DIRECT && size <= kMaxDirectLock && !(flags & D3DLOCK_READONLY)) {
        direct = g_arena.Alloc(size);
        if (!direct) {                                                      // this frame's arena is full: do it the old way
            ++g_lockOverflow;
            Drain();
            return vi->lock(self, off, size, pp, flags);
        }
        newMode = MODE_ARENA;
    } else {
        TblLock();
        Entry* e = Find(self);
        if (e && !e->shadow) e->shadow = (uint8_t*)mi_zalloc(e->size);
        shadow = e ? e->shadow : nullptr;
        TblUnlock();
        if (!shadow) { ++g_lockSync; Drain(); return vi->lock(self, off, size, pp, flags); }
        newMode = MODE_SHADOW;
    }

    TblLock();
    Entry* e = Find(self);
    if (!e) {                                                               // erased under us: cannot happen for a locked buffer
        TblUnlock();
        ++g_lockSync; Drain();
        return vi->lock(self, off, size, pp, flags);
    }
    e->mode = newMode; e->lockOff = off; e->lockSize = size; e->lockFlags = flags;
    e->lockData = direct;
    TblUnlock();

    if (newMode == MODE_ARENA) { *pp = direct; ++g_lockDirect; }
    else                       { *pp = shadow + off; ++g_lockShadow; }
    return D3D_OK;
}

HRESULT __stdcall T_BufUnlock(void* self) {
    VtInfo* vi = FindVt(self);
    if (!vi) return D3DERR_INVALIDCALL;
    if (!Live() || !g_table) return vi->unlock(self);

    uint8_t mode = MODE_NONE, *data = nullptr, *shadow = nullptr;
    uint32_t off = 0, size = 0, flags = 0;
    TblLock();
    if (Entry* e = Find(self)) {
        mode = e->mode; data = e->lockData; shadow = e->shadow;
        off = e->lockOff; size = e->lockSize; flags = e->lockFlags;
        e->mode = MODE_NONE; e->lockData = nullptr;
    }
    TblUnlock();

    if (mode == MODE_NONE) return vi->unlock(self);                         // a real lock (SYNC class or a fallback)
    if (flags & D3DLOCK_READONLY) return D3D_OK;

    const DWORD lf = flags & kRealLockMask;
    if (mode == MODE_ARENA) {
        Post(vi, self, data, off, size, lf);
        return D3D_OK;
    }
    // Shadow: snapshot the locked range into the arena and queue it, in pieces
    // no larger than a direct lock. Only the first piece may discard: the rest
    // write into a buffer that piece has already renamed.
    for (uint32_t c = 0; c < size; c += kMaxDirectLock) {
        const uint32_t n = (size - c < kMaxDirectLock) ? (size - c) : kMaxDirectLock;
        const DWORD pf = (c == 0 || !(lf & D3DLOCK_DISCARD)) ? lf : ((lf & ~D3DLOCK_DISCARD) | D3DLOCK_NOOVERWRITE);
        uint8_t* p = g_arena.Alloc(n);
        if (p) {
            memcpy(p, shadow + off + c, n);
            Post(vi, self, p, off + c, n, pf);
        } else {
            UploadInPlace(vi, self, shadow + off + c, off + c, n, pf);
        }
    }
    return D3D_OK;
}

HRESULT __stdcall T_CreateVertexBuffer(IDirect3DDevice9* d, UINT len, DWORD usage, DWORD fvf,
                                       D3DPOOL pool, IDirect3DVertexBuffer9** pp, HANDLE* shared) {
    const HRESULT hr = O<F_CreateVB>(26)(d, len, usage, fvf, pool, pp, shared);
    if (SUCCEEDED(hr) && pp && *pp && Live() && !shared) Track(*pp, len, usage, pool);
    return hr;
}

HRESULT __stdcall T_CreateIndexBuffer(IDirect3DDevice9* d, UINT len, DWORD usage, D3DFORMAT fmt,
                                      D3DPOOL pool, IDirect3DIndexBuffer9** pp, HANDLE* shared) {
    const HRESULT hr = O<F_CreateIB>(27)(d, len, usage, fmt, pool, pp, shared);
    if (SUCCEEDED(hr) && pp && *pp && Live() && !shared) Track(*pp, len, usage, pool);
    return hr;
}

bool BuffersInit() {
    if (g_table) return true;
    g_table = (Entry*)HighTables::Reserve("gx_buffers", sizeof(Entry) * kTableSize);
    if (!g_table) {
        Log("[GxRT] the buffer table could not be reserved: every buffer lock will drain the ring instead.");
        return false;
    }
    return true;
}

void BuffersLogStats() {
    const unsigned long total = g_lockDirect + g_lockShadow + g_lockSync;
    Log("[GxRT]   buffers: %ld tracked now (%lu ever, %lu left untracked). %lu lock(s): %lu zero-copy into the "
        "arena, %lu through a shadow copy, %lu that drained the ring and locked the real buffer. "
        "%lu lock(s) found the frame's arena full and did it the old way.",
        (long)g_live, g_tracked, g_untracked, total, g_lockDirect, g_lockShadow, g_lockSync, g_lockOverflow);
    Log("[GxRT]   uploads: %lu queued (%.1f MB), %lu done in place after a drain. "
        "A high 'drained' share above means the client locks static buffers during play.",
        g_uploads, (double)g_uploadBytes / (1024.0 * 1024.0), g_uploadInPlace);
}

}  // namespace GxRT
