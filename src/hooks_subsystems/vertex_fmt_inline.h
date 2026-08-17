#pragma once
#ifndef WOW_OPT_VERTEX_FMT_INLINE_H
#define WOW_OPT_VERTEX_FMT_INLINE_H

// Removes a per-vertex call from the UI batcher and the particle vertex filler.
// The call resolved to `global + 532` and the dword read from it is a property
// of the render device, constant for the whole batch. Replaced in place with
// the same fourteen bytes, no branch.
namespace VertexFmtInline {

bool Init();
void LogStats();

} // namespace VertexFmtInline

#endif
