#pragma once
#ifndef WOW_OPT_OBJMGR_FIND_FAST_H
#define WOW_OPT_OBJMGR_FIND_FAST_H

// The object manager's find-by-GUID (sub_4D4BB0). Its chain walk re-derived the
// bucket's link offset from the table header on every node; this reads it once.
// Verifies itself against the client's own result and retires on a single
// disagreement.
namespace ObjMgrFindFast {

bool Init();
void LogStats();

} // namespace ObjMgrFindFast

#endif
