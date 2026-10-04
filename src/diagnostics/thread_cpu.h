// ============================================================================
// Description: CPU time of every thread in the process, from the kernel's own
//              per-thread counters, for the periodic report.
// Safety & Threading: Report() is called from the periodic report and returns at once;
//                     the reading runs on a short-lived thread of its own. It opens each
//                     thread for query access only and never suspends or touches one.
// ============================================================================

#pragma once

namespace ThreadCpu {

// One block in the log: the busiest threads by CPU time over the time since the
// previous call and over the whole session, each with its Win32 start address
// and, when the thread was given one, its name. A thread that could not be
// opened is counted and said so; it is not shown as idle.
void Report();

} // namespace ThreadCpu
