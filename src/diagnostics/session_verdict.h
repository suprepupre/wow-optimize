#pragma once

// A short list of what went wrong this session, at the top of every periodic
// report. See session_verdict.cpp for why.
namespace Verdict {

enum Severity {
    Note = 0,   // worth knowing, not a fault
    Warn = 1,   // something is off and may explain a complaint
    Bad  = 2,   // a fault a player would notice
};

// Record a finding. Same text twice is counted, not repeated. Printf-style, and
// the formatted result is capped - a finding is one line.
void Add(Severity s, const char* fmt, ...);

// Printed first in the periodic report.
void LogStats();

}  // namespace Verdict
