#pragma once

// Skips the UI layout dependency scan (sub_489710) when the client's own
// dependants index says the scan cannot find anything. See the .cpp for the
// measurement, the mechanism, and the account of the first attempt, which
// crashed the game.

namespace LayoutRelinkFast {

bool Init();
void LogStats();

} // namespace LayoutRelinkFast
