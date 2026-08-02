#pragma once

// ============================================================================
// Module: render_null_guard.h
// ============================================================================









bool InstallRenderNullGuard();

// Printed from the periodic report. Says how many draw-path calls the guard
// suppressed and why - a suppressed call draws a model with the previous
// model's parameters, so a non-zero count here is a visible defect.
void RenderNullGuard_LogStats();
