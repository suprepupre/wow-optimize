#pragma once

void InitTrigLUT();
bool IsTrigLutInitialized();
void FastSinCos4(const float* angles, float* outSin, float* outCos);