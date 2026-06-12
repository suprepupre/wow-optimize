#pragma once

#include <cstdint>

bool InstallRegexCache();
void ShutdownRegexCache();
void RegexCache_Clear();

const uint8_t* RegexCache_Get(const char* pattern, int patternLen, int* outCompiledLen);
void RegexCache_Put(const char* pattern, int patternLen, const uint8_t* compiled, int compiledLen);