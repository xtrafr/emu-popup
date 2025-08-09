#pragma once

#include <string>

// Color constants (match Windows console attributes where applicable)
#ifndef COLOR_RED
#define COLOR_RED 0x0004
#endif
#ifndef COLOR_GREEN
#define COLOR_GREEN 0x0002
#endif
#ifndef COLOR_BLUE
#define COLOR_BLUE 0x0001
#endif
#ifndef COLOR_YELLOW
#define COLOR_YELLOW 0x0006
#endif
#ifndef COLOR_CYAN
#define COLOR_CYAN 0x0003
#endif
#ifndef COLOR_WHITE
#define COLOR_WHITE 0x0007
#endif

void setConsoleColor(int color);
void logMessage(const std::string& message, int color);