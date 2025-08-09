#pragma once

#include <Windows.h>
#include <iostream>
#include <string>

// Console colors
#define COLOR_RED     FOREGROUND_RED
#define COLOR_GREEN   FOREGROUND_GREEN
#define COLOR_BLUE    FOREGROUND_BLUE
#define COLOR_YELLOW  (FOREGROUND_RED | FOREGROUND_GREEN)
#define COLOR_CYAN    (FOREGROUND_GREEN | FOREGROUND_BLUE)
#define COLOR_WHITE   (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

/**
 * Sets the console text color
 */
inline void setConsoleColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

/**
 * Logs a message with color
 */
inline void logMessage(const std::string& message, WORD color) {
    setConsoleColor(color);
    std::cout << "[*] " << message << std::endl;
    setConsoleColor(COLOR_WHITE);
}