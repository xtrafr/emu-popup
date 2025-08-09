/**
 * Valorant VGC Process Emulator - Header File
 * 
 * Contains function declarations, constants, and structure definitions for the
 * Valorant VGC Process Emulator project.
 * 
 * This emulator simulates the behavior of Riot Vanguard, which is a kernel-mode
 * anti-cheat system that runs at boot time and monitors system integrity.
 * 
 * Key Vanguard features simulated:
 * - Kernel-mode driver presence (simulated through registry)
 * - System integrity monitoring
 * - Process scanning and detection
 * - TPM and Secure Boot verification
 */

#pragma once

#include <windows.h>
#include <string>
#include <atomic>

// Console color codes for visual feedback
#define COLOR_RED     12
#define COLOR_GREEN   10
#define COLOR_BLUE    9
#define COLOR_YELLOW  14
#define COLOR_CYAN    11
#define COLOR_WHITE   15

// Function declarations

/**
 * Sets the console text color for visual feedback
 * @param color The color code to set
 */
void setConsoleColor(int color);

/**
 * Logs a message to both console and log file with timestamp and color coding
 * @param message The message to log
 * @param color The color to use for console output
 */
void logMessage(const std::string& message, int color);

/**
 * Generates a randomized process name for stealth purposes
 * @return A randomized string that can be used as a process name
 */
std::string generateRandomProcessName();

/**
 * Freezes the DNS service to prevent unwanted network communications
 * @return TRUE if successful, FALSE otherwise
 */
BOOL freezeDnsService();

/**
 * Creates a mock process that will appear in the system process list
 * @param processName The name to use for the mock process
 * @return TRUE if successful, FALSE otherwise
 */
BOOL createMockProcess(const std::string& processName);

/**
 * Checks if the current process has administrator privileges
 * @return TRUE if running as administrator, FALSE otherwise
 */
BOOL isRunningAsAdmin();

/**
 * Implements stealth techniques to hide the emulator's presence
 * and simulate Vanguard's kernel-mode driver behavior
 * 
 * This function simulates Vanguard's kernel-mode driver by creating registry entries
 * that make it appear as if a driver is loaded. It also sets appropriate process
 * priorities and minimizes memory footprint to avoid detection.
 */
void implementStealthTechniques();

/**
 * Monitors for Valorant process and responds to its system checks
 * Simulates Vanguard's behavior of monitoring system integrity and responding to game queries
 * 
 * This function simulates Vanguard's core functionality:
 * - Performs TPM 2.0 and Secure Boot verification
 * - Scans for suspicious processes that might be cheats
 * - Monitors for Valorant process and establishes communication
 * - Performs periodic system integrity checks even when Valorant is not running
 * - Emulates responses to anti-cheat queries from the game
 */
void monitorAndRespondToSystemChecks();

/**
 * Handles console commands for controlling the emulator
 */
void handleConsoleCommands();

/**
 * Cleans up resources before exiting
 */
void cleanup();

// Advanced function declarations for a more comprehensive implementation

/**
 * Intercepts and handles system calls related to process enumeration
 * to ensure our mock process appears legitimate
 */
void interceptProcessEnumeration();

/**
 * Emulates the Vanguard service responses to maintain game compatibility
 * @return TRUE if emulation is successful, FALSE otherwise
 */
BOOL emulateVanguardService();

/**
 * Implements advanced memory obfuscation techniques to avoid detection
 */
void implementMemoryObfuscation();

/**
 * Handles communication with the Valorant process
 * @param valorantPid The process ID of the Valorant process
 */
void handleValorantCommunication(DWORD valorantPid);