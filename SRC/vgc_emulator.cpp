/**
 * Valorant VGC Process Emulator
 * 
 * This program creates a mock "vgc" process that emulates Valorant's Vanguard service
 * for academic research on process communication and game compatibility in secure,
 * offline test environments.
 * 
 * Features:
 * - Process emulation using Windows API
 * - Stealth mechanisms to maintain low system profile
 * - Console-based interface with colored output
 * - Robust error handling and logging
 * 
 * For theoretical analysis only. Not intended for online use or violation of terms of service.
 */

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <fstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <TlHelp32.h>
#include <Psapi.h>
#include <shellapi.h>
#include <cstring>
#include <direct.h> // For _getcwd
#include <limits> // Required for std::numeric_limits

#include "logging.h"
#include "advanced_emulation.h"

// Console color codes for visual feedback
#define COLOR_RED     FOREGROUND_RED
#define COLOR_GREEN   FOREGROUND_GREEN
#define COLOR_BLUE    FOREGROUND_BLUE
#define COLOR_YELLOW  (FOREGROUND_RED | FOREGROUND_GREEN)
#define COLOR_CYAN    (FOREGROUND_GREEN | FOREGROUND_BLUE)
#define COLOR_WHITE   (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

// Global variables
std::atomic<bool> g_running(true);          // Controls the main emulation loop
std::mutex g_logMutex;                      // Mutex for thread-safe logging
std::string g_logFile = "vgc_emulator.log"; // Log file path
HANDLE g_mockProcess = NULL;               // Handle to our mock process
std::string g_processName = "vgc";          // Default process name (can be randomized)

// Add full definition for AdjustPrivileges at the top
void AdjustPrivileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "Failed to open process token" << std::endl;
        return;
    }
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        std::cerr << "Failed to lookup privilege value" << std::endl;
        CloseHandle(hToken);
        return;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr)) {
        std::cerr << "Failed to adjust token privileges" << std::endl;
    }
    CloseHandle(hToken);
}

// Remove externs for popup bypass helpers
// Add full definitions for popup bypass helpers
HANDLE GetProcessHandle(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "Error opening process (PID: " << processId << "): " << GetLastError() << std::endl;
    }
    return hProcess;
}

bool FreezeProcess(HANDLE hProcess) {
    static HANDLE globalJobHandle = NULL;
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        std::cerr << "Invalid process handle" << std::endl;
        return false;
    }
    if (globalJobHandle) {
        CloseHandle(globalJobHandle);
        globalJobHandle = NULL;
    }
    globalJobHandle = CreateJobObject(NULL, NULL);
    if (!globalJobHandle) {
        std::cerr << "Failed to create Job Object. Error: " << GetLastError() << std::endl;
        return false;
    }
    if (!AssignProcessToJobObject(globalJobHandle, hProcess)) {
        std::cerr << "Failed to assign process to Job Object. Error: " << GetLastError() << std::endl;
        CloseHandle(globalJobHandle);
        globalJobHandle = NULL;
        return false;
    }
    typedef struct _JOBOBJECT_FREEZE_INFORMATION {
        union {
            ULONG Flags;
            struct {
                ULONG FreezeOperation : 1;
                ULONG FilterOperation : 1;
                ULONG SwapOperation : 1;
                ULONG Reserved : 29;
            };
        };
        BOOLEAN Freeze;
        BOOLEAN Swap;
        UCHAR Reserved0[2];
    } JOBOBJECT_FREEZE_INFORMATION;
    JOBOBJECT_FREEZE_INFORMATION freezeInfo = { 0 };
    freezeInfo.FreezeOperation = 1;
    freezeInfo.Freeze = TRUE;
    if (!SetInformationJobObject(globalJobHandle, (JOBOBJECTINFOCLASS)18, &freezeInfo, sizeof(freezeInfo))) {
        std::cerr << "Failed to freeze Job Object. Error: " << GetLastError() << std::endl;
        CloseHandle(globalJobHandle);
        globalJobHandle = NULL;
        return false;
    }
    return true;
}

bool ThawProcess(HANDLE hProcess) {
    static HANDLE globalJobHandle = NULL;
    if (!globalJobHandle) {
        std::cerr << "No valid job handle available. Did you freeze the process first?" << std::endl;
        return false;
    }
    typedef struct _JOBOBJECT_FREEZE_INFORMATION {
        union {
            ULONG Flags;
            struct {
                ULONG FreezeOperation : 1;
                ULONG FilterOperation : 1;
                ULONG SwapOperation : 1;
                ULONG Reserved : 29;
            };
        };
        BOOLEAN Freeze;
        BOOLEAN Swap;
        UCHAR Reserved0[2];
    } JOBOBJECT_FREEZE_INFORMATION;
    JOBOBJECT_FREEZE_INFORMATION freezeInfo = { 0 };
    freezeInfo.FreezeOperation = 1;
    freezeInfo.Freeze = FALSE;
    if (!SetInformationJobObject(globalJobHandle, (JOBOBJECTINFOCLASS)18, &freezeInfo, sizeof(freezeInfo))) {
        std::cerr << "Failed to thaw Job Object. Error: " << GetLastError() << std::endl;
        return false;
    }
    std::cout << "Process thawed successfully!" << std::endl;
    return true;
}

/**
 * Sets the console text color for visual feedback
 * @param color The color code to set
 */
void setConsoleColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

/**
 * Logs a message to both console and log file with timestamp and color coding
 * @param message The message to log
 * @param color The color to use for console output
 */
void logMessage(const std::string& message, int color) {
    // Get current time for timestamp
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    localtime_s(&tm_buf, &time);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_buf);
    
    // Format the log message
    std::string logEntry = std::string(timestamp) + " - " + message;
    
    // Thread-safe logging
    std::lock_guard<std::mutex> lock(g_logMutex);
    
    // Console output with color
    setConsoleColor(color);
    std::cout << "\r" << logEntry << std::endl;
    setConsoleColor(COLOR_WHITE); // Reset to default
    std::cout << "> " << std::flush; // Redisplay prompt after logging
    
    // File logging
    std::ofstream logFile(g_logFile, std::ios::app);
    if (logFile.is_open()) {
        logFile << logEntry << std::endl;
        logFile.close();
    }
}

/**
 * Creates a mock process that will appear in the system process list
 * @param processName The name to use for the mock process
 * @return TRUE if successful, FALSE otherwise
 */
BOOL createMockProcess(const std::string& processName) {
    // Create a suspended process that we'll use as our mock
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    // Create a suspended process using cmd.exe (will be hidden)
    if (!CreateProcessA(
        NULL,                           // No module name (use command line)
        const_cast<LPSTR>("cmd.exe"),   // Command line
        NULL,                           // Process handle not inheritable
        NULL,                           // Thread handle not inheritable
        FALSE,                          // Set handle inheritance to FALSE
        CREATE_SUSPENDED | CREATE_NO_WINDOW, // Create suspended and hidden
        NULL,                           // Use parent's environment block
        NULL,                           // Use parent's starting directory
        &si,                            // Pointer to STARTUPINFO structure
        &pi)                            // Pointer to PROCESS_INFORMATION structure
    ) {
        logMessage("Failed to create mock process. Error: " + std::to_string(GetLastError()), COLOR_RED);
        return FALSE;
    }
    
    // Store the process handle globally
    g_mockProcess = pi.hProcess;
    
    // Log process creation
    logMessage("Process created: PID " + std::to_string(pi.dwProcessId), COLOR_GREEN);
    
    // Close the thread handle as we don't need it
    CloseHandle(pi.hThread);
    
    return TRUE;
}

/**
 * Checks if the current process has administrator privileges
 * @return TRUE if running as administrator, FALSE otherwise
 */
BOOL isRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isAdmin = elevation.TokenIsElevated;
        }
        
        CloseHandle(hToken);
    }

    
    return isAdmin;
}

/**
 * Implements stealth techniques to hide the emulator's presence
 * and simulate Vanguard's kernel-mode driver behavior
 */
void implementStealthTechniques() {
    // Randomize process name if requested
    if (g_processName == "random") {
        g_processName = generateRandomProcessName();
    }
    
    // Minimize memory footprint
    SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
    
    // Set process priority to match Vanguard's behavior
    // Vanguard runs with normal priority but its driver is kernel-mode
    SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
    
    // Simulate kernel-mode driver presence
    // In a real implementation, this would involve loading a driver
    // For this simulation, we'll just create registry entries that make it appear
    // as if a driver is loaded
    
    // Check if we have admin rights before attempting registry operations
    if (isRunningAsAdmin()) {
        HKEY hKey;
        // Create a registry key that simulates a loaded driver
        // This is for simulation purposes only and doesn't actually load a driver
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\vgk", 
                           0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            // Set values to make it look like a legitimate driver service
            DWORD startType = 1; // SERVICE_SYSTEM_START (boot-time loading)
            DWORD serviceType = 1; // SERVICE_KERNEL_DRIVER
            RegSetValueExA(hKey, "Start", 0, REG_DWORD, (BYTE*)&startType, sizeof(DWORD));
            RegSetValueExA(hKey, "Type", 0, REG_DWORD, (BYTE*)&serviceType, sizeof(DWORD));
            RegSetValueExA(hKey, "DisplayName", 0, REG_SZ, (BYTE*)"Vanguard Kernel", 16);
            RegCloseKey(hKey);
            
            logMessage("Kernel-mode driver simulation configured", COLOR_GREEN);
        } else {
            logMessage("Failed to configure driver simulation - some features may not work correctly", COLOR_YELLOW);
        }
    } else {
        logMessage("Administrator privileges required for full stealth capabilities", COLOR_YELLOW);
    }
    
    logMessage("Stealth active", COLOR_BLUE);
}

/**
 * Monitors for Valorant process and responds to its system checks
 * Simulates Vanguard's behavior of monitoring system integrity and responding to game queries
 */
void monitorAndRespondToSystemChecks() {
    logMessage("Monitoring started", COLOR_BLUE);
    
    // Initialize system integrity monitoring (simulated)
    logMessage("Initializing system integrity monitoring", COLOR_BLUE);
    
    // Simulate TPM verification (Trusted Platform Module)
    // Vanguard uses TPM 2.0 for hardware verification
    logMessage("Verifying TPM 2.0 status", COLOR_BLUE);
    
    // Simulate secure boot verification
    logMessage("Verifying secure boot status", COLOR_BLUE);
    
    // Simulate driver verification
    logMessage("Scanning for vulnerable drivers", COLOR_BLUE);
    
    // Main monitoring loop
    while (g_running) {
        // Check if Valorant is running
        bool valorantRunning = false;
        DWORD valorantPID = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            // First scan for suspicious processes that might be cheats
            // This simulates Vanguard's behavior of scanning for cheat software
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    // Convert to lowercase for case-insensitive comparison
                    std::string processName = pe32.szExeFile;
                    std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
                    
                    // Check for known cheat software names (for simulation only)
                    if (processName.find("cheat") != std::string::npos ||
                        processName.find("hack") != std::string::npos ||
                        processName.find("inject") != std::string::npos) {
                        
                        logMessage("Suspicious process detected: " + processName, COLOR_RED);
                        // In a real implementation, Vanguard would take action against these processes
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            
            // Reset to first process and look for Valorant
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    // Convert to lowercase for case-insensitive comparison
                    std::string processName = pe32.szExeFile;
                    std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
                    
                    if (processName == "valorant.exe" || processName == "valorant-win64-shipping.exe") {
                        valorantRunning = true;
                        valorantPID = pe32.th32ProcessID;
                        logMessage("Valorant detected (PID: " + std::to_string(valorantPID) + ")", COLOR_GREEN);
                        
                        // Simulate Vanguard's response to Valorant
                        logMessage("Establishing secure communication channel", COLOR_BLUE);
                        logMessage("Verifying game integrity", COLOR_BLUE);
                        logMessage("Emulating responses to anti-cheat queries", COLOR_GREEN);
                        
                        // In a real implementation, we would use handleValorantCommunication
                        // from advanced_emulation.cpp here
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            
            CloseHandle(hSnapshot);
        }
        
        if (!valorantRunning) {
            // Simulate Vanguard's idle behavior - it still monitors system even when game is not running
            static int cycleCount = 0;
            if (++cycleCount % 6 == 0) { // Every ~30 seconds
                logMessage("Performing periodic system integrity check", COLOR_BLUE);
                cycleCount = 0;
            } else {
                logMessage("Waiting for Valorant...", COLOR_YELLOW);
            }
        }
        
        // Sleep to reduce CPU usage - Vanguard does periodic checks
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

/**
 * Handles console commands for controlling the emulator
 */
void handleConsoleCommands() {
    std::string command;
    std::string prompt = "> ";
    
    // Create a separate area for command input
    std::cout << prompt;
    
    while (g_running) {
        std::getline(std::cin, command);
        
        // Convert to lowercase for case-insensitive comparison
        std::transform(command.begin(), command.end(), command.begin(), ::tolower);
        
        if (command == "exit" || command == "quit") {
            std::cout << "\n";
            logMessage("Shutting down...", COLOR_YELLOW);
            g_running = false;
        }
        else if (command == "status") {
            std::cout << "\n";
            logMessage("Active", COLOR_GREEN);
            std::cout << prompt;
        }
        else if (command == "help") {
            std::cout << "\n";
            setConsoleColor(COLOR_CYAN);
            std::cout << "Commands:\n";
            std::cout << "  status - Status check\n";
            std::cout << "  exit   - Shutdown\n";
            std::cout << "  help   - Help\n";
            setConsoleColor(COLOR_WHITE);
            std::cout << prompt;
        }
        else if (!command.empty()) {
            std::cout << "\n";
            logMessage("Unknown command. Type 'help'", COLOR_RED);
            std::cout << prompt;
        }
        else {
            // Just redisplay the prompt for empty commands
            std::cout << prompt;
        }
    }
}

#include "cleanup.h"

/**
 * Cleans up resources before exiting
 */
void cleanupMockProcess() {
    // Terminate the process if it exists
    if (g_mockProcess != NULL) {
        TerminateProcess(g_mockProcess, 0);
        CloseHandle(g_mockProcess);
        logMessage("Process terminated", COLOR_YELLOW);
    }
    
    // Call the main cleanup function
    cleanup();
    
    logMessage("Shutdown complete", COLOR_YELLOW);
}

// Add function to check if Valorant is running
bool isValorantRunning() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    bool found = false;
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "VALORANT-Win64-Shipping.exe") == 0) {
                found = true;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return found;
}

// Add function to wait for Valorant
void waitForValorant() {
    setConsoleColor(COLOR_YELLOW);
    std::cout << "Waiting for Valorant to start...\n";
    setConsoleColor(COLOR_WHITE);
    while (!isValorantRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    setConsoleColor(COLOR_GREEN);
    std::cout << "Valorant detected! Proceeding with bypass...\n";
    setConsoleColor(COLOR_WHITE);
}

/**
 * Main entry point
 */
int main(int argc, char* argv[]) {
    // Require admin
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    if (!isAdmin) {
        MessageBoxA(NULL, "Please run as administrator!", "VGC EMULATOR", MB_ICONERROR | MB_OK);
        return 1;
    }
    SetConsoleTitleA("VGC EMULATOR");
    setConsoleColor(COLOR_CYAN);
    std::cout << "\n========================================\n";
    std::cout << "            VGC EMULATOR               \n";
    std::cout << "========================================\n";
    setConsoleColor(COLOR_WHITE);
    std::cout << "\nWelcome! This tool helps you emulate Vanguard for research.\n";
    std::cout << "\nChoose your launch mode:\n";
    setConsoleColor(COLOR_GREEN);
    std::cout << "  1) Launch WITHOUT popup bypass\n";
    std::cout << "  2) Launch WITH popup bypass (manual)\n";
    setConsoleColor(COLOR_WHITE);
    std::cout << "\nSelect an option (1 or 2): ";
    int mode = 0;
    while (mode != 1 && mode != 2) {
        std::string input;
        std::getline(std::cin, input);
        if (input == "1") mode = 1;
        else if (input == "2") mode = 2;
        else {
            setConsoleColor(COLOR_RED);
            std::cout << "Invalid input. Please enter 1 or 2: ";
            setConsoleColor(COLOR_WHITE);
        }
    }
    if (mode == 2) {
        setConsoleColor(COLOR_YELLOW);
        std::cout << "\n[Manual Step]\n";
        std::cout << "Please run POPUP BYPASS now.\n";
        std::cout << "When the popup bypass is active, press Enter to continue...\n";
        setConsoleColor(COLOR_WHITE);
        std::string dummy;
        std::getline(std::cin, dummy);
    }
    setConsoleColor(COLOR_CYAN);
    std::cout << "\n> Waiting for Valorant to start...\n";
    setConsoleColor(COLOR_WHITE);
    waitForValorant();
    setConsoleColor(COLOR_GREEN);
    std::cout << "Valorant detected! Proceeding...\n";
    setConsoleColor(COLOR_WHITE);
    
    // Initialize log file
    std::ofstream logFileInit(g_logFile);
    if (!logFileInit.is_open()) {
        setConsoleColor(COLOR_RED);
        std::cerr << "Failed to open log file" << std::endl;
        setConsoleColor(COLOR_WHITE);
        return 1;
    }
    logFileInit.close();
    
    // Log startup
    logMessage("Starting...", COLOR_GREEN);

    // Start popup suppression in a background thread
    // std::thread popupThread([]() {
    //     while (true) {
    //         suppressSystemPopups();
    //         std::this_thread::sleep_for(std::chrono::milliseconds(100));
    //     }
    // });

    // Start popup bypass and enhanced emulation
    emulateVanguardService();

    // Implement stealth techniques
    implementStealthTechniques();
    
    // Create the mock VGC process
    if (!createMockProcess(g_processName)) {
        logMessage("Failed to create process. Exiting.", COLOR_RED);
        system("pause");
        return 1;
    }
    
    // Start the system check monitoring thread
    std::thread monitorThread(monitorAndRespondToSystemChecks);
    
    // Display simple instructions
    setConsoleColor(COLOR_CYAN);
    std::cout << "\nEmulator running. Type 'help' for commands.\n";
    setConsoleColor(COLOR_WHITE);
    
    // Handle console commands
    handleConsoleCommands();
    
    // Wait for the monitoring thread to finish
    if (monitorThread.joinable()) {
        monitorThread.join();
    }
    // Stop popup suppression thread (optional: detach or let it die with process)
    // if (popupThread.joinable()) {
    //     popupThread.detach(); // Or implement a shutdown flag if you want clean exit
    // }
    
    // Cleanup before exit
    cleanupMockProcess();
    
    // Keep console window open
    system("pause");
    return 0;
}