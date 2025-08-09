#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <conio.h>
#include <psapi.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <winhttp.h>
#include <random>
// #include "Auth.hpp"
// #include "skStr.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winhttp.lib")

// ====================== APPLICATION CODE ======================

const std::string xor_key = "tpm";
std::string XOR(const std::string& input, const std::string& key) {
    std::string output = input;
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = input[i] ^ key[i % key.size()];
    }
    return output;
}

std::string name = XOR("tpm", xor_key);
std::string ownerid = XOR("1fusJvrjGT", xor_key);
std::string version = XOR("1.0", xor_key);
std::string url = XOR("https://keyauth.win/api/1.3/", xor_key);
std::string path = XOR("", xor_key);

// Remove KeyAuth and license key logic

constexpr uint32_t JobObjectFreezeInformation = 18;

typedef struct _JOBOBJECT_WAKE_FILTER {
    ULONG HighEdgeFilter;
    ULONG LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;

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
    JOBOBJECT_WAKE_FILTER WakeFilter;
} JOBOBJECT_FREEZE_INFORMATION, * PJOBOBJECT_FREEZE_INFORMATION;

std::atomic<bool> g_bShutdown(false);
std::mutex g_mtxSecurity;
HANDLE globalJobHandle = NULL;
DWORD vgc_pid = 0;

std::string GetHardwareID() {
    std::ostringstream hwid;
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);
    hwid << std::hex << cpuInfo[0] << cpuInfo[1] << cpuInfo[2] << cpuInfo[3];

    IP_ADAPTER_INFO adapterInfo[16];
    ULONG bufLen = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &bufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = adapterInfo;
        while (pAdapter) {
            if (pAdapter->AddressLength == 6) {
                for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                    hwid << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapter->Address[i];
                }
                break;
            }
            pAdapter = pAdapter->Next;
        }
    }
    return hwid.str();
}

DWORD GetServicePID(const wchar_t* serviceName) {
    DWORD pid = 0;
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) return 0;

    SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_QUERY_STATUS);
    if (!hService) {
        CloseServiceHandle(hSCManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        pid = ssp.dwProcessId;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return pid;
}

HANDLE GetProcessHandle(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        // g_Logger.Log("Failed to open process handle for PID: " + std::to_string(processId));
    }
    return hProcess;
}

bool FreezeProcess(HANDLE hProcess) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        // g_Logger.Log("Invalid process handle in FreezeProcess");
        return false;
    }

    if (globalJobHandle) {
        CloseHandle(globalJobHandle);
        globalJobHandle = NULL;
    }

    globalJobHandle = CreateJobObject(NULL, NULL);
    if (!globalJobHandle) {
        // g_Logger.Log("Failed to create Job Object. Error: " + std::to_string(GetLastError()));
        return false;
    }

    if (!AssignProcessToJobObject(globalJobHandle, hProcess)) {
        // g_Logger.Log("Failed to assign process to Job Object. Error: " + std::to_string(GetLastError()));
        CloseHandle(globalJobHandle);
        globalJobHandle = NULL;
        return false;
    }

    JOBOBJECT_FREEZE_INFORMATION freezeInfo = { 0 };
    freezeInfo.FreezeOperation = 1;
    freezeInfo.Freeze = TRUE;

    if (!SetInformationJobObject(globalJobHandle, (JOBOBJECTINFOCLASS)JobObjectFreezeInformation, &freezeInfo, sizeof(freezeInfo))) {
        // g_Logger.Log("Failed to freeze Job Object. Error: " + std::to_string(GetLastError()));
        CloseHandle(globalJobHandle);
        globalJobHandle = NULL;
        return false;
    }

    // g_Logger.Log("Successfully froze process");
    return true;
}

bool ThawProcess(HANDLE hProcess) {
    if (!globalJobHandle) {
        // g_Logger.Log("No valid job handle available in ThawProcess");
        return false;
    }

    JOBOBJECT_FREEZE_INFORMATION freezeInfo = { 0 };
    freezeInfo.FreezeOperation = 1;
    freezeInfo.Freeze = FALSE;

    if (!SetInformationJobObject(globalJobHandle, (JOBOBJECTINFOCLASS)JobObjectFreezeInformation, &freezeInfo, sizeof(freezeInfo))) {
        // g_Logger.Log("Failed to thaw Job Object. Error: " + std::to_string(GetLastError()));
        return false;
    }

    // g_Logger.Log("Successfully thawed process");
    return true;
}

void AdjustPrivileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        // g_Logger.Log("Failed to open process token");
        return;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        // g_Logger.Log("Failed to lookup privilege value");
        CloseHandle(hToken);
        return;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr)) {
        // g_Logger.Log("Failed to adjust token privileges");
    }

    CloseHandle(hToken);
}

void CleanupBeforeExit() {
    const wchar_t* serviceName = L"Dnscache";
    DWORD pid = GetServicePID(serviceName);
    if (pid) {
        HANDLE hProcess = GetProcessHandle(pid);
        if (hProcess) {
            ThawProcess(hProcess);
            CloseHandle(hProcess);
        }
    }

    if (globalJobHandle) {
        CloseHandle(globalJobHandle);
        globalJobHandle = NULL;
    }

    // g_Logger.Log("Application exiting after cleanup");
}

std::string get_cpu_id() {
    int cpuInfo[4] = { -1 };
    __cpuid(cpuInfo, 1);
    std::ostringstream oss;
    oss << std::hex << cpuInfo[0] << cpuInfo[1] << cpuInfo[2] << cpuInfo[3];
    return oss.str();
}

std::string encrypt_key(const std::string& input, const std::string& key) {
    std::string output = input;
    for (size_t i = 0; i < input.size(); ++i) {
        output[i] = input[i] ^ key[i % key.size()];
    }
    return output;
}

std::string get_saved_key() {
    HKEY hKey;
    char buffer[256] = { 0 };
    DWORD bufferSize = sizeof(buffer);

    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\POPUP_BYPASS_V1", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        DWORD disposition;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\POPUP_BYPASS_V1", 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_READ, nullptr, &hKey, &disposition) != ERROR_SUCCESS) {
            return "";
        }
    }

    if (RegQueryValueExA(hKey, "LicenseKey", nullptr, nullptr, (LPBYTE)buffer, &bufferSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return "";
    }

    RegCloseKey(hKey);

    std::string hwid = get_cpu_id();
    std::string enc(buffer);
    std::string dec = encrypt_key(enc, hwid);
    return dec;
}

bool save_key_to_registry(const std::string& key) {
    HKEY hKey;
    DWORD disposition;
    std::string hwid = get_cpu_id();
    std::string enc = encrypt_key(key, hwid);

    if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\POPUP_BYPASS_V1", 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, &disposition) != ERROR_SUCCESS) {
        return false;
    }

    if (RegSetValueExA(hKey, "LicenseKey", 0, REG_SZ,
        (const BYTE*)enc.c_str(), static_cast<DWORD>(enc.length() + 1)) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    return true;
}

void OpenURL(const std::string& url) {
    ShellExecuteA(0, "open", url.c_str(), 0, 0, SW_SHOWNORMAL);
}

void ShowMenu(bool bypassActive) {
    system("cls");
    std::cout << "============================================\n";
    std::cout << "              POPUP BYPASS v1.0.0           \n";
    std::cout << "============================================\n\n";

    std::cout << "  Current Status: " << (bypassActive ? "ACTIVE" : "INACTIVE") << "\n\n";

    std::cout << "  [F2] Toggle Bypass\n";
    std::cout << "  [F3] Open Discord Support\n";
    std::cout << "  [END] Exit Safely\n\n";
}

void ToggleBypass(bool& bypassActive) {
    // SERVER_CHECK; // This line is removed as per the edit hint

    const wchar_t* serviceName = L"Dnscache";
    DWORD pid = GetServicePID(serviceName);

    if (!pid) {
        // g_Logger.Log("Failed to find target service");
        return;
    }

    HANDLE hProcess = GetProcessHandle(pid);
    if (!hProcess) {
        // g_Logger.Log("Failed to open process handle");
        return;
    }

    if (!bypassActive) {
        if (FreezeProcess(hProcess)) {
            bypassActive = true;
            std::cout << "\nBypass activated successfully!" << std::endl;
            // g_Logger.Log("Bypass activated for PID: " + std::to_string(pid));
        }
        else {
            std::cerr << "\nFailed to activate bypass!" << std::endl;
            // g_Logger.Log("Failed to activate bypass for PID: " + std::to_string(pid));
        }
    }
    else {
        if (ThawProcess(hProcess)) {
            bypassActive = false;
            std::cout << "\nBypass deactivated successfully!" << std::endl;
            // g_Logger.Log("Bypass deactivated for PID: " + std::to_string(pid));
        }
        else {
            std::cerr << "\nFailed to deactivate bypass!" << std::endl;
            // g_Logger.Log("Failed to deactivate bypass for PID: " + std::to_string(pid));
        }
    }
    CloseHandle(hProcess);
    Sleep(1500);
}

int main() {
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
        MessageBoxA(NULL, "Please run as administrator!", "POPUP BYPASS v2.0", MB_ICONERROR | MB_OK);
        return 1;
    }
    // Set console color and title
    SetConsoleTitleA("POPUP BYPASS v2.0");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n========================================\n");
    printf("           POPUP BYPASS v2.0           \n");
    printf("========================================\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\nThis tool will suppress security popups.\n");
    printf("Press END to exit safely.\n\n");
    AdjustPrivileges();
    bool bypassActive = false;
    while (!g_bShutdown) {
        // Show current state
        system("cls");
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("========================================\n");
        printf("           POPUP BYPASS v2.0           \n");
        printf("========================================\n");
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        printf("\nThis tool will suppress security popups.\n");
        printf("Press END to exit safely.\n\n");
        if (bypassActive) {
            SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            printf("[ACTIVE]   Press F2 to deactivate bypass.\n");
        } else {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
            printf("[INACTIVE] Press F2 to activate bypass.\n");
        }
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        // Wait for user input
        bool toggled = false;
        while (!g_bShutdown && !toggled) {
            if (GetAsyncKeyState(VK_F2) & 0x8000) {
                ToggleBypass(bypassActive);
                toggled = true;
            }
            if (GetAsyncKeyState(VK_END) & 0x8000) {
                printf("\nExiting...\n");
                CleanupBeforeExit();
                g_bShutdown = true;
                break;
            }
            Sleep(100);
        }
    }
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    return 0;
}