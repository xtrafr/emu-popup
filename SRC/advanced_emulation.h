#pragma once

#include <Windows.h>
#include <string>
#include "logging.h"
#include "memory_protection.h"

// Function declarations
DWORD GetServicePID(const wchar_t* serviceName);
bool freezeDnsService();
void implementMemoryObfuscation();
void implementStealthTechniques();
BOOL bypassSecurityValidation();
void handleValorantCommunication(DWORD valorantPid);
std::string generateRandomProcessName();
// Declare emulateVanguardService for popup bypass and enhanced emulation
BOOL emulateVanguardService();

// Global variables
extern std::atomic<bool> g_running;
extern HANDLE g_serviceHandle;
extern HANDLE g_jobHandle;
extern std::vector<MemoryBlock> g_memoryBlocks;