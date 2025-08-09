#pragma once

#include <Windows.h>
#include <vector>

// Global handle for service operations
extern HANDLE g_serviceHandle;

// Memory block structure for dynamic memory protection
struct MemoryBlock {
    LPVOID address;
    SIZE_T size;
    DWORD protection;
    std::vector<BYTE> key; // Encryption key for this block
};

// Global vector for memory blocks
extern std::vector<MemoryBlock> g_memoryBlocks;

// Global handle for job object
extern HANDLE g_jobHandle;