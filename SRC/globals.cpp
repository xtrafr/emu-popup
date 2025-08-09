#include "memory_protection.h"

// Global handle for service operations
HANDLE g_serviceHandle = NULL;

// Global vector for memory blocks
std::vector<MemoryBlock> g_memoryBlocks;

// Global handle for job object
HANDLE g_jobHandle = NULL;