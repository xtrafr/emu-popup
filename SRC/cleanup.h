#pragma once

#include <Windows.h>
#include "logging.h"
#include "memory_protection.h"

// Forward declarations
void restoreTPMFunctionality();

/**
 * Cleans up resources before exiting
 */
inline void cleanup() {
    // Restore TPM functionality
    restoreTPMFunctionality();
    
    // Clear any existing blocks
    g_memoryBlocks.clear();
    
    // Clean up any remaining resources
    if (g_serviceHandle != NULL) {
        CloseServiceHandle((SC_HANDLE)g_serviceHandle);
        g_serviceHandle = NULL;
    }
}