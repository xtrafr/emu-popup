#pragma once

#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

struct MemoryBlock {
#ifdef _WIN32
    void* address = nullptr;
    SIZE_T size = 0;
    DWORD protection = 0;
    std::vector<unsigned char> key;
#else
    void* address = nullptr;
    size_t size = 0;
    unsigned int protection = 0;
    std::vector<unsigned char> key;
#endif
};