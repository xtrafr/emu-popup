# CMakeLists.txt for Valorant VGC Process Emulator
# This file configures the build process for the emulator project

cmake_minimum_required(VERSION 3.10)

# Project name and version
project(VGCEmulator VERSION 1.0)

# Specify C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add source files
set(SOURCES
    vgc_emulator.cpp
    advanced_emulation.cpp
    globals.cpp
)

# Add header files
set(HEADERS
    vgc_emulator.h
)

# Create executable
add_executable(vgc_emulator ${SOURCES} ${HEADERS})

# Link Windows libraries
target_link_libraries(vgc_emulator
    psapi.lib
)

# Set output directory
set_target_properties(vgc_emulator PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Add compiler flags
if(MSVC)
    target_compile_options(vgc_emulator PRIVATE /W4)
    # Enable advanced Windows API features
    target_compile_definitions(vgc_emulator PRIVATE _WIN32_WINNT=0x0601)
else()
    target_compile_options(vgc_emulator PRIVATE -Wall -Wextra)
endif()

# Installation rules
install(TARGETS vgc_emulator DESTINATION bin)

# Create executable for popup bypass only
add_executable(popup_bypass "POPUP Bypass V1.0.cpp")
target_link_libraries(popup_bypass user32.lib)
set_target_properties(popup_bypass PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")