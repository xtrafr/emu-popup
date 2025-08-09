# CMakeLists.txt for Valorant VGC Process Emulator
# This file configures the build process for the emulator project

cmake_minimum_required(VERSION 3.10)

project(VGCEmulator VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_executable(vgc_emulator
        vgc_emulator.cpp
        advanced_emulation.cpp
        cleanup.cpp
    )

    target_include_directories(vgc_emulator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

    target_compile_definitions(vgc_emulator PRIVATE _WIN32_WINNT=0x0601)

    if(MSVC)
        target_compile_options(vgc_emulator PRIVATE /W4)
    else()
        target_compile_options(vgc_emulator PRIVATE -Wall -Wextra)
    endif()

    target_link_libraries(vgc_emulator PRIVATE
        Psapi
        User32
        Advapi32
        Crypt32
        Iphlpapi
        Shell32
        Shlwapi
        Winhttp
    )

    set_target_properties(vgc_emulator PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )

    install(TARGETS vgc_emulator DESTINATION bin)

    # Popup bypass tool (Windows only)
    add_executable(popup_bypass "POPUP Bypass V1.0.cpp")
    target_compile_definitions(popup_bypass PRIVATE _WIN32_WINNT=0x0601)
    target_link_libraries(popup_bypass PRIVATE
        Psapi
        User32
        Advapi32
        Crypt32
        Iphlpapi
        Shell32
        Shlwapi
        Winhttp
    )
    set_target_properties(popup_bypass PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
else()
    message(STATUS "Non-Windows host detected. Building portable stubs.")
    add_executable(vgc_emulator portable_stub.cpp)
    set_target_properties(vgc_emulator PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif()