# CMakeLists.txt for Iggy Wireshark dissector plugin
#
# This can be built either:
# 1. As part of the Wireshark source tree (in-tree build)
# 2. As a standalone plugin (out-of-tree build)

cmake_minimum_required(VERSION 3.12)

project(iggy-dissector C)

# For out-of-tree builds, find Wireshark
if(NOT WIRESHARK_BUILD)
    find_package(Wireshark CONFIG REQUIRED)

    if(NOT Wireshark_FOUND)
        message(FATAL_ERROR "Wireshark development files not found. Please install Wireshark headers or build in-tree.")
    endif()

    # Use Wireshark's plugin directory
    if(NOT WIRESHARK_PLUGIN_DIR)
        set(WIRESHARK_PLUGIN_DIR "$ENV{HOME}/.local/lib/wireshark/plugins")
    endif()

    # Include Wireshark's CMake helpers
    include(WiresharkPlugin)
endif()

# Plugin information
set(PLUGIN_VERSION "0.1.0")
set(PLUGIN_NAME "iggy")
set(PLUGIN_DESCRIPTION "Iggy Protocol Dissector")
set(PLUGIN_AUTHOR "Iggy Contributors")

# Source files
set(DISSECTOR_SRC
    packet-iggy.c
)

# For in-tree builds
if(WIRESHARK_BUILD)
    set(PLUGIN_FILES
        plugin.c
        ${DISSECTOR_SRC}
    )

    add_plugin_library(iggy epan)

    target_sources(iggy PRIVATE ${PLUGIN_FILES})

    target_link_libraries(iggy epan)

    install_plugin(iggy epan)

else()
    # For out-of-tree builds
    add_library(iggy MODULE ${DISSECTOR_SRC})

    set_target_properties(iggy PROPERTIES
        PREFIX ""
        DEFINE_SYMBOL ""
        C_VISIBILITY_PRESET hidden
    )

    target_include_directories(iggy PRIVATE
        ${Wireshark_INCLUDE_DIRS}
    )

    target_link_libraries(iggy
        ${Wireshark_LIBRARIES}
    )

    # Installation
    install(TARGETS iggy
        LIBRARY DESTINATION "${WIRESHARK_PLUGIN_DIR}"
    )
endif()

# Compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(iggy PRIVATE
        -Wall
        -Wextra
        -Wno-unused-parameter
    )
endif()

# Print build information
message(STATUS "Iggy dissector plugin configuration:")
message(STATUS "  Version: ${PLUGIN_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
if(NOT WIRESHARK_BUILD)
    message(STATUS "  Install directory: ${WIRESHARK_PLUGIN_DIR}")
endif()
