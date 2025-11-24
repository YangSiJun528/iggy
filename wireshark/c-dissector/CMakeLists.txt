# CMakeLists.txt for Iggy Wireshark C dissector
cmake_minimum_required(VERSION 3.12)
project(iggy-dissector C)

# Find Wireshark
find_package(Wireshark CONFIG)

if(NOT Wireshark_FOUND)
    message(FATAL_ERROR "Wireshark development files not found. Install Wireshark headers.")
endif()

# Plugin version
set(PLUGIN_VERSION "0.1.0")

# Source files
set(DISSECTOR_SRC packet-iggy.c)

# Create plugin library
add_library(iggy MODULE ${DISSECTOR_SRC})

set_target_properties(iggy PROPERTIES
    PREFIX ""
    DEFINE_SYMBOL ""
    C_VISIBILITY_PRESET hidden
)

target_include_directories(iggy PRIVATE ${Wireshark_INCLUDE_DIRS})
target_link_libraries(iggy ${Wireshark_LIBRARIES})

# Compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(iggy PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

# Installation
if(NOT WIRESHARK_PLUGIN_DIR)
    set(WIRESHARK_PLUGIN_DIR "$ENV{HOME}/.local/lib/wireshark/plugins")
endif()

install(TARGETS iggy LIBRARY DESTINATION "${WIRESHARK_PLUGIN_DIR}")

message(STATUS "Iggy dissector version: ${PLUGIN_VERSION}")
message(STATUS "Install directory: ${WIRESHARK_PLUGIN_DIR}")
