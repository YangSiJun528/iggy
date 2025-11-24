cmake_minimum_required(VERSION 3.12)
project(iggy-dissector C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Find pkg-config
find_package(PkgConfig REQUIRED)

# Find Wireshark using pkg-config
pkg_check_modules(WIRESHARK REQUIRED wireshark)

# Get Wireshark plugin directory
execute_process(
    COMMAND pkg-config --variable=plugindir wireshark
    OUTPUT_VARIABLE WIRESHARK_PLUGIN_DIR_BASE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Create the plugin
add_library(iggy MODULE packet-iggy.c)

# Set plugin properties
set_target_properties(iggy PROPERTIES
    PREFIX ""
    C_VISIBILITY_PRESET hidden
)

# Include directories
target_include_directories(iggy PRIVATE
    ${WIRESHARK_INCLUDE_DIRS}
)

# Add library directories
target_link_directories(iggy PRIVATE
    ${WIRESHARK_LIBRARY_DIRS}
)

# Link libraries
target_link_libraries(iggy
    wireshark
    wsutil
    ${WIRESHARK_LIBRARIES}
)

# Set install directory
if(NOT WIRESHARK_PLUGIN_DIR)
    if(WIRESHARK_PLUGIN_DIR_BASE)
        # Use user's local plugin directory
        set(WIRESHARK_PLUGIN_DIR "$ENV{HOME}/.local/lib/wireshark/plugins")
    else()
        set(WIRESHARK_PLUGIN_DIR "$ENV{HOME}/.local/lib/wireshark/plugins")
    endif()
endif()

message(STATUS "Wireshark plugin will be installed to: ${WIRESHARK_PLUGIN_DIR}")

install(TARGETS iggy LIBRARY DESTINATION "${WIRESHARK_PLUGIN_DIR}")
