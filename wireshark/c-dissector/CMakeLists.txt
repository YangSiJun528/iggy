cmake_minimum_required(VERSION 3.12)
project(iggy-dissector C)

find_package(Wireshark CONFIG REQUIRED)

add_library(iggy MODULE packet-iggy.c)

set_target_properties(iggy PROPERTIES PREFIX "")
target_include_directories(iggy PRIVATE ${Wireshark_INCLUDE_DIRS})
target_link_libraries(iggy ${Wireshark_LIBRARIES})

if(NOT WIRESHARK_PLUGIN_DIR)
    set(WIRESHARK_PLUGIN_DIR "$ENV{HOME}/.local/lib/wireshark/plugins")
endif()

install(TARGETS iggy LIBRARY DESTINATION "${WIRESHARK_PLUGIN_DIR}")
