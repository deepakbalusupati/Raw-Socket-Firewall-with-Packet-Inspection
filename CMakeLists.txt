cmake_minimum_required(VERSION 3.10)
project(RawSocketFirewall)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Platform specific settings
if(WIN32)
    # Windows-specific
    find_path(PCAP_ROOT_DIR
        NAMES include/pcap.h
        HINTS ENV PCAP_ROOT
        PATHS "C:/WpdPack" "C:/npcap-sdk"
    )

    find_path(PCAP_INCLUDE_DIR
        NAMES pcap.h
        HINTS ${PCAP_ROOT_DIR}/Include
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        # 64-bit
        find_library(PCAP_LIBRARY
            NAMES wpcap
            HINTS ${PCAP_ROOT_DIR}/Lib/x64
        )
    else()
        # 32-bit
        find_library(PCAP_LIBRARY
            NAMES wpcap
            HINTS ${PCAP_ROOT_DIR}/Lib
        )
    endif()

    # Add Windows-specific library
    set(PLATFORM_LIBS ws2_32 iphlpapi)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    
    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR "WinPcap/Npcap not found. Please install WinPcap or Npcap SDK.")
    endif()
    
    set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
else()
    # Linux-specific
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
    set(PLATFORM_LIBS pthread)
endif()

include_directories(
    ${PCAP_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/include
)

file(GLOB SOURCES
    "src/main.cpp"
    "src/impl/*.cpp"
)

add_executable(firewall ${SOURCES})

target_link_libraries(firewall
    ${PCAP_LIBRARIES}
    ${PLATFORM_LIBS}
)

install(TARGETS firewall DESTINATION bin)