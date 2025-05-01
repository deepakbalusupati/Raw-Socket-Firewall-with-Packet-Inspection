cmake_minimum_required(VERSION 3.10)
project(RawSocketFirewall)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

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
    pthread
)

install(TARGETS firewall DESTINATION bin)