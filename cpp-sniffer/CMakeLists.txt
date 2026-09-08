cmake_minimum_required(VERSION 3.10)
project(packet_sniffer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto -march=native -pthread")

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})

add_executable(packet_sniffer main.cpp sniffer.cpp utils.cpp)
target_link_libraries(packet_sniffer ${PCAP_LIBRARIES} ssl crypto Threads::Threads)
