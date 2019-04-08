cmake_minimum_required(VERSION 3.13)
project(proj2)

set(CMAKE_CXX_STANDARD 14)

SET(GCC_COVERAGE_LINK_FLAGS "-lpcap")

include(FindPCAP.cmake)

add_executable(proj2 main.cpp argument_parser.h argument_parser.cpp udp_scanner.h udp_scanner.cpp tcp_scanner.h tcp_scanner.cpp scanner.h scanner.cpp)
target_link_libraries(proj2 ${PCAP_LIBRARY})
