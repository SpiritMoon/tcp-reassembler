cmake_minimum_required (VERSION 2.6)

set (NAME tcp_reassembler)
project (${NAME})

if (${DEBUG})
    set (CMAKE_C_FLAGS "-g -std=gnu99 -Wall -Wno-unused-function ${CMAKE_C_FLAGS}")
else ()
    set (CMAKE_C_FLAGS "-std=gnu99 -Wall ${CMAKE_C_FLAGS}")
endif()

set (LIBS ${LIBS}
		lib/util.c
		lib/hash.c
		lib/file.c
		lib/mydirent.c)

set (SRCS ${SRCS}
        src/network.c
        src/ip.c
        src/udp.c
        src/tcp.c
        src/http_parser.c
        src/http.c
        src/main.c)

find_library(HAS_PCAP pcap)
find_library(HAS_LIBZ z)

if (${HAS_PCAP} MATCHES ".*-NOTFOUND")
    message(FATAL_ERROR "Not found libpcap")
endif()
if (${HAS_LIBZ} MATCHES ".*-NOTFOUND")
    message(FATAL_ERROR "Not found libz")
endif()

include_directories("lib" "src")
add_executable(${NAME} ${LIBS} ${SRCS})
target_link_libraries(${NAME} pcap z)