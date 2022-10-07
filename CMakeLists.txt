cmake_minimum_required(VERSION 3.16.3)
project(sscanfpatch C)

set(CMAKE_C_STANDARD 99)

if ($ENV{CLION_IDE})
    include_directories(SYSTEM /usr/include/machine)
endif()
include_directories(SYSTEM /usr/local/include/samba4)

add_library(sscanfpatch SHARED library.c samba.h tevent.h http.h tsocket.h talloc.h debug.h)
add_compile_options(-fPIC -Wall -shared -Wl,-z,defs -Wl,--as-needed -rpath,/usr/local/lib/samba4,/usr/local/lib/samba4/private)
