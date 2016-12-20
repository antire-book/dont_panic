project(computeChecksums CXX)
cmake_minimum_required(VERSION 3.0)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -g")

add_executable(${PROJECT_NAME}
                src/computeChecksums.cpp
                src/crc32.c)

set_source_files_properties(src/crc32.c PROPERTIES LANGUAGE CXX)
