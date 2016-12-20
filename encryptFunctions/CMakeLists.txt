project(encryptFunctions CXX)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -g -std=c++11")

add_executable(${PROJECT_NAME} src/encryptFunctions.cpp src/rc4.c)

set_source_files_properties(src/rc4.c PROPERTIES LANGUAGE CXX)
