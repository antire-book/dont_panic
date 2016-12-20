project(fakeHeadersXBit CXX)
cmake_minimum_required(VERSION 3.0)

set(CMAKE_C_FLAGS "-Wall -Wextra -Wshadow")
add_executable(${PROJECT_NAME} src/fakeHeadersXBit.cpp)
