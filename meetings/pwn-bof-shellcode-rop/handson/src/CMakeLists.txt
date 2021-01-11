cmake_minimum_required(VERSION 3.00)

project(pwn-bof-shellcode-rop-handson)

add_custom_target(32)
add_custom_target(64)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_C_FLAGS "-O0 -fno-pic -no-pie -fno-stack-protector -zexecstack -Wl,--build-id=none")
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)

set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

foreach(chalN IN ITEMS chal1 chal3 chal4)
  foreach(bits IN ITEMS 32 64)
    # normal build
    set(exename ${chalN}-${bits})
    add_executable(${exename} ${chalN}.c)
    set_target_properties(${exename} PROPERTIES COMPILE_FLAGS "-m${bits}" LINK_FLAGS "-m${bits}" INSTALL_RPATH "./")
    if(EXISTS ${CMAKE_SOURCE_DIR}/${chalN}.lds)
      set_target_properties(${exename} PROPERTIES LINK_DEPENDS "${CMAKE_SOURCE_DIR}/${chalN}.lds" LINK_FLAGS "-m${bits} -Wl,-T,${CMAKE_SOURCE_DIR}/${chalN}.lds")
    endif()
    add_dependencies(${bits} ${exename})
  endforeach()
endforeach()
