cmake_minimum_required(VERSION 3.00)

project(pwn-ovf-stack-handson)

add_custom_target(32)
add_custom_target(64)
add_custom_target(32s)
add_custom_target(64s)
add_custom_target(32n)
add_custom_target(64n)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_C_FLAGS "-O0 -fno-pic -no-pie -fno-stack-protector -Wl,--build-id=none")
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)

set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

foreach(bits IN ITEMS 32 64)
  # dynamic link library
  add_library(stkdbg${bits} SHARED stkdbg.c)
  set_target_properties(stkdbg${bits} PROPERTIES COMPILE_FLAGS "-m${bits}" LINK_FLAGS "-m${bits}" INSTALL_RPATH "")
  # static library
  add_library(stkdbg_s${bits} STATIC stkdbg.c)
  set_target_properties(stkdbg_s${bits} PROPERTIES COMPILE_FLAGS "-m${bits}" LINK_FLAGS "-m${bits}" INSTALL_RPATH "")
endforeach()

foreach(chalN IN ITEMS chal1 chal2 chal3 chal4 chal5)
  foreach(bits IN ITEMS 32 64)
    # normal build
    set(exename ${chalN}-${bits})
    add_executable(${exename} ${chalN}.c)
    set_target_properties(${exename} PROPERTIES COMPILE_FLAGS "-m${bits}" LINK_FLAGS "-m${bits}" INSTALL_RPATH "./")
    target_link_libraries(${exename} stkdbg${bits})
    if(EXISTS ${CMAKE_SOURCE_DIR}/${chalN}.lds)
      set_target_properties(${exename} PROPERTIES LINK_DEPENDS "${CMAKE_SOURCE_DIR}/${chalN}.lds" LINK_FLAGS "-m${bits} -Wl,-T,${CMAKE_SOURCE_DIR}/${chalN}.lds")
    endif()
    add_dependencies(${bits} ${exename})
    # static link build
    add_executable(${exename}s ${chalN}.c)
    set_target_properties(${exename}s PROPERTIES COMPILE_FLAGS "-m${bits}" LINK_FLAGS "-m${bits}" INSTALL_RPATH "")
    target_link_libraries(${exename}s stkdbg_s${bits})
    if(EXISTS ${CMAKE_SOURCE_DIR}/${chalN}.lds)
      set_target_properties(${exename}s PROPERTIES LINK_DEPENDS "${CMAKE_SOURCE_DIR}/${chalN}.lds" LINK_FLAGS "-m${bits} -Wl,-T,${CMAKE_SOURCE_DIR}/${chalN}.lds")
    endif()
    add_dependencies(${bits}s ${exename}s)
    # non-dump build
    add_executable(${exename}n ${chalN}.c)
    set_target_properties(${exename}n PROPERTIES COMPILE_FLAGS "-m${bits} -DNO_DUMP" LINK_FLAGS "-m${bits}" INSTALL_RPATH "")
    if(EXISTS ${CMAKE_SOURCE_DIR}/${chalN}.lds)
      set_target_properties(${exename}n PROPERTIES LINK_DEPENDS "${CMAKE_SOURCE_DIR}/${chalN}.lds" LINK_FLAGS "-m${bits} -Wl,-T,${CMAKE_SOURCE_DIR}/${chalN}.lds")
    endif()
    add_dependencies(${bits}n ${exename}n)
  endforeach()
endforeach()
