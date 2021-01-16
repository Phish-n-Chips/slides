cmake_minimum_required(VERSION 3.00)

project(pwn-bof-shellcode-rop-handson)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_C_FLAGS "-O0 -fno-pic -no-pie -Wl,--build-id=none")
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)

function(define_target chalN bits options)
  set(exename ${chalN})
  add_executable(${exename} ${chalN}.c)
  set_target_properties(${exename} PROPERTIES COMPILE_FLAGS "-m${bits} ${options}" LINK_FLAGS "-m${bits} ${options}")
  if(EXISTS ${CMAKE_SOURCE_DIR}/${chalN}.lds)
    set_target_properties(${exename} PROPERTIES LINK_DEPENDS "${CMAKE_SOURCE_DIR}/${chalN}.lds" LINK_FLAGS "-m${bits} ${options} -Wl,-T,${CMAKE_SOURCE_DIR}/${chalN}.lds")
  endif()
endfunction(define_target)

define_target(chal1 64 "-fno-stack-protector -zexecstack")
define_target(chal3 64 "-fno-stack-protector -zexecstack")
define_target(chal4 32 "-fno-stack-protector")
define_target(chal5 32 "-fno-stack-protector")
define_target(chal6 64 "-fno-stack-protector")
