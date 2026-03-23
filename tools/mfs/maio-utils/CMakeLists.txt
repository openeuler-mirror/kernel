#*******************************************************************************
#*******************************************************************************

cmake_minimum_required(VERSION 3.0)
cmake_policy(SET CMP0057 NEW)

project(maio)

#*******************************************************************************
#*******************************************************************************

add_definitions(-D__LINUX_USR__)
add_definitions(-D__USE_GNU)
add_definitions(-D__POSIX_SOURCE)
add_definitions(-D_GNU_SOURCE)
add_definitions(-D_FILE_OFFSET_BITS=64)

#*******************************************************************************
#*******************************************************************************

include(TestBigEndian)

TEST_BIG_ENDIAN(BIGENDIAN)
    if (${BIGENDIAN})
        message(">>> Big Endian")
        add_definitions(-D_CMAKE_BIGENDIAN)
    else()
        message(">>> Little Endian")
    endif(${BIGENDIAN})

#*******************************************************************************
#*******************************************************************************

EXECUTE_PROCESS(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCH)
if(${ARCH} STREQUAL "x86_64" OR  ${ARCH} STREQUAL "aarch64")
    message(STATUS "Architecture: ${ARCH}")
else()
    message(STATUS "Invalid Architecture: ${ARCH}")
    return()
endif()

#*******************************************************************************
#*******************************************************************************

set(BASE_FLAGS            "-g -Wall -Werror -fno-strict-overflow -rdynamic")
set(SP_C_FLAGS            "-std=gnu99")
set(SP_C++_FLAGS          "-std=c++11")
set(SP_RELEASE_FLAGS      "-O2")
set(SP_DEBUG_FLAGS        "-O0")
set(SEC_REQ_FLAGS         "-fstack-protector-all -fPIE -pie -fPIC -Wl,-z,relro,-z,now,-z,noexecstack")
set(SEC_SUG_BASE_FLAGS    "-Wformat=2")
set(SEC_SUG_SP_C_FLAGS    "-Wshadow")

set(C_FLAGS               "${BASE_FLAGS}    ${SP_C_FLAGS}")
set(C++_FLAGS             "${BASE_FLAGS}    ${SP_C++_FLAGS}")
set(SEC_C_FLAGS           "${SEC_REQ_FLAGS} ${SEC_SUG_BASE_FLAGS} ${SEC_SUG_SP_C_FLAGS}")
set(SEC_C++_FLAGS         "${SEC_REQ_FLAGS} ${SEC_SUG_BASE_FLAGS}")
set(DEPC_FLAGS            "-Wno-error=deprecated-declarations -Wno-deprecated-declarations")

if(CMAKE_BUILD_TYPE MATCHES "Release")
    message(">>> Release Mode")
    set(CMAKE_C_FLAGS       "${C_FLAGS} ${SP_RELEASE_FLAGS} ${SEC_C_FLAGS}")
    set(CMAKE_CXX_FLAGS   "${C++_FLAGS} ${SP_RELEASE_FLAGS} ${SEC_C++_FLAGS} ${DEPC_FLAGS}")
else()
    message(">>> Debug Mode")
    add_definitions(-D_DEBUG)
    set(CMAKE_C_FLAGS       "${C_FLAGS} ${SP_DEBUG_FLAGS} ${SEC_C_FLAGS}")
    set(CMAKE_CXX_FLAGS   "${C++_FLAGS} ${SP_DEBUG_FLAGS} ${SEC_C++_FLAGS} ${DEPC_FLAGS}")
    set(COVERAGE_FLAGS    "-coverage")
    set(COVERAGE_LINK     "gcov")
endif()

message(STATUS ">>> Source Dir: " ${PROJECT_SOURCE_DIR})
message(STATUS ">>> Binary Dir: " ${PROJECT_BINARY_DIR})
message(STATUS ">>> C_FLAGS   : " ${CMAKE_C_FLAGS})
message(STATUS ">>> CXX_FLAGS : " ${CMAKE_CXX_FLAGS})

#*******************************************************************************
#*******************************************************************************

set(EXECUTABLE_OUTPUT_PATH    ${PROJECT_BINARY_DIR}/bin)

#*******************************************************************************
#*******************************************************************************

if(DEFINED THIRD_PARTY)
    message(">>> third_party: ${THIRD_PARTY}")
else()
    set(THIRD_PARTY ${PROJECT_SOURCE_DIR}/lib)
endif()

set(INFRA_DIR      ${PROJECT_SOURCE_DIR}/infrastructure)
set(SECUREC_DIR    ${THIRD_PARTY}/securec)
set(ZLOG_DIR       ${THIRD_PARTY}/zlog)
set(LIBNUMA_DIR    ${THIRD_PARTY}/libnuma)

#*******************************************************************************
#*******************************************************************************

add_subdirectory(infrastructure)
add_subdirectory(src)
