#*******************************************************************************
#*******************************************************************************

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/inner)
include_directories(${PROJECT_SOURCE_DIR}/include/uapi)
include_directories(${PROJECT_SOURCE_DIR}/include/client)
include_directories(${PROJECT_SOURCE_DIR}/include/loader)
include_directories(${PROJECT_SOURCE_DIR}/include/policy)
include_directories(${PROJECT_SOURCE_DIR}/include/monitor)
include_directories(${PROJECT_SOURCE_DIR}/include/parser)

include_directories(${INFRA_DIR}/include)
include_directories(${SECUREC_DIR}/include)
include_directories(${ZLOG_DIR}/include)
include_directories(${LIBNUMA_DIR}/include)

#*******************************************************************************
#*******************************************************************************

link_directories(${PROJECT_BINARY_DIR}/lib)
link_directories(${SECUREC_DIR}/lib)
link_directories(${ZLOG_DIR}/lib)
link_directories(${LIBNUMA_DIR}/lib)

#*******************************************************************************
#*******************************************************************************

add_subdirectory(client)
add_subdirectory(loader)
add_subdirectory(policy)
add_subdirectory(parser)

add_executable(maio-utils main.c)
target_link_libraries(maio-utils "-Wl,--whole-archive"
                                 client
                                 loader
                                 policy
                                 parser
                                 "-Wl,--no-whole-archive"
                                 infra
                                 dl)
