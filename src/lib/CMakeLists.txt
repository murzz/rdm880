cmake_minimum_required(VERSION 2.8)

set(PROJECT_NAME_LIB ${CMAKE_PROJECT_NAME}-lib)
project(${PROJECT_NAME_LIB})

include_directories(
    ${Boost_INCLUDES}
    ${CMAKE_SOURCE_DIR}
)

set(LIB_SOURCES
    lib.cpp
)

add_library(${PROJECT_NAME}
    ${LIB_SOURCES}
)