cmake_minimum_required(VERSION 2.8)

project(${PROJECT_NAME_LIB})

include_directories(
    ${Boost_INCLUDES}
    ${CMAKE_SOURCE_DIR}
)

set(LIB_SOURCES
    impl.cpp
)

add_library(${PROJECT_NAME}
    ${LIB_SOURCES}
)
