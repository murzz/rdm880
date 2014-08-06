cmake_minimum_required(VERSION 2.8)

project(${CMAKE_PROJECT_NAME}-client)

include_directories(
    ${CMAKE_SOURCE_DIR}/lib
    ${Boost_INCLUDES}
)
    
add_executable(${PROJECT_NAME}
    client.cpp
    serialstream.cpp
    TimeoutSerial.cpp
)

target_link_libraries(${PROJECT_NAME}
    ${Boost_LIBRARIES}
    ${PROJECT_NAME_LIB}
)