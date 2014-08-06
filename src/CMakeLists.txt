cmake_minimum_required(VERSION 2.8)

project(rdm)

add_definitions(-std=c++11 -std=gnu++11)
add_definitions(-Wall)

#SET(Boost_USE_STATIC_LIBS ON)
find_package(Boost COMPONENTS system thread unit_test_framework log REQUIRED)
add_definitions(-DBOOST_ALL_DYN_LINK)

add_subdirectory(lib)
add_subdirectory(client)
add_subdirectory(test)