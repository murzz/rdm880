cmake_minimum_required(VERSION 3.14)
project(rdm-client LANGUAGES CXX)

include("../../cmake/utils.cmake")
string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}" is_top_level)

include("../../cmake/simple-boost-serial-port.cmake")
add_library(simple-boost-serial-port::lib ALIAS simple-boost-serial-port)
target_compile_definitions(simple-boost-serial-port PRIVATE BOOST_BIND_GLOBAL_PLACEHOLDERS)

if (is_top_level)
    find_package(rdm REQUIRED)
endif ()

set(sources client.cpp)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${sources})

find_package(Boost COMPONENTS
        date_time
        log
        system
        REQUIRED)

add_executable(rdm-client)
target_sources(rdm-client PRIVATE ${sources})
target_link_libraries(rdm-client
        PRIVATE
        rdm::rdm
        simple-boost-serial-port::lib
        Boost::headers
        Boost::date_time
        Boost::log
        Boost::system
        )

if (NOT is_top_level)
    win_copy_deps_to_target_dir(rdm-client rdm::rdm)
endif ()
