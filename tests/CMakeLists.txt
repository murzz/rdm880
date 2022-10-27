cmake_minimum_required(VERSION 3.14)
project(rdm-tests)

#----------------------------------------------------------------------------------------------------------------------
# general settings and options
#----------------------------------------------------------------------------------------------------------------------

include("../cmake/utils.cmake")
string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}" is_top_level)

if(is_top_level)
    enable_testing()
endif()

#----------------------------------------------------------------------------------------------------------------------
# testing framework
#----------------------------------------------------------------------------------------------------------------------

find_package(Boost COMPONENTS unit_test_framework REQUIRED)

#----------------------------------------------------------------------------------------------------------------------
# tests dependencies
#----------------------------------------------------------------------------------------------------------------------

if(is_top_level)
    find_package(rdm REQUIRED)
endif()

#----------------------------------------------------------------------------------------------------------------------
# tests sources
#----------------------------------------------------------------------------------------------------------------------

set(sources
    main-test.cpp)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${sources})

#----------------------------------------------------------------------------------------------------------------------
# tests target
#----------------------------------------------------------------------------------------------------------------------

add_executable(rdm-tests)
target_sources(rdm-tests PRIVATE ${sources})

target_link_libraries(rdm-tests
    PRIVATE
        rdm::rdm
        Boost::unit_test_framework)

if(NOT is_top_level)
    win_copy_deps_to_target_dir(rdm-tests rdm::rdm)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/modules")
include(BoostTestDiscoverTests)
boosttest_discover_tests(rdm-tests)
