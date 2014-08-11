cmake_minimum_required(VERSION 2.8)

project(${CMAKE_PROJECT_NAME}-test)

include_directories(
    ${Boost_INCLUDES}
    ${CMAKE_SOURCE_DIR}/lib
)

add_executable(${PROJECT_NAME}
    main-test.cpp
)

target_link_libraries(${PROJECT_NAME}
    ${PROJECT_NAME_LIB}
    ${Boost_LIBRARIES}
)

enable_testing()
add_test( unit-tests ${PROJECT_NAME})

# work around cmake bug(?): http://stackoverflow.com/questions/733475/cmake-ctest-make-test-doesnt-build-tests
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND}
                  DEPENDS ${PROJECT_NAME})
