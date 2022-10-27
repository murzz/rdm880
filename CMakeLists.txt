cmake_minimum_required(VERSION 3.14)

project(rdm
    VERSION 1.0.0
    DESCRIPTION "RDM880 RFID module communication protocol library"
    LANGUAGES CXX
)

#----------------------------------------------------------------------------------------------------------------------
# general settings and options
#----------------------------------------------------------------------------------------------------------------------

include(cmake/utils.cmake)
include(GNUInstallDirs)

string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}" is_top_level)

# RDM_SHARED_LIBS option (undefined by default) can be used to force shared/static build
option(RDM_BUILD_TESTS "Build RDM880 tests" OFF)
option(RDM_BUILD_EXAMPLES "Build RDM880 examples" OFF)
option(RDM_BUILD_DOCS "Build RDM880 documentation" OFF)
option(RDM_INSTALL "Generate target for installing RDM880" ${is_top_level})
set_if_undefined(RDM_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/rdm" CACHE STRING
    "Install path for RDM880 package-related CMake files")

if(DEFINED RDM_SHARED_LIBS)
    set(BUILD_SHARED_LIBS ${RDM_SHARED_LIBS})
endif()

if(NOT DEFINED CMAKE_BUILD_TYPE AND NOT DEFINED CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

set_if_undefined(CMAKE_CXX_VISIBILITY_PRESET hidden)
set_if_undefined(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

add_library(rdm) # initialized below
add_library(rdm::rdm ALIAS rdm)

#----------------------------------------------------------------------------------------------------------------------
# RDM880 dependencies
#----------------------------------------------------------------------------------------------------------------------

find_package(Boost COMPONENTS log REQUIRED)
target_link_libraries(rdm
    PRIVATE
        Boost::log
)

#----------------------------------------------------------------------------------------------------------------------
# RDM880 sources
#----------------------------------------------------------------------------------------------------------------------

include(GenerateExportHeader)
set(export_file_name "export_shared.h")

if(NOT BUILD_SHARED_LIBS)
    set(export_file_name "export_static.h")
endif()

generate_export_header(rdm EXPORT_FILE_NAME include/rdm/${export_file_name})

set(sources
    include/rdm/export.hpp
    include/rdm/rdm.hpp
    include/rdm/impl.hpp
    include/rdm/misc.hpp
    src/impl.cpp)
source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}" FILES ${sources})

#----------------------------------------------------------------------------------------------------------------------
# rdm target
#----------------------------------------------------------------------------------------------------------------------

include(CMakePackageConfigHelpers)

target_sources(rdm PRIVATE ${sources})
target_compile_definitions(rdm PUBLIC "$<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:RDM_STATIC_DEFINE>")

target_include_directories(rdm
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>")

set_target_properties(rdm PROPERTIES
    SOVERSION ${PROJECT_VERSION_MAJOR}
    VERSION ${PROJECT_VERSION})

if(RDM_INSTALL AND NOT CMAKE_SKIP_INSTALL_RULES)
    configure_package_config_file(cmake/rdm-config.cmake.in rdm-config.cmake
        INSTALL_DESTINATION "${RDM_INSTALL_CMAKEDIR}")

    write_basic_package_version_file(rdm-config-version.cmake
        COMPATIBILITY SameMajorVersion)

    install(TARGETS rdm EXPORT rdm_export
        RUNTIME COMPONENT rdm
        LIBRARY COMPONENT rdm NAMELINK_COMPONENT rdm-dev
        ARCHIVE COMPONENT rdm-dev
        INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
    install(DIRECTORY include/
        TYPE INCLUDE
        COMPONENT rdm-dev)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/include/rdm/${export_file_name}"
        COMPONENT rdm-dev
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/rdm")

    set(targets_file "rdm-shared-targets.cmake")

    if(NOT BUILD_SHARED_LIBS)
        set(targets_file "rdm-static-targets.cmake")
    endif()

    install(EXPORT rdm_export
        COMPONENT rdm-dev
        FILE "${targets_file}"
        DESTINATION "${RDM_INSTALL_CMAKEDIR}"
        NAMESPACE rdm::)

    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/rdm-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/rdm-config-version.cmake"
        COMPONENT rdm-dev
        DESTINATION "${RDM_INSTALL_CMAKEDIR}")

    if(MSVC)
        set(pdb_file "")
        set(pdb_file_destination "")

        if(BUILD_SHARED_LIBS)
            set(pdb_file "$<TARGET_PDB_FILE:rdm>")
            set(pdb_file_destination "${CMAKE_INSTALL_BINDIR}")
        else()
            # TARGET_PDB_FILE does not work for pdb file generated for static library build, determining it manually
            set(pdb_file "$<TARGET_FILE_DIR:rdm>/$<TARGET_FILE_PREFIX:rdm>$<TARGET_FILE_BASE_NAME:rdm>.pdb")
            set(pdb_file_destination "${CMAKE_INSTALL_LIBDIR}")
        endif()

        install(FILES "${pdb_file}"
            COMPONENT rdm-dev
            CONFIGURATIONS Debug RelWithDebInfo
            DESTINATION "${pdb_file_destination}"
            OPTIONAL)
    endif()
endif()

#----------------------------------------------------------------------------------------------------------------------
# other targets
#----------------------------------------------------------------------------------------------------------------------

if(RDM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(RDM_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(RDM_BUILD_DOCS)
    find_package(Doxygen REQUIRED)
    doxygen_add_docs(docs include)
endif()
