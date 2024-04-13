#
# This is a camera duration test, it reports statistics at the end
# part of: https://github.com/janwilmans/gvcp-tools 
#
project(PylonTool)

cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

if (NOT BUILD_VCENTER_TREE)

    message(STATUS "Building ${PROJECT_NAME} as standalone project")

    add_library(imported_gcbase_pylon5 SHARED IMPORTED GLOBAL)
    set_target_properties(imported_gcbase_pylon5 PROPERTIES IMPORTED_LOCATION "/opt/pylon5/lib64/libGCBase_gcc_v3_0_Basler_pylon_v5_0.so")
    add_library(pylon5::gcbase ALIAS imported_gcbase_pylon5)

    add_library(imported_liblog_pylon5 SHARED IMPORTED GLOBAL)
    set_target_properties(imported_liblog_pylon5 PROPERTIES IMPORTED_LOCATION "/opt/pylon5/lib64/libLog_gcc_v3_0_Basler_pylon_v5_0.so")
    add_library(pylon5::liblog ALIAS imported_liblog_pylon5)

    add_library(imported_nodemapdata_pylon5 SHARED IMPORTED GLOBAL)
    set_target_properties(imported_nodemapdata_pylon5 PROPERTIES IMPORTED_LOCATION "/opt/pylon5/lib64/libNodeMapData_gcc_v3_0_Basler_pylon_v5_0.so")
    add_library(pylon5::nodemapdata ALIAS imported_nodemapdata_pylon5)

    add_library(imported_mathparser_pylon5 SHARED IMPORTED GLOBAL)
    set_target_properties(imported_mathparser_pylon5 PROPERTIES IMPORTED_LOCATION "/opt/pylon5/lib64/libMathParser_gcc_v3_0_Basler_pylon_v5_0.so")
    add_library(pylon5::mathparser ALIAS imported_mathparser_pylon5)

    add_library(imported_xmlparser_pylon5 SHARED IMPORTED GLOBAL)
    set_target_properties(imported_xmlparser_pylon5 PROPERTIES IMPORTED_LOCATION "/opt/pylon5/lib64/libXmlParser_gcc_v3_0_Basler_pylon_v5_0.so")
    add_library(pylon5::xmlparser ALIAS imported_xmlparser_pylon5)

    add_library(imported_pylonbase_pylon5 SHARED IMPORTED GLOBAL)
    set_target_properties(imported_pylonbase_pylon5 PROPERTIES IMPORTED_LOCATION "/opt/pylon5/lib64/libpylonbase.so")
    add_library(pylon5::pylonbase ALIAS imported_pylonbase_pylon5)

    add_library(imported_gxapi_pylon5 SHARED IMPORTED GLOBAL)
    set_target_properties(imported_gxapi_pylon5 PROPERTIES IMPORTED_LOCATION "/opt/pylon5/lib64/libgxapi.so")
    add_library(pylon5::gxapi ALIAS imported_gxapi_pylon5)

    add_library(imported_genapi_pylon5 SHARED IMPORTED GLOBAL)
    set_target_properties(imported_genapi_pylon5 PROPERTIES
      IMPORTED_LOCATION "/opt/pylon5/lib64/libGenApi_gcc_v3_0_Basler_pylon_v5_0.so"
      INTERFACE_INCLUDE_DIRECTORIES "/opt/pylon5/include"
    )
    add_library(pylon5::genapi ALIAS imported_genapi_pylon5)

    include(FetchContent)

    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)

    FetchContent_Declare(fmt
      GIT_REPOSITORY https://github.com/fmtlib/fmt.git
      GIT_TAG 8.1.1
    )

    FetchContent_MakeAvailable(fmt)

    FetchContent_Declare(docopt
      GIT_REPOSITORY https://github.com/docopt/docopt.cpp.git
      GIT_TAG v0.6.3
    )

    FetchContent_MakeAvailable(docopt)

endif()

#add_compile_options(-fsanitize=address)
#add_link_options(-fsanitize=address)

#add_compile_options(-fsanitize=thread -g -O1)
#add_link_options(-fsanitize=thread)

add_executable(PylonTool
    PylonTool.cc
)

find_package(Threads REQUIRED)

target_link_libraries(PylonTool
  PRIVATE
    pylon5::gcbase
    pylon5::liblog
    pylon5::nodemapdata
    pylon5::mathparser
    pylon5::xmlparser
    pylon5::pylonbase
    pylon5::gxapi
    pylon5::genapi
    Threads::Threads
    fmt::fmt
    docopt
)
