cmake_minimum_required (VERSION 2.8)

set(CMAKE_BUILD_TYPE "release")

project(demo CXX)
set(CMAKE_CXX_STANDARD 11)

set( CMAKE_CXX_FLAGS ${PALISADE_CXX_FLAGS} )
set( CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS} )



file(GLOB SOURCES "lib/*.cpp")


add_executable(MatGSW ${SOURCES})

target_include_directories(MatGSW
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include)
