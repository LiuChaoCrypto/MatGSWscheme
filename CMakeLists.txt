cmake_minimum_required (VERSION 2.8)

project(demo CXX)
set(CMAKE_CXX_STANDARD 11)

set( CMAKE_CXX_FLAGS ${PALISADE_CXX_FLAGS} )
set( CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS} )

aux_source_directory(. DIR_SRCS)
add_executable(MatGSW ${DIR_SRCS})
