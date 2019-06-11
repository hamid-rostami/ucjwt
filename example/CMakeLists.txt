cmake_minimum_required (VERSION 2.6)

include_directories("../src")
set(SOURCE_DIR ../src)
file(GLOB SOURCES "${SOURCE_DIR}/*.c")

add_executable(example example.c ${SOURCES})
