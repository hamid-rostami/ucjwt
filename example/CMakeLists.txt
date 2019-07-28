cmake_minimum_required (VERSION 3.1)

add_executable(example example.c)

set_target_properties(example PROPERTIES
                      EXCLUDE_FROM_ALL 1
                      EXCLUDE_FROM_DEFAULT_BUILD 1)
#target_include_directories(example PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(example ucjwt)
