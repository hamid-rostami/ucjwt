cmake_minimum_required (VERSION 3.1)


add_library(ucjwt
            src/base64.c
            src/hmac-sha256.c
            src/sha256.c
            src/jwt.c)

target_compile_options(ucjwt
  PRIVATE
    -Wall
    -Werror
    -std=gnu99  # FIXME gnu11
    -Os
)

target_include_directories(ucjwt
                           PUBLIC
                           "src")

add_subdirectory(example)
