cmake_minimum_required(VERSION 3.16)
project(OpenRAR VERSION 7.01 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(OPENRAR_SOURCES
    src/rar_crypto.cpp
    src/rar_codec.cpp
    src/rar_archive.cpp
    src/rar_cli.cpp
    src/main.cpp
)

add_executable(rar ${OPENRAR_SOURCES})
target_include_directories(rar PRIVATE include)

if(MSVC)
    target_compile_options(rar PRIVATE /utf-8 /W3 /O2 /EHsc)
    target_link_libraries(rar PRIVATE shell32 advapi32)
else()
    target_compile_options(rar PRIVATE -Wall -Wextra -O2)
endif()

# Also build unrar-free compatible binary alias
add_executable(unrar-free ${OPENRAR_SOURCES})
target_include_directories(unrar-free PRIVATE include)
if(MSVC)
    target_compile_options(unrar-free PRIVATE /utf-8 /W3 /O2 /EHsc)
    target_link_libraries(unrar-free PRIVATE shell32 advapi32)
else()
    target_compile_options(unrar-free PRIVATE -Wall -Wextra -O2)
endif()
