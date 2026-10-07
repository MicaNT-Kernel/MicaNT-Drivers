cmake_minimum_required(VERSION 3.25)
project(micant_driver_pluton LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

add_executable(test_pluton tests/test_pluton.cpp)
if(MSVC)
    target_compile_options(test_pluton PRIVATE /W4 /EHsc /utf-8 /wd4201 /wd4100)
else()
    target_compile_options(test_pluton PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

add_test(NAME DriverTest_pluton COMMAND test_pluton)
