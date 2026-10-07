cmake_minimum_required(VERSION 3.25)
project(micant_driver_usb4 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

add_executable(test_usb4 tests/test_usb4.cpp)
if(MSVC)
    target_compile_options(test_usb4 PRIVATE /W4 /EHsc /utf-8 /wd4201 /wd4100)
else()
    target_compile_options(test_usb4 PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

add_test(NAME DriverTest_usb4 COMMAND test_usb4)
