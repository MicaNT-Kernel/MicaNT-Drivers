cmake_minimum_required(VERSION 3.25)
project(micant_driver_iommu LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

add_executable(test_iommu tests/test_iommu.cpp)
if(MSVC)
    target_compile_options(test_iommu PRIVATE /W4 /EHsc /utf-8 /wd4201 /wd4100)
else()
    target_compile_options(test_iommu PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

add_test(NAME DriverTest_iommu COMMAND test_iommu)
