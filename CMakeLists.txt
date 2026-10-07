cmake_minimum_required(VERSION 3.25)
project(MicaNT-Drivers VERSION 10.0.26100.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /EHsc /utf-8 /wd4201 /wd4100)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
endif()

include_directories(include)

enable_testing()

# Add all standalone driver test subdirectories
add_subdirectory(drivers/acpi)
add_subdirectory(drivers/amx)
add_subdirectory(drivers/bluetooth)
add_subdirectory(drivers/bypassio)
add_subdirectory(drivers/cet)
add_subdirectory(drivers/cxl)
add_subdirectory(drivers/dsa)
add_subdirectory(drivers/graphics)
add_subdirectory(drivers/hdaudio)
add_subdirectory(drivers/hfi)
add_subdirectory(drivers/iommu)
add_subdirectory(drivers/ndis)
add_subdirectory(drivers/npu)
add_subdirectory(drivers/nvme)
add_subdirectory(drivers/pci)
add_subdirectory(drivers/pluton)
add_subdirectory(drivers/pmem)
add_subdirectory(drivers/qat)
add_subdirectory(drivers/rdma)
add_subdirectory(drivers/sriov)
add_subdirectory(drivers/tee)
add_subdirectory(drivers/ucsi)
add_subdirectory(drivers/usb)
add_subdirectory(drivers/usb4)
add_subdirectory(drivers/wdf)
add_subdirectory(drivers/wifi)

# Master Driver Test Suite Runner
set(ALL_DRIVER_TEST_SOURCES
    drivers/acpi/tests/test_acpi.cpp
    drivers/amx/tests/test_amx.cpp
    drivers/bluetooth/tests/test_bluetooth.cpp
    drivers/bypassio/tests/test_bypassio.cpp
    drivers/cet/tests/test_cet.cpp
    drivers/cxl/tests/test_cxl.cpp
    drivers/dsa/tests/test_dsa.cpp
    drivers/graphics/tests/test_graphics.cpp
    drivers/hdaudio/tests/test_hdaudio.cpp
    drivers/hfi/tests/test_hfi.cpp
    drivers/iommu/tests/test_iommu.cpp
    drivers/ndis/tests/test_ndis.cpp
    drivers/npu/tests/test_npu.cpp
    drivers/nvme/tests/test_nvme.cpp
    drivers/pci/tests/test_pci.cpp
    drivers/pluton/tests/test_pluton.cpp
    drivers/pmem/tests/test_pmem.cpp
    drivers/qat/tests/test_qat.cpp
    drivers/rdma/tests/test_rdma.cpp
    drivers/sriov/tests/test_sriov.cpp
    drivers/tee/tests/test_tee.cpp
    drivers/ucsi/tests/test_ucsi.cpp
    drivers/usb/tests/test_usb.cpp
    drivers/usb4/tests/test_usb4.cpp
    drivers/wdf/tests/test_wdf.cpp
    drivers/wifi/tests/test_wifi.cpp
)

# Combined test runner
add_executable(micant_drivers_all_tests tests/test_all_drivers.cpp)
add_test(NAME AllDriversMasterSuite COMMAND micant_drivers_all_tests)
