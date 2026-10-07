# MicaNT-Drivers

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-purple.svg)](https://en.cppreference.com/w/cpp/23)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20UEFI-green.svg)](https://github.com/MicaNT-Kernel)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-Zero%20(100%25%20Offline)-brightgreen.svg)](https://github.com/MicaNT-Kernel)

**Clean-room, modern ISO C++23 NT-compatible hardware, bus, and accelerator drivers.**  
*Each driver is decoupled into its own isolated directory with standard INF files, headers, and standalone test suites.*

</div>

---

## 1. Overview & Sovereign Architecture

**MicaNT-Drivers** decouples the sovereign hardware and bus driver subsystems from the [MicaNT operating system executive](https://github.com/MicaNT-Kernel/MicaNT), allowing developers, system builders, and security auditors to easily inspect, consume, or test each driver independently.

Every driver adheres strictly to:
- **Clean-Room Provenance:** Authored 100% offline from public processor manuals, PCI-SIG, USB-IF, ACPI, IEEE standards, and `microsoft/win32metadata`.
- **Zero Dependencies:** Pure ISO C++23. No proprietary DDK or WDK headers required.
- **Zero Telemetry:** 100% offline execution with deterministic memory layouts.
- **Stand-Alone Portability:** Each driver has its own directory with its own `CMakeLists.txt`, `.inf` setup file, documentation, and unit test.

---

## 2. Driver Catalog & Master Matrix

| Driver / Folder | Sovereign Codename | Driver Binary | Hardware Domain / Category | Industry Standards & Specifications |
| :--- | :--- | :--- | :--- | :--- |
| [**`acpi`**](drivers/acpi) | **TitanACPI / AegisACPI** | `acpi.sys` | ACPI 6.5 Platform & AML Interpreter Subsystem | ACPI 6.5 Platform Architecture & AML Interpreter Driver |
| [**`amx`**](drivers/amx) | **TitanMatrix / NexusAMX** | `intel_amx.sys` | Intel AMX & Arm SME Matrix Accelerator Subsystem | Intel Advanced Matrix Extensions (AMX) & Arm SME Driver |
| [**`bluetooth`**](drivers/bluetooth) | **TitanBTH / NexusBTH** | `bthport.sys` | Bluetooth 5.4 & LE Audio Kernel Port Driver Subsystem | Bluetooth 5.4 Host Controller & LE Audio Port Driver |
| [**`bypassio`**](drivers/bypassio) | **TitanBypassIO / NexusBypassIO** | `bypassio.sys` | DirectStorage 1.2 / BypassIO Storage Acceleration Subsystem | Fast-Path BypassIO Minifilter & DirectStorage Acceleration Driver |
| [**`cet`**](drivers/cet) | **TitanCET / AegisCET** | `kshadowstack.sys` | Intel CET & Hardware-Enforced Stack Protection Subsystem | Intel Control-Flow Enforcement Technology (CET) Kernel Driver |
| [**`cxl`**](drivers/cxl) | **TitanCXL / NexusCXL** | `cxlhost.sys` | Compute Express Link (CXL 2.0 / 3.1) Heterogeneous Memory Fabric | Compute Express Link (CXL) Host Bridge & Memory Driver |
| [**`dsa`**](drivers/dsa) | **TitanDSA / NexusDSA** | `intel_dsa.sys` | Intel DSA & IAA Fast-Memory Streaming Subsystem | Intel Data Streaming Accelerator (DSA) & IAA Driver |
| [**`graphics`**](drivers/graphics) | **TitanWDDM / NexusWDDM** | `dxgkrnl.sys` | Windows Display Driver Model (WDDM 3.2) & Graphics Kernel | WDDM 3.2 DirectX Graphics Kernel & Display Miniport Driver |
| [**`hdaudio`**](drivers/hdaudio) | **TitanHDA / NexusHDA** | `hdaudio.sys` | Intel High Definition Audio (HDA 1.0a) & USB Audio 2.0 Subsystem | Intel High Definition Audio Bus & Codec Controller Driver |
| [**`hfi`**](drivers/hfi) | **TitanDirector / AegisScheduler** | `intel_hfi.sys` | Intel Thread Director (HFI) & AMD CPPC Heterogeneous Scheduling | Intel Hardware Feedback Interface (HFI) & AMD CPPC Driver |
| [**`iommu`**](drivers/iommu) | **TitanIOMMU / AegisIOMMU** | `dmar.sys` | Hardware IOMMU (Intel VT-d / AMD-Vi / Arm SMMUv3) & Kernel DMA Protection | Hardware I/O Memory Management Unit & DMA Remapping Driver |
| [**`ndis`**](drivers/ndis) | **TitanNDIS / RazzleNet** | `ndis.sys` | NDIS 6.88 & High-Speed Network Adapter Subsystem (RazzleNet) | Network Driver Interface Specification (NDIS 6.88) & 100GbE Driver |
| [**`npu`**](drivers/npu) | **TitanNPU / NexusNPU** | `mcdm.sys` | Neural Processing Unit & Microsoft Compute Driver Model (MCDM) | Neural Processing Unit (NPU) & MCDM Copilot+ Accelerator Driver |
| [**`nvme`**](drivers/nvme) | **TitanNVMe / TitanFlash** | `stornvme.sys` | NVM Express (NVMe 1.0-2.0), UFS 4.0 & AHCI Storage Subsystem | NVM Express (NVMe) & Flash Storage Miniport Driver |
| [**`pci`**](drivers/pci) | **TitanPCI / NexusPCI** | `pci.sys` | PCI Express (PCIe 5.0/6.0) Bus, Root Complex & AER Subsystem | PCI Express (PCIe 5.0/6.0) Bus & Root Port Driver |
| [**`pluton`**](drivers/pluton) | **TitanPluton / AegisPluton** | `pluton.sys` | Microsoft Pluton On-Die Security Processor & Hardware RoT | Microsoft Pluton Security Processor & Hardware TPM 2.0 Driver |
| [**`pmem`**](drivers/pmem) | **TitanPMEM / NexusPMEM** | `pmem.sys` | Persistent Memory (NVDIMM / Optane PMEM) & DAX Storage Subsystem | Persistent Memory (NVDIMM / Optane) & DAX Driver |
| [**`qat`**](drivers/qat) | **TitanQAT / NexusQAT** | `intel_qat.sys` | Intel QuickAssist Technology (QAT 2.0 / 4xxx) Crypto/Compression Offload | Intel QuickAssist Technology (QAT) Hardware Offload Driver |
| [**`rdma`**](drivers/rdma) | **TitanRDMA / NexusSMB** | `ndisrdma.sys` | Remote Direct Memory Access (RoCE v2 / InfiniBand) & SMB Direct | NetworkDirect RDMA (RoCE v2 / InfiniBand) & SMB Direct Driver |
| [**`sriov`**](drivers/sriov) | **TitanSRIOV / NexusSVA** | `pci_sriov.sys` | PCIe SR-IOV 1.1, PASID (20-bit) & Shared Virtual Addressing (SVA) | PCIe Single Root I/O Virtualization (SR-IOV) & SVA Driver |
| [**`tee`**](drivers/tee) | **TitanTEE / AegisTEE** | `virtenclave.sys` | Intel SGX/TDX & AMD SEV-SNP Confidential Computing Subsystem | Hardware Confidential Computing & Trusted Execution Environment Driver |
| [**`ucsi`**](drivers/ucsi) | **TitanUCSI / NexusUCSI** | `ucsi.sys` | USB Type-C (UCSI 2.1/3.0) & USB Power Delivery 3.1 Subsystem | USB Type-C Connector System Software Interface (UCSI) Driver |
| [**`usb`**](drivers/usb) | **TitanUSB / NexusUSB** | `usbxhci.sys` | Universal Serial Bus (USB 3.2 Gen 2) & xHCI 1.2 Host Controller | USB 3.2 eXtensible Host Controller Interface (xHCI) Driver |
| [**`usb4`**](drivers/usb4) | **TitanUSB4 / NexusUSB4** | `usb4host.sys` | USB4 2.0 & Thunderbolt 4 Protocol Tunneling Subsystem | USB4 2.0 Host Router & Thunderbolt 4 Tunneling Driver |
| [**`wdf`**](drivers/wdf) | **TitanWDF / AegisWDF** | `Wdf01000.sys` | Windows Driver Frameworks (KMDF v1.33 & UMDF 2.0) Core Library | Kernel-Mode Driver Framework (KMDF v1.33) Runtime Library |
| [**`wifi`**](drivers/wifi) | **TitanWiFi / NexusWiFi** | `wdiwifi.sys` | Wi-Fi 7 (802.11be EHT) & WDI NetAdapterCx Miniport Subsystem | Wi-Fi 7 (802.11be) Wireless Network Adapter Driver |

---

## 3. Directory Layout

```
MicaNT-Drivers/
├── .github/workflows/ci.yml       # GitHub Actions CI matrix (Windows & Linux)
├── CMakeLists.txt                 # Master build file for all drivers
├── LICENSE                        # MIT License
├── README.md                      # Driver catalog & quickstart guide
├── include/micant/                # Freestanding kernel support headers
├── tests/test_all_drivers.cpp     # Combined regression suite (26 suites)
└── drivers/
    ├── acpi/
    │   ├── acpi.hpp
    │   ├── acpi.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_acpi.cpp
    ├── amx/
    │   ├── amx.hpp
    │   ├── amx.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_amx.cpp
    ├── bluetooth/
    │   ├── bthport.hpp
    │   ├── bluetooth.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_bluetooth.cpp
    ├── bypassio/
    │   ├── bypassio.hpp
    │   ├── bypassio.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_bypassio.cpp
    ├── cet/
    │   ├── cet.hpp
    │   ├── cet.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_cet.cpp
    ├── cxl/
    │   ├── cxl.hpp
    │   ├── cxl.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_cxl.cpp
    ├── dsa/
    │   ├── dsa.hpp
    │   ├── dsa.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_dsa.cpp
    ├── graphics/
    │   ├── wddm.hpp
    │   ├── graphics.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_graphics.cpp
    ├── hdaudio/
    │   ├── hdaudio.hpp
    │   ├── hdaudio.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_hdaudio.cpp
    ├── hfi/
    │   ├── hfi.hpp
    │   ├── hfi.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_hfi.cpp
    ├── iommu/
    │   ├── iommu.hpp
    │   ├── iommu.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_iommu.cpp
    ├── ndis/
    │   ├── ndis.hpp
    │   ├── ndis.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_ndis.cpp
    ├── npu/
    │   ├── npu.hpp
    │   ├── npu.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_npu.cpp
    ├── nvme/
    │   ├── nvme.hpp
    │   ├── nvme.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_nvme.cpp
    ├── pci/
    │   ├── pci.hpp
    │   ├── pci.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_pci.cpp
    ├── pluton/
    │   ├── pluton.hpp
    │   ├── pluton.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_pluton.cpp
    ├── pmem/
    │   ├── pmem.hpp
    │   ├── pmem.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_pmem.cpp
    ├── qat/
    │   ├── qat.hpp
    │   ├── qat.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_qat.cpp
    ├── rdma/
    │   ├── rdma.hpp
    │   ├── rdma.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_rdma.cpp
    ├── sriov/
    │   ├── sriov.hpp
    │   ├── sriov.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_sriov.cpp
    ├── tee/
    │   ├── tee.hpp
    │   ├── tee.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_tee.cpp
    ├── ucsi/
    │   ├── ucsi.hpp
    │   ├── ucsi.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_ucsi.cpp
    ├── usb/
    │   ├── usb.hpp
    │   ├── usb.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_usb.cpp
    ├── usb4/
    │   ├── usb4.hpp
    │   ├── usb4.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_usb4.cpp
    ├── wdf/
    │   ├── wdf.hpp
    │   ├── wdf.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_wdf.cpp
    ├── wifi/
    │   ├── wdiwifi.hpp
    │   ├── wifi.inf
    │   ├── CMakeLists.txt
    │   ├── README.md
    │   └── tests/test_wifi.cpp
```

---

## 4. Building & Testing

### Building All Drivers Together
```bash
# Configure with CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build all driver tests
cmake --build build --config Release

# Run master test suite across all 26 drivers
./build/bin/micant_drivers_all_tests
# or with CTest:
ctest --test-dir build --output-on-failure
```

### Building an Individual Driver
You can also build any driver independently:
```bash
cd drivers/nvme
cmake -B build
cmake --build build
./build/test_nvme
```

---

## 5. Legal & Clean-Room Provenance

MicaNT-Drivers is an independent clean-room engineering effort created strictly for software and hardware interoperability under *Google LLC v. Oracle America, Inc.* (593 U.S. 1, 2021). All trademarks belong to their respective holders and are used solely for nominative compatibility identification.

---

## 6. License

Licensed under the **MIT License**. Copyright (c) 2026 MicaNT Clean-Room Foundation.
