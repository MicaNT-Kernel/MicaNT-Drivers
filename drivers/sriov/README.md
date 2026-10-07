# PCIe SR-IOV 1.1, PASID (20-bit) & Shared Virtual Addressing (SVA)

> **Sovereign Codename:** `TitanSRIOV / NexusSVA`  
> **Driver Binary:** `pci_sriov.sys`  
> **Header:** `sriov.hpp`  
> **Class:** `System` (`{4D36E97D-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **PCIe SR-IOV 1.1, PASID (20-bit) & Shared Virtual Addressing (SVA)** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `sriov.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `PCI\SRIOV` | PCIe SR-IOV 1.1, PASID (20-bit) & Shared Virtual Addressing (SVA) endpoint |
| `PCI\PASID` | PCIe SR-IOV 1.1, PASID (20-bit) & Shared Virtual Addressing (SVA) endpoint |
| `PCI\ATS` | PCIe SR-IOV 1.1, PASID (20-bit) & Shared Virtual Addressing (SVA) endpoint |

---

## 3. Directory Layout

```
drivers/sriov/
├── sriov.hpp               # Standalone Driver Core Implementation
├── sriov.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── sriov.hpp
└── tests/
    └── test_sriov.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_sriov
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
