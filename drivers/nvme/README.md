# NVM Express (NVMe 1.0-2.0), UFS 4.0 & AHCI Storage Subsystem

> **Sovereign Codename:** `TitanNVMe / TitanFlash`  
> **Driver Binary:** `stornvme.sys`  
> **Header:** `nvme.hpp`  
> **Class:** `SCSIAdapter` (`{4D36E97B-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **NVM Express (NVMe 1.0-2.0), UFS 4.0 & AHCI Storage Subsystem** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `nvme.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `PCI\CC_010802` | NVM Express (NVMe 1.0-2.0), UFS 4.0 & AHCI Storage Subsystem endpoint |
| `PCI\VEN_8086&DEV_0A54` | NVM Express (NVMe 1.0-2.0), UFS 4.0 & AHCI Storage Subsystem endpoint |

---

## 3. Directory Layout

```
drivers/nvme/
├── nvme.hpp               # Standalone Driver Core Implementation
├── nvme.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── nvme.hpp
└── tests/
    └── test_nvme.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_nvme
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
