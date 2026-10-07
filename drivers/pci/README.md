# PCI Express (PCIe 5.0/6.0) Bus, Root Complex & AER Subsystem

> **Sovereign Codename:** `TitanPCI / NexusPCI`  
> **Driver Binary:** `pci.sys`  
> **Header:** `pci.hpp`  
> **Class:** `System` (`{4D36E97D-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **PCI Express (PCIe 5.0/6.0) Bus, Root Complex & AER Subsystem** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `pci.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `PCI\CC_060000` | PCI Express (PCIe 5.0/6.0) Bus, Root Complex & AER Subsystem endpoint |
| `PCI\CC_060400` | PCI Express (PCIe 5.0/6.0) Bus, Root Complex & AER Subsystem endpoint |
| `*PNP0A08` | PCI Express (PCIe 5.0/6.0) Bus, Root Complex & AER Subsystem endpoint |

---

## 3. Directory Layout

```
drivers/pci/
├── pci.hpp               # Standalone Driver Core Implementation
├── pci.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── pci.hpp
└── tests/
    └── test_pci.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_pci
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
