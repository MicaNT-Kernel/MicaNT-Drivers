# Persistent Memory (NVDIMM / Optane PMEM) & DAX Storage Subsystem

> **Sovereign Codename:** `TitanPMEM / NexusPMEM`  
> **Driver Binary:** `pmem.sys`  
> **Header:** `pmem.hpp`  
> **Class:** `Memory` (`{5099944A-E698-4D3C-B038-0207F2104719}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **Persistent Memory (NVDIMM / Optane PMEM) & DAX Storage Subsystem** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `pmem.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `ACPI\ACPI0012` | Persistent Memory (NVDIMM / Optane PMEM) & DAX Storage Subsystem endpoint |
| `ACPI\NFIT` | Persistent Memory (NVDIMM / Optane PMEM) & DAX Storage Subsystem endpoint |

---

## 3. Directory Layout

```
drivers/pmem/
├── pmem.hpp               # Standalone Driver Core Implementation
├── pmem.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── pmem.hpp
└── tests/
    └── test_pmem.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_pmem
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
