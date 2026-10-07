# NDIS 6.88 & High-Speed Network Adapter Subsystem (RazzleNet)

> **Sovereign Codename:** `TitanNDIS / RazzleNet`  
> **Driver Binary:** `ndis.sys`  
> **Header:** `ndis.hpp`  
> **Class:** `Net` (`{4D36E972-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **NDIS 6.88 & High-Speed Network Adapter Subsystem (RazzleNet)** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `ndis.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `PCI\VEN_8086&DEV_1563` | NDIS 6.88 & High-Speed Network Adapter Subsystem (RazzleNet) endpoint |
| `PCI\CC_020000` | NDIS 6.88 & High-Speed Network Adapter Subsystem (RazzleNet) endpoint |

---

## 3. Directory Layout

```
drivers/ndis/
├── ndis.hpp               # Standalone Driver Core Implementation
├── ndis.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── ndis.hpp
└── tests/
    └── test_ndis.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_ndis
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
