# Microsoft Pluton On-Die Security Processor & Hardware RoT

> **Sovereign Codename:** `TitanPluton / AegisPluton`  
> **Driver Binary:** `pluton.sys`  
> **Header:** `pluton.hpp`  
> **Class:** `SecurityDevices` (`{D94EE5D8-D189-4994-83D2-F68D7D41B0E6}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **Microsoft Pluton On-Die Security Processor & Hardware RoT** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `pluton.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `ACPI\MSFT0101` | Microsoft Pluton On-Die Security Processor & Hardware RoT endpoint |
| `ACPI\MSFT0200` | Microsoft Pluton On-Die Security Processor & Hardware RoT endpoint |
| `ACPI\PLTN0001` | Microsoft Pluton On-Die Security Processor & Hardware RoT endpoint |

---

## 3. Directory Layout

```
drivers/pluton/
├── pluton.hpp               # Standalone Driver Core Implementation
├── pluton.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── pluton.hpp
└── tests/
    └── test_pluton.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_pluton
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
