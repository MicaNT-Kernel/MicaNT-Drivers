# USB Type-C (UCSI 2.1/3.0) & USB Power Delivery 3.1 Subsystem

> **Sovereign Codename:** `TitanUCSI / NexusUCSI`  
> **Driver Binary:** `ucsi.sys`  
> **Header:** `ucsi.hpp`  
> **Class:** `USB` (`{36FC9E60-C465-11CF-8056-444553540000}`)  
> **Start Type:** `SERVICE_SYSTEM_START`  

---

## 1. Architectural Overview & Provenance

The **USB Type-C (UCSI 2.1/3.0) & USB Power Delivery 3.1 Subsystem** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `ucsi.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `ACPI\USBC000` | USB Type-C (UCSI 2.1/3.0) & USB Power Delivery 3.1 Subsystem endpoint |
| `ACPI\PNP0CA0` | USB Type-C (UCSI 2.1/3.0) & USB Power Delivery 3.1 Subsystem endpoint |

---

## 3. Directory Layout

```
drivers/ucsi/
├── ucsi.hpp               # Standalone Driver Core Implementation
├── ucsi.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── ucsi.hpp
└── tests/
    └── test_ucsi.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_ucsi
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
