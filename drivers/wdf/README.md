# Windows Driver Frameworks (KMDF v1.33 & UMDF 2.0) Core Library

> **Sovereign Codename:** `TitanWDF / AegisWDF`  
> **Driver Binary:** `Wdf01000.sys`  
> **Header:** `wdf.hpp`  
> **Class:** `System` (`{4D36E97D-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **Windows Driver Frameworks (KMDF v1.33 & UMDF 2.0) Core Library** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `wdf.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `ROOT\WDF01000` | Windows Driver Frameworks (KMDF v1.33 & UMDF 2.0) Core Library endpoint |
| `WDF\KMDF_1_33` | Windows Driver Frameworks (KMDF v1.33 & UMDF 2.0) Core Library endpoint |

---

## 3. Directory Layout

```
drivers/wdf/
├── wdf.hpp               # Standalone Driver Core Implementation
├── wdf.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── wdf.hpp
└── tests/
    └── test_wdf.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_wdf
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
