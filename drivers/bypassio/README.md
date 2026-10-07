# DirectStorage 1.2 / BypassIO Storage Acceleration Subsystem

> **Sovereign Codename:** `TitanBypassIO / NexusBypassIO`  
> **Driver Binary:** `bypassio.sys`  
> **Header:** `bypassio.hpp`  
> **Class:** `FSFilter-Bottom` (`{71AA7053-C8A4-47FA-9E24-2C6274E8203E}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **DirectStorage 1.2 / BypassIO Storage Acceleration Subsystem** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `bypassio.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `MS_BYPASSIO_FILTER` | DirectStorage 1.2 / BypassIO Storage Acceleration Subsystem endpoint |
| `FSFilter\BypassIO` | DirectStorage 1.2 / BypassIO Storage Acceleration Subsystem endpoint |

---

## 3. Directory Layout

```
drivers/bypassio/
├── bypassio.hpp               # Standalone Driver Core Implementation
├── bypassio.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── bypassio.hpp
└── tests/
    └── test_bypassio.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_bypassio
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
