# Intel CET & Hardware-Enforced Stack Protection Subsystem

> **Sovereign Codename:** `TitanCET / AegisCET`  
> **Driver Binary:** `kshadowstack.sys`  
> **Header:** `cet.hpp`  
> **Class:** `System` (`{4D36E97D-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **Intel CET & Hardware-Enforced Stack Protection Subsystem** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `cet.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `CPUID\CET_SS` | Intel CET & Hardware-Enforced Stack Protection Subsystem endpoint |
| `CPUID\CET_IBT` | Intel CET & Hardware-Enforced Stack Protection Subsystem endpoint |

---

## 3. Directory Layout

```
drivers/cet/
├── cet.hpp               # Standalone Driver Core Implementation
├── cet.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── cet.hpp
└── tests/
    └── test_cet.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_cet
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
