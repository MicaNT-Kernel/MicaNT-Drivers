# Intel AMX & Arm SME Matrix Accelerator Subsystem

> **Sovereign Codename:** `TitanMatrix / NexusAMX`  
> **Driver Binary:** `intel_amx.sys`  
> **Header:** `amx.hpp`  
> **Class:** `System` (`{4D36E97D-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **Intel AMX & Arm SME Matrix Accelerator Subsystem** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `amx.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `CPUID\AMX_TILE` | Intel AMX & Arm SME Matrix Accelerator Subsystem endpoint |
| `CPUID\AMX_INT8` | Intel AMX & Arm SME Matrix Accelerator Subsystem endpoint |
| `CPUID\AMX_BF16` | Intel AMX & Arm SME Matrix Accelerator Subsystem endpoint |

---

## 3. Directory Layout

```
drivers/amx/
├── amx.hpp               # Standalone Driver Core Implementation
├── amx.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── amx.hpp
└── tests/
    └── test_amx.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_amx
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
