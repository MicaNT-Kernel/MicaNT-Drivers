# Intel SGX/TDX & AMD SEV-SNP Confidential Computing Subsystem

> **Sovereign Codename:** `TitanTEE / AegisTEE`  
> **Driver Binary:** `virtenclave.sys`  
> **Header:** `tee.hpp`  
> **Class:** `System` (`{4D36E97D-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_SYSTEM_START`  

---

## 1. Architectural Overview & Provenance

The **Intel SGX/TDX & AMD SEV-SNP Confidential Computing Subsystem** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `tee.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `CPUID\SGX` | Intel SGX/TDX & AMD SEV-SNP Confidential Computing Subsystem endpoint |
| `CPUID\TDX` | Intel SGX/TDX & AMD SEV-SNP Confidential Computing Subsystem endpoint |
| `CPUID\SEV_SNP` | Intel SGX/TDX & AMD SEV-SNP Confidential Computing Subsystem endpoint |

---

## 3. Directory Layout

```
drivers/tee/
├── tee.hpp               # Standalone Driver Core Implementation
├── tee.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── tee.hpp
└── tests/
    └── test_tee.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_tee
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
