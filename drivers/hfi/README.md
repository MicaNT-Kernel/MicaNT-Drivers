# Intel Thread Director (HFI) & AMD CPPC Heterogeneous Scheduling

> **Sovereign Codename:** `TitanDirector / AegisScheduler`  
> **Driver Binary:** `intel_hfi.sys`  
> **Header:** `hfi.hpp`  
> **Class:** `System` (`{4D36E97D-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **Intel Thread Director (HFI) & AMD CPPC Heterogeneous Scheduling** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `hfi.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `ACPI\INTC1072` | Intel Thread Director (HFI) & AMD CPPC Heterogeneous Scheduling endpoint |
| `CPUID\HFI` | Intel Thread Director (HFI) & AMD CPPC Heterogeneous Scheduling endpoint |
| `MSR\HFI` | Intel Thread Director (HFI) & AMD CPPC Heterogeneous Scheduling endpoint |

---

## 3. Directory Layout

```
drivers/hfi/
├── hfi.hpp               # Standalone Driver Core Implementation
├── hfi.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── hfi.hpp
└── tests/
    └── test_hfi.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_hfi
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
