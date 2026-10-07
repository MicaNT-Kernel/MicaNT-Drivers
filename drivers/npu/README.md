# Neural Processing Unit & Microsoft Compute Driver Model (MCDM)

> **Sovereign Codename:** `TitanNPU / NexusNPU`  
> **Driver Binary:** `mcdm.sys`  
> **Header:** `npu.hpp`  
> **Class:** `ComputeAccelerator` (`{F043A03B-FFC4-4270-83C1-9A727005706E}`)  
> **Start Type:** `SERVICE_SYSTEM_START`  

---

## 1. Architectural Overview & Provenance

The **Neural Processing Unit & Microsoft Compute Driver Model (MCDM)** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `npu.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `PCI\VEN_8086&DEV_7D1D` | Neural Processing Unit & Microsoft Compute Driver Model (MCDM) endpoint |
| `PCI\CC_120000` | Neural Processing Unit & Microsoft Compute Driver Model (MCDM) endpoint |

---

## 3. Directory Layout

```
drivers/npu/
├── npu.hpp               # Standalone Driver Core Implementation
├── npu.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── npu.hpp
└── tests/
    └── test_npu.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_npu
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
