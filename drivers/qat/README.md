# Intel QuickAssist Technology (QAT 2.0 / 4xxx) Crypto/Compression Offload

> **Sovereign Codename:** `TitanQAT / NexusQAT`  
> **Driver Binary:** `intel_qat.sys`  
> **Header:** `qat.hpp`  
> **Class:** `System` (`{4D36E97D-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_SYSTEM_START`  

---

## 1. Architectural Overview & Provenance

The **Intel QuickAssist Technology (QAT 2.0 / 4xxx) Crypto/Compression Offload** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `qat.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `PCI\VEN_8086&DEV_4940` | Intel QuickAssist Technology (QAT 2.0 / 4xxx) Crypto/Compression Offload endpoint |
| `PCI\VEN_8086&DEV_4941` | Intel QuickAssist Technology (QAT 2.0 / 4xxx) Crypto/Compression Offload endpoint |

---

## 3. Directory Layout

```
drivers/qat/
├── qat.hpp               # Standalone Driver Core Implementation
├── qat.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── qat.hpp
└── tests/
    └── test_qat.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_qat
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
