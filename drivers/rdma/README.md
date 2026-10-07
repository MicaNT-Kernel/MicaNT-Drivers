# Remote Direct Memory Access (RoCE v2 / InfiniBand) & SMB Direct

> **Sovereign Codename:** `TitanRDMA / NexusSMB`  
> **Driver Binary:** `ndisrdma.sys`  
> **Header:** `rdma.hpp`  
> **Class:** `Net` (`{4D36E972-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **Remote Direct Memory Access (RoCE v2 / InfiniBand) & SMB Direct** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `rdma.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `PCI\VEN_15B3&DEV_101B` | Remote Direct Memory Access (RoCE v2 / InfiniBand) & SMB Direct endpoint |
| `PCI\CC_020700` | Remote Direct Memory Access (RoCE v2 / InfiniBand) & SMB Direct endpoint |

---

## 3. Directory Layout

```
drivers/rdma/
├── rdma.hpp               # Standalone Driver Core Implementation
├── rdma.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── rdma.hpp
└── tests/
    └── test_rdma.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_rdma
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
