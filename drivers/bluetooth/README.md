# Bluetooth 5.4 & LE Audio Kernel Port Driver Subsystem

> **Sovereign Codename:** `TitanBTH / NexusBTH`  
> **Driver Binary:** `bthport.sys`  
> **Header:** `bthport.hpp`  
> **Class:** `Bluetooth` (`{E0CBF06C-CD8B-4647-BB8A-263B43F0F974}`)  
> **Start Type:** `SERVICE_SYSTEM_START`  

---

## 1. Architectural Overview & Provenance

The **Bluetooth 5.4 & LE Audio Kernel Port Driver Subsystem** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `bluetooth.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `USB\Class_E0&SubClass_01&Prot_01` | Bluetooth 5.4 & LE Audio Kernel Port Driver Subsystem endpoint |
| `BTH\MS_BTHPORT` | Bluetooth 5.4 & LE Audio Kernel Port Driver Subsystem endpoint |

---

## 3. Directory Layout

```
drivers/bluetooth/
├── bthport.hpp               # Standalone Driver Core Implementation
├── bluetooth.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── bthport.hpp
└── tests/
    └── test_bluetooth.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_bluetooth
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
