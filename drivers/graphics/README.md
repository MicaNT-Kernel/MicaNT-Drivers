# Windows Display Driver Model (WDDM 3.2) & Graphics Kernel

> **Sovereign Codename:** `TitanWDDM / NexusWDDM`  
> **Driver Binary:** `dxgkrnl.sys`  
> **Header:** `wddm.hpp`  
> **Class:** `Display` (`{4D36E968-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **Windows Display Driver Model (WDDM 3.2) & Graphics Kernel** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `graphics.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `PCI\CC_030000` | Windows Display Driver Model (WDDM 3.2) & Graphics Kernel endpoint |
| `PCI\VEN_1E0F&DEV_3D12` | Windows Display Driver Model (WDDM 3.2) & Graphics Kernel endpoint |
| `PCI\VEN_10DE` | Windows Display Driver Model (WDDM 3.2) & Graphics Kernel endpoint |
| `PCI\VEN_1002` | Windows Display Driver Model (WDDM 3.2) & Graphics Kernel endpoint |
| `PCI\VEN_8086` | Windows Display Driver Model (WDDM 3.2) & Graphics Kernel endpoint |

---

## 3. Directory Layout

```
drivers/graphics/
├── wddm.hpp               # Standalone Driver Core Implementation
├── graphics.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── wddm.hpp
└── tests/
    └── test_graphics.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_graphics
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
