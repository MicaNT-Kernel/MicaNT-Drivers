# Universal Serial Bus (USB 3.2 Gen 2) & xHCI 1.2 Host Controller

> **Sovereign Codename:** `TitanUSB / NexusUSB`  
> **Driver Binary:** `usbxhci.sys`  
> **Header:** `usb.hpp`  
> **Class:** `USB` (`{36FC9E60-C465-11CF-8056-444553540000}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **Universal Serial Bus (USB 3.2 Gen 2) & xHCI 1.2 Host Controller** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `usb.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `PCI\CC_0C0330` | Universal Serial Bus (USB 3.2 Gen 2) & xHCI 1.2 Host Controller endpoint |
| `PCI\VEN_8086&DEV_8D31` | Universal Serial Bus (USB 3.2 Gen 2) & xHCI 1.2 Host Controller endpoint |

---

## 3. Directory Layout

```
drivers/usb/
├── usb.hpp               # Standalone Driver Core Implementation
├── usb.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── usb.hpp
└── tests/
    └── test_usb.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_usb
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
