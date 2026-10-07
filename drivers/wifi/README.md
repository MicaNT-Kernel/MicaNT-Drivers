# Wi-Fi 7 (802.11be EHT) & WDI NetAdapterCx Miniport Subsystem

> **Sovereign Codename:** `TitanWiFi / NexusWiFi`  
> **Driver Binary:** `wdiwifi.sys`  
> **Header:** `wdiwifi.hpp`  
> **Class:** `Net` (`{4D36E972-E325-11CE-BFC1-08002BE10318}`)  
> **Start Type:** `SERVICE_BOOT_START`  

---

## 1. Architectural Overview & Provenance

The **Wi-Fi 7 (802.11be EHT) & WDI NetAdapterCx Miniport Subsystem** is a sovereign, clean-room implementation authored from public, openly licensed industry standards, hardware specifications, and `win32metadata`.

- **Clean-Room Compliance:** Authored 100% offline with zero decompilation, zero leaked proprietary symbols, and zero external runtime dependencies outside ISO C++23.
- **Auditing:** Fully verified by the **MicaNT Clean-Room Sentinel** automated heuristic and provenance auditor.
- **Telemetry:** Zero remote telemetry, zero cloud callbacks, completely deterministic memory footprint.

---

## 2. Hardware IDs & Supported Devices

This driver binds to the following hardware IDs via `wifi.inf`:

| Hardware ID | Description |
| :--- | :--- |
| `PCI\VEN_8086&DEV_272B` | Wi-Fi 7 (802.11be EHT) & WDI NetAdapterCx Miniport Subsystem endpoint |
| `PCI\CC_028000` | Wi-Fi 7 (802.11be EHT) & WDI NetAdapterCx Miniport Subsystem endpoint |

---

## 3. Directory Layout

```
drivers/wifi/
├── wdiwifi.hpp               # Standalone Driver Core Implementation
├── wifi.inf               # Windows Setup & PnP Installation INF File
├── CMakeLists.txt             # Standalone Driver CMake Build Specification
├── README.md                  # Subsystem Architecture Documentation
├── include/
│   └── micant/drivers/
│       └── wdiwifi.hpp
└── tests/
    └── test_wifi.cpp      # Comprehensive Standalone Verification Suite
```

---

## 4. Standalone Building & Verification

You can build and test this driver independently:

```bash
# Build standalone test runner
cmake -B build
cmake --build build --config Release

# Run verification test
./build/test_wifi
```

---

## 5. License & Attributions

Licensed under the **MIT License**. Part of the [MicaNT Operating System Foundation](https://github.com/MicaNT-Kernel).
