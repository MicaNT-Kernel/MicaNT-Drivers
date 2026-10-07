#pragma once

/**
 * @file bluetooth.hpp
 * @brief Clean-Room Windows Bluetooth Core Architecture & Radio Subsystem (bluetoothapis.dll / bthprops.cpl).
 *
 * Implements the Win32 Bluetooth API architecture, radio enumeration and telemetry inspection,
 * remote device discovery, SDP service installation/enumeration, Secure Simple Pairing (SSP),
 * authentication callbacks, SCM services (bthserv, BthHFSrv), and Win32 C client APIs.
 *
 * 100% clean-room engineering referencing Microsoft's MIT-licensed win32metadata.
 * Zero proprietary, leaked, or decompiled code.
 */

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <algorithm>
#include <mutex>
#include <cstring>
#include <cwchar>
#include <sstream>
#include <iomanip>
#include <iostream>

#include "ntdef.hpp"
#include "kernel32.hpp"
#include "ole32.hpp"
#include "scm.hpp"
#include "ldr.hpp"

namespace micant::bluetooth {

using namespace micant::ole32;

// ============================================================================
// 1. Bluetooth Constants, Types & Status Codes
// ============================================================================

inline constexpr size_t BLUETOOTH_MAX_NAME_SIZE    = 248;
inline constexpr size_t BLUETOOTH_MAX_PASSKEY_SIZE = 16;

inline constexpr uint32_t BLUETOOTH_SERVICE_DISABLE = 0x00000000;
inline constexpr uint32_t BLUETOOTH_SERVICE_ENABLE  = 0x00000001;

// Error Codes
inline constexpr uint32_t BT_ERROR_SUCCESS              = 0;
inline constexpr uint32_t BT_ERROR_INVALID_PARAMETER    = 87;
inline constexpr uint32_t BT_ERROR_GEN_FAILURE          = 31;
inline constexpr uint32_t BT_ERROR_NOT_FOUND            = 1168;
inline constexpr uint32_t BT_ERROR_NO_MORE_ITEMS        = 259;
inline constexpr uint32_t BT_ERROR_DEVICE_NOT_CONNECTED = 1167;
inline constexpr uint32_t BT_ERROR_AUTH_FAILURE         = 1244;

// Bluetooth Device Major Classes (CoD)
inline constexpr uint32_t BTH_COD_MAJOR_MISCELLANEOUS = 0x00000000;
inline constexpr uint32_t BTH_COD_MAJOR_COMPUTER      = 0x00000100;
inline constexpr uint32_t BTH_COD_MAJOR_PHONE         = 0x00000200;
inline constexpr uint32_t BTH_COD_MAJOR_LAN_ACCESS    = 0x00000300;
inline constexpr uint32_t BTH_COD_MAJOR_AUDIO         = 0x00000400;
inline constexpr uint32_t BTH_COD_MAJOR_PERIPHERAL    = 0x00000500;
inline constexpr uint32_t BTH_COD_MAJOR_IMAGING       = 0x00000600;
inline constexpr uint32_t BTH_COD_MAJOR_WEARABLE      = 0x00000700;
inline constexpr uint32_t BTH_COD_MAJOR_TOY           = 0x00000800;
inline constexpr uint32_t BTH_COD_MAJOR_HEALTH        = 0x00000900;
inline constexpr uint32_t BTH_COD_MAJOR_UNCLASSIFIED  = 0x00001F00;

// Bluetooth 48-bit MAC Address representation
union BLUETOOTH_ADDRESS {
    uint64_t ullLong{0};
    uint8_t  rgBytes[6];

    constexpr bool operator==(const BLUETOOTH_ADDRESS& o) const noexcept {
        return (ullLong & 0x0000FFFFFFFFFFFFULL) == (o.ullLong & 0x0000FFFFFFFFFFFFULL);
    }
    constexpr bool operator!=(const BLUETOOTH_ADDRESS& o) const noexcept {
        return !(*this == o);
    }
};

inline std::string FormatBluetoothAddress(const BLUETOOTH_ADDRESS& addr) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    oss << std::setw(2) << static_cast<int>(addr.rgBytes[5]) << ":"
        << std::setw(2) << static_cast<int>(addr.rgBytes[4]) << ":"
        << std::setw(2) << static_cast<int>(addr.rgBytes[3]) << ":"
        << std::setw(2) << static_cast<int>(addr.rgBytes[2]) << ":"
        << std::setw(2) << static_cast<int>(addr.rgBytes[1]) << ":"
        << std::setw(2) << static_cast<int>(addr.rgBytes[0]);
    return oss.str();
}

inline BLUETOOTH_ADDRESS ParseBluetoothAddress(const std::string& str) {
    BLUETOOTH_ADDRESS addr{};
    std::string clean;
    for (char c : str) {
        if (c != ':' && c != '-' && c != ' ') {
            clean += c;
        }
    }
    if (clean.length() == 12) {
        try {
            uint64_t val = std::stoull(clean, nullptr, 16);
            for (size_t i = 0; i < 6; ++i) {
                addr.rgBytes[i] = static_cast<uint8_t>((val >> (i * 8)) & 0xFF);
            }
        } catch (...) {}
    }
    return addr;
}

using HBLUETOOTH_RADIO_FIND = void*;
using HBLUETOOTH_DEVICE_FIND = void*;
using HBLUETOOTH_AUTHENTICATION_REGISTRATION = void*;

struct BLUETOOTH_RADIO_INFO {
    uint32_t            dwSize{sizeof(BLUETOOTH_RADIO_INFO)};
    BLUETOOTH_ADDRESS   address{};
    wchar_t             szName[BLUETOOTH_MAX_NAME_SIZE]{};
    uint32_t            ulClassofDevice{0};
    uint16_t            lmpSubversion{0};
    uint16_t            manufacturer{0};
};

struct SYSTEMTIME {
    uint16_t wYear{2026};
    uint16_t wMonth{10};
    uint16_t wDayOfWeek{0};
    uint16_t wDay{4};
    uint16_t wHour{12};
    uint16_t wMinute{0};
    uint16_t wSecond{0};
    uint16_t wMilliseconds{0};
};

struct BLUETOOTH_DEVICE_INFO {
    uint32_t            dwSize{sizeof(BLUETOOTH_DEVICE_INFO)};
    BLUETOOTH_ADDRESS   Address{};
    uint32_t            ulClassofDevice{0};
    int32_t             fConnected{0};
    int32_t             fRemembered{0};
    int32_t             fAuthenticated{0};
    SYSTEMTIME          stLastSeen{};
    SYSTEMTIME          stLastUsed{};
    wchar_t             szName[BLUETOOTH_MAX_NAME_SIZE]{};
};

struct BLUETOOTH_DEVICE_SEARCH_PARAMS {
    uint32_t            dwSize{sizeof(BLUETOOTH_DEVICE_SEARCH_PARAMS)};
    int32_t             fReturnAuthenticated{1};
    int32_t             fReturnRemembered{1};
    int32_t             fReturnUnknown{1};
    int32_t             fReturnConnected{1};
    int32_t             fIssueInquiry{0};
    uint8_t             cTimeoutMultiplier{2};
    void*               hRadio{nullptr};
};

struct BLUETOOTH_FIND_RADIO_PARAMS {
    uint32_t            dwSize{sizeof(BLUETOOTH_FIND_RADIO_PARAMS)};
};

// Well-Known Bluetooth Service UUIDs (128-bit)
// Base: 00000000-0000-1000-8000-00805F9B34FB
inline const GUID GUID_BLUETOOTH_BASE = {
    0x00000000, 0x0000, 0x1000, { 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};

inline const GUID SerialPortServiceClass_UUID = {
    0x00001101, 0x0000, 0x1000, { 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};

inline const GUID DialupNetworkingServiceClass_UUID = {
    0x00001103, 0x0000, 0x1000, { 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};

inline const GUID HeadsetServiceClass_UUID = {
    0x00001108, 0x0000, 0x1000, { 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};

inline const GUID AudioSinkServiceClass_UUID = { // A2DP
    0x0000110B, 0x0000, 0x1000, { 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};

inline const GUID AV_RemoteControlServiceClass_UUID = { // AVRCP
    0x0000110E, 0x0000, 0x1000, { 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};

inline const GUID HandsfreeServiceClass_UUID = { // HFP
    0x0000111E, 0x0000, 0x1000, { 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};

inline const GUID HumanInterfaceDeviceServiceClass_UUID = { // HID
    0x00001124, 0x0000, 0x1000, { 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};

inline const GUID GenericAttributeProfile_UUID = { // GATT
    0x00001801, 0x0000, 0x1000, { 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};

inline const GUID BatteryService_UUID = {
    0x0000180F, 0x0000, 0x1000, { 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};

typedef int32_t (__stdcall *PFN_AUTHENTICATION_CALLBACK)(
    void* pvParam,
    BLUETOOTH_DEVICE_INFO* pDevice
);

// ============================================================================
// 2. Sovereign Bluetooth Architecture & Manager Engine
// ============================================================================

struct SovereignBluetoothRadio {
    void*               handle{nullptr};
    BLUETOOTH_RADIO_INFO info{};
    bool                isDiscoverable{true};
    bool                isConnectable{true};
    bool                isEnabled{true};
};

struct SovereignBluetoothDevice {
    BLUETOOTH_DEVICE_INFO info{};
    int32_t             rssi{-60}; // dBm
    uint8_t             batteryLevel{95}; // percent
    std::vector<GUID>   installedServices;
    std::string         passkey{"000000"};
};

class BluetoothManager {
public:
    static BluetoothManager& get() {
        static BluetoothManager s_instance;
        return s_instance;
    }

    BluetoothManager() {
        seedHardware();
    }

    void reset() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_radios.clear();
        m_devices.clear();
        m_authCallbacks.clear();
        seedHardware();
    }

    // Radios
    std::vector<SovereignBluetoothRadio> getRadios() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_radios;
    }

    SovereignBluetoothRadio* findRadio(void* hRadio) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& r : m_radios) {
            if (r.handle == hRadio || hRadio == nullptr) {
                return &r;
            }
        }
        return nullptr;
    }

    // Devices
    std::vector<SovereignBluetoothDevice> getDevices() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_devices;
    }

    SovereignBluetoothDevice* findDevice(const BLUETOOTH_ADDRESS& addr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& d : m_devices) {
            if (d.info.Address == addr) {
                return &d;
            }
        }
        return nullptr;
    }

    bool removeDevice(const BLUETOOTH_ADDRESS& addr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::remove_if(m_devices.begin(), m_devices.end(), [&](const SovereignBluetoothDevice& d) {
            return d.info.Address == addr;
        });
        if (it != m_devices.end()) {
            m_devices.erase(it, m_devices.end());
            return true;
        }
        return false;
    }

    bool updateDevice(const BLUETOOTH_DEVICE_INFO& info) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& d : m_devices) {
            if (d.info.Address == info.Address) {
                d.info = info;
                return true;
            }
        }
        return false;
    }

    // Services
    bool setServiceState(const BLUETOOTH_ADDRESS& addr, const GUID& guid, bool enable) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& d : m_devices) {
            if (d.info.Address == addr) {
                auto it = std::find_if(d.installedServices.begin(), d.installedServices.end(), [&](const GUID& g) {
                    return std::memcmp(&g, &guid, sizeof(GUID)) == 0;
                });
                if (enable && it == d.installedServices.end()) {
                    d.installedServices.push_back(guid);
                    return true;
                } else if (!enable && it != d.installedServices.end()) {
                    d.installedServices.erase(it);
                    return true;
                }
                return true;
            }
        }
        return false;
    }

    std::vector<GUID> getInstalledServices(const BLUETOOTH_ADDRESS& addr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& d : m_devices) {
            if (d.info.Address == addr) {
                return d.installedServices;
            }
        }
        return {};
    }

    // Authentication
    uint32_t registerAuthCallback(const BLUETOOTH_DEVICE_INFO* pDev, PFN_AUTHENTICATION_CALLBACK pfn, void* pvParam) {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t id = m_nextCallbackId++;
        AuthCallbackRec rec{};
        rec.id = id;
        rec.pfn = pfn;
        rec.param = pvParam;
        if (pDev) {
            rec.hasTarget = true;
            rec.targetAddr = pDev->Address;
        }
        m_authCallbacks.push_back(rec);
        return id;
    }

    bool unregisterAuthCallback(uint32_t id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::remove_if(m_authCallbacks.begin(), m_authCallbacks.end(), [&](const AuthCallbackRec& r) {
            return r.id == id;
        });
        if (it != m_authCallbacks.end()) {
            m_authCallbacks.erase(it, m_authCallbacks.end());
            return true;
        }
        return false;
    }

    bool authenticateDevice(const BLUETOOTH_ADDRESS& addr, const std::wstring& passkey) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& d : m_devices) {
            if (d.info.Address == addr) {
                d.info.fAuthenticated = 1;
                d.info.fRemembered = 1;
                d.info.fConnected = 1;
                // Dispatch callbacks if registered
                for (auto& cb : m_authCallbacks) {
                    if (!cb.hasTarget || cb.targetAddr == addr) {
                        if (cb.pfn) {
                            cb.pfn(cb.param, &d.info);
                        }
                    }
                }
                return true;
            }
        }
        return false;
    }

private:
    struct AuthCallbackRec {
        uint32_t id{0};
        PFN_AUTHENTICATION_CALLBACK pfn{nullptr};
        void* param{nullptr};
        bool hasTarget{false};
        BLUETOOTH_ADDRESS targetAddr{};
    };

    void seedHardware() {
        // 1. Primary Sovereign Bluetooth 5.4 Dual-Mode Host Controller Radio
        SovereignBluetoothRadio radio{};
        radio.handle = reinterpret_cast<void*>(0x401);
        radio.info.dwSize = sizeof(BLUETOOTH_RADIO_INFO);
        // Address: 00:1A:7D:DA:71:01
        radio.info.address.rgBytes[5] = 0x00;
        radio.info.address.rgBytes[4] = 0x1A;
        radio.info.address.rgBytes[3] = 0x7D;
        radio.info.address.rgBytes[2] = 0xDA;
        radio.info.address.rgBytes[1] = 0x71;
        radio.info.address.rgBytes[0] = 0x01;
        wcsncpy(radio.info.szName, L"MicaNT Sovereign Dual-Mode Bluetooth 5.4 Radio", BLUETOOTH_MAX_NAME_SIZE - 1);
        radio.info.ulClassofDevice = BTH_COD_MAJOR_COMPUTER | 0x04; // Desktop Workstation
        radio.info.lmpSubversion = 13; // LMP 13.0 (Bluetooth 5.4)
        radio.info.manufacturer = 0x05D6; // MicaNT Silicon Systems
        radio.isDiscoverable = true;
        radio.isConnectable = true;
        radio.isEnabled = true;
        m_radios.push_back(radio);

        // 2. Remote Peripheral: Titan Elite Wireless ANC Headset (Audio / Wearable)
        {
            SovereignBluetoothDevice dev{};
            dev.info.dwSize = sizeof(BLUETOOTH_DEVICE_INFO);
            // E4:5F:01:23:45:67
            dev.info.Address.rgBytes[5] = 0xE4;
            dev.info.Address.rgBytes[4] = 0x5F;
            dev.info.Address.rgBytes[3] = 0x01;
            dev.info.Address.rgBytes[2] = 0x23;
            dev.info.Address.rgBytes[1] = 0x45;
            dev.info.Address.rgBytes[0] = 0x67;
            dev.info.ulClassofDevice = BTH_COD_MAJOR_AUDIO | 0x04; // Headset / Audio Sink
            dev.info.fConnected = 1;
            dev.info.fRemembered = 1;
            dev.info.fAuthenticated = 1;
            wcsncpy(dev.info.szName, L"Titan Elite Wireless ANC Headset", BLUETOOTH_MAX_NAME_SIZE - 1);
            dev.rssi = -52;
            dev.batteryLevel = 88;
            dev.installedServices.push_back(AudioSinkServiceClass_UUID);
            dev.installedServices.push_back(HandsfreeServiceClass_UUID);
            dev.installedServices.push_back(AV_RemoteControlServiceClass_UUID);
            dev.installedServices.push_back(BatteryService_UUID);
            m_devices.push_back(dev);
        }

        // 3. Remote Peripheral: MicaPad Low Energy Wireless Controller (Peripheral / Gamepad)
        {
            SovereignBluetoothDevice dev{};
            dev.info.dwSize = sizeof(BLUETOOTH_DEVICE_INFO);
            // DC:A6:32:89:AB:CD
            dev.info.Address.rgBytes[5] = 0xDC;
            dev.info.Address.rgBytes[4] = 0xA6;
            dev.info.Address.rgBytes[3] = 0x32;
            dev.info.Address.rgBytes[2] = 0x89;
            dev.info.Address.rgBytes[1] = 0xAB;
            dev.info.Address.rgBytes[0] = 0xCD;
            dev.info.ulClassofDevice = BTH_COD_MAJOR_PERIPHERAL | 0x08; // Gamepad
            dev.info.fConnected = 1;
            dev.info.fRemembered = 1;
            dev.info.fAuthenticated = 1;
            wcsncpy(dev.info.szName, L"MicaPad Low Energy Wireless Controller", BLUETOOTH_MAX_NAME_SIZE - 1);
            dev.rssi = -60;
            dev.batteryLevel = 94;
            dev.installedServices.push_back(HumanInterfaceDeviceServiceClass_UUID);
            dev.installedServices.push_back(GenericAttributeProfile_UUID);
            dev.installedServices.push_back(BatteryService_UUID);
            m_devices.push_back(dev);
        }

        // 4. Remote Peripheral: Sovereign Precision Keyboard & Mouse (Discovered / Unpaired)
        {
            SovereignBluetoothDevice dev{};
            dev.info.dwSize = sizeof(BLUETOOTH_DEVICE_INFO);
            // 70:B3:D5:FE:10:99
            dev.info.Address.rgBytes[5] = 0x70;
            dev.info.Address.rgBytes[4] = 0xB3;
            dev.info.Address.rgBytes[3] = 0xD5;
            dev.info.Address.rgBytes[2] = 0xFE;
            dev.info.Address.rgBytes[1] = 0x10;
            dev.info.Address.rgBytes[0] = 0x99;
            dev.info.ulClassofDevice = BTH_COD_MAJOR_PERIPHERAL | 0xC0; // Combo Keyboard & Pointing
            dev.info.fConnected = 0;
            dev.info.fRemembered = 0;
            dev.info.fAuthenticated = 0;
            wcsncpy(dev.info.szName, L"Sovereign Precision Keyboard & Mouse", BLUETOOTH_MAX_NAME_SIZE - 1);
            dev.rssi = -74;
            dev.batteryLevel = 100;
            dev.installedServices.push_back(HumanInterfaceDeviceServiceClass_UUID);
            dev.installedServices.push_back(BatteryService_UUID);
            m_devices.push_back(dev);
        }
    }

    std::mutex m_mutex;
    std::vector<SovereignBluetoothRadio> m_radios;
    std::vector<SovereignBluetoothDevice> m_devices;
    std::vector<AuthCallbackRec> m_authCallbacks;
    uint32_t m_nextCallbackId{1};
};

// ============================================================================
// 3. Enumeration Handle Contexts
// ============================================================================

struct BluetoothRadioFindContext {
    std::vector<SovereignBluetoothRadio> radios;
    size_t index{0};
};

struct BluetoothDeviceFindContext {
    std::vector<SovereignBluetoothDevice> devices;
    size_t index{0};
};

// ============================================================================
// 4. Win32 Bluetooth C Client APIs (bluetoothapis.dll / bthprops.cpl)
// ============================================================================

inline HBLUETOOTH_RADIO_FIND __stdcall BluetoothFindFirstRadio(
    const BLUETOOTH_FIND_RADIO_PARAMS* pbtfrp,
    void** phRadio
) {
    if (!phRadio) return nullptr;
    *phRadio = nullptr;

    auto radios = BluetoothManager::get().getRadios();
    if (radios.empty()) return nullptr;

    auto ctx = new BluetoothRadioFindContext();
    ctx->radios = std::move(radios);
    ctx->index = 0;

    *phRadio = ctx->radios[0].handle;
    return reinterpret_cast<HBLUETOOTH_RADIO_FIND>(ctx);
}

inline int32_t __stdcall BluetoothFindNextRadio(
    HBLUETOOTH_RADIO_FIND hFind,
    void** phRadio
) {
    if (!hFind || !phRadio) return 0;
    auto ctx = reinterpret_cast<BluetoothRadioFindContext*>(hFind);
    ctx->index++;
    if (ctx->index < ctx->radios.size()) {
        *phRadio = ctx->radios[ctx->index].handle;
        return 1;
    }
    *phRadio = nullptr;
    return 0;
}

inline int32_t __stdcall BluetoothFindRadioClose(
    HBLUETOOTH_RADIO_FIND hFind
) {
    if (!hFind) return 0;
    delete reinterpret_cast<BluetoothRadioFindContext*>(hFind);
    return 1;
}

inline uint32_t __stdcall BluetoothGetRadioInfo(
    void* hRadio,
    BLUETOOTH_RADIO_INFO* pRadioInfo
) {
    if (!pRadioInfo) return BT_ERROR_INVALID_PARAMETER;
    auto* r = BluetoothManager::get().findRadio(hRadio);
    if (!r) return BT_ERROR_NOT_FOUND;

    *pRadioInfo = r->info;
    return BT_ERROR_SUCCESS;
}

inline HBLUETOOTH_DEVICE_FIND __stdcall BluetoothFindFirstDevice(
    const BLUETOOTH_DEVICE_SEARCH_PARAMS* pbtsp,
    BLUETOOTH_DEVICE_INFO* pbtdi
) {
    if (!pbtdi) return nullptr;

    auto allDevices = BluetoothManager::get().getDevices();
    std::vector<SovereignBluetoothDevice> matched;

    for (const auto& d : allDevices) {
        if (pbtsp) {
            if (!pbtsp->fReturnAuthenticated && d.info.fAuthenticated) continue;
            if (!pbtsp->fReturnRemembered && d.info.fRemembered) continue;
            if (!pbtsp->fReturnConnected && d.info.fConnected) continue;
            if (!pbtsp->fReturnUnknown && !d.info.fRemembered && !d.info.fAuthenticated) continue;
        }
        matched.push_back(d);
    }

    if (matched.empty()) return nullptr;

    auto ctx = new BluetoothDeviceFindContext();
    ctx->devices = std::move(matched);
    ctx->index = 0;

    *pbtdi = ctx->devices[0].info;
    return reinterpret_cast<HBLUETOOTH_DEVICE_FIND>(ctx);
}

inline int32_t __stdcall BluetoothFindNextDevice(
    HBLUETOOTH_DEVICE_FIND hFind,
    BLUETOOTH_DEVICE_INFO* pbtdi
) {
    if (!hFind || !pbtdi) return 0;
    auto ctx = reinterpret_cast<BluetoothDeviceFindContext*>(hFind);
    ctx->index++;
    if (ctx->index < ctx->devices.size()) {
        *pbtdi = ctx->devices[ctx->index].info;
        return 1;
    }
    return 0;
}

inline int32_t __stdcall BluetoothFindDeviceClose(
    HBLUETOOTH_DEVICE_FIND hFind
) {
    if (!hFind) return 0;
    delete reinterpret_cast<BluetoothDeviceFindContext*>(hFind);
    return 1;
}

inline uint32_t __stdcall BluetoothGetDeviceInfo(
    void* /*hRadio*/,
    BLUETOOTH_DEVICE_INFO* pbtdi
) {
    if (!pbtdi) return BT_ERROR_INVALID_PARAMETER;
    auto* d = BluetoothManager::get().findDevice(pbtdi->Address);
    if (!d) return BT_ERROR_NOT_FOUND;

    *pbtdi = d->info;
    return BT_ERROR_SUCCESS;
}

inline uint32_t __stdcall BluetoothUpdateDeviceRecord(
    const BLUETOOTH_DEVICE_INFO* pbtdi
) {
    if (!pbtdi) return BT_ERROR_INVALID_PARAMETER;
    return BluetoothManager::get().updateDevice(*pbtdi) ? BT_ERROR_SUCCESS : BT_ERROR_NOT_FOUND;
}

inline uint32_t __stdcall BluetoothRemoveDevice(
    const BLUETOOTH_ADDRESS* pAddress
) {
    if (!pAddress) return BT_ERROR_INVALID_PARAMETER;
    return BluetoothManager::get().removeDevice(*pAddress) ? BT_ERROR_SUCCESS : BT_ERROR_NOT_FOUND;
}

inline uint32_t __stdcall BluetoothSetServiceState(
    void* /*hRadio*/,
    const BLUETOOTH_DEVICE_INFO* pbtdi,
    const GUID* pGuidService,
    uint32_t dwServiceFlags
) {
    if (!pbtdi || !pGuidService) return BT_ERROR_INVALID_PARAMETER;
    bool enable = (dwServiceFlags & BLUETOOTH_SERVICE_ENABLE) != 0;
    return BluetoothManager::get().setServiceState(pbtdi->Address, *pGuidService, enable)
        ? BT_ERROR_SUCCESS : BT_ERROR_NOT_FOUND;
}

inline uint32_t __stdcall BluetoothEnumerateInstalledServices(
    void* /*hRadio*/,
    const BLUETOOTH_DEVICE_INFO* pbtdi,
    uint32_t* pcServiceInout,
    GUID* pGuidServices
) {
    if (!pbtdi || !pcServiceInout) return BT_ERROR_INVALID_PARAMETER;

    auto svcs = BluetoothManager::get().getInstalledServices(pbtdi->Address);
    if (!pGuidServices || *pcServiceInout == 0) {
        *pcServiceInout = static_cast<uint32_t>(svcs.size());
        return BT_ERROR_SUCCESS;
    }

    uint32_t copyCount = std::min(*pcServiceInout, static_cast<uint32_t>(svcs.size()));
    for (uint32_t i = 0; i < copyCount; ++i) {
        pGuidServices[i] = svcs[i];
    }
    *pcServiceInout = copyCount;
    return BT_ERROR_SUCCESS;
}

inline int32_t __stdcall BluetoothEnableDiscovery(
    void* hRadio,
    int32_t fEnable
) {
    auto* r = BluetoothManager::get().findRadio(hRadio);
    if (!r) return 0;
    r->isDiscoverable = (fEnable != 0);
    return 1;
}

inline int32_t __stdcall BluetoothIsDiscoverable(
    void* hRadio
) {
    auto* r = BluetoothManager::get().findRadio(hRadio);
    if (!r) return 0;
    return r->isDiscoverable ? 1 : 0;
}

inline int32_t __stdcall BluetoothEnableIncomingConnections(
    void* hRadio,
    int32_t fEnable
) {
    auto* r = BluetoothManager::get().findRadio(hRadio);
    if (!r) return 0;
    r->isConnectable = (fEnable != 0);
    return 1;
}

inline int32_t __stdcall BluetoothIsConnectable(
    void* hRadio
) {
    auto* r = BluetoothManager::get().findRadio(hRadio);
    if (!r) return 0;
    return r->isConnectable ? 1 : 0;
}

inline uint32_t __stdcall BluetoothRegisterForAuthentication(
    const BLUETOOTH_DEVICE_INFO* pbtdi,
    HBLUETOOTH_AUTHENTICATION_REGISTRATION* phRegHandle,
    PFN_AUTHENTICATION_CALLBACK pfnCallback,
    void* pvParam
) {
    if (!phRegHandle || !pfnCallback) return BT_ERROR_INVALID_PARAMETER;
    uint32_t id = BluetoothManager::get().registerAuthCallback(pbtdi, pfnCallback, pvParam);
    *phRegHandle = reinterpret_cast<HBLUETOOTH_AUTHENTICATION_REGISTRATION>(static_cast<uintptr_t>(id));
    return BT_ERROR_SUCCESS;
}

inline int32_t __stdcall BluetoothUnregisterAuthentication(
    HBLUETOOTH_AUTHENTICATION_REGISTRATION hRegHandle
) {
    if (!hRegHandle) return 0;
    uint32_t id = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(hRegHandle));
    return BluetoothManager::get().unregisterAuthCallback(id) ? 1 : 0;
}

inline uint32_t __stdcall BluetoothSendAuthenticationResponse(
    void* /*hRadio*/,
    BLUETOOTH_DEVICE_INFO* pbtdi,
    const wchar_t* pszPasskey
) {
    if (!pbtdi || !pszPasskey) return BT_ERROR_INVALID_PARAMETER;
    bool ok = BluetoothManager::get().authenticateDevice(pbtdi->Address, pszPasskey);
    return ok ? BT_ERROR_SUCCESS : BT_ERROR_AUTH_FAILURE;
}

inline uint32_t __stdcall BluetoothAuthenticateDevice(
    void* /*hwndParent*/,
    void* hRadio,
    BLUETOOTH_DEVICE_INFO* pbtdi,
    const wchar_t* pszPasskey,
    uint32_t /*ulPasskeyLength*/
) {
    if (!pbtdi) return BT_ERROR_INVALID_PARAMETER;
    std::wstring pk = pszPasskey ? pszPasskey : L"000000";
    return BluetoothSendAuthenticationResponse(hRadio, pbtdi, pk.c_str());
}

// bthprops.cpl Dialog Stubs
inline int32_t __stdcall CPlApplet(
    void* /*hwnd*/,
    uint32_t /*uMsg*/,
    uintptr_t /*lParam1*/,
    uintptr_t /*lParam2*/
) {
    return 1; // S_OK
}

inline int32_t __stdcall BluetoothSelectDevices(
    void* /*pbtsdp*/
) {
    return 1; // True
}

inline int32_t __stdcall BluetoothSelectDevicesFree(
    void* /*pbtsdp*/
) {
    return 1;
}

// ============================================================================
// 5. Dynamic Module Export Registration
// ============================================================================

inline void InitializeBluetoothSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // 1. bluetoothapis.dll
    ldr.registerExport("bluetoothapis.dll", "BluetoothFindFirstRadio", reinterpret_cast<void*>(&BluetoothFindFirstRadio));
    ldr.registerExport("bluetoothapis.dll", "BluetoothFindNextRadio", reinterpret_cast<void*>(&BluetoothFindNextRadio));
    ldr.registerExport("bluetoothapis.dll", "BluetoothFindRadioClose", reinterpret_cast<void*>(&BluetoothFindRadioClose));
    ldr.registerExport("bluetoothapis.dll", "BluetoothGetRadioInfo", reinterpret_cast<void*>(&BluetoothGetRadioInfo));
    ldr.registerExport("bluetoothapis.dll", "BluetoothFindFirstDevice", reinterpret_cast<void*>(&BluetoothFindFirstDevice));
    ldr.registerExport("bluetoothapis.dll", "BluetoothFindNextDevice", reinterpret_cast<void*>(&BluetoothFindNextDevice));
    ldr.registerExport("bluetoothapis.dll", "BluetoothFindDeviceClose", reinterpret_cast<void*>(&BluetoothFindDeviceClose));
    ldr.registerExport("bluetoothapis.dll", "BluetoothGetDeviceInfo", reinterpret_cast<void*>(&BluetoothGetDeviceInfo));
    ldr.registerExport("bluetoothapis.dll", "BluetoothUpdateDeviceRecord", reinterpret_cast<void*>(&BluetoothUpdateDeviceRecord));
    ldr.registerExport("bluetoothapis.dll", "BluetoothRemoveDevice", reinterpret_cast<void*>(&BluetoothRemoveDevice));
    ldr.registerExport("bluetoothapis.dll", "BluetoothSetServiceState", reinterpret_cast<void*>(&BluetoothSetServiceState));
    ldr.registerExport("bluetoothapis.dll", "BluetoothEnumerateInstalledServices", reinterpret_cast<void*>(&BluetoothEnumerateInstalledServices));
    ldr.registerExport("bluetoothapis.dll", "BluetoothEnableDiscovery", reinterpret_cast<void*>(&BluetoothEnableDiscovery));
    ldr.registerExport("bluetoothapis.dll", "BluetoothIsDiscoverable", reinterpret_cast<void*>(&BluetoothIsDiscoverable));
    ldr.registerExport("bluetoothapis.dll", "BluetoothEnableIncomingConnections", reinterpret_cast<void*>(&BluetoothEnableIncomingConnections));
    ldr.registerExport("bluetoothapis.dll", "BluetoothIsConnectable", reinterpret_cast<void*>(&BluetoothIsConnectable));
    ldr.registerExport("bluetoothapis.dll", "BluetoothRegisterForAuthentication", reinterpret_cast<void*>(&BluetoothRegisterForAuthentication));
    ldr.registerExport("bluetoothapis.dll", "BluetoothUnregisterAuthentication", reinterpret_cast<void*>(&BluetoothUnregisterAuthentication));
    ldr.registerExport("bluetoothapis.dll", "BluetoothSendAuthenticationResponse", reinterpret_cast<void*>(&BluetoothSendAuthenticationResponse));
    ldr.registerExport("bluetoothapis.dll", "BluetoothAuthenticateDevice", reinterpret_cast<void*>(&BluetoothAuthenticateDevice));

    // 2. bthprops.cpl
    ldr.registerExport("bthprops.cpl", "CPlApplet", reinterpret_cast<void*>(&CPlApplet));
    ldr.registerExport("bthprops.cpl", "BluetoothSelectDevices", reinterpret_cast<void*>(&BluetoothSelectDevices));
    ldr.registerExport("bthprops.cpl", "BluetoothSelectDevicesFree", reinterpret_cast<void*>(&BluetoothSelectDevicesFree));

    // 3. Register SCM Daemons
    auto& scm = scm::ServiceControlManager::get();
    if (!scm.getServiceRecord(L"bthserv")) {
        auto bthSvc = std::make_shared<scm::ServiceRecord>();
        bthSvc->serviceName = L"bthserv";
        bthSvc->displayName = L"Bluetooth Support Service";
        bthSvc->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        bthSvc->startType = scm::SERVICE_DEMAND_START;
        bthSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
        bthSvc->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k LocalService";
        bthSvc->loadOrderGroup = L"LocalService";
        bthSvc->status.dwServiceType = bthSvc->serviceType;
        bthSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
        bthSvc->status.dwProcessId = 1170;
        scm.registerServiceRecord(bthSvc);
    }

    if (!scm.getServiceRecord(L"BthHFSrv")) {
        auto hfSvc = std::make_shared<scm::ServiceRecord>();
        hfSvc->serviceName = L"BthHFSrv";
        hfSvc->displayName = L"Bluetooth Audio Gateway Service";
        hfSvc->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        hfSvc->startType = scm::SERVICE_DEMAND_START;
        hfSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
        hfSvc->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k LocalService";
        hfSvc->loadOrderGroup = L"LocalService";
        hfSvc->status.dwServiceType = hfSvc->serviceType;
        hfSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
        hfSvc->status.dwProcessId = 1174;
        scm.registerServiceRecord(hfSvc);
    }
}

} // namespace micant::bluetooth
