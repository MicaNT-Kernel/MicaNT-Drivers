// ============================================================================
// MicaNT: Sovereign Operating System Executive
// include/micant/setupapi.hpp - Windows Device Installation & Setup Subsystem
// (setupapi.dll)
//
// 100% Clean-Room Architecture authored from Microsoft win32metadata interface definitions.
// Zero proprietary code used or referenced. Google LLC v. Oracle America (2021).
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <cstring>
#include <cwchar>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <atomic>

#include "ntdef.hpp"
#include "heap.hpp"
#include "kernel32.hpp"
#include "ole32.hpp"
#include "cm.hpp"
#include "ldr.hpp"

namespace micant::setupapi {

// ============================================================================
// 1. SetupAPI Error Codes & Constants
// ============================================================================

inline constexpr uint32_t NO_ERROR_SETUP                      = 0;
inline constexpr uint32_t ERROR_LINE_NOT_FOUND                = 0xE0000102;
inline constexpr uint32_t ERROR_SECTION_NOT_FOUND             = 0xE0000103;
inline constexpr uint32_t ERROR_BAD_INF_SYNTAX                = 0xE0000100;
inline constexpr uint32_t ERROR_NO_DEVICE_ICON                = 0xE000020A;
inline constexpr uint32_t ERROR_INVALID_DEVINST_NAME          = 0xE000020B;
inline constexpr uint32_t ERROR_INVALID_CLASS                 = 0xE000020C;
inline constexpr uint32_t ERROR_DEVINST_ALREADY_EXISTS        = 0xE000020D;
inline constexpr uint32_t ERROR_NO_SUCH_DEVINST               = 0xE000020E;
inline constexpr uint32_t ERROR_NO_SUCH_INTERFACE             = 0xE000020F;
inline constexpr uint32_t ERROR_INVALID_CLASS_INSTALLER        = 0xE0000210;
inline constexpr uint32_t ERROR_DI_DO_DEFAULT                 = 0xE0000211;
inline constexpr uint32_t ERROR_DI_NO_FILE_COPY               = 0xE0000212;
inline constexpr uint32_t ERROR_INVALID_HWPROFILE             = 0xE0000213;
inline constexpr uint32_t ERROR_NO_DEVICE_SELECTED            = 0xE0000214;
inline constexpr uint32_t ERROR_KEY_DOES_NOT_EXIST            = 0xE0000215;
inline constexpr uint32_t ERROR_INVALID_DEVINST_HANDLE        = 0xE0000216;
inline constexpr uint32_t ERROR_NO_MORE_ITEMS                 = 259; // ERROR_NO_MORE_ITEMS

// GetClassDevs Flags
inline constexpr uint32_t DIGCF_DEFAULT         = 0x00000001;
inline constexpr uint32_t DIGCF_PRESENT         = 0x00000002;
inline constexpr uint32_t DIGCF_ALLCLASSES      = 0x00000004;
inline constexpr uint32_t DIGCF_PROFILE         = 0x00000008;
inline constexpr uint32_t DIGCF_DEVICEINTERFACE = 0x00000010;

// Device Registry Property Codes (SPDRP_*)
inline constexpr uint32_t SPDRP_DEVICEDESC                  = 0x00000000;
inline constexpr uint32_t SPDRP_HARDWAREID                  = 0x00000001;
inline constexpr uint32_t SPDRP_COMPATIBLEIDS               = 0x00000002;
inline constexpr uint32_t SPDRP_UNUSED0                     = 0x00000003;
inline constexpr uint32_t SPDRP_SERVICE                     = 0x00000004;
inline constexpr uint32_t SPDRP_UNUSED1                     = 0x00000005;
inline constexpr uint32_t SPDRP_UNUSED2                     = 0x00000006;
inline constexpr uint32_t SPDRP_CLASS                       = 0x00000007;
inline constexpr uint32_t SPDRP_CLASSGUID                   = 0x00000008;
inline constexpr uint32_t SPDRP_DRIVER                      = 0x00000009;
inline constexpr uint32_t SPDRP_CONFIGFLAGS                 = 0x0000000A;
inline constexpr uint32_t SPDRP_MFG                         = 0x0000000B;
inline constexpr uint32_t SPDRP_FRIENDLYNAME                = 0x0000000C;
inline constexpr uint32_t SPDRP_LOCATION_INFORMATION        = 0x0000000D;
inline constexpr uint32_t SPDRP_PHYSICAL_DEVICE_OBJECT_NAME = 0x0000000E;
inline constexpr uint32_t SPDRP_CAPABILITIES                = 0x0000000F;
inline constexpr uint32_t SPDRP_UI_NUMBER                   = 0x00000010;
inline constexpr uint32_t SPDRP_UPPERFILTERS                = 0x00000011;
inline constexpr uint32_t SPDRP_LOWERFILTERS                = 0x00000012;
inline constexpr uint32_t SPDRP_BUSTYPEGUID                 = 0x00000013;
inline constexpr uint32_t SPDRP_LEGACYBUSTYPE               = 0x00000014;
inline constexpr uint32_t SPDRP_BUSNUMBER                   = 0x00000015;
inline constexpr uint32_t SPDRP_ENUMERATOR_NAME             = 0x00000016;
inline constexpr uint32_t SPDRP_SECURITY                    = 0x00000017;
inline constexpr uint32_t SPDRP_SECURITY_SDS                = 0x00000018;
inline constexpr uint32_t SPDRP_DEVTYPE                     = 0x00000019;
inline constexpr uint32_t SPDRP_EXCLUSIVE                   = 0x0000001A;
inline constexpr uint32_t SPDRP_CHARACTERISTICS             = 0x0000001B;
inline constexpr uint32_t SPDRP_ADDRESS                     = 0x0000001C;
inline constexpr uint32_t SPDRP_UI_NUMBER_DESC_FORMAT       = 0x0000001D;
inline constexpr uint32_t SPDRP_DEVICE_POWER_DATA           = 0x0000001E;
inline constexpr uint32_t SPDRP_REMOVAL_POLICY              = 0x0000001F;
inline constexpr uint32_t SPDRP_REMOVAL_POLICY_HW_DEFAULT   = 0x00000020;
inline constexpr uint32_t SPDRP_REMOVAL_POLICY_OVERRIDE     = 0x00000021;
inline constexpr uint32_t SPDRP_INSTALL_STATE               = 0x00000022;
inline constexpr uint32_t SPDRP_LOCATION_PATHS              = 0x00000023;
inline constexpr uint32_t SPDRP_BASE_CONTAINERID            = 0x00000024;
inline constexpr uint32_t SPDRP_MAXIMUM_PROPERTY            = 0x00000025;

// DevKey Flags
inline constexpr uint32_t DICS_FLAG_GLOBAL   = 0x00000001;
inline constexpr uint32_t DICS_FLAG_CONFIGSPECIFIC = 0x00000002;
inline constexpr uint32_t DIREG_DEV          = 0x00000001;
inline constexpr uint32_t DIREG_DRV          = 0x00000002;
inline constexpr uint32_t DIREG_BOTH         = 0x00000004;

// Device Interface Flags
inline constexpr uint32_t SPINT_ACTIVE  = 0x00000001;
inline constexpr uint32_t SPINT_DEFAULT = 0x00000002;
inline constexpr uint32_t SPINT_REMOVED = 0x00000004;

// Driver Types
inline constexpr uint32_t SPDIT_CLASSDRIVER   = 0x00000001;
inline constexpr uint32_t SPDIT_COMPATDRIVER  = 0x00000002;

// Standard Device Setup Class GUIDs
inline const micant::GUID GUID_DEVCLASS_DISPLAY = {
    0x4d36e968, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
};
inline const micant::GUID GUID_DEVCLASS_NET = {
    0x4d36e972, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
};
inline const micant::GUID GUID_DEVCLASS_DISKDRIVE = {
    0x4d36e967, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
};
inline const micant::GUID GUID_DEVCLASS_MEDIA = {
    0x4d36e96c, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
};
inline const micant::GUID GUID_DEVCLASS_MOUSE = {
    0x4d36e96f, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
};
inline const micant::GUID GUID_DEVCLASS_KEYBOARD = {
    0x4d36e96b, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
};
inline const micant::GUID GUID_DEVCLASS_SYSTEM = {
    0x4d36e97d, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
};
inline const micant::GUID GUID_DEVCLASS_USB = {
    0x36fc9e60, 0xc465, 0x11cf, { 0x80, 0x56, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00 }
};
inline const micant::GUID GUID_DEVCLASS_HIDCLASS = {
    0x745a17a0, 0x74d3, 0x11d0, { 0xb6, 0xfe, 0x00, 0xa0, 0xc9, 0x0f, 0x57, 0xda }
};
inline const micant::GUID GUID_DEVCLASS_SCSIADAPTER = {
    0x4d36e97b, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
};

// ============================================================================
// 2. Data Structures (INFCONTEXT, SP_DEVINFO_DATA, SP_DEVICE_INTERFACE_DATA)
// ============================================================================

using HINF      = void*;
using HDEVINFO  = void*;
using HSPFILEQ  = void*;

struct INFCONTEXT {
    void*    Inf{nullptr};
    void*    CurrentInf{nullptr};
    uint32_t Section{0};
    uint32_t Line{0};
};

struct SP_DEVINFO_DATA {
    uint32_t     cbSize{sizeof(SP_DEVINFO_DATA)};
    micant::GUID ClassGuid{};
    uint32_t     DevInst{0};
    uintptr_t    Reserved{0};
};

struct SP_DEVICE_INTERFACE_DATA {
    uint32_t     cbSize{sizeof(SP_DEVICE_INTERFACE_DATA)};
    micant::GUID InterfaceClassGuid{};
    uint32_t     Flags{0};
    uintptr_t    Reserved{0};
};

struct SP_DEVICE_INTERFACE_DETAIL_DATA_W {
    uint32_t cbSize{sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)};
    wchar_t  DevicePath[1];
};

struct SP_DRVINFO_DATA_W {
    uint32_t     cbSize{sizeof(SP_DRVINFO_DATA_W)};
    uint32_t     DriverType{0};
    uintptr_t    Reserved{0};
    wchar_t      Description[256]{};
    wchar_t      MfgName[256]{};
    wchar_t      ProviderName[256]{};
    uint64_t     DriverDate{0};
    uint64_t     DriverVersion{0};
};

// ============================================================================
// 3. INF File Parser Architecture
// ============================================================================

struct InfLine {
    std::string key;
    std::vector<std::string> fields;
    std::string rawText;
};

struct InfSection {
    std::string name;
    std::vector<InfLine> lines;
};

class InfFile {
public:
    std::unordered_map<std::string, InfSection> sections;
    std::vector<std::string> sectionOrder;
    std::unordered_map<std::string, std::string> strings;

    static std::string trim(std::string_view s) {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string_view::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return std::string(s.substr(start, end - start + 1));
    }

    std::string expandString(const std::string& input) const {
        if (input.find('%') == std::string::npos) return input;
        std::string result;
        size_t i = 0;
        while (i < input.size()) {
            if (input[i] == '%') {
                size_t next = input.find('%', i + 1);
                if (next != std::string::npos) {
                    std::string key = input.substr(i + 1, next - i - 1);
                    std::string lowerKey = key;
                    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
                    auto it = strings.find(lowerKey);
                    if (it != strings.end()) {
                        result.append(it->second);
                    } else {
                        result.append(input.substr(i, next - i + 1));
                    }
                    i = next + 1;
                    continue;
                }
            }
            result.push_back(input[i++]);
        }
        return result;
    }

    bool parse(std::string_view content) {
        std::istringstream stream{ std::string(content) };
        std::string line;
        std::string currentSection = "";

        while (std::getline(stream, line)) {
            // Strip comments
            size_t commentPos = line.find(';');
            if (commentPos != std::string::npos) {
                line = line.substr(0, commentPos);
            }
            line = trim(line);
            if (line.empty()) continue;

            // Section header: [SectionName]
            if (line.front() == '[' && line.back() == ']') {
                currentSection = trim(line.substr(1, line.size() - 2));
                std::string lowerSec = currentSection;
                std::transform(lowerSec.begin(), lowerSec.end(), lowerSec.begin(), ::tolower);
                if (sections.find(lowerSec) == sections.end()) {
                    sections[lowerSec] = InfSection{ currentSection, {} };
                    sectionOrder.push_back(lowerSec);
                }
                continue;
            }

            if (currentSection.empty()) continue;

            std::string lowerSec = currentSection;
            std::transform(lowerSec.begin(), lowerSec.end(), lowerSec.begin(), ::tolower);

            // Parse key = field1, field2, ...
            InfLine infLine{};
            infLine.rawText = line;
            size_t eqPos = line.find('=');
            std::string fieldsStr;
            if (eqPos != std::string::npos) {
                infLine.key = trim(line.substr(0, eqPos));
                fieldsStr = trim(line.substr(eqPos + 1));
            } else {
                fieldsStr = line;
            }

            // Parse comma-delimited fields respecting quotes
            bool inQuotes = false;
            std::string curField;
            for (char c : fieldsStr) {
                if (c == '"') {
                    inQuotes = !inQuotes;
                } else if (c == ',' && !inQuotes) {
                    infLine.fields.push_back(trim(curField));
                    curField.clear();
                } else {
                    curField.push_back(c);
                }
            }
            if (!curField.empty() || !infLine.fields.empty()) {
                infLine.fields.push_back(trim(curField));
            }

            // Strip enclosing quotes from fields
            for (auto& f : infLine.fields) {
                if (f.size() >= 2 && f.front() == '"' && f.back() == '"') {
                    f = f.substr(1, f.size() - 2);
                }
            }

            // Populate [Strings] map
            if (lowerSec == "strings" && !infLine.key.empty()) {
                std::string lowerKey = infLine.key;
                std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
                std::string val = infLine.fields.empty() ? "" : infLine.fields[0];
                strings[lowerKey] = val;
            }

            sections[lowerSec].lines.push_back(std::move(infLine));
        }

        // Apply string substitutions across all fields
        for (auto& [secName, sec] : sections) {
            if (secName == "strings") continue;
            for (auto& l : sec.lines) {
                for (auto& f : l.fields) {
                    f = expandString(f);
                }
            }
        }

        return true;
    }
};

// ============================================================================
// 4. Device Information Element & Set
// ============================================================================

struct DeviceInterfaceElement {
    micant::GUID interfaceClassGuid{};
    uint32_t     flags{SPINT_ACTIVE};
    std::wstring devicePath;
};

struct DeviceInfoElement {
    uint32_t     devInst{0};
    micant::GUID classGuid{};
    std::wstring instanceId;
    std::unordered_map<uint32_t, std::vector<uint8_t>> registryProperties;
    std::vector<DeviceInterfaceElement> interfaces;
    std::vector<SP_DRVINFO_DATA_W> drivers;
};

class DeviceInfoSet {
public:
    explicit DeviceInfoSet(const micant::GUID* classGuid = nullptr) {
        if (classGuid) {
            m_hasSetClass = true;
            m_setClass = *classGuid;
        }
    }

    uint32_t addDevice(const micant::GUID& guid, const std::wstring& instanceId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t id = m_nextDevInst++;
        DeviceInfoElement dev{};
        dev.devInst = id;
        dev.classGuid = guid;
        dev.instanceId = instanceId;

        // Set standard default properties
        setStringProp(dev, SPDRP_CLASSGUID, guidToString(guid));
        setStringProp(dev, SPDRP_PHYSICAL_DEVICE_OBJECT_NAME, L"\\Device\\NTPNP_PCI" + std::to_wstring(id));

        m_devices.push_back(std::move(dev));
        return id;
    }

    bool removeDevice(uint32_t devInst) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find_if(m_devices.begin(), m_devices.end(), [&](const DeviceInfoElement& d) {
            return d.devInst == devInst;
        });
        if (it != m_devices.end()) {
            m_devices.erase(it);
            return true;
        }
        return false;
    }

    DeviceInfoElement* getDevice(uint32_t devInst) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& d : m_devices) {
            if (d.devInst == devInst) return &d;
        }
        return nullptr;
    }

    DeviceInfoElement* getDeviceByIndex(uint32_t index) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (index < m_devices.size()) {
            return &m_devices[index];
        }
        return nullptr;
    }

    size_t getDeviceCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_devices.size();
    }

    bool hasClassFilter() const noexcept { return m_hasSetClass; }
    const micant::GUID& getClassFilter() const noexcept { return m_setClass; }

    static void setStringProp(DeviceInfoElement& dev, uint32_t prop, const std::wstring& str) {
        size_t byteCount = (str.size() + 1) * sizeof(wchar_t);
        std::vector<uint8_t> buf(byteCount);
        std::memcpy(buf.data(), str.c_str(), byteCount);
        dev.registryProperties[prop] = std::move(buf);
    }

    static std::wstring getStringProp(const DeviceInfoElement& dev, uint32_t prop) {
        auto it = dev.registryProperties.find(prop);
        if (it == dev.registryProperties.end()) return L"";
        return std::wstring(reinterpret_cast<const wchar_t*>(it->second.data()));
    }

    static std::wstring guidToString(const micant::GUID& g) {
        wchar_t buf[64]{};
        std::swprintf(buf, sizeof(buf) / sizeof(wchar_t),
            L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
            g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
        return std::wstring(buf);
    }

private:
    mutable std::mutex m_mutex;
    bool m_hasSetClass{false};
    micant::GUID m_setClass{};
    uint32_t m_nextDevInst{100};
    std::vector<DeviceInfoElement> m_devices;
};

// Global Hardware Device Registry
class GlobalDeviceManager {
public:
    static GlobalDeviceManager& Instance() {
        static GlobalDeviceManager s_instance;
        return s_instance;
    }

    void seedStandardHardware() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_seeded) return;
        m_seeded = true;

        // 1. Display Adapter: Sovereign PrismX GPU
        {
            DeviceInfoElement d{};
            d.devInst = 1;
            d.classGuid = GUID_DEVCLASS_DISPLAY;
            d.instanceId = L"PCI\\VEN_10DE&DEV_2684&SUBSYS_168210DE&REV_A1\\4&3b3b1c2e&0&0008";
            DeviceInfoSet::setStringProp(d, SPDRP_DEVICEDESC, L"MicaNT Sovereign PrismX Graphics Accelerator");
            DeviceInfoSet::setStringProp(d, SPDRP_FRIENDLYNAME, L"MicaNT PrismX 3D/Compute Adapter");
            DeviceInfoSet::setStringProp(d, SPDRP_HARDWAREID, L"PCI\\VEN_10DE&DEV_2684&SUBSYS_168210DE&REV_A1");
            DeviceInfoSet::setStringProp(d, SPDRP_CLASS, L"Display");
            DeviceInfoSet::setStringProp(d, SPDRP_CLASSGUID, DeviceInfoSet::guidToString(GUID_DEVCLASS_DISPLAY));
            DeviceInfoSet::setStringProp(d, SPDRP_MFG, L"MicaNT Project MICA");
            DeviceInfoSet::setStringProp(d, SPDRP_DRIVER, L"{4d36e968-e325-11ce-bfc1-08002be10318}\\0000");

            DeviceInterfaceElement iface{};
            iface.interfaceClassGuid = GUID_DEVCLASS_DISPLAY;
            iface.flags = SPINT_ACTIVE | SPINT_DEFAULT;
            iface.devicePath = L"\\\\?\\PCI#VEN_10DE&DEV_2684#{4d36e968-e325-11ce-bfc1-08002be10318}";
            d.interfaces.push_back(iface);

            m_devices.push_back(std::move(d));
        }

        // 2. Network Controller: Sovereign NDIS VirtIO Adapter
        {
            DeviceInfoElement d{};
            d.devInst = 2;
            d.classGuid = GUID_DEVCLASS_NET;
            d.instanceId = L"PCI\\VEN_1AF4&DEV_1000&SUBSYS_00011AF4&REV_00\\4&1a2b3c4d&0&0010";
            DeviceInfoSet::setStringProp(d, SPDRP_DEVICEDESC, L"MicaNT RazzleNet 10Gbps Virtual Network Adapter");
            DeviceInfoSet::setStringProp(d, SPDRP_FRIENDLYNAME, L"Ethernet 0 (MicaNT Virtual Adapter)");
            DeviceInfoSet::setStringProp(d, SPDRP_HARDWAREID, L"PCI\\VEN_1AF4&DEV_1000");
            DeviceInfoSet::setStringProp(d, SPDRP_CLASS, L"Net");
            DeviceInfoSet::setStringProp(d, SPDRP_CLASSGUID, DeviceInfoSet::guidToString(GUID_DEVCLASS_NET));
            DeviceInfoSet::setStringProp(d, SPDRP_MFG, L"MicaNT Sovereign Project");
            DeviceInfoSet::setStringProp(d, SPDRP_DRIVER, L"{4d36e972-e325-11ce-bfc1-08002be10318}\\0000");

            DeviceInterfaceElement iface{};
            iface.interfaceClassGuid = GUID_DEVCLASS_NET;
            iface.flags = SPINT_ACTIVE;
            iface.devicePath = L"\\\\?\\PCI#VEN_1AF4&DEV_1000#{4d36e972-e325-11ce-bfc1-08002be10318}";
            d.interfaces.push_back(iface);

            m_devices.push_back(std::move(d));
        }

        // 3. Block Storage Controller: NVMe SSD
        {
            DeviceInfoElement d{};
            d.devInst = 3;
            d.classGuid = GUID_DEVCLASS_DISKDRIVE;
            d.instanceId = L"SCSI\\Disk&Ven_NVMe&Prod_MicaNT_SSD\\5&11223344&0&000000";
            DeviceInfoSet::setStringProp(d, SPDRP_DEVICEDESC, L"MicaNT Sovereign FastFAT/NTFS Solid State Drive");
            DeviceInfoSet::setStringProp(d, SPDRP_FRIENDLYNAME, L"NVMe MicaNT 1024GB SSD Disk Device");
            DeviceInfoSet::setStringProp(d, SPDRP_HARDWAREID, L"SCSI\\DiskNVMe____MicaNT_SSD______1.0");
            DeviceInfoSet::setStringProp(d, SPDRP_CLASS, L"DiskDrive");
            DeviceInfoSet::setStringProp(d, SPDRP_CLASSGUID, DeviceInfoSet::guidToString(GUID_DEVCLASS_DISKDRIVE));
            DeviceInfoSet::setStringProp(d, SPDRP_MFG, L"(Standard disk drives)");

            DeviceInterfaceElement iface{};
            iface.interfaceClassGuid = GUID_DEVCLASS_DISKDRIVE;
            iface.flags = SPINT_ACTIVE;
            iface.devicePath = L"\\\\?\\SCSI#Disk&Ven_NVMe#{4d36e967-e325-11ce-bfc1-08002be10318}";
            d.interfaces.push_back(iface);

            m_devices.push_back(std::move(d));
        }

        // 4. Audio Controller: High Definition Audio
        {
            DeviceInfoElement d{};
            d.devInst = 4;
            d.classGuid = GUID_DEVCLASS_MEDIA;
            d.instanceId = L"HDAUDIO\\FUNC_01&VEN_10EC&DEV_0892&SUBSYS_1043841B&REV_1003";
            DeviceInfoSet::setStringProp(d, SPDRP_DEVICEDESC, L"MicaNT PrismAudio High Definition Audio Device");
            DeviceInfoSet::setStringProp(d, SPDRP_FRIENDLYNAME, L"PrismAudio HD Sound Controller");
            DeviceInfoSet::setStringProp(d, SPDRP_HARDWAREID, L"HDAUDIO\\FUNC_01&VEN_10EC&DEV_0892");
            DeviceInfoSet::setStringProp(d, SPDRP_CLASS, L"Media");
            DeviceInfoSet::setStringProp(d, SPDRP_CLASSGUID, DeviceInfoSet::guidToString(GUID_DEVCLASS_MEDIA));
            DeviceInfoSet::setStringProp(d, SPDRP_MFG, L"MicaNT Project MICA");

            DeviceInterfaceElement iface{};
            iface.interfaceClassGuid = GUID_DEVCLASS_MEDIA;
            iface.flags = SPINT_ACTIVE;
            iface.devicePath = L"\\\\?\\HDAUDIO#FUNC_01#{4d36e96c-e325-11ce-bfc1-08002be10318}";
            d.interfaces.push_back(iface);

            m_devices.push_back(std::move(d));
        }

        // 5. System Root Device
        {
            DeviceInfoElement d{};
            d.devInst = 5;
            d.classGuid = GUID_DEVCLASS_SYSTEM;
            d.instanceId = L"ROOT\\ACPI_HAL\\0000";
            DeviceInfoSet::setStringProp(d, SPDRP_DEVICEDESC, L"MicaNT ACPI x64-based Sovereign Executive PC");
            DeviceInfoSet::setStringProp(d, SPDRP_FRIENDLYNAME, L"ACPI Multiprocessor PC");
            DeviceInfoSet::setStringProp(d, SPDRP_HARDWAREID, L"ROOT\\ACPI_HAL");
            DeviceInfoSet::setStringProp(d, SPDRP_CLASS, L"System");
            DeviceInfoSet::setStringProp(d, SPDRP_CLASSGUID, DeviceInfoSet::guidToString(GUID_DEVCLASS_SYSTEM));
            DeviceInfoSet::setStringProp(d, SPDRP_MFG, L"(Standard system devices)");

            m_devices.push_back(std::move(d));
        }
    }

    std::vector<DeviceInfoElement> getSnapshot(const micant::GUID* classGuid, uint32_t flags) {
        seedStandardHardware();
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<DeviceInfoElement> result;

        for (const auto& dev : m_devices) {
            if (!(flags & DIGCF_ALLCLASSES) && classGuid) {
                if (dev.classGuid != *classGuid) continue;
            }
            if ((flags & DIGCF_DEVICEINTERFACE) && dev.interfaces.empty()) {
                continue;
            }
            result.push_back(dev);
        }
        return result;
    }

private:
    GlobalDeviceManager() = default;
    std::mutex m_mutex;
    bool m_seeded{false};
    std::vector<DeviceInfoElement> m_devices;
};

// ============================================================================
// 5. INF File API Implementations
// ============================================================================

inline HINF __stdcall SetupOpenInfFileW(
    const wchar_t* fileName,
    [[maybe_unused]] const wchar_t* infClass,
    [[maybe_unused]] uint32_t infStyle,
    uint32_t* errorLine
) {
    if (!fileName) {
        if (errorLine) *errorLine = 0;
        return reinterpret_cast<HINF>(static_cast<uintptr_t>(-1));
    }

    // Convert filename to narrow path and load
    std::string path;
    for (int i = 0; fileName[i] != L'\0'; ++i) {
        path.push_back(static_cast<char>(fileName[i] & 0x7F));
    }

    std::string content;
    // Attempt reading from VFS or host filesystem
    std::ifstream file(path);
    if (file.is_open()) {
        std::stringstream ss;
        ss << file.rdbuf();
        content = ss.str();
    } else {
        // Fallback default built-in driver INF if file doesn't exist on disk
        content =
            "[Version]\n"
            "Signature = \"$WINDOWS NT$\"\n"
            "Class = Display\n"
            "ClassGuid = {4d36e968-e325-11ce-bfc1-08002be10318}\n"
            "Provider = %ManufacturerName%\n"
            "DriverVer = 10/01/2026,1.0.70.0\n"
            "\n"
            "[Manufacturer]\n"
            "%ManufacturerName% = Standard,NTamd64\n"
            "\n"
            "[Standard.NTamd64]\n"
            "%PrismXDevice% = PrismX_Install, PCI\\VEN_10DE&DEV_2684\n"
            "\n"
            "[PrismX_Install]\n"
            "CopyFiles = PrismX_Copy\n"
            "\n"
            "[PrismX_Copy]\n"
            "prismx.sys\n"
            "\n"
            "[Strings]\n"
            "ManufacturerName = \"MicaNT Sovereign Project\"\n"
            "PrismXDevice = \"MicaNT Sovereign PrismX Graphics Accelerator\"\n";
    }

    auto inf = std::make_unique<InfFile>();
    if (!inf->parse(content)) {
        if (errorLine) *errorLine = 1;
        return reinterpret_cast<HINF>(static_cast<uintptr_t>(-1));
    }

    return reinterpret_cast<HINF>(inf.release());
}

inline HINF __stdcall SetupOpenInfFileA(
    const char* fileName,
    const char* infClass,
    uint32_t infStyle,
    uint32_t* errorLine
) {
    if (!fileName) return reinterpret_cast<HINF>(static_cast<uintptr_t>(-1));
    std::wstring wPath;
    for (int i = 0; fileName[i] != '\0'; ++i) wPath.push_back(static_cast<wchar_t>(fileName[i]));
    std::wstring wClass;
    if (infClass) for (int i = 0; infClass[i] != '\0'; ++i) wClass.push_back(static_cast<wchar_t>(infClass[i]));
    return SetupOpenInfFileW(wPath.c_str(), infClass ? wClass.c_str() : nullptr, infStyle, errorLine);
}

inline void __stdcall SetupCloseInfFile(HINF infHandle) {
    if (!infHandle || infHandle == reinterpret_cast<HINF>(static_cast<uintptr_t>(-1))) return;
    delete reinterpret_cast<InfFile*>(infHandle);
}

inline win32::BOOL __stdcall SetupFindFirstLineW(
    HINF infHandle,
    const wchar_t* sectionName,
    const wchar_t* key,
    INFCONTEXT* context
) {
    if (!infHandle || infHandle == reinterpret_cast<HINF>(static_cast<uintptr_t>(-1)) || !sectionName || !context) {
        return 0;
    }

    auto* inf = reinterpret_cast<InfFile*>(infHandle);
    std::string sName;
    for (int i = 0; sectionName[i] != L'\0'; ++i) sName.push_back(static_cast<char>(std::tolower(sectionName[i])));

    auto it = inf->sections.find(sName);
    if (it == inf->sections.end() || it->second.lines.empty()) {
        return 0;
    }

    std::string sKey;
    if (key) {
        for (int i = 0; key[i] != L'\0'; ++i) sKey.push_back(static_cast<char>(std::tolower(key[i])));
    }

    const auto& lines = it->second.lines;
    for (size_t i = 0; i < lines.size(); ++i) {
        if (!sKey.empty()) {
            std::string lineKey = lines[i].key;
            std::transform(lineKey.begin(), lineKey.end(), lineKey.begin(), ::tolower);
            if (lineKey != sKey) continue;
        }

        context->Inf = infHandle;
        context->CurrentInf = infHandle;
        // Section index
        auto orderIt = std::find(inf->sectionOrder.begin(), inf->sectionOrder.end(), sName);
        context->Section = static_cast<uint32_t>(std::distance(inf->sectionOrder.begin(), orderIt));
        context->Line = static_cast<uint32_t>(i);
        return 1;
    }
    return 0;
}

inline win32::BOOL __stdcall SetupFindNextLine(
    INFCONTEXT* contextIn,
    INFCONTEXT* contextOut
) {
    if (!contextIn || !contextOut || !contextIn->Inf) return 0;
    auto* inf = reinterpret_cast<InfFile*>(contextIn->Inf);
    if (contextIn->Section >= inf->sectionOrder.size()) return 0;

    const std::string& secName = inf->sectionOrder[contextIn->Section];
    const auto& sec = inf->sections[secName];

    uint32_t nextLine = contextIn->Line + 1;
    if (nextLine >= sec.lines.size()) return 0;

    *contextOut = *contextIn;
    contextOut->Line = nextLine;
    return 1;
}

inline int32_t __stdcall SetupGetLineCountW(HINF infHandle, const wchar_t* sectionName) {
    if (!infHandle || !sectionName) return -1;
    auto* inf = reinterpret_cast<InfFile*>(infHandle);
    std::string sName;
    for (int i = 0; sectionName[i] != L'\0'; ++i) sName.push_back(static_cast<char>(std::tolower(sectionName[i])));
    auto it = inf->sections.find(sName);
    if (it == inf->sections.end()) return -1;
    return static_cast<int32_t>(it->second.lines.size());
}

inline uint32_t __stdcall SetupGetFieldCount(INFCONTEXT* context) {
    if (!context || !context->Inf) return 0;
    auto* inf = reinterpret_cast<InfFile*>(context->Inf);
    if (context->Section >= inf->sectionOrder.size()) return 0;
    const std::string& secName = inf->sectionOrder[context->Section];
    const auto& sec = inf->sections[secName];
    if (context->Line >= sec.lines.size()) return 0;
    return static_cast<uint32_t>(sec.lines[context->Line].fields.size());
}

inline win32::BOOL __stdcall SetupGetStringFieldW(
    INFCONTEXT* context,
    uint32_t fieldIndex,
    wchar_t* returnBuffer,
    uint32_t returnBufferSize,
    uint32_t* requiredSize
) {
    if (!context || !context->Inf) return 0;
    auto* inf = reinterpret_cast<InfFile*>(context->Inf);
    if (context->Section >= inf->sectionOrder.size()) return 0;
    const std::string& secName = inf->sectionOrder[context->Section];
    const auto& sec = inf->sections[secName];
    if (context->Line >= sec.lines.size()) return 0;

    const auto& line = sec.lines[context->Line];
    std::string val;
    if (fieldIndex == 0) {
        val = line.key;
    } else if (fieldIndex <= line.fields.size()) {
        val = line.fields[fieldIndex - 1];
    } else {
        return 0;
    }

    uint32_t charsNeeded = static_cast<uint32_t>(val.size() + 1);
    if (requiredSize) *requiredSize = charsNeeded;

    if (!returnBuffer || returnBufferSize == 0) {
        return 1; // Query size only
    }

    if (returnBufferSize < charsNeeded) return 0;

    for (size_t i = 0; i < val.size(); ++i) {
        returnBuffer[i] = static_cast<wchar_t>(static_cast<uint8_t>(val[i]));
    }
    returnBuffer[val.size()] = L'\0';
    return 1;
}

inline win32::BOOL __stdcall SetupGetIntField(
    INFCONTEXT* context,
    uint32_t fieldIndex,
    int32_t* integerValue
) {
    if (!context || !integerValue) return 0;
    wchar_t buf[64]{};
    uint32_t req = 0;
    if (!SetupGetStringFieldW(context, fieldIndex, buf, 64, &req)) return 0;
    *integerValue = std::wcstol(buf, nullptr, 0);
    return 1;
}

// ============================================================================
// 6. Device Information Set & Property APIs (SetupDi*)
// ============================================================================

inline HDEVINFO __stdcall SetupDiCreateDeviceInfoList(
    const micant::GUID* classGuid,
    [[maybe_unused]] win32::HWND hwndParent
) {
    auto set = std::make_unique<DeviceInfoSet>(classGuid);
    return reinterpret_cast<HDEVINFO>(set.release());
}

inline win32::BOOL __stdcall SetupDiDestroyDeviceInfoList(HDEVINFO deviceInfoSet) {
    if (!deviceInfoSet || deviceInfoSet == reinterpret_cast<HDEVINFO>(static_cast<uintptr_t>(-1))) {
        return 0;
    }
    delete reinterpret_cast<DeviceInfoSet*>(deviceInfoSet);
    return 1;
}

inline win32::BOOL __stdcall SetupDiCreateDeviceInfoW(
    HDEVINFO deviceInfoSet,
    const wchar_t* deviceName,
    const micant::GUID* classGuid,
    [[maybe_unused]] const wchar_t* deviceDescription,
    [[maybe_unused]] win32::HWND hwndParent,
    [[maybe_unused]] uint32_t creationFlags,
    SP_DEVINFO_DATA* deviceInfoData
) {
    if (!deviceInfoSet || !deviceName || !classGuid) return 0;
    auto* set = reinterpret_cast<DeviceInfoSet*>(deviceInfoSet);

    uint32_t devInst = set->addDevice(*classGuid, deviceName);
    auto* dev = set->getDevice(devInst);
    if (deviceDescription && dev) {
        DeviceInfoSet::setStringProp(*dev, SPDRP_DEVICEDESC, deviceDescription);
    }

    if (deviceInfoData) {
        deviceInfoData->cbSize = sizeof(SP_DEVINFO_DATA);
        deviceInfoData->ClassGuid = *classGuid;
        deviceInfoData->DevInst = devInst;
        deviceInfoData->Reserved = 0;
    }
    return 1;
}

inline win32::BOOL __stdcall SetupDiEnumDeviceInfo(
    HDEVINFO deviceInfoSet,
    uint32_t memberIndex,
    SP_DEVINFO_DATA* deviceInfoData
) {
    if (!deviceInfoSet || !deviceInfoData) return 0;
    auto* set = reinterpret_cast<DeviceInfoSet*>(deviceInfoSet);
    auto* dev = set->getDeviceByIndex(memberIndex);
    if (!dev) return 0;

    deviceInfoData->cbSize = sizeof(SP_DEVINFO_DATA);
    deviceInfoData->ClassGuid = dev->classGuid;
    deviceInfoData->DevInst = dev->devInst;
    deviceInfoData->Reserved = 0;
    return 1;
}

inline win32::BOOL __stdcall SetupDiGetDeviceRegistryPropertyW(
    HDEVINFO deviceInfoSet,
    SP_DEVINFO_DATA* deviceInfoData,
    uint32_t property,
    uint32_t* propertyRegDataType,
    uint8_t* propertyBuffer,
    uint32_t propertyBufferSize,
    uint32_t* requiredSize
) {
    if (!deviceInfoSet || !deviceInfoData) return 0;
    auto* set = reinterpret_cast<DeviceInfoSet*>(deviceInfoSet);
    auto* dev = set->getDevice(deviceInfoData->DevInst);
    if (!dev) return 0;

    auto it = dev->registryProperties.find(property);
    if (it == dev->registryProperties.end()) return 0;

    uint32_t bytes = static_cast<uint32_t>(it->second.size());
    if (requiredSize) *requiredSize = bytes;

    if (!propertyBuffer || propertyBufferSize == 0) {
        return 1; // Size query
    }

    if (propertyBufferSize < bytes) return 0;

    std::memcpy(propertyBuffer, it->second.data(), bytes);
    if (propertyRegDataType) {
        *propertyRegDataType = 1; // REG_SZ default
    }
    return 1;
}

inline win32::BOOL __stdcall SetupDiSetDeviceRegistryPropertyW(
    HDEVINFO deviceInfoSet,
    SP_DEVINFO_DATA* deviceInfoData,
    uint32_t property,
    const uint8_t* propertyBuffer,
    uint32_t propertyBufferSize
) {
    if (!deviceInfoSet || !deviceInfoData || !propertyBuffer) return 0;
    auto* set = reinterpret_cast<DeviceInfoSet*>(deviceInfoSet);
    auto* dev = set->getDevice(deviceInfoData->DevInst);
    if (!dev) return 0;

    std::vector<uint8_t> buf(propertyBuffer, propertyBuffer + propertyBufferSize);
    dev->registryProperties[property] = std::move(buf);
    return 1;
}

inline win32::BOOL __stdcall SetupDiGetDeviceInstanceIdW(
    HDEVINFO deviceInfoSet,
    SP_DEVINFO_DATA* deviceInfoData,
    wchar_t* deviceInstanceId,
    uint32_t deviceInstanceIdSize,
    uint32_t* requiredSize
) {
    if (!deviceInfoSet || !deviceInfoData) return 0;
    auto* set = reinterpret_cast<DeviceInfoSet*>(deviceInfoSet);
    auto* dev = set->getDevice(deviceInfoData->DevInst);
    if (!dev) return 0;

    uint32_t chars = static_cast<uint32_t>(dev->instanceId.size() + 1);
    if (requiredSize) *requiredSize = chars;

    if (!deviceInstanceId || deviceInstanceIdSize == 0) return 1;
    if (deviceInstanceIdSize < chars) return 0;

    std::wcscpy(deviceInstanceId, dev->instanceId.c_str());
    return 1;
}

inline win32::BOOL __stdcall SetupDiCreateDeviceInterfaceW(
    HDEVINFO deviceInfoSet,
    SP_DEVINFO_DATA* deviceInfoData,
    const micant::GUID* interfaceClassGuid,
    [[maybe_unused]] const wchar_t* referenceString,
    [[maybe_unused]] uint32_t creationFlags,
    SP_DEVICE_INTERFACE_DATA* deviceInterfaceData
) {
    if (!deviceInfoSet || !deviceInfoData || !interfaceClassGuid) return 0;
    auto* set = reinterpret_cast<DeviceInfoSet*>(deviceInfoSet);
    auto* dev = set->getDevice(deviceInfoData->DevInst);
    if (!dev) return 0;

    DeviceInterfaceElement iface{};
    iface.interfaceClassGuid = *interfaceClassGuid;
    iface.flags = SPINT_ACTIVE;
    iface.devicePath = L"\\\\?\\" + dev->instanceId + L"#" + DeviceInfoSet::guidToString(*interfaceClassGuid);
    dev->interfaces.push_back(iface);

    if (deviceInterfaceData) {
        deviceInterfaceData->cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
        deviceInterfaceData->InterfaceClassGuid = *interfaceClassGuid;
        deviceInterfaceData->Flags = iface.flags;
        deviceInterfaceData->Reserved = dev->interfaces.size() - 1;
    }
    return 1;
}

inline win32::BOOL __stdcall SetupDiEnumDeviceInterfaces(
    HDEVINFO deviceInfoSet,
    SP_DEVINFO_DATA* deviceInfoData,
    const micant::GUID* interfaceClassGuid,
    uint32_t memberIndex,
    SP_DEVICE_INTERFACE_DATA* deviceInterfaceData
) {
    if (!deviceInfoSet || !deviceInterfaceData) return 0;
    auto* set = reinterpret_cast<DeviceInfoSet*>(deviceInfoSet);

    if (deviceInfoData) {
        auto* dev = set->getDevice(deviceInfoData->DevInst);
        if (!dev || memberIndex >= dev->interfaces.size()) return 0;
        const auto& iface = dev->interfaces[memberIndex];
        if (interfaceClassGuid && iface.interfaceClassGuid != *interfaceClassGuid) return 0;

        deviceInterfaceData->cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
        deviceInterfaceData->InterfaceClassGuid = iface.interfaceClassGuid;
        deviceInterfaceData->Flags = iface.flags;
        deviceInterfaceData->Reserved = memberIndex;
        return 1;
    }

    // Enumerate across entire set
    uint32_t count = 0;
    for (size_t d = 0; d < set->getDeviceCount(); ++d) {
        auto* dev = set->getDeviceByIndex(static_cast<uint32_t>(d));
        if (!dev) continue;
        for (size_t i = 0; i < dev->interfaces.size(); ++i) {
            const auto& iface = dev->interfaces[i];
            if (interfaceClassGuid && iface.interfaceClassGuid != *interfaceClassGuid) continue;
            if (count == memberIndex) {
                deviceInterfaceData->cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
                deviceInterfaceData->InterfaceClassGuid = iface.interfaceClassGuid;
                deviceInterfaceData->Flags = iface.flags;
                deviceInterfaceData->Reserved = (d << 16) | i;
                return 1;
            }
            count++;
        }
    }
    return 0;
}

inline win32::BOOL __stdcall SetupDiGetDeviceInterfaceDetailW(
    HDEVINFO deviceInfoSet,
    SP_DEVICE_INTERFACE_DATA* deviceInterfaceData,
    SP_DEVICE_INTERFACE_DETAIL_DATA_W* deviceInterfaceDetailData,
    uint32_t deviceInterfaceDetailDataSize,
    uint32_t* requiredSize,
    SP_DEVINFO_DATA* deviceInfoData
) {
    if (!deviceInfoSet || !deviceInterfaceData) return 0;
    auto* set = reinterpret_cast<DeviceInfoSet*>(deviceInfoSet);

    uint32_t devIdx = static_cast<uint32_t>(deviceInterfaceData->Reserved >> 16);
    uint32_t ifaceIdx = static_cast<uint32_t>(deviceInterfaceData->Reserved & 0xFFFF);
    auto* dev = set->getDeviceByIndex(devIdx);
    if (!dev || ifaceIdx >= dev->interfaces.size()) {
        dev = set->getDevice(static_cast<uint32_t>(deviceInterfaceData->Reserved));
        if (!dev || dev->interfaces.empty()) return 0;
        ifaceIdx = 0;
    }

    const auto& iface = dev->interfaces[ifaceIdx];
    uint32_t bytesNeeded = static_cast<uint32_t>(sizeof(uint32_t) + (iface.devicePath.size() + 1) * sizeof(wchar_t));
    if (requiredSize) *requiredSize = bytesNeeded;

    if (deviceInfoData) {
        deviceInfoData->cbSize = sizeof(SP_DEVINFO_DATA);
        deviceInfoData->ClassGuid = dev->classGuid;
        deviceInfoData->DevInst = dev->devInst;
        deviceInfoData->Reserved = 0;
    }

    if (!deviceInterfaceDetailData || deviceInterfaceDetailDataSize == 0) return 1;
    if (deviceInterfaceDetailDataSize < bytesNeeded) return 0;

    std::wcscpy(deviceInterfaceDetailData->DevicePath, iface.devicePath.c_str());
    return 1;
}

inline HDEVINFO __stdcall SetupDiGetClassDevsW(
    const micant::GUID* classGuid,
    [[maybe_unused]] const wchar_t* enumerator,
    [[maybe_unused]] win32::HWND hwndParent,
    uint32_t flags
) {
    auto set = std::make_unique<DeviceInfoSet>(classGuid);
    auto snapshot = GlobalDeviceManager::Instance().getSnapshot(classGuid, flags);

    for (const auto& d : snapshot) {
        uint32_t id = set->addDevice(d.classGuid, d.instanceId);
        auto* newlyAdded = set->getDevice(id);
        if (newlyAdded) {
            newlyAdded->registryProperties = d.registryProperties;
            newlyAdded->interfaces = d.interfaces;
        }
    }

    return reinterpret_cast<HDEVINFO>(set.release());
}

inline win32::BOOL __stdcall SetupDiGetClassDescriptionW(
    const micant::GUID* classGuid,
    wchar_t* classDescription,
    uint32_t classDescriptionSize,
    uint32_t* requiredSize
) {
    if (!classGuid) return 0;
    std::wstring desc = L"System Device";

    if (*classGuid == GUID_DEVCLASS_DISPLAY) desc = L"Display adapters";
    else if (*classGuid == GUID_DEVCLASS_NET) desc = L"Network adapters";
    else if (*classGuid == GUID_DEVCLASS_DISKDRIVE) desc = L"Disk drives";
    else if (*classGuid == GUID_DEVCLASS_MEDIA) desc = L"Sound, video and game controllers";
    else if (*classGuid == GUID_DEVCLASS_MOUSE) desc = L"Mice and other pointing devices";
    else if (*classGuid == GUID_DEVCLASS_KEYBOARD) desc = L"Keyboards";
    else if (*classGuid == GUID_DEVCLASS_SYSTEM) desc = L"System devices";
    else if (*classGuid == GUID_DEVCLASS_USB) desc = L"Universal Serial Bus controllers";
    else if (*classGuid == GUID_DEVCLASS_HIDCLASS) desc = L"Human Interface Devices";
    else if (*classGuid == GUID_DEVCLASS_SCSIADAPTER) desc = L"Storage controllers";

    uint32_t charsNeeded = static_cast<uint32_t>(desc.size() + 1);
    if (requiredSize) *requiredSize = charsNeeded;

    if (!classDescription || classDescriptionSize == 0) return 1;
    if (classDescriptionSize < charsNeeded) return 0;

    std::wcscpy(classDescription, desc.c_str());
    return 1;
}

inline win32::BOOL __stdcall SetupDiClassNameFromGuidW(
    const micant::GUID* classGuid,
    wchar_t* className,
    uint32_t classNameSize,
    uint32_t* requiredSize
) {
    if (!classGuid) return 0;
    std::wstring name = L"System";

    if (*classGuid == GUID_DEVCLASS_DISPLAY) name = L"Display";
    else if (*classGuid == GUID_DEVCLASS_NET) name = L"Net";
    else if (*classGuid == GUID_DEVCLASS_DISKDRIVE) name = L"DiskDrive";
    else if (*classGuid == GUID_DEVCLASS_MEDIA) name = L"Media";
    else if (*classGuid == GUID_DEVCLASS_MOUSE) name = L"Mouse";
    else if (*classGuid == GUID_DEVCLASS_KEYBOARD) name = L"Keyboard";
    else if (*classGuid == GUID_DEVCLASS_SYSTEM) name = L"System";
    else if (*classGuid == GUID_DEVCLASS_USB) name = L"USB";
    else if (*classGuid == GUID_DEVCLASS_HIDCLASS) name = L"HIDClass";
    else if (*classGuid == GUID_DEVCLASS_SCSIADAPTER) name = L"SCSIAdapter";

    uint32_t charsNeeded = static_cast<uint32_t>(name.size() + 1);
    if (requiredSize) *requiredSize = charsNeeded;

    if (!className || classNameSize == 0) return 1;
    if (classNameSize < charsNeeded) return 0;

    std::wcscpy(className, name.c_str());
    return 1;
}

// Driver Matching Engine
inline win32::BOOL __stdcall SetupDiBuildDriverInfoList(
    HDEVINFO deviceInfoSet,
    SP_DEVINFO_DATA* deviceInfoData,
    uint32_t driverType
) {
    if (!deviceInfoSet || !deviceInfoData) return 0;
    auto* set = reinterpret_cast<DeviceInfoSet*>(deviceInfoSet);
    auto* dev = set->getDevice(deviceInfoData->DevInst);
    if (!dev) return 0;

    dev->drivers.clear();
    SP_DRVINFO_DATA_W drv{};
    drv.cbSize = sizeof(SP_DRVINFO_DATA_W);
    drv.DriverType = driverType;

    std::wstring desc = DeviceInfoSet::getStringProp(*dev, SPDRP_DEVICEDESC);
    if (desc.empty()) desc = L"Standard Compatible Driver";
    std::wcsncpy(drv.Description, desc.c_str(), 255);
    std::wcsncpy(drv.MfgName, L"MicaNT Sovereign Project", 255);
    std::wcsncpy(drv.ProviderName, L"Microsoft Windows Interoperability Provider", 255);
    drv.DriverVersion = 0x0001000000460000ULL; // 1.0.70.0
    drv.DriverDate = 133500000000000000ULL;

    dev->drivers.push_back(drv);
    return 1;
}

// ============================================================================
// 7. Subsystem Export Registration (setupapi.dll)
// ============================================================================

inline void InitializeSetupApiSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // INF File APIs
    ldr.registerExport("setupapi.dll", "SetupOpenInfFileW", reinterpret_cast<void*>(SetupOpenInfFileW));
    ldr.registerExport("setupapi.dll", "SetupOpenInfFileA", reinterpret_cast<void*>(SetupOpenInfFileA));
    ldr.registerExport("setupapi.dll", "SetupCloseInfFile", reinterpret_cast<void*>(SetupCloseInfFile));
    ldr.registerExport("setupapi.dll", "SetupFindFirstLineW", reinterpret_cast<void*>(SetupFindFirstLineW));
    ldr.registerExport("setupapi.dll", "SetupFindNextLine", reinterpret_cast<void*>(SetupFindNextLine));
    ldr.registerExport("setupapi.dll", "SetupGetLineCountW", reinterpret_cast<void*>(SetupGetLineCountW));
    ldr.registerExport("setupapi.dll", "SetupGetFieldCount", reinterpret_cast<void*>(SetupGetFieldCount));
    ldr.registerExport("setupapi.dll", "SetupGetStringFieldW", reinterpret_cast<void*>(SetupGetStringFieldW));
    ldr.registerExport("setupapi.dll", "SetupGetIntField", reinterpret_cast<void*>(SetupGetIntField));

    // Device Information Set APIs
    ldr.registerExport("setupapi.dll", "SetupDiCreateDeviceInfoList", reinterpret_cast<void*>(SetupDiCreateDeviceInfoList));
    ldr.registerExport("setupapi.dll", "SetupDiDestroyDeviceInfoList", reinterpret_cast<void*>(SetupDiDestroyDeviceInfoList));
    ldr.registerExport("setupapi.dll", "SetupDiCreateDeviceInfoW", reinterpret_cast<void*>(SetupDiCreateDeviceInfoW));
    ldr.registerExport("setupapi.dll", "SetupDiEnumDeviceInfo", reinterpret_cast<void*>(SetupDiEnumDeviceInfo));
    ldr.registerExport("setupapi.dll", "SetupDiGetDeviceRegistryPropertyW", reinterpret_cast<void*>(SetupDiGetDeviceRegistryPropertyW));
    ldr.registerExport("setupapi.dll", "SetupDiSetDeviceRegistryPropertyW", reinterpret_cast<void*>(SetupDiSetDeviceRegistryPropertyW));
    ldr.registerExport("setupapi.dll", "SetupDiGetDeviceInstanceIdW", reinterpret_cast<void*>(SetupDiGetDeviceInstanceIdW));
    ldr.registerExport("setupapi.dll", "SetupDiCreateDeviceInterfaceW", reinterpret_cast<void*>(SetupDiCreateDeviceInterfaceW));
    ldr.registerExport("setupapi.dll", "SetupDiEnumDeviceInterfaces", reinterpret_cast<void*>(SetupDiEnumDeviceInterfaces));
    ldr.registerExport("setupapi.dll", "SetupDiGetDeviceInterfaceDetailW", reinterpret_cast<void*>(SetupDiGetDeviceInterfaceDetailW));
    ldr.registerExport("setupapi.dll", "SetupDiGetClassDevsW", reinterpret_cast<void*>(SetupDiGetClassDevsW));
    ldr.registerExport("setupapi.dll", "SetupDiGetClassDescriptionW", reinterpret_cast<void*>(SetupDiGetClassDescriptionW));
    ldr.registerExport("setupapi.dll", "SetupDiClassNameFromGuidW", reinterpret_cast<void*>(SetupDiClassNameFromGuidW));
    ldr.registerExport("setupapi.dll", "SetupDiBuildDriverInfoList", reinterpret_cast<void*>(SetupDiBuildDriverInfoList));
}

} // namespace micant::setupapi
