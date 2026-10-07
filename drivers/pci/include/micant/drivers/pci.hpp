// ============================================================================
// MicaNT: Sovereign PCI Express (PCIe 5.0/6.0) Bus, Root Complex & AER Subsystem
// File: include/micant/pci.hpp
// Sovereign System Domain: TitanPCI / NexusPCI
//
// Description:
//   Clean-room implementation of the PCI Local Bus Specification 3.0, PCI Express
//   Base Specification Revision 5.0/6.0, Root Complex topology, Type 0/1
//   configuration space headers, Base Address Register (BAR) dynamic sizing,
//   standard capabilities (Power Management, MSI, MSI-X, PCIe Capabilities),
//   extended capabilities (Advanced Error Reporting - AER, SR-IOV, Access Control
//   Services - ACS), interrupt routing, and Windows NT PCI Bus Driver (pci.sys)
//   kernel architecture.
//
// Clean-Room Engineering Reference & Standards:
//   - PCI-SIG: PCI Local Bus Specification Revision 3.0
//   - PCI-SIG: PCI Express Base Specification Revision 5.0 Version 1.0 & Rev 6.0
//   - PCI-SIG: PCI-to-PCI Bridge Architecture Specification Revision 1.2
//   - Microsoft Open win32metadata repository: Windows.Win32.Devices.Pci
//   - ISO/IEC 14882:2023 C++ Standard
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <array>
#include <unordered_map>
#include <map>
#include <queue>
#include <mutex>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "janusldr.hpp"
#include "scm.hpp"
#include "version.hpp"
#include "vanguarddriver.hpp"

#ifndef WINAPI
#define WINAPI __stdcall
#endif

namespace micant::pci {

using BOOL = int32_t;

#ifndef TRUE
inline constexpr BOOL TRUE = 1;
#endif

#ifndef FALSE
inline constexpr BOOL FALSE = 0;
#endif

// ============================================================================
// 1. PCI Addresses, Register Offsets, Bitmasks & Class Codes
// ============================================================================

struct PciAddress {
    uint8_t bus{0};
    uint8_t device{0};
    uint8_t function{0};

    constexpr PciAddress() = default;
    constexpr PciAddress(uint8_t b, uint8_t d, uint8_t f)
        : bus(b), device(d & 0x1F), function(f & 0x07) {}

    constexpr uint32_t toBdf() const {
        return (static_cast<uint32_t>(bus) << 8) |
               (static_cast<uint32_t>(device & 0x1F) << 3) |
               (static_cast<uint32_t>(function & 0x07));
    }

    static constexpr PciAddress fromBdf(uint32_t bdf) {
        return PciAddress(
            static_cast<uint8_t>((bdf >> 8) & 0xFF),
            static_cast<uint8_t>((bdf >> 3) & 0x1F),
            static_cast<uint8_t>(bdf & 0x07)
        );
    }

    std::string toString() const {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0')
           << std::setw(2) << static_cast<int>(bus) << ":"
           << std::setw(2) << static_cast<int>(device) << "."
           << static_cast<int>(function);
        return ss.str();
    }

    auto operator<=>(const PciAddress&) const = default;
};

// Standard Configuration Header Register Offsets
inline constexpr uint16_t PCI_CONFIG_VENDOR_ID         = 0x00;
inline constexpr uint16_t PCI_CONFIG_DEVICE_ID         = 0x02;
inline constexpr uint16_t PCI_CONFIG_COMMAND           = 0x04;
inline constexpr uint16_t PCI_CONFIG_STATUS            = 0x06;
inline constexpr uint16_t PCI_CONFIG_REVISION_ID       = 0x08;
inline constexpr uint16_t PCI_CONFIG_PROG_IF           = 0x09;
inline constexpr uint16_t PCI_CONFIG_SUBCLASS          = 0x0A;
inline constexpr uint16_t PCI_CONFIG_BASECLASS         = 0x0B;
inline constexpr uint16_t PCI_CONFIG_CACHE_LINE_SIZE   = 0x0C;
inline constexpr uint16_t PCI_CONFIG_LATENCY_TIMER     = 0x0D;
inline constexpr uint16_t PCI_CONFIG_HEADER_TYPE       = 0x0E;
inline constexpr uint16_t PCI_CONFIG_BIST              = 0x0F;

// Type 0 (Endpoint) Offsets
inline constexpr uint16_t PCI_CONFIG_BAR0              = 0x10;
inline constexpr uint16_t PCI_CONFIG_BAR1              = 0x14;
inline constexpr uint16_t PCI_CONFIG_BAR2              = 0x18;
inline constexpr uint16_t PCI_CONFIG_BAR3              = 0x1C;
inline constexpr uint16_t PCI_CONFIG_BAR4              = 0x20;
inline constexpr uint16_t PCI_CONFIG_BAR5              = 0x24;
inline constexpr uint16_t PCI_CONFIG_CARDBUS_CIS       = 0x28;
inline constexpr uint16_t PCI_CONFIG_SUBSYS_VENDOR_ID  = 0x2C;
inline constexpr uint16_t PCI_CONFIG_SUBSYS_ID         = 0x2E;
inline constexpr uint16_t PCI_CONFIG_EXPANSION_ROM     = 0x30;
inline constexpr uint16_t PCI_CONFIG_CAPABILITIES_PTR  = 0x34;
inline constexpr uint16_t PCI_CONFIG_INTERRUPT_LINE    = 0x3C;
inline constexpr uint16_t PCI_CONFIG_INTERRUPT_PIN     = 0x3D;
inline constexpr uint16_t PCI_CONFIG_MIN_GNT           = 0x3E;
inline constexpr uint16_t PCI_CONFIG_MAX_LAT           = 0x3F;

// Type 1 (PCI-to-PCI Bridge) Offsets
inline constexpr uint16_t PCI_CONFIG_PRIMARY_BUS       = 0x18;
inline constexpr uint16_t PCI_CONFIG_SECONDARY_BUS     = 0x19;
inline constexpr uint16_t PCI_CONFIG_SUBORDINATE_BUS   = 0x1A;
inline constexpr uint16_t PCI_CONFIG_SEC_LATENCY_TIMER = 0x1B;
inline constexpr uint16_t PCI_CONFIG_IO_BASE           = 0x1C;
inline constexpr uint16_t PCI_CONFIG_IO_LIMIT          = 0x1D;
inline constexpr uint16_t PCI_CONFIG_SEC_STATUS        = 0x1E;
inline constexpr uint16_t PCI_CONFIG_MEM_BASE          = 0x20;
inline constexpr uint16_t PCI_CONFIG_MEM_LIMIT         = 0x22;
inline constexpr uint16_t PCI_CONFIG_PREFETCH_MEM_BASE = 0x24;
inline constexpr uint16_t PCI_CONFIG_PREFETCH_MEM_LIMIT= 0x26;
inline constexpr uint16_t PCI_CONFIG_BRIDGE_CONTROL    = 0x3E;

// Header Types
inline constexpr uint8_t PCI_HEADER_TYPE_NORMAL        = 0x00;
inline constexpr uint8_t PCI_HEADER_TYPE_BRIDGE        = 0x01;
inline constexpr uint8_t PCI_HEADER_TYPE_CARDBUS       = 0x02;
inline constexpr uint8_t PCI_HEADER_TYPE_MULTI_FUNC    = 0x80;

// Command Register Bitmasks
inline constexpr uint16_t PCI_COMMAND_IO_ENABLE        = 0x0001;
inline constexpr uint16_t PCI_COMMAND_MEM_ENABLE       = 0x0002;
inline constexpr uint16_t PCI_COMMAND_BUS_MASTER       = 0x0004;
inline constexpr uint16_t PCI_COMMAND_SPECIAL_CYCLES   = 0x0008;
inline constexpr uint16_t PCI_COMMAND_MWI_ENABLE       = 0x0010;
inline constexpr uint16_t PCI_COMMAND_VGA_PALETTE_SNOOP= 0x0020;
inline constexpr uint16_t PCI_COMMAND_PARITY_ERROR_RESP= 0x0040;
inline constexpr uint16_t PCI_COMMAND_STEPPING_CONTROL = 0x0080;
inline constexpr uint16_t PCI_COMMAND_SERR_ENABLE      = 0x0100;
inline constexpr uint16_t PCI_COMMAND_FAST_BACK_TO_BACK= 0x0200;
inline constexpr uint16_t PCI_COMMAND_INTX_DISABLE     = 0x0400;

// Status Register Bitmasks
inline constexpr uint16_t PCI_STATUS_IMM_READ          = 0x0001;
inline constexpr uint16_t PCI_STATUS_INTX_STATE        = 0x0008;
inline constexpr uint16_t PCI_STATUS_CAPABILITIES_LIST = 0x0010;
inline constexpr uint16_t PCI_STATUS_66MHZ_CAPABLE     = 0x0020;
inline constexpr uint16_t PCI_STATUS_UDF_SUPPORTED     = 0x0040;
inline constexpr uint16_t PCI_STATUS_FAST_BACK_TO_BACK = 0x0080;
inline constexpr uint16_t PCI_STATUS_MASTER_DATA_PARITY= 0x0100;
inline constexpr uint16_t PCI_STATUS_DEVSEL_TIMING     = 0x0600;
inline constexpr uint16_t PCI_STATUS_SIGNALED_TARGET_AB= 0x0800;
inline constexpr uint16_t PCI_STATUS_RECEIVED_TARGET_AB= 0x1000;
inline constexpr uint16_t PCI_STATUS_RECEIVED_MASTER_AB= 0x2000;
inline constexpr uint16_t PCI_STATUS_SIGNALED_SYS_ERR  = 0x4000;
inline constexpr uint16_t PCI_STATUS_DETECTED_PARITY   = 0x8000;

// Standard PCI Capability IDs (Offset < 0x100)
inline constexpr uint8_t PCI_CAP_ID_PM                 = 0x01;
inline constexpr uint8_t PCI_CAP_ID_AGP                = 0x02;
inline constexpr uint8_t PCI_CAP_ID_VPD                = 0x03;
inline constexpr uint8_t PCI_CAP_ID_SLOT_ID            = 0x04;
inline constexpr uint8_t PCI_CAP_ID_MSI                = 0x05;
inline constexpr uint8_t PCI_CAP_ID_CHSWP              = 0x06;
inline constexpr uint8_t PCI_CAP_ID_PCIX               = 0x07;
inline constexpr uint8_t PCI_CAP_ID_HT                 = 0x08;
inline constexpr uint8_t PCI_CAP_ID_VENDOR             = 0x09;
inline constexpr uint8_t PCI_CAP_ID_DEBUG_PORT         = 0x0A;
inline constexpr uint8_t PCI_CAP_ID_HOTPLUG            = 0x0C;
inline constexpr uint8_t PCI_CAP_ID_SUBSYS_VENDOR      = 0x0D;
inline constexpr uint8_t PCI_CAP_ID_EXP                = 0x10; // PCI Express
inline constexpr uint8_t PCI_CAP_ID_MSIX               = 0x11; // MSI-X
inline constexpr uint8_t PCI_CAP_ID_SATA               = 0x12;
inline constexpr uint8_t PCI_CAP_ID_ADVANCED_FEATURES  = 0x13;

// PCIe Extended Capability IDs (Offset >= 0x100)
inline constexpr uint16_t PCIE_EXT_CAP_ID_AER          = 0x0001; // Advanced Error Reporting
inline constexpr uint16_t PCIE_EXT_CAP_ID_VC           = 0x0002; // Virtual Channel
inline constexpr uint16_t PCIE_EXT_CAP_ID_DSN          = 0x0003; // Device Serial Number
inline constexpr uint16_t PCIE_EXT_CAP_ID_PWR_BUDGET   = 0x0004; // Power Budgeting
inline constexpr uint16_t PCIE_EXT_CAP_ID_ACS          = 0x000D; // Access Control Services
inline constexpr uint16_t PCIE_EXT_CAP_ID_ARI          = 0x000E; // Alt Routing-ID Interpretation
inline constexpr uint16_t PCIE_EXT_CAP_ID_SRIOV        = 0x0010; // Single Root I/O Virtualization
inline constexpr uint16_t PCIE_EXT_CAP_ID_LTR          = 0x0018; // Latency Tolerance Reporting
inline constexpr uint16_t PCIE_EXT_CAP_ID_SEC_PCIE     = 0x0019; // Secondary PCIe
inline constexpr uint16_t PCIE_EXT_CAP_ID_DPC          = 0x001D; // Downstream Port Containment
inline constexpr uint16_t PCIE_EXT_CAP_ID_L1PM         = 0x001E; // L1 PM Substates
inline constexpr uint16_t PCIE_EXT_CAP_ID_DOE          = 0x002E; // Data Object Exchange

// PCIe Link Speeds
enum class PciLinkSpeed : uint8_t {
    Unknown = 0,
    Gen1_2_5GT = 1, // 2.5 GT/s
    Gen2_5_0GT = 2, // 5.0 GT/s
    Gen3_8_0GT = 3, // 8.0 GT/s
    Gen4_16_0GT= 4, // 16.0 GT/s
    Gen5_32_0GT= 5, // 32.0 GT/s
    Gen6_64_0GT= 6  // 64.0 GT/s (PAM4)
};

// PCIe Link Widths
enum class PciLinkWidth : uint8_t {
    x1  = 1,
    x2  = 2,
    x4  = 4,
    x8  = 8,
    x12 = 12,
    x16 = 16,
    x32 = 32
};

// PCI Class Codes
enum class PciBaseClass : uint8_t {
    Legacy              = 0x00,
    MassStorage         = 0x01,
    Network             = 0x02,
    Display             = 0x03,
    Multimedia          = 0x04,
    Memory              = 0x05,
    Bridge              = 0x06,
    Communication       = 0x07,
    GenericSystem       = 0x08,
    Input               = 0x09,
    Docking             = 0x0A,
    Processor           = 0x0B,
    SerialBus           = 0x0C,
    Wireless            = 0x0D,
    IntelligentIo       = 0x0E,
    Satellite           = 0x0F,
    Cryptographic       = 0x10,
    SignalProcessing    = 0x11,
    Accelerator         = 0x12
};

inline std::string PciBaseClassToString(PciBaseClass cls) {
    switch (cls) {
        case PciBaseClass::Legacy: return "Legacy Device";
        case PciBaseClass::MassStorage: return "Mass Storage Controller";
        case PciBaseClass::Network: return "Network Controller";
        case PciBaseClass::Display: return "Display / 3D Controller";
        case PciBaseClass::Multimedia: return "Multimedia Device";
        case PciBaseClass::Memory: return "Memory Controller";
        case PciBaseClass::Bridge: return "PCI Bridge Device";
        case PciBaseClass::Communication: return "Communication Controller";
        case PciBaseClass::GenericSystem: return "Generic System Peripheral";
        case PciBaseClass::Input: return "Input Device";
        case PciBaseClass::Docking: return "Docking Station";
        case PciBaseClass::Processor: return "Processor / Coprocessor";
        case PciBaseClass::SerialBus: return "Serial Bus Controller";
        case PciBaseClass::Wireless: return "Wireless Controller";
        case PciBaseClass::IntelligentIo: return "Intelligent I/O (I2O)";
        case PciBaseClass::Satellite: return "Satellite Communication";
        case PciBaseClass::Cryptographic: return "Cryptographic Controller";
        case PciBaseClass::SignalProcessing: return "Signal Processing Controller";
        case PciBaseClass::Accelerator: return "Processing Accelerator";
        default: return "Unknown Class";
    }
}

// ============================================================================
// 2. Base Address Register (BAR) Modeling
// ============================================================================

enum class PciBarType : uint8_t {
    None     = 0,
    Memory32 = 1,
    Memory64 = 2,
    IoSpace  = 3
};

struct PciBar {
    uint8_t index{0};
    PciBarType type{PciBarType::None};
    bool prefetchable{false};
    uint64_t baseAddress{0};
    uint64_t size{0};
    bool is64BitUpperHalf{false};
    std::vector<uint8_t> mmioStorage;

    constexpr bool isMemory() const {
        return type == PciBarType::Memory32 || type == PciBarType::Memory64;
    }

    constexpr bool isIo() const {
        return type == PciBarType::IoSpace;
    }

    uint32_t toRawLow() const {
        if (type == PciBarType::IoSpace) {
            return static_cast<uint32_t>(baseAddress & 0xFFFFFFFC) | 0x01;
        }
        uint32_t val = static_cast<uint32_t>(baseAddress & 0xFFFFFFF0);
        if (type == PciBarType::Memory64) val |= (0x02 << 1);
        if (prefetchable) val |= (0x01 << 3);
        return val;
    }

    uint32_t toRawHigh() const {
        return static_cast<uint32_t>((baseAddress >> 32) & 0xFFFFFFFF);
    }
};

// ============================================================================
// 3. Message Signaled Interrupts (MSI & MSI-X) Model
// ============================================================================

struct MsiCapability {
    uint8_t offset{0};
    bool enabled{false};
    bool is64Bit{false};
    bool perVectorMasking{false};
    uint8_t multiMessageCapable{0}; // 0=1, 1=2, 2=4, 3=8, 4=16, 5=32
    uint8_t multiMessageEnable{0};
    uint64_t messageAddress{0};
    uint16_t messageData{0};
    uint32_t maskBits{0};
    uint32_t pendingBits{0};
};

struct MsixTableEntry {
    uint32_t msgAddrLow{0};
    uint32_t msgAddrHigh{0};
    uint32_t msgData{0};
    uint32_t vectorControl{1}; // Bit 0 = Mask

    constexpr bool isMasked() const { return (vectorControl & 0x01) != 0; }
    void setMasked(bool m) {
        if (m) vectorControl |= 0x01;
        else vectorControl &= ~0x01u;
    }

    uint64_t getAddress() const {
        return (static_cast<uint64_t>(msgAddrHigh) << 32) | msgAddrLow;
    }
};

struct MsixCapability {
    uint8_t offset{0};
    bool enabled{false};
    bool functionMask{false};
    uint16_t tableSize{0}; // 1..2048 entries
    uint8_t tableBir{0};   // BAR indicator (0..5)
    uint32_t tableOffset{0};
    uint8_t pbaBir{0};
    uint32_t pbaOffset{0};

    std::vector<MsixTableEntry> table;
    std::vector<uint64_t> pbaBits; // 64 bits per element
};

// ============================================================================
// 4. Advanced Error Reporting (AER) Model
// ============================================================================

namespace aer {

// Uncorrectable Error Status & Mask Bits
inline constexpr uint32_t AER_UNCORR_TRAINING_ERROR        = 0x00000001;
inline constexpr uint32_t AER_UNCORR_DLP_ERROR             = 0x00000010;
inline constexpr uint32_t AER_UNCORR_SURPRISE_DOWN         = 0x00000020;
inline constexpr uint32_t AER_UNCORR_POISONED_TLP          = 0x00001000;
inline constexpr uint32_t AER_UNCORR_FLOW_CONTROL_PROT     = 0x00002000;
inline constexpr uint32_t AER_UNCORR_COMPLETION_TIMEOUT    = 0x00004000;
inline constexpr uint32_t AER_UNCORR_COMPLETER_ABORT       = 0x00008000;
inline constexpr uint32_t AER_UNCORR_UNEXPECTED_COMPLETION = 0x00010000;
inline constexpr uint32_t AER_UNCORR_RECEIVER_OVERFLOW     = 0x00020000;
inline constexpr uint32_t AER_UNCORR_MALFORMED_TLP         = 0x00040000;
inline constexpr uint32_t AER_UNCORR_ECRC_ERROR            = 0x00080000;
inline constexpr uint32_t AER_UNCORR_UNSUPPORTED_REQUEST   = 0x00100000;
inline constexpr uint32_t AER_UNCORR_ACS_VIOLATION         = 0x00200000;
inline constexpr uint32_t AER_UNCORR_MC_BLOCKED_TLP        = 0x00400000;

// Correctable Error Status & Mask Bits
inline constexpr uint32_t AER_CORR_RECEIVER_ERROR          = 0x00000001;
inline constexpr uint32_t AER_CORR_BAD_TLP                 = 0x00000040;
inline constexpr uint32_t AER_CORR_BAD_DLLP                = 0x00000080;
inline constexpr uint32_t AER_CORR_REPLAY_NUM_ROLLOVER     = 0x00000100;
inline constexpr uint32_t AER_CORR_REPLAY_TIMER_TIMEOUT    = 0x00000400;
inline constexpr uint32_t AER_CORR_ADVISORY_NON_FATAL      = 0x00002000;
inline constexpr uint32_t AER_CORR_CORRECTED_INTERNAL_ERR  = 0x00004000;
inline constexpr uint32_t AER_CORR_HDR_LOG_OVERFLOW        = 0x00008000;

} // namespace aer

struct AerCapability {
    uint16_t offset{0};
    uint32_t uncorrStatus{0};
    uint32_t uncorrMask{0};
    uint32_t uncorrSeverity{0}; // 1 = Fatal, 0 = Non-Fatal
    uint32_t corrStatus{0};
    uint32_t corrMask{0};
    uint32_t advancedCapControl{0};
    std::array<uint32_t, 4> headerLog{}; // 16-byte TLP header log
    uint32_t rootErrorCommand{0};
    uint32_t rootErrorStatus{0};
    uint16_t errorSourceRequesterId{0};

    uint64_t totalCorrectableErrors{0};
    uint64_t totalNonFatalErrors{0};
    uint64_t totalFatalErrors{0};
};

// ============================================================================
// 5. Single Root I/O Virtualization (SR-IOV) Model
// ============================================================================

struct SriovCapability {
    uint16_t offset{0};
    uint16_t sriovControl{0}; // Bit 0 = VF Enable
    uint16_t sriovStatus{0};
    uint16_t initialVfs{0};
    uint16_t totalVfs{0};
    uint16_t numVfs{0};
    uint16_t vfOffset{0};
    uint16_t vfStride{0};
    uint16_t vfDeviceId{0};
    uint32_t supportedPageSizes{0};
    uint32_t systemPageSize{0x1000};
    std::array<PciBar, 6> vfBars{};
};

// ============================================================================
// 6. Base PCI Express Device Representation
// ============================================================================

class PciDevice {
protected:
    PciAddress m_address{};
    std::array<uint8_t, 4096> m_configSpace{};
    std::array<PciBar, 6> m_bars{};
    std::string m_deviceName{"Generic PCIe Device"};
    std::string m_hardwareId;
    std::string m_compatibleId;

    // Capabilities
    MsiCapability m_msi{};
    MsixCapability m_msix{};
    AerCapability m_aer{};
    SriovCapability m_sriov{};

    bool m_hasPcieCap{false};
    uint8_t m_pcieCapOffset{0};
    PciLinkSpeed m_maxSpeed{PciLinkSpeed::Gen4_16_0GT};
    PciLinkSpeed m_currentSpeed{PciLinkSpeed::Gen4_16_0GT};
    PciLinkWidth m_maxWidth{PciLinkWidth::x4};
    PciLinkWidth m_currentWidth{PciLinkWidth::x4};

    mutable std::mutex m_mutex;

public:
    PciDevice(PciAddress addr, uint16_t vendorId, uint16_t deviceId,
              PciBaseClass baseClass, uint8_t subClass, uint8_t progIf,
              uint8_t headerType = PCI_HEADER_TYPE_NORMAL)
        : m_address(addr)
    {
        m_configSpace.fill(0);
        writeConfigWord(PCI_CONFIG_VENDOR_ID, vendorId);
        writeConfigWord(PCI_CONFIG_DEVICE_ID, deviceId);
        writeConfigByte(PCI_CONFIG_REVISION_ID, 0x01);
        writeConfigByte(PCI_CONFIG_PROG_IF, progIf);
        writeConfigByte(PCI_CONFIG_SUBCLASS, subClass);
        writeConfigByte(PCI_CONFIG_BASECLASS, static_cast<uint8_t>(baseClass));
        writeConfigByte(PCI_CONFIG_HEADER_TYPE, headerType);

        // Default capabilities bit in status
        uint16_t status = readConfigWord(PCI_CONFIG_STATUS);
        status |= PCI_STATUS_CAPABILITIES_LIST;
        writeConfigWord(PCI_CONFIG_STATUS, status);

        // Default Command Register
        writeConfigWord(PCI_CONFIG_COMMAND, PCI_COMMAND_MEM_ENABLE | PCI_COMMAND_BUS_MASTER);

        // Setup Hardware IDs
        std::ostringstream hw;
        hw << "PCI\\VEN_" << std::hex << std::uppercase << std::setfill('0')
           << std::setw(4) << vendorId << "&DEV_" << std::setw(4) << deviceId;
        m_hardwareId = hw.str();

        std::ostringstream cid;
        cid << "PCI\\CC_" << std::hex << std::uppercase << std::setfill('0')
           << std::setw(2) << static_cast<int>(baseClass)
           << std::setw(2) << static_cast<int>(subClass);
        m_compatibleId = cid.str();
    }

    virtual ~PciDevice() = default;

    const PciAddress& getAddress() const { return m_address; }
    void setAddress(PciAddress addr) { m_address = addr; }
    const std::string& getName() const { return m_deviceName; }
    void setName(const std::string& name) { m_deviceName = name; }
    const std::string& getHardwareId() const { return m_hardwareId; }
    const std::string& getCompatibleId() const { return m_compatibleId; }

    uint16_t getVendorId() const { return readConfigWord(PCI_CONFIG_VENDOR_ID); }
    uint16_t getDeviceId() const { return readConfigWord(PCI_CONFIG_DEVICE_ID); }
    uint8_t getBaseClass() const { return readConfigByte(PCI_CONFIG_BASECLASS); }
    uint8_t getSubClass() const { return readConfigByte(PCI_CONFIG_SUBCLASS); }
    uint8_t getProgIf() const { return readConfigByte(PCI_CONFIG_PROG_IF); }
    uint8_t getHeaderType() const { return readConfigByte(PCI_CONFIG_HEADER_TYPE); }

    bool isBridge() const {
        return (getHeaderType() & 0x7F) == PCI_HEADER_TYPE_BRIDGE;
    }

    // Config Space Read / Write
    uint8_t readConfigByte(uint16_t offset) const {
        if (offset >= 4096) return 0xFF;
        return m_configSpace[offset];
    }

    uint16_t readConfigWord(uint16_t offset) const {
        if (offset > 4094) return 0xFFFF;
        return static_cast<uint16_t>(m_configSpace[offset]) |
              (static_cast<uint16_t>(m_configSpace[offset + 1]) << 8);
    }

    uint32_t readConfigDword(uint16_t offset) const {
        if (offset > 4092) return 0xFFFFFFFF;
        return static_cast<uint32_t>(m_configSpace[offset]) |
              (static_cast<uint32_t>(m_configSpace[offset + 1]) << 8) |
              (static_cast<uint32_t>(m_configSpace[offset + 2]) << 16) |
              (static_cast<uint32_t>(m_configSpace[offset + 3]) << 24);
    }

    void writeConfigByte(uint16_t offset, uint8_t val) {
        if (offset >= 4096) return;
        m_configSpace[offset] = val;
    }

    void writeConfigWord(uint16_t offset, uint16_t val) {
        if (offset > 4094) return;
        m_configSpace[offset] = static_cast<uint8_t>(val & 0xFF);
        m_configSpace[offset + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    }

    void writeConfigDword(uint16_t offset, uint32_t val) {
        if (offset > 4092) return;
        m_configSpace[offset] = static_cast<uint8_t>(val & 0xFF);
        m_configSpace[offset + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
        m_configSpace[offset + 2] = static_cast<uint8_t>((val >> 16) & 0xFF);
        m_configSpace[offset + 3] = static_cast<uint8_t>((val >> 24) & 0xFF);
    }

    // Dynamic BAR Probing and Sizing Simulation
    uint32_t readBar(uint8_t barIndex) const {
        if (barIndex >= 6) return 0;
        uint16_t off = static_cast<uint16_t>(PCI_CONFIG_BAR0 + (barIndex * 4));
        return readConfigDword(off);
    }

    void writeBar(uint8_t barIndex, uint32_t val) {
        if (barIndex >= 6) return;
        uint16_t off = static_cast<uint16_t>(PCI_CONFIG_BAR0 + (barIndex * 4));

        auto& bar = m_bars[barIndex];
        if (val == 0xFFFFFFFF) {
            // OS Sizing Probe!
            if (bar.type == PciBarType::None) {
                writeConfigDword(off, 0);
            } else if (bar.type == PciBarType::IoSpace) {
                uint32_t mask = ~(static_cast<uint32_t>(bar.size) - 1) | 0x01;
                writeConfigDword(off, mask);
            } else if (bar.type == PciBarType::Memory32 || (bar.type == PciBarType::Memory64 && !bar.is64BitUpperHalf)) {
                uint32_t mask = ~(static_cast<uint32_t>(bar.size) - 1);
                if (bar.type == PciBarType::Memory64) mask |= 0x04;
                if (bar.prefetchable) mask |= 0x08;
                writeConfigDword(off, mask);
            } else if (bar.is64BitUpperHalf) {
                uint32_t mask = ~(static_cast<uint32_t>(bar.size >> 32) - 1);
                writeConfigDword(off, mask);
            }
        } else {
            // Set Base Address
            if (bar.type == PciBarType::Memory64 && !bar.is64BitUpperHalf) {
                bar.baseAddress = (bar.baseAddress & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFF0ULL);
            } else if (bar.is64BitUpperHalf) {
                bar.baseAddress = (static_cast<uint64_t>(val) << 32) | (bar.baseAddress & 0x00000000FFFFFFFFULL);
                // Also update lower bar's full base
                if (barIndex > 0) m_bars[barIndex - 1].baseAddress = bar.baseAddress;
            } else if (bar.type == PciBarType::Memory32) {
                bar.baseAddress = val & 0xFFFFFFF0ULL;
            } else if (bar.type == PciBarType::IoSpace) {
                bar.baseAddress = val & 0xFFFFFFFCULL;
            }
            writeConfigDword(off, val);
        }
    }

    void configureBar(uint8_t barIndex, PciBarType type, uint64_t size, bool prefetchable = false) {
        if (barIndex >= 6) return;
        auto& bar = m_bars[barIndex];
        bar.index = barIndex;
        bar.type = type;
        bar.size = size;
        bar.prefetchable = prefetchable;
        bar.is64BitUpperHalf = false;
        if (size > 0 && size <= (128 * 1024 * 1024)) {
            bar.mmioStorage.resize(static_cast<size_t>(size), 0);
        }

        uint16_t off = static_cast<uint16_t>(PCI_CONFIG_BAR0 + (barIndex * 4));
        uint32_t raw = bar.toRawLow();
        writeConfigDword(off, raw);

        if (type == PciBarType::Memory64 && barIndex < 5) {
            // Allocate upper 32-bit BAR paired
            auto& upper = m_bars[barIndex + 1];
            upper.index = barIndex + 1;
            upper.type = PciBarType::Memory64;
            upper.size = size;
            upper.prefetchable = prefetchable;
            upper.is64BitUpperHalf = true;
            writeConfigDword(off + 4, bar.toRawHigh());
        }
    }

    const PciBar& getBar(uint8_t index) const {
        static PciBar s_empty{};
        if (index >= 6) return s_empty;
        return m_bars[index];
    }

    // MMIO Simulation Access
    virtual uint32_t mmioRead32(uint8_t barIndex, uint64_t offset) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (barIndex >= 6) return 0xFFFFFFFF;
        auto& bar = m_bars[barIndex];
        if (offset + 4 <= bar.mmioStorage.size()) {
            return *reinterpret_cast<const uint32_t*>(&bar.mmioStorage[offset]);
        }
        return 0;
    }

    virtual void mmioWrite32(uint8_t barIndex, uint64_t offset, uint32_t val) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (barIndex >= 6) return;
        auto& bar = m_bars[barIndex];
        if (offset + 4 <= bar.mmioStorage.size()) {
            *reinterpret_cast<uint32_t*>(&bar.mmioStorage[offset]) = val;
        }
    }

    // Capabilities Setup
    void addMsiCapability(uint8_t offset, uint8_t maxVectorsPowerOf2 = 0, bool is64Bit = true) {
        m_msi.offset = offset;
        m_msi.is64Bit = is64Bit;
        m_msi.multiMessageCapable = maxVectorsPowerOf2;
        m_msi.multiMessageEnable = 0;
        m_msi.enabled = false;

        // Link in config space
        uint8_t prevCap = readConfigByte(PCI_CONFIG_CAPABILITIES_PTR);
        writeConfigByte(PCI_CONFIG_CAPABILITIES_PTR, offset);
        writeConfigByte(offset, PCI_CAP_ID_MSI);
        writeConfigByte(offset + 1, prevCap); // Next ptr

        uint16_t msgCtrl = (maxVectorsPowerOf2 & 0x07) << 1;
        if (is64Bit) msgCtrl |= (1 << 7);
        writeConfigWord(offset + 2, msgCtrl);
    }

    void addMsixCapability(uint8_t offset, uint16_t tableSize, uint8_t barIndex, uint32_t tableOffset, uint32_t pbaOffset) {
        m_msix.offset = offset;
        m_msix.enabled = false;
        m_msix.functionMask = false;
        m_msix.tableSize = tableSize;
        m_msix.tableBir = barIndex;
        m_msix.tableOffset = tableOffset;
        m_msix.pbaBir = barIndex;
        m_msix.pbaOffset = pbaOffset;

        m_msix.table.resize(tableSize);
        size_t pbaWords = (tableSize + 63) / 64;
        m_msix.pbaBits.resize(pbaWords, 0);

        // Link in config space
        uint8_t prevCap = readConfigByte(PCI_CONFIG_CAPABILITIES_PTR);
        writeConfigByte(PCI_CONFIG_CAPABILITIES_PTR, offset);
        writeConfigByte(offset, PCI_CAP_ID_MSIX);
        writeConfigByte(offset + 1, prevCap); // Next ptr

        uint16_t msgCtrl = (tableSize - 1) & 0x07FF;
        writeConfigWord(offset + 2, msgCtrl);
        writeConfigDword(offset + 4, (tableOffset & ~0x07u) | (barIndex & 0x07));
        writeConfigDword(offset + 8, (pbaOffset & ~0x07u) | (barIndex & 0x07));
    }

    void addPcieCapability(uint8_t offset, PciLinkSpeed maxSpeed, PciLinkWidth maxWidth) {
        m_hasPcieCap = true;
        m_pcieCapOffset = offset;
        m_maxSpeed = maxSpeed;
        m_currentSpeed = maxSpeed;
        m_maxWidth = maxWidth;
        m_currentWidth = maxWidth;

        uint8_t prevCap = readConfigByte(PCI_CONFIG_CAPABILITIES_PTR);
        writeConfigByte(PCI_CONFIG_CAPABILITIES_PTR, offset);
        writeConfigByte(offset, PCI_CAP_ID_EXP);
        writeConfigByte(offset + 1, prevCap);

        // PCIe Capabilities Register (v2, endpoint)
        uint16_t pcieCaps = 0x0002;
        if (isBridge()) pcieCaps |= (0x04 << 4); // Root Port
        writeConfigWord(offset + 2, pcieCaps);

        // Link Capabilities
        uint32_t linkCaps = static_cast<uint32_t>(maxSpeed) |
                           (static_cast<uint32_t>(maxWidth) << 4);
        writeConfigDword(offset + 12, linkCaps);

        // Link Status
        uint16_t linkStatus = static_cast<uint16_t>(maxSpeed) |
                             (static_cast<uint16_t>(maxWidth) << 4);
        writeConfigWord(offset + 18, linkStatus);
    }

    void addAerCapability(uint16_t offset) {
        m_aer.offset = offset;
        m_aer.uncorrStatus = 0;
        m_aer.uncorrMask = 0;
        m_aer.uncorrSeverity = 0;
        m_aer.corrStatus = 0;
        m_aer.corrMask = 0;

        // Write extended cap header at offset >= 0x100
        writeConfigWord(offset, PCIE_EXT_CAP_ID_AER);
        writeConfigWord(offset + 2, 0x0002); // Version 2, next = 0
    }

    void addSriovCapability(uint16_t offset, uint16_t totalVfs, uint16_t vfDeviceId) {
        m_sriov.offset = offset;
        m_sriov.totalVfs = totalVfs;
        m_sriov.initialVfs = totalVfs;
        m_sriov.vfDeviceId = vfDeviceId;

        writeConfigWord(offset, PCIE_EXT_CAP_ID_SRIOV);
        writeConfigWord(offset + 2, 0x0001); // Version 1
        writeConfigWord(offset + 0x0E, totalVfs);
        writeConfigWord(offset + 0x10, totalVfs);
        writeConfigWord(offset + 0x1A, vfDeviceId);
    }

    // Accessors for Capabilities
    MsiCapability& getMsi() { return m_msi; }
    const MsiCapability& getMsi() const { return m_msi; }

    MsixCapability& getMsix() { return m_msix; }
    const MsixCapability& getMsix() const { return m_msix; }

    AerCapability& getAer() { return m_aer; }
    const AerCapability& getAer() const { return m_aer; }

    SriovCapability& getSriov() { return m_sriov; }
    const SriovCapability& getSriov() const { return m_sriov; }

    bool hasPcieCap() const { return m_hasPcieCap; }
    PciLinkSpeed getLinkSpeed() const { return m_currentSpeed; }
    PciLinkWidth getLinkWidth() const { return m_currentWidth; }

    std::string getLinkSpeedString() const {
        switch (m_currentSpeed) {
            case PciLinkSpeed::Gen1_2_5GT: return "Gen 1 (2.5 GT/s)";
            case PciLinkSpeed::Gen2_5_0GT: return "Gen 2 (5.0 GT/s)";
            case PciLinkSpeed::Gen3_8_0GT: return "Gen 3 (8.0 GT/s)";
            case PciLinkSpeed::Gen4_16_0GT: return "Gen 4 (16.0 GT/s)";
            case PciLinkSpeed::Gen5_32_0GT: return "Gen 5 (32.0 GT/s)";
            case PciLinkSpeed::Gen6_64_0GT: return "Gen 6 (64.0 GT/s PAM4)";
            default: return "Unknown Speed";
        }
    }

    std::string getLinkWidthString() const {
        return "x" + std::to_string(static_cast<int>(m_currentWidth));
    }

    // MSI-X Table Programming
    bool setMsixEntry(uint16_t index, uint64_t address, uint32_t data, bool masked = false) {
        if (index >= m_msix.table.size()) return false;
        auto& entry = m_msix.table[index];
        entry.msgAddrLow = static_cast<uint32_t>(address & 0xFFFFFFFF);
        entry.msgAddrHigh = static_cast<uint32_t>(address >> 32);
        entry.msgData = data;
        entry.setMasked(masked);
        return true;
    }

    // AER Error Triggering and Logging
    void triggerAerError(uint32_t errorBit, bool isUncorrectable, bool isFatal = false,
                         const std::array<uint32_t, 4>& header = {0, 0, 0, 0})
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_aer.offset == 0) return;

        if (isUncorrectable) {
            m_aer.uncorrStatus |= errorBit;
            if (isFatal) {
                m_aer.uncorrSeverity |= errorBit;
                m_aer.totalFatalErrors++;
            } else {
                m_aer.uncorrSeverity &= ~errorBit;
                m_aer.totalNonFatalErrors++;
            }
            m_aer.headerLog = header;
        } else {
            m_aer.corrStatus |= errorBit;
            m_aer.totalCorrectableErrors++;
        }
    }

    void clearAerStatus(uint32_t uncorrClearBits = 0xFFFFFFFF, uint32_t corrClearBits = 0xFFFFFFFF) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_aer.uncorrStatus &= ~uncorrClearBits;
        m_aer.corrStatus &= ~corrClearBits;
    }
};

// ============================================================================
// 7. Specialized Sovereign PCIe Devices
// ============================================================================

// Sovereign Host Bridge / Root Complex
class PciHostBridge : public PciDevice {
public:
    PciHostBridge(PciAddress addr)
        : PciDevice(addr, 0x1022, 0x1480, PciBaseClass::Bridge, 0x00, 0x00, PCI_HEADER_TYPE_NORMAL)
    {
        setName("MicaNT PCIe Root Complex Host Bridge");
    }
};

// Sovereign PCIe Root Port (Type 1 PCI-to-PCI Bridge)
class PciRootPort : public PciDevice {
    uint8_t m_secondaryBus{0};
    uint8_t m_subordinateBus{0};

public:
    PciRootPort(PciAddress addr, uint8_t secondaryBus, uint8_t subordinateBus,
                PciLinkSpeed speed = PciLinkSpeed::Gen5_32_0GT,
                PciLinkWidth width = PciLinkWidth::x16)
        : PciDevice(addr, 0x1022, 0x1483 + (addr.device & 0x07),
                    PciBaseClass::Bridge, 0x04, 0x00, PCI_HEADER_TYPE_BRIDGE),
          m_secondaryBus(secondaryBus),
          m_subordinateBus(subordinateBus)
    {
        setName("MicaNT PCIe Root Port " + std::to_string(addr.device));
        writeConfigByte(PCI_CONFIG_PRIMARY_BUS, addr.bus);
        writeConfigByte(PCI_CONFIG_SECONDARY_BUS, secondaryBus);
        writeConfigByte(PCI_CONFIG_SUBORDINATE_BUS, subordinateBus);

        addPcieCapability(0x40, speed, width);
        addAerCapability(0x100);
    }

    uint8_t getSecondaryBus() const { return m_secondaryBus; }
    uint8_t getSubordinateBus() const { return m_subordinateBus; }
};

// Sovereign PrismX 3D Discrete GPU
class PrismXGpuPciDevice : public PciDevice {
public:
    PrismXGpuPciDevice(PciAddress addr)
        : PciDevice(addr, 0x10DE, 0x2684, PciBaseClass::Display, 0x00, 0x00, PCI_HEADER_TYPE_NORMAL)
    {
        setName("PrismX Discrete 3D GPU (RTX Sovereign Edition)");

        // BAR0: Control Registers (16MB MMIO, 32-bit non-prefetchable)
        configureBar(0, PciBarType::Memory32, 16 * 1024 * 1024, false);

        // BAR1: VRAM Framebuffer (16GB, 64-bit prefetchable)
        configureBar(1, PciBarType::Memory64, 16ULL * 1024 * 1024 * 1024, true);

        // BAR3: I/O Ports (128 bytes)
        configureBar(3, PciBarType::IoSpace, 128);

        // PCIe Gen 5 x16
        addPcieCapability(0x70, PciLinkSpeed::Gen5_32_0GT, PciLinkWidth::x16);

        // MSI-X with 32 vectors
        addMsixCapability(0x90, 32, 0, 0x1000, 0x2000);

        // AER
        addAerCapability(0x100);
    }
};

// Sovereign TitanNVMe High-Speed Flash Controller
class TitanNvmePciDevice : public PciDevice {
public:
    TitanNvmePciDevice(PciAddress addr)
        : PciDevice(addr, 0x144D, 0xA80A, PciBaseClass::MassStorage, 0x08, 0x02, PCI_HEADER_TYPE_NORMAL)
    {
        setName("TitanNVMe Enterprise Solid-State Storage Controller");

        // BAR0: NVMe Controller Registers (16KB MMIO, 64-bit non-prefetchable)
        configureBar(0, PciBarType::Memory64, 16 * 1024, false);

        // PCIe Gen 4 x4
        addPcieCapability(0x70, PciLinkSpeed::Gen4_16_0GT, PciLinkWidth::x4);

        // MSI-X with 64 vectors
        addMsixCapability(0x90, 64, 0, 0x2000, 0x3000);

        // AER
        addAerCapability(0x100);
    }
};

// Sovereign TitanUSB xHCI 1.2 Host Controller
class TitanXhciPciDevice : public PciDevice {
public:
    TitanXhciPciDevice(PciAddress addr)
        : PciDevice(addr, 0x1B73, 0x1100, PciBaseClass::SerialBus, 0x03, 0x30, PCI_HEADER_TYPE_NORMAL)
    {
        setName("TitanUSB 3.2 eXtensible Host Controller (xHCI 1.2)");

        // BAR0: xHCI MMIO Registers (64KB MMIO, 64-bit non-prefetchable)
        configureBar(0, PciBarType::Memory64, 64 * 1024, false);

        // PCIe Gen 3 x2
        addPcieCapability(0x70, PciLinkSpeed::Gen3_8_0GT, PciLinkWidth::x2);

        // MSI with 8 vectors (power of 2: 3)
        addMsiCapability(0x90, 3, true);
    }
};

// Sovereign RazzleNet 10GbE Network Controller
class RazzleNetPciDevice : public PciDevice {
public:
    RazzleNetPciDevice(PciAddress addr)
        : PciDevice(addr, 0x8086, 0x1563, PciBaseClass::Network, 0x00, 0x00, PCI_HEADER_TYPE_NORMAL)
    {
        setName("RazzleNet 10-Gigabit Ethernet Adapter (Titan 10G-SR)");

        // BAR0: 512KB MMIO (64-bit non-prefetchable)
        configureBar(0, PciBarType::Memory64, 512 * 1024, false);

        // PCIe Gen 3 x4
        addPcieCapability(0x70, PciLinkSpeed::Gen3_8_0GT, PciLinkWidth::x4);

        // MSI-X with 16 vectors
        addMsixCapability(0x90, 16, 0, 0x4000, 0x5000);

        // AER
        addAerCapability(0x100);
    }
};

// Sovereign PrismAudio High Definition Audio Controller
class PrismAudioPciDevice : public PciDevice {
public:
    PrismAudioPciDevice(PciAddress addr)
        : PciDevice(addr, 0x8086, 0x7AD0, PciBaseClass::Multimedia, 0x03, 0x00, PCI_HEADER_TYPE_NORMAL)
    {
        setName("PrismAudio High Definition Audio Controller");

        // BAR0: 16KB MMIO (64-bit non-prefetchable)
        configureBar(0, PciBarType::Memory64, 16 * 1024, false);

        // PCIe Gen 2 x1
        addPcieCapability(0x70, PciLinkSpeed::Gen2_5_0GT, PciLinkWidth::x1);

        // MSI with 1 vector
        addMsiCapability(0x90, 0, true);
    }
};

// Sovereign TitanWiFi 7 (802.11be) Wireless Network Adapter
class TitanWiFiPciDevice : public PciDevice {
public:
    TitanWiFiPciDevice(PciAddress addr)
        : PciDevice(addr, 0x8086, 0x272B, PciBaseClass::Network, 0x80, 0x00, PCI_HEADER_TYPE_NORMAL)
    {
        setName("TitanWiFi 7 802.11be Wireless Adapter (Intel BE200)");

        // BAR0: 1MB MMIO (64-bit non-prefetchable)
        configureBar(0, PciBarType::Memory64, 1024 * 1024, false);

        // PCIe Gen 4 x1
        addPcieCapability(0x70, PciLinkSpeed::Gen4_16_0GT, PciLinkWidth::x1);

        // MSI-X with 16 vectors
        addMsixCapability(0x90, 16, 0, 0x8000, 0x9000);

        // AER
        addAerCapability(0x100);
    }
};

// Sovereign TitanUSB4 2.0 / Thunderbolt 4 Host Router
class TitanUsb4PciDevice : public PciDevice {
public:
    TitanUsb4PciDevice(PciAddress addr)
        : PciDevice(addr, 0x8086, 0x9A1B, PciBaseClass::SerialBus, 0x03, 0x40, PCI_HEADER_TYPE_NORMAL)
    {
        setName("TitanUSB4 2.0 / Thunderbolt 4 Host Router (Intel Arrow Lake)");

        // BAR0: 64KB MMIO (64-bit non-prefetchable)
        configureBar(0, PciBarType::Memory64, 64 * 1024, false);

        // PCIe Gen 4 x4
        addPcieCapability(0x70, PciLinkSpeed::Gen4_16_0GT, PciLinkWidth::x4);

        // MSI-X with 8 vectors
        addMsixCapability(0x90, 8, 0, 0x2000, 0x3000);

        // AER
        addAerCapability(0x100);
    }
};

// Sovereign TitanNPU Core Ultra NPU 4000 (Processing Accelerator)
class TitanNpuPciDevice : public PciDevice {
public:
    TitanNpuPciDevice(PciAddress addr)
        : PciDevice(addr, 0x8086, 0x7D1D, PciBaseClass::Accelerator, 0x00, 0x00, PCI_HEADER_TYPE_NORMAL)
    {
        setName("TitanNPU Core Ultra NPU 4000 (Intel AI Boost)");

        // BAR0: 16MB MMIO (64-bit non-prefetchable) - NPU Registers & Command Rings
        configureBar(0, PciBarType::Memory64, 16 * 1024 * 1024, false);

        // BAR2: 128MB MMIO (64-bit prefetchable) - On-Chip Weight / Activation SRAM window
        configureBar(2, PciBarType::Memory64, 128 * 1024 * 1024, true);

        // PCIe Gen 4 x4
        addPcieCapability(0x70, PciLinkSpeed::Gen4_16_0GT, PciLinkWidth::x4);

        // MSI-X with 16 vectors
        addMsixCapability(0x90, 16, 0, 0x2000, 0x3000);

        // AER
        addAerCapability(0x100);
    }
};

// Sovereign TitanCXL 3.1 Host Bridge & Root Port
class TitanCxlHostBridgePciDevice : public PciRootPort {
public:
    TitanCxlHostBridgePciDevice(PciAddress addr, uint8_t secondaryBus = 4, uint8_t subordinateBus = 4)
        : PciRootPort(addr, secondaryBus, subordinateBus, PciLinkSpeed::Gen5_32_0GT, PciLinkWidth::x16)
    {
        setName("TitanCXL 3.1 Host Bridge & Root Complex (CXL.io / CXL.cache / CXL.mem)");
        writeConfigWord(PCI_CONFIG_VENDOR_ID, 0x1E98); // CXL Consortium Vendor ID
        writeConfigWord(PCI_CONFIG_DEVICE_ID, 0x0001); // CXL 3.1 Host Bridge

        // BAR0: 64KB MMIO for CXL Host Bridge Component Registers (CXL.cachemem / HDM Decoders)
        configureBar(0, PciBarType::Memory64, 64 * 1024, false);
    }
};

// Sovereign TitanCXL 128GB Type 3 DDR5 Memory Expander
class TitanCxlMemoryPciDevice : public PciDevice {
public:
    TitanCxlMemoryPciDevice(PciAddress addr)
        : PciDevice(addr, 0x1E98, 0x0010, PciBaseClass::Memory, 0x80, 0x00, PCI_HEADER_TYPE_NORMAL)
    {
        setName("TitanCXL 128GB DDR5 Type 3 Memory Expander");

        // BAR0: 64KB MMIO (64-bit non-prefetchable) - CXL Component / Mailbox Registers
        configureBar(0, PciBarType::Memory64, 64 * 1024, false);

        // BAR2: 128GB MMIO (64-bit prefetchable) - CXL.mem Byte-Addressable Aperture
        configureBar(2, PciBarType::Memory64, 128ULL * 1024 * 1024 * 1024, true);

        // PCIe Gen 5 x16
        addPcieCapability(0x70, PciLinkSpeed::Gen5_32_0GT, PciLinkWidth::x16);

        // MSI-X with 16 vectors
        addMsixCapability(0x90, 16, 0, 0x2000, 0x3000);

        // AER
        addAerCapability(0x100);
    }
};

// Sovereign TitanCXL Type 2 Heterogeneous AI Accelerator
class TitanCxlAcceleratorPciDevice : public PciDevice {
public:
    TitanCxlAcceleratorPciDevice(PciAddress addr)
        : PciDevice(addr, 0x1E98, 0x0020, PciBaseClass::Accelerator, 0x00, 0x00, PCI_HEADER_TYPE_NORMAL)
    {
        setName("TitanCXL Type 2 Heterogeneous Accelerator (CXL.cache / CXL.mem 64GB HBM)");

        // BAR0: 32MB MMIO (64-bit non-prefetchable) - Control & DMA Registers
        configureBar(0, PciBarType::Memory64, 32 * 1024 * 1024, false);

        // BAR2: 64GB MMIO (64-bit prefetchable) - Coherent Local Memory Aperture
        configureBar(2, PciBarType::Memory64, 64ULL * 1024 * 1024 * 1024, true);

        // PCIe Gen 5 x16
        addPcieCapability(0x70, PciLinkSpeed::Gen5_32_0GT, PciLinkWidth::x16);

        // MSI-X with 32 vectors
        addMsixCapability(0x90, 32, 0, 0x4000, 0x5000);

        // AER
        addAerCapability(0x100);
    }
};

// ============================================================================
// 8. PCI Bus Topology & Root Complex Engine
// ============================================================================

class PciBus {
    uint8_t m_busNumber{0};
    std::map<uint8_t, std::shared_ptr<PciDevice>> m_devices; // key = (dev << 3) | func

public:
    explicit PciBus(uint8_t busNum) : m_busNumber(busNum) {}

    uint8_t getBusNumber() const { return m_busNumber; }

    bool attachDevice(std::shared_ptr<PciDevice> dev) {
        if (!dev) return false;
        auto addr = dev->getAddress();
        uint8_t slot = (addr.device << 3) | (addr.function & 0x07);
        m_devices[slot] = dev;
        return true;
    }

    std::shared_ptr<PciDevice> getDevice(uint8_t device, uint8_t function) const {
        uint8_t slot = (device << 3) | (function & 0x07);
        auto it = m_devices.find(slot);
        if (it != m_devices.end()) return it->second;
        return nullptr;
    }

    std::vector<std::shared_ptr<PciDevice>> getAllDevices() const {
        std::vector<std::shared_ptr<PciDevice>> res;
        res.reserve(m_devices.size());
        for (const auto& [slot, dev] : m_devices) {
            res.push_back(dev);
        }
        return res;
    }
};

class TitanPciSubsystem {
    std::map<uint8_t, std::shared_ptr<PciBus>> m_buses;
    std::atomic<bool> m_initialized{false};
    mutable std::mutex m_mutex;

    // Resource allocation state
    uint64_t m_nextMmio32{0xC0000000ULL};     // 3GB
    uint64_t m_nextMmio64{0x8000000000ULL};   // 512GB high window
    uint16_t m_nextIoPort{0x2000};            // 8KB

    TitanPciSubsystem() = default;

public:
    static TitanPciSubsystem& Instance() {
        static TitanPciSubsystem s_inst;
        return s_inst;
    }

    void initialize() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_initialized.load()) return;

        // Create Buses 0..4
        for (uint8_t b = 0; b <= 4; ++b) {
            m_buses[b] = std::make_shared<PciBus>(b);
        }

        // Bus 0: Root Complex, Root Ports, and On-board Peripherals
        // 00:00.0 - Host Bridge
        auto hostBridge = std::make_shared<PciHostBridge>(PciAddress(0, 0, 0));
        m_buses[0]->attachDevice(hostBridge);

        // 00:01.0 - Root Port 1 (Bridge to Bus 1: GPU)
        auto rootPort1 = std::make_shared<PciRootPort>(PciAddress(0, 1, 0), 1, 1,
                                                      PciLinkSpeed::Gen5_32_0GT, PciLinkWidth::x16);
        m_buses[0]->attachDevice(rootPort1);

        // 00:02.0 - Root Port 2 (Bridge to Bus 2: NVMe)
        auto rootPort2 = std::make_shared<PciRootPort>(PciAddress(0, 2, 0), 2, 2,
                                                      PciLinkSpeed::Gen4_16_0GT, PciLinkWidth::x4);
        m_buses[0]->attachDevice(rootPort2);

        // 00:03.0 - Root Port 3 (Bridge to Bus 3: USB xHCI)
        auto rootPort3 = std::make_shared<PciRootPort>(PciAddress(0, 3, 0), 3, 3,
                                                      PciLinkSpeed::Gen3_8_0GT, PciLinkWidth::x2);
        m_buses[0]->attachDevice(rootPort3);

        // 00:04.0 - RazzleNet 10GbE
        auto nic = std::make_shared<RazzleNetPciDevice>(PciAddress(0, 4, 0));
        m_buses[0]->attachDevice(nic);

        // 00:05.0 - PrismAudio HDA
        auto audio = std::make_shared<PrismAudioPciDevice>(PciAddress(0, 5, 0));
        m_buses[0]->attachDevice(audio);

        // 00:06.0 - TitanWiFi 7 (802.11be)
        auto wifi = std::make_shared<TitanWiFiPciDevice>(PciAddress(0, 6, 0));
        m_buses[0]->attachDevice(wifi);

        // 00:07.0 - TitanUSB4 2.0 Host Router
        auto usb4 = std::make_shared<TitanUsb4PciDevice>(PciAddress(0, 7, 0));
        m_buses[0]->attachDevice(usb4);

        // 00:08.0 - TitanNPU AI Accelerator
        auto npu = std::make_shared<TitanNpuPciDevice>(PciAddress(0, 8, 0));
        m_buses[0]->attachDevice(npu);

        // 00:09.0 - TitanCXL 3.1 Host Bridge / Root Port (Bridge to Bus 4: CXL Fabric)
        auto cxlBridge = std::make_shared<TitanCxlHostBridgePciDevice>(PciAddress(0, 9, 0), 4, 4);
        m_buses[0]->attachDevice(cxlBridge);

        // Bus 1: PrismX 3D GPU
        auto gpu = std::make_shared<PrismXGpuPciDevice>(PciAddress(1, 0, 0));
        m_buses[1]->attachDevice(gpu);

        // Bus 2: TitanNVMe SSD
        auto nvme = std::make_shared<TitanNvmePciDevice>(PciAddress(2, 0, 0));
        m_buses[2]->attachDevice(nvme);

        // Bus 3: TitanUSB xHCI Controller
        auto xhci = std::make_shared<TitanXhciPciDevice>(PciAddress(3, 0, 0));
        m_buses[3]->attachDevice(xhci);

        // Bus 4: CXL Fabric Devices
        // 04:00.0 - TitanCXL 128GB Type 3 DDR5 Memory Expander
        auto cxlMem = std::make_shared<TitanCxlMemoryPciDevice>(PciAddress(4, 0, 0));
        m_buses[4]->attachDevice(cxlMem);

        // 04:01.0 - TitanCXL Type 2 Heterogeneous AI Accelerator
        auto cxlAcc = std::make_shared<TitanCxlAcceleratorPciDevice>(PciAddress(4, 1, 0));
        m_buses[4]->attachDevice(cxlAcc);

        // Assign MMIO and I/O ranges to all devices
        allocateResources();

        m_initialized.store(true);
    }

    void allocateResources() {
        for (auto& [busNum, bus] : m_buses) {
            for (auto& dev : bus->getAllDevices()) {
                for (uint8_t barIdx = 0; barIdx < 6; ++barIdx) {
                    auto bar = dev->getBar(barIdx);
                    if (bar.type == PciBarType::None || bar.size == 0) continue;
                    if (bar.is64BitUpperHalf) continue;

                    if (bar.type == PciBarType::IoSpace) {
                        uint16_t align = static_cast<uint16_t>(bar.size - 1);
                        m_nextIoPort = (m_nextIoPort + align) & ~align;
                        dev->writeBar(barIdx, m_nextIoPort);
                        m_nextIoPort += static_cast<uint16_t>(bar.size);
                    } else if (bar.type == PciBarType::Memory32) {
                        uint64_t align = bar.size - 1;
                        m_nextMmio32 = (m_nextMmio32 + align) & ~align;
                        dev->writeBar(barIdx, static_cast<uint32_t>(m_nextMmio32));
                        m_nextMmio32 += bar.size;
                    } else if (bar.type == PciBarType::Memory64) {
                        uint64_t align = bar.size - 1;
                        m_nextMmio64 = (m_nextMmio64 + align) & ~align;
                        dev->writeBar(barIdx, static_cast<uint32_t>(m_nextMmio64 & 0xFFFFFFFF));
                        dev->writeBar(barIdx + 1, static_cast<uint32_t>(m_nextMmio64 >> 32));
                        m_nextMmio64 += bar.size;
                    }
                }
            }
        }
    }

    std::shared_ptr<PciDevice> findDevice(PciAddress addr) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_buses.find(addr.bus);
        if (it != m_buses.end()) {
            return it->second->getDevice(addr.device, addr.function);
        }
        return nullptr;
    }

    std::shared_ptr<PciDevice> findDeviceByVendorDevice(uint16_t vendorId, uint16_t deviceId) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& [busNum, bus] : m_buses) {
            for (const auto& dev : bus->getAllDevices()) {
                if (dev->getVendorId() == vendorId && dev->getDeviceId() == deviceId) {
                    return dev;
                }
            }
        }
        return nullptr;
    }

    std::vector<std::shared_ptr<PciDevice>> findDevicesByClass(PciBaseClass baseClass) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<std::shared_ptr<PciDevice>> res;
        for (const auto& [busNum, bus] : m_buses) {
            for (const auto& dev : bus->getAllDevices()) {
                if (dev->getBaseClass() == static_cast<uint8_t>(baseClass)) {
                    res.push_back(dev);
                }
            }
        }
        return res;
    }

    std::vector<std::shared_ptr<PciDevice>> getAllDevices() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<std::shared_ptr<PciDevice>> res;
        for (const auto& [busNum, bus] : m_buses) {
            auto devs = bus->getAllDevices();
            res.insert(res.end(), devs.begin(), devs.end());
        }
        return res;
    }

    size_t getBusCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_buses.size();
    }
};

// ============================================================================
// 9. Win32 / PCI Bus Driver C ABI Exports (pci.sys)
// ============================================================================

extern "C" {

inline uint8_t WINAPI PciReadConfigByte(uint32_t bdf, uint16_t offset) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (!dev) return 0xFF;
    return dev->readConfigByte(offset);
}

inline uint16_t WINAPI PciReadConfigWord(uint32_t bdf, uint16_t offset) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (!dev) return 0xFFFF;
    return dev->readConfigWord(offset);
}

inline uint32_t WINAPI PciReadConfigDword(uint32_t bdf, uint16_t offset) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (!dev) return 0xFFFFFFFF;
    return dev->readConfigDword(offset);
}

inline void WINAPI PciWriteConfigByte(uint32_t bdf, uint16_t offset, uint8_t val) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (dev) dev->writeConfigByte(offset, val);
}

inline void WINAPI PciWriteConfigWord(uint32_t bdf, uint16_t offset, uint16_t val) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (dev) dev->writeConfigWord(offset, val);
}

inline void WINAPI PciWriteConfigDword(uint32_t bdf, uint16_t offset, uint32_t val) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (dev) dev->writeConfigDword(offset, val);
}

inline BOOL WINAPI PciFindDevice(uint16_t vendorId, uint16_t deviceId, uint32_t* pBdf) {
    if (!pBdf) return FALSE;
    auto dev = TitanPciSubsystem::Instance().findDeviceByVendorDevice(vendorId, deviceId);
    if (!dev) return FALSE;
    *pBdf = dev->getAddress().toBdf();
    return TRUE;
}

inline BOOL WINAPI PciGetBarInfo(
    uint32_t bdf,
    uint8_t barIndex,
    uint64_t* pBaseAddress,
    uint64_t* pSize,
    uint8_t* pIsIo,
    uint8_t* pPrefetchable
) {
    if (!pBaseAddress || !pSize || !pIsIo || !pPrefetchable) return FALSE;
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (!dev || barIndex >= 6) return FALSE;

    const auto& bar = dev->getBar(barIndex);
    if (bar.type == PciBarType::None) return FALSE;

    *pBaseAddress = bar.baseAddress;
    *pSize = bar.size;
    *pIsIo = bar.isIo() ? 1 : 0;
    *pPrefetchable = bar.prefetchable ? 1 : 0;
    return TRUE;
}

inline BOOL WINAPI PciEnableBusMastering(uint32_t bdf, BOOL enable) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (!dev) return FALSE;

    uint16_t cmd = dev->readConfigWord(PCI_CONFIG_COMMAND);
    if (enable) cmd |= PCI_COMMAND_BUS_MASTER;
    else cmd &= ~PCI_COMMAND_BUS_MASTER;
    dev->writeConfigWord(PCI_CONFIG_COMMAND, cmd);
    return TRUE;
}

inline BOOL WINAPI PciEnableMemorySpace(uint32_t bdf, BOOL enable) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (!dev) return FALSE;

    uint16_t cmd = dev->readConfigWord(PCI_CONFIG_COMMAND);
    if (enable) cmd |= PCI_COMMAND_MEM_ENABLE;
    else cmd &= ~PCI_COMMAND_MEM_ENABLE;
    dev->writeConfigWord(PCI_CONFIG_COMMAND, cmd);
    return TRUE;
}

inline BOOL WINAPI PciConfigureMsi(
    uint32_t bdf,
    uint64_t messageAddress,
    uint16_t messageData,
    uint8_t  vectorCountPowerOf2
) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (!dev || dev->getMsi().offset == 0) return FALSE;

    auto& msi = dev->getMsi();
    msi.messageAddress = messageAddress;
    msi.messageData = messageData;
    msi.multiMessageEnable = std::min(vectorCountPowerOf2, msi.multiMessageCapable);
    msi.enabled = true;
    return TRUE;
}

inline BOOL WINAPI PciConfigureMsix(
    uint32_t bdf,
    uint16_t tableIndex,
    uint64_t messageAddress,
    uint32_t messageData,
    BOOL     masked
) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (!dev || dev->getMsix().offset == 0) return FALSE;

    if (dev->setMsixEntry(tableIndex, messageAddress, messageData, masked == TRUE)) {
        dev->getMsix().enabled = true;
        return TRUE;
    }
    return FALSE;
}

inline BOOL WINAPI PciTriggerMsiVector(uint32_t bdf, uint16_t vectorIndex) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (!dev) return FALSE;

    if (dev->getMsix().enabled && vectorIndex < dev->getMsix().table.size()) {
        const auto& entry = dev->getMsix().table[vectorIndex];
        if (entry.isMasked()) {
            // Record pending bit in PBA
            size_t wordIdx = vectorIndex / 64;
            uint8_t bitIdx = vectorIndex % 64;
            if (wordIdx < dev->getMsix().pbaBits.size()) {
                dev->getMsix().pbaBits[wordIdx] |= (1ULL << bitIdx);
            }
            return FALSE; // Interrupt masked, queued in PBA
        }
        return TRUE; // Delivered!
    } else if (dev->getMsi().enabled) {
        return TRUE;
    }
    return FALSE;
}

inline BOOL WINAPI PciInjectAerError(
    uint32_t bdf,
    uint32_t errorBit,
    BOOL     isUncorrectable,
    BOOL     isFatal
) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (!dev || dev->getAer().offset == 0) return FALSE;

    std::array<uint32_t, 4> fakeHdr = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    dev->triggerAerError(errorBit, isUncorrectable == TRUE, isFatal == TRUE, fakeHdr);
    return TRUE;
}

inline BOOL WINAPI PciClearAerStatus(uint32_t bdf) {
    auto dev = TitanPciSubsystem::Instance().findDevice(PciAddress::fromBdf(bdf));
    if (!dev || dev->getAer().offset == 0) return FALSE;
    dev->clearAerStatus();
    return TRUE;
}

} // extern "C"

// ============================================================================
// 10. Subsystem Initialization & Registration
// ============================================================================

inline void InitializePciSubsystem() {
    static bool s_registered = false;
    if (s_registered) return;
    s_registered = true;

    // 1. Initialize Subsystem Singleton & Hardware Device Tree
    TitanPciSubsystem::Instance().initialize();

    // 2. Dynamic Loader Exports for pci.sys
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("pci.sys", "PciReadConfigByte", reinterpret_cast<void*>(PciReadConfigByte));
    ldr.registerExport("pci.sys", "PciReadConfigWord", reinterpret_cast<void*>(PciReadConfigWord));
    ldr.registerExport("pci.sys", "PciReadConfigDword", reinterpret_cast<void*>(PciReadConfigDword));
    ldr.registerExport("pci.sys", "PciWriteConfigByte", reinterpret_cast<void*>(PciWriteConfigByte));
    ldr.registerExport("pci.sys", "PciWriteConfigWord", reinterpret_cast<void*>(PciWriteConfigWord));
    ldr.registerExport("pci.sys", "PciWriteConfigDword", reinterpret_cast<void*>(PciWriteConfigDword));
    ldr.registerExport("pci.sys", "PciFindDevice", reinterpret_cast<void*>(PciFindDevice));
    ldr.registerExport("pci.sys", "PciGetBarInfo", reinterpret_cast<void*>(PciGetBarInfo));
    ldr.registerExport("pci.sys", "PciEnableBusMastering", reinterpret_cast<void*>(PciEnableBusMastering));
    ldr.registerExport("pci.sys", "PciEnableMemorySpace", reinterpret_cast<void*>(PciEnableMemorySpace));
    ldr.registerExport("pci.sys", "PciConfigureMsi", reinterpret_cast<void*>(PciConfigureMsi));
    ldr.registerExport("pci.sys", "PciConfigureMsix", reinterpret_cast<void*>(PciConfigureMsix));
    ldr.registerExport("pci.sys", "PciTriggerMsiVector", reinterpret_cast<void*>(PciTriggerMsiVector));
    ldr.registerExport("pci.sys", "PciInjectAerError", reinterpret_cast<void*>(PciInjectAerError));
    ldr.registerExport("pci.sys", "PciClearAerStatus", reinterpret_cast<void*>(PciClearAerStatus));

    // 3. Register PCI Bus Driver in SCM
    auto pciSvc = std::make_shared<scm::ServiceRecord>();
    pciSvc->serviceName = L"pci";
    pciSvc->displayName = L"MicaNT PCI Express Bus Driver";
    pciSvc->serviceType = scm::SERVICE_KERNEL_DRIVER;
    pciSvc->startType = scm::SERVICE_BOOT_START;
    pciSvc->errorControl = scm::SERVICE_ERROR_CRITICAL;
    pciSvc->binaryPath = L"C:\\Windows\\System32\\drivers\\pci.sys";
    pciSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    scm::ServiceControlManager::get().registerServiceRecord(pciSvc);

    // 4. Register Version Database Information
    version::VersionDatabase::Instance().RegisterModule(
        "pci.sys",
        "10.0.22621.1",
        "MicaNT Sovereign PCI Express Bus Driver"
    );
}

} // namespace micant::pci
