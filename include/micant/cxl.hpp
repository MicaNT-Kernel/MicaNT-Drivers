// ============================================================================
// MicaNT: Sovereign Operating System Subsystem
// Component: Compute Express Link (CXL 2.0 / 3.1) & Heterogeneous Memory Fabric
// Designation: TitanCXL (Host Bridge & Memory Fabric) / NexusCXL (Bus & Device Manager)
// Clean-Room Engineering Reference & Standards:
//   - Compute Express Link™ (CXL™) Specification Revision 3.1 (CXL Consortium)
//   - Compute Express Link™ (CXL™) Specification Revision 2.0 (CXL Consortium)
//   - PCI Express® Base Specification Revision 5.0 / 6.0 (PAM4 Flit Signaling)
//   - Microsoft Compute Driver Model / Heterogeneous Memory Architecture Guidelines
//   - Microsoft Open win32metadata repository
//   - ISO/IEC 14882:2023 C++ Standard
// Zero External Dependencies - Zero Telemetry - Freestanding Safe C++23
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <array>
#include <unordered_map>
#include <map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "pci.hpp"
#include "janusldr.hpp"
#include "scm.hpp"
#include "version.hpp"

#ifndef WINAPI
#define WINAPI __stdcall
#endif

namespace micant::cxl {

// ============================================================================
// 1. CXL Protocol, Device Type & Hardware Constants
// ============================================================================

// CXL Sub-Protocols
enum class CxlProtocol : uint32_t {
    None     = 0x00,
    CxlIo    = 0x01, // Enhanced PCIe for discovery, config, DMA, and AER
    CxlCache = 0x02, // Ultra-low latency coherent device cache of host memory
    CxlMem   = 0x04, // Low-latency byte-addressable host access to device memory
    All      = 0x07
};

inline constexpr uint32_t operator|(CxlProtocol a, CxlProtocol b) noexcept {
    return static_cast<uint32_t>(a) | static_cast<uint32_t>(b);
}

// CXL Device Classifications
enum class CxlDeviceType : uint8_t {
    Type1_Accelerator        = 1, // CXL.io + CXL.cache (SmartNIC, PGAS collective offload)
    Type2_DenseAccelerator   = 2, // CXL.io + CXL.cache + CXL.mem (GPU, NPU with coherent local memory)
    Type3_MemoryExpander      = 3  // CXL.io + CXL.mem (DDR5/NVM byte-addressable expander / pooling blade)
};

// CXL Link Signaling Speeds
enum class CxlLinkSpeed : uint8_t {
    Gen5_32GT = 5, // 32.0 GT/s (NRZ / 128b/130b or 256B Flit)
    Gen6_64GT = 6  // 64.0 GT/s (PAM4 / 256B Flit Mode)
};

// CXL Interleave Granularity
enum class CxlInterleaveGranularity : uint8_t {
    Granularity256B = 0,
    Granularity512B = 1,
    Granularity1KB  = 2,
    Granularity2KB  = 3,
    Granularity4KB  = 4,
    Granularity8KB  = 5,
    Granularity16KB = 6
};

// CXL Interleave Ways
enum class CxlInterleaveWays : uint8_t {
    Way1  = 0,
    Way2  = 1,
    Way4  = 2,
    Way8  = 3,
    Way16 = 4
};

// CXL Standard Mailbox Opcodes (CXL Spec 2.0/3.1 Table 8-34)
inline constexpr uint16_t CXL_MBOX_OP_IDENTIFY_MEMORY_DEVICE = 0x4000;
inline constexpr uint16_t CXL_MBOX_OP_GET_SMART_HEALTH       = 0x4001;
inline constexpr uint16_t CXL_MBOX_OP_GET_PARTITION_INFO     = 0x4100;
inline constexpr uint16_t CXL_MBOX_OP_SET_PARTITION_INFO     = 0x4101;
inline constexpr uint16_t CXL_MBOX_OP_GET_POISON_LIST        = 0x4300;
inline constexpr uint16_t CXL_MBOX_OP_INJECT_POISON          = 0x4301;
inline constexpr uint16_t CXL_MBOX_OP_CLEAR_POISON           = 0x4302;
inline constexpr uint16_t CXL_MBOX_OP_SCAN_MEDIA             = 0x4303;
inline constexpr uint16_t CXL_MBOX_OP_BACKGROUND_OP_STATUS   = 0x0002;

// CXL Vendor ID (CXL Consortium / Standard)
inline constexpr uint16_t CXL_CONSORTIUM_VENDOR_ID           = 0x1E98;

// ============================================================================
// 2. Data Structures: S.M.A.R.T. Health, Decoders, Poison & Telemetry
// ============================================================================

struct CxlSmartHealthInfo {
    uint8_t healthStatus{0};                // 0 = Normal, 1 = Maintenance, 2 = Degraded, 3 = Critical
    uint8_t mediaStatus{0};                 // 0 = Normal, 1 = Degraded, 2 = ReadOnly
    float temperatureCelsius{41.5f};        // Device operating temperature
    uint8_t percentLifeUsed{1};             // Device endurance percentage
    uint32_t dirtyShutdownCount{0};         // Unsafe power loss count
    uint32_t correctedVolatileErrorCount{0}; // Corrected ECC errors
    uint32_t uncorrectedVolatileErrorCount{0}; // Uncorrected fatal errors
    uint64_t volatileCapacityBytes{128ULL * 1024 * 1024 * 1024}; // 128 GB Volatile RAM
    uint64_t persistentCapacityBytes{0};    // Persistent NVM capacity
};

struct CxlHdmDecoder {
    uint8_t decoderIndex{0};                // HDM Decoder 0..3
    uint64_t baseSpa{0};                    // System Physical Address Base
    uint64_t sizeBytes{0};                  // Mapped Memory Size
    CxlInterleaveGranularity granularity{CxlInterleaveGranularity::Granularity256B};
    CxlInterleaveWays ways{CxlInterleaveWays::Way1};
    bool isCommitted{false};                // Decoder locked & committed to HW
    std::vector<uint8_t> targetList;        // Target Port / Device IDs for interleaving
};

struct CxlPoisonRecord {
    uint64_t devicePhysicalAddress{0};      // DPA of poisoned cache line
    uint16_t lengthBytes{64};               // Poisoned cache line size (64 bytes)
    uint32_t sourceTag{0};                  // 1 = External Bus, 2 = Media ECC, 3 = Injected
    uint64_t timestampUs{0};                // Microsecond timestamp
};

struct CxlDeviceInfo {
    uint32_t deviceId{0};
    pci::PciAddress pciAddress{};
    std::string deviceName;
    uint16_t vendorId{CXL_CONSORTIUM_VENDOR_ID};
    uint16_t devId{0x0010};
    CxlDeviceType type{CxlDeviceType::Type3_MemoryExpander};
    uint32_t supportedProtocols{static_cast<uint32_t>(CxlProtocol::CxlIo) | static_cast<uint32_t>(CxlProtocol::CxlMem)};
    CxlLinkSpeed linkSpeed{CxlLinkSpeed::Gen5_32GT};
    uint8_t linkWidth{16}; // x16
    uint64_t totalMemoryBytes{128ULL * 1024 * 1024 * 1024}; // 128 GB
    uint32_t numaNodeId{1}; // Associated NUMA domain
    CxlSmartHealthInfo smart{};
    std::vector<CxlHdmDecoder> decoders;
    std::vector<CxlPoisonRecord> poisonList;
};

struct CxlNumaTieringInfo {
    uint32_t tierId{1};                     // Tier 1: Far Memory (CXL.mem)
    uint32_t numaNodeId{1};
    uint64_t totalCapacityBytes{128ULL * 1024 * 1024 * 1024};
    uint64_t allocatedBytes{0};
    uint32_t readLatencyNs{140};            // Near memory ~80ns, CXL ~140ns
    uint32_t writeLatencyNs{150};           // CXL write latency
    float peakBandwidthGBps{64.0f};         // PCIe Gen5 x16 bandwidth
    uint64_t pagesMigratedToFar{0};
    uint64_t pagesPromotedToNear{0};
};

struct CxlTelemetry {
    uint64_t totalCxlReadTransactions{0};
    uint64_t totalCxlWriteTransactions{0};
    uint64_t totalFlitsTransferred{0};
    uint64_t totalMailboxCommandsExecuted{0};
    uint32_t activeDevices{0};
    uint32_t totalPoisonEntries{0};
    float currentFabricThroughputGBps{0.0f};
};

// ============================================================================
// 3. TitanCXL Host Fabric & Memory Manager Engine
// ============================================================================

class TitanCxlSubsystem {
public:
    static TitanCxlSubsystem& Instance() {
        static TitanCxlSubsystem s_instance;
        return s_instance;
    }

    void initialize() {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if (m_initialized) return;

        // 1. Initialize Host Bridge Information
        m_hostBridgeAddress = pci::PciAddress(0, 9, 0);
        m_cxlSpecVersionMajor = 3;
        m_cxlSpecVersionMinor = 1;

        // 2. Clear devices & decoders
        m_devices.clear();
        m_nextDeviceId = 1;

        // 3. Register Default Device 1: Sovereign TitanCXL 128GB Type 3 DDR5 Memory Expander
        CxlDeviceInfo dev1{};
        dev1.deviceId = m_nextDeviceId++;
        dev1.pciAddress = pci::PciAddress(4, 0, 0);
        dev1.deviceName = "TitanCXL 128GB DDR5 Type 3 Memory Expander";
        dev1.vendorId = CXL_CONSORTIUM_VENDOR_ID;
        dev1.devId = 0x0010;
        dev1.type = CxlDeviceType::Type3_MemoryExpander;
        dev1.supportedProtocols = static_cast<uint32_t>(CxlProtocol::CxlIo) | static_cast<uint32_t>(CxlProtocol::CxlMem);
        dev1.linkSpeed = CxlLinkSpeed::Gen5_32GT;
        dev1.linkWidth = 16;
        dev1.totalMemoryBytes = 128ULL * 1024 * 1024 * 1024;
        dev1.numaNodeId = 1;
        dev1.smart.healthStatus = 0;
        dev1.smart.mediaStatus = 0;
        dev1.smart.temperatureCelsius = 41.5f;
        dev1.smart.percentLifeUsed = 1;
        dev1.smart.volatileCapacityBytes = dev1.totalMemoryBytes;

        // Configure HDM Decoder 0 for Device 1 (Maps 128GB starting at 64GB SPA: 0x10_0000_0000)
        CxlHdmDecoder dec0{};
        dec0.decoderIndex = 0;
        dec0.baseSpa = 0x1000000000ULL; // 64 GB boundary
        dec0.sizeBytes = dev1.totalMemoryBytes;
        dec0.granularity = CxlInterleaveGranularity::Granularity256B;
        dec0.ways = CxlInterleaveWays::Way1;
        dec0.isCommitted = true;
        dec0.targetList = {0};
        dev1.decoders.push_back(dec0);

        m_devices[dev1.deviceId] = dev1;

        // 4. Register Default Device 2: Sovereign TitanCXL Type 2 Heterogeneous AI Accelerator
        CxlDeviceInfo dev2{};
        dev2.deviceId = m_nextDeviceId++;
        dev2.pciAddress = pci::PciAddress(4, 1, 0);
        dev2.deviceName = "TitanCXL Type 2 Heterogeneous Accelerator (64GB Coherent HBM)";
        dev2.vendorId = CXL_CONSORTIUM_VENDOR_ID;
        dev2.devId = 0x0020;
        dev2.type = CxlDeviceType::Type2_DenseAccelerator;
        dev2.supportedProtocols = static_cast<uint32_t>(CxlProtocol::CxlIo) |
                                 static_cast<uint32_t>(CxlProtocol::CxlCache) |
                                 static_cast<uint32_t>(CxlProtocol::CxlMem);
        dev2.linkSpeed = CxlLinkSpeed::Gen5_32GT;
        dev2.linkWidth = 16;
        dev2.totalMemoryBytes = 64ULL * 1024 * 1024 * 1024;
        dev2.numaNodeId = 2;
        dev2.smart.healthStatus = 0;
        dev2.smart.mediaStatus = 0;
        dev2.smart.temperatureCelsius = 45.0f;
        dev2.smart.percentLifeUsed = 0;
        dev2.smart.volatileCapacityBytes = dev2.totalMemoryBytes;

        // Configure HDM Decoder 0 for Device 2 (Maps 64GB starting at 192GB SPA: 0x30_0000_0000)
        CxlHdmDecoder dec1{};
        dec1.decoderIndex = 0;
        dec1.baseSpa = 0x3000000000ULL; // 192 GB boundary
        dec1.sizeBytes = dev2.totalMemoryBytes;
        dec1.granularity = CxlInterleaveGranularity::Granularity512B;
        dec1.ways = CxlInterleaveWays::Way1;
        dec1.isCommitted = true;
        dec1.targetList = {1};
        dev2.decoders.push_back(dec1);

        m_devices[dev2.deviceId] = dev2;

        // 5. Initialize NUMA Dynamic Memory Tiering (DMT)
        m_tiering.tierId = 1;
        m_tiering.numaNodeId = 1;
        m_tiering.totalCapacityBytes = dev1.totalMemoryBytes;
        m_tiering.allocatedBytes = 16ULL * 1024 * 1024 * 1024; // 16GB pre-allocated cold pages
        m_tiering.readLatencyNs = 140;
        m_tiering.writeLatencyNs = 150;
        m_tiering.peakBandwidthGBps = 64.0f;
        m_tiering.pagesMigratedToFar = 4194304ULL; // 16GB / 4KB
        m_tiering.pagesPromotedToNear = 1048576ULL; // 4GB / 4KB

        // 6. Update Telemetry
        m_telemetry.activeDevices = static_cast<uint32_t>(m_devices.size());
        m_telemetry.totalCxlReadTransactions = 1250000000ULL;
        m_telemetry.totalCxlWriteTransactions = 850000000ULL;
        m_telemetry.totalFlitsTransferred = 3500000000ULL;
        m_telemetry.currentFabricThroughputGBps = 48.5f;

        m_initialized = true;
    }

    bool isInitialized() const noexcept {
        return m_initialized;
    }

    void getVersion(uint32_t* major, uint32_t* minor) const noexcept {
        if (major) *major = m_cxlSpecVersionMajor;
        if (minor) *minor = m_cxlSpecVersionMinor;
    }

    pci::PciAddress getHostBridgeAddress() const noexcept {
        return m_hostBridgeAddress;
    }

    // ------------------------------------------------------------------------
    // Device Management
    // ------------------------------------------------------------------------
    uint32_t registerDevice(const CxlDeviceInfo& dev) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        uint32_t id = dev.deviceId ? dev.deviceId : m_nextDeviceId++;
        CxlDeviceInfo copy = dev;
        copy.deviceId = id;
        m_devices[id] = copy;
        m_telemetry.activeDevices = static_cast<uint32_t>(m_devices.size());
        return id;
    }

    size_t getDeviceCount() const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_devices.size();
    }

    const CxlDeviceInfo* getDevice(uint32_t id) const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        auto it = m_devices.find(id);
        if (it == m_devices.end()) return nullptr;
        return &it->second;
    }

    const CxlDeviceInfo* getDeviceByPciAddress(pci::PciAddress addr) const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        for (const auto& [_, dev] : m_devices) {
            if (dev.pciAddress == addr) return &dev;
        }
        return nullptr;
    }

    std::vector<CxlDeviceInfo> getDevices() const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        std::vector<CxlDeviceInfo> list;
        list.reserve(m_devices.size());
        for (const auto& [_, dev] : m_devices) {
            list.push_back(dev);
        }
        return list;
    }

    // ------------------------------------------------------------------------
    // HDM (Host-Managed Device Memory) Decoder Configuration
    // ------------------------------------------------------------------------
    bool configureHdmDecoder(uint32_t devId, uint8_t decoderIdx, uint64_t baseSpa, uint64_t sizeBytes,
                             CxlInterleaveGranularity gran = CxlInterleaveGranularity::Granularity256B,
                             CxlInterleaveWays ways = CxlInterleaveWays::Way1) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        auto it = m_devices.find(devId);
        if (it == m_devices.end()) return false;

        auto& decoders = it->second.decoders;
        for (auto& dec : decoders) {
            if (dec.decoderIndex == decoderIdx) {
                dec.baseSpa = baseSpa;
                dec.sizeBytes = sizeBytes;
                dec.granularity = gran;
                dec.ways = ways;
                dec.isCommitted = true;
                return true;
            }
        }

        // Add new decoder
        CxlHdmDecoder newDec{};
        newDec.decoderIndex = decoderIdx;
        newDec.baseSpa = baseSpa;
        newDec.sizeBytes = sizeBytes;
        newDec.granularity = gran;
        newDec.ways = ways;
        newDec.isCommitted = true;
        decoders.push_back(newDec);
        return true;
    }

    const CxlHdmDecoder* getHdmDecoder(uint32_t devId, uint8_t decoderIdx) const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        auto it = m_devices.find(devId);
        if (it == m_devices.end()) return nullptr;

        for (const auto& dec : it->second.decoders) {
            if (dec.decoderIndex == decoderIdx) return &dec;
        }
        return nullptr;
    }

    // ------------------------------------------------------------------------
    // Mailbox Command Processing
    // ------------------------------------------------------------------------
    NTSTATUS sendMailboxCommand(uint32_t devId, uint16_t opcode,
                                const std::vector<uint8_t>& inputPayload,
                                std::vector<uint8_t>& outputPayload) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        auto it = m_devices.find(devId);
        if (it == m_devices.end()) return STATUS_NO_SUCH_DEVICE;

        m_telemetry.totalMailboxCommandsExecuted++;

        switch (opcode) {
            case CXL_MBOX_OP_IDENTIFY_MEMORY_DEVICE: {
                outputPayload.resize(64, 0);
                // Serial number, capacities, FW revision
                std::memcpy(outputPayload.data(), "TITAN-CXL-REV31", 15);
                uint64_t cap = it->second.totalMemoryBytes;
                std::memcpy(outputPayload.data() + 16, &cap, sizeof(cap));
                return STATUS_SUCCESS;
            }
            case CXL_MBOX_OP_GET_SMART_HEALTH: {
                outputPayload.resize(sizeof(CxlSmartHealthInfo));
                std::memcpy(outputPayload.data(), &it->second.smart, sizeof(CxlSmartHealthInfo));
                return STATUS_SUCCESS;
            }
            case CXL_MBOX_OP_GET_POISON_LIST: {
                size_t count = it->second.poisonList.size();
                outputPayload.resize(sizeof(uint32_t) + count * sizeof(CxlPoisonRecord));
                uint32_t c = static_cast<uint32_t>(count);
                std::memcpy(outputPayload.data(), &c, sizeof(c));
                if (count > 0) {
                    std::memcpy(outputPayload.data() + sizeof(uint32_t),
                                it->second.poisonList.data(),
                                count * sizeof(CxlPoisonRecord));
                }
                return STATUS_SUCCESS;
            }
            case CXL_MBOX_OP_INJECT_POISON: {
                if (inputPayload.size() < sizeof(uint64_t)) return STATUS_INVALID_PARAMETER;
                uint64_t dpa = 0;
                std::memcpy(&dpa, inputPayload.data(), sizeof(dpa));
                injectPoison(devId, dpa);
                return STATUS_SUCCESS;
            }
            case CXL_MBOX_OP_CLEAR_POISON: {
                if (inputPayload.size() < sizeof(uint64_t)) return STATUS_INVALID_PARAMETER;
                uint64_t dpa = 0;
                std::memcpy(&dpa, inputPayload.data(), sizeof(dpa));
                clearPoison(devId, dpa);
                return STATUS_SUCCESS;
            }
            default:
                return STATUS_NOT_SUPPORTED;
        }
    }

    // ------------------------------------------------------------------------
    // S.M.A.R.T. Health & Telemetry
    // ------------------------------------------------------------------------
    const CxlSmartHealthInfo* getSmartHealth(uint32_t devId) const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        auto it = m_devices.find(devId);
        if (it == m_devices.end()) return nullptr;
        return &it->second.smart;
    }

    const CxlTelemetry& getTelemetry() const noexcept {
        return m_telemetry;
    }

    // ------------------------------------------------------------------------
    // Address Poisoning & Error Containment
    // ------------------------------------------------------------------------
    std::vector<CxlPoisonRecord> getPoisonList(uint32_t devId) const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        auto it = m_devices.find(devId);
        if (it == m_devices.end()) return {};
        return it->second.poisonList;
    }

    bool injectPoison(uint32_t devId, uint64_t dpa) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        auto it = m_devices.find(devId);
        if (it == m_devices.end()) return false;

        // Check if already in list
        for (const auto& p : it->second.poisonList) {
            if (p.devicePhysicalAddress == dpa) return true;
        }

        CxlPoisonRecord rec{};
        rec.devicePhysicalAddress = dpa;
        rec.lengthBytes = 64; // Standard 64-byte cache line
        rec.sourceTag = 3;    // Software Injected
        rec.timestampUs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

        it->second.poisonList.push_back(rec);
        m_telemetry.totalPoisonEntries++;
        return true;
    }

    bool clearPoison(uint32_t devId, uint64_t dpa) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        auto it = m_devices.find(devId);
        if (it == m_devices.end()) return false;

        auto& list = it->second.poisonList;
        for (auto iter = list.begin(); iter != list.end(); ++iter) {
            if (iter->devicePhysicalAddress == dpa) {
                list.erase(iter);
                if (m_telemetry.totalPoisonEntries > 0) m_telemetry.totalPoisonEntries--;
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------------
    // Dynamic Memory Tiering (DMT) & NUMA Node Migration
    // ------------------------------------------------------------------------
    const CxlNumaTieringInfo& getNumaTieringInfo() const noexcept {
        return m_tiering;
    }

    bool migratePages(uint32_t /*devId*/, uint64_t pageCount, bool toFarMemory) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        uint64_t bytes = pageCount * 4096ULL;
        if (toFarMemory) {
            if (m_tiering.allocatedBytes + bytes > m_tiering.totalCapacityBytes) {
                return false;
            }
            m_tiering.allocatedBytes += bytes;
            m_tiering.pagesMigratedToFar += pageCount;
        } else {
            if (m_tiering.allocatedBytes >= bytes) {
                m_tiering.allocatedBytes -= bytes;
            } else {
                m_tiering.allocatedBytes = 0;
            }
            m_tiering.pagesPromotedToNear += pageCount;
        }
        return true;
    }

private:
    TitanCxlSubsystem() = default;

    mutable std::recursive_mutex m_mutex;
    bool m_initialized{false};
    uint32_t m_cxlSpecVersionMajor{3};
    uint32_t m_cxlSpecVersionMinor{1};
    pci::PciAddress m_hostBridgeAddress{0, 9, 0};
    std::unordered_map<uint32_t, CxlDeviceInfo> m_devices;
    uint32_t m_nextDeviceId{1};
    CxlNumaTieringInfo m_tiering{};
    CxlTelemetry m_telemetry{};
};

// ============================================================================
// 4. JanusLDR Dynamic C ABI Driver Exports
// ============================================================================

extern "C" {

// --- cxlhost.sys (CXL Host Bridge & Root Complex Driver) ---

inline NTSTATUS WINAPI CxlHostInitialize() {
    auto& cxl = TitanCxlSubsystem::Instance();
    cxl.initialize();
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI CxlHostGetVersion(uint32_t* pMajor, uint32_t* pMinor) {
    if (!pMajor || !pMinor) return STATUS_INVALID_PARAMETER;
    auto& cxl = TitanCxlSubsystem::Instance();
    if (!cxl.isInitialized()) cxl.initialize();
    cxl.getVersion(pMajor, pMinor);
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI CxlHostEnumerateBridges(uint32_t* pCount) {
    if (!pCount) return STATUS_INVALID_PARAMETER;
    *pCount = 1; // 1 Host Bridge at 00:09.0
    return STATUS_SUCCESS;
}

// --- cxlmem.sys (CXL Memory Device & NUMA Node Driver) ---

inline NTSTATUS WINAPI CxlMemGetDeviceInfo(uint32_t deviceId, CxlDeviceInfo* pInfo) {
    if (!pInfo) return STATUS_INVALID_PARAMETER;
    auto& cxl = TitanCxlSubsystem::Instance();
    if (!cxl.isInitialized()) cxl.initialize();
    const auto* dev = cxl.getDevice(deviceId);
    if (!dev) return STATUS_NO_SUCH_DEVICE;
    *pInfo = *dev;
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI CxlMemConfigureHdmDecoder(uint32_t deviceId, uint8_t decoderIdx, uint64_t baseSpa, uint64_t sizeBytes) {
    auto& cxl = TitanCxlSubsystem::Instance();
    if (!cxl.isInitialized()) cxl.initialize();
    return cxl.configureHdmDecoder(deviceId, decoderIdx, baseSpa, sizeBytes) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

inline NTSTATUS WINAPI CxlMemGetSmartHealth(uint32_t deviceId, CxlSmartHealthInfo* pHealth) {
    if (!pHealth) return STATUS_INVALID_PARAMETER;
    auto& cxl = TitanCxlSubsystem::Instance();
    if (!cxl.isInitialized()) cxl.initialize();
    const auto* sh = cxl.getSmartHealth(deviceId);
    if (!sh) return STATUS_NO_SUCH_DEVICE;
    *pHealth = *sh;
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI CxlMemQueryPoisonList(uint32_t deviceId, uint32_t* pCount, CxlPoisonRecord* pRecords) {
    if (!pCount) return STATUS_INVALID_PARAMETER;
    auto& cxl = TitanCxlSubsystem::Instance();
    if (!cxl.isInitialized()) cxl.initialize();
    auto list = cxl.getPoisonList(deviceId);
    if (pRecords && *pCount >= list.size()) {
        std::memcpy(pRecords, list.data(), list.size() * sizeof(CxlPoisonRecord));
    }
    *pCount = static_cast<uint32_t>(list.size());
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI CxlMemInjectPoison(uint32_t deviceId, uint64_t dpa) {
    auto& cxl = TitanCxlSubsystem::Instance();
    if (!cxl.isInitialized()) cxl.initialize();
    return cxl.injectPoison(deviceId, dpa) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

inline NTSTATUS WINAPI CxlMemMigratePages(uint32_t deviceId, uint64_t count, int toFar) {
    auto& cxl = TitanCxlSubsystem::Instance();
    if (!cxl.isInitialized()) cxl.initialize();
    return cxl.migratePages(deviceId, count, toFar != 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// --- cxlbus.sys (CXL Fabric & Bus Enumeration Driver) ---

inline NTSTATUS WINAPI CxlBusRegisterDevice(const CxlDeviceInfo* pInfo, uint32_t* pAssignedId) {
    if (!pInfo) return STATUS_INVALID_PARAMETER;
    auto& cxl = TitanCxlSubsystem::Instance();
    if (!cxl.isInitialized()) cxl.initialize();
    uint32_t id = cxl.registerDevice(*pInfo);
    if (pAssignedId) *pAssignedId = id;
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI CxlBusGetDeviceCount(uint32_t* pCount) {
    if (!pCount) return STATUS_INVALID_PARAMETER;
    auto& cxl = TitanCxlSubsystem::Instance();
    if (!cxl.isInitialized()) cxl.initialize();
    *pCount = static_cast<uint32_t>(cxl.getDeviceCount());
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI CxlBusSendMailboxCommand(uint32_t deviceId, uint16_t opcode,
                                                const void* inBuf, size_t inSize,
                                                void* outBuf, size_t* outSize) {
    auto& cxl = TitanCxlSubsystem::Instance();
    if (!cxl.isInitialized()) cxl.initialize();

    std::vector<uint8_t> inPayload;
    if (inBuf && inSize > 0) {
        inPayload.assign(static_cast<const uint8_t*>(inBuf), static_cast<const uint8_t*>(inBuf) + inSize);
    }

    std::vector<uint8_t> outPayload;
    NTSTATUS st = cxl.sendMailboxCommand(deviceId, opcode, inPayload, outPayload);
    if (st == STATUS_SUCCESS && outBuf && outSize) {
        size_t toCopy = std::min(*outSize, outPayload.size());
        std::memcpy(outBuf, outPayload.data(), toCopy);
        *outSize = outPayload.size();
    }
    return st;
}

} // extern "C"

// ============================================================================
// 5. Subsystem Initialization & Registration
// ============================================================================

inline void InitializeCxlSubsystem() {
    // 0. Ensure Host PCI Bus and Root Ports are Initialized
    pci::InitializePciSubsystem();

    // 1. Initialize Core Subsystem
    TitanCxlSubsystem::Instance().initialize();

    // 2. Register Driver Exports in JanusLDR Dynamic Loader
    auto& ldr = ldr::DynamicLoader::get();

    // cxlhost.sys exports
    ldr.registerExport("cxlhost.sys", "CxlHostInitialize", reinterpret_cast<void*>(CxlHostInitialize));
    ldr.registerExport("cxlhost.sys", "CxlHostGetVersion", reinterpret_cast<void*>(CxlHostGetVersion));
    ldr.registerExport("cxlhost.sys", "CxlHostEnumerateBridges", reinterpret_cast<void*>(CxlHostEnumerateBridges));

    // cxlmem.sys exports
    ldr.registerExport("cxlmem.sys", "CxlMemGetDeviceInfo", reinterpret_cast<void*>(CxlMemGetDeviceInfo));
    ldr.registerExport("cxlmem.sys", "CxlMemConfigureHdmDecoder", reinterpret_cast<void*>(CxlMemConfigureHdmDecoder));
    ldr.registerExport("cxlmem.sys", "CxlMemGetSmartHealth", reinterpret_cast<void*>(CxlMemGetSmartHealth));
    ldr.registerExport("cxlmem.sys", "CxlMemQueryPoisonList", reinterpret_cast<void*>(CxlMemQueryPoisonList));
    ldr.registerExport("cxlmem.sys", "CxlMemInjectPoison", reinterpret_cast<void*>(CxlMemInjectPoison));
    ldr.registerExport("cxlmem.sys", "CxlMemMigratePages", reinterpret_cast<void*>(CxlMemMigratePages));

    // cxlbus.sys exports
    ldr.registerExport("cxlbus.sys", "CxlBusRegisterDevice", reinterpret_cast<void*>(CxlBusRegisterDevice));
    ldr.registerExport("cxlbus.sys", "CxlBusGetDeviceCount", reinterpret_cast<void*>(CxlBusGetDeviceCount));
    ldr.registerExport("cxlbus.sys", "CxlBusSendMailboxCommand", reinterpret_cast<void*>(CxlBusSendMailboxCommand));

    // 3. Register Core Drivers in SCM
    auto cxlHostSvc = std::make_shared<scm::ServiceRecord>();
    cxlHostSvc->serviceName = L"cxlhost";
    cxlHostSvc->displayName = L"Compute Express Link Host Bridge Driver (cxlhost.sys)";
    cxlHostSvc->serviceType = scm::SERVICE_KERNEL_DRIVER;
    cxlHostSvc->startType = scm::SERVICE_BOOT_START;
    cxlHostSvc->errorControl = scm::SERVICE_ERROR_CRITICAL;
    cxlHostSvc->binaryPath = L"C:\\Windows\\System32\\drivers\\cxlhost.sys";
    cxlHostSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    scm::ServiceControlManager::get().registerServiceRecord(cxlHostSvc);

    auto cxlMemSvc = std::make_shared<scm::ServiceRecord>();
    cxlMemSvc->serviceName = L"cxlmem";
    cxlMemSvc->displayName = L"CXL Heterogeneous Memory & NUMA Driver (cxlmem.sys)";
    cxlMemSvc->serviceType = scm::SERVICE_KERNEL_DRIVER;
    cxlMemSvc->startType = scm::SERVICE_BOOT_START;
    cxlMemSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
    cxlMemSvc->binaryPath = L"C:\\Windows\\System32\\drivers\\cxlmem.sys";
    cxlMemSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    scm::ServiceControlManager::get().registerServiceRecord(cxlMemSvc);

    auto cxlBusSvc = std::make_shared<scm::ServiceRecord>();
    cxlBusSvc->serviceName = L"cxlbus";
    cxlBusSvc->displayName = L"CXL Fabric & Bus Enumeration Driver (cxlbus.sys)";
    cxlBusSvc->serviceType = scm::SERVICE_KERNEL_DRIVER;
    cxlBusSvc->startType = scm::SERVICE_SYSTEM_START;
    cxlBusSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
    cxlBusSvc->binaryPath = L"C:\\Windows\\System32\\drivers\\cxlbus.sys";
    cxlBusSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    scm::ServiceControlManager::get().registerServiceRecord(cxlBusSvc);

    // 4. Register Version Database Records
    auto& verDb = version::VersionDatabase::Instance();
    verDb.RegisterModule("cxlhost.sys", "10.0.26100.1", "MicaNT Compute Express Link Host Bridge Driver");
    verDb.RegisterModule("cxlmem.sys", "10.0.26100.1", "MicaNT CXL Heterogeneous Memory & NUMA Driver");
    verDb.RegisterModule("cxlbus.sys", "10.0.26100.1", "MicaNT CXL Fabric & Bus Enumeration Driver");
}

} // namespace micant::cxl
