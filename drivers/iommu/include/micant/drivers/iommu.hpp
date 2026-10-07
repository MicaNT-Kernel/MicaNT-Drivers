// ============================================================================
// MicaNT Clean-Room Kernel - Hardware-Accelerated I/O Memory Management Unit (IOMMU) Subsystem
// File: include/micant/iommu.hpp
//
// Provenance & Clean-Room Statement:
// Authored strictly from public processor and I/O virtualization specifications:
//   - Intel Virtualization Technology for Directed I/O (VT-d Architecture Rev 3.3):
//     * Chapter 3: Scalable Mode Translation, Root & Context Tables
//     * Chapter 5: Interrupt Remapping & Posted Interrupt Architecture
//     * Chapter 6: Queued Invalidation & IOTLB Caching Architecture
//     * Chapter 7: Fault Reporting Architecture & Primary Fault Logging
//   - AMD I/O Virtualization Technology (AMD-Vi) Architecture Specification Rev 3.0
//   - Arm System Memory Management Unit Architecture Specification (SMMUv3.2)
//   - ACPI 6.5 DMA Remapping Reporting (DMAR) Table Architecture
//   - Microsoft Open Specifications & win32metadata: Windows Kernel DMA Protection
//
// Sovereign Codename: TitanIOMMU / AegisIOMMU
// Strict ISO C++23, zero external dependencies, 100% offline, zero telemetry.
// ============================================================================

#ifndef MICANT_IOMMU_HPP
#define MICANT_IOMMU_HPP

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <map>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include "ntstatus.hpp"
#include "scm.hpp"
#include "version.hpp"

namespace micant::iommu {

// Common NTSTATUS codes
#ifndef STATUS_SUCCESS
constexpr int32_t STATUS_SUCCESS = 0x00000000;
#endif
#ifndef STATUS_UNSUCCESSFUL
constexpr int32_t STATUS_UNSUCCESSFUL = static_cast<int32_t>(0xC0000001);
#endif
#ifndef STATUS_ACCESS_VIOLATION
constexpr int32_t STATUS_ACCESS_VIOLATION = static_cast<int32_t>(0xC0000005);
#endif
#ifndef STATUS_INVALID_PARAMETER
constexpr int32_t STATUS_INVALID_PARAMETER = static_cast<int32_t>(0xC000000D);
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
constexpr int32_t STATUS_BUFFER_TOO_SMALL = static_cast<int32_t>(0xC0000023);
#endif
#ifndef STATUS_DEVICE_NOT_READY
constexpr int32_t STATUS_DEVICE_NOT_READY = static_cast<int32_t>(0xC000010A);
#endif
#ifndef STATUS_NOT_FOUND
constexpr int32_t STATUS_NOT_FOUND = static_cast<int32_t>(0xC0000225);
#endif
#ifndef STATUS_ACCESS_DENIED
constexpr int32_t STATUS_ACCESS_DENIED = static_cast<int32_t>(0xC0000022);
#endif

// ============================================================================
// Intel VT-d Global Command & Status Register Bits
// ============================================================================
constexpr uint32_t GCMD_TE   = 0x80000000; // Translation Enable
constexpr uint32_t GCMD_SRTP = 0x40000000; // Set Root Table Pointer
constexpr uint32_t GCMD_SFL  = 0x20000000; // Set Fault Log
constexpr uint32_t GCMD_EAFL = 0x10000000; // Enable Advanced Fault Logging
constexpr uint32_t GCMD_WBF  = 0x08000000; // Write Buffer Flush
constexpr uint32_t GCMD_QIE  = 0x04000000; // Queued Invalidation Enable
constexpr uint32_t GCMD_IRE  = 0x02000000; // Interrupt Remapping Enable
constexpr uint32_t GCMD_CFI  = 0x01000000; // Compatibility Format Interrupt

constexpr uint32_t GSTS_TES  = 0x80000000; // Translation Enable Status
constexpr uint32_t GSTS_RTPS = 0x40000000; // Root Table Pointer Status
constexpr uint32_t GSTS_FLS  = 0x20000000; // Fault Log Status
constexpr uint32_t GSTS_AFLS = 0x10000000; // Advanced Fault Logging Status
constexpr uint32_t GSTS_WBFS = 0x08000000; // Write Buffer Flush Status
constexpr uint32_t GSTS_QIES = 0x04000000; // Queued Invalidation Enable Status
constexpr uint32_t GSTS_IRES = 0x02000000; // Interrupt Remapping Enable Status
constexpr uint32_t GSTS_CFIS = 0x01000000; // Compatibility Format Interrupt Status

// ============================================================================
// IOMMU Fault Reasons (Intel VT-d Section 7.2)
// ============================================================================
constexpr uint8_t FAULT_ROOT_ENTRY_NOT_PRESENT        = 0x01;
constexpr uint8_t FAULT_CONTEXT_ENTRY_NOT_PRESENT     = 0x02;
constexpr uint8_t FAULT_CONTEXT_ENTRY_INVALID         = 0x03;
constexpr uint8_t FAULT_PAGING_ENTRY_NOT_PRESENT      = 0x04;
constexpr uint8_t FAULT_WRITE_PERMISSION_VIOLATION     = 0x05;
constexpr uint8_t FAULT_READ_PERMISSION_VIOLATION      = 0x06;
constexpr uint8_t FAULT_PAGE_TABLE_RANGE_VIOLATION    = 0x07;
constexpr uint8_t FAULT_ROOT_TABLE_ADDRESS_INVALID    = 0x08;
constexpr uint8_t FAULT_CONTEXT_TABLE_ADDRESS_INVALID = 0x09;
constexpr uint8_t FAULT_UNMAPPED_ADDRESS              = 0x0A;
constexpr uint8_t FAULT_SID_VERIFICATION_FAILED       = 0x20; // IRTE Source ID mismatch
constexpr uint8_t FAULT_IRTE_NOT_PRESENT              = 0x21;

// ============================================================================
// BDF Struct (PCIe Bus:Device.Function)
// ============================================================================
struct IommuBdf {
    uint8_t bus{0};
    uint8_t device{0};
    uint8_t function{0};

    constexpr IommuBdf() = default;
    constexpr IommuBdf(uint8_t b, uint8_t d, uint8_t f)
        : bus(b), device(d & 0x1F), function(f & 0x07) {}

    constexpr uint32_t toRaw() const {
        return (static_cast<uint32_t>(bus) << 8) |
               (static_cast<uint32_t>(device & 0x1F) << 3) |
               (static_cast<uint32_t>(function & 0x07));
    }

    static constexpr IommuBdf fromRaw(uint32_t raw) {
        return IommuBdf(
            static_cast<uint8_t>((raw >> 8) & 0xFF),
            static_cast<uint8_t>((raw >> 3) & 0x1F),
            static_cast<uint8_t>(raw & 0x07)
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
};

// ============================================================================
// IOMMU Protection Domain
// ============================================================================
struct IommuPageMapping {
    uint64_t hostPhysical{0};
    bool readAllowed{true};
    bool writeAllowed{true};
};

struct IommuDomain {
    uint16_t domainId{0};
    uint8_t  addressWidth{48}; // 48-bit (4-level paging) default
    uint64_t pageDirectoryRoot{0}; // SLPTPTR
    std::unordered_map<uint64_t, IommuPageMapping> pageTable; // IOVA (4KB aligned) -> Mapping
    std::vector<IommuBdf> attachedDevices;
};

// ============================================================================
// Interrupt Remapping Table Entry (IRTE - 128 bits)
// ============================================================================
struct InterruptRemappingEntry {
    bool     present{false};
    bool     faultProcessingDisable{false};
    bool     destinationModeLogical{false};
    bool     redirectionHint{false};
    bool     triggerModeLevel{false};
    uint8_t  deliveryMode{0}; // 000b: Fixed
    uint8_t  vector{0};       // Target CPU interrupt vector (32..255)
    uint32_t destinationApicId{0}; // Target CPU Core APIC ID

    // Source Validation (SID)
    uint8_t  sourceValidationType{1}; // 01b: Exact SID match required
    IommuBdf sourceId{};             // Source BDF permitted to signal this IRTE

    // Posted Interrupts
    bool     postedInterrupt{false};
    uint64_t postedDescriptorAddress{0};
};

// ============================================================================
// IOMMU Hardware Unit Fault Record (FRR)
// ============================================================================
struct IommuFaultRecord {
    uint64_t faultAddress{0};
    IommuBdf sourceBdf{};
    uint8_t  faultReason{0};
    bool     isWrite{false};
    uint32_t timestampMs{0};
    std::string description;
};

// ============================================================================
// IOTLB Cache Entry
// ============================================================================
struct IotlbEntry {
    uint16_t domainId{0};
    uint64_t deviceAddressPage{0};
    uint64_t hostPhysicalPage{0};
    bool     readAllowed{true};
    bool     writeAllowed{true};
};

// ============================================================================
// IOMMU Telemetry
// ============================================================================
struct IommuTelemetry {
    uint64_t totalDmaTranslations{0};
    uint64_t iotlbHits{0};
    uint64_t iotlbMisses{0};
    uint64_t totalInterruptsRemapped{0};
    uint64_t totalPostedInterrupts{0};
    uint64_t totalIotlbInvalidations{0};
    uint64_t totalDmaFaultsBlocked{0};
    uint64_t totalMaliciousDmaBlocked{0};
};

// ============================================================================
// TitanIOMMU / AegisIOMMU Core Engine
// ============================================================================
class TitanIommuSubsystem {
private:
    mutable std::mutex m_mutex;
    bool m_initialized{false};

    uint32_t m_globalCommand{0};
    uint32_t m_globalStatus{0};

    std::map<uint16_t, IommuDomain> m_domains;
    std::map<uint32_t, uint16_t>    m_deviceToDomain; // BDF_raw -> domainId
    std::map<uint32_t, bool>        m_passThroughDevices; // BDF_raw -> isPassThrough

    std::array<InterruptRemappingEntry, 256> m_irteTable; // 256 IRTE entries
    std::vector<IotlbEntry>                  m_iotlbCache;
    std::vector<IommuFaultRecord>            m_faultLog;
    IommuTelemetry                           m_telemetry{};

    TitanIommuSubsystem() = default;

public:
    static TitanIommuSubsystem& Instance() {
        static TitanIommuSubsystem s_inst;
        return s_inst;
    }

    bool initialize() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_initialized) return true;

        m_domains.clear();
        m_deviceToDomain.clear();
        m_passThroughDevices.clear();
        m_iotlbCache.clear();
        m_faultLog.clear();
        m_telemetry = {};

        for (auto& irte : m_irteTable) {
            irte = {};
        }

        // Enable Hardware Capabilities: Translation Enable (TE), Interrupt Remap (IRE), Queued Invalidation (QIE)
        m_globalCommand = GCMD_TE | GCMD_IRE | GCMD_QIE | GCMD_SRTP;
        m_globalStatus  = GSTS_TES | GSTS_IRES | GSTS_QIES | GSTS_RTPS;

        // Register SCM Boot Drivers
        auto& scm = micant::scm::ServiceControlManager::get();

        auto dmarSvc = std::make_shared<micant::scm::ServiceRecord>();
        dmarSvc->serviceName = L"dmar";
        dmarSvc->displayName = L"MicaNT DMA Remapping & IOMMU Core Architecture Driver";
        dmarSvc->binaryPath = L"C:\\MicaNT\\System32\\drivers\\dmar.sys";
        dmarSvc->serviceType = micant::scm::SERVICE_KERNEL_DRIVER;
        dmarSvc->startType = micant::scm::SERVICE_BOOT_START;
        dmarSvc->errorControl = micant::scm::SERVICE_ERROR_CRITICAL;
        dmarSvc->status.dwCurrentState = micant::scm::SERVICE_RUNNING;
        scm.registerServiceRecord(dmarSvc);

        auto iommuSvc = std::make_shared<micant::scm::ServiceRecord>();
        iommuSvc->serviceName = L"iommu";
        iommuSvc->displayName = L"MicaNT I/O Memory Management Unit Bus Driver";
        iommuSvc->binaryPath = L"C:\\MicaNT\\System32\\drivers\\iommu.sys";
        iommuSvc->serviceType = micant::scm::SERVICE_KERNEL_DRIVER;
        iommuSvc->startType = micant::scm::SERVICE_BOOT_START;
        iommuSvc->errorControl = micant::scm::SERVICE_ERROR_CRITICAL;
        iommuSvc->status.dwCurrentState = micant::scm::SERVICE_RUNNING;
        scm.registerServiceRecord(iommuSvc);

        auto kdmaSvc = std::make_shared<micant::scm::ServiceRecord>();
        kdmaSvc->serviceName = L"kdmapt";
        kdmaSvc->displayName = L"MicaNT Kernel DMA Protection & Drive-By Interceptor";
        kdmaSvc->binaryPath = L"C:\\MicaNT\\System32\\drivers\\kdmapt.sys";
        kdmaSvc->serviceType = micant::scm::SERVICE_KERNEL_DRIVER;
        kdmaSvc->startType = micant::scm::SERVICE_SYSTEM_START;
        kdmaSvc->errorControl = micant::scm::SERVICE_ERROR_NORMAL;
        kdmaSvc->status.dwCurrentState = micant::scm::SERVICE_RUNNING;
        scm.registerServiceRecord(kdmaSvc);

        // Register with Version Database
        auto& verDb = micant::version::VersionDatabase::Instance();
        verDb.RegisterModule("dmar.sys", "10.0.26100.1", "DMA Remapping & IOMMU Core Driver");
        verDb.RegisterModule("iommu.sys", "10.0.26100.1", "I/O Memory Management Unit Bus Driver");
        verDb.RegisterModule("kdmapt.sys", "10.0.26100.1", "Kernel DMA Protection Filter Driver");

        m_initialized = true;
        return true;
    }

    bool isInitialized() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_initialized;
    }

    // Protection Domain Lifecycle
    int32_t createDomain(uint16_t domainId, uint8_t addressWidth = 48) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;
        if (m_domains.find(domainId) != m_domains.end()) return STATUS_INVALID_PARAMETER;

        IommuDomain domain{};
        domain.domainId = domainId;
        domain.addressWidth = addressWidth;
        domain.pageDirectoryRoot = 0x300000000ULL + (static_cast<uint64_t>(domainId) * 0x10000);

        m_domains[domainId] = std::move(domain);
        return STATUS_SUCCESS;
    }

    int32_t destroyDomain(uint16_t domainId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        auto it = m_domains.find(domainId);
        if (it == m_domains.end()) return STATUS_NOT_FOUND;

        // Detach all attached devices
        for (const auto& bdf : it->second.attachedDevices) {
            m_deviceToDomain.erase(bdf.toRaw());
            m_passThroughDevices.erase(bdf.toRaw());
        }

        // Purge IOTLB for this domain
        m_iotlbCache.erase(std::remove_if(m_iotlbCache.begin(), m_iotlbCache.end(), [domainId](const IotlbEntry& e) {
            return e.domainId == domainId;
        }), m_iotlbCache.end());

        m_domains.erase(it);
        return STATUS_SUCCESS;
    }

    // Attach / Detach Device to Protection Domain
    int32_t attachDevice(IommuBdf bdf, uint16_t domainId, bool isPassThrough = false) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        auto it = m_domains.find(domainId);
        if (it == m_domains.end()) return STATUS_NOT_FOUND;

        uint32_t rawBdf = bdf.toRaw();
        m_deviceToDomain[rawBdf] = domainId;
        m_passThroughDevices[rawBdf] = isPassThrough;
        it->second.attachedDevices.push_back(bdf);

        return STATUS_SUCCESS;
    }

    int32_t detachDevice(IommuBdf bdf) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        uint32_t rawBdf = bdf.toRaw();
        auto devIt = m_deviceToDomain.find(rawBdf);
        if (devIt == m_deviceToDomain.end()) return STATUS_NOT_FOUND;

        uint16_t domainId = devIt->second;
        m_deviceToDomain.erase(devIt);
        m_passThroughDevices.erase(rawBdf);

        auto domIt = m_domains.find(domainId);
        if (domIt != m_domains.end()) {
            auto& devs = domIt->second.attachedDevices;
            devs.erase(std::remove_if(devs.begin(), devs.end(), [rawBdf](const IommuBdf& b) {
                return b.toRaw() == rawBdf;
            }), devs.end());
        }

        return STATUS_SUCCESS;
    }

    // Map DMA range (IOVA -> Host Physical Address)
    int32_t mapDmaRange(uint16_t domainId, uint64_t deviceAddress, uint64_t hostPhysical,
                        size_t sizeBytes, bool readAllowed = true, bool writeAllowed = true) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        auto domIt = m_domains.find(domainId);
        if (domIt == m_domains.end()) return STATUS_NOT_FOUND;

        uint64_t startPage = deviceAddress & ~0xFFFULL;
        uint64_t endPage = (deviceAddress + sizeBytes + 0xFFFULL) & ~0xFFFULL;

        uint64_t currentPhys = hostPhysical & ~0xFFFULL;
        for (uint64_t page = startPage; page < endPage; page += 4096) {
            IommuPageMapping mapping{};
            mapping.hostPhysical = currentPhys;
            mapping.readAllowed = readAllowed;
            mapping.writeAllowed = writeAllowed;

            domIt->second.pageTable[page] = mapping;
            currentPhys += 4096;
        }

        return STATUS_SUCCESS;
    }

    int32_t unmapDmaRange(uint16_t domainId, uint64_t deviceAddress, size_t sizeBytes) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        auto domIt = m_domains.find(domainId);
        if (domIt == m_domains.end()) return STATUS_NOT_FOUND;

        uint64_t startPage = deviceAddress & ~0xFFFULL;
        uint64_t endPage = (deviceAddress + sizeBytes + 0xFFFULL) & ~0xFFFULL;

        for (uint64_t page = startPage; page < endPage; page += 4096) {
            domIt->second.pageTable.erase(page);
        }

        // Flush IOTLB entries for this range
        m_iotlbCache.erase(std::remove_if(m_iotlbCache.begin(), m_iotlbCache.end(), [domainId, startPage, endPage](const IotlbEntry& e) {
            return (e.domainId == domainId) && (e.deviceAddressPage >= startPage && e.deviceAddressPage < endPage);
        }), m_iotlbCache.end());

        m_telemetry.totalIotlbInvalidations++;
        return STATUS_SUCCESS;
    }

    // Hardware DMA Address Translation (DMAR Core Engine)
    int32_t translateDma(IommuBdf bdf, uint64_t deviceAddress, bool isWrite,
                         uint64_t* outHostPhysical, uint32_t* outLatencyNs) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;
        if (!outHostPhysical) return STATUS_INVALID_PARAMETER;

        m_telemetry.totalDmaTranslations++;
        uint32_t rawBdf = bdf.toRaw();

        // 1. Check if device is attached to a Domain
        auto devIt = m_deviceToDomain.find(rawBdf);
        if (devIt == m_deviceToDomain.end()) {
            // Unauthorized DMA Device! Block DMA drive-by attack
            IommuFaultRecord fault{};
            fault.faultAddress = deviceAddress;
            fault.sourceBdf = bdf;
            fault.faultReason = FAULT_CONTEXT_ENTRY_NOT_PRESENT;
            fault.isWrite = isWrite;
            fault.description = "Kernel DMA Protection: Unattached device attempted DMA access";
            m_faultLog.push_back(fault);

            m_telemetry.totalDmaFaultsBlocked++;
            m_telemetry.totalMaliciousDmaBlocked++;
            return STATUS_ACCESS_DENIED;
        }

        // Check Pass-Through Mode
        if (m_passThroughDevices[rawBdf]) {
            *outHostPhysical = deviceAddress;
            if (outLatencyNs) *outLatencyNs = 1; // 1 ns pass-through
            return STATUS_SUCCESS;
        }

        uint16_t domainId = devIt->second;
        uint64_t pageAddress = deviceAddress & ~0xFFFULL;
        uint64_t offsetInPage = deviceAddress & 0xFFFULL;

        // 2. Check IOTLB Cache
        for (const auto& entry : m_iotlbCache) {
            if (entry.domainId == domainId && entry.deviceAddressPage == pageAddress) {
                if (isWrite && !entry.writeAllowed) {
                    IommuFaultRecord fault{};
                    fault.faultAddress = deviceAddress;
                    fault.sourceBdf = bdf;
                    fault.faultReason = FAULT_WRITE_PERMISSION_VIOLATION;
                    fault.isWrite = isWrite;
                    fault.description = "DMA Write permission violation on mapped IOTLB page";
                    m_faultLog.push_back(fault);
                    m_telemetry.totalDmaFaultsBlocked++;
                    return STATUS_ACCESS_VIOLATION;
                }
                *outHostPhysical = entry.hostPhysicalPage + offsetInPage;
                if (outLatencyNs) *outLatencyNs = 3; // 3 ns IOTLB hit
                m_telemetry.iotlbHits++;
                return STATUS_SUCCESS;
            }
        }

        // 3. IOTLB Miss -> Walk IOMMU Second-Level Multi-Tier Page Tables
        m_telemetry.iotlbMisses++;
        auto domIt = m_domains.find(domainId);
        if (domIt == m_domains.end()) return STATUS_NOT_FOUND;

        auto pageIt = domIt->second.pageTable.find(pageAddress);
        if (pageIt == domIt->second.pageTable.end()) {
            // Unmapped DMA Address!
            IommuFaultRecord fault{};
            fault.faultAddress = deviceAddress;
            fault.sourceBdf = bdf;
            fault.faultReason = FAULT_UNMAPPED_ADDRESS;
            fault.isWrite = isWrite;
            fault.description = "DMA Translation Fault: Unmapped Device Address";
            m_faultLog.push_back(fault);

            m_telemetry.totalDmaFaultsBlocked++;
            return STATUS_ACCESS_VIOLATION;
        }

        const auto& mapping = pageIt->second;
        if (isWrite && !mapping.writeAllowed) {
            IommuFaultRecord fault{};
            fault.faultAddress = deviceAddress;
            fault.sourceBdf = bdf;
            fault.faultReason = FAULT_WRITE_PERMISSION_VIOLATION;
            fault.isWrite = isWrite;
            fault.description = "DMA Write denied by second-stage page table permissions";
            m_faultLog.push_back(fault);

            m_telemetry.totalDmaFaultsBlocked++;
            return STATUS_ACCESS_VIOLATION;
        }

        *outHostPhysical = mapping.hostPhysical + offsetInPage;
        if (outLatencyNs) *outLatencyNs = 38; // 38 ns IOMMU hardware page walk

        // 4. Insert into IOTLB cache (FIFO ring, max 512 entries)
        if (m_iotlbCache.size() >= 512) {
            m_iotlbCache.erase(m_iotlbCache.begin());
        }
        IotlbEntry newEntry{};
        newEntry.domainId = domainId;
        newEntry.deviceAddressPage = pageAddress;
        newEntry.hostPhysicalPage = mapping.hostPhysical;
        newEntry.readAllowed = mapping.readAllowed;
        newEntry.writeAllowed = mapping.writeAllowed;
        m_iotlbCache.push_back(newEntry);

        return STATUS_SUCCESS;
    }

    // Register Interrupt Remapping Table Entry (IRTE)
    int32_t registerIrte(uint8_t index, uint8_t vector, uint32_t destApicId,
                         IommuBdf sourceBdf, bool isPosted = false, uint64_t postedDesc = 0) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        InterruptRemappingEntry irte{};
        irte.present = true;
        irte.vector = vector;
        irte.destinationApicId = destApicId;
        irte.sourceValidationType = 1; // Strict SID matching
        irte.sourceId = sourceBdf;
        irte.postedInterrupt = isPosted;
        irte.postedDescriptorAddress = postedDesc;

        m_irteTable[index] = irte;
        return STATUS_SUCCESS;
    }

    // Remap Interrupt (MSI/MSI-X Remapped Format)
    int32_t remapInterrupt(IommuBdf sourceBdf, uint8_t irteIndex, uint8_t* outVector, uint32_t* outApicId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;
        if (!outVector || !outApicId) return STATUS_INVALID_PARAMETER;

        const auto& irte = m_irteTable[irteIndex];
        if (!irte.present) {
            IommuFaultRecord fault{};
            fault.sourceBdf = sourceBdf;
            fault.faultReason = FAULT_IRTE_NOT_PRESENT;
            fault.description = "Interrupt Remapping: IRTE not present";
            m_faultLog.push_back(fault);
            return STATUS_ACCESS_DENIED;
        }

        // Validate Source ID (SID) match
        if (irte.sourceValidationType == 1 && irte.sourceId.toRaw() != sourceBdf.toRaw()) {
            IommuFaultRecord fault{};
            fault.sourceBdf = sourceBdf;
            fault.faultReason = FAULT_SID_VERIFICATION_FAILED;
            fault.description = "Interrupt Remapping: Source ID spoofing detected and blocked";
            m_faultLog.push_back(fault);
            m_telemetry.totalMaliciousDmaBlocked++;
            return STATUS_ACCESS_DENIED;
        }

        *outVector = irte.vector;
        *outApicId = irte.destinationApicId;

        if (irte.postedInterrupt) {
            m_telemetry.totalPostedInterrupts++;
        } else {
            m_telemetry.totalInterruptsRemapped++;
        }

        return STATUS_SUCCESS;
    }

    // Invalidation
    void invalidateIotlbGlobal() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_iotlbCache.clear();
        m_telemetry.totalIotlbInvalidations++;
    }

    // Query Methods
    const std::map<uint16_t, IommuDomain>& getDomains() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_domains;
    }

    const std::map<uint32_t, uint16_t>& getDeviceAssignments() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_deviceToDomain;
    }

    const std::vector<IommuFaultRecord>& getFaultLog() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_faultLog;
    }

    void clearFaultLog() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_faultLog.clear();
    }

    IommuTelemetry getTelemetry() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_telemetry;
    }

    void resetTelemetry() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_telemetry = {};
    }
};

// ============================================================================
// C ABI Driver Interface Exports
// ============================================================================
extern "C" {

inline int32_t IommuTranslateDma(uint8_t bus, uint8_t dev, uint8_t fn, uint64_t devAddr,
                                 int32_t isWrite, uint64_t* outHostPhys, uint32_t* outLatNs) {
    return TitanIommuSubsystem::Instance().translateDma(IommuBdf(bus, dev, fn), devAddr, isWrite != 0, outHostPhys, outLatNs);
}

inline int32_t IommuRemapInterrupt(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t irteIdx,
                                   uint8_t* outVector, uint32_t* outApicId) {
    return TitanIommuSubsystem::Instance().remapInterrupt(IommuBdf(bus, dev, fn), irteIdx, outVector, outApicId);
}

inline int32_t IommuInvalidateIotlbGlobal() {
    TitanIommuSubsystem::Instance().invalidateIotlbGlobal();
    return STATUS_SUCCESS;
}

inline int32_t IommuGetVersion(uint32_t* major, uint32_t* minor, uint32_t* build) {
    if (major) *major = 10;
    if (minor) *minor = 0;
    if (build) *build = 26100;
    return STATUS_SUCCESS;
}

} // extern "C"

} // namespace micant::iommu

#endif // MICANT_IOMMU_HPP
