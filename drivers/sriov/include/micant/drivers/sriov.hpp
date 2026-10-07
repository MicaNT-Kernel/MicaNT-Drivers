// ============================================================================
// MicaNT Clean-Room Kernel - PCIe SR-IOV, PASID & Shared Virtual Addressing (SVA) Subsystem
// File: include/micant/sriov.hpp
//
// Provenance & Clean-Room Statement:
// Authored strictly from public PCIe, IOMMU, and virtualization standards:
//   - PCI-SIG Single Root I/O Virtualization and Sharing Specification (SR-IOV Rev 1.1)
//   - PCI Express Base Specification Revision 5.0/6.0:
//     * Section 6.13: Address Translation Services (ATS)
//     * Section 6.14: Page Request Interface (PRI / PRS)
//     * Section 6.20: Process Address Space ID (PASID) Extended Capability
//     * Section 7.8: Access Control Services (ACS) & SR-IOV Extended Capability
//   - Intel Virtualization Technology for Directed I/O (VT-d Architecture Rev 3.3):
//     * Scalable Mode Translation, First-Stage / Second-Stage Page Tables
//     * PASID Table Entry format & Page Request Queue architecture
//   - Arm System Memory Management Unit Architecture Specification (SMMUv3.2):
//     * Stream Table & Context Descriptors (CD), SubstreamID / PASID support
//   - Microsoft Open Specifications & WDK:
//     * PCI_EXPRESS_SRIOV_CAPABILITY_REGISTER_V1, PCI_EXPRESS_PASID_CAPABILITY_REGISTER
//     * IO_STACK_LOCATION, IRP_MN_READ_CONFIG / WRITE_CONFIG, SR-IOV Bus Driver
//
// Sovereign Codename: TitanSRIOV / NexusSVA
// Strict ISO C++23, zero external dependencies, 100% offline, zero telemetry.
// ============================================================================

#ifndef MICANT_SRIOV_HPP
#define MICANT_SRIOV_HPP

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

namespace micant::sriov {

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
#ifndef STATUS_INSUFFICIENT_RESOURCES
constexpr int32_t STATUS_INSUFFICIENT_RESOURCES = static_cast<int32_t>(0xC000009A);
#endif
#ifndef STATUS_DEVICE_NOT_READY
constexpr int32_t STATUS_DEVICE_NOT_READY = static_cast<int32_t>(0xC000010A);
#endif
#ifndef STATUS_NOT_FOUND
constexpr int32_t STATUS_NOT_FOUND = static_cast<int32_t>(0xC0000225);
#endif
#ifndef STATUS_PAGE_FAULT
constexpr int32_t STATUS_PAGE_FAULT = static_cast<int32_t>(0xC0000006);
#endif

// ============================================================================
// PCIe Extended Capability IDs
// ============================================================================
constexpr uint16_t PCI_EXT_CAP_ID_SRIOV = 0x0010;
constexpr uint16_t PCI_EXT_CAP_ID_ATS   = 0x000F;
constexpr uint16_t PCI_EXT_CAP_ID_PRI   = 0x0013;
constexpr uint16_t PCI_EXT_CAP_ID_PASID = 0x001B;
constexpr uint16_t PCI_EXT_CAP_ID_ACS   = 0x000D;

// SR-IOV Control Bits
constexpr uint16_t SRIOV_CTRL_VF_ENABLE               = 0x0001;
constexpr uint16_t SRIOV_CTRL_VF_MSE                  = 0x0002; // Memory Space Enable
constexpr uint16_t SRIOV_CTRL_ARI_CAPABLE_HIERARCHY   = 0x0010;

// PASID Capabilities & Control Bits
constexpr uint16_t PASID_CAP_EXEC_PERMISSION          = 0x0002;
constexpr uint16_t PASID_CAP_PRIVILEGED_MODE          = 0x0004;
constexpr uint16_t PASID_CTRL_ENABLE                  = 0x0001;
constexpr uint16_t PASID_CTRL_EXEC_PERM_ENABLE        = 0x0002;
constexpr uint16_t PASID_CTRL_PRIV_MODE_ENABLE        = 0x0004;
constexpr uint32_t PASID_MAX_VALUE                    = 0x000FFFFF; // 20-bit PASID (1,048,576)

// ATS Capabilities & Control Bits
constexpr uint16_t ATS_CTRL_ENABLE                    = 0x8000;

// PRI Status Bits & Response Codes
constexpr uint16_t PRI_CTRL_ENABLE                    = 0x0001;
constexpr uint16_t PRI_CTRL_RESET                     = 0x0002;
constexpr uint16_t PRI_STATUS_RESP_FAILURE            = 0x0001;
constexpr uint16_t PRI_STATUS_UNEXPECTED_COMPLETION   = 0x0002;
constexpr uint16_t PRI_STATUS_STOPPED                 = 0x0100;

constexpr uint8_t  PRG_RESPONSE_SUCCESS               = 0;
constexpr uint8_t  PRG_RESPONSE_INVALID_REQUEST       = 1;
constexpr uint8_t  PRG_RESPONSE_FAILURE               = 2;

// ============================================================================
// Helper PCIe BDF Struct
// ============================================================================
struct SriovBdf {
    uint8_t bus{0};
    uint8_t device{0};
    uint8_t function{0};

    constexpr SriovBdf() = default;
    constexpr SriovBdf(uint8_t b, uint8_t d, uint8_t f)
        : bus(b), device(d & 0x1F), function(f & 0x07) {}

    constexpr uint32_t toRaw() const {
        return (static_cast<uint32_t>(bus) << 8) |
               (static_cast<uint32_t>(device & 0x1F) << 3) |
               (static_cast<uint32_t>(function & 0x07));
    }

    static constexpr SriovBdf fromRaw(uint32_t raw) {
        return SriovBdf(
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
// SR-IOV Extended Capability Header (PCI-SIG SR-IOV Rev 1.1)
// ============================================================================
struct SriovCapability {
    uint16_t capId{PCI_EXT_CAP_ID_SRIOV};
    uint8_t  capVersion{1};
    uint16_t nextCapOffset{0};

    uint32_t sriovCapabilities{0};
    uint16_t sriovControl{0};
    uint16_t sriovStatus{0};

    uint16_t initialVFs{0};
    uint16_t totalVFs{0};
    uint16_t numVFs{0};
    uint8_t  functionDependencyLink{0};

    uint16_t vfFirstOffset{0};
    uint16_t vfFunctionStride{1};
    uint16_t vfDeviceId{0};

    uint32_t supportedPageSizes{0x00000555}; // 4KB, 8KB, 64KB, 256KB, 1MB, 4MB, 16MB
    uint32_t systemPageSize{0x00000001};    // 4KB default

    std::array<uint32_t, 6> vfBarBase{0, 0, 0, 0, 0, 0};
    std::array<uint32_t, 6> vfBarSize{0, 0, 0, 0, 0, 0};
};

// ============================================================================
// PASID Extended Capability Header (PCIe Base Spec 5.0 Section 6.20)
// ============================================================================
struct PasidCapability {
    uint16_t capId{PCI_EXT_CAP_ID_PASID};
    uint8_t  capVersion{1};
    uint16_t nextCapOffset{0};

    uint16_t pasidCapabilities{PASID_CAP_EXEC_PERMISSION | PASID_CAP_PRIVILEGED_MODE};
    uint16_t pasidControl{PASID_CTRL_ENABLE | PASID_CTRL_EXEC_PERM_ENABLE | PASID_CTRL_PRIV_MODE_ENABLE};
    uint8_t  maxPasidWidth{20}; // Up to 20 bits
};

// ============================================================================
// Virtual Function Descriptor
// ============================================================================
struct VirtualFunction {
    uint16_t vfIndex{0};
    SriovBdf bdf{};
    SriovBdf pfBdf{};
    uint16_t deviceId{0};
    bool     enabled{false};
    bool     assigned{false};
    std::string assignedDomain{"Host/Unassigned"};
    std::array<uint64_t, 6> barAddress{0, 0, 0, 0, 0, 0};
    std::array<uint32_t, 6> barSize{0, 0, 0, 0, 0, 0};
    bool     flrPending{false};
    uint64_t totalTransactions{0};
};

// ============================================================================
// PASID Process Address Space Binding Context (SVA / SVM)
// ============================================================================
struct PasidBinding {
    uint32_t pasid{0};
    uint32_t processId{0};
    std::string processName;
    uint64_t cr3DirectoryBase{0}; // Host page table root (CR3 / TTBR0)
    SriovBdf targetBdf{};
    bool executePermission{true};
    bool privilegedMode{false};
    bool active{true};
    uint64_t translationsCached{0};
    uint64_t pageFaultsHandled{0};
};

// ============================================================================
// Peripheral Page Request Packet (PCIe PRI / PPR)
// ============================================================================
struct PageRequestPacket {
    uint16_t prgIndex{0};     // Page Request Group Index
    uint32_t pasid{0};
    uint64_t virtualAddress{0};
    bool readRequested{true};
    bool writeRequested{false};
    bool executeRequested{false};
    bool privilegedRequested{false};
};

struct PageResponsePacket {
    uint16_t prgIndex{0};
    uint32_t pasid{0};
    uint8_t  responseCode{PRG_RESPONSE_SUCCESS};
    uint32_t latencyNs{0};
};

// ============================================================================
// Address Translation Cache (ATC) Entry for ATS
// ============================================================================
struct AtcCacheEntry {
    uint32_t pasid{0};
    uint64_t virtualPage{0};
    uint64_t physicalPage{0};
    bool readAllowed{true};
    bool writeAllowed{true};
    bool executeAllowed{false};
    bool privileged{false};
};

// ============================================================================
// Physical Function Descriptor
// ============================================================================
struct PhysicalFunction {
    SriovBdf bdf{};
    uint16_t vendorId{0};
    uint16_t deviceId{0};
    std::string deviceName;

    SriovCapability sriovCap{};
    PasidCapability pasidCap{};

    bool atsEnabled{true};
    bool priEnabled{true};
    uint16_t maxOutstandingPrg{64};

    std::vector<VirtualFunction> virtualFunctions;
    std::vector<AtcCacheEntry>   atcCache;
};

// ============================================================================
// Subsystem Telemetry
// ============================================================================
struct SriovTelemetry {
    uint64_t totalPfRegistered{0};
    uint64_t totalVfsEnabled{0};
    uint64_t totalVfsDisabled{0};
    uint64_t totalVfResets{0};
    uint64_t totalPasidBindings{0};
    uint64_t totalPasidUnbindings{0};
    uint64_t totalAtsTranslations{0};
    uint64_t totalAtsHits{0};
    uint64_t totalAtsMisses{0};
    uint64_t totalPriPageFaults{0};
    uint64_t totalPriResponsesSent{0};
};

// ============================================================================
// TitanSRIOV / NexusSVA Subsystem Core Implementation
// ============================================================================
class TitanSriovSubsystem {
private:
    mutable std::mutex m_mutex;
    bool m_initialized{false};
    std::map<uint32_t, PhysicalFunction> m_pfs;
    std::map<std::pair<uint32_t, uint32_t>, PasidBinding> m_pasidBindings; // <BDF_raw, PASID> -> Binding
    std::unordered_map<uint64_t, uint64_t> m_virtualToPhysicalMemory; // Simulated host memory mappings: VA -> PA
    SriovTelemetry m_telemetry{};

    TitanSriovSubsystem() = default;

public:
    static TitanSriovSubsystem& Instance() {
        static TitanSriovSubsystem s_inst;
        return s_inst;
    }

    bool initialize() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_initialized) return true;

        m_pfs.clear();
        m_pasidBindings.clear();
        m_virtualToPhysicalMemory.clear();
        m_telemetry = {};

        // Pre-populate some simulated page mappings (VA -> PA)
        for (uint64_t page = 0; page < 64; ++page) {
            uint64_t va = 0x7FFF00000000ULL + (page * 4096);
            uint64_t pa = 0x100000000ULL + (page * 4096);
            m_virtualToPhysicalMemory[va] = pa;
        }

        // Register SCM boot driver records
        auto& scm = micant::scm::ServiceControlManager::get();

        auto sriovSvc = std::make_shared<micant::scm::ServiceRecord>();
        sriovSvc->serviceName = L"pci_sriov";
        sriovSvc->displayName = L"MicaNT PCIe Single Root I/O Virtualization (SR-IOV) Bus Filter Driver";
        sriovSvc->binaryPath = L"C:\\MicaNT\\System32\\drivers\\pci_sriov.sys";
        sriovSvc->serviceType = micant::scm::SERVICE_KERNEL_DRIVER;
        sriovSvc->startType = micant::scm::SERVICE_BOOT_START;
        sriovSvc->errorControl = micant::scm::SERVICE_ERROR_CRITICAL;
        sriovSvc->status.dwCurrentState = micant::scm::SERVICE_RUNNING;
        scm.registerServiceRecord(sriovSvc);

        auto svaSvc = std::make_shared<micant::scm::ServiceRecord>();
        svaSvc->serviceName = L"pcie_sva";
        svaSvc->displayName = L"MicaNT PCIe Shared Virtual Addressing (SVA/SVM) & PASID Driver";
        svaSvc->binaryPath = L"C:\\MicaNT\\System32\\drivers\\pcie_sva.sys";
        svaSvc->serviceType = micant::scm::SERVICE_KERNEL_DRIVER;
        svaSvc->startType = micant::scm::SERVICE_SYSTEM_START;
        svaSvc->errorControl = micant::scm::SERVICE_ERROR_NORMAL;
        svaSvc->status.dwCurrentState = micant::scm::SERVICE_RUNNING;
        scm.registerServiceRecord(svaSvc);

        // Register with Version Database
        auto& verDb = micant::version::VersionDatabase::Instance();
        verDb.RegisterModule("pci_sriov.sys", "10.0.26100.1", "PCIe SR-IOV Bus Filter Driver");
        verDb.RegisterModule("pcie_sva.sys", "10.0.26100.1", "PCIe Shared Virtual Addressing Driver");

        m_initialized = true;
        return true;
    }

    bool isInitialized() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_initialized;
    }

    // Register a Physical Function with SR-IOV & PASID capabilities
    int32_t registerPhysicalFunction(SriovBdf bdf, uint16_t vendorId, uint16_t deviceId,
                                     const std::string& name, uint16_t totalVFs,
                                     uint16_t vfFirstOffset, uint16_t vfStride,
                                     uint16_t vfDeviceId, uint32_t vfBar0Size = 0x10000) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;
        if (totalVFs == 0 || vfStride == 0) return STATUS_INVALID_PARAMETER;

        uint32_t rawBdf = bdf.toRaw();
        PhysicalFunction pf{};
        pf.bdf = bdf;
        pf.vendorId = vendorId;
        pf.deviceId = deviceId;
        pf.deviceName = name;

        pf.sriovCap.capId = PCI_EXT_CAP_ID_SRIOV;
        pf.sriovCap.initialVFs = totalVFs;
        pf.sriovCap.totalVFs = totalVFs;
        pf.sriovCap.numVFs = 0;
        pf.sriovCap.vfFirstOffset = vfFirstOffset;
        pf.sriovCap.vfFunctionStride = vfStride;
        pf.sriovCap.vfDeviceId = vfDeviceId;
        pf.sriovCap.vfBarBase[0] = 0xE0000000;
        pf.sriovCap.vfBarSize[0] = vfBar0Size;

        pf.pasidCap.capId = PCI_EXT_CAP_ID_PASID;
        pf.pasidCap.pasidCapabilities = PASID_CAP_EXEC_PERMISSION | PASID_CAP_PRIVILEGED_MODE;
        pf.pasidCap.pasidControl = PASID_CTRL_ENABLE | PASID_CTRL_EXEC_PERM_ENABLE | PASID_CTRL_PRIV_MODE_ENABLE;
        pf.pasidCap.maxPasidWidth = 20;

        m_pfs[rawBdf] = std::move(pf);
        m_telemetry.totalPfRegistered++;
        return STATUS_SUCCESS;
    }

    // Enable Virtual Functions on a target Physical Function
    int32_t enableVirtualFunctions(SriovBdf pfBdf, uint16_t numVFs) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        uint32_t rawBdf = pfBdf.toRaw();
        auto it = m_pfs.find(rawBdf);
        if (it == m_pfs.end()) return STATUS_NOT_FOUND;

        PhysicalFunction& pf = it->second;
        if (numVFs == 0 || numVFs > pf.sriovCap.totalVFs) {
            return STATUS_INVALID_PARAMETER;
        }

        pf.virtualFunctions.clear();
        pf.virtualFunctions.reserve(numVFs);

        for (uint16_t i = 0; i < numVFs; ++i) {
            VirtualFunction vf{};
            vf.vfIndex = i;
            vf.pfBdf = pfBdf;
            vf.deviceId = pf.sriovCap.vfDeviceId;

            // Calculate VF BDF using PCI-SIG SR-IOV arithmetic:
            // VF_BDF = PF_BDF + First_VF_Offset + (VF_Index * VF_Stride)
            uint32_t vfRaw = rawBdf + pf.sriovCap.vfFirstOffset + (i * pf.sriovCap.vfFunctionStride);
            vf.bdf = SriovBdf::fromRaw(vfRaw);
            vf.enabled = true;
            vf.assigned = false;

            // Allocate VF BAR addresses
            uint64_t bar0Base = static_cast<uint64_t>(pf.sriovCap.vfBarBase[0]) + (static_cast<uint64_t>(i) * pf.sriovCap.vfBarSize[0]);
            vf.barAddress[0] = bar0Base;
            vf.barSize[0] = pf.sriovCap.vfBarSize[0];

            pf.virtualFunctions.push_back(vf);
        }

        pf.sriovCap.numVFs = numVFs;
        pf.sriovCap.sriovControl |= SRIOV_CTRL_VF_ENABLE | SRIOV_CTRL_VF_MSE;
        m_telemetry.totalVfsEnabled += numVFs;
        return STATUS_SUCCESS;
    }

    // Disable Virtual Functions on a target Physical Function
    int32_t disableVirtualFunctions(SriovBdf pfBdf) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        uint32_t rawBdf = pfBdf.toRaw();
        auto it = m_pfs.find(rawBdf);
        if (it == m_pfs.end()) return STATUS_NOT_FOUND;

        PhysicalFunction& pf = it->second;
        uint16_t vfsRemoved = static_cast<uint16_t>(pf.virtualFunctions.size());
        pf.virtualFunctions.clear();
        pf.sriovCap.numVFs = 0;
        pf.sriovCap.sriovControl &= ~(SRIOV_CTRL_VF_ENABLE | SRIOV_CTRL_VF_MSE);

        m_telemetry.totalVfsDisabled += vfsRemoved;
        return STATUS_SUCCESS;
    }

    // Function Level Reset (FLR) on a Virtual Function
    int32_t resetVirtualFunction(SriovBdf vfBdf) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        uint32_t rawVfBdf = vfBdf.toRaw();
        for (auto& [rawPf, pf] : m_pfs) {
            for (auto& vf : pf.virtualFunctions) {
                if (vf.bdf.toRaw() == rawVfBdf) {
                    vf.flrPending = true;
                    vf.totalTransactions = 0;
                    vf.flrPending = false;
                    m_telemetry.totalVfResets++;
                    return STATUS_SUCCESS;
                }
            }
        }
        return STATUS_NOT_FOUND;
    }

    // Assign Virtual Function to a VM or Tenant
    int32_t assignVirtualFunction(SriovBdf vfBdf, const std::string& domain) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        uint32_t rawVfBdf = vfBdf.toRaw();
        for (auto& [rawPf, pf] : m_pfs) {
            for (auto& vf : pf.virtualFunctions) {
                if (vf.bdf.toRaw() == rawVfBdf) {
                    vf.assigned = true;
                    vf.assignedDomain = domain;
                    return STATUS_SUCCESS;
                }
            }
        }
        return STATUS_NOT_FOUND;
    }

    // Bind Process Address Space ID (PASID) for Shared Virtual Addressing (SVA)
    int32_t bindPasid(uint32_t pasid, uint32_t pid, const std::string& procName,
                      uint64_t cr3, SriovBdf targetBdf, bool execPerm = true, bool privMode = false) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;
        if (pasid > PASID_MAX_VALUE) return STATUS_INVALID_PARAMETER;
        if (cr3 == 0) return STATUS_INVALID_PARAMETER;

        uint32_t rawBdf = targetBdf.toRaw();
        auto key = std::make_pair(rawBdf, pasid);
        if (m_pasidBindings.find(key) != m_pasidBindings.end()) {
            return STATUS_INVALID_PARAMETER; // Already bound
        }

        PasidBinding binding{};
        binding.pasid = pasid;
        binding.processId = pid;
        binding.processName = procName;
        binding.cr3DirectoryBase = cr3;
        binding.targetBdf = targetBdf;
        binding.executePermission = execPerm;
        binding.privilegedMode = privMode;
        binding.active = true;

        m_pasidBindings[key] = binding;
        m_telemetry.totalPasidBindings++;
        return STATUS_SUCCESS;
    }

    // Unbind PASID
    int32_t unbindPasid(uint32_t pasid, SriovBdf targetBdf) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        uint32_t rawBdf = targetBdf.toRaw();
        auto key = std::make_pair(rawBdf, pasid);
        auto it = m_pasidBindings.find(key);
        if (it == m_pasidBindings.end()) return STATUS_NOT_FOUND;

        m_pasidBindings.erase(it);

        // Purge ATC cache for this PASID on the target device
        auto pfIt = m_pfs.find(rawBdf);
        if (pfIt != m_pfs.end()) {
            auto& atc = pfIt->second.atcCache;
            atc.erase(std::remove_if(atc.begin(), atc.end(), [pasid](const AtcCacheEntry& e) {
                return e.pasid == pasid;
            }), atc.end());
        }

        m_telemetry.totalPasidUnbindings++;
        return STATUS_SUCCESS;
    }

    // Address Translation Services (ATS): translates Virtual Address to Physical Address
    int32_t translateAddress(SriovBdf bdf, uint32_t pasid, uint64_t virtualAddress,
                             bool isWrite, uint64_t* outPhysAddress, uint32_t* outLatencyNs) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;
        if (!outPhysAddress) return STATUS_INVALID_PARAMETER;

        uint32_t rawBdf = bdf.toRaw();
        auto key = std::make_pair(rawBdf, pasid);
        auto bindIt = m_pasidBindings.find(key);
        if (bindIt == m_pasidBindings.end()) {
            return STATUS_NOT_FOUND;
        }

        m_telemetry.totalAtsTranslations++;
        uint64_t pageVa = virtualAddress & ~0xFFFULL;
        uint64_t pageOffset = virtualAddress & 0xFFFULL;

        // Check Device ATC Cache
        auto pfIt = m_pfs.find(rawBdf);
        if (pfIt != m_pfs.end()) {
            for (const auto& entry : pfIt->second.atcCache) {
                if (entry.pasid == pasid && entry.virtualPage == pageVa) {
                    if (isWrite && !entry.writeAllowed) return STATUS_ACCESS_VIOLATION;
                    *outPhysAddress = entry.physicalPage + pageOffset;
                    if (outLatencyNs) *outLatencyNs = 4; // 4 ns ATC cache hit latency
                    m_telemetry.totalAtsHits++;
                    bindIt->second.translationsCached++;
                    return STATUS_SUCCESS;
                }
            }
        }

        // Cache Miss: Perform IOMMU translation against host page tables
        m_telemetry.totalAtsMisses++;
        auto memIt = m_virtualToPhysicalMemory.find(pageVa);
        if (memIt == m_virtualToPhysicalMemory.end()) {
            // Unmapped page -> Requires PRI Page Request
            return STATUS_PAGE_FAULT;
        }

        uint64_t pa = memIt->second + pageOffset;
        *outPhysAddress = pa;
        if (outLatencyNs) *outLatencyNs = 45; // 45 ns IOMMU walk latency

        // Insert into ATC cache (max 256 entries per device)
        if (pfIt != m_pfs.end()) {
            if (pfIt->second.atcCache.size() >= 256) {
                pfIt->second.atcCache.erase(pfIt->second.atcCache.begin());
            }
            AtcCacheEntry newEntry{};
            newEntry.pasid = pasid;
            newEntry.virtualPage = pageVa;
            newEntry.physicalPage = memIt->second;
            newEntry.readAllowed = true;
            newEntry.writeAllowed = true;
            newEntry.executeAllowed = bindIt->second.executePermission;
            newEntry.privileged = bindIt->second.privilegedMode;
            pfIt->second.atcCache.push_back(newEntry);
        }

        bindIt->second.translationsCached++;
        return STATUS_SUCCESS;
    }

    // Page Request Interface (PRI / PRS): Handle Device Peripheral Page Request (PPR)
    int32_t handlePageRequest(SriovBdf bdf, const PageRequestPacket& request, PageResponsePacket* outResponse) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;
        if (!outResponse) return STATUS_INVALID_PARAMETER;

        m_telemetry.totalPriPageFaults++;
        uint32_t rawBdf = bdf.toRaw();
        auto key = std::make_pair(rawBdf, request.pasid);
        auto bindIt = m_pasidBindings.find(key);

        outResponse->prgIndex = request.prgIndex;
        outResponse->pasid = request.pasid;

        if (bindIt == m_pasidBindings.end()) {
            outResponse->responseCode = PRG_RESPONSE_INVALID_REQUEST;
            outResponse->latencyNs = 120;
            m_telemetry.totalPriResponsesSent++;
            return STATUS_NOT_FOUND;
        }

        uint64_t pageVa = request.virtualAddress & ~0xFFFULL;

        // Demand page simulation: Allocate backing physical memory for faulting page
        if (m_virtualToPhysicalMemory.find(pageVa) == m_virtualToPhysicalMemory.end()) {
            // Allocate new 4KB physical page
            uint64_t newPa = 0x200000000ULL + (m_virtualToPhysicalMemory.size() * 4096);
            m_virtualToPhysicalMemory[pageVa] = newPa;
        }

        bindIt->second.pageFaultsHandled++;
        outResponse->responseCode = PRG_RESPONSE_SUCCESS;
        outResponse->latencyNs = 350; // 350 ns OS page-in resolution latency
        m_telemetry.totalPriResponsesSent++;

        return STATUS_SUCCESS;
    }

    // Invalidate ATS Cache (ATC Purge)
    int32_t invalidateAtsCache(SriovBdf bdf, uint32_t pasid, uint64_t virtualAddress, size_t sizeBytes) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return STATUS_DEVICE_NOT_READY;

        uint32_t rawBdf = bdf.toRaw();
        auto pfIt = m_pfs.find(rawBdf);
        if (pfIt == m_pfs.end()) return STATUS_NOT_FOUND;

        uint64_t startPage = virtualAddress & ~0xFFFULL;
        uint64_t endPage = (virtualAddress + sizeBytes + 0xFFFULL) & ~0xFFFULL;

        auto& atc = pfIt->second.atcCache;
        atc.erase(std::remove_if(atc.begin(), atc.end(), [pasid, startPage, endPage](const AtcCacheEntry& e) {
            return (e.pasid == pasid) && (e.virtualPage >= startPage && e.virtualPage < endPage);
        }), atc.end());

        return STATUS_SUCCESS;
    }

    // Query physical functions
    const std::map<uint32_t, PhysicalFunction>& getPhysicalFunctions() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pfs;
    }

    // Query PASID bindings
    const std::map<std::pair<uint32_t, uint32_t>, PasidBinding>& getPasidBindings() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pasidBindings;
    }

    // Query Telemetry
    SriovTelemetry getTelemetry() const {
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

inline int32_t SriovEnableVirtualFunctions(uint8_t bus, uint8_t dev, uint8_t fn, uint16_t numVFs) {
    return TitanSriovSubsystem::Instance().enableVirtualFunctions(SriovBdf(bus, dev, fn), numVFs);
}

inline int32_t SriovDisableVirtualFunctions(uint8_t bus, uint8_t dev, uint8_t fn) {
    return TitanSriovSubsystem::Instance().disableVirtualFunctions(SriovBdf(bus, dev, fn));
}

inline int32_t SriovBindProcessAddressSpace(uint32_t pasid, uint32_t pid, const char* procName,
                                            uint64_t cr3, uint8_t bus, uint8_t dev, uint8_t fn) {
    std::string name = procName ? procName : "Unknown";
    return TitanSriovSubsystem::Instance().bindPasid(pasid, pid, name, cr3, SriovBdf(bus, dev, fn));
}

inline int32_t SriovUnbindProcessAddressSpace(uint32_t pasid, uint8_t bus, uint8_t dev, uint8_t fn) {
    return TitanSriovSubsystem::Instance().unbindPasid(pasid, SriovBdf(bus, dev, fn));
}

inline int32_t SriovTranslateAddress(uint8_t bus, uint8_t dev, uint8_t fn, uint32_t pasid,
                                     uint64_t va, int32_t isWrite, uint64_t* outPa, uint32_t* outLat) {
    return TitanSriovSubsystem::Instance().translateAddress(SriovBdf(bus, dev, fn), pasid, va, isWrite != 0, outPa, outLat);
}

inline int32_t SriovGetVersion(uint32_t* major, uint32_t* minor, uint32_t* build) {
    if (major) *major = 10;
    if (minor) *minor = 0;
    if (build) *build = 26100;
    return STATUS_SUCCESS;
}

} // extern "C"

} // namespace micant::sriov

#endif // MICANT_SRIOV_HPP
