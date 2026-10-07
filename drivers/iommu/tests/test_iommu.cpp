// ============================================================================
// Standalone Driver Verification Test: iommu (TitanIOMMU / AegisIOMMU)
// Subsystem: Hardware IOMMU (Intel VT-d / AMD-Vi / Arm SMMUv3) & Kernel DMA Protection
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/iommu.hpp"

using namespace micant;

static int g_PassedTests = 0;
static int g_FailedTests = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "  [FAIL] " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            g_FailedTests++; \
            return; \
        } \
    } while (0)

#define RUN_TEST(fn) \
    do { \
        std::cout << "[RUNNING] " << #fn << "...\n" << std::flush; \
        int before = g_FailedTests; \
        fn(); \
        if (g_FailedTests == before) { \
            std::cout << "  [PASS] " << #fn << "\n" << std::flush; \
            g_PassedTests++; \
        } \
    } while (0)

void Test_HardwareIOMMU_VTd_AMDVi_DMA_Remapping_Subsystem() {
    std::cout << "\n--- [Suite 175] Hardware-Accelerated IOMMU (Intel VT-d / AMD-Vi / Arm SMMUv3) Subsystem ---\n";

    auto& iommuSub = micant::iommu::TitanIommuSubsystem::Instance();

    // Stage 1: Hardware Initialization & Capability Enablement
    bool initOk = iommuSub.initialize();
    TEST_ASSERT(initOk, "TitanIOMMU hardware initialization must succeed");
    TEST_ASSERT(iommuSub.isInitialized(), "TitanIOMMU must report initialized state");

    // Stage 2: Protection Domain Lifecycle (Creation & Parameter Validation)
    int32_t dom1Stat = iommuSub.createDomain(1, 48); // 48-bit address width
    TEST_ASSERT(dom1Stat == micant::iommu::STATUS_SUCCESS, "Domain 1 creation must succeed");
    int32_t dom2Stat = iommuSub.createDomain(2, 48);
    TEST_ASSERT(dom2Stat == micant::iommu::STATUS_SUCCESS, "Domain 2 creation must succeed");

    int32_t dupDomStat = iommuSub.createDomain(1, 48);
    TEST_ASSERT(dupDomStat == micant::iommu::STATUS_INVALID_PARAMETER, "Duplicate domain creation must return STATUS_INVALID_PARAMETER");

    const auto& doms = iommuSub.getDomains();
    TEST_ASSERT(doms.find(1) != doms.end(), "Domain 1 must exist in domain map");
    TEST_ASSERT(doms.find(2) != doms.end(), "Domain 2 must exist in domain map");
    TEST_ASSERT(doms.at(1).addressWidth == 48, "Domain 1 address width must be 48 bits");

    // Stage 3: Device Attachment to Protection Domains
    micant::iommu::IommuBdf gpuBdf(1, 0, 0); // Bus 1, Dev 0, Fn 0 (GPU)
    micant::iommu::IommuBdf nicBdf(2, 0, 0); // Bus 2, Dev 0, Fn 0 (100GbE NIC)
    int32_t attachGpu = iommuSub.attachDevice(gpuBdf, 1, false);
    TEST_ASSERT(attachGpu == micant::iommu::STATUS_SUCCESS, "Attaching GPU to Domain 1 must succeed");
    int32_t attachNic = iommuSub.attachDevice(nicBdf, 2, false);
    TEST_ASSERT(attachNic == micant::iommu::STATUS_SUCCESS, "Attaching NIC to Domain 2 must succeed");

    const auto& devMap = iommuSub.getDeviceAssignments();
    TEST_ASSERT(devMap.find(gpuBdf.toRaw()) != devMap.end(), "GPU BDF must be registered in device map");
    TEST_ASSERT(devMap.at(gpuBdf.toRaw()) == 1, "GPU must be mapped to Domain 1");
    TEST_ASSERT(devMap.at(nicBdf.toRaw()) == 2, "NIC must be mapped to Domain 2");

    // Stage 4: Multi-Page DMA Memory Mapping
    // Map 16KB (4 pages) for GPU IOVA 0x10000000 -> Host Phys 0x80000000 (RW)
    int32_t mapGpu = iommuSub.mapDmaRange(1, 0x10000000ULL, 0x80000000ULL, 0x4000, true, true);
    TEST_ASSERT(mapGpu == micant::iommu::STATUS_SUCCESS, "mapDmaRange for Domain 1 (GPU) must succeed");

    // Map 8KB (2 pages) for NIC IOVA 0x20000000 -> Host Phys 0x90000000 (Read-Only)
    int32_t mapNic = iommuSub.mapDmaRange(2, 0x20000000ULL, 0x90000000ULL, 0x2000, true, false);
    TEST_ASSERT(mapNic == micant::iommu::STATUS_SUCCESS, "mapDmaRange for Domain 2 (NIC Read-Only) must succeed");

    // Stage 5: DMAR Hardware DMA Address Translation (Cold Walk / IOTLB Miss)
    uint64_t physAddr1 = 0;
    uint32_t latency1 = 0;
    int32_t transStat1 = iommuSub.translateDma(gpuBdf, 0x10000080ULL, false, &physAddr1, &latency1);
    TEST_ASSERT(transStat1 == micant::iommu::STATUS_SUCCESS, "DMA translation 1 must succeed");
    TEST_ASSERT(physAddr1 == 0x80000080ULL, "Physical address must match 0x80000080");
    TEST_ASSERT(latency1 == 38, "Cold translation latency must be 38 ns (IOMMU hardware page walk)");

    // Stage 6: IOTLB Caching & Accelerated Hit Latency
    uint64_t physAddr2 = 0;
    uint32_t latency2 = 0;
    int32_t transStat2 = iommuSub.translateDma(gpuBdf, 0x10000100ULL, false, &physAddr2, &latency2);
    TEST_ASSERT(transStat2 == micant::iommu::STATUS_SUCCESS, "DMA translation 2 must succeed");
    TEST_ASSERT(physAddr2 == 0x80000100ULL, "Physical address must match 0x80000100");
    TEST_ASSERT(latency2 == 3, "Cached translation latency must be 3 ns (IOTLB hit)");

    // Stage 7: Second-Level Permission Violation Interception
    uint64_t violPhys = 0;
    int32_t violStat = iommuSub.translateDma(nicBdf, 0x20000040ULL, true, &violPhys, nullptr); // Attempt write on read-only domain
    TEST_ASSERT(violStat == micant::iommu::STATUS_ACCESS_VIOLATION, "DMA write to read-only mapping must return STATUS_ACCESS_VIOLATION");

    const auto& faults = iommuSub.getFaultLog();
    TEST_ASSERT(!faults.empty(), "Fault log must record permission violation");
    TEST_ASSERT(faults.back().faultReason == micant::iommu::FAULT_WRITE_PERMISSION_VIOLATION, "Fault reason must be FAULT_WRITE_PERMISSION_VIOLATION");

    // Stage 8: Unmapped Address Translation Fault Interception
    uint64_t unmappedPhys = 0;
    int32_t unmappedStat = iommuSub.translateDma(gpuBdf, 0xDEAD0000ULL, false, &unmappedPhys, nullptr);
    TEST_ASSERT(unmappedStat == micant::iommu::STATUS_ACCESS_VIOLATION, "Translating unmapped IOVA must yield STATUS_ACCESS_VIOLATION");
    TEST_ASSERT(iommuSub.getFaultLog().back().faultReason == micant::iommu::FAULT_UNMAPPED_ADDRESS, "Fault reason must be FAULT_UNMAPPED_ADDRESS");

    // Stage 9: Kernel DMA Protection & Drive-By Attack Blocking
    micant::iommu::IommuBdf rogueThb(5, 0, 0); // Rogue Thunderbolt 4 / USB4 device not attached
    uint64_t roguePhys = 0;
    int32_t rogueStat = iommuSub.translateDma(rogueThb, 0x80000000ULL, true, &roguePhys, nullptr);
    TEST_ASSERT(rogueStat == micant::iommu::STATUS_ACCESS_DENIED, "Unattached DMA device drive-by attack must be blocked with STATUS_ACCESS_DENIED");
    TEST_ASSERT(iommuSub.getFaultLog().back().faultReason == micant::iommu::FAULT_CONTEXT_ENTRY_NOT_PRESENT, "Fault reason must be FAULT_CONTEXT_ENTRY_NOT_PRESENT");
    TEST_ASSERT(iommuSub.getTelemetry().totalMaliciousDmaBlocked >= 1, "Malicious DMA attack counter must be incremented");

    // Stage 10: Device Pass-Through (Identity Mapping) Translation
    micant::iommu::IommuBdf ptDev(3, 0, 0);
    int32_t attachPt = iommuSub.attachDevice(ptDev, 1, true); // Pass-through = true
    TEST_ASSERT(attachPt == micant::iommu::STATUS_SUCCESS, "Attaching pass-through device must succeed");
    uint64_t ptPhys = 0;
    uint32_t ptLat = 0;
    int32_t ptStat = iommuSub.translateDma(ptDev, 0x40001234ULL, false, &ptPhys, &ptLat);
    TEST_ASSERT(ptStat == micant::iommu::STATUS_SUCCESS, "Pass-through DMA translation must succeed");
    TEST_ASSERT(ptPhys == 0x40001234ULL, "Pass-through physical address must match device address (1:1)");
    TEST_ASSERT(ptLat == 1, "Pass-through latency must be 1 ns");

    // Stage 11: Interrupt Remapping Table Entry (IRTE) Registration
    int32_t irte1Stat = iommuSub.registerIrte(10, 0x40, 0, gpuBdf, false, 0);
    TEST_ASSERT(irte1Stat == micant::iommu::STATUS_SUCCESS, "IRTE 10 registration for GPU must succeed");
    int32_t irte2Stat = iommuSub.registerIrte(11, 0x41, 1, nicBdf, false, 0);
    TEST_ASSERT(irte2Stat == micant::iommu::STATUS_SUCCESS, "IRTE 11 registration for NIC must succeed");

    // Stage 12: MSI/MSI-X Interrupt Remapping & Delivery
    uint8_t remapVec = 0;
    uint32_t remapApic = 0;
    int32_t remapStat = iommuSub.remapInterrupt(gpuBdf, 10, &remapVec, &remapApic);
    TEST_ASSERT(remapStat == micant::iommu::STATUS_SUCCESS, "Interrupt remapping for GPU must succeed");
    TEST_ASSERT(remapVec == 0x40, "Remapped interrupt vector must match 0x40");
    TEST_ASSERT(remapApic == 0, "Remapped APIC ID must match CPU 0");

    // Stage 13: Source ID (SID) Spoofing Interception
    uint8_t spoofVec = 0;
    uint32_t spoofApic = 0;
    int32_t spoofStat = iommuSub.remapInterrupt(rogueThb, 10, &spoofVec, &spoofApic); // Rogue device signals GPU's IRTE
    TEST_ASSERT(spoofStat == micant::iommu::STATUS_ACCESS_DENIED, "SID spoofing must be blocked with STATUS_ACCESS_DENIED");
    TEST_ASSERT(iommuSub.getFaultLog().back().faultReason == micant::iommu::FAULT_SID_VERIFICATION_FAILED, "Fault reason must be FAULT_SID_VERIFICATION_FAILED");

    // Stage 14: Posted Interrupts (PIR) Architecture
    int32_t postedStat = iommuSub.registerIrte(12, 0x50, 2, gpuBdf, true, 0xFED00000ULL);
    TEST_ASSERT(postedStat == micant::iommu::STATUS_SUCCESS, "Posted interrupt IRTE registration must succeed");
    uint8_t postVec = 0;
    uint32_t postApic = 0;
    int32_t postRemapStat = iommuSub.remapInterrupt(gpuBdf, 12, &postVec, &postApic);
    TEST_ASSERT(postRemapStat == micant::iommu::STATUS_SUCCESS, "Posted interrupt remapping must succeed");
    TEST_ASSERT(postVec == 0x50, "Posted interrupt vector must match 0x50");
    TEST_ASSERT(postApic == 2, "Posted interrupt APIC ID must match CPU 2");
    TEST_ASSERT(iommuSub.getTelemetry().totalPostedInterrupts >= 1, "Posted interrupts counter must increment");

    // Stage 15: IOTLB Invalidation & Domain Teardown
    int32_t unmapStat = iommuSub.unmapDmaRange(1, 0x10000000ULL, 0x4000);
    TEST_ASSERT(unmapStat == micant::iommu::STATUS_SUCCESS, "unmapDmaRange must succeed");
    uint64_t postUnmapPa = 0;
    int32_t postUnmapStat = iommuSub.translateDma(gpuBdf, 0x10000080ULL, false, &postUnmapPa, nullptr);
    TEST_ASSERT(postUnmapStat == micant::iommu::STATUS_ACCESS_VIOLATION, "Translating unmapped DMA range must fail");

    iommuSub.invalidateIotlbGlobal();
    TEST_ASSERT(iommuSub.getTelemetry().totalIotlbInvalidations >= 2, "totalIotlbInvalidations must be >= 2");

    int32_t detachStat = iommuSub.detachDevice(gpuBdf);
    TEST_ASSERT(detachStat == micant::iommu::STATUS_SUCCESS, "detachDevice must succeed");
    int32_t destroyStat = iommuSub.destroyDomain(1);
    TEST_ASSERT(destroyStat == micant::iommu::STATUS_SUCCESS, "destroyDomain must succeed");
    TEST_ASSERT(iommuSub.getDomains().find(1) == iommuSub.getDomains().end(), "Domain 1 must no longer exist");

    // Stage 16: SCM Boot Drivers, Version Database & C ABI Driver Exports
    auto& scm = micant::scm::ServiceControlManager::get();
    auto dmarSvc = scm.getServiceRecord(L"dmar");
    TEST_ASSERT(dmarSvc != nullptr, "dmar.sys must be registered in SCM");
    TEST_ASSERT(dmarSvc->startType == micant::scm::SERVICE_BOOT_START, "dmar.sys must be Boot start");

    auto iommuSvc = scm.getServiceRecord(L"iommu");
    TEST_ASSERT(iommuSvc != nullptr, "iommu.sys must be registered in SCM");
    TEST_ASSERT(iommuSvc->startType == micant::scm::SERVICE_BOOT_START, "iommu.sys must be Boot start");

    auto kdmaSvc = scm.getServiceRecord(L"kdmapt");
    TEST_ASSERT(kdmaSvc != nullptr, "kdmapt.sys must be registered in SCM");
    TEST_ASSERT(kdmaSvc->startType == micant::scm::SERVICE_SYSTEM_START, "kdmapt.sys must be System start");

    const auto* modDmar = micant::version::VersionDatabase::Instance().GetModuleInfo("dmar.sys");
    TEST_ASSERT(modDmar != nullptr, "dmar.sys must be registered in VersionDatabase");
    TEST_ASSERT(modDmar->stringTable.at("ProductVersion") == "10.0.26100.1", "dmar.sys version must match 10.0.26100.1");

    uint32_t cMajor = 0, cMinor = 0, cBuild = 0;
    int32_t vStat = micant::iommu::IommuGetVersion(&cMajor, &cMinor, &cBuild);
    TEST_ASSERT(vStat == micant::iommu::STATUS_SUCCESS, "IommuGetVersion must succeed");
    TEST_ASSERT(cMajor == 10 && cBuild == 26100, "IOMMU version must match 10.0.26100");

    int32_t cInvStat = micant::iommu::IommuInvalidateIotlbGlobal();
    TEST_ASSERT(cInvStat == micant::iommu::STATUS_SUCCESS, "IommuInvalidateIotlbGlobal C ABI must succeed");

    std::cout << "[TEST] Suite 175: Hardware-Accelerated IOMMU (Intel VT-d / AMD-Vi / Arm SMMUv3) Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Hardware IOMMU (Intel VT-d / AMD-Vi / Arm SMMUv3) & Kernel DMA Protection\n";
    std::cout << "       Codename: TitanIOMMU / AegisIOMMU | Binary: dmar.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_HardwareIOMMU_VTd_AMDVi_DMA_Remapping_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
