// ============================================================================
// Standalone Driver Verification Test: sriov (TitanSRIOV / NexusSVA)
// Subsystem: PCIe SR-IOV 1.1, PASID (20-bit) & Shared Virtual Addressing (SVA)
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/sriov.hpp"

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

void Test_PCIeSRIOV_PASID_SharedVirtualAddressing_Subsystem() {
    std::cout << "[TEST] Starting Suite 174: PCIe SR-IOV, PASID & Shared Virtual Addressing (SVA) Subsystem...\n";

    auto& sriovSub = micant::sriov::TitanSriovSubsystem::Instance();

    // Stage 1: Hardware Capabilities & Subsystem Initialization
    bool initOk = sriovSub.initialize();
    TEST_ASSERT(initOk, "TitanSriovSubsystem initialization must succeed");
    TEST_ASSERT(sriovSub.isInitialized(), "Subsystem must report initialized state");

    // Stage 2: Physical Function Registration & SR-IOV Extended Capability Discovery
    micant::sriov::SriovBdf nicBdf(1, 0, 0); // 01:00.0 (Intel E810 100GbE NIC)
    int32_t regStat = sriovSub.registerPhysicalFunction(
        nicBdf, 0x8086, 0x1592, "Intel E810-C 100GbE QSFP28 (TitanNIC)",
        8, 1, 1, 0x1889, 0x10000 // 8 Total VFs, VF Offset 1, VF Stride 1, VF DevID 0x1889, 64KB BAR0
    );
    TEST_ASSERT(regStat == micant::sriov::STATUS_SUCCESS, "registerPhysicalFunction for E810 must succeed");
    const auto& pfs = sriovSub.getPhysicalFunctions();
    TEST_ASSERT(pfs.find(nicBdf.toRaw()) != pfs.end(), "PF 01:00.0 must be registered");
    const auto& nicPf = pfs.at(nicBdf.toRaw());
    TEST_ASSERT(nicPf.sriovCap.capId == micant::sriov::PCI_EXT_CAP_ID_SRIOV, "CapId must be SR-IOV (0x0010)");
    TEST_ASSERT(nicPf.sriovCap.totalVFs == 8, "TotalVFs must be 8");
    TEST_ASSERT(nicPf.sriovCap.numVFs == 0, "Initial numVFs must be 0");

    // Stage 3: Virtual Function BDF Calculation & Offset/Stride Validation
    micant::sriov::SriovBdf gpuBdf(3, 0, 0); // 03:00.0 (NVIDIA H100 Tensor Core GPU)
    int32_t gpuRegStat = sriovSub.registerPhysicalFunction(
        gpuBdf, 0x10DE, 0x2330, "NVIDIA H100 SXM5 80GB (TitanGPU)",
        7, 1, 1, 0x2331, 0x40000 // 7 Total VFs (MIG partitions), 256KB BAR0
    );
    TEST_ASSERT(gpuRegStat == micant::sriov::STATUS_SUCCESS, "registerPhysicalFunction for H100 must succeed");

    // Stage 4: Dynamic Virtual Function Enablement (SR-IOV Control VF Enable)
    int32_t enStat = sriovSub.enableVirtualFunctions(nicBdf, 4);
    TEST_ASSERT(enStat == micant::sriov::STATUS_SUCCESS, "Enabling 4 VFs on E810 must succeed");
    const auto& updatedNicPf = sriovSub.getPhysicalFunctions().at(nicBdf.toRaw());
    TEST_ASSERT(updatedNicPf.sriovCap.numVFs == 4, "Configured numVFs must be 4");
    TEST_ASSERT((updatedNicPf.sriovCap.sriovControl & micant::sriov::SRIOV_CTRL_VF_ENABLE) != 0, "VF_ENABLE control bit must be set");
    TEST_ASSERT(updatedNicPf.virtualFunctions.size() == 4, "PF must hold 4 Virtual Function descriptors");

    // Verify VF BDF addresses
    TEST_ASSERT(updatedNicPf.virtualFunctions[0].bdf.bus == 1 && updatedNicPf.virtualFunctions[0].bdf.function == 1, "VF0 BDF must be 01:00.1");
    TEST_ASSERT(updatedNicPf.virtualFunctions[3].bdf.bus == 1 && updatedNicPf.virtualFunctions[3].bdf.function == 4, "VF3 BDF must be 01:00.4");

    // Stage 5: Out of Range / Exceeding TotalVFs Validation
    int32_t oobStat = sriovSub.enableVirtualFunctions(nicBdf, 16); // TotalVFs is 8
    TEST_ASSERT(oobStat == micant::sriov::STATUS_INVALID_PARAMETER, "Enabling VFs > TotalVFs must fail with STATUS_INVALID_PARAMETER");
    int32_t zeroVfStat = sriovSub.enableVirtualFunctions(nicBdf, 0);
    TEST_ASSERT(zeroVfStat == micant::sriov::STATUS_INVALID_PARAMETER, "Enabling 0 VFs must fail with STATUS_INVALID_PARAMETER");

    // Stage 6: VF Base Address Register (BAR) Partitioning & Sizing
    const auto& vf0 = updatedNicPf.virtualFunctions[0];
    const auto& vf1 = updatedNicPf.virtualFunctions[1];
    TEST_ASSERT(vf0.barAddress[0] == 0xE0000000, "VF0 BAR0 must start at 0xE0000000");
    TEST_ASSERT(vf0.barSize[0] == 0x10000, "VF0 BAR0 size must be 64KB");
    TEST_ASSERT(vf1.barAddress[0] == 0xE0010000, "VF1 BAR0 must start at 0xE0010000");
    TEST_ASSERT(vf1.barSize[0] == 0x10000, "VF1 BAR0 size must be 64KB");

    // Stage 7: Virtual Function Domain Assignment & Function Level Reset (FLR)
    micant::sriov::SriovBdf vf0Bdf = vf0.bdf;
    int32_t assignStat = sriovSub.assignVirtualFunction(vf0Bdf, "Hyper-V Tenant VM-01");
    TEST_ASSERT(assignStat == micant::sriov::STATUS_SUCCESS, "assignVirtualFunction must succeed");
    int32_t resetStat = sriovSub.resetVirtualFunction(vf0Bdf);
    TEST_ASSERT(resetStat == micant::sriov::STATUS_SUCCESS, "Function Level Reset (FLR) on VF0 must succeed");

    // Stage 8: PASID Extended Capability Inspection & Width Validation
    const auto& gpuPf = sriovSub.getPhysicalFunctions().at(gpuBdf.toRaw());
    TEST_ASSERT(gpuPf.pasidCap.capId == micant::sriov::PCI_EXT_CAP_ID_PASID, "PASID Extended Cap ID must match 0x001B");
    TEST_ASSERT(gpuPf.pasidCap.maxPasidWidth == 20, "PASID width must support 20 bits (1,048,576 address spaces)");
    TEST_ASSERT((gpuPf.pasidCap.pasidControl & micant::sriov::PASID_CTRL_ENABLE) != 0, "PASID_CTRL_ENABLE must be active");

    // Stage 9: Process Address Space ID (PASID) Binding (Shared Virtual Addressing / SVA)
    uint32_t testPasid = 42;
    uint32_t testPid = 4096;
    uint64_t cr3Base = 0x2B4000000ULL;
    int32_t bindStat = sriovSub.bindPasid(testPasid, testPid, "pytorch_worker.exe", cr3Base, gpuBdf, true, false);
    TEST_ASSERT(bindStat == micant::sriov::STATUS_SUCCESS, "bindPasid on GPU must succeed");
    const auto& bindings = sriovSub.getPasidBindings();
    auto bindKey = std::make_pair(gpuBdf.toRaw(), testPasid);
    TEST_ASSERT(bindings.find(bindKey) != bindings.end(), "PASID binding must exist in lookup table");
    const auto& bindInfo = bindings.at(bindKey);
    TEST_ASSERT(bindInfo.processId == testPid, "Bound PID must match 4096");
    TEST_ASSERT(bindInfo.cr3DirectoryBase == cr3Base, "CR3 must match 0x2B4000000");

    // Stage 10: PASID Range Checking & Duplicate Rejection
    int32_t dupStat = sriovSub.bindPasid(testPasid, 8192, "other.exe", cr3Base, gpuBdf);
    TEST_ASSERT(dupStat == micant::sriov::STATUS_INVALID_PARAMETER, "Duplicate PASID binding must return STATUS_INVALID_PARAMETER");
    int32_t oobPasidStat = sriovSub.bindPasid(0x00200000, 100, "oob.exe", cr3Base, gpuBdf); // Exceeds 20-bit PASID (0xFFFFF)
    TEST_ASSERT(oobPasidStat == micant::sriov::STATUS_INVALID_PARAMETER, "PASID > 20 bits must fail with STATUS_INVALID_PARAMETER");

    // Stage 11: Address Translation Services (ATS) - IOMMU Translation & Cache Hit
    uint64_t testVa = 0x7FFF00001000ULL; // Pre-mapped page in initialize()
    uint64_t physAddr = 0;
    uint32_t atsLatency = 0;
    // First translation: ATC Miss -> IOMMU page table walk (~45 ns)
    int32_t transStat1 = sriovSub.translateAddress(gpuBdf, testPasid, testVa + 0x120, false, &physAddr, &atsLatency);
    TEST_ASSERT(transStat1 == micant::sriov::STATUS_SUCCESS, "ATS translation 1 must succeed");
    TEST_ASSERT(physAddr == 0x100001120ULL, "Physical address must match 0x100001120");
    TEST_ASSERT(atsLatency == 45, "First access latency must be 45 ns (IOMMU walk)");

    // Second translation: ATC Hit (~4 ns)
    uint64_t cachedPa = 0;
    uint32_t cachedLat = 0;
    int32_t transStat2 = sriovSub.translateAddress(gpuBdf, testPasid, testVa + 0x200, false, &cachedPa, &cachedLat);
    TEST_ASSERT(transStat2 == micant::sriov::STATUS_SUCCESS, "ATS translation 2 must succeed");
    TEST_ASSERT(cachedPa == 0x100001200ULL, "Physical address must match 0x100001200");
    TEST_ASSERT(cachedLat == 4, "Subsequent access must hit ATC cache with 4 ns latency");

    // Stage 12: ATS Address Translation Cache (ATC) Invalidation
    int32_t invStat = sriovSub.invalidateAtsCache(gpuBdf, testPasid, testVa, 4096);
    TEST_ASSERT(invStat == micant::sriov::STATUS_SUCCESS, "invalidateAtsCache must succeed");
    // After invalidation, next translation must be a miss (45 ns)
    uint64_t postInvPa = 0;
    uint32_t postInvLat = 0;
    sriovSub.translateAddress(gpuBdf, testPasid, testVa + 0x120, false, &postInvPa, &postInvLat);
    TEST_ASSERT(postInvLat == 45, "Access after ATC invalidation must incur IOMMU walk (45 ns)");

    // Stage 13: Page Request Interface (PRI / PPR) - Peripheral Page Fault Handling
    uint64_t unmappedVa = 0x7FFF00088000ULL; // Not pre-mapped!
    uint64_t faultPa = 0;
    int32_t faultStat = sriovSub.translateAddress(gpuBdf, testPasid, unmappedVa, false, &faultPa, nullptr);
    TEST_ASSERT(faultStat == micant::sriov::STATUS_PAGE_FAULT, "Translating unmapped VA must yield STATUS_PAGE_FAULT");

    // Device issues Peripheral Page Request (PPR) over PCIe PRI
    micant::sriov::PageRequestPacket priReq{};
    priReq.prgIndex = 10;
    priReq.pasid = testPasid;
    priReq.virtualAddress = unmappedVa;
    priReq.readRequested = true;
    priReq.writeRequested = true;

    micant::sriov::PageResponsePacket priResp{};
    int32_t priStat = sriovSub.handlePageRequest(gpuBdf, priReq, &priResp);
    TEST_ASSERT(priStat == micant::sriov::STATUS_SUCCESS, "handlePageRequest must succeed");
    TEST_ASSERT(priResp.prgIndex == 10, "Response PRG Index must match request (10)");
    TEST_ASSERT(priResp.pasid == testPasid, "Response PASID must match request");
    TEST_ASSERT(priResp.responseCode == micant::sriov::PRG_RESPONSE_SUCCESS, "PRI response code must be SUCCESS (0)");
    TEST_ASSERT(priResp.latencyNs == 350, "PRI OS page-in latency must be 350 ns");

    // Stage 14: Translation Success Post-PRI Resolution
    uint64_t resolvedPa = 0;
    int32_t postPriStat = sriovSub.translateAddress(gpuBdf, testPasid, unmappedVa, false, &resolvedPa, nullptr);
    TEST_ASSERT(postPriStat == micant::sriov::STATUS_SUCCESS, "Translation after PRI demand page-in must succeed");
    TEST_ASSERT(resolvedPa >= 0x200000000ULL, "Resolved physical address must be in demand-paged range >= 0x200000000");

    // Stage 15: Monotonic Telemetry Verification
    const auto& telem = sriovSub.getTelemetry();
    TEST_ASSERT(telem.totalPfRegistered >= 2, "totalPfRegistered must be >= 2");
    TEST_ASSERT(telem.totalVfsEnabled >= 4, "totalVfsEnabled must be >= 4");
    TEST_ASSERT(telem.totalVfResets >= 1, "totalVfResets must be >= 1");
    TEST_ASSERT(telem.totalPasidBindings >= 1, "totalPasidBindings must be >= 1");
    TEST_ASSERT(telem.totalAtsTranslations >= 4, "totalAtsTranslations must be >= 4");
    TEST_ASSERT(telem.totalAtsHits >= 1, "totalAtsHits must be >= 1");
    TEST_ASSERT(telem.totalAtsMisses >= 3, "totalAtsMisses must be >= 3");
    TEST_ASSERT(telem.totalPriPageFaults >= 1, "totalPriPageFaults must be >= 1");
    TEST_ASSERT(telem.totalPriResponsesSent >= 1, "totalPriResponsesSent must be >= 1");

    // Stage 16: SCM Boot Driver Registration & Version Database Audit
    auto& scm = micant::scm::ServiceControlManager::get();
    auto sriovSvc = scm.getServiceRecord(L"pci_sriov");
    TEST_ASSERT(sriovSvc != nullptr, "pci_sriov.sys must be registered in SCM");
    TEST_ASSERT(sriovSvc->startType == micant::scm::SERVICE_BOOT_START, "pci_sriov must be Boot start");

    auto svaSvc = scm.getServiceRecord(L"pcie_sva");
    TEST_ASSERT(svaSvc != nullptr, "pcie_sva.sys must be registered in SCM");
    TEST_ASSERT(svaSvc->startType == micant::scm::SERVICE_SYSTEM_START, "pcie_sva must be System start");

    const auto* modSriov = micant::version::VersionDatabase::Instance().GetModuleInfo("pci_sriov.sys");
    TEST_ASSERT(modSriov != nullptr, "pci_sriov.sys must be registered in VersionDatabase");
    TEST_ASSERT(modSriov->stringTable.at("ProductVersion") == "10.0.26100.1", "pci_sriov.sys version must match 10.0.26100.1");

    // C ABI Driver Exports
    uint32_t cMajor = 0, cMinor = 0, cBuild = 0;
    int32_t vStat = micant::sriov::SriovGetVersion(&cMajor, &cMinor, &cBuild);
    TEST_ASSERT(vStat == micant::sriov::STATUS_SUCCESS, "SriovGetVersion must succeed");
    TEST_ASSERT(cMajor == 10 && cBuild == 26100, "SR-IOV version must match 10.0.26100");

    // C ABI SRIOV enable/disable test
    int32_t cAbiEnStat = micant::sriov::SriovEnableVirtualFunctions(1, 0, 0, 2);
    TEST_ASSERT(cAbiEnStat == micant::sriov::STATUS_SUCCESS, "SriovEnableVirtualFunctions C ABI must succeed");
    int32_t cAbiDisStat = micant::sriov::SriovDisableVirtualFunctions(1, 0, 0);
    TEST_ASSERT(cAbiDisStat == micant::sriov::STATUS_SUCCESS, "SriovDisableVirtualFunctions C ABI must succeed");

    std::cout << "[TEST] Suite 174: PCIe SR-IOV, PASID & Shared Virtual Addressing Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: PCIe SR-IOV 1.1, PASID (20-bit) & Shared Virtual Addressing (SVA)\n";
    std::cout << "       Codename: TitanSRIOV / NexusSVA | Binary: pci_sriov.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_PCIeSRIOV_PASID_SharedVirtualAddressing_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
