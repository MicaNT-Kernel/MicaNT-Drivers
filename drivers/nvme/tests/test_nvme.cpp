// ============================================================================
// Standalone Driver Verification Test: nvme (TitanNVMe / TitanFlash)
// Subsystem: NVM Express (NVMe 1.0-2.0), UFS 4.0 & AHCI Storage Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/nvme.hpp"

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

void Test_NVMExpress_UniversalFlashStorage_Subsystem() {
    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 153: NVM Express (NVMe 1.0-2.0) & Universal Flash Storage       \n";
    std::cout << "========================================================================\n";

    // Initialize Subsystem
    nvme::InitializeNvmeSubsystem();
    auto& flashSub = nvme::TitanFlashSubsystem::Instance();
    auto nvmeCtrl = flashSub.getNvme();
    TEST_ASSERT(nvmeCtrl != nullptr, "NVMe controller must be instantiated in TitanFlash subsystem");

    // Stage 1: Multi-Generation Specification Versioning
    TEST_ASSERT(nvmeCtrl->getVersion() == nvme::NvmeVersion::Version_2_0, "Default NVMe version must be 2.0");
    TEST_ASSERT(nvme::NvmeVersionToString(nvmeCtrl->getVersion()) == "NVMe 2.0d", "Version string must report NVMe 2.0d");
    TEST_ASSERT(nvme::NvmeVersionToString(nvme::NvmeVersion::Version_1_4) == "NVMe 1.4b", "Backward version mapping must support NVMe 1.4b");
    TEST_ASSERT(nvme::NvmeVersionToString(nvme::NvmeVersion::Version_1_3) == "NVMe 1.3d", "Backward version mapping must support NVMe 1.3d");
    TEST_ASSERT(nvme::NvmeVersionToString(nvme::NvmeVersion::Version_1_0) == "NVMe 1.0e", "Backward version mapping must support legacy NVMe 1.0e");

    uint32_t vsReg = nvmeCtrl->readReg32(nvme::NVME_REG_VS);
    TEST_ASSERT(vsReg == static_cast<uint32_t>(nvme::NvmeVersion::Version_2_0), "VS register must match Version 2.0");

    uint32_t capLow = nvmeCtrl->readReg32(nvme::NVME_REG_CAP);
    TEST_ASSERT((capLow & 0xFFFF) == 0x03FF, "CAP.MQES must support 1024 queue entries (1023 0-based)");

    // Stage 2: Controller Reset & Enable Sequence
    win32::BOOL bReset = nvme::NvmeControllerReset();
    TEST_ASSERT(bReset == win32::TRUE, "NvmeControllerReset must succeed");
    TEST_ASSERT(nvmeCtrl->isReady(), "Controller must be in READY state after reset and enable");
    uint32_t csts = nvmeCtrl->readReg32(nvme::NVME_REG_CSTS);
    TEST_ASSERT((csts & nvme::NVME_CSTS_RDY) != 0, "CSTS.RDY bit must be set");

    // Stage 3: Admin Queue Ring Buffers & Phase Toggling
    nvme::NvmeSqe sqePing{};
    sqePing.opcode = nvme::NVME_ADMIN_GET_FEATURES;
    sqePing.commandId = 0x1001;
    nvme::NvmeCqe cqePing{};
    win32::BOOL bPing = nvme::NvmeSubmitAdminCommand(&sqePing, &cqePing, nullptr, 0);
    TEST_ASSERT(bPing == win32::TRUE, "Admin Get Features command must execute");
    TEST_ASSERT(cqePing.commandId == 0x1001, "CQE command ID must echo SQE command ID");
    TEST_ASSERT(cqePing.getPhase() == true, "CQE phase tag must be true");
    TEST_ASSERT(cqePing.getStatusCode() == nvme::NVME_SC_SUCCESS, "CQE status must be SUCCESS");

    // Stage 4: Admin Identify Controller
    nvme::NvmeIdentifyController idCtrl{};
    nvme::NvmeSqe sqeIdCtrl{};
    sqeIdCtrl.opcode = nvme::NVME_ADMIN_IDENTIFY;
    sqeIdCtrl.commandId = 0x1002;
    sqeIdCtrl.cdw10 = nvme::NVME_IDENTIFY_CNS_CTRL;
    nvme::NvmeCqe cqeIdCtrl{};
    win32::BOOL bIdCtrl = nvme::NvmeSubmitAdminCommand(&sqeIdCtrl, &cqeIdCtrl, &idCtrl, sizeof(idCtrl));
    TEST_ASSERT(bIdCtrl == win32::TRUE, "Identify Controller command must succeed");
    TEST_ASSERT(idCtrl.vid == 0x144D, "Controller Vendor ID must match 0x144D");
    TEST_ASSERT(std::string(idCtrl.mn).find("TitanNVMe") != std::string::npos, "Controller Model Number must contain TitanNVMe");
    TEST_ASSERT(idCtrl.ver == static_cast<uint32_t>(nvme::NvmeVersion::Version_2_0), "Controller version must report 2.0");
    TEST_ASSERT(idCtrl.nn >= 2, "Controller must advertise at least 2 active namespaces");

    // Stage 5: Multi-Namespace Architecture (512B vs 4096B 4Kn sectors)
    auto ns1 = nvmeCtrl->getNamespace(1);
    TEST_ASSERT(ns1 != nullptr, "Namespace 1 must exist");
    TEST_ASSERT(ns1->getBlockSize() == 512, "Namespace 1 block size must be 512 bytes");
    TEST_ASSERT(ns1->getTotalBlocks() > 1000000ULL, "Namespace 1 capacity must exceed 1M blocks");

    auto ns2 = nvmeCtrl->getNamespace(2);
    TEST_ASSERT(ns2 != nullptr, "Namespace 2 must exist");
    TEST_ASSERT(ns2->getBlockSize() == 4096, "Namespace 2 block size must be 4096 bytes (4Kn Advanced Format)");

    nvme::NvmeIdentifyNamespace idNs{};
    nvme::NvmeSqe sqeIdNs{};
    sqeIdNs.opcode = nvme::NVME_ADMIN_IDENTIFY;
    sqeIdNs.commandId = 0x1003;
    sqeIdNs.nsid = 1;
    sqeIdNs.cdw10 = nvme::NVME_IDENTIFY_CNS_NS;
    nvme::NvmeCqe cqeIdNs{};
    win32::BOOL bIdNs = nvme::NvmeSubmitAdminCommand(&sqeIdNs, &cqeIdNs, &idNs, sizeof(idNs));
    TEST_ASSERT(bIdNs == win32::TRUE, "Identify Namespace 1 must succeed");
    TEST_ASSERT(idNs.nsze == ns1->getTotalBlocks(), "Identify NSZE must equal namespace block count");
    TEST_ASSERT(idNs.lbaf[0].lbaDataSizeShift == 9, "Format 0 shift must be 9 (512 bytes)");
    TEST_ASSERT(idNs.lbaf[1].lbaDataSizeShift == 12, "Format 1 shift must be 12 (4096 bytes)");

    // Stage 6: Multi-Block NVM Read & Write Operations
    std::vector<uint8_t> payload(1024, 0x5A);
    nvme::NvmeSqe sqeWrite{};
    sqeWrite.opcode = nvme::NVME_NVM_WRITE;
    sqeWrite.commandId = 0x2001;
    sqeWrite.nsid = 1;
    sqeWrite.cdw10 = 500; // SLBA = 500
    sqeWrite.cdw12 = 1;   // NLB = 2 blocks (0-based)
    nvme::NvmeCqe cqeWrite{};
    win32::BOOL bWrite = nvme::NvmeSubmitIoCommand(&sqeWrite, &cqeWrite, payload.data(), 1024);
    TEST_ASSERT(bWrite == win32::TRUE, "NVMe Multi-Block Write must succeed");

    std::vector<uint8_t> readback(1024, 0x00);
    nvme::NvmeSqe sqeRead{};
    sqeRead.opcode = nvme::NVME_NVM_READ;
    sqeRead.commandId = 0x2002;
    sqeRead.nsid = 1;
    sqeRead.cdw10 = 500;
    sqeRead.cdw12 = 1;
    nvme::NvmeCqe cqeRead{};
    win32::BOOL bRead = nvme::NvmeSubmitIoCommand(&sqeRead, &cqeRead, readback.data(), 1024);
    TEST_ASSERT(bRead == win32::TRUE, "NVMe Multi-Block Read must succeed");
    TEST_ASSERT(std::memcmp(payload.data(), readback.data(), 1024) == 0, "Payload data written and read back must match byte-for-byte");

    // Stage 7: Volatile Cache Flush & Write Zeroes Operations
    nvme::NvmeSqe sqeFlush{};
    sqeFlush.opcode = nvme::NVME_NVM_FLUSH;
    sqeFlush.commandId = 0x2003;
    sqeFlush.nsid = 1;
    nvme::NvmeCqe cqeFlush{};
    win32::BOOL bFlush = nvme::NvmeSubmitIoCommand(&sqeFlush, &cqeFlush, nullptr, 0);
    TEST_ASSERT(bFlush == win32::TRUE, "NVMe Flush command must succeed");

    nvme::NvmeSqe sqeZero{};
    sqeZero.opcode = nvme::NVME_NVM_WRITE_ZEROES;
    sqeZero.commandId = 0x2004;
    sqeZero.nsid = 1;
    sqeZero.cdw10 = 500;
    sqeZero.cdw12 = 0; // 1 block
    nvme::NvmeCqe cqeZero{};
    win32::BOOL bZero = nvme::NvmeSubmitIoCommand(&sqeZero, &cqeZero, nullptr, 0);
    TEST_ASSERT(bZero == win32::TRUE, "NVMe Write Zeroes command must succeed");

    std::vector<uint8_t> zeroCheck(512, 0xFF);
    ns1->readBlocks(500, 1, zeroCheck.data());
    bool allZero = true;
    for (uint8_t b : zeroCheck) { if (b != 0) { allZero = false; break; } }
    TEST_ASSERT(allZero, "LBA 500 must contain all zeroes after Write Zeroes command");

    // Stage 8: Dataset Management (TRIM / Deallocate)
    uint8_t dsmData[16]{};
    *reinterpret_cast<uint32_t*>(dsmData + 4) = 5; // 5 blocks
    *reinterpret_cast<uint64_t*>(dsmData + 8) = 500; // SLBA 500
    nvme::NvmeSqe sqeDsm{};
    sqeDsm.opcode = nvme::NVME_NVM_DATASET_MGMT;
    sqeDsm.commandId = 0x2005;
    sqeDsm.nsid = 1;
    sqeDsm.cdw10 = 0; // 1 range (0-based)
    sqeDsm.cdw11 = 0x04; // Attribute: Deallocate
    nvme::NvmeCqe cqeDsm{};
    win32::BOOL bDsm = nvme::NvmeSubmitIoCommand(&sqeDsm, &cqeDsm, dsmData, sizeof(dsmData));
    TEST_ASSERT(bDsm == win32::TRUE, "NVMe Dataset Management (TRIM) must succeed");
    TEST_ASSERT(ns1->isTrimmed(500), "LBA 500 must be marked trimmed");
    TEST_ASSERT(ns1->isTrimmed(504), "LBA 504 must be marked trimmed");

    // Stage 9: S.M.A.R.T. / Health Information Telemetry Log
    nvme::NvmeSmartLog smart{};
    win32::BOOL bSmart = nvme::NvmeGetSmartLog(&smart);
    TEST_ASSERT(bSmart == win32::TRUE, "NvmeGetSmartLog must succeed");
    TEST_ASSERT(smart.compositeTemp > 273, "Temperature must be reported in Kelvin (> 273 K)");
    TEST_ASSERT(smart.availableSpare == 100, "Available spare must report 100% on healthy flash");
    TEST_ASSERT(smart.percentageUsed == 1, "Percentage used wear level must report 1%");
    TEST_ASSERT(smart.hostReadCommands[0] > 0, "Host read command telemetry counter must be greater than zero");
    TEST_ASSERT(smart.hostWriteCommands[0] > 0, "Host write command telemetry counter must be greater than zero");

    // Stage 10: Universal Flash Storage (UFS 3.1 & 4.0) Subsystem
    auto ufs = flashSub.getUfs();
    TEST_ASSERT(ufs != nullptr, "UFS host controller must exist");
    TEST_ASSERT(ufs->getVersion() == 0x00040000, "UFS version must report 4.0 (JESD220F)");
    TEST_ASSERT(ufs->isEnabled(), "UFS host controller must be enabled");
    TEST_ASSERT(ufs->getLunCount() == 2, "UFS must expose 2 LUNs (Boot LUN 0 and Data LUN 1)");
    auto lun0 = ufs->getLun(0);
    TEST_ASSERT(lun0 != nullptr, "UFS LUN 0 must exist");
    TEST_ASSERT(lun0->getBlockSize() == 4096, "UFS LUN 0 block size must be 4096 bytes");

    // Stage 11: eMMC 5.1 & AHCI 1.3.1 SATA SSD with NCQ
    auto emmc = flashSub.getEmmc();
    TEST_ASSERT(emmc != nullptr, "eMMC host controller must exist");
    TEST_ASSERT(emmc->getSpecVersion() == 0x0501, "eMMC specification version must be 5.1");
    auto emmcDev = emmc->getUserPartition();
    TEST_ASSERT(emmcDev != nullptr, "eMMC user partition must be accessible");

    auto ahci = flashSub.getAhci();
    TEST_ASSERT(ahci != nullptr, "AHCI SATA controller must exist");
    TEST_ASSERT(ahci->getVersion() == 0x00010301, "AHCI version must be 1.3.1");
    ahci->submitNcqCommand(7);
    TEST_ASSERT((ahci->getActiveTags() & (1U << 7)) != 0, "NCQ Tag 7 must be marked active");
    ahci->completeNcqCommand(7);
    TEST_ASSERT((ahci->getActiveTags() & (1U << 7)) == 0, "NCQ Tag 7 must be cleared after completion");

    // Stage 12: StorPort Miniport Driver Parity & SCM Registration
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("stornvme.sys", "NvmeControllerReset") != nullptr, "stornvme.sys NvmeControllerReset export must exist");
    TEST_ASSERT(ldr.getExport("stornvme.sys", "NvmeSubmitAdminCommand") != nullptr, "stornvme.sys NvmeSubmitAdminCommand export must exist");
    TEST_ASSERT(ldr.getExport("stornvme.sys", "NvmeSubmitIoCommand") != nullptr, "stornvme.sys NvmeSubmitIoCommand export must exist");
    TEST_ASSERT(ldr.getExport("stornvme.sys", "NvmeGetSmartLog") != nullptr, "stornvme.sys NvmeGetSmartLog export must exist");

    auto nvmeSvc = scm::ServiceControlManager::get().getServiceRecord(L"stornvme");
    TEST_ASSERT(nvmeSvc != nullptr, "stornvme service record must exist in SCM");
    TEST_ASSERT(nvmeSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "stornvme service type must be kernel driver");
    TEST_ASSERT(nvmeSvc->startType == scm::SERVICE_BOOT_START, "stornvme start type must be boot start");

    auto ahciSvc = scm::ServiceControlManager::get().getServiceRecord(L"storahci");
    TEST_ASSERT(ahciSvc != nullptr, "storahci service record must exist in SCM");

    auto ufsSvc = scm::ServiceControlManager::get().getServiceRecord(L"storufs");
    TEST_ASSERT(ufsSvc != nullptr, "storufs service record must exist in SCM");

    auto nvmeVer = version::VersionDatabase::Instance().GetModuleInfo("stornvme.sys");
    TEST_ASSERT(nvmeVer != nullptr, "stornvme.sys must be registered in Version Database");
    TEST_ASSERT(nvmeVer->stringTable.count("FileVersion") > 0, "stornvme.sys FileVersion must exist");

    // Verify PCIe device 02:00.0 integration
    auto pciDev = pci::TitanPciSubsystem::Instance().findDevice(pci::PciAddress(2, 0, 0));
    TEST_ASSERT(pciDev != nullptr, "PCIe device 02:00.0 (TitanNVMe) must exist on PCIe bus");
    TEST_ASSERT(pciDev->getVendorId() == 0x144D, "PCIe device 02:00.0 vendor must match Samsung/Titan NVMe");

    std::cout << "[TEST] Suite 153: NVM Express (NVMe 1.0-2.0) & Universal Flash Storage PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: NVM Express (NVMe 1.0-2.0), UFS 4.0 & AHCI Storage Subsystem\n";
    std::cout << "       Codename: TitanNVMe / TitanFlash | Binary: stornvme.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_NVMExpress_UniversalFlashStorage_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
