// ============================================================================
// Standalone Driver Verification Test: pci (TitanPCI / NexusPCI)
// Subsystem: PCI Express (PCIe 5.0/6.0) Bus, Root Complex & AER Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/pci.hpp"

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

void Test_PCIExpress_PCIe_Bus_Subsystem() {
    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 152: PCI Express (PCIe 5.0) Bus, Root Complex & AER Subsystem    \n";
    std::cout << "========================================================================\n";

    // Initialize Subsystem
    pci::InitializePciSubsystem();
    auto& pciSub = pci::TitanPciSubsystem::Instance();

    // Stage 1: PCI Configuration Space Header & Address Decoding
    pci::PciAddress addrGpu(1, 0, 0);
    TEST_ASSERT(addrGpu.bus == 1 && addrGpu.device == 0 && addrGpu.function == 0, "PciAddress BDF components must match");
    TEST_ASSERT(addrGpu.toBdf() == 0x0100, "BDF packing must equal 0x0100");
    TEST_ASSERT(pci::PciAddress::fromBdf(0x0100) == addrGpu, "BDF unpacking must recover original address");
    TEST_ASSERT(addrGpu.toString() == "01:00.0", "PciAddress toString formatting must match");

    auto gpu = pciSub.findDevice(addrGpu);
    TEST_ASSERT(gpu != nullptr, "PrismX GPU device 01:00.0 must be registered in PCI subsystem");
    TEST_ASSERT(gpu->getVendorId() == 0x10DE, "GPU Vendor ID must be NVIDIA/Sovereign 0x10DE");
    TEST_ASSERT(gpu->getDeviceId() == 0x2684, "GPU Device ID must be 0x2684");
    TEST_ASSERT(gpu->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Display), "GPU Base Class must be Display (0x03)");
    TEST_ASSERT(gpu->getHeaderType() == pci::PCI_HEADER_TYPE_NORMAL, "GPU Header Type must be Type 0 Normal Endpoint");

    // Stage 2: Base Address Register (BAR) Dynamic Sizing & Probing
    // BAR0: 16MB 32-bit Memory
    const auto& bar0 = gpu->getBar(0);
    TEST_ASSERT(bar0.type == pci::PciBarType::Memory32, "GPU BAR0 must be Memory32");
    TEST_ASSERT(bar0.size == 16 * 1024 * 1024, "GPU BAR0 size must be 16MB");
    TEST_ASSERT(!bar0.prefetchable, "GPU BAR0 control MMIO must not be prefetchable");

    // Simulate OS sizing probe on BAR0: write 0xFFFFFFFF, read back inverted size mask
    uint32_t origBar0 = gpu->readBar(0);
    gpu->writeBar(0, 0xFFFFFFFF);
    uint32_t maskBar0 = gpu->readBar(0);
    TEST_ASSERT((maskBar0 & 0xFF000000) == 0xFF000000, "BAR0 size probe mask must reflect 16MB boundary");
    gpu->writeBar(0, origBar0);

    // BAR1: 16GB 64-bit Memory Prefetchable
    const auto& bar1 = gpu->getBar(1);
    TEST_ASSERT(bar1.type == pci::PciBarType::Memory64, "GPU BAR1 must be Memory64");
    TEST_ASSERT(bar1.size == 16ULL * 1024 * 1024 * 1024, "GPU BAR1 size must be 16GB VRAM");
    TEST_ASSERT(bar1.prefetchable, "GPU BAR1 VRAM must be prefetchable");

    // BAR3: I/O Space (128 bytes)
    const auto& bar3 = gpu->getBar(3);
    TEST_ASSERT(bar3.type == pci::PciBarType::IoSpace, "GPU BAR3 must be I/O Space");
    TEST_ASSERT(bar3.size == 128, "GPU BAR3 size must be 128 bytes");
    TEST_ASSERT((bar3.toRawLow() & 0x01) == 0x01, "I/O BAR must have bit 0 set to 1");

    // Stage 3: Multi-Bus Topology Enumeration & Device Discovery
    TEST_ASSERT(pciSub.getBusCount() >= 4, "PCI subsystem must manage at least 4 active buses (Buses 0..3)");
    auto allDevs = pciSub.getAllDevices();
    TEST_ASSERT(allDevs.size() >= 8, "PCI subsystem must discover at least 8 endpoints and bridges");

    // Verify Root Complex Host Bridge (00:00.0)
    auto hostBridge = pciSub.findDevice(pci::PciAddress(0, 0, 0));
    TEST_ASSERT(hostBridge != nullptr, "Host Bridge at 00:00.0 must exist");
    TEST_ASSERT(hostBridge->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Bridge), "Host Bridge class must be Bridge");

    // Verify PCIe Root Port 1 (00:01.0 -> Bus 1)
    auto rp1 = pciSub.findDevice(pci::PciAddress(0, 1, 0));
    TEST_ASSERT(rp1 != nullptr && rp1->isBridge(), "Root Port 1 at 00:01.0 must be a Type 1 Bridge");
    TEST_ASSERT(rp1->readConfigByte(pci::PCI_CONFIG_SECONDARY_BUS) == 1, "Root Port 1 secondary bus must be 1");

    // Stage 4: Standard Capability Linked-List Traversal
    uint8_t capPtr = gpu->readConfigByte(pci::PCI_CONFIG_CAPABILITIES_PTR);
    TEST_ASSERT(capPtr > 0, "Capabilities pointer at 0x34 must be non-zero");

    bool foundPcieCap = false;
    bool foundMsixCap = false;
    uint8_t currCap = capPtr;
    int maxHops = 16;
    while (currCap != 0 && maxHops-- > 0) {
        uint8_t capId = gpu->readConfigByte(currCap);
        if (capId == pci::PCI_CAP_ID_EXP) foundPcieCap = true;
        if (capId == pci::PCI_CAP_ID_MSIX) foundMsixCap = true;
        currCap = gpu->readConfigByte(currCap + 1);
    }
    TEST_ASSERT(foundPcieCap, "PCI Express Capability (0x10) must be discovered in linked list");
    TEST_ASSERT(foundMsixCap, "MSI-X Capability (0x11) must be discovered in linked list");

    // Stage 5: PCI Express Capability Structure & Link Negotiation
    TEST_ASSERT(gpu->hasPcieCap(), "GPU must report PCIe Capability");
    TEST_ASSERT(gpu->getLinkSpeed() == pci::PciLinkSpeed::Gen5_32_0GT, "PrismX GPU must negotiate PCIe Gen 5 (32 GT/s)");
    TEST_ASSERT(gpu->getLinkWidth() == pci::PciLinkWidth::x16, "PrismX GPU must negotiate PCIe x16 link width");
    TEST_ASSERT(gpu->getLinkSpeedString() == "Gen 5 (32.0 GT/s)", "Link speed string formatting must match");
    TEST_ASSERT(gpu->getLinkWidthString() == "x16", "Link width string formatting must match");

    // Stage 6: Message Signaled Interrupts (MSI) Configuration
    auto xhciDev = pciSub.findDevice(pci::PciAddress(3, 0, 0));
    TEST_ASSERT(xhciDev != nullptr, "TitanUSB xHCI controller 03:00.0 must exist");
    const auto& msi = xhciDev->getMsi();
    TEST_ASSERT(msi.offset > 0, "TitanUSB xHCI must support MSI capability");
    TEST_ASSERT(msi.multiMessageCapable == 3, "TitanUSB xHCI must support 8 MSI vectors (2^3)");

    win32::BOOL bMsiCfg = pci::PciConfigureMsi(xhciDev->getAddress().toBdf(), 0xFEE00000ULL, 0x60, 3);
    TEST_ASSERT(bMsiCfg == win32::TRUE, "PciConfigureMsi must succeed for xHCI");
    TEST_ASSERT(xhciDev->getMsi().enabled, "MSI must be enabled after configuration");
    TEST_ASSERT(xhciDev->getMsi().messageAddress == 0xFEE00000ULL, "MSI target address must match");

    // Stage 7: MSI-X Architecture & Table Programming
    auto nvmeDev = pciSub.findDevice(pci::PciAddress(2, 0, 0));
    TEST_ASSERT(nvmeDev != nullptr, "TitanNVMe controller 02:00.0 must exist");
    const auto& msix = nvmeDev->getMsix();
    TEST_ASSERT(msix.offset > 0, "TitanNVMe must support MSI-X capability");
    TEST_ASSERT(msix.tableSize == 64, "TitanNVMe MSI-X table must have 64 vectors");

    // Program MSI-X Vector 0 (Unmasked)
    win32::BOOL bMsixCfg0 = pci::PciConfigureMsix(nvmeDev->getAddress().toBdf(), 0, 0xFEE00000ULL, 0x40, win32::FALSE);
    TEST_ASSERT(bMsixCfg0 == win32::TRUE, "PciConfigureMsix for vector 0 must succeed");
    TEST_ASSERT(nvmeDev->getMsix().enabled, "MSI-X must be enabled");

    // Trigger Vector 0 -> should deliver immediately
    win32::BOOL bDelivered = pci::PciTriggerMsiVector(nvmeDev->getAddress().toBdf(), 0);
    TEST_ASSERT(bDelivered == win32::TRUE, "Unmasked MSI-X vector trigger must deliver immediately");

    // Program MSI-X Vector 1 (Masked)
    win32::BOOL bMsixCfg1 = pci::PciConfigureMsix(nvmeDev->getAddress().toBdf(), 1, 0xFEE00000ULL, 0x41, win32::TRUE);
    TEST_ASSERT(bMsixCfg1 == win32::TRUE, "PciConfigureMsix for vector 1 must succeed");
    win32::BOOL bMaskedTrig = pci::PciTriggerMsiVector(nvmeDev->getAddress().toBdf(), 1);
    TEST_ASSERT(bMaskedTrig == win32::FALSE, "Masked MSI-X vector trigger must not deliver immediately");
    TEST_ASSERT((nvmeDev->getMsix().pbaBits[0] & 0x02) != 0, "MSI-X PBA bit 1 must be set for pending interrupt");

    // Stage 8: PCIe Extended Capabilities Linked-List Traversal (offset >= 0x100)
    TEST_ASSERT(gpu->getAer().offset >= 0x100, "AER extended capability offset must be >= 0x100 in 4KB config space");
    TEST_ASSERT(gpu->readConfigWord(gpu->getAer().offset) == pci::PCIE_EXT_CAP_ID_AER, "Extended capability ID at offset must be AER (0x0001)");

    // Stage 9: Advanced Error Reporting (AER) Logging & Severity Classification
    uint32_t bdfGpu = gpu->getAddress().toBdf();
    pci::PciInjectAerError(bdfGpu, pci::aer::AER_CORR_BAD_TLP, win32::FALSE, win32::FALSE);
    TEST_ASSERT((gpu->getAer().corrStatus & pci::aer::AER_CORR_BAD_TLP) != 0, "AER correctable Bad TLP status must be recorded");
    TEST_ASSERT(gpu->getAer().totalCorrectableErrors == 1, "Total correctable error count must be 1");

    pci::PciInjectAerError(bdfGpu, pci::aer::AER_UNCORR_POISONED_TLP, win32::TRUE, win32::TRUE);
    TEST_ASSERT((gpu->getAer().uncorrStatus & pci::aer::AER_UNCORR_POISONED_TLP) != 0, "AER uncorrectable Poisoned TLP must be recorded");
    TEST_ASSERT((gpu->getAer().uncorrSeverity & pci::aer::AER_UNCORR_POISONED_TLP) != 0, "AER error severity must be marked Fatal");
    TEST_ASSERT(gpu->getAer().totalFatalErrors == 1, "Total fatal error count must be 1");

    win32::BOOL bAerClr = pci::PciClearAerStatus(bdfGpu);
    TEST_ASSERT(bAerClr == win32::TRUE, "PciClearAerStatus must succeed");
    TEST_ASSERT(gpu->getAer().uncorrStatus == 0, "AER uncorrectable status must be zero after clear");
    TEST_ASSERT(gpu->getAer().corrStatus == 0, "AER correctable status must be zero after clear");

    // Stage 10: Single Root I/O Virtualization (SR-IOV) Metadata & Simulation
    auto nicDev = pciSub.findDevice(pci::PciAddress(0, 4, 0));
    TEST_ASSERT(nicDev != nullptr, "RazzleNet 10GbE controller 00:04.0 must exist");
    nicDev->addSriovCapability(0x200, 64, 0x1565);
    const auto& sriov = nicDev->getSriov();
    TEST_ASSERT(sriov.offset == 0x200, "SR-IOV capability offset must match");
    TEST_ASSERT(sriov.totalVfs == 64, "SR-IOV total VFs must be 64");
    TEST_ASSERT(sriov.vfDeviceId == 0x1565, "SR-IOV VF Device ID must match");

    // Stage 11: Dynamic Loader Module Exports in pci.sys
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("pci.sys", "PciReadConfigByte") != nullptr, "pci.sys PciReadConfigByte export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciReadConfigDword") != nullptr, "pci.sys PciReadConfigDword export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciWriteConfigDword") != nullptr, "pci.sys PciWriteConfigDword export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciFindDevice") != nullptr, "pci.sys PciFindDevice export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciGetBarInfo") != nullptr, "pci.sys PciGetBarInfo export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciEnableBusMastering") != nullptr, "pci.sys PciEnableBusMastering export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciConfigureMsi") != nullptr, "pci.sys PciConfigureMsi export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciConfigureMsix") != nullptr, "pci.sys PciConfigureMsix export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciTriggerMsiVector") != nullptr, "pci.sys PciTriggerMsiVector export must be registered");
    TEST_ASSERT(ldr.getExport("pci.sys", "PciInjectAerError") != nullptr, "pci.sys PciInjectAerError export must be registered");

    // Stage 12: System Services & Driver Registration
    auto pciSvc = scm::ServiceControlManager::get().getServiceRecord(L"pci");
    TEST_ASSERT(pciSvc != nullptr, "pci service record must exist in SCM");
    TEST_ASSERT(pciSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "pci service type must be kernel driver");
    TEST_ASSERT(pciSvc->startType == scm::SERVICE_BOOT_START, "pci service start type must be boot start");

    auto pciVer = version::VersionDatabase::Instance().GetModuleInfo("pci.sys");
    TEST_ASSERT(pciVer != nullptr, "pci.sys must be registered in Version Database");
    TEST_ASSERT(pciVer->stringTable.count("FileVersion") > 0, "pci.sys FileVersion must exist");

    std::cout << "[TEST] Suite 152: PCI Express (PCIe 5.0) Bus, Root Complex & AER Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: PCI Express (PCIe 5.0/6.0) Bus, Root Complex & AER Subsystem\n";
    std::cout << "       Codename: TitanPCI / NexusPCI | Binary: pci.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_PCIExpress_PCIe_Bus_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
