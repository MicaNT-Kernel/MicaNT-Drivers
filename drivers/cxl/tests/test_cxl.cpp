// ============================================================================
// Standalone Driver Verification Test: cxl (TitanCXL / NexusCXL)
// Subsystem: Compute Express Link (CXL 2.0 / 3.1) Heterogeneous Memory Fabric
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/cxl.hpp"

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

void Test_ComputeExpressLink_CXL_HeterogeneousMemory_Subsystem() {
    std::cout << "[TEST] Starting Suite 162: Compute Express Link (CXL 2.0 / 3.1) & Heterogeneous Memory Fabric...\n";

    // Initialize Subsystem & Register Components
    pci::InitializePciSubsystem();
    cxl::InitializeCxlSubsystem();
    auto& cxlSub = cxl::TitanCxlSubsystem::Instance();
    TEST_ASSERT(cxlSub.isInitialized() == true, "TitanCXL subsystem must be initialized");

    // Stage 1: CXL Specification Version Verification (Revision 3.1)
    uint32_t cxlMaj = 0, cxlMin = 0;
    cxlSub.getVersion(&cxlMaj, &cxlMin);
    TEST_ASSERT(cxlMaj == 3 && cxlMin == 1, "CXL specification version must be 3.1");

    // Stage 2: CXL Host Bridge & Root Port on PCIe Bus 0 (00:09.0)
    auto pciDev = pci::TitanPciSubsystem::Instance().findDevice(pci::PciAddress(0, 9, 0));
    TEST_ASSERT(pciDev != nullptr, "TitanCXL Host Bridge must be registered at 00:09.0");
    TEST_ASSERT(pciDev->getVendorId() == 0x1E98, "CXL Host Bridge Vendor ID must be 0x1E98 (CXL Consortium)");
    TEST_ASSERT(pciDev->getDeviceId() == 0x0001, "CXL Host Bridge Device ID must be 0x0001 (CXL 3.1 Host Bridge)");
    TEST_ASSERT(pciDev->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Bridge), "Base class must be Bridge (0x06)");
    TEST_ASSERT(pciDev->getSubClass() == 0x04, "Subclass must be PCI-to-PCI Bridge (0x04)");

    // Stage 3: CXL Host Bridge BAR0 MMIO Component Registers
    const auto& bar0 = pciDev->getBar(0);
    TEST_ASSERT(bar0.type == pci::PciBarType::Memory64, "BAR0 must be 64-bit MMIO");
    TEST_ASSERT(bar0.size == 64 * 1024, "BAR0 Component Register size must be 64 KB");

    // Stage 4: CXL Bus 4 Endpoint Enumeration & Type Identification
    auto memDev = pci::TitanPciSubsystem::Instance().findDevice(pci::PciAddress(4, 0, 0));
    TEST_ASSERT(memDev != nullptr, "TitanCXL Type 3 Memory Expander must be registered at 04:00.0");
    TEST_ASSERT(memDev->getVendorId() == 0x1E98, "Type 3 Memory Expander Vendor ID must be 0x1E98");
    TEST_ASSERT(memDev->getDeviceId() == 0x0010, "Type 3 Memory Expander Device ID must be 0x0010");
    TEST_ASSERT(memDev->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Memory), "Base class must be Memory (0x05)");

    auto accDev = pci::TitanPciSubsystem::Instance().findDevice(pci::PciAddress(4, 1, 0));
    TEST_ASSERT(accDev != nullptr, "TitanCXL Type 2 Heterogeneous Accelerator must be registered at 04:01.0");
    TEST_ASSERT(accDev->getVendorId() == 0x1E98, "Type 2 Accelerator Vendor ID must be 0x1E98");
    TEST_ASSERT(accDev->getDeviceId() == 0x0020, "Type 2 Accelerator Device ID must be 0x0020");
    TEST_ASSERT(accDev->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::Accelerator), "Base class must be Accelerator (0x12)");

    // Stage 5: CXL Sub-Protocols Negotiation
    const auto* dev1Info = cxlSub.getDevice(1);
    TEST_ASSERT(dev1Info != nullptr, "Device 1 lookup must succeed");
    TEST_ASSERT(dev1Info->type == cxl::CxlDeviceType::Type3_MemoryExpander, "Device 1 must be Type 3 Memory Expander");
    TEST_ASSERT(dev1Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlIo), "Device 1 must support CXL.io");
    TEST_ASSERT(dev1Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlMem), "Device 1 must support CXL.mem");
    TEST_ASSERT(!(dev1Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlCache)), "Device 1 Type 3 does not use CXL.cache");

    const auto* dev2Info = cxlSub.getDevice(2);
    TEST_ASSERT(dev2Info != nullptr, "Device 2 lookup must succeed");
    TEST_ASSERT(dev2Info->type == cxl::CxlDeviceType::Type2_DenseAccelerator, "Device 2 must be Type 2 Dense Accelerator");
    TEST_ASSERT(dev2Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlIo), "Device 2 must support CXL.io");
    TEST_ASSERT(dev2Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlCache), "Device 2 must support CXL.cache");
    TEST_ASSERT(dev2Info->supportedProtocols & static_cast<uint32_t>(cxl::CxlProtocol::CxlMem), "Device 2 must support CXL.mem");

    // Stage 6: Type 3 Memory Expander BAR Allocation (BAR2 128GB Memory Aperture)
    const auto& memBar0 = memDev->getBar(0);
    TEST_ASSERT(memBar0.size == 64 * 1024, "Type 3 BAR0 MMIO size must be 64 KB");
    const auto& memBar2 = memDev->getBar(2);
    TEST_ASSERT(memBar2.type == pci::PciBarType::Memory64, "BAR2 must be 64-bit MMIO");
    TEST_ASSERT(memBar2.prefetchable == true, "BAR2 CXL.mem aperture must be prefetchable");
    TEST_ASSERT(memBar2.size == 128ULL * 1024 * 1024 * 1024, "BAR2 CXL.mem capacity must be 128 GB");

    // Stage 7: HDM Decoder 0 Configuration & SPA Mapping
    TEST_ASSERT(!dev1Info->decoders.empty(), "Device 1 must have at least one HDM decoder");
    const auto& dec0 = dev1Info->decoders[0];
    TEST_ASSERT(dec0.decoderIndex == 0, "Decoder index must be 0");
    TEST_ASSERT(dec0.baseSpa == 0x1000000000ULL, "Base SPA must be 64 GB physical address boundary (0x10_0000_0000)");
    TEST_ASSERT(dec0.sizeBytes == 128ULL * 1024 * 1024 * 1024, "Decoder 0 size must match 128 GB capacity");
    TEST_ASSERT(dec0.granularity == cxl::CxlInterleaveGranularity::Granularity256B, "Interleave granularity must be 256 bytes");
    TEST_ASSERT(dec0.ways == cxl::CxlInterleaveWays::Way1, "Interleave ways must be 1-way (single device)");
    TEST_ASSERT(dec0.isCommitted == true, "Decoder 0 must be committed to hardware");

    // Stage 8: Type 2 Accelerator Coherent Memory Aperture (64GB HBM)
    TEST_ASSERT(!dev2Info->decoders.empty(), "Device 2 must have HDM decoder");
    const auto& dec1 = dev2Info->decoders[0];
    TEST_ASSERT(dec1.baseSpa == 0x3000000000ULL, "Base SPA must be 192 GB boundary (0x30_0000_0000)");
    TEST_ASSERT(dec1.sizeBytes == 64ULL * 1024 * 1024 * 1024, "Decoder size must match 64 GB HBM");
    TEST_ASSERT(dec1.granularity == cxl::CxlInterleaveGranularity::Granularity512B, "Granularity must be 512 bytes");
    TEST_ASSERT(dec1.isCommitted == true, "Decoder must be committed");

    // Stage 9: CXL Mailbox Command Execution: IDENTIFY_MEMORY_DEVICE (0x4000)
    std::vector<uint8_t> identOut;
    NTSTATUS idSt = cxlSub.sendMailboxCommand(1, cxl::CXL_MBOX_OP_IDENTIFY_MEMORY_DEVICE, {}, identOut);
    TEST_ASSERT(idSt == STATUS_SUCCESS, "Identify Memory Device mailbox command must succeed");
    TEST_ASSERT(identOut.size() >= 15, "Identify payload size must be >= 15 bytes");
    std::string identStr(reinterpret_cast<char*>(identOut.data()), 15);
    TEST_ASSERT(identStr == "TITAN-CXL-REV31", "Identify string must match TITAN-CXL-REV31");

    // Stage 10: CXL Mailbox S.M.A.R.T. Health Telemetry (0x4001)
    std::vector<uint8_t> smartOut;
    NTSTATUS smSt = cxlSub.sendMailboxCommand(1, cxl::CXL_MBOX_OP_GET_SMART_HEALTH, {}, smartOut);
    TEST_ASSERT(smSt == STATUS_SUCCESS, "Get S.M.A.R.T. Health mailbox command must succeed");
    TEST_ASSERT(smartOut.size() == sizeof(cxl::CxlSmartHealthInfo), "S.M.A.R.T. payload size must match struct size");
    const auto* smart = reinterpret_cast<const cxl::CxlSmartHealthInfo*>(smartOut.data());
    TEST_ASSERT(smart->healthStatus == 0, "Health status must be normal (0)");
    TEST_ASSERT(smart->mediaStatus == 0, "Media status must be normal (0)");
    TEST_ASSERT(smart->temperatureCelsius > 20.0f && smart->temperatureCelsius < 80.0f, "Temperature must be within operating range");
    TEST_ASSERT(smart->dirtyShutdownCount == 0, "Dirty shutdown count must be 0");

    // Stage 11: Address Poisoning & Fault Isolation (INJECT_POISON, GET_POISON_LIST, CLEAR_POISON)
    uint64_t targetDpa = 0x10008000ULL;
    std::vector<uint8_t> injPayload(sizeof(targetDpa));
    std::memcpy(injPayload.data(), &targetDpa, sizeof(targetDpa));
    NTSTATUS injSt = cxlSub.sendMailboxCommand(1, cxl::CXL_MBOX_OP_INJECT_POISON, injPayload, identOut);
    TEST_ASSERT(injSt == STATUS_SUCCESS, "Inject Poison mailbox command must succeed");

    std::vector<uint8_t> poisonOut;
    NTSTATUS plistSt = cxlSub.sendMailboxCommand(1, cxl::CXL_MBOX_OP_GET_POISON_LIST, {}, poisonOut);
    TEST_ASSERT(plistSt == STATUS_SUCCESS, "Get Poison List mailbox command must succeed");
    uint32_t poisonCount = 0;
    std::memcpy(&poisonCount, poisonOut.data(), sizeof(poisonCount));
    TEST_ASSERT(poisonCount == 1, "Poison list must contain exactly 1 entry");

    const auto* prec = reinterpret_cast<const cxl::CxlPoisonRecord*>(poisonOut.data() + sizeof(uint32_t));
    TEST_ASSERT(prec->devicePhysicalAddress == targetDpa, "Poisoned DPA must match injected address");
    TEST_ASSERT(prec->lengthBytes == 64, "Poisoned cache line length must be 64 bytes");

    // Clear poison
    NTSTATUS clrSt = cxlSub.sendMailboxCommand(1, cxl::CXL_MBOX_OP_CLEAR_POISON, injPayload, identOut);
    TEST_ASSERT(clrSt == STATUS_SUCCESS, "Clear Poison mailbox command must succeed");
    auto clearedList = cxlSub.getPoisonList(1);
    TEST_ASSERT(clearedList.empty(), "Poison list must be empty after clearing");

    // Stage 12: Dynamic Memory Tiering (DMT) & NUMA Node 1 Expansion
    const auto& tiering = cxlSub.getNumaTieringInfo();
    TEST_ASSERT(tiering.tierId == 1, "Tier ID must be 1 (Far Memory)");
    TEST_ASSERT(tiering.numaNodeId == 1, "NUMA node must be Node 1");
    TEST_ASSERT(tiering.totalCapacityBytes == 128ULL * 1024 * 1024 * 1024, "Total capacity must be 128 GB");
    TEST_ASSERT(tiering.readLatencyNs == 140, "Far Memory read latency must be 140 ns");
    TEST_ASSERT(tiering.writeLatencyNs == 150, "Far Memory write latency must be 150 ns");
    TEST_ASSERT(tiering.peakBandwidthGBps >= 60.0f, "Peak bandwidth must be >= 60 GB/s (PCIe 5.0 x16)");

    // Stage 13: DMT Page Migration Simulation (Demote to Far Memory & Promote to Near Memory)
    uint64_t initialAllocated = tiering.allocatedBytes;
    uint64_t initialMigrated = tiering.pagesMigratedToFar;
    bool migOk = cxlSub.migratePages(1, 1024, true); // Demote 1024 pages (4 MB)
    TEST_ASSERT(migOk == true, "Page migration to far memory must succeed");
    const auto& updatedTiering = cxlSub.getNumaTieringInfo();
    TEST_ASSERT(updatedTiering.allocatedBytes == initialAllocated + (1024 * 4096ULL), "Allocated capacity must increase by 4 MB");
    TEST_ASSERT(updatedTiering.pagesMigratedToFar == initialMigrated + 1024, "Pages migrated counter must increment by 1024");

    uint64_t initialPromoted = updatedTiering.pagesPromotedToNear;
    bool promOk = cxlSub.migratePages(1, 512, false); // Promote 512 pages (2 MB)
    TEST_ASSERT(promOk == true, "Page promotion to near memory must succeed");
    const auto& finalTiering = cxlSub.getNumaTieringInfo();
    TEST_ASSERT(finalTiering.pagesPromotedToNear == initialPromoted + 512, "Pages promoted counter must increment by 512");

    // Stage 14: CXL Fabric Telemetry Accounting
    const auto& telem = cxlSub.getTelemetry();
    TEST_ASSERT(telem.activeDevices >= 2, "Active CXL devices counter must be >= 2");
    TEST_ASSERT(telem.totalCxlReadTransactions > 0, "CXL read transactions counter must be positive");
    TEST_ASSERT(telem.totalCxlWriteTransactions > 0, "CXL write transactions counter must be positive");
    TEST_ASSERT(telem.totalFlitsTransferred > 0, "Flits transferred counter must be positive");
    TEST_ASSERT(telem.totalMailboxCommandsExecuted >= 4, "Mailbox commands executed counter must be >= 4");
    TEST_ASSERT(telem.currentFabricThroughputGBps > 0.0f, "Current fabric throughput must be positive");

    // Stage 15: Dynamic Loader C ABI Driver Exports (cxlhost.sys, cxlmem.sys, cxlbus.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("cxlhost.sys", "CxlHostInitialize") != nullptr, "cxlhost.sys CxlHostInitialize must exist");
    TEST_ASSERT(ldr.getExport("cxlhost.sys", "CxlHostGetVersion") != nullptr, "cxlhost.sys CxlHostGetVersion must exist");
    TEST_ASSERT(ldr.getExport("cxlhost.sys", "CxlHostEnumerateBridges") != nullptr, "cxlhost.sys CxlHostEnumerateBridges must exist");

    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemGetDeviceInfo") != nullptr, "cxlmem.sys CxlMemGetDeviceInfo must exist");
    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemConfigureHdmDecoder") != nullptr, "cxlmem.sys CxlMemConfigureHdmDecoder must exist");
    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemGetSmartHealth") != nullptr, "cxlmem.sys CxlMemGetSmartHealth must exist");
    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemQueryPoisonList") != nullptr, "cxlmem.sys CxlMemQueryPoisonList must exist");
    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemInjectPoison") != nullptr, "cxlmem.sys CxlMemInjectPoison must exist");
    TEST_ASSERT(ldr.getExport("cxlmem.sys", "CxlMemMigratePages") != nullptr, "cxlmem.sys CxlMemMigratePages must exist");

    TEST_ASSERT(ldr.getExport("cxlbus.sys", "CxlBusRegisterDevice") != nullptr, "cxlbus.sys CxlBusRegisterDevice must exist");
    TEST_ASSERT(ldr.getExport("cxlbus.sys", "CxlBusGetDeviceCount") != nullptr, "cxlbus.sys CxlBusGetDeviceCount must exist");
    TEST_ASSERT(ldr.getExport("cxlbus.sys", "CxlBusSendMailboxCommand") != nullptr, "cxlbus.sys CxlBusSendMailboxCommand must exist");

    // Direct C ABI Calls Verification
    uint32_t abiMaj = 0, abiMin = 0;
    NTSTATUS vSt = cxl::CxlHostGetVersion(&abiMaj, &abiMin);
    TEST_ASSERT(vSt == STATUS_SUCCESS && abiMaj == 3 && abiMin == 1, "CxlHostGetVersion C ABI call must succeed");

    uint32_t bridgeCount = 0;
    NTSTATUS brSt = cxl::CxlHostEnumerateBridges(&bridgeCount);
    TEST_ASSERT(brSt == STATUS_SUCCESS && bridgeCount >= 1, "CxlHostEnumerateBridges C ABI call must succeed");

    cxl::CxlDeviceInfo abiDev{};
    NTSTATUS dSt = cxl::CxlMemGetDeviceInfo(1, &abiDev);
    TEST_ASSERT(dSt == STATUS_SUCCESS && abiDev.totalMemoryBytes == 128ULL * 1024 * 1024 * 1024, "CxlMemGetDeviceInfo C ABI call must succeed");

    cxl::CxlSmartHealthInfo abiHealth{};
    NTSTATUS shSt = cxl::CxlMemGetSmartHealth(1, &abiHealth);
    TEST_ASSERT(shSt == STATUS_SUCCESS && abiHealth.healthStatus == 0, "CxlMemGetSmartHealth C ABI call must succeed");

    // Stage 16: SCM Service Control Manager Records & Version Database Registrations
    auto cxlHostSvc = scm::ServiceControlManager::get().getServiceRecord(L"cxlhost");
    TEST_ASSERT(cxlHostSvc != nullptr, "cxlhost service record must exist in SCM");
    TEST_ASSERT(cxlHostSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "cxlhost must be a kernel driver");
    TEST_ASSERT(cxlHostSvc->startType == scm::SERVICE_BOOT_START, "cxlhost must have boot start type");

    auto cxlMemSvc = scm::ServiceControlManager::get().getServiceRecord(L"cxlmem");
    TEST_ASSERT(cxlMemSvc != nullptr, "cxlmem service record must exist in SCM");
    TEST_ASSERT(cxlMemSvc->startType == scm::SERVICE_BOOT_START, "cxlmem must have boot start type");

    auto cxlBusSvc = scm::ServiceControlManager::get().getServiceRecord(L"cxlbus");
    TEST_ASSERT(cxlBusSvc != nullptr, "cxlbus service record must exist in SCM");
    TEST_ASSERT(cxlBusSvc->startType == scm::SERVICE_SYSTEM_START, "cxlbus must have system start type");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("cxlhost.sys") != nullptr, "cxlhost.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("cxlmem.sys") != nullptr, "cxlmem.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("cxlbus.sys") != nullptr, "cxlbus.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 162: Compute Express Link (CXL 2.0 / 3.1) & Heterogeneous Memory Fabric PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Compute Express Link (CXL 2.0 / 3.1) Heterogeneous Memory Fabric\n";
    std::cout << "       Codename: TitanCXL / NexusCXL | Binary: cxlhost.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_ComputeExpressLink_CXL_HeterogeneousMemory_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
