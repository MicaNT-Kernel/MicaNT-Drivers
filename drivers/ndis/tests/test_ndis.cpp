// ============================================================================
// Standalone Driver Verification Test: ndis (TitanNDIS / RazzleNet)
// Subsystem: NDIS 6.88 & High-Speed Network Adapter Subsystem (RazzleNet)
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/ndis.hpp"

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

void Test_NDIS688_HighSpeedNetworking_Subsystem() {
    std::cout << "[TEST] Starting Suite 157: NDIS 6.88 & High-Speed Network Adapter Subsystem (RazzleNet)...\n";

    // Stage 1: NDIS 6.88 Subsystem Initialization & Adapter Discovery
    ndis::InitializeNdisSubsystem();
    auto& ndisSub = ndis::TitanNdisSubsystem::Instance();
    TEST_ASSERT(ndisSub.isInitialized() == true, "NDIS subsystem must be initialized");
    TEST_ASSERT(ndisSub.getAdapterCount() >= 2, "At least 2 adapters must be registered (RazzleNet & Virtual)");

    // Stage 2: RazzleNet PCIe Miniport Discovery & Binding (BDF 00:04.0)
    auto primary = ndisSub.getPrimaryAdapter();
    TEST_ASSERT(primary != nullptr, "Primary network adapter must not be null");
    auto razzle = std::dynamic_pointer_cast<ndis::RazzleNetAdapter>(primary);
    TEST_ASSERT(razzle != nullptr, "Primary adapter must be RazzleNet 10GbE miniport");
    TEST_ASSERT(razzle->getPciAddress().bus == 0 && razzle->getPciAddress().device == 4 && razzle->getPciAddress().function == 0,
                "RazzleNet must bind to PCIe BDF 00:04.0");

    // Stage 3: MAC Address, Link State, and Link Speed Verification
    auto mac = razzle->getMacAddress();
    TEST_ASSERT(mac == ndis::MacAddress::razzleNetDefault(), "MAC address must match Sovereign RazzleNet default");
    TEST_ASSERT(mac.isBroadcast() == false, "Adapter MAC must not be broadcast");
    TEST_ASSERT(mac.isMulticast() == false, "Adapter MAC must not be multicast");
    TEST_ASSERT(razzle->getLinkState() == ndis::MediaConnectState::Connected, "Initial link state must be Connected");
    TEST_ASSERT(razzle->getSpeedBps() == 10'000'000'000ULL, "Default link speed must be 10 Gbps");

    // Stage 4: Dynamic Link Speed (40GbE / 100GbE) & MTU Tuning (Jumbo Frames)
    razzle->setLinkSpeed(40'000'000'000ULL);
    TEST_ASSERT(razzle->getSpeedBps() == 40'000'000'000ULL, "Link speed must update to 40 Gbps");
    razzle->setLinkSpeed(100'000'000'000ULL);
    TEST_ASSERT(razzle->getSpeedBps() == 100'000'000'000ULL, "Link speed must update to 100 Gbps");
    razzle->setLinkSpeed(10'000'000'000ULL); // restore 10G

    razzle->setMtu(static_cast<uint32_t>(ndis::JUMBO_MTU));
    TEST_ASSERT(razzle->getMtu() == ndis::JUMBO_MTU, "MTU must be configurable up to 9014 (Jumbo Frames)");
    razzle->setMtu(static_cast<uint32_t>(ndis::DEFAULT_MTU));
    TEST_ASSERT(razzle->getMtu() == ndis::DEFAULT_MTU, "MTU must restore to 1500 bytes");

    // Stage 5: NET_BUFFER & NET_BUFFER_LIST (NBL) Memory Pool Allocation & Recycling
    auto* pool = ndisSub.getNblPool();
    TEST_ASSERT(pool != nullptr, "NBL Pool must be allocated");
    size_t initActive = pool->getActiveCount();
    std::vector<uint8_t> dummyData = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    auto nbl1 = pool->allocate(dummyData);
    TEST_ASSERT(nbl1 != nullptr, "NBL allocation must succeed");
    TEST_ASSERT(nbl1->firstNetBuffer != nullptr, "NBL must contain firstNetBuffer");
    TEST_ASSERT(nbl1->firstNetBuffer->dataLength == dummyData.size(), "NB dataLength must match payload");
    TEST_ASSERT(pool->getActiveCount() == initActive + 1, "Pool active count must increment");

    pool->free(nbl1);
    TEST_ASSERT(pool->getActiveCount() == initActive, "Pool active count must decrement upon free");

    // Stage 6: Hardware Checksum Offload Engine (RFC 1071 1's Complement Sum)
    const uint8_t testIpHdr[] = {
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x64, // 192.168.1.100
        0xC0, 0xA8, 0x01, 0x01                          // 192.168.1.1
    };
    uint16_t csum = ndis::calculateIpChecksum(testIpHdr, sizeof(testIpHdr));
    TEST_ASSERT(csum != 0, "Calculated IP checksum must be non-zero");
    uint8_t verifiedHdr[sizeof(testIpHdr)];
    std::memcpy(verifiedHdr, testIpHdr, sizeof(testIpHdr));
    verifiedHdr[10] = static_cast<uint8_t>(csum >> 8);
    verifiedHdr[11] = static_cast<uint8_t>(csum & 0xFF);
    uint16_t verifyResult = ndis::calculateIpChecksum(verifiedHdr, sizeof(verifiedHdr));
    TEST_ASSERT(verifyResult == 0x0000 || verifyResult == 0xFFFF, "Checksum verification of complete header must evaluate to 0");

    // Stage 7: Large Send Offload v2 (LSOv2 / TSO) Segmentation
    auto& offloads = razzle->getOffloadCapabilities();
    TEST_ASSERT(offloads.lsoV2.enabled == true, "LSOv2 must be enabled by default");
    TEST_ASSERT(offloads.lsoV2.maxOffloadSize == 65536, "LSOv2 max offload size must be 64KB");

    std::vector<uint8_t> largePayload(4096, 0x55);
    auto largeFrame = ndis::buildEthernetFrame(
        ndis::MacAddress::broadcast(),
        razzle->getMacAddress(),
        ndis::ETHERTYPE_IPV4,
        largePayload
    );
    auto lsoStatus = razzle->sendPacket(largeFrame);
    TEST_ASSERT(lsoStatus == NtStatus::Success, "LSOv2 large packet transmission must succeed");
    auto statsAfterLso = razzle->getStatistics();
    TEST_ASSERT(statsAfterLso.lsoPackets >= 2, "LSO segmentation must produce at least 2 hardware segments");

    // Stage 8: Receive Side Scaling (RSS) 40-byte Toeplitz Hash & Indirection Table
    auto& rss = razzle->getRssParameters();
    TEST_ASSERT(rss.enabled == true, "RSS must be enabled by default");
    TEST_ASSERT(rss.numCpuQueues == 4, "Default RSS CPU queues must be 4");

    std::vector<uint8_t> sampleFlow = { 192, 168, 1, 100, 192, 168, 1, 1, 0x1F, 0x90, 0x00, 0x50 };
    uint32_t hashVal = ndis::computeToeplitzHash(sampleFlow, rss.secretKey);
    TEST_ASSERT(hashVal != 0, "Toeplitz hash must compute a non-zero 32-bit hash");
    uint8_t targetCpu = rss.getTargetCpu(hashVal);
    TEST_ASSERT(targetCpu < rss.numCpuQueues, "Target CPU must be within configured queue range");

    // Stage 9: High-Speed TX DMA Ring Descriptors & MMIO Doorbells
    auto& rings = razzle->getRingBuffer();
    uint32_t preTxCompleted = static_cast<uint32_t>(rings.txCompleted);

    std::vector<uint8_t> stdPayload(128, 0x77);
    auto stdFrame = ndis::buildEthernetFrame(
        ndis::MacAddress::broadcast(),
        razzle->getMacAddress(),
        ndis::ETHERTYPE_IPV4,
        stdPayload
    );
    auto txStatus = razzle->sendPacket(stdFrame);
    TEST_ASSERT(txStatus == NtStatus::Success, "Standard frame transmission must succeed");
    TEST_ASSERT(rings.txCompleted == preTxCompleted + 1, "TX completed counter must increment");
    TEST_ASSERT(razzle->readMmio32(ndis::RazzleNetAdapter::REG_TDH) == rings.txHead, "MMIO TDH must match ring txHead");
    TEST_ASSERT(razzle->readMmio32(ndis::RazzleNetAdapter::REG_TDT) == rings.txTail, "MMIO TDT must match ring txTail");

    // Stage 10: High-Speed RX DMA Ring Descriptors & Packet Ingestion
    bool rxInvoked = false;
    size_t rxBytesReceived = 0;
    razzle->registerReceiveHandler([&](std::span<const uint8_t> pkt) {
        rxInvoked = true;
        rxBytesReceived = pkt.size();
    });

    uint32_t preRxCompleted = static_cast<uint32_t>(rings.rxCompleted);
    razzle->receivePacket(stdFrame);
    TEST_ASSERT(rxInvoked == true, "Receive handler must be invoked on packet ingestion");
    TEST_ASSERT(rxBytesReceived == stdFrame.size(), "Received packet byte size must match transmitted size");
    TEST_ASSERT(rings.rxCompleted == preRxCompleted + 1, "RX completed counter must increment");

    // Stage 11: Single Root I/O Virtualization (SR-IOV) VF Provisioning
    auto& sriov = razzle->getSriovManager();
    TEST_ASSERT(sriov.enableSriov(8) == true, "Enabling 8 Virtual Functions (VFs) must succeed");
    TEST_ASSERT(sriov.getActiveVfCount() == 8, "Active VF count must be 8");
    ndis::MacAddress vfMac(0x52, 0x5A, 0x00, 0x04, 0x01, 0x03);
    TEST_ASSERT(sriov.configureVf(3, vfMac, 100, 2500, true) == true, "Configuring VF #3 (VLAN 100, 2.5G) must succeed");
    const auto* vf3 = sriov.getVf(3);
    TEST_ASSERT(vf3 != nullptr && vf3->allocated == true, "VF #3 must be allocated");
    TEST_ASSERT(vf3->vfMac == vfMac, "VF #3 MAC must match configured MAC");
    TEST_ASSERT(vf3->vlanId == 100, "VF #3 VLAN ID must be 100");
    TEST_ASSERT(vf3->maxRateMbps == 2500, "VF #3 rate limit must be 2500 Mbps");

    // Stage 12: Dual Adapter Virtual Bus & Inter-Adapter Communication
    auto vnetAdp = std::dynamic_pointer_cast<ndis::VirtualNetworkAdapter>(ndisSub.getAdapter(L"vnet0"));
    TEST_ASSERT(vnetAdp != nullptr, "Virtual network adapter (vnet0) must exist");
    auto vnetStats = vnetAdp->getStatistics();
    TEST_ASSERT(vnetAdp->getMtu() == ndis::DEFAULT_MTU, "vnet0 MTU must be 1500");

    // Stage 13: Dynamic Loader C ABI Exports (ndis.sys & razzlenet.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisMRegisterMiniportDriver") != nullptr, "ndis.sys NdisMRegisterMiniportDriver export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisAllocateNetBufferListPool") != nullptr, "ndis.sys NdisAllocateNetBufferListPool export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisAllocateNetBufferList") != nullptr, "ndis.sys NdisAllocateNetBufferList export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisFreeNetBufferList") != nullptr, "ndis.sys NdisFreeNetBufferList export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisMIndicateReceiveNetBufferLists") != nullptr, "ndis.sys NdisMIndicateReceiveNetBufferLists export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisMSendNetBufferListsComplete") != nullptr, "ndis.sys NdisMSendNetBufferListsComplete export must exist");
    TEST_ASSERT(ldr.getExport("ndis.sys", "NdisQueryAdapterInformation") != nullptr, "ndis.sys NdisQueryAdapterInformation export must exist");

    TEST_ASSERT(ldr.getExport("razzlenet.sys", "RazzleNetInitializeMiniport") != nullptr, "razzlenet.sys RazzleNetInitializeMiniport export must exist");
    TEST_ASSERT(ldr.getExport("razzlenet.sys", "RazzleNetTransmitPacket") != nullptr, "razzlenet.sys RazzleNetTransmitPacket export must exist");

    // Stage 14: SCM Service Records & Version Database Verification
    auto ndisSvc = scm::ServiceControlManager::get().getServiceRecord(L"ndis");
    TEST_ASSERT(ndisSvc != nullptr, "ndis service record must exist in SCM");
    TEST_ASSERT(ndisSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "ndis must be a kernel driver");
    TEST_ASSERT(ndisSvc->startType == scm::SERVICE_BOOT_START, "ndis must have boot start type");

    auto razzleSvc = scm::ServiceControlManager::get().getServiceRecord(L"razzlenet");
    TEST_ASSERT(razzleSvc != nullptr, "razzlenet service record must exist in SCM");
    TEST_ASSERT(razzleSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "razzlenet must be a kernel driver");
    TEST_ASSERT(razzleSvc->startType == scm::SERVICE_SYSTEM_START, "razzlenet must have system start type");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("ndis.sys") != nullptr, "ndis.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("razzlenet.sys") != nullptr, "razzlenet.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 157: NDIS 6.88 & High-Speed Network Adapter Subsystem (RazzleNet) PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: NDIS 6.88 & High-Speed Network Adapter Subsystem (RazzleNet)\n";
    std::cout << "       Codename: TitanNDIS / RazzleNet | Binary: ndis.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_NDIS688_HighSpeedNetworking_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
