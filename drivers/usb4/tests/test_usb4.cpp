// ============================================================================
// Standalone Driver Verification Test: usb4 (TitanUSB4 / NexusUSB4)
// Subsystem: USB4 2.0 & Thunderbolt 4 Protocol Tunneling Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/usb4.hpp"

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

void Test_USB4_Thunderbolt4_ProtocolTunneling_Subsystem() {
    std::cout << "[TEST] Starting Suite 160: USB4 2.0 & Thunderbolt 4 Protocol Tunneling Subsystem...\n";

    // 1. Initialize Subsystem & Register Components
    usb4::InitializeUsb4Subsystem();
    auto& usb4Sub = usb4::TitanUsb4Subsystem::Instance();
    TEST_ASSERT(usb4Sub.isInitialized() == true, "TitanUSB4 subsystem must be initialized");

    // Stage 1: PCIe Miniport Binding (Bus 00:07.0)
    auto pciDev = pci::TitanPciSubsystem::Instance().findDevice(pci::PciAddress(0, 7, 0));
    TEST_ASSERT(pciDev != nullptr, "TitanUSB4 PCIe device must be registered at 00:07.0");
    TEST_ASSERT(pciDev->getVendorId() == 0x8086, "USB4 Host Router Vendor ID must be 0x8086 (Intel / Titan)");
    TEST_ASSERT(pciDev->getDeviceId() == 0x9A1B, "USB4 Host Router Device ID must be 0x9A1B (Arrow Lake USB4 Host Router)");
    TEST_ASSERT(pciDev->getBaseClass() == static_cast<uint8_t>(pci::PciBaseClass::SerialBus), "Base class must be SerialBus");
    TEST_ASSERT(pciDev->getProgIf() == 0x40, "Programming Interface must be 0x40 (USB4 Host Interface)");

    // Stage 2: Host Router Capabilities & USB4 2.0 Version Discovery
    auto topo = usb4Sub.getTopology();
    TEST_ASSERT(!topo.empty(), "Topology must contain Host Router at root");
    const auto& hostRouter = topo[0];
    TEST_ASSERT(hostRouter.routerId == 0, "Host Router ID must be 0");
    TEST_ASSERT(hostRouter.depth == 0, "Host Router topology depth must be 0");
    TEST_ASSERT(hostRouter.negotiatedBandwidthGbps >= 80, "Host Router base link bandwidth must be at least 80 Gbps");
    TEST_ASSERT(hostRouter.adapters.size() >= 5, "Host Router must contain at least 5 adapters (HI, PCIe, DP, USB3, Lane)");

    // Stage 3: Physical Layer Signaling & Link Modes (80 Gbps symmetric PAM3)
    TEST_ASSERT(usb4Sub.getLinkSpeed() == usb4::Usb4LinkSpeed::Gen4_80G_Symmetric, "Default link speed must be 80 Gbps symmetric PAM3");
    TEST_ASSERT(usb4Sub.isAsymmetricModeEnabled() == false, "Asymmetric PAM3 mode must be disabled by default");

    // Stage 4: Dynamic PAM3 Asymmetric Mode Toggle (120 Gbps downstream / 40 Gbps upstream)
    usb4Sub.setAsymmetricMode(true);
    TEST_ASSERT(usb4Sub.isAsymmetricModeEnabled() == true, "Asymmetric PAM3 mode must report enabled");
    TEST_ASSERT(usb4Sub.getLinkSpeed() == usb4::Usb4LinkSpeed::Gen4_120G_Asymmetric, "Link speed must update to Gen4 120 Gbps Asymmetric");
    auto topoAsym = usb4Sub.getTopology();
    TEST_ASSERT(topoAsym[0].negotiatedBandwidthGbps == 120, "Host router negotiated bandwidth must scale to 120 Gbps");
    usb4Sub.setAsymmetricMode(false);
    TEST_ASSERT(usb4Sub.getLinkSpeed() == usb4::Usb4LinkSpeed::Gen4_80G_Symmetric, "Link speed must restore to 80 Gbps Symmetric");

    // Stage 5: Router Topology Tree Discovery (Host -> Tier 1 Dock -> Tier 2 eGPU)
    TEST_ASSERT(usb4Sub.getConnectedRoutersCount() >= 3, "Subsystem must discover at least 3 cascaded routers");
    const auto& dockRouter = topo[1];
    TEST_ASSERT(dockRouter.routerId == 1, "Tier 1 Router ID must be 1");
    TEST_ASSERT(dockRouter.depth == 1, "Tier 1 Router depth must be 1");
    TEST_ASSERT(dockRouter.modelName.find("Docking Station") != std::string::npos, "Router 1 must be Quantum 80G Dock");

    const auto& egpuRouter = topo[2];
    TEST_ASSERT(egpuRouter.routerId == 2, "Tier 2 Router ID must be 2");
    TEST_ASSERT(egpuRouter.depth == 2, "Tier 2 Router depth must be 2");
    TEST_ASSERT(egpuRouter.modelName.find("eGPU") != std::string::npos, "Router 2 must be eGPU Accelerator");

    // Stage 6: Peripheral UUID Interrogation and Metadata Inspection
    TEST_ASSERT(dockRouter.deviceUuid == "80860001-BEEF-4000-8000-001A7DDA7201", "Dock UUID must match registered descriptor");
    TEST_ASSERT(egpuRouter.deviceUuid == "10DE0002-CAFE-4000-8000-001A7DDA7202", "eGPU UUID must match registered descriptor");

    // Stage 7: Thunderbolt Security Level Policy Enforcement (SL0..SL3)
    TEST_ASSERT(usb4Sub.getSecurityLevel() == usb4::Usb4SecurityLevel::SL2_SecureConnection, "Default security level must be SL2 (Secure Connection)");
    usb4Sub.setSecurityLevel(usb4::Usb4SecurityLevel::SL3_DisplayPortOnly);
    TEST_ASSERT(usb4Sub.getSecurityLevel() == usb4::Usb4SecurityLevel::SL3_DisplayPortOnly, "Security level must update to SL3");
    // Under SL3, PCIe path creation must be rejected
    uint16_t blockedHop = 0;
    auto blockedSt = usb4Sub.createPath(0, 1, 1, 1, usb4::Usb4PathType::PCIe, 16000, 32, blockedHop);
    TEST_ASSERT(blockedSt == NtStatus::AccessDenied, "PCIe path creation must be rejected under SL3 (DisplayPort only)");
    usb4Sub.setSecurityLevel(usb4::Usb4SecurityLevel::SL2_SecureConnection);

    // Stage 8: SL2 Cryptographic Peripheral Authorization & Challenge-Response
    bool authOk = usb4Sub.authorizeDevice("10DE0002-CAFE-4000-8000-001A7DDA7202");
    TEST_ASSERT(authOk == true, "Peripheral authorization for valid UUID must succeed");
    bool badAuth = usb4Sub.authorizeDevice("00000000-0000-0000-0000-000000000000");
    TEST_ASSERT(badAuth == false, "Peripheral authorization for invalid UUID must fail");

    // Stage 9: PCIe Protocol Tunneling Adapter Configuration & Path Establishment (USB4_PATH)
    auto activePaths = usb4Sub.getActivePaths();
    TEST_ASSERT(!activePaths.empty(), "Active paths list must contain pre-configured default tunnels");
    bool foundPciePath = false;
    for (const auto& p : activePaths) {
        if (p.hopId == 8 && p.pathType == usb4::Usb4PathType::PCIe) {
            foundPciePath = true;
            TEST_ASSERT(p.allocatedBandwidthMbps >= 32000, "PCIe path bandwidth must be >= 32 Gbps");
            TEST_ASSERT(p.creditsAllocated >= 64, "PCIe path credits must be >= 64");
            TEST_ASSERT(p.isActive == true, "PCIe path must be in active state");
            break;
        }
    }
    TEST_ASSERT(foundPciePath == true, "Hop ID 8 PCIe tunneling path must exist");

    // Stage 10: PCIe Transaction Layer Packet (TLP) Encapsulation, Transmission & Decapsulation
    std::vector<uint8_t> tlpPayload = { 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF };
    bool txPcieOk = usb4Sub.tunnelPciePacket(8, tlpPayload);
    TEST_ASSERT(txPcieOk == true, "Tunneling PCIe TLP over Hop ID 8 must succeed");

    usb4::PcieTunnelEngine engine;
    auto encapsulated = engine.encapsulateTlp(8, tlpPayload);
    TEST_ASSERT(encapsulated.size() > tlpPayload.size(), "Encapsulated packet must include USB4 transport framing");
    uint16_t decapsHop = 0;
    std::vector<uint8_t> decapsTlp;
    bool decapsOk = engine.decapsulateTlp(encapsulated, decapsHop, decapsTlp);
    TEST_ASSERT(decapsOk == true, "Decapsulation of USB4 transport frame must succeed");
    TEST_ASSERT(decapsHop == 8, "Decapsulated Hop ID must match original");
    TEST_ASSERT(decapsTlp == tlpPayload, "Decapsulated TLP payload must match transmitted data byte-for-byte");

    // Stage 11: DisplayPort 2.1 Video Tunneling Path Setup & Bandwidth Verification
    bool txDpOk = usb4Sub.tunnelDpPacket(9, 8192);
    TEST_ASSERT(txDpOk == true, "Tunneling DisplayPort video frame over Hop ID 9 must succeed");

    // Stage 12: SuperSpeed USB 3.2 Protocol Tunneling
    bool txUsbOk = usb4Sub.tunnelUsb3Packet(10, 2048);
    TEST_ASSERT(txUsbOk == true, "Tunneling SuperSpeed USB 3.2 frame over Hop ID 10 must succeed");

    auto stats = usb4Sub.getStatistics();
    TEST_ASSERT(stats.totalTransmittedPackets >= 3, "Transmitted packet counter must reflect PCIe, DP, and USB3 traffic");
    TEST_ASSERT(stats.pcieTunneledBytes >= tlpPayload.size(), "PCIe tunneled byte counter must increment");
    TEST_ASSERT(stats.dpTunneledBytes >= 8192, "DisplayPort tunneled byte counter must increment");
    TEST_ASSERT(stats.usb3TunneledBytes >= 2048, "USB 3.2 tunneled byte counter must increment");

    // Stage 13: Dynamic Loader C ABI Exports Verification (usb4host.sys, thunderbolt.sys, usb4router.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("usb4host.sys", "Usb4HostInitialize") != nullptr, "Usb4HostInitialize export must exist");
    TEST_ASSERT(ldr.getExport("usb4host.sys", "Usb4HostEnumerateTopology") != nullptr, "Usb4HostEnumerateTopology export must exist");
    TEST_ASSERT(ldr.getExport("usb4host.sys", "Usb4HostCreatePath") != nullptr, "Usb4HostCreatePath export must exist");
    TEST_ASSERT(ldr.getExport("usb4host.sys", "Usb4HostDestroyPath") != nullptr, "Usb4HostDestroyPath export must exist");
    TEST_ASSERT(ldr.getExport("usb4host.sys", "Usb4HostGetRouterCapabilities") != nullptr, "Usb4HostGetRouterCapabilities export must exist");
    TEST_ASSERT(ldr.getExport("thunderbolt.sys", "ThunderboltGetSecurityLevel") != nullptr, "ThunderboltGetSecurityLevel export must exist");
    TEST_ASSERT(ldr.getExport("thunderbolt.sys", "ThunderboltSetSecurityLevel") != nullptr, "ThunderboltSetSecurityLevel export must exist");
    TEST_ASSERT(ldr.getExport("thunderbolt.sys", "ThunderboltAuthorizeDevice") != nullptr, "ThunderboltAuthorizeDevice export must exist");
    TEST_ASSERT(ldr.getExport("usb4router.sys", "Usb4TunnelPciePacket") != nullptr, "Usb4TunnelPciePacket export must exist");

    // Direct C ABI Invocation Checks
    uint32_t rCount = 0;
    TEST_ASSERT(usb4::Usb4HostEnumerateTopology(&rCount) == 0 && rCount >= 3, "Usb4HostEnumerateTopology C ABI call must succeed");
    uint8_t secLvl = 0;
    TEST_ASSERT(usb4::ThunderboltGetSecurityLevel(&secLvl) == 0 && secLvl == 2, "ThunderboltGetSecurityLevel C ABI call must return SL2");
    TEST_ASSERT(usb4::ThunderboltAuthorizeDevice("10DE0002-CAFE-4000-8000-001A7DDA7202") == 0, "ThunderboltAuthorizeDevice C ABI call must succeed");

    // Stage 14: SCM Service Records & Version Database Registrations
    auto hostSvc = scm::ServiceControlManager::get().getServiceRecord(L"usb4host");
    TEST_ASSERT(hostSvc != nullptr, "usb4host service record must exist in SCM");
    TEST_ASSERT(hostSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "usb4host must be a kernel driver");
    TEST_ASSERT(hostSvc->startType == scm::SERVICE_BOOT_START, "usb4host must have boot start type");

    auto tbtSvc = scm::ServiceControlManager::get().getServiceRecord(L"thunderbolt");
    TEST_ASSERT(tbtSvc != nullptr, "thunderbolt service record must exist in SCM");
    TEST_ASSERT(tbtSvc->startType == scm::SERVICE_BOOT_START, "thunderbolt must have boot start type");

    auto routerSvc = scm::ServiceControlManager::get().getServiceRecord(L"usb4router");
    TEST_ASSERT(routerSvc != nullptr, "usb4router service record must exist in SCM");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("usb4host.sys") != nullptr, "usb4host.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("thunderbolt.sys") != nullptr, "thunderbolt.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("usb4router.sys") != nullptr, "usb4router.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 160: USB4 2.0 & Thunderbolt 4 Protocol Tunneling Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: USB4 2.0 & Thunderbolt 4 Protocol Tunneling Subsystem\n";
    std::cout << "       Codename: TitanUSB4 / NexusUSB4 | Binary: usb4host.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_USB4_Thunderbolt4_ProtocolTunneling_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
