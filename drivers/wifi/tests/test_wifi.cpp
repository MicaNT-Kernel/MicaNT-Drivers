// ============================================================================
// Standalone Driver Verification Test: wifi (TitanWiFi / NexusWiFi)
// Subsystem: Wi-Fi 7 (802.11be EHT) & WDI NetAdapterCx Miniport Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/wdiwifi.hpp"

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

void Test_WiFi7_WDI_NetAdapterCx_Subsystem() {
    std::cout << "[TEST] Starting Suite 159: Wi-Fi 7 (802.11be) & WDI NetAdapterCx Subsystem...\n";

    // Stage 1: Subsystem Initialization & PCIe Miniport Binding (BDF 00:06.0)
    wdi::InitializeWdiWiFiSubsystem();
    auto& wifiSub = wdi::TitanWiFiSubsystem::Instance();
    TEST_ASSERT(wifiSub.isInitialized() == true, "TitanWiFi subsystem must be initialized");
    TEST_ASSERT(wifiSub.getAdapterName().find("TitanWiFi 7") != std::string::npos, "Adapter name must identify as TitanWiFi 7");
    auto pciAddr = wifiSub.getPciAddress();
    TEST_ASSERT(pciAddr.bus == 0 && pciAddr.device == 6 && pciAddr.function == 0, "TitanWiFi must bind to PCIe BDF 00:06.0");

    // Stage 2: Station MAC Address Verification (Sovereign Titan Default)
    auto mac = wifiSub.getMacAddress();
    TEST_ASSERT(mac == wdi::WlanMacAddress::titanDefault(), "Station MAC address must match Sovereign default");
    TEST_ASSERT(mac.toString() == "00:1A:7D:DA:72:01", "Station MAC string must be 00:1A:7D:DA:72:01");
    TEST_ASSERT(mac.isBroadcast() == false, "Station MAC must not be broadcast");

    // Stage 3: Hardware Radio Power State Control (Airplane Mode Toggle)
    TEST_ASSERT(wifiSub.isRadioEnabled() == true, "Radio must be enabled by default");
    wifiSub.setRadioState(false);
    TEST_ASSERT(wifiSub.isRadioEnabled() == false, "Radio must be disabled upon request");
    wifiSub.setRadioState(true);
    TEST_ASSERT(wifiSub.isRadioEnabled() == true, "Radio must be restored to enabled");

    // Stage 4: WDI Task Execution Engine: WDI_TASK_SCAN
    auto scanSt = wifiSub.executeTask(wdi::WDI_TASK_SCAN);
    TEST_ASSERT(scanSt == NtStatus::Success, "WDI_TASK_SCAN execution must succeed");
    auto stats = wifiSub.getStatistics();
    TEST_ASSERT(stats.scanOperations >= 1, "Scan operations counter must increment");

    // Stage 5: WDI BSS Scan Catalog Queries (6 GHz 320 MHz, 5 GHz 160 MHz, 2.4 GHz)
    auto bssList = wifiSub.getScanResults();
    TEST_ASSERT(bssList.size() >= 3, "BSS scan catalog must return at least 3 discovered networks");
    bool found6g = false;
    bool found5g = false;
    bool found2g = false;
    for (const auto& b : bssList) {
        if (b.band == wdi::DOT11_BAND_6GHZ && b.channelWidth == wdi::DOT11_BW_320MHZ) found6g = true;
        if (b.band == wdi::DOT11_BAND_5GHZ && b.channelWidth == wdi::DOT11_BW_160MHZ) found5g = true;
        if (b.band == wdi::DOT11_BAND_2_4GHZ) found2g = true;
    }
    TEST_ASSERT(found6g == true, "Discovered BSS catalog must include 6 GHz 320 MHz Wi-Fi 7 network");
    TEST_ASSERT(found5g == true, "Discovered BSS catalog must include 5 GHz 160 MHz network");
    TEST_ASSERT(found2g == true, "Discovered BSS catalog must include 2.4 GHz legacy network");

    // Stage 6: Security Suite Verification (WPA3-Personal SAE & WPA3-Enterprise GCMP-256)
    bool hasWpa3Sae = false;
    for (const auto& b : bssList) {
        if (b.authType == wdi::DOT11_AUTH_WPA3_SAE && b.cipherType == wdi::DOT11_CIPHER_GCMP_256) {
            hasWpa3Sae = true;
            break;
        }
    }
    TEST_ASSERT(hasWpa3Sae == true, "Wi-Fi 7 network must require WPA3-SAE with GCMP-256 encryption");

    // Stage 7: Wi-Fi 7 Multi-Link Operation (MLO) Device Context
    auto mlo = wifiSub.getMloContext();
    TEST_ASSERT(mlo.mode == wdi::MloLinkMode::Mlmr, "MLO mode must be MLMR / STR (Simultaneous Transmit & Receive)");
    TEST_ASSERT(mlo.staMldMac == mac, "Station MLD MAC must match adapter MAC");
    TEST_ASSERT(mlo.links.size() >= 2, "MLO context must configure at least 2 bonded links");

    // Stage 8: MLO Affiliated Links Configuration
    const auto& link0 = mlo.links[0];
    TEST_ASSERT(link0.linkId == 0, "Link 0 ID must be 0");
    TEST_ASSERT(link0.band == wdi::DOT11_BAND_6GHZ, "Link 0 band must be 6 GHz");
    TEST_ASSERT(link0.channelWidthMhz == 320, "Link 0 channel width must be 320 MHz");
    TEST_ASSERT(link0.modulation == wdi::DOT11_MOD_4096QAM, "Link 0 modulation must be 4096-QAM");
    TEST_ASSERT(link0.phyRateBps >= 5'000'000'000ULL, "Link 0 PHY rate must exceed 5 Gbps");

    const auto& link1 = mlo.links[1];
    TEST_ASSERT(link1.linkId == 1, "Link 1 ID must be 1");
    TEST_ASSERT(link1.band == wdi::DOT11_BAND_5GHZ, "Link 1 band must be 5 GHz");
    TEST_ASSERT(link1.channelWidthMhz == 160, "Link 1 channel width must be 160 MHz");
    TEST_ASSERT(link1.modulation == wdi::DOT11_MOD_4096QAM, "Link 1 modulation must be 4096-QAM");

    // Stage 9: Aggregate MLO PHY Throughput Evaluation
    uint64_t aggPhy = mlo.getAggregatePhyRateBps();
    TEST_ASSERT(aggPhy >= 8'000'000'000ULL, "Aggregate MLO PHY throughput must exceed 8 Gbps (8.64 Gbps)");

    // Stage 10: WDI Connection Task Execution (WDI_TASK_CONNECT)
    auto connSt = wifiSub.executeTask(wdi::WDI_TASK_CONNECT);
    TEST_ASSERT(connSt == NtStatus::Success, "WDI_TASK_CONNECT must succeed");
    TEST_ASSERT(wifiSub.isConnected() == true, "Adapter state must transition to Connected");
    TEST_ASSERT(wifiSub.getConnectedSsid() == "Sovereign-Quantum-6G", "Connected SSID must be Sovereign-Quantum-6G");

    // Stage 11: NetAdapterCx Ring Queues (Tx/Rx) Packet Transmission & Byte Accounting
    std::vector<uint8_t> testPayload(512, 0xEE);
    bool txLink0 = wifiSub.transmitFrame(testPayload, 0);
    TEST_ASSERT(txLink0 == true, "Frame transmission over MLO link 0 must succeed");
    bool txLink1 = wifiSub.transmitFrame(testPayload, 1);
    TEST_ASSERT(txLink1 == true, "Frame transmission over MLO link 1 must succeed");

    auto statsAfter = wifiSub.getStatistics();
    TEST_ASSERT(statsAfter.txPackets >= 2, "Transmitted packet counter must increment");
    TEST_ASSERT(statsAfter.txBytes >= 1024, "Transmitted byte counter must reflect submitted frames");
    TEST_ASSERT(statsAfter.mloAggregatedBytes >= 1024, "MLO aggregated bytes must match total payload");

    // Stage 12: WDI Disconnection Task Execution (WDI_TASK_DISCONNECT)
    auto discSt = wifiSub.executeTask(wdi::WDI_TASK_DISCONNECT);
    TEST_ASSERT(discSt == NtStatus::Success, "WDI_TASK_DISCONNECT must succeed");
    TEST_ASSERT(wifiSub.isConnected() == false, "Adapter state must transition to Disconnected");

    // Stage 13: Dynamic Loader C ABI Exports Verification
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("wdiwifi.sys", "WdiInitialize") != nullptr, "wdiwifi.sys WdiInitialize must exist");
    TEST_ASSERT(ldr.getExport("wdiwifi.sys", "WdiRegisterMiniportDriver") != nullptr, "wdiwifi.sys WdiRegisterMiniportDriver must exist");
    TEST_ASSERT(ldr.getExport("wdiwifi.sys", "WdiSendTaskCommand") != nullptr, "wdiwifi.sys WdiSendTaskCommand must exist");
    TEST_ASSERT(ldr.getExport("wdiwifi.sys", "WdiGetAdapterCapabilities") != nullptr, "wdiwifi.sys WdiGetAdapterCapabilities must exist");
    TEST_ASSERT(ldr.getExport("netadaptercx.sys", "NetAdapterCreate") != nullptr, "netadaptercx.sys NetAdapterCreate must exist");
    TEST_ASSERT(ldr.getExport("netadaptercx.sys", "NetAdapterStart") != nullptr, "netadaptercx.sys NetAdapterStart must exist");
    TEST_ASSERT(ldr.getExport("titanwifi.sys", "TitanWiFiInitialize") != nullptr, "titanwifi.sys TitanWiFiInitialize must exist");
    TEST_ASSERT(ldr.getExport("titanwifi.sys", "TitanWiFiTransmitFrame") != nullptr, "titanwifi.sys TitanWiFiTransmitFrame must exist");

    // Stage 14: SCM Service Records & Version Database Verification
    auto wdiSvc = scm::ServiceControlManager::get().getServiceRecord(L"wdiwifi");
    TEST_ASSERT(wdiSvc != nullptr, "wdiwifi service record must exist in SCM");
    TEST_ASSERT(wdiSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "wdiwifi must be a kernel driver");
    TEST_ASSERT(wdiSvc->startType == scm::SERVICE_BOOT_START, "wdiwifi must have boot start type");

    auto netAdpSvc = scm::ServiceControlManager::get().getServiceRecord(L"netadaptercx");
    TEST_ASSERT(netAdpSvc != nullptr, "netadaptercx service record must exist in SCM");
    TEST_ASSERT(netAdpSvc->startType == scm::SERVICE_BOOT_START, "netadaptercx must have boot start type");

    auto titanWifiSvc = scm::ServiceControlManager::get().getServiceRecord(L"titanwifi");
    TEST_ASSERT(titanWifiSvc != nullptr, "titanwifi service record must exist in SCM");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("wdiwifi.sys") != nullptr, "wdiwifi.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("netadaptercx.sys") != nullptr, "netadaptercx.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("titanwifi.sys") != nullptr, "titanwifi.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 159: Wi-Fi 7 (802.11be) & WDI NetAdapterCx Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Wi-Fi 7 (802.11be EHT) & WDI NetAdapterCx Miniport Subsystem\n";
    std::cout << "       Codename: TitanWiFi / NexusWiFi | Binary: wdiwifi.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_WiFi7_WDI_NetAdapterCx_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
