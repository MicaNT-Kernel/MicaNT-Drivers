// ============================================================================
// Standalone Driver Verification Test: bluetooth (TitanBTH / NexusBTH)
// Subsystem: Bluetooth 5.4 & LE Audio Kernel Port Driver Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/bthport.hpp"

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

void Test_Bluetooth54_KernelPortDriver_Subsystem() {
    std::cout << "[TEST] Starting Suite 158: Bluetooth 5.4 & LE Audio Kernel Port Driver Subsystem...\n";

    // Stage 1: Subsystem Initialization & Local Radio BD_ADDR Verification
    bth::InitializeBluetoothKernelSubsystem();
    auto& bthSub = bth::TitanBluetoothSubsystem::Instance();
    TEST_ASSERT(bthSub.isInitialized() == true, "TitanBTH subsystem must be initialized");
    auto localAddr = bthSub.getRadioAddress();
    TEST_ASSERT(localAddr == bth::BdAddress::sovereignRadioDefault(), "Local BD_ADDR must match Sovereign default");
    TEST_ASSERT(localAddr.toString() == "00:1A:7D:DA:71:01", "Local BD_ADDR string format must be 00:1A:7D:DA:71:01");

    // Stage 2: HCI Version, LMP & Controller Identity Reporting
    TEST_ASSERT(bthSub.getHciVersion() == bth::BTH_VERSION_5_4, "HCI Version must be 0x0D (Bluetooth 5.4)");
    TEST_ASSERT(bthSub.getRadioName().find("Sovereign Bluetooth 5.4") != std::string::npos, "Radio name must identify as Sovereign Bluetooth 5.4");

    // Stage 3: Standard HCI Command Processing Engine
    // 3a. HCI Reset
    auto resetEvt = bthSub.executeHciCommand(bth::HCI_OP_RESET);
    TEST_ASSERT(resetEvt.size() >= 6, "HCI Reset event size must be at least 6 bytes");
    TEST_ASSERT(resetEvt[0] == bth::HCI_EVT_COMMAND_COMPLETE, "HCI Reset must return Command Complete event");
    TEST_ASSERT(resetEvt[5] == 0x00, "HCI Reset status must be 0 (Success)");

    // 3b. Read BD_ADDR
    auto bdAddrEvt = bthSub.executeHciCommand(bth::HCI_OP_READ_BD_ADDR);
    TEST_ASSERT(bdAddrEvt.size() >= 12, "Read BD_ADDR event size must be at least 12 bytes");
    TEST_ASSERT(bdAddrEvt[5] == 0x00, "Read BD_ADDR status must be Success");
    bth::BdAddress readAddr;
    std::memcpy(readAddr.bytes, &bdAddrEvt[6], 6);
    TEST_ASSERT(readAddr == localAddr, "HCI Read BD_ADDR returned address must match radio address");

    // 3c. Read Local Version Info
    auto verEvt = bthSub.executeHciCommand(bth::HCI_OP_READ_LOCAL_VERSION_INFO);
    TEST_ASSERT(verEvt.size() >= 14, "Read Local Version event size must be at least 14 bytes");
    TEST_ASSERT(verEvt[5] == 0x00, "Read Local Version status must be Success");
    TEST_ASSERT(verEvt[6] == bth::BTH_VERSION_5_4, "HCI Version in event payload must be 0x0D");

    // Stage 4: Scan Enable Modes (Inquiry & Page Scan)
    uint8_t scanParam = bth::BTH_SCAN_INQUIRY_AND_PAGE;
    auto scanEvt = bthSub.executeHciCommand(bth::HCI_OP_WRITE_SCAN_ENABLE, std::span<const uint8_t>(&scanParam, 1));
    TEST_ASSERT(scanEvt[0] == bth::HCI_EVT_COMMAND_COMPLETE, "Write Scan Enable must complete");
    TEST_ASSERT(bthSub.getScanMode() == bth::BTH_SCAN_INQUIRY_AND_PAGE, "Scan mode must be Inquiry and Page Scan");

    // Stage 5: L2CAP Signaling & Dynamic Channel Allocation (CID 0x0040+)
    uint16_t localCid = bthSub.openL2capChannel(0x0001, bth::L2CAP_PSM_RFCOMM, 0x0050);
    TEST_ASSERT(localCid >= bth::L2CAP_CID_DYNAMIC_START, "Allocated L2CAP CID must be in dynamic range (>= 0x0040)");
    const auto* chan = bthSub.getL2capChannel(localCid);
    TEST_ASSERT(chan != nullptr, "L2CAP channel lookup must succeed");
    TEST_ASSERT(chan->state == bth::L2capChannelState::Open, "L2CAP channel state must be Open");
    TEST_ASSERT(chan->psm == bth::L2CAP_PSM_RFCOMM, "L2CAP channel PSM must be RFCOMM (0x0003)");
    TEST_ASSERT(chan->mtu == 672, "L2CAP channel MTU must default to 672");

    // Stage 6: L2CAP Channel Teardown & Recycling
    bool closed = bthSub.closeL2capChannel(localCid);
    TEST_ASSERT(closed == true, "Closing L2CAP channel must succeed");
    TEST_ASSERT(bthSub.getL2capChannel(localCid) == nullptr, "Closed L2CAP channel must be removed");

    // Stage 7: RFCOMM Virtual Serial Port Creation (COM4 / Server Channel 1)
    uint16_t rfcommL2capCid = bthSub.openL2capChannel(0x0001, bth::L2CAP_PSM_RFCOMM, 0x0051);
    uint8_t chNum = bthSub.createRfcommPort(rfcommL2capCid, 1);
    TEST_ASSERT(chNum == 1, "RFCOMM server channel must be 1");
    const auto* rfPort = bthSub.getRfcommPort(chNum);
    TEST_ASSERT(rfPort != nullptr, "RFCOMM port lookup must succeed");
    TEST_ASSERT(rfPort->state == bth::RfcommPortState::Connected, "RFCOMM port state must be Connected");
    TEST_ASSERT(rfPort->baudRate == 115200, "RFCOMM baud rate must default to 115200 bps");
    TEST_ASSERT(rfPort->comPortName == L"COM4", "RFCOMM port name must be COM4");

    // Stage 8: RFCOMM Serial Data Streaming & Byte Accounting
    std::vector<uint8_t> testPayload = { 'A', 'T', 'Z', '\r', '\n' };
    size_t bytesSent = bthSub.transmitRfcommData(chNum, testPayload);
    TEST_ASSERT(bytesSent == testPayload.size(), "All RFCOMM payload bytes must be transmitted");
    rfPort = bthSub.getRfcommPort(chNum);
    TEST_ASSERT(rfPort->bytesSent == testPayload.size(), "RFCOMM port byte accounting must match payload size");

    // Stage 9: Bluetooth 5.4 LE Audio Connected Isochronous Stream (CIS) Configuration
    auto leAudio = bthSub.getLeAudioConfig();
    TEST_ASSERT(leAudio.active == true, "LE Audio stream must be active");
    TEST_ASSERT(leAudio.type == bth::LeAudioStreamType::UnicastCis, "LE Audio type must be Unicast CIS");
    TEST_ASSERT(leAudio.sampleRateHz == 48000, "LE Audio sample rate must be 48 kHz");
    TEST_ASSERT(leAudio.channels == 2, "LE Audio channel count must be stereo (2)");
    TEST_ASSERT(leAudio.isoHandle == 0x0010, "LE Audio ISO handle must be 0x0010");

    // Stage 10: LE Audio LC3 Codec Isochronous Frame Streaming
    std::vector<uint8_t> lc3Frame(120, 0xAA); // 120-byte 10ms LC3 audio frame
    bool isoSuccess = bthSub.transmitIsoStreamData(0x0010, lc3Frame);
    TEST_ASSERT(isoSuccess == true, "Transmission of LC3 isochronous audio frame must succeed");
    auto leAudioAfter = bthSub.getLeAudioConfig();
    TEST_ASSERT(leAudioAfter.framesTransmitted >= 1, "Frames transmitted counter must increment");
    TEST_ASSERT(leAudioAfter.bytesTransmitted >= 120, "Bytes transmitted counter must reflect LC3 frame size");

    // Stage 11: Bluetooth Bus Enumerator (bthenum.sys) Device Tree Queries
    auto devList = bthSub.getDiscoveredDevices();
    TEST_ASSERT(devList.size() >= 2, "At least 2 Bluetooth devices must be registered");
    bool foundKb = false;
    bool foundAudio = false;
    for (const auto& dev : devList) {
        if (dev.profile == bth::BthDeviceProfile::HidKeyboard) foundKb = true;
        if (dev.profile == bth::BthDeviceProfile::AudioLeLc3) foundAudio = true;
    }
    TEST_ASSERT(foundKb == true, "Titan Wireless Mechanical Keyboard (HID) must be enumerated");
    TEST_ASSERT(foundAudio == true, "PrismAudio Studio Auracast Headset (LE Audio) must be enumerated");

    // Stage 12: Dynamic Loader C ABI Exports Verification
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("bthport.sys", "BthPortInitialize") != nullptr, "bthport.sys BthPortInitialize must exist");
    TEST_ASSERT(ldr.getExport("bthport.sys", "BthPortSendHciCommand") != nullptr, "bthport.sys BthPortSendHciCommand must exist");
    TEST_ASSERT(ldr.getExport("bthport.sys", "BthPortOpenL2capChannel") != nullptr, "bthport.sys BthPortOpenL2capChannel must exist");
    TEST_ASSERT(ldr.getExport("bthport.sys", "BthPortCloseL2capChannel") != nullptr, "bthport.sys BthPortCloseL2capChannel must exist");
    TEST_ASSERT(ldr.getExport("bthport.sys", "BthPortCreateRfcommPort") != nullptr, "bthport.sys BthPortCreateRfcommPort must exist");
    TEST_ASSERT(ldr.getExport("bthusb.sys", "BthUsbInitialize") != nullptr, "bthusb.sys BthUsbInitialize must exist");
    TEST_ASSERT(ldr.getExport("bthenum.sys", "BthEnumEnumerateDevices") != nullptr, "bthenum.sys BthEnumEnumerateDevices must exist");
    TEST_ASSERT(ldr.getExport("rfcomm.sys", "BthPortCreateRfcommPort") != nullptr, "rfcomm.sys BthPortCreateRfcommPort must exist");

    // Stage 13: SCM Service Records & Version Database Verification
    auto bthPortSvc = scm::ServiceControlManager::get().getServiceRecord(L"bthport");
    TEST_ASSERT(bthPortSvc != nullptr, "bthport service record must exist in SCM");
    TEST_ASSERT(bthPortSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "bthport must be a kernel driver");
    TEST_ASSERT(bthPortSvc->startType == scm::SERVICE_BOOT_START, "bthport must have boot start type");

    auto bthUsbSvc = scm::ServiceControlManager::get().getServiceRecord(L"bthusb");
    TEST_ASSERT(bthUsbSvc != nullptr, "bthusb service record must exist in SCM");
    TEST_ASSERT(bthUsbSvc->startType == scm::SERVICE_SYSTEM_START, "bthusb must have system start type");

    auto rfcommSvc = scm::ServiceControlManager::get().getServiceRecord(L"rfcomm");
    TEST_ASSERT(rfcommSvc != nullptr, "rfcomm service record must exist in SCM");

    auto bthEnumSvc = scm::ServiceControlManager::get().getServiceRecord(L"bthenum");
    TEST_ASSERT(bthEnumSvc != nullptr, "bthenum service record must exist in SCM");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("bthport.sys") != nullptr, "bthport.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("bthusb.sys") != nullptr, "bthusb.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("rfcomm.sys") != nullptr, "rfcomm.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("bthenum.sys") != nullptr, "bthenum.sys must be registered in Version Database");

    // Stage 14: Telemetry Statistics Aggregation & C ABI Functionality
    auto telem = bthSub.getTelemetry();
    TEST_ASSERT(telem.hciCommandsSent >= 3, "Telemetry must record at least 3 HCI commands");
    TEST_ASSERT(telem.hciEventsReceived >= 3, "Telemetry must record at least 3 HCI events");
    TEST_ASSERT(telem.aclBytesSent > 0, "Telemetry must record ACL transmitted bytes");
    TEST_ASSERT(telem.isoBytesSent > 0, "Telemetry must record ISO transmitted bytes");

    uint32_t devCount = 0;
    int32_t enumRes = bth::BthEnumEnumerateDevices(&devCount);
    TEST_ASSERT(enumRes == 0 && devCount >= 2, "BthEnumEnumerateDevices C ABI must succeed and report devices");

    std::cout << "[TEST] Suite 158: Bluetooth 5.4 & LE Audio Kernel Port Driver Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Bluetooth 5.4 & LE Audio Kernel Port Driver Subsystem\n";
    std::cout << "       Codename: TitanBTH / NexusBTH | Binary: bthport.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_Bluetooth54_KernelPortDriver_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
