// ============================================================================
// Standalone Driver Verification Test: ucsi (TitanUCSI / NexusUCSI)
// Subsystem: USB Type-C (UCSI 2.1/3.0) & USB Power Delivery 3.1 Subsystem
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/ucsi.hpp"

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

void Test_USBTypeC_UCSI_PowerDelivery31_Subsystem() {
    std::cout << "[TEST] Starting Suite 163: USB Type-C (UCSI 2.1/3.0) & USB PD 3.1 240W EPR Subsystem...\n";

    // Initialize Subsystem & Register Components
    ucsi::InitializeUcsiSubsystem();
    auto& ucsiSub = ucsi::TitanUcsiSubsystem::Instance();
    TEST_ASSERT(ucsiSub.isInitialized() == true, "TitanUCSI subsystem must be initialized");

    // Stage 1: UCSI Specification Version Verification (Revision 3.0)
    uint32_t maj = 0, min = 0;
    ucsiSub.getVersion(&maj, &min);
    TEST_ASSERT(maj == 3 && min == 0, "UCSI specification version must be 3.0");

    // Stage 2: Platform Policy Manager (PPM) & Physical Connector Enumeration
    uint8_t connCount = ucsiSub.getConnectorCount();
    TEST_ASSERT(connCount == 4, "Platform Policy Manager must report 4 physical Type-C connectors");

    // Stage 3: Connector 1 (Left Rear) Capabilities & 240W EPR Support
    const auto* cap1 = ucsiSub.getConnectorCapability(1);
    TEST_ASSERT(cap1 != nullptr, "Connector 1 capability lookup must succeed");
    TEST_ASSERT(cap1->supportsDfp == true, "Connector 1 must support DFP (Host)");
    TEST_ASSERT(cap1->supportsUfp == true, "Connector 1 must support UFP (Device)");
    TEST_ASSERT(cap1->supportsSource == true, "Connector 1 must support Power Source");
    TEST_ASSERT(cap1->supportsSink == true, "Connector 1 must support Power Sink");
    TEST_ASSERT(cap1->supportsEpr240W == true, "Connector 1 must support 240W Extended Power Range (EPR)");
    TEST_ASSERT(cap1->supportsDisplayPortAltMode == true, "Connector 1 must support DisplayPort Alt Mode");
    TEST_ASSERT(cap1->supportsThunderboltAltMode == true, "Connector 1 must support Thunderbolt / USB4 Alt Mode");

    // Stage 4: Connector 1 Sink PDOs (Inbound Power Capabilities)
    TEST_ASSERT(cap1->sinkCapabilities.size() >= 8, "Connector 1 must advertise at least 8 Sink PDOs");
    bool found48v = false;
    bool foundAvs = false;
    for (const auto& pdo : cap1->sinkCapabilities) {
        if (pdo.type == ucsi::UsbPdPdoType::FixedSupply && pdo.voltageMillivolts == 48000 && pdo.maxPowerMilliwatts == 240000) {
            found48v = true;
        }
        if (pdo.type == ucsi::UsbPdPdoType::AdjustableVoltageSupply && pdo.maxPowerMilliwatts == 240000) {
            foundAvs = true;
        }
    }
    TEST_ASSERT(found48v == true, "Connector 1 must support Fixed 48V @ 5A = 240W EPR Sink PDO");
    TEST_ASSERT(foundAvs == true, "Connector 1 must support AVS 15V-48V 240W EPR Sink PDO");

    // Stage 5: Connector 1 Active Power Contract & Status
    const auto* st1 = ucsiSub.getConnectorStatus(1);
    TEST_ASSERT(st1 != nullptr, "Connector 1 status lookup must succeed");
    TEST_ASSERT(st1->isConnected == true, "Connector 1 must be connected (240W GaN Adapter)");
    TEST_ASSERT(st1->powerRole == ucsi::UcsiPowerRole::Sink, "Connector 1 must be in Sink role (charging host)");
    TEST_ASSERT(st1->isPowerContractActive == true, "Connector 1 must have an active power contract");
    TEST_ASSERT(st1->currentPowerRange == ucsi::UsbPdPowerRange::ExtendedPowerRange_EPR, "Connector 1 power range must be EPR");
    TEST_ASSERT(st1->negotiatedVoltageMv == 48000, "Negotiated voltage must be 48V (48,000 mV)");
    TEST_ASSERT(st1->negotiatedCurrentMa == 5000, "Negotiated current must be 5A (5,000 mA)");
    TEST_ASSERT(st1->negotiatedPowerMw == 240000, "Negotiated power must be 240,000 mW (240W)");
    TEST_ASSERT(st1->batteryChargingState == 1, "Battery charging state must be Charging");

    // Stage 6: Connector 1 Cable E-Marker Discovery (SOP' Communication)
    const auto* cb1 = ucsiSub.getCableInfo(1);
    TEST_ASSERT(cb1 != nullptr, "Connector 1 cable info must exist");
    TEST_ASSERT(cb1->hasElectronicMarker == true, "Connector 1 cable must contain E-Marker chip");
    TEST_ASSERT(cb1->maxVoltageMillivolts >= 48000, "Cable must be rated for >= 48V");
    TEST_ASSERT(cb1->maxCurrentMilliamps == 5000, "Cable must be rated for 5A");
    TEST_ASSERT(cb1->isEprCapable == true, "Cable must be EPR capable (240W rated)");
    TEST_ASSERT(cb1->maxDataSpeedGbps >= 80, "Cable must support 80 Gbps PAM3 high-speed signaling");

    // Stage 7: Connector 2 DisplayPort 2.1 UHBR20 Alt-Mode & Concurrent 65W PD Passthrough
    const auto* st2 = ucsiSub.getConnectorStatus(2);
    TEST_ASSERT(st2 != nullptr && st2->isConnected == true, "Connector 2 must be connected to external monitor");
    TEST_ASSERT(st2->activeAltMode == ucsi::UsbAltMode::DisplayPort21_UHBR20, "Connector 2 must be in DisplayPort 2.1 Alt Mode");
    TEST_ASSERT(st2->negotiatedPowerMw == 65000, "Connector 2 must negotiate 65W PD passthrough from monitor");

    // Stage 8: Connector 3 Peripheral Source Operation (15W External SSD)
    const auto* st3 = ucsiSub.getConnectorStatus(3);
    TEST_ASSERT(st3 != nullptr && st3->isConnected == true, "Connector 3 must be connected to external SSD");
    TEST_ASSERT(st3->powerRole == ucsi::UcsiPowerRole::Source, "Connector 3 must be in Source role (providing power)");
    TEST_ASSERT(st3->negotiatedPowerMw == 15000, "Connector 3 must deliver 15W (5V @ 3A)");
    const auto* cb3 = ucsiSub.getCableInfo(3);
    TEST_ASSERT(cb3 != nullptr && cb3->hasElectronicMarker == false, "Standard 15W cable does not require E-Marker");

    // Stage 9: Connector 4 Disconnected State & PPS Fast Charge Capability
    const auto* st4 = ucsiSub.getConnectorStatus(4);
    TEST_ASSERT(st4 != nullptr && st4->isConnected == false, "Connector 4 must report disconnected");
    const auto* cap4 = ucsiSub.getConnectorCapability(4);
    TEST_ASSERT(cap4 != nullptr, "Connector 4 capability must exist");
    bool foundPps = false;
    for (const auto& pdo : cap4->sourceCapabilities) {
        if (pdo.type == ucsi::UsbPdPdoType::ProgrammablePowerSupply) foundPps = true;
    }
    TEST_ASSERT(foundPps == true, "Connector 4 must support PPS (Programmable Power Supply)");

    // Stage 10: UCSI Mailbox Command Dispatcher: PPM_RESET (0x01)
    std::vector<uint8_t> resetOut;
    uint32_t cci = 0;
    NTSTATUS rSt = ucsiSub.executeUcsiCommand(ucsi::UcsiCommand::PpmReset, 0, {}, resetOut, &cci);
    TEST_ASSERT(rSt == STATUS_SUCCESS, "PPM_RESET command execution must succeed");
    TEST_ASSERT(cci & ucsi::UCSI_CCI_COMMAND_COMPLETED_INDICATOR, "CCI command completed indicator must be set");
    TEST_ASSERT(cci & ucsi::UCSI_CCI_RESET_COMPLETED_INDICATOR, "CCI reset completed indicator must be set");

    // Stage 11: UCSI Mailbox Command: GET_CAPABILITY (0x06)
    std::vector<uint8_t> capOut;
    NTSTATUS gSt = ucsiSub.executeUcsiCommand(ucsi::UcsiCommand::GetCapability, 0, {}, capOut, &cci);
    TEST_ASSERT(gSt == STATUS_SUCCESS, "GET_CAPABILITY command execution must succeed");
    TEST_ASSERT(capOut.size() >= 2 && capOut[0] == 4, "Capability payload must report 4 connectors");

    // Stage 12: Dynamic Role Swapping: Power Role Swap (PR_SWAP)
    auto prevPowerRole = st2->powerRole;
    bool swapPrOk = ucsiSub.executeRoleSwap(2, true, false);
    TEST_ASSERT(swapPrOk == true, "Power role swap on Connector 2 must succeed");
    TEST_ASSERT(st2->powerRole != prevPowerRole, "Power role must toggle following PR_SWAP");
    ucsiSub.executeRoleSwap(2, true, false); // Restore to original
    TEST_ASSERT(st2->powerRole == prevPowerRole, "Power role must restore to original");

    // Stage 13: Dynamic Role Swapping: Data Role Swap (DR_SWAP)
    auto prevDataRole = st2->dataRole;
    bool swapDrOk = ucsiSub.executeRoleSwap(2, false, true);
    TEST_ASSERT(swapDrOk == true, "Data role swap on Connector 2 must succeed");
    TEST_ASSERT(st2->dataRole != prevDataRole, "Data role must toggle following DR_SWAP");
    ucsiSub.executeRoleSwap(2, false, true); // Restore to original
    TEST_ASSERT(st2->dataRole == prevDataRole, "Data role must restore to original");

    // Stage 14: USB PD Power Contract Dynamic Renegotiation (140W EPR Contract)
    bool negoOk = ucsiSub.negotiatePowerContract(1, 28000, 5000); // 28V @ 5A = 140W
    TEST_ASSERT(negoOk == true, "Renegotiating power contract must succeed");
    TEST_ASSERT(st1->negotiatedVoltageMv == 28000, "Negotiated voltage must update to 28,000 mV");
    TEST_ASSERT(st1->negotiatedPowerMw == 140000, "Negotiated power must update to 140,000 mW (140W)");
    TEST_ASSERT(st1->currentPowerRange == ucsi::UsbPdPowerRange::ExtendedPowerRange_EPR, "140W contract must remain in EPR range");
    ucsiSub.negotiatePowerContract(1, 48000, 5000); // Restore to 240W

    // Stage 15: Dynamic Loader C ABI Driver Exports (ucsi.sys, usbc.sys, ppm.sys)
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("ucsi.sys", "UcsiInitialize") != nullptr, "ucsi.sys UcsiInitialize must exist");
    TEST_ASSERT(ldr.getExport("ucsi.sys", "UcsiGetVersion") != nullptr, "ucsi.sys UcsiGetVersion must exist");
    TEST_ASSERT(ldr.getExport("ucsi.sys", "UcsiGetConnectorCount") != nullptr, "ucsi.sys UcsiGetConnectorCount must exist");
    TEST_ASSERT(ldr.getExport("ucsi.sys", "UcsiGetConnectorStatus") != nullptr, "ucsi.sys UcsiGetConnectorStatus must exist");
    TEST_ASSERT(ldr.getExport("ucsi.sys", "UcsiGetConnectorCapability") != nullptr, "ucsi.sys UcsiGetConnectorCapability must exist");

    TEST_ASSERT(ldr.getExport("usbc.sys", "UsbcGetCableProperties") != nullptr, "usbc.sys UsbcGetCableProperties must exist");
    TEST_ASSERT(ldr.getExport("usbc.sys", "UsbcExecuteRoleSwap") != nullptr, "usbc.sys UsbcExecuteRoleSwap must exist");
    TEST_ASSERT(ldr.getExport("usbc.sys", "UsbcNegotiatePowerContract") != nullptr, "usbc.sys UsbcNegotiatePowerContract must exist");
    TEST_ASSERT(ldr.getExport("usbc.sys", "UsbcConfigureAlternateMode") != nullptr, "usbc.sys UsbcConfigureAlternateMode must exist");

    TEST_ASSERT(ldr.getExport("ppm.sys", "PpmSendCommand") != nullptr, "ppm.sys PpmSendCommand must exist");
    TEST_ASSERT(ldr.getExport("ppm.sys", "PpmGetTelemetry") != nullptr, "ppm.sys PpmGetTelemetry must exist");

    // Direct C ABI Calls Verification
    uint8_t abiConnCount = 0;
    NTSTATUS cSt = ucsi::UcsiGetConnectorCount(&abiConnCount);
    TEST_ASSERT(cSt == STATUS_SUCCESS && abiConnCount == 4, "UcsiGetConnectorCount C ABI call must succeed");

    ucsi::UcsiConnectorStatus abiStatus{};
    NTSTATUS sSt = ucsi::UcsiGetConnectorStatus(1, &abiStatus);
    TEST_ASSERT(sSt == STATUS_SUCCESS && abiStatus.isConnected == true, "UcsiGetConnectorStatus C ABI call must succeed");

    ucsi::UsbTypeCCableInfo abiCable{};
    NTSTATUS cbSt = ucsi::UsbcGetCableProperties(1, &abiCable);
    TEST_ASSERT(cbSt == STATUS_SUCCESS && abiCable.isEprCapable == true, "UsbcGetCableProperties C ABI call must succeed");

    // Stage 16: SCM Service Control Manager Records & Version Database Registrations
    auto ucsiSvc = scm::ServiceControlManager::get().getServiceRecord(L"ucsi");
    TEST_ASSERT(ucsiSvc != nullptr, "ucsi service record must exist in SCM");
    TEST_ASSERT(ucsiSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "ucsi must be a kernel driver");
    TEST_ASSERT(ucsiSvc->startType == scm::SERVICE_BOOT_START, "ucsi must have boot start type");

    auto usbcSvc = scm::ServiceControlManager::get().getServiceRecord(L"usbc");
    TEST_ASSERT(usbcSvc != nullptr, "usbc service record must exist in SCM");
    TEST_ASSERT(usbcSvc->startType == scm::SERVICE_BOOT_START, "usbc must have boot start type");

    auto ppmSvc = scm::ServiceControlManager::get().getServiceRecord(L"ppm");
    TEST_ASSERT(ppmSvc != nullptr, "ppm service record must exist in SCM");
    TEST_ASSERT(ppmSvc->startType == scm::SERVICE_BOOT_START, "ppm must have boot start type");

    auto& verDb = version::VersionDatabase::Instance();
    TEST_ASSERT(verDb.GetModuleInfo("ucsi.sys") != nullptr, "ucsi.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("usbc.sys") != nullptr, "usbc.sys must be registered in Version Database");
    TEST_ASSERT(verDb.GetModuleInfo("ppm.sys") != nullptr, "ppm.sys must be registered in Version Database");

    std::cout << "[TEST] Suite 163: USB Type-C (UCSI 2.1/3.0) & USB PD 3.1 240W EPR Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: USB Type-C (UCSI 2.1/3.0) & USB Power Delivery 3.1 Subsystem\n";
    std::cout << "       Codename: TitanUCSI / NexusUCSI | Binary: ucsi.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_USBTypeC_UCSI_PowerDelivery31_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
