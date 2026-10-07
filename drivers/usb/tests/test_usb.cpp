// ============================================================================
// Standalone Driver Verification Test: usb (TitanUSB / NexusUSB)
// Subsystem: Universal Serial Bus (USB 3.2 Gen 2) & xHCI 1.2 Host Controller
// ============================================================================

#include <iostream>
#include <cstdint>
#include <cassert>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <unordered_map>

#include "micant/usb.hpp"

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

void Test_UniversalSerialBus_USB_xHCI_Subsystem() {
    using namespace micant::usb;

    std::cout << "\n========================================================================\n";
    std::cout << "  Suite 151: Universal Serial Bus (USB 3.2 / xHCI) & Hub Subsystem      \n";
    std::cout << "========================================================================\n";

    // Stage 1: Subsystem Initialization & Host Controller Register Space
    InitializeUsbSubsystem();
    auto& sub = TitanUsbSubsystem::Instance();
    auto hc = sub.getPrimaryController();
    TEST_ASSERT(hc != nullptr, "Primary xHCI Host Controller must exist");
    TEST_ASSERT(hc->isRunning(), "xHCI Host Controller must be in RUNNING state (USBCMD.RS=1)");
    TEST_ASSERT(hc->getHciVersion() == 0x0120, "xHCI revision must be 1.2 (0x0120)");
    TEST_ASSERT(hc->getMaxSlots() == 32, "xHCI maximum slots must be 32");
    TEST_ASSERT(hc->getMaxPorts() == 8, "xHCI maximum root hub ports must be 8");

    // Stage 2: Root Hub Port Status & Default Device Attachments
    auto rh = hc->getRootHub();
    TEST_ASSERT(rh != nullptr, "Root Hub must exist");
    TEST_ASSERT(rh->getPortCount() == 8, "Root Hub port count must match 8");

    for (uint8_t p = 0; p < 8; ++p) {
        const auto& pStat = rh->getPortStatus(p);
        TEST_ASSERT(pStat.powered, "All root hub ports must be powered");
    }

    auto flashDev = rh->getAttachedDevice(0);
    auto mouseDev = rh->getAttachedDevice(1);
    auto serialDev = rh->getAttachedDevice(2);
    TEST_ASSERT(flashDev != nullptr, "Port 0 must have Mass Storage device attached");
    TEST_ASSERT(mouseDev != nullptr, "Port 1 must have HID Mouse device attached");
    TEST_ASSERT(serialDev != nullptr, "Port 2 must have CDC-ACM Serial device attached");

    // Stage 3: Standard Descriptor Verification & Parsing
    const auto& devDesc = flashDev->getDeviceDescriptor();
    TEST_ASSERT(devDesc.bLength == 18, "Device descriptor bLength must be 18");
    TEST_ASSERT(devDesc.bDescriptorType == DescriptorType::Device, "Descriptor type must be Device (0x01)");
    TEST_ASSERT(devDesc.bcdUSB == 0x0320, "bcdUSB must be 0x0320 for USB 3.2 SuperSpeed");
    TEST_ASSERT(devDesc.bDeviceClass == ClassCode::MassStorage, "Flash drive class must be Mass Storage (0x08)");
    TEST_ASSERT(devDesc.idVendor == 0x0781, "SanDisk VID must be 0x0781");
    TEST_ASSERT(devDesc.idProduct == 0x5583, "SanDisk Ultra PID must be 0x5583");

    // String Descriptors
    TEST_ASSERT(flashDev->getManufacturerString() == "SanDisk", "Manufacturer string must match");
    TEST_ASSERT(flashDev->getProductString() == "Ultra USB 3.0 Flash Drive", "Product string must match");
    TEST_ASSERT(!flashDev->getSerialNumber().empty(), "Serial number string must not be empty");

    // Stage 4: xHCI Command Ring & Event Ring Execution
    xhci::TRB enableCmd{};
    enableCmd.setType(xhci::TrbType::EnableSlotCmd);
    xhci::TRB compEvent{};
    bool cmdOk = hc->submitCommand(enableCmd, compEvent);
    TEST_ASSERT(cmdOk, "Submitting EnableSlotCmd to xHCI command ring must succeed");
    TEST_ASSERT(compEvent.getType() == xhci::TrbType::CommandCompletionEvent, "Must produce CommandCompletionEvent");
    TEST_ASSERT(compEvent.getCompletionCode() == xhci::CompCode::Success, "Completion code must be Success");
    uint8_t newSlot = compEvent.getSlotId();
    TEST_ASSERT(newSlot > 0, "Allocated slot ID must be non-zero");

    xhci::TRB addrCmd{};
    addrCmd.setType(xhci::TrbType::AddressDeviceCmd);
    addrCmd.setSlotId(flashDev->getSlotId());
    cmdOk = hc->submitCommand(addrCmd, compEvent);
    TEST_ASSERT(cmdOk && compEvent.getCompletionCode() == xhci::CompCode::Success, "AddressDeviceCmd must succeed");

    xhci::TRB cfgCmd{};
    cfgCmd.setType(xhci::TrbType::ConfigureEndpointCmd);
    cfgCmd.setSlotId(flashDev->getSlotId());
    cmdOk = hc->submitCommand(cfgCmd, compEvent);
    TEST_ASSERT(cmdOk && compEvent.getCompletionCode() == xhci::CompCode::Success, "ConfigureEndpointCmd must succeed");

    // Stage 5: Control Transfer Processing (Setup Stage + Data Stage + Status Stage)
    USB_DEFAULT_PIPE_SETUP_PACKET setupStatus{};
    setupStatus.bmRequestType = RequestType::Standard | RequestType::RecipientDevice | RequestType::DirectionIn;
    setupStatus.bRequest = StandardRequest::GET_STATUS;
    setupStatus.wLength = 2;
    uint8_t statusBuf[2]{};
    uint32_t transferred = 0;
    auto usbdSt = hc->executeControlTransfer(flashDev->getSlotId(), setupStatus, statusBuf, sizeof(statusBuf), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success, "Control transfer GET_STATUS must succeed");
    TEST_ASSERT(transferred == 2, "Transferred bytes for GET_STATUS must be 2");
    TEST_ASSERT((statusBuf[0] & 0x01) != 0, "Self-powered status bit must be set");

    USB_DEFAULT_PIPE_SETUP_PACKET setupGetCfg{};
    setupGetCfg.bmRequestType = RequestType::Standard | RequestType::RecipientDevice | RequestType::DirectionIn;
    setupGetCfg.bRequest = StandardRequest::GET_CONFIGURATION;
    setupGetCfg.wLength = 1;
    uint8_t cfgVal = 0;
    usbdSt = hc->executeControlTransfer(flashDev->getSlotId(), setupGetCfg, &cfgVal, 1, transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && cfgVal == 1, "GET_CONFIGURATION must return active configuration 1");

    // Stage 6: USB Mass Storage Bulk-Only Transport (BOT) SCSI Protocol
    auto msc = std::dynamic_pointer_cast<UsbMassStorageDevice>(flashDev);
    TEST_ASSERT(msc != nullptr, "Must cast to UsbMassStorageDevice");
    TEST_ASSERT(msc->getCapacitySectors() == 65536, "Flash drive capacity must be 65536 sectors");

    // BOT CBW for SCSI INQUIRY (0x12)
    uint8_t inqCbw[31]{};
    *reinterpret_cast<uint32_t*>(inqCbw) = 0x43425355; // 'USBC'
    *reinterpret_cast<uint32_t*>(inqCbw + 4) = 0x88776655; // Tag
    *reinterpret_cast<uint32_t*>(inqCbw + 8) = 36; // 36 bytes expected
    inqCbw[12] = 0x80; // Data IN
    inqCbw[14] = 6;    // CDB length 6
    inqCbw[15] = 0x12; // INQUIRY
    inqCbw[19] = 36;

    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x01, inqCbw, sizeof(inqCbw), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 31, "CBW transfer must succeed");

    uint8_t inqData[36]{};
    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x82, inqData, sizeof(inqData), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 36, "Inquiry data reception must succeed");
    TEST_ASSERT(std::memcmp(&inqData[8], "SanDisk ", 8) == 0, "SCSI Vendor must be SanDisk");

    uint8_t mscCsw[13]{};
    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x82, mscCsw, sizeof(mscCsw), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 13, "CSW reception must succeed");
    TEST_ASSERT(*reinterpret_cast<uint32_t*>(mscCsw) == 0x53425355, "CSW signature must be 'USBS'");
    TEST_ASSERT(*reinterpret_cast<uint32_t*>(mscCsw + 4) == 0x88776655, "CSW tag must match CBW tag");
    TEST_ASSERT(mscCsw[12] == 0, "CSW status must be 0 (Passed)");

    // BOT Sector Write (WRITE 10) and Sector Read (READ 10)
    uint8_t writeCbw[31]{};
    *reinterpret_cast<uint32_t*>(writeCbw) = 0x43425355;
    *reinterpret_cast<uint32_t*>(writeCbw + 4) = 0x99001122;
    *reinterpret_cast<uint32_t*>(writeCbw + 8) = 512;
    writeCbw[12] = 0x00; // Data OUT
    writeCbw[14] = 10;   // CDB len 10
    writeCbw[15] = 0x2A; // WRITE 10
    writeCbw[17] = 0; writeCbw[18] = 0; writeCbw[19] = 0; writeCbw[20] = 50; // LBA 50
    writeCbw[22] = 0; writeCbw[23] = 1; // 1 sector

    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x01, writeCbw, sizeof(writeCbw), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success, "WRITE 10 CBW must succeed");

    std::vector<uint8_t> testSector(512, 0xAB);
    testSector[0] = 'M'; testSector[1] = 'I'; testSector[2] = 'C'; testSector[3] = 'A';
    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x01, testSector.data(), 512, transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 512, "Sector write payload transfer must succeed");

    // READ 10 on LBA 50
    uint8_t readCbw[31]{};
    *reinterpret_cast<uint32_t*>(readCbw) = 0x43425355;
    *reinterpret_cast<uint32_t*>(readCbw + 4) = 0x99001123;
    *reinterpret_cast<uint32_t*>(readCbw + 8) = 512;
    readCbw[12] = 0x80; // Data IN
    readCbw[14] = 10;   // CDB len 10
    readCbw[15] = 0x28; // READ 10
    readCbw[17] = 0; readCbw[18] = 0; readCbw[19] = 0; readCbw[20] = 50; // LBA 50
    readCbw[22] = 0; readCbw[23] = 1;

    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x01, readCbw, sizeof(readCbw), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success, "READ 10 CBW must succeed");

    std::vector<uint8_t> readSector(512, 0);
    usbdSt = hc->executeTransfer(flashDev->getSlotId(), 0x82, readSector.data(), 512, transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 512, "Sector read payload transfer must succeed");
    TEST_ASSERT(std::memcmp(readSector.data(), testSector.data(), 512) == 0, "Read data must exactly match written sector payload");

    // Stage 7: USB Human Interface Device (HID) Mouse Event Pipeline
    auto hidMouse = std::dynamic_pointer_cast<UsbHidMouseDevice>(mouseDev);
    TEST_ASSERT(hidMouse != nullptr, "Must cast to UsbHidMouseDevice");
    TEST_ASSERT(hidMouse->getDeviceDescriptor().bDeviceClass == ClassCode::HID, "Mouse class must be HID (0x03)");

    hidMouse->queueInputEvent(0x01 | 0x02, -25, 40, 2); // Left+Right buttons, dx=-25, dy=40, wheel=2
    UsbMouseReport mouseRep{};
    usbdSt = hc->executeTransfer(mouseDev->getSlotId(), 0x81, reinterpret_cast<uint8_t*>(&mouseRep), sizeof(mouseRep), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == sizeof(UsbMouseReport), "HID report read must succeed");
    TEST_ASSERT(mouseRep.buttons == 0x03, "Buttons must be Left+Right (0x03)");
    TEST_ASSERT(mouseRep.xDelta == -25, "X delta must match -25");
    TEST_ASSERT(mouseRep.yDelta == 40, "Y delta must match 40");
    TEST_ASSERT(mouseRep.wheel == 2, "Wheel delta must match 2");

    // Stage 8: USB CDC-ACM Virtual Serial Port (COM3)
    auto cdc = std::dynamic_pointer_cast<UsbCdcAcmDevice>(serialDev);
    TEST_ASSERT(cdc != nullptr, "Must cast to UsbCdcAcmDevice");

    cdc->writeSerialData("AT+GMR\r\n");
    uint8_t cdcInBuf[32]{};
    usbdSt = hc->executeTransfer(serialDev->getSlotId(), 0x83, cdcInBuf, sizeof(cdcInBuf), transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 8, "CDC serial data read must succeed");
    TEST_ASSERT(std::string(reinterpret_cast<char*>(cdcInBuf), transferred) == "AT+GMR\r\n", "Serial received text must match AT+GMR");

    const char* hostMsg = "OK\r\n";
    usbdSt = hc->executeTransfer(serialDev->getSlotId(), 0x02, const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(hostMsg)), 4, transferred);
    TEST_ASSERT(usbdSt == UsbdStatus::Success && transferred == 4, "Host to device CDC transmission must succeed");
    TEST_ASSERT(cdc->readReceivedSerialData() == "OK\r\n", "Device received buffer must match host sent message");

    // Stage 9: WinUSB Userland Client Architecture (winusb.dll Parity)
    win32::HANDLE hDev1 = reinterpret_cast<win32::HANDLE>(1);
    WINUSB_INTERFACE_HANDLE hWinUsb = nullptr;
    auto bInit = WinUsb_Initialize(hDev1, &hWinUsb);
    TEST_ASSERT(bInit && hWinUsb != nullptr, "WinUsb_Initialize must return TRUE with valid handle");

    USB_INTERFACE_DESCRIPTOR ifaceDesc{};
    auto bQuery = WinUsb_QueryInterfaceSettings(hWinUsb, 0, &ifaceDesc);
    TEST_ASSERT(bQuery, "WinUsb_QueryInterfaceSettings must succeed");
    TEST_ASSERT(ifaceDesc.bInterfaceClass == ClassCode::MassStorage, "Interface class must be Mass Storage");

    WINUSB_PIPE_INFORMATION pipeInfo{};
    auto bPipe0 = WinUsb_QueryPipe(hWinUsb, 0, 0, &pipeInfo);
    TEST_ASSERT(bPipe0 && pipeInfo.PipeId == 0x01, "First pipe must be EP1 OUT");
    TEST_ASSERT(pipeInfo.PipeType == 2, "Pipe type must be Bulk (2)");

    uint32_t timeoutVal = 4500;
    auto bSetPol = WinUsb_SetPipePolicy(hWinUsb, 0x01, WinUsbPolicy::PIPE_TRANSFER_TIMEOUT, sizeof(timeoutVal), &timeoutVal);
    TEST_ASSERT(bSetPol, "WinUsb_SetPipePolicy must return TRUE");

    uint32_t retrievedTimeout = 0;
    ULONG polLen = sizeof(retrievedTimeout);
    auto bGetPol = WinUsb_GetPipePolicy(hWinUsb, 0x01, WinUsbPolicy::PIPE_TRANSFER_TIMEOUT, &polLen, &retrievedTimeout);
    TEST_ASSERT(bGetPol && retrievedTimeout == 4500, "Retrieved pipe timeout policy must match 4500ms");

    auto bFree = WinUsb_Free(hWinUsb);
    TEST_ASSERT(bFree, "WinUsb_Free must return TRUE");

    // Stage 10: Dynamic Hotplug Attachment, Port Reset & Removal
    bool hpAttach = sub.hotplugAttach(4, "mouse");
    TEST_ASSERT(hpAttach, "Hotplug attach to Port 4 must succeed");
    auto p4Dev = rh->getAttachedDevice(4);
    TEST_ASSERT(p4Dev != nullptr, "Port 4 device must not be null");
    TEST_ASSERT(rh->getPortStatus(4).connected && rh->getPortStatus(4).enabled, "Port 4 must be connected and enabled");
    TEST_ASSERT(p4Dev->getDeviceDescriptor().bDeviceClass == ClassCode::HID, "Attached device must be HID mouse");

    bool hpDetach = sub.hotplugDetach(4);
    TEST_ASSERT(hpDetach, "Hotplug detach from Port 4 must succeed");
    TEST_ASSERT(rh->getAttachedDevice(4) == nullptr, "Port 4 must be empty after detachment");
    TEST_ASSERT(!rh->getPortStatus(4).connected, "Port 4 connected flag must be false");

    // Stage 11: Dynamic Loader Exports & Service Control Manager Parity
    auto& ldr = ldr::DynamicLoader::get();
    TEST_ASSERT(ldr.getExport("winusb.dll", "WinUsb_Initialize") != nullptr, "winusb.dll WinUsb_Initialize export must be registered");
    TEST_ASSERT(ldr.getExport("winusb.dll", "WinUsb_ReadPipe") != nullptr, "winusb.dll WinUsb_ReadPipe export must be registered");
    TEST_ASSERT(ldr.getExport("winusb.dll", "WinUsb_WritePipe") != nullptr, "winusb.dll WinUsb_WritePipe export must be registered");

    auto xhciSvc = scm::ServiceControlManager::get().getServiceRecord(L"usbxhci");
    TEST_ASSERT(xhciSvc != nullptr, "usbxhci service record must exist in SCM");
    TEST_ASSERT(xhciSvc->serviceType == scm::SERVICE_KERNEL_DRIVER, "usbxhci service type must be kernel driver");

    auto hubSvc = scm::ServiceControlManager::get().getServiceRecord(L"usbhub3");
    TEST_ASSERT(hubSvc != nullptr, "usbhub3 service record must exist in SCM");

    // Stage 12: Version Database Parity
    auto winusbVer = version::VersionDatabase::Instance().GetModuleInfo("winusb.dll");
    TEST_ASSERT(winusbVer != nullptr, "winusb.dll must be registered in Version Database");
    TEST_ASSERT(winusbVer->stringTable.count("FileVersion") > 0, "winusb.dll FileVersion must exist");

    std::cout << "[TEST] Suite 151: Universal Serial Bus (USB 3.2 / xHCI) & Hub Subsystem PASSED.\n";
}

int main() {
    std::cout << "========================================================================\n";
    std::cout << "       MicaNT Standalone Driver Test: Universal Serial Bus (USB 3.2 Gen 2) & xHCI 1.2 Host Controller\n";
    std::cout << "       Codename: TitanUSB / NexusUSB | Binary: usbxhci.sys\n";
    std::cout << "========================================================================\n\n";

    RUN_TEST(Test_UniversalSerialBus_USB_xHCI_Subsystem);

    std::cout << "\n------------------------------------------------------------------------\n";
    std::cout << "Summary: " << g_PassedTests << " Passed, " << g_FailedTests << " Failed\n";
    std::cout << "------------------------------------------------------------------------\n";

    return (g_FailedTests == 0) ? 0 : 1;
}
