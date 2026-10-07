// ============================================================================
// MicaNT: Sovereign Universal Serial Bus (USB 3.2 / xHCI) & Hub Architecture
// File: include/micant/usb.hpp
// Sovereign System Domain: TitanUSB / NexusUSB
//
// Description:
//   Clean-room implementation of the Microsoft Windows Universal Serial Bus (USB)
//   architecture, eXtensible Host Controller Interface (xHCI 1.2), USB Hub
//   topology, USB Request Block (URB) execution engine, USB Mass Storage (BOT),
//   USB HID, USB CDC-ACM virtual serial port, and WinUSB userland client
//   subsystem (winusb.dll).
//
// Clean-Room Engineering Reference & Standards:
//   - USB Implementers Forum: Universal Serial Bus 3.2 Specification
//   - Intel Corporation: eXtensible Host Controller Interface for USB (xHCI 1.2)
//   - USB Implementers Forum: Universal Serial Bus Mass Storage Class (BOT v1.0)
//   - USB Implementers Forum: Device Class Definition for HID (v1.11)
//   - Microsoft Open win32metadata repository: Windows.Win32.Devices.Usb
//   - ISO/IEC 14882:2023 C++ Standard
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <array>
#include <unordered_map>
#include <map>
#include <queue>
#include <mutex>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "janusldr.hpp"
#include "scm.hpp"
#include "version.hpp"
#include "vanguarddriver.hpp"

namespace micant::usb {

// ============================================================================
// 1. USB Speeds, Classes, and Descriptors
// ============================================================================

enum class UsbSpeed : uint8_t {
    Unknown       = 0,
    LowSpeed      = 1, // 1.5 Mbps (USB 1.1)
    FullSpeed     = 2, // 12 Mbps  (USB 1.1 / 2.0)
    HighSpeed     = 3, // 480 Mbps (USB 2.0)
    SuperSpeed    = 4, // 5 Gbps   (USB 3.0 / 3.1 Gen 1)
    SuperSpeedPlus= 5  // 10/20 Gbps (USB 3.1 Gen 2 / 3.2)
};

inline const char* UsbSpeedToString(UsbSpeed speed) noexcept {
    switch (speed) {
        case UsbSpeed::LowSpeed:       return "LowSpeed (1.5 Mbps)";
        case UsbSpeed::FullSpeed:      return "FullSpeed (12 Mbps)";
        case UsbSpeed::HighSpeed:      return "HighSpeed (480 Mbps)";
        case UsbSpeed::SuperSpeed:     return "SuperSpeed (5 Gbps)";
        case UsbSpeed::SuperSpeedPlus: return "SuperSpeedPlus (10+ Gbps)";
        default:                       return "Unknown";
    }
}

namespace ClassCode {
    inline constexpr uint8_t Composite        = 0x00;
    inline constexpr uint8_t Audio            = 0x01;
    inline constexpr uint8_t Communications   = 0x02;
    inline constexpr uint8_t HID              = 0x03;
    inline constexpr uint8_t Physical         = 0x05;
    inline constexpr uint8_t Image            = 0x06;
    inline constexpr uint8_t Printer          = 0x07;
    inline constexpr uint8_t MassStorage      = 0x08;
    inline constexpr uint8_t Hub              = 0x09;
    inline constexpr uint8_t CDCData          = 0x0A;
    inline constexpr uint8_t SmartCard        = 0x0B;
    inline constexpr uint8_t Video            = 0x0E;
    inline constexpr uint8_t Wireless         = 0xE0;
    inline constexpr uint8_t Miscellaneous    = 0xEF;
    inline constexpr uint8_t VendorSpecific   = 0xFF;
}

namespace DescriptorType {
    inline constexpr uint8_t Device                     = 0x01;
    inline constexpr uint8_t Configuration              = 0x02;
    inline constexpr uint8_t String                     = 0x03;
    inline constexpr uint8_t Interface                  = 0x04;
    inline constexpr uint8_t Endpoint                   = 0x05;
    inline constexpr uint8_t DeviceQualifier            = 0x06;
    inline constexpr uint8_t OtherSpeedConfiguration    = 0x07;
    inline constexpr uint8_t InterfacePower             = 0x08;
    inline constexpr uint8_t OTG                        = 0x09;
    inline constexpr uint8_t Debug                      = 0x0A;
    inline constexpr uint8_t InterfaceAssociation       = 0x0B;
    inline constexpr uint8_t BOS                        = 0x0F;
    inline constexpr uint8_t DeviceCapability           = 0x10;
    inline constexpr uint8_t HID                        = 0x21;
    inline constexpr uint8_t HIDReport                  = 0x22;
    inline constexpr uint8_t SuperSpeedEndpointCompanion= 0x30;
}

namespace RequestType {
    inline constexpr uint8_t Standard = 0x00;
    inline constexpr uint8_t Class    = 0x20;
    inline constexpr uint8_t Vendor   = 0x40;
    inline constexpr uint8_t Mask     = 0x60;

    inline constexpr uint8_t RecipientDevice    = 0x00;
    inline constexpr uint8_t RecipientInterface = 0x01;
    inline constexpr uint8_t RecipientEndpoint  = 0x02;
    inline constexpr uint8_t RecipientOther     = 0x03;
    inline constexpr uint8_t RecipientMask      = 0x1F;

    inline constexpr uint8_t DirectionOut = 0x00;
    inline constexpr uint8_t DirectionIn  = 0x80;
}

namespace StandardRequest {
    inline constexpr uint8_t GET_STATUS        = 0x00;
    inline constexpr uint8_t CLEAR_FEATURE     = 0x01;
    inline constexpr uint8_t SET_FEATURE       = 0x03;
    inline constexpr uint8_t SET_ADDRESS       = 0x05;
    inline constexpr uint8_t GET_DESCRIPTOR    = 0x06;
    inline constexpr uint8_t SET_DESCRIPTOR    = 0x07;
    inline constexpr uint8_t GET_CONFIGURATION = 0x08;
    inline constexpr uint8_t SET_CONFIGURATION = 0x09;
    inline constexpr uint8_t GET_INTERFACE     = 0x0A;
    inline constexpr uint8_t SET_INTERFACE     = 0x0B;
    inline constexpr uint8_t SYNCH_FRAME       = 0x0C;
}

#pragma pack(push, 1)

struct USB_DEVICE_DESCRIPTOR {
    uint8_t  bLength{18};
    uint8_t  bDescriptorType{DescriptorType::Device};
    uint16_t bcdUSB{0x0320}; // USB 3.2
    uint8_t  bDeviceClass{0};
    uint8_t  bDeviceSubClass{0};
    uint8_t  bDeviceProtocol{0};
    uint8_t  bMaxPacketSize0{64}; // 64 for USB2/3 EP0 or 512 for SS
    uint16_t idVendor{0};
    uint16_t idProduct{0};
    uint16_t bcdDevice{0x0100};
    uint8_t  iManufacturer{0};
    uint8_t  iProduct{0};
    uint8_t  iSerialNumber{0};
    uint8_t  bNumConfigurations{1};
};

struct USB_CONFIGURATION_DESCRIPTOR {
    uint8_t  bLength{9};
    uint8_t  bDescriptorType{DescriptorType::Configuration};
    uint16_t wTotalLength{0};
    uint8_t  bNumInterfaces{1};
    uint8_t  bConfigurationValue{1};
    uint8_t  iConfiguration{0};
    uint8_t  bmAttributes{0xC0}; // Self-powered
    uint8_t  bMaxPower{50};      // 100 mA units
};

struct USB_INTERFACE_DESCRIPTOR {
    uint8_t  bLength{9};
    uint8_t  bDescriptorType{DescriptorType::Interface};
    uint8_t  bInterfaceNumber{0};
    uint8_t  bAlternateSetting{0};
    uint8_t  bNumEndpoints{0};
    uint8_t  bInterfaceClass{0};
    uint8_t  bInterfaceSubClass{0};
    uint8_t  bInterfaceProtocol{0};
    uint8_t  iInterface{0};
};

struct USB_ENDPOINT_DESCRIPTOR {
    uint8_t  bLength{7};
    uint8_t  bDescriptorType{DescriptorType::Endpoint};
    uint8_t  bEndpointAddress{0}; // Bit 7: 1=IN, 0=OUT; Bits 0..3: EP #
    uint8_t  bmAttributes{0};     // 0=Control, 1=Isoch, 2=Bulk, 3=Interrupt
    uint16_t wMaxPacketSize{512};
    uint8_t  bInterval{0};
};

struct USB_SUPERSPEED_ENDPOINT_COMPANION_DESCRIPTOR {
    uint8_t  bLength{6};
    uint8_t  bDescriptorType{DescriptorType::SuperSpeedEndpointCompanion};
    uint8_t  bMaxBurst{0};
    uint8_t  bmAttributes{0};
    uint16_t wBytesPerInterval{0};
};

struct USB_BOS_DESCRIPTOR {
    uint8_t  bLength{5};
    uint8_t  bDescriptorType{DescriptorType::BOS};
    uint16_t wTotalLength{5};
    uint8_t  bNumDeviceCaps{0};
};

struct USB_DEFAULT_PIPE_SETUP_PACKET {
    uint8_t  bmRequestType{0};
    uint8_t  bRequest{0};
    uint16_t wValue{0};
    uint16_t wIndex{0};
    uint16_t wLength{0};
};

#pragma pack(pop)

// ============================================================================
// 2. USB Request Block (URB) Architecture
// ============================================================================

using USBD_STATUS = uint32_t;

namespace UsbdStatus {
    inline constexpr USBD_STATUS Success            = 0x00000000;
    inline constexpr USBD_STATUS Pending            = 0x40000000;
    inline constexpr USBD_STATUS StallPid           = 0xC0000004;
    inline constexpr USBD_STATUS BufferTooSmall     = 0xC000000B;
    inline constexpr USBD_STATUS DeviceGone         = 0xC0000010;
    inline constexpr USBD_STATUS Timeout            = 0xC0000012;
    inline constexpr USBD_STATUS InvalidParameter   = 0xC0000003;
    inline constexpr USBD_STATUS Error              = 0xC0000001;
}

namespace UrbFunction {
    inline constexpr uint16_t SELECT_CONFIGURATION       = 0x0000;
    inline constexpr uint16_t SELECT_INTERFACE           = 0x0001;
    inline constexpr uint16_t ABORT_PIPE                 = 0x0002;
    inline constexpr uint16_t CONTROL_TRANSFER           = 0x0008;
    inline constexpr uint16_t BULK_OR_INTERRUPT_TRANSFER = 0x0009;
    inline constexpr uint16_t ISOCH_TRANSFER             = 0x000A;
    inline constexpr uint16_t GET_DESCRIPTOR_FROM_DEVICE = 0x000B;
    inline constexpr uint16_t SET_DESCRIPTOR_TO_DEVICE   = 0x000C;
    inline constexpr uint16_t SYNC_RESET_PIPE            = 0x0030;
}

struct URB_HEADER {
    uint16_t    Length{sizeof(URB_HEADER)};
    uint16_t    Function{UrbFunction::CONTROL_TRANSFER};
    USBD_STATUS Status{UsbdStatus::Pending};
    void*       UsbdDeviceHandle{nullptr};
    uint32_t    UsbdFlags{0};
};

struct URB_CONTROL_TRANSFER {
    URB_HEADER                     Hdr;
    void*                          PipeHandle{nullptr};
    uint32_t                       TransferFlags{0};
    uint32_t                       TransferBufferLength{0};
    void*                          TransferBuffer{nullptr};
    void*                          TransferBufferMDL{nullptr};
    URB_HEADER*                    UrbLink{nullptr};
    USB_DEFAULT_PIPE_SETUP_PACKET  SetupPacket{};
};

struct URB_BULK_OR_INTERRUPT_TRANSFER {
    URB_HEADER  Hdr;
    void*       PipeHandle{nullptr};
    uint32_t    TransferFlags{0};
    uint32_t    TransferBufferLength{0};
    void*       TransferBuffer{nullptr};
    void*       TransferBufferMDL{nullptr};
    URB_HEADER* UrbLink{nullptr};
};

struct URB_SELECT_CONFIGURATION {
    URB_HEADER                    Hdr;
    USB_CONFIGURATION_DESCRIPTOR* ConfigurationDescriptor{nullptr};
    void*                         ConfigurationHandle{nullptr};
    uint32_t                      NumInterfaces{0};
};

// ============================================================================
// 3. xHCI (eXtensible Host Controller Interface 1.2) Register & TRB Specs
// ============================================================================

namespace xhci {

#pragma pack(push, 1)

// TRB (Transfer Request Block) - 16 bytes
struct TRB {
    uint64_t parameter{0};
    uint32_t status{0};
    uint32_t control{0};

    // Helper accessors
    uint8_t getType() const noexcept {
        return static_cast<uint8_t>((control >> 10) & 0x3F);
    }
    void setType(uint8_t type) noexcept {
        control = (control & ~(0x3FU << 10)) | (static_cast<uint32_t>(type & 0x3F) << 10);
    }

    bool getCycle() const noexcept {
        return (control & 0x1) != 0;
    }
    void setCycle(bool c) noexcept {
        if (c) control |= 0x1;
        else control &= ~0x1U;
    }

    bool getIoc() const noexcept { // Interrupt on completion
        return (control & 0x20) != 0;
    }
    void setIoc(bool ioc) noexcept {
        if (ioc) control |= 0x20;
        else control &= ~0x20U;
    }

    uint32_t getTransferLength() const noexcept {
        return status & 0x1FFFF;
    }
    void setTransferLength(uint32_t len) noexcept {
        status = (status & ~0x1FFFFU) | (len & 0x1FFFF);
    }

    uint8_t getCompletionCode() const noexcept {
        return static_cast<uint8_t>((status >> 24) & 0xFF);
    }
    void setCompletionCode(uint8_t code) noexcept {
        status = (status & ~(0xFFU << 24)) | (static_cast<uint32_t>(code) << 24);
    }

    uint8_t getSlotId() const noexcept {
        return static_cast<uint8_t>((control >> 24) & 0xFF);
    }
    void setSlotId(uint8_t slot) noexcept {
        control = (control & ~(0xFFU << 24)) | (static_cast<uint32_t>(slot) << 24);
    }

    uint8_t getEndpointId() const noexcept {
        return static_cast<uint8_t>((control >> 16) & 0x1F);
    }
    void setEndpointId(uint8_t ep) noexcept {
        control = (control & ~(0x1FU << 16)) | (static_cast<uint32_t>(ep & 0x1F) << 16);
    }
};

// TRB Types
namespace TrbType {
    inline constexpr uint8_t Normal                 = 1;
    inline constexpr uint8_t SetupStage             = 2;
    inline constexpr uint8_t DataStage              = 3;
    inline constexpr uint8_t StatusStage            = 4;
    inline constexpr uint8_t Isoch                  = 5;
    inline constexpr uint8_t Link                   = 6;
    inline constexpr uint8_t EventData              = 7;
    inline constexpr uint8_t NoOp                   = 8;
    inline constexpr uint8_t EnableSlotCmd          = 9;
    inline constexpr uint8_t DisableSlotCmd         = 10;
    inline constexpr uint8_t AddressDeviceCmd       = 11;
    inline constexpr uint8_t ConfigureEndpointCmd   = 12;
    inline constexpr uint8_t EvaluateContextCmd     = 13;
    inline constexpr uint8_t ResetEndpointCmd       = 14;
    inline constexpr uint8_t StopEndpointCmd        = 15;
    inline constexpr uint8_t SetTRDequeuePointerCmd = 16;
    inline constexpr uint8_t ResetDeviceCmd         = 17;
    inline constexpr uint8_t TransferEvent          = 32;
    inline constexpr uint8_t CommandCompletionEvent = 33;
    inline constexpr uint8_t PortStatusChangeEvent  = 34;
}

// Completion Codes
namespace CompCode {
    inline constexpr uint8_t Success                = 1;
    inline constexpr uint8_t DataBufferError        = 2;
    inline constexpr uint8_t BabbleDetected         = 3;
    inline constexpr uint8_t UsbTransactionError    = 4;
    inline constexpr uint8_t TRBError               = 5;
    inline constexpr uint8_t StallError             = 6;
    inline constexpr uint8_t ResourceError          = 7;
    inline constexpr uint8_t BandwidthError         = 8;
    inline constexpr uint8_t NoSlotsAvailable       = 9;
    inline constexpr uint8_t InvalidStreamType      = 10;
    inline constexpr uint8_t SlotNotEnabled         = 11;
    inline constexpr uint8_t EndpointNotEnabled     = 12;
    inline constexpr uint8_t ShortPacket            = 13;
    inline constexpr uint8_t EventRingFull          = 21;
    inline constexpr uint8_t CommandRingStopped     = 24;
}

// Slot Context (32 bytes)
struct SlotContext {
    uint32_t info1{0}; // Route string, Speed, Context Entries
    uint32_t info2{0}; // Max Exit Latency, Root Hub Port Number, Number of Ports
    uint32_t ttInfo{0};
    uint32_t stateAndAddress{0}; // Slot state, Device Address
    uint32_t reserved[4]{0};

    uint8_t getSpeed() const noexcept {
        return static_cast<uint8_t>((info1 >> 20) & 0x0F);
    }
    void setSpeed(uint8_t s) noexcept {
        info1 = (info1 & ~(0x0FU << 20)) | (static_cast<uint32_t>(s & 0x0F) << 20);
    }

    uint8_t getRootHubPort() const noexcept {
        return static_cast<uint8_t>((info2 >> 16) & 0xFF);
    }
    void setRootHubPort(uint8_t p) noexcept {
        info2 = (info2 & ~(0xFFU << 16)) | (static_cast<uint32_t>(p) << 16);
    }

    uint8_t getDeviceAddress() const noexcept {
        return static_cast<uint8_t>(stateAndAddress & 0xFF);
    }
    void setDeviceAddress(uint8_t addr) noexcept {
        stateAndAddress = (stateAndAddress & ~0xFFU) | (addr & 0xFF);
    }

    uint8_t getSlotState() const noexcept {
        return static_cast<uint8_t>((stateAndAddress >> 27) & 0x1F);
    }
    void setSlotState(uint8_t st) noexcept {
        stateAndAddress = (stateAndAddress & ~(0x1FU << 27)) | (static_cast<uint32_t>(st & 0x1F) << 27);
    }
};

// Endpoint Context (32 bytes)
struct EndpointContext {
    uint32_t epInfo1{0}; // EP State, Mult, MaxPStreams, LSA, Interval
    uint32_t epInfo2{0}; // Force Event, Error Count, EP Type, CErr, Max Packet Size
    uint64_t trDequeuePointer{0}; // DCS bit in bit 0
    uint32_t txInfo{0}; // Average TRB Length, Max ESIT Payload
    uint32_t reserved[3]{0};

    uint8_t getEpState() const noexcept {
        return static_cast<uint8_t>(epInfo1 & 0x07);
    }
    void setEpState(uint8_t s) noexcept {
        epInfo1 = (epInfo1 & ~0x07U) | (s & 0x07);
    }

    uint8_t getEpType() const noexcept {
        return static_cast<uint8_t>((epInfo2 >> 3) & 0x07);
    }
    void setEpType(uint8_t t) noexcept {
        epInfo2 = (epInfo2 & ~(0x07U << 3)) | (static_cast<uint32_t>(t & 0x07) << 3);
    }

    uint16_t getMaxPacketSize() const noexcept {
        return static_cast<uint16_t>((epInfo2 >> 16) & 0xFFFF);
    }
    void setMaxPacketSize(uint16_t sz) noexcept {
        epInfo2 = (epInfo2 & ~(0xFFFFU << 16)) | (static_cast<uint32_t>(sz) << 16);
    }
};

// Device Context (32 Context Entries: 1 Slot Context + 31 Endpoint Contexts)
struct DeviceContext {
    SlotContext     slot;
    EndpointContext endpoints[31];
};

#pragma pack(pop)

// Sovereign xHCI Ring
class XhciRing {
public:
    explicit XhciRing(size_t capacity = 64)
        : m_capacity(std::max<size_t>(capacity, 16))
        , m_trbs(m_capacity)
    {
        // Place Link TRB at the end to toggle cycle bit upon wrap
        auto& link = m_trbs[m_capacity - 1];
        link.setType(TrbType::Link);
        link.control |= 0x2; // Toggle Cycle bit (TC)
    }

    bool enqueue(const TRB& trb) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (isFull()) return false;

        TRB toWrite = trb;
        toWrite.setCycle(m_cycleState);
        m_trbs[m_enqueueIndex] = toWrite;

        m_enqueueIndex++;
        if (m_enqueueIndex == m_capacity - 1) {
            // Reached link TRB, wrap to beginning and invert cycle bit
            m_trbs[m_enqueueIndex].setCycle(m_cycleState);
            m_enqueueIndex = 0;
            m_cycleState = !m_cycleState;
        }
        m_count++;
        return true;
    }

    bool dequeue(TRB& outTrb) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_count == 0) return false;

        outTrb = m_trbs[m_dequeueIndex];
        m_dequeueIndex++;
        if (m_dequeueIndex == m_capacity - 1) {
            m_dequeueIndex = 0;
        }
        m_count--;
        return true;
    }

    bool isFull() const noexcept {
        return m_count >= (m_capacity - 2);
    }

    size_t count() const noexcept {
        return m_count;
    }

    size_t capacity() const noexcept {
        return m_capacity;
    }

private:
    size_t            m_capacity{64};
    std::vector<TRB>  m_trbs;
    size_t            m_enqueueIndex{0};
    size_t            m_dequeueIndex{0};
    size_t            m_count{0};
    bool              m_cycleState{true};
    mutable std::mutex m_mutex;
};

} // namespace xhci

// ============================================================================
// 4. Abstract USB Device, Endpoints & Pipes
// ============================================================================

class UsbDevice;

struct UsbPipe {
    uint8_t               endpointAddress{0}; // Includes direction bit (0x80 for IN)
    uint8_t               endpointType{0};    // 0=Control, 1=Isoch, 2=Bulk, 3=Interrupt
    uint16_t              maxPacketSize{512};
    uint8_t               interval{0};
    uint32_t              pipeFlags{0};
    xhci::XhciRing        transferRing{64};
};

class UsbDevice {
public:
    UsbDevice(uint16_t vid, uint16_t pid, UsbSpeed speed = UsbSpeed::SuperSpeed)
        : m_speed(speed)
    {
        m_deviceDesc.idVendor = vid;
        m_deviceDesc.idProduct = pid;
        m_deviceDesc.bcdUSB = (speed >= UsbSpeed::SuperSpeed) ? 0x0320 : 0x0200;
        m_deviceDesc.bMaxPacketSize0 = (speed >= UsbSpeed::SuperSpeed) ? 9 : 64;
    }

    virtual ~UsbDevice() = default;

    uint8_t getSlotId() const noexcept { return m_slotId; }
    void setSlotId(uint8_t id) noexcept { m_slotId = id; }

    uint8_t getAddress() const noexcept { return m_address; }
    void setAddress(uint8_t addr) noexcept { m_address = addr; }

    UsbSpeed getSpeed() const noexcept { return m_speed; }
    void setSpeed(UsbSpeed speed) noexcept { m_speed = speed; }

    uint8_t getPortNumber() const noexcept { return m_portNumber; }
    void setPortNumber(uint8_t port) noexcept { m_portNumber = port; }

    bool isConfigured() const noexcept { return m_configured; }
    void setConfigured(bool c) noexcept { m_configured = c; }

    const USB_DEVICE_DESCRIPTOR& getDeviceDescriptor() const noexcept { return m_deviceDesc; }
    USB_DEVICE_DESCRIPTOR& getDeviceDescriptor() noexcept { return m_deviceDesc; }

    const USB_CONFIGURATION_DESCRIPTOR& getConfigurationDescriptor() const noexcept { return m_configDesc; }
    USB_CONFIGURATION_DESCRIPTOR& getConfigurationDescriptor() noexcept { return m_configDesc; }

    const std::vector<USB_INTERFACE_DESCRIPTOR>& getInterfaces() const noexcept { return m_interfaces; }
    const std::vector<USB_ENDPOINT_DESCRIPTOR>& getEndpoints() const noexcept { return m_endpoints; }

    const std::string& getManufacturerString() const noexcept { return m_manufacturer; }
    const std::string& getProductString() const noexcept { return m_product; }
    const std::string& getSerialNumber() const noexcept { return m_serialNumber; }

    void setStrings(std::string mfg, std::string prod, std::string ser) {
        m_manufacturer = std::move(mfg);
        m_product = std::move(prod);
        m_serialNumber = std::move(ser);
        m_deviceDesc.iManufacturer = 1;
        m_deviceDesc.iProduct = 2;
        m_deviceDesc.iSerialNumber = 3;
    }

    // Pipe Management
    void addEndpoint(const USB_ENDPOINT_DESCRIPTOR& ep) {
        m_endpoints.push_back(ep);
        auto pipe = std::make_shared<UsbPipe>();
        pipe->endpointAddress = ep.bEndpointAddress;
        pipe->endpointType = ep.bmAttributes & 0x03;
        pipe->maxPacketSize = ep.wMaxPacketSize;
        pipe->interval = ep.bInterval;
        m_pipes[ep.bEndpointAddress] = pipe;
    }

    std::shared_ptr<UsbPipe> getPipe(uint8_t epAddr) {
        auto it = m_pipes.find(epAddr);
        return (it != m_pipes.end()) ? it->second : nullptr;
    }

    const std::map<uint8_t, std::shared_ptr<UsbPipe>>& getPipes() const noexcept {
        return m_pipes;
    }

    // Standard Setup Packet Handler
    virtual USBD_STATUS handleControlTransfer(
        const USB_DEFAULT_PIPE_SETUP_PACKET& setup,
        uint8_t* buffer,
        uint32_t bufferLength,
        uint32_t& transferred
    ) {
        transferred = 0;
        uint8_t reqType = setup.bmRequestType & RequestType::Mask;
        uint8_t recipient = setup.bmRequestType & RequestType::RecipientMask;
        (void)recipient;

        if (reqType == RequestType::Standard) {
            switch (setup.bRequest) {
                case StandardRequest::GET_STATUS: {
                    if (bufferLength >= 2 && buffer) {
                        buffer[0] = 0x01; // Self-powered
                        buffer[1] = 0x00;
                        transferred = 2;
                        return UsbdStatus::Success;
                    }
                    return UsbdStatus::BufferTooSmall;
                }
                case StandardRequest::SET_ADDRESS: {
                    m_address = static_cast<uint8_t>(setup.wValue & 0x7F);
                    return UsbdStatus::Success;
                }
                case StandardRequest::SET_CONFIGURATION: {
                    m_configured = (setup.wValue != 0);
                    return UsbdStatus::Success;
                }
                case StandardRequest::GET_CONFIGURATION: {
                    if (bufferLength >= 1 && buffer) {
                        buffer[0] = m_configured ? m_configDesc.bConfigurationValue : 0;
                        transferred = 1;
                        return UsbdStatus::Success;
                    }
                    return UsbdStatus::BufferTooSmall;
                }
                case StandardRequest::GET_DESCRIPTOR: {
                    uint8_t descType = static_cast<uint8_t>((setup.wValue >> 8) & 0xFF);
                    uint8_t descIndex = static_cast<uint8_t>(setup.wValue & 0xFF);
                    return handleGetDescriptor(descType, descIndex, buffer, bufferLength, transferred);
                }
                default:
                    break;
            }
        }
        return UsbdStatus::Success;
    }

    // Data Transfer Handler for Endpoints
    virtual USBD_STATUS handleDataTransfer(
        uint8_t endpointAddress,
        uint8_t* buffer,
        uint32_t bufferLength,
        uint32_t& transferred
    ) {
        (void)endpointAddress;
        (void)buffer;
        (void)bufferLength;
        transferred = 0;
        return UsbdStatus::Success;
    }

protected:
    virtual USBD_STATUS handleGetDescriptor(
        uint8_t type,
        uint8_t index,
        uint8_t* buffer,
        uint32_t bufferLength,
        uint32_t& transferred
    ) {
        if (!buffer || bufferLength == 0) return UsbdStatus::BufferTooSmall;

        if (type == DescriptorType::Device) {
            size_t copyLen = std::min<size_t>(sizeof(USB_DEVICE_DESCRIPTOR), bufferLength);
            std::memcpy(buffer, &m_deviceDesc, copyLen);
            transferred = static_cast<uint32_t>(copyLen);
            return UsbdStatus::Success;
        }

        if (type == DescriptorType::Configuration) {
            // Full configuration bundle: Config + Interfaces + Endpoints
            std::vector<uint8_t> bundle;
            bundle.resize(sizeof(USB_CONFIGURATION_DESCRIPTOR));
            std::memcpy(bundle.data(), &m_configDesc, sizeof(USB_CONFIGURATION_DESCRIPTOR));

            for (const auto& iface : m_interfaces) {
                size_t off = bundle.size();
                bundle.resize(off + sizeof(USB_INTERFACE_DESCRIPTOR));
                std::memcpy(bundle.data() + off, &iface, sizeof(USB_INTERFACE_DESCRIPTOR));
            }
            for (const auto& ep : m_endpoints) {
                size_t off = bundle.size();
                bundle.resize(off + sizeof(USB_ENDPOINT_DESCRIPTOR));
                std::memcpy(bundle.data() + off, &ep, sizeof(USB_ENDPOINT_DESCRIPTOR));
            }

            // Patch wTotalLength
            auto* pConfig = reinterpret_cast<USB_CONFIGURATION_DESCRIPTOR*>(bundle.data());
            pConfig->wTotalLength = static_cast<uint16_t>(bundle.size());

            size_t copyLen = std::min<size_t>(bundle.size(), bufferLength);
            std::memcpy(buffer, bundle.data(), copyLen);
            transferred = static_cast<uint32_t>(copyLen);
            return UsbdStatus::Success;
        }

        if (type == DescriptorType::String) {
            std::wstring str;
            if (index == 0) {
                // Language ID: 0x0409 (US English)
                uint8_t langDesc[4] = {4, DescriptorType::String, 0x09, 0x04};
                size_t copyLen = std::min<size_t>(4, bufferLength);
                std::memcpy(buffer, langDesc, copyLen);
                transferred = static_cast<uint32_t>(copyLen);
                return UsbdStatus::Success;
            } else if (index == 1) {
                str = std::wstring(m_manufacturer.begin(), m_manufacturer.end());
            } else if (index == 2) {
                str = std::wstring(m_product.begin(), m_product.end());
            } else if (index == 3) {
                str = std::wstring(m_serialNumber.begin(), m_serialNumber.end());
            }

            uint8_t totalBytes = static_cast<uint8_t>(2 + (str.size() * 2));
            std::vector<uint8_t> strDesc(totalBytes, 0);
            strDesc[0] = totalBytes;
            strDesc[1] = DescriptorType::String;
            std::memcpy(strDesc.data() + 2, str.data(), str.size() * 2);

            size_t copyLen = std::min<size_t>(strDesc.size(), bufferLength);
            std::memcpy(buffer, strDesc.data(), copyLen);
            transferred = static_cast<uint32_t>(copyLen);
            return UsbdStatus::Success;
        }

        return UsbdStatus::InvalidParameter;
    }

    uint8_t                               m_slotId{0};
    uint8_t                               m_address{0};
    uint8_t                               m_portNumber{0};
    UsbSpeed                              m_speed{UsbSpeed::SuperSpeed};
    bool                                  m_configured{false};
    USB_DEVICE_DESCRIPTOR                 m_deviceDesc{};
    USB_CONFIGURATION_DESCRIPTOR          m_configDesc{};
    std::vector<USB_INTERFACE_DESCRIPTOR> m_interfaces;
    std::vector<USB_ENDPOINT_DESCRIPTOR>  m_endpoints;
    std::map<uint8_t, std::shared_ptr<UsbPipe>> m_pipes;
    std::string                           m_manufacturer{"MicaNT Sovereign Foundation"};
    std::string                           m_product{"Sovereign USB Device"};
    std::string                           m_serialNumber{"MICA-USB-001"};
};

// ============================================================================
// 5. USB Hub Architecture & Topology
// ============================================================================

struct UsbPortStatus {
    bool     connected{false};
    bool     enabled{false};
    bool     suspended{false};
    bool     overCurrent{false};
    bool     inReset{false};
    bool     powered{true};
    UsbSpeed speed{UsbSpeed::Unknown};
    bool     connectStatusChange{false};
    bool     enableStatusChange{false};
    bool     resetChange{false};
};

class UsbHubDevice : public UsbDevice {
public:
    UsbHubDevice(uint8_t portCount = 4, UsbSpeed speed = UsbSpeed::SuperSpeed)
        : UsbDevice(0x045E, 0x0901, speed) // Standard Microsoft Root Hub ID
        , m_ports(portCount)
    {
        m_deviceDesc.bDeviceClass = ClassCode::Hub;
        m_deviceDesc.bDeviceSubClass = 0;
        m_deviceDesc.bDeviceProtocol = (speed >= UsbSpeed::SuperSpeed) ? 3 : 1;
        setStrings("MicaNT Sovereign", "Sovereign USB 3.2 Root Hub", "ROOT-HUB-01");

        // Initialize ports
        for (size_t i = 0; i < portCount; ++i) {
            m_ports[i].powered = true;
        }
    }

    uint8_t getPortCount() const noexcept {
        return static_cast<uint8_t>(m_ports.size());
    }

    const UsbPortStatus& getPortStatus(uint8_t portIndex) const {
        static UsbPortStatus s_invalid{};
        if (portIndex >= m_ports.size()) return s_invalid;
        return m_ports[portIndex];
    }

    UsbPortStatus& getPortStatus(uint8_t portIndex) {
        static UsbPortStatus s_invalid{};
        if (portIndex >= m_ports.size()) return s_invalid;
        return m_ports[portIndex];
    }

    bool attachDevice(uint8_t portIndex, std::shared_ptr<UsbDevice> device) {
        if (portIndex >= m_ports.size() || !device) return false;
        auto& port = m_ports[portIndex];
        if (port.connected) return false;

        port.connected = true;
        port.enabled = false;
        port.speed = device->getSpeed();
        port.connectStatusChange = true;
        device->setPortNumber(portIndex + 1);

        m_attachedDevices[portIndex] = device;
        return true;
    }

    std::shared_ptr<UsbDevice> detachDevice(uint8_t portIndex) {
        if (portIndex >= m_ports.size()) return nullptr;
        auto& port = m_ports[portIndex];
        if (!port.connected) return nullptr;

        auto it = m_attachedDevices.find(portIndex);
        std::shared_ptr<UsbDevice> dev = (it != m_attachedDevices.end()) ? it->second : nullptr;

        port.connected = false;
        port.enabled = false;
        port.speed = UsbSpeed::Unknown;
        port.connectStatusChange = true;
        m_attachedDevices.erase(portIndex);
        return dev;
    }

    std::shared_ptr<UsbDevice> getAttachedDevice(uint8_t portIndex) const {
        auto it = m_attachedDevices.find(portIndex);
        return (it != m_attachedDevices.end()) ? it->second : nullptr;
    }

    const std::map<uint8_t, std::shared_ptr<UsbDevice>>& getAttachedDevices() const noexcept {
        return m_attachedDevices;
    }

    // Reset sequence for port
    bool resetPort(uint8_t portIndex) {
        if (portIndex >= m_ports.size()) return false;
        auto& port = m_ports[portIndex];
        if (!port.connected) return false;

        port.inReset = true;
        // Simulate high-speed debounce and termination settle
        port.inReset = false;
        port.enabled = true;
        port.resetChange = true;
        return true;
    }

private:
    std::vector<UsbPortStatus>                      m_ports;
    std::map<uint8_t, std::shared_ptr<UsbDevice>>   m_attachedDevices;
};

// ============================================================================
// 6. USB Class Drivers: Mass Storage, HID, CDC-ACM
// ============================================================================

// 6.1 USB Mass Storage Device (Bulk-Only Transport & SCSI Transparent)
class UsbMassStorageDevice : public UsbDevice {
public:
    UsbMassStorageDevice(size_t capacitySectors = 65536) // 32MB default virtual disk
        : UsbDevice(0x0781, 0x5583, UsbSpeed::SuperSpeed) // SanDisk Ultra USB 3.0
        , m_capacitySectors(capacitySectors)
        , m_storage(capacitySectors * 512, 0)
    {
        m_deviceDesc.bDeviceClass = ClassCode::MassStorage;
        m_deviceDesc.bDeviceSubClass = 0x06; // SCSI Transparent
        m_deviceDesc.bDeviceProtocol = 0x50; // Bulk-Only Transport (BOT)
        setStrings("SanDisk", "Ultra USB 3.0 Flash Drive", "4C531001470815112151");

        // Interface 0: Mass Storage
        USB_INTERFACE_DESCRIPTOR iface{};
        iface.bInterfaceNumber = 0;
        iface.bNumEndpoints = 2;
        iface.bInterfaceClass = ClassCode::MassStorage;
        iface.bInterfaceSubClass = 0x06;
        iface.bInterfaceProtocol = 0x50;
        m_interfaces.push_back(iface);

        // EP1 OUT: Bulk OUT
        USB_ENDPOINT_DESCRIPTOR epOut{};
        epOut.bEndpointAddress = 0x01; // EP1 OUT
        epOut.bmAttributes = 0x02;    // Bulk
        epOut.wMaxPacketSize = 512;
        addEndpoint(epOut);

        // EP2 IN: Bulk IN
        USB_ENDPOINT_DESCRIPTOR epIn{};
        epIn.bEndpointAddress = 0x82; // EP2 IN
        epIn.bmAttributes = 0x02;    // Bulk
        epIn.wMaxPacketSize = 512;
        addEndpoint(epIn);
    }

    size_t getCapacitySectors() const noexcept { return m_capacitySectors; }
    size_t getSectorSize() const noexcept { return 512; }

    USBD_STATUS handleDataTransfer(
        uint8_t endpointAddress,
        uint8_t* buffer,
        uint32_t bufferLength,
        uint32_t& transferred
    ) override {
        transferred = 0;
        if (!buffer || bufferLength == 0) return UsbdStatus::InvalidParameter;

        // BOT Command Block Wrapper (CBW) processing on EP1 OUT
        if (endpointAddress == 0x01) {
            bool isCbw = false;
            if (bufferLength >= 31) {
                uint32_t sig = *reinterpret_cast<uint32_t*>(buffer);
                if (sig == 0x43425355) { // 'USBC'
                    isCbw = true;
                    m_lastCbwTag = *reinterpret_cast<uint32_t*>(buffer + 4);
                    m_dataTransferLength = *reinterpret_cast<uint32_t*>(buffer + 8);
                    m_cbwFlags = buffer[12];
                    uint8_t scsiOp = buffer[15];

                    if (scsiOp == 0x12) { // INQUIRY
                        m_pendingScsiOp = ScsiOp::Inquiry;
                    } else if (scsiOp == 0x25) { // READ CAPACITY 10
                        m_pendingScsiOp = ScsiOp::ReadCapacity;
                    } else if (scsiOp == 0x28) { // READ 10
                        m_pendingScsiOp = ScsiOp::Read10;
                        m_transferLba = (static_cast<uint32_t>(buffer[17]) << 24) |
                                        (static_cast<uint32_t>(buffer[18]) << 16) |
                                        (static_cast<uint32_t>(buffer[19]) << 8)  |
                                        static_cast<uint32_t>(buffer[20]);
                        m_transferSectors = (static_cast<uint16_t>(buffer[22]) << 8) | buffer[23];
                    } else if (scsiOp == 0x2A) { // WRITE 10
                        m_pendingScsiOp = ScsiOp::Write10;
                        m_transferLba = (static_cast<uint32_t>(buffer[17]) << 24) |
                                        (static_cast<uint32_t>(buffer[18]) << 16) |
                                        (static_cast<uint32_t>(buffer[19]) << 8)  |
                                        static_cast<uint32_t>(buffer[20]);
                        m_transferSectors = (static_cast<uint16_t>(buffer[22]) << 8) | buffer[23];
                    } else {
                        m_pendingScsiOp = ScsiOp::None;
                    }
                    transferred = 31;
                    return UsbdStatus::Success;
                }
            }
            if (!isCbw && m_pendingScsiOp == ScsiOp::Write10) {
                // Write payload
                size_t byteOffset = static_cast<size_t>(m_transferLba) * 512;
                size_t copyBytes = std::min<size_t>(bufferLength, m_storage.size() - byteOffset);
                std::memcpy(m_storage.data() + byteOffset, buffer, copyBytes);
                transferred = static_cast<uint32_t>(copyBytes);
                m_pendingScsiOp = ScsiOp::SendCsw;
                return UsbdStatus::Success;
            }
        }

        // BOT Data In or CSW on EP2 IN
        if (endpointAddress == 0x82) {
            if (m_pendingScsiOp == ScsiOp::Inquiry) {
                uint8_t inq[36]{};
                inq[0] = 0x00; // Direct access block device
                inq[1] = 0x80; // Removable
                inq[2] = 0x02; // ANSI SCSI-2
                inq[3] = 0x02; // Response data format
                inq[4] = 31;   // Additional length
                std::memcpy(&inq[8], "SanDisk ", 8);
                std::memcpy(&inq[16], "Cruzer Blade    ", 16);
                std::memcpy(&inq[32], "1.00", 4);

                size_t copyLen = std::min<size_t>(sizeof(inq), bufferLength);
                std::memcpy(buffer, inq, copyLen);
                transferred = static_cast<uint32_t>(copyLen);
                m_pendingScsiOp = ScsiOp::SendCsw;
                return UsbdStatus::Success;
            } else if (m_pendingScsiOp == ScsiOp::ReadCapacity) {
                uint8_t cap[8]{};
                uint32_t lastLba = static_cast<uint32_t>(m_capacitySectors - 1);
                cap[0] = static_cast<uint8_t>((lastLba >> 24) & 0xFF);
                cap[1] = static_cast<uint8_t>((lastLba >> 16) & 0xFF);
                cap[2] = static_cast<uint8_t>((lastLba >> 8) & 0xFF);
                cap[3] = static_cast<uint8_t>(lastLba & 0xFF);
                cap[4] = 0; cap[5] = 0; cap[6] = 0x02; cap[7] = 0x00; // 512 bytes

                size_t copyLen = std::min<size_t>(sizeof(cap), bufferLength);
                std::memcpy(buffer, cap, copyLen);
                transferred = static_cast<uint32_t>(copyLen);
                m_pendingScsiOp = ScsiOp::SendCsw;
                return UsbdStatus::Success;
            } else if (m_pendingScsiOp == ScsiOp::Read10) {
                size_t byteOffset = static_cast<size_t>(m_transferLba) * 512;
                size_t reqBytes = static_cast<size_t>(m_transferSectors) * 512;
                size_t copyLen = std::min<size_t>(std::min<size_t>(reqBytes, bufferLength), m_storage.size() - byteOffset);
                std::memcpy(buffer, m_storage.data() + byteOffset, copyLen);
                transferred = static_cast<uint32_t>(copyLen);
                m_pendingScsiOp = ScsiOp::SendCsw;
                return UsbdStatus::Success;
            } else if (m_pendingScsiOp == ScsiOp::SendCsw) {
                // Command Status Wrapper (CSW - 13 bytes)
                if (bufferLength >= 13) {
                    *reinterpret_cast<uint32_t*>(buffer) = 0x53425355; // 'USBS'
                    *reinterpret_cast<uint32_t*>(buffer + 4) = m_lastCbwTag;
                    *reinterpret_cast<uint32_t*>(buffer + 8) = 0; // Residue = 0
                    buffer[12] = 0x00; // Command Passed
                    transferred = 13;
                    m_pendingScsiOp = ScsiOp::None;
                    return UsbdStatus::Success;
                }
            }
        }
        return UsbdStatus::Success;
    }

private:
    enum class ScsiOp { None, Inquiry, ReadCapacity, Read10, Write10, SendCsw };

    size_t               m_capacitySectors{65536};
    std::vector<uint8_t> m_storage;
    uint32_t             m_lastCbwTag{0};
    uint32_t             m_dataTransferLength{0};
    uint8_t              m_cbwFlags{0};
    ScsiOp               m_pendingScsiOp{ScsiOp::None};
    uint32_t             m_transferLba{0};
    uint16_t             m_transferSectors{0};
};

// 6.2 USB HID Device (Mouse / Keyboard)
struct UsbMouseReport {
    uint8_t buttons{0}; // Bit 0: Left, 1: Right, 2: Middle
    int8_t  xDelta{0};
    int8_t  yDelta{0};
    int8_t  wheel{0};
};

class UsbHidMouseDevice : public UsbDevice {
public:
    UsbHidMouseDevice()
        : UsbDevice(0x046D, 0xC077, UsbSpeed::FullSpeed) // Logitech Optical Mouse
    {
        m_deviceDesc.bDeviceClass = ClassCode::HID;
        m_deviceDesc.bDeviceSubClass = 0x01; // Boot Interface
        m_deviceDesc.bDeviceProtocol = 0x02; // Mouse
        setStrings("Logitech", "Optical USB Mouse", "LOGI-M-001");

        // Interface 0: HID
        USB_INTERFACE_DESCRIPTOR iface{};
        iface.bInterfaceNumber = 0;
        iface.bNumEndpoints = 1;
        iface.bInterfaceClass = ClassCode::HID;
        iface.bInterfaceSubClass = 0x01;
        iface.bInterfaceProtocol = 0x02;
        m_interfaces.push_back(iface);

        // EP1 IN: Interrupt IN
        USB_ENDPOINT_DESCRIPTOR epIn{};
        epIn.bEndpointAddress = 0x81; // EP1 IN
        epIn.bmAttributes = 0x03;    // Interrupt
        epIn.wMaxPacketSize = 64;
        epIn.bInterval = 10;         // 10ms
        addEndpoint(epIn);
    }

    void queueInputEvent(uint8_t buttons, int8_t dx, int8_t dy, int8_t wheel = 0) {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        UsbMouseReport rep{buttons, dx, dy, wheel};
        m_reportQueue.push(rep);
    }

    USBD_STATUS handleDataTransfer(
        uint8_t endpointAddress,
        uint8_t* buffer,
        uint32_t bufferLength,
        uint32_t& transferred
    ) override {
        transferred = 0;
        if (endpointAddress == 0x81 && buffer && bufferLength >= sizeof(UsbMouseReport)) {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            if (!m_reportQueue.empty()) {
                UsbMouseReport rep = m_reportQueue.front();
                m_reportQueue.pop();
                std::memcpy(buffer, &rep, sizeof(UsbMouseReport));
                transferred = sizeof(UsbMouseReport);
                return UsbdStatus::Success;
            }
        }
        return UsbdStatus::Success;
    }

private:
    std::mutex                 m_queueMutex;
    std::queue<UsbMouseReport> m_reportQueue;
};

// 6.3 USB CDC-ACM Device (Virtual COM Port)
class UsbCdcAcmDevice : public UsbDevice {
public:
    UsbCdcAcmDevice()
        : UsbDevice(0x2341, 0x0043, UsbSpeed::FullSpeed) // Arduino Uno USB Serial
    {
        m_deviceDesc.bDeviceClass = ClassCode::Communications;
        m_deviceDesc.bDeviceSubClass = 0x00;
        m_deviceDesc.bDeviceProtocol = 0x00;
        setStrings("Arduino LLC", "Arduino Uno Virtual COM Port", "85334333630351711201");

        // Interface 0: CDC Communication
        USB_INTERFACE_DESCRIPTOR iface0{};
        iface0.bInterfaceNumber = 0;
        iface0.bNumEndpoints = 1;
        iface0.bInterfaceClass = ClassCode::Communications;
        iface0.bInterfaceSubClass = 0x02; // ACM
        iface0.bInterfaceProtocol = 0x01; // AT commands
        m_interfaces.push_back(iface0);

        // EP1 IN: Interrupt IN (Notifications)
        USB_ENDPOINT_DESCRIPTOR epNotify{};
        epNotify.bEndpointAddress = 0x81;
        epNotify.bmAttributes = 0x03; // Interrupt
        epNotify.wMaxPacketSize = 16;
        epNotify.bInterval = 10;
        addEndpoint(epNotify);

        // Interface 1: CDC Data
        USB_INTERFACE_DESCRIPTOR iface1{};
        iface1.bInterfaceNumber = 1;
        iface1.bNumEndpoints = 2;
        iface1.bInterfaceClass = ClassCode::CDCData;
        m_interfaces.push_back(iface1);

        // EP2 OUT: Bulk OUT (Host -> Device rx)
        USB_ENDPOINT_DESCRIPTOR epOut{};
        epOut.bEndpointAddress = 0x02;
        epOut.bmAttributes = 0x02; // Bulk
        epOut.wMaxPacketSize = 64;
        addEndpoint(epOut);

        // EP3 IN: Bulk IN (Device -> Host tx)
        USB_ENDPOINT_DESCRIPTOR epIn{};
        epIn.bEndpointAddress = 0x83;
        epIn.bmAttributes = 0x02; // Bulk
        epIn.wMaxPacketSize = 64;
        addEndpoint(epIn);
    }

    void writeSerialData(const std::string& data) {
        std::lock_guard<std::mutex> lock(m_serialMutex);
        for (char ch : data) {
            m_txFifo.push(static_cast<uint8_t>(ch));
        }
    }

    std::string readReceivedSerialData() {
        std::lock_guard<std::mutex> lock(m_serialMutex);
        std::string res;
        while (!m_rxFifo.empty()) {
            res.push_back(static_cast<char>(m_rxFifo.front()));
            m_rxFifo.pop();
        }
        return res;
    }

    USBD_STATUS handleDataTransfer(
        uint8_t endpointAddress,
        uint8_t* buffer,
        uint32_t bufferLength,
        uint32_t& transferred
    ) override {
        transferred = 0;
        if (!buffer || bufferLength == 0) return UsbdStatus::InvalidParameter;

        std::lock_guard<std::mutex> lock(m_serialMutex);
        if (endpointAddress == 0x02) { // Bulk OUT (Data received from host)
            for (uint32_t i = 0; i < bufferLength; ++i) {
                m_rxFifo.push(buffer[i]);
            }
            transferred = bufferLength;
            return UsbdStatus::Success;
        }

        if (endpointAddress == 0x83) { // Bulk IN (Data sent to host)
            uint32_t count = 0;
            while (!m_txFifo.empty() && count < bufferLength) {
                buffer[count++] = m_txFifo.front();
                m_txFifo.pop();
            }
            transferred = count;
            return UsbdStatus::Success;
        }

        return UsbdStatus::Success;
    }

private:
    std::mutex           m_serialMutex;
    std::queue<uint8_t>  m_txFifo;
    std::queue<uint8_t>  m_rxFifo;
};

// ============================================================================
// 7. xHCI Host Controller Engine
// ============================================================================

class XhciHostController {
public:
    XhciHostController(uint8_t maxSlots = 32, uint8_t maxPorts = 8)
        : m_maxSlots(maxSlots)
        , m_maxPorts(maxPorts)
        , m_rootHub(std::make_shared<UsbHubDevice>(maxPorts, UsbSpeed::SuperSpeed))
        , m_commandRing(128)
        , m_eventRing(256)
    {
        // Setup MMIO Capability Registers
        m_capLength = 0x20;
        m_hciVersion = 0x0120; // xHCI 1.2
        m_hcsParams1 = (maxPorts << 24) | (maxSlots & 0xFF);
        m_hccParams1 = 0x00010020; // 64-bit addressing, standard context size

        // Setup DCBAA (Device Context Base Address Array)
        m_dcbaa.resize(maxSlots + 1, nullptr);
    }

    ~XhciHostController() = default;

    bool initialize() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_usbCmd = 0x00000001; // Run/Stop bit = 1
        m_usbSts = 0x00000000; // Normal state, not halted
        m_initialized = true;
        return true;
    }

    bool isRunning() const noexcept {
        return m_initialized && (m_usbCmd & 0x01);
    }

    std::shared_ptr<UsbHubDevice> getRootHub() const noexcept {
        return m_rootHub;
    }

    // Command Submission to Command Ring
    bool submitCommand(const xhci::TRB& cmdTrb, xhci::TRB& eventTrb) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!isRunning()) return false;

        m_commandRing.enqueue(cmdTrb);

        // Process Command Immediately (Deterministic Sovereign Simulation)
        uint8_t type = cmdTrb.getType();
        eventTrb = {};
        eventTrb.setType(xhci::TrbType::CommandCompletionEvent);
        eventTrb.setCompletionCode(xhci::CompCode::Success);

        if (type == xhci::TrbType::EnableSlotCmd) {
            uint8_t slot = allocateSlot();
            if (slot == 0) {
                eventTrb.setCompletionCode(xhci::CompCode::NoSlotsAvailable);
            } else {
                eventTrb.setSlotId(slot);
            }
        } else if (type == xhci::TrbType::DisableSlotCmd) {
            uint8_t slot = cmdTrb.getSlotId();
            freeSlot(slot);
        } else if (type == xhci::TrbType::AddressDeviceCmd) {
            uint8_t slot = cmdTrb.getSlotId();
            if (slot > 0 && slot <= m_maxSlots && m_slots[slot]) {
                m_slots[slot]->setAddress(slot);
            } else {
                eventTrb.setCompletionCode(xhci::CompCode::SlotNotEnabled);
            }
        } else if (type == xhci::TrbType::ConfigureEndpointCmd) {
            uint8_t slot = cmdTrb.getSlotId();
            if (slot > 0 && slot <= m_maxSlots && m_slots[slot]) {
                m_slots[slot]->setConfigured(true);
            } else {
                eventTrb.setCompletionCode(xhci::CompCode::SlotNotEnabled);
            }
        }

        m_eventRing.enqueue(eventTrb);
        return (eventTrb.getCompletionCode() == xhci::CompCode::Success);
    }

    // Ring Doorbell to Dispatch Transfers
    USBD_STATUS executeTransfer(
        uint8_t slotId,
        uint8_t endpointAddress,
        uint8_t* buffer,
        uint32_t bufferLength,
        uint32_t& transferred
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        transferred = 0;
        if (slotId == 0 || slotId > m_maxSlots || !m_slots[slotId]) {
            return UsbdStatus::DeviceGone;
        }

        auto dev = m_slots[slotId];
        return dev->handleDataTransfer(endpointAddress, buffer, bufferLength, transferred);
    }

    // Control Transfer Execution (Setup + Data + Status)
    USBD_STATUS executeControlTransfer(
        uint8_t slotId,
        const USB_DEFAULT_PIPE_SETUP_PACKET& setup,
        uint8_t* buffer,
        uint32_t bufferLength,
        uint32_t& transferred
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        transferred = 0;
        if (slotId == 0 || slotId > m_maxSlots || !m_slots[slotId]) {
            return UsbdStatus::DeviceGone;
        }

        auto dev = m_slots[slotId];
        return dev->handleControlTransfer(setup, buffer, bufferLength, transferred);
    }

    // Attach Device to Controller Slot
    uint8_t attachDeviceToSlot(std::shared_ptr<UsbDevice> device) {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint8_t slot = allocateSlot();
        if (slot == 0) return 0;

        device->setSlotId(slot);
        m_slots[slot] = device;
        return slot;
    }

    std::shared_ptr<UsbDevice> getDeviceBySlot(uint8_t slotId) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (slotId == 0 || slotId > m_maxSlots) return nullptr;
        auto it = m_slots.find(slotId);
        return (it != m_slots.end()) ? it->second : nullptr;
    }

    const std::map<uint8_t, std::shared_ptr<UsbDevice>>& getActiveSlots() const noexcept {
        return m_slots;
    }

    // Telemetry & Hardware Spec
    uint32_t getHciVersion() const noexcept { return m_hciVersion; }
    uint8_t  getMaxSlots() const noexcept { return m_maxSlots; }
    uint8_t  getMaxPorts() const noexcept { return m_maxPorts; }

private:
    uint8_t allocateSlot() {
        for (uint8_t i = 1; i <= m_maxSlots; ++i) {
            if (m_slots.find(i) == m_slots.end()) {
                m_slots[i] = nullptr;
                return i;
            }
        }
        return 0;
    }

    void freeSlot(uint8_t slot) {
        m_slots.erase(slot);
    }

    uint8_t                                         m_maxSlots{32};
    uint8_t                                         m_maxPorts{8};
    bool                                            m_initialized{false};
    uint8_t                                         m_capLength{0x20};
    uint32_t                                        m_hciVersion{0x0120};
    uint32_t                                        m_hcsParams1{0};
    uint32_t                                        m_hccParams1{0};
    uint32_t                                        m_usbCmd{0};
    uint32_t                                        m_usbSts{0};
    std::shared_ptr<UsbHubDevice>                   m_rootHub;
    xhci::XhciRing                                  m_commandRing;
    xhci::XhciRing                                  m_eventRing;
    std::vector<void*>                              m_dcbaa;
    std::map<uint8_t, std::shared_ptr<UsbDevice>>   m_slots;
    mutable std::mutex                              m_mutex;
};

// ============================================================================
// 8. WinUSB Client Driver Subsystem (winusb.dll Parity)
// ============================================================================

#ifndef _WIN32_BASIC_TYPES_DEFINED
#define _WIN32_BASIC_TYPES_DEFINED
using BOOL = int32_t;
using UCHAR = uint8_t;
using PUCHAR = uint8_t*;
using ULONG = uint32_t;
using PULONG = uint32_t*;
using PVOID = void*;
#ifndef TRUE
inline constexpr BOOL TRUE  = 1;
#endif
#ifndef FALSE
inline constexpr BOOL FALSE = 0;
#endif
#endif

using WINUSB_INTERFACE_HANDLE = void*;
using PWINUSB_INTERFACE_HANDLE = WINUSB_INTERFACE_HANDLE*;

#pragma pack(push, 1)

struct WINUSB_PIPE_INFORMATION {
    uint8_t  PipeType{0};        // UsbdPipeTypeControl, etc.
    uint8_t  PipeId{0};          // Endpoint address
    uint16_t MaximumPacketSize{0};
    uint8_t  Interval{0};
};

struct WINUSB_SETUP_PACKET {
    uint8_t  RequestType{0};
    uint8_t  Request{0};
    uint16_t Value{0};
    uint16_t Index{0};
    uint16_t Length{0};
};

#pragma pack(pop)

namespace WinUsbPolicy {
    inline constexpr uint32_t SHORT_PACKET_TERMINATE = 0x01;
    inline constexpr uint32_t AUTO_CLEAR_STALL       = 0x02;
    inline constexpr uint32_t PIPE_TRANSFER_TIMEOUT  = 0x03;
    inline constexpr uint32_t IGNORE_SHORT_PACKETS   = 0x04;
    inline constexpr uint32_t ALLOW_PARTIAL_READS    = 0x05;
    inline constexpr uint32_t AUTO_FLUSH             = 0x06;
    inline constexpr uint32_t RAW_IO                 = 0x07;
}

class WinUsbContext {
public:
    WinUsbContext(std::shared_ptr<UsbDevice> device, std::shared_ptr<XhciHostController> hc)
        : m_device(std::move(device))
        , m_hostController(std::move(hc))
    {}

    std::shared_ptr<UsbDevice> getDevice() const noexcept { return m_device; }
    std::shared_ptr<XhciHostController> getHostController() const noexcept { return m_hostController; }

    void setPolicy(uint8_t pipeId, uint32_t policyType, uint32_t value) {
        m_policies[pipeId][policyType] = value;
    }

    uint32_t getPolicy(uint8_t pipeId, uint32_t policyType) const {
        auto itP = m_policies.find(pipeId);
        if (itP != m_policies.end()) {
            auto itVal = itP->second.find(policyType);
            if (itVal != itP->second.end()) return itVal->second;
        }
        return 0;
    }

private:
    std::shared_ptr<UsbDevice>          m_device;
    std::shared_ptr<XhciHostController> m_hostController;
    std::map<uint8_t, std::map<uint32_t, uint32_t>> m_policies;
};

// ============================================================================
// 9. Sovereign USB Subsystem Manager (TitanUSB / NexusUSB)
// ============================================================================

class TitanUsbSubsystem {
public:
    static TitanUsbSubsystem& Instance() {
        static TitanUsbSubsystem s_instance;
        return s_instance;
    }

    void initialize() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_initialized) return;

        // Instantiate Primary xHCI Host Controller (xHCI 1.2)
        m_primaryController = std::make_shared<XhciHostController>(32, 8);
        m_primaryController->initialize();

        // Seed Root Hub with standard demo hardware:
        // Port 0: USB 3.0 Flash Drive (SanDisk Ultra BOT)
        auto flashDrive = std::make_shared<UsbMassStorageDevice>(65536);
        uint8_t slot1 = m_primaryController->attachDeviceToSlot(flashDrive);
        m_primaryController->getRootHub()->attachDevice(0, flashDrive);
        m_primaryController->getRootHub()->resetPort(0);
        flashDrive->setAddress(slot1);
        flashDrive->setConfigured(true);

        // Port 1: USB Optical Mouse (HID)
        auto mouse = std::make_shared<UsbHidMouseDevice>();
        uint8_t slot2 = m_primaryController->attachDeviceToSlot(mouse);
        m_primaryController->getRootHub()->attachDevice(1, mouse);
        m_primaryController->getRootHub()->resetPort(1);
        mouse->setAddress(slot2);
        mouse->setConfigured(true);

        // Port 2: USB CDC-ACM Serial Port (COM3)
        auto serial = std::make_shared<UsbCdcAcmDevice>();
        uint8_t slot3 = m_primaryController->attachDeviceToSlot(serial);
        m_primaryController->getRootHub()->attachDevice(2, serial);
        m_primaryController->getRootHub()->resetPort(2);
        serial->setAddress(slot3);
        serial->setConfigured(true);

        m_initialized = true;
    }

    std::shared_ptr<XhciHostController> getPrimaryController() const {
        return m_primaryController;
    }

    // WinUSB Handle Management
    WINUSB_INTERFACE_HANDLE openWinUsbHandle(std::shared_ptr<UsbDevice> dev) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!dev) return nullptr;
        auto ctx = std::make_unique<WinUsbContext>(dev, m_primaryController);
        void* handle = reinterpret_cast<void*>(++m_nextHandleId);
        m_winusbHandles[handle] = std::move(ctx);
        return handle;
    }

    bool closeWinUsbHandle(WINUSB_INTERFACE_HANDLE handle) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return (m_winusbHandles.erase(handle) > 0);
    }

    WinUsbContext* getWinUsbContext(WINUSB_INTERFACE_HANDLE handle) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_winusbHandles.find(handle);
        return (it != m_winusbHandles.end()) ? it->second.get() : nullptr;
    }

    // Hotplug Simulation
    bool hotplugAttach(uint8_t portIndex, const std::string& deviceType) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_primaryController) return false;
        auto rootHub = m_primaryController->getRootHub();

        std::shared_ptr<UsbDevice> newDev;
        if (deviceType == "flash" || deviceType == "storage" || deviceType == "mass_storage") {
            newDev = std::make_shared<UsbMassStorageDevice>(131072); // 64MB
        } else if (deviceType == "mouse" || deviceType == "hid") {
            newDev = std::make_shared<UsbHidMouseDevice>();
        } else if (deviceType == "serial" || deviceType == "cdc" || deviceType == "com") {
            newDev = std::make_shared<UsbCdcAcmDevice>();
        } else {
            newDev = std::make_shared<UsbDevice>(0x1234, 0x5678, UsbSpeed::SuperSpeed);
            newDev->setStrings("Generic Maker", "Generic Sovereign USB Peripheral", "SN-998877");
        }

        uint8_t slot = m_primaryController->attachDeviceToSlot(newDev);
        if (slot == 0) return false;

        bool attached = rootHub->attachDevice(portIndex, newDev);
        if (!attached) return false;

        rootHub->resetPort(portIndex);
        newDev->setAddress(slot);
        newDev->setConfigured(true);
        return true;
    }

    bool hotplugDetach(uint8_t portIndex) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_primaryController) return false;
        auto rootHub = m_primaryController->getRootHub();
        auto dev = rootHub->detachDevice(portIndex);
        return (dev != nullptr);
    }

private:
    TitanUsbSubsystem() = default;

    bool                                                 m_initialized{false};
    std::shared_ptr<XhciHostController>                  m_primaryController;
    uintptr_t                                            m_nextHandleId{0x1000};
    std::map<WINUSB_INTERFACE_HANDLE, std::unique_ptr<WinUsbContext>> m_winusbHandles;
    mutable std::mutex                                   m_mutex;
};

// ============================================================================
// 10. Win32 C ABI Exports for winusb.dll
// ============================================================================

extern "C" {

inline BOOL WINAPI WinUsb_Initialize(
    win32::HANDLE            DeviceHandle,
    PWINUSB_INTERFACE_HANDLE InterfaceHandle
) {
    if (!InterfaceHandle) return FALSE;

    // Resolve attached device on slot matching handle or slot 1
    auto hc = TitanUsbSubsystem::Instance().getPrimaryController();
    if (!hc) return FALSE;

    uint8_t targetSlot = 1;
    if (DeviceHandle) {
        uintptr_t val = reinterpret_cast<uintptr_t>(DeviceHandle);
        if (val >= 1 && val <= 32) targetSlot = static_cast<uint8_t>(val);
    }

    auto dev = hc->getDeviceBySlot(targetSlot);
    if (!dev) return FALSE;

    *InterfaceHandle = TitanUsbSubsystem::Instance().openWinUsbHandle(dev);
    return (*InterfaceHandle != nullptr) ? TRUE : FALSE;
}

inline BOOL WINAPI WinUsb_Free(
    WINUSB_INTERFACE_HANDLE InterfaceHandle
) {
    return TitanUsbSubsystem::Instance().closeWinUsbHandle(InterfaceHandle) ? TRUE : FALSE;
}

inline BOOL WINAPI WinUsb_QueryInterfaceSettings(
    WINUSB_INTERFACE_HANDLE   InterfaceHandle,
    UCHAR                     AltSettingNumber,
    USB_INTERFACE_DESCRIPTOR* UsbAltInterfaceDescriptor
) {
    auto ctx = TitanUsbSubsystem::Instance().getWinUsbContext(InterfaceHandle);
    if (!ctx || !UsbAltInterfaceDescriptor) return FALSE;

    const auto& ifaces = ctx->getDevice()->getInterfaces();
    if (AltSettingNumber >= ifaces.size()) return FALSE;

    *UsbAltInterfaceDescriptor = ifaces[AltSettingNumber];
    return TRUE;
}

inline BOOL WINAPI WinUsb_QueryPipe(
    WINUSB_INTERFACE_HANDLE   InterfaceHandle,
    UCHAR                     AltSettingNumber,
    UCHAR                     PipeIndex,
    WINUSB_PIPE_INFORMATION*  PipeInformation
) {
    (void)AltSettingNumber;
    auto ctx = TitanUsbSubsystem::Instance().getWinUsbContext(InterfaceHandle);
    if (!ctx || !PipeInformation) return FALSE;

    const auto& pipes = ctx->getDevice()->getPipes();
    if (PipeIndex >= pipes.size()) return FALSE;

    auto it = pipes.begin();
    std::advance(it, PipeIndex);

    PipeInformation->PipeType = it->second->endpointType;
    PipeInformation->PipeId = it->second->endpointAddress;
    PipeInformation->MaximumPacketSize = it->second->maxPacketSize;
    PipeInformation->Interval = it->second->interval;
    return TRUE;
}

inline BOOL WINAPI WinUsb_ReadPipe(
    WINUSB_INTERFACE_HANDLE InterfaceHandle,
    UCHAR                   PipeID,
    PUCHAR                  Buffer,
    ULONG                   BufferLength,
    PULONG                  LengthTransferred,
    void*                   Overlapped
) {
    (void)Overlapped;
    auto ctx = TitanUsbSubsystem::Instance().getWinUsbContext(InterfaceHandle);
    if (!ctx || !Buffer) return FALSE;

    uint32_t transferred = 0;
    USBD_STATUS st = ctx->getHostController()->executeTransfer(
        ctx->getDevice()->getSlotId(),
        PipeID,
        Buffer,
        BufferLength,
        transferred
    );

    if (LengthTransferred) *LengthTransferred = transferred;
    return (st == UsbdStatus::Success) ? TRUE : FALSE;
}

inline BOOL WINAPI WinUsb_WritePipe(
    WINUSB_INTERFACE_HANDLE InterfaceHandle,
    UCHAR                   PipeID,
    PUCHAR                  Buffer,
    ULONG                   BufferLength,
    PULONG                  LengthTransferred,
    void*                   Overlapped
) {
    (void)Overlapped;
    auto ctx = TitanUsbSubsystem::Instance().getWinUsbContext(InterfaceHandle);
    if (!ctx || !Buffer) return FALSE;

    uint32_t transferred = 0;
    USBD_STATUS st = ctx->getHostController()->executeTransfer(
        ctx->getDevice()->getSlotId(),
        PipeID,
        Buffer,
        BufferLength,
        transferred
    );

    if (LengthTransferred) *LengthTransferred = transferred;
    return (st == UsbdStatus::Success) ? TRUE : FALSE;
}

inline BOOL WINAPI WinUsb_ControlTransfer(
    WINUSB_INTERFACE_HANDLE    InterfaceHandle,
    WINUSB_SETUP_PACKET        SetupPacket,
    PUCHAR                     Buffer,
    ULONG                      BufferLength,
    PULONG                     LengthTransferred,
    void*                      Overlapped
) {
    (void)Overlapped;
    auto ctx = TitanUsbSubsystem::Instance().getWinUsbContext(InterfaceHandle);
    if (!ctx) return FALSE;

    USB_DEFAULT_PIPE_SETUP_PACKET setup{};
    setup.bmRequestType = SetupPacket.RequestType;
    setup.bRequest = SetupPacket.Request;
    setup.wValue = SetupPacket.Value;
    setup.wIndex = SetupPacket.Index;
    setup.wLength = SetupPacket.Length;

    uint32_t transferred = 0;
    USBD_STATUS st = ctx->getHostController()->executeControlTransfer(
        ctx->getDevice()->getSlotId(),
        setup,
        Buffer,
        BufferLength,
        transferred
    );

    if (LengthTransferred) *LengthTransferred = transferred;
    return (st == UsbdStatus::Success) ? TRUE : FALSE;
}

inline BOOL WINAPI WinUsb_SetPipePolicy(
    WINUSB_INTERFACE_HANDLE InterfaceHandle,
    UCHAR                   PipeID,
    ULONG                   PolicyType,
    ULONG                   ValueLength,
    PVOID                   Value
) {
    auto ctx = TitanUsbSubsystem::Instance().getWinUsbContext(InterfaceHandle);
    if (!ctx || !Value || ValueLength < 4) return FALSE;

    uint32_t val = *reinterpret_cast<uint32_t*>(Value);
    ctx->setPolicy(PipeID, PolicyType, val);
    return TRUE;
}

inline BOOL WINAPI WinUsb_GetPipePolicy(
    WINUSB_INTERFACE_HANDLE InterfaceHandle,
    UCHAR                   PipeID,
    ULONG                   PolicyType,
    PULONG                  ValueLength,
    PVOID                   Value
) {
    auto ctx = TitanUsbSubsystem::Instance().getWinUsbContext(InterfaceHandle);
    if (!ctx || !Value || !ValueLength || *ValueLength < 4) return FALSE;

    *reinterpret_cast<uint32_t*>(Value) = ctx->getPolicy(PipeID, PolicyType);
    *ValueLength = 4;
    return TRUE;
}

} // extern "C"

// ============================================================================
// 11. Subsystem Export & SCM Registration
// ============================================================================

inline void InitializeUsbSubsystem() {
    static bool s_initialized = false;
    if (s_initialized) return;
    s_initialized = true;

    // 1. Initialize Subsystem Singleton & Controllers
    TitanUsbSubsystem::Instance().initialize();

    // 2. Dynamic Loader Exports in winusb.dll
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("winusb.dll", "WinUsb_Initialize", reinterpret_cast<void*>(WinUsb_Initialize));
    ldr.registerExport("winusb.dll", "WinUsb_Free", reinterpret_cast<void*>(WinUsb_Free));
    ldr.registerExport("winusb.dll", "WinUsb_QueryInterfaceSettings", reinterpret_cast<void*>(WinUsb_QueryInterfaceSettings));
    ldr.registerExport("winusb.dll", "WinUsb_QueryPipe", reinterpret_cast<void*>(WinUsb_QueryPipe));
    ldr.registerExport("winusb.dll", "WinUsb_ReadPipe", reinterpret_cast<void*>(WinUsb_ReadPipe));
    ldr.registerExport("winusb.dll", "WinUsb_WritePipe", reinterpret_cast<void*>(WinUsb_WritePipe));
    ldr.registerExport("winusb.dll", "WinUsb_ControlTransfer", reinterpret_cast<void*>(WinUsb_ControlTransfer));
    ldr.registerExport("winusb.dll", "WinUsb_SetPipePolicy", reinterpret_cast<void*>(WinUsb_SetPipePolicy));
    ldr.registerExport("winusb.dll", "WinUsb_GetPipePolicy", reinterpret_cast<void*>(WinUsb_GetPipePolicy));

    // 3. Register USB System Drivers in SCM
    auto xhciSvc = std::make_shared<scm::ServiceRecord>();
    xhciSvc->serviceName = L"usbxhci";
    xhciSvc->displayName = L"MicaNT USB 3.0 eXtensible Host Controller Driver";
    xhciSvc->serviceType = scm::SERVICE_KERNEL_DRIVER;
    xhciSvc->startType = scm::SERVICE_BOOT_START;
    xhciSvc->errorControl = scm::SERVICE_ERROR_CRITICAL;
    xhciSvc->binaryPath = L"C:\\Windows\\System32\\drivers\\usbxhci.sys";
    xhciSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    scm::ServiceControlManager::get().registerServiceRecord(xhciSvc);

    auto hubSvc = std::make_shared<scm::ServiceRecord>();
    hubSvc->serviceName = L"usbhub3";
    hubSvc->displayName = L"MicaNT SuperSpeed USB Hub Driver";
    hubSvc->serviceType = scm::SERVICE_KERNEL_DRIVER;
    hubSvc->startType = scm::SERVICE_SYSTEM_START;
    hubSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
    hubSvc->binaryPath = L"C:\\Windows\\System32\\drivers\\usbhub3.sys";
    hubSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    scm::ServiceControlManager::get().registerServiceRecord(hubSvc);

    // 4. Register Version Database Information
    version::VersionDatabase::Instance().RegisterModule(
        "winusb.dll",
        "10.0.22621.1",
        "MicaNT Sovereign WinUSB Client Library"
    );
    version::VersionDatabase::Instance().RegisterModule(
        "usbxhci.sys",
        "10.0.22621.1",
        "MicaNT Sovereign USB xHCI Host Controller Miniport"
    );
}

} // namespace micant::usb
