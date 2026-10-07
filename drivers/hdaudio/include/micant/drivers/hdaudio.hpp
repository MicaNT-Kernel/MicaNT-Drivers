// ============================================================================
// MicaNT: Sovereign High Definition Audio (Intel HDA 1.0a & USB Audio 2.0/3.0)
// File: include/micant/hdaudio.hpp
// Sovereign System Domain: TitanHDA / NexusHDA
//
// Description:
//   Clean-room implementation of the Intel High Definition Audio (HDA 1.0a /
//   Azalia) specification, Memory Mapped I/O (MMIO) register architecture,
//   Command Outbound Ring Buffer (CORB), Response Inbound Ring Buffer (RIRB),
//   Immediate Command Interface (ICO/ICI), Stream Descriptors (BDL - Buffer
//   Descriptor List), Audio Codec Widget Architecture (DAC, ADC, Mixers,
//   Pin Complexes with Jack Sense), USB Audio Class (UAC 2.0 / 3.0), and
//   Windows High Definition Audio Driver C ABI Exports (hdaudio.sys).
//
// Clean-Room Engineering Reference & Standards:
//   - Intel Corporation: High Definition Audio Specification Revision 1.0a (2010)
//   - USB Implementers Forum: Universal Serial Bus Device Class Definition
//     for Audio Devices (Release 2.0 & 3.0)
//   - Microsoft Open win32metadata repository: Windows.Win32.Media.Audio
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
#include <cmath>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <span>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "janusldr.hpp"
#include "scm.hpp"
#include "version.hpp"
#include "pci.hpp"
#include "prismaudio.hpp"

namespace micant::hda {

// ============================================================================
// 1. Intel HD Audio 1.0a Hardware MMIO Registers & Bitmasks
// ============================================================================

inline constexpr uint32_t HDA_REG_GCAP       = 0x00; // Global Capabilities (16-bit)
inline constexpr uint32_t HDA_REG_VMIN       = 0x02; // Minor Version (8-bit)
inline constexpr uint32_t HDA_REG_VMAJ       = 0x03; // Major Version (8-bit)
inline constexpr uint32_t HDA_REG_OUTPAY     = 0x04; // Output Payload (16-bit)
inline constexpr uint32_t HDA_REG_INPAY      = 0x06; // Input Payload (16-bit)
inline constexpr uint32_t HDA_REG_GCTL       = 0x08; // Global Control (32-bit)
inline constexpr uint32_t HDA_REG_WAKEEN     = 0x0C; // Wake Enable (16-bit)
inline constexpr uint32_t HDA_REG_STATESTS   = 0x0E; // State Change Status (16-bit)
inline constexpr uint32_t HDA_REG_GSTS       = 0x10; // Global Status (16-bit)
inline constexpr uint32_t HDA_REG_INTCTL     = 0x20; // Interrupt Control (32-bit)
inline constexpr uint32_t HDA_REG_INTSTS     = 0x24; // Interrupt Status (32-bit)
inline constexpr uint32_t HDA_REG_WALCLK     = 0x30; // Wall Clock Counter (32-bit, 24 MHz)
inline constexpr uint32_t HDA_REG_SSYNC      = 0x38; // Stream Synchronization (32-bit)

// CORB Registers
inline constexpr uint32_t HDA_REG_CORBLBASE  = 0x40; // CORB Lower Base Address (32-bit)
inline constexpr uint32_t HDA_REG_CORBUBASE  = 0x44; // CORB Upper Base Address (32-bit)
inline constexpr uint32_t HDA_REG_CORBWP     = 0x48; // CORB Write Pointer (16-bit)
inline constexpr uint32_t HDA_REG_CORBRP     = 0x4A; // CORB Read Pointer (16-bit)
inline constexpr uint32_t HDA_REG_CORBCTL    = 0x4C; // CORB Control (8-bit)
inline constexpr uint32_t HDA_REG_CORBSTS    = 0x4D; // CORB Status (8-bit)
inline constexpr uint32_t HDA_REG_CORBSIZE   = 0x4E; // CORB Size (8-bit)

// RIRB Registers
inline constexpr uint32_t HDA_REG_RIRBLBASE  = 0x50; // RIRB Lower Base Address (32-bit)
inline constexpr uint32_t HDA_REG_RIRBUBASE  = 0x54; // RIRB Upper Base Address (32-bit)
inline constexpr uint32_t HDA_REG_RIRBWP     = 0x58; // RIRB Write Pointer (16-bit)
inline constexpr uint32_t HDA_REG_RINTCNT    = 0x5A; // Response Interrupt Count (16-bit)
inline constexpr uint32_t HDA_REG_RIRBCTL    = 0x5C; // RIRB Control (8-bit)
inline constexpr uint32_t HDA_REG_RIRBSTS    = 0x5D; // RIRB Status (8-bit)
inline constexpr uint32_t HDA_REG_RIRBSIZE   = 0x5E; // RIRB Size (8-bit)

// Immediate Command Registers
inline constexpr uint32_t HDA_REG_ICO        = 0x60; // Immediate Command Output (32-bit)
inline constexpr uint32_t HDA_REG_ICI        = 0x64; // Immediate Command Input / Response (32-bit)
inline constexpr uint32_t HDA_REG_ICS        = 0x68; // Immediate Command Status (16-bit)

// Stream Descriptor Register Offsets (Base = 0x80 + StreamIndex * 0x20)
inline constexpr uint32_t HDA_SD_BASE        = 0x80;
inline constexpr uint32_t HDA_SD_STRIDE      = 0x20;
inline constexpr uint32_t HDA_SD_CTL         = 0x00; // Stream Descriptor Control (24-bit)
inline constexpr uint32_t HDA_SD_STS         = 0x03; // Stream Descriptor Status (8-bit)
inline constexpr uint32_t HDA_SD_LPIB        = 0x04; // Link Position in Buffer (32-bit)
inline constexpr uint32_t HDA_SD_CBL         = 0x08; // Cyclic Buffer Length (32-bit)
inline constexpr uint32_t HDA_SD_LVI         = 0x0C; // Last Valid Index (16-bit)
inline constexpr uint32_t HDA_SD_FIFOS       = 0x10; // FIFO Size (16-bit)
inline constexpr uint32_t HDA_SD_FMT         = 0x12; // Stream Format (16-bit)
inline constexpr uint32_t HDA_SD_BDLPL       = 0x18; // Buffer Descriptor List Pointer Lower (32-bit)
inline constexpr uint32_t HDA_SD_BDLPU       = 0x1C; // Buffer Descriptor List Pointer Upper (32-bit)

// Control Flags & Status Bits
inline constexpr uint32_t HDA_GCTL_CRST       = (1u << 0);  // Controller Reset (1 = Out of reset, 0 = In reset)
inline constexpr uint32_t HDA_GCTL_FCNTRL     = (1u << 1);  // Flush Control
inline constexpr uint32_t HDA_GCTL_UNSOL      = (1u << 8);  // Accept Unsolicited Response Enable

inline constexpr uint32_t HDA_INTCTL_GIE      = (1u << 31); // Global Interrupt Enable
inline constexpr uint32_t HDA_INTCTL_CIE      = (1u << 30); // Controller Interrupt Enable

inline constexpr uint8_t  HDA_CORBCTL_RUN     = (1u << 1);  // CORB DMA Engine Run
inline constexpr uint8_t  HDA_CORBCTL_MEIE    = (1u << 0);  // Memory Error Interrupt Enable
inline constexpr uint16_t HDA_CORBRP_RST      = (1u << 15); // CORB Read Pointer Reset

inline constexpr uint8_t  HDA_RIRBCTL_DMAEN   = (1u << 1);  // RIRB DMA Engine Enable
inline constexpr uint8_t  HDA_RIRBCTL_RINTCTL = (1u << 0);  // Response Interrupt Enable
inline constexpr uint8_t  HDA_RIRBSTS_RINTFL  = (1u << 0);  // Response Interrupt Flag
inline constexpr uint16_t HDA_RIRBWP_RST      = (1u << 15); // RIRB Write Pointer Reset

inline constexpr uint16_t HDA_ICS_ICB         = (1u << 0);  // Immediate Command Busy
inline constexpr uint16_t HDA_ICS_IRV         = (1u << 1);  // Immediate Result Valid

inline constexpr uint32_t HDA_SD_CTL_SRST     = (1u << 0);  // Stream Reset
inline constexpr uint32_t HDA_SD_CTL_RUN      = (1u << 1);  // Stream DMA Run
inline constexpr uint32_t HDA_SD_CTL_IOCE     = (1u << 2);  // Interrupt on Completion Enable
inline constexpr uint32_t HDA_SD_CTL_FEIE     = (1u << 3);  // FIFO Error Interrupt Enable
inline constexpr uint8_t  HDA_SD_STS_BCIS     = (1u << 2);  // Buffer Completion Interrupt Status
inline constexpr uint8_t  HDA_SD_STS_FIFOE    = (1u << 3);  // FIFO Error Status

// ============================================================================
// 2. Buffer Descriptor List (BDL) & Audio Format Structures
// ============================================================================

#pragma pack(push, 1)
struct HdaBdlEntry {
    uint64_t address{0}; // 64-bit physical address of PCM buffer segment
    uint32_t length{0};  // Byte length of buffer segment (must be 128-byte aligned)
    uint32_t flags{0};   // bit 0: IOC (Interrupt On Completion)
};
#pragma pack(pop)

// Stream Format Word (16-bit)
// [14]: Base Rate (0 = 48 kHz, 1 = 44.1 kHz)
// [13:11]: Multiplier (000 = x1, 001 = x2, 010 = x3, 011 = x4)
// [10:8]: Divisor (000 = /1, 001 = /2, 010 = /3, ..., 111 = /8)
// [6:4]: Bits per Sample (000=8-bit, 001=16-bit, 010=20-bit, 011=24-bit, 100=32-bit)
// [3:0]: Number of Channels (0000 = 1 ch, 0001 = 2 ch, ..., 1111 = 16 ch)
inline uint16_t HdaEncodeFormat(uint32_t sampleRate, uint8_t channels, uint8_t bitsPerSample) {
    uint16_t fmt = 0;
    // Base rate
    if (sampleRate % 44100 == 0) {
        fmt |= (1u << 14);
        uint32_t mult = sampleRate / 44100;
        if (mult == 2) fmt |= (1u << 11);
        else if (mult == 4) fmt |= (3u << 11);
    } else {
        // 48 kHz base
        uint32_t mult = sampleRate / 48000;
        if (mult == 2) fmt |= (1u << 11);
        else if (mult == 4) fmt |= (3u << 11);
    }

    // Bits per sample
    if (bitsPerSample == 16) fmt |= (1u << 4);
    else if (bitsPerSample == 20) fmt |= (2u << 4);
    else if (bitsPerSample == 24) fmt |= (3u << 4);
    else if (bitsPerSample == 32) fmt |= (4u << 4);

    // Channels (0-based)
    if (channels > 0) {
        fmt |= ((channels - 1) & 0x0F);
    }
    return fmt;
}

// ============================================================================
// 3. Codec Verbs & Widget Constants
// ============================================================================

inline constexpr uint32_t HDA_VERB_GET_PARAM          = 0xF00;
inline constexpr uint32_t HDA_VERB_GET_CONN_SELECT    = 0xF01;
inline constexpr uint32_t HDA_VERB_SET_CONN_SELECT    = 0x701;
inline constexpr uint32_t HDA_VERB_GET_CONN_LIST      = 0xF02;
inline constexpr uint32_t HDA_VERB_GET_PIN_SENSE      = 0xF09;
inline constexpr uint32_t HDA_VERB_EXEC_PIN_SENSE     = 0x709;
inline constexpr uint32_t HDA_VERB_GET_PIN_CTRL       = 0xF07;
inline constexpr uint32_t HDA_VERB_SET_PIN_CTRL       = 0x707;
inline constexpr uint32_t HDA_VERB_GET_POWER_STATE    = 0xF05;
inline constexpr uint32_t HDA_VERB_SET_POWER_STATE    = 0x705;
inline constexpr uint32_t HDA_VERB_GET_STREAM_CHANNEL = 0xF06;
inline constexpr uint32_t HDA_VERB_SET_STREAM_CHANNEL = 0x706;
inline constexpr uint32_t HDA_VERB_GET_AMP_GAIN_MUTE  = 0xB00;
inline constexpr uint32_t HDA_VERB_SET_AMP_GAIN_MUTE  = 0x300;
inline constexpr uint32_t HDA_VERB_GET_UNSOL_RESP     = 0xF08;
inline constexpr uint32_t HDA_VERB_SET_UNSOL_RESP     = 0x708;
inline constexpr uint32_t HDA_VERB_GET_CONFIG_DEFAULT = 0xF1C;
inline constexpr uint32_t HDA_VERB_RESET              = 0x7FF;

// Parameter IDs (used with HDA_VERB_GET_PARAM)
inline constexpr uint8_t  HDA_PARAM_VENDOR_ID         = 0x00;
inline constexpr uint8_t  HDA_PARAM_REVISION_ID       = 0x02;
inline constexpr uint8_t  HDA_PARAM_SUB_NODE_COUNT    = 0x04;
inline constexpr uint8_t  HDA_PARAM_FUNC_GROUP_TYPE   = 0x05;
inline constexpr uint8_t  HDA_PARAM_AUDIO_WIDGET_CAPS = 0x09;
inline constexpr uint8_t  HDA_PARAM_SUPPORTED_FORMATS = 0x0A;
inline constexpr uint8_t  HDA_PARAM_PIN_CAPS          = 0x0C;
inline constexpr uint8_t  HDA_PARAM_IN_AMP_CAPS       = 0x0D;
inline constexpr uint8_t  HDA_PARAM_OUT_AMP_CAPS      = 0x12;

// Audio Widget Types
enum class HdaWidgetType : uint8_t {
    AudioOutput     = 0x0, // DAC
    AudioInput      = 0x1, // ADC
    AudioMixer      = 0x2, // Sum / Mixer
    AudioSelector   = 0x3, // MUX
    PinComplex      = 0x4, // Input / Output Jack
    PowerWidget     = 0x5,
    VolumeKnob      = 0x6,
    BeepGenerator   = 0x7,
    VendorDefined   = 0xF
};

// Power States
enum class HdaPowerState : uint8_t {
    D0_FullyOn = 0,
    D1_LightSleep = 1,
    D2_DeepSleep = 2,
    D3_PoweredOff = 3
};

// Pin Complex Configuration Default (Color & Connection Type)
enum class HdaPortColor : uint8_t {
    Unknown = 0,
    Black   = 1,
    Grey    = 2,
    Blue    = 3,
    Green   = 4, // Line Out / Front L/R
    Red     = 5,
    Orange  = 6, // Center / Subwoofer
    Yellow  = 7,
    Purple  = 8,
    Pink    = 9, // Mic In
    White   = 10
};

// ============================================================================
// 4. Codec Widget Representation & Functional Tree
// ============================================================================

struct HdaWidget {
    uint8_t nodeId{0};
    std::string name;
    HdaWidgetType type{HdaWidgetType::AudioOutput};
    uint32_t capabilities{0};
    uint32_t supportedFormats{0x0001007F}; // PCM 44.1k/48k/96k/192k, 16/24/32-bit
    uint8_t streamId{0};
    uint8_t channelIndex{0};
    uint8_t pinControl{0};     // bit 7: H-Phn Enable, bit 6: Out Enable, bit 5: In Enable
    bool isConnected{false};   // Jack Presence Detect
    HdaPortColor jackColor{HdaPortColor::Green};
    uint8_t ampGainLeft{0x7F}; // Max volume, unmuted
    uint8_t ampGainRight{0x7F};
    bool isMuted{false};
    HdaPowerState powerState{HdaPowerState::D0_FullyOn};
    std::vector<uint8_t> connectionList;
};

// Sovereign Audio Codec Representation (e.g. Realtek ALC887 / Sovereign HDA Codec)
class HdaCodec {
    uint8_t m_address{0};
    uint16_t m_vendorId{0x10EC};   // Realtek / Sovereign Codec
    uint16_t m_deviceId{0x0887};   // ALC887 / Sovereign Studio HDA Codec
    uint32_t m_revision{0x00010003};
    std::map<uint8_t, HdaWidget> m_widgets;
    mutable std::mutex m_mutex;

public:
    explicit HdaCodec(uint8_t addr = 0) : m_address(addr) {
        initializeStandardTopology();
    }

    uint8_t getAddress() const { return m_address; }
    uint16_t getVendorId() const { return m_vendorId; }
    uint16_t getDeviceId() const { return m_deviceId; }
    uint32_t getRevision() const { return m_revision; }

    void initializeStandardTopology() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_widgets.clear();

        // Node 0: Root Codec
        // Node 1: Audio Function Group (AFG)
        // Widgets:
        // Node 0x02: DAC 0 (Front Output L/R)
        HdaWidget dac0;
        dac0.nodeId = 0x02;
        dac0.name = "DAC 0 (Front Stereo Out)";
        dac0.type = HdaWidgetType::AudioOutput;
        dac0.capabilities = 0x00000001; // Stereo, Amp present
        m_widgets[0x02] = dac0;

        // Node 0x03: DAC 1 (Headphone / Surround Out)
        HdaWidget dac1;
        dac1.nodeId = 0x03;
        dac1.name = "DAC 1 (Headphone Out)";
        dac1.type = HdaWidgetType::AudioOutput;
        dac1.capabilities = 0x00000001;
        m_widgets[0x03] = dac1;

        // Node 0x04: ADC 0 (Mic / Line-In Capture)
        HdaWidget adc0;
        adc0.nodeId = 0x04;
        adc0.name = "ADC 0 (Mic / Line-In In)";
        adc0.type = HdaWidgetType::AudioInput;
        adc0.capabilities = 0x00100001; // Stereo, Input amp
        adc0.connectionList = { 0x0C }; // Fed from mixer
        m_widgets[0x04] = adc0;

        // Node 0x0C: Audio Mixer (Sum Widget)
        HdaWidget mixer;
        mixer.nodeId = 0x0C;
        mixer.name = "Master Software Mixer";
        mixer.type = HdaWidgetType::AudioMixer;
        mixer.connectionList = { 0x02, 0x03, 0x18 };
        m_widgets[0x0C] = mixer;

        // Node 0x14: Front Panel Headphone Jack (3.5mm Green/Black with Jack Detect)
        HdaWidget hpJack;
        hpJack.nodeId = 0x14;
        hpJack.name = "Front Headphone Jack (3.5mm)";
        hpJack.type = HdaWidgetType::PinComplex;
        hpJack.pinControl = 0xC0; // Output Enable (0x40) + Headphone Amp Enable (0x80)
        hpJack.isConnected = true; // Plugged in
        hpJack.jackColor = HdaPortColor::Green;
        hpJack.connectionList = { 0x03 };
        m_widgets[0x14] = hpJack;

        // Node 0x15: Rear Panel Line Out (3.5mm Green with Jack Detect)
        HdaWidget lineOut;
        lineOut.nodeId = 0x15;
        lineOut.name = "Rear Speaker Line-Out (3.5mm)";
        lineOut.type = HdaWidgetType::PinComplex;
        lineOut.pinControl = 0x40; // Output Enable
        lineOut.isConnected = true; // Plugged in
        lineOut.jackColor = HdaPortColor::Green;
        lineOut.connectionList = { 0x02 };
        m_widgets[0x15] = lineOut;

        // Node 0x18: Front Panel Microphone Jack (3.5mm Pink with VRef)
        HdaWidget micJack;
        micJack.nodeId = 0x18;
        micJack.name = "Front Microphone In (3.5mm)";
        micJack.type = HdaWidgetType::PinComplex;
        micJack.pinControl = 0x24; // Input Enable (0x20) + VRef 80% (0x04)
        micJack.isConnected = false; // Unplugged initially
        micJack.jackColor = HdaPortColor::Pink;
        m_widgets[0x18] = micJack;
    }

    uint32_t executeVerb(uint8_t nodeId, uint32_t verb, uint16_t payload) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Root Node (Node 0)
        if (nodeId == 0) {
            if (verb == HDA_VERB_GET_PARAM) {
                if (payload == HDA_PARAM_VENDOR_ID) {
                    return (static_cast<uint32_t>(m_vendorId) << 16) | m_deviceId;
                }
                if (payload == HDA_PARAM_REVISION_ID) {
                    return m_revision;
                }
                if (payload == HDA_PARAM_SUB_NODE_COUNT) {
                    // Start Node = 1, Total Nodes = 1 (Audio Function Group)
                    return (1u << 16) | 1u;
                }
            }
            return 0;
        }

        // Audio Function Group (Node 1)
        if (nodeId == 1) {
            if (verb == HDA_VERB_GET_PARAM) {
                if (payload == HDA_PARAM_FUNC_GROUP_TYPE) {
                    return 0x01; // Audio Function Group
                }
                if (payload == HDA_PARAM_SUB_NODE_COUNT) {
                    // Start Node = 2, Total Nodes = 24
                    return (2u << 16) | 24u;
                }
            }
            if (verb == HDA_VERB_GET_POWER_STATE) return 0; // D0
            if (verb == HDA_VERB_SET_POWER_STATE) return 0;
            return 0;
        }

        // Widget lookup
        auto it = m_widgets.find(nodeId);
        if (it == m_widgets.end()) return 0;
        auto& w = it->second;

        // Get Parameter
        if (verb == HDA_VERB_GET_PARAM) {
            if (payload == HDA_PARAM_AUDIO_WIDGET_CAPS) {
                return (static_cast<uint32_t>(w.type) << 20) | w.capabilities;
            }
            if (payload == HDA_PARAM_SUPPORTED_FORMATS) {
                return w.supportedFormats;
            }
            if (payload == HDA_PARAM_PIN_CAPS && w.type == HdaWidgetType::PinComplex) {
                return 0x00010037; // Output, Input, Headphone, Presence Detect
            }
            return 0;
        }

        // Stream and Channel
        if (verb == HDA_VERB_SET_STREAM_CHANNEL) {
            w.streamId = static_cast<uint8_t>((payload >> 4) & 0x0F);
            w.channelIndex = static_cast<uint8_t>(payload & 0x0F);
            return 0;
        }
        if (verb == HDA_VERB_GET_STREAM_CHANNEL) {
            return (static_cast<uint32_t>(w.streamId) << 4) | w.channelIndex;
        }

        // Pin Control
        if (verb == HDA_VERB_SET_PIN_CTRL) {
            w.pinControl = static_cast<uint8_t>(payload & 0xFF);
            return 0;
        }
        if (verb == HDA_VERB_GET_PIN_CTRL) {
            return w.pinControl;
        }

        // Pin Sense / Jack Detect
        if (verb == HDA_VERB_GET_PIN_SENSE) {
            // Bit 31: Presence Detect (1 = Connected, 0 = Disconnected)
            return w.isConnected ? (1u << 31) : 0u;
        }
        if (verb == HDA_VERB_EXEC_PIN_SENSE) {
            return w.isConnected ? (1u << 31) : 0u;
        }

        // Amp Gain / Mute
        if (verb == HDA_VERB_SET_AMP_GAIN_MUTE) {
            bool setLeft = (payload & (1 << 13)) != 0;
            bool setRight = (payload & (1 << 12)) != 0;
            bool mute = (payload & (1 << 7)) != 0;
            uint8_t gain = static_cast<uint8_t>(payload & 0x7F);
            w.isMuted = mute;
            if (setLeft) w.ampGainLeft = gain;
            if (setRight) w.ampGainRight = gain;
            return 0;
        }
        if (verb == HDA_VERB_GET_AMP_GAIN_MUTE) {
            uint32_t resp = w.ampGainLeft & 0x7F;
            if (w.isMuted) resp |= (1u << 7);
            return resp;
        }

        // Power State
        if (verb == HDA_VERB_SET_POWER_STATE) {
            w.powerState = static_cast<HdaPowerState>(payload & 0x03);
            return 0;
        }
        if (verb == HDA_VERB_GET_POWER_STATE) {
            return static_cast<uint32_t>(w.powerState);
        }

        return 0;
    }

    const std::map<uint8_t, HdaWidget>& getWidgets() const { return m_widgets; }

    void setJackConnected(uint8_t pinNodeId, bool connected) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_widgets.find(pinNodeId);
        if (it != m_widgets.end() && it->second.type == HdaWidgetType::PinComplex) {
            it->second.isConnected = connected;
        }
    }
};

// ============================================================================
// 5. Hardware Stream Descriptor Engine & DMA Buffer Management
// ============================================================================

class HdaStreamDescriptor {
    uint8_t m_streamIndex{0}; // 0..3 Input, 4..7 Output
    bool m_isOutput{false};
    uint32_t m_control{0};
    uint8_t m_status{0};
    uint32_t m_linkPosition{0};
    uint32_t m_cyclicBufferLength{0};
    uint16_t m_lastValidIndex{0};
    uint16_t m_fifoSize{192}; // bytes
    uint16_t m_format{0};
    uint64_t m_bdlAddress{0};
    std::vector<HdaBdlEntry> m_bdl;
    std::vector<uint8_t> m_virtualBuffer;
    bool m_active{false};
    mutable std::mutex m_mutex;

public:
    HdaStreamDescriptor(uint8_t idx, bool output)
        : m_streamIndex(idx), m_isOutput(output)
    {
        m_fifoSize = output ? 192 : 128;
    }

    uint8_t getIndex() const { return m_streamIndex; }
    bool isOutput() const { return m_isOutput; }
    bool isActive() const { return m_active; }
    uint32_t getPosition() const { return m_linkPosition; }
    uint32_t getBufferLength() const { return m_cyclicBufferLength; }
    uint16_t getFormat() const { return m_format; }

    void setControl(uint32_t ctl) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_control = ctl;
        if (ctl & HDA_SD_CTL_SRST) {
            m_linkPosition = 0;
            m_status = 0;
            m_active = false;
        }
        if (ctl & HDA_SD_CTL_RUN) {
            m_active = true;
        } else {
            m_active = false;
        }
    }

    uint32_t getControl() const { return m_control; }
    uint8_t getStatus() const { return m_status; }

    void setFormat(uint16_t fmt) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_format = fmt;
    }

    void setCyclicBufferLength(uint32_t cbl) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_cyclicBufferLength = cbl;
        if (cbl > 0 && cbl <= 1024 * 1024) {
            m_virtualBuffer.resize(cbl, 0);
        }
    }

    void setLastValidIndex(uint16_t lvi) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastValidIndex = lvi;
    }

    void setBdlAddress(uint64_t addr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_bdlAddress = addr;
    }

    void programBdl(const std::vector<HdaBdlEntry>& entries) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_bdl = entries;
        uint32_t total = 0;
        for (const auto& e : entries) total += e.length;
        m_cyclicBufferLength = total;
        m_lastValidIndex = static_cast<uint16_t>(entries.empty() ? 0 : entries.size() - 1);
        if (total > 0 && total <= 1024 * 1024) {
            m_virtualBuffer.resize(total, 0);
        }
    }

    void advanceDma(uint32_t byteCount) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_active || m_cyclicBufferLength == 0) return;

        m_linkPosition = (m_linkPosition + byteCount) % m_cyclicBufferLength;
        // Signal buffer completion interrupt flag (BCIS)
        m_status |= HDA_SD_STS_BCIS;
    }

    void writeVirtualPcm(uint32_t offset, const uint8_t* data, size_t length) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_virtualBuffer.empty() || !data) return;
        for (size_t i = 0; i < length; ++i) {
            uint32_t pos = (offset + i) % m_virtualBuffer.size();
            m_virtualBuffer[pos] = data[i];
        }
    }

    const std::vector<uint8_t>& getVirtualBuffer() const { return m_virtualBuffer; }
};

// ============================================================================
// 6. USB Audio Class 2.0 / 3.0 Platform Subsystem (UAC2 / UAC3)
// ============================================================================

class UsbAudioDevice {
    std::string m_name{"Sovereign Studio USB-C DAC"};
    uint16_t m_vendorId{0x1234};
    uint16_t m_productId{0x5678};
    uint32_t m_sampleRate{48000};
    uint8_t m_channels{2};
    uint8_t m_bitsPerSample{24};
    bool m_isStreaming{false};
    bool m_isMuted{false};
    uint8_t m_masterVolume{80}; // 0..100
    mutable std::mutex m_mutex;

public:
    UsbAudioDevice() = default;

    const std::string& getName() const { return m_name; }
    uint16_t getVendorId() const { return m_vendorId; }
    uint16_t getProductId() const { return m_productId; }
    uint32_t getSampleRate() const { return m_sampleRate; }
    uint8_t getChannels() const { return m_channels; }
    uint8_t getBitsPerSample() const { return m_bitsPerSample; }
    bool isStreaming() const { return m_isStreaming; }
    bool isMuted() const { return m_isMuted; }
    uint8_t getVolume() const { return m_masterVolume; }

    void startStreaming() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_isStreaming = true;
    }

    void stopStreaming() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_isStreaming = false;
    }

    void setVolume(uint8_t vol) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_masterVolume = std::min<uint8_t>(vol, 100);
    }

    void setMute(bool mute) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_isMuted = mute;
    }
};

// ============================================================================
// 7. Sovereign Intel HD Audio Platform Subsystem (TitanHDA)
// ============================================================================

class TitanHdaSubsystem {
    std::atomic<bool> m_initialized{false};
    uint64_t m_mmioBaseAddress{0x00000000FED18000ULL};
    uint32_t m_globalControl{0};
    uint32_t m_interruptControl{0};
    uint32_t m_interruptStatus{0};

    // CORB Ring Buffer (256 entries x 4 bytes = 1024 bytes)
    uint64_t m_corbBase{0};
    uint16_t m_corbWp{0};
    uint16_t m_corbRp{0};
    uint8_t  m_corbCtl{0};
    uint8_t  m_corbSize{0x02}; // 256 entries

    // RIRB Ring Buffer (256 entries x 8 bytes = 2048 bytes)
    uint64_t m_rirbBase{0};
    uint16_t m_rirbWp{0};
    uint8_t  m_rirbCtl{0};
    uint8_t  m_rirbSize{0x02}; // 256 entries

    // Stream Descriptors (4 Input: 0..3, 4 Output: 4..7)
    std::vector<std::shared_ptr<HdaStreamDescriptor>> m_streams;

    // Attached Codecs
    std::map<uint8_t, std::shared_ptr<HdaCodec>> m_codecs;

    // Attached USB Audio Device
    UsbAudioDevice m_usbAudio;

    mutable std::mutex m_mutex;

public:
    static TitanHdaSubsystem& Instance() {
        static TitanHdaSubsystem s_instance;
        return s_instance;
    }

    bool isInitialized() const { return m_initialized.load(); }

    void initialize() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_initialized.load()) return;

        // Ensure PCIe subsystem is up so PrismAudio PCI Device is discovered
        pci::TitanPciSubsystem::Instance().initialize();
        auto audioPci = pci::TitanPciSubsystem::Instance().findDeviceByVendorDevice(0x8086, 0x7AD0);
        if (audioPci) {
            uint16_t cmd = audioPci->readConfigWord(pci::PCI_CONFIG_COMMAND);
            cmd |= pci::PCI_COMMAND_BUS_MASTER | pci::PCI_COMMAND_MEM_ENABLE;
            audioPci->writeConfigWord(pci::PCI_CONFIG_COMMAND, cmd);
            auto bar0 = audioPci->getBar(0);
            if (bar0.baseAddress != 0) {
                m_mmioBaseAddress = bar0.baseAddress;
            }
        }

        // Initialize 8 Streams (0..3 Input, 4..7 Output)
        m_streams.clear();
        for (uint8_t i = 0; i < 4; ++i) {
            m_streams.push_back(std::make_shared<HdaStreamDescriptor>(i, false));
        }
        for (uint8_t i = 0; i < 4; ++i) {
            m_streams.push_back(std::make_shared<HdaStreamDescriptor>(i + 4, true));
        }

        // Initialize Onboard Codec 0 (Realtek ALC887 / Sovereign HDA Codec)
        m_codecs.clear();
        m_codecs[0] = std::make_shared<HdaCodec>(0);

        // Perform hardware controller reset sequence
        resetControllerInternal();

        m_initialized.store(true);
    }

    void resetController() {
        std::lock_guard<std::mutex> lock(m_mutex);
        resetControllerInternal();
    }

    uint64_t getMmioBaseAddress() const { return m_mmioBaseAddress; }
    uint32_t getInterruptStatus() const { return m_interruptStatus; }
    uint8_t getCorbSize() const { return m_corbSize; }
    uint8_t getRirbSize() const { return m_rirbSize; }

    uint32_t sendVerb(uint8_t codecAddr, uint8_t nodeId, uint32_t verb, uint16_t payload) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_codecs.find(codecAddr);
        if (it == m_codecs.end()) return 0;
        return it->second->executeVerb(nodeId, verb, payload);
    }

    std::shared_ptr<HdaCodec> getCodec(uint8_t codecAddr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_codecs.find(codecAddr);
        if (it != m_codecs.end()) return it->second;
        return nullptr;
    }

    const std::map<uint8_t, std::shared_ptr<HdaCodec>>& getAllCodecs() const {
        return m_codecs;
    }

    std::shared_ptr<HdaStreamDescriptor> getStream(uint8_t streamId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (streamId < m_streams.size()) return m_streams[streamId];
        return nullptr;
    }

    UsbAudioDevice& getUsbAudio() { return m_usbAudio; }

    // Synthesize PCM sine wave audio tone directly through Output Stream DMA
    bool synthesizeTone(uint8_t streamId, float frequencyHz, uint32_t durationMs, float volume = 0.8f) {
        auto stream = getStream(streamId);
        if (!stream || !stream->isOutput()) return false;

        uint32_t sampleRate = 48000;
        uint8_t channels = 2;
        uint32_t totalSamples = (sampleRate * durationMs) / 1000;
        uint32_t bytesPerSample = 2; // 16-bit
        uint32_t bufferLength = totalSamples * channels * bytesPerSample;

        // Setup stream format: 48kHz, 2 channels, 16-bit
        uint16_t fmt = HdaEncodeFormat(sampleRate, channels, 16);
        stream->setFormat(fmt);

        // Build BDL entry for DMA transfer
        HdaBdlEntry bdlEntry;
        bdlEntry.address = 0x0000000078000000ULL;
        bdlEntry.length = bufferLength;
        bdlEntry.flags = 1; // IOC
        stream->programBdl({ bdlEntry });

        // Synthesize raw 16-bit stereo PCM samples
        std::vector<uint8_t> pcmData(bufferLength);
        int16_t* samples = reinterpret_cast<int16_t*>(pcmData.data());
        double phase = 0.0;
        double phaseInc = 2.0 * 3.14159265358979323846 * frequencyHz / sampleRate;

        for (uint32_t i = 0; i < totalSamples; ++i) {
            int16_t val = static_cast<int16_t>(std::sin(phase) * volume * 32767.0);
            samples[i * 2 + 0] = val; // Left
            samples[i * 2 + 1] = val; // Right
            phase += phaseInc;
            if (phase > 2.0 * 3.14159265358979323846) {
                phase -= 2.0 * 3.14159265358979323846;
            }
        }

        stream->writeVirtualPcm(0, pcmData.data(), pcmData.size());
        stream->setControl(HDA_SD_CTL_RUN | HDA_SD_CTL_IOCE);

        return true;
    }

private:
    TitanHdaSubsystem() = default;

    void resetControllerInternal() {
        // Assert reset (CRST = 0)
        m_globalControl &= ~HDA_GCTL_CRST;
        // Deassert reset (CRST = 1)
        m_globalControl |= HDA_GCTL_CRST;

        // Enable Global and Controller Interrupts
        m_interruptControl = HDA_INTCTL_GIE | HDA_INTCTL_CIE;

        // Configure CORB & RIRB DMA rings
        m_corbBase = 0x0000000077000000ULL;
        m_corbWp = 0;
        m_corbRp = HDA_CORBRP_RST;
        m_corbCtl = HDA_CORBCTL_RUN | HDA_CORBCTL_MEIE;

        m_rirbBase = 0x0000000077001000ULL;
        m_rirbWp = HDA_RIRBWP_RST;
        m_rirbCtl = HDA_RIRBCTL_DMAEN | HDA_RIRBCTL_RINTCTL;
    }
};

// ============================================================================
// 8. Windows HD Audio Driver C ABI Exports (hdaudio.sys & usbaudio2.sys)
// ============================================================================

extern "C" {

inline int32_t WINAPI HdaControllerReset() {
    auto& hda = TitanHdaSubsystem::Instance();
    if (!hda.isInitialized()) hda.initialize();
    hda.resetController();
    return 1;
}

inline int32_t WINAPI HdaSendVerb(uint8_t codecAddr, uint8_t nodeId, uint32_t verb, uint16_t payload, uint32_t* outResponse) {
    auto& hda = TitanHdaSubsystem::Instance();
    if (!hda.isInitialized()) hda.initialize();

    uint32_t resp = hda.sendVerb(codecAddr, nodeId, verb, payload);
    if (outResponse) {
        *outResponse = resp;
    }
    return 1;
}

inline int32_t WINAPI HdaSetupStream(uint8_t streamId, int32_t isOutput, uint32_t sampleRate, uint8_t channels, uint8_t bitsPerSample, uint64_t bufferPhysAddr, uint32_t bufferLength) {
    auto& hda = TitanHdaSubsystem::Instance();
    if (!hda.isInitialized()) hda.initialize();

    auto stream = hda.getStream(streamId);
    if (!stream || (stream->isOutput() != (isOutput != 0))) return 0;

    uint16_t fmt = HdaEncodeFormat(sampleRate, channels, bitsPerSample);
    stream->setFormat(fmt);

    HdaBdlEntry entry;
    entry.address = bufferPhysAddr;
    entry.length = bufferLength;
    entry.flags = 1; // IOC
    stream->programBdl({ entry });
    return 1;
}

inline int32_t WINAPI HdaStartStream(uint8_t streamId) {
    auto& hda = TitanHdaSubsystem::Instance();
    if (!hda.isInitialized()) hda.initialize();

    auto stream = hda.getStream(streamId);
    if (!stream) return 0;

    stream->setControl(HDA_SD_CTL_RUN | HDA_SD_CTL_IOCE);
    return 1;
}

inline int32_t WINAPI HdaStopStream(uint8_t streamId) {
    auto& hda = TitanHdaSubsystem::Instance();
    if (!hda.isInitialized()) hda.initialize();

    auto stream = hda.getStream(streamId);
    if (!stream) return 0;

    stream->setControl(0);
    return 1;
}

inline int32_t WINAPI HdaGetStreamPosition(uint8_t streamId, uint32_t* outPosition) {
    if (!outPosition) return 0;
    auto& hda = TitanHdaSubsystem::Instance();
    if (!hda.isInitialized()) hda.initialize();

    auto stream = hda.getStream(streamId);
    if (!stream) return 0;

    *outPosition = stream->getPosition();
    return 1;
}

inline int32_t WINAPI HdaGetCodecInfo(uint8_t codecAddr, uint16_t* outVendorId, uint16_t* outDeviceId, uint32_t* outRevision) {
    auto& hda = TitanHdaSubsystem::Instance();
    if (!hda.isInitialized()) hda.initialize();

    auto codec = hda.getCodec(codecAddr);
    if (!codec) return 0;

    if (outVendorId) *outVendorId = codec->getVendorId();
    if (outDeviceId) *outDeviceId = codec->getDeviceId();
    if (outRevision) *outRevision = codec->getRevision();
    return 1;
}

inline int32_t WINAPI HdaGetJackStatus(uint8_t codecAddr, uint8_t pinNodeId, int32_t* outConnected) {
    if (!outConnected) return 0;
    auto& hda = TitanHdaSubsystem::Instance();
    if (!hda.isInitialized()) hda.initialize();

    auto codec = hda.getCodec(codecAddr);
    if (!codec) return 0;

    const auto& widgets = codec->getWidgets();
    auto it = widgets.find(pinNodeId);
    if (it == widgets.end() || it->second.type != HdaWidgetType::PinComplex) {
        return 0;
    }

    *outConnected = it->second.isConnected ? 1 : 0;
    return 1;
}

inline int32_t WINAPI HdaSynthesizeTone(uint8_t streamId, float frequencyHz, uint32_t durationMs, float volume) {
    auto& hda = TitanHdaSubsystem::Instance();
    if (!hda.isInitialized()) hda.initialize();

    return hda.synthesizeTone(streamId, frequencyHz, durationMs, volume) ? 1 : 0;
}

} // extern "C"

// ============================================================================
// 9. Subsystem Initialization & Registration
// ============================================================================

inline void InitializeHdaSubsystem() {
    // 1. Initialize Controller & Codecs
    TitanHdaSubsystem::Instance().initialize();

    // 2. Register Module Exports in JanusLDR Dynamic Loader
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("hdaudio.sys", "HdaControllerReset", reinterpret_cast<void*>(HdaControllerReset));
    ldr.registerExport("hdaudio.sys", "HdaSendVerb", reinterpret_cast<void*>(HdaSendVerb));
    ldr.registerExport("hdaudio.sys", "HdaSetupStream", reinterpret_cast<void*>(HdaSetupStream));
    ldr.registerExport("hdaudio.sys", "HdaStartStream", reinterpret_cast<void*>(HdaStartStream));
    ldr.registerExport("hdaudio.sys", "HdaStopStream", reinterpret_cast<void*>(HdaStopStream));
    ldr.registerExport("hdaudio.sys", "HdaGetStreamPosition", reinterpret_cast<void*>(HdaGetStreamPosition));
    ldr.registerExport("hdaudio.sys", "HdaGetCodecInfo", reinterpret_cast<void*>(HdaGetCodecInfo));
    ldr.registerExport("hdaudio.sys", "HdaGetJackStatus", reinterpret_cast<void*>(HdaGetJackStatus));
    ldr.registerExport("hdaudio.sys", "HdaSynthesizeTone", reinterpret_cast<void*>(HdaSynthesizeTone));

    // 3. Register HDA Driver in Service Control Manager (SCM)
    auto hdaSvc = std::make_shared<scm::ServiceRecord>();
    hdaSvc->serviceName = L"hdaudio";
    hdaSvc->displayName = L"MicaNT High Definition Audio Function Driver";
    hdaSvc->serviceType = scm::SERVICE_KERNEL_DRIVER;
    hdaSvc->startType = scm::SERVICE_BOOT_START;
    hdaSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
    hdaSvc->binaryPath = L"C:\\Windows\\System32\\drivers\\hdaudio.sys";
    hdaSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    scm::ServiceControlManager::get().registerServiceRecord(hdaSvc);

    // 4. Register USB Audio 2.0 Driver in SCM
    auto uacSvc = std::make_shared<scm::ServiceRecord>();
    uacSvc->serviceName = L"usbaudio2";
    uacSvc->displayName = L"MicaNT USB Audio 2.0 Class Driver";
    uacSvc->serviceType = scm::SERVICE_KERNEL_DRIVER;
    uacSvc->startType = scm::SERVICE_DEMAND_START;
    uacSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
    uacSvc->binaryPath = L"C:\\Windows\\System32\\drivers\\usbaudio2.sys";
    uacSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    scm::ServiceControlManager::get().registerServiceRecord(uacSvc);

    // 5. Register Version Database Information
    version::VersionDatabase::Instance().RegisterModule(
        "hdaudio.sys",
        "10.0.22621.1",
        "MicaNT Sovereign High Definition Audio Function Driver"
    );
    version::VersionDatabase::Instance().RegisterModule(
        "usbaudio2.sys",
        "10.0.22621.1",
        "MicaNT USB Audio 2.0 Class Driver"
    );
}

} // namespace micant::hda
