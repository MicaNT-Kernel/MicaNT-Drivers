#pragma once

// ============================================================================
// MicaNT Kernel - TitanUSB4 & NexusUSB4 Subsystem
// Milestone 160: USB4 2.0 (80G/120G PAM3) & Thunderbolt 4 Protocol Tunneling
//
// Clean-Room Implementation & Provenance:
// Referenced strictly from public specifications:
//   - USB4™ Specification Version 2.0 (incorporating 80 Gbps / 120 Gbps PAM3)
//   - USB Type-C® Cable and Connector Specification Release 2.2
//   - Intel Thunderbolt™ 4 / 5 Architecture Specification & Security Guides
//   - Microsoft win32metadata (MIT License)
//
// ZERO proprietary or leaked source code used.
// ============================================================================

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ldr.hpp"
#include "scm.hpp"
#include "version.hpp"
#include "pci.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <array>
#include <span>
#include <sstream>
#include <iomanip>

namespace micant::usb4 {

// ============================================================================
// 1. USB4 2.0 & Thunderbolt Constants and Enumerations
// ============================================================================

enum class Usb4LinkSpeed : uint8_t {
    Gen2x2_20G            = 0x01, // 20 Gbps (10 Gbps x 2 NRZ)
    Gen3x2_40G            = 0x02, // 40 Gbps (20 Gbps x 2 NRZ)
    Gen4_80G_Symmetric    = 0x03, // 80 Gbps symmetric (40 Gbps x 2 PAM3)
    Gen4_120G_Asymmetric  = 0x04  // 120 Gbps asymmetric (120 Gbps Tx / 40 Gbps Rx PAM3)
};

enum class Usb4AdapterType : uint8_t {
    NotImplemented        = 0x00,
    PcieDownstream        = 0x01, // Tunnels PCIe downstream to peripherals
    PcieUpstream          = 0x02, // Tunnels PCIe upstream to root complex
    DisplayPortIn         = 0x03, // DP Source / Input
    DisplayPortOut        = 0x04, // DP Sink / Output
    Usb3Host              = 0x05, // Tunnels USB 3.2 from host controller
    Usb3Device            = 0x06, // Tunnels USB 3.2 to peripheral hub
    HostInterface         = 0x07, // HI Adapter for Connection Manager DMA
    ProtocolLane          = 0x08  // Physical transport lane
};

enum class Usb4SecurityLevel : uint8_t {
    SL0_NoSecurity        = 0,    // Open / Legacy Thunderbolt compatibility
    SL1_UserAuthorization = 1,    // Prompt user before enabling PCIe tunneling
    SL2_SecureConnection  = 2,    // Cryptographic HMAC-SHA256 challenge-response
    SL3_DisplayPortOnly   = 3,    // PCIe tunneling blocked, DP video only
    SL4_UsbOnly           = 4     // PCIe & DP blocked, USB3 tunneling only
};

enum class Usb4PathType : uint8_t {
    PCIe                  = 0x01,
    DisplayPort           = 0x02,
    USB3                  = 0x03,
    InterRouterControl    = 0x04
};

// ============================================================================
// 2. Hardware Topology & Data Structures
// ============================================================================

struct Usb4AdapterDescriptor {
    uint8_t adapterNumber{0};
    Usb4AdapterType type{Usb4AdapterType::NotImplemented};
    bool isEnabled{false};
    bool isBound{false};
    uint16_t allocatedCredits{0};
    uint32_t allocatedBandwidthMbps{0};
    uint8_t peerRouterId{0};
    uint8_t peerAdapterNumber{0};
};

struct Usb4Path {
    uint16_t hopId{0};
    uint8_t sourceRouterId{0};
    uint8_t sourceAdapterNumber{0};
    uint8_t destRouterId{0};
    uint8_t destAdapterNumber{0};
    Usb4PathType pathType{Usb4PathType::PCIe};
    uint32_t allocatedBandwidthMbps{0};
    uint16_t creditsAllocated{0};
    bool isActive{false};
};

struct Usb4DeviceNode {
    uint8_t routerId{0};
    uint8_t depth{0}; // 0 = Host Router
    std::string deviceUuid;
    std::string vendorName;
    std::string modelName;
    Usb4LinkSpeed linkSpeed{Usb4LinkSpeed::Gen4_80G_Symmetric};
    uint32_t negotiatedBandwidthGbps{80};
    bool isAuthorized{false};
    Usb4SecurityLevel securityLevel{Usb4SecurityLevel::SL2_SecureConnection};
    std::vector<Usb4AdapterDescriptor> adapters;
};

struct Usb4SubsystemStats {
    uint64_t totalTransmittedPackets{0};
    uint64_t pcieTunneledBytes{0};
    uint64_t dpTunneledBytes{0};
    uint64_t usb3TunneledBytes{0};
    uint64_t droppedPackets{0};
    uint32_t activePathsCount{0};
    uint32_t connectedRoutersCount{0};
};

// ============================================================================
// 3. PCIe Tunneling Transaction Engine
// ============================================================================

class PcieTunnelEngine {
public:
    PcieTunnelEngine() = default;

    // Encapsulate raw PCIe Transaction Layer Packet (TLP) into USB4 Transport Frame
    [[nodiscard]] std::vector<uint8_t> encapsulateTlp(
        uint16_t hopId,
        std::span<const uint8_t> tlpPayload
    ) {
        std::vector<uint8_t> frame;
        frame.reserve(tlpPayload.size() + 8);

        // USB4 Transport Header:
        // Byte 0: Hop ID (7:0)
        // Byte 1: Hop ID (10:8) | Packet Type (PCIe = 0x01 << 3)
        // Byte 2: Credit Sequence Number
        // Byte 3: Payload Length (lower 8 bits)
        // Byte 4-7: Reserved / CRC
        frame.push_back(static_cast<uint8_t>(hopId & 0xFF));
        frame.push_back(static_cast<uint8_t>(((hopId >> 8) & 0x07) | (0x01 << 3)));
        frame.push_back(static_cast<uint8_t>(sequenceNumber_++ & 0xFF));
        frame.push_back(static_cast<uint8_t>(tlpPayload.size() & 0xFF));
        frame.push_back(0x00);
        frame.push_back(0x00);
        frame.push_back(0x5A); // Framing delimiter
        frame.push_back(0xA5);

        frame.insert(frame.end(), tlpPayload.begin(), tlpPayload.end());
        return frame;
    }

    // Decapsulate USB4 Transport Frame to extract PCIe TLP
    [[nodiscard]] bool decapsulateTlp(
        std::span<const uint8_t> frame,
        uint16_t& outHopId,
        std::vector<uint8_t>& outTlpPayload
    ) {
        if (frame.size() < 8) return false;
        if (frame[6] != 0x5A || frame[7] != 0xA5) return false;

        outHopId = static_cast<uint16_t>(frame[0] | ((frame[1] & 0x07) << 8));
        outTlpPayload.assign(frame.begin() + 8, frame.end());
        return true;
    }

private:
    uint32_t sequenceNumber_{1};
};

// ============================================================================
// 4. TitanUSB4 Subsystem Singleton (Host Router & Connection Manager)
// ============================================================================

class TitanUsb4Subsystem {
public:
    static TitanUsb4Subsystem& Instance() {
        static TitanUsb4Subsystem s_instance;
        return s_instance;
    }

    void initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) return;

        securityLevel_ = Usb4SecurityLevel::SL2_SecureConnection;
        asymmetricMode_ = false;
        currentLinkSpeed_ = Usb4LinkSpeed::Gen4_80G_Symmetric;

        buildInitialTopology();
        setupDefaultPaths();

        initialized_ = true;
    }

    [[nodiscard]] bool isInitialized() const noexcept { return initialized_; }

    // Host Link Control
    [[nodiscard]] Usb4LinkSpeed getLinkSpeed() const noexcept { return currentLinkSpeed_; }

    void setAsymmetricMode(bool enable120G) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        asymmetricMode_ = enable120G;
        if (enable120G) {
            currentLinkSpeed_ = Usb4LinkSpeed::Gen4_120G_Asymmetric;
            if (!topology_.empty()) {
                topology_[0].linkSpeed = Usb4LinkSpeed::Gen4_120G_Asymmetric;
                topology_[0].negotiatedBandwidthGbps = 120;
            }
        } else {
            currentLinkSpeed_ = Usb4LinkSpeed::Gen4_80G_Symmetric;
            if (!topology_.empty()) {
                topology_[0].linkSpeed = Usb4LinkSpeed::Gen4_80G_Symmetric;
                topology_[0].negotiatedBandwidthGbps = 80;
            }
        }
    }

    [[nodiscard]] bool isAsymmetricModeEnabled() const noexcept { return asymmetricMode_; }

    // Security Level & Device Authorization (Thunderbolt 4 / Kernel DMA Guard)
    [[nodiscard]] Usb4SecurityLevel getSecurityLevel() const noexcept { return securityLevel_; }

    void setSecurityLevel(Usb4SecurityLevel level) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        securityLevel_ = level;
    }

    bool authorizeDevice(std::string_view uuid) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& dev : topology_) {
            if (dev.deviceUuid == uuid) {
                dev.isAuthorized = true;
                return true;
            }
        }
        return false;
    }

    // Topology & Connection Manager Queries
    [[nodiscard]] std::vector<Usb4DeviceNode> getTopology() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return topology_;
    }

    [[nodiscard]] size_t getConnectedRoutersCount() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return topology_.size();
    }

    // Path Configuration & Management
    NtStatus createPath(
        uint8_t srcRouter, uint8_t srcAdapter,
        uint8_t dstRouter, uint8_t dstAdapter,
        Usb4PathType pathType,
        uint32_t bandwidthMbps,
        uint16_t credits,
        uint16_t& outHopId
    ) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Verify security permissions for PCIe tunneling
        if (pathType == Usb4PathType::PCIe) {
            if (securityLevel_ == Usb4SecurityLevel::SL3_DisplayPortOnly ||
                securityLevel_ == Usb4SecurityLevel::SL4_UsbOnly) {
                return NtStatus::AccessDenied;
            }
            // Verify destination router is authorized
            bool authorized = false;
            for (const auto& r : topology_) {
                if (r.routerId == dstRouter && r.isAuthorized) {
                    authorized = true;
                    break;
                }
            }
            if (!authorized && securityLevel_ >= Usb4SecurityLevel::SL1_UserAuthorization) {
                return NtStatus::AccessDenied;
            }
        }

        uint16_t hopId = nextHopId_++;
        Usb4Path path{
            .hopId = hopId,
            .sourceRouterId = srcRouter,
            .sourceAdapterNumber = srcAdapter,
            .destRouterId = dstRouter,
            .destAdapterNumber = dstAdapter,
            .pathType = pathType,
            .allocatedBandwidthMbps = bandwidthMbps,
            .creditsAllocated = credits,
            .isActive = true
        };

        paths_.push_back(path);
        stats_.activePathsCount = static_cast<uint32_t>(paths_.size());
        outHopId = hopId;
        return NtStatus::Success;
    }

    NtStatus destroyPath(uint16_t hopId) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = paths_.begin(); it != paths_.end(); ++it) {
            if (it->hopId == hopId) {
                paths_.erase(it);
                stats_.activePathsCount = static_cast<uint32_t>(paths_.size());
                return NtStatus::Success;
            }
        }
        return NtStatus::ObjectNameNotFound;
    }

    [[nodiscard]] std::vector<Usb4Path> getActivePaths() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return paths_;
    }

    // Packet Tunneling Datapath
    bool tunnelPciePacket(uint16_t hopId, std::span<const uint8_t> tlpBytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tlpBytes.empty()) return false;

        // Verify active PCIe path
        bool validPath = false;
        for (const auto& p : paths_) {
            if (p.hopId == hopId && p.pathType == Usb4PathType::PCIe && p.isActive) {
                validPath = true;
                break;
            }
        }
        if (!validPath) {
            stats_.droppedPackets++;
            return false;
        }

        auto frame = tunnelEngine_.encapsulateTlp(hopId, tlpBytes);
        stats_.totalTransmittedPackets++;
        stats_.pcieTunneledBytes += tlpBytes.size();
        return !frame.empty();
    }

    bool tunnelDpPacket(uint16_t hopId, size_t byteCount) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool valid = false;
        for (const auto& p : paths_) {
            if (p.hopId == hopId && p.pathType == Usb4PathType::DisplayPort && p.isActive) {
                valid = true;
                break;
            }
        }
        if (!valid) return false;

        stats_.totalTransmittedPackets++;
        stats_.dpTunneledBytes += byteCount;
        return true;
    }

    bool tunnelUsb3Packet(uint16_t hopId, size_t byteCount) {
        std::lock_guard<std::mutex> lock(mutex_);
        bool valid = false;
        for (const auto& p : paths_) {
            if (p.hopId == hopId && p.pathType == Usb4PathType::USB3 && p.isActive) {
                valid = true;
                break;
            }
        }
        if (!valid) return false;

        stats_.totalTransmittedPackets++;
        stats_.usb3TunneledBytes += byteCount;
        return true;
    }

    [[nodiscard]] Usb4SubsystemStats getStatistics() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stats_;
    }

private:
    TitanUsb4Subsystem() = default;

    void buildInitialTopology() {
        topology_.clear();

        // 1. Router 0: Host Router (Root / Depth 0)
        Usb4DeviceNode hostRouter{
            .routerId = 0,
            .depth = 0,
            .deviceUuid = "80860000-0000-4000-8000-001A7DDA7200",
            .vendorName = "Intel / Titan Architecture",
            .modelName = "Sovereign USB4 2.0 Host Router (Arrow Lake)",
            .linkSpeed = Usb4LinkSpeed::Gen4_80G_Symmetric,
            .negotiatedBandwidthGbps = 80,
            .isAuthorized = true,
            .securityLevel = Usb4SecurityLevel::SL2_SecureConnection,
            .adapters = {
                { .adapterNumber = 0, .type = Usb4AdapterType::HostInterface, .isEnabled = true, .isBound = true, .allocatedCredits = 64, .allocatedBandwidthMbps = 80000, .peerRouterId = 0, .peerAdapterNumber = 0 },
                { .adapterNumber = 1, .type = Usb4AdapterType::PcieUpstream,   .isEnabled = true, .isBound = true, .allocatedCredits = 128, .allocatedBandwidthMbps = 64000, .peerRouterId = 1, .peerAdapterNumber = 1 },
                { .adapterNumber = 2, .type = Usb4AdapterType::DisplayPortIn,  .isEnabled = true, .isBound = true, .allocatedCredits = 64, .allocatedBandwidthMbps = 40000, .peerRouterId = 1, .peerAdapterNumber = 2 },
                { .adapterNumber = 3, .type = Usb4AdapterType::Usb3Host,       .isEnabled = true, .isBound = true, .allocatedCredits = 32, .allocatedBandwidthMbps = 20000, .peerRouterId = 1, .peerAdapterNumber = 3 },
                { .adapterNumber = 4, .type = Usb4AdapterType::ProtocolLane,   .isEnabled = true, .isBound = true, .allocatedCredits = 256, .allocatedBandwidthMbps = 80000, .peerRouterId = 1, .peerAdapterNumber = 0 }
            }
        };
        topology_.push_back(hostRouter);

        // 2. Router 1: USB4 80G Multi-Port Dock (Depth 1)
        Usb4DeviceNode dockRouter{
            .routerId = 1,
            .depth = 1,
            .deviceUuid = "80860001-BEEF-4000-8000-001A7DDA7201",
            .vendorName = "Titan Sovereign Hardware",
            .modelName = "Titan Quantum 80G PAM3 Docking Station",
            .linkSpeed = Usb4LinkSpeed::Gen4_80G_Symmetric,
            .negotiatedBandwidthGbps = 80,
            .isAuthorized = true,
            .securityLevel = Usb4SecurityLevel::SL2_SecureConnection,
            .adapters = {
                { .adapterNumber = 0, .type = Usb4AdapterType::ProtocolLane,   .isEnabled = true, .isBound = true, .allocatedCredits = 256, .allocatedBandwidthMbps = 80000, .peerRouterId = 0, .peerAdapterNumber = 4 },
                { .adapterNumber = 1, .type = Usb4AdapterType::PcieDownstream, .isEnabled = true, .isBound = true, .allocatedCredits = 128, .allocatedBandwidthMbps = 64000, .peerRouterId = 0, .peerAdapterNumber = 1 },
                { .adapterNumber = 2, .type = Usb4AdapterType::DisplayPortOut, .isEnabled = true, .isBound = true, .allocatedCredits = 64, .allocatedBandwidthMbps = 40000, .peerRouterId = 0, .peerAdapterNumber = 2 },
                { .adapterNumber = 3, .type = Usb4AdapterType::Usb3Device,     .isEnabled = true, .isBound = true, .allocatedCredits = 32, .allocatedBandwidthMbps = 20000, .peerRouterId = 0, .peerAdapterNumber = 3 },
                { .adapterNumber = 4, .type = Usb4AdapterType::ProtocolLane,   .isEnabled = true, .isBound = true, .allocatedCredits = 256, .allocatedBandwidthMbps = 80000, .peerRouterId = 2, .peerAdapterNumber = 0 }
            }
        };
        topology_.push_back(dockRouter);

        // 3. Router 2: External High-Speed eGPU / Storage Enclosure (Depth 2)
        Usb4DeviceNode egpuRouter{
            .routerId = 2,
            .depth = 2,
            .deviceUuid = "10DE0002-CAFE-4000-8000-001A7DDA7202",
            .vendorName = "Titan / NVIDIA Architecture",
            .modelName = "Titan RTX Sovereign eGPU & NVMe Accelerator",
            .linkSpeed = Usb4LinkSpeed::Gen4_80G_Symmetric,
            .negotiatedBandwidthGbps = 80,
            .isAuthorized = true,
            .securityLevel = Usb4SecurityLevel::SL2_SecureConnection,
            .adapters = {
                { .adapterNumber = 0, .type = Usb4AdapterType::ProtocolLane,   .isEnabled = true, .isBound = true, .allocatedCredits = 256, .allocatedBandwidthMbps = 80000, .peerRouterId = 1, .peerAdapterNumber = 4 },
                { .adapterNumber = 1, .type = Usb4AdapterType::PcieDownstream, .isEnabled = true, .isBound = true, .allocatedCredits = 128, .allocatedBandwidthMbps = 64000, .peerRouterId = 1, .peerAdapterNumber = 1 }
            }
        };
        topology_.push_back(egpuRouter);

        stats_.connectedRoutersCount = static_cast<uint32_t>(topology_.size());
    }

    void setupDefaultPaths() {
        paths_.clear();

        // Path 1: PCIe Tunneling Path to Dock (Hop ID 8)
        paths_.push_back(Usb4Path{
            .hopId = 8,
            .sourceRouterId = 0,
            .sourceAdapterNumber = 1,
            .destRouterId = 1,
            .destAdapterNumber = 1,
            .pathType = Usb4PathType::PCIe,
            .allocatedBandwidthMbps = 32000, // 32 Gbps PCIe Gen 4 x2
            .creditsAllocated = 64,
            .isActive = true
        });

        // Path 2: DisplayPort 2.1 Video Tunneling Path (Hop ID 9)
        paths_.push_back(Usb4Path{
            .hopId = 9,
            .sourceRouterId = 0,
            .sourceAdapterNumber = 2,
            .destRouterId = 1,
            .destAdapterNumber = 2,
            .pathType = Usb4PathType::DisplayPort,
            .allocatedBandwidthMbps = 38000, // 38 Gbps UHBR20
            .creditsAllocated = 64,
            .isActive = true
        });

        // Path 3: USB 3.2 SuperSpeed Tunneling Path (Hop ID 10)
        paths_.push_back(Usb4Path{
            .hopId = 10,
            .sourceRouterId = 0,
            .sourceAdapterNumber = 3,
            .destRouterId = 1,
            .destAdapterNumber = 3,
            .pathType = Usb4PathType::USB3,
            .allocatedBandwidthMbps = 10000, // 10 Gbps SuperSpeed+
            .creditsAllocated = 32,
            .isActive = true
        });

        // Path 4: Dedicated PCIe Tunneling Path to eGPU on Router 2 (Hop ID 11)
        paths_.push_back(Usb4Path{
            .hopId = 11,
            .sourceRouterId = 0,
            .sourceAdapterNumber = 1,
            .destRouterId = 2,
            .destAdapterNumber = 1,
            .pathType = Usb4PathType::PCIe,
            .allocatedBandwidthMbps = 64000, // 64 Gbps PCIe Gen 4 x4
            .creditsAllocated = 128,
            .isActive = true
        });

        stats_.activePathsCount = static_cast<uint32_t>(paths_.size());
        nextHopId_ = 12;
    }

    mutable std::mutex mutex_;
    bool initialized_{false};
    bool asymmetricMode_{false};
    Usb4LinkSpeed currentLinkSpeed_{Usb4LinkSpeed::Gen4_80G_Symmetric};
    Usb4SecurityLevel securityLevel_{Usb4SecurityLevel::SL2_SecureConnection};
    uint16_t nextHopId_{12};

    std::vector<Usb4DeviceNode> topology_;
    std::vector<Usb4Path> paths_;
    Usb4SubsystemStats stats_;
    PcieTunnelEngine tunnelEngine_;
};

// ============================================================================
// 5. Dynamic Loader C ABI Exports (usb4host.sys, thunderbolt.sys, usb4router.sys)
// ============================================================================

extern "C" {

inline int32_t WINAPI Usb4HostInitialize(void) {
    auto& usb4 = TitanUsb4Subsystem::Instance();
    if (!usb4.isInitialized()) usb4.initialize();
    return 0;
}

inline int32_t WINAPI Usb4HostEnumerateTopology(uint32_t* outRouterCount) {
    auto& usb4 = TitanUsb4Subsystem::Instance();
    if (!usb4.isInitialized()) usb4.initialize();
    if (outRouterCount) *outRouterCount = static_cast<uint32_t>(usb4.getConnectedRoutersCount());
    return 0;
}

inline int32_t WINAPI Usb4HostCreatePath(
    uint8_t srcRouter, uint8_t srcAdapter,
    uint8_t dstRouter, uint8_t dstAdapter,
    uint8_t pathType, uint32_t bandwidthMbps,
    uint16_t* outHopId
) {
    if (!outHopId) return -1;
    auto& usb4 = TitanUsb4Subsystem::Instance();
    if (!usb4.isInitialized()) usb4.initialize();

    uint16_t hop = 0;
    auto st = usb4.createPath(
        srcRouter, srcAdapter, dstRouter, dstAdapter,
        static_cast<Usb4PathType>(pathType), bandwidthMbps, 64, hop
    );
    if (st == NtStatus::Success) {
        *outHopId = hop;
        return 0;
    }
    return -1;
}

inline int32_t WINAPI Usb4HostDestroyPath(uint16_t hopId) {
    auto& usb4 = TitanUsb4Subsystem::Instance();
    if (!usb4.isInitialized()) usb4.initialize();
    return (usb4.destroyPath(hopId) == NtStatus::Success) ? 0 : -1;
}

inline int32_t WINAPI Usb4HostGetRouterCapabilities(
    uint8_t routerId,
    uint8_t* outDepth,
    uint32_t* outBandwidthGbps,
    uint8_t* outLinkSpeed
) {
    auto& usb4 = TitanUsb4Subsystem::Instance();
    if (!usb4.isInitialized()) usb4.initialize();

    auto topo = usb4.getTopology();
    for (const auto& r : topo) {
        if (r.routerId == routerId) {
            if (outDepth) *outDepth = r.depth;
            if (outBandwidthGbps) *outBandwidthGbps = r.negotiatedBandwidthGbps;
            if (outLinkSpeed) *outLinkSpeed = static_cast<uint8_t>(r.linkSpeed);
            return 0;
        }
    }
    return -1;
}

inline int32_t WINAPI ThunderboltGetSecurityLevel(uint8_t* outLevel) {
    if (!outLevel) return -1;
    auto& usb4 = TitanUsb4Subsystem::Instance();
    if (!usb4.isInitialized()) usb4.initialize();
    *outLevel = static_cast<uint8_t>(usb4.getSecurityLevel());
    return 0;
}

inline int32_t WINAPI ThunderboltSetSecurityLevel(uint8_t level) {
    if (level > 4) return -1;
    auto& usb4 = TitanUsb4Subsystem::Instance();
    if (!usb4.isInitialized()) usb4.initialize();
    usb4.setSecurityLevel(static_cast<Usb4SecurityLevel>(level));
    return 0;
}

inline int32_t WINAPI ThunderboltAuthorizeDevice(const char* uuidStr) {
    if (!uuidStr) return -1;
    auto& usb4 = TitanUsb4Subsystem::Instance();
    if (!usb4.isInitialized()) usb4.initialize();
    return usb4.authorizeDevice(uuidStr) ? 0 : -1;
}

inline int32_t WINAPI Usb4TunnelPciePacket(uint16_t hopId, const uint8_t* packetBytes, uint32_t packetLen) {
    if (!packetBytes || packetLen == 0) return -1;
    auto& usb4 = TitanUsb4Subsystem::Instance();
    if (!usb4.isInitialized()) usb4.initialize();
    return usb4.tunnelPciePacket(hopId, std::span<const uint8_t>(packetBytes, packetLen)) ? 0 : -1;
}

} // extern "C"

// ============================================================================
// 6. Subsystem Initialization & Registration
// ============================================================================

inline void InitializeUsb4Subsystem() {
    // 0. Ensure Host PCI Bus and Root Ports are Initialized
    pci::InitializePciSubsystem();

    // 1. Initialize Core Subsystem
    TitanUsb4Subsystem::Instance().initialize();

    // 2. Register Driver Exports in JanusLDR Dynamic Loader
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("usb4host.sys", "Usb4HostInitialize", reinterpret_cast<void*>(Usb4HostInitialize));
    ldr.registerExport("usb4host.sys", "Usb4HostEnumerateTopology", reinterpret_cast<void*>(Usb4HostEnumerateTopology));
    ldr.registerExport("usb4host.sys", "Usb4HostCreatePath", reinterpret_cast<void*>(Usb4HostCreatePath));
    ldr.registerExport("usb4host.sys", "Usb4HostDestroyPath", reinterpret_cast<void*>(Usb4HostDestroyPath));
    ldr.registerExport("usb4host.sys", "Usb4HostGetRouterCapabilities", reinterpret_cast<void*>(Usb4HostGetRouterCapabilities));

    ldr.registerExport("thunderbolt.sys", "ThunderboltGetSecurityLevel", reinterpret_cast<void*>(ThunderboltGetSecurityLevel));
    ldr.registerExport("thunderbolt.sys", "ThunderboltSetSecurityLevel", reinterpret_cast<void*>(ThunderboltSetSecurityLevel));
    ldr.registerExport("thunderbolt.sys", "ThunderboltAuthorizeDevice", reinterpret_cast<void*>(ThunderboltAuthorizeDevice));

    ldr.registerExport("usb4router.sys", "Usb4TunnelPciePacket", reinterpret_cast<void*>(Usb4TunnelPciePacket));

    // 3. Register Core USB4 / Thunderbolt Drivers in SCM
    auto hostSvc = std::make_shared<scm::ServiceRecord>();
    hostSvc->serviceName = L"usb4host";
    hostSvc->displayName = L"USB4 Host Router & Connection Manager (usb4host.sys)";
    hostSvc->serviceType = scm::SERVICE_KERNEL_DRIVER;
    hostSvc->startType = scm::SERVICE_BOOT_START;
    hostSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
    hostSvc->binaryPath = L"C:\\Windows\\System32\\drivers\\usb4host.sys";
    hostSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    scm::ServiceControlManager::get().registerServiceRecord(hostSvc);

    auto tbtSvc = std::make_shared<scm::ServiceRecord>();
    tbtSvc->serviceName = L"thunderbolt";
    tbtSvc->displayName = L"Thunderbolt 4 / DMA Security Subsystem (thunderbolt.sys)";
    tbtSvc->serviceType = scm::SERVICE_KERNEL_DRIVER;
    tbtSvc->startType = scm::SERVICE_BOOT_START;
    tbtSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
    tbtSvc->binaryPath = L"C:\\Windows\\System32\\drivers\\thunderbolt.sys";
    tbtSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    scm::ServiceControlManager::get().registerServiceRecord(tbtSvc);

    auto routerSvc = std::make_shared<scm::ServiceRecord>();
    routerSvc->serviceName = L"usb4router";
    routerSvc->displayName = L"USB4 Router & Protocol Tunneling Fabric (usb4router.sys)";
    routerSvc->serviceType = scm::SERVICE_KERNEL_DRIVER;
    routerSvc->startType = scm::SERVICE_SYSTEM_START;
    routerSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
    routerSvc->binaryPath = L"C:\\Windows\\System32\\drivers\\usb4router.sys";
    routerSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
    scm::ServiceControlManager::get().registerServiceRecord(routerSvc);

    // 4. Register Version Database Records
    auto& verDb = version::VersionDatabase::Instance();
    verDb.RegisterModule("usb4host.sys", "10.0.22621.1", "MicaNT USB4 Host Router Subsystem");
    verDb.RegisterModule("thunderbolt.sys", "10.0.22621.1", "MicaNT Thunderbolt 4 Security Subsystem");
    verDb.RegisterModule("usb4router.sys", "10.0.22621.1", "MicaNT USB4 Protocol Tunneling Subsystem");
}

} // namespace micant::usb4
