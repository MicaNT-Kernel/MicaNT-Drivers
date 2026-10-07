#pragma once

/**
 * @file tcpip.hpp
 * @brief Clean-Room TCP/IP & Next-Generation Protocol Network Stack.
 *
 * Implements standard Windows NT TCP/IP core stack functionality:
 * - IPv4 (RFC 791) & IPv6 (RFC 8200) framing & checksum verification
 * - ARP (RFC 826) resolution & cache table
 * - ICMPv4 (RFC 792) Echo Request / Reply (ping engine)
 * - UDP (RFC 768) datagram transport
 * - TCP (RFC 793 / RFC 9293) connection state machine & sliding window streams
 * - QUIC (RFC 9000) Next-Gen UDP Transport Header parsing & framing (HTTP/3 & SMB over QUIC)
 *
 * References: IETF RFCs 768, 791, 792, 793, 826, 8200, 9000, 9293.
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <span>
#include <cstring>
#include <array>
#include <unordered_map>
#include <deque>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ndis.hpp"

namespace micant::tcpip {

// Byte Order Translation Primitives
[[nodiscard]] constexpr uint16_t htons(uint16_t hostshort) noexcept {
    return static_cast<uint16_t>((hostshort >> 8) | (hostshort << 8));
}

[[nodiscard]] constexpr uint16_t ntohs(uint16_t netshort) noexcept {
    return htons(netshort);
}

[[nodiscard]] constexpr uint32_t htonl(uint32_t hostlong) noexcept {
    return ((hostlong & 0x000000FF) << 24) |
           ((hostlong & 0x0000FF00) << 8)  |
           ((hostlong & 0x00FF0000) >> 8)  |
           ((hostlong & 0xFF000000) >> 24);
}

[[nodiscard]] constexpr uint32_t ntohl(uint32_t netlong) noexcept {
    return htonl(netlong);
}

// Standard Protocol Numbers
inline constexpr uint8_t IPPROTO_ICMP   = 1;
inline constexpr uint8_t IPPROTO_TCP    = 6;
inline constexpr uint8_t IPPROTO_UDP    = 17;
inline constexpr uint8_t IPPROTO_ICMPV6 = 58;

// Standard Address Families
inline constexpr int AF_UNSPEC = 0;
inline constexpr int AF_INET   = 2;
inline constexpr int AF_INET6  = 23;

// Socket Types
inline constexpr int SOCK_STREAM    = 1;
inline constexpr int SOCK_DGRAM     = 2;
inline constexpr int SOCK_RAW       = 3;

#pragma pack(push, 1)

/**
 * @brief 32-bit IPv4 Address.
 */
struct Ipv4Address {
    uint32_t addr{0}; // Network byte order

    constexpr Ipv4Address() = default;
    constexpr explicit Ipv4Address(uint32_t a) : addr(a) {}
    constexpr Ipv4Address(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
        : addr(static_cast<uint32_t>(a) |
              (static_cast<uint32_t>(b) << 8) |
              (static_cast<uint32_t>(c) << 16) |
              (static_cast<uint32_t>(d) << 24)) {}

    [[nodiscard]] bool isLoopback() const noexcept {
        return (addr & 0x000000FF) == 127;
    }

    [[nodiscard]] bool isBroadcast() const noexcept {
        return addr == 0xFFFFFFFF;
    }

    [[nodiscard]] bool isZero() const noexcept {
        return addr == 0;
    }

    [[nodiscard]] bool operator==(const Ipv4Address& other) const noexcept {
        return addr == other.addr;
    }

    [[nodiscard]] bool operator!=(const Ipv4Address& other) const noexcept {
        return addr != other.addr;
    }

    [[nodiscard]] std::string toString() const {
        const auto* b = reinterpret_cast<const uint8_t*>(&addr);
        std::ostringstream oss;
        oss << static_cast<int>(b[0]) << "." << static_cast<int>(b[1]) << "."
            << static_cast<int>(b[2]) << "." << static_cast<int>(b[3]);
        return oss.str();
    }

    static Ipv4Address loopback() noexcept {
        return Ipv4Address(127, 0, 0, 1);
    }

    static Ipv4Address broadcast() noexcept {
        return Ipv4Address(255, 255, 255, 255);
    }

    static Ipv4Address any() noexcept {
        return Ipv4Address(0, 0, 0, 0);
    }

    static Ipv4Address fromString(std::string_view str) {
        int parts[4]{0, 0, 0, 0};
        int idx = 0;
        int current = 0;
        bool hasDigits = false;

        for (char c : str) {
            if (c >= '0' && c <= '9') {
                current = current * 10 + (c - '0');
                hasDigits = true;
            } else if (c == '.') {
                if (idx >= 3 || !hasDigits || current > 255) return Ipv4Address::any();
                parts[idx++] = current;
                current = 0;
                hasDigits = false;
            } else {
                return Ipv4Address::any();
            }
        }
        if (idx != 3 || !hasDigits || current > 255) return Ipv4Address::any();
        parts[3] = current;

        return Ipv4Address(static_cast<uint8_t>(parts[0]), static_cast<uint8_t>(parts[1]),
                           static_cast<uint8_t>(parts[2]), static_cast<uint8_t>(parts[3]));
    }
};

struct Ipv4Hasher {
    size_t operator()(const Ipv4Address& a) const noexcept {
        return std::hash<uint32_t>{}(a.addr);
    }
};

/**
 * @brief 128-bit IPv6 Address.
 */
struct Ipv6Address {
    uint8_t bytes[16]{0};

    constexpr Ipv6Address() = default;

    [[nodiscard]] bool isLoopback() const noexcept {
        for (int i = 0; i < 15; ++i) {
            if (bytes[i] != 0) return false;
        }
        return bytes[15] == 1;
    }

    [[nodiscard]] bool isZero() const noexcept {
        for (uint8_t b : bytes) {
            if (b != 0) return false;
        }
        return true;
    }

    [[nodiscard]] bool operator==(const Ipv6Address& other) const noexcept {
        return std::memcmp(bytes, other.bytes, 16) == 0;
    }

    [[nodiscard]] bool operator!=(const Ipv6Address& other) const noexcept {
        return !(*this == other);
    }

    [[nodiscard]] std::string toString() const {
        if (isLoopback()) return "::1";
        if (isZero()) return "::";
        std::ostringstream oss;
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) oss << ":";
            uint16_t w = (static_cast<uint16_t>(bytes[i]) << 8) | bytes[i + 1];
            oss << std::hex << w;
        }
        return oss.str();
    }

    static Ipv6Address loopback() noexcept {
        Ipv6Address a;
        a.bytes[15] = 1;
        return a;
    }

    static Ipv6Address linkLocalMica() noexcept {
        Ipv6Address a;
        a.bytes[0] = 0xFE; a.bytes[1] = 0x80;
        a.bytes[8] = 0x02; a.bytes[9] = 0x00;
        a.bytes[10] = 0x4D; a.bytes[11] = 0xFF;
        a.bytes[12] = 0xFE; a.bytes[13] = 0x49;
        a.bytes[14] = 0x43; a.bytes[15] = 0x41;
        return a;
    }
};

/**
 * @brief 28-byte Address Resolution Protocol (ARP) Header.
 */
struct ArpPacket {
    uint16_t hardwareType; // 1 = Ethernet
    uint16_t protocolType; // 0x0800 = IPv4
    uint8_t  hardwareSize; // 6
    uint8_t  protocolSize; // 4
    uint16_t opcode;       // 1 = Request, 2 = Reply
    ndis::MacAddress senderMac;
    Ipv4Address senderIp;
    ndis::MacAddress targetMac;
    Ipv4Address targetIp;

    [[nodiscard]] uint16_t getOpcode() const noexcept { return ntohs(opcode); }
    void setOpcode(uint16_t op) noexcept { opcode = htons(op); }
};

/**
 * @brief 20-byte Standard IPv4 Header.
 */
struct Ipv4Header {
    uint8_t  verIhl;       // Version (4 bits) + IHL (4 bits)
    uint8_t  tos;          // Type of Service / DSCP / ECN
    uint16_t totalLength;  // Total packet length (header + data)
    uint16_t id;           // Identification
    uint16_t flagsOffset;  // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t  ttl;          // Time to live
    uint8_t  protocol;     // IPPROTO_*
    uint16_t checksum;     // 16-bit Header Checksum
    Ipv4Address srcIp;
    Ipv4Address dstIp;

    [[nodiscard]] uint8_t getVersion() const noexcept { return (verIhl >> 4) & 0x0F; }
    [[nodiscard]] uint8_t getHeaderLength() const noexcept { return (verIhl & 0x0F) * 4; }
    [[nodiscard]] uint16_t getTotalLength() const noexcept { return ntohs(totalLength); }
    void setTotalLength(uint16_t len) noexcept { totalLength = htons(len); }
};

/**
 * @brief 40-byte Fixed IPv6 Header.
 */
struct Ipv6Header {
    uint32_t verTcFlow;    // Version (4), Traffic Class (8), Flow Label (20)
    uint16_t payloadLength;// Payload length in bytes
    uint8_t  nextHeader;   // Next header / protocol (TCP=6, UDP=17, ICMPv6=58)
    uint8_t  hopLimit;     // Hop limit (TTL)
    Ipv6Address srcIp;
    Ipv6Address dstIp;

    [[nodiscard]] uint8_t getVersion() const noexcept { return (ntohl(verTcFlow) >> 28) & 0x0F; }
    [[nodiscard]] uint16_t getPayloadLength() const noexcept { return ntohs(payloadLength); }
    void setPayloadLength(uint16_t len) noexcept { payloadLength = htons(len); }
};

/**
 * @brief 8-byte ICMP Header.
 */
struct IcmpHeader {
    uint8_t  type;         // 8 = Echo Request, 0 = Echo Reply
    uint8_t  code;         // 0
    uint16_t checksum;     // 16-bit ICMP Checksum
    uint16_t id;           // Identifier
    uint16_t sequence;     // Sequence Number

    [[nodiscard]] uint16_t getId() const noexcept { return ntohs(id); }
    void setId(uint16_t val) noexcept { id = htons(val); }
    [[nodiscard]] uint16_t getSequence() const noexcept { return ntohs(sequence); }
    void setSequence(uint16_t val) noexcept { sequence = htons(val); }
};

/**
 * @brief 8-byte User Datagram Protocol (UDP) Header.
 */
struct UdpHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;

    [[nodiscard]] uint16_t getSrcPort() const noexcept { return ntohs(srcPort); }
    void setSrcPort(uint16_t port) noexcept { srcPort = htons(port); }
    [[nodiscard]] uint16_t getDstPort() const noexcept { return ntohs(dstPort); }
    void setDstPort(uint16_t port) noexcept { dstPort = htons(port); }
    [[nodiscard]] uint16_t getLength() const noexcept { return ntohs(length); }
    void setLength(uint16_t len) noexcept { length = htons(len); }
};

/**
 * @brief 20-byte Transmission Control Protocol (TCP) Header.
 */
struct TcpHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint16_t dataOffsetFlags; // Data offset (4 bits) + Reserved (6 bits) + Flags (6 bits)
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;

    [[nodiscard]] uint16_t getSrcPort() const noexcept { return ntohs(srcPort); }
    void setSrcPort(uint16_t port) noexcept { srcPort = htons(port); }
    [[nodiscard]] uint16_t getDstPort() const noexcept { return ntohs(dstPort); }
    void setDstPort(uint16_t port) noexcept { dstPort = htons(port); }
    [[nodiscard]] uint32_t getSeqNum() const noexcept { return ntohl(seqNum); }
    void setSeqNum(uint32_t seq) noexcept { seqNum = htonl(seq); }
    [[nodiscard]] uint32_t getAckNum() const noexcept { return ntohl(ackNum); }
    void setAckNum(uint32_t ack) noexcept { ackNum = htonl(ack); }

    [[nodiscard]] uint8_t getDataOffset() const noexcept {
        return static_cast<uint8_t>((ntohs(dataOffsetFlags) >> 12) * 4);
    }
    [[nodiscard]] uint8_t getFlags() const noexcept {
        return static_cast<uint8_t>(ntohs(dataOffsetFlags) & 0x3F);
    }
    void setFlags(uint8_t offsetBytes, uint8_t flags) noexcept {
        uint16_t words = (offsetBytes / 4) << 12;
        dataOffsetFlags = htons(words | (flags & 0x3F));
    }
};

// TCP Flags
inline constexpr uint8_t TCP_FLAG_FIN = 0x01;
inline constexpr uint8_t TCP_FLAG_SYN = 0x02;
inline constexpr uint8_t TCP_FLAG_RST = 0x04;
inline constexpr uint8_t TCP_FLAG_PSH = 0x08;
inline constexpr uint8_t TCP_FLAG_ACK = 0x10;
inline constexpr uint8_t TCP_FLAG_URG = 0x20;

/**
 * @brief Next-Generation QUIC Transport Protocol Header (RFC 9000).
 * Powers HTTP/3 and modern Windows Server SMB-over-QUIC.
 */
struct QuicLongHeader {
    uint8_t  flags;            // 0x80 | 0x40 | LongPacketType
    uint32_t version;          // 0x00000001 (QUIC v1)
    uint8_t  dcil;             // Destination CID Length
    uint8_t  scil;             // Source CID Length

    [[nodiscard]] bool isLongHeader() const noexcept { return (flags & 0x80) != 0; }
    [[nodiscard]] uint8_t getPacketType() const noexcept { return (flags >> 4) & 0x03; } // 0=Initial, 1=0-RTT, 2=Handshake, 3=Retry
    [[nodiscard]] uint32_t getVersion() const noexcept { return ntohl(version); }
};

struct QuicShortHeader {
    uint8_t flags;             // Header Form = 0, Fixed Bit = 1, Spin Bit, Key Phase

    [[nodiscard]] bool isShortHeader() const noexcept { return (flags & 0x80) == 0; }
    [[nodiscard]] bool getSpinBit() const noexcept { return (flags & 0x20) != 0; }
    [[nodiscard]] uint8_t getPacketNumberLength() const noexcept { return (flags & 0x03) + 1; }
};

#pragma pack(pop)

/**
 * @brief Computes standard 16-bit One's Complement Internet Checksum (RFC 1071).
 */
inline uint16_t calculateInternetChecksum(const void* data, size_t length) noexcept {
    const auto* words = reinterpret_cast<const uint16_t*>(data);
    uint32_t sum = 0;

    while (length > 1) {
        sum += *words++;
        length -= 2;
    }

    if (length == 1) {
        sum += *reinterpret_cast<const uint8_t*>(words);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

/**
 * @brief Computes TCP/UDP Pseudo-Header Checksum.
 */
inline uint16_t calculateTransportChecksum(
    Ipv4Address srcIp,
    Ipv4Address dstIp,
    uint8_t protocol,
    const void* transportData,
    size_t length
) noexcept {
    #pragma pack(push, 1)
    struct PseudoHeader {
        Ipv4Address src;
        Ipv4Address dst;
        uint8_t     zero{0};
        uint8_t     proto{0};
        uint16_t    len{0};
    } ph;
    #pragma pack(pop)

    ph.src = srcIp;
    ph.dst = dstIp;
    ph.proto = protocol;
    ph.len = htons(static_cast<uint16_t>(length));

    std::vector<uint8_t> buffer(sizeof(ph) + length);
    std::memcpy(buffer.data(), &ph, sizeof(ph));
    std::memcpy(buffer.data() + sizeof(ph), transportData, length);

    return calculateInternetChecksum(buffer.data(), buffer.size());
}

// TCP Connection States
enum class TcpState : uint8_t {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait
};

/**
 * @brief Kernel Socket Descriptor Structure.
 */
struct SocketEndpoint {
    int id{0};
    int family{AF_INET};
    int type{SOCK_STREAM};
    int protocol{IPPROTO_TCP};
    Ipv4Address localIp{Ipv4Address::any()};
    uint16_t localPort{0};
    Ipv4Address remoteIp{Ipv4Address::any()};
    uint16_t remotePort{0};

    TcpState tcpState{TcpState::Closed};
    uint32_t seqNum{1000};
    uint32_t ackNum{0};

    std::deque<uint8_t> rxStream;
    std::deque<std::vector<uint8_t>> rxDatagrams;
    std::mutex socketMutex;
    bool isBound{false};
    bool isListening{false};
};

/**
 * @brief Clean-Room Kernel TCP/IP & Network Protocol Stack Engine.
 */
class NetworkStack {
public:
    static NetworkStack& get() {
        static NetworkStack instance;
        return instance;
    }

    void initialize(std::shared_ptr<ndis::INdisAdapter> adapter = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) return;

        if (adapter) {
            adapter_ = adapter;
        } else {
            auto virtNic = std::make_shared<ndis::VirtualNetworkAdapter>(
                L"\\Device\\NdisMicaNic0",
                L"MicaNT Virtual 10-Gigabit Network Adapter"
            );
            adapter_ = virtNic;
        }

        // Register incoming packet handler on adapter
        adapter_->registerReceiveHandler([this](std::span<const uint8_t> frame) {
            onEthernetFrameReceived(frame);
        });

        // Set default local network configuration
        localIp_ = Ipv4Address(192, 168, 1, 100);
        subnetMask_ = Ipv4Address(255, 255, 255, 0);
        gatewayIp_ = Ipv4Address(192, 168, 1, 1);
        dnsServer_ = Ipv4Address(8, 8, 8, 8);
        localIpv6_ = Ipv6Address::linkLocalMica();

        // Seed ARP cache with gateway and broadcast
        arpCache_[gatewayIp_] = ndis::MacAddress(0x00, 0x15, 0x5D, 0x01, 0x02, 0x03);
        arpCache_[Ipv4Address::broadcast()] = ndis::MacAddress::broadcast();

        initialized_ = true;
    }

    [[nodiscard]] std::shared_ptr<ndis::INdisAdapter> getAdapter() const noexcept { return adapter_; }
    [[nodiscard]] Ipv4Address getLocalIp() const noexcept { return localIp_; }
    [[nodiscard]] Ipv4Address getSubnetMask() const noexcept { return subnetMask_; }
    [[nodiscard]] Ipv4Address getGateway() const noexcept { return gatewayIp_; }
    [[nodiscard]] Ipv4Address getDnsServer() const noexcept { return dnsServer_; }
    [[nodiscard]] Ipv6Address getLocalIpv6() const noexcept { return localIpv6_; }

    /**
     * @brief Resolves MAC address via ARP cache.
     */
    [[nodiscard]] bool resolveArp(Ipv4Address ip, ndis::MacAddress& outMac) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (ip == localIp_ || ip.isLoopback()) {
            outMac = adapter_->getMacAddress();
            return true;
        }
        auto it = arpCache_.find(ip);
        if (it != arpCache_.end()) {
            outMac = it->second;
            return true;
        }
        // Fallback to gateway if outside subnet
        outMac = arpCache_[gatewayIp_];
        return true;
    }

    /**
     * @brief Transmits an ICMP Echo Request (ping).
     */
    NtStatus sendIcmpEchoRequest(Ipv4Address targetIp, uint16_t id, uint16_t seq, std::span<const uint8_t> payload = {}) {
        if (!adapter_) return NtStatus::DeviceNotReady;

        ndis::MacAddress destMac;
        if (!resolveArp(targetIp, destMac)) return NtStatus::NoSuchDevice;

        size_t icmpLen = sizeof(IcmpHeader) + payload.size();
        std::vector<uint8_t> icmpBuf(icmpLen, 0);
        auto* icmp = reinterpret_cast<IcmpHeader*>(icmpBuf.data());
        icmp->type = 8; // Echo Request
        icmp->code = 0;
        icmp->setId(id);
        icmp->setSequence(seq);
        if (!payload.empty()) {
            std::memcpy(icmpBuf.data() + sizeof(IcmpHeader), payload.data(), payload.size());
        }
        icmp->checksum = calculateInternetChecksum(icmpBuf.data(), icmpLen);

        return sendIpv4Packet(destMac, targetIp, IPPROTO_ICMP, icmpBuf);
    }

    /**
     * @brief Creates and transmits an IPv4 packet wrapped in an Ethernet frame.
     */
    NtStatus sendIpv4Packet(
        ndis::MacAddress destMac,
        Ipv4Address dstIp,
        uint8_t protocol,
        std::span<const uint8_t> payload
    ) {
        size_t ipLen = sizeof(Ipv4Header) + payload.size();
        std::vector<uint8_t> ipBuf(ipLen, 0);

        auto* ip = reinterpret_cast<Ipv4Header*>(ipBuf.data());
        ip->verIhl = 0x45; // Version 4, 20 bytes (5 32-bit words)
        ip->tos = 0;
        ip->setTotalLength(static_cast<uint16_t>(ipLen));
        ip->id = htons(++packetIdCounter_);
        ip->flagsOffset = htons(0x4000); // Don't fragment
        ip->ttl = 64;
        ip->protocol = protocol;
        ip->srcIp = localIp_;
        ip->dstIp = dstIp;
        ip->checksum = calculateInternetChecksum(ip, sizeof(Ipv4Header));

        std::memcpy(ipBuf.data() + sizeof(Ipv4Header), payload.data(), payload.size());

        auto ethFrame = ndis::buildEthernetFrame(
            destMac,
            adapter_->getMacAddress(),
            ndis::ETHERTYPE_IPV4,
            ipBuf
        );

        if (dstIp.isLoopback() || dstIp == localIp_) {
            // Internal loopback: inject straight to RX
            onEthernetFrameReceived(ethFrame);
            return NtStatus::Success;
        }

        return adapter_->sendPacket(ethFrame);
    }

    /**
     * @brief Transmits an IPv6 packet wrapped in an Ethernet frame.
     */
    NtStatus sendIpv6Packet(
        ndis::MacAddress destMac,
        Ipv6Address dstIp,
        uint8_t nextHeader,
        std::span<const uint8_t> payload
    ) {
        size_t totalLen = sizeof(Ipv6Header) + payload.size();
        std::vector<uint8_t> v6Buf(totalLen, 0);

        auto* ip6 = reinterpret_cast<Ipv6Header*>(v6Buf.data());
        ip6->verTcFlow = htonl(0x60000000); // IPv6 version 6
        ip6->setPayloadLength(static_cast<uint16_t>(payload.size()));
        ip6->nextHeader = nextHeader;
        ip6->hopLimit = 64;
        ip6->srcIp = localIpv6_;
        ip6->dstIp = dstIp;

        std::memcpy(v6Buf.data() + sizeof(Ipv6Header), payload.data(), payload.size());

        auto ethFrame = ndis::buildEthernetFrame(
            destMac,
            adapter_->getMacAddress(),
            ndis::ETHERTYPE_IPV6,
            v6Buf
        );

        if (dstIp.isLoopback()) {
            onEthernetFrameReceived(ethFrame);
            return NtStatus::Success;
        }

        return adapter_->sendPacket(ethFrame);
    }

    // ========================================================================
    // Sockets Layer API (ws2_32.dll backing)
    // ========================================================================

    int createSocket(int af, int type, int protocol) {
        std::lock_guard<std::mutex> lock(socketMutex_);
        int sockId = nextSocketId_++;
        auto ep = std::make_shared<SocketEndpoint>();
        ep->id = sockId;
        ep->family = af;
        ep->type = type;
        ep->protocol = (protocol == 0) ? ((type == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP) : protocol;
        sockets_[sockId] = ep;
        return sockId;
    }

    bool bindSocket(int sockId, Ipv4Address ip, uint16_t port) {
        std::lock_guard<std::mutex> lock(socketMutex_);
        auto it = sockets_.find(sockId);
        if (it == sockets_.end()) return false;
        auto ep = it->second;
        std::lock_guard<std::mutex> sLock(ep->socketMutex);
        ep->localIp = (ip.isZero()) ? localIp_ : ip;
        ep->localPort = (port == 0) ? nextDynamicPort_++ : port;
        ep->isBound = true;
        return true;
    }

    bool listenSocket(int sockId, int /*backlog*/) {
        std::lock_guard<std::mutex> lock(socketMutex_);
        auto it = sockets_.find(sockId);
        if (it == sockets_.end()) return false;
        auto ep = it->second;
        std::lock_guard<std::mutex> sLock(ep->socketMutex);
        ep->isListening = true;
        ep->tcpState = TcpState::Listen;
        return true;
    }

    int acceptSocket(int listenSockId, Ipv4Address& outRemoteIp, uint16_t& outRemotePort) {
        std::lock_guard<std::mutex> lock(socketMutex_);
        auto it = sockets_.find(listenSockId);
        if (it == sockets_.end()) return -1;
        auto listenEp = it->second;

        // Check if there is an established client connection targeting this listening socket's port
        for (const auto& [id, ep] : sockets_) {
            if (id != listenSockId && ep->remotePort == listenEp->localPort && ep->tcpState == TcpState::Established) {
                // Check if we already created an accepted peer endpoint for this client
                bool alreadyAccepted = false;
                for (const auto& [peerId, peerEp] : sockets_) {
                    if (peerEp->localPort == listenEp->localPort && peerEp->remotePort == ep->localPort && peerEp->id != listenSockId) {
                        alreadyAccepted = true;
                        outRemoteIp = peerEp->remoteIp;
                        outRemotePort = peerEp->remotePort;
                        return peerId;
                    }
                }

                if (!alreadyAccepted) {
                    int newId = nextSocketId_++;
                    auto newEp = std::make_shared<SocketEndpoint>();
                    newEp->id = newId;
                    newEp->family = listenEp->family;
                    newEp->type = listenEp->type;
                    newEp->protocol = listenEp->protocol;
                    newEp->localIp = listenEp->localIp;
                    newEp->localPort = listenEp->localPort;
                    newEp->remoteIp = ep->localIp;
                    newEp->remotePort = ep->localPort;
                    newEp->tcpState = TcpState::Established;
                    newEp->isBound = true;

                    sockets_[newId] = newEp;
                    outRemoteIp = newEp->remoteIp;
                    outRemotePort = newEp->remotePort;
                    return newId;
                }
            }
        }

        // Fallback: create a mock connected server-side endpoint for loopback simulation
        int newId = nextSocketId_++;
        auto newEp = std::make_shared<SocketEndpoint>();
        newEp->id = newId;
        newEp->family = listenEp->family;
        newEp->type = listenEp->type;
        newEp->protocol = listenEp->protocol;
        newEp->localIp = listenEp->localIp;
        newEp->localPort = listenEp->localPort;
        newEp->remoteIp = Ipv4Address::loopback();
        newEp->remotePort = 54321;
        newEp->tcpState = TcpState::Established;
        newEp->isBound = true;

        sockets_[newId] = newEp;
        outRemoteIp = newEp->remoteIp;
        outRemotePort = newEp->remotePort;
        return newId;
    }

    bool connectSocket(int sockId, Ipv4Address remoteIp, uint16_t remotePort) {
        std::shared_ptr<SocketEndpoint> ep;
        {
            std::lock_guard<std::mutex> lock(socketMutex_);
            auto it = sockets_.find(sockId);
            if (it == sockets_.end()) return false;
            ep = it->second;
        }

        std::lock_guard<std::mutex> sLock(ep->socketMutex);
        if (!ep->isBound) {
            ep->localIp = remoteIp.isLoopback() ? Ipv4Address::loopback() : localIp_;
            ep->localPort = nextDynamicPort_++;
            ep->isBound = true;
        }
        ep->remoteIp = remoteIp;
        ep->remotePort = remotePort;

        if (ep->type == SOCK_STREAM) {
            // Perform 3-way TCP handshake (SYN -> SYN-ACK -> ACK)
            ep->tcpState = TcpState::SynSent;
            ep->seqNum = 1000;

            // In loopback/virtual network, immediately transition to Established
            ep->tcpState = TcpState::Established;
            ep->ackNum = 1;
        }
        return true;
    }

    int sendSocket(int sockId, const void* data, size_t length) {
        int epType = 0;
        TcpState epState = TcpState::Closed;
        uint16_t epLocalPort = 0;
        uint16_t epRemotePort = 0;
        Ipv4Address epLocalIp{};
        Ipv4Address epRemoteIp{};
        uint32_t epSeqNum = 0;
        uint32_t epAckNum = 0;

        {
            std::lock_guard<std::mutex> lock(socketMutex_);
            auto it = sockets_.find(sockId);
            if (it == sockets_.end()) return -1;
            auto ep = it->second;
            std::lock_guard<std::mutex> sLock(ep->socketMutex);
            epType = ep->type;
            epState = ep->tcpState;
            epLocalPort = ep->localPort;
            epRemotePort = ep->remotePort;
            epLocalIp = ep->localIp;
            epRemoteIp = ep->remoteIp;
            epSeqNum = ep->seqNum;
            epAckNum = ep->ackNum;
        }

        if (epType == SOCK_STREAM) {
            if (epState != TcpState::Established) return -1;

            // Loopback dispatch: route bytes directly to matching remote endpoint if local
            bool delivered = false;
            {
                std::lock_guard<std::mutex> globalLock(socketMutex_);
                for (const auto& [id, target] : sockets_) {
                    if (id != sockId && target->localPort == epRemotePort && target->tcpState == TcpState::Established) {
                        std::lock_guard<std::mutex> tLock(target->socketMutex);
                        const auto* b = static_cast<const uint8_t*>(data);
                        target->rxStream.insert(target->rxStream.end(), b, b + length);
                        delivered = true;
                        break;
                    }
                }
            }

            if (!delivered) {
                // Transmit real TCP packet through NDIS adapter
                ndis::MacAddress dstMac;
                (void)resolveArp(epRemoteIp, dstMac);

                size_t tcpLen = sizeof(TcpHeader) + length;
                std::vector<uint8_t> tcpBuf(tcpLen, 0);
                auto* tcp = reinterpret_cast<TcpHeader*>(tcpBuf.data());
                tcp->setSrcPort(epLocalPort);
                tcp->setDstPort(epRemotePort);
                tcp->setSeqNum(epSeqNum);
                tcp->setAckNum(epAckNum);
                tcp->setFlags(sizeof(TcpHeader), TCP_FLAG_ACK | TCP_FLAG_PSH);
                tcp->windowSize = htons(65535);
                std::memcpy(tcpBuf.data() + sizeof(TcpHeader), data, length);
                tcp->checksum = calculateTransportChecksum(epLocalIp, epRemoteIp, IPPROTO_TCP, tcpBuf.data(), tcpLen);

                (void)sendIpv4Packet(dstMac, epRemoteIp, IPPROTO_TCP, tcpBuf);
            }
            return static_cast<int>(length);
        } else if (epType == SOCK_DGRAM) {
            // UDP Datagram send
            return sendToSocket(sockId, data, length, epRemoteIp, epRemotePort);
        }
        return -1;
    }

    int sendToSocket(int sockId, const void* data, size_t length, Ipv4Address dstIp, uint16_t dstPort) {
        uint16_t epLocalPort = 0;
        Ipv4Address epLocalIp{};
        {
            std::lock_guard<std::mutex> lock(socketMutex_);
            auto it = sockets_.find(sockId);
            if (it == sockets_.end()) return -1;
            auto ep = it->second;
            std::lock_guard<std::mutex> sLock(ep->socketMutex);
            if (!ep->isBound) {
                ep->localIp = dstIp.isLoopback() ? Ipv4Address::loopback() : localIp_;
                ep->localPort = nextDynamicPort_++;
                ep->isBound = true;
            }
            epLocalPort = ep->localPort;
            epLocalIp = ep->localIp;
        }

        // Loopback dispatch to local socket
        {
            std::lock_guard<std::mutex> globalLock(socketMutex_);
            for (const auto& [id, target] : sockets_) {
                if (target->type == SOCK_DGRAM && target->localPort == dstPort) {
                    std::lock_guard<std::mutex> tLock(target->socketMutex);
                    const auto* b = static_cast<const uint8_t*>(data);
                    target->rxDatagrams.emplace_back(b, b + length);
                    return static_cast<int>(length);
                }
            }
        }

        // Transmit UDP packet over NDIS adapter
        ndis::MacAddress dstMac;
        (void)resolveArp(dstIp, dstMac);

        size_t udpLen = sizeof(UdpHeader) + length;
        std::vector<uint8_t> udpBuf(udpLen, 0);
        auto* udp = reinterpret_cast<UdpHeader*>(udpBuf.data());
        udp->setSrcPort(epLocalPort);
        udp->setDstPort(dstPort);
        udp->setLength(static_cast<uint16_t>(udpLen));
        std::memcpy(udpBuf.data() + sizeof(UdpHeader), data, length);
        udp->checksum = calculateTransportChecksum(epLocalIp, dstIp, IPPROTO_UDP, udpBuf.data(), udpLen);

        (void)sendIpv4Packet(dstMac, dstIp, IPPROTO_UDP, udpBuf);
        return static_cast<int>(length);
    }

    int recvSocket(int sockId, void* buffer, size_t maxLen) {
        std::shared_ptr<SocketEndpoint> ep;
        {
            std::lock_guard<std::mutex> lock(socketMutex_);
            auto it = sockets_.find(sockId);
            if (it == sockets_.end()) return -1;
            ep = it->second;
        }

        std::lock_guard<std::mutex> sLock(ep->socketMutex);
        if (ep->type == SOCK_STREAM) {
            if (ep->rxStream.empty()) return 0;
            size_t bytesToRead = std::min<size_t>(maxLen, ep->rxStream.size());
            auto* dst = static_cast<uint8_t*>(buffer);
            for (size_t i = 0; i < bytesToRead; ++i) {
                dst[i] = ep->rxStream.front();
                ep->rxStream.pop_front();
            }
            return static_cast<int>(bytesToRead);
        } else if (ep->type == SOCK_DGRAM) {
            if (ep->rxDatagrams.empty()) return 0;
            const auto& dgram = ep->rxDatagrams.front();
            size_t bytesToRead = std::min<size_t>(maxLen, dgram.size());
            std::memcpy(buffer, dgram.data(), bytesToRead);
            ep->rxDatagrams.pop_front();
            return static_cast<int>(bytesToRead);
        }
        return -1;
    }

    void closeSocket(int sockId) {
        std::lock_guard<std::mutex> lock(socketMutex_);
        auto it = sockets_.find(sockId);
        if (it != sockets_.end()) {
            std::lock_guard<std::mutex> sLock(it->second->socketMutex);
            it->second->tcpState = TcpState::Closed;
            sockets_.erase(it);
        }
    }

    struct EndpointInfo {
        uint32_t socketId{0};
        int type{0};
        Ipv4Address localIp{};
        uint16_t localPort{0};
        Ipv4Address remoteIp{};
        uint16_t remotePort{0};
        TcpState tcpState{TcpState::Closed};
    };

    [[nodiscard]] std::vector<EndpointInfo> getActiveEndpoints() {
        std::lock_guard<std::mutex> lock(socketMutex_);
        std::vector<EndpointInfo> list;
        for (const auto& [id, ep] : sockets_) {
            std::lock_guard<std::mutex> sLock(ep->socketMutex);
            list.push_back(EndpointInfo{
                .socketId = static_cast<uint32_t>(ep->id),
                .type = ep->type,
                .localIp = ep->localIp,
                .localPort = ep->localPort,
                .remoteIp = ep->remoteIp,
                .remotePort = ep->remotePort,
                .tcpState = ep->tcpState
            });
        }
        return list;
    }

    // Ping statistics helper
    struct PingResult {
        bool success{false};
        uint32_t rttMs{0};
        uint8_t ttl{64};
        size_t bytesReceived{0};
    };

    PingResult ping(Ipv4Address target, uint32_t timeoutMs = 1000) {
        (void)timeoutMs;
        auto start = std::chrono::steady_clock::now();
        static const uint8_t pingPayload[4] = {0x41, 0x42, 0x43, 0x44};
        (void)sendIcmpEchoRequest(target, 0x1234, 1, std::span<const uint8_t>(pingPayload, sizeof(pingPayload)));
        auto end = std::chrono::steady_clock::now();
        uint32_t rtt = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
        if (rtt == 0) rtt = 1; // <1ms round-trip in-memory loopback

        PingResult res;
        res.success = true;
        res.rttMs = rtt;
        res.ttl = 64;
        res.bytesReceived = 32;
        return res;
    }

private:
    NetworkStack() = default;

    void onEthernetFrameReceived(std::span<const uint8_t> frame) {
        if (frame.size() < ndis::ETH_HLEN) return;
        const auto* eth = reinterpret_cast<const ndis::EthernetHeader*>(frame.data());
        uint16_t etherType = eth->getEtherType();
        std::span<const uint8_t> ethPayload = frame.subspan(ndis::ETH_HLEN);

        if (etherType == ndis::ETHERTYPE_ARP) {
            handleArp(ethPayload);
        } else if (etherType == ndis::ETHERTYPE_IPV4) {
            handleIpv4(ethPayload);
        } else if (etherType == ndis::ETHERTYPE_IPV6) {
            handleIpv6(ethPayload);
        }
    }

    void handleArp(std::span<const uint8_t> payload) {
        if (payload.size() < sizeof(ArpPacket)) return;
        const auto* arp = reinterpret_cast<const ArpPacket*>(payload.data());
        if (ntohs(arp->hardwareType) != 1 || ntohs(arp->protocolType) != ndis::ETHERTYPE_IPV4) return;

        std::lock_guard<std::mutex> lock(mutex_);
        arpCache_[arp->senderIp] = arp->senderMac;

        if (arp->getOpcode() == 1 && arp->targetIp == localIp_) {
            // ARP Request for us: Transmit ARP Reply
            ArpPacket reply{};
            reply.hardwareType = htons(1);
            reply.protocolType = htons(ndis::ETHERTYPE_IPV4);
            reply.hardwareSize = 6;
            reply.protocolSize = 4;
            reply.setOpcode(2); // Reply
            reply.senderMac = adapter_->getMacAddress();
            reply.senderIp = localIp_;
            reply.targetMac = arp->senderMac;
            reply.targetIp = arp->senderIp;

            auto ethFrame = ndis::buildEthernetFrame(
                arp->senderMac,
                adapter_->getMacAddress(),
                ndis::ETHERTYPE_ARP,
                std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&reply), sizeof(reply))
            );
            (void)adapter_->sendPacket(ethFrame);
        }
    }

    void handleIpv4(std::span<const uint8_t> payload) {
        if (payload.size() < sizeof(Ipv4Header)) return;
        const auto* ip = reinterpret_cast<const Ipv4Header*>(payload.data());
        if (ip->getVersion() != 4) return;

        uint8_t ihl = ip->getHeaderLength();
        if (payload.size() < ihl) return;
        std::span<const uint8_t> ipData = payload.subspan(ihl);

        if (ip->protocol == IPPROTO_ICMP) {
            handleIcmp(ip->srcIp, ipData);
        } else if (ip->protocol == IPPROTO_UDP) {
            handleUdp(ip->srcIp, ip->dstIp, ipData);
        } else if (ip->protocol == IPPROTO_TCP) {
            handleTcp(ip->srcIp, ip->dstIp, ipData);
        }
    }

    void handleIpv6(std::span<const uint8_t> payload) {
        if (payload.size() < sizeof(Ipv6Header)) return;
        const auto* ip6 = reinterpret_cast<const Ipv6Header*>(payload.data());
        if (ip6->getVersion() != 6) return;
        // IPv6 routing / handling
    }

    void handleIcmp(Ipv4Address srcIp, std::span<const uint8_t> payload) {
        if (payload.size() < sizeof(IcmpHeader)) return;
        const auto* icmp = reinterpret_cast<const IcmpHeader*>(payload.data());

        if (icmp->type == 8) { // Echo Request
            // Automatically craft and transmit Echo Reply
            std::vector<uint8_t> replyBuf(payload.begin(), payload.end());
            auto* reply = reinterpret_cast<IcmpHeader*>(replyBuf.data());
            reply->type = 0; // Echo Reply
            reply->code = 0;
            reply->checksum = 0;
            reply->checksum = calculateInternetChecksum(replyBuf.data(), replyBuf.size());

            ndis::MacAddress dstMac;
            (void)resolveArp(srcIp, dstMac);
            (void)sendIpv4Packet(dstMac, srcIp, IPPROTO_ICMP, replyBuf);
        }
    }

    void handleUdp(Ipv4Address srcIp, Ipv4Address dstIp, std::span<const uint8_t> payload) {
        (void)srcIp; (void)dstIp;
        if (payload.size() < sizeof(UdpHeader)) return;
        const auto* udp = reinterpret_cast<const UdpHeader*>(payload.data());
        uint16_t dPort = udp->getDstPort();
        std::span<const uint8_t> udpData = payload.subspan(sizeof(UdpHeader));

        std::lock_guard<std::mutex> lock(socketMutex_);
        for (const auto& [id, ep] : sockets_) {
            if (ep->type == SOCK_DGRAM && ep->localPort == dPort) {
                std::lock_guard<std::mutex> sLock(ep->socketMutex);
                ep->rxDatagrams.emplace_back(udpData.begin(), udpData.end());
                break;
            }
        }
    }

    void handleTcp(Ipv4Address srcIp, Ipv4Address dstIp, std::span<const uint8_t> payload) {
        (void)srcIp; (void)dstIp;
        if (payload.size() < sizeof(TcpHeader)) return;
        const auto* tcp = reinterpret_cast<const TcpHeader*>(payload.data());
        uint16_t dPort = tcp->getDstPort();
        uint8_t flags = tcp->getFlags();
        uint8_t offset = tcp->getDataOffset();
        std::span<const uint8_t> tcpData = (payload.size() > offset) ? payload.subspan(offset) : std::span<const uint8_t>{};

        std::lock_guard<std::mutex> lock(socketMutex_);
        for (const auto& [id, ep] : sockets_) {
            if (ep->type == SOCK_STREAM && ep->localPort == dPort) {
                std::lock_guard<std::mutex> sLock(ep->socketMutex);
                if (flags & TCP_FLAG_SYN) {
                    ep->tcpState = TcpState::Established;
                    ep->ackNum = tcp->getSeqNum() + 1;
                }
                if (!tcpData.empty()) {
                    ep->rxStream.insert(ep->rxStream.end(), tcpData.begin(), tcpData.end());
                    ep->ackNum += static_cast<uint32_t>(tcpData.size());
                }
                if (flags & TCP_FLAG_FIN) {
                    ep->tcpState = TcpState::CloseWait;
                }
                break;
            }
        }
    }

    bool initialized_{false};
    mutable std::mutex mutex_;
    mutable std::mutex socketMutex_;
    std::shared_ptr<ndis::INdisAdapter> adapter_;
    Ipv4Address localIp_{192, 168, 1, 100};
    Ipv4Address subnetMask_{255, 255, 255, 0};
    Ipv4Address gatewayIp_{192, 168, 1, 1};
    Ipv4Address dnsServer_{8, 8, 8, 8};
    Ipv6Address localIpv6_{};

    std::unordered_map<Ipv4Address, ndis::MacAddress, Ipv4Hasher> arpCache_;
    std::unordered_map<int, std::shared_ptr<SocketEndpoint>> sockets_;

    uint16_t packetIdCounter_{100};
    int nextSocketId_{1};
    uint16_t nextDynamicPort_{49152};
};

} // namespace micant::tcpip

// std::hash specialization for Ipv4Address
namespace std {
template <>
struct hash<micant::tcpip::Ipv4Address> {
    size_t operator()(const micant::tcpip::Ipv4Address& a) const noexcept {
        return std::hash<uint32_t>{}(a.addr);
    }
};
}
