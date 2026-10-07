#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <chrono>
#include <span>
#include <queue>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ob.hpp"

namespace micant::lpc {

// Standard NT LPC Message Types
enum class PortMessageType : uint16_t {
    LpcRequest           = 1,
    LpcReply             = 2,
    LpcDatagram          = 3,
    LpcConnectionRequest = 4,
    LpcClientDied        = 5,
    LpcPortClosed        = 6,
    LpcErrorEvent        = 7
};

/**
 * @brief Standard NT LPC/ALPC Message Header (PORT_MESSAGE).
 */
struct PortMessage {
    struct {
        uint16_t dataLength{0};
        uint16_t totalLength{sizeof(PortMessage)};
    } u1;
    struct {
        uint16_t type{static_cast<uint16_t>(PortMessageType::LpcRequest)};
        uint16_t dataInfoOffset{0};
    } u2;
    ClientId clientId{};
    uint32_t messageId{0};
    uint32_t callbackId{0};
};

/**
 * @brief Internal LPC Packet containing header and variable payload.
 */
struct PortPacket {
    PortMessage header{};
    std::vector<uint8_t> payload;
};

enum class PortType : uint32_t {
    ConnectionPort,            // Named listener port (e.g. \RPC Control\MicaPort)
    ServerCommunicationPort,   // Server-side dedicated endpoint
    ClientCommunicationPort    // Client-side dedicated endpoint
};

class PortObject;

/**
 * @brief Advanced Local Procedure Call (ALPC) Port Object.
 * Implements high-throughput, synchronous rendezvous message queues between NT processes.
 */
class PortObject : public std::enable_shared_from_this<PortObject> {
public:
    PortObject(std::wstring name, PortType type)
        : name_(std::move(name)), type_(type) {}

    [[nodiscard]] const std::wstring& getName() const noexcept { return name_; }
    [[nodiscard]] PortType getType() const noexcept { return type_; }
    [[nodiscard]] bool isConnected() const noexcept { return !peerPort_.expired(); }

    void setPeerPort(std::shared_ptr<PortObject> peer) {
        peerPort_ = peer;
    }

    [[nodiscard]] std::shared_ptr<PortObject> getPeerPort() const {
        return peerPort_.lock();
    }

    /**
     * @brief Post a message packet into this port's incoming queue.
     */
    NtStatus postMessage(const PortMessage& header, std::span<const uint8_t> payload) {
        std::unique_lock<std::mutex> lock(mutex_);
        PortPacket packet{
            .header = header,
            .payload = std::vector<uint8_t>(payload.begin(), payload.end())
        };
        packet.header.u1.dataLength = static_cast<uint16_t>(payload.size());
        packet.header.u1.totalLength = static_cast<uint16_t>(sizeof(PortMessage) + payload.size());

        inboundQueue_.push(std::move(packet));
        cv_.notify_one();
        return NtStatus::Success;
    }

    /**
     * @brief Receive an incoming message from the port queue.
     */
    NtStatus receiveMessage(PortMessage& outHeader, std::vector<uint8_t>& outPayload, uint32_t timeoutMs = 0xFFFFFFFF) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (inboundQueue_.empty()) {
            if (timeoutMs == 0) {
                return NtStatus::Timeout;
            }
            if (timeoutMs == 0xFFFFFFFF) {
                cv_.wait(lock, [this]() { return !inboundQueue_.empty(); });
            } else {
                bool ok = cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this]() {
                    return !inboundQueue_.empty();
                });
                if (!ok) return NtStatus::Timeout;
            }
        }

        auto packet = std::move(inboundQueue_.front());
        inboundQueue_.pop();

        outHeader = packet.header;
        outPayload = std::move(packet.payload);
        return NtStatus::Success;
    }

    /**
     * @brief Synchronous LPC Request-Wait-Reply Rendezvous.
     * Posts request to peer communication port and waits for matching reply.
     */
    NtStatus requestWaitReply(
        const PortMessage& reqHeader,
        std::span<const uint8_t> reqPayload,
        PortMessage& replyHeader,
        std::vector<uint8_t>& replyPayload,
        uint32_t timeoutMs = 5000
    ) {
        auto peer = peerPort_.lock();
        if (!peer) return NtStatus::PortConnectionRefused;

        // Generate sequential message ID if not provided
        PortMessage msg = reqHeader;
        if (msg.messageId == 0) {
            static std::atomic<uint32_t> s_NextMsgId{1};
            msg.messageId = s_NextMsgId++;
        }
        msg.u2.type = static_cast<uint16_t>(PortMessageType::LpcRequest);

        // Send request to server peer
        NtStatus sendStatus = peer->postMessage(msg, reqPayload);
        if (!NT_SUCCESS(sendStatus)) return sendStatus;

        // Wait for reply on this port
        auto startTime = std::chrono::steady_clock::now();
        while (true) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed >= timeoutMs) {
                return NtStatus::Timeout;
            }

            uint32_t remaining = static_cast<uint32_t>(timeoutMs - elapsed);
            PortMessage incoming{};
            std::vector<uint8_t> incomingData;

            NtStatus recStatus = receiveMessage(incoming, incomingData, remaining);
            if (!NT_SUCCESS(recStatus)) return recStatus;

            // Check if this reply matches our messageId
            if (incoming.messageId == msg.messageId && 
                incoming.u2.type == static_cast<uint16_t>(PortMessageType::LpcReply)) {
                replyHeader = incoming;
                replyPayload = std::move(incomingData);
                return NtStatus::Success;
            }
        }
    }

    /**
     * @brief Send a reply to a previous request across the peer port.
     */
    NtStatus reply(const PortMessage& reqHeader, std::span<const uint8_t> replyPayload) {
        auto peer = peerPort_.lock();
        if (!peer) return NtStatus::PortConnectionRefused;

        PortMessage replyMsg = reqHeader;
        replyMsg.u2.type = static_cast<uint16_t>(PortMessageType::LpcReply);
        return peer->postMessage(replyMsg, replyPayload);
    }

    [[nodiscard]] size_t getQueuedCount() const {
        std::unique_lock<std::mutex> lock(mutex_);
        return inboundQueue_.size();
    }

private:
    std::wstring name_;
    PortType type_;
    std::weak_ptr<PortObject> peerPort_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<PortPacket> inboundQueue_;
};

/**
 * @brief ALPC Subsystem Manager.
 * Registers and connects message ports under \RPC Control.
 */
class PortManager {
public:
    static PortManager& get() {
        static PortManager instance;
        return instance;
    }

    /**
     * @brief Create a named connection port under \RPC Control\<name>.
     */
    std::shared_ptr<PortObject> createPort(std::wstring_view name) {
        std::unique_lock<std::mutex> lock(mutex_);
        std::wstring fullName = normalizePortName(name);

        auto it = namedPorts_.find(fullName);
        if (it != namedPorts_.end()) return nullptr;

        auto port = std::make_shared<PortObject>(fullName, PortType::ConnectionPort);
        namedPorts_[fullName] = port;
        return port;
    }

    /**
     * @brief Connect a client to a named connection port, generating paired endpoints.
     */
    NtStatus connectPort(
        std::wstring_view name,
        std::shared_ptr<PortObject>& clientCommPort,
        std::shared_ptr<PortObject>& serverCommPort
    ) {
        std::unique_lock<std::mutex> lock(mutex_);
        std::wstring fullName = normalizePortName(name);

        auto it = namedPorts_.find(fullName);
        if (it == namedPorts_.end()) {
            return NtStatus::ObjectNameNotFound;
        }

        // Create paired bidirectional communication endpoints
        clientCommPort = std::make_shared<PortObject>(fullName + L":Client", PortType::ClientCommunicationPort);
        serverCommPort = std::make_shared<PortObject>(fullName + L":Server", PortType::ServerCommunicationPort);

        clientCommPort->setPeerPort(serverCommPort);
        serverCommPort->setPeerPort(clientCommPort);

        return NtStatus::Success;
    }

    [[nodiscard]] std::shared_ptr<PortObject> lookupPort(std::wstring_view name) const {
        std::unique_lock<std::mutex> lock(mutex_);
        std::wstring fullName = normalizePortName(name);
        auto it = namedPorts_.find(fullName);
        if (it != namedPorts_.end()) return it->second;
        return nullptr;
    }

    [[nodiscard]] size_t getPortCount() const {
        std::unique_lock<std::mutex> lock(mutex_);
        return namedPorts_.size();
    }

private:
    PortManager() = default;

    static std::wstring normalizePortName(std::wstring_view name) {
        if (name.starts_with(L"\\RPC Control\\")) {
            return std::wstring(name);
        }
        if (name.starts_with(L"\\")) {
            return std::wstring(L"\\RPC Control") + std::wstring(name);
        }
        return std::wstring(L"\\RPC Control\\") + std::wstring(name);
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::wstring, std::shared_ptr<PortObject>> namedPorts_;
};

} // namespace micant::lpc
