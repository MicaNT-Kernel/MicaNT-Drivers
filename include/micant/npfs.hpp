#pragma once

/**
 * @file npfs.hpp
 * @brief Named Pipe File System (NPFS) & Mailslot File System (MSFS) Subsystems.
 *
 * Implements clean-room Windows NT IPC file systems:
 *   - \Device\NamedPipe (NPFS): Byte and Message streaming, full duplex,
 *     transactional RPC (TransactNamedPipe), Peeking, and multi-instance servers.
 *   - \Device\Mailslot (MSFS): Connectionless datagram broadcast messaging.
 *
 * References: Microsoft win32metadata & Microsoft Learn Public Win32 API Specification.
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <deque>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <span>
#include <optional>
#include <unordered_map>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "io.hpp"

namespace micant::npfs {

// ============================================================================
// 1. Named Pipe Constants & Mode Flags
// ============================================================================

inline constexpr uint32_t PIPE_ACCESS_INBOUND         = 0x00000001;
inline constexpr uint32_t PIPE_ACCESS_OUTBOUND        = 0x00000002;
inline constexpr uint32_t PIPE_ACCESS_DUPLEX          = 0x00000003;

inline constexpr uint32_t FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;
inline constexpr uint32_t FILE_FLAG_WRITE_THROUGH     = 0x80000000;
inline constexpr uint32_t FILE_FLAG_OVERLAPPED        = 0x40000000;

inline constexpr uint32_t PIPE_WAIT                   = 0x00000000;
inline constexpr uint32_t PIPE_NOWAIT                 = 0x00000001;
inline constexpr uint32_t PIPE_READMODE_BYTE          = 0x00000000;
inline constexpr uint32_t PIPE_READMODE_MESSAGE       = 0x00000002;
inline constexpr uint32_t PIPE_TYPE_BYTE              = 0x00000000;
inline constexpr uint32_t PIPE_TYPE_MESSAGE           = 0x00000004;

inline constexpr uint32_t PIPE_ACCEPT_REMOTE_CLIENTS  = 0x00000000;
inline constexpr uint32_t PIPE_REJECT_REMOTE_CLIENTS  = 0x00000008;

inline constexpr uint32_t PIPE_UNLIMITED_INSTANCES    = 255;
inline constexpr uint32_t NMPWAIT_WAIT_FOREVER        = 0xFFFFFFFF;
inline constexpr uint32_t NMPWAIT_NOWAIT              = 0x00000001;
inline constexpr uint32_t NMPWAIT_USE_DEFAULT_WAIT    = 0x00000000;

inline constexpr uint32_t PIPE_CLIENT_END             = 0x00000000;
inline constexpr uint32_t PIPE_SERVER_END             = 0x00000001;

// Mailslot Constants
inline constexpr uint32_t MAILSLOT_NO_MESSAGE         = static_cast<uint32_t>(-1);
inline constexpr uint32_t MAILSLOT_WAIT_FOREVER       = static_cast<uint32_t>(-1);

// Pipe State Machine
enum class PipeState : uint32_t {
    Listening    = 0, // Server created, awaiting client
    Connected    = 1, // Client and server both connected
    Disconnected = 2, // Server disconnected or client closed
    Closing      = 3, // Pipe being torn down
    Broken       = 4  // Connection broken (e.g. client crashed/closed)
};

// ============================================================================
// 2. Named Pipe Buffer & Message Queue
// ============================================================================

struct PipeMessage {
    std::vector<uint8_t> data;
    size_t readOffset{0};

    [[nodiscard]] size_t remaining() const noexcept {
        return (readOffset < data.size()) ? (data.size() - readOffset) : 0;
    }
};

class PipeBuffer {
public:
    explicit PipeBuffer(size_t capacity = 4096) : capacity_(capacity) {}

    void write(std::span<const uint8_t> bytes, bool asMessage) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (asMessage || messages_.empty()) {
            PipeMessage msg;
            msg.data.assign(bytes.begin(), bytes.end());
            messages_.push_back(std::move(msg));
        } else {
            // Append to current tail message if byte-mode stream
            auto& tail = messages_.back();
            tail.data.insert(tail.data.end(), bytes.begin(), bytes.end());
        }
        totalBytesAvailable_ += bytes.size();
        cv_.notify_all();
    }

    NtStatus read(
        std::span<uint8_t> outBuffer,
        bool messageMode,
        uint32_t& bytesRead,
        bool isNonBlocking,
        bool isBroken
    ) {
        std::unique_lock<std::mutex> lock(mutex_);
        bytesRead = 0;

        while (messages_.empty()) {
            if (isBroken) {
                return NtStatus::PipeBroken;
            }
            if (isNonBlocking) {
                return NtStatus::PipeBusy;
            }
            cv_.wait_for(lock, std::chrono::milliseconds(50), [&]() {
                return !messages_.empty() || isBroken;
            });
            if (messages_.empty() && isBroken) {
                return NtStatus::PipeBroken;
            }
        }

        if (messages_.empty()) {
            return isBroken ? NtStatus::PipeBroken : NtStatus::PipeBusy;
        }

        auto& front = messages_.front();
        size_t rem = front.remaining();

        if (messageMode) {
            // In message mode, each read consumes from the current message.
            // If the buffer is too small, copy partial and return BufferOverflow (ERROR_MORE_DATA).
            size_t toCopy = std::min(outBuffer.size(), rem);
            std::memcpy(outBuffer.data(), front.data.data() + front.readOffset, toCopy);
            front.readOffset += toCopy;
            totalBytesAvailable_ -= toCopy;
            bytesRead = static_cast<uint32_t>(toCopy);

            if (front.remaining() > 0) {
                return NtStatus::BufferOverflow; // Win32 ERROR_MORE_DATA
            } else {
                messages_.pop_front();
                return NtStatus::Success;
            }
        } else {
            // Byte-stream mode: drain across messages if necessary
            size_t totalCopied = 0;
            while (!messages_.empty() && totalCopied < outBuffer.size()) {
                auto& cur = messages_.front();
                size_t toCopy = std::min(outBuffer.size() - totalCopied, cur.remaining());
                std::memcpy(outBuffer.data() + totalCopied, cur.data.data() + cur.readOffset, toCopy);
                cur.readOffset += toCopy;
                totalBytesAvailable_ -= toCopy;
                totalCopied += toCopy;
                if (cur.remaining() == 0) {
                    messages_.pop_front();
                }
            }
            bytesRead = static_cast<uint32_t>(totalCopied);
            return NtStatus::Success;
        }
    }

    void peek(
        std::span<uint8_t> outBuffer,
        uint32_t* outBytesRead,
        uint32_t* outTotalBytesAvail,
        uint32_t* outBytesLeftThisMessage
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (outTotalBytesAvail) {
            *outTotalBytesAvail = static_cast<uint32_t>(totalBytesAvailable_);
        }

        if (messages_.empty()) {
            if (outBytesRead) *outBytesRead = 0;
            if (outBytesLeftThisMessage) *outBytesLeftThisMessage = 0;
            return;
        }

        const auto& front = messages_.front();
        if (outBytesLeftThisMessage) {
            *outBytesLeftThisMessage = static_cast<uint32_t>(front.remaining());
        }

        size_t totalCopied = 0;
        if (!outBuffer.empty()) {
            for (const auto& msg : messages_) {
                size_t rem = msg.remaining();
                size_t toCopy = std::min(outBuffer.size() - totalCopied, rem);
                std::memcpy(outBuffer.data() + totalCopied, msg.data.data() + msg.readOffset, toCopy);
                totalCopied += toCopy;
                if (totalCopied >= outBuffer.size()) break;
            }
        }

        if (outBytesRead) {
            *outBytesRead = static_cast<uint32_t>(totalCopied);
        }
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        messages_.clear();
        totalBytesAvailable_ = 0;
        cv_.notify_all();
    }

    [[nodiscard]] size_t getAvailable() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return totalBytesAvailable_;
    }

private:
    size_t capacity_{4096};
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<PipeMessage> messages_;
    size_t totalBytesAvailable_{0};
};

// ============================================================================
// 3. Named Pipe Instance
// ============================================================================

class NamedPipe;

class NamedPipeInstance : public std::enable_shared_from_this<NamedPipeInstance> {
public:
    NamedPipeInstance(
        std::wstring_view name,
        uint32_t openMode,
        uint32_t pipeMode,
        uint32_t maxInstances,
        uint32_t outBufferSize,
        uint32_t inBufferSize,
        uint32_t defaultTimeoutMs,
        std::weak_ptr<NamedPipe> parentPipe
    ) : name_(name),
        openMode_(openMode),
        pipeMode_(pipeMode),
        maxInstances_(maxInstances),
        outBufferSize_(outBufferSize),
        inBufferSize_(inBufferSize),
        defaultTimeoutMs_(defaultTimeoutMs),
        parentPipe_(parentPipe),
        serverToClient_(outBufferSize ? outBufferSize : 4096),
        clientToServer_(inBufferSize ? inBufferSize : 4096) {}

    [[nodiscard]] const std::wstring& getName() const noexcept { return name_; }
    [[nodiscard]] uint32_t getOpenMode() const noexcept { return openMode_; }
    [[nodiscard]] uint32_t getPipeMode() const noexcept { return pipeMode_; }
    [[nodiscard]] uint32_t getMaxInstances() const noexcept { return maxInstances_; }
    [[nodiscard]] uint32_t getOutBufferSize() const noexcept { return outBufferSize_; }
    [[nodiscard]] uint32_t getInBufferSize() const noexcept { return inBufferSize_; }
    [[nodiscard]] uint32_t getDefaultTimeout() const noexcept { return defaultTimeoutMs_; }

    [[nodiscard]] PipeState getState() const noexcept {
        return state_.load(std::memory_order_acquire);
    }

    void setMode(uint32_t newMode) noexcept {
        pipeMode_ = newMode;
    }

    NtStatus connectServer(uint32_t timeoutMs = NMPWAIT_WAIT_FOREVER) {
        std::unique_lock<std::mutex> lock(stateMutex_);
        if (state_ == PipeState::Connected) {
            return NtStatus::PipeConnected;
        }

        state_ = PipeState::Listening;
        notifyAvailable();

        auto pred = [this]() {
            return state_ == PipeState::Connected || state_ == PipeState::Closing;
        };

        if (timeoutMs == NMPWAIT_WAIT_FOREVER) {
            stateCv_.wait(lock, pred);
        } else {
            if (!stateCv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), pred)) {
                return NtStatus::Timeout;
            }
        }

        if (state_ == PipeState::Connected) {
            return NtStatus::Success;
        }
        return NtStatus::PipeBroken;
    }

    NtStatus connectClient(uint32_t /*desiredAccess*/, uint32_t /*timeoutMs*/) {
        std::lock_guard<std::mutex> lock(stateMutex_);
        if (state_ != PipeState::Listening) {
            return NtStatus::PipeBusy;
        }

        state_ = PipeState::Connected;
        clientConnected_ = true;
        stateCv_.notify_all();
        return NtStatus::Success;
    }

    NtStatus disconnectServer() {
        std::lock_guard<std::mutex> lock(stateMutex_);
        state_ = PipeState::Disconnected;
        clientConnected_ = false;
        serverToClient_.clear();
        clientToServer_.clear();
        stateCv_.notify_all();
        return NtStatus::Success;
    }

    void clientClose() {
        std::lock_guard<std::mutex> lock(stateMutex_);
        clientConnected_ = false;
        if (state_ == PipeState::Connected) {
            state_ = PipeState::Broken;
        }
        stateCv_.notify_all();
    }

    NtStatus read(bool isServer, void* buffer, uint32_t length, uint32_t& bytesRead) {
        if (!buffer) return NtStatus::InvalidParameter;

        bool isMsgMode = (pipeMode_ & PIPE_READMODE_MESSAGE) != 0;
        bool isNonBlocking = (pipeMode_ & PIPE_NOWAIT) != 0;
        bool broken = (state_.load(std::memory_order_relaxed) == PipeState::Broken);

        std::span<uint8_t> outSpan(static_cast<uint8_t*>(buffer), length);

        if (isServer) {
            // Server reads from Client-To-Server buffer
            return clientToServer_.read(outSpan, isMsgMode, bytesRead, isNonBlocking, broken);
        } else {
            // Client reads from Server-To-Client buffer
            return serverToClient_.read(outSpan, isMsgMode, bytesRead, isNonBlocking, broken);
        }
    }

    NtStatus write(bool isServer, const void* buffer, uint32_t length, uint32_t& bytesWritten) {
        if (!buffer) return NtStatus::InvalidParameter;

        if (state_.load(std::memory_order_acquire) == PipeState::Broken ||
            state_.load(std::memory_order_acquire) == PipeState::Disconnected) {
            return NtStatus::PipeBroken;
        }

        bool asMessage = ((pipeMode_ & PIPE_TYPE_MESSAGE) != 0);
        std::span<const uint8_t> inSpan(static_cast<const uint8_t*>(buffer), length);

        if (isServer) {
            // Server writes to Server-To-Client buffer
            serverToClient_.write(inSpan, asMessage);
        } else {
            // Client writes to Client-To-Server buffer
            clientToServer_.write(inSpan, asMessage);
        }

        bytesWritten = length;
        return NtStatus::Success;
    }

    NtStatus peek(
        bool isServer,
        void* buffer,
        uint32_t bufferSize,
        uint32_t* bytesRead,
        uint32_t* totalBytesAvail,
        uint32_t* bytesLeftThisMessage
    ) {
        std::span<uint8_t> outSpan(static_cast<uint8_t*>(buffer), bufferSize);
        if (isServer) {
            clientToServer_.peek(outSpan, bytesRead, totalBytesAvail, bytesLeftThisMessage);
        } else {
            serverToClient_.peek(outSpan, bytesRead, totalBytesAvail, bytesLeftThisMessage);
        }
        return NtStatus::Success;
    }

    NtStatus transact(
        bool isServer,
        const void* inBuffer,
        uint32_t inBufferSize,
        void* outBuffer,
        uint32_t outBufferSize,
        uint32_t& bytesRead
    ) {
        uint32_t written = 0;
        NtStatus st = write(isServer, inBuffer, inBufferSize, written);
        if (!NT_SUCCESS(st)) return st;

        return read(isServer, outBuffer, outBufferSize, bytesRead);
    }

private:
    void notifyAvailable();

    std::wstring name_;
    uint32_t openMode_{PIPE_ACCESS_DUPLEX};
    uint32_t pipeMode_{PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT};
    uint32_t maxInstances_{PIPE_UNLIMITED_INSTANCES};
    uint32_t outBufferSize_{4096};
    uint32_t inBufferSize_{4096};
    uint32_t defaultTimeoutMs_{50};
    std::weak_ptr<NamedPipe> parentPipe_;

    std::atomic<PipeState> state_{PipeState::Listening};
    bool clientConnected_{false};
    mutable std::mutex stateMutex_;
    std::condition_variable stateCv_;

    PipeBuffer serverToClient_;
    PipeBuffer clientToServer_;
};

// ============================================================================
// 4. Named Pipe Root Container
// ============================================================================

class NamedPipe : public std::enable_shared_from_this<NamedPipe> {
public:
    explicit NamedPipe(std::wstring_view name) : name_(name) {}

    [[nodiscard]] const std::wstring& getName() const noexcept { return name_; }

    NtStatus createInstance(
        uint32_t openMode,
        uint32_t pipeMode,
        uint32_t maxInstances,
        uint32_t outBufferSize,
        uint32_t inBufferSize,
        uint32_t defaultTimeoutMs,
        std::shared_ptr<NamedPipeInstance>& outInstance
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instances_.size() >= maxInstances && maxInstances != PIPE_UNLIMITED_INSTANCES) {
            return NtStatus::PipeBusy;
        }

        auto inst = std::make_shared<NamedPipeInstance>(
            name_,
            openMode,
            pipeMode,
            maxInstances,
            outBufferSize,
            inBufferSize,
            defaultTimeoutMs,
            weak_from_this()
        );

        instances_.push_back(inst);
        outInstance = inst;
        availableCv_.notify_all();
        return NtStatus::Success;
    }

    std::shared_ptr<NamedPipeInstance> findListeningInstance() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& inst : instances_) {
            if (inst->getState() == PipeState::Listening) {
                return inst;
            }
        }
        return nullptr;
    }

    NtStatus waitAvailable(uint32_t timeoutMs) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto pred = [this]() {
            for (auto& inst : instances_) {
                if (inst->getState() == PipeState::Listening) return true;
            }
            return false;
        };

        if (pred()) return NtStatus::Success;

        if (timeoutMs == NMPWAIT_WAIT_FOREVER) {
            availableCv_.wait(lock, pred);
            return NtStatus::Success;
        } else {
            if (availableCv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), pred)) {
                return NtStatus::Success;
            }
            return NtStatus::Timeout;
        }
    }

    void notifyInstanceAvailable() {
        std::lock_guard<std::mutex> lock(mutex_);
        availableCv_.notify_all();
    }

    [[nodiscard]] size_t getInstanceCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return instances_.size();
    }

private:
    std::wstring name_;
    mutable std::mutex mutex_;
    std::condition_variable availableCv_;
    std::vector<std::shared_ptr<NamedPipeInstance>> instances_;
};

inline void NamedPipeInstance::notifyAvailable() {
    if (auto parent = parentPipe_.lock()) {
        parent->notifyInstanceAvailable();
    }
}

// ============================================================================
// 5. Named Pipe File System Driver (NPFS)
// ============================================================================

class NamedPipeFileSystem {
public:
    static NamedPipeFileSystem& get() {
        static NamedPipeFileSystem instance;
        return instance;
    }

    void initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) return;

        // Register NPFS driver & device
        driver_ = std::make_unique<io::DriverObject>();
        driver_->driverName = L"\\Driver\\Npfs";

        device_ = io::IoManager::get().createDevice(
            driver_.get(),
            L"\\Device\\NamedPipe",
            io::DeviceType::FileSystem
        );

        initialized_ = true;
    }

    [[nodiscard]] io::DeviceObject* getDevice() const noexcept {
        return device_.get();
    }

    static std::wstring canonicalizeName(std::wstring_view name) {
        std::wstring s(name);
        if (s.starts_with(L"\\\\.\\pipe\\")) {
            s = s.substr(9);
        } else if (s.starts_with(L"\\??\\pipe\\")) {
            s = s.substr(9);
        } else if (s.starts_with(L"\\DosDevices\\pipe\\")) {
            s = s.substr(17);
        } else if (s.starts_with(L"\\Device\\NamedPipe\\")) {
            s = s.substr(18);
        } else if (s.starts_with(L"pipe\\")) {
            s = s.substr(5);
        }
        return s;
    }

    NtStatus createNamedPipe(
        std::wstring_view name,
        uint32_t openMode,
        uint32_t pipeMode,
        uint32_t maxInstances,
        uint32_t outBufferSize,
        uint32_t inBufferSize,
        uint32_t defaultTimeoutMs,
        std::shared_ptr<NamedPipeInstance>& outInstance
    ) {
        initialize();
        std::wstring canon = canonicalizeName(name);

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pipes_.find(canon);
        if (it == pipes_.end()) {
            auto pipe = std::make_shared<NamedPipe>(canon);
            pipes_[canon] = pipe;
            return pipe->createInstance(
                openMode, pipeMode, maxInstances,
                outBufferSize, inBufferSize, defaultTimeoutMs, outInstance
            );
        } else {
            if ((openMode & FILE_FLAG_FIRST_PIPE_INSTANCE) != 0) {
                return NtStatus::AccessDenied;
            }
            return it->second->createInstance(
                openMode, pipeMode, maxInstances,
                outBufferSize, inBufferSize, defaultTimeoutMs, outInstance
            );
        }
    }

    NtStatus openClientPipe(
        std::wstring_view name,
        uint32_t desiredAccess,
        uint32_t timeoutMs,
        std::shared_ptr<NamedPipeInstance>& outInstance
    ) {
        initialize();
        std::wstring canon = canonicalizeName(name);

        std::shared_ptr<NamedPipe> pipe;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = pipes_.find(canon);
            if (it == pipes_.end()) {
                return NtStatus::ObjectNameNotFound;
            }
            pipe = it->second;
        }

        auto inst = pipe->findListeningInstance();
        if (!inst) {
            if (timeoutMs == 0) {
                return NtStatus::PipeBusy;
            }
            NtStatus waitSt = pipe->waitAvailable(timeoutMs);
            if (!NT_SUCCESS(waitSt)) return waitSt;
            inst = pipe->findListeningInstance();
            if (!inst) return NtStatus::PipeBusy;
        }

        NtStatus connSt = inst->connectClient(desiredAccess, timeoutMs);
        if (NT_SUCCESS(connSt)) {
            outInstance = inst;
        }
        return connSt;
    }

    NtStatus waitNamedPipe(std::wstring_view name, uint32_t timeoutMs) {
        initialize();
        std::wstring canon = canonicalizeName(name);

        std::shared_ptr<NamedPipe> pipe;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = pipes_.find(canon);
            if (it == pipes_.end()) {
                return NtStatus::ObjectNameNotFound;
            }
            pipe = it->second;
        }

        return pipe->waitAvailable(timeoutMs);
    }

    [[nodiscard]] size_t getPipeCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pipes_.size();
    }

private:
    NamedPipeFileSystem() = default;
    bool initialized_{false};
    mutable std::mutex mutex_;
    std::unique_ptr<io::DriverObject> driver_;
    std::shared_ptr<io::DeviceObject> device_;
    std::unordered_map<std::wstring, std::shared_ptr<NamedPipe>> pipes_;
};

// ============================================================================
// 6. Mailslot Subsystem (MSFS)
// ============================================================================

struct MailslotDatagram {
    std::vector<uint8_t> data;
};

class Mailslot {
public:
    Mailslot(std::wstring_view name, uint32_t maxMessageSize, uint32_t readTimeoutMs)
        : name_(name),
          maxMessageSize_(maxMessageSize),
          readTimeoutMs_(readTimeoutMs) {}

    [[nodiscard]] const std::wstring& getName() const noexcept { return name_; }
    [[nodiscard]] uint32_t getMaxMessageSize() const noexcept { return maxMessageSize_; }
    [[nodiscard]] uint32_t getReadTimeout() const noexcept { return readTimeoutMs_; }

    void setReadTimeout(uint32_t timeoutMs) noexcept {
        readTimeoutMs_ = timeoutMs;
    }

    NtStatus write(const void* buffer, uint32_t length) {
        if (!buffer && length > 0) return NtStatus::InvalidParameter;
        if (maxMessageSize_ > 0 && length > maxMessageSize_) {
            return NtStatus::BufferOverflow;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        MailslotDatagram d;
        if (length > 0) {
            const auto* src = static_cast<const uint8_t*>(buffer);
            d.data.assign(src, src + length);
        }
        messages_.push_back(std::move(d));
        cv_.notify_all();
        return NtStatus::Success;
    }

    NtStatus read(void* buffer, uint32_t length, uint32_t& bytesRead, uint32_t timeoutMs = MAILSLOT_WAIT_FOREVER) {
        if (!buffer && length > 0) return NtStatus::InvalidParameter;

        std::unique_lock<std::mutex> lock(mutex_);
        auto pred = [this]() { return !messages_.empty(); };

        if (messages_.empty()) {
            if (timeoutMs == 0) {
                bytesRead = 0;
                return NtStatus::Timeout;
            }
            if (timeoutMs == MAILSLOT_WAIT_FOREVER) {
                cv_.wait(lock, pred);
            } else {
                if (!cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), pred)) {
                    bytesRead = 0;
                    return NtStatus::Timeout;
                }
            }
        }

        if (messages_.empty()) {
            bytesRead = 0;
            return NtStatus::Timeout;
        }

        auto msg = std::move(messages_.front());
        messages_.pop_front();

        size_t toCopy = std::min<size_t>(length, msg.data.size());
        if (toCopy > 0) {
            std::memcpy(buffer, msg.data.data(), toCopy);
        }
        bytesRead = static_cast<uint32_t>(toCopy);
        return NtStatus::Success;
    }

    void getInfo(
        uint32_t* outMaxMessageSize,
        uint32_t* outNextSize,
        uint32_t* outMessageCount,
        uint32_t* outReadTimeout
    ) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (outMaxMessageSize) *outMaxMessageSize = maxMessageSize_;
        if (outReadTimeout) *outReadTimeout = readTimeoutMs_;
        if (outMessageCount) *outMessageCount = static_cast<uint32_t>(messages_.size());
        if (outNextSize) {
            if (messages_.empty()) {
                *outNextSize = MAILSLOT_NO_MESSAGE;
            } else {
                *outNextSize = static_cast<uint32_t>(messages_.front().data.size());
            }
        }
    }

private:
    std::wstring name_;
    uint32_t maxMessageSize_{0};
    uint32_t readTimeoutMs_{MAILSLOT_WAIT_FOREVER};
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<MailslotDatagram> messages_;
};

class MailslotFileSystem {
public:
    static MailslotFileSystem& get() {
        static MailslotFileSystem instance;
        return instance;
    }

    void initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) return;

        driver_ = std::make_unique<io::DriverObject>();
        driver_->driverName = L"\\Driver\\Msfs";

        device_ = io::IoManager::get().createDevice(
            driver_.get(),
            L"\\Device\\Mailslot",
            io::DeviceType::FileSystem
        );

        initialized_ = true;
    }

    [[nodiscard]] io::DeviceObject* getDevice() const noexcept {
        return device_.get();
    }

    static std::wstring canonicalizeName(std::wstring_view name) {
        std::wstring s(name);
        if (s.starts_with(L"\\\\.\\mailslot\\")) {
            s = s.substr(13);
        } else if (s.starts_with(L"\\??\\mailslot\\")) {
            s = s.substr(13);
        } else if (s.starts_with(L"\\DosDevices\\mailslot\\")) {
            s = s.substr(21);
        } else if (s.starts_with(L"\\Device\\Mailslot\\")) {
            s = s.substr(17);
        } else if (s.starts_with(L"mailslot\\")) {
            s = s.substr(9);
        }
        return s;
    }

    NtStatus createMailslot(
        std::wstring_view name,
        uint32_t maxMessageSize,
        uint32_t readTimeoutMs,
        std::shared_ptr<Mailslot>& outSlot
    ) {
        initialize();
        std::wstring canon = canonicalizeName(name);

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = slots_.find(canon);
        if (it != slots_.end()) {
            return NtStatus::ObjectNameCollision;
        }

        auto slot = std::make_shared<Mailslot>(canon, maxMessageSize, readTimeoutMs);
        slots_[canon] = slot;
        outSlot = slot;
        return NtStatus::Success;
    }

    std::shared_ptr<Mailslot> lookupMailslot(std::wstring_view name) {
        initialize();
        std::wstring canon = canonicalizeName(name);

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = slots_.find(canon);
        if (it != slots_.end()) return it->second;
        return nullptr;
    }

    [[nodiscard]] size_t getMailslotCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return slots_.size();
    }

private:
    MailslotFileSystem() = default;
    bool initialized_{false};
    mutable std::mutex mutex_;
    std::unique_ptr<io::DriverObject> driver_;
    std::shared_ptr<io::DeviceObject> device_;
    std::unordered_map<std::wstring, std::shared_ptr<Mailslot>> slots_;
};

} // namespace micant::npfs
