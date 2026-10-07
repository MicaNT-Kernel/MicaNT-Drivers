#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <span>
#include <optional>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "lpc.hpp"

namespace micant::csrss {

// Well-known ALPC port name for the Win32 subsystem server
inline constexpr std::wstring_view CSR_PORT_NAME = L"\\RPC Control\\WindowsSubsystem";

// Win32 Subsystem CSR API Numbers
enum class CsrApiNumber : uint32_t {
    ProcessCreate               = 0x0001,
    ProcessTerminate            = 0x0002,
    ThreadCreate                = 0x0003,
    ThreadTerminate             = 0x0004,
    GetProcessInfo              = 0x0005,
    AllocConsole                = 0x0010,
    AttachConsole               = 0x0011,
    FreeConsole                 = 0x0012,
    WriteConsole                = 0x0013,
    ReadConsole                 = 0x0014,
    SetConsoleTitle             = 0x0015,
    GetConsoleTitle             = 0x0016,
    GetScreenBufferInfo         = 0x0017
};

/**
 * @brief Thread tracking entry in CSRSS.
 */
struct CsrThreadEntry {
    uint32_t threadId{0};
    uint32_t processId{0};
    Handle threadHandle{0};
    bool terminated{false};
};

/**
 * @brief Process tracking entry in CSRSS.
 */
struct CsrProcessEntry {
    uint32_t processId{0};
    uint32_t parentProcessId{0};
    uint32_t sequenceNumber{0};
    uint32_t flags{0};
    uint32_t shutdownPriority{0x280}; // Default standard Win32 level
    Handle consoleHandle{0};
    std::wstring imagePath;
    std::vector<CsrThreadEntry> threads;
    bool terminated{false};
    uint32_t exitCode{0};
};

/**
 * @brief CSRSS API Message format passed over ALPC rendezvous port.
 */
struct CsrApiMessage {
    lpc::PortMessage portMessage{};
    CsrApiNumber apiNumber{CsrApiNumber::ProcessCreate};
    NtStatus returnStatus{NtStatus::Success};

    // Subsystem payload
    union {
        struct {
            uint32_t processId;
            uint32_t parentProcessId;
            uint32_t flags;
            Handle consoleHandle;
        } processCreate;

        struct {
            uint32_t processId;
            uint32_t exitCode;
        } processTerminate;

        struct {
            uint32_t processId;
            uint32_t threadId;
            Handle threadHandle;
        } threadCreate;

        struct {
            uint32_t processId;
            uint32_t threadId;
            uint32_t exitCode;
        } threadTerminate;

        struct {
            uint32_t processId;
            Handle outConsoleHandle;
        } consoleAlloc;

        struct {
            uint32_t processId;
            uint32_t targetProcessId;
            Handle outConsoleHandle;
        } consoleAttach;

        struct {
            uint32_t processId;
        } consoleFree;

        struct {
            Handle consoleHandle;
            uint32_t characterCount;
        } consoleIo;
    } data{};

    std::wstring stringPayload;
};

/**
 * @brief Telemetry stats for CSRSS.
 */
struct CsrTelemetry {
    uint64_t totalProcessesCreated{0};
    uint64_t totalProcessesTerminated{0};
    uint64_t totalThreadsCreated{0};
    uint64_t totalMessagesProcessed{0};
    uint64_t activeConsoles{0};
};

/**
 * @brief Client/Server Runtime Subsystem (CSRSS) Server Engine.
 * Manages the Win32 Process/Thread subsystem table and ALPC communication.
 */
class CsrSubsystemServer {
private:
    std::mutex m_mutex;
    std::shared_ptr<lpc::PortObject> m_serverPort;
    std::unordered_map<uint32_t, CsrProcessEntry> m_processes;
    uint32_t m_nextSequenceNumber{1};
    CsrTelemetry m_telemetry{};
    bool m_isRunning{false};

    CsrSubsystemServer() = default;

public:
    static CsrSubsystemServer& get() noexcept {
        static CsrSubsystemServer instance;
        return instance;
    }

    ~CsrSubsystemServer() {
        stop();
    }

    /**
     * @brief Start CSRSS and listen on the well-known ALPC port.
     */
    bool start() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_isRunning) return true;

        m_serverPort = lpc::PortManager::get().createPort(
            std::wstring(CSR_PORT_NAME)
        );

        if (!m_serverPort) return false;

        m_isRunning = true;
        return true;
    }

    /**
     * @brief Stop CSRSS and disconnect port.
     */
    void stop() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isRunning) return;

        m_isRunning = false;
        m_processes.clear();
        m_serverPort.reset();
    }

    [[nodiscard]] bool isRunning() const noexcept { return m_isRunning; }

    /**
     * @brief Register a new Win32 process with CSRSS.
     */
    NtStatus registerProcess(uint32_t pid, uint32_t parentPid, std::wstring_view imagePath, Handle consoleHandle = 0) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isRunning) return NtStatus::ServerNotRunning;

        if (m_processes.find(pid) != m_processes.end()) {
            return NtStatus::ObjectNameCollision;
        }

        CsrProcessEntry entry{};
        entry.processId = pid;
        entry.parentProcessId = parentPid;
        entry.sequenceNumber = m_nextSequenceNumber++;
        entry.imagePath = std::wstring(imagePath);
        entry.consoleHandle = consoleHandle;
        entry.terminated = false;

        m_processes[pid] = std::move(entry);
        m_telemetry.totalProcessesCreated++;
        return NtStatus::Success;
    }

    /**
     * @brief Register a new Win32 thread within a process.
     */
    NtStatus registerThread(uint32_t pid, uint32_t tid, Handle threadHandle) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isRunning) return NtStatus::ServerNotRunning;

        auto it = m_processes.find(pid);
        if (it == m_processes.end() || it->second.terminated) {
            return NtStatus::NoSuchProcess;
        }

        CsrThreadEntry threadEntry{};
        threadEntry.processId = pid;
        threadEntry.threadId = tid;
        threadEntry.threadHandle = threadHandle;
        threadEntry.terminated = false;

        it->second.threads.push_back(threadEntry);
        m_telemetry.totalThreadsCreated++;
        return NtStatus::Success;
    }

    /**
     * @brief Mark a process as terminated in CSRSS.
     */
    NtStatus terminateProcess(uint32_t pid, uint32_t exitCode) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_isRunning) return NtStatus::ServerNotRunning;

        auto it = m_processes.find(pid);
        if (it == m_processes.end()) {
            return NtStatus::NoSuchProcess;
        }

        it->second.terminated = true;
        it->second.exitCode = exitCode;
        m_telemetry.totalProcessesTerminated++;
        return NtStatus::Success;
    }

    /**
     * @brief Assign or bind a console handle to a Win32 process.
     */
    NtStatus bindConsole(uint32_t pid, Handle consoleHandle) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_processes.find(pid);
        if (it == m_processes.end()) return NtStatus::NoSuchProcess;
        it->second.consoleHandle = consoleHandle;
        return NtStatus::Success;
    }

    /**
     * @brief Detach console handle from a Win32 process.
     */
    NtStatus unbindConsole(uint32_t pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_processes.find(pid);
        if (it == m_processes.end()) return NtStatus::NoSuchProcess;
        it->second.consoleHandle = 0;
        return NtStatus::Success;
    }

    /**
     * @brief Query process info by PID.
     */
    std::optional<CsrProcessEntry> getProcess(uint32_t pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_processes.find(pid);
        if (it != m_processes.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] size_t getActiveProcessCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t count = 0;
        for (const auto& [_, proc] : m_processes) {
            if (!proc.terminated) count++;
        }
        return count;
    }

    [[nodiscard]] CsrTelemetry getTelemetry() const noexcept {
        return m_telemetry;
    }

    /**
     * @brief Dispatch an in-flight CSR API message synchronously.
     */
    NtStatus dispatchApi(CsrApiMessage& msg) {
        m_telemetry.totalMessagesProcessed++;

        switch (msg.apiNumber) {
            case CsrApiNumber::ProcessCreate: {
                msg.returnStatus = registerProcess(
                    msg.data.processCreate.processId,
                    msg.data.processCreate.parentProcessId,
                    msg.stringPayload,
                    msg.data.processCreate.consoleHandle
                );
                return msg.returnStatus;
            }
            case CsrApiNumber::ProcessTerminate: {
                msg.returnStatus = terminateProcess(
                    msg.data.processTerminate.processId,
                    msg.data.processTerminate.exitCode
                );
                return msg.returnStatus;
            }
            case CsrApiNumber::ThreadCreate: {
                msg.returnStatus = registerThread(
                    msg.data.threadCreate.processId,
                    msg.data.threadCreate.threadId,
                    msg.data.threadCreate.threadHandle
                );
                return msg.returnStatus;
            }
            case CsrApiNumber::FreeConsole: {
                msg.returnStatus = unbindConsole(msg.data.consoleFree.processId);
                return msg.returnStatus;
            }
            default:
                msg.returnStatus = NtStatus::NotImplemented;
                return msg.returnStatus;
        }
    }
};

} // namespace micant::csrss
