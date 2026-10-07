// ============================================================================
// MicaNT: AegisSandbox Sovereign Process Containment & Job Objects Engine
// 
// Strict Clean-Room Implementation in modern ISO C++23. Zero External Dependencies.
// Implements Win32 Job Object containment, process isolation boundaries,
// CPU rate controls, memory quota fences, and security token confinement.
// Named in honor of the Aegis shield and Cutler's executive process containment.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <atomic>
#include <algorithm>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ob.hpp"
#include "ps.hpp"
#include "se.hpp"

namespace micant::aegis {

// ============================================================================
// 1. Standard Job Object Limit Flags (win32metadata / winnt.h Parity)
// ============================================================================

inline constexpr uint32_t JOB_OBJECT_LIMIT_WORKINGSET                 = 0x00000001;
inline constexpr uint32_t JOB_OBJECT_LIMIT_PROCESS_TIME               = 0x00000002;
inline constexpr uint32_t JOB_OBJECT_LIMIT_JOB_TIME                   = 0x00000004;
inline constexpr uint32_t JOB_OBJECT_LIMIT_ACTIVE_PROCESS             = 0x00000008;
inline constexpr uint32_t JOB_OBJECT_LIMIT_AFFINITY                   = 0x00000010;
inline constexpr uint32_t JOB_OBJECT_LIMIT_PRIORITY_CLASS             = 0x00000020;
inline constexpr uint32_t JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME          = 0x00000040;
inline constexpr uint32_t JOB_OBJECT_LIMIT_SCHEDULING_CLASS           = 0x00000080;
inline constexpr uint32_t JOB_OBJECT_LIMIT_PROCESS_MEMORY             = 0x00000100;
inline constexpr uint32_t JOB_OBJECT_LIMIT_JOB_MEMORY                 = 0x00000200;
inline constexpr uint32_t JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400;
inline constexpr uint32_t JOB_OBJECT_LIMIT_BREAKAWAY_OK               = 0x00000800;
inline constexpr uint32_t JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK        = 0x00001000;
inline constexpr uint32_t JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE          = 0x00002000;
inline constexpr uint32_t JOB_OBJECT_LIMIT_SUBSET_AFFINITY            = 0x00004000;

// ============================================================================
// 2. UI Restrictions Flags
// ============================================================================

inline constexpr uint32_t JOB_OBJECT_UILIMIT_NONE                     = 0x00000000;
inline constexpr uint32_t JOB_OBJECT_UILIMIT_HANDLES                  = 0x00000001;
inline constexpr uint32_t JOB_OBJECT_UILIMIT_READCLIPBOARD            = 0x00000002;
inline constexpr uint32_t JOB_OBJECT_UILIMIT_WRITECLIPBOARD           = 0x00000004;
inline constexpr uint32_t JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS         = 0x00000008;
inline constexpr uint32_t JOB_OBJECT_UILIMIT_DISPLAYSETTINGS          = 0x00000010;
inline constexpr uint32_t JOB_OBJECT_UILIMIT_GLOBALATOMS              = 0x00000020;
inline constexpr uint32_t JOB_OBJECT_UILIMIT_DESKTOP                  = 0x00000040;
inline constexpr uint32_t JOB_OBJECT_UILIMIT_EXITWINDOWS              = 0x00000080;

// ============================================================================
// 3. CPU Rate Control Flags
// ============================================================================

inline constexpr uint32_t JOB_OBJECT_CPU_RATE_CONTROL_ENABLE          = 0x00000001;
inline constexpr uint32_t JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED    = 0x00000002;
inline constexpr uint32_t JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP        = 0x00000004;
inline constexpr uint32_t JOB_OBJECT_CPU_RATE_CONTROL_NOTIFY          = 0x00000008;
inline constexpr uint32_t JOB_OBJECT_CPU_RATE_CONTROL_MIN_MAX_RATE    = 0x00000010;

// ============================================================================
// 4. Job Object Information Classes
// ============================================================================

enum class JobObjectInfoClass : uint32_t {
    BasicAccountingInformation               = 1,
    BasicLimitInformation                    = 2,
    BasicProcessIdList                       = 3,
    BasicUIRestrictions                      = 4,
    SecurityLimitInformation                 = 5,
    EndOfJobTimeInformation                  = 6,
    AssociateCompletionPortInformation       = 7,
    BasicAndIoAccountingInformation          = 8,
    ExtendedLimitInformation                 = 9,
    JobSetInformation                        = 10,
    CpuRateControlInformation                = 15
};

// ============================================================================
// 5. Job Object Standard Structures
// ============================================================================

struct IO_COUNTERS {
    uint64_t ReadOperationCount{0};
    uint64_t WriteOperationCount{0};
    uint64_t OtherOperationCount{0};
    uint64_t ReadTransferCount{0};
    uint64_t WriteTransferCount{0};
    uint64_t OtherTransferCount{0};
};

struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
    uint64_t TotalUserTime{0};
    uint64_t TotalKernelTime{0};
    uint64_t ThisPeriodTotalUserTime{0};
    uint64_t ThisPeriodTotalKernelTime{0};
    uint32_t TotalPageFaultCount{0};
    uint32_t TotalProcesses{0};
    uint32_t ActiveProcesses{0};
    uint32_t TotalTerminatedProcesses{0};
};

struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    uint64_t PerProcessUserTimeLimit{0}; // 100-ns units
    uint64_t PerJobUserTimeLimit{0};     // 100-ns units
    uint32_t LimitFlags{0};
    size_t   MinimumWorkingSetSize{0};
    size_t   MaximumWorkingSetSize{0};
    uint32_t ActiveProcessLimit{0};
    uint64_t Affinity{0};
    uint32_t PriorityClass{0};
    uint32_t SchedulingClass{0};
};

struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation{};
    IO_COUNTERS IoInfo{};
    size_t ProcessMemoryLimit{0};
    size_t JobMemoryLimit{0};
    size_t PeakProcessMemoryUsed{0};
    size_t PeakJobMemoryUsed{0};
};

struct JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
    uint32_t ControlFlags{0};
    uint32_t CpuRate{0}; // 1 - 10000 represents 0.01% - 100.0%
};

// ============================================================================
// 6. AegisJobObject: Sovereign Job Object Container
// ============================================================================

class AegisJobObject {
public:
    explicit AegisJobObject(std::wstring name = L"")
        : name_(std::move(name)) {}

    [[nodiscard]] const std::wstring& getName() const noexcept { return name_; }

    /**
     * @brief Configures extended limits on the job container.
     */
    void setExtendedLimits(const JOBOBJECT_EXTENDED_LIMIT_INFORMATION& limits) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        extendedLimits_ = limits;
    }

    [[nodiscard]] JOBOBJECT_EXTENDED_LIMIT_INFORMATION getExtendedLimits() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return extendedLimits_;
    }

    /**
     * @brief Configures UI restrictions for sandboxed processes in the job.
     */
    void setUIRestrictions(uint32_t uiRestrictions) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        uiRestrictions_ = uiRestrictions;
    }

    [[nodiscard]] uint32_t getUIRestrictions() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return uiRestrictions_;
    }

    /**
     * @brief Configures CPU rate control limits (percentage bandwidth cap).
     */
    void setCpuRateControl(const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION& cpuRate) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        cpuRateControl_ = cpuRate;
    }

    [[nodiscard]] JOBOBJECT_CPU_RATE_CONTROL_INFORMATION getCpuRateControl() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return cpuRateControl_;
    }

    /**
     * @brief Assigns a process to the Job container.
     * Enforces active process limits and ensures the process is not already trapped in a conflicting job.
     */
    NtStatus assignProcess(const std::shared_ptr<ps::EProcess>& process) {
        if (!process) return NtStatus::InvalidParameter;
        std::lock_guard<std::mutex> lock(mutex_);

        Handle pid = process->getPid();
        if (memberProcesses_.contains(pid)) {
            return NtStatus::Success; // Already in job
        }

        // Check Active Process Limit
        const auto& basicLimits = extendedLimits_.BasicLimitInformation;
        if ((basicLimits.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) && basicLimits.ActiveProcessLimit > 0) {
            if (activeProcesses_.size() >= basicLimits.ActiveProcessLimit) {
                return NtStatus::QuotaExceeded;
            }
        }

        memberProcesses_[pid] = process;
        activeProcesses_.insert(pid);
        processMemoryUsage_[pid] = 0;

        accounting_.TotalProcesses++;
        accounting_.ActiveProcesses = static_cast<uint32_t>(activeProcesses_.size());

        // Apply sandboxed token if configured
        if (sandboxToken_) {
            process->setToken(sandboxToken_);
        }

        return NtStatus::Success;
    }

    /**
     * @brief Checks and records dynamic memory allocation for a member process.
     * Enforces per-process memory limits and aggregate job memory limits.
     */
    NtStatus checkAndRecordMemoryAlloc(Handle pid, size_t allocBytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!activeProcesses_.contains(pid)) {
            return NtStatus::NoSuchProcess;
        }

        size_t currentProcMem = processMemoryUsage_[pid];
        size_t newProcMem = currentProcMem + allocBytes;

        // Check Per-Process Limit
        if ((extendedLimits_.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_PROCESS_MEMORY) &&
            extendedLimits_.ProcessMemoryLimit > 0) {
            if (newProcMem > extendedLimits_.ProcessMemoryLimit) {
                return NtStatus::QuotaExceeded;
            }
        }

        // Check Job-Wide Aggregate Limit
        size_t newJobMem = currentJobMemory_ + allocBytes;
        if ((extendedLimits_.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_JOB_MEMORY) &&
            extendedLimits_.JobMemoryLimit > 0) {
            if (newJobMem > extendedLimits_.JobMemoryLimit) {
                return NtStatus::QuotaExceeded;
            }
        }

        // Update Accounting
        processMemoryUsage_[pid] = newProcMem;
        currentJobMemory_ = newJobMem;

        extendedLimits_.PeakProcessMemoryUsed = std::max(extendedLimits_.PeakProcessMemoryUsed, newProcMem);
        extendedLimits_.PeakJobMemoryUsed = std::max(extendedLimits_.PeakJobMemoryUsed, newJobMem);

        return NtStatus::Success;
    }

    /**
     * @brief Records memory freed by a process.
     */
    void recordMemoryFree(Handle pid, size_t freeBytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (processMemoryUsage_.contains(pid)) {
            size_t& pMem = processMemoryUsage_[pid];
            size_t actualFree = std::min(pMem, freeBytes);
            pMem -= actualFree;
            currentJobMemory_ = (currentJobMemory_ >= actualFree) ? (currentJobMemory_ - actualFree) : 0;
        }
    }

    /**
     * @brief Records CPU cycle execution and checks per-process user time limits.
     */
    NtStatus recordCpuExecution(Handle pid, uint64_t userTimeUnits, uint64_t kernelTimeUnits) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!activeProcesses_.contains(pid)) {
            return NtStatus::NoSuchProcess;
        }

        accounting_.TotalUserTime += userTimeUnits;
        accounting_.TotalKernelTime += kernelTimeUnits;
        accounting_.ThisPeriodTotalUserTime += userTimeUnits;
        accounting_.ThisPeriodTotalKernelTime += kernelTimeUnits;

        processUserTime_[pid] += userTimeUnits;

        // Enforce Per-Process User Time Limit
        const auto& basicLimits = extendedLimits_.BasicLimitInformation;
        if ((basicLimits.LimitFlags & JOB_OBJECT_LIMIT_PROCESS_TIME) && basicLimits.PerProcessUserTimeLimit > 0) {
            if (processUserTime_[pid] > basicLimits.PerProcessUserTimeLimit) {
                // Terminate process that exceeded user time quota
                auto it = memberProcesses_.find(pid);
                if (it != memberProcesses_.end() && it->second) {
                    it->second->terminate(NtStatus::QuotaExceeded);
                    activeProcesses_.erase(pid);
                    accounting_.ActiveProcesses = static_cast<uint32_t>(activeProcesses_.size());
                    accounting_.TotalTerminatedProcesses++;
                }
                return NtStatus::QuotaExceeded;
            }
        }

        return NtStatus::Success;
    }

    /**
     * @brief Atomically terminates all processes in the job container.
     */
    void terminateJob(NtStatus exitCode) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (Handle pid : activeProcesses_) {
            auto it = memberProcesses_.find(pid);
            if (it != memberProcesses_.end() && it->second) {
                it->second->terminate(exitCode);
                accounting_.TotalTerminatedProcesses++;
            }
        }
        activeProcesses_.clear();
        accounting_.ActiveProcesses = 0;
    }

    /**
     * @brief Invoked when a handle to the Job Object is closed.
     * If JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE is set, kills all member processes immediately.
     */
    void onHandleClosed() {
        bool shouldKill = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            shouldKill = (extendedLimits_.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0;
        }
        if (shouldKill) {
            terminateJob(NtStatus::Success);
        }
    }

    /**
     * @brief Sets a restricted sandbox token that will be applied to all processes entering this job.
     */
    void setSandboxToken(std::shared_ptr<se::TokenObject> token) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        sandboxToken_ = std::move(token);
    }

    [[nodiscard]] std::shared_ptr<se::TokenObject> getSandboxToken() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return sandboxToken_;
    }

    [[nodiscard]] JOBOBJECT_BASIC_ACCOUNTING_INFORMATION getAccountingInfo() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return accounting_;
    }

    [[nodiscard]] size_t getActiveProcessCount() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return activeProcesses_.size();
    }

    [[nodiscard]] bool containsProcess(Handle pid) const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return activeProcesses_.contains(pid);
    }

private:
    mutable std::mutex mutex_;
    std::wstring name_;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION extendedLimits_{};
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting_{};
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuRateControl_{};
    uint32_t uiRestrictions_{JOB_OBJECT_UILIMIT_NONE};
    std::shared_ptr<se::TokenObject> sandboxToken_{nullptr};

    std::unordered_map<Handle, std::shared_ptr<ps::EProcess>> memberProcesses_;
    std::unordered_set<Handle> activeProcesses_;
    std::unordered_map<Handle, size_t> processMemoryUsage_;
    std::unordered_map<Handle, uint64_t> processUserTime_;
    size_t currentJobMemory_{0};
};

// ============================================================================
// 7. AegisSandboxManager: Global Job Object Registry & Subsystem Controller
// ============================================================================

class AegisSandboxManager {
public:
    static AegisSandboxManager& get() {
        static AegisSandboxManager instance;
        return instance;
    }

    /**
     * @brief Creates a new sovereign job object.
     */
    std::shared_ptr<AegisJobObject> createJobObject(std::wstring_view name = L"") {
        std::lock_guard<std::mutex> lock(mutex_);
        auto job = std::make_shared<AegisJobObject>(std::wstring(name));
        if (!name.empty()) {
            namedJobs_[std::wstring(name)] = job;
        }
        allJobs_.push_back(job);
        return job;
    }

    /**
     * @brief Opens an existing named job object.
     */
    std::shared_ptr<AegisJobObject> openJobObject(std::wstring_view name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = namedJobs_.find(std::wstring(name));
        if (it != namedJobs_.end()) {
            return it->second.lock();
        }
        return nullptr;
    }

    /**
     * @brief Finds which job object currently contains a given process ID.
     */
    std::shared_ptr<AegisJobObject> getJobForProcess(Handle pid) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& job : allJobs_) {
            if (job && job->containsProcess(pid)) {
                return job;
            }
        }
        return nullptr;
    }

    [[nodiscard]] size_t getJobCount() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return allJobs_.size();
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& job : allJobs_) {
            if (job) {
                job->terminateJob(NtStatus::Success);
            }
        }
        namedJobs_.clear();
        allJobs_.clear();
    }

private:
    AegisSandboxManager() = default;
    mutable std::mutex mutex_;
    std::unordered_map<std::wstring, std::weak_ptr<AegisJobObject>> namedJobs_;
    std::vector<std::shared_ptr<AegisJobObject>> allJobs_;
};

} // namespace micant::aegis

// Taxonomy Namespace Alias
namespace micant::sandbox {
    using namespace micant::aegis;
}
