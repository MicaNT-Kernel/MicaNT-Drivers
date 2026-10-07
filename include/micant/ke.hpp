#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <atomic>
#include <array>
#include <deque>
#include <functional>
#include <chrono>
#if defined(_M_X64) || defined(__x86_64__)
#include <immintrin.h>
#endif
#include "ntdef.hpp"
#include "ntstatus.hpp"

namespace micant::ke {

// ============================================================================
// 1. Interrupt Request Levels (IRQL)
// ============================================================================
using KIRQL = uint8_t;

inline constexpr KIRQL PASSIVE_LEVEL      = 0;  // Normal user / kernel execution; paging allowed
inline constexpr KIRQL APC_LEVEL          = 1;  // Asynchronous Procedure Calls; paging allowed
inline constexpr KIRQL DISPATCH_LEVEL     = 2;  // Thread scheduler & DPCs; NO PAGE FAULTS ALLOWED
inline constexpr KIRQL DIRQL_MIN          = 3;  // Device Interrupts minimum
inline constexpr KIRQL DIRQL_MAX          = 26; // Device Interrupts maximum
inline constexpr KIRQL PROFILE_LEVEL      = 27; // Profiling timer
inline constexpr KIRQL CLOCK_LEVEL        = 28; // System clock timer
inline constexpr KIRQL IPI_LEVEL          = 29; // Inter-Processor Interrupt
inline constexpr KIRQL POWER_LEVEL        = 30; // Power failure interrupt
inline constexpr KIRQL HIGH_LEVEL         = 31; // Mask all interrupts

/**
 * @brief Processor Control Region (KPCR) state tracking per CPU core.
 */
struct ProcessorControlBlock {
    uint32_t processorNumber{0};
    KIRQL currentIrql{PASSIVE_LEVEL};
    uint64_t interruptCount{0};
    uint64_t dpcCount{0};
    uint64_t contextSwitches{0};
};

// Thread-local or per-CPU simulated KPCR
inline thread_local ProcessorControlBlock g_CurrentCpu{ .processorNumber = 0, .currentIrql = PASSIVE_LEVEL };

[[nodiscard]] inline KIRQL KeGetCurrentIrql() noexcept {
    return g_CurrentCpu.currentIrql;
}

inline KIRQL KfRaiseIrql(KIRQL newIrql) noexcept {
    KIRQL old = g_CurrentCpu.currentIrql;
    if (newIrql > old) {
        g_CurrentCpu.currentIrql = newIrql;
    }
    return old;
}

inline void KeLowerIrql(KIRQL newIrql) noexcept {
    g_CurrentCpu.currentIrql = newIrql;
}

// ============================================================================
// 2. Kernel Spinlocks (KSPIN_LOCK)
// ============================================================================
/**
 * @brief Native NT Kernel Spinlock.
 * Acquiring raises IRQL to DISPATCH_LEVEL and spins atomically.
 * Releasing restores previous IRQL.
 */
class SpinLock {
public:
    SpinLock() = default;
    SpinLock(const SpinLock&) = delete;
    SpinLock& operator=(const SpinLock&) = delete;

    KIRQL acquire() noexcept {
        KIRQL oldIrql = KfRaiseIrql(DISPATCH_LEVEL);
        while (lockFlag_.test_and_set(std::memory_order_acquire)) {
#if defined(_M_X64) || defined(__x86_64__)
            _mm_pause();
#endif
        }
        ownerCpu_ = g_CurrentCpu.processorNumber;
        return oldIrql;
    }

    void release(KIRQL oldIrql) noexcept {
        ownerCpu_ = 0xFFFFFFFF;
        lockFlag_.clear(std::memory_order_release);
        KeLowerIrql(oldIrql);
    }

    [[nodiscard]] bool isLocked() const noexcept {
        // test_and_set/test idiom
        return lockFlag_.test(std::memory_order_relaxed);
    }

private:
    std::atomic_flag lockFlag_ = ATOMIC_FLAG_INIT;
    uint32_t ownerCpu_{0xFFFFFFFF};
};

/**
 * @brief RAII SpinLock Guard.
 */
class SpinLockGuard {
public:
    explicit SpinLockGuard(SpinLock& lock) noexcept
        : lock_(lock), previousIrql_(lock_.acquire()) {}

    ~SpinLockGuard() noexcept {
        lock_.release(previousIrql_);
    }

    SpinLockGuard(const SpinLockGuard&) = delete;
    SpinLockGuard& operator=(const SpinLockGuard&) = delete;

    [[nodiscard]] KIRQL getPreviousIrql() const noexcept { return previousIrql_; }

private:
    SpinLock& lock_;
    KIRQL previousIrql_;
};

// ============================================================================
// 3. Deferred Procedure Calls (KDPC)
// ============================================================================
enum class DpcImportance : uint32_t {
    Low,
    Medium,
    High,
    HighPriority
};

struct KDPC;
using PKDEFERRED_ROUTINE = void (*)(KDPC* dpc, void* deferredContext, void* sysArg1, void* sysArg2);

struct KDPC {
    PKDEFERRED_ROUTINE routine{nullptr};
    void* deferredContext{nullptr};
    void* systemArgument1{nullptr};
    void* systemArgument2{nullptr};
    DpcImportance importance{DpcImportance::Medium};
    uint32_t targetProcessor{0};
    bool inserted{false};
};

class DpcQueue {
public:
    static DpcQueue& get() {
        static DpcQueue instance;
        return instance;
    }

    bool queueDpc(KDPC* dpc, void* arg1 = nullptr, void* arg2 = nullptr) {
        if (!dpc || !dpc->routine) return false;
        SpinLockGuard guard(lock_);
        if (dpc->inserted) return false;

        dpc->systemArgument1 = arg1;
        dpc->systemArgument2 = arg2;
        dpc->inserted = true;
        entries_.push_back(dpc);
        return true;
    }

    size_t drainDpcs() {
        std::vector<KDPC*> toExecute;
        {
            SpinLockGuard guard(lock_);
            toExecute.swap(entries_);
            for (auto* dpc : toExecute) {
                dpc->inserted = false;
            }
        }

        // DPCs execute at DISPATCH_LEVEL
        KIRQL oldIrql = KfRaiseIrql(DISPATCH_LEVEL);
        for (auto* dpc : toExecute) {
            dpc->routine(dpc, dpc->deferredContext, dpc->systemArgument1, dpc->systemArgument2);
            g_CurrentCpu.dpcCount++;
        }
        KeLowerIrql(oldIrql);

        return toExecute.size();
    }

    [[nodiscard]] size_t getQueuedCount() const {
        return entries_.size();
    }

private:
    DpcQueue() = default;
    SpinLock lock_;
    std::vector<KDPC*> entries_;
};

// ============================================================================
// 4. Asynchronous Procedure Calls (KAPC)
// ============================================================================
enum class ApcEnvironment : uint8_t {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment
};

struct KAPC;
using PKNORMAL_ROUTINE = void (*)(void* normalContext, void* sysArg1, void* sysArg2);
using PKKERNEL_ROUTINE = void (*)(KAPC* apc, PKNORMAL_ROUTINE* normalRoutine, void** normalContext, void** sysArg1, void** sysArg2);

struct KAPC {
    Handle targetTid{0};
    PKKERNEL_ROUTINE kernelRoutine{nullptr};
    PKNORMAL_ROUTINE normalRoutine{nullptr};
    void* normalContext{nullptr};
    void* systemArgument1{nullptr};
    void* systemArgument2{nullptr};
    uint8_t apcMode{0}; // 0 = KernelMode, 1 = UserMode
    bool inserted{false};
};

// ============================================================================
// 5. 32-Queue Priority Thread Scheduler
// ============================================================================
inline constexpr uint32_t PRIORITY_LOWEST         = 0;
inline constexpr uint32_t PRIORITY_IDLE           = 0;
inline constexpr uint32_t PRIORITY_NORMAL         = 8;
inline constexpr uint32_t PRIORITY_HIGH           = 13;
inline constexpr uint32_t PRIORITY_REALTIME_MIN   = 16;
inline constexpr uint32_t PRIORITY_REALTIME_MAX   = 31;
inline constexpr uint32_t NUM_PRIORITY_LEVELS     = 32;

inline constexpr uint32_t DEFAULT_QUANTUM_WORKSTATION = 6;
inline constexpr uint32_t DEFAULT_QUANTUM_SERVER      = 36;

struct ScheduledThreadEntry {
    Handle tid{0};
    Handle pid{0};
    uint32_t basePriority{PRIORITY_NORMAL};
    uint32_t currentPriority{PRIORITY_NORMAL};
    int32_t quantumRemaining{DEFAULT_QUANTUM_WORKSTATION};
    uint64_t totalCyclesExecuted{0};
    std::string name;
};

class PriorityScheduler {
public:
    static PriorityScheduler& get() {
        static PriorityScheduler instance;
        return instance;
    }

    void readyThread(ScheduledThreadEntry thread) {
        SpinLockGuard guard(lock_);
        uint32_t prio = std::min(thread.currentPriority, PRIORITY_REALTIME_MAX);
        runQueues_[prio].push_back(std::move(thread));
        totalReadyThreads_++;
    }

    /**
     * @brief Select next highest priority runnable thread (KiSelectNextThread).
     */
    [[nodiscard]] std::optional<ScheduledThreadEntry> selectNextThread() {
        SpinLockGuard guard(lock_);
        // Scan priority queues from Real-Time 31 down to Idle 0
        for (int p = PRIORITY_REALTIME_MAX; p >= 0; --p) {
            if (!runQueues_[p].empty()) {
                auto selected = std::move(runQueues_[p].front());
                runQueues_[p].pop_front();
                totalReadyThreads_--;
                g_CurrentCpu.contextSwitches++;
                return selected;
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Clock tick quantum expiration & dynamic priority decay.
     */
    void clockTick(ScheduledThreadEntry& runningThread) {
        runningThread.quantumRemaining--;
        runningThread.totalCyclesExecuted += 1000;

        // If quantum exhausted
        if (runningThread.quantumRemaining <= 0) {
            // Real-time priorities do NOT decay
            if (runningThread.currentPriority < PRIORITY_REALTIME_MIN) {
                if (runningThread.currentPriority > runningThread.basePriority) {
                    runningThread.currentPriority--; // Priority decay
                }
            }
            runningThread.quantumRemaining = DEFAULT_QUANTUM_WORKSTATION;
            readyThread(runningThread);
        }
    }

    /**
     * @brief Boost thread priority upon I/O event completion.
     */
    void boostPriority(ScheduledThreadEntry& thread, uint32_t boostAmount) {
        if (thread.currentPriority < PRIORITY_REALTIME_MIN) {
            thread.currentPriority = std::min(
                thread.currentPriority + boostAmount,
                PRIORITY_REALTIME_MIN - 1
            );
        }
    }

    [[nodiscard]] size_t getReadyThreadCount() const noexcept {
        return totalReadyThreads_;
    }

private:
    PriorityScheduler() : totalReadyThreads_(0) {}
    mutable SpinLock lock_;
    std::array<std::deque<ScheduledThreadEntry>, NUM_PRIORITY_LEVELS> runQueues_;
    std::atomic<size_t> totalReadyThreads_;
};

} // namespace micant::ke
