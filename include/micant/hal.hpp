#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <chrono>
#include <atomic>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ke.hpp"

namespace micant::hal {

/**
 * @brief Processor Architecture Family.
 */
enum class ProcessorArchitecture : uint16_t {
    Amd64 = 9,      // PROCESSOR_ARCHITECTURE_AMD64
    Arm64 = 12,     // PROCESSOR_ARCHITECTURE_ARM64
    Intel = 0       // PROCESSOR_ARCHITECTURE_INTEL
};

/**
 * @brief Kernel Processor Control Block (KPRCB).
 * Detailed per-core CPU execution statistics and scheduler status.
 */
struct KernelProcessorControlBlock {
    uint32_t cpuId{0};
    ProcessorArchitecture architecture{ProcessorArchitecture::Amd64};
    uint32_t coreClockMhz{3600};
    std::atomic<uint64_t> contextSwitches{0};
    std::atomic<uint64_t> interruptsServiced{0};
    std::atomic<uint64_t> dpcsServiced{0};
    std::atomic<uint64_t> totalCycles{0};
    bool dpcRoutineActive{false};
};

/**
 * @brief Kernel Processor Control Region (KPCR).
 * Standard NT structure located at GS:[0] in kernel mode.
 */
struct KernelProcessorControlRegion {
    KernelProcessorControlRegion* self{this};
    void* currentThread{nullptr};  // KTHREAD*
    void* nextThread{nullptr};     // KTHREAD*
    void* idleThread{nullptr};     // KTHREAD*
    ke::KIRQL currentIrql{ke::PASSIVE_LEVEL};
    KernelProcessorControlBlock prcb{};
};

/**
 * @brief Hardware Abstraction Layer (HAL).
 * Abstracts physical APIC timers, clocks, CPU topology, and I/O bus interfaces.
 */
class HardwareAbstractionLayer {
public:
    static HardwareAbstractionLayer& get() {
        static HardwareAbstractionLayer instance;
        return instance;
    }

    void initialize(uint32_t processorCount = 4, ProcessorArchitecture arch = ProcessorArchitecture::Amd64, uint32_t clockMhz = 3600) {
        processors_.clear();
        for (uint32_t i = 0; i < processorCount; ++i) {
            auto pc = std::make_unique<KernelProcessorControlRegion>();
            pc->prcb.cpuId = i;
            pc->prcb.architecture = arch;
            pc->prcb.coreClockMhz = clockMhz;
            processors_.push_back(std::move(pc));
        }
        bootTimestamp_ = std::chrono::steady_clock::now();
    }

    [[nodiscard]] uint32_t getProcessorCount() const noexcept {
        return static_cast<uint32_t>(processors_.size());
    }

    [[nodiscard]] KernelProcessorControlRegion* getKpcr(uint32_t cpuIndex = 0) const {
        if (cpuIndex >= processors_.size()) return nullptr;
        return processors_[cpuIndex].get();
    }

    /**
     * @brief High-precision timer query (KeQueryPerformanceCounter).
     */
    void queryPerformanceCounter(LargeInteger& performanceCounter, LargeInteger* performanceFrequency = nullptr) const noexcept {
        auto now = std::chrono::steady_clock::now();
        auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now - bootTimestamp_).count();
        
        performanceCounter.quadPart = nanos;
        if (performanceFrequency) {
            performanceFrequency->quadPart = 1'000'000'000; // 1 GHz nanosecond resolution
        }
    }

    /**
     * @brief Stalls CPU execution for specified microseconds (KeStallExecutionProcessor).
     */
    void stallExecutionProcessor(uint32_t microseconds) const noexcept {
        auto start = std::chrono::steady_clock::now();
        while (true) {
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= microseconds) break;
#if defined(_M_X64) || defined(__x86_64__)
            _mm_pause();
#endif
        }
    }

    /**
     * @brief Dispatches LAPIC periodic scheduling tick.
     */
    void dispatchClockTick(uint32_t cpuIndex = 0) {
        auto* kpcr = getKpcr(cpuIndex);
        if (kpcr) {
            kpcr->prcb.totalCycles += 10000;
            kpcr->prcb.interruptsServiced++;
        }
    }

private:
    HardwareAbstractionLayer() { initialize(); }
    std::vector<std::unique_ptr<KernelProcessorControlRegion>> processors_;
    std::chrono::steady_clock::time_point bootTimestamp_;
};

// Standard NT HAL API helpers
inline void KeQueryPerformanceCounter(LargeInteger& counter, LargeInteger* frequency = nullptr) {
    HardwareAbstractionLayer::get().queryPerformanceCounter(counter, frequency);
}

inline void KeStallExecutionProcessor(uint32_t microseconds) {
    HardwareAbstractionLayer::get().stallExecutionProcessor(microseconds);
}

} // namespace micant::hal
