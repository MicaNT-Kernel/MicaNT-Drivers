#pragma once

#include <cstdint>
#include <functional>
#include <queue>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ke.hpp"

namespace micant::ex {

// Standard NT Executive Work Queue Types
enum class WorkQueueType : uint32_t {
    CriticalWorkQueue       = 0,
    DelayedWorkQueue        = 1,
    HyperCriticalWorkQueue  = 2,
    MaxWorkQueue            = 3
};

using WorkerRoutineCallback = void (*)(void* parameter);

/**
 * @brief Standard NT Executive Work Queue Item (WORK_QUEUE_ITEM)
 */
struct WorkQueueItem {
    WorkerRoutineCallback routine{nullptr};
    void* parameter{nullptr};
    bool inUse{false};
};

/**
 * @brief Clean-room Executive Worker Queue Subsystem
 * Executes deferred system tasks on background kernel threads at PASSIVE_LEVEL.
 */
class ExecutiveWorkQueueManager {
public:
    static ExecutiveWorkQueueManager& get() {
        static ExecutiveWorkQueueManager instance;
        return instance;
    }

    void initialize(size_t workerThreadCount = 2) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (running_) return;
        running_ = true;

        for (size_t i = 0; i < workerThreadCount; ++i) {
            workers_.emplace_back([this]() {
                workerThreadLoop();
            });
        }
    }

    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_) return;
            running_ = false;
        }
        cv_.notify_all();
        for (auto& t : workers_) {
            if (t.joinable()) {
                t.join();
            }
        }
        workers_.clear();
    }

    ~ExecutiveWorkQueueManager() {
        shutdown();
    }

    void queueWorkItem(WorkQueueItem* item, WorkQueueType queueType) {
        if (!item || !item->routine) return;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            item->inUse = true;
            uint32_t qIndex = static_cast<uint32_t>(queueType);
            if (qIndex >= static_cast<uint32_t>(WorkQueueType::MaxWorkQueue)) {
                qIndex = static_cast<uint32_t>(WorkQueueType::CriticalWorkQueue);
            }
            queues_[qIndex].push(item);
            totalQueued_++;
        }
        cv_.notify_one();
    }

    [[nodiscard]] uint64_t getTotalProcessed() const noexcept {
        return totalProcessed_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] size_t getActiveWorkerCount() const noexcept {
        return workers_.size();
    }

private:
    ExecutiveWorkQueueManager() = default;

    void workerThreadLoop() {
        // Executive worker threads run strictly at PASSIVE_LEVEL (IRQL 0)
        ke::KeLowerIrql(ke::PASSIVE_LEVEL);

        while (true) {
            WorkQueueItem* itemToRun = nullptr;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this]() {
                    if (!running_) return true;
                    for (int i = 2; i >= 0; --i) {
                        if (!queues_[i].empty()) return true;
                    }
                    return false;
                });

                if (!running_) {
                    // Drain remaining if needed or exit
                    bool hasItems = false;
                    for (int i = 2; i >= 0; --i) {
                        if (!queues_[i].empty()) { hasItems = true; break; }
                    }
                    if (!hasItems) break;
                }

                // Dequeue with strict priority: HyperCritical > Critical > Delayed
                for (int i = 2; i >= 0; --i) {
                    if (!queues_[i].empty()) {
                        itemToRun = queues_[i].front();
                        queues_[i].pop();
                        break;
                    }
                }
            }

            if (itemToRun && itemToRun->routine) {
                // Assert PASSIVE_LEVEL before calling worker routine
                if (ke::KeGetCurrentIrql() == ke::PASSIVE_LEVEL) {
                    itemToRun->routine(itemToRun->parameter);
                }
                itemToRun->inUse = false;
                totalProcessed_.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    std::mutex mutex_;
    std::condition_variable cv_;
    bool running_{false};
    std::vector<std::thread> workers_;
    std::queue<WorkQueueItem*> queues_[3]; // HyperCritical, Critical, Delayed
    uint64_t totalQueued_{0};
    std::atomic<uint64_t> totalProcessed_{0};
};

// Standard NT Executive Work Item Functions
inline void ExInitializeWorkItem(
    WorkQueueItem* item,
    WorkerRoutineCallback routine,
    void* context
) noexcept {
    if (item) {
        item->routine = routine;
        item->parameter = context;
        item->inUse = false;
    }
}

inline void ExQueueWorkItem(
    WorkQueueItem* item,
    WorkQueueType queueType
) {
    ExecutiveWorkQueueManager::get().queueWorkItem(item, queueType);
}

} // namespace micant::ex
