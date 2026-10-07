#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <algorithm>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ke.hpp"
#include "sync.hpp"
#include "ob.hpp"

namespace micant::timer {

enum class TimerType : uint32_t {
    NotificationTimer    = 0, // Manual reset - awakens all waiters when signaled
    SynchronizationTimer = 1  // Auto reset - awakens a single waiter and resets
};

struct KTIMER;

/**
 * @brief Clean-room modern C++23 NT Kernel Timer Object (KTIMER / TimerObject).
 * Inherits from sync::DispatcherObject for multi-object wait synchronization.
 */
class TimerObject : public sync::DispatcherObject {
public:
    explicit TimerObject(TimerType type = TimerType::NotificationTimer)
        : type_(type), signaled_(false) {}

    [[nodiscard]] bool isSignaled(Handle /*threadId*/ = 0) const override {
        std::unique_lock<std::mutex> lock(mutex_);
        return signaled_;
    }

    bool satisfyWait(Handle /*threadId*/ = 0) override {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!signaled_) return false;
        if (type_ == TimerType::SynchronizationTimer) {
            signaled_ = false; // Auto-reset
        }
        return true;
    }

    bool wait(uint32_t timeoutMs = 0xFFFFFFFF) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (signaled_) {
            if (type_ == TimerType::SynchronizationTimer) {
                signaled_ = false;
            }
            return true;
        }
        if (timeoutMs == 0) return false;

        auto pred = [this]() { return signaled_; };
        if (timeoutMs == 0xFFFFFFFF) {
            cv_.wait(lock, pred);
        } else {
            if (!cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), pred)) {
                return false;
            }
        }
        if (type_ == TimerType::SynchronizationTimer) {
            signaled_ = false;
        }
        return true;
    }

    void setSignaled() {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            signaled_ = true;
            if (type_ == TimerType::NotificationTimer) {
                cv_.notify_all();
            } else {
                cv_.notify_one();
            }
        }
        notifyListeners();
    }

    void reset() {
        std::unique_lock<std::mutex> lock(mutex_);
        signaled_ = false;
    }

    [[nodiscard]] TimerType getType() const noexcept { return type_; }
    void setType(TimerType type) noexcept { type_ = type; }

    [[nodiscard]] LargeInteger getDueTime() const noexcept { return dueTime_; }
    void setDueTime(LargeInteger dueTime) noexcept { dueTime_ = dueTime; }

    [[nodiscard]] uint32_t getPeriodMs() const noexcept { return periodMs_; }
    void setPeriodMs(uint32_t periodMs) noexcept { periodMs_ = periodMs; }

    [[nodiscard]] ke::KDPC* getDpc() const noexcept { return dpc_; }
    void setDpc(ke::KDPC* dpc) noexcept { dpc_ = dpc; }

    [[nodiscard]] bool isInserted() const noexcept { return inserted_; }
    void setInserted(bool inserted) noexcept { inserted_ = inserted; }

    [[nodiscard]] std::chrono::steady_clock::time_point getDeadline() const noexcept { return deadline_; }
    void setDeadline(std::chrono::steady_clock::time_point deadline) noexcept { deadline_ = deadline; }

private:
    TimerType type_{TimerType::NotificationTimer};
    bool signaled_{false};
    bool inserted_{false};
    LargeInteger dueTime_{};
    uint32_t periodMs_{0};
    ke::KDPC* dpc_{nullptr};
    std::chrono::steady_clock::time_point deadline_{};
    mutable std::mutex mutex_;
    std::condition_variable cv_;
};

/**
 * @brief Standard NT Kernel Timer structure (KTIMER) representation.
 */
struct KTIMER {
    TimerObject obj;

    explicit KTIMER(TimerType type = TimerType::NotificationTimer) : obj(type) {}
};

/**
 * @brief Kernel Timer Manager Subsystem
 * Manages active KTIMERs, checks deadlines, queues Timer DPCs, and signals events.
 */
class TimerManager {
public:
    static TimerManager& get() {
        static TimerManager instance;
        return instance;
    }

    bool setTimer(KTIMER* timer, LargeInteger dueTime, uint32_t periodMs = 0, ke::KDPC* dpc = nullptr) {
        if (!timer) return false;
        std::lock_guard<std::mutex> lock(mutex_);

        bool wasInserted = timer->obj.isInserted();
        timer->obj.reset();
        timer->obj.setDueTime(dueTime);
        timer->obj.setPeriodMs(periodMs);
        timer->obj.setDpc(dpc);

        // Compute expiration time point
        // If dueTime.quadPart < 0: relative time in 100ns units (-10,000 = 1ms)
        // If dueTime.quadPart >= 0: relative offset or absolute
        std::chrono::nanoseconds delayNs{0};
        if (dueTime.quadPart < 0) {
            delayNs = std::chrono::nanoseconds(-dueTime.quadPart * 100);
        } else if (dueTime.quadPart > 0) {
            delayNs = std::chrono::nanoseconds(dueTime.quadPart * 100);
        }
        timer->obj.setDeadline(std::chrono::steady_clock::now() + delayNs);
        timer->obj.setInserted(true);

        if (!wasInserted) {
            activeTimers_.push_back(timer);
        }
        return wasInserted;
    }

    bool cancelTimer(KTIMER* timer) {
        if (!timer) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!timer->obj.isInserted()) return false;

        timer->obj.setInserted(false);
        std::erase(activeTimers_, timer);
        return true;
    }

    size_t processTimers() {
        std::vector<KTIMER*> expired;
        auto now = std::chrono::steady_clock::now();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = activeTimers_.begin(); it != activeTimers_.end(); ) {
                KTIMER* timer = *it;
                if (timer && timer->obj.isInserted() && now >= timer->obj.getDeadline()) {
                    expired.push_back(timer);
                    if (timer->obj.getPeriodMs() > 0) {
                        // Re-arm periodic timer
                        timer->obj.setDeadline(now + std::chrono::milliseconds(timer->obj.getPeriodMs()));
                        ++it;
                    } else {
                        timer->obj.setInserted(false);
                        it = activeTimers_.erase(it);
                    }
                } else {
                    ++it;
                }
            }
        }

        for (auto* timer : expired) {
            timer->obj.setSignaled();
            if (timer->obj.getDpc()) {
                ke::DpcQueue::get().queueDpc(timer->obj.getDpc());
            }
        }
        return expired.size();
    }

    [[nodiscard]] size_t getActiveTimerCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return activeTimers_.size();
    }

private:
    TimerManager() = default;
    mutable std::mutex mutex_;
    std::vector<KTIMER*> activeTimers_;
};

// Standard NT Kernel DDK C-style APIs
inline void KeInitializeTimer(KTIMER* timer) {
    if (timer) {
        timer->obj.setType(TimerType::NotificationTimer);
        timer->obj.reset();
        timer->obj.setInserted(false);
    }
}

inline void KeInitializeTimerEx(KTIMER* timer, TimerType type) {
    if (timer) {
        timer->obj.setType(type);
        timer->obj.reset();
        timer->obj.setInserted(false);
    }
}

inline bool KeSetTimer(KTIMER* timer, LargeInteger dueTime, ke::KDPC* dpc = nullptr) {
    return TimerManager::get().setTimer(timer, dueTime, 0, dpc);
}

inline bool KeSetTimerEx(KTIMER* timer, LargeInteger dueTime, uint32_t periodMs, ke::KDPC* dpc = nullptr) {
    return TimerManager::get().setTimer(timer, dueTime, periodMs, dpc);
}

inline bool KeCancelTimer(KTIMER* timer) {
    return TimerManager::get().cancelTimer(timer);
}

inline bool KeReadStateTimer(const KTIMER* timer) {
    return timer ? timer->obj.isSignaled() : false;
}

} // namespace micant::timer
