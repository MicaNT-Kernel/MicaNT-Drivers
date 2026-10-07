#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <vector>
#include <memory>
#include <functional>
#include <algorithm>
#include <unordered_map>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ob.hpp"

namespace micant::sync {

/**
 * @brief Dispatcher Object base class for NT synchronization primitives.
 * Enables wait-for-single-object and wait-for-multiple-objects across
 * Events, Mutants, Semaphores, Timers, and other kernel objects.
 */
class DispatcherObject {
public:
    virtual ~DispatcherObject() = default;

    [[nodiscard]] virtual bool isSignaled(Handle threadId = 0) const = 0;
    virtual bool satisfyWait(Handle threadId = 0) = 0;

    void addWaitListener(const std::shared_ptr<std::condition_variable>& cv, const std::shared_ptr<std::mutex>& cvMutex) {
        std::lock_guard<std::mutex> lock(listenerMutex_);
        listeners_.push_back({cv, cvMutex});
    }

    void removeWaitListener(const std::shared_ptr<std::condition_variable>& cv) {
        std::lock_guard<std::mutex> lock(listenerMutex_);
        std::erase_if(listeners_, [&](const auto& pair) {
            return pair.first.lock() == cv;
        });
    }

protected:
    void notifyListeners() {
        std::lock_guard<std::mutex> lock(listenerMutex_);
        for (auto& [weakCv, weakMutex] : listeners_) {
            auto cv = weakCv.lock();
            auto mtx = weakMutex.lock();
            if (cv && mtx) {
                std::lock_guard<std::mutex> lk(*mtx);
                cv->notify_all();
            }
        }
    }

private:
    mutable std::mutex listenerMutex_;
    std::vector<std::pair<std::weak_ptr<std::condition_variable>, std::weak_ptr<std::mutex>>> listeners_;
};

enum class EventType : uint32_t {
    NotificationEvent = 0,    // Manual reset
    SynchronizationEvent = 1  // Auto reset
};

/**
 * @brief NT Event Object (KEVENT).
 */
class EventObject : public DispatcherObject {
public:
    EventObject(EventType type, bool initialState)
        : type_(type), signaled_(initialState) {}

    void set() {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            signaled_ = true;
            if (type_ == EventType::NotificationEvent) {
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

    [[nodiscard]] bool isSignaled(Handle /*threadId*/ = 0) const override {
        std::unique_lock<std::mutex> lock(mutex_);
        return signaled_;
    }

    bool satisfyWait(Handle /*threadId*/ = 0) override {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!signaled_) return false;
        if (type_ == EventType::SynchronizationEvent) {
            signaled_ = false; // Auto-reset
        }
        return true;
    }

    bool wait(uint32_t timeoutMs = 0xFFFFFFFF) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (signaled_) {
            if (type_ == EventType::SynchronizationEvent) {
                signaled_ = false; // Auto-reset
            }
            return true;
        }

        if (timeoutMs == 0) {
            return false;
        }

        auto pred = [this]() { return signaled_; };
        if (timeoutMs == 0xFFFFFFFF) {
            cv_.wait(lock, pred);
        } else {
            if (!cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), pred)) {
                return false; // Timeout
            }
        }

        if (type_ == EventType::SynchronizationEvent) {
            signaled_ = false; // Auto-reset
        }
        return true;
    }

    [[nodiscard]] EventType getType() const noexcept {
        return type_;
    }

private:
    EventType type_;
    bool signaled_{false};
    mutable std::mutex mutex_;
    std::condition_variable cv_;
};

/**
 * @brief NT Mutant / Mutex Object (KMUTANT).
 * Supports recursive acquisition by owning thread.
 */
class MutantObject : public DispatcherObject {
public:
    explicit MutantObject(bool initialOwner)
        : ownerThreadId_(initialOwner ? 1 : 0), recursionCount_(initialOwner ? 1 : 0) {}

    [[nodiscard]] bool isSignaled(Handle threadId = 0) const override {
        std::unique_lock<std::mutex> lock(mutex_);
        return ownerThreadId_ == 0 || (threadId != 0 && ownerThreadId_ == threadId);
    }

    bool satisfyWait(Handle threadId = 0) override {
        std::unique_lock<std::mutex> lock(mutex_);
        Handle tid = (threadId != 0) ? threadId : 1;
        if (ownerThreadId_ == 0) {
            ownerThreadId_ = tid;
            recursionCount_ = 1;
            return true;
        }
        if (ownerThreadId_ == tid) {
            recursionCount_++;
            return true;
        }
        return false;
    }

    bool acquire(Handle threadId, uint32_t timeoutMs = 0xFFFFFFFF) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (ownerThreadId_ == threadId) {
            recursionCount_++;
            return true;
        }

        auto pred = [this]() { return ownerThreadId_ == 0; };
        if (timeoutMs == 0xFFFFFFFF) {
            cv_.wait(lock, pred);
        } else if (timeoutMs > 0) {
            if (!cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), pred)) {
                return false;
            }
        } else {
            if (ownerThreadId_ != 0) return false;
        }

        ownerThreadId_ = threadId;
        recursionCount_ = 1;
        return true;
    }

    bool release(Handle threadId) {
        bool releasedToZero = false;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (ownerThreadId_ != threadId) {
                return false; // Mutex not owned by caller
            }

            recursionCount_--;
            if (recursionCount_ == 0) {
                ownerThreadId_ = 0;
                cv_.notify_one();
                releasedToZero = true;
            }
        }
        if (releasedToZero) {
            notifyListeners();
        }
        return true;
    }

    [[nodiscard]] Handle getOwner() const noexcept {
        std::unique_lock<std::mutex> lock(mutex_);
        return ownerThreadId_;
    }

    [[nodiscard]] uint32_t getRecursionCount() const noexcept {
        std::unique_lock<std::mutex> lock(mutex_);
        return recursionCount_;
    }

private:
    Handle ownerThreadId_{0};
    uint32_t recursionCount_{0};
    mutable std::mutex mutex_;
    std::condition_variable cv_;
};

/**
 * @brief NT Semaphore Object (KSEMAPHORE).
 */
class SemaphoreObject : public DispatcherObject {
public:
    SemaphoreObject(int32_t initialCount, int32_t maximumCount)
        : currentCount_(initialCount), maximumCount_(maximumCount) {}

    [[nodiscard]] bool isSignaled(Handle /*threadId*/ = 0) const override {
        std::unique_lock<std::mutex> lock(mutex_);
        return currentCount_ > 0;
    }

    bool satisfyWait(Handle /*threadId*/ = 0) override {
        std::unique_lock<std::mutex> lock(mutex_);
        if (currentCount_ > 0) {
            currentCount_--;
            return true;
        }
        return false;
    }

    bool release(int32_t releaseCount, int32_t* previousCount = nullptr) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (previousCount) *previousCount = currentCount_;
            if (currentCount_ + releaseCount > maximumCount_) {
                return false;
            }
            currentCount_ += releaseCount;
            for (int32_t i = 0; i < releaseCount; ++i) {
                cv_.notify_one();
            }
        }
        notifyListeners();
        return true;
    }

    bool wait(uint32_t timeoutMs = 0xFFFFFFFF) {
        std::unique_lock<std::mutex> lock(mutex_);
        auto pred = [this]() { return currentCount_ > 0; };
        if (timeoutMs == 0xFFFFFFFF) {
            cv_.wait(lock, pred);
        } else {
            if (!cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), pred)) {
                return false;
            }
        }
        currentCount_--;
        return true;
    }

    [[nodiscard]] int32_t getCount() const noexcept {
        std::unique_lock<std::mutex> lock(mutex_);
        return currentCount_;
    }

private:
    int32_t currentCount_{0};
    int32_t maximumCount_{1};
    mutable std::mutex mutex_;
    std::condition_variable cv_;
};

/**
 * @brief Kernel Dispatcher Object Registry
 * Centralized tracking and handle allocation for all NT synchronization and timer objects.
 */
class DispatcherRegistry {
public:
    static DispatcherRegistry& get() {
        static DispatcherRegistry instance;
        return instance;
    }

    Handle registerObject(std::shared_ptr<DispatcherObject> obj) {
        std::lock_guard<std::mutex> lock(mutex_);
        Handle h = nextHandle_;
        nextHandle_ += 4;
        objects_[h] = std::move(obj);
        return h;
    }

    void registerWithHandle(Handle h, std::shared_ptr<DispatcherObject> obj) {
        std::lock_guard<std::mutex> lock(mutex_);
        objects_[h] = std::move(obj);
    }

    std::shared_ptr<DispatcherObject> lookup(Handle h) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = objects_.find(h);
        return (it != objects_.end()) ? it->second : nullptr;
    }

    template <typename T>
    std::shared_ptr<T> lookupAs(Handle h) const {
        auto base = lookup(h);
        return std::dynamic_pointer_cast<T>(base);
    }

    void unregister(Handle h) {
        std::lock_guard<std::mutex> lock(mutex_);
        objects_.erase(h);
    }

    [[nodiscard]] size_t getObjectCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return objects_.size();
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        objects_.clear();
        nextHandle_ = 0x100;
    }

private:
    DispatcherRegistry() = default;
    mutable std::mutex mutex_;
    Handle nextHandle_{0x100};
    std::unordered_map<Handle, std::shared_ptr<DispatcherObject>> objects_;
};

} // namespace micant::sync
