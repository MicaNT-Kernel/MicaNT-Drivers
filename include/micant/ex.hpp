#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <memory>
#include <mutex>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iomanip>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ke.hpp"

namespace micant::ex {

// Standard NT Executive Pool Types
enum class PoolType : uint32_t {
    NonPagedPool                   = 0,
    PagedPool                      = 1,
    NonPagedPoolMustSucceed        = 2,
    DontUseThisType                = 3,
    NonPagedPoolCacheAligned       = 4,
    PagedPoolCacheAligned          = 5,
    NonPagedPoolNx                 = 512,
    PagedPoolNx                    = 513
};

/**
 * @brief Helper to construct standard 4-byte NT pool tags.
 * e.g. MAKE_POOL_TAG('M', 'i', 'c', 'a')
 */
[[nodiscard]] constexpr uint32_t makePoolTag(char c1, char c2, char c3, char c4) noexcept {
    return (static_cast<uint32_t>(static_cast<uint8_t>(c1))) |
           (static_cast<uint32_t>(static_cast<uint8_t>(c2)) << 8) |
           (static_cast<uint32_t>(static_cast<uint8_t>(c3)) << 16) |
           (static_cast<uint32_t>(static_cast<uint8_t>(c4)) << 24);
}

inline constexpr uint32_t TAG_MICA_CORE = makePoolTag('M', 'i', 'c', 'a');
inline constexpr uint32_t TAG_PROCESS   = makePoolTag('P', 'r', 'o', 'c');
inline constexpr uint32_t TAG_THREAD    = makePoolTag('T', 'h', 'r', 'e');
inline constexpr uint32_t TAG_SECTION   = makePoolTag('S', 'e', 'c', 'O');
inline constexpr uint32_t TAG_IO_BUFFER = makePoolTag('I', 'o', ' ', ' ');
inline constexpr uint32_t TAG_REGISTRY  = makePoolTag('C', 'm', 'R', 'e');
inline constexpr uint32_t TAG_SECURITY  = makePoolTag('S', 'e', 'c', 'u');

struct PoolBlockHeader {
    uint32_t magic{0x4D494341}; // 'MICA'
    uint32_t tag{0};
    PoolType type{PoolType::NonPagedPool};
    size_t requestedSize{0};
};

struct PoolTagStats {
    uint32_t tag{0};
    size_t activeAllocations{0};
    size_t activeBytes{0};
    size_t totalAllocations{0};
    size_t totalFrees{0};
};

/**
 * @brief Executive Memory Pool Manager.
 * Implements NonPagedPool (RAM-resident) and PagedPool with strict IRQL enforcement.
 */
class ExecutivePool {
public:
    static ExecutivePool& get() {
        static ExecutivePool instance;
        return instance;
    }

    /**
     * @brief Allocates pool memory with 4-byte diagnostic tag.
     * Enforces that PagedPool CANNOT be allocated at IRQL >= DISPATCH_LEVEL.
     */
    void* allocatePoolWithTag(PoolType poolType, size_t numberOfBytes, uint32_t tag) {
        if (numberOfBytes == 0) return nullptr;

        // IRQL CONTRACT: PagedPool cannot be accessed or allocated at DISPATCH_LEVEL or above
        ke::KIRQL currentIrql = ke::KeGetCurrentIrql();
        bool isPaged = (poolType == PoolType::PagedPool || poolType == PoolType::PagedPoolNx || poolType == PoolType::PagedPoolCacheAligned);
        
        if (isPaged && currentIrql >= ke::DISPATCH_LEVEL) {
            std::cerr << "[MicaNT BugCheck] IRQL_NOT_LESS_OR_EQUAL: Attempted to allocate PagedPool at IRQL " 
                      << static_cast<uint32_t>(currentIrql) << " (>= DISPATCH_LEVEL)\n";
            return nullptr;
        }

        size_t totalBytes = sizeof(PoolBlockHeader) + numberOfBytes;
        void* raw = std::malloc(totalBytes);
        if (!raw) return nullptr;

        auto* header = reinterpret_cast<PoolBlockHeader*>(raw);
        header->magic = 0x4D494341;
        header->tag = tag;
        header->type = poolType;
        header->requestedSize = numberOfBytes;

        void* userPtr = header + 1;

        // Record telemetry
        {
            ke::SpinLockGuard guard(lock_);
            auto& stats = tagStats_[tag];
            stats.tag = tag;
            stats.activeAllocations++;
            stats.activeBytes += numberOfBytes;
            stats.totalAllocations++;

            if (isPaged) {
                totalPagedBytes_ += numberOfBytes;
            } else {
                totalNonPagedBytes_ += numberOfBytes;
            }
        }

        return userPtr;
    }

    /**
     * @brief Frees pool memory previously allocated with allocatePoolWithTag.
     */
    void freePoolWithTag(void* p, uint32_t tag) {
        if (!p) return;

        auto* header = reinterpret_cast<PoolBlockHeader*>(p) - 1;
        if (header->magic != 0x4D494341) {
            std::cerr << "[MicaNT BugCheck] BAD_POOL_CALLER: Memory block corrupted or double freed\n";
            return;
        }

        // Verify tag if provided
        if (tag != 0 && header->tag != tag) {
            std::cerr << "[MicaNT BugCheck] BAD_POOL_CALLER: Pool tag mismatch on free\n";
        }

        size_t size = header->requestedSize;
        bool isPaged = (header->type == PoolType::PagedPool || header->type == PoolType::PagedPoolNx);

        // Clear magic to detect double frees
        header->magic = 0xDEADBEEF;

        {
            ke::SpinLockGuard guard(lock_);
            auto it = tagStats_.find(header->tag);
            if (it != tagStats_.end()) {
                it->second.activeAllocations--;
                it->second.activeBytes -= size;
                it->second.totalFrees++;
            }

            if (isPaged) {
                totalPagedBytes_ -= size;
            } else {
                totalNonPagedBytes_ -= size;
            }
        }

        std::free(header);
    }

    [[nodiscard]] size_t getTotalNonPagedBytes() const noexcept { return totalNonPagedBytes_; }
    [[nodiscard]] size_t getTotalPagedBytes() const noexcept { return totalPagedBytes_; }

    [[nodiscard]] PoolTagStats getTagStats(uint32_t tag) const {
        ke::SpinLockGuard guard(lock_);
        auto it = tagStats_.find(tag);
        if (it != tagStats_.end()) return it->second;
        return PoolTagStats{ .tag = tag };
    }

    void dumpPoolTelemetry() const {
        ke::SpinLockGuard guard(lock_);
        std::cout << "\n================ Executive Pool Telemetry ================\n";
        std::cout << "  - NonPaged Pool Active: " << (totalNonPagedBytes_ / 1024) << " KB\n";
        std::cout << "  - Paged Pool Active:    " << (totalPagedBytes_ / 1024) << " KB\n";
        std::cout << "  - Active Tags:\n";
        for (const auto& [tag, stat] : tagStats_) {
            char tagStr[5] = {
                static_cast<char>(tag & 0xFF),
                static_cast<char>((tag >> 8) & 0xFF),
                static_cast<char>((tag >> 16) & 0xFF),
                static_cast<char>((tag >> 24) & 0xFF),
                '\0'
            };
            std::cout << "      * Tag: ['" << tagStr << "'] Active Allocs: " 
                      << stat.activeAllocations << " (" << stat.activeBytes << " bytes)\n";
        }
        std::cout << "==========================================================\n\n";
    }

private:
    ExecutivePool() = default;
    mutable ke::SpinLock lock_;
    std::unordered_map<uint32_t, PoolTagStats> tagStats_;
    std::atomic<size_t> totalNonPagedBytes_{0};
    std::atomic<size_t> totalPagedBytes_{0};
};

// Standard NT Executive Pool Allocation API
inline void* ExAllocatePoolWithTag(PoolType poolType, size_t numberOfBytes, uint32_t tag) {
    return ExecutivePool::get().allocatePoolWithTag(poolType, numberOfBytes, tag);
}

inline void ExFreePoolWithTag(void* p, uint32_t tag) {
    ExecutivePool::get().freePoolWithTag(p, tag);
}

} // namespace micant::ex
