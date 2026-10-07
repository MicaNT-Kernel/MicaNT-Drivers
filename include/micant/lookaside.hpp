#pragma once

#include <cstdint>
#include <vector>
#include <mutex>
#include <memory>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ke.hpp"
#include "ex.hpp"

namespace micant::ex {

/**
 * @brief Singly-linked list entry for lock-free and spinlock lookaside lists.
 */
struct SingleListEntry {
    SingleListEntry* next{nullptr};
};

/**
 * @brief Common lookaside list statistics and telemetry.
 */
struct GeneralLookaside {
    size_t size{0};
    uint32_t tag{0};
    uint16_t depth{0};
    uint16_t maximumDepth{256};
    uint32_t totalAllocates{0};
    uint32_t allocateMisses{0};
    uint32_t totalFrees{0};
    uint32_t freeMisses{0};
};

/**
 * @brief Clean-room NonPaged Lookaside List (NPAGED_LOOKASIDE_LIST).
 * Fast O(1) fixed-size block allocator for drivers running at IRQL <= DISPATCH_LEVEL.
 */
class NPagedLookasideList {
public:
    NPagedLookasideList() = default;

    void initialize(size_t blockSize, uint32_t tag, uint16_t maxDepth = 256) {
        ke::SpinLockGuard guard(lock_);
        general_.size = blockSize;
        general_.tag = tag;
        general_.depth = 0;
        general_.maximumDepth = maxDepth;
        general_.totalAllocates = 0;
        general_.allocateMisses = 0;
        general_.totalFrees = 0;
        general_.freeMisses = 0;
        head_ = nullptr;
    }

    void* allocate() {
        void* result = nullptr;
        {
            ke::SpinLockGuard guard(lock_);
            general_.totalAllocates++;
            if (head_ != nullptr) {
                // Cache hit: O(1) pop from SLIST
                SingleListEntry* entry = head_;
                head_ = entry->next;
                general_.depth--;
                result = entry;
            } else {
                general_.allocateMisses++;
            }
        }

        if (!result) {
            // Cache miss: fall back to non-paged pool manager
            result = ExecutivePool::get().allocatePoolWithTag(
                PoolType::NonPagedPool,
                general_.size,
                general_.tag
            );
        }
        return result;
    }

    void free(void* entry) {
        if (!entry) return;

        bool returnedToPool = false;
        {
            ke::SpinLockGuard guard(lock_);
            general_.totalFrees++;
            if (general_.depth < general_.maximumDepth) {
                // Cache hit: O(1) push to SLIST
                auto* listEntry = reinterpret_cast<SingleListEntry*>(entry);
                listEntry->next = head_;
                head_ = listEntry;
                general_.depth++;
            } else {
                // Cache full: free back to pool
                general_.freeMisses++;
                returnedToPool = true;
            }
        }

        if (returnedToPool) {
            ExecutivePool::get().freePoolWithTag(entry, general_.tag);
        }
    }

    void flush() {
        std::vector<void*> toFree;
        {
            ke::SpinLockGuard guard(lock_);
            SingleListEntry* current = head_;
            while (current) {
                toFree.push_back(current);
                current = current->next;
            }
            head_ = nullptr;
            general_.depth = 0;
        }

        for (void* ptr : toFree) {
            ExecutivePool::get().freePoolWithTag(ptr, general_.tag);
        }
    }

    ~NPagedLookasideList() {
        flush();
    }

    [[nodiscard]] const GeneralLookaside& getStats() const noexcept { return general_; }

private:
    GeneralLookaside general_{};
    SingleListEntry* head_{nullptr};
    ke::SpinLock lock_{};
};

/**
 * @brief Clean-room Paged Lookaside List (PAGED_LOOKASIDE_LIST).
 * Fast O(1) fixed-size block allocator for pageable driver memory at IRQL <= APC_LEVEL.
 */
class PagedLookasideList {
public:
    PagedLookasideList() = default;

    void initialize(size_t blockSize, uint32_t tag, uint16_t maxDepth = 256) {
        std::lock_guard<std::mutex> lock(mutex_);
        general_.size = blockSize;
        general_.tag = tag;
        general_.depth = 0;
        general_.maximumDepth = maxDepth;
        general_.totalAllocates = 0;
        general_.allocateMisses = 0;
        general_.totalFrees = 0;
        general_.freeMisses = 0;
        head_ = nullptr;
    }

    void* allocate() {
        if (ke::KeGetCurrentIrql() >= ke::DISPATCH_LEVEL) {
            std::cerr << "[MicaNT BugCheck] IRQL_NOT_LESS_OR_EQUAL: PagedLookasideList allocate at IRQL >= DISPATCH_LEVEL\n";
            return nullptr;
        }

        void* result = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            general_.totalAllocates++;
            if (head_ != nullptr) {
                SingleListEntry* entry = head_;
                head_ = entry->next;
                general_.depth--;
                result = entry;
            } else {
                general_.allocateMisses++;
            }
        }

        if (!result) {
            result = ExecutivePool::get().allocatePoolWithTag(
                PoolType::PagedPool,
                general_.size,
                general_.tag
            );
        }
        return result;
    }

    void free(void* entry) {
        if (!entry) return;

        if (ke::KeGetCurrentIrql() >= ke::DISPATCH_LEVEL) {
            std::cerr << "[MicaNT BugCheck] IRQL_NOT_LESS_OR_EQUAL: PagedLookasideList free at IRQL >= DISPATCH_LEVEL\n";
            return;
        }

        bool returnedToPool = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            general_.totalFrees++;
            if (general_.depth < general_.maximumDepth) {
                auto* listEntry = reinterpret_cast<SingleListEntry*>(entry);
                listEntry->next = head_;
                head_ = listEntry;
                general_.depth++;
            } else {
                general_.freeMisses++;
                returnedToPool = true;
            }
        }

        if (returnedToPool) {
            ExecutivePool::get().freePoolWithTag(entry, general_.tag);
        }
    }

    void flush() {
        std::vector<void*> toFree;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            SingleListEntry* current = head_;
            while (current) {
                toFree.push_back(current);
                current = current->next;
            }
            head_ = nullptr;
            general_.depth = 0;
        }

        for (void* ptr : toFree) {
            ExecutivePool::get().freePoolWithTag(ptr, general_.tag);
        }
    }

    ~PagedLookasideList() {
        flush();
    }

    [[nodiscard]] const GeneralLookaside& getStats() const noexcept { return general_; }

private:
    GeneralLookaside general_{};
    SingleListEntry* head_{nullptr};
    std::mutex mutex_{};
};

// C-style DDK exports
inline void ExInitializeNPagedLookasideList(NPagedLookasideList* lookaside, size_t size, uint32_t tag, uint16_t depth = 256) {
    if (lookaside) lookaside->initialize(size, tag, depth);
}

inline void ExDeleteNPagedLookasideList(NPagedLookasideList* lookaside) {
    if (lookaside) lookaside->flush();
}

inline void* ExAllocateFromNPagedLookasideList(NPagedLookasideList* lookaside) {
    return lookaside ? lookaside->allocate() : nullptr;
}

inline void ExFreeToNPagedLookasideList(NPagedLookasideList* lookaside, void* entry) {
    if (lookaside) lookaside->free(entry);
}

inline void ExInitializePagedLookasideList(PagedLookasideList* lookaside, size_t size, uint32_t tag, uint16_t depth = 256) {
    if (lookaside) lookaside->initialize(size, tag, depth);
}

inline void ExDeletePagedLookasideList(PagedLookasideList* lookaside) {
    if (lookaside) lookaside->flush();
}

inline void* ExAllocateFromPagedLookasideList(PagedLookasideList* lookaside) {
    return lookaside ? lookaside->allocate() : nullptr;
}

inline void ExFreeToPagedLookasideList(PagedLookasideList* lookaside, void* entry) {
    if (lookaside) lookaside->free(entry);
}

} // namespace micant::ex
