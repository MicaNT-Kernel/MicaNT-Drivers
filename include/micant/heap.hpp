#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <mutex>
#include <algorithm>
#include <cstring>
#include "ntdef.hpp"
#include "ntstatus.hpp"

namespace micant::heap {

// Win32 / NT Heap Flags (Reference: win32metadata)
inline constexpr uint32_t HEAP_NO_SERIALIZE          = 0x00000001;
inline constexpr uint32_t HEAP_GROWABLE              = 0x00000002;
inline constexpr uint32_t HEAP_GENERATE_EXCEPTIONS   = 0x00000004;
inline constexpr uint32_t HEAP_ZERO_MEMORY           = 0x00000008;
inline constexpr uint32_t HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010;

// Chunk Flags
inline constexpr uint16_t CHUNK_BUSY = 0x0001;
inline constexpr uint16_t CHUNK_LAST = 0x0002;
inline constexpr uint32_t HEAP_MAGIC = 0x48454150; // 'HEAP'

/**
 * @brief 16-byte aligned Userland Heap Chunk Header.
 */
struct alignas(16) HeapChunk {
    uint32_t size{0};          // Total chunk size including header in bytes (multiple of 16)
    uint32_t previousSize{0};  // Total chunk size of previous adjacent chunk in bytes (0 if first)
    uint16_t flags{0};         // CHUNK_BUSY, CHUNK_LAST
    uint16_t unusedBytes{0};   // Extra alignment bytes beyond requested payload
    uint32_t magic{HEAP_MAGIC};// Safety cookie for heap corruption detection
};

static_assert(sizeof(HeapChunk) == 16, "HeapChunk header must be exactly 16 bytes for 16-byte alignment");

/**
 * @brief Telemetry and diagnostic counters for Userland Heap.
 */
struct HeapTelemetry {
    uint64_t totalAllocates{0};
    uint64_t activeAllocates{0};
    uint64_t totalFrees{0};
    uint64_t currentBytesAllocated{0};
    uint64_t peakBytesAllocated{0};
    uint64_t coalesceCount{0};
    size_t segmentCount{0};
};

/**
 * @brief Userland Heap Segment representing a contiguous memory block.
 */
class HeapSegment {
public:
    explicit HeapSegment(size_t size)
        : size_((size + 15) & ~size_t(15)), storage_(size_, 0) {
        auto* initialChunk = getFirstChunk();
        initialChunk->size = static_cast<uint32_t>(size_);
        initialChunk->previousSize = 0;
        initialChunk->flags = CHUNK_LAST;
        initialChunk->unusedBytes = 0;
        initialChunk->magic = HEAP_MAGIC;
    }

    [[nodiscard]] size_t getSize() const noexcept { return size_; }
    [[nodiscard]] uint8_t* getData() noexcept { return storage_.data(); }
    [[nodiscard]] const uint8_t* getData() const noexcept { return storage_.data(); }

    [[nodiscard]] HeapChunk* getFirstChunk() noexcept {
        return reinterpret_cast<HeapChunk*>(storage_.data());
    }

    [[nodiscard]] bool contains(const void* ptr) const noexcept {
        const auto* bytePtr = reinterpret_cast<const uint8_t*>(ptr);
        return bytePtr >= storage_.data() && bytePtr < (storage_.data() + size_);
    }

private:
    size_t size_;
    std::vector<uint8_t> storage_;
};

/**
 * @brief Clean-room NT Userland Heap Manager (ntdll!RtlHeap implementation).
 */
class UserHeap {
public:
    explicit UserHeap(uint32_t flags = HEAP_GROWABLE, size_t defaultCommitSize = 64 * 1024)
        : flags_(flags), defaultCommitSize_(defaultCommitSize ? defaultCommitSize : 64 * 1024) {
        addSegment(defaultCommitSize_);
    }

    ~UserHeap() {
        destroy();
    }

    // Disable copy
    UserHeap(const UserHeap&) = delete;
    UserHeap& operator=(const UserHeap&) = delete;

    [[nodiscard]] void* allocate(size_t userBytes, uint32_t allocFlags = 0) {
        std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
        if (!(flags_ & HEAP_NO_SERIALIZE) && !(allocFlags & HEAP_NO_SERIALIZE)) {
            lock.lock();
        }

        if (userBytes == 0) userBytes = 1;

        // Calculate chunk size: header (16 bytes) + aligned payload (multiple of 16)
        size_t alignedPayload = (userBytes + 15) & ~size_t(15);
        size_t needed = sizeof(HeapChunk) + alignedPayload;
        if (needed < 32) needed = 32;

        HeapChunk* chosen = findFreeChunk(needed);
        if (!chosen) {
            // Need heap growth
            if ((flags_ & HEAP_GROWABLE) || (allocFlags & HEAP_GROWABLE)) {
                size_t segSize = std::max(defaultCommitSize_, needed + sizeof(HeapChunk) + 4096);
                if (addSegment(segSize)) {
                    chosen = findFreeChunk(needed);
                }
            }
        }

        if (!chosen) {
            return nullptr;
        }

        // Chunk splitting
        size_t excess = chosen->size - needed;
        if (excess >= 32) {
            auto* remainder = reinterpret_cast<HeapChunk*>(reinterpret_cast<uint8_t*>(chosen) + needed);
            remainder->size = static_cast<uint32_t>(excess);
            remainder->previousSize = static_cast<uint32_t>(needed);
            remainder->flags = chosen->flags & CHUNK_LAST;
            remainder->unusedBytes = 0;
            remainder->magic = HEAP_MAGIC;

            if (!(remainder->flags & CHUNK_LAST)) {
                auto* subsequent = reinterpret_cast<HeapChunk*>(reinterpret_cast<uint8_t*>(remainder) + remainder->size);
                subsequent->previousSize = remainder->size;
            }

            chosen->size = static_cast<uint32_t>(needed);
            chosen->flags = CHUNK_BUSY; // Not last anymore

            // Replace chosen with remainder in free list
            for (auto& item : freeList_) {
                if (item == chosen) {
                    item = remainder;
                    break;
                }
            }
        } else {
            chosen->flags |= CHUNK_BUSY;
            std::erase(freeList_, chosen);
        }

        chosen->unusedBytes = static_cast<uint16_t>(chosen->size - sizeof(HeapChunk) - userBytes);

        void* userPtr = reinterpret_cast<uint8_t*>(chosen) + sizeof(HeapChunk);

        if ((flags_ & HEAP_ZERO_MEMORY) || (allocFlags & HEAP_ZERO_MEMORY)) {
            std::memset(userPtr, 0, userBytes);
        }

        telemetry_.totalAllocates++;
        telemetry_.activeAllocates++;
        telemetry_.currentBytesAllocated += userBytes;
        telemetry_.peakBytesAllocated = std::max(telemetry_.peakBytesAllocated, telemetry_.currentBytesAllocated);

        return userPtr;
    }

    bool free(void* userPtr, uint32_t freeFlags = 0) {
        if (!userPtr) return false;

        std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
        if (!(flags_ & HEAP_NO_SERIALIZE) && !(freeFlags & HEAP_NO_SERIALIZE)) {
            lock.lock();
        }

        auto* chunk = reinterpret_cast<HeapChunk*>(reinterpret_cast<uint8_t*>(userPtr) - sizeof(HeapChunk));
        if (chunk->magic != HEAP_MAGIC || !(chunk->flags & CHUNK_BUSY)) {
            return false; // Heap corruption or double free
        }

        size_t userBytes = chunk->size - sizeof(HeapChunk) - chunk->unusedBytes;
        chunk->flags &= ~CHUNK_BUSY;

        telemetry_.totalFrees++;
        if (telemetry_.activeAllocates > 0) telemetry_.activeAllocates--;
        if (telemetry_.currentBytesAllocated >= userBytes) {
            telemetry_.currentBytesAllocated -= userBytes;
        }

        // Backward coalescing
        bool mergedWithPrev = false;
        if (chunk->previousSize > 0) {
            auto* prev = reinterpret_cast<HeapChunk*>(reinterpret_cast<uint8_t*>(chunk) - chunk->previousSize);
            if (prev->magic == HEAP_MAGIC && !(prev->flags & CHUNK_BUSY)) {
                prev->size += chunk->size;
                prev->flags |= (chunk->flags & CHUNK_LAST);
                if (!(prev->flags & CHUNK_LAST)) {
                    auto* next = reinterpret_cast<HeapChunk*>(reinterpret_cast<uint8_t*>(prev) + prev->size);
                    next->previousSize = prev->size;
                }
                chunk = prev;
                mergedWithPrev = true;
                telemetry_.coalesceCount++;
            }
        }

        // Forward coalescing
        if (!(chunk->flags & CHUNK_LAST)) {
            auto* next = reinterpret_cast<HeapChunk*>(reinterpret_cast<uint8_t*>(chunk) + chunk->size);
            if (next->magic == HEAP_MAGIC && !(next->flags & CHUNK_BUSY)) {
                chunk->size += next->size;
                chunk->flags |= (next->flags & CHUNK_LAST);
                if (!(chunk->flags & CHUNK_LAST)) {
                    auto* nextNext = reinterpret_cast<HeapChunk*>(reinterpret_cast<uint8_t*>(chunk) + chunk->size);
                    nextNext->previousSize = chunk->size;
                }
                std::erase(freeList_, next);
                telemetry_.coalesceCount++;
            }
        }

        if (!mergedWithPrev) {
            freeList_.push_back(chunk);
        }

        return true;
    }

    [[nodiscard]] size_t getSize(const void* userPtr) const {
        if (!userPtr) return 0;
        const auto* chunk = reinterpret_cast<const HeapChunk*>(reinterpret_cast<const uint8_t*>(userPtr) - sizeof(HeapChunk));
        if (chunk->magic != HEAP_MAGIC || !(chunk->flags & CHUNK_BUSY)) {
            return 0;
        }
        return chunk->size - sizeof(HeapChunk) - chunk->unusedBytes;
    }

    void* reallocate(void* userPtr, size_t newBytes, uint32_t reallocFlags = 0) {
        if (!userPtr) return allocate(newBytes, reallocFlags);
        if (newBytes == 0) {
            free(userPtr, reallocFlags);
            return nullptr;
        }

        size_t currentSize = getSize(userPtr);
        if (newBytes <= currentSize) {
            return userPtr; // Fits in place
        }

        if (reallocFlags & HEAP_REALLOC_IN_PLACE_ONLY) {
            return nullptr;
        }

        void* newPtr = allocate(newBytes, reallocFlags);
        if (!newPtr) return nullptr;

        std::memcpy(newPtr, userPtr, std::min(currentSize, newBytes));
        free(userPtr, reallocFlags);
        return newPtr;
    }

    void destroy() {
        std::lock_guard<std::mutex> lock(mutex_);
        freeList_.clear();
        segments_.clear();
        telemetry_ = {};
    }

    [[nodiscard]] const HeapTelemetry& getTelemetry() const noexcept {
        return telemetry_;
    }

private:
    bool addSegment(size_t size) {
        auto seg = std::make_unique<HeapSegment>(size);
        freeList_.push_back(seg->getFirstChunk());
        segments_.push_back(std::move(seg));
        telemetry_.segmentCount = segments_.size();
        return true;
    }

    HeapChunk* findFreeChunk(size_t needed) {
        HeapChunk* best = nullptr;
        for (auto* chunk : freeList_) {
            if (chunk->size >= needed) {
                if (!best || chunk->size < best->size) {
                    best = chunk;
                    if (best->size == needed) break; // Perfect match
                }
            }
        }
        return best;
    }

    uint32_t flags_;
    size_t defaultCommitSize_;
    std::mutex mutex_;
    std::vector<std::unique_ptr<HeapSegment>> segments_;
    std::vector<HeapChunk*> freeList_;
    HeapTelemetry telemetry_{};
};

// ============================================================================
// NTDLL Public Heap API Functions (Rtl* Heap Family)
// ============================================================================

inline void* RtlCreateHeap(
    uint32_t flags,
    void* /*heapBase*/ = nullptr,
    size_t reserveSize = 0,
    size_t commitSize = 0,
    void* /*lock*/ = nullptr,
    void* /*parameters*/ = nullptr
) {
    if (reserveSize == 0 || (flags & HEAP_GROWABLE)) {
        flags |= HEAP_GROWABLE;
    }
    size_t initialSize = commitSize ? commitSize : (reserveSize ? reserveSize : 64 * 1024);
    auto heap = std::make_unique<UserHeap>(flags, initialSize);
    return heap.release();
}

inline void* RtlAllocateHeap(void* heapHandle, uint32_t flags, size_t size) {
    if (!heapHandle) return nullptr;
    auto* heap = reinterpret_cast<UserHeap*>(heapHandle);
    return heap->allocate(size, flags);
}

inline bool RtlFreeHeap(void* heapHandle, uint32_t flags, void* baseAddress) {
    if (!heapHandle || !baseAddress) return false;
    auto* heap = reinterpret_cast<UserHeap*>(heapHandle);
    return heap->free(baseAddress, flags);
}

inline void* RtlDestroyHeap(void* heapHandle) {
    if (!heapHandle) return nullptr;
    auto* heap = reinterpret_cast<UserHeap*>(heapHandle);
    delete heap;
    return nullptr;
}

inline size_t RtlSizeHeap(void* heapHandle, uint32_t flags, const void* baseAddress) {
    if (!heapHandle || !baseAddress) return 0;
    const auto* heap = reinterpret_cast<const UserHeap*>(heapHandle);
    return heap->getSize(baseAddress);
}

inline void* RtlReAllocateHeap(void* heapHandle, uint32_t flags, void* baseAddress, size_t size) {
    if (!heapHandle) return nullptr;
    auto* heap = reinterpret_cast<UserHeap*>(heapHandle);
    return heap->reallocate(baseAddress, size, flags);
}

} // namespace micant::heap
