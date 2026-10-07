#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <vector>
#include <memory>
#include "ntdef.hpp"

namespace micant::mm {

// Standard Page Constants
inline constexpr size_t PageSize4KB   = 4096;
inline constexpr size_t PageShift4KB  = 12;
inline constexpr size_t PageMask4KB   = PageSize4KB - 1;

// Virtual Memory Allocation Types
inline constexpr uint32_t MEM_COMMIT      = 0x00001000;
inline constexpr uint32_t MEM_RESERVE     = 0x00002000;
inline constexpr uint32_t MEM_DECOMMIT    = 0x00004000;
inline constexpr uint32_t MEM_RELEASE     = 0x00008000;
inline constexpr uint32_t MEM_FREE        = 0x00010000;
inline constexpr uint32_t MEM_RESET       = 0x00080000;
inline constexpr uint32_t MEM_TOP_DOWN    = 0x00100000;
inline constexpr uint32_t MEM_LARGE_PAGES = 0x20000000;

// Memory Page Protection Constants
inline constexpr uint32_t PAGE_NOACCESS          = 0x01;
inline constexpr uint32_t PAGE_READONLY          = 0x02;
inline constexpr uint32_t PAGE_READWRITE         = 0x04;
inline constexpr uint32_t PAGE_WRITECOPY         = 0x08;
inline constexpr uint32_t PAGE_EXECUTE           = 0x10;
inline constexpr uint32_t PAGE_EXECUTE_READ      = 0x20;
inline constexpr uint32_t PAGE_EXECUTE_READWRITE = 0x40;
inline constexpr uint32_t PAGE_EXECUTE_WRITECOPY = 0x80;
inline constexpr uint32_t PAGE_GUARD             = 0x100;
inline constexpr uint32_t PAGE_NOCACHE           = 0x200;

/**
 * @brief x86-64 Hardware Page Table Entry (PTE).
 */
union PageTableEntry {
    uint64_t value{0};
    struct {
        uint64_t present : 1;
        uint64_t writable : 1;
        uint64_t user : 1;
        uint64_t writeThrough : 1;
        uint64_t cacheDisable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t largePage : 1;
        uint64_t global : 1;
        uint64_t available : 3;
        uint64_t pageFrameNumber : 40;
        uint64_t noExecute : 1;
    };

    [[nodiscard]] uintptr_t getPhysicalAddress() const noexcept {
        return static_cast<uintptr_t>(pageFrameNumber) << PageShift4KB;
    }
};

/**
 * @brief Virtual Address Descriptor (VAD).
 * Represents a contiguous range of committed or reserved virtual memory in a process.
 */
struct VirtualAddressDescriptor {
    uintptr_t startingAddress{0};
    uintptr_t endingAddress{0};
    uint32_t protection{PAGE_NOACCESS};
    uint32_t allocationType{MEM_RESERVE};
    bool committed{false};

    [[nodiscard]] size_t size() const noexcept {
        return endingAddress >= startingAddress ? (endingAddress - startingAddress + 1) : 0;
    }

    [[nodiscard]] bool contains(uintptr_t addr) const noexcept {
        return addr >= startingAddress && addr <= endingAddress;
    }
};

/**
 * @brief Memory Manager address space abstraction.
 */
class ProcessAddressSpace {
public:
    static constexpr uintptr_t UserSpaceMin = 0x0000000000010000ULL;
    static constexpr uintptr_t UserSpaceMax = 0x00007FFFFFFFFFFFULL;

    ProcessAddressSpace() : nextFreeAddress_(0x0000000100000000ULL) {}

    NtStatus allocate(uintptr_t& baseAddress, size_t size, uint32_t allocationType, uint32_t protect) {
        if (size == 0) return NtStatus::InvalidParameter;

        // Align size to page boundary
        size_t alignedSize = (size + PageMask4KB) & ~PageMask4KB;

        uintptr_t targetAddr = baseAddress;
        if (targetAddr == 0) {
            targetAddr = nextFreeAddress_;
            nextFreeAddress_ += alignedSize + PageSize4KB; // Guard page spacing
        }

        VirtualAddressDescriptor vad{
            .startingAddress = targetAddr,
            .endingAddress = targetAddr + alignedSize - 1,
            .protection = protect,
            .allocationType = allocationType,
            .committed = (allocationType & MEM_COMMIT) != 0
        };

        vads_.push_back(vad);
        baseAddress = targetAddr;
        return NtStatus::Success;
    }

    NtStatus free(uintptr_t baseAddress, size_t size, uint32_t freeType) {
        for (auto it = vads_.begin(); it != vads_.end(); ++it) {
            if (it->startingAddress == baseAddress) {
                if (freeType & MEM_RELEASE) {
                    vads_.erase(it);
                    return NtStatus::Success;
                } else if (freeType & MEM_DECOMMIT) {
                    it->committed = false;
                    return NtStatus::Success;
                }
            }
        }
        return NtStatus::InvalidParameter;
    }

    [[nodiscard]] size_t getRegionCount() const noexcept { return vads_.size(); }

    [[nodiscard]] VirtualAddressDescriptor* findVad(uintptr_t addr) noexcept {
        for (auto& vad : vads_) {
            if (vad.contains(addr)) return &vad;
        }
        return nullptr;
    }

    [[nodiscard]] const VirtualAddressDescriptor* findVad(uintptr_t addr) const noexcept {
        for (const auto& vad : vads_) {
            if (vad.contains(addr)) return &vad;
        }
        return nullptr;
    }

private:
    uintptr_t nextFreeAddress_;
    std::vector<VirtualAddressDescriptor> vads_;
};

} // namespace micant::mm
