#pragma once

#include <cstdint>
#include "ntdef.hpp"
#include "ntstatus.hpp"

namespace micant::mm {

// Standard AMD64 Canonical User-Mode Address Limit (0x00007FFFFFFFFFFF)
inline constexpr uintptr_t MM_HIGHEST_USER_ADDRESS = 0x00007FFFFFFFFFFFULL;

/**
 * @brief Validates that a user-mode buffer is completely within user address space
 * and properly aligned.
 */
inline NtStatus ProbeForRead(const void* address, size_t length, uint32_t alignment) noexcept {
    if (length == 0) return NtStatus::Success;
    if (!address) return NtStatus::AccessViolation;

    uintptr_t addr = reinterpret_cast<uintptr_t>(address);

    // Alignment check (alignment must be a power of 2)
    if (alignment > 1 && (addr & (alignment - 1)) != 0) {
        return NtStatus::DatatypeMisalignment;
    }

    // Range overflow check
    if (addr + length < addr) {
        return NtStatus::AccessViolation;
    }

    // Must be strictly within user-mode address space
    if (addr + length > MM_HIGHEST_USER_ADDRESS) {
        return NtStatus::AccessViolation;
    }

    return NtStatus::Success;
}

/**
 * @brief Validates that a user-mode buffer is within user space, aligned, and writable.
 */
inline NtStatus ProbeForWrite(void* address, size_t length, uint32_t alignment) noexcept {
    return ProbeForRead(address, length, alignment);
}

} // namespace micant::mm
