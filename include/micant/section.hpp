#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ob.hpp"
#include "mm.hpp"
#include "ps.hpp"

namespace micant::section {

// Section Allocation Attributes
inline constexpr uint32_t SEC_FILE           = 0x00800000;
inline constexpr uint32_t SEC_IMAGE          = 0x01000000;
inline constexpr uint32_t SEC_PROTECTED_IMAGE= 0x02000000;
inline constexpr uint32_t SEC_RESERVE        = 0x04000000;
inline constexpr uint32_t SEC_COMMIT         = 0x08000000;
inline constexpr uint32_t SEC_NOCACHE        = 0x10000000;
inline constexpr uint32_t SEC_WRITECOMBINE   = 0x40000000;
inline constexpr uint32_t SEC_LARGE_PAGES    = 0x80000000;

// Section View Inherit Options
enum class ViewShare : uint32_t {
    ViewShare = 1,
    ViewUnmap = 2
};

/**
 * @brief Section Object representing shared memory or mapped image backing.
 */
class SectionObject {
public:
    SectionObject(size_t maximumSize, uint32_t allocationAttributes, uint32_t pageProtection)
        : maximumSize_(maximumSize), allocationAttributes_(allocationAttributes), pageProtection_(pageProtection) {
        // Backing storage buffer for memory-backed sections
        data_.resize(maximumSize_, 0);
    }

    [[nodiscard]] size_t getSize() const noexcept { return maximumSize_; }
    [[nodiscard]] uint32_t getAllocationAttributes() const noexcept { return allocationAttributes_; }
    [[nodiscard]] uint32_t getPageProtection() const noexcept { return pageProtection_; }

    [[nodiscard]] uint8_t* getData() noexcept { return data_.data(); }
    [[nodiscard]] const uint8_t* getData() const noexcept { return data_.data(); }

    void loadData(const void* src, size_t size) {
        if (!src || size == 0) return;
        size_t copySize = (size < maximumSize_) ? size : maximumSize_;
        std::memcpy(data_.data(), src, copySize);
    }

private:
    size_t maximumSize_{0};
    uint32_t allocationAttributes_{0};
    uint32_t pageProtection_{0};
    std::vector<uint8_t> data_;
};

/**
 * @brief Section Manager handling NtCreateSection and NtMapViewOfSection.
 */
class SectionManager {
public:
    static SectionManager& get() {
        static SectionManager instance;
        return instance;
    }

    NtStatus createSection(
        Handle& outSectionHandle,
        ob::HandleTable& handleTable,
        size_t maximumSize,
        uint32_t allocationAttributes,
        uint32_t pageProtection,
        std::shared_ptr<SectionObject>& outSection
    ) {
        if (maximumSize == 0) {
            return NtStatus::InvalidParameter;
        }

        outSection = std::make_shared<SectionObject>(maximumSize, allocationAttributes, pageProtection);
        
        // Wrap in ObjectHeader
        auto header = std::make_unique<ob::ObjectHeader>();
        header->objectName = L"\\BaseNamedObjects\\Section";
        
        NtStatus status = handleTable.createHandle(header.get(), outSectionHandle);
        if (NT_SUCCESS(status)) {
            // Retain reference
            header.release();
        }
        return status;
    }

    NtStatus mapViewOfSection(
        std::shared_ptr<SectionObject> section,
        ps::EProcess& targetProcess,
        uintptr_t& baseAddress,
        size_t& viewSize,
        uint32_t allocationType,
        uint32_t protect
    ) {
        if (!section) return NtStatus::InvalidHandle;

        if (viewSize == 0 || viewSize > section->getSize()) {
            viewSize = section->getSize();
        }

        // Allocate memory view in target process address space
        NtStatus status = targetProcess.getAddressSpace().allocate(
            baseAddress,
            viewSize,
            allocationType ? allocationType : (mm::MEM_COMMIT | mm::MEM_RESERVE),
            protect ? protect : section->getPageProtection()
        );

        return status;
    }

    NtStatus unmapViewOfSection(ps::EProcess& targetProcess, uintptr_t baseAddress) {
        return targetProcess.getAddressSpace().free(baseAddress, 0, mm::MEM_RELEASE);
    }

private:
    SectionManager() = default;
};

} // namespace micant::section
