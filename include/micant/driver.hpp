#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <memory>
#include <unordered_map>
#include <mutex>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "io.hpp"

namespace micant::driver {

// Standard NT IOCTL Transfer Methods
inline constexpr uint32_t METHOD_BUFFERED   = 0;
inline constexpr uint32_t METHOD_IN_DIRECT  = 1;
inline constexpr uint32_t METHOD_OUT_DIRECT = 2;
inline constexpr uint32_t METHOD_NEITHER    = 3;

// Standard NT IOCTL Required Access Masks
inline constexpr uint32_t FILE_ANY_ACCESS     = 0;
inline constexpr uint32_t FILE_READ_ACCESS    = 1;
inline constexpr uint32_t FILE_WRITE_ACCESS   = 2;

/**
 * @brief Standard NT CTL_CODE macro evaluated constexpr.
 * Constructs a 32-bit Device I/O Control code.
 */
[[nodiscard]] constexpr uint32_t CTL_CODE(
    uint32_t deviceType,
    uint32_t function,
    uint32_t method,
    uint32_t access
) noexcept {
    return (deviceType << 16) | (access << 14) | (function << 2) | method;
}

// Standard Driver Callback Types
using DriverEntryRoutine = NtStatus (*)(io::DriverObject* driverObject, const UnicodeString* registryPath);
using DriverUnloadRoutine = void (*)(io::DriverObject* driverObject);

/**
 * @brief Kernel Driver Manager
 * Manages the lifecycle of loaded Ring 0 device drivers in MicaNT.
 */
class DriverManager {
public:
    static DriverManager& get() {
        static DriverManager instance;
        return instance;
    }

    NtStatus loadDriver(
        std::wstring_view driverName,
        DriverEntryRoutine entryPoint,
        std::wstring_view registryPath = L""
    ) {
        if (!entryPoint) return NtStatus::InvalidParameter;

        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring name(driverName);
        if (drivers_.contains(name)) {
            return NtStatus::ObjectNameCollision;
        }

        auto driverObj = std::make_unique<io::DriverObject>();
        driverObj->driverName = name;

        // Populate standard default dispatch routines
        driverObj->setDispatch(io::IRP_MJ_CREATE, [](io::DeviceObject* dev, io::Irp* irp) -> NtStatus {
            (void)dev;
            if (irp) {
                irp->ioStatus.status = NtStatus::Success;
                irp->ioStatus.information = 1; // FILE_OPENED
            }
            return NtStatus::Success;
        });

        driverObj->setDispatch(io::IRP_MJ_CLOSE, [](io::DeviceObject* dev, io::Irp* irp) -> NtStatus {
            (void)dev;
            if (irp) irp->ioStatus.status = NtStatus::Success;
            return NtStatus::Success;
        });

        // Prepare UnicodeString registry path for DriverEntry
        UnicodeString regPathUnicode(registryPath.empty() ? L"\\Registry\\Machine\\System\\CurrentControlSet\\Services" : registryPath.data());

        // Invoke the driver's DriverEntry routine
        NtStatus status = entryPoint(driverObj.get(), &regPathUnicode);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        drivers_[name] = std::move(driverObj);
        return NtStatus::Success;
    }

    [[nodiscard]] io::DriverObject* lookupDriver(std::wstring_view driverName) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = drivers_.find(std::wstring(driverName));
        if (it != drivers_.end()) {
            return it->second.get();
        }
        return nullptr;
    }

    [[nodiscard]] size_t getLoadedDriverCount() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return drivers_.size();
    }

private:
    DriverManager() = default;
    mutable std::mutex mutex_;
    std::unordered_map<std::wstring, std::unique_ptr<io::DriverObject>> drivers_;
};

} // namespace micant::driver
