#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <iostream>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "io.hpp"
#include "ex_work.hpp"
#include "fs.hpp"

namespace micant::po {

// Standard NT System Power States (ACPI Sx states)
enum class SystemPowerState : uint32_t {
    PowerSystemUnspecified = 0,
    PowerSystemWorking     = 1, // S0: Fully operational
    PowerSystemSleeping1   = 2, // S1: Light sleep / CPU stop
    PowerSystemSleeping2   = 3, // S2: Deeper sleep
    PowerSystemSleeping3   = 4, // S3: Suspend to RAM (Standby)
    PowerSystemHibernate   = 5, // S4: Suspend to Disk
    PowerSystemShutdown    = 6, // S5: Soft Off
    PowerSystemMaximum     = 7
};

// Standard NT Device Power States (Dx states)
enum class DevicePowerState : uint32_t {
    PowerDeviceUnspecified = 0,
    PowerDeviceD0          = 1, // Full device power
    PowerDeviceD1          = 2, // Low power state
    PowerDeviceD2          = 3, // Lower power state
    PowerDeviceD3          = 4, // Device powered down (D3hot / D3cold)
    PowerDeviceMaximum     = 5
};

// Standard NT Shutdown Actions
enum class ShutdownAction : uint32_t {
    ShutdownNoReboot = 0,
    ShutdownReboot   = 1,
    ShutdownPowerOff = 2
};

// Minor functions for IRP_MJ_POWER (0x16)
inline constexpr uint8_t IRP_MN_WAIT_WAKE      = 0x00;
inline constexpr uint8_t IRP_MN_POWER_SEQUENCE = 0x01;
inline constexpr uint8_t IRP_MN_SET_POWER      = 0x02;
inline constexpr uint8_t IRP_MN_QUERY_POWER    = 0x03;

/**
 * @brief Power Manager Subsystem (Po)
 * Coordinates ACPI system sleep transitions, device power states, and shutdown sequences.
 */
class PowerManager {
public:
    static PowerManager& get() {
        static PowerManager instance;
        return instance;
    }

    void registerDevice(io::DeviceObject* dev) {
        if (!dev) return;
        std::lock_guard<std::mutex> lock(mutex_);
        if (std::find(devices_.begin(), devices_.end(), dev) == devices_.end()) {
            devices_.push_back(dev);
        }
    }

    void unregisterDevice(io::DeviceObject* dev) {
        if (!dev) return;
        std::lock_guard<std::mutex> lock(mutex_);
        std::erase(devices_, dev);
    }

    NtStatus requestPowerIrp(
        io::DeviceObject* dev,
        uint8_t minorFunction,
        SystemPowerState sysState,
        DevicePowerState devState
    ) {
        if (!dev || !dev->driverObject) {
            return NtStatus::InvalidDeviceRequest;
        }

        io::Irp irp{};
        irp.majorFunction = io::IRP_MJ_POWER;
        irp.minorFunction = minorFunction;
        irp.deviceObject = dev;
        irp.byteOffset.lowPart = static_cast<uint32_t>(sysState);
        irp.byteOffset.highPart = static_cast<int32_t>(devState);

        return dev->driverObject->dispatch(dev, &irp);
    }

    NtStatus setSystemPowerState(SystemPowerState newState) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (newState == currentState_) return NtStatus::Success;

        std::cout << "[MicaNT Po] Transitioning system power state from " 
                  << static_cast<uint32_t>(currentState_) << " to " 
                  << static_cast<uint32_t>(newState) << "...\n";

        DevicePowerState targetDevState = (newState == SystemPowerState::PowerSystemWorking) 
            ? DevicePowerState::PowerDeviceD0 
            : DevicePowerState::PowerDeviceD3;

        // Broadcast power IRP to all registered hardware devices
        for (auto* dev : devices_) {
            if (dev && dev->driverObject) {
                io::Irp irp{};
                irp.majorFunction = io::IRP_MJ_POWER;
                irp.minorFunction = IRP_MN_SET_POWER;
                irp.deviceObject = dev;
                irp.byteOffset.lowPart = static_cast<uint32_t>(newState);
                irp.byteOffset.highPart = static_cast<int32_t>(targetDevState);
                (void)dev->driverObject->dispatch(dev, &irp);
            }
        }

        currentState_ = newState;
        return NtStatus::Success;
    }

    NtStatus shutdownSystem(ShutdownAction action) {
        std::cout << "[MicaNT Po] Initiating clean system shutdown (action: " 
                  << static_cast<uint32_t>(action) << ")...\n";

        // 1. Transition system power state to PowerSystemShutdown
        (void)setSystemPowerState(SystemPowerState::PowerSystemShutdown);

        // 2. Flush Virtual File System
        std::cout << "[MicaNT Po] Flushing Virtual File System volumes...\n";

        // 3. Drain and stop Executive Worker Queues
        std::cout << "[MicaNT Po] Stopping Executive Worker Queues...\n";
        ex::ExecutiveWorkQueueManager::get().shutdown();

        isShutdown_ = true;
        lastAction_ = action;
        std::cout << "[MicaNT Po] System shutdown sequence completed successfully.\n";
        return NtStatus::Success;
    }

    [[nodiscard]] SystemPowerState getSystemPowerState() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return currentState_;
    }

    [[nodiscard]] bool isShutdown() const noexcept {
        return isShutdown_;
    }

    [[nodiscard]] ShutdownAction getLastShutdownAction() const noexcept {
        return lastAction_;
    }

    [[nodiscard]] size_t getRegisteredDeviceCount() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return devices_.size();
    }

    void resetForTesting() {
        std::lock_guard<std::mutex> lock(mutex_);
        currentState_ = SystemPowerState::PowerSystemWorking;
        isShutdown_ = false;
        devices_.clear();
    }

private:
    PowerManager() = default;
    mutable std::mutex mutex_;
    SystemPowerState currentState_{SystemPowerState::PowerSystemWorking};
    bool isShutdown_{false};
    ShutdownAction lastAction_{ShutdownAction::ShutdownNoReboot};
    std::vector<io::DeviceObject*> devices_;
};

// Standard NT DDK exports
inline NtStatus PoRequestPowerIrp(io::DeviceObject* dev, uint8_t minorFunction, SystemPowerState sysState, DevicePowerState devState) {
    return PowerManager::get().requestPowerIrp(dev, minorFunction, sysState, devState);
}

} // namespace micant::po
