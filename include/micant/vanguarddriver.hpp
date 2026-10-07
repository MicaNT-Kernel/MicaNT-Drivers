// ============================================================================
// MicaNT: VanguardDriver - Sovereign Driver Framework & Device Subsystem
//
// Named in honor of the vanguard kernel engineering principles established
// during the DEC Alpha and Windows NT layered driver architecture evolutions.
//
// Strict Clean-Room Implementation in modern ISO C++23.
// Compatible with Windows Driver Model (WDM) & KMDF specifications.
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "io.hpp"
#include "driver.hpp"
#include "prismx.hpp" // for GUID
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <functional>

namespace micant::vanguarddriver {

using namespace micant::io;

// ============================================================================
// 1. PnP Minor Function Codes
// ============================================================================

inline constexpr uint8_t IRP_MN_START_DEVICE                 = 0x00;
inline constexpr uint8_t IRP_MN_QUERY_REMOVE_DEVICE          = 0x01;
inline constexpr uint8_t IRP_MN_REMOVE_DEVICE                = 0x02;
inline constexpr uint8_t IRP_MN_CANCEL_REMOVE_DEVICE         = 0x03;
inline constexpr uint8_t IRP_MN_STOP_DEVICE                  = 0x04;
inline constexpr uint8_t IRP_MN_QUERY_STOP_DEVICE            = 0x05;
inline constexpr uint8_t IRP_MN_CANCEL_STOP_DEVICE           = 0x06;
inline constexpr uint8_t IRP_MN_QUERY_DEVICE_RELATIONS       = 0x07;
inline constexpr uint8_t IRP_MN_QUERY_INTERFACE              = 0x08;
inline constexpr uint8_t IRP_MN_QUERY_CAPABILITIES           = 0x09;
inline constexpr uint8_t IRP_MN_QUERY_RESOURCE_REQUIREMENTS  = 0x0B;
inline constexpr uint8_t IRP_MN_SURPRISE_REMOVAL             = 0x17;

// Power Minor Function Codes
inline constexpr uint8_t IRP_MN_WAIT_WAKE                    = 0x00;
inline constexpr uint8_t IRP_MN_POWER_SEQUENCE               = 0x01;
inline constexpr uint8_t IRP_MN_SET_POWER                    = 0x02;
inline constexpr uint8_t IRP_MN_QUERY_POWER                  = 0x03;

// Device Power State
enum class DevicePowerState : uint32_t {
    PowerDeviceUnspecified = 0,
    PowerDeviceD0, // Full On
    PowerDeviceD1,
    PowerDeviceD2,
    PowerDeviceD3  // Off
};

// PnP Device Lifecycle States
enum class PnpDeviceState : uint32_t {
    Uninitialized = 0,
    Initialized,
    Starting,
    Started,
    StopPending,
    Stopped,
    RemovePending,
    Removed,
    SurpriseRemoved
};

// ============================================================================
// 2. Standard Device Interface Class GUIDs
// ============================================================================

inline constexpr GUID GUID_DEVINTERFACE_DISK = {
    0x53f56307, 0xb6bf, 0x11d0, { 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b }
};

inline constexpr GUID GUID_DEVINTERFACE_DISPLAY_ADAPTER = {
    0x5b45201d, 0xf2f2, 0x4f3b, { 0x85, 0xbb, 0x30, 0xff, 0x1f, 0x95, 0x35, 0x99 }
};

inline constexpr GUID GUID_DEVINTERFACE_AUDIO = {
    0x6994ad04, 0x93ef, 0x11d0, { 0xa3, 0xcc, 0x00, 0xa0, 0xc9, 0x22, 0x31, 0x96 }
};

inline constexpr GUID GUID_DEVINTERFACE_KEYBOARD = {
    0x884b96c3, 0x56ef, 0x11d1, { 0xbc, 0x8c, 0x00, 0xa0, 0xc9, 0x14, 0x05, 0xdd }
};

inline constexpr GUID GUID_DEVINTERFACE_MOUSE = {
    0x378de44c, 0x56ef, 0x11d1, { 0xbc, 0x8c, 0x00, 0xa0, 0xc9, 0x14, 0x05, 0xdd }
};

// ============================================================================
// 3. Layered Device Stack Helper Functions
// ============================================================================

/**
 * @brief Traverses the attachedDevice chain up to the top of the stack.
 */
inline DeviceObject* IoGetAttachedDevice(DeviceObject* device) {
    if (!device) return nullptr;
    DeviceObject* current = device;
    while (current->attachedDevice != nullptr) {
        current = current->attachedDevice;
    }
    return current;
}

/**
 * @brief Attaches sourceDevice to the top of the stack containing targetDevice.
 * @return The device object to which sourceDevice was attached (lower device).
 */
inline DeviceObject* IoAttachDeviceToDeviceStack(DeviceObject* sourceDevice, DeviceObject* targetDevice) {
    if (!sourceDevice || !targetDevice) return nullptr;

    DeviceObject* top = IoGetAttachedDevice(targetDevice);
    top->attachedDevice = sourceDevice;
    return top;
}

/**
 * @brief Detaches the sourceDevice from targetDevice's attachment chain.
 */
inline void IoDetachDevice(DeviceObject* targetDevice) {
    if (!targetDevice) return;
    targetDevice->attachedDevice = nullptr;
}

/**
 * @brief Forwards an IRP down or directly to a target device object.
 */
inline NtStatus IoCallDriver(DeviceObject* targetDevice, Irp* irp) {
    if (!targetDevice || !targetDevice->driverObject || !irp) {
        return NtStatus::InvalidParameter;
    }
    return targetDevice->driverObject->dispatch(targetDevice, irp);
}

// ============================================================================
// 4. Vanguard PnP Device Node & Interface Registry
// ============================================================================

struct DeviceInterfaceEntry {
    GUID interfaceClassGuid{};
    std::wstring symbolicLink;
    std::wstring referenceString;
    DeviceObject* pdo{nullptr};
    bool isEnabled{false};
};

class PnpDeviceNode {
public:
    PnpDeviceNode(std::wstring_view deviceId, DeviceObject* pdo)
        : m_deviceId(deviceId), m_pdo(pdo), m_state(PnpDeviceState::Initialized) {}

    const std::wstring& GetDeviceId() const { return m_deviceId; }
    DeviceObject* GetPdo() const { return m_pdo; }
    DeviceObject* GetFdo() const { return m_fdo; }
    void SetFdo(DeviceObject* fdo) { m_fdo = fdo; }

    PnpDeviceState GetState() const { return m_state; }
    void SetState(PnpDeviceState s) { m_state = s; }

    DevicePowerState GetPowerState() const { return m_powerState; }
    void SetPowerState(DevicePowerState s) { m_powerState = s; }

    void AddChild(std::shared_ptr<PnpDeviceNode> child) {
        m_children.push_back(std::move(child));
    }

    const std::vector<std::shared_ptr<PnpDeviceNode>>& GetChildren() const {
        return m_children;
    }

    /**
     * @brief Dispatches a PnP IRP to the top of this device node's stack.
     */
    NtStatus DispatchPnp(uint8_t minorFunction) {
        if (!m_pdo) return NtStatus::InvalidDeviceRequest;

        DeviceObject* topDevice = IoGetAttachedDevice(m_pdo);
        Irp irp{};
        irp.majorFunction = IRP_MJ_PNP;
        irp.minorFunction = minorFunction;
        irp.deviceObject = topDevice;

        return IoCallDriver(topDevice, &irp);
    }

    /**
     * @brief Dispatches a Power state transition IRP to this device stack.
     */
    NtStatus DispatchSetPower(DevicePowerState newPowerState) {
        if (!m_pdo) return NtStatus::InvalidDeviceRequest;

        DeviceObject* topDevice = IoGetAttachedDevice(m_pdo);
        Irp irp{};
        irp.majorFunction = IRP_MJ_POWER;
        irp.minorFunction = IRP_MN_SET_POWER;
        irp.deviceObject = topDevice;
        irp.length = static_cast<uint32_t>(newPowerState);

        NtStatus st = IoCallDriver(topDevice, &irp);
        if (NT_SUCCESS(st)) {
            m_powerState = newPowerState;
        }
        return st;
    }

private:
    std::wstring m_deviceId;
    DeviceObject* m_pdo{nullptr};
    DeviceObject* m_fdo{nullptr};
    PnpDeviceState m_state{PnpDeviceState::Uninitialized};
    DevicePowerState m_powerState{DevicePowerState::PowerDeviceD0};
    std::vector<std::shared_ptr<PnpDeviceNode>> m_children;
};

// ============================================================================
// 5. VanguardDriver Engine (Centralized PnP & Device Manager)
// ============================================================================

class VanguardDriverEngine {
public:
    static VanguardDriverEngine& get() {
        static VanguardDriverEngine instance;
        return instance;
    }

    VanguardDriverEngine() {
        // Create root bus device node (e.g. ROOT\SYSTEM)
        m_rootNode = std::make_shared<PnpDeviceNode>(L"ROOT\\SYSTEM\\0000", nullptr);
    }

    std::shared_ptr<PnpDeviceNode> GetRootNode() const {
        return m_rootNode;
    }

    /**
     * @brief Registers a PnP child device node.
     */
    std::shared_ptr<PnpDeviceNode> CreateDeviceNode(
        std::wstring_view deviceId,
        DeviceObject* pdo,
        std::shared_ptr<PnpDeviceNode> parent = nullptr
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto node = std::make_shared<PnpDeviceNode>(deviceId, pdo);
        if (!parent) parent = m_rootNode;
        parent->AddChild(node);
        m_deviceNodes[std::wstring(deviceId)] = node;
        return node;
    }

    std::shared_ptr<PnpDeviceNode> LookupNode(std::wstring_view deviceId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_deviceNodes.find(std::wstring(deviceId));
        if (it != m_deviceNodes.end()) return it->second;
        return nullptr;
    }

    /**
     * @brief Registers a device interface with a class GUID (e.g. Audio, Disk, GPU).
     */
    NtStatus RegisterDeviceInterface(
        DeviceObject* pdo,
        const GUID& interfaceClassGuid,
        std::wstring_view referenceString,
        std::wstring& outSymbolicLink
    ) {
        if (!pdo) return NtStatus::InvalidParameter;
        std::lock_guard<std::mutex> lock(m_mutex);

        // Generate clean-room symbolic link \\?\DeviceInterface#...
        wchar_t guidBuf[64];
        std::swprintf(guidBuf, sizeof(guidBuf)/sizeof(wchar_t),
            L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
            interfaceClassGuid.Data1, interfaceClassGuid.Data2, interfaceClassGuid.Data3,
            interfaceClassGuid.Data4[0], interfaceClassGuid.Data4[1],
            interfaceClassGuid.Data4[2], interfaceClassGuid.Data4[3],
            interfaceClassGuid.Data4[4], interfaceClassGuid.Data4[5],
            interfaceClassGuid.Data4[6], interfaceClassGuid.Data4[7]
        );

        std::wstring symLink = L"\\\\?\\" + pdo->deviceName + L"#" + guidBuf;
        if (!referenceString.empty()) {
            symLink += L"#" + std::wstring(referenceString);
        }

        DeviceInterfaceEntry entry{
            .interfaceClassGuid = interfaceClassGuid,
            .symbolicLink = symLink,
            .referenceString = std::wstring(referenceString),
            .pdo = pdo,
            .isEnabled = false
        };

        m_interfaces[symLink] = entry;
        outSymbolicLink = symLink;
        return NtStatus::Success;
    }

    /**
     * @brief Sets the active/enabled state of a device interface.
     */
    NtStatus SetDeviceInterfaceState(std::wstring_view symbolicLink, bool enable) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_interfaces.find(std::wstring(symbolicLink));
        if (it == m_interfaces.end()) return NtStatus::NoSuchDevice;

        it->second.isEnabled = enable;
        return NtStatus::Success;
    }

    /**
     * @brief Queries all enabled device interfaces matching a specific class GUID.
     */
    std::vector<std::wstring> EnumerateDeviceInterfaces(const GUID& interfaceClassGuid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<std::wstring> result;
        for (const auto& [link, entry] : m_interfaces) {
            if (entry.isEnabled && entry.interfaceClassGuid == interfaceClassGuid) {
                result.push_back(link);
            }
        }
        return result;
    }

    /**
     * @brief High-level helper: Start Device sequence (Initializes, Sends START_DEVICE, sets Started state).
     */
    NtStatus StartDevice(PnpDeviceNode& node) {
        node.SetState(PnpDeviceState::Starting);
        NtStatus st = node.DispatchPnp(IRP_MN_START_DEVICE);
        if (NT_SUCCESS(st)) {
            node.SetState(PnpDeviceState::Started);
        } else {
            node.SetState(PnpDeviceState::Stopped);
        }
        return st;
    }

    /**
     * @brief High-level helper: Stop Device sequence (Sends QUERY_STOP and STOP_DEVICE).
     */
    NtStatus StopDevice(PnpDeviceNode& node) {
        node.SetState(PnpDeviceState::StopPending);
        NtStatus st = node.DispatchPnp(IRP_MN_QUERY_STOP_DEVICE);
        if (!NT_SUCCESS(st)) {
            node.SetState(PnpDeviceState::Started);
            return st;
        }

        st = node.DispatchPnp(IRP_MN_STOP_DEVICE);
        node.SetState(PnpDeviceState::Stopped);
        return st;
    }

    /**
     * @brief High-level helper: Remove Device sequence (Sends QUERY_REMOVE and REMOVE_DEVICE).
     */
    NtStatus RemoveDevice(PnpDeviceNode& node) {
        node.SetState(PnpDeviceState::RemovePending);
        node.DispatchPnp(IRP_MN_QUERY_REMOVE_DEVICE);
        NtStatus st = node.DispatchPnp(IRP_MN_REMOVE_DEVICE);
        node.SetState(PnpDeviceState::Removed);
        return st;
    }

    /**
     * @brief High-level helper: Surprise Removal.
     */
    NtStatus SurpriseRemoveDevice(PnpDeviceNode& node) {
        node.SetState(PnpDeviceState::SurpriseRemoved);
        return node.DispatchPnp(IRP_MN_SURPRISE_REMOVAL);
    }

private:
    std::mutex m_mutex;
    std::shared_ptr<PnpDeviceNode> m_rootNode;
    std::unordered_map<std::wstring, std::shared_ptr<PnpDeviceNode>> m_deviceNodes;
    std::unordered_map<std::wstring, DeviceInterfaceEntry> m_interfaces;
};

// ============================================================================
// 6. Cancel-Safe IRP Queue (WDM / KMDF Parity)
// ============================================================================

class CancelSafeIrpQueue {
public:
    void InsertTail(Irp* irp) {
        if (!irp) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push_back(irp);
    }

    Irp* RemoveNext() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_queue.empty()) return nullptr;
        Irp* irp = m_queue.front();
        m_queue.erase(m_queue.begin());
        return irp;
    }

    bool CancelIrp(Irp* irp) {
        if (!irp) return false;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find(m_queue.begin(), m_queue.end(), irp);
        if (it != m_queue.end()) {
            irp->ioStatus.status = NtStatus::Cancelled;
            irp->ioStatus.information = 0;
            m_queue.erase(it);
            return true;
        }
        return false;
    }

    size_t Count() const {
        return m_queue.size();
    }

private:
    std::mutex m_mutex;
    std::vector<Irp*> m_queue;
};

} // namespace micant::vanguarddriver

namespace micant::driver::vanguard {
    using namespace micant::vanguarddriver;
}
