// ============================================================================
// MicaNT: Windows DXCore Modern Adapter Enumeration Subsystem
//
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/DirectX-Headers (dxcore.h / dxcore_interface.h)
//   - Open DirectX Specifications for Modern Adapter Enumeration
//
// Subsystem Overview:
//   dxcore.hpp provides low-overhead, modular GPU/NPU device enumeration
//   independent of DXGI desktop/swapchain dependencies, engineered for compute,
//   machine learning (DirectML), and Direct3D 12 device creation.
//
// Interfaces:
//   - IDXCoreAdapter
//   - IDXCoreAdapterList
//   - IDXCoreAdapterFactory
//
// Trademark & Nominative Fair Use Notice:
//   DXCore, DirectX, and Direct3D are registered trademarks of Microsoft Corporation.
//   MicaNT's DXCore is an independent sovereign clean-room implementation
//   engineered for the MicaNT operating system executive.
// ============================================================================

#pragma once

#include "prism3d12.hpp"
#include "ldr.hpp"
#include "version.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>

namespace micant::dxcore {

using namespace micant::prismx;
using micant::GUID;
using micant::prismx::IUnknown;
using micant::prismx::IID_IUnknown;
using micant::LUID;

// ============================================================================
// 1. GUIDs & Interface Identifiers
// ============================================================================

inline constexpr GUID IID_IDXCoreAdapter_Const = {
    0xf0db4c7f, 0xcf5a, 0x42a6, { 0xa1, 0x52, 0xcb, 0x81, 0x12, 0x7b, 0x3f, 0x66 }
};

inline constexpr GUID IID_IDXCoreAdapterList_Const = {
    0x526c7776, 0x40e9, 0x459b, { 0xb7, 0x11, 0xf3, 0x2a, 0xd7, 0x6d, 0xfc, 0x28 }
};

inline constexpr GUID IID_IDXCoreAdapterFactory_Const = {
    0x78e687d0, 0x2629, 0x495b, { 0xa2, 0x4c, 0x68, 0xe7, 0x74, 0x64, 0x85, 0x94 }
};

// Adapter Attribute GUIDs
inline constexpr GUID DXCORE_ADAPTER_ATTRIBUTE_D3D11_GRAPHICS_CONST = {
    0x8c47866b, 0xf31a, 0x45e5, { 0xbd, 0x98, 0x04, 0x84, 0xa7, 0x37, 0x83, 0xfa }
};

inline constexpr GUID DXCORE_ADAPTER_ATTRIBUTE_D3D12_GRAPHICS_CONST = {
    0x0c9e7e61, 0xcb94, 0x4645, { 0x89, 0xf9, 0xd7, 0x2d, 0x0d, 0xe3, 0x0e, 0xcb }
};

inline constexpr GUID DXCORE_ADAPTER_ATTRIBUTE_D3D12_CORE_COMPUTE_CONST = {
    0x248e2800, 0xa793, 0x4724, { 0xab, 0xaa, 0x23, 0xa6, 0xde, 0x1a, 0x47, 0xd0 }
};

inline constexpr GUID DXCORE_ADAPTER_ATTRIBUTE_WSL_CONST = {
    0x9035f5e5, 0x33a7, 0x4fe7, { 0x87, 0xb4, 0x3a, 0x56, 0x24, 0x7c, 0x0a, 0x87 }
};

// ============================================================================
// 2. Constants & Enums
// ============================================================================

enum class DXCoreAdapterProperty : uint32_t {
    InstanceLUID                 = 0,
    DriverVersion                = 1,
    DriverDescription            = 2,
    HardwareID                   = 3,
    KmdModelVersion              = 4,
    ComputePreemptionGranularity = 5,
    GraphicsPreemptionGranularity= 6,
    DedicatedAdapterMemory       = 7,
    DedicatedSystemMemory        = 8,
    SharedSystemMemory           = 9,
    AdapterEngineCount           = 10,
    IsHardware                   = 11,
    IsIntegrated                 = 12,
    IsDetachable                 = 13,
    HardwareIDParts              = 14
};

enum class DXCoreAdapterEngineGranularity : uint32_t {
    DMA         = 0,
    Packet      = 1,
    Instruction = 2,
    PageFault   = 3,
    Partition   = 4
};

enum class DXCoreAdapterState : uint32_t {
    IsDriverUpdateInProgress = 0,
    AdapterMemoryBudget      = 1
};

enum class DXCoreSegmentGroup : uint32_t {
    Local    = 0,
    NonLocal = 1
};

enum class DXCoreNotificationType : uint32_t {
    AdapterListStale                          = 0,
    AdapterNoLongerValid                      = 1,
    AdapterBudgetChange                       = 2,
    AdapterHardwareContentProtectionTeardown  = 3
};

enum class DXCoreAdapterPreference : uint32_t {
    Hardware        = 0,
    MinimumPower    = 1,
    HighPerformance = 2
};

// ============================================================================
// 3. Structures
// ============================================================================

struct DXCoreHardwareID {
    uint32_t vendorID;
    uint32_t deviceID;
    uint32_t subSysID;
    uint32_t revision;
};

struct DXCoreHardwareIDParts {
    uint32_t vendorID;
    uint32_t deviceID;
    uint32_t subSysID;
    uint32_t revision;
};

struct DXCoreAdapterMemoryBudget {
    uint64_t budget;
    uint64_t currentUsage;
    uint64_t availableForReservation;
    uint64_t currentReservation;
};

struct DXCoreAdapterMemoryBudgetNodeSegmentGroup {
    uint32_t nodeIndex;
    DXCoreSegmentGroup segmentGroup;
};

using PFN_DXCORE_NOTIFICATION_CALLBACK = void (*)(DXCoreNotificationType notificationType, IUnknown* object, void* context);

// ============================================================================
// 4. Abstract COM Interfaces
// ============================================================================

class IDXCoreAdapter;
class IDXCoreAdapterList;
class IDXCoreAdapterFactory;

class IDXCoreAdapter : public IUnknown {
public:
    virtual bool IsValid() = 0;
    virtual bool IsAttributeSupported(const GUID& attributeGUID) = 0;
    virtual bool IsPropertySupported(DXCoreAdapterProperty property) = 0;
    virtual int32_t GetProperty(DXCoreAdapterProperty property, size_t bufferSize, void* propertyData) = 0;
    virtual int32_t GetPropertySize(DXCoreAdapterProperty property, size_t* bufferSize) = 0;
    virtual bool IsQueryStateSupported(DXCoreAdapterState property) = 0;
    virtual int32_t QueryState(DXCoreAdapterState state, size_t inputStateDetailsSize, const void* inputStateDetails, size_t outputBufferSize, void* outputBuffer) = 0;
    virtual bool IsSetStateSupported(DXCoreAdapterState property) = 0;
    virtual int32_t SetState(DXCoreAdapterState state, size_t inputStateDetailsSize, const void* inputStateDetails, size_t inputDataSize, const void* inputData) = 0;
    virtual int32_t GetFactory(const GUID& riid, void** ppvFactory) = 0;
};

class IDXCoreAdapterList : public IUnknown {
public:
    virtual int32_t GetAdapter(uint32_t index, const GUID& riid, void** ppvAdapter) = 0;
    virtual uint32_t GetAdapterCount() = 0;
    virtual bool IsStale() = 0;
    virtual int32_t GetFactory(const GUID& riid, void** ppvFactory) = 0;
    virtual int32_t Sort(uint32_t preferencesCount, const DXCoreAdapterPreference* preferences) = 0;
    virtual bool IsAdapterInList(IDXCoreAdapter* adapter) = 0;
};

class IDXCoreAdapterFactory : public IUnknown {
public:
    virtual int32_t CreateAdapterList(uint32_t numAttributes, const GUID* filterAttributes, const GUID& riid, void** ppvAdapterList) = 0;
    virtual int32_t GetAdapterByLUID(const LUID& adapterLUID, const GUID& riid, void** ppvAdapter) = 0;
    virtual bool IsNotificationTypeSupported(DXCoreNotificationType notificationType) = 0;
    virtual int32_t RegisterEventNotification(IUnknown* dxCoreObject, DXCoreNotificationType notificationType, PFN_DXCORE_NOTIFICATION_CALLBACK callback, void* callbackContext, uint32_t* eventCookie) = 0;
    virtual int32_t UnregisterEventNotification(uint32_t eventCookie) = 0;
};

// ============================================================================
// 5. Concrete Subsystem Implementation
// ============================================================================

class MicaDXCoreAdapterImpl : public IDXCoreAdapter {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IDXCoreAdapterFactory* m_pFactory{ nullptr };
    std::string m_description;
    LUID m_luid{};
    DXCoreHardwareID m_hwId{};
    uint64_t m_driverVersion{ 0x001F000000010000ULL }; // 31.0.100.1
    uint64_t m_dedicatedAdapterMemory{ 16ULL * 1024 * 1024 * 1024 }; // 16 GB
    uint64_t m_dedicatedSystemMemory{ 0 };
    uint64_t m_sharedSystemMemory{ 32ULL * 1024 * 1024 * 1024 };    // 32 GB
    uint32_t m_engineCount{ 8 };
    bool m_isHardware{ true };
    bool m_isIntegrated{ false };
    bool m_isDetachable{ false };
    bool m_isValid{ true };
    std::vector<GUID> m_supportedAttributes;

public:
    MicaDXCoreAdapterImpl(IDXCoreAdapterFactory* factory,
                         std::string desc,
                         LUID luid,
                         DXCoreHardwareID hwId,
                         uint64_t dedicatedMem,
                         bool isIntegrated)
        : m_pFactory(factory),
          m_description(std::move(desc)),
          m_luid(luid),
          m_hwId(hwId),
          m_dedicatedAdapterMemory(dedicatedMem),
          m_isIntegrated(isIntegrated) {
        m_supportedAttributes.push_back(DXCORE_ADAPTER_ATTRIBUTE_D3D11_GRAPHICS_CONST);
        m_supportedAttributes.push_back(DXCORE_ADAPTER_ATTRIBUTE_D3D12_GRAPHICS_CONST);
        m_supportedAttributes.push_back(DXCORE_ADAPTER_ATTRIBUTE_D3D12_CORE_COMPUTE_CONST);
        m_supportedAttributes.push_back(DXCORE_ADAPTER_ATTRIBUTE_WSL_CONST);
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IDXCoreAdapter_Const) {
            *ppv = static_cast<IDXCoreAdapter*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override {
        return m_refCount.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (count == 0) delete this;
        return count;
    }

    bool IsValid() override {
        return m_isValid;
    }

    bool IsAttributeSupported(const GUID& attributeGUID) override {
        for (const auto& attr : m_supportedAttributes) {
            if (attr == attributeGUID) return true;
        }
        return false;
    }

    bool IsPropertySupported(DXCoreAdapterProperty property) override {
        switch (property) {
            case DXCoreAdapterProperty::InstanceLUID:
            case DXCoreAdapterProperty::DriverVersion:
            case DXCoreAdapterProperty::DriverDescription:
            case DXCoreAdapterProperty::HardwareID:
            case DXCoreAdapterProperty::KmdModelVersion:
            case DXCoreAdapterProperty::ComputePreemptionGranularity:
            case DXCoreAdapterProperty::GraphicsPreemptionGranularity:
            case DXCoreAdapterProperty::DedicatedAdapterMemory:
            case DXCoreAdapterProperty::DedicatedSystemMemory:
            case DXCoreAdapterProperty::SharedSystemMemory:
            case DXCoreAdapterProperty::AdapterEngineCount:
            case DXCoreAdapterProperty::IsHardware:
            case DXCoreAdapterProperty::IsIntegrated:
            case DXCoreAdapterProperty::IsDetachable:
            case DXCoreAdapterProperty::HardwareIDParts:
                return true;
            default:
                return false;
        }
    }

    int32_t GetPropertySize(DXCoreAdapterProperty property, size_t* bufferSize) override {
        if (!bufferSize) return -2147467261;
        switch (property) {
            case DXCoreAdapterProperty::InstanceLUID:
                *bufferSize = sizeof(LUID);
                return 0;
            case DXCoreAdapterProperty::DriverVersion:
                *bufferSize = sizeof(uint64_t);
                return 0;
            case DXCoreAdapterProperty::DriverDescription:
                *bufferSize = m_description.size() + 1;
                return 0;
            case DXCoreAdapterProperty::HardwareID:
            case DXCoreAdapterProperty::HardwareIDParts:
                *bufferSize = sizeof(DXCoreHardwareID);
                return 0;
            case DXCoreAdapterProperty::KmdModelVersion:
                *bufferSize = sizeof(uint32_t);
                return 0;
            case DXCoreAdapterProperty::ComputePreemptionGranularity:
            case DXCoreAdapterProperty::GraphicsPreemptionGranularity:
                *bufferSize = sizeof(DXCoreAdapterEngineGranularity);
                return 0;
            case DXCoreAdapterProperty::DedicatedAdapterMemory:
            case DXCoreAdapterProperty::DedicatedSystemMemory:
            case DXCoreAdapterProperty::SharedSystemMemory:
                *bufferSize = sizeof(uint64_t);
                return 0;
            case DXCoreAdapterProperty::AdapterEngineCount:
                *bufferSize = sizeof(uint32_t);
                return 0;
            case DXCoreAdapterProperty::IsHardware:
            case DXCoreAdapterProperty::IsIntegrated:
            case DXCoreAdapterProperty::IsDetachable:
                *bufferSize = sizeof(bool);
                return 0;
            default:
                return -2147024809;
        }
    }

    int32_t GetProperty(DXCoreAdapterProperty property, size_t bufferSize, void* propertyData) override {
        if (!propertyData) return -2147467261;
        size_t requiredSize = 0;
        int32_t hr = GetPropertySize(property, &requiredSize);
        if (hr < 0) return hr;
        if (bufferSize < requiredSize) return -2147024809;

        switch (property) {
            case DXCoreAdapterProperty::InstanceLUID:
                std::memcpy(propertyData, &m_luid, sizeof(LUID));
                return 0;
            case DXCoreAdapterProperty::DriverVersion:
                std::memcpy(propertyData, &m_driverVersion, sizeof(uint64_t));
                return 0;
            case DXCoreAdapterProperty::DriverDescription:
                std::memcpy(propertyData, m_description.c_str(), m_description.size() + 1);
                return 0;
            case DXCoreAdapterProperty::HardwareID:
            case DXCoreAdapterProperty::HardwareIDParts:
                std::memcpy(propertyData, &m_hwId, sizeof(DXCoreHardwareID));
                return 0;
            case DXCoreAdapterProperty::KmdModelVersion: {
                uint32_t kmd = 0x2000; // WDDM 2.0+
                std::memcpy(propertyData, &kmd, sizeof(uint32_t));
                return 0;
            }
            case DXCoreAdapterProperty::ComputePreemptionGranularity: {
                auto g = DXCoreAdapterEngineGranularity::Instruction;
                std::memcpy(propertyData, &g, sizeof(g));
                return 0;
            }
            case DXCoreAdapterProperty::GraphicsPreemptionGranularity: {
                auto g = DXCoreAdapterEngineGranularity::DMA;
                std::memcpy(propertyData, &g, sizeof(g));
                return 0;
            }
            case DXCoreAdapterProperty::DedicatedAdapterMemory:
                std::memcpy(propertyData, &m_dedicatedAdapterMemory, sizeof(uint64_t));
                return 0;
            case DXCoreAdapterProperty::DedicatedSystemMemory:
                std::memcpy(propertyData, &m_dedicatedSystemMemory, sizeof(uint64_t));
                return 0;
            case DXCoreAdapterProperty::SharedSystemMemory:
                std::memcpy(propertyData, &m_sharedSystemMemory, sizeof(uint64_t));
                return 0;
            case DXCoreAdapterProperty::AdapterEngineCount:
                std::memcpy(propertyData, &m_engineCount, sizeof(uint32_t));
                return 0;
            case DXCoreAdapterProperty::IsHardware:
                std::memcpy(propertyData, &m_isHardware, sizeof(bool));
                return 0;
            case DXCoreAdapterProperty::IsIntegrated:
                std::memcpy(propertyData, &m_isIntegrated, sizeof(bool));
                return 0;
            case DXCoreAdapterProperty::IsDetachable:
                std::memcpy(propertyData, &m_isDetachable, sizeof(bool));
                return 0;
            default:
                return -2147024809;
        }
    }

    bool IsQueryStateSupported(DXCoreAdapterState property) override {
        return (property == DXCoreAdapterState::IsDriverUpdateInProgress ||
                property == DXCoreAdapterState::AdapterMemoryBudget);
    }

    int32_t QueryState(DXCoreAdapterState state, size_t, const void*, size_t outputBufferSize, void* outputBuffer) override {
        if (!outputBuffer) return -2147467261;
        if (state == DXCoreAdapterState::IsDriverUpdateInProgress) {
            if (outputBufferSize < sizeof(bool)) return -2147024809;
            bool updating = false;
            std::memcpy(outputBuffer, &updating, sizeof(bool));
            return 0;
        } else if (state == DXCoreAdapterState::AdapterMemoryBudget) {
            if (outputBufferSize < sizeof(DXCoreAdapterMemoryBudget)) return -2147024809;
            DXCoreAdapterMemoryBudget budget{};
            budget.budget = m_dedicatedAdapterMemory;
            budget.currentUsage = 1024ULL * 1024 * 256; // 256 MB in use
            budget.availableForReservation = m_dedicatedAdapterMemory - budget.currentUsage;
            budget.currentReservation = 0;
            std::memcpy(outputBuffer, &budget, sizeof(budget));
            return 0;
        }
        return -2147467263;
    }

    bool IsSetStateSupported(DXCoreAdapterState) override {
        return false;
    }

    int32_t SetState(DXCoreAdapterState, size_t, const void*, size_t, const void*) override {
        return -2147467263;
    }

    int32_t GetFactory(const GUID& riid, void** ppvFactory) override {
        if (!ppvFactory) return -2147467261;
        if (!m_pFactory) return -2147467259;
        return m_pFactory->QueryInterface(riid, ppvFactory);
    }

    const LUID& GetLUID() const { return m_luid; }
    uint64_t GetDedicatedMemory() const { return m_dedicatedAdapterMemory; }
    bool IsIntegratedAdapter() const { return m_isIntegrated; }
    const std::string& GetDescription() const { return m_description; }
};

class MicaDXCoreAdapterListImpl : public IDXCoreAdapterList {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    IDXCoreAdapterFactory* m_pFactory{ nullptr };
    std::vector<IDXCoreAdapter*> m_adapters;
    bool m_isStale{ false };

public:
    MicaDXCoreAdapterListImpl(IDXCoreAdapterFactory* factory, std::vector<IDXCoreAdapter*> adapters)
        : m_pFactory(factory), m_adapters(std::move(adapters)) {
        for (auto* a : m_adapters) {
            if (a) a->AddRef();
        }
    }

    ~MicaDXCoreAdapterListImpl() {
        for (auto* a : m_adapters) {
            if (a) a->Release();
        }
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IDXCoreAdapterList_Const) {
            *ppv = static_cast<IDXCoreAdapterList*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override {
        return m_refCount.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (count == 0) delete this;
        return count;
    }

    int32_t GetAdapter(uint32_t index, const GUID& riid, void** ppvAdapter) override {
        if (!ppvAdapter) return -2147467261;
        if (index >= m_adapters.size()) return -2147024809;
        return m_adapters[index]->QueryInterface(riid, ppvAdapter);
    }

    uint32_t GetAdapterCount() override {
        return static_cast<uint32_t>(m_adapters.size());
    }

    bool IsStale() override {
        return m_isStale;
    }

    int32_t GetFactory(const GUID& riid, void** ppvFactory) override {
        if (!ppvFactory) return -2147467261;
        if (!m_pFactory) return -2147467259;
        return m_pFactory->QueryInterface(riid, ppvFactory);
    }

    int32_t Sort(uint32_t preferencesCount, const DXCoreAdapterPreference* preferences) override {
        if (!preferences && preferencesCount > 0) return -2147467261;

        for (uint32_t i = 0; i < preferencesCount; ++i) {
            if (preferences[i] == DXCoreAdapterPreference::HighPerformance) {
                std::stable_sort(m_adapters.begin(), m_adapters.end(), [](IDXCoreAdapter* a, IDXCoreAdapter* b) {
                    auto* pa = static_cast<MicaDXCoreAdapterImpl*>(a);
                    auto* pb = static_cast<MicaDXCoreAdapterImpl*>(b);
                    return pa->GetDedicatedMemory() > pb->GetDedicatedMemory();
                });
            } else if (preferences[i] == DXCoreAdapterPreference::MinimumPower) {
                std::stable_sort(m_adapters.begin(), m_adapters.end(), [](IDXCoreAdapter* a, IDXCoreAdapter* b) {
                    auto* pa = static_cast<MicaDXCoreAdapterImpl*>(a);
                    auto* pb = static_cast<MicaDXCoreAdapterImpl*>(b);
                    return pa->IsIntegratedAdapter() && !pb->IsIntegratedAdapter();
                });
            }
        }
        return 0;
    }

    bool IsAdapterInList(IDXCoreAdapter* adapter) override {
        if (!adapter) return false;
        for (auto* a : m_adapters) {
            if (a == adapter) return true;
        }
        return false;
    }
};

class MicaDXCoreAdapterFactoryImpl : public IDXCoreAdapterFactory {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::mutex m_mutex;
    std::vector<MicaDXCoreAdapterImpl*> m_allAdapters;
    struct NotificationEntry {
        uint32_t cookie;
        DXCoreNotificationType type;
        PFN_DXCORE_NOTIFICATION_CALLBACK callback;
        void* context;
    };
    std::vector<NotificationEntry> m_notifications;
    uint32_t m_nextCookie{ 100 };

public:
    MicaDXCoreAdapterFactoryImpl() {
        // 1. Primary Sovereign Dedicated GPU
        LUID luid1{ 0x1000, 0 };
        DXCoreHardwareID hw1{ 0x13B5, 0x2B80, 0x0001, 0x01 }; // PrismX Sovereign
        auto* primary = new MicaDXCoreAdapterImpl(this, "PrismX Sovereign Neural & Graphics Accelerator", luid1, hw1, 16ULL * 1024 * 1024 * 1024, false);
        m_allAdapters.push_back(primary);

        // 2. Secondary Integrated Neural Compute Unit
        LUID luid2{ 0x1001, 0 };
        DXCoreHardwareID hw2{ 0x13B5, 0x10A0, 0x0001, 0x01 };
        auto* secondary = new MicaDXCoreAdapterImpl(this, "PrismX Integrated Neural Compute Core", luid2, hw2, 0, true);
        m_allAdapters.push_back(secondary);
    }

    ~MicaDXCoreAdapterFactoryImpl() {
        for (auto* a : m_allAdapters) {
            if (a) a->Release();
        }
    }

    int32_t QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return -2147467261;
        if (riid == IID_IUnknown || riid == IID_IDXCoreAdapterFactory_Const) {
            *ppv = static_cast<IDXCoreAdapterFactory*>(this);
            AddRef();
            return 0;
        }
        *ppv = nullptr;
        return -2147467262;
    }

    uint32_t AddRef() override {
        return m_refCount.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (count == 0) delete this;
        return count;
    }

    int32_t CreateAdapterList(uint32_t numAttributes, const GUID* filterAttributes, const GUID& riid, void** ppvAdapterList) override {
        if (!ppvAdapterList) return -2147467261;
        std::vector<IDXCoreAdapter*> matched;

        for (auto* adapter : m_allAdapters) {
            bool matches = true;
            for (uint32_t i = 0; i < numAttributes; ++i) {
                if (!adapter->IsAttributeSupported(filterAttributes[i])) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                matched.push_back(adapter);
            }
        }

        auto* list = new MicaDXCoreAdapterListImpl(this, std::move(matched));
        int32_t hr = list->QueryInterface(riid, ppvAdapterList);
        list->Release();
        return hr;
    }

    int32_t GetAdapterByLUID(const LUID& adapterLUID, const GUID& riid, void** ppvAdapter) override {
        if (!ppvAdapter) return -2147467261;
        for (auto* adapter : m_allAdapters) {
            const auto& l = adapter->GetLUID();
            if (l.lowPart == adapterLUID.lowPart && l.highPart == adapterLUID.highPart) {
                return adapter->QueryInterface(riid, ppvAdapter);
            }
        }
        return -2147467259;
    }

    bool IsNotificationTypeSupported(DXCoreNotificationType notificationType) override {
        return notificationType == DXCoreNotificationType::AdapterBudgetChange ||
               notificationType == DXCoreNotificationType::AdapterListStale;
    }

    int32_t RegisterEventNotification(IUnknown*, DXCoreNotificationType notificationType, PFN_DXCORE_NOTIFICATION_CALLBACK callback, void* callbackContext, uint32_t* eventCookie) override {
        if (!callback || !eventCookie) return -2147467261;
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t cookie = m_nextCookie++;
        m_notifications.push_back({ cookie, notificationType, callback, callbackContext });
        *eventCookie = cookie;
        return 0;
    }

    int32_t UnregisterEventNotification(uint32_t eventCookie) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::remove_if(m_notifications.begin(), m_notifications.end(), [eventCookie](const auto& entry) {
            return entry.cookie == eventCookie;
        });
        if (it != m_notifications.end()) {
            m_notifications.erase(it, m_notifications.end());
            return 0;
        }
        return -2147024809;
    }
};

// ============================================================================
// 6. Global API Factory Function & Dynamic Exports
// ============================================================================

inline int32_t __stdcall DXCoreCreateAdapterFactory(const GUID& riid, void** ppvFactory) {
    if (!ppvFactory) return -2147467261;
    static MicaDXCoreAdapterFactoryImpl s_factory;
    return s_factory.QueryInterface(riid, ppvFactory);
}

inline void InitializeDXCoreExports() {
    auto& loader = micant::ldr::DynamicLoader::get();
    loader.registerExport("dxcore.dll", "DXCoreCreateAdapterFactory", reinterpret_cast<void*>(DXCoreCreateAdapterFactory));

    version::VersionDatabase::Instance().RegisterModule(
        "dxcore.dll",
        "10.0.22621.1",
        "DirectX Core Modern Adapter Enumeration Subsystem",
        "MicaNT Sovereign Project"
    );
}

} // namespace micant::dxcore
