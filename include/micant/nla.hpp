#pragma once

/**
 * @file nla.hpp
 * @brief Clean-room Windows Network Location Awareness (NLA) & Network List Service.
 *
 * Implements the Network List Manager COM hierarchy (INetworkListManager, INetwork,
 * INetworkConnection, INetworkCostManager, IEnumNetworks, IEnumNetworkConnections),
 * Network Location Awareness (NLA) Winsock Name Space Provider query structures,
 * network connectivity profiling, network category management, and SCM services
 * (NLASvc, netprofm, NcbService).
 *
 * Strict clean-room implementation referencing Microsoft's MIT-licensed win32metadata.
 * Zero proprietary, leaked, or decompiled code.
 */

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <algorithm>
#include <mutex>
#include <cstring>
#include <cwchar>
#include <sstream>
#include <iomanip>
#include <iostream>

#include "ntdef.hpp"
#include "kernel32.hpp"
#include "ole32.hpp"
#include "oleaut32.hpp"
#include "scm.hpp"
#include "ldr.hpp"

namespace micant::nla {

using namespace micant::ole32;

// ============================================================================
// 1. NLM Enums & Constants (win32metadata)
// ============================================================================

enum NLM_CONNECTIVITY : uint32_t {
    NLM_CONNECTIVITY_DISCONNECTED       = 0x0000,
    NLM_CONNECTIVITY_IPV4_NOTRAFFIC     = 0x0001,
    NLM_CONNECTIVITY_IPV6_NOTRAFFIC     = 0x0002,
    NLM_CONNECTIVITY_IPV4_SUBNET        = 0x0010,
    NLM_CONNECTIVITY_IPV4_LOCALNETWORK  = 0x0020,
    NLM_CONNECTIVITY_IPV4_INTERNET      = 0x0040,
    NLM_CONNECTIVITY_IPV6_SUBNET        = 0x0100,
    NLM_CONNECTIVITY_IPV6_LOCALNETWORK  = 0x0200,
    NLM_CONNECTIVITY_IPV6_INTERNET      = 0x0400
};

enum NLM_NETWORK_CATEGORY : uint32_t {
    NLM_NETWORK_CATEGORY_PUBLIC               = 0,
    NLM_NETWORK_CATEGORY_PRIVATE              = 1,
    NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED = 2
};

enum NLM_ENUM_NETWORK : uint32_t {
    NLM_ENUM_NETWORK_CONNECTED    = 0x01,
    NLM_ENUM_NETWORK_DISCONNECTED = 0x02,
    NLM_ENUM_NETWORK_ALL          = 0x03
};

enum NLM_DOMAIN_TYPE : uint32_t {
    NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK   = 0,
    NLM_DOMAIN_TYPE_DOMAIN_NETWORK       = 1,
    NLM_DOMAIN_TYPE_DOMAIN_AUTHENTICATED = 2
};

enum NLM_CONNECTION_COST : uint32_t {
    NLM_CONNECTION_COST_UNKNOWN                = 0x0,
    NLM_CONNECTION_COST_UNRESTRICTED           = 0x1,
    NLM_CONNECTION_COST_FIXED                  = 0x2,
    NLM_CONNECTION_COST_VARIABLE               = 0x4,
    NLM_CONNECTION_COST_OVERDATALIMIT          = 0x10000,
    NLM_CONNECTION_COST_CONGESTED              = 0x20000,
    NLM_CONNECTION_COST_ROAMING                = 0x40000,
    NLM_CONNECTION_COST_APPROACHINGDATALIMIT   = 0x80000
};

enum NLM_NETWORK_PROPERTY_CHANGE : uint32_t {
    NLM_NETWORK_PROPERTY_CHANGE_CONNECTION       = 0x01,
    NLM_NETWORK_PROPERTY_CHANGE_DESCRIPTION      = 0x02,
    NLM_NETWORK_PROPERTY_CHANGE_NAME             = 0x04,
    NLM_NETWORK_PROPERTY_CHANGE_ICON             = 0x08,
    NLM_NETWORK_PROPERTY_CHANGE_CATEGORY_VALUE   = 0x10
};

enum NLM_CONNECTION_PROPERTY_CHANGE : uint32_t {
    NLM_CONNECTION_PROPERTY_CHANGE_AUTHENTICATION = 0x01
};

#pragma pack(push, 1)

struct NLM_USAGE_DATA {
    uint32_t UsageInMegabytes;
    win32::FILETIME LastSyncTime;
};

struct NLM_CONNECTION_COST_DATA {
    uint32_t ConnectionCost;
    uint32_t CostFlags;
};

struct NLM_DATAPLAN_STATUS {
    GUID InterfaceGuid;
    NLM_USAGE_DATA UsageData;
    uint32_t DataLimitInMegabytes;
    uint32_t InboundBandwidthInKbps;
    uint32_t OutboundBandwidthInKbps;
    win32::FILETIME NextBillingCycle;
    uint32_t MaxTransferSizeInMegabytes;
    uint32_t Reserved;
};

// NLA Name Space Provider ID (NS_NLA = 15)
inline constexpr uint32_t NS_NLA = 15;

enum NLA_BLOB_DATA_TYPE : uint32_t {
    NLA_RAW_DATA          = 0,
    NLA_INTERFACE         = 1,
    NLA_802_1X_LOCATION   = 2,
    NLA_CONNECTIVITY      = 3,
    NLA_ICS               = 4
};

enum NLA_CONNECTIVITY_TYPE : uint32_t {
    NLA_NETWORK_UNKNOWN        = 0,
    NLA_NETWORK_AD_HOC         = 1,
    NLA_NETWORK_MANAGED        = 2,
    NLA_NETWORK_UNMANAGED      = 3,
    NLA_NETWORK_UNKNOWN_PORTAL = 4
};

enum NLA_INTERNET : uint32_t {
    NLA_INTERNET_UNKNOWN = 0,
    NLA_INTERNET_NO      = 1,
    NLA_INTERNET_YES     = 2
};

struct NLA_CONNECTIVITY_BLOB {
    NLA_CONNECTIVITY_TYPE type;
    NLA_INTERNET          internet;
};

#pragma pack(pop)

// ============================================================================
// 2. Network List Manager GUIDs
// ============================================================================

inline const GUID CLSID_NetworkListManager = {
    0xDCB00C01, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B }
};

inline const GUID IID_INetworkListManager = {
    0xDCB00000, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B }
};

inline const GUID IID_INetwork = {
    0xDCB00002, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B }
};

inline const GUID IID_IEnumNetworks = {
    0xDCB00003, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B }
};

inline const GUID IID_INetworkEvents = {
    0xDCB00004, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B }
};

inline const GUID IID_INetworkConnection = {
    0xDCB00005, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B }
};

inline const GUID IID_IEnumNetworkConnections = {
    0xDCB00006, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B }
};

inline const GUID IID_INetworkConnectionEvents = {
    0xDCB00007, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B }
};

inline const GUID IID_INetworkCostManager = {
    0xDCB00008, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B }
};

inline const GUID IID_INetworkConnectionCost = {
    0xDCB0000A, 0x570F, 0x4A9B, { 0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B }
};

inline const GUID NLA_NAMESPACE_GUID = {
    0x6642243A, 0x3BA8, 0x4AA6, { 0xBA, 0xA5, 0xCA, 0x81, 0x2A, 0x78, 0x21, 0x56 }
};

// ============================================================================
// 3. COM Interface Definitions
// ============================================================================

class INetwork;
class IEnumNetworks;
class INetworkConnection;
class IEnumNetworkConnections;
class INetworkCostManager;

class INetworkListManager : public ole32::IDispatch {
public:
    virtual HRESULT __stdcall GetNetworks(NLM_ENUM_NETWORK Flags, IEnumNetworks** ppEnumNetwork) = 0;
    virtual HRESULT __stdcall GetNetwork(GUID gdNetworkId, INetwork** ppNetwork) = 0;
    virtual HRESULT __stdcall GetNetworkConnections(IEnumNetworkConnections** ppEnum) = 0;
    virtual HRESULT __stdcall GetNetworkConnection(GUID gdNetworkConnectionId, INetworkConnection** ppNetworkConnection) = 0;
    virtual HRESULT __stdcall get_IsConnectedToInternet(VARIANT_BOOL* pbIsConnected) = 0;
    virtual HRESULT __stdcall get_IsConnected(VARIANT_BOOL* pbIsConnected) = 0;
    virtual HRESULT __stdcall GetConnectivity(NLM_CONNECTIVITY* pConnectivity) = 0;
};

class INetwork : public ole32::IDispatch {
public:
    virtual HRESULT __stdcall GetName(BSTR* pszNetworkName) = 0;
    virtual HRESULT __stdcall SetName(BSTR szNetworkName) = 0;
    virtual HRESULT __stdcall GetDescription(BSTR* pszDescription) = 0;
    virtual HRESULT __stdcall SetDescription(BSTR szDescription) = 0;
    virtual HRESULT __stdcall GetNetworkId(GUID* pgdGuidNetworkId) = 0;
    virtual HRESULT __stdcall GetDomainType(NLM_DOMAIN_TYPE* pNetworkType) = 0;
    virtual HRESULT __stdcall GetNetworkConnections(IEnumNetworkConnections** ppEnumNetworkConnection) = 0;
    virtual HRESULT __stdcall GetTimeCreatedAndConnected(
        uint32_t* pdwLowDateTimeCreated, uint32_t* pdwHighDateTimeCreated,
        uint32_t* pdwLowDateTimeConnected, uint32_t* pdwHighDateTimeConnected
    ) = 0;
    virtual HRESULT __stdcall get_IsConnectedToInternet(VARIANT_BOOL* pbIsConnected) = 0;
    virtual HRESULT __stdcall get_IsConnected(VARIANT_BOOL* pbIsConnected) = 0;
    virtual HRESULT __stdcall GetConnectivity(NLM_CONNECTIVITY* pConnectivity) = 0;
    virtual HRESULT __stdcall GetCategory(NLM_NETWORK_CATEGORY* pCategory) = 0;
    virtual HRESULT __stdcall SetCategory(NLM_NETWORK_CATEGORY NewCategory) = 0;
};

class INetworkConnection : public ole32::IDispatch {
public:
    virtual HRESULT __stdcall GetNetwork(INetwork** ppNetwork) = 0;
    virtual HRESULT __stdcall get_IsConnectedToInternet(VARIANT_BOOL* pbIsConnected) = 0;
    virtual HRESULT __stdcall get_IsConnected(VARIANT_BOOL* pbIsConnected) = 0;
    virtual HRESULT __stdcall GetConnectivity(NLM_CONNECTIVITY* pConnectivity) = 0;
    virtual HRESULT __stdcall GetConnectionId(GUID* pgdConnectionId) = 0;
    virtual HRESULT __stdcall GetAdapterId(GUID* pgdAdapterId) = 0;
    virtual HRESULT __stdcall GetDomainType(NLM_DOMAIN_TYPE* pDomainType) = 0;
};

class IEnumNetworks : public ole32::IDispatch {
public:
    virtual HRESULT __stdcall Next(uint32_t celt, INetwork** rgelt, uint32_t* pceltFetched) = 0;
    virtual HRESULT __stdcall Skip(uint32_t celt) = 0;
    virtual HRESULT __stdcall Reset() = 0;
    virtual HRESULT __stdcall Clone(IEnumNetworks** ppEnumNetwork) = 0;
};

class IEnumNetworkConnections : public ole32::IDispatch {
public:
    virtual HRESULT __stdcall Next(uint32_t celt, INetworkConnection** rgelt, uint32_t* pceltFetched) = 0;
    virtual HRESULT __stdcall Skip(uint32_t celt) = 0;
    virtual HRESULT __stdcall Reset() = 0;
    virtual HRESULT __stdcall Clone(IEnumNetworkConnections** ppEnum) = 0;
};

class INetworkCostManager : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall GetCost(uint32_t* pCost, NLM_CONNECTION_COST_DATA* pData) = 0;
    virtual HRESULT __stdcall GetDataPlanStatus(NLM_DATAPLAN_STATUS* pDataPlanStatus, void* pInterfaceKey) = 0;
    virtual HRESULT __stdcall SetDestinationAddresses(uint32_t length, void* pDestAddresses, VARIANT_BOOL bInclude) = 0;
};

// ============================================================================
// 4. Sovereign Network Location & Profiling Engine
// ============================================================================

struct NetworkProfile {
    GUID networkId{};
    std::wstring name;
    std::wstring description;
    NLM_NETWORK_CATEGORY category{NLM_NETWORK_CATEGORY_PRIVATE};
    NLM_DOMAIN_TYPE domainType{NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK};
    std::wstring domainSuffix;
    uint32_t connectivity{NLM_CONNECTIVITY_DISCONNECTED};
    GUID adapterId{};
    GUID connectionId{};
    uint32_t cost{NLM_CONNECTION_COST_UNRESTRICTED};
    uint32_t timeCreatedLow{0x10000000};
    uint32_t timeCreatedHigh{0x01DA0000};
    uint32_t timeConnectedLow{0x10005000};
    uint32_t timeConnectedHigh{0x01DA0000};
};

class NetworkLocationManager {
private:
    mutable std::mutex m_mutex;
    std::vector<NetworkProfile> m_profiles;

    NetworkLocationManager() {
        initDefaultProfiles();
        registerScmServices();
    }

    void initDefaultProfiles() {
        // 1. Corporate / Domain Authenticated Ethernet Profile
        {
            NetworkProfile p;
            p.networkId = { 0xA1B2C3D4, 0xE5F6, 0x47A1, { 0x80, 0x90, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } };
            p.name = L"MicaNT Corporate Domain Network";
            p.description = L"High-Speed Gigabit Sovereign Ethernet Network (micant.local)";
            p.category = NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED;
            p.domainType = NLM_DOMAIN_TYPE_DOMAIN_AUTHENTICATED;
            p.domainSuffix = L"micant.local";
            p.connectivity = NLM_CONNECTIVITY_IPV4_INTERNET | NLM_CONNECTIVITY_IPV4_LOCALNETWORK | NLM_CONNECTIVITY_IPV4_SUBNET
                           | NLM_CONNECTIVITY_IPV6_INTERNET | NLM_CONNECTIVITY_IPV6_LOCALNETWORK | NLM_CONNECTIVITY_IPV6_SUBNET;
            p.adapterId = { 0x11112222, 0x3333, 0x4444, { 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88 } };
            p.connectionId = { 0x99998888, 0x7777, 0x6666, { 0x55, 0x55, 0x44, 0x44, 0x33, 0x33, 0x22, 0x22 } };
            p.cost = NLM_CONNECTION_COST_UNRESTRICTED;
            m_profiles.push_back(p);
        }

        // 2. Private Secure Wi-Fi Profile
        {
            NetworkProfile p;
            p.networkId = { 0xB2C3D4E5, 0xF6A7, 0x48B2, { 0x91, 0xA1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 } };
            p.name = L"MicaNT Secure Wireless";
            p.description = L"WPA3-Enterprise 802.11ax Wireless Network";
            p.category = NLM_NETWORK_CATEGORY_PRIVATE;
            p.domainType = NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK;
            p.domainSuffix = L"corp.internal";
            p.connectivity = NLM_CONNECTIVITY_IPV4_INTERNET | NLM_CONNECTIVITY_IPV4_LOCALNETWORK | NLM_CONNECTIVITY_IPV4_SUBNET;
            p.adapterId = { 0x22223333, 0x4444, 0x5555, { 0x66, 0x66, 0x77, 0x77, 0x88, 0x88, 0x99, 0x99 } };
            p.connectionId = { 0x88887777, 0x6666, 0x5555, { 0x44, 0x44, 0x33, 0x33, 0x22, 0x22, 0x11, 0x11 } };
            p.cost = NLM_CONNECTION_COST_FIXED;
            m_profiles.push_back(p);
        }

        // 3. Isolated Public / Lab Network Profile
        {
            NetworkProfile p;
            p.networkId = { 0xC3D4E5F6, 0xA7B8, 0x49C3, { 0xA2, 0xB2, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 } };
            p.name = L"MicaNT Isolated Lab Network";
            p.description = L"Sandbox Test Environment (Subnet Only)";
            p.category = NLM_NETWORK_CATEGORY_PUBLIC;
            p.domainType = NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK;
            p.domainSuffix = L"";
            p.connectivity = NLM_CONNECTIVITY_IPV4_LOCALNETWORK | NLM_CONNECTIVITY_IPV4_SUBNET;
            p.adapterId = { 0x33334444, 0x5555, 0x6666, { 0x77, 0x77, 0x88, 0x88, 0x99, 0x99, 0x00, 0x00 } };
            p.connectionId = { 0x77776666, 0x5555, 0x4444, { 0x33, 0x33, 0x22, 0x22, 0x11, 0x11, 0x00, 0x00 } };
            p.cost = NLM_CONNECTION_COST_UNRESTRICTED;
            m_profiles.push_back(p);
        }
    }

    void registerScmServices() {
        auto& scm = scm::ServiceControlManager::get();

        // 1. NLASvc: Network Location Awareness Service
        auto nlaRec = std::make_shared<scm::ServiceRecord>();
        nlaRec->serviceName = L"NLASvc";
        nlaRec->displayName = L"Network Location Awareness";
        nlaRec->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        nlaRec->startType = scm::SERVICE_AUTO_START;
        nlaRec->errorControl = scm::SERVICE_ERROR_NORMAL;
        nlaRec->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k NetworkService";
        nlaRec->loadOrderGroup = L"NetworkService";
        nlaRec->status.dwServiceType = nlaRec->serviceType;
        nlaRec->status.dwCurrentState = scm::SERVICE_RUNNING;
        nlaRec->status.dwProcessId = 1130;
        scm.registerServiceRecord(nlaRec);

        // 2. netprofm: Network List Service
        auto netprofRec = std::make_shared<scm::ServiceRecord>();
        netprofRec->serviceName = L"netprofm";
        netprofRec->displayName = L"Network List Service";
        netprofRec->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        netprofRec->startType = scm::SERVICE_DEMAND_START;
        netprofRec->errorControl = scm::SERVICE_ERROR_NORMAL;
        netprofRec->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k LocalService";
        netprofRec->loadOrderGroup = L"LocalService";
        netprofRec->status.dwServiceType = netprofRec->serviceType;
        netprofRec->status.dwCurrentState = scm::SERVICE_RUNNING;
        netprofRec->status.dwProcessId = 1134;
        scm.registerServiceRecord(netprofRec);

        // 3. NcbService: Network Connection Broker
        auto ncbRec = std::make_shared<scm::ServiceRecord>();
        ncbRec->serviceName = L"NcbService";
        ncbRec->displayName = L"Network Connection Broker";
        ncbRec->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        ncbRec->startType = scm::SERVICE_DEMAND_START;
        ncbRec->errorControl = scm::SERVICE_ERROR_NORMAL;
        ncbRec->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted";
        ncbRec->loadOrderGroup = L"LocalSystemNetworkRestricted";
        ncbRec->status.dwServiceType = ncbRec->serviceType;
        ncbRec->status.dwCurrentState = scm::SERVICE_RUNNING;
        ncbRec->status.dwProcessId = 1138;
        scm.registerServiceRecord(ncbRec);
    }

public:
    static NetworkLocationManager& get() noexcept {
        static NetworkLocationManager instance;
        return instance;
    }

    NetworkLocationManager(const NetworkLocationManager&) = delete;
    NetworkLocationManager& operator=(const NetworkLocationManager&) = delete;

    void resetToDefault() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_profiles.clear();
        initDefaultProfiles();
    }

    std::vector<NetworkProfile> getProfiles() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_profiles;
    }

    bool getProfile(const GUID& id, NetworkProfile& out) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& p : m_profiles) {
            if (p.networkId == id) {
                out = p;
                return true;
            }
        }
        return false;
    }

    bool setCategory(const GUID& id, NLM_NETWORK_CATEGORY cat) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& p : m_profiles) {
            if (p.networkId == id) {
                p.category = cat;
                return true;
            }
        }
        return false;
    }

    bool setName(const GUID& id, const std::wstring& name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& p : m_profiles) {
            if (p.networkId == id) {
                p.name = name;
                return true;
            }
        }
        return false;
    }

    bool setDescription(const GUID& id, const std::wstring& desc) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& p : m_profiles) {
            if (p.networkId == id) {
                p.description = desc;
                return true;
            }
        }
        return false;
    }

    uint32_t getOverallConnectivity() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t conn = NLM_CONNECTIVITY_DISCONNECTED;
        for (const auto& p : m_profiles) {
            conn |= p.connectivity;
        }
        return conn;
    }

    bool isConnectedToInternet() const {
        uint32_t conn = getOverallConnectivity();
        return (conn & (NLM_CONNECTIVITY_IPV4_INTERNET | NLM_CONNECTIVITY_IPV6_INTERNET)) != 0;
    }

    bool isConnected() const {
        uint32_t conn = getOverallConnectivity();
        return conn != NLM_CONNECTIVITY_DISCONNECTED;
    }
};

// ============================================================================
// 5. COM Class Implementations
// ============================================================================

class DispatchHelper : public ole32::IDispatch {
public:
    virtual HRESULT __stdcall GetTypeInfoCount(uint32_t* pctinfo) override {
        if (!pctinfo) return E_POINTER;
        *pctinfo = 0;
        return S_OK;
    }
    virtual HRESULT __stdcall GetTypeInfo(uint32_t /*iTInfo*/, LCID /*lcid*/, ITypeInfo** ppTInfo) override {
        if (!ppTInfo) return E_POINTER;
        *ppTInfo = nullptr;
        return E_NOTIMPL;
    }
    virtual HRESULT __stdcall GetIDsOfNames(REFIID /*riid*/, LPOLESTR* /*rgszNames*/, uint32_t /*cNames*/, LCID /*lcid*/, DISPID* /*rgDispId*/) override {
        return E_NOTIMPL;
    }
    virtual HRESULT __stdcall Invoke(DISPID /*dispIdMember*/, REFIID /*riid*/, LCID /*lcid*/, uint16_t /*wFlags*/, DISPPARAMS* /*pDispParams*/, VARIANT* /*pVarResult*/, EXCEPINFO* /*pExcepInfo*/, uint32_t* /*puArgErr*/) override {
        return E_NOTIMPL;
    }
};

class NetworkConnectionImpl : public INetworkConnection {
private:
    std::atomic<uint32_t> m_refCount{1};
    GUID m_networkId{};
    GUID m_connectionId{};
    GUID m_adapterId{};

public:
    NetworkConnectionImpl(const GUID& netId, const GUID& connId, const GUID& adaptId)
        : m_networkId(netId), m_connectionId(connId), m_adapterId(adaptId) {}

    // IUnknown
    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_INetworkConnection) {
            *ppvObject = static_cast<INetworkConnection*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override {
        return ++m_refCount;
    }

    virtual uint32_t __stdcall Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    // IDispatch
    virtual HRESULT __stdcall GetTypeInfoCount(uint32_t* pctinfo) override {
        if (!pctinfo) return E_POINTER;
        *pctinfo = 0;
        return S_OK;
    }
    virtual HRESULT __stdcall GetTypeInfo(uint32_t, LCID, ITypeInfo** ppTInfo) override {
        if (!ppTInfo) return E_POINTER;
        *ppTInfo = nullptr;
        return E_NOTIMPL;
    }
    virtual HRESULT __stdcall GetIDsOfNames(REFIID, LPOLESTR*, uint32_t, LCID, DISPID*) override { return E_NOTIMPL; }
    virtual HRESULT __stdcall Invoke(DISPID, REFIID, LCID, uint16_t, DISPPARAMS*, VARIANT*, EXCEPINFO*, uint32_t*) override { return E_NOTIMPL; }

    // INetworkConnection
    virtual HRESULT __stdcall GetNetwork(INetwork** ppNetwork) override;

    virtual HRESULT __stdcall get_IsConnectedToInternet(VARIANT_BOOL* pbIsConnected) override {
        if (!pbIsConnected) return E_POINTER;
        NetworkProfile prof;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            *pbIsConnected = (prof.connectivity & (NLM_CONNECTIVITY_IPV4_INTERNET | NLM_CONNECTIVITY_IPV6_INTERNET)) ? VARIANT_TRUE : VARIANT_FALSE;
            return S_OK;
        }
        *pbIsConnected = VARIANT_FALSE;
        return S_OK;
    }

    virtual HRESULT __stdcall get_IsConnected(VARIANT_BOOL* pbIsConnected) override {
        if (!pbIsConnected) return E_POINTER;
        NetworkProfile prof;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            *pbIsConnected = (prof.connectivity != NLM_CONNECTIVITY_DISCONNECTED) ? VARIANT_TRUE : VARIANT_FALSE;
            return S_OK;
        }
        *pbIsConnected = VARIANT_FALSE;
        return S_OK;
    }

    virtual HRESULT __stdcall GetConnectivity(NLM_CONNECTIVITY* pConnectivity) override {
        if (!pConnectivity) return E_POINTER;
        NetworkProfile prof;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            *pConnectivity = static_cast<NLM_CONNECTIVITY>(prof.connectivity);
            return S_OK;
        }
        *pConnectivity = NLM_CONNECTIVITY_DISCONNECTED;
        return S_OK;
    }

    virtual HRESULT __stdcall GetConnectionId(GUID* pgdConnectionId) override {
        if (!pgdConnectionId) return E_POINTER;
        *pgdConnectionId = m_connectionId;
        return S_OK;
    }

    virtual HRESULT __stdcall GetAdapterId(GUID* pgdAdapterId) override {
        if (!pgdAdapterId) return E_POINTER;
        *pgdAdapterId = m_adapterId;
        return S_OK;
    }

    virtual HRESULT __stdcall GetDomainType(NLM_DOMAIN_TYPE* pDomainType) override {
        if (!pDomainType) return E_POINTER;
        NetworkProfile prof;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            *pDomainType = prof.domainType;
            return S_OK;
        }
        *pDomainType = NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK;
        return S_OK;
    }
};

class EnumNetworkConnectionsImpl : public IEnumNetworkConnections {
private:
    std::atomic<uint32_t> m_refCount{1};
    std::vector<std::shared_ptr<NetworkConnectionImpl>> m_connections;
    size_t m_cursor{0};

public:
    EnumNetworkConnectionsImpl(std::vector<std::shared_ptr<NetworkConnectionImpl>> conns)
        : m_connections(std::move(conns)) {}

    // IUnknown
    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IEnumNetworkConnections) {
            *ppvObject = static_cast<IEnumNetworkConnections*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override { return ++m_refCount; }
    virtual uint32_t __stdcall Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    // IDispatch
    virtual HRESULT __stdcall GetTypeInfoCount(uint32_t* pctinfo) override { if (!pctinfo) return E_POINTER; *pctinfo = 0; return S_OK; }
    virtual HRESULT __stdcall GetTypeInfo(uint32_t, LCID, ITypeInfo** ppTInfo) override { if (!ppTInfo) return E_POINTER; *ppTInfo = nullptr; return E_NOTIMPL; }
    virtual HRESULT __stdcall GetIDsOfNames(REFIID, LPOLESTR*, uint32_t, LCID, DISPID*) override { return E_NOTIMPL; }
    virtual HRESULT __stdcall Invoke(DISPID, REFIID, LCID, uint16_t, DISPPARAMS*, VARIANT*, EXCEPINFO*, uint32_t*) override { return E_NOTIMPL; }

    // IEnumNetworkConnections
    virtual HRESULT __stdcall Next(uint32_t celt, INetworkConnection** rgelt, uint32_t* pceltFetched) override {
        if (!rgelt) return E_POINTER;
        uint32_t fetched = 0;
        while (m_cursor < m_connections.size() && fetched < celt) {
            rgelt[fetched] = m_connections[m_cursor].get();
            rgelt[fetched]->AddRef();
            ++m_cursor;
            ++fetched;
        }
        if (pceltFetched) *pceltFetched = fetched;
        return (fetched == celt) ? S_OK : S_FALSE;
    }

    virtual HRESULT __stdcall Skip(uint32_t celt) override {
        m_cursor = std::min(m_cursor + celt, m_connections.size());
        return S_OK;
    }

    virtual HRESULT __stdcall Reset() override {
        m_cursor = 0;
        return S_OK;
    }

    virtual HRESULT __stdcall Clone(IEnumNetworkConnections** ppEnum) override {
        if (!ppEnum) return E_POINTER;
        auto clone = new EnumNetworkConnectionsImpl(m_connections);
        clone->m_cursor = m_cursor;
        *ppEnum = clone;
        return S_OK;
    }
};

class NetworkImpl : public INetwork {
private:
    std::atomic<uint32_t> m_refCount{1};
    GUID m_networkId{};

public:
    explicit NetworkImpl(const GUID& id) : m_networkId(id) {}

    // IUnknown
    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_INetwork) {
            *ppvObject = static_cast<INetwork*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override { return ++m_refCount; }
    virtual uint32_t __stdcall Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    // IDispatch
    virtual HRESULT __stdcall GetTypeInfoCount(uint32_t* pctinfo) override { if (!pctinfo) return E_POINTER; *pctinfo = 0; return S_OK; }
    virtual HRESULT __stdcall GetTypeInfo(uint32_t, LCID, ITypeInfo** ppTInfo) override { if (!ppTInfo) return E_POINTER; *ppTInfo = nullptr; return E_NOTIMPL; }
    virtual HRESULT __stdcall GetIDsOfNames(REFIID, LPOLESTR*, uint32_t, LCID, DISPID*) override { return E_NOTIMPL; }
    virtual HRESULT __stdcall Invoke(DISPID, REFIID, LCID, uint16_t, DISPPARAMS*, VARIANT*, EXCEPINFO*, uint32_t*) override { return E_NOTIMPL; }

    // INetwork
    virtual HRESULT __stdcall GetName(BSTR* pszNetworkName) override {
        if (!pszNetworkName) return E_POINTER;
        NetworkProfile prof;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            *pszNetworkName = ole32::SysAllocString(prof.name.c_str());
            return S_OK;
        }
        *pszNetworkName = nullptr;
        return E_FAIL;
    }

    virtual HRESULT __stdcall SetName(BSTR szNetworkName) override {
        if (!szNetworkName) return E_POINTER;
        NetworkLocationManager::get().setName(m_networkId, szNetworkName);
        return S_OK;
    }

    virtual HRESULT __stdcall GetDescription(BSTR* pszDescription) override {
        if (!pszDescription) return E_POINTER;
        NetworkProfile prof;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            *pszDescription = ole32::SysAllocString(prof.description.c_str());
            return S_OK;
        }
        *pszDescription = nullptr;
        return E_FAIL;
    }

    virtual HRESULT __stdcall SetDescription(BSTR szDescription) override {
        if (!szDescription) return E_POINTER;
        NetworkLocationManager::get().setDescription(m_networkId, szDescription);
        return S_OK;
    }

    virtual HRESULT __stdcall GetNetworkId(GUID* pgdGuidNetworkId) override {
        if (!pgdGuidNetworkId) return E_POINTER;
        *pgdGuidNetworkId = m_networkId;
        return S_OK;
    }

    virtual HRESULT __stdcall GetDomainType(NLM_DOMAIN_TYPE* pNetworkType) override {
        if (!pNetworkType) return E_POINTER;
        NetworkProfile prof;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            *pNetworkType = prof.domainType;
            return S_OK;
        }
        *pNetworkType = NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK;
        return S_OK;
    }

    virtual HRESULT __stdcall GetNetworkConnections(IEnumNetworkConnections** ppEnumNetworkConnection) override {
        if (!ppEnumNetworkConnection) return E_POINTER;
        NetworkProfile prof;
        std::vector<std::shared_ptr<NetworkConnectionImpl>> conns;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            conns.push_back(std::make_shared<NetworkConnectionImpl>(prof.networkId, prof.connectionId, prof.adapterId));
        }
        *ppEnumNetworkConnection = new EnumNetworkConnectionsImpl(conns);
        return S_OK;
    }

    virtual HRESULT __stdcall GetTimeCreatedAndConnected(
        uint32_t* pdwLowDateTimeCreated, uint32_t* pdwHighDateTimeCreated,
        uint32_t* pdwLowDateTimeConnected, uint32_t* pdwHighDateTimeConnected
    ) override {
        NetworkProfile prof;
        if (!NetworkLocationManager::get().getProfile(m_networkId, prof)) return E_FAIL;
        if (pdwLowDateTimeCreated) *pdwLowDateTimeCreated = prof.timeCreatedLow;
        if (pdwHighDateTimeCreated) *pdwHighDateTimeCreated = prof.timeCreatedHigh;
        if (pdwLowDateTimeConnected) *pdwLowDateTimeConnected = prof.timeConnectedLow;
        if (pdwHighDateTimeConnected) *pdwHighDateTimeConnected = prof.timeConnectedHigh;
        return S_OK;
    }

    virtual HRESULT __stdcall get_IsConnectedToInternet(VARIANT_BOOL* pbIsConnected) override {
        if (!pbIsConnected) return E_POINTER;
        NetworkProfile prof;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            *pbIsConnected = (prof.connectivity & (NLM_CONNECTIVITY_IPV4_INTERNET | NLM_CONNECTIVITY_IPV6_INTERNET)) ? VARIANT_TRUE : VARIANT_FALSE;
            return S_OK;
        }
        *pbIsConnected = VARIANT_FALSE;
        return S_OK;
    }

    virtual HRESULT __stdcall get_IsConnected(VARIANT_BOOL* pbIsConnected) override {
        if (!pbIsConnected) return E_POINTER;
        NetworkProfile prof;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            *pbIsConnected = (prof.connectivity != NLM_CONNECTIVITY_DISCONNECTED) ? VARIANT_TRUE : VARIANT_FALSE;
            return S_OK;
        }
        *pbIsConnected = VARIANT_FALSE;
        return S_OK;
    }

    virtual HRESULT __stdcall GetConnectivity(NLM_CONNECTIVITY* pConnectivity) override {
        if (!pConnectivity) return E_POINTER;
        NetworkProfile prof;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            *pConnectivity = static_cast<NLM_CONNECTIVITY>(prof.connectivity);
            return S_OK;
        }
        *pConnectivity = NLM_CONNECTIVITY_DISCONNECTED;
        return S_OK;
    }

    virtual HRESULT __stdcall GetCategory(NLM_NETWORK_CATEGORY* pCategory) override {
        if (!pCategory) return E_POINTER;
        NetworkProfile prof;
        if (NetworkLocationManager::get().getProfile(m_networkId, prof)) {
            *pCategory = prof.category;
            return S_OK;
        }
        *pCategory = NLM_NETWORK_CATEGORY_PUBLIC;
        return S_OK;
    }

    virtual HRESULT __stdcall SetCategory(NLM_NETWORK_CATEGORY NewCategory) override {
        return NetworkLocationManager::get().setCategory(m_networkId, NewCategory) ? S_OK : E_FAIL;
    }
};

inline HRESULT __stdcall NetworkConnectionImpl::GetNetwork(INetwork** ppNetwork) {
    if (!ppNetwork) return E_POINTER;
    *ppNetwork = new NetworkImpl(m_networkId);
    return S_OK;
}

class EnumNetworksImpl : public IEnumNetworks {
private:
    std::atomic<uint32_t> m_refCount{1};
    std::vector<std::shared_ptr<NetworkImpl>> m_networks;
    size_t m_cursor{0};

public:
    explicit EnumNetworksImpl(std::vector<std::shared_ptr<NetworkImpl>> nets)
        : m_networks(std::move(nets)) {}

    // IUnknown
    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_IEnumNetworks) {
            *ppvObject = static_cast<IEnumNetworks*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override { return ++m_refCount; }
    virtual uint32_t __stdcall Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    // IDispatch
    virtual HRESULT __stdcall GetTypeInfoCount(uint32_t* pctinfo) override { if (!pctinfo) return E_POINTER; *pctinfo = 0; return S_OK; }
    virtual HRESULT __stdcall GetTypeInfo(uint32_t, LCID, ITypeInfo** ppTInfo) override { if (!ppTInfo) return E_POINTER; *ppTInfo = nullptr; return E_NOTIMPL; }
    virtual HRESULT __stdcall GetIDsOfNames(REFIID, LPOLESTR*, uint32_t, LCID, DISPID*) override { return E_NOTIMPL; }
    virtual HRESULT __stdcall Invoke(DISPID, REFIID, LCID, uint16_t, DISPPARAMS*, VARIANT*, EXCEPINFO*, uint32_t*) override { return E_NOTIMPL; }

    // IEnumNetworks
    virtual HRESULT __stdcall Next(uint32_t celt, INetwork** rgelt, uint32_t* pceltFetched) override {
        if (!rgelt) return E_POINTER;
        uint32_t fetched = 0;
        while (m_cursor < m_networks.size() && fetched < celt) {
            rgelt[fetched] = m_networks[m_cursor].get();
            rgelt[fetched]->AddRef();
            ++m_cursor;
            ++fetched;
        }
        if (pceltFetched) *pceltFetched = fetched;
        return (fetched == celt) ? S_OK : S_FALSE;
    }

    virtual HRESULT __stdcall Skip(uint32_t celt) override {
        m_cursor = std::min(m_cursor + celt, m_networks.size());
        return S_OK;
    }

    virtual HRESULT __stdcall Reset() override {
        m_cursor = 0;
        return S_OK;
    }

    virtual HRESULT __stdcall Clone(IEnumNetworks** ppEnumNetwork) override {
        if (!ppEnumNetwork) return E_POINTER;
        auto clone = new EnumNetworksImpl(m_networks);
        clone->m_cursor = m_cursor;
        *ppEnumNetwork = clone;
        return S_OK;
    }
};

class NetworkListManagerImpl : public INetworkListManager, public INetworkCostManager {
private:
    std::atomic<uint32_t> m_refCount{1};

public:
    NetworkListManagerImpl() = default;

    // IUnknown
    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDispatch || riid == IID_INetworkListManager) {
            *ppvObject = static_cast<INetworkListManager*>(this);
            AddRef();
            return S_OK;
        }
        if (riid == IID_INetworkCostManager) {
            *ppvObject = static_cast<INetworkCostManager*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override { return ++m_refCount; }
    virtual uint32_t __stdcall Release() override {
        uint32_t c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }

    // IDispatch
    virtual HRESULT __stdcall GetTypeInfoCount(uint32_t* pctinfo) override { if (!pctinfo) return E_POINTER; *pctinfo = 0; return S_OK; }
    virtual HRESULT __stdcall GetTypeInfo(uint32_t, LCID, ITypeInfo** ppTInfo) override { if (!ppTInfo) return E_POINTER; *ppTInfo = nullptr; return E_NOTIMPL; }
    virtual HRESULT __stdcall GetIDsOfNames(REFIID, LPOLESTR*, uint32_t, LCID, DISPID*) override { return E_NOTIMPL; }
    virtual HRESULT __stdcall Invoke(DISPID, REFIID, LCID, uint16_t, DISPPARAMS*, VARIANT*, EXCEPINFO*, uint32_t*) override { return E_NOTIMPL; }

    // INetworkListManager
    virtual HRESULT __stdcall GetNetworks(NLM_ENUM_NETWORK Flags, IEnumNetworks** ppEnumNetwork) override {
        if (!ppEnumNetwork) return E_POINTER;
        auto profiles = NetworkLocationManager::get().getProfiles();
        std::vector<std::shared_ptr<NetworkImpl>> matching;
        for (const auto& p : profiles) {
            bool isConn = (p.connectivity != NLM_CONNECTIVITY_DISCONNECTED);
            if ((Flags & NLM_ENUM_NETWORK_CONNECTED) && isConn) {
                matching.push_back(std::make_shared<NetworkImpl>(p.networkId));
            } else if ((Flags & NLM_ENUM_NETWORK_DISCONNECTED) && !isConn) {
                matching.push_back(std::make_shared<NetworkImpl>(p.networkId));
            } else if (Flags == NLM_ENUM_NETWORK_ALL) {
                matching.push_back(std::make_shared<NetworkImpl>(p.networkId));
            }
        }
        *ppEnumNetwork = new EnumNetworksImpl(matching);
        return S_OK;
    }

    virtual HRESULT __stdcall GetNetwork(GUID gdNetworkId, INetwork** ppNetwork) override {
        if (!ppNetwork) return E_POINTER;
        NetworkProfile prof;
        if (!NetworkLocationManager::get().getProfile(gdNetworkId, prof)) {
            *ppNetwork = nullptr;
            return E_INVALIDARG;
        }
        *ppNetwork = new NetworkImpl(gdNetworkId);
        return S_OK;
    }

    virtual HRESULT __stdcall GetNetworkConnections(IEnumNetworkConnections** ppEnum) override {
        if (!ppEnum) return E_POINTER;
        auto profiles = NetworkLocationManager::get().getProfiles();
        std::vector<std::shared_ptr<NetworkConnectionImpl>> conns;
        for (const auto& p : profiles) {
            conns.push_back(std::make_shared<NetworkConnectionImpl>(p.networkId, p.connectionId, p.adapterId));
        }
        *ppEnum = new EnumNetworkConnectionsImpl(conns);
        return S_OK;
    }

    virtual HRESULT __stdcall GetNetworkConnection(GUID gdNetworkConnectionId, INetworkConnection** ppNetworkConnection) override {
        if (!ppNetworkConnection) return E_POINTER;
        auto profiles = NetworkLocationManager::get().getProfiles();
        for (const auto& p : profiles) {
            if (p.connectionId == gdNetworkConnectionId) {
                *ppNetworkConnection = new NetworkConnectionImpl(p.networkId, p.connectionId, p.adapterId);
                return S_OK;
            }
        }
        *ppNetworkConnection = nullptr;
        return E_INVALIDARG;
    }

    virtual HRESULT __stdcall get_IsConnectedToInternet(VARIANT_BOOL* pbIsConnected) override {
        if (!pbIsConnected) return E_POINTER;
        *pbIsConnected = NetworkLocationManager::get().isConnectedToInternet() ? VARIANT_TRUE : VARIANT_FALSE;
        return S_OK;
    }

    virtual HRESULT __stdcall get_IsConnected(VARIANT_BOOL* pbIsConnected) override {
        if (!pbIsConnected) return E_POINTER;
        *pbIsConnected = NetworkLocationManager::get().isConnected() ? VARIANT_TRUE : VARIANT_FALSE;
        return S_OK;
    }

    virtual HRESULT __stdcall GetConnectivity(NLM_CONNECTIVITY* pConnectivity) override {
        if (!pConnectivity) return E_POINTER;
        *pConnectivity = static_cast<NLM_CONNECTIVITY>(NetworkLocationManager::get().getOverallConnectivity());
        return S_OK;
    }

    // INetworkCostManager
    virtual HRESULT __stdcall GetCost(uint32_t* pCost, NLM_CONNECTION_COST_DATA* pData) override {
        if (!pCost) return E_POINTER;
        *pCost = NLM_CONNECTION_COST_UNRESTRICTED;
        if (pData) {
            pData->ConnectionCost = NLM_CONNECTION_COST_UNRESTRICTED;
            pData->CostFlags = 0;
        }
        return S_OK;
    }

    virtual HRESULT __stdcall GetDataPlanStatus(NLM_DATAPLAN_STATUS* pDataPlanStatus, void* /*pInterfaceKey*/) override {
        if (!pDataPlanStatus) return E_POINTER;
        std::memset(pDataPlanStatus, 0, sizeof(NLM_DATAPLAN_STATUS));
        pDataPlanStatus->DataLimitInMegabytes = 51200; // 50 GB
        pDataPlanStatus->UsageData.UsageInMegabytes = 1240;
        pDataPlanStatus->InboundBandwidthInKbps = 1000000; // 1 Gbps
        pDataPlanStatus->OutboundBandwidthInKbps = 1000000;
        return S_OK;
    }

    virtual HRESULT __stdcall SetDestinationAddresses(uint32_t /*length*/, void* /*pDestAddresses*/, VARIANT_BOOL /*bInclude*/) override {
        return S_OK;
    }
};

// ============================================================================
// 6. COM Class Factory & Dynamic Loader / SCM Integration
// ============================================================================

class NetworkListManagerClassFactory : public ole32::IClassFactory {
private:
    std::atomic<uint32_t> m_refCount{1};

public:
    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppvObject = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override { return ++m_refCount; }
    virtual uint32_t __stdcall Release() override { return --m_refCount; }

    virtual HRESULT __stdcall CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        if (!ppvObject) return E_POINTER;
        auto mgr = new NetworkListManagerImpl();
        HRESULT hr = mgr->QueryInterface(riid, ppvObject);
        mgr->Release();
        return hr;
    }

    virtual HRESULT __stdcall LockServer(int32_t /*fLock*/) override {
        return S_OK;
    }
};

inline HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;
    if (rclsid == CLSID_NetworkListManager) {
        static NetworkListManagerClassFactory factory;
        return factory.QueryInterface(riid, ppv);
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

inline HRESULT __stdcall DllCanUnloadNow() {
    return S_OK;
}

inline HRESULT __stdcall DllRegisterServer() {
    return S_OK;
}

inline HRESULT __stdcall DllUnregisterServer() {
    return S_OK;
}

inline uint32_t __stdcall NlaGetNetworkProfiles(NetworkProfile* pProfiles, uint32_t* pcProfiles) {
    if (!pcProfiles) return 1; // ERROR_INVALID_PARAMETER
    auto profs = NetworkLocationManager::get().getProfiles();
    if (!pProfiles || *pcProfiles < profs.size()) {
        *pcProfiles = static_cast<uint32_t>(profs.size());
        return 0; // S_OK / size returned
    }
    for (size_t i = 0; i < profs.size(); ++i) {
        pProfiles[i] = profs[i];
    }
    *pcProfiles = static_cast<uint32_t>(profs.size());
    return 0;
}

inline HRESULT __stdcall NlsGetInterfaceGuidFromInterfaceIndex(uint32_t ifIndex, GUID* pInterfaceGuid) {
    if (!pInterfaceGuid) return ole32::E_POINTER;
    auto profs = NetworkLocationManager::get().getProfiles();
    if (ifIndex > 0 && ifIndex <= profs.size()) {
        *pInterfaceGuid = profs[ifIndex - 1].adapterId;
        return ole32::S_OK;
    }
    *pInterfaceGuid = { 0x11112222, 0x3333, 0x4444, { 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88 } };
    return ole32::S_OK;
}

inline HRESULT __stdcall NlsFreeInterfaceGuid(GUID* pInterfaceGuid) {
    if (pInterfaceGuid) {
        *pInterfaceGuid = GUID{};
    }
    return ole32::S_OK;
}

inline HRESULT __stdcall NlsUpdateInterfaceCostCache(const GUID* pInterfaceGuid, uint32_t cost) {
    (void)pInterfaceGuid;
    (void)cost;
    return ole32::S_OK;
}

inline void __stdcall SvchostPushServiceGlobals(void* /*pGlobals*/) {
}

inline void InitializeNlaSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // 1. netprofm.dll (Network List Manager COM Server)
    ldr.registerExport("netprofm.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));
    ldr.registerExport("netprofm.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));
    ldr.registerExport("netprofm.dll", "DllRegisterServer", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("netprofm.dll", "DllUnregisterServer", reinterpret_cast<void*>(DllUnregisterServer));

    // 2. nlasvc.dll (Network Location Awareness Service)
    ldr.registerExport("nlasvc.dll", "ServiceMain", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("nlasvc.dll", "SvchostPushServiceGlobals", reinterpret_cast<void*>(SvchostPushServiceGlobals));
    ldr.registerExport("nlasvc.dll", "NlaGetNetworkProfiles", reinterpret_cast<void*>(NlaGetNetworkProfiles));

    // 3. ncbservice.dll (Network Connection Broker)
    ldr.registerExport("ncbservice.dll", "ServiceMain", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("ncbservice.dll", "SvchostPushServiceGlobals", reinterpret_cast<void*>(SvchostPushServiceGlobals));
    ldr.registerExport("ncbservice.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));

    // 4. nlaapi.dll (NLA Client API)
    ldr.registerExport("nlaapi.dll", "NlsGetInterfaceGuidFromInterfaceIndex", reinterpret_cast<void*>(NlsGetInterfaceGuidFromInterfaceIndex));
    ldr.registerExport("nlaapi.dll", "NlsFreeInterfaceGuid", reinterpret_cast<void*>(NlsFreeInterfaceGuid));
    ldr.registerExport("nlaapi.dll", "NlsUpdateInterfaceCostCache", reinterpret_cast<void*>(NlsUpdateInterfaceCostCache));
    ldr.registerExport("nlaapi.dll", "NlaGetNetworkProfiles", reinterpret_cast<void*>(NlaGetNetworkProfiles));

    // Register CLSID_NetworkListManager Class Factory in ole32 COM runtime
    static NetworkListManagerClassFactory s_nlmFactory;
    uint32_t cookie = 0;
    (void)ole32::CoRegisterClassObject(
        CLSID_NetworkListManager,
        &s_nlmFactory,
        ole32::CLSCTX_INPROC_SERVER,
        ole32::REGCLS_MULTIPLEUSE,
        &cookie
    );

    // Trigger sovereign initialization & SCM service registrations
    NetworkLocationManager::get();
}

} // namespace micant::nla
