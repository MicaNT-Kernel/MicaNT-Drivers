// ============================================================================
// MicaNT: Windows Security Center (WSC) & Health Aggregation Subsystem
// (include/micant/wscapi.hpp)
//
// Sovereign Subsystem: SentinelCenter
//
// Strict Clean-Room Implementation based on:
//   - Microsoft Windows Security Center Architecture Specification (wscapi.dll / wscsvc)
//   - Win32 Windows Security Center Management API (wscapi.h) C ABI
//   - Windows Security Center COM Interfaces (IWscProduct, IWscProduct2, IWscProduct3, IWscProductList)
//   - Google LLC v. Oracle America, Inc. & Sega v. Accolade interoperability doctrine
//
// Subsystem Overview:
//   wscapi.hpp provides the clean-room Windows Security Center subsystem
//   (wscapi.dll) for MicaNT, codenamed "SentinelCenter". It serves as the
//   central health and status aggregator for all endpoint security subsystems,
//   including:
//     * Windows Filtering Platform & Firewall (micant::wfp)
//     * Antivirus & Antimalware Protection (AegisDefender / ci.hpp)
//     * AntiSpyware Protection
//     * Full Volume Encryption (BitLocker / fveapi.hpp)
//     * Servicing & Automatic Update Stack (cbs.hpp)
//     * User Account Control (UAC / SAM)
//     * Security Center Core Service (wscsvc)
//
// Features:
//   - Native Win32 Windows Security Center C ABI (wscapi.dll):
//       * WscGetSecurityProviderHealth
//       * WscRegisterForChanges
//       * WscUnRegisterChanges
//       * WscQueryAntiVirusStatus
//       * WscRegisterProduct
//       * WscUnregisterProduct
//       * WscUpdateProductStatus
//       * WscGetAntiVirusProducts
//       * WscFreeMemory
//   - Standard WSC Provider Bitmasks (WSC_SECURITY_PROVIDER):
//       * WSC_SECURITY_PROVIDER_FIREWALL (0x1)
//       * WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS (0x2)
//       * WSC_SECURITY_PROVIDER_ANTIVIRUS (0x4)
//       * WSC_SECURITY_PROVIDER_ANTISPYWARE (0x8)
//       * WSC_SECURITY_PROVIDER_INTERNET_SETTINGS (0x10)
//       * WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL (0x20)
//       * WSC_SECURITY_PROVIDER_SERVICE (0x40)
//       * WSC_SECURITY_PROVIDER_ALL (0x7F)
//   - Standard Health States (WSC_SECURITY_PROVIDER_HEALTH):
//       * WSC_SECURITY_PROVIDER_HEALTH_GOOD (0)
//       * WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED (1)
//       * WSC_SECURITY_PROVIDER_HEALTH_POOR (2)
//       * WSC_SECURITY_PROVIDER_HEALTH_SNOOZE (3)
//   - Standard Product States & Substatus (WSC_SECURITY_PRODUCT_STATE / SUBSTATUS):
//       * WSC_SECURITY_PRODUCT_STATE_ON (0), OFF (1), SNOOZED (2), EXPIRED (3)
//       * WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION (1), ACTION_RECOMMENDED (2), ACTION_NEEDED (3)
//   - Full COM Interfaces:
//       * IWscProduct (PackageName, ProductState, SignatureStatus, RemediationPath, Guid)
//       * IWscProduct2 (AntivirusScanSubstatus, EngineVersion, SignatureVersion)
//       * IWscProduct3 (ProductReportingStatus)
//       * IWSCProductList (Initialize, Count, Item)
//   - DynamicLoader export registration into "wscapi.dll".
//   - VersionDatabase registration ("wscapi.dll", "10.0.26100.1").
//
// Core Dynamic Module:
//   - wscapi.dll
//
// Trademark & Nominative Fair Use Notice:
//   Microsoft, Windows, Windows Security Center, and Windows Defender are trademarks
//   or registered trademarks of Microsoft Corp. MicaNT SentinelCenter is an independent,
//   clean-room sovereign implementation engineered from first principles solely for
//   binary interoperability (*Google LLC v. Oracle America, Inc.*).
//   No proprietary Microsoft source code or binaries are used or contained herein.
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "kernel32.hpp"
#include "ldr.hpp"
#include "version.hpp"
#include "ole32.hpp"
#include "fwpuclnt.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <functional>
#include <optional>
#include <chrono>

namespace micant::wsc {

// ============================================================================
// 1. Standard Win32 Types, Enums & Constants (wscapi.h)
// ============================================================================

using DWORD     = uint32_t;
using PDWORD    = uint32_t*;
using HANDLE    = void*;
using PHANDLE   = void**;
using HRESULT   = int32_t;
using BOOL      = int32_t;
using LONG      = int32_t;
using ULONG     = uint32_t;
using LPVOID    = void*;
using PVOID     = void*;
using LPCWSTR   = const wchar_t*;
using LPWSTR    = wchar_t*;
using GUID      = micant::GUID;
using BSTR      = wchar_t*;
using LPTHREAD_START_ROUTINE = uint32_t (__stdcall *)(void*);

#ifndef WINAPI
#define WINAPI __stdcall
#endif

// HRESULT Success & Error Codes
inline constexpr HRESULT S_OK                     = 0;
inline constexpr HRESULT S_FALSE                  = 1;
inline constexpr HRESULT E_FAIL                   = static_cast<HRESULT>(0x80004005);
inline constexpr HRESULT E_POINTER                = static_cast<HRESULT>(0x80004003);
inline constexpr HRESULT E_INVALIDARG             = static_cast<HRESULT>(0x80070057);
inline constexpr HRESULT E_NOINTERFACE            = static_cast<HRESULT>(0x80004002);
inline constexpr HRESULT E_OUTOFMEMORY            = static_cast<HRESULT>(0x8007000E);
inline constexpr HRESULT HRESULT_FROM_WIN32_NOT_FOUND = static_cast<HRESULT>(0x80070490); // ERROR_NOT_FOUND
inline constexpr HRESULT HRESULT_FROM_WIN32_INVALID_HANDLE = static_cast<HRESULT>(0x80070006); // ERROR_INVALID_HANDLE

// WSC_SECURITY_PROVIDER Bitmask Flags
inline constexpr DWORD WSC_SECURITY_PROVIDER_NONE                 = 0x00;
inline constexpr DWORD WSC_SECURITY_PROVIDER_FIREWALL             = 0x01;
inline constexpr DWORD WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS  = 0x02;
inline constexpr DWORD WSC_SECURITY_PROVIDER_ANTIVIRUS            = 0x04;
inline constexpr DWORD WSC_SECURITY_PROVIDER_ANTISPYWARE          = 0x08;
inline constexpr DWORD WSC_SECURITY_PROVIDER_INTERNET_SETTINGS    = 0x10;
inline constexpr DWORD WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL = 0x20;
inline constexpr DWORD WSC_SECURITY_PROVIDER_SERVICE              = 0x40;
inline constexpr DWORD WSC_SECURITY_PROVIDER_ALL                  = 0x7F;

// WSC_SECURITY_PROVIDER_HEALTH
enum WSC_SECURITY_PROVIDER_HEALTH : DWORD {
    WSC_SECURITY_PROVIDER_HEALTH_GOOD         = 0,
    WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED = 1,
    WSC_SECURITY_PROVIDER_HEALTH_POOR         = 2,
    WSC_SECURITY_PROVIDER_HEALTH_SNOOZE       = 3
};
using PWSC_SECURITY_PROVIDER_HEALTH = WSC_SECURITY_PROVIDER_HEALTH*;

// WSC_SECURITY_PRODUCT_STATE
enum WSC_SECURITY_PRODUCT_STATE : DWORD {
    WSC_SECURITY_PRODUCT_STATE_ON      = 0,
    WSC_SECURITY_PRODUCT_STATE_OFF     = 1,
    WSC_SECURITY_PRODUCT_STATE_SNOOZED = 2,
    WSC_SECURITY_PRODUCT_STATE_EXPIRED = 3
};
using PWSC_SECURITY_PRODUCT_STATE = WSC_SECURITY_PRODUCT_STATE*;

// WSC_SECURITY_PRODUCT_SUBSTATUS
enum WSC_SECURITY_PRODUCT_SUBSTATUS : DWORD {
    WSC_SECURITY_PRODUCT_SUBSTATUS_NOT_SET            = 0,
    WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION          = 1,
    WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED = 2,
    WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_NEEDED      = 3
};
using PWSC_SECURITY_PRODUCT_SUBSTATUS = WSC_SECURITY_PRODUCT_SUBSTATUS*;

// WSC Antivirus Status Bitmask Flags (WscQueryAntiVirusStatus)
inline constexpr DWORD WSC_AV_STATUS_ON                    = 0x0001; // Bit 0: Product State On
inline constexpr DWORD WSC_AV_STATUS_SIGNATURE_UPTODATE    = 0x0010; // Bit 4: Signatures Up to Date
inline constexpr DWORD WSC_AV_STATUS_RTP_ENABLED           = 0x0100; // Bit 8: Real-Time Protection Active
inline constexpr DWORD WSC_AV_STATUS_PROVIDER_ANTIVIRUS    = 0x00040000; // Bits 16-19: Provider Type (0x4)

// COM Interface GUIDs
// IID_IWscProduct: {8C38232E-3A45-4A27-92B0-1A16A975F669}
inline constexpr GUID IID_IWscProduct = {
    0x8C38232E, 0x3A45, 0x4A27, { 0x92, 0xB0, 0x1A, 0x16, 0xA9, 0x75, 0xF6, 0x69 }
};

// IID_IWscProduct2: {F8995653-0CE3-4BD4-B89B-153A09043EA5}
inline constexpr GUID IID_IWscProduct2 = {
    0xF8995653, 0x0CE3, 0x4BD4, { 0xB8, 0x9B, 0x15, 0x3A, 0x09, 0x04, 0x3E, 0xA5 }
};

// IID_IWscProduct3: {55BA109C-3C53-421E-9D82-964F6E0863CB}
inline constexpr GUID IID_IWscProduct3 = {
    0x55BA109C, 0x3C53, 0x421E, { 0x9D, 0x82, 0x96, 0x4F, 0x6E, 0x08, 0x63, 0xCB }
};

// IID_IWSCProductList: {7224A849-A2FD-4A3C-9926-1B57E5340E03}
inline constexpr GUID IID_IWSCProductList = {
    0x7224A849, 0xA2FD, 0x4A3C, { 0x99, 0x26, 0x1B, 0x57, 0xE5, 0x34, 0x0E, 0x03 }
};

// CLSID_WSCProductList: {17CD7EDD-9BE3-4370-B533-5FE6D6177EB2}
inline constexpr GUID CLSID_WSCProductList = {
    0x17CD7EDD, 0x9BE3, 0x4370, { 0xB5, 0x33, 0x5F, 0xE6, 0xD6, 0x17, 0x7E, 0xB2 }
};

// Helper: GUID to string
inline std::wstring GuidToWString(const GUID& g) {
    wchar_t buf[40]{};
    swprintf(buf, 40, L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             g.Data1, g.Data2, g.Data3,
             g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
             g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return std::wstring(buf);
}

inline std::string GuidToString(const GUID& g) {
    char buf[40]{};
    snprintf(buf, 40, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
             g.Data1, g.Data2, g.Data3,
             g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
             g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return std::string(buf);
}

inline bool operator<(const GUID& a, const GUID& b) noexcept {
    if (a.Data1 != b.Data1) return a.Data1 < b.Data1;
    if (a.Data2 != b.Data2) return a.Data2 < b.Data2;
    if (a.Data3 != b.Data3) return a.Data3 < b.Data3;
    for (int i = 0; i < 8; ++i) {
        if (a.Data4[i] != b.Data4[i]) return a.Data4[i] < b.Data4[i];
    }
    return false;
}

// ============================================================================
// 2. Security Product Registration Structure
// ============================================================================

struct WscProductEntry {
    GUID productGuid{};
    std::wstring productName;
    DWORD providerType{ WSC_SECURITY_PROVIDER_ANTIVIRUS };
    std::wstring pathToProduct;
    std::wstring pathToSettings;
    WSC_SECURITY_PRODUCT_STATE state{ WSC_SECURITY_PRODUCT_STATE_ON };
    bool signatureUpToDate{ true };
    bool realTimeProtectionEnabled{ true };
    uint64_t stateTimestamp{ 0 };
    std::wstring engineVersion{ L"1.411.890.0" };
    std::wstring signatureVersion{ L"1.411.890.0" };
    DWORD reportingFlags{ 0 };
};

// ============================================================================
// 3. COM Interface Definitions (IWscProduct, IWscProduct2, IWscProduct3, IWSCProductList)
// ============================================================================

class IWscProduct : public ole32::IUnknown {
public:
    virtual HRESULT WINAPI get_PackageName(BSTR* pVal) = 0;
    virtual HRESULT WINAPI get_ProductState(WSC_SECURITY_PRODUCT_STATE* pVal) = 0;
    virtual HRESULT WINAPI get_SignatureStatus(WSC_SECURITY_PRODUCT_SUBSTATUS* pVal) = 0;
    virtual HRESULT WINAPI get_RemediationPath(BSTR* pVal) = 0;
    virtual HRESULT WINAPI get_ProductGuid(BSTR* pVal) = 0;
    virtual HRESULT WINAPI get_ProductStateTimestamp(BSTR* pVal) = 0;
};

class IWscProduct2 : public IWscProduct {
public:
    virtual HRESULT WINAPI get_AntivirusScanSubstatus(WSC_SECURITY_PRODUCT_SUBSTATUS* pVal) = 0;
    virtual HRESULT WINAPI get_EngineVersion(BSTR* pVal) = 0;
    virtual HRESULT WINAPI get_SignatureVersion(BSTR* pVal) = 0;
};

class IWscProduct3 : public IWscProduct2 {
public:
    virtual HRESULT WINAPI get_ProductReportingStatus(DWORD* pVal) = 0;
};

class IWSCProductList : public ole32::IUnknown {
public:
    virtual HRESULT WINAPI Initialize(DWORD provider) = 0;
    virtual HRESULT WINAPI get_Count(LONG* pVal) = 0;
    virtual HRESULT WINAPI get_Item(ULONG index, IWscProduct** pVal) = 0;
};

// ============================================================================
// 4. COM Implementation Classes (WscProductImpl & WscProductListImpl)
// ============================================================================

class WscProductImpl final : public IWscProduct3 {
public:
    explicit WscProductImpl(WscProductEntry entry)
        : m_refCount(1), m_entry(std::move(entry)) {}

    // IUnknown
    HRESULT WINAPI QueryInterface(const micant::GUID& riid, void** ppvObject) noexcept override {
        if (!ppvObject) return E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IWscProduct ||
            riid == IID_IWscProduct2 || riid == IID_IWscProduct3) {
            *ppvObject = static_cast<IWscProduct3*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG WINAPI AddRef() noexcept override {
        return ++m_refCount;
    }

    ULONG WINAPI Release() noexcept override {
        ULONG count = --m_refCount;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    // IWscProduct
    HRESULT WINAPI get_PackageName(BSTR* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = ole32::SysAllocString(m_entry.productName.c_str());
        return *pVal ? S_OK : E_OUTOFMEMORY;
    }

    HRESULT WINAPI get_ProductState(WSC_SECURITY_PRODUCT_STATE* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = m_entry.state;
        return S_OK;
    }

    HRESULT WINAPI get_SignatureStatus(WSC_SECURITY_PRODUCT_SUBSTATUS* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = m_entry.signatureUpToDate ?
                WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION :
                WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED;
        return S_OK;
    }

    HRESULT WINAPI get_RemediationPath(BSTR* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = ole32::SysAllocString(m_entry.pathToProduct.c_str());
        return *pVal ? S_OK : E_OUTOFMEMORY;
    }

    HRESULT WINAPI get_ProductGuid(BSTR* pVal) override {
        if (!pVal) return E_POINTER;
        std::wstring ws = GuidToWString(m_entry.productGuid);
        *pVal = ole32::SysAllocString(ws.c_str());
        return *pVal ? S_OK : E_OUTOFMEMORY;
    }

    HRESULT WINAPI get_ProductStateTimestamp(BSTR* pVal) override {
        if (!pVal) return E_POINTER;
        wchar_t buf[64]{};
        swprintf(buf, 64, L"%llu", static_cast<unsigned long long>(m_entry.stateTimestamp));
        *pVal = ole32::SysAllocString(buf);
        return *pVal ? S_OK : E_OUTOFMEMORY;
    }

    // IWscProduct2
    HRESULT WINAPI get_AntivirusScanSubstatus(WSC_SECURITY_PRODUCT_SUBSTATUS* pVal) override {
        if (!pVal) return E_POINTER;
        if (m_entry.state == WSC_SECURITY_PRODUCT_STATE_ON && m_entry.realTimeProtectionEnabled) {
            *pVal = WSC_SECURITY_PRODUCT_SUBSTATUS_NO_ACTION;
        } else if (m_entry.state == WSC_SECURITY_PRODUCT_STATE_SNOOZED) {
            *pVal = WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_RECOMMENDED;
        } else {
            *pVal = WSC_SECURITY_PRODUCT_SUBSTATUS_ACTION_NEEDED;
        }
        return S_OK;
    }

    HRESULT WINAPI get_EngineVersion(BSTR* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = ole32::SysAllocString(m_entry.engineVersion.c_str());
        return *pVal ? S_OK : E_OUTOFMEMORY;
    }

    HRESULT WINAPI get_SignatureVersion(BSTR* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = ole32::SysAllocString(m_entry.signatureVersion.c_str());
        return *pVal ? S_OK : E_OUTOFMEMORY;
    }

    // IWscProduct3
    HRESULT WINAPI get_ProductReportingStatus(DWORD* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = m_entry.reportingFlags;
        return S_OK;
    }

private:
    std::atomic<ULONG> m_refCount;
    WscProductEntry m_entry;
};

class WscProductListImpl final : public IWSCProductList {
public:
    WscProductListImpl() : m_refCount(1) {}

    // IUnknown
    HRESULT WINAPI QueryInterface(const micant::GUID& riid, void** ppvObject) noexcept override {
        if (!ppvObject) return E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IWSCProductList) {
            *ppvObject = static_cast<IWSCProductList*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    ULONG WINAPI AddRef() noexcept override {
        return ++m_refCount;
    }

    ULONG WINAPI Release() noexcept override {
        ULONG count = --m_refCount;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    // IWSCProductList
    HRESULT WINAPI Initialize(DWORD provider) override;

    HRESULT WINAPI get_Count(LONG* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = static_cast<LONG>(m_items.size());
        return S_OK;
    }

    HRESULT WINAPI get_Item(ULONG index, IWscProduct** pVal) override {
        if (!pVal) return E_POINTER;
        if (index >= m_items.size()) return E_INVALIDARG;
        *pVal = m_items[index];
        (*pVal)->AddRef();
        return S_OK;
    }

    ~WscProductListImpl() {
        for (auto* item : m_items) {
            if (item) item->Release();
        }
        m_items.clear();
    }

private:
    std::atomic<ULONG> m_refCount;
    std::vector<IWscProduct*> m_items;
};

// ============================================================================
// 5. Sovereign Security Center Manager (SentinelCenter Core Engine)
// ============================================================================

struct WscNotificationSubscription {
    HANDLE handle{ nullptr };
    LPTHREAD_START_ROUTINE callback{ nullptr };
    PVOID context{ nullptr };
};

class SovereignWscManager {
private:
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, WscProductEntry> m_products;
    std::vector<WscNotificationSubscription> m_subscribers;
    uintptr_t m_nextHandleId{ 0x53454E540001ULL }; // 'SENT'

    // Manual test overrides
    std::unordered_map<DWORD, WSC_SECURITY_PROVIDER_HEALTH> m_overrides;

    SovereignWscManager() {
        seedDefaultSecurityProviders();
    }

    void seedDefaultSecurityProviders() {
        // 1. Pre-seed AegisDefender Antivirus & Protection
        WscProductEntry av{};
        av.productGuid = { 0xA301E615, 0x5EC5, 0x4B89, { 0x9B, 0x9D, 0x1C, 0x97, 0xFA, 0x2D, 0x41, 0xA1 } };
        av.productName = L"AegisDefender Antivirus";
        av.providerType = WSC_SECURITY_PROVIDER_ANTIVIRUS | WSC_SECURITY_PROVIDER_ANTISPYWARE;
        av.pathToProduct = L"C:\\Windows\\System32\\SecurityHealth\\AegisDefender.exe";
        av.pathToSettings = L"C:\\Windows\\System32\\SecurityHealth\\AegisDefenderUI.exe";
        av.state = WSC_SECURITY_PRODUCT_STATE_ON;
        av.signatureUpToDate = true;
        av.realTimeProtectionEnabled = true;
        av.stateTimestamp = static_cast<uint64_t>(std::chrono::system_clock::now().time_since_epoch().count());
        av.engineVersion = L"1.411.890.0";
        av.signatureVersion = L"1.411.890.0";
        av.reportingFlags = 0x01;
        m_products[GuidToString(av.productGuid)] = av;

        // 2. Pre-seed MicaNT Sovereign Advanced Firewall
        WscProductEntry fw{};
        fw.productGuid = { 0xF18E9A34, 0x4C21, 0x4E1B, { 0x98, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
        fw.productName = L"MicaNT Sovereign Advanced Firewall";
        fw.providerType = WSC_SECURITY_PROVIDER_FIREWALL;
        fw.pathToProduct = L"C:\\Windows\\System32\\FirewallControlPanel.exe";
        fw.pathToSettings = L"C:\\Windows\\System32\\FirewallControlPanel.exe";
        fw.state = WSC_SECURITY_PRODUCT_STATE_ON;
        fw.signatureUpToDate = true;
        fw.realTimeProtectionEnabled = true;
        fw.stateTimestamp = av.stateTimestamp;
        fw.engineVersion = L"10.0.26100.1";
        fw.signatureVersion = L"10.0.26100.1";
        fw.reportingFlags = 0x01;
        m_products[GuidToString(fw.productGuid)] = fw;

        // 3. Pre-seed MicaNT Servicing & Auto-Update
        WscProductEntry cbs{};
        cbs.productGuid = { 0xC8500001, 0x4D49, 0x4341, { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
        cbs.productName = L"MicaNT Sovereign Servicing Stack";
        cbs.providerType = WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS;
        cbs.pathToProduct = L"C:\\Windows\\System32\\UsoClient.exe";
        cbs.state = WSC_SECURITY_PRODUCT_STATE_ON;
        cbs.signatureUpToDate = true;
        cbs.realTimeProtectionEnabled = true;
        cbs.stateTimestamp = av.stateTimestamp;
        cbs.engineVersion = L"10.0.26100.1";
        m_products[GuidToString(cbs.productGuid)] = cbs;

        // 4. Pre-seed User Account Control (UAC)
        WscProductEntry uac{};
        uac.productGuid = { 0x5A140001, 0x4D49, 0x4341, { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
        uac.productName = L"MicaNT User Account Control";
        uac.providerType = WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL;
        uac.pathToProduct = L"C:\\Windows\\System32\\UserAccountControlSettings.exe";
        uac.state = WSC_SECURITY_PRODUCT_STATE_ON;
        uac.signatureUpToDate = true;
        uac.realTimeProtectionEnabled = true;
        uac.stateTimestamp = av.stateTimestamp;
        uac.engineVersion = L"10.0.26100.1";
        m_products[GuidToString(uac.productGuid)] = uac;

        // 5. Pre-seed Security Center Core Service
        WscProductEntry svc{};
        svc.productGuid = { 0x75C50001, 0x4D49, 0x4341, { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
        svc.productName = L"Windows Security Center Service";
        svc.providerType = WSC_SECURITY_PROVIDER_SERVICE;
        svc.pathToProduct = L"C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted";
        svc.state = WSC_SECURITY_PRODUCT_STATE_ON;
        svc.signatureUpToDate = true;
        svc.realTimeProtectionEnabled = true;
        svc.stateTimestamp = av.stateTimestamp;
        svc.engineVersion = L"10.0.26100.1";
        m_products[GuidToString(svc.productGuid)] = svc;
    }

public:
    static SovereignWscManager& get() {
        static SovereignWscManager s_instance;
        return s_instance;
    }

    // ------------------------------------------------------------------------
    // Provider Health Interrogation Engine
    // ------------------------------------------------------------------------
    WSC_SECURITY_PROVIDER_HEALTH getFirewallHealth() const {
        // Query live state from SovereignWfpManager
        bool enabled = micant::wfp::SovereignWfpManager::get().getProfile(micant::wfp::FW_PROFILE_TYPE_PUBLIC).enabled;
        if (!enabled) return WSC_SECURITY_PROVIDER_HEALTH_POOR;

        // Check if any registered firewall product is in poor or snoozed state
        bool hasProduct = false;
        for (const auto& [_, p] : m_products) {
            if (p.providerType & WSC_SECURITY_PROVIDER_FIREWALL) {
                hasProduct = true;
                if (p.state == WSC_SECURITY_PRODUCT_STATE_OFF || p.state == WSC_SECURITY_PRODUCT_STATE_EXPIRED) {
                    return WSC_SECURITY_PROVIDER_HEALTH_POOR;
                }
                if (p.state == WSC_SECURITY_PRODUCT_STATE_SNOOZED) {
                    return WSC_SECURITY_PROVIDER_HEALTH_SNOOZE;
                }
            }
        }
        return hasProduct ? WSC_SECURITY_PROVIDER_HEALTH_GOOD : WSC_SECURITY_PROVIDER_HEALTH_POOR;
    }

    WSC_SECURITY_PROVIDER_HEALTH getAntivirusHealth() const {
        bool hasProduct = false;
        bool allSnoozed = true;
        bool anyGood = false;

        for (const auto& [_, p] : m_products) {
            if (p.providerType & WSC_SECURITY_PROVIDER_ANTIVIRUS) {
                hasProduct = true;
                if (p.state == WSC_SECURITY_PRODUCT_STATE_ON) {
                    allSnoozed = false;
                    if (p.signatureUpToDate && p.realTimeProtectionEnabled) {
                        anyGood = true;
                    }
                } else if (p.state != WSC_SECURITY_PRODUCT_STATE_SNOOZED) {
                    allSnoozed = false;
                }
            }
        }

        if (!hasProduct) return WSC_SECURITY_PROVIDER_HEALTH_POOR;
        if (anyGood) return WSC_SECURITY_PROVIDER_HEALTH_GOOD;
        if (allSnoozed) return WSC_SECURITY_PROVIDER_HEALTH_SNOOZE;
        return WSC_SECURITY_PROVIDER_HEALTH_POOR;
    }

    WSC_SECURITY_PROVIDER_HEALTH getAntispywareHealth() const {
        return getAntivirusHealth();
    }

    WSC_SECURITY_PROVIDER_HEALTH getAutoUpdateHealth() const {
        for (const auto& [_, p] : m_products) {
            if (p.providerType & WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS) {
                if (p.state == WSC_SECURITY_PRODUCT_STATE_ON) return WSC_SECURITY_PROVIDER_HEALTH_GOOD;
                if (p.state == WSC_SECURITY_PRODUCT_STATE_SNOOZED) return WSC_SECURITY_PROVIDER_HEALTH_SNOOZE;
                return WSC_SECURITY_PROVIDER_HEALTH_POOR;
            }
        }
        return WSC_SECURITY_PROVIDER_HEALTH_GOOD;
    }

    WSC_SECURITY_PROVIDER_HEALTH getUacHealth() const {
        for (const auto& [_, p] : m_products) {
            if (p.providerType & WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) {
                if (p.state == WSC_SECURITY_PRODUCT_STATE_ON) return WSC_SECURITY_PROVIDER_HEALTH_GOOD;
                return WSC_SECURITY_PROVIDER_HEALTH_POOR;
            }
        }
        return WSC_SECURITY_PROVIDER_HEALTH_GOOD;
    }

    WSC_SECURITY_PROVIDER_HEALTH getInternetSettingsHealth() const {
        return WSC_SECURITY_PROVIDER_HEALTH_GOOD;
    }

    WSC_SECURITY_PROVIDER_HEALTH getServiceHealth() const {
        return WSC_SECURITY_PROVIDER_HEALTH_GOOD;
    }

    // Aggregates health across any set of requested providers
    HRESULT getSecurityProviderHealth(DWORD providers, WSC_SECURITY_PROVIDER_HEALTH* pHealth) {
        if (!pHealth) return E_POINTER;
        if (providers == 0 || (providers & ~WSC_SECURITY_PROVIDER_ALL) != 0) {
            return E_INVALIDARG;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        // Precedence: POOR > SNOOZE > NOTMONITORED > GOOD
        WSC_SECURITY_PROVIDER_HEALTH worstHealth = WSC_SECURITY_PROVIDER_HEALTH_GOOD;

        auto evaluateHealth = [&](WSC_SECURITY_PROVIDER_HEALTH h) {
            if (h == WSC_SECURITY_PROVIDER_HEALTH_POOR) {
                worstHealth = WSC_SECURITY_PROVIDER_HEALTH_POOR;
            } else if (h == WSC_SECURITY_PROVIDER_HEALTH_SNOOZE) {
                if (worstHealth != WSC_SECURITY_PROVIDER_HEALTH_POOR) {
                    worstHealth = WSC_SECURITY_PROVIDER_HEALTH_SNOOZE;
                }
            } else if (h == WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED) {
                if (worstHealth == WSC_SECURITY_PROVIDER_HEALTH_GOOD) {
                    worstHealth = WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED;
                }
            }
        };

        if (providers & WSC_SECURITY_PROVIDER_FIREWALL) {
            auto it = m_overrides.find(WSC_SECURITY_PROVIDER_FIREWALL);
            evaluateHealth(it != m_overrides.end() ? it->second : getFirewallHealth());
        }
        if (providers & WSC_SECURITY_PROVIDER_ANTIVIRUS) {
            auto it = m_overrides.find(WSC_SECURITY_PROVIDER_ANTIVIRUS);
            evaluateHealth(it != m_overrides.end() ? it->second : getAntivirusHealth());
        }
        if (providers & WSC_SECURITY_PROVIDER_ANTISPYWARE) {
            auto it = m_overrides.find(WSC_SECURITY_PROVIDER_ANTISPYWARE);
            evaluateHealth(it != m_overrides.end() ? it->second : getAntispywareHealth());
        }
        if (providers & WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS) {
            auto it = m_overrides.find(WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS);
            evaluateHealth(it != m_overrides.end() ? it->second : getAutoUpdateHealth());
        }
        if (providers & WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) {
            auto it = m_overrides.find(WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL);
            evaluateHealth(it != m_overrides.end() ? it->second : getUacHealth());
        }
        if (providers & WSC_SECURITY_PROVIDER_INTERNET_SETTINGS) {
            auto it = m_overrides.find(WSC_SECURITY_PROVIDER_INTERNET_SETTINGS);
            evaluateHealth(it != m_overrides.end() ? it->second : getInternetSettingsHealth());
        }
        if (providers & WSC_SECURITY_PROVIDER_SERVICE) {
            auto it = m_overrides.find(WSC_SECURITY_PROVIDER_SERVICE);
            evaluateHealth(it != m_overrides.end() ? it->second : getServiceHealth());
        }

        *pHealth = worstHealth;
        return S_OK;
    }

    // ------------------------------------------------------------------------
    // Product Registration & Status Tracking
    // ------------------------------------------------------------------------
    HRESULT registerProduct(
        const std::wstring& productName,
        DWORD providerType,
        const std::wstring& pathToProduct,
        WSC_SECURITY_PRODUCT_STATE state,
        bool signatureUpToDate,
        bool realTimeProtection,
        GUID* pOutGuid
    ) {
        if (productName.empty() || !pOutGuid) return E_INVALIDARG;

        std::lock_guard<std::mutex> lock(m_mutex);

        // Generate a new GUID for the product
        GUID g{};
        g.Data1 = 0xA3010000 | (static_cast<uint32_t>(m_products.size() + 1) & 0xFFFF);
        g.Data2 = 0x4D49;
        g.Data3 = 0x4341;
        g.Data4[0] = 0x53; g.Data4[1] = 0x45; g.Data4[2] = 0x4E; g.Data4[3] = 0x54;
        g.Data4[4] = 0x00; g.Data4[5] = 0x00; g.Data4[6] = 0x00;
        g.Data4[7] = static_cast<uint8_t>(m_products.size() + 1);

        WscProductEntry entry{};
        entry.productGuid = g;
        entry.productName = productName;
        entry.providerType = providerType;
        entry.pathToProduct = pathToProduct;
        entry.state = state;
        entry.signatureUpToDate = signatureUpToDate;
        entry.realTimeProtectionEnabled = realTimeProtection;
        entry.stateTimestamp = static_cast<uint64_t>(std::chrono::system_clock::now().time_since_epoch().count());
        entry.engineVersion = L"10.0.26100.1";
        entry.signatureVersion = L"10.0.26100.1";
        entry.reportingFlags = 0x01;

        std::string sGuid = GuidToString(g);
        m_products[sGuid] = entry;
        *pOutGuid = g;

        notifySubscribersInternal();
        return S_OK;
    }

    HRESULT unregisterProduct(const GUID& guid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string sGuid = GuidToString(guid);
        auto it = m_products.find(sGuid);
        if (it == m_products.end()) {
            return HRESULT_FROM_WIN32_NOT_FOUND;
        }

        m_products.erase(it);
        notifySubscribersInternal();
        return S_OK;
    }

    HRESULT updateProductStatus(
        const GUID& guid,
        WSC_SECURITY_PRODUCT_STATE state,
        bool signatureUpToDate,
        bool realTimeProtection
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string sGuid = GuidToString(guid);
        auto it = m_products.find(sGuid);
        if (it == m_products.end()) {
            return HRESULT_FROM_WIN32_NOT_FOUND;
        }

        it->second.state = state;
        it->second.signatureUpToDate = signatureUpToDate;
        it->second.realTimeProtectionEnabled = realTimeProtection;
        it->second.stateTimestamp = static_cast<uint64_t>(std::chrono::system_clock::now().time_since_epoch().count());

        notifySubscribersInternal();
        return S_OK;
    }

    HRESULT queryAntiVirusStatus(DWORD* pdwStatus) {
        if (!pdwStatus) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        DWORD status = WSC_AV_STATUS_PROVIDER_ANTIVIRUS;
        for (const auto& [_, p] : m_products) {
            if (p.providerType & WSC_SECURITY_PROVIDER_ANTIVIRUS) {
                if (p.state == WSC_SECURITY_PRODUCT_STATE_ON) status |= WSC_AV_STATUS_ON;
                if (p.signatureUpToDate) status |= WSC_AV_STATUS_SIGNATURE_UPTODATE;
                if (p.realTimeProtectionEnabled) status |= WSC_AV_STATUS_RTP_ENABLED;
                break;
            }
        }
        *pdwStatus = status;
        return S_OK;
    }

    std::vector<WscProductEntry> getProducts(DWORD providerFilter = WSC_SECURITY_PROVIDER_ALL) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<WscProductEntry> result;
        for (const auto& [_, p] : m_products) {
            if (p.providerType & providerFilter) {
                result.push_back(p);
            }
        }
        return result;
    }

    std::optional<WscProductEntry> getProductByGuid(const GUID& guid) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::string sGuid = GuidToString(guid);
        auto it = m_products.find(sGuid);
        if (it != m_products.end()) return it->second;
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // Change Notification Dispatcher
    // ------------------------------------------------------------------------
    HRESULT registerForChanges(
        PHANDLE phCallbackRegistration,
        LPTHREAD_START_ROUTINE lpCallbackAddress,
        PVOID pContext
    ) {
        if (!phCallbackRegistration || !lpCallbackAddress) return E_POINTER;

        std::lock_guard<std::mutex> lock(m_mutex);
        HANDLE h = reinterpret_cast<HANDLE>(m_nextHandleId++);
        WscNotificationSubscription sub{};
        sub.handle = h;
        sub.callback = lpCallbackAddress;
        sub.context = pContext;
        m_subscribers.push_back(sub);

        *phCallbackRegistration = h;
        return S_OK;
    }

    HRESULT unregisterChanges(HANDLE hRegistrationHandle) {
        if (!hRegistrationHandle) return E_INVALIDARG;

        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::remove_if(m_subscribers.begin(), m_subscribers.end(),
            [hRegistrationHandle](const WscNotificationSubscription& s) {
                return s.handle == hRegistrationHandle;
            });

        if (it != m_subscribers.end()) {
            m_subscribers.erase(it, m_subscribers.end());
            return S_OK;
        }
        return HRESULT_FROM_WIN32_INVALID_HANDLE;
    }

    void notifySubscribers() {
        std::lock_guard<std::mutex> lock(m_mutex);
        notifySubscribersInternal();
    }

    // Manual test override for simulation
    void setProviderOverride(DWORD provider, std::optional<WSC_SECURITY_PROVIDER_HEALTH> health) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (health) {
            m_overrides[provider] = *health;
        } else {
            m_overrides.erase(provider);
        }
        notifySubscribersInternal();
    }

    void clearOverrides() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_overrides.clear();
        notifySubscribersInternal();
    }

    void resetToDefaults() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_products.clear();
        m_overrides.clear();
        seedDefaultSecurityProviders();
        notifySubscribersInternal();
    }

private:
    void notifySubscribersInternal() {
        for (const auto& sub : m_subscribers) {
            if (sub.callback) {
                sub.callback(sub.context);
            }
        }
    }
};

inline HRESULT WINAPI WscProductListImpl::Initialize(DWORD provider) {
    auto products = SovereignWscManager::get().getProducts(provider);
    for (auto* item : m_items) {
        if (item) item->Release();
    }
    m_items.clear();

    for (const auto& p : products) {
        m_items.push_back(new WscProductImpl(p));
    }
    return S_OK;
}

// ============================================================================
// 6. Win32 Windows Security Center C ABI Functions (wscapi.dll)
// ============================================================================

inline HRESULT WINAPI WscGetSecurityProviderHealth(
    DWORD Providers,
    PWSC_SECURITY_PROVIDER_HEALTH pHealth
) {
    return SovereignWscManager::get().getSecurityProviderHealth(Providers, pHealth);
}

inline HRESULT WINAPI WscRegisterForChanges(
    LPVOID Reserved,
    PHANDLE phCallbackRegistration,
    LPTHREAD_START_ROUTINE lpCallbackAddress,
    PVOID pContext
) {
    if (Reserved != nullptr) return E_INVALIDARG;
    return SovereignWscManager::get().registerForChanges(phCallbackRegistration, lpCallbackAddress, pContext);
}

inline HRESULT WINAPI WscUnRegisterChanges(HANDLE hRegistrationHandle) {
    return SovereignWscManager::get().unregisterChanges(hRegistrationHandle);
}

inline HRESULT WINAPI WscQueryAntiVirusStatus(PDWORD pdwStatus) {
    return SovereignWscManager::get().queryAntiVirusStatus(pdwStatus);
}

inline HRESULT WINAPI WscRegisterProduct(
    LPCWSTR pszProductName,
    DWORD dwProviderType,
    LPCWSTR pszPathToProduct,
    DWORD dwProductState,
    DWORD dwSignatureStatus,
    [[maybe_unused]] DWORD dwTimestamp,
    GUID* pProductGuid
) {
    if (!pszProductName || !pProductGuid) return E_INVALIDARG;
    std::wstring name(pszProductName);
    std::wstring path(pszPathToProduct ? pszPathToProduct : L"");
    auto state = static_cast<WSC_SECURITY_PRODUCT_STATE>(dwProductState);
    bool sigUpToDate = (dwSignatureStatus != 0);

    return SovereignWscManager::get().registerProduct(
        name, dwProviderType, path, state, sigUpToDate, true, pProductGuid
    );
}

inline HRESULT WINAPI WscUnregisterProduct(const GUID* pProductGuid) {
    if (!pProductGuid) return E_INVALIDARG;
    return SovereignWscManager::get().unregisterProduct(*pProductGuid);
}

inline HRESULT WINAPI WscUpdateProductStatus(
    const GUID* pProductGuid,
    DWORD dwProductState,
    DWORD dwSignatureStatus
) {
    if (!pProductGuid) return E_INVALIDARG;
    auto state = static_cast<WSC_SECURITY_PRODUCT_STATE>(dwProductState);
    bool sigUpToDate = (dwSignatureStatus != 0);
    return SovereignWscManager::get().updateProductStatus(*pProductGuid, state, sigUpToDate, true);
}

inline HRESULT WINAPI WscGetAntiVirusProducts(DWORD* pCount, WscProductEntry** ppProducts) {
    if (!pCount || !ppProducts) return E_POINTER;
    auto prods = SovereignWscManager::get().getProducts(WSC_SECURITY_PROVIDER_ANTIVIRUS);
    *pCount = static_cast<DWORD>(prods.size());
    if (prods.empty()) {
        *ppProducts = nullptr;
        return S_OK;
    }

    auto* buffer = new WscProductEntry[prods.size()];
    for (size_t i = 0; i < prods.size(); ++i) {
        buffer[i] = prods[i];
    }
    *ppProducts = buffer;
    return S_OK;
}

inline void WINAPI WscFreeMemory(void* p) {
    if (p) {
        delete[] reinterpret_cast<WscProductEntry*>(p);
    }
}

// COM Factory Helper
inline HRESULT WINAPI WscCreateProductList(DWORD provider, IWSCProductList** ppList) {
    if (!ppList) return E_POINTER;
    auto* list = new WscProductListImpl();
    HRESULT hr = list->Initialize(provider);
    if (FAILED(hr)) {
        list->Release();
        *ppList = nullptr;
        return hr;
    }
    *ppList = list;
    return S_OK;
}

// ============================================================================
// 7. Subsystem Export Registration Helper
// ============================================================================

inline void InitializeWscSubsystemExports() {
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        auto& loader = ldr::DynamicLoader::get();

        // 1. Register wscapi.dll dynamic exports
        loader.registerExport("wscapi.dll", "WscGetSecurityProviderHealth", reinterpret_cast<void*>(&WscGetSecurityProviderHealth));
        loader.registerExport("wscapi.dll", "WscRegisterForChanges", reinterpret_cast<void*>(&WscRegisterForChanges));
        loader.registerExport("wscapi.dll", "WscUnRegisterChanges", reinterpret_cast<void*>(&WscUnRegisterChanges));
        loader.registerExport("wscapi.dll", "WscQueryAntiVirusStatus", reinterpret_cast<void*>(&WscQueryAntiVirusStatus));
        loader.registerExport("wscapi.dll", "WscRegisterProduct", reinterpret_cast<void*>(&WscRegisterProduct));
        loader.registerExport("wscapi.dll", "WscUnregisterProduct", reinterpret_cast<void*>(&WscUnregisterProduct));
        loader.registerExport("wscapi.dll", "WscUpdateProductStatus", reinterpret_cast<void*>(&WscUpdateProductStatus));
        loader.registerExport("wscapi.dll", "WscGetAntiVirusProducts", reinterpret_cast<void*>(&WscGetAntiVirusProducts));
        loader.registerExport("wscapi.dll", "WscFreeMemory", reinterpret_cast<void*>(&WscFreeMemory));

        // 2. Register module in VersionDatabase
        version::VersionDatabase::Instance().RegisterModule(
            "wscapi.dll",
            "10.0.26100.1",
            "Windows Security Center API Client",
            "MicaNT Sovereign Project"
        );
    });
}

} // namespace micant::wsc
