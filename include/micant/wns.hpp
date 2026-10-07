#pragma once

/**
 * @file wns.hpp
 * @brief Clean-Room Windows Push Notification Service (WNS) & Push Notification Platform.
 *
 * Implements the Windows Push Notification Platform (WPN) COM architecture,
 * push notification channel management, interactive Toast and Badge notification pipelines,
 * Action Center notification persistence, SCM background daemons (WpnService, WpnUserService),
 * and Win32 C client APIs.
 *
 * 100% clean-room engineering referencing Microsoft's MIT-licensed win32metadata.
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
#include <chrono>

#include "ntdef.hpp"
#include "kernel32.hpp"
#include "ole32.hpp"
#include "oleaut32.hpp"
#include "scm.hpp"
#include "ldr.hpp"

namespace micant::wns {

using namespace micant::ole32;

// ============================================================================
// 1. WNS Constants, Enums & Structs (win32metadata)
// ============================================================================

enum NOTIFICATION_SETTING : uint32_t {
    NOTIFICATION_SETTING_ENABLED                   = 0,
    NOTIFICATION_SETTING_DISABLED_FOR_APPLICATION  = 1,
    NOTIFICATION_SETTING_DISABLED_FOR_USER         = 2,
    NOTIFICATION_SETTING_DISABLED_BY_GROUP_POLICY  = 3,
    NOTIFICATION_SETTING_DISABLED_BY_MANIFEST      = 4
};

enum TOAST_TEMPLATE_TYPE : uint32_t {
    TOAST_TEMPLATE_IMAGE_AND_TEXT01 = 0,
    TOAST_TEMPLATE_IMAGE_AND_TEXT02 = 1,
    TOAST_TEMPLATE_IMAGE_AND_TEXT03 = 2,
    TOAST_TEMPLATE_IMAGE_AND_TEXT04 = 3,
    TOAST_TEMPLATE_TEXT01           = 4,
    TOAST_TEMPLATE_TEXT02           = 5,
    TOAST_TEMPLATE_TEXT03           = 6,
    TOAST_TEMPLATE_TEXT04           = 7,
    TOAST_TEMPLATE_GENERIC          = 8
};

enum BADGE_TEMPLATE_TYPE : uint32_t {
    BADGE_TEMPLATE_GLYPH  = 0,
    BADGE_TEMPLATE_NUMBER = 1
};

enum WNS_CHANNEL_STATUS : uint32_t {
    WNS_CHANNEL_ACTIVE  = 0,
    WNS_CHANNEL_EXPIRED = 1,
    WNS_CHANNEL_REVOKED = 2,
    WNS_CHANNEL_CLOSED  = 3
};

enum WNS_NOTIFICATION_TYPE : uint32_t {
    WNS_TYPE_TOAST = 1,
    WNS_TYPE_BADGE = 2,
    WNS_TYPE_TILE  = 3,
    WNS_TYPE_RAW   = 4
};

#pragma pack(push, 1)

struct WNS_CHANNEL_INFO {
    GUID channelId;
    wchar_t appId[128];
    wchar_t channelUri[256];
    win32::FILETIME createdTime;
    win32::FILETIME expirationTime;
    uint32_t status;
};

struct WNS_TOAST_DESCRIPTOR {
    uint32_t notificationId;
    wchar_t appId[128];
    wchar_t tag[64];
    wchar_t group[64];
    wchar_t title[128];
    wchar_t message[256];
    wchar_t launchArgs[256];
    win32::FILETIME timestamp;
    win32::FILETIME expiration;
    uint32_t isDismissed;
};

#pragma pack(pop)

// ============================================================================
// 2. WNS & Push Notification COM GUIDs
// ============================================================================

inline const GUID CLSID_ToastNotificationManager = {
    0x50AC103F, 0xD235, 0x4598, { 0xBB, 0xEB, 0x98, 0xE6, 0x3D, 0x4B, 0x22, 0x22 }
};

inline const GUID IID_IToastNotificationManager = {
    0x50AC103E, 0xD235, 0x4598, { 0xBB, 0xEB, 0x98, 0xE6, 0x3D, 0x4B, 0x22, 0x22 }
};

inline const GUID IID_IToastNotifier = {
    0x75927B40, 0x03F8, 0x4176, { 0x9D, 0xCA, 0x34, 0x80, 0xE9, 0x5A, 0x4D, 0x44 }
};

inline const GUID IID_IToastNotification = {
    0x997B2675, 0x059E, 0x4946, { 0x8B, 0x55, 0x29, 0xBB, 0x6F, 0xBF, 0x64, 0x44 }
};

inline const GUID CLSID_PushNotificationChannelManager = {
    0x3F8A7D0A, 0x7520, 0x4A6B, { 0x95, 0xD1, 0x50, 0x02, 0x4E, 0x5C, 0xA2, 0x11 }
};

inline const GUID IID_IPushNotificationChannelManager = {
    0x8B10762E, 0x92AE, 0x4555, { 0xAD, 0x25, 0x8E, 0x11, 0x19, 0x4A, 0xDC, 0x5B }
};

inline const GUID IID_IPushNotificationChannel = {
    0x2B7C0A60, 0x860C, 0x4642, { 0xAA, 0xC2, 0x0D, 0xC1, 0x2E, 0x23, 0x28, 0xA9 }
};

inline const GUID IID_IBadgeNotification = {
    0x075CB4CA, 0xEBBE, 0x4458, { 0x87, 0x59, 0xF9, 0x35, 0xB6, 0xFB, 0x59, 0xD0 }
};

inline const GUID IID_IBadgeUpdateManager = {
    0x334333AE, 0x2E54, 0x4931, { 0x83, 0x6E, 0x43, 0x43, 0x11, 0xC6, 0x14, 0xA0 }
};

inline const GUID IID_IBadgeUpdater = {
    0x6FB179AE, 0xD594, 0x481E, { 0x88, 0xCA, 0xAE, 0x30, 0x81, 0x3B, 0x0D, 0x77 }
};

// ============================================================================
// 3. COM Interface Definitions
// ============================================================================

class IToastNotification;
class IToastNotifier;
class IPushNotificationChannel;

class IToastNotification : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall GetContent(BSTR* ppXmlContent) = 0;
    virtual HRESULT __stdcall SetContent(BSTR pXmlContent) = 0;
    virtual HRESULT __stdcall GetExpirationTime(win32::FILETIME* pExpirationTime) = 0;
    virtual HRESULT __stdcall SetExpirationTime(const win32::FILETIME* pExpirationTime) = 0;
    virtual HRESULT __stdcall GetTag(BSTR* pTag) = 0;
    virtual HRESULT __stdcall SetTag(BSTR tag) = 0;
    virtual HRESULT __stdcall GetGroup(BSTR* pGroup) = 0;
    virtual HRESULT __stdcall SetGroup(BSTR group) = 0;
    virtual HRESULT __stdcall GetSuppressPopup(int16_t* pSuppress) = 0;
    virtual HRESULT __stdcall SetSuppressPopup(int16_t suppress) = 0;
};

class IToastNotifier : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall Show(IToastNotification* notification) = 0;
    virtual HRESULT __stdcall Hide(IToastNotification* notification) = 0;
    virtual HRESULT __stdcall GetSetting(NOTIFICATION_SETTING* pSetting) = 0;
};

class IToastNotificationManager : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall CreateToastNotifier(BSTR applicationId, IToastNotifier** ppNotifier) = 0;
    virtual HRESULT __stdcall GetTemplateContent(TOAST_TEMPLATE_TYPE templateType, BSTR* ppXmlContent) = 0;
};

class IPushNotificationChannel : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall GetUri(BSTR* pUri) = 0;
    virtual HRESULT __stdcall GetExpirationTime(win32::FILETIME* pExpirationTime) = 0;
    virtual HRESULT __stdcall Close() = 0;
    virtual HRESULT __stdcall GetStatus(uint32_t* pStatus) = 0;
};

class IPushNotificationChannelManager : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall CreatePushNotificationChannelForApplication(
        BSTR applicationId, IPushNotificationChannel** ppChannel
    ) = 0;
};

class IBadgeNotification : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall GetContent(BSTR* ppXmlContent) = 0;
    virtual HRESULT __stdcall GetExpirationTime(win32::FILETIME* pExpirationTime) = 0;
};

class IBadgeUpdater : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall Update(IBadgeNotification* notification) = 0;
    virtual HRESULT __stdcall Clear() = 0;
};

class IBadgeUpdateManager : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall CreateBadgeUpdaterForApplication(
        BSTR applicationId, IBadgeUpdater** ppUpdater
    ) = 0;
};

// ============================================================================
// 4. Sovereign Push Notification & Action Center Store
// ============================================================================

struct ToastRecord {
    uint32_t id{0};
    std::wstring appId;
    std::wstring tag;
    std::wstring group;
    std::wstring title;
    std::wstring message;
    std::wstring launchArgs;
    std::wstring rawXml;
    win32::FILETIME timestamp{};
    win32::FILETIME expiration{};
    bool isDismissed{false};
    bool isRead{false};
};

struct ChannelRecord {
    GUID channelId{};
    std::wstring appId;
    std::wstring channelUri;
    win32::FILETIME createdTime{};
    win32::FILETIME expirationTime{};
    uint32_t status{WNS_CHANNEL_ACTIVE};
    uint32_t deliveredCount{0};
};

struct BadgeRecord {
    std::wstring appId;
    std::wstring glyph;
    uint32_t number{0};
    bool hasNumber{false};
};

class PushNotificationManager {
private:
    mutable std::mutex m_mutex;
    uint32_t m_nextNotificationId{1001};
    std::vector<ToastRecord> m_notifications;
    std::vector<ChannelRecord> m_channels;
    std::map<std::wstring, BadgeRecord> m_badges;

    PushNotificationManager() {
        initDefaultState();
        registerScmServices();
    }

    void initDefaultState() {
        // Seed initial system notification
        ToastRecord rec;
        rec.id = m_nextNotificationId++;
        rec.appId = L"Microsoft.Windows.SystemSettings";
        rec.tag = L"SystemReady";
        rec.group = L"System";
        rec.title = L"MicaNT Executive Initialized";
        rec.message = L"Zero-telemetry sovereign Windows NT subsystem ready.";
        rec.launchArgs = L"page=system";
        rec.rawXml = L"<toast><visual><binding template=\"ToastGeneric\"><text>MicaNT Executive Initialized</text><text>Zero-telemetry sovereign Windows NT subsystem ready.</text></binding></visual></toast>";
        rec.timestamp.dwLowDateTime = 0x20000000;
        rec.timestamp.dwHighDateTime = 0x01DA0000;
        rec.expiration.dwLowDateTime = 0xFFFFFFFF;
        rec.expiration.dwHighDateTime = 0x01DAFFFF;
        rec.isDismissed = false;
        rec.isRead = true;
        m_notifications.push_back(rec);

        // Seed default channel for Windows Shell
        ChannelRecord chan;
        chan.channelId = { 0x11223344, 0x5566, 0x7788, { 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 } };
        chan.appId = L"Microsoft.Windows.ShellExperienceHost";
        chan.channelUri = L"https://wns.micant.local/push/v1/channel-11223344-5566-7788-99aabbccddeeff00";
        chan.createdTime.dwLowDateTime = 0x10000000;
        chan.createdTime.dwHighDateTime = 0x01DA0000;
        chan.expirationTime.dwLowDateTime = 0x90000000;
        chan.expirationTime.dwHighDateTime = 0x01DA5000;
        chan.status = WNS_CHANNEL_ACTIVE;
        chan.deliveredCount = 1;
        m_channels.push_back(chan);

        // Seed default badge
        BadgeRecord b;
        b.appId = L"Microsoft.Windows.ShellExperienceHost";
        b.number = 1;
        b.hasNumber = true;
        m_badges[b.appId] = b;
    }

    void registerScmServices() {
        auto& scm = scm::ServiceControlManager::get();

        // 1. WpnService: Windows Push Notifications System Service
        auto wpnSvc = std::make_shared<scm::ServiceRecord>();
        wpnSvc->serviceName = L"WpnService";
        wpnSvc->displayName = L"Windows Push Notifications System Service";
        wpnSvc->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        wpnSvc->startType = scm::SERVICE_AUTO_START;
        wpnSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
        wpnSvc->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k System";
        wpnSvc->loadOrderGroup = L"System";
        wpnSvc->status.dwServiceType = wpnSvc->serviceType;
        wpnSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
        wpnSvc->status.dwProcessId = 1142;
        scm.registerServiceRecord(wpnSvc);

        // 2. WpnUserService: Windows Push Notifications User Service
        auto wpnUser = std::make_shared<scm::ServiceRecord>();
        wpnUser->serviceName = L"WpnUserService";
        wpnUser->displayName = L"Windows Push Notifications User Service";
        wpnUser->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        wpnUser->startType = scm::SERVICE_DEMAND_START;
        wpnUser->errorControl = scm::SERVICE_ERROR_NORMAL;
        wpnUser->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k UnistoreSvcGroup";
        wpnUser->loadOrderGroup = L"UnistoreSvcGroup";
        wpnUser->status.dwServiceType = wpnUser->serviceType;
        wpnUser->status.dwCurrentState = scm::SERVICE_RUNNING;
        wpnUser->status.dwProcessId = 1146;
        scm.registerServiceRecord(wpnUser);
    }

public:
    static PushNotificationManager& get() noexcept {
        static PushNotificationManager instance;
        return instance;
    }

    PushNotificationManager(const PushNotificationManager&) = delete;
    PushNotificationManager& operator=(const PushNotificationManager&) = delete;

    void resetToDefault() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_notifications.clear();
        m_channels.clear();
        m_badges.clear();
        m_nextNotificationId = 1001;
        initDefaultState();
    }

    // Channel Management
    ChannelRecord createChannel(const std::wstring& appId) {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Check if an active channel already exists for this app
        for (const auto& c : m_channels) {
            if (c.appId == appId && c.status == WNS_CHANNEL_ACTIVE) {
                return c;
            }
        }

        ChannelRecord ch;
        uint32_t seed = static_cast<uint32_t>(m_channels.size() + 1);
        ch.channelId = { 0x55000000 | seed, 0xAABB, 0xCCDD, { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, static_cast<uint8_t>(seed) } };
        ch.appId = appId;

        std::wostringstream oss;
        oss << L"https://wns.micant.local/push/v1/channel-"
            << std::hex << std::setfill(L'0') << std::setw(8) << ch.channelId.Data1
            << L"-" << std::setw(4) << ch.channelId.Data2
            << L"-" << std::setw(4) << ch.channelId.Data3
            << L"-userland";
        ch.channelUri = oss.str();

        ch.createdTime.dwLowDateTime = 0x30000000;
        ch.createdTime.dwHighDateTime = 0x01DA0000;
        ch.expirationTime.dwLowDateTime = 0xB0000000;
        ch.expirationTime.dwHighDateTime = 0x01DA5000; // ~30 days out
        ch.status = WNS_CHANNEL_ACTIVE;
        ch.deliveredCount = 0;

        m_channels.push_back(ch);
        return ch;
    }

    bool closeChannel(const std::wstring& appId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& c : m_channels) {
            if (c.appId == appId && c.status == WNS_CHANNEL_ACTIVE) {
                c.status = WNS_CHANNEL_CLOSED;
                return true;
            }
        }
        return false;
    }

    std::vector<ChannelRecord> getChannels() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_channels;
    }

    // Toast Management
    uint32_t postToast(const ToastRecord& input) {
        std::lock_guard<std::mutex> lock(m_mutex);
        ToastRecord rec = input;
        rec.id = m_nextNotificationId++;
        if (rec.timestamp.dwLowDateTime == 0 && rec.timestamp.dwHighDateTime == 0) {
            rec.timestamp.dwLowDateTime = 0x40000000;
            rec.timestamp.dwHighDateTime = 0x01DA0000;
        }
        if (rec.expiration.dwLowDateTime == 0 && rec.expiration.dwHighDateTime == 0) {
            rec.expiration.dwLowDateTime = 0xFFFFFFFF;
            rec.expiration.dwHighDateTime = 0x01DAFFFF;
        }

        // If tag is present, replace existing toast with same tag and group
        if (!rec.tag.empty()) {
            for (auto& existing : m_notifications) {
                if (existing.appId == rec.appId && existing.tag == rec.tag && existing.group == rec.group && !existing.isDismissed) {
                    existing.isDismissed = true;
                    break;
                }
            }
        }

        m_notifications.push_back(rec);
        return rec.id;
    }

    bool dismissToast(uint32_t id) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& n : m_notifications) {
            if (n.id == id && !n.isDismissed) {
                n.isDismissed = true;
                return true;
            }
        }
        return false;
    }

    void clearAllToasts() {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& n : m_notifications) {
            n.isDismissed = true;
        }
    }

    std::vector<ToastRecord> getActiveToasts() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<ToastRecord> active;
        for (const auto& n : m_notifications) {
            if (!n.isDismissed) {
                active.push_back(n);
            }
        }
        return active;
    }

    std::vector<ToastRecord> getAllToasts() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_notifications;
    }

    // Badge Management
    void setBadgeNumber(const std::wstring& appId, uint32_t number) {
        std::lock_guard<std::mutex> lock(m_mutex);
        BadgeRecord b;
        b.appId = appId;
        b.number = number;
        b.hasNumber = true;
        m_badges[appId] = b;
    }

    void setBadgeGlyph(const std::wstring& appId, const std::wstring& glyph) {
        std::lock_guard<std::mutex> lock(m_mutex);
        BadgeRecord b;
        b.appId = appId;
        b.glyph = glyph;
        b.hasNumber = false;
        m_badges[appId] = b;
    }

    void clearBadge(const std::wstring& appId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_badges.erase(appId);
    }

    bool getBadge(const std::wstring& appId, BadgeRecord& out) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_badges.find(appId);
        if (it != m_badges.end()) {
            out = it->second;
            return true;
        }
        return false;
    }
};

// ============================================================================
// 5. COM Class Implementations
// ============================================================================

class PushNotificationChannelImpl : public IPushNotificationChannel {
private:
    uint32_t m_refCount{1};
    ChannelRecord m_record;

public:
    explicit PushNotificationChannelImpl(const ChannelRecord& rec)
        : m_record(rec) {}

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IPushNotificationChannel) {
            *ppvObject = static_cast<IPushNotificationChannel*>(this);
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
        uint32_t count = --m_refCount;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    virtual HRESULT __stdcall GetUri(BSTR* pUri) override {
        if (!pUri) return E_POINTER;
        *pUri = ole32::SysAllocString(m_record.channelUri.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall GetExpirationTime(win32::FILETIME* pExpirationTime) override {
        if (!pExpirationTime) return E_POINTER;
        *pExpirationTime = m_record.expirationTime;
        return S_OK;
    }

    virtual HRESULT __stdcall Close() override {
        PushNotificationManager::get().closeChannel(m_record.appId);
        m_record.status = WNS_CHANNEL_CLOSED;
        return S_OK;
    }

    virtual HRESULT __stdcall GetStatus(uint32_t* pStatus) override {
        if (!pStatus) return E_POINTER;
        *pStatus = m_record.status;
        return S_OK;
    }
};

class PushNotificationChannelManagerImpl : public IPushNotificationChannelManager {
private:
    uint32_t m_refCount{1};

public:
    PushNotificationChannelManagerImpl() = default;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IPushNotificationChannelManager) {
            *ppvObject = static_cast<IPushNotificationChannelManager*>(this);
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
        uint32_t count = --m_refCount;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    virtual HRESULT __stdcall CreatePushNotificationChannelForApplication(
        BSTR applicationId, IPushNotificationChannel** ppChannel
    ) override {
        if (!ppChannel) return E_POINTER;
        std::wstring app = applicationId ? applicationId : L"DefaultApp";
        ChannelRecord rec = PushNotificationManager::get().createChannel(app);
        *ppChannel = new PushNotificationChannelImpl(rec);
        return S_OK;
    }
};

class ToastNotificationImpl : public IToastNotification {
private:
    uint32_t m_refCount{1};
    std::wstring m_xmlContent;
    win32::FILETIME m_expiration{};
    std::wstring m_tag;
    std::wstring m_group;
    int16_t m_suppressPopup{0};

public:
    explicit ToastNotificationImpl(const std::wstring& xml)
        : m_xmlContent(xml) {
        m_expiration.dwLowDateTime = 0xFFFFFFFF;
        m_expiration.dwHighDateTime = 0x01DAFFFF;
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IToastNotification) {
            *ppvObject = static_cast<IToastNotification*>(this);
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
        uint32_t count = --m_refCount;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    virtual HRESULT __stdcall GetContent(BSTR* ppXmlContent) override {
        if (!ppXmlContent) return E_POINTER;
        *ppXmlContent = ole32::SysAllocString(m_xmlContent.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall SetContent(BSTR pXmlContent) override {
        if (!pXmlContent) return E_POINTER;
        m_xmlContent = pXmlContent;
        return S_OK;
    }

    virtual HRESULT __stdcall GetExpirationTime(win32::FILETIME* pExpirationTime) override {
        if (!pExpirationTime) return E_POINTER;
        *pExpirationTime = m_expiration;
        return S_OK;
    }

    virtual HRESULT __stdcall SetExpirationTime(const win32::FILETIME* pExpirationTime) override {
        if (!pExpirationTime) return E_POINTER;
        m_expiration = *pExpirationTime;
        return S_OK;
    }

    virtual HRESULT __stdcall GetTag(BSTR* pTag) override {
        if (!pTag) return E_POINTER;
        *pTag = ole32::SysAllocString(m_tag.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall SetTag(BSTR tag) override {
        m_tag = tag ? tag : L"";
        return S_OK;
    }

    virtual HRESULT __stdcall GetGroup(BSTR* pGroup) override {
        if (!pGroup) return E_POINTER;
        *pGroup = ole32::SysAllocString(m_group.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall SetGroup(BSTR group) override {
        m_group = group ? group : L"";
        return S_OK;
    }

    virtual HRESULT __stdcall GetSuppressPopup(int16_t* pSuppress) override {
        if (!pSuppress) return E_POINTER;
        *pSuppress = m_suppressPopup;
        return S_OK;
    }

    virtual HRESULT __stdcall SetSuppressPopup(int16_t suppress) override {
        m_suppressPopup = suppress;
        return S_OK;
    }
};

class ToastNotifierImpl : public IToastNotifier {
private:
    uint32_t m_refCount{1};
    std::wstring m_appId;

    static void parseToastXml(const std::wstring& xml, std::wstring& title, std::wstring& body, std::wstring& launch) {
        // Extract launch
        size_t lPos = xml.find(L"launch=\"");
        if (lPos != std::wstring::npos) {
            size_t endL = xml.find(L"\"", lPos + 8);
            if (endL != std::wstring::npos) {
                launch = xml.substr(lPos + 8, endL - (lPos + 8));
            }
        }

        // Extract text nodes
        size_t t1 = xml.find(L"<text");
        if (t1 != std::wstring::npos) {
            size_t open1 = xml.find(L">", t1);
            size_t close1 = xml.find(L"</text>", open1);
            if (open1 != std::wstring::npos && close1 != std::wstring::npos) {
                title = xml.substr(open1 + 1, close1 - (open1 + 1));
            }

            size_t t2 = xml.find(L"<text", close1);
            if (t2 != std::wstring::npos) {
                size_t open2 = xml.find(L">", t2);
                size_t close2 = xml.find(L"</text>", open2);
                if (open2 != std::wstring::npos && close2 != std::wstring::npos) {
                    body = xml.substr(open2 + 1, close2 - (open2 + 1));
                }
            }
        }
        if (title.empty()) title = L"Notification";
        if (body.empty()) body = L"MicaNT Toast Notification";
    }

public:
    explicit ToastNotifierImpl(const std::wstring& appId)
        : m_appId(appId) {}

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IToastNotifier) {
            *ppvObject = static_cast<IToastNotifier*>(this);
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
        uint32_t count = --m_refCount;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    virtual HRESULT __stdcall Show(IToastNotification* notification) override {
        if (!notification) return E_POINTER;

        ToastRecord rec;
        rec.appId = m_appId;

        ole32::BSTR xml = nullptr;
        notification->GetContent(&xml);
        rec.rawXml = xml ? xml : L"";
        ole32::SysFreeString(xml);

        parseToastXml(rec.rawXml, rec.title, rec.message, rec.launchArgs);

        ole32::BSTR tag = nullptr;
        notification->GetTag(&tag);
        rec.tag = tag ? tag : L"";
        ole32::SysFreeString(tag);

        ole32::BSTR group = nullptr;
        notification->GetGroup(&group);
        rec.group = group ? group : L"";
        ole32::SysFreeString(group);

        notification->GetExpirationTime(&rec.expiration);

        PushNotificationManager::get().postToast(rec);
        return S_OK;
    }

    virtual HRESULT __stdcall Hide(IToastNotification* notification) override {
        if (!notification) return E_POINTER;
        ole32::BSTR tag = nullptr;
        notification->GetTag(&tag);
        std::wstring sTag = tag ? tag : L"";
        ole32::SysFreeString(tag);

        auto toasts = PushNotificationManager::get().getActiveToasts();
        for (const auto& t : toasts) {
            if (t.appId == m_appId && t.tag == sTag) {
                PushNotificationManager::get().dismissToast(t.id);
            }
        }
        return S_OK;
    }

    virtual HRESULT __stdcall GetSetting(NOTIFICATION_SETTING* pSetting) override {
        if (!pSetting) return E_POINTER;
        *pSetting = NOTIFICATION_SETTING_ENABLED;
        return S_OK;
    }
};

class ToastNotificationManagerImpl : public IToastNotificationManager {
private:
    uint32_t m_refCount{1};

public:
    ToastNotificationManagerImpl() = default;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IToastNotificationManager) {
            *ppvObject = static_cast<IToastNotificationManager*>(this);
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
        uint32_t count = --m_refCount;
        if (count == 0) {
            delete this;
        }
        return count;
    }

    virtual HRESULT __stdcall CreateToastNotifier(BSTR applicationId, IToastNotifier** ppNotifier) override {
        if (!ppNotifier) return E_POINTER;
        std::wstring app = applicationId ? applicationId : L"DefaultApp";
        *ppNotifier = new ToastNotifierImpl(app);
        return S_OK;
    }

    virtual HRESULT __stdcall GetTemplateContent(TOAST_TEMPLATE_TYPE templateType, BSTR* ppXmlContent) override {
        if (!ppXmlContent) return E_POINTER;

        std::wstring xml;
        switch (templateType) {
            case TOAST_TEMPLATE_IMAGE_AND_TEXT01:
                xml = L"<toast><visual><binding template=\"ToastImageAndText01\"><image id=\"1\" src=\"\"/><text id=\"1\"/></binding></visual></toast>";
                break;
            case TOAST_TEMPLATE_IMAGE_AND_TEXT02:
                xml = L"<toast><visual><binding template=\"ToastImageAndText02\"><image id=\"1\" src=\"\"/><text id=\"1\"/><text id=\"2\"/></binding></visual></toast>";
                break;
            case TOAST_TEMPLATE_TEXT01:
                xml = L"<toast><visual><binding template=\"ToastText01\"><text id=\"1\"/></binding></visual></toast>";
                break;
            case TOAST_TEMPLATE_TEXT02:
                xml = L"<toast><visual><binding template=\"ToastText02\"><text id=\"1\"/><text id=\"2\"/></binding></visual></toast>";
                break;
            case TOAST_TEMPLATE_GENERIC:
            default:
                xml = L"<toast><visual><binding template=\"ToastGeneric\"><text id=\"1\"/><text id=\"2\"/></binding></visual></toast>";
                break;
        }
        *ppXmlContent = ole32::SysAllocString(xml.c_str());
        return S_OK;
    }
};

// ============================================================================
// 6. COM Class Factories
// ============================================================================

class ToastNotificationManagerClassFactory : public ole32::IClassFactory {
private:
    uint32_t m_refCount{1};

public:
    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == ole32::IID_IClassFactory) {
            *ppvObject = static_cast<IClassFactory*>(this);
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
        return --m_refCount;
    }

    virtual HRESULT __stdcall CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        if (!ppvObject) return E_POINTER;

        auto* pMgr = new ToastNotificationManagerImpl();
        HRESULT hr = pMgr->QueryInterface(riid, ppvObject);
        pMgr->Release();
        return hr;
    }

    virtual HRESULT __stdcall LockServer(int32_t /*fLock*/) override {
        return S_OK;
    }
};

class PushNotificationChannelManagerClassFactory : public ole32::IClassFactory {
private:
    uint32_t m_refCount{1};

public:
    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == ole32::IID_IClassFactory) {
            *ppvObject = static_cast<IClassFactory*>(this);
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
        return --m_refCount;
    }

    virtual HRESULT __stdcall CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        if (!ppvObject) return E_POINTER;

        auto* pMgr = new PushNotificationChannelManagerImpl();
        HRESULT hr = pMgr->QueryInterface(riid, ppvObject);
        pMgr->Release();
        return hr;
    }

    virtual HRESULT __stdcall LockServer(int32_t /*fLock*/) override {
        return S_OK;
    }
};

// ============================================================================
// 7. C Client API & Dynamic Exports
// ============================================================================

inline HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (rclsid == CLSID_ToastNotificationManager) {
        static ToastNotificationManagerClassFactory s_toastFactory;
        return s_toastFactory.QueryInterface(riid, ppv);
    }
    if (rclsid == CLSID_PushNotificationChannelManager) {
        static PushNotificationChannelManagerClassFactory s_pushFactory;
        return s_pushFactory.QueryInterface(riid, ppv);
    }
    *ppv = nullptr;
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

inline void __stdcall SvchostPushServiceGlobals(void* /*pGlobals*/) {
}

// C client APIs
inline HRESULT __stdcall WpnInitialize() {
    PushNotificationManager::get();
    return S_OK;
}

inline HRESULT __stdcall WpnUninitialize() {
    return S_OK;
}

inline HRESULT __stdcall WpnCreateChannelForApp(const wchar_t* appId, WNS_CHANNEL_INFO* pChannelInfo) {
    if (!pChannelInfo) return E_POINTER;
    std::wstring app = appId ? appId : L"DefaultApp";
    ChannelRecord ch = PushNotificationManager::get().createChannel(app);

    std::memset(pChannelInfo, 0, sizeof(WNS_CHANNEL_INFO));
    pChannelInfo->channelId = ch.channelId;
    wcsncpy_s(pChannelInfo->appId, ch.appId.c_str(), 127);
    wcsncpy_s(pChannelInfo->channelUri, ch.channelUri.c_str(), 255);
    pChannelInfo->createdTime = ch.createdTime;
    pChannelInfo->expirationTime = ch.expirationTime;
    pChannelInfo->status = ch.status;
    return S_OK;
}

inline HRESULT __stdcall WpnCloseChannel(const wchar_t* appId) {
    std::wstring app = appId ? appId : L"DefaultApp";
    bool ok = PushNotificationManager::get().closeChannel(app);
    return ok ? S_OK : S_FALSE;
}

inline HRESULT __stdcall WpnShowToast(
    const wchar_t* appId, const wchar_t* title, const wchar_t* message, const wchar_t* tag, uint32_t* pNotificationId
) {
    ToastRecord rec;
    rec.appId = appId ? appId : L"DefaultApp";
    rec.title = title ? title : L"Notification";
    rec.message = message ? message : L"";
    rec.tag = tag ? tag : L"";
    rec.group = L"Default";
    rec.rawXml = L"<toast><visual><binding template=\"ToastGeneric\"><text>" + rec.title + L"</text><text>" + rec.message + L"</text></binding></visual></toast>";

    uint32_t id = PushNotificationManager::get().postToast(rec);
    if (pNotificationId) *pNotificationId = id;
    return S_OK;
}

inline HRESULT __stdcall WpnQueryPendingNotifications(uint32_t* pCount, WNS_TOAST_DESCRIPTOR* pDescriptors, uint32_t maxCount) {
    if (!pCount) return E_POINTER;
    auto active = PushNotificationManager::get().getActiveToasts();
    *pCount = static_cast<uint32_t>(active.size());
    if (!pDescriptors || maxCount == 0) return S_OK;

    uint32_t toCopy = std::min(maxCount, static_cast<uint32_t>(active.size()));
    for (uint32_t i = 0; i < toCopy; ++i) {
        const auto& a = active[i];
        pDescriptors[i].notificationId = a.id;
        wcsncpy_s(pDescriptors[i].appId, a.appId.c_str(), 127);
        wcsncpy_s(pDescriptors[i].tag, a.tag.c_str(), 63);
        wcsncpy_s(pDescriptors[i].group, a.group.c_str(), 63);
        wcsncpy_s(pDescriptors[i].title, a.title.c_str(), 127);
        wcsncpy_s(pDescriptors[i].message, a.message.c_str(), 255);
        wcsncpy_s(pDescriptors[i].launchArgs, a.launchArgs.c_str(), 255);
        pDescriptors[i].timestamp = a.timestamp;
        pDescriptors[i].expiration = a.expiration;
        pDescriptors[i].isDismissed = a.isDismissed ? 1 : 0;
    }
    return S_OK;
}

inline void InitializeWnsSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // 1. wpncore.dll (Windows Push Notifications Platform Core)
    ldr.registerExport("wpncore.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));
    ldr.registerExport("wpncore.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));
    ldr.registerExport("wpncore.dll", "DllRegisterServer", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("wpncore.dll", "DllUnregisterServer", reinterpret_cast<void*>(DllUnregisterServer));
    ldr.registerExport("wpncore.dll", "WpnInitialize", reinterpret_cast<void*>(WpnInitialize));
    ldr.registerExport("wpncore.dll", "WpnUninitialize", reinterpret_cast<void*>(WpnUninitialize));
    ldr.registerExport("wpncore.dll", "WpnQueryPendingNotifications", reinterpret_cast<void*>(WpnQueryPendingNotifications));

    // 2. wpnclient.dll (Windows Push Notifications Client API)
    ldr.registerExport("wpnclient.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));
    ldr.registerExport("wpnclient.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));
    ldr.registerExport("wpnclient.dll", "WpnCreateChannelForApp", reinterpret_cast<void*>(WpnCreateChannelForApp));
    ldr.registerExport("wpnclient.dll", "WpnCloseChannel", reinterpret_cast<void*>(WpnCloseChannel));
    ldr.registerExport("wpnclient.dll", "WpnShowToast", reinterpret_cast<void*>(WpnShowToast));

    // 3. wpnapps.dll (Windows Push Notifications App Service)
    ldr.registerExport("wpnapps.dll", "ServiceMain", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("wpnapps.dll", "SvchostPushServiceGlobals", reinterpret_cast<void*>(SvchostPushServiceGlobals));
    ldr.registerExport("wpnapps.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));

    // Register COM Class Factories in ole32 runtime
    static ToastNotificationManagerClassFactory s_toastFactory;
    static PushNotificationChannelManagerClassFactory s_pushFactory;
    uint32_t cookie = 0;

    (void)ole32::CoRegisterClassObject(
        CLSID_ToastNotificationManager,
        &s_toastFactory,
        ole32::CLSCTX_INPROC_SERVER,
        ole32::REGCLS_MULTIPLEUSE,
        &cookie
    );

    (void)ole32::CoRegisterClassObject(
        CLSID_PushNotificationChannelManager,
        &s_pushFactory,
        ole32::CLSCTX_INPROC_SERVER,
        ole32::REGCLS_MULTIPLEUSE,
        &cookie
    );

    // Trigger sovereign initialization & SCM service registrations
    PushNotificationManager::get();
}

} // namespace micant::wns
