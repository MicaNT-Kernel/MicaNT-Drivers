#pragma once

/**
 * @file location.hpp
 * @brief Clean-Room Windows Geolocation & Location Framework Subsystem (locationapi.dll).
 *
 * Implements the Windows Location API COM architecture, LatLong and Civic Address reports,
 * location events and listeners, sensor telemetry injection, SCM background daemons
 * (lfsvc, SensorService), and Win32 C client APIs.
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
#include "wasapi.hpp"

namespace micant::location {

using namespace micant::ole32;

// ============================================================================
// 1. Location Enums & Structs (win32metadata)
// ============================================================================

enum LOCATION_REPORT_STATUS : uint32_t {
    REPORT_NOT_SUPPORTED = 0,
    REPORT_ERROR         = 1,
    REPORT_ACCESS_DENIED = 2,
    REPORT_INITIALIZING  = 3,
    REPORT_RUNNING       = 4
};

enum LOCATION_DESIRED_ACCURACY : uint32_t {
    LOCATION_DESIRED_ACCURACY_DEFAULT = 0,
    LOCATION_DESIRED_ACCURACY_HIGH    = 1
};

using SENSOR_ID = GUID;

#pragma pack(push, 1)

struct LOCATION_COORDINATES {
    double latitude;
    double longitude;
    double altitude;
    double errorRadius;
    double altitudeError;
    double heading;
    double speed;
    win32::SYSTEMTIME timestamp;
};

struct LOCATION_CIVIC_ADDRESS {
    wchar_t addressLine1[128];
    wchar_t addressLine2[128];
    wchar_t city[64];
    wchar_t stateProvince[64];
    wchar_t postalCode[32];
    wchar_t countryRegion[32];
    uint32_t detailLevel;
};

#pragma pack(pop)

// ============================================================================
// 2. Location COM GUIDs
// ============================================================================

inline const GUID CLSID_Location = {
    0xE5B8E079, 0xEE6D, 0x4E33, { 0xA4, 0x38, 0xC0, 0xF3, 0xE7, 0xE9, 0x42, 0xA0 }
};

inline const GUID IID_ILocation = {
    0xAB2EC69F, 0x3956, 0x414B, { 0x95, 0x20, 0xFE, 0x45, 0x0D, 0x54, 0x02, 0x1C }
};

inline const GUID IID_ILocationReport = {
    0xC8B7F7EE, 0x75D0, 0x4DB9, { 0xB6, 0x2D, 0x7A, 0x0F, 0x36, 0x9C, 0xA4, 0x56 }
};

inline const GUID IID_ILatLongReport = {
    0x7FED806D, 0x0E42, 0x47E0, { 0x80, 0x13, 0x71, 0x84, 0x4C, 0xB4, 0xE3, 0x66 }
};

inline const GUID IID_ICivicAddressReport = {
    0xC0B19F40, 0x2111, 0x4EA3, { 0xAC, 0x7F, 0x95, 0x9E, 0x16, 0x57, 0x02, 0xB2 }
};

inline const GUID IID_ILocationEvents = {
    0xCAE2DE34, 0xEE2C, 0x4271, { 0x84, 0xE9, 0xE4, 0xBD, 0x70, 0xCE, 0x4D, 0x10 }
};

inline const GUID IID_IDispLatLongReport = {
    0x8AE32723, 0x389B, 0x4A11, { 0x99, 0x57, 0x5B, 0xD8, 0x27, 0x7E, 0x37, 0xEB }
};

inline const GUID IID_IDispCivicAddressReport = {
    0x16FF1A34, 0x9E30, 0x42C1, { 0x9D, 0x45, 0x70, 0x54, 0xC3, 0x5F, 0x36, 0x0C }
};

inline const GUID CLSID_LatLongReportFactory = {
    0x9D32F696, 0xAE53, 0x46D4, { 0xB8, 0x50, 0x79, 0x5B, 0x95, 0x92, 0x20, 0xAB }
};

inline const GUID CLSID_CivicAddressReportFactory = {
    0x2A11F42C, 0x3E81, 0x4AD8, { 0x9C, 0x18, 0x22, 0xA5, 0x03, 0xC4, 0x0C, 0x72 }
};

// ============================================================================
// 3. COM Interface Definitions
// ============================================================================

class ILocationReport;
class ILatLongReport;
class ICivicAddressReport;
class ILocationEvents;
class ILocation;

class ILocationReport : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall GetSensorID(SENSOR_ID* pSensorID) = 0;
    virtual HRESULT __stdcall GetTimestamp(win32::SYSTEMTIME* pCreationTime) = 0;
    virtual HRESULT __stdcall GetValue(const wasapi::PROPERTYKEY* pKey, wasapi::PROPVARIANT* pValue) = 0;
};

class ILatLongReport : public ILocationReport {
public:
    virtual HRESULT __stdcall GetLatitude(double* pLatitude) = 0;
    virtual HRESULT __stdcall GetLongitude(double* pLongitude) = 0;
    virtual HRESULT __stdcall GetErrorRadius(double* pErrorRadius) = 0;
    virtual HRESULT __stdcall GetAltitude(double* pAltitude) = 0;
    virtual HRESULT __stdcall GetAltitudeError(double* pAltitudeError) = 0;
    virtual HRESULT __stdcall GetHeading(double* pHeading) = 0;
    virtual HRESULT __stdcall GetSpeed(double* pSpeed) = 0;
};

class ICivicAddressReport : public ILocationReport {
public:
    virtual HRESULT __stdcall GetAddressLine1(BSTR* pbstrAddress1) = 0;
    virtual HRESULT __stdcall GetAddressLine2(BSTR* pbstrAddress2) = 0;
    virtual HRESULT __stdcall GetCity(BSTR* pbstrCity) = 0;
    virtual HRESULT __stdcall GetStateProvince(BSTR* pbstrStateProvince) = 0;
    virtual HRESULT __stdcall GetPostalCode(BSTR* pbstrPostalCode) = 0;
    virtual HRESULT __stdcall GetCountryRegion(BSTR* pbstrCountryRegion) = 0;
    virtual HRESULT __stdcall GetDetailLevel(uint32_t* pDetailLevel) = 0;
};

class ILocationEvents : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall OnLocationChanged(REFIID reportType, ILocationReport* pLocationReport) = 0;
    virtual HRESULT __stdcall OnStatusChanged(REFIID reportType, LOCATION_REPORT_STATUS status) = 0;
};

class ILocation : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall RegisterForReport(ILocationEvents* pEvents, REFIID reportType, uint32_t dwMinInterval) = 0;
    virtual HRESULT __stdcall UnregisterForReport(REFIID reportType) = 0;
    virtual HRESULT __stdcall GetReport(REFIID reportType, ILocationReport** ppLocationReport) = 0;
    virtual HRESULT __stdcall GetReportStatus(REFIID reportType, LOCATION_REPORT_STATUS* pStatus) = 0;
    virtual HRESULT __stdcall GetReportInterval(REFIID reportType, uint32_t* pMilliseconds) = 0;
    virtual HRESULT __stdcall SetReportInterval(REFIID reportType, uint32_t milliseconds) = 0;
    virtual HRESULT __stdcall RequestPermissions(void* hParent, IID* pReportTypes, uint32_t count, int32_t fModal) = 0;
    virtual HRESULT __stdcall GetDesiredAccuracy(REFIID reportType, LOCATION_DESIRED_ACCURACY* pDesiredAccuracy) = 0;
    virtual HRESULT __stdcall SetDesiredAccuracy(REFIID reportType, LOCATION_DESIRED_ACCURACY desiredAccuracy) = 0;
};

// ============================================================================
// 4. Sovereign Geolocation State & LocationManager Singleton
// ============================================================================

struct LocationListenerEntry {
    GUID reportType;
    ILocationEvents* pEvents{nullptr};
    uint32_t minInterval{1000};
};

class LocationManager {
private:
    mutable std::mutex m_mutex;
    SENSOR_ID m_sensorId{};
    LOCATION_COORDINATES m_coords{};
    LOCATION_CIVIC_ADDRESS m_civic{};
    LOCATION_REPORT_STATUS m_status{REPORT_RUNNING};
    LOCATION_DESIRED_ACCURACY m_accuracy{LOCATION_DESIRED_ACCURACY_DEFAULT};
    uint32_t m_interval{1000};
    std::vector<LocationListenerEntry> m_listeners;

    LocationManager() {
        initDefaultLocation();
        registerScmServices();
    }

    void initDefaultLocation() {
        // Cutler DEC WRL / Sovereign Seattle Coordinates
        m_sensorId = { 0x53454E53, 0x4750, 0x5330, { 0x4D, 0x49, 0x43, 0x41, 0x4C, 0x4F, 0x43, 0x31 } }; // SENSGPS0-MICALOC1

        m_coords.latitude = 47.6062;      // Seattle, WA
        m_coords.longitude = -122.3321;
        m_coords.altitude = 54.0;         // 54m above MSL
        m_coords.errorRadius = 5.0;       // 5m horizontal accuracy
        m_coords.altitudeError = 2.0;     // 2m vertical accuracy
        m_coords.heading = 180.0;         // Southbound
        m_coords.speed = 0.0;             // Stationary

        m_coords.timestamp.wYear = 2026;
        m_coords.timestamp.wMonth = 10;
        m_coords.timestamp.wDay = 4;
        m_coords.timestamp.wHour = 8;
        m_coords.timestamp.wMinute = 0;
        m_coords.timestamp.wSecond = 0;
        m_coords.timestamp.wMilliseconds = 0;

        wcsncpy_s(m_civic.addressLine1, L"One Sovereign Way", 127);
        wcsncpy_s(m_civic.addressLine2, L"Suite 100", 127);
        wcsncpy_s(m_civic.city, L"Redmond", 63);
        wcsncpy_s(m_civic.stateProvince, L"WA", 63);
        wcsncpy_s(m_civic.postalCode, L"98052", 31);
        wcsncpy_s(m_civic.countryRegion, L"US", 31);
        m_civic.detailLevel = 1;

        m_status = REPORT_RUNNING;
        m_accuracy = LOCATION_DESIRED_ACCURACY_DEFAULT;
        m_interval = 1000;
    }

    void registerScmServices() {
        auto& scm = scm::ServiceControlManager::get();

        // 1. lfsvc: Geolocation Service
        auto lfSvc = std::make_shared<scm::ServiceRecord>();
        lfSvc->serviceName = L"lfsvc";
        lfSvc->displayName = L"Geolocation Service";
        lfSvc->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        lfSvc->startType = scm::SERVICE_DEMAND_START;
        lfSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
        lfSvc->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted";
        lfSvc->loadOrderGroup = L"LocalSystemNetworkRestricted";
        lfSvc->status.dwServiceType = lfSvc->serviceType;
        lfSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
        lfSvc->status.dwProcessId = 1150;
        scm.registerServiceRecord(lfSvc);

        // 2. SensorService / sensrsvc: Sensor Service
        auto sensorSvc = std::make_shared<scm::ServiceRecord>();
        sensorSvc->serviceName = L"SensorService";
        sensorSvc->displayName = L"Sensor Service";
        sensorSvc->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        sensorSvc->startType = scm::SERVICE_DEMAND_START;
        sensorSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
        sensorSvc->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k LocalService";
        sensorSvc->loadOrderGroup = L"LocalService";
        sensorSvc->status.dwServiceType = sensorSvc->serviceType;
        sensorSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
        sensorSvc->status.dwProcessId = 1154;
        scm.registerServiceRecord(sensorSvc);
    }

public:
    static LocationManager& get() noexcept {
        static LocationManager instance;
        return instance;
    }

    LocationManager(const LocationManager&) = delete;
    LocationManager& operator=(const LocationManager&) = delete;

    void resetToDefault() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_listeners.clear();
        initDefaultLocation();
    }

    SENSOR_ID getSensorId() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sensorId;
    }

    LOCATION_COORDINATES getCoordinates() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_coords;
    }

    LOCATION_CIVIC_ADDRESS getCivicAddress() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_civic;
    }

    LOCATION_REPORT_STATUS getStatus() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_status;
    }

    void setStatus(LOCATION_REPORT_STATUS status) {
        std::vector<LocationListenerEntry> listenersCopy;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_status = status;
            listenersCopy = m_listeners;
        }
        for (const auto& entry : listenersCopy) {
            if (entry.pEvents) {
                entry.pEvents->OnStatusChanged(entry.reportType, status);
            }
        }
    }

    LOCATION_DESIRED_ACCURACY getDesiredAccuracy() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_accuracy;
    }

    void setDesiredAccuracy(LOCATION_DESIRED_ACCURACY accuracy) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_accuracy = accuracy;
    }

    uint32_t getReportInterval() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_interval;
    }

    void setReportInterval(uint32_t ms) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_interval = ms;
    }

    void setCoordinates(double lat, double lon, double alt = 0.0, double accuracy = 5.0, double heading = 0.0, double speed = 0.0) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_coords.latitude = lat;
        m_coords.longitude = lon;
        m_coords.altitude = alt;
        m_coords.errorRadius = accuracy;
        m_coords.heading = heading;
        m_coords.speed = speed;
    }

    void setCivicAddress(const std::wstring& addr1, const std::wstring& addr2, const std::wstring& city,
                         const std::wstring& state, const std::wstring& zip, const std::wstring& country) {
        std::lock_guard<std::mutex> lock(m_mutex);
        wcsncpy_s(m_civic.addressLine1, addr1.c_str(), 127);
        wcsncpy_s(m_civic.addressLine2, addr2.c_str(), 127);
        wcsncpy_s(m_civic.city, city.c_str(), 63);
        wcsncpy_s(m_civic.stateProvince, state.c_str(), 63);
        wcsncpy_s(m_civic.postalCode, zip.c_str(), 31);
        wcsncpy_s(m_civic.countryRegion, country.c_str(), 31);
    }

    void registerListener(REFIID reportType, ILocationEvents* pEvents, uint32_t minInterval) {
        if (!pEvents) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& entry : m_listeners) {
            if (entry.reportType == reportType && entry.pEvents == pEvents) {
                entry.minInterval = minInterval;
                return;
            }
        }
        LocationListenerEntry entry;
        entry.reportType = reportType;
        entry.pEvents = pEvents;
        entry.minInterval = minInterval;
        pEvents->AddRef();
        m_listeners.push_back(entry);
    }

    void unregisterListener(REFIID reportType) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_listeners.begin(); it != m_listeners.end(); ) {
            if (it->reportType == reportType) {
                if (it->pEvents) {
                    it->pEvents->Release();
                }
                it = m_listeners.erase(it);
            } else {
                ++it;
            }
        }
    }

    size_t getListenerCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_listeners.size();
    }
};

// ============================================================================
// 5. COM Class Implementations
// ============================================================================

class LatLongReportImpl : public ILatLongReport {
private:
    uint32_t m_refCount{1};
    SENSOR_ID m_sensorId{};
    LOCATION_COORDINATES m_coords{};

public:
    LatLongReportImpl(const SENSOR_ID& sensorId, const LOCATION_COORDINATES& coords)
        : m_sensorId(sensorId), m_coords(coords) {}

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ILocationReport || riid == IID_ILatLongReport) {
            *ppvObject = static_cast<ILatLongReport*>(this);
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

    // ILocationReport
    virtual HRESULT __stdcall GetSensorID(SENSOR_ID* pSensorID) override {
        if (!pSensorID) return E_POINTER;
        *pSensorID = m_sensorId;
        return S_OK;
    }

    virtual HRESULT __stdcall GetTimestamp(win32::SYSTEMTIME* pCreationTime) override {
        if (!pCreationTime) return E_POINTER;
        *pCreationTime = m_coords.timestamp;
        return S_OK;
    }

    virtual HRESULT __stdcall GetValue(const wasapi::PROPERTYKEY* /*pKey*/, wasapi::PROPVARIANT* pValue) override {
        if (!pValue) return E_POINTER;
        std::memset(pValue, 0, sizeof(wasapi::PROPVARIANT));
        return S_OK;
    }

    // ILatLongReport
    virtual HRESULT __stdcall GetLatitude(double* pLatitude) override {
        if (!pLatitude) return E_POINTER;
        *pLatitude = m_coords.latitude;
        return S_OK;
    }

    virtual HRESULT __stdcall GetLongitude(double* pLongitude) override {
        if (!pLongitude) return E_POINTER;
        *pLongitude = m_coords.longitude;
        return S_OK;
    }

    virtual HRESULT __stdcall GetErrorRadius(double* pErrorRadius) override {
        if (!pErrorRadius) return E_POINTER;
        *pErrorRadius = m_coords.errorRadius;
        return S_OK;
    }

    virtual HRESULT __stdcall GetAltitude(double* pAltitude) override {
        if (!pAltitude) return E_POINTER;
        *pAltitude = m_coords.altitude;
        return S_OK;
    }

    virtual HRESULT __stdcall GetAltitudeError(double* pAltitudeError) override {
        if (!pAltitudeError) return E_POINTER;
        *pAltitudeError = m_coords.altitudeError;
        return S_OK;
    }

    virtual HRESULT __stdcall GetHeading(double* pHeading) override {
        if (!pHeading) return E_POINTER;
        *pHeading = m_coords.heading;
        return S_OK;
    }

    virtual HRESULT __stdcall GetSpeed(double* pSpeed) override {
        if (!pSpeed) return E_POINTER;
        *pSpeed = m_coords.speed;
        return S_OK;
    }
};

class CivicAddressReportImpl : public ICivicAddressReport {
private:
    uint32_t m_refCount{1};
    SENSOR_ID m_sensorId{};
    LOCATION_CIVIC_ADDRESS m_civic{};
    win32::SYSTEMTIME m_timestamp{};

public:
    CivicAddressReportImpl(const SENSOR_ID& sensorId, const LOCATION_CIVIC_ADDRESS& civic, const win32::SYSTEMTIME& st)
        : m_sensorId(sensorId), m_civic(civic), m_timestamp(st) {}

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ILocationReport || riid == IID_ICivicAddressReport) {
            *ppvObject = static_cast<ICivicAddressReport*>(this);
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

    // ILocationReport
    virtual HRESULT __stdcall GetSensorID(SENSOR_ID* pSensorID) override {
        if (!pSensorID) return E_POINTER;
        *pSensorID = m_sensorId;
        return S_OK;
    }

    virtual HRESULT __stdcall GetTimestamp(win32::SYSTEMTIME* pCreationTime) override {
        if (!pCreationTime) return E_POINTER;
        *pCreationTime = m_timestamp;
        return S_OK;
    }

    virtual HRESULT __stdcall GetValue(const wasapi::PROPERTYKEY* /*pKey*/, wasapi::PROPVARIANT* pValue) override {
        if (!pValue) return E_POINTER;
        std::memset(pValue, 0, sizeof(wasapi::PROPVARIANT));
        return S_OK;
    }

    // ICivicAddressReport
    virtual HRESULT __stdcall GetAddressLine1(BSTR* pbstrAddress1) override {
        if (!pbstrAddress1) return E_POINTER;
        *pbstrAddress1 = ole32::SysAllocString(m_civic.addressLine1);
        return S_OK;
    }

    virtual HRESULT __stdcall GetAddressLine2(BSTR* pbstrAddress2) override {
        if (!pbstrAddress2) return E_POINTER;
        *pbstrAddress2 = ole32::SysAllocString(m_civic.addressLine2);
        return S_OK;
    }

    virtual HRESULT __stdcall GetCity(BSTR* pbstrCity) override {
        if (!pbstrCity) return E_POINTER;
        *pbstrCity = ole32::SysAllocString(m_civic.city);
        return S_OK;
    }

    virtual HRESULT __stdcall GetStateProvince(BSTR* pbstrStateProvince) override {
        if (!pbstrStateProvince) return E_POINTER;
        *pbstrStateProvince = ole32::SysAllocString(m_civic.stateProvince);
        return S_OK;
    }

    virtual HRESULT __stdcall GetPostalCode(BSTR* pbstrPostalCode) override {
        if (!pbstrPostalCode) return E_POINTER;
        *pbstrPostalCode = ole32::SysAllocString(m_civic.postalCode);
        return S_OK;
    }

    virtual HRESULT __stdcall GetCountryRegion(BSTR* pbstrCountryRegion) override {
        if (!pbstrCountryRegion) return E_POINTER;
        *pbstrCountryRegion = ole32::SysAllocString(m_civic.countryRegion);
        return S_OK;
    }

    virtual HRESULT __stdcall GetDetailLevel(uint32_t* pDetailLevel) override {
        if (!pDetailLevel) return E_POINTER;
        *pDetailLevel = m_civic.detailLevel;
        return S_OK;
    }
};

class LocationImpl : public ILocation {
private:
    uint32_t m_refCount{1};

public:
    LocationImpl() = default;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ILocation) {
            *ppvObject = static_cast<ILocation*>(this);
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

    virtual HRESULT __stdcall RegisterForReport(ILocationEvents* pEvents, REFIID reportType, uint32_t dwMinInterval) override {
        if (!pEvents) return E_POINTER;
        LocationManager::get().registerListener(reportType, pEvents, dwMinInterval);
        return S_OK;
    }

    virtual HRESULT __stdcall UnregisterForReport(REFIID reportType) override {
        LocationManager::get().unregisterListener(reportType);
        return S_OK;
    }

    virtual HRESULT __stdcall GetReport(REFIID reportType, ILocationReport** ppLocationReport) override {
        if (!ppLocationReport) return E_POINTER;
        *ppLocationReport = nullptr;

        auto& mgr = LocationManager::get();
        if (mgr.getStatus() != REPORT_RUNNING) {
            return static_cast<HRESULT>(0x80004005); // E_FAIL
        }

        if (reportType == IID_ILatLongReport) {
            auto sensorId = mgr.getSensorId();
            auto coords = mgr.getCoordinates();
            *ppLocationReport = new LatLongReportImpl(sensorId, coords);
            return S_OK;
        }

        if (reportType == IID_ICivicAddressReport) {
            auto sensorId = mgr.getSensorId();
            auto civic = mgr.getCivicAddress();
            auto coords = mgr.getCoordinates();
            *ppLocationReport = new CivicAddressReportImpl(sensorId, civic, coords.timestamp);
            return S_OK;
        }

        return E_NOINTERFACE;
    }

    virtual HRESULT __stdcall GetReportStatus(REFIID /*reportType*/, LOCATION_REPORT_STATUS* pStatus) override {
        if (!pStatus) return E_POINTER;
        *pStatus = LocationManager::get().getStatus();
        return S_OK;
    }

    virtual HRESULT __stdcall GetReportInterval(REFIID /*reportType*/, uint32_t* pMilliseconds) override {
        if (!pMilliseconds) return E_POINTER;
        *pMilliseconds = LocationManager::get().getReportInterval();
        return S_OK;
    }

    virtual HRESULT __stdcall SetReportInterval(REFIID /*reportType*/, uint32_t milliseconds) override {
        LocationManager::get().setReportInterval(milliseconds);
        return S_OK;
    }

    virtual HRESULT __stdcall RequestPermissions(void* /*hParent*/, IID* /*pReportTypes*/, uint32_t /*count*/, int32_t /*fModal*/) override {
        // MicaNT Sovereign: User permissions are granted by default with zero cloud telemetry
        return S_OK;
    }

    virtual HRESULT __stdcall GetDesiredAccuracy(REFIID /*reportType*/, LOCATION_DESIRED_ACCURACY* pDesiredAccuracy) override {
        if (!pDesiredAccuracy) return E_POINTER;
        *pDesiredAccuracy = LocationManager::get().getDesiredAccuracy();
        return S_OK;
    }

    virtual HRESULT __stdcall SetDesiredAccuracy(REFIID /*reportType*/, LOCATION_DESIRED_ACCURACY desiredAccuracy) override {
        LocationManager::get().setDesiredAccuracy(desiredAccuracy);
        return S_OK;
    }
};

// ============================================================================
// 6. Class Factories
// ============================================================================

class LocationClassFactory : public ole32::IClassFactory {
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

        auto* pLoc = new LocationImpl();
        HRESULT hr = pLoc->QueryInterface(riid, ppvObject);
        pLoc->Release();
        return hr;
    }

    virtual HRESULT __stdcall LockServer(int32_t /*fLock*/) override {
        return S_OK;
    }
};

// ============================================================================
// 7. C Client API & Dynamic Exports (locationapi.dll)
// ============================================================================

inline HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (rclsid == CLSID_Location) {
        static LocationClassFactory s_locationFactory;
        return s_locationFactory.QueryInterface(riid, ppv);
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

// C client APIs
inline HRESULT __stdcall LocationInitialize() {
    LocationManager::get();
    return S_OK;
}

inline HRESULT __stdcall LocationUninitialize() {
    return S_OK;
}

inline HRESULT __stdcall LocationGetCoordinates(double* pLat, double* pLon, double* pAccuracy) {
    if (!pLat || !pLon) return E_POINTER;
    auto coords = LocationManager::get().getCoordinates();
    *pLat = coords.latitude;
    *pLon = coords.longitude;
    if (pAccuracy) *pAccuracy = coords.errorRadius;
    return S_OK;
}

inline HRESULT __stdcall LocationSetCoordinates(double lat, double lon, double alt) {
    LocationManager::get().setCoordinates(lat, lon, alt);
    return S_OK;
}

inline HRESULT __stdcall LocationGetStatus(uint32_t* pStatus) {
    if (!pStatus) return E_POINTER;
    *pStatus = LocationManager::get().getStatus();
    return S_OK;
}

inline void InitializeLocationSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // locationapi.dll (Windows Location API)
    ldr.registerExport("locationapi.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));
    ldr.registerExport("locationapi.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));
    ldr.registerExport("locationapi.dll", "DllRegisterServer", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("locationapi.dll", "DllUnregisterServer", reinterpret_cast<void*>(DllUnregisterServer));
    ldr.registerExport("locationapi.dll", "LocationInitialize", reinterpret_cast<void*>(LocationInitialize));
    ldr.registerExport("locationapi.dll", "LocationUninitialize", reinterpret_cast<void*>(LocationUninitialize));
    ldr.registerExport("locationapi.dll", "LocationGetCoordinates", reinterpret_cast<void*>(LocationGetCoordinates));
    ldr.registerExport("locationapi.dll", "LocationSetCoordinates", reinterpret_cast<void*>(LocationSetCoordinates));
    ldr.registerExport("locationapi.dll", "LocationGetStatus", reinterpret_cast<void*>(LocationGetStatus));

    // Register COM Class Factory in ole32 runtime
    static LocationClassFactory s_locationFactory;
    uint32_t cookie = 0;

    (void)ole32::CoRegisterClassObject(
        CLSID_Location,
        &s_locationFactory,
        ole32::CLSCTX_INPROC_SERVER,
        ole32::REGCLS_MULTIPLEUSE,
        &cookie
    );

    // Ensure sovereign services and default state initialized
    LocationManager::get();
}

} // namespace micant::location
