#pragma once

/**
 * @file sensors.hpp
 * @brief Clean-Room Windows Sensors API & Sensor Class Extension Subsystem (sensorsapi.dll / sensorsclassextension.dll).
 *
 * Implements the Windows Sensor Platform COM architecture, ISensorManager, ISensorCollection,
 * ISensor, ISensorDataReport, ISensorEvents, ISensorClassExtension, sensor data type definitions,
 * SCM background daemon (SensorDataService), and Win32 C client APIs.
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

#include "ntdef.hpp"
#include "kernel32.hpp"
#include "ole32.hpp"
#include "oleaut32.hpp"
#include "scm.hpp"
#include "ldr.hpp"
#include "wasapi.hpp"

namespace micant::sensors {

using namespace micant::ole32;

// ============================================================================
// 1. Sensor Platform COM GUIDs, Categories, Types & Properties
// ============================================================================

inline const GUID CLSID_SensorManager = {
    0x77A1C827, 0xFCD2, 0x4689, { 0x89, 0x15, 0x9D, 0x61, 0x3C, 0xC5, 0xFA, 0x3E }
};

inline const GUID IID_ISensorManager = {
    0xBD77DB67, 0x45A8, 0x47DC, { 0x8D, 0x53, 0x83, 0x7F, 0x04, 0xE9, 0xF8, 0x04 }
};

inline const GUID CLSID_SensorCollection = {
    0x79C07232, 0x4AEC, 0x4583, { 0xB4, 0x1E, 0xD7, 0xF4, 0xE9, 0xFA, 0x79, 0xAE }
};

inline const GUID IID_ISensorCollection = {
    0x23571E11, 0xE545, 0x4DD8, { 0xA3, 0x37, 0xB8, 0x9B, 0x44, 0x5D, 0x10, 0xF8 }
};

inline const GUID IID_ISensor = {
    0x5FA08F80, 0x2657, 0x458E, { 0xAF, 0x75, 0x46, 0xF7, 0x3F, 0xA6, 0xAC, 0x5C }
};

inline const GUID IID_ISensorDataReport = {
    0x5FD70311, 0x4A9F, 0x44EC, { 0xA9, 0x8B, 0xF6, 0xE2, 0x07, 0x03, 0xC1, 0x24 }
};

inline const GUID IID_ISensorEvents = {
    0x5D8DCC91, 0x4641, 0x47E7, { 0xB7, 0xC3, 0xB7, 0x4F, 0x48, 0xA6, 0x32, 0x17 }
};

inline const GUID CLSID_SensorClassExtension = {
    0x897EB1C6, 0x1FDF, 0x4395, { 0x97, 0xCE, 0x29, 0x7D, 0x5B, 0x21, 0xA1, 0xA5 }
};

inline const GUID IID_ISensorClassExtension = {
    0xC02A8290, 0x7F16, 0x4B1C, { 0xAA, 0x6B, 0x66, 0x2B, 0x6E, 0x6A, 0x8A, 0x9E }
};

// Sensor Categories
inline const GUID SENSOR_CATEGORY_ALL = {
    0xC317C286, 0xC468, 0x4288, { 0x99, 0x75, 0xD4, 0xC4, 0xB6, 0x99, 0xA7, 0x3A }
};

inline const GUID SENSOR_CATEGORY_MOTION = {
    0xCD084D50, 0xE431, 0x476C, { 0x83, 0xB6, 0xC9, 0x60, 0xEB, 0xE6, 0x00, 0x11 }
};

inline const GUID SENSOR_CATEGORY_ORIENTATION = {
    0x9D6DE96D, 0x60B4, 0x4516, { 0xA5, 0xEC, 0xB9, 0x8D, 0x4A, 0x0D, 0x2B, 0x59 }
};

inline const GUID SENSOR_CATEGORY_LIGHT = {
    0x17A665C0, 0xE0F7, 0x4B24, { 0xAA, 0x85, 0x72, 0xE6, 0x77, 0xDE, 0xE6, 0x3C }
};

inline const GUID SENSOR_CATEGORY_ENVIRONMENTAL = {
    0x322DAF82, 0xD021, 0x40F9, { 0xBE, 0xD1, 0x93, 0x16, 0x03, 0x6D, 0x21, 0x5F }
};

inline const GUID SENSOR_CATEGORY_LOCATION = {
    0xBFA794E4, 0xF964, 0x4F53, { 0xB0, 0x55, 0x98, 0x3C, 0xA5, 0x07, 0x2E, 0xC8 }
};

// Sensor Types
inline const GUID SENSOR_TYPE_ACCELEROMETER_3D = {
    0xC2FB0F5F, 0xE2D2, 0x4C78, { 0xBC, 0xD0, 0x3B, 0xC8, 0x6F, 0x99, 0x8F, 0x37 }
};

inline const GUID SENSOR_TYPE_AMBIENT_LIGHT = {
    0x97F115C8, 0x599A, 0x4153, { 0x88, 0x94, 0xD2, 0xD1, 0x28, 0x99, 0x91, 0x8A }
};

inline const GUID SENSOR_TYPE_COMPASS_3D = {
    0xB7305015, 0x3269, 0x42E5, { 0xAC, 0x19, 0x4E, 0x50, 0x4E, 0x62, 0x47, 0xF5 }
};

inline const GUID SENSOR_TYPE_GYROSCOPE_3D = {
    0x09485F82, 0x7593, 0x495A, { 0x8C, 0x69, 0x70, 0xF9, 0x8E, 0x5E, 0x12, 0xFB }
};

inline const GUID SENSOR_TYPE_INCLINOMETER_3D = {
    0x0E903829, 0xFF8A, 0x4A93, { 0x97, 0xD4, 0xF3, 0xC6, 0xF7, 0x9B, 0x97, 0x66 }
};

inline const GUID SENSOR_TYPE_BAROMETER = {
    0x0E796CA1, 0x6CA4, 0x4106, { 0xA0, 0x59, 0x45, 0x04, 0x53, 0x7D, 0x1D, 0x08 }
};

// Sensor Data Fields (PROPERTYKEY)
inline const wasapi::PROPERTYKEY SENSOR_DATA_TYPE_ACCELERATION_X_G = {
    { 0x3F8A69A2, 0x160F, 0x4FB4, { 0xA7, 0x7B, 0xD5, 0xC3, 0xCF, 0x40, 0x36, 0x04 } }, 2
};
inline const wasapi::PROPERTYKEY SENSOR_DATA_TYPE_ACCELERATION_Y_G = {
    { 0x3F8A69A2, 0x160F, 0x4FB4, { 0xA7, 0x7B, 0xD5, 0xC3, 0xCF, 0x40, 0x36, 0x04 } }, 3
};
inline const wasapi::PROPERTYKEY SENSOR_DATA_TYPE_ACCELERATION_Z_G = {
    { 0x3F8A69A2, 0x160F, 0x4FB4, { 0xA7, 0x7B, 0xD5, 0xC3, 0xCF, 0x40, 0x36, 0x04 } }, 4
};
inline const wasapi::PROPERTYKEY SENSOR_DATA_TYPE_LIGHT_LUX = {
    { 0xE4C77969, 0x9AB7, 0x4447, { 0x9D, 0x72, 0x5F, 0x73, 0xE3, 0xB5, 0x05, 0x09 } }, 2
};
inline const wasapi::PROPERTYKEY SENSOR_DATA_TYPE_MAGNETIC_HEADING_DEGREES = {
    { 0xB3995874, 0x12C6, 0x4C54, { 0x8B, 0x8E, 0xA4, 0x30, 0x26, 0xCE, 0x64, 0x0F } }, 2
};
inline const wasapi::PROPERTYKEY SENSOR_DATA_TYPE_ANGULAR_VELOCITY_X_DEGREES_PER_SECOND = {
    { 0x3B86C2B8, 0x64F4, 0x49E0, { 0xAE, 0x30, 0xE5, 0x77, 0xA7, 0x79, 0x0E, 0x52 } }, 2
};
inline const wasapi::PROPERTYKEY SENSOR_DATA_TYPE_ANGULAR_VELOCITY_Y_DEGREES_PER_SECOND = {
    { 0x3B86C2B8, 0x64F4, 0x49E0, { 0xAE, 0x30, 0xE5, 0x77, 0xA7, 0x79, 0x0E, 0x52 } }, 3
};
inline const wasapi::PROPERTYKEY SENSOR_DATA_TYPE_ANGULAR_VELOCITY_Z_DEGREES_PER_SECOND = {
    { 0x3B86C2B8, 0x64F4, 0x49E0, { 0xAE, 0x30, 0xE5, 0x77, 0xA7, 0x79, 0x0E, 0x52 } }, 4
};
inline const wasapi::PROPERTYKEY SENSOR_DATA_TYPE_ATMOSPHERIC_PRESSURE_BAR = {
    { 0x8E204EE4, 0xD586, 0x4340, { 0x9E, 0x00, 0x82, 0xB8, 0xE6, 0x71, 0x23, 0x20 } }, 2
};
inline const wasapi::PROPERTYKEY SENSOR_DATA_TYPE_TIMESTAMP = {
    { 0x310605A4, 0x5F57, 0x454A, { 0x8A, 0x97, 0x12, 0xE5, 0x57, 0xF8, 0x99, 0xCF } }, 2
};

// Sensor Properties
inline const wasapi::PROPERTYKEY SENSOR_PROPERTY_FRIENDLY_NAME = {
    { 0x7F8383EC, 0xDEDA, 0x4CAE, { 0x8A, 0x96, 0x38, 0x08, 0x0E, 0x7B, 0x0E, 0xA8 } }, 2
};
inline const wasapi::PROPERTYKEY SENSOR_PROPERTY_MANUFACTURER = {
    { 0x7F8383EC, 0xDEDA, 0x4CAE, { 0x8A, 0x96, 0x38, 0x08, 0x0E, 0x7B, 0x0E, 0xA8 } }, 3
};
inline const wasapi::PROPERTYKEY SENSOR_PROPERTY_MODEL = {
    { 0x7F8383EC, 0xDEDA, 0x4CAE, { 0x8A, 0x96, 0x38, 0x08, 0x0E, 0x7B, 0x0E, 0xA8 } }, 4
};
inline const wasapi::PROPERTYKEY SENSOR_PROPERTY_SERIAL_NUMBER = {
    { 0x7F8383EC, 0xDEDA, 0x4CAE, { 0x8A, 0x96, 0x38, 0x08, 0x0E, 0x7B, 0x0E, 0xA8 } }, 5
};
inline const wasapi::PROPERTYKEY SENSOR_PROPERTY_MIN_REPORT_INTERVAL = {
    { 0x7F8383EC, 0xDEDA, 0x4CAE, { 0x8A, 0x96, 0x38, 0x08, 0x0E, 0x7B, 0x0E, 0xA8 } }, 8
};
inline const wasapi::PROPERTYKEY SENSOR_PROPERTY_CURRENT_REPORT_INTERVAL = {
    { 0x7F8383EC, 0xDEDA, 0x4CAE, { 0x8A, 0x96, 0x38, 0x08, 0x0E, 0x7B, 0x0E, 0xA8 } }, 9
};

// Sensor States
enum SensorState : uint32_t {
    SENSOR_STATE_MIN          = 0,
    SENSOR_STATE_READY        = 0,
    SENSOR_STATE_NOT_AVAILABLE= 1,
    SENSOR_STATE_NO_DATA      = 2,
    SENSOR_STATE_INITIALIZING = 3,
    SENSOR_STATE_ACCESS_DENIED= 4,
    SENSOR_STATE_ERROR        = 5,
    SENSOR_STATE_MAX          = 5
};

using SENSOR_ID = GUID;
using SENSOR_TYPE_ID = GUID;
using SENSOR_CATEGORY_ID = GUID;

// ============================================================================
// 2. COM Interfaces
// ============================================================================

class ISensorDataReport;
class ISensor;
class ISensorCollection;
class ISensorEvents;
class ISensorManager;
class ISensorClassExtension;

class ISensorDataReport : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall GetTimestamp(win32::SYSTEMTIME* pTimeStamp) = 0;
    virtual HRESULT __stdcall GetSensorValue(const wasapi::PROPERTYKEY& pKey, wasapi::PROPVARIANT* pValue) = 0;
    virtual HRESULT __stdcall GetSensorValues(void* pKeys, void** ppValues) = 0;
};

class ISensor : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall GetID(SENSOR_ID* pID) = 0;
    virtual HRESULT __stdcall GetCategory(SENSOR_CATEGORY_ID* pSensorCategory) = 0;
    virtual HRESULT __stdcall GetType(SENSOR_TYPE_ID* pSensorType) = 0;
    virtual HRESULT __stdcall GetFriendlyName(BSTR* pFriendlyName) = 0;
    virtual HRESULT __stdcall GetProperty(const wasapi::PROPERTYKEY& key, wasapi::PROPVARIANT* pProperty) = 0;
    virtual HRESULT __stdcall GetProperties(void* pKeys, void** ppProperties) = 0;
    virtual HRESULT __stdcall SetProperties(void* pProperties, void** ppResults) = 0;
    virtual HRESULT __stdcall SupportsDataField(const wasapi::PROPERTYKEY& key, int16_t* pIsSupported) = 0;
    virtual HRESULT __stdcall GetState(SensorState* pState) = 0;
    virtual HRESULT __stdcall GetData(ISensorDataReport** ppDataReport) = 0;
    virtual HRESULT __stdcall SupportsEvent(const GUID& eventGuid, int16_t* pIsSupported) = 0;
    virtual HRESULT __stdcall GetEventInterest(GUID** ppValues, uint32_t* pCount) = 0;
    virtual HRESULT __stdcall SetEventInterest(const GUID* pValues, uint32_t count) = 0;
    virtual HRESULT __stdcall SetEventSink(ISensorEvents* pEvents) = 0;
};

class ISensorCollection : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall GetAt(uint32_t ulIndex, ISensor** ppSensor) = 0;
    virtual HRESULT __stdcall GetCount(uint32_t* pCount) = 0;
    virtual HRESULT __stdcall Add(ISensor* pSensor) = 0;
    virtual HRESULT __stdcall Remove(ISensor* pSensor) = 0;
    virtual HRESULT __stdcall RemoveByID(const SENSOR_ID& sensorID) = 0;
    virtual HRESULT __stdcall Clear() = 0;
};

class ISensorEvents : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall OnStateChanged(ISensor* pSensor, SensorState state) = 0;
    virtual HRESULT __stdcall OnDataUpdated(ISensor* pSensor, ISensorDataReport* pNewData) = 0;
    virtual HRESULT __stdcall OnEvent(ISensor* pSensor, const GUID& eventID, void* pEventData) = 0;
    virtual HRESULT __stdcall OnLeave(const SENSOR_ID& sensorID) = 0;
};

class ISensorManagerEvents : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall OnSensorEnter(ISensor* pSensor, SensorState state) = 0;
};

class ISensorManager : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall GetSensorsByCategory(const SENSOR_CATEGORY_ID& sensorCategory, ISensorCollection** ppSensorsFound) = 0;
    virtual HRESULT __stdcall GetSensorsByType(const SENSOR_TYPE_ID& sensorType, ISensorCollection** ppSensorsFound) = 0;
    virtual HRESULT __stdcall GetSensorByID(const SENSOR_ID& sensorID, ISensor** ppSensorFound) = 0;
    virtual HRESULT __stdcall RequestPermissions(win32::HWND hParent, ISensorCollection* pSensors, win32::BOOL fModal) = 0;
    virtual HRESULT __stdcall SetEventSink(ISensorManagerEvents* pEvents) = 0;
};

class ISensorClassExtension : public ole32::IUnknown {
public:
    virtual HRESULT __stdcall Initialize(IUnknown* pWdfDeviceUnknown, IUnknown* pSensorDriverUnknown) = 0;
    virtual HRESULT __stdcall Uninitialize() = 0;
    virtual HRESULT __stdcall ProcessIoControl(void* pRequest) = 0;
    virtual HRESULT __stdcall PostDataUpdate(ISensor* pSensor, ISensorDataReport* pData) = 0;
    virtual HRESULT __stdcall PostEvent(ISensor* pSensor, const GUID& eventGuid, void* pEventData) = 0;
    virtual HRESULT __stdcall PostStateChange(const SENSOR_ID& sensorID, SensorState state) = 0;
};

// ============================================================================
// 3. Sovereign Sensor Data & Registry
// ============================================================================

struct SensorHardwareRecord {
    SENSOR_ID id{};
    SENSOR_CATEGORY_ID category{};
    SENSOR_TYPE_ID type{};
    std::wstring friendlyName;
    std::wstring manufacturer;
    std::wstring model;
    std::wstring serialNumber;
    uint32_t minReportInterval{10};     // 10 ms
    uint32_t currentReportInterval{100}; // 100 ms
    SensorState state{SENSOR_STATE_READY};

    // Sensor Readings (Data Fields)
    std::map<wasapi::PROPERTYKEY, wasapi::PROPVARIANT> readings;
};

class SensorManager {
private:
    mutable std::mutex m_mutex;
    std::vector<SensorHardwareRecord> m_sensors;
    ISensorManagerEvents* m_managerSink{nullptr};

    SensorManager() {
        initDefaultSensors();
        registerScmServices();
    }

    void initDefaultSensors() {
        // 1. Accelerometer 3D
        {
            SensorHardwareRecord r;
            r.id = { 0x11111111, 0x1111, 0x1111, { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 } };
            r.category = SENSOR_CATEGORY_MOTION;
            r.type = SENSOR_TYPE_ACCELEROMETER_3D;
            r.friendlyName = L"MicaNT Sovereign 3-Axis Accelerometer";
            r.manufacturer = L"MicaNT Hardware Systems";
            r.model = L"MICA-ACCEL-3D";
            r.serialNumber = L"SN-ACC-2026-001";
            r.state = SENSOR_STATE_READY;

            wasapi::PROPVARIANT xVal{};
            xVal.vt = 5; // VT_R8
            xVal.dblVal = 0.02; // +0.02 g
            r.readings[SENSOR_DATA_TYPE_ACCELERATION_X_G] = xVal;

            wasapi::PROPVARIANT yVal{};
            yVal.vt = 5;
            yVal.dblVal = -0.01; // -0.01 g
            r.readings[SENSOR_DATA_TYPE_ACCELERATION_Y_G] = yVal;

            wasapi::PROPVARIANT zVal{};
            zVal.vt = 5;
            zVal.dblVal = 0.98; // +0.98 g (nominal gravity)
            r.readings[SENSOR_DATA_TYPE_ACCELERATION_Z_G] = zVal;

            m_sensors.push_back(r);
        }

        // 2. Ambient Light Sensor (ALS)
        {
            SensorHardwareRecord r;
            r.id = { 0x22222222, 0x2222, 0x2222, { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 } };
            r.category = SENSOR_CATEGORY_LIGHT;
            r.type = SENSOR_TYPE_AMBIENT_LIGHT;
            r.friendlyName = L"MicaNT Sovereign Ambient Light Sensor";
            r.manufacturer = L"MicaNT Hardware Systems";
            r.model = L"MICA-ALS-LUX";
            r.serialNumber = L"SN-ALS-2026-002";
            r.state = SENSOR_STATE_READY;

            wasapi::PROPVARIANT luxVal{};
            luxVal.vt = 5;
            luxVal.dblVal = 350.0; // 350.0 Lux
            r.readings[SENSOR_DATA_TYPE_LIGHT_LUX] = luxVal;

            m_sensors.push_back(r);
        }

        // 3. 3-Axis Electronic Compass / Magnetometer
        {
            SensorHardwareRecord r;
            r.id = { 0x33333333, 0x3333, 0x3333, { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 } };
            r.category = SENSOR_CATEGORY_ORIENTATION;
            r.type = SENSOR_TYPE_COMPASS_3D;
            r.friendlyName = L"MicaNT Sovereign 3D Compass & Magnetometer";
            r.manufacturer = L"MicaNT Hardware Systems";
            r.model = L"MICA-MAG-3D";
            r.serialNumber = L"SN-MAG-2026-003";
            r.state = SENSOR_STATE_READY;

            wasapi::PROPVARIANT headingVal{};
            headingVal.vt = 5;
            headingVal.dblVal = 184.5; // 184.5 degrees
            r.readings[SENSOR_DATA_TYPE_MAGNETIC_HEADING_DEGREES] = headingVal;

            m_sensors.push_back(r);
        }

        // 4. 3-Axis Gyroscope
        {
            SensorHardwareRecord r;
            r.id = { 0x44444444, 0x4444, 0x4444, { 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 } };
            r.category = SENSOR_CATEGORY_MOTION;
            r.type = SENSOR_TYPE_GYROSCOPE_3D;
            r.friendlyName = L"MicaNT Sovereign 3-Axis Gyroscope";
            r.manufacturer = L"MicaNT Hardware Systems";
            r.model = L"MICA-GYRO-3D";
            r.serialNumber = L"SN-GYRO-2026-004";
            r.state = SENSOR_STATE_READY;

            wasapi::PROPVARIANT xVal{};
            xVal.vt = 5;
            xVal.dblVal = 0.0;
            r.readings[SENSOR_DATA_TYPE_ANGULAR_VELOCITY_X_DEGREES_PER_SECOND] = xVal;

            wasapi::PROPVARIANT yVal{};
            yVal.vt = 5;
            yVal.dblVal = 0.0;
            r.readings[SENSOR_DATA_TYPE_ANGULAR_VELOCITY_Y_DEGREES_PER_SECOND] = yVal;

            wasapi::PROPVARIANT zVal{};
            zVal.vt = 5;
            zVal.dblVal = 0.0;
            r.readings[SENSOR_DATA_TYPE_ANGULAR_VELOCITY_Z_DEGREES_PER_SECOND] = zVal;

            m_sensors.push_back(r);
        }

        // 5. Environmental Barometer
        {
            SensorHardwareRecord r;
            r.id = { 0x55555555, 0x5555, 0x5555, { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 } };
            r.category = SENSOR_CATEGORY_ENVIRONMENTAL;
            r.type = SENSOR_TYPE_BAROMETER;
            r.friendlyName = L"MicaNT Sovereign Atmospheric Barometer";
            r.manufacturer = L"MicaNT Hardware Systems";
            r.model = L"MICA-BARO-ENV";
            r.serialNumber = L"SN-BARO-2026-005";
            r.state = SENSOR_STATE_READY;

            wasapi::PROPVARIANT barVal{};
            barVal.vt = 5;
            barVal.dblVal = 1.01325; // 1.01325 Bar (sea-level atm)
            r.readings[SENSOR_DATA_TYPE_ATMOSPHERIC_PRESSURE_BAR] = barVal;

            m_sensors.push_back(r);
        }
    }

    void registerScmServices() {
        auto& scm = scm::ServiceControlManager::get();

        // SensorDataService: Windows Sensor Data Service
        auto sensorSvc = std::make_shared<scm::ServiceRecord>();
        sensorSvc->serviceName = L"SensorDataService";
        sensorSvc->displayName = L"Sensor Data Service";
        sensorSvc->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        sensorSvc->startType = scm::SERVICE_DEMAND_START;
        sensorSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
        sensorSvc->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k LocalService";
        sensorSvc->loadOrderGroup = L"LocalService";
        sensorSvc->status.dwServiceType = sensorSvc->serviceType;
        sensorSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
        sensorSvc->status.dwProcessId = 1162;
        scm.registerServiceRecord(sensorSvc);
    }

public:
    static SensorManager& get() noexcept {
        static SensorManager instance;
        return instance;
    }

    SensorManager(const SensorManager&) = delete;
    SensorManager& operator=(const SensorManager&) = delete;

    void resetToDefault() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_sensors.clear();
        initDefaultSensors();
    }

    std::vector<SensorHardwareRecord> getAllSensors() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sensors;
    }

    bool findSensorByID(const SENSOR_ID& id, SensorHardwareRecord& out) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& s : m_sensors) {
            if (s.id == id) {
                out = s;
                return true;
            }
        }
        return false;
    }

    std::vector<SensorHardwareRecord> findSensorsByCategory(const SENSOR_CATEGORY_ID& cat) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<SensorHardwareRecord> res;
        for (const auto& s : m_sensors) {
            if (cat == SENSOR_CATEGORY_ALL || s.category == cat) {
                res.push_back(s);
            }
        }
        return res;
    }

    std::vector<SensorHardwareRecord> findSensorsByType(const SENSOR_TYPE_ID& type) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<SensorHardwareRecord> res;
        for (const auto& s : m_sensors) {
            if (s.type == type) {
                res.push_back(s);
            }
        }
        return res;
    }

    void setSensorReading(const SENSOR_ID& id, const wasapi::PROPERTYKEY& key, double val) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& s : m_sensors) {
            if (s.id == id) {
                wasapi::PROPVARIANT pv{};
                pv.vt = 5; // VT_R8
                pv.dblVal = val;
                s.readings[key] = pv;
                return;
            }
        }
    }

    void setSensorState(const SENSOR_ID& id, SensorState state) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& s : m_sensors) {
            if (s.id == id) {
                s.state = state;
                return;
            }
        }
    }
};

// ============================================================================
// 4. COM Implementations
// ============================================================================

class SensorDataReportImpl : public ISensorDataReport {
private:
    uint32_t m_refCount{1};
    std::map<wasapi::PROPERTYKEY, wasapi::PROPVARIANT> m_values;
    win32::SYSTEMTIME m_timestamp{};

public:
    explicit SensorDataReportImpl(const std::map<wasapi::PROPERTYKEY, wasapi::PROPVARIANT>& vals)
        : m_values(vals) {
        m_timestamp.wYear = 2026;
        m_timestamp.wMonth = 10;
        m_timestamp.wDay = 4;
        m_timestamp.wHour = 12;
        m_timestamp.wMinute = 0;
        m_timestamp.wSecond = 0;
        m_timestamp.wMilliseconds = 0;
    }

    virtual ~SensorDataReportImpl() = default;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ISensorDataReport) {
            *ppvObject = static_cast<ISensorDataReport*>(this);
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

    virtual HRESULT __stdcall GetTimestamp(win32::SYSTEMTIME* pTimeStamp) override {
        if (!pTimeStamp) return E_POINTER;
        *pTimeStamp = m_timestamp;
        return S_OK;
    }

    virtual HRESULT __stdcall GetSensorValue(const wasapi::PROPERTYKEY& pKey, wasapi::PROPVARIANT* pValue) override {
        if (!pValue) return E_POINTER;
        auto it = m_values.find(pKey);
        if (it == m_values.end()) return static_cast<HRESULT>(0x80070490); // NOT_FOUND
        return wasapi::PropVariantCopy(pValue, &it->second);
    }

    virtual HRESULT __stdcall GetSensorValues(void* /*pKeys*/, void** /*ppValues*/) override {
        return E_NOTIMPL;
    }
};

class SensorImpl : public ISensor {
private:
    uint32_t m_refCount{1};
    SENSOR_ID m_id{};
    ISensorEvents* m_events{nullptr};

public:
    explicit SensorImpl(const SENSOR_ID& id)
        : m_id(id) {}

    virtual ~SensorImpl() {
        if (m_events) m_events->Release();
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ISensor) {
            *ppvObject = static_cast<ISensor*>(this);
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

    virtual HRESULT __stdcall GetID(SENSOR_ID* pID) override {
        if (!pID) return E_POINTER;
        *pID = m_id;
        return S_OK;
    }

    virtual HRESULT __stdcall GetCategory(SENSOR_CATEGORY_ID* pSensorCategory) override {
        if (!pSensorCategory) return E_POINTER;
        SensorHardwareRecord rec;
        if (!SensorManager::get().findSensorByID(m_id, rec)) return static_cast<HRESULT>(0x80070490);
        *pSensorCategory = rec.category;
        return S_OK;
    }

    virtual HRESULT __stdcall GetType(SENSOR_TYPE_ID* pSensorType) override {
        if (!pSensorType) return E_POINTER;
        SensorHardwareRecord rec;
        if (!SensorManager::get().findSensorByID(m_id, rec)) return static_cast<HRESULT>(0x80070490);
        *pSensorType = rec.type;
        return S_OK;
    }

    virtual HRESULT __stdcall GetFriendlyName(BSTR* pFriendlyName) override {
        if (!pFriendlyName) return E_POINTER;
        SensorHardwareRecord rec;
        if (!SensorManager::get().findSensorByID(m_id, rec)) return static_cast<HRESULT>(0x80070490);
        *pFriendlyName = ole32::SysAllocString(rec.friendlyName.c_str());
        return S_OK;
    }

    virtual HRESULT __stdcall GetProperty(const wasapi::PROPERTYKEY& key, wasapi::PROPVARIANT* pProperty) override {
        if (!pProperty) return E_POINTER;
        SensorHardwareRecord rec;
        if (!SensorManager::get().findSensorByID(m_id, rec)) return static_cast<HRESULT>(0x80070490);

        if (key == SENSOR_PROPERTY_FRIENDLY_NAME) {
            pProperty->vt = ole32::VT_LPWSTR;
            size_t len = rec.friendlyName.size();
            pProperty->pwszVal = static_cast<wchar_t*>(ole32::CoTaskMemAlloc((len + 1) * sizeof(wchar_t)));
            wcsncpy_s(pProperty->pwszVal, len + 1, rec.friendlyName.c_str(), len);
            return S_OK;
        }
        if (key == SENSOR_PROPERTY_MANUFACTURER) {
            pProperty->vt = ole32::VT_LPWSTR;
            size_t len = rec.manufacturer.size();
            pProperty->pwszVal = static_cast<wchar_t*>(ole32::CoTaskMemAlloc((len + 1) * sizeof(wchar_t)));
            wcsncpy_s(pProperty->pwszVal, len + 1, rec.manufacturer.c_str(), len);
            return S_OK;
        }
        if (key == SENSOR_PROPERTY_MODEL) {
            pProperty->vt = ole32::VT_LPWSTR;
            size_t len = rec.model.size();
            pProperty->pwszVal = static_cast<wchar_t*>(ole32::CoTaskMemAlloc((len + 1) * sizeof(wchar_t)));
            wcsncpy_s(pProperty->pwszVal, len + 1, rec.model.c_str(), len);
            return S_OK;
        }
        if (key == SENSOR_PROPERTY_SERIAL_NUMBER) {
            pProperty->vt = ole32::VT_LPWSTR;
            size_t len = rec.serialNumber.size();
            pProperty->pwszVal = static_cast<wchar_t*>(ole32::CoTaskMemAlloc((len + 1) * sizeof(wchar_t)));
            wcsncpy_s(pProperty->pwszVal, len + 1, rec.serialNumber.c_str(), len);
            return S_OK;
        }
        if (key == SENSOR_PROPERTY_MIN_REPORT_INTERVAL) {
            pProperty->vt = 19; // VT_UI4
            pProperty->ulVal = rec.minReportInterval;
            return S_OK;
        }
        if (key == SENSOR_PROPERTY_CURRENT_REPORT_INTERVAL) {
            pProperty->vt = 19; // VT_UI4
            pProperty->ulVal = rec.currentReportInterval;
            return S_OK;
        }

        return static_cast<HRESULT>(0x80070490);
    }

    virtual HRESULT __stdcall GetProperties(void* /*pKeys*/, void** /*ppProperties*/) override {
        return E_NOTIMPL;
    }

    virtual HRESULT __stdcall SetProperties(void* /*pProperties*/, void** /*ppResults*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall SupportsDataField(const wasapi::PROPERTYKEY& key, int16_t* pIsSupported) override {
        if (!pIsSupported) return E_POINTER;
        SensorHardwareRecord rec;
        if (!SensorManager::get().findSensorByID(m_id, rec)) return static_cast<HRESULT>(0x80070490);
        *pIsSupported = (rec.readings.find(key) != rec.readings.end()) ? -1 : 0;
        return S_OK;
    }

    virtual HRESULT __stdcall GetState(SensorState* pState) override {
        if (!pState) return E_POINTER;
        SensorHardwareRecord rec;
        if (!SensorManager::get().findSensorByID(m_id, rec)) return static_cast<HRESULT>(0x80070490);
        *pState = rec.state;
        return S_OK;
    }

    virtual HRESULT __stdcall GetData(ISensorDataReport** ppDataReport) override {
        if (!ppDataReport) return E_POINTER;
        SensorHardwareRecord rec;
        if (!SensorManager::get().findSensorByID(m_id, rec)) return static_cast<HRESULT>(0x80070490);
        *ppDataReport = new SensorDataReportImpl(rec.readings);
        return S_OK;
    }

    virtual HRESULT __stdcall SupportsEvent(const GUID& /*eventGuid*/, int16_t* pIsSupported) override {
        if (!pIsSupported) return E_POINTER;
        *pIsSupported = -1; // VARIANT_TRUE
        return S_OK;
    }

    virtual HRESULT __stdcall GetEventInterest(GUID** /*ppValues*/, uint32_t* pCount) override {
        if (!pCount) return E_POINTER;
        *pCount = 0;
        return S_OK;
    }

    virtual HRESULT __stdcall SetEventInterest(const GUID* /*pValues*/, uint32_t /*count*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall SetEventSink(ISensorEvents* pEvents) override {
        if (m_events) {
            m_events->Release();
            m_events = nullptr;
        }
        if (pEvents) {
            m_events = pEvents;
            m_events->AddRef();
        }
        return S_OK;
    }

    void notifyDataUpdated() {
        if (m_events) {
            ISensorDataReport* pReport = nullptr;
            if (GetData(&pReport) == S_OK && pReport) {
                m_events->OnDataUpdated(this, pReport);
                pReport->Release();
            }
        }
    }

    void notifyStateChanged(SensorState state) {
        if (m_events) {
            m_events->OnStateChanged(this, state);
        }
    }
};

class SensorCollectionImpl : public ISensorCollection {
private:
    uint32_t m_refCount{1};
    std::vector<ISensor*> m_sensors;

public:
    SensorCollectionImpl() = default;
    virtual ~SensorCollectionImpl() {
        for (auto* s : m_sensors) {
            if (s) s->Release();
        }
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ISensorCollection) {
            *ppvObject = static_cast<ISensorCollection*>(this);
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

    virtual HRESULT __stdcall GetAt(uint32_t ulIndex, ISensor** ppSensor) override {
        if (!ppSensor) return E_POINTER;
        if (ulIndex >= m_sensors.size()) return E_INVALIDARG;
        *ppSensor = m_sensors[ulIndex];
        (*ppSensor)->AddRef();
        return S_OK;
    }

    virtual HRESULT __stdcall GetCount(uint32_t* pCount) override {
        if (!pCount) return E_POINTER;
        *pCount = static_cast<uint32_t>(m_sensors.size());
        return S_OK;
    }

    virtual HRESULT __stdcall Add(ISensor* pSensor) override {
        if (!pSensor) return E_POINTER;
        pSensor->AddRef();
        m_sensors.push_back(pSensor);
        return S_OK;
    }

    virtual HRESULT __stdcall Remove(ISensor* pSensor) override {
        if (!pSensor) return E_POINTER;
        auto it = std::find(m_sensors.begin(), m_sensors.end(), pSensor);
        if (it != m_sensors.end()) {
            (*it)->Release();
            m_sensors.erase(it);
            return S_OK;
        }
        return static_cast<HRESULT>(0x80070490);
    }

    virtual HRESULT __stdcall RemoveByID(const SENSOR_ID& sensorID) override {
        for (auto it = m_sensors.begin(); it != m_sensors.end(); ++it) {
            SENSOR_ID id{};
            (*it)->GetID(&id);
            if (id == sensorID) {
                (*it)->Release();
                m_sensors.erase(it);
                return S_OK;
            }
        }
        return static_cast<HRESULT>(0x80070490);
    }

    virtual HRESULT __stdcall Clear() override {
        for (auto* s : m_sensors) {
            if (s) s->Release();
        }
        m_sensors.clear();
        return S_OK;
    }
};

class SensorManagerImpl : public ISensorManager {
private:
    uint32_t m_refCount{1};
    ISensorManagerEvents* m_events{nullptr};

public:
    SensorManagerImpl() = default;
    virtual ~SensorManagerImpl() {
        if (m_events) m_events->Release();
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ISensorManager) {
            *ppvObject = static_cast<ISensorManager*>(this);
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

    virtual HRESULT __stdcall GetSensorsByCategory(const SENSOR_CATEGORY_ID& sensorCategory, ISensorCollection** ppSensorsFound) override {
        if (!ppSensorsFound) return E_POINTER;
        auto recs = SensorManager::get().findSensorsByCategory(sensorCategory);
        auto* pCol = new SensorCollectionImpl();
        for (const auto& r : recs) {
            auto* s = new SensorImpl(r.id);
            pCol->Add(s);
            s->Release();
        }
        *ppSensorsFound = pCol;
        return S_OK;
    }

    virtual HRESULT __stdcall GetSensorsByType(const SENSOR_TYPE_ID& sensorType, ISensorCollection** ppSensorsFound) override {
        if (!ppSensorsFound) return E_POINTER;
        auto recs = SensorManager::get().findSensorsByType(sensorType);
        auto* pCol = new SensorCollectionImpl();
        for (const auto& r : recs) {
            auto* s = new SensorImpl(r.id);
            pCol->Add(s);
            s->Release();
        }
        *ppSensorsFound = pCol;
        return S_OK;
    }

    virtual HRESULT __stdcall GetSensorByID(const SENSOR_ID& sensorID, ISensor** ppSensorFound) override {
        if (!ppSensorFound) return E_POINTER;
        SensorHardwareRecord rec;
        if (!SensorManager::get().findSensorByID(sensorID, rec)) {
            *ppSensorFound = nullptr;
            return static_cast<HRESULT>(0x80070490); // NOT_FOUND
        }
        *ppSensorFound = new SensorImpl(sensorID);
        return S_OK;
    }

    virtual HRESULT __stdcall RequestPermissions(win32::HWND /*hParent*/, ISensorCollection* /*pSensors*/, win32::BOOL /*fModal*/) override {
        // Sovereign architecture grants all local sensor access
        return S_OK;
    }

    virtual HRESULT __stdcall SetEventSink(ISensorManagerEvents* pEvents) override {
        if (m_events) {
            m_events->Release();
            m_events = nullptr;
        }
        if (pEvents) {
            m_events = pEvents;
            m_events->AddRef();
        }
        return S_OK;
    }
};

class SensorClassExtensionImpl : public ISensorClassExtension {
private:
    uint32_t m_refCount{1};
    bool m_initialized{false};

public:
    SensorClassExtensionImpl() = default;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ISensorClassExtension) {
            *ppvObject = static_cast<ISensorClassExtension*>(this);
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

    virtual HRESULT __stdcall Initialize(IUnknown* /*pWdfDeviceUnknown*/, IUnknown* /*pSensorDriverUnknown*/) override {
        m_initialized = true;
        return S_OK;
    }

    virtual HRESULT __stdcall Uninitialize() override {
        m_initialized = false;
        return S_OK;
    }

    virtual HRESULT __stdcall ProcessIoControl(void* /*pRequest*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall PostDataUpdate(ISensor* /*pSensor*/, ISensorDataReport* /*pData*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall PostEvent(ISensor* /*pSensor*/, const GUID& /*eventGuid*/, void* /*pEventData*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall PostStateChange(const SENSOR_ID& sensorID, SensorState state) override {
        SensorManager::get().setSensorState(sensorID, state);
        return S_OK;
    }
};

// ============================================================================
// 5. Class Factories
// ============================================================================

class SensorManagerClassFactory : public ole32::IClassFactory {
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

    virtual uint32_t __stdcall AddRef() override { return ++m_refCount; }
    virtual uint32_t __stdcall Release() override { return --m_refCount; }

    virtual HRESULT __stdcall CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        if (!ppvObject) return E_POINTER;
        auto* pMgr = new SensorManagerImpl();
        HRESULT hr = pMgr->QueryInterface(riid, ppvObject);
        pMgr->Release();
        return hr;
    }

    virtual HRESULT __stdcall LockServer(int32_t /*fLock*/) override { return S_OK; }
};

class SensorCollectionClassFactory : public ole32::IClassFactory {
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

    virtual uint32_t __stdcall AddRef() override { return ++m_refCount; }
    virtual uint32_t __stdcall Release() override { return --m_refCount; }

    virtual HRESULT __stdcall CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        if (!ppvObject) return E_POINTER;
        auto* pCol = new SensorCollectionImpl();
        HRESULT hr = pCol->QueryInterface(riid, ppvObject);
        pCol->Release();
        return hr;
    }

    virtual HRESULT __stdcall LockServer(int32_t /*fLock*/) override { return S_OK; }
};

class SensorClassExtensionClassFactory : public ole32::IClassFactory {
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

    virtual uint32_t __stdcall AddRef() override { return ++m_refCount; }
    virtual uint32_t __stdcall Release() override { return --m_refCount; }

    virtual HRESULT __stdcall CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        if (!ppvObject) return E_POINTER;
        auto* pExt = new SensorClassExtensionImpl();
        HRESULT hr = pExt->QueryInterface(riid, ppvObject);
        pExt->Release();
        return hr;
    }

    virtual HRESULT __stdcall LockServer(int32_t /*fLock*/) override { return S_OK; }
};

// ============================================================================
// 6. C Client API & Dynamic Exports (sensorsapi.dll / sensorsclassextension.dll)
// ============================================================================

inline HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (rclsid == CLSID_SensorManager) {
        static SensorManagerClassFactory s_mgrFactory;
        return s_mgrFactory.QueryInterface(riid, ppv);
    }
    if (rclsid == CLSID_SensorCollection) {
        static SensorCollectionClassFactory s_colFactory;
        return s_colFactory.QueryInterface(riid, ppv);
    }
    if (rclsid == CLSID_SensorClassExtension) {
        static SensorClassExtensionClassFactory s_extFactory;
        return s_extFactory.QueryInterface(riid, ppv);
    }
    *ppv = nullptr;
    return CLASS_E_CLASSNOTAVAILABLE;
}

inline HRESULT __stdcall DllCanUnloadNow() { return S_OK; }
inline HRESULT __stdcall DllRegisterServer() { return S_OK; }
inline HRESULT __stdcall DllUnregisterServer() { return S_OK; }

// C APIs
inline HRESULT __stdcall SensorsCreateSensorManager(ISensorManager** ppManager) {
    if (!ppManager) return E_POINTER;
    *ppManager = new SensorManagerImpl();
    return S_OK;
}

inline HRESULT __stdcall SensorsGetSensorCount(uint32_t* pCount) {
    if (!pCount) return E_POINTER;
    *pCount = static_cast<uint32_t>(SensorManager::get().getAllSensors().size());
    return S_OK;
}

inline HRESULT __stdcall SensorsClassExtensionCreate(ISensorClassExtension** ppExtension) {
    if (!ppExtension) return E_POINTER;
    *ppExtension = new SensorClassExtensionImpl();
    return S_OK;
}

inline void InitializeSensorsSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // 1. sensorsapi.dll (Windows Sensors API)
    ldr.registerExport("sensorsapi.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));
    ldr.registerExport("sensorsapi.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));
    ldr.registerExport("sensorsapi.dll", "DllRegisterServer", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("sensorsapi.dll", "DllUnregisterServer", reinterpret_cast<void*>(DllUnregisterServer));
    ldr.registerExport("sensorsapi.dll", "SensorsCreateSensorManager", reinterpret_cast<void*>(SensorsCreateSensorManager));
    ldr.registerExport("sensorsapi.dll", "SensorsGetSensorCount", reinterpret_cast<void*>(SensorsGetSensorCount));

    // 2. sensorsclassextension.dll (Windows Sensor Class Extension)
    ldr.registerExport("sensorsclassextension.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));
    ldr.registerExport("sensorsclassextension.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));
    ldr.registerExport("sensorsclassextension.dll", "DllRegisterServer", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("sensorsclassextension.dll", "DllUnregisterServer", reinterpret_cast<void*>(DllUnregisterServer));
    ldr.registerExport("sensorsclassextension.dll", "SensorsClassExtensionCreate", reinterpret_cast<void*>(SensorsClassExtensionCreate));

    // Register COM Class Factories in ole32 runtime
    static SensorManagerClassFactory s_mgrFactory;
    static SensorCollectionClassFactory s_colFactory;
    static SensorClassExtensionClassFactory s_extFactory;
    uint32_t cookie = 0;

    (void)ole32::CoRegisterClassObject(
        CLSID_SensorManager,
        &s_mgrFactory,
        ole32::CLSCTX_INPROC_SERVER,
        ole32::REGCLS_MULTIPLEUSE,
        &cookie
    );

    (void)ole32::CoRegisterClassObject(
        CLSID_SensorCollection,
        &s_colFactory,
        ole32::CLSCTX_INPROC_SERVER,
        ole32::REGCLS_MULTIPLEUSE,
        &cookie
    );

    (void)ole32::CoRegisterClassObject(
        CLSID_SensorClassExtension,
        &s_extFactory,
        ole32::CLSCTX_INPROC_SERVER,
        ole32::REGCLS_MULTIPLEUSE,
        &cookie
    );

    // Initialize sovereign state
    SensorManager::get();
}

} // namespace micant::sensors
