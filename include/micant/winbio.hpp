#pragma once

/**
 * @file winbio.hpp
 * @brief Clean-Room Windows Biometric Framework (WBF) & Windows Hello Subsystem (winbio.dll / winbiosrvc.dll).
 *
 * Implements the Windows Biometric Framework architecture, session lifecycle, biometric unit enumeration,
 * enrollment workflows (Begin/Capture/Commit/Discard), verification, identification, biometric database storage,
 * SCM daemon (WbioSrvc), and Win32 C client APIs.
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
#include "scm.hpp"
#include "ldr.hpp"

namespace micant::winbio {

using namespace micant::ole32;

// ============================================================================
// 1. WinBio Constants, Flags & Status Codes
// ============================================================================

using WINBIO_SESSION_HANDLE = uint32_t;
using WINBIO_UNIT_ID = uint32_t;
using WINBIO_BIOMETRIC_TYPE = uint32_t;
using WINBIO_BIOMETRIC_SUBTYPE = uint8_t;
using WINBIO_CAPABILITIES = uint32_t;
using WINBIO_REJECT_DETAIL = uint32_t;
using WINBIO_COMPONENT = uint32_t;
using WINBIO_SESSION_FLAGS = uint32_t;
using WINBIO_STORAGE_TYPE = uint32_t;

inline constexpr WINBIO_STORAGE_TYPE WINBIO_DATABASE_FLAG_DEFAULT = 0x00000000;
inline constexpr WINBIO_STORAGE_TYPE WINBIO_DATABASE_FLAG_FILE    = 0x00000001;

// Biometric Types
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_MULTIPLE            = 0x00000001;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_FACIAL_FEATURES     = 0x00000002;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_VOICE               = 0x00000004;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_FINGERPRINT         = 0x00000008;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_IRIS                = 0x00000010;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_RETINA              = 0x00000020;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_HAND_GEOMETRY       = 0x00000040;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_SIGNATURE_DYNAMICS  = 0x00000080;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_KEYSTROKE_DYNAMICS  = 0x00000100;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_LIP_MOVEMENT        = 0x00000200;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_THERMAL_FACE_IMAGE  = 0x00000400;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_THERMAL_HAND_IMAGE  = 0x00000800;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_GAIT                = 0x00001000;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_PASSWORD            = 0x00002000;
inline constexpr WINBIO_BIOMETRIC_TYPE WINBIO_TYPE_ANY                 = 0x00000000;

// Biometric Subtypes / Subfactors
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_NO_INFORMATION  = 0x00;
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_RH_THUMB        = 0x01;
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_RH_INDEX_FINGER = 0x02;
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_RH_MIDDLE_FINGER= 0x03;
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_RH_RING_FINGER  = 0x04;
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_RH_LITTLE_FINGER= 0x05;
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_LH_THUMB        = 0x06;
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_LH_INDEX_FINGER = 0x07;
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_LH_MIDDLE_FINGER= 0x08;
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_LH_RING_FINGER  = 0x09;
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_LH_LITTLE_FINGER= 0x0A;
inline constexpr WINBIO_BIOMETRIC_SUBTYPE WINBIO_SUBTYPE_ANY             = 0xFF;

// Biometric Unit Capabilities
inline constexpr WINBIO_CAPABILITIES WINBIO_CAPABILITY_SENSOR         = 0x00000001;
inline constexpr WINBIO_CAPABILITIES WINBIO_CAPABILITY_MATCHING       = 0x00000002;
inline constexpr WINBIO_CAPABILITIES WINBIO_CAPABILITY_DATABASE       = 0x00000004;
inline constexpr WINBIO_CAPABILITIES WINBIO_CAPABILITY_PROCESSING     = 0x00000008;
inline constexpr WINBIO_CAPABILITIES WINBIO_CAPABILITY_ENCRYPTION     = 0x00000010;
inline constexpr WINBIO_CAPABILITIES WINBIO_CAPABILITY_NAVIGATION     = 0x00000020;
inline constexpr WINBIO_CAPABILITIES WINBIO_CAPABILITY_INDICATOR      = 0x00000040;
inline constexpr WINBIO_CAPABILITIES WINBIO_CAPABILITY_VIRTUAL_SENSOR = 0x00000080;
inline constexpr WINBIO_CAPABILITIES WINBIO_CAPABILITY_SECURE_SENSOR  = 0x00000100;

// Sensor States
enum WINBIO_SENSOR_STATUS : uint32_t {
    WINBIO_SENSOR_UNKNOWN        = 0,
    WINBIO_SENSOR_READY          = 1,
    WINBIO_SENSOR_BUSY           = 2,
    WINBIO_SENSOR_NOT_CALIBRATED = 3,
    WINBIO_SENSOR_FAILURE        = 4
};

// Reject Details
inline constexpr WINBIO_REJECT_DETAIL WINBIO_FP_TOO_HIGH       = 1;
inline constexpr WINBIO_REJECT_DETAIL WINBIO_FP_TOO_LOW        = 2;
inline constexpr WINBIO_REJECT_DETAIL WINBIO_FP_TOO_LEFT       = 3;
inline constexpr WINBIO_REJECT_DETAIL WINBIO_FP_TOO_RIGHT      = 4;
inline constexpr WINBIO_REJECT_DETAIL WINBIO_FP_TOO_FAST       = 5;
inline constexpr WINBIO_REJECT_DETAIL WINBIO_FP_TOO_SLOW       = 6;
inline constexpr WINBIO_REJECT_DETAIL WINBIO_FP_POOR_QUALITY   = 7;
inline constexpr WINBIO_REJECT_DETAIL WINBIO_FP_TOO_SKEWED     = 8;
inline constexpr WINBIO_REJECT_DETAIL WINBIO_FP_TOO_SHORT      = 9;
inline constexpr WINBIO_REJECT_DETAIL WINBIO_FP_MERGE_FAILURE  = 10;

// Session Flags
inline constexpr WINBIO_SESSION_FLAGS WINBIO_FLAG_DEFAULT     = 0x00000000;
inline constexpr WINBIO_SESSION_FLAGS WINBIO_FLAG_BASIC       = 0x00000001;
inline constexpr WINBIO_SESSION_FLAGS WINBIO_FLAG_ADVANCED    = 0x00000002;
inline constexpr WINBIO_SESSION_FLAGS WINBIO_FLAG_RAW         = 0x00000004;
inline constexpr WINBIO_SESSION_FLAGS WINBIO_FLAG_MAINTENANCE = 0x00000008;

// WinBio HRESULTs
inline constexpr HRESULT WINBIO_S_OK                          = 0x00000000;
inline constexpr HRESULT WINBIO_I_MORE_DATA                   = 0x00090001;
inline constexpr HRESULT WINBIO_E_UNSUPPORTED_FACTOR          = static_cast<HRESULT>(0x80098001);
inline constexpr HRESULT WINBIO_E_INVALID_UNIT                = static_cast<HRESULT>(0x80098002);
inline constexpr HRESULT WINBIO_E_UNKNOWN_ID                  = static_cast<HRESULT>(0x80098003);
inline constexpr HRESULT WINBIO_E_CANCELED                    = static_cast<HRESULT>(0x80098004);
inline constexpr HRESULT WINBIO_E_NO_MATCH                    = static_cast<HRESULT>(0x80098005);
inline constexpr HRESULT WINBIO_E_CAPTURE_ABORTED             = static_cast<HRESULT>(0x80098006);
inline constexpr HRESULT WINBIO_E_ENROLLMENT_IN_PROGRESS      = static_cast<HRESULT>(0x80098007);
inline constexpr HRESULT WINBIO_E_BAD_CAPTURE                 = static_cast<HRESULT>(0x80098008);
inline constexpr HRESULT WINBIO_E_INVALID_CONTROL_CODE        = static_cast<HRESULT>(0x80098009);
inline constexpr HRESULT WINBIO_E_LOCK_VIOLATION              = static_cast<HRESULT>(0x8009800B);
inline constexpr HRESULT WINBIO_E_DUPLICATE_ENROLLMENT        = static_cast<HRESULT>(0x8009800F);
inline constexpr HRESULT WINBIO_E_DATABASE_FULL               = static_cast<HRESULT>(0x80098010);
inline constexpr HRESULT WINBIO_E_DATABASE_LOCKED             = static_cast<HRESULT>(0x80098011);
inline constexpr HRESULT WINBIO_E_DATABASE_CORRUPTED          = static_cast<HRESULT>(0x80098012);
inline constexpr HRESULT WINBIO_E_DATABASE_NO_SUCH_RECORD     = static_cast<HRESULT>(0x80098013);
inline constexpr HRESULT WINBIO_E_DUPLICATE_TEMPLATE          = static_cast<HRESULT>(0x80098014);
inline constexpr HRESULT WINBIO_E_ALREADY_INITIALIZED         = static_cast<HRESULT>(0x80098015);
inline constexpr HRESULT WINBIO_E_DATABASE_READ_ERROR         = static_cast<HRESULT>(0x80098016);
inline constexpr HRESULT WINBIO_E_DATABASE_WRITE_ERROR        = static_cast<HRESULT>(0x80098017);

// Identity types
enum WINBIO_IDENTITY_TYPE : uint32_t {
    WINBIO_ID_TYPE_NULL       = 0,
    WINBIO_ID_TYPE_WILDCARD   = 1,
    WINBIO_ID_TYPE_GUID       = 2,
    WINBIO_ID_TYPE_SID        = 3
};

struct WINBIO_IDENTITY {
    WINBIO_IDENTITY_TYPE Type{WINBIO_ID_TYPE_NULL};
    union {
        GUID Null;
        GUID Wildcard;
        GUID TemplateGuid;
        struct {
            uint32_t Size;
            uint8_t  Data[68];
        } AccountSid;
    } Value{};
};

struct WINBIO_UNIT_SCHEMA {
    WINBIO_UNIT_ID          UnitId{0};
    WINBIO_BIOMETRIC_TYPE   PoolType{WINBIO_TYPE_ANY};
    WINBIO_BIOMETRIC_TYPE   BiometricFactor{WINBIO_TYPE_FINGERPRINT};
    WINBIO_SENSOR_STATUS    SensorStatus{WINBIO_SENSOR_READY};
    WINBIO_CAPABILITIES     Capabilities{0};
    wchar_t                 DeviceInstanceId[256]{};
    wchar_t                 Description[256]{};
    wchar_t                 Manufacturer[256]{};
    wchar_t                 Model[256]{};
    wchar_t                 SerialNumber[256]{};
    struct {
        uint32_t Major{1};
        uint32_t Minor{0};
    } FirmwareVersion;
};

struct WINBIO_STORAGE_SCHEMA {
    GUID                    DatabaseId{};
    WINBIO_STORAGE_TYPE     DataFormat{};
    WINBIO_BIOMETRIC_TYPE   BiometricFactor{WINBIO_TYPE_FINGERPRINT};
    GUID                    Format{};
    uint32_t                InitialSize{1048576}; // 1MB
    uint32_t                AutoScan{1};
    wchar_t                 FilePath[260]{};
    wchar_t                 ConnectionString[260]{};
};

struct WINBIO_BIR {
    uint32_t HeaderVersion{1};
    uint32_t HeaderLength{sizeof(WINBIO_BIR)};
    uint32_t PayloadLength{0};
    uint32_t FormatOwner{0x0001};
    uint32_t FormatType{0x0001};
    WINBIO_BIOMETRIC_TYPE BiometricType{WINBIO_TYPE_FINGERPRINT};
    WINBIO_BIOMETRIC_SUBTYPE SubFactor{WINBIO_SUBTYPE_RH_INDEX_FINGER};
    uint8_t Purpose{0x01}; // WINBIO_PURPOSE_VERIFY
    uint8_t DataQuality{100};
};

// ============================================================================
// 2. Sovereign Biometric Manager Engine
// ============================================================================

struct BiometricEnrollmentRecord {
    WINBIO_IDENTITY identity{};
    WINBIO_BIOMETRIC_SUBTYPE subFactor{WINBIO_SUBTYPE_NO_INFORMATION};
    WINBIO_UNIT_ID unitId{0};
    std::vector<uint8_t> templateData;
    uint32_t sampleCount{0};
};

struct BiometricSessionRecord {
    WINBIO_SESSION_HANDLE handle{0};
    WINBIO_BIOMETRIC_TYPE factor{WINBIO_TYPE_ANY};
    WINBIO_SESSION_FLAGS flags{WINBIO_FLAG_DEFAULT};
    bool inEnrollment{false};
    WINBIO_UNIT_ID enrollUnitId{0};
    WINBIO_BIOMETRIC_SUBTYPE enrollSubFactor{WINBIO_SUBTYPE_NO_INFORMATION};
    uint32_t enrollSampleCount{0};
    uint32_t enrollRequiredSamples{3};
};

class BiometricManager {
private:
    mutable std::mutex m_mutex;
    std::vector<WINBIO_UNIT_SCHEMA> m_units;
    std::vector<WINBIO_STORAGE_SCHEMA> m_databases;
    std::vector<BiometricEnrollmentRecord> m_enrollments;
    std::map<WINBIO_SESSION_HANDLE, BiometricSessionRecord> m_sessions;
    WINBIO_SESSION_HANDLE m_nextSessionHandle{1001};

    BiometricManager() {
        initDefaultUnits();
        initDefaultDatabases();
        initDefaultEnrollments();
        registerScmServices();
    }

    void initDefaultUnits() {
        // Unit 1: Sovereign Fingerprint Sensor
        {
            WINBIO_UNIT_SCHEMA u{};
            u.UnitId = 1;
            u.PoolType = WINBIO_TYPE_FINGERPRINT;
            u.BiometricFactor = WINBIO_TYPE_FINGERPRINT;
            u.SensorStatus = WINBIO_SENSOR_READY;
            u.Capabilities = WINBIO_CAPABILITY_SENSOR | WINBIO_CAPABILITY_MATCHING |
                             WINBIO_CAPABILITY_DATABASE | WINBIO_CAPABILITY_PROCESSING |
                             WINBIO_CAPABILITY_ENCRYPTION | WINBIO_CAPABILITY_SECURE_SENSOR;
            wcscpy_s(u.DeviceInstanceId, L"USB\\VID_1414&PID_0090\\MICA_FP_01");
            wcscpy_s(u.Description, L"MicaNT Sovereign Optical Fingerprint Sensor");
            wcscpy_s(u.Manufacturer, L"MicaNT Security Systems");
            wcscpy_s(u.Model, L"MICA-BIO-FP500");
            wcscpy_s(u.SerialNumber, L"SN-FP-2026-001");
            u.FirmwareVersion.Major = 2;
            u.FirmwareVersion.Minor = 1;
            m_units.push_back(u);
        }

        // Unit 2: Sovereign Facial Recognition Infrared Camera
        {
            WINBIO_UNIT_SCHEMA u{};
            u.UnitId = 2;
            u.PoolType = WINBIO_TYPE_FACIAL_FEATURES;
            u.BiometricFactor = WINBIO_TYPE_FACIAL_FEATURES;
            u.SensorStatus = WINBIO_SENSOR_READY;
            u.Capabilities = WINBIO_CAPABILITY_SENSOR | WINBIO_CAPABILITY_MATCHING |
                             WINBIO_CAPABILITY_DATABASE | WINBIO_CAPABILITY_PROCESSING |
                             WINBIO_CAPABILITY_ENCRYPTION | WINBIO_CAPABILITY_SECURE_SENSOR;
            wcscpy_s(u.DeviceInstanceId, L"USB\\VID_1414&PID_0091\\MICA_FACE_01");
            wcscpy_s(u.Description, L"MicaNT Sovereign TrueDepth Infrared Facial Sensor");
            wcscpy_s(u.Manufacturer, L"MicaNT Security Systems");
            wcscpy_s(u.Model, L"MICA-BIO-FACE-IR");
            wcscpy_s(u.SerialNumber, L"SN-IR-2026-002");
            u.FirmwareVersion.Major = 1;
            u.FirmwareVersion.Minor = 5;
            m_units.push_back(u);
        }
    }

    void initDefaultDatabases() {
        WINBIO_STORAGE_SCHEMA db{};
        // System Database GUID
        db.DatabaseId = { 0xD662C889, 0x30BE, 0x4CEF, { 0xAB, 0xE7, 0x1A, 0x22, 0x07, 0x8C, 0x89, 0x20 } };
        db.BiometricFactor = WINBIO_TYPE_FINGERPRINT | WINBIO_TYPE_FACIAL_FEATURES;
        db.Format = { 0x11111111, 0x2222, 0x3333, { 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } };
        db.InitialSize = 1048576;
        db.AutoScan = 1;
        wcscpy_s(db.FilePath, L"C:\\Windows\\System32\\WinBioDatabase\\system.db");
        wcscpy_s(db.ConnectionString, L"Provider=MicaBioStorage;Data Source=system.db");
        m_databases.push_back(db);
    }

    void initDefaultEnrollments() {
        // Pre-seed Administrator enrollment for Unit 1 (Fingerprint: Right Index Finger)
        {
            BiometricEnrollmentRecord rec{};
            rec.identity.Type = WINBIO_ID_TYPE_SID;
            // S-1-5-18 (Local System / Administrator)
            const char* sidStr = "S-1-5-18";
            rec.identity.Value.AccountSid.Size = static_cast<uint32_t>(strlen(sidStr));
            std::memcpy(rec.identity.Value.AccountSid.Data, sidStr, strlen(sidStr));
            rec.subFactor = WINBIO_SUBTYPE_RH_INDEX_FINGER;
            rec.unitId = 1;
            rec.sampleCount = 3;
            rec.templateData = { 0xAA, 0x55, 0x01, 0x02, 0x03, 0x04 };
            m_enrollments.push_back(rec);
        }

        // Pre-seed Administrator enrollment for Unit 2 (Facial Recognition)
        {
            BiometricEnrollmentRecord rec{};
            rec.identity.Type = WINBIO_ID_TYPE_SID;
            const char* sidStr = "S-1-5-18";
            rec.identity.Value.AccountSid.Size = static_cast<uint32_t>(strlen(sidStr));
            std::memcpy(rec.identity.Value.AccountSid.Data, sidStr, strlen(sidStr));
            rec.subFactor = WINBIO_SUBTYPE_NO_INFORMATION;
            rec.unitId = 2;
            rec.sampleCount = 3;
            rec.templateData = { 0xFA, 0xCE, 0x11, 0x22, 0x33, 0x44 };
            m_enrollments.push_back(rec);
        }
    }

    void registerScmServices() {
        auto& scm = scm::ServiceControlManager::get();

        // WbioSrvc: Windows Biometric Service
        auto bioSvc = std::make_shared<scm::ServiceRecord>();
        bioSvc->serviceName = L"WbioSrvc";
        bioSvc->displayName = L"Windows Biometric Service";
        bioSvc->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
        bioSvc->startType = scm::SERVICE_DEMAND_START;
        bioSvc->errorControl = scm::SERVICE_ERROR_NORMAL;
        bioSvc->binaryPath = L"%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted";
        bioSvc->loadOrderGroup = L"LocalSystemNetworkRestricted";
        bioSvc->status.dwServiceType = bioSvc->serviceType;
        bioSvc->status.dwCurrentState = scm::SERVICE_RUNNING;
        bioSvc->status.dwProcessId = 1166;
        scm.registerServiceRecord(bioSvc);
    }

public:
    static BiometricManager& get() noexcept {
        static BiometricManager instance;
        return instance;
    }

    // Unit Enumeration
    std::vector<WINBIO_UNIT_SCHEMA> enumerateUnits(WINBIO_BIOMETRIC_TYPE factor) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (factor == WINBIO_TYPE_ANY) return m_units;
        std::vector<WINBIO_UNIT_SCHEMA> res;
        for (const auto& u : m_units) {
            if (u.BiometricFactor & factor) res.push_back(u);
        }
        return res;
    }

    bool findUnit(WINBIO_UNIT_ID unitId, WINBIO_UNIT_SCHEMA& outSchema) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& u : m_units) {
            if (u.UnitId == unitId) {
                outSchema = u;
                return true;
            }
        }
        return false;
    }

    // Database Enumeration
    std::vector<WINBIO_STORAGE_SCHEMA> enumerateDatabases(WINBIO_BIOMETRIC_TYPE factor) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (factor == WINBIO_TYPE_ANY) return m_databases;
        std::vector<WINBIO_STORAGE_SCHEMA> res;
        for (const auto& db : m_databases) {
            if (db.BiometricFactor & factor) res.push_back(db);
        }
        return res;
    }

    // Enrollment Enumeration
    std::vector<BiometricEnrollmentRecord> enumerateEnrollments(WINBIO_UNIT_ID unitId) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<BiometricEnrollmentRecord> res;
        for (const auto& e : m_enrollments) {
            if (unitId == 0 || e.unitId == unitId) res.push_back(e);
        }
        return res;
    }

    // Session Management
    HRESULT openSession(WINBIO_BIOMETRIC_TYPE factor, WINBIO_SESSION_FLAGS flags, WINBIO_SESSION_HANDLE* outHandle) {
        if (!outHandle) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        WINBIO_SESSION_HANDLE h = m_nextSessionHandle++;
        BiometricSessionRecord s{};
        s.handle = h;
        s.factor = factor;
        s.flags = flags;
        m_sessions[h] = s;
        *outHandle = h;
        return S_OK;
    }

    HRESULT closeSession(WINBIO_SESSION_HANDLE handle) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(handle);
        if (it == m_sessions.end()) return WINBIO_E_INVALID_UNIT;
        m_sessions.erase(it);
        return S_OK;
    }

    // Enrollment Workflow
    HRESULT enrollBegin(WINBIO_SESSION_HANDLE session, WINBIO_BIOMETRIC_SUBTYPE subFactor, WINBIO_UNIT_ID unitId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(session);
        if (it == m_sessions.end()) return WINBIO_E_INVALID_UNIT;

        WINBIO_UNIT_SCHEMA schema{};
        bool found = false;
        for (const auto& u : m_units) {
            if (u.UnitId == unitId) { schema = u; found = true; break; }
        }
        if (!found) return WINBIO_E_INVALID_UNIT;

        it->second.inEnrollment = true;
        it->second.enrollUnitId = unitId;
        it->second.enrollSubFactor = subFactor;
        it->second.enrollSampleCount = 0;
        it->second.enrollRequiredSamples = 3;
        return S_OK;
    }

    HRESULT enrollCapture(WINBIO_SESSION_HANDLE session, WINBIO_REJECT_DETAIL* rejectDetail) {
        if (rejectDetail) *rejectDetail = 0;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(session);
        if (it == m_sessions.end() || !it->second.inEnrollment) return WINBIO_E_NO_MATCH;

        it->second.enrollSampleCount++;
        if (it->second.enrollSampleCount < it->second.enrollRequiredSamples) {
            return WINBIO_I_MORE_DATA;
        }
        return S_OK;
    }

    HRESULT enrollCommit(WINBIO_SESSION_HANDLE session, WINBIO_IDENTITY* identity, win32::BOOL* isNewTemplate) {
        if (!identity) return E_POINTER;
        if (isNewTemplate) *isNewTemplate = 1;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(session);
        if (it == m_sessions.end() || !it->second.inEnrollment) return WINBIO_E_NO_MATCH;

        BiometricEnrollmentRecord rec{};
        rec.identity = *identity;
        rec.subFactor = it->second.enrollSubFactor;
        rec.unitId = it->second.enrollUnitId;
        rec.sampleCount = it->second.enrollSampleCount;
        rec.templateData = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02 };

        m_enrollments.push_back(rec);
        it->second.inEnrollment = false;
        return S_OK;
    }

    HRESULT enrollDiscard(WINBIO_SESSION_HANDLE session) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(session);
        if (it == m_sessions.end()) return WINBIO_E_INVALID_UNIT;
        it->second.inEnrollment = false;
        it->second.enrollSampleCount = 0;
        return S_OK;
    }

    // Verification Workflow
    HRESULT verify(WINBIO_SESSION_HANDLE session, WINBIO_UNIT_ID unitId, WINBIO_BIOMETRIC_SUBTYPE subFactor,
                   WINBIO_IDENTITY* identity, win32::BOOL* match, WINBIO_REJECT_DETAIL* rejectDetail) {
        if (!identity || !match) return E_POINTER;
        if (rejectDetail) *rejectDetail = 0;
        std::lock_guard<std::mutex> lock(m_mutex);
        (void)session;

        *match = 0;
        for (const auto& e : m_enrollments) {
            if (e.unitId == unitId) {
                if (subFactor == WINBIO_SUBTYPE_ANY || e.subFactor == subFactor) {
                    *identity = e.identity;
                    *match = 1;
                    return S_OK;
                }
            }
        }
        return WINBIO_E_NO_MATCH;
    }

    // Identification Workflow
    HRESULT identify(WINBIO_SESSION_HANDLE session, WINBIO_UNIT_ID unitId,
                    WINBIO_IDENTITY* identity, WINBIO_BIOMETRIC_SUBTYPE* subFactor, WINBIO_REJECT_DETAIL* rejectDetail) {
        if (!identity || !subFactor) return E_POINTER;
        if (rejectDetail) *rejectDetail = 0;
        std::lock_guard<std::mutex> lock(m_mutex);
        (void)session;

        for (const auto& e : m_enrollments) {
            if (unitId == 0 || e.unitId == unitId) {
                *identity = e.identity;
                *subFactor = e.subFactor;
                return S_OK;
            }
        }
        return WINBIO_E_NO_MATCH;
    }

    size_t getSessionCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sessions.size();
    }
};

// ============================================================================
// 3. WinBio C Client APIs (winbio.dll)
// ============================================================================

inline HRESULT __stdcall WinBioOpenSession(
    WINBIO_BIOMETRIC_TYPE Factor,
    uint32_t /*PoolType*/,
    WINBIO_SESSION_FLAGS Flags,
    WINBIO_UNIT_ID* /*UnitArray*/,
    size_t /*UnitCount*/,
    GUID* /*DatabaseId*/,
    WINBIO_SESSION_HANDLE* SessionHandle
) {
    if (!SessionHandle) return E_POINTER;
    return BiometricManager::get().openSession(Factor, Flags, SessionHandle);
}

inline HRESULT __stdcall WinBioCloseSession(WINBIO_SESSION_HANDLE SessionHandle) {
    return BiometricManager::get().closeSession(SessionHandle);
}

inline HRESULT __stdcall WinBioEnumBiometricUnits(
    WINBIO_BIOMETRIC_TYPE Factor,
    WINBIO_UNIT_SCHEMA** UnitSchemaArray,
    size_t* UnitCount
) {
    if (!UnitSchemaArray || !UnitCount) return E_POINTER;
    auto units = BiometricManager::get().enumerateUnits(Factor);
    *UnitCount = units.size();
    if (units.empty()) {
        *UnitSchemaArray = nullptr;
        return S_OK;
    }

    size_t byteSize = sizeof(WINBIO_UNIT_SCHEMA) * units.size();
    auto* pArr = static_cast<WINBIO_UNIT_SCHEMA*>(ole32::CoTaskMemAlloc(byteSize));
    if (!pArr) return E_OUTOFMEMORY;
    std::memcpy(pArr, units.data(), byteSize);
    *UnitSchemaArray = pArr;
    return S_OK;
}

inline HRESULT __stdcall WinBioEnumDatabases(
    WINBIO_BIOMETRIC_TYPE Factor,
    WINBIO_STORAGE_SCHEMA** StorageSchemaArray,
    size_t* StorageCount
) {
    if (!StorageSchemaArray || !StorageCount) return E_POINTER;
    auto dbs = BiometricManager::get().enumerateDatabases(Factor);
    *StorageCount = dbs.size();
    if (dbs.empty()) {
        *StorageSchemaArray = nullptr;
        return S_OK;
    }

    size_t byteSize = sizeof(WINBIO_STORAGE_SCHEMA) * dbs.size();
    auto* pArr = static_cast<WINBIO_STORAGE_SCHEMA*>(ole32::CoTaskMemAlloc(byteSize));
    if (!pArr) return E_OUTOFMEMORY;
    std::memcpy(pArr, dbs.data(), byteSize);
    *StorageSchemaArray = pArr;
    return S_OK;
}

inline HRESULT __stdcall WinBioEnumEnrollments(
    WINBIO_SESSION_HANDLE /*SessionHandle*/,
    WINBIO_UNIT_ID UnitId,
    WINBIO_IDENTITY* /*Identity*/,
    WINBIO_BIOMETRIC_SUBTYPE** SubFactorArray,
    size_t* SubFactorCount
) {
    if (!SubFactorArray || !SubFactorCount) return E_POINTER;
    auto enrolls = BiometricManager::get().enumerateEnrollments(UnitId);
    *SubFactorCount = enrolls.size();
    if (enrolls.empty()) {
        *SubFactorArray = nullptr;
        return S_OK;
    }

    size_t byteSize = sizeof(WINBIO_BIOMETRIC_SUBTYPE) * enrolls.size();
    auto* pArr = static_cast<WINBIO_BIOMETRIC_SUBTYPE*>(ole32::CoTaskMemAlloc(byteSize));
    if (!pArr) return E_OUTOFMEMORY;
    for (size_t i = 0; i < enrolls.size(); ++i) {
        pArr[i] = enrolls[i].subFactor;
    }
    *SubFactorArray = pArr;
    return S_OK;
}

inline HRESULT __stdcall WinBioLocateSensor(WINBIO_SESSION_HANDLE /*SessionHandle*/, WINBIO_UNIT_ID* UnitId) {
    if (!UnitId) return E_POINTER;
    *UnitId = 1; // Primary fingerprint sensor
    return S_OK;
}

inline HRESULT __stdcall WinBioEnrollBegin(
    WINBIO_SESSION_HANDLE SessionHandle,
    WINBIO_BIOMETRIC_SUBTYPE SubFactor,
    WINBIO_UNIT_ID UnitId
) {
    return BiometricManager::get().enrollBegin(SessionHandle, SubFactor, UnitId);
}

inline HRESULT __stdcall WinBioEnrollCapture(
    WINBIO_SESSION_HANDLE SessionHandle,
    WINBIO_REJECT_DETAIL* RejectDetail
) {
    return BiometricManager::get().enrollCapture(SessionHandle, RejectDetail);
}

inline HRESULT __stdcall WinBioEnrollCommit(
    WINBIO_SESSION_HANDLE SessionHandle,
    WINBIO_IDENTITY* Identity,
    win32::BOOL* IsNewTemplate
) {
    return BiometricManager::get().enrollCommit(SessionHandle, Identity, IsNewTemplate);
}

inline HRESULT __stdcall WinBioEnrollDiscard(WINBIO_SESSION_HANDLE SessionHandle) {
    return BiometricManager::get().enrollDiscard(SessionHandle);
}

inline HRESULT __stdcall WinBioVerify(
    WINBIO_SESSION_HANDLE SessionHandle,
    WINBIO_UNIT_ID UnitId,
    WINBIO_BIOMETRIC_SUBTYPE SubFactor,
    WINBIO_IDENTITY* Identity,
    win32::BOOL* Match,
    WINBIO_REJECT_DETAIL* RejectDetail
) {
    return BiometricManager::get().verify(SessionHandle, UnitId, SubFactor, Identity, Match, RejectDetail);
}

inline HRESULT __stdcall WinBioIdentify(
    WINBIO_SESSION_HANDLE SessionHandle,
    WINBIO_UNIT_ID UnitId,
    WINBIO_IDENTITY* Identity,
    WINBIO_BIOMETRIC_SUBTYPE* SubFactor,
    WINBIO_REJECT_DETAIL* RejectDetail
) {
    return BiometricManager::get().identify(SessionHandle, UnitId, Identity, SubFactor, RejectDetail);
}

inline HRESULT __stdcall WinBioFree(void* Address) {
    if (Address) ole32::CoTaskMemFree(Address);
    return S_OK;
}

inline HRESULT __stdcall WinBioCancel(WINBIO_SESSION_HANDLE /*SessionHandle*/) {
    return S_OK;
}

inline HRESULT __stdcall WinBioWait(WINBIO_SESSION_HANDLE /*SessionHandle*/) {
    return S_OK;
}

inline HRESULT __stdcall WinBioAcquireFocus() {
    return S_OK;
}

inline HRESULT __stdcall WinBioReleaseFocus() {
    return S_OK;
}

// Dynamic Exports for winbiosrvc.dll
inline HRESULT __stdcall WbioSrvcMain(uint32_t /*argc*/, wchar_t** /*argv*/) {
    return S_OK;
}

inline HRESULT __stdcall DllGetClassObject(REFCLSID /*rclsid*/, REFIID /*riid*/, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;
    return CLASS_E_CLASSNOTAVAILABLE;
}

inline HRESULT __stdcall DllCanUnloadNow() { return S_OK; }
inline HRESULT __stdcall DllRegisterServer() { return S_OK; }
inline HRESULT __stdcall DllUnregisterServer() { return S_OK; }

inline void InitializeBiometricsSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // 1. winbio.dll (Windows Biometric Framework Client API)
    ldr.registerExport("winbio.dll", "WinBioOpenSession", reinterpret_cast<void*>(WinBioOpenSession));
    ldr.registerExport("winbio.dll", "WinBioCloseSession", reinterpret_cast<void*>(WinBioCloseSession));
    ldr.registerExport("winbio.dll", "WinBioEnumBiometricUnits", reinterpret_cast<void*>(WinBioEnumBiometricUnits));
    ldr.registerExport("winbio.dll", "WinBioEnumDatabases", reinterpret_cast<void*>(WinBioEnumDatabases));
    ldr.registerExport("winbio.dll", "WinBioEnumEnrollments", reinterpret_cast<void*>(WinBioEnumEnrollments));
    ldr.registerExport("winbio.dll", "WinBioLocateSensor", reinterpret_cast<void*>(WinBioLocateSensor));
    ldr.registerExport("winbio.dll", "WinBioEnrollBegin", reinterpret_cast<void*>(WinBioEnrollBegin));
    ldr.registerExport("winbio.dll", "WinBioEnrollCapture", reinterpret_cast<void*>(WinBioEnrollCapture));
    ldr.registerExport("winbio.dll", "WinBioEnrollCommit", reinterpret_cast<void*>(WinBioEnrollCommit));
    ldr.registerExport("winbio.dll", "WinBioEnrollDiscard", reinterpret_cast<void*>(WinBioEnrollDiscard));
    ldr.registerExport("winbio.dll", "WinBioVerify", reinterpret_cast<void*>(WinBioVerify));
    ldr.registerExport("winbio.dll", "WinBioIdentify", reinterpret_cast<void*>(WinBioIdentify));
    ldr.registerExport("winbio.dll", "WinBioFree", reinterpret_cast<void*>(WinBioFree));
    ldr.registerExport("winbio.dll", "WinBioCancel", reinterpret_cast<void*>(WinBioCancel));
    ldr.registerExport("winbio.dll", "WinBioWait", reinterpret_cast<void*>(WinBioWait));
    ldr.registerExport("winbio.dll", "WinBioAcquireFocus", reinterpret_cast<void*>(WinBioAcquireFocus));
    ldr.registerExport("winbio.dll", "WinBioReleaseFocus", reinterpret_cast<void*>(WinBioReleaseFocus));

    // 2. winbiosrvc.dll (Windows Biometric Service)
    ldr.registerExport("winbiosrvc.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));
    ldr.registerExport("winbiosrvc.dll", "DllCanUnloadNow", reinterpret_cast<void*>(DllCanUnloadNow));
    ldr.registerExport("winbiosrvc.dll", "DllRegisterServer", reinterpret_cast<void*>(DllRegisterServer));
    ldr.registerExport("winbiosrvc.dll", "DllUnregisterServer", reinterpret_cast<void*>(DllUnregisterServer));
    ldr.registerExport("winbiosrvc.dll", "WbioSrvcMain", reinterpret_cast<void*>(WbioSrvcMain));

    // Initialize sovereign singleton
    BiometricManager::get();
}

} // namespace micant::winbio
