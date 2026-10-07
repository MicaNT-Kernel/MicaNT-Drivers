// ============================================================================
// MicaNT: Clean-Room Windows-Compatible Operating System Executive
// Subsystem: Windows Volume Shadow Copy Service (VSS)
// Implementation: include/micant/vss.hpp
// Reference: Microsoft Win32 Metadata (MIT Licensed)
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ole32.hpp"
#include "oleaut32.hpp"
#include "fs.hpp"
#include "janusldr.hpp"

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <algorithm>

namespace micant::vss {

using namespace micant::ole32;

using VSS_ID = GUID;
using VSS_PWSZ = wchar_t*;
using VSS_TIMESTAMP = uint64_t;

struct VSSIDLess {
    bool operator()(const VSS_ID& a, const VSS_ID& b) const noexcept {
        return std::memcmp(&a, &b, sizeof(VSS_ID)) < 0;
    }
};

// ============================================================================
// 1. GUIDs & CLSIDs
// ============================================================================

// CLSID_VssCoordinator: {507c37b9-1116-4518-9c30-e9da7c4156e5}
inline const GUID CLSID_VssCoordinator = {
    0x507c37b9, 0x1116, 0x4518, { 0x9c, 0x30, 0xe9, 0xda, 0x7c, 0x41, 0x56, 0xe5 }
};

// IID_IVssBackupComponents: {665c1d5f-c218-414d-a05d-7fef5f9d5c86}
inline const IID IID_IVssBackupComponents = {
    0x665c1d5f, 0xc218, 0x414d, { 0xa0, 0x5d, 0x7f, 0xef, 0x5f, 0x9d, 0x5c, 0x86 }
};

// IID_IVssAsync: {507c37b9-1116-4518-9c30-e9da7c4156e7}
inline const IID IID_IVssAsync = {
    0x507c37b9, 0x1116, 0x4518, { 0x9c, 0x30, 0xe9, 0xda, 0x7c, 0x41, 0x56, 0xe7 }
};

// IID_IVssEnumObject: {ae1c7110-2f60-11d3-8a39-00c04f72d8e3}
inline const IID IID_IVssEnumObject = {
    0xae1c7110, 0x2f60, 0x11d3, { 0x8a, 0x39, 0x00, 0xc0, 0x4f, 0x72, 0xd8, 0xe3 }
};

// IID_IVssWMFiledesc: {a3861214-41d8-4f80-87a3-764f693d2cb2}
inline const IID IID_IVssWMFiledesc = {
    0xa3861214, 0x41d8, 0x4f80, { 0x87, 0xa3, 0x76, 0x4f, 0x69, 0x3d, 0x2c, 0xb2 }
};

// IID_IVssComponent: {d2c72c96-c121-4518-b627-f5a93d010ead}
inline const IID IID_IVssComponent = {
    0xd2c72c96, 0xc121, 0x4518, { 0xb6, 0x27, 0xf5, 0xa9, 0x3d, 0x01, 0x0e, 0xad }
};

// Default Microsoft Software Shadow Copy provider: {b5946137-7b9f-4925-af80-51abd60b20d5}
inline const GUID VSS_SW_PROVIDER_ID = {
    0xb5946137, 0x7b9f, 0x4925, { 0xaf, 0x80, 0x51, 0xab, 0xd6, 0x0b, 0x20, 0xd5 }
};

// Pre-seeded Writer IDs
inline const GUID VSS_SYSTEM_WRITER_ID = {
    0xe81062d3, 0x1809, 0x446b, { 0x80, 0x16, 0xe7, 0x36, 0x09, 0x59, 0x21, 0xe0 }
};

inline const GUID VSS_REGISTRY_WRITER_ID = {
    0xafbab4a2, 0x367d, 0x4d15, { 0xa5, 0x86, 0x71, 0xdb, 0xb1, 0x8f, 0x84, 0x85 }
};

inline const GUID VSS_WMI_WRITER_ID = {
    0xa6ad56c2, 0xb509, 0x4e6c, { 0xbb, 0x19, 0x49, 0xd8, 0xf4, 0x35, 0x32, 0xf0 }
};

inline const GUID VSS_SHADOW_OPT_WRITER_ID = {
    0x4dc3e18e, 0x5da5, 0x430c, { 0xac, 0x53, 0x2e, 0xe2, 0x19, 0xc0, 0x88, 0x33 }
};

// ============================================================================
// 2. Constants & Enums
// ============================================================================

enum VSS_OBJECT_TYPE {
    VSS_OBJECT_UNKNOWN      = 0,
    VSS_OBJECT_NONE         = 1,
    VSS_OBJECT_SNAPSHOT_SET = 2,
    VSS_OBJECT_SNAPSHOT     = 3,
    VSS_OBJECT_PROVIDER     = 4,
    VSS_OBJECT_TYPE_COUNT   = 5
};

enum VSS_SNAPSHOT_STATE {
    VSS_SS_UNKNOWN              = 0,
    VSS_SS_PREPARING            = 1,
    VSS_SS_PROCESSING_PREPARE   = 2,
    VSS_SS_PREPARED             = 3,
    VSS_SS_PROCESSING_PRECOMMIT = 4,
    VSS_SS_PRECOMMITTED         = 5,
    VSS_SS_PROCESSING_COMMIT    = 6,
    VSS_SS_COMMITTED            = 7,
    VSS_SS_ERROR                = 8
};

enum VSS_SNAPSHOT_CONTEXT {
    VSS_CTX_BACKUP            = 0,
    VSS_CTX_FILE_SHARE_BACKUP = 0x10,
    VSS_CTX_NAS_ROLLBACK      = 0x19,
    VSS_CTX_APP_ROLLBACK      = 0x20,
    VSS_CTX_CLIENT_ACCESSIBLE = 0x29,
    VSS_CTX_ALL               = 0xFFFFFFFF
};

enum VSS_BACKUP_TYPE {
    VSS_BT_UNDEFINED    = 0,
    VSS_BT_FULL         = 1,
    VSS_BT_INCREMENTAL  = 2,
    VSS_BT_DIFFERENTIAL = 3,
    VSS_BT_LOG          = 4,
    VSS_BT_COPY         = 5,
    VSS_BT_OTHER        = 6
};

enum VSS_PROVIDER_TYPE {
    VSS_PROV_UNKNOWN  = 0,
    VSS_PROV_SYSTEM   = 1,
    VSS_PROV_SOFTWARE = 2,
    VSS_PROV_HARDWARE = 3
};

enum VSS_VOLUME_SNAPSHOT_ATTRIBUTES {
    VSS_VOLSNAP_ATTR_PERSISTENT        = 0x00000001,
    VSS_VOLSNAP_ATTR_NO_AUTORECOVERY   = 0x00000002,
    VSS_VOLSNAP_ATTR_CLIENT_ACCESSIBLE = 0x00000004,
    VSS_VOLSNAP_ATTR_NO_AUTO_RELEASE   = 0x00000008,
    VSS_VOLSNAP_ATTR_DIFFERENTIAL      = 0x00000010,
    VSS_VOLSNAP_ATTR_TRANSPORTABLE     = 0x00000800
};

enum VSS_WRITER_STATE {
    VSS_WS_STABLE                       = 1,
    VSS_WS_WAITING_FOR_FREEZE           = 2,
    VSS_WS_WAITING_FOR_THAW             = 3,
    VSS_WS_WAITING_FOR_POST_SNAPSHOT    = 4,
    VSS_WS_WAITING_FOR_BACKUP_COMPLETE  = 5,
    VSS_WS_FAILED_AT_IDENTIFY           = 6,
    VSS_WS_FAILED_AT_PREPARE_BACKUP     = 7,
    VSS_WS_FAILED_AT_PREPARE_SNAPSHOT   = 8,
    VSS_WS_FAILED_AT_FREEZE             = 9,
    VSS_WS_FAILED_AT_THAW               = 10,
    VSS_WS_FAILED_AT_POST_SNAPSHOT      = 11,
    VSS_WS_FAILED_AT_BACKUP_COMPLETE    = 12
};

// HRESULT status codes
constexpr HRESULT VSS_S_ASYNC_PENDING                    = 0x00042309;
constexpr HRESULT VSS_S_ASYNC_FINISHED                   = 0x0004230A;
constexpr HRESULT VSS_S_ASYNC_CANCELLED                  = 0x0004230B;
constexpr HRESULT VSS_E_BAD_STATE                        = static_cast<HRESULT>(0x80042301);
constexpr HRESULT VSS_E_PROVIDER_ALREADY_REGISTERED      = static_cast<HRESULT>(0x80042303);
constexpr HRESULT VSS_E_PROVIDER_NOT_REGISTERED          = static_cast<HRESULT>(0x80042304);
constexpr HRESULT VSS_E_OBJECT_NOT_FOUND                 = static_cast<HRESULT>(0x80042308);
constexpr HRESULT VSS_E_VOLUME_NOT_SUPPORTED             = static_cast<HRESULT>(0x8004230C);
constexpr HRESULT VSS_E_VOLUME_NOT_SUPPORTED_BY_PROVIDER = static_cast<HRESULT>(0x8004230E);
constexpr HRESULT VSS_E_SNAPSHOT_SET_IN_PROGRESS         = static_cast<HRESULT>(0x80042316);
constexpr HRESULT VSS_E_MAXIMUM_NUMBER_OF_SNAPSHOTS_REACHED = static_cast<HRESULT>(0x80042317);
constexpr HRESULT VSS_E_WRITER_INFRASTRUCTURE            = static_cast<HRESULT>(0x80042318);
constexpr HRESULT VSS_E_WRITER_NOT_FOUND                 = static_cast<HRESULT>(0x80042319);
constexpr HRESULT VSS_E_INSUFFICIENT_STORAGE             = static_cast<HRESULT>(0x8004231F);

// ============================================================================
// 3. Structs
// ============================================================================

struct VSS_SNAPSHOT_PROP {
    VSS_ID              m_SnapshotId{};
    VSS_ID              m_SnapshotSetId{};
    int32_t             m_lSnapshotsCount{0};
    VSS_PWSZ            m_pwszSnapshotDeviceObject{nullptr};
    VSS_PWSZ            m_pwszOriginalVolumeName{nullptr};
    VSS_PWSZ            m_pwszOriginatingMachine{nullptr};
    VSS_PWSZ            m_pwszServiceMachine{nullptr};
    VSS_PWSZ            m_pwszExposedName{nullptr};
    VSS_PWSZ            m_pwszExposedPath{nullptr};
    VSS_ID              m_ProviderId{};
    int32_t             m_lSnapshotAttributes{0};
    VSS_TIMESTAMP       m_tsCreationTimestamp{0};
    VSS_SNAPSHOT_STATE  m_eStatus{VSS_SS_UNKNOWN};
};

struct VSS_PROVIDER_PROP {
    VSS_ID              m_ProviderId{};
    VSS_PWSZ            m_pwszProviderName{nullptr};
    VSS_PROVIDER_TYPE   m_eProviderType{VSS_PROV_UNKNOWN};
    VSS_PWSZ            m_pwszProviderVersion{nullptr};
    VSS_ID              m_ProviderVersionId{};
    CLSID               m_ClassId{};
};

struct VSS_OBJECT_PROP {
    VSS_OBJECT_TYPE Type{VSS_OBJECT_UNKNOWN};
    union {
        VSS_SNAPSHOT_PROP Snap;
        VSS_PROVIDER_PROP Prov;
    } Obj{};
};

struct VSS_DIFF_AREA_PROP {
    std::wstring VolumeName;
    std::wstring DiffVolumeName;
    uint64_t MaximumDiffSpace{0};
    uint64_t AllocatedDiffSpace{0};
    uint64_t UsedDiffSpace{0};
};

struct VSS_WRITER_INFO {
    VSS_ID WriterId{};
    VSS_ID InstanceId{};
    std::wstring WriterName;
    VSS_WRITER_STATE State{VSS_WS_STABLE};
    HRESULT LastError{S_OK};
};

inline void VssFreeSnapshotProperties(VSS_SNAPSHOT_PROP* pProp) {
    if (!pProp) return;
    if (pProp->m_pwszSnapshotDeviceObject) ole32::CoTaskMemFree(pProp->m_pwszSnapshotDeviceObject);
    if (pProp->m_pwszOriginalVolumeName) ole32::CoTaskMemFree(pProp->m_pwszOriginalVolumeName);
    if (pProp->m_pwszOriginatingMachine) ole32::CoTaskMemFree(pProp->m_pwszOriginatingMachine);
    if (pProp->m_pwszServiceMachine) ole32::CoTaskMemFree(pProp->m_pwszServiceMachine);
    if (pProp->m_pwszExposedName) ole32::CoTaskMemFree(pProp->m_pwszExposedName);
    if (pProp->m_pwszExposedPath) ole32::CoTaskMemFree(pProp->m_pwszExposedPath);
    std::memset(pProp, 0, sizeof(VSS_SNAPSHOT_PROP));
}

// ============================================================================
// 4. COM Interface Declarations
// ============================================================================

class IVssAsync;
class IVssEnumObject;
class IVssWMFiledesc;
class IVssComponent;
class IVssBackupComponents;

class IVssAsync : public IUnknown {
public:
    virtual HRESULT __stdcall Cancel() = 0;
    virtual HRESULT __stdcall Wait(uint32_t dwMilliseconds) = 0;
    virtual HRESULT __stdcall QueryStatus(HRESULT* pHrResult, int32_t* pReserved) = 0;
};

class IVssEnumObject : public IUnknown {
public:
    virtual HRESULT __stdcall Next(uint32_t celt, VSS_OBJECT_PROP* rgelt, uint32_t* pceltFetched) = 0;
    virtual HRESULT __stdcall Skip(uint32_t celt) = 0;
    virtual HRESULT __stdcall Reset() = 0;
    virtual HRESULT __stdcall Clone(IVssEnumObject** ppenum) = 0;
};

class IVssWMFiledesc : public IUnknown {
public:
    virtual HRESULT __stdcall GetPath(VSS_PWSZ* pbstrPath) = 0;
    virtual HRESULT __stdcall GetFilespec(VSS_PWSZ* pbstrFilespec) = 0;
    virtual HRESULT __stdcall GetRecursive(bool* pbRecursive) = 0;
    virtual HRESULT __stdcall GetAlternateLocation(VSS_PWSZ* pbstrAlternateLocation) = 0;
    virtual HRESULT __stdcall GetBackupTypeMask(uint32_t* pdwTypeMask) = 0;
};

class IVssComponent : public IUnknown {
public:
    virtual HRESULT __stdcall GetLogicalPath(VSS_PWSZ* pbstrPath) = 0;
    virtual HRESULT __stdcall GetComponentType(int32_t* pct) = 0;
    virtual HRESULT __stdcall GetComponentName(VSS_PWSZ* pbstrName) = 0;
    virtual HRESULT __stdcall GetBackupSucceeded(bool* pbSucceeded) = 0;
    virtual HRESULT __stdcall GetFileDescriptorCount(uint32_t* pcFiles) = 0;
    virtual HRESULT __stdcall GetFileDescriptor(uint32_t iFile, IVssWMFiledesc** ppFiledesc) = 0;
};

class IVssBackupComponents : public IUnknown {
public:
    virtual HRESULT __stdcall InitializeForBackup(wchar_t* bstrXML) = 0;
    virtual HRESULT __stdcall SetBackupState(bool bSelectComponents, bool bBootableSystemStateBackup, VSS_BACKUP_TYPE backupType, bool bPartialFileSupport) = 0;
    virtual HRESULT __stdcall InitializeForRestore(wchar_t* bstrXML) = 0;
    virtual HRESULT __stdcall SetRestoreState(int32_t restoreType) = 0;
    virtual HRESULT __stdcall GatherWriterMetadata(IVssAsync** ppAsync) = 0;
    virtual HRESULT __stdcall GetWriterMetadataCount(uint32_t* pcWriters) = 0;
    virtual HRESULT __stdcall FreeWriterMetadata() = 0;
    virtual HRESULT __stdcall AddComponent(VSS_ID instanceId, VSS_ID writerId, int32_t ct, wchar_t* wszLogicalPath, wchar_t* wszComponentName) = 0;
    virtual HRESULT __stdcall PrepareForBackup(IVssAsync** ppAsync) = 0;
    virtual HRESULT __stdcall AbortBackup() = 0;
    virtual HRESULT __stdcall GatherWriterStatus(IVssAsync** ppAsync) = 0;
    virtual HRESULT __stdcall GetWriterStatusCount(uint32_t* pcWriters) = 0;
    virtual HRESULT __stdcall FreeWriterStatus() = 0;
    virtual HRESULT __stdcall GetWriterStatus(uint32_t iWriter, VSS_ID* pidInstance, VSS_ID* pidWriter, VSS_PWSZ* pbstrWriter, VSS_WRITER_STATE* pnStatus, HRESULT* phrFailureReason) = 0;
    virtual HRESULT __stdcall SetBackupSucceeded(VSS_ID instanceId, VSS_ID writerId, int32_t ct, wchar_t* wszLogicalPath, wchar_t* wszComponentName, bool bSucceded) = 0;
    virtual HRESULT __stdcall StartSnapshotSet(VSS_ID* pSnapshotSetId) = 0;
    virtual HRESULT __stdcall AddToSnapshotSet(VSS_PWSZ pwszVolumeName, VSS_ID ProviderId, VSS_ID* pidSnapshot) = 0;
    virtual HRESULT __stdcall DoSnapshotSet(IVssAsync** ppAsync) = 0;
    virtual HRESULT __stdcall ImportSnapshots(IVssAsync** ppAsync) = 0;
    virtual HRESULT __stdcall BreakSnapshotSet(VSS_ID SnapshotSetId) = 0;
    virtual HRESULT __stdcall GetSnapshotProperties(VSS_ID SnapshotId, VSS_SNAPSHOT_PROP* pProp) = 0;
    virtual HRESULT __stdcall Query(VSS_ID QueriedObjectId, VSS_OBJECT_TYPE eQueriedObjectType, VSS_OBJECT_TYPE eReturnedObjectsType, IVssEnumObject** ppEnum) = 0;
    virtual HRESULT __stdcall DeleteSnapshots(VSS_ID SourceObjectId, VSS_OBJECT_TYPE eSourceObjectType, bool bForceDelete, int32_t* plDeletedSnapshots, VSS_ID* pNondeletedSnapshotID) = 0;
    virtual HRESULT __stdcall ExposeSnapshot(VSS_ID SnapshotId, wchar_t* wszPathFromRoot, int32_t lAttributes, wchar_t* wszExpose, wchar_t** pwszExposed) = 0;
    virtual HRESULT __stdcall RevertToSnapshot(VSS_ID SnapshotId, bool bForceDismount) = 0;
};

// ============================================================================
// 5. Concrete Implementation Classes
// ============================================================================

// ----------------------------------------------------------------------------
// VssAsync
// ----------------------------------------------------------------------------
class VssAsync : public IVssAsync {
private:
    std::atomic<uint32_t> m_refCount{1};
    HRESULT m_finalStatus{VSS_S_ASYNC_FINISHED};
    std::atomic<bool> m_isDone{true};
    std::atomic<bool> m_isCancelled{false};

public:
    VssAsync(HRESULT status = VSS_S_ASYNC_FINISHED) : m_finalStatus(status) {}
    virtual ~VssAsync() = default;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IVssAsync) {
            *ppv = static_cast<IVssAsync*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t __stdcall Release() override {
        uint32_t cnt = m_refCount.fetch_sub(1) - 1;
        if (cnt == 0) delete this;
        return cnt;
    }

    virtual HRESULT __stdcall Cancel() override {
        m_isCancelled = true;
        m_isDone = true;
        m_finalStatus = VSS_S_ASYNC_CANCELLED;
        return S_OK;
    }

    virtual HRESULT __stdcall Wait(uint32_t /*dwMilliseconds*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall QueryStatus(HRESULT* pHrResult, int32_t* pReserved) override {
        if (!pHrResult) return E_POINTER;
        if (pReserved) *pReserved = 0;
        *pHrResult = m_finalStatus;
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// VssEnumObject
// ----------------------------------------------------------------------------
class VssEnumObject : public IVssEnumObject {
private:
    std::atomic<uint32_t> m_refCount{1};
    std::vector<VSS_OBJECT_PROP> m_objects;
    size_t m_cursor{0};

public:
    VssEnumObject(std::vector<VSS_OBJECT_PROP> objs) : m_objects(std::move(objs)) {}
    virtual ~VssEnumObject() {
        for (auto& obj : m_objects) {
            if (obj.Type == VSS_OBJECT_SNAPSHOT) {
                VssFreeSnapshotProperties(&obj.Obj.Snap);
            } else if (obj.Type == VSS_OBJECT_PROVIDER) {
                if (obj.Obj.Prov.m_pwszProviderName) ole32::CoTaskMemFree(obj.Obj.Prov.m_pwszProviderName);
                if (obj.Obj.Prov.m_pwszProviderVersion) ole32::CoTaskMemFree(obj.Obj.Prov.m_pwszProviderVersion);
            }
        }
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IVssEnumObject) {
            *ppv = static_cast<IVssEnumObject*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t __stdcall Release() override {
        uint32_t cnt = m_refCount.fetch_sub(1) - 1;
        if (cnt == 0) delete this;
        return cnt;
    }

    virtual HRESULT __stdcall Next(uint32_t celt, VSS_OBJECT_PROP* rgelt, uint32_t* pceltFetched) override {
        if (!rgelt) return E_POINTER;
        if (celt > 1 && !pceltFetched) return E_INVALIDARG;

        uint32_t fetched = 0;
        while (fetched < celt && m_cursor < m_objects.size()) {
            const auto& src = m_objects[m_cursor++];
            rgelt[fetched].Type = src.Type;

            if (src.Type == VSS_OBJECT_SNAPSHOT) {
                rgelt[fetched].Obj.Snap = src.Obj.Snap;
                auto dupString = [](const wchar_t* s) -> wchar_t* {
                    if (!s) return nullptr;
                    size_t sz = (wcslen(s) + 1) * sizeof(wchar_t);
                    auto* p = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(sz));
                    if (p) memcpy(p, s, sz);
                    return p;
                };
                rgelt[fetched].Obj.Snap.m_pwszSnapshotDeviceObject = dupString(src.Obj.Snap.m_pwszSnapshotDeviceObject);
                rgelt[fetched].Obj.Snap.m_pwszOriginalVolumeName = dupString(src.Obj.Snap.m_pwszOriginalVolumeName);
                rgelt[fetched].Obj.Snap.m_pwszOriginatingMachine = dupString(src.Obj.Snap.m_pwszOriginatingMachine);
                rgelt[fetched].Obj.Snap.m_pwszServiceMachine = dupString(src.Obj.Snap.m_pwszServiceMachine);
                rgelt[fetched].Obj.Snap.m_pwszExposedName = dupString(src.Obj.Snap.m_pwszExposedName);
                rgelt[fetched].Obj.Snap.m_pwszExposedPath = dupString(src.Obj.Snap.m_pwszExposedPath);
            } else if (src.Type == VSS_OBJECT_PROVIDER) {
                rgelt[fetched].Obj.Prov = src.Obj.Prov;
                auto dupString = [](const wchar_t* s) -> wchar_t* {
                    if (!s) return nullptr;
                    size_t sz = (wcslen(s) + 1) * sizeof(wchar_t);
                    auto* p = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(sz));
                    if (p) memcpy(p, s, sz);
                    return p;
                };
                rgelt[fetched].Obj.Prov.m_pwszProviderName = dupString(src.Obj.Prov.m_pwszProviderName);
                rgelt[fetched].Obj.Prov.m_pwszProviderVersion = dupString(src.Obj.Prov.m_pwszProviderVersion);
            }
            fetched++;
        }

        if (pceltFetched) *pceltFetched = fetched;
        return (fetched == celt) ? S_OK : S_FALSE;
    }

    virtual HRESULT __stdcall Skip(uint32_t celt) override {
        m_cursor = std::min(m_objects.size(), m_cursor + celt);
        return (m_cursor < m_objects.size()) ? S_OK : S_FALSE;
    }

    virtual HRESULT __stdcall Reset() override {
        m_cursor = 0;
        return S_OK;
    }

    virtual HRESULT __stdcall Clone(IVssEnumObject** ppenum) override {
        if (!ppenum) return E_POINTER;
        *ppenum = nullptr;
        return E_NOTIMPL;
    }
};

// ----------------------------------------------------------------------------
// Internal Snapshot Record
// ----------------------------------------------------------------------------
struct SnapshotRecord {
    VSS_ID SnapshotId{};
    VSS_ID SnapshotSetId{};
    std::wstring VolumeName;
    std::wstring DeviceObject;
    std::wstring OriginatingMachine{L"MICANT-HOST"};
    std::wstring ServiceMachine{L"MICANT-HOST"};
    std::wstring ExposedName;
    std::wstring ExposedPath;
    VSS_ID ProviderId{};
    int32_t Attributes{VSS_VOLSNAP_ATTR_PERSISTENT | VSS_VOLSNAP_ATTR_CLIENT_ACCESSIBLE | VSS_VOLSNAP_ATTR_DIFFERENTIAL};
    VSS_TIMESTAMP CreationTimestamp{0};
    VSS_SNAPSHOT_STATE Status{VSS_SS_COMMITTED};
};

// ----------------------------------------------------------------------------
// VssCoordinator (Central VSS System Manager)
// ----------------------------------------------------------------------------
class VssCoordinator {
private:
    std::mutex m_mutex;
    std::map<VSS_ID, SnapshotRecord, VSSIDLess> m_snapshots;
    std::vector<VSS_WRITER_INFO> m_writers;
    std::vector<VSS_PROVIDER_PROP> m_providers;
    std::vector<VSS_DIFF_AREA_PROP> m_diffAreas;
    uint32_t m_nextDeviceIndex{1};

    VssCoordinator() {
        // 1. Pre-seed Default VSS Provider (Microsoft Software Shadow Copy provider 1.0)
        VSS_PROVIDER_PROP prov{};
        prov.m_ProviderId = VSS_SW_PROVIDER_ID;
        prov.m_eProviderType = VSS_PROV_SYSTEM;
        prov.m_ProviderVersionId = { 0x11111111, 0x2222, 0x3333, { 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb } };
        prov.m_ClassId = CLSID_VssCoordinator;
        
        auto dupString = [](const wchar_t* s) -> wchar_t* {
            if (!s) return nullptr;
            size_t sz = (wcslen(s) + 1) * sizeof(wchar_t);
            auto* p = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(sz));
            if (p) memcpy(p, s, sz);
            return p;
        };
        prov.m_pwszProviderName = dupString(L"Microsoft Software Shadow Copy provider 1.0");
        prov.m_pwszProviderVersion = dupString(L"1.0.0.7");
        m_providers.push_back(prov);

        // 2. Pre-seed System Writers
        VSS_WRITER_INFO wSystem{};
        wSystem.WriterId = VSS_SYSTEM_WRITER_ID;
        wSystem.InstanceId = { 0x10000000, 0x0001, 0x0001, { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
        wSystem.WriterName = L"System Writer";
        wSystem.State = VSS_WS_STABLE;
        wSystem.LastError = S_OK;
        m_writers.push_back(wSystem);

        VSS_WRITER_INFO wReg{};
        wReg.WriterId = VSS_REGISTRY_WRITER_ID;
        wReg.InstanceId = { 0x20000000, 0x0002, 0x0002, { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } };
        wReg.WriterName = L"Registry Writer";
        wReg.State = VSS_WS_STABLE;
        wReg.LastError = S_OK;
        m_writers.push_back(wReg);

        VSS_WRITER_INFO wWmi{};
        wWmi.WriterId = VSS_WMI_WRITER_ID;
        wWmi.InstanceId = { 0x30000000, 0x0003, 0x0003, { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 } };
        wWmi.WriterName = L"WMI Writer";
        wWmi.State = VSS_WS_STABLE;
        wWmi.LastError = S_OK;
        m_writers.push_back(wWmi);

        VSS_WRITER_INFO wOpt{};
        wOpt.WriterId = VSS_SHADOW_OPT_WRITER_ID;
        wOpt.InstanceId = { 0x40000000, 0x0004, 0x0004, { 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04 } };
        wOpt.WriterName = L"Shadow Copy Optimization Writer";
        wOpt.State = VSS_WS_STABLE;
        wOpt.LastError = S_OK;
        m_writers.push_back(wOpt);

        // 3. Pre-seed Default Shadow Storage for Volume C:
        VSS_DIFF_AREA_PROP diffC{};
        diffC.VolumeName = L"C:\\";
        diffC.DiffVolumeName = L"C:\\";
        diffC.MaximumDiffSpace = 10ULL * 1024 * 1024 * 1024; // 10 GB
        diffC.AllocatedDiffSpace = 512ULL * 1024 * 1024;      // 512 MB
        diffC.UsedDiffSpace = 128ULL * 1024 * 1024;           // 128 MB
        m_diffAreas.push_back(diffC);

        // 4. Pre-seed Initial Shadow Copy for C:\ (Automatic System Restore Point)
        SnapshotRecord snapInit{};
        snapInit.SnapshotId = { 0x38a12345, 0x6789, 0x4abc, { 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab } };
        snapInit.SnapshotSetId = { 0x38a12345, 0x0000, 0x4abc, { 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x90, 0x00 } };
        snapInit.VolumeName = L"C:\\";
        snapInit.DeviceObject = L"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1";
        snapInit.ProviderId = VSS_SW_PROVIDER_ID;
        snapInit.Attributes = VSS_VOLSNAP_ATTR_PERSISTENT | VSS_VOLSNAP_ATTR_CLIENT_ACCESSIBLE | VSS_VOLSNAP_ATTR_DIFFERENTIAL;
        snapInit.CreationTimestamp = 133500000000000000ULL; // Approximate Windows FILETIME
        snapInit.Status = VSS_SS_COMMITTED;
        m_snapshots[snapInit.SnapshotId] = snapInit;
        m_nextDeviceIndex = 2;
    }

public:
    static VssCoordinator& Instance() {
        static VssCoordinator s_coordinator;
        return s_coordinator;
    }

    ~VssCoordinator() {
        for (auto& prov : m_providers) {
            if (prov.m_pwszProviderName) ole32::CoTaskMemFree(prov.m_pwszProviderName);
            if (prov.m_pwszProviderVersion) ole32::CoTaskMemFree(prov.m_pwszProviderVersion);
        }
    }

    HRESULT CreateSnapshot(const std::wstring& volumeName, const VSS_ID& providerId, const VSS_ID& setId, VSS_ID* pSnapshotId, SnapshotRecord* pOutRecord = nullptr) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!pSnapshotId) return E_POINTER;

        // Generate SnapshotId
        VSS_ID newId{};
        ole32::CoCreateGuid(&newId);

        SnapshotRecord rec{};
        rec.SnapshotId = newId;
        rec.SnapshotSetId = setId;
        rec.VolumeName = volumeName.empty() ? L"C:\\" : volumeName;
        if (rec.VolumeName.back() != L'\\') rec.VolumeName.push_back(L'\\');

        std::wstringstream wss;
        wss << L"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" << m_nextDeviceIndex++;
        rec.DeviceObject = wss.str();

        rec.ProviderId = providerId;
        rec.Attributes = VSS_VOLSNAP_ATTR_PERSISTENT | VSS_VOLSNAP_ATTR_CLIENT_ACCESSIBLE | VSS_VOLSNAP_ATTR_DIFFERENTIAL;

        uint64_t nowTicks = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() * 10 + 116444736000000000ULL;
        rec.CreationTimestamp = nowTicks;
        rec.Status = VSS_SS_COMMITTED;

        m_snapshots[newId] = rec;
        *pSnapshotId = newId;

        // Adjust shadow storage usage
        for (auto& diff : m_diffAreas) {
            if (diff.VolumeName == rec.VolumeName) {
                diff.AllocatedDiffSpace += 64ULL * 1024 * 1024;
                diff.UsedDiffSpace += 32ULL * 1024 * 1024;
            }
        }

        if (pOutRecord) *pOutRecord = rec;
        return S_OK;
    }

    HRESULT GetSnapshot(const VSS_ID& snapshotId, SnapshotRecord& outRecord) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_snapshots.find(snapshotId);
        if (it == m_snapshots.end()) return VSS_E_OBJECT_NOT_FOUND;
        outRecord = it->second;
        return S_OK;
    }

    HRESULT DeleteSnapshot(const VSS_ID& snapshotId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_snapshots.find(snapshotId);
        if (it == m_snapshots.end()) return VSS_E_OBJECT_NOT_FOUND;
        m_snapshots.erase(it);
        return S_OK;
    }

    std::vector<SnapshotRecord> GetAllSnapshots(const std::wstring& volFilter = L"") {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<SnapshotRecord> res;
        for (const auto& [_, rec] : m_snapshots) {
            if (volFilter.empty() || _wcsicmp(rec.VolumeName.c_str(), volFilter.c_str()) == 0) {
                res.push_back(rec);
            }
        }
        return res;
    }

    std::vector<VSS_WRITER_INFO> GetWriters() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_writers;
    }

    std::vector<VSS_PROVIDER_PROP> GetProviders() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_providers;
    }

    std::vector<VSS_DIFF_AREA_PROP> GetDiffAreas() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_diffAreas;
    }

    bool ResizeDiffArea(const std::wstring& vol, uint64_t maxBytes) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& d : m_diffAreas) {
            if (_wcsicmp(d.VolumeName.c_str(), vol.c_str()) == 0) {
                d.MaximumDiffSpace = maxBytes;
                return true;
            }
        }
        return false;
    }
};

// ----------------------------------------------------------------------------
// VssBackupComponents
// ----------------------------------------------------------------------------
class VssBackupComponents : public IVssBackupComponents {
private:
    std::atomic<uint32_t> m_refCount{1};
    VSS_ID m_currentSetId{};
    std::vector<VSS_ID> m_pendingSnapshots;
    VSS_BACKUP_TYPE m_backupType{VSS_BT_FULL};
    bool m_selectComponents{false};
    bool m_bootableSystemState{false};
    bool m_partialFileSupport{false};
    bool m_setStarted{false};
    std::mutex m_compMutex;

public:
    VssBackupComponents() = default;
    virtual ~VssBackupComponents() = default;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IVssBackupComponents) {
            *ppv = static_cast<IVssBackupComponents*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t __stdcall Release() override {
        uint32_t cnt = m_refCount.fetch_sub(1) - 1;
        if (cnt == 0) delete this;
        return cnt;
    }

    virtual HRESULT __stdcall InitializeForBackup(wchar_t* /*bstrXML*/) override {
        std::lock_guard<std::mutex> lock(m_compMutex);
        m_setStarted = false;
        m_pendingSnapshots.clear();
        return S_OK;
    }

    virtual HRESULT __stdcall SetBackupState(bool bSelectComponents, bool bBootableSystemStateBackup, VSS_BACKUP_TYPE backupType, bool bPartialFileSupport) override {
        std::lock_guard<std::mutex> lock(m_compMutex);
        m_selectComponents = bSelectComponents;
        m_bootableSystemState = bBootableSystemStateBackup;
        m_backupType = backupType;
        m_partialFileSupport = bPartialFileSupport;
        return S_OK;
    }

    virtual HRESULT __stdcall InitializeForRestore(wchar_t* /*bstrXML*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall SetRestoreState(int32_t /*restoreType*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall GatherWriterMetadata(IVssAsync** ppAsync) override {
        if (!ppAsync) return E_POINTER;
        *ppAsync = new VssAsync(VSS_S_ASYNC_FINISHED);
        return S_OK;
    }

    virtual HRESULT __stdcall GetWriterMetadataCount(uint32_t* pcWriters) override {
        if (!pcWriters) return E_POINTER;
        *pcWriters = static_cast<uint32_t>(VssCoordinator::Instance().GetWriters().size());
        return S_OK;
    }

    virtual HRESULT __stdcall FreeWriterMetadata() override {
        return S_OK;
    }

    virtual HRESULT __stdcall AddComponent(VSS_ID /*instanceId*/, VSS_ID /*writerId*/, int32_t /*ct*/, wchar_t* /*wszLogicalPath*/, wchar_t* /*wszComponentName*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall PrepareForBackup(IVssAsync** ppAsync) override {
        if (!ppAsync) return E_POINTER;
        *ppAsync = new VssAsync(VSS_S_ASYNC_FINISHED);
        return S_OK;
    }

    virtual HRESULT __stdcall AbortBackup() override {
        std::lock_guard<std::mutex> lock(m_compMutex);
        m_setStarted = false;
        m_pendingSnapshots.clear();
        return S_OK;
    }

    virtual HRESULT __stdcall GatherWriterStatus(IVssAsync** ppAsync) override {
        if (!ppAsync) return E_POINTER;
        *ppAsync = new VssAsync(VSS_S_ASYNC_FINISHED);
        return S_OK;
    }

    virtual HRESULT __stdcall GetWriterStatusCount(uint32_t* pcWriters) override {
        if (!pcWriters) return E_POINTER;
        *pcWriters = static_cast<uint32_t>(VssCoordinator::Instance().GetWriters().size());
        return S_OK;
    }

    virtual HRESULT __stdcall FreeWriterStatus() override {
        return S_OK;
    }

    virtual HRESULT __stdcall GetWriterStatus(uint32_t iWriter, VSS_ID* pidInstance, VSS_ID* pidWriter, VSS_PWSZ* pbstrWriter, VSS_WRITER_STATE* pnStatus, HRESULT* phrFailureReason) override {
        auto writers = VssCoordinator::Instance().GetWriters();
        if (iWriter >= writers.size()) return E_INVALIDARG;

        const auto& w = writers[iWriter];
        if (pidInstance) *pidInstance = w.InstanceId;
        if (pidWriter) *pidWriter = w.WriterId;
        if (pnStatus) *pnStatus = w.State;
        if (phrFailureReason) *phrFailureReason = w.LastError;

        if (pbstrWriter) {
            size_t sz = (w.WriterName.size() + 1) * sizeof(wchar_t);
            *pbstrWriter = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(sz));
            if (*pbstrWriter) memcpy(*pbstrWriter, w.WriterName.c_str(), sz);
        }
        return S_OK;
    }

    virtual HRESULT __stdcall SetBackupSucceeded(VSS_ID /*instanceId*/, VSS_ID /*writerId*/, int32_t /*ct*/, wchar_t* /*wszLogicalPath*/, wchar_t* /*wszComponentName*/, bool /*bSucceded*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall StartSnapshotSet(VSS_ID* pSnapshotSetId) override {
        if (!pSnapshotSetId) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_compMutex);
        if (m_setStarted) return VSS_E_SNAPSHOT_SET_IN_PROGRESS;

        ole32::CoCreateGuid(&m_currentSetId);
        *pSnapshotSetId = m_currentSetId;
        m_setStarted = true;
        m_pendingSnapshots.clear();
        return S_OK;
    }

    virtual HRESULT __stdcall AddToSnapshotSet(VSS_PWSZ pwszVolumeName, VSS_ID ProviderId, VSS_ID* pidSnapshot) override {
        if (!pwszVolumeName || !pidSnapshot) return E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_compMutex);
        if (!m_setStarted) return VSS_E_BAD_STATE;

        VSS_ID prov = (ProviderId == GUID_NULL) ? VSS_SW_PROVIDER_ID : ProviderId;
        HRESULT hr = VssCoordinator::Instance().CreateSnapshot(pwszVolumeName, prov, m_currentSetId, pidSnapshot);
        if (hr == S_OK) {
            m_pendingSnapshots.push_back(*pidSnapshot);
        }
        return hr;
    }

    virtual HRESULT __stdcall DoSnapshotSet(IVssAsync** ppAsync) override {
        if (!ppAsync) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_compMutex);
        if (!m_setStarted) return VSS_E_BAD_STATE;

        m_setStarted = false;
        *ppAsync = new VssAsync(VSS_S_ASYNC_FINISHED);
        return S_OK;
    }

    virtual HRESULT __stdcall ImportSnapshots(IVssAsync** ppAsync) override {
        if (!ppAsync) return E_POINTER;
        *ppAsync = new VssAsync(VSS_S_ASYNC_FINISHED);
        return S_OK;
    }

    virtual HRESULT __stdcall BreakSnapshotSet(VSS_ID /*SnapshotSetId*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall GetSnapshotProperties(VSS_ID SnapshotId, VSS_SNAPSHOT_PROP* pProp) override {
        if (!pProp) return E_POINTER;
        SnapshotRecord rec{};
        HRESULT hr = VssCoordinator::Instance().GetSnapshot(SnapshotId, rec);
        if (hr != S_OK) return hr;

        std::memset(pProp, 0, sizeof(VSS_SNAPSHOT_PROP));
        pProp->m_SnapshotId = rec.SnapshotId;
        pProp->m_SnapshotSetId = rec.SnapshotSetId;
        pProp->m_lSnapshotsCount = 1;
        pProp->m_ProviderId = rec.ProviderId;
        pProp->m_lSnapshotAttributes = rec.Attributes;
        pProp->m_tsCreationTimestamp = rec.CreationTimestamp;
        pProp->m_eStatus = rec.Status;

        auto dupString = [](const std::wstring& s) -> wchar_t* {
            if (s.empty()) return nullptr;
            size_t sz = (s.size() + 1) * sizeof(wchar_t);
            auto* p = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(sz));
            if (p) memcpy(p, s.c_str(), sz);
            return p;
        };

        pProp->m_pwszSnapshotDeviceObject = dupString(rec.DeviceObject);
        pProp->m_pwszOriginalVolumeName = dupString(rec.VolumeName);
        pProp->m_pwszOriginatingMachine = dupString(rec.OriginatingMachine);
        pProp->m_pwszServiceMachine = dupString(rec.ServiceMachine);
        pProp->m_pwszExposedName = dupString(rec.ExposedName);
        pProp->m_pwszExposedPath = dupString(rec.ExposedPath);

        return S_OK;
    }

    virtual HRESULT __stdcall Query(VSS_ID /*QueriedObjectId*/, VSS_OBJECT_TYPE eQueriedObjectType, VSS_OBJECT_TYPE eReturnedObjectsType, IVssEnumObject** ppEnum) override {
        if (!ppEnum) return E_POINTER;
        *ppEnum = nullptr;

        std::vector<VSS_OBJECT_PROP> objs;
        auto dupString = [](const std::wstring& s) -> wchar_t* {
            if (s.empty()) return nullptr;
            size_t sz = (s.size() + 1) * sizeof(wchar_t);
            auto* p = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(sz));
            if (p) memcpy(p, s.c_str(), sz);
            return p;
        };

        if (eReturnedObjectsType == VSS_OBJECT_SNAPSHOT || eQueriedObjectType == VSS_OBJECT_SNAPSHOT) {
            auto snaps = VssCoordinator::Instance().GetAllSnapshots();
            for (const auto& s : snaps) {
                VSS_OBJECT_PROP op{};
                op.Type = VSS_OBJECT_SNAPSHOT;
                op.Obj.Snap.m_SnapshotId = s.SnapshotId;
                op.Obj.Snap.m_SnapshotSetId = s.SnapshotSetId;
                op.Obj.Snap.m_lSnapshotsCount = 1;
                op.Obj.Snap.m_ProviderId = s.ProviderId;
                op.Obj.Snap.m_lSnapshotAttributes = s.Attributes;
                op.Obj.Snap.m_tsCreationTimestamp = s.CreationTimestamp;
                op.Obj.Snap.m_eStatus = s.Status;
                op.Obj.Snap.m_pwszSnapshotDeviceObject = dupString(s.DeviceObject);
                op.Obj.Snap.m_pwszOriginalVolumeName = dupString(s.VolumeName);
                op.Obj.Snap.m_pwszOriginatingMachine = dupString(s.OriginatingMachine);
                op.Obj.Snap.m_pwszServiceMachine = dupString(s.ServiceMachine);
                objs.push_back(op);
            }
        } else if (eReturnedObjectsType == VSS_OBJECT_PROVIDER || eQueriedObjectType == VSS_OBJECT_PROVIDER) {
            auto provs = VssCoordinator::Instance().GetProviders();
            for (const auto& p : provs) {
                VSS_OBJECT_PROP op{};
                op.Type = VSS_OBJECT_PROVIDER;
                op.Obj.Prov.m_ProviderId = p.m_ProviderId;
                op.Obj.Prov.m_eProviderType = p.m_eProviderType;
                op.Obj.Prov.m_ProviderVersionId = p.m_ProviderVersionId;
                op.Obj.Prov.m_ClassId = p.m_ClassId;
                op.Obj.Prov.m_pwszProviderName = dupString(p.m_pwszProviderName ? p.m_pwszProviderName : L"");
                op.Obj.Prov.m_pwszProviderVersion = dupString(p.m_pwszProviderVersion ? p.m_pwszProviderVersion : L"");
                objs.push_back(op);
            }
        }

        *ppEnum = new VssEnumObject(std::move(objs));
        return S_OK;
    }

    virtual HRESULT __stdcall DeleteSnapshots(VSS_ID SourceObjectId, VSS_OBJECT_TYPE eSourceObjectType, bool /*bForceDelete*/, int32_t* plDeletedSnapshots, VSS_ID* pNondeletedSnapshotID) override {
        if (!plDeletedSnapshots) return E_POINTER;
        *plDeletedSnapshots = 0;
        if (pNondeletedSnapshotID) *pNondeletedSnapshotID = GUID_NULL;

        if (eSourceObjectType == VSS_OBJECT_SNAPSHOT) {
            HRESULT hr = VssCoordinator::Instance().DeleteSnapshot(SourceObjectId);
            if (hr == S_OK) {
                *plDeletedSnapshots = 1;
                return S_OK;
            }
            return hr;
        } else if (eSourceObjectType == VSS_OBJECT_SNAPSHOT_SET) {
            auto snaps = VssCoordinator::Instance().GetAllSnapshots();
            int32_t cnt = 0;
            for (const auto& s : snaps) {
                if (s.SnapshotSetId == SourceObjectId) {
                    if (VssCoordinator::Instance().DeleteSnapshot(s.SnapshotId) == S_OK) {
                        cnt++;
                    }
                }
            }
            *plDeletedSnapshots = cnt;
            return S_OK;
        }
        return E_INVALIDARG;
    }

    virtual HRESULT __stdcall ExposeSnapshot(VSS_ID SnapshotId, wchar_t* /*wszPathFromRoot*/, int32_t /*lAttributes*/, wchar_t* wszExpose, wchar_t** pwszExposed) override {
        SnapshotRecord rec{};
        HRESULT hr = VssCoordinator::Instance().GetSnapshot(SnapshotId, rec);
        if (hr != S_OK) return hr;

        if (pwszExposed && wszExpose) {
            size_t sz = (wcslen(wszExpose) + 1) * sizeof(wchar_t);
            *pwszExposed = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(sz));
            if (*pwszExposed) memcpy(*pwszExposed, wszExpose, sz);
        }
        return S_OK;
    }

    virtual HRESULT __stdcall RevertToSnapshot(VSS_ID SnapshotId, bool /*bForceDismount*/) override {
        SnapshotRecord rec{};
        return VssCoordinator::Instance().GetSnapshot(SnapshotId, rec);
    }
};

// ----------------------------------------------------------------------------
// VssBackupComponentsClassFactory
// ----------------------------------------------------------------------------
class VssBackupComponentsClassFactory : public IClassFactory {
private:
    std::atomic<uint32_t> m_refCount{1};

public:
    VssBackupComponentsClassFactory() = default;
    virtual ~VssBackupComponentsClassFactory() = default;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    virtual uint32_t __stdcall AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t __stdcall Release() override {
        uint32_t cnt = m_refCount.fetch_sub(1) - 1;
        if (cnt == 0) delete this;
        return cnt;
    }

    virtual HRESULT __stdcall CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        *ppvObject = nullptr;
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;

        auto* comp = new VssBackupComponents();
        HRESULT hr = comp->QueryInterface(riid, ppvObject);
        comp->Release();
        return hr;
    }

    virtual HRESULT __stdcall LockServer(win32::BOOL /*fLock*/) override {
        return S_OK;
    }
};

// ============================================================================
// 6. Dynamic Loader & Dynamic Exports (vssapi.dll / vss_ps.dll)
// ============================================================================

extern "C" inline HRESULT __stdcall CreateVssBackupComponents(IVssBackupComponents** ppBackup) {
    if (!ppBackup) return E_POINTER;
    *ppBackup = new VssBackupComponents();
    return S_OK;
}

extern "C" inline HRESULT __stdcall VSS_DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (rclsid == CLSID_VssCoordinator) {
        static VssBackupComponentsClassFactory factory;
        return factory.QueryInterface(riid, ppv);
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

extern "C" inline HRESULT __stdcall VSS_DllCanUnloadNow() {
    return S_FALSE;
}

extern "C" inline HRESULT __stdcall VSS_DllRegisterServer() {
    return S_OK;
}

extern "C" inline HRESULT __stdcall VSS_DllUnregisterServer() {
    return S_OK;
}

inline void InitializeVSSSubsystemExports() {
    static std::atomic<bool> s_initialized{false};
    if (s_initialized.exchange(true)) return;

    auto& ldr = ldr::DynamicLoader::get();

    // Register vssapi.dll (Volume Shadow Copy Service API)
    ldr.registerExport("vssapi.dll", "CreateVssBackupComponents", reinterpret_cast<void*>(&CreateVssBackupComponents));
    ldr.registerExport("vssapi.dll", "VssFreeSnapshotProperties", reinterpret_cast<void*>(&VssFreeSnapshotProperties));
    ldr.registerExport("vssapi.dll", "DllGetClassObject", reinterpret_cast<void*>(&VSS_DllGetClassObject));
    ldr.registerExport("vssapi.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&VSS_DllCanUnloadNow));
    ldr.registerExport("vssapi.dll", "DllRegisterServer", reinterpret_cast<void*>(&VSS_DllRegisterServer));
    ldr.registerExport("vssapi.dll", "DllUnregisterServer", reinterpret_cast<void*>(&VSS_DllUnregisterServer));

    // Register vss_ps.dll (Proxy/Stub)
    ldr.registerExport("vss_ps.dll", "DllGetClassObject", reinterpret_cast<void*>(&VSS_DllGetClassObject));
    ldr.registerExport("vss_ps.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&VSS_DllCanUnloadNow));
    ldr.registerExport("vss_ps.dll", "DllRegisterServer", reinterpret_cast<void*>(&VSS_DllRegisterServer));
    ldr.registerExport("vss_ps.dll", "DllUnregisterServer", reinterpret_cast<void*>(&VSS_DllUnregisterServer));

    // Register COM Class Factory
    auto* factory = new VssBackupComponentsClassFactory();
    uint32_t regCookie = 0;
    ole32::CoRegisterClassObject(CLSID_VssCoordinator, factory, 1 /* CLSCTX_INPROC_SERVER */, 0, &regCookie);
}

} // namespace micant::vss
