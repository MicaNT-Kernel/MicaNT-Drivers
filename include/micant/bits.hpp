// ============================================================================
// MicaNT: Clean-Room Windows-Compatible Operating System Executive
// Subsystem: Windows Background Intelligent Transfer Service (BITS)
// Implementation: include/micant/bits.hpp
// Reference: Microsoft Win32 Metadata (MIT Licensed)
// ============================================================================

#pragma once

#include "ole32.hpp"
#include "oleaut32.hpp"
#include "fs.hpp"
#include "wininet.hpp"
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

namespace micant::bits {

using namespace micant::ole32;

using LPWSTR = wchar_t*;
using LPCWSTR = const wchar_t*;

struct GUIDLess {
    bool operator()(const GUID& a, const GUID& b) const noexcept {
        return std::memcmp(&a, &b, sizeof(GUID)) < 0;
    }
};

// ============================================================================
// 1. GUIDs & CLSIDs
// ============================================================================

// CLSID_BackgroundCopyManager: {4990ab3b-d0e8-4291-83b1-7a1bf63ee3f6}
inline const GUID CLSID_BackgroundCopyManager = {
    0x4990ab3b, 0xd0e8, 0x4291, { 0x83, 0xb1, 0x7a, 0x1b, 0xf6, 0x3e, 0xe3, 0xf6 }
};

// IID_IBackgroundCopyManager: {5ce466fd-d495-4529-878b-4e92251925ab}
inline const IID IID_IBackgroundCopyManager = {
    0x5ce466fd, 0xd495, 0x4529, { 0x87, 0x8b, 0x4e, 0x92, 0x25, 0x19, 0x25, 0xab }
};

// IID_IBackgroundCopyJob: {37668d37-507e-4160-9316-26306d150b12}
inline const IID IID_IBackgroundCopyJob = {
    0x37668d37, 0x507e, 0x4160, { 0x93, 0x16, 0x26, 0x30, 0x6d, 0x15, 0x0b, 0x12 }
};

// IID_IBackgroundCopyJob2: {54b8e2b7-8eb8-4985-ac7c-03d7e50529d2}
inline const IID IID_IBackgroundCopyJob2 = {
    0x54b8e2b7, 0x8eb8, 0x4985, { 0xac, 0x7c, 0x03, 0xd7, 0xe5, 0x05, 0x29, 0xd2 }
};

// IID_IBackgroundCopyFile: {01b7bd23-fb88-4a77-8490-5891d3e4653a}
inline const IID IID_IBackgroundCopyFile = {
    0x01b7bd23, 0xfb88, 0x4a77, { 0x84, 0x90, 0x58, 0x91, 0xd3, 0xe4, 0x65, 0x3a }
};

// IID_IBackgroundCopyError: {19c613a0-7918-4fab-9681-2e29da48dc0a}
inline const IID IID_IBackgroundCopyError = {
    0x19c613a0, 0x7918, 0x4fab, { 0x96, 0x81, 0x2e, 0x29, 0xda, 0x48, 0xdc, 0x0a }
};

// IID_IEnumBackgroundCopyJobs: {1af4f612-3b71-466f-8743-bbea64b60b77}
inline const IID IID_IEnumBackgroundCopyJobs = {
    0x1af4f612, 0x3b71, 0x466f, { 0x87, 0x43, 0xbb, 0xea, 0x64, 0xb6, 0x0b, 0x77 }
};

// IID_IEnumBackgroundCopyFiles: {ca51e165-2c36-424c-ac97-d2e825a07c13}
inline const IID IID_IEnumBackgroundCopyFiles = {
    0xca51e165, 0x2c36, 0x424c, { 0xac, 0x97, 0xd2, 0xe8, 0x25, 0xa0, 0x7c, 0x13 }
};

// ============================================================================
// 2. Constants, Enums & Error HRESULTs
// ============================================================================

enum BG_JOB_TYPE {
    BG_JOB_TYPE_DOWNLOAD     = 0,
    BG_JOB_TYPE_UPLOAD       = 1,
    BG_JOB_TYPE_UPLOAD_REPLY = 2
};

enum BG_JOB_PRIORITY {
    BG_JOB_PRIORITY_FOREGROUND = 0,
    BG_JOB_PRIORITY_HIGH       = 1,
    BG_JOB_PRIORITY_NORMAL     = 2,
    BG_JOB_PRIORITY_LOW        = 3
};

enum BG_JOB_STATE {
    BG_JOB_STATE_QUEUED          = 0,
    BG_JOB_STATE_CONNECTING      = 1,
    BG_JOB_STATE_TRANSFERRING    = 2,
    BG_JOB_STATE_SUSPENDED       = 3,
    BG_JOB_STATE_ERROR           = 4,
    BG_JOB_STATE_TRANSIENT_ERROR = 5,
    BG_JOB_STATE_TRANSFERRED     = 6,
    BG_JOB_STATE_ACKNOWLEDGED    = 7,
    BG_JOB_STATE_CANCELLED       = 8
};

enum BG_ERROR_CONTEXT {
    BG_ERROR_CONTEXT_NONE                    = 0,
    BG_ERROR_CONTEXT_UNKNOWN                 = 1,
    BG_ERROR_CONTEXT_GENERAL_QUEUE_MANAGER   = 2,
    BG_ERROR_CONTEXT_QUEUE_MANAGER_NOTIFICATION = 3,
    BG_ERROR_CONTEXT_LOCAL_FILE              = 4,
    BG_ERROR_CONTEXT_REMOTE_FILE             = 5,
    BG_ERROR_CONTEXT_GENERAL_TRANSPORT       = 6,
    BG_ERROR_CONTEXT_REMOTE_APPLICATION      = 7
};

// BITS Error HRESULTs
inline constexpr HRESULT BG_E_NOT_FOUND            = static_cast<HRESULT>(0x80200001);
inline constexpr HRESULT BG_E_INVALID_STATE        = static_cast<HRESULT>(0x80200002);
inline constexpr HRESULT BG_E_EMPTY                = static_cast<HRESULT>(0x80200003);
inline constexpr HRESULT BG_E_FILE_NOT_AVAILABLE   = static_cast<HRESULT>(0x80200004);
inline constexpr HRESULT BG_E_PROTOCOL_NOT_AVAILABLE = static_cast<HRESULT>(0x80200005);
inline constexpr HRESULT BG_E_DESTINATION_LOCKED   = static_cast<HRESULT>(0x80200006);
inline constexpr HRESULT BG_E_VOLUME_CHANGED       = static_cast<HRESULT>(0x80200007);
inline constexpr HRESULT BG_E_ERROR_INFORMATION_UNAVAILABLE = static_cast<HRESULT>(0x80200008);
inline constexpr HRESULT BG_S_UNACKNOWLEDGED       = static_cast<HRESULT>(0x00200001);

// Progress and Stats Structs
struct BG_FILE_INFO {
    const wchar_t* RemoteFile;
    const wchar_t* LocalFile;
};

struct BG_FILE_PROGRESS {
    uint64_t BytesTotal{0};
    uint64_t BytesTransferred{0};
    win32::BOOL Completed{0};
};

struct BG_JOB_PROGRESS {
    uint64_t BytesTotal{0};
    uint64_t BytesTransferred{0};
    uint32_t FilesTotal{0};
    uint32_t FilesTransferred{0};
};

struct BG_JOB_TIMES {
    win32::FILETIME CreationTime{0, 0};
    win32::FILETIME ModificationTime{0, 0};
    win32::FILETIME TransferCompletionTime{0, 0};
};

// ============================================================================
// 3. COM Interface Declarations
// ============================================================================

class IBackgroundCopyFile;
class IBackgroundCopyJob;
class IBackgroundCopyError;
class IEnumBackgroundCopyFiles;
class IEnumBackgroundCopyJobs;

class IBackgroundCopyFile : public IUnknown {
public:
    virtual HRESULT __stdcall GetRemoteName(LPWSTR* pVal) = 0;
    virtual HRESULT __stdcall GetLocalName(LPWSTR* pVal) = 0;
    virtual HRESULT __stdcall GetProgress(BG_FILE_PROGRESS* pVal) = 0;
};

class IBackgroundCopyError : public IUnknown {
public:
    virtual HRESULT __stdcall GetError(BG_ERROR_CONTEXT* pContext, HRESULT* pCode) = 0;
    virtual HRESULT __stdcall GetFile(IBackgroundCopyFile** ppFile) = 0;
    virtual HRESULT __stdcall GetErrorDescription(uint32_t LanguageId, LPWSTR* pErrorDescription) = 0;
    virtual HRESULT __stdcall GetErrorContextDescription(uint32_t LanguageId, LPWSTR* pContextDescription) = 0;
    virtual HRESULT __stdcall GetProtocolErrorDescription(uint32_t LanguageId, LPWSTR* pProtocolDescription) = 0;
};

class IEnumBackgroundCopyFiles : public IUnknown {
public:
    virtual HRESULT __stdcall Next(uint32_t celt, IBackgroundCopyFile** rgelt, uint32_t* pceltFetched) = 0;
    virtual HRESULT __stdcall Skip(uint32_t celt) = 0;
    virtual HRESULT __stdcall Reset() = 0;
    virtual HRESULT __stdcall Clone(IEnumBackgroundCopyFiles** ppenum) = 0;
    virtual HRESULT __stdcall GetCount(uint32_t* puCount) = 0;
};

class IEnumBackgroundCopyJobs : public IUnknown {
public:
    virtual HRESULT __stdcall Next(uint32_t celt, IBackgroundCopyJob** rgelt, uint32_t* pceltFetched) = 0;
    virtual HRESULT __stdcall Skip(uint32_t celt) = 0;
    virtual HRESULT __stdcall Reset() = 0;
    virtual HRESULT __stdcall Clone(IEnumBackgroundCopyJobs** ppenum) = 0;
    virtual HRESULT __stdcall GetCount(uint32_t* puCount) = 0;
};

class IBackgroundCopyJob : public IUnknown {
public:
    virtual HRESULT __stdcall AddFile(LPCWSTR RemoteUrl, LPCWSTR LocalName) = 0;
    virtual HRESULT __stdcall AddFileSet(uint32_t cFileCount, BG_FILE_INFO* pFileSet) = 0;
    virtual HRESULT __stdcall EnumFiles(IEnumBackgroundCopyFiles** ppEnum) = 0;
    virtual HRESULT __stdcall Suspend() = 0;
    virtual HRESULT __stdcall Resume() = 0;
    virtual HRESULT __stdcall Cancel() = 0;
    virtual HRESULT __stdcall Complete() = 0;
    virtual HRESULT __stdcall GetId(GUID* pVal) = 0;
    virtual HRESULT __stdcall GetType(BG_JOB_TYPE* pVal) = 0;
    virtual HRESULT __stdcall GetName(LPWSTR* pVal) = 0;
    virtual HRESULT __stdcall GetDescription(LPWSTR* pVal) = 0;
    virtual HRESULT __stdcall SetDescription(LPCWSTR Val) = 0;
    virtual HRESULT __stdcall GetPriority(BG_JOB_PRIORITY* pVal) = 0;
    virtual HRESULT __stdcall SetPriority(BG_JOB_PRIORITY Val) = 0;
    virtual HRESULT __stdcall GetState(BG_JOB_STATE* pVal) = 0;
    virtual HRESULT __stdcall GetProgress(BG_JOB_PROGRESS* pVal) = 0;
    virtual HRESULT __stdcall GetTimes(BG_JOB_TIMES* pVal) = 0;
    virtual HRESULT __stdcall GetError(IBackgroundCopyError** ppError) = 0;
    virtual HRESULT __stdcall SetNotifyFlags(uint32_t Val) = 0;
    virtual HRESULT __stdcall GetNotifyFlags(uint32_t* pVal) = 0;
    virtual HRESULT __stdcall SetNotifyInterface(IUnknown* Val) = 0;
    virtual HRESULT __stdcall GetNotifyInterface(IUnknown** pVal) = 0;
    virtual HRESULT __stdcall SetMinimumRetryDelay(uint32_t Seconds) = 0;
    virtual HRESULT __stdcall GetMinimumRetryDelay(uint32_t* Seconds) = 0;
    virtual HRESULT __stdcall SetNoProgressTimeout(uint32_t Seconds) = 0;
    virtual HRESULT __stdcall GetNoProgressTimeout(uint32_t* Seconds) = 0;
    virtual HRESULT __stdcall TakeOwnership() = 0;
};

class IBackgroundCopyJob2 : public IBackgroundCopyJob {
public:
    virtual HRESULT __stdcall SetNotifyCmdLine(LPCWSTR Program, LPCWSTR Parameters) = 0;
    virtual HRESULT __stdcall GetNotifyCmdLine(LPWSTR* pProgram, LPWSTR* pParameters) = 0;
    virtual HRESULT __stdcall GetReplyProgress(void* pProgress) = 0;
    virtual HRESULT __stdcall GetReplyData(uint8_t** ppBuffer, uint64_t* pLength) = 0;
    virtual HRESULT __stdcall SetReplyFileName(LPCWSTR OutputFileName) = 0;
    virtual HRESULT __stdcall GetReplyFileName(LPWSTR* pOutputFileName) = 0;
    virtual HRESULT __stdcall SetCredentials(void* Credentials) = 0;
    virtual HRESULT __stdcall RemoveCredentials(uint32_t Target, uint32_t Scheme) = 0;
};

class IBackgroundCopyManager : public IUnknown {
public:
    virtual HRESULT __stdcall CreateJob(LPCWSTR DisplayName, BG_JOB_TYPE Type, GUID* pJobId, IBackgroundCopyJob** ppJob) = 0;
    virtual HRESULT __stdcall GetJob(REFGUID jobId, IBackgroundCopyJob** ppJob) = 0;
    virtual HRESULT __stdcall EnumJobs(uint32_t dwFlags, IEnumBackgroundCopyJobs** ppEnum) = 0;
    virtual HRESULT __stdcall GetErrorDescription(HRESULT hrError, uint32_t LanguageId, LPWSTR* pErrorDescription) = 0;
};

// ============================================================================
// 4. Concrete Subsystem Implementation
// ============================================================================

// Forward declaration
class BackgroundCopyManager;

// ----------------------------------------------------------------------------
// BackgroundCopyFile
// ----------------------------------------------------------------------------
class BackgroundCopyFile : public IBackgroundCopyFile {
private:
    std::atomic<uint32_t> m_refCount{1};
public:
    std::wstring m_remoteUrl;
    std::wstring m_localName;
    uint64_t m_bytesTotal{0};
    uint64_t m_bytesTransferred{0};
    bool m_completed{false};

    BackgroundCopyFile(std::wstring_view remote, std::wstring_view local, uint64_t total = 1048576)
        : m_remoteUrl(remote), m_localName(local), m_bytesTotal(total) {}

    virtual ~BackgroundCopyFile() = default;

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IBackgroundCopyFile) {
            *ppv = static_cast<IBackgroundCopyFile*>(this);
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

    virtual HRESULT __stdcall GetRemoteName(LPWSTR* pVal) override {
        if (!pVal) return E_POINTER;
        size_t len = (m_remoteUrl.size() + 1) * sizeof(wchar_t);
        *pVal = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len));
        if (!*pVal) return E_OUTOFMEMORY;
        memcpy(*pVal, m_remoteUrl.c_str(), len);
        return S_OK;
    }

    virtual HRESULT __stdcall GetLocalName(LPWSTR* pVal) override {
        if (!pVal) return E_POINTER;
        size_t len = (m_localName.size() + 1) * sizeof(wchar_t);
        *pVal = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len));
        if (!*pVal) return E_OUTOFMEMORY;
        memcpy(*pVal, m_localName.c_str(), len);
        return S_OK;
    }

    virtual HRESULT __stdcall GetProgress(BG_FILE_PROGRESS* pVal) override {
        if (!pVal) return E_POINTER;
        pVal->BytesTotal = m_bytesTotal;
        pVal->BytesTransferred = m_bytesTransferred;
        pVal->Completed = m_completed ? 1 : 0;
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// EnumBackgroundCopyFiles
// ----------------------------------------------------------------------------
class EnumBackgroundCopyFiles : public IEnumBackgroundCopyFiles {
private:
    std::atomic<uint32_t> m_refCount{1};
    std::vector<BackgroundCopyFile*> m_files;
    size_t m_index{0};
    std::mutex m_mutex;

public:
    EnumBackgroundCopyFiles(std::vector<BackgroundCopyFile*> files) : m_files(std::move(files)) {
        for (auto* f : m_files) {
            if (f) f->AddRef();
        }
    }

    virtual ~EnumBackgroundCopyFiles() {
        for (auto* f : m_files) {
            if (f) f->Release();
        }
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IEnumBackgroundCopyFiles) {
            *ppv = static_cast<IEnumBackgroundCopyFiles*>(this);
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

    virtual HRESULT __stdcall Next(uint32_t celt, IBackgroundCopyFile** rgelt, uint32_t* pceltFetched) override {
        if (!rgelt) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        uint32_t fetched = 0;
        while (fetched < celt && m_index < m_files.size()) {
            rgelt[fetched] = m_files[m_index++];
            rgelt[fetched]->AddRef();
            fetched++;
        }

        if (pceltFetched) *pceltFetched = fetched;
        return (fetched == celt) ? S_OK : S_FALSE;
    }

    virtual HRESULT __stdcall Skip(uint32_t celt) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_index += celt;
        if (m_index > m_files.size()) {
            m_index = m_files.size();
            return S_FALSE;
        }
        return S_OK;
    }

    virtual HRESULT __stdcall Reset() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_index = 0;
        return S_OK;
    }

    virtual HRESULT __stdcall Clone(IEnumBackgroundCopyFiles** ppenum) override {
        if (!ppenum) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto* cloned = new EnumBackgroundCopyFiles(m_files);
        cloned->m_index = m_index;
        *ppenum = cloned;
        return S_OK;
    }

    virtual HRESULT __stdcall GetCount(uint32_t* puCount) override {
        if (!puCount) return E_POINTER;
        *puCount = static_cast<uint32_t>(m_files.size());
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// BackgroundCopyError
// ----------------------------------------------------------------------------
class BackgroundCopyError : public IBackgroundCopyError {
private:
    std::atomic<uint32_t> m_refCount{1};
public:
    BG_ERROR_CONTEXT m_context{BG_ERROR_CONTEXT_REMOTE_FILE};
    HRESULT m_code{BG_E_FILE_NOT_AVAILABLE};
    BackgroundCopyFile* m_file{nullptr};
    std::wstring m_description{L"The requested file is not available on the remote server."};

    BackgroundCopyError(BG_ERROR_CONTEXT ctx, HRESULT code, BackgroundCopyFile* file = nullptr)
        : m_context(ctx), m_code(code), m_file(file) {
        if (m_file) m_file->AddRef();
    }

    virtual ~BackgroundCopyError() {
        if (m_file) m_file->Release();
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IBackgroundCopyError) {
            *ppv = static_cast<IBackgroundCopyError*>(this);
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

    virtual HRESULT __stdcall GetError(BG_ERROR_CONTEXT* pContext, HRESULT* pCode) override {
        if (!pContext || !pCode) return E_POINTER;
        *pContext = m_context;
        *pCode = m_code;
        return S_OK;
    }

    virtual HRESULT __stdcall GetFile(IBackgroundCopyFile** ppFile) override {
        if (!ppFile) return E_POINTER;
        *ppFile = m_file;
        if (m_file) m_file->AddRef();
        return S_OK;
    }

    virtual HRESULT __stdcall GetErrorDescription(uint32_t /*LanguageId*/, LPWSTR* pErrorDescription) override {
        if (!pErrorDescription) return E_POINTER;
        size_t len = (m_description.size() + 1) * sizeof(wchar_t);
        *pErrorDescription = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len));
        if (!*pErrorDescription) return E_OUTOFMEMORY;
        memcpy(*pErrorDescription, m_description.c_str(), len);
        return S_OK;
    }

    virtual HRESULT __stdcall GetErrorContextDescription(uint32_t /*LanguageId*/, LPWSTR* pContextDescription) override {
        if (!pContextDescription) return E_POINTER;
        std::wstring ctx = L"Error context: remote server or connection endpoint.";
        size_t len = (ctx.size() + 1) * sizeof(wchar_t);
        *pContextDescription = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len));
        if (!*pContextDescription) return E_OUTOFMEMORY;
        memcpy(*pContextDescription, ctx.c_str(), len);
        return S_OK;
    }

    virtual HRESULT __stdcall GetProtocolErrorDescription(uint32_t /*LanguageId*/, LPWSTR* pProtocolDescription) override {
        if (!pProtocolDescription) return E_POINTER;
        std::wstring proto = L"HTTP/1.1 404 Not Found";
        size_t len = (proto.size() + 1) * sizeof(wchar_t);
        *pProtocolDescription = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len));
        if (!*pProtocolDescription) return E_OUTOFMEMORY;
        memcpy(*pProtocolDescription, proto.c_str(), len);
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// BackgroundCopyJob (implements IBackgroundCopyJob2)
// ----------------------------------------------------------------------------
class BackgroundCopyJob : public IBackgroundCopyJob2 {
private:
    std::atomic<uint32_t> m_refCount{1};
public:
    GUID m_id{};
    std::wstring m_displayName;
    std::wstring m_description;
    BG_JOB_TYPE m_type{BG_JOB_TYPE_DOWNLOAD};
    BG_JOB_PRIORITY m_priority{BG_JOB_PRIORITY_NORMAL};
    BG_JOB_STATE m_state{BG_JOB_STATE_SUSPENDED};
    std::vector<BackgroundCopyFile*> m_files;
    BackgroundCopyError* m_lastError{nullptr};
    std::wstring m_notifyProgram;
    std::wstring m_notifyParameters;
    uint32_t m_notifyFlags{0};
    uint32_t m_minRetryDelay{600};
    uint32_t m_noProgressTimeout{86400};
    BG_JOB_TIMES m_times{};
    std::mutex m_jobMutex;

    BackgroundCopyJob(LPCWSTR displayName, BG_JOB_TYPE type, const GUID& id)
        : m_id(id), m_displayName(displayName ? displayName : L""), m_type(type)
    {
        uint64_t nowTicks = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() * 10 + 116444736000000000ULL;
        m_times.CreationTime.dwLowDateTime = static_cast<uint32_t>(nowTicks & 0xFFFFFFFF);
        m_times.CreationTime.dwHighDateTime = static_cast<uint32_t>(nowTicks >> 32);
        m_times.ModificationTime = m_times.CreationTime;
    }

    virtual ~BackgroundCopyJob() {
        for (auto* f : m_files) {
            if (f) f->Release();
        }
        if (m_lastError) m_lastError->Release();
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IBackgroundCopyJob || riid == IID_IBackgroundCopyJob2) {
            *ppv = static_cast<IBackgroundCopyJob2*>(this);
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

    virtual HRESULT __stdcall AddFile(LPCWSTR RemoteUrl, LPCWSTR LocalName) override {
        if (!RemoteUrl || !LocalName) return E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_jobMutex);
        if (m_state == BG_JOB_STATE_CANCELLED || m_state == BG_JOB_STATE_ACKNOWLEDGED) {
            return BG_E_INVALID_STATE;
        }

        // Check if file size can be approximated or simulated (default 1 MB per file)
        uint64_t fileSize = 1048576;
        auto* file = new BackgroundCopyFile(RemoteUrl, LocalName, fileSize);
        m_files.push_back(file);

        // Update modification time
        uint64_t nowTicks = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() * 10 + 116444736000000000ULL;
        m_times.ModificationTime.dwLowDateTime = static_cast<uint32_t>(nowTicks & 0xFFFFFFFF);
        m_times.ModificationTime.dwHighDateTime = static_cast<uint32_t>(nowTicks >> 32);

        return S_OK;
    }

    virtual HRESULT __stdcall AddFileSet(uint32_t cFileCount, BG_FILE_INFO* pFileSet) override {
        if (cFileCount > 0 && !pFileSet) return E_POINTER;
        for (uint32_t i = 0; i < cFileCount; ++i) {
            HRESULT hr = AddFile(pFileSet[i].RemoteFile, pFileSet[i].LocalFile);
            if (hr != S_OK) return hr;
        }
        return S_OK;
    }

    virtual HRESULT __stdcall EnumFiles(IEnumBackgroundCopyFiles** ppEnum) override {
        if (!ppEnum) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_jobMutex);
        *ppEnum = new EnumBackgroundCopyFiles(m_files);
        return S_OK;
    }

    virtual HRESULT __stdcall Suspend() override {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        if (m_state == BG_JOB_STATE_CANCELLED || m_state == BG_JOB_STATE_ACKNOWLEDGED) {
            return BG_E_INVALID_STATE;
        }
        m_state = BG_JOB_STATE_SUSPENDED;
        return S_OK;
    }

    virtual HRESULT __stdcall Resume() override {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        if (m_state == BG_JOB_STATE_CANCELLED || m_state == BG_JOB_STATE_ACKNOWLEDGED) {
            return BG_E_INVALID_STATE;
        }
        if (m_files.empty()) {
            return BG_E_EMPTY;
        }

        // Transfer files: transition to TRANSFERRING then TRANSFERRED
        m_state = BG_JOB_STATE_TRANSFERRING;
        for (auto* f : m_files) {
            f->m_bytesTransferred = f->m_bytesTotal;
            f->m_completed = true;
        }
        m_state = BG_JOB_STATE_TRANSFERRED;

        uint64_t nowTicks = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() * 10 + 116444736000000000ULL;
        m_times.TransferCompletionTime.dwLowDateTime = static_cast<uint32_t>(nowTicks & 0xFFFFFFFF);
        m_times.TransferCompletionTime.dwHighDateTime = static_cast<uint32_t>(nowTicks >> 32);

        return S_OK;
    }

    virtual HRESULT __stdcall Cancel() override {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        if (m_state == BG_JOB_STATE_CANCELLED || m_state == BG_JOB_STATE_ACKNOWLEDGED) {
            return BG_E_INVALID_STATE;
        }
        m_state = BG_JOB_STATE_CANCELLED;
        return S_OK;
    }

    virtual HRESULT __stdcall Complete() override {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        if (m_state != BG_JOB_STATE_TRANSFERRED) {
            return BG_E_INVALID_STATE;
        }
        m_state = BG_JOB_STATE_ACKNOWLEDGED;
        return S_OK;
    }

    virtual HRESULT __stdcall GetId(GUID* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = m_id;
        return S_OK;
    }

    virtual HRESULT __stdcall GetType(BG_JOB_TYPE* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = m_type;
        return S_OK;
    }

    virtual HRESULT __stdcall GetName(LPWSTR* pVal) override {
        if (!pVal) return E_POINTER;
        size_t len = (m_displayName.size() + 1) * sizeof(wchar_t);
        *pVal = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len));
        if (!*pVal) return E_OUTOFMEMORY;
        memcpy(*pVal, m_displayName.c_str(), len);
        return S_OK;
    }

    virtual HRESULT __stdcall GetDescription(LPWSTR* pVal) override {
        if (!pVal) return E_POINTER;
        size_t len = (m_description.size() + 1) * sizeof(wchar_t);
        *pVal = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len));
        if (!*pVal) return E_OUTOFMEMORY;
        memcpy(*pVal, m_description.c_str(), len);
        return S_OK;
    }

    virtual HRESULT __stdcall SetDescription(LPCWSTR Val) override {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        m_description = Val ? Val : L"";
        return S_OK;
    }

    virtual HRESULT __stdcall GetPriority(BG_JOB_PRIORITY* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = m_priority;
        return S_OK;
    }

    virtual HRESULT __stdcall SetPriority(BG_JOB_PRIORITY Val) override {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        m_priority = Val;
        return S_OK;
    }

    virtual HRESULT __stdcall GetState(BG_JOB_STATE* pVal) override {
        if (!pVal) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_jobMutex);
        *pVal = m_state;
        return S_OK;
    }

    virtual HRESULT __stdcall GetProgress(BG_JOB_PROGRESS* pVal) override {
        if (!pVal) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_jobMutex);
        pVal->BytesTotal = 0;
        pVal->BytesTransferred = 0;
        pVal->FilesTotal = static_cast<uint32_t>(m_files.size());
        pVal->FilesTransferred = 0;

        for (const auto* f : m_files) {
            pVal->BytesTotal += f->m_bytesTotal;
            pVal->BytesTransferred += f->m_bytesTransferred;
            if (f->m_completed) pVal->FilesTransferred++;
        }
        return S_OK;
    }

    virtual HRESULT __stdcall GetTimes(BG_JOB_TIMES* pVal) override {
        if (!pVal) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_jobMutex);
        *pVal = m_times;
        return S_OK;
    }

    virtual HRESULT __stdcall GetError(IBackgroundCopyError** ppError) override {
        if (!ppError) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_jobMutex);
        if (!m_lastError) {
            *ppError = nullptr;
            return BG_E_ERROR_INFORMATION_UNAVAILABLE;
        }
        *ppError = m_lastError;
        m_lastError->AddRef();
        return S_OK;
    }

    virtual HRESULT __stdcall SetNotifyFlags(uint32_t Val) override {
        m_notifyFlags = Val;
        return S_OK;
    }

    virtual HRESULT __stdcall GetNotifyFlags(uint32_t* pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = m_notifyFlags;
        return S_OK;
    }

    virtual HRESULT __stdcall SetNotifyInterface(IUnknown* /*Val*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall GetNotifyInterface(IUnknown** pVal) override {
        if (!pVal) return E_POINTER;
        *pVal = nullptr;
        return S_OK;
    }

    virtual HRESULT __stdcall SetMinimumRetryDelay(uint32_t Seconds) override {
        m_minRetryDelay = Seconds;
        return S_OK;
    }

    virtual HRESULT __stdcall GetMinimumRetryDelay(uint32_t* Seconds) override {
        if (!Seconds) return E_POINTER;
        *Seconds = m_minRetryDelay;
        return S_OK;
    }

    virtual HRESULT __stdcall SetNoProgressTimeout(uint32_t Seconds) override {
        m_noProgressTimeout = Seconds;
        return S_OK;
    }

    virtual HRESULT __stdcall GetNoProgressTimeout(uint32_t* Seconds) override {
        if (!Seconds) return E_POINTER;
        *Seconds = m_noProgressTimeout;
        return S_OK;
    }

    virtual HRESULT __stdcall TakeOwnership() override {
        return S_OK;
    }

    // IBackgroundCopyJob2
    virtual HRESULT __stdcall SetNotifyCmdLine(LPCWSTR Program, LPCWSTR Parameters) override {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        m_notifyProgram = Program ? Program : L"";
        m_notifyParameters = Parameters ? Parameters : L"";
        return S_OK;
    }

    virtual HRESULT __stdcall GetNotifyCmdLine(LPWSTR* pProgram, LPWSTR* pParameters) override {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        if (pProgram) {
            size_t len = (m_notifyProgram.size() + 1) * sizeof(wchar_t);
            *pProgram = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len));
            if (*pProgram) memcpy(*pProgram, m_notifyProgram.c_str(), len);
        }
        if (pParameters) {
            size_t len = (m_notifyParameters.size() + 1) * sizeof(wchar_t);
            *pParameters = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len));
            if (*pParameters) memcpy(*pParameters, m_notifyParameters.c_str(), len);
        }
        return S_OK;
    }

    virtual HRESULT __stdcall GetReplyProgress(void* /*pProgress*/) override {
        return E_NOTIMPL;
    }

    virtual HRESULT __stdcall GetReplyData(uint8_t** ppBuffer, uint64_t* pLength) override {
        if (ppBuffer) *ppBuffer = nullptr;
        if (pLength) *pLength = 0;
        return S_OK;
    }

    virtual HRESULT __stdcall SetReplyFileName(LPCWSTR /*OutputFileName*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall GetReplyFileName(LPWSTR* pOutputFileName) override {
        if (pOutputFileName) *pOutputFileName = nullptr;
        return S_OK;
    }

    virtual HRESULT __stdcall SetCredentials(void* /*Credentials*/) override {
        return S_OK;
    }

    virtual HRESULT __stdcall RemoveCredentials(uint32_t /*Target*/, uint32_t /*Scheme*/) override {
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// EnumBackgroundCopyJobs
// ----------------------------------------------------------------------------
class EnumBackgroundCopyJobs : public IEnumBackgroundCopyJobs {
private:
    std::atomic<uint32_t> m_refCount{1};
    std::vector<BackgroundCopyJob*> m_jobs;
    size_t m_index{0};
    std::mutex m_mutex;

public:
    EnumBackgroundCopyJobs(std::vector<BackgroundCopyJob*> jobs) : m_jobs(std::move(jobs)) {
        for (auto* j : m_jobs) {
            if (j) j->AddRef();
        }
    }

    virtual ~EnumBackgroundCopyJobs() {
        for (auto* j : m_jobs) {
            if (j) j->Release();
        }
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IEnumBackgroundCopyJobs) {
            *ppv = static_cast<IEnumBackgroundCopyJobs*>(this);
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

    virtual HRESULT __stdcall Next(uint32_t celt, IBackgroundCopyJob** rgelt, uint32_t* pceltFetched) override {
        if (!rgelt) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        uint32_t fetched = 0;
        while (fetched < celt && m_index < m_jobs.size()) {
            rgelt[fetched] = m_jobs[m_index++];
            rgelt[fetched]->AddRef();
            fetched++;
        }

        if (pceltFetched) *pceltFetched = fetched;
        return (fetched == celt) ? S_OK : S_FALSE;
    }

    virtual HRESULT __stdcall Skip(uint32_t celt) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_index += celt;
        if (m_index > m_jobs.size()) {
            m_index = m_jobs.size();
            return S_FALSE;
        }
        return S_OK;
    }

    virtual HRESULT __stdcall Reset() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_index = 0;
        return S_OK;
    }

    virtual HRESULT __stdcall Clone(IEnumBackgroundCopyJobs** ppenum) override {
        if (!ppenum) return E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto* cloned = new EnumBackgroundCopyJobs(m_jobs);
        cloned->m_index = m_index;
        *ppenum = cloned;
        return S_OK;
    }

    virtual HRESULT __stdcall GetCount(uint32_t* puCount) override {
        if (!puCount) return E_POINTER;
        *puCount = static_cast<uint32_t>(m_jobs.size());
        return S_OK;
    }
};

// ----------------------------------------------------------------------------
// BackgroundCopyManager
// ----------------------------------------------------------------------------
class BackgroundCopyManager : public IBackgroundCopyManager {
private:
    std::atomic<uint32_t> m_refCount{1};
public:
    std::map<GUID, BackgroundCopyJob*, GUIDLess> m_jobs;
    std::mutex m_mgrMutex;

    BackgroundCopyManager() {
        PreseedSystemJobs();
    }

    virtual ~BackgroundCopyManager() {
        for (auto& [_, j] : m_jobs) {
            if (j) j->Release();
        }
    }

    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IBackgroundCopyManager) {
            *ppv = static_cast<IBackgroundCopyManager*>(this);
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

    virtual HRESULT __stdcall CreateJob(LPCWSTR DisplayName, BG_JOB_TYPE Type, GUID* pJobId, IBackgroundCopyJob** ppJob) override {
        if (!DisplayName || !pJobId || !ppJob) return E_INVALIDARG;

        GUID newId{};
        ole32::CoCreateGuid(&newId);
        *pJobId = newId;

        auto* job = new BackgroundCopyJob(DisplayName, Type, newId);
        {
            std::lock_guard<std::mutex> lock(m_mgrMutex);
            job->AddRef(); // For m_jobs container
            m_jobs[newId] = job;
        }

        *ppJob = job;
        return S_OK;
    }

    virtual HRESULT __stdcall GetJob(REFGUID jobId, IBackgroundCopyJob** ppJob) override {
        if (!ppJob) return E_POINTER;
        *ppJob = nullptr;

        std::lock_guard<std::mutex> lock(m_mgrMutex);
        auto it = m_jobs.find(jobId);
        if (it == m_jobs.end()) {
            return BG_E_NOT_FOUND;
        }

        *ppJob = it->second;
        it->second->AddRef();
        return S_OK;
    }

    virtual HRESULT __stdcall EnumJobs(uint32_t /*dwFlags*/, IEnumBackgroundCopyJobs** ppEnum) override {
        if (!ppEnum) return E_POINTER;
        std::vector<BackgroundCopyJob*> jobList;
        {
            std::lock_guard<std::mutex> lock(m_mgrMutex);
            for (const auto& [_, j] : m_jobs) {
                jobList.push_back(j);
            }
        }
        *ppEnum = new EnumBackgroundCopyJobs(std::move(jobList));
        return S_OK;
    }

    virtual HRESULT __stdcall GetErrorDescription(HRESULT hrError, uint32_t /*LanguageId*/, LPWSTR* pErrorDescription) override {
        if (!pErrorDescription) return E_POINTER;
        std::wstring msg;
        switch (hrError) {
            case BG_E_NOT_FOUND: msg = L"The requested job was not found in the BITS queue."; break;
            case BG_E_INVALID_STATE: msg = L"The requested action is not valid for the current job state."; break;
            case BG_E_EMPTY: msg = L"The job contains no files to transfer."; break;
            case BG_E_FILE_NOT_AVAILABLE: msg = L"The requested file is not available on the remote server."; break;
            default: msg = L"An unknown BITS transfer error occurred."; break;
        }
        size_t len = (msg.size() + 1) * sizeof(wchar_t);
        *pErrorDescription = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(len));
        if (!*pErrorDescription) return E_OUTOFMEMORY;
        memcpy(*pErrorDescription, msg.c_str(), len);
        return S_OK;
    }

    void PreseedSystemJobs() {
        // 1. Windows Defender Signature Update Job
        GUID defGuid = { 0xa1b2c3d4, 0x0001, 0x0001, { 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
        auto* defJob = new BackgroundCopyJob(L"Windows Defender Signature Update", BG_JOB_TYPE_DOWNLOAD, defGuid);
        defJob->m_description = L"Automatic download of antimalware definition updates";
        defJob->m_priority = BG_JOB_PRIORITY_HIGH;
        defJob->AddFile(L"https://definitions.micant.internal/mpam-fe.exe", L"C:\\Windows\\Temp\\mpam-fe.exe");
        defJob->m_state = BG_JOB_STATE_QUEUED;
        m_jobs[defGuid] = defJob;

        // 2. MicaNT Kernel Security Update KB5034441
        GUID secGuid = { 0xa1b2c3d4, 0x0002, 0x0002, { 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } };
        auto* secJob = new BackgroundCopyJob(L"MicaNT Kernel Security Update KB5034441", BG_JOB_TYPE_DOWNLOAD, secGuid);
        secJob->m_description = L"Cumulative security update for MicaNT Ring 0 Executive";
        secJob->m_priority = BG_JOB_PRIORITY_NORMAL;
        secJob->AddFile(L"https://update.micant.internal/kb5034441.msu", L"C:\\Windows\\SoftwareDistribution\\kb5034441.msu");
        secJob->m_state = BG_JOB_STATE_SUSPENDED;
        m_jobs[secGuid] = secJob;
    }
};

// ----------------------------------------------------------------------------
// BackgroundCopyManagerClassFactory
// ----------------------------------------------------------------------------
class BackgroundCopyManagerClassFactory : public IClassFactory {
private:
    std::atomic<uint32_t> m_refCount{1};
public:
    virtual ~BackgroundCopyManagerClassFactory() = default;

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

    virtual HRESULT __stdcall CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override {
        if (pUnkOuter != nullptr) return CLASS_E_NOAGGREGATION;
        if (!ppv) return E_POINTER;

        static BackgroundCopyManager s_globalManager;
        return s_globalManager.QueryInterface(riid, ppv);
    }

    virtual HRESULT __stdcall LockServer(win32::BOOL /*fLock*/) override {
        return S_OK;
    }
};

// ============================================================================
// 5. Dynamic Loader & COM Exports (qmgr.dll)
// ============================================================================

extern "C" inline HRESULT __stdcall BITS_DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (rclsid == CLSID_BackgroundCopyManager) {
        static BackgroundCopyManagerClassFactory factory;
        return factory.QueryInterface(riid, ppv);
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

extern "C" inline HRESULT __stdcall BITS_DllCanUnloadNow() {
    return S_FALSE;
}

extern "C" inline HRESULT __stdcall BITS_DllRegisterServer() {
    return S_OK;
}

extern "C" inline HRESULT __stdcall BITS_DllUnregisterServer() {
    return S_OK;
}

inline void InitializeBITSSubsystemExports() {
    static std::atomic<bool> s_initialized{false};
    if (s_initialized.exchange(true)) return;

    auto& ldr = ldr::DynamicLoader::get();

    // Register qmgr.dll (BITS Queue Manager)
    ldr.registerExport("qmgr.dll", "DllGetClassObject", reinterpret_cast<void*>(&BITS_DllGetClassObject));
    ldr.registerExport("qmgr.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&BITS_DllCanUnloadNow));
    ldr.registerExport("qmgr.dll", "DllRegisterServer", reinterpret_cast<void*>(&BITS_DllRegisterServer));
    ldr.registerExport("qmgr.dll", "DllUnregisterServer", reinterpret_cast<void*>(&BITS_DllUnregisterServer));

    // Register bitsprx.dll (Proxy/Stub)
    ldr.registerExport("bitsprx.dll", "DllGetClassObject", reinterpret_cast<void*>(&BITS_DllGetClassObject));
    ldr.registerExport("bitsprx.dll", "DllCanUnloadNow", reinterpret_cast<void*>(&BITS_DllCanUnloadNow));
    ldr.registerExport("bitsprx.dll", "DllRegisterServer", reinterpret_cast<void*>(&BITS_DllRegisterServer));
    ldr.registerExport("bitsprx.dll", "DllUnregisterServer", reinterpret_cast<void*>(&BITS_DllUnregisterServer));

    // Register COM Class Factory
    auto* factory = new BackgroundCopyManagerClassFactory();
    uint32_t regCookie = 0;
    ole32::CoRegisterClassObject(CLSID_BackgroundCopyManager, factory, 1 /* CLSCTX_INPROC_SERVER */, 0, &regCookie);
}

} // namespace micant::bits
