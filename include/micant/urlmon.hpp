// ============================================================================
// MicaNT: Windows URL Moniker Subsystem (urlmon.dll)
//
// Modern Clean-Room Implementation in pure ISO C++23.
// Provides high-level URL Moniker, MIME analysis, and content transfer APIs:
// - URLDownloadToFileA/W with IBindStatusCallback progress notifications
// - URLDownloadToCacheFileA/W with WinINet Temporary Internet Files backing
// - URLOpenStreamA/W & URLOpenBlockingStreamA/W returning ole32::IStream
// - FindMimeFromData binary magic sniffer (PNG, JPEG, GIF, BMP, PDF, ZIP, MZ, HTML, JSON, XML)
// - CreateURLMoniker / CreateURLMonikerEx COM Moniker architecture
// - Full integration with MicaNT VFS and WinINet HTTP transfer pipeline
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <fstream>
#include <cstring>
#include <cwchar>

#include "ntdef.hpp"
#include "kernel32.hpp"
#include "ole32.hpp"
#include "wininet.hpp"
#include "fs.hpp"

namespace micant::urlmon {

#ifndef MAX_PATH
inline constexpr uint32_t MAX_PATH = 260;
#endif

// ============================================================================
// 1. COM Interfaces & GUIDs
// ============================================================================

// IBindStatusCallback GUID: {79eac9c1-baf9-11ce-8c82-00aa004ba90b}
inline const micant::GUID IID_IBindStatusCallback = {
    0x79eac9c1, 0xbaf9, 0x11ce, { 0x8c, 0x82, 0x00, 0xaa, 0x00, 0x4b, 0xa9, 0x0b }
};

// IAsyncMoniker GUID: {79eac9d0-baf9-11ce-8c82-00aa004ba90b}
inline const micant::GUID IID_IAsyncMoniker = {
    0x79eac9d0, 0xbaf9, 0x11ce, { 0x8c, 0x82, 0x00, 0xaa, 0x00, 0x4b, 0xa9, 0x0b }
};

// IMoniker GUID: {0000000f-0000-0000-C000-000000000046}
inline const micant::GUID IID_IMoniker = {
    0x0000000f, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }
};

// Progress Status Codes
inline constexpr uint32_t BINDSTATUS_FINDINGRESOURCE            = 1;
inline constexpr uint32_t BINDSTATUS_CONNECTING                 = 2;
inline constexpr uint32_t BINDSTATUS_REDIRECTING                = 3;
inline constexpr uint32_t BINDSTATUS_BEGINDOWNLOADDATA          = 4;
inline constexpr uint32_t BINDSTATUS_DOWNLOADINGDATA            = 5;
inline constexpr uint32_t BINDSTATUS_ENDDOWNLOADDATA            = 6;
inline constexpr uint32_t BINDSTATUS_BEGINDOWNLOADCOMPONENTS    = 7;
inline constexpr uint32_t BINDSTATUS_INSTALLINGCOMPONENTS       = 8;
inline constexpr uint32_t BINDSTATUS_ENDDOWNLOADCOMPONENTS      = 9;
inline constexpr uint32_t BINDSTATUS_USINGCACHEDCOPY            = 10;
inline constexpr uint32_t BINDSTATUS_SENDINGREQUEST             = 11;
inline constexpr uint32_t BINDSTATUS_CLASSINSTALLOCATION        = 12;
inline constexpr uint32_t BINDSTATUS_MIMETEXT                   = 13;
inline constexpr uint32_t BINDSTATUS_CACHEFILENAMEAVAILABLE     = 14;

// Bind Flags
inline constexpr uint32_t BINDF_ASYNCHRONOUS                    = 0x00000001;
inline constexpr uint32_t BINDF_ASYNCSTORAGE                    = 0x00000002;
inline constexpr uint32_t BINDF_NOPROGRESSCONTAINER             = 0x00000004;
inline constexpr uint32_t BINDF_OFFLINEOPERATION                = 0x00000008;
inline constexpr uint32_t BINDF_GETNEWESTVERSION                = 0x00000010;
inline constexpr uint32_t BINDF_NOWRITECACHE                    = 0x00000020;
inline constexpr uint32_t BINDF_NEEDFILE                        = 0x00000040;
inline constexpr uint32_t BINDF_PULLDATA                        = 0x00000080;
inline constexpr uint32_t BINDF_IGNORESECURITYPROBLEM           = 0x00000100;
inline constexpr uint32_t BINDF_RESYNCHRONIZE                   = 0x00000200;
inline constexpr uint32_t BINDF_HYPERLINK                       = 0x00000400;
inline constexpr uint32_t BINDF_NO_UI                           = 0x00000800;

// URLMon HRESULT error codes
inline constexpr ole32::HRESULT INET_E_CANNOT_CONNECT          = static_cast<ole32::HRESULT>(0x800C0004);
inline constexpr ole32::HRESULT INET_E_RESOURCE_NOT_FOUND       = static_cast<ole32::HRESULT>(0x800C0005);
inline constexpr ole32::HRESULT INET_E_OBJECT_NOT_FOUND         = static_cast<ole32::HRESULT>(0x800C0006);
inline constexpr ole32::HRESULT INET_E_DATA_NOT_AVAILABLE       = static_cast<ole32::HRESULT>(0x800C0007);
inline constexpr ole32::HRESULT INET_E_DOWNLOAD_FAILURE         = static_cast<ole32::HRESULT>(0x800C0008);
inline constexpr ole32::HRESULT INET_E_AUTHENTICATION_REQUIRED  = static_cast<ole32::HRESULT>(0x800C0009);
inline constexpr ole32::HRESULT INET_E_UNKNOWN_PROTOCOL         = static_cast<ole32::HRESULT>(0x800C000D);
inline constexpr ole32::HRESULT INET_E_SECURITY_PROBLEM         = static_cast<ole32::HRESULT>(0x800C000E);
inline constexpr ole32::HRESULT INET_E_CANNOT_LOAD_DATA         = static_cast<ole32::HRESULT>(0x800C000F);

class IBindStatusCallback : public ole32::IUnknown {
public:
    virtual ole32::HRESULT OnStartBinding(uint32_t dwReserved, void* pib) = 0;
    virtual ole32::HRESULT GetPriority(int32_t* pnPriority) = 0;
    virtual ole32::HRESULT OnLowResource(uint32_t reserved) = 0;
    virtual ole32::HRESULT OnProgress(uint32_t ulProgress, uint32_t ulProgressMax, uint32_t ulStatusCode, const wchar_t* szStatusText) = 0;
    virtual ole32::HRESULT OnStopBinding(ole32::HRESULT hresult, const wchar_t* szError) = 0;
    virtual ole32::HRESULT GetBindInfo(uint32_t* grfBINDF, void* pbindinfo) = 0;
    virtual ole32::HRESULT OnDataAvailable(uint32_t grfBSCF, uint32_t dwSize, void* pformatetc, void* pstgmed) = 0;
    virtual ole32::HRESULT OnObjectAvailable(ole32::REFIID riid, ole32::IUnknown* punk) = 0;
};

class IMoniker : public ole32::IUnknown {
public:
    virtual ole32::HRESULT BindToObject(void* pbc, IMoniker* pmkToLeft, ole32::REFIID riidResult, void** ppvResult) = 0;
    virtual ole32::HRESULT BindToStorage(void* pbc, IMoniker* pmkToLeft, ole32::REFIID riid, void** ppvObj) = 0;
    virtual ole32::HRESULT Reduce(void* pbc, uint32_t dwReduceHowFar, IMoniker** ppmkToLeft, IMoniker** ppmkReduced) = 0;
    virtual ole32::HRESULT ComposeWith(IMoniker* pmkRight, win32::BOOL fOnlyIfNotGeneric, IMoniker** ppmkComposite) = 0;
    virtual ole32::HRESULT Enum(win32::BOOL fForward, void** ppenumMoniker) = 0;
    virtual ole32::HRESULT IsEqual(IMoniker* pmkOtherMoniker) = 0;
    virtual ole32::HRESULT Hash(uint32_t* pdwHash) = 0;
    virtual ole32::HRESULT IsRunning(void* pbc, IMoniker* pmkToLeft, IMoniker* pmkNewlyRunning) = 0;
    virtual ole32::HRESULT GetTimeOfLastChange(void* pbc, IMoniker* pmkToLeft, void* pFileTime) = 0;
    virtual ole32::HRESULT Inverse(IMoniker** ppmk) = 0;
    virtual ole32::HRESULT CommonPrefixWith(IMoniker* pmkOther, IMoniker** ppmkPrefix) = 0;
    virtual ole32::HRESULT RelativePathTo(IMoniker* pmkOther, IMoniker** ppmkRelPath) = 0;
    virtual ole32::HRESULT GetDisplayName(void* pbc, IMoniker* pmkToLeft, wchar_t** ppszDisplayName) = 0;
    virtual ole32::HRESULT ParseDisplayName(void* pbc, IMoniker* pmkToLeft, wchar_t* pszDisplayName, uint32_t* pchEaten, IMoniker** ppmkOut) = 0;
    virtual ole32::HRESULT IsSystemMoniker(uint32_t* pdwMksys) = 0;
};

// ============================================================================
// 2. URL Moniker Implementation
// ============================================================================

class UrlMoniker : public IMoniker {
private:
    std::atomic<uint32_t> m_refCount{1};
    std::wstring m_url;

public:
    explicit UrlMoniker(std::wstring_view url) : m_url(url) {}

    virtual ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppvObject) override {
        if (!ppvObject) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IMoniker) {
            *ppvObject = static_cast<IMoniker*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppvObject = nullptr;
        return ole32::E_NOINTERFACE;
    }

    virtual uint32_t AddRef() override {
        return m_refCount.fetch_add(1) + 1;
    }

    virtual uint32_t Release() override {
        uint32_t count = m_refCount.fetch_sub(1) - 1;
        if (count == 0) delete this;
        return count;
    }

    virtual ole32::HRESULT BindToObject(void*, IMoniker*, ole32::REFIID, void**) override { return ole32::E_NOTIMPL; }
    virtual ole32::HRESULT BindToStorage(void*, IMoniker*, ole32::REFIID, void**) override { return ole32::E_NOTIMPL; }
    virtual ole32::HRESULT Reduce(void*, uint32_t, IMoniker**, IMoniker**) override { return ole32::S_OK; }
    virtual ole32::HRESULT ComposeWith(IMoniker*, win32::BOOL, IMoniker**) override { return ole32::E_NOTIMPL; }
    virtual ole32::HRESULT Enum(win32::BOOL, void**) override { return ole32::E_NOTIMPL; }

    virtual ole32::HRESULT IsEqual(IMoniker* pmkOther) override {
        if (!pmkOther) return ole32::S_FALSE;
        wchar_t* name = nullptr;
        if (SUCCEEDED(pmkOther->GetDisplayName(nullptr, nullptr, &name)) && name) {
            bool eq = (m_url == name);
            ole32::CoTaskMemFree(name);
            return eq ? ole32::S_OK : ole32::S_FALSE;
        }
        return ole32::S_FALSE;
    }

    virtual ole32::HRESULT Hash(uint32_t* pdwHash) override {
        if (!pdwHash) return ole32::E_POINTER;
        uint32_t h = 2166136261u;
        for (wchar_t c : m_url) {
            h ^= static_cast<uint32_t>(c);
            h *= 16777619u;
        }
        *pdwHash = h;
        return ole32::S_OK;
    }

    virtual ole32::HRESULT IsRunning(void*, IMoniker*, IMoniker*) override { return ole32::S_FALSE; }
    virtual ole32::HRESULT GetTimeOfLastChange(void*, IMoniker*, void*) override { return ole32::E_NOTIMPL; }
    virtual ole32::HRESULT Inverse(IMoniker**) override { return ole32::E_NOTIMPL; }
    virtual ole32::HRESULT CommonPrefixWith(IMoniker*, IMoniker**) override { return ole32::E_NOTIMPL; }
    virtual ole32::HRESULT RelativePathTo(IMoniker*, IMoniker**) override { return ole32::E_NOTIMPL; }

    virtual ole32::HRESULT GetDisplayName(void*, IMoniker*, wchar_t** ppszDisplayName) override {
        if (!ppszDisplayName) return ole32::E_POINTER;
        size_t bytes = (m_url.size() + 1) * sizeof(wchar_t);
        auto* buf = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(bytes));
        if (!buf) return ole32::E_OUTOFMEMORY;
        std::memcpy(buf, m_url.data(), bytes);
        *ppszDisplayName = buf;
        return ole32::S_OK;
    }

    virtual ole32::HRESULT ParseDisplayName(void*, IMoniker*, wchar_t*, uint32_t*, IMoniker**) override { return ole32::E_NOTIMPL; }
    virtual ole32::HRESULT IsSystemMoniker(uint32_t* pdwMksys) override {
        if (pdwMksys) *pdwMksys = 6; // MKSYS_URLMONIKER
        return ole32::S_OK;
    }
};

// ============================================================================
// 3. MIME Sniffer (FindMimeFromData)
// ============================================================================

inline ole32::HRESULT __stdcall FindMimeFromData(
    ole32::IUnknown* /*pBC*/,
    const wchar_t*  pwzUrl,
    const void*     pBuffer,
    uint32_t        cbSize,
    const wchar_t*  /*pwzMimeProposed*/,
    uint32_t        /*dwMimeFlags*/,
    wchar_t**       ppwzMimeOut,
    uint32_t        /*dwReserved*/
) {
    if (!ppwzMimeOut) return ole32::E_INVALIDARG;
    *ppwzMimeOut = nullptr;

    std::wstring detected = L"application/octet-stream";

    if (pBuffer && cbSize >= 2) {
        const auto* b = static_cast<const uint8_t*>(pBuffer);
        if (cbSize >= 8 && b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G' &&
            b[4] == 0x0D && b[5] == 0x0A && b[6] == 0x1A && b[7] == 0x0A) {
            detected = L"image/png";
        } else if (cbSize >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) {
            detected = L"image/jpeg";
        } else if (cbSize >= 6 && std::memcmp(b, "GIF87a", 6) == 0) {
            detected = L"image/gif";
        } else if (cbSize >= 6 && std::memcmp(b, "GIF89a", 6) == 0) {
            detected = L"image/gif";
        } else if (b[0] == 'B' && b[1] == 'M') {
            detected = L"image/bmp";
        } else if (cbSize >= 4 && std::memcmp(b, "%PDF", 4) == 0) {
            detected = L"application/pdf";
        } else if (cbSize >= 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 0x03 && b[3] == 0x04) {
            detected = L"application/zip";
        } else if (b[0] == 'M' && b[1] == 'Z') {
            detected = L"application/x-msdownload";
        } else if (cbSize >= 12 && (std::memcmp(b, "RIFF", 4) == 0) && (std::memcmp(b + 8, "WAVE", 4) == 0)) {
            detected = L"audio/wav";
        } else {
            // Check text-based formats
            std::string_view text(reinterpret_cast<const char*>(b), std::min(cbSize, 256u));
            std::string lowerText = wininet::toLower(text);
            if (lowerText.find("<!doctype html") != std::string::npos || lowerText.find("<html") != std::string::npos) {
                detected = L"text/html";
            } else if (lowerText.find("<?xml") != std::string::npos) {
                detected = L"text/xml";
            } else if (lowerText.starts_with('{') || lowerText.starts_with('[')) {
                detected = L"application/json";
            } else {
                bool isAsciiText = true;
                for (size_t i = 0; i < std::min(cbSize, 128u); ++i) {
                    if (b[i] < 0x09 || (b[i] > 0x0D && b[i] < 0x20)) {
                        isAsciiText = false;
                        break;
                    }
                }
                if (isAsciiText) detected = L"text/plain";
            }
        }
    } else if (pwzUrl) {
        // Fallback to URL extension
        std::wstring wUrl(pwzUrl);
        size_t dot = wUrl.find_last_of(L'.');
        if (dot != std::wstring::npos) {
            std::wstring ext = wUrl.substr(dot + 1);
            for (auto& c : ext) c = static_cast<wchar_t>(std::tolower(static_cast<int>(c)));
            if (ext == L"png") detected = L"image/png";
            else if (ext == L"jpg" || ext == L"jpeg") detected = L"image/jpeg";
            else if (ext == L"gif") detected = L"image/gif";
            else if (ext == L"bmp") detected = L"image/bmp";
            else if (ext == L"html" || ext == L"htm") detected = L"text/html";
            else if (ext == L"xml") detected = L"text/xml";
            else if (ext == L"json") detected = L"application/json";
            else if (ext == L"txt") detected = L"text/plain";
            else if (ext == L"pdf") detected = L"application/pdf";
            else if (ext == L"zip") detected = L"application/zip";
            else if (ext == L"exe") detected = L"application/x-msdownload";
        }
    }

    size_t charCount = detected.size() + 1;
    auto* outBuf = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(charCount * sizeof(wchar_t)));
    if (!outBuf) return ole32::E_OUTOFMEMORY;
    std::memcpy(outBuf, detected.data(), detected.size() * sizeof(wchar_t));
    outBuf[detected.size()] = L'\0';
    *ppwzMimeOut = outBuf;
    return ole32::S_OK;
}

// ============================================================================
// 4. URL Moniker API Functions (urlmon.dll)
// ============================================================================

inline ole32::HRESULT __stdcall URLDownloadToFileW(
    ole32::IUnknown*     /*pCaller*/,
    const wchar_t*       szURL,
    const wchar_t*       szFileName,
    uint32_t             /*dwReserved*/,
    IBindStatusCallback* lpfnCB
) {
    if (!szURL || !szFileName) return ole32::E_INVALIDARG;

    if (lpfnCB) {
        lpfnCB->OnStartBinding(0, nullptr);
        lpfnCB->OnProgress(0, 0, BINDSTATUS_FINDINGRESOURCE, szURL);
    }

    wininet::ParsedUrl parsed;
    std::string narrowUrl = wininet::toNarrow(szURL);
    if (!wininet::ParseUrlComponents(narrowUrl, parsed)) {
        if (lpfnCB) lpfnCB->OnStopBinding(INET_E_DOWNLOAD_FAILURE, L"Invalid URL format");
        return INET_E_DOWNLOAD_FAILURE;
    }

    if (lpfnCB) {
        std::wstring wHost = wininet::toWide(parsed.host);
        lpfnCB->OnProgress(0, 0, BINDSTATUS_CONNECTING, wHost.c_str());
    }

    wininet::HINTERNET hSession = wininet::InternetOpenW(L"MicaNT URLMon", wininet::INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (!hSession) {
        if (lpfnCB) lpfnCB->OnStopBinding(INET_E_CANNOT_CONNECT, L"Failed to open Internet session");
        return INET_E_CANNOT_CONNECT;
    }

    std::wstring wHost = wininet::toWide(parsed.host);
    std::wstring wPath = wininet::toWide(parsed.path + parsed.extra);

    wininet::HINTERNET hConn = wininet::InternetConnectW(
        hSession, wHost.c_str(), parsed.port, nullptr, nullptr,
        wininet::INTERNET_SERVICE_HTTP, 0, 0
    );
    if (!hConn) {
        wininet::InternetCloseHandle(hSession);
        if (lpfnCB) lpfnCB->OnStopBinding(INET_E_CANNOT_CONNECT, L"Failed to connect to host");
        return INET_E_CANNOT_CONNECT;
    }

    uint32_t flags = (parsed.schemeType == wininet::INTERNET_SCHEME_HTTPS) ? wininet::INTERNET_FLAG_SECURE : 0;
    wininet::HINTERNET hReq = wininet::HttpOpenRequestW(hConn, L"GET", wPath.c_str(), L"HTTP/1.1", nullptr, nullptr, flags, 0);
    if (!hReq) {
        wininet::InternetCloseHandle(hConn);
        wininet::InternetCloseHandle(hSession);
        if (lpfnCB) lpfnCB->OnStopBinding(INET_E_DOWNLOAD_FAILURE, L"Failed to open HTTP request");
        return INET_E_DOWNLOAD_FAILURE;
    }

    if (lpfnCB) {
        lpfnCB->OnProgress(0, 0, BINDSTATUS_SENDINGREQUEST, szURL);
    }

    if (!wininet::HttpSendRequestW(hReq, nullptr, 0, nullptr, 0)) {
        wininet::InternetCloseHandle(hReq);
        wininet::InternetCloseHandle(hConn);
        wininet::InternetCloseHandle(hSession);
        if (lpfnCB) lpfnCB->OnStopBinding(INET_E_DOWNLOAD_FAILURE, L"HttpSendRequest failed");
        return INET_E_DOWNLOAD_FAILURE;
    }

    uint32_t totalSize = 0;
    uint32_t queryLen = sizeof(uint32_t);
    wininet::HttpQueryInfoW(hReq, wininet::HTTP_QUERY_CONTENT_LENGTH | wininet::HTTP_QUERY_FLAG_NUMBER, &totalSize, &queryLen, nullptr);

    if (lpfnCB) {
        lpfnCB->OnProgress(0, totalSize, BINDSTATUS_BEGINDOWNLOADDATA, szURL);
    }

    // Read full payload
    std::vector<uint8_t> payload;
    uint8_t chunk[4096];
    uint32_t bytesRead = 0;
    uint32_t received = 0;

    while (wininet::InternetReadFile(hReq, chunk, sizeof(chunk), &bytesRead) && bytesRead > 0) {
        payload.insert(payload.end(), chunk, chunk + bytesRead);
        received += bytesRead;
        if (lpfnCB) {
            lpfnCB->OnProgress(received, totalSize, BINDSTATUS_DOWNLOADINGDATA, szURL);
        }
    }

    wininet::InternetCloseHandle(hReq);
    wininet::InternetCloseHandle(hConn);
    wininet::InternetCloseHandle(hSession);

    // Save to local target file (via VFS or host file write)
    std::wstring wDest(szFileName);
    std::shared_ptr<fs::FileObject> fileObj;
    NtStatus st = fs::VirtualFileSystem::get().createOrOpenFile(
        wDest,
        fs::FILE_GENERIC_WRITE,
        fs::FILE_OVERWRITE_IF,
        fileObj
    );
    if (NT_SUCCESS(st) && fileObj) {
        uint32_t written = 0;
        fs::VirtualFileSystem::get().writeFile(
            fileObj.get(),
            payload.data(),
            static_cast<uint32_t>(payload.size()),
            nullptr,
            written
        );
        fileObj->writeData(0, std::span<const uint8_t>(payload.data(), payload.size()));
        fs::VirtualFileSystem::get().closeFile(fileObj.get());
    } else {
        std::string nDest = wininet::toNarrow(szFileName);
        std::ofstream ofs(nDest, std::ios::binary);
        if (ofs.is_open()) {
            ofs.write(reinterpret_cast<const char*>(payload.data()), payload.size());
            ofs.close();
        }
    }

    if (lpfnCB) {
        lpfnCB->OnProgress(received, totalSize ? totalSize : received, BINDSTATUS_ENDDOWNLOADDATA, szURL);
        lpfnCB->OnStopBinding(ole32::S_OK, L"Download complete");
    }

    return ole32::S_OK;
}

inline ole32::HRESULT __stdcall URLDownloadToFileA(
    ole32::IUnknown*     pCaller,
    const char*          szURL,
    const char*          szFileName,
    uint32_t             dwReserved,
    IBindStatusCallback* lpfnCB
) {
    if (!szURL || !szFileName) return ole32::E_INVALIDARG;
    std::wstring wUrl = wininet::toWide(szURL);
    std::wstring wDest = wininet::toWide(szFileName);
    return URLDownloadToFileW(pCaller, wUrl.c_str(), wDest.c_str(), dwReserved, lpfnCB);
}

inline ole32::HRESULT __stdcall URLDownloadToCacheFileW(
    ole32::IUnknown*     pCaller,
    const wchar_t*       szURL,
    wchar_t*             szFileName,
    uint32_t             dwFileNameLength,
    uint32_t             dwReserved,
    IBindStatusCallback* lpfnCB
) {
    if (!szURL || !szFileName || dwFileNameLength < MAX_PATH) return ole32::E_INVALIDARG;

    wchar_t cachePath[MAX_PATH]{};
    if (!wininet::CreateUrlCacheEntryW(szURL, 1024, L"tmp", cachePath, 0)) {
        return INET_E_DOWNLOAD_FAILURE;
    }

    ole32::HRESULT hr = URLDownloadToFileW(pCaller, szURL, cachePath, dwReserved, lpfnCB);
    if (SUCCEEDED(hr)) {
        wininet::CommitUrlCacheEntryW(szURL, cachePath, 0, 0, 0, nullptr, 0, nullptr, nullptr);
        std::wcscpy(szFileName, cachePath);
    }
    return hr;
}

inline ole32::HRESULT __stdcall URLDownloadToCacheFileA(
    ole32::IUnknown*     pCaller,
    const char*          szURL,
    char*                szFileName,
    uint32_t             dwFileNameLength,
    uint32_t             dwReserved,
    IBindStatusCallback* lpfnCB
) {
    if (!szURL || !szFileName || dwFileNameLength < MAX_PATH) return ole32::E_INVALIDARG;
    wchar_t wCachePath[MAX_PATH]{};
    std::wstring wUrl = wininet::toWide(szURL);
    ole32::HRESULT hr = URLDownloadToCacheFileW(pCaller, wUrl.c_str(), wCachePath, MAX_PATH, dwReserved, lpfnCB);
    if (SUCCEEDED(hr)) {
        std::string nPath = wininet::toNarrow(wCachePath);
        std::strcpy(szFileName, nPath.c_str());
    }
    return hr;
}

inline ole32::HRESULT __stdcall URLOpenStreamW(
    ole32::IUnknown*     /*pCaller*/,
    const wchar_t*       szURL,
    uint32_t             /*dwReserved*/,
    IBindStatusCallback* lpfnCB
) {
    if (!szURL) return ole32::E_INVALIDARG;

    wchar_t tempFile[MAX_PATH]{};
    wininet::CreateUrlCacheEntryW(szURL, 1024, L"tmp", tempFile, 0);

    ole32::HRESULT hr = URLDownloadToFileW(nullptr, szURL, tempFile, 0, lpfnCB);
    return hr;
}

inline ole32::HRESULT __stdcall URLOpenStreamA(
    ole32::IUnknown*     pCaller,
    const char*          szURL,
    uint32_t             dwReserved,
    IBindStatusCallback* lpfnCB
) {
    if (!szURL) return ole32::E_INVALIDARG;
    std::wstring wUrl = wininet::toWide(szURL);
    return URLOpenStreamW(pCaller, wUrl.c_str(), dwReserved, lpfnCB);
}

inline ole32::HRESULT __stdcall URLOpenBlockingStreamW(
    ole32::IUnknown*     pCaller,
    const wchar_t*       szURL,
    ole32::IStream**     ppStream,
    uint32_t             dwReserved,
    IBindStatusCallback* lpfnCB
) {
    if (!szURL || !ppStream) return ole32::E_INVALIDARG;
    *ppStream = nullptr;

    wchar_t tempFile[MAX_PATH]{};
    wininet::CreateUrlCacheEntryW(szURL, 1024, L"tmp", tempFile, 0);

    ole32::HRESULT hr = URLDownloadToFileW(pCaller, szURL, tempFile, dwReserved, lpfnCB);
    if (FAILED(hr)) return hr;

    // Read cached file into memory stream
    std::shared_ptr<fs::FileObject> fileObj;
    NtStatus st = fs::VirtualFileSystem::get().createOrOpenFile(
        tempFile, fs::FILE_GENERIC_READ, fs::FILE_OPEN, fileObj
    );
    if (NT_SUCCESS(st) && fileObj) {
        const auto& data = fileObj->getData();
        *ppStream = new ole32::MemoryStream(data.data(), data.size());
        return ole32::S_OK;
    }

    std::string nPath = wininet::toNarrow(tempFile);
    std::ifstream ifs(nPath, std::ios::binary);
    if (ifs.is_open()) {
        std::vector<uint8_t> buf((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        *ppStream = new ole32::MemoryStream(buf.data(), buf.size());
        return ole32::S_OK;
    }

    return INET_E_CANNOT_LOAD_DATA;
}

inline ole32::HRESULT __stdcall URLOpenBlockingStreamA(
    ole32::IUnknown*     pCaller,
    const char*          szURL,
    ole32::IStream**     ppStream,
    uint32_t             dwReserved,
    IBindStatusCallback* lpfnCB
) {
    if (!szURL || !ppStream) return ole32::E_INVALIDARG;
    std::wstring wUrl = wininet::toWide(szURL);
    return URLOpenBlockingStreamW(pCaller, wUrl.c_str(), ppStream, dwReserved, lpfnCB);
}

inline ole32::HRESULT __stdcall CreateURLMoniker(
    IMoniker*       /*pmkContext*/,
    const wchar_t*  szURL,
    IMoniker**      ppmk
) {
    if (!szURL || !ppmk) return ole32::E_INVALIDARG;
    *ppmk = new UrlMoniker(szURL);
    return ole32::S_OK;
}

inline ole32::HRESULT __stdcall CreateURLMonikerEx(
    IMoniker*       pmkContext,
    const wchar_t*  szURL,
    IMoniker**      ppmk,
    uint32_t        /*dwFlags*/
) {
    return CreateURLMoniker(pmkContext, szURL, ppmk);
}

inline win32::BOOL __stdcall IsValidURL(
    ole32::IUnknown* /*pBC*/,
    const wchar_t*   szURL,
    uint32_t         /*dwFlags*/
) {
    if (!szURL) return 0;
    wininet::ParsedUrl p;
    return wininet::ParseUrlComponents(wininet::toNarrow(szURL), p) ? 1 : 0;
}

// ============================================================================
// 5. Subsystem Export Registration
// ============================================================================

inline void InitializeUrlMonSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    ldr.registerExport("urlmon.dll", "URLDownloadToFileA", reinterpret_cast<void*>(URLDownloadToFileA));
    ldr.registerExport("urlmon.dll", "URLDownloadToFileW", reinterpret_cast<void*>(URLDownloadToFileW));
    ldr.registerExport("urlmon.dll", "URLDownloadToCacheFileA", reinterpret_cast<void*>(URLDownloadToCacheFileA));
    ldr.registerExport("urlmon.dll", "URLDownloadToCacheFileW", reinterpret_cast<void*>(URLDownloadToCacheFileW));
    ldr.registerExport("urlmon.dll", "URLOpenStreamA", reinterpret_cast<void*>(URLOpenStreamA));
    ldr.registerExport("urlmon.dll", "URLOpenStreamW", reinterpret_cast<void*>(URLOpenStreamW));
    ldr.registerExport("urlmon.dll", "URLOpenBlockingStreamA", reinterpret_cast<void*>(URLOpenBlockingStreamA));
    ldr.registerExport("urlmon.dll", "URLOpenBlockingStreamW", reinterpret_cast<void*>(URLOpenBlockingStreamW));
    ldr.registerExport("urlmon.dll", "FindMimeFromData", reinterpret_cast<void*>(FindMimeFromData));
    ldr.registerExport("urlmon.dll", "CreateURLMoniker", reinterpret_cast<void*>(CreateURLMoniker));
    ldr.registerExport("urlmon.dll", "CreateURLMonikerEx", reinterpret_cast<void*>(CreateURLMonikerEx));
    ldr.registerExport("urlmon.dll", "IsValidURL", reinterpret_cast<void*>(IsValidURL));
}

} // namespace micant::urlmon
