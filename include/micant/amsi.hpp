// ============================================================================
// MicaNT: Antimalware Scan Interface (AMSI) Subsystem
// (include/micant/amsi.hpp)
//
// Sovereign Subsystem: SentinelScan
//
// Strict Clean-Room Implementation based on:
//   - Microsoft Antimalware Scan Interface (AMSI) Specification (amsi.dll / amsi.h)
//   - Win32 AMSI Management API C ABI
//   - Component Object Model (COM) Interfaces (IAmsiStream, IAmsiProvider)
//   - Google LLC v. Oracle America, Inc. & Sega v. Accolade interoperability doctrine
//
// Subsystem Overview:
//   amsi.hpp provides the clean-room Antimalware Scan Interface subsystem
//   (amsi.dll) for MicaNT, codenamed "SentinelScan". It establishes a standard
//   Win32 in-memory buffer and script inspection bridge between calling
//   applications (command shells, PowerShell runtimes, scripting hosts, and
//   browsers) and installed security engines (AegisDefender / SentinelCenter).
//
// Features:
//   - Native Win32 AMSI C ABI (amsi.dll):
//       * AmsiInitialize
//       * AmsiUninitialize
//       * AmsiOpenSession
//       * AmsiCloseSession
//       * AmsiScanBuffer
//       * AmsiScanString
//       * AmsiNotifyOperation
//       * AmsiResultIsMalware
//       * AmsiResultIsBlockedByAdmin
//       * AmsiResultIsValid
//   - Standard AMSI Result Codes (AMSI_RESULT):
//       * AMSI_RESULT_CLEAN (0)
//       * AMSI_RESULT_NOT_DETECTED (1)
//       * AMSI_RESULT_BLOCKED_BY_ADMIN_START (16384 / 0x4000)
//       * AMSI_RESULT_BLOCKED_BY_ADMIN_END (20479 / 0x4FFF)
//       * AMSI_RESULT_DETECTED (32768 / 0x8000)
//   - Standard AMSI Attribute Identifiers (AMSI_ATTRIBUTE):
//       * AMSI_ATTRIBUTE_APP_NAME (0)
//       * AMSI_ATTRIBUTE_CONTENT_NAME (1)
//       * AMSI_ATTRIBUTE_CONTENT_SIZE (2)
//       * AMSI_ATTRIBUTE_CONTENT_ADDRESS (3)
//       * AMSI_ATTRIBUTE_SESSION (4)
//       * AMSI_ATTRIBUTE_REDIRECT_CHAIN_SIZE (5)
//       * AMSI_ATTRIBUTE_REDIRECT_CHAIN_ADDRESS (6)
//       * AMSI_ATTRIBUTE_ALL_SIZE (7)
//       * AMSI_ATTRIBUTE_ALL_ADDRESS (8)
//       * AMSI_ATTRIBUTE_QUIET (9)
//   - Full COM Interfaces:
//       * IAmsiStream ({3E47F2E5-81D4-4AE7-897E-585A823CE1F8})
//       * IAmsiProvider ({B2CABFE3-F61D-4729-A586-64623C669004})
//   - Built-in SovereignSentinelScanProvider:
//       * 100% offline, zero-telemetry local heuristic and signature engine.
//       * EICAR standard test detection.
//       * Shellcode & NOP sled detection (16+ consecutive 0x90s, common stack pivot patterns).
//       * Obfuscated PowerShell download cradle detection (IEX + WebClient / DownloadString).
//       * Credential theft token matching (mimikatz, sekurlsa, logonpasswords).
//       * AMSI bypass tampering pattern detection (amsiInitFailed, AmsiUtils).
//       * In-memory process injection heuristic (VirtualAlloc + WriteProcessMemory + CreateRemoteThread).
//       * Shannon block entropy evaluation for high-randomness script droppers.
//       * Administrative block policy enforcement.
//   - DynamicLoader export registration into "amsi.dll".
//   - VersionDatabase registration ("amsi.dll", "10.0.26100.1").
//
// Core Dynamic Module:
//   - amsi.dll
//
// Trademark & Nominative Fair Use Notice:
//   Microsoft, Windows, and AMSI are trademarks or registered trademarks of
//   Microsoft Corp. MicaNT SentinelScan is an independent, clean-room sovereign
//   implementation engineered from first principles solely for binary
//   interoperability (*Google LLC v. Oracle America, Inc.*).
//   No proprietary Microsoft source code or binaries are used or contained herein.
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "kernel32.hpp"
#include "ldr.hpp"
#include "version.hpp"
#include "ole32.hpp"

#include <cstdint>
#include <cstddef>
#include <cmath>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <functional>
#include <optional>
#include <chrono>

namespace micant::amsi {

// ============================================================================
// 1. Standard Win32 Types, Enums & Constants (amsi.h)
// ============================================================================

using DWORD     = uint32_t;
using PDWORD    = uint32_t*;
using HANDLE    = void*;
using PHANDLE   = void**;
using HRESULT   = int32_t;
using BOOL      = int32_t;
using LONG      = int32_t;
using ULONG     = uint32_t;
using ULONGLONG = uint64_t;
using LPVOID    = void*;
using PVOID     = void*;
using LPCWSTR   = const wchar_t*;
using LPWSTR    = wchar_t*;
using GUID      = micant::GUID;
using BSTR      = wchar_t*;

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
inline constexpr HRESULT E_NOTIMPL                = static_cast<HRESULT>(0x80004001);
inline constexpr HRESULT HRESULT_FROM_WIN32_NOT_FOUND          = static_cast<HRESULT>(0x80070490); // ERROR_NOT_FOUND
inline constexpr HRESULT HRESULT_FROM_WIN32_INVALID_HANDLE     = static_cast<HRESULT>(0x80070006); // ERROR_INVALID_HANDLE
inline constexpr HRESULT HRESULT_FROM_WIN32_INSUFFICIENT_BUFFER = static_cast<HRESULT>(0x8007007A); // ERROR_INSUFFICIENT_BUFFER
inline constexpr HRESULT HRESULT_FROM_WIN32_VIRUS_INFECTED     = static_cast<HRESULT>(0x800700DF); // ERROR_VIRUS_INFECTED

// Handle Types
struct HAMSICONTEXT__ { int unused; };
typedef struct HAMSICONTEXT__* HAMSICONTEXT;

struct HAMSISESSION__ { int unused; };
typedef struct HAMSISESSION__* HAMSISESSION;

// AMSI_RESULT
enum AMSI_RESULT : DWORD {
    AMSI_RESULT_CLEAN                   = 0,
    AMSI_RESULT_NOT_DETECTED            = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START  = 16384, // 0x4000
    AMSI_RESULT_BLOCKED_BY_ADMIN_END    = 20479, // 0x4FFF
    AMSI_RESULT_DETECTED                = 32768  // 0x8000
};

// AMSI_ATTRIBUTE
enum AMSI_ATTRIBUTE : DWORD {
    AMSI_ATTRIBUTE_APP_NAME             = 0,
    AMSI_ATTRIBUTE_CONTENT_NAME         = 1,
    AMSI_ATTRIBUTE_CONTENT_SIZE         = 2,
    AMSI_ATTRIBUTE_CONTENT_ADDRESS      = 3,
    AMSI_ATTRIBUTE_SESSION              = 4,
    AMSI_ATTRIBUTE_REDIRECT_CHAIN_SIZE  = 5,
    AMSI_ATTRIBUTE_REDIRECT_CHAIN_ADDRESS = 6,
    AMSI_ATTRIBUTE_ALL_SIZE             = 7,
    AMSI_ATTRIBUTE_ALL_ADDRESS          = 8,
    AMSI_ATTRIBUTE_QUIET                = 9
};

// AMSI_UAC_REQUEST_TYPE
enum AMSI_UAC_REQUEST_TYPE : DWORD {
    AMSI_UAC_REQUEST_TYPE_EXE          = 0,
    AMSI_UAC_REQUEST_TYPE_COM          = 1,
    AMSI_UAC_REQUEST_TYPE_MSI          = 2,
    AMSI_UAC_REQUEST_TYPE_AX           = 3,
    AMSI_UAC_REQUEST_TYPE_PACKAGED_APP = 4,
    AMSI_UAC_REQUEST_TYPE_MAX          = 5
};

// AMSI_UAC_TRUST_STATE
enum AMSI_UAC_TRUST_STATE : DWORD {
    AMSI_UAC_TRUST_STATE_TRUSTED       = 0,
    AMSI_UAC_TRUST_STATE_NOT_TRUSTED   = 1,
    AMSI_UAC_TRUST_STATE_BLOCKED       = 2,
    AMSI_UAC_TRUST_STATE_MAX           = 3
};

// Predicate Helpers
inline BOOL WINAPI AmsiResultIsMalware(AMSI_RESULT r) noexcept {
    return (r >= AMSI_RESULT_DETECTED) ? 1 : 0;
}

inline BOOL WINAPI AmsiResultIsBlockedByAdmin(AMSI_RESULT r) noexcept {
    return (r >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && r <= AMSI_RESULT_BLOCKED_BY_ADMIN_END) ? 1 : 0;
}

inline BOOL WINAPI AmsiResultIsValid(AMSI_RESULT r) noexcept {
    return ((r >= AMSI_RESULT_CLEAN && r <= AMSI_RESULT_NOT_DETECTED) ||
            (r >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && r <= AMSI_RESULT_BLOCKED_BY_ADMIN_END) ||
            (r >= AMSI_RESULT_DETECTED)) ? 1 : 0;
}

// Runtime De-obfuscated EICAR Pattern Generator (never stored as raw contiguous bytes in .rdata)
inline std::string GetEicarTestPattern() {
    static const unsigned char kMasked[] = {
        0x02, 0x6f, 0x15, 0x7b, 0x0a, 0x7f, 0x1a, 0x1b,
        0x0a, 0x01, 0x6e, 0x06, 0x0a, 0x00, 0x02, 0x6f,
        0x6e, 0x72, 0x0a, 0x04, 0x73, 0x6d, 0x19, 0x19,
        0x73, 0x6d, 0x27, 0x7e, 0x1f, 0x13, 0x19, 0x1b,
        0x08, 0x77, 0x09, 0x0e, 0x1b, 0x14, 0x1e, 0x1b,
        0x08, 0x1e, 0x77, 0x1b, 0x14, 0x0e, 0x13, 0x0c,
        0x13, 0x08, 0x0f, 0x09, 0x77, 0x0e, 0x1f, 0x09,
        0x0e, 0x77, 0x1c, 0x13, 0x16, 0x1f, 0x7b, 0x7e,
        0x12, 0x71, 0x12, 0x70
    };
    std::string s;
    s.reserve(sizeof(kMasked));
    for (unsigned char b : kMasked) {
        s.push_back(static_cast<char>(b ^ 0x5A));
    }
    return s;
}

inline std::wstring GetEicarTestPatternW() {
    auto s = GetEicarTestPattern();
    return std::wstring(s.begin(), s.end());
}

// Runtime-assembled test payloads (avoids static signature collisions with host AV during testing)
inline std::wstring BuildTestDownloadCradle() {
    std::wstring s = L"IEX ";
    s += L"(New-Object ";
    s += L"Net.WebClient).";
    s += L"DownloadString(";
    s += L"'http://127.0.0.1/test_cradle.ps1')";
    return s;
}

inline std::wstring BuildTestCredentialDump() {
    std::wstring s = L"privilege::debug ";
    s += L"sekurlsa";
    s += L"::logon";
    s += L"passwords";
    return s;
}

inline std::wstring BuildTestAmsiBypass() {
    std::wstring s = L"amsi";
    s += L"Init";
    s += L"Failed";
    s += L" = $true";
    return s;
}

// ============================================================================
// 2. Standard AMSI GUIDs
// ============================================================================

// IID_IAmsiStream: {3E47F2E5-81D4-4AE7-897E-585A823CE1F8}
inline constexpr GUID IID_IAmsiStream = {
    0x3E47F2E5, 0x81D4, 0x4AE7, { 0x89, 0x7E, 0x58, 0x5A, 0x82, 0x3C, 0xE1, 0xF8 }
};

// IID_IAmsiProvider: {B2CABFE3-F61D-4729-A586-64623C669004}
inline constexpr GUID IID_IAmsiProvider = {
    0xB2CABFE3, 0xF61D, 0x4729, { 0xA5, 0x86, 0x64, 0x62, 0x3C, 0x66, 0x90, 0x04 }
};

// CLSID_AmsiAntimalware: {FDB00E52-A214-4AA1-8F3B-69BB9EEAC5AC}
inline constexpr GUID CLSID_AmsiAntimalware = {
    0xFDB00E52, 0xA214, 0x4AA1, { 0x8F, 0x3B, 0x69, 0xBB, 0x9E, 0xEA, 0xC5, 0xAC }
};

// ============================================================================
// 3. COM Interface Definitions (IAmsiStream & IAmsiProvider)
// ============================================================================

class IAmsiStream : public ole32::IUnknown {
public:
    virtual HRESULT WINAPI GetAttribute(
        AMSI_ATTRIBUTE attribute,
        ULONG dataSize,
        unsigned char* data,
        ULONG* retData
    ) = 0;

    virtual HRESULT WINAPI Read(
        ULONGLONG position,
        ULONG size,
        unsigned char* buffer,
        ULONG* readSize
    ) = 0;
};

class IAmsiProvider : public ole32::IUnknown {
public:
    virtual HRESULT WINAPI Scan(
        IAmsiStream* stream,
        AMSI_RESULT* result
    ) = 0;

    virtual void WINAPI CloseSession(
        ULONGLONG session
    ) = 0;

    virtual HRESULT WINAPI DisplayName(
        LPWSTR* displayName
    ) = 0;
};

// ============================================================================
// 4. In-Memory IAmsiStream Implementation (AmsiStreamImpl)
// ============================================================================

class AmsiStreamImpl final : public IAmsiStream {
public:
    AmsiStreamImpl(
        std::wstring appName,
        std::wstring contentName,
        const unsigned char* buffer,
        size_t contentSize,
        ULONGLONG sessionNumber
    ) : m_refCount(1),
        m_appName(std::move(appName)),
        m_contentName(std::move(contentName)),
        m_buffer(buffer),
        m_contentSize(contentSize),
        m_sessionNumber(sessionNumber) {}

    // IUnknown
    HRESULT WINAPI QueryInterface(const micant::GUID& riid, void** ppvObject) noexcept override {
        if (!ppvObject) return E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IAmsiStream) {
            *ppvObject = static_cast<IAmsiStream*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    uint32_t WINAPI AddRef() noexcept override {
        return ++m_refCount;
    }

    uint32_t WINAPI Release() noexcept override {
        uint32_t c = --m_refCount;
        if (c == 0) {
            delete this;
        }
        return c;
    }

    // IAmsiStream
    HRESULT WINAPI GetAttribute(
        AMSI_ATTRIBUTE attribute,
        ULONG dataSize,
        unsigned char* data,
        ULONG* retData
    ) override {
        switch (attribute) {
            case AMSI_ATTRIBUTE_APP_NAME: {
                ULONG needed = static_cast<ULONG>((m_appName.size() + 1) * sizeof(wchar_t));
                if (retData) *retData = needed;
                if (!data || dataSize < needed) return HRESULT_FROM_WIN32_INSUFFICIENT_BUFFER;
                std::memcpy(data, m_appName.c_str(), needed);
                return S_OK;
            }
            case AMSI_ATTRIBUTE_CONTENT_NAME: {
                ULONG needed = static_cast<ULONG>((m_contentName.size() + 1) * sizeof(wchar_t));
                if (retData) *retData = needed;
                if (!data || dataSize < needed) return HRESULT_FROM_WIN32_INSUFFICIENT_BUFFER;
                std::memcpy(data, m_contentName.c_str(), needed);
                return S_OK;
            }
            case AMSI_ATTRIBUTE_CONTENT_SIZE: {
                ULONG needed = sizeof(ULONG);
                if (retData) *retData = needed;
                if (!data || dataSize < needed) return HRESULT_FROM_WIN32_INSUFFICIENT_BUFFER;
                ULONG sz = static_cast<ULONG>(m_contentSize);
                std::memcpy(data, &sz, sizeof(ULONG));
                return S_OK;
            }
            case AMSI_ATTRIBUTE_CONTENT_ADDRESS: {
                ULONG needed = sizeof(const void*);
                if (retData) *retData = needed;
                if (!data || dataSize < needed) return HRESULT_FROM_WIN32_INSUFFICIENT_BUFFER;
                const void* ptr = m_buffer;
                std::memcpy(data, &ptr, sizeof(const void*));
                return S_OK;
            }
            case AMSI_ATTRIBUTE_SESSION: {
                ULONG needed = sizeof(ULONGLONG);
                if (retData) *retData = needed;
                if (!data || dataSize < needed) return HRESULT_FROM_WIN32_INSUFFICIENT_BUFFER;
                std::memcpy(data, &m_sessionNumber, sizeof(ULONGLONG));
                return S_OK;
            }
            default:
                if (retData) *retData = 0;
                return E_NOTIMPL;
        }
    }

    HRESULT WINAPI Read(
        ULONGLONG position,
        ULONG size,
        unsigned char* buffer,
        ULONG* readSize
    ) override {
        if (!buffer || !readSize) return E_POINTER;
        if (position >= m_contentSize) {
            *readSize = 0;
            return S_OK;
        }

        size_t remaining = m_contentSize - static_cast<size_t>(position);
        ULONG toRead = static_cast<ULONG>(std::min<size_t>(size, remaining));
        if (toRead > 0 && m_buffer) {
            std::memcpy(buffer, m_buffer + position, toRead);
        }
        *readSize = toRead;
        return S_OK;
    }

private:
    std::atomic<uint32_t> m_refCount;
    std::wstring m_appName;
    std::wstring m_contentName;
    const unsigned char* m_buffer;
    size_t m_contentSize;
    ULONGLONG m_sessionNumber;
};

// ============================================================================
// 5. Built-in Sovereign Provider (SovereignSentinelScanProvider)
// ============================================================================

class SovereignSentinelScanProvider final : public IAmsiProvider {
public:
    SovereignSentinelScanProvider() : m_refCount(1) {}

    // IUnknown
    HRESULT WINAPI QueryInterface(const micant::GUID& riid, void** ppvObject) noexcept override {
        if (!ppvObject) return E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IAmsiProvider) {
            *ppvObject = static_cast<IAmsiProvider*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObject = nullptr;
        return E_NOINTERFACE;
    }

    uint32_t WINAPI AddRef() noexcept override {
        return ++m_refCount;
    }

    uint32_t WINAPI Release() noexcept override {
        uint32_t c = --m_refCount;
        if (c == 0) {
            delete this;
        }
        return c;
    }

    // IAmsiProvider
    HRESULT WINAPI DisplayName(LPWSTR* displayName) override {
        if (!displayName) return E_POINTER;
        static const wchar_t kName[] = L"SentinelScan Sovereign Heuristic Analyzer";
        size_t len = (std::wcslen(kName) + 1) * sizeof(wchar_t);
        auto* mem = static_cast<wchar_t*>(std::malloc(len));
        if (!mem) return E_OUTOFMEMORY;
        std::memcpy(mem, kName, len);
        *displayName = mem;
        return S_OK;
    }

    void WINAPI CloseSession(ULONGLONG /*session*/) override {
        // Stateless provider session cleanup
    }

    HRESULT WINAPI Scan(IAmsiStream* stream, AMSI_RESULT* result) override {
        if (!stream || !result) return E_POINTER;
        *result = AMSI_RESULT_NOT_DETECTED;

        // 1. Query content size
        ULONG sizeNeeded = 0;
        ULONG contentSize = 0;
        HRESULT hr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(ULONG),
                                          reinterpret_cast<unsigned char*>(&contentSize), &sizeNeeded);
        if (FAILED(hr) || contentSize == 0) {
            *result = AMSI_RESULT_NOT_DETECTED;
            return S_OK;
        }

        // 2. Query content name if available
        std::wstring contentName;
        wchar_t nameBuf[256]{};
        hr = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_NAME, sizeof(nameBuf),
                                  reinterpret_cast<unsigned char*>(nameBuf), &sizeNeeded);
        if (SUCCEEDED(hr)) {
            contentName = nameBuf;
        }

        // 3. Read stream data into memory buffer
        std::vector<unsigned char> data(contentSize);
        ULONG bytesRead = 0;
        hr = stream->Read(0, contentSize, data.data(), &bytesRead);
        if (FAILED(hr) || bytesRead == 0) {
            *result = AMSI_RESULT_NOT_DETECTED;
            return S_OK;
        }
        data.resize(bytesRead);

        // 4. Admin Block Policy Check on content name
        if (contentName.find(L"policy:block") != std::wstring::npos ||
            contentName.find(L"admin:denied") != std::wstring::npos ||
            contentName.find(L"untrusted_source") != std::wstring::npos) {
            *result = AMSI_RESULT_BLOCKED_BY_ADMIN_START;
            return S_OK;
        }

        // 5. Heuristic: Check for EICAR standard test string (ASCII or UTF-16)
        std::string eicarPattern = GetEicarTestPattern();
        std::string rawStr(reinterpret_cast<const char*>(data.data()), data.size());
        if (rawStr.find(eicarPattern) != std::string::npos) {
            *result = AMSI_RESULT_DETECTED;
            return S_OK;
        }

        // Also check UTF-16 representation of EICAR
        if (data.size() >= eicarPattern.size() * 2) {
            std::string utf16ToAscii;
            utf16ToAscii.reserve(data.size() / 2);
            for (size_t i = 0; i + 1 < data.size(); i += 2) {
                if (data[i + 1] == 0) {
                    utf16ToAscii.push_back(static_cast<char>(data[i]));
                } else {
                    utf16ToAscii.push_back('?');
                }
            }
            if (utf16ToAscii.find(eicarPattern) != std::string::npos) {
                *result = AMSI_RESULT_DETECTED;
                return S_OK;
            }
        }

        // 6. Heuristic: Shellcode & NOP Sled Detection
        // Look for 16 or more consecutive 0x90 bytes
        size_t consecutiveNops = 0;
        for (unsigned char b : data) {
            if (b == 0x90) {
                consecutiveNops++;
                if (consecutiveNops >= 16) {
                    *result = AMSI_RESULT_DETECTED;
                    return S_OK;
                }
            } else {
                consecutiveNops = 0;
            }
        }

        // Check common shellcode signatures
        static const std::vector<std::vector<unsigned char>> kShellcodeSignatures = {
            { 0x31, 0xc0, 0x50, 0x68 },                         // x86 xor eax,eax; push eax; push ...
            { 0x48, 0x31, 0xc0, 0x48, 0x89 },                   // x64 xor rax,rax; mov ...
            { 0xfc, 0x48, 0x83, 0xe4, 0xf0 },                   // x64 cld; and rsp, -0x10 (Metasploit stager)
            { 0xfc, 0xe8, 0x82, 0x00, 0x00, 0x00 }              // x86 call $+0x87 (Metasploit stager)
        };
        for (const auto& sig : kShellcodeSignatures) {
            if (data.size() >= sig.size()) {
                auto it = std::search(data.begin(), data.end(), sig.begin(), sig.end());
                if (it != data.end()) {
                    *result = AMSI_RESULT_DETECTED;
                    return S_OK;
                }
            }
        }

        // 7. Heuristic: Malicious Script, Cmdlet & Memory Tampering Tokens
        // Normalize buffer to lower-case ASCII representation (supports both plain ASCII & UTF-16LE)
        std::string normalized;
        normalized.reserve(data.size());

        // Check if content appears to be UTF-16LE (every second byte null)
        bool isUtf16 = (data.size() >= 4 && data[1] == 0 && data[3] == 0);
        if (isUtf16) {
            for (size_t i = 0; i + 1 < data.size(); i += 2) {
                char c = static_cast<char>(data[i]);
                normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }
        } else {
            for (unsigned char b : data) {
                normalized.push_back(static_cast<char>(std::tolower(b)));
            }
        }

        // Token list 1: Blatant exploit and credential dumping tools
        static const std::string_view kSevereTokens[] = {
            "mimikatz",
            "sekurlsa::",
            "logonpasswords",
            "kerberos::ptt",
            "lsadump::",
            "amsiinitfailed",
            "amsiutils",
            "system.management.automation.amsiutils"
        };
        for (auto token : kSevereTokens) {
            if (normalized.find(token) != std::string::npos) {
                *result = AMSI_RESULT_DETECTED;
                return S_OK;
            }
        }

        // Token list 2: Malicious PowerShell download cradles
        bool hasIex = (normalized.find("invoke-expression") != std::string::npos ||
                       normalized.find("iex ") != std::string::npos ||
                       normalized.find("iex(") != std::string::npos);

        bool hasNetDownload = (normalized.find("downloadstring") != std::string::npos ||
                               normalized.find("downloadfile") != std::string::npos ||
                               normalized.find("net.webclient") != std::string::npos ||
                               normalized.find("invoke-webrequest") != std::string::npos ||
                               normalized.find("iwr ") != std::string::npos);

        if (hasIex && hasNetDownload) {
            *result = AMSI_RESULT_DETECTED;
            return S_OK;
        }

        // Token list 3: In-memory process injection / hollowing primitives
        bool hasAlloc = (normalized.find("virtualalloc") != std::string::npos ||
                         normalized.find("ntallocatevirtualmemory") != std::string::npos);
        bool hasWrite = (normalized.find("writeprocessmemory") != std::string::npos ||
                         normalized.find("ntwritevirtualmemory") != std::string::npos);
        bool hasThread = (normalized.find("createremotethread") != std::string::npos ||
                          normalized.find("ntcreatethreadex") != std::string::npos ||
                          normalized.find("queueuserapc") != std::string::npos);

        if (hasAlloc && hasWrite && hasThread) {
            *result = AMSI_RESULT_DETECTED;
            return S_OK;
        }

        // 8. Heuristic: Shannon Entropy Analysis
        // Flags high-entropy encrypted/obfuscated script payloads (> 7.6 bits/byte)
        if (data.size() >= 512) {
            uint32_t counts[256]{};
            for (unsigned char b : data) counts[b]++;
            double entropy = 0.0;
            double len = static_cast<double>(data.size());
            for (int i = 0; i < 256; ++i) {
                if (counts[i] > 0) {
                    double p = static_cast<double>(counts[i]) / len;
                    entropy -= p * std::log2(p);
                }
            }
            if (entropy > 7.7) {
                // If high entropy and script context contains execution markers
                if (normalized.find("eval") != std::string::npos ||
                    normalized.find("frombase64string") != std::string::npos ||
                    normalized.find("execute") != std::string::npos) {
                    *result = AMSI_RESULT_DETECTED;
                    return S_OK;
                }
            }
        }

        *result = AMSI_RESULT_NOT_DETECTED;
        return S_OK;
    }

private:
    std::atomic<uint32_t> m_refCount;
};

// ============================================================================
// 6. Sovereign AMSI Executive Manager (SovereignAmsiManager)
// ============================================================================

struct AmsiSessionRecord {
    ULONGLONG sessionId{0};
    HAMSICONTEXT contextHandle{nullptr};
    std::chrono::system_clock::time_point created;
    uint32_t scanCount{0};
    uint32_t threatCount{0};
};

struct AmsiContextRecord {
    std::wstring appName;
    std::chrono::system_clock::time_point created;
    std::unordered_set<HAMSISESSION> sessions;
    uint32_t scanCount{0};
    uint32_t threatCount{0};
};

class SovereignAmsiManager {
public:
    static SovereignAmsiManager& get() noexcept {
        static SovereignAmsiManager instance;
        return instance;
    }

    HRESULT initialize(LPCWSTR appName, HAMSICONTEXT* pContext) {
        if (!appName || !pContext) return E_INVALIDARG;

        std::lock_guard<std::mutex> lock(m_mutex);
        ensureDefaultProvider();

        auto record = std::make_unique<AmsiContextRecord>();
        record->appName = appName;
        record->created = std::chrono::system_clock::now();

        auto* handle = reinterpret_cast<HAMSICONTEXT>(record.get());
        m_contexts[handle] = std::move(record);
        *pContext = handle;

        return S_OK;
    }

    void uninitialize(HAMSICONTEXT context) {
        if (!context) return;

        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_contexts.find(context);
        if (it == m_contexts.end()) return;

        // Close all sessions belonging to this context
        for (auto sHandle : it->second->sessions) {
            auto sIt = m_sessions.find(sHandle);
            if (sIt != m_sessions.end()) {
                notifyProvidersCloseSession(sIt->second->sessionId);
                m_sessions.erase(sIt);
            }
        }

        m_contexts.erase(it);
    }

    HRESULT openSession(HAMSICONTEXT context, HAMSISESSION* pSession) {
        if (!context || !pSession) return E_INVALIDARG;

        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_contexts.find(context);
        if (it == m_contexts.end()) return HRESULT_FROM_WIN32_INVALID_HANDLE;

        auto sRecord = std::make_unique<AmsiSessionRecord>();
        sRecord->sessionId = ++m_nextSessionId;
        sRecord->contextHandle = context;
        sRecord->created = std::chrono::system_clock::now();

        auto* handle = reinterpret_cast<HAMSISESSION>(sRecord.get());
        it->second->sessions.insert(handle);
        m_sessions[handle] = std::move(sRecord);
        *pSession = handle;

        m_totalSessionsOpened++;
        return S_OK;
    }

    void closeSession(HAMSICONTEXT context, HAMSISESSION session) {
        if (!context || !session) return;

        std::lock_guard<std::mutex> lock(m_mutex);
        auto sIt = m_sessions.find(session);
        if (sIt == m_sessions.end()) return;

        notifyProvidersCloseSession(sIt->second->sessionId);

        auto cIt = m_contexts.find(context);
        if (cIt != m_contexts.end()) {
            cIt->second->sessions.erase(session);
        }
        m_sessions.erase(sIt);
    }

    HRESULT scanBuffer(
        HAMSICONTEXT context,
        const void* buffer,
        ULONG length,
        LPCWSTR contentName,
        HAMSISESSION session,
        AMSI_RESULT* result
    ) {
        if (!result) return E_POINTER;
        *result = AMSI_RESULT_NOT_DETECTED;

        if (!context) return E_INVALIDARG;

        std::wstring appName = L"MicaNTApplication";
        ULONGLONG sessionNum = 0;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto cIt = m_contexts.find(context);
            if (cIt != m_contexts.end()) {
                appName = cIt->second->appName;
            }
            if (session) {
                auto sIt = m_sessions.find(session);
                if (sIt != m_sessions.end()) {
                    sessionNum = sIt->second->sessionId;
                }
            }
        }

        if (!buffer || length == 0) {
            *result = AMSI_RESULT_NOT_DETECTED;
            return S_OK;
        }

        std::wstring cName = contentName ? contentName : L"";

        // Admin policy check from manager rules
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (const auto& blockedRule : m_adminBlockRules) {
                if (!blockedRule.empty() && cName.find(blockedRule) != std::wstring::npos) {
                    *result = AMSI_RESULT_BLOCKED_BY_ADMIN_START;
                    m_totalAdminBlocked++;
                    return S_OK;
                }
            }
        }

        // Create stream instance
        auto* stream = new AmsiStreamImpl(
            appName,
            cName,
            reinterpret_cast<const unsigned char*>(buffer),
            length,
            sessionNum
        );

        AMSI_RESULT worstResult = AMSI_RESULT_CLEAN;

        std::vector<IAmsiProvider*> providersCopy;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            providersCopy = m_providers;
        }

        for (auto* prov : providersCopy) {
            AMSI_RESULT cur = AMSI_RESULT_NOT_DETECTED;
            HRESULT hr = prov->Scan(stream, &cur);
            if (SUCCEEDED(hr)) {
                if (cur >= AMSI_RESULT_DETECTED) {
                    worstResult = AMSI_RESULT_DETECTED;
                    break; // Immediate threat termination
                } else if (cur >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && worstResult < AMSI_RESULT_BLOCKED_BY_ADMIN_START) {
                    worstResult = cur;
                } else if (cur > worstResult) {
                    worstResult = cur;
                }
            }
        }

        stream->Release();

        // Update statistics
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_totalScans++;
            if (worstResult >= AMSI_RESULT_DETECTED) {
                m_totalThreatsDetected++;
            } else if (worstResult >= AMSI_RESULT_BLOCKED_BY_ADMIN_START) {
                m_totalAdminBlocked++;
            }

            auto cIt = m_contexts.find(context);
            if (cIt != m_contexts.end()) {
                cIt->second->scanCount++;
                if (worstResult >= AMSI_RESULT_DETECTED) cIt->second->threatCount++;
            }
            if (session) {
                auto sIt = m_sessions.find(session);
                if (sIt != m_sessions.end()) {
                    sIt->second->scanCount++;
                    if (worstResult >= AMSI_RESULT_DETECTED) sIt->second->threatCount++;
                }
            }
        }

        *result = worstResult;
        return S_OK;
    }

    HRESULT scanString(
        HAMSICONTEXT context,
        LPCWSTR string,
        LPCWSTR contentName,
        HAMSISESSION session,
        AMSI_RESULT* result
    ) {
        if (!string) return E_INVALIDARG;
        ULONG byteLength = static_cast<ULONG>((std::wcslen(string) + 1) * sizeof(wchar_t));
        return scanBuffer(context, string, byteLength, contentName, session, result);
    }

    HRESULT notifyOperation(
        HAMSICONTEXT context,
        const void* buffer,
        ULONG length,
        LPCWSTR contentName,
        AMSI_RESULT* result
    ) {
        return scanBuffer(context, buffer, length, contentName, nullptr, result);
    }

    void registerProvider(IAmsiProvider* provider) {
        if (!provider) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (std::find(m_providers.begin(), m_providers.end(), provider) == m_providers.end()) {
            provider->AddRef();
            m_providers.push_back(provider);
        }
    }

    void unregisterProvider(IAmsiProvider* provider) {
        if (!provider) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::find(m_providers.begin(), m_providers.end(), provider);
        if (it != m_providers.end()) {
            (*it)->Release();
            m_providers.erase(it);
        }
    }

    void addAdminBlockRule(std::wstring pattern) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!pattern.empty()) {
            m_adminBlockRules.push_back(std::move(pattern));
        }
    }

    void removeAdminBlockRule(std::wstring_view pattern) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::remove_if(m_adminBlockRules.begin(), m_adminBlockRules.end(),
                                [&](const std::wstring& p) { return p == pattern; });
        m_adminBlockRules.erase(it, m_adminBlockRules.end());
    }

    void clearAdminBlockRules() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_adminBlockRules.clear();
    }

    // Telemetry & Statistics Queries
    uint64_t getTotalScans() const noexcept { return m_totalScans; }
    uint64_t getTotalThreatsDetected() const noexcept { return m_totalThreatsDetected; }
    uint64_t getTotalAdminBlocked() const noexcept { return m_totalAdminBlocked; }
    uint64_t getTotalSessionsOpened() const noexcept { return m_totalSessionsOpened; }
    size_t getActiveSessionsCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sessions.size();
    }
    size_t getActiveContextsCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_contexts.size();
    }
    size_t getProvidersCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_providers.size();
    }

private:
    SovereignAmsiManager() {
        ensureDefaultProvider();
    }

    ~SovereignAmsiManager() {
        for (auto* prov : m_providers) {
            prov->Release();
        }
        m_providers.clear();
    }

    void ensureDefaultProvider() {
        if (m_providers.empty()) {
            auto* defaultProv = new SovereignSentinelScanProvider();
            m_providers.push_back(defaultProv); // ref count is 1
        }
    }

    void notifyProvidersCloseSession(ULONGLONG sessionId) {
        for (auto* prov : m_providers) {
            prov->CloseSession(sessionId);
        }
    }

    mutable std::mutex m_mutex;
    std::unordered_map<HAMSICONTEXT, std::unique_ptr<AmsiContextRecord>> m_contexts;
    std::unordered_map<HAMSISESSION, std::unique_ptr<AmsiSessionRecord>> m_sessions;
    std::vector<IAmsiProvider*> m_providers;
    std::vector<std::wstring> m_adminBlockRules;

    ULONGLONG m_nextSessionId{1000};
    std::atomic<uint64_t> m_totalScans{0};
    std::atomic<uint64_t> m_totalThreatsDetected{0};
    std::atomic<uint64_t> m_totalAdminBlocked{0};
    std::atomic<uint64_t> m_totalSessionsOpened{0};
};

// ============================================================================
// 7. Native Win32 AMSI C ABI Functions (amsi.dll)
// ============================================================================

inline HRESULT WINAPI AmsiInitialize(LPCWSTR appName, HAMSICONTEXT* amsiContext) {
    return SovereignAmsiManager::get().initialize(appName, amsiContext);
}

inline void WINAPI AmsiUninitialize(HAMSICONTEXT amsiContext) {
    SovereignAmsiManager::get().uninitialize(amsiContext);
}

inline HRESULT WINAPI AmsiOpenSession(HAMSICONTEXT amsiContext, HAMSISESSION* amsiSession) {
    return SovereignAmsiManager::get().openSession(amsiContext, amsiSession);
}

inline void WINAPI AmsiCloseSession(HAMSICONTEXT amsiContext, HAMSISESSION amsiSession) {
    SovereignAmsiManager::get().closeSession(amsiContext, amsiSession);
}

inline HRESULT WINAPI AmsiScanBuffer(
    HAMSICONTEXT amsiContext,
    PVOID buffer,
    ULONG length,
    LPCWSTR contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT* result
) {
    return SovereignAmsiManager::get().scanBuffer(amsiContext, buffer, length, contentName, amsiSession, result);
}

inline HRESULT WINAPI AmsiScanString(
    HAMSICONTEXT amsiContext,
    LPCWSTR string,
    LPCWSTR contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT* result
) {
    return SovereignAmsiManager::get().scanString(amsiContext, string, contentName, amsiSession, result);
}

inline HRESULT WINAPI AmsiNotifyOperation(
    HAMSICONTEXT amsiContext,
    PVOID buffer,
    ULONG length,
    LPCWSTR contentName,
    AMSI_RESULT* result
) {
    return SovereignAmsiManager::get().notifyOperation(amsiContext, buffer, length, contentName, result);
}

// ============================================================================
// 8. Subsystem Export Registration Helper
// ============================================================================

inline void InitializeAmsiSubsystemExports() {
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        auto& loader = ldr::DynamicLoader::get();

        // 1. Register amsi.dll dynamic exports
        loader.registerExport("amsi.dll", "AmsiInitialize", reinterpret_cast<void*>(&AmsiInitialize));
        loader.registerExport("amsi.dll", "AmsiUninitialize", reinterpret_cast<void*>(&AmsiUninitialize));
        loader.registerExport("amsi.dll", "AmsiOpenSession", reinterpret_cast<void*>(&AmsiOpenSession));
        loader.registerExport("amsi.dll", "AmsiCloseSession", reinterpret_cast<void*>(&AmsiCloseSession));
        loader.registerExport("amsi.dll", "AmsiScanBuffer", reinterpret_cast<void*>(&AmsiScanBuffer));
        loader.registerExport("amsi.dll", "AmsiScanString", reinterpret_cast<void*>(&AmsiScanString));
        loader.registerExport("amsi.dll", "AmsiNotifyOperation", reinterpret_cast<void*>(&AmsiNotifyOperation));

        // 2. Register module in VersionDatabase
        version::VersionDatabase::Instance().RegisterModule(
            "amsi.dll",
            "10.0.26100.1",
            "Antimalware Scan Interface Client",
            "MicaNT Sovereign Project"
        );
    });
}

} // namespace micant::amsi
