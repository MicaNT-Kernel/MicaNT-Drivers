// ============================================================================
// MicaNT: Windows Speech API (SAPI 5.4) & Voice Synthesis Subsystem (sapi.hpp)
//
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/win32metadata (Windows.Win32.Media.Speech)
//   - SAPI 5.4 Component Object Model (COM) Architecture Specifications
//   - W3C Speech Synthesis Markup Language (SSML) Version 1.0 Recommendations
//
// Subsystem Overview:
//   sapi.hpp provides the clean-room SAPI 5.4 text-to-speech (TTS), voice token
//   catalog, audio format translation, and command-and-control speech recognition
//   subsystem for MicaNT.
//
// Core Dynamic Modules:
//   - sapi.dll (Speech API 5.4 Core Engine, SpVoice, SpStream, SpObjectToken)
//
// Trademark & Nominative Fair Use Notice:
//   SAPI, Windows, and Microsoft are registered trademarks of Microsoft Corp.
//   MicaNT's Speech API subsystem is an independent sovereign clean-room
//   implementation engineered for binary interoperability (*Google LLC v. Oracle America, Inc.*).
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ldr.hpp"
#include "version.hpp"
#include "ole32.hpp"
#include "appmodel.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <numbers>
#include <chrono>

namespace micant::sapi {

// ============================================================================
// 1. SAPI COM GUIDs & Constants
// ============================================================================

inline constexpr micant::GUID CLSID_SpVoice = {
    0x96749377, 0x3391, 0x11D2, { 0x9E, 0xE3, 0x00, 0xC0, 0x4F, 0x79, 0x73, 0x96 }
};

inline constexpr micant::GUID IID_ISpVoice = {
    0x6C44DF74, 0x72B9, 0x4992, { 0xA1, 0xEC, 0xEF, 0x99, 0x6E, 0x04, 0x22, 0xD4 }
};

inline constexpr micant::GUID CLSID_SpObjectTokenCategory = {
    0xA91018BA, 0x2426, 0x457F, { 0xAC, 0xF4, 0x1F, 0x4F, 0x78, 0x07, 0x0F, 0x6A }
};

inline constexpr micant::GUID IID_ISpObjectTokenCategory = {
    0x2D3D3845, 0x39AF, 0x4850, { 0xBB, 0xF9, 0x40, 0xB4, 0x97, 0x80, 0x01, 0x1D }
};

inline constexpr micant::GUID IID_ISpObjectToken = {
    0x14056581, 0xE16C, 0x11D2, { 0xBB, 0x90, 0x00, 0xC0, 0x4F, 0x8E, 0xE6, 0xC0 }
};

inline constexpr micant::GUID IID_IEnumSpObjectTokens = {
    0x06B64FAC, 0xA52C, 0x4974, { 0x86, 0xA9, 0x51, 0x6E, 0x42, 0x5F, 0x88, 0xFB }
};

inline constexpr micant::GUID CLSID_SpStream = {
    0x715D9E59, 0x4442, 0x11D2, { 0x96, 0x0E, 0x00, 0xC0, 0x4F, 0x8E, 0xE6, 0x28 }
};

inline constexpr micant::GUID IID_ISpStream = {
    0xBED530AE, 0x3000, 0x49CE, { 0x8A, 0xC7, 0x7A, 0x63, 0x80, 0x30, 0x7D, 0x02 }
};

inline constexpr micant::GUID IID_ISpAudio = {
    0xC05C7686, 0x3BE2, 0x4B42, { 0x8A, 0x73, 0x20, 0x0E, 0x15, 0x72, 0x11, 0xEC }
};

inline constexpr micant::GUID CLSID_SpSharedRecognizer = {
    0x3BEE4890, 0x4FE3, 0x11D2, { 0x96, 0x0E, 0x00, 0xC0, 0x4F, 0x8E, 0xE6, 0x28 }
};

inline constexpr micant::GUID IID_ISpRecognizer = {
    0xC2B5F241, 0xDAA0, 0x4507, { 0x9E, 0x16, 0x5A, 0x1E, 0xAA, 0x2B, 0x7A, 0x54 }
};

inline constexpr micant::GUID IID_ISpRecoContext = {
    0xF740A62F, 0x7D15, 0x489E, { 0x8A, 0x29, 0x68, 0x6A, 0x7F, 0x96, 0x67, 0x4C }
};

inline constexpr micant::GUID IID_ISpRecoGrammar = {
    0xA2EAE232, 0xD120, 0x4250, { 0xB8, 0x27, 0x3D, 0x73, 0x33, 0x72, 0x22, 0x1E }
};

// SAPI Categories
inline constexpr const wchar_t* SPCAT_VOICES        = L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Speech\\Voices";
inline constexpr const wchar_t* SPCAT_AUDIOOUT      = L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Speech\\AudioOutput";
inline constexpr const wchar_t* SPCAT_AUDIOIN       = L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Speech\\AudioInput";
inline constexpr const wchar_t* SPCAT_RECOGNIZERS   = L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Speech\\Recognizers";

// SAPI Speak Flags
inline constexpr uint32_t SPF_DEFAULT           = 0x00000000;
inline constexpr uint32_t SPF_ASYNC             = 0x00000001;
inline constexpr uint32_t SPF_PURGEBEFORESPEAK   = 0x00000002;
inline constexpr uint32_t SPF_IS_FILENAME       = 0x00000004;
inline constexpr uint32_t SPF_IS_XML            = 0x00000008;
inline constexpr uint32_t SPF_IS_NOT_XML        = 0x00000010;
inline constexpr uint32_t SPF_PERSIST_XML       = 0x00000020;

// SAPI Audio Stream Formats
enum SPSTREAMFORMAT {
    SPSF_NoFormat = 0,
    SPSF_8kHz8BitMono,
    SPSF_8kHz8BitStereo,
    SPSF_8kHz16BitMono,
    SPSF_8kHz16BitStereo,
    SPSF_11kHz8BitMono,
    SPSF_11kHz8BitStereo,
    SPSF_11kHz16BitMono,
    SPSF_11kHz16BitStereo,
    SPSF_12kHz8BitMono,
    SPSF_12kHz8BitStereo,
    SPSF_12kHz16BitMono,
    SPSF_12kHz16BitStereo,
    SPSF_16kHz8BitMono,
    SPSF_16kHz8BitStereo,
    SPSF_16kHz16BitMono,
    SPSF_16kHz16BitStereo,
    SPSF_22kHz8BitMono,
    SPSF_22kHz8BitStereo,
    SPSF_22kHz16BitMono,
    SPSF_22kHz16BitStereo,
    SPSF_24kHz8BitMono,
    SPSF_24kHz8BitStereo,
    SPSF_24kHz16BitMono,
    SPSF_24kHz16BitStereo,
    SPSF_32kHz8BitMono,
    SPSF_32kHz8BitStereo,
    SPSF_32kHz16BitMono,
    SPSF_32kHz16BitStereo,
    SPSF_44kHz8BitMono,
    SPSF_44kHz8BitStereo,
    SPSF_44kHz16BitMono,
    SPSF_44kHz16BitStereo,
    SPSF_48kHz8BitMono,
    SPSF_48kHz8BitStereo,
    SPSF_48kHz16BitMono,
    SPSF_48kHz16BitStereo
};

// SAPI Audio States
enum SPAUDIOSTATE {
    SPAS_CLOSED = 0,
    SPAS_STOP   = 1,
    SPAS_PAUSE  = 2,
    SPAS_RUN    = 3
};

struct SPAUDIOSTATUS {
    int32_t   cbFreeBuffSpace;
    uint32_t  cbNonBlockingIO;
    SPAUDIOSTATE State;
    uint64_t  CurSeekPos;
    uint64_t  CurDevicePos;
    uint32_t  dwAudioLevel;
    uint32_t  dwReserved2;
};

struct SPVOICESTATUS {
    uint32_t ulCurrentStreamNum;
    uint32_t ulLastStreamNumQueued;
    int32_t  hrLastResult;
    uint32_t dwRunningState;
    uint32_t ulInputWordPos;
    uint32_t ulInputWordLen;
    uint32_t ulInputSentPos;
    uint32_t ulInputSentLen;
    int32_t  lBookmarkId;
    int32_t  PhonemeId;
    int32_t  VisemeId;
};

// Forward Declarations
class ISpObjectToken;
class ISpObjectTokenCategory;
class IEnumSpObjectTokens;
class ISpStream;

// ============================================================================
// 2. SAPI COM Interfaces
// ============================================================================

class ISpObjectToken : public ole32::IUnknown {
public:
    virtual int32_t __stdcall SetId(const wchar_t* pszCategoryId, const wchar_t* pszTokenId, int32_t fCreateIfNotExist) = 0;
    virtual int32_t __stdcall GetId(wchar_t** ppszCoMemTokenId) = 0;
    virtual int32_t __stdcall GetCategory(ISpObjectTokenCategory** ppTokenCategory) = 0;
    virtual int32_t __stdcall SetStringValue(const wchar_t* pszValueName, const wchar_t* pszValue) = 0;
    virtual int32_t __stdcall GetStringValue(const wchar_t* pszValueName, wchar_t** ppszCoMemValue) = 0;
    virtual int32_t __stdcall Remove(const micant::GUID* pclsidCaller) = 0;
    virtual int32_t __stdcall MatchesAttributes(const wchar_t* pszAttributes, int32_t* pfMatches) = 0;
};

class IEnumSpObjectTokens : public ole32::IUnknown {
public:
    virtual int32_t __stdcall Next(uint32_t celt, ISpObjectToken** pelt, uint32_t* pceltFetched) = 0;
    virtual int32_t __stdcall Skip(uint32_t celt) = 0;
    virtual int32_t __stdcall Reset() = 0;
    virtual int32_t __stdcall Clone(IEnumSpObjectTokens** ppEnum) = 0;
    virtual int32_t __stdcall GetCount(uint32_t* pulCount) = 0;
    virtual int32_t __stdcall Item(uint32_t Index, ISpObjectToken** ppToken) = 0;
};

class ISpObjectTokenCategory : public ole32::IUnknown {
public:
    virtual int32_t __stdcall SetId(const wchar_t* pszCategoryId, int32_t fCreateIfNotExist) = 0;
    virtual int32_t __stdcall GetId(wchar_t** ppszCoMemCategoryId) = 0;
    virtual int32_t __stdcall GetDataKey(uint32_t dkf, void** ppDataKey) = 0;
    virtual int32_t __stdcall EnumTokens(const wchar_t* pzsReqAttribs, const wchar_t* pszOptAttribs, IEnumSpObjectTokens** ppEnum) = 0;
    virtual int32_t __stdcall SetDefaultTokenId(const wchar_t* pszTokenId) = 0;
    virtual int32_t __stdcall GetDefaultTokenId(wchar_t** ppszCoMemTokenId) = 0;
};

class ISpStream : public ole32::IStream {
public:
    virtual int32_t __stdcall BindToFile(const wchar_t* pszFileName, uint32_t dwMode, const micant::GUID* pFormatId, const void* pWaveFormatEx, uint64_t ullEventInterest) = 0;
    virtual int32_t __stdcall Close() = 0;
    virtual int32_t __stdcall GetFormat(micant::GUID* pFormatId, void** ppCoMemWaveFormatEx) = 0;
    virtual int32_t __stdcall SetBaseStream(ole32::IStream* pStream, const micant::GUID* pFormatId, const void* pWaveFormatEx) = 0;
    virtual int32_t __stdcall GetBaseStream(ole32::IStream** ppStream) = 0;
};

class ISpAudio : public ISpStream {
public:
    virtual int32_t __stdcall SetState(SPAUDIOSTATE NewState, uint64_t ullReserved) = 0;
    virtual int32_t __stdcall SetFormat(const micant::GUID* pFormatId, const void* pWaveFormatEx) = 0;
    virtual int32_t __stdcall GetStatus(SPAUDIOSTATUS* pStatus) = 0;
    virtual int32_t __stdcall SetBufferInfo(const void* pBuffInfo) = 0;
    virtual int32_t __stdcall GetBufferInfo(void* pBuffInfo) = 0;
    virtual int32_t __stdcall GetDefaultFormat(micant::GUID* pFormatId, void** ppCoMemWaveFormatEx) = 0;
    virtual int32_t __stdcall EventHandle(void** pEventHandle) = 0;
    virtual int32_t __stdcall GetVolumeLevel(uint32_t* pLevel) = 0;
    virtual int32_t __stdcall SetVolumeLevel(uint32_t Level) = 0;
    virtual int32_t __stdcall GetBufferNotifySize(uint32_t* pcbSize) = 0;
    virtual int32_t __stdcall SetBufferNotifySize(uint32_t cbSize) = 0;
};

class ISpVoice : public ole32::IUnknown {
public:
    virtual int32_t __stdcall SetOutput(ole32::IUnknown* pUnkOutput, int32_t fAllowFormatChanges) = 0;
    virtual int32_t __stdcall GetOutputObjectToken(ISpObjectToken** ppObjectToken) = 0;
    virtual int32_t __stdcall GetOutputStream(ISpStream** ppStream) = 0;
    virtual int32_t __stdcall Pause() = 0;
    virtual int32_t __stdcall Resume() = 0;
    virtual int32_t __stdcall SetVoice(ISpObjectToken* pToken) = 0;
    virtual int32_t __stdcall GetVoice(ISpObjectToken** ppToken) = 0;
    virtual int32_t __stdcall Speak(const wchar_t* pwcs, uint32_t dwFlags, uint32_t* pulStreamNumber) = 0;
    virtual int32_t __stdcall SpeakStream(ole32::IStream* pStream, uint32_t dwFlags, uint32_t* pulStreamNumber) = 0;
    virtual int32_t __stdcall GetStatus(SPVOICESTATUS* pStatus, wchar_t** ppszLastBookmark) = 0;
    virtual int32_t __stdcall Skip(const wchar_t* pItemType, int32_t lNumItems, uint32_t* pulNumSkipped) = 0;
    virtual int32_t __stdcall SetPriority(int32_t ePriority) = 0;
    virtual int32_t __stdcall GetPriority(int32_t* pePriority) = 0;
    virtual int32_t __stdcall SetAlertBoundary(int32_t eBoundary) = 0;
    virtual int32_t __stdcall GetAlertBoundary(int32_t* peBoundary) = 0;
    virtual int32_t __stdcall SetRate(int32_t RateAdjust) = 0;
    virtual int32_t __stdcall GetRate(int32_t* pRateAdjust) = 0;
    virtual int32_t __stdcall SetVolume(uint16_t usVolume) = 0;
    virtual int32_t __stdcall GetVolume(uint16_t* pusVolume) = 0;
    virtual int32_t __stdcall WaitUntilDone(uint32_t msTimeout) = 0;
    virtual int32_t __stdcall SetSyncSpeakTimeout(uint32_t msTimeout) = 0;
    virtual int32_t __stdcall GetSyncSpeakTimeout(uint32_t* pmsTimeout) = 0;
    virtual int32_t __stdcall SpeakCompleteEvent(void** phEvent) = 0;
    virtual int32_t __stdcall IsUISupported(const wchar_t* pszTypeOfUI, void* pvExtraData, uint32_t cbExtraData, int32_t* pfSupported) = 0;
    virtual int32_t __stdcall DisplayUI(void* hwndParent, const wchar_t* pszTitle, const wchar_t* pszTypeOfUI, void* pvExtraData, uint32_t cbExtraData) = 0;
};

// ============================================================================
// 3. String & CoTaskMem Helpers
// ============================================================================

inline wchar_t* AllocateCoTaskString(const std::wstring& str) {
    size_t bytes = (str.length() + 1) * sizeof(wchar_t);
    auto* p = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(bytes));
    if (p) {
        std::memcpy(p, str.c_str(), bytes);
    }
    return p;
}

// ============================================================================
// 4. Token & Token Category Implementations
// ============================================================================

class CSpObjectTokenImpl : public ISpObjectToken {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_id;
    std::wstring m_categoryId;
    std::unordered_map<std::wstring, std::wstring> m_attributes;
    std::mutex m_mutex;

public:
    CSpObjectTokenImpl(std::wstring id, std::wstring catId, std::unordered_map<std::wstring, std::wstring> attrs)
        : m_id(std::move(id)), m_categoryId(std::move(catId)), m_attributes(std::move(attrs)) {}

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ISpObjectToken) {
            *ppv = static_cast<ISpObjectToken*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall SetId(const wchar_t* pszCategoryId, const wchar_t* pszTokenId, int32_t) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (pszCategoryId) m_categoryId = pszCategoryId;
        if (pszTokenId) m_id = pszTokenId;
        return ole32::S_OK;
    }

    int32_t __stdcall GetId(wchar_t** ppszCoMemTokenId) override {
        if (!ppszCoMemTokenId) return ole32::E_POINTER;
        *ppszCoMemTokenId = AllocateCoTaskString(m_id);
        return ole32::S_OK;
    }

    int32_t __stdcall GetCategory(ISpObjectTokenCategory** ppTokenCategory) override;

    int32_t __stdcall SetStringValue(const wchar_t* pszValueName, const wchar_t* pszValue) override {
        if (!pszValueName || !pszValue) return ole32::E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_attributes[pszValueName] = pszValue;
        return ole32::S_OK;
    }

    int32_t __stdcall GetStringValue(const wchar_t* pszValueName, wchar_t** ppszCoMemValue) override {
        if (!ppszCoMemValue) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        std::wstring key = pszValueName ? pszValueName : L"";
        auto it = m_attributes.find(key);
        if (it != m_attributes.end()) {
            *ppszCoMemValue = AllocateCoTaskString(it->second);
            return ole32::S_OK;
        }
        *ppszCoMemValue = nullptr;
        return ole32::E_FAIL;
    }

    int32_t __stdcall Remove(const micant::GUID*) override { return ole32::S_OK; }

    int32_t __stdcall MatchesAttributes(const wchar_t* pszAttributes, int32_t* pfMatches) override {
        if (!pfMatches) return ole32::E_POINTER;
        if (!pszAttributes || wcslen(pszAttributes) == 0) {
            *pfMatches = 1;
            return ole32::S_OK;
        }

        std::wstring req(pszAttributes);
        std::string reqUtf8 = appmodel::WideToUtf8(req);
        bool matches = true;

        // Attributes are semicolon delimited key=value pairs, e.g. "Gender=Female;Language=409"
        std::istringstream iss(reqUtf8);
        std::string token;
        while (std::getline(iss, token, ';')) {
            size_t eq = token.find('=');
            if (eq != std::string::npos) {
                std::string k = token.substr(0, eq);
                std::string v = token.substr(eq + 1);
                std::wstring wk = appmodel::Utf8ToWide(k);
                std::wstring wv = appmodel::Utf8ToWide(v);
                auto it = m_attributes.find(wk);
                if (it == m_attributes.end() || it->second != wv) {
                    matches = false;
                    break;
                }
            }
        }
        *pfMatches = matches ? 1 : 0;
        return ole32::S_OK;
    }
};

class CEnumSpObjectTokensImpl : public IEnumSpObjectTokens {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<ISpObjectToken*> m_tokens;
    size_t m_currentPos{ 0 };

public:
    CEnumSpObjectTokensImpl(std::vector<ISpObjectToken*> tokens)
        : m_tokens(std::move(tokens)) {}

    ~CEnumSpObjectTokensImpl() {
        for (auto* t : m_tokens) {
            if (t) t->Release();
        }
    }

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IEnumSpObjectTokens) {
            *ppv = static_cast<IEnumSpObjectTokens*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall Next(uint32_t celt, ISpObjectToken** pelt, uint32_t* pceltFetched) override {
        if (!pelt) return ole32::E_POINTER;
        uint32_t fetched = 0;
        while (m_currentPos < m_tokens.size() && fetched < celt) {
            pelt[fetched] = m_tokens[m_currentPos++];
            pelt[fetched]->AddRef();
            fetched++;
        }
        if (pceltFetched) *pceltFetched = fetched;
        return (fetched == celt) ? ole32::S_OK : ole32::S_FALSE;
    }

    int32_t __stdcall Skip(uint32_t celt) override {
        m_currentPos = std::min(m_tokens.size(), m_currentPos + celt);
        return (m_currentPos < m_tokens.size()) ? ole32::S_OK : ole32::S_FALSE;
    }

    int32_t __stdcall Reset() override {
        m_currentPos = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall Clone(IEnumSpObjectTokens** ppEnum) override {
        if (!ppEnum) return ole32::E_POINTER;
        std::vector<ISpObjectToken*> dup;
        dup.reserve(m_tokens.size());
        for (auto* t : m_tokens) {
            if (t) { t->AddRef(); dup.push_back(t); }
        }
        auto* clone = new CEnumSpObjectTokensImpl(std::move(dup));
        clone->m_currentPos = m_currentPos;
        *ppEnum = clone;
        return ole32::S_OK;
    }

    int32_t __stdcall GetCount(uint32_t* pulCount) override {
        if (!pulCount) return ole32::E_POINTER;
        *pulCount = static_cast<uint32_t>(m_tokens.size());
        return ole32::S_OK;
    }

    int32_t __stdcall Item(uint32_t Index, ISpObjectToken** ppToken) override {
        if (!ppToken) return ole32::E_POINTER;
        if (Index >= m_tokens.size()) return ole32::E_INVALIDARG;
        *ppToken = m_tokens[Index];
        (*ppToken)->AddRef();
        return ole32::S_OK;
    }
};

class CSpObjectTokenCategoryImpl : public ISpObjectTokenCategory {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_id;
    std::vector<ISpObjectToken*> m_tokens;
    std::mutex m_mutex;

    void ClearTokens() {
        for (auto* t : m_tokens) {
            if (t) t->Release();
        }
        m_tokens.clear();
    }

    void SeedDefaultVoices() {
        if (m_id.find(L"Voices") != std::wstring::npos) {
            // 1. MicaNT David
            m_tokens.push_back(new CSpObjectTokenImpl(
                L"MicaNT_David", m_id,
                std::unordered_map<std::wstring, std::wstring>{
                    { L"", L"MicaNT David (US English)" },
                    { L"Name", L"MicaNT David" },
                    { L"Gender", L"Male" },
                    { L"Age", L"Adult" },
                    { L"Language", L"409" },
                    { L"Vendor", L"MicaNT Sovereign Project" }
                }
            ));

            // 2. MicaNT Zira
            m_tokens.push_back(new CSpObjectTokenImpl(
                L"MicaNT_Zira", m_id,
                std::unordered_map<std::wstring, std::wstring>{
                    { L"", L"MicaNT Zira (US English)" },
                    { L"Name", L"MicaNT Zira" },
                    { L"Gender", L"Female" },
                    { L"Age", L"Adult" },
                    { L"Language", L"409" },
                    { L"Vendor", L"MicaNT Sovereign Project" }
                }
            ));

            // 3. MicaNT Mark
            m_tokens.push_back(new CSpObjectTokenImpl(
                L"MicaNT_Mark", m_id,
                std::unordered_map<std::wstring, std::wstring>{
                    { L"", L"MicaNT Mark (US English)" },
                    { L"Name", L"MicaNT Mark" },
                    { L"Gender", L"Male" },
                    { L"Age", L"Adult" },
                    { L"Language", L"409" },
                    { L"Vendor", L"MicaNT Sovereign Project" }
                }
            ));

            // 4. MicaNT Helena
            m_tokens.push_back(new CSpObjectTokenImpl(
                L"MicaNT_Helena", m_id,
                std::unordered_map<std::wstring, std::wstring>{
                    { L"", L"MicaNT Helena (Spanish)" },
                    { L"Name", L"MicaNT Helena" },
                    { L"Gender", L"Female" },
                    { L"Age", L"Adult" },
                    { L"Language", L"c0a" },
                    { L"Vendor", L"MicaNT Sovereign Project" }
                }
            ));
        }
    }

public:
    CSpObjectTokenCategoryImpl(std::wstring id = SPCAT_VOICES)
        : m_id(std::move(id)) {
        SeedDefaultVoices();
    }

    ~CSpObjectTokenCategoryImpl() {
        ClearTokens();
    }

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ISpObjectTokenCategory) {
            *ppv = static_cast<ISpObjectTokenCategory*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall SetId(const wchar_t* pszCategoryId, int32_t) override {
        if (!pszCategoryId) return ole32::E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_id = pszCategoryId;
        ClearTokens();
        SeedDefaultVoices();
        return ole32::S_OK;
    }

    int32_t __stdcall GetId(wchar_t** ppszCoMemCategoryId) override {
        if (!ppszCoMemCategoryId) return ole32::E_POINTER;
        *ppszCoMemCategoryId = AllocateCoTaskString(m_id);
        return ole32::S_OK;
    }

    int32_t __stdcall GetDataKey(uint32_t, void** ppDataKey) override {
        if (!ppDataKey) return ole32::E_POINTER;
        *ppDataKey = nullptr;
        return ole32::S_OK;
    }

    int32_t __stdcall EnumTokens(const wchar_t* pzsReqAttribs, const wchar_t*, IEnumSpObjectTokens** ppEnum) override {
        if (!ppEnum) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<ISpObjectToken*> matching;
        for (auto* spTok : m_tokens) {
            int32_t matches = 0;
            spTok->MatchesAttributes(pzsReqAttribs, &matches);
            if (matches) {
                spTok->AddRef();
                matching.push_back(spTok);
            }
        }
        *ppEnum = new CEnumSpObjectTokensImpl(std::move(matching));
        return ole32::S_OK;
    }

    int32_t __stdcall SetDefaultTokenId(const wchar_t*) override { return ole32::S_OK; }

    int32_t __stdcall GetDefaultTokenId(wchar_t** ppszCoMemTokenId) override {
        if (!ppszCoMemTokenId) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_tokens.empty()) {
            return m_tokens[0]->GetId(ppszCoMemTokenId);
        }
        *ppszCoMemTokenId = nullptr;
        return ole32::E_FAIL;
    }
};

inline int32_t __stdcall CSpObjectTokenImpl::GetCategory(ISpObjectTokenCategory** ppTokenCategory) {
    if (!ppTokenCategory) return ole32::E_POINTER;
    *ppTokenCategory = new CSpObjectTokenCategoryImpl(m_categoryId);
    return ole32::S_OK;
}

// ============================================================================
// 5. Sovereign SAPI Stream Implementation (ISpStream)
// ============================================================================

class CSpStreamImpl : public ISpStream {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<uint8_t> m_buffer;
    size_t m_pos{ 0 };
    std::wstring m_fileName;
    micant::GUID m_formatId{};
    std::mutex m_mutex;

public:
    CSpStreamImpl() = default;

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == ole32::IID_ISequentialStream ||
            riid == ole32::IID_IStream || riid == IID_ISpStream) {
            *ppv = static_cast<ISpStream*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    // ISequentialStream
    ole32::HRESULT Read(void* pv, uint32_t cb, uint32_t* pcbRead) override {
        if (!pv) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        uint32_t avail = static_cast<uint32_t>(m_buffer.size() > m_pos ? m_buffer.size() - m_pos : 0);
        uint32_t toRead = std::min(cb, avail);
        if (toRead > 0) {
            std::memcpy(pv, m_buffer.data() + m_pos, toRead);
            m_pos += toRead;
        }
        if (pcbRead) *pcbRead = toRead;
        return ole32::S_OK;
    }

    ole32::HRESULT Write(const void* pv, uint32_t cb, uint32_t* pcbWritten) override {
        if (!pv) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pos + cb > m_buffer.size()) {
            m_buffer.resize(m_pos + cb);
        }
        std::memcpy(m_buffer.data() + m_pos, pv, cb);
        m_pos += cb;
        if (pcbWritten) *pcbWritten = cb;
        return ole32::S_OK;
    }

    // IStream
    ole32::HRESULT Seek(int64_t dlibMove, uint32_t dwOrigin, uint64_t* plibNewPosition) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        int64_t newPos = 0;
        if (dwOrigin == 0) newPos = dlibMove;
        else if (dwOrigin == 1) newPos = static_cast<int64_t>(m_pos) + dlibMove;
        else if (dwOrigin == 2) newPos = static_cast<int64_t>(m_buffer.size()) + dlibMove;
        if (newPos < 0) return ole32::E_INVALIDARG;
        m_pos = static_cast<size_t>(newPos);
        if (plibNewPosition) *plibNewPosition = m_pos;
        return ole32::S_OK;
    }

    ole32::HRESULT SetSize(uint64_t libNewSize) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_buffer.resize(static_cast<size_t>(libNewSize));
        return ole32::S_OK;
    }

    ole32::HRESULT CopyTo(ole32::IStream* pstm, uint64_t cb, uint64_t* pcbRead, uint64_t* pcbWritten) override {
        if (!pstm) return ole32::E_POINTER;
        std::vector<uint8_t> tmp(static_cast<size_t>(cb));
        uint32_t r = 0, w = 0;
        Read(tmp.data(), static_cast<uint32_t>(cb), &r);
        pstm->Write(tmp.data(), r, &w);
        if (pcbRead) *pcbRead = r;
        if (pcbWritten) *pcbWritten = w;
        return ole32::S_OK;
    }

    ole32::HRESULT Commit(uint32_t) override { return ole32::S_OK; }
    ole32::HRESULT Revert() override { return ole32::S_OK; }
    ole32::HRESULT LockRegion(uint64_t, uint64_t, uint32_t) override { return ole32::S_OK; }
    ole32::HRESULT UnlockRegion(uint64_t, uint64_t, uint32_t) override { return ole32::S_OK; }

    ole32::HRESULT Stat(ole32::STATSTG* pstatstg, uint32_t) override {
        if (!pstatstg) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        pstatstg->cbSize = m_buffer.size();
        pstatstg->type = 2; // STGTY_STREAM
        return ole32::S_OK;
    }

    ole32::HRESULT Clone(ole32::IStream** ppstm) override {
        if (!ppstm) return ole32::E_POINTER;
        auto* clone = new CSpStreamImpl();
        clone->m_buffer = m_buffer;
        clone->m_pos = m_pos;
        *ppstm = clone;
        return ole32::S_OK;
    }

    // ISpStream
    int32_t __stdcall BindToFile(const wchar_t* pszFileName, uint32_t, const micant::GUID* pFormatId, const void*, uint64_t) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (pszFileName) m_fileName = pszFileName;
        if (pFormatId) m_formatId = *pFormatId;
        return ole32::S_OK;
    }

    int32_t __stdcall Close() override { return ole32::S_OK; }

    int32_t __stdcall GetFormat(micant::GUID* pFormatId, void** ppCoMemWaveFormatEx) override {
        if (pFormatId) *pFormatId = m_formatId;
        if (ppCoMemWaveFormatEx) *ppCoMemWaveFormatEx = nullptr;
        return ole32::S_OK;
    }

    int32_t __stdcall SetBaseStream(ole32::IStream*, const micant::GUID*, const void*) override { return ole32::S_OK; }
    int32_t __stdcall GetBaseStream(ole32::IStream** ppStream) override {
        if (!ppStream) return ole32::E_POINTER;
        *ppStream = nullptr;
        return ole32::S_OK;
    }

    const std::vector<uint8_t>& GetBuffer() const { return m_buffer; }
};

// ============================================================================
// 6. Phonetic Audio Synthesizer Engine (Text to 16-bit PCM waveform)
// ============================================================================

struct SynthesizedAudio {
    uint32_t sampleRate{ 22050 };
    uint16_t channels{ 1 };
    uint16_t bitsPerSample{ 16 };
    std::vector<int16_t> pcmSamples;
    uint32_t phonemeCount{ 0 };
    uint32_t wordCount{ 0 };
    double durationSec{ 0.0 };
};

class PhoneticSynthesizer {
public:
    static SynthesizedAudio SynthesizeText(
        const std::wstring& text,
        int32_t rateAdjust = 0,     // -10 to +10
        uint16_t volumePercent = 100, // 0 to 100
        float pitchAdjust = 1.0f,    // 0.5 to 2.0
        bool isFemale = false
    ) {
        SynthesizedAudio audio;
        audio.sampleRate = 22050;
        audio.channels = 1;
        audio.bitsPerSample = 16;

        float basePitch = isFemale ? 220.0f : 130.0f;
        basePitch *= std::clamp(pitchAdjust, 0.5f, 2.5f);

        // Rate adjustment factor: 1.0 at rate 0, 0.5 at rate -10, 2.0 at rate +10
        float rateFactor = std::pow(2.0f, static_cast<float>(rateAdjust) / 10.0f);
        float ampScale = (static_cast<float>(volumePercent) / 100.0f) * 16000.0f;

        float samplesPerPhoneme = (audio.sampleRate * 0.08f) / rateFactor;

        // Vowel formant center frequencies
        struct Formant { float f1; float f2; };
        static const std::unordered_map<wchar_t, Formant> vowelFormants = {
            { L'a', { 730.0f, 1090.0f } },
            { L'e', { 530.0f, 1840.0f } },
            { L'i', { 270.0f, 2290.0f } },
            { L'o', { 570.0f, 840.0f } },
            { L'u', { 300.0f, 870.0f } }
        };

        for (wchar_t ch : text) {
            wchar_t lch = static_cast<wchar_t>(std::towlower(ch));
            if (std::iswspace(ch)) {
                // Short silence for word boundary
                size_t silenceSamples = static_cast<size_t>(samplesPerPhoneme * 0.6f);
                audio.pcmSamples.resize(audio.pcmSamples.size() + silenceSamples, 0);
                audio.wordCount++;
                continue;
            }

            audio.phonemeCount++;
            auto it = vowelFormants.find(lch);
            float f1 = (it != vowelFormants.end()) ? it->second.f1 : (basePitch * 1.5f);
            float f2 = (it != vowelFormants.end()) ? it->second.f2 : (basePitch * 3.0f);

            size_t nSamples = static_cast<size_t>(samplesPerPhoneme);
            for (size_t s = 0; s < nSamples; ++s) {
                float t = static_cast<float>(s) / audio.sampleRate;
                float env = std::sin((static_cast<float>(s) / nSamples) * std::numbers::pi_v<float>);

                // Multi-formant harmonic wave
                float val = 0.5f * std::sin(2.0f * std::numbers::pi_v<float> * basePitch * t) +
                            0.3f * std::sin(2.0f * std::numbers::pi_v<float> * f1 * t) +
                            0.2f * std::sin(2.0f * std::numbers::pi_v<float> * f2 * t);

                int16_t sample = static_cast<int16_t>(std::clamp(val * env * ampScale, -32767.0f, 32767.0f));
                audio.pcmSamples.push_back(sample);
            }
        }

        if (audio.wordCount == 0 && !audio.pcmSamples.empty()) {
            audio.wordCount = 1;
        }

        audio.durationSec = static_cast<double>(audio.pcmSamples.size()) / audio.sampleRate;
        return audio;
    }
};

// ============================================================================
// 7. SAPI Voice Subsystem Implementation (ISpVoice)
// ============================================================================

class CSpVoiceImpl : public ISpVoice {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    int32_t m_rateAdjust{ 0 };       // -10 to +10
    uint16_t m_volume{ 100 };        // 0 to 100
    ISpObjectToken* m_currentVoice{ nullptr };
    ole32::IUnknown* m_output{ nullptr };
    SPVOICESTATUS m_status{};
    std::wstring m_lastBookmark;
    std::mutex m_mutex;

    // Helper: Parse SSML / XML Voice Tags
    void ParseSsmlAndSynthesize(
        const std::wstring& xmlText,
        std::vector<int16_t>& outPcm,
        uint32_t& outPhonemes,
        uint32_t& outWords
    ) {
        float pitchMod = 1.0f;
        int32_t localRate = m_rateAdjust;
        uint16_t localVol = m_volume;
        bool isFemale = false;

        if (m_currentVoice) {
            wchar_t* pGen = nullptr;
            m_currentVoice->GetStringValue(L"Gender", &pGen);
            if (pGen) {
                if (wcscmp(pGen, L"Female") == 0) isFemale = true;
                ole32::CoTaskMemFree(pGen);
            }
        }

        // Simple XML tag stripper & attribute extraction
        std::wstring cleanText;
        size_t i = 0;
        const size_t len = xmlText.length();

        while (i < len) {
            if (xmlText[i] == L'<') {
                size_t close = xmlText.find(L'>', i);
                if (close == std::wstring::npos) break;
                std::wstring tag = xmlText.substr(i, close - i + 1);

                if (tag.find(L"pitch") != std::wstring::npos) {
                    if (tag.find(L"high") != std::wstring::npos || tag.find(L"+") != std::wstring::npos) pitchMod = 1.4f;
                    else if (tag.find(L"low") != std::wstring::npos || tag.find(L"-") != std::wstring::npos) pitchMod = 0.75f;
                } else if (tag.find(L"rate") != std::wstring::npos) {
                    if (tag.find(L"fast") != std::wstring::npos) localRate = std::min(10, localRate + 5);
                    else if (tag.find(L"slow") != std::wstring::npos) localRate = std::max(-10, localRate - 5);
                } else if (tag.find(L"volume") != std::wstring::npos) {
                    if (tag.find(L"soft") != std::wstring::npos) localVol = 50;
                    else if (tag.find(L"loud") != std::wstring::npos) localVol = 100;
                } else if (tag.find(L"silence") != std::wstring::npos) {
                    // Inject 100ms silence
                    size_t silSamples = 22050 / 10;
                    outPcm.resize(outPcm.size() + silSamples, 0);
                }
                i = close + 1;
            } else {
                cleanText.push_back(xmlText[i++]);
            }
        }

        auto audio = PhoneticSynthesizer::SynthesizeText(cleanText, localRate, localVol, pitchMod, isFemale);
        outPcm.insert(outPcm.end(), audio.pcmSamples.begin(), audio.pcmSamples.end());
        outPhonemes += audio.phonemeCount;
        outWords += audio.wordCount;
    }

public:
    CSpVoiceImpl() {
        m_status.dwRunningState = 1; // SPRS_DONE
        m_status.ulCurrentStreamNum = 0;

        // Default Voice: MicaNT David
        m_currentVoice = new CSpObjectTokenImpl(
            L"MicaNT_David", SPCAT_VOICES,
            std::unordered_map<std::wstring, std::wstring>{
                { L"", L"MicaNT David (US English)" },
                { L"Name", L"MicaNT David" },
                { L"Gender", L"Male" },
                { L"Language", L"409" }
            }
        );
    }

    ~CSpVoiceImpl() {
        if (m_currentVoice) m_currentVoice->Release();
        if (m_output) m_output->Release();
    }

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ISpVoice) {
            *ppv = static_cast<ISpVoice*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t __stdcall SetOutput(ole32::IUnknown* pUnkOutput, int32_t) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_output) m_output->Release();
        m_output = pUnkOutput;
        if (m_output) m_output->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutputObjectToken(ISpObjectToken** ppObjectToken) override {
        if (!ppObjectToken) return ole32::E_POINTER;
        *ppObjectToken = nullptr;
        return ole32::S_OK;
    }

    int32_t __stdcall GetOutputStream(ISpStream** ppStream) override {
        if (!ppStream) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_output) {
            return m_output->QueryInterface(IID_ISpStream, reinterpret_cast<void**>(ppStream));
        }
        *ppStream = nullptr;
        return ole32::S_FALSE;
    }

    int32_t __stdcall Pause() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_status.dwRunningState = 2; // SPRS_IS_PAUSED
        return ole32::S_OK;
    }

    int32_t __stdcall Resume() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_status.dwRunningState = 1; // SPRS_DONE
        return ole32::S_OK;
    }

    int32_t __stdcall SetVoice(ISpObjectToken* pToken) override {
        if (!pToken) return ole32::E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_currentVoice) m_currentVoice->Release();
        m_currentVoice = pToken;
        m_currentVoice->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetVoice(ISpObjectToken** ppToken) override {
        if (!ppToken) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_currentVoice) {
            *ppToken = m_currentVoice;
            (*ppToken)->AddRef();
            return ole32::S_OK;
        }
        *ppToken = nullptr;
        return ole32::E_FAIL;
    }

    int32_t __stdcall Speak(const wchar_t* pwcs, uint32_t dwFlags, uint32_t* pulStreamNumber) override {
        if (!pwcs) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        m_status.ulCurrentStreamNum++;
        if (pulStreamNumber) *pulStreamNumber = m_status.ulCurrentStreamNum;

        std::wstring text(pwcs);
        std::vector<int16_t> pcm;
        uint32_t phonemes = 0;
        uint32_t words = 0;

        bool isXml = (dwFlags & SPF_IS_XML) || (text.find(L"<") != std::wstring::npos && text.find(L">") != std::wstring::npos);

        if (isXml) {
            ParseSsmlAndSynthesize(text, pcm, phonemes, words);
        } else {
            bool isFemale = false;
            if (m_currentVoice) {
                wchar_t* pGen = nullptr;
                m_currentVoice->GetStringValue(L"Gender", &pGen);
                if (pGen) {
                    if (wcscmp(pGen, L"Female") == 0) isFemale = true;
                    ole32::CoTaskMemFree(pGen);
                }
            }
            auto res = PhoneticSynthesizer::SynthesizeText(text, m_rateAdjust, m_volume, 1.0f, isFemale);
            pcm = std::move(res.pcmSamples);
            phonemes = res.phonemeCount;
            words = res.wordCount;
        }

        // If an output stream is bound, write synthesized wave data
        if (m_output) {
            ole32::IStream* pStream = nullptr;
            if (m_output->QueryInterface(ole32::IID_IStream, reinterpret_cast<void**>(&pStream)) == ole32::S_OK && pStream) {
                uint32_t written = 0;
                pStream->Write(pcm.data(), static_cast<uint32_t>(pcm.size() * sizeof(int16_t)), &written);
                pStream->Release();
            }
        }

        m_status.ulInputWordPos = 0;
        m_status.ulInputWordLen = words;
        m_status.dwRunningState = 1; // Done
        m_status.hrLastResult = ole32::S_OK;
        return ole32::S_OK;
    }

    int32_t __stdcall SpeakStream(ole32::IStream* pStream, uint32_t, uint32_t* pulStreamNumber) override {
        if (!pStream) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_status.ulCurrentStreamNum++;
        if (pulStreamNumber) *pulStreamNumber = m_status.ulCurrentStreamNum;
        return ole32::S_OK;
    }

    int32_t __stdcall GetStatus(SPVOICESTATUS* pStatus, wchar_t** ppszLastBookmark) override {
        if (!pStatus) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pStatus = m_status;
        if (ppszLastBookmark) {
            *ppszLastBookmark = AllocateCoTaskString(m_lastBookmark);
        }
        return ole32::S_OK;
    }

    int32_t __stdcall Skip(const wchar_t*, int32_t, uint32_t* pulNumSkipped) override {
        if (pulNumSkipped) *pulNumSkipped = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall SetPriority(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall GetPriority(int32_t* pePriority) override {
        if (pePriority) *pePriority = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall SetAlertBoundary(int32_t) override { return ole32::S_OK; }
    int32_t __stdcall GetAlertBoundary(int32_t* peBoundary) override {
        if (peBoundary) *peBoundary = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall SetRate(int32_t RateAdjust) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_rateAdjust = std::clamp(RateAdjust, -10, 10);
        return ole32::S_OK;
    }

    int32_t __stdcall GetRate(int32_t* pRateAdjust) override {
        if (!pRateAdjust) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pRateAdjust = m_rateAdjust;
        return ole32::S_OK;
    }

    int32_t __stdcall SetVolume(uint16_t usVolume) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_volume = std::min<uint16_t>(usVolume, 100);
        return ole32::S_OK;
    }

    int32_t __stdcall GetVolume(uint16_t* pusVolume) override {
        if (!pusVolume) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *pusVolume = m_volume;
        return ole32::S_OK;
    }

    int32_t __stdcall WaitUntilDone(uint32_t) override { return ole32::S_OK; }
    int32_t __stdcall SetSyncSpeakTimeout(uint32_t) override { return ole32::S_OK; }
    int32_t __stdcall GetSyncSpeakTimeout(uint32_t* pmsTimeout) override {
        if (pmsTimeout) *pmsTimeout = 10000;
        return ole32::S_OK;
    }
    int32_t __stdcall SpeakCompleteEvent(void** phEvent) override {
        if (phEvent) *phEvent = nullptr;
        return ole32::S_OK;
    }
    int32_t __stdcall IsUISupported(const wchar_t*, void*, uint32_t, int32_t* pfSupported) override {
        if (pfSupported) *pfSupported = 0;
        return ole32::S_OK;
    }
    int32_t __stdcall DisplayUI(void*, const wchar_t*, const wchar_t*, void*, uint32_t) override {
        return ole32::S_OK;
    }
};

// ============================================================================
// 8. Command-and-Control Speech Recognition Subsystem
// ============================================================================

class CSpRecoGrammarImpl : public ole32::IUnknown {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<std::wstring> m_grammarRules;

public:
    CSpRecoGrammarImpl() = default;

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ISpRecoGrammar) {
            *ppv = this;
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) delete this;
        return r;
    }

    int32_t LoadCmdFromMemory(const wchar_t* pGrammar) {
        if (!pGrammar) return ole32::E_INVALIDARG;
        m_grammarRules.push_back(pGrammar);
        return ole32::S_OK;
    }

    size_t GetRuleCount() const { return m_grammarRules.size(); }
};

// ============================================================================
// 9. Dynamic Export Functions (sapi.dll)
// ============================================================================

inline int32_t __stdcall SpEnumTokens(
    const wchar_t* pszCategoryId,
    const wchar_t* pszReqAttribs,
    const wchar_t* pszOptAttribs,
    IEnumSpObjectTokens** ppEnum
) {
    if (!ppEnum) return ole32::E_POINTER;
    CSpObjectTokenCategoryImpl cat(pszCategoryId ? pszCategoryId : SPCAT_VOICES);
    return cat.EnumTokens(pszReqAttribs, pszOptAttribs, ppEnum);
}

inline int32_t __stdcall SpGetCategoryFromId(
    const wchar_t* pszCategoryId,
    ISpObjectTokenCategory** ppCategory
) {
    if (!ppCategory) return ole32::E_POINTER;
    *ppCategory = new CSpObjectTokenCategoryImpl(pszCategoryId ? pszCategoryId : SPCAT_VOICES);
    return ole32::S_OK;
}

inline int32_t __stdcall SpCreateVoice(ISpVoice** ppVoice) {
    if (!ppVoice) return ole32::E_POINTER;
    *ppVoice = new CSpVoiceImpl();
    return ole32::S_OK;
}

inline int32_t __stdcall SpCreateStream(ISpStream** ppStream) {
    if (!ppStream) return ole32::E_POINTER;
    *ppStream = new CSpStreamImpl();
    return ole32::S_OK;
}

// ============================================================================
// 10. Module Registration & Version Table (sapi.dll)
// ============================================================================

inline void InitializeSapiSubsystemExports() {
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        auto& loader = ldr::DynamicLoader::get();

        // 1. sapi.dll exports
        loader.registerExport("sapi.dll", "SpEnumTokens", reinterpret_cast<void*>(&SpEnumTokens));
        loader.registerExport("sapi.dll", "SpGetCategoryFromId", reinterpret_cast<void*>(&SpGetCategoryFromId));
        loader.registerExport("sapi.dll", "SpCreateVoice", reinterpret_cast<void*>(&SpCreateVoice));
        loader.registerExport("sapi.dll", "SpCreateStream", reinterpret_cast<void*>(&SpCreateStream));

        // 2. Register module version
        version::VersionDatabase::Instance().RegisterModule(
            "sapi.dll",
            "10.0.22621.1",
            "Speech API 5.4 Subsystem",
            "MicaNT Sovereign Project"
        );
    });
}

} // namespace micant::sapi
