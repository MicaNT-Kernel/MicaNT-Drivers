// ============================================================================
// MicaNT: Windows Text Services Framework (TSF) & Modern IME Subsystem
// (include/micant/tsf.hpp)
//
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/win32metadata (Windows.Win32.UI.TextServices)
//   - https://github.com/microsoft/win32metadata (Windows.Win32.UI.Input.Ime)
//   - Text Services Framework (TSF) 1.0/2.0 specifications
//   - Input Method Manager (IMM32) Win32 Subsystem
//
// Subsystem Overview:
//   tsf.hpp provides the unified Text Services Framework and Input Method
//   Manager (IMM32) for MicaNT.
//   Supports:
//     - ITfThreadMgr (central thread text manager & focus coordinator)
//     - ITfDocumentMgr (document manager & context stack)
//     - ITfContext (text store binding, edit sessions, selections)
//     - ITfRange (text navigation, anchor extents, text manipulation)
//     - ITfCompartmentMgr & ITfCompartment (IME status & conversion states)
//     - ITfInputProcessorProfiles (TIP registration & language profiles)
//     - ITfCategoryMgr (GUID categorization & atom mapping)
//     - ITfInputScope (modern soft-keyboard input scope constraints)
//     - IMM32 Win32 API Layer (HIMC, composition strings, candidate lists)
//
// Core Dynamic Modules:
//   - msctf.dll (Text Services Framework Engine)
//   - imm32.dll (Input Method Manager Engine)
//
// Trademark & Nominative Fair Use Notice:
//   Windows, Text Services Framework, TSF, and IMM32 are registered trademarks
//   of Microsoft Corp. MicaNT is an independent sovereign clean-room implementation
//   engineered for binary interoperability (*Google LLC v. Oracle America, Inc.*).
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ole32.hpp"
#include "user32.hpp"
#include "wcs.hpp"
#include "ldr.hpp"
#include "version.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <iostream>

namespace micant::tsf {

// ============================================================================
// 1. TSF & IMM32 GUIDs & Constants
// ============================================================================

inline constexpr GUID CLSID_TF_ThreadMgr = {
    0x0848833d, 0x13fb, 0x4ad4, { 0x91, 0x84, 0x64, 0x63, 0xdb, 0x13, 0x11, 0xa0 }
};

inline constexpr GUID CLSID_TF_InputProcessorProfiles = {
    0x33c53a50, 0xf456, 0x4884, { 0xb0, 0x49, 0x85, 0xfd, 0x64, 0x3e, 0xcf, 0xed }
};

inline constexpr GUID CLSID_TF_CategoryMgr = {
    0xa4b544a1, 0x438d, 0x4b41, { 0x91, 0xf3, 0xbe, 0x70, 0x55, 0x40, 0xdb, 0x85 }
};

inline constexpr GUID IID_ITfThreadMgr = {
    0xaa80e7f0, 0x2021, 0x11d2, { 0x93, 0xe0, 0x00, 0x60, 0xb0, 0x67, 0xb8, 0x6e }
};

inline constexpr GUID IID_ITfDocumentMgr = {
    0xaa80e7f4, 0x2021, 0x11d2, { 0x93, 0xe0, 0x00, 0x60, 0xb0, 0x67, 0xb8, 0x6e }
};

inline constexpr GUID IID_ITfContext = {
    0xaa80e7fd, 0x2021, 0x11d2, { 0x93, 0xe0, 0x00, 0x60, 0xb0, 0x67, 0xb8, 0x6e }
};

inline constexpr GUID IID_ITfEditSession = {
    0xaa80e803, 0x2021, 0x11d2, { 0x93, 0xe0, 0x00, 0x60, 0xb0, 0x67, 0xb8, 0x6e }
};

inline constexpr GUID IID_ITfRange = {
    0xaa80e7ff, 0x2021, 0x11d2, { 0x93, 0xe0, 0x00, 0x60, 0xb0, 0x67, 0xb8, 0x6e }
};

inline constexpr GUID IID_ITfCompartmentMgr = {
    0x7dcf57ac, 0x8127, 0x4a70, { 0x94, 0x1e, 0x9f, 0x3f, 0x44, 0xe4, 0x1e, 0xe4 }
};

inline constexpr GUID IID_ITfCompartment = {
    0xbb08f7a9, 0x607a, 0x4384, { 0xa6, 0x95, 0x9f, 0x30, 0xa6, 0x03, 0xd2, 0x10 }
};

inline constexpr GUID IID_ITfInputProcessorProfiles = {
    0x1f0288c5, 0xd43a, 0x497f, { 0x82, 0x0c, 0xd3, 0xd1, 0x23, 0x24, 0x41, 0x44 }
};

inline constexpr GUID IID_ITfCategoryMgr = {
    0xc3acefb5, 0xf69d, 0x4905, { 0x92, 0x8f, 0xdb, 0xa9, 0xb5, 0xa4, 0x22, 0x65 }
};

inline constexpr GUID IID_ITfInputScope = {
    0xfde1eaf0, 0x4b78, 0x407c, { 0x87, 0x92, 0x8a, 0x64, 0x34, 0xa4, 0x00, 0xc2 }
};

// Global Compartment GUIDs
inline constexpr GUID GUID_COMPARTMENT_KEYBOARD_OPENCLOSE = {
    0xa3c04d1a, 0x4c2a, 0x478e, { 0x98, 0x76, 0x99, 0x74, 0x8b, 0x44, 0xa8, 0x77 }
};

inline constexpr GUID GUID_COMPARTMENT_KEYBOARD_INPUTMODE_CONVERSION = {
    0xccf05dd8, 0x4a87, 0x11d7, { 0xb6, 0xe8, 0x00, 0x4b, 0x24, 0x4b, 0x8a, 0x78 }
};

inline constexpr GUID GUID_COMPARTMENT_KEYBOARD_INPUTMODE_SENTENCE = {
    0xccf05dd9, 0x4a87, 0x11d7, { 0xb6, 0xe8, 0x00, 0x4b, 0x24, 0x4b, 0x8a, 0x78 }
};

struct GUIDHasher {
    size_t operator()(const GUID& g) const noexcept {
        uint64_t low = (static_cast<uint64_t>(g.Data1) << 32) | (static_cast<uint64_t>(g.Data2) << 16) | g.Data3;
        uint64_t high = 0;
        std::memcpy(&high, g.Data4, sizeof(high));
        return std::hash<uint64_t>{}(low ^ high);
    }
};

struct GUIDComparer {
    bool operator()(const GUID& a, const GUID& b) const noexcept {
        return std::memcmp(&a, &b, sizeof(GUID)) == 0;
    }
};

struct POINT {
    int32_t x;
    int32_t y;
};

struct RECT {
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
};

using HKL = void*;

// ============================================================================
// 2. Types, Enums & Structs
// ============================================================================

using TfClientId    = uint32_t;
using TfEditCookie  = uint32_t;
using TfGuidAtom    = uint32_t;
using HIMC          = void*;

enum TfAnchor : uint32_t {
    TF_ANCHOR_START = 0,
    TF_ANCHOR_END   = 1
};

enum TfGravity : uint32_t {
    TF_GRAVITY_BACKWARD = 0,
    TF_GRAVITY_FORWARD  = 1
};

enum TfShiftDir : uint32_t {
    TF_SD_BACKWARD = 0,
    TF_SD_FORWARD  = 1
};

enum InputScope : int32_t {
    IS_DEFAULT                      = 0,
    IS_URL                          = 1,
    IS_FILE_FULLFILEPATH            = 2,
    IS_FILE_FILENAME                = 3,
    IS_EMAIL_USERNAME               = 4,
    IS_EMAIL_SMTPADDRESS            = 5,
    IS_LOGONNAME                    = 6,
    IS_PERSONALNAME_FULLNAME        = 7,
    IS_PERSONALNAME_PREFIX          = 8,
    IS_PERSONALNAME_GIVENNAME       = 9,
    IS_PERSONALNAME_MIDDLENAME      = 10,
    IS_PERSONALNAME_SURNAME         = 11,
    IS_PERSONALNAME_SUFFIX          = 12,
    IS_ADDRESS_FULLPOSTALADDRESS    = 13,
    IS_ADDRESS_POSTALCODE           = 14,
    IS_ADDRESS_STREET               = 15,
    IS_ADDRESS_STATEORPROVINCE      = 16,
    IS_ADDRESS_CITY                 = 17,
    IS_ADDRESS_COUNTRYNAME          = 18,
    IS_ADDRESS_COUNTRYSHORTNAME     = 19,
    IS_CURRENCY_AMOUNTANDSYMBOL     = 20,
    IS_CURRENCY_AMOUNT              = 21,
    IS_DATE_FULLDATE                = 22,
    IS_DATE_MONTH                   = 23,
    IS_DATE_DAY                     = 24,
    IS_DATE_YEAR                    = 25,
    IS_TELEPHONE_FULLTELEPHONENUMBER= 32,
    IS_NUMERIC                      = 38,
    IS_DIGITS                       = 39,
    IS_PASSWORD                     = 40,
    IS_SEARCH                       = 50
};

// IMM32 Composition String Indices
inline constexpr uint32_t GCS_COMPREADSTR      = 0x0001;
inline constexpr uint32_t GCS_COMPREADATTR     = 0x0002;
inline constexpr uint32_t GCS_COMPREADCLAUSE   = 0x0004;
inline constexpr uint32_t GCS_COMPSTR          = 0x0008;
inline constexpr uint32_t GCS_COMPATTR         = 0x0010;
inline constexpr uint32_t GCS_COMPCLAUSE       = 0x0020;
inline constexpr uint32_t GCS_CURSORPOS        = 0x0080;
inline constexpr uint32_t GCS_DELTASTART       = 0x0100;
inline constexpr uint32_t GCS_RESULTREADSTR    = 0x0200;
inline constexpr uint32_t GCS_RESULTREADCLAUSE = 0x0400;
inline constexpr uint32_t GCS_RESULTSTR        = 0x0800;
inline constexpr uint32_t GCS_RESULTCLAUSE     = 0x1000;

// IMM32 Conversion Modes
inline constexpr uint32_t IME_CMODE_ALPHANUMERIC = 0x0000;
inline constexpr uint32_t IME_CMODE_NATIVE       = 0x0001;
inline constexpr uint32_t IME_CMODE_KATAKANA     = 0x0002;
inline constexpr uint32_t IME_CMODE_LANGUAGE     = 0x0003;
inline constexpr uint32_t IME_CMODE_FULLSHAPE    = 0x0008;
inline constexpr uint32_t IME_CMODE_ROMAN        = 0x0010;
inline constexpr uint32_t IME_CMODE_CHARCODE     = 0x0020;

struct CANDIDATELIST {
    uint32_t dwSize;
    uint32_t dwStyle;
    uint32_t dwCount;
    uint32_t dwSelection;
    uint32_t dwPageStart;
    uint32_t dwPageSize;
    uint32_t dwOffset[1];
};

struct CANDIDATEFORM {
    uint32_t    dwIndex;
    uint32_t    dwStyle;
    POINT       ptCurrentPos;
    RECT        rcArea;
};

struct COMPOSITIONFORM {
    uint32_t    dwStyle;
    POINT       ptCurrentPos;
    RECT        rcArea;
};

struct TF_SELECTION {
    class ITfRange* range;
    uint32_t        style;
};

struct TF_STATUS {
    uint32_t dwDynamicFlags;
    uint32_t dwStaticFlags;
};

struct TF_LANGUAGEPROFILE {
    GUID     clsid;
    uint16_t langid;
    GUID     catid;
    int32_t  fActive;
    GUID     guidProfile;
};

// ============================================================================
// 3. TSF COM Interfaces
// ============================================================================

class ITfRange;
class ITfContext;
class ITfDocumentMgr;
class ITfEditSession;
class ITfCompartmentMgr;
class ITfCompartment;

class ITfEditSession : public ole32::IUnknown {
public:
    virtual int32_t __stdcall DoEditSession(TfEditCookie ec) = 0;
};

class ITfRange : public ole32::IUnknown {
public:
    virtual int32_t __stdcall GetText(TfEditCookie ec, uint32_t dwFlags, wchar_t* pchText, uint32_t cchMax, uint32_t* pcch) = 0;
    virtual int32_t __stdcall SetText(TfEditCookie ec, uint32_t dwFlags, const wchar_t* pchText, int32_t cch) = 0;
    virtual int32_t __stdcall GetExtent(TfEditCookie ec, int32_t* pacpAnchor, int32_t* pcch) = 0;
    virtual int32_t __stdcall SetExtent(TfEditCookie ec, int32_t acpAnchor, int32_t cch) = 0;
    virtual int32_t __stdcall Collapse(TfEditCookie ec, TfAnchor aPos) = 0;
    virtual int32_t __stdcall Clone(ITfRange** ppClone) = 0;
};

class ITfContext : public ole32::IUnknown {
public:
    virtual int32_t __stdcall RequestEditSession(TfClientId tid, ITfEditSession* pes, uint32_t dwFlags, int32_t* phrSession) = 0;
    virtual int32_t __stdcall GetSelection(TfEditCookie ec, uint32_t ulIndex, uint32_t ulCount, TF_SELECTION* pSelection, uint32_t* pcFetched) = 0;
    virtual int32_t __stdcall SetSelection(TfEditCookie ec, uint32_t ulCount, const TF_SELECTION* pSelection) = 0;
    virtual int32_t __stdcall GetStart(TfEditCookie ec, ITfRange** ppRange) = 0;
    virtual int32_t __stdcall GetEnd(TfEditCookie ec, ITfRange** ppRange) = 0;
    virtual int32_t __stdcall GetStatus(TF_STATUS* pdcs) = 0;
    virtual int32_t __stdcall GetDocumentMgr(ITfDocumentMgr** ppDm) = 0;
};

class ITfDocumentMgr : public ole32::IUnknown {
public:
    virtual int32_t __stdcall CreateContext(TfClientId tidOwner, uint32_t dwFlags, ole32::IUnknown* punk, ITfContext** ppic, TfEditCookie* pecTextStore) = 0;
    virtual int32_t __stdcall Push(ITfContext* pic) = 0;
    virtual int32_t __stdcall Pop(uint32_t dwFlags) = 0;
    virtual int32_t __stdcall GetTop(ITfContext** ppic) = 0;
    virtual int32_t __stdcall GetBase(ITfContext** ppic) = 0;
};

class ITfCompartment : public ole32::IUnknown {
public:
    virtual int32_t __stdcall SetValue(TfClientId tid, uint32_t dwVal) = 0;
    virtual int32_t __stdcall GetValue(uint32_t* pdwVal) = 0;
};

class ITfCompartmentMgr : public ole32::IUnknown {
public:
    virtual int32_t __stdcall GetCompartment(const GUID& rguid, ITfCompartment** ppComp) = 0;
    virtual int32_t __stdcall ClearCompartment(TfClientId tid, const GUID& rguid) = 0;
};

class ITfThreadMgr : public ole32::IUnknown {
public:
    virtual int32_t __stdcall Activate(TfClientId* pClientId) = 0;
    virtual int32_t __stdcall Deactivate() = 0;
    virtual int32_t __stdcall CreateDocumentMgr(ITfDocumentMgr** ppdim) = 0;
    virtual int32_t __stdcall GetFocus(ITfDocumentMgr** ppdimFocus) = 0;
    virtual int32_t __stdcall SetFocus(ITfDocumentMgr* pdimFocus) = 0;
    virtual int32_t __stdcall AssociateFocus(win32::HWND hwnd, ITfDocumentMgr* pdimNew, ITfDocumentMgr** ppdimPrev) = 0;
    virtual int32_t __stdcall IsThreadFocus(int32_t* pfThreadFocus) = 0;
    virtual int32_t __stdcall GetGlobalCompartment(ITfCompartmentMgr** ppCompMgr) = 0;
};

class ITfInputProcessorProfiles : public ole32::IUnknown {
public:
    virtual int32_t __stdcall Register(const GUID& rclsid) = 0;
    virtual int32_t __stdcall Unregister(const GUID& rclsid) = 0;
    virtual int32_t __stdcall AddLanguageProfile(
        const GUID& rclsid,
        uint16_t langid,
        const GUID& guidProfile,
        const wchar_t* pchDesc,
        uint32_t cchDesc,
        const wchar_t* pchIconFile,
        uint32_t cchFile,
        uint32_t uIconIndex) = 0;
    virtual int32_t __stdcall GetActiveLanguageProfile(const GUID& rclsid, uint16_t* plangid, GUID* pguidProfile) = 0;
    virtual int32_t __stdcall ActivateLanguageProfile(const GUID& rclsid, uint16_t langid, const GUID& guidProfile) = 0;
};

class ITfCategoryMgr : public ole32::IUnknown {
public:
    virtual int32_t __stdcall RegisterCategory(const GUID& rclsid, const GUID& rcatid, const GUID& rguid) = 0;
    virtual int32_t __stdcall UnregisterCategory(const GUID& rclsid, const GUID& rcatid, const GUID& rguid) = 0;
    virtual int32_t __stdcall RegisterGUID(const GUID& rguid, TfGuidAtom* pguidatom) = 0;
    virtual int32_t __stdcall GetGUID(TfGuidAtom guidatom, GUID* pguid) = 0;
};

class ITfInputScope : public ole32::IUnknown {
public:
    virtual int32_t __stdcall GetInputScopes(InputScope** pprgInputScopes, uint32_t* pcCount) = 0;
    virtual int32_t __stdcall GetPhrase(wchar_t*** pppbstrPhrases, uint32_t* pcCount) = 0;
    virtual int32_t __stdcall GetRegularExpression(wchar_t** pbstrRegExp) = 0;
    virtual int32_t __stdcall GetSRGS(wchar_t** pbstrSRGS) = 0;
    virtual int32_t __stdcall GetXML(wchar_t** pbstrXML) = 0;
};

// ============================================================================
// 4. Concrete TSF Implementations
// ============================================================================

class CD2DTextStore {
public:
    std::wstring m_text;
    std::mutex   m_lock;

    CD2DTextStore() = default;
};

class CTfRangeImpl : public ITfRange {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::shared_ptr<CD2DTextStore> m_store;
    int32_t m_anchor{ 0 };
    int32_t m_extent{ 0 };

public:
    CTfRangeImpl(std::shared_ptr<CD2DTextStore> store, int32_t anchor, int32_t extent)
        : m_store(store), m_anchor(anchor), m_extent(extent) {}

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ITfRange) {
            *ppv = static_cast<ITfRange*>(this);
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

    int32_t __stdcall GetText(TfEditCookie, uint32_t, wchar_t* pchText, uint32_t cchMax, uint32_t* pcch) override {
        if (!m_store || !pcch) return ole32::E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_store->m_lock);
        int32_t start = (std::max)(0, m_anchor);
        int32_t end = (std::min)(static_cast<int32_t>(m_store->m_text.length()), m_anchor + m_extent);
        int32_t len = (std::max)(0, end - start);

        if (!pchText || cchMax == 0) {
            *pcch = static_cast<uint32_t>(len);
            return ole32::S_OK;
        }

        uint32_t copyCount = (std::min)(cchMax - 1, static_cast<uint32_t>(len));
        for (uint32_t i = 0; i < copyCount; ++i) {
            pchText[i] = m_store->m_text[start + i];
        }
        pchText[copyCount] = L'\0';
        *pcch = copyCount;
        return ole32::S_OK;
    }

    int32_t __stdcall SetText(TfEditCookie, uint32_t, const wchar_t* pchText, int32_t cch) override {
        if (!m_store) return ole32::E_FAIL;
        std::lock_guard<std::mutex> lock(m_store->m_lock);
        int32_t start = (std::max)(0, m_anchor);
        int32_t currentLen = static_cast<int32_t>(m_store->m_text.length());
        if (start > currentLen) start = currentLen;

        std::wstring newSub = (pchText && cch > 0) ? std::wstring(pchText, pchText + cch) : (pchText ? std::wstring(pchText) : L"");
        int32_t replaceLen = (std::min)(static_cast<int32_t>(m_store->m_text.length()) - start, m_extent);
        if (replaceLen < 0) replaceLen = 0;

        m_store->m_text.replace(start, replaceLen, newSub);
        m_extent = static_cast<int32_t>(newSub.length());
        return ole32::S_OK;
    }

    int32_t __stdcall GetExtent(TfEditCookie, int32_t* pacpAnchor, int32_t* pcch) override {
        if (pacpAnchor) *pacpAnchor = m_anchor;
        if (pcch) *pcch = m_extent;
        return ole32::S_OK;
    }

    int32_t __stdcall SetExtent(TfEditCookie, int32_t acpAnchor, int32_t cch) override {
        m_anchor = acpAnchor;
        m_extent = cch;
        return ole32::S_OK;
    }

    int32_t __stdcall Collapse(TfEditCookie, TfAnchor aPos) override {
        if (aPos == TF_ANCHOR_END) {
            m_anchor += m_extent;
        }
        m_extent = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall Clone(ITfRange** ppClone) override {
        if (!ppClone) return ole32::E_POINTER;
        *ppClone = new CTfRangeImpl(m_store, m_anchor, m_extent);
        return ole32::S_OK;
    }
};

class CTfContextImpl : public ITfContext {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    [[maybe_unused]] TfClientId m_ownerTid{ 0 };
    ITfDocumentMgr* m_pDocMgr{ nullptr };
    std::shared_ptr<CD2DTextStore> m_store;
    int32_t m_selectionAnchor{ 0 };
    int32_t m_selectionExtent{ 0 };

public:
    CTfContextImpl(TfClientId tid, ITfDocumentMgr* pDocMgr)
        : m_ownerTid(tid), m_pDocMgr(pDocMgr), m_store(std::make_shared<CD2DTextStore>()) {}

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ITfContext) {
            *ppv = static_cast<ITfContext*>(this);
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

    int32_t __stdcall RequestEditSession(TfClientId, ITfEditSession* pes, uint32_t, int32_t* phrSession) override {
        if (!pes) return ole32::E_INVALIDARG;
        TfEditCookie ec = 1001; // Sovereign clean-room read/write edit cookie
        int32_t hr = pes->DoEditSession(ec);
        if (phrSession) *phrSession = hr;
        return ole32::S_OK;
    }

    int32_t __stdcall GetSelection(TfEditCookie, uint32_t, uint32_t ulCount, TF_SELECTION* pSelection, uint32_t* pcFetched) override {
        if (!pSelection || !pcFetched || ulCount == 0) return ole32::E_INVALIDARG;
        pSelection[0].range = new CTfRangeImpl(m_store, m_selectionAnchor, m_selectionExtent);
        pSelection[0].style = 0;
        *pcFetched = 1;
        return ole32::S_OK;
    }

    int32_t __stdcall SetSelection(TfEditCookie, uint32_t ulCount, const TF_SELECTION* pSelection) override {
        if (!pSelection || ulCount == 0 || !pSelection[0].range) return ole32::E_INVALIDARG;
        pSelection[0].range->GetExtent(0, &m_selectionAnchor, &m_selectionExtent);
        return ole32::S_OK;
    }

    int32_t __stdcall GetStart(TfEditCookie, ITfRange** ppRange) override {
        if (!ppRange) return ole32::E_POINTER;
        *ppRange = new CTfRangeImpl(m_store, 0, 0);
        return ole32::S_OK;
    }

    int32_t __stdcall GetEnd(TfEditCookie, ITfRange** ppRange) override {
        if (!ppRange) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_store->m_lock);
        int32_t endPos = static_cast<int32_t>(m_store->m_text.length());
        *ppRange = new CTfRangeImpl(m_store, endPos, 0);
        return ole32::S_OK;
    }

    int32_t __stdcall GetStatus(TF_STATUS* pdcs) override {
        if (!pdcs) return ole32::E_POINTER;
        pdcs->dwDynamicFlags = 0;
        pdcs->dwStaticFlags = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall GetDocumentMgr(ITfDocumentMgr** ppDm) override {
        if (!ppDm) return ole32::E_POINTER;
        *ppDm = m_pDocMgr;
        if (m_pDocMgr) m_pDocMgr->AddRef();
        return ole32::S_OK;
    }

    std::shared_ptr<CD2DTextStore> GetStore() const { return m_store; }
};

class CTfDocumentMgrImpl : public ITfDocumentMgr {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<ITfContext*> m_contextStack;
    std::mutex m_mutex;

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ITfDocumentMgr) {
            *ppv = static_cast<ITfDocumentMgr*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) {
            for (auto* ctx : m_contextStack) ctx->Release();
            m_contextStack.clear();
            delete this;
        }
        return r;
    }

    int32_t __stdcall CreateContext(TfClientId tidOwner, uint32_t, ole32::IUnknown*, ITfContext** ppic, TfEditCookie* pecTextStore) override {
        if (!ppic) return ole32::E_POINTER;
        *ppic = new CTfContextImpl(tidOwner, this);
        if (pecTextStore) *pecTextStore = 1001;
        return ole32::S_OK;
    }

    int32_t __stdcall Push(ITfContext* pic) override {
        if (!pic) return ole32::E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        pic->AddRef();
        m_contextStack.push_back(pic);
        return ole32::S_OK;
    }

    int32_t __stdcall Pop(uint32_t) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_contextStack.empty()) return ole32::E_FAIL;
        m_contextStack.back()->Release();
        m_contextStack.pop_back();
        return ole32::S_OK;
    }

    int32_t __stdcall GetTop(ITfContext** ppic) override {
        if (!ppic) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_contextStack.empty()) {
            *ppic = nullptr;
            return ole32::S_FALSE;
        }
        *ppic = m_contextStack.back();
        (*ppic)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall GetBase(ITfContext** ppic) override {
        if (!ppic) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_contextStack.empty()) {
            *ppic = nullptr;
            return ole32::S_FALSE;
        }
        *ppic = m_contextStack.front();
        (*ppic)->AddRef();
        return ole32::S_OK;
    }
};

class CTfCompartmentImpl : public ITfCompartment {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    uint32_t m_value{ 0 };

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ITfCompartment) {
            *ppv = static_cast<ITfCompartment*>(this);
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

    int32_t __stdcall SetValue(TfClientId, uint32_t dwVal) override {
        m_value = dwVal;
        return ole32::S_OK;
    }

    int32_t __stdcall GetValue(uint32_t* pdwVal) override {
        if (!pdwVal) return ole32::E_POINTER;
        *pdwVal = m_value;
        return ole32::S_OK;
    }
};

class CTfCompartmentMgrImpl : public ITfCompartmentMgr {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::unordered_map<GUID, ITfCompartment*, GUIDHasher, GUIDComparer> m_compartments;
    std::mutex m_mutex;

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ITfCompartmentMgr) {
            *ppv = static_cast<ITfCompartmentMgr*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) {
            for (auto& [g, c] : m_compartments) c->Release();
            m_compartments.clear();
            delete this;
        }
        return r;
    }

    int32_t __stdcall GetCompartment(const GUID& rguid, ITfCompartment** ppComp) override {
        if (!ppComp) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_compartments.find(rguid);
        if (it != m_compartments.end()) {
            *ppComp = it->second;
            (*ppComp)->AddRef();
            return ole32::S_OK;
        }
        auto* comp = new CTfCompartmentImpl();
        m_compartments[rguid] = comp;
        *ppComp = comp;
        (*ppComp)->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall ClearCompartment(TfClientId, const GUID& rguid) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_compartments.find(rguid);
        if (it != m_compartments.end()) {
            it->second->Release();
            m_compartments.erase(it);
        }
        return ole32::S_OK;
    }
};

class CTfInputProcessorProfilesImpl : public ITfInputProcessorProfiles {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<TF_LANGUAGEPROFILE> m_profiles;
    std::mutex m_mutex;

public:
    CTfInputProcessorProfilesImpl() {
        // Pre-seed sovereign clean-room multi-language keyboard & IME profiles
        // US English QWERTY
        TF_LANGUAGEPROFILE en{};
        en.langid = 0x0409;
        en.fActive = 1;
        en.clsid = { 0x529a9e6b, 0x65dc, 0x4e4e, { 0x87, 0x48, 0x76, 0x9c, 0x96, 0xa8, 0x4d, 0x67 } };
        en.guidProfile = { 0x00000409, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
        m_profiles.push_back(en);

        // Microsoft Pinyin (Simplified Chinese)
        TF_LANGUAGEPROFILE zh{};
        zh.langid = 0x0804;
        zh.fActive = 1;
        zh.clsid = { 0xfa550b04, 0x5ad7, 0x411f, { 0xa5, 0xac, 0xca, 0x03, 0x8e, 0xc5, 0x15, 0xd7 } };
        zh.guidProfile = { 0x00000804, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
        m_profiles.push_back(zh);

        // Microsoft Japanese IME
        TF_LANGUAGEPROFILE ja{};
        ja.langid = 0x0411;
        ja.fActive = 1;
        ja.clsid = { 0x03b5835f, 0xf03c, 0x411b, { 0x9c, 0xe2, 0xaa, 0x23, 0xe1, 0x17, 0x1e, 0x36 } };
        ja.guidProfile = { 0x00000411, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
        m_profiles.push_back(ja);
    }

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ITfInputProcessorProfiles) {
            *ppv = static_cast<ITfInputProcessorProfiles*>(this);
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

    int32_t __stdcall Register(const GUID&) override { return ole32::S_OK; }
    int32_t __stdcall Unregister(const GUID&) override { return ole32::S_OK; }

    int32_t __stdcall AddLanguageProfile(
        const GUID& rclsid,
        uint16_t langid,
        const GUID& guidProfile,
        const wchar_t*,
        uint32_t,
        const wchar_t*,
        uint32_t,
        uint32_t) override
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        TF_LANGUAGEPROFILE p{};
        p.clsid = rclsid;
        p.langid = langid;
        p.guidProfile = guidProfile;
        p.fActive = 1;
        m_profiles.push_back(p);
        return ole32::S_OK;
    }

    int32_t __stdcall GetActiveLanguageProfile(const GUID&, uint16_t* plangid, GUID* pguidProfile) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_profiles.empty()) return ole32::E_FAIL;
        if (plangid) *plangid = m_profiles[0].langid;
        if (pguidProfile) *pguidProfile = m_profiles[0].guidProfile;
        return ole32::S_OK;
    }

    int32_t __stdcall ActivateLanguageProfile(const GUID&, uint16_t langid, const GUID& guidProfile) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& p : m_profiles) {
            if (p.langid == langid && p.guidProfile == guidProfile) {
                p.fActive = 1;
                return ole32::S_OK;
            }
        }
        return ole32::E_INVALIDARG;
    }

    size_t GetProfileCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_profiles.size();
    }
};

class CTfCategoryMgrImpl : public ITfCategoryMgr {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::unordered_map<TfGuidAtom, GUID> m_atomToGuid;
    std::unordered_map<GUID, TfGuidAtom, GUIDHasher, GUIDComparer> m_guidToAtom;
    uint32_t m_nextAtom{ 100 };
    std::mutex m_mutex;

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ITfCategoryMgr) {
            *ppv = static_cast<ITfCategoryMgr*>(this);
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

    int32_t __stdcall RegisterCategory(const GUID&, const GUID&, const GUID&) override { return ole32::S_OK; }
    int32_t __stdcall UnregisterCategory(const GUID&, const GUID&, const GUID&) override { return ole32::S_OK; }

    int32_t __stdcall RegisterGUID(const GUID& rguid, TfGuidAtom* pguidatom) override {
        if (!pguidatom) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_guidToAtom.find(rguid);
        if (it != m_guidToAtom.end()) {
            *pguidatom = it->second;
            return ole32::S_OK;
        }
        TfGuidAtom atom = m_nextAtom++;
        m_guidToAtom[rguid] = atom;
        m_atomToGuid[atom] = rguid;
        *pguidatom = atom;
        return ole32::S_OK;
    }

    int32_t __stdcall GetGUID(TfGuidAtom guidatom, GUID* pguid) override {
        if (!pguid) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_atomToGuid.find(guidatom);
        if (it == m_atomToGuid.end()) return ole32::E_INVALIDARG;
        *pguid = it->second;
        return ole32::S_OK;
    }
};

class CTfInputScopeImpl : public ITfInputScope {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<InputScope> m_scopes;

public:
    CTfInputScopeImpl(const std::vector<InputScope>& scopes) : m_scopes(scopes) {}

    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ITfInputScope) {
            *ppv = static_cast<ITfInputScope*>(this);
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

    int32_t __stdcall GetInputScopes(InputScope** pprgInputScopes, uint32_t* pcCount) override {
        if (!pprgInputScopes || !pcCount) return ole32::E_POINTER;
        *pcCount = static_cast<uint32_t>(m_scopes.size());
        auto* arr = static_cast<InputScope*>(ole32::CoTaskMemAlloc(sizeof(InputScope) * m_scopes.size()));
        for (size_t i = 0; i < m_scopes.size(); ++i) arr[i] = m_scopes[i];
        *pprgInputScopes = arr;
        return ole32::S_OK;
    }

    int32_t __stdcall GetPhrase(wchar_t***, uint32_t* pcCount) override { if (pcCount) *pcCount = 0; return ole32::S_OK; }
    int32_t __stdcall GetRegularExpression(wchar_t** pbstr) override { if (pbstr) *pbstr = nullptr; return ole32::S_OK; }
    int32_t __stdcall GetSRGS(wchar_t** pbstr) override { if (pbstr) *pbstr = nullptr; return ole32::S_OK; }
    int32_t __stdcall GetXML(wchar_t** pbstr) override { if (pbstr) *pbstr = nullptr; return ole32::S_OK; }
};

class CTfThreadMgrImpl : public ITfThreadMgr {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    TfClientId m_clientId{ 1 };
    bool m_activated{ false };
    ITfDocumentMgr* m_pFocusDocMgr{ nullptr };
    std::unordered_map<win32::HWND, ITfDocumentMgr*> m_focusMap;
    CTfCompartmentMgrImpl m_globalCompartment;
    std::mutex m_mutex;

public:
    int32_t __stdcall QueryInterface(const GUID& riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ITfThreadMgr) {
            *ppv = static_cast<ITfThreadMgr*>(this);
            AddRef();
            return ole32::S_OK;
        }
        *ppv = nullptr;
        return ole32::E_NOINTERFACE;
    }

    uint32_t __stdcall AddRef() override { return ++m_refCount; }
    uint32_t __stdcall Release() override {
        uint32_t r = --m_refCount;
        if (r == 0) {
            if (m_pFocusDocMgr) m_pFocusDocMgr->Release();
            for (auto& [w, d] : m_focusMap) if (d) d->Release();
            delete this;
        }
        return r;
    }

    int32_t __stdcall Activate(TfClientId* pClientId) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_activated = true;
        if (pClientId) *pClientId = m_clientId;
        return ole32::S_OK;
    }

    int32_t __stdcall Deactivate() override {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_activated = false;
        return ole32::S_OK;
    }

    int32_t __stdcall CreateDocumentMgr(ITfDocumentMgr** ppdim) override {
        if (!ppdim) return ole32::E_POINTER;
        *ppdim = new CTfDocumentMgrImpl();
        return ole32::S_OK;
    }

    int32_t __stdcall GetFocus(ITfDocumentMgr** ppdimFocus) override {
        if (!ppdimFocus) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);
        *ppdimFocus = m_pFocusDocMgr;
        if (m_pFocusDocMgr) m_pFocusDocMgr->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall SetFocus(ITfDocumentMgr* pdimFocus) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pFocusDocMgr) m_pFocusDocMgr->Release();
        m_pFocusDocMgr = pdimFocus;
        if (m_pFocusDocMgr) m_pFocusDocMgr->AddRef();
        return ole32::S_OK;
    }

    int32_t __stdcall AssociateFocus(win32::HWND hwnd, ITfDocumentMgr* pdimNew, ITfDocumentMgr** ppdimPrev) override {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_focusMap.find(hwnd);
        ITfDocumentMgr* prev = (it != m_focusMap.end()) ? it->second : nullptr;
        if (ppdimPrev) {
            *ppdimPrev = prev;
            if (prev) prev->AddRef();
        }
        if (pdimNew) pdimNew->AddRef();
        if (prev) prev->Release();
        m_focusMap[hwnd] = pdimNew;
        return ole32::S_OK;
    }

    int32_t __stdcall IsThreadFocus(int32_t* pfThreadFocus) override {
        if (!pfThreadFocus) return ole32::E_POINTER;
        *pfThreadFocus = m_activated ? 1 : 0;
        return ole32::S_OK;
    }

    int32_t __stdcall GetGlobalCompartment(ITfCompartmentMgr** ppCompMgr) override {
        if (!ppCompMgr) return ole32::E_POINTER;
        *ppCompMgr = &m_globalCompartment;
        m_globalCompartment.AddRef();
        return ole32::S_OK;
    }
};

// ============================================================================
// 5. Input Method Manager (IMM32) Subsystem State & Engine
// ============================================================================

struct CIMCContext {
    win32::HWND hWnd{ nullptr };
    bool        openStatus{ true };
    uint32_t    conversionMode{ IME_CMODE_NATIVE | IME_CMODE_FULLSHAPE };
    uint32_t    sentenceMode{ 0 };
    std::wstring compString;
    std::wstring compReadString;
    std::vector<uint8_t> compAttr;
    std::vector<uint32_t> compClause;
    std::wstring resultString;
    std::wstring resultReadString;
    uint32_t    cursorPos{ 0 };
    std::vector<std::wstring> candidates;
    uint32_t    candidateSelection{ 0 };
    CANDIDATEFORM candidateForm{};
    COMPOSITIONFORM compForm{};
};

class CIMCManager {
private:
    std::unordered_map<HIMC, std::unique_ptr<CIMCContext>> m_contexts;
    std::unordered_map<win32::HWND, HIMC> m_windowContextMap;
    std::atomic<uintptr_t> m_nextHandle{ 0x1000 };
    std::mutex m_mutex;

public:
    static CIMCManager& Instance() {
        static CIMCManager s_instance;
        return s_instance;
    }

    HIMC CreateContext() {
        std::lock_guard<std::mutex> lock(m_mutex);
        HIMC handle = reinterpret_cast<HIMC>(m_nextHandle.fetch_add(0x10));
        m_contexts[handle] = std::make_unique<CIMCContext>();
        return handle;
    }

    bool DestroyContext(HIMC hIMC) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_contexts.erase(hIMC) > 0;
    }

    HIMC GetContext(win32::HWND hWnd) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_windowContextMap.find(hWnd);
        if (it != m_windowContextMap.end()) return it->second;
        HIMC hIMC = reinterpret_cast<HIMC>(m_nextHandle.fetch_add(0x10));
        auto ctx = std::make_unique<CIMCContext>();
        ctx->hWnd = hWnd;
        m_contexts[hIMC] = std::move(ctx);
        m_windowContextMap[hWnd] = hIMC;
        return hIMC;
    }

    bool ReleaseContext(win32::HWND, HIMC) {
        return true;
    }

    CIMCContext* Lookup(HIMC hIMC) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_contexts.find(hIMC);
        return (it != m_contexts.end()) ? it->second.get() : nullptr;
    }
};

// ============================================================================
// 6. Public Exported C/Win32 APIs
// ============================================================================

// msctf.dll Exports
inline int32_t __stdcall TF_CreateThreadMgr(ITfThreadMgr** ppThreadMgr) {
    if (!ppThreadMgr) return ole32::E_POINTER;
    *ppThreadMgr = new CTfThreadMgrImpl();
    return ole32::S_OK;
}

inline int32_t __stdcall TF_CreateInputProcessorProfiles(ITfInputProcessorProfiles** ppProfiles) {
    if (!ppProfiles) return ole32::E_POINTER;
    *ppProfiles = new CTfInputProcessorProfilesImpl();
    return ole32::S_OK;
}

inline int32_t __stdcall TF_CreateCategoryMgr(ITfCategoryMgr** ppCatMgr) {
    if (!ppCatMgr) return ole32::E_POINTER;
    *ppCatMgr = new CTfCategoryMgrImpl();
    return ole32::S_OK;
}

inline int32_t __stdcall TF_CreateInputScope(const std::vector<InputScope>& scopes, ITfInputScope** ppScope) {
    if (!ppScope) return ole32::E_POINTER;
    *ppScope = new CTfInputScopeImpl(scopes);
    return ole32::S_OK;
}

inline int32_t __stdcall TF_GetGlobalCompartment(ITfCompartmentMgr** ppCompMgr) {
    if (!ppCompMgr) return ole32::E_POINTER;
    static CTfCompartmentMgrImpl s_globalComp;
    *ppCompMgr = &s_globalComp;
    s_globalComp.AddRef();
    return ole32::S_OK;
}

// imm32.dll Exports
inline HIMC __stdcall ImmGetContext(win32::HWND hWnd) {
    return CIMCManager::Instance().GetContext(hWnd);
}

inline int32_t __stdcall ImmReleaseContext(win32::HWND hWnd, HIMC hIMC) {
    return CIMCManager::Instance().ReleaseContext(hWnd, hIMC) ? 1 : 0;
}

inline HIMC __stdcall ImmCreateContext() {
    return CIMCManager::Instance().CreateContext();
}

inline int32_t __stdcall ImmDestroyContext(HIMC hIMC) {
    return CIMCManager::Instance().DestroyContext(hIMC) ? 1 : 0;
}

inline int32_t __stdcall ImmGetOpenStatus(HIMC hIMC) {
    auto* ctx = CIMCManager::Instance().Lookup(hIMC);
    return (ctx && ctx->openStatus) ? 1 : 0;
}

inline int32_t __stdcall ImmSetOpenStatus(HIMC hIMC, int32_t fOpen) {
    auto* ctx = CIMCManager::Instance().Lookup(hIMC);
    if (!ctx) return 0;
    ctx->openStatus = (fOpen != 0);
    return 1;
}

inline int32_t __stdcall ImmGetConversionStatus(HIMC hIMC, uint32_t* lpfdwConversion, uint32_t* lpfdwSentence) {
    auto* ctx = CIMCManager::Instance().Lookup(hIMC);
    if (!ctx) return 0;
    if (lpfdwConversion) *lpfdwConversion = ctx->conversionMode;
    if (lpfdwSentence) *lpfdwSentence = ctx->sentenceMode;
    return 1;
}

inline int32_t __stdcall ImmSetConversionStatus(HIMC hIMC, uint32_t fdwConversion, uint32_t fdwSentence) {
    auto* ctx = CIMCManager::Instance().Lookup(hIMC);
    if (!ctx) return 0;
    ctx->conversionMode = fdwConversion;
    ctx->sentenceMode = fdwSentence;
    return 1;
}

inline int32_t __stdcall ImmGetCompositionStringW(HIMC hIMC, uint32_t dwIndex, void* lpBuf, uint32_t dwBufLen) {
    auto* ctx = CIMCManager::Instance().Lookup(hIMC);
    if (!ctx) return -1;

    switch (dwIndex) {
    case GCS_COMPSTR: {
        uint32_t byteLen = static_cast<uint32_t>(ctx->compString.length() * sizeof(wchar_t));
        if (!lpBuf || dwBufLen == 0) return byteLen;
        uint32_t copyBytes = (std::min)(dwBufLen, byteLen);
        std::memcpy(lpBuf, ctx->compString.data(), copyBytes);
        return copyBytes;
    }
    case GCS_COMPREADSTR: {
        uint32_t byteLen = static_cast<uint32_t>(ctx->compReadString.length() * sizeof(wchar_t));
        if (!lpBuf || dwBufLen == 0) return byteLen;
        uint32_t copyBytes = (std::min)(dwBufLen, byteLen);
        std::memcpy(lpBuf, ctx->compReadString.data(), copyBytes);
        return copyBytes;
    }
    case GCS_RESULTSTR: {
        uint32_t byteLen = static_cast<uint32_t>(ctx->resultString.length() * sizeof(wchar_t));
        if (!lpBuf || dwBufLen == 0) return byteLen;
        uint32_t copyBytes = (std::min)(dwBufLen, byteLen);
        std::memcpy(lpBuf, ctx->resultString.data(), copyBytes);
        return copyBytes;
    }
    case GCS_CURSORPOS:
        return static_cast<int32_t>(ctx->cursorPos);
    default:
        return 0;
    }
}

inline int32_t __stdcall ImmSetCompositionStringW(
    HIMC hIMC,
    uint32_t dwIndex,
    const void* lpComp,
    uint32_t dwCompLen,
    const void* lpRead,
    uint32_t dwReadLen)
{
    auto* ctx = CIMCManager::Instance().Lookup(hIMC);
    if (!ctx) return 0;

    if (dwIndex & GCS_COMPSTR) {
        if (lpComp && dwCompLen > 0) {
            uint32_t cch = dwCompLen / sizeof(wchar_t);
            const auto* pwc = static_cast<const wchar_t*>(lpComp);
            ctx->compString.assign(pwc, pwc + cch);
            ctx->cursorPos = cch;
        } else {
            ctx->compString.clear();
            ctx->cursorPos = 0;
        }
    }
    if (dwIndex & GCS_COMPREADSTR) {
        if (lpRead && dwReadLen > 0) {
            uint32_t cch = dwReadLen / sizeof(wchar_t);
            const auto* pwc = static_cast<const wchar_t*>(lpRead);
            ctx->compReadString.assign(pwc, pwc + cch);
        } else {
            ctx->compReadString.clear();
        }
    }
    if (dwIndex & GCS_RESULTSTR) {
        if (lpComp && dwCompLen > 0) {
            uint32_t cch = dwCompLen / sizeof(wchar_t);
            const auto* pwc = static_cast<const wchar_t*>(lpComp);
            ctx->resultString.assign(pwc, pwc + cch);
        } else {
            ctx->resultString.clear();
        }
    }
    return 1;
}

inline int32_t __stdcall ImmGetCandidateListW(HIMC hIMC, uint32_t, CANDIDATELIST* lpCandList, uint32_t dwBufLen) {
    auto* ctx = CIMCManager::Instance().Lookup(hIMC);
    if (!ctx) return 0;

    uint32_t candCount = static_cast<uint32_t>(ctx->candidates.size());
    uint32_t reqSize = sizeof(CANDIDATELIST) + (candCount > 0 ? (candCount - 1) * sizeof(uint32_t) : 0);
    for (const auto& c : ctx->candidates) {
        reqSize += static_cast<uint32_t>((c.length() + 1) * sizeof(wchar_t));
    }

    if (!lpCandList || dwBufLen < reqSize) return reqSize;

    lpCandList->dwSize = reqSize;
    lpCandList->dwStyle = 0;
    lpCandList->dwCount = candCount;
    lpCandList->dwSelection = ctx->candidateSelection;
    lpCandList->dwPageStart = 0;
    lpCandList->dwPageSize = (candCount < 9) ? candCount : 9;

    uint32_t stringOffset = sizeof(CANDIDATELIST) + (candCount > 0 ? (candCount - 1) * sizeof(uint32_t) : 0);
    uint8_t* pBase = reinterpret_cast<uint8_t*>(lpCandList);

    for (uint32_t i = 0; i < candCount; ++i) {
        lpCandList->dwOffset[i] = stringOffset;
        uint32_t byteSize = static_cast<uint32_t>((ctx->candidates[i].length() + 1) * sizeof(wchar_t));
        std::memcpy(pBase + stringOffset, ctx->candidates[i].c_str(), byteSize);
        stringOffset += byteSize;
    }
    return reqSize;
}

inline int32_t __stdcall ImmSetCandidateWindow(HIMC hIMC, const CANDIDATEFORM* lpCandidate) {
    auto* ctx = CIMCManager::Instance().Lookup(hIMC);
    if (!ctx || !lpCandidate) return 0;
    ctx->candidateForm = *lpCandidate;
    return 1;
}

inline int32_t __stdcall ImmSetCompositionWindow(HIMC hIMC, const COMPOSITIONFORM* lpCompForm) {
    auto* ctx = CIMCManager::Instance().Lookup(hIMC);
    if (!ctx || !lpCompForm) return 0;
    ctx->compForm = *lpCompForm;
    return 1;
}

inline int32_t __stdcall ImmIsIME(HKL) {
    return 1; // Sovereign environment defaults to full modern IME support
}

// Dynamic Registration Helper
inline void InitializeTextServicesExports() {
    auto& loader = micant::ldr::DynamicLoader::get();

    // msctf.dll exports
    loader.registerExport("msctf.dll", "TF_CreateThreadMgr", reinterpret_cast<void*>(TF_CreateThreadMgr));
    loader.registerExport("msctf.dll", "TF_CreateInputProcessorProfiles", reinterpret_cast<void*>(TF_CreateInputProcessorProfiles));
    loader.registerExport("msctf.dll", "TF_CreateCategoryMgr", reinterpret_cast<void*>(TF_CreateCategoryMgr));
    loader.registerExport("msctf.dll", "TF_GetGlobalCompartment", reinterpret_cast<void*>(TF_GetGlobalCompartment));

    // imm32.dll exports
    loader.registerExport("imm32.dll", "ImmGetContext", reinterpret_cast<void*>(ImmGetContext));
    loader.registerExport("imm32.dll", "ImmReleaseContext", reinterpret_cast<void*>(ImmReleaseContext));
    loader.registerExport("imm32.dll", "ImmCreateContext", reinterpret_cast<void*>(ImmCreateContext));
    loader.registerExport("imm32.dll", "ImmDestroyContext", reinterpret_cast<void*>(ImmDestroyContext));
    loader.registerExport("imm32.dll", "ImmGetOpenStatus", reinterpret_cast<void*>(ImmGetOpenStatus));
    loader.registerExport("imm32.dll", "ImmSetOpenStatus", reinterpret_cast<void*>(ImmSetOpenStatus));
    loader.registerExport("imm32.dll", "ImmGetConversionStatus", reinterpret_cast<void*>(ImmGetConversionStatus));
    loader.registerExport("imm32.dll", "ImmSetConversionStatus", reinterpret_cast<void*>(ImmSetConversionStatus));
    loader.registerExport("imm32.dll", "ImmGetCompositionStringW", reinterpret_cast<void*>(ImmGetCompositionStringW));
    loader.registerExport("imm32.dll", "ImmSetCompositionStringW", reinterpret_cast<void*>(ImmSetCompositionStringW));
    loader.registerExport("imm32.dll", "ImmGetCandidateListW", reinterpret_cast<void*>(ImmGetCandidateListW));
    loader.registerExport("imm32.dll", "ImmSetCandidateWindow", reinterpret_cast<void*>(ImmSetCandidateWindow));
    loader.registerExport("imm32.dll", "ImmSetCompositionWindow", reinterpret_cast<void*>(ImmSetCompositionWindow));
    loader.registerExport("imm32.dll", "ImmIsIME", reinterpret_cast<void*>(ImmIsIME));

    version::VersionDatabase::Instance().RegisterModule(
        "msctf.dll",
        "10.0.22621.1",
        "Windows Text Services Framework Subsystem",
        "MicaNT Sovereign Project"
    );

    version::VersionDatabase::Instance().RegisterModule(
        "imm32.dll",
        "10.0.22621.1",
        "Windows Input Method Manager Subsystem",
        "MicaNT Sovereign Project"
    );
}

} // namespace micant::tsf
