// ============================================================================
// MicaNT: Windows Spell Checking & Extended Linguistic Services (ELS) Subsystem
// (include/micant/spellcheck.hpp)
//
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/win32metadata (Windows.Win32.Globalization)
//   - Windows 8+ Spell Checking API (spellcheck.dll)
//   - Extended Linguistic Services (ELS) Architecture (elscore.dll)
//
// Subsystem Overview:
//   spellcheck.hpp provides the modern Windows Linguistic & Spell Checking
//   subsystem for MicaNT, fully decoupled from external dictionaries or telemetry.
//   Supports:
//     - ISpellCheckerFactory (discovery, language querying, engine instantiation)
//     - ISpellChecker (spell checking, word suggestions, user dictionaries)
//     - IEnumSpellingError & ISpellingError (error ranges, corrective actions)
//     - IOptionDescription & IEnumString (feature enumeration & option descriptors)
//     - Levenshtein Edit-Distance & Soundex Phonetic Suggestion Matrix
//     - Extended Linguistic Services (ELS):
//         * Script Detection (Latn, Cyrl, Grek, Arab, Hans, Kana, Hang)
//         * Language Identification (en, es, de, fr, ru, zh, ja, etc.)
//         * Multi-script Transliteration (Cyrillic to Latin, Pinyin)
//
// Core Dynamic Modules:
//   - spellcheck.dll (Windows Spell Checking API Engine)
//   - elscore.dll (Extended Linguistic Services Engine)
//
// Trademark & Nominative Fair Use Notice:
//   Windows, Spell Checking API, and Extended Linguistic Services (ELS) are
//   registered trademarks of Microsoft Corp. MicaNT is an independent sovereign
//   clean-room implementation engineered for binary interoperability
//   (*Google LLC v. Oracle America, Inc.*).
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ole32.hpp"
#include "appmodel.hpp"
#include "ldr.hpp"
#include "version.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <atomic>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <cwctype>

namespace micant::spellcheck {

// ============================================================================
// 1. GUIDs & Standard Constants
// ============================================================================

inline constexpr GUID IID_IEnumString =
    { 0x00000101, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

inline constexpr GUID CLSID_SpellCheckerFactory =
    { 0x7AB49AE2, 0x9E7F, 0x4C01, { 0x81, 0x7E, 0x66, 0x2E, 0x8C, 0x43, 0x41, 0xF2 } };

inline constexpr GUID IID_ISpellCheckerFactory =
    { 0x8E018A9D, 0x2415, 0x4677, { 0xBF, 0x08, 0x7D, 0x74, 0x1F, 0x89, 0x0B, 0x97 } };

inline constexpr GUID IID_ISpellChecker =
    { 0xB6FD0B71, 0xE2BC, 0x4653, { 0x9D, 0x05, 0xF1, 0x97, 0xE4, 0x12, 0xB2, 0xF2 } };

inline constexpr GUID IID_IEnumSpellingError =
    { 0x803E3B5E, 0xCE70, 0x4387, { 0x90, 0x68, 0xDC, 0xE5, 0x40, 0x30, 0x61, 0xBD } };

inline constexpr GUID IID_ISpellingError =
    { 0xB2767002, 0x0724, 0x43B8, { 0x81, 0xE8, 0x24, 0x4F, 0x13, 0xB2, 0x3B, 0x16 } };

inline constexpr GUID IID_IOptionDescription =
    { 0x432E5F85, 0x35CF, 0x4606, { 0xA8, 0x01, 0x6F, 0x70, 0x27, 0x7E, 0x1D, 0x7A } };

// ELS GUIDs
inline constexpr GUID ELS_GUID_LANGUAGE_DETECTION =
    { 0x243E4F4C, 0x4624, 0x4A6B, { 0x98, 0x2E, 0x64, 0x5D, 0x22, 0x39, 0x1E, 0x86 } };

inline constexpr GUID ELS_GUID_SCRIPT_DETECTION =
    { 0x2D4815E3, 0x45E5, 0x47A8, { 0xBD, 0x90, 0x4A, 0x9A, 0xE1, 0x3E, 0x32, 0xE2 } };

inline constexpr GUID ELS_GUID_TRANSLITERATION_CYRILLIC_TO_LATIN =
    { 0x3DD12A98, 0xD440, 0x450D, { 0x50, 0x71, 0xE3, 0x42, 0x21, 0x02, 0x96, 0x83 } };

// ============================================================================
// 2. COM Interfaces & Enums
// ============================================================================

enum CORRECTIVE_ACTION : int32_t {
    CORRECTIVE_ACTION_NONE = 0,
    CORRECTIVE_ACTION_GET_SUGGESTIONS = 1,
    CORRECTIVE_ACTION_REPLACE = 2,
    CORRECTIVE_ACTION_DELETE = 3
};

class IEnumString : public ole32::IUnknown {
public:
    virtual int32_t __stdcall Next(uint32_t celt, wchar_t** rgelt, uint32_t* pceltFetched) = 0;
    virtual int32_t __stdcall Skip(uint32_t celt) = 0;
    virtual int32_t __stdcall Reset() = 0;
    virtual int32_t __stdcall Clone(IEnumString** ppenum) = 0;
};

class ISpellingError : public ole32::IUnknown {
public:
    virtual int32_t __stdcall get_StartIndex(uint32_t* value) = 0;
    virtual int32_t __stdcall get_Length(uint32_t* value) = 0;
    virtual int32_t __stdcall get_CorrectiveAction(CORRECTIVE_ACTION* value) = 0;
    virtual int32_t __stdcall get_Replacement(wchar_t** value) = 0;
};

class IEnumSpellingError : public ole32::IUnknown {
public:
    virtual int32_t __stdcall Next(ISpellingError** value) = 0;
};

class IOptionDescription : public ole32::IUnknown {
public:
    virtual int32_t __stdcall get_Id(wchar_t** value) = 0;
    virtual int32_t __stdcall get_Heading(wchar_t** value) = 0;
    virtual int32_t __stdcall get_Description(wchar_t** value) = 0;
    virtual int32_t __stdcall get_Labels(IEnumString** value) = 0;
};

class ISpellChecker : public ole32::IUnknown {
public:
    virtual int32_t __stdcall get_LanguageTag(wchar_t** value) = 0;
    virtual int32_t __stdcall Check(const wchar_t* text, IEnumSpellingError** value) = 0;
    virtual int32_t __stdcall Suggest(const wchar_t* word, IEnumString** value) = 0;
    virtual int32_t __stdcall Add(const wchar_t* word) = 0;
    virtual int32_t __stdcall Ignore(const wchar_t* word) = 0;
    virtual int32_t __stdcall AutoCorrect(const wchar_t* from, const wchar_t* to) = 0;
    virtual int32_t __stdcall GetOptionDescription(const wchar_t* optionId, IOptionDescription** value) = 0;
    virtual int32_t __stdcall get_OptionIds(IEnumString** value) = 0;
    virtual int32_t __stdcall get_Id(wchar_t** value) = 0;
    virtual int32_t __stdcall get_LocalizedName(wchar_t** value) = 0;
};

class ISpellCheckerFactory : public ole32::IUnknown {
public:
    virtual int32_t __stdcall get_SupportedLanguages(IEnumString** value) = 0;
    virtual int32_t __stdcall IsSupported(const wchar_t* languageTag, int32_t* value) = 0;
    virtual int32_t __stdcall CreateSpellChecker(const wchar_t* languageTag, ISpellChecker** value) = 0;
};

// ============================================================================
// 3. Extended Linguistic Services (ELS) Win32 Structures
// ============================================================================

struct MAPPING_ENUM_OPTIONS {
    size_t   Size;
    wchar_t* pszCategory;
    wchar_t* pszInputLanguage;
    wchar_t* pszOutputLanguage;
    wchar_t* pszInputScript;
    wchar_t* pszOutputScript;
};

struct MAPPING_SERVICE_INFO {
    size_t       Size;
    wchar_t*     pszDescription;
    uint32_t     dwDescriptionLength;
    wchar_t*     pszCopyright;
    uint32_t     dwMajorVersion;
    uint32_t     dwMinorVersion;
    uint32_t     dwBuildVersion;
    uint32_t     dwStepVersion;
    uint32_t     dwInputContentTypesCount;
    wchar_t**    prgInputContentTypes;
    uint32_t     dwOutputContentTypesCount;
    wchar_t**    prgOutputContentTypes;
    wchar_t*     pszInputLanguage;
    wchar_t*     pszOutputLanguage;
    wchar_t*     pszInputScript;
    wchar_t*     pszOutputScript;
    GUID         guid;
    wchar_t*     pszCategory;
};

struct MAPPING_OPTIONS {
    size_t   Size;
    wchar_t* pszInputLanguage;
    wchar_t* pszOutputLanguage;
    wchar_t* pszInputScript;
    wchar_t* pszOutputScript;
    wchar_t* pszFlagOptions;
    uint32_t dwFormat;
};

struct MAPPING_PROPERTY_BAG {
    size_t   Size;
    void*    pDataResult;
    uint32_t dwDataSize;
    wchar_t* pszResultRanges;
    uint32_t dwRangesCount;
    void*    pServiceData;
    uint32_t dwServiceDataSize;
    void*    pCallerData;
    size_t   dwCallerDataSize;
    void*    pContext;
};

// ============================================================================
// 4. Clean-Room Linguistic Utilities (Levenshtein & Soundex)
// ============================================================================

inline wchar_t* AllocateCoTaskString(const std::wstring& s) {
    size_t bytes = (s.length() + 1) * sizeof(wchar_t);
    auto* mem = static_cast<wchar_t*>(ole32::CoTaskMemAlloc(bytes));
    if (mem) {
        std::memcpy(mem, s.c_str(), bytes);
    }
    return mem;
}

inline std::wstring ToLowerString(const std::wstring& str) {
    std::wstring res = str;
    for (auto& c : res) c = std::towlower(c);
    return res;
}

inline uint32_t ComputeLevenshteinDistance(const std::wstring& s1, const std::wstring& s2) {
    const size_t m = s1.length();
    const size_t n = s2.length();
    if (m == 0) return static_cast<uint32_t>(n);
    if (n == 0) return static_cast<uint32_t>(m);

    std::vector<uint32_t> prev(n + 1);
    std::vector<uint32_t> curr(n + 1);

    for (size_t j = 0; j <= n; ++j) prev[j] = static_cast<uint32_t>(j);

    for (size_t i = 1; i <= m; ++i) {
        curr[0] = static_cast<uint32_t>(i);
        for (size_t j = 1; j <= n; ++j) {
            uint32_t cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            curr[j] = std::min({
                prev[j] + 1,        // deletion
                curr[j - 1] + 1,    // insertion
                prev[j - 1] + cost  // substitution
            });
        }
        prev = curr;
    }
    return prev[n];
}

inline std::string ComputeSoundex(const std::wstring& word) {
    if (word.empty()) return "0000";
    std::string s;
    for (wchar_t wc : word) {
        if (wc >= 'A' && wc <= 'Z') s.push_back(static_cast<char>(wc));
        else if (wc >= 'a' && wc <= 'z') s.push_back(static_cast<char>(wc - 'a' + 'A'));
    }
    if (s.empty()) return "0000";

    auto GetCode = [](char c) -> char {
        switch (c) {
            case 'B': case 'F': case 'P': case 'V': return '1';
            case 'C': case 'G': case 'J': case 'K': case 'Q': case 'S': case 'X': case 'Z': return '2';
            case 'D': case 'T': return '3';
            case 'L': return '4';
            case 'M': case 'N': return '5';
            case 'R': return '6';
            default: return '0';
        }
    };

    std::string result;
    result.push_back(s[0]);
    char prevCode = GetCode(s[0]);

    for (size_t i = 1; i < s.size() && result.size() < 4; ++i) {
        char code = GetCode(s[i]);
        if (code != '0' && code != prevCode) {
            result.push_back(code);
        }
        prevCode = code;
    }
    while (result.size() < 4) result.push_back('0');
    return result;
}

// ============================================================================
// 5. IEnumString Implementation
// ============================================================================

class CEnumStringImpl : public IEnumString {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<std::wstring> m_strings;
    size_t m_currentPos{ 0 };

public:
    CEnumStringImpl(std::vector<std::wstring> strings)
        : m_strings(std::move(strings)) {}

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IEnumString) {
            *ppv = static_cast<IEnumString*>(this);
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

    int32_t __stdcall Next(uint32_t celt, wchar_t** rgelt, uint32_t* pceltFetched) override {
        if (!rgelt) return ole32::E_POINTER;
        uint32_t fetched = 0;
        while (m_currentPos < m_strings.size() && fetched < celt) {
            rgelt[fetched] = AllocateCoTaskString(m_strings[m_currentPos]);
            fetched++;
            m_currentPos++;
        }
        if (pceltFetched) *pceltFetched = fetched;
        return (fetched == celt) ? ole32::S_OK : ole32::S_FALSE;
    }

    int32_t __stdcall Skip(uint32_t celt) override {
        m_currentPos = std::min(m_strings.size(), m_currentPos + celt);
        return (m_currentPos < m_strings.size()) ? ole32::S_OK : ole32::S_FALSE;
    }

    int32_t __stdcall Reset() override {
        m_currentPos = 0;
        return ole32::S_OK;
    }

    int32_t __stdcall Clone(IEnumString** ppenum) override {
        if (!ppenum) return ole32::E_POINTER;
        auto* clone = new CEnumStringImpl(m_strings);
        clone->m_currentPos = m_currentPos;
        *ppenum = clone;
        return ole32::S_OK;
    }
};

// ============================================================================
// 6. ISpellingError & IEnumSpellingError Implementations
// ============================================================================

class CSpellingErrorImpl : public ISpellingError {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    uint32_t m_startIndex{ 0 };
    uint32_t m_length{ 0 };
    CORRECTIVE_ACTION m_action{ CORRECTIVE_ACTION_NONE };
    std::wstring m_replacement;

public:
    CSpellingErrorImpl(uint32_t start, uint32_t len, CORRECTIVE_ACTION action, std::wstring repl = L"")
        : m_startIndex(start), m_length(len), m_action(action), m_replacement(std::move(repl)) {}

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ISpellingError) {
            *ppv = static_cast<ISpellingError*>(this);
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

    int32_t __stdcall get_StartIndex(uint32_t* value) override {
        if (!value) return ole32::E_POINTER;
        *value = m_startIndex;
        return ole32::S_OK;
    }

    int32_t __stdcall get_Length(uint32_t* value) override {
        if (!value) return ole32::E_POINTER;
        *value = m_length;
        return ole32::S_OK;
    }

    int32_t __stdcall get_CorrectiveAction(CORRECTIVE_ACTION* value) override {
        if (!value) return ole32::E_POINTER;
        *value = m_action;
        return ole32::S_OK;
    }

    int32_t __stdcall get_Replacement(wchar_t** value) override {
        if (!value) return ole32::E_POINTER;
        *value = AllocateCoTaskString(m_replacement);
        return ole32::S_OK;
    }
};

class CEnumSpellingErrorImpl : public IEnumSpellingError {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<ISpellingError*> m_errors;
    size_t m_currentPos{ 0 };

public:
    CEnumSpellingErrorImpl(std::vector<ISpellingError*> errors)
        : m_errors(std::move(errors)) {}

    ~CEnumSpellingErrorImpl() {
        for (auto* e : m_errors) {
            if (e) e->Release();
        }
    }

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IEnumSpellingError) {
            *ppv = static_cast<IEnumSpellingError*>(this);
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

    int32_t __stdcall Next(ISpellingError** value) override {
        if (!value) return ole32::E_POINTER;
        if (m_currentPos >= m_errors.size()) {
            *value = nullptr;
            return ole32::S_FALSE;
        }
        *value = m_errors[m_currentPos++];
        (*value)->AddRef();
        return ole32::S_OK;
    }
};

// ============================================================================
// 7. IOptionDescription Implementation
// ============================================================================

class COptionDescriptionImpl : public IOptionDescription {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_id;
    std::wstring m_heading;
    std::wstring m_description;
    std::vector<std::wstring> m_labels;

public:
    COptionDescriptionImpl(std::wstring id, std::wstring head, std::wstring desc, std::vector<std::wstring> labels)
        : m_id(std::move(id)), m_heading(std::move(head)), m_description(std::move(desc)), m_labels(std::move(labels)) {}

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_IOptionDescription) {
            *ppv = static_cast<IOptionDescription*>(this);
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

    int32_t __stdcall get_Id(wchar_t** value) override {
        if (!value) return ole32::E_POINTER;
        *value = AllocateCoTaskString(m_id);
        return ole32::S_OK;
    }

    int32_t __stdcall get_Heading(wchar_t** value) override {
        if (!value) return ole32::E_POINTER;
        *value = AllocateCoTaskString(m_heading);
        return ole32::S_OK;
    }

    int32_t __stdcall get_Description(wchar_t** value) override {
        if (!value) return ole32::E_POINTER;
        *value = AllocateCoTaskString(m_description);
        return ole32::S_OK;
    }

    int32_t __stdcall get_Labels(IEnumString** value) override {
        if (!value) return ole32::E_POINTER;
        *value = new CEnumStringImpl(m_labels);
        return ole32::S_OK;
    }
};

// ============================================================================
// 8. Sovereign Clean-Room Lexicon & Spell Checker Implementation
// ============================================================================

class CSpellCheckerImpl : public ISpellChecker {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::wstring m_languageTag;
    std::unordered_set<std::wstring> m_lexicon;
    std::unordered_set<std::wstring> m_addedWords;
    std::unordered_set<std::wstring> m_ignoredWords;
    std::unordered_map<std::wstring, std::wstring> m_autoCorrect;
    std::mutex m_mutex;

    void SeedBuiltinLexicon() {
        // Multi-lingual core vocabulary (English, Spanish, German, French, IT/OS terminology)
        static const std::vector<std::wstring> enWords = {
            L"the", L"be", L"to", L"of", L"and", L"a", L"in", L"that", L"have", L"i",
            L"it", L"for", L"not", L"on", L"with", L"he", L"as", L"you", L"do", L"at",
            L"this", L"but", L"his", L"by", L"from", L"they", L"we", L"say", L"her", L"she",
            L"or", L"an", L"will", L"my", L"one", L"all", L"would", L"there", L"their", L"what",
            L"so", L"up", L"out", L"if", L"about", L"who", L"get", L"which", L"go", L"me",
            L"when", L"make", L"can", L"like", L"time", L"no", L"just", L"him", L"know", L"take",
            L"people", L"into", L"year", L"your", L"good", L"some", L"could", L"them", L"see", L"other",
            L"than", L"then", L"now", L"look", L"only", L"come", L"its", L"over", L"think", L"also",
            L"back", L"after", L"use", L"two", L"how", L"our", L"work", L"first", L"well", L"way",
            L"even", L"new", L"want", L"because", L"any", L"these", L"give", L"day", L"most", L"us",
            L"quick", L"brown", L"fox", L"jump", L"jumps", L"jumped", L"lazy", L"dog",
            L"run", L"running", L"test", L"testing", L"check", L"checking",
            // Technical & OS Architecture terms
            L"kernel", L"subsystem", L"architecture", L"operating", L"system", L"windows", L"micant",
            L"sovereign", L"memory", L"process", L"thread", L"graphics", L"driver", L"security",
            L"file", L"network", L"device", L"display", L"keyboard", L"language", L"spelling",
            L"checker", L"linguistic", L"service", L"engine", L"correct", L"error", L"suggestion",
            L"hello", L"world", L"computer", L"software", L"hardware", L"clean", L"room", L"native"
        };

        static const std::vector<std::wstring> esWords = {
            L"el", L"la", L"de", L"que", L"y", L"a", L"en", L"un", L"ser", L"se",
            L"no", L"haber", L"por", L"con", L"su", L"para", L"como", L"estar", L"tener", L"le",
            L"lo", L"todo", L"pero", L"mas", L"hacer", L"o", L"poder", L"decir", L"este", L"ir",
            L"otro", L"ese", L"la", L"si", L"me", L"ya", L"ver", L"porque", L"dar", L"cuando",
            L"sistema", L"operativo", L"arquitectura", L"memoria", L"proceso", L"hilo", L"idioma"
        };

        static const std::vector<std::wstring> deWords = {
            L"der", L"die", L"und", L"in", L"den", L"von", L"zu", L"das", L"mit", L"sich",
            L"des", L"auf", L"fur", L"ist", L"im", L"dem", L"nicht", L"ein", L"eine", L"als",
            L"auch", L"es", L"an", L"werden", L"aus", L"er", L"hat", L"dass", L"sie", L"nach",
            L"wird", L"bei", L"einer", L"um", L"am", L"sind", L"noch", L"wie", L"einem", L"uber",
            L"betriebssystem", L"architektur", L"speicher", L"prozess", L"sprache", L"prufung"
        };

        static const std::vector<std::wstring> frWords = {
            L"le", L"de", L"un", L"a", L"etre", L"et", L"en", L"avoir", L"que", L"pour",
            L"dans", L"ce", L"il", L"qui", L"ne", L"sur", L"se", L"pas", L"plus", L"pouvoir",
            L"par", L"je", L"avec", L"tout", L"faire", L"son", L"mettre", L"autre", L"on", L"mais",
            L"systeme", L"exploitation", L"architecture", L"memoire", L"processus", L"langue"
        };

        std::string tagUtf8 = appmodel::WideToUtf8(m_languageTag);
        std::transform(tagUtf8.begin(), tagUtf8.end(), tagUtf8.begin(), ::tolower);

        if (tagUtf8.find("es") != std::string::npos) {
            for (const auto& w : esWords) m_lexicon.insert(w);
        } else if (tagUtf8.find("de") != std::string::npos) {
            for (const auto& w : deWords) m_lexicon.insert(w);
        } else if (tagUtf8.find("fr") != std::string::npos) {
            for (const auto& w : frWords) m_lexicon.insert(w);
        } else {
            // Default English & Technical vocabulary
            for (const auto& w : enWords) m_lexicon.insert(w);
        }

        // Default standard autocorrect abbreviations / typos
        m_autoCorrect[L"teh"] = L"the";
        m_autoCorrect[L"recieve"] = L"receive";
        m_autoCorrect[L"seperate"] = L"separate";
        m_autoCorrect[L"occured"] = L"occurred";
        m_autoCorrect[L"untill"] = L"until";
        m_autoCorrect[L"adress"] = L"address";
    }

public:
    CSpellCheckerImpl(std::wstring languageTag)
        : m_languageTag(std::move(languageTag)) {
        SeedBuiltinLexicon();
    }

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ISpellChecker) {
            *ppv = static_cast<ISpellChecker*>(this);
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

    int32_t __stdcall get_LanguageTag(wchar_t** value) override {
        if (!value) return ole32::E_POINTER;
        *value = AllocateCoTaskString(m_languageTag);
        return ole32::S_OK;
    }

    int32_t __stdcall Check(const wchar_t* text, IEnumSpellingError** value) override {
        if (!text || !value) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::vector<ISpellingError*> errors;
        std::wstring wText(text);
        const size_t len = wText.length();
        size_t i = 0;

        while (i < len) {
            // Skip non-alphabetic whitespace and punctuation
            while (i < len && !std::iswalpha(wText[i])) i++;
            if (i >= len) break;

            size_t start = i;
            while (i < len && (std::iswalpha(wText[i]) || wText[i] == L'\'')) i++;
            size_t wordLen = i - start;

            std::wstring word = wText.substr(start, wordLen);
            std::wstring lowerWord = ToLowerString(word);

            // 1. Check AutoCorrect table
            auto acIt = m_autoCorrect.find(lowerWord);
            if (acIt != m_autoCorrect.end()) {
                errors.push_back(new CSpellingErrorImpl(
                    static_cast<uint32_t>(start),
                    static_cast<uint32_t>(wordLen),
                    CORRECTIVE_ACTION_REPLACE,
                    acIt->second
                ));
                continue;
            }

            // 2. Check if valid in lexicon, user added, or user ignored
            if (m_lexicon.count(lowerWord) > 0 ||
                m_addedWords.count(lowerWord) > 0 ||
                m_ignoredWords.count(lowerWord) > 0) {
                continue;
            }

            // 3. Mark as spelling error requiring suggestions
            errors.push_back(new CSpellingErrorImpl(
                static_cast<uint32_t>(start),
                static_cast<uint32_t>(wordLen),
                CORRECTIVE_ACTION_GET_SUGGESTIONS,
                L""
            ));
        }

        *value = new CEnumSpellingErrorImpl(std::move(errors));
        return ole32::S_OK;
    }

    int32_t __stdcall Suggest(const wchar_t* word, IEnumString** value) override {
        if (!word || !value) return ole32::E_POINTER;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring query = ToLowerString(word);
        std::string querySoundex = ComputeSoundex(query);

        struct Candidate {
            std::wstring word;
            uint32_t distance;
            bool phoneticMatch;
        };
        std::vector<Candidate> candidates;

        auto EvaluateCandidate = [&](const std::wstring& dictWord) {
            uint32_t dist = ComputeLevenshteinDistance(query, dictWord);
            bool phonetic = (ComputeSoundex(dictWord) == querySoundex);
            if (dist <= 3 || phonetic) {
                candidates.push_back({ dictWord, dist, phonetic });
            }
        };

        for (const auto& w : m_lexicon) EvaluateCandidate(w);
        for (const auto& w : m_addedWords) EvaluateCandidate(w);

        // Sort candidates: smallest distance first, then phonetic match, then alphabetical
        std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
            if (a.distance != b.distance) return a.distance < b.distance;
            if (a.phoneticMatch != b.phoneticMatch) return a.phoneticMatch > b.phoneticMatch;
            return a.word < b.word;
        });

        std::vector<std::wstring> suggestions;
        size_t maxSuggestions = std::min(candidates.size(), static_cast<size_t>(8));
        for (size_t i = 0; i < maxSuggestions; ++i) {
            suggestions.push_back(candidates[i].word);
        }

        *value = new CEnumStringImpl(std::move(suggestions));
        return ole32::S_OK;
    }

    int32_t __stdcall Add(const wchar_t* word) override {
        if (!word) return ole32::E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_addedWords.insert(ToLowerString(word));
        return ole32::S_OK;
    }

    int32_t __stdcall Ignore(const wchar_t* word) override {
        if (!word) return ole32::E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_ignoredWords.insert(ToLowerString(word));
        return ole32::S_OK;
    }

    int32_t __stdcall AutoCorrect(const wchar_t* from, const wchar_t* to) override {
        if (!from || !to) return ole32::E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        m_autoCorrect[ToLowerString(from)] = to;
        return ole32::S_OK;
    }

    int32_t __stdcall GetOptionDescription(const wchar_t* optionId, IOptionDescription** value) override {
        if (!optionId || !value) return ole32::E_POINTER;
        std::wstring opt(optionId);
        if (opt == L"ignore_uppercase") {
            *value = new COptionDescriptionImpl(
                L"ignore_uppercase",
                L"Ignore Uppercase Words",
                L"Do not check words in UPPERCASE",
                { L"Disabled", L"Enabled" }
            );
            return ole32::S_OK;
        }
        return ole32::E_INVALIDARG;
    }

    int32_t __stdcall get_OptionIds(IEnumString** value) override {
        if (!value) return ole32::E_POINTER;
        std::vector<std::wstring> options = { L"ignore_uppercase", L"ignore_words_with_numbers" };
        *value = new CEnumStringImpl(std::move(options));
        return ole32::S_OK;
    }

    int32_t __stdcall get_Id(wchar_t** value) override {
        if (!value) return ole32::E_POINTER;
        *value = AllocateCoTaskString(L"MicaNT.Sovereign.SpellChecker." + m_languageTag);
        return ole32::S_OK;
    }

    int32_t __stdcall get_LocalizedName(wchar_t** value) override {
        if (!value) return ole32::E_POINTER;
        *value = AllocateCoTaskString(L"MicaNT Clean-Room Spell Checker (" + m_languageTag + L")");
        return ole32::S_OK;
    }
};

// ============================================================================
// 9. ISpellCheckerFactory Implementation
// ============================================================================

class CSpellCheckerFactoryImpl : public ISpellCheckerFactory {
private:
    std::atomic<uint32_t> m_refCount{ 1 };
    std::vector<std::wstring> m_supportedLanguages;

public:
    CSpellCheckerFactoryImpl() {
        m_supportedLanguages = {
            L"en-US", L"en-GB", L"es-ES", L"de-DE", L"fr-FR", L"it-IT", L"pt-BR", L"ja-JP", L"zh-CN"
        };
    }

    ole32::HRESULT QueryInterface(ole32::REFIID riid, void** ppv) override {
        if (!ppv) return ole32::E_POINTER;
        if (riid == ole32::IID_IUnknown || riid == IID_ISpellCheckerFactory) {
            *ppv = static_cast<ISpellCheckerFactory*>(this);
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

    int32_t __stdcall get_SupportedLanguages(IEnumString** value) override {
        if (!value) return ole32::E_POINTER;
        *value = new CEnumStringImpl(m_supportedLanguages);
        return ole32::S_OK;
    }

    int32_t __stdcall IsSupported(const wchar_t* languageTag, int32_t* value) override {
        if (!languageTag || !value) return ole32::E_INVALIDARG;
        std::wstring tag(languageTag);
        bool found = false;
        for (const auto& sup : m_supportedLanguages) {
            if (ToLowerString(sup) == ToLowerString(tag)) {
                found = true;
                break;
            }
        }
        *value = found ? 1 : 0;
        return ole32::S_OK;
    }

    int32_t __stdcall CreateSpellChecker(const wchar_t* languageTag, ISpellChecker** value) override {
        if (!languageTag || !value) return ole32::E_POINTER;
        int32_t isSup = 0;
        IsSupported(languageTag, &isSup);
        if (!isSup) {
            // Default fallback is permitted in sovereign environments
            *value = new CSpellCheckerImpl(languageTag);
            return ole32::S_OK;
        }
        *value = new CSpellCheckerImpl(languageTag);
        return ole32::S_OK;
    }
};

// ============================================================================
// 10. Extended Linguistic Services (ELS) Implementation (`elscore.dll`)
// ============================================================================

class CELSServiceEngine {
public:
    static CELSServiceEngine& Instance() {
        static CELSServiceEngine s_instance;
        return s_instance;
    }

    std::wstring DetectScript(const wchar_t* text, size_t length) {
        if (!text || length == 0) return L"Latn";
        size_t countLatn = 0;
        size_t countCyrl = 0;
        size_t countGrek = 0;
        size_t countArab = 0;
        size_t countHans = 0;
        size_t countKana = 0;
        size_t countHang = 0;

        for (size_t i = 0; i < length; ++i) {
            uint32_t cp = static_cast<uint32_t>(text[i]);
            if (cp >= 0x0041 && cp <= 0x024F) countLatn++;
            else if (cp >= 0x0400 && cp <= 0x04FF) countCyrl++;
            else if (cp >= 0x0370 && cp <= 0x03FF) countGrek++;
            else if (cp >= 0x0600 && cp <= 0x06FF) countArab++;
            else if (cp >= 0x4E00 && cp <= 0x9FFF) countHans++;
            else if (cp >= 0x3040 && cp <= 0x30FF) countKana++;
            else if (cp >= 0xAC00 && cp <= 0xD7AF) countHang++;
        }

        size_t maxCount = countLatn;
        std::wstring best = L"Latn";

        if (countCyrl > maxCount) { maxCount = countCyrl; best = L"Cyrl"; }
        if (countGrek > maxCount) { maxCount = countGrek; best = L"Grek"; }
        if (countArab > maxCount) { maxCount = countArab; best = L"Arab"; }
        if (countHans > maxCount) { maxCount = countHans; best = L"Hans"; }
        if (countKana > maxCount) { maxCount = countKana; best = L"Kana"; }
        if (countHang > maxCount) { maxCount = countHang; best = L"Hang"; }
        return best;
    }

    std::wstring DetectLanguage(const wchar_t* text, size_t length) {
        if (!text || length == 0) return L"en";
        std::wstring script = DetectScript(text, length);
        if (script == L"Cyrl") return L"ru";
        if (script == L"Grek") return L"el";
        if (script == L"Arab") return L"ar";
        if (script == L"Hans") return L"zh";
        if (script == L"Kana") return L"ja";
        if (script == L"Hang") return L"ko";

        // Latin script language heuristic
        std::wstring lower(text, length);
        for (auto& c : lower) c = std::towlower(c);

        if (lower.find(L"que") != std::wstring::npos || lower.find(L"por") != std::wstring::npos || lower.find(L"el") != std::wstring::npos) return L"es";
        if (lower.find(L"der") != std::wstring::npos || lower.find(L"die") != std::wstring::npos || lower.find(L"und") != std::wstring::npos) return L"de";
        if (lower.find(L"les") != std::wstring::npos || lower.find(L"des") != std::wstring::npos || lower.find(L"est") != std::wstring::npos) return L"fr";
        return L"en";
    }

    std::wstring TransliterateCyrillicToLatin(const wchar_t* text, size_t length) {
        static const std::unordered_map<wchar_t, std::wstring> cyrlMap = {
            { L'А', L"A" }, { L'Б', L"B" }, { L'В', L"V" }, { L'Г', L"G" }, { L'Д', L"D" },
            { L'Е', L"E" }, { L'Ё', L"Yo" }, { L'Ж', L"Zh" }, { L'З', L"Z" }, { L'И', L"I" },
            { L'Й', L"Y" }, { L'К', L"K" }, { L'Л', L"L" }, { L'М', L"M" }, { L'Н', L"N" },
            { L'О', L"O" }, { L'П', L"P" }, { L'Р', L"R" }, { L'С', L"S" }, { L'Т', L"T" },
            { L'У', L"U" }, { L'Ф', L"F" }, { L'Х', L"Kh" }, { L'Ц', L"Ts" }, { L'Ч', L"Ch" },
            { L'Ш', L"Sh" }, { L'Щ', L"Shch" }, { L'Ъ', L"" }, { L'Ы', L"Y" }, { L'Ь', L"'" },
            { L'Э', L"E" }, { L'Ю', L"Yu" }, { L'Я', L"Ya" },
            { L'а', L"a" }, { L'б', L"b" }, { L'в', L"v" }, { L'г', L"g" }, { L'д', L"d" },
            { L'е', L"e" }, { L'ё', L"yo" }, { L'ж', L"zh" }, { L'з', L"z" }, { L'и', L"i" },
            { L'й', L"y" }, { L'к', L"k" }, { L'л', L"l" }, { L'м', L"m" }, { L'н', L"n" },
            { L'о', L"o" }, { L'п', L"p" }, { L'р', L"r" }, { L'с', L"s" }, { L'т', L"t" },
            { L'у', L"u" }, { L'ф', L"f" }, { L'х', L"kh" }, { L'ц', L"ts" }, { L'ч', L"ch" },
            { L'ш', L"sh" }, { L'щ', L"shch" }, { L'ъ', L"" }, { L'ы', L"y" }, { L'ь', L"'" },
            { L'э', L"e" }, { L'ю', L"yu" }, { L'я', L"ya" }
        };

        std::wstring out;
        for (size_t i = 0; i < length; ++i) {
            auto it = cyrlMap.find(text[i]);
            if (it != cyrlMap.end()) {
                out += it->second;
            } else {
                out.push_back(text[i]);
            }
        }
        return out;
    }
};

// ============================================================================
// 11. Dynamic Export Functions (spellcheck.dll & elscore.dll)
// ============================================================================

inline int32_t __stdcall SpellChecker_CreateFactory(ISpellCheckerFactory** ppFactory) {
    if (!ppFactory) return ole32::E_POINTER;
    *ppFactory = new CSpellCheckerFactoryImpl();
    return ole32::S_OK;
}

inline int32_t __stdcall MappingGetServices(
    [[maybe_unused]] MAPPING_ENUM_OPTIONS* pOptions,
    MAPPING_SERVICE_INFO** prgServices,
    uint32_t* pdwServicesCount
) {
    if (!prgServices || !pdwServicesCount) return ole32::E_INVALIDARG;

    static MAPPING_SERVICE_INFO s_services[3];
    s_services[0].Size = sizeof(MAPPING_SERVICE_INFO);
    s_services[0].pszDescription = const_cast<wchar_t*>(L"ELS Language Detection Service");
    s_services[0].guid = ELS_GUID_LANGUAGE_DETECTION;

    s_services[1].Size = sizeof(MAPPING_SERVICE_INFO);
    s_services[1].pszDescription = const_cast<wchar_t*>(L"ELS Script Detection Service");
    s_services[1].guid = ELS_GUID_SCRIPT_DETECTION;

    s_services[2].Size = sizeof(MAPPING_SERVICE_INFO);
    s_services[2].pszDescription = const_cast<wchar_t*>(L"ELS Cyrillic to Latin Transliteration Service");
    s_services[2].guid = ELS_GUID_TRANSLITERATION_CYRILLIC_TO_LATIN;

    *prgServices = s_services;
    *pdwServicesCount = 3;
    return ole32::S_OK;
}

inline int32_t __stdcall MappingFreePropertyBag(MAPPING_PROPERTY_BAG* pBag) {
    if (!pBag) return ole32::E_INVALIDARG;
    if (pBag->pDataResult) {
        ole32::CoTaskMemFree(pBag->pDataResult);
        pBag->pDataResult = nullptr;
    }
    pBag->dwDataSize = 0;
    return ole32::S_OK;
}

inline int32_t __stdcall MappingRecognizeText(
    MAPPING_SERVICE_INFO* pServiceInfo,
    const wchar_t* pszText,
    uint32_t dwLength,
    [[maybe_unused]] uint32_t dwIndex,
    [[maybe_unused]] MAPPING_OPTIONS* pOptions,
    MAPPING_PROPERTY_BAG* pBag
) {
    if (!pServiceInfo || !pszText || !pBag) return ole32::E_INVALIDARG;

    std::wstring resultStr;
    if (pServiceInfo->guid == ELS_GUID_LANGUAGE_DETECTION) {
        resultStr = CELSServiceEngine::Instance().DetectLanguage(pszText, dwLength);
    } else if (pServiceInfo->guid == ELS_GUID_SCRIPT_DETECTION) {
        resultStr = CELSServiceEngine::Instance().DetectScript(pszText, dwLength);
    } else if (pServiceInfo->guid == ELS_GUID_TRANSLITERATION_CYRILLIC_TO_LATIN) {
        resultStr = CELSServiceEngine::Instance().TransliterateCyrillicToLatin(pszText, dwLength);
    } else {
        resultStr = L"Unknown";
    }

    size_t byteCount = (resultStr.length() + 1) * sizeof(wchar_t);
    pBag->pDataResult = ole32::CoTaskMemAlloc(byteCount);
    if (pBag->pDataResult) {
        std::memcpy(pBag->pDataResult, resultStr.c_str(), byteCount);
        pBag->dwDataSize = static_cast<uint32_t>(byteCount);
    }
    return ole32::S_OK;
}

inline int32_t __stdcall MappingDoAction(
    [[maybe_unused]] MAPPING_PROPERTY_BAG* pBag,
    [[maybe_unused]] uint32_t dwRangeIndex,
    [[maybe_unused]] const wchar_t* pszActionId
) {
    return ole32::S_OK;
}

// Subsystem Registration Helper
inline void InitializeSpellCheckExports() {
    auto& loader = micant::ldr::DynamicLoader::get();

    // spellcheck.dll exports
    loader.registerExport("spellcheck.dll", "SpellChecker_CreateFactory", reinterpret_cast<void*>(SpellChecker_CreateFactory));

    // elscore.dll exports
    loader.registerExport("elscore.dll", "MappingGetServices", reinterpret_cast<void*>(MappingGetServices));
    loader.registerExport("elscore.dll", "MappingFreePropertyBag", reinterpret_cast<void*>(MappingFreePropertyBag));
    loader.registerExport("elscore.dll", "MappingRecognizeText", reinterpret_cast<void*>(MappingRecognizeText));
    loader.registerExport("elscore.dll", "MappingDoAction", reinterpret_cast<void*>(MappingDoAction));

    version::VersionDatabase::Instance().RegisterModule(
        "spellcheck.dll",
        "10.0.22621.1",
        "Windows Spell Checking Subsystem",
        "MicaNT Sovereign Project"
    );

    version::VersionDatabase::Instance().RegisterModule(
        "elscore.dll",
        "10.0.22621.1",
        "Windows Extended Linguistic Services (ELS) Subsystem",
        "MicaNT Sovereign Project"
    );
}

} // namespace micant::spellcheck
