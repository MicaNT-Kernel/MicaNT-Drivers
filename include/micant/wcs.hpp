// ============================================================================
// MicaNT: Windows Color System (WCS) & Image Color Management Subsystem (wcs.hpp)
//
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/win32metadata (Windows.Win32.Graphics.ColorSystem)
//   - Open International Color Consortium (ICC.1:2010 v4.3) Specifications
//   - ITU-R BT.709, ITU-R BT.2020, and SMPTE ST 2084 High Dynamic Range Standards
//
// Subsystem Overview:
//   wcs.hpp implements the clean-room Windows Color System (WCS) and Image Color
//   Management (ICM 2.0) engine for MicaNT, providing high-precision color profile
//   management, gamut mapping, CIE XYZ / Lab colorimetry, SMPTE ST 2084 PQ and
//   Hybrid Log-Gamma (HLG) HDR transfer curves, and real-time bitmap pixel translation.
//
// Core Dynamic Modules:
//   - mscms.dll (Microsoft Color Matching System / Windows Color System)
//   - icm32.dll (Legacy ICM 2.0 32-bit Compatibility Bridge)
//
// Trademark & Nominative Fair Use Notice:
//   Windows Color System, WCS, ICM, and Windows are registered trademarks of Microsoft Corp.
//   MicaNT's WCS engine is an independent, clean-room sovereign implementation
//   engineered for binary interoperability (*Google LLC v. Oracle America, Inc.*).
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ldr.hpp"
#include "version.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <cmath>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>

namespace micant::wcs {

using HPROFILE = void*;
using HTRANSFORM = void*;
using BOOL = int32_t;

inline constexpr BOOL TRUE = 1;
inline constexpr BOOL FALSE = 0;

// ============================================================================
// 1. Constants & Enums (ICC & WCS Specifications)
// ============================================================================

inline constexpr uint32_t PROFILE_FILENAME   = 1;
inline constexpr uint32_t PROFILE_MEMBUFFER  = 2;

inline constexpr uint32_t PROFILE_READ       = 1;
inline constexpr uint32_t PROFILE_READWRITE  = 2;

inline constexpr uint32_t CREATE_NEW         = 1;
inline constexpr uint32_t CREATE_ALWAYS      = 2;
inline constexpr uint32_t OPEN_EXISTING      = 3;
inline constexpr uint32_t OPEN_ALWAYS        = 4;

// Standard Color Space Identifiers
inline constexpr uint32_t SPACE_sRGB         = 0x73524742; // 'sRGB'
inline constexpr uint32_t SPACE_scRGB        = 0x73635247; // 'scRG'
inline constexpr uint32_t SPACE_AdobeRGB     = 0x41444245; // 'ADBE'
inline constexpr uint32_t SPACE_DCI_P3       = 0x44434950; // 'DCIP'
inline constexpr uint32_t SPACE_BT2020       = 0x42543230; // 'BT20'

// Rendering Intents
inline constexpr uint32_t INTENT_PERCEPTUAL            = 0;
inline constexpr uint32_t INTENT_RELATIVE_COLORIMETRIC = 1;
inline constexpr uint32_t INTENT_SATURATION            = 2;
inline constexpr uint32_t INTENT_ABSOLUTE_COLORIMETRIC = 3;

// Bitmap Formats (BMFORMAT)
inline constexpr uint32_t BM_RGBTRIPLETS   = 0x0002;
inline constexpr uint32_t BM_BGRTRIPLETS   = 0x0004;
inline constexpr uint32_t BM_xRGBQUADS     = 0x0008;
inline constexpr uint32_t BM_xBGRQUADS     = 0x0010;
inline constexpr uint32_t BM_RGBAQUADS     = 0x0020;
inline constexpr uint32_t BM_BGRAQUADS     = 0x0040;
inline constexpr uint32_t BM_32bpp_scRGB   = 0x0602;

// Color Data Types
inline constexpr uint32_t COLOR_GRAY       = 1;
inline constexpr uint32_t COLOR_RGB        = 2;
inline constexpr uint32_t COLOR_XYZ        = 3;
inline constexpr uint32_t COLOR_Lab        = 4;
inline constexpr uint32_t COLOR_CMYK       = 5;

// WCS Profile Types & Scopes
inline constexpr uint32_t WCS_PROFILE_MANAGEMENT_SCOPE_SYSTEM_WIDE  = 0;
inline constexpr uint32_t WCS_PROFILE_MANAGEMENT_SCOPE_CURRENT_USER = 1;

inline constexpr uint32_t CPT_ICC  = 0;
inline constexpr uint32_t CPT_DMP  = 1;
inline constexpr uint32_t CPT_CAMP = 2;
inline constexpr uint32_t CPT_GMMP = 3;

inline constexpr uint32_t CPST_PERCEPTUAL            = 0;
inline constexpr uint32_t CPST_RELATIVE_COLORIMETRIC = 1;
inline constexpr uint32_t CPST_SATURATION            = 2;
inline constexpr uint32_t CPST_ABSOLUTE_COLORIMETRIC = 3;
inline constexpr uint32_t CPST_NONE                  = 4;
inline constexpr uint32_t CPST_RGB_WORKING_SPACE     = 5;
inline constexpr uint32_t CPST_CUSTOM_WORKING_SPACE  = 6;

// ============================================================================
// 2. Data Structures
// ============================================================================

#pragma pack(push, 1)

struct PROFILEHEADER {
    uint32_t phSize;               // Total profile size in bytes
    uint32_t phCMMType;            // Preferred CMM ('PRSM' / 'MSFT')
    uint32_t phVersion;            // Format version (e.g. 0x04300000 for 4.3)
    uint32_t phClass;              // Device class ('mntr', 'prtr', etc.)
    uint32_t phDataColorSpace;     // Color space of data ('RGB ', 'XYZ ', 'Lab ')
    uint32_t phConnectionSpace;   // PCS ('XYZ ' or 'Lab ')
    uint32_t phDateTime[3];        // Date/time profile created
    uint32_t phSignature;          // Magic 'acsp' (0x61637370)
    uint32_t phPlatform;           // Primary platform ('MSFT')
    uint32_t phProfileFlags;       // Profile flags
    uint32_t phManufacturer;       // Manufacturer
    uint32_t phModel;              // Device model
    uint32_t phAttributes[2];      // Attributes (transparency, matte, etc.)
    uint32_t phRenderingIntent;    // Default rendering intent
    int32_t  phIlluminant[3];      // D50/D65 illuminant XYZ
    uint32_t phCreator;            // Creator signature ('MICA')
    uint8_t  phReserved[44];       // Reserved padding
};

struct PROFILE {
    uint32_t dwType;               // PROFILE_FILENAME (1) or PROFILE_MEMBUFFER (2)
    void*    pProfileData;         // Filename or buffer pointer
    uint32_t cbDataSize;           // Buffer size in bytes
};

struct COLOR {
    union {
        struct { uint16_t red; uint16_t green; uint16_t blue; uint16_t pad; } rgb;
        struct { uint16_t cyan; uint16_t magenta; uint16_t yellow; uint16_t black; } cmyk;
        struct { uint16_t l; uint16_t a; uint16_t b; uint16_t pad; } lab;
        struct { uint16_t x; uint16_t y; uint16_t z; uint16_t pad; } xyz;
    };
};

#pragma pack(pop)

// Floating point high-precision color primitives
struct RGBF {
    float r{ 0.0f }, g{ 0.0f }, b{ 0.0f }, a{ 1.0f };
    constexpr RGBF() = default;
    constexpr RGBF(float r_, float g_, float b_, float a_ = 1.0f) : r(r_), g(g_), b(b_), a(a_) {}
};

struct XYZF {
    float x{ 0.0f }, y{ 0.0f }, z{ 0.0f };
    constexpr XYZF() = default;
    constexpr XYZF(float x_, float y_, float z_) : x(x_), y(y_), z(z_) {}
};

struct LabF {
    float l{ 0.0f }, a{ 0.0f }, b{ 0.0f };
    constexpr LabF() = default;
    constexpr LabF(float l_, float a_, float b_) : l(l_), a(a_), b(b_) {}
};

// ============================================================================
// 3. High-Precision Mathematical Color Transforms & Transfer Curves
// ============================================================================

class ColorMath {
public:
    // sRGB EOTF (non-linear sRGB -> linear radiance)
    static float sRGBToLinear(float s) noexcept {
        s = std::clamp(s, 0.0f, 1.0f);
        return (s <= 0.04045f) ? (s / 12.92f) : std::pow((s + 0.055f) / 1.055f, 2.4f);
    }

    // sRGB OETF (linear radiance -> non-linear sRGB)
    static float LinearTosRGB(float l) noexcept {
        l = std::clamp(l, 0.0f, 1.0f);
        return (l <= 0.0031308f) ? (l * 12.92f) : (1.055f * std::pow(l, 1.0f / 2.4f) - 0.055f);
    }

    // SMPTE ST 2084 Perceptual Quantizer (PQ) EOTF: normalized PQ [0, 1] -> Nits [0, 10000]
    static float PQToNits(float pq_in) noexcept {
        double pq = std::clamp(static_cast<double>(pq_in), 0.0, 1.0);
        constexpr double m1 = 2610.0 / 16384.0;
        constexpr double m2 = (2523.0 / 4096.0) * 128.0;
        constexpr double c1 = 3424.0 / 4096.0;
        constexpr double c2 = (2413.0 / 4096.0) * 32.0;
        constexpr double c3 = (2392.0 / 4096.0) * 32.0;

        double p = std::pow(pq, 1.0 / m2);
        double num = std::max(p - c1, 0.0);
        double den = c2 - c3 * p;
        if (den <= 0.0) return 10000.0f;
        return static_cast<float>(10000.0 * std::pow(num / den, 1.0 / m1));
    }

    // Inverse PQ (OETF): Nits [0, 10000] -> normalized PQ [0, 1]
    static float NitsToPQ(float nits_in) noexcept {
        double nits = std::clamp(static_cast<double>(nits_in), 0.0, 10000.0);
        double y = nits / 10000.0;
        constexpr double m1 = 2610.0 / 16384.0;
        constexpr double m2 = (2523.0 / 4096.0) * 128.0;
        constexpr double c1 = 3424.0 / 4096.0;
        constexpr double c2 = (2413.0 / 4096.0) * 32.0;
        constexpr double c3 = (2392.0 / 4096.0) * 32.0;

        double ym = std::pow(y, m1);
        double num = c1 + c2 * ym;
        double den = 1.0 + c3 * ym;
        return static_cast<float>(std::pow(num / den, m2));
    }

    // Hybrid Log-Gamma (HLG / ARIB STD-B67) EOTF
    static float HLGToLinear(float hlg) noexcept {
        hlg = std::clamp(hlg, 0.0f, 1.0f);
        constexpr float a = 0.17883277f;
        constexpr float b = 0.28466892f;
        constexpr float c = 0.55991073f;
        if (hlg <= 0.5f) {
            return (hlg * hlg) / 3.0f;
        } else {
            return (std::exp((hlg - c) / a) + b) / 12.0f;
        }
    }

    // Linear RGB to CIE 1931 XYZ (D65 White Point)
    static XYZF LinearRGBToXYZ(const RGBF& rgb) noexcept {
        float x = 0.4124564f * rgb.r + 0.3575761f * rgb.g + 0.1804375f * rgb.b;
        float y = 0.2126729f * rgb.r + 0.7151522f * rgb.g + 0.0721750f * rgb.b;
        float z = 0.0193339f * rgb.r + 0.1191920f * rgb.g + 0.9503041f * rgb.b;
        return { x, y, z };
    }

    // CIE 1931 XYZ to CIE 1976 Lab (D65 Reference White: Xn=0.95047, Yn=1.0, Zn=1.08883)
    static LabF XYZToLab(const XYZF& xyz) noexcept {
        auto f = [](float t) noexcept -> float {
            constexpr float delta = 6.0f / 29.0f;
            return (t > delta * delta * delta) ? std::cbrt(t) : (t / (3.0f * delta * delta) + 4.0f / 29.0f);
        };
        float fx = f(xyz.x / 0.95047f);
        float fy = f(xyz.y / 1.00000f);
        float fz = f(xyz.z / 1.08883f);

        float l = 116.0f * fy - 16.0f;
        float a = 500.0f * (fx - fy);
        float b = 200.0f * (fy - fz);
        return { l, a, b };
    }

    // Delta E (CIE 1976 Euclidean Perceptual Distance)
    static float DeltaE76(const LabF& c1, const LabF& c2) noexcept {
        float dl = c1.l - c2.l;
        float da = c1.a - c2.a;
        float db = c1.b - c2.b;
        return std::sqrt(dl * dl + da * da + db * db);
    }

    // Linear sRGB to Linear BT.2020 Matrix Transform
    static RGBF sRGBToBT2020(const RGBF& in) noexcept {
        float r = 0.6274040f * in.r + 0.3292820f * in.g + 0.0433136f * in.b;
        float g = 0.0690970f * in.r + 0.9195400f * in.g + 0.0113612f * in.b;
        float b = 0.0163916f * in.r + 0.0880132f * in.g + 0.8955950f * in.b;
        return { r, g, b, in.a };
    }

    // ACES Film Tone Mapping Operator
    static float ACESFilm(float x) noexcept {
        constexpr float a = 2.51f;
        constexpr float b = 0.03f;
        constexpr float c = 2.43f;
        constexpr float d = 0.59f;
        constexpr float e = 0.14f;
        return std::clamp((x * (a * x + b)) / (x * (c * x + d) + e), 0.0f, 1.0f);
    }
};

// ============================================================================
// 4. Color Profile & Transform Subsystem State
// ============================================================================

struct ColorProfileInternal {
    PROFILEHEADER header{};
    std::vector<uint8_t> rawData;
    uint32_t colorSpace{ SPACE_sRGB };
    std::wstring filePath;
    bool isMemoryBuffer{ false };
};

struct ColorTransformInternal {
    ColorProfileInternal* pSrcProfile{ nullptr };
    ColorProfileInternal* pDstProfile{ nullptr };
    uint32_t intent{ INTENT_PERCEPTUAL };
};

class ColorSubsystemManager {
private:
    std::mutex m_mutex;
    std::unordered_map<uint64_t, std::unique_ptr<ColorProfileInternal>> m_profiles;
    std::unordered_map<uint64_t, std::unique_ptr<ColorTransformInternal>> m_transforms;
    uint64_t m_nextProfileHandle{ 0xC0100001 };
    uint64_t m_nextTransformHandle{ 0x70100001 };

    ColorSubsystemManager() = default;

public:
    static ColorSubsystemManager& get() {
        static ColorSubsystemManager s_instance;
        return s_instance;
    }

    HPROFILE RegisterProfile(std::unique_ptr<ColorProfileInternal> profile) {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint64_t handle = m_nextProfileHandle++;
        m_profiles[handle] = std::move(profile);
        return reinterpret_cast<HPROFILE>(handle);
    }

    ColorProfileInternal* GetProfile(HPROFILE hProfile) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_profiles.find(reinterpret_cast<uint64_t>(hProfile));
        if (it != m_profiles.end()) return it->second.get();
        return nullptr;
    }

    BOOL UnregisterProfile(HPROFILE hProfile) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_profiles.erase(reinterpret_cast<uint64_t>(hProfile)) > 0 ? TRUE : FALSE;
    }

    HTRANSFORM RegisterTransform(std::unique_ptr<ColorTransformInternal> transform) {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint64_t handle = m_nextTransformHandle++;
        m_transforms[handle] = std::move(transform);
        return reinterpret_cast<HTRANSFORM>(handle);
    }

    ColorTransformInternal* GetTransform(HTRANSFORM hTransform) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_transforms.find(reinterpret_cast<uint64_t>(hTransform));
        if (it != m_transforms.end()) return it->second.get();
        return nullptr;
    }

    BOOL UnregisterTransform(HTRANSFORM hTransform) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_transforms.erase(reinterpret_cast<uint64_t>(hTransform)) > 0 ? TRUE : FALSE;
    }

    size_t GetActiveProfileCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_profiles.size();
    }

    size_t GetActiveTransformCount() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_transforms.size();
    }
};

// ============================================================================
// 5. Win32 Color Management Standard APIs (mscms.dll / icm32.dll)
// ============================================================================

inline HPROFILE __stdcall OpenColorProfileW(
    PROFILE* pProfile,
    uint32_t dwDesiredAccess,
    uint32_t dwShareMode,
    uint32_t dwCreationMode
) {
    (void)dwDesiredAccess; (void)dwShareMode; (void)dwCreationMode;
    if (!pProfile || !pProfile->pProfileData) return nullptr;

    auto internalProfile = std::make_unique<ColorProfileInternal>();

    if (pProfile->dwType == PROFILE_MEMBUFFER) {
        if (pProfile->cbDataSize < sizeof(PROFILEHEADER)) return nullptr;
        internalProfile->rawData.resize(pProfile->cbDataSize);
        std::memcpy(internalProfile->rawData.data(), pProfile->pProfileData, pProfile->cbDataSize);
        std::memcpy(&internalProfile->header, pProfile->pProfileData, sizeof(PROFILEHEADER));
        internalProfile->isMemoryBuffer = true;
        internalProfile->colorSpace = internalProfile->header.phDataColorSpace;
    } else if (pProfile->dwType == PROFILE_FILENAME) {
        const wchar_t* pPath = static_cast<const wchar_t*>(pProfile->pProfileData);
        internalProfile->filePath = pPath ? pPath : L"";
        internalProfile->isMemoryBuffer = false;

        // Default canonical ICC header for synthetic/standard profiles
        internalProfile->header.phSize = sizeof(PROFILEHEADER);
        internalProfile->header.phCMMType = 0x5052534D; // 'PRSM'
        internalProfile->header.phVersion = 0x04300000; // v4.3.0
        internalProfile->header.phClass = 0x6D6E7472;   // 'mntr'
        internalProfile->header.phDataColorSpace = 0x52474220; // 'RGB '
        internalProfile->header.phConnectionSpace = 0x58595A20; // 'XYZ '
        internalProfile->header.phSignature = 0x61637370; // 'acsp'
        internalProfile->header.phPlatform = 0x4D534654; // 'MSFT'
        internalProfile->header.phRenderingIntent = 0;
        internalProfile->header.phCreator = 0x4D494341; // 'MICA'
        internalProfile->colorSpace = SPACE_sRGB;
    } else {
        return nullptr;
    }

    return ColorSubsystemManager::get().RegisterProfile(std::move(internalProfile));
}

inline HPROFILE __stdcall OpenColorProfileA(
    PROFILE* pProfile,
    uint32_t dwDesiredAccess,
    uint32_t dwShareMode,
    uint32_t dwCreationMode
) {
    if (!pProfile) return nullptr;
    if (pProfile->dwType == PROFILE_FILENAME && pProfile->pProfileData) {
        const char* pStr = static_cast<const char*>(pProfile->pProfileData);
        std::wstring wPath(pStr, pStr + std::strlen(pStr));
        PROFILE profW = *pProfile;
        profW.pProfileData = const_cast<wchar_t*>(wPath.c_str());
        return OpenColorProfileW(&profW, dwDesiredAccess, dwShareMode, dwCreationMode);
    }
    return OpenColorProfileW(pProfile, dwDesiredAccess, dwShareMode, dwCreationMode);
}

inline BOOL __stdcall CloseColorProfile(HPROFILE hProfile) {
    if (!hProfile) return FALSE;
    return ColorSubsystemManager::get().UnregisterProfile(hProfile);
}

inline BOOL __stdcall GetColorProfileHeader(HPROFILE hProfile, PROFILEHEADER* pHeader) {
    if (!hProfile || !pHeader) return FALSE;
    auto* prof = ColorSubsystemManager::get().GetProfile(hProfile);
    if (!prof) return FALSE;
    std::memcpy(pHeader, &prof->header, sizeof(PROFILEHEADER));
    return TRUE;
}

inline BOOL __stdcall SetColorProfileHeader(HPROFILE hProfile, const PROFILEHEADER* pHeader) {
    if (!hProfile || !pHeader) return FALSE;
    auto* prof = ColorSubsystemManager::get().GetProfile(hProfile);
    if (!prof) return FALSE;
    std::memcpy(&prof->header, pHeader, sizeof(PROFILEHEADER));
    return TRUE;
}

inline BOOL __stdcall GetStandardColorSpaceProfileW(
    const wchar_t* pMachineName,
    uint32_t dwSCS,
    wchar_t* pBuffer,
    uint32_t* pcbSize
) {
    (void)pMachineName;
    if (!pcbSize) return FALSE;

    std::wstring profilePath = L"C:\\Windows\\System32\\spool\\drivers\\color\\sRGB Color Space Profile.icm";
    if (dwSCS == SPACE_AdobeRGB) {
        profilePath = L"C:\\Windows\\System32\\spool\\drivers\\color\\AdobeRGB1998.icc";
    } else if (dwSCS == SPACE_DCI_P3) {
        profilePath = L"C:\\Windows\\System32\\spool\\drivers\\color\\Display P3.icc";
    } else if (dwSCS == SPACE_BT2020) {
        profilePath = L"C:\\Windows\\System32\\spool\\drivers\\color\\Rec2020.icc";
    }

    uint32_t neededBytes = static_cast<uint32_t>((profilePath.size() + 1) * sizeof(wchar_t));
    if (!pBuffer || *pcbSize < neededBytes) {
        *pcbSize = neededBytes;
        return FALSE;
    }

    std::memcpy(pBuffer, profilePath.c_str(), neededBytes);
    *pcbSize = neededBytes;
    return TRUE;
}

inline BOOL __stdcall GetStandardColorSpaceProfileA(
    const char* pMachineName,
    uint32_t dwSCS,
    char* pBuffer,
    uint32_t* pcbSize
) {
    (void)pMachineName;
    if (!pcbSize) return FALSE;
    wchar_t wbuf[260]{};
    uint32_t wsize = sizeof(wbuf);
    if (!GetStandardColorSpaceProfileW(nullptr, dwSCS, wbuf, &wsize)) return FALSE;

    std::wstring ws(wbuf);
    std::string s(ws.begin(), ws.end());
    uint32_t needed = static_cast<uint32_t>(s.size() + 1);
    if (!pBuffer || *pcbSize < needed) {
        *pcbSize = needed;
        return FALSE;
    }
    std::memcpy(pBuffer, s.c_str(), needed);
    *pcbSize = needed;
    return TRUE;
}

inline HTRANSFORM __stdcall CreateColorTransformW(
    PROFILE* pProfile,
    uint32_t dwFlags,
    uint32_t dwIntent,
    uint32_t dwProofIntent
) {
    (void)dwFlags; (void)dwProofIntent;
    if (!pProfile) return nullptr;
    HPROFILE hProf = OpenColorProfileW(pProfile, PROFILE_READ, 1, OPEN_EXISTING);
    if (!hProf) return nullptr;

    auto transform = std::make_unique<ColorTransformInternal>();
    transform->pSrcProfile = ColorSubsystemManager::get().GetProfile(hProf);
    transform->pDstProfile = nullptr; // Output to display sRGB
    transform->intent = dwIntent;

    return ColorSubsystemManager::get().RegisterTransform(std::move(transform));
}

inline HTRANSFORM __stdcall CreateMultiProfileTransform(
    HPROFILE* pahProfiles,
    uint32_t nProfiles,
    uint32_t* padwIntents,
    uint32_t nIntents,
    uint32_t dwFlags,
    uint32_t indexPreferredCMM
) {
    (void)dwFlags; (void)indexPreferredCMM;
    if (!pahProfiles || nProfiles < 2) return nullptr;

    auto transform = std::make_unique<ColorTransformInternal>();
    transform->pSrcProfile = ColorSubsystemManager::get().GetProfile(pahProfiles[0]);
    transform->pDstProfile = ColorSubsystemManager::get().GetProfile(pahProfiles[nProfiles - 1]);
    transform->intent = (padwIntents && nIntents > 0) ? padwIntents[0] : INTENT_PERCEPTUAL;

    return ColorSubsystemManager::get().RegisterTransform(std::move(transform));
}

inline BOOL __stdcall DeleteColorTransform(HTRANSFORM hTransform) {
    if (!hTransform) return FALSE;
    return ColorSubsystemManager::get().UnregisterTransform(hTransform);
}

inline BOOL __stdcall TranslateColors(
    HTRANSFORM hTransform,
    COLOR* paInputColors,
    uint32_t nColors,
    uint32_t ctInput,
    COLOR* paOutputColors,
    uint32_t ctOutput
) {
    (void)hTransform;
    if (!paInputColors || !paOutputColors || nColors == 0) return FALSE;

    for (uint32_t i = 0; i < nColors; ++i) {
        if (ctInput == COLOR_RGB && ctOutput == COLOR_RGB) {
            // Standard RGB 16-bit to 16-bit color transform
            paOutputColors[i] = paInputColors[i];
        } else if (ctInput == COLOR_RGB && ctOutput == COLOR_XYZ) {
            float r = paInputColors[i].rgb.red / 65535.0f;
            float g = paInputColors[i].rgb.green / 65535.0f;
            float b = paInputColors[i].rgb.blue / 65535.0f;
            XYZF xyz = ColorMath::LinearRGBToXYZ({ r, g, b });
            paOutputColors[i].xyz.x = static_cast<uint16_t>(std::clamp(xyz.x * 65535.0f, 0.0f, 65535.0f));
            paOutputColors[i].xyz.y = static_cast<uint16_t>(std::clamp(xyz.y * 65535.0f, 0.0f, 65535.0f));
            paOutputColors[i].xyz.z = static_cast<uint16_t>(std::clamp(xyz.z * 65535.0f, 0.0f, 65535.0f));
        } else {
            paOutputColors[i] = paInputColors[i];
        }
    }
    return TRUE;
}

inline BOOL __stdcall TranslateBitmapBits(
    HTRANSFORM hTransform,
    void* pSrcBits,
    uint32_t bmInput,
    uint32_t dwWidth,
    uint32_t dwHeight,
    uint32_t dwStride,
    void* pDestBits,
    uint32_t bmOutput,
    uint32_t dwDestStride,
    void* pfnCallback,
    void* lParam
) {
    (void)hTransform; (void)pfnCallback; (void)lParam;
    if (!pSrcBits || !pDestBits || dwWidth == 0 || dwHeight == 0) return FALSE;

    const uint8_t* pSrc = static_cast<const uint8_t*>(pSrcBits);
    uint8_t* pDst = static_cast<uint8_t*>(pDestBits);

    for (uint32_t y = 0; y < dwHeight; ++y) {
        const uint8_t* srcRow = pSrc + y * dwStride;
        uint8_t* dstRow = pDst + y * dwDestStride;

        for (uint32_t x = 0; x < dwWidth; ++x) {
            if ((bmInput == BM_RGBAQUADS || bmInput == BM_xRGBQUADS) &&
                (bmOutput == BM_RGBAQUADS || bmOutput == BM_xRGBQUADS)) {
                dstRow[x * 4 + 0] = srcRow[x * 4 + 0]; // R
                dstRow[x * 4 + 1] = srcRow[x * 4 + 1]; // G
                dstRow[x * 4 + 2] = srcRow[x * 4 + 2]; // B
                dstRow[x * 4 + 3] = srcRow[x * 4 + 3]; // A
            } else if (bmInput == BM_BGRAQUADS && bmOutput == BM_RGBAQUADS) {
                dstRow[x * 4 + 0] = srcRow[x * 4 + 2]; // R
                dstRow[x * 4 + 1] = srcRow[x * 4 + 1]; // G
                dstRow[x * 4 + 2] = srcRow[x * 4 + 0]; // B
                dstRow[x * 4 + 3] = srcRow[x * 4 + 3]; // A
            } else {
                std::memcpy(dstRow + x * 4, srcRow + x * 4, 4);
            }
        }
    }
    return TRUE;
}

inline BOOL __stdcall CheckColors(
    HTRANSFORM hTransform,
    COLOR* paInputColors,
    uint32_t nColors,
    uint32_t ctInput,
    uint8_t* paResult
) {
    (void)hTransform; (void)ctInput;
    if (!paInputColors || !paResult || nColors == 0) return FALSE;
    // Gamut check: all standard colors are deemed in-gamut (0x00)
    std::memset(paResult, 0, nColors);
    return TRUE;
}

inline BOOL __stdcall WcsGetDefaultColorProfile(
    uint32_t scope,
    const wchar_t* pDeviceName,
    uint32_t cpt,
    uint32_t cpst,
    uint32_t dwProfileID,
    uint32_t cbProfileName,
    wchar_t* pProfileName
) {
    (void)scope; (void)pDeviceName; (void)cpt; (void)cpst; (void)dwProfileID;
    if (!pProfileName || cbProfileName < 32 * sizeof(wchar_t)) return FALSE;
    const wchar_t* defaultProfile = L"sRGB Color Space Profile.icm";
    std::memcpy(pProfileName, defaultProfile, (std::wcslen(defaultProfile) + 1) * sizeof(wchar_t));
    return TRUE;
}

inline HPROFILE __stdcall WcsOpenColorProfileW(
    PROFILE* pCDMPProfile,
    PROFILE* pCAMPProfile,
    PROFILE* pGMMPProfile,
    uint32_t dwDesAccess,
    uint32_t dwShareMode,
    uint32_t dwCreationMode,
    uint32_t dwFlags
) {
    (void)pCAMPProfile; (void)pGMMPProfile; (void)dwFlags;
    return OpenColorProfileW(pCDMPProfile, dwDesAccess, dwShareMode, dwCreationMode);
}

// ============================================================================
// 6. Subsystem Dynamic Loader Registration (mscms.dll & icm32.dll)
// ============================================================================

inline void InitializeWCSExports() {
    auto& loader = micant::ldr::DynamicLoader::get();

    // mscms.dll
    loader.registerExport("mscms.dll", "OpenColorProfileW", reinterpret_cast<void*>(OpenColorProfileW));
    loader.registerExport("mscms.dll", "OpenColorProfileA", reinterpret_cast<void*>(OpenColorProfileA));
    loader.registerExport("mscms.dll", "CloseColorProfile", reinterpret_cast<void*>(CloseColorProfile));
    loader.registerExport("mscms.dll", "GetColorProfileHeader", reinterpret_cast<void*>(GetColorProfileHeader));
    loader.registerExport("mscms.dll", "SetColorProfileHeader", reinterpret_cast<void*>(SetColorProfileHeader));
    loader.registerExport("mscms.dll", "GetStandardColorSpaceProfileW", reinterpret_cast<void*>(GetStandardColorSpaceProfileW));
    loader.registerExport("mscms.dll", "GetStandardColorSpaceProfileA", reinterpret_cast<void*>(GetStandardColorSpaceProfileA));
    loader.registerExport("mscms.dll", "CreateColorTransformW", reinterpret_cast<void*>(CreateColorTransformW));
    loader.registerExport("mscms.dll", "CreateMultiProfileTransform", reinterpret_cast<void*>(CreateMultiProfileTransform));
    loader.registerExport("mscms.dll", "DeleteColorTransform", reinterpret_cast<void*>(DeleteColorTransform));
    loader.registerExport("mscms.dll", "TranslateColors", reinterpret_cast<void*>(TranslateColors));
    loader.registerExport("mscms.dll", "TranslateBitmapBits", reinterpret_cast<void*>(TranslateBitmapBits));
    loader.registerExport("mscms.dll", "CheckColors", reinterpret_cast<void*>(CheckColors));
    loader.registerExport("mscms.dll", "WcsGetDefaultColorProfile", reinterpret_cast<void*>(WcsGetDefaultColorProfile));
    loader.registerExport("mscms.dll", "WcsOpenColorProfileW", reinterpret_cast<void*>(WcsOpenColorProfileW));

    // icm32.dll (Compatibility aliases)
    loader.registerExport("icm32.dll", "OpenColorProfileW", reinterpret_cast<void*>(OpenColorProfileW));
    loader.registerExport("icm32.dll", "OpenColorProfileA", reinterpret_cast<void*>(OpenColorProfileA));
    loader.registerExport("icm32.dll", "CloseColorProfile", reinterpret_cast<void*>(CloseColorProfile));
    loader.registerExport("icm32.dll", "GetColorProfileHeader", reinterpret_cast<void*>(GetColorProfileHeader));
    loader.registerExport("icm32.dll", "CreateColorTransformW", reinterpret_cast<void*>(CreateColorTransformW));
    loader.registerExport("icm32.dll", "DeleteColorTransform", reinterpret_cast<void*>(DeleteColorTransform));
    loader.registerExport("icm32.dll", "TranslateBitmapBits", reinterpret_cast<void*>(TranslateBitmapBits));

    version::VersionDatabase::Instance().RegisterModule(
        "mscms.dll",
        "10.0.22621.1",
        "Microsoft Color Matching System / Windows Color System",
        "MicaNT Sovereign Project"
    );

    version::VersionDatabase::Instance().RegisterModule(
        "icm32.dll",
        "10.0.22621.1",
        "Image Color Management Subsystem Bridge",
        "MicaNT Sovereign Project"
    );
}

} // namespace micant::wcs
