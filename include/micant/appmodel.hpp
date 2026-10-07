// ============================================================================
// MicaNT: Windows AppModel & Modern Application Lifecycle Management (appmodel.hpp)
//
// Strict Clean-Room Implementation based on Microsoft's MIT-licensed:
//   - https://github.com/microsoft/win32metadata (Windows.Win32.Storage.Packaging.Appx)
//   - Open Windows AppModel Architecture & Package Identity Specifications
//   - WinRT Process Lifetime Management (PLM) & Application State Transitions
//
// Subsystem Overview:
//   appmodel.hpp provides the clean-room Windows AppModel subsystem for MicaNT.
//   Supports package identity parsing (FullName, FamilyName, PublisherId, AUMID),
//   AppX / MSIX package manifest parsing (AppxManifest.xml), package catalog
//   management, and Process Lifetime Management (PLM: Active, Suspending, Suspended,
//   Resuming, Terminated) with extended execution grants and memory pressure handling.
//
// Core Dynamic Modules:
//   - kernelbase.dll (Package Identity & AppPolicy APIs)
//   - twinapi.appcore.dll (PLM & Modern Application State Architecture)
//   - appxdeploymentclient.dll (Package Deployment & Manifest Staging Engine)
//
// Trademark & Nominative Fair Use Notice:
//   Windows, Win32, WinRT, AppX, and MSIX are registered trademarks of Microsoft Corp.
//   MicaNT's AppModel subsystem is an independent sovereign clean-room implementation
//   engineered for binary interoperability (*Google LLC v. Oracle America, Inc.*).
// ============================================================================

#pragma once

#include "ntdef.hpp"
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
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>

namespace micant::appmodel {

using LONG = int32_t;
using BOOL = int32_t;
using HANDLE = void*;

inline constexpr BOOL TRUE_VAL = 1;
inline constexpr BOOL FALSE_VAL = 0;

// Win32 AppModel Error Codes
inline constexpr LONG ERROR_SUCCESS_VAL             = 0;
inline constexpr LONG ERROR_INVALID_PARAMETER_VAL   = 87;
inline constexpr LONG ERROR_INSUFFICIENT_BUFFER_VAL = 122;
inline constexpr LONG ERROR_NOT_FOUND_VAL           = 1168;
inline constexpr LONG APPMODEL_ERROR_NO_PACKAGE_VAL = 15700;

// Processor Architectures
inline constexpr uint32_t PROCESSOR_ARCHITECTURE_INTEL_VAL   = 0;
inline constexpr uint32_t PROCESSOR_ARCHITECTURE_ARM_VAL     = 5;
inline constexpr uint32_t PROCESSOR_ARCHITECTURE_AMD64_VAL   = 9;
inline constexpr uint32_t PROCESSOR_ARCHITECTURE_ARM64_VAL   = 12;
inline constexpr uint32_t PROCESSOR_ARCHITECTURE_NEUTRAL_VAL = 11;

// App Policies
enum class AppPolicyProcessTerminationMethod : int32_t {
    ExitProcess = 0,
    TerminateProcess = 1
};

enum class AppPolicyThreadInitializationType : int32_t {
    None = 0,
    InitializeWinRT = 1
};

enum class AppPolicyShowDeveloperDiagnostic : int32_t {
    None = 0,
    ShowUI = 1
};

enum class AppPolicyWindowingModel : int32_t {
    None = 0,
    Universal = 1,
    ClassicDesktop = 2,
    ClassicPhone = 3
};

// PLM Lifecycle States
enum class PlmApplicationState : int32_t {
    NotRunning = 0,
    Running    = 1,
    Suspending = 2,
    Suspended  = 3,
    Resuming   = 4,
    Terminated = 5
};

// Extended Execution Reasons
enum class PlmExtendedExecutionReason : int32_t {
    Unspecified      = 0,
    LocationTracking = 1,
    SavingData       = 2
};

// ============================================================================
// 1. Package Identity Structs
// ============================================================================

#pragma pack(push, 8)

union PACKAGE_VERSION {
    uint64_t Version;
    struct {
        uint16_t Revision;
        uint16_t Build;
        uint16_t Minor;
        uint16_t Major;
    };
};

struct PACKAGE_ID {
    uint32_t        reserved;
    uint32_t        processorArchitecture;
    PACKAGE_VERSION version;
    const wchar_t*  name;
    const wchar_t*  publisher;
    const wchar_t*  resourceId;
    const wchar_t*  publisherId;
};

#pragma pack(pop)

// ============================================================================
// 2. Base32 / Crockford Hash & String Helpers
// ============================================================================

inline std::string WideToUtf8(const std::wstring& wstr) {
    std::string str;
    str.reserve(wstr.size() * 3);
    for (wchar_t wc : wstr) {
        uint32_t cp = static_cast<uint32_t>(wc);
        if (cp <= 0x7F) {
            str.push_back(static_cast<char>(cp));
        } else if (cp <= 0x7FF) {
            str.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
            str.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            str.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
            str.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            str.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return str;
}

inline std::wstring Utf8ToWide(const std::string& str) {
    std::wstring wstr;
    wstr.reserve(str.size());
    size_t i = 0;
    const size_t len = str.size();
    while (i < len) {
        uint8_t b0 = static_cast<uint8_t>(str[i++]);
        if (b0 <= 0x7F) {
            wstr.push_back(static_cast<wchar_t>(b0));
        } else if ((b0 & 0xE0) == 0xC0) {
            if (i < len) {
                uint8_t b1 = static_cast<uint8_t>(str[i++]);
                uint32_t cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F);
                wstr.push_back(static_cast<wchar_t>(cp));
            }
        } else if ((b0 & 0xF0) == 0xE0) {
            if (i + 1 < len) {
                uint8_t b1 = static_cast<uint8_t>(str[i++]);
                uint8_t b2 = static_cast<uint8_t>(str[i++]);
                uint32_t cp = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
                wstr.push_back(static_cast<wchar_t>(cp));
            }
        } else if ((b0 & 0xF8) == 0xF0) {
            if (i + 2 < len) {
                uint8_t b1 = static_cast<uint8_t>(str[i++]);
                uint8_t b2 = static_cast<uint8_t>(str[i++]);
                uint8_t b3 = static_cast<uint8_t>(str[i++]);
                uint32_t cp = ((b0 & 0x07) << 18) | ((b1 & 0x3F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F);
                if (cp > 0xFFFF) {
                    cp -= 0x10000;
                    wstr.push_back(static_cast<wchar_t>(0xD800 + (cp >> 10)));
                    wstr.push_back(static_cast<wchar_t>(0xDC00 + (cp & 0x3FF)));
                } else {
                    wstr.push_back(static_cast<wchar_t>(cp));
                }
            }
        }
    }
    return wstr;
}

// Clean-room Base32 Publisher ID digest generator (13 alphanumeric characters)
inline std::string ComputePublisherId(const std::string& publisher) {
    static constexpr char base32Chars[] = "0123456789abcdefghjkmnpqrstvwxyz";
    uint64_t hash = 14695981039346656037ULL; // FNV-1a 64-bit seed
    for (char c : publisher) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 1099511628211ULL;
    }
    std::string pubId;
    pubId.reserve(13);
    for (size_t i = 0; i < 13; ++i) {
        pubId.push_back(base32Chars[(hash >> (i * 4)) & 0x1F]);
    }
    return pubId;
}

inline std::string ArchitectureToString(uint32_t arch) {
    switch (arch) {
        case PROCESSOR_ARCHITECTURE_AMD64_VAL:   return "x64";
        case PROCESSOR_ARCHITECTURE_ARM64_VAL:   return "arm64";
        case PROCESSOR_ARCHITECTURE_INTEL_VAL:   return "x86";
        case PROCESSOR_ARCHITECTURE_ARM_VAL:     return "arm";
        case PROCESSOR_ARCHITECTURE_NEUTRAL_VAL: return "neutral";
        default:                                 return "neutral";
    }
}

inline uint32_t StringToArchitecture(const std::string& str) {
    if (str == "x64") return PROCESSOR_ARCHITECTURE_AMD64_VAL;
    if (str == "arm64") return PROCESSOR_ARCHITECTURE_ARM64_VAL;
    if (str == "x86") return PROCESSOR_ARCHITECTURE_INTEL_VAL;
    if (str == "arm") return PROCESSOR_ARCHITECTURE_ARM_VAL;
    return PROCESSOR_ARCHITECTURE_NEUTRAL_VAL;
}

// ============================================================================
// 3. AppX / MSIX Manifest Object Model & Parser
// ============================================================================

struct AppxApplication {
    std::string id;
    std::string executable;
    std::string entryPoint;
    std::string displayName;
    std::string square150x150Logo;
    std::string square44x44Logo;
    std::string backgroundColor;
};

struct AppxExtension {
    std::string category;
    std::unordered_map<std::string, std::string> attributes;
};

struct AppxPackageManifest {
    std::string name;
    std::string publisher;
    std::string versionString{"1.0.0.0"};
    PACKAGE_VERSION version{ .Version = 0x0001000000000000ULL };
    uint32_t architecture{ PROCESSOR_ARCHITECTURE_AMD64_VAL };
    std::string resourceId;
    std::string publisherId;

    std::string displayName;
    std::string publisherDisplayName;
    std::string description;
    std::string logo;

    std::string targetDeviceFamily{"Windows.Desktop"};
    std::string minVersion{"10.0.19041.0"};
    std::string maxVersionTested{"10.0.22621.0"};

    std::vector<std::string> capabilities;
    std::vector<AppxApplication> applications;
    std::vector<AppxExtension> extensions;

    std::string GetPackageFullName() const {
        std::ostringstream ss;
        ss << name << "_"
           << version.Major << "." << version.Minor << "." << version.Build << "." << version.Revision
           << "_" << ArchitectureToString(architecture)
           << "_" << (resourceId.empty() ? "" : resourceId)
           << "_" << publisherId;
        return ss.str();
    }

    std::string GetPackageFamilyName() const {
        return name + "_" + publisherId;
    }

    std::string GetAUMID(const std::string& appId = "") const {
        std::string chosenId = appId;
        if (chosenId.empty() && !applications.empty()) {
            chosenId = applications[0].id;
        }
        if (chosenId.empty()) chosenId = "App";
        return GetPackageFamilyName() + "!" + chosenId;
    }
};

class AppxManifestParser {
public:
    static bool Parse(const std::string& xml, AppxPackageManifest& outManifest) {
        if (xml.empty()) return false;

        // Parse Identity
        std::string identityBlock = ExtractTag(xml, "Identity");
        if (!identityBlock.empty()) {
            outManifest.name = ExtractAttribute(identityBlock, "Name");
            outManifest.publisher = ExtractAttribute(identityBlock, "Publisher");
            outManifest.versionString = ExtractAttribute(identityBlock, "Version");
            outManifest.resourceId = ExtractAttribute(identityBlock, "ResourceId");
            std::string archStr = ExtractAttribute(identityBlock, "ProcessorArchitecture");
            if (!archStr.empty()) {
                outManifest.architecture = StringToArchitecture(archStr);
            }
            if (!outManifest.versionString.empty()) {
                outManifest.version = ParseVersion(outManifest.versionString);
            }
            if (!outManifest.publisher.empty()) {
                outManifest.publisherId = ComputePublisherId(outManifest.publisher);
            }
        }

        // Parse Properties
        std::string propsBlock = ExtractBlock(xml, "Properties");
        if (!propsBlock.empty()) {
            outManifest.displayName = ExtractInnerXml(propsBlock, "DisplayName");
            outManifest.publisherDisplayName = ExtractInnerXml(propsBlock, "PublisherDisplayName");
            outManifest.description = ExtractInnerXml(propsBlock, "Description");
            outManifest.logo = ExtractInnerXml(propsBlock, "Logo");
        }

        // Parse TargetDeviceFamily
        std::string tdfBlock = ExtractTag(xml, "TargetDeviceFamily");
        if (!tdfBlock.empty()) {
            outManifest.targetDeviceFamily = ExtractAttribute(tdfBlock, "Name");
            outManifest.minVersion = ExtractAttribute(tdfBlock, "MinVersion");
            outManifest.maxVersionTested = ExtractAttribute(tdfBlock, "MaxVersionTested");
        }

        // Parse Capabilities
        size_t capPos = xml.find("<Capabilities>");
        size_t capEnd = xml.find("</Capabilities>", capPos);
        if (capPos != std::string::npos && capEnd != std::string::npos) {
            std::string capsBlock = xml.substr(capPos, capEnd - capPos + 15);
            size_t cIdx = 0;
            while ((cIdx = capsBlock.find("<Capability", cIdx)) != std::string::npos) {
                size_t closeIdx = capsBlock.find("/>", cIdx);
                if (closeIdx == std::string::npos) break;
                std::string tag = capsBlock.substr(cIdx, closeIdx - cIdx + 2);
                std::string capName = ExtractAttribute(tag, "Name");
                if (!capName.empty()) outManifest.capabilities.push_back(capName);
                cIdx = closeIdx + 2;
            }
            // Also check for <rescap:Capability>
            cIdx = 0;
            while ((cIdx = capsBlock.find("<rescap:Capability", cIdx)) != std::string::npos) {
                size_t closeIdx = capsBlock.find("/>", cIdx);
                if (closeIdx == std::string::npos) break;
                std::string tag = capsBlock.substr(cIdx, closeIdx - cIdx + 2);
                std::string capName = ExtractAttribute(tag, "Name");
                if (!capName.empty()) outManifest.capabilities.push_back(capName);
                cIdx = closeIdx + 2;
            }
        }

        // Parse Applications
        size_t appPos = xml.find("<Application ");
        while (appPos != std::string::npos) {
            size_t appEnd = xml.find("</Application>", appPos);
            if (appEnd == std::string::npos) break;
            std::string appBlock = xml.substr(appPos, appEnd - appPos + 14);

            AppxApplication app;
            app.id = ExtractAttribute(appBlock, "Id");
            app.executable = ExtractAttribute(appBlock, "Executable");
            app.entryPoint = ExtractAttribute(appBlock, "EntryPoint");

            std::string uielem = ExtractTag(appBlock, "uap:VisualElements");
            if (uielem.empty()) uielem = ExtractTag(appBlock, "VisualElements");
            if (!uielem.empty()) {
                app.displayName = ExtractAttribute(uielem, "DisplayName");
                app.square150x150Logo = ExtractAttribute(uielem, "Square150x150Logo");
                app.square44x44Logo = ExtractAttribute(uielem, "Square44x44Logo");
                app.backgroundColor = ExtractAttribute(uielem, "BackgroundColor");
            }
            outManifest.applications.push_back(app);
            appPos = xml.find("<Application ", appEnd);
        }

        return !outManifest.name.empty();
    }

private:
    static PACKAGE_VERSION ParseVersion(const std::string& ver) {
        PACKAGE_VERSION pv{};
        std::istringstream iss(ver);
        std::string token;
        uint16_t parts[4] = { 0, 0, 0, 0 };
        int idx = 0;
        while (std::getline(iss, token, '.') && idx < 4) {
            parts[idx++] = static_cast<uint16_t>(std::strtoul(token.c_str(), nullptr, 10));
        }
        pv.Major = parts[0];
        pv.Minor = parts[1];
        pv.Build = parts[2];
        pv.Revision = parts[3];
        return pv;
    }

    static std::string ExtractBlock(const std::string& xml, const std::string& tagName) {
        std::string openTag = "<" + tagName;
        size_t start = xml.find(openTag);
        if (start == std::string::npos) return "";
        size_t tagClose = xml.find(">", start);
        if (tagClose == std::string::npos) return "";
        std::string endTag = "</" + tagName + ">";
        size_t end = xml.find(endTag, tagClose);
        if (end == std::string::npos) {
            return xml.substr(start, tagClose - start + 1);
        }
        return xml.substr(start, (end + endTag.length()) - start);
    }

    static std::string ExtractTag(const std::string& xml, const std::string& tagName) {
        std::string openTag = "<" + tagName;
        size_t start = xml.find(openTag);
        if (start == std::string::npos) return "";
        size_t end = xml.find(">", start);
        if (end == std::string::npos) return "";
        return xml.substr(start, end - start + 1);
    }

    static std::string ExtractAttribute(const std::string& tag, const std::string& attrName) {
        std::string pattern = attrName + "=\"";
        size_t start = tag.find(pattern);
        if (start == std::string::npos) return "";
        start += pattern.length();
        size_t end = tag.find("\"", start);
        if (end == std::string::npos) return "";
        return tag.substr(start, end - start);
    }

    static std::string ExtractInnerXml(const std::string& xml, const std::string& tagName) {
        std::string openTag = "<" + tagName + ">";
        std::string closeTag = "</" + tagName + ">";
        size_t start = xml.find(openTag);
        if (start == std::string::npos) return "";
        start += openTag.length();
        size_t end = xml.find(closeTag, start);
        if (end == std::string::npos) return "";
        return xml.substr(start, end - start);
    }
};

// ============================================================================
// 4. AppModel Package Catalog & Store
// ============================================================================

struct InstalledPackage {
    AppxPackageManifest manifest;
    std::string installPath;
    std::string packageFullName;
    std::string packageFamilyName;
    std::string aumid;
    bool isMSIX{ true };
    bool isFramework{ false };
    std::chrono::system_clock::time_point installTime;
};

class AppModelCatalog {
private:
    std::mutex m_mutex;
    std::unordered_map<std::string, InstalledPackage> m_packagesByFullName;
    std::unordered_map<std::string, std::string> m_familyToFullName;
    std::unordered_map<std::string, std::string> m_aumidToFullName;
    std::string m_currentProcessPackageFullName;

    AppModelCatalog() {
        InitializeStandardPackages();
    }

    void InitializeStandardPackages() {
        // 1. Sovereign Shell
        AppxPackageManifest shellManifest;
        shellManifest.name = "MicaNT.Shell";
        shellManifest.publisher = "CN=MicaNT Sovereign Project";
        shellManifest.publisherId = "sovereign001a";
        shellManifest.version = { .Version = 0x0001000000000000ULL };
        shellManifest.versionString = "1.0.0.0";
        shellManifest.architecture = PROCESSOR_ARCHITECTURE_AMD64_VAL;
        shellManifest.displayName = "MicaNT Shell Experience";
        shellManifest.publisherDisplayName = "MicaNT Sovereign Project";
        shellManifest.capabilities = { "runFullTrust", "localExperienceHost" };
        AppxApplication shellApp;
        shellApp.id = "App";
        shellApp.executable = "micant_shell.exe";
        shellApp.displayName = "MicaNT Shell";
        shellManifest.applications.push_back(shellApp);
        RegisterPackageDirect(shellManifest, "C:\\Windows\\SystemApps\\MicaNT.Shell", false);

        // 2. Sovereign Windows Terminal
        AppxPackageManifest termManifest;
        termManifest.name = "Microsoft.WindowsTerminal";
        termManifest.publisher = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
        termManifest.publisherId = "8wekyb3d8bbwe";
        termManifest.version = { .Version = 0x0001001202860000ULL }; // 1.18.10301.0
        termManifest.versionString = "1.18.10301.0";
        termManifest.architecture = PROCESSOR_ARCHITECTURE_AMD64_VAL;
        termManifest.displayName = "Windows Terminal";
        termManifest.publisherDisplayName = "Microsoft Corporation";
        termManifest.capabilities = { "runFullTrust" };
        AppxApplication termApp;
        termApp.id = "App";
        termApp.executable = "wt.exe";
        termApp.displayName = "Terminal";
        termManifest.applications.push_back(termApp);
        RegisterPackageDirect(termManifest, "C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.18.10301.0_x64__8wekyb3d8bbwe", false);

        // 3. Sovereign Immersive Control Panel / Settings
        AppxPackageManifest setManifest;
        setManifest.name = "windows.immersivecontrolpanel";
        setManifest.publisher = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
        setManifest.publisherId = "cw5n1h2txyewy";
        setManifest.version = { .Version = 0x000A000058650001ULL }; // 10.0.22621.1
        setManifest.versionString = "10.0.22621.1";
        setManifest.architecture = PROCESSOR_ARCHITECTURE_NEUTRAL_VAL;
        setManifest.displayName = "Settings";
        setManifest.publisherDisplayName = "Microsoft Windows";
        AppxApplication setApp;
        setApp.id = "microsoft.windows.immersivecontrolpanel";
        setApp.executable = "SystemSettings.exe";
        setApp.displayName = "Settings";
        setManifest.applications.push_back(setApp);
        RegisterPackageDirect(setManifest, "C:\\Windows\\ImmersiveControlPanel", false);

        // 4. Sovereign Calculator
        AppxPackageManifest calcManifest;
        calcManifest.name = "Microsoft.WindowsCalculator";
        calcManifest.publisher = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
        calcManifest.publisherId = "8wekyb3d8bbwe";
        calcManifest.version = { .Version = 0x000B090100000000ULL }; // 11.2305.0.0
        calcManifest.versionString = "11.2305.0.0";
        calcManifest.architecture = PROCESSOR_ARCHITECTURE_AMD64_VAL;
        calcManifest.displayName = "Calculator";
        calcManifest.publisherDisplayName = "Microsoft Corporation";
        AppxApplication calcApp;
        calcApp.id = "App";
        calcApp.executable = "CalculatorApp.exe";
        calcApp.displayName = "Calculator";
        calcManifest.applications.push_back(calcApp);
        RegisterPackageDirect(calcManifest, "C:\\Program Files\\WindowsApps\\Microsoft.WindowsCalculator_11.2305.0.0_x64__8wekyb3d8bbwe", false);

        // Set default current process package to MicaNT.Shell
        m_currentProcessPackageFullName = shellManifest.GetPackageFullName();
    }

public:
    static AppModelCatalog& get() {
        static AppModelCatalog instance;
        return instance;
    }

    bool RegisterPackageDirect(const AppxPackageManifest& manifest, const std::string& installPath, bool isFramework = false) {
        std::lock_guard<std::mutex> lock(m_mutex);
        InstalledPackage pkg;
        pkg.manifest = manifest;
        pkg.installPath = installPath;
        pkg.packageFullName = manifest.GetPackageFullName();
        pkg.packageFamilyName = manifest.GetPackageFamilyName();
        pkg.aumid = manifest.GetAUMID();
        pkg.isMSIX = true;
        pkg.isFramework = isFramework;
        pkg.installTime = std::chrono::system_clock::now();

        m_packagesByFullName[pkg.packageFullName] = pkg;
        m_familyToFullName[pkg.packageFamilyName] = pkg.packageFullName;
        m_aumidToFullName[pkg.aumid] = pkg.packageFullName;
        return true;
    }

    bool RegisterPackageXml(const std::string& xml, const std::string& installPath, std::string& outFullName) {
        AppxPackageManifest manifest;
        if (!AppxManifestParser::Parse(xml, manifest)) return false;
        outFullName = manifest.GetPackageFullName();
        return RegisterPackageDirect(manifest, installPath, false);
    }

    bool UnregisterPackage(const std::string& fullName) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_packagesByFullName.find(fullName);
        if (it == m_packagesByFullName.end()) return false;
        m_familyToFullName.erase(it->second.packageFamilyName);
        m_aumidToFullName.erase(it->second.aumid);
        m_packagesByFullName.erase(it);
        return true;
    }

    bool FindPackageByFullName(const std::string& fullName, InstalledPackage& outPkg) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_packagesByFullName.find(fullName);
        if (it == m_packagesByFullName.end()) return false;
        outPkg = it->second;
        return true;
    }

    bool FindPackageByFamilyName(const std::string& familyName, InstalledPackage& outPkg) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto fit = m_familyToFullName.find(familyName);
        if (fit == m_familyToFullName.end()) return false;
        auto it = m_packagesByFullName.find(fit->second);
        if (it == m_packagesByFullName.end()) return false;
        outPkg = it->second;
        return true;
    }

    bool FindPackageByAUMID(const std::string& aumid, InstalledPackage& outPkg) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto ait = m_aumidToFullName.find(aumid);
        if (ait == m_aumidToFullName.end()) return false;
        auto it = m_packagesByFullName.find(ait->second);
        if (it == m_packagesByFullName.end()) return false;
        outPkg = it->second;
        return true;
    }

    std::vector<InstalledPackage> GetAllPackages() {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<InstalledPackage> pkgs;
        pkgs.reserve(m_packagesByFullName.size());
        for (const auto& [_, pkg] : m_packagesByFullName) {
            pkgs.push_back(pkg);
        }
        return pkgs;
    }

    void SetCurrentProcessPackage(const std::string& fullName) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_currentProcessPackageFullName = fullName;
    }

    std::string GetCurrentProcessPackage() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_currentProcessPackageFullName;
    }
};

// ============================================================================
// 5. Process Lifetime Management (PLM) & Application State Engine
// ============================================================================

struct PlmExtendedExecutionToken {
    uint32_t tokenId{ 0 };
    PlmExtendedExecutionReason reason{ PlmExtendedExecutionReason::Unspecified };
    std::chrono::system_clock::time_point grantedTime;
    std::chrono::seconds duration{ 10 };
    bool isRevoked{ false };
};

struct PlmSession {
    uint32_t processId{ 0 };
    std::string aumid;
    std::string packageFullName;
    PlmApplicationState state{ PlmApplicationState::NotRunning };
    std::chrono::system_clock::time_point lastStateChange;
    std::vector<PlmExtendedExecutionToken> activeTokens;
    uint32_t memoryPressureLevel{ 0 }; // 0 = Normal, 1 = Low, 2 = Medium, 3 = Critical
    std::vector<std::string> stateHistory;
};

class PlmManager {
private:
    std::mutex m_mutex;
    std::unordered_map<uint32_t, PlmSession> m_sessions;
    std::atomic<uint32_t> m_nextTokenId{ 1 };

    PlmManager() = default;

public:
    static PlmManager& get() {
        static PlmManager instance;
        return instance;
    }

    bool RegisterProcess(uint32_t pid, const std::string& aumid, const std::string& pkgFullName) {
        std::lock_guard<std::mutex> lock(m_mutex);
        PlmSession session;
        session.processId = pid;
        session.aumid = aumid;
        session.packageFullName = pkgFullName;
        session.state = PlmApplicationState::Running;
        session.lastStateChange = std::chrono::system_clock::now();
        session.stateHistory.push_back("Running");
        m_sessions[pid] = session;
        return true;
    }

    bool SuspendProcess(uint32_t pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(pid);
        if (it == m_sessions.end()) return false;

        // Transition: Running -> Suspending -> Suspended
        it->second.state = PlmApplicationState::Suspending;
        it->second.stateHistory.push_back("Suspending");

        // Simulate save state / event dispatch
        it->second.state = PlmApplicationState::Suspended;
        it->second.stateHistory.push_back("Suspended");
        it->second.lastStateChange = std::chrono::system_clock::now();
        return true;
    }

    bool ResumeProcess(uint32_t pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(pid);
        if (it == m_sessions.end()) return false;
        if (it->second.state != PlmApplicationState::Suspended) return false;

        // Transition: Suspended -> Resuming -> Running
        it->second.state = PlmApplicationState::Resuming;
        it->second.stateHistory.push_back("Resuming");

        it->second.state = PlmApplicationState::Running;
        it->second.stateHistory.push_back("Running");
        it->second.lastStateChange = std::chrono::system_clock::now();
        return true;
    }

    bool TerminateProcess(uint32_t pid, const std::string& reason = "MemoryPressure") {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(pid);
        if (it == m_sessions.end()) return false;

        it->second.state = PlmApplicationState::Terminated;
        it->second.stateHistory.push_back("Terminated (" + reason + ")");
        it->second.lastStateChange = std::chrono::system_clock::now();
        return true;
    }

    uint32_t RequestExtendedExecution(uint32_t pid, PlmExtendedExecutionReason reason, uint32_t durationSec = 10) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(pid);
        if (it == m_sessions.end()) return 0;

        uint32_t tid = m_nextTokenId++;
        PlmExtendedExecutionToken token;
        token.tokenId = tid;
        token.reason = reason;
        token.grantedTime = std::chrono::system_clock::now();
        token.duration = std::chrono::seconds(durationSec);
        token.isRevoked = false;

        it->second.activeTokens.push_back(token);
        return tid;
    }

    bool RevokeExtendedExecution(uint32_t pid, uint32_t tokenId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(pid);
        if (it == m_sessions.end()) return false;

        for (auto& token : it->second.activeTokens) {
            if (token.tokenId == tokenId && !token.isRevoked) {
                token.isRevoked = true;
                return true;
            }
        }
        return false;
    }

    PlmApplicationState GetProcessState(uint32_t pid) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(pid);
        if (it == m_sessions.end()) return PlmApplicationState::NotRunning;
        return it->second.state;
    }

    bool GetSessionInfo(uint32_t pid, PlmSession& outSession) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(pid);
        if (it == m_sessions.end()) return false;
        outSession = it->second;
        return true;
    }

    std::vector<PlmSession> GetAllSessions() {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<PlmSession> list;
        list.reserve(m_sessions.size());
        for (const auto& [_, s] : m_sessions) {
            list.push_back(s);
        }
        return list;
    }
};

// ============================================================================
// 6. Win32 AppModel API Exports (kernelbase.dll / kernel32.dll)
// ============================================================================

inline LONG GetCurrentPackageFullName(uint32_t* packageFullNameLength, wchar_t* packageFullName) {
    if (!packageFullNameLength) return ERROR_INVALID_PARAMETER_VAL;
    std::string fullNameUtf8 = AppModelCatalog::get().GetCurrentProcessPackage();
    if (fullNameUtf8.empty()) return APPMODEL_ERROR_NO_PACKAGE_VAL;

    std::wstring fullNameWide = Utf8ToWide(fullNameUtf8);
    uint32_t neededLength = static_cast<uint32_t>(fullNameWide.length() + 1);

    if (!packageFullName || *packageFullNameLength < neededLength) {
        *packageFullNameLength = neededLength;
        return ERROR_INSUFFICIENT_BUFFER_VAL;
    }

    std::memcpy(packageFullName, fullNameWide.c_str(), neededLength * sizeof(wchar_t));
    *packageFullNameLength = neededLength;
    return ERROR_SUCCESS_VAL;
}

inline LONG GetCurrentPackageFamilyName(uint32_t* packageFamilyNameLength, wchar_t* packageFamilyName) {
    if (!packageFamilyNameLength) return ERROR_INVALID_PARAMETER_VAL;
    std::string fullNameUtf8 = AppModelCatalog::get().GetCurrentProcessPackage();
    if (fullNameUtf8.empty()) return APPMODEL_ERROR_NO_PACKAGE_VAL;

    InstalledPackage pkg;
    if (!AppModelCatalog::get().FindPackageByFullName(fullNameUtf8, pkg)) {
        return APPMODEL_ERROR_NO_PACKAGE_VAL;
    }

    std::wstring famWide = Utf8ToWide(pkg.packageFamilyName);
    uint32_t neededLength = static_cast<uint32_t>(famWide.length() + 1);

    if (!packageFamilyName || *packageFamilyNameLength < neededLength) {
        *packageFamilyNameLength = neededLength;
        return ERROR_INSUFFICIENT_BUFFER_VAL;
    }

    std::memcpy(packageFamilyName, famWide.c_str(), neededLength * sizeof(wchar_t));
    *packageFamilyNameLength = neededLength;
    return ERROR_SUCCESS_VAL;
}

inline LONG GetCurrentPackagePath(uint32_t* pathLength, wchar_t* path) {
    if (!pathLength) return ERROR_INVALID_PARAMETER_VAL;
    std::string fullNameUtf8 = AppModelCatalog::get().GetCurrentProcessPackage();
    if (fullNameUtf8.empty()) return APPMODEL_ERROR_NO_PACKAGE_VAL;

    InstalledPackage pkg;
    if (!AppModelCatalog::get().FindPackageByFullName(fullNameUtf8, pkg)) {
        return APPMODEL_ERROR_NO_PACKAGE_VAL;
    }

    std::wstring pathWide = Utf8ToWide(pkg.installPath);
    uint32_t neededLength = static_cast<uint32_t>(pathWide.length() + 1);

    if (!path || *pathLength < neededLength) {
        *pathLength = neededLength;
        return ERROR_INSUFFICIENT_BUFFER_VAL;
    }

    std::memcpy(path, pathWide.c_str(), neededLength * sizeof(wchar_t));
    *pathLength = neededLength;
    return ERROR_SUCCESS_VAL;
}

inline LONG GetPackagePathByFullName(const wchar_t* packageFullName, uint32_t* pathLength, wchar_t* path) {
    if (!packageFullName || !pathLength) return ERROR_INVALID_PARAMETER_VAL;
    std::string fullNameUtf8 = WideToUtf8(packageFullName);

    InstalledPackage pkg;
    if (!AppModelCatalog::get().FindPackageByFullName(fullNameUtf8, pkg)) {
        return ERROR_NOT_FOUND_VAL;
    }

    std::wstring pathWide = Utf8ToWide(pkg.installPath);
    uint32_t neededLength = static_cast<uint32_t>(pathWide.length() + 1);

    if (!path || *pathLength < neededLength) {
        *pathLength = neededLength;
        return ERROR_INSUFFICIENT_BUFFER_VAL;
    }

    std::memcpy(path, pathWide.c_str(), neededLength * sizeof(wchar_t));
    *pathLength = neededLength;
    return ERROR_SUCCESS_VAL;
}

inline LONG PackageFamilyNameFromFullName(const wchar_t* packageFullName, uint32_t* packageFamilyNameLength, wchar_t* packageFamilyName) {
    if (!packageFullName || !packageFamilyNameLength) return ERROR_INVALID_PARAMETER_VAL;
    std::string fn = WideToUtf8(packageFullName);

    // Full name format: Name_Version_Arch_ResourceId_PublisherId
    size_t firstUnderscore = fn.find('_');
    size_t lastUnderscore = fn.rfind('_');
    if (firstUnderscore == std::string::npos || lastUnderscore == std::string::npos || firstUnderscore >= lastUnderscore) {
        return ERROR_INVALID_PARAMETER_VAL;
    }

    std::string name = fn.substr(0, firstUnderscore);
    std::string pubId = fn.substr(lastUnderscore + 1);
    std::string fam = name + "_" + pubId;

    std::wstring famWide = Utf8ToWide(fam);
    uint32_t neededLength = static_cast<uint32_t>(famWide.length() + 1);

    if (!packageFamilyName || *packageFamilyNameLength < neededLength) {
        *packageFamilyNameLength = neededLength;
        return ERROR_INSUFFICIENT_BUFFER_VAL;
    }

    std::memcpy(packageFamilyName, famWide.c_str(), neededLength * sizeof(wchar_t));
    *packageFamilyNameLength = neededLength;
    return ERROR_SUCCESS_VAL;
}

inline LONG PackageNameAndPublisherIdFromFamilyName(
    const wchar_t* packageFamilyName,
    uint32_t* packageNameLength, wchar_t* packageName,
    uint32_t* publisherIdLength, wchar_t* publisherId)
{
    if (!packageFamilyName || !packageNameLength || !publisherIdLength) return ERROR_INVALID_PARAMETER_VAL;
    std::string fam = WideToUtf8(packageFamilyName);

    size_t underscore = fam.find('_');
    if (underscore == std::string::npos) return ERROR_INVALID_PARAMETER_VAL;

    std::string name = fam.substr(0, underscore);
    std::string pubId = fam.substr(underscore + 1);

    std::wstring nameWide = Utf8ToWide(name);
    std::wstring pubWide = Utf8ToWide(pubId);

    uint32_t needName = static_cast<uint32_t>(nameWide.length() + 1);
    uint32_t needPub = static_cast<uint32_t>(pubWide.length() + 1);

    if (!packageName || *packageNameLength < needName || !publisherId || *publisherIdLength < needPub) {
        *packageNameLength = needName;
        *publisherIdLength = needPub;
        return ERROR_INSUFFICIENT_BUFFER_VAL;
    }

    std::memcpy(packageName, nameWide.c_str(), needName * sizeof(wchar_t));
    *packageNameLength = needName;

    std::memcpy(publisherId, pubWide.c_str(), needPub * sizeof(wchar_t));
    *publisherIdLength = needPub;

    return ERROR_SUCCESS_VAL;
}

inline LONG CheckIsMSIXPackage(const wchar_t* packageFullName, BOOL* isMSIX) {
    if (!packageFullName || !isMSIX) return ERROR_INVALID_PARAMETER_VAL;
    std::string fullName = WideToUtf8(packageFullName);
    InstalledPackage pkg;
    if (AppModelCatalog::get().FindPackageByFullName(fullName, pkg)) {
        *isMSIX = pkg.isMSIX ? TRUE_VAL : FALSE_VAL;
        return ERROR_SUCCESS_VAL;
    }
    *isMSIX = FALSE_VAL;
    return ERROR_NOT_FOUND_VAL;
}

// AppPolicy APIs
inline LONG AppPolicyGetProcessTerminationMethod(HANDLE, AppPolicyProcessTerminationMethod* policy) {
    if (!policy) return ERROR_INVALID_PARAMETER_VAL;
    *policy = AppPolicyProcessTerminationMethod::TerminateProcess;
    return ERROR_SUCCESS_VAL;
}

inline LONG AppPolicyGetThreadInitializationType(HANDLE, AppPolicyThreadInitializationType* policy) {
    if (!policy) return ERROR_INVALID_PARAMETER_VAL;
    *policy = AppPolicyThreadInitializationType::InitializeWinRT;
    return ERROR_SUCCESS_VAL;
}

inline LONG AppPolicyGetShowDeveloperDiagnostic(HANDLE, AppPolicyShowDeveloperDiagnostic* policy) {
    if (!policy) return ERROR_INVALID_PARAMETER_VAL;
    *policy = AppPolicyShowDeveloperDiagnostic::ShowUI;
    return ERROR_SUCCESS_VAL;
}

inline LONG AppPolicyGetWindowingModel(HANDLE, AppPolicyWindowingModel* policy) {
    if (!policy) return ERROR_INVALID_PARAMETER_VAL;
    *policy = AppPolicyWindowingModel::Universal;
    return ERROR_SUCCESS_VAL;
}

// ============================================================================
// 7. PLM APIs (twinapi.appcore.dll)
// ============================================================================

inline LONG PlmGetApplicationState(uint32_t pid, PlmApplicationState* pState) {
    if (!pState) return ERROR_INVALID_PARAMETER_VAL;
    *pState = PlmManager::get().GetProcessState(pid);
    return ERROR_SUCCESS_VAL;
}

inline LONG PlmSuspendApplication(uint32_t pid) {
    return PlmManager::get().SuspendProcess(pid) ? ERROR_SUCCESS_VAL : ERROR_NOT_FOUND_VAL;
}

inline LONG PlmResumeApplication(uint32_t pid) {
    return PlmManager::get().ResumeProcess(pid) ? ERROR_SUCCESS_VAL : ERROR_NOT_FOUND_VAL;
}

inline LONG PlmTerminateApplication(uint32_t pid, const char* reason) {
    std::string r = (reason && *reason) ? reason : "OSResourceManagement";
    return PlmManager::get().TerminateProcess(pid, r) ? ERROR_SUCCESS_VAL : ERROR_NOT_FOUND_VAL;
}

inline LONG PlmRequestExtendedExecution(uint32_t pid, PlmExtendedExecutionReason reason, uint32_t durationSec, uint32_t* pTokenId) {
    if (!pTokenId) return ERROR_INVALID_PARAMETER_VAL;
    uint32_t tid = PlmManager::get().RequestExtendedExecution(pid, reason, durationSec);
    if (tid == 0) return ERROR_NOT_FOUND_VAL;
    *pTokenId = tid;
    return ERROR_SUCCESS_VAL;
}

inline LONG PlmRevokeExtendedExecution(uint32_t pid, uint32_t tokenId) {
    return PlmManager::get().RevokeExtendedExecution(pid, tokenId) ? ERROR_SUCCESS_VAL : ERROR_NOT_FOUND_VAL;
}

// ============================================================================
// 8. Package Deployment Client APIs (appxdeploymentclient.dll)
// ============================================================================

inline LONG AppxRegisterPackage(const char* xmlManifest, const char* installPath, char* outFullName, uint32_t maxLen) {
    if (!xmlManifest || !installPath) return ERROR_INVALID_PARAMETER_VAL;
    std::string fn;
    if (!AppModelCatalog::get().RegisterPackageXml(xmlManifest, installPath, fn)) {
        return ERROR_INVALID_PARAMETER_VAL;
    }
    if (outFullName && maxLen > 0) {
        std::strncpy(outFullName, fn.c_str(), maxLen - 1);
        outFullName[maxLen - 1] = '\0';
    }
    return ERROR_SUCCESS_VAL;
}

inline LONG AppxUnregisterPackage(const char* packageFullName) {
    if (!packageFullName) return ERROR_INVALID_PARAMETER_VAL;
    return AppModelCatalog::get().UnregisterPackage(packageFullName) ? ERROR_SUCCESS_VAL : ERROR_NOT_FOUND_VAL;
}

// ============================================================================
// 9. Subsystem Dynamic Loader Registration
// ============================================================================

inline void InitializeAppModelExports() {
    auto& loader = micant::ldr::DynamicLoader::get();

    // kernelbase.dll exports
    loader.registerExport("kernelbase.dll", "GetCurrentPackageFullName", reinterpret_cast<void*>(GetCurrentPackageFullName));
    loader.registerExport("kernelbase.dll", "GetCurrentPackageFamilyName", reinterpret_cast<void*>(GetCurrentPackageFamilyName));
    loader.registerExport("kernelbase.dll", "GetCurrentPackagePath", reinterpret_cast<void*>(GetCurrentPackagePath));
    loader.registerExport("kernelbase.dll", "GetPackagePathByFullName", reinterpret_cast<void*>(GetPackagePathByFullName));
    loader.registerExport("kernelbase.dll", "PackageFamilyNameFromFullName", reinterpret_cast<void*>(PackageFamilyNameFromFullName));
    loader.registerExport("kernelbase.dll", "PackageNameAndPublisherIdFromFamilyName", reinterpret_cast<void*>(PackageNameAndPublisherIdFromFamilyName));
    loader.registerExport("kernelbase.dll", "CheckIsMSIXPackage", reinterpret_cast<void*>(CheckIsMSIXPackage));
    loader.registerExport("kernelbase.dll", "AppPolicyGetProcessTerminationMethod", reinterpret_cast<void*>(AppPolicyGetProcessTerminationMethod));
    loader.registerExport("kernelbase.dll", "AppPolicyGetThreadInitializationType", reinterpret_cast<void*>(AppPolicyGetThreadInitializationType));
    loader.registerExport("kernelbase.dll", "AppPolicyGetShowDeveloperDiagnostic", reinterpret_cast<void*>(AppPolicyGetShowDeveloperDiagnostic));
    loader.registerExport("kernelbase.dll", "AppPolicyGetWindowingModel", reinterpret_cast<void*>(AppPolicyGetWindowingModel));

    // Also mirror in kernel32.dll for legacy compatibility
    loader.registerExport("kernel32.dll", "GetCurrentPackageFullName", reinterpret_cast<void*>(GetCurrentPackageFullName));
    loader.registerExport("kernel32.dll", "GetCurrentPackageFamilyName", reinterpret_cast<void*>(GetCurrentPackageFamilyName));
    loader.registerExport("kernel32.dll", "GetCurrentPackagePath", reinterpret_cast<void*>(GetCurrentPackagePath));
    loader.registerExport("kernel32.dll", "GetPackagePathByFullName", reinterpret_cast<void*>(GetPackagePathByFullName));
    loader.registerExport("kernel32.dll", "PackageFamilyNameFromFullName", reinterpret_cast<void*>(PackageFamilyNameFromFullName));
    loader.registerExport("kernel32.dll", "PackageNameAndPublisherIdFromFamilyName", reinterpret_cast<void*>(PackageNameAndPublisherIdFromFamilyName));
    loader.registerExport("kernel32.dll", "CheckIsMSIXPackage", reinterpret_cast<void*>(CheckIsMSIXPackage));

    // twinapi.appcore.dll exports
    loader.registerExport("twinapi.appcore.dll", "PlmGetApplicationState", reinterpret_cast<void*>(PlmGetApplicationState));
    loader.registerExport("twinapi.appcore.dll", "PlmSuspendApplication", reinterpret_cast<void*>(PlmSuspendApplication));
    loader.registerExport("twinapi.appcore.dll", "PlmResumeApplication", reinterpret_cast<void*>(PlmResumeApplication));
    loader.registerExport("twinapi.appcore.dll", "PlmTerminateApplication", reinterpret_cast<void*>(PlmTerminateApplication));
    loader.registerExport("twinapi.appcore.dll", "PlmRequestExtendedExecution", reinterpret_cast<void*>(PlmRequestExtendedExecution));
    loader.registerExport("twinapi.appcore.dll", "PlmRevokeExtendedExecution", reinterpret_cast<void*>(PlmRevokeExtendedExecution));

    // appxdeploymentclient.dll exports
    loader.registerExport("appxdeploymentclient.dll", "AppxRegisterPackage", reinterpret_cast<void*>(AppxRegisterPackage));
    loader.registerExport("appxdeploymentclient.dll", "AppxUnregisterPackage", reinterpret_cast<void*>(AppxUnregisterPackage));

    version::VersionDatabase::Instance().RegisterModule(
        "kernelbase.dll",
        "10.0.22621.1",
        "Windows Base API Client Subsystem & AppModel",
        "MicaNT Sovereign Project"
    );

    version::VersionDatabase::Instance().RegisterModule(
        "twinapi.appcore.dll",
        "10.0.22621.1",
        "Windows Modern Application Lifecycle & PLM Core Architecture",
        "MicaNT Sovereign Project"
    );

    version::VersionDatabase::Instance().RegisterModule(
        "appxdeploymentclient.dll",
        "10.0.22621.1",
        "AppX / MSIX Deployment & Manifest Staging Engine",
        "MicaNT Sovereign Project"
    );
}

} // namespace micant::appmodel
