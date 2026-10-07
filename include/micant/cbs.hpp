#pragma once

/**
 * @file cbs.hpp
 * @brief MicaNT Component-Based Servicing (CBS) & Deployment Image Servicing and Management (DISM) Subsystem.
 *
 * Implements clean-room Windows DISM and CBS architectures referencing Microsoft win32metadata:
 * - DISM API Surface (dismapi.dll):
 *     DismInitialize, DismShutdown, DismOpenSession, DismCloseSession, DismDelete,
 *     DismGetPackages, DismGetPackageInfo, DismAddPackage, DismRemovePackage,
 *     DismGetFeatures, DismGetFeatureInfo, DismEnableFeature, DismDisableFeature,
 *     DismGetCapabilities, DismGetCapabilityInfo, DismAddCapability, DismRemoveCapability,
 *     DismCheckImageHealth, DismScanImageHealth, DismRestoreImageHealth.
 * - CBS Engine & Component Store (cbsapi.dll):
 *     WinSxS manifest verification, component payload state machine, pending reboot transactions.
 * - TrustedInstaller Service Integration (SCM):
 *     Windows Modules Installer daemon registration.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <map>
#include <algorithm>
#include <chrono>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ldr.hpp"
#include "scm.hpp"
#include "fs.hpp"

namespace micant::cbs {

// ============================================================================
// 1. DISM Constants, Enumerations & Types
// ============================================================================

using DismSession = uint32_t;
inline constexpr DismSession DISM_SESSION_DEFAULT = 0;
inline constexpr DismSession DISM_SESSION_INVALID = 0xFFFFFFFF;

inline const wchar_t* const DISM_ONLINE_IMAGE = L"DISM_{53BFAE52-B167-4E2F-A7AB-60C129381BEA}";

// DISM HRESULT Error Codes
inline constexpr int32_t DISMAPI_S_OK                          = 0;
inline constexpr int32_t DISMAPI_E_INVALIDARG                  = static_cast<int32_t>(0x80070057);
inline constexpr int32_t DISMAPI_E_DISMAPI_NOT_INITIALIZED     = static_cast<int32_t>(0xC0040001);
inline constexpr int32_t DISMAPI_E_IMAGE_NOT_LOADED            = static_cast<int32_t>(0xC0040002);
inline constexpr int32_t DISMAPI_E_OPEN_HANDLES_UNCLOSED       = static_cast<int32_t>(0xC0040003);
inline constexpr int32_t DISMAPI_E_BUSY                        = static_cast<int32_t>(0xC0040004);
inline constexpr int32_t DISMAPI_E_IMAGE_DIR_INVALID           = static_cast<int32_t>(0xC0040005);
inline constexpr int32_t DISMAPI_E_SESSION_NOT_FOUND           = static_cast<int32_t>(0xC0040006);
inline constexpr int32_t DISMAPI_E_PACKAGE_NOT_FOUND           = static_cast<int32_t>(0x80070002);
inline constexpr int32_t DISMAPI_E_FEATURE_NOT_FOUND           = static_cast<int32_t>(0x80070002);
inline constexpr int32_t DISMAPI_E_NOT_SUPPORTED               = static_cast<int32_t>(0x80004001);
inline constexpr int32_t DISMAPI_S_REBOOT_REQUIRED             = static_cast<int32_t>(0x00003010); // ERROR_SUCCESS_REBOOT_REQUIRED

enum DismPackageFeatureState {
    DismStateNotPresent = 0,
    DismStateUninstallPending = 1,
    DismStateStaged = 2,
    DismStateResolved = 3,
    DismStateInstalled = 4,
    DismStateInstallPending = 5,
    DismStateSuperseded = 6,
    DismStatePartiallyInstalled = 7
};

enum DismPackageIdentifier {
    DismPackageNone = 0,
    DismPackageName = 1,
    DismPackagePath = 2
};

enum DismReleaseType {
    DismReleaseTypeCriticalUpdate = 0,
    DismReleaseTypeDriver = 1,
    DismReleaseTypeFeaturePack = 2,
    DismReleaseTypeLanguagePack = 3,
    DismReleaseTypeSecurityUpdate = 4,
    DismReleaseTypeServicePack = 5,
    DismReleaseTypeUpdate = 6,
    DismReleaseTypeFoundation = 7,
    DismReleaseTypeUnspecified = 8
};

enum DismRestartType {
    DismRestartNo = 0,
    DismRestartPossible = 1,
    DismRestartRequired = 2
};

enum DismImageHealthState {
    DismImageHealthy = 0,
    DismImageRepairable = 1,
    DismImageNonRepairable = 2
};

enum DismLogLevel {
    DismLogErrors = 0,
    DismLogErrorsWarnings = 1,
    DismLogErrorsWarningsInfo = 2
};

enum DismImageType {
    DismImageTypeUnsupported = -1,
    DismImageTypeWim = 0,
    DismImageTypeVhd = 1
};

using DISM_PROGRESS_CALLBACK = void (__stdcall *)(uint32_t Current, uint32_t Total, void* UserData);

// ============================================================================
// 2. DISM Public C Structures
// ============================================================================

struct DismCustomProperty {
    const wchar_t* Name;
    const wchar_t* Value;
    const wchar_t* Path;
};

struct DismFeature {
    const wchar_t* FeatureName;
    DismPackageFeatureState State;
};

struct DismFeatureInfo {
    const wchar_t* FeatureName;
    DismPackageFeatureState FeatureState;
    const wchar_t* DisplayName;
    const wchar_t* Description;
    DismRestartType RestartRequired;
    DismCustomProperty* CustomProperty;
    uint32_t CustomPropertyCount;
};

struct DismPackage {
    const wchar_t* PackageName;
    DismPackageFeatureState PackageState;
    DismReleaseType ReleaseType;
    win32::SYSTEMTIME InstallTime;
};

struct DismPackageInfo {
    const wchar_t* PackageName;
    DismPackageFeatureState PackageState;
    DismReleaseType ReleaseType;
    win32::SYSTEMTIME InstallTime;
    int32_t Applicable;
    const wchar_t* Copyright;
    const wchar_t* Company;
    win32::SYSTEMTIME CreationTime;
    const wchar_t* DisplayName;
    const wchar_t* Description;
    const wchar_t* InstallClient;
    const wchar_t* InstallPackageName;
    win32::SYSTEMTIME LastUpdateTime;
    DismRestartType RestartRequired;
    DismCustomProperty* CustomProperty;
    uint32_t CustomPropertyCount;
    DismFeature* Feature;
    uint32_t FeatureCount;
};

struct DismCapability {
    const wchar_t* Name;
    DismPackageFeatureState State;
};

struct DismCapabilityInfo {
    const wchar_t* Name;
    DismPackageFeatureState State;
    const wchar_t* DisplayName;
    const wchar_t* Description;
    uint32_t DownloadSize;
    uint32_t InstallSize;
};

struct DismString {
    const wchar_t* Value;
};

// ============================================================================
// 3. Memory Allocation Tracker for DismDelete()
// ============================================================================

class DismMemoryTracker {
private:
    std::mutex m_mutex;
    std::unordered_map<void*, std::vector<void*>> m_allocations;

public:
    static DismMemoryTracker& get() {
        static DismMemoryTracker s_instance;
        return s_instance;
    }

    void* allocateRoot(size_t size) {
        void* p = ::operator new(size, std::nothrow);
        if (!p) return nullptr;
        std::memset(p, 0, size);
        std::lock_guard<std::mutex> lock(m_mutex);
        m_allocations[p] = {};
        return p;
    }

    void trackChild(void* root, void* child) {
        if (!root || !child) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_allocations.find(root);
        if (it != m_allocations.end()) {
            it->second.push_back(child);
        }
    }

    const wchar_t* allocString(void* root, std::wstring_view sv) {
        if (!root) return nullptr;
        size_t len = sv.size();
        wchar_t* buf = new (std::nothrow) wchar_t[len + 1];
        if (!buf) return nullptr;
        std::memcpy(buf, sv.data(), len * sizeof(wchar_t));
        buf[len] = L'\0';
        trackChild(root, buf);
        return buf;
    }

    int32_t freeAllocation(void* root) {
        if (!root) return DISMAPI_S_OK;
        std::vector<void*> toFree;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_allocations.find(root);
            if (it == m_allocations.end()) {
                // Not a managed pointer or already freed
                return DISMAPI_E_INVALIDARG;
            }
            toFree = std::move(it->second);
            m_allocations.erase(it);
        }
        for (void* child : toFree) {
            delete[] reinterpret_cast<uint8_t*>(child);
        }
        ::operator delete(root);
        return DISMAPI_S_OK;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& [root, children] : m_allocations) {
            for (void* child : children) {
                delete[] reinterpret_cast<uint8_t*>(child);
            }
            ::operator delete(root);
        }
        m_allocations.clear();
    }
};

// ============================================================================
// 4. CBS Internal Records & Component Store
// ============================================================================

struct InternalPackage {
    std::wstring packageName;
    DismPackageFeatureState state{DismStateInstalled};
    DismReleaseType releaseType{DismReleaseTypeUpdate};
    win32::SYSTEMTIME installTime{};
    std::wstring displayName;
    std::wstring description;
    std::wstring company{L"MicaNT Sovereign Foundation"};
    std::wstring copyright{L"Copyright (C) 2026 MicaNT. All rights reserved."};
    std::wstring installClient{L"DISM"};
    DismRestartType restartRequired{DismRestartNo};
    std::vector<std::pair<std::wstring, std::wstring>> customProps;
    std::vector<std::wstring> features;
};

struct InternalFeature {
    std::wstring featureName;
    DismPackageFeatureState state{DismStateInstalled};
    std::wstring displayName;
    std::wstring description;
    DismRestartType restartRequired{DismRestartNo};
    std::wstring parentPackage;
    std::vector<std::pair<std::wstring, std::wstring>> customProps;
    std::vector<std::wstring> dependencies;
};

struct InternalCapability {
    std::wstring name;
    DismPackageFeatureState state{DismStateInstalled};
    std::wstring displayName;
    std::wstring description;
    uint32_t downloadSize{0};
    uint32_t installSize{0};
};

class CbsComponentStore {
private:
    mutable std::mutex m_mutex;
    std::map<std::wstring, InternalPackage> m_packages;
    std::map<std::wstring, InternalFeature> m_features;
    std::map<std::wstring, InternalCapability> m_capabilities;
    DismImageHealthState m_healthState{DismImageHealthy};
    std::vector<std::wstring> m_pendingTransactions;
    bool m_rebootPending{false};

    CbsComponentStore() {
        seedComponentStore();
    }

    void seedComponentStore() {
        win32::SYSTEMTIME now{};
        now.wYear = 2026;
        now.wMonth = 10;
        now.wDay = 1;
        now.wHour = 12;
        now.wMinute = 0;
        now.wSecond = 0;

        // 1. Pre-seeded Windows Packages
        {
            InternalPackage p{};
            p.packageName = L"Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1.1.0";
            p.displayName = L"2026-10 Cumulative Update for MicaNT 24H2 for x64-based Systems (KB5044284)";
            p.description = L"Fixes security vulnerabilities and hardens kernel executive subsystems.";
            p.releaseType = DismReleaseTypeUpdate;
            p.state = DismStateInstalled;
            p.installTime = now;
            p.features = { L"Microsoft-Windows-Subsystem-Linux", L"Containers" };
            p.customProps.push_back({ L"KBArticle", L"5044284" });
            p.customProps.push_back({ L"SupportInformation", L"https://micant.org/kb/5044284" });
            m_packages[p.packageName] = p;
        }
        {
            InternalPackage p{};
            p.packageName = L"Package_for_DotNetFramework~31bf3856ad364e35~amd64~~4.8.9032.0";
            p.displayName = L"Microsoft .NET Framework 4.8.1 Servicing Package";
            p.description = L"Provides managed runtime engine and core BCL assemblies.";
            p.releaseType = DismReleaseTypeFeaturePack;
            p.state = DismStateInstalled;
            p.installTime = now;
            p.features = { L"NetFx3" };
            p.customProps.push_back({ L"FrameworkVersion", L"4.8.1" });
            m_packages[p.packageName] = p;
        }
        {
            InternalPackage p{};
            p.packageName = L"Package_for_ServicingStack~31bf3856ad364e35~amd64~~26100.1000.1.0";
            p.displayName = L"Servicing Stack Update 26100.1000";
            p.description = L"Provides reliability fixes to the Windows Component-Based Servicing stack.";
            p.releaseType = DismReleaseTypeServicePack;
            p.state = DismStateInstalled;
            p.installTime = now;
            p.customProps.push_back({ L"SSUVersion", L"26100.1000" });
            m_packages[p.packageName] = p;
        }

        // 2. Pre-seeded Windows Features
        {
            InternalFeature f{};
            f.featureName = L"NetFx3";
            f.displayName = L".NET Framework 3.5 (includes .NET 2.0 and 3.0)";
            f.description = L"Runs legacy managed applications requiring .NET 2.0-3.5 runtime engines.";
            f.state = DismStateInstalled;
            f.parentPackage = L"Package_for_DotNetFramework~31bf3856ad364e35~amd64~~4.8.9032.0";
            m_features[f.featureName] = f;
        }
        {
            InternalFeature f{};
            f.featureName = L"Microsoft-Windows-Subsystem-Linux";
            f.displayName = L"Windows Subsystem for Linux";
            f.description = L"Provides services and environments for running native ELF Linux 64-bit binaries.";
            f.state = DismStateInstalled;
            f.parentPackage = L"Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1.1.0";
            m_features[f.featureName] = f;
        }
        {
            InternalFeature f{};
            f.featureName = L"Containers";
            f.displayName = L"Containers Subsystem";
            f.description = L"Provides services and tools for creating and managing Windows Server and kernel containers.";
            f.state = DismStateStaged;
            f.parentPackage = L"Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1.1.0";
            m_features[f.featureName] = f;
        }
        {
            InternalFeature f{};
            f.featureName = L"Hyper-V-All";
            f.displayName = L"Hyper-V Platform and Management Tools";
            f.description = L"Provides hypervisor virtualization infrastructure and management console.";
            f.state = DismStateStaged;
            m_features[f.featureName] = f;
        }
        {
            InternalFeature f{};
            f.featureName = L"IIS-WebServerRole";
            f.displayName = L"Internet Information Services";
            f.description = L"Provides secure, manageable Web and FTP server capabilities.";
            f.state = DismStateStaged;
            m_features[f.featureName] = f;
        }
        {
            InternalFeature f{};
            f.featureName = L"TelnetClient";
            f.displayName = L"Telnet Client";
            f.description = L"Connects to remote computers using the legacy Telnet protocol.";
            f.state = DismStateNotPresent;
            m_features[f.featureName] = f;
        }
        {
            InternalFeature f{};
            f.featureName = L"TFTP";
            f.displayName = L"TFTP Client";
            f.description = L"Transfers files using Trivial File Transfer Protocol.";
            f.state = DismStateNotPresent;
            m_features[f.featureName] = f;
        }
        {
            InternalFeature f{};
            f.featureName = L"SMB1Protocol";
            f.displayName = L"SMB 1.0/CIFS File Sharing Support";
            f.description = L"Provides legacy support for the SMBv1 networking protocol.";
            f.state = DismStateNotPresent;
            m_features[f.featureName] = f;
        }

        // 3. Pre-seeded Capabilities
        {
            InternalCapability c{};
            c.name = L"OpenSSH.Client~~~~0.0.1.0";
            c.displayName = L"OpenSSH Client";
            c.description = L"Secure Shell (SSH) based key-management and authentication tool.";
            c.state = DismStateInstalled;
            c.downloadSize = 1320000;
            c.installSize = 4850000;
            m_capabilities[c.name] = c;
        }
        {
            InternalCapability c{};
            c.name = L"OpenSSH.Server~~~~0.0.1.0";
            c.displayName = L"OpenSSH Server";
            c.description = L"Secure Shell (SSH) daemon for remote host administration.";
            c.state = DismStateNotPresent;
            c.downloadSize = 1950000;
            c.installSize = 6500000;
            m_capabilities[c.name] = c;
        }
        {
            InternalCapability c{};
            c.name = L"Language.Basic~~~en-US~0.0.1.0";
            c.displayName = L"English (US) Text-to-Speech and Language Pack";
            c.description = L"Core spelling, hyphenation, and vocabulary dictionaries for en-US.";
            c.state = DismStateInstalled;
            c.downloadSize = 42000000;
            c.installSize = 85000000;
            m_capabilities[c.name] = c;
        }
        {
            InternalCapability c{};
            c.name = L"Tools.Graphics.DirectX~~~~0.0.1.0";
            c.displayName = L"Graphics Tools (Direct3D SDK Diagnostic Layer)";
            c.description = L"Enables DirectX Graphics Diagnostic tools, D3D11/12 debug layers, and shader analyzers.";
            c.state = DismStateInstalled;
            c.downloadSize = 18000000;
            c.installSize = 54000000;
            m_capabilities[c.name] = c;
        }
    }

public:
    static CbsComponentStore& get() {
        static CbsComponentStore s_instance;
        return s_instance;
    }

    // Packages
    std::vector<InternalPackage> getPackages() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<InternalPackage> result;
        for (const auto& [name, pkg] : m_packages) {
            result.push_back(pkg);
        }
        return result;
    }

    bool getPackage(const std::wstring& name, InternalPackage& outPkg) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_packages.find(name);
        if (it != m_packages.end()) {
            outPkg = it->second;
            return true;
        }
        // Substring / prefix search
        for (const auto& [pkgName, pkg] : m_packages) {
            if (pkgName.find(name) != std::wstring::npos) {
                outPkg = pkg;
                return true;
            }
        }
        return false;
    }

    bool addPackage(const std::wstring& packagePath, bool preventPending, std::wstring& outPkgName) {
        std::lock_guard<std::mutex> lock(m_mutex);
        // Synthesize package name from file path if necessary
        std::wstring name = packagePath;
        size_t slash = name.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            name = name.substr(slash + 1);
        }
        if (name.ends_with(L".cab") || name.ends_with(L".msu")) {
            name = name.substr(0, name.size() - 4);
        }
        if (name.empty()) {
            name = L"Package_for_Hotfix~31bf3856ad364e35~amd64~~26100.2.1.0";
        }

        win32::SYSTEMTIME now{};
        now.wYear = 2026; now.wMonth = 10; now.wDay = 3;
        now.wHour = 16; now.wMinute = 30; now.wSecond = 0;

        InternalPackage p{};
        p.packageName = name;
        p.displayName = L"Servicing Package " + name;
        p.description = L"Dynamic Hotfix Package applied via DISM Servicing API.";
        p.releaseType = DismReleaseTypeUpdate;
        p.state = preventPending ? DismStateInstalled : DismStateInstallPending;
        p.installTime = now;
        p.restartRequired = preventPending ? DismRestartNo : DismRestartRequired;
        if (!preventPending) {
            m_rebootPending = true;
            m_pendingTransactions.push_back(L"Install Package " + name);
        }

        m_packages[name] = p;
        outPkgName = name;
        return true;
    }

    bool removePackage(const std::wstring& identifier, bool& outRebootRequired) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& [pkgName, pkg] : m_packages) {
            if (pkgName == identifier || pkgName.find(identifier) != std::wstring::npos) {
                pkg.state = DismStateUninstallPending;
                pkg.restartRequired = DismRestartRequired;
                m_rebootPending = true;
                outRebootRequired = true;
                m_pendingTransactions.push_back(L"Uninstall Package " + pkgName);
                return true;
            }
        }
        return false;
    }

    // Features
    std::vector<InternalFeature> getFeatures() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<InternalFeature> result;
        for (const auto& [name, feat] : m_features) {
            result.push_back(feat);
        }
        return result;
    }

    bool getFeature(const std::wstring& name, InternalFeature& outFeat) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_features.find(name);
        if (it != m_features.end()) {
            outFeat = it->second;
            return true;
        }
        for (const auto& [featName, feat] : m_features) {
            if (featName.find(name) != std::wstring::npos) {
                outFeat = feat;
                return true;
            }
        }
        return false;
    }

    bool enableFeature(const std::wstring& featureName, bool enableDependencies, bool& outRebootRequired) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_features.find(featureName);
        if (it == m_features.end()) return false;

        it->second.state = DismStateInstalled;
        if (enableDependencies) {
            for (const auto& dep : it->second.dependencies) {
                auto dit = m_features.find(dep);
                if (dit != m_features.end()) {
                    dit->second.state = DismStateInstalled;
                }
            }
        }
        outRebootRequired = (it->second.restartRequired == DismRestartRequired);
        return true;
    }

    bool disableFeature(const std::wstring& featureName, bool removePayload, bool& outRebootRequired) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_features.find(featureName);
        if (it == m_features.end()) return false;

        it->second.state = removePayload ? DismStateNotPresent : DismStateStaged;
        outRebootRequired = (it->second.restartRequired == DismRestartRequired);
        return true;
    }

    // Capabilities
    std::vector<InternalCapability> getCapabilities() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<InternalCapability> result;
        for (const auto& [name, cap] : m_capabilities) {
            result.push_back(cap);
        }
        return result;
    }

    bool getCapability(const std::wstring& name, InternalCapability& outCap) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_capabilities.find(name);
        if (it != m_capabilities.end()) {
            outCap = it->second;
            return true;
        }
        for (const auto& [capName, cap] : m_capabilities) {
            if (capName.find(name) != std::wstring::npos) {
                outCap = cap;
                return true;
            }
        }
        return false;
    }

    bool addCapability(const std::wstring& name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_capabilities.find(name);
        if (it != m_capabilities.end()) {
            it->second.state = DismStateInstalled;
            return true;
        }
        InternalCapability c{};
        c.name = name;
        c.displayName = name;
        c.description = L"On-Demand Capability added via DISM";
        c.state = DismStateInstalled;
        c.downloadSize = 5000000;
        c.installSize = 15000000;
        m_capabilities[name] = c;
        return true;
    }

    bool removeCapability(const std::wstring& name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_capabilities.find(name);
        if (it != m_capabilities.end()) {
            it->second.state = DismStateNotPresent;
            return true;
        }
        return false;
    }

    // Health
    DismImageHealthState getHealthState() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_healthState;
    }

    void setHealthState(DismImageHealthState state) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_healthState = state;
    }

    bool restoreHealth() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_healthState = DismImageHealthy;
        return true;
    }

    bool isRebootPending() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_rebootPending;
    }

    const std::vector<std::wstring>& getPendingTransactions() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pendingTransactions;
    }
};

// ============================================================================
// 5. DISM Servicing Session Manager
// ============================================================================

struct SessionRecord {
    DismSession id;
    std::wstring imagePath;
    std::wstring windowsDir;
    std::wstring systemDrive;
    bool isOnline{false};
};

class DismSessionManager {
private:
    std::mutex m_mutex;
    bool m_initialized{false};
    DismLogLevel m_logLevel{DismLogErrorsWarningsInfo};
    std::wstring m_logFilePath;
    std::wstring m_scratchDir;
    DismSession m_nextSessionId{1};
    std::unordered_map<DismSession, SessionRecord> m_sessions;

    DismSessionManager() = default;

public:
    static DismSessionManager& get() {
        static DismSessionManager s_instance;
        return s_instance;
    }

    int32_t initialize(DismLogLevel level, const wchar_t* logFile, const wchar_t* scratchDir) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_logLevel = level;
        m_logFilePath = logFile ? logFile : L"\\Windows\\Logs\\DISM\\dism.log";
        m_scratchDir = scratchDir ? scratchDir : L"\\Windows\\Temp";
        m_initialized = true;
        return DISMAPI_S_OK;
    }

    int32_t shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return DISMAPI_E_DISMAPI_NOT_INITIALIZED;
        m_sessions.clear();
        m_initialized = false;
        DismMemoryTracker::get().reset();
        return DISMAPI_S_OK;
    }

    bool isInitialized() const {
        return m_initialized;
    }

    int32_t openSession(const wchar_t* imagePath, const wchar_t* winDir, const wchar_t* sysDrive, DismSession* outSession) {
        if (!outSession) return DISMAPI_E_INVALIDARG;
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return DISMAPI_E_DISMAPI_NOT_INITIALIZED;

        bool online = false;
        if (!imagePath || std::wcscmp(imagePath, DISM_ONLINE_IMAGE) == 0) {
            online = true;
        }

        SessionRecord rec{};
        rec.id = m_nextSessionId++;
        rec.imagePath = imagePath ? imagePath : DISM_ONLINE_IMAGE;
        rec.windowsDir = winDir ? winDir : L"C:\\Windows";
        rec.systemDrive = sysDrive ? sysDrive : L"C:";
        rec.isOnline = online;

        m_sessions[rec.id] = rec;
        *outSession = rec.id;
        return DISMAPI_S_OK;
    }

    int32_t closeSession(DismSession session) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return DISMAPI_E_DISMAPI_NOT_INITIALIZED;
        auto it = m_sessions.find(session);
        if (it == m_sessions.end()) return DISMAPI_E_SESSION_NOT_FOUND;
        m_sessions.erase(it);
        return DISMAPI_S_OK;
    }

    bool findSession(DismSession session, SessionRecord& outRec) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized) return false;
        auto it = m_sessions.find(session);
        if (it == m_sessions.end()) return false;
        outRec = it->second;
        return true;
    }
};

// ============================================================================
// 6. DISM Standard Win32 API Implementation (dismapi.dll)
// ============================================================================

inline int32_t __stdcall DismInitialize(DismLogLevel LogLevel, const wchar_t* LogFilePath, const wchar_t* ScratchDirectory) {
    return DismSessionManager::get().initialize(LogLevel, LogFilePath, ScratchDirectory);
}

inline int32_t __stdcall DismShutdown() {
    return DismSessionManager::get().shutdown();
}

inline int32_t __stdcall DismOpenSession(const wchar_t* ImagePath, const wchar_t* WindowsDirectory, const wchar_t* SystemDrive, DismSession* Session) {
    return DismSessionManager::get().openSession(ImagePath, WindowsDirectory, SystemDrive, Session);
}

inline int32_t __stdcall DismCloseSession(DismSession Session) {
    return DismSessionManager::get().closeSession(Session);
}

inline int32_t __stdcall DismDelete(void* DismStructure) {
    return DismMemoryTracker::get().freeAllocation(DismStructure);
}

inline int32_t __stdcall DismGetPackages(DismSession Session, DismPackage** Package, uint32_t* Count) {
    if (!Package || !Count) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    auto internalPkgs = CbsComponentStore::get().getPackages();
    uint32_t count = static_cast<uint32_t>(internalPkgs.size());
    if (count == 0) {
        *Package = nullptr;
        *Count = 0;
        return DISMAPI_S_OK;
    }

    auto* arr = reinterpret_cast<DismPackage*>(DismMemoryTracker::get().allocateRoot(sizeof(DismPackage) * count));
    if (!arr) return static_cast<int32_t>(0x8007000E); // E_OUTOFMEMORY

    for (uint32_t i = 0; i < count; ++i) {
        arr[i].PackageName = DismMemoryTracker::get().allocString(arr, internalPkgs[i].packageName);
        arr[i].PackageState = internalPkgs[i].state;
        arr[i].ReleaseType = internalPkgs[i].releaseType;
        arr[i].InstallTime = internalPkgs[i].installTime;
    }

    *Package = arr;
    *Count = count;
    return DISMAPI_S_OK;
}

inline int32_t __stdcall DismGetPackageInfo(DismSession Session, const wchar_t* Identifier, DismPackageIdentifier PackageIdentifier, DismPackageInfo** PackageInfo) {
    if (!Identifier || !PackageInfo) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    InternalPackage pkg{};
    if (!CbsComponentStore::get().getPackage(Identifier, pkg)) {
        return DISMAPI_E_PACKAGE_NOT_FOUND;
    }

    auto* info = reinterpret_cast<DismPackageInfo*>(DismMemoryTracker::get().allocateRoot(sizeof(DismPackageInfo)));
    if (!info) return static_cast<int32_t>(0x8007000E);

    info->PackageName = DismMemoryTracker::get().allocString(info, pkg.packageName);
    info->PackageState = pkg.state;
    info->ReleaseType = pkg.releaseType;
    info->InstallTime = pkg.installTime;
    info->Applicable = 1;
    info->Copyright = DismMemoryTracker::get().allocString(info, pkg.copyright);
    info->Company = DismMemoryTracker::get().allocString(info, pkg.company);
    info->CreationTime = pkg.installTime;
    info->DisplayName = DismMemoryTracker::get().allocString(info, pkg.displayName);
    info->Description = DismMemoryTracker::get().allocString(info, pkg.description);
    info->InstallClient = DismMemoryTracker::get().allocString(info, pkg.installClient);
    info->InstallPackageName = DismMemoryTracker::get().allocString(info, pkg.packageName);
    info->LastUpdateTime = pkg.installTime;
    info->RestartRequired = pkg.restartRequired;

    // Custom Properties
    if (!pkg.customProps.empty()) {
        uint32_t cpCount = static_cast<uint32_t>(pkg.customProps.size());
        auto* cpArr = reinterpret_cast<DismCustomProperty*>(new (std::nothrow) uint8_t[sizeof(DismCustomProperty) * cpCount]);
        if (cpArr) {
            DismMemoryTracker::get().trackChild(info, cpArr);
            for (uint32_t i = 0; i < cpCount; ++i) {
                cpArr[i].Name = DismMemoryTracker::get().allocString(info, pkg.customProps[i].first);
                cpArr[i].Value = DismMemoryTracker::get().allocString(info, pkg.customProps[i].second);
                cpArr[i].Path = nullptr;
            }
            info->CustomProperty = cpArr;
            info->CustomPropertyCount = cpCount;
        }
    }

    // Associated Features
    if (!pkg.features.empty()) {
        uint32_t fCount = static_cast<uint32_t>(pkg.features.size());
        auto* fArr = reinterpret_cast<DismFeature*>(new (std::nothrow) uint8_t[sizeof(DismFeature) * fCount]);
        if (fArr) {
            DismMemoryTracker::get().trackChild(info, fArr);
            for (uint32_t i = 0; i < fCount; ++i) {
                fArr[i].FeatureName = DismMemoryTracker::get().allocString(info, pkg.features[i]);
                fArr[i].State = DismStateInstalled;
            }
            info->Feature = fArr;
            info->FeatureCount = fCount;
        }
    }

    *PackageInfo = info;
    return DISMAPI_S_OK;
}

inline int32_t __stdcall DismAddPackage(DismSession Session, const wchar_t* PackagePath, int32_t IgnoreCheck, int32_t PreventPending, void* CancelEvent, DISM_PROGRESS_CALLBACK Progress, void* UserContext) {
    if (!PackagePath) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    if (Progress) Progress(50, 100, UserContext);

    std::wstring outName;
    bool success = CbsComponentStore::get().addPackage(PackagePath, PreventPending != 0, outName);
    if (!success) return DISMAPI_E_PACKAGE_NOT_FOUND;

    if (Progress) Progress(100, 100, UserContext);
    return (PreventPending == 0) ? DISMAPI_S_REBOOT_REQUIRED : DISMAPI_S_OK;
}

inline int32_t __stdcall DismRemovePackage(DismSession Session, const wchar_t* Identifier, DismPackageIdentifier PackageIdentifier, void* CancelEvent, DISM_PROGRESS_CALLBACK Progress, void* UserContext) {
    if (!Identifier) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    if (Progress) Progress(50, 100, UserContext);

    bool rebootReq = false;
    bool success = CbsComponentStore::get().removePackage(Identifier, rebootReq);
    if (!success) return DISMAPI_E_PACKAGE_NOT_FOUND;

    if (Progress) Progress(100, 100, UserContext);
    return rebootReq ? DISMAPI_S_REBOOT_REQUIRED : DISMAPI_S_OK;
}

inline int32_t __stdcall DismGetFeatures(DismSession Session, const wchar_t* Identifier, DismPackageIdentifier PackageIdentifier, DismFeature** Feature, uint32_t* Count) {
    if (!Feature || !Count) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    auto internalFeats = CbsComponentStore::get().getFeatures();
    uint32_t count = static_cast<uint32_t>(internalFeats.size());
    if (count == 0) {
        *Feature = nullptr;
        *Count = 0;
        return DISMAPI_S_OK;
    }

    auto* arr = reinterpret_cast<DismFeature*>(DismMemoryTracker::get().allocateRoot(sizeof(DismFeature) * count));
    if (!arr) return static_cast<int32_t>(0x8007000E);

    for (uint32_t i = 0; i < count; ++i) {
        arr[i].FeatureName = DismMemoryTracker::get().allocString(arr, internalFeats[i].featureName);
        arr[i].State = internalFeats[i].state;
    }

    *Feature = arr;
    *Count = count;
    return DISMAPI_S_OK;
}

inline int32_t __stdcall DismGetFeatureInfo(DismSession Session, const wchar_t* FeatureName, const wchar_t* Identifier, DismPackageIdentifier PackageIdentifier, DismFeatureInfo** FeatureInfo) {
    if (!FeatureName || !FeatureInfo) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    InternalFeature feat{};
    if (!CbsComponentStore::get().getFeature(FeatureName, feat)) {
        return DISMAPI_E_FEATURE_NOT_FOUND;
    }

    auto* info = reinterpret_cast<DismFeatureInfo*>(DismMemoryTracker::get().allocateRoot(sizeof(DismFeatureInfo)));
    if (!info) return static_cast<int32_t>(0x8007000E);

    info->FeatureName = DismMemoryTracker::get().allocString(info, feat.featureName);
    info->FeatureState = feat.state;
    info->DisplayName = DismMemoryTracker::get().allocString(info, feat.displayName);
    info->Description = DismMemoryTracker::get().allocString(info, feat.description);
    info->RestartRequired = feat.restartRequired;

    *FeatureInfo = info;
    return DISMAPI_S_OK;
}

inline int32_t __stdcall DismEnableFeature(DismSession Session, const wchar_t* FeatureName, const wchar_t* Identifier, DismPackageIdentifier PackageIdentifier, int32_t LimitAccess, const wchar_t** SourcePaths, uint32_t SourcePathCount, int32_t EnableAllDependencies, void* CancelEvent, DISM_PROGRESS_CALLBACK Progress, void* UserContext) {
    if (!FeatureName) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    if (Progress) Progress(50, 100, UserContext);

    bool rebootReq = false;
    bool success = CbsComponentStore::get().enableFeature(FeatureName, EnableAllDependencies != 0, rebootReq);
    if (!success) return DISMAPI_E_FEATURE_NOT_FOUND;

    if (Progress) Progress(100, 100, UserContext);
    return rebootReq ? DISMAPI_S_REBOOT_REQUIRED : DISMAPI_S_OK;
}

inline int32_t __stdcall DismDisableFeature(DismSession Session, const wchar_t* FeatureName, const wchar_t* PackageName, int32_t RemovePayload, void* CancelEvent, DISM_PROGRESS_CALLBACK Progress, void* UserContext) {
    if (!FeatureName) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    if (Progress) Progress(50, 100, UserContext);

    bool rebootReq = false;
    bool success = CbsComponentStore::get().disableFeature(FeatureName, RemovePayload != 0, rebootReq);
    if (!success) return DISMAPI_E_FEATURE_NOT_FOUND;

    if (Progress) Progress(100, 100, UserContext);
    return rebootReq ? DISMAPI_S_REBOOT_REQUIRED : DISMAPI_S_OK;
}

inline int32_t __stdcall DismCheckImageHealth(DismSession Session, int32_t ScanImage, void* CancelEvent, DISM_PROGRESS_CALLBACK Progress, void* UserContext, DismImageHealthState* ImageHealth) {
    if (!ImageHealth) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    if (Progress) Progress(100, 100, UserContext);
    *ImageHealth = CbsComponentStore::get().getHealthState();
    return DISMAPI_S_OK;
}

inline int32_t __stdcall DismScanImageHealth(DismSession Session, void* CancelEvent, DISM_PROGRESS_CALLBACK Progress, void* UserContext, DismImageHealthState* ImageHealth) {
    if (!ImageHealth) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    for (uint32_t p = 10; p <= 100; p += 30) {
        if (Progress) Progress(p, 100, UserContext);
    }

    *ImageHealth = CbsComponentStore::get().getHealthState();
    return DISMAPI_S_OK;
}

inline int32_t __stdcall DismRestoreImageHealth(DismSession Session, const wchar_t** SourcePaths, uint32_t SourcePathCount, int32_t LimitAccess, void* CancelEvent, DISM_PROGRESS_CALLBACK Progress, void* UserContext) {
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    for (uint32_t p = 20; p <= 100; p += 20) {
        if (Progress) Progress(p, 100, UserContext);
    }

    CbsComponentStore::get().restoreHealth();
    return DISMAPI_S_OK;
}

inline int32_t __stdcall DismGetCapabilities(DismSession Session, DismCapability** Capability, uint32_t* Count) {
    if (!Capability || !Count) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    auto internalCaps = CbsComponentStore::get().getCapabilities();
    uint32_t count = static_cast<uint32_t>(internalCaps.size());
    if (count == 0) {
        *Capability = nullptr;
        *Count = 0;
        return DISMAPI_S_OK;
    }

    auto* arr = reinterpret_cast<DismCapability*>(DismMemoryTracker::get().allocateRoot(sizeof(DismCapability) * count));
    if (!arr) return static_cast<int32_t>(0x8007000E);

    for (uint32_t i = 0; i < count; ++i) {
        arr[i].Name = DismMemoryTracker::get().allocString(arr, internalCaps[i].name);
        arr[i].State = internalCaps[i].state;
    }

    *Capability = arr;
    *Count = count;
    return DISMAPI_S_OK;
}

inline int32_t __stdcall DismGetCapabilityInfo(DismSession Session, const wchar_t* CapabilityName, DismCapabilityInfo** CapabilityInfo) {
    if (!CapabilityName || !CapabilityInfo) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    InternalCapability cap{};
    if (!CbsComponentStore::get().getCapability(CapabilityName, cap)) {
        return DISMAPI_E_PACKAGE_NOT_FOUND;
    }

    auto* info = reinterpret_cast<DismCapabilityInfo*>(DismMemoryTracker::get().allocateRoot(sizeof(DismCapabilityInfo)));
    if (!info) return static_cast<int32_t>(0x8007000E);

    info->Name = DismMemoryTracker::get().allocString(info, cap.name);
    info->State = cap.state;
    info->DisplayName = DismMemoryTracker::get().allocString(info, cap.displayName);
    info->Description = DismMemoryTracker::get().allocString(info, cap.description);
    info->DownloadSize = cap.downloadSize;
    info->InstallSize = cap.installSize;

    *CapabilityInfo = info;
    return DISMAPI_S_OK;
}

inline int32_t __stdcall DismAddCapability(DismSession Session, const wchar_t* CapabilityName, int32_t LimitAccess, const wchar_t** SourcePaths, uint32_t SourcePathCount, void* CancelEvent, DISM_PROGRESS_CALLBACK Progress, void* UserContext) {
    if (!CapabilityName) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    if (Progress) Progress(50, 100, UserContext);
    bool ok = CbsComponentStore::get().addCapability(CapabilityName);
    if (!ok) return DISMAPI_E_PACKAGE_NOT_FOUND;

    if (Progress) Progress(100, 100, UserContext);
    return DISMAPI_S_OK;
}

inline int32_t __stdcall DismRemoveCapability(DismSession Session, const wchar_t* CapabilityName, void* CancelEvent, DISM_PROGRESS_CALLBACK Progress, void* UserContext) {
    if (!CapabilityName) return DISMAPI_E_INVALIDARG;
    SessionRecord sess{};
    if (!DismSessionManager::get().findSession(Session, sess)) return DISMAPI_E_SESSION_NOT_FOUND;

    if (Progress) Progress(50, 100, UserContext);
    bool ok = CbsComponentStore::get().removeCapability(CapabilityName);
    if (!ok) return DISMAPI_E_PACKAGE_NOT_FOUND;

    if (Progress) Progress(100, 100, UserContext);
    return DISMAPI_S_OK;
}

// ============================================================================
// 7. CBS API Implementation (cbsapi.dll)
// ============================================================================

inline int32_t __stdcall CbsInitialize(uint32_t flags) {
    return DismSessionManager::get().initialize(DismLogErrorsWarningsInfo, nullptr, nullptr);
}

inline int32_t __stdcall CbsShutdown() {
    return DismSessionManager::get().shutdown();
}

inline int32_t __stdcall CbsCreateSession(uint32_t flags, DismSession* pSession) {
    return DismSessionManager::get().openSession(DISM_ONLINE_IMAGE, nullptr, nullptr, pSession);
}

// ============================================================================
// 8. Dynamic Loader Registration & SCM Integration
// ============================================================================

inline void InitializeCbsSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // dismapi.dll
    ldr.registerExport("dismapi.dll", "DismInitialize", reinterpret_cast<void*>(DismInitialize));
    ldr.registerExport("dismapi.dll", "DismShutdown", reinterpret_cast<void*>(DismShutdown));
    ldr.registerExport("dismapi.dll", "DismOpenSession", reinterpret_cast<void*>(DismOpenSession));
    ldr.registerExport("dismapi.dll", "DismCloseSession", reinterpret_cast<void*>(DismCloseSession));
    ldr.registerExport("dismapi.dll", "DismDelete", reinterpret_cast<void*>(DismDelete));
    ldr.registerExport("dismapi.dll", "DismGetPackages", reinterpret_cast<void*>(DismGetPackages));
    ldr.registerExport("dismapi.dll", "DismGetPackageInfo", reinterpret_cast<void*>(DismGetPackageInfo));
    ldr.registerExport("dismapi.dll", "DismAddPackage", reinterpret_cast<void*>(DismAddPackage));
    ldr.registerExport("dismapi.dll", "DismRemovePackage", reinterpret_cast<void*>(DismRemovePackage));
    ldr.registerExport("dismapi.dll", "DismGetFeatures", reinterpret_cast<void*>(DismGetFeatures));
    ldr.registerExport("dismapi.dll", "DismGetFeatureInfo", reinterpret_cast<void*>(DismGetFeatureInfo));
    ldr.registerExport("dismapi.dll", "DismEnableFeature", reinterpret_cast<void*>(DismEnableFeature));
    ldr.registerExport("dismapi.dll", "DismDisableFeature", reinterpret_cast<void*>(DismDisableFeature));
    ldr.registerExport("dismapi.dll", "DismCheckImageHealth", reinterpret_cast<void*>(DismCheckImageHealth));
    ldr.registerExport("dismapi.dll", "DismScanImageHealth", reinterpret_cast<void*>(DismScanImageHealth));
    ldr.registerExport("dismapi.dll", "DismRestoreImageHealth", reinterpret_cast<void*>(DismRestoreImageHealth));
    ldr.registerExport("dismapi.dll", "DismGetCapabilities", reinterpret_cast<void*>(DismGetCapabilities));
    ldr.registerExport("dismapi.dll", "DismGetCapabilityInfo", reinterpret_cast<void*>(DismGetCapabilityInfo));
    ldr.registerExport("dismapi.dll", "DismAddCapability", reinterpret_cast<void*>(DismAddCapability));
    ldr.registerExport("dismapi.dll", "DismRemoveCapability", reinterpret_cast<void*>(DismRemoveCapability));

    // cbsapi.dll
    ldr.registerExport("cbsapi.dll", "CbsInitialize", reinterpret_cast<void*>(CbsInitialize));
    ldr.registerExport("cbsapi.dll", "CbsShutdown", reinterpret_cast<void*>(CbsShutdown));
    ldr.registerExport("cbsapi.dll", "CbsCreateSession", reinterpret_cast<void*>(CbsCreateSession));

    // Register TrustedInstaller service in Service Control Manager
    auto& scm = scm::ServiceControlManager::get();
    auto tiRecord = std::make_shared<scm::ServiceRecord>();
    tiRecord->serviceName = L"TrustedInstaller";
    tiRecord->displayName = L"Windows Modules Installer";
    tiRecord->serviceType = scm::SERVICE_WIN32_OWN_PROCESS;
    tiRecord->startType = scm::SERVICE_DEMAND_START;
    tiRecord->errorControl = scm::SERVICE_ERROR_NORMAL;
    tiRecord->binaryPath = L"%SystemRoot%\\servicing\\TrustedInstaller.exe";
    tiRecord->status.dwCurrentState = scm::SERVICE_RUNNING;
    tiRecord->status.dwProcessId = 1060;
    scm.registerServiceRecord(tiRecord);
}

} // namespace micant::cbs
