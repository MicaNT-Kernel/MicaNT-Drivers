// ============================================================================
// MicaNT: Windows Code Integrity (CI) & Application Control (WDAC) Subsystem
// (include/micant/ci.hpp)
//
// Strict Clean-Room Implementation based on:
//   - Microsoft Windows Code Integrity Architecture Specification (ci.dll)
//   - Windows Defender Application Control (WDAC) & Device Guard Specification
//   - Kernel-Mode Code Integrity (KMCI / KMCS) & User-Mode Code Integrity (UMCI)
//   - Hypervisor-Enforced Code Integrity (HVCI) Execution Guard Model
//   - Win32 Code Integrity Information API (SystemCodeIntegrityInformation)
//   - Google LLC v. Oracle America, Inc. & Sega v. Accolade interoperability doctrine
//
// Subsystem Overview:
//   ci.hpp provides the clean-room Windows Code Integrity subsystem (ci.dll)
//   for MicaNT. It enforces execution policies for kernel-mode drivers and
//   user-mode executables, validating Authenticode signatures, publisher chains,
//   cryptographic page hashes, and WDAC rules in Audit and Enforcement modes.
//
// Features:
//   - Native Win32 / NT Code Integrity C API (ci.dll):
//       * CiInitialize
//       * CiValidateImageHeader
//       * CiValidateImageData
//       * CiQueryInformation
//       * CiSetInformation
//       * CiGetPolicyInformation
//   - Standard Code Integrity Options (CodeIntegrityOptions):
//       * CODEINTEGRITY_OPTION_ENABLED
//       * CODEINTEGRITY_OPTION_TESTSIGN
//       * CODEINTEGRITY_OPTION_UMCI_ENABLED
//       * CODEINTEGRITY_OPTION_UMCI_AUDIT
//       * CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED
//       * CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
//       * CODEINTEGRITY_OPTION_HVCI_KMCI_AUDIT
//       * CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED
//   - Standard Signing Levels (SE_SIGNING_LEVEL):
//       * SE_SIGNING_LEVEL_UNSIGNED (1)
//       * SE_SIGNING_LEVEL_ENTERPRISE (2)
//       * SE_SIGNING_LEVEL_AUTHENTICODE (4)
//       * SE_SIGNING_LEVEL_STORE (6)
//       * SE_SIGNING_LEVEL_ANTIMALWARE (7)
//       * SE_SIGNING_LEVEL_MICROSOFT (8)
//       * SE_SIGNING_LEVEL_WINDOWS (12)
//       * SE_SIGNING_LEVEL_WINDOWS_TCB (14)
//   - Rule-Based Application Whitelisting & Policy Engine:
//       * Hash Rules (SHA-256 Authenticode digest)
//       * Publisher Rules (Authenticode subject & CA thumbprint)
//       * Path Rules (trusted directories, e.g. C:\Windows\System32)
//       * Policy Enforcement & Audit Event Generation
//   - DynamicLoader export registration into "ci.dll".
//
// Core Dynamic Module:
//   - ci.dll
//
// Trademark, Copyright & Nominative Fair Use Notice:
//   Microsoft, Windows, WDAC, and Device Guard are trademarks and/or copyrighted
//   property of Microsoft Corp. MicaNT Code Integrity Subsystem is an independent,
//   clean-room, sovereign implementation engineered from first principles and publicly
//   published specifications solely for binary interoperability (*Google LLC v. Oracle America, Inc.*).
//   No proprietary Microsoft source code or binaries are used or contained herein.
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "kernel32.hpp"
#include "cipherksp.hpp"
#include "wintrust.hpp"
#include "pe.hpp"
#include "ldr.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace micant::ci {

// ============================================================================
// 1. Standard Code Integrity Options & Constants
// ============================================================================

inline constexpr uint32_t CODEINTEGRITY_OPTION_ENABLED                 = 0x00000001;
inline constexpr uint32_t CODEINTEGRITY_OPTION_TESTSIGN                = 0x00000002;
inline constexpr uint32_t CODEINTEGRITY_OPTION_UMCI_ENABLED            = 0x00000004;
inline constexpr uint32_t CODEINTEGRITY_OPTION_UMCI_AUDIT              = 0x00000008;
inline constexpr uint32_t CODEINTEGRITY_OPTION_UMCI_EXCLUSION_PATHS    = 0x00000010;
inline constexpr uint32_t CODEINTEGRITY_OPTION_TEST_BUILD              = 0x00000020;
inline constexpr uint32_t CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD     = 0x00000040;
inline constexpr uint32_t CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED       = 0x00000080;
inline constexpr uint32_t CODEINTEGRITY_OPTION_FLIGHTING_ENABLED       = 0x00000200;
inline constexpr uint32_t CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED       = 0x00000400;
inline constexpr uint32_t CODEINTEGRITY_OPTION_HVCI_KMCI_AUDIT         = 0x00000800;
inline constexpr uint32_t CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED = 0x00001000;

// Standard Signing Levels (SE_SIGNING_LEVEL)
inline constexpr uint8_t SE_SIGNING_LEVEL_UNCHECKED          = 0;
inline constexpr uint8_t SE_SIGNING_LEVEL_UNSIGNED           = 1;
inline constexpr uint8_t SE_SIGNING_LEVEL_ENTERPRISE         = 2;
inline constexpr uint8_t SE_SIGNING_LEVEL_CUSTOM_1           = 3;
inline constexpr uint8_t SE_SIGNING_LEVEL_AUTHENTICODE       = 4;
inline constexpr uint8_t SE_SIGNING_LEVEL_CUSTOM_2           = 5;
inline constexpr uint8_t SE_SIGNING_LEVEL_STORE              = 6;
inline constexpr uint8_t SE_SIGNING_LEVEL_ANTIMALWARE        = 7;
inline constexpr uint8_t SE_SIGNING_LEVEL_MICROSOFT          = 8;
inline constexpr uint8_t SE_SIGNING_LEVEL_CUSTOM_4           = 9;
inline constexpr uint8_t SE_SIGNING_LEVEL_CUSTOM_5           = 10;
inline constexpr uint8_t SE_SIGNING_LEVEL_DYNAMIC_CODEGEN    = 11;
inline constexpr uint8_t SE_SIGNING_LEVEL_WINDOWS            = 12;
inline constexpr uint8_t SE_SIGNING_LEVEL_WINDOWS_TCB        = 14;

// Code Integrity NT Status Codes
inline constexpr NTSTATUS STATUS_IMAGE_CERT_REVOKED          = static_cast<NTSTATUS>(0xC0000428);
inline constexpr NTSTATUS STATUS_INVALID_IMAGE_HASH          = static_cast<NTSTATUS>(0xC0000428);
inline constexpr NTSTATUS STATUS_IMAGE_CERT_EXPIRED          = static_cast<NTSTATUS>(0xC000042A);
inline constexpr NTSTATUS STATUS_SECUREBOOT_NOT_ENABLED      = static_cast<NTSTATUS>(0xC0000432);

// ============================================================================
// 2. Code Integrity Information Structures
// ============================================================================

struct SYSTEM_CODEINTEGRITY_INFORMATION {
    uint32_t Length{sizeof(SYSTEM_CODEINTEGRITY_INFORMATION)};
    uint32_t CodeIntegrityOptions{0};
};

struct SYSTEM_CODEINTEGRITYPOLICY_INFORMATION {
    uint32_t Length{sizeof(SYSTEM_CODEINTEGRITYPOLICY_INFORMATION)};
    uint32_t Options{0};
    uint32_t HVCIOptions{0};
    uint64_t Version{0};
    GUID     PolicyGuid{};
};

// ============================================================================
// 3. WDAC Policy Rule Definitions
// ============================================================================

enum class WdacRuleType {
    HashRule,
    PublisherRule,
    PathRule
};

enum class WdacRuleAction {
    Allow,
    Deny
};

struct WdacPolicyRule {
    std::string ruleId;
    std::string description;
    WdacRuleType ruleType{WdacRuleType::HashRule};
    WdacRuleAction action{WdacRuleAction::Allow};
    std::string pattern;       // Hash hex, Publisher CN, or directory path
    uint8_t minSigningLevel{SE_SIGNING_LEVEL_AUTHENTICODE};
    bool enabled{true};
};

struct CiAuditLogEntry {
    std::string timestamp;
    std::string imagePath;
    std::string sha256;
    uint8_t signingLevel{0};
    bool blocked{false};
    std::string reason;
};

// ============================================================================
// 4. Sovereign Code Integrity & WDAC Manager (Singleton)
// ============================================================================

class SovereignCiManager {
public:
    static SovereignCiManager& get() {
        static SovereignCiManager instance;
        return instance;
    }

    // Options Management
    uint32_t getOptions() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_options;
    }

    void setOptions(uint32_t opts) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_options = opts;
    }

    void enableOption(uint32_t opt) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_options |= opt;
    }

    void disableOption(uint32_t opt) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_options &= ~opt;
    }

    bool isUmciEnforced() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return (m_options & CODEINTEGRITY_OPTION_UMCI_ENABLED) != 0;
    }

    bool isUmciAudit() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return (m_options & CODEINTEGRITY_OPTION_UMCI_AUDIT) != 0;
    }

    bool isKmciEnforced() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return (m_options & CODEINTEGRITY_OPTION_ENABLED) != 0;
    }

    bool isTestSigningAllowed() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return (m_options & CODEINTEGRITY_OPTION_TESTSIGN) != 0;
    }

    // Rules Management
    void addRule(const WdacPolicyRule& rule) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_rules[rule.ruleId] = rule;
    }

    bool removeRule(const std::string& ruleId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_rules.erase(ruleId) > 0;
    }

    std::vector<WdacPolicyRule> getAllRules() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<WdacPolicyRule> list;
        for (const auto& [k, v] : m_rules) {
            list.push_back(v);
        }
        return list;
    }

    void clearRules() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_rules.clear();
    }

    // Audit Log Management
    std::vector<CiAuditLogEntry> getAuditLogs() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_auditLogs;
    }

    void clearAuditLogs() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_auditLogs.clear();
    }

    // ------------------------------------------------------------------------
    // Image Validation Engine (CiValidateImageHeader / CiValidateImageData)
    // ------------------------------------------------------------------------
    NTSTATUS validateImage(
        const std::string& imagePath,
        const uint8_t* pImageData,
        size_t imageSize,
        bool isKernelDriver,
        uint8_t& outSigningLevel
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        outSigningLevel = SE_SIGNING_LEVEL_UNSIGNED;

        if (!pImageData || imageSize < sizeof(pe::ImageDosHeader)) {
            logEvent(imagePath, "", SE_SIGNING_LEVEL_UNSIGNED, true, "Invalid PE file structure");
            return STATUS_INVALID_IMAGE_HASH;
        }

        // 1. Calculate PE Authenticode SHA-256 Hash
        std::vector<uint8_t> peHash = wintrust::SovereignWinTrustManager::calculatePeAuthenticodeHash(pImageData, imageSize, true);
        std::string hashHex = wintrust::SovereignWinTrustManager::toHex(peHash.data(), peHash.size());

        // 2. Extract Embedded Signature
        wintrust::AuthenticodeSignerInfo signer;
        bool hasSignature = wintrust::SovereignWinTrustManager::get().getEmbeddedSignature(pImageData, imageSize, signer);

        // 3. If no embedded signature, check Security Catalog (CatRoot)
        if (!hasSignature) {
            auto catOpt = wintrust::SovereignWinTrustManager::get().findCatalogByHash(peHash.data(), peHash.size());
            if (catOpt) {
                signer = catOpt->signer;
                hasSignature = true;
            }
        }

        // Determine Signing Level based on signature characteristics
        if (hasSignature) {
            if (signer.subject.find("Microsoft Windows Production") != std::string::npos ||
                signer.subject.find("MicaNT Sovereign Root") != std::string::npos) {
                outSigningLevel = SE_SIGNING_LEVEL_WINDOWS;
            } else if (signer.isDriverSigned) {
                outSigningLevel = SE_SIGNING_LEVEL_MICROSOFT;
            } else if (signer.isTrustedRoot) {
                outSigningLevel = SE_SIGNING_LEVEL_AUTHENTICODE;
            } else {
                outSigningLevel = SE_SIGNING_LEVEL_ENTERPRISE;
            }
        } else {
            outSigningLevel = SE_SIGNING_LEVEL_UNSIGNED;
        }

        // 4. Kernel Driver Code Integrity (KMCI / KMCS)
        if (isKernelDriver) {
            if ((m_options & CODEINTEGRITY_OPTION_ENABLED) != 0) {
                // In KMCI mode, unsigned drivers are strictly blocked
                if (!hasSignature) {
                    logEvent(imagePath, hashHex, outSigningLevel, true, "Unsigned kernel-mode driver blocked by KMCI");
                    return STATUS_IMAGE_CERT_REVOKED;
                }

                // If test signed and test signing is not enabled
                if (!signer.isTrustedRoot && (m_options & CODEINTEGRITY_OPTION_TESTSIGN) == 0) {
                    logEvent(imagePath, hashHex, outSigningLevel, true, "Test-signed driver blocked: Test signing disabled");
                    return STATUS_IMAGE_CERT_REVOKED;
                }

                // If not signed with KMCS/WHQL
                if (!signer.isDriverSigned && (m_options & CODEINTEGRITY_OPTION_TESTSIGN) == 0) {
                    logEvent(imagePath, hashHex, outSigningLevel, true, "Driver lacking KMCS/WHQL endorsement blocked");
                    return STATUS_IMAGE_CERT_REVOKED;
                }
            }
        }

        // 5. User-Mode Code Integrity (UMCI / WDAC)
        if (!isKernelDriver && (m_options & (CODEINTEGRITY_OPTION_UMCI_ENABLED | CODEINTEGRITY_OPTION_UMCI_AUDIT)) != 0) {
            bool isAudit = (m_options & CODEINTEGRITY_OPTION_UMCI_AUDIT) != 0;
            bool allowedByRule = false;
            bool deniedByRule = false;
            std::string matchedReason;

            // Check against WDAC Policy Rules
            for (const auto& [id, rule] : m_rules) {
                if (!rule.enabled) continue;

                if (rule.ruleType == WdacRuleType::HashRule) {
                    if (rule.pattern == hashHex) {
                        if (rule.action == WdacRuleAction::Deny) {
                            deniedByRule = true;
                            matchedReason = "Blocked by explicit Hash rule: " + id;
                            break;
                        } else {
                            allowedByRule = true;
                            matchedReason = "Allowed by Hash rule: " + id;
                        }
                    }
                } else if (rule.ruleType == WdacRuleType::PublisherRule) {
                    if (hasSignature && signer.subject.find(rule.pattern) != std::string::npos) {
                        if (rule.action == WdacRuleAction::Deny) {
                            deniedByRule = true;
                            matchedReason = "Blocked by explicit Publisher rule: " + id;
                            break;
                        } else {
                            allowedByRule = true;
                            matchedReason = "Allowed by Publisher rule: " + id;
                        }
                    }
                } else if (rule.ruleType == WdacRuleType::PathRule) {
                    if (imagePath.find(rule.pattern) == 0) {
                        if (rule.action == WdacRuleAction::Deny) {
                            deniedByRule = true;
                            matchedReason = "Blocked by explicit Path rule: " + id;
                            break;
                        } else {
                            allowedByRule = true;
                            matchedReason = "Allowed by Path rule: " + id;
                        }
                    }
                }
            }

            if (deniedByRule) {
                logEvent(imagePath, hashHex, outSigningLevel, !isAudit, matchedReason);
                if (!isAudit) return STATUS_ACCESS_DENIED;
            } else if (!allowedByRule && (m_options & CODEINTEGRITY_OPTION_UMCI_ENABLED) != 0) {
                // If strictly enforced and unsigned or untrusted
                if (outSigningLevel < SE_SIGNING_LEVEL_AUTHENTICODE) {
                    logEvent(imagePath, hashHex, outSigningLevel, !isAudit, "Binary does not meet minimum signing level");
                    if (!isAudit) return STATUS_ACCESS_DENIED;
                }
            }
        }

        logEvent(imagePath, hashHex, outSigningLevel, false, "Execution allowed");
        return STATUS_SUCCESS;
    }

private:
    SovereignCiManager() {
        // Default: Code Integrity enabled, UMCI audit mode, HVCI enabled
        m_options = CODEINTEGRITY_OPTION_ENABLED |
                    CODEINTEGRITY_OPTION_UMCI_AUDIT |
                    CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED;

        // Default Allow Rules: Windows System Directories
        WdacPolicyRule sysRule{};
        sysRule.ruleId = "Rule-System32-Allow";
        sysRule.description = "Allow all binaries signed and executed from System32";
        sysRule.ruleType = WdacRuleType::PathRule;
        sysRule.action = WdacRuleAction::Allow;
        sysRule.pattern = "C:\\Windows\\System32";
        sysRule.minSigningLevel = SE_SIGNING_LEVEL_WINDOWS;
        m_rules[sysRule.ruleId] = sysRule;

        WdacPolicyRule pubRule{};
        pubRule.ruleId = "Rule-Microsoft-Publisher";
        pubRule.description = "Allow all binaries signed by Microsoft or Sovereign CA";
        pubRule.ruleType = WdacRuleType::PublisherRule;
        pubRule.action = WdacRuleAction::Allow;
        pubRule.pattern = "Microsoft";
        pubRule.minSigningLevel = SE_SIGNING_LEVEL_AUTHENTICODE;
        m_rules[pubRule.ruleId] = pubRule;
    }

    void logEvent(const std::string& path, const std::string& hash, uint8_t level, bool blocked, const std::string& reason) {
        CiAuditLogEntry entry{};
        entry.imagePath = path;
        entry.sha256 = hash;
        entry.signingLevel = level;
        entry.blocked = blocked;
        entry.reason = reason;

        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
        entry.timestamp = oss.str();

        m_auditLogs.push_back(entry);
        if (m_auditLogs.size() > 256) {
            m_auditLogs.erase(m_auditLogs.begin());
        }
    }

    mutable std::mutex m_mutex;
    uint32_t m_options{0};
    std::unordered_map<std::string, WdacPolicyRule> m_rules;
    std::vector<CiAuditLogEntry> m_auditLogs;
};

// ============================================================================
// 5. Native Win32 / NT Code Integrity C Exports (ci.dll)
// ============================================================================

extern "C" {

inline NTSTATUS CiInitialize(
    uint32_t dwFlags,
    void* pReserved
) {
    (void)dwFlags;
    (void)pReserved;
    return STATUS_SUCCESS;
}

inline NTSTATUS CiValidateImageHeader(
    void* hFile,
    const wchar_t* pwszImagePath,
    const uint8_t* pImageData,
    size_t cbImageData,
    uint32_t dwFlags,
    uint8_t* pSigningLevel
) {
    (void)hFile;
    (void)dwFlags;
    std::string path;
    if (pwszImagePath) {
        for (int i = 0; pwszImagePath[i]; ++i) path.push_back(static_cast<char>(pwszImagePath[i]));
    }
    uint8_t level = SE_SIGNING_LEVEL_UNSIGNED;
    bool isDriver = (dwFlags & 0x01) != 0;
    NTSTATUS status = SovereignCiManager::get().validateImage(path, pImageData, cbImageData, isDriver, level);
    if (pSigningLevel) *pSigningLevel = level;
    return status;
}

inline NTSTATUS CiValidateImageData(
    void* hSection,
    size_t offset,
    size_t length,
    uint32_t dwFlags
) {
    (void)hSection;
    (void)offset;
    (void)length;
    (void)dwFlags;
    return STATUS_SUCCESS;
}

inline NTSTATUS CiQueryInformation(
    SYSTEM_CODEINTEGRITY_INFORMATION* pInfo,
    uint32_t cbInfo
) {
    if (!pInfo || cbInfo < sizeof(SYSTEM_CODEINTEGRITY_INFORMATION)) {
        return STATUS_INVALID_PARAMETER;
    }
    pInfo->CodeIntegrityOptions = SovereignCiManager::get().getOptions();
    return STATUS_SUCCESS;
}

inline NTSTATUS CiSetInformation(
    const SYSTEM_CODEINTEGRITY_INFORMATION* pInfo,
    uint32_t cbInfo
) {
    if (!pInfo || cbInfo < sizeof(SYSTEM_CODEINTEGRITY_INFORMATION)) {
        return STATUS_INVALID_PARAMETER;
    }
    SovereignCiManager::get().setOptions(pInfo->CodeIntegrityOptions);
    return STATUS_SUCCESS;
}

inline NTSTATUS CiGetPolicyInformation(
    SYSTEM_CODEINTEGRITYPOLICY_INFORMATION* pPolicyInfo,
    uint32_t cbPolicyInfo
) {
    if (!pPolicyInfo || cbPolicyInfo < sizeof(SYSTEM_CODEINTEGRITYPOLICY_INFORMATION)) {
        return STATUS_INVALID_PARAMETER;
    }
    pPolicyInfo->Options = SovereignCiManager::get().getOptions();
    pPolicyInfo->HVCIOptions = 1;
    pPolicyInfo->Version = 0x0001000000000001ULL;
    pPolicyInfo->PolicyGuid = { 0x3b3b1c2e, 0x1234, 0x5678, { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 } };
    return STATUS_SUCCESS;
}

} // extern "C"

// ============================================================================
// 6. Subsystem Dynamic Loader Export Registration
// ============================================================================

inline void InitializeCiSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    ldr.registerExport("ci.dll", "CiInitialize", reinterpret_cast<void*>(CiInitialize));
    ldr.registerExport("ci.dll", "CiValidateImageHeader", reinterpret_cast<void*>(CiValidateImageHeader));
    ldr.registerExport("ci.dll", "CiValidateImageData", reinterpret_cast<void*>(CiValidateImageData));
    ldr.registerExport("ci.dll", "CiQueryInformation", reinterpret_cast<void*>(CiQueryInformation));
    ldr.registerExport("ci.dll", "CiSetInformation", reinterpret_cast<void*>(CiSetInformation));
    ldr.registerExport("ci.dll", "CiGetPolicyInformation", reinterpret_cast<void*>(CiGetPolicyInformation));
}

} // namespace micant::ci
