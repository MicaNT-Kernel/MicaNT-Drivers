// ============================================================================
// MicaNT Sovereign Security System: Protected Process Light (PPL) & ELAM
// Module: ppl.hpp
// Clean-Room Implementation conforming to Windows NT SRM & VBS specifications
//
// Capabilities:
//   - Process Protection Level (PPL) Architecture:
//       * PS_PROTECTED_TYPE (None, ProtectedLight, Protected)
//       * PS_PROTECTED_SIGNER (None, Authenticode, CodeGen, Antimalware, Lsa,
//                              Windows, WinTcb, WinSystem, App)
//       * PS_PROTECTION bitfield union
//       * Signer Dominance Matrix (RtlTestProtectedAccess)
//       * Access Mask Sanitization (PROCESS_DANGEROUS_ACCESS_MASK stripping)
//       * SeDebugPrivilege Escalation Defense
//   - Early Launch Anti-Malware (ELAM) Subsystem:
//       * Boot Driver Callback registration (IoRegisterBootDriverCallback)
//       * Boot Driver Classification (BDCB_CLASSIFICATION)
//       * Boot Driver Verification & Rootkit Blocking
//       * Configurable ELAM Boot Driver Policy
//   - Win32 & NT Clean-Room C ABI:
//       * PsIsProtectedProcess
//       * PsGetProcessProtection
//       * PsSetProcessProtection
//       * PsFilterAccessMask
//       * PsTerminateProcessSecure
//       * IoRegisterBootDriverCallback
//       * IoUnRegisterBootDriverCallback
//       * ElamGetDriverClassification
//       * ElamSetDriverClassification
//       * ElamEvaluateBootDriver
//   - DynamicLoader export registration into "ntoskrnl.exe" and "kernel32.dll".
//
// Core Dynamic Modules:
//   - ntoskrnl.exe
//   - elam.sys
//
// Trademark, Copyright & Nominative Fair Use Notice:
//   Microsoft, Windows, Protected Process Light (PPL), and Early Launch Anti-Malware (ELAM)
//   are trademarks and/or copyrighted property of Microsoft Corp. MicaNT PPL & ELAM
//   Subsystem is an independent, clean-room, sovereign implementation engineered from
//   first principles and publicly published specifications solely for binary interoperability
//   (Google LLC v. Oracle America, Inc.). No proprietary Microsoft source code or binaries
//   are used or contained herein.
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "kernel32.hpp"
#include "ldr.hpp"
#include "version.hpp"
#include "ps.hpp"
#include "se.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace micant::ppl {

// ============================================================================
// 1. Process Access Rights & Mask Definitions
// ============================================================================

inline constexpr uint32_t PROCESS_TERMINATE                 = 0x0001;
inline constexpr uint32_t PROCESS_CREATE_THREAD             = 0x0002;
inline constexpr uint32_t PROCESS_SET_SESSIONID             = 0x0004;
inline constexpr uint32_t PROCESS_VM_OPERATION              = 0x0008;
inline constexpr uint32_t PROCESS_VM_READ                   = 0x0010;
inline constexpr uint32_t PROCESS_VM_WRITE                  = 0x0020;
inline constexpr uint32_t PROCESS_DUP_HANDLE                = 0x0040;
inline constexpr uint32_t PROCESS_CREATE_PROCESS            = 0x0080;
inline constexpr uint32_t PROCESS_SET_QUOTA                 = 0x0100;
inline constexpr uint32_t PROCESS_SET_INFORMATION           = 0x0200;
inline constexpr uint32_t PROCESS_QUERY_INFORMATION         = 0x0400;
inline constexpr uint32_t PROCESS_SUSPEND_RESUME            = 0x0800;
inline constexpr uint32_t PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
inline constexpr uint32_t PROCESS_SET_LIMITED_INFORMATION   = 0x2000;
inline constexpr uint32_t SYNCHRONIZE                       = 0x00100000;
inline constexpr uint32_t STANDARD_RIGHTS_REQUIRED          = 0x000F0000;
inline constexpr uint32_t PROCESS_ALL_ACCESS                = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF);

// Dangerous rights stripped by SRM when accessing a protected process without proper dominance
inline constexpr uint32_t PROCESS_DANGEROUS_ACCESS_MASK =
    PROCESS_TERMINATE |
    PROCESS_CREATE_THREAD |
    PROCESS_VM_OPERATION |
    PROCESS_VM_READ |
    PROCESS_VM_WRITE |
    PROCESS_DUP_HANDLE |
    PROCESS_CREATE_PROCESS |
    PROCESS_SET_QUOTA |
    PROCESS_SET_INFORMATION |
    PROCESS_SUSPEND_RESUME |
    0x00010000 | // DELETE
    0x00040000 | // WRITE_DAC
    0x00080000;  // WRITE_OWNER

// ============================================================================
// 2. Protected Process Types & Signer Levels
// ============================================================================

enum PS_PROTECTED_TYPE : uint8_t {
    PsProtectedTypeNone           = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected      = 2
};

enum PS_PROTECTED_SIGNER : uint8_t {
    PsProtectedSignerNone         = 0,
    PsProtectedSignerAuthenticode = 1,
    PsProtectedSignerCodeGen      = 2,
    PsProtectedSignerAntimalware  = 3,
    PsProtectedSignerLsa          = 4,
    PsProtectedSignerWindows      = 5,
    PsProtectedSignerWinTcb       = 6,
    PsProtectedSignerWinSystem    = 7,
    PsProtectedSignerApp          = 8,
    PsProtectedSignerMax          = 9
};

union PS_PROTECTION {
    struct {
        uint8_t Type   : 3; // PS_PROTECTED_TYPE
        uint8_t Audit  : 1; // 1 if audit mode active
        uint8_t Signer : 4; // PS_PROTECTED_SIGNER
    };
    uint8_t Level;
};

[[nodiscard]] inline std::string_view ProtectedTypeToString(PS_PROTECTED_TYPE type) noexcept {
    switch (type) {
        case PsProtectedTypeNone:           return "None";
        case PsProtectedTypeProtectedLight: return "ProtectedLight";
        case PsProtectedTypeProtected:      return "Protected";
        default:                            return "Unknown";
    }
}

[[nodiscard]] inline std::string_view ProtectedSignerToString(PS_PROTECTED_SIGNER signer) noexcept {
    switch (signer) {
        case PsProtectedSignerNone:         return "None";
        case PsProtectedSignerAuthenticode: return "Authenticode";
        case PsProtectedSignerCodeGen:      return "CodeGen";
        case PsProtectedSignerAntimalware:  return "Antimalware";
        case PsProtectedSignerLsa:          return "Lsa";
        case PsProtectedSignerWindows:      return "Windows";
        case PsProtectedSignerWinTcb:       return "WinTcb";
        case PsProtectedSignerWinSystem:    return "WinSystem";
        case PsProtectedSignerApp:          return "App";
        default:                            return "Unknown";
    }
}

// Dominance evaluation conforming to Windows NT SRM rules
[[nodiscard]] inline bool RtlTestProtectedAccess(PS_PROTECTION source, PS_PROTECTION target) noexcept {
    // If target is unprotected, all access is permitted
    if (target.Type == PsProtectedTypeNone) {
        return true;
    }
    // Unprotected source cannot access protected target
    if (source.Type == PsProtectedTypeNone) {
        return false;
    }
    // ProtectedLight cannot access full Protected
    if (source.Type == PsProtectedTypeProtectedLight && target.Type == PsProtectedTypeProtected) {
        return false;
    }

    // WinSystem dominates everything
    if (source.Signer == PsProtectedSignerWinSystem) return true;

    // WinTcb dominates WinTcb, Windows, Antimalware, Lsa, CodeGen, Authenticode, None
    if (source.Signer == PsProtectedSignerWinTcb) {
        return target.Signer <= PsProtectedSignerWinTcb;
    }

    // Windows dominates Windows, Antimalware, Authenticode, None
    if (source.Signer == PsProtectedSignerWindows) {
        return target.Signer == PsProtectedSignerWindows ||
               target.Signer == PsProtectedSignerAntimalware ||
               target.Signer == PsProtectedSignerAuthenticode ||
               target.Signer == PsProtectedSignerNone;
    }

    // Antimalware dominates Antimalware, Authenticode, None
    if (source.Signer == PsProtectedSignerAntimalware) {
        return target.Signer == PsProtectedSignerAntimalware ||
               target.Signer == PsProtectedSignerAuthenticode ||
               target.Signer == PsProtectedSignerNone;
    }

    // Lsa dominates Lsa, Authenticode, None
    if (source.Signer == PsProtectedSignerLsa) {
        return target.Signer == PsProtectedSignerLsa ||
               target.Signer == PsProtectedSignerAuthenticode ||
               target.Signer == PsProtectedSignerNone;
    }

    // CodeGen dominates CodeGen, Authenticode, None
    if (source.Signer == PsProtectedSignerCodeGen) {
        return target.Signer == PsProtectedSignerCodeGen ||
               target.Signer == PsProtectedSignerAuthenticode ||
               target.Signer == PsProtectedSignerNone;
    }

    // Authenticode dominates Authenticode, None
    if (source.Signer == PsProtectedSignerAuthenticode) {
        return target.Signer == PsProtectedSignerAuthenticode ||
               target.Signer == PsProtectedSignerNone;
    }

    // App dominates App, None
    if (source.Signer == PsProtectedSignerApp) {
        return target.Signer == PsProtectedSignerApp ||
               target.Signer == PsProtectedSignerNone;
    }

    return false;
}

// Sanitize access mask when accessing a protected process
[[nodiscard]] inline uint32_t FilterAccessMask(
    PS_PROTECTION source,
    PS_PROTECTION target,
    uint32_t desiredAccess
) noexcept {
    if (RtlTestProtectedAccess(source, target)) {
        return desiredAccess; // Full access allowed
    }
    // Strip dangerous rights
    uint32_t granted = desiredAccess & ~PROCESS_DANGEROUS_ACCESS_MASK;
    // Always preserve safe rights if requested
    granted |= (desiredAccess & (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE));
    return granted;
}

// ============================================================================
// 3. Early Launch Anti-Malware (ELAM) Data Structures
// ============================================================================

enum BDCB_CALLBACK_TYPE {
    BdCbStatusUpdate    = 0,
    BdCbInitializeImage = 1
};

enum BDCB_STATUS_UPDATE_TYPE {
    BdCbGlobalStatusUpdate = 0,
    BdCbDriverStatusUpdate = 1
};

enum BDCB_CLASSIFICATION : uint32_t {
    BDCB_CLASSIFICATION_KNOWN_GOOD          = 0,
    BDCB_CLASSIFICATION_UNKNOWN             = 1,
    BDCB_CLASSIFICATION_KNOWN_BAD           = 2,
    BDCB_CLASSIFICATION_KNOWN_BAD_CRITICAL  = 3
};

struct BDCB_IMAGE_INFORMATION {
    std::wstring ImagePath;
    std::wstring RegistryPath;
    std::wstring CertificatePublisher;
    std::wstring CertificateIssuer;
    std::string  ImageHash;
    std::string  CertificateThumbprint;
    BDCB_CLASSIFICATION Classification{BDCB_CLASSIFICATION_UNKNOWN};
};

using PBOOT_DRIVER_CALLBACK_FUNCTION = NTSTATUS(*)(
    void* CallbackContext,
    BDCB_CALLBACK_TYPE CallbackType,
    void* CallbackInformation
);

enum ElamPolicy : uint32_t {
    ELAM_POLICY_GOOD_ONLY                        = 0,
    ELAM_POLICY_GOOD_AND_UNKNOWN                 = 1, // Windows default
    ELAM_POLICY_GOOD_UNKNOWN_AND_BAD_CRITICAL    = 2,
    ELAM_POLICY_ALL                              = 3
};

[[nodiscard]] inline std::string_view ElamClassificationToString(BDCB_CLASSIFICATION cls) noexcept {
    switch (cls) {
        case BDCB_CLASSIFICATION_KNOWN_GOOD:         return "KnownGood";
        case BDCB_CLASSIFICATION_UNKNOWN:            return "Unknown";
        case BDCB_CLASSIFICATION_KNOWN_BAD:          return "KnownBad";
        case BDCB_CLASSIFICATION_KNOWN_BAD_CRITICAL: return "KnownBadCritical";
        default:                                     return "Invalid";
    }
}

[[nodiscard]] inline std::string_view ElamPolicyToString(ElamPolicy policy) noexcept {
    switch (policy) {
        case ELAM_POLICY_GOOD_ONLY:                     return "GoodOnly";
        case ELAM_POLICY_GOOD_AND_UNKNOWN:              return "GoodAndUnknown (Default)";
        case ELAM_POLICY_GOOD_UNKNOWN_AND_BAD_CRITICAL: return "GoodUnknownAndBadCritical";
        case ELAM_POLICY_ALL:                           return "All (Audit)";
        default:                                        return "Unknown";
    }
}

// ============================================================================
// 4. Protected Process Manager (PPL Subsystem)
// ============================================================================

struct ProcessProtectionRecord {
    uint32_t pid{0};
    std::wstring processName;
    PS_PROTECTION protection{};
    uint64_t protectTimestamp{0};
};

struct PplAuditEvent {
    uint64_t timestamp{0};
    uint32_t callerPid{0};
    uint32_t targetPid{0};
    std::wstring targetName;
    uint32_t requestedAccess{0};
    uint32_t grantedAccess{0};
    std::string action; // "Blocked OpenProcess", "Blocked Terminate"
    std::string reason;
};

class ProtectedProcessManager {
public:
    static ProtectedProcessManager& get() {
        static ProtectedProcessManager instance;
        return instance;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_processes.clear();
        m_auditLog.clear();
        seedDefaultProtectedProcesses();
    }

    bool setProcessProtection(
        uint32_t pid,
        PS_PROTECTION protection,
        const std::wstring& processName = L""
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_processes.find(pid);
        if (it != m_processes.end()) {
            it->second.protection = protection;
            if (!processName.empty()) {
                it->second.processName = processName;
            }
        } else {
            ProcessProtectionRecord rec;
            rec.pid = pid;
            rec.processName = processName.empty() ? (L"PID_" + std::to_wstring(pid)) : processName;
            rec.protection = protection;
            rec.protectTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            m_processes[pid] = rec;
        }
        return true;
    }

    bool getProcessProtection(uint32_t pid, PS_PROTECTION& outProtection) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_processes.find(pid);
        if (it != m_processes.end()) {
            outProtection = it->second.protection;
            return true;
        }
        outProtection.Level = 0; // None
        return false;
    }

    bool isProtected(uint32_t pid) const {
        PS_PROTECTION prot{};
        if (getProcessProtection(pid, prot)) {
            return prot.Type != PsProtectedTypeNone;
        }
        return false;
    }

    // Intercept and sanitize access mask for NtOpenProcess
    NTSTATUS filterAccess(
        uint32_t callerPid,
        uint32_t targetPid,
        uint32_t desiredAccess,
        uint32_t& grantedAccess
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);

        PS_PROTECTION callerProt{};
        auto itCaller = m_processes.find(callerPid);
        if (itCaller != m_processes.end()) {
            callerProt = itCaller->second.protection;
        }

        PS_PROTECTION targetProt{};
        std::wstring targetName = L"Unknown";
        auto itTarget = m_processes.find(targetPid);
        if (itTarget != m_processes.end()) {
            targetProt = itTarget->second.protection;
            targetName = itTarget->second.processName;
        }

        grantedAccess = FilterAccessMask(callerProt, targetProt, desiredAccess);

        // If target is protected and dangerous rights were stripped
        if (targetProt.Type != PsProtectedTypeNone && (desiredAccess & PROCESS_DANGEROUS_ACCESS_MASK) != 0) {
            if ((grantedAccess & PROCESS_DANGEROUS_ACCESS_MASK) == 0 && (desiredAccess & ~PROCESS_DANGEROUS_ACCESS_MASK) == 0) {
                // Caller ONLY requested dangerous rights and all were stripped
                PplAuditEvent ev;
                ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                ev.callerPid = callerPid;
                ev.targetPid = targetPid;
                ev.targetName = targetName;
                ev.requestedAccess = desiredAccess;
                ev.grantedAccess = grantedAccess;
                ev.action = "Blocked OpenProcess";
                ev.reason = "Caller protection does not dominate target PPL";
                m_auditLog.push_back(ev);

                return STATUS_ACCESS_DENIED;
            }
        }

        return STATUS_SUCCESS;
    }

    // Intercept NtTerminateProcess attempt
    NTSTATUS attemptTerminate(
        uint32_t callerPid,
        uint32_t targetPid,
        bool callerHasDebugPrivilege = false
    ) {
        (void)callerHasDebugPrivilege; // In PPL, SeDebugPrivilege is ignored by design
        std::lock_guard<std::mutex> lock(m_mutex);

        PS_PROTECTION callerProt{};
        auto itCaller = m_processes.find(callerPid);
        if (itCaller != m_processes.end()) {
            callerProt = itCaller->second.protection;
        }

        PS_PROTECTION targetProt{};
        std::wstring targetName = L"Unknown";
        auto itTarget = m_processes.find(targetPid);
        if (itTarget != m_processes.end()) {
            targetProt = itTarget->second.protection;
            targetName = itTarget->second.processName;
        }

        // If target is not protected, termination is permitted
        if (targetProt.Type == PsProtectedTypeNone) {
            return STATUS_SUCCESS;
        }

        // Test dominance
        if (RtlTestProtectedAccess(callerProt, targetProt)) {
            return STATUS_SUCCESS;
        }

        // Access denied: target PPL dominates or caller is unprotected
        PplAuditEvent ev;
        ev.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        ev.callerPid = callerPid;
        ev.targetPid = targetPid;
        ev.targetName = targetName;
        ev.requestedAccess = PROCESS_TERMINATE;
        ev.grantedAccess = 0;
        ev.action = "Blocked Terminate";
        ev.reason = "Target is protected by PPL (" +
                    std::string(ProtectedTypeToString(static_cast<PS_PROTECTED_TYPE>(targetProt.Type))) + "-" +
                    std::string(ProtectedSignerToString(static_cast<PS_PROTECTED_SIGNER>(targetProt.Signer))) + ")";
        m_auditLog.push_back(ev);

        return STATUS_ACCESS_DENIED;
    }

    [[nodiscard]] std::vector<ProcessProtectionRecord> listProtectedProcesses() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<ProcessProtectionRecord> result;
        result.reserve(m_processes.size());
        for (const auto& [pid, rec] : m_processes) {
            result.push_back(rec);
        }
        return result;
    }

    [[nodiscard]] std::vector<PplAuditEvent> getAuditLog() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_auditLog;
    }

    void clearAuditLog() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_auditLog.clear();
    }

private:
    ProtectedProcessManager() {
        seedDefaultProtectedProcesses();
    }

    void seedDefaultProtectedProcesses() {
        // Pre-seed core Windows NT protected processes
        // PID 4: System (Protected, WinSystem)
        PS_PROTECTION sysProt{};
        sysProt.Type = PsProtectedTypeProtected;
        sysProt.Signer = PsProtectedSignerWinSystem;
        m_processes[4] = {4, L"System", sysProt, 1};

        // PID 492: lsass.exe (ProtectedLight, Lsa)
        PS_PROTECTION lsaProt{};
        lsaProt.Type = PsProtectedTypeProtectedLight;
        lsaProt.Signer = PsProtectedSignerLsa;
        m_processes[492] = {492, L"lsass.exe", lsaProt, 1};

        // PID 500: LsaIso.exe (Protected, Lsa)
        PS_PROTECTION isoProt{};
        isoProt.Type = PsProtectedTypeProtected;
        isoProt.Signer = PsProtectedSignerLsa;
        m_processes[500] = {500, L"LsaIso.exe", isoProt, 1};

        // PID 600: csrss.exe (Protected, WinTcb)
        PS_PROTECTION csrssProt{};
        csrssProt.Type = PsProtectedTypeProtected;
        csrssProt.Signer = PsProtectedSignerWinTcb;
        m_processes[600] = {600, L"csrss.exe", csrssProt, 1};

        // PID 700: services.exe (ProtectedLight, WinTcb)
        PS_PROTECTION svcProt{};
        svcProt.Type = PsProtectedTypeProtectedLight;
        svcProt.Signer = PsProtectedSignerWinTcb;
        m_processes[700] = {700, L"services.exe", svcProt, 1};

        // PID 900: MsMpEng.exe (ProtectedLight, Antimalware)
        PS_PROTECTION mpProt{};
        mpProt.Type = PsProtectedTypeProtectedLight;
        mpProt.Signer = PsProtectedSignerAntimalware;
        m_processes[900] = {900, L"MsMpEng.exe", mpProt, 1};

        // PID 904: NisSrv.exe (ProtectedLight, Antimalware)
        PS_PROTECTION nisProt{};
        nisProt.Type = PsProtectedTypeProtectedLight;
        nisProt.Signer = PsProtectedSignerAntimalware;
        m_processes[904] = {904, L"NisSrv.exe", nisProt, 1};
    }

    mutable std::mutex m_mutex;
    std::unordered_map<uint32_t, ProcessProtectionRecord> m_processes;
    std::vector<PplAuditEvent> m_auditLog;
};

// ============================================================================
// 5. Early Launch Anti-Malware (ELAM Subsystem)
// ============================================================================

struct ElamCallbackRecord {
    uint64_t handleId{0};
    PBOOT_DRIVER_CALLBACK_FUNCTION callbackFn{nullptr};
    void* callbackContext{nullptr};
};

struct ElamBlockedDriverRecord {
    uint64_t timestamp{0};
    std::wstring driverPath;
    std::string sha256;
    BDCB_CLASSIFICATION classification;
    std::string reason;
};

class EarlyLaunchAntiMalwareManager {
public:
    static EarlyLaunchAntiMalwareManager& get() {
        static EarlyLaunchAntiMalwareManager instance;
        return instance;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_callbacks.clear();
        m_driverClassifications.clear();
        m_blockedDrivers.clear();
        m_policy = ELAM_POLICY_GOOD_AND_UNKNOWN;
        m_nextHandle = 1;
        seedDefaultDrivers();
    }

    NTSTATUS registerCallback(
        PBOOT_DRIVER_CALLBACK_FUNCTION callbackFn,
        void* callbackContext,
        void** outHandle
    ) {
        if (!callbackFn || !outHandle) return STATUS_INVALID_PARAMETER;

        std::lock_guard<std::mutex> lock(m_mutex);
        uint64_t handle = m_nextHandle++;
        m_callbacks[handle] = {handle, callbackFn, callbackContext};
        *outHandle = reinterpret_cast<void*>(static_cast<uintptr_t>(handle));
        return STATUS_SUCCESS;
    }

    NTSTATUS unregisterCallback(void* callbackHandle) {
        if (!callbackHandle) return STATUS_INVALID_PARAMETER;

        std::lock_guard<std::mutex> lock(m_mutex);
        uint64_t handle = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(callbackHandle));
        auto it = m_callbacks.find(handle);
        if (it == m_callbacks.end()) {
            return STATUS_NOT_FOUND;
        }
        m_callbacks.erase(it);
        return STATUS_SUCCESS;
    }

    void setPolicy(ElamPolicy policy) noexcept {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_policy = policy;
    }

    [[nodiscard]] ElamPolicy getPolicy() const noexcept {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_policy;
    }

    void classifyDriver(const std::wstring& driverPath, BDCB_CLASSIFICATION classification) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_driverClassifications[normalizePath(driverPath)] = classification;
    }

    [[nodiscard]] BDCB_CLASSIFICATION getDriverClassification(const std::wstring& driverPath) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_driverClassifications.find(normalizePath(driverPath));
        if (it != m_driverClassifications.end()) {
            return it->second;
        }
        return BDCB_CLASSIFICATION_UNKNOWN;
    }

    // Evaluate driver at early boot time against registered ELAM callbacks and active policy
    NTSTATUS evaluateBootDriver(
        const std::wstring& driverPath,
        const std::string& sha256 = ""
    ) {
        std::lock_guard<std::mutex> lock(m_mutex);

        std::wstring norm = normalizePath(driverPath);
        BDCB_CLASSIFICATION classification = BDCB_CLASSIFICATION_UNKNOWN;

        auto it = m_driverClassifications.find(norm);
        if (it != m_driverClassifications.end()) {
            classification = it->second;
        }

        // Dispatch BDCB_IMAGE_INFORMATION to registered callbacks
        BDCB_IMAGE_INFORMATION imgInfo;
        imgInfo.ImagePath = driverPath;
        imgInfo.RegistryPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + getBaseName(driverPath);
        imgInfo.ImageHash = sha256;
        imgInfo.Classification = classification;

        for (const auto& [id, cb] : m_callbacks) {
            if (cb.callbackFn) {
                cb.callbackFn(cb.callbackContext, BdCbInitializeImage, &imgInfo);
                // The callback can update the classification
                classification = imgInfo.Classification;
            }
        }

        // Check against ELAM policy
        bool allowed = false;
        switch (m_policy) {
            case ELAM_POLICY_GOOD_ONLY:
                allowed = (classification == BDCB_CLASSIFICATION_KNOWN_GOOD);
                break;
            case ELAM_POLICY_GOOD_AND_UNKNOWN:
                allowed = (classification == BDCB_CLASSIFICATION_KNOWN_GOOD ||
                           classification == BDCB_CLASSIFICATION_UNKNOWN);
                break;
            case ELAM_POLICY_GOOD_UNKNOWN_AND_BAD_CRITICAL:
                allowed = (classification == BDCB_CLASSIFICATION_KNOWN_GOOD ||
                           classification == BDCB_CLASSIFICATION_UNKNOWN ||
                           classification == BDCB_CLASSIFICATION_KNOWN_BAD_CRITICAL);
                break;
            case ELAM_POLICY_ALL:
                allowed = true;
                break;
        }

        if (!allowed) {
            ElamBlockedDriverRecord rec;
            rec.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            rec.driverPath = driverPath;
            rec.sha256 = sha256;
            rec.classification = classification;
            rec.reason = "Driver classification (" + std::string(ElamClassificationToString(classification)) +
                         ") rejected by ELAM policy (" + std::string(ElamPolicyToString(m_policy)) + ")";
            m_blockedDrivers.push_back(rec);

            return STATUS_ACCESS_DENIED;
        }

        return STATUS_SUCCESS;
    }

    [[nodiscard]] std::vector<ElamBlockedDriverRecord> getBlockedDrivers() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_blockedDrivers;
    }

    [[nodiscard]] size_t getCallbackCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_callbacks.size();
    }

    [[nodiscard]] std::unordered_map<std::wstring, BDCB_CLASSIFICATION> getAllClassifications() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_driverClassifications;
    }

private:
    EarlyLaunchAntiMalwareManager() {
        seedDefaultDrivers();
    }

    static std::wstring normalizePath(std::wstring_view path) {
        std::wstring s(path);
        for (auto& c : s) {
            if (c == L'/') c = L'\\';
            c = static_cast<wchar_t>(std::towlower(c));
        }
        return s;
    }

    static std::wstring getBaseName(std::wstring_view path) {
        size_t idx = path.find_last_of(L"\\/");
        if (idx == std::wstring_view::npos) return std::wstring(path);
        return std::wstring(path.substr(idx + 1));
    }

    void seedDefaultDrivers() {
        // Pre-seed core trusted Windows drivers
        m_driverClassifications[normalizePath(L"disk.sys")] = BDCB_CLASSIFICATION_KNOWN_GOOD;
        m_driverClassifications[normalizePath(L"ntfs.sys")] = BDCB_CLASSIFICATION_KNOWN_GOOD;
        m_driverClassifications[normalizePath(L"tcpip.sys")] = BDCB_CLASSIFICATION_KNOWN_GOOD;
        m_driverClassifications[normalizePath(L"fltmgr.sys")] = BDCB_CLASSIFICATION_KNOWN_GOOD;
        m_driverClassifications[normalizePath(L"wdfilter.sys")] = BDCB_CLASSIFICATION_KNOWN_GOOD;
        m_driverClassifications[normalizePath(L"elam.sys")] = BDCB_CLASSIFICATION_KNOWN_GOOD;

        // Pre-seed known malicious rootkits
        m_driverClassifications[normalizePath(L"rootkit.sys")] = BDCB_CLASSIFICATION_KNOWN_BAD;
        m_driverClassifications[normalizePath(L"mimikatz_driver.sys")] = BDCB_CLASSIFICATION_KNOWN_BAD;
        m_driverClassifications[normalizePath(L"gdrv.sys")] = BDCB_CLASSIFICATION_KNOWN_BAD_CRITICAL;
    }

    mutable std::mutex m_mutex;
    uint64_t m_nextHandle{1};
    ElamPolicy m_policy{ELAM_POLICY_GOOD_AND_UNKNOWN};
    std::unordered_map<uint64_t, ElamCallbackRecord> m_callbacks;
    std::unordered_map<std::wstring, BDCB_CLASSIFICATION> m_driverClassifications;
    std::vector<ElamBlockedDriverRecord> m_blockedDrivers;
};

// ============================================================================
// 6. Clean-Room Win32 C ABI Exports (ntoskrnl.exe & kernel32.dll)
// ============================================================================

inline uint8_t WINAPI PsIsProtectedProcess(uint32_t ProcessId) noexcept {
    return ProtectedProcessManager::get().isProtected(ProcessId) ? 1 : 0;
}

inline NTSTATUS WINAPI PsGetProcessProtection(
    uint32_t ProcessId,
    PS_PROTECTION* Protection
) noexcept {
    if (!Protection) return STATUS_INVALID_PARAMETER;
    if (ProtectedProcessManager::get().getProcessProtection(ProcessId, *Protection)) {
        return STATUS_SUCCESS;
    }
    Protection->Level = 0;
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI PsSetProcessProtection(
    uint32_t ProcessId,
    PS_PROTECTION Protection
) noexcept {
    ProtectedProcessManager::get().setProcessProtection(ProcessId, Protection);
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI PsFilterAccessMask(
    uint32_t CallerPid,
    uint32_t TargetPid,
    uint32_t DesiredAccess,
    uint32_t* GrantedAccess
) noexcept {
    if (!GrantedAccess) return STATUS_INVALID_PARAMETER;
    return ProtectedProcessManager::get().filterAccess(CallerPid, TargetPid, DesiredAccess, *GrantedAccess);
}

inline NTSTATUS WINAPI PsTerminateProcessSecure(
    uint32_t CallerPid,
    uint32_t TargetPid,
    NTSTATUS ExitStatus
) noexcept {
    (void)ExitStatus;
    return ProtectedProcessManager::get().attemptTerminate(CallerPid, TargetPid, false);
}

inline NTSTATUS WINAPI IoRegisterBootDriverCallback(
    PBOOT_DRIVER_CALLBACK_FUNCTION CallbackFunction,
    void* CallbackContext,
    void** CallbackHandle
) noexcept {
    return EarlyLaunchAntiMalwareManager::get().registerCallback(CallbackFunction, CallbackContext, CallbackHandle);
}

inline NTSTATUS WINAPI IoUnRegisterBootDriverCallback(void* CallbackHandle) noexcept {
    return EarlyLaunchAntiMalwareManager::get().unregisterCallback(CallbackHandle);
}

inline NTSTATUS WINAPI ElamGetDriverClassification(
    const wchar_t* DriverPath,
    uint32_t* Classification
) noexcept {
    if (!DriverPath || !Classification) return STATUS_INVALID_PARAMETER;
    *Classification = static_cast<uint32_t>(EarlyLaunchAntiMalwareManager::get().getDriverClassification(DriverPath));
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI ElamSetDriverClassification(
    const wchar_t* DriverPath,
    uint32_t Classification
) noexcept {
    if (!DriverPath) return STATUS_INVALID_PARAMETER;
    EarlyLaunchAntiMalwareManager::get().classifyDriver(DriverPath, static_cast<BDCB_CLASSIFICATION>(Classification));
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI ElamEvaluateBootDriver(
    const wchar_t* DriverPath,
    const char* Sha256Hash
) noexcept {
    if (!DriverPath) return STATUS_INVALID_PARAMETER;
    std::string hash = Sha256Hash ? Sha256Hash : "";
    return EarlyLaunchAntiMalwareManager::get().evaluateBootDriver(DriverPath, hash);
}

// ============================================================================
// 7. DynamicLoader & VersionDatabase Registration
// ============================================================================

inline void InitializePplSubsystemExports() {
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        auto& loader = ldr::DynamicLoader::get();

        // Register exports in ntoskrnl.exe
        loader.registerExport("ntoskrnl.exe", "PsIsProtectedProcess", reinterpret_cast<void*>(&PsIsProtectedProcess));
        loader.registerExport("ntoskrnl.exe", "PsGetProcessProtection", reinterpret_cast<void*>(&PsGetProcessProtection));
        loader.registerExport("ntoskrnl.exe", "PsSetProcessProtection", reinterpret_cast<void*>(&PsSetProcessProtection));
        loader.registerExport("ntoskrnl.exe", "PsFilterAccessMask", reinterpret_cast<void*>(&PsFilterAccessMask));
        loader.registerExport("ntoskrnl.exe", "PsTerminateProcessSecure", reinterpret_cast<void*>(&PsTerminateProcessSecure));
        loader.registerExport("ntoskrnl.exe", "IoRegisterBootDriverCallback", reinterpret_cast<void*>(&IoRegisterBootDriverCallback));
        loader.registerExport("ntoskrnl.exe", "IoUnRegisterBootDriverCallback", reinterpret_cast<void*>(&IoUnRegisterBootDriverCallback));

        // Register exports in kernel32.dll
        loader.registerExport("kernel32.dll", "PsIsProtectedProcess", reinterpret_cast<void*>(&PsIsProtectedProcess));
        loader.registerExport("kernel32.dll", "ElamGetDriverClassification", reinterpret_cast<void*>(&ElamGetDriverClassification));
        loader.registerExport("kernel32.dll", "ElamSetDriverClassification", reinterpret_cast<void*>(&ElamSetDriverClassification));
        loader.registerExport("kernel32.dll", "ElamEvaluateBootDriver", reinterpret_cast<void*>(&ElamEvaluateBootDriver));

        // VersionDatabase registrations
        auto& vdb = version::VersionDatabase::Instance();
        vdb.RegisterModule(
            "ntoskrnl.exe",
            "10.0.26100.1",
            "MicaNT Operating System Kernel",
            "Project MICA"
        );

        vdb.RegisterModule(
            "elam.sys",
            "10.0.26100.1",
            "MicaNT Early Launch Anti-Malware Driver",
            "Project MICA"
        );
    });
}

} // namespace micant::ppl
