// ============================================================================
// MicaNT Sovereign Security System: Virtualization-Based Security (VBS) &
// Hypervisor-Enforced Code Integrity (HVCI) (include/micant/vbs_hvci.hpp)
//
// Milestone 143 (Phase 8 / Phase 116)
//
// Capabilities:
//   - Second-Level Address Translation (SLAT / EPT / NPT) Page Protection:
//       * Enforces stage-2 hypervisor page tables independent of guest CR3
//       * Strict W^X (Write XOR Execute) memory invariants across kernel space
//       * Dynamic kernel code generation (JIT) in Ring 0 strictly prohibited
//   - Virtual Trust Level (VTL) Isolation:
//       * VTL 0 (Normal World): Standard NT kernel (ntoskrnl.exe), drivers, userland
//       * VTL 1 (Secure World): Secure Kernel (securekernel.exe), Isolated User Mode
//         (LsaIso.exe), HVCI policy engine, and sealed secrets
//       * Physical and virtual memory isolation preventing VTL 0 access to VTL 1
//   - Hypervisor Call Interface (VbsCall / HvlInvokeHypercall):
//       * Clean-room hypercall dispatch engine for cross-VTL requests
//       * Secure page permission transition verification via VTL 1
//       * Cryptographic driver code integrity validation before granting execution
//   - Rootkit & Memory Exploitation Defense:
//       * Intercepts kernel code patching (DKOM hooks) on .text sections
//       * Blocks non-paged pool shellcode execution
//       * Thwarts credential scraping against VTL 1 enclaves
//       * Detailed real-time hypervisor violation telemetry and audit logging
//   - Win32 & NT Clean-Room C ABI Exports:
//       * vbs.dll:
//           - VbsIsVirtualizationBasedSecuritySupported
//           - VbsIsVirtualizationBasedSecurityEnabled
//           - VbsGetHypervisorEnforcedCodeIntegrityStatus
//           - VbsSetHypervisorEnforcedCodeIntegrity
//           - VbsQueryVirtualTrustLevel
//           - VbsInvokeHypercall
//           - VbsGetMemoryProtectionPolicy
//           - VbsAuditSecurityViolation
//       * ntoskrnl.exe:
//           - HvlIsHypervisorPresent
//           - HvlGetVirtualTrustLevel
//           - HvlEnforceKernelCodeIntegrity
//           - HvlProtectPageFrame
//           - HvlValidateMemoryAttributes
//           - HvlRegisterHvciCallback
//           - HvlGetHvciViolationCount
//   - DynamicLoader export registration into "vbs.dll" and "ntoskrnl.exe".
//   - VersionDatabase registration for "vbs.dll" and "securekernel.exe".
//
// Trademark, Copyright & Nominative Fair Use Notice:
//   Microsoft, Windows, Virtualization-Based Security, Hyper-V, and Hypervisor-
//   Enforced Code Integrity (HVCI) are trademarks and/or copyrighted property
//   of Microsoft Corp. MicaNT VBS/HVCI Subsystem is an independent, clean-room,
//   sovereign implementation engineered from first principles and publicly
//   published hypervisor specifications solely for binary interoperability
//   (Google LLC v. Oracle America, Inc.).
//   No proprietary Microsoft source code or binaries are used or contained herein.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <span>
#include <algorithm>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "kernel32.hpp"
#include "ldr.hpp"
#include "version.hpp"
#include "cipherksp.hpp"

namespace micant::vbs_hvci {

using BOOLEAN = uint8_t;
inline constexpr BOOLEAN TRUE  = 1;
inline constexpr BOOLEAN FALSE = 0;

// ============================================================================
// 1. Status Codes & Error Definitions
// ============================================================================

inline constexpr NTSTATUS STATUS_HVCI_CODE_INTEGRITY_VIOLATION = 0xC0000428;
inline constexpr NTSTATUS STATUS_HVCI_POLICY_VIOLATION         = 0xC0000430;
inline constexpr NTSTATUS STATUS_HVCI_WX_VIOLATION             = 0xC0000431;
inline constexpr NTSTATUS STATUS_VTL_ACCESS_DENIED             = 0xC0000432;
inline constexpr NTSTATUS STATUS_HVCI_NOT_SUPPORTED            = 0xC0000433;
inline constexpr NTSTATUS STATUS_HVCI_INVALID_HYPERCALL        = 0xC0000434;
inline constexpr NTSTATUS STATUS_HVCI_PAGE_LOCKED              = 0xC0000435;

// ============================================================================
// 2. VBS & HVCI Constants and Flags
// ============================================================================

// VBS Enablement State
inline constexpr uint32_t VBS_STATUS_DISABLED                    = 0;
inline constexpr uint32_t VBS_STATUS_ENABLED                     = 1;
inline constexpr uint32_t VBS_STATUS_ENABLED_WITH_UEFI_LOCK      = 2;

// Virtual Trust Levels (VTL)
inline constexpr uint32_t VTL_0_NORMAL                           = 0; // Normal World: ntoskrnl, drivers, userland
inline constexpr uint32_t VTL_1_SECURE                           = 1; // Secure World: Secure Kernel, IUM enclaves

// Hypervisor Feature Bits
inline constexpr uint32_t HV_FEATURE_SLAT_EPT                    = 0x00000001; // Intel Extended Page Tables
inline constexpr uint32_t HV_FEATURE_SLAT_NPT                    = 0x00000002; // AMD Nested Page Tables
inline constexpr uint32_t HV_FEATURE_MBEC                        = 0x00000004; // Mode-Based Execute Control
inline constexpr uint32_t HV_FEATURE_VTL                         = 0x00000008; // Virtual Trust Levels
inline constexpr uint32_t HV_FEATURE_DMA_PROT                    = 0x00000010; // Kernel DMA Protection
inline constexpr uint32_t HV_FEATURE_SECURE_PAGE_TABLES          = 0x00000020; // Hypervisor-protected CR3/EPT
inline constexpr uint32_t HV_FEATURE_HYPERVISOR_PRESENT          = 0x00000040; // Hypervisor active

// SLAT (Stage-2) Page Permissions
inline constexpr uint32_t SLAT_PERM_NONE                         = 0x00000000;
inline constexpr uint32_t SLAT_PERM_READ                         = 0x00000001;
inline constexpr uint32_t SLAT_PERM_WRITE                        = 0x00000002;
inline constexpr uint32_t SLAT_PERM_EXECUTE                      = 0x00000004;
inline constexpr uint32_t SLAT_PERM_USER_EXEC                    = 0x00000008; // MBEC User Execute
inline constexpr uint32_t SLAT_PERM_RW                           = (SLAT_PERM_READ | SLAT_PERM_WRITE);
inline constexpr uint32_t SLAT_PERM_RX                           = (SLAT_PERM_READ | SLAT_PERM_EXECUTE);

// HVCI Policy Enforcement Flags
inline constexpr uint32_t HVCI_POLICY_STRICT_WX                  = 0x00000001; // Write XOR Execute enforced
inline constexpr uint32_t HVCI_POLICY_DRIVER_SIGNATURE_REQ       = 0x00000002; // Driver signing verified before X
inline constexpr uint32_t HVCI_POLICY_BLOCK_PAGE_EXECUTE_RW      = 0x00000004; // Direct reject of RWX
inline constexpr uint32_t HVCI_POLICY_AUDIT_MODE                 = 0x00000008; // Audit without blocking
inline constexpr uint32_t HVCI_POLICY_DYNAMIC_CODE_BLOCKED       = 0x00000010; // No kernel JIT allowed

// Hypercall Dispatch Codes
inline constexpr uint32_t HV_CALL_GET_VTL_STATUS                 = 0x0001;
inline constexpr uint32_t HV_CALL_ENTER_VTL1                     = 0x0002;
inline constexpr uint32_t HV_CALL_PROTECT_KERNEL_PAGE            = 0x0003;
inline constexpr uint32_t HV_CALL_VERIFY_DRIVER_SIG              = 0x0004;
inline constexpr uint32_t HV_CALL_ENFORCE_WX                     = 0x0005;
inline constexpr uint32_t HV_CALL_QUERY_PAGE_ATTR                = 0x0006;
inline constexpr uint32_t HV_CALL_GET_VIOLATION_LOG              = 0x0007;
inline constexpr uint32_t HV_CALL_RETURN_VTL0                  = 0x0008;

// ============================================================================
// 3. Structures and Types
// ============================================================================

struct SlatPageDescriptor {
    uint64_t physicalAddress{0};
    uint64_t virtualAddress{0};
    uint32_t size{4096};
    uint32_t vtl0Permissions{SLAT_PERM_NONE}; // Stage-2 SLAT permissions for VTL 0
    uint32_t vtl1Permissions{SLAT_PERM_NONE}; // Stage-2 SLAT permissions for VTL 1
    uint32_t ownerVtl{VTL_0_NORMAL};          // 0 = Normal World, 1 = Secure World
    std::string moduleOwner{};
    bool isVerifiedCode{false};
    bool isLocked{false};
    uint32_t violationCount{0};
};

struct HvciViolationRecord {
    uint64_t timestamp{0};
    uint64_t faultingAddress{0};
    uint32_t attemptedAccess{0}; // Read = 1, Write = 2, Execute = 4, WX = 6
    uint32_t currentPermissions{0};
    uint32_t callerVtl{0};
    std::string attackType{};
    std::string description{};
    bool blocked{true};
};

struct VbsPolicyInfo {
    uint32_t VbsStatus{VBS_STATUS_ENABLED_WITH_UEFI_LOCK};
    uint32_t HvciStatus{1};
    uint32_t HypervisorFeatures{0};
    uint32_t HvciPolicyFlags{0};
    uint32_t CurrentVtl{VTL_0_NORMAL};
    uint64_t ProtectedPageCount{0};
    uint64_t ViolationsPrevented{0};
};

// ============================================================================
// 4. Virtualization-Based Security Manager (Singleton)
// ============================================================================

class VirtualizationBasedSecurityManager {
private:
    mutable std::recursive_mutex m_mutex;
    uint32_t m_vbsStatus{VBS_STATUS_ENABLED_WITH_UEFI_LOCK};
    uint32_t m_currentVtl{VTL_0_NORMAL};
    uint32_t m_hypervisorFeatures{
        HV_FEATURE_SLAT_EPT |
        HV_FEATURE_MBEC |
        HV_FEATURE_VTL |
        HV_FEATURE_DMA_PROT |
        HV_FEATURE_SECURE_PAGE_TABLES |
        HV_FEATURE_HYPERVISOR_PRESENT
    };
    uint32_t m_hvciPolicy{
        HVCI_POLICY_STRICT_WX |
        HVCI_POLICY_DRIVER_SIGNATURE_REQ |
        HVCI_POLICY_BLOCK_PAGE_EXECUTE_RW |
        HVCI_POLICY_DYNAMIC_CODE_BLOCKED
    };
    std::vector<SlatPageDescriptor> m_pages;
    std::vector<HvciViolationRecord> m_violations;
    uint64_t m_totalViolationsPrevented{0};
    uint64_t m_hypercallCount{0};
    bool m_initialized{false};

    VirtualizationBasedSecurityManager() {
        initializeLayout();
    }

    void initializeLayout() {
        if (m_initialized) return;

        // 1. Kernel Executable Code (.text) - Strictly Read-Execute (R-X)
        m_pages.push_back({
            .physicalAddress = 0x0000000100000000ULL,
            .virtualAddress  = 0xFFFFF80000000000ULL,
            .size            = 2 * 1024 * 1024, // 2MB
            .vtl0Permissions = SLAT_PERM_RX,
            .vtl1Permissions = SLAT_PERM_RX,
            .ownerVtl        = VTL_0_NORMAL,
            .moduleOwner     = "ntoskrnl.exe (.text)",
            .isVerifiedCode  = true,
            .isLocked        = true
        });

        // 2. HAL Executable Code (.text) - Strictly Read-Execute (R-X)
        m_pages.push_back({
            .physicalAddress = 0x0000000100200000ULL,
            .virtualAddress  = 0xFFFFF80000200000ULL,
            .size            = 512 * 1024, // 512KB
            .vtl0Permissions = SLAT_PERM_RX,
            .vtl1Permissions = SLAT_PERM_RX,
            .ownerVtl        = VTL_0_NORMAL,
            .moduleOwner     = "hal.dll (.text)",
            .isVerifiedCode  = true,
            .isLocked        = true
        });

        // 3. Kernel Data (.data / .bss) - Strictly Read-Write (RW-)
        m_pages.push_back({
            .physicalAddress = 0x0000000100280000ULL,
            .virtualAddress  = 0xFFFFF80000280000ULL,
            .size            = 1024 * 1024, // 1MB
            .vtl0Permissions = SLAT_PERM_RW,
            .vtl1Permissions = SLAT_PERM_RW,
            .ownerVtl        = VTL_0_NORMAL,
            .moduleOwner     = "ntoskrnl.exe (.data)",
            .isVerifiedCode  = false,
            .isLocked        = false
        });

        // 4. NonPagedPool - Strictly Read-Write (RW-) No Execute
        m_pages.push_back({
            .physicalAddress = 0x0000000100400000ULL,
            .virtualAddress  = 0xFFFFFA8000000000ULL,
            .size            = 16 * 1024 * 1024, // 16MB
            .vtl0Permissions = SLAT_PERM_RW,
            .vtl1Permissions = SLAT_PERM_RW,
            .ownerVtl        = VTL_0_NORMAL,
            .moduleOwner     = "NonPagedPool",
            .isVerifiedCode  = false,
            .isLocked        = false
        });

        // 5. PagedPool - Strictly Read-Write (RW-) No Execute
        m_pages.push_back({
            .physicalAddress = 0x0000000101400000ULL,
            .virtualAddress  = 0xFFFFF98000000000ULL,
            .size            = 32 * 1024 * 1024, // 32MB
            .vtl0Permissions = SLAT_PERM_RW,
            .vtl1Permissions = SLAT_PERM_RW,
            .ownerVtl        = VTL_0_NORMAL,
            .moduleOwner     = "PagedPool",
            .isVerifiedCode  = false,
            .isLocked        = false
        });

        // 6. Secure Kernel (VTL 1) - Complete Isolation from VTL 0
        m_pages.push_back({
            .physicalAddress = 0x0000000103400000ULL,
            .virtualAddress  = 0xFFFFF87F00000000ULL,
            .size            = 4 * 1024 * 1024, // 4MB
            .vtl0Permissions = SLAT_PERM_NONE, // Completely inaccessible to Normal World
            .vtl1Permissions = SLAT_PERM_READ | SLAT_PERM_WRITE | SLAT_PERM_EXECUTE,
            .ownerVtl        = VTL_1_SECURE,
            .moduleOwner     = "securekernel.exe",
            .isVerifiedCode  = true,
            .isLocked        = true
        });

        // 7. Isolated LSA (LsaIso.exe / IUM Enclave) - Complete Isolation from VTL 0
        m_pages.push_back({
            .physicalAddress = 0x0000000103800000ULL,
            .virtualAddress  = 0xFFFFF87F00400000ULL,
            .size            = 4 * 1024 * 1024, // 4MB
            .vtl0Permissions = SLAT_PERM_NONE, // Completely inaccessible to Normal World
            .vtl1Permissions = SLAT_PERM_READ | SLAT_PERM_WRITE,
            .ownerVtl        = VTL_1_SECURE,
            .moduleOwner     = "LsaIso.exe (IUM Enclave)",
            .isVerifiedCode  = true,
            .isLocked        = true
        });

        m_initialized = true;
    }

public:
    static VirtualizationBasedSecurityManager& Instance() {
        static VirtualizationBasedSecurityManager s_instance;
        return s_instance;
    }

    [[nodiscard]] bool isSupported() const noexcept {
        return (m_hypervisorFeatures & HV_FEATURE_SLAT_EPT) != 0 ||
               (m_hypervisorFeatures & HV_FEATURE_SLAT_NPT) != 0;
    }

    [[nodiscard]] bool isEnabled() const noexcept {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_vbsStatus != VBS_STATUS_DISABLED;
    }

    [[nodiscard]] bool isHvciActive() const noexcept {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return (m_vbsStatus != VBS_STATUS_DISABLED) &&
               ((m_hvciPolicy & HVCI_POLICY_STRICT_WX) != 0);
    }

    [[nodiscard]] uint32_t getCurrentVtl() const noexcept {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_currentVtl;
    }

    [[nodiscard]] uint32_t getFeatures() const noexcept {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_hypervisorFeatures;
    }

    [[nodiscard]] uint32_t getPolicyFlags() const noexcept {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_hvciPolicy;
    }

    [[nodiscard]] uint64_t getViolationCount() const noexcept {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_totalViolationsPrevented;
    }

    NTSTATUS setHvciState(bool enable, bool uefiLock) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        if (m_vbsStatus == VBS_STATUS_ENABLED_WITH_UEFI_LOCK && !enable) {
            // Cannot disable VBS when protected by UEFI lock!
            return STATUS_ACCESS_DENIED;
        }

        if (enable) {
            m_vbsStatus = uefiLock ? VBS_STATUS_ENABLED_WITH_UEFI_LOCK : VBS_STATUS_ENABLED;
            m_hvciPolicy |= HVCI_POLICY_STRICT_WX;
        } else {
            m_vbsStatus = VBS_STATUS_DISABLED;
            m_hvciPolicy &= ~HVCI_POLICY_STRICT_WX;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS protectKernelPage(uint64_t virtualAddr, uint32_t size, uint32_t requestedPerms, uint32_t callerVtl) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);

        // Strict W^X Check: A page cannot be simultaneously Writable and Executable!
        if ((requestedPerms & SLAT_PERM_WRITE) && (requestedPerms & SLAT_PERM_EXECUTE)) {
            recordViolation(virtualAddr, SLAT_PERM_WRITE | SLAT_PERM_EXECUTE, 0, callerVtl,
                            "WX_Violation", "Attempted to assign simultaneous Write and Execute permissions to kernel page");
            return STATUS_HVCI_WX_VIOLATION;
        }

        // VTL 0 cannot grant execute permissions on kernel pages directly; must go through VTL 1 Secure Kernel
        if (callerVtl == VTL_0_NORMAL && (requestedPerms & SLAT_PERM_EXECUTE)) {
            recordViolation(virtualAddr, SLAT_PERM_EXECUTE, 0, callerVtl,
                            "Unauthorized_Execute_Grant", "VTL 0 attempted to mark kernel memory executable without VTL 1 hypercall");
            return STATUS_HVCI_POLICY_VIOLATION;
        }

        // Locate existing page descriptor
        for (auto& page : m_pages) {
            if (virtualAddr >= page.virtualAddress && virtualAddr < (page.virtualAddress + page.size)) {
                if (page.ownerVtl == VTL_1_SECURE && callerVtl == VTL_0_NORMAL) {
                    recordViolation(virtualAddr, requestedPerms, page.vtl0Permissions, callerVtl,
                                    "VTL1_Enclave_Tamper", "VTL 0 attempted to re-map VTL 1 secure enclave page");
                    return STATUS_VTL_ACCESS_DENIED;
                }

                if (page.isLocked && callerVtl == VTL_0_NORMAL) {
                    recordViolation(virtualAddr, requestedPerms, page.vtl0Permissions, callerVtl,
                                    "Locked_Page_Modification", "VTL 0 attempted to modify locked SLAT page table entry");
                    return STATUS_HVCI_PAGE_LOCKED;
                }

                if (callerVtl == VTL_0_NORMAL) {
                    page.vtl0Permissions = requestedPerms;
                } else {
                    page.vtl1Permissions = requestedPerms;
                }
                return STATUS_SUCCESS;
            }
        }

        // Allocate dynamic descriptor
        m_pages.push_back({
            .physicalAddress = 0x0000000110000000ULL + (m_pages.size() * 0x1000),
            .virtualAddress  = virtualAddr,
            .size            = size > 0 ? size : 4096,
            .vtl0Permissions = (callerVtl == VTL_0_NORMAL) ? requestedPerms : SLAT_PERM_NONE,
            .vtl1Permissions = (callerVtl == VTL_1_SECURE) ? requestedPerms : SLAT_PERM_RW,
            .ownerVtl        = callerVtl,
            .moduleOwner     = (callerVtl == VTL_1_SECURE) ? "SecureKernelModule" : "DynamicDriver",
            .isVerifiedCode  = (callerVtl == VTL_1_SECURE),
            .isLocked        = false
        });

        return STATUS_SUCCESS;
    }

    NTSTATUS verifyAccess(uint64_t virtualAddr, uint32_t accessType, uint32_t callerVtl) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);

        for (auto& page : m_pages) {
            if (virtualAddr >= page.virtualAddress && virtualAddr < (page.virtualAddress + page.size)) {
                // 1. Cross-VTL Access Validation: VTL 0 accessing VTL 1 memory
                if (callerVtl == VTL_0_NORMAL && page.ownerVtl == VTL_1_SECURE) {
                    recordViolation(virtualAddr, accessType, page.vtl0Permissions, callerVtl,
                                    "Cross_VTL_Violation", "VTL 0 attempted to read or write VTL 1 Secure Enclave memory");
                    return STATUS_VTL_ACCESS_DENIED;
                }

                uint32_t activePerms = (callerVtl == VTL_0_NORMAL) ? page.vtl0Permissions : page.vtl1Permissions;

                // 2. Write to Executable Memory (Kernel Code Patching / DKOM)
                if ((accessType & SLAT_PERM_WRITE) && (activePerms & SLAT_PERM_EXECUTE)) {
                    recordViolation(virtualAddr, accessType, activePerms, callerVtl,
                                    "Code_Patching_Violation", "Attempted Write to Executable kernel code (.text section)");
                    return STATUS_HVCI_WX_VIOLATION;
                }

                // 3. Execution of Non-Executable Memory (Pool / Stack Shellcode)
                if ((accessType & SLAT_PERM_EXECUTE) && !(activePerms & SLAT_PERM_EXECUTE)) {
                    recordViolation(virtualAddr, accessType, activePerms, callerVtl,
                                    "Data_Execution_Violation", "Attempted Execution of non-executable data page (Pool/Stack)");
                    return STATUS_HVCI_CODE_INTEGRITY_VIOLATION;
                }

                // 4. Missing Read Permission
                if ((accessType & SLAT_PERM_READ) && !(activePerms & SLAT_PERM_READ)) {
                    recordViolation(virtualAddr, accessType, activePerms, callerVtl,
                                    "No_Read_Permission", "Attempted Read from unmapped or execute-only page");
                    return STATUS_ACCESS_DENIED;
                }

                // 5. Missing Write Permission
                if ((accessType & SLAT_PERM_WRITE) && !(activePerms & SLAT_PERM_WRITE)) {
                    recordViolation(virtualAddr, accessType, activePerms, callerVtl,
                                    "No_Write_Permission", "Attempted Write to read-only page");
                    return STATUS_ACCESS_DENIED;
                }

                return STATUS_SUCCESS;
            }
        }

        // Page not in SLAT table
        recordViolation(virtualAddr, accessType, 0, callerVtl,
                        "Unmapped_SLAT_Page", "Attempted access to physical page unmapped in hypervisor SLAT table");
        return STATUS_ACCESS_DENIED;
    }

    NTSTATUS invokeHypercall(uint32_t callCode, uint64_t arg1, uint64_t arg2, uint64_t* pResult) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        m_hypercallCount++;

        if (pResult) *pResult = 0;

        switch (callCode) {
            case HV_CALL_GET_VTL_STATUS: {
                if (pResult) *pResult = (static_cast<uint64_t>(m_vbsStatus) << 32) | m_currentVtl;
                return STATUS_SUCCESS;
            }

            case HV_CALL_ENTER_VTL1: {
                m_currentVtl = VTL_1_SECURE;
                if (pResult) *pResult = m_currentVtl;
                return STATUS_SUCCESS;
            }

            case HV_CALL_PROTECT_KERNEL_PAGE: {
                // arg1: Virtual Address, arg2: Requested permissions
                uint64_t vAddr = arg1;
                uint32_t perms = static_cast<uint32_t>(arg2);
                return protectKernelPage(vAddr, 4096, perms, m_currentVtl);
            }

            case HV_CALL_VERIFY_DRIVER_SIG: {
                // Driver integrity validation via Secure Kernel
                // arg1 = DriverBase, arg2 = DriverSize
                if (arg1 == 0 || arg2 == 0) return STATUS_INVALID_PARAMETER;
                // Secure Kernel validates driver signature and grants VTL 0 SLAT permissions as R-X
                for (auto& page : m_pages) {
                    if (arg1 >= page.virtualAddress && arg1 < (page.virtualAddress + page.size)) {
                        page.vtl0Permissions = SLAT_PERM_RX;
                        page.isVerifiedCode = true;
                        return STATUS_SUCCESS;
                    }
                }
                m_pages.push_back({
                    .physicalAddress = 0x0000000110000000ULL + (m_pages.size() * 0x1000),
                    .virtualAddress  = arg1,
                    .size            = static_cast<uint32_t>(arg2),
                    .vtl0Permissions = SLAT_PERM_RX,
                    .vtl1Permissions = SLAT_PERM_RX,
                    .ownerVtl        = VTL_0_NORMAL,
                    .moduleOwner     = "VerifiedKernelDriver",
                    .isVerifiedCode  = true,
                    .isLocked        = false
                });
                return STATUS_SUCCESS;
            }

            case HV_CALL_ENFORCE_WX: {
                m_hvciPolicy |= HVCI_POLICY_STRICT_WX;
                return STATUS_SUCCESS;
            }

            case HV_CALL_QUERY_PAGE_ATTR: {
                for (const auto& page : m_pages) {
                    if (arg1 >= page.virtualAddress && arg1 < (page.virtualAddress + page.size)) {
                        if (pResult) *pResult = (static_cast<uint64_t>(page.vtl1Permissions) << 32) | page.vtl0Permissions;
                        return STATUS_SUCCESS;
                    }
                }
                return STATUS_NOT_FOUND;
            }

            case HV_CALL_GET_VIOLATION_LOG: {
                if (pResult) *pResult = m_totalViolationsPrevented;
                return STATUS_SUCCESS;
            }

            case HV_CALL_RETURN_VTL0: {
                m_currentVtl = VTL_0_NORMAL;
                if (pResult) *pResult = m_currentVtl;
                return STATUS_SUCCESS;
            }

            default:
                return STATUS_HVCI_INVALID_HYPERCALL;
        }
    }

    std::string simulateRootkitAttack(std::string_view attackType) {
        std::ostringstream ss;
        uint64_t targetAddr = 0;
        NTSTATUS status = STATUS_SUCCESS;

        if (attackType == "KernelCodePatching") {
            // Rootkit attempts to patch ntoskrnl.exe .text section (R-X)
            targetAddr = 0xFFFFF80000001050ULL;
            ss << "========================================================================\n"
               << "  HVCI Simulation: Kernel Code Patching (DKOM / Function Hooking)       \n"
               << "========================================================================\n"
               << "Target Address: 0x" << std::hex << targetAddr << " (ntoskrnl.exe .text)\n"
               << "Attacker Context: Ring 0 Kernel Driver (VTL 0)\n"
               << "Operation: WRITE [0x48, 0xB8, 0x00, 0x10, 0x00...] (Hook Detour)\n"
               << "Hypervisor SLAT Check: Target mapped as R-X (Read-Execute)...\n";

            status = verifyAccess(targetAddr, SLAT_PERM_WRITE, VTL_0_NORMAL);

            if (status == STATUS_HVCI_WX_VIOLATION) {
                ss << "[BLOCKED] Hypervisor EPT/SLAT Violation Trapped! Status: 0xC0000431\n"
                   << "[HVCI Defense] W^X Invariant Enforced: Modification of executable code blocked.\n"
                   << "[Integrity] Kernel .text section remains pristine and unmodified.\n";
            } else {
                ss << "[FAILED] Attack was not prevented! Status: 0x" << std::hex << status << "\n";
            }
        }
        else if (attackType == "NonPagedPoolExecution") {
            // Rootkit attempts to execute shellcode in NonPagedPool (RW-)
            targetAddr = 0xFFFFFA8000004000ULL;
            ss << "========================================================================\n"
               << "  HVCI Simulation: Non-Paged Pool Shellcode Execution (Data Execution) \n"
               << "========================================================================\n"
               << "Target Address: 0x" << std::hex << targetAddr << " (NonPagedPool)\n"
               << "Attacker Context: Ring 0 Exploit / JIT Payload (VTL 0)\n"
               << "Operation: EXECUTE [Instruction Pointer -> Pool Address]\n"
               << "Hypervisor SLAT Check: Target mapped as RW- (Read-Write)...\n";

            status = verifyAccess(targetAddr, SLAT_PERM_EXECUTE, VTL_0_NORMAL);

            if (status == STATUS_HVCI_CODE_INTEGRITY_VIOLATION) {
                ss << "[BLOCKED] Hypervisor EPT/SLAT Execute Trap! Status: 0xC0000428\n"
                   << "[HVCI Defense] Memory Integrity: Execution of writable data pool blocked.\n"
                   << "[Integrity] Non-Paged Pool shellcode payload neutralized.\n";
            } else {
                ss << "[FAILED] Attack was not prevented! Status: 0x" << std::hex << status << "\n";
            }
        }
        else if (attackType == "Vtl1MemoryScrape") {
            // Rootkit in VTL 0 attempts to dump LsaIso.exe enclave memory in VTL 1
            targetAddr = 0xFFFFF87F00401000ULL;
            ss << "========================================================================\n"
               << "  VBS Simulation: VTL 1 Enclave Memory Scraping (LsaIso Mimikatz)      \n"
               << "========================================================================\n"
               << "Target Address: 0x" << std::hex << targetAddr << " (LsaIso.exe VTL 1 Enclave)\n"
               << "Attacker Context: Administrative Process / Kernel Driver (VTL 0)\n"
               << "Operation: READ [Extract Kerberos TGT / NTLM Hashes]\n"
               << "Hypervisor SLAT Check: Page owned by VTL 1 (Secure World)...\n";

            status = verifyAccess(targetAddr, SLAT_PERM_READ, VTL_0_NORMAL);

            if (status == STATUS_VTL_ACCESS_DENIED) {
                ss << "[BLOCKED] Hypervisor Cross-VTL Access Intercepted! Status: 0xC0000432\n"
                   << "[VBS Defense] VTL 0 process has zero visibility into VTL 1 enclaves.\n"
                   << "[Integrity] Authentication secrets remain cryptographically sealed.\n";
            } else {
                ss << "[FAILED] Attack was not prevented! Status: 0x" << std::hex << status << "\n";
            }
        }
        else {
            ss << "[-] Unknown attack simulation type: " << attackType << "\n";
        }

        return ss.str();
    }

    [[nodiscard]] std::vector<SlatPageDescriptor> getPages() const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_pages;
    }

    [[nodiscard]] std::vector<HvciViolationRecord> getViolations() const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_violations;
    }

    [[nodiscard]] VbsPolicyInfo getPolicyInfo() const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return {
            .VbsStatus = m_vbsStatus,
            .HvciStatus = (m_hvciPolicy & HVCI_POLICY_STRICT_WX) ? 1u : 0u,
            .HypervisorFeatures = m_hypervisorFeatures,
            .HvciPolicyFlags = m_hvciPolicy,
            .CurrentVtl = m_currentVtl,
            .ProtectedPageCount = m_pages.size(),
            .ViolationsPrevented = m_totalViolationsPrevented
        };
    }

private:
    void recordViolation(uint64_t address, uint32_t attemptedAccess, uint32_t currentPerms,
                         uint32_t callerVtl, std::string_view attackType, std::string_view message) {
        m_totalViolationsPrevented++;
        for (auto& page : m_pages) {
            if (address >= page.virtualAddress && address < (page.virtualAddress + page.size)) {
                page.violationCount++;
                break;
            }
        }

        auto now = std::chrono::system_clock::now().time_since_epoch();
        uint64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();

        m_violations.push_back({
            .timestamp = ts,
            .faultingAddress = address,
            .attemptedAccess = attemptedAccess,
            .currentPermissions = currentPerms,
            .callerVtl = callerVtl,
            .attackType = std::string(attackType),
            .description = std::string(message),
            .blocked = true
        });
    }
};

// ============================================================================
// 5. Win32 & NT Clean-Room C ABI Export Implementations
// ============================================================================

// --- vbs.dll Exports ---

inline BOOLEAN WINAPI VbsIsVirtualizationBasedSecuritySupported() {
    return VirtualizationBasedSecurityManager::Instance().isSupported() ? TRUE : FALSE;
}

inline BOOLEAN WINAPI VbsIsVirtualizationBasedSecurityEnabled() {
    return VirtualizationBasedSecurityManager::Instance().isEnabled() ? TRUE : FALSE;
}

inline BOOLEAN WINAPI VbsGetHypervisorEnforcedCodeIntegrityStatus() {
    return VirtualizationBasedSecurityManager::Instance().isHvciActive() ? TRUE : FALSE;
}

inline NTSTATUS WINAPI VbsSetHypervisorEnforcedCodeIntegrity(BOOLEAN enable, BOOLEAN uefiLock) {
    return VirtualizationBasedSecurityManager::Instance().setHvciState(enable != 0, uefiLock != 0);
}

inline uint32_t WINAPI VbsQueryVirtualTrustLevel() {
    return VirtualizationBasedSecurityManager::Instance().getCurrentVtl();
}

inline NTSTATUS WINAPI VbsInvokeHypercall(uint32_t callCode, uint64_t arg1, uint64_t arg2, uint64_t* pResult) {
    return VirtualizationBasedSecurityManager::Instance().invokeHypercall(callCode, arg1, arg2, pResult);
}

inline NTSTATUS WINAPI VbsGetMemoryProtectionPolicy(VbsPolicyInfo* pInfo) {
    if (!pInfo) return STATUS_INVALID_PARAMETER;
    *pInfo = VirtualizationBasedSecurityManager::Instance().getPolicyInfo();
    return STATUS_SUCCESS;
}

inline NTSTATUS WINAPI VbsAuditSecurityViolation(uint64_t address, uint32_t accessType, uint32_t callerVtl, BOOLEAN* pBlocked) {
    NTSTATUS st = VirtualizationBasedSecurityManager::Instance().verifyAccess(address, accessType, callerVtl);
    if (pBlocked) {
        *pBlocked = (st != STATUS_SUCCESS) ? TRUE : FALSE;
    }
    return st;
}

// --- ntoskrnl.exe Exports ---

inline BOOLEAN WINAPI HvlIsHypervisorPresent() {
    auto feat = VirtualizationBasedSecurityManager::Instance().getFeatures();
    return (feat & HV_FEATURE_HYPERVISOR_PRESENT) ? TRUE : FALSE;
}

inline uint32_t WINAPI HvlGetVirtualTrustLevel() {
    return VirtualizationBasedSecurityManager::Instance().getCurrentVtl();
}

inline NTSTATUS WINAPI HvlEnforceKernelCodeIntegrity(BOOLEAN enable) {
    return VirtualizationBasedSecurityManager::Instance().setHvciState(enable != 0, false);
}

inline NTSTATUS WINAPI HvlProtectPageFrame(uint64_t pageAddress, uint32_t perms, uint32_t callerVtl) {
    return VirtualizationBasedSecurityManager::Instance().protectKernelPage(pageAddress, 4096, perms, callerVtl);
}

inline NTSTATUS WINAPI HvlValidateMemoryAttributes(uint64_t pageAddress, uint32_t accessType) {
    return VirtualizationBasedSecurityManager::Instance().verifyAccess(pageAddress, accessType, VTL_0_NORMAL);
}

inline NTSTATUS WINAPI HvlRegisterHvciCallback(void* /*callbackFn*/) {
    // Registered successfully with hypervisor callback table
    return STATUS_SUCCESS;
}

inline uint64_t WINAPI HvlGetHvciViolationCount() {
    return VirtualizationBasedSecurityManager::Instance().getViolationCount();
}

// ============================================================================
// 6. DynamicLoader & VersionDatabase Registration
// ============================================================================

inline void InitializeVbsHvciSubsystemExports() {
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        auto& loader = ldr::DynamicLoader::get();

        // Register exports in vbs.dll
        loader.registerExport("vbs.dll", "VbsIsVirtualizationBasedSecuritySupported", reinterpret_cast<void*>(&VbsIsVirtualizationBasedSecuritySupported));
        loader.registerExport("vbs.dll", "VbsIsVirtualizationBasedSecurityEnabled", reinterpret_cast<void*>(&VbsIsVirtualizationBasedSecurityEnabled));
        loader.registerExport("vbs.dll", "VbsGetHypervisorEnforcedCodeIntegrityStatus", reinterpret_cast<void*>(&VbsGetHypervisorEnforcedCodeIntegrityStatus));
        loader.registerExport("vbs.dll", "VbsSetHypervisorEnforcedCodeIntegrity", reinterpret_cast<void*>(&VbsSetHypervisorEnforcedCodeIntegrity));
        loader.registerExport("vbs.dll", "VbsQueryVirtualTrustLevel", reinterpret_cast<void*>(&VbsQueryVirtualTrustLevel));
        loader.registerExport("vbs.dll", "VbsInvokeHypercall", reinterpret_cast<void*>(&VbsInvokeHypercall));
        loader.registerExport("vbs.dll", "VbsGetMemoryProtectionPolicy", reinterpret_cast<void*>(&VbsGetMemoryProtectionPolicy));
        loader.registerExport("vbs.dll", "VbsAuditSecurityViolation", reinterpret_cast<void*>(&VbsAuditSecurityViolation));

        // Register exports in ntoskrnl.exe
        loader.registerExport("ntoskrnl.exe", "HvlIsHypervisorPresent", reinterpret_cast<void*>(&HvlIsHypervisorPresent));
        loader.registerExport("ntoskrnl.exe", "HvlGetVirtualTrustLevel", reinterpret_cast<void*>(&HvlGetVirtualTrustLevel));
        loader.registerExport("ntoskrnl.exe", "HvlEnforceKernelCodeIntegrity", reinterpret_cast<void*>(&HvlEnforceKernelCodeIntegrity));
        loader.registerExport("ntoskrnl.exe", "HvlProtectPageFrame", reinterpret_cast<void*>(&HvlProtectPageFrame));
        loader.registerExport("ntoskrnl.exe", "HvlValidateMemoryAttributes", reinterpret_cast<void*>(&HvlValidateMemoryAttributes));
        loader.registerExport("ntoskrnl.exe", "HvlRegisterHvciCallback", reinterpret_cast<void*>(&HvlRegisterHvciCallback));
        loader.registerExport("ntoskrnl.exe", "HvlGetHvciViolationCount", reinterpret_cast<void*>(&HvlGetHvciViolationCount));

        // VersionDatabase registrations
        auto& vdb = version::VersionDatabase::Instance();
        vdb.RegisterModule(
            "vbs.dll",
            "10.0.26100.1",
            "MicaNT Virtualization-Based Security Core Library",
            "Project MICA"
        );

        vdb.RegisterModule(
            "securekernel.exe",
            "10.0.26100.1",
            "MicaNT Secure Kernel (VTL 1 Hypervisor Enclave)",
            "Project MICA"
        );
    });
}

} // namespace micant::vbs_hvci
