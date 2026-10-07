#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>
#include <optional>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <span>
#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ob.hpp"

namespace micant::se {

// ============================================================================
// Standard Access Rights & Masks (aligned with Win32/NT security model)
// ============================================================================
inline constexpr uint32_t DELETE                    = 0x00010000;
inline constexpr uint32_t READ_CONTROL              = 0x00020000;
inline constexpr uint32_t WRITE_DAC                 = 0x00040000;
inline constexpr uint32_t WRITE_OWNER               = 0x00080000;
inline constexpr uint32_t SYNCHRONIZE               = 0x00100000;

inline constexpr uint32_t STANDARD_RIGHTS_REQUIRED  = 0x000F0000;
inline constexpr uint32_t STANDARD_RIGHTS_READ      = READ_CONTROL;
inline constexpr uint32_t STANDARD_RIGHTS_WRITE     = READ_CONTROL;
inline constexpr uint32_t STANDARD_RIGHTS_EXECUTE   = READ_CONTROL;
inline constexpr uint32_t STANDARD_RIGHTS_ALL       = 0x001F0000;
inline constexpr uint32_t SPECIFIC_RIGHTS_ALL       = 0x0000FFFF;

inline constexpr uint32_t GENERIC_READ              = 0x80000000;
inline constexpr uint32_t GENERIC_WRITE             = 0x40000000;
inline constexpr uint32_t GENERIC_EXECUTE           = 0x20000000;
inline constexpr uint32_t GENERIC_ALL               = 0x10000000;

// Token Privilege Attribute Flags
inline constexpr uint32_t SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
inline constexpr uint32_t SE_PRIVILEGE_ENABLED            = 0x00000002;
inline constexpr uint32_t SE_PRIVILEGE_REMOVED            = 0x00000004;
inline constexpr uint32_t SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000;

// Standard NT Privilege Strings
inline constexpr std::wstring_view SE_DEBUG_NAME             = L"SeDebugPrivilege";
inline constexpr std::wstring_view SE_SHUTDOWN_NAME          = L"SeShutdownPrivilege";
inline constexpr std::wstring_view SE_BACKUP_NAME            = L"SeBackupPrivilege";
inline constexpr std::wstring_view SE_RESTORE_NAME           = L"SeRestorePrivilege";
inline constexpr std::wstring_view SE_SECURITY_NAME          = L"SeSecurityPrivilege";
inline constexpr std::wstring_view SE_TAKE_OWNERSHIP_NAME    = L"SeTakeOwnershipPrivilege";
inline constexpr std::wstring_view SE_TCB_NAME               = L"SeTcbPrivilege";
inline constexpr std::wstring_view SE_IMPERSONATE_NAME       = L"SeImpersonatePrivilege";
inline constexpr std::wstring_view SE_CHANGE_NOTIFY_NAME     = L"SeChangeNotifyPrivilege";
inline constexpr std::wstring_view SE_SYSTEMTIME_NAME        = L"SeSystemtimePrivilege";
inline constexpr std::wstring_view SE_SYSTEM_ENVIRONMENT_NAME= L"SeSystemEnvironmentPrivilege";
inline constexpr std::wstring_view SE_ASSIGNPRIMARYTOKEN_NAME= L"SeAssignPrimaryTokenPrivilege";
inline constexpr std::wstring_view SE_INCREASE_QUOTA_NAME    = L"SeIncreaseQuotaPrivilege";
inline constexpr std::wstring_view SE_LOAD_DRIVER_NAME       = L"SeLoadDriverPrivilege";
inline constexpr std::wstring_view SE_CREATE_TOKEN_NAME      = L"SeCreateTokenPrivilege";
inline constexpr std::wstring_view SE_LOCK_MEMORY_NAME       = L"SeLockMemoryPrivilege";

/**
 * @brief Security Identifier (SID).
 * Variable-length numerical value used to uniquely identify security principals.
 * Canonical string format: S-1-<IdentifierAuthority>-<SubAuth1>-<SubAuth2>...
 */
class Sid {
public:
    Sid() : revision_(1), identifierAuthority_{0, 0, 0, 0, 0, 0} {}

    Sid(uint64_t authority, std::initializer_list<uint32_t> subAuthorities)
        : revision_(1) {
        for (int i = 5; i >= 0; --i) {
            identifierAuthority_[i] = static_cast<uint8_t>(authority & 0xFF);
            authority >>= 8;
        }
        subAuthorities_.assign(subAuthorities.begin(), subAuthorities.end());
    }

    [[nodiscard]] uint8_t getRevision() const noexcept { return revision_; }
    [[nodiscard]] uint64_t getIdentifierAuthority() const noexcept {
        uint64_t auth = 0;
        for (uint8_t b : identifierAuthority_) {
            auth = (auth << 8) | b;
        }
        return auth;
    }
    [[nodiscard]] const std::vector<uint32_t>& getSubAuthorities() const noexcept {
        return subAuthorities_;
    }

    [[nodiscard]] std::wstring toString() const {
        std::wostringstream wos;
        wos << L"S-" << static_cast<uint32_t>(revision_) << L"-" << getIdentifierAuthority();
        for (uint32_t sa : subAuthorities_) {
            wos << L"-" << sa;
        }
        return wos.str();
    }

    bool operator==(const Sid& other) const noexcept {
        return revision_ == other.revision_ &&
               std::equal(identifierAuthority_, identifierAuthority_ + 6, other.identifierAuthority_) &&
               subAuthorities_ == other.subAuthorities_;
    }

    // Well-Known SIDs
    [[nodiscard]] static Sid null() { return Sid(0, {0}); }                     // S-1-0-0
    [[nodiscard]] static Sid everyone() { return Sid(1, {0}); }                 // S-1-1-0 (World)
    [[nodiscard]] static Sid local() { return Sid(2, {0}); }                    // S-1-2-0
    [[nodiscard]] static Sid creatorOwner() { return Sid(3, {0}); }             // S-1-3-0
    [[nodiscard]] static Sid authenticatedUsers() { return Sid(5, {11}); }      // S-1-5-11
    [[nodiscard]] static Sid localSystem() { return Sid(5, {18}); }             // S-1-5-18
    [[nodiscard]] static Sid localService() { return Sid(5, {19}); }            // S-1-5-19
    [[nodiscard]] static Sid networkService() { return Sid(5, {20}); }          // S-1-5-20
    [[nodiscard]] static Sid administrators() { return Sid(5, {32, 544}); }     // S-1-5-32-544 (Builtin Administrators)
    [[nodiscard]] static Sid users() { return Sid(5, {32, 545}); }              // S-1-5-32-545 (Builtin Users)

private:
    uint8_t revision_{1};
    uint8_t identifierAuthority_[6]{0};
    std::vector<uint32_t> subAuthorities_;
};

// ACE Types
enum class AceType : uint8_t {
    AccessAllowed = 0x00,
    AccessDenied  = 0x01,
    SystemAudit   = 0x02,
    SystemAlarm   = 0x03
};

/**
 * @brief Access Control Entry (ACE).
 */
struct Ace {
    AceType type{AceType::AccessAllowed};
    uint8_t flags{0};
    uint32_t mask{0};
    Sid sid;
};

/**
 * @brief Access Control List (ACL).
 * Manages an ordered collection of ACEs.
 */
class Acl {
public:
    Acl() = default;

    void addAllowedAce(const Sid& sid, uint32_t mask, uint8_t flags = 0) {
        aces_.push_back(Ace{ .type = AceType::AccessAllowed, .flags = flags, .mask = mask, .sid = sid });
    }

    void addDeniedAce(const Sid& sid, uint32_t mask, uint8_t flags = 0) {
        aces_.push_back(Ace{ .type = AceType::AccessDenied, .flags = flags, .mask = mask, .sid = sid });
    }

    [[nodiscard]] size_t getAceCount() const noexcept { return aces_.size(); }
    [[nodiscard]] const std::vector<Ace>& getAces() const noexcept { return aces_; }

private:
    std::vector<Ace> aces_;
};

/**
 * @brief Security Descriptor.
 * Contains security information associated with an object: Owner, Group, DACL, SACL.
 */
class SecurityDescriptor {
public:
    SecurityDescriptor() = default;

    void setOwner(Sid owner) { owner_ = std::move(owner); }
    [[nodiscard]] const std::optional<Sid>& getOwner() const noexcept { return owner_; }

    void setGroup(Sid group) { group_ = std::move(group); }
    [[nodiscard]] const std::optional<Sid>& getGroup() const noexcept { return group_; }

    void setDacl(Acl dacl) { dacl_ = std::move(dacl); daclPresent_ = true; }
    [[nodiscard]] const std::optional<Acl>& getDacl() const noexcept { return dacl_; }
    [[nodiscard]] bool hasDacl() const noexcept { return daclPresent_; }

private:
    std::optional<Sid> owner_;
    std::optional<Sid> group_;
    std::optional<Acl> dacl_;
    bool daclPresent_{false};
};

/**
 * @brief Token Type (Primary or Impersonation).
 */
enum class TokenType : uint32_t {
    Primary = 1,
    Impersonation = 2
};

/**
 * @brief Security Impersonation Level.
 */
enum class SecurityImpersonationLevel : uint32_t {
    Anonymous = 0,
    Identification = 1,
    Impersonation = 2,
    Delegation = 3
};

/**
 * @brief Process / Thread Access Token.
 * Represents user identity, group memberships, and assigned administrative privileges.
 */
class TokenObject {
public:
    explicit TokenObject(Sid userSid, TokenType type = TokenType::Primary)
        : userSid_(std::move(userSid)), tokenType_(type) {}

    [[nodiscard]] const Sid& getUserSid() const noexcept { return userSid_; }
    [[nodiscard]] const std::vector<Sid>& getGroupSids() const noexcept { return groupSids_; }
    [[nodiscard]] TokenType getTokenType() const noexcept { return tokenType_; }

    void addGroup(Sid group) {
        groupSids_.push_back(std::move(group));
    }

    [[nodiscard]] bool hasSid(const Sid& sid) const {
        if (userSid_ == sid) return true;
        for (const auto& g : groupSids_) {
            if (g == sid) return true;
        }
        return false;
    }

    void addPrivilege(std::wstring_view name, uint32_t attributes = SE_PRIVILEGE_ENABLED) {
        privileges_[std::wstring(name)] = attributes;
    }

    [[nodiscard]] bool hasPrivilege(std::wstring_view name, bool mustBeEnabled = true) const {
        auto it = privileges_.find(std::wstring(name));
        if (it == privileges_.end()) return false;
        if (mustBeEnabled) {
            return (it->second & SE_PRIVILEGE_ENABLED) != 0;
        }
        return true;
    }

    bool enablePrivilege(std::wstring_view name, bool enable = true) {
        auto it = privileges_.find(std::wstring(name));
        if (it == privileges_.end()) return false;
        if (enable) {
            it->second |= SE_PRIVILEGE_ENABLED;
        } else {
            it->second &= ~SE_PRIVILEGE_ENABLED;
        }
        return true;
    }

    [[nodiscard]] const std::unordered_map<std::wstring, uint32_t>& getPrivileges() const noexcept {
        return privileges_;
    }

    [[nodiscard]] Luid getAuthenticationId() const noexcept { return authId_; }
    void setAuthenticationId(Luid id) noexcept { authId_ = id; }

    [[nodiscard]] uint32_t getSessionId() const noexcept { return sessionId_; }
    void setSessionId(uint32_t id) noexcept { sessionId_ = id; }

    // Factory Helpers
    [[nodiscard]] static std::shared_ptr<TokenObject> createSystemToken() {
        auto token = std::make_shared<TokenObject>(Sid::localSystem());
        token->addGroup(Sid::administrators());
        token->addGroup(Sid::authenticatedUsers());
        token->addGroup(Sid::everyone());
        token->addPrivilege(SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        token->addPrivilege(SE_SHUTDOWN_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        token->addPrivilege(SE_TCB_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        token->addPrivilege(SE_IMPERSONATE_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        return token;
    }

    [[nodiscard]] static std::shared_ptr<TokenObject> createAdminToken(Sid userSid) {
        auto token = std::make_shared<TokenObject>(std::move(userSid));
        token->addGroup(Sid::administrators());
        token->addGroup(Sid::authenticatedUsers());
        token->addGroup(Sid::everyone());
        token->addPrivilege(SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        token->addPrivilege(SE_SHUTDOWN_NAME, SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        token->addPrivilege(SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        return token;
    }

    [[nodiscard]] static std::shared_ptr<TokenObject> createUserToken(Sid userSid) {
        auto token = std::make_shared<TokenObject>(std::move(userSid));
        token->addGroup(Sid::users());
        token->addGroup(Sid::authenticatedUsers());
        token->addGroup(Sid::everyone());
        token->addPrivilege(SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT);
        return token;
    }

private:
    Sid userSid_;
    std::vector<Sid> groupSids_;
    std::unordered_map<std::wstring, uint32_t> privileges_;
    TokenType tokenType_{TokenType::Primary};
    SecurityImpersonationLevel impersonationLevel_{SecurityImpersonationLevel::Impersonation};
    Luid authId_{0, 0};
    uint32_t sessionId_{0};
};

/**
 * @brief Security Reference Monitor (SRM).
 * Performs Dave Cutler's NT access validation algorithm against Security Descriptors.
 */
class SecurityReferenceMonitor {
public:
    /**
     * @brief Performs access validation according to standard NT security semantics.
     *
     * 1. If desiredAccess is 0, access is granted.
     * 2. Owner rights: Owner is always granted READ_CONTROL and WRITE_DAC if requested.
     * 3. If no DACL is present (daclPresent == false), full access is granted to all callers.
     * 4. If DACL is present but empty (aceCount == 0), all access is denied.
     * 5. ACEs are traversed in order:
     *    - If matching SID has an AccessDenied ACE covering requested rights -> ACCESS_DENIED.
     *    - If matching SID has an AccessAllowed ACE -> accumulate granted rights.
     *    - If all desired rights are granted -> STATUS_SUCCESS.
     * 6. If loop finishes and ungranted rights remain -> ACCESS_DENIED.
     */
    [[nodiscard]] static NtStatus accessCheck(
        const TokenObject& token,
        const SecurityDescriptor& secDesc,
        uint32_t desiredAccess,
        uint32_t& grantedAccess
    ) noexcept {
        grantedAccess = 0;
        if (desiredAccess == 0) {
            return NtStatus::Success;
        }

        // Map generic rights if present
        uint32_t remainingDesired = desiredAccess;
        if (remainingDesired & GENERIC_ALL) {
            remainingDesired = STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL;
        }

        // Owner privilege: Owner always has READ_CONTROL and WRITE_DAC
        if (secDesc.getOwner() && token.hasSid(*secDesc.getOwner())) {
            uint32_t ownerGrant = remainingDesired & (READ_CONTROL | WRITE_DAC);
            grantedAccess |= ownerGrant;
            remainingDesired &= ~ownerGrant;
            if (remainingDesired == 0) {
                return NtStatus::Success;
            }
        }

        // Check DACL presence
        if (!secDesc.hasDacl()) {
            // Null DACL = Full access granted to everyone
            grantedAccess = desiredAccess;
            return NtStatus::Success;
        }

        const auto& daclOpt = secDesc.getDacl();
        if (!daclOpt || daclOpt->getAceCount() == 0) {
            // Empty DACL = Access denied to everyone
            return NtStatus::AccessDenied;
        }

        // Traverse DACL ACEs in order
        for (const auto& ace : daclOpt->getAces()) {
            if (!token.hasSid(ace.sid)) {
                continue;
            }

            if (ace.type == AceType::AccessDenied) {
                if ((remainingDesired & ace.mask) != 0) {
                    grantedAccess = 0;
                    return NtStatus::AccessDenied;
                }
            } else if (ace.type == AceType::AccessAllowed) {
                uint32_t matched = (remainingDesired & ace.mask);
                grantedAccess |= matched;
                remainingDesired &= ~matched;

                if (remainingDesired == 0) {
                    return NtStatus::Success;
                }
            }
        }

        return (remainingDesired == 0) ? NtStatus::Success : NtStatus::AccessDenied;
    }
};

} // namespace micant::se
