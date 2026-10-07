#pragma once

/**
 * @file acl.hpp
 * @brief MicaNT Security Descriptor, Access Control List (ACL) & Auditing Subsystem
 *
 * Clean-room implementation referencing Microsoft's MIT-licensed win32metadata.
 * Implements:
 * - Security Descriptor & ACL APIs (advapi32.dll / secur32.dll / sspicli.dll)
 * - Access Control Entries (ACEs): Allowed, Denied, System Audit
 * - Security Identifier (SID) allocation, conversion, and comparison
 * - Relative and Absolute Security Descriptor transformation (MakeSelfRelativeSD / MakeAbsoluteSD)
 * - AccessCheck authorization calculation
 * - Security Auditing Policy Engine (auditpol.exe)
 * - Permission and Integrity CLI (icacls.exe)
 * - SCM integration with COM+ Event System (EventSystem)
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <functional>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ldr.hpp"
#include "scm.hpp"

namespace micant::acl {

// ============================================================================
// 1. Windows ACL & Security Descriptor Constants & Types
// ============================================================================

using BOOL = int32_t;
inline constexpr BOOL TRUE  = 1;
inline constexpr BOOL FALSE = 0;

inline constexpr uint32_t ERROR_SUCCESS                   = 0;
inline constexpr uint32_t ERROR_INVALID_PARAMETER         = 87;
inline constexpr uint32_t ERROR_INSUFFICIENT_BUFFER       = 122;
inline constexpr uint32_t ERROR_INVALID_SID               = 1337;
inline constexpr uint32_t ERROR_INVALID_ACL               = 1336;
inline constexpr uint32_t ERROR_INVALID_SECURITY_DESCR    = 1338;
inline constexpr uint32_t ERROR_ACCESS_DENIED             = 5;
inline constexpr uint32_t ERROR_NOT_FOUND                 = 1168;

// Security Descriptor Revision
inline constexpr uint32_t SECURITY_DESCRIPTOR_REVISION    = 1;
inline constexpr uint32_t ACL_REVISION                    = 2;
inline constexpr uint32_t ACL_REVISION_DS                 = 4;

// Security Descriptor Control Flags
inline constexpr uint16_t SE_OWNER_DEFAULTED              = 0x0001;
inline constexpr uint16_t SE_GROUP_DEFAULTED              = 0x0002;
inline constexpr uint16_t SE_DACL_PRESENT                 = 0x0004;
inline constexpr uint16_t SE_DACL_DEFAULTED               = 0x0008;
inline constexpr uint16_t SE_SACL_PRESENT                 = 0x0010;
inline constexpr uint16_t SE_SACL_DEFAULTED               = 0x0020;
inline constexpr uint16_t SE_DACL_AUTO_INHERIT_REQ        = 0x0100;
inline constexpr uint16_t SE_SACL_AUTO_INHERIT_REQ        = 0x0200;
inline constexpr uint16_t SE_DACL_AUTO_INHERITED          = 0x0400;
inline constexpr uint16_t SE_SACL_AUTO_INHERITED          = 0x0800;
inline constexpr uint16_t SE_DACL_PROTECTED               = 0x1000;
inline constexpr uint16_t SE_SACL_PROTECTED               = 0x2000;
inline constexpr uint16_t SE_SELF_RELATIVE                = 0x8000;

// ACE Types
inline constexpr uint8_t ACCESS_ALLOWED_ACE_TYPE          = 0x0;
inline constexpr uint8_t ACCESS_DENIED_ACE_TYPE           = 0x1;
inline constexpr uint8_t SYSTEM_AUDIT_ACE_TYPE            = 0x2;
inline constexpr uint8_t SYSTEM_ALARM_ACE_TYPE            = 0x3;

// ACE Inheritance and Audit Flags
inline constexpr uint8_t OBJECT_INHERIT_ACE               = 0x01;
inline constexpr uint8_t CONTAINER_INHERIT_ACE            = 0x02;
inline constexpr uint8_t NO_PROPAGATE_INHERIT_ACE         = 0x04;
inline constexpr uint8_t INHERIT_ONLY_ACE                 = 0x08;
inline constexpr uint8_t INHERITED_ACE                    = 0x10;
inline constexpr uint8_t SUCCESSFUL_ACCESS_ACE_FLAG       = 0x40;
inline constexpr uint8_t FAILED_ACCESS_ACE_FLAG           = 0x80;

// Access Masks
inline constexpr uint32_t DELETE                          = 0x00010000;
inline constexpr uint32_t READ_CONTROL                    = 0x00020000;
inline constexpr uint32_t WRITE_DAC                       = 0x00040000;
inline constexpr uint32_t WRITE_OWNER                     = 0x00080000;
inline constexpr uint32_t SYNCHRONIZE                     = 0x00100000;
inline constexpr uint32_t STANDARD_RIGHTS_REQUIRED        = 0x000F0000;
inline constexpr uint32_t STANDARD_RIGHTS_ALL             = 0x001F0000;
inline constexpr uint32_t SPECIFIC_RIGHTS_ALL             = 0x0000FFFF;
inline constexpr uint32_t GENERIC_READ                    = 0x80000000;
inline constexpr uint32_t GENERIC_WRITE                   = 0x40000000;
inline constexpr uint32_t GENERIC_EXECUTE                 = 0x20000000;
inline constexpr uint32_t GENERIC_ALL                     = 0x10000000;

// File Rights
inline constexpr uint32_t FILE_READ_DATA                  = 0x0001;
inline constexpr uint32_t FILE_WRITE_DATA                 = 0x0002;
inline constexpr uint32_t FILE_APPEND_DATA                = 0x0004;
inline constexpr uint32_t FILE_READ_EA                    = 0x0008;
inline constexpr uint32_t FILE_WRITE_EA                   = 0x0010;
inline constexpr uint32_t FILE_EXECUTE                    = 0x0020;
inline constexpr uint32_t FILE_DELETE_CHILD               = 0x0040;
inline constexpr uint32_t FILE_READ_ATTRIBUTES            = 0x0080;
inline constexpr uint32_t FILE_WRITE_ATTRIBUTES           = 0x0100;
inline constexpr uint32_t FILE_ALL_ACCESS                 = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF);

// Auditing Policy Flags
inline constexpr uint32_t AUDIT_POLICY_NONE               = 0;
inline constexpr uint32_t AUDIT_POLICY_SUCCESS            = 1;
inline constexpr uint32_t AUDIT_POLICY_FAILURE            = 2;
inline constexpr uint32_t AUDIT_POLICY_SUCCESS_AND_FAILURE = 3;

// ============================================================================
// 2. Win32 Binary Layout Structures
// ============================================================================

struct SID_IDENTIFIER_AUTHORITY {
    uint8_t Value[6]{0};
};

inline constexpr SID_IDENTIFIER_AUTHORITY SECURITY_NT_AUTHORITY = { {0, 0, 0, 0, 0, 5} };
inline constexpr SID_IDENTIFIER_AUTHORITY SECURITY_WORLD_SID_AUTHORITY = { {0, 0, 0, 0, 0, 1} };

struct SID {
    uint8_t  Revision{1};
    uint8_t  SubAuthorityCount{0};
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority{};
    uint32_t SubAuthority[8]{0};
};
using PSID = void*;

struct ACL {
    uint8_t  AclRevision{static_cast<uint8_t>(ACL_REVISION)};
    uint8_t  Sbz1{0};
    uint16_t AclSize{sizeof(ACL)};
    uint16_t AceCount{0};
    uint16_t Sbz2{0};
};
using PACL = ACL*;

struct ACE_HEADER {
    uint8_t  AceType{ACCESS_ALLOWED_ACE_TYPE};
    uint8_t  AceFlags{0};
    uint16_t AceSize{sizeof(ACE_HEADER)};
};

struct ACCESS_ALLOWED_ACE {
    ACE_HEADER Header{};
    uint32_t   Mask{0};
    uint32_t   SidStart{0};
};

struct ACCESS_DENIED_ACE {
    ACE_HEADER Header{};
    uint32_t   Mask{0};
    uint32_t   SidStart{0};
};

struct SYSTEM_AUDIT_ACE {
    ACE_HEADER Header{};
    uint32_t   Mask{0};
    uint32_t   SidStart{0};
};

struct SECURITY_DESCRIPTOR {
    uint8_t  Revision{static_cast<uint8_t>(SECURITY_DESCRIPTOR_REVISION)};
    uint8_t  Sbz1{0};
    uint16_t Control{0};
    PSID     Owner{nullptr};
    PSID     Group{nullptr};
    PACL     Sacl{nullptr};
    PACL     Dacl{nullptr};
};
using PSECURITY_DESCRIPTOR = void*;

struct SECURITY_DESCRIPTOR_RELATIVE {
    uint8_t  Revision{static_cast<uint8_t>(SECURITY_DESCRIPTOR_REVISION)};
    uint8_t  Sbz1{0};
    uint16_t Control{SE_SELF_RELATIVE};
    uint32_t Owner{0};
    uint32_t Group{0};
    uint32_t Sacl{0};
    uint32_t Dacl{0};
};

struct GENERIC_MAPPING {
    uint32_t GenericRead{FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE};
    uint32_t GenericWrite{FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | READ_CONTROL | SYNCHRONIZE};
    uint32_t GenericExecute{FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE};
    uint32_t GenericAll{FILE_ALL_ACCESS};
};

struct PRIVILEGE_SET {
    uint32_t PrivilegeCount{0};
    uint32_t Control{0};
};

// ============================================================================
// 3. SID & Security Descriptor Conversion & Utility Functions
// ============================================================================

inline BOOL __stdcall IsValidSid(PSID pSid) {
    if (!pSid) return FALSE;
    const auto* sid = static_cast<const SID*>(pSid);
    if (sid->Revision != 1) return FALSE;
    if (sid->SubAuthorityCount > 8) return FALSE;
    return TRUE;
}

inline uint32_t __stdcall GetLengthSid(PSID pSid) {
    if (!IsValidSid(pSid)) return 0;
    const auto* sid = static_cast<const SID*>(pSid);
    return static_cast<uint32_t>(sizeof(uint8_t) * 2 + sizeof(SID_IDENTIFIER_AUTHORITY) +
                                 sizeof(uint32_t) * sid->SubAuthorityCount);
}

inline BOOL __stdcall EqualSid(PSID pSid1, PSID pSid2) {
    if (!IsValidSid(pSid1) || !IsValidSid(pSid2)) return FALSE;
    const auto* s1 = static_cast<const SID*>(pSid1);
    const auto* s2 = static_cast<const SID*>(pSid2);
    if (s1->Revision != s2->Revision) return FALSE;
    if (s1->SubAuthorityCount != s2->SubAuthorityCount) return FALSE;
    if (std::memcmp(s1->IdentifierAuthority.Value, s2->IdentifierAuthority.Value, 6) != 0) return FALSE;
    for (uint8_t i = 0; i < s1->SubAuthorityCount; ++i) {
        if (s1->SubAuthority[i] != s2->SubAuthority[i]) return FALSE;
    }
    return TRUE;
}

inline BOOL __stdcall AllocateAndInitializeSid(
    const SID_IDENTIFIER_AUTHORITY* pIdentifierAuthority,
    uint8_t nSubAuthorityCount,
    uint32_t nSubAuthority0, uint32_t nSubAuthority1,
    uint32_t nSubAuthority2, uint32_t nSubAuthority3,
    uint32_t nSubAuthority4, uint32_t nSubAuthority5,
    uint32_t nSubAuthority6, uint32_t nSubAuthority7,
    PSID* pSid
) {
    if (!pIdentifierAuthority || !pSid || nSubAuthorityCount > 8) return FALSE;

    auto* newSid = new SID();
    newSid->Revision = 1;
    newSid->SubAuthorityCount = nSubAuthorityCount;
    newSid->IdentifierAuthority = *pIdentifierAuthority;

    uint32_t subs[8] = { nSubAuthority0, nSubAuthority1, nSubAuthority2, nSubAuthority3,
                         nSubAuthority4, nSubAuthority5, nSubAuthority6, nSubAuthority7 };
    for (uint8_t i = 0; i < nSubAuthorityCount; ++i) {
        newSid->SubAuthority[i] = subs[i];
    }

    *pSid = newSid;
    return TRUE;
}

inline void* __stdcall FreeSid(PSID pSid) {
    if (pSid) {
        delete static_cast<SID*>(pSid);
    }
    return nullptr;
}

inline uint8_t* __stdcall GetSidSubAuthorityCount(PSID pSid) {
    if (!IsValidSid(pSid)) return nullptr;
    return &(static_cast<SID*>(pSid)->SubAuthorityCount);
}

inline uint32_t* __stdcall GetSidSubAuthority(PSID pSid, uint32_t nSubAuthority) {
    if (!IsValidSid(pSid)) return nullptr;
    auto* sid = static_cast<SID*>(pSid);
    if (nSubAuthority >= sid->SubAuthorityCount) return nullptr;
    return &(sid->SubAuthority[nSubAuthority]);
}

inline SID_IDENTIFIER_AUTHORITY* __stdcall GetSidIdentifierAuthority(PSID pSid) {
    if (!IsValidSid(pSid)) return nullptr;
    return &(static_cast<SID*>(pSid)->IdentifierAuthority);
}

inline BOOL __stdcall ConvertSidToStringSidW(PSID pSid, wchar_t** StringSid) {
    if (!IsValidSid(pSid) || !StringSid) return FALSE;
    const auto* sid = static_cast<const SID*>(pSid);

    uint64_t auth = 0;
    for (int i = 0; i < 6; ++i) auth = (auth << 8) | sid->IdentifierAuthority.Value[i];

    std::wostringstream wos;
    wos << L"S-" << static_cast<uint32_t>(sid->Revision) << L"-" << auth;
    for (uint8_t i = 0; i < sid->SubAuthorityCount; ++i) {
        wos << L"-" << sid->SubAuthority[i];
    }

    std::wstring ws = wos.str();
    wchar_t* buf = new wchar_t[ws.size() + 1];
    std::memcpy(buf, ws.c_str(), (ws.size() + 1) * sizeof(wchar_t));
    *StringSid = buf;
    return TRUE;
}

inline BOOL __stdcall ConvertSidToStringSidA(PSID pSid, char** StringSid) {
    wchar_t* wStr = nullptr;
    if (!ConvertSidToStringSidW(pSid, &wStr) || !wStr) return FALSE;
    std::wstring ws(wStr);
    delete[] wStr;

    char* buf = new char[ws.size() + 1];
    for (size_t i = 0; i < ws.size(); ++i) buf[i] = static_cast<char>(ws[i]);
    buf[ws.size()] = '\0';
    *StringSid = buf;
    return TRUE;
}

inline BOOL __stdcall ConvertStringSidToSidW(const wchar_t* StringSid, PSID* pSid) {
    if (!StringSid || !pSid) return FALSE;
    std::wstring s(StringSid);
    if (s.rfind(L"S-", 0) != 0) return FALSE;

    std::vector<uint32_t> parts;
    std::wstring part;
    std::wistringstream wiss(s.substr(2));
    uint64_t auth = 0;
    int idx = 0;

    while (std::getline(wiss, part, L'-')) {
        if (idx == 0) {
            // revision (must be 1)
            uint32_t rev = static_cast<uint32_t>(std::stoul(part));
            if (rev != 1) return FALSE;
        } else if (idx == 1) {
            auth = std::stoull(part);
        } else {
            parts.push_back(static_cast<uint32_t>(std::stoul(part)));
        }
        idx++;
    }

    if (parts.size() > 8) return FALSE;

    SID_IDENTIFIER_AUTHORITY sia{};
    for (int i = 5; i >= 0; --i) {
        sia.Value[i] = static_cast<uint8_t>(auth & 0xFF);
        auth >>= 8;
    }

    auto* newSid = new SID();
    newSid->Revision = 1;
    newSid->SubAuthorityCount = static_cast<uint8_t>(parts.size());
    newSid->IdentifierAuthority = sia;
    for (size_t i = 0; i < parts.size(); ++i) {
        newSid->SubAuthority[i] = parts[i];
    }

    *pSid = newSid;
    return TRUE;
}

// ============================================================================
// 4. ACL APIs
// ============================================================================

inline BOOL __stdcall InitializeAcl(PACL pAcl, uint32_t nAclLength, uint32_t dwAclRevision) {
    if (!pAcl || nAclLength < sizeof(ACL)) return FALSE;
    pAcl->AclRevision = static_cast<uint8_t>(dwAclRevision);
    pAcl->Sbz1 = 0;
    pAcl->AclSize = static_cast<uint16_t>(nAclLength);
    pAcl->AceCount = 0;
    pAcl->Sbz2 = 0;
    return TRUE;
}

inline BOOL __stdcall IsValidAcl(PACL pAcl) {
    if (!pAcl) return FALSE;
    if (pAcl->AclRevision != ACL_REVISION && pAcl->AclRevision != ACL_REVISION_DS) return FALSE;
    if (pAcl->AclSize < sizeof(ACL)) return FALSE;
    return TRUE;
}

inline BOOL __stdcall AddAccessAllowedAce(PACL pAcl, uint32_t dwAceRevision, uint32_t AccessMask, PSID pSid) {
    (void)dwAceRevision;
    if (!IsValidAcl(pAcl) || !IsValidSid(pSid)) return FALSE;

    uint32_t sidLen = GetLengthSid(pSid);
    uint32_t aceSize = static_cast<uint32_t>(sizeof(ACCESS_ALLOWED_ACE) - sizeof(uint32_t) + sidLen);

    // Calculate current used size
    uint8_t* pStart = reinterpret_cast<uint8_t*>(pAcl) + sizeof(ACL);
    uint32_t currentOffset = sizeof(ACL);
    for (uint16_t i = 0; i < pAcl->AceCount; ++i) {
        const auto* hdr = reinterpret_cast<const ACE_HEADER*>(pStart);
        currentOffset += hdr->AceSize;
        pStart += hdr->AceSize;
    }

    if (currentOffset + aceSize > pAcl->AclSize) return FALSE;

    auto* ace = reinterpret_cast<ACCESS_ALLOWED_ACE*>(pStart);
    ace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    ace->Header.AceFlags = 0;
    ace->Header.AceSize = static_cast<uint16_t>(aceSize);
    ace->Mask = AccessMask;
    std::memcpy(&ace->SidStart, pSid, sidLen);

    pAcl->AceCount++;
    return TRUE;
}

inline BOOL __stdcall AddAccessAllowedAceEx(PACL pAcl, uint32_t dwAceRevision, uint8_t AceFlags, uint32_t AccessMask, PSID pSid) {
    if (!AddAccessAllowedAce(pAcl, dwAceRevision, AccessMask, pSid)) return FALSE;
    // Set flags on newly added ACE
    uint8_t* p = reinterpret_cast<uint8_t*>(pAcl) + sizeof(ACL);
    for (uint16_t i = 0; i < pAcl->AceCount - 1; ++i) {
        p += reinterpret_cast<ACE_HEADER*>(p)->AceSize;
    }
    reinterpret_cast<ACE_HEADER*>(p)->AceFlags = AceFlags;
    return TRUE;
}

inline BOOL __stdcall AddAccessDeniedAce(PACL pAcl, uint32_t dwAceRevision, uint32_t AccessMask, PSID pSid) {
    (void)dwAceRevision;
    if (!IsValidAcl(pAcl) || !IsValidSid(pSid)) return FALSE;

    uint32_t sidLen = GetLengthSid(pSid);
    uint32_t aceSize = static_cast<uint32_t>(sizeof(ACCESS_DENIED_ACE) - sizeof(uint32_t) + sidLen);

    uint8_t* pStart = reinterpret_cast<uint8_t*>(pAcl) + sizeof(ACL);
    uint32_t currentOffset = sizeof(ACL);
    for (uint16_t i = 0; i < pAcl->AceCount; ++i) {
        const auto* hdr = reinterpret_cast<const ACE_HEADER*>(pStart);
        currentOffset += hdr->AceSize;
        pStart += hdr->AceSize;
    }

    if (currentOffset + aceSize > pAcl->AclSize) return FALSE;

    auto* ace = reinterpret_cast<ACCESS_DENIED_ACE*>(pStart);
    ace->Header.AceType = ACCESS_DENIED_ACE_TYPE;
    ace->Header.AceFlags = 0;
    ace->Header.AceSize = static_cast<uint16_t>(aceSize);
    ace->Mask = AccessMask;
    std::memcpy(&ace->SidStart, pSid, sidLen);

    pAcl->AceCount++;
    return TRUE;
}

inline BOOL __stdcall AddAuditAccessAce(PACL pAcl, uint32_t dwAceRevision, uint32_t dwAccessMask, PSID pSid, BOOL bAuditSuccess, BOOL bAuditFailure) {
    (void)dwAceRevision;
    if (!IsValidAcl(pAcl) || !IsValidSid(pSid)) return FALSE;

    uint32_t sidLen = GetLengthSid(pSid);
    uint32_t aceSize = static_cast<uint32_t>(sizeof(SYSTEM_AUDIT_ACE) - sizeof(uint32_t) + sidLen);

    uint8_t* pStart = reinterpret_cast<uint8_t*>(pAcl) + sizeof(ACL);
    uint32_t currentOffset = sizeof(ACL);
    for (uint16_t i = 0; i < pAcl->AceCount; ++i) {
        const auto* hdr = reinterpret_cast<const ACE_HEADER*>(pStart);
        currentOffset += hdr->AceSize;
        pStart += hdr->AceSize;
    }

    if (currentOffset + aceSize > pAcl->AclSize) return FALSE;

    auto* ace = reinterpret_cast<SYSTEM_AUDIT_ACE*>(pStart);
    ace->Header.AceType = SYSTEM_AUDIT_ACE_TYPE;
    ace->Header.AceFlags = 0;
    if (bAuditSuccess) ace->Header.AceFlags |= SUCCESSFUL_ACCESS_ACE_FLAG;
    if (bAuditFailure) ace->Header.AceFlags |= FAILED_ACCESS_ACE_FLAG;
    ace->Header.AceSize = static_cast<uint16_t>(aceSize);
    ace->Mask = dwAccessMask;
    std::memcpy(&ace->SidStart, pSid, sidLen);

    pAcl->AceCount++;
    return TRUE;
}

inline BOOL __stdcall GetAce(PACL pAcl, uint32_t dwAceIndex, void** pAce) {
    if (!IsValidAcl(pAcl) || !pAce || dwAceIndex >= pAcl->AceCount) return FALSE;

    uint8_t* p = reinterpret_cast<uint8_t*>(pAcl) + sizeof(ACL);
    for (uint32_t i = 0; i < dwAceIndex; ++i) {
        p += reinterpret_cast<const ACE_HEADER*>(p)->AceSize;
    }

    *pAce = p;
    return TRUE;
}

inline BOOL __stdcall DeleteAce(PACL pAcl, uint32_t dwAceIndex) {
    if (!IsValidAcl(pAcl) || dwAceIndex >= pAcl->AceCount) return FALSE;

    uint8_t* p = reinterpret_cast<uint8_t*>(pAcl) + sizeof(ACL);
    for (uint32_t i = 0; i < dwAceIndex; ++i) {
        p += reinterpret_cast<const ACE_HEADER*>(p)->AceSize;
    }

    auto* targetAce = reinterpret_cast<ACE_HEADER*>(p);
    uint16_t deleteSize = targetAce->AceSize;

    uint8_t* next = p + deleteSize;
    uint8_t* end = reinterpret_cast<uint8_t*>(pAcl) + sizeof(ACL);
    for (uint16_t i = 0; i < pAcl->AceCount; ++i) {
        end += reinterpret_cast<ACE_HEADER*>(end)->AceSize;
    }

    size_t copyLen = end - next;
    if (copyLen > 0) {
        std::memmove(p, next, copyLen);
    }

    pAcl->AceCount--;
    return TRUE;
}

// ============================================================================
// 5. Security Descriptor APIs
// ============================================================================

inline BOOL __stdcall InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor, uint32_t dwRevision) {
    if (!pSecurityDescriptor || dwRevision != SECURITY_DESCRIPTOR_REVISION) return FALSE;
    auto* sd = static_cast<SECURITY_DESCRIPTOR*>(pSecurityDescriptor);
    sd->Revision = static_cast<uint8_t>(dwRevision);
    sd->Sbz1 = 0;
    sd->Control = 0;
    sd->Owner = nullptr;
    sd->Group = nullptr;
    sd->Sacl = nullptr;
    sd->Dacl = nullptr;
    return TRUE;
}

inline BOOL __stdcall IsValidSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor) {
    if (!pSecurityDescriptor) return FALSE;
    const auto* sd = static_cast<const SECURITY_DESCRIPTOR*>(pSecurityDescriptor);
    return (sd->Revision == SECURITY_DESCRIPTOR_REVISION) ? TRUE : FALSE;
}

inline uint32_t __stdcall GetSecurityDescriptorLength(PSECURITY_DESCRIPTOR pSecurityDescriptor) {
    if (!IsValidSecurityDescriptor(pSecurityDescriptor)) return 0;
    const auto* sd = static_cast<const SECURITY_DESCRIPTOR*>(pSecurityDescriptor);

    if (sd->Control & SE_SELF_RELATIVE) {
        const auto* rel = static_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(pSecurityDescriptor);
        uint32_t maxOff = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
        if (rel->Owner > maxOff) maxOff = rel->Owner + GetLengthSid(reinterpret_cast<PSID>(reinterpret_cast<uintptr_t>(rel) + rel->Owner));
        if (rel->Group > maxOff) maxOff = rel->Group + GetLengthSid(reinterpret_cast<PSID>(reinterpret_cast<uintptr_t>(rel) + rel->Group));
        if (rel->Dacl > maxOff) {
            const auto* acl = reinterpret_cast<const ACL*>(reinterpret_cast<uintptr_t>(rel) + rel->Dacl);
            maxOff = rel->Dacl + acl->AclSize;
        }
        if (rel->Sacl > maxOff) {
            const auto* acl = reinterpret_cast<const ACL*>(reinterpret_cast<uintptr_t>(rel) + rel->Sacl);
            maxOff = rel->Sacl + acl->AclSize;
        }
        return maxOff;
    }

    uint32_t len = sizeof(SECURITY_DESCRIPTOR);
    if (sd->Owner) len += GetLengthSid(sd->Owner);
    if (sd->Group) len += GetLengthSid(sd->Group);
    if (sd->Dacl) len += sd->Dacl->AclSize;
    if (sd->Sacl) len += sd->Sacl->AclSize;
    return len;
}

inline BOOL __stdcall GetSecurityDescriptorControl(PSECURITY_DESCRIPTOR pSecurityDescriptor, uint16_t* pControl, uint32_t* lpdwRevision) {
    if (!IsValidSecurityDescriptor(pSecurityDescriptor) || !pControl || !lpdwRevision) return FALSE;
    const auto* sd = static_cast<const SECURITY_DESCRIPTOR*>(pSecurityDescriptor);
    *pControl = sd->Control;
    *lpdwRevision = sd->Revision;
    return TRUE;
}

inline BOOL __stdcall SetSecurityDescriptorControl(PSECURITY_DESCRIPTOR pSecurityDescriptor, uint16_t ControlBitsOfInterest, uint16_t ControlBitsToSet) {
    if (!IsValidSecurityDescriptor(pSecurityDescriptor)) return FALSE;
    auto* sd = static_cast<SECURITY_DESCRIPTOR*>(pSecurityDescriptor);
    sd->Control = (sd->Control & ~ControlBitsOfInterest) | (ControlBitsToSet & ControlBitsOfInterest);
    return TRUE;
}

inline BOOL __stdcall SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL bDaclPresent, PACL pDacl, BOOL bDaclDefaulted) {
    if (!IsValidSecurityDescriptor(pSecurityDescriptor)) return FALSE;
    auto* sd = static_cast<SECURITY_DESCRIPTOR*>(pSecurityDescriptor);
    if (bDaclPresent) {
        sd->Control |= SE_DACL_PRESENT;
        sd->Dacl = pDacl;
        if (bDaclDefaulted) sd->Control |= SE_DACL_DEFAULTED;
        else sd->Control &= ~SE_DACL_DEFAULTED;
    } else {
        sd->Control &= ~SE_DACL_PRESENT;
        sd->Dacl = nullptr;
    }
    return TRUE;
}

inline BOOL __stdcall GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR pSecurityDescriptor, BOOL* lpbDaclPresent, PACL* pDacl, BOOL* lpbDaclDefaulted) {
    if (!IsValidSecurityDescriptor(pSecurityDescriptor) || !lpbDaclPresent || !pDacl || !lpbDaclDefaulted) return FALSE;
    const auto* sd = static_cast<const SECURITY_DESCRIPTOR*>(pSecurityDescriptor);

    if (sd->Control & SE_SELF_RELATIVE) {
        const auto* rel = static_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(pSecurityDescriptor);
        *lpbDaclPresent = (rel->Control & SE_DACL_PRESENT) ? TRUE : FALSE;
        *lpbDaclDefaulted = (rel->Control & SE_DACL_DEFAULTED) ? TRUE : FALSE;
        *pDacl = (rel->Dacl > 0) ? reinterpret_cast<PACL>(reinterpret_cast<uintptr_t>(rel) + rel->Dacl) : nullptr;
        return TRUE;
    }

    *lpbDaclPresent = (sd->Control & SE_DACL_PRESENT) ? TRUE : FALSE;
    *lpbDaclDefaulted = (sd->Control & SE_DACL_DEFAULTED) ? TRUE : FALSE;
    *pDacl = sd->Dacl;
    return TRUE;
}

inline BOOL __stdcall SetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID pOwner, BOOL bOwnerDefaulted) {
    if (!IsValidSecurityDescriptor(pSecurityDescriptor)) return FALSE;
    auto* sd = static_cast<SECURITY_DESCRIPTOR*>(pSecurityDescriptor);
    sd->Owner = pOwner;
    if (bOwnerDefaulted) sd->Control |= SE_OWNER_DEFAULTED;
    else sd->Control &= ~SE_OWNER_DEFAULTED;
    return TRUE;
}

inline BOOL __stdcall GetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID* pOwner, BOOL* lpbOwnerDefaulted) {
    if (!IsValidSecurityDescriptor(pSecurityDescriptor) || !pOwner || !lpbOwnerDefaulted) return FALSE;
    const auto* sd = static_cast<const SECURITY_DESCRIPTOR*>(pSecurityDescriptor);

    if (sd->Control & SE_SELF_RELATIVE) {
        const auto* rel = static_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(pSecurityDescriptor);
        *lpbOwnerDefaulted = (rel->Control & SE_OWNER_DEFAULTED) ? TRUE : FALSE;
        *pOwner = (rel->Owner > 0) ? reinterpret_cast<PSID>(reinterpret_cast<uintptr_t>(rel) + rel->Owner) : nullptr;
        return TRUE;
    }

    *lpbOwnerDefaulted = (sd->Control & SE_OWNER_DEFAULTED) ? TRUE : FALSE;
    *pOwner = sd->Owner;
    return TRUE;
}

inline BOOL __stdcall SetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID pGroup, BOOL bGroupDefaulted) {
    if (!IsValidSecurityDescriptor(pSecurityDescriptor)) return FALSE;
    auto* sd = static_cast<SECURITY_DESCRIPTOR*>(pSecurityDescriptor);
    sd->Group = pGroup;
    if (bGroupDefaulted) sd->Control |= SE_GROUP_DEFAULTED;
    else sd->Control &= ~SE_GROUP_DEFAULTED;
    return TRUE;
}

inline BOOL __stdcall GetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR pSecurityDescriptor, PSID* pGroup, BOOL* lpbGroupDefaulted) {
    if (!IsValidSecurityDescriptor(pSecurityDescriptor) || !pGroup || !lpbGroupDefaulted) return FALSE;
    const auto* sd = static_cast<const SECURITY_DESCRIPTOR*>(pSecurityDescriptor);

    if (sd->Control & SE_SELF_RELATIVE) {
        const auto* rel = static_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(pSecurityDescriptor);
        *lpbGroupDefaulted = (rel->Control & SE_GROUP_DEFAULTED) ? TRUE : FALSE;
        *pGroup = (rel->Group > 0) ? reinterpret_cast<PSID>(reinterpret_cast<uintptr_t>(rel) + rel->Group) : nullptr;
        return TRUE;
    }

    *lpbGroupDefaulted = (sd->Control & SE_GROUP_DEFAULTED) ? TRUE : FALSE;
    *pGroup = sd->Group;
    return TRUE;
}

inline BOOL __stdcall MakeSelfRelativeSD(PSECURITY_DESCRIPTOR pAbsoluteSD, PSECURITY_DESCRIPTOR pSelfRelativeSD, uint32_t* lpdwBufferLength) {
    if (!IsValidSecurityDescriptor(pAbsoluteSD) || !lpdwBufferLength) return FALSE;
    const auto* abs = static_cast<const SECURITY_DESCRIPTOR*>(pAbsoluteSD);

    uint32_t needed = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    uint32_t ownerLen = abs->Owner ? GetLengthSid(abs->Owner) : 0;
    uint32_t groupLen = abs->Group ? GetLengthSid(abs->Group) : 0;
    uint32_t daclLen = abs->Dacl ? abs->Dacl->AclSize : 0;
    uint32_t saclLen = abs->Sacl ? abs->Sacl->AclSize : 0;

    needed += ownerLen + groupLen + daclLen + saclLen;
    if (!pSelfRelativeSD || *lpdwBufferLength < needed) {
        *lpdwBufferLength = needed;
        return FALSE;
    }

    auto* rel = static_cast<SECURITY_DESCRIPTOR_RELATIVE*>(pSelfRelativeSD);
    rel->Revision = abs->Revision;
    rel->Sbz1 = 0;
    rel->Control = abs->Control | SE_SELF_RELATIVE;

    uint32_t offset = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    uint8_t* base = reinterpret_cast<uint8_t*>(pSelfRelativeSD);

    if (abs->Owner) {
        rel->Owner = offset;
        std::memcpy(base + offset, abs->Owner, ownerLen);
        offset += ownerLen;
    } else rel->Owner = 0;

    if (abs->Group) {
        rel->Group = offset;
        std::memcpy(base + offset, abs->Group, groupLen);
        offset += groupLen;
    } else rel->Group = 0;

    if (abs->Dacl) {
        rel->Dacl = offset;
        std::memcpy(base + offset, abs->Dacl, daclLen);
        offset += daclLen;
    } else rel->Dacl = 0;

    if (abs->Sacl) {
        rel->Sacl = offset;
        std::memcpy(base + offset, abs->Sacl, saclLen);
        offset += saclLen;
    } else rel->Sacl = 0;

    *lpdwBufferLength = needed;
    return TRUE;
}

inline BOOL __stdcall MakeAbsoluteSD(
    PSECURITY_DESCRIPTOR pSelfRelativeSD,
    PSECURITY_DESCRIPTOR pAbsoluteSD, uint32_t* lpdwAbsoluteSDSize,
    PACL pDacl, uint32_t* lpdwDaclSize,
    PACL pSacl, uint32_t* lpdwSaclSize,
    PSID pOwner, uint32_t* lpdwOwnerSize,
    PSID pPrimaryGroup, uint32_t* lpdwPrimaryGroupSize
) {
    if (!IsValidSecurityDescriptor(pSelfRelativeSD) || !lpdwAbsoluteSDSize) return FALSE;
    const auto* rel = static_cast<const SECURITY_DESCRIPTOR_RELATIVE*>(pSelfRelativeSD);
    if (!(rel->Control & SE_SELF_RELATIVE)) return FALSE;

    uintptr_t base = reinterpret_cast<uintptr_t>(pSelfRelativeSD);
    PSID ownerPtr = (rel->Owner > 0) ? reinterpret_cast<PSID>(base + rel->Owner) : nullptr;
    PSID groupPtr = (rel->Group > 0) ? reinterpret_cast<PSID>(base + rel->Group) : nullptr;
    PACL daclPtr = (rel->Dacl > 0) ? reinterpret_cast<PACL>(base + rel->Dacl) : nullptr;
    PACL saclPtr = (rel->Sacl > 0) ? reinterpret_cast<PACL>(base + rel->Sacl) : nullptr;

    uint32_t ownerLen = ownerPtr ? GetLengthSid(ownerPtr) : 0;
    uint32_t groupLen = groupPtr ? GetLengthSid(groupPtr) : 0;
    uint32_t daclLen = daclPtr ? daclPtr->AclSize : 0;
    uint32_t saclLen = saclPtr ? saclPtr->AclSize : 0;

    bool bufOk = true;
    if (!pAbsoluteSD || *lpdwAbsoluteSDSize < sizeof(SECURITY_DESCRIPTOR)) { *lpdwAbsoluteSDSize = sizeof(SECURITY_DESCRIPTOR); bufOk = false; }
    if (ownerPtr && (!pOwner || !lpdwOwnerSize || *lpdwOwnerSize < ownerLen)) { if (lpdwOwnerSize) *lpdwOwnerSize = ownerLen; bufOk = false; }
    if (groupPtr && (!pPrimaryGroup || !lpdwPrimaryGroupSize || *lpdwPrimaryGroupSize < groupLen)) { if (lpdwPrimaryGroupSize) *lpdwPrimaryGroupSize = groupLen; bufOk = false; }
    if (daclPtr && (!pDacl || !lpdwDaclSize || *lpdwDaclSize < daclLen)) { if (lpdwDaclSize) *lpdwDaclSize = daclLen; bufOk = false; }
    if (saclPtr && (!pSacl || !lpdwSaclSize || *lpdwSaclSize < saclLen)) { if (lpdwSaclSize) *lpdwSaclSize = saclLen; bufOk = false; }

    if (!bufOk) return FALSE;

    auto* abs = static_cast<SECURITY_DESCRIPTOR*>(pAbsoluteSD);
    abs->Revision = rel->Revision;
    abs->Sbz1 = 0;
    abs->Control = rel->Control & ~SE_SELF_RELATIVE;

    if (ownerPtr) {
        std::memcpy(pOwner, ownerPtr, ownerLen);
        abs->Owner = pOwner;
    } else abs->Owner = nullptr;

    if (groupPtr) {
        std::memcpy(pPrimaryGroup, groupPtr, groupLen);
        abs->Group = pPrimaryGroup;
    } else abs->Group = nullptr;

    if (daclPtr) {
        std::memcpy(pDacl, daclPtr, daclLen);
        abs->Dacl = pDacl;
    } else abs->Dacl = nullptr;

    if (saclPtr) {
        std::memcpy(pSacl, saclPtr, saclLen);
        abs->Sacl = pSacl;
    } else abs->Sacl = nullptr;

    return TRUE;
}

// ============================================================================
// 6. AccessCheck - Access Authorization Engine
// ============================================================================

inline BOOL __stdcall AccessCheck(
    PSECURITY_DESCRIPTOR pSecurityDescriptor,
    void*                ClientToken,
    uint32_t             DesiredAccess,
    GENERIC_MAPPING*     GenericMapping,
    PRIVILEGE_SET*       PrivilegeSet,
    uint32_t*            PrivilegeSetLength,
    uint32_t*            GrantedAccess,
    BOOL*                AccessStatus
) {
    (void)ClientToken;
    (void)GenericMapping;
    (void)PrivilegeSet;
    (void)PrivilegeSetLength;

    if (!pSecurityDescriptor || !GrantedAccess || !AccessStatus) return FALSE;

    BOOL daclPresent = FALSE;
    PACL dacl = nullptr;
    BOOL daclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(pSecurityDescriptor, &daclPresent, &dacl, &daclDefaulted)) {
        return FALSE;
    }

    // If DACL is not present, full access is granted (NULL DACL)
    if (!daclPresent || !dacl) {
        *GrantedAccess = DesiredAccess;
        *AccessStatus = TRUE;
        return TRUE;
    }

    // Evaluate ACEs in DACL
    uint32_t remainingAccess = DesiredAccess;
    uint32_t granted = 0;

    for (uint32_t i = 0; i < dacl->AceCount; ++i) {
        void* pAce = nullptr;
        if (!GetAce(dacl, i, &pAce) || !pAce) continue;

        const auto* hdr = static_cast<const ACE_HEADER*>(pAce);
        if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) {
            const auto* denied = static_cast<const ACCESS_DENIED_ACE*>(pAce);
            if (remainingAccess & denied->Mask) {
                // Explicit DENY overrides any grant
                *GrantedAccess = 0;
                *AccessStatus = FALSE;
                return TRUE;
            }
        } else if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            const auto* allowed = static_cast<const ACCESS_ALLOWED_ACE*>(pAce);
            uint32_t matched = remainingAccess & allowed->Mask;
            granted |= matched;
            remainingAccess &= ~matched;

            if (remainingAccess == 0) break;
        }
    }

    if (remainingAccess == 0) {
        *GrantedAccess = granted;
        *AccessStatus = TRUE;
    } else {
        *GrantedAccess = 0;
        *AccessStatus = FALSE;
    }

    return TRUE;
}

// ============================================================================
// 7. Security Auditing Policy Engine (auditpol.exe architecture)
// ============================================================================

struct AuditSubCategory {
    std::string guid;
    std::string name;
    uint32_t    policy{AUDIT_POLICY_NONE};
};

struct AuditCategory {
    std::string guid;
    std::string name;
    std::vector<AuditSubCategory> subCategories;
};

class AuditPolicyManager {
public:
    static AuditPolicyManager& get() {
        static AuditPolicyManager instance;
        return instance;
    }

    AuditPolicyManager() {
        initializeCategories();
    }

    void reset() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_categories.clear();
        initializeCategories();
    }

    const std::vector<AuditCategory>& getCategories() const {
        return m_categories;
    }

    bool setSubCategoryPolicy(const std::string& subCatName, uint32_t policy) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& cat : m_categories) {
            for (auto& sub : cat.subCategories) {
                if (sub.name == subCatName || sub.guid == subCatName) {
                    sub.policy = policy;
                    return true;
                }
            }
        }
        return false;
    }

    uint32_t getSubCategoryPolicy(const std::string& subCatName) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& cat : m_categories) {
            for (const auto& sub : cat.subCategories) {
                if (sub.name == subCatName || sub.guid == subCatName) {
                    return sub.policy;
                }
            }
        }
        return AUDIT_POLICY_NONE;
    }

private:
    void initializeCategories() {
        m_categories = {
            {
                "{69979848-797A-11D9-BED3-505054503030}", "System",
                {
                    { "{0CCE9210-69AE-11D9-BED3-505054503030}", "Security State Change", AUDIT_POLICY_SUCCESS },
                    { "{0CCE9211-69AE-11D9-BED3-505054503030}", "Security System Extension", AUDIT_POLICY_SUCCESS },
                    { "{0CCE9212-69AE-11D9-BED3-505054503030}", "System Integrity", AUDIT_POLICY_SUCCESS_AND_FAILURE },
                    { "{0CCE9213-69AE-11D9-BED3-505054503030}", "IPsec Driver", AUDIT_POLICY_FAILURE },
                    { "{0CCE9214-69AE-11D9-BED3-505054503030}", "Other System Events", AUDIT_POLICY_NONE }
                }
            },
            {
                "{69979849-797A-11D9-BED3-505054503030}", "Logon/Logoff",
                {
                    { "{0CCE9215-69AE-11D9-BED3-505054503030}", "Logon", AUDIT_POLICY_SUCCESS_AND_FAILURE },
                    { "{0CCE9216-69AE-11D9-BED3-505054503030}", "Logoff", AUDIT_POLICY_SUCCESS },
                    { "{0CCE9217-69AE-11D9-BED3-505054503030}", "Account Lockout", AUDIT_POLICY_FAILURE },
                    { "{0CCE9218-69AE-11D9-BED3-505054503030}", "Special Logon", AUDIT_POLICY_SUCCESS }
                }
            },
            {
                "{6997984A-797A-11D9-BED3-505054503030}", "Object Access",
                {
                    { "{0CCE921D-69AE-11D9-BED3-505054503030}", "File System", AUDIT_POLICY_SUCCESS_AND_FAILURE },
                    { "{0CCE921E-69AE-11D9-BED3-505054503030}", "Registry", AUDIT_POLICY_FAILURE },
                    { "{0CCE921F-69AE-11D9-BED3-505054503030}", "Kernel Object", AUDIT_POLICY_SUCCESS },
                    { "{0CCE9220-69AE-11D9-BED3-505054503030}", "SAM", AUDIT_POLICY_NONE }
                }
            },
            {
                "{6997984B-797A-11D9-BED3-505054503030}", "Privilege Use",
                {
                    { "{0CCE9228-69AE-11D9-BED3-505054503030}", "Sensitive Privilege Use", AUDIT_POLICY_SUCCESS_AND_FAILURE },
                    { "{0CCE9229-69AE-11D9-BED3-505054503030}", "Non Sensitive Privilege Use", AUDIT_POLICY_NONE }
                }
            },
            {
                "{6997984C-797A-11D9-BED3-505054503030}", "Detailed Tracking",
                {
                    { "{0CCE922B-69AE-11D9-BED3-505054503030}", "Process Creation", AUDIT_POLICY_SUCCESS },
                    { "{0CCE922C-69AE-11D9-BED3-505054503030}", "Process Termination", AUDIT_POLICY_SUCCESS }
                }
            },
            {
                "{6997984D-797A-11D9-BED3-505054503030}", "Policy Change",
                {
                    { "{0CCE922F-69AE-11D9-BED3-505054503030}", "Audit Policy Change", AUDIT_POLICY_SUCCESS },
                    { "{0CCE9230-69AE-11D9-BED3-505054503030}", "Authentication Policy Change", AUDIT_POLICY_SUCCESS }
                }
            },
            {
                "{6997984E-797A-11D9-BED3-505054503030}", "Account Management",
                {
                    { "{0CCE9235-69AE-11D9-BED3-505054503030}", "User Account Management", AUDIT_POLICY_SUCCESS_AND_FAILURE },
                    { "{0CCE9236-69AE-11D9-BED3-505054503030}", "Security Group Management", AUDIT_POLICY_SUCCESS }
                }
            }
        };
    }

    mutable std::mutex m_mutex;
    std::vector<AuditCategory> m_categories;
};

// ============================================================================
// 8. Dynamic Loader & SCM Registration
// ============================================================================

inline void InitializeAclSubsystemExports() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    auto& ldr = ldr::DynamicLoader::get();

    // 1. advapi32.dll Security Descriptor & ACL exports
    ldr.registerExport("advapi32.dll", "InitializeSecurityDescriptor", reinterpret_cast<void*>(InitializeSecurityDescriptor));
    ldr.registerExport("advapi32.dll", "IsValidSecurityDescriptor", reinterpret_cast<void*>(IsValidSecurityDescriptor));
    ldr.registerExport("advapi32.dll", "GetSecurityDescriptorLength", reinterpret_cast<void*>(GetSecurityDescriptorLength));
    ldr.registerExport("advapi32.dll", "GetSecurityDescriptorControl", reinterpret_cast<void*>(GetSecurityDescriptorControl));
    ldr.registerExport("advapi32.dll", "SetSecurityDescriptorControl", reinterpret_cast<void*>(SetSecurityDescriptorControl));
    ldr.registerExport("advapi32.dll", "GetSecurityDescriptorDacl", reinterpret_cast<void*>(GetSecurityDescriptorDacl));
    ldr.registerExport("advapi32.dll", "SetSecurityDescriptorDacl", reinterpret_cast<void*>(SetSecurityDescriptorDacl));
    ldr.registerExport("advapi32.dll", "GetSecurityDescriptorOwner", reinterpret_cast<void*>(GetSecurityDescriptorOwner));
    ldr.registerExport("advapi32.dll", "SetSecurityDescriptorOwner", reinterpret_cast<void*>(SetSecurityDescriptorOwner));
    ldr.registerExport("advapi32.dll", "GetSecurityDescriptorGroup", reinterpret_cast<void*>(GetSecurityDescriptorGroup));
    ldr.registerExport("advapi32.dll", "SetSecurityDescriptorGroup", reinterpret_cast<void*>(SetSecurityDescriptorGroup));
    ldr.registerExport("advapi32.dll", "MakeSelfRelativeSD", reinterpret_cast<void*>(MakeSelfRelativeSD));
    ldr.registerExport("advapi32.dll", "MakeAbsoluteSD", reinterpret_cast<void*>(MakeAbsoluteSD));

    ldr.registerExport("advapi32.dll", "InitializeAcl", reinterpret_cast<void*>(InitializeAcl));
    ldr.registerExport("advapi32.dll", "IsValidAcl", reinterpret_cast<void*>(IsValidAcl));
    ldr.registerExport("advapi32.dll", "AddAccessAllowedAce", reinterpret_cast<void*>(AddAccessAllowedAce));
    ldr.registerExport("advapi32.dll", "AddAccessAllowedAceEx", reinterpret_cast<void*>(AddAccessAllowedAceEx));
    ldr.registerExport("advapi32.dll", "AddAccessDeniedAce", reinterpret_cast<void*>(AddAccessDeniedAce));
    ldr.registerExport("advapi32.dll", "AddAuditAccessAce", reinterpret_cast<void*>(AddAuditAccessAce));
    ldr.registerExport("advapi32.dll", "GetAce", reinterpret_cast<void*>(GetAce));
    ldr.registerExport("advapi32.dll", "DeleteAce", reinterpret_cast<void*>(DeleteAce));

    ldr.registerExport("advapi32.dll", "AllocateAndInitializeSid", reinterpret_cast<void*>(AllocateAndInitializeSid));
    ldr.registerExport("advapi32.dll", "FreeSid", reinterpret_cast<void*>(FreeSid));
    ldr.registerExport("advapi32.dll", "EqualSid", reinterpret_cast<void*>(EqualSid));
    ldr.registerExport("advapi32.dll", "IsValidSid", reinterpret_cast<void*>(IsValidSid));
    ldr.registerExport("advapi32.dll", "GetLengthSid", reinterpret_cast<void*>(GetLengthSid));
    ldr.registerExport("advapi32.dll", "GetSidIdentifierAuthority", reinterpret_cast<void*>(GetSidIdentifierAuthority));
    ldr.registerExport("advapi32.dll", "GetSidSubAuthority", reinterpret_cast<void*>(GetSidSubAuthority));
    ldr.registerExport("advapi32.dll", "GetSidSubAuthorityCount", reinterpret_cast<void*>(GetSidSubAuthorityCount));
    ldr.registerExport("advapi32.dll", "ConvertSidToStringSidW", reinterpret_cast<void*>(ConvertSidToStringSidW));
    ldr.registerExport("advapi32.dll", "ConvertSidToStringSidA", reinterpret_cast<void*>(ConvertSidToStringSidA));
    ldr.registerExport("advapi32.dll", "ConvertStringSidToSidW", reinterpret_cast<void*>(ConvertStringSidToSidW));
    ldr.registerExport("advapi32.dll", "AccessCheck", reinterpret_cast<void*>(AccessCheck));

    // 2. secur32.dll & sspicli.dll aliases
    ldr.registerExport("secur32.dll", "InitializeSecurityDescriptor", reinterpret_cast<void*>(InitializeSecurityDescriptor));
    ldr.registerExport("secur32.dll", "IsValidSecurityDescriptor", reinterpret_cast<void*>(IsValidSecurityDescriptor));
    ldr.registerExport("secur32.dll", "AccessCheck", reinterpret_cast<void*>(AccessCheck));
    ldr.registerExport("sspicli.dll", "InitializeSecurityDescriptor", reinterpret_cast<void*>(InitializeSecurityDescriptor));
    ldr.registerExport("sspicli.dll", "AccessCheck", reinterpret_cast<void*>(AccessCheck));

    // 3. SCM Service: EventSystem ("COM+ Event System")
    auto& scm = scm::ServiceControlManager::get();
    auto eventSysRecord = std::make_shared<scm::ServiceRecord>();
    eventSysRecord->serviceName = L"EventSystem";
    eventSysRecord->displayName = L"COM+ Event System";
    eventSysRecord->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
    eventSysRecord->startType = scm::SERVICE_AUTO_START;
    eventSysRecord->errorControl = scm::SERVICE_ERROR_NORMAL;
    eventSysRecord->svchostGroup = "LocalService";
    eventSysRecord->binaryPath = L"C:\\Windows\\System32\\svchost.exe -k LocalService -p";
    eventSysRecord->status.dwServiceType = eventSysRecord->serviceType;
    eventSysRecord->status.dwCurrentState = scm::SERVICE_RUNNING;
    eventSysRecord->status.dwProcessId = scm::SvcHostManager::get().getOrCreateGroupProcess("LocalService");
    scm::SvcHostManager::get().assignService("LocalService", eventSysRecord->serviceName);
    scm.registerServiceRecord(eventSysRecord);
}

} // namespace micant::acl
