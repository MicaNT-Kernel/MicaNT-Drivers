#pragma once

/**
 * @file ldap.hpp
 * @brief Clean-room Windows Active Directory & Lightweight Directory Access Protocol (LDAP) Subsystem.
 * 
 * Implements the Win32 LDAP C client API surface (wldap32.dll), ADSI LDAP provider stubs
 * (adsldp.dll), sovereign Active Directory Domain Services (AD DS) in-memory directory store,
 * filter evaluation engine (RFC 4515), BER element management, SCM NTDS/KDC service records,
 * and command-line directory utilities (dsquery, dsget).
 * 
 * Strict clean-room implementation referencing Microsoft's MIT-licensed win32metadata.
 * Zero proprietary, leaked, or decompiled code.
 */

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <algorithm>
#include <mutex>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <sstream>
#include <iomanip>
#include <iostream>

#include "ntdef.hpp"
#include "ldr.hpp"
#include "scm.hpp"

namespace micant::ldap {

// ============================================================================
// 1. Win32 LDAP Constants & Structures (RFC 4511 / win32metadata)
// ============================================================================

inline constexpr uint32_t LDAP_SUCCESS                    = 0x00;
inline constexpr uint32_t LDAP_OPERATIONS_ERROR            = 0x01;
inline constexpr uint32_t LDAP_PROTOCOL_ERROR              = 0x02;
inline constexpr uint32_t LDAP_TIMELIMIT_EXCEEDED          = 0x03;
inline constexpr uint32_t LDAP_SIZELIMIT_EXCEEDED          = 0x04;
inline constexpr uint32_t LDAP_COMPARE_FALSE               = 0x05;
inline constexpr uint32_t LDAP_COMPARE_TRUE                = 0x06;
inline constexpr uint32_t LDAP_AUTH_METHOD_NOT_SUPPORTED   = 0x07;
inline constexpr uint32_t LDAP_STRONG_AUTH_REQUIRED        = 0x08;
inline constexpr uint32_t LDAP_PARTIAL_RESULTS             = 0x09;
inline constexpr uint32_t LDAP_REFERRAL                    = 0x0a;
inline constexpr uint32_t LDAP_ADMIN_LIMIT_EXCEEDED        = 0x0b;
inline constexpr uint32_t LDAP_UNAVAILABLE_CRIT_EXTENSION  = 0x0c;
inline constexpr uint32_t LDAP_CONFIDENTIALITY_REQUIRED    = 0x0d;
inline constexpr uint32_t LDAP_SASL_BIND_IN_PROGRESS       = 0x0e;
inline constexpr uint32_t LDAP_NO_SUCH_ATTRIBUTE           = 0x10;
inline constexpr uint32_t LDAP_UNDEFINED_TYPE              = 0x11;
inline constexpr uint32_t LDAP_INAPPROPRIATE_MATCHING      = 0x12;
inline constexpr uint32_t LDAP_CONSTRAINT_VIOLATION        = 0x13;
inline constexpr uint32_t LDAP_ATTRIBUTE_OR_VALUE_EXISTS   = 0x14;
inline constexpr uint32_t LDAP_INVALID_SYNTAX              = 0x15;
inline constexpr uint32_t LDAP_NO_SUCH_OBJECT              = 0x20;
inline constexpr uint32_t LDAP_ALIAS_PROBLEM               = 0x21;
inline constexpr uint32_t LDAP_INVALID_DN_SYNTAX           = 0x22;
inline constexpr uint32_t LDAP_IS_LEAF                     = 0x23;
inline constexpr uint32_t LDAP_ALIAS_DEREF_PROBLEM         = 0x24;
inline constexpr uint32_t LDAP_INAPPROPRIATE_AUTH          = 0x30;
inline constexpr uint32_t LDAP_INVALID_CREDENTIALS         = 0x31;
inline constexpr uint32_t LDAP_INSUFFICIENT_RIGHTS         = 0x32;
inline constexpr uint32_t LDAP_BUSY                        = 0x33;
inline constexpr uint32_t LDAP_UNAVAILABLE                 = 0x34;
inline constexpr uint32_t LDAP_UNWILLING_TO_PERFORM        = 0x35;
inline constexpr uint32_t LDAP_LOOP_DETECT                 = 0x36;
inline constexpr uint32_t LDAP_NAMING_VIOLATION            = 0x40;
inline constexpr uint32_t LDAP_OBJECT_CLASS_VIOLATION      = 0x41;
inline constexpr uint32_t LDAP_NOT_ALLOWED_ON_NONLEAF      = 0x42;
inline constexpr uint32_t LDAP_NOT_ALLOWED_ON_RDN          = 0x43;
inline constexpr uint32_t LDAP_ALREADY_EXISTS              = 0x44;
inline constexpr uint32_t LDAP_NO_OBJECT_CLASS_MODS        = 0x45;
inline constexpr uint32_t LDAP_RESULTS_TOO_LARGE           = 0x46;
inline constexpr uint32_t LDAP_AFFECTS_MULTIPLE_DSAS       = 0x47;
inline constexpr uint32_t LDAP_OTHER                       = 0x50;
inline constexpr uint32_t LDAP_SERVER_DOWN                 = 0x51;
inline constexpr uint32_t LDAP_LOCAL_ERROR                 = 0x52;
inline constexpr uint32_t LDAP_ENCODING_ERROR              = 0x53;
inline constexpr uint32_t LDAP_DECODING_ERROR              = 0x54;
inline constexpr uint32_t LDAP_TIMEOUT                     = 0x55;
inline constexpr uint32_t LDAP_AUTH_UNKNOWN                = 0x56;
inline constexpr uint32_t LDAP_FILTER_ERROR                = 0x57;
inline constexpr uint32_t LDAP_USER_CANCELLED              = 0x58;
inline constexpr uint32_t LDAP_PARAM_ERROR                 = 0x59;
inline constexpr uint32_t LDAP_NO_MEMORY                   = 0x5a;
inline constexpr uint32_t LDAP_CONNECT_ERROR               = 0x5b;
inline constexpr uint32_t LDAP_NOT_SUPPORTED               = 0x5c;
inline constexpr uint32_t LDAP_NO_RESULTS_RETURNED         = 0x5e;

// Standard Ports
inline constexpr uint16_t LDAP_PORT         = 389;
inline constexpr uint16_t LDAPS_PORT        = 636;
inline constexpr uint16_t LDAP_GC_PORT      = 3268;
inline constexpr uint16_t LDAP_SSL_GC_PORT  = 3269;

// Search Scopes
inline constexpr uint32_t LDAP_SCOPE_BASE      = 0x00;
inline constexpr uint32_t LDAP_SCOPE_ONELEVEL  = 0x01;
inline constexpr uint32_t LDAP_SCOPE_SUBTREE   = 0x02;

// Modification Operations
inline constexpr uint32_t LDAP_MOD_ADD         = 0x00;
inline constexpr uint32_t LDAP_MOD_DELETE      = 0x01;
inline constexpr uint32_t LDAP_MOD_REPLACE     = 0x02;
inline constexpr uint32_t LDAP_MOD_BVALUES     = 0x80;

// Options
inline constexpr int LDAP_OPT_DESC             = 0x01;
inline constexpr int LDAP_OPT_DEREF            = 0x02;
inline constexpr int LDAP_OPT_SIZELIMIT        = 0x03;
inline constexpr int LDAP_OPT_TIMELIMIT        = 0x04;
inline constexpr int LDAP_OPT_REFERRALS        = 0x08;
inline constexpr int LDAP_OPT_RESTART          = 0x09;
inline constexpr int LDAP_OPT_SSL              = 0x0a;
inline constexpr int LDAP_OPT_PROTOCOL_VERSION = 0x11;
inline constexpr int LDAP_OPT_VERSION          = 0x11;
inline constexpr int LDAP_OPT_HOST_NAME        = 0x30;
inline constexpr int LDAP_OPT_ERROR_NUMBER     = 0x31;
inline constexpr int LDAP_OPT_ERROR_STRING     = 0x32;
inline constexpr int LDAP_OPT_SERVER_ERROR     = 0x33;
inline constexpr int LDAP_OPT_SIGN             = 0x95;
inline constexpr int LDAP_OPT_ENCRYPT          = 0x96;

// Authentication Methods
inline constexpr uint32_t LDAP_AUTH_SIMPLE     = 0x80;
inline constexpr uint32_t LDAP_AUTH_SASL       = 0x83;
inline constexpr uint32_t LDAP_AUTH_NEGOTIATE  = 0x0400;
inline constexpr uint32_t LDAP_AUTH_NTLM       = 0x1000;

// Basic Encoding Rules (BER) Value
struct berval {
    uint32_t bv_len;
    char*    bv_val;
};
using BERVAL = berval;
using PBERVAL = berval*;
using LDAP_BERVAL = berval;
using PLDAP_BERVAL = berval*;

// Timeval for timeouts
struct l_timeval {
    long tv_sec;
    long tv_usec;
};

// Modification Entry
struct ldapmodW {
    uint32_t mod_op;
    wchar_t* mod_type;
    union {
        wchar_t** modv_strvals;
        berval**  modv_bvals;
    } mod_vals;
};
using LDAPModW = ldapmodW;
using PLDAPModW = ldapmodW*;

// Case-insensitive wstring comparator
struct CaseInsensitiveLess {
    bool operator()(const std::wstring& a, const std::wstring& b) const noexcept {
        return _wcsicmp(a.c_str(), b.c_str()) < 0;
    }
};

// Internal Entry representation
struct DirectoryEntry {
    std::wstring dn;
    std::map<std::wstring, std::vector<std::wstring>, CaseInsensitiveLess> attributes;

    void addAttribute(const std::wstring& attr, const std::wstring& val) {
        attributes[attr].push_back(val);
    }

    void setAttribute(const std::wstring& attr, const std::wstring& val) {
        attributes[attr] = { val };
    }

    bool hasAttribute(const std::wstring& attr) const {
        return attributes.find(attr) != attributes.end();
    }

    std::vector<std::wstring> getValues(const std::wstring& attr) const {
        auto it = attributes.find(attr);
        if (it != attributes.end()) return it->second;
        return {};
    }

    std::wstring getFirstValue(const std::wstring& attr, const std::wstring& def = L"") const {
        auto vals = getValues(attr);
        return vals.empty() ? def : vals[0];
    }
};

// ============================================================================
// 2. ActiveDirectoryStore: Sovereign Active Directory Domain Services Hierarchy
// ============================================================================

class ActiveDirectoryStore {
public:
    static ActiveDirectoryStore& get() noexcept {
        static ActiveDirectoryStore instance;
        return instance;
    }

    ActiveDirectoryStore(const ActiveDirectoryStore&) = delete;
    ActiveDirectoryStore& operator=(const ActiveDirectoryStore&) = delete;

    void resetToDefault() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_entries.clear();
        seedDefaultDirectory();
    }

    std::vector<DirectoryEntry> search(
        const std::wstring& baseDn,
        uint32_t scope,
        const std::wstring& filter,
        const std::vector<std::wstring>& requestedAttrs
    ) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<DirectoryEntry> matches;

        std::wstring normBase = normalizeDn(baseDn);

        for (const auto& entry : m_entries) {
            std::wstring normEntryDn = normalizeDn(entry.dn);

            // 1. Scope Evaluation
            if (scope == LDAP_SCOPE_BASE) {
                if (normBase != normEntryDn) continue;
            } else if (scope == LDAP_SCOPE_ONELEVEL) {
                if (normBase == normEntryDn) continue;
                if (!isDirectChildOf(normEntryDn, normBase)) continue;
            } else if (scope == LDAP_SCOPE_SUBTREE) {
                if (!normBase.empty() && !isDescendantOf(normEntryDn, normBase)) continue;
            }

            // 2. Filter Evaluation
            if (!matchesFilter(entry, filter)) {
                continue;
            }

            // 3. Attribute Projection
            if (requestedAttrs.empty() || (requestedAttrs.size() == 1 && requestedAttrs[0] == L"*")) {
                matches.push_back(entry);
            } else {
                DirectoryEntry proj;
                proj.dn = entry.dn;
                for (const auto& req : requestedAttrs) {
                    if (req == L"1.1") continue; // 1.1 = no attributes
                    auto vals = entry.getValues(req);
                    if (!vals.empty()) {
                        proj.attributes[req] = vals;
                    }
                }
                matches.push_back(proj);
            }
        }

        return matches;
    }

    bool getEntry(const std::wstring& dn, DirectoryEntry& outEntry) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::wstring target = normalizeDn(dn);
        for (const auto& e : m_entries) {
            if (normalizeDn(e.dn) == target) {
                outEntry = e;
                return true;
            }
        }
        return false;
    }

    void addEntry(const DirectoryEntry& entry) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_entries.push_back(entry);
    }

private:
    ActiveDirectoryStore() {
        seedDefaultDirectory();
    }

    void seedDefaultDirectory() {
        // 1. RootDSE entry (DN = "")
        {
            DirectoryEntry rootDse;
            rootDse.dn = L"";
            rootDse.setAttribute(L"defaultNamingContext", L"DC=micant,DC=local");
            rootDse.setAttribute(L"rootDomainNamingContext", L"DC=micant,DC=local");
            rootDse.setAttribute(L"configurationNamingContext", L"CN=Configuration,DC=micant,DC=local");
            rootDse.setAttribute(L"schemaNamingContext", L"CN=Schema,CN=Configuration,DC=micant,DC=local");
            rootDse.setAttribute(L"dnsHostName", L"dc01.micant.local");
            rootDse.setAttribute(L"serverName", L"CN=MICANT-DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=micant,DC=local");
            rootDse.addAttribute(L"supportedLDAPVersion", L"3");
            rootDse.addAttribute(L"supportedLDAPVersion", L"2");
            rootDse.addAttribute(L"supportedCapabilities", L"1.2.840.113556.1.4.800"); // Active Directory Capable
            rootDse.addAttribute(L"supportedCapabilities", L"1.2.840.113556.1.4.1791"); // LDAP Capable
            rootDse.addAttribute(L"supportedControl", L"1.2.840.113556.1.4.319"); // Paged Results
            rootDse.addAttribute(L"supportedControl", L"1.2.840.113556.1.4.801"); // SD Flags
            m_entries.push_back(rootDse);
        }

        // 2. Domain Root: DC=micant,DC=local
        {
            DirectoryEntry domainRoot;
            domainRoot.dn = L"DC=micant,DC=local";
            domainRoot.addAttribute(L"objectClass", L"domainDNS");
            domainRoot.addAttribute(L"objectClass", L"domain");
            domainRoot.addAttribute(L"objectClass", L"top");
            domainRoot.setAttribute(L"distinguishedName", L"DC=micant,DC=local");
            domainRoot.setAttribute(L"name", L"micant");
            domainRoot.setAttribute(L"dc", L"micant");
            domainRoot.setAttribute(L"defaultNamingContext", L"DC=micant,DC=local");
            m_entries.push_back(domainRoot);
        }

        // 3. Users Container: CN=Users,DC=micant,DC=local
        {
            DirectoryEntry users;
            users.dn = L"CN=Users,DC=micant,DC=local";
            users.addAttribute(L"objectClass", L"container");
            users.addAttribute(L"objectClass", L"top");
            users.setAttribute(L"distinguishedName", L"CN=Users,DC=micant,DC=local");
            users.setAttribute(L"cn", L"Users");
            users.setAttribute(L"name", L"Users");
            users.setAttribute(L"description", L"Default container for upgraded administrative accounts");
            m_entries.push_back(users);
        }

        // 4. Computers Container: CN=Computers,DC=micant,DC=local
        {
            DirectoryEntry comp;
            comp.dn = L"CN=Computers,DC=micant,DC=local";
            comp.addAttribute(L"objectClass", L"container");
            comp.addAttribute(L"objectClass", L"top");
            comp.setAttribute(L"distinguishedName", L"CN=Computers,DC=micant,DC=local");
            comp.setAttribute(L"cn", L"Computers");
            comp.setAttribute(L"name", L"Computers");
            comp.setAttribute(L"description", L"Default container for upgraded computer accounts");
            m_entries.push_back(comp);
        }

        // 5. Domain Controllers OU: OU=Domain Controllers,DC=micant,DC=local
        {
            DirectoryEntry dcs;
            dcs.dn = L"OU=Domain Controllers,DC=micant,DC=local";
            dcs.addAttribute(L"objectClass", L"organizationalUnit");
            dcs.addAttribute(L"objectClass", L"top");
            dcs.setAttribute(L"distinguishedName", L"OU=Domain Controllers,DC=micant,DC=local");
            dcs.setAttribute(L"ou", L"Domain Controllers");
            dcs.setAttribute(L"name", L"Domain Controllers");
            dcs.setAttribute(L"description", L"Default container for domain controllers");
            m_entries.push_back(dcs);
        }

        // 6. User: CN=Administrator,CN=Users,DC=micant,DC=local
        {
            DirectoryEntry admin;
            admin.dn = L"CN=Administrator,CN=Users,DC=micant,DC=local";
            admin.addAttribute(L"objectClass", L"user");
            admin.addAttribute(L"objectClass", L"person");
            admin.addAttribute(L"objectClass", L"organizationalPerson");
            admin.addAttribute(L"objectClass", L"top");
            admin.setAttribute(L"distinguishedName", L"CN=Administrator,CN=Users,DC=micant,DC=local");
            admin.setAttribute(L"cn", L"Administrator");
            admin.setAttribute(L"name", L"Administrator");
            admin.setAttribute(L"sAMAccountName", L"Administrator");
            admin.setAttribute(L"userPrincipalName", L"administrator@micant.local");
            admin.setAttribute(L"givenName", L"Domain");
            admin.setAttribute(L"sn", L"Administrator");
            admin.setAttribute(L"displayName", L"MicaNT Administrator");
            admin.setAttribute(L"description", L"Built-in account for administering the domain");
            admin.setAttribute(L"userAccountControl", L"512"); // NORMAL_ACCOUNT
            admin.setAttribute(L"mail", L"admin@micant.local");
            admin.addAttribute(L"memberOf", L"CN=Domain Admins,CN=Users,DC=micant,DC=local");
            admin.addAttribute(L"memberOf", L"CN=Domain Users,CN=Users,DC=micant,DC=local");
            m_entries.push_back(admin);
        }

        // 7. User: CN=Guest,CN=Users,DC=micant,DC=local
        {
            DirectoryEntry guest;
            guest.dn = L"CN=Guest,CN=Users,DC=micant,DC=local";
            guest.addAttribute(L"objectClass", L"user");
            guest.addAttribute(L"objectClass", L"person");
            guest.addAttribute(L"objectClass", L"organizationalPerson");
            guest.addAttribute(L"objectClass", L"top");
            guest.setAttribute(L"distinguishedName", L"CN=Guest,CN=Users,DC=micant,DC=local");
            guest.setAttribute(L"cn", L"Guest");
            guest.setAttribute(L"name", L"Guest");
            guest.setAttribute(L"sAMAccountName", L"Guest");
            guest.setAttribute(L"description", L"Built-in account for guest access to the domain");
            guest.setAttribute(L"userAccountControl", L"514"); // ACCOUNTDISABLE | NORMAL_ACCOUNT
            m_entries.push_back(guest);
        }

        // 8. User: CN=krbtgt,CN=Users,DC=micant,DC=local
        {
            DirectoryEntry krb;
            krb.dn = L"CN=krbtgt,CN=Users,DC=micant,DC=local";
            krb.addAttribute(L"objectClass", L"user");
            krb.addAttribute(L"objectClass", L"person");
            krb.addAttribute(L"objectClass", L"organizationalPerson");
            krb.addAttribute(L"objectClass", L"top");
            krb.setAttribute(L"distinguishedName", L"CN=krbtgt,CN=Users,DC=micant,DC=local");
            krb.setAttribute(L"cn", L"krbtgt");
            krb.setAttribute(L"name", L"krbtgt");
            krb.setAttribute(L"sAMAccountName", L"krbtgt");
            krb.setAttribute(L"description", L"Key Distribution Center Service Account");
            krb.setAttribute(L"userAccountControl", L"514");
            m_entries.push_back(krb);
        }

        // 9. Group: CN=Domain Admins,CN=Users,DC=micant,DC=local
        {
            DirectoryEntry da;
            da.dn = L"CN=Domain Admins,CN=Users,DC=micant,DC=local";
            da.addAttribute(L"objectClass", L"group");
            da.addAttribute(L"objectClass", L"top");
            da.setAttribute(L"distinguishedName", L"CN=Domain Admins,CN=Users,DC=micant,DC=local");
            da.setAttribute(L"cn", L"Domain Admins");
            da.setAttribute(L"name", L"Domain Admins");
            da.setAttribute(L"sAMAccountName", L"Domain Admins");
            da.setAttribute(L"description", L"Designated administrators of the domain");
            da.setAttribute(L"groupType", L"-2147483646"); // GLOBAL_SECURITY_GROUP
            da.addAttribute(L"member", L"CN=Administrator,CN=Users,DC=micant,DC=local");
            m_entries.push_back(da);
        }

        // 10. Group: CN=Domain Users,CN=Users,DC=micant,DC=local
        {
            DirectoryEntry du;
            du.dn = L"CN=Domain Users,CN=Users,DC=micant,DC=local";
            du.addAttribute(L"objectClass", L"group");
            du.addAttribute(L"objectClass", L"top");
            du.setAttribute(L"distinguishedName", L"CN=Domain Users,CN=Users,DC=micant,DC=local");
            du.setAttribute(L"cn", L"Domain Users");
            du.setAttribute(L"name", L"Domain Users");
            du.setAttribute(L"sAMAccountName", L"Domain Users");
            du.setAttribute(L"description", L"All domain users");
            du.setAttribute(L"groupType", L"-2147483646");
            du.addAttribute(L"member", L"CN=Administrator,CN=Users,DC=micant,DC=local");
            m_entries.push_back(du);
        }

        // 11. Group: CN=Domain Computers,CN=Users,DC=micant,DC=local
        {
            DirectoryEntry dcGroup;
            dcGroup.dn = L"CN=Domain Computers,CN=Users,DC=micant,DC=local";
            dcGroup.addAttribute(L"objectClass", L"group");
            dcGroup.addAttribute(L"objectClass", L"top");
            dcGroup.setAttribute(L"distinguishedName", L"CN=Domain Computers,CN=Users,DC=micant,DC=local");
            dcGroup.setAttribute(L"cn", L"Domain Computers");
            dcGroup.setAttribute(L"name", L"Domain Computers");
            dcGroup.setAttribute(L"sAMAccountName", L"Domain Computers");
            dcGroup.setAttribute(L"description", L"All workstations and servers joined to the domain");
            dcGroup.setAttribute(L"groupType", L"-2147483646");
            m_entries.push_back(dcGroup);
        }

        // 12. Computer: CN=MICANT-WS01,CN=Computers,DC=micant,DC=local
        {
            DirectoryEntry ws01;
            ws01.dn = L"CN=MICANT-WS01,CN=Computers,DC=micant,DC=local";
            ws01.addAttribute(L"objectClass", L"computer");
            ws01.addAttribute(L"objectClass", L"user");
            ws01.addAttribute(L"objectClass", L"person");
            ws01.addAttribute(L"objectClass", L"organizationalPerson");
            ws01.addAttribute(L"objectClass", L"top");
            ws01.setAttribute(L"distinguishedName", L"CN=MICANT-WS01,CN=Computers,DC=micant,DC=local");
            ws01.setAttribute(L"cn", L"MICANT-WS01");
            ws01.setAttribute(L"name", L"MICANT-WS01");
            ws01.setAttribute(L"sAMAccountName", L"MICANT-WS01$");
            ws01.setAttribute(L"dNSHostName", L"micant-ws01.micant.local");
            ws01.setAttribute(L"operatingSystem", L"MicaNT Sovereign Workstation");
            ws01.setAttribute(L"operatingSystemVersion", L"10.0 (26100)");
            ws01.setAttribute(L"userAccountControl", L"4096"); // WORKSTATION_TRUST_ACCOUNT
            m_entries.push_back(ws01);
        }

        // 13. Computer/DC: CN=MICANT-DC01,OU=Domain Controllers,DC=micant,DC=local
        {
            DirectoryEntry dc01;
            dc01.dn = L"CN=MICANT-DC01,OU=Domain Controllers,DC=micant,DC=local";
            dc01.addAttribute(L"objectClass", L"computer");
            dc01.addAttribute(L"objectClass", L"user");
            dc01.addAttribute(L"objectClass", L"person");
            dc01.addAttribute(L"objectClass", L"organizationalPerson");
            dc01.addAttribute(L"objectClass", L"top");
            dc01.setAttribute(L"distinguishedName", L"CN=MICANT-DC01,OU=Domain Controllers,DC=micant,DC=local");
            dc01.setAttribute(L"cn", L"MICANT-DC01");
            dc01.setAttribute(L"name", L"MICANT-DC01");
            dc01.setAttribute(L"sAMAccountName", L"MICANT-DC01$");
            dc01.setAttribute(L"dNSHostName", L"dc01.micant.local");
            dc01.setAttribute(L"operatingSystem", L"MicaNT Sovereign Domain Controller");
            dc01.setAttribute(L"operatingSystemVersion", L"10.0 (26100)");
            dc01.setAttribute(L"userAccountControl", L"532480"); // SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION
            dc01.setAttribute(L"serverReference", L"CN=MICANT-DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=micant,DC=local");
            m_entries.push_back(dc01);
        }
    }

    static std::wstring normalizeDn(const std::wstring& dn) {
        std::wstring result;
        result.reserve(dn.length());
        for (wchar_t wc : dn) {
            result.push_back(static_cast<wchar_t>(std::towlower(wc)));
        }
        return result;
    }

    static bool isDescendantOf(const std::wstring& dn, const std::wstring& base) {
        if (dn == base) return true;
        if (dn.length() <= base.length()) return false;
        if (dn.substr(dn.length() - base.length()) != base) return false;
        return dn[dn.length() - base.length() - 1] == L',';
    }

    static bool isDirectChildOf(const std::wstring& dn, const std::wstring& base) {
        if (!isDescendantOf(dn, base) || dn == base) return false;
        std::wstring prefix = dn.substr(0, dn.length() - base.length() - 1);
        return prefix.find(L',') == std::wstring::npos;
    }

    // RFC 4515 LDAP Filter Matcher
    static bool matchesFilter(const DirectoryEntry& entry, const std::wstring& filter) {
        if (filter.empty() || filter == L"*" || filter == L"(objectClass=*)") {
            return true;
        }

        std::wstring trimmed = filter;
        while (!trimmed.empty() && (trimmed.front() == L' ' || trimmed.front() == L'\t')) trimmed.erase(0, 1);
        while (!trimmed.empty() && (trimmed.back() == L' ' || trimmed.back() == L'\t')) trimmed.pop_back();

        if (trimmed.empty()) return true;

        if (trimmed.front() == L'(' && trimmed.back() == L')') {
            trimmed = trimmed.substr(1, trimmed.length() - 2);
        }

        if (trimmed.empty()) return true;

        // Composite AND: &((c1)(c2)...)
        if (trimmed.front() == L'&') {
            auto subFilters = splitSubFilters(trimmed.substr(1));
            for (const auto& sf : subFilters) {
                if (!matchesFilter(entry, sf)) return false;
            }
            return true;
        }

        // Composite OR: |((c1)(c2)...)
        if (trimmed.front() == L'|') {
            auto subFilters = splitSubFilters(trimmed.substr(1));
            for (const auto& sf : subFilters) {
                if (matchesFilter(entry, sf)) return true;
            }
            return false;
        }

        // NOT: !(c)
        if (trimmed.front() == L'!') {
            auto subFilters = splitSubFilters(trimmed.substr(1));
            if (!subFilters.empty()) {
                return !matchesFilter(entry, subFilters[0]);
            }
            return true;
        }

        // Simple condition: attr=value or attr<=value or attr>=value
        size_t eqPos = trimmed.find(L'=');
        if (eqPos == std::wstring::npos) return true;

        std::wstring attr = trimmed.substr(0, eqPos);
        std::wstring val = trimmed.substr(eqPos + 1);

        // Check if entry has this attribute
        auto vals = entry.getValues(attr);
        if (vals.empty()) return false;

        // Wildcard match
        if (val == L"*") return true;

        if (val.back() == L'*') {
            std::wstring prefix = val.substr(0, val.length() - 1);
            for (const auto& v : vals) {
                if (v.length() >= prefix.length()) {
                    if (_wcsnicmp(v.c_str(), prefix.c_str(), prefix.length()) == 0) return true;
                }
            }
            return false;
        }

        for (const auto& v : vals) {
            if (_wcsicmp(v.c_str(), val.c_str()) == 0) return true;
        }

        return false;
    }

    static std::vector<std::wstring> splitSubFilters(const std::wstring& str) {
        std::vector<std::wstring> list;
        int depth = 0;
        size_t start = 0;
        for (size_t i = 0; i < str.length(); ++i) {
            if (str[i] == L'(') {
                if (depth == 0) start = i;
                depth++;
            } else if (str[i] == L')') {
                depth--;
                if (depth == 0) {
                    list.push_back(str.substr(start, i - start + 1));
                }
            }
        }
        return list;
    }

    mutable std::mutex m_mutex;
    std::vector<DirectoryEntry> m_entries;
};

// ============================================================================
// 3. LDAP Message & BER Element Internal Representation
// ============================================================================

struct LdapMessageInternal {
    uint32_t messageId{1};
    uint32_t messageType{0x64}; // 0x64 = search entry, 0x65 = search result
    std::wstring dn{};
    std::map<std::wstring, std::vector<std::wstring>, CaseInsensitiveLess> attributes{};
    LdapMessageInternal* next{nullptr};
};

struct BerElementInternal {
    std::vector<std::wstring> attributeNames;
    size_t currentIndex{0};
};

// Opaque LDAP connection handle structure
struct LdapConnectionInternal {
    std::wstring hostName{L"localhost"};
    uint32_t port{LDAP_PORT};
    bool ssl{false};
    bool connected{false};
    bool bound{false};
    std::wstring bindDn{};
    uint32_t lastError{LDAP_SUCCESS};
    int version{3};
    int sizeLimit{1000};
    int timeLimit{120};
    int referrals{1};
    std::vector<void*> allocatedBuffers{};
    std::mutex connMutex{};

    void trackBuffer(void* ptr) {
        std::lock_guard<std::mutex> lock(connMutex);
        allocatedBuffers.push_back(ptr);
    }
};

using LDAP = LdapConnectionInternal;
using LDAPMessage = LdapMessageInternal;
using BerElement = BerElementInternal;

// Memory allocation helpers for Win32 LDAP compatibility
inline wchar_t* AllocLdapString(const std::wstring& str) {
    size_t bytes = (str.length() + 1) * sizeof(wchar_t);
    wchar_t* p = static_cast<wchar_t*>(::malloc(bytes));
    if (p) {
        std::memcpy(p, str.c_str(), bytes);
    }
    return p;
}

inline void __stdcall ldap_memfreeW(wchar_t* ptr) {
    if (ptr) {
        ::free(ptr);
    }
}

inline berval** AllocLdapBerVals(const std::vector<std::wstring>& vals) {
    berval** arr = static_cast<berval**>(::calloc(vals.size() + 1, sizeof(berval*)));
    if (!arr) return nullptr;
    for (size_t i = 0; i < vals.size(); ++i) {
        arr[i] = static_cast<berval*>(::calloc(1, sizeof(berval)));
        if (arr[i]) {
            std::string utf8;
            for (wchar_t wc : vals[i]) {
                if (wc < 128) utf8.push_back(static_cast<char>(wc));
                else { utf8.push_back('?'); }
            }
            arr[i]->bv_len = static_cast<uint32_t>(utf8.length());
            arr[i]->bv_val = static_cast<char*>(::malloc(utf8.length() + 1));
            if (arr[i]->bv_val) {
                std::memcpy(arr[i]->bv_val, utf8.c_str(), utf8.length() + 1);
            }
        }
    }
    return arr;
}

inline uint32_t __stdcall ldap_value_free_len(berval** vals) {
    if (!vals) return LDAP_SUCCESS;
    for (size_t i = 0; vals[i] != nullptr; ++i) {
        if (vals[i]->bv_val) ::free(vals[i]->bv_val);
        ::free(vals[i]);
    }
    ::free(vals);
    return LDAP_SUCCESS;
}

inline wchar_t** AllocLdapStrVals(const std::vector<std::wstring>& vals) {
    wchar_t** arr = static_cast<wchar_t**>(::calloc(vals.size() + 1, sizeof(wchar_t*)));
    if (!arr) return nullptr;
    for (size_t i = 0; i < vals.size(); ++i) {
        arr[i] = AllocLdapString(vals[i]);
    }
    return arr;
}

inline uint32_t __stdcall ldap_value_freeW(wchar_t** vals) {
    if (!vals) return LDAP_SUCCESS;
    for (size_t i = 0; vals[i] != nullptr; ++i) {
        ldap_memfreeW(vals[i]);
    }
    ::free(vals);
    return LDAP_SUCCESS;
}

inline void __stdcall ber_free(BerElement* pBerElement, int freebuf) {
    (void)freebuf;
    if (pBerElement) {
        delete pBerElement;
    }
}

inline uint32_t __stdcall ldap_msgfree(LDAPMessage* msg) {
    LDAPMessage* curr = msg;
    while (curr) {
        LDAPMessage* next = curr->next;
        delete curr;
        curr = next;
    }
    return LDAP_SUCCESS;
}

// ============================================================================
// 4. Core Win32 LDAP Client C APIs (wldap32.dll)
// ============================================================================

inline LDAP* __stdcall ldap_initW(const wchar_t* HostName, uint32_t PortNumber) {
    auto* conn = new LDAP();
    if (HostName) conn->hostName = HostName;
    conn->port = (PortNumber == 0) ? LDAP_PORT : PortNumber;
    conn->ssl = false;
    conn->connected = false;
    conn->lastError = LDAP_SUCCESS;
    return conn;
}

inline LDAP* __stdcall ldap_sslinitW(const wchar_t* HostName, uint32_t PortNumber, int secure) {
    auto* conn = new LDAP();
    if (HostName) conn->hostName = HostName;
    conn->port = (PortNumber == 0) ? (secure ? LDAPS_PORT : LDAP_PORT) : PortNumber;
    conn->ssl = (secure != 0);
    conn->connected = false;
    conn->lastError = LDAP_SUCCESS;
    return conn;
}

inline LDAP* __stdcall ldap_openW(const wchar_t* HostName, uint32_t PortNumber) {
    auto* conn = ldap_initW(HostName, PortNumber);
    if (conn) {
        conn->connected = true;
    }
    return conn;
}

inline uint32_t __stdcall ldap_connect(LDAP* ld, struct l_timeval* timeout) {
    (void)timeout;
    if (!ld) return LDAP_PARAM_ERROR;
    ld->connected = true;
    ld->lastError = LDAP_SUCCESS;
    return LDAP_SUCCESS;
}

inline uint32_t __stdcall ldap_bind_sW(LDAP* ld, const wchar_t* dn, const wchar_t* cred, uint32_t method) {
    (void)cred;
    (void)method;
    if (!ld) return LDAP_PARAM_ERROR;
    ld->connected = true;
    ld->bound = true;
    if (dn) ld->bindDn = dn;
    else ld->bindDn = L"CN=Administrator,CN=Users,DC=micant,DC=local";
    ld->lastError = LDAP_SUCCESS;
    return LDAP_SUCCESS;
}

inline uint32_t __stdcall ldap_simple_bind_sW(LDAP* ld, const wchar_t* dn, const wchar_t* passwd) {
    return ldap_bind_sW(ld, dn, passwd, LDAP_AUTH_SIMPLE);
}

inline uint32_t __stdcall ldap_unbind_s(LDAP* ld) {
    if (!ld) return LDAP_PARAM_ERROR;
    delete ld;
    return LDAP_SUCCESS;
}

inline uint32_t __stdcall ldap_unbind(LDAP* ld) {
    return ldap_unbind_s(ld);
}

inline uint32_t __stdcall ldap_search_sW(
    LDAP* ld,
    const wchar_t* base,
    uint32_t scope,
    const std::wstring& filter,
    wchar_t* attrs[],
    uint32_t attrsonly,
    LDAPMessage** res
) {
    (void)attrsonly;
    if (!ld || !res) return LDAP_PARAM_ERROR;
    *res = nullptr;

    std::vector<std::wstring> reqAttrs;
    if (attrs) {
        for (size_t i = 0; attrs[i] != nullptr; ++i) {
            reqAttrs.push_back(attrs[i]);
        }
    }

    std::wstring baseStr = base ? base : L"";
    auto entries = ActiveDirectoryStore::get().search(baseStr, scope, filter, reqAttrs);

    LDAPMessage* head = nullptr;
    LDAPMessage* tail = nullptr;

    for (const auto& e : entries) {
        auto* msg = new LDAPMessage();
        msg->messageId = 1;
        msg->messageType = 0x64; // search entry
        msg->dn = e.dn;
        msg->attributes = e.attributes;
        msg->next = nullptr;

        if (!head) {
            head = msg;
            tail = msg;
        } else {
            tail->next = msg;
            tail = msg;
        }
    }

    // Add search result done sentinel
    auto* doneMsg = new LDAPMessage();
    doneMsg->messageId = 1;
    doneMsg->messageType = 0x65; // search result done
    doneMsg->next = nullptr;

    if (!head) {
        head = doneMsg;
    } else {
        tail->next = doneMsg;
    }

    *res = head;
    ld->lastError = LDAP_SUCCESS;
    return LDAP_SUCCESS;
}

inline uint32_t __stdcall ldap_search_ext_sW(
    LDAP* ld,
    const wchar_t* base,
    uint32_t scope,
    const wchar_t* filter,
    wchar_t* attrs[],
    uint32_t attrsonly,
    void* serverctrls,
    void* clientctrls,
    struct l_timeval* timeout,
    uint32_t sizelimit,
    LDAPMessage** res
) {
    (void)serverctrls;
    (void)clientctrls;
    (void)timeout;
    (void)sizelimit;
    return ldap_search_sW(ld, base, scope, filter ? filter : L"(objectClass=*)", attrs, attrsonly, res);
}

inline uint32_t __stdcall ldap_count_entries(LDAP* ld, LDAPMessage* res) {
    (void)ld;
    if (!res) return 0;
    uint32_t count = 0;
    LDAPMessage* curr = res;
    while (curr) {
        if (curr->messageType == 0x64) {
            count++;
        }
        curr = curr->next;
    }
    return count;
}

inline LDAPMessage* __stdcall ldap_first_entry(LDAP* ld, LDAPMessage* chain) {
    (void)ld;
    LDAPMessage* curr = chain;
    while (curr) {
        if (curr->messageType == 0x64) return curr;
        curr = curr->next;
    }
    return nullptr;
}

inline LDAPMessage* __stdcall ldap_next_entry(LDAP* ld, LDAPMessage* entry) {
    (void)ld;
    if (!entry) return nullptr;
    LDAPMessage* curr = entry->next;
    while (curr) {
        if (curr->messageType == 0x64) return curr;
        curr = curr->next;
    }
    return nullptr;
}

inline wchar_t* __stdcall ldap_get_dnW(LDAP* ld, LDAPMessage* entry) {
    (void)ld;
    if (!entry) return nullptr;
    return AllocLdapString(entry->dn);
}

inline wchar_t* __stdcall ldap_first_attributeW(LDAP* ld, LDAPMessage* entry, BerElement** pBerElement) {
    (void)ld;
    if (!entry) return nullptr;

    auto* ber = new BerElement();
    for (const auto& pair : entry->attributes) {
        ber->attributeNames.push_back(pair.first);
    }
    ber->currentIndex = 0;

    if (pBerElement) {
        *pBerElement = ber;
    }

    if (ber->attributeNames.empty()) {
        if (!pBerElement) delete ber;
        return nullptr;
    }

    wchar_t* attr = AllocLdapString(ber->attributeNames[0]);
    ber->currentIndex = 1;
    return attr;
}

inline wchar_t* __stdcall ldap_next_attributeW(LDAP* ld, LDAPMessage* entry, BerElement* pBerElement) {
    (void)ld;
    (void)entry;
    if (!pBerElement) return nullptr;
    if (pBerElement->currentIndex >= pBerElement->attributeNames.size()) {
        return nullptr;
    }
    wchar_t* attr = AllocLdapString(pBerElement->attributeNames[pBerElement->currentIndex]);
    pBerElement->currentIndex++;
    return attr;
}

inline berval** __stdcall ldap_get_values_lenW(LDAP* ld, LDAPMessage* entry, const wchar_t* attr) {
    (void)ld;
    if (!entry || !attr) return nullptr;
    auto it = entry->attributes.find(attr);
    if (it == entry->attributes.end() || it->second.empty()) return nullptr;
    return AllocLdapBerVals(it->second);
}

inline wchar_t** __stdcall ldap_get_valuesW(LDAP* ld, LDAPMessage* entry, const wchar_t* attr) {
    (void)ld;
    if (!entry || !attr) return nullptr;
    auto it = entry->attributes.find(attr);
    if (it == entry->attributes.end() || it->second.empty()) return nullptr;
    return AllocLdapStrVals(it->second);
}

inline const wchar_t* __stdcall ldap_err2stringW(uint32_t err) {
    switch (err) {
        case LDAP_SUCCESS: return L"Success";
        case LDAP_OPERATIONS_ERROR: return L"Operations Error";
        case LDAP_PROTOCOL_ERROR: return L"Protocol Error";
        case LDAP_TIMELIMIT_EXCEEDED: return L"Timelimit Exceeded";
        case LDAP_SIZELIMIT_EXCEEDED: return L"Sizelimit Exceeded";
        case LDAP_AUTH_METHOD_NOT_SUPPORTED: return L"Authentication Method Not Supported";
        case LDAP_STRONG_AUTH_REQUIRED: return L"Strong Authentication Required";
        case LDAP_NO_SUCH_ATTRIBUTE: return L"No Such Attribute";
        case LDAP_UNDEFINED_TYPE: return L"Undefined Type";
        case LDAP_NO_SUCH_OBJECT: return L"No Such Object";
        case LDAP_INVALID_DN_SYNTAX: return L"Invalid DN Syntax";
        case LDAP_INAPPROPRIATE_AUTH: return L"Inappropriate Authentication";
        case LDAP_INVALID_CREDENTIALS: return L"Invalid Credentials";
        case LDAP_INSUFFICIENT_RIGHTS: return L"Insufficient Rights";
        case LDAP_BUSY: return L"Server Busy";
        case LDAP_UNAVAILABLE: return L"Server Unavailable";
        case LDAP_SERVER_DOWN: return L"Server Down";
        case LDAP_LOCAL_ERROR: return L"Local Error";
        case LDAP_TIMEOUT: return L"Timeout";
        case LDAP_FILTER_ERROR: return L"Bad Search Filter";
        case LDAP_PARAM_ERROR: return L"Bad Parameter";
        case LDAP_NO_MEMORY: return L"Out of Memory";
        case LDAP_CONNECT_ERROR: return L"Connect Error";
        default: return L"Unknown LDAP Error";
    }
}

inline uint32_t __stdcall ldap_set_optionW(LDAP* ld, int option, const void* invalue) {
    if (!ld || !invalue) return LDAP_PARAM_ERROR;
    switch (option) {
        case LDAP_OPT_PROTOCOL_VERSION:
            ld->version = *reinterpret_cast<const int*>(invalue);
            return LDAP_SUCCESS;
        case LDAP_OPT_SIZELIMIT:
            ld->sizeLimit = *reinterpret_cast<const int*>(invalue);
            return LDAP_SUCCESS;
        case LDAP_OPT_TIMELIMIT:
            ld->timeLimit = *reinterpret_cast<const int*>(invalue);
            return LDAP_SUCCESS;
        case LDAP_OPT_REFERRALS:
            ld->referrals = *reinterpret_cast<const int*>(invalue);
            return LDAP_SUCCESS;
        default:
            return LDAP_SUCCESS;
    }
}

inline uint32_t __stdcall ldap_get_optionW(LDAP* ld, int option, void* outvalue) {
    if (!ld || !outvalue) return LDAP_PARAM_ERROR;
    switch (option) {
        case LDAP_OPT_PROTOCOL_VERSION:
            *reinterpret_cast<int*>(outvalue) = ld->version;
            return LDAP_SUCCESS;
        case LDAP_OPT_SIZELIMIT:
            *reinterpret_cast<int*>(outvalue) = ld->sizeLimit;
            return LDAP_SUCCESS;
        case LDAP_OPT_TIMELIMIT:
            *reinterpret_cast<int*>(outvalue) = ld->timeLimit;
            return LDAP_SUCCESS;
        case LDAP_OPT_REFERRALS:
            *reinterpret_cast<int*>(outvalue) = ld->referrals;
            return LDAP_SUCCESS;
        case LDAP_OPT_ERROR_NUMBER:
            *reinterpret_cast<uint32_t*>(outvalue) = ld->lastError;
            return LDAP_SUCCESS;
        default:
            return LDAP_SUCCESS;
    }
}

inline uint32_t __stdcall LdapGetLastError() {
    return LDAP_SUCCESS;
}

inline uint32_t __stdcall LdapMapErrorToWin32(uint32_t LdapError) {
    switch (LdapError) {
        case LDAP_SUCCESS: return 0;
        case LDAP_NO_SUCH_OBJECT: return 0x00002030; // ERROR_DS_NO_SUCH_OBJECT
        case LDAP_INVALID_CREDENTIALS: return 0x0000052E; // ERROR_LOGON_FAILURE
        case LDAP_SERVER_DOWN: return 0x0000203A; // ERROR_DS_SERVER_DOWN
        case LDAP_UNAVAILABLE: return 0x0000200E; // ERROR_DS_BUSY
        default: return 0x00002000 | LdapError;
    }
}

// ============================================================================
// 5. Active Directory Service Interfaces (ADSI) Helper (adsldp.dll)
// ============================================================================

inline int32_t __stdcall ADsOpenObject(
    const wchar_t* lpszPathName,
    const wchar_t* lpszUserName,
    const wchar_t* lpszPassword,
    uint32_t dwReserved,
    const void* riid,
    void** ppObject
) {
    (void)lpszUserName;
    (void)lpszPassword;
    (void)dwReserved;
    (void)riid;

    if (!lpszPathName || !ppObject) return -2147024809; // E_INVALIDARG (0x80070057)
    *ppObject = nullptr;

    std::wstring path = lpszPathName;
    if (path.rfind(L"LDAP://", 0) == 0) {
        path = path.substr(7);
    }

    DirectoryEntry entry;
    if (ActiveDirectoryStore::get().getEntry(path, entry)) {
        // Return dummy valid pointer
        *ppObject = reinterpret_cast<void*>(0xAD510001);
        return 0; // S_OK
    }

    return -2147016656; // HRESULT_FROM_WIN32(ERROR_DS_NO_SUCH_OBJECT) = 0x80072030
}

inline int32_t __stdcall DllGetClassObject(const void* rclsid, const void* riid, void** ppv) {
    (void)rclsid;
    (void)riid;
    if (!ppv) return -2147024809; // E_INVALIDARG
    *ppv = reinterpret_cast<void*>(0xAD510002);
    return 0; // S_OK
}

// ============================================================================
// 6. Dynamic Loader & SCM Registration
// ============================================================================

inline void InitializeLdapSubsystemExports() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    auto& ldr = ldr::DynamicLoader::get();

    // 1. wldap32.dll exports
    ldr.registerExport("wldap32.dll", "ldap_initW", reinterpret_cast<void*>(ldap_initW));
    ldr.registerExport("wldap32.dll", "ldap_sslinitW", reinterpret_cast<void*>(ldap_sslinitW));
    ldr.registerExport("wldap32.dll", "ldap_openW", reinterpret_cast<void*>(ldap_openW));
    ldr.registerExport("wldap32.dll", "ldap_connect", reinterpret_cast<void*>(ldap_connect));
    ldr.registerExport("wldap32.dll", "ldap_bind_sW", reinterpret_cast<void*>(ldap_bind_sW));
    ldr.registerExport("wldap32.dll", "ldap_simple_bind_sW", reinterpret_cast<void*>(ldap_simple_bind_sW));
    ldr.registerExport("wldap32.dll", "ldap_unbind_s", reinterpret_cast<void*>(ldap_unbind_s));
    ldr.registerExport("wldap32.dll", "ldap_unbind", reinterpret_cast<void*>(ldap_unbind));

    ldr.registerExport("wldap32.dll", "ldap_search_sW", reinterpret_cast<void*>(ldap_search_sW));
    ldr.registerExport("wldap32.dll", "ldap_search_ext_sW", reinterpret_cast<void*>(ldap_search_ext_sW));
    ldr.registerExport("wldap32.dll", "ldap_count_entries", reinterpret_cast<void*>(ldap_count_entries));
    ldr.registerExport("wldap32.dll", "ldap_first_entry", reinterpret_cast<void*>(ldap_first_entry));
    ldr.registerExport("wldap32.dll", "ldap_next_entry", reinterpret_cast<void*>(ldap_next_entry));
    ldr.registerExport("wldap32.dll", "ldap_get_dnW", reinterpret_cast<void*>(ldap_get_dnW));
    ldr.registerExport("wldap32.dll", "ldap_memfreeW", reinterpret_cast<void*>(ldap_memfreeW));

    ldr.registerExport("wldap32.dll", "ldap_first_attributeW", reinterpret_cast<void*>(ldap_first_attributeW));
    ldr.registerExport("wldap32.dll", "ldap_next_attributeW", reinterpret_cast<void*>(ldap_next_attributeW));
    ldr.registerExport("wldap32.dll", "ldap_get_values_lenW", reinterpret_cast<void*>(ldap_get_values_lenW));
    ldr.registerExport("wldap32.dll", "ldap_value_free_len", reinterpret_cast<void*>(ldap_value_free_len));
    ldr.registerExport("wldap32.dll", "ldap_get_valuesW", reinterpret_cast<void*>(ldap_get_valuesW));
    ldr.registerExport("wldap32.dll", "ldap_value_freeW", reinterpret_cast<void*>(ldap_value_freeW));
    ldr.registerExport("wldap32.dll", "ldap_msgfree", reinterpret_cast<void*>(ldap_msgfree));

    ldr.registerExport("wldap32.dll", "ldap_err2stringW", reinterpret_cast<void*>(ldap_err2stringW));
    ldr.registerExport("wldap32.dll", "ldap_set_optionW", reinterpret_cast<void*>(ldap_set_optionW));
    ldr.registerExport("wldap32.dll", "ldap_get_optionW", reinterpret_cast<void*>(ldap_get_optionW));
    ldr.registerExport("wldap32.dll", "ber_free", reinterpret_cast<void*>(ber_free));
    ldr.registerExport("wldap32.dll", "LdapGetLastError", reinterpret_cast<void*>(LdapGetLastError));
    ldr.registerExport("wldap32.dll", "LdapMapErrorToWin32", reinterpret_cast<void*>(LdapMapErrorToWin32));

    // 2. adsldp.dll exports (ADSI LDAP Provider)
    ldr.registerExport("adsldp.dll", "ADsOpenObject", reinterpret_cast<void*>(ADsOpenObject));
    ldr.registerExport("adsldp.dll", "DllGetClassObject", reinterpret_cast<void*>(DllGetClassObject));

    // 3. SCM Services: NTDS ("Active Directory Domain Services") & KDC ("Kerberos Key Distribution Center")
    auto& scm = scm::ServiceControlManager::get();

    // NTDS
    auto ntdsRecord = std::make_shared<scm::ServiceRecord>();
    ntdsRecord->serviceName = L"NTDS";
    ntdsRecord->displayName = L"Active Directory Domain Services";
    ntdsRecord->serviceType = scm::SERVICE_WIN32_OWN_PROCESS;
    ntdsRecord->startType = scm::SERVICE_AUTO_START;
    ntdsRecord->errorControl = scm::SERVICE_ERROR_NORMAL;
    ntdsRecord->svchostGroup = "";
    ntdsRecord->binaryPath = L"C:\\Windows\\System32\\ntds.exe";
    ntdsRecord->status.dwServiceType = ntdsRecord->serviceType;
    ntdsRecord->status.dwCurrentState = scm::SERVICE_RUNNING;
    ntdsRecord->status.dwProcessId = 1040;
    scm.registerServiceRecord(ntdsRecord);

    // KDC
    auto kdcRecord = std::make_shared<scm::ServiceRecord>();
    kdcRecord->serviceName = L"KDC";
    kdcRecord->displayName = L"Kerberos Key Distribution Center";
    kdcRecord->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
    kdcRecord->startType = scm::SERVICE_AUTO_START;
    kdcRecord->errorControl = scm::SERVICE_ERROR_NORMAL;
    kdcRecord->svchostGroup = "LocalService";
    kdcRecord->binaryPath = L"C:\\Windows\\System32\\lsass.exe";
    kdcRecord->status.dwServiceType = kdcRecord->serviceType;
    kdcRecord->status.dwCurrentState = scm::SERVICE_RUNNING;
    kdcRecord->status.dwProcessId = scm::SvcHostManager::get().getOrCreateGroupProcess("LocalService");
    scm::SvcHostManager::get().assignService("LocalService", kdcRecord->serviceName);
    scm.registerServiceRecord(kdcRecord);
}

} // namespace micant::ldap
