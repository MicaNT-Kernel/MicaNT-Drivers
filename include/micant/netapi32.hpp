#pragma once

/**
 * @file netapi32.hpp
 * @brief MicaNT Network Management & NetAPI32 Subsystem
 *
 * Clean-room implementation referencing Microsoft's MIT-licensed win32metadata.
 * Implements:
 * - Network Management Memory Allocator (NetApiBufferAllocate / Free / Size)
 * - Network Share Management (NetShareEnum, NetShareAdd, NetShareDel, NetShareGetInfo)
 * - Server & Workstation Introspection (NetServerGetInfo, NetWkstaGetInfo)
 * - Network Sessions & Connection Tracking (NetSessionEnum, NetSessionDel)
 * - User & Local Group Management (NetUserEnum, NetUserGetInfo, NetUserAdd, NetUserDel, NetLocalGroupEnum, NetLocalGroupGetInfo)
 * - SCM integration with LanmanServer ("Server") and LanmanWorkstation ("Workstation")
 * - Dynamic exports for netapi32.dll, srvcli.dll, wkscli.dll
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

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ldr.hpp"
#include "scm.hpp"

namespace micant::netapi {

// ============================================================================
// 1. NetAPI Constants & Error Codes
// ============================================================================

using NET_API_STATUS = uint32_t;

inline constexpr NET_API_STATUS NERR_Success              = 0;
inline constexpr NET_API_STATUS ERROR_ACCESS_DENIED       = 5;
inline constexpr NET_API_STATUS ERROR_NOT_ENOUGH_MEMORY   = 8;
inline constexpr NET_API_STATUS ERROR_INVALID_PARAMETER   = 87;
inline constexpr NET_API_STATUS ERROR_MORE_DATA           = 234;
inline constexpr NET_API_STATUS NERR_NetNotStarted        = 2102;
inline constexpr NET_API_STATUS NERR_ServerNotStarted     = 2114;
inline constexpr NET_API_STATUS NERR_WkstaNotStarted      = 2138;
inline constexpr NET_API_STATUS NERR_ClientNameNotFound   = 2210;
inline constexpr NET_API_STATUS NERR_UserNotFound         = 2221;
inline constexpr NET_API_STATUS NERR_GroupNotFound        = 2220;
inline constexpr NET_API_STATUS NERR_ShareNotFound        = 2310;
inline constexpr NET_API_STATUS NERR_DuplicateShare       = 2118;

inline constexpr uint32_t MAX_PREFERRED_LENGTH            = 0xFFFFFFFF;

// Platform Identifiers
inline constexpr uint32_t PLATFORM_ID_DOS                 = 300;
inline constexpr uint32_t PLATFORM_ID_OS2                 = 400;
inline constexpr uint32_t PLATFORM_ID_NT                  = 500;

// Server Type Bitmasks
inline constexpr uint32_t SV_TYPE_WORKSTATION             = 0x00000001;
inline constexpr uint32_t SV_TYPE_SERVER                  = 0x00000002;
inline constexpr uint32_t SV_TYPE_SQLSERVER               = 0x00000004;
inline constexpr uint32_t SV_TYPE_DOMAIN_CTRL             = 0x00000008;
inline constexpr uint32_t SV_TYPE_DOMAIN_BAKCTRL          = 0x00000010;
inline constexpr uint32_t SV_TYPE_TIME_SOURCE             = 0x00000020;
inline constexpr uint32_t SV_TYPE_AFP                     = 0x00000040;
inline constexpr uint32_t SV_TYPE_NOVELL                  = 0x00000080;
inline constexpr uint32_t SV_TYPE_DOMAIN_MEMBER           = 0x00000100;
inline constexpr uint32_t SV_TYPE_PRINTQ_SERVER           = 0x00000200;
inline constexpr uint32_t SV_TYPE_DIALIN_SERVER           = 0x00000400;
inline constexpr uint32_t SV_TYPE_XENIX_SERVER            = 0x00000800;
inline constexpr uint32_t SV_TYPE_SERVER_UNIX             = 0x00000800;
inline constexpr uint32_t SV_TYPE_NT                      = 0x00001000;
inline constexpr uint32_t SV_TYPE_WFW                     = 0x00002000;
inline constexpr uint32_t SV_TYPE_SERVER_MFPN             = 0x00004000;
inline constexpr uint32_t SV_TYPE_SERVER_NT               = 0x00008000;
inline constexpr uint32_t SV_TYPE_POTENTIAL_BROWSER       = 0x00010000;
inline constexpr uint32_t SV_TYPE_BACKUP_BROWSER          = 0x00020000;
inline constexpr uint32_t SV_TYPE_MASTER_BROWSER          = 0x00040000;
inline constexpr uint32_t SV_TYPE_DOMAIN_MASTER           = 0x00080000;
inline constexpr uint32_t SV_TYPE_SERVER_OSF              = 0x00100000;
inline constexpr uint32_t SV_TYPE_SERVER_VMS              = 0x00200000;
inline constexpr uint32_t SV_TYPE_WINDOWS                 = 0x00400000;
inline constexpr uint32_t SV_TYPE_DFS                     = 0x00800000;
inline constexpr uint32_t SV_TYPE_CLUSTER_NT              = 0x01000000;
inline constexpr uint32_t SV_TYPE_TERMINALSERVER          = 0x02000000;
inline constexpr uint32_t SV_TYPE_CLUSTER_VS_NT           = 0x04000000;

// Share Types
inline constexpr uint32_t STYPE_DISKTREE                  = 0;
inline constexpr uint32_t STYPE_PRINTQ                    = 1;
inline constexpr uint32_t STYPE_DEVICE                    = 2;
inline constexpr uint32_t STYPE_IPC                       = 3;
inline constexpr uint32_t STYPE_SPECIAL                   = 0x80000000;

// Share Permissions
inline constexpr uint32_t ACCESS_READ                     = 0x01;
inline constexpr uint32_t ACCESS_WRITE                    = 0x02;
inline constexpr uint32_t ACCESS_CREATE                   = 0x04;
inline constexpr uint32_t ACCESS_EXEC                     = 0x08;
inline constexpr uint32_t ACCESS_DELETE                   = 0x10;
inline constexpr uint32_t ACCESS_ATRIB                    = 0x20;
inline constexpr uint32_t ACCESS_PERM                     = 0x40;
inline constexpr uint32_t ACCESS_ALL                      = (ACCESS_READ | ACCESS_WRITE | ACCESS_CREATE | ACCESS_EXEC | ACCESS_DELETE | ACCESS_ATRIB | ACCESS_PERM);

// User Privilege Levels & Account Flags
inline constexpr uint32_t USER_PRIV_GUEST                 = 0;
inline constexpr uint32_t USER_PRIV_USER                  = 1;
inline constexpr uint32_t USER_PRIV_ADMIN                 = 2;
inline constexpr uint32_t UF_SCRIPT                       = 0x0001;
inline constexpr uint32_t UF_ACCOUNTDISABLE               = 0x0002;
inline constexpr uint32_t UF_NORMAL_ACCOUNT               = 0x0200;
inline constexpr uint32_t UF_DONT_EXPIRE_PASSWORD         = 0x10000;

// ============================================================================
// 2. Win32 Metadata Binary Structures
// ============================================================================

struct SERVER_INFO_100 {
    uint32_t sv100_platform_id{PLATFORM_ID_NT};
    wchar_t* sv100_name{nullptr};
};

struct SERVER_INFO_101 {
    uint32_t sv101_platform_id{PLATFORM_ID_NT};
    wchar_t* sv101_name{nullptr};
    uint32_t sv101_version_major{10};
    uint32_t sv101_version_minor{0};
    uint32_t sv101_type{SV_TYPE_SERVER | SV_TYPE_WORKSTATION | SV_TYPE_NT | SV_TYPE_SERVER_NT};
    wchar_t* sv101_comment{nullptr};
};

struct WKSTA_INFO_100 {
    uint32_t wki100_platform_id{PLATFORM_ID_NT};
    wchar_t* wki100_computername{nullptr};
    wchar_t* wki100_langroup{nullptr};
    uint32_t wki100_ver_major{10};
    uint32_t wki100_ver_minor{0};
};

struct SHARE_INFO_0 {
    wchar_t* shi0_netname{nullptr};
};

struct SHARE_INFO_1 {
    wchar_t* shi1_netname{nullptr};
    uint32_t shi1_type{STYPE_DISKTREE};
    wchar_t* shi1_remark{nullptr};
};

struct SHARE_INFO_2 {
    wchar_t* shi2_netname{nullptr};
    uint32_t shi2_type{STYPE_DISKTREE};
    wchar_t* shi2_remark{nullptr};
    uint32_t shi2_permissions{ACCESS_ALL};
    uint32_t shi2_max_uses{static_cast<uint32_t>(-1)};
    uint32_t shi2_current_uses{0};
    wchar_t* shi2_path{nullptr};
    wchar_t* shi2_passwd{nullptr};
};

struct SESSION_INFO_0 {
    wchar_t* sesi0_cname{nullptr};
};

struct SESSION_INFO_10 {
    wchar_t* sesi10_cname{nullptr};
    wchar_t* sesi10_username{nullptr};
    uint32_t sesi10_time{0};
    uint32_t sesi10_idle_time{0};
};

struct USER_INFO_0 {
    wchar_t* usri0_name{nullptr};
};

struct USER_INFO_1 {
    wchar_t* usri1_name{nullptr};
    wchar_t* usri1_password{nullptr};
    uint32_t usri1_password_age{0};
    uint32_t usri1_priv{USER_PRIV_USER};
    wchar_t* usri1_home_dir{nullptr};
    wchar_t* usri1_comment{nullptr};
    uint32_t usri1_flags{UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWORD};
    wchar_t* usri1_script_path{nullptr};
};

struct LOCALGROUP_INFO_0 {
    wchar_t* lgrpi0_name{nullptr};
};

struct LOCALGROUP_INFO_1 {
    wchar_t* lgrpi1_name{nullptr};
    wchar_t* lgrpi1_comment{nullptr};
};

struct LOCALGROUP_MEMBERS_INFO_3 {
    wchar_t* lgrmi3_domainandname{nullptr};
};

// ============================================================================
// 3. NetApiBuffer Memory Allocator
// ============================================================================

struct BufferHeader {
    uint32_t magic;
    uint32_t size;
};

inline constexpr uint32_t NETAPI_BUFFER_MAGIC = 0x4E455442; // 'NETB'

inline NET_API_STATUS __stdcall NetApiBufferAllocate(uint32_t ByteCount, void** Buffer) {
    if (!Buffer) return ERROR_INVALID_PARAMETER;
    size_t total = sizeof(BufferHeader) + ByteCount;
    auto* raw = static_cast<uint8_t*>(::operator new(total, std::nothrow));
    if (!raw) {
        *Buffer = nullptr;
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    std::memset(raw, 0, total);
    auto* hdr = reinterpret_cast<BufferHeader*>(raw);
    hdr->magic = NETAPI_BUFFER_MAGIC;
    hdr->size = ByteCount;
    *Buffer = raw + sizeof(BufferHeader);
    return NERR_Success;
}

inline NET_API_STATUS __stdcall NetApiBufferFree(void* Buffer) {
    if (!Buffer) return NERR_Success;
    auto* raw = static_cast<uint8_t*>(Buffer) - sizeof(BufferHeader);
    auto* hdr = reinterpret_cast<BufferHeader*>(raw);
    if (hdr->magic != NETAPI_BUFFER_MAGIC) {
        return ERROR_INVALID_PARAMETER;
    }
    hdr->magic = 0;
    ::operator delete(raw);
    return NERR_Success;
}

inline NET_API_STATUS __stdcall NetApiBufferSize(void* Buffer, uint32_t* ByteCount) {
    if (!Buffer || !ByteCount) return ERROR_INVALID_PARAMETER;
    const auto* raw = static_cast<const uint8_t*>(Buffer) - sizeof(BufferHeader);
    const auto* hdr = reinterpret_cast<const BufferHeader*>(raw);
    if (hdr->magic != NETAPI_BUFFER_MAGIC) {
        return ERROR_INVALID_PARAMETER;
    }
    *ByteCount = hdr->size;
    return NERR_Success;
}

inline NET_API_STATUS __stdcall NetApiBufferReallocate(void* OldBuffer, uint32_t NewByteCount, void** NewBuffer) {
    if (!NewBuffer) return ERROR_INVALID_PARAMETER;
    if (!OldBuffer) return NetApiBufferAllocate(NewByteCount, NewBuffer);

    uint32_t oldSize = 0;
    NET_API_STATUS st = NetApiBufferSize(OldBuffer, &oldSize);
    if (st != NERR_Success) return st;

    void* newBuf = nullptr;
    st = NetApiBufferAllocate(NewByteCount, &newBuf);
    if (st != NERR_Success) return st;

    std::memcpy(newBuf, OldBuffer, std::min(oldSize, NewByteCount));
    NetApiBufferFree(OldBuffer);
    *NewBuffer = newBuf;
    return NERR_Success;
}

// Helper: Allocate and copy a wide string within an allocated NetApi buffer or standalone
inline wchar_t* AllocNetApiString(const std::wstring& str) {
    void* p = nullptr;
    uint32_t bytes = static_cast<uint32_t>((str.size() + 1) * sizeof(wchar_t));
    if (NetApiBufferAllocate(bytes, &p) != NERR_Success) return nullptr;
    std::memcpy(p, str.c_str(), bytes);
    return static_cast<wchar_t*>(p);
}

// ============================================================================
// 4. Network Management Repository Engine
// ============================================================================

struct ShareRecord {
    std::wstring netname;
    uint32_t     type{STYPE_DISKTREE};
    std::wstring remark;
    uint32_t     permissions{ACCESS_ALL};
    uint32_t     maxUses{static_cast<uint32_t>(-1)};
    uint32_t     currentUses{0};
    std::wstring path;
    std::wstring passwd;
};

struct SessionRecord {
    std::wstring clientName;
    std::wstring userName;
    uint32_t     timeSeconds{0};
    uint32_t     idleSeconds{0};
};

struct UserRecord {
    std::wstring name;
    std::wstring password;
    uint32_t     passwordAge{0};
    uint32_t     privilege{USER_PRIV_USER};
    std::wstring homeDir;
    std::wstring comment;
    uint32_t     flags{UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWORD};
    std::wstring scriptPath;
};

struct LocalGroupRecord {
    std::wstring name;
    std::wstring comment;
    std::vector<std::wstring> members;
};

class NetworkManagementEngine {
public:
    static NetworkManagementEngine& get() {
        static NetworkManagementEngine instance;
        return instance;
    }

    NetworkManagementEngine() {
        resetDefaults();
    }

    void resetDefaults() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_serverName = L"MICANT-SRV";
        m_domainName = L"WORKGROUP";
        m_serverComment = L"MicaNT Clean-Room Sovereign OS Server";

        m_shares = {
            { L"ADMIN$", STYPE_DISKTREE | STYPE_SPECIAL, L"Remote Admin", ACCESS_ALL, static_cast<uint32_t>(-1), 0, L"C:\\Windows", L"" },
            { L"C$",     STYPE_DISKTREE | STYPE_SPECIAL, L"Default share", ACCESS_ALL, static_cast<uint32_t>(-1), 0, L"C:\\", L"" },
            { L"IPC$",   STYPE_IPC | STYPE_SPECIAL,      L"Remote IPC",    ACCESS_ALL, static_cast<uint32_t>(-1), 0, L"", L"" }
        };

        m_sessions = {
            { L"\\\\192.168.1.50", L"Administrator", 3600, 120 },
            { L"\\\\192.168.1.88", L"Guest",         720,  60 }
        };

        m_users = {
            { L"Administrator", L"", 0, USER_PRIV_ADMIN, L"C:\\Users\\Administrator", L"Built-in account for administering the computer/domain", UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWORD, L"" },
            { L"Guest",         L"", 0, USER_PRIV_GUEST, L"C:\\Users\\Guest",         L"Built-in account for guest access to the computer/domain", UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE, L"" },
            { L"DefaultAccount",L"", 0, USER_PRIV_USER,  L"C:\\Users\\DefaultAccount",L"A user account managed by the system",                     UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE, L"" }
        };

        m_localGroups = {
            { L"Administrators",         L"Administrators have complete and unrestricted access to the computer/domain", { L"Administrator" } },
            { L"Users",                  L"Users are prevented from making accidental or intentional system-wide changes", { L"Administrator", L"DefaultAccount" } },
            { L"Guests",                 L"Guests have the same access as members of the Users group by default",        { L"Guest" } },
            { L"Remote Desktop Users",   L"Members in this group are granted the right to logon remotely",              { L"Administrator" } }
        };
    }

    // Server Info
    std::wstring getServerName() const { std::lock_guard<std::mutex> lock(m_mutex); return m_serverName; }
    std::wstring getDomainName() const { std::lock_guard<std::mutex> lock(m_mutex); return m_domainName; }
    std::wstring getServerComment() const { std::lock_guard<std::mutex> lock(m_mutex); return m_serverComment; }

    void setServerComment(const std::wstring& comment) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_serverComment = comment;
    }

    // Shares
    std::vector<ShareRecord> getShares() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_shares;
    }

    bool addShare(const ShareRecord& share) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& s : m_shares) {
            if (_wcsicmp(s.netname.c_str(), share.netname.c_str()) == 0) {
                return false; // duplicate
            }
        }
        m_shares.push_back(share);
        return true;
    }

    bool deleteShare(const std::wstring& netname) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::remove_if(m_shares.begin(), m_shares.end(), [&](const ShareRecord& s) {
            return _wcsicmp(s.netname.c_str(), netname.c_str()) == 0;
        });
        if (it != m_shares.end()) {
            m_shares.erase(it, m_shares.end());
            return true;
        }
        return false;
    }

    bool getShare(const std::wstring& netname, ShareRecord& outShare) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& s : m_shares) {
            if (_wcsicmp(s.netname.c_str(), netname.c_str()) == 0) {
                outShare = s;
                return true;
            }
        }
        return false;
    }

    // Sessions
    std::vector<SessionRecord> getSessions() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sessions;
    }

    bool deleteSession(const std::wstring& clientName, const std::wstring& userName) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::remove_if(m_sessions.begin(), m_sessions.end(), [&](const SessionRecord& s) {
            bool cMatch = clientName.empty() || (_wcsicmp(s.clientName.c_str(), clientName.c_str()) == 0);
            bool uMatch = userName.empty() || (_wcsicmp(s.userName.c_str(), userName.c_str()) == 0);
            return cMatch && uMatch;
        });
        if (it != m_sessions.end()) {
            m_sessions.erase(it, m_sessions.end());
            return true;
        }
        return false;
    }

    // Users
    std::vector<UserRecord> getUsers() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_users;
    }

    bool getUser(const std::wstring& name, UserRecord& outUser) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& u : m_users) {
            if (_wcsicmp(u.name.c_str(), name.c_str()) == 0) {
                outUser = u;
                return true;
            }
        }
        return false;
    }

    bool addUser(const UserRecord& user) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& u : m_users) {
            if (_wcsicmp(u.name.c_str(), user.name.c_str()) == 0) return false;
        }
        m_users.push_back(user);
        return true;
    }

    bool deleteUser(const std::wstring& name) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = std::remove_if(m_users.begin(), m_users.end(), [&](const UserRecord& u) {
            return _wcsicmp(u.name.c_str(), name.c_str()) == 0;
        });
        if (it != m_users.end()) {
            m_users.erase(it, m_users.end());
            return true;
        }
        return false;
    }

    // Local Groups
    std::vector<LocalGroupRecord> getLocalGroups() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_localGroups;
    }

    bool getLocalGroup(const std::wstring& name, LocalGroupRecord& outGrp) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& g : m_localGroups) {
            if (_wcsicmp(g.name.c_str(), name.c_str()) == 0) {
                outGrp = g;
                return true;
            }
        }
        return false;
    }

    bool addLocalGroupMember(const std::wstring& group, const std::wstring& member) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& g : m_localGroups) {
            if (_wcsicmp(g.name.c_str(), group.c_str()) == 0) {
                for (const auto& m : g.members) {
                    if (_wcsicmp(m.c_str(), member.c_str()) == 0) return true; // already member
                }
                g.members.push_back(member);
                return true;
            }
        }
        return false;
    }

private:
    mutable std::mutex m_mutex;
    std::wstring m_serverName;
    std::wstring m_domainName;
    std::wstring m_serverComment;
    std::vector<ShareRecord> m_shares;
    std::vector<SessionRecord> m_sessions;
    std::vector<UserRecord> m_users;
    std::vector<LocalGroupRecord> m_localGroups;
};

// ============================================================================
// 5. NetAPI32 Win32 Implementation Functions
// ============================================================================

// --- Server & Workstation Info ---

inline NET_API_STATUS __stdcall NetServerGetInfo(const wchar_t* servername, uint32_t level, uint8_t** bufptr) {
    (void)servername;
    if (!bufptr) return ERROR_INVALID_PARAMETER;

    auto& engine = NetworkManagementEngine::get();
    std::wstring sName = engine.getServerName();
    std::wstring sComment = engine.getServerComment();

    if (level == 100) {
        SERVER_INFO_100* pInfo = nullptr;
        if (NetApiBufferAllocate(sizeof(SERVER_INFO_100), reinterpret_cast<void**>(&pInfo)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        pInfo->sv100_platform_id = PLATFORM_ID_NT;
        pInfo->sv100_name = AllocNetApiString(sName);
        *bufptr = reinterpret_cast<uint8_t*>(pInfo);
        return NERR_Success;
    } else if (level == 101) {
        SERVER_INFO_101* pInfo = nullptr;
        if (NetApiBufferAllocate(sizeof(SERVER_INFO_101), reinterpret_cast<void**>(&pInfo)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        pInfo->sv101_platform_id = PLATFORM_ID_NT;
        pInfo->sv101_name = AllocNetApiString(sName);
        pInfo->sv101_version_major = 10;
        pInfo->sv101_version_minor = 0;
        pInfo->sv101_type = SV_TYPE_SERVER | SV_TYPE_WORKSTATION | SV_TYPE_NT | SV_TYPE_SERVER_NT;
        pInfo->sv101_comment = AllocNetApiString(sComment);
        *bufptr = reinterpret_cast<uint8_t*>(pInfo);
        return NERR_Success;
    }

    return ERROR_INVALID_PARAMETER;
}

inline NET_API_STATUS __stdcall NetWkstaGetInfo(const wchar_t* servername, uint32_t level, uint8_t** bufptr) {
    (void)servername;
    if (!bufptr) return ERROR_INVALID_PARAMETER;

    auto& engine = NetworkManagementEngine::get();
    std::wstring sName = engine.getServerName();
    std::wstring dName = engine.getDomainName();

    if (level == 100) {
        WKSTA_INFO_100* pInfo = nullptr;
        if (NetApiBufferAllocate(sizeof(WKSTA_INFO_100), reinterpret_cast<void**>(&pInfo)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        pInfo->wki100_platform_id = PLATFORM_ID_NT;
        pInfo->wki100_computername = AllocNetApiString(sName);
        pInfo->wki100_langroup = AllocNetApiString(dName);
        pInfo->wki100_ver_major = 10;
        pInfo->wki100_ver_minor = 0;
        *bufptr = reinterpret_cast<uint8_t*>(pInfo);
        return NERR_Success;
    }

    return ERROR_INVALID_PARAMETER;
}

// --- Share Management ---

inline NET_API_STATUS __stdcall NetShareEnum(
    const wchar_t* servername,
    uint32_t level,
    uint8_t** bufptr,
    uint32_t prefmaxlen,
    uint32_t* entriesread,
    uint32_t* totalentries,
    uint32_t* resume_handle
) {
    (void)servername;
    (void)prefmaxlen;
    (void)resume_handle;

    if (!bufptr || !entriesread || !totalentries) return ERROR_INVALID_PARAMETER;

    auto shares = NetworkManagementEngine::get().getShares();
    *totalentries = static_cast<uint32_t>(shares.size());
    *entriesread = *totalentries;

    if (level == 0) {
        uint32_t allocBytes = *entriesread * sizeof(SHARE_INFO_0);
        SHARE_INFO_0* pArr = nullptr;
        if (NetApiBufferAllocate(allocBytes, reinterpret_cast<void**>(&pArr)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        for (uint32_t i = 0; i < *entriesread; ++i) {
            pArr[i].shi0_netname = AllocNetApiString(shares[i].netname);
        }
        *bufptr = reinterpret_cast<uint8_t*>(pArr);
        return NERR_Success;
    } else if (level == 1) {
        uint32_t allocBytes = *entriesread * sizeof(SHARE_INFO_1);
        SHARE_INFO_1* pArr = nullptr;
        if (NetApiBufferAllocate(allocBytes, reinterpret_cast<void**>(&pArr)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        for (uint32_t i = 0; i < *entriesread; ++i) {
            pArr[i].shi1_netname = AllocNetApiString(shares[i].netname);
            pArr[i].shi1_type = shares[i].type;
            pArr[i].shi1_remark = AllocNetApiString(shares[i].remark);
        }
        *bufptr = reinterpret_cast<uint8_t*>(pArr);
        return NERR_Success;
    } else if (level == 2) {
        uint32_t allocBytes = *entriesread * sizeof(SHARE_INFO_2);
        SHARE_INFO_2* pArr = nullptr;
        if (NetApiBufferAllocate(allocBytes, reinterpret_cast<void**>(&pArr)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        for (uint32_t i = 0; i < *entriesread; ++i) {
            pArr[i].shi2_netname = AllocNetApiString(shares[i].netname);
            pArr[i].shi2_type = shares[i].type;
            pArr[i].shi2_remark = AllocNetApiString(shares[i].remark);
            pArr[i].shi2_permissions = shares[i].permissions;
            pArr[i].shi2_max_uses = shares[i].maxUses;
            pArr[i].shi2_current_uses = shares[i].currentUses;
            pArr[i].shi2_path = AllocNetApiString(shares[i].path);
            pArr[i].shi2_passwd = AllocNetApiString(shares[i].passwd);
        }
        *bufptr = reinterpret_cast<uint8_t*>(pArr);
        return NERR_Success;
    }

    return ERROR_INVALID_PARAMETER;
}

inline NET_API_STATUS __stdcall NetShareGetInfo(
    const wchar_t* servername,
    const wchar_t* netname,
    uint32_t level,
    uint8_t** bufptr
) {
    (void)servername;
    if (!netname || !bufptr) return ERROR_INVALID_PARAMETER;

    ShareRecord rec;
    if (!NetworkManagementEngine::get().getShare(netname, rec)) {
        return NERR_ShareNotFound;
    }

    if (level == 1) {
        SHARE_INFO_1* pInfo = nullptr;
        if (NetApiBufferAllocate(sizeof(SHARE_INFO_1), reinterpret_cast<void**>(&pInfo)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        pInfo->shi1_netname = AllocNetApiString(rec.netname);
        pInfo->shi1_type = rec.type;
        pInfo->shi1_remark = AllocNetApiString(rec.remark);
        *bufptr = reinterpret_cast<uint8_t*>(pInfo);
        return NERR_Success;
    } else if (level == 2) {
        SHARE_INFO_2* pInfo = nullptr;
        if (NetApiBufferAllocate(sizeof(SHARE_INFO_2), reinterpret_cast<void**>(&pInfo)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        pInfo->shi2_netname = AllocNetApiString(rec.netname);
        pInfo->shi2_type = rec.type;
        pInfo->shi2_remark = AllocNetApiString(rec.remark);
        pInfo->shi2_permissions = rec.permissions;
        pInfo->shi2_max_uses = rec.maxUses;
        pInfo->shi2_current_uses = rec.currentUses;
        pInfo->shi2_path = AllocNetApiString(rec.path);
        pInfo->shi2_passwd = AllocNetApiString(rec.passwd);
        *bufptr = reinterpret_cast<uint8_t*>(pInfo);
        return NERR_Success;
    }

    return ERROR_INVALID_PARAMETER;
}

inline NET_API_STATUS __stdcall NetShareAdd(
    const wchar_t* servername,
    uint32_t level,
    const uint8_t* buf,
    uint32_t* parm_err
) {
    (void)servername;
    (void)parm_err;
    if (!buf) return ERROR_INVALID_PARAMETER;

    ShareRecord rec{};
    if (level == 2) {
        const auto* s2 = reinterpret_cast<const SHARE_INFO_2*>(buf);
        if (!s2->shi2_netname || !s2->shi2_path) return ERROR_INVALID_PARAMETER;
        rec.netname = s2->shi2_netname;
        rec.type = s2->shi2_type;
        rec.remark = s2->shi2_remark ? s2->shi2_remark : L"";
        rec.permissions = s2->shi2_permissions;
        rec.maxUses = s2->shi2_max_uses;
        rec.currentUses = 0;
        rec.path = s2->shi2_path;
        rec.passwd = s2->shi2_passwd ? s2->shi2_passwd : L"";
    } else if (level == 1) {
        const auto* s1 = reinterpret_cast<const SHARE_INFO_1*>(buf);
        if (!s1->shi1_netname) return ERROR_INVALID_PARAMETER;
        rec.netname = s1->shi1_netname;
        rec.type = s1->shi1_type;
        rec.remark = s1->shi1_remark ? s1->shi1_remark : L"";
        rec.path = L"C:\\" + rec.netname;
    } else {
        return ERROR_INVALID_PARAMETER;
    }

    if (!NetworkManagementEngine::get().addShare(rec)) {
        return NERR_DuplicateShare;
    }
    return NERR_Success;
}

inline NET_API_STATUS __stdcall NetShareDel(
    const wchar_t* servername,
    const wchar_t* netname,
    uint32_t reserved
) {
    (void)servername;
    (void)reserved;
    if (!netname) return ERROR_INVALID_PARAMETER;

    if (!NetworkManagementEngine::get().deleteShare(netname)) {
        return NERR_ShareNotFound;
    }
    return NERR_Success;
}

// --- Session Management ---

inline NET_API_STATUS __stdcall NetSessionEnum(
    const wchar_t* servername,
    const wchar_t* UncClientName,
    const wchar_t* username,
    uint32_t level,
    uint8_t** bufptr,
    uint32_t prefmaxlen,
    uint32_t* entriesread,
    uint32_t* totalentries,
    uint32_t* resume_handle
) {
    (void)servername;
    (void)prefmaxlen;
    (void)resume_handle;

    if (!bufptr || !entriesread || !totalentries) return ERROR_INVALID_PARAMETER;

    auto allSessions = NetworkManagementEngine::get().getSessions();
    std::vector<SessionRecord> filtered;
    for (const auto& s : allSessions) {
        bool cMatch = !UncClientName || (_wcsicmp(s.clientName.c_str(), UncClientName) == 0);
        bool uMatch = !username || (_wcsicmp(s.userName.c_str(), username) == 0);
        if (cMatch && uMatch) filtered.push_back(s);
    }

    *totalentries = static_cast<uint32_t>(filtered.size());
    *entriesread = *totalentries;

    if (level == 0) {
        uint32_t bytes = *entriesread * sizeof(SESSION_INFO_0);
        SESSION_INFO_0* pArr = nullptr;
        if (NetApiBufferAllocate(bytes, reinterpret_cast<void**>(&pArr)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        for (uint32_t i = 0; i < *entriesread; ++i) {
            pArr[i].sesi0_cname = AllocNetApiString(filtered[i].clientName);
        }
        *bufptr = reinterpret_cast<uint8_t*>(pArr);
        return NERR_Success;
    } else if (level == 10) {
        uint32_t bytes = *entriesread * sizeof(SESSION_INFO_10);
        SESSION_INFO_10* pArr = nullptr;
        if (NetApiBufferAllocate(bytes, reinterpret_cast<void**>(&pArr)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        for (uint32_t i = 0; i < *entriesread; ++i) {
            pArr[i].sesi10_cname = AllocNetApiString(filtered[i].clientName);
            pArr[i].sesi10_username = AllocNetApiString(filtered[i].userName);
            pArr[i].sesi10_time = filtered[i].timeSeconds;
            pArr[i].sesi10_idle_time = filtered[i].idleSeconds;
        }
        *bufptr = reinterpret_cast<uint8_t*>(pArr);
        return NERR_Success;
    }

    return ERROR_INVALID_PARAMETER;
}

inline NET_API_STATUS __stdcall NetSessionDel(
    const wchar_t* servername,
    const wchar_t* UncClientName,
    const wchar_t* username
) {
    (void)servername;
    std::wstring c = UncClientName ? UncClientName : L"";
    std::wstring u = username ? username : L"";

    if (!NetworkManagementEngine::get().deleteSession(c, u)) {
        return NERR_ClientNameNotFound;
    }
    return NERR_Success;
}

// --- User Management ---

inline NET_API_STATUS __stdcall NetUserEnum(
    const wchar_t* servername,
    uint32_t level,
    uint32_t filter,
    uint8_t** bufptr,
    uint32_t prefmaxlen,
    uint32_t* entriesread,
    uint32_t* totalentries,
    uint32_t* resume_handle
) {
    (void)servername;
    (void)filter;
    (void)prefmaxlen;
    (void)resume_handle;

    if (!bufptr || !entriesread || !totalentries) return ERROR_INVALID_PARAMETER;

    auto users = NetworkManagementEngine::get().getUsers();
    *totalentries = static_cast<uint32_t>(users.size());
    *entriesread = *totalentries;

    if (level == 0) {
        uint32_t bytes = *entriesread * sizeof(USER_INFO_0);
        USER_INFO_0* pArr = nullptr;
        if (NetApiBufferAllocate(bytes, reinterpret_cast<void**>(&pArr)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        for (uint32_t i = 0; i < *entriesread; ++i) {
            pArr[i].usri0_name = AllocNetApiString(users[i].name);
        }
        *bufptr = reinterpret_cast<uint8_t*>(pArr);
        return NERR_Success;
    } else if (level == 1) {
        uint32_t bytes = *entriesread * sizeof(USER_INFO_1);
        USER_INFO_1* pArr = nullptr;
        if (NetApiBufferAllocate(bytes, reinterpret_cast<void**>(&pArr)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        for (uint32_t i = 0; i < *entriesread; ++i) {
            pArr[i].usri1_name = AllocNetApiString(users[i].name);
            pArr[i].usri1_password = AllocNetApiString(users[i].password);
            pArr[i].usri1_password_age = users[i].passwordAge;
            pArr[i].usri1_priv = users[i].privilege;
            pArr[i].usri1_home_dir = AllocNetApiString(users[i].homeDir);
            pArr[i].usri1_comment = AllocNetApiString(users[i].comment);
            pArr[i].usri1_flags = users[i].flags;
            pArr[i].usri1_script_path = AllocNetApiString(users[i].scriptPath);
        }
        *bufptr = reinterpret_cast<uint8_t*>(pArr);
        return NERR_Success;
    }

    return ERROR_INVALID_PARAMETER;
}

inline NET_API_STATUS __stdcall NetUserGetInfo(
    const wchar_t* servername,
    const wchar_t* username,
    uint32_t level,
    uint8_t** bufptr
) {
    (void)servername;
    if (!username || !bufptr) return ERROR_INVALID_PARAMETER;

    UserRecord u;
    if (!NetworkManagementEngine::get().getUser(username, u)) {
        return NERR_UserNotFound;
    }

    if (level == 0) {
        USER_INFO_0* pInfo = nullptr;
        if (NetApiBufferAllocate(sizeof(USER_INFO_0), reinterpret_cast<void**>(&pInfo)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        pInfo->usri0_name = AllocNetApiString(u.name);
        *bufptr = reinterpret_cast<uint8_t*>(pInfo);
        return NERR_Success;
    } else if (level == 1) {
        USER_INFO_1* pInfo = nullptr;
        if (NetApiBufferAllocate(sizeof(USER_INFO_1), reinterpret_cast<void**>(&pInfo)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        pInfo->usri1_name = AllocNetApiString(u.name);
        pInfo->usri1_password = AllocNetApiString(u.password);
        pInfo->usri1_password_age = u.passwordAge;
        pInfo->usri1_priv = u.privilege;
        pInfo->usri1_home_dir = AllocNetApiString(u.homeDir);
        pInfo->usri1_comment = AllocNetApiString(u.comment);
        pInfo->usri1_flags = u.flags;
        pInfo->usri1_script_path = AllocNetApiString(u.scriptPath);
        *bufptr = reinterpret_cast<uint8_t*>(pInfo);
        return NERR_Success;
    }

    return ERROR_INVALID_PARAMETER;
}

inline NET_API_STATUS __stdcall NetUserAdd(
    const wchar_t* servername,
    uint32_t level,
    const uint8_t* buf,
    uint32_t* parm_err
) {
    (void)servername;
    (void)parm_err;
    if (!buf) return ERROR_INVALID_PARAMETER;

    UserRecord rec{};
    if (level == 1) {
        const auto* u1 = reinterpret_cast<const USER_INFO_1*>(buf);
        if (!u1->usri1_name) return ERROR_INVALID_PARAMETER;
        rec.name = u1->usri1_name;
        rec.password = u1->usri1_password ? u1->usri1_password : L"";
        rec.passwordAge = u1->usri1_password_age;
        rec.privilege = u1->usri1_priv;
        rec.homeDir = u1->usri1_home_dir ? u1->usri1_home_dir : L"";
        rec.comment = u1->usri1_comment ? u1->usri1_comment : L"";
        rec.flags = u1->usri1_flags;
        rec.scriptPath = u1->usri1_script_path ? u1->usri1_script_path : L"";
    } else {
        return ERROR_INVALID_PARAMETER;
    }

    if (!NetworkManagementEngine::get().addUser(rec)) {
        return ERROR_INVALID_PARAMETER;
    }
    return NERR_Success;
}

inline NET_API_STATUS __stdcall NetUserDel(
    const wchar_t* servername,
    const wchar_t* username
) {
    (void)servername;
    if (!username) return ERROR_INVALID_PARAMETER;
    if (!NetworkManagementEngine::get().deleteUser(username)) {
        return NERR_UserNotFound;
    }
    return NERR_Success;
}

// --- Local Group Management ---

inline NET_API_STATUS __stdcall NetLocalGroupEnum(
    const wchar_t* servername,
    uint32_t level,
    uint8_t** bufptr,
    uint32_t prefmaxlen,
    uint32_t* entriesread,
    uint32_t* totalentries,
    uint32_t* resume_handle
) {
    (void)servername;
    (void)prefmaxlen;
    (void)resume_handle;

    if (!bufptr || !entriesread || !totalentries) return ERROR_INVALID_PARAMETER;

    auto grps = NetworkManagementEngine::get().getLocalGroups();
    *totalentries = static_cast<uint32_t>(grps.size());
    *entriesread = *totalentries;

    if (level == 0) {
        uint32_t bytes = *entriesread * sizeof(LOCALGROUP_INFO_0);
        LOCALGROUP_INFO_0* pArr = nullptr;
        if (NetApiBufferAllocate(bytes, reinterpret_cast<void**>(&pArr)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        for (uint32_t i = 0; i < *entriesread; ++i) {
            pArr[i].lgrpi0_name = AllocNetApiString(grps[i].name);
        }
        *bufptr = reinterpret_cast<uint8_t*>(pArr);
        return NERR_Success;
    } else if (level == 1) {
        uint32_t bytes = *entriesread * sizeof(LOCALGROUP_INFO_1);
        LOCALGROUP_INFO_1* pArr = nullptr;
        if (NetApiBufferAllocate(bytes, reinterpret_cast<void**>(&pArr)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        for (uint32_t i = 0; i < *entriesread; ++i) {
            pArr[i].lgrpi1_name = AllocNetApiString(grps[i].name);
            pArr[i].lgrpi1_comment = AllocNetApiString(grps[i].comment);
        }
        *bufptr = reinterpret_cast<uint8_t*>(pArr);
        return NERR_Success;
    }

    return ERROR_INVALID_PARAMETER;
}

inline NET_API_STATUS __stdcall NetLocalGroupGetInfo(
    const wchar_t* servername,
    const wchar_t* groupname,
    uint32_t level,
    uint8_t** bufptr
) {
    (void)servername;
    if (!groupname || !bufptr) return ERROR_INVALID_PARAMETER;

    LocalGroupRecord grp;
    if (!NetworkManagementEngine::get().getLocalGroup(groupname, grp)) {
        return NERR_GroupNotFound;
    }

    if (level == 0) {
        LOCALGROUP_INFO_0* pInfo = nullptr;
        if (NetApiBufferAllocate(sizeof(LOCALGROUP_INFO_0), reinterpret_cast<void**>(&pInfo)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        pInfo->lgrpi0_name = AllocNetApiString(grp.name);
        *bufptr = reinterpret_cast<uint8_t*>(pInfo);
        return NERR_Success;
    } else if (level == 1) {
        LOCALGROUP_INFO_1* pInfo = nullptr;
        if (NetApiBufferAllocate(sizeof(LOCALGROUP_INFO_1), reinterpret_cast<void**>(&pInfo)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        pInfo->lgrpi1_name = AllocNetApiString(grp.name);
        pInfo->lgrpi1_comment = AllocNetApiString(grp.comment);
        *bufptr = reinterpret_cast<uint8_t*>(pInfo);
        return NERR_Success;
    }

    return ERROR_INVALID_PARAMETER;
}

inline NET_API_STATUS __stdcall NetLocalGroupGetMembers(
    const wchar_t* servername,
    const wchar_t* localgroupname,
    uint32_t level,
    uint8_t** bufptr,
    uint32_t prefmaxlen,
    uint32_t* entriesread,
    uint32_t* totalentries,
    uint32_t* resumehandle
) {
    (void)servername;
    (void)prefmaxlen;
    (void)resumehandle;

    if (!localgroupname || !bufptr || !entriesread || !totalentries) return ERROR_INVALID_PARAMETER;

    LocalGroupRecord grp;
    if (!NetworkManagementEngine::get().getLocalGroup(localgroupname, grp)) {
        return NERR_GroupNotFound;
    }

    *totalentries = static_cast<uint32_t>(grp.members.size());
    *entriesread = *totalentries;

    if (level == 3) {
        uint32_t bytes = *entriesread * sizeof(LOCALGROUP_MEMBERS_INFO_3);
        LOCALGROUP_MEMBERS_INFO_3* pArr = nullptr;
        if (NetApiBufferAllocate(bytes, reinterpret_cast<void**>(&pArr)) != NERR_Success) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        for (uint32_t i = 0; i < *entriesread; ++i) {
            pArr[i].lgrmi3_domainandname = AllocNetApiString(grp.members[i]);
        }
        *bufptr = reinterpret_cast<uint8_t*>(pArr);
        return NERR_Success;
    }

    return ERROR_INVALID_PARAMETER;
}

inline NET_API_STATUS __stdcall NetLocalGroupAddMembers(
    const wchar_t* servername,
    const wchar_t* groupname,
    uint32_t level,
    const uint8_t* buf,
    uint32_t totalentries
) {
    (void)servername;
    if (!groupname || !buf || totalentries == 0) return ERROR_INVALID_PARAMETER;

    if (level == 3) {
        const auto* arr = reinterpret_cast<const LOCALGROUP_MEMBERS_INFO_3*>(buf);
        for (uint32_t i = 0; i < totalentries; ++i) {
            if (arr[i].lgrmi3_domainandname) {
                NetworkManagementEngine::get().addLocalGroupMember(groupname, arr[i].lgrmi3_domainandname);
            }
        }
        return NERR_Success;
    }

    return ERROR_INVALID_PARAMETER;
}

// ============================================================================
// 6. Dynamic Loader & SCM Registration
// ============================================================================

inline void InitializeNetApiSubsystemExports() {
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    auto& ldr = ldr::DynamicLoader::get();

    // 1. netapi32.dll exports
    ldr.registerExport("netapi32.dll", "NetApiBufferAllocate", reinterpret_cast<void*>(NetApiBufferAllocate));
    ldr.registerExport("netapi32.dll", "NetApiBufferFree", reinterpret_cast<void*>(NetApiBufferFree));
    ldr.registerExport("netapi32.dll", "NetApiBufferSize", reinterpret_cast<void*>(NetApiBufferSize));
    ldr.registerExport("netapi32.dll", "NetApiBufferReallocate", reinterpret_cast<void*>(NetApiBufferReallocate));

    ldr.registerExport("netapi32.dll", "NetServerGetInfo", reinterpret_cast<void*>(NetServerGetInfo));
    ldr.registerExport("netapi32.dll", "NetWkstaGetInfo", reinterpret_cast<void*>(NetWkstaGetInfo));

    ldr.registerExport("netapi32.dll", "NetShareEnum", reinterpret_cast<void*>(NetShareEnum));
    ldr.registerExport("netapi32.dll", "NetShareGetInfo", reinterpret_cast<void*>(NetShareGetInfo));
    ldr.registerExport("netapi32.dll", "NetShareAdd", reinterpret_cast<void*>(NetShareAdd));
    ldr.registerExport("netapi32.dll", "NetShareDel", reinterpret_cast<void*>(NetShareDel));

    ldr.registerExport("netapi32.dll", "NetSessionEnum", reinterpret_cast<void*>(NetSessionEnum));
    ldr.registerExport("netapi32.dll", "NetSessionDel", reinterpret_cast<void*>(NetSessionDel));

    ldr.registerExport("netapi32.dll", "NetUserEnum", reinterpret_cast<void*>(NetUserEnum));
    ldr.registerExport("netapi32.dll", "NetUserGetInfo", reinterpret_cast<void*>(NetUserGetInfo));
    ldr.registerExport("netapi32.dll", "NetUserAdd", reinterpret_cast<void*>(NetUserAdd));
    ldr.registerExport("netapi32.dll", "NetUserDel", reinterpret_cast<void*>(NetUserDel));

    ldr.registerExport("netapi32.dll", "NetLocalGroupEnum", reinterpret_cast<void*>(NetLocalGroupEnum));
    ldr.registerExport("netapi32.dll", "NetLocalGroupGetInfo", reinterpret_cast<void*>(NetLocalGroupGetInfo));
    ldr.registerExport("netapi32.dll", "NetLocalGroupGetMembers", reinterpret_cast<void*>(NetLocalGroupGetMembers));
    ldr.registerExport("netapi32.dll", "NetLocalGroupAddMembers", reinterpret_cast<void*>(NetLocalGroupAddMembers));

    // 2. srvcli.dll exports (Server Service Client)
    ldr.registerExport("srvcli.dll", "NetServerGetInfo", reinterpret_cast<void*>(NetServerGetInfo));
    ldr.registerExport("srvcli.dll", "NetShareEnum", reinterpret_cast<void*>(NetShareEnum));
    ldr.registerExport("srvcli.dll", "NetShareGetInfo", reinterpret_cast<void*>(NetShareGetInfo));
    ldr.registerExport("srvcli.dll", "NetShareAdd", reinterpret_cast<void*>(NetShareAdd));
    ldr.registerExport("srvcli.dll", "NetShareDel", reinterpret_cast<void*>(NetShareDel));
    ldr.registerExport("srvcli.dll", "NetSessionEnum", reinterpret_cast<void*>(NetSessionEnum));
    ldr.registerExport("srvcli.dll", "NetSessionDel", reinterpret_cast<void*>(NetSessionDel));

    // 3. wkscli.dll exports (Workstation Service Client)
    ldr.registerExport("wkscli.dll", "NetWkstaGetInfo", reinterpret_cast<void*>(NetWkstaGetInfo));

    // 4. SCM Services: LanmanServer ("Server") & LanmanWorkstation ("Workstation")
    auto& scm = scm::ServiceControlManager::get();

    // LanmanServer
    auto srvRecord = std::make_shared<scm::ServiceRecord>();
    srvRecord->serviceName = L"LanmanServer";
    srvRecord->displayName = L"Server";
    srvRecord->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
    srvRecord->startType = scm::SERVICE_AUTO_START;
    srvRecord->errorControl = scm::SERVICE_ERROR_NORMAL;
    srvRecord->svchostGroup = "netsvcs";
    srvRecord->binaryPath = L"C:\\Windows\\System32\\svchost.exe -k netsvcs -p";
    srvRecord->status.dwServiceType = srvRecord->serviceType;
    srvRecord->status.dwCurrentState = scm::SERVICE_RUNNING;
    srvRecord->status.dwProcessId = scm::SvcHostManager::get().getOrCreateGroupProcess("netsvcs");
    scm::SvcHostManager::get().assignService("netsvcs", srvRecord->serviceName);
    scm.registerServiceRecord(srvRecord);

    // LanmanWorkstation
    auto wkstaRecord = std::make_shared<scm::ServiceRecord>();
    wkstaRecord->serviceName = L"LanmanWorkstation";
    wkstaRecord->displayName = L"Workstation";
    wkstaRecord->serviceType = scm::SERVICE_WIN32_SHARE_PROCESS;
    wkstaRecord->startType = scm::SERVICE_AUTO_START;
    wkstaRecord->errorControl = scm::SERVICE_ERROR_NORMAL;
    wkstaRecord->svchostGroup = "NetworkService";
    wkstaRecord->binaryPath = L"C:\\Windows\\System32\\svchost.exe -k NetworkService -p";
    wkstaRecord->status.dwServiceType = wkstaRecord->serviceType;
    wkstaRecord->status.dwCurrentState = scm::SERVICE_RUNNING;
    wkstaRecord->status.dwProcessId = scm::SvcHostManager::get().getOrCreateGroupProcess("NetworkService");
    scm::SvcHostManager::get().assignService("NetworkService", wkstaRecord->serviceName);
    scm.registerServiceRecord(wkstaRecord);
}

} // namespace micant::netapi
