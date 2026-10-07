#pragma once

/**
 * @file advapi32.hpp
 * @brief MicaNT Clean-Room Advanced Windows 32 Base API (advapi32.dll) Bridge.
 *
 * Implements security, crypto random, token management, and Service Control
 * Manager (SCM) exports.
 */

#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "kernel32.hpp"
#include "ldr.hpp"
#include "scm.hpp"
#include "sam.hpp"
#include "lsass.hpp"
#include "cipherksp.hpp"

namespace micant::advapi32 {

using SC_HANDLE   = void*;
using HCRYPTPROV  = uintptr_t;
using HCRYPTHASH  = uintptr_t;
using HCRYPTKEY   = uintptr_t;

inline constexpr uint32_t PROV_RSA_FULL        = 1;
inline constexpr uint32_t PROV_RSA_AES         = 24;

inline constexpr uint32_t CRYPT_VERIFYCONTEXT  = 0xF0000000;
inline constexpr uint32_t CRYPT_NEWKEYSET      = 0x00000008;
inline constexpr uint32_t CRYPT_DELETEKEYSET   = 0x00000010;

inline constexpr uint32_t CALG_MD5             = 0x8003;
inline constexpr uint32_t CALG_SHA1            = 0x8004;
inline constexpr uint32_t CALG_SHA_256         = 0x800c;
inline constexpr uint32_t CALG_AES_128         = 0x660e;
inline constexpr uint32_t CALG_AES_256         = 0x6610;

inline constexpr uint32_t HP_ALGID             = 0x0001;
inline constexpr uint32_t HP_HASHVAL           = 0x0002;
inline constexpr uint32_t HP_HASHSIZE          = 0x0004;

inline constexpr uint32_t PLAINTEXTKEYBLOB     = 0x8;
inline constexpr uint32_t SIMPLEBLOB           = 0x1;

struct CryptoApiContext {
    std::string container;
    std::string provider;
    uint32_t provType{PROV_RSA_FULL};
};

struct CryptoApiHash {
    uint32_t algId{CALG_SHA_256};
    std::vector<uint8_t> buffer;
    bool finished{false};
    std::vector<uint8_t> digest;

    void update(const uint8_t* data, size_t len) {
        if (!finished) buffer.insert(buffer.end(), data, data + len);
    }

    const std::vector<uint8_t>& getDigest() {
        if (!finished) {
            finished = true;
            if (algId == CALG_MD5) {
                digest = crypto::Md5::hash(buffer);
            } else if (algId == CALG_SHA1) {
                digest = crypto::Sha1::hash(buffer);
            } else {
                digest = crypto::Sha256::hash(buffer);
            }
        }
        return digest;
    }
};

struct CryptoApiKey {
    uint32_t algId{CALG_AES_256};
    std::vector<uint8_t> secret;
};

class CryptoApiManager {
private:
    std::mutex m_mutex;
    uintptr_t m_nextId{0x1000};
    std::unordered_map<HCRYPTPROV, std::shared_ptr<CryptoApiContext>> m_provs;
    std::unordered_map<HCRYPTHASH, std::shared_ptr<CryptoApiHash>>    m_hashes;
    std::unordered_map<HCRYPTKEY,  std::shared_ptr<CryptoApiKey>>     m_keys;

public:
    static CryptoApiManager& Instance() {
        static CryptoApiManager s_inst;
        return s_inst;
    }

    HCRYPTPROV registerProv(const std::string& cont, const std::string& prov, uint32_t type) {
        std::lock_guard<std::mutex> lock(m_mutex);
        uintptr_t id = m_nextId++;
        auto ctx = std::make_shared<CryptoApiContext>();
        ctx->container = cont;
        ctx->provider = prov;
        ctx->provType = type;
        m_provs[id] = ctx;
        return id;
    }

    bool releaseProv(HCRYPTPROV hProv) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_provs.erase(hProv) > 0;
    }

    HCRYPTHASH registerHash(uint32_t algId) {
        std::lock_guard<std::mutex> lock(m_mutex);
        uintptr_t id = m_nextId++;
        auto h = std::make_shared<CryptoApiHash>();
        h->algId = algId;
        m_hashes[id] = h;
        return id;
    }

    std::shared_ptr<CryptoApiHash> getHash(HCRYPTHASH hHash) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_hashes.find(hHash);
        return (it != m_hashes.end()) ? it->second : nullptr;
    }

    bool releaseHash(HCRYPTHASH hHash) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_hashes.erase(hHash) > 0;
    }

    HCRYPTKEY registerKey(uint32_t algId, std::span<const uint8_t> secret) {
        std::lock_guard<std::mutex> lock(m_mutex);
        uintptr_t id = m_nextId++;
        auto k = std::make_shared<CryptoApiKey>();
        k->algId = algId;
        k->secret.assign(secret.begin(), secret.end());
        m_keys[id] = k;
        return id;
    }

    std::shared_ptr<CryptoApiKey> getKey(HCRYPTKEY hKey) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_keys.find(hKey);
        return (it != m_keys.end()) ? it->second : nullptr;
    }

    bool releaseKey(HCRYPTKEY hKey) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_keys.erase(hKey) > 0;
    }
};

inline win32::BOOL CryptAcquireContextA(
    HCRYPTPROV* phProv,
    const char* szContainer,
    const char* szProvider,
    uint32_t dwProvType,
    [[maybe_unused]] uint32_t dwFlags
) noexcept {
    if (!phProv) {
        win32::SetLastError(87);
        return win32::FALSE;
    }
    std::string cont = szContainer ? szContainer : "";
    std::string prov = szProvider ? szProvider : "MicaNT RSA/AES Provider";
    *phProv = CryptoApiManager::Instance().registerProv(cont, prov, dwProvType);
    return win32::TRUE;
}

inline win32::BOOL CryptAcquireContextW(
    HCRYPTPROV* phProv,
    const wchar_t* szContainer,
    const wchar_t* szProvider,
    uint32_t dwProvType,
    uint32_t dwFlags
) noexcept {
    std::string cont;
    if (szContainer) {
        while (*szContainer) cont.push_back(static_cast<char>(*szContainer++));
    }
    std::string prov;
    if (szProvider) {
        while (*szProvider) prov.push_back(static_cast<char>(*szProvider++));
    }
    return CryptAcquireContextA(phProv, cont.empty() ? nullptr : cont.c_str(), prov.empty() ? nullptr : prov.c_str(), dwProvType, dwFlags);
}

inline win32::BOOL CryptReleaseContext(HCRYPTPROV hProv, [[maybe_unused]] uint32_t dwFlags) noexcept {
    return CryptoApiManager::Instance().releaseProv(hProv) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL CryptGenRandom([[maybe_unused]] HCRYPTPROV hProv, uint32_t dwLen, uint8_t* pbBuffer) noexcept {
    if (!pbBuffer) {
        win32::SetLastError(87);
        return win32::FALSE;
    }
    crypto::Csprng::get().getBytes(std::span<uint8_t>(pbBuffer, dwLen));
    return win32::TRUE;
}

inline win32::BOOL CryptCreateHash(
    [[maybe_unused]] HCRYPTPROV hProv,
    uint32_t Algid,
    [[maybe_unused]] HCRYPTKEY hKey,
    [[maybe_unused]] uint32_t dwFlags,
    HCRYPTHASH* phHash
) noexcept {
    if (!phHash) {
        win32::SetLastError(87);
        return win32::FALSE;
    }
    *phHash = CryptoApiManager::Instance().registerHash(Algid);
    return win32::TRUE;
}

inline win32::BOOL CryptHashData(
    HCRYPTHASH hHash,
    const uint8_t* pbData,
    uint32_t dwDataLen,
    [[maybe_unused]] uint32_t dwFlags
) noexcept {
    if (!pbData && dwDataLen > 0) {
        win32::SetLastError(87);
        return win32::FALSE;
    }
    auto hash = CryptoApiManager::Instance().getHash(hHash);
    if (!hash) {
        win32::SetLastError(6); // ERROR_INVALID_HANDLE
        return win32::FALSE;
    }
    hash->update(pbData, dwDataLen);
    return win32::TRUE;
}

inline win32::BOOL CryptGetHashParam(
    HCRYPTHASH hHash,
    uint32_t dwParam,
    uint8_t* pbData,
    uint32_t* pdwDataLen,
    [[maybe_unused]] uint32_t dwFlags
) noexcept {
    if (!pdwDataLen) {
        win32::SetLastError(87);
        return win32::FALSE;
    }
    auto hash = CryptoApiManager::Instance().getHash(hHash);
    if (!hash) {
        win32::SetLastError(6);
        return win32::FALSE;
    }

    if (dwParam == HP_HASHSIZE) {
        uint32_t sz = (hash->algId == CALG_MD5) ? 16 : ((hash->algId == CALG_SHA1) ? 20 : 32);
        if (!pbData) {
            *pdwDataLen = sizeof(uint32_t);
            return win32::TRUE;
        }
        if (*pdwDataLen < sizeof(uint32_t)) {
            *pdwDataLen = sizeof(uint32_t);
            win32::SetLastError(122);
            return win32::FALSE;
        }
        std::memcpy(pbData, &sz, sizeof(uint32_t));
        return win32::TRUE;
    }

    if (dwParam == HP_HASHVAL) {
        const auto& d = hash->getDigest();
        uint32_t req = static_cast<uint32_t>(d.size());
        if (!pbData) {
            *pdwDataLen = req;
            return win32::TRUE;
        }
        if (*pdwDataLen < req) {
            *pdwDataLen = req;
            win32::SetLastError(122);
            return win32::FALSE;
        }
        std::memcpy(pbData, d.data(), req);
        *pdwDataLen = req;
        return win32::TRUE;
    }

    win32::SetLastError(87);
    return win32::FALSE;
}

inline win32::BOOL CryptDestroyHash(HCRYPTHASH hHash) noexcept {
    return CryptoApiManager::Instance().releaseHash(hHash) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL CryptDeriveKey(
    [[maybe_unused]] HCRYPTPROV hProv,
    uint32_t Algid,
    HCRYPTHASH hBaseData,
    [[maybe_unused]] uint32_t dwFlags,
    HCRYPTKEY* phKey
) noexcept {
    if (!phKey) {
        win32::SetLastError(87);
        return win32::FALSE;
    }
    auto hash = CryptoApiManager::Instance().getHash(hBaseData);
    if (!hash) {
        win32::SetLastError(6);
        return win32::FALSE;
    }
    const auto& d = hash->getDigest();
    uint32_t keyLen = (Algid == CALG_AES_128) ? 16 : 32;
    std::vector<uint8_t> secret(keyLen);
    for (size_t i = 0; i < keyLen; ++i) {
        secret[i] = d[i % d.size()];
    }
    *phKey = CryptoApiManager::Instance().registerKey(Algid, secret);
    return win32::TRUE;
}

inline win32::BOOL CryptDestroyKey(HCRYPTKEY hKey) noexcept {
    return CryptoApiManager::Instance().releaseKey(hKey) ? win32::TRUE : win32::FALSE;
}

inline win32::BOOL CryptEncrypt(
    HCRYPTKEY hKey,
    [[maybe_unused]] HCRYPTHASH hHash,
    [[maybe_unused]] win32::BOOL Final,
    [[maybe_unused]] uint32_t dwFlags,
    uint8_t* pbData,
    uint32_t* pdwDataLen,
    uint32_t dwBufLen
) noexcept {
    if (!pbData || !pdwDataLen) {
        win32::SetLastError(87);
        return win32::FALSE;
    }
    auto key = CryptoApiManager::Instance().getKey(hKey);
    if (!key) {
        win32::SetLastError(6);
        return win32::FALSE;
    }

    crypto::Aes aes(key->secret);
    uint8_t iv[16]{};
    auto enc = aes.encrypt(std::span<const uint8_t>(pbData, *pdwDataLen), crypto::Aes::Mode::CBC, iv, true);

    if (dwBufLen < enc.size()) {
        *pdwDataLen = static_cast<uint32_t>(enc.size());
        win32::SetLastError(122);
        return win32::FALSE;
    }

    std::memcpy(pbData, enc.data(), enc.size());
    *pdwDataLen = static_cast<uint32_t>(enc.size());
    return win32::TRUE;
}

inline win32::BOOL CryptDecrypt(
    HCRYPTKEY hKey,
    [[maybe_unused]] HCRYPTHASH hHash,
    [[maybe_unused]] win32::BOOL Final,
    [[maybe_unused]] uint32_t dwFlags,
    uint8_t* pbData,
    uint32_t* pdwDataLen
) noexcept {
    if (!pbData || !pdwDataLen) {
        win32::SetLastError(87);
        return win32::FALSE;
    }
    auto key = CryptoApiManager::Instance().getKey(hKey);
    if (!key) {
        win32::SetLastError(6);
        return win32::FALSE;
    }

    crypto::Aes aes(key->secret);
    uint8_t iv[16]{};
    bool ok = false;
    auto dec = aes.decrypt(std::span<const uint8_t>(pbData, *pdwDataLen), crypto::Aes::Mode::CBC, iv, true, &ok);
    if (!ok) {
        win32::SetLastError(0x80090005); // NTE_BAD_DATA
        return win32::FALSE;
    }

    std::memcpy(pbData, dec.data(), dec.size());
    *pdwDataLen = static_cast<uint32_t>(dec.size());
    return win32::TRUE;
}

inline win32::BOOL OpenProcessToken(
    win32::HANDLE /*ProcessHandle*/,
    uint32_t /*DesiredAccess*/,
    win32::HANDLE* TokenHandle
) noexcept {
    if (TokenHandle) *TokenHandle = reinterpret_cast<win32::HANDLE>(0x0000000000000100ULL);
    return win32::TRUE;
}

inline win32::BOOL GetTokenInformation(
    win32::HANDLE /*TokenHandle*/,
    uint32_t /*TokenInformationClass*/,
    void* /*TokenInformation*/,
    uint32_t /*TokenInformationLength*/,
    uint32_t* ReturnLength
) noexcept {
    if (ReturnLength) *ReturnLength = 64;
    return win32::TRUE;
}

// ============================================================================
// Security, Logon & LSA Win32 APIs
// ============================================================================

inline win32::BOOL LogonUserW(
    const wchar_t* lpszUsername,
    const wchar_t* lpszDomain,
    const wchar_t* lpszPassword,
    uint32_t dwLogonType,
    uint32_t /*dwLogonProvider*/,
    win32::HANDLE* phToken
) noexcept {
    if (!lpszUsername || !phToken) {
        win32::SetLastError(87); // ERROR_INVALID_PARAMETER
        return win32::FALSE;
    }

    std::wstring user(lpszUsername);
    std::wstring dom = lpszDomain ? lpszDomain : L"";
    std::wstring pass = lpszPassword ? lpszPassword : L"";

    std::shared_ptr<se::TokenObject> token;
    Luid logonId{0, 0};
    NTSTATUS st = lsass::LocalSecurityAuthority::get().logonUser(
        dom, user, pass, static_cast<lsass::SecurityLogonType>(dwLogonType), L"MSV1_0", token, logonId
    );

    if (st != STATUS_SUCCESS) {
        win32::SetLastError(1326); // ERROR_LOGON_FAILURE
        return win32::FALSE;
    }

    *phToken = reinterpret_cast<win32::HANDLE>(static_cast<uintptr_t>(logonId.toUint64()));
    return win32::TRUE;
}

inline win32::BOOL LookupAccountSidW(
    const wchar_t* /*lpSystemName*/,
    const se::Sid* lpSid,
    wchar_t* lpName,
    uint32_t* cchName,
    wchar_t* lpReferencedDomainName,
    uint32_t* cchReferencedDomainName,
    uint32_t* peUse
) noexcept {
    if (!lpSid || !cchName || !cchReferencedDomainName) {
        win32::SetLastError(87);
        return win32::FALSE;
    }

    std::wstring name, domain;
    if (!lsass::LocalSecurityAuthority::get().lookupAccountSid(*lpSid, name, domain)) {
        win32::SetLastError(1332); // ERROR_NONE_MAPPED
        return win32::FALSE;
    }

    if (lpName && *cchName > name.size()) {
        wcscpy_s(lpName, *cchName, name.c_str());
    }
    *cchName = static_cast<uint32_t>(name.size());

    if (lpReferencedDomainName && *cchReferencedDomainName > domain.size()) {
        wcscpy_s(lpReferencedDomainName, *cchReferencedDomainName, domain.c_str());
    }
    *cchReferencedDomainName = static_cast<uint32_t>(domain.size());

    if (peUse) *peUse = 1; // SidTypeUser
    return win32::TRUE;
}

inline win32::BOOL LookupAccountNameW(
    const wchar_t* /*lpSystemName*/,
    const wchar_t* lpAccountName,
    se::Sid* Sid,
    uint32_t* cbSid,
    wchar_t* ReferencedDomainName,
    uint32_t* cchReferencedDomainName,
    uint32_t* peUse
) noexcept {
    if (!lpAccountName || !cbSid || !cchReferencedDomainName) {
        win32::SetLastError(87);
        return win32::FALSE;
    }

    se::Sid resolvedSid;
    std::wstring domain;
    if (!lsass::LocalSecurityAuthority::get().lookupAccountName(lpAccountName, resolvedSid, domain)) {
        win32::SetLastError(1332);
        return win32::FALSE;
    }

    if (Sid) *Sid = resolvedSid;
    *cbSid = sizeof(se::Sid);

    if (ReferencedDomainName && *cchReferencedDomainName > domain.size()) {
        wcscpy_s(ReferencedDomainName, *cchReferencedDomainName, domain.c_str());
    }
    *cchReferencedDomainName = static_cast<uint32_t>(domain.size());

    if (peUse) *peUse = 1;
    return win32::TRUE;
}

inline win32::BOOL LookupPrivilegeValueW(
    const wchar_t* /*lpSystemName*/,
    const wchar_t* lpName,
    Luid* lpLuid
) noexcept {
    if (!lpName || !lpLuid) {
        win32::SetLastError(87);
        return win32::FALSE;
    }

    static const std::unordered_map<std::wstring, uint32_t> privMap = {
        {L"SeCreateTokenPrivilege", 2},
        {L"SeAssignPrimaryTokenPrivilege", 3},
        {L"SeLockMemoryPrivilege", 4},
        {L"SeIncreaseQuotaPrivilege", 5},
        {L"SeTcbPrivilege", 7},
        {L"SeSecurityPrivilege", 8},
        {L"SeTakeOwnershipPrivilege", 9},
        {L"SeLoadDriverPrivilege", 10},
        {L"SeSystemtimePrivilege", 12},
        {L"SeBackupPrivilege", 17},
        {L"SeRestorePrivilege", 18},
        {L"SeShutdownPrivilege", 19},
        {L"SeDebugPrivilege", 20},
        {L"SeSystemEnvironmentPrivilege", 22},
        {L"SeChangeNotifyPrivilege", 23},
        {L"SeImpersonatePrivilege", 29}
    };

    auto it = privMap.find(lpName);
    if (it != privMap.end()) {
        lpLuid->lowPart = it->second;
        lpLuid->highPart = 0;
        return win32::TRUE;
    }

    win32::SetLastError(1313); // ERROR_NO_SUCH_PRIVILEGE
    return win32::FALSE;
}

inline win32::BOOL LookupPrivilegeNameW(
    const wchar_t* /*lpSystemName*/,
    const Luid* lpLuid,
    wchar_t* lpName,
    uint32_t* cchName
) noexcept {
    if (!lpLuid || !cchName) {
        win32::SetLastError(87);
        return win32::FALSE;
    }

    static const std::unordered_map<uint32_t, std::wstring> luidMap = {
        {2, L"SeCreateTokenPrivilege"},
        {3, L"SeAssignPrimaryTokenPrivilege"},
        {4, L"SeLockMemoryPrivilege"},
        {5, L"SeIncreaseQuotaPrivilege"},
        {7, L"SeTcbPrivilege"},
        {8, L"SeSecurityPrivilege"},
        {9, L"SeTakeOwnershipPrivilege"},
        {10, L"SeLoadDriverPrivilege"},
        {12, L"SeSystemtimePrivilege"},
        {17, L"SeBackupPrivilege"},
        {18, L"SeRestorePrivilege"},
        {19, L"SeShutdownPrivilege"},
        {20, L"SeDebugPrivilege"},
        {22, L"SeSystemEnvironmentPrivilege"},
        {23, L"SeChangeNotifyPrivilege"},
        {29, L"SeImpersonatePrivilege"}
    };

    auto it = luidMap.find(lpLuid->lowPart);
    if (it != luidMap.end()) {
        if (lpName && *cchName > it->second.size()) {
            wcscpy_s(lpName, *cchName, it->second.c_str());
        }
        *cchName = static_cast<uint32_t>(it->second.size());
        return win32::TRUE;
    }

    win32::SetLastError(1313);
    return win32::FALSE;
}

inline NTSTATUS LsaOpenPolicy(
    const void* /*SystemName*/,
    const void* /*ObjectAttributes*/,
    uint32_t /*DesiredAccess*/,
    uintptr_t* PolicyHandle
) noexcept {
    if (PolicyHandle) *PolicyHandle = 0xCAFE0002;
    return STATUS_SUCCESS;
}

inline NTSTATUS LsaClose(uintptr_t /*ObjectHandle*/) noexcept {
    return STATUS_SUCCESS;
}

// ============================================================================
// Service Control Manager (SCM) Win32 APIs
// ============================================================================

inline SC_HANDLE OpenSCManagerW(
    const wchar_t* lpMachineName,
    const wchar_t* lpDatabaseName,
    uint32_t dwDesiredAccess
) noexcept {
    uintptr_t handle = 0;
    std::wstring machine = lpMachineName ? lpMachineName : L"";
    std::wstring db = lpDatabaseName ? lpDatabaseName : L"";
    uint32_t err = scm::ServiceControlManager::get().openSCManager(machine, db, dwDesiredAccess, handle);
    if (err != scm::ERROR_SUCCESS) {
        win32::SetLastError(err);
        return nullptr;
    }
    return reinterpret_cast<SC_HANDLE>(handle);
}

inline SC_HANDLE CreateServiceW(
    SC_HANDLE hSCManager,
    const wchar_t* lpServiceName,
    const wchar_t* lpDisplayName,
    uint32_t dwDesiredAccess,
    uint32_t dwServiceType,
    uint32_t dwStartType,
    uint32_t dwErrorControl,
    const wchar_t* lpBinaryPathName,
    const wchar_t* lpLoadOrderGroup,
    uint32_t* lpdwTagId,
    const wchar_t* lpDependencies,
    const wchar_t* lpServiceStartName,
    const wchar_t* lpPassword
) noexcept {
    (void)lpdwTagId;
    (void)lpPassword;
    uintptr_t hManager = reinterpret_cast<uintptr_t>(hSCManager);
    uintptr_t hService = 0;
    std::wstring name = lpServiceName ? lpServiceName : L"";
    std::wstring disp = lpDisplayName ? lpDisplayName : L"";
    std::wstring bin = lpBinaryPathName ? lpBinaryPathName : L"";
    std::wstring grp = lpLoadOrderGroup ? lpLoadOrderGroup : L"";
    std::wstring startName = lpServiceStartName ? lpServiceStartName : L"LocalSystem";
    std::vector<std::wstring> deps;
    if (lpDependencies) {
        const wchar_t* p = lpDependencies;
        while (*p) {
            deps.emplace_back(p);
            p += wcslen(p) + 1;
        }
    }
    uint32_t err = scm::ServiceControlManager::get().createService(
        hManager, name, disp, dwDesiredAccess, dwServiceType, dwStartType,
        dwErrorControl, bin, grp, deps, startName, hService
    );
    if (err != scm::ERROR_SUCCESS) {
        win32::SetLastError(err);
        return nullptr;
    }
    return reinterpret_cast<SC_HANDLE>(hService);
}

inline SC_HANDLE OpenServiceW(
    SC_HANDLE hSCManager,
    const wchar_t* lpServiceName,
    uint32_t dwDesiredAccess
) noexcept {
    uintptr_t hManager = reinterpret_cast<uintptr_t>(hSCManager);
    uintptr_t hService = 0;
    std::wstring name = lpServiceName ? lpServiceName : L"";
    uint32_t err = scm::ServiceControlManager::get().openService(hManager, name, dwDesiredAccess, hService);
    if (err != scm::ERROR_SUCCESS) {
        win32::SetLastError(err);
        return nullptr;
    }
    return reinterpret_cast<SC_HANDLE>(hService);
}

inline win32::BOOL StartServiceW(
    SC_HANDLE hService,
    uint32_t dwNumServiceArgs,
    const wchar_t** lpServiceArgVectors
) noexcept {
    uintptr_t h = reinterpret_cast<uintptr_t>(hService);
    std::vector<std::wstring> args;
    if (lpServiceArgVectors && dwNumServiceArgs > 0) {
        for (uint32_t i = 0; i < dwNumServiceArgs; ++i) {
            if (lpServiceArgVectors[i]) args.emplace_back(lpServiceArgVectors[i]);
        }
    }
    uint32_t err = scm::ServiceControlManager::get().startService(h, args);
    if (err != scm::ERROR_SUCCESS) {
        win32::SetLastError(err);
        return win32::FALSE;
    }
    return win32::TRUE;
}

inline win32::BOOL ControlService(
    SC_HANDLE hService,
    uint32_t dwControl,
    scm::SERVICE_STATUS* lpServiceStatus
) noexcept {
    if (!lpServiceStatus) {
        win32::SetLastError(scm::ERROR_INVALID_PARAMETER);
        return win32::FALSE;
    }
    uintptr_t h = reinterpret_cast<uintptr_t>(hService);
    scm::SERVICE_STATUS st{};
    uint32_t err = scm::ServiceControlManager::get().controlService(h, dwControl, st);
    if (err != scm::ERROR_SUCCESS) {
        win32::SetLastError(err);
        return win32::FALSE;
    }
    *lpServiceStatus = st;
    return win32::TRUE;
}

inline win32::BOOL DeleteService(SC_HANDLE hService) noexcept {
    uintptr_t h = reinterpret_cast<uintptr_t>(hService);
    uint32_t err = scm::ServiceControlManager::get().deleteService(h);
    if (err != scm::ERROR_SUCCESS) {
        win32::SetLastError(err);
        return win32::FALSE;
    }
    return win32::TRUE;
}

inline win32::BOOL QueryServiceStatus(
    SC_HANDLE hService,
    scm::SERVICE_STATUS* lpServiceStatus
) noexcept {
    if (!lpServiceStatus) {
        win32::SetLastError(scm::ERROR_INVALID_PARAMETER);
        return win32::FALSE;
    }
    uintptr_t h = reinterpret_cast<uintptr_t>(hService);
    scm::SERVICE_STATUS_PROCESS ssp{};
    uint32_t err = scm::ServiceControlManager::get().queryServiceStatus(h, ssp);
    if (err != scm::ERROR_SUCCESS) {
        win32::SetLastError(err);
        return win32::FALSE;
    }
    lpServiceStatus->dwServiceType = ssp.dwServiceType;
    lpServiceStatus->dwCurrentState = ssp.dwCurrentState;
    lpServiceStatus->dwControlsAccepted = ssp.dwControlsAccepted;
    lpServiceStatus->dwWin32ExitCode = ssp.dwWin32ExitCode;
    lpServiceStatus->dwServiceSpecificExitCode = ssp.dwServiceSpecificExitCode;
    lpServiceStatus->dwCheckPoint = ssp.dwCheckPoint;
    lpServiceStatus->dwWaitHint = ssp.dwWaitHint;
    return win32::TRUE;
}

inline win32::BOOL QueryServiceStatusEx(
    SC_HANDLE hService,
    uint32_t InfoLevel,
    uint8_t* lpBuffer,
    uint32_t cbBufSize,
    uint32_t* pcbBytesNeeded
) noexcept {
    if (InfoLevel != 0 || !lpBuffer || cbBufSize < sizeof(scm::SERVICE_STATUS_PROCESS)) {
        if (pcbBytesNeeded) *pcbBytesNeeded = sizeof(scm::SERVICE_STATUS_PROCESS);
        win32::SetLastError(scm::ERROR_INSUFFICIENT_BUFFER);
        return win32::FALSE;
    }
    uintptr_t h = reinterpret_cast<uintptr_t>(hService);
    scm::SERVICE_STATUS_PROCESS ssp{};
    uint32_t err = scm::ServiceControlManager::get().queryServiceStatus(h, ssp);
    if (err != scm::ERROR_SUCCESS) {
        win32::SetLastError(err);
        return win32::FALSE;
    }
    std::memcpy(lpBuffer, &ssp, sizeof(scm::SERVICE_STATUS_PROCESS));
    if (pcbBytesNeeded) *pcbBytesNeeded = sizeof(scm::SERVICE_STATUS_PROCESS);
    return win32::TRUE;
}

inline win32::BOOL CloseServiceHandle(SC_HANDLE hSCObject) noexcept {
    uintptr_t h = reinterpret_cast<uintptr_t>(hSCObject);
    uint32_t err = scm::ServiceControlManager::get().closeServiceHandle(h);
    if (err != scm::ERROR_SUCCESS) {
        win32::SetLastError(err);
        return win32::FALSE;
    }
    return win32::TRUE;
}

inline void InitializeAdvapi32SubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();
    ldr.registerExport("advapi32.dll", "CryptAcquireContextA", reinterpret_cast<void*>(CryptAcquireContextA));
    ldr.registerExport("advapi32.dll", "CryptAcquireContextW", reinterpret_cast<void*>(CryptAcquireContextW));
    ldr.registerExport("advapi32.dll", "CryptReleaseContext", reinterpret_cast<void*>(CryptReleaseContext));
    ldr.registerExport("advapi32.dll", "CryptGenRandom", reinterpret_cast<void*>(CryptGenRandom));
    ldr.registerExport("advapi32.dll", "CryptCreateHash", reinterpret_cast<void*>(CryptCreateHash));
    ldr.registerExport("advapi32.dll", "CryptHashData", reinterpret_cast<void*>(CryptHashData));
    ldr.registerExport("advapi32.dll", "CryptGetHashParam", reinterpret_cast<void*>(CryptGetHashParam));
    ldr.registerExport("advapi32.dll", "CryptDestroyHash", reinterpret_cast<void*>(CryptDestroyHash));
    ldr.registerExport("advapi32.dll", "CryptDeriveKey", reinterpret_cast<void*>(CryptDeriveKey));
    ldr.registerExport("advapi32.dll", "CryptDestroyKey", reinterpret_cast<void*>(CryptDestroyKey));
    ldr.registerExport("advapi32.dll", "CryptEncrypt", reinterpret_cast<void*>(CryptEncrypt));
    ldr.registerExport("advapi32.dll", "CryptDecrypt", reinterpret_cast<void*>(CryptDecrypt));
    ldr.registerExport("advapi32.dll", "OpenProcessToken", reinterpret_cast<void*>(OpenProcessToken));
    ldr.registerExport("advapi32.dll", "GetTokenInformation", reinterpret_cast<void*>(GetTokenInformation));

    // SCM Exports
    ldr.registerExport("advapi32.dll", "OpenSCManagerW", reinterpret_cast<void*>(OpenSCManagerW));
    ldr.registerExport("advapi32.dll", "CreateServiceW", reinterpret_cast<void*>(CreateServiceW));
    ldr.registerExport("advapi32.dll", "OpenServiceW", reinterpret_cast<void*>(OpenServiceW));
    ldr.registerExport("advapi32.dll", "StartServiceW", reinterpret_cast<void*>(StartServiceW));
    ldr.registerExport("advapi32.dll", "ControlService", reinterpret_cast<void*>(ControlService));
    ldr.registerExport("advapi32.dll", "DeleteService", reinterpret_cast<void*>(DeleteService));
    ldr.registerExport("advapi32.dll", "QueryServiceStatus", reinterpret_cast<void*>(QueryServiceStatus));
    ldr.registerExport("advapi32.dll", "QueryServiceStatusEx", reinterpret_cast<void*>(QueryServiceStatusEx));
    ldr.registerExport("advapi32.dll", "CloseServiceHandle", reinterpret_cast<void*>(CloseServiceHandle));

    // Security & Logon Exports
    ldr.registerExport("advapi32.dll", "LogonUserW", reinterpret_cast<void*>(LogonUserW));
    ldr.registerExport("advapi32.dll", "LookupAccountSidW", reinterpret_cast<void*>(LookupAccountSidW));
    ldr.registerExport("advapi32.dll", "LookupAccountNameW", reinterpret_cast<void*>(LookupAccountNameW));
    ldr.registerExport("advapi32.dll", "LookupPrivilegeValueW", reinterpret_cast<void*>(LookupPrivilegeValueW));
    ldr.registerExport("advapi32.dll", "LookupPrivilegeNameW", reinterpret_cast<void*>(LookupPrivilegeNameW));
    ldr.registerExport("advapi32.dll", "LsaOpenPolicy", reinterpret_cast<void*>(LsaOpenPolicy));
    ldr.registerExport("advapi32.dll", "LsaClose", reinterpret_cast<void*>(LsaClose));

    // Initialize SCM daemon
    scm::ServiceControlManager::get().initialize();
}

} // namespace micant::advapi32
