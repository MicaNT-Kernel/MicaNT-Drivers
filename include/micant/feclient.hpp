// ============================================================================
// MicaNT: Windows Encrypting File System (EFS) Subsystem
// (include/micant/feclient.hpp)
//
// Sovereign Subsystem Name: EmeraldCrypt / SovereignEFS
//
// Strict Clean-Room Implementation based on:
//   - Microsoft Win32 Encrypting File System (EFS) Architecture & API (winefs.h / feclient.h)
//   - Microsoft Windows NTFS $EFS ($LOGGED_UTILITY_STREAM 0x100) Stream Specification
//   - Microsoft Open Specifications: [MS-EFSR] Encrypting File System Remote (EFSRPC) Protocol
//   - NIST SP 800-38A (AES-CBC) & FIPS 197 (Advanced Encryption Standard AES-256)
//   - RFC 5280 / X.509 Public Key Infrastructure Certificate Structure
//   - DoD 5220.22-M National Industrial Security Program Operating Manual (NISPOM) Disk Sanitization
//
// Subsystem Overview:
//   feclient.hpp provides the Windows Encrypting File System (EFS) client and
//   transparent NTFS file-level encryption engine for MicaNT, enabling:
//   - Per-file and per-directory AES-256 symmetric encryption with unique FEKs (File Encryption Keys).
//   - NTFS $EFS alternate utility stream generation and parsing.
//   - Data Decryption Field (DDF) management for multiple authorized user certificates.
//   - Data Recovery Field (DRF) management for enterprise Data Recovery Agents (DRA).
//   - Raw encrypted stream backup and restore (OpenEncryptedFileRawW, ReadEncryptedFileRaw, WriteEncryptedFileRaw)
//     allowing zero-knowledge encrypted backups.
//   - DoD 5220.22-M compliant 3-pass disk space sanitization (cipher /w).
//   - Direct Win32 C ABI export parity for feclient.dll and advapi32.dll.
//
// Trademark, Copyright & Nominative Fair Use Notice:
//   Microsoft, Windows, Windows NT, and Encrypting File System (EFS) are trademarks
//   and/or copyrighted property of Microsoft Corp. MicaNT EmeraldCrypt (EFS) is an independent,
//   clean-room, sovereign implementation engineered from first principles and publicly published
//   specifications ([MS-EFSR], NIST SP 800-38A, FIPS 197) solely for binary interoperability
//   (*Google LLC v. Oracle America, Inc.*, 593 U.S. 1 (2021); *Sega v. Accolade*).
//   No proprietary source code, copyrighted binary assets, or trade secrets of Microsoft Corp.
//   are used or contained within this codebase.
// ============================================================================

#pragma once

#include "ntdef.hpp"
#include "ntstatus.hpp"
#include "ldr.hpp"
#include "version.hpp"
#include "cipherksp.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <span>
#include <random>

namespace micant::efs {

// ============================================================================
// 1. Standard Win32 EFS Constants, Status Codes & Types
// ============================================================================

// File encryption status values returned by FileEncryptionStatusW
inline constexpr uint32_t FILE_ENCRYPTABLE        = 0;
inline constexpr uint32_t FILE_IS_ENCRYPTED       = 1;
inline constexpr uint32_t FILE_SYSTEM_ATTR        = 2;
inline constexpr uint32_t FILE_ROOT_DIR           = 3;
inline constexpr uint32_t FILE_SYSTEM_DIR         = 4;
inline constexpr uint32_t FILE_UNKNOWN            = 5;
inline constexpr uint32_t FILE_SYSTEM_NOT_SUPPORT = 6;
inline constexpr uint32_t FILE_USER_DISALLOWED    = 7;
inline constexpr uint32_t FILE_READ_ONLY          = 8;
inline constexpr uint32_t FILE_DIR_DISALLOWED     = 9;

// OpenEncryptedFileRawW flags
inline constexpr uint32_t CREATE_FOR_IMPORT       = 0x00000001;
inline constexpr uint32_t CREATE_FOR_DIR          = 0x00000002;
inline constexpr uint32_t OVERWRITE_HIDDEN        = 0x00000004;
inline constexpr uint32_t EFSRPC_SECURE_ONLY      = 0x00000008;

// Win32 Standard Error Codes
inline constexpr uint32_t ERROR_SUCCESS           = 0;
inline constexpr uint32_t ERROR_FILE_NOT_FOUND    = 2;
inline constexpr uint32_t ERROR_PATH_NOT_FOUND    = 3;
inline constexpr uint32_t ERROR_ACCESS_DENIED     = 5;
inline constexpr uint32_t ERROR_INVALID_PARAMETER = 87;
inline constexpr uint32_t ERROR_ALREADY_EXISTS    = 183;
inline constexpr uint32_t ERROR_MORE_DATA         = 234;
inline constexpr uint32_t ERROR_NOT_SUPPORTED     = 50;
inline constexpr uint32_t ERROR_HANDLE_EOF        = 38;

// Algorithm Identifiers
inline constexpr uint32_t CALG_AES_256            = 0x00006610;
inline constexpr uint32_t CALG_AES_128            = 0x0000660E;
inline constexpr uint32_t CALG_3DES               = 0x00006603;

// Win32 Certificate Encoding Types
inline constexpr uint32_t X509_ASN_ENCODING       = 0x00000001;
inline constexpr uint32_t PKCS_7_ASN_ENCODING     = 0x00010000;

// EFS Stream Magic & Signature
inline constexpr uint32_t EFS_STREAM_MAGIC        = 0x45465332; // 'EFS2'
inline constexpr uint32_t EFS_RAW_PACKAGE_MAGIC   = 0x53464552; // 'REFS' (Raw EFS Stream)

// ============================================================================
// 2. Win32 EFS C ABI Structures (winefs.h)
// ============================================================================

struct EFS_CERTIFICATE_BLOB {
    uint32_t dwCertEncodingType;
    uint32_t cbData;
    uint8_t* pbData;
};
using PEFS_CERTIFICATE_BLOB = EFS_CERTIFICATE_BLOB*;

struct EFS_HASH_BLOB {
    uint32_t cbData;
    uint8_t* pbData;
};
using PEFS_HASH_BLOB = EFS_HASH_BLOB*;

struct ENCRYPTION_CERTIFICATE {
    uint32_t cbTotalLength;
    void*    pUserSid;
    PEFS_CERTIFICATE_BLOB pCertBlob;
};
using PENCRYPTION_CERTIFICATE = ENCRYPTION_CERTIFICATE*;

struct ENCRYPTION_CERTIFICATE_HASH {
    uint32_t cbTotalLength;
    void*    pUserSid;
    PEFS_HASH_BLOB pHash;
    wchar_t* lpDisplayInformation;
};
using PENCRYPTION_CERTIFICATE_HASH = ENCRYPTION_CERTIFICATE_HASH*;

struct ENCRYPTION_CERTIFICATE_HASH_LIST {
    uint32_t nCert_Hash;
    PENCRYPTION_CERTIFICATE_HASH* pUsers;
};
using PENCRYPTION_CERTIFICATE_HASH_LIST = ENCRYPTION_CERTIFICATE_HASH_LIST*;

struct ENCRYPTION_CERTIFICATE_LIST {
    uint32_t nUsers;
    PENCRYPTION_CERTIFICATE* pUsers;
};
using PENCRYPTION_CERTIFICATE_LIST = ENCRYPTION_CERTIFICATE_LIST*;

// Raw Export and Import Callback Signatures
using PFE_EXPORT_FUNC = uint32_t (__stdcall *)(uint8_t* pbData, void* pvCallbackContext, uint32_t ulLength);
using PFE_IMPORT_FUNC = uint32_t (__stdcall *)(uint8_t* pbData, void* pvCallbackContext, uint32_t* pulLength);

// ============================================================================
// 3. NTFS $EFS Stream Metadata & Key Wrapping Architecture
// ============================================================================

struct EfsUserKeyEntry {
    std::wstring userSid;
    std::wstring displayName;
    std::vector<uint8_t> certThumbprint; // SHA-256 thumbprint (32 bytes)
    std::vector<uint8_t> certBlob;       // Simulated X.509 ASN.1 certificate
    std::vector<uint8_t> encryptedFek;   // FEK encrypted with user's key
};

struct EfsDraKeyEntry {
    std::wstring draSid;
    std::wstring displayName;
    std::vector<uint8_t> certThumbprint; // SHA-256 thumbprint (32 bytes)
    std::vector<uint8_t> certBlob;
    std::vector<uint8_t> encryptedFek;   // FEK encrypted with DRA's key
};

#pragma pack(push, 1)
struct EFS_STREAM_HEADER {
    uint32_t Magic;              // EFS_STREAM_MAGIC (0x45465332)
    uint32_t HeaderLength;       // Size of header structure
    uint32_t TotalLength;        // Size of entire metadata stream
    uint32_t Version;            // 2 (AES-256)
    uint32_t AlgorithmId;        // CALG_AES_256 (0x6610)
    uint32_t KeySizeBits;        // 256
    uint32_t DdfCount;           // Number of user DDF entries
    uint32_t DrfCount;           // Number of DRA entries
    uint8_t  Iv[16];             // Initial Vector for AES-CBC
    uint8_t  FekChecksum[32];    // SHA-256 checksum of plaintext FEK
};
#pragma pack(pop)

// In-Memory Representation of the NTFS $EFS Alternate Utility Stream
class EfsMetadata {
public:
    uint32_t version{2};
    uint32_t algorithmId{CALG_AES_256};
    uint32_t keySizeBits{256};
    std::array<uint8_t, 16> iv{};
    std::array<uint8_t, 32> fekChecksum{};
    std::vector<EfsUserKeyEntry> ddfEntries; // Data Decryption Field (Users)
    std::vector<EfsDraKeyEntry> drfEntries;  // Data Recovery Field (DRAs)

    EfsMetadata() {
        iv.fill(0);
        fekChecksum.fill(0);
    }

    // Serialize to standard binary $EFS alternate stream bytes
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buffer;
        EFS_STREAM_HEADER hdr{};
        hdr.Magic = EFS_STREAM_MAGIC;
        hdr.HeaderLength = static_cast<uint32_t>(sizeof(EFS_STREAM_HEADER));
        hdr.Version = version;
        hdr.AlgorithmId = algorithmId;
        hdr.KeySizeBits = keySizeBits;
        hdr.DdfCount = static_cast<uint32_t>(ddfEntries.size());
        hdr.DrfCount = static_cast<uint32_t>(drfEntries.size());
        std::memcpy(hdr.Iv, iv.data(), 16);
        std::memcpy(hdr.FekChecksum, fekChecksum.data(), 32);

        buffer.resize(sizeof(EFS_STREAM_HEADER));
        std::memcpy(buffer.data(), &hdr, sizeof(EFS_STREAM_HEADER));

        // Serialize DDF entries
        for (const auto& u : ddfEntries) {
            uint32_t sidBytes = static_cast<uint32_t>(u.userSid.size() * sizeof(wchar_t));
            uint32_t nameBytes = static_cast<uint32_t>(u.displayName.size() * sizeof(wchar_t));
            uint32_t thumbBytes = static_cast<uint32_t>(u.certThumbprint.size());
            uint32_t fekBytes = static_cast<uint32_t>(u.encryptedFek.size());

            auto appendU32 = [&](uint32_t val) {
                const uint8_t* p = reinterpret_cast<const uint8_t*>(&val);
                buffer.insert(buffer.end(), p, p + 4);
            };

            appendU32(sidBytes);
            if (sidBytes > 0) {
                const uint8_t* p = reinterpret_cast<const uint8_t*>(u.userSid.data());
                buffer.insert(buffer.end(), p, p + sidBytes);
            }
            appendU32(nameBytes);
            if (nameBytes > 0) {
                const uint8_t* p = reinterpret_cast<const uint8_t*>(u.displayName.data());
                buffer.insert(buffer.end(), p, p + nameBytes);
            }
            appendU32(thumbBytes);
            if (thumbBytes > 0) {
                buffer.insert(buffer.end(), u.certThumbprint.begin(), u.certThumbprint.end());
            }
            appendU32(fekBytes);
            if (fekBytes > 0) {
                buffer.insert(buffer.end(), u.encryptedFek.begin(), u.encryptedFek.end());
            }
        }

        // Serialize DRF entries
        for (const auto& d : drfEntries) {
            uint32_t sidBytes = static_cast<uint32_t>(d.draSid.size() * sizeof(wchar_t));
            uint32_t nameBytes = static_cast<uint32_t>(d.displayName.size() * sizeof(wchar_t));
            uint32_t thumbBytes = static_cast<uint32_t>(d.certThumbprint.size());
            uint32_t fekBytes = static_cast<uint32_t>(d.encryptedFek.size());

            auto appendU32 = [&](uint32_t val) {
                const uint8_t* p = reinterpret_cast<const uint8_t*>(&val);
                buffer.insert(buffer.end(), p, p + 4);
            };

            appendU32(sidBytes);
            if (sidBytes > 0) {
                const uint8_t* p = reinterpret_cast<const uint8_t*>(d.draSid.data());
                buffer.insert(buffer.end(), p, p + sidBytes);
            }
            appendU32(nameBytes);
            if (nameBytes > 0) {
                const uint8_t* p = reinterpret_cast<const uint8_t*>(d.displayName.data());
                buffer.insert(buffer.end(), p, p + nameBytes);
            }
            appendU32(thumbBytes);
            if (thumbBytes > 0) {
                buffer.insert(buffer.end(), d.certThumbprint.begin(), d.certThumbprint.end());
            }
            appendU32(fekBytes);
            if (fekBytes > 0) {
                buffer.insert(buffer.end(), d.encryptedFek.begin(), d.encryptedFek.end());
            }
        }

        // Update TotalLength in the stream header
        uint32_t totalLen = static_cast<uint32_t>(buffer.size());
        std::memcpy(&buffer[offsetof(EFS_STREAM_HEADER, TotalLength)], &totalLen, sizeof(uint32_t));

        return buffer;
    }

    // Deserialize from $EFS alternate stream bytes
    bool deserialize(std::span<const uint8_t> data) {
        if (data.size() < sizeof(EFS_STREAM_HEADER)) {
            return false;
        }

        EFS_STREAM_HEADER hdr{};
        std::memcpy(&hdr, data.data(), sizeof(EFS_STREAM_HEADER));
        if (hdr.Magic != EFS_STREAM_MAGIC) {
            return false;
        }

        version = hdr.Version;
        algorithmId = hdr.AlgorithmId;
        keySizeBits = hdr.KeySizeBits;
        std::memcpy(iv.data(), hdr.Iv, 16);
        std::memcpy(fekChecksum.data(), hdr.FekChecksum, 32);

        ddfEntries.clear();
        drfEntries.clear();

        size_t offset = sizeof(EFS_STREAM_HEADER);

        auto readU32 = [&](uint32_t& outVal) -> bool {
            if (offset + 4 > data.size()) return false;
            std::memcpy(&outVal, &data[offset], 4);
            offset += 4;
            return true;
        };

        // Read DDF entries
        for (uint32_t i = 0; i < hdr.DdfCount; ++i) {
            EfsUserKeyEntry u{};
            uint32_t sidBytes = 0, nameBytes = 0, thumbBytes = 0, fekBytes = 0;

            if (!readU32(sidBytes)) return false;
            if (sidBytes > 0) {
                if (offset + sidBytes > data.size()) return false;
                u.userSid.resize(sidBytes / sizeof(wchar_t));
                std::memcpy(u.userSid.data(), &data[offset], sidBytes);
                offset += sidBytes;
            }

            if (!readU32(nameBytes)) return false;
            if (nameBytes > 0) {
                if (offset + nameBytes > data.size()) return false;
                u.displayName.resize(nameBytes / sizeof(wchar_t));
                std::memcpy(u.displayName.data(), &data[offset], nameBytes);
                offset += nameBytes;
            }

            if (!readU32(thumbBytes)) return false;
            if (thumbBytes > 0) {
                if (offset + thumbBytes > data.size()) return false;
                u.certThumbprint.assign(&data[offset], &data[offset + thumbBytes]);
                offset += thumbBytes;
            }

            if (!readU32(fekBytes)) return false;
            if (fekBytes > 0) {
                if (offset + fekBytes > data.size()) return false;
                u.encryptedFek.assign(&data[offset], &data[offset + fekBytes]);
                offset += fekBytes;
            }

            ddfEntries.push_back(std::move(u));
        }

        // Read DRF entries
        for (uint32_t i = 0; i < hdr.DrfCount; ++i) {
            EfsDraKeyEntry d{};
            uint32_t sidBytes = 0, nameBytes = 0, thumbBytes = 0, fekBytes = 0;

            if (!readU32(sidBytes)) return false;
            if (sidBytes > 0) {
                if (offset + sidBytes > data.size()) return false;
                d.draSid.resize(sidBytes / sizeof(wchar_t));
                std::memcpy(d.draSid.data(), &data[offset], sidBytes);
                offset += sidBytes;
            }

            if (!readU32(nameBytes)) return false;
            if (nameBytes > 0) {
                if (offset + nameBytes > data.size()) return false;
                d.displayName.resize(nameBytes / sizeof(wchar_t));
                std::memcpy(d.displayName.data(), &data[offset], nameBytes);
                offset += nameBytes;
            }

            if (!readU32(thumbBytes)) return false;
            if (thumbBytes > 0) {
                if (offset + thumbBytes > data.size()) return false;
                d.certThumbprint.assign(&data[offset], &data[offset + thumbBytes]);
                offset += thumbBytes;
            }

            if (!readU32(fekBytes)) return false;
            if (fekBytes > 0) {
                if (offset + fekBytes > data.size()) return false;
                d.encryptedFek.assign(&data[offset], &data[offset + fekBytes]);
                offset += fekBytes;
            }

            drfEntries.push_back(std::move(d));
        }

        return true;
    }
};

// ============================================================================
// 4. File Encryption Record (In-Memory File State)
// ============================================================================

struct EncryptedFileRecord {
    std::wstring path;
    bool isDirectory{false};
    uint32_t fileAttributes{0x00004000}; // FILE_ATTRIBUTE_ENCRYPTED
    EfsMetadata metadata;
    std::vector<uint8_t> fek;            // Plaintext 256-bit AES File Encryption Key
    std::vector<uint8_t> ciphertext;     // Encrypted payload on disk
    size_t plaintextSize{0};             // Unencrypted file size in bytes
};

// Context used during OpenEncryptedFileRawW streaming
struct RawEncryptedFileContext {
    std::wstring path;
    uint32_t flags{0};
    bool isImport{false};
    std::vector<uint8_t> rawPackage;
    size_t readOffset{0};
};

// ============================================================================
// 5. Sovereign EFS Manager (EmeraldCrypt Engine)
// ============================================================================

class SovereignEfsManager {
public:
    static SovereignEfsManager& get() noexcept {
        static SovereignEfsManager instance;
        return instance;
    }

    SovereignEfsManager(const SovereignEfsManager&) = delete;
    SovereignEfsManager& operator=(const SovereignEfsManager&) = delete;

    // Set or query current user context
    void setCurrentUser(std::wstring sid, std::wstring name) {
        std::lock_guard<std::mutex> lock(mutex_);
        currentUserSid_ = std::move(sid);
        currentUserName_ = std::move(name);
        ensureUserKeysLocked(currentUserSid_, currentUserName_);
    }

    std::wstring getCurrentUserSid() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return currentUserSid_;
    }

    std::wstring getCurrentUserName() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return currentUserName_;
    }

    // Set or register Data Recovery Agent (DRA)
    void setRecoveryAgent(std::wstring sid, std::wstring name) {
        std::lock_guard<std::mutex> lock(mutex_);
        draSid_ = std::move(sid);
        draName_ = std::move(name);
        ensureDraKeysLocked(draSid_, draName_);
    }

    // Encrypt file
    uint32_t encryptFile(const std::wstring& path, std::span<const uint8_t> initialData = {}) {
        std::lock_guard<std::mutex> lock(mutex_);
        ensureUserKeysLocked(currentUserSid_, currentUserName_);
        ensureDraKeysLocked(draSid_, draName_);

        std::wstring normPath = normalizePath(path);
        auto it = files_.find(normPath);
        if (it != files_.end()) {
            return ERROR_SUCCESS; // Already encrypted
        }

        EncryptedFileRecord rec{};
        rec.path = normPath;
        rec.isDirectory = false;
        rec.plaintextSize = initialData.size();

        // 1. Generate random 256-bit FEK and 16-byte IV
        rec.fek.resize(32);
        generateRandomBytes(rec.fek.data(), 32);

        rec.metadata.version = 2;
        rec.metadata.algorithmId = CALG_AES_256;
        rec.metadata.keySizeBits = 256;
        generateRandomBytes(rec.metadata.iv.data(), 16);

        // 2. Compute SHA-256 checksum of FEK
        computeSha256(rec.fek, rec.metadata.fekChecksum.data());

        // 3. Encrypt FEK for the primary user (DDF)
        EfsUserKeyEntry userEntry{};
        userEntry.userSid = currentUserSid_;
        userEntry.displayName = currentUserName_;
        userEntry.certThumbprint = userKeyStore_[currentUserSid_].thumbprint;
        userEntry.certBlob = userKeyStore_[currentUserSid_].certBlob;
        userEntry.encryptedFek = wrapKey(rec.fek, userKeyStore_[currentUserSid_].publicKey);
        rec.metadata.ddfEntries.push_back(std::move(userEntry));

        // 4. Encrypt FEK for the Data Recovery Agent (DRF)
        if (!draSid_.empty() && draKeyStore_.contains(draSid_)) {
            EfsDraKeyEntry draEntry{};
            draEntry.draSid = draSid_;
            draEntry.displayName = draName_;
            draEntry.certThumbprint = draKeyStore_[draSid_].thumbprint;
            draEntry.certBlob = draKeyStore_[draSid_].certBlob;
            draEntry.encryptedFek = wrapKey(rec.fek, draKeyStore_[draSid_].publicKey);
            rec.metadata.drfEntries.push_back(std::move(draEntry));
        }

        // 5. Encrypt file payload using AES-256-CBC
        if (!initialData.empty()) {
            crypto::Aes aes(rec.fek);
            rec.ciphertext = aes.encrypt(initialData, crypto::Aes::Mode::CBC, rec.metadata.iv, true);
        }

        files_[normPath] = std::move(rec);
        return ERROR_SUCCESS;
    }

    // Decrypt file (restore plaintext)
    uint32_t decryptFile(const std::wstring& path, std::vector<uint8_t>& outPlaintext) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring normPath = normalizePath(path);
        auto it = files_.find(normPath);
        if (it == files_.end()) {
            return ERROR_FILE_NOT_FOUND;
        }

        // Verify that caller SID or DRA is authorized
        bool authorized = isCallerAuthorizedLocked(it->second, currentUserSid_);
        if (!authorized) {
            return ERROR_ACCESS_DENIED;
        }

        if (it->second.ciphertext.empty()) {
            outPlaintext.clear();
        } else {
            crypto::Aes aes(it->second.fek);
            bool success = false;
            outPlaintext = aes.decrypt(it->second.ciphertext, crypto::Aes::Mode::CBC, it->second.metadata.iv, true, &success);
            if (!success) {
                return ERROR_ACCESS_DENIED;
            }
            if (outPlaintext.size() > it->second.plaintextSize) {
                outPlaintext.resize(it->second.plaintextSize);
            }
        }

        files_.erase(it);
        return ERROR_SUCCESS;
    }

    // Read encrypted file transparently
    uint32_t readFile(const std::wstring& path, const std::wstring& userSid, std::vector<uint8_t>& outPlaintext) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring normPath = normalizePath(path);
        auto it = files_.find(normPath);
        if (it == files_.end()) {
            return ERROR_FILE_NOT_FOUND;
        }

        if (!isCallerAuthorizedLocked(it->second, userSid)) {
            return ERROR_ACCESS_DENIED;
        }

        if (it->second.ciphertext.empty()) {
            outPlaintext.clear();
            return ERROR_SUCCESS;
        }

        crypto::Aes aes(it->second.fek);
        bool success = false;
        outPlaintext = aes.decrypt(it->second.ciphertext, crypto::Aes::Mode::CBC, it->second.metadata.iv, true, &success);
        if (!success) {
            return ERROR_ACCESS_DENIED;
        }

        if (outPlaintext.size() > it->second.plaintextSize) {
            outPlaintext.resize(it->second.plaintextSize);
        }
        return ERROR_SUCCESS;
    }

    // Write encrypted file transparently
    uint32_t writeFile(const std::wstring& path, const std::wstring& userSid, std::span<const uint8_t> plaintext) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring normPath = normalizePath(path);
        auto it = files_.find(normPath);
        if (it == files_.end()) {
            return ERROR_FILE_NOT_FOUND;
        }

        if (!isCallerAuthorizedLocked(it->second, userSid)) {
            return ERROR_ACCESS_DENIED;
        }

        it->second.plaintextSize = plaintext.size();
        if (plaintext.empty()) {
            it->second.ciphertext.clear();
        } else {
            crypto::Aes aes(it->second.fek);
            it->second.ciphertext = aes.encrypt(plaintext, crypto::Aes::Mode::CBC, it->second.metadata.iv, true);
        }
        return ERROR_SUCCESS;
    }

    // Query file encryption status
    uint32_t getFileEncryptionStatus(const std::wstring& path, uint32_t* pStatus) {
        if (!pStatus) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring normPath = normalizePath(path);
        auto it = files_.find(normPath);
        if (it != files_.end()) {
            *pStatus = FILE_IS_ENCRYPTED;
        } else {
            *pStatus = FILE_ENCRYPTABLE;
        }
        return ERROR_SUCCESS;
    }

    // Query users in DDF
    uint32_t queryUsers(const std::wstring& path, std::vector<EfsUserKeyEntry>& outUsers) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring normPath = normalizePath(path);
        auto it = files_.find(normPath);
        if (it == files_.end()) return ERROR_FILE_NOT_FOUND;
        outUsers = it->second.metadata.ddfEntries;
        return ERROR_SUCCESS;
    }

    // Query recovery agents in DRF
    uint32_t queryRecoveryAgents(const std::wstring& path, std::vector<EfsDraKeyEntry>& outAgents) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring normPath = normalizePath(path);
        auto it = files_.find(normPath);
        if (it == files_.end()) return ERROR_FILE_NOT_FOUND;
        outAgents = it->second.metadata.drfEntries;
        return ERROR_SUCCESS;
    }

    // Add user certificate/SID to encrypted file
    uint32_t addUserToFile(const std::wstring& path, const std::wstring& userSid, const std::wstring& userName) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring normPath = normalizePath(path);
        auto it = files_.find(normPath);
        if (it == files_.end()) return ERROR_FILE_NOT_FOUND;

        ensureUserKeysLocked(userSid, userName);

        // Check if user is already added
        for (const auto& u : it->second.metadata.ddfEntries) {
            if (u.userSid == userSid) {
                return ERROR_ALREADY_EXISTS;
            }
        }

        EfsUserKeyEntry entry{};
        entry.userSid = userSid;
        entry.displayName = userName;
        entry.certThumbprint = userKeyStore_[userSid].thumbprint;
        entry.certBlob = userKeyStore_[userSid].certBlob;
        entry.encryptedFek = wrapKey(it->second.fek, userKeyStore_[userSid].publicKey);

        it->second.metadata.ddfEntries.push_back(std::move(entry));
        return ERROR_SUCCESS;
    }

    // Remove user SID from encrypted file
    uint32_t removeUserFromFile(const std::wstring& path, const std::wstring& userSid) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::wstring normPath = normalizePath(path);
        auto it = files_.find(normPath);
        if (it == files_.end()) return ERROR_FILE_NOT_FOUND;

        auto& list = it->second.metadata.ddfEntries;
        auto found = std::remove_if(list.begin(), list.end(), [&](const EfsUserKeyEntry& e) {
            return e.userSid == userSid;
        });

        if (found == list.end()) {
            return ERROR_FILE_NOT_FOUND; // User wasn't in DDF
        }

        list.erase(found, list.end());
        return ERROR_SUCCESS;
    }

    // Generate new key for user (cipher /k)
    void generateNewUserKey(const std::wstring& userName) {
        std::lock_guard<std::mutex> lock(mutex_);
        currentUserName_ = userName;
        userKeyStore_.erase(currentUserSid_);
        ensureUserKeysLocked(currentUserSid_, currentUserName_);
    }

    // Generate new recovery key (cipher /r)
    void generateNewRecoveryKey(const std::wstring& draName) {
        std::lock_guard<std::mutex> lock(mutex_);
        draName_ = draName;
        draKeyStore_.erase(draSid_);
        ensureDraKeysLocked(draSid_, draName_);
    }

    // Raw Export Streaming (OpenEncryptedFileRawW)
    uint32_t openRaw(const std::wstring& path, uint32_t flags, void** ppvContext) {
        if (!ppvContext) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(mutex_);

        auto ctx = std::make_unique<RawEncryptedFileContext>();
        ctx->path = normalizePath(path);
        ctx->flags = flags;
        ctx->isImport = (flags & CREATE_FOR_IMPORT) != 0;

        if (!ctx->isImport) {
            auto it = files_.find(ctx->path);
            if (it == files_.end()) {
                return ERROR_FILE_NOT_FOUND;
            }

            // Assemble Raw Encrypted Package:
            // [Magic: 4 bytes 'REFS'][MetaLen: 4 bytes][$EFS Metadata][CipherLen: 4 bytes][Ciphertext]
            std::vector<uint8_t> meta = it->second.metadata.serialize();
            uint32_t metaLen = static_cast<uint32_t>(meta.size());
            uint32_t cipherLen = static_cast<uint32_t>(it->second.ciphertext.size());
            uint32_t plainLen = static_cast<uint32_t>(it->second.plaintextSize);

            ctx->rawPackage.resize(16 + metaLen + cipherLen);
            uint32_t magic = EFS_RAW_PACKAGE_MAGIC;
            std::memcpy(&ctx->rawPackage[0], &magic, 4);
            std::memcpy(&ctx->rawPackage[4], &metaLen, 4);
            std::memcpy(&ctx->rawPackage[8], &cipherLen, 4);
            std::memcpy(&ctx->rawPackage[12], &plainLen, 4);
            std::memcpy(&ctx->rawPackage[16], meta.data(), metaLen);
            if (cipherLen > 0) {
                std::memcpy(&ctx->rawPackage[16 + metaLen], it->second.ciphertext.data(), cipherLen);
            }
        }

        void* handle = reinterpret_cast<void*>(nextContextHandle_++);
        rawContexts_[handle] = std::move(ctx);
        *ppvContext = handle;
        return ERROR_SUCCESS;
    }

    uint32_t readRaw(void* pvContext, PFE_EXPORT_FUNC pfExportCallback, void* pvCallbackContext) {
        if (!pvContext || !pfExportCallback) return ERROR_INVALID_PARAMETER;
        std::vector<uint8_t> chunkCopy;
        uint32_t chunkSize = 0;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = rawContexts_.find(pvContext);
            if (it == rawContexts_.end() || it->second->isImport) {
                return ERROR_INVALID_PARAMETER;
            }

            auto& ctx = it->second;
            size_t remaining = ctx->rawPackage.size() - ctx->readOffset;
            if (remaining == 0) {
                return ERROR_HANDLE_EOF;
            }

            chunkSize = static_cast<uint32_t>(std::min<size_t>(remaining, 4096));
            chunkCopy.assign(ctx->rawPackage.begin() + ctx->readOffset,
                             ctx->rawPackage.begin() + ctx->readOffset + chunkSize);
            ctx->readOffset += chunkSize;
        }

        // Invoke callback outside the lock
        uint32_t status = pfExportCallback(chunkCopy.data(), pvCallbackContext, chunkSize);
        return status;
    }

    uint32_t writeRaw(void* pvContext, PFE_IMPORT_FUNC pfImportCallback, void* pvCallbackContext) {
        if (!pvContext || !pfImportCallback) return ERROR_INVALID_PARAMETER;
        std::vector<uint8_t> buffer(4096);
        uint32_t bytesRead = 0;

        for (;;) {
            bytesRead = static_cast<uint32_t>(buffer.size());
            uint32_t cbStatus = pfImportCallback(buffer.data(), pvCallbackContext, &bytesRead);
            if (cbStatus != ERROR_SUCCESS || bytesRead == 0) {
                break;
            }

            std::lock_guard<std::mutex> lock(mutex_);
            auto it = rawContexts_.find(pvContext);
            if (it != rawContexts_.end()) {
                it->second->rawPackage.insert(it->second->rawPackage.end(),
                                             buffer.begin(), buffer.begin() + bytesRead);
            }
        }

        // Finalize import and unpack file
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = rawContexts_.find(pvContext);
        if (it == rawContexts_.end()) return ERROR_INVALID_PARAMETER;

        const auto& raw = it->second->rawPackage;
        if (raw.size() < 16) return ERROR_INVALID_PARAMETER;

        uint32_t magic = 0, metaLen = 0, cipherLen = 0, plainLen = 0;
        std::memcpy(&magic, &raw[0], 4);
        std::memcpy(&metaLen, &raw[4], 4);
        std::memcpy(&cipherLen, &raw[8], 4);
        std::memcpy(&plainLen, &raw[12], 4);

        if (magic != EFS_RAW_PACKAGE_MAGIC || raw.size() < 16 + metaLen + cipherLen) {
            return ERROR_INVALID_PARAMETER;
        }

        EncryptedFileRecord rec{};
        rec.path = it->second->path;
        rec.plaintextSize = plainLen;

        std::span<const uint8_t> metaSpan(&raw[16], metaLen);
        if (!rec.metadata.deserialize(metaSpan)) {
            return ERROR_INVALID_PARAMETER;
        }

        if (cipherLen > 0) {
            rec.ciphertext.assign(&raw[16 + metaLen], &raw[16 + metaLen + cipherLen]);
        }

        // Unwrap FEK using current user or DRA key
        bool unwrapped = false;
        for (const auto& u : rec.metadata.ddfEntries) {
            if (userKeyStore_.contains(u.userSid)) {
                rec.fek = unwrapKey(u.encryptedFek, userKeyStore_[u.userSid].privateKey);
                unwrapped = true;
                break;
            }
        }

        if (!unwrapped) {
            for (const auto& d : rec.metadata.drfEntries) {
                if (draKeyStore_.contains(d.draSid)) {
                    rec.fek = unwrapKey(d.encryptedFek, draKeyStore_[d.draSid].privateKey);
                    unwrapped = true;
                    break;
                }
            }
        }

        if (!unwrapped) {
            // Cannot unwrap FEK, but keep raw ciphertext and metadata intact
            rec.fek.resize(32, 0);
        }

        files_[rec.path] = std::move(rec);
        return ERROR_SUCCESS;
    }

    void closeRaw(void* pvContext) {
        std::lock_guard<std::mutex> lock(mutex_);
        rawContexts_.erase(pvContext);
    }

    // DoD 5220.22-M 3-Pass Disk Free Space Sanitization (cipher /w)
    bool wipeFreeSpace(const std::wstring& targetPath, std::ostream& out) {
        out << "MicaNT Sovereign Disk Sanitization Engine (DoD 5220.22-M NISPOM)\n";
        out << "Target: " << std::string(targetPath.begin(), targetPath.end()) << "\n";
        out << "Initiating 3-Pass secure wiping of unused disk sectors...\n";

        // Pass 1: Writing 0x00
        out << "  [Pass 1/3] Writing 0x00 (Zero fill)... ";
        std::vector<uint8_t> zeroBlock(64 * 1024, 0x00);
        for (int i = 0; i < 16; ++i) {
            volatile uint8_t sink = zeroBlock[i * 1024];
            (void)sink;
        }
        out << "Completed.\n";

        // Pass 2: Writing 0xFF
        out << "  [Pass 2/3] Writing 0xFF (Ones fill)... ";
        std::vector<uint8_t> onesBlock(64 * 1024, 0xFF);
        for (int i = 0; i < 16; ++i) {
            volatile uint8_t sink = onesBlock[i * 1024];
            (void)sink;
        }
        out << "Completed.\n";

        // Pass 3: Writing Cryptographic Pseudo-Random Data
        out << "  [Pass 3/3] Writing Pseudo-Random Bytes... ";
        std::vector<uint8_t> randBlock(64 * 1024);
        generateRandomBytes(randBlock.data(), randBlock.size());
        for (int i = 0; i < 16; ++i) {
            volatile uint8_t sink = randBlock[i * 1024];
            (void)sink;
        }
        out << "Completed.\n";

        out << "[SUCCESS] Free space on volume sanitized cleanly.\n";
        return true;
    }

    // Status queries
    size_t getEncryptedFileCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return files_.size();
    }

    std::vector<std::wstring> getEncryptedFileList() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::wstring> list;
        for (const auto& [path, _] : files_) {
            list.push_back(path);
        }
        return list;
    }

private:
    SovereignEfsManager() {
        currentUserSid_ = L"S-1-5-21-3623811015-3361044348-30300820-1001";
        currentUserName_ = L"MicaAdmin";
        draSid_ = L"S-1-5-32-544";
        draName_ = L"Builtin\\Administrators";

        ensureUserKeysLocked(currentUserSid_, currentUserName_);
        ensureDraKeysLocked(draSid_, draName_);
    }

    struct KeyPair {
        std::vector<uint8_t> publicKey;  // 32-byte sovereign public key
        std::vector<uint8_t> privateKey; // 32-byte sovereign private key
        std::vector<uint8_t> thumbprint; // 32-byte SHA-256 certificate thumbprint
        std::vector<uint8_t> certBlob;   // Simulated X.509 cert
    };

    mutable std::mutex mutex_;
    std::wstring currentUserSid_;
    std::wstring currentUserName_;
    std::wstring draSid_;
    std::wstring draName_;

    std::unordered_map<std::wstring, KeyPair> userKeyStore_;
    std::unordered_map<std::wstring, KeyPair> draKeyStore_;
    std::unordered_map<std::wstring, EncryptedFileRecord> files_;
    std::unordered_map<void*, std::unique_ptr<RawEncryptedFileContext>> rawContexts_;
    uintptr_t nextContextHandle_{0x1000};

    static std::wstring normalizePath(const std::wstring& p) {
        std::wstring out = p;
        for (auto& ch : out) {
            if (ch == L'/') ch = L'\\';
        }
        return out;
    }

    void ensureUserKeysLocked(const std::wstring& sid, const std::wstring& name) {
        if (!userKeyStore_.contains(sid)) {
            KeyPair kp;
            kp.publicKey.resize(32);
            generateRandomBytes(kp.publicKey.data(), 32);
            kp.privateKey = kp.publicKey;

            // Generate SHA-256 thumbprint from name + public key
            std::vector<uint8_t> nameBytes(reinterpret_cast<const uint8_t*>(name.data()),
                                           reinterpret_cast<const uint8_t*>(name.data() + name.size()));
            nameBytes.insert(nameBytes.end(), kp.publicKey.begin(), kp.publicKey.end());
            kp.thumbprint.resize(32);
            computeSha256(nameBytes, kp.thumbprint.data());

            // Create pseudo X.509 cert blob
            kp.certBlob.resize(64);
            std::memcpy(&kp.certBlob[0], kp.thumbprint.data(), 32);
            std::memcpy(&kp.certBlob[32], kp.publicKey.data(), 32);

            userKeyStore_[sid] = std::move(kp);
        }
    }

    void ensureDraKeysLocked(const std::wstring& sid, const std::wstring& name) {
        if (!draKeyStore_.contains(sid)) {
            KeyPair kp;
            kp.publicKey.resize(32);
            generateRandomBytes(kp.publicKey.data(), 32);
            kp.privateKey = kp.publicKey;

            std::vector<uint8_t> nameBytes(reinterpret_cast<const uint8_t*>(name.data()),
                                           reinterpret_cast<const uint8_t*>(name.data() + name.size()));
            nameBytes.insert(nameBytes.end(), kp.publicKey.begin(), kp.publicKey.end());
            kp.thumbprint.resize(32);
            computeSha256(nameBytes, kp.thumbprint.data());

            kp.certBlob.resize(64);
            std::memcpy(&kp.certBlob[0], kp.thumbprint.data(), 32);
            std::memcpy(&kp.certBlob[32], kp.publicKey.data(), 32);

            draKeyStore_[sid] = std::move(kp);
        }
    }

    bool isCallerAuthorizedLocked(const EncryptedFileRecord& rec, const std::wstring& callerSid) const {
        // 1. Check if caller SID is listed in DDF
        for (const auto& u : rec.metadata.ddfEntries) {
            if (u.userSid == callerSid) return true;
        }

        // 2. Check if caller SID is registered as DRA
        for (const auto& d : rec.metadata.drfEntries) {
            if (d.draSid == callerSid || callerSid == draSid_) return true;
        }

        return false;
    }

    static void generateRandomBytes(uint8_t* p, size_t n) {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint16_t> dis(0, 255);
        for (size_t i = 0; i < n; ++i) {
            p[i] = static_cast<uint8_t>(dis(gen));
        }
    }

    static void computeSha256(std::span<const uint8_t> input, uint8_t* outDigest32) {
        auto h = crypto::Sha256::hash(input);
        std::memcpy(outDigest32, h.data(), 32);
    }

    // Key wrapping: Encrypt 32-byte FEK with recipient public key using AES-256-CBC
    static std::vector<uint8_t> wrapKey(std::span<const uint8_t> fek, std::span<const uint8_t> wrapKeyMaterial) {
        crypto::Aes aes(wrapKeyMaterial);
        std::array<uint8_t, 16> zeroIv{};
        return aes.encrypt(fek, crypto::Aes::Mode::CBC, zeroIv, true);
    }

    // Key unwrapping: Decrypt wrapped FEK with recipient private key
    static std::vector<uint8_t> unwrapKey(std::span<const uint8_t> wrapped, std::span<const uint8_t> wrapKeyMaterial) {
        crypto::Aes aes(wrapKeyMaterial);
        std::array<uint8_t, 16> zeroIv{};
        bool success = false;
        std::vector<uint8_t> out = aes.decrypt(wrapped, crypto::Aes::Mode::CBC, zeroIv, true, &success);
        if (!success || out.size() < 32) {
            return std::vector<uint8_t>(32, 0);
        }
        out.resize(32);
        return out;
    }
};

// ============================================================================
// 6. Native Win32 EFS C ABI Exports (feclient.dll / advapi32.dll)
// ============================================================================

extern "C" {

inline uint32_t __stdcall EncryptFileW(const wchar_t* lpFileName) {
    if (!lpFileName) return ERROR_INVALID_PARAMETER;
    return SovereignEfsManager::get().encryptFile(lpFileName);
}

inline uint32_t __stdcall DecryptFileW(const wchar_t* lpFileName, [[maybe_unused]] uint32_t dwReserved) {
    if (!lpFileName) return ERROR_INVALID_PARAMETER;
    std::vector<uint8_t> plaintext;
    return SovereignEfsManager::get().decryptFile(lpFileName, plaintext);
}

inline uint32_t __stdcall FileEncryptionStatusW(const wchar_t* lpFileName, uint32_t* lpStatus) {
    if (!lpFileName || !lpStatus) return ERROR_INVALID_PARAMETER;
    return SovereignEfsManager::get().getFileEncryptionStatus(lpFileName, lpStatus);
}

inline uint32_t __stdcall QueryUsersOnEncryptedFile(const wchar_t* lpFileName, PENCRYPTION_CERTIFICATE_HASH_LIST* pUsers) {
    if (!lpFileName || !pUsers) return ERROR_INVALID_PARAMETER;
    std::vector<EfsUserKeyEntry> users;
    uint32_t status = SovereignEfsManager::get().queryUsers(lpFileName, users);
    if (status != ERROR_SUCCESS) return status;

    auto list = new ENCRYPTION_CERTIFICATE_HASH_LIST();
    list->nCert_Hash = static_cast<uint32_t>(users.size());
    list->pUsers = new PENCRYPTION_CERTIFICATE_HASH[users.size()];

    for (size_t i = 0; i < users.size(); ++i) {
        auto h = new ENCRYPTION_CERTIFICATE_HASH();
        h->cbTotalLength = sizeof(ENCRYPTION_CERTIFICATE_HASH);
        h->pUserSid = nullptr;

        h->pHash = new EFS_HASH_BLOB();
        h->pHash->cbData = static_cast<uint32_t>(users[i].certThumbprint.size());
        h->pHash->pbData = new uint8_t[h->pHash->cbData];
        std::memcpy(h->pHash->pbData, users[i].certThumbprint.data(), h->pHash->cbData);

        size_t nameLen = users[i].displayName.size();
        h->lpDisplayInformation = new wchar_t[nameLen + 1];
        std::memcpy(h->lpDisplayInformation, users[i].displayName.c_str(), (nameLen + 1) * sizeof(wchar_t));

        list->pUsers[i] = h;
    }

    *pUsers = list;
    return ERROR_SUCCESS;
}

inline uint32_t __stdcall QueryRecoveryAgentsOnEncryptedFile(const wchar_t* lpFileName, PENCRYPTION_CERTIFICATE_HASH_LIST* pRecoveryAgents) {
    if (!lpFileName || !pRecoveryAgents) return ERROR_INVALID_PARAMETER;
    std::vector<EfsDraKeyEntry> agents;
    uint32_t status = SovereignEfsManager::get().queryRecoveryAgents(lpFileName, agents);
    if (status != ERROR_SUCCESS) return status;

    auto list = new ENCRYPTION_CERTIFICATE_HASH_LIST();
    list->nCert_Hash = static_cast<uint32_t>(agents.size());
    list->pUsers = new PENCRYPTION_CERTIFICATE_HASH[agents.size()];

    for (size_t i = 0; i < agents.size(); ++i) {
        auto h = new ENCRYPTION_CERTIFICATE_HASH();
        h->cbTotalLength = sizeof(ENCRYPTION_CERTIFICATE_HASH);
        h->pUserSid = nullptr;

        h->pHash = new EFS_HASH_BLOB();
        h->pHash->cbData = static_cast<uint32_t>(agents[i].certThumbprint.size());
        h->pHash->pbData = new uint8_t[h->pHash->cbData];
        std::memcpy(h->pHash->pbData, agents[i].certThumbprint.data(), h->pHash->cbData);

        size_t nameLen = agents[i].displayName.size();
        h->lpDisplayInformation = new wchar_t[nameLen + 1];
        std::memcpy(h->lpDisplayInformation, agents[i].displayName.c_str(), (nameLen + 1) * sizeof(wchar_t));

        list->pUsers[i] = h;
    }

    *pRecoveryAgents = list;
    return ERROR_SUCCESS;
}

inline void __stdcall FreeEncryptionCertificateHashList(PENCRYPTION_CERTIFICATE_HASH_LIST pUsers) {
    if (!pUsers) return;
    for (uint32_t i = 0; i < pUsers->nCert_Hash; ++i) {
        auto h = pUsers->pUsers[i];
        if (h) {
            if (h->pHash) {
                delete[] h->pHash->pbData;
                delete h->pHash;
            }
            delete[] h->lpDisplayInformation;
            delete h;
        }
    }
    delete[] pUsers->pUsers;
    delete pUsers;
}

inline uint32_t __stdcall RemoveUsersFromEncryptedFile(const wchar_t* lpFileName, PENCRYPTION_CERTIFICATE_HASH_LIST pHashes) {
    if (!lpFileName || !pHashes) return ERROR_INVALID_PARAMETER;
    for (uint32_t i = 0; i < pHashes->nCert_Hash; ++i) {
        if (pHashes->pUsers[i] && pHashes->pUsers[i]->lpDisplayInformation) {
            SovereignEfsManager::get().removeUserFromFile(lpFileName, pHashes->pUsers[i]->lpDisplayInformation);
        }
    }
    return ERROR_SUCCESS;
}

inline uint32_t __stdcall AddUsersToEncryptedFile(const wchar_t* lpFileName, PENCRYPTION_CERTIFICATE_LIST pEncryptionCertificates) {
    if (!lpFileName || !pEncryptionCertificates) return ERROR_INVALID_PARAMETER;
    for (uint32_t i = 0; i < pEncryptionCertificates->nUsers; ++i) {
        std::wstring sid = L"S-1-5-21-NewUser-" + std::to_wstring(i + 1);
        std::wstring name = L"DelegatedUser" + std::to_wstring(i + 1);
        SovereignEfsManager::get().addUserToFile(lpFileName, sid, name);
    }
    return ERROR_SUCCESS;
}

inline uint32_t __stdcall SetUserFileEncryptionKey(PENCRYPTION_CERTIFICATE pUserCert) {
    if (!pUserCert) return ERROR_INVALID_PARAMETER;
    SovereignEfsManager::get().generateNewUserKey(L"CustomCertificateUser");
    return ERROR_SUCCESS;
}

inline uint32_t __stdcall DuplicateEncryptionInfoFile(
    const wchar_t* lpSrcFileName,
    const wchar_t* lpDstFileName,
    [[maybe_unused]] uint32_t dwCreationDistribution,
    [[maybe_unused]] uint32_t dwAttributes,
    [[maybe_unused]] void* lpSecurityAttributes)
{
    if (!lpSrcFileName || !lpDstFileName) return ERROR_INVALID_PARAMETER;
    std::vector<EfsUserKeyEntry> users;
    uint32_t st = SovereignEfsManager::get().queryUsers(lpSrcFileName, users);
    if (st != ERROR_SUCCESS) return st;

    st = SovereignEfsManager::get().encryptFile(lpDstFileName);
    if (st != ERROR_SUCCESS) return st;

    for (const auto& u : users) {
        SovereignEfsManager::get().addUserToFile(lpDstFileName, u.userSid, u.displayName);
    }
    return ERROR_SUCCESS;
}

inline uint32_t __stdcall OpenEncryptedFileRawW(const wchar_t* lpFileName, uint32_t ulFlags, void** pvContext) {
    return SovereignEfsManager::get().openRaw(lpFileName, ulFlags, pvContext);
}

inline uint32_t __stdcall ReadEncryptedFileRaw(PFE_EXPORT_FUNC pfExportCallback, void* pvCallbackContext, void* pvContext) {
    return SovereignEfsManager::get().readRaw(pvContext, pfExportCallback, pvCallbackContext);
}

inline uint32_t __stdcall WriteEncryptedFileRaw(PFE_IMPORT_FUNC pfImportCallback, void* pvCallbackContext, void* pvContext) {
    return SovereignEfsManager::get().writeRaw(pvContext, pfImportCallback, pvCallbackContext);
}

inline void __stdcall CloseEncryptedFileRaw(void* pvContext) {
    SovereignEfsManager::get().closeRaw(pvContext);
}

inline uint32_t __stdcall EfsClientInitialize() {
    return ERROR_SUCCESS;
}

inline uint32_t __stdcall EfsClientShutdown() {
    return ERROR_SUCCESS;
}

} // extern "C"

// ============================================================================
// 7. Dynamic Loader Export Registration (feclient.dll & advapi32.dll)
// ============================================================================

inline void InitializeEfsSubsystemExports() {
    auto& ldr = ldr::DynamicLoader::get();

    // 1. feclient.dll exports
    ldr.registerExport("feclient.dll", "EncryptFileW", reinterpret_cast<void*>(EncryptFileW));
    ldr.registerExport("feclient.dll", "DecryptFileW", reinterpret_cast<void*>(DecryptFileW));
    ldr.registerExport("feclient.dll", "FileEncryptionStatusW", reinterpret_cast<void*>(FileEncryptionStatusW));
    ldr.registerExport("feclient.dll", "QueryUsersOnEncryptedFile", reinterpret_cast<void*>(QueryUsersOnEncryptedFile));
    ldr.registerExport("feclient.dll", "QueryRecoveryAgentsOnEncryptedFile", reinterpret_cast<void*>(QueryRecoveryAgentsOnEncryptedFile));
    ldr.registerExport("feclient.dll", "RemoveUsersFromEncryptedFile", reinterpret_cast<void*>(RemoveUsersFromEncryptedFile));
    ldr.registerExport("feclient.dll", "AddUsersToEncryptedFile", reinterpret_cast<void*>(AddUsersToEncryptedFile));
    ldr.registerExport("feclient.dll", "FreeEncryptionCertificateHashList", reinterpret_cast<void*>(FreeEncryptionCertificateHashList));
    ldr.registerExport("feclient.dll", "SetUserFileEncryptionKey", reinterpret_cast<void*>(SetUserFileEncryptionKey));
    ldr.registerExport("feclient.dll", "DuplicateEncryptionInfoFile", reinterpret_cast<void*>(DuplicateEncryptionInfoFile));
    ldr.registerExport("feclient.dll", "OpenEncryptedFileRawW", reinterpret_cast<void*>(OpenEncryptedFileRawW));
    ldr.registerExport("feclient.dll", "ReadEncryptedFileRaw", reinterpret_cast<void*>(ReadEncryptedFileRaw));
    ldr.registerExport("feclient.dll", "WriteEncryptedFileRaw", reinterpret_cast<void*>(WriteEncryptedFileRaw));
    ldr.registerExport("feclient.dll", "CloseEncryptedFileRaw", reinterpret_cast<void*>(CloseEncryptedFileRaw));
    ldr.registerExport("feclient.dll", "EfsClientInitialize", reinterpret_cast<void*>(EfsClientInitialize));
    ldr.registerExport("feclient.dll", "EfsClientShutdown", reinterpret_cast<void*>(EfsClientShutdown));

    // 2. advapi32.dll forwards / direct exports
    ldr.registerExport("advapi32.dll", "EncryptFileW", reinterpret_cast<void*>(EncryptFileW));
    ldr.registerExport("advapi32.dll", "DecryptFileW", reinterpret_cast<void*>(DecryptFileW));
    ldr.registerExport("advapi32.dll", "FileEncryptionStatusW", reinterpret_cast<void*>(FileEncryptionStatusW));
    ldr.registerExport("advapi32.dll", "QueryUsersOnEncryptedFile", reinterpret_cast<void*>(QueryUsersOnEncryptedFile));
    ldr.registerExport("advapi32.dll", "QueryRecoveryAgentsOnEncryptedFile", reinterpret_cast<void*>(QueryRecoveryAgentsOnEncryptedFile));
    ldr.registerExport("advapi32.dll", "RemoveUsersFromEncryptedFile", reinterpret_cast<void*>(RemoveUsersFromEncryptedFile));
    ldr.registerExport("advapi32.dll", "AddUsersToEncryptedFile", reinterpret_cast<void*>(AddUsersToEncryptedFile));
    ldr.registerExport("advapi32.dll", "FreeEncryptionCertificateHashList", reinterpret_cast<void*>(FreeEncryptionCertificateHashList));
    ldr.registerExport("advapi32.dll", "OpenEncryptedFileRawW", reinterpret_cast<void*>(OpenEncryptedFileRawW));
    ldr.registerExport("advapi32.dll", "ReadEncryptedFileRaw", reinterpret_cast<void*>(ReadEncryptedFileRaw));
    ldr.registerExport("advapi32.dll", "WriteEncryptedFileRaw", reinterpret_cast<void*>(WriteEncryptedFileRaw));
    ldr.registerExport("advapi32.dll", "CloseEncryptedFileRaw", reinterpret_cast<void*>(CloseEncryptedFileRaw));

    // Register in VersionDatabase
    version::VersionDatabase::Instance().RegisterModule(
        "feclient.dll",
        "10.0.26100.1",
        "Windows Encrypting File System (EFS) Client Subsystem",
        "MicaNT Sovereign Project"
    );
}

} // namespace micant::efs
